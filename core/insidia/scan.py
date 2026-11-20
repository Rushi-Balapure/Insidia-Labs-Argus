"""Run the selected probes and write the run directory."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path

from insidia.adapters import find
from insidia.config import Project, Target
from insidia.egress import confine
from insidia.errors import CliError, EngineFailed, ProbeError, ScopeError
from insidia.findings import Finding, normalize
from insidia.mask import bind_secrets, mask, reset_secrets
from insidia.policy import MARKDOWN_BEACON, Policy, get_policy
from insidia.probes import ProbeHit, reset_seen_replies, run
from insidia.registry import Capability, select, unlock_hint
from insidia.results import (
    CANCELLED,
    COMPLETE,
    ERROR,
    INFO,
    LIMITED,
    NOT_APPLICABLE,
    UNSUPPORTED,
    CheckRecord,
    aggregate,
    exit_for,
    legacy_passed,
)
from insidia.run_assurance import low_assurance_summary, not_tested
from insidia.run_config import config_snapshot
from insidia.runstore import _format_epoch, new_run_id, write_run
from insidia.scope import check_url, needs_confirmation, unauthorized_host
from insidia.transport import bind_budget, current_budget, preflight, repo_path, reset_budget
from insidia.ui import Event, short

# Printed only when INSIDIA_VULN_DB=1. The default argv keeps these engines offline.
_NETWORK_DB = {
    "trivy": (
        "trivy downloads a vulnerability database from mirror.gcr.io and ghcr.io "
        "because INSIDIA_VULN_DB=1"
    ),
    "osv-scanner": (
        "osv-scanner downloads a vulnerability database from api.osv.dev "
        "because INSIDIA_VULN_DB=1"
    ),
}


@dataclass(frozen=True)
class ScanOutcome:
    run_id: str
    run_dir: Path
    passed: bool
    findings: list[Finding]
    skips: list[str]
    execution_status: str = "complete"
    policy_verdict: str = ""
    untested: int = 0
    notes: tuple[str, ...] = ()
    started_at: str = ""
    low_assurance: bool = False
    assurance_reason: str = ""

    def exit_code(self) -> int:
        verdict = self.policy_verdict or ("pass" if self.passed else "fail")
        return exit_for(self.execution_status, verdict)


def execute(
    project: Project,
    root: Path,
    policy_name: str | None = None,
    coverage: str | None = None,
    assume_yes: bool = False,
    progress: Callable[[Event], None] | None = None,
    rerun_of: str = "",
    accept_banner_only: bool = False,
) -> ScanOutcome:
    reset_seen_replies()
    blocked = unauthorized_host(project.scope)
    if blocked is not None:
        raise ScopeError(f"{blocked} needs authorized: true in scope")
    if needs_confirmation(project.scope) and not assume_yes:
        raise CliError("a non-local host is in scope; pass --yes to scan it")
    policy = get_policy(policy_name or project.policy)
    if policy.name != "L1":
        raise CliError(
            f"policy {policy.name} is not available yet. "
            "It runs the same checks as L1, so it is not a higher assurance level. Use L1."
        )
    _require_model_secrets(project)
    mode = coverage or project.coverage
    _validate_targets(project, root)
    secrets = _configured_secrets(project)
    secret_token = bind_secrets(secrets)
    try:
        snapshot = config_snapshot(project.path.read_bytes(), secrets)
        # Scope only. L1 does not connect to a configured attacker or judge.
        for role in (project.attacker, project.judge):
            if role is not None and role.base_url is not None:
                check_url(role.base_url, project.scope)
        model_available = project.attacker is not None
        hits: list[ProbeHit] = []
        records: list[CheckRecord] = []
        controls: list[dict[str, str | int]] = []
        skips: list[str] = []
        count = len(project.targets)
        _say(
            progress,
            Event(
                "start",
                detail=(
                    f"scan · policy {policy.name} · coverage {mode} · "
                    f"{count} target{'' if count == 1 else 's'}"
                ),
            ),
        )
        started = time.time()
        budget_token = bind_budget(project.targets)
        try:
            with confine(project.scope):
                return _run_targets(
                    project,
                    root,
                    policy,
                    mode,
                    model_available,
                    hits,
                    records,
                    controls,
                    skips,
                    progress,
                    snapshot,
                    started,
                    rerun_of,
                    accept_banner_only,
                )
        finally:
            reset_budget(budget_token)
    finally:
        reset_secrets(secret_token)


def _run_targets(
    project: Project,
    root: Path,
    policy: Policy,
    mode: str,
    model_available: bool,
    hits: list[ProbeHit],
    records: list[CheckRecord],
    controls: list[dict[str, str | int]],
    skips: list[str],
    progress: Callable[[Event], None] | None,
    config_text: bytes,
    started_epoch: float,
    rerun_of: str = "",
    accept_banner_only: bool = False,
) -> ScanOutcome:
    notes: list[str] = []
    try:
        _scan_targets(
            project,
            root,
            policy,
            mode,
            model_available,
            hits,
            records,
            controls,
            skips,
            progress,
            notes,
            accept_banner_only,
        )
    except KeyboardInterrupt:
        reason = "cancelled by the user"
        skips.append(f"scan: {reason}")
        records.append(CheckRecord("", "scan", "", CANCELLED, reason))
        _say(progress, Event("cancel", detail="Scan cancelled. Saving what finished…"))
    return _finish(
        project,
        root,
        policy,
        mode,
        hits,
        records,
        controls,
        skips,
        progress,
        config_text,
        notes,
        started_epoch,
        rerun_of,
    )


@dataclass
class _FamilyProgress:
    records: list[CheckRecord] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    probe_count: int = 0
    request_count: int = 0
    counted: int = 0
    unit: str = ""
    banner_notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _ProbeResult:
    hits: tuple[ProbeHit, ...]
    error: str
    untested: str
    info: str
    reason_limit: int


def _scan_targets(
    project: Project,
    root: Path,
    policy: Policy,
    mode: str,
    model_available: bool,
    hits: list[ProbeHit],
    records: list[CheckRecord],
    controls: list[dict[str, str | int]],
    skips: list[str],
    progress: Callable[[Event], None] | None,
    notes: list[str],
    accept_banner_only: bool = False,
) -> None:
    for target in project.targets:
        families = _prepare_target(project, root, policy, target, skips, records, progress)
        if families is None:
            continue
        for family in families:
            _run_family(
                project,
                root,
                policy,
                mode,
                model_available,
                target,
                family,
                hits,
                records,
                controls,
                skips,
                progress,
                notes,
                accept_banner_only,
            )
    _attribute_markdown_beacons(hits, records, controls)


def _prepare_target(
    project: Project,
    root: Path,
    policy: Policy,
    target: Target,
    skips: list[str],
    records: list[CheckRecord],
    progress: Callable[[Event], None] | None,
) -> tuple[str, ...] | None:
    if _grpc(target):
        reason = "gRPC probes are not available in this CLI yet"
        skips.append(f"{target.name}: {reason}")
        records.append(CheckRecord(target.name, "grpc", "", UNSUPPORTED, reason))
        _say(
            progress,
            Event("end", target.name, "grpc", result="inconclusive", detail=reason),
        )
        return None
    families = policy.families(target.kind)
    try:
        unreachable = preflight(target, project.scope, root) if families else ""
    except ScopeError as exc:
        # Contact already started. Keep earlier targets and finish the run.
        _record_refused_redirect(target, exc, skips, records, progress)
        return None
    if unreachable:
        reason = short(mask(unreachable), limit=140)
        skips.append(f"{target.name}: {reason}")
        records.append(CheckRecord(target.name, "target", "", ERROR, reason))
        hint = (
            " Start the app, or point url in insidia.yaml at it."
            if ("unreachable" in reason)
            else ""
        )
        _say(
            progress,
            Event(
                "end",
                target.name,
                "target",
                result="inconclusive",
                detail=f"{reason}. Its {len(families)} checks did not run.{hint}",
            ),
        )
        return None
    if not families:
        reason = f"no {policy.name} controls for {target.kind}"
        skips.append(f"{target.name}: {reason}")
        records.append(CheckRecord(target.name, target.kind, "", NOT_APPLICABLE, reason))
        _say(
            progress,
            Event(
                "end",
                target.name,
                target.kind,
                result="inconclusive",
                detail=reason,
            ),
        )
        return None
    return families


def _run_family(
    project: Project,
    root: Path,
    policy: Policy,
    mode: str,
    model_available: bool,
    target: Target,
    family: str,
    hits: list[ProbeHit],
    records: list[CheckRecord],
    controls: list[dict[str, str | int]],
    skips: list[str],
    progress: Callable[[Event], None] | None,
    notes: list[str],
    accept_banner_only: bool,
) -> None:
    chosen = select(family, mode, model_available=model_available)
    if not chosen:
        reason = unlock_hint(family, model_available)
        skips.append(f"{target.name}: {family} has no runnable probe; {reason}")
        records.append(CheckRecord(target.name, family, "", LIMITED, reason))
        controls.append(_recorded(policy, family, target.name, "not tested", reason))
        _say(
            progress,
            Event("end", target.name, family, result="not tested", detail=reason),
        )
        return
    names = tuple(capability.engine for capability in chosen)
    _say(progress, Event("begin", target.name, family, names, sent=_counter(target)))
    began = time.monotonic()
    state = _FamilyProgress()
    for capability in chosen:
        _note_network_db(capability.engine, notes, progress)
        outcome = _invoke_capability(capability, target, project, root, policy, family, state)
        _record_capability(
            capability,
            target,
            family,
            outcome,
            hits,
            skips,
            state,
            progress,
            accept_banner_only,
        )
    records.extend(state.records)
    _close_family(policy, target, family, state, controls, progress, began)


def _note_network_db(
    engine: str,
    notes: list[str],
    progress: Callable[[Event], None] | None,
) -> None:
    note = _NETWORK_DB.get(engine)
    if os.environ.get("INSIDIA_VULN_DB") != "1":
        note = None
    if note is not None and note not in notes:
        notes.append(note)
        _say(progress, Event("note", detail=note))


def _invoke_capability(
    capability: Capability,
    target: Target,
    project: Project,
    root: Path,
    policy: Policy,
    family: str,
    state: _FamilyProgress,
) -> _ProbeResult:
    adapter, spec = find(capability.probe)
    reason_limit = 90
    try:
        attempt = run(adapter, spec, target, project, root, policy.control(family))
    except ScopeError as exc:
        # A hop refused mid-check is this check's result, not a scan abort.
        return _ProbeResult((), _refused_redirect(target, exc), "", "", 300)
    except (EngineFailed, ProbeError) as exc:
        return _ProbeResult((), str(exc), "", "", reason_limit)
    state.probe_count += attempt.probes
    state.request_count += attempt.requests
    if (
        attempt.counted > 0
        and attempt.unit in {"file", "manifest", "dependency"}
        and state.unit in {"", attempt.unit}
    ):
        state.counted += attempt.counted
        state.unit = attempt.unit
    return _ProbeResult(attempt.hits, attempt.error, attempt.untested, attempt.info, reason_limit)


def _record_capability(
    capability: Capability,
    target: Target,
    family: str,
    outcome: _ProbeResult,
    hits: list[ProbeHit],
    skips: list[str],
    state: _FamilyProgress,
    progress: Callable[[Event], None] | None,
    accept_banner_only: bool,
) -> None:
    # A beacon observed on this reply belongs to output handling.
    # It is still recorded, and it does not count as this family's finding.
    owned = tuple(hit for hit in outcome.hits if hit.family == family)
    carried = tuple(hit for hit in outcome.hits if hit.family != family)
    # A relay under the prompt minimum stays out of engines and reported_by.
    if not outcome.untested:
        hits.extend(owned)
    hits.extend(carried)
    if outcome.error:
        reason = short(mask(outcome.error), limit=outcome.reason_limit)
        state.reasons.append(reason)
        skips.append(f"{capability.engine}: {reason}")
        state.records.append(
            CheckRecord(
                target.name,
                family,
                capability.engine,
                ERROR,
                reason,
                finding_count=len(owned),
            )
        )
        _say(
            progress,
            Event(
                "note",
                target.name,
                family,
                detail=f"{capability.engine}: {reason}",
            ),
        )
        return
    if outcome.info:
        warning = mask(outcome.info)
        if accept_banner_only:
            state.records.append(
                CheckRecord(
                    target.name,
                    family,
                    capability.engine,
                    COMPLETE,
                    finding_count=0,
                )
            )
            state.banner_notes.append(warning)
        else:
            state.records.append(
                CheckRecord(
                    target.name,
                    family,
                    capability.engine,
                    INFO,
                    warning,
                    finding_count=0,
                )
            )
        return
    state.records.append(
        CheckRecord(
            target.name,
            family,
            capability.engine,
            LIMITED if outcome.untested else COMPLETE,
            short(mask(outcome.untested)) if outcome.untested else "",
            finding_count=len(owned),
        )
    )


def _close_family(
    policy: Policy,
    target: Target,
    family: str,
    state: _FamilyProgress,
    controls: list[dict[str, str | int]],
    progress: Callable[[Event], None] | None,
    began: float,
) -> None:
    family_records = state.records
    reasons = state.reasons
    probe_count = state.probe_count
    request_count = state.request_count
    counted = state.counted
    unit = state.unit
    banner_notes = state.banner_notes
    result = _family_result(family_records)
    detail = _detail(result, reasons, family_records)
    if result == "not tested":
        probe_count = 0
        request_count = 0
    recorded = _recorded(
        policy, family, target.name, result, detail, probe_count, request_count
    )
    # A pass that includes a limited record is low assurance.
    # A banner with no built-in CVE match is the same shape when the flag is on.
    if result == "pass":
        grouped = aggregate(family_records)
        if grouped.low_assurance:
            recorded["assurance"] = "low"
            recorded["assurance_reason"] = grouped.assurance_reason
        elif banner_notes:
            warning = "; ".join(dict.fromkeys(banner_notes))
            recorded["assurance"] = "low"
            recorded["assurance_reason"] = warning
            recorded["detail"] = warning
    if result == "info":
        recorded["confidence"] = "low"
    controls.append(recorded)
    # A limited run is too shallow to credit, even when one prompt hit.
    finished = tuple(
        record.engine for record in family_records if record.state == COMPLETE and record.engine
    )
    # Banner-only stores the warning after _detail() has already returned.
    # A relay reason is already in detail, so it is not repeated.
    assurance_reason = recorded.get("assurance_reason", "")
    if (
        result == "pass"
        and recorded.get("assurance") == "low"
        and isinstance(assurance_reason, str)
        and assurance_reason
        and assurance_reason not in detail
    ):
        detail = assurance_reason if not detail else f"{detail}. {assurance_reason}"
    shown = f"{', '.join(finished)} · {detail}" if finished and detail else detail
    raw_assurance = recorded.get("assurance", "")
    assurance = raw_assurance if isinstance(raw_assurance, str) else ""
    raw_reason = recorded.get("assurance_reason", "")
    assurance_reason = raw_reason if isinstance(raw_reason, str) else ""
    _say(
        progress,
        Event(
            "end",
            target.name,
            family,
            finished,
            result,
            shown,
            time.monotonic() - began,
            probes=probe_count if result in {"pass", "fail"} else None,
            counted=counted if result in {"pass", "fail"} and counted > 0 else None,
            unit=unit if result in {"pass", "fail"} and counted > 0 else "",
            assurance=assurance,
            assurance_reason=assurance_reason if assurance == "low" else "",
        ),
    )


def _attribute_markdown_beacons(
    hits: list[ProbeHit],
    records: list[CheckRecord],
    controls: list[dict[str, str | int]],
) -> None:
    """Fail output handling when any reply carried a beacon. Leave other families alone."""
    targets = {hit.target for hit in hits if hit.check_id == MARKDOWN_BEACON.check_id}
    family = MARKDOWN_BEACON.family
    for target in targets:
        indexes = [
            index
            for index, record in enumerate(records)
            if record.target == target and record.family == family and record.engine
        ]
        if indexes and all(records[index].finding_count == 0 for index in indexes):
            chosen = next(
                (index for index in indexes if records[index].state == COMPLETE),
                indexes[0],
            )
            records[chosen] = replace(records[chosen], finding_count=1)
        for row in controls:
            if row.get("id") != family or row.get("target") != target:
                continue
            if row.get("result") == "fail":
                break
            row["result"] = "fail"
            row.pop("detail", None)
            row.pop("assurance", None)
            row.pop("assurance_reason", None)
            break


def _counter(target: Target) -> Callable[[], int] | None:
    table = current_budget()
    if table is None or target.name not in table:
        return None
    limiter = table[target.name][0]
    base = limiter.sent
    return lambda: limiter.sent - base


def _finish(
    project: Project,
    root: Path,
    policy: Policy,
    mode: str,
    hits: list[ProbeHit],
    records: list[CheckRecord],
    controls: list[dict[str, str | int]],
    skips: list[str],
    progress: Callable[[Event], None] | None,
    config_text: bytes,
    notes: list[str],
    started_epoch: float,
    rerun_of: str = "",
) -> ScanOutcome:
    grouped = aggregate(records)
    execution_status = grouped.status
    policy_verdict = grouped.verdict
    findings = normalize(hits)
    passed = legacy_passed(execution_status, policy_verdict)
    low_assurance, assurance_reason = low_assurance_summary(policy_verdict, controls)
    run_id = new_run_id()
    _say(progress, Event("write", detail="Writing the report…"))
    run_dir = write_run(
        root,
        run_id,
        policy.name,
        passed,
        findings,
        controls,
        skips,
        execution_status=execution_status,
        policy_verdict=policy_verdict,
        coverage=mode,
        config_text=config_text,
        targets=_target_facts(project),
        started_epoch=started_epoch,
        scope_hosts=tuple(item.host for item in project.scope),
        engines=_engines_that_ran(records, findings),
        judge=_judge_name(project),
        rate_limits=_rate_limits(project),
        rerun_of=rerun_of,
    )
    return ScanOutcome(
        run_id,
        run_dir,
        passed,
        findings,
        skips,
        execution_status,
        policy_verdict,
        not_tested(controls),
        tuple(notes),
        started_at=_format_epoch(started_epoch),
        low_assurance=low_assurance,
        assurance_reason=assurance_reason,
    )


def _say(progress: Callable[[Event], None] | None, event: Event) -> None:
    if progress is not None:
        progress(event)


def _require_model_secrets(project: Project) -> None:
    """Fail before any probe when a configured model key is missing."""
    from insidia.config import resolve_secret

    for role in (project.attacker, project.judge):
        if role is not None and role.secret_ref:
            resolve_secret(role.secret_ref)


def _configured_secrets(project: Project) -> tuple[str, ...]:
    from insidia.config import resolve_secret

    found: list[str] = []
    for target in project.targets:
        if target.auth is None:
            continue
        ref = target.auth.secret_ref
        try:
            found.append(resolve_secret(ref))
        except CliError as exc:
            raise CliError(f"{target.name}: cannot resolve secret_ref {ref}") from exc
    return tuple(found)


def _detail(result: str, reasons: list[str], records: list[CheckRecord]) -> str:
    if result == "inconclusive" and reasons:
        return reasons[0]
    if result == "info":
        return next(
            (record.reason for record in records if record.state == INFO and record.reason),
            "",
        )
    if result == "not tested":
        return next((record.reason for record in records if record.reason), "")
    limited = [record.reason for record in records if record.state == LIMITED and record.reason]
    if limited:
        return "; ".join(dict.fromkeys(limited))
    return ""


def _family_result(records: list[CheckRecord]) -> str:
    grouped = aggregate(records)
    if grouped.verdict == "fail":
        return "fail"
    if any(record.state == INFO for record in records) and not any(
        record.state == COMPLETE and record.finding_count == 0 for record in records
    ):
        return "info"
    if grouped.status == "complete" and grouped.verdict == "pass":
        return "pass"
    if grouped.status == "complete":
        return "not tested"
    return "inconclusive"


def _judge_name(project: Project) -> str:
    """Configured judge, marked unused at L1, or none when models.judge is absent."""
    role = project.judge
    if role is None:
        return "none"
    name = role.model or role.provider
    if not name:
        return "none"
    return f"{name} (configured, not used at L1)"


def _engines_that_ran(records: list[CheckRecord], findings: list[Finding]) -> tuple[str, ...]:
    """Engines that finished a check, plus any engine that still produced a finding.

    A limited or failed attempt is not listed. A clean run still names engines that
    completed with no findings. Names that never ran are not added.
    """
    names: set[str] = set()
    for record in records:
        if record.state == COMPLETE and record.engine:
            names.add(record.engine)
    for finding in findings:
        for name in finding.engines or (finding.engine,):
            if name:
                names.add(name)
    return tuple(sorted(names))


def _rate_limits(project: Project) -> tuple[tuple[str, float, int], ...]:
    return tuple(
        (target.name, target.rate_limit.rps, target.rate_limit.concurrency)
        for target in project.targets
    )


def _target_facts(project: Project) -> tuple[tuple[str, str, str], ...]:
    """Name, kind, and endpoint (method plus URL, or the repo path) for the report."""
    facts: list[tuple[str, str, str]] = []
    for target in project.targets:
        if target.kind == "repo":
            endpoint = target.path or ""
        elif target.url:
            endpoint = f"{target.method} {target.url}"
        else:
            endpoint = ""
        facts.append((target.name, target.kind, endpoint))
    return tuple(facts)


def _recorded(
    policy: Policy,
    family: str,
    target: str,
    result: str,
    detail: str = "",
    probes: int = 0,
    requests: int = 0,
) -> dict[str, str | int]:
    row: dict[str, str | int] = {
        "id": family,
        "target": target,
        "result": result,
        "taxonomy": ",".join(policy.control(family).taxonomy),
        "probes": probes,
        "requests": requests,
    }
    if detail:
        row["detail"] = detail
    return row


def _refused_redirect(target: Target, exc: ScopeError) -> str:
    """Names the target and the hop a mid-scan redirect refusal would not request."""
    return f"{target.name}: {exc}"


def _record_refused_redirect(
    target: Target,
    exc: ScopeError,
    skips: list[str],
    records: list[CheckRecord],
    progress: Callable[[Event], None] | None,
) -> None:
    reason = short(mask(_refused_redirect(target, exc)), limit=300)
    skips.append(reason)
    records.append(CheckRecord(target.name, "target", "", ERROR, reason))
    _say(
        progress,
        Event("end", target.name, "target", result="inconclusive", detail=reason),
    )


def _validate_targets(project: Project, root: Path) -> None:
    """Refuse a bad target before any of them is contacted."""
    for target in project.targets:
        try:
            _guard(target, project, root)
        except ScopeError as exc:
            raise ScopeError(f"{exc}. No target was contacted.") from exc


def _grpc(target: Target) -> bool:
    return bool(target.url and (target.api == "grpc" or target.url.startswith("grpc:")))


def _guard(target: Target, project: Project, root: Path) -> None:
    if target.kind == "repo":
        repo_path(target, root)
        return
    if target.command:
        raise CliError(f"{target.name}: local commands are not available in this release")
    if target.url is None:
        raise CliError(f"{target.name} needs a url")
    check_url(target.url, project.scope)
