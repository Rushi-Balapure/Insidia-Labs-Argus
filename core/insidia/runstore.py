"""Write one run directory under .insidia/runs."""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from insidia import version_text
from insidia.errors import CliError
from insidia.findings import Finding, prepare_findings
from insidia.report_html import _render, _ReportData
from insidia.results import SCHEMA_VERSION, legacy_passed
from insidia.run_artifacts import (
    _artefact_digests,
    _write_benchmark,
    _write_findings_csv,
    _write_findings_json,
    _write_manifest,
)
from insidia.run_assurance import low_assurance_summary
from insidia.run_baseline import (
    _compare_findings,
    _FixedFinding,
    _select_baseline,
    _stamp_targets,
    _target_names,
    _Tracked,
)
from insidia.sarif import _write_sarif
from insidia.score import Score, score_frameworks


def new_run_id() -> str:
    # UTC, so that sorting the ids sorts the runs whatever the local zone.
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return f"{stamp}-{secrets.token_hex(3)}"


def local_time(run_id: str) -> str:
    """When the run started, in this machine's time zone, or "" for an id without a stamp."""
    try:
        started = datetime.strptime(run_id[:16], "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    except ValueError:
        return ""
    return started.astimezone().strftime("%Y-%m-%d %H:%M:%S %z")


def _format_epoch(epoch: float) -> str:
    return datetime.fromtimestamp(epoch).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")


@dataclass(frozen=True)
class _Draft:
    run_id: str
    policy: str
    passed: bool
    findings: list[Finding]
    controls: list[dict[str, str | int]]
    skips: list[str]
    targets: tuple[tuple[str, str, str], ...]
    execution_status: str
    verdict: str
    coverage: str
    scope_hosts: tuple[str, ...]
    config_digest: str
    engines: tuple[str, ...] | None
    judge: str
    rate_limits: tuple[tuple[str, float, int], ...]
    baseline_id: str
    fixed: tuple[_FixedFinding, ...]
    tracked: tuple[_Tracked, ...]
    low_assurance: bool
    assurance_reason: str
    rerun_of: str
    scores: tuple[Score, ...]


def write_run(
    root: Path,
    run_id: str,
    policy: str,
    passed: bool,
    findings: list[Finding],
    controls: list[dict[str, str | int]],
    skips: list[str],
    execution_status: str = "complete",
    policy_verdict: str | None = None,
    config_digest: str = "",
    coverage: str = "standard",
    config_text: bytes | None = None,
    targets: tuple[tuple[str, str, str], ...] = (),
    started_epoch: float | None = None,
    scope_hosts: tuple[str, ...] = (),
    engines: tuple[str, ...] | None = None,
    judge: str = "none",
    rate_limits: tuple[tuple[str, float, int], ...] = (),
    rerun_of: str = "",
) -> Path:
    runs = root / ".insidia" / "runs"
    staging, directory = _claim_staging(runs, run_id)
    draft = _assembled(
        runs,
        run_id,
        policy,
        passed,
        findings,
        controls,
        skips,
        execution_status,
        policy_verdict,
        config_digest,
        coverage,
        config_text,
        targets,
        scope_hosts,
        engines,
        judge,
        rate_limits,
        rerun_of,
    )
    draft = _write_scanned_files(staging, draft)
    names = ["findings.json", "findings.csv", "results.sarif", "benchmark.json", "report.html"]
    digest = _store_config(staging, names, config_text, draft.config_digest)
    _publish(staging, names, replace(draft, config_digest=digest), started_epoch)
    staging.rename(directory)
    return directory


def _claim_staging(runs: Path, run_id: str) -> tuple[Path, Path]:
    staging = runs / f".{run_id}.partial"
    directory = runs / run_id
    if staging.exists():
        raise CliError(f"run {run_id} is already being written")
    staging.mkdir(parents=True)
    return staging, directory


def _prepare(
    passed: bool,
    findings: list[Finding],
    controls: list[dict[str, str | int]],
    execution_status: str,
    policy_verdict: str | None,
    config_digest: str,
    config_text: bytes | None,
    targets: tuple[tuple[str, str, str], ...],
) -> tuple[str, bool, list[Finding], str, bool, str]:
    verdict = policy_verdict or ("pass" if passed else "fail")
    kept = legacy_passed(execution_status, verdict)
    low_assurance, assurance_reason = low_assurance_summary(verdict, controls)
    stamped = _stamp_targets(prepare_findings(findings), targets)
    if config_text is not None:
        config_digest = hashlib.sha256(config_text).hexdigest()
    return verdict, kept, stamped, config_digest, low_assurance, assurance_reason


def _with_baseline(
    runs: Path,
    run_id: str,
    findings: list[Finding],
    controls: list[dict[str, str | int]],
    targets: tuple[tuple[str, str, str], ...],
    config_digest: str,
    rerun_of: str,
) -> tuple[str, tuple[_Tracked, ...], tuple[_FixedFinding, ...]]:
    baseline_id, baseline_dir = _select_baseline(
        runs,
        run_id,
        config_digest,
        frozenset(_target_names(findings, controls, targets)),
        rerun_of,
    )
    tracked, fixed = _compare_findings(run_id, findings, baseline_id, baseline_dir)
    return baseline_id, tracked, fixed


def _assembled(
    runs: Path,
    run_id: str,
    policy: str,
    passed: bool,
    findings: list[Finding],
    controls: list[dict[str, str | int]],
    skips: list[str],
    execution_status: str,
    policy_verdict: str | None,
    config_digest: str,
    coverage: str,
    config_text: bytes | None,
    targets: tuple[tuple[str, str, str], ...],
    scope_hosts: tuple[str, ...],
    engines: tuple[str, ...] | None,
    judge: str,
    rate_limits: tuple[tuple[str, float, int], ...],
    rerun_of: str,
) -> _Draft:
    verdict, passed, findings, config_digest, low_assurance, assurance_reason = _prepare(
        passed,
        findings,
        controls,
        execution_status,
        policy_verdict,
        config_digest,
        config_text,
        targets,
    )
    baseline_id, tracked, fixed = _with_baseline(
        runs,
        run_id,
        findings,
        controls,
        targets,
        config_digest,
        rerun_of,
    )
    return _Draft(
        run_id=run_id,
        policy=policy,
        passed=passed,
        findings=findings,
        controls=controls,
        skips=skips,
        targets=targets,
        execution_status=execution_status,
        verdict=verdict,
        coverage=coverage,
        scope_hosts=scope_hosts,
        config_digest=config_digest,
        engines=engines,
        judge=judge,
        rate_limits=rate_limits,
        baseline_id=baseline_id,
        fixed=fixed,
        tracked=tracked,
        low_assurance=low_assurance,
        assurance_reason=assurance_reason,
        rerun_of=rerun_of,
        scores=(),
    )


def _write_scanned_files(staging: Path, draft: _Draft) -> _Draft:
    _write_findings_json(staging, draft.findings, draft.tracked)
    _write_findings_csv(staging, draft.findings, draft.run_id, draft.targets)
    _write_sarif(staging, draft.findings, draft.controls, draft.targets, draft.verdict)
    scored = replace(draft, scores=score_frameworks(draft.controls))
    _write_benchmark(
        staging,
        scored.policy,
        scored.passed,
        scored.execution_status,
        scored.verdict,
        scored.low_assurance,
        scored.assurance_reason,
        scored.controls,
        scored.skips,
        scored.scores,
    )
    return scored


def _store_config(
    staging: Path,
    names: list[str],
    config_text: bytes | None,
    config_digest: str,
) -> str:
    if config_text is None:
        return config_digest
    (staging / "insidia.yaml").write_bytes(config_text)
    names.append("insidia.yaml")
    return hashlib.sha256(config_text).hexdigest()


def _publish(
    staging: Path,
    names: list[str],
    draft: _Draft,
    started_epoch: float | None,
) -> None:
    finished_epoch = time.time()
    started_at, finished_at, duration_s = _timing(draft.run_id, started_epoch, finished_epoch)
    version = version_text()
    ran = _engine_names(draft.findings, draft.engines)
    limits = _limit_rows(draft.rate_limits)
    artefacts = _written_report(
        staging,
        names,
        draft,
        started_at,
        finished_at,
        duration_s,
        version,
        tuple(ran),
        limits,
    )
    _write_manifest(
        staging,
        _manifest_body(
            draft,
            started_at,
            finished_at,
            duration_s,
            version,
            ran,
            limits,
            artefacts,
        ),
    )


def _timing(
    run_id: str, started_epoch: float | None, finished_epoch: float
) -> tuple[str, str, float]:
    if started_epoch is None:
        return local_time(run_id), _format_epoch(finished_epoch), 0.0
    duration_s = round(max(0.0, finished_epoch - started_epoch), 3)
    return _format_epoch(started_epoch), _format_epoch(finished_epoch), duration_s


def _written_report(
    staging: Path,
    names: list[str],
    draft: _Draft,
    started_at: str,
    finished_at: str,
    duration_s: float,
    version: str,
    ran: tuple[str, ...],
    limits: list[dict[str, object]],
) -> dict[str, str]:
    # report.html is hashed after it is written, because the page lists these digests.
    artefacts = _artefact_digests(staging, names)
    page = _render(
        _ReportData(
            run_id=draft.run_id,
            policy=draft.policy,
            passed=draft.passed,
            findings=draft.findings,
            controls=draft.controls,
            skips=draft.skips,
            scores=draft.scores,
            targets=draft.targets,
            started_at=started_at,
            finished_at=finished_at,
            duration_s=duration_s,
            version=version,
            execution_status=draft.execution_status,
            verdict=draft.verdict,
            coverage_name=draft.coverage,
            scope_hosts=draft.scope_hosts,
            config_digest=draft.config_digest,
            judge=draft.judge,
            rate_limits=limits,
            engines=ran,
            artefacts=tuple(artefacts.items()),
            baseline_id=draft.baseline_id,
            fixed=draft.fixed,
            new_count=sum(1 for item in draft.tracked if item.state == "new"),
            still_open_count=sum(1 for item in draft.tracked if item.state == "still_open"),
            fixed_count=len(draft.fixed),
            low_assurance=draft.low_assurance,
            assurance_reason=draft.assurance_reason,
        )
    )
    (staging / "report.html").write_text(page, encoding="utf-8")
    artefacts["report.html"] = hashlib.sha256((staging / "report.html").read_bytes()).hexdigest()
    return {name: artefacts[name] for name in names}


def _manifest_body(
    draft: _Draft,
    started_at: str,
    finished_at: str,
    duration_s: float,
    version: str,
    ran: list[str],
    limits: list[dict[str, object]],
    artefacts: dict[str, str],
) -> dict[str, object]:
    manifest: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "run_id": draft.run_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_s": duration_s,
        "insidia_version": version,
        "policy": draft.policy,
        "execution_status": draft.execution_status,
        "policy_verdict": draft.verdict,
        "low_assurance": draft.low_assurance,
        "assurance_reason": draft.assurance_reason,
        "config_digest": draft.config_digest,
        "coverage": draft.coverage,
        "models": {"judge": draft.judge},
        "rate_limits": limits,
        "engines": ran,
        "skips": draft.skips,
        "files": artefacts,
    }
    if draft.rerun_of:
        manifest["rerun_of"] = draft.rerun_of
    return manifest


def _pass_label(low_assurance: bool, assurance_reason: str) -> str:
    if not low_assurance:
        return "passed"
    if assurance_reason:
        return f"passed (low assurance: {assurance_reason})"
    return "passed (low assurance)"


def verdict_text(
    policy: str,
    passed: bool,
    findings: int,
    execution_status: str = "complete",
    policy_verdict: str | None = None,
    untested: int = 0,
    low_assurance: bool = False,
    assurance_reason: str = "",
) -> str:
    verdict = policy_verdict or ("pass" if passed else "fail")
    label = "finding" if findings == 1 else "findings"
    if execution_status == "cancelled":
        return (
            f"Scan cancelled. Policy {policy} has no verdict. {findings} {label} before it stopped."
        )
    if execution_status != "complete":
        if verdict == "fail":
            return f"The scan did not finish. Policy {policy} did not pass. {findings} {label}."
        return f"The scan did not finish. Policy {policy} is inconclusive."
    outcome = _pass_label(low_assurance, assurance_reason)
    if verdict == "pass" and untested:
        checks = "check was" if untested == 1 else "checks were"
        return (
            f"The scan ran. Policy {policy} {outcome} with no findings, "
            f"but {untested} {checks} not tested. See the report's coverage."
        )
    if verdict == "pass":
        return f"The scan ran. Policy {policy} {outcome}. No findings."
    if verdict == "inconclusive":
        return f"The scan ran. Policy {policy} is inconclusive."
    return f"The scan ran. Policy {policy} did not pass. {findings} {label}."


def is_contained_run(root: Path, path: Path) -> bool:
    """True when path is a real directory inside root/.insidia/runs."""

    insidia = root / ".insidia"
    runs = insidia / "runs"
    if insidia.is_symlink() or runs.is_symlink() or path.is_symlink() or not path.is_dir():
        return False
    try:
        resolved = path.resolve()
    except OSError:
        return False
    return runs.resolve() in resolved.parents


def latest_run(root: Path) -> Path | None:
    insidia = root / ".insidia"
    runs = insidia / "runs"
    if insidia.is_symlink() or runs.is_symlink() or not runs.is_dir():
        return None
    names = sorted(
        path.name
        for path in runs.iterdir()
        if not path.name.startswith(".") and is_contained_run(root, path)
    )
    if not names:
        return None
    return runs / names[-1]


def _engine_names(findings: list[Finding], engines: tuple[str, ...] | None) -> list[str]:
    """Engines the scan recorded. Without that list, use engines that produced findings."""
    if engines is None:
        names: list[str] = []
        for finding in findings:
            for name in finding.engines or (finding.engine,):
                if name and name not in names:
                    names.append(name)
        names.sort()
        return names
    return sorted({name for name in engines if name})


def _limit_rows(rate_limits: tuple[tuple[str, float, int], ...]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for name, rps, concurrency in rate_limits:
        shown: int | float = int(rps) if float(rps).is_integer() else rps
        rows.append({"target": name, "rps": shown, "concurrency": concurrency})
    return rows
