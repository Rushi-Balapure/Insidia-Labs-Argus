"""Run one probe through its engine adapter. The adapter value names the engine."""

from __future__ import annotations

import contextvars
import tempfile
import threading
import weakref
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TypeGuard

from insidia import repo_scan
from insidia.adapters import (
    FIXTURE_ONLY,
    ORACLES,
    Adapter,
    BuiltIn,
    EngineHit,
    Invocation,
    ProbeSpec,
    RelayAdapter,
    RepoPath,
    ReportAdapter,
    ScopedUrl,
    markdown_beacon,
)
from insidia.config import Project, Target
from insidia.errors import (
    CliError,
    ConfigError,
    EngineFailed,
    HttpStatus,
    ProbeError,
    ProbeTimeout,
    ScopeError,
)
from insidia.policy import MARKDOWN_BEACON, Control, get_policy
from insidia.probes_http import (
    _BANNER_GAP_MARK,
    _paired_bola,
    _paired_cve,
    _paired_open_redirect,
    _paired_sqli,
    _paired_ssti,
)
from insidia.probes_http import _redirect_evidence as _redirect_evidence  # noqa: F401
from insidia.probes_relay import _relay
from insidia.probes_tls import _paired_tls
from insidia.process import launch_installed
from insidia.scope import ScopeHost, check_url
from insidia.transport import AI_KINDS, RateLimiter, carries_payload, current_budget, repo_path
from insidia.transport import exchange as exchange

Launch = Callable[[Invocation, Path], None]


@dataclass(frozen=True)
class ProbeHit:
    target: str
    family: str
    engine: str
    probe: str
    response: str
    severity: str
    confidence: str
    track: str
    taxonomy: tuple[str, ...]
    remediation: str
    upstream: str = ""
    evidence: str = ""
    location: str = ""
    check_id: str = ""
    title: str = ""
    synopsis: str = ""
    description: str = ""


@dataclass(frozen=True)
class Attempt:
    """Observations from one engine, plus an error if that engine did not finish."""

    hits: tuple[ProbeHit, ...] = ()
    error: str = ""
    # The engine finished but could not test this target, for example TLS over plain HTTP.
    untested: str = ""
    # Payloads or prompts handed to the target, and HTTP requests made for them.
    probes: int = 0
    requests: int = 0
    # Files, manifests, or dependencies a repository check read. Not a payload total.
    counted: int = 0
    unit: str = ""
    # A finished observation that is not a pass and not a finding. Banner gaps use this.
    info: str = ""


# Shared list so a worker thread can record a payload the scan thread totals.
_probe_tally: contextvars.ContextVar[list[int] | None] = contextvars.ContextVar(
    "insidia_probe_tally", default=None
)
_probe_tally_lock = threading.Lock()


def _count_bucket(bucket: list[int] | None) -> None:
    if bucket is None:
        return
    with _probe_tally_lock:
        bucket[0] += 1


def _count_probe() -> None:
    _count_bucket(_probe_tally.get())


def _bound_limiter(target: Target) -> RateLimiter | None:
    table = current_budget()
    if table is None or target.name not in table:
        return None
    return table[target.name][0]


def _request_count(target: Target) -> int:
    limiter = _bound_limiter(target)
    return 0 if limiter is None else limiter.sent


# Replies this scan already received. A judge-only check reads them and does not send again.
# Keyed by id so a later object that reuses the id cannot see a dead target's replies.
_SEEN_LIMIT = 64
_SEEN_CHARS = 512
_seen_replies: dict[int, tuple[weakref.ref[Target], list[tuple[str, str]]]] = {}
_seen_lock = threading.Lock()


def reset_seen_replies() -> None:
    """Drop replies from an earlier scan. The next scan starts with an empty log."""
    with _seen_lock:
        _seen_replies.clear()


def _remember_reply(target: Target, payload: str, outcome: str) -> None:
    text = outcome if len(outcome) <= _SEEN_CHARS else outcome[:_SEEN_CHARS]
    with _seen_lock:
        _drop_dead_replies()
        current = _seen_replies.get(id(target))
        if current is None or current[0]() is not target:
            rows: list[tuple[str, str]] = []
            _seen_replies[id(target)] = (weakref.ref(target), rows)
        else:
            rows = current[1]
        rows.append((payload, text))
        if len(rows) > _SEEN_LIMIT:
            del rows[:-_SEEN_LIMIT]


def _remembered(target: Target) -> tuple[tuple[str, str], ...]:
    with _seen_lock:
        current = _seen_replies.get(id(target))
        if current is None or current[0]() is not target:
            return ()
        return tuple(current[1])


def _drop_dead_replies() -> None:
    dead = [key for key, (ref, _rows) in _seen_replies.items() if ref() is None]
    for key in dead:
        del _seen_replies[key]


def _judge_only(
    spec: ProbeSpec,
    target: Target,
) -> tuple[list[EngineHit], str, str]:
    """Score a plant already in this scan's replies. Do not send a new prompt."""
    oracle = ORACLES[spec.family]
    for payload, outcome in _remembered(target):
        evidence = oracle(payload, outcome, target)
        if evidence is None:
            continue
        return _judge_reply(spec, payload, outcome, target, evidence), "", ""
    return [], "", _JUDGE_UNUSED_NOTE


def _probe_hit(
    spec: ProbeSpec,
    target_name: str,
    engine: str,
    control: Control,
    hit: EngineHit,
) -> ProbeHit:
    """One engine observation. A markdown beacon keeps its own title on this family."""
    chosen = control
    if hit.family and hit.family != spec.family:
        chosen = get_policy("L1").control(hit.family)
    return ProbeHit(
        target_name,
        hit.family or spec.family,
        engine,
        hit.probe or spec.probe,
        hit.response,
        hit.severity or chosen.severity,
        hit.confidence or "high",
        chosen.track,
        chosen.taxonomy,
        hit.remediation or chosen.remediation,
        hit.upstream,
        hit.evidence,
        hit.location,
        check_id=hit.check_id,
        title=hit.title,
        synopsis=hit.synopsis,
        description=hit.description,
    )


# Distinct from the active-HTML probe so SARIF can describe the beacon on its own.
_BEACON_PROBE = "insidia.ai.output_handling_sinks.markdown_beacon"


def _judge_reply(
    spec: ProbeSpec,
    payload: str,
    outcome: str,
    target: Target,
    evidence: str | None,
) -> list[EngineHit]:
    """The family oracle, plus a markdown beacon on any chat-style reply.

    The beacon belongs to output handling, not to the family that received the
    reply. The URL is recorded and not requested.
    """
    found: list[EngineHit] = []
    if evidence is not None:
        found.append(EngineHit(spec.upstream, payload, outcome, evidence))
    if target.kind not in AI_KINDS:
        return found
    url = markdown_beacon(payload, outcome, target)
    if url is None:
        return found
    copy = MARKDOWN_BEACON
    found.append(
        EngineHit(
            spec.upstream,
            payload,
            outcome,
            url,
            family=copy.family,
            probe=_BEACON_PROBE,
            check_id=copy.check_id,
            title=copy.title,
            synopsis=copy.synopsis,
            description=copy.description,
            remediation=copy.remediation,
        )
    )
    return found


def run(
    adapter: Adapter,
    spec: ProbeSpec,
    target: Target,
    project: Project,
    root: Path,
    control: Control,
    launch: Launch = launch_installed,
) -> Attempt:
    if target.kind not in spec.target_kinds:
        return Attempt()
    if _payload_cannot_land(target, spec.family):
        return Attempt(untested=_NO_PAYLOAD)
    bucket = [0]
    token = _probe_tally.set(bucket)
    before = _request_count(target)
    try:
        untested = ""
        counted = 0
        unit = ""
        match adapter:
            case BuiltIn() if target.kind == "repo":
                found, untested, counted, unit = _judge_repo(spec, target, root)
                error = ""
            case BuiltIn():
                found, error, untested = _judge(adapter, spec, target, project.scope, root)
            case RelayAdapter():
                found, error, untested = _relay(adapter, spec, target, project, root, launch)
            case ReportAdapter() if _over_url(adapter):
                found, error = _report(adapter, spec, _scoped_url(target, project.scope), launch)
            case ReportAdapter() if _over_repo(adapter):
                found, error = _report(adapter, spec, RepoPath(repo_path(target, root)), launch)
            case _:
                raise CliError(f"{adapter.engine}: no adapter arm")
        hits = tuple(_probe_hit(spec, target.name, adapter.engine, control, hit) for hit in found)
        # Only this family's hits clear a miss-only note. A markdown beacon is
        # output handling's finding, even when another family's reply carried it.
        # A relay under the prompt minimum stays limited.
        owned = tuple(hit for hit in hits if hit.family == spec.family)
        if owned and not _is_relay_shallow_note(untested):
            untested = ""
        info = ""
        if untested.startswith(_BANNER_GAP_MARK):
            info = untested.removeprefix(_BANNER_GAP_MARK)
            untested = ""
        sent = _request_count(target) - before
        return Attempt(
            hits,
            error,
            untested,
            bucket[0],
            sent if sent > 0 else 0,
            counted,
            unit,
            info,
        )
    finally:
        _probe_tally.reset(token)


_FIXTURE_ONLY_NOTE = "this check only recognises Insidia's benchmark app"
# A judge is the only oracle that could score these on a real app. L1 does not call one.
_JUDGE_ONLY = frozenset(
    {
        "ai.harmful_content_policy",
        "ai.bias",
        "ai.citation_groundedness",
    }
)
_JUDGE_UNUSED_NOTE = "this coverage does not call the judge"
# Fewer prompts than this is a smoke test, not coverage of the family.
_RELAY_MIN_PROMPTS = 3
_SHALLOW_NOTE = " sent only "
_SHALLOW_TAIL = " prompt(s)"
_NO_PAYLOAD = (
    "no {{payload}} placeholder in url, query, or body, "
    "so every probe sent the same request"
)
# Banner and handshake checks read the server itself. They do not inject a payload.
_PAYLOAD_FREE = frozenset({"infra.cve", "infra.tls"})

_REPO_CHECKS = {
    "code.sast_sinks": repo_scan.sinks,
    "code.secrets": repo_scan.secrets,
    "deps.sca": repo_scan.dependencies,
}


def _payload_cannot_land(target: Target, family: str) -> bool:
    """True when every payload would build the same request, so the check cannot run."""
    if target.kind == "repo" or family in _PAYLOAD_FREE or target.url is None:
        return False
    return not carries_payload(target)


def _relay_shallow_note(engine: str, sent: int) -> str:
    """Why a relay that sent too few prompts did not cover the family."""
    return f"{engine}{_SHALLOW_NOTE}{sent}{_SHALLOW_TAIL}"


def _is_relay_shallow_note(note: str) -> bool:
    engine, marker, rest = note.partition(_SHALLOW_NOTE)
    if not engine or not marker or not rest.endswith(_SHALLOW_TAIL):
        return False
    return rest.removesuffix(_SHALLOW_TAIL).isdigit()


def _untested_note(family: str) -> str:
    """Why a fixture-only miss is not a pass. Judge-only families name the unused judge."""
    if family in _JUDGE_ONLY:
        return _JUDGE_UNUSED_NOTE
    return _FIXTURE_ONLY_NOTE


def _judge(
    adapter: BuiltIn,
    spec: ProbeSpec,
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str, str]:
    """Hits, an error if the check did not finish, and why nothing could be tested."""
    # L1 does not call a judge, so this check does not prompt the target.
    if spec.family in _JUDGE_ONLY:
        return _judge_only(spec, target)
    if target.kind == "repo":
        hits, untested, _counted, _unit = _judge_repo(spec, target, root)
        return hits, "", untested
    paired = _PAIRED.get(spec.family)
    if paired is not None:
        return paired(target, scope, root)
    hits, error = _corpus(adapter, spec, target, scope, root)
    if spec.family in FIXTURE_ONLY:
        # A matching plant is still a finding. The note only explains a miss.
        return hits, error, _untested_note(spec.family)
    return hits, error, ""


def _corpus(
    adapter: BuiltIn,
    spec: ProbeSpec,
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str]:
    oracle = ORACLES[spec.family]
    payloads = adapter.corpus[spec]
    # Judge-only families return in `_judge` before this. The first entry is the
    # benchmark plant's trigger. Later entries repeat a request this oracle cannot
    # judge on any other app. Cap that one request so a slow target cannot stall
    # the check. A timeout or a miss is not tested.
    timeout: float | None = None
    if spec.family in FIXTURE_ONLY and spec.family not in _ORDERED:
        payloads = payloads[:1]
        timeout = _FIXTURE_ONLY_TIMEOUT
    hits: list[EngineHit] = []
    answered = 0
    rejected = ""
    try:
        for index, (payload, outcome) in enumerate(
            _replies(target, payloads, spec.family, scope, root, timeout)
        ):
            if isinstance(outcome, HttpStatus):
                # An AI endpoint that refuses one prompt still answers the others.
                rejected = str(outcome)
                if _fixture_follow_up_is_useless(spec.family, index, outcome):
                    break
                continue
            answered += 1
            evidence = oracle(payload, outcome, target)
            hits.extend(_judge_reply(spec, payload, outcome, target, evidence))
            if _fixture_follow_up_is_useless(spec.family, index, outcome):
                break
    except ProbeError as exc:
        if timeout is not None and isinstance(exc, ProbeTimeout):
            return [], ""
        return hits, str(exc)
    if not answered and rejected:
        return hits, f"every payload was rejected: {rejected}"
    return hits, ""


# Each payload depends on the reply to the one before it.
_ORDERED = frozenset({"ai.memory_poisoning"})
_MEMORY_PLANT = "insidia-memory-plant"
# Fixture-only triggers do not inherit a slow target's timeout.
_FIXTURE_ONLY_TIMEOUT = 1.0


def _fixture_follow_up_is_useless(family: str, index: int, outcome: str | HttpStatus) -> bool:
    """A memory plant that did not stick cannot be read back by the next payload."""
    if family not in FIXTURE_ONLY or family not in _ORDERED or index != 0:
        return False
    return not isinstance(outcome, str) or _MEMORY_PLANT not in outcome


def _replies(
    target: Target,
    payloads: tuple[str, ...],
    family: str,
    scope: tuple[ScopeHost, ...],
    root: Path,
    timeout: float | None = None,
) -> Iterator[tuple[str, str | HttpStatus]]:
    """Each payload with its reply, in order. Sent in parallel up to the target's concurrency."""

    def one(payload: str) -> str | HttpStatus:
        try:
            return _send(target, payload, scope, root, timeout)
        except HttpStatus as exc:
            return exc

    workers = min(target.rate_limit.concurrency, len(payloads))
    if workers <= 1 or family in _ORDERED:
        for payload in payloads:
            yield payload, one(payload)
        return
    with ThreadPoolExecutor(workers) as pool:
        futures = [pool.submit(contextvars.copy_context().run, one, item) for item in payloads]
        try:
            for payload, future in zip(payloads, futures, strict=True):
                yield payload, future.result()
        finally:
            for future in futures:
                future.cancel()


def _send(
    target: Target,
    payload: str,
    scope: tuple[ScopeHost, ...],
    root: Path,
    timeout: float | None = None,
) -> str:
    """A web app's error page is its answer to the attack, so it is judged too."""
    _count_probe()
    sent = replace(target, timeout=timeout) if timeout is not None else target
    try:
        body = exchange(sent, payload, scope, root)
    except HttpStatus as exc:
        if target.kind in AI_KINDS:
            raise
        return exc.body
    _remember_reply(target, payload, body)
    return body


_PAIRED: dict[
    str, Callable[[Target, tuple[ScopeHost, ...], Path], tuple[list[EngineHit], str, str]]
] = {
    "web.ssti": _paired_ssti,
    "web.sqli": _paired_sqli,
    "web.open_redirect": _paired_open_redirect,
    "api.bola_idor": _paired_bola,
    "infra.tls": _paired_tls,
    "infra.cve": _paired_cve,
}


def _judge_repo(
    spec: ProbeSpec, target: Target, root: Path
) -> tuple[list[EngineHit], str, int, str]:
    """Hits across the repository's files, why nothing could be tested, and the real total."""
    result = _REPO_CHECKS[spec.family](repo_path(target, root))
    hits = [
        EngineHit(f"insidia-{hit.rule}", hit.rule, hit.line, hit.evidence, hit.location)
        for hit in result.hits
    ]
    return hits, result.untested, result.counted, result.unit


def _report[View: (ScopedUrl, RepoPath)](
    adapter: ReportAdapter[View],
    spec: ProbeSpec,
    view: View,
    launch: Launch,
) -> tuple[list[EngineHit], str]:
    with tempfile.TemporaryDirectory(prefix=f"insidia-{adapter.engine}-") as name:
        workspace = Path(name).resolve()
        invocation = adapter.prepare(spec, view, workspace)
        report = (workspace / invocation.report).resolve()
        if workspace not in report.parents:
            raise ScopeError(f"{adapter.engine} report path leaves its workspace")
        try:
            launch(invocation, workspace)
        except EngineFailed as exc:
            return [], str(exc)
        try:
            return adapter.parse(report, spec), ""
        except EngineFailed as exc:
            return [], str(exc)


def _scoped_url(target: Target, scope: tuple[ScopeHost, ...]) -> ScopedUrl:
    if target.url is None:
        raise ConfigError(f"{target.name} needs a url")
    check_url(target.url, scope)
    return ScopedUrl(target.url, tuple(target.query.items()))


def _over_url(
    adapter: ReportAdapter[ScopedUrl] | ReportAdapter[RepoPath],
) -> TypeGuard[ReportAdapter[ScopedUrl]]:
    return adapter.view is ScopedUrl


def _over_repo(
    adapter: ReportAdapter[ScopedUrl] | ReportAdapter[RepoPath],
) -> TypeGuard[ReportAdapter[RepoPath]]:
    return adapter.view is RepoPath
