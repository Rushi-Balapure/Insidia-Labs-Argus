"""Execution state and policy verdict. A finished scan is not the same as a pass."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass

SCHEMA_VERSION = "2.0"

COMPLETE = "complete"
# Finished, but too shallow to count as a pass. It still fails on a finding.
LIMITED = "limited"
# Finished observation that is not evidence of a pass and is not a finding.
INFO = "info"
ERROR = "error"
UNSUPPORTED = "unsupported"
NOT_APPLICABLE = "not_applicable"
CANCELLED = "cancelled"

PASS = "pass"
FAIL = "fail"
INCONCLUSIVE = "inconclusive"

RUN_COMPLETE = "complete"
RUN_INCOMPLETE = "incomplete"
RUN_CANCELLED = "cancelled"


@dataclass(frozen=True)
class CheckRecord:
    """One engine attempt for one target and capability."""

    target: str
    family: str
    engine: str
    state: str
    reason: str = ""
    finding_count: int = 0


@dataclass(frozen=True)
class Aggregate:
    """Execution status and policy verdict. Unpacks as (status, verdict)."""

    status: str
    verdict: str
    low_assurance: bool = False
    assurance_reason: str = ""

    def __iter__(self) -> Iterator[str]:
        yield self.status
        yield self.verdict


def aggregate(records: Sequence[CheckRecord]) -> Aggregate:
    """Return run execution status, policy verdict, and low assurance.

    A finding fails the policy even when another required check did not finish.
    No applicable check, or a required check that did not finish, is inconclusive.
    A limited or info check finished, so the run can complete, but it cannot be the pass.
    A pass that includes a limited record is low assurance. The exit code stays a pass.
    """

    status, verdict = _status_and_verdict(records)
    low, reason = _low_assurance(records, verdict)
    return Aggregate(status, verdict, low, reason)


def _status_and_verdict(records: Sequence[CheckRecord]) -> tuple[str, str]:
    applicable = [record for record in records if record.state != NOT_APPLICABLE]
    findings = sum(record.finding_count for record in records)
    finished = {COMPLETE, LIMITED, INFO}
    unfinished = [record for record in applicable if record.state not in finished]
    tested = [record for record in applicable if record.state == COMPLETE]
    if findings:
        verdict = FAIL
    elif not applicable or unfinished or not tested:
        verdict = INCONCLUSIVE
    else:
        verdict = PASS
    if any(record.state == CANCELLED for record in records):
        status = RUN_CANCELLED
    elif unfinished or not applicable:
        status = RUN_INCOMPLETE
    else:
        status = RUN_COMPLETE
    return status, verdict


def _low_assurance(records: Sequence[CheckRecord], verdict: str) -> tuple[bool, str]:
    """A passing target and family that includes a limited record, and why."""

    if verdict != PASS:
        return False, ""
    groups: dict[tuple[str, str], list[CheckRecord]] = {}
    for record in records:
        groups.setdefault((record.target, record.family), []).append(record)
    reasons: list[str] = []
    saw = False
    for group in groups.values():
        _status, group_verdict = _status_and_verdict(group)
        if group_verdict != PASS:
            continue
        for record in group:
            if record.state != LIMITED:
                continue
            saw = True
            text = record.reason or (f"{record.engine} was limited" if record.engine else "limited")
            if text not in reasons:
                reasons.append(text)
    if not saw:
        return False, ""
    return True, "; ".join(reasons)


def exit_for(execution_status: str, policy_verdict: str) -> int:
    """0 is a finished pass. 1 is a finding. 2 is incomplete with no finding. 130 is cancelled.

    A finding wins over an incomplete target, so CI that checks for 1 sees it.
    """

    if execution_status == RUN_CANCELLED:
        return 130
    if policy_verdict == FAIL:
        return 1
    if execution_status != RUN_COMPLETE:
        return 2
    if policy_verdict == PASS:
        return 0
    return 2


def legacy_passed(execution_status: str, policy_verdict: str) -> bool:
    """True only for the exit-0 case. Older readers treat this as the whole result."""

    return exit_for(execution_status, policy_verdict) == 0
