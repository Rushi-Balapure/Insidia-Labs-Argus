"""Low-assurance passes shared by the run record, the report, and SARIF."""

from __future__ import annotations


def not_tested(controls: list[dict[str, str | int]]) -> int:
    return sum(1 for control in controls if control.get("result") == "not tested")


def low_assurance_summary(
    verdict: str, controls: list[dict[str, str | int]]
) -> tuple[bool, str]:
    """Whether a passing run contains a low-assurance pass, and why."""

    if verdict != "pass":
        return False, ""
    reasons: list[str] = []
    low = False
    for control in controls:
        if control.get("result") != "pass" or control.get("assurance") != "low":
            continue
        low = True
        text = control.get("assurance_reason", "")
        if isinstance(text, str):
            cleaned = text.strip()
            if cleaned and cleaned not in reasons:
                reasons.append(cleaned)
    return low, "; ".join(reasons)


def _control_text(control: dict[str, str | int], key: str) -> str:
    value = control.get(key, "")
    return value if isinstance(value, str) else ""


def _low_assurance_label(reason: str) -> str:
    if reason:
        return f"pass (low assurance: {reason})"
    return "pass (low assurance)"
