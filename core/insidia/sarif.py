"""Build a SARIF 2.1.0 document for one run."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from insidia import __version__
from insidia.findings import Finding
from insidia.mask import mask
from insidia.run_assurance import _control_text, _low_assurance_label, low_assurance_summary


def _sarif_level(severity: str) -> str:
    """GitHub code scanning: error, warning, and note. Info and low are notes."""
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    if severity in {"low", "informational", "info"}:
        return "note"
    return "none"


def _file_location(location: str) -> dict[str, object] | None:
    """A repository path stays file:line. A URL is not a file."""
    if not location or "://" in location:
        return None
    path, separator, line = location.rpartition(":")
    if separator and line.isdigit() and path:
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": path},
                "region": {"startLine": int(line)},
            }
        }
    return {"physicalLocation": {"artifactLocation": {"uri": location}}}


def _endpoint_location(target: str, endpoint: str) -> dict[str, object]:
    """Point GitHub code scanning at an endpoint that is not a file in the repo.

    Code scanning requires physicalLocation.artifactLocation.uri to be a relative
    path and drops results whose uri is an absolute URL. The method and URL are
    the logicalLocation. The physicalLocation is a relative fallback plus a snippet
    of that same endpoint, so the result still appears when the URL is not a file.
    """

    return {
        "physicalLocation": {
            "artifactLocation": {"uri": _relative_endpoint_uri(target, endpoint)},
            "region": {"startLine": 1, "snippet": {"text": endpoint}},
        },
        "logicalLocations": [{"kind": "endpoint", "name": target, "fullyQualifiedName": endpoint}],
    }


def _relative_endpoint_uri(target: str, endpoint: str) -> str:
    text = endpoint.strip()
    _method, separator, rest = text.partition(" ")
    url = rest if separator and "://" in rest else text
    if "://" not in url:
        return f"insidia-endpoints/{_safe_part(target)}"
    parsed = urlparse(url)
    host = _safe_part(parsed.netloc or "unknown")
    parts = [_safe_part(part) for part in parsed.path.split("/") if part not in {"", ".", ".."}]
    suffix = "/".join(parts) if parts else "root"
    return f"insidia-endpoints/{host}/{suffix}"


def _safe_part(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-.")
    return cleaned or "target"


def _sarif_result_location(finding: Finding) -> dict[str, object]:
    filed = _file_location(finding.location)
    if filed is not None:
        return filed
    endpoint = finding.endpoint
    if not endpoint and finding.location and "://" in finding.location:
        endpoint = finding.location
    if not endpoint:
        endpoint = finding.target or "target"
    return _endpoint_location(finding.target or "target", endpoint)


def _sarif_tags(taxonomy: tuple[str, ...]) -> list[str]:
    """security, then each taxonomy id. cwe:CWE-200 is emitted as CWE-200."""
    tags = ["security"]
    for item in taxonomy:
        prefix, separator, rest = item.partition(":")
        tag = rest if separator and prefix == "cwe" and rest else item
        if tag and tag not in tags:
            tags.append(tag)
    return tags


def _sarif_help(finding: Finding) -> str:
    """Remediation, then each reference on its own line."""
    refs = [item for item in finding.references if item]
    if not finding.remediation:
        return "\n".join(refs)
    if not refs:
        return finding.remediation
    return f"{finding.remediation}\n\n" + "\n".join(refs)


def _sarif_rule(finding: Finding) -> dict[str, object]:
    help_text = _sarif_help(finding)
    rule: dict[str, object] = {
        "id": finding.probe,
        "name": finding.attack,
        "shortDescription": {"text": finding.title or finding.attack},
        "fullDescription": {"text": finding.synopsis or finding.description or finding.remediation},
        "help": {"text": help_text, "markdown": help_text},
        "properties": {
            "security-severity": f"{finding.risk_score:.1f}",
            "tags": _sarif_tags(finding.taxonomy),
        },
    }
    if finding.references:
        rule["helpUri"] = finding.references[0]
    return rule


def _banner_warning(control: dict[str, str | int]) -> str:
    """The low-confidence banner note, when this control is that case."""
    result = _control_text(control, "result")
    if result == "info":
        text = _control_text(control, "detail").strip()
    elif result == "pass" and control.get("assurance") == "low":
        text = _control_text(control, "assurance_reason").strip()
        if not text:
            text = _control_text(control, "detail").strip()
    else:
        return ""
    if "not a vulnerability assessment" not in text or "low confidence" not in text:
        return ""
    return text


def _sarif_message(finding: Finding) -> str:
    """Name the finding and show masked evidence. A raw secret never reaches SARIF."""
    title = finding.title or finding.attack
    evidence = mask(finding.response).strip()
    if evidence:
        return f"{title} ({finding.target}): {evidence}"
    return f"{title} ({finding.target})"


_BANNER_RULE_ID = "insidia.infra.cve.banner"
_LOW_RULE_ID = "insidia.low-assurance"


def _sarif_banner_note(
    control: dict[str, str | int], endpoints: dict[str, str]
) -> dict[str, object] | None:
    warning = _banner_warning(control)
    if not warning:
        return None
    target_name = _control_text(control, "target") or "target"
    endpoint = endpoints.get(target_name, "") or target_name
    return {
        "ruleId": _BANNER_RULE_ID,
        "level": "note",
        "message": {"text": mask(warning)},
        "properties": {
            "engine": "insidia",
            "severity": "info",
            "confidence": "low",
            "security-severity": "0.0",
        },
        "locations": [_endpoint_location(target_name, endpoint)],
    }


def _banner_rule(warning: str) -> dict[str, object]:
    return {
        "id": _BANNER_RULE_ID,
        "name": "infra.cve",
        "shortDescription": {"text": "Banner version is not a vulnerability assessment"},
        "fullDescription": {"text": warning},
        "help": {"text": warning, "markdown": warning},
        "properties": {"security-severity": "0.0", "tags": ["security"]},
    }


def _stamp_assurance(note: dict[str, object], control: dict[str, str | int]) -> None:
    if control.get("result") != "pass" or control.get("assurance") != "low":
        return
    properties = note.get("properties")
    if not isinstance(properties, dict):
        return
    properties["assurance"] = "low"
    properties["low_assurance"] = True
    reason = _control_text(control, "assurance_reason").strip()
    if reason:
        properties["assurance_reason"] = reason


def _sarif_low_assurance_note(
    control: dict[str, str | int], endpoints: dict[str, str]
) -> dict[str, object] | None:
    if control.get("result") != "pass" or control.get("assurance") != "low":
        return None
    if _banner_warning(control):
        return None
    reason = _control_text(control, "assurance_reason").strip()
    target_name = _control_text(control, "target") or "target"
    endpoint = endpoints.get(target_name, "") or target_name
    family = _control_text(control, "id") or "check"
    properties: dict[str, object] = {
        "assurance": "low",
        "low_assurance": True,
        "family": family,
        "security-severity": "0.0",
    }
    if reason:
        properties["assurance_reason"] = reason
    return {
        "ruleId": _LOW_RULE_ID,
        "level": "note",
        "message": {"text": mask(_low_assurance_label(reason))},
        "properties": properties,
        "locations": [_endpoint_location(target_name, endpoint)],
    }


def _low_assurance_rule() -> dict[str, object]:
    summary = "A passing check included a limited result."
    return {
        "id": _LOW_RULE_ID,
        "name": "low-assurance",
        "shortDescription": {"text": "Pass with low assurance"},
        "fullDescription": {"text": summary},
        "help": {"text": summary, "markdown": summary},
        "properties": {"security-severity": "0.0", "tags": ["security"]},
    }


def _sarif(
    findings: list[Finding],
    controls: list[dict[str, str | int]] | None = None,
    targets: tuple[tuple[str, str, str], ...] = (),
    verdict: str = "pass",
) -> dict[str, object]:
    rules = []
    seen: set[str] = set()
    results = []
    for finding in findings:
        if finding.probe not in seen:
            seen.add(finding.probe)
            rules.append(_sarif_rule(finding))
        result: dict[str, object] = {
            "ruleId": finding.probe,
            "level": _sarif_level(finding.severity),
            "message": {"text": _sarif_message(finding)},
            "properties": {
                "engine": finding.engine,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "security-severity": f"{finding.risk_score:.1f}",
            },
        }
        result["locations"] = [_sarif_result_location(finding)]
        results.append(result)
    endpoints = {name: endpoint for name, _kind, endpoint in targets}
    low_notes: list[dict[str, object]] = []
    for control in controls or []:
        warning = _banner_warning(control)
        note = _sarif_banner_note(control, endpoints)
        if warning and note is not None:
            _stamp_assurance(note, control)
            rule_id = _BANNER_RULE_ID
            if rule_id not in seen:
                seen.add(rule_id)
                rules.append(_banner_rule(mask(warning)))
            results.append(note)
            continue
        extra = _sarif_low_assurance_note(control, endpoints)
        if extra is not None:
            low_notes.append(extra)
    if low_notes and _LOW_RULE_ID not in seen:
        seen.add(_LOW_RULE_ID)
        rules.append(_low_assurance_rule())
    results.extend(low_notes)
    low, reason = low_assurance_summary(verdict, list(controls or []))
    properties: dict[str, object] = {"low_assurance": low, "assurance_reason": reason}
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "Insidia", "version": __version__, "rules": rules}},
                "results": results,
                "properties": properties,
            }
        ],
    }


def _write_sarif(
    directory: Path,
    findings: list[Finding],
    controls: list[dict[str, str | int]],
    targets: tuple[tuple[str, str, str], ...],
    verdict: str,
) -> None:
    (directory / "results.sarif").write_text(
        json.dumps(_sarif(findings, controls, targets, verdict), indent=2) + "\n",
        encoding="utf-8",
    )
