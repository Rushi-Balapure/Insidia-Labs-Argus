"""Render the offline HTML report for one run."""

from __future__ import annotations

import base64
import hashlib
import html
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from insidia.findings import Finding
from insidia.mask import mask
from insidia.report_script import REPORT_SCRIPT
from insidia.report_styles import REPORT_CSS as _CSS
from insidia.report_ui import (
    CheckCounts,
    check_counts,
    coverage_filter,
    framework_chart,
    framework_groups,
    outcomes_chart,
    report_identity,
    severity_chart,
    status_badge,
    summary_metrics,
    tested_chart,
    untested_reason,
    verdict_strip,
)
from insidia.run_assurance import _control_text, _low_assurance_label
from insidia.run_baseline import _FixedFinding, _target_names
from insidia.score import Score, severity_rank


def _brand_lockup(variant: str) -> str:
    """Embed the approved outlined logo, with document-unique SVG identifiers."""
    svg = (Path(__file__).resolve().parent / "brand" / f"lockup-{variant}.svg").read_text()
    for identifier in re.findall(r'\bid="([^"]+)"', svg):
        qualified = f"report-logo-{variant}-{identifier}"
        svg = svg.replace(f'id="{identifier}"', f'id="{qualified}"')
        svg = svg.replace(f"url(#{identifier})", f"url(#{qualified})")
        svg = svg.replace(f'href="#{identifier}"', f'href="#{qualified}"')
    svg = svg.replace("<svg ", '<svg aria-hidden="true" focusable="false" ', 1)
    return (
        f'<span class="report-logo report-logo-{variant}" role="img" '
        f'aria-label="Insidia Labs">{svg.strip()}</span>'
    )


def _passed_text(passed: int, low: int) -> str:
    """How many passes, and how many of those have assurance low."""
    return f"{passed} passed ({low} low assurance)"


def _score_rows(scores: tuple[Score, ...]) -> str:
    lines = []
    for score in scores:
        lines.append(
            "<tr>"
            f'<td data-l="Framework">{_escape(score.title)}</td>'
            f'<td class="number count-fail" data-l="Failed">{score.failed}</td>'
            f'<td class="number count-pass" data-l="Passed">'
            f"{_escape(_passed_text(score.passed, score.low_assurance))}</td>"
            f'<td class="number count-nt" data-l="Not tested">{score.not_tested}</td>'
            "</tr>"
        )
    return "\n".join(lines)


_BUCKETS = ("critical", "high", "medium", "low", "informational")
_BUCKET_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Info",
}
_BUCKET_CLASS = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}


def _bucket(severity: str) -> str:
    if severity in {"info", "informational", "unspecified"}:
        return "informational"
    if severity in _BUCKETS:
        return severity
    return "informational"


@dataclass(frozen=True)
class _ReportData:
    run_id: str
    policy: str
    passed: bool
    findings: list[Finding]
    controls: list[dict[str, str | int]]
    skips: list[str]
    scores: tuple[Score, ...]
    targets: tuple[tuple[str, str, str], ...]
    started_at: str
    finished_at: str
    duration_s: float
    version: str
    execution_status: str
    verdict: str
    coverage_name: str
    scope_hosts: tuple[str, ...]
    config_digest: str
    judge: str
    rate_limits: list[dict[str, object]]
    engines: tuple[str, ...]
    artefacts: tuple[tuple[str, str], ...]
    baseline_id: str = ""
    fixed: tuple[_FixedFinding, ...] = ()
    new_count: int = 0
    still_open_count: int = 0
    fixed_count: int = 0
    low_assurance: bool = False
    assurance_reason: str = ""


def _render(report: _ReportData) -> str:
    names = _target_names(report.findings, report.controls, report.targets)
    title = "Security scan report" + (f": {', '.join(names)}" if names else "")
    parts = (
        _report_head(report, title),
        _report_navigation(len(report.findings)),
        '<main id="main" tabindex="-1">',
        _report_pages(report, names),
        "</main>",
        _report_footer(report.run_id),
        '<div id="report-tooltip" role="tooltip" hidden></div>',
        f"<script data-report-ui>{REPORT_SCRIPT}</script>",
        "</body></html>",
    )
    document = "\n".join(part for part in parts if part) + "\n"
    return _with_content_security_policy(document)


def _report_pages(report: _ReportData, names: list[str]) -> str:
    pages = (
        ("summary", _report_overview(report)),
        ("findings", _report_findings(report, names)),
        (
            "remediation",
            '<h2 id="remediation">Remediation summary</h2>' + _remediation_table(report.findings),
        ),
        (
            "targets",
            '<h2 id="targets">Targets</h2>'
            + _targets_table(report.findings, report.controls, report.targets),
        ),
        (
            "coverage",
            '<h2 id="coverage">Coverage by target</h2>'
            + _coverage_by_target(report.controls, report.skips),
        ),
        ("frameworks", _report_frameworks(report.controls, report.scores)),
        ("scaninfo", _report_scan_information(report)),
    )
    sections = []
    for page, content in pages:
        hidden = "" if page == "summary" else " hidden"
        sections.append(
            f'<section class="report-page" data-page="{page}" '
            f'aria-labelledby="{page}"{hidden}>{content}</section>'
        )
    fallback = (
        "<noscript><style>.report-page[hidden] { display: block; }</style>"
        '<p class="note">JavaScript is disabled. '
        "All report sections are shown below.</p></noscript>"
    )
    return fallback + "\n".join(sections)


def _report_head(report: _ReportData, title: str) -> str:
    return "\n".join(
        (
            '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{_escape(title)}</title><style>{_CSS}</style></head><body>",
            '<a class="skip-link" href="#main">Skip to report</a>',
            '<header><div class="header-inner">',
            _brand_lockup("dark"),
            _brand_lockup("light"),
            '<div class="report-heading">',
            f"<h1>{_escape(title)}</h1>",
            report_identity(
                report.run_id, report.started_at, report.policy, report.version, report.engines
            ),
            "</div></div></header>",
        )
    )


def _report_navigation(findings: int) -> str:
    pages = (
        ("summary", "Overview"),
        ("findings", f"Findings ({findings})"),
        ("remediation", "Remediation"),
        ("targets", "Targets"),
        ("coverage", "Coverage"),
        ("frameworks", "Frameworks"),
        ("scaninfo", "Scan info"),
    )
    links = []
    for page, label in pages:
        current = ' aria-current="page"' if page == "summary" else ""
        links.append(f'<a href="?page={page}" data-page-link="{page}"{current}>{label}</a>')
    return (
        '<nav aria-label="Report sections"><div class="report-nav-inner">'
        + "".join(links)
        + "</div></nav>"
    )


def _report_overview(report: _ReportData) -> str:
    counts = check_counts(report.controls)
    status = "pass" if report.passed else "fail"
    summary = _executive_summary(
        run_id=report.run_id,
        policy=report.policy,
        findings=report.findings,
        controls=report.controls,
        targets=report.targets,
        execution_status=report.execution_status,
        verdict=report.verdict,
        baseline_id=report.baseline_id,
        new_count=report.new_count,
        still_open_count=report.still_open_count,
        fixed_count=report.fixed_count,
    )
    return "\n".join(
        (
            '<h2 id="summary">Executive summary</h2>',
            verdict_strip(report.execution_status, report.policy, report.verdict, counts),
            summary_metrics(counts, len(report.findings)),
            '<div class="charts-grid">',
            tested_chart(counts),
            outcomes_chart(counts),
            "</div>",
            '<details class="summary-detail"><summary>Scan summary and limitations</summary>',
            f'<p class="status {status}">{_escape(summary)}</p></details>',
        )
    )


def _report_findings(report: _ReportData, names: list[str]) -> str:
    return "\n".join(
        (
            '<h2 id="findings">Findings by severity</h2>',
            severity_chart([finding.severity for finding in report.findings]),
            _finding_cards(report.findings, report.run_id, names),
            _fixed_section(report.baseline_id, report.fixed),
        )
    )


def _report_frameworks(controls: list[dict[str, str | int]], scores: tuple[Score, ...]) -> str:
    counts = CheckCounts(
        sum(s.passed for s in scores),
        sum(s.failed for s in scores),
        0,
        sum(s.not_tested for s in scores),
    )
    return "\n".join(
        (
            '<h2 id="frameworks">Framework coverage</h2>',
            '<p class="note">Counts below are mapped framework items, not individual checks. '
            "An item can contain multiple checks. This is coverage, not a security rating.</p>",
            framework_chart(scores),
            '<table class="framework-scores">',
            "<thead><tr><th>Framework</th><th>Failed</th>"
            "<th>Passed</th><th>Not tested</th></tr></thead>",
            f"<tbody>\n{_score_rows(scores)}\n</tbody></table>",
            '<details class="framework-list"><summary>OWASP item list</summary>',
            '<p class="note">Not tested means no passing or failing check mapped to this item. '
            "See Coverage by target for recorded check limitations.</p>",
            coverage_filter(
                framework_groups(controls, scores),
                counts,
                prefix="framework-filter",
                unit="framework items",
            ),
            "</details>",
        )
    )


def _report_scan_information(report: _ReportData) -> str:
    verdict = report.verdict
    if report.low_assurance:
        verdict = _low_assurance_label(report.assurance_reason)
    return '<h2 id="scaninfo">Scan information</h2>\n' + _scan_table(
        report.run_id,
        report.started_at,
        report.finished_at,
        report.duration_s,
        report.version,
        report.policy,
        report.coverage_name,
        report.execution_status,
        verdict,
        report.scope_hosts,
        report.skips,
        report.config_digest,
        report.judge,
        report.rate_limits,
        report.engines,
        report.artefacts,
    )


def _report_footer(run_id: str) -> str:
    return (
        '<footer><div class="footer-inner"><section aria-labelledby="downloads">'
        '<h2 id="downloads">Report files</h2>'
        '<p class="note">Download the evidence and results from this run.</p>'
        f'<div class="artifact-links">{_artifact_links()}</div></section>'
        '<section class="rerun-panel" aria-labelledby="repeat-scan">'
        '<h2 id="repeat-scan">Repeat this scan</h2>'
        '<p class="note">Run this command from your project directory.</p>'
        f'<pre class="rerun-command"><code>insidia rerun {_escape(run_id)}</code></pre>'
        '<p class="footer-note">Insidia Labs · Test evidence, not a certification.</p>'
        "</section></div></footer>"
    )


def _artifact_links() -> str:
    files = (
        ("findings.json", "Structured findings"),
        ("findings.csv", "Spreadsheet export"),
        ("results.sarif", "Code scanning results"),
        ("benchmark.json", "Coverage and check results"),
        ("manifest.json", "Run metadata and checksums"),
        ("report.html", "Offline HTML report"),
    )
    return "".join(
        f'<a class="artifact-link" href="{name}" download><strong>{name}</strong>'
        f'<span>{description}</span><span class="download-label">Download ↓</span></a>'
        for name, description in files
    )


def _executive_summary(
    run_id: str,
    policy: str,
    findings: list[Finding],
    controls: list[dict[str, str | int]],
    targets: tuple[tuple[str, str, str], ...],
    execution_status: str,
    verdict: str,
    baseline_id: str = "",
    new_count: int = 0,
    still_open_count: int = 0,
    fixed_count: int = 0,
) -> str:
    """Fail, pass, and incomplete summaries share one shape and one ending."""

    names = _target_names(findings, controls, targets)
    counts = check_counts(controls)
    noun = "target" if len(names) == 1 else "targets"
    target_clause = f"{len(names)} {noun}" + (f" ({', '.join(names)})" if names else "")
    sentences = [
        f"Insidia ran {counts.tested} of {counts.total} checks against {target_clause}.",
        _summary_outcome(policy, verdict, execution_status, findings),
        _summary_serious_finding(findings),
        _summary_assurance(counts),
    ]
    if execution_status != "complete":
        sentences.extend(
            (
                f"Results below cover {counts.tested} checks only.",
                f"Re-run with `insidia rerun {run_id}`.",
            )
        )
    if baseline_id:
        sentences.append(
            f"{new_count} new, {still_open_count} still open, and {fixed_count} fixed "
            f"since {mask(baseline_id)}."
        )
    sentences.append("This report is test evidence, not a certification.")
    return " ".join(sentences)


def _summary_outcome(policy: str, verdict: str, execution: str, findings: list[Finding]) -> str:
    counts = {bucket: 0 for bucket in _BUCKETS}
    for finding in findings:
        counts[_bucket(finding.severity)] += 1
    severity_counts = ", ".join(
        f"{counts[bucket]} {_BUCKET_LABEL[bucket].lower()}" for bucket in _BUCKETS
    )
    outcome = {"pass": "passed", "fail": "did not pass"}.get(verdict, "is inconclusive")
    noun = "finding" if len(findings) == 1 else "findings"
    sentence = f"Policy {policy} {outcome}: {len(findings)} {noun} ({severity_counts})."
    return (
        sentence if execution == "complete" else f"The scan did not finish: {execution}. {sentence}"
    )


def _summary_serious_finding(findings: list[Finding]) -> str:
    if not findings:
        return "The most serious finding is none."
    top = findings[0]
    return (
        f"The most serious finding is {top.title or top.attack}, severity {top.severity}, "
        f"score {top.risk_score:.1f}, target {top.target}."
    )


def _summary_assurance(counts: CheckCounts) -> str:
    weak = (
        "1 passed check has low assurance"
        if counts.low_assurance == 1
        else f"{counts.low_assurance} passed checks have low assurance"
    )
    untested = (
        "1 check was not tested"
        if counts.untested == 1
        else f"{counts.untested} checks were not tested"
    )
    return (
        f"{weak} and {untested}. "
        "Checks that were not tested are not evidence that those risks are absent."
    )


def _fixed_section(baseline_id: str, fixed: tuple[_FixedFinding, ...]) -> str:
    """Baseline findings whose evidence hash is absent. Evidence text is not printed."""
    if not baseline_id:
        return ""
    rows = []
    for item in fixed:
        title = _escape(mask(item.title))
        target = _escape(mask(item.target))
        fingerprint = _escape(mask(item.evidence_hash))
        rows.append(f"<li>{title} · {target} · <code>{fingerprint}</code></li>")
    body = "<ul>" + "".join(rows) + "</ul>"
    heading = _escape(mask(baseline_id))
    return f'<h2 id="fixed">Fixed since {heading}</h2>\n{body}'


def _targets_table(
    findings: list[Finding],
    controls: list[dict[str, str | int]],
    targets: tuple[tuple[str, str, str], ...],
) -> str:
    meta = {name: (kind, endpoint) for name, kind, endpoint in targets}
    names = _target_names(findings, controls, targets)
    if not names:
        return '<p class="note">No targets.</p>'
    rows = []
    for name in names:
        kind, endpoint = meta.get(name, ("", ""))
        if not kind:
            kind = next((item.target_kind for item in findings if item.target == name), "")
        if not endpoint:
            endpoint = next((item.endpoint for item in findings if item.target == name), "")
        counts = {bucket: 0 for bucket in _BUCKETS}
        for finding in findings:
            if finding.target == name:
                counts[_bucket(finding.severity)] += 1
        tallies = {"fail": 0, "pass": 0, "not tested": 0}
        low = 0
        for control in controls:
            if control.get("target") != name:
                continue
            result = control.get("result", "")
            if result in tallies:
                tallies[result] += 1
            if result == "pass" and control.get("assurance") == "low":
                low += 1
        chips = "".join(
            f'<td data-l="{_BUCKET_LABEL[bucket]}">{counts[bucket]}</td>' for bucket in _BUCKETS
        )
        summary = (
            f"{tallies['fail']} fail · {_passed_text(tallies['pass'], low)} · "
            f"{tallies['not tested']} not tested"
        )
        rows.append(
            "<tr>"
            f'<td data-l="Target">{_escape(name)}</td>'
            f'<td data-l="Kind">{_escape(kind)}</td>'
            f'<td data-l="Endpoint"><code>{_escape(endpoint)}</code></td>'
            f"{chips}"
            f'<td data-l="Checks">{_escape(summary)}</td>'
            "</tr>"
        )
    head = (
        "<tr><th>Target</th><th>Kind</th><th>Endpoint</th>"
        "<th>Crit</th><th>High</th><th>Med</th><th>Low</th><th>Info</th>"
        "<th>Checks</th></tr>"
    )
    return f'<table class="targets"><thead>{head}</thead><tbody>{"".join(rows)}</tbody></table>'


# A check with three or fewer hits stays a flat card. More than three share one header.
_GROUP_AFTER = 3
_PACKAGE_PIN = re.compile(
    r"(?<![A-Za-z0-9_])(@?[A-Za-z0-9_][\w.-]{0,60}==[A-Za-z0-9][\w.+-]{0,40})"
)
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}")


def _finding_cards(findings: list[Finding], run_id: str, target_names: list[str]) -> str:
    """Cards for each hit. A busy check collapses, and two targets can be filtered."""
    if not findings:
        return (
            '<div class="empty-findings"><strong>No findings detected '
            "in the checks performed.</strong>"
            "<p>Review untested checks and coverage limitations "
            "before interpreting this result.</p>"
            '<a href="?page=coverage">Review check coverage →</a></div>'
        )
    names = list(target_names)
    for finding in findings:
        if finding.target and finding.target not in names:
            names.append(finding.target)
    tokens = {name: f"t{index}" for index, name in enumerate(names)} if len(names) >= 2 else {}
    cards = _render_finding_cards(findings, run_id, tokens)
    if not tokens:
        return "\n".join(cards)
    return _by_target_filter(cards, names)


def _render_finding_cards(
    findings: list[Finding], run_id: str, tokens: dict[str, str]
) -> list[str]:
    buckets: dict[str, list[Finding]] = {}
    order: list[str] = []
    for finding in findings:
        key = _check_key(finding)
        if key not in buckets:
            order.append(key)
            buckets[key] = []
        buckets[key].append(finding)
    cards: list[str] = []
    index = 0
    for key in order:
        items = buckets[key]
        if len(items) > _GROUP_AFTER:
            cards.append(_grouped_finding_card(items, index, run_id, tokens))
            index += 1
            continue
        for finding in items:
            cards.append(_finding_card(finding, index, run_id, tokens.get(finding.target, "")))
            index += 1
    return cards


def _check_key(finding: Finding) -> str:
    return finding.check_id or finding.probe or finding.attack


def _finding_card(finding: Finding, index: int, run_id: str, token: str = "") -> str:
    bucket = _bucket(finding.severity)
    css = _BUCKET_CLASS[bucket]
    label = _BUCKET_LABEL[bucket].upper()
    opened = " open" if index < 2 else ""
    title = finding.title or finding.attack
    check = _check_key(finding)
    target_attr = f' data-target="{token}"' if token else ""
    right = f"{finding.target} · {label} {finding.risk_score:.1f}"
    return (
        f'<details class="finding"{target_attr}{opened}>'
        f"{_finding_summary(css, check, title, right, finding.engine)}"
        f"<dl>{_finding_body(finding, run_id)}</dl></details>"
    )


def _grouped_finding_card(
    items: list[Finding], index: int, run_id: str, tokens: dict[str, str]
) -> str:
    """One header for a check, then every hit's file, package, and CVE."""
    worst = items[0]
    bucket = _bucket(worst.severity)
    css = _BUCKET_CLASS[bucket]
    label = _BUCKET_LABEL[bucket].upper()
    opened = " open" if index < 2 else ""
    title = worst.title or worst.attack
    check = _check_key(worst)
    targets = list(dict.fromkeys(item.target for item in items if item.target))
    if len(targets) == 1:
        where = targets[0]
        token = tokens.get(where, "")
        target_attr = f' data-target="{token}"' if token else ""
    else:
        where = f"{len(targets)} targets" if targets else (worst.target or "unspecified")
        target_attr = ""
    noun = "location" if len(items) == 1 else "locations"
    right = f"{where} · {len(items)} {noun} · {label} {worst.risk_score:.1f}"
    show_target = bool(tokens)
    rows = "".join(
        _location_row(item, tokens.get(item.target, ""), show_target=show_target) for item in items
    )
    return (
        f'<details class="finding"{target_attr}{opened}>'
        f"{_finding_summary(css, check, title, right, worst.engine)}"
        f'<ul class="locations">{rows}</ul>'
        f"<dl>{_finding_body(worst, run_id)}</dl></details>"
    )


def _finding_summary(css: str, check: str, title: str, right: str, engine: str) -> str:
    return (
        f'<summary class="bar bar-{css}">'
        f'<span class="sev sev-{css}">{css.upper()}</span>'
        f'<span class="pid">{_escape(check)}</span> {_escape(title)}'
        f'<span class="finding-engine">Engine: {_escape(engine)}</span>'
        f'<span class="right">{_escape(right)}</span>'
        f"</summary>"
    )


def _finding_body(finding: Finding, run_id: str) -> str:
    bucket = _bucket(finding.severity)
    css = _BUCKET_CLASS[bucket]
    label = _BUCKET_LABEL[bucket].upper()
    factors = "; ".join(finding.risk_factors) or "base score"
    reported = len(finding.engines) or 1
    engine_word = "engine" if reported == 1 else "engines"
    corroborated = "cross-validated" if finding.cross_validated else "not cross-validated"
    risk_factor = (
        f'<span class="sev sev-{css}">{label}</span>'
        f" · confidence {_escape(finding.confidence)}"
        f" · reported by {reported} {engine_word} ({corroborated})"
    )
    fields = (
        ("Synopsis", _escape(finding.synopsis or finding.remediation)),
        ("Description", _escape(finding.description or finding.remediation)),
        ("Solution", _escape(finding.remediation)),
        ("Risk factor", risk_factor),
        (
            "Insidia Risk Score",
            _escape(f"{finding.risk_score:.1f}/10 ({factors})"),
        ),
        ("References", _escape(_reference_text(finding.taxonomy))),
        ("See Also", _see_also(finding.references)),
        ("Plugin output", _plugin_output(finding)),
        ("Re-run", f"<code>insidia rerun {_escape(run_id)}</code>"),
    )
    return "".join(f"<dt>{name}</dt><dd>{value}</dd>" for name, value in fields)


def _location_row(finding: Finding, token: str, show_target: bool) -> str:
    attr = f' data-target="{token}"' if token else ""
    return f'<li class="loc"{attr}>{_location_html(finding, show_target=show_target)}</li>'


def _location_html(finding: Finding, show_target: bool) -> str:
    file_line = _file_line_text(finding.location)
    pins = _package_pins(finding)
    cves = _cve_ids(finding)
    chunks: list[str] = []
    if show_target and finding.target:
        chunks.append(_escape(finding.target))
    if file_line:
        chunks.append(f"<code>{_escape(file_line)}</code>")
    chunks.extend(f"<code>{_escape(pin)}</code>" for pin in pins)
    chunks.extend(_escape(cve) for cve in cves)
    if not file_line and not pins and not cves:
        fallback = finding.endpoint or finding.location
        if fallback:
            chunks.append(f"<code>{_escape(fallback)}</code>")
        elif not chunks:
            chunks.append(_escape(finding.target or "unspecified"))
    return " · ".join(chunks)


def _file_line_text(location: str) -> str:
    if not location or "://" in location or "==" in location:
        return ""
    path, separator, line = location.rpartition(":")
    if separator and line.isdigit() and path:
        return f"{path}:{line}"
    return ""


def _package_pins(finding: Finding) -> list[str]:
    found: list[str] = []
    for pin in _PACKAGE_PIN.findall(_location_source(finding)):
        if pin not in found:
            found.append(pin)
    return found


def _cve_ids(finding: Finding) -> list[str]:
    if finding.cve:
        return list(dict.fromkeys(finding.cve))
    found: list[str] = []
    for cve in _CVE_ID.findall(_location_source(finding)):
        if cve not in found:
            found.append(cve)
    return found


def _location_source(finding: Finding) -> str:
    parts = [finding.location, finding.response]
    parts.extend(item.evidence for item in finding.observations)
    return "\n".join(parts)


def _by_target_filter(cards: list[str], names: list[str]) -> str:
    """All targets stays selected. Choosing a target hides the other findings."""
    controls = [
        '<input type="radio" name="by-target" id="flt-all" checked>',
        '<label for="flt-all">All targets</label>',
    ]
    rules: list[str] = []
    for index, name in enumerate(names):
        token = f"t{index}"
        controls.append(f'<input type="radio" name="by-target" id="flt-{index}">')
        controls.append(f'<label for="flt-{index}">{_escape(name)}</label>')
        rules.append(
            f"#flt-{index}:checked ~ .finding"
            f':not([data-target="{token}"]):not(:has([data-target="{token}"]))'
            "{display:none}"
        )
        rules.append(
            f'#flt-{index}:checked ~ .finding .loc:not([data-target="{token}"]){{display:none}}'
        )
    style = "<style>" + " ".join(rules) + "</style>"
    return '<div class="by-target">' + "".join(controls) + style + "\n".join(cards) + "</div>"


def _reference_text(taxonomy: tuple[str, ...]) -> str:
    labels: list[str] = []
    for tag in taxonomy:
        prefix, separator, item = tag.partition(":")
        if not separator:
            labels.append(tag)
            continue
        if prefix == "owasp-llm":
            labels.append(f"OWASP {item}")
        elif prefix == "owasp-web":
            labels.append(f"OWASP Web {item}")
        elif prefix == "owasp-api":
            labels.append(f"OWASP API {item}")
        elif prefix == "owasp-asi":
            labels.append(f"OWASP ASI {item}")
        elif prefix == "cwe":
            labels.append(item)
        else:
            labels.append(tag)
    return " · ".join(labels) or "None"


def _safe_href(url: str) -> str | None:
    """http(s) or a same-document relative URL, escaped for an href attribute."""
    if not url or any(ord(char) <= 32 or char == "\x7f" or char == "\\" for char in url):
        return None
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme in {"http", "https"}:
        return _escape(url) if parsed.netloc else None
    if scheme or parsed.netloc or url.startswith("//") or ":" in url:
        return None
    return _escape(url)


def _see_also(urls: tuple[str, ...]) -> str:
    links = []
    for url in urls:
        href = _safe_href(url)
        if href is not None:
            links.append(f'<a href="{href}">{_escape(url)}</a>')
        elif url:
            links.append(_escape(url))
    return "<br>".join(links) or "None"


# One card shows this many characters of plugin output. A longer body keeps
# its start, and the card names this cap when that body was cut.
_PLUGIN_OUTPUT_CAP = 500


def _plugin_output(finding: Finding) -> str:
    """Masked evidence as text. Counts and the endpoint or file:line sit with it."""
    excerpt, truncated = _capped_plugin_excerpt(finding)
    if finding.location and "://" not in finding.location:
        affected = finding.location
    else:
        affected = finding.endpoint or finding.location or finding.target
    kind = f" · {_escape(finding.target_kind)}" if finding.target_kind else ""
    cap = f" · truncated to {_PLUGIN_OUTPUT_CAP} characters" if truncated else ""
    lines = [
        f"<pre>{_escape(excerpt)}</pre>",
        (
            f"<p>{len(finding.observations)} observations"
            f" · probe <code>{_escape(finding.probe)}</code>"
            f" · engine {_escape(finding.engine)}{cap}</p>"
        ),
        f"<p>evidence_hash <code>{_escape(finding.evidence_hash)}</code></p>",
        f"<p>Affected {_escape(finding.target)}{kind} · <code>{_escape(affected)}</code></p>",
    ]
    return "".join(lines)


def _capped_plugin_excerpt(finding: Finding) -> tuple[str, bool]:
    """One excerpt. Observations that already hold the response are not copied again."""
    text = _plugin_source(finding)
    if len(text) <= _PLUGIN_OUTPUT_CAP:
        return text, False
    first, _, _rest = text.partition("\n")
    excerpt = first if first.strip() else text[:_PLUGIN_OUTPUT_CAP]
    if len(excerpt) > _PLUGIN_OUTPUT_CAP:
        excerpt = excerpt[:_PLUGIN_OUTPUT_CAP]
    return excerpt, True


def _plugin_source(finding: Finding) -> str:
    chunks: list[str] = []
    for item in finding.observations:
        if item.evidence and item.evidence not in chunks:
            chunks.append(item.evidence)
    response = finding.response
    if response and not any(response in chunk for chunk in chunks):
        chunks.append(response)
    return "\n".join(chunks)


def _remediation_table(findings: list[Finding]) -> str:
    if not findings:
        return '<p class="note">No remediation actions were recorded for this run.</p>'
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.remediation, []).append(finding)
    ranked = sorted(
        grouped.items(),
        key=lambda item: (
            min(severity_rank(finding.severity) for finding in item[1]),
            -len(item[1]),
            item[0],
        ),
    )
    rows = []
    for text, items in ranked:
        worst = min(items, key=lambda finding: severity_rank(finding.severity))
        bucket = _bucket(worst.severity)
        names = ", ".join(sorted({finding.target for finding in items}))
        rows.append(
            "<tr>"
            f'<td data-l="Action">{_escape(text)}</td>'
            f'<td data-l="Fixes">{len(items)}</td>'
            f'<td data-l="Worst"><span class="sev sev-{_BUCKET_CLASS[bucket]}">'
            f"{_BUCKET_LABEL[bucket]}</span></td>"
            f'<td data-l="Targets">{_escape(names)}</td>'
            "</tr>"
        )
    return (
        '<table class="remediation"><thead><tr><th>Action</th><th>Fixes</th>'
        f"<th>Worst</th><th>Targets</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _coverage_by_target(controls: list[dict[str, str | int]], skips: list[str]) -> str:
    if not controls:
        return '<p class="note">No checks were recorded.</p>'
    by_target: dict[str, list[dict[str, str | int]]] = {}
    for control in controls:
        by_target.setdefault(str(control.get("target", "")), []).append(control)
    content = "\n".join(_coverage_target(name, rows, skips) for name, rows in by_target.items())
    return coverage_filter(content, check_counts(controls), prefix="check-filter", unit="checks")


def _coverage_target(name: str, controls: list[dict[str, str | int]], skips: list[str]) -> str:
    counts = check_counts(controls)
    body = "".join(_coverage_check_row(control, skips) for control in controls)
    return (
        f"<h3>{_escape(name or 'Unspecified target')}</h3>"
        f'<p class="note">{_passed_text(counts.passed, counts.low_assurance)}</p>'
        f'<div class="coverage-checks">{body}</div>'
    )


def _coverage_check_row(control: dict[str, str | int], skips: list[str]) -> str:
    result = _control_text(control, "result")
    reason = ""
    if result == "pass" and _control_text(control, "assurance") == "low":
        reason = _control_text(control, "assurance_reason").strip()
        result = "pass (low assurance)"
    badge = status_badge(result, uppercase=True, reason=reason)
    why = _coverage_why(control, skips)
    outcome = _control_outcome(control)
    explanation = untested_reason(why) if outcome == "not tested" else f"<p>{_escape(why)}</p>"
    counts = "".join(
        f"<div><dt>{label}</dt><dd>{_escape(str(control[key]))}</dd></div>"
        for key, label in (("probes", "Probes sent"), ("requests", "Requests sent"))
        if key in control
    )
    return (
        f'<details class="check-accordion coverage-row" data-result="{_escape(outcome)}">'
        '<summary><span class="check-name">'
        f"<code>{_escape(str(control.get('id', '')))}</code></span>"
        f'<span data-l="Result">{badge}</span><span class="accordion-cue">Details</span></summary>'
        f'<div class="accordion-body"><div data-l="Why">{explanation}</div>'
        f'<dl class="check-metadata">{counts}</dl></div></details>'
    )


def _control_outcome(control: dict[str, str | int]) -> str:
    result = _control_text(control, "result")
    return result if result in {"pass", "fail", "info"} else "not tested"


# Same cause, so the same sentence. Different causes must not share this text.
_JUDGE_WHY = {
    "ai.harmful_content_policy": "needs a judge model: `models: {}`",
    "ai.bias": "needs a judge model: `models: {}`",
    "ai.citation_groundedness": "needs a judge model: `models: {}`",
}


def _sent_clause(control: dict[str, str | int]) -> str:
    value = control.get("probes", 0)
    count = value if isinstance(value, int) else 0
    if count <= 0:
        return ""
    noun = "prompt" if _control_text(control, "id").startswith("ai.") else "payload"
    if count != 1:
        noun += "s"
    return f"{count} {noun} sent"


def _coverage_why(control: dict[str, str | int], skips: list[str]) -> str:
    reason = ""
    if _control_text(control, "assurance") == "low":
        reason = _control_text(control, "assurance_reason").strip()
    detail = _control_text(control, "detail").strip()
    result = _control_text(control, "result")
    # Low assurance stays a pass. A non-pass keeps the reason and gains no sent clause.
    if reason and result != "pass":
        return reason
    if result in {"pass", "fail"} and "probes" in control:
        sent = _sent_clause(control)
        if result == "pass" and reason:
            if sent:
                return f"{sent}, none triggered. {reason}"
            return reason
        if sent and detail:
            return f"{sent}. {detail}"
        if detail:
            return detail
        if result == "pass":
            if sent:
                return f"{sent}, none triggered."
            return "none triggered."
        if sent:
            return f"{sent}. A probe reported this check."
        return "A probe reported this check."
    if reason:
        return reason
    if detail:
        return detail
    family = _control_text(control, "id")
    target = _control_text(control, "target")
    if result == "fail":
        return "A probe reported this check."
    if result == "pass":
        return "Probes ran and did not trigger."
    if result != "not tested":
        return result or "No result recorded."
    for skip in skips:
        if family and family in skip:
            return skip
    if family in _JUDGE_WHY:
        return _JUDGE_WHY[family]
    if family:
        return f"{family} was not run for {target or 'this target'}"
    return "No check id was recorded for this row."


def _rate_limits_text(rate_limits: list[dict[str, object]]) -> str:
    if not rate_limits:
        return "none"
    parts: list[str] = []
    for row in rate_limits:
        parts.append(f"{row['target']}: {row['rps']} rps, concurrency {row['concurrency']}")
    return "; ".join(parts)


def _skips_text(skips: list[str]) -> str:
    count = len(skips)
    if count == 0:
        return "0"
    return f"{count}: {'; '.join(skips)}"


def _artefacts_text(artefacts: tuple[tuple[str, str], ...]) -> str:
    return ", ".join(f"{name} {digest}" for name, digest in artefacts)


def _scan_table(
    run_id: str,
    started_at: str,
    finished_at: str,
    duration_s: float,
    version: str,
    policy: str,
    coverage_name: str,
    execution_status: str,
    verdict: str,
    scope_hosts: tuple[str, ...],
    skips: list[str],
    config_digest: str,
    judge: str,
    rate_limits: list[dict[str, object]],
    engines: tuple[str, ...],
    artefacts: tuple[tuple[str, str], ...],
) -> str:
    rows = (
        ("Run id", run_id),
        ("Started", started_at),
        ("Finished", finished_at),
        ("Duration", f"{duration_s:.3f}s"),
        ("Insidia version", version),
        ("Policy", policy),
        ("Coverage", coverage_name),
        ("Execution status", execution_status),
        ("Verdict", verdict),
        ("Scope hosts", ", ".join(scope_hosts)),
        ("models/judge", judge),
        ("Rate limits", _rate_limits_text(rate_limits)),
        ("Engines", ", ".join(engines)),
        ("Skips", _skips_text(skips)),
        ("Config digest", config_digest),
        ("Artefacts", _artefacts_text(artefacts)),
    )
    body = "".join(
        f"<tr><th>{_escape(label)}</th><td>{_escape(value)}</td></tr>" for label, value in rows
    )
    return f'<table class="scan">{body}</table>'


def _escape(value: str) -> str:
    return html.escape(value, quote=True)


def _embedded_blocks(document: str, tag: str) -> list[str]:
    return re.findall(rf"<{tag}\b[^>]*>(.*?)</{tag}>", document, flags=re.DOTALL)


def _csp_hash(content: str) -> str:
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


def _content_security_policy(document: str) -> str:
    def sources(tag: str) -> str:
        hashes = [f"'{_csp_hash(body)}'" for body in dict.fromkeys(_embedded_blocks(document, tag))]
        return " ".join(hashes) if hashes else "'none'"

    return (
        "default-src 'none'; "
        "img-src data:; "
        f"style-src {sources('style')}; "
        f"script-src {sources('script')}; "
        "base-uri 'none'; "
        "form-action 'none'"
    )


def _with_content_security_policy(document: str) -> str:
    meta = (
        '<meta http-equiv="Content-Security-Policy" content="'
        + _content_security_policy(document)
        + '">'
    )
    return document.replace("<head>", "<head>" + meta, 1)
