"""Repository engine plans and parsers."""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from pathlib import Path

from insidia.adapters import EngineHit, Invocation, ProbeSpec, RepoPath
from insidia.errors import EngineFailed
from insidia.upstream_support import _load_json, _program

# NuGuard imports litellm, which fetches a price table from GitHub unless told not to.
NUGUARD_ENV = {
    "LITELLM_LOCAL_MODEL_COST_MAP": "True",
    "LITELLM_TELEMETRY": "False",
}
_NUGUARD_SEVERITIES = frozenset({"critical", "high", "medium"})
# The only opt-in for Trivy and osv-scanner vulnerability database downloads.
_VULN_DB_OPT_IN = "INSIDIA_VULN_DB"


def _repo_prepare(engine: str) -> Callable[[ProbeSpec, RepoPath, Path], Invocation]:
    def prepare(spec: ProbeSpec, view: RepoPath, workspace: Path) -> Invocation:
        report = str(workspace / "report.json")
        source = str(view.path)
        args: tuple[str, ...]
        if engine == "nuguard":
            (workspace / "nuguard_run.py").write_text(_NUGUARD_PY, encoding="utf-8")
            return Invocation(
                _program("nuguard"),
                (str(workspace / "nuguard_run.py"), source, str(workspace)),
                "report.json",
                env=NUGUARD_ENV,
                timeout=300,
            )
        if engine == "mcp-scanner":
            args = (
                "--analyzers",
                "yara",
                "behavioral",
                source,
                "--format",
                "raw",
                "-o",
                report,
            )
        elif engine == "skillspector":
            args = ("scan", source, "--no-llm", "--format", "json", "-o", report)
        elif engine == "trivy":
            # --skip-db-update and --skip-java-db-update are Trivy 0.75 flags.
            # The first run errors locally instead of downloading a database.
            args = (
                "fs",
                "--format",
                "json",
                "--output",
                report,
                "--skip-version-check",
                *_vuln_db_flags("--skip-db-update", "--skip-java-db-update"),
                source,
            )
        elif engine == "osv-scanner":
            # --offline is osv-scanner 2.6. It uses a cached database and does not connect.
            args = (
                "scan",
                "source",
                "--recursive",
                "--format",
                "json",
                "--output-file",
                report,
                *_vuln_db_flags("--offline"),
                source,
            )
        elif engine == "gitleaks":
            args = (
                "detect",
                "--source",
                source,
                "--report-format",
                "json",
                "--report-path",
                report,
                "--no-git",
                "--exit-code",
                "0",
            )
        elif engine == "bandit":
            args = ("-r", source, "-f", "json", "-o", report, "-q")
        elif engine == "gosec":
            args = ("-fmt", "json", "-out", report, "-no-fail", f"{source}/...")
        else:
            raise ValueError(engine)
        return Invocation(_program(engine), args, "report.json", timeout=180)

    return prepare


def _repo_parser(engine: str) -> Callable[[Path, ProbeSpec], list[EngineHit]]:
    def parse(report: Path, spec: ProbeSpec) -> list[EngineHit]:
        loaded = _load_json(report)
        if engine == "gitleaks":
            return _gitleaks_hits(loaded, spec)
        if isinstance(loaded, dict) and "error" in loaded and "Results" not in loaded:
            raise EngineFailed(f"{engine} reported an error")
        reader = _REPO_RULES.get(engine)
        if reader is None:
            return []
        return [EngineHit(spec.upstream, spec.probe, rule, rule) for rule in reader(loaded)]

    return parse


def _bandit_rules(loaded: object) -> list[str]:
    if not isinstance(loaded, dict):
        raise EngineFailed("bandit report has an unexpected shape")
    rows = loaded.get("results")
    if not isinstance(rows, list):
        return []
    found: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        rule = row.get("test_id")
        if not isinstance(rule, str) or not rule:
            rule = row.get("issue_text")
        if isinstance(rule, str) and rule:
            found.append(rule)
    return found


def _gitleaks_hits(loaded: object, spec: ProbeSpec) -> list[EngineHit]:
    if not isinstance(loaded, list):
        raise EngineFailed("gitleaks report has an unexpected shape")
    hits: list[EngineHit] = []
    for row in loaded:
        if not isinstance(row, dict):
            raise EngineFailed("gitleaks report has a malformed record")
        rule = row.get("RuleID")
        if not isinstance(rule, str) or not rule:
            raise EngineFailed("gitleaks report has a malformed record")
        file = row.get("File")
        line = row.get("StartLine")
        location = ""
        if isinstance(file, str) and file:
            location = f"{file}:{line}" if isinstance(line, int) else file
        evidence = row.get("Match")
        if not isinstance(evidence, str) or not evidence:
            evidence = rule
        severity = row.get("Severity")
        hits.append(
            EngineHit(
                spec.upstream,
                spec.probe,
                evidence,
                evidence,
                location,
                severity if isinstance(severity, str) else "",
            )
        )
    return hits


def _trivy_rules(loaded: object) -> list[str]:
    if not isinstance(loaded, dict) or not isinstance(loaded.get("Results"), list):
        raise EngineFailed("trivy report has an unexpected shape")
    results = loaded["Results"]
    if not isinstance(results, list):
        raise EngineFailed("trivy report has an unexpected shape")
    found: list[str] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        vulns = result.get("Vulnerabilities")
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            rule = vuln.get("VulnerabilityID")
            if isinstance(rule, str) and rule:
                found.append(rule)
    return found


def _osv_rules(loaded: object) -> list[str]:
    if not isinstance(loaded, dict):
        return []
    results = loaded.get("results")
    if not isinstance(results, list):
        return []
    found: list[str] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        packages = result.get("packages")
        if not isinstance(packages, list):
            continue
        for package in packages:
            if not isinstance(package, dict):
                continue
            vulns = package.get("vulnerabilities")
            if not isinstance(vulns, list):
                continue
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                rule = vuln.get("id")
                if isinstance(rule, str) and rule:
                    found.append(rule)
    return found


def _gitleaks_rules(loaded: object) -> list[str]:
    if not isinstance(loaded, list):
        return []
    found: list[str] = []
    for row in loaded:
        if not isinstance(row, dict):
            continue
        rule = row.get("RuleID")
        if isinstance(rule, str) and rule:
            found.append(rule)
    return found


def _gosec_rules(loaded: object) -> list[str]:
    if not isinstance(loaded, dict):
        return []
    rows = loaded.get("Issues")
    if not isinstance(rows, list):
        return []
    found: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        rule = row.get("rule_id")
        if isinstance(rule, str) and rule:
            found.append(rule)
    return found


def _mcp_rules(loaded: object) -> list[str]:
    rows = loaded if isinstance(loaded, list) else None
    if rows is None:
        return []
    found: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        findings = row.get("findings")
        if not isinstance(findings, dict):
            continue
        for analyzer in findings.values():
            if not isinstance(analyzer, dict) or not analyzer.get("total_findings"):
                continue
            names = analyzer.get("threat_names")
            if not isinstance(names, list):
                continue
            found.extend(name for name in names if isinstance(name, str) and name)
    return found


def _skillspector_rules(loaded: object) -> list[str]:
    if not isinstance(loaded, dict):
        return []
    rows = loaded.get("issues")
    if not isinstance(rows, list):
        return []
    found: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        rule = row.get("id")
        if isinstance(rule, str) and rule:
            found.append(rule)
    return found


def _nuguard_rules(loaded: object) -> list[str]:
    if not isinstance(loaded, dict):
        return []
    rows = loaded.get("findings")
    if not isinstance(rows, list):
        return []
    found: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or row.get("severity") not in _NUGUARD_SEVERITIES:
            continue
        rule = _nuguard_rule(row)
        if rule:
            found.append(rule)
    return found


def _nuguard_rule(row: dict[str, object]) -> str:
    identifier = row.get("finding_id")
    if isinstance(identifier, str):
        matched = re.search(r"NGA(?:-SC)?-\d+", identifier, re.IGNORECASE)
        if matched:
            return matched.group(0).upper()
    title = row.get("title")
    return title if isinstance(title, str) else ""


_REPO_RULES: dict[str, Callable[[object], list[str]]] = {
    "nuguard": _nuguard_rules,
    "bandit": _bandit_rules,
    "trivy": _trivy_rules,
    "osv-scanner": _osv_rules,
    "gitleaks": _gitleaks_rules,
    "gosec": _gosec_rules,
    "mcp-scanner": _mcp_rules,
    "skillspector": _skillspector_rules,
}


def _vuln_db_flags(*flags: str) -> tuple[str, ...]:
    """Keep vulnerability database downloads off unless INSIDIA_VULN_DB=1."""
    if os.environ.get(_VULN_DB_OPT_IN) == "1":
        return ()
    return flags


_NUGUARD_PY = """\
import os
import subprocess
import sys
from pathlib import Path

source, workspace = sys.argv[1], Path(sys.argv[2])
exe = Path(sys.executable).with_name("nuguard.exe" if os.name == "nt" else "nuguard")
sbom = workspace / "app.sbom.json"
subprocess.run(
    [str(exe), "sbom", "generate", "--source", source, "--output", str(sbom), "--no-llm"],
    check=True,
)
# analyze exits 1 when it finds something. The report is the success signal.
subprocess.run(
    [
        str(exe), "analyze", "--sbom", str(sbom), "--source", source,
        "--format", "json", "--output", str(workspace / "report.json"),
        "--no-llm", "--no-osv", "--no-grype", "--no-trivy", "--no-checkov",
        "--no-semgrep", "--supply-chain-verify", "off",
    ],
)
sys.exit(0 if (workspace / "report.json").is_file() else 1)
"""
