"""Write and check the CSV, JSON, and manifest files for one run."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import asdict
from pathlib import Path

from insidia.errors import CliError
from insidia.findings import Finding
from insidia.mask import mask
from insidia.results import SCHEMA_VERSION
from insidia.run_baseline import _Tracked
from insidia.score import Score

_CSV_COLUMNS = (
    "check_id",
    "title",
    "severity",
    "risk_score",
    "target",
    "target_kind",
    "endpoint",
    "cve",
    "taxonomy",
    "synopsis",
    "solution",
    "evidence",
    "evidence_hash",
    "engines",
    "run_id",
)
_CSV_EVIDENCE_CAP = 500
_CSV_TRIM_NOTE = " truncated to 500 characters"
_CSV_FORMULA = ("=", "+", "-", "@")


def _findings_csv(
    findings: list[Finding],
    run_id: str,
    targets: tuple[tuple[str, str, str], ...],
) -> str:
    """One header, then one row per finding. Cells are masked and formula-safe."""
    kinds = {name: kind for name, kind, _endpoint in targets}
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(_CSV_COLUMNS)
    for finding in findings:
        writer.writerow(
            [
                _csv_cell(finding.check_id),
                _csv_cell(finding.title),
                _csv_cell(finding.severity),
                _csv_cell(json.dumps(finding.risk_score)),
                _csv_cell(finding.target),
                _csv_cell(kinds.get(finding.target, "")),
                _csv_cell(finding.endpoint or finding.location),
                _csv_cell("; ".join(finding.cve)),
                _csv_cell("; ".join(finding.taxonomy)),
                _csv_cell(finding.synopsis),
                _csv_cell(finding.remediation),
                _csv_evidence(finding),
                _csv_cell(finding.evidence_hash),
                _csv_cell("; ".join(finding.engines)),
                _csv_cell(run_id),
            ]
        )
    return buffer.getvalue()


def _finding_evidence(finding: Finding) -> str:
    """Observation evidence, or the response when no observation stored any."""
    parts = [item.evidence for item in finding.observations if item.evidence]
    if parts:
        return "\n".join(parts)
    return finding.response


def _csv_evidence(finding: Finding) -> str:
    """Mask evidence, then keep at most 500 characters."""
    text = mask(_finding_evidence(finding))
    if len(text) > _CSV_EVIDENCE_CAP:
        text = text[:_CSV_EVIDENCE_CAP] + _CSV_TRIM_NOTE
    return _formula_safe(text)


def _csv_cell(value: str) -> str:
    return _formula_safe(mask(value))


def _formula_safe(value: str) -> str:
    """A leading spreadsheet formula is text. Applied after masking and trimming."""
    if value.startswith(_CSV_FORMULA):
        return f"'{value}"
    return value


def read_manifest(directory: Path) -> dict[str, object] | None:
    """Check a finalized manifest. A legacy run with no manifest is left unchanged."""

    if directory.is_symlink():
        raise CliError(f"run {directory.name} manifest escapes the run directory")
    path = directory / "manifest.json"
    if path.is_symlink():
        raise CliError(f"run {directory.name} manifest escapes the run directory")
    if not path.is_file():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CliError(f"run {directory.name} manifest is not valid JSON") from exc
    if not isinstance(loaded, dict):
        raise CliError(f"run {directory.name} manifest is not valid JSON")
    files = loaded.get("files")
    if not isinstance(files, dict):
        raise CliError(f"run {directory.name} manifest does not list its files")
    root = directory.resolve()
    for name, digest in files.items():
        if not isinstance(name, str) or not isinstance(digest, str) or "/" in name:
            raise CliError(f"run {directory.name} manifest has an invalid file entry")
        artifact_path = directory / name
        if artifact_path.is_symlink():
            raise CliError(f"run {directory.name} manifest escapes the run directory")
        artifact = artifact_path.resolve()
        if root != artifact and root not in artifact.parents:
            raise CliError(f"run {directory.name} manifest escapes the run directory")
        if not artifact.is_file():
            raise CliError(f"run {directory.name} is missing {name}")
        actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if actual != digest:
            raise CliError(f"run {directory.name} {name} does not match the manifest")
    return loaded


def _write_findings_json(
    directory: Path,
    findings: list[Finding],
    tracked: tuple[_Tracked, ...],
) -> None:
    payload = []
    for finding, item in zip(findings, tracked, strict=True):
        document = finding.as_json()
        document["state"] = item.state
        document["first_seen_run"] = item.first_seen_run
        payload.append(document)
    (directory / "findings.json").write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )


def _write_findings_csv(
    directory: Path,
    findings: list[Finding],
    run_id: str,
    targets: tuple[tuple[str, str, str], ...],
) -> None:
    (directory / "findings.csv").write_text(
        _findings_csv(findings, run_id, targets),
        encoding="utf-8",
        newline="",
    )


def _write_benchmark(
    directory: Path,
    policy: str,
    passed: bool,
    execution_status: str,
    verdict: str,
    low_assurance: bool,
    assurance_reason: str,
    controls: list[dict[str, str | int]],
    skips: list[str],
    scores: tuple[Score, ...],
) -> None:
    benchmark = {
        "schema_version": SCHEMA_VERSION,
        "policy": policy,
        "passed": passed,
        "execution_status": execution_status,
        "policy_verdict": verdict,
        "low_assurance": low_assurance,
        "assurance_reason": assurance_reason,
        "controls": controls,
        "skips": skips,
        "scores": [asdict(score) for score in scores],
    }
    (directory / "benchmark.json").write_text(
        json.dumps(benchmark, indent=2) + "\n",
        encoding="utf-8",
    )


def _write_manifest(directory: Path, manifest: dict[str, object]) -> None:
    (directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )


def _artefact_digests(directory: Path, names: list[str]) -> dict[str, str]:
    return {
        name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
        for name in names
        if name != "report.html"
    }
