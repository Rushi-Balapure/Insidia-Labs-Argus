"""A scan that does not finish is an error, not an empty finding list."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmark.harness.run_cell import ScanError, _ensure_insidia_import, _run_scan


def _install_main(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    _ensure_insidia_import()
    import insidia.cli

    monkeypatch.setattr(insidia.cli, "main", handler)


def _write_run(
    root: Path,
    *,
    status: str,
    verdict: str,
    findings: list[dict[str, object]],
) -> None:
    run = root / ".insidia" / "runs" / "20200101T000000Z"
    run.mkdir(parents=True)
    (run / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    (run / "benchmark.json").write_text(
        json.dumps({"execution_status": status, "policy_verdict": verdict}),
        encoding="utf-8",
    )


def test_exit_2_is_not_a_negative(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_run(tmp_path, status="incomplete", verdict="inconclusive", findings=[])

    def main(argv: list[str]) -> int:
        assert "--config" in argv
        return 2

    _install_main(monkeypatch, main)
    with pytest.raises(ScanError):
        _run_scan(tmp_path)


def test_missing_run_is_not_a_negative(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def main(argv: list[str]) -> int:
        return 0

    _install_main(monkeypatch, main)
    with pytest.raises(ScanError):
        _run_scan(tmp_path)


def test_a_raised_scan_is_not_a_negative(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def main(argv: list[str]) -> int:
        raise RuntimeError("scanner crashed")

    _install_main(monkeypatch, main)
    with pytest.raises(ScanError):
        _run_scan(tmp_path)


def test_cancelled_scan_is_not_a_negative(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_run(tmp_path, status="cancelled", verdict="inconclusive", findings=[])

    def main(argv: list[str]) -> int:
        return 130

    _install_main(monkeypatch, main)
    with pytest.raises(ScanError):
        _run_scan(tmp_path)


def test_finished_pass_with_no_findings_is_a_negative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_run(tmp_path, status="complete", verdict="pass", findings=[])

    def main(argv: list[str]) -> int:
        return 0

    _install_main(monkeypatch, main)
    assert _run_scan(tmp_path) == []


def test_a_finding_is_kept_when_another_check_did_not_finish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorded = [{"attack": "web.cmdi", "severity": "critical"}]
    _write_run(tmp_path, status="incomplete", verdict="fail", findings=recorded)

    def main(argv: list[str]) -> int:
        return 1

    _install_main(monkeypatch, main)
    assert _run_scan(tmp_path) == recorded


def test_policy_failure_without_findings_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_run(tmp_path, status="complete", verdict="fail", findings=[])

    def main(argv: list[str]) -> int:
        return 1

    _install_main(monkeypatch, main)
    with pytest.raises(ScanError):
        _run_scan(tmp_path)
