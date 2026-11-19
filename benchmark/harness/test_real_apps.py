"""Real-app cells run Argus. A library with no endpoint stays target verified."""

from __future__ import annotations

from pathlib import Path

import pytest

from benchmark.harness import live, upstream
from benchmark.harness.run_cell import (
    SCANNER_PROVEN,
    TARGET_VERIFIED,
    ScanError,
    _ensure_insidia_import,
    cell_evidence,
    run_cell,
    scanner_ready,
    summarize,
)
from benchmark.harness.suite import suite_ready
from benchmark.matrix.registry import valid_cells


def test_real_app_cells_split_scanner_proof_from_target_checks() -> None:
    judged = [
        cell
        for cell in valid_cells()
        if scanner_ready(cell) and not cell.target.startswith("insidia-")
    ]
    assert len(judged) == 129
    labels = [cell_evidence(cell) for cell in judged]
    summary = summarize(labels)
    assert summary.scanner_proven + summary.target_verified == 129
    verified = [cell for cell in judged if cell_evidence(cell) == TARGET_VERIFIED]
    assert summary.target_verified == len(verified) == 18
    assert summary.scanner_proven == 111
    assert all(suite_ready(cell) for cell in verified)
    proven = [cell for cell in judged if cell not in verified]
    assert all(cell_evidence(cell) == SCANNER_PROVEN for cell in proven)


def test_agentdojo_library_is_target_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    cell = next(
        item
        for item in valid_cells()
        if item.target == "agentdojo" and item.box == "black" and item.conn == "direct"
    )
    monkeypatch.setattr("benchmark.harness.suite.suite_verified", lambda _cell: True)
    result = run_cell(cell)
    assert result.label == TARGET_VERIFIED
    assert result.findings == ()


def test_upstream_score_comes_from_the_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    cell = next(item for item in valid_cells() if item.cell_id == "api_rest|white|web.sqli|direct")
    monkeypatch.setattr(upstream, "_SCANNED", {})
    monkeypatch.setattr(upstream, "_scan_sources", lambda _cell: [])
    assert upstream.prove_upstream(cell) == []
    monkeypatch.setattr(
        upstream,
        "_scan_sources",
        lambda _cell: [{"attack": "web.sqli", "severity": "high"}],
    )
    monkeypatch.setattr(upstream, "_SCANNED", {})
    found = upstream.prove_upstream(cell)
    assert [item.plant_id for item in found] == [cell.plant_ids[0]]


def test_missing_upstream_source_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    cell = next(item for item in valid_cells() if item.cell_id == "api_rest|white|web.sqli|direct")
    source = upstream._ROOT / "VAmPI" / "models" / "user_model.py"
    if source.is_file():
        pytest.skip("VAmPI is checked out")
    monkeypatch.setattr(upstream, "_SCANNED", {})
    with pytest.raises(ScanError):
        upstream._scan_sources(cell)


def test_live_score_comes_from_the_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    cell = next(item for item in valid_cells() if item.cell_id == "web|black|web.sqli|direct")
    monkeypatch.setattr(live, "_SCANNED", {})
    monkeypatch.setattr(live, "_scan_live", lambda _cell: [])
    assert live.prove_live(cell) == []
    monkeypatch.setattr(
        live,
        "_scan_live",
        lambda _cell: [{"attack": "web.sqli", "severity": "high"}],
    )
    monkeypatch.setattr(live, "_SCANNED", {})
    found = live.prove_live(cell)
    assert [item.plant_id for item in found] == [cell.plant_ids[0]]


def test_live_config_stays_on_localhost_and_loads(tmp_path: Path) -> None:
    _ensure_insidia_import()
    from insidia.config import load_project

    for key in live._CHECKS:
        text = live._config_text(key[0], key[1], 3000, "insidia-cell-token")
        assert "authorized:" not in text
        assert "{{payload}}" in text
        path = tmp_path / f"{key[0]}-{key[1].replace('.', '-')}.yaml"
        path.write_text(text, encoding="utf-8")
        project = load_project(path)
        target = project.targets[0]
        assert target.url is not None
        assert target.url.startswith("http://127.0.0.1:3000/")
        assert project.scope[0].host == "127.0.0.1"
        assert project.scope[0].authorized is False
    assert set(live._SHAPES) == set(live._CHECKS)
