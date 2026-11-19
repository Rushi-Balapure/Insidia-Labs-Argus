"""sdk_bridge cells run a scan. They do not call the detection checks themselves."""

from __future__ import annotations

import pytest

from benchmark.harness import run_cell
from benchmark.matrix.registry import valid_cells


def _sdk_cell():
    return next(
        cell
        for cell in valid_cells()
        if cell.conn == "sdk_bridge"
        and cell.target == "insidia-chatbot"
        and cell.attack == "ai.jailbreak"
    )


def test_sdk_bridge_invokes_the_scanner(monkeypatch: pytest.MonkeyPatch) -> None:
    cell = _sdk_cell()
    seen: list[tuple[str, int | None]] = []

    def cli(call: run_cell.SandboxCall, port: int | None) -> list[dict[str, object]]:
        seen.append((call.fn, port))
        return [{"attack": call.attack, "severity": "high"}]

    monkeypatch.setattr(run_cell, "_cli", cli)
    monkeypatch.setattr(run_cell, "_ensure_sandbox", lambda: 4321)
    monkeypatch.setattr(run_cell, "_reset", lambda port: None)
    monkeypatch.setattr(run_cell, "_SCANS", {})

    found = run_cell.run_cell(cell)
    assert seen == [("jailbreak", 4321)]
    assert [item.plant_id for item in found] == [cell.plant_ids[0]]
    assert not hasattr(run_cell, "_sdk")
