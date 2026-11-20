"""Each valid cell meets ground truth once the scanner can prove it. The rest stay xfail."""

from __future__ import annotations

import pytest

from benchmark.harness.run_cell import TARGET_VERIFIED, run_cell, scanner_ready
from benchmark.harness.score import golden_dropped, meets_threshold, score_findings
from benchmark.harness.upstream import material_ready
from benchmark.matrix.plants import plant_for
from benchmark.matrix.registry import Cell, valid_cells


def _parameters() -> list[object]:
    parameters: list[object] = []
    for cell in valid_cells():
        marks = [getattr(pytest.mark, name) for name in cell.marker_names()]
        if not scanner_ready(cell):
            marks.append(
                pytest.mark.xfail(
                    strict=True,
                    reason=f"phase {cell.phase} scanner is not built",
                )
            )
        parameters.append(pytest.param(cell, id=cell.cell_id, marks=marks))
    return parameters


@pytest.mark.parametrize("cell", _parameters())
def test_cell_meets_ground_truth(cell: Cell) -> None:
    if not material_ready(cell):
        pytest.skip("third-party target is not on this machine")
    outcome = run_cell(cell)
    if outcome.label == TARGET_VERIFIED:
        pytest.xfail(outcome.detail or "target verified, not scanner proven")
    actual = list(outcome.findings)
    expected = [plant_for(cell.target, cell.attack)]
    result = score_findings(expected, actual)
    assert meets_threshold(result, cell.recall_floor, cell.precision_floor)
    found = {item.plant_id for item in actual}
    assert golden_dropped(set(cell.plant_ids), found) == ()


def test_locally_runnable_precision() -> None:
    true_positives = 0
    false_positives = 0
    misses = 0
    counted = 0
    for cell in valid_cells():
        if not scanner_ready(cell) or not cell.target.startswith("insidia-"):
            continue
        outcome = run_cell(cell)
        counted += 1
        score = score_findings([plant_for(cell.target, cell.attack)], list(outcome.findings))
        false_positives += len(score.false_positives)
        true_positives += len(outcome.findings) - len(score.false_positives)
        misses += len(score.missed)
    precision = 1.0 if true_positives + false_positives == 0 else true_positives / (
        true_positives + false_positives
    )
    recall = 1.0 if counted == 0 else (counted - misses) / counted
    assert counted == 1062
    assert (misses, false_positives) == (0, 0)
    assert (precision, recall) == (1.0, 1.0)
