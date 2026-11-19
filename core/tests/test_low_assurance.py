"""A pass that includes a limited engine result is low assurance in every output."""

import json
from pathlib import Path

import pytest
from insidia.cli import main
from insidia.probes import Attempt
from insidia.registry import Capability
from insidia.runstore import verdict_text, write_run

_REASON = "gitleaks read only the baseline file"


def test_a_pass_with_a_limited_record_is_flagged_in_each_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _scan(tmp_path, monkeypatch, limited=True)
    captured = capsys.readouterr()
    label = f"pass (low assurance: {_REASON})"
    assert code == 0
    assert label in captured.err
    assert f"passed (low assurance: {_REASON})" in captured.out
    run = _latest(tmp_path)
    benchmark = json.loads((run / "benchmark.json").read_text(encoding="utf-8"))
    assert benchmark["policy_verdict"] == "pass"
    assert benchmark["low_assurance"] is True
    assert benchmark["assurance_reason"] == _REASON
    row = _secrets(benchmark)
    assert row["result"] == "pass"
    assert row["assurance"] == "low"
    assert row["assurance_reason"] == _REASON
    findings = json.loads((run / "findings.json").read_text(encoding="utf-8"))
    assert findings == []
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["low_assurance"] is True
    assert manifest["assurance_reason"] == _REASON
    html = (run / "report.html").read_text(encoding="utf-8")
    assert f"PASS (low assurance: {_REASON})" in html
    assert label in html
    badge = html.split("<code>code.secrets</code>", 1)[1].split("</summary>", 1)[0]
    assert "res-low" in badge
    assert "res-pass" not in badge
    sarif = json.loads((run / "results.sarif").read_text(encoding="utf-8"))
    run_props = sarif["runs"][0]["properties"]
    assert run_props["low_assurance"] is True
    assert run_props["assurance_reason"] == _REASON
    notes = [
        item
        for item in sarif["runs"][0]["results"]
        if item.get("properties", {}).get("assurance") == "low"
    ]
    assert notes
    assert label in notes[0]["message"]["text"]
    assert notes[0]["properties"]["assurance_reason"] == _REASON


def test_a_pass_with_only_complete_records_is_not_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _scan(tmp_path, monkeypatch, limited=False)
    captured = capsys.readouterr()
    line = next(item for item in captured.err.splitlines() if "code.secrets" in item)
    assert code == 0
    assert "low assurance" not in line
    assert "passed (low assurance" not in captured.out
    run = _latest(tmp_path)
    benchmark = json.loads((run / "benchmark.json").read_text(encoding="utf-8"))
    assert benchmark["policy_verdict"] == "pass"
    assert benchmark["low_assurance"] is False
    assert benchmark["assurance_reason"] == ""
    row = _secrets(benchmark)
    assert row["result"] == "pass"
    assert row.get("assurance") != "low"
    html = (run / "report.html").read_text(encoding="utf-8")
    badge = html.split("<code>code.secrets</code>", 1)[1].split("</summary>", 1)[0]
    assert "PASS (low assurance" not in badge
    assert ">PASS<" in badge
    sarif = json.loads((run / "results.sarif").read_text(encoding="utf-8"))
    assert sarif["runs"][0]["properties"]["low_assurance"] is False
    assert sarif["runs"][0]["results"] == []


def test_a_low_assurance_pass_without_a_reason_keeps_the_short_label(tmp_path: Path) -> None:
    controls = [
        {
            "id": "web.headers",
            "target": "shop",
            "result": "pass",
            "taxonomy": "owasp-web:A05",
            "assurance": "low",
        }
    ]
    directory = write_run(tmp_path, "run-weak-plain", "L1", True, [], controls, [])
    html = (directory / "report.html").read_text(encoding="utf-8")
    badge = html.split("<code>web.headers</code>", 1)[1].split("</summary>", 1)[0]
    assert "PASS (low assurance)" in badge
    assert "PASS (low assurance:" not in badge
    benchmark = json.loads((directory / "benchmark.json").read_text(encoding="utf-8"))
    assert benchmark["low_assurance"] is True
    assert benchmark["assurance_reason"] == ""
    sarif = json.loads((directory / "results.sarif").read_text(encoding="utf-8"))
    assert sarif["runs"][0]["properties"]["low_assurance"] is True
    assert sarif["runs"][0]["results"][0]["message"]["text"] == "pass (low assurance)"
    summary = verdict_text("L1", True, 0, low_assurance=True)
    assert summary == "The scan ran. Policy L1 passed (low assurance). No findings."


def test_a_failed_run_does_not_mark_the_run_low_assurance(tmp_path: Path) -> None:
    controls = [
        {
            "id": "web.headers",
            "target": "shop",
            "result": "pass",
            "taxonomy": "owasp-web:A05",
            "assurance": "low",
            "assurance_reason": "partial",
        },
        {
            "id": "web.ssti",
            "target": "shop",
            "result": "fail",
            "taxonomy": "owasp-web:A03",
        },
    ]
    directory = write_run(
        tmp_path, "run-failed-weak", "L1", False, [], controls, [], policy_verdict="fail"
    )
    benchmark = json.loads((directory / "benchmark.json").read_text(encoding="utf-8"))
    assert benchmark["policy_verdict"] == "fail"
    assert benchmark["low_assurance"] is False
    sarif = json.loads((directory / "results.sarif").read_text(encoding="utf-8"))
    assert sarif["runs"][0]["properties"]["low_assurance"] is False
    assert sarif["runs"][0]["results"][0]["message"]["text"] == "pass (low assurance: partial)"


def test_cli_json_reports_a_low_assurance_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _scan(tmp_path, monkeypatch, limited=True, as_json=True)
    document = json.loads(capsys.readouterr().out)
    assert code == 0
    assert document["passed"] is True
    assert document["policy_verdict"] == "pass"
    assert document["low_assurance"] is True
    assert document["assurance_reason"] == _REASON
    assert f"passed (low assurance: {_REASON})" in document["summary"]


def _scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limited: bool,
    as_json: bool = False,
) -> int:
    source = tmp_path / "src"
    source.mkdir()
    (tmp_path / "insidia.yaml").write_text(
        """\
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  code:
    kind: repo
    path: src
""",
        encoding="utf-8",
    )
    state = {"n": 0}

    def select(
        family: str,
        coverage: str,
        model_available: bool = False,
        entries: object = None,
    ) -> list[Capability]:
        del coverage, model_available, entries
        if family != "code.secrets":
            return []
        chosen = [
            Capability("code.secrets", "insidia", "insidia.code.secrets", 100, False, True)
        ]
        if limited:
            chosen.append(
                Capability("code.secrets", "gitleaks", "insidia.code.secrets", 50, False, True)
            )
        return chosen

    def run(*_args: object, **_kwargs: object) -> Attempt:
        state["n"] += 1
        if limited and state["n"] > 1:
            return Attempt(untested=_REASON)
        return Attempt()

    monkeypatch.setattr("insidia.scan.select", select)
    monkeypatch.setattr("insidia.scan.run", run)
    command = ["scan", "--config", str(tmp_path / "insidia.yaml"), "--no-color"]
    if as_json:
        command.append("--json")
    return main(command)


def _latest(tmp_path: Path) -> Path:
    runs = tmp_path / ".insidia" / "runs"
    return max(path for path in runs.iterdir() if path.is_dir() and not path.name.startswith("."))


def _secrets(benchmark: dict[str, object]) -> dict[str, object]:
    controls = benchmark["controls"]
    assert isinstance(controls, list)
    rows = [row for row in controls if isinstance(row, dict) and row.get("id") == "code.secrets"]
    assert len(rows) == 1
    row = rows[0]
    assert isinstance(row, dict)
    return row
