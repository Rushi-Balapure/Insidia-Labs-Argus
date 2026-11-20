"""Precision counts findings that are not the cell's expected vulnerability."""

from __future__ import annotations

import os
import shutil
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from benchmark.harness.run_cell import _matched, _run_scan
from benchmark.harness.score import Finding, score_findings
from benchmark.matrix.plants import plant_for
from benchmark.matrix.registry import valid_cells
from benchmark.targets.insidia import fixed

_FIXED_REPO = Path(__file__).resolve().parents[1] / "targets" / "insidia" / "fixed_repo"


def test_an_unmatched_finding_is_a_false_positive() -> None:
    cell = next(item for item in valid_cells() if item.cell_id == "web|black|web.cmdi|direct")
    recorded = [
        {"attack": "web.cmdi", "severity": "critical", "evidence_hash": "tp"},
        {"attack": "web.xss", "severity": "medium", "evidence_hash": "abc"},
    ]
    actual = _matched(cell, recorded)
    result = score_findings([plant_for(cell.target, cell.attack)], actual)
    assert result.recall == 1.0
    assert result.precision == 0.5
    assert result.false_positives == ("unmatched.web.xss.abc",)


def test_another_plant_in_the_same_target_is_not_a_false_positive() -> None:
    cell = next(
        item for item in valid_cells() if item.cell_id == "codebase|white|code.secrets|direct"
    )
    recorded = [
        {"attack": "code.secrets", "severity": "high", "evidence_hash": "secret"},
        {"attack": "code.sast_sinks", "severity": "high", "evidence_hash": "sast"},
        {"attack": "deps.sca", "severity": "high", "evidence_hash": "sca"},
    ]
    actual = _matched(cell, recorded)
    result = score_findings([plant_for(cell.target, cell.attack)], actual)
    assert result.recall == 1.0
    assert result.precision == 1.0
    assert result.false_positives == ()


def test_clean_controls_have_no_findings(tmp_path: Path) -> None:
    scans = (
        _scan_http(tmp_path / "chat", "chat", "POST", fixed.chat),
        _scan_http(tmp_path / "web", "web", "GET", fixed.web),
        _scan_http(tmp_path / "api", "api", "GET", fixed.api),
        _scan_repo(tmp_path / "repo"),
    )
    for raw in scans:
        actual = [
            Finding(f"unmatched.{item.get('attack')}.{item.get('evidence_hash')}") for item in raw
        ]
        result = score_findings([], actual)
        assert raw == []
        assert result.recall == 1.0
        assert result.precision == 1.0
        assert result.false_positives == ()


def _scan_http(
    root: Path, kind: str, method: str, reply: Callable[[str], str]
) -> list[dict[str, object]]:
    root.mkdir(parents=True)
    server, thread = _start(reply)
    try:
        port = int(server.server_address[1])
        query = ""
        if method == "GET":
            query = '    query:\n      q: "{{payload}}"\n'
        (root / "insidia.yaml").write_text(
            f"""\
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  plant:
    kind: {kind}
    url: http://127.0.0.1:{port}/fixed
    method: {method}
{query}    rate_limit:
      rps: 100
      concurrency: 1
""",
            encoding="utf-8",
        )
        return _scan(root)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _scan_repo(root: Path) -> list[dict[str, object]]:
    root.mkdir(parents=True)
    shutil.copytree(_FIXED_REPO, root / "app")
    (root / "insidia.yaml").write_text(
        """\
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  plant:
    kind: repo
    path: app
""",
        encoding="utf-8",
    )
    return _scan(root)


def _scan(root: Path) -> list[dict[str, object]]:
    previous = os.environ.get("INSIDIA_TOOLCHAIN")
    toolchain = root / "toolchain"
    toolchain.mkdir()
    os.environ["INSIDIA_TOOLCHAIN"] = str(toolchain)
    try:
        return _run_scan(root)
    finally:
        if previous is None:
            os.environ.pop("INSIDIA_TOOLCHAIN", None)
        else:
            os.environ["INSIDIA_TOOLCHAIN"] = previous


def _start(reply: Callable[[str], str]) -> tuple[ThreadingHTTPServer, threading.Thread]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self._send(reply(self.path))

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length).decode("utf-8", "replace")
            self._send(reply(body))

        def _send(self, text: str) -> None:
            payload = text.encode()
            self.send_response(200)
            self.send_header("content-type", "text/plain; charset=utf-8")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    return server, thread
