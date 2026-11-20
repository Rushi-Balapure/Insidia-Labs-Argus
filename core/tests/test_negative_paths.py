"""Engine failures, relay limits, and install rollback never look like a pass."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import urllib.request
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from insidia.adapters import Invocation, ProbeSpec, RelayAdapter, RelayEndpoint
from insidia.config import Project, load_project
from insidia.engines import install
from insidia.errors import CliError, EngineFailed
from insidia.policy import POLICIES
from insidia.probes import _RELAY_MIN_PROMPTS, Attempt
from insidia.probes import run as probe_run
from insidia.process import _kill_tree, child_env, launch_installed
from insidia.registry import Capability
from insidia.results import (
    COMPLETE,
    ERROR,
    LIMITED,
    PASS,
    CheckRecord,
    aggregate,
    exit_for,
    legacy_passed,
)
from insidia.scan import ScanOutcome, execute
from insidia.scope import ScopeHost
from tests.support import target

_LOCAL = (ScopeHost("127.0.0.1", False),)
_ONE_PROMPT = """\
import json
import sys
import urllib.request
from pathlib import Path


def flag(name: str) -> str:
    return sys.argv[sys.argv.index(name) + 1]


with Path(flag("--generator_option_file")).open(encoding="utf-8") as handle:
    generator = json.loads(handle.read())
rest = generator["rest"]["RestGenerator"]
body = json.dumps({"prompt": "secret"}).encode()
request = urllib.request.Request(
    str(rest["uri"]), data=body, headers=rest["headers"], method="POST"
)
with urllib.request.urlopen(request, timeout=5) as response:
    response.read()
"""


def _only_garak(
    family: str,
    mode: str,
    model_available: bool = False,
    entries: object = None,
) -> list[Capability]:
    del mode, model_available, entries
    if family != "ai.data_leakage":
        return []
    return [Capability("ai.data_leakage", "garak", "garak.ai.data_leakage", 50, False, True)]


def _launch_with_python(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run the staged file with this interpreter.

    `_argv_for` only inserts python.exe for a Windows `.exe` that sits beside
    one. A shebang script is not executable on Windows, so the test supplies
    the interpreter on every platform.
    """

    def command_argv(program: str, args: tuple[str, ...]) -> list[str]:
        return [sys.executable, program, *args]

    monkeypatch.setattr("insidia.process._command_argv", command_argv)


def _stage_garak(tools: Path, script: str) -> None:
    binary = tools / "garak" / "bin" / "garak.py"
    binary.parent.mkdir(parents=True)
    binary.write_text(script, encoding="utf-8")
    (tools / "garak" / "receipt.json").write_text(
        json.dumps({"name": "garak", "version": "0.17.0", "program": "bin/garak.py"}) + "\n",
        encoding="utf-8",
    )


@contextmanager
def _serve() -> Iterator[tuple[ThreadingHTTPServer, dict[str, int]]]:
    hits = {"n": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            hits["n"] += 1
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, hits
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _scan(tmp_path: Path, port: int) -> ScanOutcome:
    config = tmp_path / "insidia.yaml"
    config.write_text(
        f"""
version: 1
policy: L1
coverage: thorough
scope:
  - host: 127.0.0.1
targets:
  bot:
    kind: chat
    url: http://127.0.0.1:{port}/chat
    rate_limit:
      rps: 100
      concurrency: 1
"""
    )
    return execute(load_project(config), tmp_path)


def _controls(outcome: ScanOutcome) -> list[dict[str, object]]:
    document = json.loads((outcome.run_dir / "benchmark.json").read_text(encoding="utf-8"))
    controls = document["controls"]
    assert isinstance(controls, list)
    return [row for row in controls if isinstance(row, dict)]


@pytest.mark.parametrize("mode", ["error", "timeout", "missing", "silent", "shallow"])
def test_engine_failure_never_passes(
    mode: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tools = tmp_path / "toolchain"
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tools))
    monkeypatch.setattr("insidia.scan.select", _only_garak)
    _launch_with_python(monkeypatch)
    if mode == "error":
        _stage_garak(tools, "import sys\nsys.exit(2)\n")
    elif mode == "timeout":
        _stage_garak(tools, "import time\ntime.sleep(30)\n")

        def capped(
            argv: list[str],
            cwd: Path | None,
            env: Mapping[str, str],
            timeout: float,
            name: str | None = None,
        ) -> tuple[int, str]:
            del timeout
            label = name or Path(argv[0]).name
            proc = subprocess.Popen(
                argv,
                cwd=cwd,
                env=child_env(env),
                shell=False,
                start_new_session=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                _stdout, stderr = proc.communicate(timeout=0.4)
            except subprocess.TimeoutExpired:
                _kill_tree(proc)
                raise EngineFailed(f"{label} timed out") from None
            finally:
                for pipe in (proc.stdout, proc.stderr):
                    if pipe is not None:
                        pipe.close()
            code = 1 if proc.returncode is None else proc.returncode
            detail = stderr.decode("utf-8", errors="replace").strip()
            return code, detail[-400:]

        monkeypatch.setattr("insidia.process.run_command", capped)
    elif mode == "missing":
        _stage_garak(tools, "import sys\nsys.exit(0)\n")

        def program_for(name: str) -> str:
            del name
            return str(tools / "garak" / "missing-binary")

        monkeypatch.setattr("insidia.engines.program_for", program_for)
    elif mode == "silent":
        _stage_garak(tools, "raise SystemExit(0)\n")
    else:
        _stage_garak(tools, _ONE_PROMPT)
    with _serve() as (server, hits):
        port = int(server.server_address[1])
        outcome = _scan(tmp_path, port)
    assert outcome.passed is False
    assert outcome.policy_verdict != "pass"
    assert outcome.exit_code() != 0
    rows = _controls(outcome)
    assert rows
    assert all(row.get("result") != "pass" for row in rows)
    leak = [row for row in rows if row.get("id") == "ai.data_leakage"]
    assert leak and all(row.get("result") != "pass" for row in leak)
    skips = "\n".join(outcome.skips)
    if mode == "error":
        assert "exited 2" in skips
    elif mode == "timeout":
        assert "timed out" in skips
    elif mode == "missing":
        assert "is not installed" in skips
    elif mode == "silent":
        assert "without contacting the target" in skips
    else:
        details = " ".join(str(row.get("detail", "")) for row in leak)
        assert "sent only 1 prompt" in details
        assert hits["n"] == 2


def test_a_passing_check_beside_an_engine_error_is_not_a_pass() -> None:
    records = [
        CheckRecord("bot", "ai.jailbreak", "insidia", COMPLETE, finding_count=0),
        CheckRecord("bot", "ai.data_leakage", "garak", ERROR, "garak timed out"),
        CheckRecord("bot", "ai.data_leakage", "promptfoo", ERROR, "promptfoo is not installed"),
    ]
    status, verdict = aggregate(records)
    assert verdict != PASS
    assert legacy_passed(status, verdict) is False
    assert exit_for(status, verdict) != 0


def test_a_shallow_relay_record_is_not_a_pass() -> None:
    records = [
        CheckRecord(
            "bot",
            "ai.data_leakage",
            "garak",
            LIMITED,
            "garak sent only 1 prompt(s)",
        )
    ]
    status, verdict = aggregate(records)
    assert verdict != PASS
    assert legacy_passed(status, verdict) is False
    assert exit_for(status, verdict) != 0


def test_relay_below_the_minimum_does_not_finish_as_a_pass(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def exchange(_app: object, _payload: str, _scope: object, _root: object) -> str:
        return "ok"

    monkeypatch.setattr("insidia.probes.exchange", exchange)
    for prompts in (0, 1, 2, _RELAY_MIN_PROMPTS):
        attempt = _relay(tmp_path, prompts)
        if prompts == 0:
            assert attempt.hits == ()
            assert "without contacting the target" in attempt.error
            state = ERROR
            reason = attempt.error
        elif prompts < _RELAY_MIN_PROMPTS:
            assert attempt.error == ""
            assert attempt.untested == f"garak sent only {prompts} prompt(s)"
            state = LIMITED
            reason = attempt.untested
        else:
            assert attempt.error == ""
            assert attempt.untested == ""
            assert attempt.hits == ()
            continue
        status, verdict = aggregate(
            [CheckRecord("bot", "ai.data_leakage", "garak", state, reason)]
        )
        assert verdict != PASS
        assert legacy_passed(status, verdict) is False


def _relay(tmp_path: Path, prompts: int) -> Attempt:
    holder: list[RelayEndpoint] = []

    def prepare(spec: ProbeSpec, endpoint: RelayEndpoint, workspace: Path) -> Invocation:
        del spec, workspace
        holder.append(endpoint)
        return Invocation(sys.executable, (), "unused.json")

    def launch(invocation: Invocation, workspace: Path) -> None:
        del invocation, workspace
        endpoint = holder[0]
        for index in range(prompts):
            body = json.dumps({"prompt": f"probe-{index}"}).encode()
            request = urllib.request.Request(
                endpoint.url,
                data=body,
                headers={
                    "Authorization": f"Bearer {endpoint.token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                assert response.status == 200

    spec = ProbeSpec("garak.ai.data_leakage", "test.Blank", "ai.data_leakage", 50, False, ("chat",))
    adapter = RelayAdapter("garak", "Apache-2.0", (spec,), prepare)
    project = Project(tmp_path / "insidia.yaml", 1, "L1", "standard", _LOCAL, (), None, None)
    return probe_run(
        adapter,
        spec,
        target(kind="chat", url="http://127.0.0.1/chat"),
        project,
        tmp_path,
        POLICIES["L1"].control("ai.data_leakage"),
        launch,
    )


def test_missing_binary_raises_before_a_pass(tmp_path: Path) -> None:
    missing = tmp_path / "garak"
    invocation = Invocation(str(missing), (), "report.json")
    with pytest.raises(EngineFailed, match="is not installed"):
        launch_installed(invocation, tmp_path)
    assert not (tmp_path / "report.json").exists()


def _fake_stage(body: bytes, *, fail: bool = False) -> object:
    def stage(spec: object, stage_path: Path, allow_unverified: bool = False) -> str:
        del spec, allow_unverified
        program = stage_path / "bin" / "nuclei"
        program.parent.mkdir(parents=True)
        program.write_bytes(body)
        program.chmod(0o755)
        python = stage_path / "venv" / "bin" / "python"
        python.parent.mkdir(parents=True)
        python.write_text("", encoding="utf-8")
        script = stage_path / "venv" / "bin" / "tool"
        script.write_text("#!/old/staging/python\nprint(1)\n", encoding="utf-8")
        if fail:
            (stage_path / "partial.bin").write_bytes(b"partial-bytes")
            raise CliError("install failed")
        return "bin/nuclei"

    return stage


def test_a_failed_stage_leaves_no_partial_install(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "toolchain"
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(root))
    neighbor = root / "garak" / "keep"
    neighbor.parent.mkdir(parents=True)
    neighbor.write_text("keep", encoding="utf-8")
    monkeypatch.setattr("insidia.engines._stage", _fake_stage(b"unused", fail=True))
    with pytest.raises(CliError, match="install failed"):
        install(("nuclei",))
    assert not (root / "nuclei").exists()
    assert not (root / ".nuclei.staging").exists()
    assert neighbor.read_text(encoding="utf-8") == "keep"
    assert not any(path.name == "partial.bin" for path in root.rglob("*"))


def test_a_failed_upgrade_keeps_the_previous_install(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "toolchain"
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(root))
    monkeypatch.setattr("insidia.engines._stage", _fake_stage(b"original-nuclei"))
    junk = root / ".nuclei.staging" / "leftover"
    junk.parent.mkdir(parents=True)
    junk.write_text("junk", encoding="utf-8")
    assert install(("nuclei",)).startswith("installed nuclei")
    final = root / "nuclei"
    script = (final / "venv" / "bin" / "tool").read_text(encoding="utf-8")
    assert script.startswith(f"#!{final / 'venv' / 'bin' / 'python'}\n")
    assert not (root / ".nuclei.staging").exists()
    assert "leftover" not in script
    receipt = json.loads((final / "receipt.json").read_text(encoding="utf-8"))
    receipt["version"] = "0"
    (final / "receipt.json").write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    monkeypatch.setattr("insidia.engines._stage", _fake_stage(b"partial-new", fail=True))
    with pytest.raises(CliError, match="install failed"):
        install(("nuclei",))
    assert (final / "bin" / "nuclei").read_bytes() == b"original-nuclei"
    assert json.loads((final / "receipt.json").read_text(encoding="utf-8"))["version"] == "0"
    assert not (root / ".nuclei.staging").exists()
    assert not any(path.name == "partial.bin" for path in root.rglob("*"))


def test_a_failed_publish_restores_the_previous_install(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "toolchain"
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(root))
    monkeypatch.setattr("insidia.engines._stage", _fake_stage(b"original-nuclei"))
    assert install(("nuclei",)).startswith("installed nuclei")
    final = root / "nuclei"
    receipt = json.loads((final / "receipt.json").read_text(encoding="utf-8"))
    receipt["version"] = "0"
    (final / "receipt.json").write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    original = (final / "bin" / "nuclei").read_bytes()
    fail = {"publish": True}
    real_rename = Path.rename

    def rename(self: Path, target: Path) -> Path:
        if fail["publish"] and self.name == ".nuclei.staging" and target.name == "nuclei":
            raise OSError("simulated publish failure")
        return real_rename(self, target)

    monkeypatch.setattr(Path, "rename", rename)
    monkeypatch.setattr("insidia.engines._stage", _fake_stage(b"replacement-nuclei"))
    with pytest.raises(OSError, match="simulated publish failure"):
        install(("nuclei",))
    assert (final / "bin" / "nuclei").read_bytes() == original
    assert json.loads((final / "receipt.json").read_text(encoding="utf-8"))["version"] == "0"
    assert not (root / ".nuclei.staging").exists()
    assert not (root / ".nuclei.previous").exists()
    leaked = [
        path.name
        for path in root.rglob("*")
        if path.is_file() and b"replacement-nuclei" in path.read_bytes()
    ]
    assert leaked == []

