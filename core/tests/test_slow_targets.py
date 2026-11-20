import io
import socket
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from insidia.adapters import find
from insidia.config import Project, RateLimit, Target, load_project
from insidia.errors import ConfigError, ProbeError, ProbeTimeout
from insidia.policy import get_policy
from insidia.probes import _FIXTURE_ONLY_NOTE, Attempt, _replies, run
from insidia.scope import ScopeHost
from insidia.transport import RateLimiter, exchange
from insidia.ui import Event, ScanView, Terminal
from tests.support import target

SCOPE = (ScopeHost("127.0.0.1", False),)


@pytest.fixture
def slow() -> Iterator[int]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            time.sleep(1.5 if b"stall" in body else 0.4)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield int(server.server_address[1])
    server.shutdown()
    server.server_close()


def test_target_timeout_is_used(slow: int, tmp_path: Path) -> None:
    app = replace(target("web", f"http://127.0.0.1:{slow}/"), timeout=0.5)
    with pytest.raises(ProbeError, match="timed out"):
        exchange(app, "stall", SCOPE, tmp_path)


def test_payloads_run_in_parallel_up_to_concurrency(slow: int, tmp_path: Path) -> None:
    app = replace(target("web", f"http://127.0.0.1:{slow}/"), rate_limit=RateLimit(100, 4))
    payloads = tuple(f"p{index}" for index in range(8))
    began = time.monotonic()
    replies = list(_replies(app, payloads, "web.cmdi", SCOPE, tmp_path))
    assert [payload for payload, _reply in replies] == list(payloads)
    assert time.monotonic() - began < 8 * 0.4 / 2


def test_timeout_must_be_in_range(tmp_path: Path) -> None:
    config = tmp_path / "insidia.yaml"
    config.write_text(
        "version: 1\nscope:\n  - host: 127.0.0.1\ntargets:\n"
        "  app:\n    kind: web\n    url: http://127.0.0.1:1/\n    timeout: 0\n"
    )
    with pytest.raises(ConfigError, match="timeout"):
        load_project(config)
    config.write_text(config.read_text().replace("timeout: 0", "timeout: 15"))
    assert load_project(config).targets[0].timeout == 15.0


def test_live_line_counts_requests() -> None:
    limiter = RateLimiter(1000)
    stream = io.StringIO()
    view = ScanView(Terminal(stream, animate=True, no_color=True))
    view(Event("begin", "app", "web.cmdi", ("insidia",), sent=lambda: limiter.sent))
    for _ in range(3):
        limiter.wait()
    time.sleep(0.3)
    view(Event("end", "app", "web.cmdi", ("insidia",), "pass"))
    assert "3 requests" in stream.getvalue()


@contextmanager
def _accept_and_hold() -> Iterator[int]:
    """Accept loopback connections and leave them open."""
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)
    sock.settimeout(0.2)
    port = int(sock.getsockname()[1])
    stop = threading.Event()
    held: list[socket.socket] = []

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            held.append(conn)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        sock.close()
        for conn in held:
            conn.close()
        thread.join(1)


def _attempt(app: Target, family: str, root: Path) -> Attempt:
    project = Project(root / "insidia.yaml", 1, "L1", "standard", SCOPE, (app,), None, None)
    adapter, spec = find(f"insidia.{family}")
    return run(adapter, spec, app, project, root, get_policy("L1").control(family))


def test_socket_timeout_is_a_probe_timeout(tmp_path: Path) -> None:
    with _accept_and_hold() as port:
        app = replace(
            target("web", f"http://127.0.0.1:{port}/"),
            timeout=0.2,
            rate_limit=RateLimit(100, 8),
        )
        with pytest.raises(ProbeTimeout, match="^target timed out$") as caught:
            exchange(app, "ping", SCOPE, tmp_path)
        assert isinstance(caught.value, ProbeError)
        assert str(caught.value) == "target timed out"
        answered = _attempt(app, "web.cmdi", tmp_path)
        stalled = replace(app, timeout=30)
        missed = _attempt(stalled, "web.deserialization", tmp_path)
    assert answered.hits == ()
    assert answered.error == "target timed out"
    assert answered.untested == ""
    assert missed.hits == ()
    assert missed.error == ""
    assert missed.untested == _FIXTURE_ONLY_NOTE


def test_timed_out_text_is_not_a_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_exchange(*_args: object, **_kwargs: object) -> str:
        raise ProbeError("target timed out")

    monkeypatch.setattr("insidia.probes.exchange", fake_exchange)
    app = replace(target("web", "http://127.0.0.1/ping"), timeout=30)
    attempt = _attempt(app, "web.deserialization", tmp_path)
    assert attempt.error == "target timed out"
    assert attempt.untested == _FIXTURE_ONLY_NOTE


def test_url_error_text_is_not_a_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(_self: object, _request: object, **_kwargs: object) -> object:
        raise urllib.error.URLError(OSError("timed out"))

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", fail)
    app = replace(target("web", "http://127.0.0.1:9/"), timeout=0.2)
    with pytest.raises(ProbeError, match="^endpoint is unreachable$") as caught:
        exchange(app, "ping", SCOPE, tmp_path)
    assert not isinstance(caught.value, ProbeTimeout)
