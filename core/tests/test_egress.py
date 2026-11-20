"""Resolved addresses stay inside scope, and the engine proxy enforces that."""

from __future__ import annotations

import socket
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from insidia.adapters import ADAPTERS, Invocation, RelayAdapter, RelayEndpoint, ScopedUrl
from insidia.egress import confine, current_gate, engine_proxy_args
from insidia.errors import EngineFailed, ScopeError
from insidia.process import child_env, launch_installed
from insidia.scope import ScopeHost
from insidia.transport import fetch

_LOCAL = (ScopeHost("localhost", False), ScopeHost("127.0.0.1", False), ScopeHost("::1", False))


class _Quiet(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        return


def _server(box: dict[str, object]) -> type[_Quiet]:
    class Handler(_Quiet):
        def do_GET(self) -> None:  # noqa: N802
            box["n"] = int(box["n"]) + 1
            hosts = box["hosts"]
            assert isinstance(hosts, list)
            hosts.append(self.headers.get("Host", ""))
            body = b"landed"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            self.do_GET()

    return Handler


@contextmanager
def _http(box: dict[str, object]) -> Iterator[ThreadingHTTPServer]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _server(box))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _port(server: ThreadingHTTPServer) -> int:
    return int(server.server_address[1])


def _box() -> dict[str, object]:
    return {"n": 0, "hosts": []}


def _lookup(
    monkeypatch: pytest.MonkeyPatch, answers: dict[str, tuple[str, ...]]
) -> None:
    real = socket.getaddrinfo

    def lookup(host: object, port: object, *args: object, **kwargs: object) -> object:
        if isinstance(host, str) and host in answers:
            port_n = port if isinstance(port, int) else 0
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port_n)) for ip in answers[host]
            ]
        return real(host, port, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(socket, "getaddrinfo", lookup)


def test_localhost_that_resolves_off_loopback_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _lookup(monkeypatch, {"localhost": ("192.168.1.50",)})
    with pytest.raises(ScopeError, match="resolved outside loopback"):
        fetch("http://localhost:9/", _LOCAL)


def test_localhost_with_a_loopback_and_a_lan_address_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _lookup(monkeypatch, {"localhost": ("127.0.0.1", "10.2.2.2")})
    with pytest.raises(ScopeError, match="resolved outside loopback"):
        fetch("http://localhost:9/", _LOCAL)


def test_localhost_dials_the_loopback_address_and_keeps_the_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _lookup(monkeypatch, {"localhost": ("127.0.0.1",)})
    box = _box()
    with _http(box) as server:
        port = _port(server)
        status, _headers, body = fetch(f"http://localhost:{port}/", _LOCAL)
    assert status == 200
    assert body == "landed"
    assert box["n"] == 1
    assert box["hosts"] == [f"localhost:{port}"]


@pytest.mark.parametrize(
    "url",
    [
        "http://2130706433/",
        "http://127.1/",
        "http://0x7f.0.0.1/",
        "http://[::ffff:127.0.0.1]/",
    ],
)
def test_lookalike_strings_are_rejected_before_resolution(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    def lookup(*_args: object, **_kwargs: object) -> list[object]:
        raise AssertionError("resolved a host the string check should refuse")

    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    with pytest.raises(ScopeError, match="not in scope"):
        fetch(url, _LOCAL)


def test_rebinding_after_the_scan_pin_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = {"pinned.invalid": ("127.0.0.1",)}
    _lookup(monkeypatch, answers)
    box = _box()
    scope = (ScopeHost("pinned.invalid", True),)
    with _http(box) as server:
        port = _port(server)
        with confine(scope):
            status, _headers, body = fetch(f"http://pinned.invalid:{port}/", scope)
            assert status == 200
            assert body == "landed"
            answers["pinned.invalid"] = ("10.9.8.7",)
            with pytest.raises(ScopeError, match="not pinned at scan start"):
                fetch(f"http://pinned.invalid:{port}/again", scope)
    assert box["n"] == 1
    assert box["hosts"] == [f"pinned.invalid:{port}"]


def test_a_scan_refuses_localhost_before_contact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _lookup(monkeypatch, {"localhost": ("192.168.1.50",)})
    box = _box()
    with _http(box) as server:
        port = _port(server)
        config = tmp_path / "insidia.yaml"
        config.write_text(
            f"""
version: 1
policy: L1
coverage: standard
scope:
  - host: localhost
targets:
  app:
    kind: web
    url: http://localhost:{port}/
    method: GET
""",
            encoding="utf-8",
        )
        from insidia.config import load_project
        from insidia.scan import execute

        with pytest.raises(ScopeError, match="resolved outside loopback"):
            execute(load_project(config), tmp_path)
    assert box["n"] == 0


def test_proxy_forwards_an_in_scope_request_and_blocks_the_rest() -> None:
    box = _box()
    scope = (ScopeHost("127.0.0.1", False),)
    with _http(box) as server:
        port = _port(server)
        with confine(scope) as gate:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": gate.url, "https": gate.url})
            )
            with opener.open(f"http://127.0.0.1:{port}/", timeout=2) as response:
                assert response.status == 200
                assert response.read() == b"landed"
            mark = gate.mark()
            with pytest.raises(urllib.error.HTTPError) as caught:
                opener.open(f"http://out-of-scope.invalid:{port}/secret", timeout=2)
            assert caught.value.code == 403
            caught.value.close()
            blocked = gate.since(mark)
            assert blocked[0].host == "out-of-scope.invalid"
            _assert_connect_blocked(gate, port)
    assert box["n"] == 2


def _assert_connect_blocked(gate: object, port: int) -> None:
    from insidia.egress import Gate

    assert isinstance(gate, Gate)
    mark = gate.mark()
    sock = socket.create_connection(("127.0.0.1", gate.port), timeout=2)
    try:
        sock.sendall(
            b"CONNECT out-of-scope.invalid:443 HTTP/1.1\r\n"
            b"Host: out-of-scope.invalid:443\r\n\r\n"
        )
        data = _read_some(sock)
    finally:
        sock.close()
    assert b"403" in data
    assert gate.since(mark)[0].host == "out-of-scope.invalid"
    allowed = socket.create_connection(("127.0.0.1", gate.port), timeout=2)
    try:
        target = f"127.0.0.1:{port}"
        allowed.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = allowed.recv(4096)
            assert chunk
            head += chunk
        assert b"200" in head.split(b"\r\n", 1)[0]
        allowed.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        body = _read_some(allowed)
    finally:
        allowed.close()
    assert b"landed" in body


def _read_some(sock: socket.socket) -> bytes:
    sock.settimeout(2)
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        data += chunk
        if len(data) > 65536:
            break
    return data


def test_proxy_allows_only_the_registered_relay_port(monkeypatch: pytest.MonkeyPatch) -> None:
    _lookup(monkeypatch, {"pinned.invalid": ("127.0.0.1",)})
    allowed = _box()
    other = _box()
    with _http(allowed) as server, _http(other) as extra:
        port = _port(server)
        extra_port = _port(extra)
        with confine((ScopeHost("pinned.invalid", True),)) as gate:
            gate.allow_internal("127.0.0.1", port)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": gate.url}))
            with opener.open(f"http://127.0.0.1:{port}/", timeout=2) as response:
                assert response.status == 200
            with pytest.raises(urllib.error.HTTPError) as caught:
                opener.open(f"http://127.0.0.1:{extra_port}/", timeout=2)
            assert caught.value.code == 403
            caught.value.close()
    assert allowed["n"] == 1
    assert other["n"] == 0


def test_a_proxied_subprocess_cannot_reach_an_out_of_scope_listener(tmp_path: Path) -> None:
    box = _box()
    with _http(box) as server:
        port = _port(server)
        script = tmp_path / "engine.py"
        script.write_text(
            "import urllib.request\n"
            f"urllib.request.urlopen('http://out-of-scope.invalid:{port}/secret', timeout=2)\n",
            encoding="utf-8",
        )
        with confine((ScopeHost("127.0.0.1", False),)):
            with pytest.raises(EngineFailed, match="tried to leave scope"):
                launch_installed(
                    Invocation(sys.executable, (str(script),), "report.json", timeout=15),
                    tmp_path,
                )
    assert box["n"] == 0


def test_a_proxied_subprocess_can_reach_an_in_scope_listener(tmp_path: Path) -> None:
    box = _box()
    with _http(box) as server:
        port = _port(server)
        script = tmp_path / "engine.py"
        script.write_text(
            "import urllib.request\n"
            f"urllib.request.urlopen('http://127.0.0.1:{port}/', timeout=2).read()\n",
            encoding="utf-8",
        )
        with confine((ScopeHost("127.0.0.1", False),)):
            launch_installed(
                Invocation(sys.executable, (str(script),), "report.json", timeout=15),
                tmp_path,
            )
    assert box["n"] == 1


def test_confinement_points_children_at_the_proxy_and_drops_a_caller_proxy() -> None:
    assert current_gate() is None
    assert "http_proxy" not in child_env({"http_proxy": "http://evil.example"})
    scope = (ScopeHost("127.0.0.1", False),)
    with confine(scope) as gate:
        assert current_gate() is gate
        env = child_env({"http_proxy": "http://evil.example", "NO_PROXY": "localhost"})
        assert env["HTTP_PROXY"] == gate.url
        assert env["HTTPS_PROXY"] == gate.url
        assert env["ALL_PROXY"] == gate.url
        assert env["INSIDIA_EGRESS_PROXY"] == gate.url
        assert "evil.example" not in env["HTTP_PROXY"]
        assert "NO_PROXY" not in env
        assert "no_proxy" not in env
        assert engine_proxy_args("nuclei") == ("-proxy", gate.url)
        assert engine_proxy_args("katana") == ("-proxy", gate.url)
        assert engine_proxy_args("httpx") == ("-http-proxy", gate.url)
        assert engine_proxy_args("dalfox") == ("--proxy", gate.url)
        zap = engine_proxy_args("zap")
        assert f"network.connection.httpProxy.port={gate.port}" in zap
        assert f"connection.proxyChain.port={gate.port}" in zap
        assert engine_proxy_args("trivy") == ()
        assert engine_proxy_args("gitleaks") == ()
    assert current_gate() is None
    assert engine_proxy_args("nuclei") == ()


def test_garak_is_forced_through_the_proxy(tmp_path: Path) -> None:
    adapter = next(item for item in ADAPTERS if item.engine == "garak")
    assert isinstance(adapter, RelayAdapter)
    with confine((ScopeHost("127.0.0.1", False),)) as gate:
        adapter.prepare(
            adapter.probes[0],
            RelayEndpoint("http://127.0.0.1:9/send", "relay-token"),
            tmp_path,
        )
        text = (tmp_path / "generator.json").read_text(encoding="utf-8")
    assert gate.url in text


def test_web_engines_receive_proxy_flags_only_while_confined(tmp_path: Path) -> None:
    adapter = next(item for item in ADAPTERS if item.engine == "nuclei")
    view = ScopedUrl("http://127.0.0.1:9/", ())
    with confine((ScopeHost("127.0.0.1", False),)) as gate:
        invocation = adapter.prepare(adapter.probes[0], view, tmp_path)  # type: ignore[arg-type]
    assert invocation.args[-2:] == ("-proxy", gate.url)


def test_confine_releases_the_gate_when_setup_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _lookup(monkeypatch, {"localhost": ("192.168.1.50",)})
    with pytest.raises(ScopeError):
        with confine((ScopeHost("localhost", False),)):
            raise AssertionError("proxy should not start")
    assert current_gate() is None
