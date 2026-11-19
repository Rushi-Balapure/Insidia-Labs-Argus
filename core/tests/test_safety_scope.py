"""Scope edges, and proof that an out-of-scope hop is never contacted."""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from insidia.adapters import BUILT_IN
from insidia.config import ModelRole
from insidia.errors import ConfigError, ScopeError
from insidia.providers import build_provider
from insidia.registry import Capability
from insidia.scan import execute
from insidia.scope import (
    LOCAL_HOSTS,
    ScopeHost,
    check_url,
    hostname,
    redirect_refusal,
    unauthorized_host,
)
from insidia.transport import exchange, fetch
from tests.support import target

_LOCAL = (ScopeHost("localhost", False), ScopeHost("127.0.0.1", False), ScopeHost("::1", False))
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


class _Guard:
    """Record every connect and non-local lookup. Non-local connects are blocked."""

    def __init__(self) -> None:
        self.contacts: list[tuple[str, int]] = []
        self.lookups: list[str] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real_connect = socket.create_connection
        real_lookup = socket.getaddrinfo

        def connect(address: object, *args: object, **kwargs: object) -> socket.socket:
            host, port = _address(address)
            self.contacts.append((host, port))
            if host not in _LOOPBACK:
                raise OSError(f"blocked connection to {host}")
            return real_connect(address, *args, **kwargs)  # type: ignore[arg-type]

        def lookup(host: object, port: object, *args: object, **kwargs: object) -> object:
            if isinstance(host, str) and host not in _LOOPBACK:
                self.lookups.append(host)
                host = "127.0.0.1"
            return real_lookup(host, port, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(socket, "create_connection", connect)
        monkeypatch.setattr(socket, "getaddrinfo", lookup)


def _address(address: object) -> tuple[str, int]:
    if isinstance(address, tuple) and address:
        host = str(address[0])
        port = address[1] if len(address) > 1 and isinstance(address[1], int) else -1
        return host, port
    return str(address), -1


class _Quiet(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        return


@contextmanager
def _http(handler: type[BaseHTTPRequestHandler]) -> Iterator[ThreadingHTTPServer]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
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


# Localhost certificate for the downgrade test. It is not a credential we use.
_CERT_PEM = """\
-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUN4/oP2pWfBk3W9/z0MPUAQXqxOUwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJMTI3LjAuMC4xMB4XDTI2MTExOTAyMjQ1N1oXDTM2MTEx
NjAyMjQ1N1owFDESMBAGA1UEAwwJMTI3LjAuMC4xMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAjgd+vwOWAWHADa3faQl/yFYWpKeGOwbMCW4qAEzskkcE
mV031nVxuvAdckiPKQG8cPXl6jK+QmX42xgJcpIVIzjpKAvzUwGIDXq6afC08u5Y
srkdiYTP5QsZWkfHiLf5U24ulPaDa4lrgFfcTOqi92E944ox9oYacVz4jF3GojNO
r4fg2WCfY7+jlj4eXbzKNCJgfAXKujKlXJVNu3V8FdE5uWrg4kaF+2dzNNHcXrqr
yPIcSw+d+mpxyL0DUg0CSuqn0GKMmQe6SraK+3IZSuckWZc523MzwJk5BG0y/oJW
tPUtLHFKLWy0I4oTZSLs2EkpQ2bKt3JAxWhvbTF9hQIDAQABo1MwUTAdBgNVHQ4E
FgQUs3cFHTdK2tdMpC6pIBAaBiSXAm4wHwYDVR0jBBgwFoAUs3cFHTdK2tdMpC6p
IBAaBiSXAm4wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAY84F
2WeiXO556OFO2dJmLNT45eqX6RmiVssuo4D4FXcRVrESH125i9tTBJWOl3ezGy32
LrVyEG3aWGBtbtPy3o3uJZM85KJRqxUwSeNuo5sVfRbvshM+70q/X0mhFMRReRfe
rVU9oOImM0va0YxPSrd6872ATTCcEAaOycFXMjj+Oyt1FklBLlzURSuFO4S91j0F
tcR88qkxz1emjWWXrVYC5MK2gPO0bZ14ncTS0gtZcVjh/TTU8SVjNmLlXzDS09lg
Mbv8/N/f6jX+IZyMoKbST+BnSghusCvaAfYaGs5TNdOKBs+svpMoZ6QAOtDkolcf
OEzL8TNOGQyHclbqLg==
-----END CERTIFICATE-----
"""
_KEY_PEM = """\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCOB36/A5YBYcAN
rd9pCX/IVhakp4Y7BswJbioATOySRwSZXTfWdXG68B1ySI8pAbxw9eXqMr5CZfjb
GAlykhUjOOkoC/NTAYgNerpp8LTy7liyuR2JhM/lCxlaR8eIt/lTbi6U9oNriWuA
V9xM6qL3YT3jijH2hhpxXPiMXcaiM06vh+DZYJ9jv6OWPh5dvMo0ImB8Bcq6MqVc
lU27dXwV0Tm5auDiRoX7Z3M00dxeuqvI8hxLD536anHIvQNSDQJK6qfQYoyZB7pK
tor7chlK5yRZlznbczPAmTkEbTL+gla09S0scUotbLQjihNlIuzYSSlDZsq3ckDF
aG9tMX2FAgMBAAECggEAPG6w/fq7IYRjsQ5aALnzfp0uzkmfwk7ek2amBXG1uXnx
WYZCA4T+auHPTbjU/UhJU7E1bmS/8sWr0SGVp4PD7bRB9PG8y4VbzAx79Cbg/3ru
D8HXcROrV9RUqcbf/mr1cgvwUx7fBWs37Ci2Sp4N0H+2UzKSlsgxySmbcjJWmd3j
pS6m3m6NJ+Bq42FKqR7CqUlbFjw73kC7N4XxvNHr+RuRP0ptpfQa1qtxGJ056VPE
za//agmm+n60pvhFZQzYAAN0/rdJloAH3AIjNhExEn2o8WcMrl31pmN2NUw4G6VY
mWhZ1bxF45uGrPADw0ZnISU/yPKFcjndw5qhsxkBgwKBgQDBJo/IjX6DZFTED9is
xf1Sg2PyKRvuICw0Vbz6wD4w9vYSMGhpc2DfsvltEPPvWBVpYMF8nSA12fhIn7S0
kFC5IAM2O8czp3xw0Cv5mfvlUJlvoVI/zAVqnf9XljAO3ByI3hHhaLYsvQnYWo6W
jXersuzlINm1JH7McxW1AWAQqwKBgQC8PobyLufygfBp0zBLHler3xFovcntQByG
dev47tWy0nFRzZS9Brq2+GpanhwxEz51791BcA8GHY6YgM1nIeOIE9yWeGgZg3X5
3H8EVfWnOg8snFMKV6w2VTKlaCOdrMY0hkCW60r4f4jbsr25hbDqQfMEow42Tx5m
fwTVlqSKjwKBgQC6PItQ7hV5bUlKTpk2ZiVO5T9+ZGL45O6ae70e7jRJFCbJ/QEA
BG744uIbZsg+FGl41QFbPUmsgwIiTFN58tjS12ohZdw6Exkq0Z5FKlM2ldOMTjk3
KGpklfl5o2etPFELK0yEUmmtk4ylnxNzWO51kK1YdKdWQN0+Fw1sHOpaxwKBgBoS
evROJNgEwTyXAIhW8oOeiLW+G5qdl5XT/VPkGHsFBKb011X6+Z9f9rMIVRVC+hKx
ny5yC9KoA1kB9fED05TEU3gPwzNNbuilbn42PajktLdUC3hSPkrkL/iS3OP4yxb5
RTbh7edPGrB7KCXq6172tWb+AnjpKme9zfibPbznAoGATG26YwjH/QupcT+XG5sB
SSmdSxaZBJvinV62zTDFc7aGf0/Q2m2YurILgnJoqpg4g1seWP2tbqL7n0Olc7s9
jus/EoRXIO78l4rJb3Ah4RRw9dT+6uaQJbdzr5dSenIPuXcLO5kA29TSNSNIXjJ2
U9JskX0u3T1SLtnMyaTlcnw=
-----END PRIVATE KEY-----
"""


def _pem(tmp_path: Path) -> tuple[Path, Path]:
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text(_CERT_PEM, encoding="utf-8")
    key.write_text(_KEY_PEM, encoding="utf-8")
    return cert, key


@contextmanager
def _https(
    cert: Path, key: Path, handler: type[BaseHTTPRequestHandler]
) -> Iterator[ThreadingHTTPServer]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _trust_local_cert(monkeypatch: pytest.MonkeyPatch) -> None:
    def context(_http_version: int) -> ssl.SSLContext:
        client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client.check_hostname = False
        client.verify_mode = ssl.CERT_NONE
        return client

    monkeypatch.setattr(http.client, "_create_https_context", context)


def _counts() -> dict[str, int]:
    return {"n": 0}


def _ok(box: dict[str, int]) -> type[_Quiet]:
    class Handler(_Quiet):
        def do_GET(self) -> None:  # noqa: N802
            box["n"] += 1
            body = b"landed"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            self.do_GET()

    return Handler


def _redirect(box: dict[str, int], location: str) -> type[_Quiet]:
    class Handler(_Quiet):
        def do_GET(self) -> None:  # noqa: N802
            box["n"] += 1
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()

        def do_POST(self) -> None:  # noqa: N802
            self.do_GET()

    return Handler


def test_same_origin_redirect_is_followed(monkeypatch: pytest.MonkeyPatch) -> None:
    guard = _Guard()
    guard.install(monkeypatch)
    seen = _counts()

    class Handler(_Quiet):
        def do_GET(self) -> None:  # noqa: N802
            seen["n"] += 1
            if self.path.startswith("/go"):
                self.send_response(302)
                self.send_header("Location", "/landed")
                self.end_headers()
                return
            body = b"landed"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with _http(Handler) as server:
        port = _port(server)
        status, _headers, body = fetch(f"http://127.0.0.1:{port}/go", _LOCAL)
    assert status == 200
    assert body == "landed"
    assert seen["n"] == 2
    assert {host for host, _port_n in guard.contacts} == {"127.0.0.1"}
    assert guard.lookups == []


def test_direct_out_of_scope_host_is_not_contacted(monkeypatch: pytest.MonkeyPatch) -> None:
    guard = _Guard()
    guard.install(monkeypatch)
    evil = _counts()
    with _http(_ok(evil)) as server:
        port = _port(server)
        with pytest.raises(ScopeError, match="not in scope"):
            fetch(f"http://out-of-scope.invalid:{port}/secret", _LOCAL)
    assert evil["n"] == 0
    assert guard.contacts == []
    assert guard.lookups == []


@pytest.mark.parametrize(
    "location_for",
    [
        "host",
        "protocol-relative",
        "userinfo-host",
        "userinfo-port",
    ],
)
def test_redirect_off_host_is_not_contacted(
    monkeypatch: pytest.MonkeyPatch, location_for: str
) -> None:
    guard = _Guard()
    guard.install(monkeypatch)
    evil = _counts()
    origin = _counts()
    with _http(_ok(evil)) as other:
        other_port = _port(other)
        if location_for == "host":
            location = f"http://out-of-scope.invalid:{other_port}/secret"
        elif location_for == "protocol-relative":
            location = f"//out-of-scope.invalid:{other_port}/secret"
        elif location_for == "userinfo-host":
            location = f"http://127.0.0.1@out-of-scope.invalid:{other_port}/secret"
        else:
            location = f"http://out-of-scope.invalid@127.0.0.1:{other_port}/secret"
        with _http(_redirect(origin, location)) as server:
            port = _port(server)
            with pytest.raises((ScopeError, ConfigError)):
                fetch(f"http://127.0.0.1:{port}/go", _LOCAL)
    assert origin["n"] == 1
    assert evil["n"] == 0
    assert all(host in _LOOPBACK for host, _seen_port in guard.contacts)
    assert "out-of-scope.invalid" not in guard.lookups
    assert other_port not in {seen for _host, seen in guard.contacts}


def test_redirect_to_another_port_is_not_contacted(monkeypatch: pytest.MonkeyPatch) -> None:
    guard = _Guard()
    guard.install(monkeypatch)
    landed = _counts()
    origin = _counts()
    with _http(_ok(landed)) as other:
        other_port = _port(other)
        location = f"http://127.0.0.1:{other_port}/secret"
        with _http(_redirect(origin, location)) as server:
            port = _port(server)
            with pytest.raises(ScopeError, match="redirect changed port"):
                exchange(
                    target(url=f"http://127.0.0.1:{port}/go", method="GET"),
                    "payload",
                    _LOCAL,
                    Path("."),
                )
    assert origin["n"] == 1
    assert landed["n"] == 0
    assert other_port not in {seen for _host, seen in guard.contacts}
    assert {host for host, _seen in guard.contacts} == {"127.0.0.1"}


def test_https_downgrade_is_not_contacted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    guard = _Guard()
    guard.install(monkeypatch)
    _trust_local_cert(monkeypatch)
    landed = _counts()
    origin = _counts()
    cert, key = _pem(tmp_path)
    with _http(_ok(landed)) as plain:
        plain_port = _port(plain)
        location = f"http://127.0.0.1:{plain_port}/downgraded"
        with _https(cert, key, _redirect(origin, location)) as server:
            port = _port(server)
            with pytest.raises(ScopeError, match="downgraded https to http"):
                fetch(f"https://127.0.0.1:{port}/start", _LOCAL)
    assert origin["n"] == 1
    assert landed["n"] == 0
    assert plain_port not in {seen for _host, seen in guard.contacts}


def test_scan_does_not_follow_an_out_of_scope_redirect(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    guard = _Guard()
    guard.install(monkeypatch)
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    evil = _counts()
    origin = _counts()
    spec = next(item for item in BUILT_IN.probes if item.family == "web.ssti")

    def only_ssti(
        family: str,
        mode: str,
        model_available: bool = False,
        entries: object = None,
    ) -> list[Capability]:
        del mode, model_available, entries
        if family != "web.ssti":
            return []
        return [Capability(family, "insidia", spec.probe, spec.priority, False, True)]

    monkeypatch.setattr("insidia.scan.select", only_ssti)
    with _http(_ok(evil)) as other:
        other_port = _port(other)
        location = f"http://out-of-scope.invalid:{other_port}/secret"
        with _http(_redirect(origin, location)) as server:
            port = _port(server)
            config = tmp_path / "insidia.yaml"
            config.write_text(
                f"""
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  app:
    kind: web
    url: http://127.0.0.1:{port}/go
    method: GET
    rate_limit:
      rps: 100
      concurrency: 1
"""
            )
            from insidia.config import load_project

            outcome = execute(load_project(config), tmp_path)
    assert origin["n"] >= 1
    assert evil["n"] == 0
    assert "out-of-scope.invalid" not in guard.lookups
    assert other_port not in {seen for _host, seen in guard.contacts}
    assert outcome.passed is False
    assert outcome.policy_verdict != "pass"
    document = json.loads((outcome.run_dir / "benchmark.json").read_text(encoding="utf-8"))
    rows = [row for row in document["controls"] if row.get("id") == "web.ssti"]
    assert rows
    assert all(row["result"] != "pass" for row in rows)


def test_userinfo_url_is_rejected_before_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    guard = _Guard()
    guard.install(monkeypatch)
    with pytest.raises(ConfigError, match="secret_ref"):
        fetch("http://localhost@out-of-scope.invalid/secret", _LOCAL)
    with pytest.raises(ConfigError, match="secret_ref"):
        check_url("http://evil.com@localhost/secret", _LOCAL)
    assert guard.contacts == []
    assert guard.lookups == []


def test_in_scope_model_host_is_not_called(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    guard = _Guard()
    guard.install(monkeypatch)
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    hits = _counts()
    source = tmp_path / "src"
    source.mkdir()
    (source / "main.py").write_text("print('hello')\n", encoding="utf-8")
    with _http(_ok(hits)) as server:
        port = _port(server)
        config = tmp_path / "insidia.yaml"
        config.write_text(
            f"""
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  code:
    kind: repo
    path: src
models:
  attacker:
    provider: openai-compatible
    base_url: http://127.0.0.1:{port}/v1
    model: local
  judge:
    provider: anthropic
    base_url: http://127.0.0.1:{port}
    model: claude
"""
        )
        from insidia.config import load_project

        execute(load_project(config), tmp_path)
    assert hits["n"] == 0
    assert port not in {seen for _host, seen in guard.contacts}


@pytest.mark.parametrize(
    ("provider", "base_url", "model"),
    [
        ("openai-compatible", "http://out-of-scope.invalid/v1", "local"),
        ("anthropic", "http://out-of-scope.invalid", "claude"),
        ("gemini", "http://out-of-scope.invalid", "gemini-pro"),
    ],
)
def test_provider_does_not_connect_to_an_unlisted_host(
    monkeypatch: pytest.MonkeyPatch, provider: str, base_url: str, model: str
) -> None:
    guard = _Guard()
    guard.install(monkeypatch)
    role = ModelRole("attacker", provider, base_url, model, None)
    with pytest.raises(ScopeError, match="not in scope"):
        build_provider(role, _LOCAL)
    assert guard.contacts == []
    assert guard.lookups == []


def test_provider_constructors_do_not_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    guard = _Guard()
    guard.install(monkeypatch)
    scope = (ScopeHost("127.0.0.1", False),)
    build_provider(
        ModelRole("attacker", "openai-compatible", "http://127.0.0.1:9/v1", "local", None),
        scope,
    )
    build_provider(
        ModelRole("judge", "anthropic", "http://127.0.0.1:9", "claude", None),
        scope,
    )
    build_provider(
        ModelRole("judge", "gemini", "http://127.0.0.1:9", "gemini-pro", None),
        scope,
    )
    with pytest.raises(ConfigError, match="base_url and model"):
        build_provider(ModelRole("attacker", "anthropic", None, "claude", None), scope)
    with pytest.raises(ConfigError, match="base_url and model"):
        build_provider(ModelRole("judge", "gemini", "http://127.0.0.1:9", None, None), scope)
    with pytest.raises(ConfigError, match="openai-compatible"):
        build_provider(
            ModelRole("attacker", "bedrock", "http://127.0.0.1:9", "model", None),
            scope,
        )
    with pytest.raises(ConfigError, match="unknown model provider"):
        build_provider(ModelRole("attacker", "custom", "http://127.0.0.1:9", "model", None), scope)
    assert guard.contacts == []
    assert guard.lookups == []


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost@evil.com/a",
        "http://user:pass@127.0.0.1/a",
        "https://:secret@localhost/a",
        "http://127.0.0.1:80@evil.com/a",
        "http://evil.com\\@localhost/",
    ],
)
def test_userinfo_is_rejected(url: str) -> None:
    with pytest.raises(ConfigError, match="secret_ref"):
        check_url(url, _LOCAL)


@pytest.mark.parametrize(
    "url",
    [
        "ftp://127.0.0.1/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "gopher://127.0.0.1/",
        "http://",
        "localhost/path",
        "",
    ],
)
def test_unsupported_scheme_or_missing_host_is_rejected(url: str) -> None:
    with pytest.raises(ConfigError):
        check_url(url, _LOCAL)
    with pytest.raises(ConfigError):
        hostname(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:1/a",
        "http://127.0.0.1:65535/a",
        "https://localhost/a",
        "HTTP://LocalHost:8080/a",
        "ws://127.0.0.1:9/a",
        "wss://localhost/a",
        "grpc://127.0.0.1/pkg.Service",
    ],
)
def test_local_host_matches_on_every_port_and_supported_scheme(url: str) -> None:
    host = hostname(url)
    assert host in LOCAL_HOSTS
    assert check_url(url, _LOCAL) == host


@pytest.mark.parametrize(
    "url",
    [
        "http://2130706433/",
        "http://127.1/",
        "http://0x7f.0.0.1/",
        "http://0177.0.0.1/",
        "http://127.0.0.1.evil.com/",
        "http://127.0.0.1%2eevil.com/",
        "http://0.0.0.0/",
        "http://[::]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[0:0:0:0:0:0:0:1]/",
        "http://spoofed.localhost/",
        "http://localhost.localhost/",
    ],
)
def test_lookalike_addresses_are_not_loopback(url: str) -> None:
    host = hostname(url)
    assert host not in LOCAL_HOSTS
    with pytest.raises(ScopeError, match="not in scope"):
        check_url(url, _LOCAL)


def test_localhost_and_ip_are_different_hosts() -> None:
    names = (ScopeHost("localhost", False),)
    addresses = (ScopeHost("127.0.0.1", False),)
    with pytest.raises(ScopeError, match="not in scope"):
        check_url("http://127.0.0.1/", names)
    with pytest.raises(ScopeError, match="not in scope"):
        check_url("http://localhost/", addresses)
    assert check_url("http://[::1]:9/", (ScopeHost("::1", False),)) == "::1"


@pytest.mark.parametrize(
    "url",
    [
        "http://api.example.com/",
        "http://example.com.evil.net/",
        "http://notexample.com/",
        "http://example.com./",
        "http://example.com.evil.com/",
        "https://evil.example.com/a",
    ],
)
def test_subdomains_and_suffixes_are_not_implied(url: str) -> None:
    scope = (ScopeHost("example.com", True),)
    with pytest.raises(ScopeError, match="not in scope"):
        check_url(url, scope)


def test_wildcard_scope_is_literal() -> None:
    scope = (ScopeHost("*.example.com", True),)
    with pytest.raises(ScopeError, match="not in scope"):
        check_url("http://api.example.com/", scope)
    with pytest.raises(ScopeError, match="not in scope"):
        check_url("http://example.com/", scope)
    assert check_url("http://*.example.com/", scope) == "*.example.com"
    assert unauthorized_host((ScopeHost("*.example.com", False),)) == "*.example.com"


def test_trailing_dot_is_a_different_host() -> None:
    assert hostname("http://localhost./a") == "localhost."
    assert hostname("http://example.com./a") == "example.com."
    assert "localhost." not in LOCAL_HOSTS
    with pytest.raises(ScopeError, match="not in scope"):
        check_url("http://localhost./a", _LOCAL)
    with pytest.raises(ScopeError, match="authorized: true"):
        check_url("http://localhost./a", (ScopeHost("localhost.", False),))
    assert check_url("http://localhost./a", (ScopeHost("localhost.", True),)) == "localhost."


def test_idn_and_case_use_the_parsed_hostname() -> None:
    host = hostname("http://EXÄMPLE.COM/a")
    assert host == host.lower()
    assert host != "example.com"
    assert check_url("http://exämple.com/a", (ScopeHost(host, True),)) == host
    with pytest.raises(ScopeError):
        check_url("http://exämple.com/a", (ScopeHost("example.com", True),))
    puny = "xn--exmple-cua.com"
    if host != puny:
        with pytest.raises(ScopeError, match="not in scope"):
            check_url("http://exämple.com/a", (ScopeHost(puny, True),))
    assert hostname("HTTP://Example.COM:8443/a") == "example.com"
    assert check_url("HTTP://Example.COM/a", (ScopeHost("example.com", True),)) == "example.com"


def test_redirect_refusal_edges() -> None:
    assert redirect_refusal("http://Example.COM/a", "HTTP://example.com/b") is None
    assert redirect_refusal("http://127.0.0.1:80/a", "http://127.0.0.1/b") is None
    assert redirect_refusal("https://127.0.0.1/a", "wss://127.0.0.1/b") is None
    assert redirect_refusal("http://127.0.0.1:9/a", "https://127.0.0.1:9/a") is None
    assert redirect_refusal("ws://127.0.0.1:9/a", "wss://127.0.0.1:9/a") is None
    assert (
        redirect_refusal("https://127.0.0.1/a", "http://127.0.0.1:8443/a")
        == "redirect downgraded https to http"
    )
    assert (
        redirect_refusal("wss://127.0.0.1:443/a", "ws://127.0.0.1/a")
        == "redirect downgraded wss to ws"
    )
    assert redirect_refusal("http://example.com./a", "http://example.com/a") == (
        "redirect left example.com."
    )
    assert redirect_refusal("https://127.0.0.1/a", "https://[::1]/a") == "redirect left 127.0.0.1"
