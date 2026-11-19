"""Old TLS is a finding only when a handshake shows the server accepted it.

A dead host, a DNS failure, a timeout, or a peer that closes before any TLS
alert is not evidence that the server refuses TLS 1.0 or 1.1. Those stay not
tested. A protocol-version or handshake-failure alert is a refusal, which is a
pass. A client that cannot offer the old version is not tested either.
"""

from __future__ import annotations

import socket
import ssl
import subprocess
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest
from insidia.adapters import find
from insidia.config import Project
from insidia.policy import get_policy
from insidia.probes import Attempt, run
from insidia.scope import ScopeHost
from tests.support import target

pytestmark = pytest.mark.filterwarnings("ignore:ssl.TLSVersion.TLSv1:DeprecationWarning")

_CLIENT_GAP = "this machine's OpenSSL cannot offer TLS 1.0 or 1.1"
_LOCAL = (ScopeHost("127.0.0.1", False),)


def _attempt(url: str, root: Path) -> Attempt:
    chosen = replace(target("web", url, method="GET"), timeout=2)
    project = Project(root / "insidia.yaml", 1, "L1", "standard", _LOCAL, (chosen,), None, None)
    adapter, spec = find("insidia.infra.tls")
    return run(
        adapter,
        spec,
        chosen,
        project,
        root,
        get_policy("L1").control("infra.tls"),
    )


def _assert_not_tested(attempt: Attempt, reason: str) -> None:
    assert attempt.hits == ()
    assert attempt.error == ""
    assert attempt.untested == reason


def _closed_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


@contextmanager
def _tcp_server(close: bool) -> Iterator[int]:
    """Accept loopback connections. Close immediately, or hold them open."""
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
            if close:
                conn.close()
                continue
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


def _client_offers(version: ssl.TLSVersion) -> bool:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        context.minimum_version = version
        context.maximum_version = version
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return False
    return True


def _certificate(directory: Path) -> tuple[Path, Path]:
    cert = directory / "cert.pem"
    key = directory / "key.pem"
    result = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
        ],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        pytest.skip("openssl could not write a localhost certificate")
    return cert, key


@contextmanager
def _tls_server(
    directory: Path,
    minimum: ssl.TLSVersion,
    maximum: ssl.TLSVersion,
) -> Iterator[int]:
    cert, key = _certificate(directory)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.minimum_version = minimum
        context.maximum_version = maximum
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError) as exc:
        pytest.skip(f"this machine's OpenSSL cannot serve {minimum.name}: {exc}")
    context.load_cert_chain(cert, key)
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)
    sock.settimeout(0.2)
    port = int(sock.getsockname()[1])
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                conn.settimeout(2)
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(4096)
                    tls.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                    )
            except (OSError, ssl.SSLError):
                try:
                    conn.close()
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        sock.close()
        thread.join(1)


def test_unreachable_port_is_not_tested(tmp_path: Path) -> None:
    port = _closed_port()
    attempt = _attempt(f"https://127.0.0.1:{port}/", tmp_path)
    _assert_not_tested(attempt, "connection refused")


def test_dns_failure_is_not_tested(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> list[object]:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    attempt = _attempt("https://127.0.0.1:443/", tmp_path)
    _assert_not_tested(attempt, "DNS lookup failed")


def test_timeout_is_not_tested(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> socket.socket:
        raise TimeoutError("timed out")

    monkeypatch.setattr(socket, "create_connection", fail)
    attempt = _attempt("https://127.0.0.1:443/", tmp_path)
    _assert_not_tested(attempt, "connection timed out")


def test_reset_before_handshake_is_not_tested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_args: object, **_kwargs: object) -> socket.socket:
        raise ConnectionResetError("reset")

    monkeypatch.setattr(socket, "create_connection", fail)
    attempt = _attempt("https://127.0.0.1:443/", tmp_path)
    _assert_not_tested(attempt, "connection reset before a TLS handshake")


def test_tcp_close_before_a_tls_alert_is_not_tested(tmp_path: Path) -> None:
    """A peer that accepts TCP and drops it never sent a protocol alert.

    That is not a refusal of TLS 1.0, so the check must not pass.
    """
    with _tcp_server(close=True) as port:
        attempt = _attempt(f"https://127.0.0.1:{port}/", tmp_path)
    assert attempt.hits == ()
    assert attempt.error == ""
    assert attempt.untested in {
        "connection closed before a TLS handshake",
        "connection reset before a TLS handshake",
    }


def test_aborted_connection_is_not_tested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_args: object, **_kwargs: object) -> socket.socket:
        raise ConnectionAbortedError("aborted")

    monkeypatch.setattr(socket, "create_connection", fail)
    attempt = _attempt("https://127.0.0.1:443/", tmp_path)
    _assert_not_tested(attempt, "connection closed before a TLS handshake")


def test_other_oserror_is_not_tested(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> socket.socket:
        raise OSError("network is down")

    monkeypatch.setattr(socket, "create_connection", fail)
    attempt = _attempt("https://127.0.0.1:443/", tmp_path)
    _assert_not_tested(attempt, "could not open a connection")


def test_modern_tls_server_refuses_old_versions(tmp_path: Path) -> None:
    offers = _client_offers(ssl.TLSVersion.TLSv1) and _client_offers(ssl.TLSVersion.TLSv1_1)
    with _tls_server(tmp_path, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3) as port:
        attempt = _attempt(f"https://127.0.0.1:{port}/", tmp_path)
    assert attempt.hits == ()
    assert attempt.error == ""
    if not offers or attempt.untested == _CLIENT_GAP:
        assert attempt.untested == _CLIENT_GAP
        return
    assert attempt.untested == ""


def test_accepted_tls_1_0_is_a_finding(tmp_path: Path) -> None:
    if not _client_offers(ssl.TLSVersion.TLSv1):
        pytest.skip(_CLIENT_GAP)
    with _tls_server(tmp_path, ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1) as port:
        attempt = _attempt(f"https://127.0.0.1:{port}/", tmp_path)
    if attempt.untested == _CLIENT_GAP:
        pytest.skip(attempt.untested)
    assert attempt.error == ""
    assert attempt.untested == ""
    assert attempt.hits
    assert "TLS 1.0" in attempt.hits[0].evidence


def test_client_without_old_protocols_is_not_tested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def wrap(self: ssl.SSLContext, sock: socket.socket, *_args: object, **_kwargs: object) -> None:
        raise ssl.SSLError(1, "[SSL: NO_PROTOCOLS_AVAILABLE] no protocols available")

    with _tcp_server(close=False) as port:
        monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
        attempt = _attempt(f"https://127.0.0.1:{port}/", tmp_path)
    _assert_not_tested(attempt, _CLIENT_GAP)


def test_unsupported_protocol_on_the_client_is_not_tested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def wrap(self: ssl.SSLContext, sock: socket.socket, *_args: object, **_kwargs: object) -> None:
        raise ssl.SSLError(1, "[SSL: UNSUPPORTED_PROTOCOL] unsupported protocol")

    with _tcp_server(close=False) as port:
        monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
        attempt = _attempt(f"https://127.0.0.1:{port}/", tmp_path)
    _assert_not_tested(attempt, _CLIENT_GAP)


def test_handshake_failure_alert_is_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def wrap(self: ssl.SSLContext, sock: socket.socket, *_args: object, **_kwargs: object) -> None:
        raise ssl.SSLError(1, "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure")

    with _tcp_server(close=False) as port:
        monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
        attempt = _attempt(f"https://127.0.0.1:{port}/", tmp_path)
    assert attempt.hits == ()
    assert attempt.error == ""
    assert attempt.untested == ""


class _Negotiated:
    def __init__(self, name: str | None) -> None:
        self._name = name

    def version(self) -> str | None:
        return self._name

    def __enter__(self) -> _Negotiated:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False


def test_modern_negotiated_version_is_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def wrap(
        self: ssl.SSLContext, sock: socket.socket, *_args: object, **_kwargs: object
    ) -> _Negotiated:
        return _Negotiated("TLSv1.2")

    monkeypatch.setattr("insidia.probes._send", lambda *_args, **_kwargs: "ok")
    with _tcp_server(close=False) as port:
        monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
        attempt = _attempt(f"https://127.0.0.1:{port}/", tmp_path)
    assert attempt.hits == ()
    assert attempt.error == ""
    assert attempt.untested == ""


def test_unknown_negotiated_version_is_not_tested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def wrap(
        self: ssl.SSLContext, sock: socket.socket, *_args: object, **_kwargs: object
    ) -> _Negotiated:
        return _Negotiated(None)

    monkeypatch.setattr("insidia.probes._send", lambda *_args, **_kwargs: "ok")
    with _tcp_server(close=False) as port:
        monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
        attempt = _attempt(f"https://127.0.0.1:{port}/", tmp_path)
    _assert_not_tested(attempt, "TLS handshake did not finish")


def test_context_that_rejects_old_tls_is_not_tested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def setter(self: ssl.SSLContext, value: ssl.TLSVersion) -> None:
        raise ValueError("unsupported protocol")

    monkeypatch.setattr(
        ssl.SSLContext,
        "minimum_version",
        property(lambda self: ssl.TLSVersion.MINIMUM_SUPPORTED, setter),
    )
    port = _closed_port()
    attempt = _attempt(f"https://127.0.0.1:{port}/", tmp_path)
    _assert_not_tested(attempt, _CLIENT_GAP)


def test_non_tls_bytes_are_not_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def wrap(self: ssl.SSLContext, sock: socket.socket, *_args: object, **_kwargs: object) -> None:
        raise ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER] wrong version number")

    with _tcp_server(close=False) as port:
        monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
        attempt = _attempt(f"https://127.0.0.1:{port}/", tmp_path)
    _assert_not_tested(attempt, "TLS handshake did not finish")
