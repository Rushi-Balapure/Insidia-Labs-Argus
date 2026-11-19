"""TLS handshake classification for the infra.tls probe."""

from __future__ import annotations

import socket
import ssl
from pathlib import Path
from urllib.parse import urlparse

from insidia.adapters import ORACLES, EngineHit
from insidia.config import Target
from insidia.egress import open_socket
from insidia.errors import ConfigError, ProbeError
from insidia.scope import ScopeHost, check_url


def _paired_tls(
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str, str]:
    """A handshake that succeeds with TLS 1.0 or 1.1 only."""
    from insidia.probes import _send

    try:
        planted = _send(target, "proto", scope, root)
    except ProbeError:
        planted = ""
    if ORACLES["infra.tls"]("proto", planted, target) is not None:
        return [EngineHit("insidia-tls", "proto", planted, planted)], "", ""
    if target.url is None:
        raise ConfigError(f"{target.name} needs a url")
    parsed = urlparse(target.url)
    if parsed.scheme not in {"https", "wss"} or parsed.hostname is None:
        return [], "", f"{parsed.scheme}:// target has no TLS to test"
    check_url(target.url, scope)
    port = parsed.port or 443
    accepted: list[str] = []
    for name, version in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        outcome = _handshake(parsed.hostname, port, version)
        if isinstance(outcome, str):
            if accepted:
                break
            return [], "", outcome
        if outcome:
            accepted.append(name)
    if not accepted:
        return [], "", ""
    evidence = f"{parsed.hostname}:{port} accepted {' and '.join(accepted)}"
    return [EngineHit("insidia-tls", "handshake", evidence, evidence)], "", ""


_CLIENT_TLS_GAP = "this machine's OpenSSL cannot offer TLS 1.0 or 1.1"
_LEGACY_TLS = {
    ssl.TLSVersion.TLSv1: "TLSv1",
    ssl.TLSVersion.TLSv1_1: "TLSv1.1",
}
_MODERN_TLS = frozenset({"TLSv1.2", "TLSv1.3"})


def _ssl_text(exc: BaseException) -> str:
    reason = getattr(exc, "reason", None)
    text = str(exc)
    if isinstance(reason, str) and reason:
        return f"{reason} {text}".upper()
    return text.upper()


def _client_cannot_offer(exc: BaseException) -> bool:
    token = _ssl_text(exc)
    return (
        "NO_PROTOCOLS_AVAILABLE" in token
        or "UNSUPPORTED_PROTOCOL" in token
        or "UNSUPPORTED PROTOCOL" in token
        or "NO_CIPHERS_AVAILABLE" in token
    )


def _server_refused(exc: ssl.SSLError) -> bool:
    """True only for a protocol-version or handshake-failure alert from the peer."""
    token = _ssl_text(exc)
    return "PROTOCOL_VERSION" in token or "HANDSHAKE_FAILURE" in token


def _connect_gap(exc: OSError) -> str:
    if isinstance(exc, TimeoutError):
        return "connection timed out"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, socket.gaierror):
        return "DNS lookup failed"
    if isinstance(exc, ConnectionResetError):
        return "connection reset before a TLS handshake"
    if isinstance(exc, ConnectionAbortedError | BrokenPipeError):
        return "connection closed before a TLS handshake"
    return "could not open a connection"


def _tls_gap(exc: ssl.SSLError) -> bool | str:
    if _client_cannot_offer(exc):
        return _CLIENT_TLS_GAP
    if _server_refused(exc):
        return False
    if isinstance(exc, ssl.SSLEOFError) or "EOF" in _ssl_text(exc):
        return "connection closed before a TLS handshake"
    return "TLS handshake did not finish"


def _handshake(host: str, port: int, version: ssl.TLSVersion) -> bool | str:
    """True when the server accepts this version, False when it refuses it.

    A string means the attempt was not tested. The string is why.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = version
        context.maximum_version = version
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return _CLIENT_TLS_GAP
    wanted = _LEGACY_TLS[version]
    try:
        with open_socket(host, port, 10) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                chosen = tls.version()
    except ssl.SSLError as exc:
        return _tls_gap(exc)
    except OSError as exc:
        return _connect_gap(exc)
    if chosen == wanted:
        return True
    if chosen in _MODERN_TLS:
        return False
    return "TLS handshake did not finish"
