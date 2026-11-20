"""Scope checks on the address a connection uses, and a proxy for engines.

Insidia's own client dials an address returned for the hostname, then checks
the socket peer. It does not dial the name. On the default localhost scope
every address must be loopback, so a hosts-file or DNS answer that includes
any other address is refused. For an authorized host, confine() records the
addresses at scan start. A later answer that does not overlap that set is
refused. The dialed address is one of the allowed ones. The Host header and
TLS server name stay the hostname.

confine() also listens on 127.0.0.1. Engine subprocesses get that listener as
HTTP_PROXY, HTTPS_PROXY, and ALL_PROXY. It accepts HTTP and CONNECT, and it
allows a host in the scan scope only after the same address check, plus the
loopback relay port registered with allow_internal. Anything else is recorded
and answered with 403. A recorded block fails that engine check.

How each engine is confined:

- nuclei, httpx, katana, dalfox, and ZAP get a proxy flag as well as the
  variables. ZAP may still skip its outbound proxy for localhost.
- garak's generator config sets proxies to this proxy.
- promptfoo's provider script posts through the proxy. NODE_USE_ENV_PROXY is
  set for the rest of that process and applies on Node 22 and newer.
- pyrit and deepteam force httpx's AsyncClient to trust the environment when
  this proxy is active. deepteam's own calls use urllib, which honors it.
- trivy, gitleaks, osv-scanner, nuguard, mcp-scanner, and skillspector are
  confined only when they honor the variables.
- bandit and gosec do not open scan connections. The variables are still set.

A binary that ignores the variables and its proxy flag can open its own
socket. Network namespaces are not used.
"""

from __future__ import annotations

import errno
import http.client
import ipaddress
import socket
import socketserver
import threading
import urllib.parse
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, cast

from insidia.errors import ScopeError
from insidia.scope import LOCAL_HOSTS, ScopeHost

_MAX_HEAD = 65_536
_MAX_BODY = 1_000_000
_MAX_BLOCKS = 64
_PROXY_LOOP = frozenset({"127.0.0.1", "localhost", "::1"})


@dataclass(frozen=True)
class Blocked:
    host: str
    port: int
    reason: str


class Gate:
    """One scan's address pin and its proxy. Shared by the scan's threads."""

    def __init__(self, scope: tuple[ScopeHost, ...]) -> None:
        self.scope = scope
        self.pins: dict[str, frozenset[str]] = {}
        self._internal: set[tuple[str, int]] = set()
        self._blocks: list[Blocked] = []
        self._lock = threading.Lock()
        self.port = 0
        self._server: _ProxyServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def pin(self) -> None:
        """Record the addresses each scope host has right now."""
        pinned: dict[str, frozenset[str]] = {}
        for item in self.scope:
            try:
                found = resolve(item.host, 0)
            except socket.gaierror:
                if item.host in LOCAL_HOSTS:
                    raise ScopeError(f"{item.host} resolved outside loopback") from None
                pinned[item.host] = frozenset()
                continue
            if item.host in LOCAL_HOSTS and not _loopback_only(found):
                raise ScopeError(f"{item.host} resolved outside loopback")
            pinned[item.host] = frozenset(found)
        self.pins = pinned

    def allow_internal(self, host: str, port: int) -> None:
        """Let engines reach Insidia's own relay. The address must be loopback."""
        self._internal.add((host.lower(), port))

    def start(self) -> None:
        server = _ProxyServer(self)
        thread = threading.Thread(target=server.serve_forever, name="insidia-egress", daemon=True)
        thread.start()
        self._server = server
        self._thread = thread
        bound = server.server_address
        self.port = int(bound[1])

    def stop(self) -> None:
        server = self._server
        thread = self._thread
        self._server = None
        self._thread = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=2)

    def mark(self) -> int:
        with self._lock:
            return len(self._blocks)

    def since(self, mark: int) -> tuple[Blocked, ...]:
        with self._lock:
            return tuple(self._blocks[mark:])

    def add_block(self, block: Blocked) -> None:
        with self._lock:
            if len(self._blocks) < _MAX_BLOCKS:
                self._blocks.append(block)

    def refusal(self, host: str, port: int) -> str | None:
        """Why this host:port is not a destination, before any dial."""
        name = host.lower()
        if name in _PROXY_LOOP and port == self.port:
            return "proxy loop"
        if (name, port) in self._internal:
            return None
        known = {item.host for item in self.scope}
        if name not in known:
            return f"{name} is not in scope"
        entry = next(item for item in self.scope if item.host == name)
        if name not in LOCAL_HOSTS and not entry.authorized:
            return f"{name} needs authorized: true"
        return None

    def vetted_ips(self, host: str, port: int) -> tuple[str, ...]:
        name = host.lower()
        if name in LOCAL_HOSTS or (name, port) in self._internal:
            return _require_loopback(name, port)
        return self._pinned(name, port)

    def _pinned(self, host: str, port: int) -> tuple[str, ...]:
        found = resolve(host, port)
        if not found:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        with self._lock:
            pinned = self.pins.get(host)
            if pinned is None:
                raise ScopeError(f"{host} is not in scope")
            if not pinned:
                self.pins[host] = frozenset(found)
                pinned = self.pins[host]
        allowed = tuple(ip for ip in found if ip in pinned)
        if not allowed:
            raise ScopeError(f"{host} resolved to an address that was not pinned at scan start")
        return _prefer_v4(allowed)


_stack: list[Gate] = []
_stack_lock = threading.Lock()


def current_gate() -> Gate | None:
    with _stack_lock:
        return _stack[-1] if _stack else None


@contextmanager
def confine(scope: tuple[ScopeHost, ...]) -> Iterator[Gate]:
    """Pin scope addresses and publish the proxy for this scan."""
    gate = Gate(scope)
    gate.pin()
    gate.start()
    with _stack_lock:
        _stack.append(gate)
    try:
        yield gate
    finally:
        with _stack_lock:
            try:
                _stack.remove(gate)
            except ValueError:
                pass
        gate.stop()


def is_loopback(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    if isinstance(mapped, ipaddress.IPv4Address):
        address = mapped
    return bool(address.is_loopback)


def canonical(ip: str) -> str:
    address = ipaddress.ip_address(ip.split("%", 1)[0])
    mapped = getattr(address, "ipv4_mapped", None)
    if isinstance(mapped, ipaddress.IPv4Address):
        address = mapped
    return address.compressed


def resolve(host: str, port: int) -> tuple[str, ...]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    seen: list[str] = []
    for info in infos:
        ip = canonical(str(info[4][0]))
        if ip not in seen:
            seen.append(ip)
    return tuple(seen)


def open_socket(
    host: str,
    port: int,
    timeout: float | None = None,
    source_address: tuple[str, int] | None = None,
    gate: Gate | None = None,
) -> socket.socket:
    """Dial one vetted address and require the peer to be that address."""
    active = current_gate() if gate is None else gate
    ips = _ungated(host, port) if active is None else active.vetted_ips(host, port)
    last: OSError | None = None
    for ip in ips:
        try:
            sock = socket.create_connection((ip, port), timeout, source_address)
        except OSError as exc:
            last = exc
            continue
        peer = canonical(str(sock.getpeername()[0]))
        if peer != canonical(ip):
            sock.close()
            raise ScopeError(f"{host} connected to {peer}")
        _nodelay(sock)
        return sock
    if last is not None:
        raise last
    raise ScopeError(f"{host} resolved outside loopback")


def engine_proxy_args(engine: str) -> tuple[str, ...]:
    """Flags that force a proxy for engines that ignore the environment."""
    gate = current_gate()
    if gate is None:
        return ()
    url = gate.url
    port = str(gate.port)
    if engine in {"nuclei", "katana"}:
        return ("-proxy", url)
    if engine == "httpx":
        return ("-http-proxy", url)
    if engine == "dalfox":
        return ("--proxy", url)
    if engine == "zap":
        return (
            "-config",
            "network.connection.httpProxy.enabled=true",
            "-config",
            "network.connection.httpProxy.host=127.0.0.1",
            "-config",
            f"network.connection.httpProxy.port={port}",
            "-config",
            "connection.proxyChain.enabled=true",
            "-config",
            "connection.proxyChain.hostName=127.0.0.1",
            "-config",
            f"connection.proxyChain.port={port}",
        )
    return ()


def handlers() -> tuple[urllib.request.BaseHandler, ...]:
    return (_CheckedHTTPHandler(), _CheckedHTTPSHandler())


class _CheckedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        cast(Any, self)._create_connection = _checked_connect


class _CheckedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        cast(Any, self)._create_connection = _checked_connect


class _CheckedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(_CheckedHTTPConnection, req)


class _CheckedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(
            _CheckedHTTPSConnection,
            req,
            context=cast(Any, self)._context,
        )


class _ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, gate: Gate) -> None:
        super().__init__(("127.0.0.1", 0), _ProxyHandler)
        self.gate = gate


class _ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client = cast(socket.socket, self.request)
        gate = cast(_ProxyServer, self.server).gate
        try:
            _handle_client(client, gate)
        except (OSError, ValueError, UnicodeError):
            return


@dataclass(frozen=True)
class _Target:
    method: str
    host: str
    port: int
    path: str
    version: str
    headers: list[tuple[str, str]]
    tunnel: bool


def _handle_client(client: socket.socket, gate: Gate) -> None:
    client.settimeout(30)
    try:
        head, rest = _read_headers(client)
        target = _parse_target(head)
        body = b"" if target.tunnel else _read_body(client, rest, target.headers)
    except ValueError:
        _reply(client, 400, "Bad Request", "bad request")
        return
    if target.tunnel:
        rest_body = rest
    else:
        rest_body = body
    reason = gate.refusal(target.host, target.port)
    if reason == "proxy loop":
        _reply(client, 502, "Bad Gateway", reason)
        return
    if reason is not None:
        gate.add_block(Blocked(target.host.lower(), target.port, reason))
        _reply(client, 403, "Forbidden", reason)
        return
    try:
        upstream = open_socket(target.host, target.port, 10, gate=gate)
    except ScopeError as exc:
        gate.add_block(Blocked(target.host.lower(), target.port, str(exc)))
        _reply(client, 403, "Forbidden", str(exc))
        return
    except OSError:
        _reply(client, 502, "Bad Gateway", "connection failed")
        return
    try:
        if target.tunnel:
            _reply(client, 200, "Connection Established", "")
            if rest_body:
                upstream.sendall(rest_body)
            client.settimeout(None)
            upstream.settimeout(None)
            _splice(client, upstream)
            return
        upstream.sendall(_origin_request(target, rest_body))
        upstream.settimeout(120)
        _reply_raw(client, _read_until_close(upstream))
    finally:
        upstream.close()


def _parse_target(head: bytes) -> _Target:
    lines = head.split(b"\r\n")
    if not lines or not lines[0]:
        raise ValueError("empty request")
    parts = lines[0].decode("latin-1").split(" ", 2)
    if len(parts) != 3:
        raise ValueError("bad request line")
    method, raw_target, version = parts
    if not method.isascii() or not method.isalnum() or len(method) > 16:
        raise ValueError("bad method")
    headers = _header_pairs(lines[1:])
    if method.upper() == "CONNECT":
        host, port = _split_host_port(raw_target, 443)
        return _Target(method.upper(), _safe_host(host), port, "", version, headers, True)
    if "://" not in raw_target:
        raise ValueError("proxy request needs an absolute URL")
    parsed = urllib.parse.urlsplit(raw_target)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise ValueError("unsupported proxy target")
    if parsed.scheme == "https":
        raise ValueError("https needs CONNECT")
    host = _safe_host(parsed.hostname)
    port = parsed.port or 80
    if port < 1 or port > 65535:
        raise ValueError("bad port")
    path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    return _Target(method.upper(), host, port, _safe_path(path), version, headers, False)


def _header_pairs(lines: list[bytes]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for line in lines:
        if not line:
            continue
        if b":" not in line:
            raise ValueError("bad header")
        raw_name, raw_value = line.split(b":", 1)
        name = raw_name.decode("latin-1").strip()
        value = raw_value.decode("latin-1").strip()
        if not name or any(ord(char) <= 32 or ord(char) == 127 for char in name):
            raise ValueError("bad header")
        pairs.append((name, value))
    return pairs


def _read_headers(sock: socket.socket) -> tuple[bytes, bytes]:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > _MAX_HEAD:
            raise ValueError("headers too large")
    head, sep, rest = data.partition(b"\r\n\r\n")
    if not sep:
        raise ValueError("incomplete headers")
    return head, rest


def _read_body(sock: socket.socket, rest: bytes, headers: list[tuple[str, str]]) -> bytes:
    raw = next((value for name, value in headers if name.lower() == "content-length"), None)
    if raw is None:
        return b""
    needed = int(raw)
    if needed < 0 or needed > _MAX_BODY:
        raise ValueError("body too large")
    while len(rest) < needed:
        chunk = sock.recv(min(65536, needed - len(rest)))
        if not chunk:
            break
        rest += chunk
    if len(rest) < needed:
        raise ValueError("short body")
    return rest[:needed]


def _origin_request(target: _Target, body: bytes) -> bytes:
    skip = {"proxy-connection", "proxy-authorization", "connection"}
    lines = [f"{target.method} {target.path} {target.version}"]
    for name, value in target.headers:
        if name.lower() in skip:
            continue
        lines.append(f"{name}: {value}")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def _split_host_port(authority: str, default: int) -> tuple[str, int]:
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            raise ValueError("bad host")
        host = authority[1:end]
        rest = authority[end + 1 :]
        if rest == "":
            return host, default
        if not rest.startswith(":"):
            raise ValueError("bad host")
        return host, _port_number(rest[1:])
    if authority.count(":") > 1:
        raise ValueError("bad host")
    if ":" in authority:
        host, raw = authority.rsplit(":", 1)
        return host, _port_number(raw)
    return authority, default


def _port_number(raw: str) -> int:
    port = int(raw)
    if port < 1 or port > 65535:
        raise ValueError("bad port")
    return port


def _safe_host(host: str) -> str:
    if not host or any(ord(char) <= 32 or ord(char) == 127 for char in host):
        raise ValueError("bad host")
    return host


def _safe_path(path: str) -> str:
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise ValueError("bad path")
    return path or "/"


def _reply(sock: socket.socket, status: int, reason: str, body: str) -> None:
    payload = body.encode("utf-8")
    if status == 200 and not payload:
        head = f"HTTP/1.1 {status} {reason}\r\n\r\n"
        _send(sock, head.encode("ascii"))
        return
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    _send(sock, head.encode("ascii") + payload)


def _reply_raw(sock: socket.socket, payload: bytes) -> None:
    _send(sock, payload)


def _send(sock: socket.socket, payload: bytes) -> None:
    try:
        sock.sendall(payload)
    except OSError:
        return


def _read_until_close(sock: socket.socket) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while size <= _MAX_BODY:
        try:
            chunk = sock.recv(65536)
        except TimeoutError:
            break
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)


def _splice(left: socket.socket, right: socket.socket) -> None:
    def pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    forward = threading.Thread(target=pump, args=(left, right), daemon=True)
    backward = threading.Thread(target=pump, args=(right, left), daemon=True)
    forward.start()
    backward.start()
    forward.join()
    backward.join()


def _ungated(host: str, port: int) -> tuple[str, ...]:
    name = host.lower()
    if name in LOCAL_HOSTS:
        return _require_loopback(name, port)
    found = resolve(name, port)
    if not found:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    return _prefer_v4(found)


def _require_loopback(host: str, port: int) -> tuple[str, ...]:
    found = resolve(host, port)
    if not _loopback_only(found):
        raise ScopeError(f"{host} resolved outside loopback")
    return _prefer_v4(found)


def _loopback_only(found: tuple[str, ...]) -> bool:
    return bool(found) and all(is_loopback(ip) for ip in found)


def _prefer_v4(ips: tuple[str, ...]) -> tuple[str, ...]:
    v4 = tuple(ip for ip in ips if ":" not in ip)
    v6 = tuple(ip for ip in ips if ":" in ip)
    return v4 + v6


def _nodelay(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError as exc:
        if exc.errno != errno.ENOPROTOOPT:
            raise


def _checked_connect(
    address: tuple[str, int],
    timeout: object = None,
    source_address: tuple[str, int] | None = None,
) -> socket.socket:
    host, port = address
    return open_socket(host, int(port), _timeout(timeout), source_address)


def _timeout(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)
