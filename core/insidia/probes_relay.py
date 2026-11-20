"""Loopback relay that forwards engine prompts to the target."""

from __future__ import annotations

import hmac
import json
import secrets
import tempfile
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from insidia.adapters import (
    FIXTURE_ONLY,
    ORACLES,
    EngineHit,
    Invocation,
    ProbeSpec,
    RelayAdapter,
    RelayEndpoint,
)
from insidia.config import Project, Target, resolve_secret
from insidia.egress import current_gate
from insidia.errors import CliError, EngineFailed
from insidia.scope import check_url
from insidia.transport import BoundBudget, Budget, current_budget

Launch = Callable[[Invocation, Path], None]


def _relay(
    adapter: RelayAdapter,
    spec: ProbeSpec,
    target: Target,
    project: Project,
    root: Path,
    launch: Launch,
) -> tuple[list[EngineHit], str, str]:
    from insidia.probes import _JUDGE_ONLY, _judge_only, _probe_tally

    # Same skip as the built-in path: preparing the engine would prompt the target.
    if spec.family in _JUDGE_ONLY:
        return _judge_only(spec, target)
    token = secrets.token_hex(16)
    pairs: list[tuple[str, str]] = []
    budget = current_budget()
    bucket = _probe_tally.get()
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        _handler(token, pairs, budget, bucket, target, project, root),
    )
    port = int(server.server_address[1])
    gate = current_gate()
    if gate is not None:
        gate.allow_internal("127.0.0.1", port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        return _relay_result(adapter, spec, target, project, port, token, pairs, launch)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _handler(
    token: str,
    pairs: list[tuple[str, str]],
    budget: Budget | None,
    bucket: list[int] | None,
    target: Target,
    project: Project,
    root: Path,
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            _post_prompt(self, token, pairs, budget, bucket, target, project, root)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    return Handler


def _post_prompt(
    handler: BaseHTTPRequestHandler,
    token: str,
    pairs: list[tuple[str, str]],
    budget: Budget | None,
    bucket: list[int] | None,
    target: Target,
    project: Project,
    root: Path,
) -> None:
    import insidia.probes as probes

    auth = handler.headers.get("Authorization", "")
    if not hmac.compare_digest(auth, f"Bearer {token}"):
        handler.send_response(401)
        handler.end_headers()
        return
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        handler.send_response(400)
        handler.end_headers()
        return
    if length > 1_000_000:
        handler.send_response(413)
        handler.end_headers()
        return
    try:
        body = json.loads(handler.rfile.read(length))
    except json.JSONDecodeError:
        handler.send_response(400)
        handler.end_headers()
        return
    prompt = body.get("prompt") if isinstance(body, dict) else None
    if not isinstance(prompt, str):
        handler.send_response(400)
        handler.end_headers()
        return
    try:
        # The relay thread does not inherit the scan tally. Count the prompt here.
        probes._count_bucket(bucket)
        with BoundBudget(budget):
            response = probes.exchange(target, prompt, project.scope, root)
    except (CliError, OSError):
        handler.send_response(502)
        handler.end_headers()
        return
    pairs.append((prompt, response))
    payload = json.dumps({"text": response}).encode()
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    try:
        handler.wfile.write(payload)
    except (BrokenPipeError, ConnectionResetError):
        # The engine gave up before the target answered. Nothing to send to.
        return


def _relay_result(
    adapter: RelayAdapter,
    spec: ProbeSpec,
    target: Target,
    project: Project,
    port: int,
    token: str,
    pairs: list[tuple[str, str]],
    launch: Launch,
) -> tuple[list[EngineHit], str, str]:
    from insidia.probes import (
        _RELAY_MIN_PROMPTS,
        _judge_reply,
        _relay_shallow_note,
        _untested_note,
    )

    endpoint = _with_model(RelayEndpoint(f"http://127.0.0.1:{port}/send", token), project)
    with tempfile.TemporaryDirectory(prefix=f"insidia-{adapter.engine}-") as name:
        workspace = Path(name).resolve()
        invocation = adapter.prepare(spec, endpoint, workspace)
        failed: EngineFailed | None = None
        try:
            launch(invocation, workspace)
        except EngineFailed as exc:
            failed = exc
        oracle = ORACLES[spec.family]
        hits: list[EngineHit] = []
        for prompt, response in pairs:
            evidence = oracle(prompt, response, target)
            hits.extend(_judge_reply(spec, prompt, response, target, evidence))
        if failed is not None:
            return hits, str(failed), ""
        if not pairs:
            return [], "engine finished without contacting the target", ""
        if spec.family in FIXTURE_ONLY:
            return hits, "", _untested_note(spec.family)
        if len(pairs) < _RELAY_MIN_PROMPTS:
            return hits, "", _relay_shallow_note(adapter.engine, len(pairs))
        return hits, "", ""


def _with_model(endpoint: RelayEndpoint, project: Project) -> RelayEndpoint:
    """Hand the user's own attacker model to engines that must call one."""
    role = project.attacker
    if role is None or role.provider != "openai-compatible":
        return endpoint
    if role.base_url is None or role.model is None:
        return endpoint
    check_url(role.base_url, project.scope)
    key = resolve_secret(role.secret_ref) if role.secret_ref else None
    return RelayEndpoint(
        endpoint.url,
        endpoint.token,
        role.base_url.rstrip("/"),
        role.model,
        key,
    )
