"""Masking holds for generated secrets and for a scan of the bundled plant."""

from __future__ import annotations

import hashlib
import json
import logging
import random
import re
import socket
import string
import subprocess
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path

import pytest
from insidia.cli import main
from insidia.mask import SECRET_PATTERNS, _secrets, bind_secrets, find_secret, mask
from tests.support import REPO, start_fixture, stop_fixture

_SEED = 20261119
_TOKEN = re.compile(r"\[[A-Z0-9_]+ len=\d+ fp=[0-9a-f]{8}\]")
_WORD = string.ascii_letters + string.digits
_B64 = string.ascii_letters + string.digits + "+/"
_URL = string.ascii_letters + string.digits + "_-"
_PLANT = REPO / "benchmark" / "targets" / "insidia" / "repo" / "sinks.py"
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


def _chars(rng: random.Random, alphabet: str, length: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


def _aws_access(rng: random.Random) -> str:
    prefix = rng.choice(("AKIA", "ASIA"))
    return prefix + _chars(rng, string.ascii_uppercase + string.digits, 16)


def _aws_secret(rng: random.Random) -> str:
    label = "".join(rng.choice((char.lower(), char.upper())) for char in "aws_secret_access_key")
    gap = rng.choice(("", " "))
    sep = rng.choice((":", "="))
    quote = rng.choice(("", '"', "'"))
    # The pattern ends on a word boundary, so the last character has to be a word character.
    body = _chars(rng, _WORD, 39) + rng.choice(_WORD)
    return f"{label}{gap}{sep}{gap}{quote}{body}"


def _github(rng: random.Random) -> str:
    prefix = rng.choice(("ghp_", "gho_", "ghu_", "ghs_", "ghr_"))
    return prefix + _chars(rng, _WORD, rng.randint(20, 64))


def _github_pat(rng: random.Random) -> str:
    return "github_pat_" + _chars(rng, _WORD + "_", rng.randint(22, 70))


def _slack(rng: random.Random) -> str:
    kind = rng.choice("abposr")
    body = _chars(rng, _WORD + "-", rng.randint(10, 40))
    return f"xox{kind}-{body}"


def _google(rng: random.Random) -> str:
    return "AIza" + _chars(rng, _URL, 35)


def _stripe(rng: random.Random) -> str:
    prefix = rng.choice(("sk_live_", "rk_live_"))
    return prefix + _chars(rng, _WORD, rng.randint(10, 48))


def _anthropic(rng: random.Random) -> str:
    return "sk-ant-" + _chars(rng, _URL, rng.randint(20, 60))


def _openai(rng: random.Random) -> str:
    prefix = rng.choice(("sk-", "sk-proj-"))
    body = _chars(rng, _URL, rng.randint(20, 60))
    if prefix == "sk-" and body.startswith("ant-"):
        body = "x" + body[1:]
    return prefix + body


def _jwt(rng: random.Random) -> str:
    parts = ["eyJ" + _chars(rng, _URL, rng.randint(8, 40)) for _ in range(2)]
    parts.append(_chars(rng, _URL, rng.randint(8, 40)))
    return ".".join(parts)


def _private_key(rng: random.Random) -> str:
    kind = rng.choice(("PRIVATE KEY", "RSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "EC PRIVATE KEY"))
    body = _chars(rng, _B64, rng.randint(16, 80))
    return f"-----BEGIN {kind}-----\n{body}\n-----END {kind}-----"


def _bearer(rng: random.Random) -> str:
    return "Bearer " + _chars(rng, _URL + ".", rng.randint(8, 64))


_GENERATORS: dict[str, Callable[[random.Random], str]] = {
    "aws-access": _aws_access,
    "aws-secret": _aws_secret,
    "github": _github,
    "github-pat": _github_pat,
    "slack": _slack,
    "google": _google,
    "stripe": _stripe,
    "anthropic": _anthropic,
    "openai": _openai,
    "jwt": _jwt,
    "private-key": _private_key,
    "bearer": _bearer,
}


def _first_match(text: str) -> tuple[str, str]:
    from insidia.mask import _PATTERNS

    for kind, pattern in _PATTERNS:
        found = pattern.search(text)
        if found is not None and found.group(0) == text:
            return kind, found.group(0)
    raise AssertionError(f"generator did not match a mask pattern: {text!r}")


@pytest.mark.parametrize("name", sorted(_GENERATORS))
def test_generated_secrets_are_masked(name: str) -> None:
    rng = random.Random(f"{_SEED}:{name}")
    for index in range(24):
        secret = _GENERATORS[name](rng)
        kind, matched = _first_match(secret)
        assert matched == secret
        text = f"pre {index}\n{secret}\npost {index}"
        masked = mask(text)
        assert secret not in masked
        assert f"pre {index}" in masked
        assert f"post {index}" in masked
        token = f"[{kind} len={len(secret)} fp={hashlib.sha256(secret.encode()).hexdigest()[:8]}]"
        assert token in masked
        assert _TOKEN.fullmatch(token)
        if name != "bearer":
            found = find_secret(secret)
            assert found == (kind, secret)


def test_many_secrets_in_one_blob_are_all_masked() -> None:
    rng = random.Random(_SEED)
    secrets = [_GENERATORS[name](rng) for name in sorted(_GENERATORS)]
    text = " | ".join(secrets)
    masked = mask(text)
    for secret in secrets:
        assert secret not in masked
        kind, _matched = _first_match(secret)
        token = f"[{kind} len={len(secret)} fp={hashlib.sha256(secret.encode()).hexdigest()[:8]}]"
        assert token in masked
    assert len(_TOKEN.findall(masked)) == len(secrets)


def test_configured_secrets_of_varied_lengths_are_masked() -> None:
    rng = random.Random(f"{_SEED}:configured")
    alphabet = string.ascii_lowercase + string.digits
    secrets = tuple("cfg-" + _chars(rng, alphabet, length) for length in range(8, 48))
    token = bind_secrets(secrets)
    try:
        text = " ".join(f"[{item}]" for item in secrets)
        masked = mask(text)
        for secret in secrets:
            assert secret not in masked
            fingerprint = hashlib.sha256(secret.encode()).hexdigest()[:8]
            assert f"[CONFIGURED len={len(secret)} fp={fingerprint}]" in masked
    finally:
        _secrets.reset(token)


def test_configured_secret_shorter_than_eight_is_not_bound() -> None:
    short = "cfg-abc"
    token = bind_secrets((short,))
    try:
        assert mask(f"see {short}") == f"see {short}"
    finally:
        _secrets.reset(token)


def test_ansi_wrapped_secret_is_masked_and_colors_are_removed() -> None:
    secret = _aws_access(random.Random(_SEED))
    masked = mask(f"\x1b[31m{secret}\x1b[0m")
    assert secret not in masked
    assert "\x1b" not in masked
    assert masked.startswith("[AWS_ACCESS_KEY ")


def test_ordinary_text_is_unchanged() -> None:
    prose = "The port is 443 and the host is localhost. No credentials here."
    assert mask(prose) == prose
    assert find_secret(prose) is None
    kinds = {kind for kind, _pattern in SECRET_PATTERNS}
    assert {"AWS_ACCESS_KEY", "GITHUB_TOKEN", "PRIVATE_KEY", "JWT"} <= kinds


@pytest.mark.xfail(
    strict=True,
    reason=(
        "AWS secret keys ending in / + or = are not masked; "
        "the pattern's word boundary rejects them"
    ),
)
@pytest.mark.parametrize("tail", ["=", "/", "+"])
def test_aws_secret_key_with_base64_tail_is_masked(tail: str) -> None:
    key = ("Ab9" * 20)[:39] + tail
    assert len(key) == 40
    secret = f"aws_secret_access_key={key}"
    masked = mask(f"token {secret} end")
    assert key not in masked
    assert "[AWS_SECRET_KEY " in masked
    found = find_secret(secret)
    assert found is not None and found[1] == secret


def _block_off_host(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    real_connect = socket.create_connection
    real_lookup = socket.getaddrinfo
    blocked: list[str] = []

    def connect(address: object, *args: object, **kwargs: object) -> socket.socket:
        host = address[0] if isinstance(address, tuple) and address else address
        if str(host) not in _LOOPBACK:
            blocked.append(str(host))
            raise OSError(f"blocked connection to {host}")
        return real_connect(address, *args, **kwargs)  # type: ignore[arg-type]

    def lookup(host: object, port: object, *args: object, **kwargs: object) -> object:
        if isinstance(host, str) and host not in _LOOPBACK:
            blocked.append(host)
            host = "127.0.0.1"
        return real_lookup(host, port, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    return blocked


def _wait(url: str) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=0.2) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("sandbox did not start")


def _planted_secret() -> str:
    match = re.search(r'PLANTED_SECRET = "([^"]+)"', _PLANT.read_text(encoding="utf-8"))
    assert match is not None
    return match.group(1)


def test_scan_outputs_never_contain_the_planted_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    blocked = _block_off_host(monkeypatch)
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    secret = _planted_secret()
    fingerprint = hashlib.sha256(secret.encode()).hexdigest()[:8]
    token = f"[AWS_ACCESS_KEY len={len(secret)} fp={fingerprint}]"
    plant = tmp_path / "src"
    plant.mkdir()
    (plant / "sinks.py").write_bytes(_PLANT.read_bytes())
    process: subprocess.Popen[bytes] | None = None
    process_port = 0
    try:
        for _attempt in range(5):
            process_port = _free_port()
            candidate = start_fixture(process_port)
            try:
                _wait(f"http://127.0.0.1:{process_port}/healthz")
            except AssertionError:
                _stop(candidate)
                continue
            process = candidate
            break
        else:
            raise AssertionError("sandbox did not start")
        config = tmp_path / "insidia.yaml"
        config.write_text(
            f"""
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  sandbox-chat:
    kind: chat
    url: http://127.0.0.1:{process_port}/call
    method: GET
    query:
      module: chatbot
      fn: data_leakage
      q: "{{{{prompt}}}}"
    rate_limit:
      rps: 100
      concurrency: 1
  code:
    kind: repo
    path: src
"""
        )
        code = main(["scan", "--config", str(config), "--json", "--no-color"])
    finally:
        if process is not None:
            _stop(process)
    captured = capsys.readouterr()
    run_dir = next((tmp_path / ".insidia" / "runs").iterdir())
    findings_text = (run_dir / "findings.json").read_text(encoding="utf-8")
    sarif_text = (run_dir / "results.sarif").read_text(encoding="utf-8")
    html_text = (run_dir / "report.html").read_text(encoding="utf-8")
    stored = [
        findings_text,
        sarif_text,
        html_text,
        (run_dir / "findings.csv").read_text(encoding="utf-8"),
        (run_dir / "benchmark.json").read_text(encoding="utf-8"),
        (run_dir / "insidia.yaml").read_text(encoding="utf-8"),
        (run_dir / "manifest.json").read_text(encoding="utf-8"),
        captured.out,
        captured.err,
        caplog.text,
    ]
    for text in stored:
        assert secret not in text
    assert token in findings_text
    assert token in sarif_text
    assert token in html_text
    findings = json.loads(findings_text)
    assert any(item["attack"] == "code.secrets" for item in findings)
    assert blocked == []
    assert code == 1


def _stop(process: subprocess.Popen[bytes]) -> None:
    stop_fixture(process)
    for pipe in (process.stdout, process.stderr):
        if pipe is not None and not pipe.closed:
            pipe.close()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
