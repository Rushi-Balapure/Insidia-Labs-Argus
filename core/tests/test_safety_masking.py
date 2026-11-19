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
from insidia.config import load_project
from insidia.errors import CliError
from insidia.mask import SECRET_PATTERNS, _secrets, bind_secrets, find_secret, mask
from insidia.probes import Attempt, ProbeHit
from insidia.runstore import config_snapshot
from insidia.scan import ScanOutcome, execute
from tests.support import REPO, start_fixture, stop_fixture

_SEED = 20261119
_TOKEN = re.compile(r"\[[A-Z0-9_]+ len=\d+ fp=[0-9a-f]{8}\]")
_KEY_KIND = {
    "password": "PASSWORD",
    "passwd": "PASSWORD",
    "pwd": "PASSWORD",
    "secret": "SECRET",
    "api_key": "API_KEY",
    "apikey": "API_KEY",
    "api-key": "API_KEY",
    "token": "TOKEN",
}
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
    tail = rng.choice("+/=") if rng.randrange(2) == 0 else rng.choice(_B64 + "=")
    body = _chars(rng, _B64, 39) + tail
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


def _configured(secret: str) -> str:
    fingerprint = hashlib.sha256(secret.encode()).hexdigest()[:8]
    return f"[CONFIGURED len={len(secret)} fp={fingerprint}]"


def _masked(kind: str, secret: str) -> str:
    fingerprint = hashlib.sha256(secret.encode()).hexdigest()[:8]
    return f"[{kind} len={len(secret)} fp={fingerprint}]"


def _case_key(rng: random.Random, key: str) -> str:
    return "".join(rng.choice((char.lower(), char.upper())) for char in key)


def _structured_assignment(rng: random.Random) -> tuple[str, str, str, str]:
    key = rng.choice(tuple(_KEY_KIND))
    shown = _case_key(rng, key)
    value = "z9" + _chars(rng, string.ascii_lowercase + string.digits, rng.randint(4, 14))
    form = rng.choice(("eq", "colon", "json", "query"))
    if form == "eq":
        prefix = f"{shown}="
        body = prefix + value
    elif form == "colon":
        prefix = f"{shown}: "
        body = prefix + value
    elif form == "json":
        prefix = f'"{shown}": "'
        body = f"{prefix}{value}\""
    else:
        prefix = f"?{shown}="
        body = prefix + value
    return body, value, _KEY_KIND[key], prefix


def _structured_authorization(rng: random.Random) -> tuple[str, str, str, str]:
    scheme = rng.choice(("Basic", "Bearer", "Token", "Digest"))
    value = "z9" + _chars(rng, string.ascii_lowercase + string.digits, rng.randint(4, 14))
    form = rng.choice(("header", "json", "dict"))
    if form == "header":
        prefix = f"Authorization: {scheme} "
        body = prefix + value
    elif form == "json":
        prefix = f'"Authorization": "{scheme} '
        body = f"{prefix}{value}\""
    else:
        prefix = f"'Authorization': '{scheme} "
        body = f"{prefix}{value}'"
    return body, value, "AUTHORIZATION", prefix


def _structured_url(rng: random.Random) -> tuple[str, str, str, str]:
    user = "u" + _chars(rng, string.ascii_lowercase, 4)
    value = "z9" + _chars(rng, string.ascii_lowercase + string.digits, rng.randint(1, 12))
    scheme = rng.choice(("https", "http", "wss"))
    prefix = f"{scheme}://{user}:"
    body = f"{prefix}{value}@files.example/a"
    return body, value, "URL_PASSWORD", prefix


_STRUCTURED: dict[str, Callable[[random.Random], tuple[str, str, str, str]]] = {
    "assignment": _structured_assignment,
    "authorization": _structured_authorization,
    "url-userinfo": _structured_url,
}


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


def test_configured_secrets_shorter_than_four_are_not_masked() -> None:
    token = bind_secrets(("a", "to", "id", "    "))
    try:
        assert _secrets.get() == ()
        assert mask("a to id     word") == "a to id     word"
    finally:
        _secrets.reset(token)


def test_configured_secrets_of_four_or_more_mask_whole_tokens() -> None:
    secret = "pass"
    longer = "pass-word"
    literal = "a+b.c"
    token = bind_secrets((secret, longer, literal, "   "))
    try:
        bound = _secrets.get()
        assert secret in bound and longer in bound and literal in bound
        assert "   " not in bound
        assert bound.index(longer) < bound.index(secret)
        masked = mask(f"see {longer} and {secret} end")
        assert longer not in masked
        assert "-word" not in masked
        assert _configured(longer) in masked
        assert _configured(secret) in masked
        assert mask("password passphrase") == "password passphrase"
        assert literal not in mask(f"x {literal} y")
        assert mask("abbc axb.c") == "abbc axb.c"
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


@pytest.mark.parametrize(
    ("secret", "kind"),
    [
        ("xoxb-" + ("a" * 9) + "-", "SLACK_TOKEN"),
        ("AIza" + ("a" * 34) + "-", "GOOGLE_API_KEY"),
        ("sk-ant-" + ("a" * 19) + "-", "ANTHROPIC_KEY"),
        ("sk-" + ("a" * 19) + "-", "OPENAI_KEY"),
        ("eyJaaaaaaaa.eyJaaaaaaaa.aaaaaaaa-", "JWT"),
    ],
)
def test_secrets_ending_in_a_non_word_character_are_masked(secret: str, kind: str) -> None:
    masked = mask(f"token {secret} end")
    assert secret not in masked
    assert _masked(kind, secret) in masked


@pytest.mark.parametrize("name", sorted(_STRUCTURED))
def test_structured_secrets_mask_the_value_and_keep_the_key(name: str) -> None:
    rng = random.Random(f"{_SEED}:structured:{name}")
    for index in range(24):
        body, value, kind, prefix = _STRUCTURED[name](rng)
        text = f"pre {index}\n{body}\npost {index}"
        masked = mask(text)
        assert value not in masked
        assert prefix in masked
        assert f"pre {index}" in masked
        assert f"post {index}" in masked
        token = _masked(kind, value)
        assert token in masked
        assert _TOKEN.fullmatch(token)
        assert find_secret(body) is None


def test_password_word_and_short_assignments_stay_visible() -> None:
    prose = "Choose a password. The token is not an assignment. secret_ref: env:APP_TOKEN"
    assert mask(prose) == prose
    assert mask("token: the") == "token: the"
    assert mask('{"token": true, "secret": null, "password": false}') == (
        '{"token": true, "secret": null, "password": false}'
    )
    assert mask("expressJwt(({ secret: publicKey })") == "expressJwt(({ secret: publicKey })"
    assert mask("tokenize=abcd1234") == "tokenize=abcd1234"


def test_assignment_authorization_url_and_query_mask_only_the_value() -> None:
    password = "hunter2zz"
    api_key = "jsonkey99"
    bearer = "bearerval99"
    basic = "YWRtaW46c2VjcmV0"
    url_password = "urlpass9"
    query = "queryval9"
    digest = 'username="ada", response="digestval99"'
    text = "\n".join(
        [
            "Choose a password before you continue.",
            f"password={password}",
            f'{{"api_key": "{api_key}"}}',
            f"Authorization: Bearer {bearer}",
            f"Authorization: Basic {basic}",
            f"Authorization: Digest {digest}",
            f"https://ada:{url_password}@files.example/a?pwd={query}",
            "{'Authorization': 'Token dicttok99'}",
        ]
    )
    masked = mask(text)
    assert "Choose a password before you continue." in masked
    assert masked.splitlines()[1] == f"password={_masked('PASSWORD', password)}"
    assert masked.splitlines()[2] == f'{{"api_key": "{_masked("API_KEY", api_key)}"}}'
    assert masked.splitlines()[3] == f"Authorization: Bearer {_masked('AUTHORIZATION', bearer)}"
    assert masked.splitlines()[4] == f"Authorization: Basic {_masked('AUTHORIZATION', basic)}"
    assert masked.splitlines()[5] == f"Authorization: Digest {_masked('AUTHORIZATION', digest)}"
    url = (
        f"https://ada:{_masked('URL_PASSWORD', url_password)}"
        f"@files.example/a?pwd={_masked('PASSWORD', query)}"
    )
    assert masked.splitlines()[6] == url
    token = "{'Authorization': 'Token " + _masked("AUTHORIZATION", "dicttok99") + "'}"
    assert masked.splitlines()[7] == token
    leaked = (password, api_key, bearer, basic, url_password, query, "digestval99", "dicttok99")
    for value in leaked:
        assert value not in masked
    assert mask(masked) == masked


def test_config_snapshot_redacts_short_secrets_on_token_boundaries() -> None:
    secret = "ab12"
    raw = f"note: {secret}\nlabel: {secret}word\n".encode()
    stored = config_snapshot(raw, (secret, "x")).decode()
    assert f"note: {secret}" not in stored
    assert "note: REDACTED" in stored
    assert f"{secret}word" in stored


def test_unresolvable_secret_ref_fails_before_a_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    present = "present-secret-value"
    monkeypatch.setenv("INSIDIA_PRESENT_TOKEN", present)
    monkeypatch.delenv("INSIDIA_MISSING_TOKEN", raising=False)
    monkeypatch.setattr("insidia.scan.preflight", lambda *_args, **_kwargs: "")
    monkeypatch.setattr("insidia.scan.run", lambda *_args, **_kwargs: Attempt())
    config = tmp_path / "insidia.yaml"
    config.write_text(
        """
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  first:
    kind: chat
    url: http://127.0.0.1:9/chat
    auth:
      header: Authorization
      secret_ref: env:INSIDIA_PRESENT_TOKEN
  second:
    kind: chat
    url: http://127.0.0.1:9/chat
    auth:
      header: Authorization
      secret_ref: env:INSIDIA_MISSING_TOKEN
"""
    )
    try:
        with pytest.raises(CliError, match="cannot resolve secret_ref") as caught:
            execute(load_project(config), tmp_path)
    finally:
        bind_secrets(())
    message = str(caught.value)
    assert message == "second: cannot resolve secret_ref env:INSIDIA_MISSING_TOKEN"
    assert present not in message
    assert mask(present) == present


def test_configured_secrets_reset_after_a_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = "alpha7secret"
    second = "beta8secret"
    seen: list[str] = []

    def finish(*_args: object, **_kwargs: object) -> ScanOutcome:
        seen.append(mask(f"{first} {second}"))
        return ScanOutcome("run", tmp_path, True, [], [])

    monkeypatch.setattr("insidia.scan._run_targets", finish)
    try:
        monkeypatch.setenv("INSIDIA_SCAN_ONE", first)
        execute(_auth_project(tmp_path / "one", "INSIDIA_SCAN_ONE"), tmp_path / "one")
        assert _configured(first) in seen[0]
        assert second in seen[0]
        assert mask(f"{first} {second}") == f"{first} {second}"
        monkeypatch.setenv("INSIDIA_SCAN_TWO", second)
        execute(_auth_project(tmp_path / "two", "INSIDIA_SCAN_TWO"), tmp_path / "two")
        assert first in seen[1]
        assert _configured(second) in seen[1]
        assert _configured(first) not in seen[1]
        assert mask(f"{first} {second}") == f"{first} {second}"
    finally:
        bind_secrets(())


def test_configured_secrets_reset_when_a_scan_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "gamma9secret"

    def explode(*_args: object, **_kwargs: object) -> ScanOutcome:
        assert _configured(secret) in mask(secret)
        raise CliError("stopped")

    monkeypatch.setattr("insidia.scan._run_targets", explode)
    monkeypatch.setenv("INSIDIA_SCAN_FAIL", secret)
    try:
        with pytest.raises(CliError, match="stopped"):
            execute(_auth_project(tmp_path, "INSIDIA_SCAN_FAIL"), tmp_path)
        assert mask(secret) == secret
        assert secret not in str(CliError("stopped"))
    finally:
        bind_secrets(())


def test_scan_outputs_mask_passwords_headers_and_configured_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    configured = "q7xm"
    password = "hunter2zz"
    api_key = "jsonkey99"
    bearer = "bearerval99"
    basic = "YWRtaW46c2VjcmV0"
    url_password = "urlpass9"
    query = "queryval9"
    digest = 'username="ada", response="digestval99"'
    blob = "\n".join(
        [
            "Choose a password before you continue.",
            f"password={password}",
            f'{{"api_key": "{api_key}"}}',
            f"Authorization: Bearer {bearer}",
            f"Authorization: Basic {basic}",
            f"Authorization: Digest {digest}",
            f"https://ada:{url_password}@files.example/a?pwd={query}",
            f"configured {configured} end",
        ]
    )
    sent = {"done": False}

    def fake_run(*_args: object, **_kwargs: object) -> Attempt:
        if sent["done"]:
            return Attempt()
        sent["done"] = True
        hit = ProbeHit(
            "app",
            "ai.data_leakage",
            "insidia",
            "insidia.ai.data_leakage",
            blob,
            "high",
            "high",
            "ai",
            ("owasp-llm:LLM02",),
            "Stop returning secrets.",
            evidence=blob,
        )
        return Attempt(hits=(hit,), error=f"password={password} {configured}")

    monkeypatch.setenv("INSIDIA_APP_TOKEN", configured)
    monkeypatch.setattr("insidia.scan.preflight", lambda *_args, **_kwargs: "")
    monkeypatch.setattr("insidia.scan.run", fake_run)
    config = tmp_path / "insidia.yaml"
    config.write_text(
        """
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  app:
    kind: chat
    url: http://127.0.0.1:9/chat
    auth:
      header: Authorization
      secret_ref: env:INSIDIA_APP_TOKEN
"""
    )
    try:
        code = main(["scan", "--config", str(config), "--no-color"])
    finally:
        bind_secrets(())
    captured = capsys.readouterr()
    run_dir = next((tmp_path / ".insidia" / "runs").iterdir())
    stored = [
        (run_dir / "findings.json").read_text(encoding="utf-8"),
        (run_dir / "results.sarif").read_text(encoding="utf-8"),
        (run_dir / "report.html").read_text(encoding="utf-8"),
        (run_dir / "findings.csv").read_text(encoding="utf-8"),
        (run_dir / "benchmark.json").read_text(encoding="utf-8"),
        (run_dir / "insidia.yaml").read_text(encoding="utf-8"),
        (run_dir / "manifest.json").read_text(encoding="utf-8"),
        captured.out,
        captured.err,
        caplog.text,
    ]
    raw_values = (
        configured,
        password,
        api_key,
        bearer,
        basic,
        url_password,
        query,
        "digestval99",
    )
    for text in stored:
        for value in raw_values:
            assert value not in text
    findings = stored[0]
    sarif = stored[1]
    html = stored[2]
    expected = (
        _masked("PASSWORD", password),
        _masked("API_KEY", api_key),
        _masked("AUTHORIZATION", bearer),
        _masked("AUTHORIZATION", basic),
        _masked("AUTHORIZATION", digest),
        _masked("URL_PASSWORD", url_password),
        _masked("PASSWORD", query),
        _configured(configured),
    )
    for token in expected:
        assert token in findings
        assert token in sarif
        assert token in html
    assert "Choose a password before you continue." in findings
    assert "Choose a password before you continue." in html
    assert code == 1


def _auth_project(root: Path, env_name: str) -> object:
    root.mkdir(parents=True, exist_ok=True)
    config = root / "insidia.yaml"
    config.write_text(
        f"""
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  app:
    kind: chat
    url: http://127.0.0.1:9/chat
    auth:
      header: Authorization
      secret_ref: env:{env_name}
"""
    )
    return load_project(config)


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
