"""Mask secret-shaped text before it is stored or printed.

Configured secrets are masked at 4 characters or more, and only as whole tokens.
The value must not sit inside a longer run of letters, digits, or underscores,
so ``pass`` does not rewrite ``password``. One- to three-character secrets are
left unchanged: even as whole tokens they are ordinary words (``a``, ``to``,
``id``) and masking them rewrites unrelated text. A trailing ``\\b`` is not
used, because a secret may end in ``/``, ``+``, or ``=``.

Assignment, header, URL userinfo, and query-parameter patterns mask the value
and leave the key. Prose assignments need a value of at least 4 characters, so
``token: the`` stays put, and a camelCase identifier such as ``secret: publicKey``
is left alone. Query values and URL passwords are delimited by the URL, so any
non-empty value is masked. The words ``password`` and ``token`` with no
assignment are not.
"""

from __future__ import annotations

import contextvars
import hashlib
import re
from collections.abc import Callable

# Credential formats with a fixed shape. Detection reads these too, so a
# pattern here must not match ordinary prose.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "AWS_SECRET_KEY",
        re.compile(
            r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"
        ),
    ),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("GITHUB_TOKEN", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}")),
    ("SLACK_TOKEN", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("STRIPE_KEY", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{10,}")),
    ("ANTHROPIC_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ),
    (
        "PRIVATE_KEY",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
    ),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)
_KEYS = r"password|passwd|pwd|secret|api[_-]?key|token"
_AUTH_DIGEST = re.compile(
    r"(?ix)(?<![A-Za-z0-9_])"
    r"(?P<prefix>[\"']?authorization[\"']?\s*[:=]\s*[\"']?digest\s+)"
    r"(?P<value>(?:[^\"'\[\]\r\n]+|\"[^\"\r\n]*\"|'[^'\r\n]*')+)"
)
_AUTH_TOKEN = re.compile(
    r"(?ix)(?<![A-Za-z0-9_])"
    r"(?P<prefix>[\"']?authorization[\"']?\s*[:=]\s*[\"']?(?:basic|bearer|token)\s+)"
    r"(?P<value>[A-Za-z0-9._~+/=-]{4,})"
)
_URL_USERINFO = re.compile(
    r"(?i)(?P<prefix>[a-z][a-z0-9+.\-]*://[^/\s:@]{1,256}:)"
    r"(?P<value>[^/\s:@\[\]]{1,256})(?=@)"
)
_QUERY = re.compile(
    rf"(?ix)(?P<prefix>[?&](?P<key>{_KEYS})=)(?P<value>[^&\s#\[\]]{{1,}})"
)
_ASSIGNMENT = re.compile(
    rf"(?ix)(?<![A-Za-z0-9_])"
    rf"(?P<prefix>[\"']?(?P<key>{_KEYS})[\"']?\s*[:=]\s*[\"']?)"
    rf"(?P<value>[^\s\"',;&\#\[\]{{}}]{{4,}})"
)
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    *SECRET_PATTERNS,
    ("AUTHORIZATION", _AUTH_DIGEST),
    ("AUTHORIZATION", _AUTH_TOKEN),
    ("URL_PASSWORD", _URL_USERINFO),
    ("PASSWORD", _QUERY),
    ("PASSWORD", _ASSIGNMENT),
    ("BEARER", re.compile(r"Bearer [A-Za-z0-9._\-]{8,}")),
)
_KEY_KINDS = {
    "password": "PASSWORD",
    "passwd": "PASSWORD",
    "pwd": "PASSWORD",
    "secret": "SECRET",
    "api_key": "API_KEY",
    "apikey": "API_KEY",
    "api-key": "API_KEY",
    "token": "TOKEN",
}
_NON_SECRETS = frozenset(
    {
        "true",
        "false",
        "null",
        "none",
        "nil",
        "undefined",
        "yes",
        "no",
        "on",
        "off",
        "required",
        "optional",
        "string",
        "boolean",
        "number",
        "integer",
        "object",
        "array",
        "example",
        "placeholder",
        "todo",
        "fixme",
        "redacted",
        "password",
        "secret",
        "token",
        "changeme",
    }
)
# Below this length a configured value is an ordinary word even as its own token.
MIN_CONFIGURED_SECRET_LENGTH = 4
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_secrets: contextvars.ContextVar[tuple[str, ...]] = contextvars.ContextVar(
    "insidia_secrets", default=()
)


def find_secret(text: str) -> tuple[str, str] | None:
    """The first credential-shaped value in text, as (kind, value)."""
    for kind, pattern in SECRET_PATTERNS:
        found = pattern.search(text)
        if found is not None:
            return kind, found.group(0)
    return None


def bind_secrets(values: tuple[str, ...]) -> contextvars.Token[tuple[str, ...]]:
    """Remember configured secrets for later masking. Blank and 1–3 character values are dropped."""
    return _secrets.set(_eligible(values))


def reset_secrets(token: contextvars.Token[tuple[str, ...]]) -> None:
    _secrets.reset(token)


def replace_configured(
    text: str,
    values: tuple[str, ...],
    replacement: Callable[[str], str],
) -> str:
    """Replace whole-token occurrences. ``replacement`` is inserted literally."""
    for secret in _eligible(values):
        pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(secret)}(?![A-Za-z0-9_])")
        text = pattern.sub(_literal(secret, replacement), text)
    return text


def mask(text: str) -> str:
    masked = _ANSI.sub("", text)
    masked = replace_configured(
        masked,
        _secrets.get(),
        lambda secret: _token("CONFIGURED", secret),
    )
    for kind, pattern in _PATTERNS:

        def replace(match: re.Match[str], kind: str = kind) -> str:
            return _mask_match(match, kind)

        masked = pattern.sub(replace, masked)
    return masked


def _eligible(values: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    chosen: list[str] = []
    for item in values:
        if len(item) < MIN_CONFIGURED_SECRET_LENGTH or not item.strip() or item in seen:
            continue
        seen.add(item)
        chosen.append(item)
    chosen.sort(key=len, reverse=True)
    return tuple(chosen)


def _literal(secret: str, replacement: Callable[[str], str]) -> Callable[[re.Match[str]], str]:
    def apply(_match: re.Match[str]) -> str:
        return replacement(secret)

    return apply


def _mask_match(match: re.Match[str], kind: str) -> str:
    if "value" not in match.re.groupindex:
        return _token(kind, match.group(0))
    value = match.group("value")
    if not isinstance(value, str) or _skip_value(match, value):
        return match.group(0)
    prefix = match.group("prefix")
    if not isinstance(prefix, str):
        prefix = ""
    key = match.group("key") if "key" in match.re.groupindex else None
    if not isinstance(key, str):
        key = None
    return f"{prefix}{_token(_kind_for(kind, key), value)}"


def _skip_value(match: re.Match[str], value: str) -> bool:
    if "key" not in match.re.groupindex:
        return False
    if value.lower() in _NON_SECRETS:
        return True
    if any(char.isdigit() for char in value):
        return False
    letters = [char for char in value if char.isalpha()]
    return bool(
        letters
        and any(char.islower() for char in letters)
        and any(char.isupper() for char in letters)
        and all(char.isalnum() or char == "_" for char in value)
    )


def _kind_for(kind: str, key: str | None) -> str:
    if key is None:
        return kind
    return _KEY_KINDS.get(key.lower(), kind)


def _token(kind: str, secret: str) -> str:
    fingerprint = hashlib.sha256(secret.encode()).hexdigest()[:8]
    return f"[{kind} len={len(secret)} fp={fingerprint}]"
