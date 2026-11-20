"""Mask a configuration before it is stored with a run."""

from __future__ import annotations

import re

from insidia.errors import CliError
from insidia.mask import SECRET_PATTERNS, replace_configured

_BEARER = re.compile(r"Bearer [A-Za-z0-9._\-]{8,}")


def config_snapshot(raw: bytes, secrets: tuple[str, ...] = ()) -> bytes:
    """Config text safe to store. Resolved secret values are never kept."""
    text = raw.decode("utf-8")
    cleaned = replace_configured(text, secrets, lambda _secret: "REDACTED")
    for _kind, pattern in SECRET_PATTERNS:
        cleaned = pattern.sub("REDACTED", cleaned)
    cleaned = _BEARER.sub("REDACTED", cleaned)
    if replace_configured(cleaned, secrets, lambda _secret: "REDACTED") != cleaned:
        raise CliError("refusing to store a configuration that still contains a secret")
    if cleaned == text:
        return raw
    return cleaned.encode("utf-8")
