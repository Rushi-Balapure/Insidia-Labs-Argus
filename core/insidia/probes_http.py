"""Paired HTTP probes for injection, object access, redirects, and banners."""

from __future__ import annotations

import json
import random
import re
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

from insidia.adapters import ORACLES, SENSITIVE_FIELDS, EngineHit, has_standalone
from insidia.config import Target
from insidia.errors import ConfigError, ProbeError
from insidia.scope import ScopeHost
from insidia.transport import fetch, fetch_target


def _paired_ssti(
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str, str]:
    """A fresh product must appear in the attack response and not in the baseline."""
    from insidia.probes import _send

    left = random.randint(13, 97)
    right = random.randint(13, 97)
    product = str(left * right)
    attack = "{{" + f"{left}*{right}" + "}}"
    fixed = "{{7*7}}"
    try:
        baseline = _send(target, "baseline", scope, root)
        rendered = _send(target, attack, scope, root)
        planted = _send(target, fixed, scope, root)
    except ProbeError as exc:
        return [], str(exc), ""
    if (
        attack not in rendered
        and has_standalone(product, rendered)
        and not has_standalone(product, baseline)
    ):
        return [EngineHit("insidia-ssti-arith", attack, rendered, product)], "", ""
    if (
        fixed not in planted
        and has_standalone("49", planted)
        and not has_standalone("49", baseline)
    ):
        return [EngineHit("insidia-ssti-arith", fixed, planted, "49")], "", ""
    return [], "", ""


def _paired_bola(
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str, str]:
    """Two object ids return two different records that hold personal fields.

    An endpoint that ignores the id and returns the caller's own record gives
    the same body every time, so it does not match.
    """
    from insidia.probes import _send

    try:
        legacy = _send(target, "2", scope, root)
        if ORACLES["api.bola_idor"]("2", legacy, target) is not None:
            return [EngineHit("insidia-bola", "2", legacy, "admin")], "", ""
        bodies = {object_id: _send(target, object_id, scope, root) for object_id in ("1", "3")}
    except ProbeError as exc:
        return [], str(exc), ""
    bodies["2"] = legacy
    records = {key: _record(body, key) for key, body in bodies.items()}
    found = {key: record for key, record in records.items() if record is not None}
    distinct = {json.dumps(record, sort_keys=True, default=str) for record in found.values()}
    if len(found) < 2 or len(distinct) < 2:
        return [], "", ""
    first, second = sorted(found)[:2]
    fields = sorted(SENSITIVE_FIELDS & {key.lower() for key in found[second]})
    who = "with no credentials" if target.auth is None else "with one set of credentials"
    evidence = f"ids {first} and {second} each returned a user record ({', '.join(fields)}) {who}"
    hit = EngineHit("insidia-bola", second, bodies[second], evidence, confidence="medium")
    return [hit], "", ""


def _record(body: str, object_id: str) -> dict[str, object] | None:
    try:
        loaded: object = json.loads(body)
    except json.JSONDecodeError:
        return None
    if isinstance(loaded, dict) and isinstance(loaded.get("data"), dict):
        loaded = loaded["data"]
    if not isinstance(loaded, dict):
        return None
    record = {str(key): value for key, value in loaded.items()}
    if not SENSITIVE_FIELDS & {key.lower() for key in record}:
        return None
    for key in ("id", "user_id", "userId", "uid"):
        if key in record and str(record[key]) != object_id:
            return None
    return record


# Versions with a well-known remote exploit or no upstream security fixes.
# A banner that is not listed is not evidence that the server is current.
# The prefix never reaches a report. run() lifts it onto Attempt.info.
_BANNER_GAP_MARK = "banner-gap\n"
_BANNERS: tuple[tuple[re.Pattern[str], Callable[[tuple[int, ...]], bool], str], ...] = (
    (re.compile(r"Apache/(\d+)\.(\d+)\.(\d+)"), lambda v: v == (2, 4, 49), "CVE-2021-41773"),
    (re.compile(r"Apache/(\d+)\.(\d+)\.(\d+)"), lambda v: v == (2, 4, 50), "CVE-2021-42013"),
    (re.compile(r"Apache/(\d+)\.(\d+)"), lambda v: v < (2, 4), "Apache httpd 2.2 or older is EOL"),
    (
        re.compile(r"nginx/(\d+)\.(\d+)\.(\d+)"),
        lambda v: (1, 3, 9) <= v <= (1, 4, 0),
        "CVE-2013-2028",
    ),
    (
        re.compile(r"OpenSSL/1\.0\.1([a-f]?)\b"),
        lambda v: True,
        "CVE-2014-0160 (Heartbleed)",
    ),
    (re.compile(r"Microsoft-IIS/(\d+)\.(\d+)"), lambda v: v <= (6, 0), "CVE-2017-7269"),
    (re.compile(r"PHP/(\d+)\.(\d+)"), lambda v: v < (8, 1), "PHP before 8.1 is EOL"),
    (re.compile(r"Python/(\d+)\.(\d+)"), lambda v: v < (3, 9), "Python before 3.9 is EOL"),
)


def _banner_gap(banner: str) -> str:
    """A recognised version the built-in list does not mark. This is not a pass."""
    shown = " ".join(banner.split())
    if len(shown) > 180:
        shown = shown[:179].rstrip() + "…"
    return (
        f"{shown} identified; no match in the built-in list ({len(_BANNERS)} entries); "
        "banner-based, low confidence; not a vulnerability assessment"
    )


def _paired_cve(
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str, str]:
    """A server or framework banner that names a known-vulnerable or EOL version."""
    from insidia.probes import _bound_limiter, _send

    try:
        planted = _send(target, "banner", scope, root)
    except ProbeError as exc:
        return [], str(exc), ""
    if ORACLES["infra.cve"]("banner", planted, target) is not None:
        return [EngineHit("insidia-banner", "banner", planted, planted)], "", ""
    if target.url is None:
        raise ConfigError(f"{target.name} needs a url")
    try:
        _status, headers, _body = fetch(
            target.url,
            scope,
            headers=dict(target.headers),
            limiter=_bound_limiter(target),
        )
    except ProbeError as exc:
        return [], str(exc), ""
    banner = " ".join(
        headers[name]
        for name in ("server", "x-powered-by", "x-aspnet-version")
        if name in headers
    )
    if not re.search(r"\d+\.\d+", banner):
        return [], "", "the server does not disclose a version"
    for pattern, vulnerable, label in _BANNERS:
        found = pattern.search(banner)
        if found is None:
            continue
        version = tuple(int(part) for part in found.groups() if part.isdigit())
        if vulnerable(version):
            evidence = f"{found.group(0)}: {label}"
            return [EngineHit("insidia-banner", "GET", banner, evidence)], "", ""
    return [], "", _BANNER_GAP_MARK + _banner_gap(banner)


# A database error that is already on the baseline page is the app's normal reply.
_SQL_ERROR = re.compile(
    r"sqlite3\.OperationalError"
    r"|unrecognized token"
    r"|syntax error near"
    r"|SQLSTATE"
    r"|You have an error in your SQL syntax"
    r"|PG::SyntaxError"
    r"|ORA-\d*"
    r"|near\s+[\"'].{0,40}?syntax error",
    re.IGNORECASE,
)
_SQLI_BASELINE = "aa"
_SQLI_TRUE = "' OR '1'='1"
_SQLI_FALSE = "' AND '1'='2"
_SQLI_QUOTE = "'"
# Echoing a short payload changes the length by a few bytes. A real boolean
# leak returns the rows the true condition added.
_SQLI_GROWTH = 48


def _paired_sqli(
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str, str]:
    """Error-based and boolean-based SQL injection, each compared with a baseline.

    A quote that produces a database error only on the attack, or a true
    condition that returns more rows than both the baseline and a false
    condition, is a finding. The same error on every reply is not.
    """
    from insidia.probes import _send

    try:
        baseline = _send(target, _SQLI_BASELINE, scope, root)
        quoted = _send(target, _SQLI_QUOTE, scope, root)
        truth = _send(target, _SQLI_TRUE, scope, root)
        falsehood = _send(target, _SQLI_FALSE, scope, root)
    except ProbeError as exc:
        return [], str(exc), ""
    for payload, body in ((_SQLI_QUOTE, quoted), (_SQLI_TRUE, truth), (_SQLI_FALSE, falsehood)):
        evidence = _sql_error(baseline, payload, body)
        if evidence is not None:
            return [EngineHit("insidia-sqli", payload, body, evidence)], "", ""
    evidence = _boolean_sqli(baseline, truth, falsehood)
    if evidence is not None:
        return [EngineHit("insidia-sqli", _SQLI_TRUE, truth, evidence)], "", ""
    return [], "", ""


def _sql_error(baseline: str, attack: str, response: str) -> str | None:
    found = _SQL_ERROR.search(response)
    if found is None:
        return None
    evidence = found.group(0)
    folded = evidence.lower()
    if folded in baseline.lower() or folded in attack.lower():
        return None
    return evidence


def _boolean_sqli(baseline: str, truth: str, falsehood: str) -> str | None:
    base_rows, true_rows, false_rows = (
        _listed_rows(baseline),
        _listed_rows(truth),
        _listed_rows(falsehood),
    )
    if base_rows is not None and true_rows is not None and false_rows is not None:
        if true_rows > base_rows and true_rows > false_rows:
            return (
                f"{true_rows} rows for a true condition, "
                f"{base_rows} for the baseline, {false_rows} for a false condition"
            )
        return None
    if (
        len(truth) >= len(baseline) + _SQLI_GROWTH
        and len(truth) >= len(falsehood) + _SQLI_GROWTH
        and len(truth) > int(len(baseline) * 1.5)
        and len(truth) > int(len(falsehood) * 1.5)
    ):
        return (
            f"true condition is {len(truth)} bytes, "
            f"baseline {len(baseline)}, false condition {len(falsehood)}"
        )
    return None


def _listed_rows(body: str) -> int | None:
    try:
        loaded: object = json.loads(body)
    except json.JSONDecodeError:
        return None
    if isinstance(loaded, list):
        return len(loaded)
    if isinstance(loaded, dict):
        for key in ("data", "accounts", "results", "rows", "items"):
            value = loaded.get(key)
            if isinstance(value, list):
                return len(value)
    return None


_REDIRECT_HOST = "insidia-redirect.invalid"
_OPEN_REDIRECTS = (f"https://{_REDIRECT_HOST}/", f"//{_REDIRECT_HOST}")
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_JS_REDIRECT = re.compile(
    r"""(?i)(?:window\s*\.\s*)?location(?:\s*\.\s*href)?\s*=\s*['"]([^'"]+)['"]"""
    r"""|location\s*\.\s*replace\(\s*['"]([^'"]+)['"]"""
)


def _paired_open_redirect(
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str, str]:
    """A 3xx or client redirect to the canary host. The canary host is never requested."""
    from insidia.probes import _count_probe

    del root
    try:
        for payload in _OPEN_REDIRECTS:
            _count_probe()
            status, headers, body = fetch_target(target, payload, scope, follow=False)
            evidence = _redirect_evidence(status, headers, body)
            if evidence is not None:
                return [EngineHit("insidia-open-redirect", payload, evidence, evidence)], "", ""
    except ProbeError as exc:
        return [], str(exc), ""
    return [], "", ""


def _redirect_evidence(status: int, headers: dict[str, str], body: str) -> str | None:
    if status in _REDIRECT_STATUSES:
        location = headers.get("location", "")
        if _redirect_host(location) == _REDIRECT_HOST:
            return f"{status} Location: {location.strip()}"
    for url in _client_redirects(body):
        if _redirect_host(url) == _REDIRECT_HOST:
            return f"client redirect to {url}"
    return None


def _redirect_host(url: str) -> str:
    return (urlparse(url.strip()).hostname or "").lower().rstrip(".")


def _client_redirects(body: str) -> tuple[str, ...]:
    found: list[str] = []
    for tag in re.findall(r"(?is)<meta\b[^>]*>", body):
        if re.search(r"(?i)http-equiv\s*=\s*['\"]?\s*refresh\b", tag) is None:
            continue
        match = re.search(r"(?i)\burl\s*=\s*['\"]?\s*([^'\"\s>]+)", tag)
        if match is not None:
            found.append(match.group(1))
    for match in _JS_REDIRECT.finditer(body):
        url = match.group(1) or match.group(2)
        if url:
            found.append(url)
    return tuple(found)
