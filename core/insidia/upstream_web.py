"""Web engine plans and parsers for nuclei, zap, katana, httpx, and dalfox."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import cast
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

import yaml  # type: ignore[import-untyped]

from insidia.adapters import EngineHit, Invocation, ProbeSpec, ScopedUrl, has_standalone
from insidia.catalog import SSTI_PAYLOAD
from insidia.egress import engine_proxy_args
from insidia.errors import EngineFailed
from insidia.upstream_support import _loads, _program

_SSTI_PRODUCT = "49"


def _web_prepare(engine: str) -> Callable[[ProbeSpec, ScopedUrl, Path], Invocation]:
    def prepare(spec: ProbeSpec, view: ScopedUrl, workspace: Path) -> Invocation:
        report = "report.jsonl" if engine in {"nuclei", "katana"} else "report.json"
        url = _request_url(view, SSTI_PAYLOAD)
        args: tuple[str, ...]
        if engine == "nuclei":
            path = _nuclei_path(view)
            # Nuclei evaluates {{7*7}} as its own syntax. The template keeps the
            # expression percent-encoded so the sandbox still sees it.
            (workspace / "ssti.yaml").write_text(_nuclei_yaml(path), encoding="utf-8")
            args = (
                "-u",
                _origin(view.url),
                "-t",
                str(workspace / "ssti.yaml"),
                "-jsonl",
                "-o",
                report,
                "-silent",
                "-disable-update-check",
                "-no-interactsh",
                # Nuclei follows off-host redirects only when -fr is set. -dr
                # keeps that off even if a template asks to follow.
                "-dr",
            )
        elif engine == "zap":
            # The plan already names a context for this URL. No proxy.
            (workspace / "plan.yaml").write_text(
                _zap_plan(url, workspace, report),
                encoding="utf-8",
            )
            args = ("-cmd", "-silent", "-autorun", str(workspace / "plan.yaml"))
        elif engine == "dalfox":
            # -F / --follow-redirects is off unless passed. Do not pass it.
            args = ("url", "--url", url, "--format", "json", "--output", report, "--silence")
        elif engine == "katana":
            # Katana follows redirects unless -dr is set. Default field scope
            # is the registrable domain, so pin the crawl to this origin.
            args = (
                "-u",
                url,
                "-silent",
                "-jsonl",
                "-o",
                report,
                "-d",
                "1",
                "-dr",
                "-fs",
                "fqdn",
                "-cs",
                _origin_scope(url),
                "-disable-update-check",
            )
        elif engine == "httpx":
            # httpx follows redirects only with -fr. Do not pass it.
            args = (
                "-u",
                url,
                "-silent",
                "-json",
                "-o",
                report,
                "-irr",
                "-disable-update-check",
            )
        else:
            raise ValueError(engine)
        proxied = (*args, *engine_proxy_args(engine))
        return Invocation(_program(engine), proxied, report, timeout=180)

    return prepare


def _web_parser(engine: str) -> Callable[[Path, ProbeSpec], list[EngineHit]]:
    def parse(report: Path, spec: ProbeSpec) -> list[EngineHit]:
        hits: list[EngineHit] = []
        for body in _web_bodies(engine, report):
            if _ssti_product(body) is None:
                continue
            hits.append(EngineHit(spec.upstream, SSTI_PAYLOAD, body[:2000], _SSTI_PRODUCT))
        return hits

    return parse


def _web_bodies(engine: str, report: Path) -> list[str]:
    if not report.is_file():
        raise EngineFailed("engine report is missing")
    text = report.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        if engine == "nuclei":
            return []
        raise EngineFailed("engine report is empty")
    if engine in {"httpx", "katana"}:
        return []
    if engine == "nuclei":
        return _nuclei_bodies(text)
    loaded = _loads(text)
    if engine == "zap":
        return _zap_bodies(loaded)
    if engine == "dalfox":
        return _dalfox_bodies(loaded)
    return []


def _ssti_product(body: str) -> str | None:
    if SSTI_PAYLOAD in body or not has_standalone(_SSTI_PRODUCT, body):
        return None
    return _SSTI_PRODUCT


def _nuclei_bodies(text: str) -> list[str]:
    bodies: list[str] = []
    for line in text.splitlines():
        loaded = _loads(line.strip())
        if not isinstance(loaded, dict):
            continue
        raw = loaded.get("response")
        if isinstance(raw, str):
            bodies.append(_http_body(raw))
    return bodies


def _zap_bodies(loaded: object) -> list[str]:
    if not isinstance(loaded, dict):
        return []
    sites = loaded.get("site")
    if not isinstance(sites, list):
        return []
    bodies: list[str] = []
    for site in sites:
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts")
        if not isinstance(alerts, list):
            continue
        for alert in alerts:
            if not isinstance(alert, dict) or not _zap_ssti(alert):
                continue
            instances = alert.get("instances")
            if not isinstance(instances, list):
                continue
            for instance in instances:
                if not isinstance(instance, dict):
                    continue
                body = instance.get("response-body")
                if isinstance(body, str):
                    bodies.append(body)
    return bodies


def _zap_ssti(alert: dict[str, object]) -> bool:
    name = f"{alert.get('name', '')} {alert.get('alert', '')}".lower()
    return alert.get("pluginid") == "90035" or "template injection" in name


def _dalfox_bodies(loaded: object) -> list[str]:
    if isinstance(loaded, list):
        rows: object = loaded
    elif isinstance(loaded, dict):
        rows = loaded.get("findings")
    else:
        return []
    if not isinstance(rows, list):
        return []
    bodies: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or not _dalfox_ssti(row):
            continue
        raw = row.get("response")
        if isinstance(raw, str):
            bodies.append(_http_body(raw))
    return bodies


def _dalfox_ssti(row: dict[str, object]) -> bool:
    text = " ".join(
        str(row.get(key, "")) for key in ("message_str", "inject_type", "cwe", "type_description")
    ).lower()
    return "ssti" in text or "template injection" in text or "cwe-1336" in text


def _http_body(raw: str) -> str:
    for separator in ("\r\n\r\n", "\n\n"):
        if separator in raw:
            return raw.split(separator, 1)[1]
    return raw


def _request_url(view: ScopedUrl, payload: str) -> str:
    parsed = urlparse(view.url)
    if not view.query and "{{" not in parsed.query:
        return view.url
    pairs = [*parse_qsl(parsed.query, keep_blank_values=True), *view.query]
    rendered = [
        (key, value.replace("{{prompt}}", payload).replace("{{payload}}", payload))
        for key, value in pairs
    ]
    return urlunparse(parsed._replace(query=urlencode(rendered)))


def _nuclei_path(view: ScopedUrl) -> str:
    encoded = quote(SSTI_PAYLOAD, safe="*")
    parsed = urlparse(view.url)
    path = parsed.path or "/"
    if not view.query:
        return path
    parts = [
        f"{quote(key, safe='')}="
        + value.replace("{{prompt}}", encoded).replace("{{payload}}", encoded)
        for key, value in view.query
    ]
    return f"{path}?{'&'.join(parts)}"


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _origin_scope(url: str) -> str:
    """Katana `-cs` regex. Only URLs on this origin are in scope."""
    return rf"^{re.escape(_origin(url))}(?:/|$)"


def _nuclei_yaml(path: str) -> str:
    # Nuclei treats a path without a scheme as a URL and refuses it. BaseURL
    # is its own placeholder for the scoped origin. The payload stays encoded.
    # A matcher is required or nuclei writes no result.
    template = {
        "id": "insidia-web-ssti",
        "info": {
            "name": "insidia ssti",
            "author": "insidia",
            "severity": "high",
        },
        "http": [
            {
                "method": "GET",
                "path": ["{{BaseURL}}" + path],
                "matchers": [
                    {
                        "type": "word",
                        "part": "body",
                        "words": ["49"],
                    }
                ],
            }
        ],
    }
    return cast(str, yaml.safe_dump(template, sort_keys=False, default_flow_style=False))


def _zap_plan(url: str, workspace: Path, report: str) -> str:
    plan = {
        "env": {
            "contexts": [
                {
                    "name": "insidia",
                    "urls": [url],
                }
            ],
            "parameters": {
                "failOnError": False,
                "progressToStdout": False,
            },
        },
        "jobs": [
            {
                "type": "requestor",
                "requests": [
                    {
                        "url": url,
                        "method": "GET",
                    }
                ],
            },
            {
                "type": "report",
                "parameters": {
                    "template": "traditional-json",
                    "reportDir": str(workspace),
                    "reportFile": report,
                },
            },
        ],
    }
    return cast(str, yaml.safe_dump(plan, sort_keys=False, default_flow_style=False))
