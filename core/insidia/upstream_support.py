"""Program lookup and JSON reports shared by the engine adapters."""

from __future__ import annotations

import json
from pathlib import Path

from insidia.catalog import BY_NAME
from insidia.errors import EngineFailed


def _load_json(report: Path) -> object:
    if not report.is_file():
        raise EngineFailed("engine report is missing")
    text = report.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        raise EngineFailed("engine report is empty")
    loaded = _loads(text)
    if loaded is None:
        raise EngineFailed("engine report is empty")
    return loaded


def _loads(text: str) -> object | None:
    if not text:
        return None
    try:
        loaded: object = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EngineFailed("engine report is not valid JSON") from exc
    return loaded


def _program(engine: str) -> str:
    from insidia.engines import program_for

    if engine not in BY_NAME:
        raise ValueError(engine)
    return program_for(engine)
