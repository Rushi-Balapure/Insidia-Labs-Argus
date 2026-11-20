"""Fixed variants of the planted handlers. Replies do not reflect or run the input."""

from __future__ import annotations


def chat(user: str) -> str:
    return "no"


def web(user: str) -> str:
    return "ok"


def api(user: str) -> str:
    return "ok"
