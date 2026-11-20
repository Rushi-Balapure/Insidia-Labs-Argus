"""Pick the baseline run and mark findings new, still open, or fixed."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

import yaml  # type: ignore[import-untyped]

from insidia.findings import Finding

# new_run_id() is "{UTC second}-{6 hex}". Sorting those ids sorts runs across
# seconds. The hex suffix does not order two runs that share a second.
_STAMPED_RUN_ID = re.compile(r"\A\d{8}T\d{6}Z-")


@dataclass(frozen=True)
class _Tracked:
    state: str
    first_seen_run: str


@dataclass(frozen=True)
class _FixedFinding:
    title: str
    target: str
    evidence_hash: str


def _select_baseline(
    runs: Path,
    run_id: str,
    config_digest: str,
    target_names: frozenset[str],
    rerun_of: str,
) -> tuple[str, Path | None]:
    """The run this one is compared with, and its directory when that directory is readable."""
    if rerun_of:
        return rerun_of, _contained_child(runs, rerun_of)
    earlier = _earlier_run_dirs(runs, run_id)
    for path in earlier:
        manifest = _loose_object(path / "manifest.json")
        digest = manifest.get("config_digest") if manifest is not None else None
        if isinstance(digest, str) and digest == config_digest:
            return path.name, path
    for path in earlier:
        if _stored_target_names(path) == target_names:
            return path.name, path
    return "", None


def _compare_findings(
    run_id: str,
    findings: list[Finding],
    baseline_id: str,
    baseline_dir: Path | None,
) -> tuple[tuple[_Tracked, ...], tuple[_FixedFinding, ...]]:
    """Mark each current finding new or still open, and list baseline hashes that are gone."""
    if not baseline_id:
        return tuple(_Tracked("new", run_id) for _finding in findings), ()
    previous = _object_list(baseline_dir / "findings.json") if baseline_dir is not None else []
    origin: dict[str, str] = {}
    for item in previous:
        digest = item.get("evidence_hash")
        if not isinstance(digest, str) or digest in origin:
            continue
        first = item.get("first_seen_run")
        origin[digest] = first if isinstance(first, str) and first else baseline_id
    current = {finding.evidence_hash for finding in findings}
    fixed: list[_FixedFinding] = []
    for item in previous:
        digest = item.get("evidence_hash")
        if not isinstance(digest, str) or digest in current:
            continue
        title = item.get("title")
        target = item.get("target")
        fixed.append(
            _FixedFinding(
                title if isinstance(title, str) else "",
                target if isinstance(target, str) else "",
                digest,
            )
        )
    tracked = tuple(
        _Tracked("still_open", origin[finding.evidence_hash])
        if finding.evidence_hash in origin
        else _Tracked("new", run_id)
        for finding in findings
    )
    return tracked, tuple(fixed)


def _earlier_run_dirs(runs: Path, run_id: str) -> list[Path]:
    """Finalized runs written before this one, newest first.

    Names starting with '.' are skipped. Ids from a later UTC second sort after
    earlier ones. Inside one second the random suffix does not record finish
    order, so a directory finished earlier in that second still counts when its
    name sorts after this id.
    """
    if runs.is_symlink() or not runs.is_dir():
        return []
    try:
        children = list(runs.iterdir())
    except OSError:
        return []
    cutoff = _directory_mtime_ns(runs / f".{run_id}.partial")
    found: list[tuple[str, int, str, Path]] = []
    for path in children:
        name = path.name
        if name.startswith(".") or name == run_id:
            continue
        if path.is_symlink() or not path.is_dir() or not _stays_inside(runs, path):
            continue
        modified = _directory_mtime_ns(path)
        if name >= run_id and not _finished_earlier_same_second(name, run_id, modified, cutoff):
            continue
        found.append((*_recency_key(name, modified), path))
    found.sort(reverse=True)
    return [item[-1] for item in found]


def _directory_mtime_ns(path: Path) -> int:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return -1


def _finished_earlier_same_second(
    name: str, run_id: str, modified_ns: int, cutoff_ns: int
) -> bool:
    """True when name sorts later only because both runs share a UTC second."""
    stamp = _utc_stamp(run_id)
    return bool(
        stamp is not None
        and name.startswith(stamp)
        and modified_ns >= 0
        and cutoff_ns >= 0
        and modified_ns < cutoff_ns
    )


def _utc_stamp(run_id: str) -> str | None:
    if _STAMPED_RUN_ID.match(run_id) is None:
        return None
    return run_id[:16]


def _recency_key(name: str, modified_ns: int) -> tuple[str, int, str]:
    """Later UTC seconds first; inside one second, the later finish first."""
    stamp = _utc_stamp(name)
    if stamp is None:
        return (name, 0, name)
    return (stamp, modified_ns, name)


def _contained_child(runs: Path, name: str) -> Path | None:
    if not name or name.startswith(".") or "/" in name or "\\" in name:
        return None
    if runs.is_symlink() or not runs.is_dir():
        return None
    path = runs / name
    if path.is_symlink() or not path.is_dir() or not _stays_inside(runs, path):
        return None
    return path


def _stays_inside(root: Path, path: Path) -> bool:
    try:
        resolved = path.resolve()
        parent = root.resolve()
    except OSError:
        return False
    return parent == resolved or parent in resolved.parents


def _stored_target_names(directory: Path) -> frozenset[str]:
    names: list[str] = []
    snapshot = _yaml_target_names(directory)
    if snapshot is not None:
        names.extend(snapshot)
    benchmark = _loose_object(directory / "benchmark.json")
    controls = benchmark.get("controls") if benchmark is not None else None
    if isinstance(controls, list):
        for item in controls:
            if not isinstance(item, dict):
                continue
            target = item.get("target")
            if isinstance(target, str) and target and target not in names:
                names.append(target)
    for item in _object_list(directory / "findings.json"):
        target = item.get("target")
        if isinstance(target, str) and target and target not in names:
            names.append(target)
    return frozenset(names)


def _yaml_target_names(directory: Path) -> tuple[str, ...] | None:
    path = directory / "insidia.yaml"
    if path.is_symlink() or not path.is_file():
        return None
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError):
        return None
    if not isinstance(loaded, dict):
        return None
    targets = loaded.get("targets")
    if not isinstance(targets, dict):
        return ()
    return tuple(key for key in targets if isinstance(key, str) and key)


def _loose_object(path: Path) -> dict[str, object] | None:
    loaded = _loose_json(path)
    if not isinstance(loaded, dict):
        return None
    return cast(dict[str, object], loaded)


def _object_list(path: Path) -> list[dict[str, object]]:
    loaded = _loose_json(path)
    if not isinstance(loaded, list):
        return []
    return [cast(dict[str, object], item) for item in loaded if isinstance(item, dict)]


def _loose_json(path: Path) -> object | None:
    if path.is_symlink() or not path.is_file():
        return None
    try:
        return cast(object, json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def _target_names(
    findings: list[Finding],
    controls: list[dict[str, str | int]],
    targets: tuple[tuple[str, str, str], ...],
) -> list[str]:
    names: list[str] = []
    for name, _kind, _endpoint in targets:
        if name and name not in names:
            names.append(name)
    for control in controls:
        name = str(control.get("target", ""))
        if name and name not in names:
            names.append(name)
    for finding in findings:
        if finding.target and finding.target not in names:
            names.append(finding.target)
    return names


def _stamp_targets(
    findings: list[Finding], targets: tuple[tuple[str, str, str], ...]
) -> list[Finding]:
    known = {name: (kind, endpoint) for name, kind, endpoint in targets}
    stamped: list[Finding] = []
    for finding in findings:
        kind, endpoint = known.get(finding.target, ("", ""))
        stamped.append(
            replace(
                finding,
                target_kind=kind or finding.target_kind,
                endpoint=endpoint or finding.endpoint,
            )
        )
    return stamped
