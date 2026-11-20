"""Phase 1B adapters. Each engine is one value. The runner does not grow a branch."""

from __future__ import annotations

from insidia.adapters import (
    ProbeSpec,
    RelayAdapter,
    RepoPath,
    ReportAdapter,
    ScopedUrl,
)
from insidia.catalog import SPECS, EngineSpec
from insidia.upstream_ai import PROMPTFOO_ENV as PROMPTFOO_ENV  # noqa: F401
from insidia.upstream_ai import _relay_prepare
from insidia.upstream_repo import NUGUARD_ENV as NUGUARD_ENV  # noqa: F401
from insidia.upstream_repo import _repo_parser, _repo_prepare
from insidia.upstream_support import _load_json as _load_json  # noqa: F401
from insidia.upstream_web import _nuclei_path as _nuclei_path  # noqa: F401
from insidia.upstream_web import _nuclei_yaml as _nuclei_yaml  # noqa: F401
from insidia.upstream_web import _web_bodies as _web_bodies  # noqa: F401
from insidia.upstream_web import _web_parser, _web_prepare
from insidia.upstream_web import _zap_plan as _zap_plan  # noqa: F401


def build() -> tuple[RelayAdapter | ReportAdapter[ScopedUrl] | ReportAdapter[RepoPath], ...]:
    adapters: list[RelayAdapter | ReportAdapter[ScopedUrl] | ReportAdapter[RepoPath]] = []
    for spec in SPECS:
        probe = _probe(spec)
        if spec.kind == "relay":
            adapters.append(
                RelayAdapter(spec.name, spec.license, (probe,), _relay_prepare(spec.name))
            )
        elif spec.kind == "web":
            adapters.append(
                ReportAdapter(
                    spec.name,
                    spec.license,
                    (probe,),
                    ScopedUrl,
                    _web_prepare(spec.name),
                    _web_parser(spec.name),
                )
            )
        else:
            adapters.append(
                ReportAdapter(
                    spec.name,
                    spec.license,
                    (probe,),
                    RepoPath,
                    _repo_prepare(spec.name),
                    _repo_parser(spec.name),
                )
            )
    return tuple(adapters)


def _probe(spec: EngineSpec) -> ProbeSpec:
    return ProbeSpec(
        f"{spec.name}.{spec.family}",
        spec.upstream,
        spec.family,
        spec.priority,
        spec.name == "deepteam",
        spec.target_kinds,
    )
