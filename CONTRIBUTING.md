# Contributing

Insidia Labs is Apache-2.0. Contributions are welcome.

## Developer Certificate of Origin

Every commit must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/), version 1.1. Add this line to each commit message:

```text
Signed-off-by: Your Name <your.email@example.com>
```

`git commit -s` does that. There is no CLA.

By signing off, you certify that you can submit the change under the Apache License, Version 2.0.

## What to change

- The CLI lives in `core/`. The benchmark lives in `benchmark/`.
- The benchmark environment uses Python 3.14. The CLI package is Python 3.12+.
- Do not add a dependency whose license is outside MIT, Apache-2.0, BSD, ISC, or a reviewed MPL-2.0. GPL, AGPL, SSPL, and Elastic-licensed code fail CI.
- A scan must stay inside the scope in `insidia.yaml`. Do not weaken that check.
- Credit an engine by name when a finding comes from it. Mask secrets. Do not log prompts.

## Checks

From `core/`:

```bash
uv sync
uv run ruff check .
uv run mypy insidia
uv run pytest
```

## Engine lockfiles

Python engines install from the hash-pinned requirements in `core/insidia/locks/`. promptfoo installs with `npm ci` from `core/insidia/locks/promptfoo/package-lock.json`. Regenerate the locks when an engine version changes. The command reaches PyPI and the npm registry:

```bash
cd core
uv run python scripts/lock_engines.py
```

It runs `uv pip compile --generate-hashes --universal --python-version 3.12`. Engine virtualenvs use Python 3.12, and `--universal` records a hash for every platform wheel of those pins. Garak is compiled with `--torch-backend cpu`. SkillSpector is pinned to commit `c7958a3268d9498644b22edb75d0f051bbc8cbfc` (tag v2.12.0), not the tag. Binary downloads are pinned by SHA-256 in `core/insidia/engines.py`; a missing pin is refused, and `--allow-unverified` does not skip the check. `insidia upgrade` installs the release wheel after its SHA-256 matches `SHA256SUMS` (and the GitHub asset digest when that is present). It does not install from a git tag.

Hatchling ships `insidia/locks` in the wheel because that directory is inside the package. Do not also `force-include` it; the build then adds each file twice and fails.

The scanner benchmark, from the repository root:

```bash
uv sync --locked --project benchmark
uv run --project benchmark ruff check benchmark
uv run --project benchmark python -m pytest benchmark
```
