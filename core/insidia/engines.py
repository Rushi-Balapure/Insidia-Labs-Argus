"""Install pinned engines into a toolchain directory and read the receipt."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import cast

from insidia.catalog import SPECS, EngineSpec
from insidia.errors import CliError
from insidia.process import child_env

_GITHUB_PREFIX = "https://github.com"
_PYTHON_PROGRAM = {
    "garak": "garak",
    "deepteam": "python",
    "pyrit": "python",
    "bandit": "bandit",
    "mcp-scanner": "mcp-scanner",
    "skillspector": "skillspector",
    "nuguard": "python",
}
# The lock pins CPU wheels. macOS resolves the default torch build; other hosts use +cpu.
_PIP_ARGS: dict[str, tuple[str, ...]] = {"garak": ("--torch-backend", "cpu")}
_HASH = re.compile(r"--hash=sha256:[0-9a-fA-F]{64}\b")

# SHA-256 of the file `_github()` names, keyed by that canonical GitHub URL.
# INSIDIA_ENGINE_MIRROR may replace the https://github.com prefix at fetch time.
# The pin is never keyed by the mirror URL. A missing pin or a mismatch fails
# before extract. `--allow-unverified` does not skip this check.
PINNED_SHA256: dict[str, str] = {
    (
        "https://github.com/aquasecurity/trivy/releases/download/"
        "v0.75.0/trivy_0.75.0_Linux-64bit.tar.gz"
    ): "c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f",
    (
        "https://github.com/aquasecurity/trivy/releases/download/"
        "v0.75.0/trivy_0.75.0_Linux-ARM64.tar.gz"
    ): "a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3",
    (
        "https://github.com/gitleaks/gitleaks/releases/download/"
        "v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz"
    ): "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
    (
        "https://github.com/gitleaks/gitleaks/releases/download/"
        "v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz"
    ): "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    (
        "https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_linux_amd64"
    ): "ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108",
    (
        "https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_linux_arm64"
    ): "2c71403eb443d05891c4f268c3ad771cf4f16e5443463fd7851ef8f454d3c7e4",
    (
        "https://github.com/hahwul/dalfox/releases/download/"
        "v3.2.3/dalfox-v3.2.3-linux-aarch64.tar.gz"
    ): "a7074d1001bb66664c1ed2db35d4b892a8f11da4d07f4deede1da8bfe7992d2b",
    (
        "https://github.com/hahwul/dalfox/releases/download/"
        "v3.2.3/dalfox-v3.2.3-linux-x86_64.tar.gz"
    ): "3b059b6bb55e686b5f240852ea6a6750aa5e35a3b404e4027ffe505e2b60a470",
    (
        "https://github.com/projectdiscovery/httpx/releases/download/"
        "v1.12.0/httpx_1.12.0_linux_amd64.zip"
    ): "9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76",
    (
        "https://github.com/projectdiscovery/httpx/releases/download/"
        "v1.12.0/httpx_1.12.0_linux_arm64.zip"
    ): "fd7b123c1dfbc3d69f19f524e4eebcd6ec06b9a6cbd56813c76f11645197331e",
    (
        "https://github.com/projectdiscovery/katana/releases/download/"
        "v1.8.0/katana_1.8.0_linux_amd64.zip"
    ): "cb027ae99d0757061b70c07a15c7a80f62c5a535ab52c4a329f80c4b0a7309d2",
    (
        "https://github.com/projectdiscovery/katana/releases/download/"
        "v1.8.0/katana_1.8.0_linux_arm64.zip"
    ): "80e269210727a855511ffac8dfb01297b2344742acec71a35e8ba4a67a90f0f2",
    (
        "https://github.com/projectdiscovery/nuclei/releases/download/"
        "v3.11.1/nuclei_3.11.1_linux_amd64.zip"
    ): "ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6",
    (
        "https://github.com/projectdiscovery/nuclei/releases/download/"
        "v3.11.1/nuclei_3.11.1_linux_arm64.zip"
    ): "8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07",
    (
        "https://github.com/projectdiscovery/nuclei/releases/download/"
        "v3.11.1/nuclei_3.11.1_macOS_amd64.zip"
    ): "75c47ce11e9dbd4288a1c895ed85e3c4df9f4acb8237d6d178da6dccd1628f2a",
    (
        "https://github.com/projectdiscovery/nuclei/releases/download/"
        "v3.11.1/nuclei_3.11.1_macOS_arm64.zip"
    ): "7d7e291addd1fc29a9bf8d089afe878a9799b20229cbea2fb1693fc40fd4c5f0",
    (
        "https://github.com/projectdiscovery/nuclei/releases/download/"
        "v3.11.1/nuclei_3.11.1_windows_amd64.zip"
    ): "bb6cb9ff8939b753f6fcab06fd30a15f5bc61d8382a597871334c007a85ff9d2",
    (
        "https://github.com/securego/gosec/releases/download/"
        "v2.29.0/gosec_2.29.0_linux_amd64.tar.gz"
    ): "6431b119741c1f4a50fdfcf94e782e16b9e642afc8c7fa9b5d39d48bf3003095",
    (
        "https://github.com/securego/gosec/releases/download/"
        "v2.29.0/gosec_2.29.0_linux_arm64.tar.gz"
    ): "c71244ec8d37488fd479d0d26990968fee03ece48b305d8224ac0c1ebd66e87c",
    (
        "https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz"
    ): "efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a",
    (
        "https://github.com/aquasecurity/trivy/releases/download/"
        "v0.75.0/trivy_0.75.0_macOS-64bit.tar.gz"
    ): "291edaa9778acbe4693d067b5ad60ee11570e5ac68296e85595417528ca641e4",
    (
        "https://github.com/aquasecurity/trivy/releases/download/"
        "v0.75.0/trivy_0.75.0_macOS-ARM64.tar.gz"
    ): "4a77108cccf8e55c8d6823e1e759939a622277e66cd0daa3c1fc621ed69e4568",
    (
        "https://github.com/aquasecurity/trivy/releases/download/"
        "v0.75.0/trivy_0.75.0_windows-64bit.zip"
    ): "4e43bd71a30f51aee39525f60f2b47043af77eb8df8fe082aae4372b69c6660f",
    (
        "https://github.com/gitleaks/gitleaks/releases/download/"
        "v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz"
    ): "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
    (
        "https://github.com/gitleaks/gitleaks/releases/download/"
        "v8.30.1/gitleaks_8.30.1_darwin_x64.tar.gz"
    ): "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
    (
        "https://github.com/gitleaks/gitleaks/releases/download/"
        "v8.30.1/gitleaks_8.30.1_windows_arm64.zip"
    ): "b95f5e4f5c425cedca7ee203d9afd29597e692c4924a12ed42f970537c72cc0f",
    (
        "https://github.com/gitleaks/gitleaks/releases/download/"
        "v8.30.1/gitleaks_8.30.1_windows_x64.zip"
    ): "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e",
    (
        "https://github.com/hahwul/dalfox/releases/download/"
        "v3.2.3/dalfox-v3.2.3-macos-aarch64.tar.gz"
    ): "b8cd129ec42663456f515cb5f655a38bb55e3ed5fcdfa8249c8306116898ac6b",
    (
        "https://github.com/hahwul/dalfox/releases/download/"
        "v3.2.3/dalfox-v3.2.3-macos-x86_64.tar.gz"
    ): "ec5edf21819ec2987c56afefb99533278992b03440b2f3f145f5c18c98f90b9b",
    (
        "https://github.com/hahwul/dalfox/releases/download/"
        "v3.2.3/dalfox-v3.2.3-windows-x86_64.zip"
    ): "0ad74b8937104d4603dea54c7e8d9d17e6802383a5f8b8133c7f55f19759e4a8",
    (
        "https://github.com/projectdiscovery/katana/releases/download/"
        "v1.8.0/katana_1.8.0_macOS_amd64.zip"
    ): "806256316dd45e0fe0e3985fd7283ddffc376c95cbaa3dcfd14cde6e1de61aaf",
    (
        "https://github.com/projectdiscovery/katana/releases/download/"
        "v1.8.0/katana_1.8.0_macOS_arm64.zip"
    ): "52e9802e9f83012a089fe57fb1ac476b936f181ac033c71bfa55f913c07cede6",
    (
        "https://github.com/projectdiscovery/katana/releases/download/"
        "v1.8.0/katana_1.8.0_windows_amd64.zip"
    ): "8013253e3092e08524527a5c3f7ebd70747acc4bb51414858f8e6dffeb17f907",
    (
        "https://github.com/projectdiscovery/katana/releases/download/"
        "v1.8.0/katana_1.8.0_windows_arm64.zip"
    ): "4b7c2e5759c8ea1a72081d75930e1ef24853a933c1d35e114ef6787bfc8ae058",
    (
        "https://github.com/projectdiscovery/httpx/releases/download/"
        "v1.12.0/httpx_1.12.0_macOS_amd64.zip"
    ): "16760b5e2122b66f57b9fbdb59f564b1181507c093d6a36066f40e5de38e8fa9",
    (
        "https://github.com/projectdiscovery/httpx/releases/download/"
        "v1.12.0/httpx_1.12.0_macOS_arm64.zip"
    ): "21d60328b383dba8a9fe249ac76b12edda4ec2e52a9cb21876c0a79123675569",
    (
        "https://github.com/projectdiscovery/httpx/releases/download/"
        "v1.12.0/httpx_1.12.0_windows_amd64.zip"
    ): "14d8ccaa2d95ce9365162682f1a2ba3f14d2000bb4bfb0924af65ec5163ae021",
    (
        "https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_darwin_amd64"
    ): "60c5296637e977b28eeda5c7f13573e447659a632922737f94d11fa7e30ad6ca",
    (
        "https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_darwin_arm64"
    ): "98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4",
    (
        "https://github.com/google/osv-scanner/releases/download/"
        "v2.6.0/osv-scanner_windows_amd64.exe"
    ): "e0ed7644118b717b028c249ee9d3515024e55e8510747ca08906eb96765354d6",
    (
        "https://github.com/google/osv-scanner/releases/download/"
        "v2.6.0/osv-scanner_windows_arm64.exe"
    ): "ca1379da0e408279ef2c85cde0846a903495738a91c7b065a208048437c1686c",
    (
        "https://github.com/securego/gosec/releases/download/"
        "v2.29.0/gosec_2.29.0_darwin_amd64.tar.gz"
    ): "a48152c3c009988f1750b6508316339c8b55076d24b1a958789e30ea2a21794c",
    (
        "https://github.com/securego/gosec/releases/download/"
        "v2.29.0/gosec_2.29.0_darwin_arm64.tar.gz"
    ): "7ab6a92c1983b7cb9df12b3ac20fb270afa43cfa12a143c354edae3109c763e5",
    (
        "https://github.com/securego/gosec/releases/download/"
        "v2.29.0/gosec_2.29.0_windows_amd64.tar.gz"
    ): "67cd5ca3a80280b27102a8d6482e7124e8a47bda240412a0fcd1bb7f1be96faf",
    (
        "https://github.com/securego/gosec/releases/download/"
        "v2.29.0/gosec_2.29.0_windows_arm64.tar.gz"
    ): "6165a36fe42ec5cbab06c1b42c1e26abb5d0b6dc789fb8661e6fe911cd30d460",
}


def _venv_python(stage: Path) -> Path:
    folder = "Scripts" if os.name == "nt" else "bin"
    name = "python.exe" if os.name == "nt" else "python"
    return stage / "venv" / folder / name


def _venv_script(name: str) -> str:
    if os.name == "nt":
        return f"venv/Scripts/{name}.exe"
    return f"venv/bin/{name}"


def _npm_script(name: str) -> str:
    if os.name == "nt":
        return f"node_modules/.bin/{name}.cmd"
    return f"node_modules/.bin/{name}"


def toolchain_root() -> Path:
    import os

    override = os.environ.get("INSIDIA_TOOLCHAIN")
    if override:
        return Path(override)
    return Path.home() / ".local" / "share" / "insidia" / "engines"


def list_engines() -> list[dict[str, object]]:
    from insidia.registry import KNOWN_ENGINES

    installed = installed_engines()
    rows: list[dict[str, object]] = []
    for name, license_name in KNOWN_ENGINES:
        receipt = _read_receipt(toolchain_root() / name)
        version = receipt.get("version") if receipt else None
        row: dict[str, object] = {
            "name": name,
            "license": license_name,
            "installed": name == "insidia" or name in installed,
            "version": version,
        }
        missing = missing_runtime(name)
        if receipt is not None and missing:
            row["note"] = f"needs {missing}"
        rows.append(row)
    return rows


# Engines whose program runs on a runtime the toolchain does not ship.
_RUNTIMES = {"zap": ("java", "Java 17 or later on PATH")}


def missing_runtime(name: str) -> str:
    """The runtime an engine needs that this machine lacks, or ""."""
    needed = _RUNTIMES.get(name)
    if needed is None or shutil.which(needed[0]) is not None:
        return ""
    return needed[1]


def unusable_engines() -> dict[str, str]:
    """Engines in the toolchain that cannot run here, with what they need."""
    return {name: missing_runtime(name) for name in _downloaded() if missing_runtime(name)}


def installed_engines() -> frozenset[str]:
    return frozenset(name for name in _downloaded() if not missing_runtime(name))


def _downloaded() -> frozenset[str]:
    root = toolchain_root()
    if not root.is_dir():
        return frozenset()
    found: list[str] = []
    for child in root.iterdir():
        if child.name.startswith("."):
            continue
        receipt = _read_receipt(child)
        if receipt is None or receipt.get("name") != child.name:
            continue
        program = child / str(receipt.get("program", ""))
        if program.is_file():
            found.append(child.name)
    return frozenset(found)


def program_for(name: str) -> str:
    final = toolchain_root() / name
    receipt = _read_receipt(final)
    if receipt is None:
        return str(final / "missing")
    # abspath, not resolve: a venv python is a symlink, and following it
    # drops the venv's site-packages.
    return os.path.abspath(final / str(receipt["program"]))


def install(
    names: tuple[str, ...] = (),
    docker: bool = False,
    progress: Callable[[str], None] | None = None,
    allow_unverified: bool = False,
) -> str:
    if docker:
        if shutil.which("docker") is None:
            raise CliError("docker is not installed")
        if names:
            raise CliError("docker images for named engines are not in this release")
        return "docker is available; engine images arrive with the engine adapters"
    if not names:
        return "built-in probes are already available; name an engine to install it"
    unknown = [name for name in names if name not in {spec.name for spec in SPECS}]
    if unknown:
        raise CliError(f"unknown engine {unknown[0]}")
    lines: list[str] = []
    specs = {spec.name: spec for spec in SPECS}
    for name in names:
        spec = specs[name]
        if progress is not None:
            progress(f"Installing {name} {spec.version}.")
        line = _install_one(name, allow_unverified=allow_unverified)
        if allow_unverified:
            line += "; warning: --allow-unverified does not skip hash verification"
        needed = missing_runtime(name)
        if needed:
            line = f"{line}; warning: needs {needed} before it can run"
        lines.append(line)
        if progress is not None:
            progress(line)
    return "; ".join(lines)


def _install_one(name: str, allow_unverified: bool = False) -> str:
    spec = next(item for item in SPECS if item.name == name)
    root = toolchain_root()
    final = root / name
    receipt = _read_receipt(final)
    if (
        receipt
        and receipt.get("version") == spec.version
        and (final / str(receipt.get("program", ""))).is_file()
    ):
        _rewrite_shebangs(final)
        return f"{name} {spec.version} is already installed"
    root.mkdir(parents=True, exist_ok=True)
    stage = root / f".{name}.staging"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir()
    try:
        program = _stage(spec, stage, allow_unverified=allow_unverified)
        _publish(
            stage,
            final,
            {"name": name, "version": spec.version, "program": program},
        )
    except Exception:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)
        raise
    return f"installed {name} {spec.version}"


def _publish(stage: Path, final: Path, receipt: dict[str, str]) -> None:
    (stage / "receipt.json").write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    if final.exists():
        backup = final.with_name(f".{final.name}.previous")
        if backup.exists():
            shutil.rmtree(backup)
        final.rename(backup)
        try:
            stage.rename(final)
        except Exception:
            backup.rename(final)
            raise
        shutil.rmtree(backup)
        _rewrite_shebangs(final)
        return
    stage.rename(final)
    _rewrite_shebangs(final)


def _rewrite_shebangs(root: Path) -> None:
    """Point venv scripts at the published interpreter.

    uv writes absolute shebangs. Staging then renaming the tree leaves them
    aimed at a directory that no longer exists.
    """
    python = root / "venv" / "bin" / "python"
    if not python.is_file():
        return
    line = f"#!{python}"
    for script in python.parent.iterdir():
        if script.is_symlink() or not script.is_file():
            continue
        try:
            text = script.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        first, sep, rest = text.partition("\n")
        if not first.startswith("#!") or "python" not in first or first == line:
            continue
        script.write_text(line + sep + rest, encoding="utf-8")


def _stage(spec: EngineSpec, stage: Path, allow_unverified: bool = False) -> str:
    if spec.name in _PYTHON_PROGRAM:
        _install_locked_python(spec, stage)
        if spec.name == "nuguard":
            _require(stage, _venv_script("nuguard"))
        return _require(stage, _venv_script(_PYTHON_PROGRAM[spec.name]))
    if spec.name == "promptfoo":
        _install_locked_npm(stage)
        return _require(stage, _npm_script("promptfoo"))
    if spec.name == "zap":
        return _fetch_zap(spec, stage, allow_unverified=allow_unverified)
    if spec.name == "osv-scanner":
        return _fetch_binary(spec, stage, raw=True, allow_unverified=allow_unverified)
    return _fetch_binary(spec, stage, raw=False, allow_unverified=allow_unverified)


def _require(stage: Path, relative: str) -> str:
    if not (stage / relative).is_file():
        raise CliError(f"{relative} was not installed")
    return relative


def _locks_root() -> Path:
    return Path(__file__).resolve().parent / "locks"


def _lock_file(name: str) -> Path:
    path = _locks_root() / f"{name}.txt"
    if not path.is_file():
        raise CliError(f"{name} has no hash-pinned lock file")
    return path


def _logical_lines(text: str) -> list[str]:
    lines: list[str] = []
    current = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            if current:
                lines.append(current)
                current = ""
            continue
        if stripped.endswith("\\"):
            current = f"{current}{stripped[:-1].strip()} "
            continue
        lines.append(f"{current}{stripped}")
        current = ""
    if current:
        lines.append(current.strip())
    return lines


def _requirement_label(line: str) -> str:
    head = line.split("--hash", 1)[0].split(";", 1)[0].strip()
    if "@" in head:
        head = head.split("@", 1)[0].strip()
    else:
        head = head.split("==", 1)[0].split("[", 1)[0].strip()
    return head or line


def _require_lock_hashes(lock: Path) -> None:
    """Refuse a requirements file that could install without a sha256 pin."""
    try:
        text = lock.read_text(encoding="utf-8")
    except OSError as exc:
        raise CliError(f"could not read {lock.name}") from exc
    requirements: list[str] = []
    for line in _logical_lines(text):
        if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
            raise CliError(f"{lock.name} cannot include another requirements file")
        if line.startswith("-"):
            continue
        requirements.append(line)
    if not requirements:
        raise CliError(f"{lock.name} pins no packages")
    for line in requirements:
        label = _requirement_label(line)
        if "git+" in line or line.startswith("git@"):
            raise CliError(f"{lock.name} pins {label} with a git ref; a git tag can be moved")
        if _HASH.search(line) is None:
            raise CliError(f"{lock.name} is missing a SHA-256 pin for {label}")


def _require_npm_integrity(lock: Path) -> None:
    """Refuse an npm lock whose installed packages have no integrity hash."""
    try:
        document = json.loads(lock.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CliError(f"{lock.name} is not a package-lock.json") from exc
    packages = document.get("packages") if isinstance(document, dict) else None
    if not isinstance(packages, dict):
        raise CliError(f"{lock.name} does not pin promptfoo")
    version = document.get("lockfileVersion")
    if not isinstance(version, int) or version < 2:
        raise CliError(f"{lock.name} is not a lockfile with integrity hashes")
    saw_promptfoo = False
    for key, meta in packages.items():
        if (
            not isinstance(key, str)
            or not key.startswith("node_modules/")
            or not isinstance(meta, dict)
        ):
            continue
        if meta.get("link") is True or meta.get("inBundle") is True:
            continue
        if key == "node_modules/promptfoo" or key.endswith("/node_modules/promptfoo"):
            saw_promptfoo = True
            if meta.get("version") != "0.124.0":
                raise CliError(f"promptfoo lock pins {meta.get('version')}, want 0.124.0")
        integrity = meta.get("integrity")
        resolved = meta.get("resolved")
        if not isinstance(resolved, str) or not resolved:
            if meta.get("optional") is True or meta.get("peer") is True:
                continue
        if not isinstance(integrity, str) or not integrity.startswith(("sha512-", "sha1-")):
            raise CliError(f"{lock.name} is missing an integrity hash for {key}")
    if not saw_promptfoo:
        raise CliError(f"{lock.name} does not pin promptfoo")


def _install_locked_python(spec: EngineSpec, stage: Path) -> None:
    lock = _lock_file(spec.name)
    _require_lock_hashes(lock)
    uv = shutil.which("uv")
    if uv is None:
        raise CliError("uv is not installed")
    python = _venv_python(stage)
    env = child_env({})
    if not python.is_file():
        _checked([uv, "venv", "--python", "3.12", str(stage / "venv")], env)
    command = [
        uv,
        "pip",
        "install",
        "--python",
        str(python),
        *_PIP_ARGS.get(spec.name, ()),
        "--require-hashes",
        "-r",
        str(lock),
    ]
    _checked(command, env)


def _install_locked_npm(stage: Path) -> None:
    npm = shutil.which("npm")
    if npm is None:
        raise CliError("npm is not installed")
    source = _locks_root() / "promptfoo"
    lock = source / "package-lock.json"
    manifest = source / "package.json"
    _require_npm_integrity(lock)
    if not manifest.is_file():
        raise CliError("promptfoo has no package.json")
    shutil.copyfile(manifest, stage / "package.json")
    shutil.copyfile(lock, stage / "package-lock.json")
    _checked(
        [npm, "ci", "--prefix", str(stage), "--no-fund", "--no-audit", "--ignore-scripts"],
        child_env({}),
    )


def _checked(command: list[str], env: dict[str, str]) -> None:
    # The tool's own chatter would scroll past the progress line. A failure
    # keeps the last lines so the reason is not lost.
    try:
        subprocess.run(
            command,
            check=True,
            env=env,
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.CalledProcessError as exc:
        tail = [line for line in (exc.stderr or exc.stdout or "").splitlines() if line.strip()]
        detail = f": {' | '.join(line.strip() for line in tail[-3:])}" if tail else ""
        raise CliError(f"{Path(command[0]).name} exited {exc.returncode}{detail}") from exc


def _fetch_binary(spec: EngineSpec, stage: Path, raw: bool, allow_unverified: bool = False) -> str:
    url = _github(spec)
    archive = stage / "download"
    _download(url, archive)
    _verify_download(spec, url, archive, allow_unverified)
    binary = f"{spec.package}.exe" if sys.platform == "win32" else spec.package
    if raw:
        destination = stage / "bin" / binary
        destination.parent.mkdir()
        shutil.copy(archive, destination)
        destination.chmod(0o755)
        return f"bin/{binary}"
    unpack = stage / "unpack"
    _extract(archive, unpack)
    matches = [path for path in unpack.rglob(binary) if path.is_file()]
    if not matches:
        raise CliError(f"{binary} was not in the archive")
    destination = stage / "bin" / binary
    destination.parent.mkdir()
    shutil.copy(matches[0], destination)
    destination.chmod(0o755)
    return f"bin/{binary}"


def _fetch_zap(spec: EngineSpec, stage: Path, allow_unverified: bool = False) -> str:
    url = _github(spec)
    archive = stage / "download"
    _download(url, archive)
    _verify_download(spec, url, archive, allow_unverified)
    unpack = stage / "unpack"
    _extract(archive, unpack)
    matches = [path for path in unpack.rglob("zap.sh") if path.is_file()]
    if not matches:
        raise CliError("zap.sh was not in the archive")
    chosen = matches[0]
    relative = chosen.relative_to(unpack).as_posix()
    target = stage / relative
    shutil.copytree(chosen.parent, target.parent)
    zap = stage / relative
    zap.chmod(0o755)
    return relative


def _extract(archive: Path, unpack: Path) -> None:
    unpack.mkdir()
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(unpack)
        return
    with tarfile.open(archive, "r:gz") as bundle:
        bundle.extractall(unpack, filter="data")


def _verify_download(spec: EngineSpec, url: str, archive: Path, allow_unverified: bool) -> None:
    """Check the downloaded bytes before they are extracted or made executable."""
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    pinned = PINNED_SHA256.get(url)
    skipped = "; --allow-unverified does not skip hash verification" if allow_unverified else ""
    if pinned is None:
        raise CliError(
            f"no SHA-256 pin for {spec.name} {spec.version} on this platform{skipped}"
        )
    if digest != pinned.lower():
        raise CliError(f"{spec.name} {spec.version} failed SHA-256 verification{skipped}")


def _mirrored_download_url(url: str) -> str:
    """Fetch URL for a canonical engine download.

    Unset, the URL is unchanged. A mirror replaces only the ``https://github.com``
    prefix. SHA-256 pins stay on the canonical URL the caller already holds.
    """
    mirror = os.environ.get("INSIDIA_ENGINE_MIRROR", "").strip()
    if not mirror:
        return url
    parsed = urllib.parse.urlsplit(mirror)
    if parsed.scheme not in {"http", "https"} or parsed.netloc == "":
        raise CliError("INSIDIA_ENGINE_MIRROR must be an http or https URL")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.netloc != "github.com":
        raise CliError("INSIDIA_ENGINE_MIRROR rewrites only https://github.com URLs")
    return mirror.rstrip("/") + url.removeprefix(_GITHUB_PREFIX)


def _download(url: str, destination: Path) -> None:
    fetch_url = _mirrored_download_url(url)
    request = urllib.request.Request(fetch_url, headers={"User-Agent": "insidia"})
    handlers: list[urllib.request.BaseHandler] = [
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(),
    ]
    # A localhost mirror is an install override. Do not send it through a proxy.
    host = urllib.parse.urlsplit(fetch_url).hostname
    if host in {"localhost", "127.0.0.1", "::1"}:
        handlers.insert(0, urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=120) as response:
            destination.write_bytes(response.read())
    except OSError as exc:
        raise CliError(f"download failed for {fetch_url}") from exc


_RELEASE_ROOT: dict[str, str] = {
    "nuclei": "https://github.com/projectdiscovery/nuclei/releases/download/v{v}/",
    "dalfox": "https://github.com/hahwul/dalfox/releases/download/v{v}/",
    "katana": "https://github.com/projectdiscovery/katana/releases/download/v{v}/",
    "httpx": "https://github.com/projectdiscovery/httpx/releases/download/v{v}/",
    "trivy": "https://github.com/aquasecurity/trivy/releases/download/v{v}/",
    "osv-scanner": "https://github.com/google/osv-scanner/releases/download/v{v}/",
    "gitleaks": "https://github.com/gitleaks/gitleaks/releases/download/v{v}/",
    "gosec": "https://github.com/securego/gosec/releases/download/v{v}/",
}
# (engine, sys.platform, cpu) -> asset filename. Absent means that host has no build.
_ASSETS: dict[tuple[str, str, str], str] = {
    ("nuclei", "linux", "amd64"): "nuclei_{v}_linux_amd64.zip",
    ("nuclei", "linux", "arm64"): "nuclei_{v}_linux_arm64.zip",
    ("nuclei", "darwin", "amd64"): "nuclei_{v}_macOS_amd64.zip",
    ("nuclei", "darwin", "arm64"): "nuclei_{v}_macOS_arm64.zip",
    ("nuclei", "win32", "amd64"): "nuclei_{v}_windows_amd64.zip",
    ("dalfox", "linux", "amd64"): "dalfox-v{v}-linux-x86_64.tar.gz",
    ("dalfox", "linux", "arm64"): "dalfox-v{v}-linux-aarch64.tar.gz",
    ("dalfox", "darwin", "amd64"): "dalfox-v{v}-macos-x86_64.tar.gz",
    ("dalfox", "darwin", "arm64"): "dalfox-v{v}-macos-aarch64.tar.gz",
    ("dalfox", "win32", "amd64"): "dalfox-v{v}-windows-x86_64.zip",
    ("katana", "linux", "amd64"): "katana_{v}_linux_amd64.zip",
    ("katana", "linux", "arm64"): "katana_{v}_linux_arm64.zip",
    ("katana", "darwin", "amd64"): "katana_{v}_macOS_amd64.zip",
    ("katana", "darwin", "arm64"): "katana_{v}_macOS_arm64.zip",
    ("katana", "win32", "amd64"): "katana_{v}_windows_amd64.zip",
    ("katana", "win32", "arm64"): "katana_{v}_windows_arm64.zip",
    ("httpx", "linux", "amd64"): "httpx_{v}_linux_amd64.zip",
    ("httpx", "linux", "arm64"): "httpx_{v}_linux_arm64.zip",
    ("httpx", "darwin", "amd64"): "httpx_{v}_macOS_amd64.zip",
    ("httpx", "darwin", "arm64"): "httpx_{v}_macOS_arm64.zip",
    ("httpx", "win32", "amd64"): "httpx_{v}_windows_amd64.zip",
    ("trivy", "linux", "amd64"): "trivy_{v}_Linux-64bit.tar.gz",
    ("trivy", "linux", "arm64"): "trivy_{v}_Linux-ARM64.tar.gz",
    ("trivy", "darwin", "amd64"): "trivy_{v}_macOS-64bit.tar.gz",
    ("trivy", "darwin", "arm64"): "trivy_{v}_macOS-ARM64.tar.gz",
    ("trivy", "win32", "amd64"): "trivy_{v}_windows-64bit.zip",
    ("osv-scanner", "linux", "amd64"): "osv-scanner_linux_amd64",
    ("osv-scanner", "linux", "arm64"): "osv-scanner_linux_arm64",
    ("osv-scanner", "darwin", "amd64"): "osv-scanner_darwin_amd64",
    ("osv-scanner", "darwin", "arm64"): "osv-scanner_darwin_arm64",
    ("osv-scanner", "win32", "amd64"): "osv-scanner_windows_amd64.exe",
    ("osv-scanner", "win32", "arm64"): "osv-scanner_windows_arm64.exe",
    ("gitleaks", "linux", "amd64"): "gitleaks_{v}_linux_x64.tar.gz",
    ("gitleaks", "linux", "arm64"): "gitleaks_{v}_linux_arm64.tar.gz",
    ("gitleaks", "darwin", "amd64"): "gitleaks_{v}_darwin_x64.tar.gz",
    ("gitleaks", "darwin", "arm64"): "gitleaks_{v}_darwin_arm64.tar.gz",
    ("gitleaks", "win32", "amd64"): "gitleaks_{v}_windows_x64.zip",
    ("gitleaks", "win32", "arm64"): "gitleaks_{v}_windows_arm64.zip",
    ("gosec", "linux", "amd64"): "gosec_{v}_linux_amd64.tar.gz",
    ("gosec", "linux", "arm64"): "gosec_{v}_linux_arm64.tar.gz",
    ("gosec", "darwin", "amd64"): "gosec_{v}_darwin_amd64.tar.gz",
    ("gosec", "darwin", "arm64"): "gosec_{v}_darwin_arm64.tar.gz",
    ("gosec", "win32", "amd64"): "gosec_{v}_windows_amd64.tar.gz",
    ("gosec", "win32", "arm64"): "gosec_{v}_windows_arm64.tar.gz",
}


def _cpu(spec: EngineSpec) -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return "amd64"
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    raise CliError(f"no {spec.name} build for {machine}")


def _github(spec: EngineSpec) -> str:
    cpu = _cpu(spec)
    if spec.name == "zap":
        # The adapter runs zap.sh from this archive. The macOS and Windows
        # releases are installers, not that layout, and this file is pinned.
        return (
            "https://github.com/zaproxy/zaproxy/releases/download/"
            f"v{spec.version}/ZAP_{spec.version}_Linux.tar.gz"
        )
    pattern = _ASSETS.get((spec.name, sys.platform, cpu))
    root = _RELEASE_ROOT.get(spec.name)
    if pattern is None or root is None:
        raise CliError(f"no {spec.name} build for {sys.platform} {cpu}")
    return root.format(v=spec.version) + pattern.format(v=spec.version)


def _read_receipt(directory: Path) -> dict[str, object] | None:
    path = directory / "receipt.json"
    if not path.is_file():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(loaded, dict):
        return None
    return cast(dict[str, object], loaded)
