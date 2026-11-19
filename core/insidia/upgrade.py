"""Find the latest GitHub release and reinstall Insidia from its verified wheel."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from insidia import __version__
from insidia.errors import CliError

REPO = "Rushi-Balapure/Insidia-Labs-Argus"
LATEST_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_URL = f"https://github.com/{REPO}/releases"

_VERSION = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}")
_COMMIT = re.compile(r"[0-9a-fA-F]{40}")


@dataclass(frozen=True)
class Release:
    tag: str
    version: str
    url: str
    wheel_url: str = ""
    sha256: str = ""
    sums_url: str = ""
    commit: str = ""


def parse_version(text: str) -> tuple[int, int, int] | None:
    found = _VERSION.fullmatch(text.strip())
    if found is None:
        return None
    major, minor, patch = (int(part) for part in found.groups())
    return major, minor, patch


def upgrade_cache() -> Path:
    override = os.environ.get("INSIDIA_UPGRADE_CACHE", "").strip()
    if override:
        return Path(override)
    return Path.home() / ".local" / "share" / "insidia" / "upgrade"


def release_from_document(document: object) -> Release:
    """Read a GitHub release. A wheel digest is kept; a branch name is not a commit."""
    if not isinstance(document, dict):
        raise CliError("the latest release response was not a JSON object")
    tag = document.get("tag_name")
    if not isinstance(tag, str) or parse_version(tag) is None:
        raise CliError(f"the latest release tag {tag!r} is not a version such as v1.0.0")
    page = document.get("html_url")
    url = page if isinstance(page, str) else f"{RELEASES_URL}/tag/{tag}"
    commit = ""
    named = document.get("target_commitish")
    if isinstance(named, str) and _COMMIT.fullmatch(named):
        commit = named.lower()
    wheel_url = ""
    sha256 = ""
    sums_url = ""
    wheels = 0
    assets = document.get("assets")
    if isinstance(assets, list):
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            name = asset.get("name")
            download = asset.get("browser_download_url")
            if not isinstance(name, str) or not isinstance(download, str):
                continue
            if name == "SHA256SUMS":
                sums_url = download
                continue
            if not name.endswith(".whl"):
                continue
            wheels += 1
            wheel_url = download
            digest = asset.get("digest")
            if isinstance(digest, str) and digest.lower().startswith("sha256:"):
                hex_digest = digest.split(":", 1)[1]
                if _SHA256.fullmatch(hex_digest):
                    sha256 = hex_digest.lower()
    if wheels > 1:
        raise CliError(f"release {tag} publishes more than one wheel")
    return Release(
        tag=tag,
        version=tag.removeprefix("v"),
        url=url,
        wheel_url=wheel_url,
        sha256=sha256,
        sums_url=sums_url,
        commit=commit,
    )


def pin_from_sums(text: str, wheel_name: str) -> str:
    """The sha256sum line for `wheel_name`."""
    found = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            continue
        digest, name = parts
        name = Path(name.removeprefix("*").replace("\\", "/")).name
        if name != wheel_name:
            continue
        if not _SHA256.fullmatch(digest):
            raise CliError("SHA256SUMS has a malformed pin")
        lowered = digest.lower()
        if found and found != lowered:
            raise CliError("SHA256SUMS lists conflicting digests")
        found = lowered
    if not found:
        raise CliError(f"SHA256SUMS has no pin for {wheel_name}")
    return found


def fetch_latest(timeout: float = 10.0) -> Release:
    request = urllib.request.Request(
        LATEST_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"insidia/{__version__}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            document = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise CliError(f"no release is published yet. See {RELEASES_URL}") from exc
        raise CliError(f"GitHub returned HTTP {exc.code} for the latest release") from exc
    except (OSError, ValueError) as exc:
        raise CliError(f"could not check GitHub for the latest release: {exc}") from exc
    return release_from_document(document)


def detect_installer(prefix: Path | None = None, package: Path | None = None) -> str:
    """uv, pipx, pip, or checkout. A checkout is this repository run in place."""
    prefix = Path(sys.prefix) if prefix is None else prefix
    package = Path(__file__).resolve().parent if package is None else package
    if (package.parent / "pyproject.toml").is_file() and (package.parents[1] / ".git").exists():
        return "checkout"
    if (prefix / "uv-receipt.toml").is_file():
        return "uv"
    if (prefix / "pipx_metadata.json").is_file():
        return "pipx"
    return "pip"


def install_command(installer: str, wheel: Path, force: bool = False) -> list[str]:
    if installer == "checkout":
        raise CliError(
            "this copy runs from a git checkout. Update it with git pull, "
            f'or install the release with: uv tool install --force "{wheel}"'
        )
    if wheel.suffix != ".whl" or not wheel.is_file():
        raise CliError("upgrade needs the verified release wheel")
    spec = str(wheel)
    if installer == "uv":
        return [_tool("uv"), "tool", "install", "--force", spec]
    if installer == "pipx":
        return [_tool("pipx"), "install", "--force", spec]
    if installer == "pip":
        if importlib.util.find_spec("pip") is None:
            raise CliError(
                "this copy was not installed with uv or pipx, and pip is not available. "
                f'Reinstall with: uv tool install --force "{spec}"'
            )
        reinstall = ["--force-reinstall"] if force else []
        return [sys.executable, "-m", "pip", "install", "--upgrade", *reinstall, spec]
    raise CliError(
        "this copy runs from a git checkout. Update it with git pull, "
        f'or install the release with: uv tool install --force "{spec}"'
    )


def _tool(name: str) -> str:
    found = shutil.which(name)
    if found is None:
        raise CliError(f"this copy was installed with {name}, but {name} is not on PATH")
    return found


def _https_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise CliError("release asset URL must be https")


def _reject_movable_release(release: Release) -> None:
    source = release.wheel_url
    if source.startswith("git+") or source.startswith("git@"):
        raise CliError(
            f"release {release.tag} points at a git ref; "
            "refusing to install because a tag can be moved"
        )
    if release.commit and _COMMIT.fullmatch(release.commit) is None:
        raise CliError(
            f"release {release.tag} names {release.commit!r}, "
            "which is not an immutable commit SHA"
        )


def _wheel_name(url: str) -> str:
    path = urllib.parse.unquote(urllib.parse.urlsplit(url).path)
    name = path.rsplit("/", 1)[-1]
    if not name.endswith(".whl"):
        raise CliError("release asset is not a wheel")
    return name


def resolve_wheel(release: Release, fetch: Callable[[str], bytes], cache: Path) -> Path:
    """Download the release wheel and keep it only when the SHA-256 matches."""
    _reject_movable_release(release)
    if not release.wheel_url and not release.sums_url:
        raise CliError(
            f"release {release.tag} has no pinned wheel SHA-256; "
            "refusing to install from a git tag that can be moved"
        )
    if release.wheel_url:
        _https_url(release.wheel_url)
    if release.sums_url:
        _https_url(release.sums_url)
    sha = release.sha256.lower()
    wheel_name = _wheel_name(release.wheel_url) if release.wheel_url else ""
    if release.sums_url:
        if not wheel_name:
            raise CliError(
                f"release {release.tag} has no pinned wheel SHA-256; "
                "refusing to install from a git tag that can be moved"
            )
        try:
            summed = pin_from_sums(fetch(release.sums_url).decode("utf-8"), wheel_name)
        except UnicodeError as exc:
            raise CliError("SHA256SUMS is not utf-8") from exc
        if sha and sha != summed:
            raise CliError("release digest does not match SHA256SUMS")
        sha = summed
    if _SHA256.fullmatch(sha) is None or not release.wheel_url:
        raise CliError(
            f"release {release.tag} has no pinned wheel SHA-256; "
            "refusing to install from a git tag that can be moved"
        )
    blob = fetch(release.wheel_url)
    if hashlib.sha256(blob).hexdigest() != sha:
        raise CliError("release wheel failed SHA-256 verification")
    cache.mkdir(parents=True, exist_ok=True)
    destination = cache / f"{sha[:16]}-{wheel_name}"
    temporary = cache / f".{destination.name}.partial"
    temporary.write_bytes(blob)
    try:
        if hashlib.sha256(temporary.read_bytes()).hexdigest() != sha:
            raise CliError("release wheel failed SHA-256 verification")
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination


def _read_url(url: str, timeout: float = 60.0) -> bytes:
    _https_url(url)
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/octet-stream",
            "User-Agent": f"insidia/{__version__}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return bytes(response.read())
    except urllib.error.HTTPError as exc:
        raise CliError(f"GitHub returned HTTP {exc.code} for {url}") from exc
    except (OSError, ValueError) as exc:
        raise CliError(f"could not download {url}: {exc}") from exc


def upgrade(
    check: bool,
    force: bool,
    output: IO[str] | None = None,
    latest: Callable[[], Release] = fetch_latest,
    installer: Callable[[], str] = detect_installer,
    run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    platform: str = sys.platform,
    fetch: Callable[[str], bytes] = _read_url,
    cache: Path | None = None,
) -> tuple[dict[str, object], str]:
    """Return the JSON document and the text line for `insidia upgrade`."""
    release = latest()
    current = parse_version(__version__)
    newest = parse_version(release.version)
    available = current is None or (newest is not None and newest > current)
    document: dict[str, object] = {
        "current": __version__,
        "latest": release.version,
        "update_available": available,
        "release": release.url,
    }
    if check or (not available and not force):
        if available:
            text = (
                f"Insidia {release.version} is available (you have {__version__}). "
                "Run insidia upgrade to install it."
            )
        else:
            text = f"Insidia {__version__} is the latest release."
        document["upgraded"] = False
        return document, text
    how = installer()
    wheel = resolve_wheel(release, fetch, upgrade_cache() if cache is None else cache)
    command = install_command(how, wheel, force=force)
    shown = f'{" ".join(command[:-1])} "{command[-1]}"'
    document["installer"] = how
    document["wheel_sha256"] = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if platform == "win32":
        # Windows locks the running python.exe and insidia.exe, so the installer
        # cannot rebuild this environment until the process exits.
        document["upgraded"] = False
        document["command"] = shown
        return document, (
            f"Insidia {release.version} is ready to install. Windows cannot replace "
            f"Insidia while it runs, so run this after it exits:\n{shown}"
        )
    target = sys.stderr if output is None else output
    print(f"Installing Insidia {release.version} with {how}.", file=target, flush=True)
    try:
        finished = run(command, stdout=target, stderr=target, check=False)
    except OSError as exc:
        raise CliError(f"could not run {command[0]}: {exc}") from exc
    if finished.returncode != 0:
        raise CliError(f"{how} exited with code {finished.returncode}. Retry by hand with: {shown}")
    document["upgraded"] = True
    return document, f"Upgraded Insidia {__version__} to {release.version}. {release.url}"
