import hashlib
import io
import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from insidia import __version__, upgrade
from insidia.cli import main
from insidia.errors import CliError
from insidia.upgrade import (
    Release,
    detect_installer,
    fetch_latest,
    install_command,
    parse_version,
    pin_from_sums,
    release_from_document,
    upgrade_cache,
)


def _release(version: str) -> Release:
    return Release(tag=f"v{version}", version=version, url=f"https://example.test/v{version}")


def _bump(version: str) -> str:
    major, minor, patch = version.split(".")
    return f"{major}.{minor}.{int(patch) + 1}"


def _pinned(
    version: str, body: bytes = b"wheel-bytes"
) -> tuple[Release, Callable[[str], bytes]]:
    digest = hashlib.sha256(body).hexdigest()
    name = f"insidia-{version}-py3-none-any.whl"
    release = Release(
        tag=f"v{version}",
        version=version,
        url=f"https://example.test/v{version}",
        wheel_url=f"https://example.test/releases/{name}",
        sha256=digest,
        sums_url="https://example.test/SHA256SUMS",
        commit="0123456789abcdef0123456789abcdef01234567",
    )

    def fetch(url: str) -> bytes:
        if url.endswith("/SHA256SUMS"):
            return f"{digest}  {name}\n".encode()
        if url.endswith(f"/{name}"):
            return body
        raise AssertionError(url)

    return release, fetch


class _Runner:
    def __init__(self, code: int = 0) -> None:
        self.code = code
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str], **_: Any) -> subprocess.CompletedProcess[bytes]:
        self.commands.append(command)
        return subprocess.CompletedProcess(command, self.code)


def _wheel(tmp_path: Path) -> Path:
    path = tmp_path / "insidia-2.0.0-py3-none-any.whl"
    path.write_bytes(b"whl")
    return path


def test_parse_version_accepts_tags_and_rejects_other_text() -> None:
    assert parse_version("v1.2.3") == (1, 2, 3)
    assert parse_version("1.10.0") == (1, 10, 0)
    assert parse_version("1.10.0") > parse_version("1.9.9")  # type: ignore[operator]
    assert parse_version("v1.2") is None
    assert parse_version("latest") is None


def test_detect_installer_reads_the_environment_markers(tmp_path: Path) -> None:
    package = tmp_path / "site-packages" / "insidia"
    package.mkdir(parents=True)
    assert detect_installer(tmp_path, package) == "pip"
    (tmp_path / "pipx_metadata.json").write_text("{}")
    assert detect_installer(tmp_path, package) == "pipx"
    (tmp_path / "uv-receipt.toml").write_text("")
    assert detect_installer(tmp_path, package) == "uv"


def test_detect_installer_recognises_a_source_checkout(tmp_path: Path) -> None:
    package = tmp_path / "repo" / "core" / "insidia"
    package.mkdir(parents=True)
    (tmp_path / "repo" / "core" / "pyproject.toml").write_text("")
    (tmp_path / "repo" / ".git").mkdir()
    assert detect_installer(tmp_path, package) == "checkout"


def test_install_command_uses_the_verified_wheel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: f"/bin/{name}")
    wheel = _wheel(tmp_path)
    assert install_command("uv", wheel) == ["/bin/uv", "tool", "install", "--force", str(wheel)]
    assert install_command("pipx", wheel) == ["/bin/pipx", "install", "--force", str(wheel)]
    with pytest.raises(CliError, match="git pull"):
        install_command("checkout", wheel)


def test_install_command_needs_the_installer_on_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: None)
    with pytest.raises(CliError, match="uv is not on PATH"):
        install_command("uv", _wheel(tmp_path))


def test_check_reports_a_newer_release_without_installing() -> None:
    runner = _Runner()

    def fetch(url: str) -> bytes:
        raise AssertionError(url)

    newer = _bump(__version__)
    document, text = upgrade.upgrade(
        check=True,
        force=False,
        latest=lambda: _release(newer),
        run=runner,
        fetch=fetch,
    )
    assert document["update_available"] is True
    assert document["upgraded"] is False
    assert "wheel_sha256" not in document
    assert newer in text
    assert runner.commands == []


def test_upgrade_does_nothing_when_already_latest() -> None:
    runner = _Runner()
    document, text = upgrade.upgrade(
        check=False, force=False, latest=lambda: _release(__version__), run=runner
    )
    assert document["update_available"] is False
    assert "is the latest release" in text
    assert runner.commands == []


def test_upgrade_installs_the_verified_wheel_not_a_git_tag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: f"/bin/{name}")
    runner = _Runner()
    newer = _bump(__version__)
    release, fetch = _pinned(newer)
    output = io.StringIO()
    document, text = upgrade.upgrade(
        check=False,
        force=False,
        output=output,
        latest=lambda: release,
        installer=lambda: "uv",
        run=runner,
        platform="linux",
        fetch=fetch,
        cache=tmp_path,
    )
    assert document["upgraded"] is True
    assert document["installer"] == "uv"
    assert document["wheel_sha256"] == hashlib.sha256(b"wheel-bytes").hexdigest()
    assert runner.commands[0][:4] == ["/bin/uv", "tool", "install", "--force"]
    installed = runner.commands[0][-1]
    assert installed.endswith(f"insidia-{newer}-py3-none-any.whl")
    assert "git+" not in installed
    assert "@v" not in installed
    assert f"Upgraded Insidia {__version__} to {newer}" in text
    assert Path(installed).read_bytes() == b"wheel-bytes"


def test_force_reinstalls_the_current_release(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: f"/bin/{name}")
    runner = _Runner()
    release, fetch = _pinned(__version__)
    document, _ = upgrade.upgrade(
        check=False,
        force=True,
        output=io.StringIO(),
        latest=lambda: release,
        installer=lambda: "pipx",
        run=runner,
        platform="linux",
        fetch=fetch,
        cache=tmp_path,
    )
    assert document["upgraded"] is True
    assert runner.commands[0][:3] == ["/bin/pipx", "install", "--force"]
    assert "git+" not in runner.commands[0][-1]


def test_a_failed_install_names_the_command_to_retry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: f"/bin/{name}")
    release, fetch = _pinned(_bump(__version__))
    with pytest.raises(CliError, match="uv exited with code 1. Retry by hand"):
        upgrade.upgrade(
            check=False,
            force=False,
            output=io.StringIO(),
            latest=lambda: release,
            installer=lambda: "uv",
            run=_Runner(code=1),
            platform="linux",
            fetch=fetch,
            cache=tmp_path,
        )


def test_windows_prints_the_command_instead_of_replacing_itself(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: f"/bin/{name}")
    runner = _Runner()
    newer = _bump(__version__)
    release, fetch = _pinned(newer)
    document, text = upgrade.upgrade(
        check=False,
        force=False,
        latest=lambda: release,
        installer=lambda: "uv",
        run=runner,
        platform="win32",
        fetch=fetch,
        cache=tmp_path,
    )
    assert runner.commands == []
    assert document["upgraded"] is False
    assert str(document["command"]).startswith("/bin/uv tool install --force ")
    assert "git+" not in str(document["command"])
    assert str(document["command"]) in text
    assert list(tmp_path.glob("*.whl"))


def test_pip_force_reinstalls(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(upgrade.importlib.util, "find_spec", lambda name: object())
    wheel = _wheel(tmp_path)
    assert "--force-reinstall" in install_command("pip", wheel, force=True)
    assert "--force-reinstall" not in install_command("pip", wheel)


def test_upgrade_refuses_a_movable_git_tag(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: "/bin/uv")
    runner = _Runner()
    release = Release(
        tag="v9.0.0",
        version="9.0.0",
        url="https://example.test/v9.0.0",
        wheel_url="git+https://github.com/Rushi-Balapure/Insidia-Labs-Argus@v9.0.0#subdirectory=core",
    )
    with pytest.raises(CliError, match="tag can be moved"):
        upgrade.upgrade(
            check=False,
            force=False,
            latest=lambda: release,
            installer=lambda: "uv",
            run=runner,
            platform="linux",
            fetch=lambda url: b"",
            cache=tmp_path,
        )
    assert runner.commands == []


def test_upgrade_refuses_an_unpinned_release(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: "/bin/uv")
    release = Release(
        tag="v9.0.0",
        version="9.0.0",
        url="https://example.test/v9.0.0",
        wheel_url="https://example.test/insidia-9.0.0-py3-none-any.whl",
    )
    with pytest.raises(CliError, match="no pinned wheel SHA-256"):
        upgrade.upgrade(
            check=False,
            force=False,
            latest=lambda: release,
            installer=lambda: "uv",
            run=_Runner(),
            platform="linux",
            fetch=lambda url: b"bytes",
            cache=tmp_path,
        )


def test_upgrade_refuses_a_wheel_whose_hash_does_not_match(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: "/bin/uv")
    runner = _Runner()
    release, fetch = _pinned("9.0.0", b"legitimate")

    def tampered(url: str) -> bytes:
        if url.endswith(".whl"):
            return b"tampered"
        return fetch(url)

    with pytest.raises(CliError, match="failed SHA-256 verification"):
        upgrade.upgrade(
            check=False,
            force=False,
            latest=lambda: release,
            installer=lambda: "uv",
            run=runner,
            platform="linux",
            fetch=tampered,
            cache=tmp_path,
        )
    assert runner.commands == []
    assert list(tmp_path.glob("*.whl")) == []


def test_upgrade_refuses_when_the_checksum_file_disagrees(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: "/bin/uv")
    release, fetch = _pinned("9.0.0")

    def disagree(url: str) -> bytes:
        if url.endswith("/SHA256SUMS"):
            name = release.wheel_url.rsplit("/", 1)[-1]
            return f"{'ab' * 32}  {name}\n".encode()
        return fetch(url)

    with pytest.raises(CliError, match="does not match SHA256SUMS"):
        upgrade.upgrade(
            check=False,
            force=False,
            latest=lambda: release,
            installer=lambda: "uv",
            run=_Runner(),
            platform="linux",
            fetch=disagree,
            cache=tmp_path,
        )


def test_upgrade_refuses_a_branch_name_as_the_commit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: "/bin/uv")
    release, fetch = _pinned("9.0.0")
    moved = Release(
        tag=release.tag,
        version=release.version,
        url=release.url,
        wheel_url=release.wheel_url,
        sha256=release.sha256,
        sums_url=release.sums_url,
        commit="main",
    )
    with pytest.raises(CliError, match="not an immutable commit SHA"):
        upgrade.upgrade(
            check=False,
            force=False,
            latest=lambda: moved,
            installer=lambda: "uv",
            run=_Runner(),
            platform="linux",
            fetch=fetch,
            cache=tmp_path,
        )


def test_release_document_pins_the_wheel_digest() -> None:
    digest = "ab" * 32
    document = {
        "tag_name": "v1.2.3",
        "html_url": "https://github.com/Rushi-Balapure/Insidia-Labs-Argus/releases/tag/v1.2.3",
        "target_commitish": "main",
        "assets": [
            {
                "name": "insidia-1.2.3-py3-none-any.whl",
                "browser_download_url": (
                    "https://github.com/Rushi-Balapure/Insidia-Labs-Argus/releases/download/"
                    "v1.2.3/insidia-1.2.3-py3-none-any.whl"
                ),
                "digest": f"sha256:{digest}",
            },
            {
                "name": "insidia-1.2.3-py3-none-any.whl.bundle",
                "browser_download_url": "https://example.test/bundle",
            },
            {
                "name": "SHA256SUMS",
                "browser_download_url": "https://example.test/SHA256SUMS",
            },
        ],
    }
    release = release_from_document(document)
    assert release.version == "1.2.3"
    assert release.sha256 == digest
    assert release.commit == ""
    assert release.sums_url.endswith("SHA256SUMS")
    assert release.wheel_url.endswith(".whl")
    pinned = release_from_document({**document, "target_commitish": "ab" * 20})
    assert pinned.commit == "ab" * 20
    with pytest.raises(CliError, match="more than one wheel"):
        release_from_document(
            {
                **document,
                "assets": [
                    *document["assets"],
                    {
                        "name": "other-1.2.3-py3-none-any.whl",
                        "browser_download_url": "https://example.test/other.whl",
                    },
                ],
            }
        )


def test_pin_from_sums_rejects_a_conflict() -> None:
    text = "ab" * 32 + "  insidia-1.0.0-py3-none-any.whl\n"
    text += "cd" * 32 + "  insidia-1.0.0-py3-none-any.whl\n"
    with pytest.raises(CliError, match="conflicting"):
        pin_from_sums(text, "insidia-1.0.0-py3-none-any.whl")
    with pytest.raises(CliError, match="no pin"):
        pin_from_sums("aa" * 32 + "  other.whl\n", "insidia-1.0.0-py3-none-any.whl")


def test_fetch_latest_reads_the_wheel_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "tag_name": "v9.9.9",
        "target_commitish": "v9.9.9",
        "assets": [
            {
                "name": "insidia-9.9.9-py3-none-any.whl",
                "browser_download_url": "https://example.test/insidia-9.9.9-py3-none-any.whl",
                "digest": "sha256:" + "cd" * 32,
            }
        ],
    }

    class Response:
        def read(self) -> bytes:
            return json.dumps(payload).encode()

        def __enter__(self) -> object:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr(upgrade.urllib.request, "urlopen", lambda *args, **kwargs: Response())
    release = fetch_latest()
    assert release.sha256 == "cd" * 32
    assert release.commit == ""
    assert release.tag == "v9.9.9"


def test_read_url_requires_https() -> None:
    with pytest.raises(CliError, match="https"):
        upgrade._read_url("http://example.test/insidia.whl")


def test_upgrade_cache_honours_the_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("INSIDIA_UPGRADE_CACHE", str(tmp_path))
    assert upgrade_cache() == tmp_path
    monkeypatch.delenv("INSIDIA_UPGRADE_CACHE")
    assert upgrade_cache() == Path.home() / ".local" / "share" / "insidia" / "upgrade"


def test_cli_upgrade_check_prints_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "insidia.cli.upgrade",
        lambda check, force: upgrade.upgrade(
            check=check, force=force, latest=lambda: _release(__version__)
        ),
    )
    assert main(["upgrade", "--check", "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document == {
        "current": __version__,
        "latest": __version__,
        "update_available": False,
        "release": f"https://example.test/v{__version__}",
        "upgraded": False,
    }


def test_cli_upgrade_reports_a_github_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def offline() -> Release:
        raise CliError("could not check GitHub for the latest release: offline")

    monkeypatch.setattr(
        "insidia.cli.upgrade",
        lambda check, force: upgrade.upgrade(check=check, force=force, latest=offline),
    )
    assert main(["upgrade", "--json"]) == 2
    assert "offline" in json.loads(capsys.readouterr().out)["error"]
