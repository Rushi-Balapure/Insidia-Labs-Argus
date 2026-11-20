"""Live containers stay on an internal network, or the harness does not start them."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

from benchmark.harness import live
from benchmark.harness.egress_guard import EgressViolation
from benchmark.harness.sandbox import SandboxOpen

_CRAPI_SERVICES = {
    "crapi-identity",
    "crapi-community",
    "crapi-workshop",
    "crapi-chatbot",
    "crapi-web",
    "postgresdb",
    "mongodb",
    "chromadb",
    "mailhog",
    "api.mypremiumdealership.com",
}


@pytest.fixture(autouse=True)
def _reset_live() -> object:
    saved = (
        live._PROJECT_ID,
        live._READY,
        live._COMPOSE,
        list(live._STARTED),
        dict(live._HOST_PORT),
    )
    live._PROJECT_ID = "insidia-bench-ab12cd34"
    live._READY = False
    live._COMPOSE = None
    live._STARTED.clear()
    live._HOST_PORT.clear()
    yield
    live._PROJECT_ID = saved[0]
    live._READY = saved[1]
    live._COMPOSE = saved[2]
    live._STARTED[:] = saved[3]
    live._HOST_PORT.clear()
    live._HOST_PORT.update(saved[4])


def _fake_docker(
    monkeypatch: pytest.MonkeyPatch,
    *,
    internal: str = "true",
    egress: tuple[str, ...] = ("1", "1"),
    probe_stdout: str | None = None,
    host_port: str = "23456",
) -> list[list[str]]:
    calls: list[list[str]] = []
    codes = iter(egress)

    def fake(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(list(argv))
        if argv[1:3] == ["network", "inspect"]:
            fmt = argv[argv.index("-f") + 1]
            if "Internal" in fmt:
                if internal == "missing":
                    return subprocess.CompletedProcess(argv, 1, "", "missing")
                return subprocess.CompletedProcess(argv, 0, f"{internal}\n", "")
            return subprocess.CompletedProcess(argv, 1, "", "missing")
        if "insidia-egress:" in " ".join(argv):
            if probe_stdout is not None:
                return subprocess.CompletedProcess(argv, 0, probe_stdout, "")
            return subprocess.CompletedProcess(argv, 0, f"insidia-egress:{next(codes)}\n", "")
        if argv[1] == "port":
            return subprocess.CompletedProcess(argv, 0, f"127.0.0.1:{host_port}\n", "")
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(argv, 1, "", "missing")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake)
    monkeypatch.setattr(live, "_wait_http", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(live, "_wait_serves", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(live, "_wait_running", lambda *_args, **_kwargs: None)
    return calls


def _at(calls: list[list[str]], pred: Callable[[list[str]], bool]) -> int:
    for index, command in enumerate(calls):
        if pred(command):
            return index
    raise AssertionError(calls)


def test_crapi_override_drops_ports_and_joins_the_sandbox() -> None:
    class Loader(yaml.SafeLoader):
        pass

    def construct(loader: yaml.SafeLoader, suffix: str, node: yaml.Node) -> object:
        del suffix
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node)
        return loader.construct_scalar(node)

    Loader.add_multi_constructor("!", construct)
    loaded = yaml.load(live._override_file().read_text(), Loader)
    assert isinstance(loaded, dict)
    networks = loaded["networks"]
    assert isinstance(networks, dict)
    sandbox = networks["sandbox"]
    assert sandbox["external"] is True
    assert sandbox["name"] == "${INSIDIA_SANDBOX_NETWORK:?must be set}"
    services = loaded["services"]
    assert isinstance(services, dict)
    assert set(services) == _CRAPI_SERVICES
    for name, service in services.items():
        assert isinstance(service, dict)
        assert service["networks"] == ["sandbox"], name
        assert service["ports"] == [], name
        assert str(service["container_name"]).startswith("${INSIDIA_BENCH_PROJECT:?must be set}-")
        labels = service["labels"]
        assert labels["insidia.benchmark"] == "1"
        assert labels["insidia.benchmark.project"] == "${INSIDIA_BENCH_PROJECT:?must be set}"


def test_open_sandbox_blocks_before_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake)

    def boom(_document: dict[str, object]) -> None:
        raise SandboxOpen("sandbox network is not internal")

    monkeypatch.setattr(live, "assert_closed", boom)
    with pytest.raises(SandboxOpen):
        live._ensure_run(live._JUICE)
    assert calls == []


def test_egress_blocks_before_the_target_starts(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_docker(monkeypatch, egress=("0", "1"))
    with pytest.raises(EgressViolation):
        live._ensure_run(live._JUICE)
    assert not any(live._JUICE_IMAGE in command for command in calls)


def test_non_internal_network_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_docker(monkeypatch, internal="false")
    with pytest.raises(SandboxOpen):
        live._ensure_run(live._JUICE)
    assert not any(live._JUICE_IMAGE in command for command in calls)
    assert not any("insidia-egress:" in " ".join(command) for command in calls)


def test_failed_probe_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_docker(monkeypatch, probe_stdout="docker: error\n")
    with pytest.raises(RuntimeError, match="egress probe"):
        live._ensure_run(live._JUICE)
    assert not any(live._JUICE_IMAGE in command for command in calls)


def test_run_container_is_internal_and_the_proxy_is_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _fake_docker(monkeypatch)
    project = live._PROJECT_ID
    assert live._ensure_run(live._JUICE) == 23456
    image = live._probe_image()
    assert calls.count(
        [
            "docker",
            "network",
            "create",
            "--internal",
            "--label",
            "insidia.benchmark=1",
            "--label",
            f"insidia.benchmark.project={project}",
            project,
        ]
    ) == 1
    assert [
        "docker",
        "network",
        "create",
        "--label",
        "insidia.benchmark=1",
        "--label",
        f"insidia.benchmark.project={project}",
        f"{project}-publish",
    ] in calls
    assert [
        "docker",
        "run",
        "--rm",
        "--network",
        project,
        "--label",
        "insidia.benchmark=1",
        "--label",
        f"insidia.benchmark.project={project}",
        image,
        "sh",
        "-c",
        live._IP_PROBE,
    ] in calls
    assert [
        "docker",
        "run",
        "--rm",
        "--network",
        project,
        "--label",
        "insidia.benchmark=1",
        "--label",
        f"insidia.benchmark.project={project}",
        image,
        "sh",
        "-c",
        live._DNS_PROBE,
    ] in calls
    target = [
        "docker",
        "run",
        "-d",
        "--name",
        f"{project}-insidia-juice",
        "--network",
        project,
        "--network-alias",
        "insidia-juice",
        "--label",
        "insidia.benchmark=1",
        "--label",
        f"insidia.benchmark.project={project}",
        live._JUICE_IMAGE,
    ]
    proxy = [
        "docker",
        "run",
        "-d",
        "--name",
        f"{project}-proxy-3000",
        "--network",
        f"{project}-publish",
        "--label",
        "insidia.benchmark=1",
        "--label",
        f"insidia.benchmark.project={project}",
        "-p",
        "127.0.0.1::3000",
        "--entrypoint",
        "python",
        live._VAMPI_IMAGE,
        "-c",
        live._PROXY_PROGRAM,
        "3000",
        "insidia-juice",
        "3000",
    ]
    assert target in calls
    assert "-p" not in target
    assert proxy in calls
    assert [
        "docker",
        "network",
        "connect",
        project,
        f"{project}-proxy-3000",
    ] in calls
    assert _at(calls, lambda command: command[2:4] == ["create", "--internal"]) < _at(
        calls, lambda command: "insidia-egress:" in " ".join(command)
    )
    assert _at(calls, lambda command: "insidia-egress:" in " ".join(command)) < calls.index(target)
    assert calls.index(target) < calls.index(proxy)
    again = len(calls)
    assert live._ensure_run(live._JUICE) == 23456
    assert len(calls) == again


def test_dvga_sidecar_shares_the_sandbox_netns(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_docker(monkeypatch)
    project = live._PROJECT_ID
    live._ensure_run(live._DVGA)
    target = next(
        command
        for command in calls
        if live._DVGA_IMAGE in command and "--entrypoint" not in command
    )
    assert target[target.index("--network") + 1] == project
    assert "-p" not in target
    assert "WEB_HOST=0.0.0.0" in target
    sidecar = next(command for command in calls if f"container:{project}-insidia-dvga" in command)
    assert "-p" not in sidecar
    assert sidecar[sidecar.index("--network") + 1] == f"container:{project}-insidia-dvga"


def test_compose_uses_its_own_project_and_does_not_stop_a_foreign_stack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _fake_docker(monkeypatch)
    project = live._PROJECT_ID
    assert live._ensure_compose(live._CRAPI) == 23456
    compose = [command for command in calls if len(command) > 1 and command[1] == "compose"]
    assert compose
    override = str(live._override_file())
    base = str(live._compose_file())
    for command in compose:
        assert "down" not in command
        assert command[command.index("-p") + 1] == project
        assert base in command
        assert override in command
    assert not any("crapi-web" == command[-1] and command[1] == "rm" for command in calls)
    marker = next(
        command
        for command in calls
        if "--network-alias" in command and "insidia-marker" in command
    )
    assert marker[marker.index("--network") + 1] == project
    assert "-p" not in marker


def test_compose_refuses_a_foreign_project(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(RuntimeError, match="refusing"):
        live._compose([Path("/tmp/docker-compose.yml")], "crapi", ["down"])
    assert calls == []


def test_stop_removes_only_owned_containers(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    project = live._PROJECT_ID
    juice = f"{project}-insidia-juice"
    live._STARTED[:] = ["crapi-web", juice]
    live._COMPOSE = (live._compose_file(), live._override_file(), project)

    def fake(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(list(argv))
        if argv[1] == "inspect" and argv[-1] == "crapi-web":
            return subprocess.CompletedProcess(argv, 0, "crapi\n", "")
        if argv[1] == "inspect" or argv[1:3] == ["network", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, f"{project}\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake)
    live._stop_started()
    assert ["docker", "rm", "-f", juice] in calls
    assert ["docker", "rm", "-f", "crapi-web"] not in calls
    down = [command for command in calls if "down" in command]
    assert down == [
        [
            "docker",
            "compose",
            "-f",
            str(live._compose_file()),
            "-f",
            str(live._override_file()),
            "-p",
            project,
            "down",
        ]
    ]
    assert ["docker", "network", "rm", project, f"{project}-publish"] in calls


def test_stop_removes_networks_when_compose_dir_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    project = live._PROJECT_ID
    live._COMPOSE = (Path("/tmp/missing-crapi/docker-compose.yml"), live._override_file(), project)

    def fake(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(list(argv))
        if "down" in argv:
            missing = kwargs.get("cwd")
            raise FileNotFoundError(2, "No such file or directory", str(missing))
        return subprocess.CompletedProcess(argv, 0, f"{project}\n", "")

    monkeypatch.setattr(subprocess, "run", fake)
    live._stop_started()
    assert ["docker", "network", "rm", project, f"{project}-publish"] in calls


def test_stop_does_not_down_a_foreign_project(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    live._COMPOSE = (Path("/tmp/docker-compose.yml"), live._override_file(), "crapi")

    def fake(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 1, "", "missing")

    monkeypatch.setattr(subprocess, "run", fake)
    live._stop_started()
    assert not any("down" in command for command in calls)
    assert not any(len(command) > 1 and command[1] == "compose" for command in calls)


def test_chrome_runs_in_the_sandbox_container(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, '<img src="x" onerror=', "")

    monkeypatch.setattr(subprocess, "run", fake)
    check = live._CHECKS[("juiceshop", "web.xss")].check
    assert isinstance(check, live.DomCheck)
    assert live._dom(3000, check) is True
    argv = calls[0]
    image_at = argv.index(live._CHROME_IMAGE)
    assert argv[0] == "docker"
    assert "google-chrome" not in argv
    assert "-p" not in argv
    assert argv[argv.index("--network") + 1] == live._PROJECT_ID
    assert "--entrypoint" in argv[:image_at]
    assert "--no-sandbox" in argv[image_at + 1 :]
    assert "--no-sandbox" not in argv[:image_at]
    assert argv[-1].startswith(f"http://{live._JUICE.name}:{live._JUICE.container_port}/")
    assert "127.0.0.1" not in argv[-1]
