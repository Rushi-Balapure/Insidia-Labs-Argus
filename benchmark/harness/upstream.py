"""White-box cells scan the cloned source with Argus. The result is the scan."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from benchmark.harness.score import Finding
from benchmark.matrix.registry import Cell

_ROOT = Path(
    os.environ.get(
        "INSIDIA_LOCAL_TARGETS",
        str(Path(__file__).resolve().parents[3] / "local-targets"),
    )
)

# (clone directory, relative path, sink text)
_SINKS: dict[tuple[str, str], tuple[tuple[str, str, str], ...]] = {
    ("juiceshop", "web.sqli"): (
        ("juice-shop", "routes/login.ts", "SELECT * FROM Users WHERE email = '${req.body.email"),
    ),
    ("juiceshop", "web.xss"): (("juice-shop", "routes/search.ts", "LIKE '%${criteria}%'"),),
    ("juiceshop", "api.bfla"): (("juice-shop", "server.ts", "verify.registerAdminChallenge()"),),
    ("juiceshop", "api.bola_idor"): (
        ("juice-shop", "routes/basket.ts", "user?.bid != parseInt(id, 10)"),
    ),
    ("juiceshop", "auth.jwt_oauth_session"): (
        ("juice-shop", "lib/insecurity.ts", "expressJwt(({ secret: publicKey })"),
    ),
    ("vampi", "web.sqli"): (
        ("VAmPI", "models/user_model.py", "SELECT * FROM users WHERE username = '{username}'"),
    ),
    ("dvga", "web.sqli"): (("dvga", "core/views.py", "title = '%s' or content = '%s'"),),
    ("dvga", "web.cmdi"): (
        ("dvga", "core/helpers.py", "os.popen(cmd)"),
        ("dvga", "core/views.py", "def resolve_system_debug"),
    ),
    ("dvga", "web.ssrf"): (("dvga", "core/views.py", "curl --insecure"),),
    ("dvga", "api.bola_idor"): (("dvga", "core/views.py", "filter_by(id=id, burn=False)"),),
    ("dvga", "api.bfla"): (("dvga", "core/views.py", "def resolve_delete_all_pastes"),),
    ("dvga", "auth.jwt_oauth_session"): (("dvga", "core/helpers.py", '"verify_signature":False'),),
    ("crapi", "web.ssrf"): (
        ("crAPI", "services/workshop/crapi/merchant/views.py", 'request_data["mechanic_api"]'),
    ),
    ("crapi", "api.bola_idor"): (
        ("crAPI", "services/workshop/crapi/mechanic/views.py", 'request.GET["report_id"]'),
    ),
    ("crapi", "api.bfla"): (
        (
            "crAPI",
            "services/community/api/router/routes.go",
            "/community/api/v2/community/posts/recent",
        ),
        ("crAPI", "services/community/api/models/user.go", 'json:"vehicleid"'),
    ),
    ("crapi", "api.mass_assignment"): (
        (
            "crAPI",
            "services/identity/src/main/java/com/crapi/model/VideoForm.java",
            "conversion_params",
        ),
    ),
    ("crapi", "auth.jwt_oauth_session"): (
        (
            "crAPI",
            "services/identity/src/main/java/com/crapi/config/JwtProvider.java",
            'alg.getName(), "HS256"',
        ),
    ),
    ("agentdojo", "ai.jailbreak"): (
        ("agentdojo", "src/agentdojo/default_suites/v1/workspace/user_tasks.py", "class UserTask0"),
        (
            "agentdojo",
            "src/agentdojo/default_suites/v1/workspace/user_tasks.py",
            "Who else is invited",
        ),
    ),
    ("agentdojo", "ai.tool_misuse"): (
        ("agentdojo", "src/agentdojo/default_suites/v1/workspace/user_tasks.py", "class UserTask0"),
        ("agentdojo", "src/agentdojo/default_suites/v1/tools/email_client.py", "def send_email"),
    ),
    ("agentdojo", "ai.prompt_injection_indirect"): (
        (
            "agentdojo",
            "src/agentdojo/default_suites/v1/workspace/injection_tasks.py",
            "class InjectionTask0",
        ),
        (
            "agentdojo",
            "src/agentdojo/default_suites/v1/workspace/injection_tasks.py",
            "Please email the text",
        ),
    ),
}

_SCANNED: dict[tuple[str, str], list[dict[str, object]]] = {}
_REPO_CONFIG = """\
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  plant:
    kind: repo
    path: target
"""


def material_ready(cell: Cell) -> bool:
    """Fixture cells always run. Third-party cells need the local checkouts."""
    from benchmark.matrix.plants import plant_for

    if plant_for(cell.target, cell.attack).location.startswith("benchmark/targets/insidia/"):
        return True
    return _ROOT.is_dir()


def upstream_ready(cell: Cell) -> bool:
    """White-box cells whose sink is in a cloned repo. Black and gray stay live."""
    return cell.phase == "1B" and cell.box == "white" and (cell.target, cell.attack) in _SINKS


def prove_upstream(cell: Cell) -> list[Finding]:
    from benchmark.harness.run_cell import _matched

    key = (cell.target, cell.attack)
    recorded = _SCANNED.get(key)
    if recorded is None:
        recorded = _scan_sources(cell)
        _SCANNED[key] = recorded
    return _matched(cell, recorded)


def _scan_sources(cell: Cell) -> list[dict[str, object]]:
    from benchmark.harness.run_cell import ScanError, _run_scan

    sinks = _SINKS[(cell.target, cell.attack)]
    with tempfile.TemporaryDirectory(prefix="insidia-upstream-") as name:
        root = Path(name)
        dest = root / "target"
        dest.mkdir()
        for clone, relative, _needle in sinks:
            source = _ROOT / clone / relative
            if not source.is_file():
                raise ScanError(f"{cell.cell_id} source {relative} is not available to scan")
            text = source.read_text(encoding="utf-8")
            (dest / Path(relative).name).write_text(text, encoding="utf-8")
        (root / "insidia.yaml").write_text(_REPO_CONFIG, encoding="utf-8")
        toolchain = root / "toolchain"
        toolchain.mkdir()
        previous = os.environ.get("INSIDIA_TOOLCHAIN")
        os.environ["INSIDIA_TOOLCHAIN"] = str(toolchain)
        try:
            return _run_scan(root)
        finally:
            if previous is None:
                os.environ.pop("INSIDIA_TOOLCHAIN", None)
            else:
                os.environ["INSIDIA_TOOLCHAIN"] = previous
