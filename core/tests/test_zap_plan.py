"""ZAP plans and Nuclei templates stay structured data."""

from pathlib import Path

import yaml
from insidia.adapters import ADAPTERS, ScopedUrl
from insidia.upstream import _nuclei_path, _nuclei_yaml, _zap_plan

_NORMAL_URL = "http://127.0.0.1:8080/call?module=web&fn=ssti&q=%7B%7B7%2A7%7D%7D"
_REPORT = "report.json"
_LEGACY_WORKSPACE = Path("/tmp/insidia-zap-workspace")
# Output of the interpolated template for _NORMAL_URL before safe_dump.
_LEGACY_NORMAL = """\
env:
  contexts:
    - name: insidia
      urls:
        - http://127.0.0.1:8080/call?module=web&fn=ssti&q=%7B%7B7%2A7%7D%7D
  parameters:
    failOnError: false
    progressToStdout: false
jobs:
  - type: requestor
    requests:
      - url: http://127.0.0.1:8080/call?module=web&fn=ssti&q=%7B%7B7%2A7%7D%7D
        method: GET
  - type: report
    parameters:
      template: traditional-json
      reportDir: {workspace}
      reportFile: report.json
"""
_HOSTILE = (
    "http://127.0.0.1:9/\n  - type: spider",
    "http://127.0.0.1:9/\njobs:\n  - type: spider\n",
    "http://127.0.0.1:9/a: b",
    "http://127.0.0.1:9/a # comment",
    'http://127.0.0.1:9/say "hi"',
    "http://127.0.0.1:9/it's",
    "http://127.0.0.1:9/{foo}",
    "http://127.0.0.1:9/[bar]",
    "{type: spider}",
    "[type, spider]",
    "http://127.0.0.1:9/&anchor",
    "&anchor",
    "*anchor",
    "!!python/object/apply:os.system [id]",
    "!!python/object:os.system",
    "true",
    "null",
    "1",
)


def _expected(url: str, workspace: Path, report: str = _REPORT) -> dict[str, object]:
    return {
        "env": {
            "contexts": [
                {
                    "name": "insidia",
                    "urls": [url],
                }
            ],
            "parameters": {
                "failOnError": False,
                "progressToStdout": False,
            },
        },
        "jobs": [
            {
                "type": "requestor",
                "requests": [
                    {
                        "url": url,
                        "method": "GET",
                    }
                ],
            },
            {
                "type": "report",
                "parameters": {
                    "template": "traditional-json",
                    "reportDir": str(workspace),
                    "reportFile": report,
                },
            },
        ],
    }


def test_normal_plan_matches_expected_structure(tmp_path: Path) -> None:
    loaded = yaml.safe_load(_zap_plan(_NORMAL_URL, tmp_path, _REPORT))
    assert loaded == _expected(_NORMAL_URL, tmp_path)
    assert loaded["env"]["parameters"]["failOnError"] is False
    assert loaded["env"]["parameters"]["progressToStdout"] is False
    assert isinstance(loaded["jobs"][0]["requests"][0]["url"], str)


def test_normal_plan_matches_legacy_template() -> None:
    text = _zap_plan(_NORMAL_URL, _LEGACY_WORKSPACE, _REPORT)
    legacy = _LEGACY_NORMAL.format(workspace=_LEGACY_WORKSPACE)
    assert yaml.safe_load(text) == yaml.safe_load(legacy)


def test_hostile_targets_stay_plain_strings(tmp_path: Path) -> None:
    for url in _HOSTILE:
        loaded = yaml.safe_load(_zap_plan(url, tmp_path, _REPORT))
        assert loaded == _expected(url, tmp_path)
        assert [job["type"] for job in loaded["jobs"]] == ["requestor", "report"]
        assert loaded["env"]["contexts"][0]["urls"] == [url]
        assert loaded["jobs"][0]["requests"] == [{"url": url, "method": "GET"}]
        assert isinstance(loaded["env"]["contexts"][0]["urls"][0], str)
        assert isinstance(loaded["jobs"][0]["requests"][0]["url"], str)


def test_report_paths_stay_plain_strings(tmp_path: Path) -> None:
    workspace = tmp_path / "a: b # not-a-comment\n  - type: spider"
    report = 'out: "report"\n  - type: spider'
    loaded = yaml.safe_load(_zap_plan(_NORMAL_URL, workspace, report))
    assert loaded == _expected(_NORMAL_URL, workspace, report)
    assert [job["type"] for job in loaded["jobs"]] == ["requestor", "report"]
    parameters = loaded["jobs"][1]["parameters"]
    assert parameters["reportDir"] == str(workspace)
    assert parameters["reportFile"] == report
    assert isinstance(parameters["reportDir"], str)
    assert isinstance(parameters["reportFile"], str)


def test_prepare_writes_one_request_plan(tmp_path: Path) -> None:
    adapter = next(item for item in ADAPTERS if item.engine == "zap")
    view = ScopedUrl(
        "http://127.0.0.1:8080/call",
        (("module", "web"), ("fn", "ssti"), ("q", "{{payload}}")),
    )
    invocation = adapter.prepare(adapter.probes[0], view, tmp_path)  # type: ignore[attr-defined]
    text = (tmp_path / "plan.yaml").read_text(encoding="utf-8")
    loaded = yaml.safe_load(text)
    assert loaded == _expected(_NORMAL_URL, tmp_path)
    assert "proxy" not in invocation.args
    assert "-dr" not in invocation.args
    assert loaded["jobs"][0]["requests"][0]["method"] == "GET"


_NORMAL_PATH = "/call?module=web&fn=ssti&q=%7B%7B7*7%7D%7D"
# Output of the interpolated Nuclei template for _NORMAL_PATH before safe_dump.
_LEGACY_NUCLEI = """\
id: insidia-web-ssti
info:
  name: insidia ssti
  author: insidia
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/call?module=web&fn=ssti&q=%7B%7B7*7%7D%7D"
    matchers:
      - type: word
        part: body
        words:
          - "49"
"""
_HOSTILE_PATHS = (
    '/say "hi"',
    "/a\nb",
    "/a\\b",
    "/a: b",
    "/a # comment",
    "/{{7*7}}",
    "/it's",
)


def _nuclei_expected(path: str) -> dict[str, object]:
    return {
        "id": "insidia-web-ssti",
        "info": {
            "name": "insidia ssti",
            "author": "insidia",
            "severity": "high",
        },
        "http": [
            {
                "method": "GET",
                "path": ["{{BaseURL}}" + path],
                "matchers": [
                    {
                        "type": "word",
                        "part": "body",
                        "words": ["49"],
                    }
                ],
            }
        ],
    }


def test_normal_nuclei_template_matches_legacy() -> None:
    loaded = yaml.safe_load(_nuclei_yaml(_NORMAL_PATH))
    assert loaded == yaml.safe_load(_LEGACY_NUCLEI)
    assert loaded == _nuclei_expected(_NORMAL_PATH)
    request = loaded["http"][0]["path"]
    assert request == ["{{BaseURL}}" + _NORMAL_PATH]
    assert isinstance(loaded["http"][0]["matchers"][0]["words"][0], str)


def test_hostile_nuclei_paths_stay_one_request() -> None:
    for path in _HOSTILE_PATHS:
        loaded = yaml.safe_load(_nuclei_yaml(path))
        assert loaded == _nuclei_expected(path)
        assert loaded["http"] == _nuclei_expected(path)["http"]
        assert loaded["http"][0]["path"] == ["{{BaseURL}}" + path]
        assert len(loaded["http"]) == 1
        word = loaded["http"][0]["matchers"][0]["words"][0]
        assert word == "49"
        assert isinstance(word, str)


def test_nuclei_path_forwards_unquoted_target_text() -> None:
    view = ScopedUrl(
        'http://127.0.0.1:9/say "hi"',
        (
            ('k"\n\\:#\'', 'v"\n\\: # {{7*7}} \''),
            ("q", "{{payload}}"),
        ),
    )
    path = _nuclei_path(view)
    assert path.startswith('/say "hi"?')
    assert "k%22%0A%5C%3A%23%27=" in path
    assert 'v"\n\\: # {{7*7}} \'' in path
    assert "q=%7B%7B7*7%7D%7D" in path
    assert "{{payload}}" not in path
    bare = _nuclei_path(ScopedUrl("http://127.0.0.1:9/a\nb #x"))
    assert bare == "/ab "
    assert _nuclei_path(ScopedUrl("http://127.0.0.1:9/a%23b")) == "/a%23b"
