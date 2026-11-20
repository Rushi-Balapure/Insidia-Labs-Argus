"""Relay engine plans for garak, promptfoo, pyrit, and deepteam."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from insidia.adapters import Invocation, ProbeSpec, RelayEndpoint
from insidia.catalog import STATIC_PROMPT
from insidia.egress import current_gate
from insidia.errors import EngineFailed
from insidia.upstream_support import _program

PROMPTFOO_ENV = {
    "PROMPTFOO_DISABLE_REMOTE_GENERATION": "true",
    "PROMPTFOO_DISABLE_TELEMETRY": "1",
    "PROMPTFOO_DISABLE_SHARING": "1",
    "PROMPTFOO_DISABLE_UPDATE": "1",
}


def _relay_prepare(engine: str) -> Callable[[ProbeSpec, RelayEndpoint, Path], Invocation]:
    def prepare(spec: ProbeSpec, endpoint: RelayEndpoint, workspace: Path) -> Invocation:
        if engine == "garak":
            return _garak(endpoint, workspace)
        if engine == "promptfoo":
            return _promptfoo(endpoint, workspace)
        if engine == "pyrit":
            return _pyrit(endpoint, workspace)
        if engine == "deepteam":
            return _deepteam(endpoint, workspace)
        raise ValueError(engine)

    return prepare


def _garak(endpoint: RelayEndpoint, workspace: Path) -> Invocation:
    # Stock garak probes do not send this word. The workspace probe config does.
    (workspace / "probe.json").write_text(
        json.dumps({"test": {"Blank": {"prompts": [STATIC_PROMPT], "active": True}}}),
        encoding="utf-8",
    )
    gate = current_gate()
    proxies = None if gate is None else {"http": gate.url, "https": gate.url}
    generator = {
        "rest": {
            "RestGenerator": {
                "uri": endpoint.url,
                "method": "post",
                "headers": {
                    "Authorization": f"Bearer {endpoint.token}",
                    "Content-Type": "application/json",
                },
                "req_template_json_object": {"prompt": "$INPUT"},
                "response_json": True,
                "response_json_field": "text",
                "parallel_requests": 8,
                "request_timeout": 180,
                "proxies": proxies,
            }
        }
    }
    (workspace / "generator.json").write_text(json.dumps(generator), encoding="utf-8")
    return Invocation(
        _program("garak"),
        (
            "--target_type",
            "rest.RestGenerator",
            "--target_name",
            endpoint.url,
            "--generator_option_file",
            str(workspace / "generator.json"),
            "--probes",
            "test.Blank",
            "--probe_option_file",
            str(workspace / "probe.json"),
            "--parallel_requests",
            "8",
            "--generations",
            "1",
            "--report_prefix",
            str(workspace / "run"),
        ),
        "run.report.jsonl",
        timeout=180,
    )


def _promptfoo(endpoint: RelayEndpoint, workspace: Path) -> Invocation:
    (workspace / "prompt.txt").write_text(STATIC_PROMPT + "\n", encoding="utf-8")
    (workspace / "provider.cjs").write_text(_PROVIDER_JS, encoding="utf-8")
    config = "\n".join(
        (
            "prompts:",
            "  - file://prompt.txt",
            "providers:",
            "  - file://provider.cjs",
            "tests:",
            "  - vars: {}",
            "outputPath: report.json",
            "",
        )
    )
    (workspace / "promptfooconfig.yaml").write_text(config, encoding="utf-8")
    env = dict(PROMPTFOO_ENV)
    env["INSIDIA_RELAY_URL"] = endpoint.url
    env["INSIDIA_RELAY_TOKEN"] = endpoint.token
    if current_gate() is not None:
        env["NODE_USE_ENV_PROXY"] = "1"
    return Invocation(
        _program("promptfoo"),
        ("eval", "-c", "promptfooconfig.yaml", "--no-cache", "-o", "report.json"),
        "report.json",
        env=env,
        timeout=180,
    )


def _pyrit(endpoint: RelayEndpoint, workspace: Path) -> Invocation:
    (workspace / "single_turn.py").write_text(_PYRIT_PY, encoding="utf-8")
    return Invocation(
        _program("pyrit"),
        (str(workspace / "single_turn.py"),),
        "report.json",
        env=_script_env(endpoint),
        timeout=180,
    )


def _deepteam(endpoint: RelayEndpoint, workspace: Path) -> Invocation:
    if endpoint.model_url is None or endpoint.model is None:
        raise EngineFailed("deepteam needs an openai-compatible models.attacker")
    (workspace / "callback.py").write_text(_DEEPTEAM_PY, encoding="utf-8")
    env = _script_env(endpoint)
    env["INSIDIA_MODEL_URL"] = endpoint.model_url
    env["INSIDIA_MODEL_NAME"] = endpoint.model
    env["DEEPTEAM_TELEMETRY_OPT_OUT"] = "YES"
    env["DEEPEVAL_TELEMETRY_OPT_OUT"] = "YES"
    if endpoint.model_key:
        env["INSIDIA_MODEL_KEY"] = endpoint.model_key
    # DeepTeam writes its own attack prompts and scores them with your model.
    # A local model is slower than a hosted one, so the run gets more time.
    return Invocation(
        _program("deepteam"),
        (str(workspace / "callback.py"),),
        "report.json",
        env=env,
        timeout=900,
    )


def _script_env(endpoint: RelayEndpoint) -> dict[str, str]:
    return {
        "INSIDIA_RELAY_URL": endpoint.url,
        "INSIDIA_RELAY_TOKEN": endpoint.token,
    }


_PROVIDER_JS = """\
const http = require("http");
const { URL } = require("url");

class InsidiaRelay {
  id() {
    return "insidia-relay";
  }

  async callApi(prompt) {
    const text = typeof prompt === "string" ? prompt : prompt.prompt;
    const body = JSON.stringify({ prompt: text });
    const payload = await post(process.env.INSIDIA_RELAY_URL, body, {
      "content-type": "application/json",
      authorization: "Bearer " + process.env.INSIDIA_RELAY_TOKEN,
    });
    const parsed = JSON.parse(payload);
    return { output: parsed.text };
  }
}

function post(url, body, headers) {
  const target = new URL(url);
  const proxy =
    process.env.INSIDIA_EGRESS_PROXY ||
    process.env.HTTPS_PROXY ||
    process.env.HTTP_PROXY ||
    process.env.https_proxy ||
    process.env.http_proxy;
  const via = proxy ? new URL(proxy) : null;
  const options = via
    ? {
        hostname: via.hostname,
        port: via.port,
        method: "POST",
        path: target.href,
        headers: Object.assign({}, headers, {
          Host: target.host,
          "Content-Length": Buffer.byteLength(body),
        }),
      }
    : {
        hostname: target.hostname,
        port: target.port,
        method: "POST",
        path: target.pathname + target.search,
        headers: Object.assign({}, headers, {
          "Content-Length": Buffer.byteLength(body),
        }),
      };
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    });
    req.on("error", reject);
    req.end(body);
  });
}

module.exports = InsidiaRelay;
"""


_PYRIT_PY = """\
import asyncio
import os

_proxy = os.environ.get("INSIDIA_EGRESS_PROXY")
if _proxy:
    import httpx as _httpx

    _client = _httpx.AsyncClient

    def _trust_proxy(*args, **kwargs):
        kwargs["trust_env"] = True
        return _client(*args, **kwargs)

    _httpx.AsyncClient = _trust_proxy

from pyrit.executor.attack import PromptSendingAttack
from pyrit.prompt_target import HTTPTarget
from pyrit.setup import IN_MEMORY, initialize_pyrit_async


def _text(*, response):
    body = response.json()
    text = body["text"]
    if not isinstance(text, str):
        raise RuntimeError("relay response was not text")
    return text


async def _run() -> None:
    await initialize_pyrit_async(IN_MEMORY, load_defaults=False)
    url = os.environ["INSIDIA_RELAY_URL"]
    token = os.environ["INSIDIA_RELAY_TOKEN"]
    raw = "\\n".join(
        (
            f"POST {url} HTTP/1.1",
            "Content-Type: application/json",
            f"Authorization: Bearer {token}",
            "",
            '{"prompt": "{PROMPT}"}',
        )
    )
    # httpx waits 5 seconds by default. A local model needs longer than that.
    target = HTTPTarget(http_request=raw, callback_function=_text, use_tls=False, timeout=180)
    attack = PromptSendingAttack(objective_target=target)
    await attack.execute_async(objective="secret")


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
"""


_DEEPTEAM_PY = """\
import json
import os
import urllib.request

_proxy = os.environ.get("INSIDIA_EGRESS_PROXY")
if _proxy:
    import httpx as _httpx

    _client = _httpx.AsyncClient

    def _trust_proxy(*args, **kwargs):
        kwargs["trust_env"] = True
        return _client(*args, **kwargs)

    _httpx.AsyncClient = _trust_proxy

from deepeval.models import DeepEvalBaseLLM
from deepteam import red_team
from deepteam.attacks.single_turn import Base64
from deepteam.vulnerabilities import Bias


class AttackerModel(DeepEvalBaseLLM):
    # DeepTeam writes and scores its attacks with a model. This one is the
    # models.attacker you configured. No other service is called.
    def __init__(self):
        super().__init__(os.environ["INSIDIA_MODEL_NAME"])

    def load_model(self):
        return self

    def get_model_name(self):
        return os.environ["INSIDIA_MODEL_NAME"]

    def _ask(self, prompt):
        body = json.dumps(
            {
                "model": os.environ["INSIDIA_MODEL_NAME"],
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0,
            }
        ).encode()
        headers = {"Content-Type": "application/json"}
        key = os.environ.get("INSIDIA_MODEL_KEY")
        if key:
            headers["Authorization"] = "Bearer " + key
        request = urllib.request.Request(
            os.environ["INSIDIA_MODEL_URL"] + "/chat/completions",
            data=body,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=300) as response:
            document = json.loads(response.read().decode())
        text = document["choices"][0]["message"]["content"]
        return text if isinstance(text, str) else ""

    def generate(self, prompt, schema=None):
        if schema is None:
            return self._ask(prompt)
        text = self._ask(prompt + " Reply with one JSON object and nothing else.")
        start = text.find("{")
        end = text.rfind("}")
        return schema.model_validate_json(text[start : end + 1])

    async def a_generate(self, prompt, schema=None):
        return self.generate(prompt, schema)


async def model_callback(prompt: str) -> str:
    payload = json.dumps({"prompt": prompt}).encode()
    request = urllib.request.Request(
        os.environ["INSIDIA_RELAY_URL"],
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + os.environ["INSIDIA_RELAY_TOKEN"],
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=180) as response:
        body = json.loads(response.read().decode())
    text = body["text"]
    if not isinstance(text, str):
        raise RuntimeError("relay response was not text")
    return text


def main() -> None:
    model = AttackerModel()
    red_team(
        model_callback=model_callback,
        vulnerabilities=[Bias(types=["race"])],
        attacks=[Base64()],
        simulator_model=model,
        evaluation_model=model,
        async_mode=False,
        ignore_errors=False,
    )


if __name__ == "__main__":
    main()
"""
