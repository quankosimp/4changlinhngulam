from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from repoguard.config import ConfigurationError, openai_config
from repoguard.models import Finding, PatchProposal


OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"


PATCH_PROPOSAL_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "finding_id": {"type": "string"},
        "action": {
            "type": "string",
            "enum": ["remove", "quarantine", "safe_replace", "refactor", "needs_review"],
        },
        "file": {"type": "string"},
        "start_line": {"type": "integer", "minimum": 1},
        "end_line": {"type": "integer", "minimum": 1},
        "replacement": {"type": "string"},
        "rationale": {"type": "string"},
        "expected_risk_reduction": {"type": "string"},
    },
    "required": [
        "finding_id",
        "action",
        "file",
        "start_line",
        "end_line",
        "replacement",
        "rationale",
        "expected_risk_reduction",
    ],
}


class AgentConfigurationError(ConfigurationError):
    """Raised when the remediation agent cannot be configured."""


class AgentResponseError(RuntimeError):
    pass


def propose_patch(repo_path: str, finding: Finding) -> PatchProposal:
    try:
        config = openai_config()
    except ConfigurationError as exc:
        raise AgentConfigurationError(str(exc)) from exc

    prompt = _build_prompt(Path(repo_path).resolve(), finding)
    body = {
        "model": config.model,
        "input": [
            {
                "role": "system",
                "content": [
                    {
                        "type": "input_text",
                        "text": (
                            "You are RepoGuard Remediation Agent. Return only a structured "
                            "PatchProposal. Propose the smallest safe patch. Do not add network "
                            "calls, eval, exec, obfuscation, or edits outside the target region. "
                            "If unsure, choose needs_review."
                        ),
                    }
                ],
            },
            {"role": "user", "content": [{"type": "input_text", "text": prompt}]},
        ],
        "text": {
            "format": {
                "type": "json_schema",
                "name": "patch_proposal",
                "schema": PATCH_PROPOSAL_SCHEMA,
                "strict": True,
            }
        },
        "reasoning": {"effort": config.reasoning_effort},
    }
    response = _post_json(config.api_key, body, timeout=config.timeout_seconds)
    data = _extract_json(response)
    return PatchProposal.from_dict(data)


def _build_prompt(repo: Path, finding: Finding) -> str:
    target = finding.target_region
    file_path = (repo / target.file).resolve()
    code_slice = _read_region(file_path, target.start_line, target.end_line)
    payload = {
        "finding": finding.to_dict(),
        "code_slice": code_slice,
        "constraints": [
            "Patch only target_region unless action is needs_review.",
            "Do not add eval/exec or network calls.",
            "Do not hide behavior with obfuscation.",
            "Prefer quarantine for malware/security sinks.",
            "Prefer remove for unused dead-code symbols with no callers/references.",
        ],
    }
    return json.dumps(payload, indent=2)


def _read_region(path: Path, start_line: int, end_line: int) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    selected = lines[start_line - 1 : end_line]
    return "\n".join(f"{start_line + offset}: {line}" for offset, line in enumerate(selected))


def _post_json(api_key: str, body: dict[str, Any], timeout: int) -> dict[str, Any]:
    request = urllib.request.Request(
        OPENAI_RESPONSES_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise AgentResponseError(f"OpenAI API error {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise AgentResponseError(f"OpenAI API request failed: {exc}") from exc


def _extract_json(response: dict[str, Any]) -> dict[str, Any]:
    if isinstance(response.get("output_text"), str):
        return json.loads(response["output_text"])

    for item in response.get("output", []):
        for content in item.get("content", []):
            if content.get("type") in {"output_text", "text"} and isinstance(content.get("text"), str):
                return json.loads(content["text"])
            if isinstance(content.get("json"), dict):
                return content["json"]
    raise AgentResponseError("Could not extract structured PatchProposal from OpenAI response.")
