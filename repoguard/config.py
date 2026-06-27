from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


DEFAULT_OPENAI_MODEL = "gpt-5.5"
DEFAULT_REASONING_EFFORT = "medium"
DEFAULT_OPENAI_TIMEOUT_SECONDS = 120


@dataclass(frozen=True)
class OpenAIConfig:
    api_key: str
    model: str = DEFAULT_OPENAI_MODEL
    reasoning_effort: str = DEFAULT_REASONING_EFFORT
    timeout_seconds: int = DEFAULT_OPENAI_TIMEOUT_SECONDS


class ConfigurationError(RuntimeError):
    pass


def load_dotenv(start: Path | None = None) -> None:
    env_path = _find_dotenv(start or Path.cwd())
    if env_path is None:
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def openai_config() -> OpenAIConfig:
    load_dotenv()
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise ConfigurationError(
            "OPENAI_API_KEY is required for `repoguard fix`. "
            "Create a .env from .env.example or export the variable."
        )
    return OpenAIConfig(
        api_key=api_key,
        model=os.environ.get("OPENAI_MODEL", DEFAULT_OPENAI_MODEL).strip() or DEFAULT_OPENAI_MODEL,
        reasoning_effort=os.environ.get("OPENAI_REASONING_EFFORT", DEFAULT_REASONING_EFFORT).strip()
        or DEFAULT_REASONING_EFFORT,
        timeout_seconds=_int_env("OPENAI_TIMEOUT_SECONDS", DEFAULT_OPENAI_TIMEOUT_SECONDS),
    )


def codegraph_enabled() -> bool:
    load_dotenv()
    return os.environ.get("REPOGUARD_DISABLE_CODEGRAPH", "0").strip() not in {"1", "true", "TRUE"}


def _find_dotenv(start: Path) -> Path | None:
    current = start.resolve()
    if current.is_file():
        current = current.parent
    for path in (current, *current.parents):
        env_path = path / ".env"
        if env_path.exists():
            return env_path
    return None


def _int_env(name: str, default: int) -> int:
    value = os.environ.get(name, "")
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default
