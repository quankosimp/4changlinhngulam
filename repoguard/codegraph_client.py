from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


class CodeGraphUnavailable(RuntimeError):
    pass


class CodeGraphClient:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()

    def get_callers(self, symbol: str) -> list[dict]:
        return self._run_json(["callers", symbol, "--json"])

    def get_callees(self, symbol: str) -> list[dict]:
        return self._run_json(["callees", symbol, "--json"])

    def get_importers(self, module: str) -> list[dict]:
        return self._run_json(["query", f"imports:{module}", "--json"])

    def get_symbol_references(self, symbol: str) -> list[dict]:
        return self._run_json(["query", symbol, "--json"])

    def get_file_impact(self, file: str) -> dict:
        return {"file": file, "impact": self._run_json(["impact", file, "--json"])}

    def _run_json(self, args: list[str]) -> Any:
        cmd = ["codegraph", *args]
        try:
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise CodeGraphUnavailable(str(exc)) from exc

        if result.returncode != 0:
            raise CodeGraphUnavailable(result.stderr.strip() or result.stdout.strip())
        if not result.stdout.strip():
            return []
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise CodeGraphUnavailable(f"CodeGraph returned non-JSON output: {result.stdout[:200]}") from exc
