from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


class CodeGraphUnavailable(RuntimeError):
    pass


class CodeGraphClient:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()

    def check_available(self) -> dict:
        binary = shutil.which("codegraph")
        if not binary:
            raise CodeGraphUnavailable("codegraph CLI is not installed or not in PATH.")
        status = self.status()
        return {"binary": binary, "repo_path": str(self.repo_path), "status": status}

    def status(self) -> dict:
        return self._run_capture(["status"])

    def init_index(self) -> dict:
        return self._run_capture(["init"])

    def files(self) -> list[dict]:
        return self._run_json(["files", "--json"])

    def query(self, query: str) -> Any:
        return self._run_json(["query", query, "--json"])

    def get_symbols(self) -> Any:
        return self._run_json(["query", "*", "--json"])

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

    def _run_capture(self, args: list[str]) -> dict:
        result = self._run(args)
        payload: Any
        try:
            payload = json.loads(result.stdout) if result.stdout.strip() else {}
        except json.JSONDecodeError:
            payload = {"stdout": result.stdout.strip()}
        return {
            "command": ["codegraph", *args],
            "returncode": result.returncode,
            "payload": payload,
            "stderr": result.stderr.strip(),
        }

    def _run_json(self, args: list[str]) -> Any:
        result = self._run(args)
        if not result.stdout.strip():
            return []
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise CodeGraphUnavailable(f"CodeGraph returned non-JSON output: {result.stdout[:200]}") from exc

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        if not shutil.which("codegraph"):
            raise CodeGraphUnavailable("codegraph CLI is not installed or not in PATH.")
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
        return result
