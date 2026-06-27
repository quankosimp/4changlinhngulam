from __future__ import annotations

import ast
from pathlib import Path

from repoguard.codegraph_client import CodeGraphClient, CodeGraphUnavailable
from repoguard.models import Finding


def enrich_findings(repo_path: str, findings: list[Finding]) -> list[Finding]:
    client = CodeGraphClient(repo_path)
    enriched = []
    for finding in findings:
        symbol = _guess_symbol(Path(repo_path), finding.file, finding.line)
        try:
            context = {
                "provider": "codegraph",
                "confidence": 1.0,
                "symbol": symbol,
                "callers": client.get_callers(symbol) if symbol else [],
                "callees": client.get_callees(symbol) if symbol else [],
                "importers": client.get_importers(Path(finding.file).stem),
                "references": client.get_symbol_references(symbol) if symbol else [],
                "file_impact": client.get_file_impact(finding.file),
                "fallback": False,
            }
        except CodeGraphUnavailable as exc:
            context = _fallback_context(Path(repo_path), finding, symbol, str(exc))
        enriched.append(finding.with_codegraph_context(context))
    return enriched


def enrich_finding(finding: Finding, repo_path: str = ".") -> dict:
    enriched = enrich_findings(repo_path, [finding])
    return enriched[0].codegraph_context if enriched else {}


def _guess_symbol(repo: Path, file: str, line: int) -> str:
    path = repo / file
    if not path.exists() or path.suffix != ".py":
        return ""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return ""

    best: tuple[int, str] | None = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        start = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", start)
        if start <= line <= end:
            size = end - start
            if best is None or size < best[0]:
                best = (size, node.name)
    return best[1] if best else Path(file).stem


def _fallback_context(repo: Path, finding: Finding, symbol: str, reason: str) -> dict:
    references = []
    importers = []
    module_name = Path(finding.file).stem
    for file in repo.rglob("*.py"):
        if any(part in {".git", ".venv", "venv", "__pycache__"} for part in file.parts):
            continue
        try:
            text = file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = file.read_text(encoding="utf-8", errors="replace")
        rel = str(file.relative_to(repo))
        if symbol:
            if symbol in text:
                references.append({"file": rel, "symbol": symbol})
        if f"import {module_name}" in text or f"from {module_name}" in text:
            importers.append({"file": rel})
    return {
        "provider": "fallback",
        "confidence": 0.45,
        "symbol": symbol,
        "callers": [],
        "callees": [],
        "references": references,
        "importers": importers,
        "file_impact": {"file": finding.file, "impact": []},
        "fallback": True,
        "fallback_reason": reason,
    }
