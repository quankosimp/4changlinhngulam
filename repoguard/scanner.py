from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable

from repoguard.models import Finding
from repoguard.rules import dead_code_rules, malware_rules, security_rules
from repoguard.rules.common import FileContext, RepoScanContext


EXCLUDE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    "dist",
    "build",
    "benchmark_reports",
}


def scan(path: str, include_dead_code: bool | None = None) -> list[Finding]:
    root = Path(path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Scan target does not exist: {path}")

    if include_dead_code is None:
        include_dead_code = _default_include_dead_code(root)

    files = _parse_files(root)
    repo = _build_repo_context(root, files)
    findings: list[Finding] = []

    for file in files:
        findings.extend(malware_rules.detect_file(file))
        findings.extend(security_rules.detect_file(file))

    if include_dead_code and root.is_dir():
        findings.extend(dead_code_rules.detect_repo(repo))

    return _dedupe(findings)


def _parse_files(root: Path) -> list[FileContext]:
    py_files = list(_iter_python_files(root)) if root.is_dir() else (
        [root] if root.suffix == ".py" else []
    )
    files: list[FileContext] = []
    for py_file in py_files:
        source = _read_text(py_file)
        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue
        rel_path = str(py_file.relative_to(root)) if root.is_dir() else py_file.name
        files.append(FileContext(root=root, abs_path=py_file, rel_path=rel_path, source=source, tree=tree))
    return files


def _iter_python_files(root: Path) -> Iterable[Path]:
    for file in root.rglob("*.py"):
        if any(part in EXCLUDE_DIRS for part in file.parts):
            continue
        if file.is_file():
            yield file


def _build_repo_context(root: Path, files: list[FileContext]) -> RepoScanContext:
    name_refs: dict[str, list[str]] = {}
    attr_refs: dict[str, list[str]] = {}
    defined: set[tuple[str, str]] = set()

    for file in files:
        for node in ast.walk(file.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                defined.add((file.rel_path, node.name))
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                name_refs.setdefault(node.id, []).append(file.rel_path)
            if isinstance(node, ast.Attribute):
                attr_refs.setdefault(node.attr, []).append(file.rel_path)

    for _, name in defined:
        refs = name_refs.get(name)
        if refs:
            name_refs[name] = refs

    return RepoScanContext(root=root, files=files, name_refs=name_refs, attr_refs=attr_refs)


def _read_text(file: Path) -> str:
    try:
        return file.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return file.read_text(encoding="utf-8", errors="replace")


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    out: list[Finding] = []
    for item in findings:
        key = (item.rule_id, item.file, item.line, item.target_region.start_line, item.target_region.end_line)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _default_include_dead_code(root: Path) -> bool:
    if root.is_file():
        return False
    marker_names = {"pyproject.toml", "setup.py", "setup.cfg"}
    if any((root / name).exists() for name in marker_names):
        return True
    return "dead_code" in root.parts or root.name == "dead_code"
