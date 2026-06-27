from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from repoguard.models import Evidence, Finding, TargetRegion


@dataclass(frozen=True)
class FileContext:
    root: Path
    abs_path: Path
    rel_path: str
    source: str
    tree: ast.AST


@dataclass(frozen=True)
class RepoScanContext:
    root: Path
    files: list[FileContext]
    name_refs: dict[str, list[str]]
    attr_refs: dict[str, list[str]]


def call_name(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    return ""


def string_constant(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def snippet(source: str, node: ast.AST) -> str:
    lines = source.splitlines()
    start = max(getattr(node, "lineno", 1) - 2, 1)
    end = min(getattr(node, "end_lineno", getattr(node, "lineno", 1)) + 1, len(lines))
    return "\n".join(lines[start - 1 : end]).strip()


def make_finding(
    *,
    rule_id: str,
    category: str,
    title: str,
    severity: str,
    confidence: float,
    file: FileContext,
    node: ast.AST,
    message: str,
    behavior_path: list[str] | None = None,
    evidence: list[Evidence] | None = None,
    target_node: ast.AST | None = None,
) -> Finding:
    target = target_node or node
    line = getattr(node, "lineno", 1)
    end_line = getattr(target, "end_lineno", getattr(target, "lineno", line))
    item = Evidence(
        file=file.rel_path,
        line=line,
        snippet=snippet(file.source, node),
        message=message,
    )
    all_evidence = [item] + list(evidence or [])
    return Finding(
        id=f"{rule_id}:{file.rel_path}:{line}",
        category=category,  # type: ignore[arg-type]
        rule_id=rule_id,
        title=title,
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence,
        file=file.rel_path,
        line=line,
        snippet=item.snippet,
        message=message,
        target_region=TargetRegion(
            file=file.rel_path,
            start_line=getattr(target, "lineno", line),
            end_line=end_line,
        ),
        behavior_path=behavior_path or [],
        evidence=all_evidence,
    )


def keyword_bool(node: ast.Call, key: str) -> bool:
    for kw in node.keywords:
        if kw.arg == key and isinstance(kw.value, ast.Constant):
            return bool(kw.value.value)
    return False


def contains_call(node: ast.AST, call_names: set[str]) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and call_name(child.func) in call_names:
            return True
    return False


def is_reconstructed_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return True
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
        step = node.slice.step
        if isinstance(step, ast.Constant) and step.value == -1:
            return True
        if (
            isinstance(step, ast.UnaryOp)
            and isinstance(step.op, ast.USub)
            and isinstance(step.operand, ast.Constant)
            and step.operand.value == 1
        ):
            return True
    if isinstance(node, ast.Call):
        name = call_name(node.func)
        return name == "join" or name.endswith(".join") or name.endswith(".format")
    return False
