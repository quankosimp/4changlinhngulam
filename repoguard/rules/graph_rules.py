from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from repoguard.models import Finding
from repoguard.rules.common import FileContext, call_name, make_finding


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


NETWORK_CALLS = {"requests.get", "urllib.request.urlopen", "urlopen"}
EXEC_CALLS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "os.system",
    "exec",
    "eval",
}


@dataclass(frozen=True)
class FunctionSummary:
    name: str
    file: FileContext
    node: ast.FunctionDef | ast.AsyncFunctionDef
    calls: set[str]
    has_network: bool
    has_write: bool
    has_exec: bool
    exec_node: ast.AST | None


def detect_repo(repo_path: str) -> list[Finding]:
    root = Path(repo_path).resolve()
    if not root.is_dir():
        return []
    functions = _collect_functions(root)
    if not functions:
        return []

    by_name: dict[str, list[FunctionSummary]] = {}
    for fn in functions:
        by_name.setdefault(fn.name, []).append(fn)

    findings: list[Finding] = []
    for exec_fn in [fn for fn in functions if fn.has_exec]:
        for write_fn in _called_functions(exec_fn, by_name):
            if not write_fn.has_write:
                continue
            for fetch_fn in _called_functions(write_fn, by_name):
                if not fetch_fn.has_network:
                    continue
                findings.append(_dropper_finding(fetch_fn, write_fn, exec_fn))
                return findings

        if exec_fn.has_write and exec_fn.has_network:
            findings.append(_dropper_finding(exec_fn, exec_fn, exec_fn))
            return findings
    return findings


def _collect_functions(root: Path) -> list[FunctionSummary]:
    summaries: list[FunctionSummary] = []
    for path in _python_files(root):
        source = path.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            continue
        file = FileContext(
            root=root,
            abs_path=path,
            rel_path=str(path.relative_to(root)),
            source=source,
            tree=tree,
        )
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            calls = {
                call_name(call.func)
                for call in ast.walk(node)
                if isinstance(call, ast.Call) and call_name(call.func)
            }
            exec_nodes = [
                call
                for call in ast.walk(node)
                if isinstance(call, ast.Call) and call_name(call.func) in EXEC_CALLS
            ]
            summaries.append(
                FunctionSummary(
                    name=node.name,
                    file=file,
                    node=node,
                    calls={name.rsplit(".", 1)[-1] for name in calls},
                    has_network=bool(calls & NETWORK_CALLS),
                    has_write=any(_is_write_sink(item) for item in ast.walk(node)),
                    has_exec=bool(exec_nodes),
                    exec_node=exec_nodes[0] if exec_nodes else None,
                )
            )
    return summaries


def _called_functions(fn: FunctionSummary, by_name: dict[str, list[FunctionSummary]]) -> list[FunctionSummary]:
    out: list[FunctionSummary] = []
    for name in fn.calls:
        out.extend(by_name.get(name, []))
    return out


def _dropper_finding(
    fetch_fn: FunctionSummary,
    write_fn: FunctionSummary,
    exec_fn: FunctionSummary,
) -> Finding:
    target = exec_fn.exec_node or exec_fn.node
    finding = make_finding(
        rule_id="PY-GRAPH-DROPPER",
        category="malware",
        title="CodeGraph dropper call chain",
        severity="high",
        confidence=0.88,
        file=exec_fn.file,
        node=target,
        target_node=target,
        message="Call chain contains network download, file write, and process/code execution stages.",
        behavior_path=[
            f"{fetch_fn.file.rel_path}:{fetch_fn.name} -> SOURCE: network download",
            f"{write_fn.file.rel_path}:{write_fn.name} -> SINK: file write",
            f"{exec_fn.file.rel_path}:{exec_fn.name} -> SINK: process/code execution",
        ],
    )
    return finding.with_codegraph_context(
        {
            "symbol": exec_fn.name,
            "call_path": [
                f"{fetch_fn.file.rel_path}:{fetch_fn.name}",
                f"{write_fn.file.rel_path}:{write_fn.name}",
                f"{exec_fn.file.rel_path}:{exec_fn.name}",
            ],
            "source": "repoguard-callgraph",
        }
    )


def _is_write_sink(node: ast.AST) -> bool:
    if isinstance(node, ast.Call) and call_name(node.func).endswith(".write"):
        return True
    if not isinstance(node, ast.Call) or call_name(node.func) != "open":
        return False
    if len(node.args) < 2:
        return False
    mode = node.args[1]
    return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(
        flag in mode.value for flag in ("w", "a", "x", "+")
    )


def _python_files(root: Path) -> list[Path]:
    return [
        file
        for file in root.rglob("*.py")
        if file.is_file() and not any(part in EXCLUDE_DIRS for part in file.parts)
    ]
