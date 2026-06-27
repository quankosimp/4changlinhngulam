from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from repoguard.codegraph_client import CodeGraphClient
from repoguard.models import Finding
from repoguard.rules.common import call_name


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


@dataclass(frozen=True)
class GraphExport:
    repo_path: str
    generated_at: str
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    raw_codegraph: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_path": self.repo_path,
            "generated_at": self.generated_at,
            "nodes": self.nodes,
            "edges": self.edges,
            "findings": self.findings,
            "raw_codegraph": self.raw_codegraph,
        }


def build_graph(repo_path: str, findings: list[Finding] | None = None, require_codegraph: bool = True) -> GraphExport:
    repo = Path(repo_path).resolve()
    root = repo.parent if repo.is_file() else repo
    client = CodeGraphClient(str(root))
    raw_codegraph = {}
    if require_codegraph:
        raw_codegraph["check"] = client.check_available()
    else:
        try:
            raw_codegraph["check"] = client.check_available()
        except Exception as exc:  # exporter still useful for tests when CodeGraph is absent
            raw_codegraph["check_error"] = str(exc)

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    symbol_index: dict[str, list[str]] = {}

    def add_node(node: dict[str, Any]) -> None:
        nodes.setdefault(node["id"], node)

    def add_edge(source: str, target: str, edge_type: str, label: str | None = None) -> None:
        key = (source, target, edge_type)
        edges.setdefault(
            key,
            {
                "source": source,
                "target": target,
                "type": edge_type,
                "label": label or edge_type,
            },
        )

    for file_path in _python_files(repo):
        rel = str(file_path.relative_to(root))
        file_id = f"file:{rel}"
        add_node({"id": file_id, "type": "file", "label": rel, "file": rel, "line": 1})
        source = file_path.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            continue

        imports = _imports(tree)
        for import_name in imports:
            import_id = f"import:{import_name}"
            add_node({"id": import_id, "type": "import", "label": import_name, "file": rel, "line": 1})
            add_edge(file_id, import_id, "imports", "imports")

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            node_type = "class" if isinstance(node, ast.ClassDef) else "function"
            symbol_id = f"{node_type}:{rel}:{node.name}"
            symbol_index.setdefault(node.name, []).append(symbol_id)
            add_node(
                {
                    "id": symbol_id,
                    "type": node_type,
                    "label": node.name,
                    "file": rel,
                    "line": getattr(node, "lineno", 1),
                }
            )
            add_edge(file_id, symbol_id, "contains", "contains")

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            source_id = f"function:{rel}:{node.name}"
            for call in [item for item in ast.walk(node) if isinstance(item, ast.Call)]:
                name = call_name(call.func)
                if not name:
                    continue
                short_name = name.rsplit(".", 1)[-1]
                targets = symbol_index.get(short_name)
                if targets:
                    for target in targets:
                        add_edge(source_id, target, "calls", f"calls {short_name}")
                else:
                    external_id = f"external:{name}"
                    add_node(
                        {
                            "id": external_id,
                            "type": "external",
                            "label": name,
                            "file": rel,
                            "line": getattr(call, "lineno", 1),
                        }
                    )
                    add_edge(source_id, external_id, "calls", f"calls {name}")

    finding_dicts = []
    for finding in findings or []:
        finding_id = f"finding:{finding.id}"
        finding_dict = finding.to_dict()
        finding_dicts.append(finding_dict)
        add_node(
            {
                "id": finding_id,
                "type": "finding",
                "label": finding.rule_id,
                "file": finding.file,
                "line": finding.line,
                "severity": finding.severity,
            }
        )
        add_edge(finding_id, f"file:{finding.file}", "finding_at", "finding")
        symbol = finding.codegraph_context.get("symbol") if finding.codegraph_context else None
        if symbol:
            for target in symbol_index.get(symbol, []):
                add_edge(finding_id, target, "references", "symbol")

    return GraphExport(
        repo_path=str(repo),
        generated_at=datetime.now(timezone.utc).isoformat(),
        nodes=sorted(nodes.values(), key=lambda item: item["id"]),
        edges=sorted(edges.values(), key=lambda item: (item["source"], item["target"], item["type"])),
        findings=finding_dicts,
        raw_codegraph=raw_codegraph,
    )


def write_graph(export: GraphExport, out_dir: str, output_format: str) -> list[Path]:
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if output_format in {"json", "both"}:
        path = target / "graph.json"
        path.write_text(json.dumps(export.to_dict(), indent=2), encoding="utf-8")
        written.append(path)
    if output_format in {"dot", "both"}:
        path = target / "graph.dot"
        path.write_text(to_dot(export), encoding="utf-8")
        written.append(path)
    return written


def to_dot(export: GraphExport) -> str:
    lines = ["digraph RepoGuardCodeGraph {", "  rankdir=LR;", "  node [fontname=\"Helvetica\"];"]
    for node in export.nodes:
        attrs = _dot_node_attrs(node)
        lines.append(f"  {_dot_id(node['id'])} [{attrs}];")
    for edge in export.edges:
        label = _dot_escape(edge.get("label") or edge["type"])
        lines.append(f"  {_dot_id(edge['source'])} -> {_dot_id(edge['target'])} [label=\"{label}\"];")
    lines.append("}")
    return "\n".join(lines) + "\n"


def graph_excerpt(export: GraphExport, center_file: str, center_symbol: str | None = None) -> dict[str, Any]:
    keep_ids = {f"file:{center_file}"}
    if center_symbol:
        keep_ids.update(node["id"] for node in export.nodes if node["label"] == center_symbol)
    for edge in export.edges:
        if edge["source"] in keep_ids or edge["target"] in keep_ids:
            keep_ids.add(edge["source"])
            keep_ids.add(edge["target"])
    return {
        "nodes": [node for node in export.nodes if node["id"] in keep_ids],
        "edges": [edge for edge in export.edges if edge["source"] in keep_ids and edge["target"] in keep_ids],
    }


def _python_files(repo: Path) -> list[Path]:
    if repo.is_file() and repo.suffix == ".py":
        return [repo]
    return [
        file
        for file in repo.rglob("*.py")
        if file.is_file() and not any(part in EXCLUDE_DIRS for part in file.parts)
    ]


def _imports(tree: ast.AST) -> list[str]:
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return sorted(set(names))


def _dot_node_attrs(node: dict[str, Any]) -> str:
    label = _dot_escape(node["label"])
    node_type = node.get("type")
    shape = {
        "file": "folder",
        "function": "box",
        "class": "box3d",
        "finding": "diamond",
        "import": "ellipse",
        "external": "ellipse",
    }.get(node_type, "box")
    color = "black"
    if node_type == "finding":
        color = {"high": "red", "medium": "orange", "low": "gray"}.get(node.get("severity"), "red")
    return f"label=\"{label}\", shape={shape}, color={color}"


def _dot_id(value: str) -> str:
    return "\"" + _dot_escape(value) + "\""


def _dot_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
