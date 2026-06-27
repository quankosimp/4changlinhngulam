from __future__ import annotations

import ast

from repoguard.rules.common import (
    FileContext,
    call_name,
    is_reconstructed_string,
    keyword_bool,
    make_finding,
)


POST_CALLS = {
    "requests.post",
    "requests.api.post",
    "urllib.request.urlopen",
    "urlopen",
}

PROCESS_CALLS = {
    "os.system",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
}


def detect_file(file: FileContext) -> list:
    findings = []
    findings.extend(_detect_env_exfil(file))
    findings.extend(_detect_shell_injection(file))
    return findings


def _detect_env_exfil(file: FileContext) -> list:
    env_aliases = _collect_env_aliases(file.tree)
    findings = []
    for node in ast.walk(file.tree):
        if not isinstance(node, ast.Call) or call_name(node.func) not in POST_CALLS:
            continue
        payload_nodes = list(node.args[1:]) + [kw.value for kw in node.keywords if kw.value]
        if not any(_contains_env_usage(item, env_aliases) for item in payload_nodes):
            continue
        findings.append(
            make_finding(
                rule_id="PY-ENV-EXFIL",
                category="security",
                title="environment secret sent over network",
                severity="high",
                confidence=0.91,
                file=file,
                node=node,
                message="Environment variable or secret-like config flows into an outbound network request.",
                behavior_path=[
                    "SOURCE: os.environ/os.getenv",
                    f"SINK: {call_name(node.func)}",
                ],
            )
        )
    return findings


def _detect_shell_injection(file: FileContext) -> list:
    findings = []
    for node in ast.walk(file.tree):
        if not isinstance(node, ast.Call) or call_name(node.func) not in PROCESS_CALLS:
            continue
        shell = keyword_bool(node, "shell")
        command = node.args[0] if node.args else None
        dynamic_command = command is not None and (
            is_reconstructed_string(command) or isinstance(command, ast.Name)
        )
        if not shell and not dynamic_command:
            continue
        findings.append(
            make_finding(
                rule_id="PY-SHELL-INJECTION",
                category="security",
                title="shell command injection risk",
                severity="high" if shell else "medium",
                confidence=0.92 if shell else 0.82,
                file=file,
                node=node,
                message="Process execution receives shell=True or a dynamically built command string.",
                behavior_path=[
                    "SOURCE: dynamic command input",
                    f"SINK: {call_name(node.func)}",
                ],
            )
        )
    return findings


def _collect_env_aliases(tree: ast.AST) -> set[str]:
    aliases: set[str] = set()

    class Visitor(ast.NodeVisitor):
        def visit_Assign(self, node: ast.Assign) -> None:
            if _is_env_expr(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        aliases.add(target.id)
            self.generic_visit(node)

    Visitor().visit(tree)
    return aliases


def _contains_env_usage(node: ast.AST | None, aliases: set[str]) -> bool:
    if node is None:
        return False
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in aliases:
            return True
        if _is_env_expr(child):
            return True
    return False


def _is_env_expr(node: ast.AST) -> bool:
    if isinstance(node, ast.Call) and call_name(node.func) in {"os.getenv", "getenv"}:
        return True
    return isinstance(node, ast.Subscript) and call_name(node.value) == "os.environ"
