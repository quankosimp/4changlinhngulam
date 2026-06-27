from __future__ import annotations

import ast
import math
from collections import Counter

from malguard.models import Finding


DECODE_CALLS = {
    "base64.b64decode",
    "base64.standard_b64decode",
    "base64.urlsafe_b64decode",
    "binascii.unhexlify",
    "codecs.decode",
}

PROCESS_LAUNCHERS = {
    "os.system",
    "system",
    "os.popen",
    "popen",
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
    "subprocess.getoutput",
}

REQUEST_GET_CALLS = {
    "requests.get",
    "requests.api.get",
    "session.get",
    "urllib.request.urlopen",
    "urlopen",
}

REQUEST_POST_CALLS = {"requests.post", "requests.api.post", "session.post", "post"}


RULES = []


def detect(tree: ast.AST, path: str, source: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(tree, path, source))
    return findings


def detect_exec_on_decoded_payload(
    tree: ast.AST, path: str, source: str | None = None
) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not _is_call_to(node, {"exec", "eval", "compile"}) or not node.args:
            continue
        if not _contains_decode_call(node.args[0]):
            continue
        direct = isinstance(node.args[0], ast.Call) and _call_name(node.args[0].func) in DECODE_CALLS
        findings.append(
            Finding(
                rule_id="PY-EXEC-DECODE",
                title="exec/eval with decoded string payload",
                severity="high" if direct else "medium",
                confidence=0.95 if direct else 0.84,
                file=path,
                line=getattr(node, "lineno", 1),
                snippet=_snippet(source, node),
                message=(
                    "Dynamic execution receives data produced by base64/hex decode. "
                    "Common malware loading pattern."
                ),
            )
        )
    return findings


def detect_high_entropy_code_execution(
    tree: ast.AST, path: str, source: str | None = None
) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not _is_call_to(node, {"exec", "eval", "compile"}) or not node.args:
            continue
        value = _string_constant(node.args[0])
        if value is None:
            continue
        entropy = _shannon_entropy(value)
        if len(value) < 64 or entropy < 4.5:
            continue
        findings.append(
            Finding(
                rule_id="PY-EXEC-ENTROPY",
                title="high-entropy string executed",
                severity="high" if entropy >= 5.0 else "medium",
                confidence=0.88 if entropy >= 5.0 else 0.76,
                file=path,
                line=getattr(node, "lineno", 1),
                snippet=_snippet(source, node),
                message=(
                    f"String length {len(value)} and entropy {entropy:.2f} "
                    "is unusual for plain source and suspicious when executed."
                ),
            )
        )
    return findings


def detect_dynamic_import_system(
    tree: ast.AST, path: str, source: str | None = None
) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr not in {"system", "popen"}:
            continue

        receiver = node.func.value
        if _is_dynamic_os_import(receiver):
            findings.append(
                Finding(
                    rule_id="PY-IMPORT-OS-SYSTEM",
                    title="dynamic __import__/import_module with system",
                    severity="high",
                    confidence=0.93,
                    file=path,
                    line=getattr(node, "lineno", 1),
                    snippet=_snippet(source, node),
                    message=(
                        "Command execution reached through dynamic import "
                        "(__import__ / importlib.import_module)."
                    ),
                )
            )
            continue

        if _call_name(node.func) in {"os.system", "os.popen"}:
            findings.append(
                Finding(
                    rule_id="PY-OS-SYSTEM",
                    title="os.system call",
                    severity="medium",
                    confidence=0.82,
                    file=path,
                    line=getattr(node, "lineno", 1),
                    snippet=_snippet(source, node),
                    message=(
                        "os.system() executes shell commands; combined with possible "
                        "import/exec patterns it is high-risk."
                    ),
                )
            )
    return findings


def detect_pickle_loads_from_network_or_socket(
    tree: ast.AST, path: str, source: str | None = None
) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not _is_call_to(node, {"pickle.loads", "loads"}) or not node.args:
            continue
        payload = node.args[0]
        if _is_requests_content(payload):
            findings.append(
                Finding(
                    rule_id="PY-PICKLE-NETWORK",
                    title="pickle.loads on network response",
                    severity="high",
                    confidence=0.96,
                    file=path,
                    line=getattr(node, "lineno", 1),
                    snippet=_snippet(source, node),
                    message=(
                        "Unpickling network payload (requests.get(...).content) is "
                        "a direct remote code execution vector."
                    ),
                )
            )
        elif _is_socket_recv(payload):
            findings.append(
                Finding(
                    rule_id="PY-PICKLE-SOCKET",
                    title="pickle.loads on socket input",
                    severity="high",
                    confidence=0.91,
                    file=path,
                    line=getattr(node, "lineno", 1),
                    snippet=_snippet(source, node),
                    message=(
                        "Unpickling raw socket bytes is high-risk and often used in "
                        "dropper pipelines."
                    ),
                )
            )
    return findings


def detect_exec_on_reconstructed_string(
    tree: ast.AST, path: str, source: str | None = None
) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not _is_call_to(node, {"exec", "eval", "compile"}) or not node.args:
            continue
        if not _is_reconstructed_string(node.args[0]):
            continue
        findings.append(
            Finding(
                rule_id="PY-EXEC-REBUILD",
                title="exec/eval on reconstructed string",
                severity="medium",
                confidence=0.8,
                file=path,
                line=getattr(node, "lineno", 1),
                snippet=_snippet(source, node),
                message=(
                    "Reconstructed payload strings (concat/join/slice/format) "
                    "before execution are common obfuscation patterns."
                ),
            )
        )
    return findings


def detect_command_injection_style_spawn(
    tree: ast.AST, path: str, source: str | None = None
) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = _call_name(node.func)
        if func_name not in PROCESS_LAUNCHERS or not node.args:
            continue

        command_arg = node.args[0]
        shell = _keyword_bool(node, "shell")
        suspicious_builder = _is_reconstructed_string(command_arg)
        if func_name in {"os.system", "os.popen", "system", "popen"}:
            suspicious_builder = suspicious_builder or isinstance(command_arg, ast.Name)
        if not suspicious_builder and not shell:
            continue

        confidence = 0.92 if func_name in {"os.system", "os.popen", "system", "popen"} else 0.82
        if shell:
            confidence = min(1.0, confidence + 0.06)
        findings.append(
            Finding(
                rule_id="PY-COMMAND-INJECT",
                title="string-built command spawn",
                severity="high" if func_name.startswith("os.") or shell else "medium",
                confidence=confidence,
                file=path,
                line=getattr(node, "lineno", 1),
                snippet=_snippet(source, node),
                message=(
                    "Command execution API receives command built by string operations "
                    "and may hide obfuscated shell instructions."
                ),
            )
        )
    return findings


def detect_env_exfiltration_via_http_post(
    tree: ast.AST, path: str, source: str | None = None
) -> list[Finding]:
    env_names = _collect_environment_aliases(tree)
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not _is_call_to(node, REQUEST_POST_CALLS):
            continue
        payload_nodes = list(node.args[1:]) + [kw.value for kw in node.keywords if kw.value]
        if not any(_contains_env_usage(payload, env_names) for payload in payload_nodes):
            continue
        findings.append(
            Finding(
                rule_id="PY-EXFIL-ENV",
                title="environment credentials in outbound post",
                severity="high",
                confidence=0.9,
                file=path,
                line=getattr(node, "lineno", 1),
                snippet=_snippet(source, node),
                message=(
                    "requests.post() payload appears to include os.environ/getenv "
                    "values, which may indicate credential exfiltration."
                ),
            )
        )
    return findings


RULES = [
    detect_exec_on_decoded_payload,
    detect_high_entropy_code_execution,
    detect_dynamic_import_system,
    detect_pickle_loads_from_network_or_socket,
    detect_exec_on_reconstructed_string,
    detect_command_injection_style_spawn,
    detect_env_exfiltration_via_http_post,
]


def _is_call_to(node: ast.AST, names: set[str]) -> bool:
    return isinstance(node, ast.Call) and _call_name(node.func) in names


def _call_name(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _string_constant(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _contains_decode_call(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and _call_name(child.func) in DECODE_CALLS:
            return True
    return False


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    total = len(value)
    freq = Counter(value)
    return -sum((count / total) * math.log(count / total, 2) for count in freq.values())


def _snippet(source: str | None, node: ast.AST) -> str:
    if not source:
        return _safe_unparse(node)
    lines = source.splitlines()
    start = max(getattr(node, "lineno", 1) - 2, 1)
    end = min(getattr(node, "end_lineno", getattr(node, "lineno", 1)) + 1, len(lines))
    return "\n".join(lines[start - 1 : end]).strip()


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _is_dynamic_os_import(expr: ast.AST | None) -> bool:
    if not isinstance(expr, ast.Call):
        return False
    if _call_name(expr.func) not in {"__import__", "importlib.import_module"}:
        return False
    if not expr.args:
        return False
    return _string_constant(expr.args[0]) == "os"


def _is_requests_content(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "content"
        and isinstance(node.value, ast.Call)
        and _call_name(node.value.func) in REQUEST_GET_CALLS
    )


def _is_socket_recv(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and (
        _call_name(node.func) == "recv" or _call_name(node.func).endswith(".recv")
    )


def _is_reconstructed_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if _is_negative_slice(node):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_reconstruct_unit(node.left) and _is_reconstruct_unit(node.right)
    if isinstance(node, ast.Call):
        fn = _call_name(node.func)
        if (fn == "join" or fn.endswith(".join")) and node.args:
            return True
        if fn == "format" or fn.endswith(".format"):
            return True
        if fn == "str" and node.args:
            return _is_reconstructed_string(node.args[0])
    return False


def _is_reconstruct_unit(node: ast.AST) -> bool:
    return isinstance(node, (ast.Name, ast.Constant, ast.Call, ast.BinOp, ast.JoinedStr))


def _is_negative_slice(node: ast.AST) -> bool:
    if not isinstance(node, ast.Subscript) or not isinstance(node.slice, ast.Slice):
        return False
    step = node.slice.step
    if isinstance(step, ast.Constant) and step.value == -1:
        return True
    return (
        isinstance(step, ast.UnaryOp)
        and isinstance(step.op, ast.USub)
        and isinstance(step.operand, ast.Constant)
        and step.operand.value == 1
    )


def _collect_environment_aliases(tree: ast.AST) -> set[str]:
    aliases: set[str] = set()

    def add_targets(targets: list[ast.expr]) -> None:
        for target in targets:
            if isinstance(target, ast.Name):
                aliases.add(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                add_targets(list(target.elts))

    class EnvAliasCollector(ast.NodeVisitor):
        def visit_Assign(self, node: ast.Assign) -> None:
            if _is_env_value(node.value):
                add_targets(list(node.targets))
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            if node.value is not None and _is_env_value(node.value):
                add_targets([node.target])
            self.generic_visit(node)

    EnvAliasCollector().visit(tree)
    return aliases


def _is_env_value(node: ast.AST) -> bool:
    if isinstance(node, ast.Subscript) and _is_os_environ_store(node):
        return True
    return isinstance(node, ast.Call) and _call_name(node.func) in {"os.getenv", "getenv"}


def _is_os_environ_store(node: ast.Subscript) -> bool:
    return isinstance(node.value, ast.Attribute) and _call_name(node.value) == "os.environ"


def _contains_env_usage(node: ast.AST | None, aliases: set[str]) -> bool:
    if node is None:
        return False
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in aliases:
            return True
        if isinstance(child, ast.Subscript) and _is_os_environ_store(child):
            return True
        if isinstance(child, ast.Call) and _call_name(child.func) in {"os.getenv", "getenv"}:
            return True
    return False


def _keyword_bool(node: ast.Call, key: str) -> bool:
    for kw in node.keywords:
        if kw.arg == key and isinstance(kw.value, ast.Constant):
            return bool(kw.value.value)
    return False
