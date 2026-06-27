from __future__ import annotations

import ast

from repoguard.rules.common import RepoScanContext, make_finding


IGNORED_NAMES = {"main", "__init__", "__repr__", "__str__", "run"}


def detect_repo(repo: RepoScanContext) -> list:
    findings = []
    for file in repo.files:
        for node in ast.iter_child_nodes(file.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if _is_unused(node.name, repo):
                    findings.append(
                        make_finding(
                            rule_id="PY-UNUSED-FUNCTION",
                            category="dead_code",
                            title="unused function candidate",
                            severity="low",
                            confidence=0.72,
                            file=file,
                            node=node,
                            message="Function has no direct name references in the scanned repo.",
                            behavior_path=[f"SYMBOL: {node.name}", "CALLERS: []"],
                        )
                    )
            elif isinstance(node, ast.ClassDef):
                if _is_unused(node.name, repo):
                    findings.append(
                        make_finding(
                            rule_id="PY-UNUSED-CLASS",
                            category="dead_code",
                            title="unused class candidate",
                            severity="low",
                            confidence=0.7,
                            file=file,
                            node=node,
                            message="Class has no direct name references in the scanned repo.",
                            behavior_path=[f"SYMBOL: {node.name}", "REFERENCES: []"],
                        )
                    )
    return findings


def _is_unused(name: str, repo: RepoScanContext) -> bool:
    if name.startswith("_") or name in IGNORED_NAMES:
        return False
    refs = repo.name_refs.get(name, [])
    return len(set(refs)) <= 1 and not repo.attr_refs.get(name)
