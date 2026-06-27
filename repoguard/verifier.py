from __future__ import annotations

import subprocess
from pathlib import Path

from repoguard.models import Finding, PatchProposal, VerificationResult
from repoguard.scanner import scan


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def verify_patch(
    repo_path: str,
    finding: Finding,
    proposal: PatchProposal,
    diff: str,
    test_command: str | None = None,
) -> VerificationResult:
    after_findings = scan(repo_path)
    matching = [
        item
        for item in after_findings
        if item.rule_id == finding.rule_id and item.file == finding.file
    ]
    scanner_passed = not matching or all(
        SEVERITY_RANK[item.severity] < SEVERITY_RANK[finding.severity] for item in matching
    )
    after_severity = max((item.severity for item in matching), default=None, key=lambda s: SEVERITY_RANK[s])
    tests_passed = _run_tests(repo_path, test_command) if test_command else None
    status = "patched" if scanner_passed and tests_passed is not False else "failed"
    if proposal.action == "needs_review":
        status = "needs_review"
    return VerificationResult(
        finding_id=finding.id,
        status=status,
        before_severity=finding.severity,
        after_severity=after_severity,
        scanner_passed=scanner_passed,
        tests_passed=tests_passed,
        diff=diff,
        notes=_notes(scanner_passed, tests_passed),
    )


def _run_tests(repo_path: str, test_command: str) -> bool:
    result = subprocess.run(
        test_command,
        cwd=Path(repo_path).resolve(),
        shell=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return result.returncode == 0


def _notes(scanner_passed: bool, tests_passed: bool | None) -> str:
    if scanner_passed and tests_passed is not False:
        return "Finding removed or reduced; no configured tests failed."
    if not scanner_passed:
        return "Scanner still reports the original finding."
    return "Configured tests failed after patch."
