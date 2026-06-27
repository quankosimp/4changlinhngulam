from __future__ import annotations

import subprocess
from pathlib import Path

from repoguard.models import Finding, PatchProposal, VerificationResult
from repoguard.scanner import scan


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def verify_patch(
    repo_path: str | Finding,
    finding: Finding | PatchProposal,
    proposal: PatchProposal | str,
    diff: str | None = None,
    test_command: str | None = None,
) -> VerificationResult:
    if isinstance(repo_path, Finding):
        legacy_finding = repo_path
        legacy_proposal = finding
        if not isinstance(legacy_proposal, PatchProposal):
            raise TypeError("legacy verify_patch expects Finding, PatchProposal, diff")
        legacy_diff = proposal if isinstance(proposal, str) else diff or ""
        return _verify_patch(str(Path(legacy_proposal.file).resolve()), legacy_finding, legacy_proposal, legacy_diff)

    if not isinstance(finding, Finding) or not isinstance(proposal, PatchProposal):
        raise TypeError("verify_patch expects repo_path, Finding, PatchProposal, diff")
    return _verify_patch(repo_path, finding, proposal, diff or "", test_command=test_command)


def _verify_patch(
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
        if item.rule_id == finding.rule_id and _same_file(repo_path, item.file, finding.file)
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


def _same_file(scan_target: str, scanned_file: str, original_file: str) -> bool:
    if scanned_file == original_file:
        return True

    target = Path(scan_target).resolve()
    original = Path(original_file)
    if target.is_file():
        return target.name == Path(scanned_file).name == original.name

    try:
        scanned_abs = (target / scanned_file).resolve()
        original_abs = original.resolve() if original.is_absolute() else (target / original).resolve()
    except OSError:
        return False
    return scanned_abs == original_abs
