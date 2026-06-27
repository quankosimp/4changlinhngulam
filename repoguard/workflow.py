from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from repoguard.agent import propose_patch
from repoguard.config import codegraph_enabled
from repoguard.models import PatchProposal, RepoGuardReport, VerificationResult
from repoguard.patcher import PatchApplication, PatchValidationError, apply_patch, preview_patch
from repoguard.repo_context import enrich_findings
from repoguard.scanner import scan
from repoguard.verifier import verify_patch


SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}


@dataclass(frozen=True)
class FixResult:
    report: RepoGuardReport
    applications: list[PatchApplication]


def run_scan(path: str, use_codegraph: bool = True) -> RepoGuardReport:
    scan_path = Path(path).resolve()
    repo_root = repo_root_for(scan_path)
    findings = scan(str(scan_path))
    if use_codegraph and codegraph_enabled():
        findings = enrich_findings(str(repo_root), findings)
    return RepoGuardReport(repo_path=str(scan_path), findings=findings)


def run_fix(
    path: str,
    *,
    apply: bool,
    max_findings: int = 10,
    test_command: str | None = None,
    use_codegraph: bool = True,
    use_llm: bool = True,
) -> FixResult:
    scan_path = Path(path).resolve()
    repo_root = repo_root_for(scan_path)
    report = run_scan(str(scan_path), use_codegraph=use_codegraph)
    selected = select_findings(report.findings, max_findings=max_findings)

    proposals = [propose_patch(str(repo_root), finding, use_llm=use_llm) for finding in selected]
    applications: list[PatchApplication] = []
    processed_patches: list[PatchProposal] = []
    verification: list[VerificationResult] = []

    pairs = list(zip(selected, proposals))
    if apply:
        pairs = sorted(pairs, key=lambda pair: (pair[1].file, pair[1].start_line), reverse=True)

    for finding, proposal in pairs:
        processed_patches.append(proposal)
        try:
            application = (
                apply_patch(str(repo_root), finding, proposal)
                if apply
                else preview_patch(str(repo_root), finding, proposal)
            )
            applications.append(application)
            if apply:
                verification.append(
                    verify_patch(
                        str(scan_path),
                        finding,
                        proposal,
                        application.diff,
                        test_command=test_command,
                    )
                )
            else:
                verification.append(
                    VerificationResult(
                        finding_id=finding.id,
                        status="needs_review",
                        before_severity=finding.severity,
                        after_severity=None,
                        scanner_passed=False,
                        tests_passed=None,
                        diff=application.diff,
                        notes="dry-run only; patch not applied",
                    )
                )
        except PatchValidationError as exc:
            verification.append(_invalid_proposal_result(finding, proposal, str(exc)))

    return FixResult(
        report=RepoGuardReport(
            repo_path=str(scan_path),
            findings=report.findings,
            patches=processed_patches,
            verification=verification,
        ),
        applications=applications,
    )


def select_findings(findings, max_findings: int):
    return sorted(
        findings,
        key=lambda item: (SEVERITY_ORDER.get(item.severity, 0), item.confidence),
        reverse=True,
    )[:max_findings]


def repo_root_for(path: Path) -> Path:
    return path.parent if path.is_file() else path


def _invalid_proposal_result(finding, proposal: PatchProposal, notes: str) -> VerificationResult:
    return VerificationResult(
        finding_id=finding.id,
        status="needs_review",
        before_severity=finding.severity,
        after_severity=finding.severity,
        scanner_passed=False,
        tests_passed=None,
        diff="",
        notes=notes,
    )
