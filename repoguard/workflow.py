from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from repoguard.agent import propose_patch
from repoguard.config import codegraph_enabled
from repoguard.models import Finding, PatchProposal, RepoGuardReport, VerificationResult
from repoguard.patcher import PatchApplication, PatchValidationError, apply_patch, preview_patch
from repoguard.repo_context import enrich_findings
from repoguard.rules import graph_rules
from repoguard.scanner import scan
from repoguard.verifier import verify_patch


SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}


@dataclass(frozen=True)
class FixRound:
    round_index: int
    findings_before: list[Finding]
    findings_after: list[Finding]
    selected_findings: list[Finding]
    proposals: list[PatchProposal]
    applications: list[PatchApplication]
    verifications: list[VerificationResult]
    status: str
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "round_index": self.round_index,
            "status": self.status,
            "notes": self.notes,
            "findings_before_count": len(self.findings_before),
            "findings_after_count": len(self.findings_after),
            "selected_count": len(self.selected_findings),
            "proposals": [item.to_dict() for item in self.proposals],
            "applications": [
                {
                    "proposal": item.proposal.to_dict(),
                    "diff": item.diff,
                    "applied": item.applied,
                    "notes": item.notes,
                }
                for item in self.applications
            ],
            "verifications": [item.to_dict() for item in self.verifications],
        }


@dataclass(frozen=True)
class FixResult:
    report: RepoGuardReport
    applications: list[PatchApplication]
    rounds: list[FixRound]
    status: str


def run_scan(path: str, use_codegraph: bool = True) -> RepoGuardReport:
    scan_path = Path(path).resolve()
    repo_root = repo_root_for(scan_path)
    findings = scan(str(scan_path))
    if use_codegraph and scan_path.is_dir():
        findings.extend(graph_rules.detect_repo(str(scan_path)))
    if use_codegraph and codegraph_enabled():
        findings = enrich_findings(str(repo_root), findings)
    return RepoGuardReport(repo_path=str(scan_path), findings=findings)


def run_fix(
    path: str,
    *,
    apply: bool,
    max_rounds: int = 3,
    max_findings: int = 3,
    min_severity: str | None = None,
    test_command: str | None = None,
    use_codegraph: bool = True,
) -> FixResult:
    scan_path = Path(path).resolve()
    repo_root = repo_root_for(scan_path)
    max_rounds = max(1, max_rounds)
    if not apply:
        max_rounds = 1

    rounds: list[FixRound] = []
    all_applications: list[PatchApplication] = []
    all_verifications: list[VerificationResult] = []
    all_proposals: list[PatchProposal] = []
    final_findings = run_scan(str(scan_path), use_codegraph=use_codegraph).findings
    status = "needs_review"
    attempts: set[str] = set()

    for round_index in range(1, max_rounds + 1):
        current_report = run_scan(str(scan_path), use_codegraph=use_codegraph)
        findings_before = current_report.findings
        selected = select_findings(
            findings_before,
            max_findings=max_findings,
            min_severity=min_severity,
        )

        if not selected:
            status = "clean" if round_index == 1 else "patched"
            rounds.append(
                FixRound(
                    round_index=round_index,
                    findings_before=findings_before,
                    findings_after=findings_before,
                    selected_findings=[],
                    proposals=[],
                    applications=[],
                    verifications=[],
                    status="clean" if round_index == 1 else "patched",
                    notes="no findings to process",
                )
            )
            final_findings = findings_before
            break

        proposals = [propose_patch(str(repo_root), finding) for finding in selected]
        all_proposals.extend(proposals)
        applications: list[PatchApplication] = []
        verifications: list[VerificationResult] = []

        if not apply:
            for finding, proposal in zip(selected, proposals):
                application = preview_patch(str(repo_root), finding, proposal)
                applications.append(application)
                all_applications.append(application)
                verification = VerificationResult(
                    finding_id=finding.id,
                    status="needs_review",
                    before_severity=finding.severity,
                    after_severity=None,
                    scanner_passed=False,
                    tests_passed=None,
                    diff=application.diff,
                    notes="dry-run only; patch not applied",
                )
                verifications.append(verification)
                all_verifications.append(verification)

            rounds.append(
                FixRound(
                    round_index=round_index,
                    findings_before=findings_before,
                    findings_after=findings_before,
                    selected_findings=selected,
                    proposals=proposals,
                    applications=applications,
                    verifications=verifications,
                    status="dry_run",
                    notes="dry-run mode; no code changes applied",
                )
            )
            status = "dry_run"
            final_findings = findings_before
            break

        pairs = list(zip(selected, proposals))
        pairs = sorted(pairs, key=lambda pair: (pair[1].file, pair[1].start_line), reverse=True)

        for finding, proposal in pairs:
            signature = _proposal_signature(proposal)
            try:
                if signature in attempts:
                    application = preview_patch(str(repo_root), finding, proposal)
                    applications.append(application)
                    all_applications.append(application)
                    verification = _invalid_proposal_result(
                        finding,
                        proposal,
                        "Duplicate repair attempt for the same proposal was skipped.",
                    )
                    verifications.append(verification)
                    all_verifications.append(verification)
                    continue

                application = apply_patch(str(repo_root), finding, proposal)
                applications.append(application)
                all_applications.append(application)
                verification = verify_patch(
                    str(scan_path),
                    finding,
                    proposal,
                    application.diff,
                    test_command=test_command,
                )
                verifications.append(verification)
                all_verifications.append(verification)
                attempts.add(signature)
            except PatchValidationError as exc:
                verification = _invalid_proposal_result(finding, proposal, str(exc))
                verifications.append(verification)
                all_verifications.append(verification)

        findings_after = run_scan(str(scan_path), use_codegraph=use_codegraph).findings
        final_findings = findings_after
        if not findings_after:
            status = "patched"
            rounds.append(
                FixRound(
                    round_index=round_index,
                    findings_before=findings_before,
                    findings_after=findings_after,
                    selected_findings=selected,
                    proposals=proposals,
                    applications=applications,
                    verifications=verifications,
                    status="patched",
                    notes="all findings removed in this round",
                )
            )
            break

        if not _progress_for_next_round(
            findings_before,
            findings_after,
            min_severity=min_severity,
        ):
            status = "needs_review"
            rounds.append(
                FixRound(
                    round_index=round_index,
                    findings_before=findings_before,
                    findings_after=findings_after,
                    selected_findings=selected,
                    proposals=proposals,
                    applications=applications,
                    verifications=verifications,
                    status="needs_review",
                    notes="no measurable progress after this round",
                )
            )
            break

        if round_index >= max_rounds:
            status = "partial"
            rounds.append(
                FixRound(
                    round_index=round_index,
                    findings_before=findings_before,
                    findings_after=findings_after,
                    selected_findings=selected,
                    proposals=proposals,
                    applications=applications,
                    verifications=verifications,
                    status="partial",
                    notes="max_rounds reached",
                )
            )
            break

        rounds.append(
            FixRound(
                round_index=round_index,
                findings_before=findings_before,
                findings_after=findings_after,
                selected_findings=selected,
                proposals=proposals,
                applications=applications,
                verifications=verifications,
                status="in_progress",
                notes="remaining findings still above threshold",
            )
        )
        if not select_findings(findings_after, max_findings=max_findings, min_severity=min_severity):
            status = "patched"
            break

    return FixResult(
        report=RepoGuardReport(
            repo_path=str(scan_path),
            findings=final_findings,
            patches=all_proposals,
            verification=all_verifications,
            fix_rounds=[item.to_dict() for item in rounds],
            fix_metadata={
                "status": status,
                "max_rounds": max_rounds,
                "requested_max_rounds": max_rounds,
                "max_findings_per_round": max_findings,
                "min_severity": min_severity,
            },
        ),
        applications=all_applications,
        rounds=rounds,
        status=status,
    )


def select_findings(
    findings,
    max_findings: int,
    min_severity: str | None = None,
):
    if min_severity:
        min_rank = SEVERITY_ORDER.get(min_severity, 0)
        findings = [item for item in findings if SEVERITY_ORDER.get(item.severity, 0) >= min_rank]
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


def _proposal_signature(proposal: PatchProposal) -> str:
    return "|".join(
        [
            proposal.finding_id,
            proposal.file,
            str(proposal.start_line),
            str(proposal.end_line),
            proposal.action,
            proposal.replacement.strip().replace("\n", "\\n"),
        ]
    )


def _targeted_subset(
    findings,
    min_severity: str | None = None,
) -> list:
    if not min_severity:
        return list(findings)
    min_rank = SEVERITY_ORDER.get(min_severity, 0)
    return [item for item in findings if SEVERITY_ORDER.get(item.severity, 0) >= min_rank]


def _progress_for_next_round(
    before_findings,
    after_findings,
    *,
    min_severity: str | None = None,
) -> bool:
    before = _targeted_subset(before_findings, min_severity=min_severity)
    after = _targeted_subset(after_findings, min_severity=min_severity)
    before_score = _severity_score(before)
    after_score = _severity_score(after)
    if after_score < before_score:
        return True
    if len(after) < len(before):
        return True
    return False


def _severity_score(findings) -> int:
    return sum(SEVERITY_ORDER.get(item.severity, 0) * 10 + 100 - int(item.confidence * 100) for item in findings)
