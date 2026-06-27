from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


Category = Literal["security", "malware", "dead_code", "refactor"]
Severity = Literal["high", "medium", "low"]
Action = Literal["remove", "quarantine", "safe_replace", "refactor", "needs_review"]
VerificationStatus = Literal["patched", "failed", "needs_review"]


@dataclass(frozen=True)
class TargetRegion:
    file: str
    start_line: int
    end_line: int

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "start_line": self.start_line,
            "end_line": self.end_line,
        }


@dataclass(frozen=True)
class Evidence:
    file: str
    line: int
    snippet: str
    message: str

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "message": self.message,
        }


@dataclass(frozen=True)
class Finding:
    id: str
    category: Category
    rule_id: str
    title: str
    severity: Severity
    confidence: float
    file: str
    line: int
    snippet: str
    message: str
    target_region: TargetRegion
    behavior_path: list[str] = field(default_factory=list)
    codegraph_context: dict = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "category": self.category,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "message": self.message,
            "target_region": self.target_region.to_dict(),
            "behavior_path": self.behavior_path,
            "codegraph_context": self.codegraph_context,
            "evidence": [item.to_dict() for item in self.evidence],
        }

    def with_codegraph_context(self, context: dict) -> "Finding":
        return Finding(
            id=self.id,
            category=self.category,
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            confidence=self.confidence,
            file=self.file,
            line=self.line,
            snippet=self.snippet,
            message=self.message,
            target_region=self.target_region,
            behavior_path=list(self.behavior_path),
            codegraph_context=context,
            evidence=list(self.evidence),
        )


@dataclass(frozen=True)
class PatchProposal:
    finding_id: str
    action: Action
    file: str
    start_line: int
    end_line: int
    replacement: str
    rationale: str
    expected_risk_reduction: str

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "action": self.action,
            "file": self.file,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "replacement": self.replacement,
            "rationale": self.rationale,
            "expected_risk_reduction": self.expected_risk_reduction,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PatchProposal":
        return cls(
            finding_id=str(data["finding_id"]),
            action=data["action"],
            file=str(data["file"]),
            start_line=int(data["start_line"]),
            end_line=int(data["end_line"]),
            replacement=str(data.get("replacement", "")),
            rationale=str(data.get("rationale", "")),
            expected_risk_reduction=str(data.get("expected_risk_reduction", "")),
        )


@dataclass(frozen=True)
class VerificationResult:
    finding_id: str
    status: VerificationStatus
    before_severity: str
    after_severity: str | None
    scanner_passed: bool
    tests_passed: bool | None
    diff: str
    notes: str

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "status": self.status,
            "before_severity": self.before_severity,
            "after_severity": self.after_severity,
            "scanner_passed": self.scanner_passed,
            "tests_passed": self.tests_passed,
            "diff": self.diff,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class RepoGuardReport:
    repo_path: str
    findings: list[Finding]
    patches: list[PatchProposal] = field(default_factory=list)
    verification: list[VerificationResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "repo_path": self.repo_path,
            "findings": [item.to_dict() for item in self.findings],
            "patches": [item.to_dict() for item in self.patches],
            "verification": [item.to_dict() for item in self.verification],
        }
