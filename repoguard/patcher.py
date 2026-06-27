from __future__ import annotations

import difflib
from dataclasses import dataclass
from pathlib import Path

from repoguard.models import Finding, PatchProposal, TargetRegion


FORBIDDEN_REPLACEMENT_TOKENS = (
    "eval(",
    "exec(",
    "__import__(",
    "requests.post(",
    "urllib.request.urlopen(",
    "socket.",
)


@dataclass(frozen=True)
class PatchApplication:
    proposal: PatchProposal
    diff: str
    applied: bool
    notes: str


class PatchValidationError(ValueError):
    pass


def preview_patch(repo_path: str, finding: Finding, proposal: PatchProposal) -> PatchApplication:
    return _build_application(repo_path, finding, proposal, apply=False)


def apply_patch(repo_path: str, finding: Finding, proposal: PatchProposal) -> PatchApplication:
    return _build_application(repo_path, finding, proposal, apply=True)


def apply_patch_proposal(
    proposal: PatchProposal,
    finding: Finding | None = None,
    apply: bool = False,
) -> PatchApplication:
    if finding is None:
        finding = Finding(
            id=proposal.finding_id,
            category="refactor",
            rule_id="UNKNOWN",
            title="Patch proposal",
            severity="low",
            confidence=0.0,
            file=proposal.file,
            line=proposal.start_line,
            snippet="",
            message="Compatibility wrapper finding.",
            target_region=TargetRegion(
                file=proposal.file,
                start_line=proposal.start_line,
                end_line=proposal.end_line,
            ),
        )
    repo_path = str(Path(proposal.file).resolve().parent) if Path(proposal.file).is_absolute() else "."
    return _build_application(repo_path, finding, proposal, apply=apply)


def _build_application(
    repo_path: str,
    finding: Finding,
    proposal: PatchProposal,
    apply: bool,
) -> PatchApplication:
    _validate_proposal(finding, proposal)
    file_path = _resolve_target(repo_path, proposal.file)
    original_lines = file_path.read_text(encoding="utf-8").splitlines(keepends=True)
    start = proposal.start_line - 1
    end = proposal.end_line
    replacement_lines = _replacement_lines(proposal.replacement, original_lines[start:end])
    updated_lines = original_lines[:start] + replacement_lines + original_lines[end:]
    diff = "".join(
        difflib.unified_diff(
            original_lines,
            updated_lines,
            fromfile=f"a/{proposal.file}",
            tofile=f"b/{proposal.file}",
        )
    )
    if apply and proposal.action != "needs_review":
        file_path.write_text("".join(updated_lines), encoding="utf-8")
    return PatchApplication(
        proposal=proposal,
        diff=diff,
        applied=apply and proposal.action != "needs_review",
        notes="needs_review proposals are not applied" if proposal.action == "needs_review" else "",
    )


def _validate_proposal(finding: Finding, proposal: PatchProposal) -> None:
    target = finding.target_region
    if proposal.finding_id != finding.id:
        raise PatchValidationError("PatchProposal finding_id does not match finding.")
    if proposal.file != target.file:
        raise PatchValidationError("PatchProposal file must match finding target_region file.")
    if proposal.start_line < target.start_line or proposal.end_line > target.end_line:
        raise PatchValidationError("PatchProposal range must stay inside finding target_region.")
    if proposal.end_line < proposal.start_line:
        raise PatchValidationError("PatchProposal line range is invalid.")
    if proposal.action == "needs_review" and proposal.replacement.strip():
        raise PatchValidationError("needs_review proposals must not include a replacement.")
    lowered = proposal.replacement.lower()
    if any(token in lowered for token in FORBIDDEN_REPLACEMENT_TOKENS):
        raise PatchValidationError("PatchProposal replacement introduces forbidden risky behavior.")


def _resolve_target(repo_path: str, file: str) -> Path:
    repo = Path(repo_path).resolve()
    target = (repo / file).resolve()
    if repo not in target.parents and target != repo:
        raise PatchValidationError("PatchProposal target escapes repo path.")
    if not target.exists():
        raise PatchValidationError(f"PatchProposal file does not exist: {file}")
    return target


def _replacement_lines(replacement: str, original_region: list[str]) -> list[str]:
    if not replacement:
        return []
    lines = replacement.splitlines()
    indent = _leading_indent(original_region[0]) if original_region else ""
    if indent and lines and lines[0] and not lines[0].startswith((" ", "\t")):
        lines = [f"{indent}{line}" if line else line for line in lines]
    return [f"{line}\n" for line in lines]


def _leading_indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip(" \t"))]
