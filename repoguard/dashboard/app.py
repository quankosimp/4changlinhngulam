from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import streamlit as st


DEFAULT_REPORTS = [
    "repoguard_report.json",
    "remediation_report.json",
    "report.json",
]


def main() -> None:
    st.set_page_config(page_title="RepoGuard", layout="wide")
    st.title("RepoGuard Agent")
    st.caption("Findings, CodeGraph context, patch diffs, and verification results.")

    report_path = _report_path_control()
    report = _load_report(report_path)
    if report is None:
        st.info(
            "No report loaded. Generate one with "
            "`python -m repoguard fix tests/corpus --dry-run --report repoguard_report.json`."
        )
        return

    findings = report.get("findings", [])
    patches = report.get("patches", [])
    verification = report.get("verification", [])

    _summary(report, findings, patches, verification)

    tab_findings, tab_context, tab_diff, tab_verification = st.tabs(
        ["Findings", "CodeGraph Context", "Patch Diff", "Verification"]
    )
    with tab_findings:
        _render_findings(findings)
    with tab_context:
        _render_context(findings)
    with tab_diff:
        _render_diffs(findings, patches, verification)
    with tab_verification:
        _render_verification(verification)


def _report_path_control() -> Path:
    existing = next((Path(path) for path in DEFAULT_REPORTS if Path(path).exists()), Path(DEFAULT_REPORTS[0]))
    raw_path = st.sidebar.text_input("Report JSON", value=str(existing))
    return Path(raw_path).expanduser()


def _load_report(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        st.error(f"Could not read report: {exc}")
        return None

    if isinstance(data, list):
        return {"repo_path": str(path), "findings": data, "patches": [], "verification": []}
    if isinstance(data, dict):
        data.setdefault("findings", [])
        data.setdefault("patches", [])
        data.setdefault("verification", [])
        return data
    st.error("Report JSON must be an object or a list of findings.")
    return None


def _summary(report: dict[str, Any], findings: list[dict], patches: list[dict], verification: list[dict]) -> None:
    patched = sum(1 for item in verification if item.get("status") == "patched")
    high = sum(1 for item in findings if item.get("severity") == "high")
    cols = st.columns(4)
    cols[0].metric("Findings", len(findings))
    cols[1].metric("High severity", high)
    cols[2].metric("Patch proposals", len(patches))
    cols[3].metric("Patched", patched)
    st.caption(f"Repo path: {report.get('repo_path', '(unknown)')}")


def _render_findings(findings: list[dict]) -> None:
    if not findings:
        st.success("No findings in this report.")
        return

    rows = [
        {
            "rule": item.get("rule_id"),
            "severity": item.get("severity"),
            "confidence": item.get("confidence"),
            "file": item.get("file"),
            "line": item.get("line"),
            "title": item.get("title"),
        }
        for item in findings
    ]
    st.dataframe(rows, use_container_width=True, hide_index=True)

    selected = _select_finding(findings, "finding-detail")
    if selected:
        st.subheader(selected.get("title", selected.get("rule_id", "Finding")))
        st.code(selected.get("snippet", ""), language="python")
        st.write(selected.get("message", ""))
        st.json(selected.get("target_region", {}))
        _render_behavior_path(selected)


def _render_context(findings: list[dict]) -> None:
    selected = _select_finding(findings, "context-detail")
    if not selected:
        st.info("No findings with context to display.")
        return

    context = selected.get("codegraph_context") or {}
    if not context:
        st.warning("This finding has no CodeGraph or fallback context.")
        return

    cols = st.columns(3)
    cols[0].metric("Provider", context.get("provider", "codegraph" if not context.get("fallback") else "fallback"))
    cols[1].metric("Confidence", context.get("confidence", "n/a"))
    cols[2].metric("Symbol", context.get("symbol") or "n/a")

    left, right = st.columns(2)
    with left:
        st.subheader("Callers")
        st.json(context.get("callers", []))
        st.subheader("Importers")
        st.json(context.get("importers", []))
    with right:
        st.subheader("References")
        st.json(context.get("references", []))
        st.subheader("File impact")
        st.json(context.get("file_impact", {}))


def _render_diffs(findings: list[dict], patches: list[dict], verification: list[dict]) -> None:
    if not patches:
        st.info("No patch proposals in this report.")
        return

    findings_by_id = {item.get("id"): item for item in findings}
    verification_by_id = {item.get("finding_id"): item for item in verification}
    labels = [
        f"{patch.get('finding_id', 'unknown')} - {patch.get('action', 'needs_review')}"
        for patch in patches
    ]
    choice = st.selectbox("Patch", labels)
    patch = patches[labels.index(choice)]
    finding = findings_by_id.get(patch.get("finding_id"), {})
    result = verification_by_id.get(patch.get("finding_id"), {})

    st.write(f"Rule: {finding.get('rule_id', 'unknown')}")
    st.write(f"Rationale: {patch.get('rationale', '')}")
    st.write(f"Expected risk reduction: {patch.get('expected_risk_reduction', '')}")
    st.code(result.get("diff") or _proposal_preview(patch), language="diff")


def _render_verification(verification: list[dict]) -> None:
    if not verification:
        st.info("No verification results in this report.")
        return

    rows = [
        {
            "finding_id": item.get("finding_id"),
            "status": item.get("status"),
            "before": item.get("before_severity"),
            "after": item.get("after_severity"),
            "scanner_passed": item.get("scanner_passed"),
            "tests_passed": item.get("tests_passed"),
            "notes": item.get("notes"),
        }
        for item in verification
    ]
    st.dataframe(rows, use_container_width=True, hide_index=True)


def _select_finding(findings: list[dict], key: str) -> dict | None:
    if not findings:
        return None
    labels = [
        f"{item.get('rule_id', 'UNKNOWN')} - {item.get('file', '')}:{item.get('line', '')}"
        for item in findings
    ]
    choice = st.selectbox("Finding", labels, key=key)
    return findings[labels.index(choice)]


def _render_behavior_path(finding: dict) -> None:
    path = finding.get("behavior_path") or []
    if not path:
        return
    st.subheader("Behavior path")
    for step in path:
        st.write(f"- {step}")


def _proposal_preview(patch: dict) -> str:
    replacement = patch.get("replacement", "")
    if not replacement:
        return "(empty replacement)"
    return "\n".join(f"+ {line}" for line in replacement.splitlines())


if __name__ == "__main__":
    main()
