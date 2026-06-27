from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

import streamlit as st


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REPORT = REPO_ROOT / "report.json"
SAMPLE_REPORT = REPO_ROOT / "sample_report.json"
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
SEVERITY_COLORS = {
    "high": "#c62828",
    "medium": "#ef6c00",
    "low": "#2e7d32",
}
REQUIRED_FINDING_FIELDS = (
    "rule_id",
    "title",
    "severity",
    "confidence",
    "file",
    "line",
    "snippet",
    "message",
)


def load_report(path: Path) -> tuple[dict[str, Any], list[str]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    warnings: list[str] = []

    if isinstance(raw, list):
        findings_raw = raw
        repo_path = ""
        patches_raw = []
        verification_raw = []
    elif isinstance(raw, dict) and isinstance(raw.get("findings"), list):
        findings_raw = raw["findings"]
        repo_path = str(raw.get("repo_path", ""))
        patches_raw = raw.get("patches", [])
        verification_raw = raw.get("verification", [])
    else:
        raise ValueError("Report must be a list or an object with a 'findings' list.")

    findings = [
        finding
        for index, item in enumerate(findings_raw, start=1)
        if (finding := normalize_finding(item, index, warnings)) is not None
    ]
    findings.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], 99),
            -item["confidence"],
            item["file"],
            item["line"],
        )
    )

    patches = normalize_records(patches_raw, "patch", warnings)
    verification = normalize_records(verification_raw, "verification", warnings)

    return (
        {
            "repo_path": repo_path,
            "findings": findings,
            "patches": patches,
            "verification": verification,
        },
        warnings,
    )


def normalize_finding(
    item: Any, index: int, warnings: list[str]
) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        warnings.append(f"Finding #{index} is not an object and was skipped.")
        return None

    finding = dict(item)
    for field in REQUIRED_FINDING_FIELDS:
        if field not in finding:
            warnings.append(f"Finding #{index} is missing '{field}'.")

    finding["rule_id"] = str(finding.get("rule_id", "UNKNOWN"))
    finding["title"] = str(finding.get("title", "Untitled finding"))
    finding["severity"] = normalize_severity(finding.get("severity"))
    finding["confidence"] = normalize_confidence(finding.get("confidence"))
    finding["file"] = str(finding.get("file", "unknown"))
    finding["line"] = normalize_line(finding.get("line"))
    finding["snippet"] = str(finding.get("snippet", ""))
    finding["message"] = str(finding.get("message", ""))
    finding["id"] = str(
        finding.get("id")
        or f"{finding['rule_id']}:{finding['file']}:{finding['line']}"
    )
    finding["category"] = normalize_category(finding.get("category"), finding["rule_id"])
    finding["target_region"] = normalize_target_region(
        finding.get("target_region"), finding["file"], finding["line"]
    )
    finding["behavior_path"] = normalize_string_list(
        finding.get("behavior_path", finding.get("call_path"))
    )
    finding["codegraph_context"] = normalize_dict(finding.get("codegraph_context"))
    finding["evidence"] = normalize_evidence(finding.get("evidence"), finding)
    return finding


def normalize_records(
    records: Any, label: str, warnings: list[str]
) -> list[dict[str, Any]]:
    if records is None:
        return []
    if not isinstance(records, list):
        warnings.append(f"Report '{label}' field is not a list and was ignored.")
        return []

    normalized = []
    for index, item in enumerate(records, start=1):
        if not isinstance(item, dict):
            warnings.append(f"{label.title()} #{index} is not an object and was skipped.")
            continue
        normalized.append(dict(item))
    return normalized


def normalize_severity(value: Any) -> str:
    severity = str(value or "low").lower()
    return severity if severity in SEVERITY_ORDER else "low"


def normalize_category(value: Any, rule_id: str) -> str:
    if value:
        return str(value)
    rule = rule_id.upper()
    if "UNUSED" in rule or "DEAD" in rule:
        return "dead_code"
    if "EXFIL" in rule or "SHELL" in rule or "PICKLE" in rule:
        return "security"
    return "malware"


def normalize_confidence(value: Any) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, confidence))


def normalize_line(value: Any) -> int:
    try:
        line = int(value)
    except (TypeError, ValueError):
        return 1
    return max(1, line)


def normalize_target_region(value: Any, file: str, line: int) -> dict[str, Any]:
    if isinstance(value, dict):
        start_line = normalize_line(value.get("start_line", line))
        end_line = normalize_line(value.get("end_line", start_line))
        return {
            "file": str(value.get("file", file)),
            "start_line": min(start_line, end_line),
            "end_line": max(start_line, end_line),
        }
    return {"file": file, "start_line": line, "end_line": line}


def normalize_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(step) for step in value if step is not None]
    return [str(value)]


def normalize_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def normalize_evidence(value: Any, finding: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [dict(item) for item in value if isinstance(item, dict)]
    return [
        {
            "file": finding["file"],
            "line": finding["line"],
            "snippet": finding["snippet"],
            "message": finding["message"],
        }
    ]


def resolve_report_path(input_value: str) -> Path:
    path = Path(input_value).expanduser()
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path


def filter_findings(
    findings: list[dict[str, Any]],
    severities: list[str],
    categories: list[str],
    rules: list[str],
    query: str,
) -> list[dict[str, Any]]:
    query = query.strip().lower()
    result = []

    for finding in findings:
        if severities and finding["severity"] not in severities:
            continue
        if categories and finding["category"] not in categories:
            continue
        if rules and finding["rule_id"] not in rules:
            continue
        searchable = " ".join(
            [
                finding["id"],
                finding["file"],
                finding["rule_id"],
                finding["title"],
                finding["message"],
                finding["snippet"],
                finding["category"],
            ]
        ).lower()
        if query and query not in searchable:
            continue
        result.append(finding)

    return result


def findings_to_csv(findings: list[dict[str, Any]]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "id",
            "category",
            "severity",
            "confidence",
            "rule_id",
            "title",
            "file",
            "line",
            "target_region",
            "message",
            "snippet",
            "behavior_path",
        ],
    )
    writer.writeheader()
    for finding in findings:
        row = dict(finding)
        target = finding["target_region"]
        row["target_region"] = (
            f"{target['file']}:{target['start_line']}-{target['end_line']}"
        )
        row["behavior_path"] = " -> ".join(finding.get("behavior_path") or [])
        writer.writerow({key: row.get(key, "") for key in writer.fieldnames})
    return output.getvalue()


def metric_summary(
    findings: list[dict[str, Any]],
    patches: list[dict[str, Any]],
    verification: list[dict[str, Any]],
) -> None:
    total = len(findings)
    high = sum(1 for item in findings if item["severity"] == "high")
    medium = sum(1 for item in findings if item["severity"] == "medium")
    avg_confidence = (
        sum(item["confidence"] for item in findings) / total if total else 0.0
    )
    patched = sum(1 for item in verification if item.get("status") == "patched")

    cols = st.columns(5)
    cols[0].metric("Findings", total)
    cols[1].metric("High", high)
    cols[2].metric("Medium", medium)
    cols[3].metric("Patches", len(patches))
    cols[4].metric("Verified", f"{patched}/{len(verification)}")
    st.caption(f"Average confidence: {avg_confidence:.0%}")


def severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#555")
    return (
        f"<span style='background:{color};color:white;padding:0.15rem 0.45rem;"
        f"border-radius:4px;font-size:0.75rem;font-weight:700;"
        f"text-transform:uppercase'>{severity}</span>"
    )


def records_by_finding_id(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        finding_id = str(record.get("finding_id", ""))
        if not finding_id:
            continue
        grouped.setdefault(finding_id, []).append(record)
    return grouped


def render_finding(finding: dict[str, Any]) -> None:
    location = f"{finding['file']}:{finding['line']}"
    target = finding["target_region"]
    label = (
        f"{finding['severity'].upper()} | {finding['category']} | "
        f"{finding['rule_id']} | {finding['title']} | {location}"
    )

    with st.expander(label):
        st.markdown(severity_badge(finding["severity"]), unsafe_allow_html=True)
        st.write(f"**Confidence:** {finding['confidence']:.0%}")
        st.progress(finding["confidence"])
        st.write(f"**Finding ID:** `{finding['id']}`")
        st.write(f"**Location:** `{location}`")
        st.write(
            "**Target region:** "
            f"`{target['file']}:{target['start_line']}-{target['end_line']}`"
        )
        st.write(f"**Message:** {finding['message']}")

        if finding["snippet"]:
            st.code(finding["snippet"], language="python")
        else:
            st.caption("No snippet provided.")

        behavior_path = finding.get("behavior_path") or []
        if behavior_path:
            st.write("**Behavior path:**")
            for index, step in enumerate(behavior_path, start=1):
                st.write(f"{index}. `{step}`")
        else:
            st.caption("No behavior path for this finding.")


def render_findings_tab(findings: list[dict[str, Any]]) -> None:
    st.subheader(f"Findings ({len(findings)})")
    if not findings:
        st.info("No findings match the current filters.")
        return
    for finding in findings:
        render_finding(finding)


def render_codegraph_tab(findings: list[dict[str, Any]]) -> None:
    st.subheader("CodeGraph Context")
    context_findings = [item for item in findings if item.get("codegraph_context")]
    if not context_findings:
        st.info("No CodeGraph context in this report.")
        return

    for finding in context_findings:
        with st.expander(f"{finding['id']} | {finding['title']}"):
            context = finding["codegraph_context"]
            for key, value in context.items():
                st.write(f"**{key}:**")
                if isinstance(value, list):
                    if value:
                        for item in value:
                            st.write(f"- `{item}`")
                    else:
                        st.caption("[]")
                elif isinstance(value, dict):
                    st.json(value)
                else:
                    st.write(value)


def render_patch_tab(
    findings: list[dict[str, Any]],
    patches: list[dict[str, Any]],
    verification: list[dict[str, Any]],
) -> None:
    st.subheader("Patch Diff")
    patch_map = records_by_finding_id(patches)
    verification_map = records_by_finding_id(verification)

    if not patches:
        st.info("No patch proposals in this report.")
        return

    for finding in findings:
        finding_patches = patch_map.get(finding["id"], [])
        if not finding_patches:
            continue

        with st.expander(f"{finding['id']} | {finding['title']}"):
            for patch in finding_patches:
                st.write(f"**Action:** `{patch.get('action', 'unknown')}`")
                st.write(f"**File:** `{patch.get('file', finding['file'])}`")
                st.write(
                    "**Range:** "
                    f"`{patch.get('start_line', '?')}-{patch.get('end_line', '?')}`"
                )
                if patch.get("rationale"):
                    st.write(f"**Rationale:** {patch['rationale']}")
                if patch.get("expected_risk_reduction"):
                    st.write(
                        "**Expected risk reduction:** "
                        f"{patch['expected_risk_reduction']}"
                    )
                if patch.get("replacement") is not None:
                    st.write("**Replacement:**")
                    st.code(str(patch.get("replacement", "")), language="python")

            for result in verification_map.get(finding["id"], []):
                diff = result.get("diff")
                if diff:
                    st.write("**Diff:**")
                    st.code(str(diff), language="diff")


def render_verification_tab(
    findings: list[dict[str, Any]], verification: list[dict[str, Any]]
) -> None:
    st.subheader("Verification")
    if not verification:
        st.info("No verification results in this report.")
        return

    finding_titles = {finding["id"]: finding["title"] for finding in findings}
    for result in verification:
        finding_id = str(result.get("finding_id", "unknown"))
        title = finding_titles.get(finding_id, "Unknown finding")
        status = str(result.get("status", "unknown"))
        with st.expander(f"{status.upper()} | {finding_id} | {title}"):
            st.write(f"**Before severity:** `{result.get('before_severity', '')}`")
            st.write(f"**After severity:** `{result.get('after_severity', '')}`")
            st.write(f"**Scanner passed:** `{result.get('scanner_passed')}`")
            st.write(f"**Tests passed:** `{result.get('tests_passed')}`")
            if result.get("notes"):
                st.write(f"**Notes:** {result['notes']}")
            if result.get("diff"):
                st.write("**Diff:**")
                st.code(str(result["diff"]), language="diff")


def main() -> None:
    st.set_page_config(page_title="RepoGuard Dashboard", layout="wide")
    st.title("RepoGuard Dashboard")

    default_path = DEFAULT_REPORT if DEFAULT_REPORT.exists() else SAMPLE_REPORT

    with st.sidebar:
        st.header("Report")
        report_input = st.text_input(
            "JSON report path",
            value=str(default_path.relative_to(REPO_ROOT))
            if default_path.is_relative_to(REPO_ROOT)
            else str(default_path),
        )

    report_path = resolve_report_path(report_input)

    if not report_path.exists():
        st.error(f"Report not found: {report_path}")
        st.stop()

    try:
        report, warnings = load_report(report_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        st.error(f"Could not load report: {exc}")
        st.stop()

    findings = report["findings"]
    patches = report["patches"]
    verification = report["verification"]

    if report.get("repo_path"):
        st.caption(f"Repo: `{report['repo_path']}`")

    if warnings:
        with st.sidebar.expander("Schema warnings", expanded=False):
            for warning in warnings:
                st.warning(warning)

    metric_summary(findings, patches, verification)

    all_rules = sorted({finding["rule_id"] for finding in findings})
    all_categories = sorted({finding["category"] for finding in findings})
    with st.sidebar:
        st.header("Filters")
        severities = st.multiselect(
            "Severity",
            options=["high", "medium", "low"],
            default=["high", "medium", "low"],
        )
        categories = st.multiselect(
            "Category", options=all_categories, default=all_categories
        )
        rules = st.multiselect("Rule", options=all_rules, default=all_rules)
        query = st.text_input("Search")

    filtered = filter_findings(findings, severities, categories, rules, query)

    export_cols = st.columns([1, 1, 4])
    export_cols[0].download_button(
        "Export JSON",
        data=json.dumps(
            {
                "repo_path": report.get("repo_path", ""),
                "findings": filtered,
                "patches": patches,
                "verification": verification,
            },
            indent=2,
        ),
        file_name="repoguard-report.json",
        mime="application/json",
        disabled=not filtered,
    )
    export_cols[1].download_button(
        "Export CSV",
        data=findings_to_csv(filtered),
        file_name="repoguard-findings.csv",
        mime="text/csv",
        disabled=not filtered,
    )

    tabs = st.tabs(["Findings", "CodeGraph Context", "Patch Diff", "Verification"])
    with tabs[0]:
        render_findings_tab(filtered)
    with tabs[1]:
        render_codegraph_tab(filtered)
    with tabs[2]:
        render_patch_tab(filtered, patches, verification)
    with tabs[3]:
        render_verification_tab(filtered, verification)


if __name__ == "__main__":
    main()
