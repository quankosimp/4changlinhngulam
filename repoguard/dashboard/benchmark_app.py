from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

import streamlit as st


DEFAULT_REPORT_DIR = "benchmark_reports/latest"


st.set_page_config(page_title="RepoGuard Benchmark", layout="wide")
st.title("RepoGuard Benchmark")


report_dir = Path(st.sidebar.text_input("Report directory", DEFAULT_REPORT_DIR)).resolve()


def _load_json(name: str, default: Any) -> Any:
    path = report_dir / name
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _load_failures() -> list[dict[str, str]]:
    path = report_dir / "failures.csv"
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as fp:
        return list(csv.DictReader(fp))


metrics = _load_json("metrics.json", {})
case_results = _load_json("case_results.json", [])
findings = _load_json("findings.json", [])
failures = _load_failures()

if not metrics:
    st.warning("No benchmark output found. Run `python -m repoguard benchmark` first.")
    st.stop()

scanner = metrics.get("scanner", {})
graph = metrics.get("graph", {})
graph_export = metrics.get("graph_export", {})
agent = metrics.get("agent", {})
patcher = metrics.get("patcher", {})
verifier = metrics.get("verifier", {})

cols = st.columns(6)
cols[0].metric("Cases", metrics.get("total_cases", 0))
cols[1].metric("Failures", metrics.get("failure_count", 0))
cols[2].metric("Scanner recall", f"{scanner.get('expected_case_recall', 0):.1%}")
cols[3].metric("Benign FPR", f"{scanner.get('benign_false_positive_rate', 0):.1%}")
cols[4].metric("Graph recall", f"{graph.get('expected_case_recall', 0):.1%}")
cols[5].metric("Verifier success", f"{verifier.get('success_rate', 0):.1%}")

st.caption(
    "Stage: "
    f"graph={graph_export.get('success_rate', 0):.1%} | "
    f"agent={agent.get('query_success_rate', 0):.1%} | "
    f"patcher={patcher.get('success_rate', 0):.1%}"
)

stage_counts = Counter(item.get("stage", "unknown") for item in failures)
category_counts = Counter(item.get("category", "unknown") for item in failures)
rule_counts = Counter(item.get("rule_id", "unknown") for item in findings)

left, right = st.columns(2)
with left:
    st.subheader("Failures by stage")
    st.bar_chart(dict(stage_counts) or {"none": 0})
with right:
    st.subheader("Failures by category")
    st.bar_chart(dict(category_counts) or {"none": 0})

st.subheader("Rule hit distribution")
st.bar_chart(dict(rule_counts) or {"none": 0})

st.subheader("Failure table")
st.dataframe(failures, use_container_width=True)

st.subheader("Case drill-down")
case_ids = [
    f"{case.get('repo_id', 'unknown')}:{case.get('path', '')}" for case in case_results
]
selected_case = st.selectbox("Case", case_ids)
selected = next(
    case
    for case in case_results
    if f"{case.get('repo_id', 'unknown')}:{case.get('path', '')}" == selected_case
)

summary_cols = st.columns(4)
summary_cols[0].metric("Label", selected.get("label", "unknown"))
summary_cols[1].metric("Category", selected.get("category", "unknown"))
summary_cols[2].metric("Scanner passed", str(selected.get("scan", {}).get("passed", False)))
summary_cols[3].metric("Graph passed", str(selected.get("graph", {}).get("passed", False)))

scan_tab, graph_tab, graph_export_tab, agent_tab, patch_tab, verify_tab, raw_tab = st.tabs(
    ["Scanner", "Graph", "Graph export", "Agent", "Patcher", "Verifier", "Raw"]
)

with scan_tab:
    st.write(
        {
            "expected_rules": selected.get("scan", {}).get("expected_rules", []),
            "actual_rules": selected.get("scan", {}).get("actual_rules", []),
            "missed_rules": selected.get("scan", {}).get("missed_rules", []),
            "unexpected_rules": selected.get("scan", {}).get("unexpected_rules", []),
        }
    )
    st.dataframe(selected.get("scan", {}).get("findings", []), use_container_width=True)

with graph_tab:
    st.json(selected.get("graph", {}))

with graph_export_tab:
    st.json(selected.get("graph_export", {}))

with agent_tab:
    st.json(selected.get("agent", {}))

with patch_tab:
    st.json(selected.get("patcher", {}))

with verify_tab:
    st.json(selected.get("verifier", {}))

with raw_tab:
    st.json(selected)

st.subheader("Missed expected rules")
rows = []
for case in case_results:
    for rule in case.get("scan", {}).get("missed_rules", []):
        rows.append(
            {
                "repo_id": case["repo_id"],
                "category": case.get("category"),
                "stage": "scanner",
                "rule_id": rule,
            }
        )
    for rule in case.get("graph", {}).get("missed_rules", []):
        rows.append(
            {
                "repo_id": case["repo_id"],
                "category": case.get("category"),
                "stage": "codegraph",
                "rule_id": rule,
            }
        )
    for rule in case.get("graph", {}).get("missing_call_paths", []):
        rows.append(
            {
                "repo_id": case["repo_id"],
                "category": case.get("category"),
                "stage": "codegraph_call_path",
                "rule_id": rule,
            }
        )
st.dataframe(rows, use_container_width=True)

st.subheader("Verifier checks")
verified_rows = []
for case in case_results:
    for item in case.get("verifier", {}).get("verifications", []):
        row = {"repo_id": case["repo_id"]}
        row.update(item)
        verified_rows.append(row)
st.dataframe(verified_rows, use_container_width=True)

st.subheader("Agent proposals")
proposal_rows: list[dict[str, Any]] = []
for case in case_results:
    for item in case.get("agent", {}).get("proposals", []):
        row = {
            "repo_id": case["repo_id"],
            "rule_id": item.get("finding_id", "").split(":", 1)[0],
        }
        row.update(item)
        proposal_rows.append(row)
st.dataframe(proposal_rows, use_container_width=True)
