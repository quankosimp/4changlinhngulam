from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import streamlit as st


DEFAULT_REPORT_DIR = "benchmark_reports/latest"


st.set_page_config(page_title="Malguard Benchmark", layout="wide")
st.title("Malguard Benchmark")

report_dir = Path(st.sidebar.text_input("Report directory", DEFAULT_REPORT_DIR)).resolve()


def load_json(name: str, default: Any) -> Any:
    path = report_dir / name
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def load_failures() -> list[dict[str, str]]:
    path = report_dir / "failures.csv"
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as fp:
        return list(csv.DictReader(fp))


metrics = load_json("metrics.json", {})
case_results = load_json("case_results.json", [])
findings = load_json("findings.json", [])
failures = load_failures()

if not metrics:
    st.warning("No benchmark output found. Run `python -m malguard benchmark` first.")
    st.stop()

scanner = metrics.get("scanner", {})
graph = metrics.get("graph", {})
agent = metrics.get("agent", {})

cols = st.columns(6)
cols[0].metric("Cases", metrics.get("total_cases", 0))
cols[1].metric("Failures", metrics.get("failure_count", 0))
cols[2].metric("Scanner recall", f"{scanner.get('expected_rule_recall', 0):.1%}")
cols[3].metric("Benign FPR", f"{scanner.get('benign_false_positive_rate', 0):.1%}")
cols[4].metric("Graph recall", f"{graph.get('expected_case_recall', 0):.1%}")
cols[5].metric("Agent success", f"{agent.get('query_success_rate', 0):.1%}")

st.caption(f"Graph status: {graph.get('status', 'unknown')} | Agent status: {agent.get('status', 'unknown')}")

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

st.subheader("Rule hits")
st.bar_chart(dict(rule_counts) or {"none": 0})

st.subheader("Failure table")
st.dataframe(failures, use_container_width=True)

st.subheader("Case drill-down")
case_ids = [case["repo_id"] for case in case_results]
selected_id = st.selectbox("Case", case_ids)
selected = next(case for case in case_results if case["repo_id"] == selected_id)

summary_cols = st.columns(4)
summary_cols[0].metric("Label", selected.get("label", "unknown"))
summary_cols[1].metric("Category", selected.get("category", "unknown"))
summary_cols[2].metric("Scanner passed", str(selected.get("scanner", {}).get("passed", False)))
summary_cols[3].metric("Agent passed", str(selected.get("agent", {}).get("passed", False)))

st.write(selected.get("notes", ""))

tabs = st.tabs(["Scanner", "Graph", "Agent", "Raw"])
with tabs[0]:
    scanner_case = selected.get("scanner", {})
    st.write(
        {
            "expected_rules": scanner_case.get("expected_rules", []),
            "actual_rules": scanner_case.get("actual_rules", []),
            "missed_rules": scanner_case.get("missed_rules", []),
            "unexpected_rules": scanner_case.get("unexpected_rules", []),
        }
    )
    st.dataframe(scanner_case.get("findings", []), use_container_width=True)
with tabs[1]:
    st.json(selected.get("graph", {}))
with tabs[2]:
    st.json(selected.get("agent", {}))
with tabs[3]:
    st.json(selected)

st.subheader("Missed expected rules")
missed_rows = []
for case in case_results:
    scanner_case = case.get("scanner", {})
    for rule in scanner_case.get("missed_rules", []):
        missed_rows.append(
            {
                "repo_id": case["repo_id"],
                "category": case.get("category"),
                "stage": "scanner",
                "rule_id": rule,
            }
        )
    graph_case = case.get("graph", {})
    for rule in graph_case.get("missed_rules", []):
        missed_rows.append(
            {
                "repo_id": case["repo_id"],
                "category": case.get("category"),
                "stage": "graph",
                "rule_id": rule,
            }
        )
st.dataframe(missed_rows, use_container_width=True)

st.subheader("False positives")
false_positive_rows = []
for case in case_results:
    if case.get("label") != "benign":
        continue
    for finding in case.get("scanner", {}).get("findings", []):
        false_positive_rows.append(
            {
                "repo_id": case["repo_id"],
                "category": case.get("category"),
                "rule_id": finding.get("rule_id"),
                "file": finding.get("file"),
                "line": finding.get("line"),
                "message": finding.get("message"),
            }
        )
st.dataframe(false_positive_rows, use_container_width=True)

st.subheader("Agent query failures")
agent_failure_rows = []
for case in case_results:
    for query in case.get("agent", {}).get("queries", []):
        if query.get("passed"):
            continue
        agent_failure_rows.append(
            {
                "repo_id": case["repo_id"],
                "category": case.get("category"),
                "query": query.get("query"),
                "error": query.get("error", "expected evidence not found"),
            }
        )
st.dataframe(agent_failure_rows, use_container_width=True)
