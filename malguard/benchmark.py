from __future__ import annotations

import csv
import importlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from malguard.scanner import scan


DEFAULT_THRESHOLDS = {
    "scanner_expected_rule_recall": 0.90,
    "benign_false_positive_rate": 0.15,
    "graph_expected_case_recall": 0.70,
    "agent_query_success_rate": 0.70,
}


@dataclass(frozen=True)
class BenchmarkRun:
    out_dir: Path
    metrics: dict[str, Any]
    case_results: list[dict[str, Any]]
    failures: list[dict[str, Any]]

    @property
    def passed(self) -> bool:
        return bool(self.metrics.get("passed"))


def run_benchmark(
    manifest_path: str,
    out_dir: str = "benchmark_reports/latest",
    strict: bool = False,
) -> BenchmarkRun:
    manifest_file = Path(manifest_path).resolve()
    out_path = Path(out_dir).resolve()
    manifest = _load_json(manifest_file)
    cases = manifest.get("cases", [])

    out_path.mkdir(parents=True, exist_ok=True)

    case_results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []

    graph_runner = _load_optional_graph_runner()
    agent_runner = _load_optional_agent_runner()

    for case in cases:
        case_path = _resolve_case_path(case["path"], manifest_file)
        scanner_result = _run_scanner_case(case, case_path)
        graph_result = _run_graph_case(case, case_path, graph_runner)
        agent_result = _run_agent_case(case, case_path, agent_runner)

        result = {
            "repo_id": case["repo_id"],
            "path": case["path"],
            "label": case["label"],
            "category": case.get("category", "uncategorized"),
            "source": case.get("source", "unknown"),
            "notes": case.get("notes", ""),
            "scanner": scanner_result,
            "graph": graph_result,
            "agent": agent_result,
        }
        case_results.append(result)
        all_findings.extend(
            {
                "repo_id": case["repo_id"],
                "stage": "scanner",
                **finding,
            }
            for finding in scanner_result["findings"]
        )
        all_findings.extend(
            {
                "repo_id": case["repo_id"],
                "stage": "graph",
                **finding,
            }
            for finding in graph_result.get("findings", [])
        )
        failures.extend(_case_failures(case, result))

    metrics = _build_metrics(case_results, failures, strict)
    _write_outputs(out_path, manifest, metrics, case_results, all_findings, failures)
    return BenchmarkRun(out_path, metrics, case_results, failures)


def print_summary(run: BenchmarkRun) -> None:
    scanner = run.metrics["scanner"]
    graph = run.metrics["graph"]
    agent = run.metrics["agent"]
    print(f"Benchmark report: {run.out_dir}")
    print(f"Cases: {run.metrics['total_cases']} | Passed: {run.metrics['passed']}")
    print(
        "Scanner: "
        f"expected-rule recall={scanner['expected_rule_recall']:.2%}, "
        f"benign FPR={scanner['benign_false_positive_rate']:.2%}"
    )
    print(
        "Graph: "
        f"status={graph['status']}, "
        f"expected-case recall={graph['expected_case_recall']:.2%}"
    )
    print(
        "Agent: "
        f"status={agent['status']}, "
        f"query success={agent['query_success_rate']:.2%}"
    )
    print(f"Failures: {len(run.failures)}")


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def _resolve_case_path(raw_path: str, manifest_file: Path) -> Path:
    path = Path(raw_path)
    if path.is_absolute():
        return path

    manifest_relative = manifest_file.parent / path
    if manifest_relative.exists():
        return manifest_relative

    cwd_relative = Path.cwd() / path
    if cwd_relative.exists():
        return cwd_relative

    return manifest_relative


def _run_scanner_case(case: dict[str, Any], case_path: Path) -> dict[str, Any]:
    expected_rules = set(case.get("expected_rules", []))
    findings = [finding.to_dict() for finding in scan(str(case_path))]
    actual_rules = {finding["rule_id"] for finding in findings}
    missed_rules = sorted(expected_rules - actual_rules)
    unexpected_rules = sorted(actual_rules - expected_rules)
    is_benign = case.get("label") == "benign"

    return {
        "status": "ok",
        "findings": findings,
        "actual_rules": sorted(actual_rules),
        "expected_rules": sorted(expected_rules),
        "missed_rules": missed_rules,
        "unexpected_rules": unexpected_rules,
        "passed": (not missed_rules) and (not is_benign or not findings),
    }


def _load_optional_graph_runner() -> Callable[[Path], list[dict[str, Any]]] | None:
    try:
        graph_rules = importlib.import_module("malguard.rules.graph_rules")
    except ImportError:
        return None

    for name in ("scan_repo", "scan", "detect_repo"):
        runner = getattr(graph_rules, name, None)
        if callable(runner):
            return lambda repo_path, fn=runner: _normalize_findings(fn(str(repo_path)))
    return None


def _load_optional_agent_runner() -> Callable[[Path, str], dict[str, Any]] | None:
    try:
        agent = importlib.import_module("malguard.agent")
    except ImportError:
        return None

    for name in ("answer_query", "run_query", "query"):
        runner = getattr(agent, name, None)
        if callable(runner):
            return lambda repo_path, query, fn=runner: _call_agent(fn, repo_path, query)
    return None


def _run_graph_case(
    case: dict[str, Any],
    case_path: Path,
    runner: Callable[[Path], list[dict[str, Any]]] | None,
) -> dict[str, Any]:
    expected = set(case.get("expected_graph_rules", []))
    if not expected and runner is None:
        return {"status": "not_required", "findings": [], "passed": True}
    if runner is None:
        return {
            "status": "skipped",
            "findings": [],
            "expected_rules": sorted(expected),
            "missed_rules": sorted(expected),
            "passed": False,
            "error": "malguard.rules.graph_rules is not available",
        }

    try:
        findings = runner(case_path)
    except Exception as exc:
        return {
            "status": "error",
            "findings": [],
            "expected_rules": sorted(expected),
            "missed_rules": sorted(expected),
            "passed": False,
            "error": str(exc),
        }

    actual = {finding.get("rule_id", "") for finding in findings}
    missed = sorted(expected - actual)
    return {
        "status": "ok",
        "findings": findings,
        "actual_rules": sorted(rule for rule in actual if rule),
        "expected_rules": sorted(expected),
        "missed_rules": missed,
        "passed": not missed,
    }


def _run_agent_case(
    case: dict[str, Any],
    case_path: Path,
    runner: Callable[[Path, str], dict[str, Any]] | None,
) -> dict[str, Any]:
    queries = case.get("agent_queries", [])
    if not queries:
        return {"status": "not_required", "queries": [], "passed": True}
    if runner is None:
        return {
            "status": "skipped",
            "queries": [
                {
                    "query": item.get("query", ""),
                    "passed": False,
                    "error": "malguard.agent is not available",
                }
                for item in queries
            ],
            "passed": False,
        }

    results = []
    for item in queries:
        query = item.get("query", "")
        try:
            response = runner(case_path, query)
            passed = _agent_response_matches(response, item)
            results.append(
                {
                    "query": query,
                    "passed": passed,
                    "expected_rules": item.get("expected_rules", []),
                    "expected_files": item.get("expected_files", []),
                    "response": response,
                }
            )
        except Exception as exc:
            results.append({"query": query, "passed": False, "error": str(exc)})

    return {
        "status": "ok",
        "queries": results,
        "passed": all(item["passed"] for item in results),
    }


def _normalize_findings(raw: Any) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, dict) and "findings" in raw:
        raw = raw["findings"]
    if not isinstance(raw, list):
        raw = [raw]

    normalized = []
    for item in raw:
        if hasattr(item, "to_dict"):
            normalized.append(item.to_dict())
        elif isinstance(item, dict):
            normalized.append(item)
    return normalized


def _call_agent(fn: Callable[..., Any], repo_path: Path, query: str) -> dict[str, Any]:
    attempts = (
        lambda: fn(query=query, path=str(repo_path)),
        lambda: fn(query=query, repo_path=str(repo_path)),
        lambda: fn(query, str(repo_path)),
        lambda: fn(str(repo_path), query),
        lambda: fn(query),
    )
    last_error: TypeError | None = None
    for attempt in attempts:
        try:
            raw = attempt()
            return raw if isinstance(raw, dict) else {"raw": raw}
        except TypeError as exc:
            last_error = exc
    raise last_error or TypeError("Unsupported agent runner signature")


def _agent_response_matches(response: dict[str, Any], expected: dict[str, Any]) -> bool:
    text = json.dumps(response, ensure_ascii=False).lower()
    expected_rules = [rule.lower() for rule in expected.get("expected_rules", [])]
    expected_files = [file.lower() for file in expected.get("expected_files", [])]
    return all(rule in text for rule in expected_rules) and all(
        file in text for file in expected_files
    )


def _case_failures(case: dict[str, Any], result: dict[str, Any]) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    scanner = result["scanner"]
    graph = result["graph"]
    agent = result["agent"]

    if scanner["missed_rules"]:
        failures.append(
            _failure(case, "scanner", f"missed rules: {', '.join(scanner['missed_rules'])}")
        )
    if case["label"] == "benign" and scanner["findings"]:
        failures.append(
            _failure(
                case,
                "scanner",
                f"false positive rules: {', '.join(scanner['actual_rules'])}",
            )
        )
    if case.get("expected_graph_rules") and not graph["passed"]:
        failures.append(_failure(case, "graph", graph.get("error", "missed graph rule")))
    if case.get("agent_queries") and not agent["passed"]:
        failures.append(_failure(case, "agent", agent.get("status", "query failed")))
    return failures


def _failure(case: dict[str, Any], stage: str, message: str) -> dict[str, Any]:
    return {
        "repo_id": case["repo_id"],
        "path": case["path"],
        "label": case["label"],
        "category": case.get("category", "uncategorized"),
        "stage": stage,
        "message": message,
    }


def _build_metrics(
    case_results: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    strict: bool,
) -> dict[str, Any]:
    benign_cases = [case for case in case_results if case["label"] == "benign"]
    scanner_expected = [
        case for case in case_results if case["scanner"]["expected_rules"]
    ]
    scanner_passed = [case for case in scanner_expected if not case["scanner"]["missed_rules"]]
    benign_fp = [case for case in benign_cases if case["scanner"]["findings"]]

    graph_expected = [
        case for case in case_results if case["graph"].get("expected_rules")
    ]
    graph_passed = [case for case in graph_expected if case["graph"]["passed"]]
    agent_expected = [
        query
        for case in case_results
        for query in case["agent"].get("queries", [])
    ]
    agent_passed = [query for query in agent_expected if query.get("passed")]

    scanner_recall = _ratio(len(scanner_passed), len(scanner_expected))
    benign_fpr = _ratio(len(benign_fp), len(benign_cases))
    graph_recall = _ratio(len(graph_passed), len(graph_expected))
    agent_success = _ratio(len(agent_passed), len(agent_expected))

    thresholds = DEFAULT_THRESHOLDS.copy()
    passed_thresholds = {
        "scanner_expected_rule_recall": scanner_recall
        >= thresholds["scanner_expected_rule_recall"],
        "benign_false_positive_rate": benign_fpr <= thresholds["benign_false_positive_rate"],
        "graph_expected_case_recall": (
            True
            if not graph_expected
            else graph_recall >= thresholds["graph_expected_case_recall"]
        ),
        "agent_query_success_rate": (
            True
            if not agent_expected
            else agent_success >= thresholds["agent_query_success_rate"]
        ),
    }

    return {
        "total_cases": len(case_results),
        "malicious_cases": len([case for case in case_results if case["label"] == "malicious"]),
        "benign_cases": len(benign_cases),
        "strict": strict,
        "passed": all(passed_thresholds.values()) if strict else True,
        "thresholds": thresholds,
        "threshold_results": passed_thresholds,
        "scanner": {
            "expected_cases": len(scanner_expected),
            "expected_cases_passed": len(scanner_passed),
            "expected_rule_recall": scanner_recall,
            "benign_false_positive_cases": len(benign_fp),
            "benign_false_positive_rate": benign_fpr,
        },
        "graph": {
            "status": "available" if graph_expected and any(
                case["graph"]["status"] == "ok" for case in graph_expected
            ) else ("not_required" if not graph_expected else "skipped_or_error"),
            "expected_cases": len(graph_expected),
            "expected_cases_passed": len(graph_passed),
            "expected_case_recall": graph_recall,
        },
        "agent": {
            "status": "available" if agent_expected and any(
                case["agent"]["status"] == "ok" for case in case_results
            ) else ("not_required" if not agent_expected else "skipped_or_error"),
            "expected_queries": len(agent_expected),
            "expected_queries_passed": len(agent_passed),
            "query_success_rate": agent_success,
        },
        "failure_count": len(failures),
        "dashboard_renderable": True,
    }


def _ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 1.0
    return numerator / denominator


def _write_outputs(
    out_dir: Path,
    manifest: dict[str, Any],
    metrics: dict[str, Any],
    case_results: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    failures: list[dict[str, Any]],
) -> None:
    _write_json(out_dir / "manifest_snapshot.json", manifest)
    _write_json(out_dir / "metrics.json", metrics)
    _write_json(out_dir / "case_results.json", case_results)
    _write_json(out_dir / "findings.json", findings)
    _write_failures_csv(out_dir / "failures.csv", failures)


def _write_json(path: Path, payload: Any) -> None:
    with path.open("w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=2)


def _write_failures_csv(path: Path, failures: list[dict[str, Any]]) -> None:
    fields = ["repo_id", "path", "label", "category", "stage", "message"]
    with path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fields)
        writer.writeheader()
        writer.writerows(failures)
