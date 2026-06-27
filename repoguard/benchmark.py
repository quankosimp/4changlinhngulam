from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from repoguard.scanner import scan


@dataclass(frozen=True)
class BenchmarkRun:
    out_dir: Path
    metrics: dict[str, Any]
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
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    out_path = Path(out_dir).resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    case_results = []
    failures = []
    findings_rows = []
    for case in manifest.get("cases", []):
        case_path = _resolve_case_path(manifest_file, case["path"])
        include_dead_code = case.get("category") == "dead_code"
        findings = [item.to_dict() for item in scan(str(case_path), include_dead_code=include_dead_code)]
        actual = {item["rule_id"] for item in findings}
        expected = set(case.get("expected_rules", []))
        missed = sorted(expected - actual)
        is_benign = case.get("label") == "benign"
        result = {
            "repo_id": case["repo_id"],
            "path": case["path"],
            "label": case["label"],
            "category": case.get("category", "uncategorized"),
            "expected_rules": sorted(expected),
            "actual_rules": sorted(actual),
            "missed_rules": missed,
            "findings": findings,
        }
        case_results.append(result)
        findings_rows.extend({"repo_id": case["repo_id"], **item} for item in findings)
        if missed:
            failures.append(_failure(case, "scanner", f"missed rules: {', '.join(missed)}"))
        high_benign_findings = [item for item in findings if item.get("severity") == "high"]
        if is_benign and high_benign_findings:
            failures.append(_failure(case, "scanner", f"false positives: {', '.join(sorted(actual))}"))

    metrics = _metrics(case_results, failures, strict)
    _write_json(out_path / "metrics.json", metrics)
    _write_json(out_path / "case_results.json", case_results)
    _write_json(out_path / "findings.json", findings_rows)
    _write_failures(out_path / "failures.csv", failures)
    return BenchmarkRun(out_path, metrics, failures)


def print_summary(run: BenchmarkRun) -> None:
    scanner = run.metrics["scanner"]
    print(f"Benchmark report: {run.out_dir}")
    print(f"Cases: {run.metrics['total_cases']} | Passed: {run.metrics['passed']}")
    print(
        "Scanner: "
        f"expected-rule recall={scanner['expected_rule_recall']:.2%}, "
        f"benign FPR={scanner['benign_false_positive_rate']:.2%}"
    )
    print(f"Failures: {len(run.failures)}")


def _resolve_case_path(manifest_file: Path, raw_path: str) -> Path:
    path = Path(raw_path)
    if path.is_absolute():
        return path
    manifest_relative = manifest_file.parent / path
    if manifest_relative.exists():
        return manifest_relative
    return Path.cwd() / path


def _metrics(
    case_results: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    strict: bool,
) -> dict[str, Any]:
    expected = [case for case in case_results if case["expected_rules"]]
    expected_passed = [case for case in expected if not case["missed_rules"]]
    benign = [case for case in case_results if case["label"] == "benign"]
    benign_fp = [
        case
        for case in benign
        if any(item.get("severity") == "high" for item in case["findings"])
    ]
    recall = len(expected_passed) / len(expected) if expected else 1.0
    fpr = len(benign_fp) / len(benign) if benign else 0.0
    threshold_passed = recall >= 0.9 and fpr <= 0.15
    return {
        "total_cases": len(case_results),
        "strict": strict,
        "passed": threshold_passed if strict else True,
        "scanner": {
            "expected_cases": len(expected),
            "expected_cases_passed": len(expected_passed),
            "expected_rule_recall": recall,
            "benign_false_positive_cases": len(benign_fp),
            "benign_false_positive_rate": fpr,
        },
        "failure_count": len(failures),
    }


def _failure(case: dict[str, Any], stage: str, message: str) -> dict[str, Any]:
    return {
        "repo_id": case["repo_id"],
        "path": case["path"],
        "label": case["label"],
        "category": case.get("category", "uncategorized"),
        "stage": stage,
        "message": message,
    }


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_failures(path: Path, failures: list[dict[str, Any]]) -> None:
    fields = ["repo_id", "path", "label", "category", "stage", "message"]
    with path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fields)
        writer.writeheader()
        writer.writerows(failures)
