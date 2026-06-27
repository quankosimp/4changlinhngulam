from __future__ import annotations

import csv
import json
import shutil
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from repoguard.agent import AgentConfigurationError, AgentResponseError
from repoguard.codegraph_client import CodeGraphClient, CodeGraphUnavailable
from repoguard.config import ConfigurationError, openai_config
from repoguard.graph_exporter import build_graph, write_graph
from repoguard.rules import graph_rules
from repoguard.scanner import scan
from repoguard.workflow import run_fix


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


BENCHMARK_THRESHOLDS = {
    "scanner_expected_rule_recall": 0.9,
    "benign_false_positive_rate": 0.15,
    "graph_expected_case_recall": 0.7,
    "graph_export_success_rate": 0.9,
    "agent_success_rate": 0.7,
    "patcher_success_rate": 0.7,
    "verifier_success_rate": 0.7,
}


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

    case_results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    findings_rows: list[dict[str, Any]] = []

    for case in manifest.get("cases", []):
        case_path = _resolve_case_path(manifest_file, case["path"])

        scan_result = _run_scan_case(case, case_path)
        graph_result = _run_graph_case(case, case_path)
        graph_export_result = _run_graph_export_case(case, case_path)
        agent_result, patcher_result, verifier_result = _run_fix_case(
            case,
            case_path,
            scan_result["findings"],
        )

        result = {
            "repo_id": case.get("repo_id", case.get("id", "unknown")),
            "path": case["path"],
            "label": case.get("label", "unknown"),
            "category": case.get("category", "uncategorized"),
            "scan": scan_result,
            "graph": graph_result,
            "graph_export": graph_export_result,
            "agent": agent_result,
            "patcher": patcher_result,
            "verifier": verifier_result,
        }
        case_results.append(result)

        findings_rows.extend(
            {
                "repo_id": result["repo_id"],
                "stage": "scanner",
                **item,
            }
            for item in scan_result["findings"]
        )
        findings_rows.extend(
            {
                "repo_id": result["repo_id"],
                "stage": "codegraph",
                **item,
            }
            for item in graph_result["findings"]
        )

        failures.extend(_case_failures(case, result))

    metrics = _metrics(case_results, failures, strict)
    _write_json(out_path / "metrics.json", metrics)
    _write_json(out_path / "case_results.json", case_results)
    _write_json(out_path / "findings.json", findings_rows)
    _write_failures(out_path / "failures.csv", failures)
    return BenchmarkRun(out_path, metrics, failures)


def print_summary(run: BenchmarkRun) -> None:
    metrics = run.metrics
    scanner = metrics["scanner"]
    graph = metrics["graph"]
    graph_export = metrics["graph_export"]
    agent = metrics["agent"]
    patcher = metrics["patcher"]
    verifier = metrics["verifier"]

    print(f"Benchmark report: {run.out_dir}")
    print(f"Cases: {metrics['total_cases']} | Passed: {run.passed}")
    print(
        "Scanner: "
        f"expected-case recall={scanner['expected_case_recall']:.2%}, "
        f"benign FPR={scanner['benign_false_positive_rate']:.2%}"
    )
    print(
        "Graph: "
        f"required cases={graph['expected_cases']}, "
        f"recall={graph['expected_case_recall']:.2%}"
    )
    print(
        "Graph export: "
        f"required cases={graph_export['expected_cases']}, "
        f"success={graph_export['success_rate']:.2%}"
    )
    print(
        "Agent: "
        f"required cases={agent['expected_cases']}, "
        f"success={agent['query_success_rate']:.2%}"
    )
    print(
        "Patcher: "
        f"required cases={patcher['expected_cases']}, "
        f"success={patcher['success_rate']:.2%}"
    )
    print(
        "Verifier: "
        f"required cases={verifier['expected_cases']}, "
        f"success={verifier['success_rate']:.2%}"
    )
    print(f"Failures: {len(run.failures)}")


def _run_scan_case(case: dict[str, Any], case_path: Path) -> dict[str, Any]:
    include_dead_code = case.get("include_dead_code")
    findings = [item.to_dict() for item in scan(str(case_path), include_dead_code=include_dead_code)]

    expected_rules = set(case.get("expected_rules", []))
    expected_findings = _normalize_expected_findings(case)
    actual_rules = {item["rule_id"] for item in findings}
    missed_rules = sorted(expected_rules - actual_rules)
    mismatches: list[str] = []

    # Support the older compact syntax.
    legacy_expected_region = case.get("expected_target_region")
    legacy_min_sev = case.get("expected_min_severity")
    if legacy_expected_region and not expected_findings and expected_rules:
        rule_hint = next(iter(expected_rules))
        expected_findings.append(
            {
                "rule_id": rule_hint,
                "target_region": legacy_expected_region,
                "expected_min_severity": legacy_min_sev,
            }
        )

    for expected in expected_findings:
        rule_id = expected.get("rule_id")
        if not rule_id:
            continue
        candidates = [item for item in findings if item["rule_id"] == rule_id]
        if not candidates:
            continue
        candidate = candidates[0]

        if not _severity_ok(candidate["severity"], expected.get("min_severity") or expected.get("expected_min_severity")):
            mismatches.append(
                f"{rule_id}: severity {candidate['severity']} below expected "
                f"{expected.get('min_severity') or expected.get('expected_min_severity')}"
            )

        if not _line_match(expected.get("target_region"), candidate["target_region"]):
            mismatches.append(
                f"{rule_id}: target region mismatch expected="
                f"{expected.get('target_region', {})} actual={candidate['target_region']}"
            )

        expected_behavior = expected.get("behavior_path_contains")
        if expected_behavior and not _contains_all(candidate.get("behavior_path", []), expected_behavior):
            mismatches.append(
                f"{rule_id}: behavior_path missing tokens {expected_behavior}"
            )

    is_benign = case.get("label") == "benign"
    high_findings = [item for item in findings if item.get("severity") == "high"]
    false_positive = bool(is_benign and high_findings)

    unexpected_rules = sorted(actual_rules - expected_rules)
    passed = (not missed_rules) and (not mismatches) and (not false_positive)

    return {
        "required": True,
        "status": "ok" if passed else "failed",
        "passed": passed,
        "expected_rules": sorted(expected_rules),
        "actual_rules": sorted(actual_rules),
        "missed_rules": missed_rules,
        "unexpected_rules": unexpected_rules,
        "target_region_mismatches": mismatches,
        "expected_findings": expected_findings,
        "findings": findings,
        "benign_high_findings": [item for item in high_findings] if is_benign else [],
    }


def _run_graph_case(case: dict[str, Any], case_path: Path) -> dict[str, Any]:
    raw = case.get("expected_codegraph")
    if raw is None and case.get("expected_graph_rules"):
        raw = {"required": True, "expected_rules": case.get("expected_graph_rules")}

    cfg = _normalize_graph_config(raw, case)
    if not cfg["required"]:
        return {
            "required": False,
            "status": "not_required",
            "passed": True,
            "expected_rules": [],
            "actual_rules": [],
            "missed_rules": [],
            "call_paths": [],
            "missing_call_paths": [],
            "findings": [],
            "codegraph_available": False,
            "error": "",
        }

    if not case_path.is_dir():
        return {
            "required": True,
            "status": "failed",
            "passed": False,
            "expected_rules": sorted(cfg.get("expected_rules", [])),
            "actual_rules": [],
            "missed_rules": list(cfg.get("expected_rules", [])),
            "call_paths": [],
            "missing_call_paths": cfg.get("required_call_paths", []),
            "findings": [],
            "codegraph_available": False,
            "error": "codegraph rules require repository path",
        }

    codegraph_available = True
    if cfg.get("require_cli"):
        try:
            client = CodeGraphClient(str(case_path))
            client.check_available()
        except CodeGraphUnavailable as exc:
            codegraph_available = False

    try:
        findings = [item.to_dict() for item in graph_rules.detect_repo(str(case_path))]
    except Exception as exc:
        return {
            "required": True,
            "status": "failed",
            "passed": False,
            "expected_rules": sorted(cfg.get("expected_rules", [])),
            "actual_rules": [],
            "missed_rules": sorted(cfg.get("expected_rules", [])),
            "call_paths": [],
            "missing_call_paths": cfg.get("required_call_paths", []),
            "findings": [],
            "codegraph_available": codegraph_available,
            "error": str(exc),
        }

    actual_rules = sorted({item["rule_id"] for item in findings})
    expected_rules = sorted(cfg.get("expected_rules", []))
    missed_rules = [item for item in expected_rules if item not in actual_rules]

    call_paths = cfg.get("required_call_paths", [])
    missing_call_paths = _missing_call_paths(findings, call_paths)

    passed = not missed_rules and not missing_call_paths
    if cfg.get("require_cli") and not codegraph_available:
        passed = False

    status = "ok" if passed else "failed"
    error = ""
    if cfg.get("require_cli") and not codegraph_available:
        error = "CodeGraph CLI required by case config but unavailable."
    return {
        "required": True,
        "status": status,
        "passed": passed,
        "expected_rules": expected_rules,
        "actual_rules": actual_rules,
        "missed_rules": missed_rules,
        "call_paths": call_paths,
        "missing_call_paths": missing_call_paths,
        "findings": findings,
        "codegraph_available": codegraph_available,
        "error": error,
    }


def _run_graph_export_case(case: dict[str, Any], case_path: Path) -> dict[str, Any]:
    cfg = _normalize_graph_export(case.get("expected_graph_export"))
    if not cfg["required"]:
        return {
            "required": False,
            "status": "not_required",
            "passed": True,
            "format": cfg.get("format", "both"),
            "written_files": [],
            "generated_count": 0,
            "error": "",
        }

    if not case_path.exists():
        return {
            "required": True,
            "status": "failed",
            "passed": False,
            "format": cfg.get("format", "both"),
            "written_files": [],
            "generated_count": 0,
            "error": "case path does not exist",
        }

    require_cli = bool(cfg.get("require_cli", False))
    if require_cli:
        try:
            CodeGraphClient(str(case_path)).check_available()
        except CodeGraphUnavailable as exc:
            return {
                "required": True,
                "status": "failed",
                "passed": False,
                "format": cfg.get("format", "both"),
                "written_files": [],
                "generated_count": 0,
                "error": str(exc),
            }

    try:
        export = build_graph(str(case_path), findings=[], require_codegraph=require_cli)
        with tempfile.TemporaryDirectory(prefix="repoguard-graph-") as tmpdir:
            written = write_graph(export, tmpdir, cfg.get("format", "both"))
        passed = bool(written)
        return {
            "required": True,
            "status": "ok" if passed else "failed",
            "passed": passed,
            "format": cfg.get("format", "both"),
            "written_files": [str(path) for path in written],
            "generated_count": len(written),
            "error": "",
        }
    except Exception as exc:
        return {
            "required": True,
            "status": "failed",
            "passed": False,
            "format": cfg.get("format", "both"),
            "written_files": [],
            "generated_count": 0,
            "error": str(exc),
        }


def _run_fix_case(
    case: dict[str, Any],
    case_path: Path,
    scan_findings: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    cfg = case.get("expected_patch")
    if not cfg:
        empty = {
            "required": False,
            "status": "not_required",
            "passed": True,
            "proposals": [],
            "error": "",
            "mode": "not_required",
        }
        return empty, empty, empty

    required = bool(cfg.get("required", False))
    if not required:
        empty = {
            "required": False,
            "status": "not_required",
            "passed": True,
            "proposals": [],
            "error": "",
            "mode": "not_required",
        }
        return empty, empty, empty

    mode = str(cfg.get("mode", "dry-run")).lower()
    apply = bool(cfg.get("apply") if cfg.get("apply") is not None else mode == "apply")
    max_rounds = _safe_int(cfg.get("max_rounds"), 1 if mode != "apply" else 3)
    max_findings = _safe_int(cfg.get("max_findings"), 1)
    target_rule = cfg.get("target_rule")
    expected_action = cfg.get("expected_action")
    expected_verification = cfg.get("expected_verification", {})

    if not scan_findings:
        payload = {
            "required": True,
            "status": "failed",
            "passed": False,
            "proposals": [],
            "error": "No findings to fix in this case.",
            "mode": mode,
            "applied": False,
        }
        return payload, payload, {
            "required": apply or bool(expected_verification),
            "status": "not_required" if not (apply or expected_verification) else "failed",
            "passed": False if (apply or expected_verification) else True,
            "verifications": [],
            "expected_verification": expected_verification,
            "error": "No findings to verify.",
        }

    if not _openai_available():
        payload = {
            "required": True,
            "status": "failed",
            "passed": False,
            "proposals": [],
            "error": "OPENAI_API_KEY is missing. Cannot run patch agent.",
            "mode": mode,
            "applied": False,
        }
        return payload, payload, {
            "required": apply or bool(expected_verification),
            "status": "failed",
            "passed": False if (apply or expected_verification) else True,
            "verifications": [],
            "expected_verification": expected_verification,
            "error": "OPENAI_API_KEY is missing.",
        }

    run_path = case_path
    cleanup = None
    if apply:
        run_path, cleanup = _copy_path_for_fix(case_path)

    try:
        fix_result = run_fix(
            str(run_path),
            apply=apply,
            max_rounds=max_rounds,
            max_findings=max_findings,
            min_severity=cfg.get("min_severity"),
            use_codegraph=False,
        )
    except (AgentConfigurationError, AgentResponseError, ConfigurationError) as exc:
        if cleanup:
            cleanup()
        payload = {
            "required": True,
            "status": "failed",
            "passed": False,
            "proposals": [],
            "error": str(exc),
            "mode": mode,
            "applied": False,
        }
        return payload, payload, {
            "required": apply or bool(expected_verification),
            "status": "failed",
            "passed": False,
            "verifications": [],
            "expected_verification": expected_verification,
            "error": str(exc),
        }

    if cleanup:
        cleanup()

    proposals = [item.to_dict() for item in fix_result.report.patches]
    applications = [
        {
            "proposal": item.proposal.to_dict(),
            "diff": item.diff,
            "applied": item.applied,
            "notes": item.notes,
        }
        for item in fix_result.applications
    ]
    verifications = [item.to_dict() for item in fix_result.report.verification]
    final_verification = verifications[-1] if verifications else {}
    fix_rounds = [item.to_dict() for item in fix_result.rounds]
    fix_status = fix_result.status

    errors: list[str] = []
    if target_rule:
        target_hit = [item for item in proposals if item["finding_id"].split(":", 1)[0] == target_rule]
        if not target_hit:
            errors.append(f"expected target_rule {target_rule} missing from proposals")

    if expected_action:
        action_hit = [item for item in proposals if item.get("action") == expected_action]
        if not action_hit:
            errors.append(f"expected action {expected_action} missing from proposals")

    if expected_verification:
        expected_status = expected_verification.get("status")
        if expected_status and final_verification.get("status") != expected_status:
            errors.append(
                f"expected verification status {expected_status}, got {final_verification.get('status')}"
            )
        if (
            "scanner_passed" in expected_verification
            and final_verification.get("scanner_passed") is not None
        ):
            if expected_verification["scanner_passed"] != final_verification.get("scanner_passed"):
                errors.append(
                    "expected verification scanner_passed="
                    f"{expected_verification['scanner_passed']} got {final_verification.get('scanner_passed')}"
                )
        if (
            "tests_passed" in expected_verification
            and final_verification.get("tests_passed") is not None
        ):
            if expected_verification["tests_passed"] != final_verification.get("tests_passed"):
                errors.append(
                    "expected verification tests_passed="
                    f"{expected_verification['tests_passed']} got {final_verification.get('tests_passed')}"
                )

    agent_passed = bool(proposals) and not errors
    applied_any = any(item.get("applied") for item in applications) if apply else True
    patcher_passed = bool(applications) and (not apply or applied_any) and not errors

    verifier_required = bool(apply or expected_verification)
    verifier_passed = True
    verifier_status = "not_required"
    verifier_error = ""
    if verifier_required:
        final_status = final_verification.get("status")
        verifier_status = (
            "ok"
            if not errors and final_verification and final_status not in {"failed", None}
            else "failed"
        )
        verifier_passed = (
            not errors
            and bool(final_verification)
            and final_status not in {"failed", None}
        )
        if verifier_status == "failed" and not verifier_error:
            verifier_error = "No verification rows returned."
    else:
        verifier_status = "not_required"

    agent = {
        "required": True,
        "status": "ok" if agent_passed else "failed",
        "passed": agent_passed,
        "proposals": proposals,
        "applications": applications,
        "mode": mode,
        "applied": apply,
        "fix_rounds": fix_rounds,
        "fix_status": fix_status,
        "fix_metadata": fix_result.report.fix_metadata,
        "error": "; ".join(errors),
    }

    patcher = {
        "required": True,
        "status": "ok" if patcher_passed else "failed",
        "passed": patcher_passed,
        "applied": apply,
        "applications": applications,
        "fix_rounds": fix_rounds,
        "error": "; ".join(errors),
    }

    verifier = {
        "required": verifier_required,
        "status": verifier_status,
        "passed": verifier_passed,
        "verifications": verifications,
        "fix_rounds": fix_rounds,
        "expected_verification": expected_verification,
        "error": verifier_error or ("; ".join(errors) if not verifier_required else ""),
    }
    return agent, patcher, verifier


def _metrics(
    case_results: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    strict: bool,
) -> dict[str, Any]:
    scanner = [case for case in case_results]
    scanner_passed = [case for case in scanner if case["scan"]["passed"]]
    benign_cases = [case for case in case_results if case["label"] == "benign"]
    benign_fp = [case for case in benign_cases if case["scan"].get("benign_high_findings")]

    graph_expected = [case for case in case_results if case["graph"]["required"]]
    graph_passed = [case for case in graph_expected if case["graph"]["passed"]]

    graph_export_expected = [
        case for case in case_results if case["graph_export"]["required"]
    ]
    graph_export_passed = [
        case for case in graph_export_expected if case["graph_export"]["passed"]
    ]

    agent_expected = [case for case in case_results if case["agent"]["required"]]
    agent_passed = [case for case in agent_expected if case["agent"]["passed"]]

    patcher_expected = [case for case in case_results if case["patcher"]["required"]]
    patcher_passed = [case for case in patcher_expected if case["patcher"]["passed"]]

    verifier_expected = [case for case in case_results if case["verifier"]["required"]]
    verifier_passed = [case for case in verifier_expected if case["verifier"]["passed"]]

    scanner_recall = _ratio(len(scanner_passed), len(scanner))
    benign_fpr = _ratio(len(benign_fp), len(benign_cases))
    graph_recall = _ratio(len(graph_passed), len(graph_expected))
    graph_export_rate = _ratio(len(graph_export_passed), len(graph_export_expected))
    agent_rate = _ratio(len(agent_passed), len(agent_expected))
    patcher_rate = _ratio(len(patcher_passed), len(patcher_expected))
    verifier_rate = _ratio(len(verifier_passed), len(verifier_expected))

    thresholds = BENCHMARK_THRESHOLDS.copy()
    threshold_results = {
        "scanner_expected_case_recall": scanner_recall >= thresholds["scanner_expected_rule_recall"],
        "benign_false_positive_rate": benign_fpr <= thresholds["benign_false_positive_rate"],
        "graph_expected_case_recall": graph_recall >= thresholds["graph_expected_case_recall"],
        "graph_export_success_rate": graph_export_rate >= thresholds["graph_export_success_rate"],
        "agent_success_rate": agent_rate >= thresholds["agent_success_rate"],
        "patcher_success_rate": patcher_rate >= thresholds["patcher_success_rate"],
        "verifier_success_rate": verifier_rate >= thresholds["verifier_success_rate"],
    }

    stage_counts = Counter(item["stage"] for item in failures)

    return {
        "total_cases": len(case_results),
        "malicious_cases": len([case for case in case_results if case["label"] == "malicious"]),
        "benign_cases": len(benign_cases),
        "strict": strict,
        "passed": all(threshold_results.values()) if strict else True,
        "thresholds": thresholds,
        "threshold_results": threshold_results,
        "failure_count": len(failures),
        "stage_failures": dict(stage_counts),
        "scanner": {
            "expected_cases": len(scanner),
            "expected_cases_passed": len(scanner_passed),
            "expected_case_recall": scanner_recall,
            "benign_false_positive_cases": len(benign_fp),
            "benign_false_positive_rate": benign_fpr,
        },
        "graph": {
            "expected_cases": len(graph_expected),
            "expected_cases_passed": len(graph_passed),
            "expected_case_recall": graph_recall,
        },
        "graph_export": {
            "expected_cases": len(graph_export_expected),
            "expected_cases_passed": len(graph_export_passed),
            "success_rate": graph_export_rate,
        },
        "agent": {
            "expected_cases": len(agent_expected),
            "expected_cases_passed": len(agent_passed),
            "query_success_rate": agent_rate,
        },
        "patcher": {
            "expected_cases": len(patcher_expected),
            "expected_cases_passed": len(patcher_passed),
            "success_rate": patcher_rate,
        },
        "verifier": {
            "expected_cases": len(verifier_expected),
            "expected_cases_passed": len(verifier_passed),
            "success_rate": verifier_rate,
        },
    }


def _case_failures(case: dict[str, Any], result: dict[str, Any]) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    scan_result = result["scan"]
    graph_result = result["graph"]
    graph_export_result = result["graph_export"]
    agent_result = result["agent"]
    patcher_result = result["patcher"]
    verifier_result = result["verifier"]

    if scan_result["missed_rules"]:
        failures.append(_failure(case, "scanner", f"missed rules: {', '.join(scan_result['missed_rules'])}"))
    for mismatch in scan_result.get("target_region_mismatches", []):
        failures.append(_failure(case, "scanner", mismatch))
    if case.get("label") == "benign" and scan_result.get("benign_high_findings"):
        failures.append(
            _failure(case, "false_positive", f"high-severity findings: {', '.join(scan_result['actual_rules'])}")
        )

    if graph_result["required"] and not graph_result["passed"]:
        failures.append(_failure(case, "codegraph", graph_result.get("error", "graph case failed")))

    if graph_export_result["required"] and not graph_export_result["passed"]:
        failures.append(
            _failure(
                case,
                "graph_export",
                graph_export_result.get("error", "graph export case failed"),
            )
        )

    if agent_result["required"] and not agent_result["passed"]:
        failures.append(
            _failure(case, "agent", agent_result.get("error", "agent generation failed"))
        )
    if patcher_result["required"] and not patcher_result["passed"]:
        failures.append(
            _failure(case, "patcher", patcher_result.get("error", "patcher failed"))
        )
    if verifier_result["required"] and not verifier_result["passed"]:
        failures.append(
            _failure(
                case,
                "verifier",
                verifier_result.get("error", "verification failed"),
            )
        )

    return failures


def _resolve_case_path(manifest_file: Path, raw_path: str) -> Path:
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


def _normalize_expected_findings(case: dict[str, Any]) -> list[dict[str, Any]]:
    findings = case.get("expected_findings") or []
    if findings:
        return list(findings)
    return [{"rule_id": rule} for rule in case.get("expected_rules", [])]


def _normalize_graph_config(raw: Any, case: dict[str, Any]) -> dict[str, Any]:
    cfg = _normalize_graph_base(raw)
    if not cfg["required"]:
        return {"required": False, "expected_rules": [], "required_call_paths": [], "require_cli": False}

    cfg.setdefault("expected_rules", case.get("expected_graph_rules", []))
    cfg.setdefault("required_call_paths", case.get("expected_call_paths", []))
    cfg.setdefault("required", bool(cfg.get("expected_rules")))
    cfg.setdefault("require_cli", bool(cfg.get("required_cli")))
    return cfg


def _normalize_graph_base(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {
            "required": False,
            "expected_rules": [],
            "required_call_paths": [],
            "require_cli": False,
        }
    if isinstance(raw, bool):
        return {
            "required": raw,
            "expected_rules": [],
            "required_call_paths": [],
            "require_cli": False,
        }
    if isinstance(raw, list):
        return {
            "required": bool(raw),
            "expected_rules": list(raw),
            "required_call_paths": [],
            "require_cli": False,
        }
    if not isinstance(raw, dict):
        return {
            "required": bool(raw),
            "expected_rules": [],
            "required_call_paths": [],
            "require_cli": False,
        }
    return {
        "required": bool(raw.get("required", raw.get("expected_rules") is not None)),
        "expected_rules": list(raw.get("expected_rules", [])),
        "required_call_paths": list(raw.get("required_call_paths", raw.get("expected_call_paths", []))),
        "require_cli": bool(raw.get("require_cli", False)),
    }


def _normalize_graph_export(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {"required": False, "format": "both", "require_cli": False}
    if isinstance(raw, bool):
        return {"required": raw, "format": "both", "require_cli": False}
    if isinstance(raw, dict):
        return {
            "required": bool(raw.get("required", False)),
            "format": raw.get("format", "both"),
            "require_cli": bool(raw.get("require_cli", False)),
        }
    return {"required": bool(raw), "format": "both", "require_cli": False}


def _missing_call_paths(findings: list[dict[str, Any]], required_paths: list[dict[str, Any]]) -> list[Any]:
    if not required_paths:
        return []

    paths = [item.get("behavior_path", []) for item in findings]
    missing = []
    for required in required_paths:
        if not any(_contains_all(path, required) for path in paths):
            missing.append(required)
    return missing


def _severity_ok(severity: str, expected_min: str | None) -> bool:
    if not expected_min:
        return True
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(expected_min, 0)


def _line_match(expected: dict[str, Any] | None, actual: dict[str, Any]) -> bool:
    if not expected:
        return True
    for key in ("file", "start_line", "end_line"):
        if key in expected and expected.get(key) != actual.get(key):
            return False
    return True


def _contains_all(behaviors: list[str], needles: list[str]) -> bool:
    all_text = "\n".join(behaviors)
    return all(needle in all_text for needle in needles)


def _copy_path_for_fix(case_path: Path) -> tuple[Path, Any]:
    workdir = Path(tempfile.mkdtemp(prefix="repoguard-fix-")).resolve()
    if case_path.is_file():
        target = workdir / case_path.name
        shutil.copy2(case_path, target)
    else:
        target = workdir / case_path.name
        shutil.copytree(case_path, target)

    def cleanup() -> None:
        shutil.rmtree(workdir, ignore_errors=True)

    return target, cleanup


def _openai_available() -> bool:
    try:
        openai_config()
    except ConfigurationError:
        return False
    return True


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 1.0
    return numerator / denominator


def _failure(case: dict[str, Any], stage: str, message: str) -> dict[str, Any]:
    return {
        "repo_id": case.get("repo_id", case.get("id", "unknown")),
        "path": case["path"],
        "label": case.get("label", "unknown"),
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
