from __future__ import annotations

import argparse
import json

from repoguard.agent import AgentConfigurationError, AgentResponseError
from repoguard.benchmark import print_summary, run_benchmark
from repoguard.codegraph_client import CodeGraphClient, CodeGraphUnavailable
from repoguard.graph_exporter import build_graph, write_graph
from repoguard.report import write_report
from repoguard.workflow import SEVERITY_ORDER, run_fix, run_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RepoGuard Agent backend")
    sub = parser.add_subparsers(dest="command")

    scan_cmd = sub.add_parser("scan", help="scan a repo or file")
    scan_cmd.add_argument("path")
    scan_cmd.add_argument("--json", action="store_true")
    scan_cmd.add_argument("--report", default=None)
    scan_cmd.add_argument("--no-codegraph", action="store_true")

    fix_cmd = sub.add_parser("fix", help="propose and optionally apply remediation patches")
    fix_cmd.add_argument("path")
    mode = fix_cmd.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    fix_cmd.add_argument("--report", default="repoguard_report.json")
    fix_cmd.add_argument("--max-rounds", type=int, default=3)
    fix_cmd.add_argument("--max-findings", type=int, default=3)
    fix_cmd.add_argument(
        "--min-severity",
        choices=["low", "medium", "high"],
        default=None,
        help="Only fix findings at or above this severity.",
    )
    fix_cmd.add_argument("--test-command", default=None)
    fix_cmd.add_argument("--no-codegraph", action="store_true")

    benchmark_cmd = sub.add_parser("benchmark", help="run benchmark manifest")
    benchmark_cmd.add_argument("manifest", nargs="?", default="tests/repoguard_manifest.json")
    benchmark_cmd.add_argument("--out", default="benchmark_reports/latest")
    benchmark_cmd.add_argument("--strict", action="store_true")
    benchmark_cmd.add_argument("--json", action="store_true")

    codegraph_cmd = sub.add_parser("codegraph", help="manage CodeGraph integration")
    codegraph_sub = codegraph_cmd.add_subparsers(dest="codegraph_command")
    check_cmd = codegraph_sub.add_parser("check", help="check CodeGraph CLI and repo status")
    check_cmd.add_argument("path")
    check_cmd.add_argument("--json", action="store_true")
    init_cmd = codegraph_sub.add_parser("init", help="initialize CodeGraph index for a repo")
    init_cmd.add_argument("path")
    init_cmd.add_argument("--json", action="store_true")

    graph_cmd = sub.add_parser("graph", help="export code graph as JSON and/or DOT")
    graph_cmd.add_argument("path")
    graph_cmd.add_argument("--format", choices=["json", "dot", "both"], default="both")
    graph_cmd.add_argument("--out", default="demo_graph")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _scan_command(args)
    if args.command == "fix":
        return _fix_command(args)
    if args.command == "benchmark":
        run = run_benchmark(args.manifest, args.out, strict=args.strict)
        if args.json:
            print(json.dumps(run.metrics, indent=2))
        else:
            print_summary(run)
        return 0 if run.passed else 1
    if args.command == "codegraph":
        return _codegraph_command(args)
    if args.command == "graph":
        return _graph_command(args)

    parser.print_help()
    return 1


def _scan_command(args: argparse.Namespace) -> int:
    report = run_scan(args.path, use_codegraph=not args.no_codegraph)
    if args.report:
        write_report(report, args.report)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_findings(report.findings)
    return 1 if report.findings else 0


def _fix_command(args: argparse.Namespace) -> int:
    if not args.dry_run and not args.apply:
        args.dry_run = True

    try:
        result = run_fix(
            args.path,
            apply=args.apply,
            max_rounds=args.max_rounds,
            max_findings=args.max_findings,
            min_severity=args.min_severity,
            test_command=args.test_command,
            use_codegraph=not args.no_codegraph,
        )
    except (AgentConfigurationError, AgentResponseError) as exc:
        print(str(exc))
        return 2
    write_report(result.report, args.report)
    print(f"Saved report: {args.report}")
    for item in result.applications:
        if item.diff:
            print(item.diff)
    print(f"Fix status: {result.status}")
    for item in result.rounds:
        print(
            f"Round {item.round_index}: status={item.status}, before={len(item.findings_before)} "
            f"after={len(item.findings_after)} proposals={len(item.proposals)}"
        )
    return 0


def _codegraph_command(args: argparse.Namespace) -> int:
    client = CodeGraphClient(args.path)
    try:
        if args.codegraph_command == "check":
            payload = client.check_available()
        elif args.codegraph_command == "init":
            payload = client.init_index()
        else:
            print("Missing CodeGraph subcommand. Use `check` or `init`.")
            return 1
    except CodeGraphUnavailable as exc:
        print(f"CodeGraph unavailable: {exc}")
        return 2

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(json.dumps(payload, indent=2))
    return 0


def _graph_command(args: argparse.Namespace) -> int:
    try:
        report = run_scan(args.path, use_codegraph=True)
        export = build_graph(args.path, findings=report.findings, require_codegraph=True)
        written = write_graph(export, args.out, args.format)
    except CodeGraphUnavailable as exc:
        print(f"CodeGraph unavailable: {exc}")
        return 2
    for path in written:
        print(f"Wrote {path}")
    return 0


def _print_findings(findings) -> None:
    if not findings:
        print("No findings.")
        return
    for finding in sorted(
        findings,
        key=lambda item: (SEVERITY_ORDER.get(item.severity, 0), item.confidence),
        reverse=True,
    ):
        print(
            f"{finding.severity:<6} {finding.confidence:.2f} "
            f"{finding.file}:{finding.line} {finding.rule_id} {finding.message}"
        )


if __name__ == "__main__":
    raise SystemExit(main())
