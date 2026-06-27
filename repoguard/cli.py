from __future__ import annotations

import argparse
import json

from repoguard.agent import AgentConfigurationError, AgentResponseError
from repoguard.benchmark import print_summary, run_benchmark
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
    fix_cmd.add_argument("--max-findings", type=int, default=10)
    fix_cmd.add_argument("--test-command", default=None)
    fix_cmd.add_argument("--no-codegraph", action="store_true")
    fix_cmd.add_argument("--no-llm", action="store_true", help="Use deterministic MVP fallback patches.")

    benchmark_cmd = sub.add_parser("benchmark", help="run benchmark manifest")
    benchmark_cmd.add_argument("manifest", nargs="?", default="tests/repoguard_manifest.json")
    benchmark_cmd.add_argument("--out", default="benchmark_reports/latest")
    benchmark_cmd.add_argument("--strict", action="store_true")
    benchmark_cmd.add_argument("--json", action="store_true")
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
    return 0


def _fix_command(args: argparse.Namespace) -> int:
    if not args.dry_run and not args.apply:
        args.dry_run = True

    try:
        result = run_fix(
            args.path,
            apply=args.apply,
            max_findings=args.max_findings,
            test_command=args.test_command,
            use_codegraph=not args.no_codegraph,
            use_llm=not args.no_llm,
        )
    except (AgentConfigurationError, AgentResponseError) as exc:
        print(str(exc))
        return 2
    write_report(result.report, args.report)
    print(f"Saved report: {args.report}")
    _print_fix_summary(result.report, dry_run=not args.apply)
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


def _print_fix_summary(report, dry_run: bool) -> None:
    if not report.findings:
        print("Finding detected: none")
        return

    findings_by_id = {item.id: item for item in report.findings}
    for proposal, verification in zip(report.patches, report.verification):
        finding = findings_by_id.get(proposal.finding_id)
        if finding is None:
            continue
        print(f"Finding detected: {finding.rule_id} {finding.severity} {finding.file}:{finding.line}")
        print(f"Patch proposed: {proposal.action} lines {proposal.start_line}-{proposal.end_line}")
        print(f"Patch applied: {'no (dry-run)' if dry_run else verification.status == 'patched'}")
        print("Scanner rerun: yes" if not dry_run else "Scanner rerun: no (dry-run)")
        print(f"Verification result: {verification.status} - {verification.notes}")
        print("Diff shown:")
        print(verification.diff or "(no diff)")


if __name__ == "__main__":
    raise SystemExit(main())
