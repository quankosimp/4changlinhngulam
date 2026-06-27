from __future__ import annotations

import argparse
import json

from malguard.benchmark import print_summary, run_benchmark
from malguard.scanner import scan


SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="malguard: Python malware triage scanner")
    sub = parser.add_subparsers(dest="command")

    scan_cmd = sub.add_parser("scan", help="scan a directory for suspicious patterns")
    scan_cmd.add_argument("path", help="file or directory to scan")
    scan_cmd.add_argument("--json", action="store_true", help="output findings as JSON")
    scan_cmd.add_argument(
        "--report",
        default=None,
        help="optional report.json output path",
    )

    benchmark_cmd = sub.add_parser("benchmark", help="run an end-to-end benchmark manifest")
    benchmark_cmd.add_argument(
        "manifest",
        nargs="?",
        default="tests/e2e_manifest.json",
        help="benchmark manifest path",
    )
    benchmark_cmd.add_argument(
        "--out",
        default="benchmark_reports/latest",
        help="benchmark output directory",
    )
    benchmark_cmd.add_argument(
        "--strict",
        action="store_true",
        help="return non-zero when benchmark thresholds fail",
    )
    benchmark_cmd.add_argument("--json", action="store_true", help="print benchmark metrics as JSON")
    return parser


def _print_table(findings) -> None:
    if not findings:
        print("No findings.")
        return

    rows = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 0), f.confidence),
        reverse=True,
    )

    rule_w = max(len(f.rule_id) for f in rows) + 2
    file_w = min(40, max(len(f.file) for f in rows) + 2)

    header = f"{'SEV':<6} {'CONF':<5} {'LINE':<6} {'FILE':<{file_w}} {'RULE':<{rule_w}} MESSAGE"
    print(header)
    print("-" * len(header))
    for finding in rows:
        msg = (finding.message[:100] + "...") if len(finding.message) > 100 else finding.message
        print(
            f"{finding.severity:<6} "
            f"{finding.confidence:.2f}  "
            f"{finding.line:<6} "
            f"{finding.file[:file_w - 2]:<{file_w}} "
            f"{finding.rule_id:<{rule_w}} "
            f"{msg}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "benchmark":
        run = run_benchmark(args.manifest, args.out, strict=args.strict)
        if args.json:
            print(json.dumps(run.metrics, indent=2))
        else:
            print_summary(run)
        return 0 if run.passed else 1

    if args.command != "scan":
        parser.print_help()
        return 1

    findings = scan(args.path)
    findings_payload = [f.to_dict() for f in findings]

    if args.report:
        with open(args.report, "w", encoding="utf-8") as fp:
            json.dump(findings_payload, fp, indent=2)
        print(f"Saved report: {args.report}")

    if args.json:
        print(json.dumps(findings_payload, indent=2))
    else:
        _print_table(findings)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
