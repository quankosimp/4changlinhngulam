# RepoGuard Demo Script

## 0:00 - 0:20 Pitch

RepoGuard Agent scans a repo, detects malware/security/dead-code findings,
uses CodeGraph or fallback repo context to understand impact, proposes a minimal
patch, applies it inside the target region, then reruns the scanner and shows a
dashboard report.

## 0:20 - 0:50 Scan

```bash
python -m repoguard scan tests/corpus --json --report report.json
```

Point out:

- base64 decode into exec
- environment secret to network
- download-write-execute dropper
- shell injection risk
- pickle from network
- unused function/class candidates

## 0:50 - 1:40 Fix Dry Run

```bash
python -m repoguard fix tests/corpus --dry-run --no-llm --report repoguard_report.json
```

Say:

RepoGuard only patches when it has a scanner finding, target region, and repo
context. Without an API key, it uses deterministic fallback patches for the MVP
rules. With an API key, the same contract is sent to the LLM agent.

## 1:40 - 2:30 Dashboard

```bash
streamlit run repoguard/dashboard/app.py
```

Show:

- Findings tab: rule, severity, confidence, file, line, target region
- CodeGraph Context tab: callers, importers, references, file impact
- Patch Diff tab: proposed target-region diff
- Verification tab: scanner rerun status and before/after severity

## Closing Line

RepoGuard is not just a scanner and not just an LLM coding assistant. It combines
deterministic findings, CodeGraph impact context, structured patch proposals,
validated target-region patching, and scanner-based verification.
