# RepoGuard Agent

RepoGuard scans Python repositories for malware, security issues, and dead-code
candidates. It enriches findings with CodeGraph context when available, proposes
minimal patches, applies validated target-region edits, reruns the scanner, and
writes a dashboard-ready report.

## MVP Rules

- `PY-DECODE-EXEC`: decoded payload passed to `exec` or `eval`
- `PY-ENV-EXFIL`: environment secret sent to an outbound network sink
- `PY-DROPPER`: download, write, then execute chain
- `PY-SHELL-INJECTION`: `shell=True` or dynamic process command risk
- `PY-PICKLE-NETWORK`: network payload passed to `pickle.loads`
- `PY-UNUSED-FUNCTION` / `PY-UNUSED-CLASS`: dead-code candidates

## Commands

```bash
python -m repoguard scan tests/corpus --json --report report.json
python -m repoguard fix tests/corpus --dry-run --no-llm --report repoguard_report.json
python -m repoguard fix tests/corpus/malicious/base64_exec.py --apply --report repoguard_report.json
streamlit run repoguard/dashboard/app.py
```

`OPENAI_API_KEY` is optional. If it is present, RepoGuard asks OpenAI for the
structured `PatchProposal`. If it is missing, RepoGuard uses deterministic
fallback patches for the MVP rules so the hackathon demo still works offline.

CodeGraph is optional. If the `codegraph` CLI is missing or fails, RepoGuard
records fallback AST/grep context instead of failing.

## Demo Flow

1. Run scan and show findings:
   `python -m repoguard scan tests/corpus --json --report report.json`
2. Run dry-run remediation:
   `python -m repoguard fix tests/corpus --dry-run --no-llm --report repoguard_report.json`
3. Open dashboard:
   `streamlit run repoguard/dashboard/app.py`
4. Demo tabs: Findings, CodeGraph Context, Patch Diff, Verification.
