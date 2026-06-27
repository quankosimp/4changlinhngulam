# RepoGuard Backend

RepoGuard scans Python repositories for security, malware, and cleanup findings,
enriches findings with CodeGraph context when available, asks OpenAI for a
structured remediation patch, applies validated patches, and verifies by rerunning
the scanner.

## Environment

Create `.env` from `.env.example`:

```bash
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-5.5
OPENAI_REASONING_EFFORT=medium
```

`OPENAI_API_KEY` is required only for `fix`. `scan` and `benchmark` run without it.

## Commands

```bash
python3 -m repoguard scan tests/corpus --json
python3 -m repoguard benchmark tests/repoguard_manifest.json --out benchmark_reports/repoguard_latest
python3 -m repoguard fix tests/corpus/malicious/base64_exec.py --dry-run --max-findings 1
python3 -m repoguard fix tests/corpus/malicious/base64_exec.py --apply --max-findings 1
```

CodeGraph is optional for scan context. If the `codegraph` CLI is missing,
RepoGuard records fallback context in the report instead of failing.
