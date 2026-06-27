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
python3 -m repoguard fix tests/corpus/malicious/base64_exec.py --apply --max-findings 3 --max-rounds 4 --min-severity high
```

```bash
python3 -m repoguard benchmark tests/repoguard_manifest.json --out benchmark_reports/repoguard_latest
python3 -m streamlit run repoguard/dashboard/benchmark_app.py -- --server.port 8502
```

CodeGraph is optional for normal scan context. If the `codegraph` CLI is
missing, RepoGuard records fallback context in the scan report instead of
failing. CodeGraph demo commands are stricter:

```bash
python3 -m repoguard codegraph check tests/e2e_corpus/graph_chains/g001_dropper_chain
python3 -m repoguard codegraph init tests/e2e_corpus/graph_chains/g001_dropper_chain
python3 -m repoguard graph tests/e2e_corpus/graph_chains/g001_dropper_chain --format both --out demo_graph
dot -Tpng demo_graph/graph.dot -o demo_graph/graph.png
```

The graph command writes `graph.json` and/or `graph.dot`. The DOT graph is the
demo-friendly view; `graph.json` is the backend/debug contract for dashboards.
