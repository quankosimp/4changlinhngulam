---
name: context:all-context
description: "Root context router for malguard — architecture, stack, CodeGraph constraints, and task routing"
keywords: malguard, architecture, stack, codegraph, detection, malware, security, scanner, agent, overview
related: []
date: 27-06-26
---
# malguard - All Context

Last updated: 2026-06-27

This file is the root context entrypoint for the repo.

Use it for two things:

1. quick routing to the right context pack or root file
2. broad architecture and repository understanding

Start here before loading deeper context files.

> **Project status:** Hackathon project (3-hour timebox, team of 3). As of this scan the
> repository holds the plan (`HACKATHON_PLAN.md`) and the agent harness only — the `malguard/`
> Python package described below is **planned, not yet implemented**. Sections marked _(planned)_
> describe the agreed target architecture from `HACKATHON_PLAN.md`; refresh this file once code lands.

---

## What This Project Is

**malguard** is a static-analysis security tool + natural-language agent that detects
**suspicious / malicious code** in a source repository — backdoors, obfuscated payloads,
`eval`/`exec` of decoded data, and dropper chains (`download → write → exec`) — using
**CodeGraph** as the underlying code knowledge-graph index.

- **Who it's for:** supply-chain / security defenders scanning third-party or AI-generated code;
  immediately, the hackathon judges (demo of catching a real PyPI-style backdoor).
- **Headline capability (target):** ask in natural language ("find places that decode base64 then
  exec") → the agent queries CodeGraph (`codegraph_explore` over MCP) → matches against the rule
  engine → returns call-path + evidence + a confidence score.
- **Full plan & 3-person work split:** see [`HACKATHON_PLAN.md`](../../HACKATHON_PLAN.md) at the repo root.

### About CodeGraph (the dependency — important constraints)

CodeGraph is a **structural** code indexer (tree-sitter → SQLite/FTS5) exposing a **symbol + call
graph** (`calls`/`imports`/`extends`/`contains`) via an **MCP server** (`codegraph_explore` default;
`codegraph_search`/`callers`/`callees`/`impact`/`node`/`files` enabled via the
`CODEGRAPH_MCP_TOOLS` env var) and a **CLI** (`codegraph query/callers/callees/impact --json`).
Install: `npx @colbymchenry/codegraph` → `codegraph init`. Supports Python/JS/TS/Java.

**Key design consequence:** CodeGraph has **no taint/data-flow analysis and no git metadata**.
Multi-step detection (e.g. `requests.get → open(w) → subprocess`) must be reconstructed by
**traversing CodeGraph's call graph + pattern-matching** — CodeGraph will not do it for you. So the
single-file **AST rule engine is the high-signal safety net**; the CodeGraph + agent layer is the
differentiator and must degrade gracefully (fixed-query fallback) if it runs out of time.

---

## How This File Works (the `all-*.md` Convention)

Every `process/context/` directory has one `all-*.md` entrypoint that acts as an attachable quick
router for that domain. This root file (`all-context.md`) is the top-level router. Context groups
each have their own `all-{group}.md` entrypoint.

**How agents use it:**

1. Agent reads `all-context.md` first (this file)
2. Finds the relevant context group from the routing tables below
3. Reads that group's `all-{group}.md` entrypoint
4. Only then loads the specific deep doc needed

This layered routing keeps context windows small. Never load the whole `process/context/` tree.

---

## Quick Start

For most substantial tasks:

1. read this file first
2. choose the smallest relevant root file or context group from the tables below
3. only then load deeper files

---

## Current Root Entry Points

<!-- The two tables below (Root Entry Points + Context Groups) are GENERATED from each
     context doc's frontmatter by `discover-context.mjs --emit-routing`. Do NOT hand-edit
     between the GENERATED markers — your edits will be overwritten on the next rebuild.
     To change a row, edit the owning doc's frontmatter (description / keywords) and re-emit.
     `--check-routing` fails lint if this block drifts from the frontmatter on disk. -->

<!-- GENERATED:routing -->
| File | Read when |
|---|---|
| `process/context/all-context.md` | any substantial planning, research, review, or implementation task |
| `process/context/planning/all-planning.md` | Planning group entrypoint — SIMPLE vs COMPLEX plan calibration and example plan shapes |
| `process/context/tests/all-tests.md` | Tests group entrypoint — pytest commands, the detection corpus, and accuracy verification |

## Current Context Groups

| Group | Entry point | Scope |
|---|---|---|
| `planning/` | `process/context/planning/all-planning.md` | Planning group entrypoint — SIMPLE vs COMPLEX plan calibration and example plan shapes |
| `tests/` | `process/context/tests/all-tests.md` | Tests group entrypoint — pytest commands, the detection corpus, and accuracy verification |
<!-- /GENERATED:routing -->

## Task Routing Table

| If the task involves... | Start with |
|---|---|
| architecture or stack questions | this file |
| detection rules / AST / scanner | this file (Technology Stack + Key Patterns below) |
| CodeGraph / call-graph / NL agent | this file (About CodeGraph above) |
| testing or verification | `process/context/tests/all-tests.md` |
| creating a new plan | `process/context/planning/all-planning.md` |

## Context Group Lifecycle

Context groups are durable knowledge domains, not feature folders.

Create a group when a topic has 3+ durable docs, a single doc exceeds ~800 lines with separable
subtopics, multiple agents repeatedly need only one slice, or the topic maps to a stable operational
domain (tests, infra, database, auth, UI, workflows). Do not create a group for a temporary report,
a plan/execution artifact, or feature-specific content (that belongs in `process/features/...`).
Move or split one group at a time, and run the `vc-audit-context` skill after every change.

## Naming Convention

There are no `README.md` files inside `process/context/`. Canonical entrypoints use `all-*.md`:
root is `process/context/all-context.md`; each group is `process/context/{group}/all-{group}.md`.

## Context Update Protocol

When durable project knowledge changes: update the smallest relevant context file; update this file
if routing/ownership/naming/groups changed; update the owning `all-{group}.md` entrypoint; run
`vc-audit-context`.

---

## Repository Structure

Current on-disk layout (harness + plan only; `malguard/` is _planned_):

```
4changlinhngulam/              # repo dir; product name = "malguard"
  HACKATHON_PLAN.md            # 3h plan + 3-person work split (source of truth for scope)
  README.md
  .claude/                     # Claude Code harness: agents/, skills/, hooks/, settings.json
  .codex/                      # Codex mirror: agents/, hooks/, config.toml, hooks.json
  .agents/skills/              # shared skill surface (mirrors .claude/skills)
  process/
    context/                   # this context system (all-context.md + planning/ + tests/)
    general-plans/             # active/ completed/ backlog/ (task-folder convention)
    features/                  # feature-scoped storage (none yet)
    development-protocols/     # RIPER-5 methodology docs
```

Planned `malguard/` package (from `HACKATHON_PLAN.md` — create during EXECUTE):

```
malguard/
  models.py            # SHARED CONTRACT: Finding dataclass (rule_id, severity, confidence,
                       #   file, line, snippet, message, call_path) + to_dict()
  scanner.py           # walk repo → run rules → aggregate list[Finding]      (Person A)
  rules/
    ast_rules.py       # single-file AST detection rules #1–#7                 (Person A)
    graph_rules.py     # multi-step call-path rules #8–#10 via CodeGraph       (Person B)
  codegraph_client.py  # wrap CodeGraph CLI/MCP (subprocess + --json)          (Person B)
  agent.py             # NL query → codegraph_explore → rule filter            (Person B)
  report.py            # JSON + CLI report                                     (Person C)
  cli.py               # python -m malguard scan <path> [--json]
  dashboard/app.py     # Streamlit UI, reads report.json (decoupled)           (Person C)
tests/corpus/{malicious,benign}/   # detection test samples                    (Person C)
```

## Technology Stack

- **Language:** Python 3.x (no manifest committed yet; a `pyproject.toml` will be added — package
  name `malguard`). Core detection uses the **standard-library `ast` module** (no parser deps).
- **Index / knowledge graph:** **CodeGraph** via `npx @colbymchenry/codegraph` — consumed through
  its **CLI** (`--json`) and **MCP server** (`codegraph_explore`, plus hidden tools behind
  `CODEGRAPH_MCP_TOOLS`). Provides structural symbol + call graph only (no taint/data-flow).
- **NL agent:** queries CodeGraph's `codegraph_explore` and filters results through the rule engine.
- **Dashboard:** **Streamlit** (`streamlit run malguard/dashboard/app.py`) — reads `report.json`.
- **Tests:** **pytest** _(planned)_ over a corpus of ~10 malicious + ~10 benign samples.
- **Pattern sources borrowed:** `apiiro/malicious-code-ruleset` (rule logic + test cases),
  `PyCQA/bandit` (`NodeVisitor` structure), Datadog GuardDog writeups (real backdoor samples).

## Key Patterns and Conventions

**The shared contract is `Finding`.** Every detection rule is a function `detect(...) -> list[Finding]`;
`scanner.scan(path) -> list[Finding]`; `report.write(findings) -> report.json`. The dashboard reads
`report.json` ONLY — frontend is fully decoupled from backend so the 3 people can work in parallel.
Lock `models.py` in the first 15 minutes and do not change it after.

- **Rule identifiers:** stable string IDs like `PY-EXEC-B64`, `PY-DROPPER`, `PY-PICKLE-NET`.
- **Severity:** `"high" | "medium" | "low"`. **Confidence:** float `0.0–1.0` (e.g. base64 + exec on
  the same line → high).
- **Multi-step findings** carry a `call_path` list (`["downloads.py:12 get()", "...write()", "setup.py:8 exec()"]`).
- **Safety net first:** the AST engine (Person A) must run standalone with zero CodeGraph dependency;
  the CodeGraph/agent layer (Person B) layers on top and has a fixed-query fallback.
- **Naming:** Python `snake_case` for functions/modules, `PascalCase` for classes/dataclasses.

## Environment and Configuration

**Config files:** none committed yet (planned: `pyproject.toml`). No `.env` is required to run the
AST engine.

**Env var groups (names only):**
- CodeGraph: `CODEGRAPH_MCP_TOOLS` — set to expose the hidden MCP query tools
  (`codegraph_search`/`callers`/`callees`/`impact`/`node`/`files`) beyond the default `codegraph_explore`.

**Gotchas / things agents should be careful about:**
- CodeGraph integration is the **biggest time-sink risk** in the 3h build — pre-test it on a tiny
  repo, cache results, and keep the regex call-heuristic fallback ready.
- CodeGraph cannot do data-flow; do not assume `codegraph_explore` returns taint paths — reconstruct
  multi-step chains from call edges yourself.
- Keep false positives low: weight `confidence`, and test against the **benign** corpus, not just malicious.

## Source References

- [`HACKATHON_PLAN.md`](../../HACKATHON_PLAN.md) — scope, architecture, and 3-person work split (source of truth).
- CodeGraph docs — `https://colbymchenry.github.io/codegraph/` (MCP server, languages, CLI reference).
- `github.com/apiiro/malicious-code-ruleset` — rule logic + positive/negative test cases (borrowed).
- `github.com/PyCQA/bandit` — `NodeVisitor` structure for AST rules (borrowed).
- Datadog GuardDog writeups — real malicious-PyPI samples for the test corpus.

## Open Questions / Outstanding Work

- **Project/package name:** context assumes `malguard`; the repo dir is `4changlinhngulam`. Confirm the
  final package name before adding `pyproject.toml`.
- **`malguard/` package is not implemented yet** — all module paths above are the planned target.
- **Test corpus not assembled** — needs ~10 malicious + ~10 benign samples before accuracy claims hold.
- **CodeGraph integration unproven** — confirm `codegraph init` + MCP query path works on the team's
  Windows machines early (biggest time-sink risk); keep the regex fallback ready.
- **NL agent scope** — fixed-query fallback must work even if the natural-language layer is cut for time.

## Scan Metadata

- Generated: 2026-06-27
- HEAD: 57cab595e4c3a3a738b1ea35290e4f28913d65a0
- Mode: fresh
- Package manager: none yet (Python; `pyproject.toml` planned)
