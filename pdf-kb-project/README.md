# 4changlinhngulam

Hackathon repository for **malguard**, a planned Python static-analysis security tool that detects suspicious or malicious code patterns with an AST rule engine plus CodeGraph-backed call-graph exploration.

The product implementation is still planned. The current repository contains the hackathon plan and the Vibe Code Kit agent harness.

## Getting Started

Read [HACKATHON_PLAN.md](HACKATHON_PLAN.md) for the product scope and work split.

For agent and workflow context, start with:

- [AGENTS.md](AGENTS.md) for Codex routing rules
- [CLAUDE.md](CLAUDE.md) for Claude compatibility rules
- [process/context/all-context.md](process/context/all-context.md) for repository context
- [process/development-protocols/all-development-protocols.md](process/development-protocols/all-development-protocols.md) for shared workflow protocols

## Development

No product package manifest has been committed yet. The planned stack is Python with pytest, Streamlit, and CodeGraph.

## 1 Agents

| Agent | Purpose |
|---|---|
| `vc-code-reviewer` | Production-readiness review and risk scouting |
| `vc-code-simplifier` | Behavior-preserving cleanup and readability refactors |
| `vc-debugger` | Root-cause investigation for bugs and failures |
| `vc-execute-agent` | Execute approved implementation plans |
| `vc-fast-mode-agent` | Compressed RIPER-5 workflow with execution pause |
| `vc-git-manager` | Git status, commit hygiene, and change grouping |
| `vc-innovate-agent` | Explore implementation options before planning |
| `vc-plan-agent` | Create detailed implementation plans |
| `vc-quick-fix-agent` | Low-risk small fixes |
| `vc-research-agent` | Read-only codebase and context research |
| `vc-spec-agent` | Product-discovery requirements specs |
| `vc-tester` | Diff-aware verification and test selection |
| `vc-ui-ux-designer` | Frontend and UX-focused implementation support |
| `vc-update-process-agent` | Process updates, context capture, and plan archival |
| `vc-validate-agent` | Validate plans before execution |

## 2 Skills

`vc-agent-browser`, `vc-agent-strategy-compare`, `vc-audit-context`, `vc-audit-plans`, `vc-audit-vc`, `vc-autopilot`, `vc-autoresearch`, `vc-context-discovery`, `vc-debug`, `vc-docs-seeker`, `vc-feasibility-test`, `vc-frontend-design`, `vc-generate-closeout`, `vc-generate-context`, `vc-generate-phase-program`, `vc-generate-plan`, `vc-generate-spec`, `vc-intent-clarify`, `vc-plan-discovery`, `vc-predict`, `vc-problem-solving`, `vc-publish`, `vc-review-situation`, `vc-risk-evidence-pack`, `vc-scenario`, `vc-scout`, `vc-security`, `vc-sequential-thinking`, `vc-setup`, `vc-test-coverage-plan`, `vc-update`, `vc-validate-findings`, `vc-web-testing`

## License

No license has been specified.
