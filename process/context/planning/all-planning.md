---
name: context:all-planning
description: "Planning group entrypoint — SIMPLE vs COMPLEX plan calibration and example plan shapes"
keywords: planning, plan, prd, simple, complex, calibration, example
related: []
date: 27-06-26
---

# Planning Context

This file is the canonical planning context entrypoint for malguard.

Use it after `process/context/all-context.md` when the task needs plan-shape calibration,
planning conventions, or implementation-plan examples.

## Scope

This group covers:

- example plan shapes
- SIMPLE vs COMPLEX plan calibration
- durable planning references that should not stay at the `process/context/` root

It does not cover:

- active implementation plans
- feature reports
- backlog items

Those belong under `process/general-plans/` or `process/features/`.

> **Note:** the hackathon's own plan lives at `HACKATHON_PLAN.md` (repo root) — that is the scope
> source of truth for this project, kept at the root so it can be committed and shared with the team.
> New RIPER-5 plan artifacts produced by `vc-plan-agent` go under `process/general-plans/active/`.

## Read When

Read this entrypoint when:

- creating a new plan with `vc-generate-plan`
- checking whether work should be `SIMPLE` or `COMPLEX`
- comparing an active plan against the repo's example plan shapes

## Quick Routing

- use `.claude/skills/vc-generate-plan/references/example-simple-prd.md` to calibrate a one-session plan
- use `.claude/skills/vc-generate-plan/references/example-complex-prd.md` to calibrate a complex or multi-phase plan

## Source Paths

- `.claude/skills/vc-generate-plan/references/example-simple-prd.md`
- `.claude/skills/vc-generate-plan/references/example-complex-prd.md`

## Update Triggers

Update this group when:

- the plan artifact contract changes
- `vc-generate-plan` expects different plan sections or statuses
- the example plan shapes move, split, or become stale
