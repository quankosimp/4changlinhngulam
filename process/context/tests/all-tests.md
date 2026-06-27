---
name: context:all-tests
description: "Tests group entrypoint — pytest commands, the detection corpus, and accuracy verification"
keywords: tests, pytest, testing, corpus, verification, accuracy, false positive, recall, precision
related: []
date: 27-06-26
---

# malguard - All Tests

Last updated: 2026-06-27

Attach this file first when the task involves testing, verification, or test debugging.

This is the fast operator guide for the testing surface: which runner to use, what command to start
with, how to debug common failures, and which deeper file to read next.

> **Status:** Test suite is _planned_, not yet committed. The commands below are the agreed target
> from `HACKATHON_PLAN.md`. The primary "test" during the hackathon is the **detection corpus** —
> running the scanner against known-malicious and known-benign samples and checking the hit rate.

---

## What This Covers

- test runner selection
- quick commands
- the detection corpus (how malguard's accuracy is verified)
- current testing gaps worth remembering

## Read This When

- running tests after implementing a rule
- verifying detection accuracy against the corpus
- debugging a false positive / false negative

## Quick Routing

(No deeper test docs yet. Add routing entries here as they are created.)

## Quick Decision Guide

### Use `pytest` for everything _(planned)_

- All unit tests run through pytest (`pip install pytest`).
- `pytest` from the repo root runs the whole suite.
- `pytest tests/test_ast_rules.py` for a single file.

### Use the detection corpus to verify accuracy (primary acceptance signal)

The most important verification is not a unit test — it is running the scanner against the sample
corpus and checking signal vs noise:

- **Recall:** scanning `tests/corpus/malicious/` must flag ≥ 8 of 10 samples.
- **Precision:** scanning `tests/corpus/benign/` should produce ~0–2 false positives.

## Default Verification Order

1. run the narrowest existing automated test (the rule's own pytest file)
2. run the scanner against the relevant corpus subset
3. only then run the full corpus + dashboard end-to-end

## Commands

| Scope | Runner | Command | Notes |
|---|---|---|---|
| unit tests | pytest | `pytest` | _(planned — once `tests/` exists)_ |
| scan malicious corpus | malguard CLI | `python -m malguard scan tests/corpus/malicious --json > report.json` | expect ≥8/10 flagged |
| scan benign corpus | malguard CLI | `python -m malguard scan tests/corpus/benign --json` | expect ~0–2 false positives |
| CodeGraph index health | codegraph | `codegraph status` | verify index built before graph rules |
| dashboard (manual) | streamlit | `streamlit run malguard/dashboard/app.py` | reads `report.json` |

## Debugging Quick Reference

- **CodeGraph not returning call paths:** confirm `codegraph init` ran and `codegraph status` shows
  nodes/edges; check the language is supported. Fall back to the regex call-heuristic if blocked.
- **Too many false positives:** tighten the entropy threshold for high-entropy-string rules and
  require co-occurring signals (e.g. decode + exec in the same function) before raising severity.
- **MCP agent flaky during demo:** use the pre-canned fixed query path and a saved "good" `report.json`.

## Known Gaps

- No unit tests committed yet (suite is planned).
- No CI configured.
- The corpus must be assembled (target ~10 malicious + ~10 benign) before accuracy claims are meaningful.
