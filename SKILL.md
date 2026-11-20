---
name: proof-gate
description: Back "done", "fixed" or "tests pass" claims with portable evidence before reporting completion. Use before telling a user that work is complete, after a fix or test run, when a reviewer asks for proof, or when a claim needs to stay valid after later edits. Creates a `.proof/<id>.json` record with command, exit code, redacted output, UTC timestamp and SHA-256 hashes, then rehashes on demand and fails when the proof is stale.
---

# Proof Gate

A claim is not evidence. This skill turns a verification run into a small,
portable artifact that a later session or a reviewer can check without trusting
the original author.

A record stores:

- the exact command that was run (or imported),
- the observed exit code,
- a redacted, capped excerpt of stdout/stderr,
- a UTC timestamp and tool version,
- SHA-256 hashes of the files the claim is about.

Later, `verify` recomputes every hash. If any watched byte changed, the proof is
**stale** and exits 1. This is the gate: machine-decidable freshness, not a
checklist.

Standard library only, Python 3.8+, no network, no git dependency, MIT licensed.

## When to use

- Before saying "done", "fixed", "tests pass", "verified" or "ship it".
- After a test, build, lint or migration run that will be cited in a report.
- When a reviewer asks "did you actually run it?" and output must be shown.
- When a claim lives in a README, report or handoff and should not rot silently.
- When the same workspace will be edited again after the claim is written.

## Commands

```
python scripts/proof-gate.py record <id> --run "<command>" --watch "<glob>" [--claim "<text>"] [--json]
python scripts/proof-gate.py record <id> --command "<command>" --exit-code N --output-file <file> --watch "<glob>"
python scripts/proof-gate.py verify <id> [--json] [--output <file>]
python scripts/proof-gate.py scan <path> [--require-fresh] [--fail-on never|any|medium|high] [--json] [--output <file>]
```

`record` writes two files: `.proof/<id>.json` (source of truth) and
`.proof/<id>.md` (readable twin). At least one `--watch` must match an existing
file; at record time the matched files are hashed. `--run` executes a trusted
command through the platform shell. For past output, use `--command` with
`--exit-code` and optional `--output-file` / `--stderr-file`.

## Output and exit contract

- `--json` emits one object with `tool`, `command` and command-specific fields.
- `verify`: `0` fresh, `1` stale/missing/empty, `2` bad input or malformed record.
- `scan`: `0` clean (default `--fail-on never`), `1` a finding reached the
  threshold, `2` bad input.
- `record`: `0` saved, `2` bad input. It never silently saves an empty watch set.
- Freshness states: `fresh`, `stale`, `missing`, `empty`.
- `verify` never rewrites a record. Re-run the command and record a new proof.

## Claim convention

In Markdown or text, a claim counts as proven when the same line or the next two
lines carry `proof:<id>` and that record exists:

```md
All 38 unit tests pass proof:tests-38
```

`scan` findings:

| Check | Severity | Meaning |
|---|---|---|
| `unproven_claim` | medium | Claim found, no nearby `proof:<id>` marker |
| `missing_proof` | high | Marker points to an absent or malformed record |
| `stale_proof` | high | With `--require-fresh`: watched bytes changed since recording |

## Safety

- Output is redacted before it touches disk: key/token/password assignments,
  `Bearer` tokens, `sk-`/`ghp_`/`github_pat_` keys and private-key blocks.
- Each stream is capped at 8000 characters with an explicit truncation marker.
- Record paths are relative and slash-separated; output files use LF newlines.
- `--run` uses the shell. Only run commands you trust.
- A recorded exit code is evidence of the past run, not a correctness guarantee.
  Freshness is what the gate enforces.

## Scope limits

- `scan` reads `.md`, `.txt` and `.rst`; skips `.git`, `.proof`, `node_modules`,
  `dist`, `build`, `__pycache__` and `.venv`.
- Scan caps: 2000 files, 2 MB per file; the report says when it stopped early.
- Hash cap: files over 32 MB are skipped from a watch expansion.
- No semantic check that the command still exists or is still the right test.

## Verification

```
python -m compileall -q proof_gate scripts test
python -m unittest discover -s test -v
python scripts/proof-gate.py scan . --json --fail-on never
```

38 unit tests, no network, no git and no `gh` required.
