# proof-gate

[![test](https://github.com/cangurel81/proof-gate/actions/workflows/test.yml/badge.svg)](https://github.com/cangurel81/proof-gate/actions/workflows/test.yml)

Back a completion claim with portable evidence: the command, its exit code, a
redacted output excerpt, a UTC timestamp, and SHA-256 hashes of the files the
claim is about. Later, rehash those files. If anything changed, the proof is
stale and the gate exits 1 — even if the original run really did pass.

Standard library only, Python 3.8+, no network, no git dependency, MIT licensed.

## Why this exists

`verification-before-completion` says *run the command before you say it is
done*. It does not leave an artifact that the next session or a reviewer can
check. A proof record does. Its freshness check is machine-decidable, which is
the difference between a checklist and a gate.

## Download

[proof-gate.zip](https://github.com/cangurel81/proof-gate/releases/latest/download/proof-gate.zip) — source archive, no dependencies.

## Install

No dependencies:

```sh
python scripts/proof-gate.py record <id> --run "<command>" --watch "src/**/*.py"
```

Or as a module:

```sh
python -m proof_gate verify <id>
```

## Commands

```sh
# Run a command, capture output, hash the files it concerns
python scripts/proof-gate.py record tests-31 \
  --run "python -m unittest discover -s test" \
  --watch "test/**/*.py" --watch "src/**/*.py" \
  --claim "All 31 unit tests pass"

# Already ran it? Import the captured output instead of rerunning
python scripts/proof-gate.py record build-ok \
  --command "python -m build" --exit-code 0 \
  --output-file build.log --watch "pyproject.toml" --claim "Package builds"

# Check freshness now (0 = fresh, 1 = stale/missing, 2 = bad input)
python scripts/proof-gate.py verify tests-31 --json

# Find claims in docs with no proof marker
python scripts/proof-gate.py scan . --fail-on any --require-fresh
```

`record` creates two files: `.proof/<id>.json` (source of truth) and
`.proof/<id>.md` (readable twin). At least one `--watch` glob is required;
paths inside the record are relative and slash-separated.

## Claim convention

In Markdown or text, a claim is considered proven when the same line or the
next two lines carry `proof:<id>` and that record exists:

```md
All 31 unit tests pass proof:tests-31
```

`scan` reports:

| Check | Severity | Meaning |
|---|---|---|
| `unproven_claim` | medium | Claim found, no `proof:<id>` marker nearby |
| `missing_proof` | high | Marker points to a record that is absent or malformed |
| `stale_proof` | high | With `--require-fresh`: watched bytes changed since recording |

Exit codes for `scan`: **0** clean, **1** a finding reached `--fail-on`,
**2** bad input. Default `--fail-on never` keeps exploration green.

## Safety

- Output is redacted before it touches disk: key/token/password assignments,
  `Bearer` tokens, `sk-`/`ghp_`/`github_pat_` keys and private-key blocks.
- Each stream is capped at 8000 characters with an explicit truncation marker.
- `--run` uses the platform shell. Only run commands you trust.
- `verify` never rewrites a record; a stale proof stays stale until you record
  a new one after re-running the command.

## Scope limits

- Scans `.md`, `.txt` and `.rst`; skips `.git`, `.proof`, `node_modules`,
  `dist`, `build`, `__pycache__` and `.venv`.
- Caps at 2000 files and 2 MB per file; the report says when it stopped early.
- Hashes files up to 32 MB; larger watched matches are skipped.
- The recorded exit code is evidence of what happened, not a guarantee of
  current correctness. Freshness is what the gate enforces.

## Tests

```sh
python -m compileall -q proof_gate scripts test
python -m unittest discover -s test -v
python scripts/proof-gate.py scan . --json --fail-on never
```

38 unit tests, no network, no git and no `gh` required.
