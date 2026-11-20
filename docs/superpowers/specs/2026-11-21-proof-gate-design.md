# proof-gate — design note (2026-11-21)

## Problem

"Fixed", "tests pass", "done" are claims. In agent sessions they are often
true at the moment they are written and false ten minutes later, after one
more edit. `verification-before-completion` says *run the command before
claiming*; it does not produce a portable artifact that a reviewer or a later
session can check.

## Answer

A claim is backed by a **proof record**: the exact command, its exit code, a
redacted output excerpt, a UTC timestamp, and SHA-256 hashes of the files the
claim is about. The record has a JSON source of truth (`.proof/<id>.json`) and
a readable twin (`.proof/<id>.md`).

Later, `verify` recomputes every hash. If a watched file changed, the proof is
**stale** and the command exits 1 — even if the original run really did pass.
This is the line that separates this skill from a checklist: freshness is
machine-decidable.

## Commands

- `record` — create a record, either by running a command (`--run`) or by
  importing already-captured output (`--command` + `--exit-code` +
  `--output-file`). Watched files are globbed and hashed at record time.
- `verify` — rehash watched files and check the record shape. Exit 0 fresh,
  1 stale/missing, 2 bad input.
- `scan` — find unproven claims in Markdown/text. A claim is proven when the
  same line or the next two lines carry `proof:<id>` and that record exists
  (and is fresh when `--require-fresh` is set).

## Non-goals

- No network, no git dependency, no external services.
- No trust in the recorded exit code as a substitute for rehashing: a stale
  proof is never accepted.
- No secret storage. Output is redacted before it touches disk.
- No claim about code correctness beyond "these bytes produced this result".

## Portability

Python 3.8+, standard library only, ASCII-safe paths, LF newlines in output
files, relative paths inside records. CI matrix mirrors trap-radar:
Ubuntu 24.04 + Windows 2022 × Python 3.9 / 3.13.
