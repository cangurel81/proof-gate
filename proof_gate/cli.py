"""Command line interface for proof-gate."""

import argparse
import re
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .capture import read_output_file, run_command
from .hashes import check_freshness, relative, resolve_watches
from .model import ProofError, load_record, new_record, save_record
from .render import scan_markdown, to_json, verify_markdown

CLAIM_PATTERNS = [
    ("test_claim", re.compile(r"\b(?:all\s+\d+\s+)?tests?\s+(?:pass|passed|green|ok)\b", re.I)),
    ("completion_claim", re.compile(
        r"\b(?:bitti|tamamland[ıi]|geçti|fixed|resolved|verified|done|completed)\b", re.I)),
]
PROOF_MARKER = re.compile(r"\bproof:([A-Za-z0-9][A-Za-z0-9._-]{0,79})\b")
SCAN_EXT = {".md", ".txt", ".rst"}
SCAN_SKIP = {".git", ".proof", "__pycache__", "node_modules", "dist", "build", ".venv"}
MAX_SCAN_FILES = 2000
MAX_SCAN_BYTES = 2 * 1024 * 1024


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proof-gate",
        description="Back completion claims with portable, freshness-checked evidence.",
    )
    parser.add_argument("--version", action="version", version="proof-gate " + __version__)
    commands = parser.add_subparsers(dest="command")

    record = commands.add_parser("record", help="create a proof record")
    record.add_argument("id", help="proof id, e.g. trap-radar-tests")
    record.add_argument("--claim", default="", help="the claim being backed")
    record.add_argument("--run", metavar="CMD", help="run this command and capture its output")
    # dest must differ from the subparser dest "command", otherwise argparse
    # overwrites the selected subcommand with this string value.
    record.add_argument("--command", dest="command_text", metavar="CMD",
                        help="command text when importing past output")
    record.add_argument("--exit-code", type=int, help="exit code when importing past output")
    record.add_argument("--output-file", metavar="FILE", help="file holding captured stdout")
    record.add_argument("--stderr-file", metavar="FILE", help="file holding captured stderr")
    record.add_argument("--watch", action="append", default=[], metavar="GLOB",
                        help="file or glob to hash; repeatable, at least one required")
    record.add_argument("--note", default="", help="optional human note")
    record.add_argument("--root", default=".", help="workspace root (default: .)")
    record.add_argument("--json", action="store_true", help="emit one JSON object")

    verify = commands.add_parser("verify", help="rehash watched files and check freshness")
    verify.add_argument("id", help="proof id to verify")
    verify.add_argument("--root", default=".", help="workspace root (default: .)")
    verify.add_argument("--json", action="store_true", help="emit one JSON object")
    verify.add_argument("--output", metavar="FILE", help="also write the report to FILE")

    scan = commands.add_parser("scan", help="find claims with no proof marker")
    scan.add_argument("path", nargs="?", default=".", help="folder to scan (default: .)")
    scan.add_argument("--require-fresh", action="store_true",
                      help="treat a stale or missing proof as a finding")
    scan.add_argument("--fail-on", choices=["never", "any", "medium", "high"],
                      default="never", help="exit 1 when a finding reaches this severity")
    scan.add_argument("--json", action="store_true", help="emit one JSON object")
    scan.add_argument("--output", metavar="FILE", help="also write the report to FILE")
    return parser


def _emit(text: str, output: Optional[str], json_mode: bool) -> None:
    if output:
        target = Path(output)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        if not json_mode:
            print("Wrote %s" % target)
    if not output or json_mode:
        print(text, end="" if text.endswith("\n") else "\n")


def _severity_rank(value: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(value, 0)


def cmd_record(args: argparse.Namespace) -> int:
    root = Path(args.root)
    if not root.is_dir():
        print("error: not a directory: %s" % root, file=sys.stderr)
        return 2
    if not args.watch:
        print("error: record needs at least one --watch pattern", file=sys.stderr)
        return 2
    if args.run:
        exit_code, out, err = run_command(args.run)
        command = args.run
    else:
        if args.command_text is None or args.exit_code is None:
            print("error: use --run, or both --command and --exit-code", file=sys.stderr)
            return 2
        exit_code = args.exit_code
        command = args.command_text
        out = read_output_file(args.output_file)
        err = read_output_file(args.stderr_file)
    watched = resolve_watches(root, args.watch)
    if not watched:
        print("error: no existing files matched --watch", file=sys.stderr)
        return 2
    try:
        record = new_record(
            args.id, args.claim, command, exit_code, watched,
            stdout=out, stderr=err, note=args.note, cwd=relative(Path.cwd(), root),
        )
        json_file, md_file = save_record(root, record)
    except ProofError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        _emit(to_json("record", {
            "id": args.id, "json": str(json_file), "markdown": str(md_file),
            "watched": len(watched), "exit_code_observed": exit_code,
        }), None, True)
    else:
        print("Recorded proof %s" % args.id)
        print("  JSON: %s" % json_file)
        print("  Markdown: %s" % md_file)
        print("  Watched files: %d" % len(watched))
        print("  Observed exit code: %d" % exit_code)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    root = Path(args.root)
    if not root.is_dir():
        print("error: not a directory: %s" % root, file=sys.stderr)
        return 2
    try:
        record = load_record(root, args.id)
    except ProofError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    status, details = check_freshness(root, record)
    report = {
        "id": args.id,
        "status": status,
        "claim": record.get("claim", ""),
        "created_utc": record.get("created_utc", ""),
        "files": details,
    }
    if args.json:
        _emit(to_json("verify", report), args.output, True)
    else:
        _emit(verify_markdown(report), args.output, False)
    return 0 if status == "fresh" else 1


def _scan_file(path: Path, root: Path, root_label: str, require_fresh: bool) -> List[dict]:
    try:
        if path.stat().st_size > MAX_SCAN_BYTES:
            return []
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    findings = []
    for index, line in enumerate(lines):
        kinds = {name for name, pattern in CLAIM_PATTERNS if pattern.search(line)}
        if not kinds:
            continue
        marker = None
        for ahead in range(0, 3):
            target = index + ahead
            if target >= len(lines):
                break
            match = PROOF_MARKER.search(lines[target])
            if match:
                marker = match.group(1)
                break
        rel = relative(path, root)
        info = {
            "path": rel if root_label else path.as_posix(),
            "line": index + 1,
            "text": line.strip()[:160],
            "kinds": sorted(kinds),
            "marker": marker,
        }
        if not marker:
            info.update(check="unproven_claim", severity="medium",
                        detail="No proof:<id> marker on this line or the next two.")
            findings.append(info)
            continue
        try:
            record = load_record(root, marker)
        except ProofError:
            info.update(check="missing_proof", severity="high",
                        detail="Referenced proof record does not exist or is malformed.")
            findings.append(info)
            continue
        if require_fresh:
            status, _ = check_freshness(root, record)
            if status != "fresh":
                info.update(check="stale_proof", severity="high",
                            detail="Proof status is '%s' after rehashing." % status)
                findings.append(info)
    return findings


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    if not root.is_dir():
        print("error: not a directory: %s" % root, file=sys.stderr)
        return 2
    findings = []
    files = sorted(path for path in root.rglob("*")
                   if path.is_file() and path.suffix.lower() in SCAN_EXT
                   and not SCAN_SKIP.intersection(path.parts))
    for path in files[:MAX_SCAN_FILES]:
        findings.extend(_scan_file(path, root, True, args.require_fresh))
    claim_count = 0
    for path in files[:MAX_SCAN_FILES]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for _, pattern in CLAIM_PATTERNS:
            claim_count += len(pattern.findall(text))
    findings.sort(key=lambda item: (-_severity_rank(item["severity"]), item["path"], item["line"]))
    report = {
        "root": str(root),
        "claim_count": claim_count,
        "findings": findings[:200],
        "truncated": len(files) > MAX_SCAN_FILES,
    }
    if args.json:
        _emit(to_json("scan", report), args.output, True)
    else:
        _emit(scan_markdown(report), args.output, False)
    threshold = _severity_rank("medium" if args.fail_on == "any" else args.fail_on)
    for item in report["findings"]:
        if _severity_rank(item["severity"]) >= threshold and threshold > 0:
            return 1
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    try:
        if args.command == "record":
            return cmd_record(args)
        if args.command == "verify":
            return cmd_verify(args)
        if args.command == "scan":
            return cmd_scan(args)
    except ProofError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    return 2
