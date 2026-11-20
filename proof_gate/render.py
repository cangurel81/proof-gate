"""Human-readable and JSON output for proof-gate."""

import json
from typing import Any, Dict, List, Optional


def to_json(command: str, payload: Dict[str, Any]) -> str:
    body = {"tool": "proof-gate", "command": command}
    body.update(payload)
    return json.dumps(body, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def record_markdown(record: Dict[str, Any]) -> str:
    lines = [
        "# Proof: %s" % record["id"],
        "",
        "- Claim: %s" % record.get("claim", ""),
        "- Created (UTC): %s" % record.get("created_utc", ""),
        "- Command: `%s`" % record.get("command", ""),
        "- Exit code: %s" % record.get("exit_code", ""),
        "- Working directory: `%s`" % record.get("cwd", "."),
        "- Tool version: %s" % record.get("version", ""),
        "",
    ]
    if record.get("note"):
        lines += ["## Note", "", str(record["note"]), ""]
    watched = record.get("watched") or []
    lines += ["## Watched files", ""]
    if watched:
        for item in watched:
            lines.append("- `%s` — `%s`" % (item["path"], item["sha256"]))
    else:
        lines.append("_none_")
    lines += ["", "## stdout", "", "```text"]
    lines.append(str(record.get("stdout") or "_empty_").rstrip())
    lines += ["```", "", "## stderr", "", "```text"]
    lines.append(str(record.get("stderr") or "_empty_").rstrip())
    lines += ["```", ""]
    return "\n".join(lines)


def verify_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Proof verification: %s" % report["id"],
        "",
        "- Status: **%s**" % report["status"],
        "- Claim: %s" % report.get("claim", ""),
        "- Created (UTC): %s" % report.get("created_utc", ""),
        "",
        "| File | Expected | Actual | Status |",
        "|---|---|---|---|",
    ]
    for item in report.get("files", []):
        lines.append("| `%s` | `%s` | `%s` | %s |" % (
            item["path"], item["expected"], item["actual"] or "-", item["status"],
        ))
    lines.append("")
    return "\n".join(lines)


def scan_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Unproven claim scan",
        "",
        "- Root: `%s`" % report["root"],
        "- Claims found: %d" % report["claim_count"],
        "- Findings: %d" % len(report["findings"]),
        "",
        "| Severity | Check | File:line | Text |",
        "|---|---|---|---|",
    ]
    for item in report["findings"]:
        text = item["text"].replace("|", "\\|")
        lines.append("| %s | %s | `%s:%d` | %s |" % (
            item["severity"], item["check"], item["path"], item["line"], text,
        ))
    lines.append("")
    return "\n".join(lines)
