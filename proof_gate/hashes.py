"""File hashing, glob resolution and freshness checks."""

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

MAX_HASH_BYTES = 32 * 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def relative(path: Path, root: Path) -> str:
    """Return a portable, slash-separated path relative to root."""
    try:
        value = Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        value = Path(path).as_posix()
    return value.replace(os.sep, "/")


def resolve_watches(root: Path, patterns: List[str]) -> List[Dict[str, str]]:
    """Expand glob patterns under root into sorted {path, sha256} entries."""
    base = Path(root).resolve()
    seen = set()
    result = []
    for pattern in patterns:
        for match in sorted(base.glob(pattern)):
            if not match.is_file():
                continue
            if any(part in (".git", ".proof", "__pycache__", "node_modules")
                   for part in match.parts):
                continue
            rel = relative(match, base)
            if rel in seen:
                continue
            seen.add(rel)
            try:
                if match.stat().st_size > MAX_HASH_BYTES:
                    continue
                checksum = sha256_file(match)
            except OSError:
                continue
            result.append({"path": rel, "sha256": checksum})
    return result


def check_freshness(
    root: Path, record: Dict[str, Any]
) -> Tuple[str, List[Dict[str, str]]]:
    """Return (status, details) for a record.

    status is 'fresh', 'stale' (content changed), 'missing' (file gone) or
    'empty' (record watches no files).
    """
    details = []
    base = Path(root).resolve()
    watched = record.get("watched") or []
    if not watched:
        return "empty", details
    status = "fresh"
    for item in watched:
        rel = str(item["path"])
        expected = str(item["sha256"])
        target = base / rel
        if not target.is_file():
            state = "missing"
            actual = ""
        else:
            try:
                actual = sha256_file(target)
            except OSError:
                state = "missing"
                actual = ""
            else:
                state = "fresh" if actual == expected else "stale"
        if state != "fresh" and status == "fresh":
            status = state
        elif state == "missing" and status == "stale":
            status = "missing"
        details.append({
            "path": rel,
            "expected": expected,
            "actual": actual,
            "status": state,
        })
    return status, details
