"""Proof record model: validate, load and save portable JSON artifacts."""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__

SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
REQUIRED = (
    "tool", "version", "id", "created_utc", "claim", "command",
    "exit_code", "watched",
)


class ProofError(ValueError):
    """Raised for a malformed proof id or record."""


def validate_id(proof_id: str) -> str:
    if not isinstance(proof_id, str) or not SAFE_ID.match(proof_id):
        raise ProofError(
            "invalid proof id: use 1-80 letters, digits, '.', '_' or '-' "
            "and start with a letter or digit"
        )
    if proof_id in (".", "..") or ".." in proof_id:
        raise ProofError("invalid proof id: path traversal is not allowed")
    return proof_id


def proof_dir(root: Path) -> Path:
    return Path(root) / ".proof"


def json_path(root: Path, proof_id: str) -> Path:
    return proof_dir(root) / (validate_id(proof_id) + ".json")


def markdown_path(root: Path, proof_id: str) -> Path:
    return proof_dir(root) / (validate_id(proof_id) + ".md")


def new_record(
    proof_id: str,
    claim: str,
    command: str,
    exit_code: int,
    watched: List[Dict[str, str]],
    stdout: str = "",
    stderr: str = "",
    note: str = "",
    cwd: str = ".",
) -> Dict[str, Any]:
    from .hashes import utc_now

    validate_id(proof_id)
    return {
        "tool": "proof-gate",
        "version": __version__,
        "id": proof_id,
        "created_utc": utc_now(),
        "claim": claim,
        "command": command,
        "exit_code": int(exit_code),
        "stdout": stdout,
        "stderr": stderr,
        "note": note,
        "cwd": cwd,
        "watched": watched,
    }


def validate_record(record: Any) -> Dict[str, Any]:
    if not isinstance(record, dict):
        raise ProofError("proof record must be a JSON object")
    missing = [key for key in REQUIRED if key not in record]
    if missing:
        raise ProofError("proof record is missing: " + ", ".join(missing))
    validate_id(str(record["id"]))
    if not isinstance(record["watched"], list):
        raise ProofError("proof record 'watched' must be a list")
    for item in record["watched"]:
        if not isinstance(item, dict) or "path" not in item or "sha256" not in item:
            raise ProofError("each watched entry needs 'path' and 'sha256'")
        if not re.match(r"^[0-9a-f]{64}$", str(item["sha256"])):
            raise ProofError("invalid sha256 for " + str(item["path"]))
    return record


def load_record(root: Path, proof_id: str) -> Dict[str, Any]:
    path = json_path(root, proof_id)
    if not path.is_file():
        raise ProofError("no proof record: " + str(path))
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ProofError("cannot read proof record %s: %s" % (path, exc))
    return validate_record(data)


def list_proofs(root: Path) -> List[str]:
    directory = proof_dir(root)
    if not directory.is_dir():
        return []
    return sorted(
        path.stem for path in directory.glob("*.json")
        if SAFE_ID.match(path.stem)
    )


def save_record(root: Path, record: Dict[str, Any]) -> Tuple[Path, Path]:
    validate_record(record)
    directory = proof_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    proof_id = str(record["id"])
    target = json_path(root, proof_id)
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(record, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    twin = markdown_path(root, proof_id)
    from .render import record_markdown
    with twin.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(record_markdown(record))
    return target, twin
