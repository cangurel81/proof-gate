"""Command execution and secret-safe output capture."""

import re
import subprocess
from pathlib import Path
from typing import Optional, Tuple

MAX_OUTPUT = 8000

REDACTORS = [
    (re.compile(r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd)\b\s*[:=]\s*\S+"),
     lambda m: m.group(1) + "=<redacted>"),
    (re.compile(r"\bBearer\s+\S+"), lambda m: "Bearer <redacted>"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"), lambda m: "<redacted>"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}"), lambda m: "<redacted>"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), lambda m: "<redacted>"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     lambda m: "<redacted private key>"),
]


def redact(text: str) -> str:
    for pattern, replacement in REDACTORS:
        text = pattern.sub(replacement, text)
    return text


def clip(text: str, limit: int = MAX_OUTPUT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... [truncated %d chars]" % (len(text) - limit)


def clean(text: str) -> str:
    return clip(redact(text.replace("\r\n", "\n").replace("\r", "\n")))


def read_output_file(path: Optional[str]) -> str:
    if not path:
        return ""
    data = Path(path).read_bytes()
    return clean(data.decode("utf-8", errors="replace"))


def run_command(command: str) -> Tuple[int, str, str]:
    """Run via the platform shell, capturing output. Returns (code, out, err)."""
    try:
        completed = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        code = completed.returncode
        out = completed.stdout.decode("utf-8", errors="replace")
        err = completed.stderr.decode("utf-8", errors="replace")
    except OSError as exc:
        return 2, "", "cannot run command: %s\n" % exc
    return code, clean(out), clean(err)
