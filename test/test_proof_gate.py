import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from proof_gate.capture import clean, clip, redact, read_output_file, run_command
from proof_gate.cli import main
from proof_gate.hashes import check_freshness, resolve_watches, sha256_file, utc_now
from proof_gate.model import (
    ProofError, list_proofs, load_record, new_record, save_record, validate_id,
)

if os.name == "nt":
    TEST_BASE = Path("C:/Users/Public/repo-audit/.test-tmp")
else:
    TEST_BASE = Path(tempfile.gettempdir())
TEST_BASE.mkdir(parents=True, exist_ok=True)


def tmpdir(prefix):
    return Path(tempfile.mkdtemp(prefix=prefix, dir=str(TEST_BASE)))


def write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def json_out(text):
    return json.loads(text)


class TestCapture(unittest.TestCase):
    def test_redact_key_value(self):
        text = 'token=sk-abcdefgh1234 password: hunter2 api_key: xyz\n'
        result = redact(text)
        self.assertNotIn("hunter2", result)
        self.assertNotIn("xyz", result)
        self.assertIn("<redacted>", result)

    def test_redact_bearer_and_github_token(self):
        text = "Authorization: Bearer abc.def.ghi ghp_" + "a" * 30
        result = redact(text)
        self.assertNotIn("abc.def.ghi", result)
        self.assertNotIn("a" * 30, result)

    def test_redact_private_key_block(self):
        text = ("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n")
        self.assertIn("<redacted private key>", redact(text))

    def test_clean_normalizes_newlines(self):
        self.assertEqual(clean("a\r\nb\rc"), "a\nb\nc")

    def test_clip_marks_truncation(self):
        result = clip("x" * 120, limit=20)
        self.assertTrue(result.endswith("[truncated 100 chars]"))

    def test_read_output_file_replaces_bad_bytes(self):
        path = TEST_BASE / "bad-output.bin"
        path.write_bytes(b"abc\xff\xfedef")
        self.assertIn("abc", read_output_file(str(path)))

    def test_run_command_captures_real_exit_code(self):
        command = '"%s" -c "print(chr(104)+chr(105))" && "%s" -c "raise SystemExit(7)"' % (
            sys.executable, sys.executable,
        )
        if os.name != "nt":
            command = "%s -c \"print('hi')\"; %s -c \"raise SystemExit(7)\"" % (
                sys.executable, sys.executable,
            )
        code, out, err = run_command(command)
        self.assertEqual(code, 7, err)
        self.assertIn("hi", out)


class TestHashes(unittest.TestCase):
    def setUp(self):
        self.root = tmpdir("pg-hash-")

    def test_utc_now_shape(self):
        self.assertRegex(utc_now(), r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_sha256_file(self):
        path = write_text(self.root / "a.txt", "hello")
        self.assertEqual(
            sha256_file(path),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )

    def test_resolve_watches_sorted_and_portable(self):
        write_text(self.root / "b.txt", "b")
        write_text(self.root / "a.txt", "a")
        write_text(self.root / ".git" / "secret.txt", "no")
        watched = resolve_watches(self.root, ["*.txt", "a.txt"])
        self.assertEqual([item["path"] for item in watched], ["a.txt", "b.txt"])
        self.assertTrue(all("/" in item["path"] or "." in item["path"] for item in watched))

    def test_check_freshness_fresh(self):
        path = write_text(self.root / "a.txt", "v1")
        watched = resolve_watches(self.root, ["a.txt"])
        record = {"watched": watched}
        status, details = check_freshness(self.root, record)
        self.assertEqual(status, "fresh")
        self.assertEqual(details[0]["status"], "fresh")

    def test_check_freshness_stale_after_edit(self):
        path = write_text(self.root / "a.txt", "v1")
        watched = resolve_watches(self.root, ["a.txt"])
        path.write_text("v2", encoding="utf-8")
        status, details = check_freshness(self.root, {"watched": watched})
        self.assertEqual(status, "stale")
        self.assertEqual(details[0]["status"], "stale")

    def test_check_freshness_missing(self):
        write_text(self.root / "a.txt", "v1")
        watched = resolve_watches(self.root, ["a.txt"])
        (self.root / "a.txt").unlink()
        status, details = check_freshness(self.root, {"watched": watched})
        self.assertEqual(status, "missing")
        self.assertEqual(details[0]["actual"], "")

    def test_check_freshness_empty(self):
        self.assertEqual(check_freshness(self.root, {"watched": []})[0], "empty")


class TestModel(unittest.TestCase):
    def setUp(self):
        self.root = tmpdir("pg-model-")

    def test_validate_id_rules(self):
        self.assertEqual(validate_id("abc-1"), "abc-1")
        for bad in ("", "../x", "a/b", "..", "-bad"):
            with self.assertRaises(ProofError):
                validate_id(bad)

    def test_save_load_roundtrip_and_twin(self):
        write_text(self.root / "a.txt", "x")
        watched = resolve_watches(self.root, ["a.txt"])
        record = new_record("demo-1", "tests pass", "python -m unittest", 0, watched,
                            stdout="OK", note="note")
        js, md = save_record(self.root, record)
        self.assertTrue(js.is_file())
        self.assertTrue(md.is_file())
        loaded = load_record(self.root, "demo-1")
        self.assertEqual(loaded["id"], "demo-1")
        self.assertEqual(loaded["stdout"], "OK")
        self.assertIn("# Proof: demo-1", md.read_text(encoding="utf-8"))
        self.assertEqual(list_proofs(self.root), ["demo-1"])

    def test_load_missing_raises(self):
        with self.assertRaises(ProofError):
            load_record(self.root, "nope")

    def test_malformed_record_rejected(self):
        directory = self.root / ".proof"
        directory.mkdir()
        (directory / "bad.json").write_text('{"id":"bad"}', encoding="utf-8")
        with self.assertRaises(ProofError):
            load_record(self.root, "bad")

    def test_bad_checksum_rejected(self):
        record = new_record("badhash", "x", "cmd", 0, [{"path": "a", "sha256": "xyz"}])
        with self.assertRaises(ProofError):
            save_record(self.root, record)


class TestCli(unittest.TestCase):
    def setUp(self):
        self.root = tmpdir("pg-cli-")
        write_text(self.root / "src.py", "x = 1\n")

    def record(self, proof_id="p1", watch="src.py", **kwargs):
        args = ["record", proof_id, "--root", str(self.root), "--watch", watch,
                "--claim", kwargs.pop("claim", "tests pass")]
        for key, value in kwargs.items():
            args += ["--" + key.replace("_", "-"), str(value)]
        return run_cli(args)

    def test_record_import_mode(self):
        out_file = self.root / "captured.txt"
        out_file.write_text("Ran 3 tests\n\nOK\n", encoding="utf-8")
        code, out, err = run_cli([
            "record", "import-1", "--root", str(self.root), "--watch", "src.py",
            "--claim", "tests pass", "--command", "python -m unittest",
            "--exit-code", "0", "--output-file", str(out_file),
        ])
        self.assertEqual(code, 0, err)
        self.assertIn("Watched files: 1", out)
        record = load_record(self.root, "import-1")
        self.assertEqual(record["exit_code"], 0)
        self.assertIn("Ran 3 tests", record["stdout"])

    def test_record_run_mode(self):
        code, out, err = run_cli([
            "record", "run-1", "--root", str(self.root), "--watch", "src.py",
            "--run", "%s -c \"print('ok')\"" % os.sys.executable,
        ])
        self.assertEqual(code, 0, err)
        self.assertEqual(load_record(self.root, "run-1")["stdout"].strip(), "ok")

    def test_record_redacts_secret_from_imported_output(self):
        out_file = self.root / "leak.txt"
        out_file.write_text("token=supersecretvalue\n", encoding="utf-8")
        code, _, err = run_cli([
            "record", "safe-1", "--root", str(self.root), "--watch", "src.py",
            "--command", "echo", "--exit-code", "0", "--output-file", str(out_file),
        ])
        self.assertEqual(code, 0, err)
        self.assertNotIn("supersecretvalue",
                         (self.root / ".proof" / "safe-1.json").read_text(encoding="utf-8"))

    def test_record_without_watch_fails(self):
        code, _, err = run_cli([
            "record", "nowatch", "--root", str(self.root), "--command", "x", "--exit-code", "0",
        ])
        self.assertEqual(code, 2)
        self.assertIn("--watch", err)

    def test_record_with_no_matching_file_fails(self):
        code, _, err = run_cli([
            "record", "nomatch", "--root", str(self.root), "--watch", "missing.py",
            "--command", "x", "--exit-code", "0",
        ])
        self.assertEqual(code, 2)
        self.assertIn("no existing files", err)

    def test_verify_fresh_zero_and_json(self):
        self.record("ok-1", command="echo", exit_code="0")
        code, out, _ = run_cli(["verify", "ok-1", "--root", str(self.root), "--json"])
        self.assertEqual(code, 0)
        payload = json_out(out)
        self.assertEqual(payload["status"], "fresh")
        self.assertEqual(payload["command"], "verify")
        self.assertEqual(payload["files"][0]["status"], "fresh")

    def test_verify_stale_returns_one(self):
        self.record("stale-1", command="echo", exit_code="0")
        write_text(self.root / "src.py", "x = 2\n")
        code, _, err = run_cli(["verify", "stale-1", "--root", str(self.root)])
        self.assertEqual(code, 1, err)

    def test_verify_missing_returns_one(self):
        self.record("gone-1", command="echo", exit_code="0")
        (self.root / "src.py").unlink()
        code, _, _ = run_cli(["verify", "gone-1", "--root", str(self.root)])
        self.assertEqual(code, 1)

    def test_verify_unknown_id_returns_two(self):
        code, _, err = run_cli(["verify", "unknown", "--root", str(self.root)])
        self.assertEqual(code, 2)
        self.assertIn("no proof record", err)

    def test_verify_output_file(self):
        self.record("file-1", command="echo", exit_code="0")
        target = self.root / "reports" / "verify.md"
        code, _, _ = run_cli([
            "verify", "file-1", "--root", str(self.root), "--output", str(target),
        ])
        self.assertEqual(code, 0)
        self.assertIn("# Proof verification: file-1", target.read_text(encoding="utf-8"))

    def test_scan_unproven_claim(self):
        write_text(self.root / "NOTES.md", "All 31 tests pass\n")
        code, out, _ = run_cli([
            "scan", str(self.root), "--json", "--fail-on", "medium",
        ])
        self.assertEqual(code, 1)
        payload = json_out(out)
        self.assertEqual(payload["findings"][0]["check"], "unproven_claim")
        self.assertEqual(payload["findings"][0]["line"], 1)

    def test_scan_proven_claim_is_clean(self):
        self.record("proof-1", command="echo", exit_code="0")
        write_text(self.root / "NOTES.md", "All tests pass proof:proof-1\n")
        code, out, _ = run_cli(["scan", str(self.root), "--json", "--fail-on", "any"])
        self.assertEqual(code, 0, out)
        self.assertEqual(json_out(out)["findings"], [])

    def test_scan_marker_within_two_lines_counts(self):
        self.record("proof-2", command="echo", exit_code="0")
        write_text(self.root / "NOTES.md", "Durum: done\nproof:proof-2\n")
        code, _, _ = run_cli(["scan", str(self.root), "--json", "--fail-on", "any"])
        self.assertEqual(code, 0)

    def test_scan_missing_proof_is_high(self):
        write_text(self.root / "NOTES.md", "Fixed proof:ghost\n")
        code, out, _ = run_cli(["scan", str(self.root), "--json", "--fail-on", "high"])
        self.assertEqual(code, 1)
        self.assertEqual(json_out(out)["findings"][0]["check"], "missing_proof")

    def test_scan_stale_proof_only_with_flag(self):
        self.record("old-1", command="echo", exit_code="0")
        write_text(self.root / "src.py", "changed\n")
        write_text(self.root / "NOTES.md", "Fixed proof:old-1\n")
        code, _, _ = run_cli(["scan", str(self.root), "--json", "--fail-on", "high"])
        self.assertEqual(code, 0)
        code, out, _ = run_cli([
            "scan", str(self.root), "--json", "--fail-on", "high", "--require-fresh",
        ])
        self.assertEqual(code, 1)
        self.assertEqual(json_out(out)["findings"][0]["check"], "stale_proof")

    def test_scan_ignores_proof_dir(self):
        self.record("hidden-1", command="echo", exit_code="0")
        code, out, _ = run_cli(["scan", str(self.root), "--json", "--fail-on", "any"])
        self.assertEqual(code, 0)
        self.assertEqual(json_out(out)["findings"], [])

    def test_scan_output_file(self):
        write_text(self.root / "NOTES.md", "Fixed\n")
        target = self.root / "report.md"
        code, _, _ = run_cli(["scan", str(self.root), "--output", str(target)])
        self.assertEqual(code, 0)
        self.assertIn("# Unproven claim scan", target.read_text(encoding="utf-8"))

    def test_scan_missing_dir_returns_two(self):
        code, _, err = run_cli(["scan", str(self.root / "nope")])
        self.assertEqual(code, 2)
        self.assertIn("not a directory", err)

    def test_version_flag(self):
        with self.assertRaises(SystemExit) as raised:
            run_cli(["--version"])
        self.assertEqual(raised.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
