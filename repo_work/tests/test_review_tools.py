"""Integration tests for the dependency-free repository review utilities."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from check_public_api import canonical_core_diff, compare_snapshot
from common import ReviewError, canonical_json, load_json, loads_json
from finalize_release import candidate_json
from freeze_audit_inputs import assert_release_tool_coverage, strict_relative_files
from qualify_candidate import capture_report


TOOLS = Path(__file__).resolve().parents[1]


def run(*arguments: str, cwd: Path, expected: int = 0) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        ["python3", *arguments],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )
    if process.returncode != expected:
        raise AssertionError(
            f"expected {expected}, got {process.returncode}\nstdout={process.stdout}\nstderr={process.stderr}"
        )
    return process


class ReviewToolsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.root, check=True)
        subprocess.run(
            ["git", "config", "user.name", "Sepehr Mahmoudian"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "sepmhn@gmail.com"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "commit.gpgsign", "false"],
            cwd=self.root,
            check=True,
        )
        (self.root / "README.md").write_text(
            "# Fixture\n\nVerified experimental fallback.\n", encoding="utf-8"
        )
        (self.root / "data.json").write_text('{"value": 1}\n', encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "Create fixture"], cwd=self.root, check=True
        )
        self.head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.root, text=True
        ).strip()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_shared_json_helpers_reject_nonfinite_and_oversized_numbers(self) -> None:
        path = self.root / "strict.json"
        invalid_documents = {
            "nan": '{"value": NaN}',
            "positive infinity": '{"value": Infinity}',
            "negative infinity": '{"value": -Infinity}',
            "overflowing exponent": '{"value": 1e1000000}',
            "underflowing exponent": '{"value": 1e-1000000}',
            "oversized integer": '{"value": ' + "9" * 5_000 + "}",
        }
        for label, document in invalid_documents.items():
            with self.subTest(label=label):
                path.write_text(document, encoding="utf-8")
                with self.assertRaisesRegex(ReviewError, "cannot load"):
                    load_json(path)

        path.write_text('{"value": 1, "value": 2}', encoding="utf-8")
        with self.assertRaisesRegex(ReviewError, "duplicate JSON key"):
            load_json(path)

        with self.assertRaisesRegex(ValueError, "not valid UTF-8"):
            loads_json(b"\xff")

        path.write_text(
            '{"finite": 1e308, "zero": 0e1000000, "negative_zero": -0.0, '
            '"safe_max": 9007199254740991, "safe_min": -9007199254740991, '
            '"retained_u64_seed": 6840335614489011713}',
            encoding="utf-8",
        )
        self.assertEqual(
            load_json(path),
            {
                "finite": 1e308,
                "zero": 0.0,
                "negative_zero": -0.0,
                "safe_max": 9_007_199_254_740_991,
                "safe_min": -9_007_199_254_740_991,
                "retained_u64_seed": 6_840_335_614_489_011_713,
            },
        )

        for value in (float("nan"), float("inf"), -float("inf")):
            with self.subTest(canonical_value=value):
                with self.assertRaisesRegex(ReviewError, "cannot encode canonical JSON"):
                    canonical_json({"value": value})

        retained = {"seed": 6_840_335_614_489_011_713}
        self.assertEqual(loads_json(canonical_json(retained)), retained)
        retained_evidence = load_json(TOOLS.parent / "evidence/post-audit-v1.json")
        self.assertEqual(
            retained_evidence["base_seed"], 6_840_335_614_489_011_713
        )
        with self.assertRaisesRegex(ReviewError, "cannot encode canonical JSON"):
            canonical_json({"value": 10**128})

    def test_evidence_manifest_reports_oversized_integer_without_traceback(self) -> None:
        manifest = self.root / "manifest.json"
        manifest.write_text(
            '{"schema":"galadriel.evidence-manifest.v1","artifacts":[],"value":'
            + "9" * 5_000
            + "}",
            encoding="utf-8",
        )
        result = run(
            str(TOOLS / "verify_evidence_manifest.py"),
            str(manifest),
            "--root",
            ".",
            cwd=self.root,
            expected=2,
        )
        self.assertIn("cannot load", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_candidate_and_report_parsers_use_strict_json(self) -> None:
        candidate_input = self.root / "candidate-input.json"
        candidate_input.write_text('{"value": NaN}', encoding="utf-8")
        invalid_utf8 = self.root / "invalid-utf8.json"
        invalid_utf8.write_bytes(b"\xff")
        subprocess.run(
            ["git", "add", candidate_input.name, invalid_utf8.name],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-q", "-m", "Add parser fixture"],
            cwd=self.root,
            check=True,
        )
        candidate = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.root, text=True
        ).strip()
        for relative in (candidate_input.name, invalid_utf8.name):
            with self.subTest(candidate_input=relative):
                with self.assertRaisesRegex(ReviewError, "candidate JSON is invalid"):
                    candidate_json(self.root, candidate, relative)

        report_cases = (
            (False, '{"value": NaN}'),
            (True, '{"value": 1, "value": 2}'),
        )
        for json_lines, document in report_cases:
            with self.subTest(json_lines=json_lines):
                with self.assertRaisesRegex(ReviewError, "invalid JSON evidence"):
                    capture_report(
                        [sys.executable, "-c", f"print({document!r})"],
                        worktree=self.root,
                        environment=os.environ.copy(),
                        output=self.root / "reports" / "report.json",
                        json_lines=json_lines,
                    )

    def test_frozen_head_accepts_exact_clean_checkout(self) -> None:
        process = run(
            str(TOOLS / "check_frozen_head.py"),
            "--expected",
            self.head,
            cwd=self.root,
        )

        self.assertIn(f"FROZEN_HEAD_OK {self.head}", process.stdout)

    def test_frozen_head_rejects_dirty_checkout(self) -> None:
        (self.root / "README.md").write_text("changed\n", encoding="utf-8")

        process = run(
            str(TOOLS / "check_frozen_head.py"),
            "--expected",
            self.head,
            cwd=self.root,
            expected=2,
        )

        self.assertIn("DIRTY_TREE", process.stderr)

    def test_audit_input_freeze_rejects_unenumerated_release_tool(self) -> None:
        tool = self.root / "repo_work/future_release_gate.py"
        tool.parent.mkdir()
        tool.write_text("raise SystemExit(0)\n", encoding="utf-8")
        subprocess.run(["git", "add", str(tool)], cwd=self.root, check=True)

        with self.assertRaisesRegex(
            ReviewError, "tracked release-tool paths are absent"
        ):
            assert_release_tool_coverage(self.root)

    def test_candidate_qualifier_refuses_output_inside_subject_repository(self) -> None:
        process = run(
            str(TOOLS / "qualify_candidate.py"),
            "--repo",
            ".",
            "--expected",
            self.head,
            "--out",
            "audit/qualification",
            "--skip-evidence",
            cwd=self.root,
            expected=2,
        )

        self.assertIn("outside --repo", process.stderr)

    def test_inventory_has_one_unreviewed_row_per_tracked_path(self) -> None:
        run(
            str(TOOLS / "audit_tracked_files.py"),
            "--repo",
            ".",
            "--out",
            "audit/generated",
            cwd=self.root,
        )

        with (self.root / "audit/generated/FILE_REVIEW_LEDGER.csv").open(
            newline="", encoding="utf-8"
        ) as handle:
            rows = list(csv.DictReader(handle))
        manifest = json.loads(
            (self.root / "audit/generated/TRACKED_FILE_MANIFEST.json").read_text()
        )
        findings = json.loads(
            (self.root / "audit/generated/SUSPICIOUS_TOKEN_INVENTORY.json").read_text()
        )

        self.assertEqual([row["path"] for row in rows], ["README.md", "data.json"])
        self.assertTrue(all(row["review_status"] == "UNREVIEWED" for row in rows))
        self.assertTrue(all(row["reviewer"].startswith("Sepehr Mahmoudian") for row in rows))
        self.assertTrue(all(row["generated"] == "NO" for row in rows))
        self.assertEqual(manifest["tracked_files"], 2)
        self.assertTrue(all(item["review_scope"] for item in manifest["files"]))
        self.assertEqual({item["path"] for item in findings}, {"README.md"})

    def test_claim_scan_and_three_lane_packet_generation_are_deterministic(self) -> None:
        run(
            str(TOOLS / "audit_tracked_files.py"),
            "--repo",
            ".",
            "--out",
            "audit/generated",
            cwd=self.root,
        )
        run(
            str(TOOLS / "make_review_packets.py"),
            "audit/generated/FILE_REVIEW_LEDGER.csv",
            "--lanes",
            "3",
            cwd=self.root,
        )
        run(
            str(TOOLS / "scan_claim_language.py"),
            "--repo",
            ".",
            "--out",
            "audit/generated/CLAIM_LANGUAGE.json",
            cwd=self.root,
        )

        packets = [
            json.loads(
                (self.root / f"audit/generated/review-packets/lane-{lane}.json").read_text()
            )
            for lane in range(1, 4)
        ]
        claims = json.loads(
            (self.root / "audit/generated/CLAIM_LANGUAGE.json").read_text()
        )

        self.assertEqual(sum(len(packet["files"]) for packet in packets), 2)
        self.assertTrue(all(packet["human_review_claimed"] is False for packet in packets))
        self.assertTrue(
            all(file["reviewer"].startswith("Sepehr Mahmoudian") for packet in packets for file in packet["files"])
        )
        self.assertEqual({finding["path"] for finding in claims}, {"README.md"})

    def test_evidence_manifest_rejects_duplicate_keys_and_path_escape(self) -> None:
        artifact = self.root / "artifact.bin"
        artifact.write_bytes(b"evidence")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        manifest = self.root / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema": "galadriel.evidence-manifest.v1",
                    "artifacts": [
                        {
                            "path": "artifact.bin",
                            "sha256": digest,
                            "size_bytes": artifact.stat().st_size,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        run(
            str(TOOLS / "verify_evidence_manifest.py"),
            str(manifest),
            "--root",
            ".",
            cwd=self.root,
        )

        manifest.write_text('{"schema":"a","schema":"b","artifacts":[]}', encoding="utf-8")
        duplicate = run(
            str(TOOLS / "verify_evidence_manifest.py"),
            str(manifest),
            "--root",
            ".",
            cwd=self.root,
            expected=2,
        )
        self.assertIn("duplicate JSON key", duplicate.stderr)

        manifest.write_text(
            json.dumps(
                {
                    "schema": "galadriel.evidence-manifest.v1",
                    "artifacts": [
                        {"path": "../outside", "sha256": "0" * 64, "size_bytes": 0}
                    ],
                }
            ),
            encoding="utf-8",
        )
        escape = run(
            str(TOOLS / "verify_evidence_manifest.py"),
            str(manifest),
            "--root",
            ".",
            cwd=self.root,
            expected=2,
        )
        self.assertIn("must be nonempty and relative", escape.stderr)

        inside = self.root / "inside-link"
        inside.symlink_to("artifact.bin")
        manifest.write_text(
            json.dumps(
                {
                    "schema": "galadriel.evidence-manifest.v1",
                    "artifacts": [
                        {
                            "path": "inside-link",
                            "sha256": digest,
                            "size_bytes": artifact.stat().st_size,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        symlink = run(
            str(TOOLS / "verify_evidence_manifest.py"),
            str(manifest),
            "--root",
            ".",
            cwd=self.root,
            expected=2,
        )
        self.assertIn("contains a symlink", symlink.stderr)

        manifest.write_text(
            json.dumps(
                {"schema": "galadriel.evidence-manifest.v1", "artifacts": []}
            ),
            encoding="utf-8",
        )
        empty = run(
            str(TOOLS / "verify_evidence_manifest.py"),
            str(manifest),
            "--root",
            ".",
            cwd=self.root,
            expected=2,
        )
        self.assertIn("must not be empty", empty.stderr)

    def test_public_api_snapshot_comparison_is_exact_and_bounded(self) -> None:
        compare_snapshot("fixture", b"pub struct Stable;\n", b"pub struct Stable;\n")

        with self.assertRaisesRegex(ReviewError, "public API snapshot drifted") as raised:
            compare_snapshot(
                "fixture",
                b"pub struct Stable;\n",
                b"pub struct Changed;\n",
            )

        self.assertIn("fixture.retained", str(raised.exception))
        self.assertIn("fixture.actual", str(raised.exception))

    def test_public_api_diff_omits_mutable_timestamps(self) -> None:
        release = self.root / "release/0.9.0/api"
        release.mkdir(parents=True)
        (release / "galadriel-core.baseline.txt").write_text(
            "pub struct Before;\n", encoding="utf-8"
        )
        (release / "galadriel-core.0.9.0.txt").write_text(
            "pub struct After;\n", encoding="utf-8"
        )

        rendered = canonical_core_diff(self.root).decode("utf-8")

        self.assertIn("--- release/0.9.0/api/galadriel-core.baseline.txt\n", rendered)
        self.assertIn("+++ release/0.9.0/api/galadriel-core.0.9.0.txt\n", rendered)
        self.assertNotRegex(rendered, r"\d{4}-\d{2}-\d{2}")

    def test_handoff_inventory_records_file_and_directory_symlinks_without_following(self) -> None:
        handoff = self.root / "handoff"
        target_directory = handoff / "directory"
        target_directory.mkdir(parents=True)
        (target_directory / "inside.txt").write_text("inside\n", encoding="utf-8")
        (handoff / "regular.txt").write_text("regular\n", encoding="utf-8")
        (handoff / "file-link").symlink_to("regular.txt")
        (handoff / "directory-link").symlink_to("directory", target_is_directory=True)

        rows = strict_relative_files(handoff)
        by_path = {row["path"]: row for row in rows}

        self.assertEqual(
            set(by_path),
            {
                "directory/inside.txt",
                "regular.txt",
                "file-link",
                "directory-link",
            },
        )
        self.assertEqual(by_path["file-link"]["kind"], "symlink")
        self.assertEqual(by_path["directory-link"]["kind"], "symlink")
        self.assertEqual(by_path["directory-link"]["target"], "directory")


if __name__ == "__main__":
    unittest.main()
