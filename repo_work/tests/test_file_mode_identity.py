"""Verify exact Git file-mode identity across the review workflow."""

from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

from common import ReviewError  # noqa: E402
from release_assurance import (  # noqa: E402
    FILE_LEDGER_COLUMNS,
    git_tree_inventory,
    validate_completed_file_ledger,
)
from qualify_candidate import QUALIFICATION_PYTHON_FLAGS  # noqa: E402


class FileModeIdentityTests(unittest.TestCase):
    """Exercise mode binding without relying on Git status mode detection."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.outputs = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        self.output_root = Path(self.outputs.name)
        self._git("init", "-q", "-b", "main")
        self._git("config", "user.name", "Sepehr Mahmoudian")
        self._git("config", "user.email", "sepmhn@gmail.com")
        self._git("config", "commit.gpgsign", "false")
        (self.repo / "plain.txt").write_text("plain\n", encoding="utf-8")
        executable = self.repo / "tool.sh"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        self._git("add", "--", "plain.txt", "tool.sh")
        self._git("commit", "-q", "-m", "Create file-mode fixture")
        self.commit = self._git_output("rev-parse", "HEAD").strip()

    def tearDown(self) -> None:
        self.outputs.cleanup()
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> None:
        subprocess.run(
            ["git", *arguments],
            cwd=self.repo,
            check=True,
            capture_output=True,
        )

    def _git_output(self, *arguments: str) -> str:
        return subprocess.check_output(
            ["git", *arguments],
            cwd=self.repo,
            text=True,
        )

    def _run_tool(self, tool: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                *QUALIFICATION_PYTHON_FLAGS,
                str(TOOLS / tool),
                *arguments,
            ],
            cwd=self.repo,
            check=False,
            capture_output=True,
            text=True,
        )

    def _run_audit(self, name: str) -> Path:
        output = self.output_root / name
        process = self._run_tool(
            "audit_tracked_files.py",
            "--repo",
            ".",
            "--out",
            str(output),
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        return output

    def _completed_rows(self, commit: str) -> list[dict[str, str]]:
        inventory = git_tree_inventory(self.repo, commit)
        return [
            {
                "path": relative,
                "git_mode": str(item["mode"]),
                "git_blob_id": str(item["git_blob_id"]),
                "sha256": str(item["sha256"]),
                "bytes": str(item["bytes"]),
                "lines": "1",
                "language": "fixture",
                "generated": "NO",
                "generator": "",
                "public_surface": "NO",
                "security_critical": "NO",
                "science_critical": "NO",
                "authority_critical": "NO",
                "reviewer": "Sepehr Mahmoudian / author-operated review",
                "review_status": "REVIEWED_NO_DEFECT",
                "requirements": "The review covered the exact candidate file.",
                "assumptions": "The review accepted no hidden assumptions.",
                "defects": "",
                "tests": "The exact file-mode identity test passed.",
                "evidence": "The retained evidence binds the candidate tree and ledger.",
                "disposition": "The disposition accepts the file for this candidate.",
                "completed_at": "2026-07-24T12:00:00Z",
            }
            for relative, item in sorted(inventory.items())
        ]

    def _write_ledger(
        self,
        name: str,
        rows: list[dict[str, str]],
        *,
        fields: tuple[str, ...] = FILE_LEDGER_COLUMNS,
    ) -> Path:
        path = self.output_root / name
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=fields,
                extrasaction="ignore",
            )
            writer.writeheader()
            writer.writerows(rows)
        return path

    def test_audit_and_packets_bind_each_index_mode(self) -> None:
        audit = self._run_audit("complete-mode-audit")
        ledger = audit / "FILE_REVIEW_LEDGER.csv"
        with ledger.open(newline="", encoding="utf-8") as handle:
            ledger_modes = {
                row["path"]: row["git_mode"] for row in csv.DictReader(handle)
            }
        self.assertEqual(
            ledger_modes,
            {"plain.txt": "100644", "tool.sh": "100755"},
        )

        manifest = json.loads(
            (audit / "TRACKED_FILE_MANIFEST.json").read_text(encoding="utf-8")
        )
        manifest_modes = {item["path"]: item["git_mode"] for item in manifest["files"]}
        self.assertEqual(manifest_modes, ledger_modes)

        packets = self.output_root / "review-packets"
        process = self._run_tool(
            "make_review_packets.py",
            str(ledger),
            "--out",
            str(packets),
            "--lanes",
            "2",
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        packet_modes: dict[str, str] = {}
        for lane in (1, 2):
            packet = json.loads(
                (packets / f"lane-{lane}.json").read_text(encoding="utf-8")
            )
            self.assertIn("exact Git mode and blob", packet["instructions"])
            packet_modes.update(
                {item["path"]: item["git_mode"] for item in packet["files"]}
            )
        self.assertEqual(packet_modes, ledger_modes)

    def test_audit_rejects_mode_drift_with_core_file_mode_disabled(self) -> None:
        self._git("config", "core.fileMode", "false")
        self._run_audit("hostile-config-matching-mode")

        (self.repo / "plain.txt").chmod(0o755)
        self.assertEqual(
            self._git_output(
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ),
            "",
        )
        output = self.output_root / "hostile-config-mode-drift"
        process = self._run_tool(
            "audit_tracked_files.py",
            "--repo",
            ".",
            "--out",
            str(output),
        )
        self.assertEqual(process.returncode, 2)
        self.assertIn(
            "working tree differs from indexed blob: plain.txt",
            process.stderr,
        )

    def test_packet_contract_rejects_missing_or_invalid_git_mode(self) -> None:
        audit = self._run_audit("packet-contract-audit")
        ledger = audit / "FILE_REVIEW_LEDGER.csv"
        with ledger.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

        missing_fields = tuple(
            field for field in FILE_LEDGER_COLUMNS if field != "git_mode"
        )
        missing = self._write_ledger(
            "missing-mode.csv",
            rows,
            fields=missing_fields,
        )
        missing_process = self._run_tool(
            "make_review_packets.py",
            str(missing),
            "--out",
            str(self.output_root / "missing-mode-packets"),
        )
        self.assertEqual(missing_process.returncode, 2)
        self.assertIn("git_mode", missing_process.stderr)

        rows[0]["git_mode"] = "100600"
        invalid = self._write_ledger("invalid-mode.csv", rows)
        invalid_process = self._run_tool(
            "make_review_packets.py",
            str(invalid),
            "--out",
            str(self.output_root / "invalid-mode-packets"),
        )
        self.assertEqual(invalid_process.returncode, 2)
        self.assertIn("invalid Git mode", invalid_process.stderr)

    def test_completed_ledger_rejects_a_mode_only_candidate_change(self) -> None:
        original_inventory = git_tree_inventory(self.repo, self.commit)
        original_ledger = self._write_ledger(
            "original-completed.csv",
            self._completed_rows(self.commit),
        )

        fields_without_mode = tuple(
            field for field in FILE_LEDGER_COLUMNS if field != "git_mode"
        )
        missing_mode = self._write_ledger(
            "completed-without-mode.csv",
            self._completed_rows(self.commit),
            fields=fields_without_mode,
        )
        with self.assertRaisesRegex(ReviewError, "wrong or duplicate columns"):
            validate_completed_file_ledger(
                missing_mode,
                self.repo,
                self.commit,
            )

        self._git("update-index", "--chmod=+x", "--", "plain.txt")
        self._git("commit", "-q", "-m", "Change only the tracked file mode")
        mode_commit = self._git_output("rev-parse", "HEAD").strip()
        mode_inventory = git_tree_inventory(self.repo, mode_commit)
        self.assertEqual(
            original_inventory["plain.txt"]["git_blob_id"],
            mode_inventory["plain.txt"]["git_blob_id"],
        )
        self.assertEqual(original_inventory["plain.txt"]["mode"], "100644")
        self.assertEqual(mode_inventory["plain.txt"]["mode"], "100755")

        with self.assertRaisesRegex(ReviewError, "mode mismatch: plain.txt"):
            validate_completed_file_ledger(
                original_ledger,
                self.repo,
                mode_commit,
            )

        matching_ledger = self._write_ledger(
            "mode-matching-completed.csv",
            self._completed_rows(mode_commit),
        )
        result = validate_completed_file_ledger(
            matching_ledger,
            self.repo,
            mode_commit,
        )
        self.assertEqual(result["tracked_files"], 2)
        self.assertEqual(result["reviewed_files"], 2)


if __name__ == "__main__":
    unittest.main()
