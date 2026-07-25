"""Adversarial tests for the release-audit repository snapshot."""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from repo_work import build_task_dispositions, common
from scripts import release_audit


class ReleaseAuditSnapshotTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, repository: Path, *arguments: str) -> None:
        subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=True,
            capture_output=True,
        )

    def repository(self) -> Path:
        repository = self.workspace / "repository"
        repository.mkdir()
        self.git(repository, "init", "--quiet")
        files = {
            "README.md": b"repository\n",
            "release/0.9.0/audit-manifest.json": b"{}\n",
            "release/0.9.0/requirements-ledger.json": b"{}\n",
        }
        for relative, data in files.items():
            path = repository / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.git(repository, "add", ".")
        return repository

    def capture(self, repository: Path, *, generated_drift: bool = False) -> object:
        with mock.patch.object(release_audit, "ROOT", repository):
            return release_audit.capture_repository_snapshot(
                allow_generated_drift=generated_drift
            )

    def test_snapshot_rejects_staged_audit_output_symlink(self) -> None:
        repository = self.repository()
        output = repository / "release/0.9.0/audit-manifest.json"
        external = self.workspace / "external-audit.json"
        external.write_bytes(output.read_bytes())
        output.unlink()
        output.symlink_to(external)
        self.git(repository, "add", "release/0.9.0/audit-manifest.json")

        with (
            mock.patch.object(release_audit, "ROOT", repository),
            self.assertRaisesRegex(
                release_audit.AuditError,
                "not a regular file",
            ),
        ):
            release_audit.verify()

    def test_snapshot_rejects_staged_covered_source_symlink(self) -> None:
        repository = self.repository()
        source = repository / "README.md"
        external = self.workspace / "external-readme.md"
        external.write_bytes(source.read_bytes())
        source.unlink()
        source.symlink_to(external)
        self.git(repository, "add", "README.md")

        with (
            mock.patch.object(release_audit, "ROOT", repository),
            self.assertRaisesRegex(
                release_audit.AuditError,
                "not a regular file",
            ),
        ):
            release_audit.verify()

    def test_snapshot_rejects_index_and_worktree_blob_drift(self) -> None:
        repository = self.repository()
        (repository / "README.md").write_bytes(b"changed but not staged\n")

        with self.assertRaisesRegex(
            release_audit.AuditError,
            "README.md.*(size|digest)|blob differs",
        ):
            self.capture(repository)

    def test_snapshot_rejects_executable_drift_with_filemode_disabled(self) -> None:
        repository = self.repository()
        tool = repository / "tool.sh"
        tool.write_bytes(b"#!/bin/sh\nexit 0\n")
        tool.chmod(0o644)
        self.git(repository, "add", "tool.sh")
        self.git(repository, "update-index", "--chmod=+x", "tool.sh")
        self.git(repository, "config", "core.fileMode", "false")
        tool.chmod(0o644)

        with self.assertRaisesRegex(
            release_audit.AuditError,
            "executable mode differs",
        ):
            self.capture(repository)

    def test_blob_batch_parser_rejects_protocol_drift(self) -> None:
        first = b"first"
        second = b"second"
        first_id = release_audit._git_blob_id(first)
        second_id = release_audit._git_blob_id(second)
        valid = (
            f"{first_id} blob {len(first)}\n".encode("ascii")
            + first
            + b"\n"
            + f"{second_id} blob {len(second)}\n".encode("ascii")
            + second
            + b"\n"
        )
        first_record_end = valid.find(second_id.encode("ascii"))
        first_record = valid[:first_record_end]
        second_record = valid[first_record_end:]
        self.assertEqual(
            release_audit._parse_blob_batch(valid, (first_id, second_id)),
            {first_id: first, second_id: second},
        )

        invalid = {
            "missing": first_record,
            "duplicate": first_record + first_record,
            "out of order": second_record + first_record,
            "trailing": valid + b"unexpected",
            "oversized": (
                f"{first_id} blob {release_audit.MAX_TRACKED_FILE_BYTES + 1}\n"
            ).encode("ascii"),
            "truncated": valid[:-2],
        }
        for label, document in invalid.items():
            with self.subTest(label=label):
                with self.assertRaises(release_audit.AuditError):
                    release_audit._parse_blob_batch(
                        document,
                        (first_id, second_id),
                    )

    def test_rooted_capture_rejects_links_special_files_and_mode_drift(self) -> None:
        root = self.workspace / "files"
        root.mkdir()
        regular = root / "regular"
        regular.write_bytes(b"content")
        linked = root / "linked"
        linked.symlink_to(regular)
        hard = root / "hard"
        os.link(regular, hard)
        fifo = root / "fifo"
        os.mkfifo(fifo)

        cases = (
            ("linked", "100644"),
            ("regular", "100644"),
            ("fifo", "100644"),
        )
        for relative, git_mode in cases:
            with self.subTest(relative=relative):
                request = common.RootedFileCaptureRequest(
                    relative,
                    None,
                    relative,
                    expected_git_mode=git_mode,
                )
                with self.assertRaises(common.ReviewError):
                    common.read_rooted_regular_files(
                        root,
                        (request,),
                        label="test capture",
                        max_files=4,
                        max_file_bytes=1024,
                        max_aggregate_bytes=4096,
                    )

        executable = root / "executable"
        executable.write_bytes(b"tool")
        executable.chmod(0o755)
        request = common.RootedFileCaptureRequest(
            "executable",
            4,
            "executable",
            hashlib.sha256(b"tool").hexdigest(),
            "100644",
        )
        with self.assertRaisesRegex(common.ReviewError, "executable mode differs"):
            common.read_rooted_regular_files(
                root,
                (request,),
                label="test capture",
                max_files=4,
                max_file_bytes=1024,
                max_aggregate_bytes=4096,
            )

    def test_rooted_capture_rejects_a_post_read_file_race(self) -> None:
        root = self.workspace / "capture-race"
        root.mkdir()
        first = root / "first"
        second = root / "second"
        first.write_bytes(b"first")
        second.write_bytes(b"second")
        requests = tuple(
            common.RootedFileCaptureRequest(
                path.name,
                path.stat().st_size,
                path.name,
                hashlib.sha256(path.read_bytes()).hexdigest(),
                "100644",
            )
            for path in (first, second)
        )
        real_verify = common._verify_rooted_file_identity
        calls = 0

        def mutate_before_verify(*args: object, **kwargs: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                first.write_bytes(b"other")
            real_verify(*args, **kwargs)

        with (
            mock.patch.object(
                common,
                "_verify_rooted_file_identity",
                side_effect=mutate_before_verify,
            ),
            self.assertRaisesRegex(common.ReviewError, "changed"),
        ):
            common.read_rooted_regular_files(
                root,
                requests,
                label="capture race",
                max_files=4,
                max_file_bytes=1024,
                max_aggregate_bytes=4096,
            )

    def test_rooted_writer_does_not_overwrite_a_replacement(self) -> None:
        root = self.workspace / "write-root"
        root.mkdir()
        output = root / "output.json"
        output.write_bytes(b"old")
        capture = common.read_rooted_regular_files(
            root,
            (
                common.RootedFileCaptureRequest(
                    "output.json",
                    3,
                    "output",
                    hashlib.sha256(b"old").hexdigest(),
                    "100644",
                ),
            ),
            label="write capture",
            max_files=2,
            max_file_bytes=1024,
            max_aggregate_bytes=2048,
        )[0]
        displaced = root / "displaced.json"
        real_truncate = common.os.ftruncate

        def replace_then_truncate(descriptor: int, length: int) -> None:
            output.rename(displaced)
            output.write_bytes(b"replacement")
            real_truncate(descriptor, length)

        with (
            mock.patch.object(
                common.os,
                "ftruncate",
                side_effect=replace_then_truncate,
            ),
            self.assertRaisesRegex(common.ReviewError, "changed"),
        ):
            common.write_rooted_regular_file(
                root,
                "output.json",
                b"new",
                expected=capture,
                expected_git_mode="100644",
                label="output",
                max_bytes=1024,
            )
        self.assertEqual(output.read_bytes(), b"replacement")

    def test_rooted_writer_rejects_parent_replacement(self) -> None:
        root = self.workspace / "parent-write-root"
        parent = root / "parent"
        parent.mkdir(parents=True)
        output = parent / "output.json"
        output.write_bytes(b"old")
        replacement = root / "replacement"
        replacement.mkdir()
        replacement_output = replacement / "output.json"
        replacement_output.write_bytes(b"replacement")
        capture = common.read_rooted_regular_files(
            root,
            (
                common.RootedFileCaptureRequest(
                    "parent/output.json",
                    3,
                    "output",
                    hashlib.sha256(b"old").hexdigest(),
                    "100644",
                ),
            ),
            label="parent write capture",
            max_files=2,
            max_file_bytes=1024,
            max_aggregate_bytes=2048,
        )[0]
        displaced = root / "displaced"
        real_truncate = common.os.ftruncate

        def replace_parent_then_truncate(descriptor: int, length: int) -> None:
            parent.rename(displaced)
            replacement.rename(parent)
            real_truncate(descriptor, length)

        with (
            mock.patch.object(
                common.os,
                "ftruncate",
                side_effect=replace_parent_then_truncate,
            ),
            self.assertRaisesRegex(common.ReviewError, "changed|replaced"),
        ):
            common.write_rooted_regular_file(
                root,
                "parent/output.json",
                b"new",
                expected=capture,
                expected_git_mode="100644",
                label="output",
                max_bytes=1024,
            )
        self.assertEqual((parent / "output.json").read_bytes(), b"replacement")

    def test_source_disposition_validator_accepts_captured_document(self) -> None:
        document = build_task_dispositions.load_json(
            build_task_dispositions.SOURCE_DISPOSITIONS_PATH
        )
        with mock.patch.object(
            build_task_dispositions,
            "load_json",
            side_effect=AssertionError("unexpected file reopen"),
        ):
            self.assertEqual(
                build_task_dispositions.validate_source_dispositions(document),
                document,
            )


if __name__ == "__main__":
    unittest.main()
