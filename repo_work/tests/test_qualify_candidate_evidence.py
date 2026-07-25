"""Focused tests for candidate-evidence qualification integration."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

from common import ReviewError  # noqa: E402
import qualify_candidate as qualifier  # noqa: E402
from release_assurance import ValidatedCandidateEvidence  # noqa: E402


class CandidateEvidenceCommandTests(unittest.TestCase):
    def test_command_pair_builds_before_direct_execution(self) -> None:
        target = Path("/private/qualification/target")
        runner = Path("/private/qualification/runner/galadriel-evidence")
        output = Path("/private/qualification/output/candidate-evidence")
        build, execute = qualifier.candidate_evidence_command_specs(
            target_directory=target,
            runner_executable=runner,
            evidence_config="evidence/galadriel-0.9-candidate.json",
            evidence_output=output,
        )

        self.assertEqual(build.name, "candidate-evidence-build")
        self.assertEqual(
            build.argv,
            (
                "cargo",
                "build",
                "--release",
                "--locked",
                "-p",
                "galadriel-eval",
                "--bin",
                "galadriel-evidence",
            ),
        )
        self.assertEqual(execute.name, "candidate-evidence")
        self.assertEqual(execute.argv[0], str(runner))
        self.assertNotIn("cargo", execute.argv)
        self.assertEqual(execute.subject_executable, str(runner))

    def test_command_pair_rejects_unsafe_paths(self) -> None:
        with self.assertRaisesRegex(ReviewError, "not canonical"):
            qualifier.candidate_evidence_command_specs(
                target_directory=Path("/private/target"),
                runner_executable=Path("/private/runner"),
                evidence_config="../outside.json",
                evidence_output=Path("/private/output"),
            )
        with self.assertRaisesRegex(ReviewError, "must be absolute"):
            qualifier.candidate_evidence_command_specs(
                target_directory=Path("relative-target"),
                runner_executable=Path("/private/runner"),
                evidence_config="evidence/config.json",
                evidence_output=Path("/private/output"),
            )


class CandidateExecutableSnapshotTests(unittest.TestCase):
    def test_snapshot_binds_exact_executable_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "built-runner"
            source.write_bytes(b"#!/bin/sh\nexit 0\n")
            source.chmod(0o500)
            snapshot_root = root / "snapshot"
            snapshot_root.mkdir(mode=0o700)
            destination = snapshot_root / "galadriel-evidence"

            identity = qualifier.snapshot_candidate_executable(
                source,
                destination,
            )

            self.assertEqual(destination.read_bytes(), source.read_bytes())
            self.assertEqual(
                identity["sha256"],
                hashlib.sha256(source.read_bytes()).hexdigest(),
            )
            self.assertEqual(identity["mode"], 0o500)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o500)

    def test_snapshot_rejects_a_hard_linked_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "built-runner"
            source.write_bytes(b"#!/bin/sh\nexit 0\n")
            source.chmod(0o500)
            os.link(source, root / "second-link")
            snapshot_root = root / "snapshot"
            snapshot_root.mkdir(mode=0o700)

            with self.assertRaisesRegex(ReviewError, "identity is invalid"):
                qualifier.snapshot_candidate_executable(
                    source,
                    snapshot_root / "galadriel-evidence",
                )

    def test_snapshot_rejects_a_nonblocking_special_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "built-runner"
            os.mkfifo(source, 0o500)
            snapshot_root = root / "snapshot"
            snapshot_root.mkdir(mode=0o700)

            with self.assertRaisesRegex(ReviewError, "identity is invalid"):
                qualifier.snapshot_candidate_executable(
                    source,
                    snapshot_root / "galadriel-evidence",
                )

    def test_snapshot_rejects_a_linked_source_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            release = root / "release"
            release.mkdir()
            source = release / "built-runner"
            source.write_bytes(b"#!/bin/sh\nexit 0\n")
            source.chmod(0o500)
            linked_release = root / "linked-release"
            linked_release.symlink_to(release, target_is_directory=True)
            snapshot_root = root / "snapshot"
            snapshot_root.mkdir(mode=0o700)

            with self.assertRaisesRegex(ReviewError, "linked parent"):
                qualifier.snapshot_candidate_executable(
                    linked_release / "built-runner",
                    snapshot_root / "galadriel-evidence",
                )


class BoundExecutableReceiptTests(unittest.TestCase):
    @staticmethod
    def process_result() -> qualifier.BoundedProcessResult:
        return qualifier.BoundedProcessResult(
            returncode=0,
            timed_out=False,
            stdout=b"",
            stderr=b"",
            output_limit_exceeded=False,
            containment_error=None,
        )

    def run_fixture(
        self,
        root: Path,
        *,
        process_side_effect: object,
    ) -> dict[str, object]:
        worktree = root / "worktree"
        worktree.mkdir()
        cargo_home = root / "cargo-home"
        cargo_home.mkdir()
        logs = root / "logs"
        logs.mkdir()
        sandbox = root / "candidate.sb"
        sandbox.write_bytes(b"test sandbox\n")
        runner = root / "runner"
        runner.write_bytes(b"#!/bin/sh\nexit 0\n")
        runner.chmod(0o500)
        clone_control = {"identity": "fixed"}
        spec = qualifier.CommandSpec(
            "candidate-evidence",
            (str(runner), "--version"),
            subject_executable=str(runner),
        )
        with (
            mock.patch.object(qualifier, "reject_cargo_configuration"),
            mock.patch.object(qualifier, "verify_materialized_candidate"),
            mock.patch.object(
                qualifier,
                "repository_control_snapshot",
                return_value=clone_control,
            ),
            mock.patch.object(
                qualifier,
                "run_bounded_process",
                side_effect=process_side_effect,
            ),
        ):
            return qualifier.run_command(
                spec,
                worktree=worktree,
                commit="1" * 40,
                tree="2" * 40,
                clone_control=clone_control,
                sandbox_profile=sandbox,
                environment={"CARGO_HOME": str(cargo_home)},
                logs=logs,
                index=1,
            )

    def test_receipt_binds_an_unchanged_subject(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_fixture(
                Path(directory).resolve(),
                process_side_effect=lambda *_args, **_kwargs: self.process_result(),
            )

        self.assertEqual(result["status"], "PASS")
        subject = result["subject_executable"]
        self.assertIsInstance(subject, dict)
        assert isinstance(subject, dict)
        self.assertEqual(subject["status"], "UNCHANGED")
        self.assertEqual(subject["identity"]["sha256"], hashlib.sha256(
            b"#!/bin/sh\nexit 0\n"
        ).hexdigest())

    def test_receipt_fails_when_subject_changes_during_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()

            def replace_subject(*_args: object, **_kwargs: object) -> object:
                runner = root / "runner"
                runner.chmod(0o700)
                runner.write_bytes(b"#!/bin/sh\nexit 1\n")
                runner.chmod(0o500)
                return self.process_result()

            result = self.run_fixture(
                root,
                process_side_effect=replace_subject,
            )

        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["subject_executable"]["status"], "UNVERIFIED")

    def test_direct_identity_rejects_a_symbolic_link(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "target"
            target.write_bytes(b"#!/bin/sh\nexit 0\n")
            target.chmod(0o500)
            linked = root / "runner"
            linked.symlink_to(target)

            with self.assertRaisesRegex(ReviewError, "direct qualification"):
                qualifier.direct_executable_file_identity(linked)


class CandidateEvidenceValidationTests(unittest.TestCase):
    RUSTC_VERBOSE = (
        "rustc 1.89.0 (fixture)\n"
        "binary: rustc\n"
        "host: aarch64-apple-darwin\n"
        "release: 1.89.0"
    )

    def test_validation_records_the_exact_independent_expectations(self) -> None:
        validated = ValidatedCandidateEvidence(
            artifacts={"manifest.json": {"sha256": "3" * 64, "size_bytes": 10}},
            config_binding={"study_design_status": "PASS"},
            manifest={"schema": "galadriel.evidence.manifest.v3"},
            summary={"schema": "galadriel.evidence.summary.v3"},
            acceptance={"status": "FAIL", "failed_criterion_ids": ["ACC-001"]},
            semantic_sha256="4" * 64,
        )
        with mock.patch.object(
            qualifier,
            "validate_candidate_evidence_bundle",
            return_value=validated,
        ) as bundle_validator:
            result, record = qualifier.validate_retained_candidate_evidence(
                Path("/private/evidence"),
                commit="1" * 40,
                tree="2" * 40,
                tracked_config_path="evidence/galadriel-0.9-candidate.json",
                tracked_config_bytes=b"tracked config\n",
                workspace_manifest_sha256="5" * 64,
                cargo_lock_sha256="6" * 64,
                runner_identity={"sha256": "7" * 64},
                rustc_verbose=self.RUSTC_VERBOSE,
                cargo_version="cargo 1.89.0 (fixture)",
            )

        self.assertIs(result, validated)
        expectations = bundle_validator.call_args.kwargs["expected"]
        self.assertEqual(expectations.runner_binary_sha256, "7" * 64)
        self.assertEqual(expectations.target_os, "macos")
        self.assertEqual(expectations.target_arch, "aarch64")
        self.assertEqual(record["status"], "PASS")
        self.assertEqual(record["semantic_sha256"], "4" * 64)
        self.assertEqual(record["expectations"]["runner_binary_sha256"], "7" * 64)

    def test_structural_bundle_error_propagates(self) -> None:
        structural_error = ReviewError("forged summary fixture")
        with (
            mock.patch.object(
                qualifier,
                "validate_candidate_evidence_bundle",
                side_effect=structural_error,
            ),
            self.assertRaises(ReviewError) as raised,
        ):
            qualifier.validate_retained_candidate_evidence(
                Path("/private/evidence"),
                commit="1" * 40,
                tree="2" * 40,
                tracked_config_path="evidence/galadriel-0.9-candidate.json",
                tracked_config_bytes=b"tracked config\n",
                workspace_manifest_sha256="5" * 64,
                cargo_lock_sha256="6" * 64,
                runner_identity={"sha256": "7" * 64},
                rustc_verbose=self.RUSTC_VERBOSE,
                cargo_version="cargo 1.89.0 (fixture)",
            )
        self.assertIs(raised.exception, structural_error)

    def test_rust_target_rejects_an_unqualified_host(self) -> None:
        for host in (
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
        ):
            with (
                self.subTest(host=host),
                self.assertRaisesRegex(ReviewError, "unsupported"),
            ):
                qualifier.rust_host_target(f"host: {host}")


if __name__ == "__main__":
    unittest.main()
