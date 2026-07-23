"""Integration tests for the dependency-free repository review utilities."""

from __future__ import annotations

import copy
import csv
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import re
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Callable
from unittest import mock

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from check_feature_graph import (
    EXPECTED_DEFAULT_MEMBERS,
    EXPECTED_UPSTREAM_MANIFESTS,
    FEATURE_GRAPH_TIMEOUT_SECONDS,
    MAX_FEATURE_GRAPH_STDERR_BYTES,
    MAX_FEATURE_GRAPH_STDOUT_BYTES,
    MAX_NCP_CONSUMER_BYTES,
    NCP_RESOLVED_FEATURES,
    PID_RESOLVED_FEATURES,
    PROFILES,
    TOKIO_RESOLVED_FEATURES,
    ZENOH_RESOLVED_FEATURES,
    package_graph,
    parse_ncp_consumer_descriptor,
    parse_graph_output,
    main as feature_graph_main,
    validate_profile_graph,
    validate_ncp_consumer_descriptor,
    validate_upstream_package_records,
    validate_workspace_manifest,
)
from check_public_api import (
    canonical_core_diff,
    compare_snapshot,
    release_tool_environment,
)
from check_vulnerable_features import (
    CARGO_METADATA_COMMAND,
    MAX_METADATA_STDERR_BYTES,
    MAX_METADATA_STDOUT_BYTES,
    METADATA_TIMEOUT_SECONDS,
    main as vulnerable_features_main,
    validate_metadata,
)
import common as common_helpers
from common import ReviewError, canonical_json, load_json, loads_json
from finalize_release import candidate_json
import freeze_audit_inputs as freeze
from freeze_audit_inputs import assert_release_tool_coverage, strict_relative_files
from qualify_candidate import capture_report
import release_assurance as assurance
from scripts import release_audit


TOOLS = Path(__file__).resolve().parents[1]


def run(
    *arguments: str, cwd: Path, expected: int = 0
) -> subprocess.CompletedProcess[str]:
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

    def test_common_git_runner_bounds_output_timeout_and_environment(self) -> None:
        recorded: dict[str, Any] = {}

        def successful_run(arguments: list[str], **kwargs: Any) -> Any:
            recorded["arguments"] = arguments
            recorded["environment"] = kwargs["environment"]
            recorded["timeout"] = kwargs["timeout_seconds"]
            return assurance.BoundedHostResult(0, b"", b"")

        ambient = {
            "PATH": os.environ["PATH"],
            "SOURCE_DATE_EPOCH": "123",
            "ANTHROPIC_API_KEY": "key-material",
            "GH_TOKEN": "token-material",
            "GIT_CONFIG_GLOBAL": "/unsafe/config",
            "GIT_OBJECT_DIRECTORY": "/unsafe/objects",
            "HTTP_PROXY": "http://proxy.invalid",
            "SSH_AUTH_SOCK": "/unsafe/agent",
            "LC_ALL": "de_DE.UTF-8",
        }
        with mock.patch.object(
            common_helpers,
            "run_bounded_host_command",
            side_effect=successful_run,
        ):
            self.assertEqual(
                common_helpers.git_bounded_output(
                    self.root,
                    "status",
                    "--short",
                    max_bytes=0,
                    environment=ambient,
                ),
                b"",
            )
        arguments = recorded["arguments"]
        self.assertEqual(arguments[0:2], ["git", "--no-replace-objects"])
        self.assertIn("core.hooksPath=/dev/null", arguments)
        self.assertIn("core.attributesFile=/dev/null", arguments)
        self.assertEqual(
            recorded["timeout"], common_helpers.DEFAULT_GIT_TIMEOUT_SECONDS
        )
        sanitized = recorded["environment"]
        self.assertEqual(sanitized["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(sanitized["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(sanitized["LC_ALL"], "C")
        self.assertEqual(sanitized["SOURCE_DATE_EPOCH"], "123")
        self.assertNotIn("ANTHROPIC_API_KEY", sanitized)
        self.assertNotIn("GH_TOKEN", sanitized)
        self.assertNotIn("GIT_OBJECT_DIRECTORY", sanitized)
        self.assertNotIn("HTTP_PROXY", sanitized)
        self.assertNotIn("SSH_AUTH_SOCK", sanitized)
        self.assertEqual(
            assurance.sanitized_host_environment(ambient),
            {
                "PATH": os.environ["PATH"],
                "SOURCE_DATE_EPOCH": "123",
                "LC_ALL": "de_DE.UTF-8",
            },
        )
        with mock.patch.dict(
            os.environ,
            {
                "ANTHROPIC_API_KEY": "key-material",
                "SSH_AUTH_SOCK": "/fixture/agent.sock",
            },
        ):
            agent_environment = assurance._ssh_host_environment(use_agent=True)
            non_agent_environment = assurance._ssh_host_environment(use_agent=False)
        self.assertNotIn("ANTHROPIC_API_KEY", agent_environment)
        self.assertEqual(agent_environment["SSH_AUTH_SOCK"], "/fixture/agent.sock")
        self.assertNotIn("SSH_AUTH_SOCK", non_agent_environment)

        def oversized_run(arguments: list[str], **kwargs: Any) -> Any:
            del arguments, kwargs
            return assurance.BoundedHostResult(0, b"x" * 17, b"")

        with (
            mock.patch.object(
                common_helpers,
                "run_bounded_host_command",
                side_effect=oversized_run,
            ),
            self.assertRaisesRegex(ReviewError, "output exceeds 16 bytes"),
        ):
            common_helpers.git_bounded_output(
                self.root,
                "status",
                "--short",
                max_bytes=16,
            )

        def failed_run(arguments: list[str], **kwargs: Any) -> Any:
            del arguments, kwargs
            return assurance.BoundedHostResult(
                128,
                b"",
                b"fatal: fixture failure\n",
            )

        with (
            mock.patch.object(
                common_helpers,
                "run_bounded_host_command",
                side_effect=failed_run,
            ),
            self.assertRaisesRegex(ReviewError, "failed with 128"),
        ):
            common_helpers.git_bounded_output(
                self.root,
                "status",
                "--short",
                max_bytes=16,
            )

        with (
            mock.patch.object(
                common_helpers,
                "run_bounded_host_command",
                side_effect=ReviewError("git status timed out after 3 seconds"),
            ) as mocked_run,
            self.assertRaisesRegex(
                ReviewError,
                "timed out after 3 seconds",
            ) as raised,
        ):
            common_helpers.git_bounded_output(
                self.root,
                "status",
                "--short",
                max_bytes=16,
                timeout_seconds=3,
            )
        self.assertEqual(mocked_run.call_args.kwargs["timeout_seconds"], 3)
        self.assertNotIn("MATERIAL-SENTINEL", str(raised.exception))
        with self.assertRaisesRegex(ReviewError, "output byte limit"):
            common_helpers.git_bounded_output(
                self.root,
                "status",
                "--short",
                max_bytes=common_helpers.MAX_GIT_CAPTURE_BYTES + 1,
            )

    def test_common_git_stream_cap_stops_descendant_processes(self) -> None:
        marker = self.root / "git-descendant-survived"
        child_program = (
            "import pathlib,signal,time;"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
            "time.sleep(2);"
            f"pathlib.Path({str(marker)!r}).write_text('survived')"
        )
        parent_program = (
            "import os,subprocess,sys,time;"
            f"subprocess.Popen([sys.executable,'-c',{child_program!r}]);"
            "os.write(1,b'x'*17);"
            "time.sleep(30)"
        )
        real_popen = subprocess.Popen

        def replace_git(arguments: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
            del arguments
            return real_popen(
                [sys.executable, "-I", "-c", parent_program],
                **kwargs,
            )

        with (
            mock.patch.object(
                common_helpers.subprocess,
                "Popen",
                side_effect=replace_git,
            ),
            self.assertRaisesRegex(ReviewError, "output exceeds 16 bytes"),
        ):
            common_helpers.git_bounded_output(
                self.root,
                "status",
                "--short",
                max_bytes=16,
                timeout_seconds=3,
            )
        time.sleep(2.2)
        self.assertFalse(marker.exists())

    def test_host_command_runner_bounds_streams_and_timeout(self) -> None:
        result = assurance.run_bounded_host_command(
            [sys.executable, "-c", "print('ok')"],
            context="host command fixture",
            max_stdout_bytes=16,
            max_stderr_bytes=16,
            timeout_seconds=2,
        )
        self.assertEqual(result, assurance.BoundedHostResult(0, b"ok\n", b""))

        command_root = self.root / "host-command-cwd"
        command_root.mkdir()
        merged_program = (
            "import os;"
            "os.write(2,b'error|');"
            "os.write(1,(os.getcwd()+'|'+os.environ['FIXTURE']).encode())"
        )
        merged = assurance.run_bounded_host_command(
            [sys.executable, "-c", merged_program],
            context="merged host command fixture",
            environment={"FIXTURE": "value"},
            cwd=command_root,
            merge_stderr=True,
            max_stdout_bytes=1024,
            max_stderr_bytes=0,
            timeout_seconds=2,
        )
        self.assertEqual(
            merged,
            assurance.BoundedHostResult(
                0,
                b"error|" + str(command_root.resolve()).encode() + b"|value",
                b"",
            ),
        )

        cases = (
            ("standard output", "import os; os.write(1, b'x' * 17)"),
            ("standard error", "import os; os.write(2, b'x' * 17)"),
        )
        for label, program in cases:
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(
                    ReviewError,
                    rf"{label} exceeds 16 bytes",
                ),
            ):
                assurance.run_bounded_host_command(
                    [sys.executable, "-c", program],
                    context="host command fixture",
                    max_stdout_bytes=16,
                    max_stderr_bytes=16,
                    timeout_seconds=2,
                )

        marker = self.root / "host-command-descendant-survived"
        child_program = (
            "import pathlib,signal,time;"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
            "time.sleep(2);"
            f"pathlib.Path({str(marker)!r}).write_text('survived')"
        )
        parent_program = (
            "import subprocess,sys,time;"
            f"subprocess.Popen([sys.executable,'-c',{child_program!r}]);"
            "time.sleep(30)"
        )
        with self.assertRaisesRegex(
            ReviewError,
            "timed out after 1 seconds",
        ):
            assurance.run_bounded_host_command(
                [sys.executable, "-c", parent_program],
                context="host command fixture",
                max_stdout_bytes=16,
                max_stderr_bytes=16,
                timeout_seconds=1,
            )
        time.sleep(2)
        self.assertFalse(marker.exists())

    def test_signing_failure_diagnostic_omits_command_output(self) -> None:
        document = self.root / "signed-document"
        key = self.root / "signing-key"
        document.write_bytes(b"document\n")
        key.write_bytes(b"key handle\n")
        result = assurance.BoundedHostResult(
            7,
            b"PUBLIC-KEY-MATERIAL-SENTINEL",
            b"PRIVATE-KEY-MATERIAL-SENTINEL",
        )
        with (
            mock.patch.object(
                assurance,
                "run_bounded_host_command",
                return_value=result,
            ),
            self.assertRaisesRegex(
                ReviewError,
                "command exited with 7",
            ) as raised,
        ):
            assurance.sign_file(document, key, "fixture")
        self.assertNotIn("KEY-MATERIAL-SENTINEL", str(raised.exception))

    def test_candidate_tree_reads_preserve_modes_and_reject_symlinks(self) -> None:
        executable = self.root / "executable"
        executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)
        link = self.root / "readme-link"
        link.symlink_to("README.md")
        subprocess.run(
            ["git", "add", "--", "executable", "readme-link"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-q", "-m", "Add mode fixtures"],
            cwd=self.root,
            check=True,
        )
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=self.root,
            text=True,
        ).strip()

        inventory = assurance.git_tree_inventory(self.root, commit)
        self.assertEqual(inventory["README.md"]["mode"], "100644")
        self.assertEqual(inventory["executable"]["mode"], "100755")
        self.assertEqual(inventory["readme-link"]["mode"], "120000")
        self.assertEqual(inventory["readme-link"]["object_type"], "blob")
        self.assertEqual(
            inventory["readme-link"]["sha256"],
            hashlib.sha256(b"README.md").hexdigest(),
        )
        self.assertEqual(inventory["readme-link"]["bytes"], len(b"README.md"))
        self.assertEqual(
            assurance.candidate_blob(self.root, commit, "README.md"),
            (self.root / "README.md").read_bytes(),
        )
        with self.assertRaisesRegex(ReviewError, "identifies a symbolic link"):
            assurance.candidate_blob(self.root, commit, "readme-link")

    def test_candidate_tree_parser_rejects_resource_and_path_abuse(self) -> None:
        object_id = "1" * 40

        def row(path: bytes, size: int = 1) -> bytes:
            return (
                f"100644 blob {object_id} {size}".encode("ascii") + b"\t" + path + b"\0"
            )

        with (
            mock.patch.object(assurance, "MAX_CANDIDATE_TREE_ENTRIES", 1),
            self.assertRaisesRegex(ReviewError, "entry-count bound"),
        ):
            assurance._parse_git_tree_listing(
                row(b"first") + row(b"second"),
                "fixture tree",
            )
        with (
            mock.patch.object(assurance, "MAX_CANDIDATE_BLOB_BYTES", 4),
            self.assertRaisesRegex(ReviewError, "per-blob byte bound"),
        ):
            assurance._parse_git_tree_listing(row(b"large", 5), "fixture tree")
        with (
            mock.patch.object(assurance, "MAX_CANDIDATE_TREE_BLOB_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "aggregate blob-byte bound"),
        ):
            assurance._parse_git_tree_listing(row(b"aggregate", 2), "fixture tree")
        with (
            mock.patch.object(assurance, "MAX_CANDIDATE_PATH_BYTES", 4),
            self.assertRaisesRegex(ReviewError, "path exceeds its byte bound"),
        ):
            assurance._parse_git_tree_listing(row(b"large"), "fixture tree")
        with (
            mock.patch.object(assurance, "MAX_CANDIDATE_PATH_DEPTH", 1),
            self.assertRaisesRegex(ReviewError, "path is unsafe"),
        ):
            assurance._parse_git_tree_listing(row(b"a/b"), "fixture tree")

        unsafe_paths = ("../README.md", "/README.md", "a//b", "a\\b")
        for path in unsafe_paths:
            with (
                self.subTest(path=path),
                mock.patch.object(
                    assurance,
                    "git_bounded_output",
                    side_effect=AssertionError("Git must not run"),
                ),
                self.assertRaises(ReviewError),
            ):
                assurance.candidate_blob(self.root, self.head, path)
        with (
            mock.patch.object(
                assurance,
                "git_bounded_output",
                side_effect=AssertionError("Git must not run"),
            ),
            self.assertRaisesRegex(ReviewError, "full lowercase Git object"),
        ):
            assurance._exact_git_commit(self.root, "HEAD")

    def test_candidate_blob_rejects_mismatched_object_identity(self) -> None:
        expected_id = hashlib.sha1(
            b"blob 1\0x",
            usedforsecurity=False,
        ).hexdigest()
        entry = assurance._GitTreeEntry(
            "fixture",
            "100644",
            "blob",
            expected_id,
            1,
        )
        with (
            mock.patch.object(
                assurance,
                "git_bounded_output",
                return_value=b"y",
            ),
            self.assertRaisesRegex(ReviewError, "Git blob identity"),
        ):
            assurance._read_git_blob(self.root, entry, "fixture blob")

    def test_vulnerable_feature_check_uses_resolved_metadata(self) -> None:
        self.assertEqual(
            CARGO_METADATA_COMMAND,
            (
                "cargo",
                "metadata",
                "--format-version",
                "1",
                "--locked",
                "--all-features",
                "--offline",
            ),
        )
        safe = {
            "packages": [
                {"id": "path+file:///workspace#galadriel@0.9.0", "name": "galadriel"},
                {
                    "id": "registry+https://github.com/rust-lang/crates.io-index#zenoh-transport@1.9.0",
                    "name": "zenoh-transport",
                    "version": "1.9.0",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                },
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": "path+file:///workspace#galadriel@0.9.0",
                        "features": ["default"],
                    },
                    {
                        "id": "registry+https://github.com/rust-lang/crates.io-index#zenoh-transport@1.9.0",
                        "features": [
                            "shared-memory",
                            "transport_tcp",
                            "transport_tls",
                            "transport_udp",
                            "zenoh-shm",
                        ],
                    },
                ]
            },
        }

        metadata_process = assurance.BoundedHostResult(
            0,
            json.dumps(safe).encode("utf-8"),
            b"",
        )
        with (
            mock.patch("check_vulnerable_features.dt.datetime") as datetime_type,
            mock.patch(
                "check_vulnerable_features.run_bounded_host_command",
                return_value=metadata_process,
            ) as run_metadata,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            datetime_type.now.return_value.date.return_value = dt.date(2026, 7, 22)
            self.assertEqual(vulnerable_features_main(), 0)
        run_metadata.assert_called_once_with(
            CARGO_METADATA_COMMAND,
            context="vulnerable-feature Cargo metadata",
            environment=release_tool_environment(),
            max_stdout_bytes=MAX_METADATA_STDOUT_BYTES,
            max_stderr_bytes=MAX_METADATA_STDERR_BYTES,
            timeout_seconds=METADATA_TIMEOUT_SECONDS,
        )

        safe_text = json.dumps(safe, separators=(",", ":"))
        safe_features = json.dumps(
            safe["resolve"]["nodes"][1]["features"], separators=(",", ":")
        )
        feature_member = f'"features":{safe_features}'
        duplicate_text = safe_text.replace(
            feature_member,
            f'"features":["transport_compression"],{feature_member}',
            1,
        )
        nonfinite_text = f'{safe_text[:-1]},"ignored_nonfinite":NaN}}'
        invalid_documents = {
            "duplicate": (duplicate_text, "duplicate JSON key"),
            "nonfinite": (nonfinite_text, "nonstandard JSON constant"),
        }
        for label, (document, diagnostic) in invalid_documents.items():
            diagnostics = io.StringIO()
            with (
                self.subTest(label=label),
                mock.patch("check_vulnerable_features.dt.datetime") as datetime_type,
                mock.patch(
                    "check_vulnerable_features.run_bounded_host_command",
                    return_value=assurance.BoundedHostResult(
                        0,
                        document.encode("utf-8"),
                        b"",
                    ),
                ),
                contextlib.redirect_stderr(diagnostics),
            ):
                datetime_type.now.return_value.date.return_value = dt.date(2026, 7, 22)
                self.assertEqual(vulnerable_features_main(), 2)
            self.assertIn(diagnostic, diagnostics.getvalue())

        validate_metadata(safe)

        enabled = copy.deepcopy(safe)
        enabled["resolve"]["nodes"][1]["features"].append("transport_compression")
        with self.assertRaisesRegex(ValueError, "transport_compression is enabled"):
            validate_metadata(enabled)

        absent = copy.deepcopy(safe)
        absent["packages"] = absent["packages"][:1]
        absent["resolve"]["nodes"] = absent["resolve"]["nodes"][:1]
        with self.assertRaisesRegex(ValueError, "exactly one zenoh-transport"):
            validate_metadata(absent)

        unresolved = copy.deepcopy(safe)
        unresolved["resolve"]["nodes"] = unresolved["resolve"]["nodes"][:1]
        with self.assertRaisesRegex(
            ValueError, "omits a resolved zenoh-transport node"
        ):
            validate_metadata(unresolved)

        with self.assertRaisesRegex(ValueError, "root is not an object"):
            validate_metadata([])

        wrong_version = copy.deepcopy(safe)
        wrong_version["packages"][1]["version"] = "1.9.1"
        with self.assertRaisesRegex(ValueError, "unexpected zenoh-transport identity"):
            validate_metadata(wrong_version)

        wrong_source = copy.deepcopy(safe)
        wrong_source["packages"][1]["source"] = "git+https://example.invalid/zenoh"
        with self.assertRaisesRegex(ValueError, "unexpected zenoh-transport identity"):
            validate_metadata(wrong_source)

        duplicate_package = copy.deepcopy(safe)
        duplicate_package["packages"].append(
            {
                "id": "registry+index#zenoh-transport@2.0.0",
                "name": "zenoh-transport",
                "version": "2.0.0",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
            }
        )
        with self.assertRaisesRegex(ValueError, "exactly one zenoh-transport"):
            validate_metadata(duplicate_package)

        malformed_package = copy.deepcopy(safe)
        malformed_package["packages"].append([])
        with self.assertRaisesRegex(ValueError, "malformed package"):
            validate_metadata(malformed_package)

        malformed_node = copy.deepcopy(safe)
        malformed_node["resolve"]["nodes"].append([])
        with self.assertRaisesRegex(ValueError, "malformed resolved node"):
            validate_metadata(malformed_node)

        unknown_node = copy.deepcopy(safe)
        unknown_node["resolve"]["nodes"].append(
            {
                "id": "registry+https://example.invalid/index#unknown@1.0.0",
                "features": [],
            }
        )
        with self.assertRaisesRegex(ValueError, "unknown package identity"):
            validate_metadata(unknown_node)

        duplicate_node = copy.deepcopy(safe)
        duplicate_node["resolve"]["nodes"].append(
            copy.deepcopy(duplicate_node["resolve"]["nodes"][1])
        )
        with self.assertRaisesRegex(ValueError, "duplicate resolved node"):
            validate_metadata(duplicate_node)

        duplicate_feature = copy.deepcopy(safe)
        duplicate_feature["resolve"]["nodes"][1]["features"].append("transport_tcp")
        with self.assertRaisesRegex(ValueError, "duplicate resolved features"):
            validate_metadata(duplicate_feature)

        for label, features in (
            ("missing", ["transport_tcp"]),
            ("extra", [*safe["resolve"]["nodes"][1]["features"], "future_feature"]),
        ):
            drifted = copy.deepcopy(safe)
            drifted["resolve"]["nodes"][1]["features"] = features
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(
                    ValueError, "unexpected zenoh-transport features"
                ),
            ):
                validate_metadata(drifted)

    def test_release_audit_cross_binds_repository_and_tool_inputs(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        release_audit.validate_inputs(inputs)

        mutations = []
        missing_repository = copy.deepcopy(inputs)
        missing_repository["repositories"].pop()
        mutations.append(("repository input set", missing_repository))

        changed_database = copy.deepcopy(inputs)
        database = next(
            item
            for item in changed_database["repositories"]
            if item["name"] == "RustSec advisory database"
        )
        database["commit"] = "0" * 40
        mutations.append(("repository input identity", changed_database))

        missing_tool = copy.deepcopy(inputs)
        missing_tool["toolchains"].pop()
        mutations.append(("toolchain input set", missing_tool))

        changed_tool = copy.deepcopy(inputs)
        current_stable = next(
            item
            for item in changed_tool["toolchains"]
            if item["name"] == "rustc-current-stable"
        )
        current_stable["identity"] = "another compiler"
        mutations.append(("tool identity", changed_tool))

        for diagnostic, mutated in mutations:
            with (
                self.subTest(diagnostic=diagnostic),
                self.assertRaisesRegex(release_audit.AuditError, diagnostic),
            ):
                release_audit.validate_inputs(mutated)

    def test_ci_cross_binds_current_stable_and_advisory_database(self) -> None:
        workflow = release_audit.CI_WORKFLOW.read_text(encoding="utf-8")
        release_audit.validate_ci_qualification_contract(workflow)

        mutations = (
            (
                "current-stable",
                workflow.replace("toolchain: 1.97.1", "toolchain: 1.97.0", 1),
                "current-stable toolchain",
            ),
            (
                "database commit",
                workflow.replace(
                    release_audit.ADVISORY_DB_COMMIT,
                    "0" * 40,
                    1,
                ),
                "RUSTSEC_ADVISORY_DB_COMMIT",
            ),
            (
                "online dependency check",
                workflow.replace(
                    "cargo deny --offline --all-features",
                    "cargo deny --all-features",
                    1,
                ),
                "pinned offline database",
            ),
            (
                "missing fuzz dependency materialization",
                workflow.replace(
                    "cargo fetch --locked --manifest-path fuzz/Cargo.toml",
                    "cargo fetch --locked --manifest-path fuzz/Cargo.toml.missing",
                    1,
                ),
                "materialize both locked dependency graphs",
            ),
            (
                "missing tree comparison",
                workflow.replace(
                    'test "$(git -C "$database" rev-parse \'HEAD^{tree}\')" = '
                    '"$RUSTSEC_ADVISORY_DB_TREE"',
                    'test -n "$database"',
                    1,
                ),
                "fully verify",
            ),
        )
        for label, mutated, diagnostic in mutations:
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(release_audit.AuditError, diagnostic),
            ):
                release_audit.validate_ci_qualification_contract(mutated)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_release_schema_ids_and_tier_verification_are_immutable_and_explicit(
        self,
    ) -> None:
        repository = TOOLS.parent
        schema_root = repository / "crates/galadriel-ncp/schemas"
        for name in (
            "galadriel-pid-envelope-v1.schema.json",
            "galadriel-monitor-envelope-v1.schema.json",
        ):
            document = json.loads((schema_root / name).read_text(encoding="utf-8"))
            self.assertEqual(
                document["$id"],
                "https://raw.githubusercontent.com/sepahead/galadriel/v0.9.0/"
                f"crates/galadriel-ncp/schemas/{name}",
            )
            identity = document["$defs"]["galadrielCoreIdentity"]
            self.assertEqual(identity["not"]["pattern"], r"[^A-Za-z0-9_.:-]")
            for value in ("uav3\n", "uav3\r", "uav+3", "crébain"):
                with self.subTest(schema=name, identity=value):
                    matches_primary = re.search(identity["pattern"], value) is not None
                    matches_forbidden = (
                        re.search(identity["not"]["pattern"], value) is not None
                    )
                    self.assertFalse(matches_primary and not matches_forbidden)

        runbook = (repository / "release/0.9.0/RELEASE-RUNBOOK.md").read_text(
            encoding="utf-8"
        )
        for literal in (
            "ssh-keygen -Y verify",
            "-I sepmhn@gmail.com",
            "-n galadriel-qualification-manifest",
            "-n galadriel-closure-manifest",
            'len(roots) == 2 or sys.exit("expected exactly two tier roots")',
            "tuple(verify_sha256sums(Path(root)) for root in roots)",
            '"https://github.com/sepahead/galadriel/blob/$tag/$path"',
            '"https://raw.githubusercontent.com/sepahead/galadriel/$tag/$path"',
            'cmp -s "$verification_dir/expected" "$verification_dir/downloaded"',
            'CPython 3.14.6"',
            "mandatory authenticated byte-for-byte comparison",
        ):
            self.assertIn(literal, runbook)
        self.assertRegex(
            runbook,
            re.compile(
                r"5\. Create.*?literal title\s+`Galadriel 0\.9\.0`.*?"
                r"exact tracked `RELEASE-NOTES\.md` body",
                re.DOTALL,
            ),
        )
        self.assertRegex(
            runbook,
            re.compile(
                r"For the two tar files only,.*?signed map\.\s+The\s+map\s+does\s+"
                r"not\s+contain\s+rows\s+for\s+itself\s+or\s+its\s+detached\s+"
                r"signature",
                re.DOTALL,
            ),
        )
        self.assertRegex(
            runbook,
            re.compile(
                r"9\. Confirm.*?literal title is\s+`Galadriel 0\.9\.0`",
                re.DOTALL,
            ),
        )
        threat_register = json.loads(
            (repository / "release/0.9.0/audit/threat-register.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            threat_register["status"],
            "LIVING_UNTIL_CANDIDATE_FREEZE",
        )
        unsupported_threat_register = copy.deepcopy(threat_register)
        unsupported_threat_register["status"] = "UNSUPPORTED"
        with (
            mock.patch.object(
                release_audit,
                "load_json",
                return_value=unsupported_threat_register,
            ),
            self.assertRaisesRegex(
                release_audit.AuditError,
                "unsupported lifecycle status",
            ),
        ):
            release_audit.validate_threat_register()
        cross_repo_threat = next(
            row
            for row in threat_register["threats"]
            if row["threat_id"] == "GLD-THR-015"
        )
        self.assertIn("ROS / ROS 2", cross_repo_threat["trust_boundary"])
        self.assertNotIn("ROS/ROS 2", cross_repo_threat["trust_boundary"])
        for path in (
            "release/0.9.0/ecosystem-cut.json",
            "release/0.9.0/claims.json",
            "docs/ADVISORY-BOUNDARY.md",
            "docs/ECOSYSTEM-CONNECTIONS.md",
            "release/0.9.0/RELEASE-RUNBOOK.md",
            "CITATION.cff",
            "release/0.9.0/local-convergence-schema.json",
            "crates/galadriel-ncp/schemas/galadriel-pid-envelope-v1.schema.json",
            "crates/galadriel-ncp/schemas/galadriel-monitor-envelope-v1.schema.json",
        ):
            self.assertIn(f'"{path}"', runbook)

    def make_frozen_input_fixture(self, name: str) -> dict[str, object]:
        repo = self.root / name
        repo.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
        for key, value in (
            ("user.name", "Sepehr Mahmoudian"),
            ("user.email", "sepmhn@gmail.com"),
            ("commit.gpgsign", "false"),
        ):
            subprocess.run(["git", "config", key, value], cwd=repo, check=True)
        subprocess.run(
            ["git", "remote", "add", "origin", "git@github.com:sepahead/galadriel.git"],
            cwd=repo,
            check=True,
        )
        baseline_contents = {
            "Cargo.toml": '[workspace]\nmembers = []\nresolver = "2"\n',
            "Cargo.lock": "version = 3\n",
            "rust-toolchain.toml": '[toolchain]\nchannel = "1.89.0"\n',
            "deny.toml": "[advisories]\nversion = 2\n",
        }
        for relative, contents in baseline_contents.items():
            (repo / relative).write_text(contents, encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "Create baseline"], cwd=repo, check=True
        )
        baseline = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True
        ).strip()
        baseline_tree = subprocess.check_output(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=repo, text=True
        ).strip()

        handoff = self.root / f"{name}-MASTER_HANDOFF"
        handoff.mkdir()
        child_name = "GALADRIEL_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF.zip"
        child = handoff / child_name
        child.write_bytes(b"child archive\n")
        ledger = handoff / Path(child_name).stem / "MASTER_TASK_LEDGER.yaml"
        ledger.parent.mkdir()
        ledger.write_text("tasks: []\n", encoding="utf-8")
        child_digest = hashlib.sha256(child.read_bytes()).hexdigest()
        ledger_digest = hashlib.sha256(ledger.read_bytes()).hexdigest()

        release = repo / "release/0.9.0"
        release.mkdir(parents=True)
        handoff_source = {
            "schema": "galadriel.handoff-source.v2",
            "prepared": "2026-07-14",
            "repository": "https://github.com/sepahead/galadriel",
            "frozen_commit": baseline,
            "original_target": "1.0.0",
            "adapted_release_target": "0.9.0",
            "master_package": handoff.name,
            "child_archive": child_name,
            "child_archive_sha256": child_digest,
            "task_ledger_sha256": ledger_digest,
            "task_count": 1,
            "supersedes_embedded_handoff_sha256": "1" * 64,
            "provenance_note": "Fixture provenance binding.",
        }
        audit_inputs = {
            "schema": "galadriel.release-audit-inputs.v1",
            "release": {
                "name": "Galadriel's Mirror",
                "version": "0.9.0",
                "author": "Sepehr Mahmoudian",
                "doi": None,
                "zenodo": None,
                "publication_channel": freeze.PUBLICATION_CHANNEL,
            },
            "audit_date": "2026-07-23",
            "baseline_repository": {
                "url": "https://github.com/sepahead/galadriel",
                "commit": baseline,
                "tree": baseline_tree,
            },
            "repositories": [],
            "toolchains": [],
            "github_actions": [],
            "artifact_sets": [],
            "external_sources": {"scan_patterns": [], "declared": []},
            "adaptation_decision": "release/0.9.0/VERSION-ADAPTATION.md",
        }
        (release / "handoff-source.json").write_bytes(canonical_json(handoff_source))
        (release / "audit-inputs.json").write_bytes(canonical_json(audit_inputs))
        threat_register = release / "audit/threat-register.json"
        threat_register.parent.mkdir()
        threat_register.write_bytes(
            canonical_json({"status": freeze.THREAT_STATUS_FROZEN})
        )
        (repo / "input.txt").write_text("release input\n", encoding="utf-8")
        subprocess.run(
            [
                "git",
                "add",
                "--",
                "release/0.9.0/audit-inputs.json",
                freeze.THREAT_REGISTER_PATH,
                "release/0.9.0/handoff-source.json",
                "input.txt",
            ],
            cwd=repo,
            check=True,
        )

        key = self.root / f"{name}-signing-key"
        subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                freeze.SIGNATURE_PRINCIPAL,
                "-f",
                str(key),
            ],
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.signingkey", str(key) + ".pub"],
            cwd=repo,
            check=True,
        )
        output = self.root / f"{name}-FROZEN-AUDIT-INPUTS.json"
        allowed_signers = self.root / f"{name}-ALLOWED_SIGNERS"
        release_inputs = (
            "release/0.9.0/audit-inputs.json",
            freeze.THREAT_REGISTER_PATH,
            "release/0.9.0/handoff-source.json",
            "input.txt",
        )
        with (
            mock.patch.object(freeze, "RELEASE_INPUTS", release_inputs),
            mock.patch.object(freeze, "EXPECTED_BASELINE_COMMIT", baseline),
            mock.patch.object(freeze, "EXPECTED_BASELINE_TREE", baseline_tree),
        ):
            freeze.generate_frozen_inputs(repo, handoff, output, allowed_signers)
        self.sign_frozen_fixture(output, key)
        return {
            "repo": repo,
            "handoff": handoff,
            "ledger": ledger,
            "output": output,
            "allowed_signers": allowed_signers,
            "key": key,
            "release_inputs": release_inputs,
            "baseline": baseline,
            "baseline_tree": baseline_tree,
        }

    def sign_frozen_fixture(
        self, output: Path, key: Path, *, namespace: str = freeze.SIGNATURE_NAMESPACE
    ) -> None:
        signature = output.with_name(output.name + ".sig")
        signature.unlink(missing_ok=True)
        subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(key),
                "-n",
                namespace,
                str(output),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def mutate_frozen_fixture(
        self,
        fixture: dict[str, object],
        mutation: Callable[[dict[str, Any]], None],
    ) -> None:
        output = fixture["output"]
        key = fixture["key"]
        assert isinstance(output, Path)
        assert isinstance(key, Path)
        manifest = load_json(output)
        assert isinstance(manifest, dict)
        mutation(manifest)
        output.write_bytes(canonical_json(manifest))
        self.sign_frozen_fixture(output, key)

    def verify_frozen_fixture(
        self, fixture: dict[str, object], *, with_handoff: bool = True
    ) -> None:
        repo = fixture["repo"]
        handoff = fixture["handoff"] if with_handoff else None
        output = fixture["output"]
        allowed_signers = fixture["allowed_signers"]
        release_inputs = fixture["release_inputs"]
        baseline = fixture["baseline"]
        baseline_tree = fixture["baseline_tree"]
        assert isinstance(repo, Path)
        assert handoff is None or isinstance(handoff, Path)
        assert isinstance(output, Path)
        assert isinstance(allowed_signers, Path)
        assert isinstance(release_inputs, tuple)
        assert isinstance(baseline, str)
        assert isinstance(baseline_tree, str)
        with (
            mock.patch.object(freeze, "RELEASE_INPUTS", release_inputs),
            mock.patch.object(freeze, "EXPECTED_BASELINE_COMMIT", baseline),
            mock.patch.object(freeze, "EXPECTED_BASELINE_TREE", baseline_tree),
        ):
            freeze.verify_frozen_inputs(repo, handoff, output, allowed_signers)

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
                with self.assertRaisesRegex(
                    ReviewError, "cannot encode canonical JSON"
                ):
                    canonical_json({"value": value})

        retained = {"seed": 6_840_335_614_489_011_713}
        self.assertEqual(loads_json(canonical_json(retained)), retained)
        retained_evidence = load_json(TOOLS.parent / "evidence/post-audit-v1.json")
        self.assertEqual(retained_evidence["base_seed"], 6_840_335_614_489_011_713)
        with self.assertRaisesRegex(ReviewError, "cannot encode canonical JSON"):
            canonical_json({"value": 10**128})

    def test_evidence_manifest_reports_oversized_integer_without_traceback(
        self,
    ) -> None:
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
        cargo_home = self.root / "isolated-cargo-home"
        cargo_home.mkdir()
        report_environment = {
            "CARGO_HOME": str(cargo_home),
            "PATH": os.environ["PATH"],
        }
        for json_lines, document in report_cases:
            with self.subTest(json_lines=json_lines):
                with self.assertRaisesRegex(ReviewError, "invalid JSON evidence"):
                    capture_report(
                        [sys.executable, "-c", f"print({document!r})"],
                        worktree=self.root,
                        environment=report_environment,
                        output=self.root / "reports" / "report.json",
                        json_lines=json_lines,
                        report_stream="stdout",
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

    def test_repository_instruction_files_are_frozen(self) -> None:
        self.assertIn("AGENTS.md", freeze.RELEASE_INPUTS)
        self.assertIn("CLAUDE.mdc", freeze.RELEASE_INPUTS)
        self.assertIn("docs/DEPENDENCY-POLICY.md", freeze.RELEASE_INPUTS)
        self.assertIn("release/0.9.0/RELEASE-RUNBOOK.md", freeze.RELEASE_INPUTS)

        instructions = (TOOLS / "README.md").read_text(encoding="utf-8")
        exact_name = "FROZEN-AUDIT-INPUTS-0.9.0.json"
        self.assertGreaterEqual(instructions.count(exact_name), 8)
        self.assertNotIn('"$freeze_dir/FROZEN-AUDIT-INPUTS.json"', instructions)

    def test_release_input_manifest_requires_exact_index_bytes(self) -> None:
        def make_repository(name: str) -> Path:
            repo = self.root / name
            repo.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
            subprocess.run(
                ["git", "config", "user.name", "Sepehr Mahmoudian"],
                cwd=repo,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "sepmhn@gmail.com"],
                cwd=repo,
                check=True,
            )
            (repo / "input.txt").write_text("indexed input\n", encoding="utf-8")
            subprocess.run(["git", "add", "input.txt"], cwd=repo, check=True)
            subprocess.run(
                ["git", "commit", "-q", "-m", "Create input"],
                cwd=repo,
                check=True,
            )
            return repo

        staged = make_repository("release-input-staged")
        staged_data = b"staged candidate input\n"
        (staged / "input.txt").write_bytes(staged_data)
        subprocess.run(["git", "add", "input.txt"], cwd=staged, check=True)
        with mock.patch.object(freeze, "RELEASE_INPUTS", ("input.txt",)):
            self.assertEqual(
                freeze.release_input_manifest(staged),
                [
                    {
                        "path": "input.txt",
                        "sha256": hashlib.sha256(staged_data).hexdigest(),
                        "size_bytes": len(staged_data),
                    }
                ],
            )

        untracked = make_repository("release-input-untracked")
        (untracked / "untracked.txt").write_text("not indexed\n", encoding="utf-8")
        with (
            mock.patch.object(freeze, "RELEASE_INPUTS", ("untracked.txt",)),
            self.assertRaisesRegex(ReviewError, "exactly one stage-zero tracked entry"),
        ):
            freeze.release_input_manifest(untracked)

        conflict = make_repository("release-input-conflict")
        blob_ids = []
        for data in (b"base\n", b"current\n", b"incoming\n"):
            process = subprocess.run(
                ["git", "hash-object", "-w", "--stdin"],
                cwd=conflict,
                input=data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            blob_ids.append(process.stdout.decode("ascii").strip())
        index_rows = (
            f"0 {'0' * 40}\tinput.txt\n"
            f"100644 {blob_ids[0]} 1\tinput.txt\n"
            f"100644 {blob_ids[1]} 2\tinput.txt\n"
            f"100644 {blob_ids[2]} 3\tinput.txt\n"
        )
        subprocess.run(
            ["git", "update-index", "--index-info"],
            cwd=conflict,
            input=index_rows.encode("ascii"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        with (
            mock.patch.object(freeze, "RELEASE_INPUTS", ("input.txt",)),
            self.assertRaisesRegex(ReviewError, "exactly one stage-zero tracked entry"),
        ):
            freeze.release_input_manifest(conflict)

        divergent = make_repository("release-input-divergent")
        (divergent / "input.txt").write_text("changed input\n", encoding="utf-8")
        with (
            mock.patch.object(freeze, "RELEASE_INPUTS", ("input.txt",)),
            self.assertRaisesRegex(ReviewError, "differs from its indexed blob"),
        ):
            freeze.release_input_manifest(divergent)

        replaced = make_repository("release-input-replaced")
        head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=replaced, text=True
        ).strip()
        subprocess.run(
            ["git", "update-ref", f"refs/replace/{head}", head],
            cwd=replaced,
            check=True,
        )
        with (
            mock.patch.object(freeze, "RELEASE_INPUTS", ("input.txt",)),
            self.assertRaisesRegex(ReviewError, "replacement references are forbidden"),
        ):
            freeze.release_input_manifest(replaced)

    def test_frozen_input_verifier_accepts_exact_inputs_and_optional_handoff(
        self,
    ) -> None:
        fixture = self.make_frozen_input_fixture("valid-freeze")
        self.verify_frozen_fixture(fixture)
        self.verify_frozen_fixture(fixture, with_handoff=False)
        output = fixture["output"]
        assert isinstance(output, Path)
        self.assertEqual(
            load_json(output)["repository_ref_inputs"]["origin"],
            "https://github.com/sepahead/galadriel",
        )

        self.mutate_frozen_fixture(
            fixture,
            lambda manifest: manifest["repository_ref_inputs"].__setitem__(
                "origin", "git@github.com:sepahead/galadriel.git"
            ),
        )
        self.verify_frozen_fixture(fixture, with_handoff=False)

        repo = fixture["repo"]
        assert isinstance(repo, Path)
        subprocess.run(
            ["git", "remote", "set-url", "origin", "https://example.invalid/moved"],
            cwd=repo,
            check=True,
        )
        subprocess.run(["git", "tag", "post-freeze-tag"], cwd=repo, check=True)
        self.verify_frozen_fixture(fixture, with_handoff=False)

        ledger = fixture["ledger"]
        assert isinstance(ledger, Path)
        ledger.write_text("tasks: [changed]\n", encoding="utf-8")
        self.verify_frozen_fixture(fixture, with_handoff=False)
        with self.assertRaisesRegex(ReviewError, "supplied handoff inventory differs"):
            self.verify_frozen_fixture(fixture)

    def test_frozen_input_generator_rejects_credential_bearing_origin_rewrites(
        self,
    ) -> None:
        for name, configure in (
            (
                "credential-origin",
                lambda repo: subprocess.run(
                    [
                        "git",
                        "remote",
                        "set-url",
                        "origin",
                        (
                            "https://fixture-user:fixture-password@github.com/"
                            "sepahead/galadriel.git"
                        ),
                    ],
                    cwd=repo,
                    check=True,
                ),
            ),
            (
                "instead-of-origin",
                lambda repo: (
                    subprocess.run(
                        [
                            "git",
                            "remote",
                            "set-url",
                            "origin",
                            "https://github.com/sepahead/galadriel.git",
                        ],
                        cwd=repo,
                        check=True,
                    ),
                    subprocess.run(
                        [
                            "git",
                            "config",
                            (
                                "url.https://fixture-user:fixture-password@"
                                "github.com/.insteadOf"
                            ),
                            "https://github.com/",
                        ],
                        cwd=repo,
                        check=True,
                    ),
                ),
            ),
            (
                "whitespace-origin",
                lambda repo: subprocess.run(
                    [
                        "git",
                        "remote",
                        "set-url",
                        "origin",
                        " https://github.com/sepahead/galadriel.git ",
                    ],
                    cwd=repo,
                    check=True,
                ),
            ),
            (
                "alternate-push-origin",
                lambda repo: subprocess.run(
                    [
                        "git",
                        "remote",
                        "set-url",
                        "--push",
                        "origin",
                        "https://example.invalid/other.git",
                    ],
                    cwd=repo,
                    check=True,
                ),
            ),
            (
                "multiple-push-origins",
                lambda repo: (
                    subprocess.run(
                        [
                            "git",
                            "remote",
                            "set-url",
                            "--add",
                            "--push",
                            "origin",
                            "git@github.com:sepahead/galadriel.git",
                        ],
                        cwd=repo,
                        check=True,
                    ),
                    subprocess.run(
                        [
                            "git",
                            "remote",
                            "set-url",
                            "--add",
                            "--push",
                            "origin",
                            "ssh://git@github.com/sepahead/galadriel.git",
                        ],
                        cwd=repo,
                        check=True,
                    ),
                ),
            ),
        ):
            with self.subTest(name=name):
                fixture = self.make_frozen_input_fixture(name)
                repo = fixture["repo"]
                handoff = fixture["handoff"]
                release_inputs = fixture["release_inputs"]
                baseline = fixture["baseline"]
                baseline_tree = fixture["baseline_tree"]
                assert isinstance(repo, Path)
                assert isinstance(handoff, Path)
                assert isinstance(release_inputs, tuple)
                assert isinstance(baseline, str)
                assert isinstance(baseline_tree, str)
                configure(repo)
                output = self.root / f"{name}-rejected.json"
                allowed = self.root / f"{name}-rejected-signers"
                with (
                    mock.patch.object(freeze, "RELEASE_INPUTS", release_inputs),
                    mock.patch.object(freeze, "EXPECTED_BASELINE_COMMIT", baseline),
                    mock.patch.object(freeze, "EXPECTED_BASELINE_TREE", baseline_tree),
                    self.assertRaises(ReviewError) as caught,
                ):
                    freeze.generate_frozen_inputs(repo, handoff, output, allowed)
                diagnostic = str(caught.exception)
                self.assertIn("canonical credential-free repository", diagnostic)
                self.assertNotIn("fixture-password", diagnostic)
                self.assertFalse(output.exists())
                self.assertFalse(allowed.exists())

    def test_frozen_manifest_cannot_change_basename_after_signing(self) -> None:
        fixture = self.make_frozen_input_fixture("signed-basename")
        repo = fixture["repo"]
        output = fixture["output"]
        allowed = fixture["allowed_signers"]
        release_inputs = fixture["release_inputs"]
        baseline = fixture["baseline"]
        baseline_tree = fixture["baseline_tree"]
        assert isinstance(repo, Path)
        assert isinstance(output, Path)
        assert isinstance(allowed, Path)
        assert isinstance(release_inputs, tuple)
        assert isinstance(baseline, str)
        assert isinstance(baseline_tree, str)

        renamed = self.root / "renamed-frozen-inputs.json"
        renamed.write_bytes(output.read_bytes())
        renamed.with_name(renamed.name + ".sig").write_bytes(
            output.with_name(output.name + ".sig").read_bytes()
        )
        with (
            mock.patch.object(freeze, "RELEASE_INPUTS", release_inputs),
            mock.patch.object(freeze, "EXPECTED_BASELINE_COMMIT", baseline),
            mock.patch.object(freeze, "EXPECTED_BASELINE_TREE", baseline_tree),
            self.assertRaisesRegex(
                ReviewError,
                "signature contract signature_path",
            ),
        ):
            freeze.verify_frozen_inputs(repo, None, renamed, allowed)

    def test_feature_contract_rejects_upstream_alias_and_resolved_feature_drift(
        self,
    ) -> None:
        def upstream_packages() -> list[dict[str, object]]:
            return [
                {
                    "name": name,
                    "version": contract["version"],
                    "source": contract["source"],
                    "features": {
                        feature: sorted(members)
                        for feature, members in contract["features"].items()
                    },
                }
                for name, contract in EXPECTED_UPSTREAM_MANIFESTS.items()
            ]

        packages = upstream_packages()
        validate_upstream_package_records(packages)

        for package_name in EXPECTED_UPSTREAM_MANIFESTS:
            for field in ("version", "source"):
                with self.subTest(package=package_name, field=field):
                    mutated = upstream_packages()
                    record = next(
                        package
                        for package in mutated
                        if package["name"] == package_name
                    )
                    record[field] = "unexpected"
                    with self.assertRaisesRegex(ReviewError, f"{field} differs"):
                        validate_upstream_package_records(mutated)

        pid_manifest = next(
            package for package in packages if package["name"] == "pid-core"
        )
        pid_manifest["features"]["experimental-pipelines"] = ["experimental-continuous"]
        with self.assertRaisesRegex(ReviewError, "experimental-pipelines differs"):
            validate_upstream_package_records(packages)

        unexpected_alias = upstream_packages()
        unexpected_pid = next(
            package for package in unexpected_alias if package["name"] == "pid-core"
        )
        unexpected_pid["features"]["unexpected"] = []
        with self.assertRaisesRegex(ReviewError, "feature aliases differ"):
            validate_upstream_package_records(unexpected_alias)

        workspace_manifest = {
            "workspace": {"default-members": list(EXPECTED_DEFAULT_MEMBERS)}
        }
        validate_workspace_manifest(workspace_manifest)
        workspace_manifest["workspace"]["default-members"].append(
            "crates/galadriel-pid"
        )
        with self.assertRaisesRegex(ReviewError, "default-members differ"):
            validate_workspace_manifest(workspace_manifest)

        expected_descriptor = (
            "cargo_rev Cargo.toml v0.8.0 "
            "2f5bd586d4bb20c90362bb6f5698b7f64057ba4e\n"
            "cargo_lock_rev Cargo.lock v0.8.0 "
            "2f5bd586d4bb20c90362bb6f5698b7f64057ba4e\n"
        )
        self.assertEqual(len(parse_ncp_consumer_descriptor(expected_descriptor)), 2)
        for attack in (
            "",
            "cargo_tag Cargo.toml\ncargo_lock Cargo.lock\n",
            expected_descriptor.splitlines()[0] + "\n",
            expected_descriptor + "unknown extra row value\n",
        ):
            with self.subTest(descriptor=attack):
                with self.assertRaises(ReviewError):
                    parse_ncp_consumer_descriptor(attack)

        profile = next(profile for profile in PROFILES if profile.name == "pid")
        graph = {
            "galadriel-pid": frozenset(),
            "pid-core": PID_RESOLVED_FEATURES,
            "pid-runlog": frozenset(),
        }
        validate_profile_graph(profile, graph)
        graph["pid-core"] = PID_RESOLVED_FEATURES | {"parallel"}
        with self.assertRaisesRegex(ReviewError, "resolved pid-core features"):
            validate_profile_graph(profile, graph)

        resolved_feature_attacks = (
            ("ncp", "ncp-core", frozenset({"default", "schema"})),
            ("ncp-live", "ncp-zenoh", frozenset({"default", "schema"})),
            ("ncp-live", "zenoh", ZENOH_RESOLVED_FEATURES | {"default"}),
            ("ncp-live", "tokio", TOKIO_RESOLVED_FEATURES | {"process"}),
        )
        for profile_name, package_name, mutated_features in resolved_feature_attacks:
            with self.subTest(profile=profile_name, package=package_name):
                attacked_profile = next(
                    profile for profile in PROFILES if profile.name == profile_name
                )
                attacked_graph = {
                    package: {
                        "pid-core": PID_RESOLVED_FEATURES,
                        "ncp-core": NCP_RESOLVED_FEATURES,
                        "ncp-zenoh": NCP_RESOLVED_FEATURES,
                        "zenoh": ZENOH_RESOLVED_FEATURES,
                    }.get(package, frozenset())
                    for package in attacked_profile.required
                }
                attacked_graph[package_name] = mutated_features
                with self.assertRaisesRegex(ReviewError, "resolved.*features"):
                    validate_profile_graph(attacked_profile, attacked_graph)

        edge_contracts = (
            ("eval-member", "ncp-core"),
            ("eval-member", "pid-core"),
            ("justify-member", "pid-core"),
        )
        exact_feature_sets = {
            "pid-core": PID_RESOLVED_FEATURES,
            "ncp-core": NCP_RESOLVED_FEATURES,
            "ncp-zenoh": NCP_RESOLVED_FEATURES,
            "zenoh": ZENOH_RESOLVED_FEATURES,
            "tokio": TOKIO_RESOLVED_FEATURES,
        }
        for profile_name, missing_package in edge_contracts:
            with self.subTest(profile=profile_name, missing=missing_package):
                member_profile = next(
                    profile for profile in PROFILES if profile.name == profile_name
                )
                member_graph = {
                    package: exact_feature_sets.get(package, frozenset())
                    for package in member_profile.required
                }
                validate_profile_graph(member_profile, member_graph)
                del member_graph[missing_package]
                with self.assertRaisesRegex(ReviewError, "missing"):
                    validate_profile_graph(member_profile, member_graph)

    def test_feature_graph_parser_tolerates_unrelated_duplicate_package_names(
        self,
    ) -> None:
        profile = next(profile for profile in PROFILES if profile.name == "ncp-live")
        output = "\n".join(
            (
                "getrandom v0.3.4|",
                "getrandom v0.4.3|std",
                "ncp-core v0.8.0 (locked)|default",
                "ncp-core v0.8.0 (locked)|default (*)",
            )
        )
        graph = parse_graph_output(profile, output)
        self.assertEqual(graph["getrandom"], frozenset({"std"}))
        self.assertEqual(graph["ncp-core"], frozenset({"default"}))

        with self.assertRaisesRegex(ReviewError, "inconsistent features for ncp-core"):
            parse_graph_output(
                profile,
                output + "\nncp-core v0.8.0 (locked)|default,schema\n",
            )

        for control in (
            "\x08",
            "\x09",
            "\x0b",
            "\x0c",
            "\x1c",
            "\x1d",
            "\x1e",
            "\x1b[0m",
            "\x7f",
            "\x85",
            "\x9b0m",
            "\u2028",
            "\u2029",
        ):
            with self.subTest(control=ascii(control)):
                with self.assertRaisesRegex(
                    ReviewError,
                    r"unsafe non-printable characters: 'ncp-core .*'",
                ):
                    parse_graph_output(
                        profile,
                        f"ncp-core v0.8.0 (locked)|default{control}\n",
                    )

        self.assertEqual(
            parse_graph_output(
                profile,
                "ncp-core v0.8.0 (locked)|default\r\n",
            )["ncp-core"],
            frozenset({"default"}),
        )
        with self.assertRaisesRegex(ReviewError, "unsafe non-printable characters"):
            parse_graph_output(
                profile,
                "ncp-core v0.8.0 (locked)|default\r",
            )

    def test_feature_graph_disables_cargo_terminal_color(self) -> None:
        profile = next(profile for profile in PROFILES if profile.name == "pure")
        completed = assurance.BoundedHostResult(
            0,
            b"galadriel-cli v0.9.0|default\n",
            b"",
        )
        with (
            mock.patch.dict(os.environ, {"CARGO_TERM_COLOR": "always"}),
            mock.patch(
                "check_feature_graph.run_bounded_host_command",
                return_value=completed,
            ) as run_cargo,
        ):
            self.assertEqual(
                package_graph(self.root, profile),
                {"galadriel-cli": frozenset({"default"})},
            )
            self.assertEqual(os.environ["CARGO_TERM_COLOR"], "always")

        self.assertEqual(
            run_cargo.call_args.kwargs["environment"],
            release_tool_environment(),
        )
        self.assertEqual(run_cargo.call_args.kwargs["cwd"], self.root)
        self.assertEqual(run_cargo.call_args.kwargs["context"], "feature graph pure")
        self.assertEqual(
            run_cargo.call_args.kwargs["max_stdout_bytes"],
            MAX_FEATURE_GRAPH_STDOUT_BYTES,
        )
        self.assertEqual(
            run_cargo.call_args.kwargs["max_stderr_bytes"],
            MAX_FEATURE_GRAPH_STDERR_BYTES,
        )
        self.assertEqual(
            run_cargo.call_args.kwargs["timeout_seconds"],
            FEATURE_GRAPH_TIMEOUT_SECONDS,
        )
        self.assertIn("--color=never", run_cargo.call_args.args[0])

        invalid_utf8 = assurance.BoundedHostResult(0, b"\xff", b"")
        with mock.patch(
            "check_feature_graph.run_bounded_host_command",
            return_value=invalid_utf8,
        ):
            with self.assertRaisesRegex(ReviewError, "non-UTF-8 stdout"):
                package_graph(self.root, profile)

        invalid_failure = assurance.BoundedHostResult(101, b"", b"\xff")
        with mock.patch(
            "check_feature_graph.run_bounded_host_command",
            return_value=invalid_failure,
        ):
            with self.assertRaisesRegex(
                ReviewError,
                "failed with exit status 101 and non-UTF-8 stderr",
            ):
                package_graph(self.root, profile)

        failed_with_junk_stdout = assurance.BoundedHostResult(
            101,
            b"\xff",
            b"error: failed to parse lock file\n",
        )
        with mock.patch(
            "check_feature_graph.run_bounded_host_command",
            return_value=failed_with_junk_stdout,
        ):
            with self.assertRaisesRegex(
                ReviewError,
                "failed to parse lock file.*stdout is non-UTF-8",
            ):
                package_graph(self.root, profile)

        unsafe_stderr = assurance.BoundedHostResult(
            101,
            b"",
            b"\x1b[31merror\x1b[0m: failed\n",
        )
        with mock.patch(
            "check_feature_graph.run_bounded_host_command",
            return_value=unsafe_stderr,
        ):
            with self.assertRaisesRegex(
                ReviewError, "unsafe non-printable characters in stderr"
            ):
                package_graph(self.root, profile)

        unsafe_success_stderr = assurance.BoundedHostResult(
            0,
            b"galadriel-cli v0.9.0|default\n",
            b"\x1b[33mwarning\x1b[0m\n",
        )
        with mock.patch(
            "check_feature_graph.run_bounded_host_command",
            return_value=unsafe_success_stderr,
        ):
            with self.assertRaisesRegex(
                ReviewError,
                "succeeded with unsafe non-printable characters in stderr",
            ):
                package_graph(self.root, profile)

    def test_machine_ecosystem_cut_binds_the_connection_prose(self) -> None:
        repo = TOOLS.parent
        cut = json.loads(
            (repo / "release/0.9.0/ecosystem-cut.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            set(cut),
            {
                "schema",
                "release",
                "author",
                "inspected_at",
                "timestamp_precision",
                "scope",
                "observations",
                "limitations",
            },
        )
        self.assertEqual(cut["schema"], "galadriel.ecosystem-inspection-cut.v1")
        self.assertEqual(cut["release"], "0.9.0")
        self.assertEqual(cut["author"], "Sepehr Mahmoudian")
        self.assertEqual(
            (cut["inspected_at"], cut["timestamp_precision"]),
            ("2026-07-23", "date"),
        )
        observations = cut["observations"]
        expected_observations = [
            {
                "id": "ECO-001",
                "project": "pid-rs",
                "relationship": "optional_build_dependency",
                "ref": "Cargo.lock git revision",
                "object": "1cd2424f7967e1752dcc8e53859e8fdad3566f51",
                "identity_kind": "immutable_dependency_pin",
                "observed_at": "2026-07-18",
                "timestamp_precision": "date",
                "required_by_default": False,
                "required_for": [
                    "pid feature",
                    "galadriel-pid",
                    "galadriel-eval",
                    "galadriel-justify",
                ],
                "supersedes": None,
                "why": "Provides the optional PID implementation and run-log types at one exact revision.",
            },
            {
                "id": "ECO-002",
                "project": "NCP",
                "relationship": "optional_build_and_transport_dependency",
                "ref": "Cargo.lock git revision",
                "object": "2f5bd586d4bb20c90362bb6f5698b7f64057ba4e",
                "identity_kind": "immutable_dependency_pin",
                "observed_at": "2026-07-18",
                "timestamp_precision": "date",
                "required_by_default": False,
                "required_for": [
                    "ncp feature",
                    "ncp-live feature",
                    "galadriel-ncp",
                    "galadriel-eval",
                ],
                "supersedes": None,
                "why": "Provides the wire-0.8 core types and, only for ncp-live, the Zenoh adapter.",
            },
            {
                "id": "ECO-003",
                "project": "NCP",
                "relationship": "upstream_design_inspection",
                "ref": "refs/heads/main",
                "object": "10492c81ac671ef1909962a9f1fede33781b9933",
                "identity_kind": "mutable_head_observation",
                "observed_at": "2026-07-18",
                "timestamp_precision": "date",
                "required_by_default": False,
                "required_for": [],
                "supersedes": None,
                "why": "Records the inspected coordination tooling and proposed wire-1.0 topology without changing the runtime pin.",
            },
            {
                "id": "ECO-004",
                "project": "Crebain",
                "relationship": "optional_reference_producer",
                "ref": "refs/heads/main",
                "object": "0a58a5b8dd799884ddb06f1308b1748216fab322",
                "identity_kind": "mutable_head_observation",
                "observed_at": "2026-07-18",
                "timestamp_precision": "date",
                "required_by_default": False,
                "required_for": [],
                "supersedes": None,
                "why": "Records component-level producer-contract alignment; no Cargo or runtime dependency exists.",
            },
            {
                "id": "ECO-005",
                "project": "Haldir",
                "relationship": "prospective_downstream_consumer",
                "ref": "refs/heads/main",
                "object": "0e94f61cfd5c78482198a765157571746a256181",
                "identity_kind": "mutable_head_discovery_observation",
                "observed_at": "2026-07-18",
                "timestamp_precision": "date",
                "required_by_default": False,
                "required_for": [],
                "supersedes": None,
                "why": "Records the initial no-edge downstream inspection; Galadriel has no Haldir adapter or route.",
            },
            {
                "id": "ECO-006",
                "project": "Haldir",
                "relationship": "prospective_downstream_consumer",
                "ref": "refs/heads/main",
                "object": "dd3d8a1c993721f89a1edb04dec5247761c694ad",
                "identity_kind": "mutable_head_reinspection",
                "observed_at": "2026-07-18",
                "timestamp_precision": "date",
                "required_by_default": False,
                "required_for": [],
                "supersedes": "ECO-005",
                "why": "Records the later same-day descendant observation; only the mutable discovery-head reference is superseded.",
            },
            {
                "id": "ECO-007",
                "project": "Prisoma",
                "relationship": "prospective_downstream_offline_consumer",
                "ref": "refs/heads/main",
                "object": "63cff105e0e40281376e6f827d7782e9b351961a",
                "identity_kind": "mutable_head_observation",
                "observed_at": "2026-07-18",
                "timestamp_precision": "date",
                "required_by_default": False,
                "required_for": [],
                "supersedes": None,
                "why": "Records the absent direct sidecar path and a possible future immutable offline comparison only.",
            },
            {
                "id": "ECO-008",
                "project": "Engram/Paper2Brain",
                "relationship": "configuration_example_without_integration",
                "ref": "Galadriel 0.9.0 local source inventory",
                "object": None,
                "identity_kind": "declared_absent_runtime_edge",
                "observed_at": "2026-07-22",
                "timestamp_precision": "date",
                "required_by_default": False,
                "required_for": [],
                "supersedes": None,
                "why": "Records that engram/ncp is a configurable example realm and creates no Paper2Brain dependency, API, route, adapter, or runtime edge.",
            },
            {
                "id": "ECO-009",
                "project": "ROS / ROS 2",
                "relationship": "external_middleware_without_interface",
                "ref": "Galadriel 0.9.0 local source inventory",
                "object": None,
                "identity_kind": "declared_absent_runtime_edge",
                "observed_at": "2026-07-22",
                "timestamp_precision": "date",
                "required_by_default": False,
                "required_for": [],
                "supersedes": None,
                "why": "Records the absence of a ROS dependency, binding, topic, service, action, node, bag importer, bridge, or compatibility claim.",
            },
            {
                "id": "ECO-010",
                "project": "external authority",
                "relationship": "advisory_boundary_without_command_edge",
                "ref": "Galadriel 0.9.0 local source inventory",
                "object": None,
                "identity_kind": "declared_absent_runtime_edge",
                "observed_at": "2026-07-22",
                "timestamp_precision": "date",
                "required_by_default": False,
                "required_for": [],
                "supersedes": None,
                "why": "Records that Galadriel has no command, credential, lease, watchdog, control, or authority path and cannot grant or widen permission.",
            },
            {
                "id": "ECO-011",
                "project": "Haldir",
                "relationship": "prospective_downstream_consumer",
                "ref": "refs/heads/main",
                "object": "c0e4b3d156500684329a92bcb16e0609894fd738",
                "identity_kind": "mutable_head_reinspection",
                "observed_at": "2026-07-22",
                "timestamp_precision": "date",
                "required_by_default": False,
                "required_for": [],
                "supersedes": "ECO-006",
                "why": "Records the activated CH-T001 repository-inventory evidence update, whose retained downstream disposition says the runtime surface and external conformance did not change; no Galadriel adapter or route was added.",
            },
            {
                "id": "ECO-012",
                "project": "Haldir",
                "relationship": "prospective_downstream_consumer",
                "ref": "refs/heads/main",
                "object": "590ba767b32a27d9dd61a2462968306c1052434e",
                "identity_kind": "mutable_head_reinspection",
                "observed_at": "2026-07-23",
                "timestamp_precision": "date",
                "required_by_default": False,
                "required_for": [],
                "supersedes": "ECO-011",
                "why": "Records the mutable Haldir head observed on 2026-07-23 after its evidence-tool updates. Galadriel still has no Haldir adapter, route, or runtime edge.",
            },
            {
                "id": "ECO-013",
                "project": "Paper2Brain",
                "relationship": "external_application_without_integration",
                "ref": "refs/heads/main",
                "object": "24e74b781a5bf8af069f69cbc2d0c42d89008211",
                "identity_kind": "mutable_head_observation",
                "observed_at": "2026-07-23",
                "timestamp_precision": "date",
                "required_by_default": False,
                "required_for": [],
                "supersedes": None,
                "why": "Records the mutable Paper2Brain head observed on 2026-07-23 as read-only provenance. Galadriel has no Paper2Brain dependency, API, route, adapter, or runtime edge.",
            },
        ]
        self.assertEqual(observations, expected_observations)
        self.assertEqual(
            cut["limitations"],
            [
                "Mutable head observations are inspection provenance, not dependency pins.",
                "No observation claims reciprocal final-candidate acceptance, deployment qualification, or a current Haldir, Prisoma, Engram/Paper2Brain, ROS, or external-authority runtime edge.",
                "Later Haldir observations do not rewrite the discovery observation or frozen historical evidence.",
                "The directed declared graph is acyclic: optional upstream inputs point into Galadriel, prospective evidence consumers point outward, and no command or feedback edge returns upstream.",
            ],
        )
        self.assertEqual(
            [row["id"] for row in observations],
            [f"ECO-{index:03d}" for index in range(1, 14)],
        )
        self.assertEqual(
            [row["project"] for row in observations],
            [
                "pid-rs",
                "NCP",
                "NCP",
                "Crebain",
                "Haldir",
                "Haldir",
                "Prisoma",
                "Engram/Paper2Brain",
                "ROS / ROS 2",
                "external authority",
                "Haldir",
                "Haldir",
                "Paper2Brain",
            ],
        )
        self.assertTrue(
            all(row["required_by_default"] is False for row in observations)
        )
        self.assertEqual(
            [
                row["id"]
                for row in observations
                if row["identity_kind"] == "immutable_dependency_pin"
            ],
            ["ECO-001", "ECO-002"],
        )
        self.assertEqual(
            {
                row["id"]: row["supersedes"]
                for row in observations
                if row["supersedes"] is not None
            },
            {
                "ECO-006": "ECO-005",
                "ECO-011": "ECO-006",
                "ECO-012": "ECO-011",
            },
        )
        self.assertEqual(
            observations[0]["required_for"],
            ["pid feature", "galadriel-pid", "galadriel-eval", "galadriel-justify"],
        )
        self.assertEqual(
            observations[1]["required_for"],
            ["ncp feature", "ncp-live feature", "galadriel-ncp", "galadriel-eval"],
        )
        self.assertEqual(
            [
                row["id"]
                for row in observations
                if row["identity_kind"] == "declared_absent_runtime_edge"
            ],
            ["ECO-008", "ECO-009", "ECO-010"],
        )
        self.assertNotEqual(
            observations[12]["identity_kind"],
            "declared_absent_runtime_edge",
        )

        public_api = (repo / "release/0.9.0/api/galadriel-core.0.9.0.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("FusedVerdict::AttributedInconsistency::channels:", public_api)
        self.assertIn("FusedVerdict::AttributedInconsistency::magnitude:", public_api)

        readme = (repo / "README.md").read_text(encoding="utf-8")
        connections = (repo / "docs/ECOSYSTEM-CONNECTIONS.md").read_text(
            encoding="utf-8"
        )
        for row in observations:
            self.assertIn(row["project"].casefold(), readme.casefold())
            self.assertIn(row["project"].casefold(), connections.casefold())
            if row["object"] is not None:
                self.assertIn(row["object"], readme)
                self.assertIn(row["object"], connections)
        for relative in ("docs/ADVISORY-BOUNDARY.md", "CHANGELOG.md"):
            text = (repo / relative).read_text(encoding="utf-8")
            self.assertIn(observations[4]["object"], text)
            self.assertIn(observations[5]["object"], text)
        self.assertIn("ecosystem-cut.json", readme)
        self.assertIn("ecosystem-cut.json", connections)

    def test_feature_graph_cli_reports_non_utf8_descriptor_without_traceback(
        self,
    ) -> None:
        (self.root / ".ncp-consumer").write_bytes(b"\xff\n")
        stderr = io.StringIO()
        with (
            mock.patch("check_feature_graph.validate_manifest"),
            mock.patch.object(
                sys, "argv", ["check_feature_graph.py", "--repo", str(self.root)]
            ),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(feature_graph_main(), 2)
        self.assertIn("feature graph check failed", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_ncp_consumer_descriptor_read_is_bounded_and_no_follow(self) -> None:
        descriptor = self.root / ".ncp-consumer"
        outside = self.root / "outside-consumer"
        outside.write_text("not trusted\n", encoding="utf-8")

        descriptor.symlink_to(outside)
        with self.assertRaisesRegex(ReviewError, "missing or unsafe"):
            validate_ncp_consumer_descriptor(self.root)
        descriptor.unlink()

        os.mkfifo(descriptor)
        with self.assertRaisesRegex(ReviewError, "bounded regular file"):
            validate_ncp_consumer_descriptor(self.root)
        descriptor.unlink()

        descriptor.write_bytes(b"x" * (MAX_NCP_CONSUMER_BYTES + 1))
        with self.assertRaisesRegex(ReviewError, "bounded regular file"):
            validate_ncp_consumer_descriptor(self.root)

    def test_frozen_input_verifier_rejects_schema_identity_and_order_attacks(
        self,
    ) -> None:
        cases = (
            (
                "extra-key",
                lambda manifest: manifest.__setitem__("unexpected", True),
                "incorrect keys",
            ),
            (
                "doi",
                lambda manifest: manifest["release"].__setitem__("doi", "10.invalid"),
                "null DOI/Zenodo",
            ),
            (
                "release-order",
                lambda manifest: manifest["release_input_files"].reverse(),
                "exact ordered current RELEASE_INPUTS",
            ),
            (
                "signature-namespace",
                lambda manifest: manifest["signature_contract"].__setitem__(
                    "namespace", "wrong-release-namespace"
                ),
                "signature contract namespace",
            ),
            (
                "signature-path",
                lambda manifest: manifest["signature_contract"].__setitem__(
                    "signature_path", "wrong-signature-path"
                ),
                "signature contract signature_path",
            ),
        )
        for name, mutation, message in cases:
            with self.subTest(name=name):
                fixture = self.make_frozen_input_fixture(f"semantic-{name}")
                self.mutate_frozen_fixture(fixture, mutation)
                with self.assertRaisesRegex(ReviewError, message):
                    self.verify_frozen_fixture(fixture, with_handoff=False)

    def test_frozen_input_verifier_rejects_release_input_digest_drift(self) -> None:
        fixture = self.make_frozen_input_fixture("release-input-digest-drift")
        repo = fixture["repo"]
        assert isinstance(repo, Path)
        (repo / "input.txt").write_text("mutated release input\n", encoding="utf-8")

        with self.assertRaisesRegex(ReviewError, "differs from its indexed blob"):
            self.verify_frozen_fixture(fixture, with_handoff=False)

    def test_frozen_input_verifier_rejects_broken_baseline_handoff_and_ref_bindings(
        self,
    ) -> None:
        cases = (
            (
                "baseline",
                lambda manifest: manifest["baseline"].__setitem__("tree", "0" * 40),
                "baseline identities",
            ),
            (
                "handoff",
                lambda manifest: manifest["handoff"].__setitem__(
                    "galadriel_child_archive_sha256", "0" * 64
                ),
                "child archive digest breaks",
            ),
            (
                "historical-ref",
                lambda manifest: manifest["repository_ref_inputs"][
                    "local_tags_at_freeze"
                ].append(
                    {
                        "ref": "refs/tags/../invalid",
                        "object": "0" * 40,
                        "object_type": "commit",
                        "peeled_object": None,
                    }
                ),
                "invalid refname",
            ),
        )
        for name, mutation, message in cases:
            with self.subTest(name=name):
                fixture = self.make_frozen_input_fixture(f"binding-{name}")
                self.mutate_frozen_fixture(fixture, mutation)
                with self.assertRaisesRegex(ReviewError, message):
                    self.verify_frozen_fixture(fixture, with_handoff=False)

    def test_frozen_input_verifier_rejects_handoff_and_ref_structure_attacks(
        self,
    ) -> None:
        def remove_bound_child(manifest: dict[str, Any]) -> None:
            handoff = manifest["handoff"]
            rows = handoff["files"]
            handoff["files"] = [
                row
                for row in rows
                if not ("/" not in row["path"] and row["path"].endswith(".zip"))
            ]
            handoff["file_count"] = len(handoff["files"])
            handoff["total_bytes"] = sum(row["size_bytes"] for row in handoff["files"])

        cases = (
            (
                "duplicate-handoff-path",
                lambda manifest: manifest["handoff"]["files"].append(
                    dict(manifest["handoff"]["files"][0])
                ),
                "handoff file path is duplicated",
            ),
            (
                "symlink-identity",
                lambda manifest: manifest["handoff"]["files"].append(
                    {
                        "path": "synthetic-link",
                        "kind": "symlink",
                        "target": "target",
                        "sha256": "0" * 64,
                        "size_bytes": 0,
                    }
                ),
                "symlink target identity is inconsistent",
            ),
            (
                "file-count",
                lambda manifest: manifest["handoff"].__setitem__(
                    "file_count", manifest["handoff"]["file_count"] + 1
                ),
                "file_count does not match",
            ),
            (
                "total-bytes",
                lambda manifest: manifest["handoff"].__setitem__(
                    "total_bytes", manifest["handoff"]["total_bytes"] + 1
                ),
                "total_bytes does not match",
            ),
            (
                "missing-bound-child",
                remove_bound_child,
                "does not contain its bound child archive",
            ),
            (
                "origin-control",
                lambda manifest: manifest["repository_ref_inputs"].__setitem__(
                    "origin", "https://example.invalid/repo\ninjected"
                ),
                "historical origin is not a canonical credential-free repository",
            ),
            (
                "annotated-tag-without-peel",
                lambda manifest: manifest["repository_ref_inputs"][
                    "local_tags_at_freeze"
                ].append(
                    {
                        "ref": "refs/tags/annotated",
                        "object": "0" * 40,
                        "object_type": "tag",
                        "peeled_object": None,
                    }
                ),
                "peeled_object must be a nonempty JSON string",
            ),
        )
        for name, mutation, message in cases:
            with self.subTest(name=name):
                fixture = self.make_frozen_input_fixture(f"structure-{name}")
                self.mutate_frozen_fixture(fixture, mutation)
                with self.assertRaisesRegex(ReviewError, message):
                    self.verify_frozen_fixture(fixture, with_handoff=False)

    def test_frozen_input_generator_rejects_multiple_configured_public_keys(
        self,
    ) -> None:
        fixture = self.make_frozen_input_fixture("multi-key-generation")
        repo = fixture["repo"]
        handoff = fixture["handoff"]
        key = fixture["key"]
        release_inputs = fixture["release_inputs"]
        baseline = fixture["baseline"]
        baseline_tree = fixture["baseline_tree"]
        assert isinstance(repo, Path)
        assert isinstance(handoff, Path)
        assert isinstance(key, Path)
        assert isinstance(release_inputs, tuple)
        assert isinstance(baseline, str)
        assert isinstance(baseline_tree, str)

        public_key = Path(str(key) + ".pub").read_text(encoding="ascii")
        multiple_keys = self.root / "multiple-signing-keys.pub"
        multiple_keys.write_text(public_key + public_key, encoding="ascii")
        subprocess.run(
            ["git", "config", "user.signingkey", str(multiple_keys)],
            cwd=repo,
            check=True,
        )
        output = self.root / "multi-key-generation-output.json"
        allowed_signers = self.root / "multi-key-generation-allowed-signers"
        with (
            mock.patch.object(freeze, "RELEASE_INPUTS", release_inputs),
            mock.patch.object(freeze, "EXPECTED_BASELINE_COMMIT", baseline),
            mock.patch.object(freeze, "EXPECTED_BASELINE_TREE", baseline_tree),
            self.assertRaisesRegex(ReviewError, "exactly one public key entry"),
        ):
            freeze.generate_frozen_inputs(repo, handoff, output, allowed_signers)
        self.assertFalse(output.exists())
        self.assertFalse(allowed_signers.exists())

    def test_frozen_input_operations_require_frozen_threat_status(self) -> None:
        fixture = self.make_frozen_input_fixture("threat-status-freeze")
        repo = fixture["repo"]
        handoff = fixture["handoff"]
        release_inputs = fixture["release_inputs"]
        baseline = fixture["baseline"]
        baseline_tree = fixture["baseline_tree"]
        assert isinstance(repo, Path)
        assert isinstance(handoff, Path)
        assert isinstance(release_inputs, tuple)
        assert isinstance(baseline, str)
        assert isinstance(baseline_tree, str)

        threat_register = repo / freeze.THREAT_REGISTER_PATH
        threat_register.write_bytes(
            canonical_json({"status": freeze.THREAT_STATUS_LIVING})
        )
        subprocess.run(
            ["git", "add", "--", freeze.THREAT_REGISTER_PATH],
            cwd=repo,
            check=True,
        )
        output = self.root / "living-generation.json"
        allowed_signers = self.root / "living-generation-signers"
        with (
            mock.patch.object(freeze, "RELEASE_INPUTS", release_inputs),
            mock.patch.object(freeze, "EXPECTED_BASELINE_COMMIT", baseline),
            mock.patch.object(freeze, "EXPECTED_BASELINE_TREE", baseline_tree),
            self.assertRaisesRegex(
                ReviewError,
                "indexed threat register must have lifecycle status "
                "FROZEN_AT_CANDIDATE",
            ),
        ):
            freeze.generate_frozen_inputs(repo, handoff, output, allowed_signers)
        self.assertFalse(output.exists())
        self.assertFalse(allowed_signers.exists())

        with self.assertRaisesRegex(
            ReviewError,
            "indexed threat register must have lifecycle status FROZEN_AT_CANDIDATE",
        ):
            self.verify_frozen_fixture(fixture, with_handoff=False)

    def test_freeze_lifecycle_verifier_is_phase_exact(self) -> None:
        fixture = self.make_frozen_input_fixture("phase-exact-freeze")
        repo = fixture["repo"]
        output = fixture["output"]
        allowed_signers = fixture["allowed_signers"]
        release_inputs = fixture["release_inputs"]
        baseline = fixture["baseline"]
        baseline_tree = fixture["baseline_tree"]
        assert isinstance(repo, Path)
        assert isinstance(output, Path)
        assert isinstance(allowed_signers, Path)
        assert isinstance(release_inputs, tuple)
        assert isinstance(baseline, str)
        assert isinstance(baseline_tree, str)

        with (
            mock.patch.object(freeze, "RELEASE_INPUTS", release_inputs),
            mock.patch.object(freeze, "EXPECTED_BASELINE_COMMIT", baseline),
            mock.patch.object(freeze, "EXPECTED_BASELINE_TREE", baseline_tree),
        ):
            self.assertEqual(
                freeze.verify_freeze_lifecycle(
                    repo,
                    None,
                    output,
                    allowed_signers,
                ),
                freeze.THREAT_STATUS_FROZEN,
            )

        threat_register = repo / freeze.THREAT_REGISTER_PATH
        threat_register.write_bytes(
            canonical_json({"status": freeze.THREAT_STATUS_LIVING})
        )
        subprocess.run(
            ["git", "add", "--", freeze.THREAT_REGISTER_PATH],
            cwd=repo,
            check=True,
        )
        absent_output = self.root / "phase-exact-active.json"
        absent_signature = absent_output.with_name(absent_output.name + ".sig")
        with (
            mock.patch.object(freeze, "RELEASE_INPUTS", release_inputs),
            mock.patch.object(freeze, "EXPECTED_BASELINE_COMMIT", baseline),
            mock.patch.object(freeze, "EXPECTED_BASELINE_TREE", baseline_tree),
        ):
            self.assertEqual(
                freeze.verify_freeze_lifecycle(
                    repo,
                    None,
                    absent_output,
                    allowed_signers,
                ),
                freeze.THREAT_STATUS_LIVING,
            )
            absent_output.write_bytes(b"partial manifest")
            with self.assertRaisesRegex(
                ReviewError,
                "active frozen manifest must be absent",
            ):
                freeze.verify_freeze_lifecycle(
                    repo,
                    None,
                    absent_output,
                    allowed_signers,
                )
            absent_output.unlink()
            absent_signature.write_bytes(b"partial signature")
            with self.assertRaisesRegex(
                ReviewError,
                "active frozen signature must be absent",
            ):
                freeze.verify_freeze_lifecycle(
                    repo,
                    None,
                    absent_output,
                    allowed_signers,
                )
            absent_signature.unlink()

    def test_historical_tag_inventory_has_a_pre_subprocess_bound(self) -> None:
        tag = {
            "ref": "refs/tags/example",
            "object": "0" * 40,
            "object_type": "commit",
            "peeled_object": None,
        }
        refs = {
            "origin": "https://github.com/sepahead/galadriel",
            "local_tags_at_freeze": [tag] * (freeze.MAX_HISTORICAL_TAGS + 1),
            "note": freeze.REF_INPUT_NOTE,
        }
        with (
            mock.patch.object(
                freeze,
                "run_bounded_host_command",
                side_effect=AssertionError("oversize tag inventory must not spawn"),
            ),
            self.assertRaisesRegex(ReviewError, "historical tag inventory exceeds"),
        ):
            freeze.validate_repository_ref_inputs(refs)

        raw_tags = "\n".join(
            f"refs/tags/tag-{index:04d}\0{'0' * 40}\0commit\0"
            for index in range(freeze.MAX_HISTORICAL_TAGS + 1)
        )
        with (
            mock.patch.object(freeze, "git", return_value=raw_tags) as git_call,
            self.assertRaisesRegex(ReviewError, "local tag inventory exceeds"),
        ):
            freeze.tag_inventory(self.root)
        self.assertIn(
            f"--count={freeze.MAX_HISTORICAL_TAGS + 1}", git_call.call_args.args
        )

    def test_frozen_input_verifier_rejects_paired_baseline_source_drift(self) -> None:
        fixture = self.make_frozen_input_fixture("paired-baseline-drift")
        repo = fixture["repo"]
        baseline = fixture["baseline"]
        baseline_tree = fixture["baseline_tree"]
        assert isinstance(repo, Path)
        assert isinstance(baseline, str)
        assert isinstance(baseline_tree, str)

        wrong_commit = "0" * 40
        wrong_tree = "1" * 40
        handoff_path = repo / "release/0.9.0/handoff-source.json"
        audit_path = repo / "release/0.9.0/audit-inputs.json"
        handoff = load_json(handoff_path)
        audit = load_json(audit_path)
        handoff["frozen_commit"] = wrong_commit
        audit["baseline_repository"]["commit"] = wrong_commit
        audit["baseline_repository"]["tree"] = wrong_tree
        handoff_path.write_bytes(canonical_json(handoff))
        audit_path.write_bytes(canonical_json(audit))

        with (
            mock.patch.object(freeze, "EXPECTED_BASELINE_COMMIT", baseline),
            mock.patch.object(freeze, "EXPECTED_BASELINE_TREE", baseline_tree),
            self.assertRaisesRegex(ReviewError, "immutable baseline commit"),
        ):
            freeze.validate_source_documents(repo)

    def test_frozen_input_verifier_rejects_noncanonical_signer_and_namespace_attacks(
        self,
    ) -> None:
        noncanonical = self.make_frozen_input_fixture("noncanonical-freeze")
        output = noncanonical["output"]
        key = noncanonical["key"]
        assert isinstance(output, Path)
        assert isinstance(key, Path)
        output.write_bytes(output.read_bytes() + b"\n")
        self.sign_frozen_fixture(output, key)
        with self.assertRaisesRegex(ReviewError, "not strict canonical JSON"):
            self.verify_frozen_fixture(noncanonical, with_handoff=False)

        signer = self.make_frozen_input_fixture("signer-freeze")
        allowed_signers = signer["allowed_signers"]
        assert isinstance(allowed_signers, Path)
        allowed_signers.write_text(
            allowed_signers.read_text(encoding="ascii").replace(
                freeze.SIGNATURE_PRINCIPAL, "wrong@example.invalid"
            ),
            encoding="ascii",
        )
        with self.assertRaisesRegex(ReviewError, "principal does not match"):
            self.verify_frozen_fixture(signer, with_handoff=False)

        key_type = self.make_frozen_input_fixture("key-type-freeze")
        key_type_signers = key_type["allowed_signers"]
        assert isinstance(key_type_signers, Path)
        key_type_signers.write_text(
            key_type_signers.read_text(encoding="ascii").replace(
                "ssh-ed25519", "ssh-rsa", 1
            ),
            encoding="ascii",
        )
        with self.assertRaisesRegex(ReviewError, "exactly ssh-ed25519"):
            self.verify_frozen_fixture(key_type, with_handoff=False)

        fingerprint = self.make_frozen_input_fixture("fingerprint-freeze")
        self.mutate_frozen_fixture(
            fingerprint,
            lambda manifest: manifest["signature_contract"].__setitem__(
                "public_key_fingerprint",
                "256 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "
                f"{freeze.SIGNATURE_PRINCIPAL} (ED25519)",
            ),
        )
        with self.assertRaisesRegex(ReviewError, "fingerprint differs"):
            self.verify_frozen_fixture(fingerprint, with_handoff=False)

        namespace = self.make_frozen_input_fixture("namespace-freeze")
        namespace_output = namespace["output"]
        namespace_key = namespace["key"]
        assert isinstance(namespace_output, Path)
        assert isinstance(namespace_key, Path)
        self.sign_frozen_fixture(
            namespace_output, namespace_key, namespace="wrong-release-namespace"
        )
        with self.assertRaisesRegex(ReviewError, "signature verification failed"):
            self.verify_frozen_fixture(namespace, with_handoff=False)

        symlink = self.make_frozen_input_fixture("symlink-freeze")
        symlink_output = symlink["output"]
        symlink_signers = symlink["allowed_signers"]
        assert isinstance(symlink_output, Path)
        assert isinstance(symlink_signers, Path)
        manifest_link = self.root / symlink_output.name.replace("FROZEN", "LINKED")
        manifest_link.symlink_to(symlink_output)
        with self.assertRaisesRegex(ReviewError, "missing or not regular"):
            freeze.verify_frozen_inputs(
                symlink["repo"], None, manifest_link, symlink_signers
            )

    def test_frozen_input_verifier_rejects_principal_prefix_and_spacing_attacks(
        self,
    ) -> None:
        cases = (
            (
                "principal-prefix",
                freeze.SIGNATURE_PRINCIPAL + ".attacker",
                "principal does not match",
            ),
            (
                "principal-spacing",
                freeze.SIGNATURE_PRINCIPAL + " ",
                "exactly principal, key type, and key data",
            ),
        )
        for name, replacement, message in cases:
            with self.subTest(name=name):
                fixture = self.make_frozen_input_fixture(name)
                allowed_signers = fixture["allowed_signers"]
                assert isinstance(allowed_signers, Path)
                allowed_signers.write_text(
                    allowed_signers.read_text(encoding="ascii").replace(
                        freeze.SIGNATURE_PRINCIPAL, replacement, 1
                    ),
                    encoding="ascii",
                )
                with self.assertRaisesRegex(ReviewError, message):
                    self.verify_frozen_fixture(fixture, with_handoff=False)

        duplicate = self.make_frozen_input_fixture("duplicate-signer-entry")
        duplicate_signers = duplicate["allowed_signers"]
        assert isinstance(duplicate_signers, Path)
        entry = duplicate_signers.read_text(encoding="ascii")
        duplicate_signers.write_text(entry + entry, encoding="ascii")
        with self.assertRaisesRegex(
            ReviewError, "exactly one newline-terminated entry"
        ):
            self.verify_frozen_fixture(duplicate, with_handoff=False)

    def test_signer_fingerprint_requires_canonical_ed25519_shape(self) -> None:
        forged = assurance.BoundedHostResult(
            0,
            (
                "256 MD5:00:11:22:33:44:55:66:77 "
                f"{freeze.SIGNATURE_PRINCIPAL} (ED25519)\n"
            ).encode("ascii"),
            b"",
        )
        with (
            mock.patch.object(
                freeze,
                "run_bounded_host_command",
                return_value=forged,
            ),
            self.assertRaisesRegex(ReviewError, "unexpected Ed25519 shape"),
        ):
            freeze.signer_fingerprint(b"unused signer entry\n")

    def test_allowed_signer_is_bounded_and_snapshotted_for_signature_use(self) -> None:
        oversize = self.root / "oversize-allowed-signers"
        oversize.write_bytes(b"x" * (freeze.MAX_ALLOWED_SIGNERS_BYTES + 1))
        with (
            mock.patch.object(
                freeze,
                "validate_allowed_signer_bytes",
                side_effect=AssertionError("oversize signer must not be parsed"),
            ),
            self.assertRaisesRegex(ReviewError, "exceeds the 4 KiB limit"),
        ):
            freeze.validate_allowed_signer(oversize)

        fixture = self.make_frozen_input_fixture("swapped-allowed-signer-freeze")
        output = fixture["output"]
        allowed_signers = fixture["allowed_signers"]
        assert isinstance(output, Path)
        assert isinstance(allowed_signers, Path)

        replacement_key = self.root / "replacement-signing-key"
        subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                freeze.SIGNATURE_PRINCIPAL,
                "-f",
                str(replacement_key),
            ],
            check=True,
        )
        replacement_fields = (
            Path(str(replacement_key) + ".pub").read_text(encoding="ascii").split()
        )
        replacement_signer = (
            f"{freeze.SIGNATURE_PRINCIPAL} {replacement_fields[0]} "
            f"{replacement_fields[1]}\n"
        ).encode("ascii")
        self.sign_frozen_fixture(output, replacement_key)
        bounded_reader = freeze.read_bounded_regular_file

        def snapshot_then_replace(path: Path, *args: object, **kwargs: object) -> bytes:
            data = bounded_reader(path, *args, **kwargs)
            if path == allowed_signers:
                path.write_bytes(replacement_signer)
            return data

        with (
            mock.patch.object(
                freeze,
                "read_bounded_regular_file",
                side_effect=snapshot_then_replace,
            ),
            self.assertRaisesRegex(ReviewError, "signature verification failed"),
        ):
            freeze.validate_signature(
                output.read_bytes(),
                output,
                allowed_signers,
            )

    def test_frozen_input_signature_is_verified_before_repository_recomputation(
        self,
    ) -> None:
        fixture = self.make_frozen_input_fixture("signature-first-freeze")
        repo = fixture["repo"]
        output = fixture["output"]
        allowed_signers = fixture["allowed_signers"]
        assert isinstance(repo, Path)
        assert isinstance(output, Path)
        assert isinstance(allowed_signers, Path)

        with (
            mock.patch.object(
                freeze,
                "validate_signature",
                side_effect=ReviewError("injected authentication failure"),
            ),
            mock.patch.object(
                freeze,
                "loads_json",
                side_effect=AssertionError("unauthenticated bytes must not be parsed"),
            ) as loads_json,
            mock.patch.object(freeze, "baseline_manifest") as baseline_manifest,
            self.assertRaisesRegex(ReviewError, "injected authentication failure"),
        ):
            freeze.verify_frozen_inputs(repo, None, output, allowed_signers)
        loads_json.assert_not_called()
        baseline_manifest.assert_not_called()

    def test_frozen_input_signature_size_is_bounded_before_verification(self) -> None:
        fixture = self.make_frozen_input_fixture("oversize-signature-freeze")
        output = fixture["output"]
        allowed_signers = fixture["allowed_signers"]
        assert isinstance(output, Path)
        assert isinstance(allowed_signers, Path)
        manifest = load_json(output)
        signature = output.with_name(output.name + ".sig")
        signature.write_bytes(b"x" * (freeze.MAX_SIGNATURE_BYTES + 1))

        with (
            mock.patch.object(
                freeze,
                "validate_allowed_signer_bytes",
                return_value=manifest["signature_contract"]["public_key_fingerprint"],
            ),
            mock.patch.object(
                freeze,
                "run_bounded_host_command",
                side_effect=AssertionError("oversize signature must not be verified"),
            ),
            self.assertRaisesRegex(ReviewError, "signature exceeds the 64 KiB limit"),
        ):
            freeze.validate_signature(
                output.read_bytes(),
                output,
                allowed_signers,
            )

        swap_fixture = self.make_frozen_input_fixture("swapped-signature-freeze")
        swap_output = swap_fixture["output"]
        swap_signers = swap_fixture["allowed_signers"]
        assert isinstance(swap_output, Path)
        assert isinstance(swap_signers, Path)
        swap_signature = swap_output.with_name(swap_output.name + ".sig")
        bounded_reader = freeze.read_bounded_regular_file

        def snapshot_then_swap(path: Path, *args: object, **kwargs: object) -> bytes:
            data = bounded_reader(path, *args, **kwargs)
            path.unlink()
            path.write_bytes(b"x" * (freeze.MAX_SIGNATURE_BYTES + 1))
            return data

        with mock.patch.object(
            freeze, "read_bounded_regular_file", side_effect=snapshot_then_swap
        ):
            freeze.validate_signature(
                swap_output.read_bytes(),
                swap_output,
                swap_signers,
            )
        self.assertGreater(swap_signature.stat().st_size, freeze.MAX_SIGNATURE_BYTES)

    def test_bounded_regular_reader_is_path_swap_safe_and_read_limited(self) -> None:
        path = self.root / "bounded-input"
        original = b"signed bytes"
        path.write_bytes(original)
        real_fstat = freeze.os.fstat

        with (
            mock.patch.object(
                freeze.os,
                "close",
                side_effect=AssertionError("fdopen-owned descriptor was reclosed"),
            ),
            self.assertRaisesRegex(ReviewError, "exceeds the zero-byte limit"),
        ):
            freeze.read_bounded_regular_file(
                path, 0, label="fixture", limit_label="zero-byte"
            )

        path_swap_calls = 0

        def replace_path(descriptor: int) -> os.stat_result:
            nonlocal path_swap_calls
            path_swap_calls += 1
            metadata = real_fstat(descriptor)
            if path_swap_calls == 1:
                path.unlink()
                path.write_bytes(b"x" * 129)
            return metadata

        with (
            mock.patch.object(freeze.os, "fstat", side_effect=replace_path),
            self.assertRaisesRegex(ReviewError, "changed while being read"),
        ):
            freeze.read_bounded_regular_file(
                path, 128, label="fixture", limit_label="128-byte"
            )

        path.write_bytes(original)

        def grow_open_file(descriptor: int) -> os.stat_result:
            metadata = real_fstat(descriptor)
            with path.open("ab") as handle:
                handle.write(b"x" * 129)
            return metadata

        with (
            mock.patch.object(freeze.os, "fstat", side_effect=grow_open_file),
            self.assertRaisesRegex(ReviewError, "exceeds the 128-byte limit"),
        ):
            freeze.read_bounded_regular_file(
                path, 128, label="fixture", limit_label="128-byte"
            )

        path.write_bytes(original)
        fstat_calls = 0

        def mutate_before_final_identity(descriptor: int) -> os.stat_result:
            nonlocal fstat_calls
            fstat_calls += 1
            if fstat_calls == 2:
                path.write_bytes(b"changed data")
            return real_fstat(descriptor)

        with (
            mock.patch.object(
                freeze.os,
                "fstat",
                side_effect=mutate_before_final_identity,
            ),
            self.assertRaisesRegex(ReviewError, "changed while being read"),
        ):
            freeze.read_bounded_regular_file(
                path, 128, label="fixture", limit_label="128-byte"
            )

        fifo = self.root / "bounded-fifo"
        os.mkfifo(fifo)
        program = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from common import ReviewError
from freeze_audit_inputs import read_bounded_regular_file
try:
    read_bounded_regular_file(
        Path(sys.argv[2]), 128, label="fixture", limit_label="128-byte"
    )
except ReviewError as error:
    if "missing or not regular" in str(error):
        raise SystemExit(0)
    print(error, file=sys.stderr)
    raise SystemExit(2)
raise SystemExit(3)
"""
        try:
            process = subprocess.run(
                [sys.executable, "-c", program, str(TOOLS), str(fifo)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=2,
            )
        except subprocess.TimeoutExpired as error:
            self.fail(f"bounded regular-file reader blocked on a FIFO: {error}")
        self.assertEqual(process.returncode, 0, process.stderr)

    def test_common_bounded_regular_reader_does_not_block_on_fifo(self) -> None:
        fifo = self.root / "common-bounded-fifo"
        os.mkfifo(fifo)
        program = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from common import ReviewError, read_bounded_regular_file
try:
    read_bounded_regular_file(Path(sys.argv[2]), max_bytes=128, label="fixture")
except ReviewError as error:
    if "not a regular file" in str(error):
        raise SystemExit(0)
    print(error, file=sys.stderr)
    raise SystemExit(2)
raise SystemExit(3)
"""
        try:
            process = subprocess.run(
                [sys.executable, "-c", program, str(TOOLS), str(fifo)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=2,
            )
        except subprocess.TimeoutExpired as error:
            self.fail(f"common bounded reader blocked on a FIFO: {error}")
        self.assertEqual(process.returncode, 0, process.stderr)

    def test_frozen_input_verify_cli_returns_controlled_nonzero(self) -> None:
        fixture = self.make_frozen_input_fixture("controlled-cli-freeze")
        output = fixture["output"]
        key = fixture["key"]
        repo = fixture["repo"]
        allowed_signers = fixture["allowed_signers"]
        release_inputs = fixture["release_inputs"]
        baseline = fixture["baseline"]
        baseline_tree = fixture["baseline_tree"]
        assert isinstance(output, Path)
        assert isinstance(key, Path)
        assert isinstance(repo, Path)
        assert isinstance(allowed_signers, Path)
        assert isinstance(release_inputs, tuple)
        assert isinstance(baseline, str)
        assert isinstance(baseline_tree, str)
        self.sign_frozen_fixture(output, key, namespace="wrong-release-namespace")
        stderr = io.StringIO()
        arguments = [
            str(TOOLS / "freeze_audit_inputs.py"),
            "verify",
            "--repo",
            str(repo),
            "--out",
            str(output),
            "--allowed-signers",
            str(allowed_signers),
        ]
        with (
            mock.patch.object(freeze, "RELEASE_INPUTS", release_inputs),
            mock.patch.object(freeze, "EXPECTED_BASELINE_COMMIT", baseline),
            mock.patch.object(freeze, "EXPECTED_BASELINE_TREE", baseline_tree),
            mock.patch.object(sys, "argv", arguments),
            contextlib.redirect_stderr(stderr),
        ):
            result = freeze.main()
        self.assertEqual(result, 2)
        self.assertIn("signature verification failed", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

        output.write_text("[" * 2_000 + "0" + "]" * 2_000, encoding="ascii")
        stderr = io.StringIO()
        with (
            mock.patch.object(freeze, "RELEASE_INPUTS", release_inputs),
            mock.patch.object(freeze, "EXPECTED_BASELINE_COMMIT", baseline),
            mock.patch.object(freeze, "EXPECTED_BASELINE_TREE", baseline_tree),
            mock.patch.object(sys, "argv", arguments),
            contextlib.redirect_stderr(stderr),
        ):
            result = freeze.main()
        self.assertEqual(result, 2)
        self.assertIn("audit-input freeze failed", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_frozen_input_cli_rejects_manifest_and_signer_symlinks(self) -> None:
        fixture = self.make_frozen_input_fixture("cli-symlink-freeze")
        repo = fixture["repo"]
        output = fixture["output"]
        allowed_signers = fixture["allowed_signers"]
        release_inputs = fixture["release_inputs"]
        baseline = fixture["baseline"]
        baseline_tree = fixture["baseline_tree"]
        assert isinstance(repo, Path)
        assert isinstance(output, Path)
        assert isinstance(allowed_signers, Path)
        assert isinstance(release_inputs, tuple)
        assert isinstance(baseline, str)
        assert isinstance(baseline_tree, str)

        manifest_link = self.root / "cli-linked-manifest.json"
        manifest_link.symlink_to(output)
        signer_dir = self.root / "cli-linked-signer"
        signer_dir.mkdir()
        signer_link = signer_dir / allowed_signers.name
        signer_link.symlink_to(allowed_signers)

        cases = (
            (manifest_link, allowed_signers, "manifest is missing or not regular"),
            (output, signer_link, "allowed-signers file is missing or not regular"),
        )
        for manifest_path, signer_path, expected in cases:
            with self.subTest(expected=expected):
                stderr = io.StringIO()
                arguments = [
                    str(TOOLS / "freeze_audit_inputs.py"),
                    "verify",
                    "--repo",
                    str(repo),
                    "--out",
                    str(manifest_path),
                    "--allowed-signers",
                    str(signer_path),
                ]
                with (
                    mock.patch.object(freeze, "RELEASE_INPUTS", release_inputs),
                    mock.patch.object(freeze, "EXPECTED_BASELINE_COMMIT", baseline),
                    mock.patch.object(freeze, "EXPECTED_BASELINE_TREE", baseline_tree),
                    mock.patch.object(sys, "argv", arguments),
                    contextlib.redirect_stderr(stderr),
                ):
                    result = freeze.main()
                self.assertEqual(result, 2)
                self.assertIn(expected, stderr.getvalue())
                self.assertNotIn("Traceback", stderr.getvalue())

    def test_frozen_input_generation_rejects_collisions_without_partial_outputs(
        self,
    ) -> None:
        fixture = self.make_frozen_input_fixture("generation-collision-freeze")
        repo = fixture["repo"]
        handoff = fixture["handoff"]
        release_inputs = fixture["release_inputs"]
        baseline = fixture["baseline"]
        baseline_tree = fixture["baseline_tree"]
        assert isinstance(repo, Path)
        assert isinstance(handoff, Path)
        assert isinstance(release_inputs, tuple)
        assert isinstance(baseline, str)
        assert isinstance(baseline_tree, str)

        output = self.root / "collision-manifest.json"
        allowed = self.root / "collision-allowed-signers"
        signature = output.with_name(output.name + ".sig")
        signature.write_text("pre-existing\n", encoding="ascii")
        with (
            mock.patch.object(freeze, "RELEASE_INPUTS", release_inputs),
            mock.patch.object(freeze, "EXPECTED_BASELINE_COMMIT", baseline),
            mock.patch.object(freeze, "EXPECTED_BASELINE_TREE", baseline_tree),
            self.assertRaisesRegex(ReviewError, "signature output already exists"),
        ):
            freeze.generate_frozen_inputs(repo, handoff, output, allowed)
        self.assertFalse(output.exists())
        self.assertFalse(allowed.exists())

        signature.unlink()
        with (
            mock.patch.object(freeze, "RELEASE_INPUTS", release_inputs),
            mock.patch.object(freeze, "EXPECTED_BASELINE_COMMIT", baseline),
            mock.patch.object(freeze, "EXPECTED_BASELINE_TREE", baseline_tree),
            mock.patch.object(
                freeze, "canonical_json", return_value=b"x" * (4 * 1024 * 1024 + 1)
            ),
            self.assertRaisesRegex(ReviewError, "generated.*exceeds 4 MiB"),
        ):
            freeze.generate_frozen_inputs(repo, handoff, output, allowed)
        self.assertFalse(output.exists())
        self.assertFalse(allowed.exists())

        with (
            mock.patch.object(freeze, "RELEASE_INPUTS", release_inputs),
            mock.patch.object(freeze, "EXPECTED_BASELINE_COMMIT", baseline),
            mock.patch.object(freeze, "EXPECTED_BASELINE_TREE", baseline_tree),
            mock.patch.object(
                freeze,
                "validate_allowed_signer",
                side_effect=ReviewError("injected signer validation failure"),
            ),
            self.assertRaisesRegex(ReviewError, "injected signer validation failure"),
        ):
            freeze.generate_frozen_inputs(repo, handoff, output, allowed)
        self.assertFalse(output.exists())
        self.assertFalse(allowed.exists())

        with self.assertRaisesRegex(ReviewError, "must be distinct"):
            freeze.generate_frozen_inputs(repo, handoff, output, signature)

    def test_frozen_input_verifier_rejects_oversize_before_reading(self) -> None:
        output = self.root / "oversize-frozen-inputs.json"
        output.write_bytes(b"x" * (freeze.MAX_MANIFEST_BYTES + 1))

        with (
            mock.patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("oversize manifest must not be read"),
            ),
            self.assertRaisesRegex(ReviewError, "exceeds the 4 MiB verification limit"),
        ):
            freeze.verify_frozen_inputs(
                self.root,
                None,
                output,
                self.root / "unused-allowed-signers",
            )

    def test_candidate_qualifier_refuses_output_inside_subject_repository(self) -> None:
        process = run(
            str(TOOLS / "qualify_candidate.py"),
            "--repo",
            ".",
            "--expected",
            self.head,
            "--out",
            "audit/qualification",
            "--signing-key",
            str(self.root.parent / "external-signing-key.pub"),
            "--allowed-signers",
            str(self.root.parent / "external-allowed-signers"),
            "--advisory-db",
            str(self.root.parent / "external-advisory-db"),
            "--skip-evidence",
            cwd=self.root,
            expected=2,
        )

        self.assertIn("outside --repo", process.stderr)

    def test_candidate_qualifier_refuses_a_dangling_output_symlink(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.root.parent) as directory:
            external = Path(directory)
            output = external / "qualification"
            output.symlink_to(external / "missing-target")

            process = run(
                str(TOOLS / "qualify_candidate.py"),
                "--repo",
                ".",
                "--expected",
                self.head,
                "--out",
                str(output),
                "--signing-key",
                str(external / "signing-key.pub"),
                "--allowed-signers",
                str(external / "allowed-signers"),
                "--advisory-db",
                str(external / "advisory-db"),
                "--skip-evidence",
                cwd=self.root,
                expected=2,
            )

            self.assertIn("new directory outside --repo", process.stderr)
            self.assertTrue(output.is_symlink())

    def test_mutation_assembler_refuses_a_dangling_output_symlink(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.root.parent) as directory:
            external = Path(directory)
            output = external / "mutation-evidence"
            output.symlink_to(external / "missing-target")
            arguments = [
                str(TOOLS / "prepare_mutation_evidence.py"),
                "--repo",
                ".",
                "--candidate",
                self.head,
                "--out",
                str(output),
                "--signing-key",
                str(external / "signing-key.pub"),
                "--allowed-signers",
                str(external / "allowed-signers"),
            ]
            for shard in ("0/4", "1/4", "2/4", "3/4"):
                arguments.extend(("--shard", f"{shard}={external / shard}"))

            process = run(*arguments, cwd=self.root, expected=2)

            self.assertIn("new directory outside --repo", process.stderr)
            self.assertTrue(output.is_symlink())

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
        self.assertTrue(
            all(row["reviewer"].startswith("Sepehr Mahmoudian") for row in rows)
        )
        self.assertTrue(all(row["generated"] == "NO" for row in rows))
        self.assertEqual(manifest["tracked_files"], 2)
        self.assertTrue(all(item["review_scope"] for item in manifest["files"]))
        self.assertEqual({item["path"] for item in findings}, {"README.md"})

    def test_claim_scan_and_three_lane_packet_generation_are_deterministic(
        self,
    ) -> None:
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
                (
                    self.root / f"audit/generated/review-packets/lane-{lane}.json"
                ).read_text()
            )
            for lane in range(1, 4)
        ]
        claims = json.loads(
            (self.root / "audit/generated/CLAIM_LANGUAGE.json").read_text()
        )

        self.assertEqual(sum(len(packet["files"]) for packet in packets), 2)
        self.assertTrue(
            all(packet["human_review_claimed"] is False for packet in packets)
        )
        self.assertTrue(
            all(
                file["reviewer"].startswith("Sepehr Mahmoudian")
                for packet in packets
                for file in packet["files"]
            )
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

        manifest.write_text(
            '{"schema":"a","schema":"b","artifacts":[]}', encoding="utf-8"
        )
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
            json.dumps({"schema": "galadriel.evidence-manifest.v1", "artifacts": []}),
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

        with self.assertRaisesRegex(
            ReviewError, "public API snapshot drifted"
        ) as raised:
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

    def test_handoff_inventory_records_file_and_directory_symlinks_without_following(
        self,
    ) -> None:
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

    def test_handoff_inventory_rejects_walk_errors_and_symlink_root(self) -> None:
        root = self.root / "handoff-walk-errors"
        root.mkdir()

        def denied_walk(*_args: object, **kwargs: object) -> object:
            onerror = kwargs["onerror"]
            assert callable(onerror)
            onerror(PermissionError(13, "Permission denied", str(root / "blocked")))
            return ()

        with (
            mock.patch.object(freeze.os, "walk", side_effect=denied_walk),
            self.assertRaisesRegex(ReviewError, "cannot completely inventory"),
        ):
            strict_relative_files(root)

        link = self.root / "handoff-root-link"
        link.symlink_to(root, target_is_directory=True)
        with self.assertRaisesRegex(ReviewError, "not a regular directory"):
            strict_relative_files(link)

    def test_handoff_inventory_rejects_non_utf8_symlink_targets(self) -> None:
        handoff = self.root / "non-utf8-handoff"
        handoff.mkdir()
        os.symlink(b"\xff-target", os.fsencode(handoff / "link"))

        with self.assertRaisesRegex(ReviewError, "target is not valid UTF-8"):
            strict_relative_files(handoff)

    def test_handoff_inventory_enforces_early_and_streaming_resource_bounds(
        self,
    ) -> None:
        entry_root = self.root / "entry-bound-handoff"
        entry_root.mkdir()
        for index in range(3):
            (entry_root / f"{index}.txt").write_bytes(b"x")
        with (
            mock.patch.object(freeze, "MAX_HANDOFF_ENTRIES", 2),
            mock.patch.object(
                freeze,
                "digest_bounded_handoff_file",
                side_effect=AssertionError("entries must be bounded before hashing"),
            ),
            self.assertRaisesRegex(ReviewError, "entry-count limit"),
        ):
            strict_relative_files(entry_root)

        file_root = self.root / "file-bound-handoff"
        file_root.mkdir()
        (file_root / "large.bin").write_bytes(b"12345")
        with (
            mock.patch.object(freeze, "MAX_HANDOFF_FILE_BYTES", 4),
            self.assertRaisesRegex(ReviewError, "per-file byte limit"),
        ):
            strict_relative_files(file_root)

        symlink_root = self.root / "symlink-bound-handoff"
        symlink_root.mkdir()
        (symlink_root / "link").symlink_to("12345")
        with (
            mock.patch.object(freeze, "MAX_HANDOFF_SYMLINK_BYTES", 4),
            self.assertRaisesRegex(ReviewError, "symlink target exceeds"),
        ):
            strict_relative_files(symlink_root)

        aggregate_root = self.root / "aggregate-bound-handoff"
        aggregate_root.mkdir()
        (aggregate_root / "a.bin").write_bytes(b"123")
        (aggregate_root / "b.bin").write_bytes(b"456")
        with (
            mock.patch.object(freeze, "MAX_HANDOFF_FILE_BYTES", 4),
            mock.patch.object(freeze, "MAX_HANDOFF_AGGREGATE_BYTES", 5),
            self.assertRaisesRegex(ReviewError, "aggregate byte limit"),
        ):
            strict_relative_files(aggregate_root)

        growing = self.root / "growing-handoff-file"
        growing.write_bytes(b"1234")
        real_fstat = freeze.os.fstat

        def grow_after_metadata(descriptor: int) -> os.stat_result:
            metadata = real_fstat(descriptor)
            with growing.open("ab") as handle:
                handle.write(b"5")
            return metadata

        with (
            mock.patch.object(freeze, "MAX_HANDOFF_FILE_BYTES", 4),
            mock.patch.object(freeze.os, "fstat", side_effect=grow_after_metadata),
            self.assertRaisesRegex(ReviewError, "per-file byte limit"),
        ):
            freeze.digest_bounded_handoff_file(growing, growing.name, 0)

        stable_size = self.root / "same-size-handoff-file"
        stable_size.write_bytes(b"1234")
        fstat_calls = 0

        def mutate_same_size(descriptor: int) -> os.stat_result:
            nonlocal fstat_calls
            fstat_calls += 1
            if fstat_calls == 2:
                stable_size.write_bytes(b"5678")
            return real_fstat(descriptor)

        with (
            mock.patch.object(freeze.os, "fstat", side_effect=mutate_same_size),
            self.assertRaisesRegex(ReviewError, "changed while read"),
        ):
            freeze.digest_bounded_handoff_file(stable_size, stable_size.name, 0)

    def test_handoff_manifest_rows_reject_declared_resource_overflow(self) -> None:
        regular = {
            "path": "large.bin",
            "kind": "regular",
            "sha256": "0" * 64,
            "size_bytes": 5,
        }
        with (
            mock.patch.object(freeze, "MAX_HANDOFF_FILE_BYTES", 4),
            self.assertRaisesRegex(ReviewError, "regular-file byte limit"),
        ):
            freeze.validate_handoff_rows([regular])

        with (
            mock.patch.object(freeze, "MAX_HANDOFF_ENTRIES", 1),
            self.assertRaisesRegex(ReviewError, "entry-count limit"),
        ):
            freeze.validate_handoff_rows([regular, {**regular, "path": "another.bin"}])


if __name__ == "__main__":
    unittest.main()
