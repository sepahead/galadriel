"""Focused tests for qualification-record finalization boundaries."""

from __future__ import annotations

import copy
import hashlib
import os
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1]
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))

from common import (  # noqa: E402
    SAFE_GIT_CONFIGURATION,
    ReviewError,
    canonical_json,
)
from finalize_release import (  # noqa: E402
    EMPTY_SHA256,
    EXPECTED_ADVISORY_WARNINGS,
    EXPECTED_GIT_PACKAGE_SOURCES,
    EXPECTED_RELEASE_CRATES,
    EXPECTED_TOOL_FILE_IDENTITIES,
    EXPECTED_TOOL_FILE_NAMES,
    MAX_QUALIFICATION_LOG_HEADER_BYTES,
    RUSTSEC_ADVISORY_DATABASE,
    TOOL_FILE_BASENAMES,
    _dynamic_qualification_specs,
    candidate_source_date_epoch,
    candidate_crate_files,
    cleanup_finalization_inputs,
    read_qualification_auxiliary_log,
    read_qualification_command_log,
    read_qualification_log_header,
    validate_advisory_database,
    validate_cargo_metadata_bindings,
    validate_command_receipt_trailer,
    validate_package_patch_receipts,
    validate_qualification_environment,
    validate_qualification_record,
    validate_qualification_sandbox,
    validate_qualification_tool_bindings,
    validate_qualification_tool_files,
    validate_receipt_timing,
    validate_recomputed_acceptance_binding,
    validate_repository_control,
    validate_supply_chain_report_records,
    validate_vulnerability_report,
)
from qualify_candidate import (  # noqa: E402
    AuxiliaryRunner,
    BoundedProcessResult,
    QUALIFICATION_PATH_TOOLS,
    MacOSProcessContainment,
    execution_policy_contract,
    qualification_environment_contract,
    render_candidate_sandbox_profile,
    run_bounded_process,
    sandboxed_argv,
    write_candidate_sandbox_profile,
)


COMMIT = "a" * 40
TREE = "b" * 40


def test_tool_read_root() -> Path:
    """Return a stable read root for the active Python executable."""

    executable = Path(sys.executable).resolve()
    parts = executable.parts
    if len(parts) >= 3 and parts[:2] == ("/", "opt"):
        return Path("/", "opt", parts[2])
    if len(parts) >= 3 and parts[:3] == ("/", "usr", "local"):
        return Path("/usr/local")
    return executable.parent


def repository_snapshot() -> dict[str, str]:
    return {
        "head": COMMIT,
        "tree": TREE,
        "status_sha256": EMPTY_SHA256,
        "refs_sha256": "c" * 64,
        "local_config_sha256": "d" * 64,
    }


def advisory_repository_snapshot() -> dict[str, str]:
    snapshot = repository_snapshot()
    snapshot["head"] = RUSTSEC_ADVISORY_DATABASE["commit"]
    snapshot["tree"] = RUSTSEC_ADVISORY_DATABASE["tree"]
    return snapshot


def vulnerability_warning(
    advisory_id: str, package_name: str, package_version: str
) -> dict[str, object]:
    return {
        "kind": "unmaintained",
        "package": {"name": package_name, "version": package_version},
        "advisory": {
            "id": advisory_id,
            "package": package_name,
            "informational": "unmaintained",
        },
        "affected": None,
        "versions": {"patched": [], "unaffected": []},
    }


def vulnerability_report() -> dict[str, object]:
    return {
        "database": {
            "advisory-count": 1166,
            "last-commit": None,
            "last-updated": None,
        },
        "lockfile": {"dependency-count": 437},
        "settings": {
            "target_arch": [],
            "target_os": [],
            "severity": None,
            "ignore": ["RUSTSEC-2026-0041"],
            "informational_warnings": ["unmaintained", "unsound", "notice"],
        },
        "vulnerabilities": {"found": False, "count": 0, "list": []},
        "warnings": {
            "unmaintained": [
                vulnerability_warning(*identity)
                for identity in EXPECTED_ADVISORY_WARNINGS
            ]
        },
    }


def tool_file_record(name: str) -> dict[str, object]:
    path = (
        Path("/usr/bin/sandbox-exec")
        if name == "sandbox-exec"
        else Path("/fixture/tools") / name / TOOL_FILE_BASENAMES[name]
    )
    sha256, size_bytes = EXPECTED_TOOL_FILE_IDENTITIES[name]
    return {
        "invoked_path": str(path),
        "resolved_path": str(path),
        "sha256": sha256,
        "size_bytes": size_bytes,
        "uid": 501,
        "gid": 20,
        "mode": 0o755,
    }


class FinalizeQualificationTest(unittest.TestCase):
    def test_candidate_timestamp_disables_signature_display(self) -> None:
        with patch("finalize_release.git", return_value="1753225600\n") as git_run:
            self.assertEqual(
                candidate_source_date_epoch(Path("/candidate"), COMMIT),
                1_753_225_600,
            )
        git_run.assert_called_once_with(
            Path("/candidate"),
            "-c",
            "log.showSignature=false",
            "show",
            "-s",
            "--format=%ct",
            COMMIT,
        )

    def test_auxiliary_command_created_cargo_configuration_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cwd = root / "worktree"
            cargo_home = root / "cargo-home"
            logs = root / "logs"
            for path in (cwd, cargo_home, logs):
                path.mkdir()
            sandbox_profile = root / "candidate.sb"
            sandbox_profile.write_text("(version 1)\n", encoding="utf-8")
            receipts: list[dict[str, object]] = []
            runner = AuxiliaryRunner(
                environment={"CARGO_HOME": str(cargo_home)},
                sandbox_profile=sandbox_profile,
                logs=logs,
                receipts=receipts,
            )

            def create_configuration(*_args: object, **_kwargs: object):
                cargo_directory = cwd / ".cargo"
                cargo_directory.mkdir()
                (cargo_directory / "config.toml").write_text(
                    "[build]\ntarget-dir = 'other'\n",
                    encoding="utf-8",
                )
                return BoundedProcessResult(0, False, b"", b"", False, None)

            with (
                patch(
                    "qualify_candidate.run_bounded_process",
                    side_effect=create_configuration,
                ),
                self.assertRaisesRegex(
                    ReviewError,
                    "artifact-generation policy failed.*Cargo configuration",
                ),
            ):
                runner.run(
                    "configuration-fixture",
                    ["fixture-tool"],
                    cwd=cwd,
                )
            self.assertEqual(len(receipts), 1)
            self.assertEqual(receipts[0]["status"], "FAIL")

    def test_process_group_permission_failure_is_fail_closed(self) -> None:
        with patch(
            "qualify_candidate.os.killpg",
            side_effect=PermissionError("fixture"),
        ):
            with self.assertRaisesRegex(ReviewError, "permission denied"):
                MacOSProcessContainment._signal_group(12_345, signal.SIGTERM)

    def test_cleanup_invalidates_pass_record_before_tree_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "inputs"
            record = root / "qualification" / "qualification.json"
            record.parent.mkdir(parents=True)
            record.write_bytes(canonical_json({"status": "PASS"}))

            def fail_cleanup() -> None:
                raise OSError("fixture cleanup failure")

            temporary = SimpleNamespace(name=str(root), cleanup=fail_cleanup)
            with patch("finalize_release.warn_cleanup_failure"):
                self.assertFalse(cleanup_finalization_inputs(temporary, None))
            self.assertFalse(record.exists())

    @unittest.skipUnless(sys.platform == "darwin", "macOS sandbox test")
    def test_candidate_sandbox_denies_unrelated_file_reads(self) -> None:
        source = """
import pathlib
import sys

try:
    pathlib.Path(sys.argv[1]).read_bytes()
except PermissionError:
    pass
else:
    raise SystemExit(42)
try:
    list(pathlib.Path(sys.argv[2]).iterdir())
except PermissionError:
    raise SystemExit(0)
raise SystemExit(43)
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            worktree = root / "worktree"
            writable = root / "writable"
            worktree.mkdir()
            writable.mkdir()
            unrelated = root.parent / f"{root.name}-unrelated"
            unrelated.mkdir()
            unrelated_file = unrelated / "private.txt"
            unrelated_file.write_bytes(b"not candidate input\n")
            profile = root / "candidate.sb"
            try:
                write_candidate_sandbox_profile(
                    profile,
                    worktree=worktree,
                    source_repo=ROOT,
                    writable_paths=(writable,),
                    tool_read_paths=(test_tool_read_root(),),
                )
                result = run_bounded_process(
                    sandboxed_argv(
                        profile,
                        [
                            sys.executable,
                            "-I",
                            "-c",
                            source,
                            str(unrelated_file),
                            str(unrelated),
                        ],
                    ),
                    cwd=writable,
                    environment={"PATH": os.environ["PATH"]},
                    timeout_seconds=2,
                    separate_stderr=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIsNone(result.containment_error)
                self.assertFalse(result.output_limit_exceeded)
            finally:
                unrelated_file.unlink(missing_ok=True)
                unrelated.rmdir()

    @unittest.skipUnless(sys.platform == "darwin", "macOS sandbox test")
    def test_candidate_sandbox_denies_advisory_source_and_reads_installed_database(
        self,
    ) -> None:
        source = """
import pathlib
import sys

if pathlib.Path(sys.argv[1]).read_bytes() != b"installed database\\n":
    raise SystemExit(41)
try:
    pathlib.Path(sys.argv[2]).read_bytes()
except PermissionError:
    raise SystemExit(0)
raise SystemExit(42)
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            worktree = root / "worktree"
            writable = root / "writable"
            advisory_source = root / "advisory-source"
            installed_database = root / "cargo-home" / "advisory-db"
            worktree.mkdir()
            writable.mkdir()
            advisory_source.mkdir()
            installed_database.mkdir(parents=True)
            source_file = advisory_source / "config"
            database_file = installed_database / "advisory"
            source_file.write_bytes(b"host-only source\n")
            database_file.write_bytes(b"installed database\n")
            profile = root / "candidate.sb"
            write_candidate_sandbox_profile(
                profile,
                worktree=worktree,
                source_repo=ROOT,
                read_only_paths=(installed_database,),
                writable_paths=(writable,),
                tool_read_paths=(test_tool_read_root(),),
                denied_read_paths=(advisory_source,),
            )
            result = run_bounded_process(
                sandboxed_argv(
                    profile,
                    [
                        sys.executable,
                        "-I",
                        "-c",
                        source,
                        str(database_file),
                        str(source_file),
                    ],
                ),
                cwd=writable,
                environment={"PATH": os.environ["PATH"]},
                timeout_seconds=2,
                separate_stderr=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIsNone(result.containment_error)
            self.assertFalse(result.output_limit_exceeded)

    @unittest.skipUnless(sys.platform == "darwin", "macOS sandbox test")
    def test_candidate_sandbox_probe_stays_exact_inside_readable_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            profile = root / "candidate.sb"
            write_candidate_sandbox_profile(
                profile,
                worktree=root,
                source_repo=ROOT,
                tool_read_paths=(test_tool_read_root(),),
            )
            result = run_bounded_process(
                sandboxed_argv(
                    profile,
                    [sys.executable, "-I", "-c", "print('armed')"],
                ),
                cwd=root,
                environment={"PATH": os.environ["PATH"]},
                timeout_seconds=2,
                separate_stderr=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"armed\n")
            self.assertIsNone(result.containment_error)
            self.assertFalse(result.output_limit_exceeded)

    @unittest.skipUnless(sys.platform == "darwin", "macOS containment test")
    def test_double_fork_pipe_escape_is_bounded_and_observational(self) -> None:
        source = """
import os
import pathlib
import sys
import time

child = os.fork()
if child:
    os.waitpid(child, 0)
    raise SystemExit(0)
os.setsid()
grandchild = os.fork()
if grandchild:
    os._exit(0)
pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding="ascii")
os.close(0)
os.close(1)
os.close(2)
time.sleep(20)
"""
        escaped_pid: int | None = None
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            worktree = root / "worktree"
            writable = root / "writable"
            worktree.mkdir()
            writable.mkdir()
            pid_file = writable / "escaped.pid"
            profile = root / "candidate.sb"
            write_candidate_sandbox_profile(
                profile,
                worktree=worktree,
                source_repo=ROOT,
                writable_paths=(writable,),
                tool_read_paths=(test_tool_read_root(),),
            )
            try:
                started = time.monotonic()
                result = run_bounded_process(
                    sandboxed_argv(
                        profile,
                        [sys.executable, "-I", "-c", source, str(pid_file)],
                    ),
                    cwd=writable,
                    environment={"PATH": os.environ["PATH"]},
                    timeout_seconds=2,
                    separate_stderr=True,
                )
                elapsed = time.monotonic() - started
                self.assertLess(elapsed, 10.0)
                self.assertFalse(result.output_limit_exceeded)
                if pid_file.exists():
                    escaped_pid = int(pid_file.read_text(encoding="ascii"))
                escaped_is_live = False
                if escaped_pid is not None:
                    try:
                        os.kill(escaped_pid, 0)
                    except ProcessLookupError:
                        pass
                    else:
                        escaped_is_live = True
                self.assertFalse(escaped_is_live)
                self.assertIsNotNone(
                    result.containment_error,
                    (
                        result.returncode,
                        result.stderr,
                        pid_file.exists(),
                    ),
                )
            finally:
                if escaped_pid is None and pid_file.exists():
                    escaped_pid = int(pid_file.read_text(encoding="ascii"))
                if escaped_pid is not None:
                    try:
                        os.kill(escaped_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    @unittest.skipUnless(sys.platform == "darwin", "macOS containment test")
    def test_interrupt_cleans_and_reaps_candidate_process(self) -> None:
        source = """
import pathlib
import os
import sys
import time

pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding="ascii")
time.sleep(20)
"""
        candidate_pid: int | None = None
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            worktree = root / "worktree"
            writable = root / "writable"
            worktree.mkdir()
            writable.mkdir()
            pid_file = writable / "candidate.pid"
            profile = root / "candidate.sb"
            write_candidate_sandbox_profile(
                profile,
                worktree=worktree,
                source_repo=ROOT,
                writable_paths=(writable,),
                tool_read_paths=(test_tool_read_root(),),
            )

            def interrupt_after_start(_timeout: float) -> list[object]:
                time.sleep(0.1)
                raise KeyboardInterrupt

            try:
                with (
                    patch(
                        "qualify_candidate.selectors.DefaultSelector.select",
                        side_effect=interrupt_after_start,
                    ),
                    self.assertRaises(KeyboardInterrupt),
                ):
                    run_bounded_process(
                        sandboxed_argv(
                            profile,
                            [sys.executable, "-I", "-c", source, str(pid_file)],
                        ),
                        cwd=writable,
                        environment={"PATH": os.environ["PATH"]},
                        timeout_seconds=2,
                        separate_stderr=True,
                    )
                if pid_file.exists():
                    candidate_pid = int(pid_file.read_text(encoding="ascii"))
                if candidate_pid is not None:
                    with self.assertRaises(ProcessLookupError):
                        os.kill(candidate_pid, 0)
            finally:
                if candidate_pid is None and pid_file.exists():
                    candidate_pid = int(pid_file.read_text(encoding="ascii"))
                if candidate_pid is not None:
                    try:
                        os.kill(candidate_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_candidate_crate_files_bind_exact_git_blobs_and_modes(self) -> None:
        manifest_object = "1" * 40
        source_object = "2" * 40
        tree = (
            f"100644 blob {manifest_object}\t"
            "crates/galadriel-core/Cargo.toml\0"
            f"100755 blob {source_object}\t"
            "crates/galadriel-core/src/tool.rs\0"
        ).encode()

        def bounded_git(
            _repo: Path,
            *arguments: str,
            max_bytes: int,
        ) -> bytes:
            self.assertGreater(max_bytes, 0)
            if arguments[0] == "ls-tree":
                return tree
            if arguments == ("cat-file", "blob", manifest_object):
                return b'[package]\nname = "galadriel-core"\n'
            if arguments == ("cat-file", "blob", source_object):
                return b"fn main() {}\n"
            self.fail(f"unexpected Git arguments: {arguments}")

        with patch(
            "finalize_release.git_bounded_output",
            side_effect=bounded_git,
        ):
            self.assertEqual(
                candidate_crate_files(
                    Path("/fixture/repo"),
                    COMMIT,
                    "galadriel-core",
                ),
                {
                    "Cargo.toml.orig": (
                        0o644,
                        b'[package]\nname = "galadriel-core"\n',
                    ),
                    "src/tool.rs": (0o755, b"fn main() {}\n"),
                },
            )

    def test_cargo_metadata_paths_bind_standalone_clone_and_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private_root = Path(directory) / "private"
            worktree = private_root / "worktree"
            target = private_root / "target"
            cargo_home = private_root / "cargo-home"
            packages = (
                SimpleNamespace(
                    name="galadriel-core",
                    version="0.9.0",
                    source=None,
                    workspace=True,
                    manifest_path=str(
                        worktree / "crates" / "galadriel-core" / "Cargo.toml"
                    ),
                    target_components=(
                        SimpleNamespace(
                            source_path=str(
                                worktree
                                / "crates"
                                / "galadriel-core"
                                / "src"
                                / "lib.rs"
                            )
                        ),
                    ),
                ),
                SimpleNamespace(
                    name="serde",
                    version="1.0.228",
                    source=("registry+https://github.com/rust-lang/crates.io-index"),
                    workspace=False,
                    manifest_path=str(
                        cargo_home
                        / "registry"
                        / "src"
                        / "index.crates.io-1949cf8c6b5b557f"
                        / "serde-1.0.228"
                        / "Cargo.toml"
                    ),
                    target_components=(
                        SimpleNamespace(
                            source_path=str(
                                cargo_home
                                / "registry"
                                / "src"
                                / "index.crates.io-1949cf8c6b5b557f"
                                / "serde-1.0.228"
                                / "src"
                                / "lib.rs"
                            )
                        ),
                    ),
                ),
                SimpleNamespace(
                    name="ncp",
                    version="0.8.0",
                    source=(
                        "git+https://github.com/sepahead/ncp"
                        "?rev=2f5bd586d4bb20c90362bb6f5698b7f64057ba4e"
                        "#2f5bd586d4bb20c90362bb6f5698b7f64057ba4e"
                    ),
                    workspace=False,
                    manifest_path=str(
                        cargo_home
                        / "git"
                        / "checkouts"
                        / "ncp-0123456789abcdef"
                        / "2f5bd58"
                        / "crates"
                        / "ncp"
                        / "Cargo.toml"
                    ),
                    target_components=(
                        SimpleNamespace(
                            source_path=str(
                                cargo_home
                                / "git"
                                / "checkouts"
                                / "ncp-0123456789abcdef"
                                / "2f5bd58"
                                / "crates"
                                / "ncp"
                                / "src"
                                / "lib.rs"
                            )
                        ),
                    ),
                ),
            )
            qualification = {
                "sandbox": {
                    "bindings": {
                        "candidate_worktree": str(worktree),
                        "cargo_home": str(cargo_home),
                        "cargo_target_directory": str(target),
                    }
                }
            }
            graph = SimpleNamespace(
                workspace_root=str(worktree),
                target_directory=str(target),
                packages=packages,
            )
            validate_cargo_metadata_bindings(qualification, graph)

            for field, value in (
                ("workspace_root", str(private_root / "forged-worktree")),
                ("target_directory", str(private_root / "forged-target")),
            ):
                forged = SimpleNamespace(
                    workspace_root=(
                        value if field == "workspace_root" else graph.workspace_root
                    ),
                    target_directory=(
                        value if field == "target_directory" else graph.target_directory
                    ),
                    packages=packages,
                )
                with (
                    self.subTest(field=field),
                    self.assertRaisesRegex(ReviewError, "another qualification"),
                ):
                    validate_cargo_metadata_bindings(qualification, forged)

            escaped_target = copy.deepcopy(graph)
            escaped_target.packages[0].target_components = (
                SimpleNamespace(source_path=str(private_root / "foreign.rs")),
            )
            with self.assertRaisesRegex(ReviewError, "target escapes"):
                validate_cargo_metadata_bindings(qualification, escaped_target)

            escaped_cache = copy.deepcopy(graph)
            escaped_cache.packages[1].manifest_path = str(
                private_root / "foreign-cache" / "serde-1.0.228" / "Cargo.toml"
            )
            with self.assertRaisesRegex(ReviewError, "registry manifest escapes"):
                validate_cargo_metadata_bindings(qualification, escaped_cache)

    def test_command_log_header_read_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "command.log"
            path.write_bytes(b"{}\n--- combined stdout/stderr ---\noutput\n")
            self.assertEqual(read_qualification_log_header(path), b"{}\n")

            path.write_bytes(b"x" * (MAX_QUALIFICATION_LOG_HEADER_BYTES + 1))
            with self.assertRaisesRegex(ReviewError, "bounded JSON header"):
                read_qualification_log_header(path)

    def test_receipt_timing_is_canonical_ordered_and_consistent(self) -> None:
        receipt = {
            "started_at": "2026-07-23T10:00:00.000+00:00",
            "finished_at": "2026-07-23T10:00:01.250+00:00",
            "duration_seconds": 1.25,
            "timeout_seconds": 3_600,
        }
        validate_receipt_timing(receipt, "fixture")

        noncanonical = copy.deepcopy(receipt)
        noncanonical["started_at"] = "2026-07-23T10:00:00Z"
        with self.assertRaisesRegex(ReviewError, "canonical UTC"):
            validate_receipt_timing(noncanonical, "fixture")

        reversed_times = copy.deepcopy(receipt)
        reversed_times["finished_at"] = "2026-07-23T09:59:59.000+00:00"
        with self.assertRaisesRegex(ReviewError, "inconsistent"):
            validate_receipt_timing(reversed_times, "fixture")

        inconsistent = copy.deepcopy(receipt)
        inconsistent["duration_seconds"] = 30.0
        with self.assertRaisesRegex(ReviewError, "inconsistent"):
            validate_receipt_timing(inconsistent, "fixture")

    def test_auxiliary_log_streams_are_exactly_framed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "auxiliary.log"
            stdout = b"first\n--- stderr ---\nsecond"
            stderr = b"diagnostic\n"
            trailer = canonical_json({"fixture": True})
            path.write_bytes(
                b"{}\n--- stdout ---\n"
                + stdout
                + b"\n--- stderr ---\n"
                + stderr
                + b"\n--- receipt trailer ---\n"
                + trailer
            )
            self.assertEqual(
                read_qualification_auxiliary_log(
                    path,
                    stdout_size=len(stdout),
                    stderr_size=len(stderr),
                ),
                (b"{}\n", stdout, stderr, trailer),
            )

            with self.assertRaisesRegex(ReviewError, "framing is invalid"):
                read_qualification_auxiliary_log(
                    path,
                    stdout_size=len(stdout) - 1,
                    stderr_size=len(stderr),
                )

            link = root / "link.log"
            link.symlink_to(path)
            with self.assertRaisesRegex(ReviewError, "missing"):
                read_qualification_auxiliary_log(
                    link,
                    stdout_size=len(stdout),
                    stderr_size=len(stderr),
                )

    def test_command_log_output_and_receipt_trailer_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "command.log"
            output = b"command output\n"
            result = {
                "name": "fixture",
                "argv": ["fixture"],
                "cwd": ".",
                "environment_overrides": {},
                "sandbox": {"network_policy": "DENY"},
                "started_at": "2026-07-23T10:00:00.000+00:00",
                "finished_at": "2026-07-23T10:00:00.100+00:00",
                "duration_seconds": 0.1,
                "timeout_seconds": 60,
                "timed_out": False,
                "exit_code": 0,
                "status": "PASS",
                "log": "logs/fixture.log",
                "log_sha256": "a" * 64,
                "log_size_bytes": 1,
                "combined_output_sha256": hashlib.sha256(output).hexdigest(),
                "combined_output_size_bytes": len(output),
            }
            embedded = {
                key: value
                for key, value in result.items()
                if key not in {"log_sha256", "log_size_bytes"}
            }
            trailer = canonical_json(
                {
                    "schema": "galadriel.command-receipt-trailer.v1",
                    "receipt": embedded,
                }
            )
            path.write_bytes(
                b"{}\n--- combined stdout/stderr ---\n"
                + output
                + b"\n--- receipt trailer ---\n"
                + trailer
            )
            self.assertEqual(
                read_qualification_command_log(
                    path,
                    combined_output_size=len(output),
                ),
                (b"{}\n", output, trailer),
            )
            validate_command_receipt_trailer(trailer, result, "fixture")

            tampered = copy.deepcopy(result)
            tampered["duration_seconds"] = 0.2
            with self.assertRaisesRegex(ReviewError, "contradicts"):
                validate_command_receipt_trailer(trailer, tampered, "fixture")

    def test_acceptance_must_equal_independent_metric_recomputation(self) -> None:
        criteria = [
            {
                "id": f"GLD-090-ACC-{number:03d}",
                "rule": "fixture rule",
                "status": "PASS",
                "observations": [
                    {
                        "metric": "fixture_metric",
                        "value": 0.0,
                        "threshold": 1.0,
                        "status": "PASS",
                    }
                ],
                "evaluation_error": None,
            }
            for number in range(1, 8)
        ]
        recomputed = {
            "schema": "galadriel.candidate-acceptance.v1",
            "release": "0.9.0",
            "partition": "holdout_results",
            "minimum_metric_eligible_tracks": 20,
            "status": "PASS",
            "failed_criterion_ids": [],
            "criteria": criteria,
        }
        qualification = {
            "acceptance": {
                "path": "candidate-acceptance.json",
                "status": "PASS",
                "failed_criterion_ids": [],
            }
        }
        validate_recomputed_acceptance_binding(
            qualification,
            canonical_json(recomputed),
            recomputed,
        )

        forged = copy.deepcopy(recomputed)
        for criterion in forged["criteria"]:
            criterion["observations"] = [{"status": "PASS"}]
        with self.assertRaisesRegex(
            ReviewError,
            "independent evidence recomputation",
        ):
            validate_recomputed_acceptance_binding(
                qualification,
                canonical_json(forged),
                recomputed,
            )

        wrong_summary = copy.deepcopy(qualification)
        wrong_summary["acceptance"]["failed_criterion_ids"] = ["GLD-090-ACC-001"]
        with self.assertRaisesRegex(ReviewError, "summary differs"):
            validate_recomputed_acceptance_binding(
                wrong_summary,
                canonical_json(recomputed),
                recomputed,
            )

    def test_package_patch_receipts_require_every_exact_git_pair(self) -> None:
        cargo_home = Path("/fixture/cargo-home")
        reproducibility_root = Path("/fixture/reproducibility")
        qualification = {
            "sandbox": {
                "bindings": {
                    "cargo_home": str(cargo_home),
                    "reproducibility_root": str(reproducibility_root),
                }
            }
        }
        packages = []
        for name, source in EXPECTED_GIT_PACKAGE_SOURCES.items():
            repository = "NCP" if name.startswith("ncp-") else "pid-rs"
            packages.append(
                SimpleNamespace(
                    name=name,
                    source=source,
                    manifest_path=str(
                        cargo_home
                        / "git"
                        / "checkouts"
                        / repository
                        / "revision"
                        / "crates"
                        / name
                        / "Cargo.toml"
                    ),
                )
            )
        cargo_graph = SimpleNamespace(packages=tuple(packages))
        receipts = {}
        for run_index in (1, 2):
            worktree = reproducibility_root / f"package-worktree-{run_index}"
            target = reproducibility_root / f"package-run-{run_index}"
            for crate in EXPECTED_RELEASE_CRATES:
                argv = [
                    "cargo",
                    "package",
                    "-p",
                    crate,
                    "--locked",
                    "--offline",
                    "--no-verify",
                    "--exclude-lockfile",
                    "--target-dir",
                    str(target),
                ]
                configs = {
                    (
                        f"patch.crates-io.{dependency}.path="
                        f'"{worktree / "crates" / dependency}"'
                    )
                    for dependency in EXPECTED_RELEASE_CRATES
                    if dependency != crate
                }
                for package in packages:
                    source_url = package.source.removeprefix("git+").split("?", 1)[0]
                    package_path = Path(package.manifest_path).parent
                    configs.add(f'patch.crates-io.{package.name}.path="{package_path}"')
                    configs.add(
                        f'patch."{source_url}".{package.name}.path="{package_path}"'
                    )
                for config in sorted(configs):
                    argv.extend(["--config", config])
                name = f"cargo-package-run-{run_index}-{crate}"
                receipts[name] = {
                    "argv": argv,
                    "cwd": str(worktree),
                }

        validate_package_patch_receipts(
            qualification,
            receipts,
            cargo_graph,
        )

        omitted = copy.deepcopy(receipts)
        omitted_name = "cargo-package-run-1-galadriel-core"
        omitted[omitted_name]["argv"] = omitted[omitted_name]["argv"][:-2]
        with self.assertRaisesRegex(ReviewError, "patch set is not exact"):
            validate_package_patch_receipts(
                qualification,
                omitted,
                cargo_graph,
            )

        substituted_packages = list(packages)
        substituted_packages[0] = SimpleNamespace(
            name=substituted_packages[0].name,
            source=substituted_packages[0].source.replace("NCP", "other"),
            manifest_path=substituted_packages[0].manifest_path,
        )
        with self.assertRaisesRegex(ReviewError, "identity or path drifted"):
            validate_package_patch_receipts(
                qualification,
                receipts,
                SimpleNamespace(packages=tuple(substituted_packages)),
            )

    def test_qualification_record_requires_canonical_repository_identity(self) -> None:
        source_date_epoch = 1_753_225_600
        qualification = {
            "schema": "galadriel.candidate-qualification.v3",
            "release": "0.9.0",
            "author": "Sepehr Mahmoudian",
            "doi": None,
            "zenodo": None,
            "status": "PASS",
            "command_status": "PASS",
            "release_gate": "PASS",
            "candidate": {
                "repository": "https://github.com/sepahead/galadriel",
                "branch": "main",
                "commit": COMMIT,
                "tree": TREE,
                "source_date_epoch": source_date_epoch,
            },
            "host": {},
            "tools": {},
            "tool_files": {},
            "environment_contract": {},
            "repository_control": {},
            "sandbox": {},
            "advisory_database": {},
            "deep_campaigns_requested": True,
            "evidence_config": "evidence/galadriel-0.9-candidate.json",
            "commands": [],
            "auxiliary_commands": [],
            "acceptance": {},
            "evidence_config_binding": {
                "tracked_path": "evidence/galadriel-0.9-candidate.json",
                "study_design_status": "PASS",
                "tracked_blob_sha256": "c" * 64,
                "accepted_semantic_digest": "d" * 64,
            },
            "source_archive": {},
            "cargo_metadata": {},
            "packages": [],
            "sboms": [],
            "license_inventory": {},
            "license_report": {},
            "vulnerability_report": {},
            "reproducibility": {},
            "mutation_evidence": {
                "status": "PASS",
                "candidate": {"commit": COMMIT, "tree": TREE},
                "shards": 4,
            },
            "limitations": "This record has component and source scope.",
        }
        validate_qualification_record(
            qualification,
            commit=COMMIT,
            tree=TREE,
            source_date_epoch=source_date_epoch,
            expected_evidence_config_sha256="c" * 64,
        )

        other = copy.deepcopy(qualification)
        other["candidate"]["repository"] = "https://example.invalid/galadriel"
        with self.assertRaisesRegex(ReviewError, "wrong candidate"):
            validate_qualification_record(
                other,
                commit=COMMIT,
                tree=TREE,
                source_date_epoch=source_date_epoch,
                expected_evidence_config_sha256="c" * 64,
            )

    def test_repository_control_requires_equal_clean_snapshots(self) -> None:
        snapshot = repository_snapshot()
        advisory_snapshot = advisory_repository_snapshot()
        qualification = {
            "repository_control": {
                "status": "UNCHANGED",
                "origin_main": COMMIT,
                "source_before": copy.deepcopy(snapshot),
                "source_after": copy.deepcopy(snapshot),
                "standalone_clone_before": copy.deepcopy(snapshot),
                "standalone_clone_after": copy.deepcopy(snapshot),
                "advisory_source_before": copy.deepcopy(advisory_snapshot),
                "advisory_source_after": copy.deepcopy(advisory_snapshot),
            }
        }
        validate_repository_control(qualification, commit=COMMIT, tree=TREE)

        wrong_origin = copy.deepcopy(qualification)
        wrong_origin["repository_control"]["origin_main"] = "f" * 40
        with self.assertRaisesRegex(ReviewError, "origin/main differs"):
            validate_repository_control(wrong_origin, commit=COMMIT, tree=TREE)

        changed = copy.deepcopy(qualification)
        changed["repository_control"]["standalone_clone_after"][
            "local_config_sha256"
        ] = "f" * 64
        with self.assertRaisesRegex(ReviewError, "standalone clone changed"):
            validate_repository_control(changed, commit=COMMIT, tree=TREE)

        dirty = copy.deepcopy(qualification)
        dirty["repository_control"]["source_before"]["status_sha256"] = "1" * 64
        with self.assertRaisesRegex(ReviewError, "snapshot is invalid"):
            validate_repository_control(dirty, commit=COMMIT, tree=TREE)

        changed_advisory = copy.deepcopy(qualification)
        changed_advisory["repository_control"]["advisory_source_after"][
            "local_config_sha256"
        ] = "e" * 64
        with self.assertRaisesRegex(ReviewError, "advisory source changed"):
            validate_repository_control(changed_advisory, commit=COMMIT, tree=TREE)

    def test_sandbox_and_advisory_records_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            repo = root / "repo"
            private_root = root / "private"
            worktree = private_root / "worktree"
            host_home = root / "host-home"
            isolated_home = private_root / "home"
            cargo_home = private_root / "cargo-home"
            cargo_target = private_root / "target"
            temporary_directory = private_root / "tmp"
            reproducibility_root = private_root / "reproducibility"
            qualification_root = root / "qualification"
            source_inventory = qualification_root / "source-inventory"
            candidate_evidence = qualification_root / "candidate-evidence"
            advisory_source = root / "advisory-source"
            advisory_databases = (
                cargo_home / "advisory-db",
                cargo_home / "advisory-dbs" / "advisory-db-3157b0e258782691",
            )
            allowed_signers_snapshot = private_root / "INDEPENDENT_ALLOWED_SIGNERS"
            rustup_home = host_home / ".rustup"
            home_tool_paths = (host_home / ".cargo" / "bin",)
            tool_read_paths = (Path("/opt/homebrew"),)
            read_only_paths = (
                *advisory_databases,
                allowed_signers_snapshot,
            )
            writable_paths = (
                isolated_home,
                cargo_home,
                cargo_target,
                temporary_directory,
                source_inventory,
                candidate_evidence,
                reproducibility_root,
            )
            allowed_home_read_paths = tuple(
                sorted((*home_tool_paths, rustup_home), key=lambda item: str(item))
            )
            bindings = {
                "candidate_worktree": str(worktree),
                "source_repository": str(repo),
                "host_home": str(host_home),
                "private_root": str(private_root),
                "isolated_home": str(isolated_home),
                "cargo_home": str(cargo_home),
                "cargo_target_directory": str(cargo_target),
                "temporary_directory": str(temporary_directory),
                "source_inventory": str(source_inventory),
                "candidate_evidence": str(candidate_evidence),
                "reproducibility_root": str(reproducibility_root),
                "advisory_source_denied_read": str(advisory_source),
                "advisory_databases": [str(path) for path in advisory_databases],
                "allowed_signers_snapshot": str(allowed_signers_snapshot),
                "rustup_home": str(rustup_home),
                "home_tool_paths": [str(path) for path in home_tool_paths],
                "tool_read_paths": [str(path) for path in tool_read_paths],
                "candidate_process_probe_deny": str(
                    private_root / "candidate.sb.containment-deny"
                ),
                "candidate_process_probe_allow": str(
                    private_root / "candidate.sb.containment-allow"
                ),
                "dependency_fetch_process_probe_deny": str(
                    private_root / "dependency-fetch.sb.containment-deny"
                ),
                "dependency_fetch_process_probe_allow": str(
                    private_root / "dependency-fetch.sb.containment-allow"
                ),
            }
            sandbox_root = qualification_root / "sandbox"
            sandbox_root.mkdir(parents=True)
            policies = {}
            for filename, allow_network in (
                ("candidate.sb", False),
                ("dependency-fetch.sb", True),
            ):
                process_probe_paths = (
                    private_root / f"{filename}.containment-deny",
                    private_root / f"{filename}.containment-allow",
                )
                document = render_candidate_sandbox_profile(
                    worktree=worktree,
                    source_repo=repo,
                    host_home=host_home,
                    read_only_paths=read_only_paths,
                    writable_paths=writable_paths,
                    allowed_home_read_paths=allowed_home_read_paths,
                    tool_read_paths=tool_read_paths,
                    denied_read_paths=(advisory_source,),
                    process_probe_paths=process_probe_paths,
                    allow_network=allow_network,
                )
                target = sandbox_root / filename
                target.write_bytes(document)
                relative = f"sandbox/{filename}"
                policies[relative] = {
                    "path": relative,
                    "sha256": hashlib.sha256(document).hexdigest(),
                    "size_bytes": len(document),
                }
                policy = document.decode("utf-8")
                self.assertIn(
                    f'(deny file-read* (subpath "{advisory_source}"))',
                    policy,
                )
                self.assertNotIn(
                    f'(allow file-read* (subpath "{advisory_source}"))',
                    policy,
                )
            qualification = {
                "sandbox": {
                    "executor": "/usr/bin/sandbox-exec",
                    "policy_path": "sandbox/candidate.sb",
                    "policy_sha256": policies["sandbox/candidate.sb"]["sha256"],
                    "dependency_fetch_policy_path": "sandbox/dependency-fetch.sb",
                    "dependency_fetch_policy_sha256": policies[
                        "sandbox/dependency-fetch.sb"
                    ]["sha256"],
                    "candidate_source_write_policy": "DENY",
                    "operator_repository_access_policy": "DENY_READ_AND_WRITE",
                    "host_home_read_policy": "DENY_EXCEPT_REQUIRED_TOOL_INPUTS",
                    "write_policy": "DENY_EXCEPT_DECLARED_PRIVATE_OUTPUTS",
                    "network_policy": "DENY_EXCEPT_LOCKED_DEPENDENCY_FETCH",
                    "process_containment_policy": execution_policy_contract(1)[
                        "containment"
                    ],
                    "process_containment_limitation": execution_policy_contract(1)[
                        "containment_residual"
                    ],
                    "bindings": bindings,
                },
                "advisory_database": copy.deepcopy(RUSTSEC_ADVISORY_DATABASE),
            }
            self.assertEqual(
                validate_qualification_sandbox(
                    qualification,
                    qualification_root=qualification_root,
                    manifest_artifacts=policies,
                    repo=repo,
                ),
                (
                    policies["sandbox/candidate.sb"]["sha256"],
                    policies["sandbox/dependency-fetch.sb"]["sha256"],
                ),
            )
            self.assertEqual(
                validate_advisory_database(qualification),
                RUSTSEC_ADVISORY_DATABASE,
            )

            wrong_source = copy.deepcopy(qualification)
            wrong_source["sandbox"]["bindings"]["source_repository"] = str(
                root / "other-repo"
            )
            with self.assertRaisesRegex(ReviewError, "source or retained output"):
                validate_qualification_sandbox(
                    wrong_source,
                    qualification_root=qualification_root,
                    manifest_artifacts=policies,
                    repo=repo,
                )

            with self.assertRaisesRegex(ReviewError, "source or retained output"):
                validate_qualification_sandbox(
                    qualification,
                    qualification_root=qualification_root,
                    manifest_artifacts=policies,
                    repo=repo,
                    recorded_root=root / "other-output",
                )

            overlapping_advisory = copy.deepcopy(qualification)
            overlapping_advisory["sandbox"]["bindings"][
                "advisory_source_denied_read"
            ] = str(repo)
            with self.assertRaisesRegex(ReviewError, "protected roots overlap"):
                validate_qualification_sandbox(
                    overlapping_advisory,
                    qualification_root=qualification_root,
                    manifest_artifacts=policies,
                    repo=repo,
                )

            legacy_advisory_allow = copy.deepcopy(qualification)
            legacy_advisory_allow["sandbox"]["bindings"]["advisory_source"] = str(
                advisory_source
            )
            with self.assertRaisesRegex(ReviewError, "path bindings are malformed"):
                validate_qualification_sandbox(
                    legacy_advisory_allow,
                    qualification_root=qualification_root,
                    manifest_artifacts=policies,
                    repo=repo,
                )

            mutable_tool_root = copy.deepcopy(qualification)
            mutable_tool_root["sandbox"]["bindings"]["tool_read_paths"] = [
                str(private_root / "tool")
            ]
            with self.assertRaisesRegex(ReviewError, "overlaps mutable material"):
                validate_qualification_sandbox(
                    mutable_tool_root,
                    qualification_root=qualification_root,
                    manifest_artifacts=policies,
                    repo=repo,
                )

            permissive = copy.deepcopy(qualification)
            permissive["sandbox"]["write_policy"] = "ALLOW"
            with self.assertRaisesRegex(ReviewError, "sandbox record"):
                validate_qualification_sandbox(
                    permissive,
                    qualification_root=qualification_root,
                    manifest_artifacts=policies,
                    repo=repo,
                )

            other_database = copy.deepcopy(qualification)
            other_database["advisory_database"]["tree"] = "0" * 40
            with self.assertRaisesRegex(ReviewError, "another RustSec"):
                validate_advisory_database(other_database)

    def test_tool_file_set_and_metadata_are_exact(self) -> None:
        executables = {
            name: tool_file_record(name) for name in EXPECTED_TOOL_FILE_NAMES
        }
        path_tool_directories = tuple(
            sorted(
                {
                    Path(executables[name]["invoked_path"]).parent
                    for name in QUALIFICATION_PATH_TOOLS
                },
                key=lambda item: str(item),
            )
        )
        qualification = {
            "tool_files": {
                "status": "UNCHANGED",
                "executables": executables,
            },
            "sandbox": {
                "bindings": {
                    "host_home": "/fixture",
                    "rustup_home": "/fixture/tools",
                    "home_tool_paths": [str(path) for path in path_tool_directories],
                    "tool_read_paths": [str(path) for path in path_tool_directories],
                },
            },
        }
        validate_qualification_tool_files(qualification)
        validate_qualification_tool_bindings(qualification)

        omitted = copy.deepcopy(qualification)
        omitted["tool_files"]["executables"].pop("cargo")
        with self.assertRaisesRegex(ReviewError, "identity set is incomplete"):
            validate_qualification_tool_files(omitted)

        writable = copy.deepcopy(qualification)
        writable["tool_files"]["executables"]["cargo"]["mode"] = 0o775
        with self.assertRaisesRegex(ReviewError, "metadata is invalid"):
            validate_qualification_tool_files(writable)

        broadened = copy.deepcopy(qualification)
        broadened["sandbox"]["bindings"]["tool_read_paths"] = ["/fixture"]
        with self.assertRaisesRegex(ReviewError, "tool roots disagree"):
            validate_qualification_tool_bindings(broadened)

        escaped_rustup = copy.deepcopy(qualification)
        escaped_rustup["tool_files"]["executables"]["rustc-1.89.0"]["invoked_path"] = (
            "/other/rustc"
        )
        with self.assertRaisesRegex(ReviewError, "escapes Rustup home"):
            validate_qualification_tool_bindings(escaped_rustup)

    def test_environment_contract_binds_safe_git_values(self) -> None:
        expected = qualification_environment_contract("1234567890")
        validate_qualification_environment(
            {"environment_contract": expected}, 1_234_567_890
        )
        for key in (
            "GIT_ATTR_NOSYSTEM",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_OPTIONAL_LOCKS",
            "GIT_TERMINAL_PROMPT",
        ):
            changed = copy.deepcopy(expected)
            changed["fixed_values"][key] = "different"
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(ReviewError, "environment contract"),
            ):
                validate_qualification_environment(
                    {"environment_contract": changed}, 1_234_567_890
                )

    def test_supply_chain_records_require_locked_offline_commands(self) -> None:
        license_inventory_path = "reports/license-inventory.json"
        license_path = "reports/license-report.jsonl"
        vulnerability_path = "reports/vulnerability-report.json"
        metadata_path = Path("/private/reproducibility/cargo-metadata.json")
        manifest = {
            license_inventory_path: {
                "path": license_inventory_path,
                "sha256": "c" * 64,
                "size_bytes": 30,
            },
            license_path: {
                "path": license_path,
                "sha256": "a" * 64,
                "size_bytes": 10,
            },
            vulnerability_path: {
                "path": vulnerability_path,
                "sha256": "b" * 64,
                "size_bytes": 20,
            },
        }
        qualification = {
            "sandbox": {
                "bindings": {
                    "reproducibility_root": str(metadata_path.parent),
                }
            },
            "license_inventory": {
                "argv": [
                    "cargo",
                    "deny",
                    "--offline",
                    "--all-features",
                    "--locked",
                    "list",
                    "--metadata-path",
                    str(metadata_path),
                    "--format",
                    "json",
                    "--layout",
                    "crate",
                ],
                "path": license_inventory_path,
                "sha256": "c" * 64,
                "size_bytes": 30,
                "report_stream": "stdout",
                "receipt": "license-inventory",
                "scope": "CARGO_DENY_HOST_FILTERED_GRAPH",
                "diagnostics": {
                    "stream": "stderr",
                    "text": "",
                    "sha256": EMPTY_SHA256,
                    "size_bytes": 0,
                },
            },
            "license_report": {
                "argv": [
                    "cargo",
                    "deny",
                    "--offline",
                    "--format",
                    "json",
                    "--all-features",
                    "--locked",
                    "check",
                    "--metadata-path",
                    str(metadata_path),
                    "licenses",
                ],
                "path": license_path,
                "sha256": "a" * 64,
                "size_bytes": 10,
                "report_stream": "stderr",
                "receipt": "license-report",
                "diagnostics": {
                    "stream": "stdout",
                    "text": "",
                    "sha256": EMPTY_SHA256,
                    "size_bytes": 0,
                },
            },
            "vulnerability_report": {
                "argv": [
                    "cargo",
                    "audit",
                    "--no-fetch",
                    "--stale",
                    "--no-yanked",
                    "--ignore",
                    "RUSTSEC-2026-0041",
                    "--format",
                    "json",
                ],
                "path": vulnerability_path,
                "sha256": "b" * 64,
                "size_bytes": 20,
                "report_stream": "stdout",
                "receipt": "vulnerability-report",
                "diagnostics": {
                    "stream": "stderr",
                    "text": "",
                    "sha256": EMPTY_SHA256,
                    "size_bytes": 0,
                },
            },
        }
        receipts = {
            "license-inventory": {
                "stdout_sha256": "c" * 64,
                "stdout_size_bytes": 30,
                "stderr_sha256": EMPTY_SHA256,
                "stderr_size_bytes": 0,
                "_diagnostics_text_sha256": EMPTY_SHA256,
            },
            "license-report": {
                "stdout_sha256": EMPTY_SHA256,
                "stdout_size_bytes": 0,
                "stderr_sha256": "a" * 64,
                "stderr_size_bytes": 10,
                "_diagnostics_text_sha256": EMPTY_SHA256,
            },
            "vulnerability-report": {
                "stdout_sha256": "b" * 64,
                "stdout_size_bytes": 20,
                "stderr_sha256": EMPTY_SHA256,
                "stderr_size_bytes": 0,
                "_diagnostics_text_sha256": EMPTY_SHA256,
            },
        }
        validate_supply_chain_report_records(qualification, manifest, receipts)

        online = copy.deepcopy(qualification)
        online["vulnerability_report"]["argv"].remove("--no-fetch")
        with self.assertRaisesRegex(ReviewError, "vulnerability_report"):
            validate_supply_chain_report_records(online, manifest, receipts)

    def test_vulnerability_report_requires_exact_residual_warnings(self) -> None:
        document = vulnerability_report()
        validate_vulnerability_report(document)

        finding = copy.deepcopy(document)
        finding["vulnerabilities"] = {"found": True, "count": 1, "list": [{}]}
        with self.assertRaisesRegex(ReviewError, "contains a finding"):
            validate_vulnerability_report(finding)

        extra = copy.deepcopy(document)
        extra["warnings"]["unsound"] = []
        with self.assertRaisesRegex(ReviewError, "warning class"):
            validate_vulnerability_report(extra)

        substituted = copy.deepcopy(document)
        substituted["warnings"]["unmaintained"][0]["package"]["version"] = "1.0.14"
        with self.assertRaisesRegex(ReviewError, "warnings are not exact"):
            validate_vulnerability_report(substituted)

    def test_dynamic_commit_verification_requires_safe_git_controls(self) -> None:
        root = Path("/private/tmp/qualification-output")
        trust = Path("/private/tmp/INDEPENDENT_ALLOWED_SIGNERS")
        by_name = {
            "verify-commit-signature-external-key": {
                "argv": [
                    "git",
                    "--no-replace-objects",
                    *SAFE_GIT_CONFIGURATION,
                    "-c",
                    "gpg.format=ssh",
                    "-c",
                    f"gpg.ssh.allowedSignersFile={trust}",
                    "verify-commit",
                    "HEAD",
                ]
            },
            "tracked-source-inventory": {
                "argv": [
                    "python3",
                    "repo_work/audit_tracked_files.py",
                    "--repo",
                    ".",
                    "--out",
                    str(root / "source-inventory"),
                ]
            },
        }
        specifications = _dynamic_qualification_specs(
            by_name,
            root,
            expected_allowed_signers_snapshot=trust,
        )
        self.assertEqual(
            specifications[0].argv,
            tuple(by_name["verify-commit-signature-external-key"]["argv"]),
        )

        unsafe = copy.deepcopy(by_name)
        unsafe["verify-commit-signature-external-key"]["argv"].remove(
            "--no-replace-objects"
        )
        with self.assertRaisesRegex(ReviewError, "commit-verification"):
            _dynamic_qualification_specs(
                unsafe,
                root,
                expected_allowed_signers_snapshot=trust,
            )

        substituted = copy.deepcopy(by_name)
        substituted["verify-commit-signature-external-key"]["argv"][-3] = (
            "gpg.ssh.allowedSignersFile=/private/other/INDEPENDENT_ALLOWED_SIGNERS"
        )
        with self.assertRaisesRegex(ReviewError, "another signer snapshot"):
            _dynamic_qualification_specs(
                substituted,
                root,
                expected_allowed_signers_snapshot=trust,
            )


if __name__ == "__main__":
    unittest.main()
