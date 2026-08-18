"""Focused tests for qualification-record finalization boundaries."""

from __future__ import annotations

import ast
import copy
import errno
import hashlib
import json
import os
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

TOOLS = Path(__file__).resolve().parents[1]
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))

from common import (  # noqa: E402
    SAFE_GIT_CONFIGURATION,
    ReviewError,
    canonical_json,
)
from finalize_release import (  # noqa: E402
    CREBAIN_CANDIDATE_BOUNDARY,
    CREBAIN_CANDIDATE_RECEIPT_SCHEMA,
    CREBAIN_DECIMAL_ORACLE_SHA256,
    CREBAIN_MACHINE_SCHEMA_BYTES,
    CREBAIN_MACHINE_SCHEMA_SHA256,
    EMPTY_SHA256,
    EXPECTED_ADVISORY_WARNINGS,
    EXPECTED_DEVELOPER_GIT_IDENTITIES,
    EXPECTED_DEVELOPER_TOOL_IDENTITIES,
    EXPECTED_GIT_PACKAGE_SOURCES,
    EXPECTED_RELEASE_CRATES,
    EXPECTED_RUNTIME_LIBRARY_IDENTITIES,
    EXPECTED_TOOL_FILE_IDENTITIES,
    EXPECTED_TOOL_FILE_NAMES,
    MAX_QUALIFICATION_LOG_HEADER_BYTES,
    RUSTSEC_ADVISORY_DATABASE,
    TOOL_FILE_BASENAMES,
    _dynamic_qualification_specs,
    candidate_evidence_outer_artifacts,
    candidate_evidence_subject_identity,
    candidate_source_date_epoch,
    candidate_crate_files,
    cleanup_finalization_inputs,
    read_qualification_auxiliary_log,
    read_qualification_command_log,
    read_qualification_log_header,
    validate_advisory_database,
    validate_cargo_metadata_bindings,
    validate_crebain_candidate_receipt,
    validate_command_receipt_trailer,
    validate_candidate_evidence_validation_record,
    validate_finalizer_candidate_evidence,
    validate_package_patch_receipts,
    validate_qualification_environment,
    validate_qualification_fuzz_runners,
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
import qualify_candidate as qualifier  # noqa: E402
from qualify_candidate import (  # noqa: E402
    AuxiliaryRunner,
    BoundedProcessResult,
    DEEP_FUZZ_BUILD_ENVIRONMENT,
    DEEP_FUZZ_COMMAND_TARGETS,
    DEEP_FUZZ_DYNAMIC_LINKER,
    DEEP_FUZZ_HOST_TARGET,
    DEEP_FUZZ_LOAD_DYLIBS,
    DEEP_FUZZ_TARGETS,
    PINNED_DEEP_FUZZ_ASAN_LIBRARY_IDENTITY,
    PINNED_DEEP_FUZZ_ASAN_LIBRARY_MODE,
    PINNED_DEVELOPER_SDK_IDENTITIES,
    PINNED_CPYTHON_RUNTIME_EXECUTABLE_IDENTITIES,
    PINNED_CPYTHON_RUNTIME_LIBRARY_IDENTITIES,
    PINNED_CPYTHON_RUNTIME_TREE_IDENTITY,
    PINNED_CPYTHON_VERSION_ROOT,
    PINNED_CPYTHON_LAUNCHER_PATH,
    PINNED_RUST_TOOLCHAIN_RUNTIME_COMPONENTS,
    PINNED_RUST_TOOLCHAIN_RUNTIME_IDENTITIES,
    PINNED_RUSTUP_SETTINGS_IDENTITY,
    QUALIFICATION_PYTHON_FLAGS,
    QUALIFICATION_COMPILER_DRIVER_NAME,
    QUALIFICATION_ENVIRONMENT_KEYS,
    QUALIFICATION_PATH_TOOLS,
    QUALIFICATION_PRESENT_BUT_DENIED_UNUSED_TOOLS,
    PINNED_PKG_CONFIG_EXECUTABLE_PATH,
    PINNED_PKG_CONFIG_IDENTITY,
    PINNED_PKG_CONFIG_MODE,
    PINNED_PKG_CONFIG_VERSION,
    QUALIFICATION_SYSTEM_PATHS,
    QUALIFICATION_SYSTEM_TOOL_PATHS,
    SANDBOX_EXECUTABLE,
    SANDBOX_SYSTEM_READ_PATHS,
    MacOSProcessContainment,
    ProcessContainmentError,
    _close_process_resources,
    _emergency_stop,
    _finalize_tracked_process,
    _wait_for_launch_gate,
    candidate_executed_argv,
    create_standalone_candidate_clone,
    deep_fuzz_runner_root,
    executable_file_identity,
    execution_policy_contract,
    install_qualification_tool_dispatch,
    macho_runtime_paths,
    pinned_pkg_config_input_path,
    qualification_allowed_executable_paths,
    qualification_compiler_driver_bytes,
    qualification_system_path_state,
    qualification_tool_read_paths,
    qualification_environment_contract,
    release_qualification_tool_dispatch,
    render_candidate_sandbox_profile,
    resolve_candidate_git_executable,
    rust_toolchain_runtime_read_paths,
    run_bounded_process,
    sandboxed_argv,
    snapshot_deep_fuzz_executables,
    validate_deep_fuzz_runner_runtime,
    validate_pinned_pkg_config_executable,
    verify_qualification_tool_dispatch,
    write_candidate_sandbox_profile,
)


COMMIT = "a" * 40
TREE = "b" * 40


def crebain_candidate_receipt() -> bytes:
    """Return one canonical passing candidate-gate stdout fixture."""

    document = {
        "schema": CREBAIN_CANDIDATE_RECEIPT_SCHEMA,
        "rust_output_sha256": "c" * 64,
        "rust_output_bytes": 253_502,
        "machine_schema_sha256": CREBAIN_MACHINE_SCHEMA_SHA256,
        "machine_schema_bytes": CREBAIN_MACHINE_SCHEMA_BYTES,
        "decimal_oracle_sha256": CREBAIN_DECIMAL_ORACLE_SHA256,
        "averaged_atom_components_compared": 66,
        "subset_mutual_informations_compared": 10,
        "pointwise_decimal_components_compared": 0,
        "maximum_abs_error_nats": "1.96486887552982119960425290562084565907426063E-16",
        "tolerance_nats": "3E-16",
        "schema_all_passed": True,
        "decimal_all_passed": True,
        "boundary": CREBAIN_CANDIDATE_BOUNDARY,
    }
    return (
        json.dumps(document, allow_nan=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


class CrebainCandidateReceiptTest(unittest.TestCase):
    def test_accepts_exact_candidate_receipt(self) -> None:
        document = validate_crebain_candidate_receipt(crebain_candidate_receipt())
        self.assertEqual(document["averaged_atom_components_compared"], 66)

    def test_rejects_weakened_or_noncanonical_candidate_receipt(self) -> None:
        document = json.loads(crebain_candidate_receipt())
        for field, value, marker in (
            ("decimal_all_passed", False, "contract drifted"),
            ("maximum_abs_error_nats", "4E-16", "exceeds"),
            ("machine_schema_sha256", "d" * 64, "contract drifted"),
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(document)
                mutated[field] = value
                encoded = (
                    json.dumps(mutated, sort_keys=True, separators=(",", ":"))
                    + "\n"
                ).encode("utf-8")
                with self.assertRaisesRegex(ReviewError, marker):
                    validate_crebain_candidate_receipt(encoded)
        with self.assertRaisesRegex(ReviewError, "not canonical"):
            validate_crebain_candidate_receipt(
                json.dumps(document, indent=2, sort_keys=True).encode("utf-8")
            )


def pinned_pkg_config_path() -> Path:
    """Return the exact pkgconf executable path used by qualification."""

    return PINNED_PKG_CONFIG_EXECUTABLE_PATH.resolve(strict=True)


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
        "lockfile": {"dependency-count": 436},
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
    if name == "sandbox-exec":
        path = Path("/usr/bin/sandbox-exec")
        resolved = path
    elif name in PINNED_CPYTHON_RUNTIME_EXECUTABLE_IDENTITIES:
        path = PINNED_CPYTHON_RUNTIME_EXECUTABLE_IDENTITIES[name][0]
        resolved = path
    elif name in QUALIFICATION_PATH_TOOLS:
        path = Path("/fixture/galadriel-tool-dispatch-fixture") / name
        selected_git = next(iter(EXPECTED_DEVELOPER_GIT_IDENTITIES))
        if name == "git":
            resolved = selected_git
        elif name in {"cc", "clang"}:
            resolved = Path("/fixture") / QUALIFICATION_COMPILER_DRIVER_NAME
        elif name in EXPECTED_DEVELOPER_TOOL_IDENTITIES[selected_git]:
            resolved = EXPECTED_DEVELOPER_TOOL_IDENTITIES[selected_git][name][0]
        elif name in QUALIFICATION_SYSTEM_TOOL_PATHS:
            resolved = QUALIFICATION_SYSTEM_TOOL_PATHS[name]
        elif name == "python3":
            resolved = PINNED_CPYTHON_LAUNCHER_PATH
        elif name == "pkg-config":
            resolved = PINNED_PKG_CONFIG_EXECUTABLE_PATH
        elif name in {"cargo", "rustc"}:
            resolved = Path("/fixture/tools/rustup/rustup")
        else:
            resolved = Path("/fixture/tools") / name / TOOL_FILE_BASENAMES[name]
    else:
        path = Path("/fixture/tools") / name / TOOL_FILE_BASENAMES[name]
        resolved = path
    sha256, size_bytes = EXPECTED_TOOL_FILE_IDENTITIES[name]
    return {
        "invoked_path": str(path),
        "resolved_path": str(resolved),
        "sha256": sha256,
        "size_bytes": size_bytes,
        "uid": (
            0
            if name == "git"
            or name in QUALIFICATION_SYSTEM_TOOL_PATHS
            or name
            in EXPECTED_DEVELOPER_TOOL_IDENTITIES[
                next(iter(EXPECTED_DEVELOPER_GIT_IDENTITIES))
            ]
            and name not in {"cc", "clang"}
            else 501
        ),
        "gid": (
            0
            if name == "git"
            or name in QUALIFICATION_SYSTEM_TOOL_PATHS
            or name
            in EXPECTED_DEVELOPER_TOOL_IDENTITIES[
                next(iter(EXPECTED_DEVELOPER_GIT_IDENTITIES))
            ]
            and name not in {"cc", "clang"}
            else 20
        ),
        "mode": (
            PINNED_PKG_CONFIG_MODE
            if name == "pkg-config"
            else 0o500
            if name in {"cc", "clang"}
            else 0o755
        ),
    }


def runtime_library_record(name: str) -> dict[str, object]:
    """Return one exact synthetic runtime-library identity record."""

    invoked, resolved, sha256, size_bytes, mode = (
        EXPECTED_RUNTIME_LIBRARY_IDENTITIES[name]
    )
    if invoked is None or resolved is None:
        invoked = (
            Path("/fixture/tools")
            / "toolchains"
            / "nightly-2026-06-16-aarch64-apple-darwin"
            / "lib"
            / "rustlib"
            / "aarch64-apple-darwin"
            / "lib"
            / "librustc-nightly_rt.asan.dylib"
        )
        resolved = invoked
    return {
        "invoked_path": str(invoked),
        "resolved_path": str(resolved),
        "sha256": sha256,
        "size_bytes": size_bytes,
        "uid": 501,
        "gid": 80,
        "mode": mode,
    }


def rust_toolchain_runtime_record(rustup_home: Path) -> dict[str, object]:
    """Return one exact synthetic Rust toolchain runtime record."""

    settings_path = rustup_home / "settings.toml"
    return {
        "schema": "galadriel.rust-toolchain-runtime.v1",
        "rustup_home": str(rustup_home),
        "settings": {
            "invoked_path": str(settings_path),
            "resolved_path": str(settings_path),
            "sha256": PINNED_RUSTUP_SETTINGS_IDENTITY[0],
            "size_bytes": PINNED_RUSTUP_SETTINGS_IDENTITY[1],
            "uid": 501,
            "gid": 20,
            "mode": PINNED_RUSTUP_SETTINGS_IDENTITY[2],
        },
        "toolchains": {
            toolchain: {
                "root": str(rustup_home / "toolchains" / toolchain),
                **copy.deepcopy(identity),
            }
            for toolchain, identity in (
                PINNED_RUST_TOOLCHAIN_RUNTIME_IDENTITIES.items()
            )
        },
    }


def compiler_input_record() -> dict[str, object]:
    """Return one exact synthetic compiler and macOS SDK input record."""

    selected_git = next(iter(EXPECTED_DEVELOPER_GIT_IDENTITIES))
    implementation_path, implementation_sha256, implementation_size = (
        EXPECTED_DEVELOPER_TOOL_IDENTITIES[selected_git]["clang"]
    )
    sdk = PINNED_DEVELOPER_SDK_IDENTITIES[selected_git]
    driver_path = Path("/fixture") / QUALIFICATION_COMPILER_DRIVER_NAME
    settings_path = sdk["resolved_root"] / "SDKSettings.json"
    return {
        "driver": {
            "invoked_path": str(driver_path),
            "resolved_path": str(driver_path),
            "sha256": EXPECTED_TOOL_FILE_IDENTITIES["cc"][0],
            "size_bytes": EXPECTED_TOOL_FILE_IDENTITIES["cc"][1],
            "uid": 501,
            "gid": 20,
            "mode": 0o500,
        },
        "implementation": {
            "invoked_path": str(implementation_path),
            "resolved_path": str(implementation_path),
            "sha256": implementation_sha256,
            "size_bytes": implementation_size,
            "uid": 0,
            "gid": 0,
            "mode": 0o755,
        },
        "sdk": {
            "invoked_root": str(sdk["invoked_root"]),
            "resolved_root": str(sdk["resolved_root"]),
            "link_target": sdk["link_target"],
            "settings": {
                "invoked_path": str(settings_path),
                "resolved_path": str(settings_path),
                "sha256": sdk["settings_sha256"],
                "size_bytes": sdk["settings_size_bytes"],
                "uid": 0,
                "gid": 0,
                "mode": sdk["settings_mode"],
            },
        },
    }


class FinalizeQualificationTest(unittest.TestCase):
    def test_candidate_python_uses_exact_no_import_cache_no_site_prefix(self) -> None:
        self.assertEqual(
            QUALIFICATION_PYTHON_FLAGS,
            ("-B", "-E", "-s", "-S"),
        )
        self.assertEqual(
            candidate_executed_argv(["python3", "script.py"], {}),
            ["python3", *QUALIFICATION_PYTHON_FLAGS, "script.py"],
        )
        self.assertEqual(
            candidate_executed_argv(
                ["python3", *QUALIFICATION_PYTHON_FLAGS, "script.py"],
                {},
            ),
            ["python3", *QUALIFICATION_PYTHON_FLAGS, "script.py"],
        )

        environment = dict(os.environ)
        environment.update(
            {
                "PYTHONHOME": "/tmp/galadriel-invalid-python-home",
                "PYTHONPATH": "/tmp/galadriel-injected-python-path",
                "PYTHONUSERBASE": "/tmp/galadriel-injected-user-base",
            }
        )
        process = subprocess.run(
            [
                sys.executable,
                *QUALIFICATION_PYTHON_FLAGS,
                "-c",
                (
                    "import json,sys; print(json.dumps({"
                    "'dont_write_bytecode':sys.flags.dont_write_bytecode,"
                    "'ignore_environment':sys.flags.ignore_environment,"
                    "'no_user_site':sys.flags.no_user_site,"
                    "'no_site':sys.flags.no_site,"
                    "'isolated':sys.flags.isolated,"
                    "'safe_path':sys.flags.safe_path,"
                    "'path':sys.path},sort_keys=True))"
                ),
            ],
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        state = json.loads(process.stdout)
        self.assertEqual(state["dont_write_bytecode"], 1)
        self.assertEqual(state["ignore_environment"], 1)
        self.assertEqual(state["no_user_site"], 1)
        self.assertEqual(state["no_site"], 1)
        self.assertEqual(state["isolated"], 0)
        self.assertFalse(state["safe_path"])
        self.assertNotIn("/tmp/galadriel-injected-python-path", state["path"])
        self.assertFalse(
            any("site-packages" in path for path in state["path"]),
            state["path"],
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bytecode_probe.py").write_text(
                "VALUE = 'loaded'\n",
                encoding="utf-8",
            )
            process = subprocess.run(
                [
                    sys.executable,
                    *QUALIFICATION_PYTHON_FLAGS,
                    "-c",
                    (
                        "import sys; "
                        "sys.path.insert(0, sys.argv[1]); "
                        "import bytecode_probe; "
                        "print(sys.flags.dont_write_bytecode, bytecode_probe.VALUE)"
                    ),
                    str(root),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(process.stdout, "1 loaded\n")
            self.assertFalse((root / "__pycache__").exists())
            self.assertEqual(list(root.rglob("*.pyc")), [])

        qualifier.require_release_python_isolation()

        for observed in (
            (0, 1, 1, 1, 0, False),
            (1, 0, 1, 1, 0, False),
            (1, 1, 0, 1, 0, False),
            (1, 1, 1, 0, 0, False),
            (1, 1, 1, 1, 1, True),
            (1, 1, 1, 1, 0, True),
        ):
            with (
                self.subTest(observed=observed),
                patch.object(
                    qualifier.sys,
                    "flags",
                    SimpleNamespace(
                        dont_write_bytecode=observed[0],
                        ignore_environment=observed[1],
                        no_user_site=observed[2],
                        no_site=observed[3],
                        isolated=observed[4],
                        safe_path=observed[5],
                    ),
                ),
                self.assertRaisesRegex(
                    ReviewError,
                    "exact -B -E -s -S flags",
                ),
            ):
                qualifier.require_release_python_isolation()

    def test_sandbox_profile_canonicalizes_linked_tool_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            worktree = root / "worktree"
            source_repo = root / "source"
            worktree.mkdir()
            source_repo.mkdir()
            target = root / "tool-target"
            target.write_bytes(b"tool\n")
            linked = root / "tool-link"
            linked.symlink_to(target)
            sandbox_executable = root / "sandbox-exec"
            sandbox_executable.write_bytes(b"fixture\n")
            profile = root / "candidate.sb"

            with patch.object(
                qualifier,
                "SANDBOX_EXECUTABLE",
                sandbox_executable,
            ):
                digest = write_candidate_sandbox_profile(
                    profile,
                    worktree=worktree,
                    source_repo=source_repo,
                    tool_read_paths=(linked,),
                )

            probes = tuple(
                path.resolve(strict=True)
                for path in qualifier.sandbox_process_probe_paths(profile)
            )
            expected = render_candidate_sandbox_profile(
                worktree=worktree,
                source_repo=source_repo,
                host_home=Path.home().resolve(),
                tool_read_paths=(target,),
                process_probe_paths=probes,
            )
            self.assertEqual(profile.read_bytes(), expected)
            self.assertEqual(hashlib.sha256(expected).hexdigest(), digest)
            self.assertNotIn(str(linked).encode("utf-8"), expected)
            self.assertIn(str(target).encode("utf-8"), expected)

    def test_every_candidate_process_wrapper_receives_the_environment(self) -> None:
        tree = ast.parse((TOOLS / "qualify_candidate.py").read_text(encoding="utf-8"))
        wrapper_names = {
            "create_standalone_candidate_clone",
            "run_bounded_process",
            "sandboxed_argv",
        }
        observed = {name: 0 for name in wrapper_names}
        for node in ast.walk(tree):
            if (
                not isinstance(node, ast.Call)
                or not isinstance(node.func, ast.Name)
                or node.func.id not in wrapper_names
            ):
                continue
            observed[node.func.id] += 1
            keywords = {
                keyword.arg for keyword in node.keywords if keyword.arg is not None
            }
            self.assertIn(
                "environment",
                keywords,
                f"qualify_candidate.py:{node.lineno} omits the common environment",
            )
        self.assertTrue(all(count > 0 for count in observed.values()))

    def test_pkg_config_selection_requires_the_pinned_byte_identity(self) -> None:
        record = {
            "resolved_path": str(PINNED_PKG_CONFIG_EXECUTABLE_PATH),
            "sha256": PINNED_PKG_CONFIG_IDENTITY[0],
            "size_bytes": PINNED_PKG_CONFIG_IDENTITY[1],
            "mode": PINNED_PKG_CONFIG_MODE,
        }
        with patch(
            "qualify_candidate.direct_executable_file_identity",
            return_value=record,
        ) as identify:
            self.assertIs(
                validate_pinned_pkg_config_executable(
                    PINNED_PKG_CONFIG_EXECUTABLE_PATH
                ),
                record,
            )
        identify.assert_called_once_with(PINNED_PKG_CONFIG_EXECUTABLE_PATH)

        drifted = dict(record, sha256="0" * 64)
        with (
            patch(
                "qualify_candidate.direct_executable_file_identity",
                return_value=drifted,
            ),
            self.assertRaisesRegex(
                ReviewError,
                f"pinned pkgconf {PINNED_PKG_CONFIG_VERSION}",
            ),
        ):
            validate_pinned_pkg_config_executable(PINNED_PKG_CONFIG_EXECUTABLE_PATH)

        with self.assertRaisesRegex(ReviewError, "path differs from the pin"):
            validate_pinned_pkg_config_executable(
                Path("/independent/tools/pkgconf-3.0.3")
            )

    def test_direct_runtime_inputs_reject_hard_links(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            executable = root / "tool"
            executable.write_bytes(b"tool\n")
            executable.chmod(0o500)
            os.link(executable, root / "another-name")
            with self.assertRaisesRegex(ReviewError, "identity is invalid"):
                qualifier.direct_executable_file_identity(executable)

    def test_rust_runtime_tree_binding_is_exact_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            rustup_home = root / ".rustup"
            toolchain_name = "fixture-aarch64-apple-darwin"
            toolchain = rustup_home / "toolchains" / toolchain_name
            for component in PINNED_RUST_TOOLCHAIN_RUNTIME_COMPONENTS:
                (toolchain / component).mkdir(parents=True, exist_ok=True)
            settings = rustup_home / "settings.toml"
            settings.write_bytes(b'version = "12"\n')
            settings.chmod(0o644)
            executable = toolchain / "bin" / "rustc"
            executable.write_bytes(b"fixture-rustc\n")
            executable.chmod(0o555)
            rows = [
                {"kind": "directory", "path": ""},
                {"kind": "directory", "path": "bin"},
                {
                    "kind": "file",
                    "mode": 0o555,
                    "path": "bin/rustc",
                    "sha256": hashlib.sha256(b"fixture-rustc\n").hexdigest(),
                    "size_bytes": len(b"fixture-rustc\n"),
                },
                {"kind": "directory", "path": "lib"},
                {"kind": "directory", "path": "libexec"},
            ]
            rows.sort(key=lambda row: (row["path"], row["kind"]))
            tree_identity = {
                "schema": "galadriel.rust-toolchain-runtime-tree.v1",
                "toolchain": toolchain_name,
                "components": list(PINNED_RUST_TOOLCHAIN_RUNTIME_COMPONENTS),
                "root_mode": 0o755,
                "sha256": hashlib.sha256(canonical_json(rows)).hexdigest(),
                "entries": len(rows),
                "regular_files": 1,
                "regular_bytes": len(b"fixture-rustc\n"),
            }
            settings_identity = (
                hashlib.sha256(b'version = "12"\n').hexdigest(),
                len(b'version = "12"\n'),
                0o644,
            )
            environment = {"RUSTUP_HOME": str(rustup_home)}
            with (
                patch.object(
                    qualifier,
                    "PINNED_RUST_TOOLCHAIN_RUNTIME_IDENTITIES",
                    {toolchain_name: tree_identity},
                ),
                patch.object(
                    qualifier,
                    "PINNED_RUSTUP_SETTINGS_IDENTITY",
                    settings_identity,
                ),
            ):
                record = qualifier.pinned_rust_toolchain_runtime_identity(
                    environment
                )
                self.assertEqual(
                    record["toolchains"][toolchain_name]["sha256"],
                    tree_identity["sha256"],
                )

                (toolchain / "lib").chmod(0o777)
                with self.assertRaisesRegex(ReviewError, "writable directory"):
                    qualifier.pinned_rust_toolchain_runtime_identity(environment)
                (toolchain / "lib").chmod(0o755)

                os.link(executable, toolchain / "bin" / "rustc-copy")
                with self.assertRaisesRegex(ReviewError, "multiply linked file"):
                    qualifier.pinned_rust_toolchain_runtime_identity(environment)

    def test_pkg_config_cli_path_is_exact_and_raw_absolute(self) -> None:
        self.assertEqual(
            pinned_pkg_config_input_path(str(PINNED_PKG_CONFIG_EXECUTABLE_PATH)),
            PINNED_PKG_CONFIG_EXECUTABLE_PATH,
        )
        cases = (
            "relative/pkgconf",
            "/opt/homebrew/Cellar/pkgconf/3.0.3/bin/../bin/pkgconf",
            "/opt/homebrew/bin/pkg-config",
        )
        for executable in cases:
            with self.subTest(executable=executable):
                with self.assertRaisesRegex(ReviewError, "exact absolute pinned path"):
                    pinned_pkg_config_input_path(executable)

    def test_deep_fuzz_runner_macho_runtime_contract_is_exact(self) -> None:
        asan_library = Path(
            "/fixture/rustup/toolchains/nightly-2026-06-16-aarch64-apple-darwin/"
            "lib/rustlib/aarch64-apple-darwin/lib/"
            "librustc-nightly_rt.asan.dylib"
        )

        def path_command(command: int, path: str) -> bytes:
            encoded = path.encode("utf-8") + b"\0"
            minimum = 12 if command in {0x0E, 0x8000001C} else 24
            size = (minimum + len(encoded) + 7) & ~7
            if command in {0x0E, 0x8000001C}:
                prefix = struct.pack("<III", command, size, minimum)
            else:
                prefix = struct.pack("<IIIIII", command, size, minimum, 0, 0, 0)
            return prefix + encoded + bytes(size - minimum - len(encoded))

        def macho(
            loads: tuple[str, ...],
            run_paths: tuple[str, ...],
            *,
            load_command: int = 0x0C,
            dynamic_linkers: tuple[str, ...] = (DEEP_FUZZ_DYNAMIC_LINKER,),
        ) -> bytes:
            commands = b"".join(path_command(load_command, path) for path in loads)
            commands += b"".join(path_command(0x8000001C, path) for path in run_paths)
            commands += b"".join(
                path_command(0x0E, path) for path in dynamic_linkers
            )
            header = struct.pack(
                "<IiiIIIII",
                0xFEEDFACF,
                0x0100000C,
                0,
                2,
                len(loads) + len(run_paths) + len(dynamic_linkers),
                len(commands),
                0,
                0,
            )
            return header + commands

        valid_document = macho(DEEP_FUZZ_LOAD_DYLIBS, (str(asan_library.parent),))
        runtime_library_record = {
            "sha256": PINNED_DEEP_FUZZ_ASAN_LIBRARY_IDENTITY[0],
            "size_bytes": PINNED_DEEP_FUZZ_ASAN_LIBRARY_IDENTITY[1],
            "mode": PINNED_DEEP_FUZZ_ASAN_LIBRARY_MODE,
        }
        with (
            patch(
                "qualify_candidate.read_bounded_regular_file",
                return_value=valid_document,
            ),
            patch(
                "qualify_candidate.direct_runtime_library_identity",
                return_value=runtime_library_record,
            ),
        ):
            self.assertEqual(
                validate_deep_fuzz_runner_runtime(
                    Path("/fixture/runner"), asan_library
                ),
                {
                    "load_dylibs": list(DEEP_FUZZ_LOAD_DYLIBS),
                    "run_paths": [str(asan_library.parent)],
                    "dynamic_linker": DEEP_FUZZ_DYNAMIC_LINKER,
                    "runtime_library": str(asan_library),
                },
            )

        invalid_contracts = (
            (DEEP_FUZZ_LOAD_DYLIBS[:-1], (str(asan_library.parent),)),
            (
                (*DEEP_FUZZ_LOAD_DYLIBS, "/tmp/injected.dylib"),
                (str(asan_library.parent),),
            ),
            (tuple(reversed(DEEP_FUZZ_LOAD_DYLIBS)), (str(asan_library.parent),)),
            (DEEP_FUZZ_LOAD_DYLIBS, ()),
            (DEEP_FUZZ_LOAD_DYLIBS, (str(asan_library.parent), "/tmp/injected")),
            (DEEP_FUZZ_LOAD_DYLIBS, ("/tmp/another-runtime",)),
        )
        for loads, run_paths in invalid_contracts:
            with (
                self.subTest(loads=loads, run_paths=run_paths),
                patch(
                    "qualify_candidate.read_bounded_regular_file",
                    return_value=macho(loads, run_paths),
                ),
                self.assertRaisesRegex(ReviewError, "runtime contract differs"),
            ):
                validate_deep_fuzz_runner_runtime(
                    Path("/fixture/runner"),
                    asan_library,
                )

        for load_command in (0x20, 0x80000018, 0x8000001F, 0x80000023):
            with (
                self.subTest(load_command=load_command),
                patch(
                    "qualify_candidate.read_bounded_regular_file",
                    return_value=macho(
                        DEEP_FUZZ_LOAD_DYLIBS,
                        (str(asan_library.parent),),
                        load_command=load_command,
                    ),
                ),
                self.assertRaisesRegex(ReviewError, "non-mandatory library load"),
            ):
                validate_deep_fuzz_runner_runtime(
                    Path("/fixture/runner"),
                    asan_library,
                )

        with (
            patch(
                "qualify_candidate.read_bounded_regular_file",
                return_value=macho(
                    DEEP_FUZZ_LOAD_DYLIBS,
                    (str(asan_library.parent),),
                    load_command=0x0F,
                ),
            ),
            self.assertRaisesRegex(ReviewError, "dynamic-linker identity"),
        ):
            validate_deep_fuzz_runner_runtime(
                Path("/fixture/runner"),
                asan_library,
            )

        for dynamic_linkers in (
            (),
            ("/tmp/injected-dyld",),
            (DEEP_FUZZ_DYNAMIC_LINKER, "/tmp/injected-dyld"),
        ):
            with (
                self.subTest(dynamic_linkers=dynamic_linkers),
                patch(
                    "qualify_candidate.read_bounded_regular_file",
                    return_value=macho(
                        DEEP_FUZZ_LOAD_DYLIBS,
                        (str(asan_library.parent),),
                        dynamic_linkers=dynamic_linkers,
                    ),
                ),
                self.assertRaisesRegex(ReviewError, "dynamic-linker contract"),
            ):
                validate_deep_fuzz_runner_runtime(
                    Path("/fixture/runner"),
                    asan_library,
                )

        drifted_runtime_library = dict(runtime_library_record, sha256="0" * 64)
        with (
            patch(
                "qualify_candidate.read_bounded_regular_file",
                return_value=valid_document,
            ),
            patch(
                "qualify_candidate.direct_runtime_library_identity",
                return_value=drifted_runtime_library,
            ),
            self.assertRaisesRegex(ReviewError, "fuzz-asan runtime library differs"),
        ):
            validate_deep_fuzz_runner_runtime(Path("/fixture/runner"), asan_library)

    def test_deep_fuzz_macho_parser_rejects_unsafe_commands(self) -> None:
        header = struct.pack(
            "<IiiIIIII",
            0xFEEDFACF,
            0x0100000C,
            0,
            2,
            1,
            8,
            0,
            0,
        )
        cases = (
            b"",
            struct.pack("<IiiIIIII", 0xFEEDFACF, 0, 0, 2, 0, 0, 0, 0),
            header + struct.pack("<II", 0x27, 8),
            header + struct.pack("<II", 0x0C, 24),
            header + struct.pack("<II", 0x0C, 7),
        )
        for document in cases:
            with self.subTest(size=len(document)), self.assertRaises(ReviewError):
                macho_runtime_paths(document, label="deep fuzz runner")

    def test_deep_fuzz_snapshot_rejects_runtime_drift(self) -> None:
        stable_runtime = {
            "load_dylibs": list(DEEP_FUZZ_LOAD_DYLIBS),
            "run_paths": ["/fixture/asan"],
            "dynamic_linker": DEEP_FUZZ_DYNAMIC_LINKER,
            "runtime_library": "/fixture/asan/librustc-nightly_rt.asan.dylib",
        }
        drifted_runtime = dict(stable_runtime, run_paths=["/tmp/injected"])
        with (
            patch(
                "qualify_candidate.validate_deep_fuzz_runner_runtime",
                side_effect=(stable_runtime, drifted_runtime),
            ),
            patch(
                "qualify_candidate.snapshot_candidate_executable",
                return_value={"sha256": "a" * 64},
            ),
            self.assertRaisesRegex(ReviewError, "changed during snapshot"),
        ):
            snapshot_deep_fuzz_executables(
                target_directory=Path("/fixture/target"),
                private_root=Path("/fixture/private"),
                asan_library=Path("/fixture/asan/librustc-nightly_rt.asan.dylib"),
            )
        self.assertEqual(DEEP_FUZZ_TARGETS[0], "ncp_decode")

    def test_finalizer_binds_every_direct_fuzz_runner(self) -> None:
        private_root = Path("/fixture/private")
        rustup_home = Path("/fixture/rustup")
        asan_library = (
            rustup_home
            / "toolchains"
            / f"nightly-2026-06-16-{DEEP_FUZZ_HOST_TARGET}"
            / "lib"
            / "rustlib"
            / DEEP_FUZZ_HOST_TARGET
            / "lib"
            / "librustc-nightly_rt.asan.dylib"
        )
        runtime = {
            "load_dylibs": list(DEEP_FUZZ_LOAD_DYLIBS),
            "run_paths": [str(asan_library.parent)],
            "dynamic_linker": DEEP_FUZZ_DYNAMIC_LINKER,
            "runtime_library": str(asan_library),
        }
        commands = []
        runners = {}
        for index, (command_name, target) in enumerate(
            DEEP_FUZZ_COMMAND_TARGETS.items(),
            1,
        ):
            path = deep_fuzz_runner_root(private_root) / target / target
            identity = {
                "invoked_path": str(path),
                "resolved_path": str(path),
                "sha256": f"{index:x}" * 64,
                "size_bytes": 1_024 + index,
                "uid": 501,
                "gid": 20,
                "mode": 0o500,
            }
            commands.append(
                {
                    "name": command_name,
                    "subject_executable": {
                        "status": "UNCHANGED",
                        "identity": identity,
                    },
                }
            )
            runners[target] = {"identity": identity, "runtime": runtime}
        qualification = {
            "commands": commands,
            "sandbox": {"bindings": {"rustup_home": str(rustup_home)}},
            "fuzz_runners": {
                "status": "UNCHANGED",
                "target_triple": DEEP_FUZZ_HOST_TARGET,
                "build_environment": dict(DEEP_FUZZ_BUILD_ENVIRONMENT),
                "runners": runners,
            },
        }
        validate_qualification_fuzz_runners(
            qualification,
            private_root=private_root,
        )

        omitted = copy.deepcopy(qualification)
        omitted["fuzz_runners"]["runners"].pop(DEEP_FUZZ_TARGETS[-1])
        with self.assertRaisesRegex(ReviewError, "set is incomplete"):
            validate_qualification_fuzz_runners(
                omitted,
                private_root=private_root,
            )

        drifted = copy.deepcopy(qualification)
        drifted["fuzz_runners"]["runners"][DEEP_FUZZ_TARGETS[0]]["runtime"][
            "run_paths"
        ] = ["/tmp/injected"]
        with self.assertRaisesRegex(ReviewError, "runner is invalid"):
            validate_qualification_fuzz_runners(
                drifted,
                private_root=private_root,
            )

    @unittest.skipUnless(sys.platform == "darwin", "macOS tool dispatch test")
    def test_candidate_git_dispatch_and_receipt_bind_developer_git(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            developer_git = resolve_candidate_git_executable()
            dispatch_directory = root / "galadriel-tool-dispatch-fixture"
            dispatch_directory.mkdir(mode=0o700)
            cargo_home = root / "cargo-home"
            cargo_home.mkdir()
            cwd = root / "worktree"
            cwd.mkdir()
            logs = root / "logs"
            logs.mkdir()
            sandbox_profile = root / "candidate.sb"
            sandbox_profile.write_text("(version 1)\n", encoding="utf-8")
            receipts: list[dict[str, object]] = []
            captured: dict[str, list[str]] = {}

            def successful_process(argv: list[str], **_kwargs: object):
                captured["argv"] = argv
                return BoundedProcessResult(0, False, b"version\n", b"", False, None)

            try:
                environment = {
                    "CARGO_HOME": str(cargo_home),
                    "PATH": os.environ["PATH"],
                    "RUSTUP_HOME": str(Path.home() / ".rustup"),
                }
                records = install_qualification_tool_dispatch(
                    dispatch_directory,
                    environment,
                    git_executable=developer_git,
                    pkg_config_executable=pinned_pkg_config_path(),
                )
                self.assertEqual(set(records), set(QUALIFICATION_PATH_TOOLS))
                entries = tuple(dispatch_directory.iterdir())
                self.assertEqual(len(entries), len(QUALIFICATION_PATH_TOOLS))
                self.assertEqual(
                    {entry.name for entry in entries},
                    set(QUALIFICATION_PATH_TOOLS),
                )
                for name, record in records.items():
                    invoked = dispatch_directory / name
                    self.assertEqual(
                        shutil.which(name, path=environment["PATH"]),
                        str(invoked),
                    )
                    self.assertEqual(
                        str(invoked.resolve(strict=True)),
                        record["resolved_path"],
                    )
                self.assertEqual(
                    candidate_executed_argv(["git", "--version"], environment),
                    [str(developer_git), "--version"],
                )
                dispatch = dispatch_directory / "git"
                identity = executable_file_identity(dispatch)
                self.assertEqual(identity["invoked_path"], str(dispatch))
                self.assertEqual(identity["resolved_path"], str(developer_git))

                runner = AuxiliaryRunner(
                    environment=environment,
                    sandbox_profile=sandbox_profile,
                    logs=logs,
                    receipts=receipts,
                )
                with patch(
                    "qualify_candidate.run_bounded_process",
                    side_effect=successful_process,
                ):
                    runner.run("developer-git", ["git", "--version"], cwd=cwd)
            finally:
                release_qualification_tool_dispatch(dispatch_directory)

            self.assertEqual(captured["argv"][3:], [str(developer_git), "--version"])
            self.assertEqual(receipts[0]["argv"], [str(developer_git), "--version"])

    def test_candidate_git_rejects_usr_bin_launcher(self) -> None:
        with self.assertRaisesRegex(ReviewError, "forbidden /usr/bin/git"):
            sandboxed_argv(
                Path("/fixture/candidate.sb"),
                ["git", "--version"],
                environment={"PATH": "/usr/bin:/bin"},
            )

    def test_qualification_environment_requires_registered_dispatch(self) -> None:
        environment = {key: "fixture" for key in QUALIFICATION_ENVIRONMENT_KEYS}
        environment["PATH"] = "/usr/bin:/bin"
        with self.assertRaisesRegex(ReviewError, "lacks the tool dispatch"):
            verify_qualification_tool_dispatch(environment)

    @unittest.skipUnless(sys.platform == "darwin", "macOS tool dispatch test")
    def test_standalone_clone_requires_the_common_tool_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with self.assertRaisesRegex(ReviewError, "forbidden /usr/bin/git"):
                create_standalone_candidate_clone(
                    root / "source",
                    root / "destination",
                    commit="a" * 40,
                    tree="b" * 40,
                    environment={"PATH": "/usr/bin:/bin"},
                    git_executable=resolve_candidate_git_executable(),
                )

    @unittest.skipUnless(sys.platform == "darwin", "macOS tool dispatch test")
    def test_tool_dispatch_replacement_fails_before_process_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            worktree = root / "worktree"
            worktree.mkdir()
            dispatch_directory = root / "galadriel-tool-dispatch-fixture"
            dispatch_directory.mkdir(mode=0o700)
            environment = {
                "PATH": os.environ["PATH"],
                "RUSTUP_HOME": str(Path.home() / ".rustup"),
            }
            try:
                records = install_qualification_tool_dispatch(
                    dispatch_directory,
                    environment,
                    git_executable=resolve_candidate_git_executable(),
                    pkg_config_executable=pinned_pkg_config_path(),
                )
                profile = root / "candidate.sb"
                write_candidate_sandbox_profile(
                    profile,
                    worktree=worktree,
                    source_repo=ROOT,
                    tool_read_paths=qualification_tool_read_paths(
                        environment,
                        host_home=Path.home().resolve(),
                    ),
                )
                os.chmod(dispatch_directory, 0o700)
                cargo_dispatch = dispatch_directory / "cargo"
                cargo_dispatch.unlink()
                cargo_dispatch.symlink_to(records["python3"]["resolved_path"])
                os.chmod(dispatch_directory, 0o500)
                with (
                    patch("qualify_candidate.subprocess.Popen") as popen,
                    self.assertRaisesRegex(ReviewError, "dispatch changed"),
                ):
                    run_bounded_process(
                        sandboxed_argv(
                            profile,
                            ["/usr/bin/true"],
                            environment=environment,
                        ),
                        cwd=worktree,
                        environment=environment,
                        timeout_seconds=2,
                        separate_stderr=True,
                    )
                popen.assert_not_called()
            finally:
                release_qualification_tool_dispatch(dispatch_directory)

    @unittest.skipUnless(sys.platform == "darwin", "macOS tool dispatch test")
    def test_tool_dispatch_post_execution_failure_is_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            worktree = root / "worktree"
            worktree.mkdir()
            profile = root / "candidate.sb"
            write_candidate_sandbox_profile(
                profile,
                worktree=worktree,
                source_repo=ROOT,
                tool_read_paths=(test_tool_read_root(),),
            )
            with (
                patch(
                    "qualify_candidate.verify_qualification_tool_dispatch",
                    side_effect=(None, ReviewError("fixture dispatch changed")),
                ) as verify_dispatch,
                self.assertRaisesRegex(ReviewError, "fixture dispatch changed"),
            ):
                run_bounded_process(
                    sandboxed_argv(
                        profile,
                        [sys.executable, "-I", "-c", "raise SystemExit(0)"],
                        environment={"PATH": os.environ["PATH"]},
                    ),
                    cwd=worktree,
                    environment={"PATH": os.environ["PATH"]},
                    timeout_seconds=2,
                    separate_stderr=True,
                )
            self.assertEqual(verify_dispatch.call_count, 2)

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

    def test_launch_gate_observation_preserves_waitable_root(self) -> None:
        process = SimpleNamespace(pid=12_345, returncode=None)
        stopped = SimpleNamespace(si_code=os.CLD_STOPPED, si_status=signal.SIGSTOP)
        with patch("qualify_candidate.os.waitid", return_value=stopped) as waitid:
            _wait_for_launch_gate(process)
        waitid.assert_called_once_with(
            os.P_PID,
            12_345,
            os.WEXITED | os.WSTOPPED | os.WNOHANG | os.WNOWAIT,
        )
        self.assertIsNone(process.returncode)

    def test_root_exit_observation_uses_wnowait(self) -> None:
        tracker = object.__new__(MacOSProcessContainment)
        tracker.root_pid = 12_345
        exited = SimpleNamespace(si_code=os.CLD_EXITED, si_status=0)
        with patch("qualify_candidate.os.waitid", return_value=exited) as waitid:
            self.assertTrue(tracker.root_exited_before_reap())
        waitid.assert_called_once_with(
            os.P_PID,
            12_345,
            os.WEXITED | os.WNOHANG | os.WNOWAIT,
        )

    def test_pre_reap_termination_ignores_waitable_root_zombie(self) -> None:
        tracker = object.__new__(MacOSProcessContainment)
        tracker.root_pid = 12_345
        with (
            patch.object(
                tracker,
                "_containment_state",
                return_value=(True, set(), {12_345}),
            ),
            patch.object(tracker, "_signal_group") as signal_group,
            patch(
                "qualify_candidate.PROCESS_EXTINCTION_QUIESCENCE_SECONDS",
                0.0,
            ),
        ):
            self.assertFalse(tracker.terminate_before_root_reap())
        signal_group.assert_not_called()

    def test_pre_reap_termination_reports_and_stops_group_descendant(self) -> None:
        tracker = object.__new__(MacOSProcessContainment)
        tracker.root_pid = 12_345
        with (
            patch.object(
                tracker,
                "_containment_state",
                side_effect=[
                    (True, {12_346}, {12_345, 12_346}),
                    (True, set(), {12_345}),
                ],
            ),
            patch.object(tracker, "_signal_group") as signal_group,
            patch(
                "qualify_candidate.PROCESS_EXTINCTION_QUIESCENCE_SECONDS",
                0.0,
            ),
        ):
            self.assertTrue(tracker.terminate_before_root_reap())
        signal_group.assert_called_once_with(12_345, signal.SIGTERM)

    def test_pre_reap_quiescence_detects_a_delayed_escape(self) -> None:
        tracker = object.__new__(MacOSProcessContainment)
        tracker.root_pid = 12_345
        with (
            patch.object(
                tracker,
                "_containment_state",
                side_effect=[
                    (True, set(), {12_345}),
                    (True, set(), {12_345}),
                    (True, {12_346}, {12_345}),
                ],
            ),
            patch("qualify_candidate.time.sleep"),
            self.assertRaisesRegex(ReviewError, "identity-safe cleanup"),
        ):
            tracker.terminate_before_root_reap()

    def test_post_reap_verification_is_read_only(self) -> None:
        tracker = object.__new__(MacOSProcessContainment)
        tracker.root_pid = 12_345
        with (
            patch(
                "qualify_candidate.os.waitid",
                side_effect=ChildProcessError("reaped"),
            ),
            patch.object(tracker, "_live_pids", return_value={12_346}),
            patch.object(tracker, "_group_pids", return_value=set()),
            patch.object(tracker, "_signal_group") as signal_group,
            self.assertRaisesRegex(ReviewError, "process remains after root reap"),
        ):
            tracker.verify_extinct_after_root_reap()
        signal_group.assert_not_called()

    def test_tracked_finalization_orders_termination_reap_and_verification(
        self,
    ) -> None:
        events: list[str] = []

        class FixtureTracker:
            def enforce_resource_bounds(self) -> None:
                events.append("resource-check")

            def terminate_before_root_reap(self) -> bool:
                events.append("terminate")
                return True

            def verify_extinct_after_root_reap(self) -> None:
                events.append("verify")

        class FixtureProcess:
            def wait(self, *, timeout: int) -> int:
                self.assert_timeout(timeout)
                events.append("reap")
                return 7

            @staticmethod
            def assert_timeout(timeout: int) -> None:
                if timeout != 2:
                    raise AssertionError(timeout)

        result = _finalize_tracked_process(
            FixtureProcess(),
            FixtureTracker(),
            enforce_resources=True,
        )
        self.assertEqual(
            events,
            ["resource-check", "terminate", "reap", "verify"],
        )
        self.assertEqual(result.returncode, 7)
        self.assertTrue(result.root_reaped)
        self.assertTrue(result.had_live_after_root_exit)
        self.assertIsNone(result.error)

    def test_tracked_finalization_rechecks_proven_extinction_before_reap(
        self,
    ) -> None:
        events: list[str] = []

        class FixtureTracker:
            @staticmethod
            def _containment_state() -> tuple[bool, set[int], set[int]]:
                events.append("state")
                return True, set(), {12_345}

            @staticmethod
            def terminate_before_root_reap() -> bool:
                events.append("unexpected-terminate")
                return False

            @staticmethod
            def verify_extinct_after_root_reap() -> None:
                events.append("verify")

        class FixtureProcess:
            @staticmethod
            def wait(*, timeout: int) -> int:
                events.append(f"reap-{timeout}")
                return 0

        result = _finalize_tracked_process(
            FixtureProcess(),
            FixtureTracker(),
            enforce_resources=False,
            termination_already_proven=True,
            had_live_after_root_exit=True,
        )
        self.assertEqual(events, ["state", "reap-2", "verify"])
        self.assertTrue(result.had_live_after_root_exit)

    def test_tracked_finalization_does_not_verify_after_failed_root_reap(self) -> None:
        events: list[str] = []

        class FixtureTracker:
            @staticmethod
            def terminate_before_root_reap() -> bool:
                events.append("terminate")
                return False

            @staticmethod
            def verify_extinct_after_root_reap() -> None:
                events.append("verify")

        class FixtureProcess:
            @staticmethod
            def wait(*, timeout: int) -> int:
                events.append("reap-attempt")
                raise subprocess.TimeoutExpired("fixture", timeout)

        with self.assertRaisesRegex(
            ProcessContainmentError,
            "root reap is not proven",
        ):
            _finalize_tracked_process(
                FixtureProcess(),
                FixtureTracker(),
                enforce_resources=False,
            )
        self.assertEqual(events, ["terminate", "reap-attempt", "reap-attempt"])

    def test_tracked_finalization_preserves_primary_and_completes_cleanup(
        self,
    ) -> None:
        events: list[str] = []

        class FixtureTracker:
            @staticmethod
            def enforce_resource_bounds() -> None:
                events.append("resource-check")
                raise KeyboardInterrupt

            @staticmethod
            def terminate_before_root_reap() -> bool:
                events.append("terminate")
                return False

            @staticmethod
            def verify_extinct_after_root_reap() -> None:
                events.append("verify")

        class FixtureProcess:
            @staticmethod
            def wait(*, timeout: int) -> int:
                events.append(f"reap-{timeout}")
                return 0

        with self.assertRaises(KeyboardInterrupt):
            _finalize_tracked_process(
                FixtureProcess(),
                FixtureTracker(),
                enforce_resources=True,
            )
        self.assertEqual(
            events,
            ["resource-check", "terminate", "reap-2", "verify"],
        )

    def test_tracked_finalization_does_not_reap_after_termination_failure(
        self,
    ) -> None:
        events: list[str] = []

        class FixtureTracker:
            @staticmethod
            def terminate_before_root_reap() -> bool:
                events.append("terminate")
                raise ReviewError("fixture termination failure")

            @staticmethod
            def verify_extinct_after_root_reap() -> None:
                events.append("verify")

        class FixtureProcess:
            @staticmethod
            def wait(*, timeout: int) -> int:
                events.append(f"reap-{timeout}")
                return 0

        with self.assertRaisesRegex(
            ProcessContainmentError,
            "termination is not proven",
        ):
            _finalize_tracked_process(
                FixtureProcess(),
                FixtureTracker(),
                enforce_resources=False,
            )
        self.assertEqual(events, ["terminate"])

    def test_process_group_signal_requires_root_identity(self) -> None:
        tracker = object.__new__(MacOSProcessContainment)
        tracker.root_pid = 12_345
        with (
            patch.object(tracker, "_signal_group") as signal_group,
            self.assertRaisesRegex(ReviewError, "not bound by its root"),
        ):
            tracker._signal_remaining(
                root_exited=False,
                remaining={12_345},
                group=set(),
                signal_number=signal.SIGTERM,
            )
        signal_group.assert_not_called()

    def test_escaped_process_does_not_receive_numeric_signal(self) -> None:
        tracker = object.__new__(MacOSProcessContainment)
        tracker.root_pid = 12_345
        with (
            patch("qualify_candidate.os.kill") as numeric_signal,
            patch.object(tracker, "_signal_group") as group_signal,
            self.assertRaisesRegex(ReviewError, "identity-safe cleanup"),
        ):
            tracker._signal_remaining(
                root_exited=True,
                remaining={12_346},
                group={12_345},
                signal_number=signal.SIGKILL,
            )
        numeric_signal.assert_not_called()
        group_signal.assert_not_called()

    def test_known_candidate_sandbox_mismatch_is_fail_closed(self) -> None:
        tracker = object.__new__(MacOSProcessContainment)
        tracker._sandbox_identity = SimpleNamespace(
            deny_path=Path("/fixture/deny"),
            allow_path=Path("/fixture/allow"),
        )
        tracker._sandbox_check = MagicMock(return_value=0)
        with (
            patch("qualify_candidate._pid_exists", return_value=True),
            self.assertRaisesRegex(ReviewError, "does not have a sandbox identity"),
        ):
            tracker._sandbox_matches(12_345, known_candidate=True)

    def test_indeterminate_live_sandbox_probe_is_fail_closed(self) -> None:
        tracker = object.__new__(MacOSProcessContainment)
        tracker._sandbox_identity = SimpleNamespace(
            deny_path=Path("/fixture/deny"),
            allow_path=Path("/fixture/allow"),
        )
        tracker._sandbox_check = MagicMock(return_value=-1)
        with (
            patch("qualify_candidate._pid_exists", return_value=True),
            self.assertRaisesRegex(ReviewError, "cannot determine"),
        ):
            tracker._sandbox_matches(12_345)

    def test_resident_measurement_retries_a_transient_exec_transition(self) -> None:
        tracker = object.__new__(MacOSProcessContainment)
        tracker.root_pid = 12_345
        tracker._exited = set()
        calls = 0

        def transient_pid_info(
            _pid: int,
            _flavor: int,
            _argument: int,
            _buffer: object,
            size: int,
        ) -> int:
            nonlocal calls
            calls += 1
            return size if calls == 3 else 0

        tracker._pid_info = transient_pid_info
        tracker._drain_events = MagicMock()
        with (
            patch("qualify_candidate.os.waitid", return_value=None),
            patch("qualify_candidate._pid_exists", return_value=True),
            patch("qualify_candidate.time.sleep") as sleep,
        ):
            self.assertEqual(tracker._resident_size(12_345), 0)
        self.assertEqual(calls, 3)
        sleep.assert_called_once()

    def test_resident_measurement_accepts_a_bound_exit_event(self) -> None:
        tracker = object.__new__(MacOSProcessContainment)
        tracker.root_pid = 12_345
        tracker._exited = set()
        tracker._pid_info = MagicMock(return_value=0)

        def record_exit() -> None:
            tracker._exited.add(12_345)

        tracker._drain_events = MagicMock(side_effect=record_exit)
        self.assertEqual(tracker._resident_size(12_345), 0)
        tracker._pid_info.assert_called_once()

    def test_resident_measurement_persistent_failure_is_bounded_and_fatal(
        self,
    ) -> None:
        tracker = object.__new__(MacOSProcessContainment)
        tracker.root_pid = 12_345
        tracker._exited = set()
        tracker._pid_info = MagicMock(return_value=0)
        tracker._drain_events = MagicMock()
        with (
            patch("qualify_candidate.os.waitid", return_value=None),
            patch("qualify_candidate._pid_exists", return_value=True),
            patch("qualify_candidate.time.sleep") as sleep,
            self.assertRaisesRegex(ReviewError, "cannot measure candidate resident"),
        ):
            tracker._resident_size(12_345)
        self.assertEqual(tracker._pid_info.call_count, 10)
        self.assertEqual(sleep.call_count, 4)

    def test_unrelated_process_can_have_no_sandbox(self) -> None:
        tracker = object.__new__(MacOSProcessContainment)
        tracker._sandbox_identity = SimpleNamespace(
            deny_path=Path("/fixture/deny"),
            allow_path=Path("/fixture/allow"),
        )
        tracker._sandbox_check = MagicMock(return_value=0)
        self.assertFalse(tracker._sandbox_matches(12_345))

    def test_process_tracker_constructor_preserves_primary_cleanup_failure(
        self,
    ) -> None:
        events: list[str] = []

        class FixtureQueue:
            @staticmethod
            def close() -> None:
                events.append("queue-close")
                raise OSError("fixture queue close failure")

        libproc = SimpleNamespace(
            proc_listchildpids=MagicMock(),
            proc_listpgrppids=MagicMock(),
            proc_listallpids=MagicMock(),
            proc_pidinfo=MagicMock(),
        )
        libsandbox = SimpleNamespace(sandbox_check=MagicMock())
        with (
            patch("qualify_candidate.platform.system", return_value="Darwin"),
            patch(
                "qualify_candidate.select.kqueue",
                return_value=FixtureQueue(),
                create=True,
            ),
            patch(
                "qualify_candidate.ctypes.CDLL",
                side_effect=[libproc, libsandbox],
            ),
            patch.object(
                MacOSProcessContainment,
                "_register",
                side_effect=ReviewError("fixture registration failure"),
            ),
            self.assertRaisesRegex(
                ReviewError, "fixture registration failure"
            ) as caught,
        ):
            MacOSProcessContainment(12_345)
        self.assertEqual(events, ["queue-close"])
        self.assertIn(
            "constructor cleanup also failed",
            "\n".join(getattr(caught.exception, "__notes__", ())),
        )

    @unittest.skipUnless(sys.platform == "darwin", "macOS kqueue test")
    def test_kqueue_registration_esrch_is_an_authoritative_exit(self) -> None:
        tracker = object.__new__(MacOSProcessContainment)
        tracker._tracked = set()
        tracker._exited = set()
        tracker._queue = SimpleNamespace(
            control=MagicMock(side_effect=ProcessLookupError(errno.ESRCH, "fixture"))
        )
        with patch("qualify_candidate._pid_exists", return_value=True):
            tracker._register(12_345)
        self.assertEqual(tracker._tracked, set())
        self.assertEqual(tracker._exited, {12_345})

    def test_process_resource_cleanup_attempts_every_resource(self) -> None:
        events: list[str] = []

        class FixtureResource:
            def __init__(self, label: str) -> None:
                self.label = label

            def close(self) -> None:
                events.append(self.label)
                raise OSError(f"fixture {self.label} failure")

        detail = _close_process_resources(
            selector=FixtureResource("selector"),
            process=SimpleNamespace(
                stdout=FixtureResource("stdout"),
                stderr=FixtureResource("stderr"),
            ),
            tracker=FixtureResource("tracker"),
        )
        self.assertEqual(events, ["selector", "stdout", "stderr", "tracker"])
        self.assertIsNotNone(detail)
        for label in (
            "selector",
            "standard output stream",
            "standard error stream",
            "process tracker",
        ):
            self.assertIn(f"{label} cleanup failed", detail or "")

    def test_unsandboxed_escape_command_is_rejected_before_launch(self) -> None:
        source = "import os; os.fork(); os.setsid()"
        with (
            patch("qualify_candidate.subprocess.Popen") as popen,
            self.assertRaisesRegex(
                ProcessContainmentError,
                "require an exact sandbox identity",
            ),
        ):
            run_bounded_process(
                [sys.executable, "-I", "-c", source],
                cwd=ROOT,
                environment={"PATH": os.environ["PATH"]},
                timeout_seconds=1,
                separate_stderr=True,
            )
        popen.assert_not_called()

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
    def test_nested_candidate_git_uses_read_only_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            worktree = root / "worktree"
            worktree.mkdir()
            dispatch_directory = root / "galadriel-tool-dispatch-fixture"
            dispatch_directory.mkdir(mode=0o700)
            developer_git = resolve_candidate_git_executable()
            environment = {
                "PATH": os.environ["PATH"],
                "RUSTUP_HOME": str(Path.home() / ".rustup"),
            }
            try:
                records = install_qualification_tool_dispatch(
                    dispatch_directory,
                    environment,
                    git_executable=developer_git,
                    pkg_config_executable=pinned_pkg_config_path(),
                )
                profile = root / "candidate.sb"
                write_candidate_sandbox_profile(
                    profile,
                    worktree=worktree,
                    source_repo=ROOT,
                    tool_read_paths=qualification_tool_read_paths(
                        environment,
                        host_home=Path.home().resolve(),
                    ),
                )
                result = run_bounded_process(
                    sandboxed_argv(
                        profile,
                        ["/usr/bin/env", "git", "--version"],
                        environment=environment,
                    ),
                    cwd=worktree,
                    environment=environment,
                    timeout_seconds=2,
                    separate_stderr=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.startswith(b"git version "))
                self.assertEqual(len(records), len(QUALIFICATION_PATH_TOOLS))
                self.assertFalse(result.timed_out)
                self.assertFalse(result.output_limit_exceeded)
                self.assertIsNone(result.containment_error)
            finally:
                release_qualification_tool_dispatch(dispatch_directory)

    def test_compiler_driver_applies_the_pinned_sdk_after_caller_arguments(self) -> None:
        for selected_git, sdk in PINNED_DEVELOPER_SDK_IDENTITIES.items():
            with self.subTest(selected_git=selected_git):
                document = qualification_compiler_driver_bytes(selected_git).decode(
                    "utf-8"
                )
                suffix = f'"$@" -isysroot \'{sdk["resolved_root"]}\'\n'
                self.assertTrue(document.endswith(suffix), document)

    @unittest.skipUnless(sys.platform == "darwin", "macOS tool dispatch test")
    def test_candidate_tool_dispatch_resolves_all_names_and_compiles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            worktree = root / "worktree"
            writable = root / "writable"
            worktree.mkdir()
            writable.mkdir()
            source = worktree / "probe.c"
            source.write_text("int probe(void) { return 0; }\n", encoding="utf-8")
            object_file = writable / "probe.o"
            rust_source = worktree / "probe.rs"
            rust_source.write_text("fn main() {}\n", encoding="utf-8")
            rust_binary = writable / "rust-probe"
            dispatch_directory = root / "galadriel-tool-dispatch-fixture"
            dispatch_directory.mkdir(mode=0o700)
            environment = {
                "PATH": os.environ["PATH"],
                "RUSTUP_HOME": str(Path.home() / ".rustup"),
                "TMPDIR": str(writable),
            }
            try:
                records = install_qualification_tool_dispatch(
                    dispatch_directory,
                    environment,
                    git_executable=resolve_candidate_git_executable(),
                    pkg_config_executable=pinned_pkg_config_path(),
                )
                self.assertEqual(
                    19,
                    len(QUALIFICATION_PATH_TOOLS),
                )
                self.assertEqual(
                    len(QUALIFICATION_PATH_TOOLS),
                    len(set(QUALIFICATION_PATH_TOOLS)),
                )
                self.assertEqual(set(records), set(QUALIFICATION_PATH_TOOLS))
                self.assertEqual(
                    tuple(environment["PATH"].split(os.pathsep)[1:]),
                    QUALIFICATION_SYSTEM_PATHS,
                )
                system_path_state = qualification_system_path_state(environment)
                self.assertEqual(
                    set(system_path_state["directories"]),
                    set(QUALIFICATION_SYSTEM_PATHS),
                )
                self.assertTrue(
                    {
                        "/bin/sh",
                        "/usr/bin/git",
                        "/usr/bin/python3",
                        "/usr/bin/cc",
                    }.issubset(system_path_state["collisions"])
                )
                selected_git = Path(records["git"]["resolved_path"])
                developer_identities = EXPECTED_DEVELOPER_TOOL_IDENTITIES[selected_git]
                for name, record in records.items():
                    if name == "git":
                        expected_identity = EXPECTED_DEVELOPER_GIT_IDENTITIES[
                            selected_git
                        ]
                    elif name in {"cc", "clang"}:
                        compiler_driver = qualification_compiler_driver_bytes(
                            selected_git
                        )
                        expected_identity = (
                            hashlib.sha256(compiler_driver).hexdigest(),
                            len(compiler_driver),
                        )
                    elif name in developer_identities:
                        expected_identity = developer_identities[name][1:]
                    else:
                        expected_identity = EXPECTED_TOOL_FILE_IDENTITIES[name]
                    self.assertEqual(
                        (record["sha256"], record["size_bytes"]),
                        expected_identity,
                        name,
                    )
                profile = root / "candidate.sb"
                write_candidate_sandbox_profile(
                    profile,
                    worktree=worktree,
                    source_repo=ROOT,
                    writable_paths=(writable,),
                    tool_read_paths=qualification_tool_read_paths(
                        environment,
                        host_home=Path.home().resolve(),
                    ),
                    allowed_executable_paths=qualification_allowed_executable_paths(
                        records
                    ),
                )
                script = """\
set -eu
dispatch=$1
source=$2
object_file=$3
rust_source=$4
rust_binary=$5
shift 5
for tool
do
    [ "$(command -v "$tool")" = "$dispatch/$tool" ]
done
cc -isysroot "$source.missing-sdk" -c "$source" -o "$object_file"
rustc +1.89.0 "$rust_source" -o "$rust_binary"
"""
                result = run_bounded_process(
                    sandboxed_argv(
                        profile,
                        [
                            "sh",
                            "-c",
                            script,
                            "qualification-tool-probe",
                            str(dispatch_directory),
                            str(source),
                            str(object_file),
                            str(rust_source),
                            str(rust_binary),
                            *(
                                name
                                for name in QUALIFICATION_PATH_TOOLS
                                if name
                                not in QUALIFICATION_PRESENT_BUT_DENIED_UNUSED_TOOLS
                            ),
                        ],
                        environment=environment,
                    ),
                    cwd=worktree,
                    environment=environment,
                    timeout_seconds=10,
                    separate_stderr=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertGreater(object_file.stat().st_size, 0)
                self.assertGreater(rust_binary.stat().st_size, 0)
                self.assertFalse(result.timed_out)
                self.assertFalse(result.output_limit_exceeded)
                self.assertIsNone(result.containment_error)
            finally:
                release_qualification_tool_dispatch(dispatch_directory)

    @unittest.skipUnless(sys.platform == "darwin", "macOS sandbox test")
    def test_candidate_sandbox_denies_absolute_usr_bin_tool_shims(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            worktree = root / "worktree"
            worktree.mkdir()
            dispatch_directory = root / "galadriel-tool-dispatch-fixture"
            dispatch_directory.mkdir(mode=0o700)
            environment = {
                "PATH": os.environ["PATH"],
                "RUSTUP_HOME": str(Path.home() / ".rustup"),
            }
            try:
                dispatch_records = install_qualification_tool_dispatch(
                    dispatch_directory,
                    environment,
                    git_executable=resolve_candidate_git_executable(),
                    pkg_config_executable=pinned_pkg_config_path(),
                )
                tool_read_paths = qualification_tool_read_paths(
                    environment,
                    host_home=Path.home().resolve(),
                )
                self.assertNotIn(Path("/opt/homebrew"), tool_read_paths)
                self.assertNotIn(Path("/opt/anaconda3"), tool_read_paths)
                self.assertNotIn(Path(environment["RUSTUP_HOME"]), tool_read_paths)
                self.assertTrue(
                    set(rust_toolchain_runtime_read_paths(environment)).issubset(
                        tool_read_paths
                    )
                )
                for name in QUALIFICATION_PRESENT_BUT_DENIED_UNUSED_TOOLS:
                    denied_path = Path(dispatch_records[name]["resolved_path"])
                    self.assertFalse(
                        any(
                            binding == denied_path or binding in denied_path.parents
                            for binding in tool_read_paths
                        ),
                        name,
                    )
                profile = root / "candidate.sb"
                write_candidate_sandbox_profile(
                    profile,
                    worktree=worktree,
                    source_repo=ROOT,
                    tool_read_paths=tool_read_paths,
                    allowed_executable_paths=qualification_allowed_executable_paths(
                        dispatch_records
                    ),
                )
                allowed_executable_paths = qualification_allowed_executable_paths(
                    dispatch_records
                )
                framework_path = PINNED_CPYTHON_RUNTIME_EXECUTABLE_IDENTITIES[
                    "python3-framework"
                ][0]
                application_path = PINNED_CPYTHON_RUNTIME_EXECUTABLE_IDENTITIES[
                    "python3-app"
                ][0]
                self.assertNotIn(framework_path, allowed_executable_paths)
                self.assertIn(application_path, allowed_executable_paths)
                for executable in (
                    "/usr/bin/git",
                    "/usr/bin/python3",
                    "/usr/bin/cc",
                    "/usr/bin/clang",
                ):
                    with self.subTest(executable=executable):
                        result = run_bounded_process(
                            [
                                str(SANDBOX_EXECUTABLE),
                                "-f",
                                str(profile),
                                executable,
                                "--version",
                            ],
                            cwd=worktree,
                            environment=environment,
                            timeout_seconds=2,
                            separate_stderr=True,
                        )
                        self.assertNotEqual(result.returncode, 0)
                        self.assertNotIn(b"xcrun_db", result.stderr)
                        self.assertFalse(result.timed_out)
                        self.assertFalse(result.output_limit_exceeded)
                        self.assertIsNone(result.containment_error)

                unlisted = next(
                    (
                        path
                        for path in (
                            Path("/opt/homebrew/bin/rg"),
                            Path("/opt/homebrew/bin/openssl"),
                            Path("/opt/anaconda3/bin/python"),
                        )
                        if path.is_file()
                        and path.resolve(strict=True)
                        not in qualification_allowed_executable_paths(dispatch_records)
                    ),
                    None,
                )
                if unlisted is None:
                    self.skipTest("host has no unlisted executable below /opt")
                unlisted_result = run_bounded_process(
                    [
                        str(SANDBOX_EXECUTABLE),
                        "-f",
                        str(profile),
                        str(unlisted),
                        "--version",
                    ],
                    cwd=worktree,
                    environment=environment,
                    timeout_seconds=2,
                    separate_stderr=True,
                )
                self.assertNotEqual(unlisted_result.returncode, 0)
                self.assertFalse(unlisted_result.timed_out)
                self.assertFalse(unlisted_result.output_limit_exceeded)
                self.assertIsNone(unlisted_result.containment_error)

                escaped_site_file = (
                    PINNED_CPYTHON_VERSION_ROOT
                    / "lib/python3.14/site-packages/pip/__init__.py"
                )
                self.assertTrue(escaped_site_file.is_file())
                self.assertNotIn(
                    PINNED_CPYTHON_VERSION_ROOT,
                    escaped_site_file.resolve(strict=True).parents,
                )
                escaped_site_result = run_bounded_process(
                    sandboxed_argv(
                        profile,
                        [
                            "python3",
                            "-c",
                            f"open({str(escaped_site_file)!r}, 'rb').read(1)",
                        ],
                        environment=environment,
                    ),
                    cwd=worktree,
                    environment=environment,
                    timeout_seconds=2,
                    separate_stderr=True,
                )
                self.assertNotEqual(escaped_site_result.returncode, 0)
                self.assertFalse(escaped_site_result.timed_out)
                self.assertFalse(escaped_site_result.output_limit_exceeded)
                self.assertIsNone(escaped_site_result.containment_error)

                for name in QUALIFICATION_PRESENT_BUT_DENIED_UNUSED_TOOLS:
                    with self.subTest(denied_unused=name):
                        denied_unused_result = run_bounded_process(
                            sandboxed_argv(
                                profile,
                                [name, "--version"],
                                environment=environment,
                            ),
                            cwd=worktree,
                            environment=environment,
                            timeout_seconds=2,
                            separate_stderr=True,
                        )
                        self.assertNotEqual(denied_unused_result.returncode, 0)

                listed_result = run_bounded_process(
                    sandboxed_argv(
                        profile,
                        ["python3", "--version"],
                        environment=environment,
                    ),
                    cwd=worktree,
                    environment=environment,
                    timeout_seconds=2,
                    separate_stderr=True,
                )
                self.assertEqual(listed_result.returncode, 0, listed_result.stderr)
            finally:
                release_qualification_tool_dispatch(dispatch_directory)

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
    def test_process_launch_failure_does_not_start_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            profile = root / "candidate.sb"
            write_candidate_sandbox_profile(
                profile,
                worktree=root,
                source_repo=ROOT,
                tool_read_paths=(test_tool_read_root(),),
            )
            with (
                patch(
                    "qualify_candidate.subprocess.Popen",
                    side_effect=OSError("fixture launch failure"),
                ),
                patch("qualify_candidate._emergency_stop") as emergency_stop,
                self.assertRaisesRegex(ReviewError, "cannot start bounded"),
            ):
                run_bounded_process(
                    sandboxed_argv(
                        profile,
                        [sys.executable, "-I", "-c", "raise SystemExit(0)"],
                    ),
                    cwd=root,
                    environment={"PATH": os.environ["PATH"]},
                    timeout_seconds=1,
                    separate_stderr=True,
                )
            emergency_stop.assert_not_called()

    @unittest.skipUnless(sys.platform == "darwin", "macOS containment test")
    def test_tracker_constructor_failure_stops_and_reaps_launch_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            profile = root / "candidate.sb"
            write_candidate_sandbox_profile(
                profile,
                worktree=root,
                source_repo=ROOT,
                tool_read_paths=(test_tool_read_root(),),
            )
            with (
                patch(
                    "qualify_candidate.MacOSProcessContainment",
                    side_effect=ReviewError("fixture tracker constructor failure"),
                ),
                patch(
                    "qualify_candidate._emergency_stop",
                    wraps=_emergency_stop,
                ) as emergency_stop,
                self.assertRaisesRegex(ReviewError, "fixture tracker constructor"),
            ):
                run_bounded_process(
                    sandboxed_argv(
                        profile,
                        [sys.executable, "-I", "-c", "raise SystemExit(0)"],
                    ),
                    cwd=root,
                    environment={"PATH": os.environ["PATH"]},
                    timeout_seconds=1,
                    separate_stderr=True,
                )
            emergency_stop.assert_called_once()
            process = emergency_stop.call_args.args[0]
            self.assertIsNotNone(process.returncode)
            self.assertTrue(process.stdout.closed)
            self.assertTrue(process.stderr.closed)

    @unittest.skipUnless(sys.platform == "darwin", "macOS containment test")
    def test_clean_exit_first_observed_after_deadline_is_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            profile = root / "candidate.sb"
            write_candidate_sandbox_profile(
                profile,
                worktree=root,
                source_repo=ROOT,
                tool_read_paths=(test_tool_read_root(),),
            )
            timeout_seconds = 30
            original_root_exited = MacOSProcessContainment.root_exited_before_reap
            real_monotonic = time.monotonic
            monotonic_origin: float | None = None
            monotonic_offset_seconds = 0.0
            crossed_deadline = False

            def controlled_monotonic() -> float:
                nonlocal monotonic_origin
                current = real_monotonic()
                if monotonic_origin is None:
                    monotonic_origin = current
                return current + monotonic_offset_seconds

            def observe_exit_after_deadline(
                tracker: MacOSProcessContainment,
            ) -> bool:
                nonlocal crossed_deadline
                nonlocal monotonic_offset_seconds
                root_exited = original_root_exited(tracker)
                if root_exited and not crossed_deadline:
                    assert monotonic_origin is not None
                    monotonic_offset_seconds = (
                        monotonic_origin + timeout_seconds + 0.5 - real_monotonic()
                    )
                    crossed_deadline = True
                return root_exited

            with (
                patch.object(
                    MacOSProcessContainment,
                    "root_exited_before_reap",
                    new=observe_exit_after_deadline,
                ),
                patch.object(
                    qualifier.time,
                    "monotonic",
                    side_effect=controlled_monotonic,
                ),
                patch.object(
                    qualifier,
                    "PROCESS_CLEANUP_TIMEOUT_SECONDS",
                    60.0,
                ),
            ):
                result = run_bounded_process(
                    sandboxed_argv(
                        profile,
                        [sys.executable, "-I", "-c", "raise SystemExit(0)"],
                    ),
                    cwd=root,
                    environment={"PATH": os.environ["PATH"]},
                    timeout_seconds=timeout_seconds,
                    separate_stderr=True,
                )
            self.assertTrue(crossed_deadline)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.timed_out)
            self.assertFalse(result.output_limit_exceeded)
            self.assertIsNone(result.containment_error)

    @unittest.skipUnless(sys.platform == "darwin", "macOS containment test")
    def test_timeout_and_output_cleanup_terminate_before_reap(self) -> None:
        cases = (
            (
                "timeout",
                "import time; time.sleep(5)",
                1,
                1_024,
                True,
                False,
                False,
            ),
            (
                "output",
                "import os, time; os.write(1, b'x' * 4096); time.sleep(5)",
                30,
                8,
                False,
                True,
                False,
            ),
            (
                "output_cleanup_crosses_deadline",
                "import os, time; os.write(1, b'x' * 4096); time.sleep(5)",
                30,
                8,
                False,
                True,
                True,
            ),
        )
        for (
            name,
            source,
            timeout_seconds,
            stdout_bound,
            expected_timeout,
            expected_output_limit,
            cross_deadline_after_first_cleanup,
        ) in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                profile = root / "candidate.sb"
                write_candidate_sandbox_profile(
                    profile,
                    worktree=root,
                    source_repo=ROOT,
                    tool_read_paths=(test_tool_read_root(),),
                )
                events: list[str] = []
                original_terminate = MacOSProcessContainment.terminate_before_root_reap
                original_wait = subprocess.Popen.wait
                real_monotonic = time.monotonic
                monotonic_origin: float | None = None
                monotonic_offset_seconds = 0.0

                def controlled_monotonic() -> float:
                    nonlocal monotonic_origin
                    current = real_monotonic()
                    if monotonic_origin is None:
                        monotonic_origin = current
                    return current + monotonic_offset_seconds

                def record_terminate(
                    tracker: MacOSProcessContainment,
                    grace_seconds: float = 2.0,
                ) -> bool:
                    nonlocal monotonic_offset_seconds
                    events.append("terminate")
                    had_live = original_terminate(tracker, grace_seconds)
                    if (
                        cross_deadline_after_first_cleanup
                        and events.count("terminate") == 1
                    ):
                        assert monotonic_origin is not None
                        monotonic_offset_seconds = (
                            monotonic_origin + timeout_seconds + 0.5 - real_monotonic()
                        )
                    return had_live

                def record_wait(
                    process: subprocess.Popen[bytes],
                    timeout: float | None = None,
                ) -> int:
                    events.append("reap")
                    return original_wait(process, timeout)

                with (
                    patch.object(
                        MacOSProcessContainment,
                        "terminate_before_root_reap",
                        new=record_terminate,
                    ),
                    patch.object(subprocess.Popen, "wait", new=record_wait),
                    patch.object(
                        qualifier.time,
                        "monotonic",
                        side_effect=controlled_monotonic,
                    ),
                    patch.object(
                        qualifier,
                        "PROCESS_CLEANUP_TIMEOUT_SECONDS",
                        60.0,
                    ),
                ):
                    result = run_bounded_process(
                        sandboxed_argv(
                            profile,
                            [sys.executable, "-I", "-c", source],
                        ),
                        cwd=root,
                        environment={"PATH": os.environ["PATH"]},
                        timeout_seconds=timeout_seconds,
                        separate_stderr=True,
                        max_stdout_bytes=stdout_bound,
                    )
                self.assertEqual(result.timed_out, expected_timeout)
                self.assertEqual(
                    result.output_limit_exceeded,
                    expected_output_limit,
                )
                self.assertEqual(events.count("terminate"), 1)
                self.assertLess(events.index("terminate"), events.index("reap"))

    @unittest.skipUnless(sys.platform == "darwin", "macOS containment test")
    def test_cleanup_only_failure_is_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            profile = root / "candidate.sb"
            write_candidate_sandbox_profile(
                profile,
                worktree=root,
                source_repo=ROOT,
                tool_read_paths=(test_tool_read_root(),),
            )

            def close_then_report(**kwargs: object) -> str:
                detail = _close_process_resources(**kwargs)
                if detail is not None:
                    raise AssertionError(detail)
                return "fixture cleanup failure"

            with (
                patch(
                    "qualify_candidate._close_process_resources",
                    side_effect=close_then_report,
                ),
                self.assertRaisesRegex(
                    ProcessContainmentError,
                    "fixture cleanup failure",
                ),
            ):
                run_bounded_process(
                    sandboxed_argv(
                        profile,
                        [sys.executable, "-I", "-c", "print('complete')"],
                    ),
                    cwd=root,
                    environment={"PATH": os.environ["PATH"]},
                    timeout_seconds=2,
                    separate_stderr=True,
                )

    @unittest.skipUnless(sys.platform == "darwin", "macOS containment test")
    def test_sandboxed_double_fork_escape_aborts_without_root_reap(self) -> None:
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
    deadline = time.monotonic() + 2
    while not pathlib.Path(sys.argv[1]).exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    os._exit(0)
pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding="ascii")
os.close(0)
os.close(1)
os.close(2)
marker = pathlib.Path(sys.argv[2])
deadline = time.monotonic() + 10
while not marker.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
pathlib.Path(sys.argv[3]).write_text("exited\\n", encoding="ascii")
"""
        escaped_pid: int | None = None
        root_processes: list[subprocess.Popen[bytes]] = []
        original_popen = subprocess.Popen

        def capture_process(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = original_popen(*args, **kwargs)
            root_processes.append(process)
            return process

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            worktree = root / "worktree"
            writable = root / "writable"
            worktree.mkdir()
            writable.mkdir()
            pid_file = writable / "escaped.pid"
            exit_marker = writable / "allow-exit"
            exited_file = writable / "exited"
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
                with (
                    patch(
                        "qualify_candidate.subprocess.Popen",
                        side_effect=capture_process,
                    ),
                    self.assertRaises(ProcessContainmentError),
                ):
                    run_bounded_process(
                        sandboxed_argv(
                            profile,
                            [
                                sys.executable,
                                "-I",
                                "-c",
                                source,
                                str(pid_file),
                                str(exit_marker),
                                str(exited_file),
                            ],
                        ),
                        cwd=writable,
                        environment={"PATH": os.environ["PATH"]},
                        timeout_seconds=2,
                        separate_stderr=True,
                    )
                elapsed = time.monotonic() - started
                self.assertLess(elapsed, 10.0)
                self.assertEqual(len(root_processes), 1)
                self.assertIsNone(root_processes[0].returncode)
                deadline = time.monotonic() + 2
                while not pid_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if pid_file.exists():
                    escaped_pid = int(pid_file.read_text(encoding="ascii"))
                self.assertIsNotNone(escaped_pid)
            finally:
                if escaped_pid is None and pid_file.exists():
                    escaped_pid = int(pid_file.read_text(encoding="ascii"))
                if escaped_pid is not None:
                    exit_marker.write_text("exit\n", encoding="ascii")
                    deadline = time.monotonic() + 2
                    while not exited_file.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(exited_file.exists())
                for root_process in root_processes:
                    root_process.wait(timeout=2)

    @unittest.skipUnless(sys.platform == "darwin", "macOS containment test")
    def test_interrupt_cleans_and_reaps_candidate_process(self) -> None:
        source = """
import pathlib
import os
import sys
import time

pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding="ascii")
marker = pathlib.Path(sys.argv[2])
deadline = time.monotonic() + 10
while not marker.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
"""
        candidate_pid: int | None = None
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            worktree = root / "worktree"
            writable = root / "writable"
            worktree.mkdir()
            writable.mkdir()
            pid_file = writable / "candidate.pid"
            exit_marker = writable / "allow-exit"
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

            def close_then_report(**kwargs: object) -> str:
                detail = _close_process_resources(**kwargs)
                if detail is not None:
                    raise AssertionError(detail)
                return "fixture cleanup after primary failure"

            try:
                with (
                    patch(
                        "qualify_candidate.selectors.DefaultSelector.select",
                        side_effect=interrupt_after_start,
                    ),
                    patch(
                        "qualify_candidate._close_process_resources",
                        side_effect=close_then_report,
                    ),
                    self.assertRaises(KeyboardInterrupt) as caught,
                ):
                    run_bounded_process(
                        sandboxed_argv(
                            profile,
                            [
                                sys.executable,
                                "-I",
                                "-c",
                                source,
                                str(pid_file),
                                str(exit_marker),
                            ],
                        ),
                        cwd=writable,
                        environment={"PATH": os.environ["PATH"]},
                        timeout_seconds=2,
                        separate_stderr=True,
                    )
                self.assertIn(
                    "fixture cleanup after primary failure",
                    "\n".join(getattr(caught.exception, "__notes__", ())),
                )
                if pid_file.exists():
                    candidate_pid = int(pid_file.read_text(encoding="ascii"))
                if candidate_pid is not None:
                    with self.assertRaises(ProcessLookupError):
                        os.kill(candidate_pid, 0)
            finally:
                exit_marker.write_text("exit\n", encoding="ascii")

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

    def test_outer_manifest_must_bind_the_exact_evidence_file_set(self) -> None:
        names = (
            "SHA256SUMS",
            "config.json",
            "manifest.json",
            "report.md",
            "summary.json",
            "trials.jsonl",
        )
        artifacts = {
            f"candidate-evidence/{name}": {
                "path": f"candidate-evidence/{name}",
                "sha256": hashlib.sha256(name.encode("utf-8")).hexdigest(),
                "size_bytes": len(name),
            }
            for name in names
        }
        expected = {
            name: {
                "sha256": artifacts[f"candidate-evidence/{name}"]["sha256"],
                "size_bytes": len(name),
            }
            for name in names
        }
        self.assertEqual(candidate_evidence_outer_artifacts(artifacts), expected)

        missing = copy.deepcopy(artifacts)
        del missing["candidate-evidence/trials.jsonl"]
        with self.assertRaisesRegex(ReviewError, "another candidate-evidence file set"):
            candidate_evidence_outer_artifacts(missing)

        extra = copy.deepcopy(artifacts)
        extra["candidate-evidence/forged.json"] = {
            "path": "candidate-evidence/forged.json",
            "sha256": "f" * 64,
            "size_bytes": 1,
        }
        with self.assertRaisesRegex(ReviewError, "another candidate-evidence file set"):
            candidate_evidence_outer_artifacts(extra)

    def test_finalizer_recomputation_must_equal_the_qualifier_record(self) -> None:
        tracked_config = b'{"study_id":"fixture"}\n'
        expectations = SimpleNamespace(
            commit=COMMIT,
            tree=TREE,
            tracked_config_path="evidence/galadriel-0.9-candidate.json",
            tracked_config_bytes=tracked_config,
            workspace_manifest_sha256="a" * 64,
            cargo_lock_sha256="b" * 64,
            runner_binary_sha256="c" * 64,
            rustc_verbose="rustc fixture",
            cargo_version="cargo fixture",
            target_os="macos",
            target_arch="aarch64",
        )
        artifacts = {"config.json": {"sha256": "d" * 64, "size_bytes": 10}}
        validated = SimpleNamespace(
            semantic_sha256="e" * 64,
            artifacts=artifacts,
        )
        qualification = {
            "candidate_evidence_validation": {
                "status": "PASS",
                "semantic_sha256": validated.semantic_sha256,
                "artifacts": artifacts,
                "expectations": {
                    "commit": expectations.commit,
                    "tree": expectations.tree,
                    "tracked_config_path": expectations.tracked_config_path,
                    "tracked_config_sha256": hashlib.sha256(tracked_config).hexdigest(),
                    "workspace_manifest_sha256": (
                        expectations.workspace_manifest_sha256
                    ),
                    "cargo_lock_sha256": expectations.cargo_lock_sha256,
                    "runner_binary_sha256": expectations.runner_binary_sha256,
                    "rustc_verbose": expectations.rustc_verbose,
                    "cargo_version": expectations.cargo_version,
                    "target_os": expectations.target_os,
                    "target_arch": expectations.target_arch,
                },
            }
        }
        validate_candidate_evidence_validation_record(
            qualification,
            expectations,
            validated,
        )

        forged = copy.deepcopy(qualification)
        forged["candidate_evidence_validation"]["semantic_sha256"] = "f" * 64
        with self.assertRaisesRegex(ReviewError, "finalizer recomputation"):
            validate_candidate_evidence_validation_record(
                forged,
                expectations,
                validated,
            )

    def test_candidate_evidence_receipt_binds_one_unchanged_direct_runner(self) -> None:
        path = "/private/tmp/evidence-runner/galadriel-evidence"
        identity = {
            "invoked_path": path,
            "resolved_path": path,
            "sha256": "a" * 64,
            "size_bytes": 1,
            "uid": 501,
            "gid": 20,
            "mode": 0o500,
        }
        qualification = {
            "commands": [
                {
                    "name": "candidate-evidence",
                    "subject_executable": {
                        "status": "UNCHANGED",
                        "identity": identity,
                    },
                }
            ]
        }
        self.assertEqual(
            candidate_evidence_subject_identity(qualification),
            identity,
        )

        writable = copy.deepcopy(qualification)
        writable["commands"][0]["subject_executable"]["identity"]["mode"] = 0o700
        with self.assertRaisesRegex(ReviewError, "runner identity is invalid"):
            candidate_evidence_subject_identity(writable)

        duplicate = copy.deepcopy(qualification)
        duplicate["commands"].append(copy.deepcopy(duplicate["commands"][0]))
        with self.assertRaisesRegex(ReviewError, "receipt is not unique"):
            candidate_evidence_subject_identity(duplicate)

    def test_finalizer_repeats_complete_candidate_evidence_validation(self) -> None:
        names = (
            "SHA256SUMS",
            "config.json",
            "manifest.json",
            "report.md",
            "summary.json",
            "trials.jsonl",
        )
        inner_artifacts = {
            name: {
                "sha256": hashlib.sha256(name.encode("utf-8")).hexdigest(),
                "size_bytes": len(name),
            }
            for name in names
        }
        outer_artifacts = {
            f"candidate-evidence/{name}": {
                "path": f"candidate-evidence/{name}",
                **inner_artifacts[name],
            }
            for name in names
        }
        tracked_config = b"{}\n"
        expected = SimpleNamespace(
            commit=COMMIT,
            tree=TREE,
            tracked_config_path="evidence/galadriel-0.9-candidate.json",
            tracked_config_bytes=tracked_config,
            workspace_manifest_sha256="a" * 64,
            cargo_lock_sha256="b" * 64,
            runner_binary_sha256="c" * 64,
            rustc_verbose="rustc fixture",
            cargo_version="cargo fixture",
            target_os="macos",
            target_arch="aarch64",
        )
        validated = SimpleNamespace(
            artifacts=inner_artifacts,
            config_binding={"study_design_status": "PASS"},
            acceptance={"status": "FAIL"},
            semantic_sha256="d" * 64,
        )
        qualification = {
            "candidate_evidence_validation": {
                "status": "PASS",
                "semantic_sha256": validated.semantic_sha256,
                "artifacts": inner_artifacts,
                "expectations": {
                    "commit": COMMIT,
                    "tree": TREE,
                    "tracked_config_path": expected.tracked_config_path,
                    "tracked_config_sha256": hashlib.sha256(tracked_config).hexdigest(),
                    "workspace_manifest_sha256": (expected.workspace_manifest_sha256),
                    "cargo_lock_sha256": expected.cargo_lock_sha256,
                    "runner_binary_sha256": expected.runner_binary_sha256,
                    "rustc_verbose": expected.rustc_verbose,
                    "cargo_version": expected.cargo_version,
                    "target_os": expected.target_os,
                    "target_arch": expected.target_arch,
                },
            }
        }
        evidence_root = Path("/retained/candidate-evidence")
        with patch(
            "finalize_release.validate_candidate_evidence_bundle",
            return_value=validated,
        ) as shared_validator:
            self.assertIs(
                validate_finalizer_candidate_evidence(
                    evidence_root,
                    qualification=qualification,
                    manifest_artifacts=outer_artifacts,
                    expected=expected,
                ),
                validated,
            )
        shared_validator.assert_called_once_with(
            evidence_root,
            expected=expected,
            expected_outer_artifacts=inner_artifacts,
        )

        with (
            patch(
                "finalize_release.validate_candidate_evidence_bundle",
                side_effect=ReviewError("structural evidence failure"),
            ),
            self.assertRaisesRegex(ReviewError, "structural evidence failure"),
        ):
            validate_finalizer_candidate_evidence(
                evidence_root,
                qualification=qualification,
                manifest_artifacts=outer_artifacts,
                expected=expected,
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
            "fuzz_runners": {},
            "environment_contract": {},
            "repository_control": {},
            "sandbox": {},
            "advisory_database": {},
            "deep_campaigns_requested": True,
            "evidence_config": "evidence/galadriel-0.9-candidate.json",
            "commands": [],
            "auxiliary_commands": [],
            "acceptance": {},
            "candidate_evidence_validation": {
                "status": "PASS",
                "semantic_sha256": "e" * 64,
                "artifacts": {},
                "expectations": {},
            },
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
            evidence_runner_root = private_root / "evidence-runner"
            rustup_home = host_home / ".rustup"
            home_tool_paths = (host_home / ".cargo" / "bin",)
            tool_read_paths = (Path("/opt/homebrew"),)
            read_only_paths = (
                *advisory_databases,
                allowed_signers_snapshot,
                evidence_runner_root,
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
            allowed_home_read_paths = home_tool_paths
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
                "candidate_evidence_runner_root": str(evidence_runner_root),
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
            sandbox_executables = {
                name: tool_file_record(name) for name in QUALIFICATION_PATH_TOOLS
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
                    allowed_executable_paths=qualification_allowed_executable_paths(
                        sandbox_executables
                    ),
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
                "tool_files": {"executables": sandbox_executables},
                "commands": [
                    {
                        "name": "candidate-evidence",
                        "subject_executable": {
                            "status": "UNCHANGED",
                            "identity": {
                                "invoked_path": str(
                                    evidence_runner_root / "galadriel-evidence"
                                ),
                                "resolved_path": str(
                                    evidence_runner_root / "galadriel-evidence"
                                ),
                                "sha256": "a" * 64,
                                "size_bytes": 1,
                                "uid": 501,
                                "gid": 20,
                                "mode": 0o500,
                            },
                        },
                    }
                ],
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
        runtime_libraries = {
            name: runtime_library_record(name)
            for name in EXPECTED_RUNTIME_LIBRARY_IDENTITIES
        }
        home_tool_directories = tuple(
            sorted(
                {
                    Path(executables[name]["invoked_path"]).parent
                    for name in QUALIFICATION_PATH_TOOLS
                },
                key=lambda item: str(item),
            )
        )
        rustup_home = Path("/fixture/tools")
        system_roots = tuple(Path(path) for path in SANDBOX_SYSTEM_READ_PATHS)

        def is_system(path: Path) -> bool:
            return any(path == root or root in path.parents for root in system_roots)

        tool_read_paths: set[Path] = set()
        for name in QUALIFICATION_PATH_TOOLS:
            if name in QUALIFICATION_PRESENT_BUT_DENIED_UNUSED_TOOLS:
                continue
            invoked = Path(executables[name]["invoked_path"])
            resolved = Path(executables[name]["resolved_path"])
            if not is_system(invoked.parent):
                tool_read_paths.add(invoked.parent)
            if name == "python3":
                tool_read_paths.add(PINNED_CPYTHON_VERSION_ROOT)
                for _load_path, resolved_path, _sha256, _size, _mode in (
                    PINNED_CPYTHON_RUNTIME_LIBRARY_IDENTITIES.values()
                ):
                    tool_read_paths.add(resolved_path)
            elif not is_system(resolved):
                tool_read_paths.add(resolved)
        for record in runtime_libraries.values():
            for field in ("invoked_path", "resolved_path"):
                path = Path(record[field])
                if path != rustup_home and rustup_home not in path.parents:
                    tool_read_paths.add(path)
        tool_read_paths.add(rustup_home / "settings.toml")
        for toolchain in PINNED_RUST_TOOLCHAIN_RUNTIME_IDENTITIES:
            root = rustup_home / "toolchains" / toolchain
            tool_read_paths.update(
                root / component
                for component in PINNED_RUST_TOOLCHAIN_RUNTIME_COMPONENTS
            )
        tool_read_directories = tuple(sorted(tool_read_paths, key=lambda item: str(item)))
        qualification = {
            "tool_files": {
                "status": "UNCHANGED",
                "executables": executables,
                "runtime_libraries": runtime_libraries,
                "compiler": compiler_input_record(),
                "python_runtime_tree": copy.deepcopy(
                    PINNED_CPYTHON_RUNTIME_TREE_IDENTITY
                ),
                "rust_toolchain_runtime": rust_toolchain_runtime_record(
                    rustup_home
                ),
            },
            "sandbox": {
                "bindings": {
                    "host_home": "/fixture",
                    "rustup_home": str(rustup_home),
                    "home_tool_paths": [str(path) for path in home_tool_directories],
                    "tool_read_paths": [str(path) for path in tool_read_directories],
                },
            },
        }
        validate_qualification_tool_files(qualification)
        validate_qualification_tool_bindings(qualification)

        drifted_tree = copy.deepcopy(qualification)
        drifted_tree["tool_files"]["python_runtime_tree"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ReviewError, "identity set is incomplete"):
            validate_qualification_tool_files(drifted_tree)

        drifted_compiler = copy.deepcopy(qualification)
        drifted_compiler["tool_files"]["compiler"]["sdk"]["settings"][
            "sha256"
        ] = "0" * 64
        with self.assertRaisesRegex(ReviewError, "macOS SDK identity"):
            validate_qualification_tool_files(drifted_compiler)

        drifted_rust_tree = copy.deepcopy(qualification)
        drifted_rust_tree["tool_files"]["rust_toolchain_runtime"]["toolchains"][
            "1.89.0-aarch64-apple-darwin"
        ]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ReviewError, "Rust runtime tree is invalid"):
            validate_qualification_tool_files(drifted_rust_tree)

        omitted_rust_read_root = copy.deepcopy(qualification)
        omitted_rust_read_root["sandbox"]["bindings"]["tool_read_paths"].remove(
            str(
                rustup_home
                / "toolchains/1.89.0-aarch64-apple-darwin/libexec"
            )
        )
        with self.assertRaisesRegex(ReviewError, "tool roots disagree"):
            validate_qualification_tool_bindings(omitted_rust_read_root)

        omitted = copy.deepcopy(qualification)
        omitted["tool_files"]["executables"].pop("cargo")
        with self.assertRaisesRegex(ReviewError, "identity set is incomplete"):
            validate_qualification_tool_files(omitted)

        omitted_library = copy.deepcopy(qualification)
        omitted_library["tool_files"]["runtime_libraries"].pop("fuzz-asan")
        with self.assertRaisesRegex(ReviewError, "identity set is incomplete"):
            validate_qualification_tool_files(omitted_library)

        drifted_library = copy.deepcopy(qualification)
        drifted_library["tool_files"]["runtime_libraries"]["fuzz-asan"]["sha256"] = (
            "0" * 64
        )
        with self.assertRaisesRegex(ReviewError, "runtime-library metadata"):
            validate_qualification_tool_files(drifted_library)

        writable_library = copy.deepcopy(qualification)
        writable_library["tool_files"]["runtime_libraries"]["fuzz-asan"]["mode"] = (
            0o666
        )
        with self.assertRaisesRegex(ReviewError, "runtime-library metadata"):
            validate_qualification_tool_files(writable_library)

        moved_library = copy.deepcopy(qualification)
        moved_library["tool_files"]["runtime_libraries"]["fuzz-asan"][
            "resolved_path"
        ] = (
            "/fixture/tools/toolchains/nightly-2026-06-16-aarch64-apple-darwin/"
            "lib/rustlib/aarch64-apple-darwin/lib/another-asan.dylib"
        )
        with self.assertRaisesRegex(ReviewError, "runtime-library metadata"):
            validate_qualification_tool_files(moved_library)

        writable = copy.deepcopy(qualification)
        writable["tool_files"]["executables"]["cargo"]["mode"] = 0o775
        with self.assertRaisesRegex(ReviewError, "metadata is invalid"):
            validate_qualification_tool_files(writable)

        another_proxy = copy.deepcopy(qualification)
        another_proxy["tool_files"]["executables"]["rustc"]["resolved_path"] = (
            "/fixture/tools/another-rustup/rustup"
        )
        with self.assertRaisesRegex(ReviewError, "proxies disagree"):
            validate_qualification_tool_files(another_proxy)

        another_shell = copy.deepcopy(qualification)
        another_shell["tool_files"]["executables"]["sh"]["resolved_path"] = (
            "/usr/bin/sh"
        )
        with self.assertRaisesRegex(ReviewError, "another system tool"):
            validate_qualification_tool_files(another_shell)

        usr_bin_git = copy.deepcopy(qualification)
        git_record = usr_bin_git["tool_files"]["executables"]["git"]
        git_record.update(
            {
                "invoked_path": "/usr/bin/git",
                "resolved_path": "/usr/bin/git",
                "sha256": (
                    "179301dcb41ea78accc3fa0048a7e6f6710d891945a751a34addd622020c1818"
                ),
                "size_bytes": 118_928,
            }
        )
        with self.assertRaisesRegex(ReviewError, "tool dispatch|direct developer Git"):
            validate_qualification_tool_files(usr_bin_git)

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
                    *QUALIFICATION_PYTHON_FLAGS,
                    "repo_work/audit_tracked_files.py",
                    "--repo",
                    ".",
                    "--out",
                    str(root / "source-inventory"),
                ]
            },
            "candidate-evidence-build": {
                "argv": [
                    "cargo",
                    "build",
                    "--release",
                    "--locked",
                    "-p",
                    "galadriel-eval",
                    "--bin",
                    "galadriel-evidence",
                ]
            },
            "candidate-evidence": {
                "argv": [
                    "/private/tmp/evidence-runner/galadriel-evidence",
                    "--config",
                    "evidence/galadriel-0.9-candidate.json",
                    "--out",
                    str(root / "candidate-evidence"),
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
        self.assertEqual(specifications[-2].name, "candidate-evidence-build")
        self.assertEqual(
            specifications[-1].subject_executable,
            "/private/tmp/evidence-runner/galadriel-evidence",
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
