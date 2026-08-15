#!/usr/bin/env python3
"""Generate or verify the canonical frozen audit-input manifest."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import os
import re
import stat
import sys
import tempfile
import tomllib
from datetime import date
from pathlib import Path
from typing import Any, NamedTuple

from check_public_api import bounded_diagnostic, release_tool_environment
from common import (
    ReviewError,
    assert_no_replace_refs,
    canonical_relative_parts,
    canonical_json,
    git,
    loads_json,
    validate_json_structure,
)
from release_assurance import canonical_repository_identity, run_bounded_host_command


SCHEMA = "galadriel.frozen-audit-inputs.v2"
PUBLICATION_CHANNEL = "review-gated GitHub research source release"
UNPUBLISHED_SOURCE_PREPARATION_STATE = "UNPUBLISHED_CANDIDATE"
DATE_BOUND_SOURCE_PREPARATION_STATE = "DATE_BOUND_CANDIDATE"
AUDIT_DATE_SEMANTICS = (
    "Maintainer-local calendar date of the latest audit-input update. It cannot "
    "precede any retained inspection or observation date at its declared precision."
)
THREAT_REGISTER_PATH = "release/0.9.0/audit/threat-register.json"
THREAT_STATUS_LIVING = "LIVING_UNTIL_CANDIDATE_FREEZE"
THREAT_STATUS_FROZEN = "FROZEN_AT_CANDIDATE"
VALID_THREAT_STATUSES = frozenset({THREAT_STATUS_LIVING, THREAT_STATUS_FROZEN})
EXPECTED_BASELINE_REPOSITORY = "https://github.com/sepahead/galadriel"
EXPECTED_BASELINE_COMMIT = "94e2f8cc01f352d2bf899b7f656997f143a2588f"
EXPECTED_BASELINE_TREE = "9d9b3f9c2eaa26f50ffcc7ab16c0d38652a9f6c0"
RELEASE_INPUTS = (
    "AGENTS.md",
    "CLAUDE.mdc",
    ".github/workflows/ci.yml",
    ".github/workflows/deep-quality.yml",
    ".ncp-consumer",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "deny.toml",
    "fuzz/Cargo.toml",
    "fuzz/Cargo.lock",
    "fuzz/deny.toml",
    "release/0.9.0/audit-inputs.json",
    "release/0.9.0/ecosystem-cut.json",
    "release/0.9.0/handoff-source.json",
    "release/0.9.0/tasks.json",
    "release/0.9.0/task-closure-plan.json",
    "release/0.9.0/task-dispositions.json",
    "release/0.9.0/requirements-ledger.json",
    "release/0.9.0/local-convergence-schema.json",
    "release/0.9.0/RELEASE-NOTES.md",
    "release/0.9.0/RELEASE-RUNBOOK.md",
    "release/0.9.0/VERSION-ADAPTATION.md",
    "release/0.9.0/claims.json",
    "release/0.9.0/audit/threat-register.json",
    "release/0.9.0/evidence/ACCEPTANCE-CRITERIA.md",
    "release/0.9.0/reviews/REVIEW-METHOD.md",
    "release/0.9.0/reviews/REVIEW-COMMENTS.md",
    "release/0.9.0/api/galadriel-core.baseline.txt",
    "release/0.9.0/api/galadriel-core.0.9.0.txt",
    "release/0.9.0/api/galadriel-dependence.0.9.0.txt",
    "release/0.9.0/evidence/galadriel-core-api.diff",
    "evidence/galadriel-0.9-candidate.json",
    "crates/galadriel-ncp/tests/fixtures/crebain_clean_capture.jsonl",
    "CITATION.cff",
    "RELEASE-POLICY.md",
    "SECURITY.md",
    "docs/ADVISORY-BOUNDARY.md",
    "docs/CLAIMS.md",
    "docs/CONFIGURATION-CONTRACT.md",
    "docs/DEPENDENCY-POLICY.md",
    "docs/ECOSYSTEM-CONNECTIONS.md",
    "docs/PRODUCER-CONTRACT.md",
    "docs/RELATED-WORK.md",
    "docs/SECURE-DEPLOYMENT.md",
    "docs/STATE-MACHINE.md",
    "docs/STATISTICAL-CONTRACT.md",
    "docs/THREAT-MODEL.md",
    "deploy/README.md",
    "deploy/galadriel-security-profile.example.json",
    "scripts/release_audit.py",
    "scripts/secure_deployment.py",
    "repo_work/README.md",
    "repo_work/audit_tracked_files.py",
    "repo_work/build_task_dispositions.py",
    "repo_work/check_feature_graph.py",
    "repo_work/check_focused_mutation.py",
    "repo_work/check_frozen_head.py",
    "repo_work/check_public_api.py",
    "repo_work/check_vulnerable_features.py",
    "repo_work/common.py",
    "repo_work/finalize_release.py",
    "repo_work/freeze_audit_inputs.py",
    "repo_work/local_convergence.py",
    "repo_work/make_review_packets.py",
    "repo_work/package_release_assets.py",
    "repo_work/prepare_mutation_evidence.py",
    "repo_work/process_containment.py",
    "repo_work/qualification_artifacts.py",
    "repo_work/qualify_candidate.py",
    "repo_work/release_assurance.py",
    "repo_work/reproduce_baseline.py",
    "repo_work/run_broad_mutation.py",
    "repo_work/scan_claim_language.py",
    "repo_work/verify_release_python_runtime.sh",
    "repo_work/tests/test_candidate_evidence_bundle.py",
    "repo_work/tests/test_finalize_qualification.py",
    "repo_work/tests/test_evidence_batch_transaction.py",
    "repo_work/tests/test_file_mode_identity.py",
    "repo_work/tests/test_host_process_bounds.py",
    "repo_work/tests/test_package_release_assets.py",
    "repo_work/tests/test_qualify_candidate_evidence.py",
    "repo_work/tests/test_qualification_artifacts.py",
    "repo_work/tests/test_release_audit_snapshot.py",
    "repo_work/tests/test_release_assurance.py",
    "repo_work/tests/test_review_tools.py",
    "repo_work/tests/test_task_dispositions.py",
    "repo_work/verify_evidence_manifest.py",
    "scripts/tests/test_release_audit.py",
)
BASELINE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "deny.toml",
)

RELEASE = {
    "version": "0.9.0",
    "author": "Sepehr Mahmoudian",
    "doi": None,
    "zenodo": None,
}
SIGNATURE_FORMAT = "OpenSSH SSHSIG"
SIGNATURE_NAMESPACE = "galadriel-release-audit"
SIGNATURE_PRINCIPAL = "sepmhn@gmail.com"
REF_INPUT_NOTE = (
    "Refs are mutable discovery inputs. Object identities and the signed "
    "candidate tag, not ref names alone, govern release qualification."
)
SCOPE_NOTE = (
    "This freezes instruction and baseline inputs only. Candidate outputs, "
    "qualification results, independent review, DOI, Zenodo, and deployment "
    "qualification are not asserted by this manifest."
)
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
HEX_OBJECT_ID = re.compile(r"[0-9a-f]{40}\Z")
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_HISTORICAL_TAGS = 4_096
MAX_SIGNATURE_BYTES = 64 * 1024
MAX_ALLOWED_SIGNERS_BYTES = 4 * 1024
MAX_HANDOFF_ENTRIES = 4_096
MAX_HANDOFF_FILE_BYTES = 64 * 1024 * 1024
MAX_HANDOFF_SYMLINK_BYTES = 16 * 1024
MAX_HANDOFF_AGGREGATE_BYTES = 512 * 1024 * 1024
MAX_HANDOFF_DEPTH = 128
MAX_HANDOFF_PATH_BYTES = 4 * 1024
MAX_HANDOFF_COMPONENT_BYTES = 255
MAX_ROOT_PARENT_ENTRIES = 32_768
MAX_RELEASE_INPUT_INDEX_BYTES = 4 * 1024 * 1024
MAX_RELEASE_INPUT_FILE_BYTES = 256 * 1024 * 1024
MAX_RELEASE_INPUT_AGGREGATE_BYTES = 4 * 1024 * 1024 * 1024
MAX_SOURCE_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_SOURCE_JSON_DEPTH = 64
MAX_SOURCE_JSON_NODES = 250_000
MAX_THREAT_REGISTER_BYTES = 4 * 1024 * 1024
HOST_IDENTITY_TIMEOUT_SECONDS = 30
MAX_HOST_IDENTITY_STDOUT_BYTES = 64 * 1024
MAX_HOST_IDENTITY_STDERR_BYTES = 64 * 1024


class HeldRoot(NamedTuple):
    """One root and its parent held by no-follow directory descriptors."""

    absolute: Path
    name: str
    parent_descriptor: int
    descriptor: int
    identity: tuple[int, ...]
    label: str


class RootedRead(NamedTuple):
    """Bytes and identity captured from one descriptor-rooted regular file."""

    document: bytes
    identity: tuple[int, ...]


class HandoffInventory(NamedTuple):
    """One bounded identity inventory from a held handoff root."""

    directories: dict[str, tuple[int, ...]]
    regular_files: dict[str, tuple[int, ...]]
    symlinks: dict[str, tuple[tuple[int, ...], str, bytes]]
    aggregate_size: int


class ReleaseIndexEntry(NamedTuple):
    """One bounded entry from the complete relevant stage-zero index capture."""

    mode: str
    blob: str
    stage: int


class ReleaseInputSnapshot(NamedTuple):
    """Release rows and source semantics from one coherent index transaction."""

    rows: list[dict[str, Any]]
    source_documents: tuple[dict[str, Any], dict[str, Any], str, str] | None


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Return the fields that bind one file-system object instance."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _close_descriptors(descriptors: list[int], *, context: str) -> None:
    """Close every descriptor and preserve an active primary failure."""

    close_error: BaseException | None = None
    for descriptor in descriptors:
        if descriptor < 0:
            continue
        try:
            os.close(descriptor)
        except BaseException as error:
            if close_error is None:
                close_error = error
    if close_error is None:
        return
    active_error = sys.exception()
    if active_error is not None:
        active_error.add_note(f"{context} descriptor cleanup also failed")
        return
    raise ReviewError(f"cannot close {context} descriptors") from close_error


def _remove_created_paths(paths: list[Path], *, context: str) -> None:
    """Remove each partial output and preserve an active primary failure."""

    cleanup_error: BaseException | None = None
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except BaseException as error:
            if cleanup_error is None:
                cleanup_error = error
    if cleanup_error is None:
        return
    active_error = sys.exception()
    if active_error is not None:
        active_error.add_note(f"{context} output cleanup also failed")
        return
    raise ReviewError(f"cannot remove partial {context} outputs") from cleanup_error


def _directory_flags() -> int:
    """Return the required no-follow flags for one directory descriptor."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    directory = getattr(os, "O_DIRECTORY", None)
    close_on_exec = getattr(os, "O_CLOEXEC", None)
    if (
        no_follow is None
        or non_block is None
        or directory is None
        or close_on_exec is None
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.readlink not in os.supports_dir_fd
        or os.scandir not in os.supports_fd
    ):
        raise ReviewError("descriptor-relative no-follow traversal is unavailable")
    return os.O_RDONLY | no_follow | non_block | directory | close_on_exec


def _file_flags() -> int:
    """Return the required no-follow flags for one regular-file descriptor."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    close_on_exec = getattr(os, "O_CLOEXEC", None)
    if no_follow is None or non_block is None or close_on_exec is None:
        raise ReviewError("descriptor-relative no-follow reads are unavailable")
    return os.O_RDONLY | no_follow | non_block | close_on_exec


def _require_exact_entry_name(
    descriptor: int,
    name: str,
    *,
    label: str,
    max_entries: int = MAX_ROOT_PARENT_ENTRIES,
) -> None:
    """Require one exact stored spelling in a bounded directory."""

    count = 0
    found = False
    try:
        with os.scandir(descriptor) as iterator:
            for entry in iterator:
                count += 1
                if count > max_entries:
                    raise ReviewError(
                        f"{label} directory exceeds the entry-count limit"
                    )
                if entry.name == name:
                    found = True
    except ReviewError:
        raise
    except OSError as error:
        raise ReviewError(f"cannot inspect {label} directory") from error
    if not found:
        raise ReviewError(f"{label} does not use its stored path spelling")


def _open_held_root(root: Path, *, label: str) -> HeldRoot:
    """Open one exact root entry and retain its parent descriptor."""

    try:
        absolute = Path(os.path.abspath(os.fspath(root.expanduser())))
        if not absolute.name:
            raise ValueError("a filesystem root is not an accepted input root")
        parent = absolute.parent.resolve(strict=True)
        resolved_absolute = parent / absolute.name
    except (OSError, RuntimeError, ValueError) as error:
        raise ReviewError(f"{label} root is missing or unsafe: {root}") from error

    parent_descriptor = -1
    root_descriptor = -1
    try:
        parent_descriptor = os.open(parent, _directory_flags())
        _require_exact_entry_name(
            parent_descriptor,
            absolute.name,
            label=f"{label} root parent",
        )
        root_descriptor = os.open(
            absolute.name,
            _directory_flags(),
            dir_fd=parent_descriptor,
        )
        identity = _file_identity(os.fstat(root_descriptor))
        if not stat.S_ISDIR(identity[2]):
            raise ReviewError(f"{label} root is not a regular directory: {root}")
        entry_identity = _file_identity(
            os.stat(
                absolute.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        )
        if entry_identity != identity:
            raise ReviewError(f"{label} root changed while it was opened")
        return HeldRoot(
            resolved_absolute,
            absolute.name,
            parent_descriptor,
            root_descriptor,
            identity,
            label,
        )
    except BaseException as error:
        _close_descriptors(
            [root_descriptor, parent_descriptor],
            context=f"{label} root",
        )
        if isinstance(error, ReviewError):
            raise
        if isinstance(error, OSError):
            raise ReviewError(f"{label} root is missing or unsafe: {root}") from error
        raise


def _close_held_root(root: HeldRoot) -> None:
    """Close one held root and its parent."""

    _close_descriptors(
        [root.descriptor, root.parent_descriptor],
        context=f"{root.label} root",
    )


def _verify_held_root(root: HeldRoot) -> None:
    """Require the held root and its parent entry to retain one identity."""

    replacement_descriptor = -1
    try:
        if _file_identity(os.fstat(root.descriptor)) != root.identity:
            raise ReviewError(f"{root.label} root changed during traversal")
        _require_exact_entry_name(
            root.parent_descriptor,
            root.name,
            label=f"{root.label} root parent",
        )
        current = _file_identity(
            os.stat(
                root.name,
                dir_fd=root.parent_descriptor,
                follow_symlinks=False,
            )
        )
        replacement_descriptor = os.open(root.absolute, _directory_flags())
        replacement_identity = _file_identity(os.fstat(replacement_descriptor))
    except ReviewError:
        raise
    except OSError as error:
        raise ReviewError(f"{root.label} root was replaced or became unsafe") from error
    finally:
        _close_descriptors(
            [replacement_descriptor],
            context=f"{root.label} root replacement check",
        )
    if current != root.identity:
        raise ReviewError(f"{root.label} root was replaced during traversal")
    if replacement_identity != root.identity:
        raise ReviewError(f"{root.label} root path was replaced during traversal")


def _relative_parts(
    relative: str,
    *,
    label: str,
    max_depth: int = MAX_HANDOFF_DEPTH,
    max_path_bytes: int = MAX_HANDOFF_PATH_BYTES,
    max_component_bytes: int = MAX_HANDOFF_COMPONENT_BYTES,
) -> tuple[str, ...]:
    """Validate one bounded canonical relative path."""

    return canonical_relative_parts(
        relative,
        label=label,
        max_depth=max_depth,
        max_path_bytes=max_path_bytes,
        max_component_bytes=max_component_bytes,
    )


def _read_rooted_regular_file(
    root_descriptor: int,
    relative: str,
    *,
    max_bytes: int,
    expected_size: int | None,
    label: str,
    directory_identities: dict[str, tuple[int, ...]],
    record_directories: bool,
    require_exact_names: bool,
    expected_git_mode: str | None = None,
    size_mismatch_message: str | None = None,
) -> RootedRead:
    """Read one file through a held root and unchanged directory descriptors."""

    parts = _relative_parts(relative, label=f"{label} path")
    if (
        type(max_bytes) is not int
        or max_bytes < 0
        or (
            expected_size is not None
            and (
                type(expected_size) is not int
                or expected_size < 0
                or expected_size > max_bytes
            )
        )
    ):
        raise ReviewError(f"{label} byte limits are invalid")

    owned_directories: list[tuple[int, tuple[int, ...]]] = []
    file_descriptor = -1
    try:
        current = os.dup(root_descriptor)
        try:
            current_identity = _file_identity(os.fstat(current))
        except BaseException:
            _close_descriptors([current], context=f"{label} root acquisition")
            raise
        owned_directories.append((current, current_identity))
        expected_root = directory_identities.get("")
        if expected_root is None:
            directory_identities[""] = current_identity
        elif expected_root != current_identity:
            raise ReviewError(f"{label} root changed before the read")

        traversed: list[str] = []
        for part in parts[:-1]:
            traversed.append(part)
            directory_path = "/".join(traversed)
            if require_exact_names:
                _require_exact_entry_name(
                    current,
                    part,
                    label=f"{label} path",
                )
            next_descriptor = os.open(
                part,
                _directory_flags(),
                dir_fd=current,
            )
            try:
                identity = _file_identity(os.fstat(next_descriptor))
            except BaseException:
                _close_descriptors(
                    [next_descriptor],
                    context=f"{label} directory acquisition",
                )
                raise
            owned_directories.append((next_descriptor, identity))
            expected = directory_identities.get(directory_path)
            if expected is None:
                if not record_directories:
                    raise ReviewError(
                        f"{label} entered an unrecorded directory: {directory_path}"
                    )
                directory_identities[directory_path] = identity
            elif expected != identity:
                raise ReviewError(f"{label} directory changed: {directory_path}")
            current = next_descriptor

        if require_exact_names:
            _require_exact_entry_name(
                current,
                parts[-1],
                label=f"{label} path",
            )
        file_descriptor = os.open(
            parts[-1],
            _file_flags(),
            dir_fd=current,
        )
        before = os.fstat(file_descriptor)
        identity = _file_identity(before)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ReviewError(f"{label} is not one singly linked regular file")
        if before.st_size > max_bytes:
            raise ReviewError(f"{label} exceeds the byte limit")
        if expected_size is not None and before.st_size != expected_size:
            raise ReviewError(
                size_mismatch_message or f"{label} size differs from its declared bound"
            )
        if expected_git_mode is not None:
            executable = bool(before.st_mode & stat.S_IXUSR)
            if executable != (expected_git_mode == "100755"):
                raise ReviewError(f"{label} executable mode differs from its index")

        chunks: list[bytes] = []
        total = 0
        read_limit = before.st_size + 1
        while total < read_limit:
            block = os.read(
                file_descriptor,
                min(1024 * 1024, read_limit - total),
            )
            if not block:
                break
            total += len(block)
            if total > before.st_size or total > max_bytes:
                raise ReviewError(f"{label} grew while it was read")
            chunks.append(block)
        after = os.fstat(file_descriptor)
        if total != before.st_size or _file_identity(after) != identity:
            raise ReviewError(f"{label} changed while it was read")
        for descriptor, expected in owned_directories:
            if _file_identity(os.fstat(descriptor)) != expected:
                raise ReviewError(f"{label} path changed while it was read")
        return RootedRead(b"".join(chunks), identity)
    except ReviewError:
        raise
    except OSError as error:
        raise ReviewError(f"{label} is missing or unsafe") from error
    finally:
        _close_descriptors(
            [file_descriptor]
            + [descriptor for descriptor, _identity in reversed(owned_directories)],
            context=label,
        )


def _verify_rooted_regular_file_identity(
    root_descriptor: int,
    relative: str,
    expected_file: tuple[int, ...],
    directory_identities: dict[str, tuple[int, ...]],
    *,
    label: str,
) -> None:
    """Require one touched file and its path to retain their identities."""

    parts = _relative_parts(relative, label=f"{label} path")
    owned_directories: list[tuple[int, tuple[int, ...]]] = []
    file_descriptor = -1
    try:
        current = os.dup(root_descriptor)
        try:
            current_identity = _file_identity(os.fstat(current))
        except BaseException:
            _close_descriptors([current], context=f"{label} path")
            raise
        if directory_identities.get("") != current_identity:
            _close_descriptors([current], context=f"{label} path")
            raise ReviewError(f"{label} root changed during the transaction")
        owned_directories.append((current, current_identity))

        traversed: list[str] = []
        for part in parts[:-1]:
            traversed.append(part)
            directory_path = "/".join(traversed)
            _require_exact_entry_name(
                current,
                part,
                label=f"{label} path",
            )
            next_descriptor = os.open(
                part,
                _directory_flags(),
                dir_fd=current,
            )
            try:
                identity = _file_identity(os.fstat(next_descriptor))
            except BaseException:
                _close_descriptors(
                    [next_descriptor],
                    context=f"{label} path",
                )
                raise
            if directory_identities.get(directory_path) != identity:
                _close_descriptors(
                    [next_descriptor],
                    context=f"{label} path",
                )
                raise ReviewError(
                    f"{label} directory changed during the transaction: "
                    f"{directory_path}"
                )
            owned_directories.append((next_descriptor, identity))
            current = next_descriptor

        _require_exact_entry_name(
            current,
            parts[-1],
            label=f"{label} path",
        )
        file_descriptor = os.open(
            parts[-1],
            _file_flags(),
            dir_fd=current,
        )
        current_file = _file_identity(os.fstat(file_descriptor))
        if (
            not stat.S_ISREG(current_file[2])
            or current_file[3] != 1
            or current_file != expected_file
        ):
            raise ReviewError(f"{label} changed during the transaction")
        if _file_identity(os.fstat(file_descriptor)) != expected_file:
            raise ReviewError(f"{label} changed during the transaction")
        for descriptor, expected_directory in owned_directories:
            if _file_identity(os.fstat(descriptor)) != expected_directory:
                raise ReviewError(f"{label} path changed during the transaction")
    except ReviewError:
        raise
    except OSError as error:
        raise ReviewError(f"{label} changed or became unsafe") from error
    finally:
        _close_descriptors(
            [file_descriptor]
            + [descriptor for descriptor, _identity in reversed(owned_directories)],
            context=f"{label} identity verification",
        )


def _verify_rooted_directories(
    root_descriptor: int,
    identities: dict[str, tuple[int, ...]],
    *,
    label: str,
) -> None:
    """Require each directory used in a rooted transaction to stay unchanged."""

    root_identity = identities.get("")
    try:
        current_root = _file_identity(os.fstat(root_descriptor))
    except OSError as error:
        raise ReviewError(f"{label} root became unsafe") from error
    if root_identity is None or current_root != root_identity:
        raise ReviewError(f"{label} root changed during the transaction")
    for relative in sorted(
        (path for path in identities if path),
        key=lambda path: (path.count("/"), path),
    ):
        parts = _relative_parts(relative, label=f"{label} directory path")
        descriptors: list[int] = []
        try:
            descriptor = os.dup(root_descriptor)
            descriptors.append(descriptor)
            traversed: list[str] = []
            for part in parts:
                traversed.append(part)
                _require_exact_entry_name(
                    descriptor,
                    part,
                    label=f"{label} directory path",
                )
                next_descriptor = os.open(
                    part,
                    _directory_flags(),
                    dir_fd=descriptor,
                )
                descriptors.append(next_descriptor)
                descriptor = next_descriptor
                traversed_path = "/".join(traversed)
                expected = identities.get(traversed_path)
                if expected is None or _file_identity(os.fstat(descriptor)) != expected:
                    raise ReviewError(f"{label} directory changed: {traversed_path}")
        except ReviewError:
            raise
        except OSError as error:
            raise ReviewError(
                f"{label} directory is missing or unsafe: {relative}"
            ) from error
        finally:
            _close_descriptors(
                list(reversed(descriptors)),
                context=f"{label} directory verification",
            )


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ReviewError(f"{label} must be a JSON object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        unexpected = sorted(actual - keys)
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        raise ReviewError(f"{label} has incorrect keys ({'; '.join(details)})")
    return value


def exact_list(value: Any, label: str) -> list[Any]:
    if type(value) is not list:
        raise ReviewError(f"{label} must be a JSON array")
    return value


def exact_string(value: Any, label: str, *, nonempty: bool = True) -> str:
    if type(value) is not str or (nonempty and not value):
        qualifier = "nonempty " if nonempty else ""
        raise ReviewError(f"{label} must be a {qualifier}JSON string")
    return value


def read_bounded_regular_file(
    path: Path,
    max_bytes: int,
    *,
    label: str,
    limit_label: str,
) -> bytes:
    """Atomically open, classify, and size-bound one untrusted input file."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    if no_follow is None or non_block is None:
        raise ReviewError(
            "atomic nonblocking no-follow file reads are unavailable on this platform"
        )
    try:
        descriptor = os.open(path, os.O_RDONLY | no_follow | non_block)
    except OSError as error:
        raise ReviewError(f"{label} is missing or not regular: {path}") from error
    try:
        handle = os.fdopen(descriptor, "rb", closefd=True)
    except BaseException:
        # Ownership transfers only after ``fdopen`` succeeds.
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    with handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ReviewError(f"{label} is missing or not regular: {path}")
        if before.st_size > max_bytes:
            raise ReviewError(f"{label} exceeds the {limit_label} limit")
        data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ReviewError(f"{label} exceeds the {limit_label} limit")
        after = os.fstat(handle.fileno())
        if len(data) != before.st_size or _file_identity(after) != _file_identity(
            before
        ):
            raise ReviewError(f"{label} changed while being read")
        return data


def exact_integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ReviewError(f"{label} must be an integer >= {minimum}")
    return value


def exact_digest(value: Any, label: str) -> str:
    digest = exact_string(value, label)
    if HEX_SHA256.fullmatch(digest) is None:
        raise ReviewError(f"{label} must be a lowercase SHA-256 digest")
    return digest


def exact_object_id(value: Any, label: str) -> str:
    object_id = exact_string(value, label)
    if HEX_OBJECT_ID.fullmatch(object_id) is None:
        raise ReviewError(f"{label} must be a full lowercase Git object ID")
    return object_id


def safe_relative_path(value: Any, label: str) -> str:
    relative = exact_string(value, label)
    candidate = Path(relative)
    if (
        candidate.is_absolute()
        or "\\" in relative
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ReviewError(f"{label} must be a normalized relative path")
    if candidate.as_posix() != relative:
        raise ReviewError(f"{label} must use normalized POSIX separators")
    return relative


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(block)
            digest.update(block)
    return digest.hexdigest(), size


def digest_bounded_handoff_file(
    path: Path,
    relative: str,
    aggregate_size: int,
) -> tuple[str, int]:
    """Hash one no-follow handoff file within per-file and aggregate limits."""

    if aggregate_size < 0 or aggregate_size > MAX_HANDOFF_AGGREGATE_BYTES:
        raise ReviewError("handoff inventory exceeds the aggregate byte limit")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    if no_follow is None or non_block is None:
        raise ReviewError("atomic nonblocking no-follow handoff reads are unavailable")
    flags = os.O_RDONLY | no_follow | non_block | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReviewError(
            f"handoff path is not a contained regular file: {relative}"
        ) from error
    try:
        handle = os.fdopen(descriptor, "rb", closefd=True)
    except BaseException:
        # Ownership transfers only after ``fdopen`` succeeds.
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    with handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ReviewError(
                f"handoff path is not a contained regular file: {relative}"
            )
        if before.st_size > MAX_HANDOFF_FILE_BYTES:
            raise ReviewError(
                f"handoff regular file exceeds the per-file byte limit: {relative}"
            )
        if aggregate_size + before.st_size > MAX_HANDOFF_AGGREGATE_BYTES:
            raise ReviewError("handoff inventory exceeds the aggregate byte limit")

        digest = hashlib.sha256()
        size = 0
        while True:
            remaining = min(
                MAX_HANDOFF_FILE_BYTES - size,
                MAX_HANDOFF_AGGREGATE_BYTES - aggregate_size - size,
            )
            block = handle.read(min(1024 * 1024, remaining + 1))
            if not block:
                break
            size += len(block)
            if size > MAX_HANDOFF_FILE_BYTES:
                raise ReviewError(
                    f"handoff regular file exceeds the per-file byte limit: {relative}"
                )
            if aggregate_size + size > MAX_HANDOFF_AGGREGATE_BYTES:
                raise ReviewError("handoff inventory exceeds the aggregate byte limit")
            digest.update(block)
        after = os.fstat(handle.fileno())
        if size != before.st_size or _file_identity(after) != _file_identity(before):
            raise ReviewError(f"handoff regular file changed while read: {relative}")
        return digest.hexdigest(), size


def _release_index_pathspecs() -> tuple[str, ...]:
    """Return the complete relevant release-input index pathspec set."""

    return (*RELEASE_INPUTS, "repo_work", "scripts")


def _read_relevant_release_index(repo: Path) -> bytes:
    """Capture all declared inputs and tracked release-tool paths once."""

    return bytes(
        git(
            repo,
            "--literal-pathspecs",
            "ls-files",
            "--stage",
            "-z",
            "--",
            *_release_index_pathspecs(),
            text=False,
            max_bytes=MAX_RELEASE_INPUT_INDEX_BYTES,
        )
    )


def _parse_relevant_release_index(
    raw_index: bytes,
) -> dict[str, list[ReleaseIndexEntry]]:
    """Parse one bounded complete relevant index capture."""

    entries: dict[str, list[ReleaseIndexEntry]] = {}
    for raw_entry in raw_index.split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            raw_mode, raw_blob, raw_stage = metadata.split(b" ")
            relative = raw_path.decode("utf-8")
            mode = raw_mode.decode("ascii")
            blob = raw_blob.decode("ascii")
            stage = int(raw_stage.decode("ascii"), 10)
        except (UnicodeError, ValueError) as error:
            raise ReviewError(
                "release input index contains a malformed entry"
            ) from error
        _relative_parts(relative, label="release input index path")
        if relative not in RELEASE_INPUTS and not (
            relative == "repo_work"
            or relative.startswith("repo_work/")
            or relative == "scripts"
            or relative.startswith("scripts/")
        ):
            raise ReviewError(
                f"release input index contains an unexpected path: {relative}"
            )
        exact_object_id(blob, f"release input index blob for {relative}")
        entries.setdefault(relative, []).append(ReleaseIndexEntry(mode, blob, stage))
    return entries


def _assert_release_tool_coverage_from_index(
    entries: dict[str, list[ReleaseIndexEntry]],
) -> None:
    """Reject an unenumerated release-tool path from one index capture."""

    tracked = {
        path
        for path in entries
        if path == "repo_work"
        or path.startswith("repo_work/")
        or path == "scripts"
        or path.startswith("scripts/")
    }
    declared = set(RELEASE_INPUTS)
    missing = sorted(tracked - declared)
    if missing:
        raise ReviewError(
            "tracked release-tool paths are absent from the frozen input set: "
            + ", ".join(missing)
        )


def assert_release_tool_coverage(repo: Path) -> None:
    """Reject an unenumerated tracked release-tool source or test."""

    entries = _parse_relevant_release_index(_read_relevant_release_index(repo))
    _assert_release_tool_coverage_from_index(entries)


def git_blob(repo: Path, commit: str, relative: str) -> bytes:
    return bytes(
        git(
            repo,
            "show",
            f"{commit}:{relative}",
            text=False,
            max_bytes=MAX_HANDOFF_FILE_BYTES,
        )
    )


def _inventory_handoff_tree(
    root_descriptor: int,
    root_identity: tuple[int, ...],
) -> HandoffInventory:
    """Inventory one complete handoff tree through held descriptors."""

    directories = {"": root_identity}
    regular_files: dict[str, tuple[int, ...]] = {}
    symlinks: dict[str, tuple[tuple[int, ...], str, bytes]] = {}
    regular_identities: set[tuple[int, int]] = set()
    symlink_identities: set[tuple[int, int]] = set()
    entry_count = 0
    aggregate_size = 0

    def visit(
        descriptor: int,
        prefix: tuple[str, ...],
        expected_directory: tuple[int, ...],
    ) -> None:
        nonlocal entry_count, aggregate_size
        entries: list[tuple[str, str, tuple[str, ...], tuple[int, ...]]] = []
        try:
            with os.scandir(descriptor) as iterator:
                for entry in iterator:
                    entry_count += 1
                    if entry_count > MAX_HANDOFF_ENTRIES:
                        raise ReviewError(
                            "handoff inventory exceeds the entry-count limit"
                        )
                    relative = "/".join((*prefix, entry.name))
                    parts = _relative_parts(
                        relative,
                        label="handoff path",
                    )
                    metadata = entry.stat(follow_symlinks=False)
                    entries.append(
                        (
                            relative,
                            entry.name,
                            parts,
                            _file_identity(metadata),
                        )
                    )
        except ReviewError:
            raise
        except OSError as error:
            raise ReviewError("cannot completely inventory handoff path") from error

        if prefix and not entries:
            raise ReviewError(
                "handoff inventory contains an unrepresented empty directory: "
                + "/".join(prefix)
            )

        for relative, name, parts, identity in sorted(
            entries,
            key=lambda row: row[0],
        ):
            mode = identity[2]
            if stat.S_ISREG(mode):
                if identity[3] != 1:
                    raise ReviewError(
                        f"handoff regular file is multiply linked: {relative}"
                    )
                inode = (identity[0], identity[1])
                if inode in regular_identities:
                    raise ReviewError(
                        f"handoff regular file identity is duplicated: {relative}"
                    )
                if identity[4] > MAX_HANDOFF_FILE_BYTES:
                    raise ReviewError(
                        "handoff regular file exceeds the per-file byte limit: "
                        f"{relative}"
                    )
                aggregate_size += identity[4]
                if aggregate_size > MAX_HANDOFF_AGGREGATE_BYTES:
                    raise ReviewError(
                        "handoff inventory exceeds the aggregate byte limit"
                    )
                regular_identities.add(inode)
                regular_files[relative] = identity
                continue

            if stat.S_ISLNK(mode):
                if identity[3] != 1:
                    raise ReviewError(f"handoff symlink is multiply linked: {relative}")
                inode = (identity[0], identity[1])
                if inode in symlink_identities:
                    raise ReviewError(
                        f"handoff symlink identity is duplicated: {relative}"
                    )
                try:
                    target = os.readlink(name, dir_fd=descriptor)
                    after = _file_identity(
                        os.stat(
                            name,
                            dir_fd=descriptor,
                            follow_symlinks=False,
                        )
                    )
                except OSError as error:
                    raise ReviewError(
                        f"handoff symlink changed or became unsafe: {relative}"
                    ) from error
                if after != identity:
                    raise ReviewError(f"handoff symlink changed while read: {relative}")
                try:
                    encoded = target.encode("utf-8", "strict")
                except UnicodeEncodeError as error:
                    raise ReviewError(
                        f"handoff symlink target is not valid UTF-8: {relative}"
                    ) from error
                if len(encoded) > MAX_HANDOFF_SYMLINK_BYTES:
                    raise ReviewError(
                        f"handoff symlink target exceeds the byte limit: {relative}"
                    )
                aggregate_size += len(encoded)
                if aggregate_size > MAX_HANDOFF_AGGREGATE_BYTES:
                    raise ReviewError(
                        "handoff inventory exceeds the aggregate byte limit"
                    )
                symlink_identities.add(inode)
                symlinks[relative] = (identity, target, encoded)
                continue

            if stat.S_ISDIR(mode):
                try:
                    child = os.open(
                        name,
                        _directory_flags(),
                        dir_fd=descriptor,
                    )
                except OSError as error:
                    raise ReviewError(
                        f"handoff directory changed or became unsafe: {relative}"
                    ) from error
                try:
                    try:
                        opened_identity = _file_identity(os.fstat(child))
                    except OSError as error:
                        raise ReviewError(
                            f"handoff directory changed or became unsafe: {relative}"
                        ) from error
                    if opened_identity != identity:
                        raise ReviewError(
                            f"handoff directory changed while opened: {relative}"
                        )
                    directories[relative] = identity
                    visit(child, parts, identity)
                    try:
                        final_identity = _file_identity(os.fstat(child))
                    except OSError as error:
                        raise ReviewError(
                            f"handoff directory changed or became unsafe: {relative}"
                        ) from error
                    if final_identity != identity:
                        raise ReviewError(
                            f"handoff directory changed during traversal: {relative}"
                        )
                finally:
                    _close_descriptors(
                        [child],
                        context=f"handoff directory {relative}",
                    )
                continue

            kind = "special file"
            raise ReviewError(f"handoff contains a {kind}: {relative}")

        try:
            final_directory = _file_identity(os.fstat(descriptor))
        except OSError as error:
            relative = "/".join(prefix) or "."
            raise ReviewError(
                f"handoff directory changed or became unsafe: {relative}"
            ) from error
        if final_directory != expected_directory:
            relative = "/".join(prefix) or "."
            raise ReviewError(f"handoff directory changed during traversal: {relative}")

    visit(root_descriptor, (), root_identity)
    return HandoffInventory(
        directories,
        regular_files,
        symlinks,
        aggregate_size,
    )


def _digest_rooted_handoff_file(
    root_descriptor: int,
    relative: str,
    expected_identity: tuple[int, ...],
    directories: dict[str, tuple[int, ...]],
) -> tuple[str, int]:
    """Hash one inventoried handoff file through the held root."""

    captured = _read_rooted_regular_file(
        root_descriptor,
        relative,
        max_bytes=MAX_HANDOFF_FILE_BYTES,
        expected_size=expected_identity[4],
        label=f"handoff regular file {relative}",
        directory_identities=directories,
        record_directories=False,
        require_exact_names=False,
    )
    if captured.identity != expected_identity:
        raise ReviewError(f"handoff regular file changed before read: {relative}")
    return digest_bytes(captured.document), len(captured.document)


def strict_relative_files(root: Path) -> list[dict[str, Any]]:
    """Create one coherent bounded inventory from a held handoff root."""

    held = _open_held_root(root, label="handoff")
    try:
        before = _inventory_handoff_tree(held.descriptor, held.identity)
        if not before.regular_files and not before.symlinks:
            raise ReviewError("handoff root contains no files")

        rows: list[dict[str, Any]] = []
        for relative, identity in sorted(before.regular_files.items()):
            digest, size = _digest_rooted_handoff_file(
                held.descriptor,
                relative,
                identity,
                before.directories,
            )
            rows.append(
                {
                    "path": relative,
                    "kind": "regular",
                    "mode": f"{stat.S_IMODE(identity[2]):04o}",
                    "sha256": digest,
                    "size_bytes": size,
                }
            )
        for relative, (_identity, target, encoded) in sorted(before.symlinks.items()):
            rows.append(
                {
                    "path": relative,
                    "kind": "symlink",
                    "target": target,
                    "sha256": digest_bytes(encoded),
                    "size_bytes": len(encoded),
                }
            )
        rows.sort(key=lambda row: str(row["path"]))

        after = _inventory_handoff_tree(held.descriptor, held.identity)
        if after != before:
            raise ReviewError("handoff inventory changed during traversal")
        _verify_held_root(held)
        return rows
    finally:
        _close_held_root(held)


def locked_git_dependencies(lock_bytes: bytes) -> list[dict[str, str]]:
    try:
        lock = tomllib.loads(lock_bytes.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ReviewError(
            f"baseline Cargo.lock is not valid UTF-8 TOML: {error}"
        ) from error
    if type(lock) is not dict:
        raise ReviewError("baseline Cargo.lock root must be a TOML table")
    packages = lock.get("package", [])
    if type(packages) is not list:
        raise ReviewError("baseline Cargo.lock package inventory must be an array")
    dependencies: list[dict[str, str]] = []
    for index, package in enumerate(packages):
        if type(package) is not dict:
            raise ReviewError(f"baseline Cargo.lock package {index} must be a table")
        source = package.get("source", "")
        if type(source) is not str:
            raise ReviewError(
                f"baseline Cargo.lock package {index} source must be text"
            )
        if not source.startswith("git+"):
            continue
        name = package.get("name")
        version = package.get("version")
        if type(name) is not str or not name or type(version) is not str or not version:
            raise ReviewError(
                f"baseline Cargo.lock Git package {index} lacks name or version text"
            )
        revision = source.rsplit("#", 1)[-1]
        if len(revision) != 40 or any(
            character not in "0123456789abcdef" for character in revision
        ):
            raise ReviewError(
                f"Git dependency is not locked to a full revision: {source}"
            )
        dependencies.append(
            {
                "name": name,
                "version": version,
                "source": source,
                "commit": revision,
            }
        )
    return sorted(
        dependencies, key=lambda item: (item["name"], item["version"], item["source"])
    )


def tag_inventory(repo: Path) -> list[dict[str, str | None]]:
    """Record every local tag object and its peeled commit, without abbreviation."""

    raw = str(
        git(
            repo,
            "for-each-ref",
            f"--count={MAX_HISTORICAL_TAGS + 1}",
            "--format=%(refname)%00%(objectname)%00%(objecttype)%00%(*objectname)",
            "refs/tags",
        )
    )
    tags: list[dict[str, str | None]] = []
    for line in raw.splitlines():
        if not line:
            continue
        fields = line.split("\0")
        if len(fields) != 4:
            raise ReviewError("cannot parse local tag inventory")
        refname, object_id, object_type, peeled = fields
        tags.append(
            {
                "ref": refname,
                "object": object_id,
                "object_type": object_type,
                "peeled_object": peeled or None,
            }
        )
        if len(tags) > MAX_HISTORICAL_TAGS:
            raise ReviewError(
                f"local tag inventory exceeds {MAX_HISTORICAL_TAGS} entries"
            )
    return sorted(tags, key=lambda item: str(item["ref"]))


def submodule_inventory(repo: Path, commit: str) -> list[dict[str, str]]:
    """Record gitlink paths and commits from the frozen baseline tree."""

    raw = bytes(git(repo, "ls-tree", "-rz", "-r", "--full-tree", commit, text=False))
    submodules: list[dict[str, str]] = []
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        metadata, encoded_path = entry.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split()
        if mode == "160000":
            if object_type != "commit":
                raise ReviewError("frozen gitlink does not identify a commit")
            submodules.append(
                {
                    "path": encoded_path.decode("utf-8", "surrogateescape"),
                    "commit": object_id,
                }
            )
    return sorted(submodules, key=lambda item: item["path"])


def validate_source_documents(
    repo: Path,
    *,
    captured_documents: dict[str, bytes] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    """Load and validate the two repository documents that bind the freeze."""

    source_paths = (
        ("release/0.9.0/handoff-source.json", "handoff source"),
        ("release/0.9.0/audit-inputs.json", "release audit inputs"),
    )
    if captured_documents is None:
        held = _open_held_root(repo, label="source-document repository")
        source_bytes: dict[str, bytes] = {}
        directory_identities = {"": held.identity}
        file_identities: set[tuple[int, int]] = set()
        source_file_identities: dict[str, tuple[int, ...]] = {}
        try:
            for relative, label in source_paths:
                captured = _read_rooted_regular_file(
                    held.descriptor,
                    relative,
                    max_bytes=MAX_SOURCE_DOCUMENT_BYTES,
                    expected_size=None,
                    label=label,
                    directory_identities=directory_identities,
                    record_directories=True,
                    require_exact_names=True,
                )
                file_identity = (captured.identity[0], captured.identity[1])
                if file_identity in file_identities:
                    raise ReviewError("source documents share one file identity")
                file_identities.add(file_identity)
                source_bytes[relative] = captured.document
                source_file_identities[relative] = captured.identity
                _verify_held_root(held)
            for relative, label in source_paths:
                _verify_rooted_regular_file_identity(
                    held.descriptor,
                    relative,
                    source_file_identities[relative],
                    directory_identities,
                    label=label,
                )
            _verify_rooted_directories(
                held.descriptor,
                directory_identities,
                label="source-document repository",
            )
            _verify_held_root(held)
        finally:
            _close_held_root(held)
    else:
        expected_paths = {relative for relative, _label in source_paths}
        if set(captured_documents) != expected_paths:
            raise ReviewError("captured source-document set is incomplete")
        source_bytes = dict(captured_documents)

    decoded: dict[str, Any] = {}
    for relative, label in source_paths:
        if len(source_bytes[relative]) > MAX_SOURCE_DOCUMENT_BYTES:
            raise ReviewError(f"{label} exceeds the byte limit")
        try:
            value = loads_json(source_bytes[relative])
            validate_json_structure(
                value,
                max_depth=MAX_SOURCE_JSON_DEPTH,
                max_nodes=MAX_SOURCE_JSON_NODES,
                label=label,
            )
        except ReviewError:
            raise
        except (UnicodeError, ValueError, RecursionError, MemoryError) as error:
            raise ReviewError(f"{label} is not strict bounded JSON") from error
        decoded[relative] = value

    handoff_source = exact_object(
        decoded["release/0.9.0/handoff-source.json"],
        {
            "schema",
            "prepared",
            "repository",
            "frozen_commit",
            "original_target",
            "adapted_release_target",
            "master_package",
            "child_archive",
            "child_archive_sha256",
            "task_ledger_sha256",
            "task_count",
            "supersedes_embedded_handoff_sha256",
            "provenance_note",
        },
        "handoff source",
    )
    if handoff_source["schema"] != "galadriel.handoff-source.v2":
        raise ReviewError("handoff source schema is not galadriel.handoff-source.v2")
    if handoff_source["original_target"] != "1.0.0":
        raise ReviewError("handoff source original target is not 1.0.0")
    if handoff_source["adapted_release_target"] != RELEASE["version"]:
        raise ReviewError("handoff source does not bind release 0.9.0")
    for key in ("prepared", "repository", "provenance_note"):
        exact_string(handoff_source[key], f"handoff source {key}")
    master_package = exact_string(
        handoff_source["master_package"],
        "handoff source master_package",
    )
    _relative_parts(
        master_package,
        label="handoff source master_package",
        max_depth=1,
    )
    child_archive = exact_string(
        handoff_source["child_archive"],
        "handoff source child_archive",
    )
    _relative_parts(
        child_archive,
        label="handoff source child_archive",
        max_depth=1,
    )
    if not child_archive.endswith(".zip"):
        raise ReviewError("handoff source child_archive must be a root-level ZIP name")
    for key in (
        "child_archive_sha256",
        "task_ledger_sha256",
        "supersedes_embedded_handoff_sha256",
    ):
        exact_digest(handoff_source[key], f"handoff source {key}")
    exact_integer(handoff_source["task_count"], "handoff source task_count", minimum=1)
    baseline_commit = exact_object_id(
        handoff_source["frozen_commit"], "handoff source frozen_commit"
    )

    audit_inputs = exact_object(
        decoded["release/0.9.0/audit-inputs.json"],
        {
            "schema",
            "release",
            "audit_date",
            "audit_date_semantics",
            "baseline_repository",
            "repositories",
            "toolchains",
            "github_actions",
            "artifact_sets",
            "external_sources",
            "adaptation_decision",
        },
        "release audit inputs",
    )
    if audit_inputs["schema"] != "galadriel.release-audit-inputs.v1":
        raise ReviewError(
            "release audit input schema is not galadriel.release-audit-inputs.v1"
        )
    audit_release = exact_object(
        audit_inputs["release"],
        {
            "name",
            "version",
            "author",
            "doi",
            "zenodo",
            "publication_channel",
            "source_preparation_state",
            "candidate_release_date",
        },
        "release audit identity",
    )
    expected_audit_release = {
        "name": "Galadriel's Mirror",
        **RELEASE,
        "publication_channel": PUBLICATION_CHANNEL,
    }
    if any(
        audit_release[key] != value
        for key, value in expected_audit_release.items()
    ):
        raise ReviewError(
            "release audit identity must name release 0.9.0 with the expected author "
            "and null DOI/Zenodo fields"
        )
    source_preparation_state = exact_string(
        audit_release["source_preparation_state"],
        "release audit source_preparation_state",
    )
    candidate_release_date = audit_release["candidate_release_date"]
    if source_preparation_state == UNPUBLISHED_SOURCE_PREPARATION_STATE:
        if candidate_release_date is not None:
            raise ReviewError(
                "UNPUBLISHED_CANDIDATE must have no candidate release date"
            )
    elif source_preparation_state == DATE_BOUND_SOURCE_PREPARATION_STATE:
        candidate_release_date = exact_string(
            candidate_release_date,
            "release audit candidate_release_date",
        )
        try:
            parsed_candidate_date = date.fromisoformat(candidate_release_date)
        except ValueError as error:
            raise ReviewError(
                "release audit candidate_release_date is not an ISO calendar date"
            ) from error
        if parsed_candidate_date.isoformat() != candidate_release_date:
            raise ReviewError(
                "release audit candidate_release_date must use YYYY-MM-DD precision"
            )
    else:
        raise ReviewError("release audit source_preparation_state is unsupported")
    audit_date = exact_string(audit_inputs["audit_date"], "release audit date")
    try:
        parsed_audit_date = date.fromisoformat(audit_date)
    except ValueError as error:
        raise ReviewError("release audit date is not an ISO calendar date") from error
    if parsed_audit_date.isoformat() != audit_date:
        raise ReviewError("release audit date must use YYYY-MM-DD precision")
    if audit_inputs["audit_date_semantics"] != AUDIT_DATE_SEMANTICS:
        raise ReviewError("release audit date semantics differ from the contract")
    for key in ("repositories", "toolchains", "github_actions", "artifact_sets"):
        exact_list(audit_inputs[key], f"release audit inputs {key}")
    exact_object(
        audit_inputs["external_sources"],
        {"scan_patterns", "declared"},
        "external sources",
    )
    adaptation_decision = exact_string(
        audit_inputs["adaptation_decision"],
        "release audit adaptation_decision",
    )
    _relative_parts(
        adaptation_decision,
        label="release audit adaptation_decision",
    )

    declared_baseline = exact_object(
        audit_inputs["baseline_repository"],
        {"url", "commit", "tree"},
        "declared baseline repository",
    )
    baseline_repository = exact_string(
        declared_baseline["url"], "declared baseline repository URL"
    )
    declared_commit = exact_object_id(
        declared_baseline["commit"], "declared baseline commit"
    )
    declared_tree = exact_object_id(declared_baseline["tree"], "declared baseline tree")
    if baseline_commit != declared_commit:
        raise ReviewError("handoff and release inputs disagree on the frozen commit")
    if handoff_source["repository"] != baseline_repository:
        raise ReviewError("handoff and release inputs disagree on the repository URL")
    if baseline_repository != EXPECTED_BASELINE_REPOSITORY:
        raise ReviewError(
            "release inputs do not name the immutable baseline repository"
        )
    if declared_commit != EXPECTED_BASELINE_COMMIT:
        raise ReviewError("release inputs do not name the immutable baseline commit")
    if declared_tree != EXPECTED_BASELINE_TREE:
        raise ReviewError("release inputs do not name the immutable baseline tree")
    return handoff_source, audit_inputs, baseline_commit, declared_tree


def baseline_manifest(
    repo: Path, baseline_commit: str, declared_tree: str
) -> dict[str, Any]:
    object_type = str(git(repo, "cat-file", "-t", baseline_commit)).strip()
    if object_type != "commit":
        raise ReviewError("declared baseline commit does not identify a Git commit")
    baseline_tree = str(git(repo, "rev-parse", f"{baseline_commit}^{{tree}}")).strip()
    if baseline_tree != declared_tree:
        raise ReviewError("declared baseline tree does not match the frozen commit")

    baseline_files: list[dict[str, Any]] = []
    baseline_lock = b""
    for relative in BASELINE_PATHS:
        data = git_blob(repo, baseline_commit, relative)
        if relative == "Cargo.lock":
            baseline_lock = data
        blob = str(git(repo, "rev-parse", f"{baseline_commit}:{relative}")).strip()
        exact_object_id(blob, f"baseline blob for {relative}")
        baseline_files.append(
            {
                "path": relative,
                "git_blob": blob,
                "sha256": digest_bytes(data),
                "size_bytes": len(data),
            }
        )
    if not baseline_lock:
        raise ReviewError("baseline path set does not contain a nonempty Cargo.lock")
    return {
        "commit": baseline_commit,
        "tree": baseline_tree,
        "files": baseline_files,
        "submodules": submodule_inventory(repo, baseline_commit),
        "locked_git_dependencies": locked_git_dependencies(baseline_lock),
    }


def threat_register_status(document: bytes) -> str:
    """Return one declared threat-register lifecycle status."""

    if len(document) > MAX_THREAT_REGISTER_BYTES:
        raise ReviewError("threat register exceeds the 4 MiB byte limit")
    try:
        value = loads_json(document)
    except (UnicodeError, ValueError, RecursionError, MemoryError) as error:
        raise ReviewError("threat register is not strict JSON") from error
    if type(value) is not dict:
        raise ReviewError("threat register must be a JSON object")
    status = value.get("status")
    if status not in VALID_THREAT_STATUSES:
        raise ReviewError("threat register has an unsupported lifecycle status")
    assert isinstance(status, str)
    return status


def validate_source_preparation_lifecycle(
    audit_inputs: dict[str, Any], threat_status: str
) -> None:
    """Reject a frozen undated source while allowing a date-bound pre-freeze state."""

    source_preparation_state = audit_inputs["release"]["source_preparation_state"]
    if (
        source_preparation_state == UNPUBLISHED_SOURCE_PREPARATION_STATE
        and threat_status != THREAT_STATUS_LIVING
    ):
        raise ReviewError(
            "UNPUBLISHED_CANDIDATE requires LIVING_UNTIL_CANDIDATE_FREEZE"
        )
    if (
        threat_status == THREAT_STATUS_FROZEN
        and source_preparation_state != DATE_BOUND_SOURCE_PREPARATION_STATE
    ):
        raise ReviewError(
            "FROZEN_AT_CANDIDATE requires a date-bound candidate source"
        )


def _capture_release_input_snapshot(
    repo: Path,
    *,
    required_threat_status: str | None = None,
    bind_source_documents: bool = False,
) -> ReleaseInputSnapshot:
    """Capture one coherent release-input and source-document transaction."""

    if (
        required_threat_status is not None
        and required_threat_status not in VALID_THREAT_STATUSES
    ):
        raise ReviewError("required threat-register lifecycle status is unsupported")
    if len(RELEASE_INPUTS) != len(set(RELEASE_INPUTS)):
        raise ReviewError("RELEASE_INPUTS contains a duplicate path")
    for relative in RELEASE_INPUTS:
        _relative_parts(relative, label="declared release input path")
    held = _open_held_root(repo, label="release repository")
    rows: list[dict[str, Any]] = []
    source_documents: tuple[dict[str, Any], dict[str, Any], str, str] | None = None
    captured_source_bytes: dict[str, bytes] = {}
    observed_threat_status: str | None = None
    directory_identities = {"": held.identity}
    file_identities: set[tuple[int, int]] = set()
    release_file_identities: dict[str, tuple[int, ...]] = {}
    aggregate_size = 0
    try:
        assert_no_replace_refs(repo)
        _verify_held_root(held)
        raw_index = _read_relevant_release_index(repo)
        _verify_held_root(held)
        index_entries = _parse_relevant_release_index(raw_index)
        _assert_release_tool_coverage_from_index(index_entries)

        for relative in RELEASE_INPUTS:
            entries = index_entries.get(relative, [])
            if len(entries) != 1 or entries[0].stage != 0:
                raise ReviewError(
                    "release audit input must have exactly one stage-zero tracked "
                    f"entry: {relative}"
                )
            mode = entries[0].mode
            blob = entries[0].blob
            if mode not in {"100644", "100755"}:
                raise ReviewError(
                    f"release audit input index entry is not a regular file: {relative}"
                )
            indexed_data = bytes(
                git(
                    repo,
                    "cat-file",
                    "blob",
                    blob,
                    text=False,
                    max_bytes=MAX_RELEASE_INPUT_FILE_BYTES,
                )
            )
            _verify_held_root(held)
            aggregate_size += len(indexed_data)
            if aggregate_size > MAX_RELEASE_INPUT_AGGREGATE_BYTES:
                raise ReviewError(
                    "release audit inputs exceed the aggregate byte limit"
                )
            if relative == THREAT_REGISTER_PATH:
                observed_threat_status = threat_register_status(indexed_data)
            if relative in {
                "release/0.9.0/handoff-source.json",
                "release/0.9.0/audit-inputs.json",
            }:
                if len(indexed_data) > MAX_SOURCE_DOCUMENT_BYTES:
                    raise ReviewError(
                        f"source document exceeds the byte limit: {relative}"
                    )
                captured_source_bytes[relative] = indexed_data

            captured = _read_rooted_regular_file(
                held.descriptor,
                relative,
                max_bytes=MAX_RELEASE_INPUT_FILE_BYTES,
                expected_size=len(indexed_data),
                label=f"release audit input {relative}",
                directory_identities=directory_identities,
                record_directories=True,
                require_exact_names=True,
                expected_git_mode=mode,
                size_mismatch_message=(
                    f"release audit input differs from its indexed blob: {relative}"
                ),
            )
            file_identity = (captured.identity[0], captured.identity[1])
            if file_identity in file_identities:
                raise ReviewError(
                    f"release audit input shares a file identity: {relative}"
                )
            file_identities.add(file_identity)
            release_file_identities[relative] = captured.identity
            if captured.document != indexed_data:
                raise ReviewError(
                    f"release audit input differs from its indexed blob: {relative}"
                )
            rows.append(
                {
                    "path": relative,
                    "git_mode": mode,
                    "git_blob_id": blob,
                    "sha256": digest_bytes(indexed_data),
                    "size_bytes": len(indexed_data),
                }
            )
            _verify_held_root(held)

        _verify_rooted_directories(
            held.descriptor,
            directory_identities,
            label="release repository",
        )
        if bind_source_documents:
            source_documents = validate_source_documents(
                repo,
                captured_documents=captured_source_bytes,
            )
            if observed_threat_status is None:
                raise ReviewError("release input snapshot omits the threat register")
            validate_source_preparation_lifecycle(
                source_documents[1],
                observed_threat_status,
            )
        for relative in RELEASE_INPUTS:
            _verify_rooted_regular_file_identity(
                held.descriptor,
                relative,
                release_file_identities[relative],
                directory_identities,
                label=f"release audit input {relative}",
            )
        final_index = _read_relevant_release_index(repo)
        _verify_held_root(held)
        if final_index != raw_index:
            raise ReviewError(
                "complete relevant release index changed during the transaction"
            )
        if required_threat_status is not None:
            if THREAT_REGISTER_PATH not in RELEASE_INPUTS:
                raise ReviewError(
                    "the threat register is absent from the release input contract"
                )
            if observed_threat_status != required_threat_status:
                raise ReviewError(
                    "indexed threat register must have lifecycle status "
                    f"{required_threat_status}"
                )
        assert_no_replace_refs(repo)
        _verify_rooted_directories(
            held.descriptor,
            directory_identities,
            label="release repository",
        )
        for relative in RELEASE_INPUTS:
            _verify_rooted_regular_file_identity(
                held.descriptor,
                relative,
                release_file_identities[relative],
                directory_identities,
                label=f"release audit input {relative}",
            )
        _verify_held_root(held)
        return ReleaseInputSnapshot(rows, source_documents)
    finally:
        _close_held_root(held)


def release_input_manifest(
    repo: Path,
    *,
    required_threat_status: str | None = None,
) -> list[dict[str, Any]]:
    """Bind each declared release input to its exact stage-zero index identity."""

    return _capture_release_input_snapshot(
        repo,
        required_threat_status=required_threat_status,
        bind_source_documents=required_threat_status is not None,
    ).rows


def validate_handoff_rows(value: Any) -> list[dict[str, Any]]:
    rows = exact_list(value, "handoff files")
    if not rows:
        raise ReviewError("handoff files must not be empty")
    if len(rows) > MAX_HANDOFF_ENTRIES:
        raise ReviewError("handoff inventory exceeds the entry-count limit")
    seen: set[str] = set()
    validated: list[dict[str, Any]] = []
    aggregate_size = 0
    previous_path = ""
    for index, raw_row in enumerate(rows):
        label = f"handoff file {index}"
        if type(raw_row) is not dict:
            raise ReviewError(f"{label} must be a JSON object")
        kind = raw_row.get("kind")
        keys = {"path", "kind", "sha256", "size_bytes"}
        if kind == "regular":
            keys.add("mode")
        elif kind == "symlink":
            keys.add("target")
        else:
            raise ReviewError(f"{label} has an unsupported kind")
        row = exact_object(raw_row, keys, label)
        relative = exact_string(row["path"], f"{label} path")
        _relative_parts(relative, label=f"{label} path")
        if relative in seen:
            raise ReviewError(f"handoff file path is duplicated: {relative}")
        if relative <= previous_path:
            raise ReviewError("handoff file paths must be unique and strictly ordered")
        seen.add(relative)
        previous_path = relative
        exact_digest(row["sha256"], f"{label} sha256")
        size = exact_integer(row["size_bytes"], f"{label} size_bytes")
        if kind == "regular":
            mode = exact_string(row["mode"], f"{label} mode")
            if re.fullmatch(r"[0-7]{4}", mode) is None:
                raise ReviewError(f"{label} mode must be four octal digits")
            if size > MAX_HANDOFF_FILE_BYTES:
                raise ReviewError(f"{label} exceeds the regular-file byte limit")
        if kind == "symlink":
            target = exact_string(row["target"], f"{label} target", nonempty=False)
            try:
                encoded = target.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ReviewError(f"{label} target is not valid UTF-8") from error
            if len(encoded) > MAX_HANDOFF_SYMLINK_BYTES:
                raise ReviewError(f"{label} target exceeds the symlink byte limit")
            if row["sha256"] != digest_bytes(encoded) or row["size_bytes"] != len(
                encoded
            ):
                raise ReviewError(f"{label} symlink target identity is inconsistent")
        aggregate_size += size
        if aggregate_size > MAX_HANDOFF_AGGREGATE_BYTES:
            raise ReviewError("handoff inventory exceeds the aggregate byte limit")
        validated.append(row)
    return validated


def validate_handoff_manifest(
    value: Any,
    handoff_source: dict[str, Any],
    supplied_root: Path | None,
) -> None:
    handoff = exact_object(
        value,
        {
            "root_name",
            "file_count",
            "total_bytes",
            "files",
            "galadriel_child_archive_sha256",
            "galadriel_task_ledger_sha256",
        },
        "frozen handoff",
    )
    root_name = exact_string(handoff["root_name"], "frozen handoff root_name")
    _relative_parts(
        root_name,
        label="frozen handoff root_name",
        max_depth=1,
    )
    if root_name != handoff_source["master_package"]:
        raise ReviewError("frozen handoff root name does not match its source binding")
    rows = validate_handoff_rows(handoff["files"])
    if exact_integer(
        handoff["file_count"], "frozen handoff file_count", minimum=1
    ) != len(rows):
        raise ReviewError("frozen handoff file_count does not match its inventory")
    expected_total = sum(int(row["size_bytes"]) for row in rows)
    declared_total = exact_integer(handoff["total_bytes"], "frozen handoff total_bytes")
    if declared_total > MAX_HANDOFF_AGGREGATE_BYTES:
        raise ReviewError("frozen handoff exceeds the aggregate byte limit")
    if declared_total != expected_total:
        raise ReviewError("frozen handoff total_bytes does not match its inventory")
    child_digest = exact_digest(
        handoff["galadriel_child_archive_sha256"],
        "frozen handoff child archive digest",
    )
    ledger_digest = exact_digest(
        handoff["galadriel_task_ledger_sha256"],
        "frozen handoff task ledger digest",
    )
    if child_digest != handoff_source["child_archive_sha256"]:
        raise ReviewError(
            "frozen handoff child archive digest breaks its source binding"
        )
    if ledger_digest != handoff_source["task_ledger_sha256"]:
        raise ReviewError("frozen handoff task ledger digest breaks its source binding")
    by_path = {row["path"]: row for row in rows}
    child = by_path.get(handoff_source["child_archive"])
    if child is None or child["kind"] != "regular" or child["sha256"] != child_digest:
        raise ReviewError("frozen handoff does not contain its bound child archive")
    ledger_path = (
        f"{Path(handoff_source['child_archive']).stem}/MASTER_TASK_LEDGER.yaml"
    )
    ledger = by_path.get(ledger_path)
    if (
        ledger is None
        or ledger["kind"] != "regular"
        or ledger["sha256"] != ledger_digest
    ):
        raise ReviewError("frozen handoff does not contain its bound task ledger")
    if supplied_root is not None:
        if supplied_root.name != root_name:
            raise ReviewError("supplied handoff root name differs from the frozen root")
        current_rows = strict_relative_files(supplied_root)
        if current_rows != rows:
            raise ReviewError(
                "supplied handoff inventory differs from the frozen inventory"
            )


def validate_repository_ref_inputs(value: Any) -> None:
    refs = exact_object(
        value,
        {"origin", "local_tags_at_freeze", "note"},
        "historical repository ref inputs",
    )
    origin = exact_string(refs["origin"], "historical origin")
    if origin not in {
        EXPECTED_BASELINE_REPOSITORY,
        "git@github.com:sepahead/galadriel.git",
        "ssh://git@github.com/sepahead/galadriel.git",
        f"{EXPECTED_BASELINE_REPOSITORY}.git",
    }:
        raise ReviewError(
            "historical origin is not a canonical credential-free repository"
        )
    if refs["note"] != REF_INPUT_NOTE:
        raise ReviewError(
            "historical ref-input note does not match the freeze contract"
        )
    tags = exact_list(refs["local_tags_at_freeze"], "historical tag inventory")
    if len(tags) > MAX_HISTORICAL_TAGS:
        raise ReviewError(
            f"historical tag inventory exceeds {MAX_HISTORICAL_TAGS} entries"
        )
    previous = ""
    for index, raw_tag in enumerate(tags):
        tag = exact_object(
            raw_tag,
            {"ref", "object", "object_type", "peeled_object"},
            f"historical tag {index}",
        )
        refname = exact_string(tag["ref"], f"historical tag {index} ref")
        if not refname.startswith("refs/tags/") or refname <= previous:
            raise ReviewError("historical tag refs must be unique and strictly ordered")
        check = run_bounded_host_command(
            ["git", "check-ref-format", refname],
            context="historical tag ref check",
            environment=release_tool_environment(),
            max_stdout_bytes=MAX_HOST_IDENTITY_STDOUT_BYTES,
            max_stderr_bytes=MAX_HOST_IDENTITY_STDERR_BYTES,
            timeout_seconds=HOST_IDENTITY_TIMEOUT_SECONDS,
        )
        if check.returncode != 0:
            raise ReviewError(f"historical tag has an invalid refname: {refname}")
        previous = refname
        exact_object_id(tag["object"], f"historical tag {index} object")
        object_type = exact_string(
            tag["object_type"], f"historical tag {index} object_type"
        )
        if object_type not in {"blob", "commit", "tag", "tree"}:
            raise ReviewError(f"historical tag {index} has an invalid object type")
        peeled = tag["peeled_object"]
        if object_type == "tag":
            exact_object_id(peeled, f"historical tag {index} peeled_object")
        elif peeled is not None:
            raise ReviewError(
                f"historical lightweight tag {index} must have null peeled_object"
            )


def signer_fingerprint(allowed_signer_bytes: bytes) -> str:
    process = run_bounded_host_command(
        ["ssh-keygen", "-lf", "-", "-E", "sha256"],
        context="allowed signer fingerprint",
        stdin_document=allowed_signer_bytes,
        environment=release_tool_environment(),
        max_stdout_bytes=MAX_HOST_IDENTITY_STDOUT_BYTES,
        max_stderr_bytes=MAX_HOST_IDENTITY_STDERR_BYTES,
        timeout_seconds=HOST_IDENTITY_TIMEOUT_SECONDS,
    )
    if process.returncode != 0:
        raise ReviewError(
            "cannot fingerprint allowed signer: " + bounded_diagnostic(process.stderr)
        )
    lines = process.stdout.decode("utf-8", "replace").splitlines()
    if len(lines) != 1 or not lines[0]:
        raise ReviewError("allowed signer must resolve to exactly one fingerprint")
    fields = lines[0].split()
    if (
        len(fields) != 4
        or fields[0] != "256"
        or not fields[1].startswith("SHA256:")
        or fields[2] != SIGNATURE_PRINCIPAL
        or fields[3] != "(ED25519)"
    ):
        raise ReviewError("allowed signer fingerprint has an unexpected Ed25519 shape")
    encoded = fields[1].removeprefix("SHA256:")
    try:
        decoded = base64.b64decode(encoded + "=", validate=True)
    except (binascii.Error, ValueError) as error:
        raise ReviewError(
            "allowed signer fingerprint is not canonical SHA-256"
        ) from error
    if (
        len(decoded) != 32
        or base64.b64encode(decoded).decode("ascii").rstrip("=") != encoded
    ):
        raise ReviewError("allowed signer fingerprint is not canonical SHA-256")
    return lines[0]


def validate_allowed_signer_bytes(raw: bytes) -> str:
    """Validate one already-snapshotted allowed-signers entry."""

    try:
        text = raw.decode("ascii")
    except UnicodeError as error:
        raise ReviewError(f"cannot read allowed signer: {error}") from error
    if not raw.endswith(b"\n") or text.count("\n") != 1:
        raise ReviewError(
            "allowed signer must contain exactly one newline-terminated entry"
        )
    fields = text.rstrip("\n").split(" ")
    if len(fields) != 3 or any(not field for field in fields):
        raise ReviewError(
            "allowed signer must have exactly principal, key type, and key data"
        )
    principal, key_type, encoded_key = fields
    if principal != SIGNATURE_PRINCIPAL:
        raise ReviewError(
            "allowed signer principal does not match the release contract"
        )
    if key_type != "ssh-ed25519":
        raise ReviewError("allowed signer key type must be exactly ssh-ed25519")
    try:
        decoded_key = base64.b64decode(encoded_key, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ReviewError("allowed signer key data is not canonical base64") from error
    if not decoded_key or base64.b64encode(decoded_key).decode("ascii") != encoded_key:
        raise ReviewError("allowed signer key data is not canonical base64")
    return signer_fingerprint(raw)


def validate_allowed_signer(allowed_signers: Path) -> str:
    raw = read_bounded_regular_file(
        allowed_signers,
        MAX_ALLOWED_SIGNERS_BYTES,
        label="allowed-signers file",
        limit_label="4 KiB",
    )
    return validate_allowed_signer_bytes(raw)


def validate_signature(
    manifest_bytes: bytes,
    output: Path,
    allowed_signers: Path,
) -> str:
    """Authenticate the raw manifest through fixed, non-manifest trust inputs."""

    signature_path = output.with_name(output.name + ".sig")
    if output == allowed_signers or signature_path == allowed_signers:
        raise ReviewError("manifest, signer, and signature paths must be distinct")
    allowed_signer_bytes = read_bounded_regular_file(
        allowed_signers,
        MAX_ALLOWED_SIGNERS_BYTES,
        label="allowed-signers file",
        limit_label="4 KiB",
    )
    fingerprint = validate_allowed_signer_bytes(allowed_signer_bytes)
    signature_bytes = read_bounded_regular_file(
        signature_path,
        MAX_SIGNATURE_BYTES,
        label="frozen audit-input signature",
        limit_label="64 KiB",
    )
    with tempfile.TemporaryDirectory(prefix="galadriel-freeze-signature-") as directory:
        signer_snapshot = Path(directory) / "ALLOWED_SIGNERS"
        signer_snapshot.write_bytes(allowed_signer_bytes)
        signature_snapshot = Path(directory) / "manifest.sshsig"
        signature_snapshot.write_bytes(signature_bytes)
        process = run_bounded_host_command(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(signer_snapshot),
                "-I",
                SIGNATURE_PRINCIPAL,
                "-n",
                SIGNATURE_NAMESPACE,
                "-s",
                str(signature_snapshot),
            ],
            context="frozen audit-input signature verification",
            stdin_document=manifest_bytes,
            environment=release_tool_environment(),
            max_stdout_bytes=MAX_HOST_IDENTITY_STDOUT_BYTES,
            max_stderr_bytes=MAX_HOST_IDENTITY_STDERR_BYTES,
            timeout_seconds=HOST_IDENTITY_TIMEOUT_SECONDS,
        )
    if process.returncode != 0:
        raise ReviewError(
            "frozen audit-input signature verification failed: "
            + bounded_diagnostic(process.stderr)
        )
    return fingerprint


def validate_signature_contract(
    contract: Any,
    output: Path,
    allowed_signers: Path,
    fingerprint: str,
) -> None:
    """Validate authenticated manifest metadata against the fixed trust contract."""

    signature_contract = exact_object(
        contract,
        {
            "format",
            "namespace",
            "principal",
            "public_key_fingerprint",
            "signature_path",
            "allowed_signers_path",
        },
        "signature contract",
    )
    expected_contract = {
        "format": SIGNATURE_FORMAT,
        "namespace": SIGNATURE_NAMESPACE,
        "principal": SIGNATURE_PRINCIPAL,
        "signature_path": output.name + ".sig",
        "allowed_signers_path": allowed_signers.name,
    }
    for key, expected in expected_contract.items():
        if signature_contract[key] != expected:
            raise ReviewError(f"signature contract {key} is not {expected!r}")
    if signature_contract["public_key_fingerprint"] != fingerprint:
        raise ReviewError(
            "allowed signer fingerprint differs from the signature contract"
        )


def generate_frozen_inputs(
    repo: Path, handoff_root: Path, output: Path, allowed_signers: Path
) -> None:
    signature_path = output.with_name(output.name + ".sig")
    if output == allowed_signers or allowed_signers == signature_path:
        raise ReviewError("manifest, signer, and signature paths must be distinct")
    for label, path in (
        ("manifest", output),
        ("allowed-signers", allowed_signers),
        ("signature", signature_path),
    ):
        if path.exists() or path.is_symlink():
            raise ReviewError(f"{label} output already exists: {path}")

    release_snapshot = _capture_release_input_snapshot(
        repo,
        required_threat_status=THREAT_STATUS_FROZEN,
        bind_source_documents=True,
    )
    if release_snapshot.source_documents is None:
        raise ReviewError("release source-document capture is incomplete")
    handoff_source, audit_inputs, baseline_commit, declared_tree = (
        release_snapshot.source_documents
    )
    baseline = baseline_manifest(repo, baseline_commit, declared_tree)
    baseline["repository"] = audit_inputs["baseline_repository"]["url"]
    release_files = release_snapshot.rows
    handoff_files = strict_relative_files(handoff_root)
    handoff = {
        "root_name": handoff_root.name,
        "file_count": len(handoff_files),
        "total_bytes": sum(int(row["size_bytes"]) for row in handoff_files),
        "files": handoff_files,
        "galadriel_child_archive_sha256": handoff_source["child_archive_sha256"],
        "galadriel_task_ledger_sha256": handoff_source["task_ledger_sha256"],
    }
    validate_handoff_manifest(handoff, handoff_source, handoff_root)

    signing_key = str(git(repo, "config", "--get", "user.signingkey")).strip()
    if not signing_key:
        raise ReviewError("Git user.signingkey is not configured")
    public_key_bytes = read_bounded_regular_file(
        Path(signing_key).expanduser(),
        MAX_ALLOWED_SIGNERS_BYTES,
        label="configured signing public key",
        limit_label="4 KiB",
    )
    try:
        public_key = public_key_bytes.decode("ascii")
    except UnicodeError as error:
        raise ReviewError("configured signing key must be ASCII") from error
    public_key_lines = public_key.splitlines()
    if len(public_key_lines) != 1:
        raise ReviewError(
            "configured signing key must contain exactly one public key entry"
        )
    key_fields = public_key_lines[0].split()
    if len(key_fields) < 2 or key_fields[0] != "ssh-ed25519":
        raise ReviewError("configured signing key must be exactly ssh-ed25519")
    allowed_signer_line = f"{SIGNATURE_PRINCIPAL} {key_fields[0]} {key_fields[1]}\n"

    # Fingerprint the exact in-memory entry before any final output path exists.
    fingerprint = signer_fingerprint(allowed_signer_line.encode("ascii"))
    manifest = {
        "schema": SCHEMA,
        "release": RELEASE,
        "baseline": baseline,
        "repository_ref_inputs": {
            "origin": canonical_repository_identity(repo),
            "local_tags_at_freeze": tag_inventory(repo),
            "note": REF_INPUT_NOTE,
        },
        "handoff": handoff,
        "release_input_files": release_files,
        "signature_contract": {
            "format": SIGNATURE_FORMAT,
            "namespace": SIGNATURE_NAMESPACE,
            "principal": SIGNATURE_PRINCIPAL,
            "public_key_fingerprint": fingerprint,
            "signature_path": output.name + ".sig",
            "allowed_signers_path": allowed_signers.name,
        },
        "scope_note": SCOPE_NOTE,
    }
    manifest_bytes = canonical_json(manifest)
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise ReviewError("generated frozen audit-input manifest exceeds 4 MiB")

    output.parent.mkdir(parents=True, exist_ok=True)
    allowed_signers.parent.mkdir(parents=True, exist_ok=True)
    signer_created = False
    output_created = False
    try:
        with allowed_signers.open("x", encoding="ascii") as handle:
            signer_created = True
            handle.write(allowed_signer_line)
        if validate_allowed_signer(allowed_signers) != fingerprint:
            raise ReviewError("generated allowed signer fingerprint is inconsistent")
        with output.open("xb") as handle:
            output_created = True
            handle.write(manifest_bytes)
    except BaseException:
        partial_outputs = []
        if output_created:
            partial_outputs.append(output)
        if signer_created:
            partial_outputs.append(allowed_signers)
        _remove_created_paths(partial_outputs, context="frozen audit-input")
        raise


def verify_frozen_inputs(
    repo: Path,
    handoff_root: Path | None,
    output: Path,
    allowed_signers: Path,
) -> None:
    manifest_bytes = read_bounded_regular_file(
        output,
        MAX_MANIFEST_BYTES,
        label="frozen audit-input manifest",
        limit_label="4 MiB verification",
    )
    fingerprint = validate_signature(manifest_bytes, output, allowed_signers)
    try:
        manifest = loads_json(manifest_bytes)
    except (UnicodeError, ValueError) as error:
        raise ReviewError(f"cannot load {output}: {error}") from error
    if canonical_json(manifest) != manifest_bytes:
        raise ReviewError("frozen audit-input manifest is not strict canonical JSON")
    root = exact_object(
        manifest,
        {
            "schema",
            "release",
            "baseline",
            "repository_ref_inputs",
            "handoff",
            "release_input_files",
            "signature_contract",
            "scope_note",
        },
        "frozen audit-input manifest",
    )
    if root["schema"] != SCHEMA:
        raise ReviewError(f"frozen audit-input schema is not {SCHEMA}")
    release = exact_object(
        root["release"], {"version", "author", "doi", "zenodo"}, "frozen release"
    )
    if release != RELEASE:
        raise ReviewError(
            "frozen release must identify 0.9.0 with the expected author and null "
            "DOI/Zenodo fields"
        )
    if root["scope_note"] != SCOPE_NOTE:
        raise ReviewError("frozen audit-input scope note differs from the contract")

    validate_signature_contract(
        root["signature_contract"], output, allowed_signers, fingerprint
    )

    release_snapshot = _capture_release_input_snapshot(
        repo,
        required_threat_status=THREAT_STATUS_FROZEN,
        bind_source_documents=True,
    )
    if release_snapshot.source_documents is None:
        raise ReviewError("release source-document capture is incomplete")
    handoff_source, audit_inputs, baseline_commit, declared_tree = (
        release_snapshot.source_documents
    )
    expected_baseline = baseline_manifest(repo, baseline_commit, declared_tree)
    expected_baseline["repository"] = audit_inputs["baseline_repository"]["url"]
    exact_object(
        root["baseline"],
        {
            "repository",
            "commit",
            "tree",
            "files",
            "submodules",
            "locked_git_dependencies",
        },
        "frozen baseline",
    )
    if root["baseline"] != expected_baseline:
        raise ReviewError(
            "frozen baseline identities do not match the declared baseline"
        )

    release_inputs = exact_list(root["release_input_files"], "release input files")
    for index, row in enumerate(release_inputs):
        validated_row = exact_object(
            row,
            {"path", "git_mode", "git_blob_id", "sha256", "size_bytes"},
            f"release input {index}",
        )
        _relative_parts(
            exact_string(validated_row["path"], f"release input {index} path"),
            label=f"release input {index} path",
        )
        mode = exact_string(
            validated_row["git_mode"],
            f"release input {index} git_mode",
        )
        if mode not in {"100644", "100755"}:
            raise ReviewError(
                f"release input {index} git_mode is not a regular-file mode"
            )
        exact_object_id(
            validated_row["git_blob_id"],
            f"release input {index} git_blob_id",
        )
        exact_digest(validated_row["sha256"], f"release input {index} sha256")
        exact_integer(
            validated_row["size_bytes"],
            f"release input {index} size_bytes",
        )
    if release_inputs != release_snapshot.rows:
        raise ReviewError(
            "release input files are not the exact ordered current RELEASE_INPUTS set"
        )

    validate_handoff_manifest(root["handoff"], handoff_source, handoff_root)
    validate_repository_ref_inputs(root["repository_ref_inputs"])


def verify_freeze_lifecycle(
    repo: Path,
    handoff_root: Path | None,
    output: Path,
    allowed_signers: Path,
) -> str:
    """Verify the exact living or frozen audit-input lifecycle state."""

    register_bytes = read_bounded_regular_file(
        repo / THREAT_REGISTER_PATH,
        MAX_THREAT_REGISTER_BYTES,
        label="threat register",
        limit_label="4 MiB lifecycle",
    )
    status = threat_register_status(register_bytes)
    signature_path = output.with_name(output.name + ".sig")
    if status == THREAT_STATUS_LIVING:
        release_input_manifest(
            repo,
            required_threat_status=THREAT_STATUS_LIVING,
        )
        validate_allowed_signer(allowed_signers)
        for label, path in (
            ("active frozen manifest", output),
            ("active frozen signature", signature_path),
        ):
            if path.exists() or path.is_symlink():
                raise ReviewError(f"{label} must be absent in the living state")
        return status
    verify_frozen_inputs(repo, handoff_root, output, allowed_signers)
    return status


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        nargs="?",
        choices=("generate", "verify", "verify-lifecycle"),
        default="generate",
    )
    parser.add_argument("--repo", default=".")
    parser.add_argument("--handoff-root")
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--allowed-signers",
        help="OpenSSH allowed-signers path (default: ALLOWED_SIGNERS beside --out)",
    )
    arguments = parser.parse_args()

    repo = Path(arguments.repo).resolve()
    handoff_root = (
        Path(os.path.abspath(os.path.expanduser(arguments.handoff_root)))
        if arguments.handoff_root
        else None
    )
    # Keep the final component lexical so the regular-file checks below cannot be
    # bypassed by resolving a manifest or signer symlink before inspecting it.
    output = Path(os.path.abspath(os.path.expanduser(arguments.out)))
    allowed_signers = (
        Path(os.path.abspath(os.path.expanduser(arguments.allowed_signers)))
        if arguments.allowed_signers
        else output.parent / "ALLOWED_SIGNERS"
    )
    if output == allowed_signers:
        print(
            "audit-input freeze failed: manifest and allowed-signers paths must differ",
            file=sys.stderr,
        )
        return 2
    if arguments.action == "generate":
        if handoff_root is None:
            print(
                "audit-input freeze failed: --handoff-root is required for generation",
                file=sys.stderr,
            )
            return 2
        if output.exists() or output.is_symlink():
            print(
                f"audit-input freeze failed: output already exists: {output}",
                file=sys.stderr,
            )
            return 2
        if allowed_signers.exists() or allowed_signers.is_symlink():
            print(
                "audit-input freeze failed: allowed-signers output already exists: "
                f"{allowed_signers}",
                file=sys.stderr,
            )
            return 2

    try:
        if arguments.action == "generate":
            assert handoff_root is not None
            generate_frozen_inputs(repo, handoff_root, output, allowed_signers)
            print(output)
            print(allowed_signers)
        elif arguments.action == "verify":
            verify_frozen_inputs(repo, handoff_root, output, allowed_signers)
            print(f"FROZEN_AUDIT_INPUTS_OK {output}")
        else:
            status = verify_freeze_lifecycle(
                repo,
                handoff_root,
                output,
                allowed_signers,
            )
            print(f"FREEZE_LIFECYCLE_OK {status} {output}")
    except (
        KeyError,
        OSError,
        RecursionError,
        ReviewError,
        UnicodeError,
        ValueError,
    ) as error:
        print(f"audit-input freeze failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
