#!/usr/bin/env python3
"""Generate and verify deterministic Galadriel release audit artifacts.

The program captures one stage-zero Git index.
It authenticates each indexed blob.
It requires each tracked worktree path to match the index.
It uses the captured bytes for all semantic checks.
It writes canonical JavaScript Object Notation output.
It uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from datetime import date
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Mapping, NamedTuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
REPO_WORK = ROOT / "repo_work"
if str(REPO_WORK) not in sys.path:
    sys.path.insert(0, str(REPO_WORK))

from repo_work import build_task_dispositions as closure_plan  # noqa: E402
from repo_work.common import (  # noqa: E402
    MAX_GIT_DIAGNOSTIC_BYTES,
    SAFE_GIT_CONFIGURATION,
    ReviewError,
    RootedFileBatchCapture,
    RootedFileCaptureRequest,
    canonical_relative_parts,
    git as safe_git,
    loads_json,
    read_rooted_regular_files,
    run_bounded_host_command,
    safe_git_environment,
    validate_json_number_bounds,
    write_rooted_regular_file,
)
from finalize_release import (  # noqa: E402
    EXPECTED_QUALIFICATION_TOOLS,
    RUSTSEC_ADVISORY_DATABASE,
)
from qualify_candidate import (  # noqa: E402
    ADVISORY_DB_COMMIT,
    ADVISORY_DB_DENY_DIRECTORY,
    ADVISORY_DB_TREE,
    ADVISORY_DB_URL,
    BASE_COMMANDS,
)


RELEASE = ROOT / "release" / "0.9.0"
INPUTS = RELEASE / "audit-inputs.json"
CLAIMS = RELEASE / "claims.json"
DISPOSITIONS = RELEASE / "task-dispositions.json"
CLOSURE_PLAN = RELEASE / "task-closure-plan.json"
TASKS = RELEASE / "tasks.json"
HANDOFF_SOURCE = RELEASE / "handoff-source.json"
THREAT_REGISTER = RELEASE / "audit" / "threat-register.json"
ECOSYSTEM_CUT = RELEASE / "ecosystem-cut.json"
AUDIT_OUTPUT = RELEASE / "audit-manifest.json"
LEDGER_OUTPUT = RELEASE / "requirements-ledger.json"
VERSION = "0.9.0"
RELEASE_DATE = "2026-07-25"
PUBLICATION_CHANNEL = "review-gated GitHub research source release"

AUDIT_SELF_EXCLUSIONS = frozenset({AUDIT_OUTPUT.relative_to(ROOT).as_posix()})
GENERATED_PATHS = frozenset(
    {
        AUDIT_OUTPUT.relative_to(ROOT).as_posix(),
        LEDGER_OUTPUT.relative_to(ROOT).as_posix(),
    }
)

MAX_TRACKED_FILES = 4_096
MAX_TRACKED_FILE_BYTES = 8 * 1024 * 1024
MAX_TRACKED_AGGREGATE_BYTES = 64 * 1024 * 1024
MAX_INDEX_BYTES = 4 * 1024 * 1024
MAX_BATCH_OUTPUT_BYTES = MAX_TRACKED_AGGREGATE_BYTES + 1024 * MAX_TRACKED_FILES
MAX_PATH_BYTES = 4 * 1024
MAX_COMPONENT_BYTES = 255
MAX_PATH_DEPTH = 128
MAX_DIRECTORY_ENTRIES = 32_768

TASK_ID = re.compile(r"T(?P<number>\d{3})\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")
URL = re.compile(r"https?://[^\s<>\]\[)}`\"']+")
DOI_URL = re.compile(r"https?://(?:dx\.)?doi\.org/", re.IGNORECASE)
VALID_STATUSES = {"OPEN", "COMPLETE", "NOT_CLAIMED"}
VALID_TIERS = {
    "IMPLEMENTED",
    "VALIDATED",
    "DEPLOYMENT_QUALIFIED",
    "NOT_CLAIMED",
}
LENSES = tuple(f"L{index:02d}" for index in range(1, 21))
VALID_THREAT_DISPOSITIONS = {
    "FIX_AND_PROVE",
    "REMOVE_FROM_0_9",
    "KEEP_EXPERIMENTAL_AND_NOT_CLAIMED",
    "NO_GO",
}
VALID_THREAT_REGISTER_STATUSES = {
    "LIVING_UNTIL_CANDIDATE_FREEZE",
    "FROZEN_AT_CANDIDATE",
}
REQUIRED_REPOSITORY_INPUTS = {
    "pid-rs": (
        "https://github.com/sepahead/pid-rs",
        "1cd2424f7967e1752dcc8e53859e8fdad3566f51",
        "optional PID research dependency selected by Cargo.lock",
        "PINNED_COMPONENT",
    ),
    "NCP": (
        "https://github.com/sepahead/NCP",
        "2f5bd586d4bb20c90362bb6f5698b7f64057ba4e",
        "optional NCP 0.8 transport dependency selected by Cargo.lock",
        "PINNED_COMPONENT",
    ),
    "Crebain": (
        "https://github.com/sepahead/crebain",
        "4c311900ade5668200a48d56fb191be1916b884a",
        "retained historical reference-producer fixture for contract review with no Cargo or runtime dependency",
        "RECIPROCAL_FIXTURE",
    ),
    "Haldir": (
        "https://github.com/sepahead/haldir",
        "5f7d183625a982741c51958e2d10bc12bb628ca0",
        "retained T000 exact-commit snapshot for prospective downstream contract review with no Galadriel runtime edge",
        "NOT_CLAIMED",
    ),
    "Prisoma": (
        "https://github.com/sepahead/prisoma",
        "0968128062f30da5c04f3f31c23f6ce8e0d95d36",
        "retained frozen-baseline inventory for prospective offline-consumer review with no Galadriel runtime edge",
        "NOT_CLAIMED",
    ),
    "Paper2Brain": (
        "https://github.com/sepahead/Paper2Brain",
        "9845c31bc5bae4746120858037b27f9c9ed2f445",
        "retained application inventory snapshot with no Galadriel dependency, API, route, adapter, or runtime edge",
        "NOT_CLAIMED",
    ),
    "RustSec advisory database": (
        "https://github.com/RustSec/advisory-db",
        "f981d991604f3e7d4a0eb94e559cb3e5a94a6dc2",
        "pinned offline advisory input for exact-candidate qualification",
        "PINNED_COMPONENT",
    ),
}
LOCKED_REPOSITORY_PACKAGES = {
    "pid-rs": {"pid-core", "pid-runlog"},
    "NCP": {"ncp-core", "ncp-zenoh"},
}
AUDIT_TO_QUALIFICATION_TOOL = {
    "git": "git",
    "rustc": "rustc",
    "cargo": "cargo",
    "python": "python",
    "cargo-public-api": "cargo_public_api",
    "rustc-nightly": "rustc_fuzz_nightly",
    "cargo-fuzz": "cargo_fuzz",
    "rustc-current-stable": "rustc_current_stable",
    "cargo-current-stable": "cargo_current_stable",
    "cargo-deny": "cargo_deny",
    "cargo-audit": "cargo_audit",
    "cargo-cyclonedx": "cargo_cyclonedx",
}
REQUIRED_TOOL_VERSIONS = {
    "git": "2.50.1",
    "rustc": "1.89.0",
    "cargo": "1.89.0",
    "python": "3.14.6",
    "host": "Darwin 25.5.0",
    "cargo-public-api": "0.52.0",
    "rustc-nightly": "nightly-2026-06-16",
    "cargo-fuzz": "0.13.2",
    "rustc-current-stable": "1.97.1",
    "cargo-current-stable": "1.97.1",
    "cargo-deny": "0.19.9",
    "cargo-audit": "0.22.2",
    "cargo-cyclonedx": "0.5.9",
    "cargo-mutants": "27.1.0",
    "OpenSSH": "10.2p1",
    "GitHub CLI": "2.95.0",
}
ADDITIONAL_TOOL_IDENTITIES = {
    "host": "arm64",
    "cargo-mutants": "cargo-mutants 27.1.0 installed with --locked",
    "OpenSSH": "OpenSSH_10.2p1, LibreSSL 3.3.6",
    "GitHub CLI": "gh version 2.95.0 (2026-06-17)",
}
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


class AuditError(RuntimeError):
    """A release input or generated artifact violates the frozen contract."""


class IndexEntry(NamedTuple):
    """One stage-zero regular-file row from the captured Git index."""

    path: str
    git_mode: str
    git_blob_id: str


class IndexedRegularFile(NamedTuple):
    """One authenticated Git blob bound to an index path."""

    path: str
    git_mode: str
    git_blob_id: str
    data: bytes
    sha256: str
    size_bytes: int


class RepositorySnapshot(NamedTuple):
    """One bounded index, object, and worktree capture."""

    index_bytes: bytes
    files: Mapping[str, IndexedRegularFile]
    worktree: Mapping[str, RootedFileBatchCapture]


def _git_blob_id(data: bytes) -> str:
    """Return the Git SHA-1 identity for exact blob bytes."""

    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()


def _read_index_bytes() -> bytes:
    """Capture the exact stage-zero index inventory with a byte bound."""

    try:
        return bytes(
            safe_git(
                ROOT,
                "--literal-pathspecs",
                "ls-files",
                "--stage",
                "-z",
                text=False,
                max_bytes=MAX_INDEX_BYTES,
            )
        )
    except RuntimeError as error:
        raise AuditError(str(error)) from error


def _parse_index(document: bytes) -> tuple[IndexEntry, ...]:
    """Parse one exact, ordered, stage-zero regular-file index inventory."""

    if not isinstance(document, bytes) or len(document) > MAX_INDEX_BYTES:
        raise AuditError("Git index inventory exceeds its byte bound")
    if not document or not document.endswith(b"\0"):
        raise AuditError("Git index inventory is empty or unterminated")
    rows: list[IndexEntry] = []
    previous_path: bytes | None = None
    for raw_entry in document[:-1].split(b"\0"):
        if not raw_entry or b"\t" not in raw_entry:
            raise AuditError("Git index inventory contains a malformed row")
        metadata, encoded_path = raw_entry.split(b"\t", 1)
        if (
            len(metadata) != 49
            or not encoded_path
            or len(encoded_path) > MAX_PATH_BYTES
        ):
            raise AuditError("Git index inventory contains an oversized row")
        try:
            mode, object_id, stage = metadata.decode("ascii", "strict").split(" ")
            path = encoded_path.decode("utf-8", "strict")
        except (UnicodeDecodeError, ValueError) as error:
            raise AuditError("Git index inventory contains invalid text") from error
        if mode not in {"100644", "100755"}:
            raise AuditError(f"tracked path is not a regular file: {path!r}")
        if stage != "0":
            raise AuditError(f"tracked path has an unmerged index stage: {path!r}")
        if REVISION.fullmatch(object_id) is None:
            raise AuditError(f"tracked path has an invalid blob identity: {path!r}")
        try:
            canonical_relative_parts(
                path,
                label="tracked path",
                max_path_bytes=MAX_PATH_BYTES,
                max_component_bytes=MAX_COMPONENT_BYTES,
                max_depth=MAX_PATH_DEPTH,
            )
        except ReviewError as error:
            raise AuditError(str(error)) from error
        if previous_path is not None and encoded_path <= previous_path:
            raise AuditError("Git index paths are duplicate or out of order")
        previous_path = encoded_path
        rows.append(IndexEntry(path, mode, object_id))
        if len(rows) > MAX_TRACKED_FILES:
            raise AuditError("Git index exceeds the tracked-file count limit")
    if not rows:
        raise AuditError("Git index inventory is empty")
    by_path = {row.path: row for row in rows}
    for generated_path in GENERATED_PATHS:
        row = by_path.get(generated_path)
        if row is None or row.git_mode != "100644":
            raise AuditError(
                f"generated audit path must be tracked as 100644: {generated_path}"
            )
    return tuple(rows)


def _read_index_blobs(entries: tuple[IndexEntry, ...]) -> dict[str, bytes]:
    """Read all unique index blobs in one bounded Git object transaction."""

    object_ids = tuple(dict.fromkeys(entry.git_blob_id for entry in entries))
    request = b"".join(object_id.encode("ascii") + b"\n" for object_id in object_ids)
    result = run_bounded_host_command(
        [
            "git",
            "--no-replace-objects",
            *SAFE_GIT_CONFIGURATION,
            "-C",
            str(ROOT),
            "cat-file",
            "--batch",
        ],
        context="release-audit Git blob batch",
        stdin_document=request,
        environment=safe_git_environment(),
        max_stdout_bytes=MAX_BATCH_OUTPUT_BYTES,
        max_stderr_bytes=MAX_GIT_DIAGNOSTIC_BYTES,
        timeout_seconds=120,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise AuditError(
            f"release-audit Git blob batch failed with {result.returncode}: {detail}"
        )
    if result.stderr:
        raise AuditError("release-audit Git blob batch produced diagnostic output")
    return _parse_blob_batch(result.stdout, object_ids)


def _parse_blob_batch(
    document: bytes,
    expected_object_ids: tuple[str, ...],
) -> dict[str, bytes]:
    """Parse one exact ordered response from `git cat-file --batch`."""

    if not isinstance(document, bytes) or len(document) > MAX_BATCH_OUTPUT_BYTES:
        raise AuditError("Git blob batch exceeds its byte bound")
    if (
        not isinstance(expected_object_ids, tuple)
        or not expected_object_ids
        or len(expected_object_ids) > MAX_TRACKED_FILES
        or any(
            not isinstance(value, str) or REVISION.fullmatch(value) is None
            for value in expected_object_ids
        )
        or len(set(expected_object_ids)) != len(expected_object_ids)
    ):
        raise AuditError("Git blob batch request is invalid")
    offset = 0
    aggregate = 0
    blobs: dict[str, bytes] = {}
    for expected_object_id in expected_object_ids:
        line_end = document.find(b"\n", offset)
        if line_end < 0:
            raise AuditError("Git blob batch has a missing response header")
        if line_end - offset > 128:
            raise AuditError("Git blob batch has an oversized response header")
        header = document[offset:line_end]
        offset = line_end + 1
        try:
            object_id, object_type, size_text = header.decode("ascii", "strict").split(
                " "
            )
        except (UnicodeDecodeError, ValueError) as error:
            raise AuditError(
                "Git blob batch has a malformed response header"
            ) from error
        if object_id != expected_object_id:
            raise AuditError("Git blob batch response is duplicate or out of order")
        if (
            object_type != "blob"
            or len(size_text) > len(str(MAX_TRACKED_FILE_BYTES))
            or re.fullmatch(r"0|[1-9][0-9]*", size_text) is None
        ):
            raise AuditError("Git blob batch response is not a canonical blob")
        size = int(size_text)
        if size > MAX_TRACKED_FILE_BYTES:
            raise AuditError(f"Git blob {object_id} exceeds the per-file byte limit")
        aggregate += size
        if aggregate > MAX_TRACKED_AGGREGATE_BYTES:
            raise AuditError("Git blob batch exceeds the aggregate byte limit")
        end = offset + size
        if end >= len(document) or document[end : end + 1] != b"\n":
            raise AuditError("Git blob batch has a truncated or unterminated blob")
        data = document[offset:end]
        offset = end + 1
        actual_object_id = _git_blob_id(data)
        if actual_object_id != object_id:
            raise AuditError(
                f"Git blob identity mismatch: expected={object_id} actual={actual_object_id}"
            )
        blobs[object_id] = data
    if offset != len(document):
        raise AuditError("Git blob batch contains trailing data")
    return blobs


def capture_repository_snapshot(*, allow_generated_drift: bool) -> RepositorySnapshot:
    """Capture and cross-check the exact index, objects, and regular files."""

    if type(allow_generated_drift) is not bool:
        raise AuditError("repository snapshot mode is invalid")
    index_bytes = _read_index_bytes()
    entries = _parse_index(index_bytes)
    try:
        blobs = _read_index_blobs(entries)
    except ReviewError as error:
        raise AuditError(str(error)) from error
    files: dict[str, IndexedRegularFile] = {}
    requests: list[RootedFileCaptureRequest] = []
    for entry in entries:
        data = blobs[entry.git_blob_id]
        indexed = IndexedRegularFile(
            path=entry.path,
            git_mode=entry.git_mode,
            git_blob_id=entry.git_blob_id,
            data=data,
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
        )
        files[entry.path] = indexed
        generated_drift = allow_generated_drift and entry.path in GENERATED_PATHS
        requests.append(
            RootedFileCaptureRequest(
                relative=entry.path,
                expected_size=None if generated_drift else indexed.size_bytes,
                label=f"tracked file {entry.path}",
                expected_sha256=None if generated_drift else indexed.sha256,
                expected_git_mode=entry.git_mode,
            )
        )
    try:
        captures = read_rooted_regular_files(
            ROOT,
            requests,
            label="release-audit tracked files",
            max_files=MAX_TRACKED_FILES,
            max_file_bytes=MAX_TRACKED_FILE_BYTES,
            max_aggregate_bytes=MAX_TRACKED_AGGREGATE_BYTES,
            max_path_bytes=MAX_PATH_BYTES,
            max_component_bytes=MAX_COMPONENT_BYTES,
            max_depth=MAX_PATH_DEPTH,
            max_directory_entries=MAX_DIRECTORY_ENTRIES,
        )
    except ReviewError as error:
        raise AuditError(str(error)) from error
    worktree = {capture.relative: capture for capture in captures}
    for path, capture in worktree.items():
        if allow_generated_drift and path in GENERATED_PATHS:
            continue
        indexed = files[path]
        actual_blob_id = _git_blob_id(capture.data)
        if actual_blob_id != indexed.git_blob_id:
            raise AuditError(f"tracked file blob differs from the Git index: {path}")
    if _read_index_bytes() != index_bytes:
        raise AuditError("Git index changed during the repository snapshot")
    return RepositorySnapshot(
        index_bytes,
        MappingProxyType(files),
        MappingProxyType(worktree),
    )


def _path_key(path: Path) -> str:
    """Return one canonical repository-relative key."""

    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError as error:
        raise AuditError(f"path is outside the repository: {path}") from error


def _snapshot_bytes(path: Path, snapshot: RepositorySnapshot) -> bytes:
    """Return exact indexed bytes from one immutable repository snapshot."""

    key = _path_key(path)
    try:
        return snapshot.files[key].data
    except KeyError as error:
        raise AuditError(f"tracked input is missing: {key}") from error


def _snapshot_text(path: Path, snapshot: RepositorySnapshot) -> str:
    """Decode one exact indexed document as UTF-8."""

    try:
        return _snapshot_bytes(path, snapshot).decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise AuditError(
            f"tracked input is not valid UTF-8: {_path_key(path)}"
        ) from error


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuditError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def load_json(path: Path, snapshot: RepositorySnapshot | None = None) -> Any:
    try:
        text = (
            _snapshot_text(path, snapshot)
            if snapshot is not None
            else path.read_text(encoding="utf-8")
        )
        return loads_json(
            text,
            object_pairs_hook=reject_duplicate_pairs,
        )
    except (OSError, UnicodeError, ValueError) as error:
        try:
            label = path.relative_to(ROOT)
        except ValueError:
            label = path
        raise AuditError(f"cannot load {label}: {error}") from error


def canonical_bytes(value: Any) -> bytes:
    try:
        validate_json_number_bounds(value)
        encoded = json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
    except ValueError as error:
        raise AuditError(f"cannot encode canonical JSON: {error}") from error
    return (encoded + "\n").encode("utf-8")


def sha256(path: Path, snapshot: RepositorySnapshot | None = None) -> str:
    if snapshot is not None:
        return hashlib.sha256(_snapshot_bytes(path, snapshot)).hexdigest()
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(*arguments: str) -> str:
    try:
        return str(safe_git(ROOT, *arguments)).strip()
    except RuntimeError as error:
        raise AuditError(str(error)) from error


def require_keys(value: dict[str, Any], keys: set[str], context: str) -> None:
    missing = sorted(keys - value.keys())
    extra = sorted(value.keys() - keys)
    if missing or extra:
        raise AuditError(f"{context}: missing={missing}, unexpected={extra}")


def artifact(
    path: Path,
    purpose: str,
    *,
    exact_bytes: bytes | None = None,
    snapshot: RepositorySnapshot | None = None,
    exact_git_mode: str = "100644",
) -> dict[str, Any]:
    key = _path_key(path)
    if exact_bytes is not None:
        if exact_git_mode not in {"100644", "100755"}:
            raise AuditError(f"generated artifact has an invalid Git mode: {key}")
        data = exact_bytes
        git_mode = exact_git_mode
        git_blob_id = _git_blob_id(data)
    elif snapshot is not None:
        try:
            indexed = snapshot.files[key]
        except KeyError as error:
            raise AuditError(f"required artifact is missing: {key}") from error
        data = indexed.data
        git_mode = indexed.git_mode
        git_blob_id = indexed.git_blob_id
    else:
        if not path.is_file():
            raise AuditError(f"required artifact is missing: {key}")
        data = path.read_bytes()
        rows = {entry.path: entry for entry in _parse_index(_read_index_bytes())}
        try:
            git_mode = rows[key].git_mode
        except KeyError as error:
            raise AuditError(f"required artifact is not tracked: {key}") from error
        git_blob_id = _git_blob_id(data)
    return {
        "path": key,
        "purpose": purpose,
        "git_mode": git_mode,
        "git_blob_id": git_blob_id,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def workflow_action_refs(
    snapshot: RepositorySnapshot | None = None,
) -> set[tuple[str, str]]:
    """Return every external action and immutable revision used by workflows."""

    reference = re.compile(
        r"^\s*uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@"
        r"([0-9a-f]{40})(?:\s+#.*)?\s*$"
    )
    result: set[tuple[str, str]] = set()
    paths = (
        [
            ROOT / path
            for path in snapshot.files
            if PurePosixPath(path).full_match(".github/workflows/*.y*ml")
        ]
        if snapshot is not None
        else sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
    )
    for path in sorted(paths):
        document = (
            _snapshot_text(path, snapshot)
            if snapshot is not None
            else path.read_text(encoding="utf-8")
        )
        for line_number, line in enumerate(document.splitlines(), 1):
            if not line.lstrip().startswith("uses:"):
                continue
            match = reference.fullmatch(line)
            if match is None:
                relative = path.relative_to(ROOT)
                raise AuditError(
                    f"{relative}:{line_number}: action use is not pinned to a full revision"
                )
            result.add((match.group(1), match.group(2)))
    if not result:
        raise AuditError("workflow action inventory is empty")
    return result


def tracked_repository_paths(
    snapshot: RepositorySnapshot | None = None,
) -> set[str]:
    """Return the exact index path set without newline-delimited ambiguity."""

    if snapshot is not None:
        return set(snapshot.files)
    return {entry.path for entry in _parse_index(_read_index_bytes())}


def validate_artifact_coverage(
    artifacts: list[dict[str, Any]],
    snapshot: RepositorySnapshot | None = None,
) -> None:
    """Require one audit artifact for every indexed path except the manifest itself."""

    tracked = tracked_repository_paths(snapshot)
    covered = {entry["path"] for entry in artifacts}
    expected = tracked - AUDIT_SELF_EXCLUSIONS
    missing = sorted(expected - covered)
    extra = sorted(covered - expected)
    if missing or extra:
        raise AuditError(
            "artifact inventory does not exactly cover tracked source: "
            f"missing={missing}, unexpected={extra}, "
            f"self_exclusions={sorted(AUDIT_SELF_EXCLUSIONS)}"
        )


def validate_repository_input_contract(
    repositories: list[dict[str, Any]],
    snapshot: RepositorySnapshot | None = None,
) -> None:
    """Cross-bind every repository input to its owning release contract."""

    by_name = {item["name"]: item for item in repositories}
    if set(by_name) != set(REQUIRED_REPOSITORY_INPUTS):
        raise AuditError(
            "repository input set differs from the release contract: "
            f"missing={sorted(set(REQUIRED_REPOSITORY_INPUTS) - set(by_name))}, "
            f"unexpected={sorted(set(by_name) - set(REQUIRED_REPOSITORY_INPUTS))}"
        )
    for name, (url, commit, role, qualification) in REQUIRED_REPOSITORY_INPUTS.items():
        item = by_name[name]
        if (
            item["url"] != url
            or item["commit"] != commit
            or item["role"] != role
            or item["qualification"] != qualification
        ):
            raise AuditError(f"{name}: repository input identity differs from contract")

    qualifier_database = {
        "url": ADVISORY_DB_URL,
        "commit": ADVISORY_DB_COMMIT,
        "tree": ADVISORY_DB_TREE,
    }
    if set(RUSTSEC_ADVISORY_DATABASE) != {
        "url",
        "commit",
        "tree",
        "inventory_sha256",
        "entries",
        "fetch_policy",
    }:
        raise AuditError("finalizer RustSec database contract has another field set")
    if {
        key: RUSTSEC_ADVISORY_DATABASE[key] for key in qualifier_database
    } != qualifier_database:
        raise AuditError("qualifier and finalizer RustSec database identities differ")
    rustsec = by_name["RustSec advisory database"]
    if {
        "url": rustsec["url"],
        "commit": rustsec["commit"],
    } != {
        "url": qualifier_database["url"],
        "commit": qualifier_database["commit"],
    }:
        raise AuditError("audit and qualification RustSec database identities differ")

    locked_sources = lockfile_git_sources(snapshot)
    expected_packages = set().union(*LOCKED_REPOSITORY_PACKAGES.values())
    actual_packages = {item["name"] for item in locked_sources}
    if actual_packages != expected_packages:
        raise AuditError(
            "locked Git package set differs from repository inputs: "
            f"missing={sorted(expected_packages - actual_packages)}, "
            f"unexpected={sorted(actual_packages - expected_packages)}"
        )
    for repository_name, package_names in LOCKED_REPOSITORY_PACKAGES.items():
        repository = by_name[repository_name]
        expected_source = (
            f"git+{repository['url']}?rev={repository['commit']}#{repository['commit']}"
        )
        for item in locked_sources:
            if item["name"] not in package_names:
                continue
            if (
                item["commit"] != repository["commit"]
                or item["source"] != expected_source
            ):
                raise AuditError(
                    f"{item['name']}: lock source differs from {repository_name}"
                )


def validate_toolchain_input_contract(toolchains: list[dict[str, Any]]) -> None:
    """Cross-bind every tool input to the exact qualification tool set."""

    by_name = {item["name"]: item for item in toolchains}
    if set(by_name) != set(REQUIRED_TOOL_VERSIONS):
        raise AuditError(
            "toolchain input set differs from the release contract: "
            f"missing={sorted(set(REQUIRED_TOOL_VERSIONS) - set(by_name))}, "
            f"unexpected={sorted(set(by_name) - set(REQUIRED_TOOL_VERSIONS))}"
        )
    if set(EXPECTED_QUALIFICATION_TOOLS) != set(AUDIT_TO_QUALIFICATION_TOOL.values()):
        raise AuditError(
            "finalizer qualification tool set differs from the audit mapping"
        )
    for name, version in REQUIRED_TOOL_VERSIONS.items():
        if by_name[name]["version"] != version:
            raise AuditError(f"{name}: tool version differs from release contract")
    for audit_name, qualification_name in AUDIT_TO_QUALIFICATION_TOOL.items():
        if (
            by_name[audit_name]["identity"]
            != EXPECTED_QUALIFICATION_TOOLS[qualification_name]
        ):
            raise AuditError(
                f"{audit_name}: tool identity differs from qualification contract"
            )
    for name, identity in ADDITIONAL_TOOL_IDENTITIES.items():
        if by_name[name]["identity"] != identity:
            raise AuditError(f"{name}: tool identity differs from release contract")

    commands = {spec.name: spec for spec in BASE_COMMANDS}
    current_stable_versions: set[str] = set()
    for name in ("current-stable-clippy", "current-stable-tests"):
        spec = commands.get(name)
        if (
            spec is None
            or len(spec.argv) < 2
            or spec.argv[0] != "cargo"
            or not spec.argv[1].startswith("+")
        ):
            raise AuditError(f"qualification command is malformed: {name}")
        current_stable_versions.add(spec.argv[1].removeprefix("+"))
    if current_stable_versions != {
        by_name["rustc-current-stable"]["version"]
    } or current_stable_versions != {by_name["cargo-current-stable"]["version"]}:
        raise AuditError(
            "audit and qualification current-stable toolchain versions differ"
        )


def _workflow_scalar(workflow: str, name: str) -> str:
    matches = re.findall(
        rf"(?m)^\s*{re.escape(name)}:\s*([^\s#]+)\s*(?:#.*)?$",
        workflow,
    )
    if len(matches) != 1:
        raise AuditError(f"CI workflow must define {name} exactly once")
    return matches[0].strip("'\"")


def validate_ci_qualification_contract(workflow: str | None = None) -> None:
    """Require CI to use the candidate qualification pins and offline policy."""

    if workflow is None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    expected_environment = {
        "RUSTSEC_ADVISORY_DB_URL": ADVISORY_DB_URL,
        "RUSTSEC_ADVISORY_DB_COMMIT": ADVISORY_DB_COMMIT,
        "RUSTSEC_ADVISORY_DB_TREE": ADVISORY_DB_TREE,
        "RUSTSEC_ADVISORY_DB_DIRECTORY": ADVISORY_DB_DENY_DIRECTORY,
    }
    for name, expected in expected_environment.items():
        if _workflow_scalar(workflow, name) != expected:
            raise AuditError(f"CI workflow has another {name} value")

    stable_step = re.search(
        r"(?ms)^      - name: Install current stable Rust\n"
        r"(?P<body>.*?)(?=^      - name:|\Z)",
        workflow,
    )
    if stable_step is None:
        raise AuditError("CI workflow omits the current-stable installation step")
    stable_match = re.search(
        r"(?m)^\s*toolchain:\s*([^\s#]+)",
        stable_step.group("body"),
    )
    if (
        stable_match is None
        or stable_match.group(1).strip("'\"")
        != REQUIRED_TOOL_VERSIONS["rustc-current-stable"]
    ):
        raise AuditError("CI workflow uses another current-stable toolchain")

    deny_commands = re.findall(
        r"(?m)^\s*run:\s*(cargo deny(?:\s+[^\n]+)?)\s*$",
        workflow,
    )
    if len(deny_commands) != 2 or any(
        not command.startswith("cargo deny --offline ") for command in deny_commands
    ):
        raise AuditError(
            "CI dependency-policy commands must both use the pinned offline database"
        )
    supply_chain = re.search(
        r"(?ms)^  supply-chain:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    if supply_chain is None:
        raise AuditError("CI workflow omits the supply-chain job")
    supply_chain_body = supply_chain.group("body")
    materialization_step = re.search(
        r"(?ms)^      - name: Materialize locked dependency graphs\n"
        r"(?P<body>.*?)(?=^      - name:|\Z)",
        supply_chain_body,
    )
    expected_fetches = (
        "cargo fetch --locked",
        "cargo fetch --locked --manifest-path fuzz/Cargo.toml",
    )
    if materialization_step is None:
        raise AuditError(
            "CI supply-chain job must materialize both locked dependency graphs"
        )
    fetches = tuple(
        line.strip()
        for line in materialization_step.group("body").splitlines()
        if line.strip().startswith("cargo fetch")
    )
    if fetches != expected_fetches:
        raise AuditError(
            "CI supply-chain job must materialize both locked dependency graphs"
        )
    first_offline_deny = supply_chain_body.find("cargo deny --offline ")
    if first_offline_deny < 0 or materialization_step.end() >= first_offline_deny:
        raise AuditError(
            "CI supply-chain job must fetch dependencies before offline checks"
        )
    required_provisioning = (
        'database="$database_root/$RUSTSEC_ADVISORY_DB_DIRECTORY"',
        'git -C "$database" fetch --no-tags --depth=1 origin '
        '"$RUSTSEC_ADVISORY_DB_COMMIT"',
        'test "$(git -C "$database" rev-parse \'HEAD^{commit}\')" = '
        '"$RUSTSEC_ADVISORY_DB_COMMIT"',
        'test "$(git -C "$database" rev-parse \'HEAD^{tree}\')" = '
        '"$RUSTSEC_ADVISORY_DB_TREE"',
        'test "$(git -C "$database" remote get-url origin)" = '
        '"$RUSTSEC_ADVISORY_DB_URL"',
        'test -z "$(git -C "$database" status --porcelain=v1 --untracked-files=all)"',
    )
    if any(fragment not in workflow for fragment in required_provisioning):
        raise AuditError(
            "CI workflow does not fully verify the pinned RustSec database"
        )


def validate_inputs(
    inputs: dict[str, Any],
    snapshot: RepositorySnapshot | None = None,
) -> None:
    require_keys(
        inputs,
        {
            "schema",
            "release",
            "audit_date",
            "baseline_repository",
            "repositories",
            "toolchains",
            "github_actions",
            "artifact_sets",
            "external_sources",
            "adaptation_decision",
        },
        "audit inputs",
    )
    if inputs["schema"] != "galadriel.release-audit-inputs.v1":
        raise AuditError("unsupported audit-input schema")
    release = inputs["release"]
    require_keys(
        release,
        {"name", "version", "author", "doi", "zenodo", "publication_channel"},
        "release identity",
    )
    if release["version"] != VERSION or release["author"] != "Sepehr Mahmoudian":
        raise AuditError("release version/author is not the frozen 0.9.0 identity")
    if release["publication_channel"] != PUBLICATION_CHANNEL:
        raise AuditError("release publication channel differs from the 0.9.0 contract")
    if release["doi"] is not None or release["zenodo"] is not None:
        raise AuditError("0.9.0 must not claim a project DOI or Zenodo record")
    baseline = inputs["baseline_repository"]
    require_keys(baseline, {"url", "commit", "tree"}, "baseline repository")
    if not REVISION.fullmatch(baseline["commit"]):
        raise AuditError("baseline commit must be a full lowercase Git object identity")
    if not REVISION.fullmatch(baseline["tree"]):
        raise AuditError("baseline tree must be a full lowercase Git object identity")
    if git("rev-parse", f"{baseline['commit']}^{{commit}}") != baseline["commit"]:
        raise AuditError("baseline commit is unavailable or resolves differently")
    if git("rev-parse", f"{baseline['commit']}^{{tree}}") != baseline["tree"]:
        raise AuditError("baseline tree identity does not match baseline commit")
    seen_repositories: set[str] = set()
    for repository in inputs["repositories"]:
        require_keys(
            repository,
            {"name", "url", "commit", "role", "qualification"},
            "repository",
        )
        if repository["name"] in seen_repositories:
            raise AuditError(f"duplicate repository name: {repository['name']}")
        seen_repositories.add(repository["name"])
        if not REVISION.fullmatch(repository["commit"]):
            raise AuditError(f"{repository['name']}: commit is not a full revision")
        if repository["qualification"] not in {
            "PINNED_COMPONENT",
            "RECIPROCAL_FIXTURE",
            "NOT_CLAIMED",
        }:
            raise AuditError(f"{repository['name']}: invalid qualification")
    validate_repository_input_contract(inputs["repositories"], snapshot)
    seen_tools: set[str] = set()
    for tool in inputs["toolchains"]:
        require_keys(tool, {"name", "version", "identity", "role"}, "toolchain")
        if not all(isinstance(tool[key], str) and tool[key] for key in tool):
            raise AuditError("toolchain entries must contain non-empty strings")
        if tool["name"] in seen_tools:
            raise AuditError(f"duplicate toolchain name: {tool['name']}")
        seen_tools.add(tool["name"])
    validate_toolchain_input_contract(inputs["toolchains"])
    recorded_actions: set[tuple[str, str]] = set()
    for action in inputs["github_actions"]:
        require_keys(
            action,
            {
                "action",
                "repository",
                "commit",
                "source_ref",
                "source_ref_kind",
                "version",
                "role",
            },
            "GitHub Action",
        )
        if not all(isinstance(action[key], str) and action[key] for key in action):
            raise AuditError("GitHub Action entries must contain non-empty strings")
        action_id = action["action"]
        revision = action["commit"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", action_id):
            raise AuditError(f"invalid GitHub Action identity: {action_id!r}")
        if not REVISION.fullmatch(revision):
            raise AuditError(f"{action_id}: action commit is not a full revision")
        if action["repository"] != f"https://github.com/{action_id}":
            raise AuditError(
                f"{action_id}: repository URL does not match action identity"
            )
        if action["source_ref_kind"] not in {
            "lightweight_tag",
            "annotated_tag_target",
            "branch_snapshot",
        }:
            raise AuditError(f"{action_id}: unsupported source-ref kind")
        key = (action_id, revision)
        if key in recorded_actions:
            raise AuditError(
                f"duplicate GitHub Action revision: {action_id}@{revision}"
            )
        recorded_actions.add(key)
    used_actions = workflow_action_refs(snapshot)
    if recorded_actions != used_actions:
        raise AuditError(
            "GitHub Action inventory differs from workflows: "
            f"missing={sorted(used_actions - recorded_actions)}, "
            f"unexpected={sorted(recorded_actions - used_actions)}"
        )
    validate_ci_qualification_contract(
        _snapshot_text(CI_WORKFLOW, snapshot) if snapshot is not None else None
    )
    if not inputs["adaptation_decision"].startswith("release/0.9.0/"):
        raise AuditError(
            "adaptation decision must be retained inside the release record"
        )


def collect_artifacts(
    inputs: dict[str, Any],
    *,
    exact_bytes: dict[Path, bytes] | None = None,
    snapshot: RepositorySnapshot | None = None,
) -> list[dict[str, Any]]:
    exact_bytes = exact_bytes or {}
    indexed_paths = tracked_repository_paths(snapshot)
    collected: dict[str, dict[str, Any]] = {}
    for artifact_set in inputs["artifact_sets"]:
        require_keys(artifact_set, {"purpose", "patterns"}, "artifact set")
        if (
            not isinstance(artifact_set["purpose"], str)
            or not artifact_set["purpose"].strip()
            or not isinstance(artifact_set["patterns"], list)
            or not artifact_set["patterns"]
        ):
            raise AuditError("artifact set purpose and patterns must be non-empty")
        matched: list[Path] = []
        for pattern in artifact_set["patterns"]:
            if (
                not isinstance(pattern, str)
                or not pattern
                or Path(pattern).is_absolute()
                or ".." in Path(pattern).parts
            ):
                raise AuditError(f"invalid artifact pattern: {pattern!r}")
            if snapshot is not None:
                matched.extend(
                    ROOT / path
                    for path in indexed_paths
                    if PurePosixPath(path).full_match(pattern)
                )
            else:
                matched.extend(
                    path
                    for path in ROOT.glob(pattern)
                    if path.is_file()
                    and path.relative_to(ROOT).as_posix() in indexed_paths
                )
                matched.extend(
                    path
                    for path in exact_bytes
                    if path.relative_to(ROOT).match(pattern)
                    and path.relative_to(ROOT).as_posix() in indexed_paths
                )
        if not matched:
            raise AuditError(f"artifact pattern set matched no files: {artifact_set}")
        for path in sorted(set(matched)):
            key = path.relative_to(ROOT).as_posix()
            entry = artifact(
                path,
                artifact_set["purpose"],
                exact_bytes=exact_bytes.get(path),
                snapshot=snapshot,
            )
            if key in collected and collected[key] != entry:
                raise AuditError(f"artifact has conflicting purposes: {key}")
            collected[key] = entry
    artifacts = [collected[key] for key in sorted(collected)]
    validate_artifact_coverage(artifacts, snapshot)
    return artifacts


def collect_external_references(
    inputs: dict[str, Any],
    snapshot: RepositorySnapshot | None = None,
) -> list[dict[str, Any]]:
    references: dict[tuple[str, str], dict[str, Any]] = {}
    source_paths = (
        sorted(
            {
                ROOT / path
                for pattern in inputs["external_sources"]["scan_patterns"]
                for path in snapshot.files
                if PurePosixPath(path).full_match(pattern)
            }
        )
        if snapshot is not None
        else sorted(
            {
                path
                for pattern in inputs["external_sources"]["scan_patterns"]
                for path in ROOT.glob(pattern)
                if path.is_file()
            }
        )
    )
    for path in source_paths:
        relative = path.relative_to(ROOT).as_posix()
        document = (
            _snapshot_text(path, snapshot)
            if snapshot is not None
            else path.read_text(encoding="utf-8")
        )
        for line_number, line in enumerate(document.splitlines(), 1):
            for match in URL.finditer(line):
                url = match.group(0).rstrip(".,;:")
                key = (relative, f"{line_number}:{url}")
                references[key] = {
                    "kind": "paper"
                    if DOI_URL.match(url) or relative == "docs/RELATED-WORK.md"
                    else "external_reference",
                    "line": line_number,
                    "path": relative,
                    "url": url,
                }
    for source in inputs["external_sources"]["declared"]:
        require_keys(source, {"kind", "title", "url", "purpose"}, "external source")
        key = ("<declared>", source["url"])
        references[key] = dict(source)
    return [references[key] for key in sorted(references)]


def lockfile_git_sources(
    snapshot: RepositorySnapshot | None = None,
) -> list[dict[str, str]]:
    lock_path = ROOT / "Cargo.lock"
    lock = tomllib.loads(
        _snapshot_text(lock_path, snapshot)
        if snapshot is not None
        else lock_path.read_text(encoding="utf-8")
    )
    sources: dict[tuple[str, str, str], dict[str, str]] = {}
    for package in lock.get("package", []):
        source = package.get("source", "")
        if not source.startswith("git+"):
            continue
        match = re.search(r"#([0-9a-f]{40})\Z", source)
        if match is None:
            raise AuditError(
                f"Git dependency lacks an immutable lock revision: {source}"
            )
        item = {
            "name": package["name"],
            "version": package["version"],
            "source": source,
            "commit": match.group(1),
        }
        sources[(item["name"], item["version"], item["source"])] = item
    return [sources[key] for key in sorted(sources)]


def validate_project_metadata(
    inputs: dict[str, Any],
    snapshot: RepositorySnapshot | None = None,
) -> dict[str, Any]:
    def text(path: Path) -> str:
        return (
            _snapshot_text(path, snapshot)
            if snapshot is not None
            else path.read_text(encoding="utf-8")
        )

    cargo = tomllib.loads(text(ROOT / "Cargo.toml"))
    package = cargo["workspace"]["package"]
    if package["version"] != VERSION:
        raise AuditError(f"Cargo workspace version must be {VERSION}")
    if package["authors"] != ["Sepehr Mahmoudian"]:
        raise AuditError("Cargo workspace author must be exactly Sepehr Mahmoudian")
    citation = text(ROOT / "CITATION.cff")
    if not re.search(r"(?m)^version: ['\"]?0\.9\.0['\"]?$", citation):
        raise AuditError("CITATION.cff does not identify version 0.9.0")
    if (
        re.search(r"(?mi)^(doi|identifiers):", citation)
        or "zenodo.org" in citation.lower()
    ):
        raise AuditError("CITATION.cff must omit project DOI/Zenodo metadata for 0.9.0")
    if (
        "family-names: Mahmoudian" not in citation
        or "given-names: Sepehr" not in citation
    ):
        raise AuditError("CITATION.cff author identity is incomplete")
    release_date_records = {
        "CITATION.cff": (
            citation,
            r"(?m)^date-released: (\d{4}-\d{2}-\d{2})$",
        ),
        "CHANGELOG.md": (
            text(ROOT / "CHANGELOG.md"),
            r"(?m)^## \[0\.9\.0\] - (\d{4}-\d{2}-\d{2})$",
        ),
        "release/0.9.0/RELEASE-NOTES.md": (
            text(RELEASE / "RELEASE-NOTES.md"),
            r"(?m)^Release date: (\d{4}-\d{2}-\d{2})$",
        ),
        "release/0.9.0/RELEASE-RUNBOOK.md": (
            text(RELEASE / "RELEASE-RUNBOOK.md"),
            r"Stop if the UTC date is later than `(\d{4}-\d{2}-\d{2})`\.",
        ),
    }
    for path, (document, pattern) in release_date_records.items():
        if re.findall(pattern, document) != [RELEASE_DATE]:
            raise AuditError(f"{path} does not identify release date {RELEASE_DATE}")
    for member in cargo["workspace"]["members"]:
        manifest = tomllib.loads(text(ROOT / member / "Cargo.toml"))
        if manifest["package"].get("publish") is not False:
            raise AuditError(
                f"{member} must remain publish=false for the GitHub-only 0.9.0"
            )
    fuzz = tomllib.loads(text(ROOT / "fuzz/Cargo.toml"))
    for dependency in ("galadriel-core", "galadriel-ncp"):
        if fuzz["dependencies"][dependency].get("version") != VERSION:
            raise AuditError(
                f"fuzz dependency {dependency} must track release {VERSION}"
            )
    return {
        "authors": package["authors"],
        "license": package["license"],
        "project_doi": inputs["release"]["doi"],
        "publication_channel": inputs["release"]["publication_channel"],
        "release_date": RELEASE_DATE,
        "version": package["version"],
        "zenodo_record": inputs["release"]["zenodo"],
    }


def validate_claims(
    snapshot: RepositorySnapshot | None = None,
) -> list[dict[str, Any]]:
    document = load_json(CLAIMS) if snapshot is None else load_json(CLAIMS, snapshot)
    require_keys(
        document, {"schema", "release", "tier_definitions", "claims"}, "claims"
    )
    if (
        document["schema"] != "galadriel.claims-matrix.v1"
        or document["release"] != VERSION
    ):
        raise AuditError("claims matrix has the wrong schema or release")
    if set(document["tier_definitions"]) != VALID_TIERS:
        raise AuditError("claims matrix must define exactly the four frozen tiers")
    seen: set[str] = set()
    deployment_claims = 0
    for claim in document["claims"]:
        require_keys(
            claim,
            {"id", "claim", "tier", "scope", "evidence", "limitations"},
            "claim",
        )
        if claim["id"] in seen or not re.fullmatch(r"CLM-\d{3}", claim["id"]):
            raise AuditError(f"invalid or duplicate claim ID: {claim['id']}")
        seen.add(claim["id"])
        if claim["tier"] not in VALID_TIERS:
            raise AuditError(f"{claim['id']}: invalid tier")
        if not claim["claim"] or not claim["scope"] or not claim["limitations"]:
            raise AuditError(f"{claim['id']}: claim fields must be non-empty")
        if claim["tier"] == "DEPLOYMENT_QUALIFIED":
            deployment_claims += 1
            if not claim["evidence"]:
                raise AuditError(f"{claim['id']}: deployment claim lacks evidence")
        if claim["tier"] == "NOT_CLAIMED" and claim["evidence"]:
            raise AuditError(
                f"{claim['id']}: NOT_CLAIMED must not cite affirmative evidence"
            )
        for path_string in claim["evidence"]:
            if not isinstance(path_string, str):
                raise AuditError(f"{claim['id']}: claim evidence path is not text")
            exists = (
                path_string in snapshot.files
                if snapshot is not None
                else (ROOT / path_string).exists()
            )
            if not exists:
                raise AuditError(
                    f"{claim['id']}: claim evidence is missing: {path_string}"
                )
    if deployment_claims:
        raise AuditError("0.9.0 has no deployment-qualified behavior")
    return document["claims"]


def validate_normative_documents(
    snapshot: RepositorySnapshot | None = None,
) -> list[dict[str, Any]]:
    requirements = {
        "release/0.9.0/README.md": ("GLD-090-AUD-001", "GLD-090-LED-001"),
        "release/0.9.0/VERSION-ADAPTATION.md": ("GLD-090-REL-001", "GLD-090-REL-005"),
        "docs/CLAIMS.md": ("GLD-090-CLM-001", "GLD-090-CLM-004"),
        "docs/STATISTICAL-CONTRACT.md": ("GLD-090-STAT-001", "GLD-090-STAT-003"),
        "docs/THREAT-MODEL.md": ("GLD-090-THR-001", "GLD-090-THR-003"),
        "docs/ADVISORY-BOUNDARY.md": ("GLD-090-AUTH-001", "GLD-090-AUTH-002"),
        "docs/API-SURFACE.md": ("GLD-090-API-001", "GLD-090-API-004"),
        "SUPPORT.md": ("GLD-090-META-001", "GLD-090-META-002"),
        "docs/DEPENDENCY-POLICY.md": ("GLD-090-PIN-001", "GLD-090-PIN-004"),
        "RELEASE-POLICY.md": ("GLD-090-CTL-001", "GLD-090-CTL-005"),
        "release/0.9.0/RELEASE-RUNBOOK.md": ("GLD-090-PUB-001", "GLD-090-PUB-003"),
    }
    artifacts = []
    for path_string, identifiers in requirements.items():
        path = ROOT / path_string
        if snapshot is not None and path_string not in snapshot.files:
            raise AuditError(f"normative document is missing: {path_string}")
        if snapshot is None and not path.is_file():
            raise AuditError(f"normative document is missing: {path_string}")
        content = (
            _snapshot_text(path, snapshot)
            if snapshot is not None
            else path.read_text(encoding="utf-8")
        )
        for identifier in identifiers:
            if identifier not in content:
                raise AuditError(f"{path_string}: missing normative ID {identifier}")
        if "**SHALL**" not in content and "**SHALL NOT**" not in content:
            raise AuditError(f"{path_string}: lacks explicit normative SHALL language")
        artifacts.append(
            artifact(
                path,
                "normative 0.9.0 release contract",
                snapshot=snapshot,
            )
        )

    statistical_path = ROOT / "docs/STATISTICAL-CONTRACT.md"
    statistical = (
        _snapshot_text(statistical_path, snapshot)
        if snapshot is not None
        else statistical_path.read_text(encoding="utf-8")
    )
    for field in (
        "sum_nis",
        "mean_nis",
        "p_right",
        "cusum_high_alarm",
        "cusum_low_alarm",
        "last_timestamp_ms",
        "corroboration",
        "redundancy",
        "synergy",
        "estimate_nats",
        "FusedVerdict",
        "PidVerdict",
    ):
        if field not in statistical:
            raise AuditError(f"statistical contract omits report field/verdict {field}")
    threat_model_path = ROOT / "docs/THREAT-MODEL.md"
    threat_model = (
        _snapshot_text(threat_model_path, snapshot)
        if snapshot is not None
        else threat_model_path.read_text(encoding="utf-8")
    ).lower()
    for threat in (
        "spoof",
        "correlated or coordinated compromise",
        "missingness",
        "timestamp",
        "route/session/producer confusion",
        "denial of service",
    ):
        if threat not in threat_model:
            raise AuditError(f"threat model omits required class: {threat}")
    public_api_path = RELEASE / "api" / "galadriel-core.0.9.0.txt"
    public_api = (
        _snapshot_text(public_api_path, snapshot)
        if snapshot is not None
        else public_api_path.read_text(encoding="utf-8")
    )
    if "pub mod galadriel_core::chi2" in public_api:
        raise AuditError(
            "accepted API snapshot still exposes the accidental chi2 module"
        )
    return artifacts


def parse_exact_date(value: Any, label: str) -> date:
    """Parse one exact calendar date."""

    if not isinstance(value, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is None:
        raise AuditError(f"{label} must use YYYY-MM-DD precision")
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise AuditError(f"{label} is not a valid calendar date") from error


def validate_ecosystem_cut(snapshot: RepositorySnapshot | None = None) -> None:
    """Require the cut date to contain every same-precision observation."""

    document = (
        load_json(ECOSYSTEM_CUT)
        if snapshot is None
        else load_json(ECOSYSTEM_CUT, snapshot)
    )
    require_keys(
        document,
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
        "ecosystem cut",
    )
    if document["schema"] != "galadriel.ecosystem-inspection-cut.v1":
        raise AuditError("ecosystem cut has the wrong schema")
    if document["release"] != VERSION or document["author"] != "Sepehr Mahmoudian":
        raise AuditError("ecosystem cut has the wrong release or author")
    if document["timestamp_precision"] != "date":
        raise AuditError("ecosystem cut must use date precision")
    inspected_at = parse_exact_date(
        document["inspected_at"],
        "ecosystem cut inspected_at",
    )
    observations = document["observations"]
    if not isinstance(observations, list) or not observations:
        raise AuditError("ecosystem cut must contain observations")
    seen: set[str] = set()
    for observation in observations:
        if not isinstance(observation, dict):
            raise AuditError("ecosystem observation must be an object")
        observation_id = observation.get("id")
        if (
            not isinstance(observation_id, str)
            or re.fullmatch(r"ECO-\d{3}", observation_id) is None
            or observation_id in seen
        ):
            raise AuditError(
                f"invalid or duplicate ecosystem observation ID: {observation_id!r}"
            )
        seen.add(observation_id)
        if observation.get("timestamp_precision") != document["timestamp_precision"]:
            raise AuditError(
                f"{observation_id}: timestamp precision differs from the ecosystem cut"
            )
        observed_at = parse_exact_date(
            observation.get("observed_at"),
            f"{observation_id} observed_at",
        )
        if observed_at > inspected_at:
            raise AuditError(
                f"ecosystem cut inspected_at predates observation {observation_id}"
            )


def validate_threat_register(
    snapshot: RepositorySnapshot | None = None,
) -> dict[str, Any]:
    document = (
        load_json(THREAT_REGISTER)
        if snapshot is None
        else load_json(THREAT_REGISTER, snapshot)
    )
    require_keys(
        document,
        {
            "schema",
            "release",
            "status",
            "source",
            "disposition_values",
            "threats",
        },
        "threat register",
    )
    if document["schema"] != "galadriel.threat-register.v1":
        raise AuditError("unsupported threat-register schema")
    if document["release"] != VERSION:
        raise AuditError("threat register has the wrong release")
    if document["status"] not in VALID_THREAT_REGISTER_STATUSES:
        raise AuditError("threat register has an unsupported lifecycle status")
    if set(document["disposition_values"]) != VALID_THREAT_DISPOSITIONS:
        raise AuditError("threat register has the wrong disposition vocabulary")
    source = document["source"]
    require_keys(source, {"handoff", "task_ledger_sha256"}, "threat-register source")
    task_source = (
        load_json(TASKS) if snapshot is None else load_json(TASKS, snapshot)
    )["source"]
    if source["task_ledger_sha256"] != task_source["task_ledger_sha256"]:
        raise AuditError("threat register is bound to the wrong task ledger")

    required_fields = {
        "threat_id",
        "asset_or_claim",
        "actor",
        "preconditions",
        "sequence",
        "trust_boundary",
        "observable_symptoms",
        "worst_consequence",
        "preventive_controls",
        "detective_controls",
        "recovery",
        "tests",
        "evidence",
        "residual_risk",
        "claim_impact",
        "owner",
        "disposition",
    }
    threats = document["threats"]
    if not isinstance(threats, list) or len(threats) < 10:
        raise AuditError("threat register must retain at least ten repository threats")
    seen: set[str] = set()
    for threat in threats:
        if not isinstance(threat, dict):
            raise AuditError("threat-register entries must be objects")
        require_keys(threat, required_fields, "threat-register entry")
        threat_id = threat["threat_id"]
        if not isinstance(threat_id, str) or not re.fullmatch(
            r"GLD-THR-\d{3}", threat_id
        ):
            raise AuditError(f"invalid threat ID: {threat_id!r}")
        if threat_id in seen:
            raise AuditError(f"duplicate threat ID: {threat_id}")
        seen.add(threat_id)
        if threat["owner"] != "Sepehr Mahmoudian":
            raise AuditError(f"{threat_id}: threat owner must be Sepehr Mahmoudian")
        if threat["disposition"] not in VALID_THREAT_DISPOSITIONS:
            raise AuditError(f"{threat_id}: invalid threat disposition")
        for field in required_fields - {"tests", "evidence"}:
            if not isinstance(threat[field], str) or not threat[field].strip():
                raise AuditError(f"{threat_id}: {field} must be non-empty text")
        for field in ("tests", "evidence"):
            values = threat[field]
            if not isinstance(values, list) or not values:
                raise AuditError(f"{threat_id}: {field} must be a non-empty list")
            for path_string in values:
                exists = (
                    path_string in snapshot.files
                    if snapshot is not None and isinstance(path_string, str)
                    else isinstance(path_string, str) and (ROOT / path_string).exists()
                )
                if not isinstance(path_string, str) or not exists:
                    raise AuditError(
                        f"{threat_id}: missing {field} path {path_string!r}"
                    )
    return artifact(
        THREAT_REGISTER,
        "repository threat, misuse, and failure register",
        snapshot=snapshot,
    )


def validate_tasks(
    snapshot: RepositorySnapshot | None = None,
) -> list[dict[str, Any]]:
    document = load_json(TASKS) if snapshot is None else load_json(TASKS, snapshot)
    require_keys(document, {"schema", "source", "tasks"}, "tasks")
    if document["schema"] != "galadriel.current-handoff-tasks.v2":
        raise AuditError("task inventory has the wrong schema")
    source = document["source"]
    require_keys(
        source,
        {
            "master_package",
            "child_package",
            "child_package_sha256",
            "task_ledger_sha256",
            "prepared",
            "frozen_commit",
            "original_target",
            "adapted_target",
        },
        "task source",
    )
    handoff = (
        load_json(HANDOFF_SOURCE)
        if snapshot is None
        else load_json(HANDOFF_SOURCE, snapshot)
    )
    if source["child_package_sha256"] != handoff["child_archive_sha256"]:
        raise AuditError(
            "task inventory child-package digest differs from handoff source"
        )
    if source["task_ledger_sha256"] != handoff["task_ledger_sha256"]:
        raise AuditError("task inventory ledger digest differs from handoff source")
    if source["frozen_commit"] != handoff["frozen_commit"]:
        raise AuditError("task inventory frozen commit differs from handoff source")
    if source["original_target"] != "1.0.0" or source["adapted_target"] != VERSION:
        raise AuditError("task inventory does not preserve the 1.0-to-0.9 adaptation")
    tasks = document["tasks"]
    if len(tasks) != 116:
        raise AuditError(f"task inventory must contain 116 tasks, got {len(tasks)}")
    for index, task in enumerate(tasks):
        require_keys(
            task,
            {
                "id",
                "phase",
                "title",
                "source_scope",
                "focus",
                "priority",
                "dependencies",
                "execution_wave",
                "subagent_lane",
                "lead_review_required",
            },
            "task",
        )
        expected = f"T{index:03d}"
        if task["id"] != expected or not TASK_ID.fullmatch(task["id"]):
            raise AuditError(f"task sequence is not contiguous at {expected}")
        expected_dependencies = [] if index == 0 else [f"T{index - 1:03d}"]
        if task["dependencies"] != expected_dependencies:
            raise AuditError(f"{expected}: dependency chain changed")
        if task["priority"] != "P0_RELEASE_BLOCKER":
            raise AuditError(f"{expected}: priority changed")
        if task["execution_wave"] != index // 12 and not (
            index >= 108 and task["execution_wave"] == 9
        ):
            raise AuditError(f"{expected}: execution wave changed")
        if task["subagent_lane"] not in {1, 2, 3}:
            raise AuditError(f"{expected}: invalid subagent lane")
        if task["lead_review_required"] is not True:
            raise AuditError(f"{expected}: lead review is not mandatory")
    return tasks


def validate_ledger(
    tasks: list[dict[str, Any]],
    claims: list[dict[str, Any]],
    snapshot: RepositorySnapshot | None = None,
) -> dict[str, Any]:
    claims_by_id = {claim["id"]: claim for claim in claims}
    try:
        if snapshot is None:
            plan = closure_plan.validate_plan(tasks, claims_by_id)
            source_state = closure_plan.validate_source_dispositions()
        else:
            plan = closure_plan.validate_plan(
                tasks,
                claims_by_id,
                document=load_json(CLOSURE_PLAN, snapshot),
            )
            source_state = closure_plan.validate_source_dispositions(
                document=load_json(DISPOSITIONS, snapshot)
            )
    except closure_plan.DispositionError as error:
        raise AuditError(f"invalid source closure plan: {error}") from error

    ledger_tasks = []
    for task, planned in zip(tasks, plan["tasks"], strict=True):
        status = "NOT_CLAIMED" if planned["status"] == "NOT_CLAIMED" else "OPEN"
        ledger_tasks.append(
            {
                **task,
                "status": status,
                "source_plan_status": planned["status"],
                "source_projection_sha256": planned["source_projection_sha256"],
                "source_requirements": {
                    field: planned["source_projection"][field]
                    for field in (
                        "preconditions",
                        "procedure",
                        "mandatory_counterfactuals",
                        "required_evidence",
                        "completion_rule",
                    )
                },
                "accepted_cases": planned["accepted_cases"],
                "rejected_cases": planned["rejected_cases"],
                "required_evidence_types": planned["evidence_types"],
                "failed_attempt_record_requirements": planned[
                    "failure_record_requirements"
                ],
                "requirement_exclusions": planned["requirement_exclusions"],
                "lens_exclusions": planned["lens_exclusions"],
                "claim_removal_links": planned["claim_removal_links"],
                "residual_risks": planned["residual_risks"],
                "review_questions": {
                    lens: planned["source_projection"]["twenty_lens_review"][lens][
                        "question"
                    ]
                    for lens in LENSES
                },
                "post_commit_evidence": [],
                "post_commit_tests": [],
                "post_commit_findings": {},
            }
        )
    counts = {
        status: sum(item["status"] == status for item in ledger_tasks)
        for status in VALID_STATUSES
    }
    if counts != {"OPEN": 107, "COMPLETE": 0, "NOT_CLAIMED": 9}:
        raise AuditError(f"source ledger has an unexpected closure count: {counts}")
    return {
        "schema": "galadriel.requirements-ledger.v2",
        "release": VERSION,
        "closure_boundary": plan["closure_boundary"],
        "source_task_plan_sha256": sha256(CLOSURE_PLAN, snapshot),
        "source_dispositions_state": source_state["state"],
        "source_task_count": len(tasks),
        "status_counts": counts,
        "tasks": ledger_tasks,
    }


def build_outputs(
    snapshot: RepositorySnapshot | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    snapshot = (
        capture_repository_snapshot(allow_generated_drift=True)
        if snapshot is None
        else snapshot
    )
    inputs = load_json(INPUTS, snapshot)
    validate_inputs(inputs, snapshot)
    validate_ecosystem_cut(snapshot)
    claims = validate_claims(snapshot)
    tasks = validate_tasks(snapshot)
    ledger = validate_ledger(tasks, claims, snapshot)
    ledger_bytes = canonical_bytes(ledger)
    metadata = validate_project_metadata(inputs, snapshot)
    audit = {
        "schema": "galadriel.release-audit-manifest.v2",
        "audit_date": inputs["audit_date"],
        "release": metadata,
        "baseline_repository": inputs["baseline_repository"],
        "repositories": inputs["repositories"],
        "toolchains": inputs["toolchains"],
        "github_actions": inputs["github_actions"],
        "git_dependencies": lockfile_git_sources(snapshot),
        "artifacts": collect_artifacts(
            inputs,
            exact_bytes={LEDGER_OUTPUT: ledger_bytes},
            snapshot=snapshot,
        ),
        "artifact_self_exclusions": sorted(AUDIT_SELF_EXCLUSIONS),
        "normative_documents": validate_normative_documents(snapshot),
        "threat_register": validate_threat_register(snapshot),
        "external_sources": collect_external_references(inputs, snapshot),
        "claims": claims,
        "requirements": ledger["status_counts"],
        "source_closure_plan": artifact(
            CLOSURE_PLAN,
            "post-commit task requirements, evidence rules, exclusions, and review questions",
            snapshot=snapshot,
        ),
        "source_task_dispositions": artifact(
            DISPOSITIONS,
            "explicitly empty source state awaiting exact-candidate review",
            snapshot=snapshot,
        ),
        "adaptation_decision": inputs["adaptation_decision"],
    }
    return audit, ledger


def _require_snapshot_unchanged(
    before: RepositorySnapshot,
    after: RepositorySnapshot,
    *,
    allow_generated_changes: bool,
) -> None:
    """Require one repository capture to retain its declared transaction state."""

    if before.index_bytes != after.index_bytes or before.files != after.files:
        raise AuditError("Git index or blob inventory changed during release audit")
    for path, initial in before.worktree.items():
        if allow_generated_changes and path in GENERATED_PATHS:
            continue
        if after.worktree.get(path) != initial:
            raise AuditError(f"tracked file changed during release audit: {path}")


def _write_generated(
    path: Path,
    data: bytes,
    snapshot: RepositorySnapshot,
) -> None:
    """Write one generated path through its captured regular-file identity."""

    key = _path_key(path)
    try:
        expected = snapshot.worktree[key]
    except KeyError as error:
        raise AuditError(
            f"generated path is absent from the worktree: {key}"
        ) from error
    try:
        write_rooted_regular_file(
            ROOT,
            key,
            data,
            expected=expected,
            expected_git_mode="100644",
            label=f"generated artifact {key}",
            max_bytes=MAX_TRACKED_FILE_BYTES,
            max_path_bytes=MAX_PATH_BYTES,
            max_component_bytes=MAX_COMPONENT_BYTES,
            max_depth=MAX_PATH_DEPTH,
            max_directory_entries=MAX_DIRECTORY_ENTRIES,
        )
    except ReviewError as error:
        raise AuditError(str(error)) from error


def generate() -> None:
    before = capture_repository_snapshot(allow_generated_drift=True)
    audit, ledger = build_outputs(before)
    expected = {
        LEDGER_OUTPUT: canonical_bytes(ledger),
        AUDIT_OUTPUT: canonical_bytes(audit),
    }
    _write_generated(LEDGER_OUTPUT, expected[LEDGER_OUTPUT], before)
    _write_generated(AUDIT_OUTPUT, expected[AUDIT_OUTPUT], before)
    after = capture_repository_snapshot(allow_generated_drift=True)
    _require_snapshot_unchanged(before, after, allow_generated_changes=True)
    for path, data in expected.items():
        capture = after.worktree[_path_key(path)]
        if capture.data != data or _git_blob_id(capture.data) != _git_blob_id(data):
            raise AuditError(
                f"generated artifact verification failed: {_path_key(path)}"
            )
    print(f"generated {LEDGER_OUTPUT.relative_to(ROOT)}")
    print(f"generated {AUDIT_OUTPUT.relative_to(ROOT)}")


def verify() -> None:
    before = capture_repository_snapshot(allow_generated_drift=False)
    audit, ledger = build_outputs(before)
    expected = {
        AUDIT_OUTPUT: canonical_bytes(audit),
        LEDGER_OUTPUT: canonical_bytes(ledger),
    }
    for path, data in expected.items():
        key = _path_key(path)
        if before.worktree[key].data != data:
            raise AuditError(
                f"generated artifact is stale: {key}; run release-audit generate"
            )
    after = capture_repository_snapshot(allow_generated_drift=False)
    _require_snapshot_unchanged(before, after, allow_generated_changes=False)
    print("release audit verified")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("generate", "verify"))
    arguments = parser.parse_args()
    try:
        generate() if arguments.command == "generate" else verify()
    except AuditError as error:
        print(f"release audit failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
