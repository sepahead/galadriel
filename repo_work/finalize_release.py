#!/usr/bin/env python3
"""Atomically finalize exact-candidate closure from signed review inputs.

The candidate remains unchanged.  This tool verifies its commit signature, the
signed qualification tier, a one-to-one completed review ledger, the signed
final review and release decision, and signed task dispositions.  It copies the
authenticated decision bytes, emits signed convergence and closure manifests,
flushes a same-parent staging tree, and publishes that tree in one rename.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

from common import ReviewError, canonical_json, git, load_json, loads_json
from freeze_audit_inputs import read_bounded_regular_file
from local_convergence import (
    CONVERGENCE_ARTIFACT_PATHS,
    SCHEMA_PATH as LOCAL_CONVERGENCE_SCHEMA,
    SIGNATURE_NAMESPACE as LOCAL_CONVERGENCE_NAMESPACE,
    artifact_path_parts,
    artifact_records as local_convergence_artifacts,
    build_document as build_local_convergence,
    validate_document as validate_local_convergence,
    validate_schema as validate_local_convergence_schema,
)
from qualify_candidate import BASE_COMMANDS, DEEP_COMMANDS, CommandSpec
from release_assurance import (
    AUTHOR,
    VERSION,
    assert_tracked_allowed_signer,
    derive_external_allowed_signers,
    digest_file,
    sign_file,
    validate_completed_file_ledger,
    validate_decision_input,
    validate_final_twenty_lens_review,
    validate_mutation_evidence,
    validate_reviewed_task_dispositions,
    verify_artifact_manifest,
    verify_candidate_commit,
    verify_signature,
)


QUALIFICATION_MANIFEST = "QUALIFICATION-MANIFEST.json"
QUALIFICATION_SIGNATURE = f"{QUALIFICATION_MANIFEST}.sig"
CLOSURE_MANIFEST = "CLOSURE-MANIFEST.json"
CLOSURE_SIGNATURE = f"{CLOSURE_MANIFEST}.sig"
RELEASE_DECISION = "RELEASE-DECISION.json"
RELEASE_DECISION_SIGNATURE = f"{RELEASE_DECISION}.sig"
LOCAL_CONVERGENCE = "LOCAL-CONVERGENCE.json"
LOCAL_CONVERGENCE_SIGNATURE = f"{LOCAL_CONVERGENCE}.sig"
ALLOWED_SIGNERS = "release/0.9.0/audit/ALLOWED_SIGNERS"
PLAN = "release/0.9.0/task-closure-plan.json"
CLAIMS = "release/0.9.0/claims.json"
TASKS = "release/0.9.0/tasks.json"
MAX_REVIEW_INPUT_BYTES = 64 * 1024 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
MAX_SIGNING_KEY_BYTES = 1024 * 1024
MAX_QUALIFICATION_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_QUALIFICATION_TIER_BYTES = 8 * 1024 * 1024 * 1024
MAX_QUALIFICATION_ENTRIES = 32_768
MAX_QUALIFICATION_DEPTH = 128
MAX_QUALIFICATION_CHECKSUM_BYTES = 16 * 1024 * 1024
CLOSURE_RESERVED_ROOT_PATHS = frozenset(
    {
        QUALIFICATION_MANIFEST,
        QUALIFICATION_SIGNATURE,
        "closure-summary.json",
        CLOSURE_MANIFEST,
        CLOSURE_SIGNATURE,
        RELEASE_DECISION,
        RELEASE_DECISION_SIGNATURE,
        LOCAL_CONVERGENCE,
        LOCAL_CONVERGENCE_SIGNATURE,
        "SHA256SUMS",
    }
)


class PublicationDurabilityError(ReviewError):
    """A complete output was renamed into place but its parent sync failed."""


def warn_cleanup_failure(label: str, error: OSError) -> None:
    """Make an abandoned temporary path visible without masking the root failure."""

    try:
        print(f"warning: could not remove {label}: {error}", file=sys.stderr)
    except Exception:
        pass


def cleanup_finalization_inputs(
    temporary: tempfile.TemporaryDirectory[str],
    signing_key: Path | None,
) -> bool:
    """Remove snapshotted inputs; return false after any observable cleanup failure."""

    failures: list[tuple[str, OSError]] = []
    if signing_key is not None:
        try:
            signing_key.unlink(missing_ok=True)
        except OSError as error:
            failures.append((str(signing_key), error))
    try:
        temporary.cleanup()
    except OSError as error:
        failures.append((temporary.name, error))
    for label, error in failures:
        warn_cleanup_failure(label, error)
    return not failures


def postpublication_cleanup_status(
    temporary: tempfile.TemporaryDirectory[str],
    signing_key: Path | None,
) -> int:
    """Map cleanup of an already-published complete bundle to status 0 or 3."""

    return 0 if cleanup_finalization_inputs(temporary, signing_key) else 3


def emit_publication_result(result: dict[str, Any], status: int) -> int:
    """Emit an unambiguous record for a fully published output and return its status."""

    if status not in {0, 3}:
        raise ReviewError("publication result status must be 0 or 3")
    record = dict(result)
    record["publication_status"] = (
        "COMMITTED" if status == 0 else "COMMITTED_WITH_CLEANUP_WARNING"
    )
    print(json.dumps(record, sort_keys=True))
    return status


def absolute_path_without_final_resolution(value: str) -> Path:
    """Resolve a path's parent without dereferencing its final component."""

    absolute = Path(os.path.abspath(os.fspath(Path(value).expanduser())))
    return absolute.parent.resolve() / absolute.name


def snapshot_input(
    source: Path,
    destination: Path,
    *,
    max_bytes: int,
    label: str,
    mode: int = 0o600,
) -> Path:
    """Snapshot one bounded regular input before authentication or later copying."""

    data = read_bounded_regular_file(
        source,
        max_bytes,
        label=label,
        limit_label=f"{label}-byte",
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    os.chmod(destination, mode)
    return destination


def snapshot_signed_qualification_tier(
    source_root: Path,
    destination_root: Path,
    *,
    manifest_path: Path,
    signature_path: Path,
    allowed_signers: Path,
) -> dict[str, Any]:
    """Authenticate, no-follow snapshot, and verify one qualification tier."""

    if source_root.is_symlink() or not source_root.is_dir():
        raise ReviewError("qualification root is missing or unsafe")
    verify_signature(
        manifest_path,
        signature_path,
        allowed_signers,
        "galadriel-qualification-manifest",
    )
    manifest = load_canonical_object(manifest_path, "qualification manifest")
    if set(manifest) != {"schema", "tier", "candidate", "artifacts"}:
        raise ReviewError("qualification manifest has unexpected fields")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ReviewError("qualification manifest must contain artifacts")
    seen: set[str] = set()
    aggregate_size = 0
    forbidden_paths = set(CLOSURE_RESERVED_ROOT_PATHS)
    for row in artifacts:
        if not isinstance(row, dict) or set(row) != {
            "path",
            "sha256",
            "size_bytes",
        }:
            raise ReviewError("qualification manifest artifact is malformed")
        relative = row["path"]
        digest = row["sha256"]
        size = row["size_bytes"]
        if not isinstance(relative, str):
            raise ReviewError("qualification manifest artifact path is malformed")
        parts = artifact_path_parts(relative)
        if (
            relative in forbidden_paths
            or parts[0] == "inputs"
            or parts[-1] in {LOCAL_CONVERGENCE, LOCAL_CONVERGENCE_SIGNATURE}
        ):
            raise ReviewError(
                f"qualification manifest contains a forbidden path: {relative}"
            )
        if relative in seen:
            raise ReviewError(f"duplicate qualification artifact: {relative}")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > MAX_QUALIFICATION_ARTIFACT_BYTES
        ):
            raise ReviewError(
                f"qualification manifest artifact bounds are invalid: {relative}"
            )
        aggregate_size += size
        if aggregate_size > MAX_QUALIFICATION_TIER_BYTES:
            raise ReviewError("qualification tier exceeds the aggregate size limit")
        seen.add(relative)

    expected_inventory = seen | {
        QUALIFICATION_MANIFEST,
        QUALIFICATION_SIGNATURE,
        "SHA256SUMS",
    }
    before_inventory = qualification_tier_inventory(source_root)
    if before_inventory != expected_inventory:
        raise ReviewError("qualification source inventory differs from its manifest")

    for row in artifacts:
        relative = row["path"]
        snapshot_qualification_artifact(
            source_root,
            relative,
            destination_root.joinpath(*artifact_path_parts(relative)),
            expected_sha256=row["sha256"],
            expected_size=row["size_bytes"],
        )

    snapshot_input(
        source_root / "SHA256SUMS",
        destination_root / "SHA256SUMS",
        max_bytes=MAX_QUALIFICATION_CHECKSUM_BYTES,
        label="qualification checksum inventory",
    )

    after_inventory = qualification_tier_inventory(source_root)
    if after_inventory != expected_inventory:
        raise ReviewError("qualification source changed while being snapshotted")

    retained_manifest = verify_artifact_manifest(
        destination_root,
        manifest_path,
        expected_schema="galadriel.tiered-artifact-manifest.v1",
        forbidden_paths=forbidden_paths,
    )
    verify_sha256sums(destination_root)
    return retained_manifest


def qualification_tier_inventory(root: Path) -> set[str]:
    """Inventory an exact no-follow qualification tree without reading file contents."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    if no_follow is None or non_block is None or directory_flag is None:
        raise ReviewError("atomic no-follow qualification inventory is unavailable")
    directory_flags = (
        os.O_RDONLY | no_follow | non_block | directory_flag | close_on_exec
    )
    try:
        root_descriptor = os.open(root, directory_flags)
    except OSError as error:
        raise ReviewError("qualification root is missing or unsafe") from error

    paths: set[str] = set()
    entry_count = 0

    def visit(directory_descriptor: int, prefix: tuple[str, ...]) -> None:
        nonlocal entry_count
        try:
            with os.scandir(directory_descriptor) as iterator:
                names = sorted(entry.name for entry in iterator)
        except OSError as error:
            raise ReviewError(
                "cannot completely inventory qualification tier"
            ) from error
        if prefix and not names:
            raise ReviewError(
                "qualification tier contains an empty directory: " + "/".join(prefix)
            )
        for name in names:
            entry_count += 1
            if entry_count > MAX_QUALIFICATION_ENTRIES:
                raise ReviewError("qualification tier exceeds the entry-count limit")
            try:
                name.encode("utf-8", "strict")
            except UnicodeEncodeError as error:
                raise ReviewError(
                    "qualification tier contains a non-UTF-8 path"
                ) from error
            if not name or name in {".", ".."} or "/" in name or "\\" in name:
                raise ReviewError("qualification tier contains an unsafe path")
            relative_parts = (*prefix, name)
            relative = "/".join(relative_parts)
            try:
                metadata = os.stat(
                    name, dir_fd=directory_descriptor, follow_symlinks=False
                )
            except OSError as error:
                raise ReviewError(
                    f"qualification entry is missing or unsafe: {relative}"
                ) from error
            if stat.S_ISREG(metadata.st_mode):
                paths.add(relative)
                continue
            if stat.S_ISDIR(metadata.st_mode):
                if len(relative_parts) > MAX_QUALIFICATION_DEPTH:
                    raise ReviewError(
                        "qualification tier exceeds the directory-depth limit"
                    )
                try:
                    child_descriptor = os.open(
                        name, directory_flags, dir_fd=directory_descriptor
                    )
                except OSError as error:
                    raise ReviewError(
                        f"qualification directory is missing or unsafe: {relative}"
                    ) from error
                try:
                    visit(child_descriptor, relative_parts)
                finally:
                    os.close(child_descriptor)
                continue
            kind = "symlink" if stat.S_ISLNK(metadata.st_mode) else "special file"
            raise ReviewError(f"qualification tier contains a {kind}: {relative}")

    try:
        visit(root_descriptor, ())
    finally:
        os.close(root_descriptor)
    return paths


def snapshot_qualification_artifact(
    source_root: Path,
    relative: str,
    destination: Path,
    *,
    expected_sha256: str,
    expected_size: int,
) -> None:
    """Stream one signed artifact through held no-follow directory descriptors."""

    parts = artifact_path_parts(relative)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    if no_follow is None or non_block is None or directory_flag is None:
        raise ReviewError("atomic no-follow qualification reads are unavailable")
    directory_flags = (
        os.O_RDONLY | no_follow | non_block | directory_flag | close_on_exec
    )
    file_flags = os.O_RDONLY | no_follow | non_block | close_on_exec
    try:
        directory_descriptor = os.open(source_root, directory_flags)
    except OSError as error:
        raise ReviewError("qualification root is missing or unsafe") from error
    try:
        for part in parts[:-1]:
            try:
                next_descriptor = os.open(
                    part, directory_flags, dir_fd=directory_descriptor
                )
            except OSError as error:
                raise ReviewError(
                    f"qualification artifact is missing or unsafe: {relative}"
                ) from error
            previous_descriptor = directory_descriptor
            directory_descriptor = next_descriptor
            os.close(previous_descriptor)
        try:
            descriptor = os.open(parts[-1], file_flags, dir_fd=directory_descriptor)
        except OSError as error:
            raise ReviewError(
                f"qualification artifact is missing or unsafe: {relative}"
            ) from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size != expected_size
                or metadata.st_size > MAX_QUALIFICATION_ARTIFACT_BYTES
            ):
                raise ReviewError(
                    f"qualification artifact size or type mismatch: {relative}"
                )
            destination.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            total = 0
            source = os.fdopen(descriptor, "rb", closefd=True)
            descriptor = -1
            with source:
                with destination.open("xb") as target:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        total += len(block)
                        if total > expected_size:
                            raise ReviewError(
                                f"qualification artifact changed while read: {relative}"
                            )
                        digest.update(block)
                        target.write(block)
            if total != expected_size or digest.hexdigest() != expected_sha256:
                raise ReviewError(f"qualification artifact digest mismatch: {relative}")
        except BaseException:
            destination.unlink(missing_ok=True)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise
    finally:
        try:
            os.close(directory_descriptor)
        except OSError:
            pass


def load_canonical_object(path: Path, label: str) -> dict[str, Any]:
    """Parse an already snapshotted signed JSON object and require canonical bytes."""

    raw = path.read_bytes()
    value = loads_json(raw)
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise ReviewError(f"{label} is not a canonical JSON object")
    return value


def qualification_command(qualification: dict[str, Any], name: str) -> dict[str, Any]:
    """Return one unique passing command record from the signed qualification."""

    matches = [
        item
        for item in qualification.get("commands", [])
        if isinstance(item, dict) and item.get("name") == name
    ]
    if len(matches) != 1 or matches[0].get("status") != "PASS":
        raise ReviewError(f"qualification lacks one passing {name} command")
    return matches[0]


def evidence_path_pairs(items: Any) -> set[tuple[str, str]]:
    """Project well-formed evidence identities without trusting their digests."""

    if not isinstance(items, list):
        return set()
    return {
        (item.get("kind"), item.get("path"))
        for item in items
        if isinstance(item, dict)
        and isinstance(item.get("kind"), str)
        and isinstance(item.get("path"), str)
    }


def validate_finalization_dag_evidence(
    dispositions: dict[str, Any],
    final_review: dict[str, Any],
    *,
    qualification_logs: set[str],
) -> None:
    """Prove T113 -> signed T114 -> signed T115 without prospective evidence."""

    rows = dispositions.get("dispositions")
    if not isinstance(rows, list) or len(rows) != 116:
        raise ReviewError("finalization DAG lacks the complete task disposition set")
    by_id = {item.get("task_id"): item for item in rows if isinstance(item, dict)}
    if set(by_id) != {f"T{index:03d}" for index in range(116)}:
        raise ReviewError("finalization DAG task identities are incomplete")

    mechanism_paths = {
        "release/0.9.0/local-convergence-schema.json",
        "release/0.9.0/VERSION-ADAPTATION.md",
        "repo_work/finalize_release.py",
        "repo_work/local_convergence.py",
        "repo_work/tests/test_release_assurance.py",
    }
    t113_pairs = evidence_path_pairs(by_id["T113"].get("evidence"))
    t113_pairs.update(evidence_path_pairs(by_id["T113"].get("tests")))
    required_t113 = {("candidate_blob", path) for path in mechanism_paths} | {
        ("qualification_artifact", path) for path in qualification_logs
    }
    if not required_t113.issubset(t113_pairs):
        raise ReviewError("T113 lacks exact mechanism and qualification evidence")
    if any(
        kind == "review_input"
        or Path(path).name.casefold()
        in {"local-convergence.json", "local-convergence.json.sig"}
        for kind, path in t113_pairs
    ):
        raise ReviewError("T113 cannot cite prospective convergence output")

    review_pairs = {
        pair
        for lens in final_review.get("lenses", {}).values()
        if isinstance(lens, dict)
        for pair in evidence_path_pairs(lens.get("evidence"))
    }
    required_review = {("candidate_blob", path) for path in mechanism_paths} | {
        ("qualification_artifact", path) for path in qualification_logs
    }
    if not required_review.issubset(review_pairs):
        raise ReviewError("T114 final review does not bind the T113 mechanism")

    for task_id, required_paths in (
        (
            "T114",
            {
                "inputs/FINAL-TWENTY-LENS-REVIEW.json",
                "inputs/FINAL-TWENTY-LENS-REVIEW.json.sig",
            },
        ),
        (
            "T115",
            {RELEASE_DECISION, RELEASE_DECISION_SIGNATURE},
        ),
    ):
        pairs = evidence_path_pairs(by_id[task_id].get("evidence"))
        pairs.update(evidence_path_pairs(by_id[task_id].get("tests")))
        required = {("review_input", path) for path in required_paths}
        if not required.issubset(pairs):
            raise ReviewError(f"{task_id} lacks its exact signed predecessor evidence")


def fsync_tree(root: Path) -> None:
    """Flush every staged regular file and directory before publishing the bundle."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or non_block is None or directory_flag is None:
        raise ReviewError("no-follow directory durability operations are unavailable")
    directories: list[Path] = []
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ReviewError("staged closure contains a symlink")
        if stat.S_ISREG(metadata.st_mode):
            descriptor = os.open(path, os.O_RDONLY | no_follow | non_block)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        elif stat.S_ISDIR(metadata.st_mode):
            directories.append(path)
        else:
            raise ReviewError("staged closure contains a special file")
    for path in [*sorted(directories, reverse=True), root]:
        descriptor = os.open(path, os.O_RDONLY | no_follow | non_block | directory_flag)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def atomic_rename_no_replace(source: Path, destination: Path) -> None:
    """Rename a directory without replacing any concurrently created path."""

    library = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin":
        rename = library.renamex_np
        rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(source_bytes, destination_bytes, 0x00000004)
    elif sys.platform.startswith("linux") and hasattr(library, "renameat2"):
        rename = library.renameat2
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        result = rename(-100, source_bytes, -100, destination_bytes, 1)
    else:
        raise ReviewError("atomic no-replace directory rename is unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise ReviewError("refusing to replace an existing finalization output")
    raise OSError(error_number, os.strerror(error_number), destination)


def publish_staged_output(staging: Path, destination: Path) -> None:
    """Flush and atomically publish one complete same-parent staging tree."""

    if staging.parent != destination.parent:
        raise ReviewError("finalization staging and output must share one parent")
    fsync_tree(staging)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or non_block is None or directory_flag is None:
        raise ReviewError("no-follow directory durability operations are unavailable")
    parent_descriptor = os.open(
        destination.parent,
        os.O_RDONLY | no_follow | non_block | directory_flag,
    )
    try:
        atomic_rename_no_replace(staging, destination)
    except BaseException:
        try:
            os.close(parent_descriptor)
        except OSError:
            pass
        raise
    durability_error: OSError | None = None
    try:
        os.fsync(parent_descriptor)
    except OSError as error:
        durability_error = error
    try:
        os.close(parent_descriptor)
    except OSError as error:
        if durability_error is None:
            durability_error = error
    if durability_error is not None:
        raise PublicationDurabilityError(
            "complete output was published, but parent-directory durability "
            "could not be confirmed"
        ) from durability_error


def candidate_json(repo: Path, commit: str, relative: str) -> dict[str, Any]:
    raw = bytes(git(repo, "show", f"{commit}:{relative}", text=False))
    try:
        value = loads_json(raw)
    except (UnicodeError, ValueError) as error:
        raise ReviewError(
            f"candidate JSON is invalid at {relative}: {error}"
        ) from error
    if not isinstance(value, dict):
        raise ReviewError(f"candidate JSON must be an object: {relative}")
    return value


def candidate_digest(repo: Path, commit: str, relative: str) -> str:
    raw = bytes(git(repo, "show", f"{commit}:{relative}", text=False))
    return hashlib.sha256(raw).hexdigest()


def artifact_rows(root: Path, excluded: set[str]) -> list[dict[str, Any]]:
    rows = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ReviewError(f"closure output contains a symlink: {relative}")
        if not path.is_file():
            continue
        if relative in excluded:
            continue
        digest, size = digest_file(path)
        rows.append({"path": relative, "sha256": digest, "size_bytes": size})
    return rows


def validate_candidate_plan_documents(
    plan: dict[str, Any], tasks_document: dict[str, Any]
) -> None:
    planned = plan.get("tasks")
    source_digest = plan.get("source_task_ledger_sha256")
    lens_catalog = plan.get("lens_catalog")
    if (
        plan.get("schema") != "galadriel.task-closure-plan.v2"
        or not isinstance(planned, list)
        or len(planned) != 116
        or any(not isinstance(item, dict) for item in planned)
        or not isinstance(source_digest, str)
        or len(source_digest) != 64
        or any(character not in "0123456789abcdef" for character in source_digest)
        or not isinstance(lens_catalog, dict)
        or set(lens_catalog) != {f"L{index:02d}" for index in range(1, 21)}
        or any(not isinstance(value, dict) for value in lens_catalog.values())
    ):
        raise ReviewError("candidate source plan is incomplete")
    task_source = tasks_document.get("source")
    if (
        not isinstance(task_source, dict)
        or task_source.get("task_ledger_sha256") != source_digest
    ):
        raise ReviewError("candidate source plan targets another task ledger")
    tasks = tasks_document.get("tasks")
    expected_ids = [f"T{index:03d}" for index in range(116)]
    if (
        not isinstance(tasks, list)
        or any(not isinstance(item, dict) for item in tasks)
        or [item.get("task_id") for item in planned] != expected_ids
        or [item.get("id") for item in tasks] != expected_ids
    ):
        raise ReviewError("candidate task sequence is not exactly T000--T115")
    completed_prefix: set[str] = set()
    for task_plan, task in zip(planned, tasks, strict=True):
        task_id = task["id"]
        source = task_plan.get("source_projection")
        dependencies = task.get("dependencies")
        if (
            not isinstance(source, dict)
            or source.get("id") != task_id
            or source.get("dependencies") != dependencies
            or not isinstance(dependencies, list)
            or len(dependencies) != len(set(dependencies))
            or not set(dependencies).issubset(completed_prefix)
        ):
            raise ReviewError(f"candidate task dependencies are invalid at {task_id}")
        completed_prefix.add(task_id)


def validate_qualification_record(
    qualification: dict[str, Any],
    *,
    commit: str,
    tree: str,
    expected_evidence_config_sha256: str,
) -> dict[str, Any]:
    if qualification.get("schema") != "galadriel.candidate-qualification.v2":
        raise ReviewError("qualification record has the wrong schema")
    if (
        qualification.get("release") != VERSION
        or qualification.get("author") != AUTHOR
        or qualification.get("doi") is not None
        or qualification.get("zenodo") is not None
    ):
        raise ReviewError(
            "qualification record has the wrong release authorship or archive scope"
        )
    if (
        qualification.get("status") != "PASS"
        or qualification.get("command_status") != "PASS"
    ):
        raise ReviewError("qualification commands or artifacts did not pass")
    if (
        qualification.get("candidate", {}).get("commit") != commit
        or qualification.get("candidate", {}).get("tree") != tree
    ):
        raise ReviewError("qualification record targets the wrong candidate")
    if qualification.get("deep_campaigns_requested") is not True:
        raise ReviewError("qualification omitted the required deep campaigns")
    if qualification.get("evidence_config") != "evidence/galadriel-0.9-candidate.json":
        raise ReviewError(
            "qualification used another or omitted candidate evidence config"
        )
    binding = qualification.get("evidence_config_binding")
    if (
        not isinstance(binding, dict)
        or binding.get("tracked_path") != "evidence/galadriel-0.9-candidate.json"
        or binding.get("study_design_status") != "PASS"
        or binding.get("tracked_blob_sha256") != expected_evidence_config_sha256
        or not isinstance(binding.get("accepted_semantic_digest"), str)
        or len(binding["accepted_semantic_digest"]) != 64
    ):
        raise ReviewError("qualification lacks the exact preregistered config binding")
    mutation = qualification.get("mutation_evidence")
    if (
        not isinstance(mutation, dict)
        or mutation.get("status") != "PASS"
        or mutation.get("candidate") != {"commit": commit, "tree": tree}
        or mutation.get("shards") != 4
    ):
        raise ReviewError("qualification lacks exact-candidate mutation evidence")
    return binding


def _absolute_recorded_path(value: Any, context: str) -> Path:
    if not isinstance(value, str):
        raise ReviewError(f"{context} must be an absolute recorded path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ReviewError(f"{context} must be an absolute recorded path")
    return path


def _dynamic_qualification_specs(
    by_name: dict[str, dict[str, Any]], qualification_root: Path
) -> tuple[CommandSpec, ...]:
    verify_argv = by_name["verify-commit-signature-external-key"].get("argv")
    if (
        not isinstance(verify_argv, list)
        or len(verify_argv) != 5
        or verify_argv[:2] != ["git", "-c"]
        or verify_argv[3:] != ["verify-commit", "HEAD"]
        or not isinstance(verify_argv[2], str)
        or not verify_argv[2].startswith("gpg.ssh.allowedSignersFile=")
    ):
        raise ReviewError("qualification used another commit-verification command")
    trust_root = _absolute_recorded_path(
        verify_argv[2].split("=", 1)[1], "qualification external trust root"
    )
    if trust_root.name != "EXTERNAL_ALLOWED_SIGNERS":
        raise ReviewError(
            "qualification did not record the ephemeral external trust root"
        )

    inventory_argv = by_name["tracked-source-inventory"].get("argv")
    if not isinstance(inventory_argv, list) or len(inventory_argv) != 6:
        raise ReviewError("qualification source-inventory command is malformed")
    inventory = _absolute_recorded_path(
        inventory_argv[-1], "qualification source-inventory output"
    )
    output_root = inventory.parent
    if output_root != qualification_root.resolve():
        raise ReviewError("qualification commands target another output directory")
    if (
        inventory.name != "source-inventory"
        or trust_root == output_root
        or output_root in trust_root.parents
    ):
        raise ReviewError(
            "qualification output and external trust roots are not separate"
        )

    dynamic = (
        CommandSpec(
            "verify-commit-signature-external-key",
            tuple(verify_argv),
        ),
        CommandSpec(
            "tracked-source-inventory",
            (
                "python3",
                "repo_work/audit_tracked_files.py",
                "--repo",
                ".",
                "--out",
                str(inventory),
            ),
        ),
        CommandSpec(
            "review-packets",
            (
                "python3",
                "repo_work/make_review_packets.py",
                str(inventory / "FILE_REVIEW_LEDGER.csv"),
                "--out",
                str(inventory / "review-packets"),
                "--lanes",
                "3",
            ),
        ),
        CommandSpec(
            "claim-language-inventory",
            (
                "python3",
                "repo_work/scan_claim_language.py",
                "--repo",
                ".",
                "--out",
                str(inventory / "CLAIM_LANGUAGE.json"),
            ),
        ),
        CommandSpec(
            "candidate-evidence",
            (
                "cargo",
                "run",
                "--release",
                "--locked",
                "-p",
                "galadriel-eval",
                "--bin",
                "galadriel-evidence",
                "--",
                "--config",
                "evidence/galadriel-0.9-candidate.json",
                "--out",
                str(output_root / "candidate-evidence"),
            ),
            timeout_seconds=7_200,
        ),
    )
    return dynamic


def validate_qualification_commands(
    commands: Any,
    *,
    manifest_artifacts: dict[str, dict[str, Any]],
    qualification_root: Path,
    recorded_root: Path | None = None,
) -> None:
    """Bind every PASS result to the frozen argv contract and retained command output."""

    if not isinstance(commands, list) or not all(
        isinstance(item, dict) for item in commands
    ):
        raise ReviewError("qualification command results are missing or malformed")
    by_name = {
        command.get("name"): command
        for command in commands
        if isinstance(command.get("name"), str)
    }
    if len(by_name) != len(commands):
        raise ReviewError("qualification command names are invalid or duplicated")
    dynamic_names = {
        "verify-commit-signature-external-key",
        "tracked-source-inventory",
        "review-packets",
        "claim-language-inventory",
        "candidate-evidence",
    }
    if not dynamic_names.issubset(by_name):
        raise ReviewError("qualification omitted a dynamic candidate-bound command")
    dynamic = _dynamic_qualification_specs(
        by_name, recorded_root if recorded_root is not None else qualification_root
    )
    dynamic_by_name = {spec.name: spec for spec in dynamic}
    ordered_specs = [
        dynamic_by_name["verify-commit-signature-external-key"],
        dynamic_by_name["tracked-source-inventory"],
        dynamic_by_name["review-packets"],
        dynamic_by_name["claim-language-inventory"],
        *BASE_COMMANDS,
        dynamic_by_name["candidate-evidence"],
        *DEEP_COMMANDS,
    ]
    expected_names = [spec.name for spec in ordered_specs]
    observed_names = [command.get("name") for command in commands]
    if observed_names != expected_names:
        raise ReviewError(
            "qualification command set or execution order differs from the frozen gate"
        )

    result_keys = {
        "name",
        "argv",
        "cwd",
        "environment_overrides",
        "started_at",
        "finished_at",
        "duration_seconds",
        "timeout_seconds",
        "timed_out",
        "exit_code",
        "status",
        "log",
        "log_sha256",
        "log_size_bytes",
    }
    marker = b"--- combined stdout/stderr ---\n"
    for spec, result in zip(ordered_specs, commands, strict=True):
        if set(result) != result_keys:
            raise ReviewError(
                f"qualification result {spec.name} has an unexpected field set"
            )
        if (
            result["argv"] != list(spec.argv)
            or result["cwd"] != spec.cwd
            or result["environment_overrides"] != dict(spec.environment)
            or result["timeout_seconds"] != spec.timeout_seconds
        ):
            raise ReviewError(f"qualification command contract drifted for {spec.name}")
        if (
            result["status"] != "PASS"
            or result["exit_code"] != 0
            or result["timed_out"] is not False
        ):
            raise ReviewError(
                f"qualification command did not pass cleanly: {spec.name}"
            )
        relative = result["log"]
        manifest_row = (
            manifest_artifacts.get(relative) if isinstance(relative, str) else None
        )
        if (
            manifest_row is None
            or result["log_sha256"] != manifest_row["sha256"]
            or result["log_size_bytes"] != manifest_row["size_bytes"]
        ):
            raise ReviewError(
                f"qualification command output is not manifest-bound: {spec.name}"
            )
        log = qualification_root / relative
        prefix, separator, _output = log.read_bytes().partition(marker)
        if not separator:
            raise ReviewError(
                f"qualification command output lacks its header: {spec.name}"
            )
        try:
            header = loads_json(prefix)
        except (UnicodeError, ValueError) as error:
            raise ReviewError(
                f"qualification command header is invalid: {spec.name}: {error}"
            ) from error
        if header != {
            "argv": result["argv"],
            "cwd": result["cwd"],
            "environment_overrides": result["environment_overrides"],
            "started_at": result["started_at"],
            "timeout_seconds": result["timeout_seconds"],
        }:
            raise ReviewError(
                f"qualification command header contradicts its result: {spec.name}"
            )


def verify_qualification(
    root: Path,
    *,
    repo: Path,
    allowed_signers: Path,
    commit: str,
    tree: str,
    expected_evidence_config_sha256: str,
    recorded_root: Path | None = None,
    manifest_path: Path | None = None,
    signature_path: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    manifest_path = manifest_path or root / QUALIFICATION_MANIFEST
    signature_path = signature_path or root / QUALIFICATION_SIGNATURE
    verify_signature(
        manifest_path,
        signature_path,
        allowed_signers,
        "galadriel-qualification-manifest",
    )
    manifest = verify_artifact_manifest(
        root,
        manifest_path,
        expected_schema="galadriel.tiered-artifact-manifest.v1",
        forbidden_paths=set(CLOSURE_RESERVED_ROOT_PATHS),
    )
    expected_inventory = {item["path"] for item in manifest["artifacts"]} | {
        QUALIFICATION_MANIFEST,
        QUALIFICATION_SIGNATURE,
        "SHA256SUMS",
    }
    if qualification_tier_inventory(root) != expected_inventory:
        raise ReviewError("qualification tier inventory differs from its manifest")
    verify_sha256sums(root)
    if manifest["tier"] != "qualification" or manifest["candidate"] != {
        "commit": commit,
        "tree": tree,
    }:
        raise ReviewError("qualification manifest targets the wrong tier or candidate")
    paths = {item["path"] for item in manifest["artifacts"]}
    mandatory = {
        "qualification.json",
        "candidate-acceptance.json",
        "candidate-evidence/config.json",
        "candidate-evidence/manifest.json",
        "candidate-evidence/summary.json",
        "cargo-metadata.json",
        "REPRODUCIBILITY.json",
        "provenance.json",
        f"galadriel-{VERSION}.tar.gz",
        "reports/license-report.jsonl",
        "reports/vulnerability-report.json",
        "source-inventory/TRACKED_FILE_MANIFEST.json",
        "source-inventory/FILE_REVIEW_LEDGER.csv",
        "mutation/manifest.json",
        "mutation/manifest.json.sig",
    }
    missing = sorted(mandatory - paths)
    if missing:
        raise ReviewError(
            f"qualification manifest omits mandatory artifacts: {missing}"
        )
    if (
        len(
            [
                path
                for path in paths
                if path.startswith("packages/") and path.endswith(".crate")
            ]
        )
        != 7
    ):
        raise ReviewError(
            "qualification tier must contain seven reproducible package artifacts"
        )
    if (
        len(
            [
                path
                for path in paths
                if path.startswith("sbom/") and path.endswith(".cdx.json")
            ]
        )
        != 7
    ):
        raise ReviewError("qualification tier must contain seven workspace SBOMs")
    mutation_document, mutation_artifacts = validate_mutation_evidence(
        root / "mutation" / "manifest.json",
        root / "mutation" / "manifest.json.sig",
        allowed_signers=allowed_signers,
        repo=repo,
        commit=commit,
        tree=tree,
    )
    if len(mutation_artifacts) != 7:
        raise ReviewError(
            "qualification tier must contain six mutation outcomes and one run receipt"
        )

    qualification = load_json(root / "qualification.json")
    config_binding = validate_qualification_record(
        qualification,
        commit=commit,
        tree=tree,
        expected_evidence_config_sha256=expected_evidence_config_sha256,
    )
    manifest_artifacts = {item["path"]: item for item in manifest["artifacts"]}
    if (
        config_binding.get("accepted_config_sha256")
        != manifest_artifacts["candidate-evidence/config.json"]["sha256"]
    ):
        raise ReviewError(
            "qualification evidence config binding differs from the retained bytes"
        )
    validate_qualification_commands(
        qualification.get("commands"),
        manifest_artifacts=manifest_artifacts,
        qualification_root=root,
        recorded_root=recorded_root,
    )
    expected_tools = {
        "cargo_deny": "cargo-deny 0.19.9",
        "cargo_audit": "cargo-audit-audit 0.22.2",
        "cargo_cyclonedx": "cargo-cyclonedx-cyclonedx 0.5.9",
        "cargo_public_api": "cargo-public-api 0.52.0",
        "cargo_fuzz": "cargo-fuzz 0.13.2",
    }
    tools = qualification.get("tools")
    if not isinstance(tools, dict) or any(
        tools.get(name) != identity for name, identity in expected_tools.items()
    ):
        raise ReviewError("qualification used an unpinned release tool")
    source_date_epoch = int(
        str(git(repo, "show", "-s", "--format=%ct", commit)).strip()
    )
    if qualification.get("environment_contract") != {
        "CARGO_INCREMENTAL": "0",
        "CARGO_TERM_COLOR": "never",
        "LC_ALL": "C",
        "SOURCE_DATE_EPOCH": str(source_date_epoch),
        "TZ": "UTC",
    }:
        raise ReviewError(
            "qualification used another deterministic environment contract"
        )
    mutation_record = qualification.get("mutation_evidence")
    if not isinstance(mutation_record, dict) or set(mutation_record) != {
        "manifest",
        "manifest_sha256",
        "signature",
        "candidate",
        "baseline_commit",
        "shards",
        "focused_checks",
        "run_receipts",
        "status",
        "artifacts",
    }:
        raise ReviewError("qualification mutation record is malformed")
    if (
        mutation_record["manifest"] != "mutation/manifest.json"
        or mutation_record["signature"] != "mutation/manifest.json.sig"
        or mutation_record["manifest_sha256"]
        != manifest_artifacts["mutation/manifest.json"]["sha256"]
        or mutation_record["candidate"] != {"commit": commit, "tree": tree}
        or mutation_record["baseline_commit"] != mutation_document["baseline_commit"]
        or any(
            type(mutation_record[field]) is not int
            for field in ("shards", "focused_checks", "run_receipts")
        )
        or mutation_record["shards"] != 4
        or mutation_record["focused_checks"] != 2
        or mutation_record["run_receipts"] != 1
        or mutation_record["status"] != "PASS"
        or not isinstance(mutation_record["artifacts"], list)
    ):
        raise ReviewError("qualification mutation record is not exact-candidate bound")
    expected_mutation_paths = {
        path.relative_to(root).as_posix() for path in mutation_artifacts
    }
    observed_mutation_paths: set[str] = set()
    for artifact in mutation_record["artifacts"]:
        if not isinstance(artifact, dict) or set(artifact) != {
            "path",
            "sha256",
            "size_bytes",
        }:
            raise ReviewError("qualification mutation artifact record is malformed")
        path = artifact["path"]
        row = manifest_artifacts.get(path) if isinstance(path, str) else None
        if (
            row is None
            or path in observed_mutation_paths
            or (artifact["sha256"], artifact["size_bytes"])
            != (row["sha256"], row["size_bytes"])
        ):
            raise ReviewError(
                "qualification mutation artifact is duplicate or not manifest-bound"
            )
        observed_mutation_paths.add(path)
    if observed_mutation_paths != expected_mutation_paths:
        raise ReviewError(
            "qualification mutation record omits exact mutation artifacts"
        )

    expected_crates = {
        "galadriel-cli",
        "galadriel-core",
        "galadriel-eval",
        "galadriel-justify",
        "galadriel-ncp",
        "galadriel-pid",
        "galadriel-sim",
    }
    packages = qualification.get("packages")
    sboms = qualification.get("sboms")
    if not isinstance(packages, list) or not isinstance(sboms, list):
        raise ReviewError("qualification record lacks package or SBOM coverage")
    package_by_crate: dict[str, dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict) or set(package) != {
            "crate",
            "version",
            "candidate_commit",
            "package_kind",
            "lockfile_policy",
            "dependency_resolution",
            "path",
            "sha256",
            "size_bytes",
        }:
            raise ReviewError("qualification package record is malformed")
        crate = package["crate"]
        if not isinstance(crate, str) or not isinstance(package["path"], str):
            raise ReviewError("qualification package identity is malformed")
        expected_path = f"packages/{crate}-{VERSION}.crate"
        row = manifest_artifacts.get(package["path"])
        if (
            crate in package_by_crate
            or package["version"] != VERSION
            or package["candidate_commit"] != commit
            or package["package_kind"] != "cargo_package_unpublished_source"
            or package["lockfile_policy"]
            != "excluded; candidate Cargo.lock is retained in the source archive"
            or package["dependency_resolution"]
            != "offline temporary path overrides for locked unpublished workspace and Git dependencies"
            or package["path"] != expected_path
            or row is None
            or (package["sha256"], package["size_bytes"])
            != (row["sha256"], row["size_bytes"])
        ):
            raise ReviewError(
                "qualification package record is duplicate or not manifest-bound"
            )
        package_by_crate[crate] = package
    if set(package_by_crate) != expected_crates:
        raise ReviewError(
            "qualification package set differs from the release workspace"
        )

    sbom_by_crate: dict[str, dict[str, Any]] = {}
    for sbom in sboms:
        if not isinstance(sbom, dict) or set(sbom) != {
            "crate",
            "path",
            "sha256",
            "size_bytes",
        }:
            raise ReviewError("qualification SBOM record is malformed")
        crate = sbom["crate"]
        if not isinstance(crate, str) or not isinstance(sbom["path"], str):
            raise ReviewError("qualification SBOM identity is malformed")
        expected_path = f"sbom/{crate}.cdx.json"
        row = manifest_artifacts.get(sbom["path"])
        if (
            crate in sbom_by_crate
            or sbom["path"] != expected_path
            or row is None
            or (sbom["sha256"], sbom["size_bytes"])
            != (row["sha256"], row["size_bytes"])
        ):
            raise ReviewError(
                "qualification SBOM record is duplicate or not manifest-bound"
            )
        document = load_json(root / sbom["path"])
        if (
            not isinstance(document, dict)
            or document.get("bomFormat") != "CycloneDX"
            or document.get("specVersion") != "1.5"
        ):
            raise ReviewError(f"qualification SBOM has the wrong format: {crate}")
        sbom_by_crate[crate] = sbom
    if set(sbom_by_crate) != expected_crates:
        raise ReviewError("qualification SBOM set differs from the release workspace")
    cargo_metadata = load_json(root / "cargo-metadata.json")
    if not isinstance(cargo_metadata, dict):
        raise ReviewError("qualification Cargo metadata is malformed")
    workspace_members = cargo_metadata.get("workspace_members")
    metadata_packages = cargo_metadata.get("packages")
    if (
        not isinstance(workspace_members, list)
        or not all(isinstance(member, str) for member in workspace_members)
        or not isinstance(metadata_packages, list)
        or not all(isinstance(package, dict) for package in metadata_packages)
    ):
        raise ReviewError("qualification Cargo metadata lacks workspace identities")
    workspace_member_set = set(workspace_members)
    observed_workspace = {
        (package.get("name"), package.get("version"))
        for package in metadata_packages
        if isinstance(package.get("id"), str) and package["id"] in workspace_member_set
    }
    if observed_workspace != {(crate, VERSION) for crate in expected_crates}:
        raise ReviewError(
            "qualification Cargo metadata targets another workspace package set"
        )

    archive = qualification.get("source_archive")
    archive_path = f"galadriel-{VERSION}.tar.gz"
    archive_row = manifest_artifacts[archive_path]
    if (
        not isinstance(archive, dict)
        or archive.get("path") != archive_path
        or (archive.get("sha256"), archive.get("size_bytes"))
        != (archive_row["sha256"], archive_row["size_bytes"])
        or not isinstance(archive.get("tracked_entries"), int)
        or archive["tracked_entries"] <= 0
    ):
        raise ReviewError("qualification source archive is not manifest-bound")
    reproducibility_pointer = qualification.get("reproducibility")
    if reproducibility_pointer != {"path": "REPRODUCIBILITY.json", "status": "PASS"}:
        raise ReviewError("two-run package/source reproducibility did not pass")
    reproducibility = load_json(root / "REPRODUCIBILITY.json")
    if (
        not isinstance(reproducibility, dict)
        or reproducibility.get("schema") != "galadriel.reproducibility-comparison.v1"
        or reproducibility.get("candidate") != {"commit": commit, "tree": tree}
        or reproducibility.get("status") != "PASS"
        or not isinstance(reproducibility.get("comparisons"), list)
    ):
        raise ReviewError("reproducibility record targets another candidate or status")
    comparisons = reproducibility["comparisons"]
    if len(comparisons) != 8:
        raise ReviewError(
            "reproducibility record lacks one source and seven package comparisons"
        )
    expected_comparisons = {archive_path: archive}
    expected_comparisons.update(
        {
            f"{crate}-{VERSION}.crate": package
            for crate, package in package_by_crate.items()
        }
    )
    seen_comparisons: set[str] = set()
    for comparison in comparisons:
        if not isinstance(comparison, dict) or set(comparison) != {
            "kind",
            "name",
            "run_1_sha256",
            "run_2_sha256",
            "size_bytes",
            "status",
        }:
            raise ReviewError("reproducibility comparison is malformed")
        name = comparison["name"]
        expected = expected_comparisons.get(name)
        expected_kind = "source_archive" if name == archive_path else "cargo_package"
        if (
            expected is None
            or name in seen_comparisons
            or comparison["kind"] != expected_kind
            or comparison["status"] != "IDENTICAL"
            or comparison["run_1_sha256"] != expected["sha256"]
            or comparison["run_2_sha256"] != expected["sha256"]
            or comparison["size_bytes"] != expected["size_bytes"]
        ):
            raise ReviewError(
                "reproducibility comparison contradicts the retained artifact"
            )
        seen_comparisons.add(name)
    if seen_comparisons != set(expected_comparisons):
        raise ReviewError("reproducibility comparisons omit release artifacts")

    provenance = load_json(root / "provenance.json")
    if (
        not isinstance(provenance, dict)
        or provenance.get("schema") != "galadriel.slsa-provenance.v1"
        or provenance.get("release") != VERSION
        or provenance.get("subject") != {"commit": commit, "tree": tree}
        or provenance.get("builder")
        != {
            "kind": "author-operated isolated qualification worktree",
            "tools": tools,
        }
        or provenance.get("invocation")
        != {
            "source_date_epoch": source_date_epoch,
            "deep_campaigns_requested": True,
            "evidence_config": "evidence/galadriel-0.9-candidate.json",
        }
        or provenance.get("materials")
        != {
            "source_archive_sha256": archive["sha256"],
            "package_sha256": [package["sha256"] for package in packages],
            "sbom_sha256": [sbom["sha256"] for sbom in sboms],
        }
    ):
        raise ReviewError(
            "qualification provenance contradicts its candidate or materials"
        )

    report_contracts = (
        (
            "license_report",
            "reports/license-report.jsonl",
            [
                "cargo",
                "deny",
                "--format",
                "json",
                "--all-features",
                "--locked",
                "check",
                "licenses",
            ],
        ),
        (
            "vulnerability_report",
            "reports/vulnerability-report.json",
            [
                "cargo",
                "audit",
                "--no-yanked",
                "--ignore",
                "RUSTSEC-2026-0041",
                "--format",
                "json",
            ],
        ),
    )
    for field, relative, argv in report_contracts:
        report = qualification.get(field)
        row = manifest_artifacts[relative]
        if (
            not isinstance(report, dict)
            or set(report) != {"argv", "path", "sha256", "size_bytes", "stderr"}
            or report["argv"] != argv
            or report["path"] != relative
            or (report["sha256"], report["size_bytes"])
            != (row["sha256"], row["size_bytes"])
        ):
            raise ReviewError(
                f"qualification {field} is not command- and manifest-bound"
            )
    license_documents = [
        loads_json(line)
        for line in (root / "reports/license-report.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    if not license_documents or not all(
        isinstance(item, dict) for item in license_documents
    ):
        raise ReviewError("qualification license report is empty or malformed")
    license_summaries = [
        item for item in license_documents if item.get("type") == "summary"
    ]
    license_counts = (
        license_summaries[-1].get("fields", {}).get("licenses", {})
        if license_summaries
        else {}
    )
    if license_counts.get("errors") != 0 or license_counts.get("warnings") != 0:
        raise ReviewError("qualification license report contains errors or warnings")
    vulnerability = load_json(root / "reports/vulnerability-report.json")
    if (
        vulnerability.get("vulnerabilities", {}).get("found") is not False
        or vulnerability.get("vulnerabilities", {}).get("count") != 0
    ):
        raise ReviewError("qualification vulnerability report contains a finding")

    acceptance = load_json(root / "candidate-acceptance.json")
    if (
        not isinstance(acceptance, dict)
        or acceptance.get("schema") != "galadriel.candidate-acceptance.v1"
    ):
        raise ReviewError("candidate acceptance record has the wrong schema")
    if (
        acceptance.get("release") != VERSION
        or acceptance.get("partition") != "holdout_results"
    ):
        raise ReviewError(
            "candidate acceptance used another release or evidence partition"
        )
    if acceptance.get("status") not in {"PASS", "FAIL"}:
        raise ReviewError("candidate acceptance was not evaluated")
    if qualification.get("acceptance", {}).get("status") != acceptance["status"]:
        raise ReviewError("qualification and acceptance status differ")
    if qualification.get("acceptance", {}).get(
        "failed_criterion_ids"
    ) != acceptance.get("failed_criterion_ids"):
        raise ReviewError("qualification and acceptance failure sets differ")
    if acceptance.get("evaluation_error"):
        raise ReviewError("candidate acceptance evaluation ended in an error")
    if any(
        criterion.get("evaluation_error")
        for criterion in acceptance.get("criteria", [])
        if isinstance(criterion, dict)
    ):
        raise ReviewError(
            "a required acceptance arm was missing, duplicate, or non-estimable"
        )
    criteria = acceptance.get("criteria")
    expected_criteria = [f"GLD-090-ACC-{number:03d}" for number in range(1, 8)]
    if (
        not isinstance(criteria, list)
        or not all(isinstance(criterion, dict) for criterion in criteria)
        or [criterion.get("id") for criterion in criteria] != expected_criteria
        or not isinstance(acceptance.get("minimum_metric_eligible_tracks"), int)
        or isinstance(acceptance["minimum_metric_eligible_tracks"], bool)
        or acceptance["minimum_metric_eligible_tracks"] < 20
    ):
        raise ReviewError(
            "candidate acceptance does not cover the seven frozen criteria"
        )
    for criterion in criteria:
        observations = criterion.get("observations")
        if (
            not isinstance(observations, list)
            or not observations
            or not all(isinstance(observation, dict) for observation in observations)
            or any(
                observation.get("status") not in {"PASS", "FAIL"}
                for observation in observations
            )
            or criterion.get("status")
            != (
                "PASS"
                if all(observation["status"] == "PASS" for observation in observations)
                else "FAIL"
            )
        ):
            raise ReviewError(
                "candidate acceptance criterion contradicts its observations"
            )
    failed = [
        criterion["id"] for criterion in criteria if criterion.get("status") == "FAIL"
    ]
    if acceptance.get("failed_criterion_ids") != failed or acceptance["status"] != (
        "PASS" if not failed else "FAIL"
    ):
        raise ReviewError(
            "candidate acceptance status contradicts its criterion results"
        )
    expected_release_gate = (
        "PASS" if acceptance["status"] == "PASS" else "NARROWED_REVIEW_REQUIRED"
    )
    if qualification.get("release_gate") != expected_release_gate:
        raise ReviewError("qualification release gate contradicts candidate acceptance")
    return manifest, qualification, acceptance


def copy_input(source: Path, destination: Path) -> Path:
    if not source.is_file() or source.is_symlink():
        raise ReviewError(f"closure input is missing or unsafe: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    return destination


def verify_sha256sums(root: Path) -> None:
    """Require SHA256SUMS to enumerate every other retained file exactly once."""

    expected = "".join(
        f"{row['sha256']}  {row['path']}\n"
        for row in artifact_rows(root, {"SHA256SUMS"})
    ).encode("utf-8")
    if (root / "SHA256SUMS").read_bytes() != expected:
        raise ReviewError("closure checksum inventory is incomplete or inconsistent")


def emit_closure_bundle(
    *,
    final_output: Path,
    retained_inputs: dict[str, Path],
    closure_summary: dict[str, Any],
    task_dispositions: dict[str, Any],
    local_convergence_schema: dict[str, Any],
    signing_key: Path,
    allowed_signers: Path,
) -> None:
    """Emit, verify, flush, and atomically publish the closure artifact graph."""

    expected_inputs = set(CONVERGENCE_ARTIFACT_PATHS) - {"closure-summary.json"}
    if set(retained_inputs) != expected_inputs:
        raise ReviewError("closure retained-input path set is not exact")
    candidate = closure_summary.get("candidate")
    if (
        not isinstance(candidate, dict)
        or set(candidate) != {"commit", "tree"}
        or not isinstance(candidate.get("commit"), str)
        or not isinstance(candidate.get("tree"), str)
    ):
        raise ReviewError("closure summary candidate is malformed")
    if os.path.lexists(final_output):
        raise ReviewError("refusing to replace an existing finalization output")

    final_output.parent.mkdir(parents=True, exist_ok=True)
    staging_output: Path | None = Path(
        tempfile.mkdtemp(
            prefix=f".{final_output.name}.staging-", dir=final_output.parent
        )
    )
    try:
        output = staging_output
        for relative in sorted(retained_inputs):
            copy_input(retained_inputs[relative], output / relative)
        (output / "closure-summary.json").write_bytes(canonical_json(closure_summary))

        convergence_document = build_local_convergence(
            commit=candidate["commit"],
            file_review=closure_summary.get("file_review", {}),
            task_dispositions=task_dispositions,
            artifacts=local_convergence_artifacts(output, CONVERGENCE_ARTIFACT_PATHS),
        )
        validate_local_convergence(
            convergence_document,
            schema=local_convergence_schema,
            expected_commit=candidate["commit"],
            artifact_root=output,
        )
        local_convergence_path = output / LOCAL_CONVERGENCE
        local_convergence_path.write_bytes(canonical_json(convergence_document))
        validate_local_convergence(
            loads_json(local_convergence_path.read_bytes()),
            schema=local_convergence_schema,
            expected_commit=candidate["commit"],
            artifact_root=output,
        )
        local_convergence_signature_path = sign_file(
            local_convergence_path,
            signing_key,
            LOCAL_CONVERGENCE_NAMESPACE,
        )
        verify_signature(
            local_convergence_path,
            local_convergence_signature_path,
            allowed_signers,
            LOCAL_CONVERGENCE_NAMESPACE,
        )

        closure_manifest_path = output / CLOSURE_MANIFEST
        closure_manifest_path.write_bytes(
            canonical_json(
                {
                    "schema": "galadriel.tiered-artifact-manifest.v1",
                    "tier": "closure",
                    "candidate": candidate,
                    "artifacts": artifact_rows(
                        output,
                        {
                            CLOSURE_MANIFEST,
                            CLOSURE_SIGNATURE,
                            "SHA256SUMS",
                        },
                    ),
                }
            )
        )
        closure_signature_path = sign_file(
            closure_manifest_path, signing_key, "galadriel-closure-manifest"
        )
        verify_signature(
            closure_manifest_path,
            closure_signature_path,
            allowed_signers,
            "galadriel-closure-manifest",
        )
        verify_artifact_manifest(
            output,
            closure_manifest_path,
            expected_schema="galadriel.tiered-artifact-manifest.v1",
            forbidden_paths={
                CLOSURE_MANIFEST,
                CLOSURE_SIGNATURE,
                "SHA256SUMS",
            },
        )

        with (output / "SHA256SUMS").open(
            "w", encoding="utf-8", newline="\n"
        ) as handle:
            for row in artifact_rows(output, {"SHA256SUMS"}):
                handle.write(f"{row['sha256']}  {row['path']}\n")
        verify_sha256sums(output)
        publish_staged_output(output, final_output)
        staging_output = None
    except PublicationDurabilityError:
        staging_output = None
        raise
    finally:
        if staging_output is not None:
            try:
                shutil.rmtree(staging_output)
            except OSError as error:
                warn_cleanup_failure(str(staging_output), error)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--qualification", required=True)
    parser.add_argument("--review-ledger", required=True)
    parser.add_argument("--task-dispositions", required=True)
    parser.add_argument("--task-dispositions-signature", required=True)
    parser.add_argument("--final-review", required=True)
    parser.add_argument("--final-review-signature", required=True)
    parser.add_argument("--decision-input", required=True)
    parser.add_argument("--decision-input-signature", required=True)
    parser.add_argument("--signing-key", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--snapshot-dir",
        help=(
            "existing external directory for the bounded qualification/input "
            "snapshot (allow up to 8 GiB plus review inputs)"
        ),
    )
    parser.add_argument("--require-branch", default="main")
    arguments = parser.parse_args()

    repo = Path(arguments.repo).resolve()
    qualification_root = absolute_path_without_final_resolution(arguments.qualification)
    review_ledger = absolute_path_without_final_resolution(arguments.review_ledger)
    task_dispositions_path = absolute_path_without_final_resolution(
        arguments.task_dispositions
    )
    task_dispositions_signature = absolute_path_without_final_resolution(
        arguments.task_dispositions_signature
    )
    final_review_path = absolute_path_without_final_resolution(arguments.final_review)
    final_review_signature = absolute_path_without_final_resolution(
        arguments.final_review_signature
    )
    decision_input_path = absolute_path_without_final_resolution(
        arguments.decision_input
    )
    decision_input_signature = absolute_path_without_final_resolution(
        arguments.decision_input_signature
    )
    signing_key_source = absolute_path_without_final_resolution(arguments.signing_key)
    final_output = absolute_path_without_final_resolution(arguments.out)
    snapshot_parent = (
        absolute_path_without_final_resolution(arguments.snapshot_dir)
        if arguments.snapshot_dir
        else None
    )

    input_temporary: tempfile.TemporaryDirectory[str] | None = None
    signing_key_snapshot: Path | None = None
    publication_committed = False
    try:
        if qualification_root.is_symlink() or not qualification_root.is_dir():
            raise ReviewError("qualification root is missing or unsafe")
        if (
            os.path.lexists(final_output)
            or final_output == repo
            or repo in final_output.parents
        ):
            raise ReviewError(
                "--out must be a new directory outside the candidate repository"
            )
        if (
            final_output == qualification_root
            or qualification_root in final_output.parents
        ):
            raise ReviewError("--out must be separate from the qualification tier")
        if snapshot_parent is not None:
            if snapshot_parent.is_symlink() or not snapshot_parent.is_dir():
                raise ReviewError(
                    "--snapshot-dir must be an existing regular directory"
                )
            snapshot_parent = snapshot_parent.resolve()
            if snapshot_parent == repo or repo in snapshot_parent.parents:
                raise ReviewError(
                    "--snapshot-dir must be outside the candidate repository"
                )
            if (
                snapshot_parent == qualification_root
                or qualification_root in snapshot_parent.parents
            ):
                raise ReviewError(
                    "--snapshot-dir must be outside the qualification tier"
                )
        input_temporary = tempfile.TemporaryDirectory(
            prefix="galadriel-finalization-inputs-",
            dir=snapshot_parent,
        )
        snapshots = Path(input_temporary.name)
        qualification_snapshot = snapshots / "qualification"
        qualification_snapshot.mkdir()
        qualification_manifest_snapshot = snapshot_input(
            qualification_root / QUALIFICATION_MANIFEST,
            qualification_snapshot / QUALIFICATION_MANIFEST,
            max_bytes=MAX_REVIEW_INPUT_BYTES,
            label="qualification manifest",
        )
        qualification_signature_snapshot = snapshot_input(
            qualification_root / QUALIFICATION_SIGNATURE,
            qualification_snapshot / QUALIFICATION_SIGNATURE,
            max_bytes=MAX_SIGNATURE_BYTES,
            label="qualification-manifest signature",
        )
        review_ledger = snapshot_input(
            review_ledger,
            snapshots / "FILE_REVIEW_LEDGER.completed.csv",
            max_bytes=MAX_REVIEW_INPUT_BYTES,
            label="completed file-review ledger",
        )
        task_dispositions_path = snapshot_input(
            task_dispositions_path,
            snapshots / "reviewed-task-dispositions.json",
            max_bytes=MAX_REVIEW_INPUT_BYTES,
            label="reviewed task dispositions",
        )
        task_dispositions_signature = snapshot_input(
            task_dispositions_signature,
            snapshots / "reviewed-task-dispositions.json.sig",
            max_bytes=MAX_SIGNATURE_BYTES,
            label="task-disposition signature",
        )
        final_review_path = snapshot_input(
            final_review_path,
            snapshots / "FINAL-TWENTY-LENS-REVIEW.json",
            max_bytes=MAX_REVIEW_INPUT_BYTES,
            label="final twenty-lens review",
        )
        final_review_signature = snapshot_input(
            final_review_signature,
            snapshots / "FINAL-TWENTY-LENS-REVIEW.json.sig",
            max_bytes=MAX_SIGNATURE_BYTES,
            label="final-review signature",
        )
        decision_input_path = snapshot_input(
            decision_input_path,
            snapshots / RELEASE_DECISION,
            max_bytes=MAX_REVIEW_INPUT_BYTES,
            label="release decision",
        )
        decision_input_signature = snapshot_input(
            decision_input_signature,
            snapshots / RELEASE_DECISION_SIGNATURE,
            max_bytes=MAX_SIGNATURE_BYTES,
            label="release-decision signature",
        )
        signing_key = snapshot_input(
            signing_key_source,
            snapshots / "SIGNING_KEY",
            max_bytes=MAX_SIGNING_KEY_BYTES,
            label="release signing key",
        )
        signing_key_snapshot = signing_key
        if str(git(repo, "status", "--porcelain=v1", "--untracked-files=all")).strip():
            raise ReviewError("finalization requires a clean candidate checkout")
        head = str(git(repo, "rev-parse", "HEAD^{commit}")).strip()
        if head != arguments.candidate:
            raise ReviewError(
                f"candidate mismatch: expected={arguments.candidate} actual={head}"
            )
        branch = str(git(repo, "branch", "--show-current")).strip()
        if arguments.require_branch and branch != arguments.require_branch:
            raise ReviewError(
                f"candidate branch must be {arguments.require_branch!r}, got {branch!r}"
            )
        allowed_signers = snapshots / "ALLOWED_SIGNERS"
        expected_signer_metadata = derive_external_allowed_signers(
            signing_key, allowed_signers
        )
        tracked_signer = snapshots / "TRACKED_ALLOWED_SIGNERS"
        tracked_signer.write_bytes(
            bytes(git(repo, "show", f"{head}:{ALLOWED_SIGNERS}", text=False))
        )
        assert_tracked_allowed_signer(tracked_signer, expected_signer_metadata)
        tree = verify_candidate_commit(repo, head, allowed_signers)

        plan = candidate_json(repo, head, PLAN)
        claims_document = candidate_json(repo, head, CLAIMS)
        tasks_document = candidate_json(repo, head, TASKS)
        local_convergence_schema = candidate_json(repo, head, LOCAL_CONVERGENCE_SCHEMA)
        validate_candidate_plan_documents(plan, tasks_document)
        validate_local_convergence_schema(local_convergence_schema)
        claims = {claim["id"]: claim for claim in claims_document.get("claims", [])}
        if len(claims) != len(claims_document.get("claims", [])):
            raise ReviewError("candidate claims matrix contains duplicate IDs")
        excluded_claim_ids = {
            claim_id
            for claim_id, claim in claims.items()
            if claim.get("tier") == "NOT_CLAIMED"
        }
        source_plan_sha256 = candidate_digest(repo, head, PLAN)

        snapshot_signed_qualification_tier(
            qualification_root,
            qualification_snapshot,
            manifest_path=qualification_manifest_snapshot,
            signature_path=qualification_signature_snapshot,
            allowed_signers=allowed_signers,
        )
        qualification_manifest, qualification, acceptance = verify_qualification(
            qualification_snapshot,
            repo=repo,
            allowed_signers=allowed_signers,
            commit=head,
            tree=tree,
            expected_evidence_config_sha256=candidate_digest(
                repo, head, "evidence/galadriel-0.9-candidate.json"
            ),
            recorded_root=qualification_root,
            manifest_path=qualification_manifest_snapshot,
            signature_path=qualification_signature_snapshot,
        )
        manifest_artifacts = {
            item["path"]: item for item in qualification_manifest["artifacts"]
        }
        source_ledger_relative = "source-inventory/FILE_REVIEW_LEDGER.csv"
        source_ledger = snapshot_input(
            qualification_snapshot / source_ledger_relative,
            snapshots / source_ledger_relative,
            max_bytes=MAX_REVIEW_INPUT_BYTES,
            label="qualification source-review ledger",
        )
        source_ledger_digest, source_ledger_size = digest_file(source_ledger)
        source_ledger_record = manifest_artifacts.get(source_ledger_relative)
        if source_ledger_record != {
            "path": source_ledger_relative,
            "sha256": source_ledger_digest,
            "size_bytes": source_ledger_size,
        }:
            raise ReviewError("qualification source-review ledger snapshot drifted")
        file_review = validate_completed_file_ledger(
            review_ledger,
            repo,
            head,
            source_ledger=source_ledger,
        )

        verify_signature(
            final_review_path,
            final_review_signature,
            allowed_signers,
            "galadriel-final-review",
        )
        final_review = load_canonical_object(
            final_review_path, "final twenty-lens review"
        )
        final_review_summary = validate_final_twenty_lens_review(
            final_review,
            lens_catalog=plan["lens_catalog"],
            repo=repo,
            commit=head,
            tree=tree,
            qualification_root=qualification_snapshot,
        )

        required_qualification_commands = {
            name: qualification_command(qualification, name)
            for name in (
                "release-tool-tests",
                "local-convergence-schema",
                "feature-graph-contract",
            )
        }
        qualification_logs = {
            str(command["log"]) for command in required_qualification_commands.values()
        }
        feature_graph_command = required_qualification_commands[
            "feature-graph-contract"
        ]

        verify_signature(
            decision_input_path,
            decision_input_signature,
            allowed_signers,
            "galadriel-release-decision",
        )
        decision_input = load_canonical_object(decision_input_path, "release decision")
        expected_decision_bindings = {
            "reconciliation_status": "LOCAL_PIN_PASS",
            "source_plan_sha256": source_plan_sha256,
            "claims_sha256": candidate_digest(repo, head, CLAIMS),
            "qualification_manifest_sha256": digest_file(
                qualification_manifest_snapshot
            )[0],
            "feature_graph_log_sha256": feature_graph_command["log_sha256"],
            "completed_file_review_ledger_sha256": digest_file(review_ledger)[0],
            "final_twenty_lens_review_sha256": digest_file(final_review_path)[0],
            "final_twenty_lens_review_signature_sha256": digest_file(
                final_review_signature
            )[0],
        }
        validate_decision_input(
            decision_input,
            acceptance=acceptance,
            excluded_claim_ids=excluded_claim_ids,
            expected_candidate={"commit": head, "tree": tree},
            expected_bindings=expected_decision_bindings,
        )
        if set(decision_input["removed_claim_ids"]) != excluded_claim_ids:
            raise ReviewError(
                "release decision must acknowledge every excluded public claim"
            )

        verify_signature(
            task_dispositions_path,
            task_dispositions_signature,
            allowed_signers,
            "galadriel-task-dispositions",
        )
        task_dispositions = load_canonical_object(
            task_dispositions_path, "reviewed task dispositions"
        )
        review_inputs = {
            "inputs/FINAL-TWENTY-LENS-REVIEW.json": final_review_path,
            "inputs/FINAL-TWENTY-LENS-REVIEW.json.sig": final_review_signature,
            RELEASE_DECISION: decision_input_path,
            RELEASE_DECISION_SIGNATURE: decision_input_signature,
        }
        task_counts = validate_reviewed_task_dispositions(
            task_dispositions,
            plan=plan,
            claims=claims,
            repo=repo,
            commit=head,
            tree=tree,
            qualification_root=qualification_snapshot,
            source_plan_sha256=source_plan_sha256,
            review_inputs=review_inputs,
        )
        validate_finalization_dag_evidence(
            task_dispositions,
            final_review,
            qualification_logs=qualification_logs,
        )
        task_removed = {
            claim_id
            for disposition in task_dispositions["dispositions"]
            for claim_id in disposition["removed_claim_ids"]
        }
        if not task_removed.issubset(set(decision_input["removed_claim_ids"])):
            raise ReviewError(
                "release decision omits claims removed by task dispositions"
            )

        closure_summary = {
            "schema": "galadriel.exact-candidate-closure.v1",
            "release": VERSION,
            "author": AUTHOR,
            "candidate": {"commit": head, "tree": tree},
            "qualification": {
                "manifest_sha256": digest_file(qualification_manifest_snapshot)[0],
                "manifest_signature_sha256": digest_file(
                    qualification_signature_snapshot
                )[0],
                "command_status": qualification["command_status"],
                "acceptance_status": acceptance["status"],
                "failed_criterion_ids": acceptance["failed_criterion_ids"],
            },
            "file_review": file_review,
            "task_dispositions": task_counts,
            "final_review": final_review_summary,
            "release_decision": {
                "decision": decision_input["decision"],
                "reconciliation_status": decision_input["bindings"][
                    "reconciliation_status"
                ],
                "sha256": digest_file(decision_input_path)[0],
                "signature_sha256": digest_file(decision_input_signature)[0],
            },
            "source_task_ledger_sha256": plan["source_task_ledger_sha256"],
            "source_plan_sha256": source_plan_sha256,
        }
        emit_closure_bundle(
            final_output=final_output,
            retained_inputs={
                "inputs/FILE_REVIEW_LEDGER.completed.csv": review_ledger,
                "inputs/reviewed-task-dispositions.json": task_dispositions_path,
                "inputs/reviewed-task-dispositions.json.sig": (
                    task_dispositions_signature
                ),
                "inputs/FINAL-TWENTY-LENS-REVIEW.json": final_review_path,
                "inputs/FINAL-TWENTY-LENS-REVIEW.json.sig": final_review_signature,
                RELEASE_DECISION: decision_input_path,
                RELEASE_DECISION_SIGNATURE: decision_input_signature,
            },
            closure_summary=closure_summary,
            task_dispositions=task_dispositions,
            local_convergence_schema=local_convergence_schema,
            signing_key=signing_key,
            allowed_signers=allowed_signers,
        )
        publication_committed = True
        result = {
            "candidate": head,
            "tree": tree,
            "decision": decision_input["decision"],
            "closed_tasks": task_counts["total"],
            "reviewed_files": file_review["reviewed_files"],
            "acceptance": acceptance["status"],
            "output": str(final_output),
        }
        cleanup_status = 0
        if input_temporary is not None:
            cleanup_status = postpublication_cleanup_status(
                input_temporary, signing_key_snapshot
            )
            input_temporary = None
            signing_key_snapshot = None
        return emit_publication_result(result, cleanup_status)
    except PublicationDurabilityError as error:
        print(f"release finalization durability warning: {error}", file=sys.stderr)
        return 3
    except (
        AttributeError,
        KeyError,
        OSError,
        RecursionError,
        ReviewError,
        TypeError,
        ValueError,
    ) as error:
        if publication_committed:
            print(
                "release finalization reporting failed after complete publication: "
                f"{error}",
                file=sys.stderr,
            )
            return 3
        print(f"release finalization failed: {error}", file=sys.stderr)
        return 2
    finally:
        if input_temporary is not None:
            cleanup_finalization_inputs(input_temporary, signing_key_snapshot)


if __name__ == "__main__":
    raise SystemExit(main())
