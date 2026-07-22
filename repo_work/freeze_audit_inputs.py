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
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

from common import ReviewError, canonical_json, git, load_json, loads_json


SCHEMA = "galadriel.frozen-audit-inputs.v1"
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
    "release/0.9.0/VERSION-ADAPTATION.md",
    "release/0.9.0/claims.json",
    "release/0.9.0/audit/threat-register.json",
    "release/0.9.0/evidence/ACCEPTANCE-CRITERIA.md",
    "release/0.9.0/reviews/REVIEW-METHOD.md",
    "release/0.9.0/reviews/REVIEW-COMMENTS.md",
    "release/0.9.0/api/galadriel-core.baseline.txt",
    "release/0.9.0/api/galadriel-core.0.9.0.txt",
    "release/0.9.0/api/galadriel-pid.0.9.0.txt",
    "release/0.9.0/evidence/galadriel-core-api.diff",
    "evidence/galadriel-0.9-candidate.json",
    "crates/galadriel-ncp/tests/fixtures/crebain_clean_capture.jsonl",
    "CITATION.cff",
    "RELEASE-POLICY.md",
    "SECURITY.md",
    "docs/ADVISORY-BOUNDARY.md",
    "docs/CLAIMS.md",
    "docs/CONFIGURATION-CONTRACT.md",
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
    "repo_work/qualify_candidate.py",
    "repo_work/release_assurance.py",
    "repo_work/reproduce_baseline.py",
    "repo_work/scan_claim_language.py",
    "repo_work/tests/test_package_release_assets.py",
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
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ReviewError(f"{label} is missing or not regular: {path}")
        if metadata.st_size > max_bytes:
            raise ReviewError(f"{label} exceeds the {limit_label} limit")
        data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ReviewError(f"{label} exceeds the {limit_label} limit")
        if len(data) != metadata.st_size:
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
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ReviewError(
                f"handoff path is not a contained regular file: {relative}"
            )
        if metadata.st_size > MAX_HANDOFF_FILE_BYTES:
            raise ReviewError(
                f"handoff regular file exceeds the per-file byte limit: {relative}"
            )
        if aggregate_size + metadata.st_size > MAX_HANDOFF_AGGREGATE_BYTES:
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
        if size != metadata.st_size:
            raise ReviewError(f"handoff regular file changed while read: {relative}")
        return digest.hexdigest(), size


def assert_release_tool_coverage(repo: Path) -> None:
    """Reject an unenumerated tracked release-tool source or test."""

    raw = bytes(
        git(
            repo,
            "ls-files",
            "-z",
            "--",
            "repo_work",
            "scripts",
            text=False,
        )
    )
    tracked = {
        path.decode("utf-8", "surrogateescape") for path in raw.split(b"\0") if path
    }
    declared = set(RELEASE_INPUTS)
    missing = sorted(tracked - declared)
    if missing:
        raise ReviewError(
            "tracked release-tool paths are absent from the frozen input set: "
            + ", ".join(missing)
        )


def git_blob(repo: Path, commit: str, relative: str) -> bytes:
    process = subprocess.run(
        ["git", "-C", str(repo), "show", f"{commit}:{relative}"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        raise ReviewError(
            f"cannot read {relative} from {commit}: "
            + process.stderr.decode("utf-8", "replace").strip()
        )
    return process.stdout


def strict_relative_files(root: Path) -> list[dict[str, Any]]:
    """Inventory every supplied path without following symlinks."""

    if root.is_symlink() or not root.is_dir():
        raise ReviewError(f"handoff root is not a regular directory: {root}")
    resolved_root = root.resolve()
    rows: list[dict[str, Any]] = []
    entry_count = 0
    aggregate_size = 0

    def symlink_target_bytes(target: str, relative: str) -> bytes:
        try:
            return target.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ReviewError(
                f"handoff symlink target is not valid UTF-8: {relative}"
            ) from error

    def fail_walk(error: OSError) -> None:
        detail = error.strerror or str(error)
        location = error.filename or str(root)
        raise ReviewError(
            f"cannot completely inventory handoff path {location}: {detail}"
        ) from error

    for directory, names, files in os.walk(root, followlinks=False, onerror=fail_walk):
        entry_count += len(names) + len(files)
        if entry_count > MAX_HANDOFF_ENTRIES:
            raise ReviewError("handoff inventory exceeds the entry-count limit")
        names.sort()
        files.sort()
        base = Path(directory)
        # ``os.walk(..., followlinks=False)`` does not descend through directory
        # symlinks, but it still places them in ``names``. Record and remove them
        # explicitly so the manifest covers every supplied directory entry.
        for name in list(names):
            path = base / name
            if not path.is_symlink():
                continue
            names.remove(name)
            target = os.readlink(path)
            relative = path.relative_to(root).as_posix()
            encoded = symlink_target_bytes(target, relative)
            if len(encoded) > MAX_HANDOFF_SYMLINK_BYTES:
                raise ReviewError(
                    f"handoff symlink target exceeds the byte limit: {relative}"
                )
            if aggregate_size + len(encoded) > MAX_HANDOFF_AGGREGATE_BYTES:
                raise ReviewError("handoff inventory exceeds the aggregate byte limit")
            rows.append(
                {
                    "path": relative,
                    "kind": "symlink",
                    "target": target,
                    "sha256": digest_bytes(encoded),
                    "size_bytes": len(encoded),
                }
            )
            aggregate_size += len(encoded)
        for name in files:
            path = base / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                target = os.readlink(path)
                encoded = symlink_target_bytes(target, relative)
                if len(encoded) > MAX_HANDOFF_SYMLINK_BYTES:
                    raise ReviewError(
                        f"handoff symlink target exceeds the byte limit: {relative}"
                    )
                if aggregate_size + len(encoded) > MAX_HANDOFF_AGGREGATE_BYTES:
                    raise ReviewError(
                        "handoff inventory exceeds the aggregate byte limit"
                    )
                rows.append(
                    {
                        "path": relative,
                        "kind": "symlink",
                        "target": target,
                        "sha256": digest_bytes(encoded),
                        "size_bytes": len(encoded),
                    }
                )
                aggregate_size += len(encoded)
                continue
            resolved = path.resolve()
            if resolved_root not in resolved.parents or not path.is_file():
                raise ReviewError(
                    f"handoff path is not a contained regular file: {relative}"
                )
            digest, size = digest_bounded_handoff_file(path, relative, aggregate_size)
            rows.append(
                {
                    "path": relative,
                    "kind": "regular",
                    "sha256": digest,
                    "size_bytes": size,
                }
            )
            aggregate_size += size
    if not rows:
        raise ReviewError("handoff root contains no files")
    return rows


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
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    """Load and validate the two repository documents that bind the freeze."""

    handoff_source = exact_object(
        load_json(repo / "release/0.9.0/handoff-source.json"),
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
    for key in ("prepared", "repository", "master_package", "provenance_note"):
        exact_string(handoff_source[key], f"handoff source {key}")
    child_archive = safe_relative_path(
        handoff_source["child_archive"], "handoff source child_archive"
    )
    if len(Path(child_archive).parts) != 1 or not child_archive.endswith(".zip"):
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
        load_json(repo / "release/0.9.0/audit-inputs.json"),
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
        "release audit inputs",
    )
    if audit_inputs["schema"] != "galadriel.release-audit-inputs.v1":
        raise ReviewError(
            "release audit input schema is not galadriel.release-audit-inputs.v1"
        )
    audit_release = exact_object(
        audit_inputs["release"],
        {"name", "version", "author", "doi", "zenodo", "publication_channel"},
        "release audit identity",
    )
    expected_audit_release = {
        "name": "Galadriel's Mirror",
        **RELEASE,
        "publication_channel": "GitHub source release",
    }
    if audit_release != expected_audit_release:
        raise ReviewError(
            "release audit identity must name release 0.9.0 with the expected author "
            "and null DOI/Zenodo fields"
        )
    exact_string(audit_inputs["audit_date"], "release audit date")
    for key in ("repositories", "toolchains", "github_actions", "artifact_sets"):
        exact_list(audit_inputs[key], f"release audit inputs {key}")
    exact_object(
        audit_inputs["external_sources"],
        {"scan_patterns", "declared"},
        "external sources",
    )
    safe_relative_path(
        audit_inputs["adaptation_decision"], "release audit adaptation_decision"
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


def release_input_manifest(repo: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    resolved_repo = repo.resolve()
    if len(RELEASE_INPUTS) != len(set(RELEASE_INPUTS)):
        raise ReviewError("RELEASE_INPUTS contains a duplicate path")
    for relative in RELEASE_INPUTS:
        safe_relative_path(relative, "declared release input path")
        path = repo / relative
        if path.is_symlink() or not path.is_file():
            raise ReviewError(
                f"release audit input is missing or not regular: {relative}"
            )
        resolved = path.resolve()
        if resolved_repo not in resolved.parents:
            raise ReviewError(f"release audit input escapes the repository: {relative}")
        digest, size = digest_file(path)
        rows.append({"path": relative, "sha256": digest, "size_bytes": size})
    return rows


def validate_handoff_rows(value: Any) -> list[dict[str, Any]]:
    rows = exact_list(value, "handoff files")
    if not rows:
        raise ReviewError("handoff files must not be empty")
    if len(rows) > MAX_HANDOFF_ENTRIES:
        raise ReviewError("handoff inventory exceeds the entry-count limit")
    seen: set[str] = set()
    validated: list[dict[str, Any]] = []
    aggregate_size = 0
    for index, raw_row in enumerate(rows):
        label = f"handoff file {index}"
        if type(raw_row) is not dict:
            raise ReviewError(f"{label} must be a JSON object")
        kind = raw_row.get("kind")
        keys = {"path", "kind", "sha256", "size_bytes"}
        if kind == "symlink":
            keys.add("target")
        elif kind != "regular":
            raise ReviewError(f"{label} has an unsupported kind")
        row = exact_object(raw_row, keys, label)
        relative = safe_relative_path(row["path"], f"{label} path")
        if relative in seen:
            raise ReviewError(f"handoff file path is duplicated: {relative}")
        seen.add(relative)
        exact_digest(row["sha256"], f"{label} sha256")
        size = exact_integer(row["size_bytes"], f"{label} size_bytes")
        if kind == "regular" and size > MAX_HANDOFF_FILE_BYTES:
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
    if (
        Path(root_name).name != root_name
        or root_name != handoff_source["master_package"]
    ):
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
    if any(character in origin for character in "\r\n\0"):
        raise ReviewError("historical origin contains a control separator")
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
        check = subprocess.run(
            ["git", "check-ref-format", refname],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
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
    process = subprocess.run(
        ["ssh-keygen", "-lf", "-", "-E", "sha256"],
        input=allowed_signer_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", "replace").strip()
        raise ReviewError(f"cannot fingerprint allowed signer: {detail}")
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
        process = subprocess.run(
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
            input=manifest_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", "replace").strip()
        raise ReviewError(f"frozen audit-input signature verification failed: {detail}")
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

    assert_release_tool_coverage(repo)
    handoff_source, audit_inputs, baseline_commit, declared_tree = (
        validate_source_documents(repo)
    )
    baseline = baseline_manifest(repo, baseline_commit, declared_tree)
    baseline["repository"] = audit_inputs["baseline_repository"]["url"]
    release_files = release_input_manifest(repo)
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
            "origin": str(git(repo, "remote", "get-url", "origin")).strip(),
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
        if signer_created:
            allowed_signers.unlink(missing_ok=True)
        if output_created:
            output.unlink(missing_ok=True)
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

    assert_release_tool_coverage(repo)
    handoff_source, audit_inputs, baseline_commit, declared_tree = (
        validate_source_documents(repo)
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
        exact_object(row, {"path", "sha256", "size_bytes"}, f"release input {index}")
    if release_inputs != release_input_manifest(repo):
        raise ReviewError(
            "release input files are not the exact ordered current RELEASE_INPUTS set"
        )

    validate_handoff_manifest(root["handoff"], handoff_source, handoff_root)
    validate_repository_ref_inputs(root["repository_ref_inputs"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action", nargs="?", choices=("generate", "verify"), default="generate"
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
        else:
            verify_frozen_inputs(repo, handoff_root, output, allowed_signers)
            print(f"FROZEN_AUDIT_INPUTS_OK {output}")
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
