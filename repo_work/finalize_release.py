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
import datetime as dt
import errno
import hashlib
import json
import math
import os
import re
import shutil
import stat
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from common import (
    SAFE_GIT_CONFIGURATION,
    ReviewError,
    absolute_path_without_final_resolution,
    canonical_json,
    git,
    git_bounded_output,
    load_json,
    loads_json,
    validate_json_structure,
)
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
from qualification_artifacts import (
    CARGO_DENY_HOST_FILTERED_SCOPE,
    MAX_CRATE_ARCHIVE_BYTES,
    MAX_LICENSE_REPORT_BYTES,
    MAX_LOCKFILE_BYTES,
    MAX_SBOM_BYTES,
    validate_cargo_deny_license_inventory,
    validate_cargo_deny_license_policy_jsonl,
    validate_cargo_graph_paths,
    validate_cargo_metadata,
    validate_crate_archive,
    validate_cyclonedx_sbom,
)
from qualify_candidate import (
    BASE_COMMANDS,
    DEPENDENCY_FETCH_COMMAND_NAMES,
    DEEP_COMMANDS,
    GIT_ARCHIVE_GLOBAL_ARGS,
    QUALIFICATION_PATH_TOOLS,
    SANDBOX_SYSTEM_READ_PATHS,
    CommandSpec,
    execution_policy_contract,
    external_input_path,
    qualification_environment_contract,
    render_candidate_sandbox_profile,
    repository_control_snapshot,
    verify_source_archive,
)
from release_assurance import (
    AUTHOR,
    VERSION,
    assert_no_replace_refs,
    assert_tracked_allowed_signer,
    digest_file,
    evaluate_acceptance,
    refresh_canonical_origin_main,
    sign_file,
    snapshot_agent_backed_public_signing_key,
    snapshot_independent_allowed_signers,
    validate_completed_file_ledger,
    validate_decision_input,
    validate_evidence_config_bytes,
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
MAX_QUALIFICATION_JSON_BYTES = 64 * 1024 * 1024
MAX_QUALIFICATION_REPORT_BYTES = 16 * 1024 * 1024
MAX_QUALIFICATION_LOG_HEADER_BYTES = 1024 * 1024
MAX_QUALIFICATION_JSON_DEPTH = 256
MAX_QUALIFICATION_JSON_NODES = 2_000_000
MAX_QUALIFICATION_EXECUTABLE_BYTES = 1024 * 1024 * 1024
MAX_CANDIDATE_CRATE_TREE_LIST_BYTES = 4 * 1024 * 1024
MAX_CANDIDATE_CRATE_MEMBER_BYTES = 64 * 1024 * 1024
MAX_CANDIDATE_CRATE_TREE_BYTES = 256 * 1024 * 1024
MAX_CANDIDATE_CRATE_MEMBERS = 4094
CANONICAL_REPOSITORY = "https://github.com/sepahead/galadriel"
RELEASE_BRANCH = "main"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
RUSTSEC_ADVISORY_DATABASE = {
    "url": "https://github.com/RustSec/advisory-db",
    "commit": "f981d991604f3e7d4a0eb94e559cb3e5a94a6dc2",
    "tree": "26bea0ac10667f826b5522a828a27861ae4b5287",
    "inventory_sha256": "bfc26634ed164598c75c91fc462f0fa527b73634859faeb9476f2631bf529619",
    "entries": 1187,
    "fetch_policy": "PINNED_OFFLINE_NO_FETCH",
}
EXPECTED_ADVISORY_WARNINGS = (
    ("RUSTSEC-2024-0436", "paste", "1.0.15"),
    ("RUSTSEC-2025-0134", "rustls-pemfile", "2.2.0"),
)
IGNORED_ADVISORY = "RUSTSEC-2026-0041"
EXPECTED_TOOL_FILE_NAMES = frozenset(
    {
        *QUALIFICATION_PATH_TOOLS,
        "sandbox-exec",
        "rustc-1.89.0",
        "cargo-1.89.0",
        "rustc-1.97.1",
        "cargo-1.97.1",
        "rustc-nightly-2026-06-16",
        "cargo-nightly-2026-06-16",
        "rustdoc-nightly-2026-06-16",
        "rustdoc-1.89.0",
        "rustfmt-1.89.0",
        "clippy-driver-1.89.0",
        "rustdoc-1.97.1",
        "clippy-driver-1.97.1",
    }
)
TOOL_FILE_BASENAMES = {
    **{name: name for name in QUALIFICATION_PATH_TOOLS},
    "sandbox-exec": "sandbox-exec",
    "rustc-1.89.0": "rustc",
    "cargo-1.89.0": "cargo",
    "rustc-1.97.1": "rustc",
    "cargo-1.97.1": "cargo",
    "rustc-nightly-2026-06-16": "rustc",
    "cargo-nightly-2026-06-16": "cargo",
    "rustdoc-nightly-2026-06-16": "rustdoc",
    "rustdoc-1.89.0": "rustdoc",
    "rustfmt-1.89.0": "rustfmt",
    "clippy-driver-1.89.0": "clippy-driver",
    "rustdoc-1.97.1": "rustdoc",
    "clippy-driver-1.97.1": "clippy-driver",
}
EXPECTED_TOOL_FILE_IDENTITIES = {
    "ar": ("179301dcb41ea78accc3fa0048a7e6f6710d891945a751a34addd622020c1818", 118928),
    "cargo": (
        "b7a341737d8777ef0e21a71f0af90723ccf692914255110c12bbcfed79d75a53",
        31259808,
    ),
    "cargo-1.89.0": (
        "798a97c06e6fc3a63f1b7e3141f87e515e6bc8da1527bc32e19ba27d86bb89c5",
        28655992,
    ),
    "cargo-1.97.1": (
        "7672ead309d505577c018fff2cafb3433601f073e38cbe87359ac1f7b944bbf5",
        31867672,
    ),
    "cargo-audit": (
        "960c4464e6f6c8f793c00f9c68528d03fcbe4b6391591020ecd581a570510f28",
        19790224,
    ),
    "cargo-cyclonedx": (
        "1284e72c28b61d59f3b2ae8863e6e793e511b6e9dcac76dc8f87427ef8343c39",
        6003488,
    ),
    "cargo-deny": (
        "69ae1960301a8bc649a2e9ef0d1e164e12c3b0b6a1d4d0c072b52741c88e35b7",
        7505744,
    ),
    "cargo-fuzz": (
        "602ad1fc84bab09d49a042d24979252308225cf6fcfa9ef2b14a2c23be72fe79",
        2146320,
    ),
    "cargo-nightly-2026-06-16": (
        "a47b73abeea12086b8e00cfc90d37c71228084a927518c9fbb95283e3521f3c8",
        31932056,
    ),
    "cargo-public-api": (
        "acdc7b1733d52476fc2ce456a2a0292b82c367566fe0d2ab15c12b99974c8d24",
        5550016,
    ),
    "cc": ("179301dcb41ea78accc3fa0048a7e6f6710d891945a751a34addd622020c1818", 118928),
    "clang": (
        "179301dcb41ea78accc3fa0048a7e6f6710d891945a751a34addd622020c1818",
        118928,
    ),
    "clippy-driver-1.89.0": (
        "d96c5d7a8e3fbb6920ade89d389f96d19003f654c75d96383d7b2fb21b883ab8",
        12354144,
    ),
    "clippy-driver-1.97.1": (
        "ca34521c9c61e5570ad5f07b303b00fbb60756fedcb62b9f1529f85971256ecf",
        15071424,
    ),
    "cmake": (
        "b2655889a98005e8ae79785c3e9b2c2db4db341ff47223095b04e95ff4654ef7",
        17732864,
    ),
    "git": ("179301dcb41ea78accc3fa0048a7e6f6710d891945a751a34addd622020c1818", 118928),
    "ld": ("179301dcb41ea78accc3fa0048a7e6f6710d891945a751a34addd622020c1818", 118928),
    "make": (
        "179301dcb41ea78accc3fa0048a7e6f6710d891945a751a34addd622020c1818",
        118928,
    ),
    "pkg-config": (
        "d1c437b9ad16182ee781175ae4e69b439a91c6c6747a7cd50f878514212730e4",
        74928,
    ),
    "python3": (
        "179301dcb41ea78accc3fa0048a7e6f6710d891945a751a34addd622020c1818",
        118928,
    ),
    "rustc": (
        "d69d40bfd2e11825feb3538512b6ffcd63de91c35ec36bb876849f0f9f8fe6bd",
        343600,
    ),
    "rustc-1.89.0": (
        "af4a9eb303553510e9d74220636dc4b21f8574ddeab73741bf6b892adc49c21c",
        414776,
    ),
    "rustc-1.97.1": (
        "210df6794001b73ec3d453878707fa1e0bdcb63c427024a6e6574bbe5615a4da",
        412504,
    ),
    "rustc-nightly-2026-06-16": (
        "b2ec2c1e93a877b3f0b5a6e1db96d5dac62a8ab4c2393fb7129b87a0deae3914",
        412504,
    ),
    "rustdoc-1.89.0": (
        "1e65fe1796464bbe73ee53231852d8a779f144e8825c2711819435e0aad2213e",
        11456472,
    ),
    "rustdoc-1.97.1": (
        "aa94960b6a477441f6d1a797394daf4cafcc889d837550c8fa462b102e3fa5da",
        12021256,
    ),
    "rustdoc-nightly-2026-06-16": (
        "02c28afca87ce40e5a352b788c975d239f57801b8af4184a43e22fccc92ac1e5",
        12091128,
    ),
    "rustfmt-1.89.0": (
        "a5127950ba832ec4a5ab8701f0e06dbae675271812c7462fd55d0ff5b1a07093",
        5119048,
    ),
    "rustup": (
        "aeb4105778ca1bd3c6b0e75768f581c656633cd51368fa61289b6a71696ac7e1",
        11053296,
    ),
    "sandbox-exec": (
        "8857d087219f0f39d3e3c163e5d0a0aed690cc22f34b50c7eee3d74f93e69688",
        102560,
    ),
    "ssh-keygen": (
        "bddae9c4ea46fd903574ec6ff61eda75e133f940fa538f2adca80af474767596",
        849024,
    ),
}
FROZEN_COMMAND_ARGUMENTS = {
    "fetch-locked-dependencies": ("cargo", "fetch", "--locked"),
    "fetch-locked-fuzz-dependencies": (
        "cargo",
        "fetch",
        "--locked",
        "--manifest-path",
        "fuzz/Cargo.toml",
    ),
    "format": ("cargo", "fmt", "--all", "--check"),
    "pure-core-no-default-test": (
        "cargo",
        "test",
        "-p",
        "galadriel-core",
        "--no-default-features",
        "--locked",
    ),
    "pure-core-no-default-build": (
        "cargo",
        "build",
        "-p",
        "galadriel-core",
        "--no-default-features",
        "--locked",
    ),
    "dependency-policy-workspace": (
        "cargo",
        "deny",
        "--offline",
        "--all-features",
        "--locked",
        "check",
    ),
    "dependency-policy-fuzz": (
        "cargo",
        "deny",
        "--offline",
        "--manifest-path",
        "fuzz/Cargo.toml",
        "--all-features",
        "--locked",
        "check",
        "--config",
        "fuzz/deny.toml",
    ),
    "cargo-audit": (
        "cargo",
        "audit",
        "--no-fetch",
        "--stale",
        "--no-yanked",
        "--ignore",
        IGNORED_ADVISORY,
        "--format",
        "json",
    ),
}
FROZEN_QUALIFICATION_COMMAND_NAMES = (
    "verify-commit-signature-external-key",
    "tracked-source-inventory",
    "review-packets",
    "claim-language-inventory",
    "git-fsck-strict",
    "release-tool-tests",
    "secure-deployment-check",
    "task-dispositions-verify",
    "local-convergence-schema",
    "frozen-audit-inputs-verify",
    "release-audit-verify",
    "fetch-locked-dependencies",
    "fetch-locked-fuzz-dependencies",
    "format",
    "feature-graph-contract",
    "cli-pure-feature-graph",
    "cli-pid-feature-graph",
    "cli-ncp-feature-graph",
    "cli-ncp-live-feature-graph",
    "clippy-all-targets-features",
    "clippy-production-no-unwrap-expect-panic",
    "tests-all-features",
    "docs-all-features",
    "pure-core-no-default-test",
    "pure-core-no-default-build",
    "core-release-tests",
    "pid-release-tests",
    "evaluation-benchmark-build",
    "current-stable-clippy",
    "current-stable-tests",
    "dependency-policy-workspace",
    "vulnerable-feature-assertion",
    "dependency-policy-fuzz",
    "cargo-audit",
    "public-api-snapshots",
    "candidate-evidence",
    "fuzz-ncp-decode-5000",
    "fuzz-detector-boundaries-5000",
)
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
FROZEN_FOCUSED_MUTATION_CHECK_IDS = (
    "delivery-boundary-state",
    "delivery-boundary-guards",
    "acceptance-evidence-estimation",
)
FROZEN_MUTATION_ARTIFACT_COUNT = 13
EXPECTED_RELEASE_CRATES = (
    "galadriel-cli",
    "galadriel-core",
    "galadriel-eval",
    "galadriel-justify",
    "galadriel-ncp",
    "galadriel-pid",
    "galadriel-sim",
)
EXPECTED_GIT_PACKAGE_SOURCES = {
    "ncp-core": (
        "git+https://github.com/sepahead/NCP"
        "?rev=2f5bd586d4bb20c90362bb6f5698b7f64057ba4e"
        "#2f5bd586d4bb20c90362bb6f5698b7f64057ba4e"
    ),
    "ncp-zenoh": (
        "git+https://github.com/sepahead/NCP"
        "?rev=2f5bd586d4bb20c90362bb6f5698b7f64057ba4e"
        "#2f5bd586d4bb20c90362bb6f5698b7f64057ba4e"
    ),
    "pid-core": (
        "git+https://github.com/sepahead/pid-rs"
        "?rev=1cd2424f7967e1752dcc8e53859e8fdad3566f51"
        "#1cd2424f7967e1752dcc8e53859e8fdad3566f51"
    ),
    "pid-runlog": (
        "git+https://github.com/sepahead/pid-rs"
        "?rev=1cd2424f7967e1752dcc8e53859e8fdad3566f51"
        "#1cd2424f7967e1752dcc8e53859e8fdad3566f51"
    ),
}
EXPECTED_QUALIFICATION_TOOLS = {
    "git": "git version 2.50.1 (Apple Git-155)",
    "rustc": """rustc 1.89.0 (29483883e 2025-08-04)
binary: rustc
commit-hash: 29483883eed69d5fb4db01964cdf2af4d86e9cb2
commit-date: 2025-08-04
host: aarch64-apple-darwin
release: 1.89.0
LLVM version: 20.1.7""",
    "cargo": """cargo 1.89.0 (c24e10642 2025-06-23)
release: 1.89.0
commit-hash: c24e1064277fe51ab72011e2612e556ac56addf7
commit-date: 2025-06-23
host: aarch64-apple-darwin
libgit2: 1.9.0 (sys:0.20.2 vendored)
libcurl: 8.7.1 (sys:0.4.80+curl-8.12.1 system ssl:(SecureTransport) LibreSSL/3.3.6)
ssl: OpenSSL 3.5.0 8 Apr 2025
os: Mac OS 26.5.1 [64-bit]""",
    "rustc_current_stable": """rustc 1.97.1 (8bab26f4f 2026-07-14)
binary: rustc
commit-hash: 8bab26f4f68e0e26f0bb7960be334d5b520ea452
commit-date: 2026-07-14
host: aarch64-apple-darwin
release: 1.97.1
LLVM version: 22.1.6""",
    "cargo_current_stable": """cargo 1.97.1 (c980f4866 2026-06-30)
release: 1.97.1
commit-hash: c980f4866141969fab6254a680546a277789d6f0
commit-date: 2026-06-30
host: aarch64-apple-darwin
libgit2: 1.9.2 (sys:0.20.4 vendored)
libcurl: 8.7.1 (sys:0.4.88+curl-8.20.0 system ssl:(SecureTransport) LibreSSL/3.3.6)
ssl: OpenSSL 3.6.2 7 Apr 2026
os: Mac OS 26.5.1 [64-bit]""",
    "rustc_fuzz_nightly": """rustc 1.98.0-nightly (01dfd7924 2026-06-15)
binary: rustc
commit-hash: 01dfd79246f1b2d5f146616deff08223a840a9ae
commit-date: 2026-06-15
host: aarch64-apple-darwin
release: 1.98.0-nightly
LLVM version: 22.1.7""",
    "python": "Python 3.14.6",
    "cargo_deny": "cargo-deny 0.19.9",
    "cargo_audit": "cargo-audit-audit 0.22.2",
    "cargo_cyclonedx": "cargo-cyclonedx-cyclonedx 0.5.9",
    "cargo_public_api": "cargo-public-api 0.52.0",
    "cargo_fuzz": "cargo-fuzz 0.13.2",
}


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
    """Invalidate the PASS snapshot and remove all snapshotted inputs."""

    failures: list[tuple[str, OSError]] = []
    qualification_record = Path(temporary.name) / "qualification" / "qualification.json"
    try:
        qualification_record.unlink(missing_ok=True)
    except OSError as error:
        failures.append((str(qualification_record), error))
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


def finalization_signing_key_source(
    value: str,
    *,
    repo: Path,
    qualification_root: Path,
    final_output: Path,
    snapshot_parent: Path | None,
) -> Path:
    """Require an external public signing-key handle in a disjoint location."""

    repo = repo.resolve()
    source = external_input_path(
        value,
        repo=repo,
        label="signing-key public handle",
    )
    qualification_root = qualification_root.resolve()
    final_output = final_output.parent.resolve() / final_output.name
    if snapshot_parent is not None:
        snapshot_parent = snapshot_parent.resolve()
    forbidden_roots = [
        (qualification_root, "qualification tier"),
        (final_output, "finalization output"),
    ]
    if snapshot_parent is not None:
        forbidden_roots.append((snapshot_parent, "snapshot root"))
    for root, label in forbidden_roots:
        if source == root or root in source.parents:
            raise ReviewError(f"signing-key public handle must be outside the {label}")
    return source


def finalization_candidate_control(
    repo: Path,
    *,
    expected_commit: str,
    expected_tree: str | None,
    required_branch: str | None,
    expected_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Capture and optionally compare the exact candidate publication state."""

    assert_no_replace_refs(repo)
    if str(git(repo, "status", "--porcelain=v1", "--untracked-files=all")).strip():
        raise ReviewError("finalization requires a clean candidate checkout")
    head = str(git(repo, "rev-parse", "HEAD^{commit}")).strip()
    if head != expected_commit:
        raise ReviewError(
            f"candidate mismatch: expected={expected_commit} actual={head}"
        )
    tree = str(git(repo, "rev-parse", "HEAD^{tree}")).strip()
    if expected_tree is not None and tree != expected_tree:
        raise ReviewError("candidate tree changed during finalization")
    branch = str(git(repo, "branch", "--show-current")).strip()
    if required_branch is not None and branch != required_branch:
        raise ReviewError(
            f"candidate branch must be {required_branch!r}, got {branch!r}"
        )
    repository, origin_main = refresh_canonical_origin_main(repo, expected_commit)
    control = repository_control_snapshot(repo)
    state = {
        "repository": repository,
        "origin_main": origin_main,
        "branch": branch,
        "control": control,
    }
    assert_no_replace_refs(repo)
    if expected_state is not None and state != expected_state:
        raise ReviewError("candidate repository control changed during finalization")
    return state


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


def qualification_tier_inventory(
    root: Path,
    *,
    reject_empty_directories: bool = True,
    context: str = "qualification tier",
    directory_paths: set[str] | None = None,
) -> set[str]:
    """Inventory one exact no-follow tree without reading file contents."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    if no_follow is None or non_block is None or directory_flag is None:
        raise ReviewError(f"atomic no-follow {context} inventory is unavailable")
    directory_flags = (
        os.O_RDONLY | no_follow | non_block | directory_flag | close_on_exec
    )
    try:
        root_descriptor = os.open(root, directory_flags)
    except OSError as error:
        raise ReviewError(f"{context} root is missing or unsafe") from error

    paths: set[str] = set()
    entry_count = 0

    def visit(directory_descriptor: int, prefix: tuple[str, ...]) -> None:
        nonlocal entry_count
        names: list[str] = []
        try:
            with os.scandir(directory_descriptor) as iterator:
                for entry in iterator:
                    entry_count += 1
                    if entry_count > MAX_QUALIFICATION_ENTRIES:
                        raise ReviewError(f"{context} exceeds the entry-count limit")
                    names.append(entry.name)
        except OSError as error:
            raise ReviewError(f"cannot completely inventory {context}") from error
        names.sort()
        if prefix and reject_empty_directories and not names:
            raise ReviewError(
                f"{context} contains an empty directory: " + "/".join(prefix)
            )
        for name in names:
            try:
                name.encode("utf-8", "strict")
            except UnicodeEncodeError as error:
                raise ReviewError(f"{context} contains a non-UTF-8 path") from error
            if (
                not name
                or name in {".", ".."}
                or "/" in name
                or "\\" in name
                or any(ord(character) < 0x20 for character in name)
            ):
                raise ReviewError(f"{context} contains an unsafe path")
            relative_parts = (*prefix, name)
            relative = "/".join(relative_parts)
            try:
                metadata = os.stat(
                    name, dir_fd=directory_descriptor, follow_symlinks=False
                )
            except OSError as error:
                raise ReviewError(
                    f"{context} entry is missing or unsafe: {relative}"
                ) from error
            if stat.S_ISREG(metadata.st_mode):
                paths.add(relative)
                continue
            if stat.S_ISDIR(metadata.st_mode):
                if len(relative_parts) > MAX_QUALIFICATION_DEPTH:
                    raise ReviewError(f"{context} exceeds the directory-depth limit")
                try:
                    child_descriptor = os.open(
                        name, directory_flags, dir_fd=directory_descriptor
                    )
                except OSError as error:
                    raise ReviewError(
                        f"{context} directory is missing or unsafe: {relative}"
                    ) from error
                try:
                    if directory_paths is not None:
                        directory_paths.add(relative)
                    visit(child_descriptor, relative_parts)
                finally:
                    os.close(child_descriptor)
                continue
            kind = "symlink" if stat.S_ISLNK(metadata.st_mode) else "special file"
            raise ReviewError(f"{context} contains a {kind}: {relative}")

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


def load_canonical_object(
    path: Path,
    label: str,
    *,
    max_bytes: int = MAX_REVIEW_INPUT_BYTES,
) -> dict[str, Any]:
    """Parse an already snapshotted signed JSON object and require canonical bytes."""

    raw = read_bounded_regular_file(
        path,
        max_bytes,
        label=label,
        limit_label=f"{label}-byte",
    )
    try:
        value = loads_json(raw)
        validate_json_structure(
            value,
            max_depth=MAX_QUALIFICATION_JSON_DEPTH,
            max_nodes=MAX_QUALIFICATION_JSON_NODES,
            label=label,
        )
    except (MemoryError, RecursionError, UnicodeError, ValueError) as error:
        raise ReviewError(f"{label} is not valid bounded JSON: {error}") from error
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise ReviewError(f"{label} is not a canonical JSON object")
    return value


def load_qualification_json(
    path: Path,
    label: str,
    *,
    max_bytes: int = MAX_QUALIFICATION_JSON_BYTES,
) -> Any:
    """Load one manifest-bound JSON artifact with fixed resource limits."""

    return load_json(
        path,
        max_bytes=max_bytes,
        max_depth=MAX_QUALIFICATION_JSON_DEPTH,
        max_nodes=MAX_QUALIFICATION_JSON_NODES,
        label=label,
    )


def read_qualification_log_header(
    path: Path, marker: bytes = b"--- combined stdout/stderr ---\n"
) -> bytes:
    """Read only the bounded JSON header from one retained command log."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    if no_follow is None or non_block is None:
        raise ReviewError("atomic bounded command-log reads are unavailable")
    try:
        descriptor = os.open(path, os.O_RDONLY | no_follow | non_block)
    except OSError as error:
        raise ReviewError(f"qualification command log is missing: {path}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ReviewError(f"qualification command log is not regular: {path}")
        buffer = bytearray()
        while len(buffer) <= MAX_QUALIFICATION_LOG_HEADER_BYTES:
            block = os.read(
                descriptor,
                min(
                    64 * 1024,
                    MAX_QUALIFICATION_LOG_HEADER_BYTES + len(marker) - len(buffer),
                ),
            )
            if not block:
                break
            buffer.extend(block)
            position = buffer.find(marker)
            if 0 <= position <= MAX_QUALIFICATION_LOG_HEADER_BYTES:
                after = os.fstat(descriptor)
                if (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                ) != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ):
                    raise ReviewError(
                        f"qualification command log changed while read: {path}"
                    )
                return bytes(buffer[:position])
        raise ReviewError(
            f"qualification command output lacks a bounded JSON header: {path.name}"
        )
    finally:
        os.close(descriptor)


def read_qualification_auxiliary_log(
    path: Path,
    *,
    stdout_size: int,
    stderr_size: int,
) -> tuple[bytes, bytes, bytes, bytes]:
    """Read and split one bounded auxiliary log through a held file descriptor."""

    max_stream_bytes = 64 * 1024 * 1024
    if (
        type(stdout_size) is not int
        or type(stderr_size) is not int
        or not 0 <= stdout_size <= max_stream_bytes
        or not 0 <= stderr_size <= max_stream_bytes
    ):
        raise ReviewError("qualification auxiliary stream size is invalid")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    if no_follow is None or non_block is None:
        raise ReviewError("atomic bounded auxiliary-log reads are unavailable")
    stdout_marker = b"--- stdout ---\n"
    stderr_marker = b"\n--- stderr ---\n"
    trailer_marker = b"\n--- receipt trailer ---\n"
    maximum_size = (
        (2 * MAX_QUALIFICATION_LOG_HEADER_BYTES)
        + len(stdout_marker)
        + stdout_size
        + len(stderr_marker)
        + stderr_size
        + len(trailer_marker)
    )
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | no_follow | non_block | close_on_exec,
        )
    except OSError as error:
        raise ReviewError(f"qualification auxiliary log is missing: {path}") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > maximum_size
        ):
            raise ReviewError(
                f"qualification auxiliary log size or type is invalid: {path}"
            )
        payload = bytearray()
        while True:
            block = os.read(
                descriptor, min(1024 * 1024, maximum_size + 1 - len(payload))
            )
            if not block:
                break
            payload.extend(block)
            if len(payload) > maximum_size:
                raise ReviewError(
                    f"qualification auxiliary log exceeds its bound: {path}"
                )
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or len(payload) != before.st_size:
            raise ReviewError(f"qualification auxiliary log changed while read: {path}")
    finally:
        os.close(descriptor)

    raw = bytes(payload)
    header_end = raw.find(stdout_marker)
    if not 0 <= header_end <= MAX_QUALIFICATION_LOG_HEADER_BYTES:
        raise ReviewError(f"qualification auxiliary log has no bounded header: {path}")
    stdout_start = header_end + len(stdout_marker)
    stdout_end = stdout_start + stdout_size
    stderr_start = stdout_end + len(stderr_marker)
    stderr_end = stderr_start + stderr_size
    trailer_start = stderr_end + len(trailer_marker)
    if (
        raw[stdout_end:stderr_start] != stderr_marker
        or raw[stderr_end:trailer_start] != trailer_marker
        or not 0 < len(raw) - trailer_start <= MAX_QUALIFICATION_LOG_HEADER_BYTES
    ):
        raise ReviewError(
            f"qualification auxiliary log stream framing is invalid: {path}"
        )
    return (
        raw[:header_end],
        raw[stdout_start:stdout_end],
        raw[stderr_start:stderr_end],
        raw[trailer_start:],
    )


def read_qualification_command_log(
    path: Path,
    *,
    combined_output_size: int,
) -> tuple[bytes, bytes, bytes]:
    """Read one bounded command log and its receipt trailer atomically."""

    max_output_bytes = 64 * 1024 * 1024
    if (
        type(combined_output_size) is not int
        or not 0 <= combined_output_size <= max_output_bytes
    ):
        raise ReviewError("qualification combined output size is invalid")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    if no_follow is None or non_block is None:
        raise ReviewError("atomic bounded command-log reads are unavailable")
    output_marker = b"--- combined stdout/stderr ---\n"
    trailer_marker = b"\n--- receipt trailer ---\n"
    maximum_size = (
        (2 * MAX_QUALIFICATION_LOG_HEADER_BYTES)
        + len(output_marker)
        + combined_output_size
        + len(trailer_marker)
    )
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | no_follow | non_block | close_on_exec,
        )
    except OSError as error:
        raise ReviewError(f"qualification command log is missing: {path}") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > maximum_size
        ):
            raise ReviewError(
                f"qualification command log size or type is invalid: {path}"
            )
        payload = bytearray()
        while True:
            block = os.read(
                descriptor,
                min(1024 * 1024, maximum_size + 1 - len(payload)),
            )
            if not block:
                break
            payload.extend(block)
            if len(payload) > maximum_size:
                raise ReviewError(
                    f"qualification command log exceeds its bound: {path}"
                )
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or len(payload) != before.st_size:
            raise ReviewError(f"qualification command log changed while read: {path}")
    finally:
        os.close(descriptor)

    raw = bytes(payload)
    header_end = raw.find(output_marker)
    if not 0 <= header_end <= MAX_QUALIFICATION_LOG_HEADER_BYTES:
        raise ReviewError(f"qualification command log has no bounded header: {path}")
    output_start = header_end + len(output_marker)
    output_end = output_start + combined_output_size
    trailer_start = output_end + len(trailer_marker)
    if (
        raw[output_end:trailer_start] != trailer_marker
        or not 0 < len(raw) - trailer_start <= MAX_QUALIFICATION_LOG_HEADER_BYTES
    ):
        raise ReviewError(f"qualification command log framing is invalid: {path}")
    return (
        raw[:header_end],
        raw[output_start:output_end],
        raw[trailer_start:],
    )


def validate_command_receipt_trailer(
    trailer_bytes: bytes,
    result: dict[str, Any],
    context: str,
) -> None:
    """Bind every non-self-referential receipt field into its command log."""

    try:
        trailer = loads_json(trailer_bytes)
        validate_json_structure(
            trailer,
            max_depth=32,
            max_nodes=4_096,
            label=f"{context} receipt trailer",
        )
    except (
        MemoryError,
        RecursionError,
        ReviewError,
        UnicodeError,
        ValueError,
    ) as error:
        raise ReviewError(f"{context} receipt trailer is invalid: {error}") from error
    embedded_receipt = {
        key: value
        for key, value in result.items()
        if key not in {"log_sha256", "log_size_bytes"}
    }
    expected = {
        "schema": "galadriel.command-receipt-trailer.v1",
        "receipt": embedded_receipt,
    }
    if trailer != expected or trailer_bytes != canonical_json(expected):
        raise ReviewError(f"{context} receipt trailer contradicts its receipt")


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
    relative_directories: set[str] = set()
    relative_files = qualification_tier_inventory(
        root,
        reject_empty_directories=False,
        context="staged closure",
        directory_paths=relative_directories,
    )
    for relative in sorted(relative_files):
        path = root.joinpath(*relative.split("/"))
        descriptor = os.open(path, os.O_RDONLY | no_follow | non_block)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ReviewError("staged closure contains a non-regular file")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    directories = [
        root.joinpath(*relative.split("/"))
        for relative in sorted(
            relative_directories,
            key=lambda item: (item.count("/"), item),
            reverse=True,
        )
    ]
    for path in [*directories, root]:
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


def publish_staged_output(
    staging: Path,
    destination: Path,
    *,
    pre_publish_guard: Callable[[], None] | None = None,
) -> None:
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
        if pre_publish_guard is not None:
            pre_publish_guard()
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
    raw = git_bounded_output(
        repo,
        "show",
        f"{commit}:{relative}",
        max_bytes=MAX_REVIEW_INPUT_BYTES,
    )
    try:
        value = loads_json(raw)
    except (UnicodeError, ValueError) as error:
        raise ReviewError(
            f"candidate JSON is invalid at {relative}: {error}"
        ) from error
    if not isinstance(value, dict):
        raise ReviewError(f"candidate JSON must be an object: {relative}")
    validate_json_structure(
        value,
        max_depth=MAX_QUALIFICATION_JSON_DEPTH,
        max_nodes=MAX_QUALIFICATION_JSON_NODES,
        label=f"candidate JSON at {relative}",
    )
    return value


def candidate_digest(repo: Path, commit: str, relative: str) -> str:
    raw = git_bounded_output(
        repo,
        "show",
        f"{commit}:{relative}",
        max_bytes=MAX_REVIEW_INPUT_BYTES,
    )
    return hashlib.sha256(raw).hexdigest()


def candidate_crate_files(
    repo: Path,
    commit: str,
    crate: str,
) -> dict[str, tuple[int, bytes]]:
    """Read the exact candidate files that one Cargo package must contain."""

    if crate not in EXPECTED_RELEASE_CRATES:
        raise ReviewError("candidate crate file request names another package")
    prefix = f"crates/{crate}/"
    raw = git_bounded_output(
        repo,
        "ls-tree",
        "-rz",
        "-r",
        "--full-tree",
        commit,
        "--",
        prefix.removesuffix("/"),
        max_bytes=MAX_CANDIDATE_CRATE_TREE_LIST_BYTES,
    )
    files: dict[str, tuple[int, bytes]] = {}
    aggregate_size = 0
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        try:
            metadata, path_bytes = encoded.split(b"\t", 1)
            mode_text, object_type, object_id = metadata.decode("ascii").split()
            path = path_bytes.decode("utf-8", "strict")
        except (UnicodeError, ValueError) as error:
            raise ReviewError("candidate crate tree record is malformed") from error
        if (
            object_type != "blob"
            or mode_text not in {"100644", "100755"}
            or not path.startswith(prefix)
        ):
            raise ReviewError("candidate crate tree contains an unsupported entry")
        relative = path.removeprefix(prefix)
        parts = relative.split("/")
        if not relative or any(
            not part
            or part in {".", ".."}
            or "\\" in part
            or any(ord(character) < 0x20 for character in part)
            for part in parts
        ):
            raise ReviewError("candidate crate tree contains an unsafe path")
        archive_relative = "Cargo.toml.orig" if relative == "Cargo.toml" else relative
        if archive_relative in files:
            raise ReviewError("candidate crate tree contains a duplicate package path")
        content = git_bounded_output(
            repo,
            "cat-file",
            "blob",
            object_id,
            max_bytes=MAX_CANDIDATE_CRATE_MEMBER_BYTES,
        )
        aggregate_size += len(content)
        if (
            len(files) >= MAX_CANDIDATE_CRATE_MEMBERS
            or aggregate_size > MAX_CANDIDATE_CRATE_TREE_BYTES
        ):
            raise ReviewError("candidate crate tree exceeds its resource bound")
        files[archive_relative] = (
            0o755 if mode_text == "100755" else 0o644,
            content,
        )
    if "Cargo.toml.orig" not in files:
        raise ReviewError("candidate crate tree lacks Cargo.toml")
    return files


def artifact_rows(root: Path, excluded: set[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for relative in sorted(qualification_tier_inventory(root)):
        if relative in excluded:
            continue
        path = root.joinpath(*relative.split("/"))
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
    source_date_epoch: int,
) -> dict[str, Any]:
    expected_fields = {
        "schema",
        "release",
        "author",
        "doi",
        "zenodo",
        "status",
        "command_status",
        "release_gate",
        "candidate",
        "host",
        "tools",
        "tool_files",
        "environment_contract",
        "repository_control",
        "sandbox",
        "advisory_database",
        "deep_campaigns_requested",
        "evidence_config",
        "commands",
        "auxiliary_commands",
        "acceptance",
        "evidence_config_binding",
        "source_archive",
        "cargo_metadata",
        "packages",
        "sboms",
        "license_inventory",
        "license_report",
        "vulnerability_report",
        "reproducibility",
        "mutation_evidence",
        "limitations",
    }
    if set(qualification) != expected_fields:
        raise ReviewError("qualification record has an unexpected field set")
    if qualification.get("schema") != "galadriel.candidate-qualification.v3":
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
    candidate = qualification.get("candidate")
    expected_candidate = {
        "repository": CANONICAL_REPOSITORY,
        "branch": RELEASE_BRANCH,
        "commit": commit,
        "tree": tree,
        "source_date_epoch": source_date_epoch,
    }
    if candidate != expected_candidate:
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
    limitations = qualification.get("limitations")
    if not isinstance(limitations, str) or not limitations:
        raise ReviewError("qualification limitations are missing")
    return binding


def validate_qualification_environment(
    qualification: dict[str, Any], source_date_epoch: int
) -> None:
    """Require the exact isolated command-environment contract."""

    expected = qualification_environment_contract(str(source_date_epoch))
    if qualification.get("environment_contract") != expected:
        raise ReviewError(
            "qualification used another deterministic environment contract"
        )


def _lower_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def validate_receipt_timing(receipt: dict[str, Any], context: str) -> None:
    """Require canonical UTC times and one consistent bounded duration."""

    timestamps: dict[str, dt.datetime] = {}
    for field in ("started_at", "finished_at"):
        value = receipt.get(field)
        if not isinstance(value, str):
            raise ReviewError(f"{context} {field} is not a timestamp")
        try:
            parsed = dt.datetime.fromisoformat(value)
        except ValueError as error:
            raise ReviewError(f"{context} {field} is not a timestamp") from error
        if (
            parsed.tzinfo != dt.timezone.utc
            or parsed.isoformat(timespec="milliseconds") != value
        ):
            raise ReviewError(f"{context} {field} is not canonical UTC")
        timestamps[field] = parsed

    duration = receipt.get("duration_seconds")
    timeout = receipt.get("timeout_seconds")
    if (
        not isinstance(duration, (int, float))
        or isinstance(duration, bool)
        or not math.isfinite(duration)
        or duration < 0
        or type(timeout) is not int
        or timeout <= 0
    ):
        raise ReviewError(f"{context} duration or timeout is invalid")
    wall_duration = (
        timestamps["finished_at"] - timestamps["started_at"]
    ).total_seconds()
    if (
        wall_duration < 0
        or duration > timeout + 1.0
        or wall_duration > timeout + 1.0
        or abs(wall_duration - duration) > 1.0
    ):
        raise ReviewError(f"{context} timing values are inconsistent")


def validate_repository_control(
    qualification: dict[str, Any], *, commit: str, tree: str
) -> None:
    """Require unchanged source and standalone-clone control snapshots."""

    control = qualification.get("repository_control")
    expected_fields = {
        "status",
        "origin_main",
        "source_before",
        "source_after",
        "standalone_clone_before",
        "standalone_clone_after",
        "advisory_source_before",
        "advisory_source_after",
    }
    if not isinstance(control, dict) or set(control) != expected_fields:
        raise ReviewError("qualification repository-control record is malformed")
    if control["status"] != "UNCHANGED":
        raise ReviewError("qualification repository controls changed during the run")
    if control["origin_main"] != commit:
        raise ReviewError("qualification origin/main differs from the candidate")

    snapshot_fields = {
        "head",
        "tree",
        "status_sha256",
        "refs_sha256",
        "local_config_sha256",
    }
    snapshot_names = (
        "source_before",
        "source_after",
        "standalone_clone_before",
        "standalone_clone_after",
    )
    for name in snapshot_names:
        snapshot = control[name]
        if (
            not isinstance(snapshot, dict)
            or set(snapshot) != snapshot_fields
            or snapshot["head"] != commit
            or snapshot["tree"] != tree
            or snapshot["status_sha256"] != EMPTY_SHA256
            or not _lower_hex(snapshot["refs_sha256"], 64)
            or not _lower_hex(snapshot["local_config_sha256"], 64)
        ):
            raise ReviewError(
                f"qualification repository-control snapshot is invalid: {name}"
            )
    if control["source_before"] != control["source_after"]:
        raise ReviewError("qualification source repository changed during the run")
    if control["standalone_clone_before"] != control["standalone_clone_after"]:
        raise ReviewError("qualification standalone clone changed during the run")
    for name in ("advisory_source_before", "advisory_source_after"):
        snapshot = control[name]
        if (
            not isinstance(snapshot, dict)
            or set(snapshot) != snapshot_fields
            or snapshot["head"] != RUSTSEC_ADVISORY_DATABASE["commit"]
            or snapshot["tree"] != RUSTSEC_ADVISORY_DATABASE["tree"]
            or snapshot["status_sha256"] != EMPTY_SHA256
            or not _lower_hex(snapshot["refs_sha256"], 64)
            or not _lower_hex(snapshot["local_config_sha256"], 64)
        ):
            raise ReviewError(
                f"qualification advisory-source control snapshot is invalid: {name}"
            )
    if control["advisory_source_before"] != control["advisory_source_after"]:
        raise ReviewError("qualification advisory source changed during the run")


def validate_qualification_sandbox(
    qualification: dict[str, Any],
    *,
    qualification_root: Path,
    manifest_artifacts: dict[str, dict[str, Any]],
    repo: Path,
    recorded_root: Path | None = None,
) -> tuple[str, str]:
    """Require exact retained sandbox policies and return both digests."""

    sandbox = qualification.get("sandbox")
    if (
        not isinstance(sandbox, dict)
        or set(sandbox)
        != {
            "executor",
            "policy_path",
            "policy_sha256",
            "dependency_fetch_policy_path",
            "dependency_fetch_policy_sha256",
            "candidate_source_write_policy",
            "operator_repository_access_policy",
            "host_home_read_policy",
            "write_policy",
            "network_policy",
            "process_containment_policy",
            "process_containment_limitation",
            "bindings",
        }
        or sandbox["executor"] != "/usr/bin/sandbox-exec"
        or sandbox["policy_path"] != "sandbox/candidate.sb"
        or sandbox["dependency_fetch_policy_path"] != "sandbox/dependency-fetch.sb"
        or not _lower_hex(sandbox["policy_sha256"], 64)
        or not _lower_hex(sandbox["dependency_fetch_policy_sha256"], 64)
        or sandbox["policy_sha256"] == sandbox["dependency_fetch_policy_sha256"]
        or sandbox["candidate_source_write_policy"] != "DENY"
        or sandbox["operator_repository_access_policy"] != "DENY_READ_AND_WRITE"
        or sandbox["host_home_read_policy"] != "DENY_EXCEPT_REQUIRED_TOOL_INPUTS"
        or sandbox["write_policy"] != "DENY_EXCEPT_DECLARED_PRIVATE_OUTPUTS"
        or sandbox["network_policy"] != "DENY_EXCEPT_LOCKED_DEPENDENCY_FETCH"
        or sandbox["process_containment_policy"]
        != execution_policy_contract(1)["containment"]
        or sandbox["process_containment_limitation"]
        != execution_policy_contract(1)["containment_residual"]
    ):
        raise ReviewError("qualification sandbox record is malformed or permissive")

    bindings = sandbox["bindings"]
    if not isinstance(bindings, dict) or set(bindings) != {
        "candidate_worktree",
        "source_repository",
        "host_home",
        "private_root",
        "isolated_home",
        "cargo_home",
        "cargo_target_directory",
        "temporary_directory",
        "source_inventory",
        "candidate_evidence",
        "reproducibility_root",
        "advisory_source_denied_read",
        "advisory_databases",
        "allowed_signers_snapshot",
        "rustup_home",
        "home_tool_paths",
        "tool_read_paths",
        "candidate_process_probe_deny",
        "candidate_process_probe_allow",
        "dependency_fetch_process_probe_deny",
        "dependency_fetch_process_probe_allow",
    }:
        raise ReviewError("qualification sandbox path bindings are malformed")

    def recorded_path(value: Any, label: str) -> Path:
        if (
            not isinstance(value, str)
            or not value
            or any(ord(character) < 0x20 for character in value)
        ):
            raise ReviewError(f"qualification sandbox {label} is invalid")
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts:
            raise ReviewError(f"qualification sandbox {label} is invalid")
        return path

    def recorded_paths(value: Any, label: str) -> tuple[Path, ...]:
        if not isinstance(value, list) or not value:
            raise ReviewError(f"qualification sandbox {label} is invalid")
        paths = tuple(recorded_path(item, f"{label} entry") for item in value)
        if len(paths) != len(set(paths)):
            raise ReviewError(f"qualification sandbox {label} contains a duplicate")
        return paths

    worktree = recorded_path(bindings["candidate_worktree"], "candidate worktree")
    source_repo = recorded_path(bindings["source_repository"], "source repository")
    host_home = recorded_path(bindings["host_home"], "host home")
    private_root = recorded_path(bindings["private_root"], "private root")
    isolated_home = recorded_path(bindings["isolated_home"], "isolated home")
    cargo_home = recorded_path(bindings["cargo_home"], "Cargo home")
    cargo_target = recorded_path(
        bindings["cargo_target_directory"], "Cargo target directory"
    )
    temporary_directory = recorded_path(
        bindings["temporary_directory"], "temporary directory"
    )
    source_inventory = recorded_path(bindings["source_inventory"], "source inventory")
    candidate_evidence = recorded_path(
        bindings["candidate_evidence"], "candidate evidence"
    )
    reproducibility_root = recorded_path(
        bindings["reproducibility_root"], "reproducibility root"
    )
    advisory_source = recorded_path(
        bindings["advisory_source_denied_read"],
        "denied advisory source",
    )
    advisory_databases = recorded_paths(
        bindings["advisory_databases"], "advisory databases"
    )
    allowed_signers_snapshot = recorded_path(
        bindings["allowed_signers_snapshot"], "allowed signers snapshot"
    )
    rustup_home = recorded_path(bindings["rustup_home"], "Rustup home")
    home_tool_paths = recorded_paths(bindings["home_tool_paths"], "home tool paths")
    tool_read_paths = recorded_paths(bindings["tool_read_paths"], "tool read paths")
    candidate_probe_paths = (
        recorded_path(
            bindings["candidate_process_probe_deny"],
            "candidate process deny probe",
        ),
        recorded_path(
            bindings["candidate_process_probe_allow"],
            "candidate process allow probe",
        ),
    )
    dependency_fetch_probe_paths = (
        recorded_path(
            bindings["dependency_fetch_process_probe_deny"],
            "dependency-fetch process deny probe",
        ),
        recorded_path(
            bindings["dependency_fetch_process_probe_allow"],
            "dependency-fetch process allow probe",
        ),
    )
    expected_private_children = {
        worktree: "worktree",
        isolated_home: "home",
        cargo_home: "cargo-home",
        cargo_target: "target",
        temporary_directory: "tmp",
        reproducibility_root: "reproducibility",
        allowed_signers_snapshot: "INDEPENDENT_ALLOWED_SIGNERS",
    }
    if any(
        path.parent != private_root or path.name != expected_name
        for path, expected_name in expected_private_children.items()
    ):
        raise ReviewError("qualification sandbox private output layout is not exact")
    expected_probe_paths = (
        private_root / "candidate.sb.containment-deny",
        private_root / "candidate.sb.containment-allow",
        private_root / "dependency-fetch.sb.containment-deny",
        private_root / "dependency-fetch.sb.containment-allow",
    )
    if (*candidate_probe_paths, *dependency_fetch_probe_paths) != expected_probe_paths:
        raise ReviewError("qualification process-probe layout is not exact")
    if (
        source_inventory.parent != candidate_evidence.parent
        or source_inventory.name != "source-inventory"
        or candidate_evidence.name != "candidate-evidence"
    ):
        raise ReviewError("qualification sandbox retained output layout is not exact")
    output_root = source_inventory.parent
    expected_advisory_databases = (
        cargo_home / "advisory-db",
        cargo_home / "advisory-dbs" / "advisory-db-3157b0e258782691",
    )
    if advisory_databases != expected_advisory_databases:
        raise ReviewError("qualification sandbox advisory database layout is not exact")
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
    home_read_set = {
        path
        for path in (*home_tool_paths, rustup_home, *writable_paths)
        if path == host_home or host_home in path.parents
    }
    allowed_home_read_paths = tuple(sorted(home_read_set, key=lambda item: str(item)))
    if (
        source_repo != repo.resolve()
        or output_root
        != (
            recorded_root if recorded_root is not None else qualification_root
        ).resolve()
    ):
        raise ReviewError(
            "qualification sandbox source or retained output binding is not exact"
        )
    if (
        worktree == source_repo
        or worktree in source_repo.parents
        or source_repo in worktree.parents
    ):
        raise ReviewError("qualification sandbox worktree overlaps its source")
    protected_roots = (source_repo, private_root, output_root, advisory_source)
    if any(
        left == right or left in right.parents or right in left.parents
        for index, left in enumerate(protected_roots)
        for right in protected_roots[index + 1 :]
    ):
        raise ReviewError("qualification sandbox protected roots overlap")
    for path in writable_paths:
        if (
            path == worktree
            or worktree in path.parents
            or path in worktree.parents
            or path == source_repo
            or source_repo in path.parents
            or path in source_repo.parents
        ):
            raise ReviewError(
                "qualification sandbox writable path overlaps source material"
            )
    for path in (*home_tool_paths, *tool_read_paths, rustup_home):
        if (
            path == source_repo
            or source_repo in path.parents
            or path in source_repo.parents
            or path == private_root
            or private_root in path.parents
            or path in private_root.parents
            or path == output_root
            or output_root in path.parents
            or path in output_root.parents
        ):
            raise ReviewError(
                "qualification sandbox tool-read path overlaps mutable material"
            )
    if any(
        path != host_home and host_home not in path.parents for path in home_tool_paths
    ):
        raise ReviewError("qualification sandbox home tool path escapes the host home")

    expected_policies = {
        sandbox["policy_path"]: render_candidate_sandbox_profile(
            worktree=worktree,
            source_repo=source_repo,
            host_home=host_home,
            read_only_paths=read_only_paths,
            writable_paths=writable_paths,
            allowed_home_read_paths=allowed_home_read_paths,
            tool_read_paths=tool_read_paths,
            denied_read_paths=(advisory_source,),
            process_probe_paths=candidate_probe_paths,
            allow_network=False,
        ),
        sandbox["dependency_fetch_policy_path"]: render_candidate_sandbox_profile(
            worktree=worktree,
            source_repo=source_repo,
            host_home=host_home,
            read_only_paths=read_only_paths,
            writable_paths=writable_paths,
            allowed_home_read_paths=allowed_home_read_paths,
            tool_read_paths=tool_read_paths,
            denied_read_paths=(advisory_source,),
            process_probe_paths=dependency_fetch_probe_paths,
            allow_network=True,
        ),
    }
    digest_fields = {
        sandbox["policy_path"]: "policy_sha256",
        sandbox["dependency_fetch_policy_path"]: ("dependency_fetch_policy_sha256"),
    }
    for relative, expected_bytes in expected_policies.items():
        row = manifest_artifacts.get(relative)
        actual = read_bounded_regular_file(
            qualification_root / relative,
            1024 * 1024,
            label=f"qualification sandbox policy {relative}",
            limit_label="qualification-sandbox-policy-byte",
        )
        digest = hashlib.sha256(actual).hexdigest()
        if (
            actual != expected_bytes
            or row is None
            or row["sha256"] != digest
            or row["size_bytes"] != len(actual)
            or sandbox[digest_fields[relative]] != digest
        ):
            raise ReviewError(f"qualification sandbox policy is not exact: {relative}")
    return (
        sandbox["policy_sha256"],
        sandbox["dependency_fetch_policy_sha256"],
    )


def validate_advisory_database(qualification: dict[str, Any]) -> dict[str, Any]:
    """Require the exact pinned, offline RustSec advisory database."""

    database = qualification.get("advisory_database")
    if database != RUSTSEC_ADVISORY_DATABASE:
        raise ReviewError("qualification used another RustSec advisory database")
    return database


def _absolute_identity_path(value: Any, label: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ReviewError(f"{label} is not a valid absolute path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ReviewError(f"{label} is not a valid absolute path")
    return path


def validate_qualification_tool_files(qualification: dict[str, Any]) -> None:
    """Require exact executable path, digest, owner, group, and mode records."""

    tool_files = qualification.get("tool_files")
    if (
        not isinstance(tool_files, dict)
        or set(tool_files) != {"status", "executables"}
        or tool_files["status"] != "UNCHANGED"
        or not isinstance(tool_files["executables"], dict)
        or set(tool_files["executables"]) != EXPECTED_TOOL_FILE_NAMES
    ):
        raise ReviewError("qualification executable identity set is incomplete")

    identities_by_resolved_path: dict[str, tuple[Any, ...]] = {}
    record_fields = {
        "invoked_path",
        "resolved_path",
        "sha256",
        "size_bytes",
        "uid",
        "gid",
        "mode",
    }
    for name, record in tool_files["executables"].items():
        if not isinstance(record, dict) or set(record) != record_fields:
            raise ReviewError(f"qualification executable identity is malformed: {name}")
        invoked = _absolute_identity_path(
            record["invoked_path"], f"{name} invoked path"
        )
        resolved = _absolute_identity_path(
            record["resolved_path"], f"{name} resolved path"
        )
        size = record["size_bytes"]
        uid = record["uid"]
        gid = record["gid"]
        mode = record["mode"]
        expected_identity = EXPECTED_TOOL_FILE_IDENTITIES.get(name)
        if (
            not _lower_hex(record["sha256"], 64)
            or expected_identity is None
            or (record["sha256"], size) != expected_identity
            or invoked.name != TOOL_FILE_BASENAMES[name]
            or type(size) is not int
            or size <= 0
            or size > MAX_QUALIFICATION_EXECUTABLE_BYTES
            or type(uid) is not int
            or uid < 0
            or type(gid) is not int
            or gid < 0
            or type(mode) is not int
            or mode < 0
            or mode > 0o7777
            or (mode & stat.S_IXUSR) == 0
            or (mode & 0o022) != 0
        ):
            raise ReviewError(f"qualification executable metadata is invalid: {name}")
        identity = (
            record["sha256"],
            size,
            uid,
            gid,
            mode,
        )
        previous = identities_by_resolved_path.setdefault(str(resolved), identity)
        if previous != identity:
            raise ReviewError(
                f"qualification executable path has conflicting identities: {resolved}"
            )
        if name == "sandbox-exec" and (
            invoked != Path("/usr/bin/sandbox-exec")
            or resolved != Path("/usr/bin/sandbox-exec")
        ):
            raise ReviewError("qualification recorded another sandbox executable")


def _path_is_within(path: Path, root: Path) -> bool:
    """Return true when a recorded path is the root or is below the root."""

    return path == root or root in path.parents


def _qualification_tool_read_root(directory: Path, host_home: Path) -> Path | None:
    """Reconstruct the minimal recorded read root for one tool directory."""

    system_roots = tuple(Path(path) for path in SANDBOX_SYSTEM_READ_PATHS)
    if any(_path_is_within(directory, root) for root in system_roots):
        return None
    if _path_is_within(directory, host_home):
        return directory
    parts = directory.parts
    if len(parts) >= 3 and parts[:2] == ("/", "opt"):
        return Path("/", "opt", parts[2])
    if len(parts) >= 3 and parts[:3] == ("/", "usr", "local"):
        return Path("/usr/local")
    return directory


def validate_qualification_tool_bindings(qualification: dict[str, Any]) -> None:
    """Bind each executable path to the exact retained sandbox read roots."""

    sandbox = qualification.get("sandbox")
    bindings = sandbox.get("bindings") if isinstance(sandbox, dict) else None
    tool_files = qualification.get("tool_files")
    executables = (
        tool_files.get("executables") if isinstance(tool_files, dict) else None
    )
    if not isinstance(bindings, dict) or not isinstance(executables, dict):
        raise ReviewError("qualification executable sandbox bindings are missing")

    host_home = _absolute_identity_path(
        bindings.get("host_home"), "qualification host home"
    )
    rustup_home = _absolute_identity_path(
        bindings.get("rustup_home"), "qualification Rustup home"
    )

    def bound_paths(field: str) -> tuple[Path, ...]:
        values = bindings.get(field)
        if not isinstance(values, list) or not values:
            raise ReviewError(f"qualification {field} binding is malformed")
        paths = tuple(
            _absolute_identity_path(value, f"qualification {field} entry")
            for value in values
        )
        if len(paths) != len(set(paths)) or paths != tuple(
            sorted(paths, key=lambda item: str(item))
        ):
            raise ReviewError(f"qualification {field} binding is not canonical")
        return paths

    home_tool_paths = bound_paths("home_tool_paths")
    tool_read_paths = bound_paths("tool_read_paths")
    if (
        host_home == Path("/")
        or rustup_home == Path("/")
        or any(path == Path("/") for path in (*home_tool_paths, *tool_read_paths))
    ):
        raise ReviewError("qualification tool read root is too broad")

    expected_home_tool_paths: set[Path] = set()
    expected_tool_read_paths: set[Path] = set()
    for name in QUALIFICATION_PATH_TOOLS:
        record = executables.get(name)
        if not isinstance(record, dict):
            raise ReviewError(f"qualification executable binding is missing: {name}")
        invoked = _absolute_identity_path(
            record.get("invoked_path"), f"{name} invoked path"
        )
        resolved = _absolute_identity_path(
            record.get("resolved_path"), f"{name} resolved path"
        )
        if _path_is_within(invoked.parent, host_home):
            expected_home_tool_paths.add(invoked.parent)
        for directory in (invoked.parent, resolved.parent):
            read_root = _qualification_tool_read_root(directory, host_home)
            if read_root is not None:
                expected_tool_read_paths.add(read_root)

    expected_home = tuple(sorted(expected_home_tool_paths, key=lambda item: str(item)))
    expected_read = tuple(sorted(expected_tool_read_paths, key=lambda item: str(item)))
    if home_tool_paths != expected_home or tool_read_paths != expected_read:
        raise ReviewError(
            "qualification executable paths and sandbox tool roots disagree"
        )

    rustup_tool_names = (
        EXPECTED_TOOL_FILE_NAMES - set(QUALIFICATION_PATH_TOOLS) - {"sandbox-exec"}
    )
    for name in rustup_tool_names:
        record = executables.get(name)
        if not isinstance(record, dict):
            raise ReviewError(f"qualification Rustup executable is missing: {name}")
        for field in ("invoked_path", "resolved_path"):
            path = _absolute_identity_path(
                record.get(field), f"{name} {field.replace('_', ' ')}"
            )
            if not _path_is_within(path, rustup_home):
                raise ReviewError(
                    f"qualification Rustup executable escapes Rustup home: {name}"
                )


def validate_qualification_tools(qualification: dict[str, Any]) -> dict[str, str]:
    """Require every pinned qualification tool and the CPython implementation."""

    tools = qualification.get("tools")
    if not isinstance(tools, dict) or tools != EXPECTED_QUALIFICATION_TOOLS:
        raise ReviewError("qualification used another toolchain or release tool set")
    host = qualification.get("host")
    if (
        not isinstance(host, dict)
        or set(host) != {"platform", "machine", "python_implementation"}
        or not isinstance(host["platform"], str)
        or not host["platform"]
        or host["machine"] != "arm64"
        or host["python_implementation"] != "CPython"
    ):
        raise ReviewError("qualification used another host or Python implementation")
    return tools


def _absolute_recorded_path(value: Any, context: str) -> Path:
    if not isinstance(value, str):
        raise ReviewError(f"{context} must be an absolute recorded path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ReviewError(f"{context} must be an absolute recorded path")
    return path


def _dynamic_qualification_specs(
    by_name: dict[str, dict[str, Any]],
    qualification_root: Path,
    *,
    expected_allowed_signers_snapshot: Path | None = None,
) -> tuple[CommandSpec, ...]:
    verify_argv = by_name["verify-commit-signature-external-key"].get("argv")
    verify_prefix = [
        "git",
        "--no-replace-objects",
        *SAFE_GIT_CONFIGURATION,
        "-c",
        "gpg.format=ssh",
        "-c",
    ]
    if (
        not isinstance(verify_argv, list)
        or len(verify_argv) != len(verify_prefix) + 3
        or verify_argv[: len(verify_prefix)] != verify_prefix
        or verify_argv[-2:] != ["verify-commit", "HEAD"]
        or not isinstance(verify_argv[-3], str)
        or not verify_argv[-3].startswith("gpg.ssh.allowedSignersFile=")
    ):
        raise ReviewError("qualification used another commit-verification command")
    trust_root = _absolute_recorded_path(
        verify_argv[-3].split("=", 1)[1], "qualification external trust root"
    )
    if trust_root.name != "INDEPENDENT_ALLOWED_SIGNERS":
        raise ReviewError(
            "qualification did not record the ephemeral external trust root"
        )
    if (
        expected_allowed_signers_snapshot is not None
        and trust_root != expected_allowed_signers_snapshot
    ):
        raise ReviewError(
            "qualification commit verification used another signer snapshot"
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
    sandbox_policy_sha256: str,
    dependency_fetch_policy_sha256: str,
    recorded_root: Path | None = None,
    allowed_signers_snapshot: Path | None = None,
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
        by_name,
        recorded_root if recorded_root is not None else qualification_root,
        expected_allowed_signers_snapshot=allowed_signers_snapshot,
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
    spec_by_name = {spec.name: spec for spec in ordered_specs}
    for name, argv in FROZEN_COMMAND_ARGUMENTS.items():
        spec = spec_by_name.get(name)
        if spec is None or spec.argv != argv:
            raise ReviewError(
                f"qualification frozen command definition drifted for {name}"
            )
    expected_names = tuple(spec.name for spec in ordered_specs)
    if expected_names != FROZEN_QUALIFICATION_COMMAND_NAMES:
        raise ReviewError("qualification command definition set drifted")
    observed_names = tuple(command.get("name") for command in commands)
    if observed_names != expected_names:
        raise ReviewError(
            "qualification command set or execution order differs from the frozen gate"
        )

    result_keys = {
        "name",
        "argv",
        "cwd",
        "environment_overrides",
        "sandbox",
        "execution_policy",
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
        "combined_output_sha256",
        "combined_output_size_bytes",
    }
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
            or result["execution_policy"]
            != execution_policy_contract(spec.timeout_seconds)
        ):
            raise ReviewError(f"qualification command contract drifted for {spec.name}")
        expected_sandbox = {
            "executor": "/usr/bin/sandbox-exec",
            "policy_sha256": (
                dependency_fetch_policy_sha256
                if spec.name in DEPENDENCY_FETCH_COMMAND_NAMES
                else sandbox_policy_sha256
            ),
            "network_policy": (
                "LOCKED_DEPENDENCY_FETCH"
                if spec.name in DEPENDENCY_FETCH_COMMAND_NAMES
                else "DENY"
            ),
        }
        if result["sandbox"] != expected_sandbox:
            raise ReviewError(
                f"qualification sandbox selection drifted for {spec.name}"
            )
        validate_receipt_timing(
            result,
            f"qualification command {spec.name}",
        )
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
            or not _lower_hex(result["combined_output_sha256"], 64)
            or type(result["combined_output_size_bytes"]) is not int
            or not 0 <= result["combined_output_size_bytes"] <= 64 * 1024 * 1024
        ):
            raise ReviewError(
                f"qualification command output is not manifest-bound: {spec.name}"
            )
        log = qualification_root / relative
        prefix, combined_output, trailer_bytes = read_qualification_command_log(
            log,
            combined_output_size=result["combined_output_size_bytes"],
        )
        if (
            hashlib.sha256(combined_output).hexdigest()
            != result["combined_output_sha256"]
        ):
            raise ReviewError(
                f"qualification command output contradicts its receipt: {spec.name}"
            )
        try:
            header = loads_json(prefix)
            validate_json_structure(
                header,
                max_depth=16,
                max_nodes=1_024,
                label=f"qualification command header {spec.name}",
            )
        except (
            MemoryError,
            RecursionError,
            ReviewError,
            UnicodeError,
            ValueError,
        ) as error:
            raise ReviewError(
                f"qualification command header is invalid: {spec.name}: {error}"
            ) from error
        if header != {
            "argv": result["argv"],
            "cwd": result["cwd"],
            "environment_overrides": result["environment_overrides"],
            "sandbox": result["sandbox"],
            "started_at": result["started_at"],
            "timeout_seconds": result["timeout_seconds"],
        }:
            raise ReviewError(
                f"qualification command header contradicts its result: {spec.name}"
            )
        validate_command_receipt_trailer(
            trailer_bytes,
            result,
            f"qualification command {spec.name}",
        )


def validate_auxiliary_commands(
    qualification: dict[str, Any],
    *,
    manifest_artifacts: dict[str, dict[str, Any]],
    qualification_root: Path,
    sandbox_policy_sha256: str,
) -> dict[str, dict[str, Any]]:
    """Bind artifact-generation processes to exact sandboxed receipts."""

    commands = qualification.get("auxiliary_commands")
    if not isinstance(commands, list) or not all(
        isinstance(item, dict) for item in commands
    ):
        raise ReviewError("qualification artifact-generation receipts are malformed")
    package_names = tuple(
        f"cargo-package-run-{run_index}-{crate}"
        for run_index in (1, 2)
        for crate in EXPECTED_RELEASE_CRATES
    )
    expected_names = (
        "cargo-metadata",
        "source-archive-run-1",
        "source-archive-run-2",
        *package_names,
        "cyclonedx-sboms-run-1",
        "cyclonedx-sboms-run-2",
        "license-inventory",
        "license-report",
        "vulnerability-report",
    )
    if tuple(item.get("name") for item in commands) != expected_names:
        raise ReviewError(
            "qualification artifact-generation command set or order drifted"
        )
    by_name = {item["name"]: item for item in commands}
    if len(by_name) != len(commands):
        raise ReviewError(
            "qualification artifact-generation command names are duplicated"
        )
    verified_by_name: dict[str, dict[str, Any]] = {}
    sandbox = qualification.get("sandbox")
    bindings = sandbox.get("bindings") if isinstance(sandbox, dict) else None
    if not isinstance(bindings, dict):
        raise ReviewError(
            "qualification sandbox bindings are unavailable to artifact receipts"
        )
    worktree = Path(bindings["candidate_worktree"])
    cargo_home = Path(bindings["cargo_home"])
    reproducibility_root = Path(bindings["reproducibility_root"])
    metadata_tool_input = reproducibility_root / "cargo-metadata.json"
    fixed_argv = {
        "cargo-metadata": [
            "cargo",
            "metadata",
            "--locked",
            "--offline",
            "--all-features",
            "--format-version=1",
        ],
        "source-archive-run-1": [
            "git",
            "-C",
            str(worktree),
            *GIT_ARCHIVE_GLOBAL_ARGS,
            "archive",
            "--format=tar",
            f"--prefix=galadriel-{VERSION}/",
            str(qualification["candidate"]["commit"]),
        ],
        "source-archive-run-2": [
            "git",
            "-C",
            str(worktree),
            *GIT_ARCHIVE_GLOBAL_ARGS,
            "archive",
            "--format=tar",
            f"--prefix=galadriel-{VERSION}/",
            str(qualification["candidate"]["commit"]),
        ],
        "cyclonedx-sboms-run-1": [
            "cargo",
            "cyclonedx",
            "--all-features",
            "--target",
            "all",
            "--format",
            "json",
            "--spec-version",
            "1.5",
            "--override-filename",
            f"galadriel-{VERSION}",
            "--quiet",
        ],
        "cyclonedx-sboms-run-2": [
            "cargo",
            "cyclonedx",
            "--all-features",
            "--target",
            "all",
            "--format",
            "json",
            "--spec-version",
            "1.5",
            "--override-filename",
            f"galadriel-{VERSION}",
            "--quiet",
        ],
        "license-inventory": [
            "cargo",
            "deny",
            "--offline",
            "--all-features",
            "--locked",
            "list",
            "--metadata-path",
            str(metadata_tool_input),
            "--format",
            "json",
            "--layout",
            "crate",
        ],
        "license-report": [
            "cargo",
            "deny",
            "--offline",
            "--format",
            "json",
            "--all-features",
            "--locked",
            "check",
            "--metadata-path",
            str(metadata_tool_input),
            "licenses",
        ],
        "vulnerability-report": [
            "cargo",
            "audit",
            "--no-fetch",
            "--stale",
            "--no-yanked",
            "--ignore",
            IGNORED_ADVISORY,
            "--format",
            "json",
        ],
    }
    fixed_cwd = {
        "cargo-metadata": worktree,
        "source-archive-run-1": worktree,
        "source-archive-run-2": worktree,
        "cyclonedx-sboms-run-1": reproducibility_root / "sbom-worktree-1",
        "cyclonedx-sboms-run-2": reproducibility_root / "sbom-worktree-2",
        "license-inventory": worktree,
        "license-report": worktree,
        "vulnerability-report": worktree,
    }
    result_keys = {
        "name",
        "argv",
        "cwd",
        "sandbox",
        "execution_policy",
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
        "stdout_sha256",
        "stdout_size_bytes",
        "stderr_sha256",
        "stderr_size_bytes",
    }
    expected_sandbox = {
        "executor": "/usr/bin/sandbox-exec",
        "policy_sha256": sandbox_policy_sha256,
        "network_policy": "DENY",
    }

    def validate_package_argv(result: dict[str, Any]) -> None:
        match = re.fullmatch(
            r"cargo-package-run-([12])-(galadriel-[a-z]+)",
            result["name"],
        )
        if match is None:
            raise ReviewError(
                "qualification package-generation receipt name is malformed"
            )
        run_index = int(match.group(1))
        crate = match.group(2)
        if crate not in EXPECTED_RELEASE_CRATES:
            raise ReviewError(
                "qualification package-generation receipt names another crate"
            )
        package_worktree = reproducibility_root / f"package-worktree-{run_index}"
        target = reproducibility_root / f"package-run-{run_index}"
        prefix = [
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
        argv = result["argv"]
        if (
            not isinstance(argv, list)
            or argv[: len(prefix)] != prefix
            or len(argv[len(prefix) :]) % 2
            or any(
                argv[index] != "--config" for index in range(len(prefix), len(argv), 2)
            )
            or result["cwd"] != str(package_worktree)
        ):
            raise ReviewError(
                f"qualification package command contract drifted for {crate}"
            )
        configs = argv[len(prefix) + 1 :: 2]
        if len(configs) != len(set(configs)):
            raise ReviewError(
                f"qualification package command repeats a patch for {crate}"
            )
        workspace_configs = {
            (
                f"patch.crates-io.{dependency}.path="
                f"{json.dumps(str(package_worktree / 'crates' / dependency))}"
            )
            for dependency in EXPECTED_RELEASE_CRATES
            if dependency != crate
        }
        if not workspace_configs.issubset(configs):
            raise ReviewError(
                f"qualification package command omits a workspace patch for {crate}"
            )
        extra = set(configs) - workspace_configs
        crate_patches: dict[str, Path] = {}
        source_patches: dict[str, tuple[str, Path]] = {}
        for config in extra:
            if "\n" in config or "\r" in config or ".path=" not in config:
                raise ReviewError(
                    f"qualification package patch is malformed for {crate}"
                )
            key, encoded_path = config.rsplit(".path=", 1)
            try:
                patch_path_value = json.loads(encoded_path)
            except (json.JSONDecodeError, TypeError) as error:
                raise ReviewError(
                    f"qualification package patch path is invalid for {crate}"
                ) from error
            if not isinstance(patch_path_value, str):
                raise ReviewError(
                    f"qualification package patch path is invalid for {crate}"
                )
            patch_path = Path(patch_path_value)
            if not patch_path.is_absolute() or (
                patch_path != cargo_home and cargo_home not in patch_path.parents
            ):
                raise ReviewError(
                    f"qualification package patch escapes Cargo home for {crate}"
                )
            crates_prefix = "patch.crates-io."
            if key.startswith(crates_prefix):
                dependency = key.removeprefix(crates_prefix)
                if (
                    not dependency
                    or dependency in crate_patches
                    or "/" in dependency
                    or "\\" in dependency
                ):
                    raise ReviewError(
                        f"qualification Cargo patch is ambiguous for {crate}"
                    )
                crate_patches[dependency] = patch_path
                continue
            if not key.startswith("patch."):
                raise ReviewError(
                    f"qualification source patch is malformed for {crate}"
                )
            encoded_source_and_dependency = key.removeprefix("patch.")
            separator = encoded_source_and_dependency.rfind(".")
            if separator <= 0:
                raise ReviewError(
                    f"qualification source patch is malformed for {crate}"
                )
            encoded_source = encoded_source_and_dependency[:separator]
            dependency = encoded_source_and_dependency[separator + 1 :]
            try:
                source = json.loads(encoded_source)
            except (json.JSONDecodeError, TypeError) as error:
                raise ReviewError(
                    f"qualification source patch is invalid for {crate}"
                ) from error
            if (
                not isinstance(source, str)
                or not source.startswith("https://github.com/sepahead/")
                or dependency in source_patches
            ):
                raise ReviewError(f"qualification source patch is invalid for {crate}")
            source_patches[dependency] = (source, patch_path)
        if set(crate_patches) != set(source_patches) or any(
            crate_patches[name] != source_patches[name][1] for name in crate_patches
        ):
            raise ReviewError(
                f"qualification Git patch pairs are incomplete for {crate}"
            )

    for result in commands:
        name = result["name"]
        if set(result) != result_keys:
            raise ReviewError(
                f"qualification artifact receipt has unexpected fields: {name}"
            )
        if (
            result["sandbox"] != expected_sandbox
            or result["execution_policy"] != execution_policy_contract(3_600)
            or result["timeout_seconds"] != 3_600
            or result["timed_out"] is not False
            or result["exit_code"] != 0
            or result["status"] != "PASS"
        ):
            raise ReviewError(
                f"qualification artifact command did not pass exactly: {name}"
            )
        validate_receipt_timing(
            result,
            f"qualification artifact command {name}",
        )
        if name.startswith("cargo-package-run-"):
            validate_package_argv(result)
        elif result["argv"] != fixed_argv[name] or result["cwd"] != str(
            fixed_cwd[name]
        ):
            raise ReviewError(
                f"qualification artifact command contract drifted: {name}"
            )
        relative = result["log"]
        row = manifest_artifacts.get(relative) if isinstance(relative, str) else None
        if (
            row is None
            or result["log_sha256"] != row["sha256"]
            or result["log_size_bytes"] != row["size_bytes"]
            or not _lower_hex(result["stdout_sha256"], 64)
            or not _lower_hex(result["stderr_sha256"], 64)
            or type(result["stdout_size_bytes"]) is not int
            or type(result["stderr_size_bytes"]) is not int
            or not 0 <= result["stdout_size_bytes"] <= 64 * 1024 * 1024
            or not 0 <= result["stderr_size_bytes"] <= 64 * 1024 * 1024
        ):
            raise ReviewError(
                f"qualification artifact receipt is not manifest-bound: {name}"
            )
        prefix, stdout, stderr, trailer_bytes = read_qualification_auxiliary_log(
            qualification_root / relative,
            stdout_size=result["stdout_size_bytes"],
            stderr_size=result["stderr_size_bytes"],
        )
        if (
            hashlib.sha256(stdout).hexdigest() != result["stdout_sha256"]
            or hashlib.sha256(stderr).hexdigest() != result["stderr_sha256"]
        ):
            raise ReviewError(
                f"qualification artifact log stream contradicts its receipt: {name}"
            )
        try:
            header = loads_json(prefix)
            validate_json_structure(
                header,
                max_depth=16,
                max_nodes=1_024,
                label=f"qualification artifact command header {name}",
            )
        except (
            MemoryError,
            RecursionError,
            ReviewError,
            UnicodeError,
            ValueError,
        ) as error:
            raise ReviewError(
                f"qualification artifact command header is invalid: {name}: {error}"
            ) from error
        if header != {
            "argv": result["argv"],
            "cwd": result["cwd"],
            "sandbox": result["sandbox"],
            "started_at": result["started_at"],
            "timeout_seconds": result["timeout_seconds"],
        }:
            raise ReviewError(
                f"qualification artifact command header contradicts its receipt: {name}"
            )
        validate_command_receipt_trailer(
            trailer_bytes,
            result,
            f"qualification artifact command {name}",
        )
        verified = dict(result)
        diagnostics_streams = {
            "license-inventory": stderr,
            "license-report": stdout,
            "vulnerability-report": stderr,
        }
        if name in diagnostics_streams:
            diagnostics_text = (
                diagnostics_streams[name].decode("utf-8", "replace").strip()
            )
            verified["_diagnostics_text_sha256"] = hashlib.sha256(
                diagnostics_text.encode("utf-8")
            ).hexdigest()
        verified_by_name[name] = verified
    return verified_by_name


def validate_package_patch_receipts(
    qualification: dict[str, Any],
    auxiliary_receipts: dict[str, dict[str, Any]],
    cargo_graph: Any,
) -> None:
    """Require every exact workspace and pinned Git package override."""

    sandbox = qualification.get("sandbox")
    bindings = sandbox.get("bindings") if isinstance(sandbox, dict) else None
    if not isinstance(bindings, dict):
        raise ReviewError("qualification package patch bindings are unavailable")
    cargo_home = Path(bindings.get("cargo_home", ""))
    reproducibility_root = Path(bindings.get("reproducibility_root", ""))
    if (
        not cargo_home.is_absolute()
        or not reproducibility_root.is_absolute()
        or cargo_home == reproducibility_root
    ):
        raise ReviewError("qualification package patch roots are invalid")

    git_package_rows = [
        package
        for package in cargo_graph.packages
        if isinstance(package.source, str) and package.source.startswith("git+")
    ]
    git_packages = {package.name: package for package in git_package_rows}
    if len(git_packages) != len(git_package_rows) or set(git_packages) != set(
        EXPECTED_GIT_PACKAGE_SOURCES
    ):
        raise ReviewError("qualification Cargo graph has another Git package set")
    git_patch_rows: list[tuple[str, str, Path]] = []
    for name in sorted(git_packages):
        package = git_packages[name]
        expected_source = EXPECTED_GIT_PACKAGE_SOURCES[name]
        manifest = Path(package.manifest_path)
        package_path = manifest.parent
        if (
            package.source != expected_source
            or not manifest.is_absolute()
            or manifest.name != "Cargo.toml"
            or (package_path != cargo_home and cargo_home not in package_path.parents)
        ):
            raise ReviewError(
                f"qualification Git package identity or path drifted: {name}"
            )
        source_url = expected_source.removeprefix("git+").split("?", 1)[0]
        git_patch_rows.append((name, source_url, package_path))

    for run_index in (1, 2):
        package_worktree = reproducibility_root / f"package-worktree-{run_index}"
        package_target = reproducibility_root / f"package-run-{run_index}"
        for crate in EXPECTED_RELEASE_CRATES:
            receipt_name = f"cargo-package-run-{run_index}-{crate}"
            receipt = auxiliary_receipts.get(receipt_name)
            if not isinstance(receipt, dict):
                raise ReviewError(
                    f"qualification package receipt is missing: {receipt_name}"
                )
            prefix = [
                "cargo",
                "package",
                "-p",
                crate,
                "--locked",
                "--offline",
                "--no-verify",
                "--exclude-lockfile",
                "--target-dir",
                str(package_target),
            ]
            argv = receipt.get("argv")
            if (
                not isinstance(argv, list)
                or argv[: len(prefix)] != prefix
                or receipt.get("cwd") != str(package_worktree)
                or len(argv[len(prefix) :]) % 2
                or any(
                    argv[index] != "--config"
                    for index in range(len(prefix), len(argv), 2)
                )
            ):
                raise ReviewError(
                    f"qualification package command drifted: {receipt_name}"
                )
            observed_configs = argv[len(prefix) + 1 :: 2]
            expected_configs = {
                (
                    f"patch.crates-io.{dependency}.path="
                    f"{json.dumps(str(package_worktree / 'crates' / dependency))}"
                )
                for dependency in EXPECTED_RELEASE_CRATES
                if dependency != crate
            }
            for dependency, source_url, package_path in git_patch_rows:
                encoded_path = json.dumps(str(package_path))
                expected_configs.add(
                    f"patch.crates-io.{dependency}.path={encoded_path}"
                )
                expected_configs.add(
                    f"patch.{json.dumps(source_url)}.{dependency}.path={encoded_path}"
                )
            if (
                len(observed_configs) != len(expected_configs)
                or set(observed_configs) != expected_configs
            ):
                raise ReviewError(
                    f"qualification package patch set is not exact: {receipt_name}"
                )


def validate_cargo_metadata_bindings(
    qualification: dict[str, Any],
    cargo_graph: Any,
) -> None:
    """Bind Cargo metadata paths to the standalone clone and isolated Cargo roots."""

    sandbox = qualification.get("sandbox")
    bindings = sandbox.get("bindings") if isinstance(sandbox, dict) else None
    if not isinstance(bindings, dict):
        raise ReviewError("qualification Cargo metadata bindings are missing")
    worktree = _absolute_identity_path(
        bindings.get("candidate_worktree"), "candidate worktree"
    )
    cargo_home = _absolute_identity_path(bindings.get("cargo_home"), "Cargo home")
    cargo_target = _absolute_identity_path(
        bindings.get("cargo_target_directory"), "Cargo target directory"
    )
    validate_cargo_graph_paths(
        cargo_graph,
        workspace_root=worktree,
        target_directory=cargo_target,
    )

    registry_root = cargo_home / "registry" / "src"
    git_root = cargo_home / "git" / "checkouts"
    for package in getattr(cargo_graph, "packages", ()):
        name = getattr(package, "name", None)
        version = getattr(package, "version", None)
        source = getattr(package, "source", None)
        workspace = getattr(package, "workspace", None)
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(version, str)
            or not version
            or type(workspace) is not bool
        ):
            raise ReviewError("qualification Cargo package path identity is malformed")
        manifest = _absolute_identity_path(
            getattr(package, "manifest_path", None),
            f"Cargo package manifest for {name}",
        )
        if manifest.name != "Cargo.toml":
            raise ReviewError(f"qualification Cargo manifest name drifted: {name}")
        package_root = manifest.parent

        if workspace:
            expected_manifest = worktree / "crates" / name / "Cargo.toml"
            if source is not None or manifest != expected_manifest:
                raise ReviewError(
                    f"qualification workspace manifest escapes the candidate clone: {name}"
                )
        elif source == "registry+https://github.com/rust-lang/crates.io-index":
            try:
                relative = manifest.relative_to(registry_root)
            except ValueError as error:
                raise ReviewError(
                    f"qualification registry manifest escapes Cargo home: {name}"
                ) from error
            if (
                len(relative.parts) != 3
                or re.fullmatch(r"index\.crates\.io-[0-9a-f]{16}", relative.parts[0])
                is None
                or relative.parts[1] != f"{name}-{version}"
                or relative.parts[2] != "Cargo.toml"
            ):
                raise ReviewError(
                    f"qualification registry manifest layout drifted: {name}"
                )
        elif isinstance(source, str) and source.startswith("git+"):
            try:
                relative = manifest.relative_to(git_root)
            except ValueError as error:
                raise ReviewError(
                    f"qualification Git manifest escapes Cargo home: {name}"
                ) from error
            if (
                len(relative.parts) < 3
                or re.fullmatch(r".+-[0-9a-f]{16}", relative.parts[0]) is None
                or re.fullmatch(r"[0-9a-f]{7,40}", relative.parts[1]) is None
                or relative.parts[-1] != "Cargo.toml"
            ):
                raise ReviewError(f"qualification Git manifest layout drifted: {name}")
        else:
            raise ReviewError(
                f"qualification Cargo package has another path source: {name}"
            )

        components = getattr(package, "target_components", ())
        if not isinstance(components, tuple):
            raise ReviewError(f"qualification Cargo target set is malformed: {name}")
        for component in components:
            source_path = _absolute_identity_path(
                getattr(component, "source_path", None),
                f"Cargo target source for {name}",
            )
            if not _path_is_within(source_path, package_root):
                raise ReviewError(
                    f"qualification Cargo target escapes its package: {name}"
                )


def validate_supply_chain_report_records(
    qualification: dict[str, Any],
    manifest_artifacts: dict[str, dict[str, Any]],
    auxiliary_receipts: dict[str, dict[str, Any]],
) -> None:
    """Bind each retained supply-chain report to its declared process stream."""

    sandbox = qualification.get("sandbox")
    bindings = sandbox.get("bindings") if isinstance(sandbox, dict) else None
    if not isinstance(bindings, dict):
        raise ReviewError("qualification report sandbox binding is missing")
    metadata_tool_input = Path(bindings["reproducibility_root"]) / "cargo-metadata.json"
    license_inventory_argv = [
        "cargo",
        "deny",
        "--offline",
        "--all-features",
        "--locked",
        "list",
        "--metadata-path",
        str(metadata_tool_input),
        "--format",
        "json",
        "--layout",
        "crate",
    ]
    license_argv = [
        "cargo",
        "deny",
        "--offline",
        "--format",
        "json",
        "--all-features",
        "--locked",
        "check",
        "--metadata-path",
        str(metadata_tool_input),
        "licenses",
    ]
    vulnerability_argv = [
        "cargo",
        "audit",
        "--no-fetch",
        "--stale",
        "--no-yanked",
        "--ignore",
        IGNORED_ADVISORY,
        "--format",
        "json",
    ]
    report_contracts = (
        (
            "license_inventory",
            "reports/license-inventory.json",
            license_inventory_argv,
            "stdout",
            "stderr",
            True,
            "license-inventory",
        ),
        (
            "license_report",
            "reports/license-report.jsonl",
            license_argv,
            "stderr",
            "stdout",
            True,
            "license-report",
        ),
        (
            "vulnerability_report",
            "reports/vulnerability-report.json",
            vulnerability_argv,
            "stdout",
            "stderr",
            False,
            "vulnerability-report",
        ),
    )
    for (
        field,
        relative,
        argv,
        expected_report_stream,
        expected_diagnostics_stream,
        require_empty_diagnostics,
        expected_receipt,
    ) in report_contracts:
        report = qualification.get(field)
        receipt = auxiliary_receipts.get(expected_receipt)
        row = manifest_artifacts.get(relative)
        diagnostics = report.get("diagnostics") if isinstance(report, dict) else None
        expected_fields = {
            "argv",
            "path",
            "sha256",
            "size_bytes",
            "report_stream",
            "receipt",
            "diagnostics",
        }
        if field == "license_inventory":
            expected_fields.add("scope")
        if (
            not isinstance(report, dict)
            or set(report) != expected_fields
            or (
                field == "license_inventory"
                and report["scope"] != CARGO_DENY_HOST_FILTERED_SCOPE
            )
            or row is None
            or report["argv"] != argv
            or report["path"] != relative
            or (report["sha256"], report["size_bytes"])
            != (row["sha256"], row["size_bytes"])
            or report["report_stream"] != expected_report_stream
            or report["receipt"] != expected_receipt
            or not isinstance(receipt, dict)
            or report["sha256"] != receipt[f"{expected_report_stream}_sha256"]
            or report["size_bytes"] != receipt[f"{expected_report_stream}_size_bytes"]
            or not isinstance(diagnostics, dict)
            or set(diagnostics) != {"stream", "text", "sha256", "size_bytes"}
            or diagnostics["stream"] != expected_diagnostics_stream
            or not isinstance(diagnostics["text"], str)
            or diagnostics["sha256"] != receipt[f"{expected_diagnostics_stream}_sha256"]
            or diagnostics["size_bytes"]
            != receipt[f"{expected_diagnostics_stream}_size_bytes"]
            or receipt.get("_diagnostics_text_sha256")
            != hashlib.sha256(diagnostics["text"].encode("utf-8")).hexdigest()
            or (require_empty_diagnostics and diagnostics["text"] != "")
            or (require_empty_diagnostics and diagnostics["size_bytes"] != 0)
        ):
            raise ReviewError(
                f"qualification {field} is not command-, stream-, and manifest-bound"
            )


def validate_vulnerability_report(document: Any) -> None:
    """Require zero vulnerabilities and the exact reviewed residual warnings."""

    if not isinstance(document, dict) or set(document) != {
        "database",
        "lockfile",
        "settings",
        "vulnerabilities",
        "warnings",
    }:
        raise ReviewError("qualification vulnerability report is malformed")
    if document["database"] != {
        "advisory-count": 1166,
        "last-commit": None,
        "last-updated": None,
    }:
        raise ReviewError("qualification vulnerability report used another database")
    if document["lockfile"] != {"dependency-count": 437}:
        raise ReviewError("qualification vulnerability report used another lockfile")
    if document["settings"] != {
        "target_arch": [],
        "target_os": [],
        "severity": None,
        "ignore": [IGNORED_ADVISORY],
        "informational_warnings": ["unmaintained", "unsound", "notice"],
    }:
        raise ReviewError("qualification vulnerability policy is not exact")
    if document["vulnerabilities"] != {
        "found": False,
        "count": 0,
        "list": [],
    }:
        raise ReviewError("qualification vulnerability report contains a finding")

    warnings = document["warnings"]
    if not isinstance(warnings, dict) or set(warnings) != {"unmaintained"}:
        raise ReviewError("qualification has an unexpected advisory warning class")
    rows = warnings["unmaintained"]
    if not isinstance(rows, list) or len(rows) != len(EXPECTED_ADVISORY_WARNINGS):
        raise ReviewError("qualification advisory warning count is not exact")
    observed: list[tuple[str, str, str]] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "kind",
            "package",
            "advisory",
            "affected",
            "versions",
        }:
            raise ReviewError("qualification advisory warning is malformed")
        package = row["package"]
        advisory = row["advisory"]
        if (
            row["kind"] != "unmaintained"
            or not isinstance(package, dict)
            or not isinstance(advisory, dict)
            or advisory.get("package") != package.get("name")
            or advisory.get("informational") != "unmaintained"
        ):
            raise ReviewError("qualification advisory warning identity is malformed")
        identity = (
            advisory.get("id"),
            package.get("name"),
            package.get("version"),
        )
        if not all(isinstance(value, str) for value in identity):
            raise ReviewError("qualification advisory warning identity is incomplete")
        observed.append(identity)
    if tuple(observed) != EXPECTED_ADVISORY_WARNINGS:
        raise ReviewError("qualification residual advisory warnings are not exact")


def validate_recomputed_acceptance_binding(
    qualification: dict[str, Any],
    acceptance_bytes: bytes,
    recomputed_acceptance: dict[str, Any],
) -> None:
    """Bind the signed acceptance bytes to an independent metric evaluation."""

    if acceptance_bytes != canonical_json(recomputed_acceptance):
        raise ReviewError(
            "candidate acceptance differs from independent evidence recomputation"
        )
    failed = recomputed_acceptance.get("failed_criterion_ids")
    status = recomputed_acceptance.get("status")
    if (
        status not in {"PASS", "FAIL"}
        or not isinstance(failed, list)
        or not all(isinstance(criterion, str) for criterion in failed)
        or qualification.get("acceptance")
        != {
            "path": "candidate-acceptance.json",
            "status": status,
            "failed_criterion_ids": failed,
        }
    ):
        raise ReviewError(
            "qualification acceptance summary differs from retained evidence"
        )


def candidate_source_date_epoch(repo: Path, commit: str) -> int:
    """Read one commit timestamp without incidental signature display."""

    value = str(
        git(
            repo,
            "-c",
            "log.showSignature=false",
            "show",
            "-s",
            "--format=%ct",
            commit,
        )
    ).strip()
    if not re.fullmatch(r"[0-9]+", value):
        raise ReviewError("candidate source timestamp is not canonical")
    return int(value)


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
        "reports/license-inventory.json",
        "reports/license-report.jsonl",
        "reports/vulnerability-report.json",
        "sandbox/candidate.sb",
        "sandbox/dependency-fetch.sb",
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
    focused_check_ids = tuple(
        check.get("id")
        for check in mutation_document.get("focused_checks", [])
        if isinstance(check, dict)
    )
    if focused_check_ids != FROZEN_FOCUSED_MUTATION_CHECK_IDS:
        raise ReviewError("qualification tier has another focused mutation set")
    if len(mutation_artifacts) != FROZEN_MUTATION_ARTIFACT_COUNT:
        raise ReviewError("qualification tier has an incomplete mutation artifact set")

    qualification = load_qualification_json(
        root / "qualification.json", "qualification record"
    )
    if not isinstance(qualification, dict):
        raise ReviewError("qualification record is not a JSON object")
    source_date_epoch = candidate_source_date_epoch(repo, commit)
    config_binding = validate_qualification_record(
        qualification,
        commit=commit,
        tree=tree,
        source_date_epoch=source_date_epoch,
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
    tracked_config_bytes = git_bounded_output(
        repo,
        "show",
        f"{commit}:evidence/galadriel-0.9-candidate.json",
        max_bytes=MAX_REVIEW_INPUT_BYTES,
    )
    accepted_config_bytes = read_bounded_regular_file(
        root / "candidate-evidence/config.json",
        MAX_QUALIFICATION_JSON_BYTES,
        label="accepted candidate evidence config",
        limit_label="qualification-evidence-config-byte",
    )
    evidence_manifest_bytes = read_bounded_regular_file(
        root / "candidate-evidence/manifest.json",
        MAX_QUALIFICATION_JSON_BYTES,
        label="candidate evidence manifest",
        limit_label="qualification-evidence-manifest-byte",
    )
    recomputed_config_binding = validate_evidence_config_bytes(
        tracked_config_bytes,
        accepted_config_bytes,
        evidence_manifest_bytes,
        tracked_relative_path="evidence/galadriel-0.9-candidate.json",
    )
    if recomputed_config_binding != config_binding:
        raise ReviewError(
            "qualification evidence config binding is not independently reproducible"
        )
    accepted_config = load_qualification_json(
        root / "candidate-evidence/config.json",
        "accepted candidate evidence config",
    )
    evidence_summary = load_qualification_json(
        root / "candidate-evidence/summary.json",
        "candidate evidence summary",
    )
    if not isinstance(accepted_config, dict) or not isinstance(evidence_summary, dict):
        raise ReviewError("qualification candidate evidence is malformed")
    recomputed_acceptance = evaluate_acceptance(
        evidence_summary,
        accepted_config,
    )
    (
        sandbox_policy_sha256,
        dependency_fetch_policy_sha256,
    ) = validate_qualification_sandbox(
        qualification,
        qualification_root=root,
        manifest_artifacts=manifest_artifacts,
        repo=repo,
        recorded_root=recorded_root,
    )
    sandbox_bindings = qualification["sandbox"]["bindings"]
    allowed_signers_snapshot = _absolute_recorded_path(
        sandbox_bindings["allowed_signers_snapshot"],
        "qualification allowed-signers snapshot",
    )
    validate_qualification_commands(
        qualification.get("commands"),
        manifest_artifacts=manifest_artifacts,
        qualification_root=root,
        sandbox_policy_sha256=sandbox_policy_sha256,
        dependency_fetch_policy_sha256=dependency_fetch_policy_sha256,
        recorded_root=recorded_root,
        allowed_signers_snapshot=allowed_signers_snapshot,
    )
    auxiliary_receipts = validate_auxiliary_commands(
        qualification,
        manifest_artifacts=manifest_artifacts,
        qualification_root=root,
        sandbox_policy_sha256=sandbox_policy_sha256,
    )
    tools = validate_qualification_tools(qualification)
    validate_qualification_tool_files(qualification)
    validate_qualification_tool_bindings(qualification)
    validate_qualification_environment(qualification, source_date_epoch)
    validate_repository_control(qualification, commit=commit, tree=tree)
    advisory_database = validate_advisory_database(qualification)
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
        or mutation_record["focused_checks"] != 3
        or mutation_record["run_receipts"] != 5
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
        sbom_by_crate[crate] = sbom
    if set(sbom_by_crate) != expected_crates:
        raise ReviewError("qualification SBOM set differs from the release workspace")
    cargo_metadata_record = qualification.get("cargo_metadata")
    cargo_metadata_row = manifest_artifacts.get("cargo-metadata.json")
    metadata_receipt = auxiliary_receipts["cargo-metadata"]
    expected_metadata_argv = [
        "cargo",
        "metadata",
        "--locked",
        "--offline",
        "--all-features",
        "--format-version=1",
    ]
    if (
        not isinstance(cargo_metadata_record, dict)
        or set(cargo_metadata_record)
        != {"argv", "receipt", "path", "sha256", "size_bytes"}
        or cargo_metadata_record["argv"] != expected_metadata_argv
        or cargo_metadata_record["receipt"] != "cargo-metadata"
        or cargo_metadata_record["path"] != "cargo-metadata.json"
        or cargo_metadata_row is None
        or (
            cargo_metadata_record["sha256"],
            cargo_metadata_record["size_bytes"],
        )
        != (cargo_metadata_row["sha256"], cargo_metadata_row["size_bytes"])
        or cargo_metadata_record["sha256"] != metadata_receipt["stdout_sha256"]
        or cargo_metadata_record["size_bytes"] != metadata_receipt["stdout_size_bytes"]
        or metadata_receipt["stderr_size_bytes"] != 0
    ):
        raise ReviewError(
            "qualification Cargo metadata is not receipt- and manifest-bound"
        )
    cargo_metadata_bytes = read_bounded_regular_file(
        root / "cargo-metadata.json",
        MAX_QUALIFICATION_JSON_BYTES,
        label="qualification Cargo metadata",
        limit_label="qualification-metadata-byte",
    )
    cargo_lock_bytes = git_bounded_output(
        repo,
        "show",
        f"{commit}:Cargo.lock",
        max_bytes=MAX_LOCKFILE_BYTES,
    )
    cargo_graph = validate_cargo_metadata(
        cargo_metadata_bytes,
        cargo_lock_bytes,
    )
    validate_cargo_metadata_bindings(qualification, cargo_graph)
    if {
        package.name for package in cargo_graph.packages if package.workspace
    } != expected_crates:
        raise ReviewError(
            "qualification Cargo metadata targets another workspace package set"
        )
    validate_package_patch_receipts(
        qualification,
        auxiliary_receipts,
        cargo_graph,
    )
    for crate, package in package_by_crate.items():
        package_bytes = read_bounded_regular_file(
            root / package["path"],
            MAX_CRATE_ARCHIVE_BYTES,
            label=f"qualification Cargo package {crate}",
            limit_label="qualification-package-byte",
        )
        validate_crate_archive(
            package_bytes,
            crate_name=crate,
            version=VERSION,
            candidate_commit=commit,
            candidate_files=candidate_crate_files(
                repo,
                commit,
                crate,
            ),
        )
    for crate, sbom in sbom_by_crate.items():
        sbom_bytes = read_bounded_regular_file(
            root / sbom["path"],
            MAX_SBOM_BYTES,
            label=f"qualification CycloneDX SBOM {crate}",
            limit_label="qualification-sbom-byte",
        )
        validate_cyclonedx_sbom(
            sbom_bytes,
            cargo_graph,
            workspace_package=crate,
            candidate_commit=commit,
            source_date_epoch=source_date_epoch,
        )

    archive = qualification.get("source_archive")
    archive_path = f"galadriel-{VERSION}.tar.gz"
    archive_row = manifest_artifacts[archive_path]
    archive_receipts = (
        auxiliary_receipts["source-archive-run-1"],
        auxiliary_receipts["source-archive-run-2"],
    )
    if (
        not isinstance(archive, dict)
        or set(archive)
        != {
            "path",
            "sha256",
            "size_bytes",
            "tar_sha256",
            "tar_size_bytes",
            "tracked_entries",
            "prefix",
        }
        or archive.get("path") != archive_path
        or (archive.get("sha256"), archive.get("size_bytes"))
        != (archive_row["sha256"], archive_row["size_bytes"])
        or not isinstance(archive.get("tracked_entries"), int)
        or archive["tracked_entries"] <= 0
        or archive.get("prefix") != f"galadriel-{VERSION}/"
        or not _lower_hex(archive.get("tar_sha256"), 64)
        or type(archive.get("tar_size_bytes")) is not int
        or archive["tar_size_bytes"] <= 0
        or any(
            receipt["stdout_sha256"] != archive["tar_sha256"]
            or receipt["stdout_size_bytes"] != archive["tar_size_bytes"]
            or receipt["stderr_size_bytes"] != 0
            for receipt in archive_receipts
        )
    ):
        raise ReviewError("qualification source archive is not manifest-bound")
    if verify_source_archive(repo, commit, root / archive_path) != archive:
        raise ReviewError(
            "qualification source archive differs from the exact candidate tree"
        )
    reproducibility_pointer = qualification.get("reproducibility")
    if reproducibility_pointer != {"path": "REPRODUCIBILITY.json", "status": "PASS"}:
        raise ReviewError("two-run package/source reproducibility did not pass")
    reproducibility = load_qualification_json(
        root / "REPRODUCIBILITY.json", "qualification reproducibility record"
    )
    if (
        not isinstance(reproducibility, dict)
        or reproducibility.get("schema") != "galadriel.reproducibility-comparison.v1"
        or reproducibility.get("candidate") != {"commit": commit, "tree": tree}
        or reproducibility.get("status") != "PASS"
        or not isinstance(reproducibility.get("comparisons"), list)
    ):
        raise ReviewError("reproducibility record targets another candidate or status")
    comparisons = reproducibility["comparisons"]
    if len(comparisons) != 15:
        raise ReviewError(
            "reproducibility record lacks the exact source, package, and SBOM comparisons"
        )
    expected_comparisons = {
        archive_path: ("source_archive", archive),
    }
    expected_comparisons.update(
        {
            f"{crate}-{VERSION}.crate": ("cargo_package", package)
            for crate, package in package_by_crate.items()
        }
    )
    expected_comparisons.update(
        {
            f"{crate}.cdx.json": ("cyclonedx_sbom", sbom)
            for crate, sbom in sbom_by_crate.items()
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
        expected_row = expected_comparisons.get(name)
        if expected_row is None:
            raise ReviewError(
                "reproducibility comparison contradicts the retained artifact"
            )
        expected_kind, expected = expected_row
        if (
            name in seen_comparisons
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

    provenance = load_qualification_json(
        root / "provenance.json", "qualification provenance"
    )
    expected_products = [
        row for row in manifest["artifacts"] if row["path"] != "provenance.json"
    ]
    independent_allowed_signers = read_bounded_regular_file(
        allowed_signers,
        MAX_SIGNING_KEY_BYTES,
        label="independent allowed-signers file",
        limit_label="independent-allowed-signers-byte",
    )
    expected_builder = {
        "kind": "author-operated sandboxed standalone qualification clone",
        "tools": tools,
        "tool_file_inventory_sha256": hashlib.sha256(
            canonical_json(qualification["tool_files"]["executables"])
        ).hexdigest(),
    }
    expected_invocation = {
        "source_date_epoch": source_date_epoch,
        "deep_campaigns_requested": True,
        "environment_contract_sha256": hashlib.sha256(
            canonical_json(qualification["environment_contract"])
        ).hexdigest(),
        "command_receipts_sha256": hashlib.sha256(
            canonical_json(qualification["commands"])
        ).hexdigest(),
        "auxiliary_receipts_sha256": hashlib.sha256(
            canonical_json(qualification["auxiliary_commands"])
        ).hexdigest(),
        "sandbox_policy_sha256": sandbox_policy_sha256,
        "dependency_fetch_policy_sha256": dependency_fetch_policy_sha256,
        "network_policy": "DENY_EXCEPT_LOCKED_DEPENDENCY_FETCH",
    }
    expected_materials = {
        "candidate_cargo_lock_sha256": candidate_digest(repo, commit, "Cargo.lock"),
        "evidence_config": {
            "path": "evidence/galadriel-0.9-candidate.json",
            "sha256": config_binding["tracked_blob_sha256"],
        },
        "mutation_manifest_sha256": mutation_record["manifest_sha256"],
        "mutation_signature_sha256": manifest_artifacts["mutation/manifest.json.sig"][
            "sha256"
        ],
        "independent_allowed_signers_sha256": hashlib.sha256(
            independent_allowed_signers
        ).hexdigest(),
        "advisory_database": advisory_database,
    }
    if (
        not isinstance(provenance, dict)
        or set(provenance)
        != {
            "schema",
            "release",
            "candidate",
            "builder",
            "invocation",
            "materials",
            "products",
        }
        or provenance.get("schema") != "galadriel.slsa-provenance.v2"
        or provenance.get("release") != VERSION
        or provenance.get("candidate")
        != {
            "repository": CANONICAL_REPOSITORY,
            "commit": commit,
            "tree": tree,
        }
        or provenance.get("builder") != expected_builder
        or provenance.get("invocation") != expected_invocation
        or provenance.get("materials") != expected_materials
        or provenance.get("products") != expected_products
    ):
        raise ReviewError(
            "qualification provenance contradicts its candidate or materials"
        )

    validate_supply_chain_report_records(
        qualification,
        manifest_artifacts,
        auxiliary_receipts,
    )
    license_inventory_bytes = read_bounded_regular_file(
        root / "reports/license-inventory.json",
        MAX_LICENSE_REPORT_BYTES,
        label="qualification license inventory",
        limit_label="qualification-license-inventory-byte",
    )
    validate_cargo_deny_license_inventory(
        license_inventory_bytes,
        cargo_graph,
        scope=CARGO_DENY_HOST_FILTERED_SCOPE,
    )
    license_policy_bytes = read_bounded_regular_file(
        root / "reports/license-report.jsonl",
        MAX_LICENSE_REPORT_BYTES,
        label="qualification license policy report",
        limit_label="qualification-license-policy-byte",
    )
    validate_cargo_deny_license_policy_jsonl(license_policy_bytes)
    vulnerability = load_qualification_json(
        root / "reports/vulnerability-report.json",
        "qualification vulnerability report",
        max_bytes=MAX_QUALIFICATION_REPORT_BYTES,
    )
    validate_vulnerability_report(vulnerability)

    acceptance = load_qualification_json(
        root / "candidate-acceptance.json", "candidate acceptance record"
    )
    acceptance_bytes = read_bounded_regular_file(
        root / "candidate-acceptance.json",
        MAX_QUALIFICATION_JSON_BYTES,
        label="candidate acceptance record",
        limit_label="qualification-acceptance-byte",
    )
    validate_recomputed_acceptance_binding(
        qualification,
        acceptance_bytes,
        recomputed_acceptance,
    )
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
    actual = read_bounded_regular_file(
        root / "SHA256SUMS",
        MAX_QUALIFICATION_CHECKSUM_BYTES,
        label="checksum inventory",
        limit_label="checksum-inventory-byte",
    )
    if actual != expected:
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
    pre_publish_guard: Callable[[], None],
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
        publish_staged_output(
            output,
            final_output,
            pre_publish_guard=pre_publish_guard,
        )
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
    parser.add_argument(
        "--allowed-signers",
        required=True,
        help="independently obtained allowed-signers trust root",
    )
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
    allowed_signers_source = absolute_path_without_final_resolution(
        arguments.allowed_signers
    )
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
        if allowed_signers_source == repo or repo in allowed_signers_source.parents:
            raise ReviewError(
                "--allowed-signers must be outside the candidate repository"
            )
        if (
            allowed_signers_source == qualification_root
            or qualification_root in allowed_signers_source.parents
        ):
            raise ReviewError("--allowed-signers must be independent of qualification")
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
        signing_key_source = finalization_signing_key_source(
            arguments.signing_key,
            repo=repo,
            qualification_root=qualification_root,
            final_output=final_output,
            snapshot_parent=snapshot_parent,
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
        allowed_signers = snapshots / "ALLOWED_SIGNERS"
        expected_signer_metadata = snapshot_independent_allowed_signers(
            allowed_signers_source, allowed_signers
        )
        signing_key, signing_key_signer = snapshot_agent_backed_public_signing_key(
            signing_key_source,
            snapshots / "SIGNING_KEY.pub",
        )
        signing_key_snapshot = signing_key
        initial_candidate_state = finalization_candidate_control(
            repo,
            expected_commit=arguments.candidate,
            expected_tree=None,
            required_branch=arguments.require_branch or None,
        )
        initial_tree = initial_candidate_state["control"]["tree"]
        initial_branch = initial_candidate_state["branch"]
        head = arguments.candidate
        branch = initial_branch
        if signing_key_signer != expected_signer_metadata:
            raise ReviewError(
                "signing-key public handle differs from the independent trust root"
            )
        tracked_signer = snapshots / "TRACKED_ALLOWED_SIGNERS"
        tracked_signer.write_bytes(
            bytes(git(repo, "show", f"{head}:{ALLOWED_SIGNERS}", text=False))
        )
        assert_tracked_allowed_signer(tracked_signer, expected_signer_metadata)
        tree = verify_candidate_commit(repo, head, allowed_signers)
        if tree != initial_tree:
            raise ReviewError("candidate tree changed during finalization")

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

        def require_unchanged_candidate() -> None:
            finalization_candidate_control(
                repo,
                expected_commit=head,
                expected_tree=tree,
                required_branch=branch,
                expected_state=initial_candidate_state,
            )

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
            pre_publish_guard=require_unchanged_candidate,
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
