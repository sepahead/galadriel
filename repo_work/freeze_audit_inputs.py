#!/usr/bin/env python3
"""Freeze repository and supplied-handoff inputs into a canonical manifest."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

from common import ReviewError, canonical_json, git, load_json


SCHEMA = "galadriel.frozen-audit-inputs.v1"
RELEASE_INPUTS = (
    ".github/workflows/ci.yml",
    ".github/workflows/deep-quality.yml",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "deny.toml",
    "fuzz/Cargo.toml",
    "fuzz/Cargo.lock",
    "fuzz/deny.toml",
    "release/0.9.0/audit-inputs.json",
    "release/0.9.0/handoff-source.json",
    "release/0.9.0/tasks.json",
    "release/0.9.0/task-closure-plan.json",
    "release/0.9.0/task-dispositions.json",
    "release/0.9.0/requirements-ledger.json",
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
    "docs/ADVISORY-BOUNDARY.md",
    "docs/CLAIMS.md",
    "docs/CONFIGURATION-CONTRACT.md",
    "docs/PRODUCER-CONTRACT.md",
    "docs/RELATED-WORK.md",
    "docs/SECURE-DEPLOYMENT.md",
    "docs/STATE-MACHINE.md",
    "docs/STATISTICAL-CONTRACT.md",
    "docs/THREAT-MODEL.md",
    "deploy/galadriel-security-profile.example.json",
    "scripts/release_audit.py",
    "scripts/secure_deployment.py",
    "repo_work/README.md",
    "repo_work/audit_tracked_files.py",
    "repo_work/build_task_dispositions.py",
    "repo_work/check_feature_graph.py",
    "repo_work/check_frozen_head.py",
    "repo_work/check_public_api.py",
    "repo_work/check_vulnerable_features.py",
    "repo_work/common.py",
    "repo_work/finalize_release.py",
    "repo_work/freeze_audit_inputs.py",
    "repo_work/make_review_packets.py",
    "repo_work/prepare_mutation_evidence.py",
    "repo_work/qualify_candidate.py",
    "repo_work/release_assurance.py",
    "repo_work/reproduce_baseline.py",
    "repo_work/scan_claim_language.py",
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
        path.decode("utf-8", "surrogateescape")
        for path in raw.split(b"\0")
        if path
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

    if not root.is_dir():
        raise ReviewError(f"handoff root is not a directory: {root}")
    resolved_root = root.resolve()
    rows: list[dict[str, Any]] = []
    for directory, names, files in os.walk(root, followlinks=False):
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
            encoded = target.encode("utf-8", "surrogateescape")
            rows.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "kind": "symlink",
                    "target": target,
                    "sha256": digest_bytes(encoded),
                    "size_bytes": len(encoded),
                }
            )
        for name in files:
            path = base / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                target = os.readlink(path)
                rows.append(
                    {
                        "path": relative,
                        "kind": "symlink",
                        "target": target,
                        "sha256": digest_bytes(target.encode("utf-8", "surrogateescape")),
                        "size_bytes": len(target.encode("utf-8", "surrogateescape")),
                    }
                )
                continue
            resolved = path.resolve()
            if resolved_root not in resolved.parents or not path.is_file():
                raise ReviewError(f"handoff path is not a contained regular file: {relative}")
            digest, size = digest_file(path)
            rows.append(
                {
                    "path": relative,
                    "kind": "regular",
                    "sha256": digest,
                    "size_bytes": size,
                }
            )
    if not rows:
        raise ReviewError("handoff root contains no files")
    return rows


def locked_git_dependencies(lock_bytes: bytes) -> list[dict[str, str]]:
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    dependencies: list[dict[str, str]] = []
    for package in lock.get("package", []):
        source = package.get("source", "")
        if not source.startswith("git+"):
            continue
        revision = source.rsplit("#", 1)[-1]
        if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
            raise ReviewError(f"Git dependency is not locked to a full revision: {source}")
        dependencies.append(
            {
                "name": package["name"],
                "version": package["version"],
                "source": source,
                "commit": revision,
            }
        )
    return sorted(dependencies, key=lambda item: (item["name"], item["version"], item["source"]))


def tag_inventory(repo: Path) -> list[dict[str, str | None]]:
    """Record every local tag object and its peeled commit, without abbreviation."""

    raw = str(
        git(
            repo,
            "for-each-ref",
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--handoff-root", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--allowed-signers",
        help="OpenSSH allowed-signers output (default: ALLOWED_SIGNERS beside --out)",
    )
    arguments = parser.parse_args()

    repo = Path(arguments.repo).resolve()
    handoff_root = Path(arguments.handoff_root).resolve()
    output = Path(arguments.out).resolve()
    allowed_signers = (
        Path(arguments.allowed_signers).resolve()
        if arguments.allowed_signers
        else output.parent / "ALLOWED_SIGNERS"
    )
    if output.exists():
        print(f"audit-input freeze failed: output already exists: {output}", file=sys.stderr)
        return 2
    if allowed_signers.exists():
        print(
            f"audit-input freeze failed: allowed-signers output already exists: {allowed_signers}",
            file=sys.stderr,
        )
        return 2
    if output == allowed_signers:
        print(
            "audit-input freeze failed: manifest and allowed-signers paths must differ",
            file=sys.stderr,
        )
        return 2

    try:
        assert_release_tool_coverage(repo)
        handoff_source = load_json(repo / "release/0.9.0/handoff-source.json")
        audit_inputs = load_json(repo / "release/0.9.0/audit-inputs.json")
        baseline_commit = handoff_source["frozen_commit"]
        declared_baseline = audit_inputs["baseline_repository"]
        if baseline_commit != declared_baseline["commit"]:
            raise ReviewError("handoff and release inputs disagree on the frozen commit")
        baseline_tree = str(git(repo, "rev-parse", f"{baseline_commit}^{{tree}}"))
        baseline_tree = baseline_tree.strip()
        if baseline_tree != declared_baseline["tree"]:
            raise ReviewError("declared baseline tree does not match the frozen commit")

        baseline_files: list[dict[str, Any]] = []
        baseline_lock = b""
        for relative in BASELINE_PATHS:
            data = git_blob(repo, baseline_commit, relative)
            if relative == "Cargo.lock":
                baseline_lock = data
            baseline_files.append(
                {
                    "path": relative,
                    "git_blob": str(git(repo, "rev-parse", f"{baseline_commit}:{relative}"))
                    .strip(),
                    "sha256": digest_bytes(data),
                    "size_bytes": len(data),
                }
            )

        release_files: list[dict[str, Any]] = []
        for relative in RELEASE_INPUTS:
            path = repo / relative
            if not path.is_file():
                raise ReviewError(f"release audit input is missing: {relative}")
            digest, size = digest_file(path)
            release_files.append({"path": relative, "sha256": digest, "size_bytes": size})

        handoff_files = strict_relative_files(handoff_root)
        child_archive = next(
            (
                row
                for row in handoff_files
                if row["path"] == handoff_source["child_archive"]
            ),
            None,
        )
        if (
            child_archive is None
            or child_archive["kind"] != "regular"
            or child_archive["sha256"] != handoff_source["child_archive_sha256"]
        ):
            raise ReviewError("supplied Galadriel child archive does not match its frozen digest")
        task_ledger_path = (
            "GALADRIEL_V1_0_CURRENT_HEAD_MAX_EFFORT_HANDOFF/MASTER_TASK_LEDGER.yaml"
        )
        task_ledger = next(
            (row for row in handoff_files if row["path"] == task_ledger_path), None
        )
        if (
            task_ledger is None
            or task_ledger["kind"] != "regular"
            or task_ledger["sha256"] != handoff_source["task_ledger_sha256"]
        ):
            raise ReviewError(
                "supplied Galadriel task ledger does not match its frozen digest"
            )

        signing_key = str(git(repo, "config", "--get", "user.signingkey")).strip()
        if not signing_key:
            raise ReviewError("Git user.signingkey is not configured")
        fingerprint = subprocess.run(
            ["ssh-keygen", "-lf", signing_key, "-E", "sha256"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if fingerprint.returncode != 0:
            raise ReviewError(f"cannot fingerprint signing key: {fingerprint.stderr.strip()}")
        public_key = Path(signing_key).read_text(encoding="utf-8").strip()
        key_fields = public_key.split()
        if len(key_fields) < 2 or not key_fields[0].startswith("ssh-"):
            raise ReviewError("configured signing key is not an OpenSSH public key")
        allowed_signer_line = f"sepmhn@gmail.com {key_fields[0]} {key_fields[1]}\n"

        manifest = {
            "schema": SCHEMA,
            "release": {
                "version": "0.9.0",
                "author": "Sepehr Mahmoudian",
                "doi": None,
                "zenodo": None,
            },
            "baseline": {
                "repository": declared_baseline["url"],
                "commit": baseline_commit,
                "tree": baseline_tree,
                "files": baseline_files,
                "submodules": submodule_inventory(repo, baseline_commit),
                "locked_git_dependencies": locked_git_dependencies(baseline_lock),
            },
            "repository_ref_inputs": {
                "origin": str(git(repo, "remote", "get-url", "origin")).strip(),
                "local_tags_at_freeze": tag_inventory(repo),
                "note": (
                    "Refs are mutable discovery inputs. Object identities and the signed "
                    "candidate tag, not ref names alone, govern release qualification."
                ),
            },
            "handoff": {
                "root_name": handoff_root.name,
                "file_count": len(handoff_files),
                "total_bytes": sum(int(row["size_bytes"]) for row in handoff_files),
                "files": handoff_files,
                "galadriel_child_archive_sha256": handoff_source["child_archive_sha256"],
                "galadriel_task_ledger_sha256": handoff_source["task_ledger_sha256"],
            },
            "release_input_files": release_files,
            "signature_contract": {
                "format": "OpenSSH SSHSIG",
                "namespace": "galadriel-release-audit",
                "principal": "sepmhn@gmail.com",
                "public_key_fingerprint": fingerprint.stdout.strip(),
                "signature_path": output.name + ".sig",
                "allowed_signers_path": allowed_signers.name,
            },
            "scope_note": (
                "This freezes instruction and baseline inputs only. Candidate outputs, "
                "qualification results, independent review, DOI, Zenodo, and deployment "
                "qualification are not asserted by this manifest."
            ),
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        allowed_signers.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(canonical_json(manifest))
        allowed_signers.write_text(allowed_signer_line, encoding="utf-8")
    except (KeyError, OSError, ReviewError, UnicodeError, ValueError) as error:
        print(f"audit-input freeze failed: {error}", file=sys.stderr)
        return 2

    print(output)
    print(allowed_signers)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
