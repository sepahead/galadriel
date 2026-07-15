#!/usr/bin/env python3
"""Assemble and sign exact-candidate broad and focused CI mutation evidence."""

from __future__ import annotations

import argparse
import hashlib
import shlex
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from common import ReviewError, canonical_json, git
from release_assurance import (
    AUTHOR,
    FOCUSED_MUTATION_RECEIPT,
    MUTATION_DIFF_OPTIONS,
    MUTATION_LIVENESS_CHECKS,
    SIGNING_PRINCIPAL,
    VERSION,
    assert_tracked_allowed_signer,
    broad_mutation_command,
    derive_external_allowed_signers,
    digest_file,
    focused_liveness_mutation_command,
    sign_file,
    validate_mutation_outcomes,
    validate_focused_mutation_receipt,
    verify_candidate_commit,
    verify_signature,
)


BASELINE = "94e2f8cc01f352d2bf899b7f656997f143a2588f"
ALLOWED_SIGNERS_PATH = "release/0.9.0/audit/ALLOWED_SIGNERS"
SHARDS = ("0/4", "1/4", "2/4", "3/4")


def parse_subject(path: Path) -> dict[str, str]:
    if not path.is_file() or path.is_symlink():
        raise ReviewError(f"mutation subject record is missing or unsafe: {path}")
    result: dict[str, str] = {}
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line or "=" not in line:
            raise ReviewError(
                f"mutation subject record has a malformed line {line_number}"
            )
        key, value = line.split("=", 1)
        if key in result or not key or not value:
            raise ReviewError(
                f"mutation subject record has a duplicate or empty field: {key!r}"
            )
        result[key] = value
    expected = {
        "candidate_commit",
        "candidate_tree",
        "baseline_commit",
        "diff_sha256",
        "shard",
    }
    if set(result) != expected:
        raise ReviewError("mutation subject record has the wrong field set")
    return result


def parse_shard_arguments(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        shard_id, separator, directory = value.partition("=")
        if (
            not separator
            or shard_id not in SHARDS
            or shard_id in result
            or not directory
        ):
            raise ReviewError(
                "--shard must provide each distinct ID as ID=/downloaded/artifact"
            )
        result[shard_id] = Path(directory).expanduser().resolve()
    if tuple(result) != SHARDS:
        raise ReviewError("--shard arguments must be ordered 0/4 through 3/4")
    return result


def mutation_command(shard_id: str) -> list[str]:
    """Compatibility wrapper for the frozen broad-shard command."""

    return broad_mutation_command(shard_id)


def validate_ci_shard(
    source: Path,
    *,
    shard_id: str,
    commit: str,
    tree: str,
    diff: bytes,
) -> tuple[Path, dict[str, Path], Path | None]:
    if not source.is_dir() or source.is_symlink():
        raise ReviewError(f"mutation shard directory is missing or unsafe: {source}")
    subject = parse_subject(source / "SUBJECT.txt")
    diff_sha256 = hashlib.sha256(diff).hexdigest()
    if subject != {
        "candidate_commit": commit,
        "candidate_tree": tree,
        "baseline_commit": BASELINE,
        "diff_sha256": diff_sha256,
        "shard": shard_id,
    }:
        raise ReviewError(f"mutation shard {shard_id} targets another subject or diff")
    retained_diff = source / "git.diff"
    retained_checksum = source / "git.diff.sha256"
    for path in (retained_diff, retained_checksum):
        if not path.is_file() or path.is_symlink():
            raise ReviewError(f"mutation shard {shard_id} lacks {path.name}")
    if retained_diff.read_bytes() != diff:
        raise ReviewError(
            f"mutation shard {shard_id} retained different Git diff bytes"
        )
    checksum_fields = retained_checksum.read_text(encoding="ascii").strip().split()
    if (
        len(checksum_fields) != 2
        or checksum_fields[0] != diff_sha256
        or checksum_fields[1].lstrip("*") != "git.diff"
    ):
        raise ReviewError(f"mutation shard {shard_id} diff checksum record is invalid")
    outcomes = source / "mutants.out" / "outcomes.json"
    validate_mutation_outcomes(outcomes, shard_id)
    receipt = source / FOCUSED_MUTATION_RECEIPT
    if shard_id == "2/4":
        _document, focused = validate_focused_mutation_receipt(
            receipt,
            root=source,
            commit=commit,
            tree=tree,
        )
        return outcomes, focused, receipt
    if receipt.exists():
        raise ReviewError(
            f"focused mutation receipt was archived by unexpected shard {shard_id}"
        )
    for check in MUTATION_LIVENESS_CHECKS:
        target = source / str(check["output"])
        if target.exists():
            raise ReviewError(
                f"focused mutation output was archived by unexpected shard {shard_id}"
            )
    return outcomes, {}, None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--signing-key", required=True)
    parser.add_argument("--require-branch", default="main")
    parser.add_argument(
        "--shard",
        action="append",
        required=True,
        help="ordered ID=/downloaded/artifact directory; provide 0/4 through 3/4",
    )
    arguments = parser.parse_args()

    repo = Path(arguments.repo).resolve()
    output = Path(arguments.out).resolve()
    signing_key = Path(arguments.signing_key).expanduser().resolve()
    try:
        shards = parse_shard_arguments(arguments.shard)
        if output.exists() or output == repo or repo in output.parents:
            raise ReviewError("--out must be a new directory outside --repo")
        if str(git(repo, "status", "--porcelain=v1", "--untracked-files=all")).strip():
            raise ReviewError("mutation evidence requires a clean candidate checkout")
        commit = str(git(repo, "rev-parse", "HEAD^{commit}")).strip()
        if commit != arguments.candidate:
            raise ReviewError(
                f"candidate mismatch: expected={arguments.candidate} actual={commit}"
            )
        branch = str(git(repo, "branch", "--show-current")).strip()
        if arguments.require_branch and branch != arguments.require_branch:
            raise ReviewError(
                f"candidate branch must be {arguments.require_branch!r}, got {branch!r}"
            )
        with tempfile.TemporaryDirectory(
            prefix="galadriel-mutation-trust-"
        ) as directory:
            allowed_signers = Path(directory) / "ALLOWED_SIGNERS"
            expected_metadata = derive_external_allowed_signers(
                signing_key, allowed_signers
            )
            assert_tracked_allowed_signer(
                repo / ALLOWED_SIGNERS_PATH, expected_metadata
            )
            tree = verify_candidate_commit(repo, commit, allowed_signers)

        git(repo, "merge-base", "--is-ancestor", BASELINE, commit)
        diff_argv = ["git", *MUTATION_DIFF_OPTIONS, f"{BASELINE}..{commit}", "--"]
        diff = bytes(git(repo, *diff_argv[1:], text=False))
        if not diff:
            raise ReviewError("candidate has an empty frozen-baseline mutation diff")
        outcomes: dict[str, Path] = {}
        focused_outcomes: dict[str, Path] = {}
        focused_receipt: Path | None = None
        for shard_id, source in shards.items():
            shard_outcomes, shard_focused, shard_receipt = validate_ci_shard(
                source,
                shard_id=shard_id,
                commit=commit,
                tree=tree,
                diff=diff,
            )
            outcomes[shard_id] = shard_outcomes
            if shard_receipt is not None:
                if focused_receipt is not None:
                    raise ReviewError(
                        "focused mutation receipt appears in multiple shards"
                    )
                focused_receipt = shard_receipt
            for check_id, path in shard_focused.items():
                if check_id in focused_outcomes:
                    raise ReviewError(
                        f"focused mutation check {check_id} appears in multiple shards"
                    )
                focused_outcomes[check_id] = path
        expected_focused = {str(check["id"]) for check in MUTATION_LIVENESS_CHECKS}
        if set(focused_outcomes) != expected_focused:
            raise ReviewError("focused mutation evidence is incomplete")
        if focused_receipt is None:
            raise ReviewError("focused mutation run receipt is missing")

        output.mkdir(parents=True, exist_ok=False)
        shard_records: list[dict[str, Any]] = []
        for shard_id in SHARDS:
            destination = (
                output / "shards" / shard_id.replace("/", "-of-") / "outcomes.json"
            )
            destination.parent.mkdir(parents=True)
            shutil.copyfile(outcomes[shard_id], destination)
            digest, size = digest_file(destination)
            shard_records.append(
                {
                    "id": shard_id,
                    "status": "PASS",
                    "command": shlex.join(mutation_command(shard_id)),
                    "artifact": {
                        "path": destination.relative_to(output).as_posix(),
                        "sha256": digest,
                        "size_bytes": size,
                    },
                }
            )
        focused_records: list[dict[str, Any]] = []
        for check in MUTATION_LIVENESS_CHECKS:
            check_id = str(check["id"])
            destination = (
                output / str(check["output"]) / "mutants.out" / "outcomes.json"
            )
            destination.parent.mkdir(parents=True)
            shutil.copyfile(focused_outcomes[check_id], destination)
            digest, size = digest_file(destination)
            focused_records.append(
                {
                    "id": check_id,
                    "status": "PASS",
                    "source_shard": "2/4",
                    "command": shlex.join(focused_liveness_mutation_command(check)),
                    "artifact": {
                        "path": destination.relative_to(output).as_posix(),
                        "sha256": digest,
                        "size_bytes": size,
                    },
                }
            )
        receipt_destination = output / FOCUSED_MUTATION_RECEIPT
        shutil.copyfile(focused_receipt, receipt_destination)
        validate_focused_mutation_receipt(
            receipt_destination,
            root=output,
            commit=commit,
            tree=tree,
        )
        receipt_digest, receipt_size = digest_file(receipt_destination)
        manifest = {
            "schema": "galadriel.mutation-evidence.v3",
            "release": VERSION,
            "author": AUTHOR,
            "candidate": {"commit": commit, "tree": tree},
            "baseline_commit": BASELINE,
            "git_diff_argv": diff_argv,
            "git_diff_sha256": hashlib.sha256(diff).hexdigest(),
            "tool": {"name": "cargo-mutants", "version": "27.1.0"},
            "shards": shard_records,
            "focused_run_receipt": {
                "source_shard": "2/4",
                "artifact": {
                    "path": FOCUSED_MUTATION_RECEIPT,
                    "sha256": receipt_digest,
                    "size_bytes": receipt_size,
                },
            },
            "focused_checks": focused_records,
        }
        manifest_path = output / "mutation-evidence.json"
        manifest_path.write_bytes(canonical_json(manifest))
        signature_path = sign_file(
            manifest_path, signing_key, "galadriel-mutation-evidence"
        )
        with tempfile.TemporaryDirectory(
            prefix="galadriel-mutation-signature-"
        ) as directory:
            allowed_signers = Path(directory) / "ALLOWED_SIGNERS"
            expected_metadata = derive_external_allowed_signers(
                signing_key, allowed_signers
            )
            assert_tracked_allowed_signer(
                repo / ALLOWED_SIGNERS_PATH, expected_metadata
            )
            verify_signature(
                manifest_path,
                signature_path,
                allowed_signers,
                "galadriel-mutation-evidence",
            )
        print(
            f"signed exact-candidate mutation evidence for {commit} as {SIGNING_PRINCIPAL}: "
            f"{manifest_path}"
        )
        return 0
    except (OSError, ReviewError, UnicodeError, ValueError) as error:
        print(f"mutation evidence assembly failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
