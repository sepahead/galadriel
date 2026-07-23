#!/usr/bin/env python3
"""Assemble and sign exact-candidate broad and focused CI mutation evidence."""

from __future__ import annotations

import argparse
import hashlib
import os
import shlex
import sys
import tempfile
from pathlib import Path
from typing import Any

from common import (
    ReviewError,
    absolute_path_without_final_resolution,
    assert_no_replace_refs,
    canonical_json,
    contained_path,
    git,
)
from release_assurance import (
    AUTHOR,
    BROAD_MUTATION_RECEIPT,
    FOCUSED_MUTATION_RECEIPT,
    MUTATION_BASELINE_COMMIT,
    MUTATION_DIFF_OPTIONS,
    MUTATION_LIVENESS_CHECKS,
    SIGNING_PRINCIPAL,
    VERSION,
    assert_tracked_allowed_signer,
    broad_mutation_command,
    focused_liveness_mutation_command,
    sign_file,
    snapshot_agent_backed_public_signing_key,
    snapshot_independent_allowed_signers,
    validate_broad_mutation_receipt,
    validate_focused_mutation_receipt,
    validate_mutation_evidence,
    validate_mutation_outcomes,
    verify_candidate_commit,
    verify_signature,
)
from run_broad_mutation import (
    MAX_CHECKSUM_BYTES,
    MAX_DIFF_BYTES,
    MAX_OUTCOMES_BYTES,
    MAX_RECEIPT_BYTES,
    MAX_SUBJECT_BYTES,
    bounded_git_output,
    read_artifact,
    validate_workflow_subject,
    write_new_file,
)


BASELINE = MUTATION_BASELINE_COMMIT
ALLOWED_SIGNERS_PATH = "release/0.9.0/audit/ALLOWED_SIGNERS"
SHARDS = ("0/4", "1/4", "2/4", "3/4")
MAX_AGGREGATE_INPUT_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024


class ArtifactBudget:
    """Bound the complete artifact bytes accepted from downloaded shards."""

    def __init__(self, maximum: int) -> None:
        self.maximum = maximum
        self.total = 0

    def snapshot(
        self,
        source_root: Path,
        destination_root: Path,
        relative: str,
        *,
        max_bytes: int,
        label: str,
    ) -> Path:
        """Read one contained artifact once and write an exclusive snapshot."""

        source = contained_path(source_root, relative)
        document = read_artifact(source, max_bytes=max_bytes, label=label)
        self.total += len(document)
        if self.total > self.maximum:
            raise ReviewError(
                f"mutation inputs exceed the {self.maximum}-byte aggregate bound"
            )
        destination = contained_path(destination_root, relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_new_file(destination, document, label=f"{label} snapshot")
        return destination


def external_regular_path(value: str, *, repo: Path, label: str) -> Path:
    """Resolve an external regular-file path without accepting a link."""

    path = Path(value).expanduser().absolute()
    if path.is_symlink():
        raise ReviewError(f"{label} must not be a symbolic link")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ReviewError(f"cannot resolve {label}: {error}") from error
    if resolved == repo or repo in resolved.parents:
        raise ReviewError(f"{label} must be outside the candidate repository")
    if not resolved.is_file() or resolved.is_symlink():
        raise ReviewError(f"{label} must be a regular file")
    return resolved


def copy_bounded(
    source: Path,
    destination: Path,
    *,
    max_bytes: int,
    label: str,
) -> tuple[str, int]:
    """Copy one trusted snapshot through a bounded descriptor."""

    document = read_artifact(source, max_bytes=max_bytes, label=label)
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_new_file(destination, document, label=label)
    return hashlib.sha256(document).hexdigest(), len(document)


def snapshot_ci_shard(
    source: Path,
    destination: Path,
    *,
    shard_id: str,
    budget: ArtifactBudget,
) -> Path:
    """Snapshot only the bounded artifacts used from one downloaded shard."""

    if source.is_symlink() or not source.is_dir():
        raise ReviewError(f"mutation shard directory is missing or unsafe: {source}")
    source = source.resolve(strict=True)
    destination.mkdir(parents=True, exist_ok=False)
    inputs = (
        ("SUBJECT.txt", MAX_SUBJECT_BYTES, f"mutation shard {shard_id} subject"),
        ("git.diff", MAX_DIFF_BYTES, f"mutation shard {shard_id} Git diff"),
        (
            "git.diff.sha256",
            MAX_CHECKSUM_BYTES,
            f"mutation shard {shard_id} Git diff checksum",
        ),
        (
            "mutants.out/outcomes.json",
            MAX_OUTCOMES_BYTES,
            f"mutation shard {shard_id} outcomes",
        ),
        (
            BROAD_MUTATION_RECEIPT,
            MAX_RECEIPT_BYTES,
            f"mutation shard {shard_id} broad receipt",
        ),
    )
    for relative, limit, label in inputs:
        budget.snapshot(
            source,
            destination,
            relative,
            max_bytes=limit,
            label=label,
        )
    if shard_id == "2/4":
        for check in MUTATION_LIVENESS_CHECKS:
            relative = f"{check['output']}/mutants.out/outcomes.json"
            budget.snapshot(
                source,
                destination,
                relative,
                max_bytes=MAX_OUTCOMES_BYTES,
                label=f"focused mutation check {check['id']} outcomes",
            )
        budget.snapshot(
            source,
            destination,
            FOCUSED_MUTATION_RECEIPT,
            max_bytes=MAX_RECEIPT_BYTES,
            label="focused mutation run receipt",
        )
    else:
        unexpected = [source / FOCUSED_MUTATION_RECEIPT]
        unexpected.extend(
            source / str(check["output"]) for check in MUTATION_LIVENESS_CHECKS
        )
        if any(path.exists() or path.is_symlink() for path in unexpected):
            raise ReviewError(
                f"focused mutation artifacts appear in unexpected shard {shard_id}"
            )
    return destination


def parse_subject(path: Path) -> dict[str, str]:
    document = read_artifact(
        path,
        max_bytes=MAX_SUBJECT_BYTES,
        label="mutation subject record",
    )
    result: dict[str, str] = {}
    try:
        lines = document.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise ReviewError("mutation subject record is not valid UTF-8") from error
    for line_number, line in enumerate(lines, 1):
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
        result[shard_id] = Path(directory).expanduser().absolute()
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
) -> tuple[Path, Path, dict[str, Path], Path | None, dict[str, str]]:
    if not source.is_dir() or source.is_symlink():
        raise ReviewError(f"mutation shard directory is missing or unsafe: {source}")
    validate_workflow_subject(
        source,
        commit=commit,
        tree=tree,
        shard=shard_id,
        diff=diff,
    )
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
    retained_diff_bytes = read_artifact(
        retained_diff,
        max_bytes=MAX_DIFF_BYTES,
        label=f"mutation shard {shard_id} Git diff",
    )
    if retained_diff_bytes != diff:
        raise ReviewError(
            f"mutation shard {shard_id} retained different Git diff bytes"
        )
    checksum_bytes = read_artifact(
        retained_checksum,
        max_bytes=MAX_CHECKSUM_BYTES,
        label=f"mutation shard {shard_id} Git diff checksum",
    )
    try:
        checksum_fields = checksum_bytes.decode("ascii", "strict").strip().split()
    except UnicodeDecodeError as error:
        raise ReviewError(
            f"mutation shard {shard_id} diff checksum is not ASCII"
        ) from error
    if (
        len(checksum_fields) != 2
        or checksum_fields[0] != diff_sha256
        or checksum_fields[1].lstrip("*") != "git.diff"
    ):
        raise ReviewError(f"mutation shard {shard_id} diff checksum record is invalid")
    outcomes = source / "mutants.out" / "outcomes.json"
    read_artifact(
        outcomes,
        max_bytes=MAX_OUTCOMES_BYTES,
        label=f"mutation shard {shard_id} outcomes",
    )
    validate_mutation_outcomes(outcomes, shard_id)
    broad_receipt = source / BROAD_MUTATION_RECEIPT
    read_artifact(
        broad_receipt,
        max_bytes=MAX_RECEIPT_BYTES,
        label=f"mutation shard {shard_id} broad receipt",
    )
    broad_document, broad_outcomes = validate_broad_mutation_receipt(
        broad_receipt,
        root=source,
        commit=commit,
        tree=tree,
        shard=shard_id,
        diff=diff,
    )
    if broad_outcomes != outcomes.resolve():
        raise ReviewError(f"mutation shard {shard_id} differs from its run receipt")
    github_run = broad_document.get("github_run")
    if not isinstance(github_run, dict):
        raise ReviewError(f"mutation shard {shard_id} lacks GitHub run provenance")
    receipt = source / FOCUSED_MUTATION_RECEIPT
    if shard_id == "2/4":
        read_artifact(
            receipt,
            max_bytes=MAX_RECEIPT_BYTES,
            label="focused mutation run receipt",
        )
        document, focused = validate_focused_mutation_receipt(
            receipt,
            root=source,
            commit=commit,
            tree=tree,
        )
        if document.get("github_run") != github_run:
            raise ReviewError(
                "focused and broad mutation receipts target different GitHub runs"
            )
        for check_id, target in focused.items():
            read_artifact(
                target,
                max_bytes=MAX_OUTCOMES_BYTES,
                label=f"focused mutation check {check_id} outcomes",
            )
        return outcomes, broad_receipt, focused, receipt, github_run
    if receipt.exists() or receipt.is_symlink():
        raise ReviewError(
            f"focused mutation receipt was archived by unexpected shard {shard_id}"
        )
    for check in MUTATION_LIVENESS_CHECKS:
        target = source / str(check["output"])
        if target.exists() or target.is_symlink():
            raise ReviewError(
                f"focused mutation output was archived by unexpected shard {shard_id}"
            )
    return outcomes, broad_receipt, {}, None, github_run


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--signing-key", required=True)
    parser.add_argument(
        "--allowed-signers",
        required=True,
        help="independently obtained allowed-signers trust root",
    )
    parser.add_argument("--require-branch", default="main")
    parser.add_argument(
        "--shard",
        action="append",
        required=True,
        help="ordered ID=/downloaded/artifact directory; provide 0/4 through 3/4",
    )
    arguments = parser.parse_args()

    repo = Path(arguments.repo).resolve()
    output = absolute_path_without_final_resolution(arguments.out)
    try:
        assert_no_replace_refs(repo)
        shards = parse_shard_arguments(arguments.shard)
        if os.path.lexists(output) or output == repo or repo in output.parents:
            raise ReviewError("--out must be a new directory outside --repo")
        signing_key = external_regular_path(
            arguments.signing_key,
            repo=repo,
            label="signing-key public handle",
        )
        allowed_signers_source = external_regular_path(
            arguments.allowed_signers,
            repo=repo,
            label="independent allowed-signers file",
        )
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
            prefix="galadriel-mutation-assembly-"
        ) as directory:
            private_root = Path(directory)
            allowed_signers = private_root / "ALLOWED_SIGNERS"
            expected_metadata = snapshot_independent_allowed_signers(
                allowed_signers_source,
                allowed_signers,
            )
            signing_key_snapshot, signing_key_metadata = (
                snapshot_agent_backed_public_signing_key(
                    signing_key,
                    private_root / "SIGNING_KEY.pub",
                )
            )
            if signing_key_metadata != expected_metadata:
                raise ReviewError(
                    "signing-key public handle differs from the independent trust root"
                )
            assert_tracked_allowed_signer(
                repo / ALLOWED_SIGNERS_PATH, expected_metadata
            )
            tree = verify_candidate_commit(repo, commit, allowed_signers)
            signing_preflight = private_root / "SIGNING-PREFLIGHT"
            write_new_file(
                signing_preflight,
                canonical_json(
                    {
                        "candidate": {"commit": commit, "tree": tree},
                        "purpose": "mutation-evidence-signing-preflight",
                    }
                ),
                label="mutation evidence signing preflight",
            )
            signing_preflight_signature = sign_file(
                signing_preflight,
                signing_key_snapshot,
                "galadriel-mutation-evidence",
            )
            verify_signature(
                signing_preflight,
                signing_preflight_signature,
                allowed_signers,
                "galadriel-mutation-evidence",
            )

            git(repo, "merge-base", "--is-ancestor", BASELINE, commit)
            diff_argv = ["git", *MUTATION_DIFF_OPTIONS, f"{BASELINE}..{commit}", "--"]
            diff = bounded_git_output(
                repo,
                diff_argv[1:],
                max_bytes=MAX_DIFF_BYTES,
                context="canonical mutation evidence diff",
            )
            if not diff:
                raise ReviewError(
                    "candidate has an empty frozen-baseline mutation diff"
                )

            snapshot_root = private_root / "shards"
            snapshot_root.mkdir()
            budget = ArtifactBudget(MAX_AGGREGATE_INPUT_BYTES)
            outcomes: dict[str, Path] = {}
            broad_receipts: dict[str, Path] = {}
            focused_outcomes: dict[str, Path] = {}
            focused_receipt: Path | None = None
            github_run: dict[str, str] | None = None
            for shard_id, source in shards.items():
                snapshot = snapshot_ci_shard(
                    source,
                    snapshot_root / shard_id.replace("/", "-of-"),
                    shard_id=shard_id,
                    budget=budget,
                )
                (
                    shard_outcomes,
                    shard_broad_receipt,
                    shard_focused,
                    shard_receipt,
                    shard_github_run,
                ) = validate_ci_shard(
                    snapshot,
                    shard_id=shard_id,
                    commit=commit,
                    tree=tree,
                    diff=diff,
                )
                if github_run is None:
                    github_run = shard_github_run
                elif shard_github_run != github_run:
                    raise ReviewError(
                        "mutation shard receipts target different GitHub runs"
                    )
                outcomes[shard_id] = shard_outcomes
                broad_receipts[shard_id] = shard_broad_receipt
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
            if github_run is None or github_run.get("sha") != commit:
                raise ReviewError(
                    "mutation evidence lacks exact-candidate GitHub provenance"
                )

            output.mkdir(parents=True, exist_ok=False)
            retained_diff = output / "git.diff"
            write_new_file(
                retained_diff,
                diff,
                label="retained canonical mutation diff",
            )
            diff_record = {
                "path": retained_diff.relative_to(output).as_posix(),
                "sha256": hashlib.sha256(diff).hexdigest(),
                "size_bytes": len(diff),
            }

            shard_records: list[dict[str, Any]] = []
            broad_receipt_records: list[dict[str, Any]] = []
            for shard_id in SHARDS:
                broad_root = output / "broad-runs" / shard_id.replace("/", "-of-")
                destination = broad_root / "mutants.out" / "outcomes.json"
                digest, size = copy_bounded(
                    outcomes[shard_id],
                    destination,
                    max_bytes=MAX_OUTCOMES_BYTES,
                    label=f"retained broad mutation shard {shard_id} outcomes",
                )
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
                receipt_destination = broad_root / BROAD_MUTATION_RECEIPT
                receipt_digest, receipt_size = copy_bounded(
                    broad_receipts[shard_id],
                    receipt_destination,
                    max_bytes=MAX_RECEIPT_BYTES,
                    label=f"retained broad mutation shard {shard_id} receipt",
                )
                _receipt_document, receipt_outcome = validate_broad_mutation_receipt(
                    receipt_destination,
                    root=broad_root,
                    commit=commit,
                    tree=tree,
                    shard=shard_id,
                    diff=diff,
                )
                if receipt_outcome != destination.resolve():
                    raise ReviewError(
                        f"copied broad mutation receipt {shard_id} targets another outcome"
                    )
                broad_receipt_records.append(
                    {
                        "shard": shard_id,
                        "artifact": {
                            "path": receipt_destination.relative_to(output).as_posix(),
                            "sha256": receipt_digest,
                            "size_bytes": receipt_size,
                        },
                    }
                )

            focused_records: list[dict[str, Any]] = []
            for check in MUTATION_LIVENESS_CHECKS:
                check_id = str(check["id"])
                destination = (
                    output / str(check["output"]) / "mutants.out" / "outcomes.json"
                )
                digest, size = copy_bounded(
                    focused_outcomes[check_id],
                    destination,
                    max_bytes=MAX_OUTCOMES_BYTES,
                    label=f"retained focused mutation check {check_id} outcomes",
                )
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
            receipt_digest, receipt_size = copy_bounded(
                focused_receipt,
                receipt_destination,
                max_bytes=MAX_RECEIPT_BYTES,
                label="retained focused mutation receipt",
            )
            focused_document, _focused_paths = validate_focused_mutation_receipt(
                receipt_destination,
                root=output,
                commit=commit,
                tree=tree,
            )
            if focused_document.get("github_run") != github_run:
                raise ReviewError(
                    "retained focused mutation receipt targets another GitHub run"
                )

            manifest = {
                "schema": "galadriel.mutation-evidence.v5",
                "release": VERSION,
                "author": AUTHOR,
                "candidate": {"commit": commit, "tree": tree},
                "baseline_commit": BASELINE,
                "github_run": github_run,
                "git_diff_argv": diff_argv,
                "git_diff_sha256": hashlib.sha256(diff).hexdigest(),
                "git_diff": diff_record,
                "tool": {"name": "cargo-mutants", "version": "27.1.0"},
                "shards": shard_records,
                "broad_run_receipts": broad_receipt_records,
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
            manifest_bytes = canonical_json(manifest)
            if len(manifest_bytes) > MAX_MANIFEST_BYTES:
                raise ReviewError("mutation evidence manifest exceeds its byte bound")
            manifest_path = output / "mutation-evidence.json"
            write_new_file(
                manifest_path,
                manifest_bytes,
                label="mutation evidence manifest",
            )
            signature_path = sign_file(
                manifest_path,
                signing_key_snapshot,
                "galadriel-mutation-evidence",
            )
            assert_tracked_allowed_signer(
                repo / ALLOWED_SIGNERS_PATH,
                expected_metadata,
            )
            verify_signature(
                manifest_path,
                signature_path,
                allowed_signers,
                "galadriel-mutation-evidence",
            )
            _validated_manifest, validated_artifacts = validate_mutation_evidence(
                manifest_path,
                signature_path,
                allowed_signers=allowed_signers,
                repo=repo,
                commit=commit,
                tree=tree,
            )
            expected_output_files = {
                manifest_path.relative_to(output).as_posix(),
                signature_path.relative_to(output).as_posix(),
                *(
                    artifact.relative_to(output).as_posix()
                    for artifact in validated_artifacts
                ),
            }
            observed_output_files: set[str] = set()
            for path in output.rglob("*"):
                if path.is_symlink():
                    raise ReviewError(
                        "mutation evidence output contains a symbolic link"
                    )
                if path.is_file():
                    observed_output_files.add(path.relative_to(output).as_posix())
                elif not path.is_dir():
                    raise ReviewError(
                        "mutation evidence output contains a special file"
                    )
            if observed_output_files != expected_output_files:
                raise ReviewError("mutation evidence output inventory is not exact")
            assert_no_replace_refs(repo)
            if (
                str(
                    git(
                        repo,
                        "status",
                        "--porcelain=v1",
                        "--untracked-files=all",
                    )
                ).strip()
                or str(git(repo, "rev-parse", "HEAD^{commit}")).strip() != commit
                or str(git(repo, "rev-parse", "HEAD^{tree}")).strip() != tree
            ):
                raise ReviewError(
                    "candidate checkout changed during mutation evidence assembly"
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
