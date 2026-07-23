#!/usr/bin/env python3
"""Reject incomplete or drifted focused mutation outcomes in deep-quality CI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

from check_public_api import bounded_diagnostic
from common import ReviewError, assert_no_replace_refs, canonical_json, git
from release_assurance import (
    CARGO_IDENTITY,
    CARGO_MUTANTS_IDENTITY,
    FOCUSED_MUTATION_ENVIRONMENT_CONTRACT,
    FOCUSED_MUTATION_RECEIPT,
    GIT_OBJECT,
    MUTATION_LIVENESS_CHECKS,
    MUTATION_PATH_TOOLS,
    RUSTC_IDENTITY,
    focused_liveness_mutation_command,
    run_bounded_host_command,
    validate_focused_liveness_outcomes,
    validate_focused_mutation_receipt,
)
from qualify_candidate import (
    build_qualification_environment,
    reject_cargo_configuration,
)
from run_broad_mutation import (
    MAX_CHECKSUM_BYTES,
    MAX_DIFF_BYTES,
    MAX_OUTCOMES_BYTES,
    MAX_RECEIPT_BYTES,
    MAX_SUBJECT_BYTES,
    MUTATION_INPUT_FILES,
    assert_stage_inputs,
    assert_untracked_allowlist,
    capture_stage_inputs,
    github_run_provenance,
    read_artifact,
    validate_workflow_subject,
    write_new_file,
)


MAX_FOCUSED_INPUT_BYTES = (
    MAX_DIFF_BYTES
    + MAX_SUBJECT_BYTES
    + MAX_CHECKSUM_BYTES
    + len(MUTATION_LIVENESS_CHECKS) * MAX_OUTCOMES_BYTES
    + MAX_RECEIPT_BYTES
)
MAX_IDENTITY_STDOUT_BYTES = 64 * 1024
MAX_IDENTITY_STDERR_BYTES = 64 * 1024
IDENTITY_TIMEOUT_SECONDS = 120
MAX_FETCH_STDOUT_BYTES = 8 * 1024 * 1024
MAX_FETCH_STDERR_BYTES = 8 * 1024 * 1024
FETCH_TIMEOUT_SECONDS = 600
MAX_MUTATION_STDOUT_BYTES = 64 * 1024 * 1024
MAX_MUTATION_STDERR_BYTES = 64 * 1024 * 1024
FOCUSED_MUTATION_TIMEOUT_SECONDS = 3 * 60 * 60


def focused_stage_allowlist(
    completed: int, *, receipt: bool
) -> tuple[frozenset[str], tuple[str, ...], frozenset[str]]:
    """Return the allowed paths after an exact number of focused checks."""

    if completed < 0 or completed > len(MUTATION_LIVENESS_CHECKS):
        raise ReviewError("focused mutation stage count is invalid")
    exact = set(MUTATION_INPUT_FILES)
    if receipt:
        exact.add(FOCUSED_MUTATION_RECEIPT)
    prefixes = tuple(
        f"{check['output']}/" for check in MUTATION_LIVENESS_CHECKS[:completed]
    )
    required = set(exact)
    required.update(
        f"{check['output']}/mutants.out/outcomes.json"
        for check in MUTATION_LIVENESS_CHECKS[:completed]
    )
    return frozenset(exact), prefixes, frozenset(required)


def exact_output(
    command: list[str],
    root: Path,
    context: str,
    *,
    environment: dict[str, str],
) -> str:
    process = run_bounded_host_command(
        command,
        cwd=root,
        environment=environment,
        context=f"focused mutation tool identity for {context}",
        max_stdout_bytes=MAX_IDENTITY_STDOUT_BYTES,
        max_stderr_bytes=MAX_IDENTITY_STDERR_BYTES,
        timeout_seconds=IDENTITY_TIMEOUT_SECONDS,
    )
    try:
        output = process.stdout.decode("utf-8", "strict").strip()
    except UnicodeDecodeError as error:
        raise ReviewError(f"cannot identify {context}: output is not UTF-8") from error
    if process.returncode != 0 or not output or "\n" in output:
        raise ReviewError(
            f"cannot identify {context}: {bounded_diagnostic(process.stderr)}"
        )
    return output


def candidate_identity(root: Path) -> tuple[str, str]:
    commit = str(git(root, "rev-parse", "HEAD^{commit}")).strip()
    tree = str(git(root, "rev-parse", "HEAD^{tree}")).strip()
    return commit, tree


def assert_candidate_checkout(
    root: Path,
    commit: str,
    tree: str,
    *,
    allowed_exact: frozenset[str] = frozenset(),
    allowed_prefixes: tuple[str, ...] = (),
    required_untracked: frozenset[str] = frozenset(),
) -> None:
    assert_no_replace_refs(root)
    tracked_status = str(
        git(root, "status", "--porcelain=v1", "--untracked-files=no")
    ).strip()
    if tracked_status or candidate_identity(root) != (commit, tree):
        raise ReviewError("focused mutation runner requires an exact tracked checkout")
    assert_untracked_allowlist(
        root,
        exact=allowed_exact,
        prefixes=allowed_prefixes,
        required=required_untracked,
    )


def assert_new_output_path(path: Path, context: str) -> None:
    if path.exists() or path.is_symlink():
        raise ReviewError(f"refusing to replace {context}: {path}")


def run_checks(root: Path, commit: str, tree: str) -> dict[str, dict[str, int]]:
    initial_exact, initial_prefixes, initial_required = focused_stage_allowlist(
        0, receipt=False
    )
    assert_candidate_checkout(
        root,
        commit,
        tree,
        allowed_exact=initial_exact,
        allowed_prefixes=initial_prefixes,
        required_untracked=initial_required,
    )
    github_run = github_run_provenance(os.environ, commit)
    retained_diff = read_artifact(
        root / "git.diff",
        max_bytes=MAX_DIFF_BYTES,
        label="focused mutation git.diff",
    )
    if not retained_diff:
        raise ReviewError(
            "focused mutation runner requires a nonempty regular git.diff"
        )
    validate_workflow_subject(
        root,
        commit=commit,
        tree=tree,
        shard="2/4",
        diff=retained_diff,
    )
    immutable_inputs = capture_stage_inputs(root, "2/4", include_focused=False)
    receipt = root / FOCUSED_MUTATION_RECEIPT
    assert_new_output_path(receipt, "focused mutation receipt")
    for check in MUTATION_LIVENESS_CHECKS:
        output = root / str(check["output"])
        assert_new_output_path(output, "focused mutation output")

    source_date_epoch = str(git(root, "show", "-s", "--format=%ct", commit)).strip()
    with tempfile.TemporaryDirectory(prefix="galadriel-focused-mutation-") as directory:
        private_root = Path(directory)
        environment = build_qualification_environment(
            os.environ,
            private_root=private_root,
            target=private_root / "target",
            source_date_epoch=source_date_epoch,
            required_path_tools=MUTATION_PATH_TOOLS,
        )
        cargo_home = Path(environment["CARGO_HOME"])
        reject_cargo_configuration(root, cargo_home)
        cargo_executable = exact_output(
            ["rustup", "which", "cargo"],
            root,
            "Cargo path",
            environment=environment,
        )
        if (
            not Path(cargo_executable).is_absolute()
            or Path(cargo_executable).name != "cargo"
        ):
            raise ReviewError("rustup returned another Cargo path")
        toolchain = {
            "cargo": exact_output(
                ["cargo", "--version"], root, "Cargo", environment=environment
            ),
            "cargo_executable": cargo_executable,
            "cargo_mutants": exact_output(
                ["cargo", "mutants", "--version"],
                root,
                "cargo-mutants",
                environment=environment,
            ),
            "rustc": exact_output(
                ["rustc", "--version"], root, "rustc", environment=environment
            ),
        }
        if toolchain != {
            "cargo": CARGO_IDENTITY,
            "cargo_executable": cargo_executable,
            "cargo_mutants": CARGO_MUTANTS_IDENTITY,
            "rustc": RUSTC_IDENTITY,
        }:
            raise ReviewError("focused mutation runner found another Rust toolchain")

        reject_cargo_configuration(root, cargo_home)
        fetch = run_bounded_host_command(
            ["cargo", "fetch", "--locked"],
            cwd=root,
            environment=environment,
            context="focused mutation dependency fetch",
            max_stdout_bytes=MAX_FETCH_STDOUT_BYTES,
            max_stderr_bytes=MAX_FETCH_STDERR_BYTES,
            timeout_seconds=FETCH_TIMEOUT_SECONDS,
        )
        reject_cargo_configuration(root, cargo_home)
        if fetch.returncode != 0:
            raise ReviewError(
                "focused mutation dependency fetch failed: "
                + bounded_diagnostic(fetch.stderr or fetch.stdout)
            )
        assert_candidate_checkout(
            root,
            commit,
            tree,
            allowed_exact=initial_exact,
            allowed_prefixes=initial_prefixes,
            required_untracked=initial_required,
        )
        assert_stage_inputs(
            root,
            "2/4",
            immutable_inputs,
            include_focused=False,
        )

        records = []
        summaries: dict[str, dict[str, int]] = {}
        aggregate_size = sum(size for _digest, size in immutable_inputs.values())
        for index, check in enumerate(MUTATION_LIVENESS_CHECKS):
            check_id = str(check["id"])
            command = focused_liveness_mutation_command(check)
            reject_cargo_configuration(root, cargo_home)
            process = run_bounded_host_command(
                command,
                cwd=root,
                environment=environment,
                context=f"focused mutation check {check_id}",
                max_stdout_bytes=MAX_MUTATION_STDOUT_BYTES,
                max_stderr_bytes=MAX_MUTATION_STDERR_BYTES,
                timeout_seconds=FOCUSED_MUTATION_TIMEOUT_SECONDS,
            )
            reject_cargo_configuration(root, cargo_home)
            if process.returncode != 0:
                raise ReviewError(
                    f"focused mutation check {check_id} exited {process.returncode}"
                )
            stage_exact, stage_prefixes, stage_required = focused_stage_allowlist(
                index + 1, receipt=False
            )
            assert_candidate_checkout(
                root,
                commit,
                tree,
                allowed_exact=stage_exact,
                allowed_prefixes=stage_prefixes,
                required_untracked=stage_required,
            )
            assert_stage_inputs(
                root,
                "2/4",
                immutable_inputs,
                include_focused=False,
            )
            relative = f"{check['output']}/mutants.out/outcomes.json"
            outcomes = root / relative
            outcome_bytes = read_artifact(
                outcomes,
                max_bytes=MAX_OUTCOMES_BYTES,
                label=f"focused mutation check {check_id} outcomes",
            )
            aggregate_size += len(outcome_bytes)
            if aggregate_size > MAX_FOCUSED_INPUT_BYTES:
                raise ReviewError(
                    "focused mutation run exceeds the aggregate artifact bound"
                )
            counts = validate_focused_liveness_outcomes(
                outcomes,
                check,
                expected_cargo_executable=cargo_executable,
            )
            digest = hashlib.sha256(outcome_bytes).hexdigest()
            size = len(outcome_bytes)
            summaries[check_id] = counts
            records.append(
                {
                    "id": check_id,
                    "status": "PASS",
                    "command_argv": command,
                    "counts": counts,
                    "outcomes": {
                        "path": relative,
                        "sha256": digest,
                        "size_bytes": size,
                    },
                }
            )
    receipt_bytes = canonical_json(
        {
            "schema": "galadriel.focused-mutation-run.v2",
            "candidate": {"commit": commit, "tree": tree},
            "github_run": github_run,
            "environment_contract": FOCUSED_MUTATION_ENVIRONMENT_CONTRACT,
            "toolchain": toolchain,
            "checks": records,
        }
    )
    if len(receipt_bytes) > MAX_RECEIPT_BYTES:
        raise ReviewError("focused mutation receipt exceeds its byte bound")
    if aggregate_size + len(receipt_bytes) > MAX_FOCUSED_INPUT_BYTES:
        raise ReviewError("focused mutation run exceeds the aggregate artifact bound")
    write_new_file(
        receipt,
        receipt_bytes,
        label="focused mutation run receipt",
    )
    final_exact, final_prefixes, final_required = focused_stage_allowlist(
        len(MUTATION_LIVENESS_CHECKS), receipt=True
    )
    assert_candidate_checkout(
        root,
        commit,
        tree,
        allowed_exact=final_exact,
        allowed_prefixes=final_prefixes,
        required_untracked=final_required,
    )
    assert_stage_inputs(
        root,
        "2/4",
        immutable_inputs,
        include_focused=False,
    )
    read_artifact(
        receipt,
        max_bytes=MAX_RECEIPT_BYTES,
        label="focused mutation run receipt",
    )
    validate_focused_mutation_receipt(
        receipt,
        root=root,
        commit=commit,
        tree=tree,
    )
    assert_candidate_checkout(
        root,
        commit,
        tree,
        allowed_exact=final_exact,
        allowed_prefixes=final_prefixes,
        required_untracked=final_required,
    )
    assert_stage_inputs(
        root,
        "2/4",
        immutable_inputs,
        include_focused=False,
    )
    return summaries


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        default=".",
        help="directory containing the focused cargo-mutants output directories",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="execute all frozen focused commands before validating them",
    )
    parser.add_argument("--candidate-commit")
    parser.add_argument("--candidate-tree")
    arguments = parser.parse_args()
    root = Path(arguments.root).resolve()
    try:
        supplied_identity = (arguments.candidate_commit, arguments.candidate_tree)
        if any(supplied_identity) and not all(supplied_identity):
            raise ReviewError("candidate commit and tree must be supplied together")
        if all(supplied_identity) and (
            not GIT_OBJECT.fullmatch(arguments.candidate_commit)
            or not GIT_OBJECT.fullmatch(arguments.candidate_tree)
        ):
            raise ReviewError("candidate commit and tree must be full object IDs")
        if arguments.run:
            commit, tree = candidate_identity(root)
            if all(supplied_identity) and supplied_identity != (commit, tree):
                raise ReviewError("supplied candidate identity differs from HEAD")
        elif all(supplied_identity):
            commit = arguments.candidate_commit
            tree = arguments.candidate_tree
            if commit is None or tree is None:
                raise ReviewError("candidate commit and tree must be full object IDs")
        else:
            commit, tree = candidate_identity(root)
        if arguments.run:
            summaries = run_checks(root, commit, tree)
        else:
            _receipt, outcomes = validate_focused_mutation_receipt(
                root / FOCUSED_MUTATION_RECEIPT,
                root=root,
                commit=commit,
                tree=tree,
            )
            summaries = {
                check_id: validate_focused_liveness_outcomes(path, check)
                for (check_id, path), check in zip(
                    outcomes.items(), MUTATION_LIVENESS_CHECKS, strict=True
                )
            }
    except (OSError, ReviewError, UnicodeError, ValueError) as error:
        print(f"focused mutation validation failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(summaries, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
