#!/usr/bin/env python3
"""Reject incomplete or drifted focused mutation outcomes in deep-quality CI."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from common import ReviewError, canonical_json, git
from release_assurance import (
    CARGO_IDENTITY,
    CARGO_MUTANTS_IDENTITY,
    FOCUSED_MUTATION_RECEIPT,
    GIT_OBJECT,
    MUTATION_LIVENESS_CHECKS,
    RUSTC_IDENTITY,
    digest_file,
    focused_liveness_mutation_command,
    validate_focused_liveness_outcomes,
    validate_focused_mutation_receipt,
)


def exact_output(command: list[str], root: Path, context: str) -> str:
    process = subprocess.run(
        command,
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    output = process.stdout.strip()
    if process.returncode != 0 or not output or "\n" in output:
        raise ReviewError(f"cannot identify {context}: {process.stderr.strip()}")
    return output


def candidate_identity(root: Path) -> tuple[str, str]:
    commit = str(git(root, "rev-parse", "HEAD^{commit}")).strip()
    tree = str(git(root, "rev-parse", "HEAD^{tree}")).strip()
    return commit, tree


def assert_candidate_checkout(root: Path, commit: str, tree: str) -> None:
    tracked_status = str(
        git(root, "status", "--porcelain=v1", "--untracked-files=no")
    ).strip()
    if tracked_status or candidate_identity(root) != (commit, tree):
        raise ReviewError("focused mutation runner requires an exact tracked checkout")


def assert_new_output_path(path: Path, context: str) -> None:
    if path.exists() or path.is_symlink():
        raise ReviewError(f"refusing to replace {context}: {path}")


def run_checks(root: Path, commit: str, tree: str) -> dict[str, dict[str, int]]:
    assert_candidate_checkout(root, commit, tree)
    receipt = root / FOCUSED_MUTATION_RECEIPT
    assert_new_output_path(receipt, "focused mutation receipt")
    for check in MUTATION_LIVENESS_CHECKS:
        output = root / str(check["output"])
        assert_new_output_path(output, "focused mutation output")

    cargo_executable = exact_output(["rustup", "which", "cargo"], root, "Cargo path")
    if not Path(cargo_executable).is_absolute():
        raise ReviewError("rustup returned a non-absolute Cargo path")
    toolchain = {
        "cargo": exact_output(["cargo", "--version"], root, "Cargo"),
        "cargo_executable": cargo_executable,
        "cargo_mutants": exact_output(
            ["cargo", "mutants", "--version"], root, "cargo-mutants"
        ),
        "rustc": exact_output(["rustc", "--version"], root, "rustc"),
    }
    if toolchain != {
        "cargo": CARGO_IDENTITY,
        "cargo_executable": cargo_executable,
        "cargo_mutants": CARGO_MUTANTS_IDENTITY,
        "rustc": RUSTC_IDENTITY,
    }:
        raise ReviewError("focused mutation runner found another Rust toolchain")

    records = []
    summaries: dict[str, dict[str, int]] = {}
    for check in MUTATION_LIVENESS_CHECKS:
        check_id = str(check["id"])
        command = focused_liveness_mutation_command(check)
        process = subprocess.run(
            command,
            cwd=root,
            stdin=subprocess.DEVNULL,
            check=False,
        )
        if process.returncode != 0:
            raise ReviewError(
                f"focused mutation check {check_id} exited {process.returncode}"
            )
        assert_candidate_checkout(root, commit, tree)
        relative = f"{check['output']}/mutants.out/outcomes.json"
        outcomes = root / relative
        counts = validate_focused_liveness_outcomes(
            outcomes,
            check,
            expected_cargo_executable=cargo_executable,
        )
        digest, size = digest_file(outcomes)
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
            "schema": "galadriel.focused-mutation-run.v1",
            "candidate": {"commit": commit, "tree": tree},
            "toolchain": toolchain,
            "checks": records,
        }
    )
    with receipt.open("xb") as handle:
        handle.write(receipt_bytes)
    validate_focused_mutation_receipt(
        receipt,
        root=root,
        commit=commit,
        tree=tree,
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
        help="execute the two frozen focused commands before validating them",
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
