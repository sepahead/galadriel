#!/usr/bin/env python3
"""Run one exact broad mutation shard in an isolated command environment."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

from common import (
    ReviewError,
    assert_no_replace_refs,
    canonical_json,
    git,
    git_bounded_output,
    read_bounded_regular_file,
)
from check_public_api import bounded_diagnostic
from qualify_candidate import (
    build_qualification_environment,
    reject_cargo_configuration,
)
from release_assurance import (
    BROAD_MUTATION_RECEIPT,
    CARGO_IDENTITY,
    CARGO_MUTANTS_IDENTITY,
    FOCUSED_MUTATION_RECEIPT,
    GIT_OBJECT,
    MUTATION_BASELINE_COMMIT,
    MUTATION_DIFF_OPTIONS,
    MUTATION_ENVIRONMENT_CONTRACT,
    MUTATION_LIVENESS_CHECKS,
    MUTATION_PATH_TOOLS,
    RUSTC_IDENTITY,
    broad_mutation_command,
    run_bounded_host_command,
    sha256_bytes,
    validate_broad_mutation_receipt,
    validate_mutation_outcomes,
)


SHARDS = ("0/4", "1/4", "2/4", "3/4")
MAX_SUBJECT_BYTES = 4 * 1024
MAX_CHECKSUM_BYTES = 4 * 1024
MAX_RECEIPT_BYTES = 1024 * 1024
MAX_OUTCOMES_BYTES = 32 * 1024 * 1024
MAX_DIFF_BYTES = 128 * 1024 * 1024
MAX_UNTRACKED_INVENTORY_BYTES = 16 * 1024 * 1024
MAX_RUN_INPUT_BYTES = MAX_DIFF_BYTES + MAX_OUTCOMES_BYTES + MAX_RECEIPT_BYTES
MAX_IDENTITY_STDOUT_BYTES = 64 * 1024
MAX_IDENTITY_STDERR_BYTES = 64 * 1024
IDENTITY_TIMEOUT_SECONDS = 120
MAX_FETCH_STDOUT_BYTES = 8 * 1024 * 1024
MAX_FETCH_STDERR_BYTES = 8 * 1024 * 1024
FETCH_TIMEOUT_SECONDS = 600
MAX_MUTATION_STDOUT_BYTES = 64 * 1024 * 1024
MAX_MUTATION_STDERR_BYTES = 64 * 1024 * 1024
MUTATION_TIMEOUT_SECONDS = 6 * 60 * 60
MUTATION_INPUT_FILES = frozenset({"SUBJECT.txt", "git.diff", "git.diff.sha256"})
CANONICAL_REPOSITORY = "sepahead/galadriel"
CANONICAL_WORKFLOW = "Deep quality"
CANONICAL_JOB = "mutation-diff"
CANONICAL_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")
CANONICAL_PULL_REF = re.compile(r"refs/pull/[1-9][0-9]*/merge\Z")


def read_artifact(path: Path, *, max_bytes: int, label: str) -> bytes:
    """Read one bounded mutation artifact through a no-follow descriptor."""

    return read_bounded_regular_file(path, max_bytes=max_bytes, label=label)


def digest_artifact(path: Path, *, max_bytes: int, label: str) -> tuple[str, int]:
    """Return a digest only after one bounded no-follow read."""

    document = read_artifact(path, max_bytes=max_bytes, label=label)
    return sha256_bytes(document), len(document)


def validate_workflow_subject(
    root: Path,
    *,
    commit: str,
    tree: str,
    shard: str,
    diff: bytes,
) -> None:
    """Require the exact workflow subject and checksum bytes."""

    digest = sha256_bytes(diff)
    expected_subject = (
        f"candidate_commit={commit}\n"
        f"candidate_tree={tree}\n"
        f"baseline_commit={MUTATION_BASELINE_COMMIT}\n"
        f"diff_sha256={digest}\n"
        f"shard={shard}\n"
    ).encode("utf-8")
    subject = read_artifact(
        root / "SUBJECT.txt",
        max_bytes=MAX_SUBJECT_BYTES,
        label="mutation subject record",
    )
    if subject != expected_subject:
        raise ReviewError(
            "mutation subject record differs from the exact workflow subject"
        )
    checksum = read_artifact(
        root / "git.diff.sha256",
        max_bytes=MAX_CHECKSUM_BYTES,
        label="mutation Git diff checksum",
    )
    if checksum != f"{digest}  git.diff\n".encode("ascii"):
        raise ReviewError("mutation Git diff checksum is not canonical")


def stage_input_limits(shard: str, *, include_focused: bool = True) -> dict[str, int]:
    """Return every immutable artifact present before a broad mutation run."""

    result = {
        "SUBJECT.txt": MAX_SUBJECT_BYTES,
        "git.diff": MAX_DIFF_BYTES,
        "git.diff.sha256": MAX_CHECKSUM_BYTES,
    }
    if shard == "2/4" and include_focused:
        result[FOCUSED_MUTATION_RECEIPT] = MAX_RECEIPT_BYTES
        result.update(
            {
                f"{check['output']}/mutants.out/outcomes.json": MAX_OUTCOMES_BYTES
                for check in MUTATION_LIVENESS_CHECKS
            }
        )
    return result


def capture_stage_inputs(
    root: Path, shard: str, *, include_focused: bool = True
) -> dict[str, tuple[str, int]]:
    """Capture bounded identities for immutable pre-run artifacts."""

    return {
        relative: digest_artifact(
            root / relative,
            max_bytes=limit,
            label=f"immutable mutation input {relative}",
        )
        for relative, limit in stage_input_limits(
            shard, include_focused=include_focused
        ).items()
    }


def assert_stage_inputs(
    root: Path,
    shard: str,
    expected: dict[str, tuple[str, int]],
    *,
    include_focused: bool = True,
) -> None:
    """Require immutable pre-run artifact bytes after one stage."""

    if capture_stage_inputs(root, shard, include_focused=include_focused) != expected:
        raise ReviewError("immutable mutation inputs changed during the run")


def write_new_file(path: Path, document: bytes, *, label: str) -> None:
    """Create one regular output without following or replacing a file."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise ReviewError(f"cannot create {label}: {error}") from error
    try:
        view = memoryview(document)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ReviewError(f"cannot complete {label}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def bounded_git_output(
    root: Path,
    arguments: list[str] | tuple[str, ...],
    *,
    max_bytes: int,
    context: str,
) -> bytes:
    """Capture bounded Git output with ambient controls disabled."""

    try:
        return git_bounded_output(root, *arguments, max_bytes=max_bytes)
    except ReviewError as error:
        raise ReviewError(f"cannot generate {context}: {error}") from error


def assert_untracked_allowlist(
    root: Path,
    *,
    exact: frozenset[str],
    prefixes: tuple[str, ...],
    required: frozenset[str] = frozenset(),
) -> frozenset[str]:
    """Reject every untracked path outside the exact stage allowlist."""

    encoded = git_bounded_output(
        root,
        "ls-files",
        "--others",
        "-z",
        "--",
        max_bytes=MAX_UNTRACKED_INVENTORY_BYTES,
    )
    try:
        paths = [
            item.decode("utf-8", "strict") for item in encoded.split(b"\0") if item
        ]
    except UnicodeDecodeError as error:
        raise ReviewError("mutation runner found a non-UTF-8 untracked path") from error
    observed: set[str] = set()
    for relative in paths:
        path = Path(relative)
        if (
            path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or relative in observed
        ):
            raise ReviewError(
                f"mutation runner found an unsafe untracked path: {relative!r}"
            )
        if relative not in exact and not any(
            relative.startswith(prefix) for prefix in prefixes
        ):
            raise ReviewError(
                f"mutation runner found an unlisted stage artifact: {relative}"
            )
        try:
            metadata = (root / path).lstat()
        except OSError as error:
            raise ReviewError(
                f"mutation runner cannot inspect untracked path {relative}: {error}"
            ) from error
        if not stat.S_ISREG(metadata.st_mode):
            raise ReviewError(
                f"mutation runner requires regular untracked files: {relative}"
            )
        observed.add(relative)
    missing = sorted(required - observed)
    if missing:
        raise ReviewError(
            "mutation runner lacks required stage artifacts: " + ", ".join(missing)
        )
    return frozenset(observed)


def github_run_provenance(
    environment: Mapping[str, str], commit: str
) -> dict[str, str] | None:
    """Return strict GitHub Actions provenance for the exact candidate."""

    if environment.get("GITHUB_ACTIONS") != "true":
        return None
    required = {
        "run_id": "GITHUB_RUN_ID",
        "run_attempt": "GITHUB_RUN_ATTEMPT",
        "job": "GITHUB_JOB",
        "workflow": "GITHUB_WORKFLOW",
        "repository": "GITHUB_REPOSITORY",
        "ref": "GITHUB_REF",
        "sha": "MUTATION_CANDIDATE_SHA",
    }
    missing = [name for name in required.values() if not environment.get(name)]
    if missing:
        raise ReviewError(
            "GitHub mutation provenance lacks: " + ", ".join(sorted(missing))
        )
    result = {field: environment[name] for field, name in required.items()}
    if any(len(value.encode("utf-8")) > 512 for value in result.values()):
        raise ReviewError("GitHub mutation provenance field exceeds 512 bytes")
    for field in ("run_id", "run_attempt"):
        value = result[field]
        if not CANONICAL_DECIMAL.fullmatch(value) or value == "0" or len(value) > 20:
            raise ReviewError(f"GitHub mutation {field} is not a positive decimal")
    if result["repository"] != CANONICAL_REPOSITORY:
        raise ReviewError("GitHub mutation repository is not canonical")
    if result["workflow"] != CANONICAL_WORKFLOW:
        raise ReviewError("GitHub mutation workflow is not canonical")
    if result["job"] != CANONICAL_JOB:
        raise ReviewError("GitHub mutation job is not canonical")
    ref = result["ref"]
    branch_prefix = "refs/heads/"
    branch = ref.removeprefix(branch_prefix)
    branch_parts = branch.split("/")
    canonical_branch = (
        ref.startswith(branch_prefix)
        and re.fullmatch(r"[A-Za-z0-9._/-]+", branch) is not None
        and ".." not in branch
        and "//" not in branch
        and not branch.endswith(".")
        and all(
            part and not part.startswith(".") and not part.endswith(".lock")
            for part in branch_parts
        )
    )
    if len(ref.encode("utf-8")) > 512 or (
        not canonical_branch and CANONICAL_PULL_REF.fullmatch(ref) is None
    ):
        raise ReviewError("GitHub mutation ref is not canonical")
    event_sha = environment.get("GITHUB_SHA", "")
    if not GIT_OBJECT.fullmatch(event_sha):
        raise ReviewError("GitHub event SHA is not a full lowercase object ID")
    if not GIT_OBJECT.fullmatch(result["sha"]) or result["sha"] != commit:
        raise ReviewError("GitHub mutation candidate SHA differs from checked HEAD")
    return result


def focused_output_prefixes() -> tuple[str, ...]:
    """Return the exact focused cargo-mutants output prefixes."""

    return tuple(f"{check['output']}/" for check in MUTATION_LIVENESS_CHECKS)


def broad_stage_allowlist(
    shard: str, *, output: bool, receipt: bool
) -> tuple[frozenset[str], tuple[str, ...], frozenset[str]]:
    """Return the allowed untracked paths for one broad-run stage."""

    exact = set(MUTATION_INPUT_FILES)
    prefixes: list[str] = []
    if shard == "2/4":
        exact.add(FOCUSED_MUTATION_RECEIPT)
        prefixes.extend(focused_output_prefixes())
    if output:
        prefixes.append("mutants.out/")
    if receipt:
        exact.add(BROAD_MUTATION_RECEIPT)
    required = set(exact)
    if shard == "2/4":
        required.update(
            f"{check['output']}/mutants.out/outcomes.json"
            for check in MUTATION_LIVENESS_CHECKS
        )
    if output:
        required.add("mutants.out/outcomes.json")
    return frozenset(exact), tuple(prefixes), frozenset(required)


def exact_output(
    argv: list[str], *, root: Path, environment: dict[str, str], context: str
) -> str:
    """Return one single-line identity from the isolated environment."""

    process = run_bounded_host_command(
        argv,
        cwd=root,
        environment=environment,
        context=f"mutation tool identity for {context}",
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


def assert_candidate_checkout(
    root: Path,
    commit: str,
    tree: str,
    *,
    allowed_exact: frozenset[str] = frozenset(),
    allowed_prefixes: tuple[str, ...] = (),
    required_untracked: frozenset[str] = frozenset(),
) -> None:
    """Require the same tracked candidate before and after the shard."""

    assert_no_replace_refs(root)
    status = str(git(root, "status", "--porcelain=v1", "--untracked-files=no")).strip()
    observed = (
        str(git(root, "rev-parse", "HEAD^{commit}")).strip(),
        str(git(root, "rev-parse", "HEAD^{tree}")).strip(),
    )
    if status or observed != (commit, tree):
        raise ReviewError("broad mutation runner requires an exact tracked checkout")
    assert_untracked_allowlist(
        root,
        exact=allowed_exact,
        prefixes=allowed_prefixes,
        required=required_untracked,
    )


def run_shard(root: Path, shard: str) -> dict[str, int]:
    """Run and validate one frozen broad mutation shard."""

    if shard not in SHARDS:
        raise ReviewError("broad mutation shard must be 0/4 through 3/4")
    root = root.resolve()
    commit = str(git(root, "rev-parse", "HEAD^{commit}")).strip()
    tree = str(git(root, "rev-parse", "HEAD^{tree}")).strip()
    initial_exact, initial_prefixes, initial_required = broad_stage_allowlist(
        shard, output=False, receipt=False
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

    diff = root / "git.diff"
    output = root / "mutants.out"
    receipt = root / BROAD_MUTATION_RECEIPT
    if not diff.is_file() or diff.is_symlink():
        raise ReviewError("broad mutation runner requires a nonempty regular git.diff")
    retained_diff = read_artifact(
        diff, max_bytes=MAX_DIFF_BYTES, label="broad mutation git.diff"
    )
    if not retained_diff:
        raise ReviewError("broad mutation runner requires a nonempty regular git.diff")
    validate_workflow_subject(
        root,
        commit=commit,
        tree=tree,
        shard=shard,
        diff=retained_diff,
    )
    initial_inputs = capture_stage_inputs(root, shard)
    if output.exists() or output.is_symlink():
        raise ReviewError("broad mutation runner refuses to replace mutants.out")
    if receipt.exists() or receipt.is_symlink():
        raise ReviewError("broad mutation runner refuses to replace its run receipt")
    git(root, "merge-base", "--is-ancestor", MUTATION_BASELINE_COMMIT, commit)
    expected_diff = bounded_git_output(
        root,
        [
            *MUTATION_DIFF_OPTIONS,
            f"{MUTATION_BASELINE_COMMIT}..{commit}",
            "--",
        ],
        max_bytes=MAX_DIFF_BYTES,
        context="canonical broad mutation diff",
    )
    if not expected_diff or retained_diff != expected_diff:
        raise ReviewError("broad mutation runner received other candidate diff bytes")

    source_date_epoch = str(git(root, "show", "-s", "--format=%ct", commit)).strip()
    with tempfile.TemporaryDirectory(prefix="galadriel-broad-mutation-") as directory:
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
        toolchain = {
            "cargo": exact_output(
                ["cargo", "--version"],
                root=root,
                environment=environment,
                context="Cargo",
            ),
            "cargo_mutants": exact_output(
                ["cargo", "mutants", "--version"],
                root=root,
                environment=environment,
                context="cargo-mutants",
            ),
            "cargo_executable": exact_output(
                ["rustup", "which", "cargo"],
                root=root,
                environment=environment,
                context="Cargo executable",
            ),
            "rustc": exact_output(
                ["rustc", "--version"],
                root=root,
                environment=environment,
                context="rustc",
            ),
        }
        if toolchain != {
            "cargo": CARGO_IDENTITY,
            "cargo_executable": toolchain["cargo_executable"],
            "cargo_mutants": CARGO_MUTANTS_IDENTITY,
            "rustc": RUSTC_IDENTITY,
        } or (
            not Path(toolchain["cargo_executable"]).is_absolute()
            or Path(toolchain["cargo_executable"]).name != "cargo"
        ):
            raise ReviewError("broad mutation runner found another Rust toolchain")

        reject_cargo_configuration(root, cargo_home)
        fetch = run_bounded_host_command(
            ["cargo", "fetch", "--locked"],
            cwd=root,
            environment=environment,
            context="broad mutation dependency fetch",
            max_stdout_bytes=MAX_FETCH_STDOUT_BYTES,
            max_stderr_bytes=MAX_FETCH_STDERR_BYTES,
            timeout_seconds=FETCH_TIMEOUT_SECONDS,
        )
        reject_cargo_configuration(root, cargo_home)
        if fetch.returncode != 0:
            raise ReviewError(
                "broad mutation dependency fetch failed: "
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
        assert_stage_inputs(root, shard, initial_inputs)

        command = broad_mutation_command(shard)
        process = run_bounded_host_command(
            command,
            cwd=root,
            environment=environment,
            context=f"broad mutation shard {shard}",
            max_stdout_bytes=MAX_MUTATION_STDOUT_BYTES,
            max_stderr_bytes=MAX_MUTATION_STDERR_BYTES,
            timeout_seconds=MUTATION_TIMEOUT_SECONDS,
        )
        reject_cargo_configuration(root, cargo_home)
        if process.returncode != 0:
            raise ReviewError(
                f"broad mutation shard {shard} exited {process.returncode}"
            )

    output_exact, output_prefixes, output_required = broad_stage_allowlist(
        shard, output=True, receipt=False
    )
    assert_candidate_checkout(
        root,
        commit,
        tree,
        allowed_exact=output_exact,
        allowed_prefixes=output_prefixes,
        required_untracked=output_required,
    )
    assert_stage_inputs(root, shard, initial_inputs)
    outcomes = output / "outcomes.json"
    outcome_bytes = read_artifact(
        outcomes,
        max_bytes=MAX_OUTCOMES_BYTES,
        label=f"broad mutation shard {shard} outcomes",
    )
    if len(expected_diff) + len(outcome_bytes) > MAX_RUN_INPUT_BYTES:
        raise ReviewError("broad mutation run exceeds the aggregate artifact bound")
    counts = validate_mutation_outcomes(outcomes, shard)
    outcome_digest = sha256_bytes(outcome_bytes)
    outcome_size = len(outcome_bytes)
    document = {
        "schema": "galadriel.broad-mutation-run.v2",
        "candidate": {"commit": commit, "tree": tree},
        "baseline_commit": MUTATION_BASELINE_COMMIT,
        "shard": shard,
        "github_run": github_run,
        "git_diff": {
            "path": "git.diff",
            "sha256": sha256_bytes(expected_diff),
            "size_bytes": len(expected_diff),
        },
        "command_argv": command,
        "environment_contract": MUTATION_ENVIRONMENT_CONTRACT,
        "toolchain": toolchain,
        "exit_code": process.returncode,
        "status": "PASS",
        "counts": counts,
        "outcomes": {
            "path": "mutants.out/outcomes.json",
            "sha256": outcome_digest,
            "size_bytes": outcome_size,
        },
    }
    receipt_bytes = canonical_json(document)
    if len(receipt_bytes) > MAX_RECEIPT_BYTES:
        raise ReviewError("broad mutation receipt exceeds its byte bound")
    if (
        len(expected_diff) + len(outcome_bytes) + len(receipt_bytes)
        > MAX_RUN_INPUT_BYTES
    ):
        raise ReviewError("broad mutation run exceeds the aggregate artifact bound")
    write_new_file(
        receipt,
        receipt_bytes,
        label="broad mutation run receipt",
    )
    final_exact, final_prefixes, final_required = broad_stage_allowlist(
        shard, output=True, receipt=True
    )
    assert_candidate_checkout(
        root,
        commit,
        tree,
        allowed_exact=final_exact,
        allowed_prefixes=final_prefixes,
        required_untracked=final_required,
    )
    assert_stage_inputs(root, shard, initial_inputs)
    read_artifact(
        receipt,
        max_bytes=MAX_RECEIPT_BYTES,
        label="broad mutation run receipt",
    )
    validate_broad_mutation_receipt(
        receipt,
        root=root,
        commit=commit,
        tree=tree,
        shard=shard,
        diff=expected_diff,
    )
    assert_candidate_checkout(
        root,
        commit,
        tree,
        allowed_exact=final_exact,
        allowed_prefixes=final_prefixes,
        required_untracked=final_required,
    )
    assert_stage_inputs(root, shard, initial_inputs)
    return counts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--shard", required=True, choices=SHARDS)
    arguments = parser.parse_args()
    try:
        counts = run_shard(Path(arguments.root), arguments.shard)
    except (OSError, ReviewError, UnicodeError, ValueError) as error:
        print(f"broad mutation run failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(counts, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
