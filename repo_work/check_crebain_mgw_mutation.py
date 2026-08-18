#!/usr/bin/env python3
"""Run and verify the bounded CREBAIN MGW mutation contract.

The gate selects seven scientific-contract functions in one Rust source file.
It binds the complete selected mutant multiset without binding source line
numbers. This permits unrelated line movement while a changed transformation,
function, return type, replacement, genre, or multiplicity fails closed.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import re
import sys
import tempfile
from collections import Counter
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, NamedTuple

from check_public_api import bounded_diagnostic
from common import (
    CANDIDATE_TREE_CONTAINMENT,
    ReviewError,
    assert_no_replace_refs,
    canonical_json,
    git,
    load_json,
    loads_json,
    validate_json_structure,
)
from qualify_candidate import (
    build_qualification_environment,
    reject_cargo_configuration,
)
from release_assurance import (
    CARGO_IDENTITY,
    CARGO_MUTANTS_IDENTITY,
    MUTATION_ENVIRONMENT_CONTRACT,
    MUTATION_PATH_TOOLS,
    RUSTC_IDENTITY,
    run_bounded_host_command,
)
from run_broad_mutation import github_run_provenance, read_artifact, write_new_file


PACKAGE = "galadriel-justify"
PACKAGE_VERSION = "0.9.0"
SOURCE_FILE = "crates/galadriel-justify/src/crebain_mgw.rs"
EXAMINE_RE = (
    "validate_manifest|validate_rows|validate_geometry|"
    "validate_atom_interpretation|validate_estimand_graph|"
    "reconcile_pid_core_source|max_abs"
)
SELECTED_FUNCTIONS = frozenset(EXAMINE_RE.split("|"))
TEST_FILTER = "crebain_mgw::tests"
OUTPUT_DIRECTORY = "mutants-crebain-mgw"
OUTCOMES_RELATIVE = f"{OUTPUT_DIRECTORY}/mutants.out/outcomes.json"
RECEIPT_NAME = "CREBAIN-MGW-MUTATION-RUN.json"
RECEIPT_SCHEMA = "galadriel.crebain-mgw-mutation-run.v1"
GITHUB_JOB = "crebain-mgw-mutation"

EXPECTED_COUNTS = {
    "total_mutants": 149,
    "missed": 0,
    "caught": 146,
    "timeout": 0,
    "unviable": 3,
    "success": 0,
}
EXPECTED_NORMALIZED_MUTANTS_SHA256 = (
    "64b9003123d33a633a949e7fa989237dd2512e03fe18878a9fd01e019c41cc7d"
)
EXPECTED_UNVIABLE = frozenset(
    {
        (
            "reconcile_pid_core_source",
            "-> Result<PidCoreSourceReconciliation>",
            "replace reconcile_pid_core_source -> "
            "Result<PidCoreSourceReconciliation> with Ok(Default::default())",
            "Ok(Default::default())",
            "FnValue",
        ),
        (
            "validate_rows",
            "-> Result<ValidatedColumns>",
            "replace validate_rows -> Result<ValidatedColumns> with "
            "Ok(Default::default())",
            "Ok(Default::default())",
            "FnValue",
        ),
        (
            "validate_atom_interpretation",
            "-> Result<AtomInterpretationReceipt>",
            "replace validate_atom_interpretation -> "
            "Result<AtomInterpretationReceipt> with Ok(Default::default())",
            "Ok(Default::default())",
            "FnValue",
        ),
    }
)

MAX_OUTCOMES_BYTES = 32 * 1024 * 1024
MAX_RECEIPT_BYTES = 1024 * 1024
MAX_LIST_BYTES = 16 * 1024 * 1024
MAX_IDENTITY_BYTES = 64 * 1024
MAX_FETCH_BYTES = 8 * 1024 * 1024
MAX_MUTATION_STREAM_BYTES = 64 * 1024 * 1024
IDENTITY_TIMEOUT_SECONDS = 120
FETCH_TIMEOUT_SECONDS = 600
MUTATION_TIMEOUT_SECONDS = 3 * 60 * 60
TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z"
)


class Span(NamedTuple):
    """One one-based cargo-mutants source span."""

    start_line: int
    start_column: int
    end_line: int
    end_column: int


class Mutant(NamedTuple):
    """One validated cargo-mutants descriptor and its normalized identity."""

    full_identity: tuple[Any, ...]
    normalized: dict[str, str]
    unviable_identity: tuple[str, str, str, str, str]


def _require_keys(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ReviewError(f"{context} has another field set")
    return value


def _text(value: Any, context: str, *, allow_empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or (not allow_empty and not value)
        or value != value.strip()
        or "\0" in value
    ):
        raise ReviewError(f"{context} must be canonical text")
    return value


def _span(value: Any, context: str) -> Span:
    document = _require_keys(value, {"start", "end"}, context)
    coordinates: list[int] = []
    for endpoint in ("start", "end"):
        position = _require_keys(
            document[endpoint], {"line", "column"}, f"{context} {endpoint}"
        )
        for coordinate in ("line", "column"):
            number = position[coordinate]
            if type(number) is not int or number <= 0:
                raise ReviewError(
                    f"{context} {endpoint} {coordinate} must be positive"
                )
            coordinates.append(number)
    result = Span(*coordinates)
    if result[:2] > result[2:]:
        raise ReviewError(f"{context} ends before it starts")
    return result


def _mutant(value: Any, context: str) -> Mutant:
    document = _require_keys(
        value,
        {"name", "package", "file", "function", "span", "replacement", "genre"},
        context,
    )
    package = _text(document["package"], f"{context} package")
    source_file = _text(document["file"], f"{context} file")
    if package != PACKAGE or source_file != SOURCE_FILE:
        raise ReviewError(f"{context} targets another package or source file")

    function = _require_keys(
        document["function"],
        {"function_name", "return_type", "span"},
        f"{context} function",
    )
    function_name = _text(
        function["function_name"], f"{context} function name"
    )
    return_type = _text(
        function["return_type"], f"{context} return type", allow_empty=True
    )
    if function_name not in SELECTED_FUNCTIONS:
        raise ReviewError(f"{context} targets an unselected function")
    function_span = _span(function["span"], f"{context} function span")
    mutation_span = _span(document["span"], f"{context} mutation span")
    if (
        mutation_span[:2] < function_span[:2]
        or mutation_span[2:] > function_span[2:]
    ):
        raise ReviewError(f"{context} mutation span escapes its function")

    name = _text(document["name"], f"{context} name")
    prefix = (
        f"{source_file}:{mutation_span.start_line}:"
        f"{mutation_span.start_column}: "
    )
    if not name.startswith(prefix) or len(name) == len(prefix):
        raise ReviewError(f"{context} name does not bind its source position")
    transformation = name.removeprefix(prefix)
    replacement = _text(
        document["replacement"], f"{context} replacement", allow_empty=True
    )
    genre = _text(document["genre"], f"{context} genre")
    normalized = {
        "package": package,
        "file": source_file,
        "function_name": function_name,
        "return_type": return_type,
        "transformation": transformation,
        "replacement": replacement,
        "genre": genre,
    }
    full_identity = (
        package,
        source_file,
        function_name,
        return_type,
        function_span,
        mutation_span,
        transformation,
        replacement,
        genre,
    )
    unviable_identity = (
        function_name,
        return_type,
        transformation,
        replacement,
        genre,
    )
    return Mutant(full_identity, normalized, unviable_identity)


def normalized_mutant_digest(mutants: list[Mutant]) -> str:
    """Return the line-insensitive digest of one complete mutant multiset."""

    rows = sorted(
        (mutant.normalized for mutant in mutants),
        key=lambda row: (
            row["package"],
            row["file"],
            row["function_name"],
            row["return_type"],
            row["transformation"],
            row["replacement"],
            row["genre"],
        ),
    )
    return hashlib.sha256(canonical_json(rows)).hexdigest()


def _status_is_failure(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"Failure"}
        and type(value["Failure"]) is int
        and value["Failure"] == 101
    )


def _phase(
    value: Any,
    *,
    context: str,
    phase: str,
    status: str,
    expected_cargo_executable: str | None,
) -> None:
    document = _require_keys(
        value, {"phase", "duration", "process_status", "argv"}, context
    )
    if document["phase"] != phase:
        raise ReviewError(f"{context} has another phase")
    duration = document["duration"]
    if (
        not isinstance(duration, (int, float))
        or isinstance(duration, bool)
        or not math.isfinite(duration)
        or duration < 0
    ):
        raise ReviewError(f"{context} has an invalid duration")
    argv = document["argv"]
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(argument, str) and "\0" not in argument for argument in argv)
    ):
        raise ReviewError(f"{context} has an invalid argument vector")
    executable = Path(argv[0])
    if (
        not executable.is_absolute()
        or executable.name != "cargo"
        or (
            expected_cargo_executable is not None
            and argv[0] != expected_cargo_executable
        )
    ):
        raise ReviewError(f"{context} used another Cargo executable")
    expected_arguments = [
        "test",
        *(["--no-run"] if phase == "Build" else []),
        "--verbose",
        f"--package={PACKAGE}@{PACKAGE_VERSION}",
        "--all-features",
        "--locked",
    ]
    if phase == "Test":
        expected_arguments.extend(["--lib", TEST_FILTER])
    if argv[1:] != expected_arguments:
        raise ReviewError(f"{context} used another Cargo command")
    process_status = document["process_status"]
    valid_status = (
        isinstance(process_status, str) and process_status == "Success"
        if status == "success"
        else _status_is_failure(process_status)
    )
    if not valid_status:
        raise ReviewError(f"{context} has another process status")


def _artifact_path(value: Any, *, context: str, directory: str) -> str:
    relative = _text(value, context)
    path = Path(relative)
    if (
        path.is_absolute()
        or ".." in path.parts
        or not relative.startswith(f"{directory}/")
    ):
        raise ReviewError(f"{context} is not a contained {directory} path")
    return relative


def validate_listing(
    document: bytes,
    *,
    expected_count: int = EXPECTED_COUNTS["total_mutants"],
    expected_digest: str = EXPECTED_NORMALIZED_MUTANTS_SHA256,
) -> dict[str, Any]:
    """Validate the exact selected set before mutation execution."""

    try:
        value = loads_json(document)
        validate_json_structure(
            value,
            max_depth=12,
            max_nodes=200_000,
            label="CREBAIN mutation listing",
        )
    except (ValueError, RecursionError, MemoryError) as error:
        raise ReviewError(f"cannot parse CREBAIN mutation listing: {error}") from error
    if not isinstance(value, list) or len(value) != expected_count:
        raise ReviewError("CREBAIN mutation listing has another size")
    mutants: list[Mutant] = []
    full_identities: set[tuple[Any, ...]] = set()
    for index, item in enumerate(value):
        context = f"CREBAIN mutation listing item {index}"
        listing_item = _require_keys(
            item,
            {
                "name",
                "package",
                "file",
                "function",
                "span",
                "replacement",
                "genre",
                "diff",
            },
            context,
        )
        mutant = _mutant(
            {key: item[key] for key in listing_item if key != "diff"}, context
        )
        if mutant.full_identity in full_identities:
            raise ReviewError(f"{context} duplicates another descriptor")
        full_identities.add(mutant.full_identity)
        diff = item["diff"]
        expected_diff_prefix = (
            f"--- {SOURCE_FILE}\n+++ {mutant.normalized['transformation']}\n"
        )
        if not isinstance(diff, str) or not diff.startswith(expected_diff_prefix):
            raise ReviewError(f"{context} has another diff header")
        mutants.append(mutant)
    digest = normalized_mutant_digest(mutants)
    if digest != expected_digest:
        raise ReviewError("CREBAIN normalized mutant set digest differs")
    return {"count": len(mutants), "normalized_sha256": digest}


def validate_outcomes_document(
    value: Any,
    *,
    expected_cargo_executable: str | None = None,
    expected_counts: Mapping[str, int] = EXPECTED_COUNTS,
    expected_digest: str = EXPECTED_NORMALIZED_MUTANTS_SHA256,
    expected_unviable: frozenset[
        tuple[str, str, str, str, str]
    ] = EXPECTED_UNVIABLE,
) -> dict[str, Any]:
    """Validate counts, the complete selected multiset, and all phase results."""

    document = _require_keys(
        value,
        {
            "outcomes",
            "total_mutants",
            "missed",
            "caught",
            "timeout",
            "unviable",
            "success",
            "start_time",
            "end_time",
            "cargo_mutants_version",
        },
        "CREBAIN mutation outcomes",
    )
    if document["cargo_mutants_version"] != "27.1.0":
        raise ReviewError("CREBAIN mutation outcomes use another tool version")
    times: list[datetime] = []
    for field in ("start_time", "end_time"):
        timestamp = document[field]
        if not isinstance(timestamp, str) or TIMESTAMP.fullmatch(timestamp) is None:
            raise ReviewError(f"CREBAIN mutation outcomes have invalid {field}")
        try:
            times.append(datetime.fromisoformat(timestamp.replace("Z", "+00:00")))
        except ValueError as error:
            raise ReviewError(
                f"CREBAIN mutation outcomes have invalid {field}"
            ) from error
    if times[1] < times[0]:
        raise ReviewError("CREBAIN mutation outcomes end before they start")

    observed_counts: dict[str, int] = {}
    for field in EXPECTED_COUNTS:
        count = document[field]
        if type(count) is not int or count < 0:
            raise ReviewError(f"CREBAIN mutation outcomes have invalid {field}")
        observed_counts[field] = count
    if observed_counts != dict(expected_counts):
        raise ReviewError("CREBAIN mutation outcome counts differ")
    if observed_counts["total_mutants"] != sum(
        observed_counts[field]
        for field in ("missed", "caught", "timeout", "unviable", "success")
    ):
        raise ReviewError("CREBAIN mutation outcome counts are inconsistent")

    outcomes = document["outcomes"]
    if (
        not isinstance(outcomes, list)
        or len(outcomes) != observed_counts["total_mutants"] + 1
    ):
        raise ReviewError("CREBAIN mutation outcome list has another size")

    baseline_count = 0
    mutants: list[Mutant] = []
    full_identities: set[tuple[Any, ...]] = set()
    unviable = Counter()
    summaries = Counter()
    artifact_paths: set[str] = set()
    for index, item in enumerate(outcomes):
        context = f"CREBAIN mutation outcome {index}"
        outcome = _require_keys(
            item,
            {"scenario", "summary", "log_path", "diff_path", "phase_results"},
            context,
        )
        scenario = outcome["scenario"]
        phases = outcome["phase_results"]
        if not isinstance(phases, list):
            raise ReviewError(f"{context} phases must be a list")
        if scenario == "Baseline":
            baseline_count += 1
            if (
                baseline_count != 1
                or outcome["summary"] != "Success"
                or outcome["log_path"] != "log/baseline.log"
                or outcome["diff_path"] is not None
                or len(phases) != 2
            ):
                raise ReviewError("CREBAIN mutation baseline differs")
            _phase(
                phases[0],
                context=f"{context} build",
                phase="Build",
                status="success",
                expected_cargo_executable=expected_cargo_executable,
            )
            _phase(
                phases[1],
                context=f"{context} test",
                phase="Test",
                status="success",
                expected_cargo_executable=expected_cargo_executable,
            )
            artifact_paths.add("log/baseline.log")
            continue

        scenario_document = _require_keys(
            scenario, {"Mutant"}, f"{context} scenario"
        )
        mutant = _mutant(scenario_document["Mutant"], f"{context} mutant")
        if mutant.full_identity in full_identities:
            raise ReviewError(f"{context} duplicates another descriptor")
        full_identities.add(mutant.full_identity)
        mutants.append(mutant)

        summary = outcome["summary"]
        if summary not in {"CaughtMutant", "Unviable"}:
            raise ReviewError(f"{context} is missed, timed out, or survived")
        summaries[summary] += 1
        is_unviable = summary == "Unviable"
        if is_unviable:
            unviable[mutant.unviable_identity] += 1
        if len(phases) != (1 if is_unviable else 2):
            raise ReviewError(f"{context} has another phase count")
        _phase(
            phases[0],
            context=f"{context} build",
            phase="Build",
            status="failure" if is_unviable else "success",
            expected_cargo_executable=expected_cargo_executable,
        )
        if not is_unviable:
            _phase(
                phases[1],
                context=f"{context} test",
                phase="Test",
                status="failure",
                expected_cargo_executable=expected_cargo_executable,
            )
        log_path = _artifact_path(
            outcome["log_path"], context=f"{context} log path", directory="log"
        )
        diff_path = _artifact_path(
            outcome["diff_path"], context=f"{context} diff path", directory="diff"
        )
        if log_path in artifact_paths or diff_path in artifact_paths:
            raise ReviewError(f"{context} reuses another artifact path")
        artifact_paths.update((log_path, diff_path))

    if baseline_count != 1:
        raise ReviewError("CREBAIN mutation outcomes lack one successful baseline")
    if summaries != Counter(
        {
            "CaughtMutant": observed_counts["caught"],
            "Unviable": observed_counts["unviable"],
        }
    ):
        raise ReviewError("CREBAIN mutation summaries contradict their counts")
    if unviable != Counter(expected_unviable):
        raise ReviewError("CREBAIN mutation unviable allowlist differs")
    digest = normalized_mutant_digest(mutants)
    if digest != expected_digest:
        raise ReviewError("CREBAIN normalized mutant set digest differs")
    return {
        "counts": observed_counts,
        "normalized_mutants_sha256": digest,
        "unviable": sorted(identity[0] for identity in unviable.elements()),
    }


def validate_outcomes(
    path: Path,
    *,
    expected_cargo_executable: str | None = None,
    expected_counts: Mapping[str, int] = EXPECTED_COUNTS,
    expected_digest: str = EXPECTED_NORMALIZED_MUTANTS_SHA256,
    expected_unviable: frozenset[
        tuple[str, str, str, str, str]
    ] = EXPECTED_UNVIABLE,
) -> dict[str, Any]:
    value = load_json(
        path,
        max_bytes=MAX_OUTCOMES_BYTES,
        max_depth=16,
        max_nodes=500_000,
        label="CREBAIN mutation outcomes",
    )
    return validate_outcomes_document(
        value,
        expected_cargo_executable=expected_cargo_executable,
        expected_counts=expected_counts,
        expected_digest=expected_digest,
        expected_unviable=expected_unviable,
    )


def mutation_command() -> list[str]:
    """Return the hardened canonical mutation command."""

    return [
        "cargo",
        "mutants",
        "--no-config",
        "--package",
        PACKAGE,
        "--file",
        SOURCE_FILE,
        "--re",
        EXAMINE_RE,
        "--line-col",
        "true",
        "--no-shuffle",
        "--baseline",
        "run",
        "--timeout",
        "120",
        "--jobs",
        "1",
        "--all-features",
        "--cargo-arg=--locked",
        "--copy-vcs",
        "true",
        "--colors",
        "never",
        "--output",
        OUTPUT_DIRECTORY,
        "--",
        "--lib",
        TEST_FILTER,
    ]


def listing_command() -> list[str]:
    """Return the non-executing selector preflight command."""

    command = mutation_command()
    baseline = command.index("--baseline")
    return [
        *command[:baseline],
        "--list",
        "--json",
        "--all-features",
        "--cargo-arg=--locked",
        "--colors",
        "never",
    ]


def _exact_output(
    command: list[str],
    *,
    root: Path,
    environment: Mapping[str, str],
    context: str,
) -> str:
    process = run_bounded_host_command(
        command,
        cwd=root,
        environment=environment,
        context=f"CREBAIN mutation {context}",
        max_stdout_bytes=MAX_IDENTITY_BYTES,
        max_stderr_bytes=MAX_IDENTITY_BYTES,
        timeout_seconds=IDENTITY_TIMEOUT_SECONDS,
        containment=CANDIDATE_TREE_CONTAINMENT,
    )
    try:
        output = process.stdout.decode("utf-8", "strict").strip()
    except UnicodeDecodeError as error:
        raise ReviewError(f"CREBAIN mutation {context} is not UTF-8") from error
    if process.returncode != 0 or not output or "\n" in output:
        raise ReviewError(
            f"cannot identify CREBAIN mutation {context}: "
            + bounded_diagnostic(process.stderr or process.stdout)
        )
    return output


def _candidate_identity(root: Path) -> tuple[str, str]:
    return (
        str(git(root, "rev-parse", "HEAD^{commit}")).strip(),
        str(git(root, "rev-parse", "HEAD^{tree}")).strip(),
    )


def _assert_tracked_candidate(
    root: Path, *, commit: str, tree: str, context: str
) -> None:
    assert_no_replace_refs(root)
    status = str(git(root, "status", "--porcelain=v1", "--untracked-files=no")).strip()
    if status or _candidate_identity(root) != (commit, tree):
        raise ReviewError(f"CREBAIN mutation {context} changed tracked candidate state")


def _assert_new_path(path: Path, context: str) -> None:
    if os.path.lexists(path):
        raise ReviewError(f"CREBAIN mutation gate refuses to replace {context}")


def run_gate(root: Path) -> dict[str, Any]:
    """Run the preflight, mutation command, and exact outcome validator."""

    root = root.resolve(strict=True)
    commit, tree = _candidate_identity(root)
    _assert_tracked_candidate(root, commit=commit, tree=tree, context="preflight")
    output = root / OUTPUT_DIRECTORY
    receipt_path = root / RECEIPT_NAME
    _assert_new_path(output, "its output directory")
    _assert_new_path(receipt_path, "its receipt")
    github_run = github_run_provenance(
        os.environ, commit, expected_job=GITHUB_JOB
    )
    if github_run is None:
        raise ReviewError(
            "CREBAIN mutation execution requires exact GitHub Actions provenance"
        )
    source_date_epoch = str(
        git(root, "show", "-s", "--format=%ct", commit)
    ).strip()

    with tempfile.TemporaryDirectory(prefix="galadriel-crebain-mutation-") as directory:
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
        cargo_executable = _exact_output(
            ["rustup", "which", "cargo"],
            root=root,
            environment=environment,
            context="Cargo executable",
        )
        toolchain = {
            "cargo": _exact_output(
                ["cargo", "--version"],
                root=root,
                environment=environment,
                context="Cargo version",
            ),
            "cargo_executable": cargo_executable,
            "cargo_mutants": _exact_output(
                ["cargo", "mutants", "--version"],
                root=root,
                environment=environment,
                context="cargo-mutants version",
            ),
            "rustc": _exact_output(
                ["rustc", "--version"],
                root=root,
                environment=environment,
                context="rustc version",
            ),
        }
        if toolchain != {
            "cargo": CARGO_IDENTITY,
            "cargo_executable": cargo_executable,
            "cargo_mutants": CARGO_MUTANTS_IDENTITY,
            "rustc": RUSTC_IDENTITY,
        } or (
            not Path(cargo_executable).is_absolute()
            or Path(cargo_executable).name != "cargo"
        ):
            raise ReviewError("CREBAIN mutation gate found another toolchain")

        fetch = run_bounded_host_command(
            ["cargo", "fetch", "--locked"],
            cwd=root,
            environment=environment,
            context="CREBAIN mutation dependency fetch",
            max_stdout_bytes=MAX_FETCH_BYTES,
            max_stderr_bytes=MAX_FETCH_BYTES,
            timeout_seconds=FETCH_TIMEOUT_SECONDS,
            containment=CANDIDATE_TREE_CONTAINMENT,
        )
        reject_cargo_configuration(root, cargo_home)
        if fetch.returncode != 0:
            raise ReviewError(
                "CREBAIN mutation dependency fetch failed: "
                + bounded_diagnostic(fetch.stderr or fetch.stdout)
            )
        _assert_tracked_candidate(
            root, commit=commit, tree=tree, context="dependency fetch"
        )

        listing = run_bounded_host_command(
            listing_command(),
            cwd=root,
            environment=environment,
            context="CREBAIN mutation listing",
            max_stdout_bytes=MAX_LIST_BYTES,
            max_stderr_bytes=MAX_IDENTITY_BYTES,
            timeout_seconds=IDENTITY_TIMEOUT_SECONDS,
            containment=CANDIDATE_TREE_CONTAINMENT,
        )
        reject_cargo_configuration(root, cargo_home)
        if listing.returncode != 0:
            raise ReviewError(
                "CREBAIN mutation listing failed: "
                + bounded_diagnostic(listing.stderr or listing.stdout)
            )
        listing_receipt = validate_listing(listing.stdout)
        _assert_tracked_candidate(
            root, commit=commit, tree=tree, context="listing preflight"
        )

        process = run_bounded_host_command(
            mutation_command(),
            cwd=root,
            environment=environment,
            context="CREBAIN mutation execution",
            max_stdout_bytes=MAX_MUTATION_STREAM_BYTES,
            max_stderr_bytes=MAX_MUTATION_STREAM_BYTES,
            timeout_seconds=MUTATION_TIMEOUT_SECONDS,
            containment=CANDIDATE_TREE_CONTAINMENT,
        )
        reject_cargo_configuration(root, cargo_home)
        if process.returncode != 0:
            raise ReviewError(
                f"CREBAIN mutation execution exited {process.returncode}: "
                + bounded_diagnostic(process.stderr or process.stdout)
            )
        _assert_tracked_candidate(
            root, commit=commit, tree=tree, context="execution"
        )
        outcomes_path = root / OUTCOMES_RELATIVE
        outcome_bytes = read_artifact(
            outcomes_path,
            max_bytes=MAX_OUTCOMES_BYTES,
            label="CREBAIN mutation outcomes",
        )
        summary = validate_outcomes(
            outcomes_path, expected_cargo_executable=cargo_executable
        )

    receipt = {
        "schema": RECEIPT_SCHEMA,
        "candidate": {"commit": commit, "tree": tree},
        "github_run": github_run,
        "environment_contract": MUTATION_ENVIRONMENT_CONTRACT,
        "toolchain": toolchain,
        "selector": {
            "package": PACKAGE,
            "source_file": SOURCE_FILE,
            "examine_re": EXAMINE_RE,
            "test_filter": TEST_FILTER,
        },
        "command_argv": mutation_command(),
        "listing": listing_receipt,
        "counts": summary["counts"],
        "normalized_mutants_sha256": summary["normalized_mutants_sha256"],
        "unviable_functions": summary["unviable"],
        "outcomes": {
            "path": OUTCOMES_RELATIVE,
            "sha256": hashlib.sha256(outcome_bytes).hexdigest(),
            "size_bytes": len(outcome_bytes),
        },
    }
    receipt_bytes = canonical_json(receipt)
    if len(receipt_bytes) > MAX_RECEIPT_BYTES:
        raise ReviewError("CREBAIN mutation receipt exceeds its byte bound")
    write_new_file(receipt_path, receipt_bytes, label="CREBAIN mutation receipt")
    return validate_receipt(receipt_path, root=root, commit=commit, tree=tree)


def validate_receipt(
    path: Path,
    *,
    root: Path,
    commit: str | None = None,
    tree: str | None = None,
    expected_counts: Mapping[str, int] = EXPECTED_COUNTS,
    expected_digest: str = EXPECTED_NORMALIZED_MUTANTS_SHA256,
    expected_unviable: frozenset[
        tuple[str, str, str, str, str]
    ] = EXPECTED_UNVIABLE,
) -> dict[str, Any]:
    """Validate one receipt and its exact outcome bytes."""

    document = load_json(
        path,
        max_bytes=MAX_RECEIPT_BYTES,
        max_depth=24,
        max_nodes=100_000,
        label="CREBAIN mutation receipt",
    )
    receipt = _require_keys(
        document,
        {
            "schema",
            "candidate",
            "github_run",
            "environment_contract",
            "toolchain",
            "selector",
            "command_argv",
            "listing",
            "counts",
            "normalized_mutants_sha256",
            "unviable_functions",
            "outcomes",
        },
        "CREBAIN mutation receipt",
    )
    if receipt["schema"] != RECEIPT_SCHEMA:
        raise ReviewError("CREBAIN mutation receipt has another schema")
    candidate = _require_keys(
        receipt["candidate"], {"commit", "tree"}, "CREBAIN mutation candidate"
    )
    if (commit is None) != (tree is None):
        raise ReviewError("CREBAIN mutation candidate override is incomplete")
    if commit is None or tree is None:
        expected_commit, expected_tree = _candidate_identity(root)
    else:
        expected_commit, expected_tree = commit, tree
    if (
        not isinstance(expected_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", expected_commit) is None
        or not isinstance(expected_tree, str)
        or re.fullmatch(r"[0-9a-f]{40}", expected_tree) is None
    ):
        raise ReviewError("CREBAIN mutation candidate identity is invalid")
    if candidate != {"commit": expected_commit, "tree": expected_tree}:
        raise ReviewError("CREBAIN mutation receipt targets another candidate")
    run = _require_keys(
        receipt["github_run"],
        {"run_id", "run_attempt", "job", "workflow", "repository", "ref", "sha"},
        "CREBAIN mutation GitHub run",
    )
    if (
        run["repository"] != "sepahead/galadriel"
        or run["workflow"] != "Deep quality"
        or run["job"] != GITHUB_JOB
        or run["sha"] != expected_commit
    ):
        raise ReviewError("CREBAIN mutation receipt has another GitHub run")
    for field in ("run_id", "run_attempt"):
        value = run[field]
        if (
            not isinstance(value, str)
            or re.fullmatch(r"[1-9][0-9]{0,19}", value) is None
        ):
            raise ReviewError(
                f"CREBAIN mutation GitHub {field} is not a positive decimal"
            )
    for field in ("repository", "workflow", "job", "ref", "sha"):
        value = run[field]
        if (
            not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > 512
            or "\0" in value
        ):
            raise ReviewError(f"CREBAIN mutation GitHub {field} is invalid")
    if re.fullmatch(
        r"(?:refs/heads/[A-Za-z0-9._/-]+|refs/pull/[1-9][0-9]*/merge)",
        run["ref"],
    ) is None or ".." in run["ref"] or "//" in run["ref"]:
        raise ReviewError("CREBAIN mutation GitHub ref is invalid")
    if receipt["environment_contract"] != MUTATION_ENVIRONMENT_CONTRACT:
        raise ReviewError("CREBAIN mutation receipt has another environment contract")
    toolchain = _require_keys(
        receipt["toolchain"],
        {"cargo", "cargo_executable", "cargo_mutants", "rustc"},
        "CREBAIN mutation toolchain",
    )
    cargo_executable = toolchain["cargo_executable"]
    if (
        toolchain
        != {
            "cargo": CARGO_IDENTITY,
            "cargo_executable": cargo_executable,
            "cargo_mutants": CARGO_MUTANTS_IDENTITY,
            "rustc": RUSTC_IDENTITY,
        }
        or not isinstance(cargo_executable, str)
        or not Path(cargo_executable).is_absolute()
        or Path(cargo_executable).name != "cargo"
    ):
        raise ReviewError("CREBAIN mutation receipt has another toolchain")
    selector = _require_keys(
        receipt["selector"],
        {"package", "source_file", "examine_re", "test_filter"},
        "CREBAIN mutation selector",
    )
    if selector != {
        "package": PACKAGE,
        "source_file": SOURCE_FILE,
        "examine_re": EXAMINE_RE,
        "test_filter": TEST_FILTER,
    } or receipt["command_argv"] != mutation_command():
        raise ReviewError("CREBAIN mutation receipt has another command")
    if receipt["listing"] != {
        "count": expected_counts["total_mutants"],
        "normalized_sha256": expected_digest,
    }:
        raise ReviewError("CREBAIN mutation receipt has another listing identity")
    if (
        receipt["counts"] != dict(expected_counts)
        or receipt["normalized_mutants_sha256"] != expected_digest
        or receipt["unviable_functions"]
        != sorted(identity[0] for identity in expected_unviable)
    ):
        raise ReviewError("CREBAIN mutation receipt has another result summary")
    outcomes = _require_keys(
        receipt["outcomes"],
        {"path", "sha256", "size_bytes"},
        "CREBAIN mutation outcome artifact",
    )
    if outcomes["path"] != OUTCOMES_RELATIVE:
        raise ReviewError("CREBAIN mutation receipt targets another outcome path")
    outcome_bytes = read_artifact(
        root / OUTCOMES_RELATIVE,
        max_bytes=MAX_OUTCOMES_BYTES,
        label="CREBAIN mutation outcomes",
    )
    if outcomes != {
        "path": OUTCOMES_RELATIVE,
        "sha256": hashlib.sha256(outcome_bytes).hexdigest(),
        "size_bytes": len(outcome_bytes),
    }:
        raise ReviewError("CREBAIN mutation receipt outcome identity differs")
    validate_outcomes(
        root / OUTCOMES_RELATIVE,
        expected_cargo_executable=cargo_executable,
        expected_counts=expected_counts,
        expected_digest=expected_digest,
        expected_unviable=expected_unviable,
    )
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--run", action="store_true")
    parser.add_argument(
        "--outcomes",
        help="validate a standalone cargo-mutants outcomes.json instead of a receipt",
    )
    arguments = parser.parse_args()
    root = Path(arguments.root).resolve()
    try:
        if arguments.run and arguments.outcomes:
            raise ReviewError("--run and --outcomes are mutually exclusive")
        if arguments.run:
            result = run_gate(root)
        elif arguments.outcomes:
            result = validate_outcomes(Path(arguments.outcomes).resolve(strict=True))
        else:
            result = validate_receipt(root / RECEIPT_NAME, root=root)
        print(canonical_json(result).decode("utf-8"), end="")
        return 0
    except (OSError, ReviewError, ValueError) as error:
        print(f"CREBAIN mutation validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
