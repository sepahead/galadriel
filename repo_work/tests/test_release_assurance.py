"""Adversarial tests for exact-candidate qualification and finalization."""

from __future__ import annotations

import ast
import copy
import csv
import contextlib
import errno
import hashlib
import io
import json
import os
import selectors
import signal
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import typing
import unittest
from collections import Counter
from collections.abc import Callable, Mapping
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1]
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))

import common as common_helpers  # noqa: E402
from common import (  # noqa: E402
    SAFE_GIT_CONFIGURATION,
    ReviewError,
    canonical_json,
    git as common_git,
)
from check_focused_mutation import assert_new_output_path  # noqa: E402
from finalize_release import (  # noqa: E402
    CLOSURE_MANIFEST,
    CLOSURE_SIGNATURE,
    EXPECTED_QUALIFICATION_TOOLS,
    LOCAL_CONVERGENCE,
    LOCAL_CONVERGENCE_SIGNATURE,
    RELEASE_DECISION,
    RELEASE_DECISION_SIGNATURE,
    PublicationDurabilityError,
    PublicationIntegrityError,
    atomic_rename_no_replace,
    cleanup_finalization_inputs,
    emit_closure_bundle,
    emit_publication_result,
    finalization_candidate_control,
    finalization_signing_key_source,
    main as finalize_release_main,
    publish_staged_output,
    postpublication_cleanup_status,
    qualification_tier_inventory,
    snapshot_qualification_artifact,
    snapshot_signed_qualification_tier,
    validate_candidate_plan_documents,
    validate_finalization_dag_evidence,
    validate_qualification_commands,
    validate_qualification_environment,
    validate_qualification_tools,
    validate_qualification_record,
    validate_supply_chain_report_records,
    verify_sha256sums,
)
from local_convergence import (  # noqa: E402
    CONVERGENCE_ARTIFACT_PATHS,
    CROSS_REPO_REQUIREMENTS,
    MAX_AGGREGATE_ARTIFACT_BYTES,
    MAX_ARTIFACT_BYTES,
    MAX_MANIFEST_BYTES,
    SCHEMA_ID as LOCAL_CONVERGENCE_SCHEMA_ID,
    SCHEMA_PATH as LOCAL_CONVERGENCE_SCHEMA,
    SIGNATURE_NAMESPACE as LOCAL_CONVERGENCE_NAMESPACE,
    artifact_path_parts as local_convergence_artifact_path_parts,
    artifact_records as local_convergence_artifacts,
    build_document as build_local_convergence,
    read_bounded_artifact as read_bounded_local_convergence_artifact,
    validate_document as validate_local_convergence,
    validate_schema as validate_local_convergence_schema,
)
import qualify_candidate as qualifier  # noqa: E402
from qualify_candidate import (  # noqa: E402
    BASE_COMMANDS,
    DEPENDENCY_FETCH_COMMAND_NAMES,
    EXPECTED_CANDIDATE_EVIDENCE_FILES,
    CommandSpec,
    QUALIFICATION_ENVIRONMENT_KEYS,
    QUALIFICATION_PATH_TOOLS,
    build_qualification_environment,
    capture_report,
    decode_candidate_evidence_json,
    deep_command_specs,
    execution_policy_contract,
    network_command_preconditions_met,
    prepare_deep_fuzz_directories,
    qualification_environment_contract,
    qualification_outcome,
    reject_cargo_configuration,
    retain_candidate_evidence,
    repository_control_snapshot,
    run_bounded_process,
    run_command,
    source_archive,
    write_atomic_canonical_json,
    write_receipt_log,
    write_candidate_sandbox_profile,
    verify_deep_fuzz_command_directories,
)
from prepare_mutation_evidence import mutation_command, parse_subject  # noqa: E402
import release_assurance as assurance  # noqa: E402
from release_assurance import (  # noqa: E402
    ACCEPTANCE_METRIC_DOMAINS,
    BoundedHostResult,
    BROAD_MUTATION_RECEIPT,
    CARGO_IDENTITY,
    CARGO_MUTANTS_IDENTITY,
    FOCUSED_MUTATION_RECEIPT,
    FOCUSED_MUTATION_ENVIRONMENT_CONTRACT,
    FOCUSED_MUTATION_SOURCE_FILES,
    FocusedMutant,
    MUTATION_DIFF_OPTIONS,
    MUTATION_BASELINE_COMMIT,
    MUTATION_ENVIRONMENT_CONTRACT,
    MUTATION_LIVENESS_CHECKS,
    RUSTC_IDENTITY,
    assert_tracked_allowed_signer,
    broad_mutation_command,
    canonical_repository_identity,
    derive_external_allowed_signers,
    evaluate_acceptance,
    focused_liveness_mutation_command,
    focused_liveness_mutation_list_command,
    git_tree_inventory,
    require_agent_backed_public_signing_key,
    require_origin_main_candidate,
    refresh_canonical_origin_main,
    run_bounded_host_command,
    sha256_bytes,
    sign_file,
    snapshot_agent_backed_public_signing_key,
    snapshot_independent_allowed_signers,
    validate_completed_file_ledger,
    validate_broad_mutation_receipt,
    validate_decision_input,
    validate_evidence_config_binding,
    validate_evidence_reference,
    validate_mutation_outcomes,
    validate_mutation_evidence,
    validate_focused_liveness_outcomes,
    validate_focused_mutant_listing,
    validate_focused_mutant_sources,
    validate_focused_mutation_receipt,
    validate_reviewed_task_dispositions,
    verify_artifact_manifest,
    verify_candidate_commit,
    verify_signature,
)
from run_broad_mutation import (  # noqa: E402
    assert_untracked_allowlist,
    github_run_provenance,
    run_shard as run_broad_mutation_shard,
)


def focused_span_document(span: tuple[int, int, int, int]) -> dict[str, object]:
    start_line, start_column, end_line, end_column = span
    return {
        "start": {"line": start_line, "column": start_column},
        "end": {"line": end_line, "column": end_column},
    }


def command_test_environment(root: Path) -> dict[str, str]:
    cargo_home = root.resolve(strict=True) / "test-cargo-home"
    cargo_home.mkdir(exist_ok=True)
    return {"CARGO_HOME": str(cargo_home), "PATH": os.environ["PATH"]}


def run_portable_test_process(
    argv: list[str] | tuple[str, ...],
    *,
    cwd: Path,
    environment: Mapping[str, str] | None,
    timeout_seconds: int,
    separate_stderr: bool,
    max_stdout_bytes: int = qualifier.MAX_COMMAND_STREAM_BYTES,
    max_stderr_bytes: int = qualifier.MAX_COMMAND_STREAM_BYTES,
) -> qualifier.BoundedProcessResult:
    """Run a trusted test fixture without candidate containment."""

    try:
        process = subprocess.run(
            list(argv),
            cwd=cwd,
            env=None if environment is None else dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE if separate_stderr else subprocess.STDOUT,
            check=False,
            timeout=timeout_seconds,
        )
        stdout = process.stdout
        stderr = process.stderr if separate_stderr else b""
        returncode = process.returncode
        timed_out = False
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or b""
        stderr = (error.stderr or b"") if separate_stderr else b""
        returncode = 124
        timed_out = True
    output_limit_exceeded = (
        len(stdout) > max_stdout_bytes or len(stderr) > max_stderr_bytes
    )
    return qualifier.BoundedProcessResult(
        returncode=returncode,
        timed_out=timed_out,
        stdout=stdout[:max_stdout_bytes],
        stderr=stderr[:max_stderr_bytes],
        output_limit_exceeded=output_limit_exceeded,
        containment_error=None,
    )


def portable_test_argv(
    _profile: Path,
    argv: list[str] | tuple[str, ...],
    **_keywords: object,
) -> list[str]:
    """Remove macOS sandbox wrapping from a trusted portable test fixture."""

    return list(argv)


def portable_test_git_executable(root: Path) -> Path:
    """Copy Git to a non-system path for a trusted portable test fixture."""

    resolved_git = shutil.which("git")
    if resolved_git is None:
        raise AssertionError("portable test environment does not provide Git")
    destination = root / "portable-developer-tools" / "git"
    destination.parent.mkdir()
    shutil.copyfile(resolved_git, destination)
    destination.chmod(0o500)
    return destination.resolve(strict=True)


def portable_test_process_patch() -> contextlib.AbstractContextManager[object]:
    """Use the production process runner on macOS and a test runner elsewhere."""

    if sys.platform == "darwin":
        return contextlib.nullcontext()
    stack = contextlib.ExitStack()
    stack.enter_context(
        mock.patch(
            "qualify_candidate.sandboxed_argv",
            side_effect=portable_test_argv,
        )
    )
    stack.enter_context(
        mock.patch(
            "qualify_candidate.run_bounded_process",
            side_effect=run_portable_test_process,
        )
    )
    return stack


def qualification_tool_fixture(root: Path) -> Path:
    """Create executable fixtures for every qualification PATH tool."""

    tools = root / "qualification-tools"
    tools.mkdir()
    for name in QUALIFICATION_PATH_TOOLS:
        executable = tools / name
        executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        executable.chmod(0o700)
    return tools


def test_tool_read_root() -> Path:
    """Return a stable read root for the active Python executable."""

    executable = Path(sys.executable).resolve()
    parts = executable.parts
    if len(parts) >= 3 and parts[:2] == ("/", "opt"):
        return Path("/", "opt", parts[2])
    if len(parts) >= 3 and parts[:3] == ("/", "usr", "local"):
        return Path("/usr/local")
    return executable.parent


def candidate_sandbox_profile(
    root: Path,
    *,
    worktree: Path,
    writable_paths: tuple[Path, ...] = (),
) -> Path:
    profile = root / "test-candidate.sb"
    write_candidate_sandbox_profile(
        profile,
        worktree=worktree,
        source_repo=ROOT,
        writable_paths=writable_paths,
        tool_read_paths=(test_tool_read_root(),),
    )
    return profile


def exact_test_candidate(root: Path) -> tuple[Path, str, str, dict[str, str]]:
    worktree = root / "worktree"
    worktree.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=worktree, check=True)
    subprocess.run(
        ["git", "config", "user.name", "Sepehr Mahmoudian"],
        cwd=worktree,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "sepmhn@gmail.com"],
        cwd=worktree,
        check=True,
    )
    (worktree / "README.md").write_text("fixture\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=worktree, check=True)
    subprocess.run(
        ["git", "commit", "-q", "--no-gpg-sign", "-m", "Create fixture"],
        cwd=worktree,
        check=True,
    )
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD^{commit}"], cwd=worktree, text=True
    ).strip()
    tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=worktree, text=True
    ).strip()
    subprocess.run(
        [
            "git",
            "remote",
            "add",
            "origin",
            "git@github.com:sepahead/galadriel.git",
        ],
        cwd=worktree,
        check=True,
    )
    subprocess.run(
        ["git", "update-ref", "refs/remotes/origin/main", commit],
        cwd=worktree,
        check=True,
    )
    return worktree, commit, tree, repository_control_snapshot(worktree)


def focused_mutant_document(mutant: FocusedMutant) -> dict[str, object]:
    return {
        "name": mutant.name,
        "package": mutant.package,
        "file": mutant.file,
        "function": {
            "function_name": mutant.function_name,
            "return_type": mutant.return_type,
            "span": focused_span_document(mutant.function_span),
        },
        "span": focused_span_document(mutant.span),
        "replacement": mutant.replacement,
        "genre": mutant.genre,
    }


def focused_phase_results(
    check: dict[str, object], *, summary: str
) -> list[dict[str, object]]:
    cargo = "/fixture/toolchain/bin/cargo"
    if check["kind"] == "direct-test":
        package = "--package=galadriel-ncp@0.9.0"
        extra_build: list[str] = ["--locked"]
        extra_test = ["--locked", "--lib", str(check["test"]), "--", "--exact"]
    else:
        package = "--package=galadriel-eval@0.9.0"
        extra_build = ["--locked"]
        extra_test = ["--locked", "--bin", str(check["binary"])]

    phases: list[dict[str, object]] = [
        {
            "phase": "Build",
            "duration": 1.0,
            "process_status": (
                {"Failure": 101} if summary == "Unviable" else "Success"
            ),
            "argv": [
                cargo,
                "test",
                "--no-run",
                "--verbose",
                package,
                "--all-features",
                *extra_build,
            ],
        }
    ]
    if summary == "Unviable":
        return phases
    phases.append(
        {
            "phase": "Test",
            "duration": 1.0,
            "process_status": ("Success" if summary == "Success" else {"Failure": 101}),
            "argv": [
                cargo,
                "test",
                "--verbose",
                package,
                "--all-features",
                *extra_test,
            ],
        }
    )
    return phases


def focused_outcomes_document(check: dict[str, object]) -> dict[str, object]:
    outcomes: list[dict[str, object]] = [
        {
            "scenario": "Baseline",
            "summary": "Success",
            "log_path": "log/baseline.log",
            "diff_path": None,
            "phase_results": focused_phase_results(check, summary="Success"),
        }
    ]
    required = check["required_mutants"]
    assert isinstance(required, tuple)
    unviable = Counter(check.get("unviable_mutants", ()))
    for index, mutant in enumerate(required):
        assert isinstance(mutant, FocusedMutant)
        summary = "Unviable" if unviable[mutant] else "CaughtMutant"
        outcomes.append(
            {
                "scenario": {"Mutant": focused_mutant_document(mutant)},
                "summary": summary,
                "log_path": f"log/focused-{index}.log",
                "diff_path": f"diff/focused-{index}.diff",
                "phase_results": focused_phase_results(check, summary=summary),
            }
        )
    count = len(required)
    unviable_count = sum(unviable.values())
    return {
        "outcomes": outcomes,
        "total_mutants": count,
        "missed": 0,
        "caught": count - unviable_count,
        "timeout": 0,
        "unviable": unviable_count,
        "success": 0,
        "start_time": "2026-07-14T00:00:00Z",
        "end_time": "2026-07-14T00:01:00Z",
        "cargo_mutants_version": "27.1.0",
    }


def focused_receipt_document(
    root: Path, *, commit: str, tree: str
) -> dict[str, object]:
    records = []
    for check in MUTATION_LIVENESS_CHECKS:
        check_id = str(check["id"])
        relative = f"{check['output']}/mutants.out/outcomes.json"
        outcomes = root / relative
        data = outcomes.read_bytes()
        count = len(check["required_mutants"])
        unviable_count = len(check.get("unviable_mutants", ()))
        records.append(
            {
                "id": check_id,
                "status": "PASS",
                "command_argv": focused_liveness_mutation_command(check),
                "counts": {
                    "total_mutants": count,
                    "missed": 0,
                    "caught": count - unviable_count,
                    "timeout": 0,
                    "unviable": unviable_count,
                    "success": 0,
                },
                "outcomes": {
                    "path": relative,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size_bytes": len(data),
                },
            }
        )
    return {
        "schema": "galadriel.focused-mutation-run.v2",
        "candidate": {"commit": commit, "tree": tree},
        "github_run": None,
        "environment_contract": FOCUSED_MUTATION_ENVIRONMENT_CONTRACT,
        "toolchain": {
            "cargo": CARGO_IDENTITY,
            "cargo_executable": "/fixture/toolchain/bin/cargo",
            "cargo_mutants": CARGO_MUTANTS_IDENTITY,
            "rustc": RUSTC_IDENTITY,
        },
        "checks": records,
    }


def broad_receipt_document(
    root: Path,
    *,
    commit: str,
    tree: str,
    baseline: str,
    shard: str,
    diff: bytes,
) -> dict[str, object]:
    outcomes = root / "mutants.out" / "outcomes.json"
    data = outcomes.read_bytes()
    document = json.loads(data)
    counts = {
        field: document[field]
        for field in (
            "total_mutants",
            "missed",
            "caught",
            "timeout",
            "unviable",
            "success",
        )
    }
    return {
        "schema": "galadriel.broad-mutation-run.v2",
        "candidate": {"commit": commit, "tree": tree},
        "baseline_commit": baseline,
        "shard": shard,
        "github_run": None,
        "git_diff": {
            "path": "git.diff",
            "sha256": hashlib.sha256(diff).hexdigest(),
            "size_bytes": len(diff),
        },
        "command_argv": broad_mutation_command(shard),
        "environment_contract": MUTATION_ENVIRONMENT_CONTRACT,
        "toolchain": {
            "cargo": CARGO_IDENTITY,
            "cargo_executable": "/fixture/toolchain/bin/cargo",
            "cargo_mutants": CARGO_MUTANTS_IDENTITY,
            "rustc": RUSTC_IDENTITY,
        },
        "exit_code": 0,
        "status": "PASS",
        "counts": counts,
        "outcomes": {
            "path": "mutants.out/outcomes.json",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data),
        },
    }


def broad_phase_results(
    *,
    package: str,
    summary: str,
    baseline_packages: tuple[str, ...] | None = None,
) -> list[dict[str, object]]:
    packages = baseline_packages if baseline_packages is not None else (package,)
    selectors = [f"--package={name}@0.9.0" for name in packages]
    phases: list[dict[str, object]] = [
        {
            "phase": "Build",
            "duration": 1.0,
            "process_status": (
                {"Failure": 101} if summary == "Unviable" else "Success"
            ),
            "argv": [
                "/fixture/toolchain/bin/cargo",
                "test",
                "--no-run",
                "--verbose",
                *selectors,
                "--all-features",
                "--locked",
            ],
        }
    ]
    if summary != "Unviable":
        phases.append(
            {
                "phase": "Test",
                "duration": 1.0,
                "process_status": (
                    "Success" if summary == "Success" else {"Failure": 101}
                ),
                "argv": [
                    "/fixture/toolchain/bin/cargo",
                    "test",
                    "--verbose",
                    *selectors,
                    "--all-features",
                    "--locked",
                ],
            }
        )
    return phases


def broad_outcomes_document(
    *,
    total: int = 500,
    caught: int = 400,
    offset: int = 0,
    package: str = "galadriel-core",
) -> dict[str, object]:
    if total < caught:
        raise ValueError("caught mutants cannot exceed total mutants")
    source = f"crates/{package}/src/fixture.rs"
    function_end = offset + total + 3
    outcomes: list[dict[str, object]] = [
        {
            "scenario": "Baseline",
            "summary": "Success",
            "log_path": "log/baseline.log",
            "diff_path": None,
            "phase_results": broad_phase_results(
                package=package,
                summary="Success",
                baseline_packages=(package,),
            ),
        }
    ]
    for index in range(total):
        line = offset + index + 2
        summary = "CaughtMutant" if index < caught else "Unviable"
        outcomes.append(
            {
                "scenario": {
                    "Mutant": {
                        "name": (
                            f"{source}:{line}:1: replace fixture_{line} -> bool "
                            "with false"
                        ),
                        "package": package,
                        "file": source,
                        "function": {
                            "function_name": f"fixture_{line}",
                            "return_type": "-> bool",
                            "span": focused_span_document((1, 1, function_end, 2)),
                        },
                        "span": focused_span_document((line, 1, line, 2)),
                        "replacement": "false",
                        "genre": "FnValue",
                    }
                },
                "summary": summary,
                "log_path": f"log/mutant-{line}.log",
                "diff_path": f"diff/mutant-{line}.diff",
                "phase_results": broad_phase_results(
                    package=package,
                    summary=summary,
                ),
            }
        )
    return {
        "outcomes": outcomes,
        "total_mutants": total,
        "missed": 0,
        "caught": caught,
        "timeout": 0,
        "unviable": total - caught,
        "success": 0,
        "start_time": "2026-07-22T00:00:00Z",
        "end_time": "2026-07-22T00:01:00Z",
        "cargo_mutants_version": "27.1.0",
    }


def metric(
    value: float, low: float, high: float, eligible: int = 100
) -> dict[str, object]:
    return {
        "status": "estimated",
        "value": value,
        "ci95": [low, high],
        "ci_status": "estimated",
        "eligible_tracks": eligible,
    }


def row(
    condition: str,
    detector: str,
    metrics: dict[str, object],
    *,
    experiment_kind: str = "targeted_attack",
    phi: float | None = None,
    covariance_scale: float | None = None,
) -> dict[str, object]:
    return {
        "condition": condition,
        "experiment_kind": experiment_kind,
        "role": "holdout",
        "detector": detector,
        "phi": phi,
        "covariance_scale": covariance_scale,
        "metrics": metrics,
    }


def passing_summary() -> dict[str, object]:
    baseline = "nis_baseline"
    default = "default_correlation_fusion"
    clean_metrics = {
        "false_alerts_per_hour": metric(0.01, 0.0, 0.09),
        "mission_probability_any_alert": metric(0.01, 0.0, 0.04),
        "abstention_fraction": metric(0.01, 0.0, 0.04),
    }
    rows = [
        row(
            "clean-reference-baseline",
            baseline,
            copy.deepcopy(clean_metrics),
            experiment_kind="clean_autocorrelation",
            phi=0.0,
            covariance_scale=1.0,
        ),
        row(
            "clean-reference-fusion",
            default,
            copy.deepcopy(clean_metrics),
            experiment_kind="clean_autocorrelation",
            phi=0.0,
            covariance_scale=1.0,
        ),
    ]
    for condition, detector in (
        ("attack_loud_acoustic", baseline),
        ("attack_loud_acoustic", default),
        ("attack_broad_degradation", baseline),
        ("attack_broad_degradation", default),
        ("attack_stealthy_acoustic", default),
    ):
        values = {
            "conditional_detection_probability": metric(0.98, 0.91, 1.0),
            "conditional_delay_p95_ms": metric(8_000.0, 7_000.0, 9_000.0),
        }
        if detector == default and condition in {
            "attack_loud_acoustic",
            "attack_stealthy_acoustic",
        }:
            values["conditional_attribution_error"] = metric(0.02, 0.0, 0.09)
        rows.append(
            row(
                condition,
                detector,
                values,
                experiment_kind=(
                    "broad_degradation_attack"
                    if condition == "attack_broad_degradation"
                    else "targeted_attack"
                ),
                phi=0.0,
                covariance_scale=1.0,
            )
        )
    rows.append(
        row(
            "clean_ordinary_missingness",
            default,
            {"abstention_fraction": metric(0.30, 0.20, 0.49)},
            experiment_kind="ordinary_missingness",
            phi=0.0,
            covariance_scale=1.0,
        )
    )
    return {"holdout_results": rows}


class AcceptanceTests(unittest.TestCase):
    def test_acceptance_metric_domains_are_closed_and_name_derived(self) -> None:
        self.assertEqual(
            ACCEPTANCE_METRIC_DOMAINS,
            {
                "false_alerts_per_hour": "rate",
                "mission_probability_any_alert": "probability",
                "conditional_detection_probability": "probability",
                "conditional_delay_p95_ms": "delay",
                "conditional_attribution_error": "probability",
                "abstention_fraction": "probability",
            },
        )

    def test_exact_arm_mapping_passes(self) -> None:
        result = evaluate_acceptance(
            passing_summary(), {"min_metric_eligible_tracks": 20}
        )
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["failed_criterion_ids"], [])

    def test_structural_garwood_rate_failure_is_retained_normally(self) -> None:
        summary = passing_summary()
        for candidate in summary["holdout_results"]:
            if candidate["experiment_kind"] == "clean_autocorrelation":
                candidate["metrics"]["false_alerts_per_hour"] = metric(
                    0.0, 0.0, 0.3688879
                )
        result = evaluate_acceptance(summary, {"min_metric_eligible_tracks": 20})
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["failed_criterion_ids"], ["GLD-090-ACC-001"])
        self.assertIsNone(result["criteria"][0]["evaluation_error"])

    def test_probability_intervals_must_stay_within_unit_interval(self) -> None:
        for interval in ([-1.0, 0.04], [0.0, 2.0]):
            with self.subTest(interval=interval):
                summary = passing_summary()
                summary["holdout_results"][0]["metrics"][
                    "mission_probability_any_alert"
                ]["ci95"] = interval
                result = evaluate_acceptance(
                    summary, {"min_metric_eligible_tracks": 20}
                )
                criterion = next(
                    item
                    for item in result["criteria"]
                    if item["id"] == "GLD-090-ACC-002"
                )
                self.assertEqual(criterion["status"], "FAIL")
                self.assertIsNotNone(criterion["evaluation_error"])

    def test_oversized_json_integers_are_evaluation_errors(self) -> None:
        huge_integer = json.loads("1" + "0" * 1_000)
        for location in ("point", "interval"):
            with self.subTest(location=location):
                summary = passing_summary()
                metric_record = summary["holdout_results"][0]["metrics"][
                    "mission_probability_any_alert"
                ]
                if location == "point":
                    metric_record["value"] = huge_integer
                else:
                    metric_record["ci95"] = [0, huge_integer]
                result = evaluate_acceptance(
                    summary, {"min_metric_eligible_tracks": 20}
                )
                criterion = next(
                    item
                    for item in result["criteria"]
                    if item["id"] == "GLD-090-ACC-002"
                )
                self.assertEqual(criterion["status"], "FAIL")
                self.assertIn("finite", criterion["evaluation_error"])

    def test_negative_rate_and_delay_metrics_are_evaluation_errors(self) -> None:
        cases = (
            (
                "GLD-090-ACC-001",
                "false_alerts_per_hour",
                metric(-1.5, -2.0, -1.0),
            ),
            (
                "GLD-090-ACC-004",
                "conditional_delay_p95_ms",
                metric(-1_500.0, -2_000.0, -1_000.0),
            ),
        )
        for criterion_id, metric_name, malformed_metric in cases:
            with self.subTest(criterion_id=criterion_id):
                summary = passing_summary()
                if criterion_id == "GLD-090-ACC-001":
                    target = summary["holdout_results"][0]
                else:
                    target = next(
                        item
                        for item in summary["holdout_results"]
                        if item["condition"] == "attack_loud_acoustic"
                        and item["detector"] == "nis_baseline"
                    )
                target["metrics"][metric_name] = malformed_metric
                result = evaluate_acceptance(
                    summary, {"min_metric_eligible_tracks": 20}
                )
                criterion = next(
                    item for item in result["criteria"] if item["id"] == criterion_id
                )
                self.assertEqual(criterion["status"], "FAIL")
                self.assertIn("negative value", criterion["evaluation_error"])

    def test_rate_and_delay_intervals_are_not_probability_bounded(self) -> None:
        summary = passing_summary()
        summary["holdout_results"][0]["metrics"]["false_alerts_per_hour"] = metric(
            1.5, 1.0, 2.0
        )
        attack_row = next(
            item
            for item in summary["holdout_results"]
            if item["condition"] == "attack_loud_acoustic"
            and item["detector"] == "nis_baseline"
        )
        attack_row["metrics"]["conditional_delay_p95_ms"] = metric(
            8_000.0, 7_000.0, 12_000.0
        )
        result = evaluate_acceptance(summary, {"min_metric_eligible_tracks": 20})
        rate_criterion = next(
            item for item in result["criteria"] if item["id"] == "GLD-090-ACC-001"
        )
        delay_criterion = next(
            item for item in result["criteria"] if item["id"] == "GLD-090-ACC-004"
        )
        self.assertEqual(rate_criterion["status"], "FAIL")
        self.assertIsNone(rate_criterion["evaluation_error"])
        self.assertEqual(delay_criterion["status"], "PASS")
        self.assertIsNone(delay_criterion["evaluation_error"])

    def test_missing_duplicate_and_underpowered_rows_are_failures(self) -> None:
        for mutation in ("missing", "duplicate", "underpowered"):
            with self.subTest(mutation=mutation):
                summary = passing_summary()
                if mutation == "missing":
                    summary["holdout_results"] = [
                        item
                        for item in summary["holdout_results"]
                        if not (
                            item["condition"] == "attack_stealthy_acoustic"
                            and item["detector"] == "default_correlation_fusion"
                        )
                    ]
                elif mutation == "duplicate":
                    summary["holdout_results"].append(
                        copy.deepcopy(summary["holdout_results"][0])
                    )
                else:
                    target = next(
                        item
                        for item in summary["holdout_results"]
                        if item["condition"] == "attack_loud_acoustic"
                        and item["detector"] == "default_correlation_fusion"
                    )
                    target["metrics"]["conditional_attribution_error"][
                        "eligible_tracks"
                    ] = 19
                result = evaluate_acceptance(
                    summary, {"min_metric_eligible_tracks": 20}
                )
                self.assertEqual(result["status"], "FAIL")
                self.assertTrue(
                    any(item["evaluation_error"] for item in result["criteria"])
                )

    def test_wrong_arm_identity_and_non_numeric_interval_are_failures(self) -> None:
        wrong_arm = passing_summary()
        target = next(
            item
            for item in wrong_arm["holdout_results"]
            if item["condition"] == "attack_broad_degradation"
        )
        target["experiment_kind"] = "targeted_attack"
        result = evaluate_acceptance(wrong_arm, {"min_metric_eligible_tracks": 20})
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("GLD-090-ACC-003", result["failed_criterion_ids"])

        boolean_interval = passing_summary()
        boolean_interval["holdout_results"][0]["metrics"]["false_alerts_per_hour"][
            "ci95"
        ] = [False, True]
        result = evaluate_acceptance(
            boolean_interval, {"min_metric_eligible_tracks": 20}
        )
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("GLD-090-ACC-001", result["failed_criterion_ids"])


class GitFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.repo, check=True)
        subprocess.run(
            ["git", "config", "user.name", "Sepehr Mahmoudian"],
            cwd=self.repo,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "sepmhn@gmail.com"],
            cwd=self.repo,
            check=True,
        )
        subprocess.run(
            ["git", "config", "commit.gpgsign", "false"], cwd=self.repo, check=True
        )
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")
        (self.repo / "data.json").write_text('{"value":1}\n', encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "Create fixture"], cwd=self.repo, check=True
        )
        self.commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, text=True
        ).strip()
        self.tree = subprocess.check_output(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=self.repo, text=True
        ).strip()

    def tearDown(self) -> None:
        self.temporary.cleanup()


class CandidateCommitIdentityTests(GitFixture):
    def configure_signing_key(self, name: str) -> tuple[Path, Path]:
        key = self.root / name
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.signingkey", str(key)],
            cwd=self.repo,
            check=True,
        )
        allowed = self.root / f"{name}.allowed"
        derive_external_allowed_signers(key.with_suffix(".pub"), allowed)
        return key, allowed

    def signed_commit(
        self,
        *,
        key: Path,
        message: str,
        author_name: str = "Sepehr Mahmoudian",
        author_email: str = "sepmhn@gmail.com",
    ) -> str:
        (self.repo / "README.md").write_text(f"{message}\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=self.repo, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                f"user.name={author_name}",
                "-c",
                f"user.email={author_email}",
                "-c",
                f"user.signingkey={key}",
                "-c",
                "gpg.format=ssh",
                "commit",
                "-q",
                "-S",
                "-m",
                message,
            ],
            cwd=self.repo,
            check=True,
        )
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, text=True
        ).strip()

    def test_signed_candidate_binds_exact_author_and_tree(self) -> None:
        key, allowed = self.configure_signing_key("candidate-key")
        commit = self.signed_commit(key=key, message="Sign candidate")
        expected_tree = subprocess.check_output(
            ["git", "rev-parse", f"{commit}^{{tree}}"],
            cwd=self.repo,
            text=True,
        ).strip()
        self.assertEqual(
            verify_candidate_commit(self.repo, commit, allowed), expected_tree
        )

    def test_replacement_reference_is_rejected_before_signature_check(self) -> None:
        original = self.commit
        key, allowed = self.configure_signing_key("replacement-key")
        replacement = self.signed_commit(key=key, message="Sign replacement")
        subprocess.run(
            ["git", "replace", original, replacement], cwd=self.repo, check=True
        )
        with self.assertRaisesRegex(ReviewError, "replacement references"):
            verify_candidate_commit(self.repo, original, allowed)

    def test_signed_candidate_with_substituted_identity_is_rejected(self) -> None:
        key, allowed = self.configure_signing_key("identity-key")
        commit = self.signed_commit(
            key=key,
            message="Sign substituted identity",
            author_name="Another Author",
            author_email="another@example.com",
        )
        with self.assertRaisesRegex(ReviewError, "author and committer identities"):
            verify_candidate_commit(self.repo, commit, allowed)

    def test_foreign_independent_trust_root_is_rejected(self) -> None:
        key, _allowed = self.configure_signing_key("candidate-key")
        commit = self.signed_commit(key=key, message="Sign candidate")
        _foreign_key, foreign_allowed = self.configure_signing_key("foreign-key")
        with self.assertRaisesRegex(ReviewError, "required signature"):
            verify_candidate_commit(self.repo, commit, foreign_allowed)

    def test_local_signature_format_is_rejected_before_verification(self) -> None:
        key, allowed = self.configure_signing_key("candidate-key")
        commit = self.signed_commit(key=key, message="Sign candidate")
        subprocess.run(
            ["git", "config", "gpg.format", "openpgp"],
            cwd=self.repo,
            check=True,
        )
        with (
            mock.patch(
                "release_assurance.run_bounded_host_command"
            ) as signature_verification,
            self.assertRaisesRegex(ReviewError, "alter a release Git operation"),
        ):
            verify_candidate_commit(self.repo, commit, allowed)
        signature_verification.assert_not_called()

    def test_independent_trust_root_snapshot_rejects_symlink(self) -> None:
        _key, allowed = self.configure_signing_key("snapshot-key")
        link = self.root / "allowed-link"
        link.symlink_to(allowed)
        with self.assertRaisesRegex(ReviewError, "cannot open"):
            snapshot_independent_allowed_signers(link, self.root / "allowed-snapshot")

    def test_origin_main_must_identify_the_exact_candidate(self) -> None:
        with self.assertRaisesRegex(ReviewError, "origin/main"):
            require_origin_main_candidate(self.repo, self.commit)
        subprocess.run(
            [
                "git",
                "update-ref",
                "refs/remotes/origin/main",
                self.commit,
            ],
            cwd=self.repo,
            check=True,
        )
        self.assertEqual(
            require_origin_main_candidate(self.repo, self.commit),
            self.commit,
        )
        (self.repo / "README.md").write_text("later candidate\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=self.repo, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "Create later candidate"],
            cwd=self.repo,
            check=True,
        )
        later = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=self.repo,
            text=True,
        ).strip()
        with self.assertRaisesRegex(ReviewError, "exact candidate"):
            require_origin_main_candidate(self.repo, later)

    def test_canonical_refresh_uses_the_literal_public_fetch_contract(self) -> None:
        with (
            mock.patch(
                "release_assurance.canonical_repository_identity",
                return_value="https://github.com/sepahead/galadriel",
            ),
            mock.patch("release_assurance._reject_unsafe_local_git_configuration"),
            mock.patch("release_assurance.assert_no_replace_refs") as no_replace,
            mock.patch("release_assurance.git", return_value="") as git_run,
            mock.patch(
                "release_assurance.require_origin_main_candidate",
                return_value=self.commit,
            ) as require_main,
        ):
            self.assertEqual(
                refresh_canonical_origin_main(self.repo, self.commit),
                ("https://github.com/sepahead/galadriel", self.commit),
            )
        fetch_arguments = git_run.call_args.args[1:]
        self.assertIn("https://github.com/sepahead/galadriel.git", fetch_arguments)
        self.assertIn("refs/heads/main:refs/remotes/origin/main", fetch_arguments)
        self.assertIn("--no-auto-maintenance", fetch_arguments)
        self.assertIn("--no-prune", fetch_arguments)
        self.assertIn("--no-prune-tags", fetch_arguments)
        self.assertIn("--no-write-commit-graph", fetch_arguments)
        self.assertIn("--show-forced-updates", fetch_arguments)
        self.assertIn("--no-write-fetch-head", fetch_arguments)
        self.assertEqual(git_run.call_args.kwargs["max_bytes"], 0)
        self.assertEqual(no_replace.call_count, 2)
        require_main.assert_called_once_with(self.repo, self.commit)

    def test_canonical_refresh_fails_closed_before_or_during_fetch(self) -> None:
        with (
            mock.patch("release_assurance._reject_unsafe_local_git_configuration"),
            mock.patch(
                "release_assurance.canonical_repository_identity",
                side_effect=ReviewError("noncanonical origin"),
            ),
            mock.patch("release_assurance.git") as git_run,
        ):
            with self.assertRaisesRegex(ReviewError, "noncanonical origin"):
                refresh_canonical_origin_main(self.repo, self.commit)
            git_run.assert_not_called()

        with (
            mock.patch(
                "release_assurance.canonical_repository_identity",
                return_value="https://github.com/sepahead/galadriel",
            ),
            mock.patch("release_assurance._reject_unsafe_local_git_configuration"),
            mock.patch("release_assurance.assert_no_replace_refs"),
            mock.patch(
                "release_assurance.git",
                side_effect=ReviewError("canonical fetch failed"),
            ),
            mock.patch(
                "release_assurance.require_origin_main_candidate"
            ) as require_main,
        ):
            with self.assertRaisesRegex(ReviewError, "canonical fetch failed"):
                refresh_canonical_origin_main(self.repo, self.commit)
            require_main.assert_not_called()

    def test_canonical_refresh_rejects_remote_advancement(self) -> None:
        with (
            mock.patch(
                "release_assurance.canonical_repository_identity",
                return_value="https://github.com/sepahead/galadriel",
            ),
            mock.patch("release_assurance._reject_unsafe_local_git_configuration"),
            mock.patch("release_assurance.assert_no_replace_refs"),
            mock.patch("release_assurance.git", return_value=""),
            mock.patch(
                "release_assurance.require_origin_main_candidate",
                side_effect=ReviewError(
                    "origin/main does not identify the exact candidate"
                ),
            ),
        ):
            with self.assertRaisesRegex(ReviewError, "exact candidate"):
                refresh_canonical_origin_main(self.repo, self.commit)

    def test_canonical_refresh_rejects_local_url_rewrite_before_fetch(self) -> None:
        subprocess.run(
            [
                "git",
                "config",
                "url.file:///tmp/substitute.insteadOf",
                "https://github.com/",
            ],
            cwd=self.repo,
            check=True,
        )
        with (
            mock.patch(
                "release_assurance.canonical_repository_identity",
                return_value="https://github.com/sepahead/galadriel",
            ),
            mock.patch("release_assurance.git", wraps=common_git) as git_run,
            self.assertRaisesRegex(ReviewError, "alter a release Git operation"),
        ):
            refresh_canonical_origin_main(self.repo, self.commit)
        self.assertFalse(
            any("fetch" in call.args[1:] for call in git_run.call_args_list)
        )

    def test_canonical_refresh_rejects_local_execution_and_integrity_overrides(
        self,
    ) -> None:
        alternate_worktree = self.root / "alternate-worktree"
        alternate_worktree.mkdir()
        skip_list = self.root / "fsck-skip-list"
        skip_list.write_text(f"{self.commit}\n", encoding="ascii")
        cases = (
            ("core.worktree", str(alternate_worktree)),
            ("extensions.worktreeConfig", "true"),
            ("fetch.fsck.missingEmail", "ignore"),
            ("fetch.fsck.skipList", str(skip_list)),
            ("gc.recentObjectsHook", "touch ignored"),
            ("gpg.format", "openpgp"),
            ("gpg.ssh.program", "touch ignored"),
        )
        for key, value in cases:
            with self.subTest(key=key):
                subprocess.run(
                    ["git", "config", key, value],
                    cwd=self.repo,
                    check=True,
                )
                with (
                    mock.patch(
                        "release_assurance.canonical_repository_identity",
                        return_value="https://github.com/sepahead/galadriel",
                    ) as canonical_identity,
                    mock.patch("release_assurance.git", wraps=common_git) as git_run,
                    self.assertRaisesRegex(
                        ReviewError, "alter a release Git operation"
                    ),
                ):
                    refresh_canonical_origin_main(self.repo, self.commit)
                canonical_identity.assert_not_called()
                self.assertFalse(
                    any("fetch" in call.args[1:] for call in git_run.call_args_list)
                )
                subprocess.run(
                    ["git", "config", "--unset-all", key],
                    cwd=self.repo,
                    check=True,
                )

    def test_canonical_refresh_rejects_alternate_refs_command_before_fetch(
        self,
    ) -> None:
        marker = self.root / "alternate-refs-command-ran"
        subprocess.run(
            [
                "git",
                "config",
                "core.alternateRefsCommand",
                f"touch {shlex.quote(str(marker))}",
            ],
            cwd=self.repo,
            check=True,
        )
        with (
            mock.patch(
                "release_assurance.canonical_repository_identity",
                return_value="https://github.com/sepahead/galadriel",
            ),
            mock.patch("release_assurance.git", wraps=common_git) as git_run,
            self.assertRaisesRegex(ReviewError, "alter a release Git operation"),
        ):
            refresh_canonical_origin_main(self.repo, self.commit)
        self.assertFalse(marker.exists())
        self.assertFalse(
            any("fetch" in call.args[1:] for call in git_run.call_args_list)
        )


class FinalizationCandidateControlTests(GitFixture):
    def setUp(self) -> None:
        super().setUp()
        subprocess.run(
            [
                "git",
                "remote",
                "add",
                "origin",
                "git@github.com:sepahead/galadriel.git",
            ],
            cwd=self.repo,
            check=True,
        )
        subprocess.run(
            ["git", "update-ref", "refs/remotes/origin/main", self.commit],
            cwd=self.repo,
            check=True,
        )

    def capture(self, expected_state: dict[str, object] | None = None):
        def refresh(repo: Path, commit: str) -> tuple[str, str]:
            return (
                canonical_repository_identity(repo),
                require_origin_main_candidate(repo, commit),
            )

        with mock.patch(
            "finalize_release.refresh_canonical_origin_main",
            side_effect=refresh,
        ):
            return finalization_candidate_control(
                self.repo,
                expected_commit=self.commit,
                expected_tree=self.tree,
                required_branch="main",
                expected_state=expected_state,
            )

    def test_control_rejects_remote_ref_drift(self) -> None:
        initial = self.capture()
        other = subprocess.check_output(
            ["git", "commit-tree", self.tree, "-m", "Create other ref target"],
            cwd=self.repo,
            text=True,
        ).strip()
        subprocess.run(
            ["git", "update-ref", "refs/remotes/origin/main", other],
            cwd=self.repo,
            check=True,
        )
        with self.assertRaisesRegex(ReviewError, "origin/main"):
            self.capture(initial)

    def test_control_rejects_origin_and_local_config_drift(self) -> None:
        initial = self.capture()
        subprocess.run(
            [
                "git",
                "remote",
                "set-url",
                "origin",
                "https://example.invalid/other.git",
            ],
            cwd=self.repo,
            check=True,
        )
        with self.assertRaisesRegex(ReviewError, "canonical credential-free"):
            self.capture(initial)

        subprocess.run(
            [
                "git",
                "remote",
                "set-url",
                "origin",
                "git@github.com:sepahead/galadriel.git",
            ],
            cwd=self.repo,
            check=True,
        )
        subprocess.run(
            ["git", "config", "fixture.changed", "true"],
            cwd=self.repo,
            check=True,
        )
        with self.assertRaisesRegex(ReviewError, "control changed"):
            self.capture(initial)

    def test_control_rejects_dirty_checkout_and_branch_drift(self) -> None:
        initial = self.capture()
        (self.repo / "README.md").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(ReviewError, "clean candidate"):
            self.capture(initial)
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")

        subprocess.run(
            ["git", "switch", "-q", "-c", "other"], cwd=self.repo, check=True
        )
        with self.assertRaisesRegex(ReviewError, "candidate branch"):
            self.capture(initial)


class FileLedgerTests(GitFixture):
    fields = [
        "path",
        "git_mode",
        "git_blob_id",
        "sha256",
        "bytes",
        "lines",
        "language",
        "generated",
        "generator",
        "public_surface",
        "security_critical",
        "science_critical",
        "authority_critical",
        "reviewer",
        "review_status",
        "requirements",
        "assumptions",
        "defects",
        "tests",
        "evidence",
        "disposition",
        "completed_at",
    ]

    def rows(self) -> list[dict[str, str]]:
        inventory = git_tree_inventory(self.repo, self.commit)
        return [
            {
                "path": path,
                "git_mode": item["mode"],
                "git_blob_id": item["git_blob_id"],
                "sha256": item["sha256"],
                "bytes": str(item["bytes"]),
                "lines": "1",
                "language": "fixture",
                "generated": "false",
                "generator": "",
                "public_surface": "false",
                "security_critical": "false",
                "science_critical": "false",
                "authority_critical": "false",
                "reviewer": "Sepehr Mahmoudian / author-operated review",
                "review_status": "REVIEWED_NO_DEFECT",
                "requirements": "Exact file requirements checked.",
                "assumptions": "No hidden assumptions recorded.",
                "defects": "",
                "tests": "Candidate-bound test evidence checked.",
                "evidence": "Exact Git blob and review notes retained.",
                "disposition": "Accepted for exact candidate.",
                "completed_at": "2026-07-14T12:00:00Z",
            }
            for path, item in sorted(inventory.items())
        ]

    def write(self, rows: list[dict[str, str]], name: str) -> Path:
        path = self.root / name
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=self.fields)
            writer.writeheader()
            writer.writerows(rows)
        return path

    def test_completed_ledger_is_exactly_one_to_one(self) -> None:
        completed = self.rows()
        source = copy.deepcopy(completed)
        for row in source:
            row.update(
                reviewer="lane assignment",
                review_status="UNREVIEWED",
                requirements="",
                assumptions="",
                defects="",
                tests="",
                evidence="",
                disposition="",
                completed_at="",
            )
        source_path = self.write(source, "source.csv")
        result = validate_completed_file_ledger(
            self.write(completed, "complete.csv"),
            self.repo,
            self.commit,
            source_ledger=source_path,
        )
        self.assertEqual(result["tracked_files"], 2)
        self.assertEqual(result["reviewed_files"], 2)
        altered = copy.deepcopy(completed)
        altered[0]["language"] = "changed"
        with self.assertRaisesRegex(ReviewError, "changed source metadata"):
            validate_completed_file_ledger(
                self.write(altered, "altered.csv"),
                self.repo,
                self.commit,
                source_ledger=source_path,
            )

    def test_missing_extra_unreviewed_and_digest_mismatch_are_rejected(self) -> None:
        variants: dict[str, list[dict[str, str]]] = {}
        base = self.rows()
        variants["missing tracked paths"] = base[:-1]
        extra = copy.deepcopy(base)
        extra.append({**base[0], "path": "extra.txt"})
        variants["extra path"] = extra
        unreviewed = copy.deepcopy(base)
        unreviewed[0]["review_status"] = "UNREVIEWED"
        variants["unreviewed file"] = unreviewed
        mismatch = copy.deepcopy(base)
        mismatch[0]["sha256"] = "0" * 64
        variants["digest or size mismatch"] = mismatch
        for message, rows in variants.items():
            with self.subTest(message=message):
                with self.assertRaisesRegex(ReviewError, message):
                    validate_completed_file_ledger(
                        self.write(rows, f"{message.split()[0]}.csv"),
                        self.repo,
                        self.commit,
                    )

    def test_completed_ledger_cannot_cross_a_mode_only_candidate_change(self) -> None:
        completed = self.write(self.rows(), "mode-bound-complete.csv")
        original = git_tree_inventory(self.repo, self.commit)["README.md"]
        subprocess.run(
            ["git", "update-index", "--chmod=+x", "--", "README.md"],
            cwd=self.repo,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-q", "-m", "Change tracked mode"],
            cwd=self.repo,
            check=True,
        )
        mode_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=self.repo,
            text=True,
        ).strip()
        changed = git_tree_inventory(self.repo, mode_commit)["README.md"]
        self.assertEqual(changed["git_blob_id"], original["git_blob_id"])
        self.assertEqual(original["mode"], "100644")
        self.assertEqual(changed["mode"], "100755")

        with self.assertRaisesRegex(ReviewError, "mode mismatch"):
            validate_completed_file_ledger(
                completed,
                self.repo,
                mode_commit,
            )

    def test_ledger_parse_and_digest_use_the_same_stable_bytes(self) -> None:
        completed = self.write(self.rows(), "stable-complete.csv")
        original = completed.read_bytes()
        real_reader = assurance.read_bounded_regular_file

        def snapshot_then_replace(
            path: Path, *arguments: object, **keywords: object
        ) -> bytes:
            document = real_reader(path, *arguments, **keywords)
            path.write_bytes(document + b"\n")
            return document

        with mock.patch.object(
            assurance,
            "read_bounded_regular_file",
            side_effect=snapshot_then_replace,
        ):
            result = validate_completed_file_ledger(
                completed,
                self.repo,
                self.commit,
            )
        self.assertEqual(result["ledger_sha256"], hashlib.sha256(original).hexdigest())
        self.assertNotEqual(
            result["ledger_sha256"],
            hashlib.sha256(completed.read_bytes()).hexdigest(),
        )

    def test_ledger_rejects_malformed_widths_and_resource_overflow(self) -> None:
        completed = self.write(self.rows(), "bounded-complete.csv")
        valid = completed.read_text(encoding="utf-8")
        lines = valid.splitlines()
        self.assertGreaterEqual(len(lines), 3)

        malformed_documents = {
            "extra": "\n".join([lines[0], lines[1] + ",unexpected", *lines[2:]]) + "\n",
            "missing": "\n".join([lines[0], lines[1].rsplit(",", 1)[0], *lines[2:]])
            + "\n",
        }
        for name, document in malformed_documents.items():
            with self.subTest(width=name):
                path = self.root / f"malformed-{name}.csv"
                path.write_text(document, encoding="utf-8")
                with self.assertRaisesRegex(ReviewError, "row 1 is malformed"):
                    validate_completed_file_ledger(path, self.repo, self.commit)

        completed.write_text(valid, encoding="utf-8")
        with (
            mock.patch.object(
                assurance, "MAX_FILE_LEDGER_BYTES", len(valid.encode("utf-8")) - 1
            ),
            self.assertRaisesRegex(ReviewError, "exceeds"),
        ):
            validate_completed_file_ledger(completed, self.repo, self.commit)

        with (
            mock.patch.object(assurance, "MAX_FILE_LEDGER_ROWS", 1),
            self.assertRaisesRegex(ReviewError, "row limit"),
        ):
            validate_completed_file_ledger(completed, self.repo, self.commit)

        with (
            mock.patch.object(assurance, "MAX_FILE_LEDGER_CELL_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "cell-size limit"),
        ):
            validate_completed_file_ledger(completed, self.repo, self.commit)

        linked = self.root / "linked-complete.csv"
        linked.symlink_to(completed)
        with self.assertRaisesRegex(ReviewError, "cannot open|not regular"):
            validate_completed_file_ledger(linked, self.repo, self.commit)

        if hasattr(os, "mkfifo"):
            fifo = self.root / "fifo-complete.csv"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ReviewError, "not a regular file"):
                validate_completed_file_ledger(fifo, self.repo, self.commit)


class BindingAndManifestTests(GitFixture):
    def test_signed_qualification_tier_is_snapshotted_once_without_following_links(
        self,
    ) -> None:
        key = self.root / "qualification-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True,
        )
        allowed = self.root / "qualification-allowed"
        derive_external_allowed_signers(key.with_suffix(".pub"), allowed)
        source = self.root / "qualification"
        artifact = source / "nested" / "evidence.json"
        artifact.parent.mkdir(parents=True)
        original = b'{"status":"PASS"}\n'
        artifact.write_bytes(original)
        manifest = source / "QUALIFICATION-MANIFEST.json"
        manifest.write_bytes(
            canonical_json(
                {
                    "schema": "galadriel.tiered-artifact-manifest.v1",
                    "tier": "qualification",
                    "candidate": {"commit": "a" * 40, "tree": "b" * 40},
                    "artifacts": [
                        {
                            "path": "nested/evidence.json",
                            "sha256": hashlib.sha256(original).hexdigest(),
                            "size_bytes": len(original),
                        }
                    ],
                }
            )
        )
        signature = sign_file(manifest, key, "galadriel-qualification-manifest")
        checksum_paths = sorted(
            (artifact, manifest, signature),
            key=lambda path: path.relative_to(source).as_posix(),
        )
        (source / "SHA256SUMS").write_text(
            "".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
                f"{path.relative_to(source).as_posix()}\n"
                for path in checksum_paths
            ),
            encoding="utf-8",
        )

        def destination(name: str) -> tuple[Path, Path, Path]:
            target = self.root / name
            target.mkdir()
            retained_manifest = target / manifest.name
            retained_signature = target / signature.name
            retained_manifest.write_bytes(manifest.read_bytes())
            retained_signature.write_bytes(signature.read_bytes())
            return target, retained_manifest, retained_signature

        retained, retained_manifest, retained_signature = destination("retained")
        snapshot_signed_qualification_tier(
            source,
            retained,
            manifest_path=retained_manifest,
            signature_path=retained_signature,
            allowed_signers=allowed,
        )
        unlisted_target = self.root / "unlisted-target"
        unlisted_target.write_bytes(b"unlisted\n")
        for index, kind in enumerate(("regular", "symlink", "fifo")):
            with self.subTest(unlisted=kind):
                unlisted = source / f"unlisted-{kind}"
                if kind == "regular":
                    unlisted.write_bytes(b"unlisted\n")
                    expected_error = "inventory differs"
                elif kind == "symlink":
                    unlisted.symlink_to(unlisted_target)
                    expected_error = "symlink"
                else:
                    os.mkfifo(unlisted)
                    expected_error = "special file"
                target, target_manifest, target_signature = destination(
                    f"unlisted-{index}"
                )
                with self.assertRaisesRegex(ReviewError, expected_error):
                    snapshot_signed_qualification_tier(
                        source,
                        target,
                        manifest_path=target_manifest,
                        signature_path=target_signature,
                        allowed_signers=allowed,
                    )
                unlisted.unlink()

        race, race_manifest, race_signature = destination("post-copy-race")

        def copy_then_add_unlisted(*args: object, **kwargs: object) -> None:
            snapshot_qualification_artifact(*args, **kwargs)  # type: ignore[arg-type]
            (source / "late-unlisted.json").write_text("{}\n", encoding="utf-8")

        with (
            mock.patch(
                "finalize_release.snapshot_qualification_artifact",
                side_effect=copy_then_add_unlisted,
            ),
            self.assertRaisesRegex(ReviewError, "changed while being snapshotted"),
        ):
            snapshot_signed_qualification_tier(
                source,
                race,
                manifest_path=race_manifest,
                signature_path=race_signature,
                allowed_signers=allowed,
            )
        (source / "late-unlisted.json").unlink()
        artifact.write_bytes(b'{"status":"CHANGED"}\n')
        self.assertEqual((retained / "nested/evidence.json").read_bytes(), original)

        artifact.write_bytes(original)
        artifact.unlink()
        outside = self.root / "outside.json"
        outside.write_bytes(original)
        artifact.symlink_to(outside)
        linked, linked_manifest, linked_signature = destination("linked")
        with self.assertRaisesRegex(
            ReviewError, "missing or unsafe|size or type mismatch|symlink"
        ):
            snapshot_signed_qualification_tier(
                source,
                linked,
                manifest_path=linked_manifest,
                signature_path=linked_signature,
                allowed_signers=allowed,
            )

        artifact.unlink()
        artifact.write_bytes(original)
        artifact.unlink()
        os.mkfifo(artifact)
        fifo, fifo_manifest, fifo_signature = destination("fifo")
        with self.assertRaisesRegex(
            ReviewError, "missing or unsafe|size or type mismatch|special file"
        ):
            snapshot_signed_qualification_tier(
                source,
                fifo,
                manifest_path=fifo_manifest,
                signature_path=fifo_signature,
                allowed_signers=allowed,
            )

        artifact.unlink()
        artifact.write_bytes(b'{"status":"FAIL"}\n')
        drift, drift_manifest, drift_signature = destination("drift")
        with self.assertRaisesRegex(ReviewError, "digest mismatch"):
            snapshot_signed_qualification_tier(
                source,
                drift,
                manifest_path=drift_manifest,
                signature_path=drift_signature,
                allowed_signers=allowed,
            )

        artifact.write_bytes(original)
        artifact.unlink()
        artifact.parent.rmdir()
        outside_directory = self.root / "outside-directory"
        outside_directory.mkdir()
        (outside_directory / "evidence.json").write_bytes(original)
        (source / "nested").symlink_to(outside_directory, target_is_directory=True)
        parent_link, parent_manifest, parent_signature = destination("parent-link")
        with self.assertRaisesRegex(ReviewError, "missing or unsafe|symlink"):
            snapshot_signed_qualification_tier(
                source,
                parent_link,
                manifest_path=parent_manifest,
                signature_path=parent_signature,
                allowed_signers=allowed,
            )

        alias = self.root / "qualification-alias"
        alias.symlink_to(source, target_is_directory=True)
        alias_target, alias_manifest, alias_signature = destination("root-link")
        with self.assertRaisesRegex(ReviewError, "root is missing or unsafe"):
            snapshot_signed_qualification_tier(
                alias,
                alias_target,
                manifest_path=alias_manifest,
                signature_path=alias_signature,
                allowed_signers=allowed,
            )

        empty_digest = hashlib.sha256(b"").hexdigest()
        for index, reserved in enumerate(
            (
                LOCAL_CONVERGENCE,
                f"nested/{LOCAL_CONVERGENCE_SIGNATURE}",
                "inputs/review.json",
                "closure-summary.json",
            )
        ):
            with self.subTest(reserved=reserved):
                reserved_manifest = self.root / f"reserved-{index}.json"
                reserved_manifest.write_bytes(
                    canonical_json(
                        {
                            "schema": "galadriel.tiered-artifact-manifest.v1",
                            "tier": "qualification",
                            "candidate": {"commit": "a" * 40, "tree": "b" * 40},
                            "artifacts": [
                                {
                                    "path": reserved,
                                    "sha256": empty_digest,
                                    "size_bytes": 0,
                                }
                            ],
                        }
                    )
                )
                reserved_signature = sign_file(
                    reserved_manifest, key, "galadriel-qualification-manifest"
                )
                reserved_target = self.root / f"reserved-target-{index}"
                reserved_target.mkdir()
                with self.assertRaisesRegex(ReviewError, "reserved|forbidden"):
                    snapshot_signed_qualification_tier(
                        source,
                        reserved_target,
                        manifest_path=reserved_manifest,
                        signature_path=reserved_signature,
                        allowed_signers=allowed,
                    )

    def test_qualification_inventory_has_a_controlled_depth_bound(self) -> None:
        root = self.root / "deep-qualification"
        root.mkdir()
        current = root
        for _index in range(129):
            current = current / "d"
            current.mkdir()
        with self.assertRaisesRegex(ReviewError, "directory-depth limit"):
            qualification_tier_inventory(root)

    def test_qualification_inventory_rejects_unsigned_empty_directories(self) -> None:
        root = self.root / "qualification-with-empty-directory"
        (root / "retained").mkdir(parents=True)
        (root / "artifact.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ReviewError, "empty directory: retained"):
            qualification_tier_inventory(root)

    def test_mutation_file_writer_preserves_failures_and_removes_partial_file(
        self,
    ) -> None:
        real_close = os.close
        for operation in ("write", "fsync"):
            with self.subTest(operation=operation):
                target = self.root / f"failed-{operation}.json"
                closed: list[int] = []

                def close_then_fail(descriptor: int) -> None:
                    closed.append(descriptor)
                    real_close(descriptor)
                    raise OSError("injected close failure")

                operation_patch = (
                    mock.patch.object(
                        qualifier.os,
                        "write",
                        side_effect=OSError("injected write failure"),
                    )
                    if operation == "write"
                    else mock.patch.object(
                        qualifier.os,
                        "fsync",
                        side_effect=OSError("injected fsync failure"),
                    )
                )
                with (
                    operation_patch,
                    mock.patch.object(
                        qualifier.os,
                        "close",
                        side_effect=close_then_fail,
                    ),
                    self.assertRaisesRegex(
                        ReviewError,
                        f"injected {operation} failure",
                    ),
                ):
                    qualifier._write_new_mutation_file(
                        target,
                        b"captured mutation bytes\n",
                        label="retained mutation test",
                    )

                self.assertFalse(target.exists())
                self.assertEqual(len(closed), 1)
                with self.assertRaises(OSError):
                    os.fstat(closed[0])

        target = self.root / "failed-close.json"
        closed = []

        def close_only_failure(descriptor: int) -> None:
            closed.append(descriptor)
            real_close(descriptor)
            raise OSError("injected close-only failure")

        with (
            mock.patch.object(
                qualifier.os,
                "close",
                side_effect=close_only_failure,
            ),
            self.assertRaisesRegex(ReviewError, "injected close-only failure"),
        ):
            qualifier._write_new_mutation_file(
                target,
                b"captured mutation bytes\n",
                label="retained mutation test",
            )
        self.assertFalse(target.exists())
        self.assertEqual(len(closed), 1)
        with self.assertRaises(OSError):
            os.fstat(closed[0])

        target = self.root / "successful-write.json"
        closed = []

        def record_close(descriptor: int) -> None:
            closed.append(descriptor)
            real_close(descriptor)

        with mock.patch.object(
            qualifier.os,
            "close",
            side_effect=record_close,
        ):
            qualifier._write_new_mutation_file(
                target,
                b"captured mutation bytes\n",
                label="retained mutation test",
            )
        self.assertEqual(target.read_bytes(), b"captured mutation bytes\n")
        self.assertEqual(len(closed), 1)
        with self.assertRaises(OSError):
            os.fstat(closed[0])

    def test_signed_mutation_manifest_binds_canonical_diff_and_outcomes(self) -> None:
        key = self.root / "mutation-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True,
        )
        allowed = self.root / "mutation-allowed"
        derive_external_allowed_signers(key.with_suffix(".pub"), allowed)
        candidate_repo = self.root / "candidate-repo"
        subprocess.run(
            ["git", "clone", "-q", "--shared", str(ROOT), str(candidate_repo)],
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Sepehr Mahmoudian"],
            cwd=candidate_repo,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "sepmhn@gmail.com"],
            cwd=candidate_repo,
            check=True,
        )
        (candidate_repo / "mutation-fixture.txt").write_text(
            "nonempty frozen-baseline diff\n", encoding="utf-8"
        )
        subprocess.run(
            ["git", "add", "mutation-fixture.txt"], cwd=candidate_repo, check=True
        )
        subprocess.run(
            ["git", "commit", "-q", "--no-gpg-sign", "-m", "Create mutation fixture"],
            cwd=candidate_repo,
            check=True,
        )
        repository_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD^{commit}"], cwd=candidate_repo, text=True
        ).strip()
        repository_tree = subprocess.check_output(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=candidate_repo, text=True
        ).strip()
        baseline = "94e2f8cc01f352d2bf899b7f656997f143a2588f"
        diff_argv = [
            "git",
            *MUTATION_DIFF_OPTIONS,
            f"{baseline}..{repository_commit}",
            "--",
        ]
        diff = subprocess.check_output(diff_argv, cwd=candidate_repo)
        retained_diff = self.root / "git.diff"
        retained_diff.write_bytes(diff)
        github_run = {
            "run_id": "123456789",
            "run_attempt": "1",
            "job": "mutation-diff",
            "workflow": "Deep quality",
            "repository": "sepahead/galadriel",
            "ref": "refs/heads/main",
            "sha": repository_commit,
        }
        shards = []
        broad_receipts = []
        for index in range(4):
            shard_id = f"{index}/4"
            broad_root = self.root / "broad-runs" / f"{index}-of-4"
            outcomes = broad_root / "mutants.out" / "outcomes.json"
            outcomes.parent.mkdir(parents=True)
            outcomes.write_bytes(
                canonical_json(broad_outcomes_document(offset=index * 1_000))
            )
            data = outcomes.read_bytes()
            shards.append(
                {
                    "id": shard_id,
                    "status": "PASS",
                    "command": shlex.join(mutation_command(shard_id)),
                    "artifact": {
                        "path": outcomes.relative_to(self.root).as_posix(),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "size_bytes": len(data),
                    },
                }
            )
            receipt = broad_root / BROAD_MUTATION_RECEIPT
            receipt_document = broad_receipt_document(
                broad_root,
                commit=repository_commit,
                tree=repository_tree,
                baseline=baseline,
                shard=shard_id,
                diff=diff,
            )
            receipt_document["github_run"] = github_run
            receipt.write_bytes(canonical_json(receipt_document))
            receipt_data = receipt.read_bytes()
            broad_receipts.append(
                {
                    "shard": shard_id,
                    "artifact": {
                        "path": receipt.relative_to(self.root).as_posix(),
                        "sha256": hashlib.sha256(receipt_data).hexdigest(),
                        "size_bytes": len(receipt_data),
                    },
                }
            )
        focused_checks = []
        for check in MUTATION_LIVENESS_CHECKS:
            check_id = str(check["id"])
            focused = self.root / str(check["output"]) / "mutants.out" / "outcomes.json"
            focused.parent.mkdir(parents=True)
            focused.write_bytes(canonical_json(focused_outcomes_document(check)))
            data = focused.read_bytes()
            focused_checks.append(
                {
                    "id": check_id,
                    "status": "PASS",
                    "source_shard": "2/4",
                    "command": shlex.join(focused_liveness_mutation_command(check)),
                    "artifact": {
                        "path": focused.relative_to(self.root).as_posix(),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "size_bytes": len(data),
                    },
                }
            )
        receipt = self.root / FOCUSED_MUTATION_RECEIPT
        focused_receipt = focused_receipt_document(
            self.root,
            commit=repository_commit,
            tree=repository_tree,
        )
        focused_receipt["github_run"] = github_run
        receipt.write_bytes(canonical_json(focused_receipt))
        receipt_data = receipt.read_bytes()
        manifest = self.root / "mutation-evidence.json"
        manifest_document = {
            "schema": "galadriel.mutation-evidence.v5",
            "release": "0.9.0",
            "author": "Sepehr Mahmoudian",
            "candidate": {
                "commit": repository_commit,
                "tree": repository_tree,
            },
            "baseline_commit": baseline,
            "github_run": github_run,
            "git_diff_argv": diff_argv,
            "git_diff_sha256": hashlib.sha256(diff).hexdigest(),
            "git_diff": {
                "path": "git.diff",
                "sha256": hashlib.sha256(diff).hexdigest(),
                "size_bytes": len(diff),
            },
            "tool": {"name": "cargo-mutants", "version": "27.1.0"},
            "shards": shards,
            "broad_run_receipts": broad_receipts,
            "focused_run_receipt": {
                "source_shard": "2/4",
                "artifact": {
                    "path": FOCUSED_MUTATION_RECEIPT,
                    "sha256": hashlib.sha256(receipt_data).hexdigest(),
                    "size_bytes": len(receipt_data),
                },
            },
            "focused_checks": focused_checks,
        }
        manifest.write_bytes(canonical_json(manifest_document))
        signature = sign_file(manifest, key, "galadriel-mutation-evidence")
        rooted_reads: list[str] = []
        real_rooted_reader = assurance.read_rooted_regular_file

        def record_rooted_read(
            root: Path,
            relative: str,
            **keywords: object,
        ) -> object:
            rooted_reads.append(relative)
            return real_rooted_reader(root, relative, **keywords)

        with mock.patch.object(
            assurance,
            "read_rooted_regular_file",
            side_effect=record_rooted_read,
        ):
            validated = validate_mutation_evidence(
                manifest,
                signature,
                allowed_signers=allowed,
                repo=candidate_repo,
                commit=repository_commit,
                tree=repository_tree,
            )
        self.assertEqual(len(validated.artifacts), 13)
        expected_rooted_reads = {
            manifest.name,
            signature.name,
            "git.diff",
            FOCUSED_MUTATION_RECEIPT,
            *(item["artifact"]["path"] for item in manifest_document["shards"]),
            *(
                item["artifact"]["path"]
                for item in manifest_document["broad_run_receipts"]
            ),
            *(item["artifact"]["path"] for item in manifest_document["focused_checks"]),
        }
        self.assertEqual(Counter(rooted_reads), Counter(expected_rooted_reads))

        first_outcomes = self.root / "broad-runs/0-of-4/mutants.out/outcomes.json"
        first_relative = first_outcomes.relative_to(self.root).as_posix()
        first_bytes = first_outcomes.read_bytes()
        manifest_bytes = manifest.read_bytes()
        signature_bytes = signature.read_bytes()
        replaced_after_capture = False

        def replace_after_rooted_capture(
            root: Path,
            relative: str,
            **keywords: object,
        ) -> object:
            nonlocal replaced_after_capture
            capture = real_rooted_reader(root, relative, **keywords)
            if relative == first_relative and not replaced_after_capture:
                first_outcomes.write_bytes(b"{}")
                replaced_after_capture = True
            return capture

        with mock.patch.object(
            assurance,
            "read_rooted_regular_file",
            side_effect=replace_after_rooted_capture,
        ):
            captured_before_replacement = validate_mutation_evidence(
                manifest,
                signature,
                allowed_signers=allowed,
                repo=candidate_repo,
                commit=repository_commit,
                tree=repository_tree,
            )
        self.assertTrue(replaced_after_capture)
        self.assertEqual(first_outcomes.read_bytes(), b"{}")
        captured_artifacts = {
            artifact.relative: artifact.capture.data
            for artifact in captured_before_replacement.artifacts
        }
        self.assertEqual(captured_artifacts[first_relative], first_bytes)

        manifest.write_bytes(b"{}\n")
        signature.write_bytes(b"replaced signature\n")
        retained_output = self.root / "retained-mutation"
        retained_output.mkdir()
        retained_records = qualifier.retain_validated_mutation_evidence(
            captured_before_replacement,
            output=retained_output,
        )
        self.assertEqual(len(retained_records), 13)
        self.assertEqual(
            (retained_output / "mutation" / "manifest.json").read_bytes(),
            manifest_bytes,
        )
        self.assertEqual(
            (retained_output / "mutation" / "manifest.json.sig").read_bytes(),
            signature_bytes,
        )
        self.assertEqual(
            (retained_output / "mutation" / first_relative).read_bytes(),
            first_bytes,
        )
        retained_validation = validate_mutation_evidence(
            retained_output / "mutation" / "manifest.json",
            retained_output / "mutation" / "manifest.json.sig",
            allowed_signers=allowed,
            repo=candidate_repo,
            commit=repository_commit,
            tree=repository_tree,
        )
        self.assertEqual(len(retained_validation.artifacts), 13)

        tampered_output = self.root / "tampered-mutation"
        tampered_output.mkdir()
        tampered_manifest = captured_before_replacement.manifest._replace(
            capture=captured_before_replacement.manifest.capture._replace(
                sha256="0" * 64
            )
        )
        with self.assertRaisesRegex(ReviewError, "capture drifted"):
            qualifier.retain_validated_mutation_evidence(
                captured_before_replacement._replace(manifest=tampered_manifest),
                output=tampered_output,
            )
        self.assertFalse((tampered_output / "mutation").exists())

        incomplete_output = self.root / "incomplete-mutation"
        incomplete_output.mkdir()
        with self.assertRaisesRegex(ReviewError, "incomplete artifact set"):
            qualifier.retain_validated_mutation_evidence(
                captured_before_replacement._replace(
                    artifacts=captured_before_replacement.artifacts[:-1]
                ),
                output=incomplete_output,
            )
        self.assertFalse((incomplete_output / "mutation").exists())

        manifest.write_bytes(manifest_bytes)
        signature.write_bytes(signature_bytes)
        first_outcomes.write_bytes(first_bytes)

        with (
            mock.patch.object(assurance, "MAX_MUTATION_EVIDENCE_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "aggregate byte limit"),
        ):
            validate_mutation_evidence(
                manifest,
                signature,
                allowed_signers=allowed,
                repo=candidate_repo,
                commit=repository_commit,
                tree=repository_tree,
            )

        retained_diff.unlink()
        with self.assertRaisesRegex(ReviewError, "retained mutation Git diff"):
            validate_mutation_evidence(
                manifest,
                signature,
                allowed_signers=allowed,
                repo=candidate_repo,
                commit=repository_commit,
                tree=repository_tree,
            )
        retained_diff.write_bytes(diff)

        broad_receipt = self.root / "broad-runs/0-of-4" / BROAD_MUTATION_RECEIPT
        valid_receipt = broad_receipt.read_bytes()
        wrong_run_receipt = json.loads(valid_receipt)
        wrong_run_receipt["github_run"]["run_attempt"] = "2"
        wrong_run_bytes = canonical_json(wrong_run_receipt)
        broad_receipt.write_bytes(wrong_run_bytes)
        manifest_document["broad_run_receipts"][0]["artifact"] = {
            "path": broad_receipt.relative_to(self.root).as_posix(),
            "sha256": hashlib.sha256(wrong_run_bytes).hexdigest(),
            "size_bytes": len(wrong_run_bytes),
        }
        signature.unlink()
        manifest.write_bytes(canonical_json(manifest_document))
        signature = sign_file(manifest, key, "galadriel-mutation-evidence")
        with self.assertRaisesRegex(ReviewError, "targets another GitHub run"):
            validate_mutation_evidence(
                manifest,
                signature,
                allowed_signers=allowed,
                repo=candidate_repo,
                commit=repository_commit,
                tree=repository_tree,
            )

        broad_receipt.write_bytes(valid_receipt)
        manifest_document["broad_run_receipts"][0]["artifact"] = {
            "path": broad_receipt.relative_to(self.root).as_posix(),
            "sha256": hashlib.sha256(valid_receipt).hexdigest(),
            "size_bytes": len(valid_receipt),
        }
        second_outcomes = self.root / "broad-runs/1-of-4/mutants.out/outcomes.json"
        duplicate_outcomes = first_outcomes.read_bytes()
        second_outcomes.write_bytes(duplicate_outcomes)
        manifest_document["shards"][1]["artifact"] = {
            "path": second_outcomes.relative_to(self.root).as_posix(),
            "sha256": hashlib.sha256(duplicate_outcomes).hexdigest(),
            "size_bytes": len(duplicate_outcomes),
        }
        second_receipt = self.root / "broad-runs/1-of-4" / BROAD_MUTATION_RECEIPT
        second_receipt_document = json.loads(second_receipt.read_bytes())
        second_receipt_document["outcomes"]["sha256"] = hashlib.sha256(
            duplicate_outcomes
        ).hexdigest()
        second_receipt_document["outcomes"]["size_bytes"] = len(duplicate_outcomes)
        second_receipt_bytes = canonical_json(second_receipt_document)
        second_receipt.write_bytes(second_receipt_bytes)
        manifest_document["broad_run_receipts"][1]["artifact"] = {
            "path": second_receipt.relative_to(self.root).as_posix(),
            "sha256": hashlib.sha256(second_receipt_bytes).hexdigest(),
            "size_bytes": len(second_receipt_bytes),
        }
        signature.unlink()
        manifest.write_bytes(canonical_json(manifest_document))
        signature = sign_file(manifest, key, "galadriel-mutation-evidence")
        with self.assertRaisesRegex(ReviewError, "duplicates another shard mutant"):
            validate_mutation_evidence(
                manifest,
                signature,
                allowed_signers=allowed,
                repo=candidate_repo,
                commit=repository_commit,
                tree=repository_tree,
            )

    def test_tracked_evidence_config_is_bound_to_accepted_output(self) -> None:
        source_bytes = (ROOT / "evidence/galadriel-0.9-candidate.json").read_bytes()
        source = json.loads(source_bytes)
        tracked = self.root / "tracked.json"
        tracked.write_bytes(source_bytes)
        accepted = assurance._accepted_evidence_config_from_source(source)
        output = self.root / "evidence"
        output.mkdir()
        (output / "config.json").write_bytes(canonical_json(accepted))
        source_sha = hashlib.sha256(tracked.read_bytes()).hexdigest()
        accepted_sha = hashlib.sha256((output / "config.json").read_bytes()).hexdigest()
        manifest = {
            "accepted_config_digest": accepted["canonical_digest"],
            "inputs": {
                "config_source_path": "evidence/galadriel-0.9-candidate.json",
                "config_source_sha256": source_sha,
                "canonical_config_sha256": accepted_sha,
            },
        }
        (output / "manifest.json").write_bytes(canonical_json(manifest))
        result = validate_evidence_config_binding(
            tracked,
            output,
            tracked_relative_path="evidence/galadriel-0.9-candidate.json",
        )
        self.assertEqual(result["tracked_blob_sha256"], source_sha)
        self.assertEqual(
            result["accepted_semantic_digest"], accepted["canonical_digest"]
        )

        altered = copy.deepcopy(accepted)
        altered["runner_contract"]["bootstrap_profile"] = "another-profile"
        (output / "config.json").write_bytes(canonical_json(altered))
        manifest["inputs"]["canonical_config_sha256"] = hashlib.sha256(
            (output / "config.json").read_bytes()
        ).hexdigest()
        (output / "manifest.json").write_bytes(canonical_json(manifest))
        with self.assertRaisesRegex(ReviewError, "exact derived object"):
            validate_evidence_config_binding(
                tracked,
                output,
                tracked_relative_path="evidence/galadriel-0.9-candidate.json",
            )

        (output / "config.json").write_bytes(canonical_json(accepted))
        manifest["inputs"]["canonical_config_sha256"] = accepted_sha

        manifest["inputs"]["config_source_sha256"] = "0" * 64
        (output / "manifest.json").write_bytes(canonical_json(manifest))
        with self.assertRaisesRegex(ReviewError, "source-config blob digest mismatch"):
            validate_evidence_config_binding(
                tracked,
                output,
                tracked_relative_path="evidence/galadriel-0.9-candidate.json",
            )

    def test_manifest_rejects_digest_mismatch_and_self_reference(self) -> None:
        tier = self.root / "manifest-tier"
        tier.mkdir()
        artifact = tier / "artifact.bin"
        artifact.write_bytes(b"artifact")
        manifest = tier / "manifest.json"
        base = {
            "schema": "fixture.v1",
            "tier": "fixture",
            "candidate": {"commit": self.commit, "tree": self.tree},
            "artifacts": [
                {"path": "artifact.bin", "sha256": "0" * 64, "size_bytes": 8}
            ],
        }
        manifest.write_bytes(canonical_json(base))
        with self.assertRaisesRegex(ReviewError, "digest mismatch"):
            verify_artifact_manifest(
                tier,
                manifest,
                expected_schema="fixture.v1",
                forbidden_paths={"manifest.json"},
            )
        base["artifacts"] = [
            {"path": "manifest.json", "sha256": "0" * 64, "size_bytes": 0}
        ]
        manifest.write_bytes(canonical_json(base))
        with self.assertRaisesRegex(ReviewError, "self-reference"):
            verify_artifact_manifest(
                tier,
                manifest,
                expected_schema="fixture.v1",
                forbidden_paths={"manifest.json"},
            )
        base["artifacts"] = [
            {
                "path": "artifact.bin",
                "sha256": hashlib.sha256(b"artifact").hexdigest(),
                "size_bytes": 8,
            }
        ]
        (tier / "unlisted.bin").write_bytes(b"unlisted")
        manifest.write_bytes(canonical_json(base))
        with self.assertRaisesRegex(ReviewError, "omits retained files"):
            verify_artifact_manifest(
                tier,
                manifest,
                expected_schema="fixture.v1",
                forbidden_paths={"manifest.json"},
            )

    def test_manifest_enforces_canonical_resource_bounds(self) -> None:
        def make_tier(
            name: str, files: dict[str, bytes]
        ) -> tuple[Path, Path, dict[str, object]]:
            tier = self.root / name
            tier.mkdir()
            rows = []
            for relative, data in sorted(files.items()):
                target = tier.joinpath(*relative.split("/"))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                rows.append(
                    {
                        "path": relative,
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "size_bytes": len(data),
                    }
                )
            document: dict[str, object] = {
                "schema": "fixture.v1",
                "tier": "fixture",
                "candidate": {"commit": self.commit, "tree": self.tree},
                "artifacts": rows,
            }
            manifest = tier / "manifest.json"
            manifest.write_bytes(canonical_json(document))
            return tier, manifest, document

        tier, manifest, document = make_tier(
            "bounded-manifest-tier",
            {"first.bin": b"12", "second.bin": b"34"},
        )
        self.assertEqual(
            verify_artifact_manifest(
                tier,
                manifest,
                expected_schema="fixture.v1",
                forbidden_paths={"manifest.json"},
            ),
            document,
        )

        manifest_size = manifest.stat().st_size
        with (
            mock.patch.object(assurance, "MAX_TIER_MANIFEST_BYTES", manifest_size - 1),
            self.assertRaisesRegex(ReviewError, "exceeds"),
        ):
            verify_artifact_manifest(
                tier,
                manifest,
                expected_schema="fixture.v1",
                forbidden_paths={"manifest.json"},
            )

        for constant, limit, message in (
            ("MAX_EVIDENCE_JSON_DEPTH", 1, "JSON depth"),
            ("MAX_EVIDENCE_JSON_NODES", 2, "JSON nodes"),
        ):
            with self.subTest(constant=constant):
                with (
                    mock.patch.object(assurance, constant, limit),
                    self.assertRaisesRegex(ReviewError, message),
                ):
                    verify_artifact_manifest(
                        tier,
                        manifest,
                        expected_schema="fixture.v1",
                        forbidden_paths={"manifest.json"},
                    )

        with (
            mock.patch.object(assurance, "MAX_TIER_ARTIFACTS", 1),
            self.assertRaisesRegex(ReviewError, "artifact limit"),
        ):
            verify_artifact_manifest(
                tier,
                manifest,
                expected_schema="fixture.v1",
                forbidden_paths={"manifest.json"},
            )

        alias_document = copy.deepcopy(document)
        alias_rows = alias_document["artifacts"]
        assert isinstance(alias_rows, list)
        alias_rows[1]["path"] = "./second.bin"
        manifest.write_bytes(canonical_json(alias_document))
        with self.assertRaisesRegex(ReviewError, "not canonical"):
            verify_artifact_manifest(
                tier,
                manifest,
                expected_schema="fixture.v1",
                forbidden_paths={"manifest.json"},
            )

        manifest.write_bytes(canonical_json(document))
        with (
            mock.patch.object(assurance, "MAX_TIER_ARTIFACT_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "per-file byte limit"),
        ):
            verify_artifact_manifest(
                tier,
                manifest,
                expected_schema="fixture.v1",
                forbidden_paths={"manifest.json"},
            )

        actual_bound = copy.deepcopy(document)
        actual_rows = actual_bound["artifacts"]
        assert isinstance(actual_rows, list)
        for row in actual_rows:
            row["size_bytes"] = 1
        manifest.write_bytes(canonical_json(actual_bound))
        with (
            mock.patch.object(assurance, "MAX_TIER_ARTIFACT_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "file exceeds"),
        ):
            verify_artifact_manifest(
                tier,
                manifest,
                expected_schema="fixture.v1",
                forbidden_paths={"manifest.json"},
            )

        manifest.write_bytes(canonical_json(document))
        with (
            mock.patch.object(assurance, "MAX_TIER_AGGREGATE_BYTES", 3),
            self.assertRaisesRegex(ReviewError, "aggregate byte limit"),
        ):
            verify_artifact_manifest(
                tier,
                manifest,
                expected_schema="fixture.v1",
                forbidden_paths={"manifest.json"},
            )

        with (
            mock.patch.object(assurance, "MAX_TIER_TREE_ENTRIES", 2),
            self.assertRaisesRegex(ReviewError, "entry limit"),
        ):
            verify_artifact_manifest(
                tier,
                manifest,
                expected_schema="fixture.v1",
                forbidden_paths={"manifest.json"},
            )

    def test_manifest_rejects_unsafe_and_incomplete_tree_inventory(self) -> None:
        def manifest_for(tier: Path, relative: str, data: bytes) -> Path:
            manifest = tier / "manifest.json"
            manifest.write_bytes(
                canonical_json(
                    {
                        "schema": "fixture.v1",
                        "tier": "fixture",
                        "candidate": {"commit": self.commit, "tree": self.tree},
                        "artifacts": [
                            {
                                "path": relative,
                                "sha256": hashlib.sha256(data).hexdigest(),
                                "size_bytes": len(data),
                            }
                        ],
                    }
                )
            )
            return manifest

        outside_file = self.root / "manifest-outside.bin"
        outside_file.write_bytes(b"outside")
        outside_directory = self.root / "manifest-outside-directory"
        outside_directory.mkdir()
        (outside_directory / "artifact.bin").write_bytes(b"outside")

        cases: list[tuple[str, str, Callable[[Path], None], str]] = [
            (
                "final-symlink",
                "artifact.bin",
                lambda path: path.symlink_to(outside_file),
                "symlink",
            ),
            (
                "hardlink",
                "artifact.bin",
                lambda path: os.link(outside_file, path),
                "multiply linked",
            ),
        ]
        if hasattr(os, "mkfifo"):
            cases.append(("fifo", "artifact.bin", os.mkfifo, "special file"))
        for name, relative, install, message in cases:
            with self.subTest(kind=name):
                tier = self.root / f"manifest-{name}-tier"
                tier.mkdir()
                target = tier / relative
                install(target)
                manifest = manifest_for(tier, relative, b"outside")
                with self.assertRaisesRegex(ReviewError, message):
                    verify_artifact_manifest(
                        tier,
                        manifest,
                        expected_schema="fixture.v1",
                        forbidden_paths={"manifest.json"},
                    )

        intermediate = self.root / "manifest-intermediate-link-tier"
        intermediate.mkdir()
        (intermediate / "nested").symlink_to(
            outside_directory, target_is_directory=True
        )
        intermediate_manifest = manifest_for(
            intermediate, "nested/artifact.bin", b"outside"
        )
        with self.assertRaisesRegex(ReviewError, "symlink"):
            verify_artifact_manifest(
                intermediate,
                intermediate_manifest,
                expected_schema="fixture.v1",
                forbidden_paths={"manifest.json"},
            )

        empty_tier = self.root / "manifest-empty-directory-tier"
        empty_tier.mkdir()
        (empty_tier / "artifact.bin").write_bytes(b"artifact")
        (empty_tier / "empty").mkdir()
        empty_manifest = manifest_for(empty_tier, "artifact.bin", b"artifact")
        with self.assertRaisesRegex(ReviewError, "empty directory"):
            verify_artifact_manifest(
                empty_tier,
                empty_manifest,
                expected_schema="fixture.v1",
                forbidden_paths={"manifest.json"},
            )

        unlisted_tier = self.root / "manifest-unlisted-tier"
        unlisted_tier.mkdir()
        (unlisted_tier / "artifact.bin").write_bytes(b"artifact")
        (unlisted_tier / "unlisted.bin").write_bytes(b"unlisted")
        unlisted_manifest = manifest_for(unlisted_tier, "artifact.bin", b"artifact")
        with self.assertRaisesRegex(ReviewError, "omits retained files"):
            verify_artifact_manifest(
                unlisted_tier,
                unlisted_manifest,
                expected_schema="fixture.v1",
                forbidden_paths={"manifest.json"},
            )

    def test_evidence_references_use_rooted_no_follow_reads(self) -> None:
        qualification = self.root / "reference-qualification"
        nested = qualification / "nested"
        nested.mkdir(parents=True)
        artifact = nested / "evidence.json"
        artifact.write_bytes(b'{"status":"PASS"}\n')
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        reference = {
            "kind": "qualification_artifact",
            "path": "nested/evidence.json",
            "sha256": digest,
        }
        validated = validate_evidence_reference(
            reference,
            repo=self.repo,
            commit=self.commit,
            qualification_root=qualification,
            review_inputs={},
        )
        self.assertEqual(
            validated,
            f"qualification_artifact:nested/evidence.json:{digest}",
        )

        artifact.unlink()
        artifact.symlink_to(self.root / "missing-reference")
        with self.assertRaisesRegex(
            ReviewError, "missing or unsafe|singly linked regular file"
        ):
            validate_evidence_reference(
                reference,
                repo=self.repo,
                commit=self.commit,
                qualification_root=qualification,
                review_inputs={},
            )

        review_input = self.root / "review-input.json"
        review_input.write_bytes(b"review input\n")
        review_digest = hashlib.sha256(review_input.read_bytes()).hexdigest()
        review_reference = {
            "kind": "review_input",
            "path": "inputs/review-input.json",
            "sha256": review_digest,
        }
        self.assertEqual(
            validate_evidence_reference(
                review_reference,
                repo=self.repo,
                commit=self.commit,
                qualification_root=qualification,
                review_inputs={"inputs/review-input.json": review_input},
            ),
            f"review_input:inputs/review-input.json:{review_digest}",
        )

    def test_candidate_replaced_allowed_signer_is_rejected(self) -> None:
        key = self.root / "key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True,
        )
        external = self.root / "external" / "allowed"
        expected = derive_external_allowed_signers(key.with_suffix(".pub"), external)
        tracked = self.root / "tracked-allowed"
        tracked.write_bytes(expected)
        assert_tracked_allowed_signer(tracked, expected)
        for altered in (b"# comment\n" + expected, expected.rstrip(b"\n")):
            tracked.write_bytes(altered)
            with self.assertRaisesRegex(ReviewError, "replaced or altered"):
                assert_tracked_allowed_signer(tracked, expected)
        tracked.write_text(
            "sepmhn@gmail.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIForged\n",
            encoding="ascii",
        )
        with self.assertRaisesRegex(ReviewError, "replaced or altered"):
            assert_tracked_allowed_signer(tracked, expected)

    def test_allowed_signer_derivation_accepts_only_a_public_handle(self) -> None:
        key = self.root / "agent-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True,
        )
        allowed = derive_external_allowed_signers(
            key.with_suffix(".pub"), self.root / "public-allowed"
        )
        self.assertTrue(allowed.startswith(b"sepmhn@gmail.com ssh-ed25519 "))
        with self.assertRaisesRegex(ReviewError, "exactly one line"):
            derive_external_allowed_signers(key, self.root / "private-allowed")
        self.assertFalse((self.root / "private-allowed").exists())

    def test_agent_backed_public_signing_key_returns_canonical_identity(self) -> None:
        public = (
            b"ssh-ed25519 "
            b"AAAAC3NzaC1lZDI1NTE5AAAAIFixtureAgentBackedPublicKey "
            b"fixture-comment\n"
        )
        handle = self.root / "agent-handle.pub"
        handle.write_bytes(public)
        with mock.patch(
            "release_assurance.run_bounded_host_command",
            return_value=BoundedHostResult(0, public, b""),
        ):
            self.assertEqual(
                require_agent_backed_public_signing_key(handle),
                (
                    b"sepmhn@gmail.com ssh-ed25519 "
                    b"AAAAC3NzaC1lZDI1NTE5AAAAIFixtureAgentBackedPublicKey\n"
                ),
            )

    def test_finalizer_signing_handle_is_external_and_public_only(self) -> None:
        qualification = self.root / "qualification"
        output = self.root / "output"
        snapshots = self.root / "snapshots"
        qualification.mkdir()
        snapshots.mkdir()
        external = self.root / "external"
        external.mkdir()
        public_handle = external / "signing-key.pub"
        public_handle.write_text(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixturePublicKey comment\n",
            encoding="ascii",
        )

        self.assertEqual(
            finalization_signing_key_source(
                str(public_handle),
                repo=self.repo,
                qualification_root=qualification,
                final_output=output,
                snapshot_parent=snapshots,
            ),
            public_handle.resolve(),
        )
        for root, label in (
            (self.repo, "candidate repository"),
            (qualification, "qualification tier"),
            (output, "finalization output"),
            (snapshots, "snapshot root"),
        ):
            root.mkdir(parents=True, exist_ok=True)
            contained = root / f"{label.replace(' ', '-')}.pub"
            contained.write_bytes(public_handle.read_bytes())
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(ReviewError, "outside"),
            ):
                finalization_signing_key_source(
                    str(contained),
                    repo=self.repo,
                    qualification_root=qualification,
                    final_output=output,
                    snapshot_parent=snapshots,
                )

        destination = snapshots / "canonical-handle.pub"
        signer = (
            b"sepmhn@gmail.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixturePublicKey\n"
        )
        with mock.patch(
            "release_assurance.require_agent_backed_public_signing_key",
            return_value=signer,
        ):
            retained, observed = snapshot_agent_backed_public_signing_key(
                public_handle,
                destination,
            )
        self.assertEqual(observed, signer)
        self.assertEqual(
            retained.read_bytes(),
            b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixturePublicKey\n",
        )
        with (
            mock.patch(
                "release_assurance.require_agent_backed_public_signing_key",
                return_value=signer,
            ),
            self.assertRaisesRegex(ReviewError, "refusing to replace"),
        ):
            snapshot_agent_backed_public_signing_key(public_handle, destination)

    def test_finalizer_does_not_snapshot_private_signing_material(self) -> None:
        private = self.root / "private-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private)],
            check=True,
        )
        destination = self.root / "snapshot" / "SIGNING_KEY.pub"
        with self.assertRaisesRegex(ReviewError, "exactly one line"):
            snapshot_agent_backed_public_signing_key(private, destination)
        self.assertFalse(destination.exists())

    def test_unsigned_input_is_rejected(self) -> None:
        document = self.root / "unsigned.json"
        allowed = self.root / "allowed"
        document.write_text("{}\n", encoding="utf-8")
        allowed.write_text(
            "sepmhn@gmail.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixture\n",
            encoding="ascii",
        )
        with self.assertRaisesRegex(ReviewError, "cannot open detached signature"):
            verify_signature(
                document,
                self.root / "missing.sig",
                allowed,
                "fixture",
            )

    def test_invalid_signature_cannot_use_a_path_verifier_shim(self) -> None:
        key = self.root / "shim-verification-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True,
        )
        document = self.root / "shim-document.json"
        signature = self.root / "shim-document.json.sig"
        allowed = self.root / "shim-allowed-signers"
        document.write_text("{}\n", encoding="utf-8")
        signature.write_text("not an SSH signature\n", encoding="utf-8")
        derive_external_allowed_signers(key.with_suffix(".pub"), allowed)
        shim_root = self.root / "signature-shim"
        shim_root.mkdir()
        marker = shim_root / "invoked"
        shim = shim_root / "ssh-keygen"
        shim.write_text(
            f"#!/bin/sh\nprintf invoked > {marker}\nexit 0\n",
            encoding="utf-8",
        )
        shim.chmod(0o700)

        with (
            mock.patch.dict(os.environ, {"PATH": str(shim_root)}),
            self.assertRaisesRegex(ReviewError, "invalid fixture signature"),
        ):
            verify_signature(document, signature, allowed, "fixture")
        self.assertFalse(marker.exists())

    def test_agent_key_check_cannot_use_a_path_ssh_add_shim(self) -> None:
        key = self.root / "shim-agent-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True,
        )
        handle = key.with_suffix(".pub")
        shim_root = self.root / "agent-shim"
        shim_root.mkdir()
        marker = shim_root / "invoked"
        shim = shim_root / "ssh-add"
        shim.write_text(
            f"#!/bin/sh\nprintf invoked > {marker}\n/bin/cat {handle}\n",
            encoding="utf-8",
        )
        shim.chmod(0o700)

        with (
            mock.patch.dict(
                os.environ,
                {
                    "PATH": str(shim_root),
                    "SSH_AUTH_SOCK": str(self.root / "missing-agent.sock"),
                },
            ),
            self.assertRaisesRegex(ReviewError, "cannot inspect ssh-agent"),
        ):
            require_agent_backed_public_signing_key(handle)
        self.assertFalse(marker.exists())


class DispositionTests(GitFixture):
    def evidence_reference(self) -> dict[str, str]:
        data = subprocess.check_output(
            ["git", "show", f"{self.commit}:README.md"], cwd=self.repo
        )
        return {
            "kind": "candidate_blob",
            "path": "README.md",
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def build_document(
        self,
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        plan = json.loads((ROOT / "release/0.9.0/task-closure-plan.json").read_text())
        claims_document = json.loads((ROOT / "release/0.9.0/claims.json").read_text())
        claims = {claim["id"]: claim for claim in claims_document["claims"]}
        reference = self.evidence_reference()
        dispositions = []
        for task in plan["tasks"]:
            task_id = task["task_id"]
            source = task["source_projection"]
            excluded = {
                item["source_path"]: item["claim_removal_links"]
                for item in task["requirement_exclusions"]
            }

            def result(text: str, path: str) -> dict[str, object]:
                links = excluded.get(path, [])
                return {
                    "source_sha256": sha256_bytes(text.encode()),
                    "status": "NOT_CLAIMED" if links else "SATISFIED",
                    "evidence": [reference],
                    "claim_removal_links": links,
                }

            source_results: dict[str, object] = {}
            for category in (
                "preconditions",
                "procedure",
                "mandatory_counterfactuals",
                "required_evidence",
            ):
                source_results[category] = [
                    result(text, f"{category}[{index}]")
                    for index, text in enumerate(source[category])
                ]
            source_results["completion_rule"] = result(
                source["completion_rule"], "completion_rule"
            )
            removed = set(task["claim_removal_links"])
            removed.update(
                claim_id
                for item in task["requirement_exclusions"]
                for claim_id in item["claim_removal_links"]
            )
            removed.update(
                claim_id
                for links in task["lens_exclusions"].values()
                for claim_id in links
            )
            answers = {}
            for lens, source_lens in source["twenty_lens_review"].items():
                links = task["lens_exclusions"].get(lens, [])
                answers[lens] = {
                    "question_sha256": sha256_bytes(source_lens["question"].encode()),
                    "status": "NOT_CLAIMED" if links else "RESOLVED",
                    "finding": (
                        f"{task_id}/{lens}: Concrete author-operated finding binds this exact "
                        "source question to the candidate blob and its retained test evidence."
                    ),
                    "evidence": [reference],
                    "claim_removal_links": links,
                }
            dispositions.append(
                {
                    "task_id": task_id,
                    "status": "NOT_CLAIMED"
                    if task["status"] == "NOT_CLAIMED"
                    else "COMPLETE_WITH_EXCLUSIONS",
                    "source_projection_sha256": task["source_projection_sha256"],
                    "source_item_results": source_results,
                    "evidence": [reference],
                    "tests": [reference],
                    "failed_attempt_inventory": {
                        "status": "NONE_RECORDED",
                        "attempts": [],
                    },
                    "lens_answers": answers,
                    "residual_risks": [
                        f"{task_id}: This author-operated fixture retains exact-candidate scope and all planned exclusions."
                    ],
                    "removed_claim_ids": sorted(removed),
                }
            )
        document = {
            "schema": "galadriel.reviewed-task-dispositions.v2",
            "release": "0.9.0",
            "author": "Sepehr Mahmoudian",
            "candidate": {"commit": self.commit, "tree": self.tree},
            "source_plan_sha256": "2" * 64,
            "dispositions": dispositions,
        }
        return plan, claims, document

    def test_real_v2_source_plan_has_a_valid_reviewed_fixture(self) -> None:
        plan, claims, document = self.build_document()
        result = validate_reviewed_task_dispositions(
            document,
            plan=plan,
            claims=claims,
            repo=self.repo,
            commit=self.commit,
            tree=self.tree,
            qualification_root=self.root,
            source_plan_sha256="2" * 64,
        )
        self.assertEqual(result["total"], 116)
        self.assertEqual(result["not_claimed"], 9)

    def test_wrong_commit_and_generic_task_lens_are_rejected(self) -> None:
        plan, claims, document = self.build_document()
        wrong = copy.deepcopy(document)
        wrong["candidate"]["commit"] = "0" * 40
        with self.assertRaisesRegex(ReviewError, "wrong candidate"):
            validate_reviewed_task_dispositions(
                wrong,
                plan=plan,
                claims=claims,
                repo=self.repo,
                commit=self.commit,
                tree=self.tree,
                qualification_root=self.root,
                source_plan_sha256="2" * 64,
            )
        newly_unclaimed = copy.deepcopy(document)
        pending_index = next(
            index
            for index, task in enumerate(plan["tasks"])
            if task["status"] == "PENDING_POST_COMMIT"
        )
        newly_unclaimed["dispositions"][pending_index]["status"] = "NOT_CLAIMED"
        with self.assertRaisesRegex(ReviewError, "must be completed"):
            validate_reviewed_task_dispositions(
                newly_unclaimed,
                plan=plan,
                claims=claims,
                repo=self.repo,
                commit=self.commit,
                tree=self.tree,
                qualification_root=self.root,
                source_plan_sha256="2" * 64,
            )
        generic = copy.deepcopy(document)
        generic["dispositions"][0]["lens_answers"]["L01"]["finding"] = (
            "A generic checklist statement has enough characters but omits the exact task identity."
        )
        with self.assertRaisesRegex(ReviewError, "generic task lens"):
            validate_reviewed_task_dispositions(
                generic,
                plan=plan,
                claims=claims,
                repo=self.repo,
                commit=self.commit,
                tree=self.tree,
                qualification_root=self.root,
                source_plan_sha256="2" * 64,
            )


class DecisionAndRunnerTests(unittest.TestCase):
    def test_process_receipt_and_probe_identity_shapes_are_exact(self) -> None:
        source = Path(qualifier.__file__).read_text(encoding="utf-8")
        module = ast.parse(source)
        classes = {
            node.name: node
            for node in module.body
            if isinstance(node, ast.ClassDef)
        }
        result_class = classes["BoundedProcessResult"]
        annotated_fields = [
            node.target.id
            for node in result_class.body
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
        ]
        self.assertEqual(
            annotated_fields,
            [
                "returncode",
                "timed_out",
                "stdout",
                "stderr",
                "output_limit_exceeded",
                "containment_error",
            ],
        )

        identity_hints = typing.get_type_hints(qualifier.SandboxProcessIdentity)
        expected_identity_fields = (int,) * 7
        self.assertEqual(
            typing.get_args(identity_hints["deny_identity"]),
            expected_identity_fields,
        )
        self.assertEqual(
            typing.get_args(identity_hints["allow_identity"]),
            expected_identity_fields,
        )

    @staticmethod
    def make_candidate_evidence(root: Path) -> Path:
        evidence = root / "candidate-evidence"
        evidence.mkdir()
        for name in EXPECTED_CANDIDATE_EVIDENCE_FILES:
            payload = b"{}\n" if name.endswith(".json") else b"fixture\n"
            (evidence / name).write_bytes(payload)
        return evidence

    def test_candidate_evidence_snapshot_rejects_special_and_oversized_files(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self.make_candidate_evidence(root)
            (evidence / "report.md").unlink()
            os.mkfifo(evidence / "report.md")
            with self.assertRaisesRegex(ReviewError, "special file"):
                retain_candidate_evidence(evidence, root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self.make_candidate_evidence(root)
            with (
                mock.patch("qualify_candidate.MAX_QUALIFICATION_ARTIFACT_BYTES", 1),
                self.assertRaisesRegex(ReviewError, "file exceeds"),
            ):
                retain_candidate_evidence(evidence, root)

    def test_candidate_evidence_json_has_structural_bounds(self) -> None:
        payload = (b'{"nested":' * 300) + b"null" + (b"}" * 300)
        with self.assertRaisesRegex(ReviewError, "depth|strict JSON"):
            decode_candidate_evidence_json(payload, "candidate evidence summary")

    def test_candidate_evidence_snapshot_detects_post_inventory_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self.make_candidate_evidence(root)
            real_inventory = qualifier.candidate_evidence_inventory
            changed = False

            def mutate_after_inventory(
                path: Path, *, capture_json: bool
            ) -> tuple[dict[str, tuple[str, int]], dict[str, bytes]]:
                nonlocal changed
                result = real_inventory(path, capture_json=capture_json)
                if path == evidence and not changed:
                    (evidence / "summary.json").write_bytes(b"[]\n")
                    changed = True
                return result

            with (
                mock.patch(
                    "qualify_candidate.candidate_evidence_inventory",
                    side_effect=mutate_after_inventory,
                ),
                self.assertRaisesRegex(ReviewError, "changed before quarantine"),
            ):
                retain_candidate_evidence(evidence, root)

    def test_shallow_qualification_cannot_report_pass(self) -> None:
        self.assertEqual(
            qualification_outcome(
                command_status="PASS",
                archive_present=True,
                acceptance_status="PASS",
                deep_requested=False,
            ),
            ("FAIL", "FAIL"),
        )
        self.assertEqual(
            qualification_outcome(
                command_status="PASS",
                archive_present=True,
                acceptance_status="PASS",
                deep_requested=True,
            ),
            ("PASS", "PASS"),
        )

    def test_host_runner_interrupt_kills_and_reaps_process_group(self) -> None:
        candidate_pid: int | None = None
        real_popen = subprocess.Popen
        real_selector = selectors.DefaultSelector

        class InterruptSelector:
            def __init__(self) -> None:
                self.delegate = real_selector()

            def register(self, *args: object, **kwargs: object) -> object:
                return self.delegate.register(*args, **kwargs)

            def get_map(self) -> object:
                return self.delegate.get_map()

            def select(self, timeout: float | None = None) -> object:
                del timeout
                raise KeyboardInterrupt

            def close(self) -> None:
                self.delegate.close()

        def start(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            nonlocal candidate_pid
            process = real_popen(*args, **kwargs)
            candidate_pid = process.pid
            return process

        with (
            mock.patch(
                "common.selectors.DefaultSelector",
                InterruptSelector,
            ),
            mock.patch("common.subprocess.Popen", side_effect=start),
            self.assertRaises(KeyboardInterrupt),
        ):
            run_bounded_host_command(
                [sys.executable, "-I", "-c", "import time; time.sleep(20)"],
                context="interrupt fixture",
                environment={"PATH": os.environ["PATH"]},
                timeout_seconds=2,
            )
        self.assertIsNotNone(candidate_pid)
        assert candidate_pid is not None
        with self.assertRaises(ProcessLookupError):
            os.kill(candidate_pid, 0)

    @unittest.skipUnless(sys.platform == "darwin", "macOS containment test")
    def test_launch_interrupt_kills_and_reaps_candidate(self) -> None:
        candidate_pid: int | None = None

        def interrupt(process: subprocess.Popen[bytes]) -> None:
            nonlocal candidate_pid
            candidate_pid = process.pid
            raise KeyboardInterrupt

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            environment = command_test_environment(root)
            sandbox = candidate_sandbox_profile(root, worktree=root)
            with (
                mock.patch(
                    "qualify_candidate._wait_for_launch_gate",
                    side_effect=interrupt,
                ),
                mock.patch(
                    "qualify_candidate.verify_qualification_tool_dispatch",
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                run_bounded_process(
                    qualifier.sandboxed_argv(
                        sandbox,
                        [
                            sys.executable,
                            "-I",
                            "-c",
                            "import time; time.sleep(20)",
                        ],
                        environment=environment,
                    ),
                    cwd=root,
                    environment=environment,
                    timeout_seconds=2,
                    separate_stderr=True,
                )
        self.assertIsNotNone(candidate_pid)
        assert candidate_pid is not None
        with self.assertRaises(ProcessLookupError):
            os.kill(candidate_pid, signal.SIGCONT)

    @unittest.skipUnless(sys.platform == "darwin", "macOS sandbox test")
    def test_candidate_sandbox_denies_external_signals_and_allows_owned_signals(
        self,
    ) -> None:
        source = """
import os
import signal
import subprocess
import sys

external = int(sys.argv[1])
try:
    os.kill(external, 0)
except PermissionError:
    pass
else:
    raise SystemExit(10)

os.kill(os.getpid(), 0)
child = subprocess.Popen(
    [sys.executable, "-I", "-c", "import time; time.sleep(20)"],
)
os.kill(child.pid, signal.SIGTERM)
child.wait(timeout=3)
if child.returncode != -signal.SIGTERM:
    raise SystemExit(11)
"""
        helper = subprocess.Popen(
            [sys.executable, "-I", "-c", "import time; time.sleep(20)"],
            start_new_session=True,
        )
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                environment = command_test_environment(root)
                sandbox = candidate_sandbox_profile(root, worktree=root)
                profile = sandbox.read_text(encoding="utf-8")
                self.assertIn("(deny signal)\n", profile)
                self.assertIn("(allow signal (target self))\n", profile)
                self.assertIn("(allow signal (target children))\n", profile)
                result = run_bounded_process(
                    qualifier.sandboxed_argv(
                        sandbox,
                        [sys.executable, "-I", "-c", source, str(helper.pid)],
                        environment=environment,
                    ),
                    cwd=root,
                    environment=environment,
                    timeout_seconds=10,
                    separate_stderr=True,
                )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
            self.assertIsNone(result.containment_error)
            self.assertIsNone(helper.poll())
        finally:
            helper.terminate()
            try:
                helper.wait(timeout=3)
            except subprocess.TimeoutExpired:
                helper.kill()
                helper.wait(timeout=3)

    def test_atomic_failure_record_replaces_a_prior_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qualification.json"
            write_atomic_canonical_json(path, {"status": "PASS"})
            write_atomic_canonical_json(
                path,
                {"status": "FAIL", "error": "late validation failed"},
            )
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                {"error": "late validation failed", "status": "FAIL"},
            )
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(
                tuple(path.parent.glob(".qualification.json.*.tmp")),
                (),
            )

    def test_locked_fetch_requires_passing_preflight(self) -> None:
        fetches = [
            spec
            for spec in BASE_COMMANDS
            if spec.name in DEPENDENCY_FETCH_COMMAND_NAMES
        ]
        self.assertEqual(
            [spec.name for spec in fetches],
            [
                "fetch-locked-dependencies",
                "fetch-locked-fuzz-dependencies",
            ],
        )
        self.assertEqual(
            fetches[1].argv,
            ("cargo", "fetch", "--locked", "--manifest-path", "fuzz/Cargo.toml"),
        )
        passing = [{"status": "PASS"}, {"status": "PASS"}]
        failed = [{"status": "PASS"}, {"status": "FAIL"}]
        for fetch in fetches:
            self.assertTrue(network_command_preconditions_met(fetch, passing))
            self.assertFalse(network_command_preconditions_met(fetch, failed))
        self.assertTrue(
            network_command_preconditions_met(
                CommandSpec("offline-check", ("true",)),
                failed,
            )
        )
        with self.assertRaisesRegex(ReviewError, "no prior preflight"):
            network_command_preconditions_met(fetches[0], [])
        with self.assertRaisesRegex(ReviewError, "invalid status"):
            network_command_preconditions_met(fetches[0], [{"status": "SKIP"}])

    def test_semantic_freeze_verification_precedes_release_audit(self) -> None:
        names = [spec.name for spec in BASE_COMMANDS]
        freeze_index = names.index("frozen-audit-inputs-verify")
        audit_index = names.index("release-audit-verify")
        self.assertEqual(freeze_index + 1, audit_index)
        self.assertIn(
            qualifier.INDEPENDENT_ALLOWED_SIGNERS_PLACEHOLDER,
            BASE_COMMANDS[freeze_index].argv,
        )
        trust = Path("/private/review/INDEPENDENT_ALLOWED_SIGNERS")
        materialized = qualifier.qualification_base_commands(trust)
        self.assertEqual(
            materialized[freeze_index].argv,
            (
                "python3",
                "repo_work/freeze_audit_inputs.py",
                "verify",
                "--repo",
                ".",
                "--out",
                "release/0.9.0/audit/FROZEN-AUDIT-INPUTS-0.9.0.json",
                "--allowed-signers",
                str(trust),
            ),
        )
        with self.assertRaisesRegex(ReviewError, "independent allowed-signers"):
            qualifier.qualification_base_commands(
                Path("release/0.9.0/audit/ALLOWED_SIGNERS")
            )

    def test_release_tool_qualification_matches_the_ci_module_set(self) -> None:
        command = next(
            spec for spec in BASE_COMMANDS if spec.name == "release-tool-tests"
        )
        modules = command.argv[4:]
        expected = (
            "scripts.tests.test_release_audit",
            "repo_work.tests.test_release_audit_snapshot",
            "repo_work.tests.test_evidence_batch_transaction",
            "repo_work.tests.test_file_mode_identity",
            "repo_work.tests.test_package_release_assets",
            "repo_work.tests.test_review_tools",
            "repo_work.tests.test_task_dispositions",
            "repo_work.tests.test_release_assurance",
            "repo_work.tests.test_candidate_evidence_bundle",
            "repo_work.tests.test_qualify_candidate_evidence",
            "repo_work.tests.test_finalize_qualification",
            "repo_work.tests.test_qualification_artifacts",
            "repo_work.tests.test_host_process_bounds",
        )
        self.assertEqual(modules, expected)
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        runbook = (ROOT / "release/0.9.0/RELEASE-RUNBOOK.md").read_text(
            encoding="utf-8"
        )
        for module in expected:
            with self.subTest(module=module):
                self.assertIn(module, workflow)
                self.assertIn(module, runbook)

    def test_qualification_commands_are_argv_and_output_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logs = root / "logs"
            logs.mkdir()
            recorded_root = root.resolve()
            inventory = recorded_root / "source-inventory"
            trust = "/tmp/galadriel-recorded-trust/INDEPENDENT_ALLOWED_SIGNERS"
            dynamic = (
                CommandSpec(
                    "verify-commit-signature-external-key",
                    (
                        "git",
                        "--no-replace-objects",
                        *SAFE_GIT_CONFIGURATION,
                        "-c",
                        "gpg.format=ssh",
                        "-c",
                        f"gpg.ssh.allowedSignersFile={trust}",
                        "verify-commit",
                        "HEAD",
                    ),
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
                    "placeholder",
                    ("true",),
                ),
            )
            dynamic_by_name = {spec.name: spec for spec in dynamic}
            evidence_build, evidence_run = qualifier.candidate_evidence_command_specs(
                target_directory=recorded_root / "target",
                runner_executable=(
                    recorded_root / "evidence-runner" / "galadriel-evidence"
                ),
                evidence_config="evidence/galadriel-0.9-candidate.json",
                evidence_output=recorded_root / "candidate-evidence",
            )
            specs = [
                dynamic_by_name["verify-commit-signature-external-key"],
                dynamic_by_name["tracked-source-inventory"],
                dynamic_by_name["review-packets"],
                dynamic_by_name["claim-language-inventory"],
                *qualifier.qualification_base_commands(Path(trust)),
                evidence_build,
                evidence_run,
                *deep_command_specs(recorded_root),
            ]
            commands = []
            manifest = {}
            candidate_policy_sha256 = "a" * 64
            dependency_fetch_policy_sha256 = "b" * 64
            if sys.platform == "darwin":
                git_executable = qualifier.resolve_candidate_git_executable()
            else:
                git_executable = portable_test_git_executable(root)
                self.enterContext(
                    mock.patch.object(
                        qualifier,
                        "DEVELOPER_GIT_PATHS",
                        (git_executable,),
                    )
                )
            for index, spec in enumerate(specs, 1):
                executed_argv = qualifier.qualification_executed_argv(
                    spec.argv,
                    git_executable=git_executable,
                )
                relative = f"logs/{index:02d}-{spec.name}.log"
                sandbox = {
                    "executor": "/usr/bin/sandbox-exec",
                    "policy_sha256": (
                        dependency_fetch_policy_sha256
                        if spec.name in DEPENDENCY_FETCH_COMMAND_NAMES
                        else candidate_policy_sha256
                    ),
                    "network_policy": (
                        "LOCKED_DEPENDENCY_FETCH"
                        if spec.name in DEPENDENCY_FETCH_COMMAND_NAMES
                        else "DENY"
                    ),
                }
                header = {
                    "argv": executed_argv,
                    "cwd": spec.cwd,
                    "environment_overrides": dict(spec.environment),
                    "sandbox": sandbox,
                    "started_at": "2026-07-14T00:00:00.000+00:00",
                    "subject_executable": spec.subject_executable,
                    "timeout_seconds": spec.timeout_seconds,
                }
                log = root / relative
                combined_output = b"PASS\n"
                receipt = {
                    "name": spec.name,
                    "argv": executed_argv,
                    "cwd": spec.cwd,
                    "environment_overrides": dict(spec.environment),
                    "sandbox": sandbox,
                    "execution_policy": execution_policy_contract(spec.timeout_seconds),
                    "started_at": "2026-07-14T00:00:00.000+00:00",
                    "finished_at": "2026-07-14T00:00:01.000+00:00",
                    "duration_seconds": 1.0,
                    "timeout_seconds": spec.timeout_seconds,
                    "timed_out": False,
                    "exit_code": 0,
                    "status": "PASS",
                    "log": relative,
                    "combined_output_sha256": hashlib.sha256(
                        combined_output
                    ).hexdigest(),
                    "combined_output_size_bytes": len(combined_output),
                    "subject_executable": (
                        None
                        if spec.subject_executable is None
                        else {
                            "status": "UNCHANGED",
                            "identity": {
                                "invoked_path": spec.subject_executable,
                                "resolved_path": spec.subject_executable,
                                "sha256": "c" * 64,
                                "size_bytes": 1_024,
                                "uid": 501,
                                "gid": 20,
                                "mode": 0o500,
                            },
                        }
                    ),
                }
                receipt = write_receipt_log(
                    log,
                    canonical_json(header)
                    + b"--- combined stdout/stderr ---\n"
                    + combined_output,
                    receipt,
                )
                manifest[relative] = {
                    "path": relative,
                    "sha256": receipt["log_sha256"],
                    "size_bytes": receipt["log_size_bytes"],
                }
                commands.append(receipt)
            validate_qualification_commands(
                commands,
                manifest_artifacts=manifest,
                qualification_root=root,
                sandbox_policy_sha256=candidate_policy_sha256,
                dependency_fetch_policy_sha256=dependency_fetch_policy_sha256,
                git_executable=git_executable,
                private_root=recorded_root,
                allowed_signers_snapshot=Path(trust),
            )
            logical_git = copy.deepcopy(commands)
            logical_git[0]["argv"][0] = "git"
            with self.assertRaisesRegex(ReviewError, "commit-verification command"):
                validate_qualification_commands(
                    logical_git,
                    manifest_artifacts=manifest,
                    qualification_root=root,
                    sandbox_policy_sha256=candidate_policy_sha256,
                    dependency_fetch_policy_sha256=dependency_fetch_policy_sha256,
                    git_executable=git_executable,
                    private_root=recorded_root,
                    allowed_signers_snapshot=Path(trust),
                )
            wrong_output = copy.deepcopy(commands)
            wrong_output[1]["argv"][-1] = "/tmp/another-qualification/source-inventory"
            with self.assertRaisesRegex(ReviewError, "another output directory"):
                validate_qualification_commands(
                    wrong_output,
                    manifest_artifacts=manifest,
                    qualification_root=root,
                    sandbox_policy_sha256=candidate_policy_sha256,
                    dependency_fetch_policy_sha256=dependency_fetch_policy_sha256,
                    git_executable=git_executable,
                    private_root=recorded_root,
                    allowed_signers_snapshot=Path(trust),
                )
            commands[5]["argv"] = ["true"]
            with self.assertRaisesRegex(ReviewError, "command contract drifted"):
                validate_qualification_commands(
                    commands,
                    manifest_artifacts=manifest,
                    qualification_root=root,
                    sandbox_policy_sha256=candidate_policy_sha256,
                    dependency_fetch_policy_sha256=dependency_fetch_policy_sha256,
                    git_executable=git_executable,
                    private_root=recorded_root,
                    allowed_signers_snapshot=Path(trust),
                )

    def test_mutation_outcomes_are_nonvacuous_and_internally_consistent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "outcomes.json"
            valid = broad_outcomes_document()
            path.write_bytes(canonical_json(valid))
            self.assertEqual(validate_mutation_outcomes(path, "0/4")["caught"], 400)

            functionless = copy.deepcopy(valid)
            top_level = functionless["outcomes"][1]["scenario"]["Mutant"]
            top_level.update(
                {
                    "name": (
                        "crates/galadriel-core/src/fixture.rs:2:1: replace * with +"
                    ),
                    "function": None,
                    "replacement": "+",
                    "genre": "BinaryOperator",
                }
            )
            path.write_bytes(canonical_json(functionless))
            self.assertEqual(
                validate_mutation_outcomes(path, "0/4")["caught"],
                400,
            )
            functionless_unary = copy.deepcopy(functionless)
            top_level_unary = functionless_unary["outcomes"][1]["scenario"]["Mutant"]
            top_level_unary.update(
                {
                    "name": "crates/galadriel-core/src/fixture.rs:2:1: delete !",
                    "replacement": "",
                    "genre": "UnaryOperator",
                }
            )
            path.write_bytes(canonical_json(functionless_unary))
            self.assertEqual(
                validate_mutation_outcomes(path, "0/4")["caught"],
                400,
            )

            for name, mutate in (
                (
                    "vacuous",
                    lambda item: item.update(
                        total_mutants=0,
                        caught=0,
                        unviable=0,
                        outcomes=[item["outcomes"][0]],
                    ),
                ),
                (
                    "missed",
                    lambda item: (
                        item.update(missed=1, caught=item["caught"] - 1),
                        item["outcomes"][1].update(summary="MissedMutant"),
                    ),
                ),
                ("contradictory", lambda item: item["outcomes"].pop()),
            ):
                with self.subTest(name=name):
                    altered = copy.deepcopy(valid)
                    mutate(altered)
                    path.write_bytes(canonical_json(altered))
                    with self.assertRaises(ReviewError):
                        validate_mutation_outcomes(path, "0/4")

            variants: list[tuple[str, dict[str, object], str]] = []
            empty_descriptor = copy.deepcopy(valid)
            empty_descriptor["outcomes"][1]["scenario"]["Mutant"] = {}
            variants.append(("empty descriptor", empty_descriptor, "missing="))
            missing_phase = copy.deepcopy(valid)
            missing_phase["outcomes"][1]["phase_results"].pop()
            variants.append(("missing phase", missing_phase, "phase or summary"))
            duplicate = copy.deepcopy(valid)
            duplicate["outcomes"][2]["scenario"]["Mutant"] = copy.deepcopy(
                duplicate["outcomes"][1]["scenario"]["Mutant"]
            )
            variants.append(("duplicate descriptor", duplicate, "duplicates"))
            duplicate_functionless = copy.deepcopy(functionless)
            duplicate_functionless["outcomes"][2]["scenario"]["Mutant"] = copy.deepcopy(
                duplicate_functionless["outcomes"][1]["scenario"]["Mutant"]
            )
            variants.append(
                (
                    "duplicate functionless descriptor",
                    duplicate_functionless,
                    "duplicates",
                )
            )
            wrong_functionless_genre = copy.deepcopy(functionless)
            wrong_functionless_genre["outcomes"][1]["scenario"]["Mutant"]["genre"] = (
                "FnValue"
            )
            variants.append(
                (
                    "wrong functionless genre",
                    wrong_functionless_genre,
                    "functionless descriptor has a function-only mutation genre",
                )
            )
            malformed_function = copy.deepcopy(valid)
            malformed_function["outcomes"][1]["scenario"]["Mutant"]["function"] = []
            variants.append(
                (
                    "function list",
                    malformed_function,
                    "function must be an object",
                )
            )
            scalar_function = copy.deepcopy(valid)
            scalar_function["outcomes"][1]["scenario"]["Mutant"]["function"] = (
                "fixture_2"
            )
            variants.append(
                (
                    "function scalar",
                    scalar_function,
                    "function must be an object",
                )
            )
            missing_function_field = copy.deepcopy(valid)
            del missing_function_field["outcomes"][1]["scenario"]["Mutant"]["function"][
                "return_type"
            ]
            variants.append(
                (
                    "missing function field",
                    missing_function_field,
                    "missing=\\['return_type'\\]",
                )
            )
            extra_function_field = copy.deepcopy(valid)
            extra_function_field["outcomes"][1]["scenario"]["Mutant"]["function"][
                "identifier"
            ] = "fixture_2"
            variants.append(
                (
                    "extra function field",
                    extra_function_field,
                    "unexpected=\\['identifier'\\]",
                )
            )
            escaped_function_span = copy.deepcopy(valid)
            escaped_function_span["outcomes"][1]["scenario"]["Mutant"]["function"][
                "span"
            ] = focused_span_document((3, 1, 503, 2))
            variants.append(
                (
                    "escaped function span",
                    escaped_function_span,
                    "mutation span escapes its function",
                )
            )
            wrong_cargo = copy.deepcopy(valid)
            wrong_cargo["outcomes"][1]["phase_results"][0]["argv"].insert(2, "--quiet")
            variants.append(
                ("wrong Cargo command", wrong_cargo, "another Cargo command")
            )
            ambiguous_replacement = copy.deepcopy(valid)
            ambiguous_replacement["outcomes"][1]["scenario"]["Mutant"][
                "replacement"
            ] = ""
            variants.append(
                (
                    "ambiguous empty replacement",
                    ambiguous_replacement,
                    "ambiguous empty replacement",
                )
            )
            for name, altered, message in variants:
                with self.subTest(name=name):
                    path.write_bytes(canonical_json(altered))
                    with self.assertRaisesRegex(ReviewError, message):
                        validate_mutation_outcomes(path, "0/4")

            path.write_bytes(
                canonical_json(broad_outcomes_document(total=499, caught=400))
            )
            with self.assertRaisesRegex(ReviewError, "fewer than 500"):
                validate_mutation_outcomes(path, "0/4")
            path.write_bytes(
                canonical_json(broad_outcomes_document(total=500, caught=1))
            )
            with self.assertRaisesRegex(ReviewError, "less than 70%"):
                validate_mutation_outcomes(path, "0/4")
            path.write_bytes(canonical_json(valid))
            linked = Path(directory) / "linked" / "outcomes.json"
            linked.parent.mkdir()
            linked.symlink_to(path)
            with self.assertRaisesRegex(ReviewError, "missing or unsafe"):
                validate_mutation_outcomes(linked, "0/4")

    def test_mutation_outcomes_reject_rooted_hazards_and_races(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = canonical_json(broad_outcomes_document())
            outside = root / "outside.json"
            outside.write_bytes(document)

            final_link = root / "final-link" / "outcomes.json"
            final_link.parent.mkdir()
            final_link.symlink_to(outside)
            with self.assertRaisesRegex(ReviewError, "missing or unsafe"):
                validate_mutation_outcomes(final_link, "0/4")

            outside_directory = root / "outside-directory"
            outside_directory.mkdir()
            (outside_directory / "outcomes.json").write_bytes(document)
            intermediate = root / "intermediate-link"
            intermediate.symlink_to(outside_directory, target_is_directory=True)
            with self.assertRaisesRegex(ReviewError, "root is missing or unsafe"):
                validate_mutation_outcomes(intermediate / "outcomes.json", "0/4")

            hardlink = root / "hardlink" / "outcomes.json"
            hardlink.parent.mkdir()
            os.link(outside, hardlink)
            with self.assertRaisesRegex(ReviewError, "singly linked regular file"):
                validate_mutation_outcomes(hardlink, "0/4")

            if hasattr(os, "mkfifo"):
                fifo = root / "fifo" / "outcomes.json"
                fifo.parent.mkdir()
                os.mkfifo(fifo)
                with self.assertRaisesRegex(ReviewError, "singly linked regular file"):
                    validate_mutation_outcomes(fifo, "0/4")

            case_root = root / "case-alias"
            case_root.mkdir()
            stored = case_root / "Outcomes.json"
            stored.write_bytes(document)
            alias = case_root / "outcomes.json"
            try:
                aliases_same_file = alias.exists() and os.path.samefile(stored, alias)
            except OSError:
                aliases_same_file = False
            if aliases_same_file:
                with self.assertRaisesRegex(ReviewError, "canonical spelling"):
                    validate_mutation_outcomes(alias, "0/4")

            race_root = root / "content-race"
            race_root.mkdir()
            race_target = race_root / "outcomes.json"
            race_target.write_bytes(document)
            race_inode = race_target.stat().st_ino
            real_fstat = common_helpers.os.fstat
            file_checks = 0

            def mutate_same_size(descriptor: int) -> os.stat_result:
                nonlocal file_checks
                metadata = real_fstat(descriptor)
                if metadata.st_ino == race_inode and stat.S_ISREG(metadata.st_mode):
                    file_checks += 1
                    if file_checks == 2:
                        race_target.write_bytes(b" " * len(document))
                        metadata = real_fstat(descriptor)
                return metadata

            with (
                mock.patch.object(
                    common_helpers.os,
                    "fstat",
                    side_effect=mutate_same_size,
                ),
                self.assertRaisesRegex(ReviewError, "changed while"),
            ):
                validate_mutation_outcomes(race_target, "0/4")

            live_root = root / "live-root"
            live_root.mkdir()
            (live_root / "outcomes.json").write_bytes(document)
            replacement = root / "replacement-root"
            replacement.mkdir()
            (replacement / "outcomes.json").write_bytes(document)
            displaced = root / "displaced-root"
            live_inode = live_root.stat().st_ino
            root_checks = 0

            def replace_root(descriptor: int) -> os.stat_result:
                nonlocal root_checks
                metadata = real_fstat(descriptor)
                if metadata.st_ino == live_inode and stat.S_ISDIR(metadata.st_mode):
                    root_checks += 1
                    if root_checks == 3:
                        live_root.rename(displaced)
                        replacement.rename(live_root)
                return metadata

            with (
                mock.patch.object(
                    common_helpers.os,
                    "fstat",
                    side_effect=replace_root,
                ),
                self.assertRaisesRegex(ReviewError, "root was replaced|root changed"),
            ):
                validate_mutation_outcomes(live_root / "outcomes.json", "0/4")

    def test_focused_mutation_outcomes_bind_the_direct_test_and_exact_set(self) -> None:
        check = MUTATION_LIVENESS_CHECKS[0]
        document = focused_outcomes_document(check)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "outcomes.json"
            path.write_bytes(canonical_json(document))
            self.assertEqual(
                validate_focused_liveness_outcomes(path, check)["caught"], 5
            )

            wrong_command = copy.deepcopy(document)
            wrong_command["outcomes"][0]["phase_results"][0]["argv"].insert(
                2, "--quiet"
            )
            path.write_bytes(canonical_json(wrong_command))
            with self.assertRaisesRegex(ReviewError, "another Cargo command"):
                validate_focused_liveness_outcomes(path, check)

            variants = {}
            wrong_package = copy.deepcopy(document)
            wrong_package["outcomes"][1]["scenario"]["Mutant"]["package"] = (
                "another-package"
            )
            variants["package"] = wrong_package
            wrong_span = copy.deepcopy(document)
            wrong_span["outcomes"][1]["scenario"]["Mutant"]["span"]["start"][
                "column"
            ] += 1
            variants["span"] = wrong_span
            duplicate_operator = copy.deepcopy(document)
            duplicate_operator["outcomes"][3]["scenario"]["Mutant"] = copy.deepcopy(
                duplicate_operator["outcomes"][2]["scenario"]["Mutant"]
            )
            variants["duplicate operator"] = duplicate_operator
            for name, altered in variants.items():
                with self.subTest(name=name):
                    path.write_bytes(canonical_json(altered))
                    with self.assertRaisesRegex(ReviewError, "another mutant set"):
                        validate_focused_liveness_outcomes(path, check)

            wrong_status = copy.deepcopy(document)
            wrong_status["outcomes"][1]["phase_results"][1]["process_status"] = (
                "Success"
            )
            path.write_bytes(canonical_json(wrong_status))
            with self.assertRaisesRegex(ReviewError, "another process status"):
                validate_focused_liveness_outcomes(path, check)

            float_status = copy.deepcopy(document)
            float_status["outcomes"][1]["phase_results"][1]["process_status"] = {
                "Failure": 101.0
            }
            path.write_bytes(canonical_json(float_status))
            with self.assertRaisesRegex(ReviewError, "another process status"):
                validate_focused_liveness_outcomes(path, check)

            huge_duration = copy.deepcopy(document)
            huge_duration["outcomes"][0]["phase_results"][0]["duration"] = 10**120
            path.write_bytes(canonical_json(huge_duration))
            with self.assertRaisesRegex(ReviewError, "invalid duration"):
                validate_focused_liveness_outcomes(path, check)

            invalid_timestamp = copy.deepcopy(document)
            invalid_timestamp["start_time"] = ["not", "a", "timestamp"]
            path.write_bytes(canonical_json(invalid_timestamp))
            with self.assertRaisesRegex(ReviewError, "invalid start_time"):
                validate_focused_liveness_outcomes(path, check)

            padded_descriptor = copy.deepcopy(document)
            padded_descriptor["outcomes"][1]["scenario"]["Mutant"]["package"] = (
                " galadriel-ncp "
            )
            path.write_bytes(canonical_json(padded_descriptor))
            with self.assertRaisesRegex(ReviewError, "canonical text"):
                validate_focused_liveness_outcomes(path, check)

            functionless_descriptor = copy.deepcopy(document)
            functionless_descriptor["outcomes"][1]["scenario"]["Mutant"]["function"] = (
                None
            )
            path.write_bytes(canonical_json(functionless_descriptor))
            with self.assertRaisesRegex(ReviewError, "function must be an object"):
                validate_focused_liveness_outcomes(path, check)

    def test_focused_mutants_bind_their_current_source_spans(self) -> None:
        sources = {
            relative: (ROOT / relative).read_bytes()
            for relative in FOCUSED_MUTATION_SOURCE_FILES
        }
        validate_focused_mutant_sources(sources)

        shifted = dict(sources)
        acceptance = shifted[assurance.ACCEPTANCE_MUTANT_FILE]
        shifted[assurance.ACCEPTANCE_MUTANT_FILE] = acceptance.replace(
            b"\nfn bootstrap_seed", b"\n\nfn bootstrap_seed", 1
        )
        with self.assertRaisesRegex(ReviewError, "function span differs"):
            validate_focused_mutant_sources(shifted)

        changed_operator = dict(sources)
        changed_operator[assurance.ACCEPTANCE_MUTANT_FILE] = acceptance.replace(
            b"mix64(base_seed ^", b"mix64(base_seed |", 1
        )
        with self.assertRaisesRegex(ReviewError, "operator span differs"):
            validate_focused_mutant_sources(changed_operator)

    def test_focused_mutant_listing_binds_the_complete_frozen_set(self) -> None:
        check = MUTATION_LIVENESS_CHECKS[2]
        listing = []
        for mutant in check["required_mutants"]:
            identity = focused_mutant_document(mutant)
            transformation = mutant.name.removeprefix(
                f"{mutant.file}:{mutant.span[0]}:{mutant.span[1]}: "
            )
            identity["diff"] = f"--- {mutant.file}\n+++ {transformation}\n"
            listing.append(identity)
        document = canonical_json(listing)
        self.assertEqual(validate_focused_mutant_listing(document, check), 26)

        missing = canonical_json(listing[:-1])
        with self.assertRaisesRegex(ReviewError, "listing has another size"):
            validate_focused_mutant_listing(missing, check)

        changed_diff = copy.deepcopy(listing)
        changed_diff[0]["diff"] = "--- another.rs\n+++ another mutation\n"
        with self.assertRaisesRegex(ReviewError, "diff header differs"):
            validate_focused_mutant_listing(canonical_json(changed_diff), check)

    def test_focused_acceptance_mutation_binds_caught_and_unviable_sets(self) -> None:
        check = MUTATION_LIVENESS_CHECKS[2]
        document = focused_outcomes_document(check)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "outcomes.json"
            path.write_bytes(canonical_json(document))
            self.assertEqual(
                validate_focused_liveness_outcomes(path, check),
                {
                    "total_mutants": 26,
                    "missed": 0,
                    "caught": 23,
                    "timeout": 0,
                    "unviable": 3,
                    "success": 0,
                },
            )

            unviable_index = next(
                index
                for index, outcome in enumerate(document["outcomes"])
                if outcome["summary"] == "Unviable"
            )
            wrong_classification = copy.deepcopy(document)
            wrong_classification["outcomes"][unviable_index]["summary"] = "CaughtMutant"
            wrong_classification["unviable"] -= 1
            wrong_classification["caught"] += 1
            path.write_bytes(canonical_json(wrong_classification))
            with self.assertRaisesRegex(ReviewError, "another outcome summary"):
                validate_focused_liveness_outcomes(path, check)

            added_test_phase = copy.deepcopy(document)
            added_test_phase["outcomes"][unviable_index]["phase_results"].append(
                copy.deepcopy(document["outcomes"][1]["phase_results"][1])
            )
            path.write_bytes(canonical_json(added_test_phase))
            with self.assertRaisesRegex(ReviewError, "exactly Build phases"):
                validate_focused_liveness_outcomes(path, check)

            caught_index = next(
                index
                for index, outcome in enumerate(document["outcomes"])
                if outcome["summary"] == "CaughtMutant"
            )
            removed_test_phase = copy.deepcopy(document)
            removed_test_phase["outcomes"][caught_index]["phase_results"].pop()
            path.write_bytes(canonical_json(removed_test_phase))
            with self.assertRaisesRegex(ReviewError, "exactly Build and Test phases"):
                validate_focused_liveness_outcomes(path, check)

            category_swap = copy.deepcopy(document)
            (
                category_swap["outcomes"][caught_index]["scenario"],
                category_swap["outcomes"][unviable_index]["scenario"],
            ) = (
                category_swap["outcomes"][unviable_index]["scenario"],
                category_swap["outcomes"][caught_index]["scenario"],
            )
            path.write_bytes(canonical_json(category_swap))
            with self.assertRaises(ReviewError):
                validate_focused_liveness_outcomes(path, check)

            empty_replacement = copy.deepcopy(document)
            empty_replacement["outcomes"][caught_index]["scenario"]["Mutant"][
                "replacement"
            ] = ""
            path.write_bytes(canonical_json(empty_replacement))
            with self.assertRaisesRegex(ReviewError, "another mutant set"):
                validate_focused_liveness_outcomes(path, check)

    def test_focused_receipt_binds_outer_invocation_and_cargo_executable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commit = "1" * 40
            tree = "2" * 40
            for check in MUTATION_LIVENESS_CHECKS:
                outcomes = root / str(check["output"]) / "mutants.out" / "outcomes.json"
                outcomes.parent.mkdir(parents=True)
                outcomes.write_bytes(canonical_json(focused_outcomes_document(check)))
            receipt = root / FOCUSED_MUTATION_RECEIPT
            valid = focused_receipt_document(root, commit=commit, tree=tree)
            receipt.write_bytes(canonical_json(valid))
            _document, artifacts = validate_focused_mutation_receipt(
                receipt,
                root=root,
                commit=commit,
                tree=tree,
            )
            self.assertEqual(
                tuple(artifacts),
                (
                    "delivery-boundary-state",
                    "delivery-boundary-guards",
                    "acceptance-evidence-estimation",
                ),
            )

            wrong_command = copy.deepcopy(valid)
            wrong_command["checks"][0]["command_argv"][
                wrong_command["checks"][0]["command_argv"].index("120")
            ] = "121"
            receipt.write_bytes(canonical_json(wrong_command))
            with self.assertRaisesRegex(ReviewError, "receipt check .* drifted"):
                validate_focused_mutation_receipt(
                    receipt, root=root, commit=commit, tree=tree
                )

            wrong_cargo = copy.deepcopy(valid)
            wrong_cargo["toolchain"]["cargo_executable"] = "/tmp/another/cargo"
            receipt.write_bytes(canonical_json(wrong_cargo))
            with self.assertRaisesRegex(ReviewError, "another Cargo command"):
                validate_focused_mutation_receipt(
                    receipt, root=root, commit=commit, tree=tree
                )

            wrong_environment = copy.deepcopy(valid)
            wrong_environment["environment_contract"]["base_keys"].append("RUSTFLAGS")
            receipt.write_bytes(canonical_json(wrong_environment))
            with self.assertRaisesRegex(ReviewError, "another environment contract"):
                validate_focused_mutation_receipt(
                    receipt, root=root, commit=commit, tree=tree
                )

            boolean_count = copy.deepcopy(valid)
            boolean_count["checks"][0]["counts"]["missed"] = False
            receipt.write_bytes(canonical_json(boolean_count))
            with self.assertRaisesRegex(ReviewError, "noncanonical counts"):
                validate_focused_mutation_receipt(
                    receipt, root=root, commit=commit, tree=tree
                )

            float_size = copy.deepcopy(valid)
            float_size["checks"][0]["outcomes"]["size_bytes"] = float(
                float_size["checks"][0]["outcomes"]["size_bytes"]
            )
            receipt.write_bytes(canonical_json(float_size))
            with self.assertRaisesRegex(ReviewError, "invalid byte count"):
                validate_focused_mutation_receipt(
                    receipt, root=root, commit=commit, tree=tree
                )

    def test_mutation_commands_disable_ambient_configuration(self) -> None:
        commands = [
            mutation_command("0/4"),
            *(
                focused_liveness_mutation_command(check)
                for check in MUTATION_LIVENESS_CHECKS
            ),
        ]
        for command in commands:
            self.assertEqual(command[:3], ["cargo", "mutants", "--no-config"])
            self.assertIn("--no-shuffle", command)
            self.assertIn("--cargo-arg=--locked", command)
            self.assertEqual(command.count("--jobs"), 1)
            self.assertEqual(
                command[command.index("--jobs") : command.index("--jobs") + 2],
                ["--jobs", "1"],
            )
            self.assertEqual(
                command[command.index("--copy-vcs") : command.index("--copy-vcs") + 2],
                ["--copy-vcs", "true"],
            )
        acceptance = focused_liveness_mutation_command(MUTATION_LIVENESS_CHECKS[2])
        self.assertEqual(acceptance[-3:], ["--", "--bin", "galadriel-evidence"])
        for check in MUTATION_LIVENESS_CHECKS:
            listing = focused_liveness_mutation_list_command(check)
            self.assertEqual(listing[:3], ["cargo", "mutants", "--no-config"])
            self.assertEqual(listing.count("--list"), 1)
            self.assertEqual(listing.count("--json"), 1)
            self.assertEqual(listing.count("--no-shuffle"), 1)
            self.assertEqual(listing.count("--cargo-arg=--locked"), 1)
            self.assertNotIn("--baseline", listing)
            self.assertNotIn("--output", listing)

    def test_mutation_subject_diagnostic_omits_untrusted_field_text(self) -> None:
        hostile_key = "attacker-controlled-secret-field-name"
        with tempfile.TemporaryDirectory() as directory:
            subject = Path(directory) / "SUBJECT.txt"
            subject.write_text(
                f"{hostile_key}=first\n{hostile_key}=second\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ReviewError, "duplicate or empty field"
            ) as caught:
                parse_subject(subject)
        self.assertNotIn(hostile_key, str(caught.exception))
        self.assertLess(len(str(caught.exception)), 128)

    def test_mutation_environment_binds_linux_candidate_tree_containment(
        self,
    ) -> None:
        self.assertEqual(
            MUTATION_ENVIRONMENT_CONTRACT["schema"],
            "galadriel.mutation-environment.v2",
        )
        self.assertEqual(
            MUTATION_ENVIRONMENT_CONTRACT["process_containment"],
            {
                "mode": "LINUX_CANDIDATE_TREE",
                "launch_gate": "STOP_BEFORE_EXEC",
                "platform": "LINUX_PROCFS_PIDFD_CHILD_SUBREAPER",
                "subreaper_ownership": "SERIALIZED_PROCESS_LOCAL",
                "root_reap": "AFTER_CANDIDATE_TREE_EXTINCTION",
                "unsupported_platform": "FAIL_BEFORE_SPAWN",
                "uninterruptible_process": "FAIL_CLOSED",
                "isolation_scope": "NOT_CGROUP_CONTAINER_OR_DEPLOYMENT_ISOLATION",
            },
        )
        self.assertIs(
            FOCUSED_MUTATION_ENVIRONMENT_CONTRACT,
            MUTATION_ENVIRONMENT_CONTRACT,
        )

    def test_broad_receipt_rejects_execution_contract_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "mutants.out" / "outcomes.json"
            output.parent.mkdir()
            output.write_bytes(canonical_json(broad_outcomes_document()))
            diff = b"frozen diff\n"
            commit = "1" * 40
            tree = "2" * 40
            valid = broad_receipt_document(
                root,
                commit=commit,
                tree=tree,
                baseline=MUTATION_BASELINE_COMMIT,
                shard="0/4",
                diff=diff,
            )
            receipt = root / BROAD_MUTATION_RECEIPT
            receipt.write_bytes(canonical_json(valid))
            validate_broad_mutation_receipt(
                receipt,
                root=root,
                commit=commit,
                tree=tree,
                shard="0/4",
                diff=diff,
            )

            variants: list[tuple[str, dict[str, object], str]] = []
            wrong_command = copy.deepcopy(valid)
            wrong_command["command_argv"].append("--list")
            variants.append(("command", wrong_command, "another command"))
            wrong_environment = copy.deepcopy(valid)
            wrong_environment["environment_contract"]["base_keys"].append("RUSTFLAGS")
            variants.append(
                ("environment", wrong_environment, "another environment contract")
            )
            wrong_diff = copy.deepcopy(valid)
            wrong_diff["git_diff"]["sha256"] = "0" * 64
            variants.append(("diff", wrong_diff, "other diff bytes"))
            wrong_outcome = copy.deepcopy(valid)
            wrong_outcome["outcomes"]["sha256"] = "0" * 64
            variants.append(("outcome", wrong_outcome, "outcome digest mismatch"))
            aliased_outcome = copy.deepcopy(valid)
            aliased_outcome["outcomes"]["path"] = "./mutants.out/outcomes.json"
            variants.append(("outcome alias", aliased_outcome, "another outcome path"))
            wrong_exit = copy.deepcopy(valid)
            wrong_exit["exit_code"] = 1
            variants.append(("exit", wrong_exit, "zero exit status"))

            for label, document, message in variants:
                with self.subTest(label=label):
                    receipt.write_bytes(canonical_json(document))
                    with self.assertRaisesRegex(ReviewError, message):
                        validate_broad_mutation_receipt(
                            receipt,
                            root=root,
                            commit=commit,
                            tree=tree,
                            shard="0/4",
                            diff=diff,
                        )

    def test_mutation_stage_allowlist_requires_each_named_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
            (root / "git.diff").write_bytes(b"diff")
            expected = frozenset({"SUBJECT.txt", "git.diff", "git.diff.sha256"})
            with self.assertRaisesRegex(ReviewError, "lacks required stage artifacts"):
                assert_untracked_allowlist(
                    root,
                    exact=expected,
                    prefixes=(),
                    required=expected,
                )
            (root / "git.diff.sha256").write_text(
                f"{hashlib.sha256(b'diff').hexdigest()}  git.diff\n",
                encoding="ascii",
            )
            (root / "SUBJECT.txt").write_text("subject\n", encoding="utf-8")
            self.assertEqual(
                assert_untracked_allowlist(
                    root,
                    exact=expected,
                    prefixes=(),
                    required=expected,
                ),
                expected,
            )
            (root / "unexpected").write_bytes(b"x")
            with self.assertRaisesRegex(ReviewError, "unlisted stage artifact"):
                assert_untracked_allowlist(
                    root,
                    exact=expected,
                    prefixes=(),
                    required=expected,
                )

    def test_github_mutation_provenance_uses_the_explicit_candidate(self) -> None:
        candidate = "a" * 40
        environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_RUN_ID": "123456789",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_JOB": "mutation-diff",
            "GITHUB_WORKFLOW": "Deep quality",
            "GITHUB_REPOSITORY": "sepahead/galadriel",
            "GITHUB_REF": "refs/pull/42/merge",
            "GITHUB_SHA": "b" * 40,
            "MUTATION_CANDIDATE_SHA": candidate,
        }
        record = github_run_provenance(environment, candidate)
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record["sha"], candidate)
        missing_candidate = dict(environment)
        del missing_candidate["MUTATION_CANDIDATE_SHA"]
        with self.assertRaisesRegex(ReviewError, "MUTATION_CANDIDATE_SHA"):
            github_run_provenance(missing_candidate, candidate)
        environment["MUTATION_CANDIDATE_SHA"] = "c" * 40
        with self.assertRaisesRegex(ReviewError, "differs from checked HEAD"):
            github_run_provenance(environment, candidate)

    def test_broad_mutation_runner_uses_the_exact_isolated_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.name", "Sepehr Mahmoudian"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "sepmhn@gmail.com"],
                cwd=root,
                check=True,
            )
            (root / "README.md").write_text("fixture\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-q", "--no-gpg-sign", "-m", "Create fixture"],
                cwd=root,
                check=True,
            )
            baseline = subprocess.check_output(
                ["git", "rev-parse", "HEAD^{commit}"], cwd=root, text=True
            ).strip()
            (root / "README.md").write_text("fixture changed\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-q", "--no-gpg-sign", "-m", "Change fixture"],
                cwd=root,
                check=True,
            )
            candidate = subprocess.check_output(
                ["git", "rev-parse", "HEAD^{commit}"], cwd=root, text=True
            ).strip()
            candidate_tree = subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True
            ).strip()
            diff = subprocess.check_output(
                ["git", *MUTATION_DIFF_OPTIONS, f"{baseline}..{candidate}", "--"],
                cwd=root,
            )
            (root / "git.diff").write_bytes(diff)
            diff_digest = hashlib.sha256(diff).hexdigest()
            (root / "git.diff.sha256").write_text(
                f"{diff_digest}  git.diff\n",
                encoding="ascii",
            )
            (root / "SUBJECT.txt").write_text(
                "\n".join(
                    (
                        f"candidate_commit={candidate}",
                        f"candidate_tree={candidate_tree}",
                        f"baseline_commit={baseline}",
                        f"diff_sha256={diff_digest}",
                        "shard=0/4",
                        "",
                    )
                ),
                encoding="utf-8",
            )

            outcomes = broad_outcomes_document()
            observed_environments: list[dict[str, str]] = []

            def run_process(argv: list[str], **kwargs: object) -> BoundedHostResult:
                environment = kwargs.get("environment")
                assert isinstance(environment, dict)
                observed_environments.append(environment)
                if argv == ["cargo", "fetch", "--locked"]:
                    return BoundedHostResult(0, b"", b"")
                self.assertEqual(argv, broad_mutation_command("0/4"))
                output = root / "mutants.out"
                output.mkdir()
                (output / "outcomes.json").write_bytes(canonical_json(outcomes))
                return BoundedHostResult(0, b"", b"")

            identities = {
                "Cargo": CARGO_IDENTITY,
                "cargo-mutants": CARGO_MUTANTS_IDENTITY,
                "Cargo executable": "/fixture/toolchain/bin/cargo",
                "rustc": RUSTC_IDENTITY,
            }
            tool_root = Path(self.enterContext(tempfile.TemporaryDirectory()))
            tools = qualification_tool_fixture(tool_root)
            host_git = shutil.which("git")
            self.assertIsNotNone(host_git)
            assert host_git is not None
            (tools / "git").unlink()
            (tools / "git").symlink_to(host_git)
            cargo_mutants = tools / "cargo-mutants"
            cargo_mutants.write_bytes(b"#!/bin/sh\nexit 0\n")
            cargo_mutants.chmod(0o700)
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "GALADRIEL_UNRELATED_INPUT": "must-not-propagate",
                        "GITHUB_ACTIONS": "false",
                        "PATH": str(tools),
                    },
                    clear=False,
                ),
                mock.patch(
                    "run_broad_mutation.exact_output",
                    side_effect=lambda *args, **kwargs: identities[kwargs["context"]],
                ),
                mock.patch(
                    "run_broad_mutation.run_bounded_host_command",
                    side_effect=run_process,
                ),
                mock.patch("run_broad_mutation.MUTATION_BASELINE_COMMIT", baseline),
                mock.patch("release_assurance.MUTATION_BASELINE_COMMIT", baseline),
            ):
                self.assertEqual(
                    run_broad_mutation_shard(root, "0/4")["caught"],
                    400,
                )

            self.assertEqual(len(observed_environments), 2)
            for environment in observed_environments:
                self.assertEqual(tuple(environment), QUALIFICATION_ENVIRONMENT_KEYS)
                self.assertNotIn("GALADRIEL_UNRELATED_INPUT", environment)
            receipt = root / BROAD_MUTATION_RECEIPT
            self.assertTrue(receipt.is_file())

        with self.assertRaisesRegex(ReviewError, "0/4 through 3/4"):
            run_broad_mutation_shard(Path("."), "4/4")

    def test_ci_focused_mutation_validator_checks_all_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commit = "1" * 40
            tree = "2" * 40
            for check in MUTATION_LIVENESS_CHECKS:
                outcomes = root / str(check["output"]) / "mutants.out" / "outcomes.json"
                outcomes.parent.mkdir(parents=True)
                outcomes.write_bytes(canonical_json(focused_outcomes_document(check)))
            (root / FOCUSED_MUTATION_RECEIPT).write_bytes(
                canonical_json(focused_receipt_document(root, commit=commit, tree=tree))
            )
            command = [
                sys.executable,
                *qualifier.QUALIFICATION_PYTHON_FLAGS,
                str(TOOLS / "check_focused_mutation.py"),
                "--root",
                str(root),
                "--candidate-commit",
                commit,
                "--candidate-tree",
                tree,
            ]
            valid = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(valid.returncode, 0, valid.stderr)

            first = MUTATION_LIVENESS_CHECKS[0]
            altered = focused_outcomes_document(first)
            altered["outcomes"][1]["phase_results"][1]["process_status"] = "Success"
            target = root / str(first["output"]) / "mutants.out" / "outcomes.json"
            target.write_bytes(canonical_json(altered))
            invalid = subprocess.run(
                command, capture_output=True, text=True, check=False
            )
            self.assertEqual(invalid.returncode, 2)
            self.assertIn("focused mutation validation failed", invalid.stderr)

    def test_focused_runner_rejects_a_dangling_output_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / FOCUSED_MUTATION_RECEIPT
            output.symlink_to(root / "missing-target")
            self.assertFalse(output.exists())
            self.assertTrue(output.is_symlink())
            with self.assertRaisesRegex(ReviewError, "refusing to replace"):
                assert_new_output_path(output, "focused mutation receipt")

    def test_finalizer_publication_is_atomic_and_never_replaces(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging = root / ".closure.staging"
            staging.mkdir()
            (staging / "complete.json").write_text("complete\n", encoding="utf-8")
            output = root / "closure"
            publish_staged_output(staging, output)
            self.assertFalse(staging.exists())
            self.assertEqual(
                (output / "complete.json").read_text(encoding="utf-8"),
                "complete\n",
            )

            replacement = root / ".replacement.staging"
            replacement.mkdir()
            with self.assertRaisesRegex(ReviewError, "refusing to replace"):
                atomic_rename_no_replace(replacement, output)
            self.assertTrue(replacement.is_dir())

            empty_output = root / "empty-output"
            empty_output.mkdir()
            empty_replacement = root / ".empty-replacement.staging"
            empty_replacement.mkdir()
            with self.assertRaisesRegex(ReviewError, "refusing to replace"):
                atomic_rename_no_replace(empty_replacement, empty_output)
            self.assertTrue(empty_output.is_dir())
            self.assertTrue(empty_replacement.is_dir())

            dangling = root / "dangling-output"
            dangling.symlink_to(root / "missing-target")
            another = root / ".another.staging"
            another.mkdir()
            with self.assertRaisesRegex(ReviewError, "refusing to replace"):
                atomic_rename_no_replace(another, dangling)
            self.assertTrue(dangling.is_symlink())
            self.assertTrue(another.is_dir())

            other_parent = root / "other-parent"
            other_parent.mkdir()
            with self.assertRaisesRegex(ReviewError, "must share one parent"):
                publish_staged_output(another, other_parent / "closure")

            preflush = root / ".preflush.staging"
            preflush.mkdir()
            preflush_output = root / "preflush-output"
            with (
                mock.patch(
                    "finalize_release._walk_staged_tree",
                    side_effect=OSError("injected pre-publication failure"),
                ),
                self.assertRaisesRegex(OSError, "injected pre-publication"),
            ):
                publish_staged_output(preflush, preflush_output)
            self.assertTrue(preflush.is_dir())
            self.assertFalse(os.path.lexists(preflush_output))

            unavailable = root / ".unavailable.staging"
            unavailable.mkdir()
            unavailable_output = root / "unavailable-output"
            with (
                mock.patch("finalize_release.os.O_NOFOLLOW", None),
                self.assertRaisesRegex(ReviewError, "durability operations"),
            ):
                publish_staged_output(unavailable, unavailable_output)
            self.assertTrue(unavailable.is_dir())
            self.assertFalse(os.path.lexists(unavailable_output))

            nonblocking = root / ".nonblocking.staging"
            nonblocking.mkdir()
            nonblocking_output = root / "nonblocking-output"
            with (
                mock.patch("finalize_release.os.O_NONBLOCK", None),
                self.assertRaisesRegex(ReviewError, "durability operations"),
            ):
                publish_staged_output(nonblocking, nonblocking_output)
            self.assertTrue(nonblocking.is_dir())
            self.assertFalse(os.path.lexists(nonblocking_output))

            special = root / ".special.staging"
            special.mkdir()
            os.mkfifo(special / "unexpected.fifo")
            special_output = root / "special-output"
            with self.assertRaisesRegex(ReviewError, "special file"):
                publish_staged_output(special, special_output)
            self.assertTrue(special.is_dir())
            self.assertFalse(os.path.lexists(special_output))

            linked_staging = root / ".linked.staging"
            linked_staging.mkdir()
            (linked_staging / "unexpected-link").symlink_to(root / "outside")
            linked_output = root / "linked-output"
            with self.assertRaisesRegex(
                ReviewError, "staged closure contains a symlink"
            ):
                publish_staged_output(linked_staging, linked_output)
            self.assertTrue(linked_staging.is_dir())
            self.assertFalse(os.path.lexists(linked_output))

    def test_finalizer_publication_guard_runs_after_flush_and_before_rename(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging = root / ".closure.staging"
            staging.mkdir()
            (staging / "artifact").write_bytes(b"complete\n")
            output = root / "closure"
            events: list[str] = []
            finalize_module = sys.modules["finalize_release"]
            real_walk = finalize_module._walk_staged_tree
            real_rename = finalize_module._atomic_rename_no_replace_at

            def record_walk(descriptor: int, *, synchronize: bool) -> dict[str, object]:
                if synchronize:
                    events.append("fsync")
                return real_walk(descriptor, synchronize=synchronize)

            def guard() -> None:
                events.append("guard")

            def record_rename(*arguments: object, **keywords: object) -> None:
                events.append("rename")
                real_rename(*arguments, **keywords)

            with (
                mock.patch(
                    "finalize_release._walk_staged_tree",
                    side_effect=record_walk,
                ),
                mock.patch(
                    "finalize_release._atomic_rename_no_replace_at",
                    side_effect=record_rename,
                ),
            ):
                publish_staged_output(
                    staging,
                    output,
                    pre_publish_guard=guard,
                )
            self.assertEqual(events, ["fsync", "guard", "rename"])
            self.assertTrue(output.is_dir())

            blocked_staging = root / ".blocked.staging"
            blocked_staging.mkdir()
            blocked_output = root / "blocked"
            with self.assertRaisesRegex(ReviewError, "candidate changed"):
                publish_staged_output(
                    blocked_staging,
                    blocked_output,
                    pre_publish_guard=lambda: (_ for _ in ()).throw(
                        ReviewError("candidate changed")
                    ),
                )
            self.assertTrue(blocked_staging.is_dir())
            self.assertFalse(os.path.lexists(blocked_output))

    def test_fsync_tree_closes_parent_chain_after_identity_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging = root / ".closure.staging"
            staging.mkdir()
            (staging / "artifact").write_bytes(b"complete\n")
            finalize_module = sys.modules["finalize_release"]
            real_open_chain = finalize_module._open_directory_chain
            real_identity = finalize_module.rooted_path_identity
            opened_descriptors: list[int] = []

            def record_chain(*arguments: object, **keywords: object) -> object:
                chain = real_open_chain(*arguments, **keywords)
                opened_descriptors.extend(entry[0] for entry in chain)
                return chain

            def fail_after_chain(metadata: os.stat_result) -> object:
                if opened_descriptors:
                    raise OSError(errno.EIO, "injected identity failure")
                return real_identity(metadata)

            with (
                mock.patch(
                    "finalize_release._open_directory_chain",
                    side_effect=record_chain,
                ),
                mock.patch(
                    "finalize_release.rooted_path_identity",
                    side_effect=fail_after_chain,
                ),
                self.assertRaisesRegex(OSError, "injected identity failure"),
            ):
                finalize_module.fsync_tree(staging)

            self.assertTrue(opened_descriptors)
            for descriptor in opened_descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_publication_rejects_tree_hazards_and_guard_replacement(self) -> None:
        def reject_tree(
            name: str,
            install: Callable[[Path], None],
            message: str,
        ) -> None:
            with self.subTest(hazard=name):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    staging = root / ".closure.staging"
                    staging.mkdir()
                    install(staging)
                    output = root / "closure"
                    with self.assertRaisesRegex(ReviewError, message):
                        publish_staged_output(staging, output)
                    self.assertTrue(staging.is_dir())
                    self.assertFalse(os.path.lexists(output))

        reject_tree(
            "intermediate link",
            lambda staging: (staging / "linked").symlink_to(
                staging.parent,
                target_is_directory=True,
            ),
            "symlink",
        )

        def install_hardlinks(staging: Path) -> None:
            first = staging / "first"
            first.write_bytes(b"same inode\n")
            os.link(first, staging / "second")

        reject_tree("hard links", install_hardlinks, "multiply linked")
        reject_tree(
            "unsafe name",
            lambda staging: (staging / "unsafe\nname").write_bytes(b"unsafe\n"),
            "control character",
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging = root / ".closure.staging"
            staging.mkdir()
            artifact = staging / "artifact"
            artifact.write_bytes(b"before\n")
            output = root / "closure"

            def mutate_content() -> None:
                artifact.write_bytes(b"after!\n")

            with self.assertRaisesRegex(
                ReviewError, "changed during publication guard"
            ):
                publish_staged_output(
                    staging,
                    output,
                    pre_publish_guard=mutate_content,
                )
            self.assertTrue(staging.is_dir())
            self.assertFalse(os.path.lexists(output))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging = root / ".closure.staging"
            staging.mkdir()
            (staging / "artifact").write_bytes(b"complete\n")
            displaced = root / ".displaced.staging"
            output = root / "closure"

            def replace_staging() -> None:
                staging.rename(displaced)
                staging.mkdir()
                (staging / "artifact").write_bytes(b"complete\n")

            with self.assertRaisesRegex(ReviewError, "staging.*changed|replaced"):
                publish_staged_output(
                    staging,
                    output,
                    pre_publish_guard=replace_staging,
                )
            self.assertTrue(staging.is_dir())
            self.assertTrue(displaced.is_dir())
            self.assertFalse(os.path.lexists(output))

    def test_publication_rejects_parent_chain_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            parent = base / "publication-parent"
            parent.mkdir()
            staging = parent / ".closure.staging"
            staging.mkdir()
            (staging / "artifact").write_bytes(b"complete\n")
            displaced_parent = base / "displaced-parent"
            output = parent / "closure"

            def replace_parent() -> None:
                parent.rename(displaced_parent)
                parent.mkdir()

            with self.assertRaisesRegex(
                ReviewError,
                "parent changed|parent.*replaced|path was replaced",
            ):
                publish_staged_output(
                    staging,
                    output,
                    pre_publish_guard=replace_parent,
                )
            self.assertTrue((displaced_parent / staging.name).is_dir())
            self.assertFalse(os.path.lexists(output))
            self.assertFalse(os.path.lexists(displaced_parent / output.name))

    def test_publication_durability_opens_files_and_directories_nonblocking(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging = root / ".closure.staging"
            nested = staging / "nested"
            nested.mkdir(parents=True)
            (nested / "artifact.json").write_text("{}\n", encoding="utf-8")
            output = root / "closure"
            finalize_module = sys.modules["finalize_release"]
            real_flags = finalize_module._durability_descriptor_flags
            observed_flags: list[tuple[bool, int]] = []

            def record_flags(*, directory: bool) -> int:
                flags = real_flags(directory=directory)
                observed_flags.append((directory, flags))
                return flags

            with mock.patch(
                "finalize_release._durability_descriptor_flags",
                side_effect=record_flags,
            ):
                publish_staged_output(staging, output)
            self.assertTrue(output.is_dir())
            self.assertGreaterEqual(len(observed_flags), 4)
            self.assertTrue(
                all(flags & os.O_NONBLOCK for _directory, flags in observed_flags)
            )
            self.assertTrue(
                all(flags & os.O_NOFOLLOW for _directory, flags in observed_flags)
            )
            directory_flags = [
                flags for directory, flags in observed_flags if directory
            ]
            self.assertGreaterEqual(len(directory_flags), 3)
            self.assertTrue(all(flags & os.O_DIRECTORY for flags in directory_flags))
            self.assertTrue(
                all(
                    not flags & os.O_DIRECTORY
                    for directory, flags in observed_flags
                    if not directory
                )
            )

    def test_post_rename_destination_replacement_is_not_durability_status(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging = root / ".closure.staging"
            staging.mkdir()
            (staging / "complete.json").write_text(
                "complete\n",
                encoding="utf-8",
            )
            output = root / "closure"
            displaced = root / "displaced-complete-output"
            finalize_module = sys.modules["finalize_release"]
            real_rename = finalize_module._atomic_rename_no_replace_at

            def replace_after_rename(
                *arguments: object,
                **keywords: object,
            ) -> None:
                real_rename(*arguments, **keywords)
                output.rename(displaced)
                output.mkdir()
                (output / "replacement.json").write_text(
                    "replacement\n",
                    encoding="utf-8",
                )

            with (
                mock.patch(
                    "finalize_release._atomic_rename_no_replace_at",
                    side_effect=replace_after_rename,
                ),
                self.assertRaises(PublicationIntegrityError),
            ):
                publish_staged_output(staging, output)

            self.assertFalse(staging.exists())
            self.assertEqual(
                (displaced / "complete.json").read_text(encoding="utf-8"),
                "complete\n",
            )
            self.assertEqual(
                (output / "replacement.json").read_text(encoding="utf-8"),
                "replacement\n",
            )

    def test_post_rename_sync_failure_retains_only_complete_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging = root / ".closure.staging"
            staging.mkdir()
            (staging / "complete.json").write_text("complete\n", encoding="utf-8")
            output = root / "closure"
            finalize_module = sys.modules["finalize_release"]
            real_rename = finalize_module._atomic_rename_no_replace_at
            real_fsync = os.fsync
            renamed = False

            def record_rename(*arguments: object, **keywords: object) -> None:
                nonlocal renamed
                real_rename(*arguments, **keywords)
                renamed = True

            def fail_parent_sync(descriptor: int) -> None:
                if renamed:
                    raise OSError("injected parent sync failure")
                real_fsync(descriptor)

            with (
                mock.patch(
                    "finalize_release._atomic_rename_no_replace_at",
                    side_effect=record_rename,
                ),
                mock.patch(
                    "finalize_release.os.fsync",
                    side_effect=fail_parent_sync,
                ),
                self.assertRaises(PublicationDurabilityError),
            ):
                publish_staged_output(staging, output)
            self.assertFalse(staging.exists())
            self.assertEqual(
                (output / "complete.json").read_text(encoding="utf-8"),
                "complete\n",
            )

            close_staging = root / ".close-failure.staging"
            close_staging.mkdir()
            (close_staging / "complete.json").write_text("complete\n", encoding="utf-8")
            close_output = root / "close-failure-output"
            real_close = os.close
            real_open_bound = finalize_module._open_bound_directory
            renamed = False
            close_failed = False
            staging_descriptor: int | None = None

            def record_close_rename(*arguments: object, **keywords: object) -> None:
                nonlocal renamed
                real_rename(*arguments, **keywords)
                renamed = True

            def record_staging_descriptor(
                *arguments: object,
                **keywords: object,
            ) -> tuple[int, object]:
                nonlocal staging_descriptor
                result = real_open_bound(*arguments, **keywords)
                if keywords.get("label") == "finalization staging":
                    staging_descriptor = result[0]
                return result

            def fail_postrename_close(descriptor: int) -> None:
                nonlocal close_failed
                real_close(descriptor)
                if renamed and descriptor == staging_descriptor and not close_failed:
                    close_failed = True
                    raise OSError("injected parent close failure")

            with (
                mock.patch(
                    "finalize_release._open_bound_directory",
                    side_effect=record_staging_descriptor,
                ),
                mock.patch(
                    "finalize_release._atomic_rename_no_replace_at",
                    side_effect=record_close_rename,
                ),
                mock.patch(
                    "finalize_release.os.close",
                    side_effect=fail_postrename_close,
                ),
                self.assertRaises(PublicationDurabilityError),
            ):
                publish_staged_output(close_staging, close_output)
            self.assertFalse(close_staging.exists())
            self.assertEqual(
                (close_output / "complete.json").read_text(encoding="utf-8"),
                "complete\n",
            )

    def test_postpublication_input_cleanup_failure_maps_to_status_three(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            temporary = tempfile.TemporaryDirectory(dir=root)
            key = Path(temporary.name) / "SIGNING_KEY"
            key.write_text("public-key-handle\n", encoding="utf-8")
            with (
                mock.patch.object(
                    temporary,
                    "cleanup",
                    side_effect=OSError("injected cleanup failure"),
                ),
                mock.patch("finalize_release.warn_cleanup_failure") as warning,
            ):
                self.assertEqual(postpublication_cleanup_status(temporary, key), 3)
            self.assertFalse(key.exists())
            warning.assert_called_once()
            self.assertIn(temporary.name, warning.call_args.args[0])
            temporary.cleanup()

    def test_publication_result_distinguishes_clean_and_cleanup_warning(self) -> None:
        result = {"candidate": "a" * 40, "output": "/complete/closure"}
        for status, expected in (
            (0, "COMMITTED"),
            (3, "COMMITTED_WITH_CLEANUP_WARNING"),
        ):
            with self.subTest(status=status):
                output = io.StringIO()
                with mock.patch("finalize_release.sys.stdout", output):
                    self.assertEqual(emit_publication_result(result, status), status)
                record = json.loads(output.getvalue())
                self.assertEqual(record["publication_status"], expected)
                self.assertEqual(record["output"], "/complete/closure")
        with self.assertRaisesRegex(ReviewError, "status must be 0 or 3"):
            emit_publication_result(result, 2)

    def test_prepublication_input_cleanup_failure_is_nonmasking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            temporary = tempfile.TemporaryDirectory(dir=root)
            key = Path(temporary.name) / "SIGNING_KEY"
            key.write_text("public-key-handle\n", encoding="utf-8")
            with (
                mock.patch.object(
                    temporary,
                    "cleanup",
                    side_effect=OSError("injected cleanup failure"),
                ),
                mock.patch("finalize_release.warn_cleanup_failure") as warning,
            ):
                self.assertFalse(cleanup_finalization_inputs(temporary, key))
            self.assertFalse(key.exists())
            warning.assert_called_once()
            temporary.cleanup()

    def test_closure_emission_success_path_has_exact_acyclic_artifact_graph(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / "release-key"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                check=True,
            )
            allowed = root / "ALLOWED_SIGNERS"
            derive_external_allowed_signers(key.with_suffix(".pub"), allowed)
            source = root / "source-inputs"
            source.mkdir()

            ledger = source / "FILE_REVIEW_LEDGER.completed.csv"
            ledger.write_text(
                "path,review_status\nREADME.md,REVIEWED\n", encoding="utf-8"
            )
            dispositions = {
                "dispositions": [
                    {
                        "task_id": f"T{index:03d}",
                        "status": "COMPLETE_WITH_EXCLUSIONS",
                    }
                    for index in range(116)
                ]
            }
            disposition_path = source / "reviewed-task-dispositions.json"
            disposition_path.write_bytes(canonical_json(dispositions))
            disposition_signature = sign_file(
                disposition_path, key, "galadriel-task-dispositions"
            )
            review_path = source / "FINAL-TWENTY-LENS-REVIEW.json"
            review_path.write_bytes(
                canonical_json(
                    {
                        "schema": "galadriel.final-twenty-lens-review.v1",
                        "candidate": {"commit": "a" * 40, "tree": "b" * 40},
                        "conclusion": "COMPLETE_WITH_EXCLUSIONS",
                    }
                )
            )
            review_signature = sign_file(review_path, key, "galadriel-final-review")
            decision_path = source / RELEASE_DECISION
            decision_path.write_bytes(
                canonical_json(
                    {
                        "schema": "galadriel.release-decision.v3",
                        "candidate": {"commit": "a" * 40, "tree": "b" * 40},
                        "decision": "NARROWED_GO",
                        "review_sha256": hashlib.sha256(
                            review_path.read_bytes()
                        ).hexdigest(),
                        "review_signature_sha256": hashlib.sha256(
                            review_signature.read_bytes()
                        ).hexdigest(),
                    }
                )
            )
            decision_signature = sign_file(
                decision_path, key, "galadriel-release-decision"
            )
            retained_inputs = {
                "inputs/FILE_REVIEW_LEDGER.completed.csv": ledger,
                "inputs/reviewed-task-dispositions.json": disposition_path,
                "inputs/reviewed-task-dispositions.json.sig": disposition_signature,
                "inputs/FINAL-TWENTY-LENS-REVIEW.json": review_path,
                "inputs/FINAL-TWENTY-LENS-REVIEW.json.sig": review_signature,
                RELEASE_DECISION: decision_path,
                RELEASE_DECISION_SIGNATURE: decision_signature,
            }
            candidate = {"commit": "a" * 40, "tree": "b" * 40}
            summary = {
                "schema": "galadriel.exact-candidate-closure.v1",
                "release": "0.9.0",
                "author": "Sepehr Mahmoudian",
                "candidate": candidate,
                "file_review": {"tracked_files": 3, "reviewed_files": 3},
                "release_decision": {
                    "decision": "NARROWED_GO",
                    "sha256": hashlib.sha256(decision_path.read_bytes()).hexdigest(),
                    "signature_sha256": hashlib.sha256(
                        decision_signature.read_bytes()
                    ).hexdigest(),
                },
            }
            output = root / "closure"
            schema = json.loads((ROOT / LOCAL_CONVERGENCE_SCHEMA).read_text())
            emit_closure_bundle(
                final_output=output,
                retained_inputs=retained_inputs,
                closure_summary=summary,
                task_dispositions=dispositions,
                local_convergence_schema=schema,
                signing_key=key,
                allowed_signers=allowed,
                pre_publish_guard=lambda: None,
            )

            expected_files = set(retained_inputs) | {
                "closure-summary.json",
                LOCAL_CONVERGENCE,
                LOCAL_CONVERGENCE_SIGNATURE,
                CLOSURE_MANIFEST,
                CLOSURE_SIGNATURE,
                "SHA256SUMS",
            }
            observed_files = {
                path.relative_to(output).as_posix()
                for path in output.rglob("*")
                if path.is_file()
            }
            self.assertEqual(observed_files, expected_files)
            self.assertFalse(list(root.glob(".closure.staging-*")))

            verify_signature(
                output / "inputs/reviewed-task-dispositions.json",
                output / "inputs/reviewed-task-dispositions.json.sig",
                allowed,
                "galadriel-task-dispositions",
            )
            verify_signature(
                output / "inputs/FINAL-TWENTY-LENS-REVIEW.json",
                output / "inputs/FINAL-TWENTY-LENS-REVIEW.json.sig",
                allowed,
                "galadriel-final-review",
            )
            verify_signature(
                output / RELEASE_DECISION,
                output / RELEASE_DECISION_SIGNATURE,
                allowed,
                "galadriel-release-decision",
            )
            verify_signature(
                output / LOCAL_CONVERGENCE,
                output / LOCAL_CONVERGENCE_SIGNATURE,
                allowed,
                LOCAL_CONVERGENCE_NAMESPACE,
            )
            verify_signature(
                output / CLOSURE_MANIFEST,
                output / CLOSURE_SIGNATURE,
                allowed,
                "galadriel-closure-manifest",
            )
            convergence = json.loads((output / LOCAL_CONVERGENCE).read_text())
            validate_local_convergence(
                convergence,
                schema=schema,
                expected_commit=candidate["commit"],
                artifact_root=output,
            )
            self.assertEqual(
                {row["path"] for row in convergence["artifacts"]},
                set(CONVERGENCE_ARTIFACT_PATHS),
            )
            self.assertNotIn(LOCAL_CONVERGENCE, CONVERGENCE_ARTIFACT_PATHS)

            manifest_document = verify_artifact_manifest(
                output,
                output / CLOSURE_MANIFEST,
                expected_schema="galadriel.tiered-artifact-manifest.v1",
                forbidden_paths={
                    CLOSURE_MANIFEST,
                    CLOSURE_SIGNATURE,
                    "SHA256SUMS",
                },
            )
            manifest_paths = {row["path"] for row in manifest_document["artifacts"]}
            self.assertEqual(
                manifest_paths,
                expected_files - {CLOSURE_MANIFEST, CLOSURE_SIGNATURE, "SHA256SUMS"},
            )
            self.assertTrue(
                {
                    RELEASE_DECISION,
                    RELEASE_DECISION_SIGNATURE,
                    LOCAL_CONVERGENCE,
                    LOCAL_CONVERGENCE_SIGNATURE,
                }.issubset(manifest_paths)
            )
            verify_sha256sums(output)
            checksum_paths = {
                line.split("  ", 1)[1]
                for line in (output / "SHA256SUMS")
                .read_text(encoding="utf-8")
                .splitlines()
            }
            self.assertEqual(checksum_paths, expected_files - {"SHA256SUMS"})
            decision_text = (output / RELEASE_DECISION).read_text(encoding="utf-8")
            for future_artifact in (
                "reviewed-task-dispositions",
                LOCAL_CONVERGENCE,
                CLOSURE_MANIFEST,
                "SHA256SUMS",
            ):
                self.assertNotIn(future_artifact, decision_text)

    def test_supply_chain_reports_must_be_nonempty_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.enterContext(portable_test_process_patch())
            sandbox = (
                candidate_sandbox_profile(root, worktree=root)
                if sys.platform == "darwin"
                else None
            )
            valid = capture_report(
                ["python3", "-c", 'print(\'{"type":"summary"}\')'],
                worktree=root,
                environment=command_test_environment(root),
                output=root / "reports" / "valid.jsonl",
                json_lines=True,
                report_stream="stdout",
                sandbox_profile=sandbox,
            )
            self.assertGreater(valid["size_bytes"], 0)
            for name, program in (
                ("empty", "pass"),
                ("invalid", "print('not-json')"),
            ):
                with self.subTest(name=name):
                    with self.assertRaisesRegex(
                        ReviewError, "empty report|invalid JSON"
                    ):
                        capture_report(
                            ["python3", "-c", program],
                            worktree=root,
                            environment=command_test_environment(root),
                            output=root / "reports" / f"{name}.json",
                            json_lines=False,
                            report_stream="stdout",
                            sandbox_profile=sandbox,
                        )

    def test_supply_chain_reports_retain_the_declared_stream(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.enterContext(portable_test_process_patch())
            sandbox = (
                candidate_sandbox_profile(root, worktree=root)
                if sys.platform == "darwin"
                else None
            )
            cases = (
                (
                    "cargo-deny-stderr-jsonl",
                    ('import sys; sys.stderr.write(\'{"type":"summary"}\\n\')'),
                    True,
                    "stderr",
                    "stdout",
                    "",
                    b"",
                    b'{"type":"summary"}\n',
                ),
                (
                    "stdout-json",
                    (
                        "import sys; "
                        "sys.stdout.write('{\"vulnerabilities\":{}}\\n'); "
                        "sys.stderr.write('audit diagnostic\\n')"
                    ),
                    False,
                    "stdout",
                    "stderr",
                    "audit diagnostic",
                    b"audit diagnostic\n",
                    b'{"vulnerabilities":{}}\n',
                ),
            )
            for (
                name,
                program,
                json_lines,
                report_stream,
                diagnostics_stream,
                diagnostics_text,
                diagnostics_payload,
                expected_report,
            ) in cases:
                with self.subTest(name=name):
                    output = root / "reports" / f"{name}.json"
                    report = capture_report(
                        [sys.executable, "-c", program],
                        worktree=root,
                        environment=command_test_environment(root),
                        output=output,
                        json_lines=json_lines,
                        report_stream=report_stream,
                        sandbox_profile=sandbox,
                    )
                    self.assertEqual(
                        set(report),
                        {
                            "argv",
                            "path",
                            "sha256",
                            "size_bytes",
                            "report_stream",
                            "receipt",
                            "diagnostics",
                        },
                    )
                    self.assertEqual(report["report_stream"], report_stream)
                    self.assertEqual(report["receipt"], "report")
                    self.assertEqual(
                        report["diagnostics"],
                        {
                            "stream": diagnostics_stream,
                            "text": diagnostics_text,
                            "sha256": hashlib.sha256(diagnostics_payload).hexdigest(),
                            "size_bytes": len(diagnostics_payload),
                        },
                    )
                    self.assertEqual(output.read_bytes(), expected_report)

    def test_supply_chain_reports_reject_wrong_or_invalid_selected_stream(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.enterContext(portable_test_process_patch())
            sandbox = (
                candidate_sandbox_profile(root, worktree=root)
                if sys.platform == "darwin"
                else None
            )
            cases = (
                (
                    "wrong-stream",
                    'import sys; sys.stderr.write(\'{"type":"summary"}\\n\')',
                    "stdout",
                    "empty report on stdout",
                ),
                (
                    "deny-nonempty-stdout",
                    (
                        "import sys; "
                        "sys.stdout.write('unexpected diagnostic\\n'); "
                        'sys.stderr.write(\'{"type":"summary"}\\n\')'
                    ),
                    "stderr",
                    "unexpected nonempty stdout",
                ),
                (
                    "deny-whitespace-only-stdout",
                    (
                        "import sys; "
                        "sys.stdout.write(' \\n'); "
                        'sys.stderr.write(\'{"type":"summary"}\\n\')'
                    ),
                    "stderr",
                    "unexpected nonempty stdout",
                ),
                (
                    "invalid-selected-stream",
                    "print('not-json')",
                    "stdout",
                    "invalid JSON evidence on stdout",
                ),
                (
                    "selected-scalar",
                    "print('1')",
                    "stdout",
                    "JSON report must be an object",
                ),
                (
                    "selected-list",
                    "print('[]')",
                    "stdout",
                    "JSON report must be an object",
                ),
                (
                    "selected-invalid-utf8",
                    "import sys; sys.stdout.buffer.write(b'\\xff')",
                    "stdout",
                    "JSON input is not valid UTF-8",
                ),
                ("empty-selected-stream", "pass", "stdout", "empty report on stdout"),
            )
            for name, program, report_stream, error in cases:
                with self.subTest(name=name):
                    with self.assertRaisesRegex(ReviewError, error):
                        capture_report(
                            [sys.executable, "-c", program],
                            worktree=root,
                            environment=command_test_environment(root),
                            output=root / "reports" / f"{name}.json",
                            json_lines=False,
                            report_stream=report_stream,
                            sandbox_profile=sandbox,
                        )

            with self.assertRaisesRegex(ReviewError, "report_stream must be exactly"):
                capture_report(
                    [sys.executable, "-c", "pass"],
                    worktree=root,
                    environment=command_test_environment(root),
                    output=root / "reports" / "unknown.json",
                    json_lines=False,
                    report_stream="unknown",
                    sandbox_profile=sandbox,
                )

            with self.assertRaisesRegex(ReviewError, "report failed"):
                capture_report(
                    [
                        sys.executable,
                        "-c",
                        "import sys; print('{\"valid\":true}'); sys.exit(7)",
                    ],
                    worktree=root,
                    environment=command_test_environment(root),
                    output=root / "reports" / "nonzero.json",
                    json_lines=False,
                    report_stream="stdout",
                    sandbox_profile=sandbox,
                )

            containment_failure = qualifier.BoundedProcessResult(
                returncode=0,
                timed_out=False,
                stdout=b'{"valid":true}\n',
                stderr=b"",
                output_limit_exceeded=False,
                containment_error="test containment failure",
            )
            with (
                mock.patch(
                    "qualify_candidate.run_bounded_process",
                    return_value=containment_failure,
                ),
                self.assertRaisesRegex(ReviewError, "report failed"),
            ):
                capture_report(
                    [sys.executable, "-c", "print('{\"valid\":true}')"],
                    worktree=root,
                    environment=command_test_environment(root),
                    output=root / "reports" / "containment-failure.json",
                    json_lines=False,
                    report_stream="stdout",
                    sandbox_profile=sandbox,
                )

    def test_finalizer_binds_supply_chain_report_streams_and_diagnostics(self) -> None:
        reproducibility_root = Path("/qualification/reproducibility")
        metadata_path = reproducibility_root / "cargo-metadata.json"
        license_inventory_path = "reports/license-inventory.json"
        license_path = "reports/license-report.jsonl"
        vulnerability_path = "reports/vulnerability-report.json"
        manifest_artifacts = {
            license_inventory_path: {"sha256": "c" * 64, "size_bytes": 303},
            license_path: {"sha256": "a" * 64, "size_bytes": 101},
            vulnerability_path: {"sha256": "b" * 64, "size_bytes": 202},
        }
        empty_digest = hashlib.sha256(b"").hexdigest()
        warning_payload = b"audit warning\n"
        warning_digest = hashlib.sha256(warning_payload).hexdigest()
        auxiliary_receipts = {
            "license-inventory": {
                "stdout_sha256": "c" * 64,
                "stdout_size_bytes": 303,
                "stderr_sha256": empty_digest,
                "stderr_size_bytes": 0,
                "_diagnostics_text_sha256": empty_digest,
            },
            "license-report": {
                "stdout_sha256": empty_digest,
                "stdout_size_bytes": 0,
                "stderr_sha256": "a" * 64,
                "stderr_size_bytes": 101,
                "_diagnostics_text_sha256": empty_digest,
            },
            "vulnerability-report": {
                "stdout_sha256": "b" * 64,
                "stdout_size_bytes": 202,
                "stderr_sha256": warning_digest,
                "stderr_size_bytes": len(warning_payload),
                "_diagnostics_text_sha256": hashlib.sha256(
                    b"audit warning"
                ).hexdigest(),
            },
        }
        qualification = {
            "sandbox": {
                "bindings": {
                    "reproducibility_root": str(reproducibility_root),
                }
            },
            "license_inventory": {
                "argv": [
                    "cargo",
                    "deny",
                    "--offline",
                    "--all-features",
                    "--locked",
                    "list",
                    "--metadata-path",
                    str(metadata_path),
                    "--format",
                    "json",
                    "--layout",
                    "crate",
                ],
                "path": license_inventory_path,
                "sha256": "c" * 64,
                "size_bytes": 303,
                "report_stream": "stdout",
                "receipt": "license-inventory",
                "scope": "CARGO_DENY_HOST_FILTERED_GRAPH",
                "diagnostics": {
                    "stream": "stderr",
                    "text": "",
                    "sha256": empty_digest,
                    "size_bytes": 0,
                },
            },
            "license_report": {
                "argv": [
                    "cargo",
                    "deny",
                    "--offline",
                    "--format",
                    "json",
                    "--all-features",
                    "--locked",
                    "check",
                    "--metadata-path",
                    str(metadata_path),
                    "licenses",
                ],
                "path": license_path,
                "sha256": "a" * 64,
                "size_bytes": 101,
                "report_stream": "stderr",
                "receipt": "license-report",
                "diagnostics": {
                    "stream": "stdout",
                    "text": "",
                    "sha256": empty_digest,
                    "size_bytes": 0,
                },
            },
            "vulnerability_report": {
                "argv": [
                    "cargo",
                    "audit",
                    "--no-fetch",
                    "--stale",
                    "--no-yanked",
                    "--ignore",
                    "RUSTSEC-2026-0041",
                    "--format",
                    "json",
                ],
                "path": vulnerability_path,
                "sha256": "b" * 64,
                "size_bytes": 202,
                "report_stream": "stdout",
                "receipt": "vulnerability-report",
                "diagnostics": {
                    "stream": "stderr",
                    "text": "audit warning",
                    "sha256": warning_digest,
                    "size_bytes": len(warning_payload),
                },
            },
        }
        validate_supply_chain_report_records(
            qualification,
            manifest_artifacts,
            auxiliary_receipts,
        )

        variants: list[tuple[str, dict[str, object], str]] = []
        swapped = copy.deepcopy(qualification)
        swapped["license_report"]["report_stream"] = "stdout"
        variants.append(("swapped-report-stream", swapped, "license_report"))
        wrong_diagnostics = copy.deepcopy(qualification)
        wrong_diagnostics["vulnerability_report"]["diagnostics"]["stream"] = "stdout"
        variants.append(
            ("wrong-diagnostics-stream", wrong_diagnostics, "vulnerability_report")
        )
        nonempty_deny_stdout = copy.deepcopy(qualification)
        nonempty_deny_stdout["license_report"]["diagnostics"]["text"] = "unexpected"
        variants.append(
            ("nonempty-deny-stdout", nonempty_deny_stdout, "license_report")
        )
        missing_key = copy.deepcopy(qualification)
        del missing_key["license_report"]["report_stream"]
        variants.append(("missing-key", missing_key, "license_report"))
        extra_key = copy.deepcopy(qualification)
        extra_key["license_report"]["stderr"] = "legacy"
        variants.append(("extra-key", extra_key, "license_report"))
        wrong_digest = copy.deepcopy(qualification)
        wrong_digest["license_report"]["sha256"] = "c" * 64
        variants.append(("digest-tamper", wrong_digest, "license_report"))
        wrong_size = copy.deepcopy(qualification)
        wrong_size["vulnerability_report"]["size_bytes"] = 203
        variants.append(("size-tamper", wrong_size, "vulnerability_report"))

        for name, document, field in variants:
            with self.subTest(name=name):
                with self.assertRaisesRegex(ReviewError, f"qualification {field}"):
                    validate_supply_chain_report_records(
                        document,
                        manifest_artifacts,
                        auxiliary_receipts,
                    )

    def test_failed_acceptance_requires_exact_narrowed_disposition(self) -> None:
        acceptance = {
            "status": "FAIL",
            "failed_criterion_ids": ["GLD-090-ACC-001"],
        }
        base = {
            "schema": "galadriel.release-decision.v3",
            "release": "0.9.0",
            "author": "Sepehr Mahmoudian",
            "issued_at": "2026-07-18T00:00:00Z",
            "candidate": {"commit": "a" * 40, "tree": "b" * 40},
            "bindings": {
                "reconciliation_status": "LOCAL_PIN_PASS",
                "source_plan_sha256": "1" * 64,
                "claims_sha256": "2" * 64,
                "qualification_manifest_sha256": "3" * 64,
                "feature_graph_log_sha256": "4" * 64,
                "completed_file_review_ledger_sha256": "5" * 64,
                "final_twenty_lens_review_sha256": "6" * 64,
                "final_twenty_lens_review_signature_sha256": "7" * 64,
            },
            "decision": "NARROWED_GO",
            "publication_scope": "review-gated GitHub research source release",
            "doi": None,
            "zenodo": None,
            "removed_claim_ids": ["CLM-007"],
            "acceptance_failure_dispositions": {},
            "residual_risks": [
                "The exact candidate does not satisfy the frozen rate-bound criterion."
            ],
        }
        expected_candidate = base["candidate"]
        expected_bindings = base["bindings"]
        with self.assertRaisesRegex(ReviewError, "lack exact narrowed dispositions"):
            validate_decision_input(
                base,
                acceptance=acceptance,
                excluded_claim_ids={"CLM-007"},
                expected_candidate=expected_candidate,
                expected_bindings=expected_bindings,
            )
        base["acceptance_failure_dispositions"] = {
            "GLD-090-ACC-001": {
                "removed_claim_ids": ["CLM-007"],
                "residual_risk": (
                    "The clean-reference exposure cannot establish the frozen rate bound; "
                    "the associated rate claim remains removed."
                ),
            }
        }
        validate_decision_input(
            base,
            acceptance=acceptance,
            excluded_claim_ids={"CLM-007"},
            expected_candidate=expected_candidate,
            expected_bindings=expected_bindings,
        )
        wrong_candidate = copy.deepcopy(base)
        wrong_candidate["candidate"]["tree"] = "c" * 40
        with self.assertRaisesRegex(ReviewError, "wrong candidate"):
            validate_decision_input(
                wrong_candidate,
                acceptance=acceptance,
                excluded_claim_ids={"CLM-007"},
                expected_candidate=expected_candidate,
                expected_bindings=expected_bindings,
            )
        wrong_review_binding = copy.deepcopy(base)
        wrong_review_binding["bindings"]["final_twenty_lens_review_sha256"] = "8" * 64
        with self.assertRaisesRegex(ReviewError, "incorrect evidence bindings"):
            validate_decision_input(
                wrong_review_binding,
                acceptance=acceptance,
                excluded_claim_ids={"CLM-007"},
                expected_candidate=expected_candidate,
                expected_bindings=expected_bindings,
            )
        not_reconciled = copy.deepcopy(base)
        not_reconciled["bindings"]["reconciliation_status"] = "NOT_RUN"
        not_reconciled_bindings = copy.deepcopy(not_reconciled["bindings"])
        with self.assertRaisesRegex(ReviewError, "must be NO_GO"):
            validate_decision_input(
                not_reconciled,
                acceptance=acceptance,
                excluded_claim_ids={"CLM-007"},
                expected_candidate=expected_candidate,
                expected_bindings=not_reconciled_bindings,
            )
        base["decision"] = "GO"
        with self.assertRaisesRegex(ReviewError, "GO is prohibited"):
            validate_decision_input(
                base,
                acceptance=acceptance,
                excluded_claim_ids={"CLM-007"},
                expected_candidate=expected_candidate,
                expected_bindings=expected_bindings,
            )

    def test_shallow_or_unbound_qualification_is_rejected(self) -> None:
        source_date_epoch = 1_753_225_600
        base = {
            "schema": "galadriel.candidate-qualification.v3",
            "release": "0.9.0",
            "author": "Sepehr Mahmoudian",
            "doi": None,
            "zenodo": None,
            "status": "PASS",
            "command_status": "PASS",
            "release_gate": "PASS",
            "candidate": {
                "repository": "https://github.com/sepahead/galadriel",
                "branch": "main",
                "commit": "a" * 40,
                "tree": "b" * 40,
                "source_date_epoch": source_date_epoch,
            },
            "host": {},
            "tools": {},
            "tool_files": {},
            "fuzz_runners": {},
            "environment_contract": {},
            "repository_control": {},
            "sandbox": {},
            "advisory_database": {},
            "deep_campaigns_requested": False,
            "evidence_config": "evidence/galadriel-0.9-candidate.json",
            "commands": [],
            "auxiliary_commands": [],
            "acceptance": {},
            "candidate_evidence_validation": {},
            "evidence_config_binding": {},
            "source_archive": {},
            "cargo_metadata": {},
            "packages": [],
            "sboms": [],
            "license_inventory": {},
            "license_report": {},
            "vulnerability_report": {},
            "reproducibility": {},
            "mutation_evidence": {},
            "limitations": "This record has component and source scope.",
        }
        with self.assertRaisesRegex(ReviewError, "deep campaigns"):
            validate_qualification_record(
                base,
                commit="a" * 40,
                tree="b" * 40,
                expected_evidence_config_sha256="c" * 64,
                source_date_epoch=source_date_epoch,
            )
        base["deep_campaigns_requested"] = True
        with self.assertRaisesRegex(ReviewError, "preregistered config binding"):
            validate_qualification_record(
                base,
                commit="a" * 40,
                tree="b" * 40,
                expected_evidence_config_sha256="c" * 64,
                source_date_epoch=source_date_epoch,
            )

    def test_real_source_plan_schema_matches_tasks(self) -> None:
        plan = json.loads((ROOT / "release/0.9.0/task-closure-plan.json").read_text())
        tasks = json.loads((ROOT / "release/0.9.0/tasks.json").read_text())
        validate_candidate_plan_documents(plan, tasks)
        forward = copy.deepcopy(tasks)
        forward["tasks"][0]["dependencies"] = ["T001"]
        with self.assertRaisesRegex(ReviewError, "dependencies are invalid at T000"):
            validate_candidate_plan_documents(plan, forward)
        missing_digest = copy.deepcopy(plan)
        del missing_digest["source_task_ledger_sha256"]
        missing_source_digest = copy.deepcopy(tasks)
        del missing_source_digest["source"]["task_ledger_sha256"]
        with self.assertRaisesRegex(ReviewError, "source plan"):
            validate_candidate_plan_documents(missing_digest, missing_source_digest)
        missing_lenses = copy.deepcopy(plan)
        del missing_lenses["lens_catalog"]
        with self.assertRaisesRegex(ReviewError, "source plan"):
            validate_candidate_plan_documents(missing_lenses, tasks)
        string_rows = copy.deepcopy(plan)
        string_rows["tasks"] = [f"T{index:03d}" for index in range(116)]
        with self.assertRaisesRegex(ReviewError, "source plan"):
            validate_candidate_plan_documents(string_rows, tasks)
        string_tasks = copy.deepcopy(tasks)
        string_tasks["tasks"] = [f"T{index:03d}" for index in range(116)]
        with self.assertRaisesRegex(ReviewError, "task sequence"):
            validate_candidate_plan_documents(plan, string_tasks)

    def test_finalization_dag_requires_exact_t113_t114_t115_evidence(self) -> None:
        mechanism_paths = {
            "release/0.9.0/local-convergence-schema.json",
            "release/0.9.0/VERSION-ADAPTATION.md",
            "repo_work/finalize_release.py",
            "repo_work/local_convergence.py",
            "repo_work/tests/test_release_assurance.py",
        }
        qualification_logs = {
            "logs/01-release-tool-tests.log",
            "logs/04-local-convergence-schema.log",
            "logs/06-feature-graph-contract.log",
        }

        def reference(kind: str, path: str) -> dict[str, str]:
            return {"kind": kind, "path": path, "sha256": "a" * 64}

        mechanism_refs = [
            *[reference("candidate_blob", path) for path in sorted(mechanism_paths)],
            *[
                reference("qualification_artifact", path)
                for path in sorted(qualification_logs)
            ],
        ]
        dispositions = {
            "dispositions": [
                {"task_id": f"T{index:03d}", "evidence": [], "tests": []}
                for index in range(116)
            ]
        }
        dispositions["dispositions"][113]["evidence"] = mechanism_refs
        dispositions["dispositions"][114]["evidence"] = [
            reference("review_input", "inputs/FINAL-TWENTY-LENS-REVIEW.json"),
            reference("review_input", "inputs/FINAL-TWENTY-LENS-REVIEW.json.sig"),
        ]
        dispositions["dispositions"][115]["evidence"] = [
            reference("review_input", "RELEASE-DECISION.json"),
            reference("review_input", "RELEASE-DECISION.json.sig"),
        ]
        final_review = {"lenses": {"L01": {"evidence": mechanism_refs}}}
        validate_finalization_dag_evidence(
            dispositions,
            final_review,
            qualification_logs=qualification_logs,
        )

        malformed = copy.deepcopy(dispositions)
        malformed["dispositions"][113]["evidence"] = None
        malformed["dispositions"][113]["tests"] = None
        with self.assertRaisesRegex(ReviewError, "T113 lacks"):
            validate_finalization_dag_evidence(
                malformed,
                final_review,
                qualification_logs=qualification_logs,
            )

        for name, mutate, message in (
            (
                "prospective-t113",
                lambda value: value["dispositions"][113]["tests"].append(
                    reference("candidate_blob", "local-Convergence.json")
                ),
                "prospective convergence",
            ),
            (
                "missing-t114",
                lambda value: value["dispositions"][114]["evidence"].pop(),
                "T114 lacks",
            ),
            (
                "missing-t115",
                lambda value: value["dispositions"][115]["evidence"].pop(),
                "T115 lacks",
            ),
        ):
            with self.subTest(name=name):
                attacked = copy.deepcopy(dispositions)
                mutate(attacked)
                with self.assertRaisesRegex(ReviewError, message):
                    validate_finalization_dag_evidence(
                        attacked,
                        final_review,
                        qualification_logs=qualification_logs,
                    )

    def test_local_convergence_schema_and_exact_candidate_record(self) -> None:
        schema = json.loads((ROOT / LOCAL_CONVERGENCE_SCHEMA).read_text())
        validate_local_convergence_schema(schema)
        self.assertEqual(
            schema["$id"],
            "https://raw.githubusercontent.com/sepahead/galadriel/v0.9.0/"
            "release/0.9.0/local-convergence-schema.json",
        )
        self.assertEqual(schema["$id"], LOCAL_CONVERGENCE_SCHEMA_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact_paths = CONVERGENCE_ARTIFACT_PATHS
            for index, relative in enumerate(artifact_paths):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(f"artifact {index}\n", encoding="utf-8")
            dispositions = {
                "dispositions": [
                    {
                        "task_id": f"T{index:03d}",
                        "status": "COMPLETE_WITH_EXCLUSIONS",
                    }
                    for index in range(116)
                ]
            }
            commit = "a" * 40
            document = build_local_convergence(
                commit=commit,
                file_review={"tracked_files": 7, "reviewed_files": 7},
                task_dispositions=dispositions,
                artifacts=local_convergence_artifacts(root, artifact_paths),
            )
            validate_local_convergence(
                document,
                schema=schema,
                expected_commit=commit,
                artifact_root=root,
            )
            canonical_round_trip = json.loads(canonical_json(document))
            validate_local_convergence(
                canonical_round_trip,
                schema=schema,
                expected_commit=commit,
                artifact_root=root,
            )
            self.assertEqual(document["completed_tasks"][0], "T000")
            self.assertEqual(document["completed_tasks"][-1], "T115")
            self.assertEqual(
                document["cross_repo_requirements"], list(CROSS_REPO_REQUIREMENTS)
            )

            attacks = (
                (
                    "candidate",
                    lambda value: value.__setitem__("source_commit", "b" * 40),
                    "another candidate",
                ),
                (
                    "wave",
                    lambda value: value["waves"][0].__setitem__(
                        "disposition", "WAVE_REWORK"
                    ),
                    "wave 0",
                ),
                (
                    "cross-repository",
                    lambda value: value["cross_repo_requirements"][0].__setitem__(
                        "pin", None
                    ),
                    "requirements drifted",
                ),
                (
                    "artifact",
                    lambda value: value["artifacts"][0].__setitem__("sha256", "0" * 64),
                    "artifact bytes do not match",
                ),
                (
                    "artifact-path-set",
                    lambda value: value["artifacts"].pop(),
                    "path set is not exact",
                ),
            )
            for name, mutate, message in attacks:
                with self.subTest(name=name):
                    attacked = copy.deepcopy(document)
                    mutate(attacked)
                    with self.assertRaisesRegex(ReviewError, message):
                        validate_local_convergence(
                            attacked,
                            schema=schema,
                            expected_commit=commit,
                            artifact_root=root,
                        )

            aggregate_attack = copy.deepcopy(document)
            for row in aggregate_attack["artifacts"]:
                row["size_bytes"] = MAX_AGGREGATE_ARTIFACT_BYTES
            with self.assertRaisesRegex(ReviewError, "aggregate size limit"):
                validate_local_convergence(
                    aggregate_attack,
                    schema=schema,
                    expected_commit=commit,
                )

            with tempfile.TemporaryDirectory() as outside_directory:
                outside = Path(outside_directory)
                (outside / "evidence.json").write_text("outside\n", encoding="utf-8")
                (root / "alias").symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(ReviewError, "missing or unsafe"):
                    local_convergence_artifacts(root, ("alias/evidence.json",))
            with self.assertRaisesRegex(ReviewError, "path is unsafe"):
                local_convergence_artifacts(root, (r"ambiguous\path.json",))

            oversized = root / artifact_paths[0]
            oversized.write_bytes(b"")
            with oversized.open("r+b") as handle:
                handle.truncate(MAX_ARTIFACT_BYTES + 1)
            with self.assertRaisesRegex(ReviewError, "exceeds the size limit"):
                local_convergence_artifacts(root, artifact_paths)
            oversized.write_text("artifact 0\n", encoding="utf-8")

            dispositions["dispositions"][0]["status"] = "OPEN"
            with self.assertRaisesRegex(ReviewError, "open task disposition"):
                build_local_convergence(
                    commit=commit,
                    file_review={"tracked_files": 7, "reviewed_files": 7},
                    task_dispositions=dispositions,
                    artifacts=local_convergence_artifacts(root, artifact_paths),
                )

    def test_local_convergence_artifact_paths_reserve_outputs_and_inputs(self) -> None:
        attacks = (
            ("LOCAL-CONVERGENCE.json", "reserved name"),
            ("nested/local-convergence.json.sig", "reserved name"),
            ("inputs/LOCAL-CONVERGENCE.json", "reserved name"),
            ("inputs/unexpected.json", "reserved input namespace"),
            (
                "Inputs/FILE_REVIEW_LEDGER.completed.csv",
                "reserved input namespace",
            ),
        )
        for relative, message in attacks:
            with self.subTest(relative=relative):
                with self.assertRaisesRegex(ReviewError, message):
                    local_convergence_artifact_path_parts(relative)

        expected = "inputs/FILE_REVIEW_LEDGER.completed.csv"
        self.assertEqual(
            local_convergence_artifact_path_parts(expected),
            ("inputs", "FILE_REVIEW_LEDGER.completed.csv"),
        )

    def test_local_convergence_reader_owns_each_descriptor_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "nested"
            nested.mkdir()
            (nested / "artifact.json").write_bytes(b"retained")
            real_close = os.close

            def strict_close(descriptor: int) -> None:
                try:
                    real_close(descriptor)
                except OSError as error:
                    if error.errno == errno.EBADF:
                        raise AssertionError("descriptor was closed more than once")
                    raise

            with (
                mock.patch("local_convergence.os.close", side_effect=strict_close),
                self.assertRaisesRegex(ReviewError, "exceeds the size limit"),
            ):
                read_bounded_local_convergence_artifact(
                    root, "nested/artifact.json", max_bytes=0
                )

            root_link = root.parent / f"{root.name}-link"
            root_link.symlink_to(root, target_is_directory=True)
            try:
                with self.assertRaisesRegex(ReviewError, "root is missing or unsafe"):
                    read_bounded_local_convergence_artifact(
                        root_link, "nested/artifact.json"
                    )
            finally:
                root_link.unlink(missing_ok=True)

    def test_local_convergence_cli_authenticates_snapshot_before_artifacts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = root / "artifacts"
            for index, relative in enumerate(CONVERGENCE_ARTIFACT_PATHS):
                target = artifacts / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(f"artifact {index}\n", encoding="utf-8")
            commit = "a" * 40
            document = build_local_convergence(
                commit=commit,
                file_review={"tracked_files": 8, "reviewed_files": 8},
                task_dispositions={
                    "dispositions": [
                        {
                            "task_id": f"T{index:03d}",
                            "status": "COMPLETE_WITH_EXCLUSIONS",
                        }
                        for index in range(116)
                    ]
                },
                artifacts=local_convergence_artifacts(
                    artifacts, CONVERGENCE_ARTIFACT_PATHS
                ),
            )
            manifest = root / "LOCAL-CONVERGENCE.json"
            manifest.write_bytes(canonical_json(document))
            key = root / "key"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                check=True,
            )
            allowed = root / "ALLOWED_SIGNERS"
            derive_external_allowed_signers(key.with_suffix(".pub"), allowed)
            signature = sign_file(manifest, key, LOCAL_CONVERGENCE_NAMESPACE)

            def verify(
                manifest_path: Path,
                signature_path: Path,
                signers_path: Path,
                artifact_root: Path,
            ) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        sys.executable,
                        *qualifier.QUALIFICATION_PYTHON_FLAGS,
                        str(TOOLS / "local_convergence.py"),
                        "verify",
                        "--repo",
                        str(ROOT),
                        "--manifest",
                        str(manifest_path),
                        "--signature",
                        str(signature_path),
                        "--allowed-signers",
                        str(signers_path),
                        "--expected-commit",
                        commit,
                        "--artifact-root",
                        str(artifact_root),
                    ],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )

            valid = verify(manifest, signature, allowed, artifacts)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertIn("LOCAL_CONVERGENCE_OK", valid.stdout)

            invalid_signature = root / "invalid.sig"
            invalid_signature.write_bytes(b"not an SSH signature\n")
            invalid = verify(
                manifest,
                invalid_signature,
                allowed,
                root / "missing-artifact-root",
            )
            self.assertEqual(invalid.returncode, 2)
            self.assertIn(
                "invalid galadriel-local-convergence signature", invalid.stderr
            )
            self.assertNotIn("artifact root", invalid.stderr)

            wrong_namespace_manifest = root / "wrong-namespace.json"
            wrong_namespace_manifest.write_bytes(manifest.read_bytes())
            wrong_namespace_signature = sign_file(
                wrong_namespace_manifest, key, "another-namespace"
            )
            wrong_namespace = verify(
                wrong_namespace_manifest,
                wrong_namespace_signature,
                allowed,
                artifacts,
            )
            self.assertEqual(wrong_namespace.returncode, 2)
            self.assertIn(
                "invalid galadriel-local-convergence signature", wrong_namespace.stderr
            )

            for label, target in (
                ("manifest", manifest),
                ("signature", signature),
                ("signers", allowed),
            ):
                link = root / f"{label}-link"
                link.symlink_to(target)
                result = verify(
                    link if label == "manifest" else manifest,
                    link if label == "signature" else signature,
                    link if label == "signers" else allowed,
                    artifacts,
                )
                with self.subTest(link=label):
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("missing or not regular", result.stderr)

            oversized = root / "oversized.json"
            with oversized.open("wb") as handle:
                handle.truncate(MAX_MANIFEST_BYTES + 1)
            oversized_result = verify(oversized, signature, allowed, artifacts)
            self.assertEqual(oversized_result.returncode, 2)
            self.assertIn("manifest-byte", oversized_result.stderr)

            fifo = root / "manifest-fifo"
            os.mkfifo(fifo)
            fifo_result = verify(fifo, signature, allowed, artifacts)
            self.assertEqual(fifo_result.returncode, 2)
            self.assertIn("missing or not regular", fifo_result.stderr)

    def test_qualification_environment_has_an_exact_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private"
            private.mkdir()
            tools = qualification_tool_fixture(root)
            source = {
                "PATH": str(tools),
                "HOME": "/host/home",
                "RUSTUP_HOME": "/host/rustup",
                "RUSTFLAGS": "unexpected",
                "RUSTC_WRAPPER": "/tmp/wrapper",
                "CARGO_HOME": "/host/cargo",
                "HTTP_PROXY": "http://proxy.invalid",
                "DYLD_INSERT_LIBRARIES": "/tmp/library",
                "PYTHONPATH": "/tmp/python",
                "TOKEN": "secret",
            }
            environment = build_qualification_environment(
                source,
                private_root=private,
                target=private / "target",
                source_date_epoch="1234567890",
            )

            self.assertEqual(tuple(environment), QUALIFICATION_ENVIRONMENT_KEYS)
            self.assertEqual(set(environment), set(QUALIFICATION_ENVIRONMENT_KEYS))
            self.assertNotEqual(environment["PATH"], source["PATH"])
            for tool in QUALIFICATION_PATH_TOOLS:
                self.assertIsNotNone(
                    shutil.which(tool, path=environment["PATH"]),
                    tool,
                )
            self.assertEqual(environment["RUSTUP_HOME"], source["RUSTUP_HOME"])
            self.assertEqual(environment["GIT_ATTR_NOSYSTEM"], "1")
            self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
            self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
            self.assertEqual(environment["GIT_OPTIONAL_LOCKS"], "0")
            self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
            for name in (
                "RUSTFLAGS",
                "RUSTC_WRAPPER",
                "HTTP_PROXY",
                "DYLD_INSERT_LIBRARIES",
                "PYTHONPATH",
                "TOKEN",
            ):
                self.assertNotIn(name, environment)
            for name in ("CARGO_HOME", "CARGO_TARGET_DIR", "HOME", "TMPDIR"):
                path = Path(environment[name])
                self.assertTrue(path.is_dir())
                self.assertTrue(path.is_relative_to(private.resolve()))
            self.assertNotEqual(environment["HOME"], source["HOME"])
            self.assertNotEqual(environment["CARGO_HOME"], source["CARGO_HOME"])

    def test_qualification_environment_rejects_unsafe_tool_paths(self) -> None:
        cases = (
            ({"HOME": "/host/home"}, "requires PATH"),
            ({"PATH": "/usr/bin::/bin", "HOME": "/host/home"}, "absolute nonempty"),
            ({"PATH": "relative:/bin", "HOME": "/host/home"}, "absolute nonempty"),
            (
                {
                    "PATH": str(Path(sys.executable).resolve().parent),
                    "HOME": "/host/home",
                    "RUSTUP_HOME": "relative-rustup",
                },
                "RUSTUP_HOME must be absolute",
            ),
        )
        for index, (source, message) in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                private = Path(directory) / "private"
                private.mkdir()
                with self.assertRaisesRegex(ReviewError, message):
                    build_qualification_environment(
                        source,
                        private_root=private,
                        target=private / "target",
                        source_date_epoch="1234567890",
                        required_path_tools=("python3",),
                    )

    def test_qualification_environment_rejects_a_missing_required_tool(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private"
            private.mkdir()
            tools = root / "tools"
            tools.mkdir()
            with self.assertRaisesRegex(
                ReviewError, "does not resolve required tool missing-tool"
            ):
                build_qualification_environment(
                    {"PATH": str(tools), "HOME": "/host/home"},
                    private_root=private,
                    target=private / "target",
                    source_date_epoch="1234567890",
                    required_path_tools=("missing-tool",),
                )

    def test_qualification_environment_does_not_require_ambient_pkg_config(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private"
            private.mkdir()
            tools = qualification_tool_fixture(root)
            (tools / "pkg-config").unlink()
            self.assertFalse((tools / "pkg-config").exists())

            real_which = shutil.which

            def reject_pkg_config_lookup(
                name: str,
                *,
                path: str | None = None,
            ) -> str | None:
                if name == "pkg-config":
                    self.fail("qualification environment looked up ambient pkg-config")
                return real_which(name, path=path)

            with mock.patch.object(
                qualifier.shutil,
                "which",
                side_effect=reject_pkg_config_lookup,
            ):
                environment = build_qualification_environment(
                    {
                        "PATH": str(tools),
                        "HOME": "/host/home",
                        "RUSTUP_HOME": "/host/rustup",
                    },
                    private_root=private,
                    target=private / "target",
                    source_date_epoch="1234567890",
                )

            self.assertEqual(environment["PATH"].split(os.pathsep)[0], str(tools))

    def test_deep_fuzz_directories_are_private_empty_and_single_use(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private"
            private.mkdir()
            tools = qualification_tool_fixture(root)
            environment = build_qualification_environment(
                {
                    "PATH": str(tools),
                    "HOME": "/host/home",
                    "RUSTUP_HOME": "/host/rustup",
                },
                private_root=private,
                target=private / "target",
                source_date_epoch="1234567890",
            )

            worktree = private / "worktree"
            worktree.mkdir()
            (private / "evidence-runner").mkdir(mode=0o700)
            prepare_deep_fuzz_directories(environment)

            for category in ("fuzz-corpus", "fuzz-artifacts"):
                for target in (
                    "ncp_decode",
                    "detector_boundaries",
                    "lifecycle_state",
                ):
                    path = Path(environment["TMPDIR"]) / category / target
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
                    self.assertEqual(list(path.iterdir()), [])
                    verify_deep_fuzz_command_directories(
                        environment,
                        worktree,
                        target,
                        require_private_empty=True,
                    )

            with self.assertRaisesRegex(ReviewError, "creation failed"):
                prepare_deep_fuzz_directories(environment)

            unexpected = (
                Path(environment["TMPDIR"])
                / "fuzz-corpus"
                / "ncp_decode"
                / "unexpected"
            )
            unexpected.write_bytes(b"unexpected")
            with self.assertRaisesRegex(ReviewError, "not initially empty"):
                verify_deep_fuzz_command_directories(
                    environment,
                    worktree,
                    "ncp_decode",
                    require_private_empty=True,
                )

    def test_deep_fuzz_corpus_rejects_a_linked_temporary_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir(mode=0o700)
            linked = root / "linked"
            linked.symlink_to(target, target_is_directory=True)

            with self.assertRaisesRegex(ReviewError, "identity is invalid"):
                prepare_deep_fuzz_directories({"TMPDIR": str(linked)})

    def test_cargo_configuration_is_rejected_at_each_search_level(self) -> None:
        cases = (
            "worktree-config",
            "ancestor-config-toml",
            "cargo-home",
            "link",
            "dangling",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                ancestor = root / "ancestor"
                worktree = ancestor / "worktree"
                cargo_home = root / "cargo-home"
                worktree.mkdir(parents=True)
                cargo_home.mkdir()
                reject_cargo_configuration(worktree, cargo_home)

                if case == "worktree-config":
                    cargo = worktree / ".cargo"
                    cargo.mkdir()
                    (cargo / "config").write_text("[build]\n", encoding="utf-8")
                elif case == "ancestor-config-toml":
                    cargo = ancestor / ".cargo"
                    cargo.mkdir()
                    (cargo / "config.toml").write_text("[build]\n", encoding="utf-8")
                elif case == "cargo-home":
                    (cargo_home / "config.toml").write_text(
                        "[build]\n", encoding="utf-8"
                    )
                elif case == "link":
                    cargo = worktree / ".cargo"
                    cargo.mkdir()
                    target = root / "target-config"
                    target.write_text("[build]\n", encoding="utf-8")
                    (cargo / "config").symlink_to(target)
                else:
                    cargo = worktree / ".cargo"
                    cargo.mkdir()
                    (cargo / "config.toml").symlink_to(root / "missing-config")

                with self.assertRaisesRegex(ReviewError, "Cargo configuration"):
                    reject_cargo_configuration(worktree, cargo_home)

    def test_command_created_cargo_configuration_fails_the_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worktree, commit, tree, clone_control = exact_test_candidate(root)
            logs = root / "logs"
            logs.mkdir()
            environment = command_test_environment(root)
            self.assertEqual(
                Path(environment["CARGO_HOME"]),
                root.resolve(strict=True) / "test-cargo-home",
            )
            if sys.platform == "darwin":
                sandbox = candidate_sandbox_profile(
                    root,
                    worktree=worktree,
                    writable_paths=(Path(environment["CARGO_HOME"]),),
                )
                runner = contextlib.nullcontext()
            else:
                sandbox = root / "test-candidate.sb"
                sandbox.write_bytes(b"test-only sandbox policy\n")

                def create_cargo_configuration(
                    _argv: list[str] | tuple[str, ...], **kwargs: object
                ) -> qualifier.BoundedProcessResult:
                    process_environment = kwargs["environment"]
                    assert isinstance(process_environment, Mapping)
                    Path(process_environment["CARGO_HOME"], "config.toml").write_text(
                        "[build]\n", encoding="utf-8"
                    )
                    return qualifier.BoundedProcessResult(
                        returncode=0,
                        timed_out=False,
                        stdout=b"",
                        stderr=b"",
                        output_limit_exceeded=False,
                        containment_error=None,
                    )

                runner = mock.patch(
                    "qualify_candidate.run_bounded_process",
                    side_effect=create_cargo_configuration,
                )
            program = (
                "import os,pathlib; "
                "pathlib.Path(os.environ['CARGO_HOME'],'config.toml').write_text('[build]\\n')"
            )
            with runner:
                result = run_command(
                    CommandSpec("create-cargo-config", (sys.executable, "-c", program)),
                    worktree=worktree,
                    commit=commit,
                    tree=tree,
                    clone_control=clone_control,
                    sandbox_profile=sandbox,
                    environment=environment,
                    logs=logs,
                    index=1,
                )
            self.assertEqual(result["status"], "FAIL")
            log = root / result["log"]
            self.assertIn(
                "QUALIFICATION_POLICY_FAILURE", log.read_text(encoding="utf-8")
            )

    def test_finalizer_requires_exact_qualification_environment_contract(self) -> None:
        expected = qualification_environment_contract("1234567890")
        qualification = {"environment_contract": expected}
        validate_qualification_environment(qualification, 1_234_567_890)

        mutations = []
        added = copy.deepcopy(expected)
        added["unexpected"] = True
        mutations.append(added)
        removed = copy.deepcopy(expected)
        removed["isolated_paths"].pop()
        mutations.append(removed)
        policy = copy.deepcopy(expected)
        policy["cargo_config_policy"] = "ALLOW"
        mutations.append(policy)
        epoch = copy.deepcopy(expected)
        epoch["fixed_values"]["SOURCE_DATE_EPOCH"] = "1234567891"
        mutations.append(epoch)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(ReviewError, "environment contract"):
                    validate_qualification_environment(
                        {"environment_contract": mutation}, 1_234_567_890
                    )

    def test_finalizer_requires_every_pinned_qualification_tool(self) -> None:
        valid = {
            "tools": copy.deepcopy(EXPECTED_QUALIFICATION_TOOLS),
            "host": {
                "platform": "macOS-26.5.1-arm64-arm-64bit-Mach-O",
                "machine": "arm64",
                "python_implementation": "CPython",
            },
        }
        validate_qualification_tools(valid)

        for name in EXPECTED_QUALIFICATION_TOOLS:
            without = copy.deepcopy(valid)
            del without["tools"][name]
            with (
                self.subTest(tool=name, attack="omission"),
                self.assertRaisesRegex(ReviewError, "toolchain or release tool set"),
            ):
                validate_qualification_tools(without)

            substituted = copy.deepcopy(valid)
            substituted["tools"][name] = f"different {name}"
            with (
                self.subTest(tool=name, attack="substitution"),
                self.assertRaisesRegex(ReviewError, "toolchain or release tool set"),
            ):
                validate_qualification_tools(substituted)

        for field, value in (
            ("python_implementation", "PyPy"),
            ("machine", "x86_64"),
        ):
            changed_host = copy.deepcopy(valid)
            changed_host["host"][field] = value
            with (
                self.subTest(host_field=field),
                self.assertRaisesRegex(ReviewError, "host or Python implementation"),
            ):
                validate_qualification_tools(changed_host)

    def test_source_archive_pins_git_config_and_rejects_mode_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.name", "Sepehr Mahmoudian"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "sepmhn@gmail.com"],
                cwd=root,
                check=True,
            )
            (root / "README.md").write_text("archive fixture\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-q", "--no-gpg-sign", "-m", "Create fixture"],
                cwd=root,
                check=True,
            )
            commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD^{commit}"], cwd=root, text=True
            ).strip()
            subprocess.run(["git", "config", "tar.umask", "0077"], cwd=root, check=True)
            environment = command_test_environment(root)
            sandbox = root / "trusted-source-archive-fixture.sb"
            sandbox.write_text("test-only sandbox fixture\n", encoding="utf-8")

            def trusted_fixture_argv(
                _profile: Path,
                argv: list[str] | tuple[str, ...],
                **_kwargs: object,
            ) -> list[str]:
                return list(argv)

            with mock.patch(
                "qualify_candidate.sandboxed_argv",
                side_effect=trusted_fixture_argv,
            ):
                with mock.patch(
                    "qualify_candidate.run_bounded_process",
                    side_effect=run_portable_test_process,
                ):
                    record = source_archive(
                        root,
                        commit,
                        root / "canonical.tar.gz",
                        environment,
                        sandbox_profile=sandbox,
                    )
                self.assertEqual(record["tracked_entries"], 1)

                archive_runner = run_portable_test_process

                def run_with_wrong_mode(
                    argv: list[str] | tuple[str, ...], **kwargs: object
                ) -> object:
                    changed = list(argv)
                    if "tar.umask=0022" in changed:
                        changed[changed.index("tar.umask=0022")] = "tar.umask=0077"
                    return archive_runner(changed, **kwargs)

                with mock.patch(
                    "qualify_candidate.run_bounded_process",
                    side_effect=run_with_wrong_mode,
                ):
                    with self.assertRaisesRegex(ReviewError, "another type or mode"):
                        source_archive(
                            root,
                            commit,
                            root / "wrong-mode.tar.gz",
                            environment,
                            sandbox_profile=sandbox,
                        )

    @unittest.skipUnless(sys.platform == "darwin", "macOS containment test")
    def test_timeout_kills_child_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worktree, commit, tree, clone_control = exact_test_candidate(root)
            logs = root / "logs"
            logs.mkdir()
            sentinel = root / "child-survived"
            child = (
                "import pathlib,time; time.sleep(2); "
                f"pathlib.Path({str(sentinel)!r}).write_text('survived')"
            )
            parent = (
                "import subprocess,time; "
                f"subprocess.Popen(['python3','-c',{child!r}]); time.sleep(60)"
            )
            environment = command_test_environment(root)
            sandbox = candidate_sandbox_profile(root, worktree=worktree)
            result = run_command(
                CommandSpec(
                    "process-group-timeout",
                    ("python3", "-c", parent),
                    timeout_seconds=1,
                ),
                worktree=worktree,
                commit=commit,
                tree=tree,
                clone_control=clone_control,
                sandbox_profile=sandbox,
                environment=environment,
                logs=logs,
                index=1,
            )
            self.assertEqual(result["status"], "FAIL")
            self.assertTrue(result["timed_out"])
            time.sleep(2.2)
            self.assertFalse(sentinel.exists())

    def test_finalizer_early_failure_is_not_masked_by_cleanup(self) -> None:
        script = TOOLS / "finalize_release.py"
        process = subprocess.run(
            [
                "python3",
                *qualifier.QUALIFICATION_PYTHON_FLAGS,
                str(script),
                "--repo",
                "/definitely/missing/repository",
                "--candidate",
                "0" * 40,
                "--qualification",
                "/missing/qualification",
                "--review-ledger",
                "/missing/review.csv",
                "--task-dispositions",
                "/missing/tasks.json",
                "--task-dispositions-signature",
                "/missing/tasks.sig",
                "--final-review",
                "/missing/review.json",
                "--final-review-signature",
                "/missing/review.sig",
                "--decision-input",
                "/missing/decision.json",
                "--decision-input-signature",
                "/missing/decision.sig",
                "--signing-key",
                "/missing/key",
                "--allowed-signers",
                "/missing/allowed-signers",
                "--out",
                "/tmp/galadriel-finalizer-early-failure-test",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(process.returncode, 2)
        self.assertIn(
            "release finalization failed: qualification root is missing or unsafe",
            process.stderr,
        )
        self.assertNotIn("UnboundLocalError", process.stderr)

    def test_finalizer_reports_key_error_as_a_controlled_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            qualification = root / "qualification"
            qualification.mkdir()
            candidate = "a" * 40
            arguments = [
                "finalize_release.py",
                "--repo",
                str(repo),
                "--candidate",
                candidate,
                "--qualification",
                str(qualification),
                "--review-ledger",
                str(root / "review.csv"),
                "--task-dispositions",
                str(root / "tasks.json"),
                "--task-dispositions-signature",
                str(root / "tasks.sig"),
                "--final-review",
                str(root / "review.json"),
                "--final-review-signature",
                str(root / "review.sig"),
                "--decision-input",
                str(root / "decision.json"),
                "--decision-input-signature",
                str(root / "decision.sig"),
                "--signing-key",
                str(root / "signing-key"),
                "--allowed-signers",
                str(root / "allowed-signers"),
                "--out",
                str(root / "closure"),
            ]

            def fake_git(_repo: Path, *args: str, text: bool = True) -> str | bytes:
                if args == ("status", "--porcelain=v1", "--untracked-files=all"):
                    return ""
                if args == ("rev-parse", "HEAD^{commit}"):
                    return f"{candidate}\n"
                if args == ("branch", "--show-current"):
                    return "main\n"
                if args[0] == "show" and text is False:
                    return b"allowed signer fixture\n"
                raise AssertionError(f"unexpected Git invocation: {args!r}")

            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "argv", arguments),
                mock.patch("finalize_release.git", side_effect=fake_git),
                mock.patch(
                    "finalize_release.snapshot_input",
                    side_effect=lambda _source, destination, **_kwargs: destination,
                ),
                mock.patch(
                    "finalize_release.snapshot_independent_allowed_signers",
                    return_value=b"allowed signer fixture\n",
                ),
                mock.patch("finalize_release.assert_tracked_allowed_signer"),
                mock.patch(
                    "finalize_release.verify_candidate_commit", return_value="b" * 40
                ),
                mock.patch(
                    "finalize_release.refresh_canonical_origin_main",
                    return_value=(
                        "https://github.com/sepahead/galadriel",
                        candidate,
                    ),
                ),
                mock.patch("finalize_release.candidate_json", return_value={}),
                mock.patch(
                    "finalize_release.validate_candidate_plan_documents",
                    side_effect=KeyError("lens_catalog"),
                ),
                mock.patch("finalize_release.require_release_python_isolation"),
                mock.patch("finalize_release.require_pinned_cpython_runtime"),
                mock.patch("finalize_release.sys.stderr", stderr),
            ):
                self.assertEqual(finalize_release_main(), 2)
            self.assertIn("release finalization failed", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_finalizer_cli_rejects_symlinked_signed_inputs_and_key(self) -> None:
        script = TOOLS / "finalize_release.py"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, candidate, _, _ = exact_test_candidate(root)
            qualification = root / "qualification"
            qualification.mkdir()
            (qualification / "QUALIFICATION-MANIFEST.json").write_text(
                "manifest\n", encoding="utf-8"
            )
            (qualification / "QUALIFICATION-MANIFEST.json.sig").write_text(
                "signature\n", encoding="utf-8"
            )
            inputs = {
                "review-ledger": root / "review.csv",
                "task-dispositions": root / "tasks.json",
                "task-dispositions-signature": root / "tasks.sig",
                "final-review": root / "review.json",
                "final-review-signature": root / "review.sig",
                "decision-input": root / "decision.json",
                "decision-input-signature": root / "decision.sig",
                "signing-key": root / "signing-key",
                "allowed-signers": root / "allowed-signers",
            }
            for path in inputs.values():
                path.write_text("placeholder\n", encoding="utf-8")
            fixture_key = root / "fixture-key"
            subprocess.run(
                [
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    str(fixture_key),
                ],
                check=True,
            )
            public_fields = (
                fixture_key.with_suffix(".pub").read_text(encoding="ascii").split()
            )
            inputs["signing-key"].write_text(
                f"{public_fields[0]} {public_fields[1]}\n",
                encoding="ascii",
            )
            inputs["allowed-signers"].write_text(
                (f"sepmhn@gmail.com {public_fields[0]} {public_fields[1]}\n"),
                encoding="ascii",
            )
            target = root / "symlink-target"
            target.write_text("replacement\n", encoding="utf-8")

            base = [
                sys.executable,
                *qualifier.QUALIFICATION_PYTHON_FLAGS,
                str(script),
                "--repo",
                str(repo),
                "--candidate",
                candidate,
                "--qualification",
                str(qualification),
            ]
            for option, path in inputs.items():
                base.extend((f"--{option}", str(path)))
            for option, path in inputs.items():
                with self.subTest(option=option):
                    original = path.read_bytes()
                    path.unlink()
                    path.symlink_to(target)
                    process = subprocess.run(
                        [*base, "--out", str(root / f"output-{option}")],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(process.returncode, 2, process.stderr)
                    expected_error = (
                        "cannot open independent allowed-signers file"
                        if option == "allowed-signers"
                        else "must not be a symbolic link"
                        if option == "signing-key"
                        else "missing or not regular"
                    )
                    self.assertIn(expected_error, process.stderr)
                    path.unlink()
                    path.write_bytes(original)

            snapshot_target = root / "snapshot-target"
            snapshot_target.mkdir()
            snapshot_link = root / "snapshot-link"
            snapshot_link.symlink_to(snapshot_target, target_is_directory=True)
            process = subprocess.run(
                [
                    *base,
                    "--snapshot-dir",
                    str(snapshot_link),
                    "--out",
                    str(root / "output-snapshot-link"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(process.returncode, 2, process.stderr)
            self.assertIn("--snapshot-dir", process.stderr)


if __name__ == "__main__":
    unittest.main()
