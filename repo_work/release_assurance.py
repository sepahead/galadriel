"""Shared strict validators for exact-candidate release assurance.

The module is dependency-free so it can run in a detached candidate worktree.
It never supplies reviewer findings or task outcomes.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import re
import shlex
import subprocess
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, NamedTuple

from common import ReviewError, contained_path, git, load_json


VERSION = "0.9.0"
AUTHOR = "Sepehr Mahmoudian"
SIGNING_PRINCIPAL = "sepmhn@gmail.com"
LENSES = tuple(f"L{number:02d}" for number in range(1, 21))
GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z"
)
MUTATION_DIFF_OPTIONS = (
    "-c",
    "color.ui=false",
    "-c",
    "core.quotePath=true",
    "diff",
    "--no-ext-diff",
    "--no-textconv",
    "--no-renames",
    "--full-index",
    "--binary",
    "--diff-algorithm=myers",
    "--no-indent-heuristic",
)
MUTATION_LIVENESS_EXCLUDE_RES = (
    r"DeliveryBoundaryState::blocks_delivery -> bool with true$",
    r"replace != with == in DeliveryBoundaryState::blocks_delivery$",
    r"replace <impl Drop for (DeliveryGuard|ResetGuard)<'_>>::drop with \(\)$",
)
FOCUSED_MUTATION_RECEIPT = "FOCUSED-MUTATION-RUN.json"
CARGO_MUTANTS_IDENTITY = "cargo-mutants 27.1.0"
CARGO_IDENTITY = "cargo 1.89.0 (c24e10642 2025-06-23)"
RUSTC_IDENTITY = "rustc 1.89.0 (29483883e 2025-08-04)"


class FocusedMutant(NamedTuple):
    """One fully identified cargo-mutants transformation at a frozen source span."""

    name: str
    package: str
    file: str
    function_name: str
    return_type: str
    function_span: tuple[int, int, int, int]
    span: tuple[int, int, int, int]
    replacement: str
    genre: str


MUTATION_LIVENESS_CHECKS = (
    {
        "id": "delivery-boundary-state",
        "examine_re": "DeliveryBoundaryState::blocks_delivery",
        "test": "live::tests::each_delivery_boundary_state_independently_blocks_delivery",
        "output": "mutants-delivery-boundary",
        "required_mutants": (
            FocusedMutant(
                "crates/galadriel-ncp/src/live.rs:1266:9: replace "
                "DeliveryBoundaryState::blocks_delivery -> bool with true",
                "galadriel-ncp",
                "crates/galadriel-ncp/src/live.rs",
                "DeliveryBoundaryState::blocks_delivery",
                "-> bool",
                (1265, 5, 1267, 6),
                (1266, 9, 1266, 78),
                "true",
                "FnValue",
            ),
            FocusedMutant(
                "crates/galadriel-ncp/src/live.rs:1266:51: replace || with && in "
                "DeliveryBoundaryState::blocks_delivery",
                "galadriel-ncp",
                "crates/galadriel-ncp/src/live.rs",
                "DeliveryBoundaryState::blocks_delivery",
                "-> bool",
                (1265, 5, 1267, 6),
                (1266, 51, 1266, 53),
                "&&",
                "BinaryOperator",
            ),
            FocusedMutant(
                "crates/galadriel-ncp/src/live.rs:1266:30: replace || with && in "
                "DeliveryBoundaryState::blocks_delivery",
                "galadriel-ncp",
                "crates/galadriel-ncp/src/live.rs",
                "DeliveryBoundaryState::blocks_delivery",
                "-> bool",
                (1265, 5, 1267, 6),
                (1266, 30, 1266, 32),
                "&&",
                "BinaryOperator",
            ),
            FocusedMutant(
                "crates/galadriel-ncp/src/live.rs:1266:74: replace != with == in "
                "DeliveryBoundaryState::blocks_delivery",
                "galadriel-ncp",
                "crates/galadriel-ncp/src/live.rs",
                "DeliveryBoundaryState::blocks_delivery",
                "-> bool",
                (1265, 5, 1267, 6),
                (1266, 74, 1266, 76),
                "==",
                "BinaryOperator",
            ),
            FocusedMutant(
                "crates/galadriel-ncp/src/live.rs:1266:9: replace "
                "DeliveryBoundaryState::blocks_delivery -> bool with false",
                "galadriel-ncp",
                "crates/galadriel-ncp/src/live.rs",
                "DeliveryBoundaryState::blocks_delivery",
                "-> bool",
                (1265, 5, 1267, 6),
                (1266, 9, 1266, 78),
                "false",
                "FnValue",
            ),
        ),
    },
    {
        "id": "delivery-boundary-guards",
        "examine_re": r"<impl Drop for (DeliveryGuard|ResetGuard)",
        "test": "live::tests::delivery_and_reset_guards_release_their_exact_boundary_state",
        "output": "mutants-delivery-guards",
        "required_mutants": (
            FocusedMutant(
                "crates/galadriel-ncp/src/live.rs:1396:9: replace "
                "<impl Drop for DeliveryGuard<'_>>::drop with ()",
                "galadriel-ncp",
                "crates/galadriel-ncp/src/live.rs",
                "<impl Drop for DeliveryGuard<'_>>::drop",
                "",
                (1395, 5, 1408, 6),
                (1396, 9, 1407, 10),
                "()",
                "FnValue",
            ),
            FocusedMutant(
                "crates/galadriel-ncp/src/live.rs:1417:9: replace "
                "<impl Drop for ResetGuard<'_>>::drop with ()",
                "galadriel-ncp",
                "crates/galadriel-ncp/src/live.rs",
                "<impl Drop for ResetGuard<'_>>::drop",
                "",
                (1416, 5, 1429, 6),
                (1417, 9, 1428, 10),
                "()",
                "FnValue",
            ),
        ),
    },
)


def broad_mutation_command(shard_id: str) -> list[str]:
    """Return the exact broad changed-diff mutation command for one shard."""

    command = [
        "cargo",
        "mutants",
        "--no-config",
        "--workspace",
        "--no-shuffle",
        "--in-diff",
        "git.diff",
        "--exclude",
        "crates/galadriel-eval/**",
        "--exclude",
        "crates/galadriel-justify/**",
    ]
    for pattern in MUTATION_LIVENESS_EXCLUDE_RES:
        command.extend(("--exclude-re", pattern))
    command.extend(
        (
            "--timeout",
            "600",
            "--jobs",
            "2",
            "--shard",
            shard_id,
            "--all-features",
        )
    )
    return command


def focused_liveness_mutation_command(check: dict[str, Any]) -> list[str]:
    """Return one exact direct-test mutation command for a blocking invariant."""

    return [
        "cargo",
        "mutants",
        "--no-config",
        "--package",
        "galadriel-ncp",
        "--file",
        "crates/galadriel-ncp/src/live.rs",
        "--re",
        str(check["examine_re"]),
        "--line-col",
        "true",
        "--all-features",
        "--timeout",
        "120",
        "--jobs",
        "2",
        "--output",
        str(check["output"]),
        "--",
        "--lib",
        str(check["test"]),
        "--",
        "--exact",
    ]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(block)
            digest.update(block)
    return digest.hexdigest(), size


def require_keys(value: Any, expected: set[str], context: str) -> None:
    if not isinstance(value, dict):
        raise ReviewError(f"{context} must be an object")
    missing = sorted(expected - value.keys())
    extra = sorted(value.keys() - expected)
    if missing or extra:
        raise ReviewError(f"{context}: missing={missing}, unexpected={extra}")


def require_text(value: Any, context: str, *, minimum: int = 1) -> str:
    if not isinstance(value, str) or len(value.strip()) < minimum:
        raise ReviewError(f"{context} must be concrete non-empty text")
    return value.strip()


def require_digest_record(value: Any, context: str) -> None:
    """Require canonical SHA-256 and byte-count fields before comparing bytes."""

    require_keys(value, {"path", "sha256", "size_bytes"}, context)
    if not isinstance(value["sha256"], str) or not SHA256.fullmatch(value["sha256"]):
        raise ReviewError(f"{context} has an invalid SHA-256 digest")
    if type(value["size_bytes"]) is not int or value["size_bytes"] < 0:
        raise ReviewError(f"{context} has an invalid byte count")


def sign_file(document: Path, key: Path, namespace: str) -> Path:
    """Create a detached SSH signature and return its conventional path."""

    if not document.is_file() or document.is_symlink():
        raise ReviewError(f"signed document is not a regular file: {document}")
    if not key.is_file():
        raise ReviewError(f"SSH signing key is unavailable: {key}")
    signature = Path(f"{document}.sig")
    if signature.exists():
        raise ReviewError(f"refusing to replace signature: {signature}")
    process = subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", namespace, str(document)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if process.returncode != 0 or not signature.is_file():
        raise ReviewError(
            f"cannot sign {document.name} in namespace {namespace}: {process.stderr.strip()}"
        )
    return signature


def derive_external_allowed_signers(signing_key: Path, destination: Path) -> bytes:
    """Derive a public trust root from an external signing-key handle.

    ``signing_key`` may be a private key or an exact OpenSSH public key whose
    private half is available through ``ssh-agent``. Only the public output is
    written. The destination must be outside the candidate and is normally
    inside a short-lived temporary directory.
    """

    if not signing_key.is_file():
        raise ReviewError(f"SSH signing key is unavailable: {signing_key}")
    try:
        configured_fields = signing_key.read_bytes().strip().split()
    except OSError as error:
        raise ReviewError(f"cannot read SSH signing key: {error}") from error
    if configured_fields and configured_fields[0] == b"ssh-ed25519":
        try:
            public_key = [
                field.decode("ascii", "strict") for field in configured_fields[:2]
            ]
        except UnicodeDecodeError as error:
            raise ReviewError("external signing public key is not ASCII") from error
    else:
        process = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(signing_key)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode != 0:
            detail = process.stderr.decode("utf-8", "replace").strip()
            raise ReviewError(f"cannot derive external signing public key: {detail}")
        public_key = process.stdout.decode("ascii", "strict").strip().split()
    if len(public_key) < 2 or public_key[0] != "ssh-ed25519":
        raise ReviewError("external release signing key must be Ed25519")
    retained = f"{SIGNING_PRINCIPAL} {public_key[0]} {public_key[1]}\n".encode("ascii")
    if destination.exists():
        raise ReviewError(f"refusing to replace external trust root: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(retained)
    os.chmod(destination, 0o600)
    return retained


def assert_tracked_allowed_signer(path: Path, expected: bytes) -> None:
    """Treat the candidate signer file as metadata, never as the trust root."""

    if not path.is_file() or path.is_symlink():
        raise ReviewError(
            "candidate tracked allowed-signers metadata is missing or unsafe"
        )
    try:
        lines = [
            line.split(b"#", 1)[0].strip()
            for line in path.read_bytes().splitlines()
            if line.split(b"#", 1)[0].strip()
        ]
    except OSError as error:
        raise ReviewError(f"cannot read candidate signer metadata: {error}") from error
    expected_line = expected.strip()
    if lines != [expected_line]:
        raise ReviewError(
            "candidate replaced or altered the externally derived allowed signer"
        )


def verify_signature(
    document: Path,
    signature: Path,
    allowed_signers: Path,
    namespace: str,
    *,
    principal: str = SIGNING_PRINCIPAL,
) -> None:
    for path, label in (
        (document, "signed document"),
        (signature, "detached signature"),
        (allowed_signers, "allowed-signers trust root"),
    ):
        if not path.is_file() or path.is_symlink():
            raise ReviewError(f"missing or unsafe {label}: {path}")
    process = subprocess.run(
        [
            "ssh-keygen",
            "-Y",
            "verify",
            "-f",
            str(allowed_signers),
            "-I",
            principal,
            "-n",
            namespace,
            "-s",
            str(signature),
        ],
        input=document.read_bytes(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", "replace").strip()
        raise ReviewError(
            f"invalid {namespace} signature for {document.name}: {detail}"
        )


def verify_candidate_commit(repo: Path, commit: str, allowed_signers: Path) -> str:
    if not GIT_OBJECT.fullmatch(commit):
        raise ReviewError("candidate commit must be a full lowercase Git object")
    resolved = str(git(repo, "rev-parse", f"{commit}^{{commit}}")).strip()
    if resolved != commit:
        raise ReviewError(f"candidate commit resolves differently: {resolved}")
    process = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            f"gpg.ssh.allowedSignersFile={allowed_signers}",
            "verify-commit",
            commit,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        text=True,
    )
    if process.returncode != 0:
        raise ReviewError(
            f"candidate commit lacks the required signature: {process.stdout.strip()}"
        )
    return str(git(repo, "rev-parse", f"{commit}^{{tree}}")).strip()


def _required_row(
    rows: list[dict[str, Any]],
    criterion: str,
    detector: str,
    *,
    condition: str | None = None,
    experiment_kind: str | None = None,
    phi: float | None = None,
    covariance_scale: float | None = None,
) -> dict[str, Any]:
    matches = []
    for row in rows:
        if row.get("role") != "holdout" or row.get("detector") != detector:
            continue
        if condition is not None and row.get("condition") != condition:
            continue
        if (
            experiment_kind is not None
            and row.get("experiment_kind") != experiment_kind
        ):
            continue
        if phi is not None and row.get("phi") != phi:
            continue
        if (
            covariance_scale is not None
            and row.get("covariance_scale") != covariance_scale
        ):
            continue
        matches.append(row)
    if len(matches) != 1:
        raise ReviewError(
            f"{criterion}: expected one {detector} holdout row, found {len(matches)}"
        )
    return matches[0]


def _metric_observation(
    criterion: str,
    row: dict[str, Any],
    metric_name: str,
    minimum_eligible: int,
    comparison: str,
    threshold: float,
) -> dict[str, Any]:
    condition = row.get("condition")
    detector = row.get("detector")
    if not isinstance(condition, str) or not condition or not isinstance(detector, str):
        raise ReviewError(f"{criterion}: required evidence row lacks an identity")
    metrics = row.get("metrics")
    if not isinstance(metrics, dict) or metric_name not in metrics:
        raise ReviewError(f"{criterion}: {row.get('condition')} omits {metric_name}")
    metric = metrics[metric_name]
    if not isinstance(metric, dict):
        raise ReviewError(f"{criterion}: {metric_name} must be an object")
    if metric.get("status") != "estimated" or metric.get("ci_status") != "estimated":
        raise ReviewError(
            f"{criterion}: {metric_name} is not estimable with its declared interval"
        )
    eligible = metric.get("eligible_tracks")
    if (
        not isinstance(eligible, int)
        or isinstance(eligible, bool)
        or eligible < minimum_eligible
    ):
        raise ReviewError(
            f"{criterion}: {metric_name} has {eligible!r} eligible tracks; {minimum_eligible} required"
        )
    ci = metric.get("ci95")
    if (
        not isinstance(ci, list)
        or len(ci) != 2
        or not all(
            isinstance(bound, (int, float))
            and not isinstance(bound, bool)
            and math.isfinite(bound)
            for bound in ci
        )
        or ci[0] > ci[1]
    ):
        raise ReviewError(
            f"{criterion}: {metric_name} lacks a finite ordered 95% interval"
        )
    value = metric.get("value")
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
    ):
        raise ReviewError(f"{criterion}: {metric_name} lacks a finite point estimate")
    if not ci[0] <= value <= ci[1]:
        raise ReviewError(
            f"{criterion}: {metric_name} estimate lies outside its interval"
        )
    if comparison == "upper_le":
        decision_value = float(ci[1])
        passed = decision_value <= threshold
    elif comparison == "lower_ge":
        decision_value = float(ci[0])
        passed = decision_value >= threshold
    elif comparison == "value_le":
        decision_value = float(value)
        passed = decision_value <= threshold
    else:
        raise ReviewError(f"internal acceptance comparison is invalid: {comparison}")
    return {
        "condition": condition,
        "detector": detector,
        "metric": metric_name,
        "eligible_tracks": eligible,
        "value": value,
        "ci95": ci,
        "comparison": comparison,
        "decision_value": decision_value,
        "threshold": threshold,
        "status": "PASS" if passed else "FAIL",
    }


def evaluate_acceptance(
    summary: dict[str, Any], config: dict[str, Any]
) -> dict[str, Any]:
    """Evaluate the seven preregistered rules on their exact holdout rows.

    A malformed, duplicate, missing, non-estimable, or underpowered required row
    fails the evaluation; it is never omitted or pooled with another row.
    """

    rows = summary.get("holdout_results")
    if (
        not isinstance(rows, list)
        or not rows
        or not all(isinstance(row, dict) for row in rows)
    ):
        raise ReviewError("candidate summary lacks holdout result rows")
    minimum = config.get("min_metric_eligible_tracks")
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 2:
        raise ReviewError(
            "accepted evidence config has an invalid minimum eligible-track count"
        )

    def clean(detector: str, criterion: str) -> dict[str, Any]:
        return _required_row(
            rows,
            criterion,
            detector,
            experiment_kind="clean_autocorrelation",
            phi=0.0,
            covariance_scale=1.0,
        )

    default = "default_correlation_fusion"
    baseline = "nis_baseline"

    def attack(
        criterion: str, detector: str, condition: str, experiment_kind: str
    ) -> dict[str, Any]:
        return _required_row(
            rows,
            criterion,
            detector,
            condition=condition,
            experiment_kind=experiment_kind,
            phi=0.0,
            covariance_scale=1.0,
        )

    def detection_rows(criterion: str) -> list[dict[str, Any]]:
        return [
            attack(criterion, baseline, "attack_loud_acoustic", "targeted_attack"),
            attack(criterion, default, "attack_loud_acoustic", "targeted_attack"),
            attack(
                criterion,
                baseline,
                "attack_broad_degradation",
                "broad_degradation_attack",
            ),
            attack(
                criterion,
                default,
                "attack_broad_degradation",
                "broad_degradation_attack",
            ),
            attack(criterion, default, "attack_stealthy_acoustic", "targeted_attack"),
        ]

    def attribution_rows(criterion: str) -> list[dict[str, Any]]:
        return [
            attack(criterion, default, "attack_loud_acoustic", "targeted_attack"),
            attack(criterion, default, "attack_stealthy_acoustic", "targeted_attack"),
        ]

    specifications = [
        (
            "GLD-090-ACC-001",
            "upper 95% bound for clean-reference false-alert episodes is at most 0.10/hour",
            lambda: [
                (
                    clean(baseline, "GLD-090-ACC-001"),
                    "false_alerts_per_hour",
                    "upper_le",
                    0.10,
                ),
                (
                    clean(default, "GLD-090-ACC-001"),
                    "false_alerts_per_hour",
                    "upper_le",
                    0.10,
                ),
            ],
        ),
        (
            "GLD-090-ACC-002",
            "upper 95% bound for clean-reference mission alert probability is at most 0.05",
            lambda: [
                (
                    clean(baseline, "GLD-090-ACC-002"),
                    "mission_probability_any_alert",
                    "upper_le",
                    0.05,
                ),
                (
                    clean(default, "GLD-090-ACC-002"),
                    "mission_probability_any_alert",
                    "upper_le",
                    0.05,
                ),
            ],
        ),
        (
            "GLD-090-ACC-003",
            "lower 95% bound for each declared detector/attack arm is at least 0.90",
            lambda: [
                (row, "conditional_detection_probability", "lower_ge", 0.90)
                for row in detection_rows("GLD-090-ACC-003")
            ],
        ),
        (
            "GLD-090-ACC-004",
            "conditional empirical detection-delay p95 is at most 10000 ms",
            lambda: [
                (row, "conditional_delay_p95_ms", "value_le", 10_000.0)
                for row in detection_rows("GLD-090-ACC-004")
            ],
        ),
        (
            "GLD-090-ACC-005",
            "upper 95% bound for default-fusion attribution error is at most 0.10",
            lambda: [
                (row, "conditional_attribution_error", "upper_le", 0.10)
                for row in attribution_rows("GLD-090-ACC-005")
            ],
        ),
        (
            "GLD-090-ACC-006",
            "upper 95% bound for default-fusion clean-reference abstention is at most 0.05",
            lambda: [
                (
                    clean(default, "GLD-090-ACC-006"),
                    "abstention_fraction",
                    "upper_le",
                    0.05,
                )
            ],
        ),
        (
            "GLD-090-ACC-007",
            "upper 95% bound for default-fusion ordinary-missingness abstention is at most 0.50",
            lambda: [
                (
                    _required_row(
                        rows,
                        "GLD-090-ACC-007",
                        default,
                        condition="clean_ordinary_missingness",
                        experiment_kind="ordinary_missingness",
                        phi=0.0,
                        covariance_scale=1.0,
                    ),
                    "abstention_fraction",
                    "upper_le",
                    0.50,
                )
            ],
        ),
    ]
    criteria = []
    for criterion_id, rule, build_observations in specifications:
        try:
            evaluated = [
                _metric_observation(
                    criterion_id, row, metric, minimum, comparison, threshold
                )
                for row, metric, comparison, threshold in build_observations()
            ]
            criteria.append(
                {
                    "id": criterion_id,
                    "rule": rule,
                    "status": "PASS"
                    if all(observation["status"] == "PASS" for observation in evaluated)
                    else "FAIL",
                    "observations": evaluated,
                    "evaluation_error": None,
                }
            )
        except ReviewError as error:
            criteria.append(
                {
                    "id": criterion_id,
                    "rule": rule,
                    "status": "FAIL",
                    "observations": [],
                    "evaluation_error": str(error),
                }
            )
    failed = [
        criterion["id"] for criterion in criteria if criterion["status"] == "FAIL"
    ]
    return {
        "schema": "galadriel.candidate-acceptance.v1",
        "release": VERSION,
        "partition": "holdout_results",
        "minimum_metric_eligible_tracks": minimum,
        "status": "PASS" if not failed else "FAIL",
        "failed_criterion_ids": failed,
        "criteria": criteria,
    }


def validate_evidence_config_binding(
    tracked_config_path: Path,
    evidence_output: Path,
    *,
    tracked_relative_path: str,
) -> dict[str, Any]:
    """Bind accepted evidence output to the tracked preregistered input."""

    source = load_json(tracked_config_path)
    accepted_path = evidence_output / "config.json"
    manifest_path = evidence_output / "manifest.json"
    accepted = load_json(accepted_path)
    manifest = load_json(manifest_path)
    source_sha, source_size = digest_file(tracked_config_path)
    accepted_sha, _accepted_size = digest_file(accepted_path)
    inputs = manifest.get("inputs")
    if not isinstance(inputs, dict):
        raise ReviewError("candidate evidence manifest lacks input provenance")
    if inputs.get("config_source_path") != tracked_relative_path:
        raise ReviewError("candidate evidence manifest targets another config path")
    if inputs.get("config_source_sha256") != source_sha:
        raise ReviewError("candidate evidence source-config blob digest mismatch")
    if inputs.get("canonical_config_sha256") != accepted_sha:
        raise ReviewError("candidate evidence accepted-config byte digest mismatch")
    canonical_digest = accepted.get("canonical_digest")
    if (
        not isinstance(canonical_digest, str)
        or not SHA256.fullmatch(canonical_digest)
        or manifest.get("accepted_config_digest") != canonical_digest
    ):
        raise ReviewError("candidate evidence semantic config digest mismatch")

    direct_fields = {
        "schema_version",
        "study_id",
        "base_seed",
        "calibration_tracks",
        "holdout_tracks",
        "frames",
        "dt_ms",
        "assessment_step",
        "alert_episode_reset_policy",
        "attack_onset_frame",
        "mission_frames",
        "rho",
        "sigma",
        "loud_bias_sigma",
        "ordinary_missing_probability",
        "autocorrelation_phis",
        "covariance_scales",
        "bootstrap_resamples",
        "min_metric_eligible_tracks",
        "min_recorded_duration_ms",
    }
    if set(source) != direct_fields | {"detector", "correlation", "recorded_fixture"}:
        raise ReviewError(
            "tracked candidate evidence config has an unexpected field set"
        )
    for field in sorted(direct_fields):
        if accepted.get(field) != source[field]:
            raise ReviewError(f"accepted candidate evidence config drifted in {field}")
    for section in ("detector", "correlation", "recorded_fixture"):
        accepted_section = accepted.get(section)
        source_section = source[section]
        if not isinstance(accepted_section, dict) or not isinstance(
            source_section, dict
        ):
            raise ReviewError(f"candidate evidence {section} config is malformed")
        for field, expected in source_section.items():
            if accepted_section.get(field) != expected:
                raise ReviewError(
                    f"accepted candidate evidence config drifted in {section}.{field}"
                )

    minimums = {
        "calibration_tracks": 20,
        "holdout_tracks": 100,
        "bootstrap_resamples": 1_000,
        "min_metric_eligible_tracks": 20,
        "min_recorded_duration_ms": 3_600_000,
    }
    for field, minimum in minimums.items():
        value = source[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
            raise ReviewError(
                f"candidate evidence design is below the frozen minimum for {field}"
            )
    exact_design = {
        "frames": 3_600,
        "dt_ms": 100,
        "assessment_step": 10,
        "attack_onset_frame": 1_800,
        "mission_frames": 3_600,
        "alert_episode_reset_policy": "nominal_only",
    }
    for field, expected in exact_design.items():
        if source[field] != expected:
            raise ReviewError(f"candidate evidence design drifted in {field}")
    return {
        "tracked_path": tracked_relative_path,
        "tracked_blob_sha256": source_sha,
        "tracked_bytes": source_size,
        "accepted_config_sha256": accepted_sha,
        "accepted_semantic_digest": canonical_digest,
        "study_design_status": "PASS",
    }


def validate_mutation_evidence(
    manifest_path: Path,
    signature_path: Path,
    *,
    allowed_signers: Path,
    repo: Path,
    commit: str,
    tree: str,
) -> tuple[dict[str, Any], list[Path]]:
    """Validate signed exact-diff shards and focused liveness checks."""

    verify_signature(
        manifest_path,
        signature_path,
        allowed_signers,
        "galadriel-mutation-evidence",
    )
    document = load_json(manifest_path)
    require_keys(
        document,
        {
            "schema",
            "release",
            "author",
            "candidate",
            "baseline_commit",
            "git_diff_argv",
            "git_diff_sha256",
            "tool",
            "shards",
            "focused_run_receipt",
            "focused_checks",
        },
        "mutation evidence",
    )
    if (
        document["schema"] != "galadriel.mutation-evidence.v3"
        or document["release"] != VERSION
        or document["author"] != AUTHOR
    ):
        raise ReviewError("mutation evidence has the wrong schema, release, or author")
    if document["candidate"] != {"commit": commit, "tree": tree}:
        raise ReviewError("mutation evidence targets the wrong candidate")
    baseline = document["baseline_commit"]
    if baseline != "94e2f8cc01f352d2bf899b7f656997f143a2588f":
        raise ReviewError("mutation evidence targets the wrong frozen baseline")
    expected_diff_argv = ["git", *MUTATION_DIFF_OPTIONS, f"{baseline}..{commit}", "--"]
    if document["git_diff_argv"] != expected_diff_argv:
        raise ReviewError("mutation evidence used another Git diff contract")
    git(repo, "merge-base", "--is-ancestor", baseline, commit)
    diff = bytes(git(repo, *expected_diff_argv[1:], text=False))
    if not diff:
        raise ReviewError("mutation evidence has an empty frozen-baseline diff")
    if document["git_diff_sha256"] != sha256_bytes(diff):
        raise ReviewError("mutation evidence targets different candidate diff bytes")
    if document["tool"] != {"name": "cargo-mutants", "version": "27.1.0"}:
        raise ReviewError("mutation evidence uses another tool or version")
    shards = document["shards"]
    expected_ids = ["0/4", "1/4", "2/4", "3/4"]
    if (
        not isinstance(shards, list)
        or [item.get("id") for item in shards if isinstance(item, dict)] != expected_ids
    ):
        raise ReviewError(
            "mutation evidence must contain ordered shards 0/4 through 3/4"
        )
    artifacts = []
    artifact_paths: set[Path] = set()
    for shard in shards:
        require_keys(shard, {"id", "status", "command", "artifact"}, "mutation shard")
        if shard["status"] != "PASS":
            raise ReviewError(f"mutation shard {shard['id']} did not pass")
        command = require_text(
            shard["command"], f"mutation shard {shard['id']} command", minimum=40
        )
        expected_command = broad_mutation_command(shard["id"])
        try:
            observed_command = shlex.split(command)
        except ValueError as error:
            raise ReviewError(
                f"mutation shard {shard['id']} command is not valid shell syntax: {error}"
            ) from error
        if observed_command != expected_command:
            raise ReviewError(
                f"mutation shard {shard['id']} command differs from the frozen gate"
            )
        artifact = shard["artifact"]
        require_digest_record(artifact, "mutation shard artifact")
        relative = require_text(artifact["path"], "mutation artifact path")
        target = contained_path(manifest_path.parent, relative)
        if target in {manifest_path, signature_path}:
            raise ReviewError(
                "mutation evidence cannot reference its own manifest or signature"
            )
        if target in artifact_paths:
            raise ReviewError(
                "mutation shards must reference distinct outcomes artifacts"
            )
        if not target.is_file() or target.is_symlink():
            raise ReviewError(
                f"mutation shard artifact is missing or unsafe: {relative}"
            )
        digest, size = digest_file(target)
        if artifact["sha256"] != digest or artifact["size_bytes"] != size:
            raise ReviewError(f"mutation shard artifact digest mismatch: {relative}")
        validate_mutation_outcomes(target, shard["id"])
        artifact_paths.add(target)
        artifacts.append(target)

    receipt_record = document["focused_run_receipt"]
    require_keys(
        receipt_record,
        {"source_shard", "artifact"},
        "focused mutation run receipt",
    )
    if receipt_record["source_shard"] != "2/4":
        raise ReviewError("focused mutation run receipt came from another shard")
    receipt_artifact = receipt_record["artifact"]
    require_digest_record(
        receipt_artifact,
        "focused mutation run receipt artifact",
    )
    if receipt_artifact["path"] != FOCUSED_MUTATION_RECEIPT:
        raise ReviewError("focused mutation run receipt has another path")
    receipt_target = contained_path(manifest_path.parent, FOCUSED_MUTATION_RECEIPT)
    if (
        receipt_target in {manifest_path, signature_path}
        or receipt_target in artifact_paths
        or not receipt_target.is_file()
        or receipt_target.is_symlink()
    ):
        raise ReviewError("focused mutation run receipt artifact is missing or unsafe")
    receipt_digest, receipt_size = digest_file(receipt_target)
    if (
        receipt_artifact["sha256"] != receipt_digest
        or receipt_artifact["size_bytes"] != receipt_size
    ):
        raise ReviewError("focused mutation run receipt artifact digest mismatch")
    receipt_document, receipt_outcomes = validate_focused_mutation_receipt(
        receipt_target,
        root=manifest_path.parent,
        commit=commit,
        tree=tree,
    )
    artifact_paths.add(receipt_target)
    artifacts.append(receipt_target)

    focused_checks = document["focused_checks"]
    expected_check_ids = [str(check["id"]) for check in MUTATION_LIVENESS_CHECKS]
    if (
        not isinstance(focused_checks, list)
        or [item.get("id") for item in focused_checks if isinstance(item, dict)]
        != expected_check_ids
    ):
        raise ReviewError("mutation evidence lacks the ordered focused liveness checks")
    for index, (item, check) in enumerate(
        zip(focused_checks, MUTATION_LIVENESS_CHECKS, strict=True)
    ):
        require_keys(
            item,
            {"id", "status", "source_shard", "command", "artifact"},
            "focused mutation check",
        )
        check_id = str(check["id"])
        if item["id"] != check_id or item["status"] != "PASS":
            raise ReviewError(f"focused mutation check {check_id} did not pass")
        if item["source_shard"] != "2/4":
            raise ReviewError(
                f"focused mutation check {check_id} came from another shard"
            )
        command = require_text(
            item["command"], f"focused mutation check {check_id} command", minimum=40
        )
        try:
            observed_command = shlex.split(command)
        except ValueError as error:
            raise ReviewError(
                f"focused mutation check {check_id} command is not valid shell syntax: {error}"
            ) from error
        if (
            observed_command != focused_liveness_mutation_command(check)
            or observed_command != receipt_document["checks"][index]["command_argv"]
        ):
            raise ReviewError(
                f"focused mutation check {check_id} differs from the frozen gate"
            )
        artifact = item["artifact"]
        require_digest_record(artifact, "focused mutation artifact")
        relative = require_text(artifact["path"], "focused mutation artifact path")
        target = contained_path(manifest_path.parent, relative)
        if target != receipt_outcomes[check_id]:
            raise ReviewError(
                f"focused mutation check {check_id} differs from its run receipt"
            )
        if target in {manifest_path, signature_path} or target in artifact_paths:
            raise ReviewError(
                f"focused mutation check {check_id} references a duplicate artifact"
            )
        if not target.is_file() or target.is_symlink():
            raise ReviewError(
                f"focused mutation artifact is missing or unsafe: {relative}"
            )
        digest, size = digest_file(target)
        if artifact["sha256"] != digest or artifact["size_bytes"] != size:
            raise ReviewError(f"focused mutation artifact digest mismatch: {relative}")
        validate_focused_liveness_outcomes(target, check)
        artifact_paths.add(target)
        artifacts.append(target)
    return document, artifacts


def validate_mutation_outcomes(path: Path, shard_id: str) -> dict[str, int]:
    """Reject vacuous, incomplete, missed, or timed-out cargo-mutants outcomes."""

    if path.name != "outcomes.json" or not path.is_file() or path.is_symlink():
        raise ReviewError(f"mutation shard {shard_id} artifact must be outcomes.json")
    document = load_json(path)
    require_keys(
        document,
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
        f"mutation shard {shard_id} outcomes",
    )
    if document["cargo_mutants_version"] != "27.1.0":
        raise ReviewError(
            f"mutation shard {shard_id} outcomes use another tool version"
        )
    parsed_times = []
    for field in ("start_time", "end_time"):
        timestamp = document[field]
        if not isinstance(timestamp, str) or not TIMESTAMP.fullmatch(timestamp):
            raise ReviewError(
                f"mutation shard {shard_id} has an invalid {field} timestamp"
            )
        try:
            parsed_times.append(
                datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            )
        except ValueError as error:
            raise ReviewError(
                f"mutation shard {shard_id} has an invalid {field} timestamp"
            ) from error
    if parsed_times[1] < parsed_times[0]:
        raise ReviewError(f"mutation shard {shard_id} ends before it starts")
    counts: dict[str, int] = {}
    for field in (
        "total_mutants",
        "missed",
        "caught",
        "timeout",
        "unviable",
        "success",
    ):
        value = document[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ReviewError(f"mutation shard {shard_id} has an invalid {field} count")
        counts[field] = value
    if counts["total_mutants"] <= 0 or counts["caught"] <= 0:
        raise ReviewError(f"mutation shard {shard_id} is vacuous or caught no mutants")
    if counts["missed"] or counts["timeout"] or counts["success"]:
        raise ReviewError(
            f"mutation shard {shard_id} contains missed, timed-out, or unclassified mutants"
        )
    if counts["total_mutants"] != sum(
        counts[field]
        for field in ("missed", "caught", "timeout", "unviable", "success")
    ):
        raise ReviewError(f"mutation shard {shard_id} summary counts are inconsistent")

    outcomes = document["outcomes"]
    if not isinstance(outcomes, list):
        raise ReviewError(f"mutation shard {shard_id} outcomes must be a list")
    baseline = []
    mutant_summaries: Counter[str] = Counter()
    for index, outcome in enumerate(outcomes):
        if not isinstance(outcome, dict):
            raise ReviewError(f"mutation shard {shard_id} outcome {index} is malformed")
        scenario = outcome.get("scenario")
        summary = outcome.get("summary")
        if scenario == "Baseline":
            baseline.append(summary)
        elif isinstance(scenario, dict) and set(scenario) == {"Mutant"}:
            if not isinstance(summary, str):
                raise ReviewError(
                    f"mutation shard {shard_id} mutant outcome lacks a summary"
                )
            mutant_summaries[summary] += 1
        else:
            raise ReviewError(f"mutation shard {shard_id} contains an unknown scenario")
    if baseline != ["Success"]:
        raise ReviewError(f"mutation shard {shard_id} lacks one successful baseline")
    expected_summaries = Counter(
        {
            "CaughtMutant": counts["caught"],
            "MissedMutant": counts["missed"],
            "Timeout": counts["timeout"],
            "Unviable": counts["unviable"],
            "Success": counts["success"],
        }
    )
    expected_summaries += Counter()
    mutant_summaries += Counter()
    if mutant_summaries != expected_summaries:
        raise ReviewError(
            f"mutation shard {shard_id} outcome details contradict its summary"
        )
    return counts


def _focused_span_signature(value: Any, context: str) -> tuple[int, int, int, int]:
    """Parse one exact cargo-mutants source span without accepting extra fields."""

    require_keys(value, {"start", "end"}, context)
    coordinates: list[int] = []
    for endpoint in ("start", "end"):
        position = value[endpoint]
        require_keys(position, {"line", "column"}, f"{context} {endpoint}")
        for coordinate in ("line", "column"):
            number = position[coordinate]
            if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
                raise ReviewError(
                    f"{context} {endpoint} {coordinate} must be a positive integer"
                )
            coordinates.append(number)
    return coordinates[0], coordinates[1], coordinates[2], coordinates[3]


def _focused_exact_text(value: Any, context: str, *, allow_empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or (not allow_empty and not value)
        or value != value.strip()
    ):
        raise ReviewError(f"{context} must be canonical text")
    return value


def _focused_mutant_signature(value: Any, context: str) -> FocusedMutant:
    """Parse the complete immutable identity of one focused mutant."""

    require_keys(
        value,
        {"name", "package", "file", "function", "span", "replacement", "genre"},
        context,
    )
    function = value["function"]
    require_keys(
        function, {"function_name", "return_type", "span"}, f"{context} function"
    )
    return FocusedMutant(
        _focused_exact_text(value["name"], f"{context} name"),
        _focused_exact_text(value["package"], f"{context} package"),
        _focused_exact_text(value["file"], f"{context} file"),
        _focused_exact_text(function["function_name"], f"{context} function name"),
        _focused_exact_text(
            function["return_type"],
            f"{context} function return type",
            allow_empty=True,
        ),
        _focused_span_signature(function["span"], f"{context} function span"),
        _focused_span_signature(value["span"], f"{context} span"),
        _focused_exact_text(value["replacement"], f"{context} replacement"),
        _focused_exact_text(value["genre"], f"{context} genre"),
    )


def _validate_focused_phase(
    value: Any,
    *,
    context: str,
    expected_phase: str,
    expected_argv: tuple[str, ...],
    expected_status: Any,
    expected_cargo_executable: str | None,
) -> None:
    """Bind one cargo-mutants phase to its exact Cargo command and outcome."""

    require_keys(value, {"phase", "duration", "process_status", "argv"}, context)
    if value["phase"] != expected_phase:
        raise ReviewError(f"{context} is not the expected {expected_phase} phase")
    duration = value["duration"]
    if not isinstance(duration, float) or not math.isfinite(duration) or duration < 0:
        raise ReviewError(f"{context} has an invalid duration")
    argv = value["argv"]
    executable_matches = False
    if isinstance(argv, list) and argv and isinstance(argv[0], str):
        executable_matches = (
            Path(argv[0]).name == "cargo"
            if expected_cargo_executable is None
            else argv[0] == expected_cargo_executable
        )
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(argument, str) for argument in argv)
        or not executable_matches
        or tuple(argv[1:]) != expected_argv
    ):
        raise ReviewError(f"{context} used another Cargo command")
    process_status = value["process_status"]
    if expected_status == "Success":
        status_matches = process_status == "Success" and isinstance(process_status, str)
    else:
        status_matches = (
            isinstance(process_status, dict)
            and set(process_status) == {"Failure"}
            and type(process_status["Failure"]) is int
            and process_status["Failure"] == 101
        )
    if not status_matches:
        raise ReviewError(f"{context} has another process status")


def _validate_focused_artifact_path(
    value: Any, *, context: str, directory: str
) -> None:
    relative = _focused_exact_text(value, context)
    path = Path(relative)
    if (
        path.is_absolute()
        or ".." in path.parts
        or not relative.startswith(f"{directory}/")
    ):
        raise ReviewError(f"{context} is not a contained {directory} path")


def validate_focused_liveness_outcomes(
    path: Path,
    check: dict[str, Any],
    *,
    expected_cargo_executable: str | None = None,
) -> dict[str, int]:
    """Require an exact focused mutant set to be caught by one exact direct test."""

    check_id = str(check["id"])
    counts = validate_mutation_outcomes(path, f"focused/{check_id}")
    required: Counter[FocusedMutant] = Counter(check["required_mutants"])
    required_count = sum(required.values())
    if counts != {
        "total_mutants": required_count,
        "missed": 0,
        "caught": required_count,
        "timeout": 0,
        "unviable": 0,
        "success": 0,
    }:
        raise ReviewError(
            f"focused mutation check {check_id} did not catch its exact mutant set"
        )

    document = load_json(path)
    observed: Counter[FocusedMutant] = Counter()
    expected_build_argv = (
        "test",
        "--no-run",
        "--verbose",
        "--package=galadriel-ncp@0.9.0",
        "--all-features",
    )
    expected_test_argv = (
        "test",
        "--verbose",
        "--package=galadriel-ncp@0.9.0",
        "--all-features",
        "--lib",
        str(check["test"]),
        "--",
        "--exact",
    )
    for index, outcome in enumerate(document["outcomes"]):
        context = f"focused mutation check {check_id} outcome {index}"
        require_keys(
            outcome,
            {"scenario", "summary", "log_path", "diff_path", "phase_results"},
            context,
        )
        phases = outcome["phase_results"]
        if not isinstance(phases, list) or len(phases) != 2:
            raise ReviewError(f"{context} must contain exactly Build and Test phases")

        scenario = outcome["scenario"]
        baseline = scenario == "Baseline"
        test_status: Any = "Success" if baseline else {"Failure": 101}
        _validate_focused_phase(
            phases[0],
            context=f"{context} build",
            expected_phase="Build",
            expected_argv=expected_build_argv,
            expected_status="Success",
            expected_cargo_executable=expected_cargo_executable,
        )
        _validate_focused_phase(
            phases[1],
            context=f"{context} test",
            expected_phase="Test",
            expected_argv=expected_test_argv,
            expected_status=test_status,
            expected_cargo_executable=expected_cargo_executable,
        )
        _validate_focused_artifact_path(
            outcome["log_path"], context=f"{context} log path", directory="log"
        )

        if baseline:
            if outcome["summary"] != "Success":
                raise ReviewError(f"{context} baseline summary is not successful")
            if (
                outcome["log_path"] != "log/baseline.log"
                or outcome["diff_path"] is not None
            ):
                raise ReviewError(f"{context} baseline paths are not canonical")
            continue

        if outcome["summary"] != "CaughtMutant":
            raise ReviewError(f"{context} mutant summary is not caught")
        _validate_focused_artifact_path(
            outcome["diff_path"], context=f"{context} diff path", directory="diff"
        )
        mutant = scenario.get("Mutant") if isinstance(scenario, dict) else None
        observed[_focused_mutant_signature(mutant, f"{context} mutant")] += 1
    if observed != required:
        raise ReviewError(
            f"focused mutation check {check_id} targets another mutant set"
        )
    return counts


def validate_focused_mutation_receipt(
    path: Path,
    *,
    root: Path,
    commit: str,
    tree: str,
) -> tuple[dict[str, Any], dict[str, Path]]:
    """Bind focused outcomes to the exact runner invocation and Rust toolchain."""

    root = root.resolve()
    if not path.is_file() or path.is_symlink():
        raise ReviewError("focused mutation run receipt is missing or unsafe")
    path = path.resolve()
    if path != root / FOCUSED_MUTATION_RECEIPT:
        raise ReviewError("focused mutation run receipt is outside its artifact root")
    document = load_json(path)
    require_keys(
        document,
        {"schema", "candidate", "toolchain", "checks"},
        "focused mutation run receipt",
    )
    if document["schema"] != "galadriel.focused-mutation-run.v1":
        raise ReviewError("focused mutation run receipt has another schema")
    if document["candidate"] != {"commit": commit, "tree": tree}:
        raise ReviewError("focused mutation run receipt targets another candidate")
    toolchain = document["toolchain"]
    require_keys(
        toolchain,
        {"cargo", "cargo_executable", "cargo_mutants", "rustc"},
        "focused mutation run toolchain",
    )
    cargo_executable = _focused_exact_text(
        toolchain["cargo_executable"], "focused mutation Cargo executable"
    )
    if (
        not Path(cargo_executable).is_absolute()
        or Path(cargo_executable).name != "cargo"
    ):
        raise ReviewError(
            "focused mutation Cargo executable is not an absolute cargo path"
        )
    if toolchain != {
        "cargo": CARGO_IDENTITY,
        "cargo_executable": cargo_executable,
        "cargo_mutants": CARGO_MUTANTS_IDENTITY,
        "rustc": RUSTC_IDENTITY,
    }:
        raise ReviewError("focused mutation run used another pinned toolchain")

    checks = document["checks"]
    expected_ids = [str(check["id"]) for check in MUTATION_LIVENESS_CHECKS]
    if (
        not isinstance(checks, list)
        or [item.get("id") for item in checks if isinstance(item, dict)] != expected_ids
    ):
        raise ReviewError("focused mutation run receipt lacks the ordered checks")
    outcomes: dict[str, Path] = {}
    for item, check in zip(checks, MUTATION_LIVENESS_CHECKS, strict=True):
        check_id = str(check["id"])
        require_keys(
            item,
            {"id", "status", "command_argv", "counts", "outcomes"},
            f"focused mutation receipt check {check_id}",
        )
        if (
            item["id"] != check_id
            or item["status"] != "PASS"
            or item["command_argv"] != focused_liveness_mutation_command(check)
        ):
            raise ReviewError(f"focused mutation receipt check {check_id} drifted")
        artifact = item["outcomes"]
        require_digest_record(
            artifact,
            f"focused mutation receipt check {check_id} outcomes",
        )
        expected_relative = f"{check['output']}/mutants.out/outcomes.json"
        if artifact["path"] != expected_relative:
            raise ReviewError(
                f"focused mutation receipt check {check_id} targets another output"
            )
        target = contained_path(root, expected_relative)
        if target in outcomes.values() or not target.is_file() or target.is_symlink():
            raise ReviewError(
                f"focused mutation receipt check {check_id} output is missing or duplicate"
            )
        digest, size = digest_file(target)
        if artifact["sha256"] != digest or artifact["size_bytes"] != size:
            raise ReviewError(
                f"focused mutation receipt check {check_id} output digest mismatch"
            )
        counts = validate_focused_liveness_outcomes(
            target,
            check,
            expected_cargo_executable=cargo_executable,
        )
        recorded_counts = item["counts"]
        require_keys(
            recorded_counts,
            set(counts),
            f"focused mutation receipt check {check_id} counts",
        )
        if any(
            type(value) is not int or value < 0 for value in recorded_counts.values()
        ):
            raise ReviewError(
                f"focused mutation receipt check {check_id} has noncanonical counts"
            )
        if recorded_counts != counts:
            raise ReviewError(
                f"focused mutation receipt check {check_id} count record drifted"
            )
        outcomes[check_id] = target
    return document, outcomes


def git_tree_inventory(repo: Path, commit: str) -> dict[str, dict[str, Any]]:
    raw = bytes(git(repo, "ls-tree", "-rz", "-r", "--full-tree", commit, text=False))
    result: dict[str, dict[str, Any]] = {}
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        metadata, path_bytes = encoded.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split()
        path = path_bytes.decode("utf-8", "surrogateescape")
        if path in result:
            raise ReviewError(f"candidate tree contains duplicate path: {path}")
        if mode == "160000":
            data = object_id.encode("ascii") + b"\n"
        else:
            data = bytes(git(repo, "cat-file", "blob", object_id, text=False))
        result[path] = {
            "mode": mode,
            "object_type": object_type,
            "git_blob_id": object_id,
            "sha256": sha256_bytes(data),
            "bytes": len(data),
        }
    if not result:
        raise ReviewError("candidate tree inventory is empty")
    return result


FILE_LEDGER_COLUMNS = (
    "path",
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
)


def validate_completed_file_ledger(
    path: Path,
    repo: Path,
    commit: str,
    *,
    source_ledger: Path | None = None,
) -> dict[str, Any]:
    inventory = git_tree_inventory(repo, commit)
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if tuple(reader.fieldnames or ()) != FILE_LEDGER_COLUMNS:
                raise ReviewError(
                    "completed review ledger has the wrong or duplicate columns"
                )
            rows = list(reader)
    except (OSError, UnicodeError, csv.Error) as error:
        raise ReviewError(
            f"cannot read completed file-review ledger: {error}"
        ) from error
    by_path: dict[str, dict[str, str]] = {}
    for row in rows:
        relative = row["path"]
        if relative in by_path:
            raise ReviewError(f"completed review ledger has duplicate path: {relative}")
        expected = inventory.get(relative)
        if expected is None:
            raise ReviewError(f"completed review ledger has an extra path: {relative}")
        if row["git_blob_id"] != expected["git_blob_id"]:
            raise ReviewError(f"completed review ledger blob mismatch: {relative}")
        if row["sha256"] != expected["sha256"] or row["bytes"] != str(
            expected["bytes"]
        ):
            raise ReviewError(
                f"completed review ledger digest or size mismatch: {relative}"
            )
        if row["review_status"] not in {"REVIEWED_NO_DEFECT", "REVIEWED_RESOLVED"}:
            raise ReviewError(f"unreviewed file in completed ledger: {relative}")
        if not row["reviewer"].strip() or not TIMESTAMP.fullmatch(row["completed_at"]):
            raise ReviewError(f"completed review identity/time is invalid: {relative}")
        for field in (
            "requirements",
            "assumptions",
            "tests",
            "evidence",
            "disposition",
        ):
            if not row[field].strip():
                raise ReviewError(f"completed review ledger lacks {field}: {relative}")
        if row["review_status"] == "REVIEWED_RESOLVED" and not row["defects"].strip():
            raise ReviewError(f"resolved review row lacks defect record: {relative}")
        if row["review_status"] == "REVIEWED_NO_DEFECT" and row["defects"].strip():
            raise ReviewError(
                f"no-defect review row contains a defect record: {relative}"
            )
        by_path[relative] = row
    missing = sorted(set(inventory) - set(by_path))
    if missing:
        raise ReviewError(
            f"completed review ledger is missing tracked paths: {missing[:10]}"
        )
    source_digest = None
    if source_ledger is not None:
        try:
            with source_ledger.open(newline="", encoding="utf-8") as handle:
                source_reader = csv.DictReader(handle)
                if tuple(source_reader.fieldnames or ()) != FILE_LEDGER_COLUMNS:
                    raise ReviewError(
                        "source review ledger has the wrong or duplicate columns"
                    )
                source_rows = list(source_reader)
        except (OSError, UnicodeError, csv.Error) as error:
            raise ReviewError(
                f"cannot read source file-review ledger: {error}"
            ) from error
        source_by_path = {row["path"]: row for row in source_rows}
        if len(source_by_path) != len(source_rows) or set(source_by_path) != set(
            by_path
        ):
            raise ReviewError(
                "completed review ledger differs from the source path set"
            )
        immutable_fields = FILE_LEDGER_COLUMNS[:12]
        for relative, row in by_path.items():
            source = source_by_path[relative]
            if source["review_status"] != "UNREVIEWED":
                raise ReviewError(
                    f"source review ledger already claims review: {relative}"
                )
            if any(row[field] != source[field] for field in immutable_fields):
                raise ReviewError(
                    f"completed review ledger changed source metadata: {relative}"
                )
        source_digest = digest_file(source_ledger)[0]
    return {
        "tracked_files": len(inventory),
        "reviewed_files": len(by_path),
        "ledger_sha256": digest_file(path)[0],
        "source_ledger_sha256": source_digest,
    }


def verify_artifact_manifest(
    root: Path,
    manifest_path: Path,
    *,
    expected_schema: str,
    forbidden_paths: set[str],
) -> dict[str, Any]:
    document = load_json(manifest_path)
    require_keys(
        document, {"schema", "tier", "candidate", "artifacts"}, "artifact manifest"
    )
    if document["schema"] != expected_schema:
        raise ReviewError("artifact manifest has the wrong schema")
    artifacts = document["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise ReviewError("artifact manifest must contain artifacts")
    seen: set[str] = set()
    for item in artifacts:
        require_digest_record(item, "manifest artifact")
        relative = item["path"]
        if not isinstance(relative, str) or relative in seen:
            raise ReviewError(f"duplicate or invalid manifest path: {relative!r}")
        if relative in forbidden_paths:
            raise ReviewError(
                f"self-reference is prohibited in artifact manifest: {relative}"
            )
        seen.add(relative)
        target = contained_path(root, relative)
        if not target.is_file():
            raise ReviewError(f"manifest artifact is missing: {relative}")
        digest, size = digest_file(target)
        if digest != item["sha256"] or size != item["size_bytes"]:
            raise ReviewError(f"manifest artifact digest mismatch: {relative}")
    actual: set[str] = set()
    for target in sorted(root.rglob("*")):
        relative = target.relative_to(root).as_posix()
        if target.is_symlink():
            raise ReviewError(f"artifact tier contains a symlink: {relative}")
        if target.is_file() and relative not in forbidden_paths:
            actual.add(relative)
    unlisted = sorted(actual - seen)
    if unlisted:
        raise ReviewError(f"artifact manifest omits retained files: {unlisted[:10]}")
    return document


def candidate_blob(repo: Path, commit: str, relative: str) -> bytes:
    candidate = Path(relative)
    if (
        not relative
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ReviewError(f"candidate evidence path is unsafe: {relative!r}")
    return bytes(git(repo, "show", f"{commit}:{relative}", text=False))


def validate_evidence_reference(
    reference: Any,
    *,
    repo: Path,
    commit: str,
    qualification_root: Path,
) -> str:
    require_keys(reference, {"kind", "path", "sha256"}, "evidence reference")
    kind = reference["kind"]
    relative = require_text(reference["path"], "evidence reference path")
    expected = reference["sha256"]
    if not isinstance(expected, str) or not SHA256.fullmatch(expected):
        raise ReviewError("evidence reference has an invalid SHA-256")
    if kind == "candidate_blob":
        actual = sha256_bytes(candidate_blob(repo, commit, relative))
    elif kind == "qualification_artifact":
        target = contained_path(qualification_root, relative)
        if not target.is_file():
            raise ReviewError(f"qualification evidence is missing: {relative}")
        actual = digest_file(target)[0]
    else:
        raise ReviewError(f"unsupported evidence reference kind: {kind!r}")
    if actual != expected:
        raise ReviewError(f"evidence reference digest mismatch: {kind}:{relative}")
    return f"{kind}:{relative}:{expected}"


def validate_reviewed_task_dispositions(
    document: dict[str, Any],
    *,
    plan: dict[str, Any],
    claims: dict[str, dict[str, Any]],
    repo: Path,
    commit: str,
    tree: str,
    qualification_root: Path,
    source_plan_sha256: str,
) -> dict[str, Any]:
    """Validate reviewer-supplied closure against every exact source item."""

    require_keys(
        document,
        {
            "schema",
            "release",
            "author",
            "candidate",
            "source_plan_sha256",
            "dispositions",
        },
        "reviewed task dispositions",
    )
    if document["schema"] != "galadriel.reviewed-task-dispositions.v2":
        raise ReviewError("reviewed task dispositions have the wrong schema")
    if document["release"] != VERSION or document["author"] != AUTHOR:
        raise ReviewError("reviewed task dispositions have the wrong release or author")
    if document["candidate"] != {"commit": commit, "tree": tree}:
        raise ReviewError("reviewed task dispositions target the wrong candidate")
    if document["source_plan_sha256"] != source_plan_sha256:
        raise ReviewError("reviewed task dispositions target the wrong source plan")
    planned = plan.get("tasks")
    dispositions = document["dispositions"]
    if (
        not isinstance(planned, list)
        or not isinstance(dispositions, list)
        or len(planned) != 116
        or len(dispositions) != 116
    ):
        raise ReviewError(
            "reviewed task dispositions must close exactly 116 planned tasks"
        )

    reference_cache: dict[str, str] = {}

    def checked_reference(item: Any) -> str:
        try:
            key = json.dumps(item, sort_keys=True, ensure_ascii=False)
        except (TypeError, ValueError) as error:
            raise ReviewError(
                f"evidence reference is not canonical JSON: {error}"
            ) from error
        if key not in reference_cache:
            reference_cache[key] = validate_evidence_reference(
                item, repo=repo, commit=commit, qualification_root=qualification_root
            )
        return reference_cache[key]

    complete = 0
    not_claimed = 0
    all_findings: set[str] = set()
    categories = (
        "preconditions",
        "procedure",
        "mandatory_counterfactuals",
        "required_evidence",
    )
    for task_plan, disposition in zip(planned, dispositions, strict=True):
        task_id = task_plan["task_id"]
        require_keys(
            disposition,
            {
                "task_id",
                "status",
                "source_projection_sha256",
                "source_item_results",
                "evidence",
                "tests",
                "failed_attempt_inventory",
                "lens_answers",
                "residual_risks",
                "removed_claim_ids",
            },
            f"reviewed disposition/{task_id}",
        )
        if disposition["task_id"] != task_id:
            raise ReviewError(
                f"reviewed task disposition sequence changed at {task_id}"
            )
        if (
            disposition["source_projection_sha256"]
            != task_plan["source_projection_sha256"]
        ):
            raise ReviewError(
                f"{task_id}: disposition targets another source projection"
            )
        status = disposition["status"]
        if status not in {"COMPLETE_WITH_EXCLUSIONS", "NOT_CLAIMED"}:
            raise ReviewError(f"{task_id}: invalid final task status")
        if task_plan["status"] == "NOT_CLAIMED" and status != "NOT_CLAIMED":
            raise ReviewError(f"{task_id}: unavailable outcome cannot become complete")
        if (
            task_plan["status"] == "PENDING_POST_COMMIT"
            and status != "COMPLETE_WITH_EXCLUSIONS"
        ):
            raise ReviewError(
                f"{task_id}: pending task must be completed, not newly unclaimed"
            )
        removed = disposition["removed_claim_ids"]
        if not isinstance(removed, list) or len(set(removed)) != len(removed):
            raise ReviewError(f"{task_id}: removed claim IDs are malformed")
        mandatory_removed = set(task_plan["claim_removal_links"])
        mandatory_removed.update(
            claim_id
            for item in task_plan["requirement_exclusions"]
            for claim_id in item["claim_removal_links"]
        )
        mandatory_removed.update(
            claim_id
            for links in task_plan["lens_exclusions"].values()
            for claim_id in links
        )
        if set(removed) != mandatory_removed:
            raise ReviewError(
                f"{task_id}: disposition changed the frozen source exclusions"
            )
        if status == "NOT_CLAIMED" and not set(
            task_plan["claim_removal_links"]
        ).issubset(set(removed)):
            raise ReviewError(
                f"{task_id}: NOT_CLAIMED omits its task-level claim removal"
            )
        for claim_id in removed:
            if claims.get(claim_id, {}).get("tier") != "NOT_CLAIMED":
                raise ReviewError(
                    f"{task_id}: removed claim is not excluded: {claim_id}"
                )

        evidence = disposition["evidence"]
        tests = disposition["tests"]
        if (
            not isinstance(evidence, list)
            or not evidence
            or not isinstance(tests, list)
            or not tests
        ):
            raise ReviewError(f"{task_id}: task evidence/tests must both be retained")
        evidence_refs = {checked_reference(item) for item in [*evidence, *tests]}

        source = task_plan["source_projection"]
        results = disposition["source_item_results"]
        require_keys(
            results, {*categories, "completion_rule"}, f"{task_id}/source item results"
        )
        excluded_paths = {
            item["source_path"]: set(item["claim_removal_links"])
            for item in task_plan["requirement_exclusions"]
        }

        def validate_result(result: Any, text: str, source_path: str) -> None:
            require_keys(
                result,
                {"source_sha256", "status", "evidence", "claim_removal_links"},
                f"{task_id}/{source_path} result",
            )
            if result["source_sha256"] != sha256_bytes(text.encode("utf-8")):
                raise ReviewError(
                    f"{task_id}/{source_path}: result targets another source item"
                )
            result_status = result["status"]
            if result_status not in {"SATISFIED", "NOT_CLAIMED"}:
                raise ReviewError(
                    f"{task_id}/{source_path}: invalid source-item status"
                )
            links = result["claim_removal_links"]
            if not isinstance(links, list) or len(set(links)) != len(links):
                raise ReviewError(f"{task_id}/{source_path}: malformed claim links")
            allowed_links = set(task_plan["claim_removal_links"]) | excluded_paths.get(
                source_path, set()
            )
            planned_links = excluded_paths.get(source_path, set())
            if planned_links and (
                result_status != "NOT_CLAIMED" or set(links) != planned_links
            ):
                raise ReviewError(
                    f"{task_id}/{source_path}: frozen source exclusion was not retained"
                )
            if result_status == "SATISFIED" and links:
                raise ReviewError(
                    f"{task_id}/{source_path}: satisfied item cannot remove claims"
                )
            if result_status == "NOT_CLAIMED" and (
                not links or not set(links).issubset(allowed_links)
            ):
                raise ReviewError(
                    f"{task_id}/{source_path}: unplanned source-item exclusion"
                )
            references = result["evidence"]
            if not isinstance(references, list) or not references:
                raise ReviewError(f"{task_id}/{source_path}: result lacks evidence")
            if not {checked_reference(item) for item in references}.issubset(
                evidence_refs
            ):
                raise ReviewError(
                    f"{task_id}/{source_path}: result evidence is outside task evidence"
                )

        for category in categories:
            source_items = source[category]
            actual_items = results[category]
            if not isinstance(actual_items, list) or len(actual_items) != len(
                source_items
            ):
                raise ReviewError(
                    f"{task_id}: {category} result coverage is incomplete"
                )
            for index, (result, text) in enumerate(
                zip(actual_items, source_items, strict=True)
            ):
                validate_result(result, text, f"{category}[{index}]")
        validate_result(
            results["completion_rule"], source["completion_rule"], "completion_rule"
        )

        failed_inventory = disposition["failed_attempt_inventory"]
        require_keys(
            failed_inventory, {"status", "attempts"}, f"{task_id}/failed attempts"
        )
        if failed_inventory["status"] not in {"NONE_RECORDED", "RETAINED"}:
            raise ReviewError(f"{task_id}: invalid failed-attempt inventory status")
        attempts = failed_inventory["attempts"]
        if not isinstance(attempts, list) or (
            failed_inventory["status"] == "RETAINED"
        ) != bool(attempts):
            raise ReviewError(
                f"{task_id}: failed-attempt inventory and attempts disagree"
            )
        for index, attempt in enumerate(attempts):
            require_keys(
                attempt,
                {"source_path", "outcome", "evidence"},
                f"{task_id}/failed attempt {index}",
            )
            require_text(
                attempt["source_path"], f"{task_id}/failed attempt source", minimum=4
            )
            require_text(
                attempt["outcome"], f"{task_id}/failed attempt outcome", minimum=40
            )
            refs = attempt["evidence"]
            if (
                not isinstance(refs, list)
                or not refs
                or not {checked_reference(item) for item in refs}.issubset(
                    evidence_refs
                )
            ):
                raise ReviewError(
                    f"{task_id}: failed attempt lacks retained task evidence"
                )

        answers = disposition["lens_answers"]
        questions = source["twenty_lens_review"]
        if not isinstance(answers, dict) or tuple(answers) != LENSES:
            raise ReviewError(
                f"{task_id}: final lens answers must contain ordered L01--L20"
            )
        for lens in LENSES:
            answer = answers[lens]
            require_keys(
                answer,
                {
                    "question_sha256",
                    "status",
                    "finding",
                    "evidence",
                    "claim_removal_links",
                },
                f"{task_id}/{lens} answer",
            )
            if answer["question_sha256"] != sha256_bytes(
                questions[lens]["question"].encode("utf-8")
            ):
                raise ReviewError(
                    f"{task_id}/{lens}: answer targets another source question"
                )
            if answer["status"] not in {"RESOLVED", "NOT_APPLICABLE", "NOT_CLAIMED"}:
                raise ReviewError(f"{task_id}/{lens}: invalid answer status")
            links = answer["claim_removal_links"]
            allowed_lens_links = set(task_plan["lens_exclusions"].get(lens, [])) | set(
                task_plan["claim_removal_links"]
            )
            planned_lens_links = set(task_plan["lens_exclusions"].get(lens, []))
            if planned_lens_links and (
                answer["status"] != "NOT_CLAIMED" or set(links) != planned_lens_links
            ):
                raise ReviewError(
                    f"{task_id}/{lens}: frozen lens exclusion was not retained"
                )
            if answer["status"] == "NOT_CLAIMED" and (
                not links or not set(links).issubset(allowed_lens_links)
            ):
                raise ReviewError(f"{task_id}/{lens}: unplanned lens exclusion")
            if answer["status"] != "NOT_CLAIMED" and links:
                raise ReviewError(
                    f"{task_id}/{lens}: resolved lens cannot remove claims"
                )
            finding = require_text(
                answer["finding"], f"{task_id}/{lens} finding", minimum=60
            )
            if task_id not in finding or lens not in finding:
                raise ReviewError(f"{task_id}/{lens}: generic task lens is prohibited")
            normalized = " ".join(finding.casefold().split())
            if normalized in all_findings:
                raise ReviewError(
                    f"{task_id}/{lens}: duplicate generic task lens finding"
                )
            all_findings.add(normalized)
            refs = answer["evidence"]
            if (
                not isinstance(refs, list)
                or not refs
                or not {checked_reference(item) for item in refs}.issubset(
                    evidence_refs
                )
            ):
                raise ReviewError(
                    f"{task_id}/{lens}: finding lacks retained task evidence"
                )

        risks = disposition["residual_risks"]
        if not isinstance(risks, list) or not risks:
            raise ReviewError(f"{task_id}: final disposition lacks residual risks")
        for index, risk in enumerate(risks):
            text = require_text(risk, f"{task_id}/residual risk {index}", minimum=40)
            if task_id not in text:
                raise ReviewError(f"{task_id}: residual risk is not task-specific")
        if status == "COMPLETE_WITH_EXCLUSIONS":
            complete += 1
        else:
            not_claimed += 1
    return {
        "complete_with_exclusions": complete,
        "not_claimed": not_claimed,
        "total": 116,
    }


def validate_final_twenty_lens_review(
    document: dict[str, Any],
    *,
    lens_catalog: dict[str, dict[str, str]],
    repo: Path,
    commit: str,
    tree: str,
    qualification_root: Path,
) -> dict[str, Any]:
    require_keys(
        document,
        {
            "schema",
            "release",
            "author",
            "candidate",
            "reviewed_at",
            "review_method",
            "lenses",
            "residual_risks",
            "conclusion",
        },
        "final twenty-lens review",
    )
    if document["schema"] != "galadriel.final-twenty-lens-review.v2":
        raise ReviewError("final twenty-lens review has the wrong schema")
    if document["release"] != VERSION or document["author"] != AUTHOR:
        raise ReviewError("final twenty-lens review has the wrong release or author")
    if document["candidate"] != {"commit": commit, "tree": tree}:
        raise ReviewError("final twenty-lens review targets the wrong candidate")
    if not isinstance(document["reviewed_at"], str) or not TIMESTAMP.fullmatch(
        document["reviewed_at"]
    ):
        raise ReviewError("final twenty-lens review has an invalid completion time")
    require_text(document["review_method"], "final review method", minimum=30)
    lenses = document["lenses"]
    if not isinstance(lenses, dict) or tuple(lenses) != LENSES:
        raise ReviewError("final review must contain ordered L01--L20")
    findings: set[str] = set()
    for lens in LENSES:
        value = lenses[lens]
        require_keys(
            value,
            {"catalog_question_sha256", "question", "status", "finding", "evidence"},
            f"final review/{lens}",
        )
        catalog_question = lens_catalog[lens]["question"]
        if value["catalog_question_sha256"] != sha256_bytes(
            catalog_question.encode("utf-8")
        ):
            raise ReviewError(f"final review/{lens}: catalog question binding changed")
        if value["question"] != catalog_question:
            raise ReviewError(f"final review/{lens}: catalog question text changed")
        if value["status"] not in {"RESOLVED", "NOT_APPLICABLE"}:
            raise ReviewError(f"final review/{lens}: invalid status")
        finding = require_text(
            value["finding"], f"final review/{lens}/finding", minimum=80
        )
        if lens not in finding:
            raise ReviewError(f"final review/{lens}: finding is not lens-specific")
        normalized = " ".join(finding.casefold().split())
        if normalized in findings:
            raise ReviewError(f"final review/{lens}: duplicate generic finding")
        findings.add(normalized)
        references = value["evidence"]
        if not isinstance(references, list) or not references:
            raise ReviewError(f"final review/{lens}: finding lacks evidence")
        for reference in references:
            validate_evidence_reference(
                reference,
                repo=repo,
                commit=commit,
                qualification_root=qualification_root,
            )
    risks = document["residual_risks"]
    if not isinstance(risks, list) or not risks:
        raise ReviewError("final review must retain residual risks")
    for index, risk in enumerate(risks):
        require_text(risk, f"final review residual risk {index}", minimum=40)
    if document["conclusion"] != "COMPLETE_WITH_EXCLUSIONS":
        raise ReviewError("final review conclusion must be COMPLETE_WITH_EXCLUSIONS")
    return {"lenses": 20, "residual_risks": len(risks)}


def validate_decision_input(
    document: dict[str, Any],
    *,
    acceptance: dict[str, Any],
    excluded_claim_ids: set[str],
) -> None:
    require_keys(
        document,
        {
            "schema",
            "release",
            "author",
            "decision",
            "publication_scope",
            "doi",
            "zenodo",
            "removed_claim_ids",
            "acceptance_failure_dispositions",
            "residual_risks",
        },
        "release decision input",
    )
    if document["schema"] != "galadriel.release-decision-input.v1":
        raise ReviewError("release decision input has the wrong schema")
    if document["release"] != VERSION or document["author"] != AUTHOR:
        raise ReviewError("release decision input has the wrong release or author")
    decision = document["decision"]
    if decision not in {"GO", "NARROWED_GO", "NO_GO"}:
        raise ReviewError("release decision input has an invalid decision")
    if document["publication_scope"] != "GitHub research source release":
        raise ReviewError("release decision input has the wrong publication scope")
    if document["doi"] is not None or document["zenodo"] is not None:
        raise ReviewError(
            "release decision input must not claim DOI or Zenodo metadata"
        )
    removed = document["removed_claim_ids"]
    if (
        not isinstance(removed, list)
        or len(set(removed)) != len(removed)
        or not set(removed).issubset(excluded_claim_ids)
    ):
        raise ReviewError("release decision input has invalid removed claims")
    risks = document["residual_risks"]
    if not isinstance(risks, list) or not risks:
        raise ReviewError("release decision input must retain residual risks")
    for index, risk in enumerate(risks):
        require_text(risk, f"decision residual risk {index}", minimum=40)

    failed = acceptance.get("failed_criterion_ids")
    if acceptance.get("status") not in {"PASS", "FAIL"} or not isinstance(failed, list):
        raise ReviewError("candidate acceptance record is malformed")
    failure_dispositions = document["acceptance_failure_dispositions"]
    if not isinstance(failure_dispositions, dict):
        raise ReviewError("acceptance failure dispositions must be an object")
    if acceptance["status"] == "PASS":
        if failure_dispositions:
            raise ReviewError("passing acceptance cannot carry failure dispositions")
    else:
        if decision == "GO":
            raise ReviewError(
                "GO is prohibited when a candidate acceptance criterion failed"
            )
        if set(failure_dispositions) != set(failed):
            raise ReviewError(
                "failed acceptance criteria lack exact narrowed dispositions"
            )
        for criterion_id, disposition in failure_dispositions.items():
            if criterion_id not in {
                f"GLD-090-ACC-{number:03d}" for number in range(1, 8)
            }:
                raise ReviewError(
                    f"unknown acceptance criterion in narrowed decision: {criterion_id}"
                )
            require_keys(
                disposition,
                {"removed_claim_ids", "residual_risk"},
                f"acceptance failure disposition/{criterion_id}",
            )
            claim_ids = disposition["removed_claim_ids"]
            if (
                not isinstance(claim_ids, list)
                or claim_ids != ["CLM-007"]
                or "CLM-007" not in excluded_claim_ids
                or not set(claim_ids).issubset(set(removed))
            ):
                raise ReviewError(
                    f"{criterion_id}: failed acceptance is not mapped to removed claims"
                )
            require_text(
                disposition["residual_risk"],
                f"acceptance failure disposition/{criterion_id}/residual risk",
                minimum=50,
            )
