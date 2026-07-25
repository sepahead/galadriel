"""Shared strict validators for exact-candidate release assurance.

The module is dependency-free so it can run in a detached candidate worktree.
It never supplies reviewer findings or task outcomes.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import math
import os
import re
import shlex
import stat
import struct
import tempfile
from collections import Counter
from decimal import Decimal, localcontext
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, NamedTuple

from common import (
    BoundedHostResult as BoundedHostResult,
    RootedFileCapture,
    RootedFileCaptureRequest,
    RootedFileDigestRequest,
    SAFE_GIT_CONFIGURATION,
    ReviewError,
    assert_no_replace_refs,
    canonical_relative_parts,
    digest_rooted_regular_file,
    digest_rooted_regular_files,
    digest_rooted_tree,
    git,
    git_bounded_output,
    loads_json,
    read_bounded_regular_file,
    read_rooted_regular_file,
    read_rooted_regular_files,
    run_bounded_host_command,
    safe_git_environment,
    sanitized_host_environment as sanitized_host_environment,
    trusted_host_executable_path,
    validate_json_structure,
)


VERSION = "0.9.0"
AUTHOR = "Sepehr Mahmoudian"
AUTHOR_EMAIL = "sepmhn@gmail.com"
SIGNING_PRINCIPAL = "sepmhn@gmail.com"
LENSES = tuple(f"L{number:02d}" for number in range(1, 21))
GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_EVIDENCE_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_JSON_DEPTH = 256
MAX_EVIDENCE_JSON_NODES = 2_000_000
MAX_EVIDENCE_TRIAL_LINE_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_TRIAL_RECORDS = 10_000
MAX_CANDIDATE_EVIDENCE_FILE_BYTES = 1024 * 1024 * 1024
MAX_CANDIDATE_EVIDENCE_BYTES = 4 * 1024 * 1024 * 1024
EVIDENCE_FILES = (
    "SHA256SUMS",
    "config.json",
    "manifest.json",
    "report.md",
    "summary.json",
    "trials.jsonl",
)
EVIDENCE_CHECKSUM_FILES = EVIDENCE_FILES[1:]
EVIDENCE_TRIAL_SCHEMA = "galadriel.evidence.trial.v3"
EVIDENCE_SUMMARY_SCHEMA = "galadriel.evidence.summary.v3"
EVIDENCE_MANIFEST_SCHEMA = "galadriel.evidence.manifest.v3"
EVIDENCE_GENERATOR_PROFILE = "galadriel-evidence-synthetic-generator-v3"
EVIDENCE_REPLAY_PROFILE = "verified-recorded-fixture-replay-v1"
EVIDENCE_MISSINGNESS_PROFILE = "deterministic-independent-bernoulli-acoustic-v1"
EVIDENCE_ACCEPTANCE_PROFILE = "galadriel-0.9-frozen-acceptance-metrics-v3"
EVIDENCE_BOOTSTRAP_PROFILE = "splitmix64-rejection-group-metric-v1"
EVIDENCE_ACCEPTED_PROFILE = "galadriel-evidence/custom-v0.9"
EVIDENCE_CONFIG_DOMAIN = b"galadriel-evidence-config-v0.9\0"
EVIDENCE_SOURCE_CONFIG_SHA256 = (
    "2eb3018c7aed325c5cefd03b8b1d3ab0db9ece3c8cbe798d80bc0746aec74092"
)
EVIDENCE_FIXTURE_PATH = "crates/galadriel-ncp/tests/fixtures/crebain_clean_capture.jsonl"
EVIDENCE_FIXTURE_SHA256 = (
    "154b2b6534659500bc8ef99b53f482692d01f4b3f65d6d52a1e890796eea643c"
)
EVIDENCE_FIXTURE_BYTES = 184_195
EVIDENCE_RELEASE_SUITE_IDENTITY = (
    "c8c0beec29b6f513921c20c5c215f4dd1877992a6a5dab3b97b540ce832fc881"
)
EVIDENCE_SCOPE = (
    "streaming normalized innovation squared (NIS) baseline",
    "streaming default signed-correlation fusion over producer-attested projections",
    (
        "partial information decomposition (PID) excluded because this revision has only a "
        "terminal replay assessment"
    ),
)
EVIDENCE_DIRECT_CONFIG_FIELDS = {
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
MAX_CANDIDATE_TREE_LISTING_BYTES = 64 * 1024 * 1024
MAX_CANDIDATE_TREE_ENTRIES = 100_000
MAX_CANDIDATE_PATH_BYTES = 4 * 1024
MAX_CANDIDATE_PATH_COMPONENT_BYTES = 255
MAX_CANDIDATE_PATH_DEPTH = 64
MAX_CANDIDATE_BLOB_BYTES = 256 * 1024 * 1024
MAX_CANDIDATE_TREE_BLOB_BYTES = 4 * 1024 * 1024 * 1024
MAX_GIT_IDENTITY_BYTES = 16 * 1024
CANONICAL_REPOSITORY = "https://github.com/sepahead/galadriel"
CANONICAL_FETCH_URL = f"{CANONICAL_REPOSITORY}.git"
CANONICAL_MAIN_REFSPEC = "refs/heads/main:refs/remotes/origin/main"
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
MUTATION_BASELINE_COMMIT = "94e2f8cc01f352d2bf899b7f656997f143a2588f"
BROAD_MUTATION_RECEIPT = "BROAD-MUTATION-RUN.json"
FOCUSED_MUTATION_RECEIPT = "FOCUSED-MUTATION-RUN.json"
MUTATION_PATH_TOOLS = (
    "git",
    "python3",
    "rustc",
    "cargo",
    "rustup",
    "cargo-mutants",
    "cc",
    "clang",
    "ar",
    "ld",
    "make",
    "cmake",
    "pkg-config",
)
MUTATION_ENVIRONMENT_CONTRACT = {
    "schema": "galadriel.mutation-environment.v2",
    "base_keys": [
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_TARGET_DIR",
        "CARGO_TERM_COLOR",
        "GIT_ATTR_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_OPTIONAL_LOCKS",
        "GIT_TERMINAL_PROMPT",
        "HOME",
        "LC_ALL",
        "PATH",
        "RUSTUP_HOME",
        "SOURCE_DATE_EPOCH",
        "TMPDIR",
        "TZ",
    ],
    "cargo_config_policy": "REJECT_FILE_DIRECTORY_OR_LINK",
    "host_tool_inputs": ["HOME", "PATH", "RUSTUP_HOME"],
    "git_configuration_policy": "NO_SYSTEM_OR_GLOBAL_CONFIGURATION",
    "path_policy": "RESOLVED_REQUIRED_TOOL_DIRECTORIES",
    "path_tools": list(MUTATION_PATH_TOOLS),
    "rustup_home_policy": "RUSTUP_HOME_OR_HOME_DOT_RUSTUP",
    "isolated_paths": ["CARGO_HOME", "CARGO_TARGET_DIR", "HOME", "TMPDIR"],
    "fixed_values": {
        "CARGO_INCREMENTAL": "0",
        "CARGO_TERM_COLOR": "never",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "TZ": "UTC",
    },
    "source_date_epoch": "CANDIDATE_COMMIT_TIME",
    "process_containment": {
        "mode": "LINUX_CANDIDATE_TREE",
        "launch_gate": "STOP_BEFORE_EXEC",
        "platform": "LINUX_PROCFS_PIDFD_CHILD_SUBREAPER",
        "subreaper_ownership": "SERIALIZED_PROCESS_LOCAL",
        "root_reap": "AFTER_CANDIDATE_TREE_EXTINCTION",
        "unsupported_platform": "FAIL_BEFORE_SPAWN",
        "uninterruptible_process": "FAIL_CLOSED",
        "isolation_scope": "NOT_CGROUP_CONTAINER_OR_DEPLOYMENT_ISOLATION",
    },
}
# Keep the focused name as a compatibility alias for callers that use the
# narrower receipt vocabulary.
FOCUSED_MUTATION_ENVIRONMENT_CONTRACT = MUTATION_ENVIRONMENT_CONTRACT
CARGO_MUTANTS_IDENTITY = "cargo-mutants 27.1.0"
CARGO_IDENTITY = "cargo 1.89.0 (c24e10642 2025-06-23)"
RUSTC_IDENTITY = "rustc 1.89.0 (29483883e 2025-08-04)"
MAX_ALLOWED_SIGNERS_BYTES = 64 * 1024
MAX_SIGNING_HANDLE_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 256 * 1024
MAX_SIGNED_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_MUTATION_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_MUTATION_RECEIPT_BYTES = 1 * 1024 * 1024
MAX_MUTATION_OUTCOMES_BYTES = 32 * 1024 * 1024
MAX_MUTATION_DIFF_BYTES = 128 * 1024 * 1024
MAX_MUTATION_EVIDENCE_BYTES = 512 * 1024 * 1024
MAX_FILE_LEDGER_BYTES = 64 * 1024 * 1024
MAX_FILE_LEDGER_ROWS = 100_000
MAX_FILE_LEDGER_CELL_BYTES = 1024 * 1024
MAX_TIER_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_TIER_ARTIFACTS = 32_768
MAX_TIER_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_TIER_AGGREGATE_BYTES = 8 * 1024 * 1024 * 1024
MAX_TIER_CONTROL_BYTES = 256 * 1024 * 1024
MAX_TIER_TREE_ENTRIES = MAX_TIER_ARTIFACTS + 256
MAX_TIER_PATH_DEPTH = 128
MAX_TIER_PATH_BYTES = 4 * 1024
MAX_TIER_PATH_COMPONENT_BYTES = 255
BROAD_MUTATION_SHARDS = ("0/4", "1/4", "2/4", "3/4")
# The exact-candidate runner supplies one absolute CARGO_TARGET_DIR.
# One worker prevents concurrent mutant copies from sharing build artifacts.
MUTATION_JOBS = "1"
BROAD_MUTATION_MINIMUM_TOTAL = 500
BROAD_MUTATION_MINIMUM_CAUGHT_RATIO = 0.70
BROAD_MUTATION_PACKAGES = (
    "galadriel-cli",
    "galadriel-core",
    "galadriel-ncp",
    "galadriel-pid",
    "galadriel-sim",
)
BROAD_MUTATION_GENRES = {
    "BinaryOperator",
    "FnValue",
    "MatchArm",
    "MatchArmGuard",
    "UnaryOperator",
}
FUNCTIONLESS_BROAD_MUTATION_GENRES = frozenset(
    {
        "BinaryOperator",
        "MatchArm",
        "MatchArmGuard",
        "UnaryOperator",
    }
)
MetricDomain = Literal["probability", "rate", "delay"]
ACCEPTANCE_METRIC_DOMAINS: dict[str, MetricDomain] = {
    "false_alerts_per_hour": "rate",
    "mission_probability_any_alert": "probability",
    "conditional_detection_probability": "probability",
    "conditional_delay_p95_ms": "delay",
    "conditional_attribution_error": "probability",
    "abstention_fraction": "probability",
}


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


class BroadMutantFunction(NamedTuple):
    """One optional cargo-mutants function identity."""

    function_name: str
    return_type: str
    span: tuple[int, int, int, int]


class BroadMutant(NamedTuple):
    """One fully identified broad mutation at a frozen source span."""

    name: str
    package: str
    file: str
    function: BroadMutantFunction | None
    span: tuple[int, int, int, int]
    replacement: str
    genre: str


def _ssh_host_environment(*, use_agent: bool) -> dict[str, str]:
    """Return a sanitized SSH environment with one optional agent socket."""

    environment = sanitized_host_environment()
    if use_agent:
        agent_socket = os.environ.get("SSH_AUTH_SOCK")
        if agent_socket is not None:
            if not agent_socket or "\0" in agent_socket:
                raise ReviewError("SSH agent socket selector is invalid")
            environment["SSH_AUTH_SOCK"] = agent_socket
    return environment


ACCEPTANCE_MUTANT_FILE = "crates/galadriel-eval/src/evidence_main.rs"


def _acceptance_mutant(
    function_name: str,
    return_type: str,
    function_span: tuple[int, int, int, int],
    span: tuple[int, int, int, int],
    replacement: str,
    genre: str,
    transformation: str,
) -> FocusedMutant:
    """Construct one exact acceptance-evidence mutant identity."""

    return FocusedMutant(
        f"{ACCEPTANCE_MUTANT_FILE}:{span[0]}:{span[1]}: {transformation}",
        "galadriel-eval",
        ACCEPTANCE_MUTANT_FILE,
        function_name,
        return_type,
        function_span,
        span,
        replacement,
        genre,
    )


ACCEPTANCE_EVIDENCE_MUTANTS = (
    _acceptance_mutant(
        "interval_envelope",
        "-> [f64; 2]",
        (2754, 1, 2758, 2),
        (2755, 5, 2757, 7),
        "[0.0; 2]",
        "FnValue",
        "replace interval_envelope -> [f64; 2] with [0.0; 2]",
    ),
    _acceptance_mutant(
        "interval_envelope",
        "-> [f64; 2]",
        (2754, 1, 2758, 2),
        (2755, 5, 2757, 7),
        "[-1.0; 2]",
        "FnValue",
        "replace interval_envelope -> [f64; 2] with [-1.0; 2]",
    ),
    _acceptance_mutant(
        "bootstrap_sample_is_sufficient",
        "-> bool",
        (2807, 1, 2809, 2),
        (2808, 5, 2808, 60),
        "true",
        "FnValue",
        "replace bootstrap_sample_is_sufficient -> bool with true",
    ),
    _acceptance_mutant(
        "bootstrap_sample_is_sufficient",
        "-> bool",
        (2807, 1, 2809, 2),
        (2808, 5, 2808, 60),
        "false",
        "FnValue",
        "replace bootstrap_sample_is_sufficient -> bool with false",
    ),
    _acceptance_mutant(
        "interval_envelope",
        "-> [f64; 2]",
        (2754, 1, 2758, 2),
        (2755, 5, 2757, 7),
        "[1.0; 2]",
        "FnValue",
        "replace interval_envelope -> [f64; 2] with [1.0; 2]",
    ),
    _acceptance_mutant(
        "estimate_metric",
        "-> MetricEstimate",
        (2816, 1, 2992, 2),
        (2822, 5, 2991, 6),
        "Default::default()",
        "FnValue",
        "replace estimate_metric -> MetricEstimate with Default::default()",
    ),
    _acceptance_mutant(
        "bootstrap_sample_is_sufficient",
        "-> bool",
        (2807, 1, 2809, 2),
        (2808, 30, 2808, 32),
        "<",
        "BinaryOperator",
        "replace >= with < in bootstrap_sample_is_sufficient",
    ),
    _acceptance_mutant(
        "estimate_metric",
        "-> MetricEstimate",
        (2816, 1, 2992, 2),
        (2845, 7, 2845, 9),
        "||",
        "BinaryOperator",
        "replace && with || in estimate_metric",
    ),
    _acceptance_mutant(
        "estimate_metric",
        "-> MetricEstimate",
        (2816, 1, 2992, 2),
        (2845, 26, 2845, 27),
        "==",
        "BinaryOperator",
        "replace < with == in estimate_metric",
    ),
    _acceptance_mutant(
        "estimate_metric",
        "-> MetricEstimate",
        (2816, 1, 2992, 2),
        (2845, 26, 2845, 27),
        ">",
        "BinaryOperator",
        "replace < with > in estimate_metric",
    ),
    _acceptance_mutant(
        "estimate_metric",
        "-> MetricEstimate",
        (2816, 1, 2992, 2),
        (2845, 26, 2845, 27),
        "<=",
        "BinaryOperator",
        "replace < with <= in estimate_metric",
    ),
    _acceptance_mutant(
        "estimate_metric",
        "-> MetricEstimate",
        (2816, 1, 2992, 2),
        (2865, 46, 2865, 47),
        "|",
        "BinaryOperator",
        "replace ^ with | in estimate_metric",
    ),
    _acceptance_mutant(
        "estimate_metric",
        "-> MetricEstimate",
        (2816, 1, 2992, 2),
        (2865, 46, 2865, 47),
        "&",
        "BinaryOperator",
        "replace ^ with & in estimate_metric",
    ),
    _acceptance_mutant(
        "estimate_metric",
        "-> MetricEstimate",
        (2816, 1, 2992, 2),
        (2865, 26, 2865, 27),
        "|",
        "BinaryOperator",
        "replace ^ with | in estimate_metric",
    ),
    _acceptance_mutant(
        "estimate_metric",
        "-> MetricEstimate",
        (2816, 1, 2992, 2),
        (2865, 26, 2865, 27),
        "&",
        "BinaryOperator",
        "replace ^ with & in estimate_metric",
    ),
    _acceptance_mutant(
        "estimate_metric",
        "-> MetricEstimate",
        (2816, 1, 2992, 2),
        (2880, 25, 2880, 26),
        "",
        "UnaryOperator",
        "delete ! in estimate_metric",
    ),
    _acceptance_mutant(
        "estimate_metric",
        "-> MetricEstimate",
        (2816, 1, 2992, 2),
        (2911, 20, 2911, 22),
        "!=",
        "BinaryOperator",
        "replace == with != in estimate_metric",
    ),
    _acceptance_mutant(
        "estimate_metric",
        "-> MetricEstimate",
        (2816, 1, 2992, 2),
        (2928, 20, 2928, 22),
        "!=",
        "BinaryOperator",
        "replace == with != in estimate_metric",
    ),
    _acceptance_mutant(
        "summarize_condition",
        "-> ConditionSummary",
        (3118, 1, 3217, 2),
        (3122, 5, 3216, 6),
        "Default::default()",
        "FnValue",
        "replace summarize_condition -> ConditionSummary with Default::default()",
    ),
    _acceptance_mutant(
        "estimate_metric",
        "-> MetricEstimate",
        (2816, 1, 2992, 2),
        (2944, 20, 2944, 22),
        "!=",
        "BinaryOperator",
        "replace == with != in estimate_metric",
    ),
    _acceptance_mutant(
        "summarize_condition",
        "-> ConditionSummary",
        (3118, 1, 3217, 2),
        (3124, 35, 3124, 37),
        "!=",
        "BinaryOperator",
        "replace == with != in summarize_condition",
    ),
    _acceptance_mutant(
        "summarize_condition",
        "-> ConditionSummary",
        (3118, 1, 3217, 2),
        (3126, 47, 3126, 49),
        "!=",
        "BinaryOperator",
        "replace == with != in summarize_condition",
    ),
    _acceptance_mutant(
        "summarize_condition",
        "-> ConditionSummary",
        (3118, 1, 3217, 2),
        (3139, 53, 3139, 54),
        "%",
        "BinaryOperator",
        "replace / with % in summarize_condition",
    ),
    _acceptance_mutant(
        "summarize_condition",
        "-> ConditionSummary",
        (3118, 1, 3217, 2),
        (3139, 53, 3139, 54),
        "*",
        "BinaryOperator",
        "replace / with * in summarize_condition",
    ),
    _acceptance_mutant(
        "summarize_condition",
        "-> ConditionSummary",
        (3118, 1, 3217, 2),
        (3147, 30, 3147, 31),
        "",
        "UnaryOperator",
        "delete ! in summarize_condition",
    ),
    _acceptance_mutant(
        "build_summary",
        "-> EvidenceSummary",
        (3258, 1, 3306, 2),
        (3263, 5, 3305, 6),
        "Default::default()",
        "FnValue",
        "replace build_summary -> EvidenceSummary with Default::default()",
    ),
)
ACCEPTANCE_EVIDENCE_UNVIABLE_NAMES = frozenset(
    {
        "crates/galadriel-eval/src/evidence_main.rs:2822:5: replace "
        "estimate_metric -> MetricEstimate with Default::default()",
        "crates/galadriel-eval/src/evidence_main.rs:3122:5: replace "
        "summarize_condition -> ConditionSummary with Default::default()",
        "crates/galadriel-eval/src/evidence_main.rs:3263:5: replace "
        "build_summary -> EvidenceSummary with Default::default()",
    }
)
ACCEPTANCE_EVIDENCE_UNVIABLE_MUTANTS = tuple(
    mutant
    for mutant in ACCEPTANCE_EVIDENCE_MUTANTS
    if mutant.name in ACCEPTANCE_EVIDENCE_UNVIABLE_NAMES
)
if {
    mutant.name for mutant in ACCEPTANCE_EVIDENCE_UNVIABLE_MUTANTS
} != ACCEPTANCE_EVIDENCE_UNVIABLE_NAMES:
    raise RuntimeError("the frozen acceptance-evidence unviable set is incomplete")


MUTATION_LIVENESS_CHECKS = (
    {
        "id": "delivery-boundary-state",
        "kind": "direct-test",
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
        "kind": "direct-test",
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
    {
        "id": "acceptance-evidence-estimation",
        "kind": "acceptance-binary",
        "examine_re": (
            "interval_envelope|bootstrap_sample_is_sufficient|estimate_metric|"
            "summarize_condition|build_summary"
        ),
        "binary": "galadriel-evidence",
        "output": "mutants-acceptance-evidence",
        "required_mutants": ACCEPTANCE_EVIDENCE_MUTANTS,
        "unviable_mutants": ACCEPTANCE_EVIDENCE_UNVIABLE_MUTANTS,
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
        "--baseline",
        "run",
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
            MUTATION_JOBS,
            "--shard",
            shard_id,
            "--all-features",
            "--cargo-arg=--locked",
            "--copy-vcs",
            "true",
            "--colors",
            "never",
        )
    )
    return command


def focused_liveness_mutation_command(check: dict[str, Any]) -> list[str]:
    """Return one exact focused mutation command."""

    kind = check.get("kind")
    if kind == "direct-test":
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
            "--no-shuffle",
            "--baseline",
            "run",
            "--timeout",
            "120",
            "--jobs",
            MUTATION_JOBS,
            "--all-features",
            "--cargo-arg=--locked",
            "--copy-vcs",
            "true",
            "--colors",
            "never",
            "--output",
            str(check["output"]),
            "--",
            "--lib",
            str(check["test"]),
            "--",
            "--exact",
        ]
    if kind == "acceptance-binary":
        return [
            "cargo",
            "mutants",
            "--no-config",
            "--package",
            "galadriel-eval",
            "--file",
            ACCEPTANCE_MUTANT_FILE,
            "--re",
            str(check["examine_re"]),
            "--line-col",
            "true",
            "--no-shuffle",
            "--baseline",
            "run",
            "--timeout",
            "120",
            "--jobs",
            MUTATION_JOBS,
            "--all-features",
            "--cargo-arg=--locked",
            "--copy-vcs",
            "true",
            "--colors",
            "never",
            "--output",
            str(check["output"]),
            "--",
            "--bin",
            str(check["binary"]),
        ]
    raise ReviewError(f"unknown focused mutation check kind: {kind!r}")


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


def bounded_digest_file(path: Path, *, max_bytes: int, context: str) -> tuple[str, int]:
    """Hash one stable no-follow regular file within an exact byte bound."""

    document = read_bounded_regular_file(path, max_bytes=max_bytes, label=context)
    return sha256_bytes(document), len(document)


class MutationArtifactCapture(NamedTuple):
    """One canonical mutation artifact and its descriptor-rooted byte capture."""

    path: Path
    relative: str
    capture: RootedFileCapture


class ValidatedMutationEvidence(NamedTuple):
    """One validated mutation manifest, signature, and retained artifact set."""

    document: dict[str, Any]
    manifest: MutationArtifactCapture
    signature: MutationArtifactCapture
    artifacts: tuple[MutationArtifactCapture, ...]


def _mutation_artifact_path(root: Path, relative: str, *, context: str) -> Path:
    """Return one canonical lexical artifact path without following it."""

    parts = canonical_relative_parts(relative, label=f"{context} path")
    absolute_root = Path(os.path.abspath(os.fspath(root.expanduser())))
    return absolute_root.joinpath(*parts)


def _capture_mutation_artifact(
    root: Path,
    relative: str,
    *,
    max_bytes: int,
    context: str,
    expected_size: int | None = None,
) -> MutationArtifactCapture:
    """Capture one canonical mutation artifact from its declared root."""

    path = _mutation_artifact_path(root, relative, context=context)
    if expected_size is not None and expected_size > max_bytes:
        raise ReviewError(f"{context} exceeds its byte limit")
    capture = read_rooted_regular_file(
        root,
        relative,
        max_bytes=max_bytes,
        expected_size=expected_size,
        label=context,
    )
    return MutationArtifactCapture(
        path,
        relative,
        capture,
    )


def _load_mutation_json(
    document: bytes,
    *,
    max_depth: int,
    max_nodes: int,
    label: str,
) -> Any:
    """Decode and bound one JSON document from an authenticated byte capture."""

    try:
        value = loads_json(document)
        validate_json_structure(
            value,
            max_depth=max_depth,
            max_nodes=max_nodes,
            label=label,
        )
        return value
    except ReviewError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError, MemoryError) as error:
        raise ReviewError(f"cannot load {label}: {error}") from error


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
    if not key.is_file() or key.is_symlink():
        raise ReviewError(f"SSH signing key is unavailable: {key}")
    signature = Path(f"{document}.sig")
    if signature.exists():
        raise ReviewError(f"refusing to replace signature: {signature}")
    process = run_bounded_host_command(
        ["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", namespace, str(document)],
        context="SSH signing command",
        environment=_ssh_host_environment(use_agent=True),
    )
    if process.returncode != 0 or not signature.is_file():
        raise ReviewError(
            f"cannot sign {document.name} in namespace {namespace}: "
            f"command exited with {process.returncode}"
        )
    return signature


def _public_key_fields(document: bytes, context: str) -> tuple[str, str]:
    """Return one exact Ed25519 key from public OpenSSH text."""

    try:
        lines = document.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise ReviewError(f"{context} is not ASCII") from error
    if len(lines) != 1:
        raise ReviewError(f"{context} must contain exactly one line")
    fields = lines[0].split()
    if len(fields) not in {2, 3} or fields[0] != "ssh-ed25519":
        raise ReviewError(f"{context} must contain one Ed25519 public key")
    try:
        decoded = base64.b64decode(fields[1], validate=True)
    except ValueError as error:
        raise ReviewError(f"{context} has invalid public-key encoding") from error
    if len(decoded) < 32:
        raise ReviewError(f"{context} has an invalid Ed25519 public key")
    return fields[0], fields[1]


def snapshot_independent_allowed_signers(
    source: Path,
    destination: Path,
    *,
    max_bytes: int = MAX_ALLOWED_SIGNERS_BYTES,
) -> bytes:
    """Copy and validate an independently obtained signer allowlist."""

    document = read_bounded_regular_file(
        source,
        max_bytes=max_bytes,
        label="independent allowed-signers file",
    )
    try:
        lines = document.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise ReviewError("independent allowed-signers file is not ASCII") from error
    if len(lines) != 1:
        raise ReviewError(
            "independent allowed-signers file must contain exactly one line"
        )
    fields = lines[0].split()
    if len(fields) != 3 or fields[0] != SIGNING_PRINCIPAL:
        raise ReviewError(
            "independent allowed-signers file has the wrong principal or field count"
        )
    _public_key_fields(" ".join(fields[1:]).encode("ascii"), "allowed signer")
    canonical = f"{fields[0]} {fields[1]} {fields[2]}\n".encode("ascii")
    if document != canonical:
        raise ReviewError("independent allowed-signers file is not canonical")
    if destination.exists():
        raise ReviewError(f"refusing to replace external trust root: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(canonical)
    os.chmod(destination, 0o600)
    return canonical


def require_agent_backed_public_signing_key(signing_key: Path) -> bytes:
    """Require an agent-backed public handle and return canonical signer metadata."""

    document = read_bounded_regular_file(
        signing_key,
        max_bytes=MAX_SIGNING_HANDLE_BYTES,
        label="agent-backed signing-key handle",
    )
    key_type, encoded = _public_key_fields(document.strip(), "signing-key handle")
    process = run_bounded_host_command(
        ["ssh-add", "-L"],
        context="SSH agent key inspection",
        environment=_ssh_host_environment(use_agent=True),
    )
    if process.returncode != 0:
        raise ReviewError(
            "cannot inspect ssh-agent signing keys: "
            f"command exited with {process.returncode}"
        )
    agent_keys: set[tuple[str, str]] = set()
    for line in process.stdout.splitlines():
        try:
            agent_keys.add(_public_key_fields(line, "ssh-agent public key"))
        except ReviewError:
            continue
    if (key_type, encoded) not in agent_keys:
        raise ReviewError("the signing-key public handle is not available in ssh-agent")
    return f"{SIGNING_PRINCIPAL} {key_type} {encoded}\n".encode("ascii")


def snapshot_agent_backed_public_signing_key(
    source: Path,
    destination: Path,
) -> tuple[Path, bytes]:
    """Validate one public handle and snapshot only its canonical public fields."""

    signer_metadata = require_agent_backed_public_signing_key(source)
    fields = signer_metadata.split()
    if len(fields) != 3:
        raise ReviewError("agent-backed signing metadata is malformed")
    public_handle = b" ".join(fields[1:]) + b"\n"
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("xb") as handle:
            handle.write(public_handle)
    except FileExistsError as error:
        raise ReviewError(
            f"refusing to replace signing-key public snapshot: {destination}"
        ) from error
    os.chmod(destination, 0o600)
    return destination, signer_metadata


def derive_external_allowed_signers(signing_key: Path, destination: Path) -> bytes:
    """Derive a canonical trust root from one external Ed25519 public handle."""

    document = read_bounded_regular_file(
        signing_key,
        max_bytes=MAX_SIGNING_HANDLE_BYTES,
        label="external signing-key public handle",
    )
    key_type, encoded = _public_key_fields(
        document.strip(),
        "external signing-key public handle",
    )
    retained = f"{SIGNING_PRINCIPAL} {key_type} {encoded}\n".encode("ascii")
    if destination.exists():
        raise ReviewError(f"refusing to replace external trust root: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(retained)
    os.chmod(destination, 0o600)
    return retained


def assert_tracked_allowed_signer(path: Path, expected: bytes) -> None:
    """Require byte-identical candidate signer metadata, never use it as trust root."""

    actual = read_bounded_regular_file(
        path,
        max_bytes=MAX_ALLOWED_SIGNERS_BYTES,
        label="candidate tracked allowed-signers metadata",
    )
    if actual != expected:
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
    document_bytes = read_bounded_regular_file(
        document,
        max_bytes=MAX_SIGNED_DOCUMENT_BYTES,
        label="signed document",
    )
    signature_bytes = read_bounded_regular_file(
        signature,
        max_bytes=MAX_SIGNATURE_BYTES,
        label="detached signature",
    )
    allowed_signers_bytes = read_bounded_regular_file(
        allowed_signers,
        max_bytes=MAX_ALLOWED_SIGNERS_BYTES,
        label="allowed-signers trust root",
    )
    with tempfile.TemporaryDirectory(
        prefix="galadriel-signature-verification-"
    ) as name:
        root = Path(name)
        signature_snapshot = root / "signature"
        allowed_signers_snapshot = root / "allowed-signers"
        signature_snapshot.write_bytes(signature_bytes)
        allowed_signers_snapshot.write_bytes(allowed_signers_bytes)
        os.chmod(signature_snapshot, 0o600)
        os.chmod(allowed_signers_snapshot, 0o600)
        process = run_bounded_host_command(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(allowed_signers_snapshot),
                "-I",
                principal,
                "-n",
                namespace,
                "-s",
                str(signature_snapshot),
            ],
            context="SSH signature verification",
            stdin_document=document_bytes,
            environment=_ssh_host_environment(use_agent=False),
        )
    if process.returncode != 0:
        raise ReviewError(
            f"invalid {namespace} signature for {document.name}: "
            f"command exited with {process.returncode}"
        )


def verify_candidate_commit(repo: Path, commit: str, allowed_signers: Path) -> str:
    if not GIT_OBJECT.fullmatch(commit):
        raise ReviewError("candidate commit must be a full lowercase Git object")
    _reject_unsafe_local_git_configuration(repo)
    assert_no_replace_refs(repo)
    resolved = str(
        git(
            repo,
            "rev-parse",
            "--verify",
            f"{commit}^{{commit}}",
            max_bytes=64,
        )
    ).strip()
    if resolved != commit:
        raise ReviewError(f"candidate commit resolves differently: {resolved}")
    identities = (
        str(
            git(
                repo,
                "-c",
                "log.showSignature=false",
                "show",
                "-s",
                "--format=%an%x00%ae%x00%cn%x00%ce",
                commit,
                max_bytes=MAX_GIT_IDENTITY_BYTES,
            )
        )
        .rstrip("\n")
        .split("\0")
    )
    expected_identities = [AUTHOR, AUTHOR_EMAIL, AUTHOR, AUTHOR_EMAIL]
    if identities != expected_identities:
        raise ReviewError(
            "candidate author and committer identities must both equal "
            f"{AUTHOR} <{AUTHOR_EMAIL}>"
        )
    with tempfile.TemporaryDirectory(prefix="galadriel-commit-verification-") as name:
        allowed_signers_snapshot = Path(name) / "allowed-signers"
        snapshot_independent_allowed_signers(allowed_signers, allowed_signers_snapshot)
        ssh_keygen = trusted_host_executable_path("ssh-keygen")
        process = run_bounded_host_command(
            [
                "git",
                "--no-replace-objects",
                "--literal-pathspecs",
                *SAFE_GIT_CONFIGURATION,
                "-C",
                str(repo),
                "-c",
                "gpg.format=ssh",
                "-c",
                f"gpg.ssh.allowedSignersFile={allowed_signers_snapshot}",
                "-c",
                f"gpg.ssh.program={ssh_keygen}",
                "verify-commit",
                commit,
            ],
            context="candidate commit signature verification",
            environment=safe_git_environment(),
            trusted_auxiliary_executables=("ssh-keygen",),
        )
    if process.returncode != 0:
        raise ReviewError(
            "candidate commit lacks the required signature: "
            f"command exited with {process.returncode}"
        )
    tree = str(
        git(
            repo,
            "rev-parse",
            "--verify",
            f"{commit}^{{tree}}",
            max_bytes=64,
        )
    ).strip()
    assert_no_replace_refs(repo)
    return tree


def canonical_repository_identity(repo: Path) -> str:
    """Require exact canonical fetch and push endpoints for the origin remote."""

    accepted = {
        "git@github.com:sepahead/galadriel.git",
        "ssh://git@github.com/sepahead/galadriel.git",
        "https://github.com/sepahead/galadriel.git",
        "https://github.com/sepahead/galadriel",
    }

    for arguments in (
        ("remote", "get-url", "--all", "origin"),
        ("remote", "get-url", "--push", "--all", "origin"),
    ):
        raw_endpoint = str(
            git(
                repo,
                *arguments,
                max_bytes=MAX_GIT_IDENTITY_BYTES,
            )
        )
        if not raw_endpoint.endswith("\n") or raw_endpoint.count("\n") != 1:
            raise ReviewError(
                "candidate origin is not the canonical credential-free repository"
            )
        endpoint = raw_endpoint[:-1]
        if endpoint not in accepted or any(
            ord(character) < 0x20 for character in endpoint
        ):
            raise ReviewError(
                "candidate origin is not the canonical credential-free repository"
            )
    return CANONICAL_REPOSITORY


def _reject_unsafe_local_git_configuration(repo: Path) -> None:
    """Reject local configuration that can alter a release Git operation."""

    raw = bytes(
        git(
            repo,
            "config",
            "--local",
            "--no-includes",
            "--null",
            "--name-only",
            "--list",
            text=False,
            max_bytes=MAX_GIT_IDENTITY_BYTES,
        )
    )
    try:
        names = [
            item.decode("utf-8", "strict").casefold()
            for item in raw.split(b"\0")
            if item
        ]
    except UnicodeDecodeError as error:
        raise ReviewError(
            "candidate local Git configuration is not valid UTF-8"
        ) from error
    unsafe = any(
        name.startswith(
            (
                "credential.",
                "extensions.",
                "gpg.",
                "http.",
                "https.",
                "include.",
                "includeif.",
                "protocol.",
                "url.",
            )
        )
        or name
        in {
            "core.alternaterefscommand",
            "core.askpass",
            "core.gitproxy",
            "core.sshcommand",
            "core.worktree",
            "gc.recentobjectshook",
        }
        or name.startswith("fetch.fsck.")
        or (
            name.startswith("remote.")
            and name
            not in {
                "remote.origin.fetch",
                "remote.origin.pushurl",
                "remote.origin.url",
            }
        )
        for name in names
    )
    if unsafe:
        raise ReviewError(
            "candidate local Git configuration can alter a release Git operation"
        )


def refresh_canonical_origin_main(repo: Path, commit: str) -> tuple[str, str]:
    """Fetch canonical public main and require it to equal one exact candidate."""

    _reject_unsafe_local_git_configuration(repo)
    repository = canonical_repository_identity(repo)
    assert_no_replace_refs(repo)
    git(
        repo,
        "-c",
        "credential.helper=",
        "-c",
        "credential.interactive=never",
        "-c",
        "core.askPass=",
        "-c",
        "fetch.fsckObjects=true",
        "-c",
        "transfer.fsckObjects=true",
        "fetch",
        "--quiet",
        "--no-tags",
        "--no-recurse-submodules",
        "--no-auto-maintenance",
        "--no-prune",
        "--no-prune-tags",
        "--no-write-commit-graph",
        "--show-forced-updates",
        "--no-write-fetch-head",
        CANONICAL_FETCH_URL,
        CANONICAL_MAIN_REFSPEC,
        max_bytes=0,
        timeout_seconds=600,
    )
    assert_no_replace_refs(repo)
    return repository, require_origin_main_candidate(repo, commit)


def require_origin_main_candidate(repo: Path, commit: str) -> str:
    """Require the exact candidate at the local origin/main tracking ref."""

    if not GIT_OBJECT.fullmatch(commit):
        raise ReviewError("candidate commit must be a full lowercase Git object")
    assert_no_replace_refs(repo)
    try:
        origin_main = str(
            git(
                repo,
                "rev-parse",
                "--verify",
                "refs/remotes/origin/main^{commit}",
                max_bytes=64,
            )
        ).strip()
    except ReviewError as error:
        raise ReviewError(
            "origin/main does not identify an available commit"
        ) from error
    if origin_main != commit:
        raise ReviewError("origin/main does not identify the exact candidate")
    assert_no_replace_refs(repo)
    return origin_main


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


def _is_finite_f64_number(value: Any) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        converted = float(value)
    except (OverflowError, TypeError, ValueError):
        return False
    return math.isfinite(converted)


def _metric_observation(
    criterion: str,
    row: dict[str, Any],
    metric_name: str,
    minimum_eligible: int,
    comparison: str,
    threshold: float,
) -> dict[str, Any]:
    metric_domain = ACCEPTANCE_METRIC_DOMAINS.get(metric_name)
    if metric_domain is None:
        raise ReviewError(
            f"internal acceptance metric domain is missing: {metric_name}"
        )
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
        or not all(_is_finite_f64_number(bound) for bound in ci)
        or ci[0] > ci[1]
    ):
        raise ReviewError(
            f"{criterion}: {metric_name} lacks a finite ordered 95% interval"
        )
    value = metric.get("value")
    if not _is_finite_f64_number(value):
        raise ReviewError(f"{criterion}: {metric_name} lacks a finite point estimate")
    if not ci[0] <= value <= ci[1]:
        raise ReviewError(
            f"{criterion}: {metric_name} estimate lies outside its interval"
        )
    domain_values = (ci[0], value, ci[1])
    if not all(candidate >= 0.0 for candidate in domain_values):
        raise ReviewError(
            f"{criterion}: {metric_name} {metric_domain} estimate or interval "
            "contains a negative value"
        )
    if metric_domain == "probability" and not all(
        candidate <= 1.0 for candidate in domain_values
    ):
        raise ReviewError(
            f"{criterion}: {metric_name} probability estimate or interval "
            "lies outside [0, 1]"
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
                (
                    row,
                    "conditional_detection_probability",
                    "lower_ge",
                    0.90,
                )
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
                (
                    row,
                    "conditional_attribution_error",
                    "upper_le",
                    0.10,
                )
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
                    criterion_id,
                    row,
                    metric,
                    minimum,
                    comparison,
                    threshold,
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


def _bounded_evidence_object(payload: bytes, label: str) -> dict[str, Any]:
    """Parse one bounded evidence object with strict JSON rules."""

    if (
        not isinstance(payload, bytes)
        or not payload
        or len(payload) > MAX_EVIDENCE_DOCUMENT_BYTES
    ):
        raise ReviewError(f"{label} has an invalid byte length")
    try:
        value = loads_json(payload)
        validate_json_structure(
            value,
            max_depth=MAX_EVIDENCE_JSON_DEPTH,
            max_nodes=MAX_EVIDENCE_JSON_NODES,
            label=label,
        )
    except (
        MemoryError,
        RecursionError,
        ReviewError,
        UnicodeError,
        ValueError,
    ) as error:
        raise ReviewError(f"{label} is invalid: {error}") from error
    if not isinstance(value, dict):
        raise ReviewError(f"{label} is not a JSON object")
    return value


def _require_exact_json_value(supplied: Any, expected: Any, label: str) -> None:
    """Require recursive JSON equality without Boolean or numeric coercion."""

    if isinstance(expected, dict):
        if not isinstance(supplied, dict) or set(supplied) != set(expected):
            raise ReviewError(f"{label} has another object field set")
        for key, value in expected.items():
            _require_exact_json_value(supplied[key], value, f"{label}.{key}")
        return
    if isinstance(expected, list):
        if not isinstance(supplied, list) or len(supplied) != len(expected):
            raise ReviewError(f"{label} has another list shape")
        for index, value in enumerate(expected):
            _require_exact_json_value(supplied[index], value, f"{label}[{index}]")
        return
    if isinstance(expected, float):
        if type(supplied) is not float or _float_bits(supplied) != _float_bits(expected):
            raise ReviewError(f"{label} has another binary64 value")
        return
    if type(supplied) is not type(expected) or supplied != expected:
        raise ReviewError(f"{label} has another JSON value")


def _accepted_evidence_config_from_source(source: dict[str, Any]) -> dict[str, Any]:
    """Derive the exact accepted v0.9 evidence configuration object."""

    seed_text = source["base_seed"]
    seed = int(seed_text)
    expected = {
        **{field: source[field] for field in EVIDENCE_DIRECT_CONFIG_FIELDS},
        "accepted_profile": EVIDENCE_ACCEPTED_PROFILE,
        "base_seed": seed_text,
        "base_seed_decimal": seed_text,
        "base_seed_hex": f"0x{seed:016x}",
        "canonical_digest": None,
        "classification": "custom_research_evidence",
        "detector": {
            "accepted_profile": "custom_evidence_input",
            **source["detector"],
        },
        "correlation": {
            "accepted_profile": "custom_evidence_input",
            "axis_family_count": 1,
            **source["correlation"],
        },
        "recorded_fixture": {
            **source["recorded_fixture"],
            "bytes": EVIDENCE_FIXTURE_BYTES,
        },
        "runner_contract": {
            "trial_schema": EVIDENCE_TRIAL_SCHEMA,
            "summary_schema": EVIDENCE_SUMMARY_SCHEMA,
            "manifest_schema": EVIDENCE_MANIFEST_SCHEMA,
            "generator_profile": EVIDENCE_GENERATOR_PROFILE,
            "recorded_replay_profile": EVIDENCE_REPLAY_PROFILE,
            "missingness_profile": EVIDENCE_MISSINGNESS_PROFILE,
            "acceptance_metric_profile": EVIDENCE_ACCEPTANCE_PROFILE,
            "bootstrap_profile": EVIDENCE_BOOTSTRAP_PROFILE,
            "delay_p95_definition": "nearest_rank_empirical_p95_milliseconds",
            "attribution_error_definition": (
                "wrong_first_emitted_attribution_after_onset_over_emitted_attributions"
            ),
        },
        "release_suite": {
            "accepted_profile": "custom_evidence_input",
            "identity": EVIDENCE_RELEASE_SUITE_IDENTITY,
            "expected_modalities": ["visual", "acoustic", "radar"],
            "axis_policy": "attested_common_projection_bonferroni_v1",
            "lifecycle_sample_units": 393_216,
            "state_bytes": 9_538_560,
        },
        "preflight_estimate": {
            "synthetic_tracks": 980,
            "synthetic_trial_records": 1_960,
            "generated_observations": 10_584_000,
            "trace_assessments": 705_600,
            "correlation_sample_products": 406_425_600,
            "bootstrap_track_draws": 15_680_000,
            "maximum_synthetic_generation_resets": 216_000,
        },
        "recorded_preflight_estimate": {
            "tracks": 1,
            "trial_records": 2,
            "observations": 476,
            "trace_assessments": 32,
            "correlation_sample_products": 18_432,
            "maximum_generation_resets": 158,
        },
        "resource_ceilings": {
            "generated_observations": 25_000_000,
            "correlation_sample_products": 500_000_000,
            "trace_assessments": 2_000_000,
            "bootstrap_track_draws": 50_000_000,
            "synthetic_generation_resets": 1_000_000,
        },
    }
    digest_bytes = json.dumps(
        expected,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    expected["canonical_digest"] = hashlib.sha256(
        EVIDENCE_CONFIG_DOMAIN + digest_bytes
    ).hexdigest()
    return expected


def validate_evidence_config_bytes(
    tracked_config_bytes: bytes,
    accepted_config_bytes: bytes,
    evidence_manifest_bytes: bytes,
    *,
    tracked_relative_path: str,
) -> dict[str, Any]:
    """Bind the complete accepted configuration to the preregistered input."""

    source = _bounded_evidence_object(
        tracked_config_bytes,
        "tracked candidate evidence config",
    )
    accepted = _bounded_evidence_object(
        accepted_config_bytes,
        "accepted candidate evidence config",
    )
    manifest = _bounded_evidence_object(
        evidence_manifest_bytes,
        "candidate evidence manifest",
    )
    source_sha = hashlib.sha256(tracked_config_bytes).hexdigest()
    source_size = len(tracked_config_bytes)
    accepted_sha = hashlib.sha256(accepted_config_bytes).hexdigest()
    if source_sha != EVIDENCE_SOURCE_CONFIG_SHA256:
        raise ReviewError("tracked candidate evidence config is not the frozen input")
    inputs = manifest.get("inputs")
    if not isinstance(inputs, dict):
        raise ReviewError("candidate evidence manifest lacks input provenance")
    if inputs.get("config_source_path") != tracked_relative_path:
        raise ReviewError("candidate evidence manifest targets another config path")
    if inputs.get("config_source_sha256") != source_sha:
        raise ReviewError("candidate evidence source-config blob digest mismatch")
    if inputs.get("canonical_config_sha256") != accepted_sha:
        raise ReviewError("candidate evidence accepted-config byte digest mismatch")
    if set(source) != EVIDENCE_DIRECT_CONFIG_FIELDS | {
        "detector",
        "correlation",
        "recorded_fixture",
    }:
        raise ReviewError(
            "tracked candidate evidence config has an unexpected field set"
        )
    require_keys(
        source.get("detector"),
        {
            "window_len",
            "min_samples",
            "min_channels",
            "max_seq_gap",
            "max_timestamp_skew_ms",
            "max_inter_sample_gap_ms",
            "max_tracks",
            "nis_alpha",
            "cusum_slack",
            "cusum_threshold",
            "jam_fraction",
        },
        "tracked candidate detector config",
    )
    require_keys(
        source.get("correlation"),
        {
            "window",
            "min_samples",
            "decouple_ratio",
            "corr_floor",
            "family_alpha",
        },
        "tracked candidate correlation config",
    )
    require_keys(
        source.get("recorded_fixture"),
        {"path", "sha256"},
        "tracked candidate fixture config",
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

    seed_text = source.get("base_seed")
    if not isinstance(seed_text, str) or not seed_text.isascii() or not seed_text.isdigit():
        raise ReviewError("tracked candidate base seed is not exact decimal text")
    seed = int(seed_text)
    if seed > 2**64 - 1:
        raise ReviewError("tracked candidate base seed exceeds u64")
    expected_accepted = _accepted_evidence_config_from_source(source)
    canonical_digest = expected_accepted["canonical_digest"]
    try:
        _require_exact_json_value(
            accepted,
            expected_accepted,
            "accepted candidate evidence config",
        )
    except ReviewError as error:
        raise ReviewError(
            "accepted candidate evidence config is not the exact derived object"
        ) from error
    if manifest.get("accepted_config_digest") != canonical_digest:
        raise ReviewError("candidate evidence semantic config digest mismatch")
    return {
        "tracked_path": tracked_relative_path,
        "tracked_blob_sha256": source_sha,
        "tracked_bytes": source_size,
        "accepted_config_sha256": accepted_sha,
        "accepted_semantic_digest": canonical_digest,
        "study_design_status": "PASS",
    }


def validate_evidence_config_binding(
    tracked_config_path: Path,
    evidence_output: Path,
    *,
    tracked_relative_path: str,
) -> dict[str, Any]:
    """Bind accepted evidence output to the tracked preregistered input."""

    tracked_config_bytes = read_bounded_regular_file(
        tracked_config_path,
        max_bytes=MAX_EVIDENCE_DOCUMENT_BYTES,
        label="tracked candidate evidence config",
    )
    accepted_config_bytes = read_bounded_regular_file(
        evidence_output / "config.json",
        max_bytes=MAX_EVIDENCE_DOCUMENT_BYTES,
        label="accepted candidate evidence config",
    )
    evidence_manifest_bytes = read_bounded_regular_file(
        evidence_output / "manifest.json",
        max_bytes=MAX_EVIDENCE_DOCUMENT_BYTES,
        label="candidate evidence manifest",
    )
    return validate_evidence_config_bytes(
        tracked_config_bytes,
        accepted_config_bytes,
        evidence_manifest_bytes,
        tracked_relative_path=tracked_relative_path,
    )


class CandidateEvidenceExpectations(NamedTuple):
    """Independent identities for one candidate-evidence bundle."""

    commit: str
    tree: str
    tracked_config_path: str
    tracked_config_bytes: bytes
    workspace_manifest_sha256: str
    cargo_lock_sha256: str
    runner_binary_sha256: str
    rustc_verbose: str
    cargo_version: str
    target_os: str
    target_arch: str


class ValidatedCandidateEvidence(NamedTuple):
    """Trusted semantic result from one complete evidence bundle."""

    artifacts: dict[str, dict[str, Any]]
    config_binding: dict[str, Any]
    manifest: dict[str, Any]
    summary: dict[str, Any]
    acceptance: dict[str, Any]
    semantic_sha256: str


EVIDENCE_TRIAL_FIELDS = {
    "schema",
    "study_id",
    "condition",
    "experiment_kind",
    "role",
    "source",
    "source_profile",
    "trial_index",
    "seed",
    "seed_hex",
    "track_id",
    "track_id_hex",
    "detector",
    "modalities",
    "truth",
    "phi",
    "covariance_scale",
    "ordinary_missing_probability",
    "frame_count",
    "duration_ms",
    "assessment_step_frames",
    "alert_episode_reset_policy",
    "assessments",
    "alert_episode_count",
    "mission_alert",
    "first_alert_assessment",
    "pre_onset_alert",
    "first_post_onset_delay_frames",
    "first_post_onset_delay_ms",
    "attribution_emitted",
    "attribution_correct",
    "insufficient_assessments",
    "rejected_input_assessments",
    "abstention_assessments",
    "abstention_fraction",
    "startup_assessments",
    "startup_abstention_assessments",
    "startup_abstention_fraction",
    "monitoring_assessments",
    "monitoring_abstention_assessments",
    "monitoring_abstention_fraction",
    "realized_modality_counts",
    "detector_generation_resets",
    "consistency",
    "evidence_status",
    "status_reasons",
    "alert_episodes",
    "trace",
}
EVIDENCE_METRIC_NAMES = (
    "false_alerts_per_hour",
    "mission_probability_any_alert",
    "arl0_assessments",
    "arl0_censoring_fraction",
    "abstention_fraction",
    "any_alert_probability",
    "pre_onset_alert_probability",
    "conditional_detection_probability",
    "conditional_delay_frames",
    "conditional_delay_p95_ms",
    "conditional_attribution_coverage",
    "conditional_attribution_accuracy",
    "conditional_attribution_error",
)
EVIDENCE_MODALITY_ORDER = {
    "visual": 0,
    "thermal": 1,
    "acoustic": 2,
    "radar": 3,
    "lidar": 4,
    "radio_frequency": 5,
}


def _evidence_integer(
    value: Any,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = 2**64 - 1,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise ReviewError(f"{label} is outside its integer domain")
    return value


def _evidence_float(value: Any, label: str) -> float:
    if not _is_finite_f64_number(value):
        raise ReviewError(f"{label} is not a finite binary64 value")
    result = float(value)
    if result == 0.0 and math.copysign(1.0, result) < 0.0:
        raise ReviewError(f"{label} uses negative zero")
    return result


def _optional_integer(value: Any, label: str) -> int | None:
    return None if value is None else _evidence_integer(value, label)


def _optional_boolean(value: Any, label: str) -> bool | None:
    if value is not None and not isinstance(value, bool):
        raise ReviewError(f"{label} is not Boolean or null")
    return value


def _optional_float(value: Any, label: str) -> float | None:
    return None if value is None else _evidence_float(value, label)


def _float_bits(value: float) -> int:
    return struct.unpack(">Q", struct.pack(">d", value))[0]


def _same_float(left: Any, right: float) -> bool:
    return _is_finite_f64_number(left) and _float_bits(float(left)) == _float_bits(right)


def _fnv1a64(value: str) -> int:
    result = 0xCBF2_9CE4_8422_2325
    for byte in value.encode("utf-8"):
        result = ((result ^ byte) * 0x0000_0100_0000_01B3) & 0xFFFF_FFFF_FFFF_FFFF
    return result


def _mix64(value: int) -> int:
    value &= 0xFFFF_FFFF_FFFF_FFFF
    value = ((value ^ (value >> 30)) * 0xBF58_476D_1CE4_E5B9) & 0xFFFF_FFFF_FFFF_FFFF
    value = ((value ^ (value >> 27)) * 0x94D0_49BB_1331_11EB) & 0xFFFF_FFFF_FFFF_FFFF
    return value ^ (value >> 31)


def _evidence_float_id(value: float) -> str:
    normalized = 0.0 if value == 0.0 else value
    human = f"{normalized:.6f}".replace("-", "m").replace(".", "p")
    return f"{human}_{_float_bits(value):016x}"


def _synthetic_conditions(config: dict[str, Any]) -> list[dict[str, Any]]:
    conditions: list[dict[str, Any]] = []
    for phi in config["autocorrelation_phis"]:
        conditions.append(
            {
                "condition": f"clean_autocorrelation_phi_{_evidence_float_id(phi)}",
                "experiment_kind": "clean_autocorrelation",
                "phi": phi,
                "covariance_scale": 1.0,
                "ordinary_missing_probability": 0.0,
                "truth_class": "clean",
                "truth_channels": [],
                "onset_frame": None,
                "expected_abstention": False,
                "calibration": True,
            }
        )
    for scale in config["covariance_scales"]:
        if scale == 1.0:
            continue
        conditions.append(
            {
                "condition": f"clean_covariance_scale_{_evidence_float_id(scale)}",
                "experiment_kind": "clean_covariance_sensitivity",
                "phi": 0.0,
                "covariance_scale": scale,
                "ordinary_missing_probability": 0.0,
                "truth_class": "clean",
                "truth_channels": [],
                "onset_frame": None,
                "expected_abstention": False,
                "calibration": True,
            }
        )
    conditions.append(
        {
            "condition": "clean_ordinary_missingness",
            "experiment_kind": "ordinary_missingness",
            "phi": 0.0,
            "covariance_scale": 1.0,
            "ordinary_missing_probability": config["ordinary_missing_probability"],
            "truth_class": "clean",
            "truth_channels": [],
            "onset_frame": None,
            "expected_abstention": False,
            "calibration": True,
        }
    )
    conditions.extend(
        [
            {
                "condition": "attack_loud_acoustic",
                "experiment_kind": "targeted_attack",
                "truth_class": "attributed_inconsistency",
                "truth_channels": ["acoustic"],
            },
            {
                "condition": "attack_stealthy_acoustic",
                "experiment_kind": "targeted_attack",
                "truth_class": "attributed_inconsistency",
                "truth_channels": ["acoustic"],
            },
            {
                "condition": "attack_broad_degradation",
                "experiment_kind": "broad_degradation_attack",
                "truth_class": "broad_degradation",
                "truth_channels": [],
            },
            {
                "condition": "provenance_missing_projection",
                "experiment_kind": "provenance_abstention",
                "truth_class": "clean_invalid_or_missing_provenance",
                "truth_channels": [],
                "expected_abstention": True,
                "onset_frame": None,
            },
            {
                "condition": "provenance_invalid_prior",
                "experiment_kind": "provenance_abstention",
                "truth_class": "clean_invalid_or_missing_provenance",
                "truth_channels": [],
                "expected_abstention": True,
                "onset_frame": None,
            },
        ]
    )
    for condition in conditions:
        condition.setdefault("phi", 0.0)
        condition.setdefault("covariance_scale", 1.0)
        condition.setdefault("ordinary_missing_probability", 0.0)
        condition.setdefault("onset_frame", config["attack_onset_frame"])
        condition.setdefault("expected_abstention", False)
        condition.setdefault("calibration", False)
    return conditions


def _expected_trial_layout(config: dict[str, Any]) -> list[dict[str, Any]]:
    layout: list[dict[str, Any]] = []
    base_seed = int(config["base_seed"])
    role_domains = {
        "calibration": 0xCA11_BA7E_0000_0001,
        "holdout": 0xC1EA_110D_0000_0002,
    }
    for condition in _synthetic_conditions(config):
        roles = (
            (("calibration", config["calibration_tracks"]), ("holdout", config["holdout_tracks"]))
            if condition["calibration"]
            else (("holdout", config["holdout_tracks"]),)
        )
        for role, count in roles:
            for trial_index in range(count):
                seed = _mix64(
                    base_seed
                    ^ _fnv1a64(condition["condition"])
                    ^ role_domains[role]
                    ^ ((trial_index * 0x9E37_79B9_7F4A_7C15) & 0xFFFF_FFFF_FFFF_FFFF)
                )
                track_id = _mix64(seed ^ 0x7A6B_1D3E_51C9_4F02) % 9_007_199_254_740_991 + 1
                for detector in ("nis_baseline", "default_correlation_fusion"):
                    layout.append(
                        {
                            **condition,
                            "role": role,
                            "trial_index": trial_index,
                            "seed": seed,
                            "track_id": track_id,
                            "detector": detector,
                            "source": "synthetic",
                        }
                    )
    for detector in ("nis_baseline", "default_correlation_fusion"):
        layout.append(
            {
                "condition": "recorded_crebain_clean",
                "experiment_kind": "recorded_smoke",
                "role": "recorded_holdout",
                "trial_index": 0,
                "seed": None,
                "track_id": 1,
                "detector": detector,
                "source": "recorded",
                "truth_class": "clean_invalid_or_missing_provenance",
                "truth_channels": [],
                "onset_frame": None,
                "expected_abstention": detector == "default_correlation_fusion",
                "phi": None,
                "covariance_scale": None,
                "ordinary_missing_probability": None,
            }
        )
    return layout


def _require_evidence_keys(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    """Require one exact evidence object field set."""

    require_keys(value, fields, label)
    return value


def _evidence_string_list(
    value: Any,
    label: str,
    *,
    unique: bool = False,
) -> list[str]:
    """Validate one bounded list of evidence strings."""

    if not isinstance(value, list) or len(value) > 10_000:
        raise ReviewError(f"{label} is not a bounded list")
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item or len(item.encode("utf-8")) > 4_096:
            raise ReviewError(f"{label} item {index} is invalid")
        result.append(item)
    if unique and len(set(result)) != len(result):
        raise ReviewError(f"{label} contains a duplicate value")
    return result


def _validate_modality_channels(value: Any, label: str) -> list[str]:
    """Require unique modalities in stable canonical order."""

    channels = _evidence_string_list(value, label, unique=True)
    try:
        orders = [EVIDENCE_MODALITY_ORDER[channel] for channel in channels]
    except KeyError as error:
        raise ReviewError(f"{label} contains an unknown modality") from error
    if orders != sorted(orders):
        raise ReviewError(f"{label} is not in stable modality order")
    return channels


def _deterministic_acoustic_missing(seed: int, frame: int, probability: float) -> bool:
    """Replay the declared deterministic acoustic-missingness predicate."""

    if probability <= 0.0:
        return False
    bits = _mix64(
        seed
        ^ ((frame * 0xD1B5_4A32_D192_ED03) & 0xFFFF_FFFF_FFFF_FFFF)
        ^ EVIDENCE_MODALITY_ORDER["acoustic"]
    )
    return (bits >> 11) / float(1 << 53) < probability


def _expected_synthetic_observation_shape(
    expected: dict[str, Any],
    config: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Derive modality counts and reset records without detector output."""

    frames = config["frames"]
    missing_probability = expected["ordinary_missing_probability"]
    acoustic_present = [
        not _deterministic_acoustic_missing(
            expected["seed"],
            frame,
            missing_probability,
        )
        for frame in range(frames)
    ]
    acoustic_observations = sum(acoustic_present)
    realized = [
        {"modality": "visual", "observations": frames, "missing_frames": 0},
        {"modality": "radar", "observations": frames, "missing_frames": 0},
        {
            "modality": "acoustic",
            "observations": acoustic_observations,
            "missing_frames": frames - acoustic_observations,
        },
    ]
    resets: list[dict[str, Any]] = []
    last_acoustic: int | None = None
    for frame, present in enumerate(acoustic_present):
        if not present:
            continue
        if (
            last_acoustic is not None
            and frame - last_acoustic > config["detector"]["max_seq_gap"]
        ):
            resets.append(
                {
                    "frame_index": frame,
                    "seq": frame,
                    "timestamp_ms": frame * config["dt_ms"],
                    "reason": "sequence_or_timestamp_discontinuity",
                }
            )
        last_acoustic = frame
    return realized, resets


def _validate_trace_label(value: Any, label: str) -> dict[str, Any]:
    """Validate one trace label and its state semantics."""

    item = _require_evidence_keys(
        value,
        {"state", "classification", "channels"},
        label,
    )
    state = item["state"]
    classification = item["classification"]
    if not isinstance(state, str) or not isinstance(classification, str):
        raise ReviewError(f"{label} state fields are invalid")
    channels = _validate_modality_channels(item["channels"], f"{label} channels")
    fixed = {
        "nominal": ("nominal", []),
        "insufficient_evidence": ("insufficient_evidence", []),
        "rejected_input": ("invalid_consistency_input", []),
    }
    if state in fixed:
        if (classification, channels) != fixed[state]:
            raise ReviewError(f"{label} contradicts its non-alert state")
    elif state == "alert":
        if classification not in {
            "attributed_inconsistency",
            "broad_degradation",
            "unclassified_anomaly",
        }:
            raise ReviewError(f"{label} has an unknown alert classification")
        if classification == "broad_degradation" and channels:
            raise ReviewError(f"{label} broad-degradation channels are not empty")
        if classification == "attributed_inconsistency" and not channels:
            raise ReviewError(f"{label} attributed alert has no channel")
    else:
        raise ReviewError(f"{label} has an unknown state")
    return {"state": state, "classification": classification, "channels": channels}


def _expected_assessment_frame(
    assessment: int,
    *,
    step: int,
    frame_count: int,
) -> int:
    return min(assessment * step - 1, frame_count - 1)


def _validate_trial_record(
    value: Any,
    expected: dict[str, Any],
    config: dict[str, Any],
    *,
    record_index: int,
) -> dict[str, Any]:
    """Validate one trial and return its trusted compact projection."""

    label = f"candidate evidence trial {record_index}"
    record = _require_evidence_keys(value, EVIDENCE_TRIAL_FIELDS, label)
    exact = {
        "schema": EVIDENCE_TRIAL_SCHEMA,
        "study_id": config["study_id"],
        "condition": expected["condition"],
        "experiment_kind": expected["experiment_kind"],
        "role": expected["role"],
        "source": expected["source"],
        "source_profile": (
            EVIDENCE_GENERATOR_PROFILE
            if expected["source"] == "synthetic"
            else EVIDENCE_REPLAY_PROFILE
        ),
        "trial_index": expected["trial_index"],
        "detector": expected["detector"],
        "alert_episode_reset_policy": config["alert_episode_reset_policy"],
        "assessment_step_frames": config["assessment_step"],
    }
    for field, required in exact.items():
        if record[field] != required:
            raise ReviewError(f"{label} has another {field}")
    if (
        _evidence_integer(record["trial_index"], f"{label} trial index")
        != expected["trial_index"]
        or _evidence_integer(
            record["assessment_step_frames"], f"{label} assessment step", minimum=1
        )
        != config["assessment_step"]
    ):
        raise ReviewError(f"{label} has a noncanonical integer identity")

    if expected["source"] == "synthetic":
        seed = expected["seed"]
        if record["seed"] != str(seed) or record["seed_hex"] != f"0x{seed:016x}":
            raise ReviewError(f"{label} has another deterministic seed")
    elif record["seed"] is not None or record["seed_hex"] is not None:
        raise ReviewError(f"{label} assigns a seed to recorded evidence")
    track_id = _evidence_integer(
        record["track_id"],
        f"{label} track ID",
        minimum=1,
        maximum=9_007_199_254_740_991,
    )
    if track_id != expected["track_id"] or record["track_id_hex"] != f"0x{track_id:016x}":
        raise ReviewError(f"{label} has another deterministic track identity")

    modalities = _evidence_string_list(record["modalities"], f"{label} modalities", unique=True)
    expected_modalities = (
        ["visual", "radar", "acoustic"]
        if expected["source"] == "synthetic"
        else ["visual", "acoustic", "radar"]
    )
    if modalities != expected_modalities:
        raise ReviewError(f"{label} has another modality order")
    truth = _require_evidence_keys(
        record["truth"],
        {"class", "channels", "onset_frame", "expected_abstention"},
        f"{label} truth",
    )
    truth_channels = _validate_modality_channels(
        truth["channels"],
        f"{label} truth channels",
    )
    if not isinstance(truth["expected_abstention"], bool):
        raise ReviewError(f"{label} truth abstention flag is not Boolean")
    expected_abstention = expected["expected_abstention"]
    if expected["detector"] == "nis_baseline":
        expected_abstention = False
    if truth != {
        "class": expected["truth_class"],
        "channels": truth_channels,
        "onset_frame": expected["onset_frame"],
        "expected_abstention": expected_abstention,
    } or truth_channels != expected["truth_channels"]:
        raise ReviewError(f"{label} has another truth contract")

    for field in ("phi", "covariance_scale", "ordinary_missing_probability"):
        required = expected[field]
        supplied = record[field]
        if required is None:
            if supplied is not None:
                raise ReviewError(f"{label} has a non-null {field}")
        elif not _same_float(supplied, required):
            raise ReviewError(f"{label} has another {field}")

    if expected["source"] == "synthetic":
        frame_count = config["frames"]
        duration_ms = (frame_count - 1) * config["dt_ms"]
        expected_realized, expected_resets = _expected_synthetic_observation_shape(
            expected,
            config,
        )
        sequence_offset = 0
        timestamp_offset_ms = 0
    else:
        frame_count = 159
        duration_ms = 15_800
        expected_realized = [
            {"modality": "visual", "observations": 159, "missing_frames": 0},
            {"modality": "acoustic", "observations": 158, "missing_frames": 1},
            {"modality": "radar", "observations": 159, "missing_frames": 0},
        ]
        expected_resets = [
            {
                "frame_index": 97,
                "seq": 99,
                "timestamp_ms": 10_800,
                "reason": "sequence_or_timestamp_discontinuity",
            }
        ]
        sequence_offset = 2
        timestamp_offset_ms = 900
    if (
        _evidence_integer(record["frame_count"], f"{label} frame count") != frame_count
        or _evidence_integer(record["duration_ms"], f"{label} duration") != duration_ms
    ):
        raise ReviewError(f"{label} has another exposure")
    assessments = (frame_count + config["assessment_step"] - 1) // config["assessment_step"]
    if _evidence_integer(record["assessments"], f"{label} assessments") != assessments:
        raise ReviewError(f"{label} has another assessment count")

    realized = record["realized_modality_counts"]
    if not isinstance(realized, list) or len(realized) != len(expected_realized):
        raise ReviewError(f"{label} has another realized-modality count")
    normalized_realized: list[dict[str, Any]] = []
    for index, item in enumerate(realized):
        item = _require_evidence_keys(
            item,
            {"modality", "observations", "missing_frames"},
            f"{label} realized modality {index}",
        )
        normalized = {
            "modality": item["modality"],
            "observations": _evidence_integer(
                item["observations"], f"{label} realized observations"
            ),
            "missing_frames": _evidence_integer(
                item["missing_frames"], f"{label} missing frames"
            ),
        }
        if normalized["observations"] + normalized["missing_frames"] != frame_count:
            raise ReviewError(f"{label} realized modality does not cover every frame")
        normalized_realized.append(normalized)
    if normalized_realized != expected_realized:
        raise ReviewError(f"{label} realized modality counts are not deterministic")

    resets = record["detector_generation_resets"]
    if not isinstance(resets, list) or len(resets) > frame_count:
        raise ReviewError(f"{label} reset list is invalid")
    normalized_resets: list[dict[str, Any]] = []
    for index, item in enumerate(resets):
        item = _require_evidence_keys(
            item,
            {"frame_index", "seq", "timestamp_ms", "reason"},
            f"{label} reset {index}",
        )
        normalized_resets.append(
            {
                "frame_index": _evidence_integer(item["frame_index"], f"{label} reset frame"),
                "seq": _evidence_integer(item["seq"], f"{label} reset sequence"),
                "timestamp_ms": _evidence_integer(
                    item["timestamp_ms"], f"{label} reset timestamp"
                ),
                "reason": item["reason"],
            }
        )
    if normalized_resets != expected_resets:
        raise ReviewError(f"{label} detector-generation resets are not deterministic")

    trace = record["trace"]
    if not isinstance(trace, list) or not trace or len(trace) > assessments:
        raise ReviewError(f"{label} trace is not bounded and nonempty")
    trace_labels: list[dict[str, Any]] = []
    prior_end = 0
    prior_label: dict[str, Any] | None = None
    insufficient = 0
    rejected = 0
    nominal = 0
    required_samples = config["detector"]["min_samples"]
    if expected["detector"] == "default_correlation_fusion":
        required_samples = max(required_samples, config["correlation"]["min_samples"])
    startup_count = (required_samples + config["assessment_step"] - 1) // config["assessment_step"] - 1
    startup_abstention = 0
    monitoring_abstention = 0
    expected_episodes: list[dict[str, Any]] = []
    previous_alert = False
    first_attribution: dict[str, Any] | None = None
    for span_index, raw_span in enumerate(trace):
        span = _require_evidence_keys(
            raw_span,
            {
                "assessment_start",
                "assessment_end",
                "frame_start",
                "frame_end",
                "seq_start",
                "seq_end",
                "label",
            },
            f"{label} trace span {span_index}",
        )
        start = _evidence_integer(
            span["assessment_start"], f"{label} trace assessment start", minimum=1
        )
        end = _evidence_integer(
            span["assessment_end"], f"{label} trace assessment end", minimum=1
        )
        if start != prior_end + 1 or end < start or end > assessments:
            raise ReviewError(f"{label} trace has a gap, overlap, or invalid bound")
        span_label = _validate_trace_label(span["label"], f"{label} trace span {span_index}")
        if prior_label == span_label:
            raise ReviewError(f"{label} trace has adjacent equal labels")
        expected_frame_start = _expected_assessment_frame(
            start,
            step=config["assessment_step"],
            frame_count=frame_count,
        )
        expected_frame_end = _expected_assessment_frame(
            end,
            step=config["assessment_step"],
            frame_count=frame_count,
        )
        if (
            span["frame_start"] != expected_frame_start
            or span["frame_end"] != expected_frame_end
            or span["seq_start"] != expected_frame_start + sequence_offset
            or span["seq_end"] != expected_frame_end + sequence_offset
        ):
            raise ReviewError(f"{label} trace endpoints do not match the assessment schedule")
        count = end - start + 1
        if span_label["state"] == "insufficient_evidence":
            insufficient += count
        elif span_label["state"] == "rejected_input":
            rejected += count
        elif span_label["state"] == "nominal":
            nominal += count
        abstention = span_label["state"] in {"insufficient_evidence", "rejected_input"}
        if abstention:
            startup_abstention += max(0, min(end, startup_count) - start + 1)
            monitoring_abstention += max(0, end - max(start, startup_count + 1) + 1)
        if span_label["state"] == "alert" and not previous_alert:
            seq = expected_frame_start + sequence_offset
            expected_episodes.append(
                {
                    "assessment_index": start,
                    "frame_index": expected_frame_start,
                    "seq": seq,
                    "timestamp_ms": seq * config["dt_ms"] + timestamp_offset_ms,
                    "classification": span_label["classification"],
                    "channels": span_label["channels"],
                }
            )
        if span_label["state"] == "alert":
            previous_alert = True
        elif span_label["state"] == "nominal":
            previous_alert = False
        onset = expected["onset_frame"]
        if (
            onset is not None
            and first_attribution is None
            and expected_frame_end >= onset
            and span_label["classification"] == "attributed_inconsistency"
        ):
            first_attribution = span_label
        trace_labels.append(span_label)
        prior_end = end
        prior_label = span_label
    if prior_end != assessments:
        raise ReviewError(f"{label} trace does not cover all assessments")

    supplied_episodes = record["alert_episodes"]
    if not isinstance(supplied_episodes, list) or len(supplied_episodes) > assessments:
        raise ReviewError(f"{label} alert episode list is invalid")
    normalized_episodes: list[dict[str, Any]] = []
    for index, item in enumerate(supplied_episodes):
        item = _require_evidence_keys(
            item,
            {
                "assessment_index",
                "frame_index",
                "seq",
                "timestamp_ms",
                "classification",
                "channels",
            },
            f"{label} alert episode {index}",
        )
        normalized_episodes.append(
            {
                "assessment_index": _evidence_integer(
                    item["assessment_index"], f"{label} episode assessment", minimum=1
                ),
                "frame_index": _evidence_integer(item["frame_index"], f"{label} episode frame"),
                "seq": _evidence_integer(item["seq"], f"{label} episode sequence"),
                "timestamp_ms": _evidence_integer(
                    item["timestamp_ms"], f"{label} episode timestamp"
                ),
                "classification": item["classification"],
                "channels": _validate_modality_channels(
                    item["channels"], f"{label} episode channels"
                ),
            }
        )
    if normalized_episodes != expected_episodes:
        raise ReviewError(f"{label} alert episodes do not match its trace")

    first_alert = expected_episodes[0]["assessment_index"] if expected_episodes else None
    mission_alert = any(
        episode["frame_index"] < config["mission_frames"] for episode in expected_episodes
    )
    onset = expected["onset_frame"]
    if onset is None:
        pre_onset = None
        delay_frames = None
        attribution_emitted = None
        attribution_correct = None
    else:
        pre_onset = any(episode["frame_index"] < onset for episode in expected_episodes)
        post = next(
            (episode for episode in expected_episodes if episode["frame_index"] >= onset),
            None,
        )
        delay_frames = None if pre_onset or post is None else post["frame_index"] - onset
        unique_attribution = (
            expected["truth_class"] == "attributed_inconsistency"
            and len(expected["truth_channels"]) == 1
        )
        attribution_emitted = (
            None if pre_onset or not unique_attribution else first_attribution is not None
        )
        attribution_correct = (
            None
            if attribution_emitted is not True
            else first_attribution["channels"] == expected["truth_channels"]
        )
    derived_scalars = {
        "alert_episode_count": len(expected_episodes),
        "mission_alert": mission_alert,
        "first_alert_assessment": first_alert,
        "pre_onset_alert": pre_onset,
        "first_post_onset_delay_frames": delay_frames,
        "first_post_onset_delay_ms": (
            None if delay_frames is None else delay_frames * config["dt_ms"]
        ),
        "attribution_emitted": attribution_emitted,
        "attribution_correct": attribution_correct,
        "insufficient_assessments": insufficient,
        "rejected_input_assessments": rejected,
        "abstention_assessments": insufficient + rejected,
        "startup_assessments": startup_count,
        "startup_abstention_assessments": startup_abstention,
        "monitoring_assessments": assessments - startup_count,
        "monitoring_abstention_assessments": monitoring_abstention,
    }
    for field, required in derived_scalars.items():
        supplied = record[field]
        if isinstance(required, bool):
            valid = isinstance(supplied, bool) and supplied is required
        elif required is None:
            valid = supplied is None
        else:
            valid = (
                _evidence_integer(supplied, f"{label} {field}") == required
            )
        if not valid:
            raise ReviewError(f"{label} {field} does not match its trace")
    fractions = {
        "abstention_fraction": (insufficient + rejected) / assessments,
        "startup_abstention_fraction": (
            startup_abstention / startup_count if startup_count else 0.0
        ),
        "monitoring_abstention_fraction": (
            monitoring_abstention / (assessments - startup_count)
            if assessments > startup_count
            else 0.0
        ),
    }
    for field, required in fractions.items():
        if not _same_float(record[field], required):
            raise ReviewError(f"{label} {field} is not the derived binary64 ratio")

    consistency = _require_evidence_keys(
        record["consistency"],
        {
            "assessed",
            "insufficient_axis",
            "missing_projection",
            "extraction_error",
            "analysis_error",
            "too_few_modalities",
        },
        f"{label} consistency counts",
    )
    normalized_consistency = {
        field: _evidence_integer(value, f"{label} consistency {field}")
        for field, value in consistency.items()
    }
    if expected["detector"] == "nis_baseline":
        if any(normalized_consistency.values()):
            raise ReviewError(f"{label} baseline reports correlation counts")
    else:
        if sum(normalized_consistency.values()) != assessments:
            raise ReviewError(f"{label} consistency categories do not cover assessments")
        if (
            normalized_consistency["extraction_error"]
            + normalized_consistency["analysis_error"]
            != rejected
        ):
            raise ReviewError(f"{label} consistency counts contradict its trace")
        if expected_abstention and nominal != 0:
            raise ReviewError(
                f"{label} recodes required provenance abstention as nominal"
            )

    expected_reasons: list[str] = []
    if expected["source"] == "recorded":
        expected_reasons.append(
            "insufficient_duration: 15800 ms is below configured minimum 3600000 ms"
        )
        if expected["detector"] == "default_correlation_fusion":
            expected_reasons.append("missing_consistency_projection")
    if expected_resets:
        expected_reasons.append(f"detector_generation_resets:{len(expected_resets)}")
    status_reasons = _evidence_string_list(
        record["status_reasons"], f"{label} status reasons", unique=True
    )
    if status_reasons != expected_reasons:
        raise ReviewError(f"{label} has another evidence-status reason set")
    expected_status = "not_estimable" if expected["source"] == "recorded" else "estimable"
    if record["evidence_status"] != expected_status:
        raise ReviewError(f"{label} has another evidence status")

    return {
        "condition": expected["condition"],
        "experiment_kind": expected["experiment_kind"],
        "role": expected["role"],
        "source": expected["source"],
        "trial_index": expected["trial_index"],
        "track_id": track_id,
        "detector": expected["detector"],
        "truth_class": expected["truth_class"],
        "phi": expected["phi"],
        "covariance_scale": expected["covariance_scale"],
        "ordinary_missing_probability": expected["ordinary_missing_probability"],
        "duration_ms": duration_ms,
        "assessments": assessments,
        "alert_episode_count": len(expected_episodes),
        "mission_alert": mission_alert,
        "first_alert_assessment": first_alert,
        "pre_onset_alert": pre_onset,
        "first_post_onset_delay_frames": delay_frames,
        "first_post_onset_delay_ms": (
            None if delay_frames is None else delay_frames * config["dt_ms"]
        ),
        "attribution_emitted": attribution_emitted,
        "attribution_correct": attribution_correct,
        "monitoring_assessments": assessments - startup_count,
        "monitoring_abstention_assessments": monitoring_abstention,
        "detector_generation_resets": len(expected_resets),
        "detector_generation_reset_signature": expected_resets,
        "realized_modality_signature": expected_realized,
    }


def _candidate_evidence_tree(root: Path, label: str) -> dict[str, Any]:
    """Capture the exact flat evidence inventory through no-follow reads."""

    inventory = digest_rooted_tree(
        root,
        label=label,
        max_entries=len(EVIDENCE_FILES),
        max_depth=1,
        max_path_bytes=255,
        max_component_bytes=255,
        max_file_bytes=MAX_CANDIDATE_EVIDENCE_FILE_BYTES,
        max_aggregate_bytes=MAX_CANDIDATE_EVIDENCE_BYTES,
        reject_empty_directories=True,
    )
    if set(inventory) != set(EVIDENCE_FILES):
        raise ReviewError("candidate evidence file set is not exact")
    return inventory


def _capture_candidate_evidence_documents(
    root: Path,
    inventory: dict[str, Any],
) -> dict[str, RootedFileBatchCapture]:
    """Capture the five bounded non-trial evidence documents."""

    names = tuple(name for name in EVIDENCE_FILES if name != "trials.jsonl")
    captures = read_rooted_regular_files(
        root,
        tuple(
            RootedFileCaptureRequest(
                name,
                inventory[name].size_bytes,
                f"candidate evidence {name}",
                inventory[name].sha256,
                None,
            )
            for name in names
        ),
        label="candidate evidence documents",
        max_files=len(names),
        max_file_bytes=MAX_EVIDENCE_DOCUMENT_BYTES,
        max_aggregate_bytes=MAX_EVIDENCE_DOCUMENT_BYTES * len(names),
        max_path_bytes=255,
        max_component_bytes=255,
        max_depth=1,
        max_directory_entries=len(EVIDENCE_FILES),
    )
    return {capture.relative: capture for capture in captures}


def _stream_validate_evidence_trials(
    root: Path,
    *,
    expected_digest: str,
    expected_size: int,
    config: dict[str, Any],
) -> tuple[list[dict[str, Any]], str, int]:
    """Stream and validate the ordered JSON Lines trial population."""

    path = root / "trials.jsonl"
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ReviewError("candidate evidence no-follow trial reads are unavailable")
    flags |= no_follow
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReviewError("candidate evidence trials are missing or unsafe") from error
    expected_layout = _expected_trial_layout(config)
    if len(expected_layout) > MAX_EVIDENCE_TRIAL_RECORDS:
        os.close(descriptor)
        raise ReviewError("candidate evidence expected trial count exceeds its bound")
    records: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    total = 0
    pending = bytearray()
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != expected_size
            or before.st_size > MAX_CANDIDATE_EVIDENCE_FILE_BYTES
        ):
            raise ReviewError("candidate evidence trials have another file identity")
        while total <= before.st_size:
            block = os.read(descriptor, min(1024 * 1024, before.st_size + 1 - total))
            if not block:
                break
            total += len(block)
            if total > before.st_size:
                raise ReviewError("candidate evidence trials grew during validation")
            digest.update(block)
            pending.extend(block)
            while True:
                newline = pending.find(b"\n")
                if newline < 0:
                    if len(pending) > MAX_EVIDENCE_TRIAL_LINE_BYTES:
                        raise ReviewError("candidate evidence trial line exceeds its bound")
                    break
                if newline == 0:
                    raise ReviewError("candidate evidence trials contain a blank line")
                if newline > MAX_EVIDENCE_TRIAL_LINE_BYTES:
                    raise ReviewError("candidate evidence trial line exceeds its bound")
                line = bytes(pending[:newline])
                del pending[: newline + 1]
                record_index = len(records) + 1
                if record_index > len(expected_layout):
                    raise ReviewError("candidate evidence has an extra trial record")
                try:
                    value = loads_json(line)
                    validate_json_structure(
                        value,
                        max_depth=64,
                        max_nodes=200_000,
                        label=f"candidate evidence trial {record_index}",
                    )
                except (
                    MemoryError,
                    RecursionError,
                    ReviewError,
                    UnicodeError,
                    ValueError,
                ) as error:
                    raise ReviewError(
                        f"candidate evidence trial {record_index} is invalid: {error}"
                    ) from error
                records.append(
                    _validate_trial_record(
                        value,
                        expected_layout[record_index - 1],
                        config,
                        record_index=record_index,
                    )
                )
        after = os.fstat(descriptor)
        if total != before.st_size or after != before:
            raise ReviewError("candidate evidence trials changed during validation")
    except OSError as error:
        raise ReviewError("candidate evidence trials could not be read safely") from error
    finally:
        os.close(descriptor)
    if pending:
        raise ReviewError("candidate evidence trials lack one final newline")
    if len(records) != len(expected_layout):
        raise ReviewError("candidate evidence trial population is incomplete")
    observed_digest = digest.hexdigest()
    if observed_digest != expected_digest:
        raise ReviewError("candidate evidence trial digest changed during validation")
    for index in range(0, len(records), 2):
        baseline = records[index]
        fused = records[index + 1]
        paired_fields = {
            "condition",
            "experiment_kind",
            "role",
            "source",
            "trial_index",
            "track_id",
            "truth_class",
            "phi",
            "covariance_scale",
            "ordinary_missing_probability",
            "duration_ms",
            "assessments",
            "detector_generation_reset_signature",
            "realized_modality_signature",
        }
        if any(baseline[field] != fused[field] for field in paired_fields):
            raise ReviewError("candidate evidence detector pair targets another physical track")
        if (
            baseline["detector"] != "nis_baseline"
            or fused["detector"] != "default_correlation_fusion"
        ):
            raise ReviewError("candidate evidence detector pair has another order")
    return records, observed_digest, total


EVIDENCE_METRIC_UNITS = {
    "false_alerts_per_hour": "alert_episodes/hour",
    "arl0_assessments": "assessments",
    "conditional_delay_frames": "frames",
    "conditional_delay_p95_ms": "ms",
}
EVIDENCE_METRIC_METHODS = {
    "false_alerts_per_hour": "pooled alert episodes / pooled track exposure",
    "mission_probability_any_alert": "track-level proportion",
    "arl0_assessments": (
        "restricted mean time to first alert. Each track end creates right censoring"
    ),
    "arl0_censoring_fraction": "track-level proportion",
    "abstention_fraction": (
        "post-warm-up pooled insufficient-or-rejected assessments / pooled monitoring assessments"
    ),
    "any_alert_probability": "track-level proportion",
    "pre_onset_alert_probability": "track-level proportion",
    "conditional_detection_probability": (
        "detected tracks / tracks without a pre-onset alert"
    ),
    "conditional_delay_frames": (
        "median first post-onset alert delay among detected tracks without pre-onset alert"
    ),
    "conditional_delay_p95_ms": (
        "nearest-rank empirical 95th percentile of first post-onset alert delay in milliseconds among detected tracks without pre-onset alert"
    ),
    "conditional_attribution_coverage": (
        "tracks emitting an attribution / uniquely altered tracks without a pre-onset alert"
    ),
    "conditional_attribution_accuracy": (
        "correct first attribution / tracks emitting an attribution"
    ),
    "conditional_attribution_error": (
        "wrong first attribution / tracks emitting an attribution"
    ),
}
EVIDENCE_BINOMIAL_METRICS = {
    "mission_probability_any_alert",
    "arl0_censoring_fraction",
    "any_alert_probability",
    "pre_onset_alert_probability",
    "conditional_detection_probability",
    "conditional_attribution_coverage",
    "conditional_attribution_accuracy",
    "conditional_attribution_error",
}
EVIDENCE_SPARSE_METRICS = {
    "conditional_detection_probability",
    "conditional_delay_frames",
    "conditional_delay_p95_ms",
    "conditional_attribution_accuracy",
    "conditional_attribution_error",
}


class _EvidenceBootstrapRng:
    """Exact SplitMix64 rejection sampler for acceptance bootstrap draws."""

    def __init__(self, state: int) -> None:
        self.state = state & 0xFFFF_FFFF_FFFF_FFFF

    def next_u64(self) -> int:
        self.state = (self.state + 0x9E37_79B9_7F4A_7C15) & 0xFFFF_FFFF_FFFF_FFFF
        return _mix64(self.state)

    def below(self, bound: int) -> int:
        if not 0 < bound <= 0xFFFF_FFFF_FFFF_FFFF:
            raise ReviewError("evidence bootstrap bound is invalid")
        threshold = ((-bound) & 0xFFFF_FFFF_FFFF_FFFF) % bound
        while True:
            draw = self.next_u64()
            if draw >= threshold:
                return draw % bound


def _f64_left_sum(values: Any) -> float:
    """Match Rust iterator binary64 addition order without compensated summation."""

    result = 0.0
    for value in values:
        result += float(value)
    return result


def _proportion_enclosure(k: int, n: int) -> tuple[float, float]:
    if k == 0:
        return 0.0, 0.0
    if k == n:
        return 1.0, 1.0
    kf = float(k)
    nf = float(n)
    lower = max(
        0.0,
        math.nextafter(
            math.nextafter(kf, -math.inf) / math.nextafter(nf, math.inf),
            -math.inf,
        ),
    )
    upper = min(
        1.0,
        math.nextafter(
            math.nextafter(kf, math.inf) / math.nextafter(nf, -math.inf),
            math.inf,
        ),
    )
    return lower, upper


def _wilson_lower_half(k: int, n: int) -> tuple[float, float]:
    z = 1.959_964
    nf = float(n)
    point = float(k) / nf
    z2 = z * z
    denominator = 1.0 + z2 / nf
    center = point + z2 / (2.0 * nf)
    margin = z * math.sqrt(
        point * (1.0 - point) / nf + z2 / (4.0 * nf * nf)
    )
    point_lower, point_upper = _proportion_enclosure(k, n)
    lower = min(max((center - margin) / denominator, 0.0), 1.0, point_lower)
    upper = max(min((center + margin) / denominator, 1.0), 0.0, point_upper)
    return lower, upper


def _one_minus_with_roundoff(value: float) -> tuple[float, float]:
    negative = -value
    difference = 1.0 + negative
    virtual_negative = difference - 1.0
    residual = (1.0 - (difference - virtual_negative)) + (negative - virtual_negative)
    return difference, residual


def _wilson_ci(successes: int, trials: int) -> tuple[float, float]:
    if trials <= 0 or not 0 <= successes <= trials:
        raise ReviewError("evidence Wilson counts are invalid")
    if successes <= trials // 2:
        return _wilson_lower_half(successes, trials)
    failure_lower, failure_upper = _wilson_lower_half(trials - successes, trials)
    point_lower, point_upper = _proportion_enclosure(successes, trials)
    lower_value, lower_residual = _one_minus_with_roundoff(failure_upper)
    if lower_residual < 0.0:
        lower_value = math.nextafter(lower_value, -math.inf)
    upper_value, upper_residual = _one_minus_with_roundoff(failure_lower)
    if upper_residual > 0.0:
        upper_value = math.nextafter(upper_value, math.inf)
    return (
        min(max(lower_value, 0.0), point_lower),
        max(min(upper_value, 1.0), point_upper),
    )


def _metric_statistic(
    records: list[dict[str, Any]],
    metric: str,
) -> tuple[float | None, int]:
    if metric == "false_alerts_per_hour":
        exposure = _f64_left_sum(
            float(record["duration_ms"]) / 3_600_000.0 for record in records
        )
        episodes = sum(record["alert_episode_count"] for record in records)
        return (episodes / exposure if exposure > 0.0 else None), len(records)
    if metric == "mission_probability_any_alert":
        return (
            sum(record["mission_alert"] for record in records) / len(records)
            if records
            else None,
            len(records),
        )
    if metric == "arl0_assessments":
        return (
            _f64_left_sum(
                float(record["first_alert_assessment"] or record["assessments"])
                for record in records
            )
            / len(records)
            if records
            else None,
            len(records),
        )
    if metric == "arl0_censoring_fraction":
        return (
            sum(record["first_alert_assessment"] is None for record in records)
            / len(records)
            if records
            else None,
            len(records),
        )
    if metric == "abstention_fraction":
        assessments = sum(record["monitoring_assessments"] for record in records)
        abstentions = sum(
            record["monitoring_abstention_assessments"] for record in records
        )
        return (abstentions / assessments if assessments else None), len(records)
    if metric == "any_alert_probability":
        return (
            sum(record["alert_episode_count"] > 0 for record in records) / len(records)
            if records
            else None,
            len(records),
        )
    if metric == "pre_onset_alert_probability":
        values = [
            record["pre_onset_alert"]
            for record in records
            if record["pre_onset_alert"] is not None
        ]
        return (sum(values) / len(values) if values else None), len(values)
    if metric == "conditional_detection_probability":
        eligible = [
            record for record in records if record["pre_onset_alert"] is False
        ]
        return (
            sum(record["first_post_onset_delay_frames"] is not None for record in eligible)
            / len(eligible)
            if eligible
            else None,
            len(eligible),
        )
    if metric in {"conditional_delay_frames", "conditional_delay_p95_ms"}:
        field = (
            "first_post_onset_delay_frames"
            if metric == "conditional_delay_frames"
            else "first_post_onset_delay_ms"
        )
        values = sorted(
            float(record[field])
            for record in records
            if record["pre_onset_alert"] is False and record[field] is not None
        )
        if not values:
            return None, 0
        if metric == "conditional_delay_frames":
            middle = len(values) // 2
            point = (
                values[middle - 1] / 2.0 + values[middle] / 2.0
                if len(values) % 2 == 0
                else values[middle]
            )
        else:
            rank = (len(values) * 95 + 99) // 100
            point = values[rank - 1]
        return point, len(values)
    if metric == "conditional_attribution_coverage":
        values = [
            record["attribution_emitted"]
            for record in records
            if record["attribution_emitted"] is not None
        ]
        return (sum(values) / len(values) if values else None), len(values)
    if metric == "conditional_attribution_accuracy":
        values = [
            record["attribution_correct"]
            for record in records
            if record["pre_onset_alert"] is False
            and record["attribution_correct"] is not None
        ]
        return (sum(values) / len(values) if values else None), len(values)
    if metric == "conditional_attribution_error":
        values = [
            record["attribution_correct"]
            for record in records
            if record["attribution_correct"] is not None
        ]
        return (
            sum(not value for value in values) / len(values) if values else None,
            len(values),
        )
    raise ReviewError(f"unknown evidence metric: {metric}")


def _binomial_counts(records: list[dict[str, Any]], metric: str) -> tuple[int, int]:
    if metric == "mission_probability_any_alert":
        return sum(record["mission_alert"] for record in records), len(records)
    if metric == "arl0_censoring_fraction":
        return sum(record["first_alert_assessment"] is None for record in records), len(records)
    if metric == "any_alert_probability":
        return sum(record["alert_episode_count"] > 0 for record in records), len(records)
    if metric == "pre_onset_alert_probability":
        values = [record["pre_onset_alert"] for record in records if record["pre_onset_alert"] is not None]
        return sum(values), len(values)
    if metric == "conditional_detection_probability":
        eligible = [record for record in records if record["pre_onset_alert"] is False]
        return sum(record["first_post_onset_delay_frames"] is not None for record in eligible), len(eligible)
    if metric == "conditional_attribution_coverage":
        values = [record["attribution_emitted"] for record in records if record["attribution_emitted"] is not None]
        return sum(values), len(values)
    if metric == "conditional_attribution_accuracy":
        values = [record["attribution_correct"] for record in records if record["pre_onset_alert"] is False and record["attribution_correct"] is not None]
        return sum(values), len(values)
    if metric == "conditional_attribution_error":
        values = [record["attribution_correct"] for record in records if record["attribution_correct"] is not None]
        return sum(not value for value in values), len(values)
    raise ReviewError(f"evidence metric is not binomial: {metric}")


def _gamma_integer_quantile(shape: int, probability: Decimal) -> Decimal:
    """Invert an integer-shape unit-scale gamma distribution at high precision."""

    if shape < 1 or not Decimal(0) < probability < Decimal(1):
        raise ReviewError("evidence gamma quantile arguments are invalid")
    target_upper = Decimal(1) - probability
    with localcontext() as context:
        context.prec = 90

        def upper_tail(point: Decimal) -> Decimal:
            term = Decimal(1)
            total = term
            for index in range(1, shape):
                term = term * point / Decimal(index)
                total += term
            return (-point).exp() * total

        lower = Decimal(0)
        upper = Decimal(max(1, shape))
        while upper_tail(upper) > target_upper:
            upper *= 2
            if upper > Decimal(1 << 32):
                raise ReviewError("evidence gamma quantile bracket did not converge")
        for _ in range(400):
            middle = (lower + upper) / 2
            if upper_tail(middle) > target_upper:
                lower = middle
            else:
                upper = middle
        return +(lower + upper) / 2


def _garwood_rate_ci(events: int, exposure_hours: float) -> list[float]:
    if events < 0 or not math.isfinite(exposure_hours) or exposure_hours <= 0.0:
        raise ReviewError("evidence Garwood inputs are invalid")
    exposure = Decimal.from_float(exposure_hours)
    lower = (
        0.0
        if events == 0
        else float(_gamma_integer_quantile(events, Decimal("0.025")) / exposure)
    )
    upper = float(
        _gamma_integer_quantile(events + 1, Decimal("0.975")) / exposure
    )
    if not (math.isfinite(lower) and math.isfinite(upper) and lower <= upper):
        raise ReviewError("evidence Garwood interval is invalid")
    return [lower, upper]


def _hoeffding_ci(
    mean: float,
    lower: float,
    upper: float,
    sum_squared_weights: float,
) -> list[float]:
    radius = (upper - lower) * math.sqrt(
        sum_squared_weights * math.log(2.0 / 0.05) / 2.0
    )
    return [max(mean - radius, lower), min(mean + radius, upper)]


def _percentile(values: list[float], probability: float) -> float:
    index = math.floor(probability * (len(values) - 1))
    return values[index]


def _not_applicable_metric(metric: str, tracks: int) -> dict[str, Any]:
    return {
        "status": "not_applicable",
        "value": None,
        "ci95": None,
        "ci_status": "not_applicable",
        "unit": EVIDENCE_METRIC_UNITS.get(metric, "probability"),
        "estimator": EVIDENCE_METRIC_METHODS[metric],
        "interval": "none",
        "tracks": tracks,
        "eligible_tracks": 0,
        "bootstrap_requested": 0,
        "bootstrap_usable": 0,
    }


def _estimate_evidence_metric(
    records: list[dict[str, Any]],
    metric: str,
    config: dict[str, Any],
    group_id: str,
) -> dict[str, Any]:
    point, eligible = _metric_statistic(records, metric)
    requested = config["bootstrap_resamples"]
    unit = EVIDENCE_METRIC_UNITS.get(metric, "probability")
    method = EVIDENCE_METRIC_METHODS[metric]
    if point is None:
        return {
            "status": "not_estimable",
            "value": None,
            "ci95": None,
            "ci_status": "not_estimable",
            "unit": unit,
            "estimator": method,
            "interval": "none: no eligible tracks",
            "tracks": len(records),
            "eligible_tracks": eligible,
            "bootstrap_requested": requested,
            "bootstrap_usable": 0,
        }
    if metric in EVIDENCE_SPARSE_METRICS and eligible < config["min_metric_eligible_tracks"]:
        return {
            "status": "descriptive_sparse",
            "value": point,
            "ci95": None,
            "ci_status": "not_estimable_sparse",
            "unit": unit,
            "estimator": method,
            "interval": (
                f"not estimable: {eligible} eligible tracks is below configured minimum "
                f"{config['min_metric_eligible_tracks']}"
            ),
            "tracks": len(records),
            "eligible_tracks": eligible,
            "bootstrap_requested": requested,
            "bootstrap_usable": 0,
        }
    rng = _EvidenceBootstrapRng(
        _mix64(int(config["base_seed"]) ^ _fnv1a64(group_id) ^ _fnv1a64(metric))
    )
    bootstrap: list[float] = []
    for _ in range(requested):
        sample = [records[rng.below(len(records))] for _ in records]
        value, _eligible = _metric_statistic(sample, metric)
        if value is not None:
            bootstrap.append(value)
    bootstrap.sort()
    usable = len(bootstrap)
    bootstrap_ci = (
        [_percentile(bootstrap, 0.025), _percentile(bootstrap, 0.975)]
        if bootstrap
        else None
    )
    usable_ci = bootstrap_ci if usable * 5 >= requested * 4 else None
    if metric in EVIDENCE_BINOMIAL_METRICS:
        successes, trials = _binomial_counts(records, metric)
        ci95 = list(_wilson_ci(successes, trials))
        ci_status = "estimated"
        interval = (
            "95% Wilson score interval for a track-level binomial proportion. The whole-track "
            "bootstrap is diagnostic. It does not replace or envelope the preregistered Wilson "
            f"bound. Usable replicates: {usable} of {requested} requested."
        )
    elif metric == "false_alerts_per_hour":
        exposure = _f64_left_sum(
            float(record["duration_ms"]) / 3_600_000.0 for record in records
        )
        events = sum(record["alert_episode_count"] for record in records)
        ci95 = _garwood_rate_ci(events, exposure)
        if usable_ci is not None:
            ci95 = [min(ci95[0], usable_ci[0]), max(ci95[1], usable_ci[1])]
        ci_status = "estimated"
        interval = (
            "95% Garwood exact Poisson count-rate interval under a homogeneous episode-rate "
            "model. A whole-track bootstrap envelope applies only when at least 80% of "
            f"replicates are usable. Usable replicates: {usable} of {requested} requested."
        )
    elif metric == "abstention_fraction":
        total = sum(record["monitoring_assessments"] for record in records)
        if total:
            squared = _f64_left_sum(
                (record["monitoring_assessments"] / total) ** 2 for record in records
            )
            ci95 = _hoeffding_ci(point, 0.0, 1.0, squared)
            if usable_ci is not None:
                ci95 = [min(ci95[0], usable_ci[0]), max(ci95[1], usable_ci[1])]
            ci_status = "estimated"
            interval = (
                "95% distribution-free weighted-track Hoeffding interval for bounded "
                "post-warm-up abstention fractions. A whole-track bootstrap envelope applies "
                "only when at least 80% of replicates are usable. Usable replicates: "
                f"{usable} of {requested} requested."
            )
        else:
            ci95 = None
            ci_status = "not_estimable"
            interval = "not estimable: no post-warm-up monitoring exposure"
    elif metric == "arl0_assessments":
        horizon = float(max(record["assessments"] for record in records))
        ci95 = _hoeffding_ci(point, 0.0, horizon, 1.0 / len(records))
        if usable_ci is not None:
            ci95 = [min(ci95[0], usable_ci[0]), max(ci95[1], usable_ci[1])]
        ci_status = "estimated"
        interval = (
            "95% distribution-free Hoeffding interval for track-level time to first alert. The "
            "configured assessment horizon bounds each track. A whole-track bootstrap envelope "
            "applies only when at least 80% of replicates are usable. Usable replicates: "
            f"{usable} of {requested} requested."
        )
    elif usable_ci is not None:
        ci95 = usable_ci
        ci_status = "estimated"
        interval = (
            f"95% whole-track percentile bootstrap interval. Usable replicates: {usable} of "
            f"{requested} requested. The minimum usable fraction is 80%."
        )
    else:
        ci95 = None
        ci_status = "not_estimable"
        interval = (
            f"not estimable: {usable} usable of {requested} requested whole-track resamples "
            "is below the 80% minimum"
        )
    return {
        "status": "estimated",
        "value": point,
        "ci95": ci95,
        "ci_status": ci_status,
        "unit": unit,
        "estimator": method,
        "interval": interval,
        "tracks": len(records),
        "eligible_tracks": eligible,
        "bootstrap_requested": requested,
        "bootstrap_usable": usable,
    }


def _evidence_raw_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    """Rebuild one condition's disclosed integer counts."""

    return {
        "tracks": len(records),
        "assessments": sum(record["assessments"] for record in records),
        "monitoring_assessments": sum(
            record["monitoring_assessments"] for record in records
        ),
        "monitoring_abstention_assessments": sum(
            record["monitoring_abstention_assessments"] for record in records
        ),
        "alert_episodes": sum(record["alert_episode_count"] for record in records),
        "mission_alert_tracks": sum(record["mission_alert"] for record in records),
        "onset_labeled_tracks": sum(
            record["pre_onset_alert"] is not None for record in records
        ),
        "pre_onset_alert_tracks": sum(
            record["pre_onset_alert"] is True for record in records
        ),
        "post_onset_detection_eligible_tracks": sum(
            record["pre_onset_alert"] is False for record in records
        ),
        "detected_post_onset_tracks": sum(
            record["pre_onset_alert"] is False
            and record["first_post_onset_delay_ms"] is not None
            for record in records
        ),
        "undetected_post_onset_tracks": sum(
            record["pre_onset_alert"] is False
            and record["first_post_onset_delay_ms"] is None
            for record in records
        ),
        "attribution_coverage_eligible_tracks": sum(
            record["attribution_emitted"] is not None for record in records
        ),
        "emitted_attribution_tracks": sum(
            record["attribution_emitted"] is True for record in records
        ),
        "correct_attribution_tracks": sum(
            record["attribution_correct"] is True for record in records
        ),
        "wrong_attribution_tracks": sum(
            record["attribution_correct"] is False for record in records
        ),
        "detector_generation_resets": sum(
            record["detector_generation_resets"] for record in records
        ),
        "tracks_with_detector_generation_resets": sum(
            record["detector_generation_resets"] > 0 for record in records
        ),
    }


def _summarize_evidence_group(
    records: list[dict[str, Any]],
    config: dict[str, Any],
) -> dict[str, Any]:
    """Independently rebuild one ordered condition summary."""

    if not records:
        raise ReviewError("candidate evidence summary group is empty")
    first = records[0]
    for record in records:
        for field in (
            "condition",
            "experiment_kind",
            "role",
            "detector",
            "truth_class",
            "phi",
            "covariance_scale",
            "ordinary_missing_probability",
        ):
            if record[field] != first[field]:
                raise ReviewError("candidate evidence summary group mixes identities")
    role_debug = {"calibration": "Calibration", "holdout": "Holdout"}[first["role"]]
    detector_debug = {
        "nis_baseline": "NisBaseline",
        "default_correlation_fusion": "DefaultCorrelationFusion",
    }[first["detector"]]
    group_id = f"{first['condition']}:{role_debug}:{detector_debug}"
    clean = first["truth_class"] == "clean"
    attack = any(record["pre_onset_alert"] is not None for record in records)
    attributed_attack = first["truth_class"] == "attributed_inconsistency"
    provenance = (
        first["truth_class"] == "clean_invalid_or_missing_provenance"
        and first["detector"] == "default_correlation_fusion"
    )
    applicable = {
        "false_alerts_per_hour": clean,
        "mission_probability_any_alert": clean,
        "arl0_assessments": clean,
        "arl0_censoring_fraction": clean,
        "abstention_fraction": True,
        "any_alert_probability": provenance,
        "pre_onset_alert_probability": attack,
        "conditional_detection_probability": attack,
        "conditional_delay_frames": attack,
        "conditional_delay_p95_ms": attack,
        "conditional_attribution_coverage": attributed_attack,
        "conditional_attribution_accuracy": attributed_attack,
        "conditional_attribution_error": attributed_attack,
    }
    metrics = {
        metric: (
            _estimate_evidence_metric(records, metric, config, group_id)
            if applicable[metric]
            else _not_applicable_metric(metric, len(records))
        )
        for metric in EVIDENCE_METRIC_NAMES
    }
    return {
        "condition": first["condition"],
        "experiment_kind": first["experiment_kind"],
        "role": first["role"],
        "detector": first["detector"],
        "truth_class": first["truth_class"],
        "tracks": len(records),
        "exposure_hours": _f64_left_sum(
            float(record["duration_ms"]) / 3_600_000.0 for record in records
        ),
        "detector_generation_resets": sum(
            record["detector_generation_resets"] for record in records
        ),
        "tracks_with_detector_generation_resets": sum(
            record["detector_generation_resets"] > 0 for record in records
        ),
        "phi": first["phi"],
        "covariance_scale": first["covariance_scale"],
        "ordinary_missing_probability": first["ordinary_missing_probability"],
        "raw_counts": _evidence_raw_counts(records),
        "metrics": metrics,
    }


def _summarize_evidence_partition(
    records: list[dict[str, Any]],
    role: str,
    config: dict[str, Any],
) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in records:
        if record["source"] == "synthetic" and record["role"] == role:
            groups.setdefault((record["condition"], record["detector"]), []).append(record)
    detector_order = {"nis_baseline": 0, "default_correlation_fusion": 1}
    keys = sorted(groups, key=lambda key: (key[0], detector_order[key[1]]))
    return [_summarize_evidence_group(groups[key], config) for key in keys]


def _recompute_evidence_summary(
    records: list[dict[str, Any]],
    config: dict[str, Any],
) -> dict[str, Any]:
    """Rebuild the complete evidence summary from validated trial projections."""

    requested = config["bootstrap_resamples"]
    return {
        "schema": EVIDENCE_SUMMARY_SCHEMA,
        "generator_profile": EVIDENCE_GENERATOR_PROFILE,
        "recorded_replay_profile": EVIDENCE_REPLAY_PROFILE,
        "missingness_profile": EVIDENCE_MISSINGNESS_PROFILE,
        "acceptance_metric_profile": EVIDENCE_ACCEPTANCE_PROFILE,
        "bootstrap_profile": EVIDENCE_BOOTSTRAP_PROFILE,
        "study_id": config["study_id"],
        "base_seed_hex": config["base_seed_hex"],
        "claim_partition": (
            "Only the holdout_results field supports reported results. The "
            "calibration_diagnostics field is descriptive. The runner does not pool it with "
            "holdout_results."
        ),
        "interval_method": (
            "Track proportions use preregistered 95% Wilson intervals. Alert-episode rates use "
            "95% Garwood Poisson intervals. Average run length under no-alert conditions "
            "(ARL0) and post-warm-up abstention use bounded-track 95% Hoeffding intervals. "
            "Garwood and Hoeffding intervals use a conservative whole-track bootstrap envelope "
            f"when at least 80% of {requested} requested replicates are usable. The bootstrap "
            "envelope does not replace the analytic interval. Delay summaries use whole-track "
            "percentile bootstrap intervals, and the delay 95th percentile uses the "
            "nearest-rank empirical percentile in milliseconds."
        ),
        "sensitivity_axes": [
            (
                "The clean_autocorrelation arm varies the first-order autoregressive phi. It "
                "keeps covariance_scale at 1."
            ),
            (
                "The clean_covariance_sensitivity arm varies the declared covariance scale at "
                "phi 0. The clean_autocorrelation phi 0 arm is the scale 1 reference."
            ),
            (
                "The ordinary_missingness arm applies deterministic, independent Bernoulli "
                "acoustic misses. A continuity hole creates an explicit whole-detector "
                "generation reset. The record includes each reset."
            ),
        ],
        "calibration_diagnostics": _summarize_evidence_partition(
            records, "calibration", config
        ),
        "holdout_results": _summarize_evidence_partition(records, "holdout", config),
        "recorded_fixture": {
            "configured_path": config["recorded_fixture"]["path"],
            "resolved_path": EVIDENCE_FIXTURE_PATH,
            "sha256": EVIDENCE_FIXTURE_SHA256,
            "bytes": EVIDENCE_FIXTURE_BYTES,
            "observations": 476,
            "tracks": 1,
            "projection_observations": 0,
            "total_duration_ms": 15_800,
            "detector_generation_resets": 1,
            "tracks_with_detector_generation_resets": 1,
            "evidence_status": "not_estimable",
            "status_reasons": [
                "insufficient_duration: 15800 ms is below configured minimum 3600000 ms",
                "missing_consistency_projection",
            ],
        },
        "limitations": [
            (
                "Synthetic observations are controlled stress tests, not a deployed residual "
                "population or operational accuracy claim."
            ),
            (
                "The configured family_alpha value is a per-assessment family-wise bound under "
                "the detector model. It is not a stream false-alert-rate guarantee."
            ),
            (
                "Garwood episode-rate intervals assume a homogeneous Poisson count process. A "
                "whole-track bootstrap can expand these intervals when at least 80% of "
                "replicates are usable. Neither method creates an operational false-alert-rate "
                "claim for the controlled stream."
            ),
            "ARL0 is a finite-horizon restricted mean. Read it with its censoring fraction.",
            (
                "Attack delay and attribution are conditional on no pre-onset alert. Delay is "
                "also conditional on detection."
            ),
            (
                "Alert episodes use the configured nominal_only reset policy. Abstention "
                "preserves an active episode. Only a nominal assessment clears it."
            ),
            (
                "The default runner evaluates streaming normalized innovation squared (NIS) "
                "and signed correlation only. Partial information decomposition (PID) has no "
                "product streaming cadence in this revision."
            ),
            (
                "Independent missingness can cross an accepted continuity limit. Each such "
                "event creates a recorded whole-detector generation boundary. Post-reset "
                "warm-up remains abstention. The runner does not recode it as nominal."
            ),
        ],
    }


def _require_evidence_semantic_equality(
    supplied: Any,
    trusted: Any,
    *,
    path: str,
) -> None:
    """Require complete equality, with a bounded Garwood display allowance."""

    if isinstance(trusted, dict):
        if not isinstance(supplied, dict) or set(supplied) != set(trusted):
            raise ReviewError(f"candidate evidence summary field set differs at {path}")
        for key, value in trusted.items():
            _require_evidence_semantic_equality(
                supplied[key], value, path=f"{path}.{key}"
            )
        return
    if isinstance(trusted, list):
        if not isinstance(supplied, list) or len(supplied) != len(trusted):
            raise ReviewError(f"candidate evidence summary list differs at {path}")
        for index, value in enumerate(trusted):
            _require_evidence_semantic_equality(
                supplied[index], value, path=f"{path}[{index}]"
            )
        return
    if isinstance(trusted, float):
        if not _is_finite_f64_number(supplied):
            raise ReviewError(f"candidate evidence summary number is invalid at {path}")
        supplied_float = float(supplied)
        if supplied_float == 0.0 and math.copysign(1.0, supplied_float) < 0.0:
            raise ReviewError(f"candidate evidence summary uses negative zero at {path}")
        if _same_float(supplied_float, trusted):
            return
        if "metrics.false_alerts_per_hour.ci95" in path:
            left = _float_bits(supplied_float)
            right = _float_bits(trusted)
            if abs(left - right) <= 4_096:
                return
        raise ReviewError(f"candidate evidence summary number differs at {path}")
    if type(supplied) is not type(trusted) or supplied != trusted:
        raise ReviewError(f"candidate evidence summary value differs at {path}")


def _validate_evidence_manifest(
    value: Any,
    *,
    expected: CandidateEvidenceExpectations,
    config: dict[str, Any],
    config_binding: dict[str, Any],
    canonical_config_sha256: str,
    trial_records: list[dict[str, Any]],
) -> dict[str, Any]:
    """Validate all candidate-evidence manifest fields independently."""

    manifest = _require_evidence_keys(
        value,
        {
            "schema",
            "trial_schema",
            "summary_schema",
            "generator_profile",
            "recorded_replay_profile",
            "missingness_profile",
            "acceptance_metric_profile",
            "bootstrap_profile",
            "study_id",
            "base_seed_hex",
            "git",
            "toolchain",
            "inputs",
            "scope",
            "trial_records",
            "synthetic_tracks",
            "recorded_tracks",
            "dirty_override_used",
            "publication_source_policy",
            "accepted_config_profile",
            "accepted_config_digest",
            "deterministic_time_policy",
        },
        "candidate evidence manifest",
    )
    exact = {
        "schema": EVIDENCE_MANIFEST_SCHEMA,
        "trial_schema": EVIDENCE_TRIAL_SCHEMA,
        "summary_schema": EVIDENCE_SUMMARY_SCHEMA,
        "generator_profile": EVIDENCE_GENERATOR_PROFILE,
        "recorded_replay_profile": EVIDENCE_REPLAY_PROFILE,
        "missingness_profile": EVIDENCE_MISSINGNESS_PROFILE,
        "acceptance_metric_profile": EVIDENCE_ACCEPTANCE_PROFILE,
        "bootstrap_profile": EVIDENCE_BOOTSTRAP_PROFILE,
        "study_id": config["study_id"],
        "base_seed_hex": config["base_seed_hex"],
        "scope": list(EVIDENCE_SCOPE),
        "dirty_override_used": False,
        "publication_source_policy": "require_clean",
        "accepted_config_profile": EVIDENCE_ACCEPTED_PROFILE,
        "accepted_config_digest": config_binding["accepted_semantic_digest"],
        "deterministic_time_policy": (
            "The artifacts do not store a wall-clock timestamp. Deterministic artifacts depend "
            "only on declared inputs and recorded tool and source provenance."
        ),
    }
    if not isinstance(manifest["dirty_override_used"], bool):
        raise ReviewError("candidate evidence dirty override flag is not Boolean")
    for field, required in exact.items():
        if manifest[field] != required:
            raise ReviewError(f"candidate evidence manifest has another {field}")
    git_record = _require_evidence_keys(
        manifest["git"],
        {"commit", "tree", "dirty", "status_porcelain_v1"},
        "candidate evidence Git provenance",
    )
    if not isinstance(git_record["dirty"], bool):
        raise ReviewError("candidate evidence Git dirty flag is not Boolean")
    if git_record != {
        "commit": expected.commit,
        "tree": expected.tree,
        "dirty": False,
        "status_porcelain_v1": "",
    }:
        raise ReviewError("candidate evidence manifest targets another Git state")
    toolchain = _require_evidence_keys(
        manifest["toolchain"],
        {
            "rustc_verbose",
            "cargo_version",
            "package_version",
            "build_profile",
            "target_os",
            "target_arch",
            "available_parallelism",
        },
        "candidate evidence toolchain provenance",
    )
    parallelism = _evidence_integer(
        toolchain["available_parallelism"],
        "candidate evidence available parallelism",
        minimum=1,
        maximum=4_096,
    )
    if toolchain != {
        "rustc_verbose": expected.rustc_verbose,
        "cargo_version": expected.cargo_version,
        "package_version": VERSION,
        "build_profile": "release",
        "target_os": expected.target_os,
        "target_arch": expected.target_arch,
        "available_parallelism": parallelism,
    }:
        raise ReviewError("candidate evidence manifest has another toolchain")
    inputs = _require_evidence_keys(
        manifest["inputs"],
        {
            "config_source_path",
            "config_source_sha256",
            "canonical_config_sha256",
            "workspace_manifest_sha256",
            "cargo_lock_sha256",
            "recorded_fixture_path",
            "recorded_fixture_sha256",
            "runner_binary_sha256",
        },
        "candidate evidence input provenance",
    )
    if inputs != {
        "config_source_path": expected.tracked_config_path,
        "config_source_sha256": hashlib.sha256(expected.tracked_config_bytes).hexdigest(),
        "canonical_config_sha256": canonical_config_sha256,
        "workspace_manifest_sha256": expected.workspace_manifest_sha256,
        "cargo_lock_sha256": expected.cargo_lock_sha256,
        "recorded_fixture_path": EVIDENCE_FIXTURE_PATH,
        "recorded_fixture_sha256": EVIDENCE_FIXTURE_SHA256,
        "runner_binary_sha256": expected.runner_binary_sha256,
    }:
        raise ReviewError("candidate evidence manifest has another input identity")
    synthetic_records = sum(record["source"] == "synthetic" for record in trial_records)
    recorded_records = sum(record["source"] == "recorded" for record in trial_records)
    expected_counts = {
        "trial_records": len(trial_records),
        "synthetic_tracks": synthetic_records // 2,
        "recorded_tracks": recorded_records // 2,
    }
    for field, required in expected_counts.items():
        if _evidence_integer(manifest[field], f"candidate evidence manifest {field}") != required:
            raise ReviewError(f"candidate evidence manifest has another {field}")
    return manifest


def _evidence_metric_text(metric: dict[str, Any]) -> str:
    value = metric["value"]
    interval = metric["ci95"]
    if value is not None and interval is not None:
        return f"{value:.4f} [{interval[0]:.4f}, {interval[1]:.4f}]"
    if value is not None:
        return f"{value:.4f} ({metric['status']}/{metric['ci_status']})"
    return metric["status"]


def _render_evidence_report(
    summary: dict[str, Any],
    manifest: dict[str, Any],
) -> bytes:
    """Render the exact independent Markdown view of validated evidence."""

    report = "# Galadriel post-audit evidence\n\n"
    report += f"Study: `{summary['study_id']}`\n\n"
    report += f"Git commit: `{manifest['git']['commit']}`\n\n"
    report += (
        "Dirty worktree at invocation: `"
        + str(manifest["git"]["dirty"]).lower()
        + "`\n\n"
    )
    report += (
        "Only holdout rows below support reported results. `summary.json` retains calibration "
        "tracks as separate diagnostics. The runner does not pool calibration and holdout "
        "tracks.\n\n"
    )
    report += (
        "Track proportions use preregistered Wilson intervals. Alert-episode rates use labeled "
        "Garwood Poisson intervals. Average run length under no-alert conditions (ARL0) and "
        "abstention use bounded-track Hoeffding intervals. Delay summaries use whole-track "
        "bootstrap intervals. A declared bootstrap envelope does not replace its boundary-safe "
        "analytic interval.\n\n"
    )
    report += (
        "Alert episodes reset only on an explicit nominal assessment. Insufficient and "
        "rejected-input outcomes preserve an active episode. Rejected inputs count toward "
        "abstention.\n\n"
    )
    report += (
        "| condition | detector | exposure hours | generation resets (affected tracks) | false "
        "alerts per hour | mission probability of any alert | restricted ARL0 | ARL0 censored "
        "fraction | abstention | provenance probability of any alert | pre-onset probability | "
        "conditional detection | median delay in frames | delay 95th percentile in milliseconds "
        "| attribution coverage | attribution error | attribution accuracy |\n"
    )
    report += (
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n"
    )
    for condition in summary["holdout_results"]:
        metrics = condition["metrics"]
        cells = [
            condition["condition"],
            condition["detector"],
            f"{condition['exposure_hours']:.4f}",
            (
                f"{condition['detector_generation_resets']} "
                f"({condition['tracks_with_detector_generation_resets']})"
            ),
            _evidence_metric_text(metrics["false_alerts_per_hour"]),
            _evidence_metric_text(metrics["mission_probability_any_alert"]),
            _evidence_metric_text(metrics["arl0_assessments"]),
            _evidence_metric_text(metrics["arl0_censoring_fraction"]),
            _evidence_metric_text(metrics["abstention_fraction"]),
            _evidence_metric_text(metrics["any_alert_probability"]),
            _evidence_metric_text(metrics["pre_onset_alert_probability"]),
            _evidence_metric_text(metrics["conditional_detection_probability"]),
            _evidence_metric_text(metrics["conditional_delay_frames"]),
            _evidence_metric_text(metrics["conditional_delay_p95_ms"]),
            _evidence_metric_text(metrics["conditional_attribution_coverage"]),
            _evidence_metric_text(metrics["conditional_attribution_error"]),
            _evidence_metric_text(metrics["conditional_attribution_accuracy"]),
        ]
        report += "| " + " | ".join(cells) + " |\n"
    report += (
        "\n`summary.json` retains exact event, eligibility, undetected, emitted-attribution, "
        "correct-attribution, and wrong-attribution counts for each row. `trials.jsonl` retains "
        "per-track delays and outcomes.\n"
    )
    fixture = summary["recorded_fixture"]
    report += "\n## Recorded fixture\n\n"
    report += (
        f"Status: `{fixture['evidence_status']}`.\n\n"
        f"The fixture contains {fixture['observations']} observations across {fixture['tracks']} "
        f"tracks. Its total observed duration is {fixture['total_duration_ms']} milliseconds. It "
        f"contains {fixture['projection_observations']} observations with a consistency "
        f"projection. It records {fixture['detector_generation_resets']} explicit "
        "detector-generation resets across "
        f"{fixture['tracks_with_detector_generation_resets']} tracks.\n\n"
    )
    if fixture["status_reasons"]:
        report += "Reasons:\n\n"
        report += "".join(f"- {reason}\n" for reason in fixture["status_reasons"])
        report += "\n"
    report += (
        "The checked-in capture is a parser, provenance, and abstention smoke test. The runner "
        "does not extrapolate its short duration into an operational false-alert rate or "
        "detection claim.\n\n"
    )
    report += "## Interpretation limits\n\n"
    report += "".join(f"- {limitation}\n" for limitation in summary["limitations"])
    return report.encode("utf-8")


def _validate_evidence_sha256sums(
    payload: bytes,
    artifacts: dict[str, dict[str, Any]],
) -> None:
    """Require the exact five-row inner checksum document."""

    expected = "".join(
        f"{artifacts[name]['sha256']}  {name}\n" for name in EVIDENCE_CHECKSUM_FILES
    ).encode("ascii")
    if payload != expected:
        raise ReviewError("candidate evidence SHA256SUMS is not exact")


def validate_candidate_evidence_bundle(
    root: Path,
    *,
    expected: CandidateEvidenceExpectations,
    expected_outer_artifacts: dict[str, dict[str, Any]] | None = None,
) -> ValidatedCandidateEvidence:
    """Validate and independently reconstruct one complete evidence bundle."""

    if not isinstance(expected, CandidateEvidenceExpectations):
        raise ReviewError("candidate evidence expectations are invalid")
    if GIT_OBJECT.fullmatch(expected.commit) is None or GIT_OBJECT.fullmatch(expected.tree) is None:
        raise ReviewError("candidate evidence expected Git identity is invalid")
    for label, digest in (
        ("workspace manifest", expected.workspace_manifest_sha256),
        ("Cargo lockfile", expected.cargo_lock_sha256),
        ("runner binary", expected.runner_binary_sha256),
    ):
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            raise ReviewError(f"candidate evidence expected {label} digest is invalid")
    canonical_relative_parts(expected.tracked_config_path, label="candidate evidence config path")

    before = _candidate_evidence_tree(root, "candidate evidence before semantic validation")
    documents = _capture_candidate_evidence_documents(root, before)
    artifacts = {
        name: {
            "sha256": before[name].sha256,
            "size_bytes": before[name].size_bytes,
        }
        for name in EVIDENCE_FILES
    }
    if expected_outer_artifacts is not None:
        if (
            not isinstance(expected_outer_artifacts, dict)
            or set(expected_outer_artifacts) != set(EVIDENCE_FILES)
        ):
            raise ReviewError("signed candidate evidence artifact set is not exact")
        for name, row in expected_outer_artifacts.items():
            if (
                not isinstance(row, dict)
                or set(row) != {"sha256", "size_bytes"}
                or SHA256.fullmatch(str(row.get("sha256"))) is None
                or type(row.get("size_bytes")) is not int
                or row["size_bytes"] < 0
            ):
                raise ReviewError(f"signed candidate evidence row is invalid: {name}")
        if artifacts != expected_outer_artifacts:
            raise ReviewError("candidate evidence differs from its signed outer inventory")

    accepted_config = _bounded_evidence_object(
        documents["config.json"].data,
        "accepted candidate evidence config",
    )
    manifest_value = _bounded_evidence_object(
        documents["manifest.json"].data,
        "candidate evidence manifest",
    )
    config_binding = validate_evidence_config_bytes(
        expected.tracked_config_bytes,
        documents["config.json"].data,
        documents["manifest.json"].data,
        tracked_relative_path=expected.tracked_config_path,
    )
    trials, trials_sha256, trials_size = _stream_validate_evidence_trials(
        root,
        expected_digest=before["trials.jsonl"].sha256,
        expected_size=before["trials.jsonl"].size_bytes,
        config=accepted_config,
    )
    if (
        trials_sha256 != artifacts["trials.jsonl"]["sha256"]
        or trials_size != artifacts["trials.jsonl"]["size_bytes"]
    ):
        raise ReviewError("candidate evidence trial identity is inconsistent")
    manifest = _validate_evidence_manifest(
        manifest_value,
        expected=expected,
        config=accepted_config,
        config_binding=config_binding,
        canonical_config_sha256=artifacts["config.json"]["sha256"],
        trial_records=trials,
    )
    supplied_summary = _bounded_evidence_object(
        documents["summary.json"].data,
        "candidate evidence summary",
    )
    trusted_summary = _recompute_evidence_summary(trials, accepted_config)
    _require_evidence_semantic_equality(
        supplied_summary,
        trusted_summary,
        path="summary",
    )
    supplied_report = documents["report.md"].data
    if (
        supplied_report != _render_evidence_report(supplied_summary, manifest)
        or supplied_report != _render_evidence_report(trusted_summary, manifest)
    ):
        raise ReviewError("candidate evidence report differs from trusted reconstruction")
    _validate_evidence_sha256sums(documents["SHA256SUMS"].data, artifacts)
    after = _candidate_evidence_tree(root, "candidate evidence after semantic validation")
    if before != after:
        raise ReviewError("candidate evidence changed during semantic validation")

    acceptance = evaluate_acceptance(trusted_summary, accepted_config)
    semantic_record = {
        "schema": "galadriel.candidate-evidence-validation.v1",
        "candidate": {"commit": expected.commit, "tree": expected.tree},
        "artifacts": artifacts,
        "accepted_config_digest": config_binding["accepted_semantic_digest"],
        "acceptance_metric_profile": EVIDENCE_ACCEPTANCE_PROFILE,
        "bootstrap_profile": EVIDENCE_BOOTSTRAP_PROFILE,
        "trusted_summary_sha256": hashlib.sha256(
            json.dumps(
                trusted_summary,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest(),
        "acceptance": acceptance,
    }
    semantic_sha256 = hashlib.sha256(
        b"galadriel-candidate-evidence-validation-v1\0"
        + json.dumps(
            semantic_record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return ValidatedCandidateEvidence(
        artifacts=artifacts,
        config_binding=config_binding,
        manifest=manifest,
        summary=trusted_summary,
        acceptance=acceptance,
        semantic_sha256=semantic_sha256,
    )


def validate_github_mutation_run(
    value: Any,
    *,
    commit: str,
    context: str,
    allow_null: bool = False,
) -> dict[str, str] | None:
    """Validate exact GitHub Actions provenance for one mutation job."""

    if value is None and allow_null:
        return None
    require_keys(
        value,
        {"run_id", "run_attempt", "job", "workflow", "repository", "ref", "sha"},
        context,
    )
    result: dict[str, str] = {}
    for field in (
        "run_id",
        "run_attempt",
        "job",
        "workflow",
        "repository",
        "ref",
        "sha",
    ):
        result[field] = _focused_exact_text(value[field], f"{context} {field}")
        if len(result[field].encode("utf-8")) > 512:
            raise ReviewError(f"{context} {field} exceeds 512 bytes")
    if len(result["run_id"]) > 20 or not re.fullmatch(r"[1-9][0-9]*", result["run_id"]):
        raise ReviewError(f"{context} has an invalid run ID")
    if len(result["run_attempt"]) > 20 or not re.fullmatch(
        r"[1-9][0-9]*", result["run_attempt"]
    ):
        raise ReviewError(f"{context} has an invalid run attempt")
    if (
        result["job"] != "mutation-diff"
        or result["workflow"] != "Deep quality"
        or result["repository"] != "sepahead/galadriel"
        or result["sha"] != commit
    ):
        raise ReviewError(f"{context} targets another workflow or candidate")
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
    canonical_pull = re.fullmatch(r"refs/pull/[1-9][0-9]*/merge", ref)
    if not canonical_branch and not canonical_pull:
        raise ReviewError(f"{context} has an invalid GitHub reference")
    return result


def _validate_broad_mutation_receipt_document(
    document: Any,
    *,
    root: Path,
    commit: str,
    tree: str,
    shard: str,
    diff: bytes,
    outcome_artifact: MutationArtifactCapture | None = None,
) -> tuple[dict[str, Any], Path]:
    """Validate one captured broad receipt and its captured outcomes."""

    require_keys(
        document,
        {
            "schema",
            "candidate",
            "baseline_commit",
            "shard",
            "github_run",
            "git_diff",
            "command_argv",
            "environment_contract",
            "toolchain",
            "exit_code",
            "status",
            "counts",
            "outcomes",
        },
        "broad mutation run receipt",
    )
    if document["schema"] != "galadriel.broad-mutation-run.v2":
        raise ReviewError("broad mutation run receipt has another schema")
    if document["candidate"] != {"commit": commit, "tree": tree}:
        raise ReviewError("broad mutation run receipt targets another candidate")
    if document["baseline_commit"] != MUTATION_BASELINE_COMMIT:
        raise ReviewError("broad mutation run receipt targets another baseline")
    if shard not in {"0/4", "1/4", "2/4", "3/4"} or document["shard"] != shard:
        raise ReviewError("broad mutation run receipt targets another shard")
    validate_github_mutation_run(
        document["github_run"],
        commit=commit,
        context="broad mutation GitHub run",
        allow_null=True,
    )

    diff_record = document["git_diff"]
    require_digest_record(diff_record, "broad mutation run diff")
    if (
        diff_record["path"] != "git.diff"
        or diff_record["sha256"] != sha256_bytes(diff)
        or diff_record["size_bytes"] != len(diff)
    ):
        raise ReviewError("broad mutation run receipt targets other diff bytes")
    if not diff:
        raise ReviewError("broad mutation run receipt targets an empty diff")
    if len(diff) > MAX_MUTATION_DIFF_BYTES:
        raise ReviewError("broad mutation run diff exceeds its byte limit")
    if document["command_argv"] != broad_mutation_command(shard):
        raise ReviewError("broad mutation run receipt used another command")
    if document["environment_contract"] != MUTATION_ENVIRONMENT_CONTRACT:
        raise ReviewError("broad mutation run used another environment contract")

    toolchain = document["toolchain"]
    require_keys(
        toolchain,
        {"cargo", "cargo_executable", "cargo_mutants", "rustc"},
        "broad mutation run toolchain",
    )
    cargo_executable = _focused_exact_text(
        toolchain["cargo_executable"], "broad mutation Cargo executable"
    )
    if (
        not Path(cargo_executable).is_absolute()
        or Path(cargo_executable).name != "cargo"
    ):
        raise ReviewError(
            "broad mutation Cargo executable is not an absolute cargo path"
        )
    if toolchain != {
        "cargo": CARGO_IDENTITY,
        "cargo_executable": cargo_executable,
        "cargo_mutants": CARGO_MUTANTS_IDENTITY,
        "rustc": RUSTC_IDENTITY,
    }:
        raise ReviewError("broad mutation run used another pinned toolchain")
    if type(document["exit_code"]) is not int or document["exit_code"] != 0:
        raise ReviewError("broad mutation run did not retain a zero exit status")
    if document["status"] != "PASS":
        raise ReviewError("broad mutation run did not pass")

    outcome_record = document["outcomes"]
    require_digest_record(outcome_record, "broad mutation run outcomes")
    if outcome_record["path"] != "mutants.out/outcomes.json":
        raise ReviewError("broad mutation run receipt targets another outcome path")
    expected_target = _mutation_artifact_path(
        root,
        outcome_record["path"],
        context="broad mutation outcomes",
    )
    if outcome_artifact is None:
        outcome_artifact = _capture_mutation_artifact(
            root,
            outcome_record["path"],
            max_bytes=MAX_MUTATION_OUTCOMES_BYTES,
            expected_size=outcome_record["size_bytes"],
            context="broad mutation outcomes",
        )
    elif outcome_artifact.path != expected_target:
        raise ReviewError("broad mutation run outcome came from another path")
    if (
        outcome_record["sha256"] != outcome_artifact.capture.sha256
        or outcome_record["size_bytes"] != outcome_artifact.capture.size_bytes
    ):
        raise ReviewError("broad mutation run outcome digest mismatch")
    outcome_document = _load_mutation_json(
        outcome_artifact.capture.data,
        max_depth=16,
        max_nodes=500_000,
        label=f"mutation shard {shard} outcomes",
    )
    counts = _validate_mutation_outcomes_document(
        outcome_document,
        shard,
        expected_cargo_executable=cargo_executable,
    )
    recorded_counts = document["counts"]
    require_keys(recorded_counts, set(counts), "broad mutation run counts")
    if any(type(value) is not int or value < 0 for value in recorded_counts.values()):
        raise ReviewError("broad mutation run has noncanonical counts")
    if recorded_counts != counts:
        raise ReviewError("broad mutation run count record drifted")
    return document, outcome_artifact.path


def validate_broad_mutation_receipt(
    path: Path,
    *,
    root: Path,
    commit: str,
    tree: str,
    shard: str,
    diff: bytes,
) -> tuple[dict[str, Any], Path]:
    """Bind one broad mutation outcome to its exact isolated execution."""

    expected_path = _mutation_artifact_path(
        root,
        BROAD_MUTATION_RECEIPT,
        context="broad mutation run receipt",
    )
    actual_path = Path(os.path.abspath(os.fspath(path.expanduser())))
    if actual_path != expected_path:
        raise ReviewError("broad mutation run receipt is outside its artifact root")
    receipt = _capture_mutation_artifact(
        root,
        BROAD_MUTATION_RECEIPT,
        max_bytes=MAX_MUTATION_RECEIPT_BYTES,
        context="broad mutation run receipt",
    )
    document = _load_mutation_json(
        receipt.capture.data,
        max_depth=16,
        max_nodes=100_000,
        label="broad mutation run receipt",
    )
    return _validate_broad_mutation_receipt_document(
        document,
        root=root,
        commit=commit,
        tree=tree,
        shard=shard,
        diff=diff,
    )


def _verify_mutation_signature(
    document: bytes,
    signature: bytes,
    allowed_signers: Path,
    *,
    document_name: str,
) -> None:
    """Verify one mutation manifest against its captured detached signature."""

    allowed_signers_bytes = read_bounded_regular_file(
        allowed_signers,
        max_bytes=MAX_ALLOWED_SIGNERS_BYTES,
        label="allowed-signers trust root",
    )
    with tempfile.TemporaryDirectory(
        prefix="galadriel-mutation-signature-verification-"
    ) as name:
        root = Path(name)
        signature_snapshot = root / "signature"
        allowed_signers_snapshot = root / "allowed-signers"
        signature_snapshot.write_bytes(signature)
        allowed_signers_snapshot.write_bytes(allowed_signers_bytes)
        os.chmod(signature_snapshot, 0o600)
        os.chmod(allowed_signers_snapshot, 0o600)
        process = run_bounded_host_command(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(allowed_signers_snapshot),
                "-I",
                SIGNING_PRINCIPAL,
                "-n",
                "galadriel-mutation-evidence",
                "-s",
                str(signature_snapshot),
            ],
            context="SSH mutation evidence signature verification",
            stdin_document=document,
            environment=_ssh_host_environment(use_agent=False),
        )
    if process.returncode != 0:
        raise ReviewError(
            f"invalid galadriel-mutation-evidence signature for {document_name}: "
            f"command exited with {process.returncode}"
        )


def validate_mutation_evidence(
    manifest_path: Path,
    signature_path: Path,
    *,
    allowed_signers: Path,
    repo: Path,
    commit: str,
    tree: str,
) -> ValidatedMutationEvidence:
    """Validate signed exact-diff shards and focused liveness checks."""

    artifact_root = manifest_path.parent
    manifest_relative = manifest_path.name
    manifest = _capture_mutation_artifact(
        artifact_root,
        manifest_relative,
        max_bytes=MAX_MUTATION_MANIFEST_BYTES,
        context="mutation evidence manifest",
    )
    signature_relative = signature_path.name
    expected_signature_path = _mutation_artifact_path(
        artifact_root,
        signature_relative,
        context="mutation evidence signature",
    )
    actual_signature_path = Path(
        os.path.abspath(os.fspath(signature_path.expanduser()))
    )
    if actual_signature_path != expected_signature_path:
        raise ReviewError("mutation evidence signature is outside its artifact root")
    if signature_relative == manifest_relative:
        raise ReviewError("mutation evidence signature aliases its manifest")
    signature = _capture_mutation_artifact(
        artifact_root,
        signature_relative,
        max_bytes=MAX_SIGNATURE_BYTES,
        context="mutation evidence signature",
    )
    _verify_mutation_signature(
        manifest.capture.data,
        signature.capture.data,
        allowed_signers,
        document_name=manifest_path.name,
    )
    document = _load_mutation_json(
        manifest.capture.data,
        max_depth=32,
        max_nodes=250_000,
        label="mutation evidence manifest",
    )
    require_keys(
        document,
        {
            "schema",
            "release",
            "author",
            "candidate",
            "baseline_commit",
            "github_run",
            "git_diff_argv",
            "git_diff_sha256",
            "git_diff",
            "tool",
            "shards",
            "broad_run_receipts",
            "focused_run_receipt",
            "focused_checks",
        },
        "mutation evidence",
    )
    if (
        document["schema"] != "galadriel.mutation-evidence.v5"
        or document["release"] != VERSION
        or document["author"] != AUTHOR
    ):
        raise ReviewError("mutation evidence has the wrong schema, release, or author")
    if document["candidate"] != {"commit": commit, "tree": tree}:
        raise ReviewError("mutation evidence targets the wrong candidate")
    baseline = document["baseline_commit"]
    if baseline != MUTATION_BASELINE_COMMIT:
        raise ReviewError("mutation evidence targets the wrong frozen baseline")
    github_run = validate_github_mutation_run(
        document["github_run"],
        commit=commit,
        context="mutation evidence GitHub run",
    )
    if github_run is None:
        raise ReviewError("mutation evidence lacks GitHub run provenance")
    expected_diff_argv = ["git", *MUTATION_DIFF_OPTIONS, f"{baseline}..{commit}", "--"]
    if document["git_diff_argv"] != expected_diff_argv:
        raise ReviewError("mutation evidence used another Git diff contract")
    git(repo, "merge-base", "--is-ancestor", baseline, commit)
    diff = git_bounded_output(
        repo,
        *expected_diff_argv[1:],
        max_bytes=MAX_MUTATION_DIFF_BYTES,
    )
    if not diff:
        raise ReviewError("mutation evidence has an empty frozen-baseline diff")
    diff_digest = sha256_bytes(diff)
    if document["git_diff_sha256"] != diff_digest:
        raise ReviewError("mutation evidence targets different candidate diff bytes")
    diff_record = document["git_diff"]
    require_digest_record(diff_record, "mutation evidence retained Git diff")
    if (
        diff_record["path"] != "git.diff"
        or diff_record["sha256"] != diff_digest
        or diff_record["size_bytes"] != len(diff)
    ):
        raise ReviewError("mutation evidence retained Git diff record is not exact")
    protected_paths = {manifest_relative, signature_relative}
    if diff_record["path"] in protected_paths:
        raise ReviewError("mutation evidence cannot reference its control files")
    retained_diff = _capture_mutation_artifact(
        artifact_root,
        diff_record["path"],
        max_bytes=MAX_MUTATION_DIFF_BYTES,
        expected_size=diff_record["size_bytes"],
        context="retained mutation Git diff",
    )
    if (
        retained_diff.capture.data != diff
        or retained_diff.capture.sha256 != diff_record["sha256"]
    ):
        raise ReviewError("mutation evidence retained other Git diff bytes")
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
    artifacts = [retained_diff]
    artifact_paths: set[str] = {retained_diff.relative}
    aggregate_size = (
        manifest.capture.size_bytes
        + signature.capture.size_bytes
        + retained_diff.capture.size_bytes
    )
    if aggregate_size > MAX_MUTATION_EVIDENCE_BYTES:
        raise ReviewError("mutation evidence exceeds its aggregate byte limit")
    shard_outcomes: dict[str, Path] = {}
    shard_outcome_artifacts: dict[str, MutationArtifactCapture] = {}
    broad_signatures: set[BroadMutant] = set()
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
        expected_relative = (
            f"broad-runs/{shard['id'].replace('/', '-of-')}/mutants.out/outcomes.json"
        )
        if relative != expected_relative:
            raise ReviewError(f"mutation shard {shard['id']} has another outcome path")
        if relative in protected_paths:
            raise ReviewError(
                "mutation evidence cannot reference its own manifest or signature"
            )
        if relative in artifact_paths:
            raise ReviewError(
                "mutation shards must reference distinct outcomes artifacts"
            )
        captured = _capture_mutation_artifact(
            artifact_root,
            relative,
            max_bytes=MAX_MUTATION_OUTCOMES_BYTES,
            expected_size=artifact["size_bytes"],
            context=f"mutation shard {shard['id']} outcomes",
        )
        if artifact["sha256"] != captured.capture.sha256:
            raise ReviewError(f"mutation shard artifact digest mismatch: {relative}")
        outcome_document = _load_mutation_json(
            captured.capture.data,
            max_depth=16,
            max_nodes=500_000,
            label=f"mutation shard {shard['id']} outcomes",
        )
        _validate_mutation_outcomes_document(
            outcome_document,
            shard["id"],
            validate_broad_details=False,
        )
        signatures = _validate_broad_outcome_details(
            outcome_document,
            shard_id=shard["id"],
            expected_cargo_executable=None,
        )
        overlap = broad_signatures.intersection(signatures)
        if overlap:
            raise ReviewError(
                f"mutation shard {shard['id']} duplicates another shard mutant"
            )
        broad_signatures.update(signatures)
        aggregate_size += captured.capture.size_bytes
        if aggregate_size > MAX_MUTATION_EVIDENCE_BYTES:
            raise ReviewError("mutation evidence exceeds its aggregate byte limit")
        artifact_paths.add(relative)
        artifacts.append(captured)
        shard_outcomes[shard["id"]] = captured.path
        shard_outcome_artifacts[shard["id"]] = captured

    broad_receipts = document["broad_run_receipts"]
    if (
        not isinstance(broad_receipts, list)
        or [item.get("shard") for item in broad_receipts if isinstance(item, dict)]
        != expected_ids
    ):
        raise ReviewError("mutation evidence must contain ordered broad run receipts")
    for record in broad_receipts:
        require_keys(record, {"shard", "artifact"}, "broad mutation run record")
        shard_id = record["shard"]
        artifact = record["artifact"]
        require_digest_record(artifact, "broad mutation run receipt artifact")
        expected_path = (
            f"broad-runs/{shard_id.replace('/', '-of-')}/{BROAD_MUTATION_RECEIPT}"
        )
        if artifact["path"] != expected_path:
            raise ReviewError(f"broad mutation run receipt {shard_id} has another path")
        if expected_path in protected_paths or expected_path in artifact_paths:
            raise ReviewError(
                f"broad mutation run receipt {shard_id} is missing or unsafe"
            )
        captured = _capture_mutation_artifact(
            artifact_root,
            expected_path,
            max_bytes=MAX_MUTATION_RECEIPT_BYTES,
            expected_size=artifact["size_bytes"],
            context=f"broad mutation run receipt {shard_id}",
        )
        if artifact["sha256"] != captured.capture.sha256:
            raise ReviewError(f"broad mutation run receipt {shard_id} digest mismatch")
        receipt_value = _load_mutation_json(
            captured.capture.data,
            max_depth=16,
            max_nodes=100_000,
            label=f"broad mutation run receipt {shard_id}",
        )
        receipt_document, receipt_outcome = _validate_broad_mutation_receipt_document(
            receipt_value,
            root=captured.path.parent,
            commit=commit,
            tree=tree,
            shard=shard_id,
            diff=diff,
            outcome_artifact=shard_outcome_artifacts[shard_id],
        )
        if receipt_document["github_run"] != github_run:
            raise ReviewError(
                f"broad mutation run receipt {shard_id} targets another GitHub run"
            )
        if receipt_outcome != shard_outcomes[shard_id]:
            raise ReviewError(
                f"broad mutation shard {shard_id} differs from its run receipt"
            )
        aggregate_size += captured.capture.size_bytes
        if aggregate_size > MAX_MUTATION_EVIDENCE_BYTES:
            raise ReviewError("mutation evidence exceeds its aggregate byte limit")
        artifact_paths.add(expected_path)
        artifacts.append(captured)

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
    if (
        FOCUSED_MUTATION_RECEIPT in protected_paths
        or FOCUSED_MUTATION_RECEIPT in artifact_paths
    ):
        raise ReviewError("focused mutation run receipt artifact is missing or unsafe")
    focused_receipt = _capture_mutation_artifact(
        artifact_root,
        FOCUSED_MUTATION_RECEIPT,
        max_bytes=MAX_MUTATION_RECEIPT_BYTES,
        expected_size=receipt_artifact["size_bytes"],
        context="focused mutation run receipt",
    )
    if receipt_artifact["sha256"] != focused_receipt.capture.sha256:
        raise ReviewError("focused mutation run receipt artifact digest mismatch")
    focused_receipt_value = _load_mutation_json(
        focused_receipt.capture.data,
        max_depth=16,
        max_nodes=100_000,
        label="focused mutation run receipt",
    )
    (
        receipt_document,
        receipt_outcomes,
        focused_outcome_artifacts,
    ) = _validate_focused_mutation_receipt_document(
        focused_receipt_value,
        root=artifact_root,
        commit=commit,
        tree=tree,
    )
    if receipt_document["github_run"] != github_run:
        raise ReviewError("focused mutation run receipt targets another GitHub run")
    aggregate_size += focused_receipt.capture.size_bytes
    if aggregate_size > MAX_MUTATION_EVIDENCE_BYTES:
        raise ReviewError("mutation evidence exceeds its aggregate byte limit")
    artifact_paths.add(FOCUSED_MUTATION_RECEIPT)
    artifacts.append(focused_receipt)

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
        captured = focused_outcome_artifacts[check_id]
        if relative != captured.relative or captured.path != receipt_outcomes[check_id]:
            raise ReviewError(
                f"focused mutation check {check_id} differs from its run receipt"
            )
        if relative in protected_paths or relative in artifact_paths:
            raise ReviewError(
                f"focused mutation check {check_id} references a duplicate artifact"
            )
        if (
            artifact["sha256"] != captured.capture.sha256
            or artifact["size_bytes"] != captured.capture.size_bytes
        ):
            raise ReviewError(f"focused mutation artifact digest mismatch: {relative}")
        aggregate_size += captured.capture.size_bytes
        if aggregate_size > MAX_MUTATION_EVIDENCE_BYTES:
            raise ReviewError("mutation evidence exceeds its aggregate byte limit")
        artifact_paths.add(relative)
        artifacts.append(captured)
    return ValidatedMutationEvidence(
        document=document,
        manifest=manifest,
        signature=signature,
        artifacts=tuple(artifacts),
    )


def _validate_mutation_outcomes_document(
    document: Any,
    shard_id: str,
    *,
    expected_cargo_executable: str | None = None,
    validate_broad_details: bool = True,
) -> dict[str, int]:
    """Validate one already captured cargo-mutants outcomes document."""

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
        if type(value) is not int or value < 0:
            raise ReviewError(f"mutation shard {shard_id} has an invalid {field} count")
        counts[field] = value
    if counts["total_mutants"] <= 0 or counts["caught"] <= 0:
        raise ReviewError(f"mutation shard {shard_id} is vacuous or caught no mutants")
    if counts["missed"] or counts["timeout"] or counts["success"]:
        raise ReviewError(
            f"mutation shard {shard_id} contains missed, timed-out, or surviving mutants"
        )
    if counts["total_mutants"] != sum(
        counts[field]
        for field in ("missed", "caught", "timeout", "unviable", "success")
    ):
        raise ReviewError(f"mutation shard {shard_id} summary counts are inconsistent")

    outcomes = document["outcomes"]
    if not isinstance(outcomes, list):
        raise ReviewError(f"mutation shard {shard_id} outcomes must be a list")
    if len(outcomes) != counts["total_mutants"] + 1:
        raise ReviewError(f"mutation shard {shard_id} outcome count is inconsistent")
    baseline: list[str] = []
    mutant_summaries: Counter[str] = Counter()
    for index, outcome in enumerate(outcomes):
        context = f"mutation shard {shard_id} outcome {index}"
        require_keys(
            outcome,
            {"scenario", "summary", "log_path", "diff_path", "phase_results"},
            context,
        )
        scenario = outcome["scenario"]
        summary = outcome["summary"]
        if scenario == "Baseline":
            baseline.append(summary)
        elif isinstance(scenario, dict) and set(scenario) == {"Mutant"}:
            if not isinstance(summary, str):
                raise ReviewError(f"{context} mutant outcome lacks a summary")
            mutant_summaries[summary] += 1
        else:
            raise ReviewError(f"{context} contains an unknown scenario")
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
    if shard_id in BROAD_MUTATION_SHARDS:
        if counts["total_mutants"] < BROAD_MUTATION_MINIMUM_TOTAL:
            raise ReviewError(
                f"mutation shard {shard_id} has fewer than "
                f"{BROAD_MUTATION_MINIMUM_TOTAL} mutants"
            )
        if counts["caught"] * 100 < counts["total_mutants"] * int(
            BROAD_MUTATION_MINIMUM_CAUGHT_RATIO * 100
        ):
            raise ReviewError(
                f"mutation shard {shard_id} caught less than "
                f"{BROAD_MUTATION_MINIMUM_CAUGHT_RATIO:.0%} of mutants"
            )
        if validate_broad_details:
            _validate_broad_outcome_details(
                document,
                shard_id=shard_id,
                expected_cargo_executable=expected_cargo_executable,
            )
    return counts


def _capture_mutation_outcomes(path: Path, shard_id: str) -> MutationArtifactCapture:
    """Capture one standalone outcomes document through its parent root."""

    if path.name != "outcomes.json":
        raise ReviewError(f"mutation shard {shard_id} artifact must be outcomes.json")
    return _capture_mutation_artifact(
        path.parent,
        path.name,
        max_bytes=MAX_MUTATION_OUTCOMES_BYTES,
        context=f"mutation shard {shard_id} outcomes",
    )


def validate_mutation_outcomes(
    path: Path,
    shard_id: str,
    *,
    expected_cargo_executable: str | None = None,
) -> dict[str, int]:
    """Reject incomplete, missed, timed-out, or weak cargo-mutants outcomes."""

    artifact = _capture_mutation_outcomes(path, shard_id)
    document = _load_mutation_json(
        artifact.capture.data,
        max_depth=16,
        max_nodes=500_000,
        label=f"mutation shard {shard_id} outcomes",
    )
    return _validate_mutation_outcomes_document(
        document,
        shard_id,
        expected_cargo_executable=expected_cargo_executable,
    )


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
    result = coordinates[0], coordinates[1], coordinates[2], coordinates[3]
    if result[:2] > result[2:]:
        raise ReviewError(f"{context} ends before it starts")
    return result


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
        _focused_exact_text(
            value["replacement"], f"{context} replacement", allow_empty=True
        ),
        _focused_exact_text(value["genre"], f"{context} genre"),
    )


def _validate_broad_phase(
    value: Any,
    *,
    context: str,
    expected_phase: str,
    expected_status: Any,
    expected_package: str | None,
    expected_packages: tuple[str, ...] | None,
    expected_cargo_executable: str | None,
) -> tuple[str, ...]:
    """Validate one broad mutation phase and return its target packages."""

    require_keys(value, {"phase", "duration", "process_status", "argv"}, context)
    if value["phase"] != expected_phase:
        raise ReviewError(f"{context} is not the expected {expected_phase} phase")
    duration = value["duration"]
    if (
        not isinstance(duration, (int, float))
        or isinstance(duration, bool)
        or not math.isfinite(duration)
        or duration < 0
    ):
        raise ReviewError(f"{context} has an invalid duration")
    argv = value["argv"]
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(argument, str) for argument in argv)
    ):
        raise ReviewError(f"{context} used a malformed Cargo command")
    executable = argv[0]
    if (
        not Path(executable).is_absolute()
        or Path(executable).name != "cargo"
        or (
            expected_cargo_executable is not None
            and executable != expected_cargo_executable
        )
    ):
        raise ReviewError(f"{context} used another Cargo executable")
    prefix = (
        ["test", "--no-run", "--verbose"]
        if expected_phase == "Build"
        else ["test", "--verbose"]
    )
    suffix = ["--all-features", "--locked"]
    arguments = argv[1:]
    if arguments[: len(prefix)] != prefix or arguments[-len(suffix) :] != suffix:
        raise ReviewError(f"{context} used another Cargo command")
    package_arguments = arguments[len(prefix) : -len(suffix)]
    package_prefix = "--package="
    if not package_arguments or any(
        not argument.startswith(package_prefix) for argument in package_arguments
    ):
        raise ReviewError(f"{context} lacks exact Cargo package selectors")
    packages = tuple(
        argument.removeprefix(package_prefix).removesuffix("@0.9.0")
        for argument in package_arguments
    )
    if any(
        argument != f"--package={package}@0.9.0"
        for argument, package in zip(package_arguments, packages, strict=True)
    ):
        raise ReviewError(f"{context} has another Cargo package version")
    if (
        tuple(sorted(packages)) != packages
        or len(set(packages)) != len(packages)
        or any(package not in BROAD_MUTATION_PACKAGES for package in packages)
    ):
        raise ReviewError(f"{context} has another Cargo package set")
    if expected_package is not None and packages != (expected_package,):
        raise ReviewError(f"{context} does not target its mutant package")
    if expected_packages is not None and packages != expected_packages:
        raise ReviewError(f"{context} changed its Cargo package set")

    process_status = value["process_status"]
    if expected_status == "Success":
        status_matches = type(process_status) is str and process_status == "Success"
    else:
        status_matches = (
            isinstance(process_status, dict)
            and set(process_status) == {"Failure"}
            and type(process_status["Failure"]) is int
            and process_status["Failure"] == 101
        )
    if not status_matches:
        raise ReviewError(f"{context} has another process status")
    return packages


def _broad_mutant_signature(value: Any, context: str) -> BroadMutant:
    """Validate one complete broad mutant descriptor."""

    require_keys(
        value,
        {"name", "package", "file", "function", "span", "replacement", "genre"},
        context,
    )
    name = _focused_exact_text(value["name"], f"{context} name")
    package = _focused_exact_text(value["package"], f"{context} package")
    file = _focused_exact_text(value["file"], f"{context} file")
    span = _focused_span_signature(value["span"], f"{context} span")
    replacement = _focused_exact_text(
        value["replacement"], f"{context} replacement", allow_empty=True
    )
    genre = _focused_exact_text(value["genre"], f"{context} genre")
    function_value = value["function"]
    function: BroadMutantFunction | None
    if function_value is None:
        function = None
    else:
        require_keys(
            function_value,
            {"function_name", "return_type", "span"},
            f"{context} function",
        )
        function = BroadMutantFunction(
            _focused_exact_text(
                function_value["function_name"], f"{context} function name"
            ),
            _focused_exact_text(
                function_value["return_type"],
                f"{context} function return type",
                allow_empty=True,
            ),
            _focused_span_signature(function_value["span"], f"{context} function span"),
        )
    signature = BroadMutant(
        name,
        package,
        file,
        function,
        span,
        replacement,
        genre,
    )
    text_limits = (
        (name, 8_192, "name"),
        (package, 128, "package"),
        (file, 1_024, "file"),
        (replacement, 8_192, "replacement"),
        (genre, 128, "genre"),
    )
    if function is not None:
        text_limits += (
            (function.function_name, 4_096, "function name"),
            (function.return_type, 4_096, "return type"),
        )
    for text, maximum, field in text_limits:
        if len(text.encode("utf-8")) > maximum:
            raise ReviewError(f"{context} {field} exceeds {maximum} bytes")
    if package not in BROAD_MUTATION_PACKAGES:
        raise ReviewError(f"{context} targets another package")
    expected_prefix = f"crates/{package}/"
    file_path = Path(file)
    if (
        file_path.is_absolute()
        or ".." in file_path.parts
        or not file.startswith(expected_prefix)
        or file_path.suffix != ".rs"
    ):
        raise ReviewError(f"{context} targets another source path")
    if genre not in BROAD_MUTATION_GENRES:
        raise ReviewError(f"{context} has an unknown mutation genre")
    if not name.startswith(f"{file}:{span[0]}:{span[1]}: "):
        raise ReviewError(f"{context} name does not bind its source span")
    if function is None and genre not in FUNCTIONLESS_BROAD_MUTATION_GENRES:
        raise ReviewError(
            f"{context} functionless descriptor has a function-only mutation genre"
        )
    if function is not None and (
        span[:2] < function.span[:2] or span[2:] > function.span[2:]
    ):
        raise ReviewError(f"{context} mutation span escapes its function")
    if not replacement and (
        genre not in {"MatchArm", "UnaryOperator"} or "delete " not in name
    ):
        raise ReviewError(f"{context} has an ambiguous empty replacement")
    return signature


def _validate_broad_outcome_details(
    document: dict[str, Any],
    *,
    shard_id: str,
    expected_cargo_executable: str | None,
) -> tuple[BroadMutant, ...]:
    """Validate all descriptors and build/test phases for one broad shard."""

    signatures: list[BroadMutant] = []
    descriptor_set: set[BroadMutant] = set()
    artifact_paths: set[str] = set()
    baseline_packages: tuple[str, ...] | None = None
    for index, outcome in enumerate(document["outcomes"]):
        context = f"mutation shard {shard_id} outcome {index}"
        scenario = outcome["scenario"]
        phases = outcome["phase_results"]
        if not isinstance(phases, list):
            raise ReviewError(f"{context} phases must be a list")
        if scenario == "Baseline":
            if (
                outcome["summary"] != "Success"
                or outcome["log_path"] != "log/baseline.log"
                or outcome["diff_path"] is not None
                or len(phases) != 2
            ):
                raise ReviewError(f"{context} baseline details are not canonical")
            baseline_packages = _validate_broad_phase(
                phases[0],
                context=f"{context} build",
                expected_phase="Build",
                expected_status="Success",
                expected_package=None,
                expected_packages=None,
                expected_cargo_executable=expected_cargo_executable,
            )
            _validate_broad_phase(
                phases[1],
                context=f"{context} test",
                expected_phase="Test",
                expected_status="Success",
                expected_package=None,
                expected_packages=baseline_packages,
                expected_cargo_executable=expected_cargo_executable,
            )
            artifact_paths.add("log/baseline.log")
            continue

        mutant = scenario.get("Mutant") if isinstance(scenario, dict) else None
        signature = _broad_mutant_signature(mutant, f"{context} mutant")
        if signature in descriptor_set:
            raise ReviewError(f"{context} duplicates another mutant descriptor")
        descriptor_set.add(signature)
        signatures.append(signature)
        summary = outcome["summary"]
        expected_phase_count = 1 if summary == "Unviable" else 2
        if (
            summary not in {"CaughtMutant", "Unviable"}
            or len(phases) != expected_phase_count
        ):
            raise ReviewError(f"{context} has another phase or summary contract")
        _validate_broad_phase(
            phases[0],
            context=f"{context} build",
            expected_phase="Build",
            expected_status={"Failure": 101} if summary == "Unviable" else "Success",
            expected_package=signature.package,
            expected_packages=None,
            expected_cargo_executable=expected_cargo_executable,
        )
        if summary == "CaughtMutant":
            _validate_broad_phase(
                phases[1],
                context=f"{context} test",
                expected_phase="Test",
                expected_status={"Failure": 101},
                expected_package=signature.package,
                expected_packages=None,
                expected_cargo_executable=expected_cargo_executable,
            )
        _validate_focused_artifact_path(
            outcome["log_path"], context=f"{context} log path", directory="log"
        )
        _validate_focused_artifact_path(
            outcome["diff_path"], context=f"{context} diff path", directory="diff"
        )
        for artifact_path in (outcome["log_path"], outcome["diff_path"]):
            if artifact_path in artifact_paths:
                raise ReviewError(f"{context} reuses another outcome artifact path")
            artifact_paths.add(artifact_path)
    if baseline_packages is None:
        raise ReviewError(f"mutation shard {shard_id} lacks baseline package details")
    if set(baseline_packages) != {signature.package for signature in signatures}:
        raise ReviewError(
            f"mutation shard {shard_id} baseline targets another package set"
        )
    return tuple(signatures)


def broad_mutation_signatures(path: Path, shard_id: str) -> tuple[BroadMutant, ...]:
    """Return the already validated, unique broad mutant identities."""

    artifact = _capture_mutation_outcomes(path, shard_id)
    document = _load_mutation_json(
        artifact.capture.data,
        max_depth=16,
        max_nodes=500_000,
        label=f"mutation shard {shard_id} outcomes",
    )
    _validate_mutation_outcomes_document(
        document,
        shard_id,
        validate_broad_details=False,
    )
    return _validate_broad_outcome_details(
        document,
        shard_id=shard_id,
        expected_cargo_executable=None,
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


def _validate_focused_liveness_document(
    document: Any,
    check: dict[str, Any],
    *,
    expected_cargo_executable: str | None = None,
) -> dict[str, int]:
    """Validate one captured focused mutation outcomes document."""

    check_id = str(check["id"])
    counts = _validate_mutation_outcomes_document(
        document,
        f"focused/{check_id}",
        expected_cargo_executable=expected_cargo_executable,
    )
    required: Counter[FocusedMutant] = Counter(check["required_mutants"])
    unviable: Counter[FocusedMutant] = Counter(check.get("unviable_mutants", ()))
    if unviable - required:
        raise ReviewError(
            f"focused mutation check {check_id} has an invalid unviable set"
        )
    required_count = sum(required.values())
    unviable_count = sum(unviable.values())
    if counts != {
        "total_mutants": required_count,
        "missed": 0,
        "caught": required_count - unviable_count,
        "timeout": 0,
        "unviable": unviable_count,
        "success": 0,
    }:
        raise ReviewError(
            f"focused mutation check {check_id} has another outcome summary"
        )

    observed: Counter[FocusedMutant] = Counter()
    if check.get("kind") == "direct-test":
        expected_build_argv = (
            "test",
            "--no-run",
            "--verbose",
            "--package=galadriel-ncp@0.9.0",
            "--all-features",
            "--locked",
        )
        expected_test_argv = (
            "test",
            "--verbose",
            "--package=galadriel-ncp@0.9.0",
            "--all-features",
            "--locked",
            "--lib",
            str(check["test"]),
            "--",
            "--exact",
        )
    elif check.get("kind") == "acceptance-binary":
        expected_build_argv = (
            "test",
            "--no-run",
            "--verbose",
            "--package=galadriel-eval@0.9.0",
            "--all-features",
            "--locked",
        )
        expected_test_argv = (
            "test",
            "--verbose",
            "--package=galadriel-eval@0.9.0",
            "--all-features",
            "--locked",
            "--bin",
            str(check["binary"]),
        )
    else:
        raise ReviewError(f"focused mutation check {check_id} has another kind")

    for index, outcome in enumerate(document["outcomes"]):
        context = f"focused mutation check {check_id} outcome {index}"
        require_keys(
            outcome,
            {"scenario", "summary", "log_path", "diff_path", "phase_results"},
            context,
        )
        scenario = outcome["scenario"]
        baseline = scenario == "Baseline"
        mutant = scenario.get("Mutant") if isinstance(scenario, dict) else None
        signature = (
            None if baseline else _focused_mutant_signature(mutant, f"{context} mutant")
        )
        is_unviable = signature is not None and unviable[signature] > 0
        phases = outcome["phase_results"]
        expected_phase_count = 1 if is_unviable else 2
        if not isinstance(phases, list) or len(phases) != expected_phase_count:
            expected_names = "Build" if is_unviable else "Build and Test"
            raise ReviewError(f"{context} must contain exactly {expected_names} phases")

        test_status: Any = "Success" if baseline else {"Failure": 101}
        _validate_focused_phase(
            phases[0],
            context=f"{context} build",
            expected_phase="Build",
            expected_argv=expected_build_argv,
            expected_status={"Failure": 101} if is_unviable else "Success",
            expected_cargo_executable=expected_cargo_executable,
        )
        if not is_unviable:
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

        expected_summary = "Unviable" if is_unviable else "CaughtMutant"
        if outcome["summary"] != expected_summary:
            raise ReviewError(f"{context} mutant summary has another classification")
        _validate_focused_artifact_path(
            outcome["diff_path"], context=f"{context} diff path", directory="diff"
        )
        if signature is None:
            raise ReviewError(f"{context} lacks a mutant identity")
        observed[signature] += 1
    if observed != required:
        raise ReviewError(
            f"focused mutation check {check_id} targets another mutant set"
        )
    return counts


def validate_focused_liveness_outcomes(
    path: Path,
    check: dict[str, Any],
    *,
    expected_cargo_executable: str | None = None,
) -> dict[str, int]:
    """Require the exact outcomes from one exact focused mutation command."""

    check_id = str(check["id"])
    artifact = _capture_mutation_outcomes(path, f"focused/{check_id}")
    document = _load_mutation_json(
        artifact.capture.data,
        max_depth=16,
        max_nodes=500_000,
        label=f"focused mutation check {check_id} outcomes",
    )
    return _validate_focused_liveness_document(
        document,
        check,
        expected_cargo_executable=expected_cargo_executable,
    )


def _validate_focused_mutation_receipt_document(
    document: Any,
    *,
    root: Path,
    commit: str,
    tree: str,
    outcome_artifacts: dict[str, MutationArtifactCapture] | None = None,
) -> tuple[
    dict[str, Any],
    dict[str, Path],
    dict[str, MutationArtifactCapture],
]:
    """Validate one captured focused receipt and its captured outcomes."""

    require_keys(
        document,
        {
            "schema",
            "candidate",
            "github_run",
            "environment_contract",
            "toolchain",
            "checks",
        },
        "focused mutation run receipt",
    )
    if document["schema"] != "galadriel.focused-mutation-run.v2":
        raise ReviewError("focused mutation run receipt has another schema")
    if document["candidate"] != {"commit": commit, "tree": tree}:
        raise ReviewError("focused mutation run receipt targets another candidate")
    validate_github_mutation_run(
        document["github_run"],
        commit=commit,
        context="focused mutation GitHub run",
        allow_null=True,
    )
    if document["environment_contract"] != FOCUSED_MUTATION_ENVIRONMENT_CONTRACT:
        raise ReviewError("focused mutation run used another environment contract")
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
    if outcome_artifacts is not None and set(outcome_artifacts) != set(expected_ids):
        raise ReviewError("focused mutation outcomes capture set is incomplete")
    outcomes: dict[str, Path] = {}
    captures: dict[str, MutationArtifactCapture] = {}
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
        expected_target = _mutation_artifact_path(
            root,
            expected_relative,
            context=f"focused mutation check {check_id} outcomes",
        )
        captured = (
            None if outcome_artifacts is None else outcome_artifacts.get(check_id)
        )
        if captured is None:
            captured = _capture_mutation_artifact(
                root,
                expected_relative,
                max_bytes=MAX_MUTATION_OUTCOMES_BYTES,
                expected_size=artifact["size_bytes"],
                context=f"focused mutation check {check_id} outcomes",
            )
        elif captured.path != expected_target:
            raise ReviewError(
                f"focused mutation receipt check {check_id} came from another path"
            )
        if captured.path in outcomes.values():
            raise ReviewError(
                f"focused mutation receipt check {check_id} output is duplicate"
            )
        if (
            artifact["sha256"] != captured.capture.sha256
            or artifact["size_bytes"] != captured.capture.size_bytes
        ):
            raise ReviewError(
                f"focused mutation receipt check {check_id} output digest mismatch"
            )
        outcome_document = _load_mutation_json(
            captured.capture.data,
            max_depth=16,
            max_nodes=500_000,
            label=f"focused mutation check {check_id} outcomes",
        )
        counts = _validate_focused_liveness_document(
            outcome_document,
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
        outcomes[check_id] = captured.path
        captures[check_id] = captured
    return document, outcomes, captures


def validate_focused_mutation_receipt(
    path: Path,
    *,
    root: Path,
    commit: str,
    tree: str,
) -> tuple[dict[str, Any], dict[str, Path]]:
    """Bind focused outcomes to the exact runner invocation and Rust toolchain."""

    expected_path = _mutation_artifact_path(
        root,
        FOCUSED_MUTATION_RECEIPT,
        context="focused mutation run receipt",
    )
    actual_path = Path(os.path.abspath(os.fspath(path.expanduser())))
    if actual_path != expected_path:
        raise ReviewError("focused mutation run receipt is outside its artifact root")
    receipt = _capture_mutation_artifact(
        root,
        FOCUSED_MUTATION_RECEIPT,
        max_bytes=MAX_MUTATION_RECEIPT_BYTES,
        context="focused mutation run receipt",
    )
    document = _load_mutation_json(
        receipt.capture.data,
        max_depth=16,
        max_nodes=100_000,
        label="focused mutation run receipt",
    )
    validated, outcomes, _captures = _validate_focused_mutation_receipt_document(
        document,
        root=root,
        commit=commit,
        tree=tree,
    )
    return validated, outcomes


class _GitTreeEntry(NamedTuple):
    """One bounded recursive Git tree entry."""

    path: str
    mode: str
    object_type: str
    object_id: str
    size: int | None


def _exact_git_commit(repo: Path, commit: str) -> str:
    """Require one immutable full commit object without replacement refs."""

    if not isinstance(commit, str) or not GIT_OBJECT.fullmatch(commit):
        raise ReviewError("candidate tree commit must be a full lowercase Git object")
    assert_no_replace_refs(repo)
    raw = git_bounded_output(
        repo,
        "rev-parse",
        "--verify",
        f"{commit}^{{commit}}",
        max_bytes=64,
    )
    try:
        resolved = raw.decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise ReviewError("candidate tree commit resolution is not ASCII") from error
    if resolved != f"{commit}\n":
        raise ReviewError("candidate tree commit resolves to another object")
    return commit


def _candidate_git_path(path_bytes: bytes, context: str) -> str:
    """Decode one bounded portable Git path without normalizing it."""

    if not path_bytes or len(path_bytes) > MAX_CANDIDATE_PATH_BYTES:
        raise ReviewError(f"{context} path exceeds its byte bound")
    try:
        path = path_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ReviewError(f"{context} path is not valid UTF-8") from error
    parts = path.split("/")
    if (
        path.startswith("/")
        or "\\" in path
        or any(part in {"", ".", ".."} for part in parts)
        or len(parts) > MAX_CANDIDATE_PATH_DEPTH
        or (len(parts[0]) == 2 and parts[0][0].isalpha() and parts[0][1] == ":")
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in path)
    ):
        raise ReviewError(f"{context} path is unsafe: {path!r}")
    if any(
        len(part.encode("utf-8")) > MAX_CANDIDATE_PATH_COMPONENT_BYTES for part in parts
    ):
        raise ReviewError(f"{context} path component exceeds its byte bound")
    return path


def _parse_git_tree_listing(raw: bytes, context: str) -> list[_GitTreeEntry]:
    """Parse one bounded `git ls-tree -rzl` result before any blob read."""

    if not raw:
        return []
    if not raw.endswith(b"\0"):
        raise ReviewError(f"{context} listing lacks its final separator")
    record_count = raw.count(b"\0")
    if record_count > MAX_CANDIDATE_TREE_ENTRIES:
        raise ReviewError(f"{context} exceeds its entry-count bound")

    entries: list[_GitTreeEntry] = []
    seen_paths: set[str] = set()
    aggregate_bytes = 0
    records = raw.split(b"\0")
    if records[-1]:
        raise ReviewError(f"{context} listing is malformed")
    for index, encoded in enumerate(records[:-1]):
        if not encoded:
            raise ReviewError(f"{context} contains an empty entry")
        if len(encoded) > MAX_CANDIDATE_PATH_BYTES + 128:
            raise ReviewError(f"{context} entry {index} exceeds its byte bound")
        try:
            metadata, path_bytes = encoded.split(b"\t", 1)
            fields = metadata.decode("ascii", "strict").split()
        except (UnicodeDecodeError, ValueError) as error:
            raise ReviewError(f"{context} entry {index} is malformed") from error
        if len(fields) != 4:
            raise ReviewError(f"{context} entry {index} has another field count")
        mode, object_type, object_id, size_text = fields
        expected_type = {
            "100644": "blob",
            "100755": "blob",
            "120000": "blob",
            "160000": "commit",
        }.get(mode)
        if expected_type is None or object_type != expected_type:
            raise ReviewError(f"{context} entry {index} has another mode or type")
        if not GIT_OBJECT.fullmatch(object_id):
            raise ReviewError(f"{context} entry {index} has an invalid object ID")
        if mode == "160000":
            if size_text != "-":
                raise ReviewError(f"{context} Git link has an invalid size")
            size = None
            logical_size = len(object_id) + 1
        else:
            if (
                not size_text.isascii()
                or not size_text.isdecimal()
                or (len(size_text) > 1 and size_text.startswith("0"))
            ):
                raise ReviewError(f"{context} blob has an invalid size")
            size = int(size_text)
            if size > MAX_CANDIDATE_BLOB_BYTES:
                raise ReviewError(f"{context} blob exceeds its per-blob byte bound")
            logical_size = size
        aggregate_bytes += logical_size
        if aggregate_bytes > MAX_CANDIDATE_TREE_BLOB_BYTES:
            raise ReviewError(f"{context} exceeds its aggregate blob-byte bound")
        path = _candidate_git_path(path_bytes, f"{context} entry {index}")
        if path in seen_paths:
            raise ReviewError(f"{context} contains duplicate path: {path}")
        seen_paths.add(path)
        entries.append(_GitTreeEntry(path, mode, object_type, object_id, size))
    return entries


def _read_git_blob(repo: Path, entry: _GitTreeEntry, context: str) -> bytes:
    """Read one exact blob within its declared per-blob size."""

    if entry.object_type != "blob" or entry.size is None:
        raise ReviewError(f"{context} does not identify a Git blob")
    if entry.size > MAX_CANDIDATE_BLOB_BYTES:
        raise ReviewError(f"{context} exceeds its per-blob byte bound")
    data = git_bounded_output(
        repo,
        "cat-file",
        "blob",
        entry.object_id,
        max_bytes=entry.size,
    )
    if len(data) != entry.size:
        raise ReviewError(f"{context} differs from its declared Git blob size")
    object_digest = hashlib.sha1(usedforsecurity=False)
    object_digest.update(f"blob {entry.size}\0".encode("ascii"))
    object_digest.update(data)
    actual_object_id = object_digest.hexdigest()
    if actual_object_id != entry.object_id:
        raise ReviewError(f"{context} differs from its declared Git blob identity")
    return data


def git_tree_inventory(repo: Path, commit: str) -> dict[str, dict[str, Any]]:
    """Inventory one exact recursive tree within fixed path and blob bounds."""

    commit = _exact_git_commit(repo, commit)
    raw = git_bounded_output(
        repo,
        "ls-tree",
        "-rz",
        "-l",
        "-r",
        "--full-tree",
        commit,
        max_bytes=MAX_CANDIDATE_TREE_LISTING_BYTES,
    )
    entries = _parse_git_tree_listing(raw, "candidate tree")
    if not entries:
        raise ReviewError("candidate tree inventory is empty")

    result: dict[str, dict[str, Any]] = {}
    blob_cache: dict[str, tuple[str, int]] = {}
    for entry in entries:
        if entry.mode == "160000":
            data = entry.object_id.encode("ascii") + b"\n"
            digest_and_size = (sha256_bytes(data), len(data))
        else:
            digest_and_size = blob_cache.get(entry.object_id)
            if digest_and_size is None:
                data = _read_git_blob(
                    repo,
                    entry,
                    f"candidate tree blob {entry.path}",
                )
                digest_and_size = (sha256_bytes(data), len(data))
                blob_cache[entry.object_id] = digest_and_size
            elif digest_and_size[1] != entry.size:
                raise ReviewError(
                    f"candidate tree blob size is inconsistent: {entry.path}"
                )
        result[entry.path] = {
            "mode": entry.mode,
            "object_type": entry.object_type,
            "git_blob_id": entry.object_id,
            "sha256": digest_and_size[0],
            "bytes": digest_and_size[1],
        }
    return result


def candidate_blob(repo: Path, commit: str, relative: str) -> bytes:
    """Read one exact regular candidate blob without using a mutable ref."""

    if not isinstance(relative, str):
        raise ReviewError("candidate evidence path is not text")
    try:
        path_bytes = relative.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise ReviewError("candidate evidence path is not valid UTF-8") from error
    path = _candidate_git_path(path_bytes, "candidate evidence")
    commit = _exact_git_commit(repo, commit)
    raw = git_bounded_output(
        repo,
        "--literal-pathspecs",
        "ls-tree",
        "-rz",
        "-l",
        "--full-tree",
        commit,
        "--",
        path,
        max_bytes=MAX_CANDIDATE_PATH_BYTES + 128,
    )
    entries = _parse_git_tree_listing(raw, "candidate evidence tree lookup")
    if len(entries) != 1 or entries[0].path != path:
        raise ReviewError("candidate evidence path does not identify one exact blob")
    entry = entries[0]
    if entry.mode == "120000":
        raise ReviewError("candidate evidence path identifies a symbolic link")
    if entry.mode not in {"100644", "100755"}:
        raise ReviewError("candidate evidence path does not identify a regular file")
    return _read_git_blob(repo, entry, f"candidate evidence blob {path}")


FILE_LEDGER_COLUMNS = (
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
)


def _load_file_review_ledger(
    path: Path, *, label: str
) -> tuple[bytes, list[dict[str, str]]]:
    """Load one bounded CSV ledger from one stable no-follow read."""

    document = read_bounded_regular_file(
        path,
        max_bytes=MAX_FILE_LEDGER_BYTES,
        label=label,
    )
    try:
        text = document.decode("utf-8", "strict")
        reader = csv.DictReader(io.StringIO(text, newline=""))
        if tuple(reader.fieldnames or ()) != FILE_LEDGER_COLUMNS:
            raise ReviewError(f"{label} has the wrong or duplicate columns")
        rows: list[dict[str, str]] = []
        for row_number, row in enumerate(reader, 1):
            if row_number > MAX_FILE_LEDGER_ROWS:
                raise ReviewError(
                    f"{label} exceeds the {MAX_FILE_LEDGER_ROWS}-row limit"
                )
            if None in row or any(value is None for value in row.values()):
                raise ReviewError(f"{label} row {row_number} is malformed")
            if any(
                len(value.encode("utf-8")) > MAX_FILE_LEDGER_CELL_BYTES
                for value in row.values()
            ):
                raise ReviewError(
                    f"{label} row {row_number} exceeds the cell-size limit"
                )
            rows.append(row)
    except ReviewError:
        raise
    except (UnicodeError, csv.Error) as error:
        raise ReviewError(f"cannot read {label}: {error}") from error
    return document, rows


def validate_completed_file_ledger(
    path: Path,
    repo: Path,
    commit: str,
    *,
    source_ledger: Path | None = None,
) -> dict[str, Any]:
    inventory = git_tree_inventory(repo, commit)
    completed_document, rows = _load_file_review_ledger(
        path, label="completed file-review ledger"
    )
    by_path: dict[str, dict[str, str]] = {}
    for row in rows:
        relative = row["path"]
        if relative in by_path:
            raise ReviewError(f"completed review ledger has duplicate path: {relative}")
        expected = inventory.get(relative)
        if expected is None:
            raise ReviewError(f"completed review ledger has an extra path: {relative}")
        if row["git_mode"] != expected["mode"]:
            raise ReviewError(f"completed review ledger mode mismatch: {relative}")
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
        source_document, source_rows = _load_file_review_ledger(
            source_ledger, label="source file-review ledger"
        )
        source_by_path = {row["path"]: row for row in source_rows}
        if len(source_by_path) != len(source_rows) or set(source_by_path) != set(
            by_path
        ):
            raise ReviewError(
                "completed review ledger differs from the source path set"
            )
        immutable_fields = FILE_LEDGER_COLUMNS[:13]
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
        source_digest = sha256_bytes(source_document)
    return {
        "tracked_files": len(inventory),
        "reviewed_files": len(by_path),
        "ledger_sha256": sha256_bytes(completed_document),
        "source_ledger_sha256": source_digest,
    }


def verify_artifact_manifest(
    root: Path,
    manifest_path: Path,
    *,
    expected_schema: str,
    forbidden_paths: set[str],
) -> dict[str, Any]:
    manifest_bytes = read_bounded_regular_file(
        manifest_path,
        max_bytes=MAX_TIER_MANIFEST_BYTES,
        label="artifact manifest",
    )
    try:
        document = loads_json(manifest_bytes)
    except (TypeError, ValueError) as error:
        raise ReviewError(f"cannot parse artifact manifest: {error}") from error
    validate_json_structure(
        document,
        max_depth=MAX_EVIDENCE_JSON_DEPTH,
        max_nodes=MAX_EVIDENCE_JSON_NODES,
        label="artifact manifest",
    )
    require_keys(
        document, {"schema", "tier", "candidate", "artifacts"}, "artifact manifest"
    )
    if document["schema"] != expected_schema:
        raise ReviewError("artifact manifest has the wrong schema")
    artifacts = document["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise ReviewError("artifact manifest must contain artifacts")
    if len(artifacts) > MAX_TIER_ARTIFACTS:
        raise ReviewError(
            f"artifact manifest exceeds the {MAX_TIER_ARTIFACTS}-artifact limit"
        )

    canonical_forbidden: set[str] = set()
    for relative in forbidden_paths:
        canonical_relative_parts(
            relative,
            label="forbidden artifact path",
            max_path_bytes=MAX_TIER_PATH_BYTES,
            max_component_bytes=MAX_TIER_PATH_COMPONENT_BYTES,
            max_depth=MAX_TIER_PATH_DEPTH,
        )
        canonical_forbidden.add(relative)

    seen: set[str] = set()
    declared_aggregate = 0
    for index, item in enumerate(artifacts):
        require_digest_record(item, "manifest artifact")
        relative = item["path"]
        if not isinstance(relative, str):
            raise ReviewError(f"manifest artifact {index} has an invalid path")
        canonical_relative_parts(
            relative,
            label=f"manifest artifact {index} path",
            max_path_bytes=MAX_TIER_PATH_BYTES,
            max_component_bytes=MAX_TIER_PATH_COMPONENT_BYTES,
            max_depth=MAX_TIER_PATH_DEPTH,
        )
        if relative in seen:
            raise ReviewError(f"duplicate manifest path: {relative!r}")
        if relative in canonical_forbidden:
            raise ReviewError(
                f"self-reference is prohibited in artifact manifest: {relative}"
            )
        if item["size_bytes"] > MAX_TIER_ARTIFACT_BYTES:
            raise ReviewError(
                f"manifest artifact exceeds the per-file byte limit: {relative}"
            )
        declared_aggregate += item["size_bytes"]
        if declared_aggregate > MAX_TIER_AGGREGATE_BYTES:
            raise ReviewError("artifact manifest exceeds the aggregate byte limit")
        seen.add(relative)

    root_absolute = Path(os.path.abspath(os.fspath(root)))
    manifest_absolute = Path(os.path.abspath(os.fspath(manifest_path)))
    try:
        manifest_relative = manifest_absolute.relative_to(root_absolute).as_posix()
    except ValueError as error:
        raise ReviewError(
            "artifact manifest must be inside its artifact root"
        ) from error
    canonical_relative_parts(
        manifest_relative,
        label="artifact manifest path",
        max_path_bytes=MAX_TIER_PATH_BYTES,
        max_component_bytes=MAX_TIER_PATH_COMPONENT_BYTES,
        max_depth=MAX_TIER_PATH_DEPTH,
    )
    if manifest_relative not in canonical_forbidden:
        raise ReviewError("artifact manifest path must be a forbidden control path")

    actual = digest_rooted_tree(
        root,
        label="artifact tier",
        max_entries=MAX_TIER_TREE_ENTRIES,
        max_depth=MAX_TIER_PATH_DEPTH,
        max_path_bytes=MAX_TIER_PATH_BYTES,
        max_component_bytes=MAX_TIER_PATH_COMPONENT_BYTES,
        max_file_bytes=MAX_TIER_ARTIFACT_BYTES,
        max_aggregate_bytes=MAX_TIER_AGGREGATE_BYTES + MAX_TIER_CONTROL_BYTES,
        reject_empty_directories=True,
    )
    retained_manifest = actual.get(manifest_relative)
    if (
        retained_manifest is None
        or retained_manifest.sha256 != sha256_bytes(manifest_bytes)
        or retained_manifest.size_bytes != len(manifest_bytes)
    ):
        raise ReviewError("artifact manifest changed during rooted verification")

    retained_paths = set(actual) - canonical_forbidden
    control_size = sum(
        actual[relative].size_bytes
        for relative in canonical_forbidden
        if relative in actual
    )
    if control_size > MAX_TIER_CONTROL_BYTES:
        raise ReviewError("artifact tier controls exceed the aggregate byte limit")
    missing = sorted(seen - retained_paths)
    if missing:
        raise ReviewError(f"manifest artifacts are missing: {missing[:10]}")
    unlisted = sorted(retained_paths - seen)
    if unlisted:
        raise ReviewError(f"artifact manifest omits retained files: {unlisted[:10]}")

    for item in artifacts:
        relative = item["path"]
        digest = actual[relative]
        if digest.sha256 != item["sha256"] or digest.size_bytes != item["size_bytes"]:
            raise ReviewError(f"manifest artifact digest mismatch: {relative}")
    return document


def validate_evidence_reference(
    reference: Any,
    *,
    repo: Path,
    commit: str,
    qualification_root: Path,
    review_inputs: dict[str, Path],
) -> str:
    require_keys(reference, {"kind", "path", "sha256"}, "evidence reference")
    kind = reference["kind"]
    relative = require_text(reference["path"], "evidence reference path")
    canonical_relative_parts(
        relative,
        label="evidence reference path",
        max_path_bytes=MAX_CANDIDATE_PATH_BYTES,
        max_component_bytes=MAX_CANDIDATE_PATH_COMPONENT_BYTES,
        max_depth=MAX_TIER_PATH_DEPTH,
    )
    expected = reference["sha256"]
    if not isinstance(expected, str) or not SHA256.fullmatch(expected):
        raise ReviewError("evidence reference has an invalid SHA-256")
    if kind == "candidate_blob":
        actual = sha256_bytes(candidate_blob(repo, commit, relative))
    elif kind == "qualification_artifact":
        actual = digest_rooted_regular_file(
            qualification_root,
            relative,
            max_bytes=MAX_TIER_ARTIFACT_BYTES,
            label=f"qualification evidence {relative!r}",
            max_path_bytes=MAX_TIER_PATH_BYTES,
            max_component_bytes=MAX_TIER_PATH_COMPONENT_BYTES,
            max_depth=MAX_TIER_PATH_DEPTH,
            max_directory_entries=MAX_TIER_TREE_ENTRIES,
        ).sha256
    elif kind == "review_input":
        target = review_inputs.get(relative)
        if target is None:
            raise ReviewError(f"review-input evidence is missing: {relative}")
        actual = digest_rooted_regular_file(
            target.parent,
            target.name,
            max_bytes=MAX_SIGNED_DOCUMENT_BYTES,
            label=f"review-input evidence {relative!r}",
            max_path_bytes=MAX_TIER_PATH_BYTES,
            max_component_bytes=MAX_TIER_PATH_COMPONENT_BYTES,
            max_depth=1,
            max_directory_entries=MAX_TIER_TREE_ENTRIES,
        ).sha256
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
    review_inputs: dict[str, Path] | None = None,
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
    retained_review_inputs = review_inputs or {}

    def checked_reference(item: Any) -> str:
        try:
            key = json.dumps(item, sort_keys=True, ensure_ascii=False)
        except (TypeError, ValueError) as error:
            raise ReviewError(
                f"evidence reference is not canonical JSON: {error}"
            ) from error
        if key not in reference_cache:
            reference_cache[key] = validate_evidence_reference(
                item,
                repo=repo,
                commit=commit,
                qualification_root=qualification_root,
                review_inputs=retained_review_inputs,
            )
        return reference_cache[key]

    complete = 0
    not_claimed = 0
    all_findings: set[str] = set()
    terminal_tasks: set[str] = set()
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
        dependencies = task_plan.get("source_projection", {}).get("dependencies")
        if (
            not isinstance(dependencies, list)
            or len(dependencies) != len(set(dependencies))
            or not set(dependencies).issubset(terminal_tasks)
        ):
            raise ReviewError(f"{task_id}: dependency is not an earlier terminal task")
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
        terminal_tasks.add(task_id)
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
                review_inputs={},
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
    expected_candidate: dict[str, str],
    expected_bindings: dict[str, Any],
) -> None:
    require_keys(
        document,
        {
            "schema",
            "release",
            "author",
            "issued_at",
            "candidate",
            "bindings",
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
    if document["schema"] != "galadriel.release-decision.v3":
        raise ReviewError("release decision has the wrong schema")
    if document["release"] != VERSION or document["author"] != AUTHOR:
        raise ReviewError("release decision has the wrong release or author")
    issued_at = document["issued_at"]
    if not isinstance(issued_at, str) or TIMESTAMP.fullmatch(issued_at) is None:
        raise ReviewError("release decision has an invalid issuance timestamp")
    if document["candidate"] != expected_candidate:
        raise ReviewError("release decision targets the wrong candidate")
    if document["bindings"] != expected_bindings:
        raise ReviewError("release decision has incorrect evidence bindings")
    reconciliation_status = expected_bindings.get("reconciliation_status")
    if reconciliation_status not in {"NOT_RUN", "LOCAL_PIN_PASS"}:
        raise ReviewError("release decision has an invalid reconciliation binding")
    for field, value in expected_bindings.items():
        if field == "reconciliation_status":
            continue
        if value is not None and (
            not isinstance(value, str) or SHA256.fullmatch(value) is None
        ):
            raise ReviewError(f"release decision binding {field} is not a SHA-256")
    decision = document["decision"]
    if decision not in {"GO", "NARROWED_GO", "NO_GO"}:
        raise ReviewError("release decision has an invalid decision")
    if reconciliation_status == "NOT_RUN" and decision != "NO_GO":
        raise ReviewError(
            "release decision must be NO_GO before local reconciliation passes"
        )
    if document["publication_scope"] != ("review-gated GitHub research source release"):
        raise ReviewError("release decision has the wrong publication scope")
    if document["doi"] is not None or document["zenodo"] is not None:
        raise ReviewError("release decision must not claim DOI or Zenodo metadata")
    removed = document["removed_claim_ids"]
    if (
        not isinstance(removed, list)
        or len(set(removed)) != len(removed)
        or not set(removed).issubset(excluded_claim_ids)
    ):
        raise ReviewError("release decision has invalid removed claims")
    if decision == "GO" and removed:
        raise ReviewError("GO is prohibited while public claims remain removed")
    risks = document["residual_risks"]
    if not isinstance(risks, list) or not risks:
        raise ReviewError("release decision must retain residual risks")
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
