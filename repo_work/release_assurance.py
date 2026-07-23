"""Shared strict validators for exact-candidate release assurance.

The module is dependency-free so it can run in a detached candidate worktree.
It never supplies reviewer findings or task outcomes.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import math
import os
import re
import shlex
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, NamedTuple

from common import (
    BoundedHostResult as BoundedHostResult,
    SAFE_GIT_CONFIGURATION,
    ReviewError,
    assert_no_replace_refs,
    contained_path,
    git,
    git_bounded_output,
    load_json,
    loads_json,
    read_bounded_regular_file,
    run_bounded_host_command,
    safe_git_environment,
    sanitized_host_environment as sanitized_host_environment,
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
    "schema": "galadriel.mutation-environment.v1",
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
                "verify-commit",
                commit,
            ],
            context="candidate commit signature verification",
            environment=safe_git_environment(),
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


def validate_evidence_config_bytes(
    tracked_config_bytes: bytes,
    accepted_config_bytes: bytes,
    evidence_manifest_bytes: bytes,
    *,
    tracked_relative_path: str,
) -> dict[str, Any]:
    """Bind retained evidence bytes to the preregistered candidate config."""

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

    root = root.resolve()
    if not path.is_file() or path.is_symlink():
        raise ReviewError("broad mutation run receipt is missing or unsafe")
    path = path.resolve()
    if path != root / BROAD_MUTATION_RECEIPT:
        raise ReviewError("broad mutation run receipt is outside its artifact root")
    document = load_json(
        path,
        max_bytes=MAX_MUTATION_RECEIPT_BYTES,
        max_depth=16,
        max_nodes=100_000,
        label="broad mutation run receipt",
    )
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
    target = contained_path(root, outcome_record["path"])
    if not target.is_file() or target.is_symlink():
        raise ReviewError("broad mutation run outcome is missing or unsafe")
    digest, size = bounded_digest_file(
        target,
        max_bytes=MAX_MUTATION_OUTCOMES_BYTES,
        context="broad mutation outcomes",
    )
    if outcome_record["sha256"] != digest or outcome_record["size_bytes"] != size:
        raise ReviewError("broad mutation run outcome digest mismatch")
    counts = validate_mutation_outcomes(
        target,
        shard,
        expected_cargo_executable=cargo_executable,
    )
    recorded_counts = document["counts"]
    require_keys(recorded_counts, set(counts), "broad mutation run counts")
    if any(type(value) is not int or value < 0 for value in recorded_counts.values()):
        raise ReviewError("broad mutation run has noncanonical counts")
    if recorded_counts != counts:
        raise ReviewError("broad mutation run count record drifted")
    return document, target


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
    _, manifest_size = bounded_digest_file(
        manifest_path,
        max_bytes=MAX_MUTATION_MANIFEST_BYTES,
        context="mutation evidence manifest",
    )
    _, signature_size = bounded_digest_file(
        signature_path,
        max_bytes=MAX_SIGNATURE_BYTES,
        context="mutation evidence signature",
    )
    document = load_json(
        manifest_path,
        max_bytes=MAX_MUTATION_MANIFEST_BYTES,
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
    diff_target = contained_path(manifest_path.parent, "git.diff")
    retained_diff = read_bounded_regular_file(
        diff_target,
        max_bytes=MAX_MUTATION_DIFF_BYTES,
        label="retained mutation Git diff",
    )
    if retained_diff != diff:
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
    artifacts = [diff_target]
    artifact_paths: set[Path] = {diff_target}
    aggregate_size = manifest_size + signature_size + len(diff)
    if aggregate_size > MAX_MUTATION_EVIDENCE_BYTES:
        raise ReviewError("mutation evidence exceeds its aggregate byte limit")
    shard_outcomes: dict[str, Path] = {}
    broad_signatures: set[FocusedMutant] = set()
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
        digest, size = bounded_digest_file(
            target,
            max_bytes=MAX_MUTATION_OUTCOMES_BYTES,
            context=f"mutation shard {shard['id']} outcomes",
        )
        if artifact["sha256"] != digest or artifact["size_bytes"] != size:
            raise ReviewError(f"mutation shard artifact digest mismatch: {relative}")
        validate_mutation_outcomes(target, shard["id"])
        signatures = broad_mutation_signatures(target, shard["id"])
        overlap = broad_signatures.intersection(signatures)
        if overlap:
            raise ReviewError(
                f"mutation shard {shard['id']} duplicates another shard mutant"
            )
        broad_signatures.update(signatures)
        aggregate_size += size
        if aggregate_size > MAX_MUTATION_EVIDENCE_BYTES:
            raise ReviewError("mutation evidence exceeds its aggregate byte limit")
        artifact_paths.add(target)
        artifacts.append(target)
        shard_outcomes[shard["id"]] = target

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
        target = contained_path(manifest_path.parent, expected_path)
        if (
            target in {manifest_path, signature_path}
            or target in artifact_paths
            or not target.is_file()
            or target.is_symlink()
        ):
            raise ReviewError(
                f"broad mutation run receipt {shard_id} is missing or unsafe"
            )
        digest, size = bounded_digest_file(
            target,
            max_bytes=MAX_MUTATION_RECEIPT_BYTES,
            context=f"broad mutation run receipt {shard_id}",
        )
        if artifact["sha256"] != digest or artifact["size_bytes"] != size:
            raise ReviewError(f"broad mutation run receipt {shard_id} digest mismatch")
        receipt_document, receipt_outcome = validate_broad_mutation_receipt(
            target,
            root=target.parent,
            commit=commit,
            tree=tree,
            shard=shard_id,
            diff=diff,
        )
        if receipt_document["github_run"] != github_run:
            raise ReviewError(
                f"broad mutation run receipt {shard_id} targets another GitHub run"
            )
        if receipt_outcome != shard_outcomes[shard_id]:
            raise ReviewError(
                f"broad mutation shard {shard_id} differs from its run receipt"
            )
        aggregate_size += size
        if aggregate_size > MAX_MUTATION_EVIDENCE_BYTES:
            raise ReviewError("mutation evidence exceeds its aggregate byte limit")
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
    receipt_digest, receipt_size = bounded_digest_file(
        receipt_target,
        max_bytes=MAX_MUTATION_RECEIPT_BYTES,
        context="focused mutation run receipt",
    )
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
    if receipt_document["github_run"] != github_run:
        raise ReviewError("focused mutation run receipt targets another GitHub run")
    aggregate_size += receipt_size
    if aggregate_size > MAX_MUTATION_EVIDENCE_BYTES:
        raise ReviewError("mutation evidence exceeds its aggregate byte limit")
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
        digest, size = bounded_digest_file(
            target,
            max_bytes=MAX_MUTATION_OUTCOMES_BYTES,
            context=f"focused mutation check {check_id} outcomes",
        )
        if artifact["sha256"] != digest or artifact["size_bytes"] != size:
            raise ReviewError(f"focused mutation artifact digest mismatch: {relative}")
        validate_focused_liveness_outcomes(target, check)
        aggregate_size += size
        if aggregate_size > MAX_MUTATION_EVIDENCE_BYTES:
            raise ReviewError("mutation evidence exceeds its aggregate byte limit")
        artifact_paths.add(target)
        artifacts.append(target)
    return document, artifacts


def validate_mutation_outcomes(
    path: Path,
    shard_id: str,
    *,
    expected_cargo_executable: str | None = None,
) -> dict[str, int]:
    """Reject incomplete, missed, timed-out, or weak cargo-mutants outcomes."""

    if path.name != "outcomes.json" or not path.is_file() or path.is_symlink():
        raise ReviewError(f"mutation shard {shard_id} artifact must be outcomes.json")
    document = load_json(
        path,
        max_bytes=MAX_MUTATION_OUTCOMES_BYTES,
        max_depth=16,
        max_nodes=500_000,
        label=f"mutation shard {shard_id} outcomes",
    )
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
        _validate_broad_outcome_details(
            document,
            shard_id=shard_id,
            expected_cargo_executable=expected_cargo_executable,
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


def _broad_mutant_signature(value: Any, context: str) -> FocusedMutant:
    """Validate one complete broad mutant descriptor."""

    signature = _focused_mutant_signature(value, context)
    (
        name,
        package,
        file,
        function_name,
        return_type,
        function_span,
        span,
        replacement,
        genre,
    ) = signature
    text_limits = (
        (name, 8_192, "name"),
        (package, 128, "package"),
        (file, 1_024, "file"),
        (function_name, 4_096, "function name"),
        (return_type, 4_096, "return type"),
        (replacement, 8_192, "replacement"),
        (genre, 128, "genre"),
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
    if span[:2] < function_span[:2] or span[2:] > function_span[2:]:
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
) -> tuple[FocusedMutant, ...]:
    """Validate all descriptors and build/test phases for one broad shard."""

    signatures: list[FocusedMutant] = []
    descriptor_set: set[FocusedMutant] = set()
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


def broad_mutation_signatures(path: Path, shard_id: str) -> tuple[FocusedMutant, ...]:
    """Return the already validated, unique broad mutant identities."""

    validate_mutation_outcomes(path, shard_id)
    document = load_json(
        path,
        max_bytes=MAX_MUTATION_OUTCOMES_BYTES,
        max_depth=16,
        max_nodes=500_000,
        label=f"mutation shard {shard_id} outcomes",
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


def validate_focused_liveness_outcomes(
    path: Path,
    check: dict[str, Any],
    *,
    expected_cargo_executable: str | None = None,
) -> dict[str, int]:
    """Require the exact outcomes from one exact focused mutation command."""

    check_id = str(check["id"])
    counts = validate_mutation_outcomes(path, f"focused/{check_id}")
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

    document = load_json(
        path,
        max_bytes=MAX_MUTATION_OUTCOMES_BYTES,
        max_depth=16,
        max_nodes=500_000,
        label=f"focused mutation check {check_id} outcomes",
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
    document = load_json(
        path,
        max_bytes=MAX_MUTATION_RECEIPT_BYTES,
        max_depth=16,
        max_nodes=100_000,
        label="focused mutation run receipt",
    )
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
        digest, size = bounded_digest_file(
            target,
            max_bytes=MAX_MUTATION_OUTCOMES_BYTES,
            context=f"focused mutation check {check_id} outcomes",
        )
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
    elif kind == "review_input":
        target = review_inputs.get(relative)
        if target is None or not target.is_file() or target.is_symlink():
            raise ReviewError(f"review-input evidence is missing: {relative}")
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
