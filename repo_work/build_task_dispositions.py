#!/usr/bin/env python3
"""Validate the byte-bound 0.9 source task-closure plan.

The plan is a faithful JSON projection of the immutable handoff ledger.  It
retains every source precondition, procedure, counterfactual, evidence item,
completion rule, and open lens question.  It contains no review result and no
``COMPLETE`` disposition; exact-candidate outcomes are external finalizer inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "release" / "0.9.0"
TASKS_PATH = RELEASE / "tasks.json"
CLAIMS_PATH = RELEASE / "claims.json"
PLAN_PATH = RELEASE / "task-closure-plan.json"
SOURCE_DISPOSITIONS_PATH = RELEASE / "task-dispositions.json"

VERSION = "0.9.0"
TASK_LEDGER_SHA256 = "b7477290a798feaa00d636ef602e0c09f07d953fd556135478334994f0a03721"
TASK_PROJECTION_SHA256 = "62b57e934425d8668fa3d5e1ed5de7548bea9a693033ce10beb25fbd9aad4c86"
BASELINE_COMMIT = "94e2f8cc01f352d2bf899b7f656997f143a2588f"
TASK_ID = re.compile(r"T\d{3}\Z")
CLAIM_ID = re.compile(r"CLM-\d{3}\Z")
LENSES = tuple(f"L{number:02d}" for number in range(1, 21))

NOT_CLAIMED_TASKS: dict[str, tuple[str, ...]] = {
    "T096": ("CLM-013",),
    "T097": ("CLM-013",),
    "T101": ("CLM-014",),
    "T105": ("CLM-008",),
    "T106": ("CLM-012",),
    "T107": ("CLM-015",),
    "T108": ("CLM-015",),
    "T110": ("CLM-016",),
    "T112": ("CLM-017",),
}


class DispositionError(RuntimeError):
    """A source plan is malformed, unfaithful, or overstates closure."""


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DispositionError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_pairs
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DispositionError(f"cannot load {relative(path)}: {error}") from error


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def compact_canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except (OSError, ValueError):
        return str(path)


def require_keys(value: Any, expected: set[str], context: str) -> None:
    if not isinstance(value, dict):
        raise DispositionError(f"{context} must be an object")
    missing = sorted(expected - value.keys())
    extra = sorted(value.keys() - expected)
    if missing or extra:
        raise DispositionError(
            f"{context}: missing keys={missing}, unexpected keys={extra}"
        )


def require_text(value: Any, context: str, *, minimum: int = 1) -> str:
    if not isinstance(value, str) or len(value.strip()) < minimum:
        raise DispositionError(f"{context} must be concrete non-empty text")
    return value.strip()


def require_text_list(
    value: Any, context: str, *, minimum_items: int = 1, minimum_length: int = 4
) -> list[str]:
    if not isinstance(value, list) or len(value) < minimum_items:
        raise DispositionError(f"{context} must contain at least {minimum_items} entries")
    result = [
        require_text(item, f"{context}[{index}]", minimum=minimum_length)
        for index, item in enumerate(value)
    ]
    return result


def validate_tasks() -> list[dict[str, Any]]:
    document = load_json(TASKS_PATH)
    require_keys(document, {"schema", "source", "tasks"}, "task inventory")
    if document["schema"] != "galadriel.current-handoff-tasks.v2":
        raise DispositionError("unsupported task inventory schema")
    source = document["source"]
    if source.get("task_ledger_sha256") != TASK_LEDGER_SHA256:
        raise DispositionError("task inventory is bound to a different handoff ledger")
    if source.get("frozen_commit") != BASELINE_COMMIT:
        raise DispositionError("task inventory is bound to a different baseline")
    if source.get("original_target") != "1.0.0" or source.get("adapted_target") != VERSION:
        raise DispositionError("task inventory lost the explicit 1.0-to-0.9 adaptation")
    tasks = document["tasks"]
    if not isinstance(tasks, list) or len(tasks) != 116:
        raise DispositionError("task inventory must contain exactly 116 tasks")
    for index, task in enumerate(tasks):
        expected_id = f"T{index:03d}"
        if task.get("id") != expected_id:
            raise DispositionError(f"task sequence is not contiguous at {expected_id}")
        expected_dependency = [] if index == 0 else [f"T{index - 1:03d}"]
        if task.get("dependencies") != expected_dependency:
            raise DispositionError(f"{expected_id}: dependency chain changed")
    return tasks


def validate_claims() -> dict[str, dict[str, Any]]:
    document = load_json(CLAIMS_PATH)
    require_keys(document, {"schema", "release", "tier_definitions", "claims"}, "claims")
    if document["schema"] != "galadriel.claims-matrix.v1" or document["release"] != VERSION:
        raise DispositionError("claims matrix has the wrong schema or release")
    claims: dict[str, dict[str, Any]] = {}
    for claim in document["claims"]:
        claim_id = claim.get("id")
        if not isinstance(claim_id, str) or not CLAIM_ID.fullmatch(claim_id):
            raise DispositionError(f"invalid claim ID: {claim_id!r}")
        if claim_id in claims:
            raise DispositionError(f"duplicate claim ID: {claim_id}")
        claims[claim_id] = claim
    return claims


def validate_source_dispositions() -> dict[str, Any]:
    document = load_json(SOURCE_DISPOSITIONS_PATH)
    require_keys(
        document,
        {
            "schema",
            "release",
            "source_task_ledger_sha256",
            "state",
            "candidate_commit",
            "candidate_tree",
            "dispositions",
        },
        "source task-disposition state",
    )
    if document["schema"] != "galadriel.task-dispositions-source-state.v1":
        raise DispositionError("source task-disposition state has the wrong schema")
    if document["release"] != VERSION or document["source_task_ledger_sha256"] != TASK_LEDGER_SHA256:
        raise DispositionError("source task-disposition state targets another release or ledger")
    if document["state"] != "AWAITING_POST_COMMIT_REVIEW":
        raise DispositionError("source task-disposition state falsely implies closure")
    if document["candidate_commit"] is not None or document["candidate_tree"] is not None:
        raise DispositionError("source task dispositions cannot bind a future candidate")
    if document["dispositions"] != []:
        raise DispositionError("source task dispositions must remain empty")
    return document


SOURCE_PROJECTION_KEYS = {
    "id",
    "phase",
    "title",
    "source_scope",
    "focus",
    "priority",
    "dependencies",
    "execution_wave",
    "subagent_lane",
    "lead_review_required",
    "preconditions",
    "procedure",
    "mandatory_counterfactuals",
    "required_evidence",
    "twenty_lens_review",
    "completion_rule",
}


def _expected_exclusions(projection: dict[str, Any]) -> list[tuple[str, str, tuple[str, ...]]]:
    expected = []
    for index, text in enumerate(projection["procedure"]):
        if text.startswith("Have an independent reviewer reproduce"):
            expected.append((f"procedure[{index}]", sha256_text(text), ("CLM-012", "CLM-016")))
    for index, text in enumerate(projection["required_evidence"]):
        if text == "independent reviewer record":
            expected.append((f"required_evidence[{index}]", sha256_text(text), ("CLM-012",)))
    return expected


def _validate_projection(
    entry: dict[str, Any],
    summary: dict[str, Any],
    claims: dict[str, dict[str, Any]],
    lens_catalog: dict[str, Any],
) -> None:
    task_id = summary["id"]
    require_keys(
        entry,
        {
            "task_id",
            "status",
            "source_projection",
            "source_projection_sha256",
            "accepted_cases",
            "rejected_cases",
            "evidence_types",
            "failure_record_requirements",
            "requirement_exclusions",
            "lens_exclusions",
            "claim_removal_links",
            "residual_risks",
        },
        f"closure plan/{task_id}",
    )
    if entry["task_id"] != task_id:
        raise DispositionError(f"closure plan sequence changed at {task_id}")
    projection = entry["source_projection"]
    require_keys(projection, SOURCE_PROJECTION_KEYS, f"{task_id}/source projection")
    if projection["id"] != task_id:
        raise DispositionError(f"{task_id}: source projection has another ID")
    for field in (
        "phase",
        "title",
        "source_scope",
        "focus",
        "priority",
        "dependencies",
        "execution_wave",
        "subagent_lane",
        "lead_review_required",
    ):
        if projection[field] != summary[field]:
            raise DispositionError(f"{task_id}: source projection differs in {field}")
    projection_digest = hashlib.sha256(compact_canonical_bytes(projection)).hexdigest()
    if entry["source_projection_sha256"] != projection_digest:
        raise DispositionError(f"{task_id}: source projection digest mismatch")
    for field in ("preconditions", "procedure", "mandatory_counterfactuals", "required_evidence"):
        require_text_list(projection[field], f"{task_id}/{field}")
    completion = require_text(projection["completion_rule"], f"{task_id}/completion rule", minimum=80)
    if "Every acceptance condition and evidence item must pass" not in completion:
        raise DispositionError(f"{task_id}: source completion rule was weakened")

    review = projection["twenty_lens_review"]
    if not isinstance(review, dict) or tuple(review) != LENSES:
        raise DispositionError(f"{task_id}: source review must contain ordered L01--L20")
    for lens in LENSES:
        value = review[lens]
        require_keys(value, {"question", "finding", "evidence", "status"}, f"{task_id}/{lens}")
        if value["question"] != lens_catalog[lens]["question"]:
            raise DispositionError(f"{task_id}/{lens}: source lens question changed")
        if value["finding"] != "" or value["evidence"] != "" or value["status"] != "OPEN":
            raise DispositionError(f"{task_id}/{lens}: source plan contains a fabricated result")

    expected_claims = list(NOT_CLAIMED_TASKS.get(task_id, ()))
    expected_status = "NOT_CLAIMED" if expected_claims else "PENDING_POST_COMMIT"
    if entry["status"] != expected_status or entry["claim_removal_links"] != expected_claims:
        raise DispositionError(f"{task_id}: task-level exclusion changed")
    for claim_id in expected_claims:
        if claims.get(claim_id, {}).get("tier") != "NOT_CLAIMED":
            raise DispositionError(f"{task_id}: task exclusion points to an affirmative claim")

    accepted = require_text_list(entry["accepted_cases"], f"{task_id}/accepted cases", minimum_items=2, minimum_length=80)
    if not all(task_id in value and projection["title"] in value for value in accepted[:1]):
        raise DispositionError(f"{task_id}: accepted case is not task-specific")
    rejected = entry["rejected_cases"]
    counterfactuals = projection["mandatory_counterfactuals"]
    if not isinstance(rejected, list) or len(rejected) != len(counterfactuals):
        raise DispositionError(f"{task_id}: rejected cases do not cover all counterfactuals")
    for index, (item, counterfactual) in enumerate(zip(rejected, counterfactuals, strict=True), 1):
        require_keys(item, {"id", "source_sha256", "case", "rejection_rule"}, f"{task_id}/rejected case {index}")
        if item["id"] != f"GLD-090-{task_id}-REJ-{index:02d}" or item["case"] != counterfactual:
            raise DispositionError(f"{task_id}: rejected case sequence changed")
        if item["source_sha256"] != sha256_text(counterfactual) or task_id not in item["rejection_rule"]:
            raise DispositionError(f"{task_id}: rejected case lacks exact source binding")
    if entry["evidence_types"] != projection["required_evidence"]:
        raise DispositionError(f"{task_id}: required evidence differs from source ledger")
    failures = require_text_list(entry["failure_record_requirements"], f"{task_id}/failure records", minimum_items=2, minimum_length=70)
    if not all(task_id in value for value in failures):
        raise DispositionError(f"{task_id}: failure-record rule is not task-specific")

    exclusions = entry["requirement_exclusions"]
    expected_exclusions = _expected_exclusions(projection)
    if not isinstance(exclusions, list) or len(exclusions) != len(expected_exclusions):
        raise DispositionError(f"{task_id}: source requirement exclusions changed")
    for actual, (path, source_digest, links) in zip(exclusions, expected_exclusions, strict=True):
        require_keys(actual, {"source_path", "source_sha256", "claim_removal_links", "reason"}, f"{task_id}/source exclusion")
        if (
            actual["source_path"] != path
            or actual["source_sha256"] != source_digest
            or actual["claim_removal_links"] != list(links)
        ):
            raise DispositionError(f"{task_id}: source exclusion no longer binds the exact item")
        require_text(actual["reason"], f"{task_id}/source exclusion reason", minimum=50)
        for claim_id in links:
            if claims.get(claim_id, {}).get("tier") != "NOT_CLAIMED":
                raise DispositionError(f"{task_id}: source exclusion uses affirmative claim {claim_id}")
    if entry["lens_exclusions"] != {"L12": ["CLM-016"]}:
        raise DispositionError(f"{task_id}: clean-room lens exclusion changed")
    risks = require_text_list(entry["residual_risks"], f"{task_id}/residual risks", minimum_items=1, minimum_length=50)
    if not all(task_id in risk for risk in risks):
        raise DispositionError(f"{task_id}: residual risk is not task-specific")


def validate_plan(
    tasks: list[dict[str, Any]] | None = None,
    claims: dict[str, dict[str, Any]] | None = None,
    document: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tasks = validate_tasks() if tasks is None else tasks
    claims = validate_claims() if claims is None else claims
    document = load_json(PLAN_PATH) if document is None else document
    require_keys(
        document,
        {
            "schema",
            "release",
            "source_task_ledger_sha256",
            "source_projection_sha256",
            "baseline_commit",
            "closure_boundary",
            "lens_catalog",
            "tasks",
        },
        "task closure plan",
    )
    if document["schema"] != "galadriel.task-closure-plan.v2":
        raise DispositionError("task closure plan has the wrong schema")
    if document["release"] != VERSION or document["source_task_ledger_sha256"] != TASK_LEDGER_SHA256:
        raise DispositionError("task closure plan targets another release or handoff ledger")
    if document["baseline_commit"] != BASELINE_COMMIT:
        raise DispositionError("task closure plan targets another audit cut")
    boundary = require_text(document["closure_boundary"], "closure boundary", minimum=80)
    for required in ("post-commit", "outside", "does not establish completion"):
        if required not in boundary:
            raise DispositionError(f"closure boundary omits required phrase: {required}")
    catalog = document["lens_catalog"]
    if not isinstance(catalog, dict) or tuple(catalog) != LENSES:
        raise DispositionError("lens catalog must contain ordered L01--L20")
    for lens in LENSES:
        require_keys(catalog[lens], {"name", "question"}, f"lens catalog/{lens}")
        require_text(catalog[lens]["name"], f"lens catalog/{lens}/name", minimum=4)
        require_text(catalog[lens]["question"], f"lens catalog/{lens}/question", minimum=40)
    entries = document["tasks"]
    if not isinstance(entries, list) or len(entries) != len(tasks):
        raise DispositionError("task closure plan must contain exactly 116 entries")
    for entry, summary in zip(entries, tasks, strict=True):
        _validate_projection(entry, summary, claims, catalog)
    combined = hashlib.sha256(
        compact_canonical_bytes([entry["source_projection"] for entry in entries])
    ).hexdigest()
    if document["source_projection_sha256"] != combined or combined != TASK_PROJECTION_SHA256:
        raise DispositionError("source task projection differs from the immutable handoff ledger")
    return document


def verify() -> None:
    tasks = validate_tasks()
    claims = validate_claims()
    validate_plan(tasks, claims)
    validate_source_dispositions()
    print("byte-bound task-closure plan verified; 107 tasks remain post-commit and 9 are NOT_CLAIMED")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("verify",))
    parser.parse_args()
    try:
        verify()
    except (DispositionError, OSError, ValueError) as error:
        print(f"task-closure plan verification failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
