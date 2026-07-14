#!/usr/bin/env python3
"""Generate and verify deterministic Galadriel release-audit artifacts.

The release inputs are reviewed source data.  This program turns them and the
checked-out repository into canonical JSON, validates the requirement ledger,
and fails on drift.  It deliberately uses only the Python standard library so
that qualification does not depend on an unpinned Python package graph.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "release" / "0.9.0"
INPUTS = RELEASE / "audit-inputs.json"
CLAIMS = RELEASE / "claims.json"
DISPOSITIONS = RELEASE / "task-dispositions.json"
TASKS = RELEASE / "handoff" / "tasks.json"
AUDIT_OUTPUT = RELEASE / "audit-manifest.json"
LEDGER_OUTPUT = RELEASE / "requirements-ledger.json"
VERSION = "0.9.0"

TASK_ID = re.compile(r"T(?P<number>\d{3})\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")
URL = re.compile(r"https?://[^\s<>\]\[)}`\"']+")
DOI_URL = re.compile(r"https?://(?:dx\.)?doi\.org/", re.IGNORECASE)
VALID_STATUSES = {"OPEN", "COMPLETE", "NOT_CLAIMED"}
VALID_TIERS = {
    "IMPLEMENTED",
    "VALIDATED",
    "DEPLOYMENT_QUALIFIED",
    "NOT_CLAIMED",
}
LENSES = (
    "correctness_and_invariants",
    "safety_and_failure_behavior",
    "security_and_adversarial_behavior",
    "determinism_and_reproducibility",
    "performance_and_bounded_resources",
    "api_schema_and_compatibility",
    "observability_and_provenance",
    "testing_and_independent_evidence",
    "documentation_and_operator_usability",
    "ecosystem_composition_and_governance",
)


class AuditError(RuntimeError):
    """A release input or generated artifact violates the frozen contract."""


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuditError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_pairs
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AuditError(f"cannot load {path.relative_to(ROOT)}: {error}") from error


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(*arguments: str) -> str:
    process = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        raise AuditError(f"git {' '.join(arguments)} failed: {process.stderr.strip()}")
    return process.stdout.strip()


def require_keys(value: dict[str, Any], keys: set[str], context: str) -> None:
    missing = sorted(keys - value.keys())
    extra = sorted(value.keys() - keys)
    if missing or extra:
        raise AuditError(f"{context}: missing={missing}, unexpected={extra}")


def artifact(path: Path, purpose: str) -> dict[str, Any]:
    if not path.is_file():
        raise AuditError(f"required artifact is missing: {path.relative_to(ROOT)}")
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "purpose": purpose,
        "sha256": sha256(path),
        "size_bytes": path.stat().st_size,
    }


def validate_inputs(inputs: dict[str, Any]) -> None:
    require_keys(
        inputs,
        {
            "schema",
            "release",
            "audit_date",
            "baseline_repository",
            "repositories",
            "toolchains",
            "artifact_sets",
            "external_sources",
            "adaptation_decision",
        },
        "audit inputs",
    )
    if inputs["schema"] != "galadriel.release-audit-inputs.v1":
        raise AuditError("unsupported audit-input schema")
    release = inputs["release"]
    require_keys(
        release,
        {"name", "version", "author", "doi", "zenodo", "publication_channel"},
        "release identity",
    )
    if release["version"] != VERSION or release["author"] != "Sepehr Mahmoudian":
        raise AuditError("release version/author is not the frozen 0.9.0 identity")
    if release["doi"] is not None or release["zenodo"] is not None:
        raise AuditError("0.9.0 must not claim a project DOI or Zenodo record")
    baseline = inputs["baseline_repository"]
    require_keys(baseline, {"url", "commit", "tree"}, "baseline repository")
    if not REVISION.fullmatch(baseline["commit"]):
        raise AuditError("baseline commit must be a full lowercase Git object identity")
    if not REVISION.fullmatch(baseline["tree"]):
        raise AuditError("baseline tree must be a full lowercase Git object identity")
    if git("rev-parse", f"{baseline['commit']}^{{commit}}") != baseline["commit"]:
        raise AuditError("baseline commit is unavailable or resolves differently")
    if git("rev-parse", f"{baseline['commit']}^{{tree}}") != baseline["tree"]:
        raise AuditError("baseline tree identity does not match baseline commit")
    seen_repositories: set[str] = set()
    for repository in inputs["repositories"]:
        require_keys(
            repository,
            {"name", "url", "commit", "role", "qualification"},
            "repository",
        )
        if repository["name"] in seen_repositories:
            raise AuditError(f"duplicate repository name: {repository['name']}")
        seen_repositories.add(repository["name"])
        if not REVISION.fullmatch(repository["commit"]):
            raise AuditError(f"{repository['name']}: commit is not a full revision")
        if repository["qualification"] not in {
            "PINNED_COMPONENT",
            "RECIPROCAL_FIXTURE",
            "NOT_CLAIMED",
        }:
            raise AuditError(f"{repository['name']}: invalid qualification")
    for tool in inputs["toolchains"]:
        require_keys(tool, {"name", "version", "identity", "role"}, "toolchain")
        if not all(isinstance(tool[key], str) and tool[key] for key in tool):
            raise AuditError("toolchain entries must contain non-empty strings")
    if not inputs["adaptation_decision"].startswith("release/0.9.0/"):
        raise AuditError("adaptation decision must be retained inside the release record")


def collect_artifacts(inputs: dict[str, Any]) -> list[dict[str, Any]]:
    collected: dict[str, dict[str, Any]] = {}
    for artifact_set in inputs["artifact_sets"]:
        require_keys(artifact_set, {"purpose", "patterns"}, "artifact set")
        matched: list[Path] = []
        for pattern in artifact_set["patterns"]:
            matched.extend(path for path in ROOT.glob(pattern) if path.is_file())
        if not matched:
            raise AuditError(f"artifact pattern set matched no files: {artifact_set}")
        for path in sorted(set(matched)):
            key = path.relative_to(ROOT).as_posix()
            entry = artifact(path, artifact_set["purpose"])
            if key in collected and collected[key] != entry:
                raise AuditError(f"artifact has conflicting purposes: {key}")
            collected[key] = entry
    return [collected[key] for key in sorted(collected)]


def collect_external_references(inputs: dict[str, Any]) -> list[dict[str, Any]]:
    references: dict[tuple[str, str], dict[str, Any]] = {}
    source_paths = sorted(
        path
        for pattern in inputs["external_sources"]["scan_patterns"]
        for path in ROOT.glob(pattern)
        if path.is_file() and RELEASE / "handoff" not in path.parents
    )
    for path in source_paths:
        relative = path.relative_to(ROOT).as_posix()
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for match in URL.finditer(line):
                url = match.group(0).rstrip(".,;:")
                key = (relative, f"{line_number}:{url}")
                references[key] = {
                    "kind": "paper"
                    if DOI_URL.match(url) or relative == "docs/RELATED-WORK.md"
                    else "external_reference",
                    "line": line_number,
                    "path": relative,
                    "url": url,
                }
    for source in inputs["external_sources"]["declared"]:
        require_keys(source, {"kind", "title", "url", "purpose"}, "external source")
        key = ("<declared>", source["url"])
        references[key] = dict(source)
    return [references[key] for key in sorted(references)]


def lockfile_git_sources() -> list[dict[str, str]]:
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    sources: dict[tuple[str, str, str], dict[str, str]] = {}
    for package in lock.get("package", []):
        source = package.get("source", "")
        if not source.startswith("git+"):
            continue
        match = re.search(r"#([0-9a-f]{40})\Z", source)
        if match is None:
            raise AuditError(f"Git dependency lacks an immutable lock revision: {source}")
        item = {
            "name": package["name"],
            "version": package["version"],
            "source": source,
            "commit": match.group(1),
        }
        sources[(item["name"], item["version"], item["source"])] = item
    return [sources[key] for key in sorted(sources)]


def validate_project_metadata(inputs: dict[str, Any]) -> dict[str, Any]:
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    package = cargo["workspace"]["package"]
    if package["version"] != VERSION:
        raise AuditError(f"Cargo workspace version must be {VERSION}")
    if package["authors"] != ["Sepehr Mahmoudian"]:
        raise AuditError("Cargo workspace author must be exactly Sepehr Mahmoudian")
    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    if not re.search(r"(?m)^version: ['\"]?0\.9\.0['\"]?$", citation):
        raise AuditError("CITATION.cff does not identify version 0.9.0")
    if re.search(r"(?mi)^(doi|identifiers):", citation) or "zenodo.org" in citation.lower():
        raise AuditError("CITATION.cff must omit project DOI/Zenodo metadata for 0.9.0")
    if "family-names: Mahmoudian" not in citation or "given-names: Sepehr" not in citation:
        raise AuditError("CITATION.cff author identity is incomplete")
    for member in cargo["workspace"]["members"]:
        manifest = tomllib.loads((ROOT / member / "Cargo.toml").read_text(encoding="utf-8"))
        if manifest["package"].get("publish") is not False:
            raise AuditError(f"{member} must remain publish=false for the GitHub-only 0.9.0")
    fuzz = tomllib.loads((ROOT / "fuzz/Cargo.toml").read_text(encoding="utf-8"))
    for dependency in ("galadriel-core", "galadriel-ncp"):
        if fuzz["dependencies"][dependency].get("version") != VERSION:
            raise AuditError(f"fuzz dependency {dependency} must track release {VERSION}")
    return {
        "authors": package["authors"],
        "license": package["license"],
        "project_doi": inputs["release"]["doi"],
        "publication_channel": inputs["release"]["publication_channel"],
        "version": package["version"],
        "zenodo_record": inputs["release"]["zenodo"],
    }


def validate_claims() -> list[dict[str, Any]]:
    document = load_json(CLAIMS)
    require_keys(document, {"schema", "release", "tier_definitions", "claims"}, "claims")
    if document["schema"] != "galadriel.claims-matrix.v1" or document["release"] != VERSION:
        raise AuditError("claims matrix has the wrong schema or release")
    if set(document["tier_definitions"]) != VALID_TIERS:
        raise AuditError("claims matrix must define exactly the four frozen tiers")
    seen: set[str] = set()
    deployment_claims = 0
    for claim in document["claims"]:
        require_keys(
            claim,
            {"id", "claim", "tier", "scope", "evidence", "limitations"},
            "claim",
        )
        if claim["id"] in seen or not re.fullmatch(r"CLM-\d{3}", claim["id"]):
            raise AuditError(f"invalid or duplicate claim ID: {claim['id']}")
        seen.add(claim["id"])
        if claim["tier"] not in VALID_TIERS:
            raise AuditError(f"{claim['id']}: invalid tier")
        if not claim["claim"] or not claim["scope"] or not claim["limitations"]:
            raise AuditError(f"{claim['id']}: claim fields must be non-empty")
        if claim["tier"] == "DEPLOYMENT_QUALIFIED":
            deployment_claims += 1
            if not claim["evidence"]:
                raise AuditError(f"{claim['id']}: deployment claim lacks evidence")
        if claim["tier"] == "NOT_CLAIMED" and claim["evidence"]:
            raise AuditError(f"{claim['id']}: NOT_CLAIMED must not cite affirmative evidence")
        for path_string in claim["evidence"]:
            if not (ROOT / path_string).exists():
                raise AuditError(f"{claim['id']}: claim evidence is missing: {path_string}")
    if deployment_claims:
        raise AuditError("0.9.0 has no deployment-qualified behavior")
    return document["claims"]


def validate_normative_documents() -> list[dict[str, Any]]:
    requirements = {
        "release/0.9.0/README.md": ("GLD-090-AUD-001", "GLD-090-LED-001"),
        "release/0.9.0/VERSION-ADAPTATION.md": ("GLD-090-REL-001", "GLD-090-REL-005"),
        "docs/CLAIMS.md": ("GLD-090-CLM-001", "GLD-090-CLM-004"),
        "docs/STATISTICAL-CONTRACT.md": ("GLD-090-STAT-001", "GLD-090-STAT-003"),
        "docs/THREAT-MODEL.md": ("GLD-090-THR-001", "GLD-090-THR-003"),
        "docs/ADVISORY-BOUNDARY.md": ("GLD-090-AUTH-001", "GLD-090-AUTH-002"),
        "docs/API-SURFACE.md": ("GLD-090-API-001", "GLD-090-API-004"),
        "SUPPORT.md": ("GLD-090-META-001", "GLD-090-META-002"),
        "docs/DEPENDENCY-POLICY.md": ("GLD-090-PIN-001", "GLD-090-PIN-004"),
        "RELEASE-POLICY.md": ("GLD-090-CTL-001", "GLD-090-CTL-005"),
    }
    artifacts = []
    for path_string, identifiers in requirements.items():
        path = ROOT / path_string
        if not path.is_file():
            raise AuditError(f"normative document is missing: {path_string}")
        content = path.read_text(encoding="utf-8")
        for identifier in identifiers:
            if identifier not in content:
                raise AuditError(f"{path_string}: missing normative ID {identifier}")
        if "**SHALL**" not in content and "**SHALL NOT**" not in content:
            raise AuditError(f"{path_string}: lacks explicit normative SHALL language")
        artifacts.append(artifact(path, "normative 0.9.0 release contract"))

    statistical = (ROOT / "docs/STATISTICAL-CONTRACT.md").read_text(encoding="utf-8")
    for field in (
        "sum_nis",
        "mean_nis",
        "p_right",
        "cusum_high_alarm",
        "cusum_low_alarm",
        "last_timestamp_ms",
        "corroboration",
        "redundancy",
        "synergy",
        "estimate_nats",
        "FusedVerdict",
        "PidVerdict",
    ):
        if field not in statistical:
            raise AuditError(f"statistical contract omits report field/verdict {field}")
    threat_model = (ROOT / "docs/THREAT-MODEL.md").read_text(encoding="utf-8").lower()
    for threat in (
        "spoof",
        "correlated or coordinated compromise",
        "missingness",
        "timestamp",
        "route/session/producer confusion",
        "denial of service",
    ):
        if threat not in threat_model:
            raise AuditError(f"threat model omits required class: {threat}")
    public_api = (RELEASE / "api" / "galadriel-core.0.9.0.txt").read_text(encoding="utf-8")
    if "pub mod galadriel_core::chi2" in public_api:
        raise AuditError("accepted API snapshot still exposes the accidental chi2 module")
    return artifacts


def validate_tasks() -> list[dict[str, Any]]:
    document = load_json(TASKS)
    require_keys(document, {"schema", "source", "source_sha256", "tasks"}, "tasks")
    source = ROOT / document["source"]
    if sha256(source) != document["source_sha256"]:
        raise AuditError("derived task inventory no longer matches the handoff ledger")
    tasks = document["tasks"]
    if len(tasks) != 120:
        raise AuditError(f"task inventory must contain 120 tasks, got {len(tasks)}")
    for index, task in enumerate(tasks):
        require_keys(task, {"id", "phase", "phase_title", "title", "priority", "dependencies"}, "task")
        expected = f"T{index:03d}"
        if task["id"] != expected or not TASK_ID.fullmatch(task["id"]):
            raise AuditError(f"task sequence is not contiguous at {expected}")
        expected_dependencies = [] if index == 0 else [f"T{index - 1:03d}"]
        if task["dependencies"] != expected_dependencies:
            raise AuditError(f"{expected}: dependency chain changed")
        if task["priority"] != "release_blocker":
            raise AuditError(f"{expected}: priority changed")
    return tasks


def validate_ledger(tasks: list[dict[str, Any]]) -> dict[str, Any]:
    document = load_json(DISPOSITIONS)
    require_keys(document, {"schema", "release", "overrides"}, "task dispositions")
    if document["schema"] != "galadriel.task-dispositions.v1" or document["release"] != VERSION:
        raise AuditError("task dispositions have the wrong schema or release")
    overrides: dict[str, Any] = {}
    for override in document["overrides"]:
        require_keys(
            override,
            {
                "task_id",
                "status",
                "requirement_ids",
                "requirements",
                "evidence",
                "tests",
                "review",
                "residual_risk",
            },
            "task disposition",
        )
        task_id = override["task_id"]
        if task_id in overrides or not TASK_ID.fullmatch(task_id):
            raise AuditError(f"invalid or duplicate task override: {task_id}")
        if override["status"] not in VALID_STATUSES - {"OPEN"}:
            raise AuditError(f"{task_id}: overrides may only close or explicitly disclaim")
        if not override["requirement_ids"] or not override["requirements"]:
            raise AuditError(f"{task_id}: disposition lacks normative requirements")
        for requirement in override["requirements"]:
            if " SHALL " not in f" {requirement} " and " SHALL NOT " not in f" {requirement} ":
                raise AuditError(f"{task_id}: requirement lacks explicit SHALL language")
        if override["status"] == "COMPLETE":
            if not override["evidence"] or not override["tests"]:
                raise AuditError(f"{task_id}: COMPLETE is prohibited without tests and evidence")
            if set(override["review"]) != set(LENSES):
                raise AuditError(f"{task_id}: ten-lens review is incomplete")
            if not all(override["review"][lens] for lens in LENSES):
                raise AuditError(f"{task_id}: ten-lens results must be concrete")
        else:
            if not override["residual_risk"]:
                raise AuditError(f"{task_id}: NOT_CLAIMED lacks an explicit reason")
        for path_string in [*override["evidence"], *override["tests"]]:
            evidence_path = ROOT / path_string.split("#", 1)[0]
            if not evidence_path.exists():
                raise AuditError(f"{task_id}: referenced evidence is missing: {path_string}")
        overrides[task_id] = override

    ledger_tasks = []
    previous_complete = True
    for task in tasks:
        override = overrides.get(task["id"])
        status = override["status"] if override else "OPEN"
        if status in {"COMPLETE", "NOT_CLAIMED"} and not previous_complete:
            raise AuditError(f"{task['id']}: cannot close before its dependency")
        previous_complete = status in {"COMPLETE", "NOT_CLAIMED"}
        ledger_tasks.append(
            {
                **task,
                "status": status,
                "requirement_ids": [] if override is None else override["requirement_ids"],
                "requirements": [] if override is None else override["requirements"],
                "evidence": [] if override is None else override["evidence"],
                "tests": [] if override is None else override["tests"],
                "review": {} if override is None else override["review"],
                "residual_risk": "Not yet reviewed." if override is None else override["residual_risk"],
            }
        )
    unknown = sorted(set(overrides) - {task["id"] for task in tasks})
    if unknown:
        raise AuditError(f"task dispositions contain unknown IDs: {unknown}")
    counts = {status: sum(item["status"] == status for item in ledger_tasks) for status in VALID_STATUSES}
    return {
        "schema": "galadriel.requirements-ledger.v1",
        "release": VERSION,
        "source_task_count": len(tasks),
        "status_counts": counts,
        "tasks": ledger_tasks,
    }


def build_outputs() -> tuple[dict[str, Any], dict[str, Any]]:
    inputs = load_json(INPUTS)
    validate_inputs(inputs)
    claims = validate_claims()
    tasks = validate_tasks()
    ledger = validate_ledger(tasks)
    metadata = validate_project_metadata(inputs)
    audit = {
        "schema": "galadriel.release-audit-manifest.v1",
        "audit_date": inputs["audit_date"],
        "release": metadata,
        "baseline_repository": inputs["baseline_repository"],
        "repositories": inputs["repositories"],
        "toolchains": inputs["toolchains"],
        "git_dependencies": lockfile_git_sources(),
        "artifacts": collect_artifacts(inputs),
        "normative_documents": validate_normative_documents(),
        "external_sources": collect_external_references(inputs),
        "claims": claims,
        "requirements": ledger["status_counts"],
        "adaptation_decision": inputs["adaptation_decision"],
    }
    return audit, ledger


def write_if_changed(path: Path, data: bytes) -> None:
    if path.exists() and path.read_bytes() == data:
        return
    path.write_bytes(data)


def generate() -> None:
    audit, ledger = build_outputs()
    write_if_changed(AUDIT_OUTPUT, canonical_bytes(audit))
    write_if_changed(LEDGER_OUTPUT, canonical_bytes(ledger))
    print(f"generated {AUDIT_OUTPUT.relative_to(ROOT)}")
    print(f"generated {LEDGER_OUTPUT.relative_to(ROOT)}")


def verify() -> None:
    audit, ledger = build_outputs()
    expected = {
        AUDIT_OUTPUT: canonical_bytes(audit),
        LEDGER_OUTPUT: canonical_bytes(ledger),
    }
    for path, data in expected.items():
        if not path.exists():
            raise AuditError(f"generated artifact is missing: {path.relative_to(ROOT)}")
        if path.read_bytes() != data:
            raise AuditError(
                f"generated artifact is stale: {path.relative_to(ROOT)}; run release-audit generate"
            )
    print("release audit verified")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("generate", "verify"))
    arguments = parser.parse_args()
    try:
        generate() if arguments.command == "generate" else verify()
    except AuditError as error:
        print(f"release audit failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
