#!/usr/bin/env python3
"""Finalize exact-candidate closure from separately completed review inputs.

The candidate remains unchanged.  This tool verifies its commit signature, the
signed qualification tier, a one-to-one completed review ledger, signed task
dispositions, and a signed final twenty-lens review.  It then emits a signed
closure tier and a separately signed release decision.  Manifests exclude their
own bytes and the later decision, avoiding digest self-reference.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from common import ReviewError, canonical_json, git, load_json, reject_duplicate_pairs
from qualify_candidate import BASE_COMMANDS, DEEP_COMMANDS, CommandSpec
from release_assurance import (
    AUTHOR,
    VERSION,
    assert_tracked_allowed_signer,
    derive_external_allowed_signers,
    digest_file,
    sign_file,
    validate_completed_file_ledger,
    validate_decision_input,
    validate_final_twenty_lens_review,
    validate_mutation_evidence,
    validate_reviewed_task_dispositions,
    verify_artifact_manifest,
    verify_candidate_commit,
    verify_signature,
)


QUALIFICATION_MANIFEST = "QUALIFICATION-MANIFEST.json"
QUALIFICATION_SIGNATURE = f"{QUALIFICATION_MANIFEST}.sig"
CLOSURE_MANIFEST = "CLOSURE-MANIFEST.json"
CLOSURE_SIGNATURE = f"{CLOSURE_MANIFEST}.sig"
RELEASE_DECISION = "RELEASE-DECISION.json"
RELEASE_DECISION_SIGNATURE = f"{RELEASE_DECISION}.sig"
ALLOWED_SIGNERS = "release/0.9.0/audit/ALLOWED_SIGNERS"
PLAN = "release/0.9.0/task-closure-plan.json"
CLAIMS = "release/0.9.0/claims.json"
TASKS = "release/0.9.0/tasks.json"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def candidate_json(repo: Path, commit: str, relative: str) -> dict[str, Any]:
    raw = bytes(git(repo, "show", f"{commit}:{relative}", text=False))
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReviewError(
            f"candidate JSON is invalid at {relative}: {error}"
        ) from error
    if not isinstance(value, dict):
        raise ReviewError(f"candidate JSON must be an object: {relative}")
    return value


def candidate_digest(repo: Path, commit: str, relative: str) -> str:
    raw = bytes(git(repo, "show", f"{commit}:{relative}", text=False))
    return hashlib.sha256(raw).hexdigest()


def artifact_rows(root: Path, excluded: set[str]) -> list[dict[str, Any]]:
    rows = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ReviewError(f"closure output contains a symlink: {relative}")
        if not path.is_file():
            continue
        if relative in excluded:
            continue
        digest, size = digest_file(path)
        rows.append({"path": relative, "sha256": digest, "size_bytes": size})
    return rows


def validate_candidate_plan_documents(
    plan: dict[str, Any], tasks_document: dict[str, Any]
) -> None:
    if (
        plan.get("schema") != "galadriel.task-closure-plan.v2"
        or len(plan.get("tasks", [])) != 116
    ):
        raise ReviewError("candidate source plan is incomplete")
    if tasks_document.get("source", {}).get("task_ledger_sha256") != plan.get(
        "source_task_ledger_sha256"
    ):
        raise ReviewError("candidate source plan targets another task ledger")


def validate_qualification_record(
    qualification: dict[str, Any],
    *,
    commit: str,
    tree: str,
    expected_evidence_config_sha256: str,
) -> dict[str, Any]:
    if qualification.get("schema") != "galadriel.candidate-qualification.v2":
        raise ReviewError("qualification record has the wrong schema")
    if (
        qualification.get("release") != VERSION
        or qualification.get("author") != AUTHOR
        or qualification.get("doi") is not None
        or qualification.get("zenodo") is not None
    ):
        raise ReviewError(
            "qualification record has the wrong release authorship or archive scope"
        )
    if (
        qualification.get("status") != "PASS"
        or qualification.get("command_status") != "PASS"
    ):
        raise ReviewError("qualification commands or artifacts did not pass")
    if (
        qualification.get("candidate", {}).get("commit") != commit
        or qualification.get("candidate", {}).get("tree") != tree
    ):
        raise ReviewError("qualification record targets the wrong candidate")
    if qualification.get("deep_campaigns_requested") is not True:
        raise ReviewError("qualification omitted the required deep campaigns")
    if qualification.get("evidence_config") != "evidence/galadriel-0.9-candidate.json":
        raise ReviewError(
            "qualification used another or omitted candidate evidence config"
        )
    binding = qualification.get("evidence_config_binding")
    if (
        not isinstance(binding, dict)
        or binding.get("tracked_path") != "evidence/galadriel-0.9-candidate.json"
        or binding.get("study_design_status") != "PASS"
        or binding.get("tracked_blob_sha256") != expected_evidence_config_sha256
        or not isinstance(binding.get("accepted_semantic_digest"), str)
        or len(binding["accepted_semantic_digest"]) != 64
    ):
        raise ReviewError("qualification lacks the exact preregistered config binding")
    mutation = qualification.get("mutation_evidence")
    if (
        not isinstance(mutation, dict)
        or mutation.get("status") != "PASS"
        or mutation.get("candidate") != {"commit": commit, "tree": tree}
        or mutation.get("shards") != 4
    ):
        raise ReviewError("qualification lacks exact-candidate mutation evidence")
    return binding


def _absolute_recorded_path(value: Any, context: str) -> Path:
    if not isinstance(value, str):
        raise ReviewError(f"{context} must be an absolute recorded path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ReviewError(f"{context} must be an absolute recorded path")
    return path


def _dynamic_qualification_specs(
    by_name: dict[str, dict[str, Any]], qualification_root: Path
) -> tuple[CommandSpec, ...]:
    verify_argv = by_name["verify-commit-signature-external-key"].get("argv")
    if (
        not isinstance(verify_argv, list)
        or len(verify_argv) != 5
        or verify_argv[:2] != ["git", "-c"]
        or verify_argv[3:] != ["verify-commit", "HEAD"]
        or not isinstance(verify_argv[2], str)
        or not verify_argv[2].startswith("gpg.ssh.allowedSignersFile=")
    ):
        raise ReviewError("qualification used another commit-verification command")
    trust_root = _absolute_recorded_path(
        verify_argv[2].split("=", 1)[1], "qualification external trust root"
    )
    if trust_root.name != "EXTERNAL_ALLOWED_SIGNERS":
        raise ReviewError(
            "qualification did not record the ephemeral external trust root"
        )

    inventory_argv = by_name["tracked-source-inventory"].get("argv")
    if not isinstance(inventory_argv, list) or len(inventory_argv) != 6:
        raise ReviewError("qualification source-inventory command is malformed")
    inventory = _absolute_recorded_path(
        inventory_argv[-1], "qualification source-inventory output"
    )
    output_root = inventory.parent
    if output_root != qualification_root.resolve():
        raise ReviewError("qualification commands target another output directory")
    if (
        inventory.name != "source-inventory"
        or trust_root == output_root
        or output_root in trust_root.parents
    ):
        raise ReviewError(
            "qualification output and external trust roots are not separate"
        )

    dynamic = (
        CommandSpec(
            "verify-commit-signature-external-key",
            tuple(verify_argv),
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
            "candidate-evidence",
            (
                "cargo",
                "run",
                "--release",
                "--locked",
                "-p",
                "galadriel-eval",
                "--bin",
                "galadriel-evidence",
                "--",
                "--config",
                "evidence/galadriel-0.9-candidate.json",
                "--out",
                str(output_root / "candidate-evidence"),
            ),
            timeout_seconds=7_200,
        ),
    )
    return dynamic


def validate_qualification_commands(
    commands: Any,
    *,
    manifest_artifacts: dict[str, dict[str, Any]],
    qualification_root: Path,
) -> None:
    """Bind every PASS result to the frozen argv contract and retained command output."""

    if not isinstance(commands, list) or not all(
        isinstance(item, dict) for item in commands
    ):
        raise ReviewError("qualification command results are missing or malformed")
    by_name = {
        command.get("name"): command
        for command in commands
        if isinstance(command.get("name"), str)
    }
    if len(by_name) != len(commands):
        raise ReviewError("qualification command names are invalid or duplicated")
    dynamic_names = {
        "verify-commit-signature-external-key",
        "tracked-source-inventory",
        "review-packets",
        "claim-language-inventory",
        "candidate-evidence",
    }
    if not dynamic_names.issubset(by_name):
        raise ReviewError("qualification omitted a dynamic candidate-bound command")
    dynamic = _dynamic_qualification_specs(by_name, qualification_root)
    dynamic_by_name = {spec.name: spec for spec in dynamic}
    ordered_specs = [
        dynamic_by_name["verify-commit-signature-external-key"],
        dynamic_by_name["tracked-source-inventory"],
        dynamic_by_name["review-packets"],
        dynamic_by_name["claim-language-inventory"],
        *BASE_COMMANDS,
        dynamic_by_name["candidate-evidence"],
        *DEEP_COMMANDS,
    ]
    expected_names = [spec.name for spec in ordered_specs]
    observed_names = [command.get("name") for command in commands]
    if observed_names != expected_names:
        raise ReviewError(
            "qualification command set or execution order differs from the frozen gate"
        )

    result_keys = {
        "name",
        "argv",
        "cwd",
        "environment_overrides",
        "started_at",
        "finished_at",
        "duration_seconds",
        "timeout_seconds",
        "timed_out",
        "exit_code",
        "status",
        "log",
        "log_sha256",
        "log_size_bytes",
    }
    marker = b"--- combined stdout/stderr ---\n"
    for spec, result in zip(ordered_specs, commands, strict=True):
        if set(result) != result_keys:
            raise ReviewError(
                f"qualification result {spec.name} has an unexpected field set"
            )
        if (
            result["argv"] != list(spec.argv)
            or result["cwd"] != spec.cwd
            or result["environment_overrides"] != dict(spec.environment)
            or result["timeout_seconds"] != spec.timeout_seconds
        ):
            raise ReviewError(f"qualification command contract drifted for {spec.name}")
        if (
            result["status"] != "PASS"
            or result["exit_code"] != 0
            or result["timed_out"] is not False
        ):
            raise ReviewError(
                f"qualification command did not pass cleanly: {spec.name}"
            )
        relative = result["log"]
        manifest_row = (
            manifest_artifacts.get(relative) if isinstance(relative, str) else None
        )
        if (
            manifest_row is None
            or result["log_sha256"] != manifest_row["sha256"]
            or result["log_size_bytes"] != manifest_row["size_bytes"]
        ):
            raise ReviewError(
                f"qualification command output is not manifest-bound: {spec.name}"
            )
        log = qualification_root / relative
        prefix, separator, _output = log.read_bytes().partition(marker)
        if not separator:
            raise ReviewError(
                f"qualification command output lacks its header: {spec.name}"
            )
        try:
            header = json.loads(prefix, object_pairs_hook=reject_duplicate_pairs)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ReviewError(
                f"qualification command header is invalid: {spec.name}: {error}"
            ) from error
        if header != {
            "argv": result["argv"],
            "cwd": result["cwd"],
            "environment_overrides": result["environment_overrides"],
            "started_at": result["started_at"],
            "timeout_seconds": result["timeout_seconds"],
        }:
            raise ReviewError(
                f"qualification command header contradicts its result: {spec.name}"
            )


def verify_qualification(
    root: Path,
    *,
    repo: Path,
    allowed_signers: Path,
    commit: str,
    tree: str,
    expected_evidence_config_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    manifest_path = root / QUALIFICATION_MANIFEST
    signature_path = root / QUALIFICATION_SIGNATURE
    verify_signature(
        manifest_path,
        signature_path,
        allowed_signers,
        "galadriel-qualification-manifest",
    )
    manifest = verify_artifact_manifest(
        root,
        manifest_path,
        expected_schema="galadriel.tiered-artifact-manifest.v1",
        forbidden_paths={
            QUALIFICATION_MANIFEST,
            QUALIFICATION_SIGNATURE,
            CLOSURE_MANIFEST,
            CLOSURE_SIGNATURE,
            RELEASE_DECISION,
            RELEASE_DECISION_SIGNATURE,
            "SHA256SUMS",
        },
    )
    if manifest["tier"] != "qualification" or manifest["candidate"] != {
        "commit": commit,
        "tree": tree,
    }:
        raise ReviewError("qualification manifest targets the wrong tier or candidate")
    paths = {item["path"] for item in manifest["artifacts"]}
    mandatory = {
        "qualification.json",
        "candidate-acceptance.json",
        "candidate-evidence/config.json",
        "candidate-evidence/manifest.json",
        "candidate-evidence/summary.json",
        "cargo-metadata.json",
        "REPRODUCIBILITY.json",
        "provenance.json",
        f"galadriel-{VERSION}.tar.gz",
        "reports/license-report.jsonl",
        "reports/vulnerability-report.json",
        "source-inventory/TRACKED_FILE_MANIFEST.json",
        "source-inventory/FILE_REVIEW_LEDGER.csv",
        "mutation/manifest.json",
        "mutation/manifest.json.sig",
    }
    missing = sorted(mandatory - paths)
    if missing:
        raise ReviewError(
            f"qualification manifest omits mandatory artifacts: {missing}"
        )
    if (
        len(
            [
                path
                for path in paths
                if path.startswith("packages/") and path.endswith(".crate")
            ]
        )
        != 7
    ):
        raise ReviewError(
            "qualification tier must contain seven reproducible package artifacts"
        )
    if (
        len(
            [
                path
                for path in paths
                if path.startswith("sbom/") and path.endswith(".cdx.json")
            ]
        )
        != 7
    ):
        raise ReviewError("qualification tier must contain seven workspace SBOMs")
    mutation_document, mutation_artifacts = validate_mutation_evidence(
        root / "mutation" / "manifest.json",
        root / "mutation" / "manifest.json.sig",
        allowed_signers=allowed_signers,
        repo=repo,
        commit=commit,
        tree=tree,
    )
    if len(mutation_artifacts) != 4:
        raise ReviewError(
            "qualification tier must contain four exact-diff mutation shards"
        )

    qualification = load_json(root / "qualification.json")
    config_binding = validate_qualification_record(
        qualification,
        commit=commit,
        tree=tree,
        expected_evidence_config_sha256=expected_evidence_config_sha256,
    )
    manifest_artifacts = {item["path"]: item for item in manifest["artifacts"]}
    if (
        config_binding.get("accepted_config_sha256")
        != manifest_artifacts["candidate-evidence/config.json"]["sha256"]
    ):
        raise ReviewError(
            "qualification evidence config binding differs from the retained bytes"
        )
    validate_qualification_commands(
        qualification.get("commands"),
        manifest_artifacts=manifest_artifacts,
        qualification_root=root,
    )
    expected_tools = {
        "cargo_deny": "cargo-deny 0.19.9",
        "cargo_audit": "cargo-audit-audit 0.22.2",
        "cargo_cyclonedx": "cargo-cyclonedx-cyclonedx 0.5.9",
        "cargo_public_api": "cargo-public-api 0.52.0",
        "cargo_fuzz": "cargo-fuzz 0.13.2",
    }
    tools = qualification.get("tools")
    if not isinstance(tools, dict) or any(
        tools.get(name) != identity for name, identity in expected_tools.items()
    ):
        raise ReviewError("qualification used an unpinned release tool")
    source_date_epoch = int(
        str(git(repo, "show", "-s", "--format=%ct", commit)).strip()
    )
    if qualification.get("environment_contract") != {
        "CARGO_INCREMENTAL": "0",
        "CARGO_TERM_COLOR": "never",
        "LC_ALL": "C",
        "SOURCE_DATE_EPOCH": str(source_date_epoch),
        "TZ": "UTC",
    }:
        raise ReviewError(
            "qualification used another deterministic environment contract"
        )
    mutation_record = qualification.get("mutation_evidence")
    if not isinstance(mutation_record, dict) or set(mutation_record) != {
        "manifest",
        "manifest_sha256",
        "signature",
        "candidate",
        "baseline_commit",
        "shards",
        "status",
        "artifacts",
    }:
        raise ReviewError("qualification mutation record is malformed")
    if (
        mutation_record["manifest"] != "mutation/manifest.json"
        or mutation_record["signature"] != "mutation/manifest.json.sig"
        or mutation_record["manifest_sha256"]
        != manifest_artifacts["mutation/manifest.json"]["sha256"]
        or mutation_record["candidate"] != {"commit": commit, "tree": tree}
        or mutation_record["baseline_commit"] != mutation_document["baseline_commit"]
        or mutation_record["shards"] != 4
        or mutation_record["status"] != "PASS"
        or not isinstance(mutation_record["artifacts"], list)
    ):
        raise ReviewError("qualification mutation record is not exact-candidate bound")
    expected_mutation_paths = {
        path.relative_to(root).as_posix() for path in mutation_artifacts
    }
    observed_mutation_paths: set[str] = set()
    for artifact in mutation_record["artifacts"]:
        if not isinstance(artifact, dict) or set(artifact) != {
            "path",
            "sha256",
            "size_bytes",
        }:
            raise ReviewError("qualification mutation artifact record is malformed")
        path = artifact["path"]
        row = manifest_artifacts.get(path) if isinstance(path, str) else None
        if (
            row is None
            or path in observed_mutation_paths
            or (artifact["sha256"], artifact["size_bytes"])
            != (row["sha256"], row["size_bytes"])
        ):
            raise ReviewError(
                "qualification mutation artifact is duplicate or not manifest-bound"
            )
        observed_mutation_paths.add(path)
    if observed_mutation_paths != expected_mutation_paths:
        raise ReviewError("qualification mutation record omits exact shard outcomes")

    expected_crates = {
        "galadriel-cli",
        "galadriel-core",
        "galadriel-eval",
        "galadriel-justify",
        "galadriel-ncp",
        "galadriel-pid",
        "galadriel-sim",
    }
    packages = qualification.get("packages")
    sboms = qualification.get("sboms")
    if not isinstance(packages, list) or not isinstance(sboms, list):
        raise ReviewError("qualification record lacks package or SBOM coverage")
    package_by_crate: dict[str, dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict) or set(package) != {
            "crate",
            "version",
            "candidate_commit",
            "package_kind",
            "lockfile_policy",
            "dependency_resolution",
            "path",
            "sha256",
            "size_bytes",
        }:
            raise ReviewError("qualification package record is malformed")
        crate = package["crate"]
        if not isinstance(crate, str) or not isinstance(package["path"], str):
            raise ReviewError("qualification package identity is malformed")
        expected_path = f"packages/{crate}-{VERSION}.crate"
        row = manifest_artifacts.get(package["path"])
        if (
            crate in package_by_crate
            or package["version"] != VERSION
            or package["candidate_commit"] != commit
            or package["package_kind"] != "cargo_package_unpublished_source"
            or package["lockfile_policy"]
            != "excluded; candidate Cargo.lock is retained in the source archive"
            or package["dependency_resolution"]
            != "offline temporary path overrides for locked unpublished workspace and Git dependencies"
            or package["path"] != expected_path
            or row is None
            or (package["sha256"], package["size_bytes"])
            != (row["sha256"], row["size_bytes"])
        ):
            raise ReviewError(
                "qualification package record is duplicate or not manifest-bound"
            )
        package_by_crate[crate] = package
    if set(package_by_crate) != expected_crates:
        raise ReviewError(
            "qualification package set differs from the release workspace"
        )

    sbom_by_crate: dict[str, dict[str, Any]] = {}
    for sbom in sboms:
        if not isinstance(sbom, dict) or set(sbom) != {
            "crate",
            "path",
            "sha256",
            "size_bytes",
        }:
            raise ReviewError("qualification SBOM record is malformed")
        crate = sbom["crate"]
        if not isinstance(crate, str) or not isinstance(sbom["path"], str):
            raise ReviewError("qualification SBOM identity is malformed")
        expected_path = f"sbom/{crate}.cdx.json"
        row = manifest_artifacts.get(sbom["path"])
        if (
            crate in sbom_by_crate
            or sbom["path"] != expected_path
            or row is None
            or (sbom["sha256"], sbom["size_bytes"])
            != (row["sha256"], row["size_bytes"])
        ):
            raise ReviewError(
                "qualification SBOM record is duplicate or not manifest-bound"
            )
        document = load_json(root / sbom["path"])
        if (
            not isinstance(document, dict)
            or document.get("bomFormat") != "CycloneDX"
            or document.get("specVersion") != "1.5"
        ):
            raise ReviewError(f"qualification SBOM has the wrong format: {crate}")
        sbom_by_crate[crate] = sbom
    if set(sbom_by_crate) != expected_crates:
        raise ReviewError("qualification SBOM set differs from the release workspace")
    cargo_metadata = load_json(root / "cargo-metadata.json")
    if not isinstance(cargo_metadata, dict):
        raise ReviewError("qualification Cargo metadata is malformed")
    workspace_members = cargo_metadata.get("workspace_members")
    metadata_packages = cargo_metadata.get("packages")
    if (
        not isinstance(workspace_members, list)
        or not all(isinstance(member, str) for member in workspace_members)
        or not isinstance(metadata_packages, list)
        or not all(isinstance(package, dict) for package in metadata_packages)
    ):
        raise ReviewError("qualification Cargo metadata lacks workspace identities")
    workspace_member_set = set(workspace_members)
    observed_workspace = {
        (package.get("name"), package.get("version"))
        for package in metadata_packages
        if isinstance(package.get("id"), str) and package["id"] in workspace_member_set
    }
    if observed_workspace != {(crate, VERSION) for crate in expected_crates}:
        raise ReviewError(
            "qualification Cargo metadata targets another workspace package set"
        )

    archive = qualification.get("source_archive")
    archive_path = f"galadriel-{VERSION}.tar.gz"
    archive_row = manifest_artifacts[archive_path]
    if (
        not isinstance(archive, dict)
        or archive.get("path") != archive_path
        or (archive.get("sha256"), archive.get("size_bytes"))
        != (archive_row["sha256"], archive_row["size_bytes"])
        or not isinstance(archive.get("tracked_entries"), int)
        or archive["tracked_entries"] <= 0
    ):
        raise ReviewError("qualification source archive is not manifest-bound")
    reproducibility_pointer = qualification.get("reproducibility")
    if reproducibility_pointer != {"path": "REPRODUCIBILITY.json", "status": "PASS"}:
        raise ReviewError("two-run package/source reproducibility did not pass")
    reproducibility = load_json(root / "REPRODUCIBILITY.json")
    if (
        not isinstance(reproducibility, dict)
        or reproducibility.get("schema") != "galadriel.reproducibility-comparison.v1"
        or reproducibility.get("candidate") != {"commit": commit, "tree": tree}
        or reproducibility.get("status") != "PASS"
        or not isinstance(reproducibility.get("comparisons"), list)
    ):
        raise ReviewError("reproducibility record targets another candidate or status")
    comparisons = reproducibility["comparisons"]
    if len(comparisons) != 8:
        raise ReviewError(
            "reproducibility record lacks one source and seven package comparisons"
        )
    expected_comparisons = {archive_path: archive}
    expected_comparisons.update(
        {
            f"{crate}-{VERSION}.crate": package
            for crate, package in package_by_crate.items()
        }
    )
    seen_comparisons: set[str] = set()
    for comparison in comparisons:
        if not isinstance(comparison, dict) or set(comparison) != {
            "kind",
            "name",
            "run_1_sha256",
            "run_2_sha256",
            "size_bytes",
            "status",
        }:
            raise ReviewError("reproducibility comparison is malformed")
        name = comparison["name"]
        expected = expected_comparisons.get(name)
        expected_kind = "source_archive" if name == archive_path else "cargo_package"
        if (
            expected is None
            or name in seen_comparisons
            or comparison["kind"] != expected_kind
            or comparison["status"] != "IDENTICAL"
            or comparison["run_1_sha256"] != expected["sha256"]
            or comparison["run_2_sha256"] != expected["sha256"]
            or comparison["size_bytes"] != expected["size_bytes"]
        ):
            raise ReviewError(
                "reproducibility comparison contradicts the retained artifact"
            )
        seen_comparisons.add(name)
    if seen_comparisons != set(expected_comparisons):
        raise ReviewError("reproducibility comparisons omit release artifacts")

    provenance = load_json(root / "provenance.json")
    if (
        not isinstance(provenance, dict)
        or provenance.get("schema") != "galadriel.slsa-provenance.v1"
        or provenance.get("release") != VERSION
        or provenance.get("subject") != {"commit": commit, "tree": tree}
        or provenance.get("builder")
        != {
            "kind": "author-operated isolated qualification worktree",
            "tools": tools,
        }
        or provenance.get("invocation")
        != {
            "source_date_epoch": source_date_epoch,
            "deep_campaigns_requested": True,
            "evidence_config": "evidence/galadriel-0.9-candidate.json",
        }
        or provenance.get("materials")
        != {
            "source_archive_sha256": archive["sha256"],
            "package_sha256": [package["sha256"] for package in packages],
            "sbom_sha256": [sbom["sha256"] for sbom in sboms],
        }
    ):
        raise ReviewError(
            "qualification provenance contradicts its candidate or materials"
        )

    report_contracts = (
        (
            "license_report",
            "reports/license-report.jsonl",
            [
                "cargo",
                "deny",
                "--format",
                "json",
                "--all-features",
                "--locked",
                "check",
                "licenses",
            ],
        ),
        (
            "vulnerability_report",
            "reports/vulnerability-report.json",
            [
                "cargo",
                "audit",
                "--no-yanked",
                "--ignore",
                "RUSTSEC-2026-0041",
                "--format",
                "json",
            ],
        ),
    )
    for field, relative, argv in report_contracts:
        report = qualification.get(field)
        row = manifest_artifacts[relative]
        if (
            not isinstance(report, dict)
            or set(report) != {"argv", "path", "sha256", "size_bytes", "stderr"}
            or report["argv"] != argv
            or report["path"] != relative
            or (report["sha256"], report["size_bytes"])
            != (row["sha256"], row["size_bytes"])
        ):
            raise ReviewError(
                f"qualification {field} is not command- and manifest-bound"
            )
    license_documents = [
        json.loads(line, object_pairs_hook=reject_duplicate_pairs)
        for line in (root / "reports/license-report.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    if not license_documents or not all(
        isinstance(item, dict) for item in license_documents
    ):
        raise ReviewError("qualification license report is empty or malformed")
    license_summaries = [
        item for item in license_documents if item.get("type") == "summary"
    ]
    license_counts = (
        license_summaries[-1].get("fields", {}).get("licenses", {})
        if license_summaries
        else {}
    )
    if license_counts.get("errors") != 0 or license_counts.get("warnings") != 0:
        raise ReviewError("qualification license report contains errors or warnings")
    vulnerability = load_json(root / "reports/vulnerability-report.json")
    if (
        vulnerability.get("vulnerabilities", {}).get("found") is not False
        or vulnerability.get("vulnerabilities", {}).get("count") != 0
    ):
        raise ReviewError("qualification vulnerability report contains a finding")

    acceptance = load_json(root / "candidate-acceptance.json")
    if (
        not isinstance(acceptance, dict)
        or acceptance.get("schema") != "galadriel.candidate-acceptance.v1"
    ):
        raise ReviewError("candidate acceptance record has the wrong schema")
    if (
        acceptance.get("release") != VERSION
        or acceptance.get("partition") != "holdout_results"
    ):
        raise ReviewError(
            "candidate acceptance used another release or evidence partition"
        )
    if acceptance.get("status") not in {"PASS", "FAIL"}:
        raise ReviewError("candidate acceptance was not evaluated")
    if qualification.get("acceptance", {}).get("status") != acceptance["status"]:
        raise ReviewError("qualification and acceptance status differ")
    if qualification.get("acceptance", {}).get(
        "failed_criterion_ids"
    ) != acceptance.get("failed_criterion_ids"):
        raise ReviewError("qualification and acceptance failure sets differ")
    if acceptance.get("evaluation_error"):
        raise ReviewError("candidate acceptance evaluation ended in an error")
    if any(
        criterion.get("evaluation_error")
        for criterion in acceptance.get("criteria", [])
        if isinstance(criterion, dict)
    ):
        raise ReviewError(
            "a required acceptance arm was missing, duplicate, or non-estimable"
        )
    criteria = acceptance.get("criteria")
    expected_criteria = [f"GLD-090-ACC-{number:03d}" for number in range(1, 8)]
    if (
        not isinstance(criteria, list)
        or not all(isinstance(criterion, dict) for criterion in criteria)
        or [criterion.get("id") for criterion in criteria] != expected_criteria
        or not isinstance(acceptance.get("minimum_metric_eligible_tracks"), int)
        or isinstance(acceptance["minimum_metric_eligible_tracks"], bool)
        or acceptance["minimum_metric_eligible_tracks"] < 20
    ):
        raise ReviewError(
            "candidate acceptance does not cover the seven frozen criteria"
        )
    for criterion in criteria:
        observations = criterion.get("observations")
        if (
            not isinstance(observations, list)
            or not observations
            or not all(isinstance(observation, dict) for observation in observations)
            or any(
                observation.get("status") not in {"PASS", "FAIL"}
                for observation in observations
            )
            or criterion.get("status")
            != (
                "PASS"
                if all(observation["status"] == "PASS" for observation in observations)
                else "FAIL"
            )
        ):
            raise ReviewError(
                "candidate acceptance criterion contradicts its observations"
            )
    failed = [
        criterion["id"] for criterion in criteria if criterion.get("status") == "FAIL"
    ]
    if acceptance.get("failed_criterion_ids") != failed or acceptance["status"] != (
        "PASS" if not failed else "FAIL"
    ):
        raise ReviewError(
            "candidate acceptance status contradicts its criterion results"
        )
    expected_release_gate = (
        "PASS" if acceptance["status"] == "PASS" else "NARROWED_REVIEW_REQUIRED"
    )
    if qualification.get("release_gate") != expected_release_gate:
        raise ReviewError("qualification release gate contradicts candidate acceptance")
    return manifest, qualification, acceptance


def copy_input(source: Path, destination: Path) -> Path:
    if not source.is_file() or source.is_symlink():
        raise ReviewError(f"closure input is missing or unsafe: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--qualification", required=True)
    parser.add_argument("--review-ledger", required=True)
    parser.add_argument("--task-dispositions", required=True)
    parser.add_argument("--task-dispositions-signature", required=True)
    parser.add_argument("--final-review", required=True)
    parser.add_argument("--final-review-signature", required=True)
    parser.add_argument("--decision-input", required=True)
    parser.add_argument("--signing-key", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--require-branch", default="main")
    arguments = parser.parse_args()

    repo = Path(arguments.repo).resolve()
    qualification_root = Path(arguments.qualification).resolve()
    review_ledger = Path(arguments.review_ledger).resolve()
    task_dispositions_path = Path(arguments.task_dispositions).resolve()
    task_dispositions_signature = Path(arguments.task_dispositions_signature).resolve()
    final_review_path = Path(arguments.final_review).resolve()
    final_review_signature = Path(arguments.final_review_signature).resolve()
    decision_input_path = Path(arguments.decision_input).resolve()
    signing_key = Path(arguments.signing_key).expanduser().resolve()
    output = Path(arguments.out).resolve()

    trust_temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        if output.exists() or output == repo or repo in output.parents:
            raise ReviewError(
                "--out must be a new directory outside the candidate repository"
            )
        if output == qualification_root or qualification_root in output.parents:
            raise ReviewError("--out must be separate from the qualification tier")
        if str(git(repo, "status", "--porcelain=v1", "--untracked-files=all")).strip():
            raise ReviewError("finalization requires a clean candidate checkout")
        head = str(git(repo, "rev-parse", "HEAD^{commit}")).strip()
        if head != arguments.candidate:
            raise ReviewError(
                f"candidate mismatch: expected={arguments.candidate} actual={head}"
            )
        branch = str(git(repo, "branch", "--show-current")).strip()
        if arguments.require_branch and branch != arguments.require_branch:
            raise ReviewError(
                f"candidate branch must be {arguments.require_branch!r}, got {branch!r}"
            )
        trust_temporary = tempfile.TemporaryDirectory(
            prefix="galadriel-external-trust-"
        )
        allowed_signers = Path(trust_temporary.name) / "ALLOWED_SIGNERS"
        expected_signer_metadata = derive_external_allowed_signers(
            signing_key, allowed_signers
        )
        assert_tracked_allowed_signer(repo / ALLOWED_SIGNERS, expected_signer_metadata)
        tree = verify_candidate_commit(repo, head, allowed_signers)

        plan = candidate_json(repo, head, PLAN)
        claims_document = candidate_json(repo, head, CLAIMS)
        tasks_document = candidate_json(repo, head, TASKS)
        validate_candidate_plan_documents(plan, tasks_document)
        claims = {claim["id"]: claim for claim in claims_document.get("claims", [])}
        if len(claims) != len(claims_document.get("claims", [])):
            raise ReviewError("candidate claims matrix contains duplicate IDs")
        excluded_claim_ids = {
            claim_id
            for claim_id, claim in claims.items()
            if claim.get("tier") == "NOT_CLAIMED"
        }
        source_plan_sha256 = candidate_digest(repo, head, PLAN)

        qualification_manifest, qualification, acceptance = verify_qualification(
            qualification_root,
            repo=repo,
            allowed_signers=allowed_signers,
            commit=head,
            tree=tree,
            expected_evidence_config_sha256=candidate_digest(
                repo, head, "evidence/galadriel-0.9-candidate.json"
            ),
        )
        file_review = validate_completed_file_ledger(
            review_ledger,
            repo,
            head,
            source_ledger=qualification_root
            / "source-inventory/FILE_REVIEW_LEDGER.csv",
        )

        verify_signature(
            task_dispositions_path,
            task_dispositions_signature,
            allowed_signers,
            "galadriel-task-dispositions",
        )
        task_dispositions = load_json(task_dispositions_path)
        task_counts = validate_reviewed_task_dispositions(
            task_dispositions,
            plan=plan,
            claims=claims,
            repo=repo,
            commit=head,
            tree=tree,
            qualification_root=qualification_root,
            source_plan_sha256=source_plan_sha256,
        )

        verify_signature(
            final_review_path,
            final_review_signature,
            allowed_signers,
            "galadriel-final-review",
        )
        final_review = load_json(final_review_path)
        final_review_summary = validate_final_twenty_lens_review(
            final_review,
            lens_catalog=plan["lens_catalog"],
            repo=repo,
            commit=head,
            tree=tree,
            qualification_root=qualification_root,
        )

        decision_input = load_json(decision_input_path)
        validate_decision_input(
            decision_input,
            acceptance=acceptance,
            excluded_claim_ids=excluded_claim_ids,
        )
        if set(decision_input["removed_claim_ids"]) != excluded_claim_ids:
            raise ReviewError(
                "release decision must acknowledge every excluded public claim"
            )
        task_removed = {
            claim_id
            for disposition in task_dispositions["dispositions"]
            for claim_id in disposition["removed_claim_ids"]
        }
        if not task_removed.issubset(set(decision_input["removed_claim_ids"])):
            raise ReviewError(
                "release decision omits claims removed by task dispositions"
            )

        output.mkdir(parents=True, exist_ok=False)
        inputs = output / "inputs"
        retained_ledger = copy_input(
            review_ledger, inputs / "FILE_REVIEW_LEDGER.completed.csv"
        )
        retained_dispositions = copy_input(
            task_dispositions_path, inputs / "reviewed-task-dispositions.json"
        )
        retained_dispositions_signature = copy_input(
            task_dispositions_signature, inputs / "reviewed-task-dispositions.json.sig"
        )
        retained_review = copy_input(
            final_review_path, inputs / "FINAL-TWENTY-LENS-REVIEW.json"
        )
        retained_review_signature = copy_input(
            final_review_signature, inputs / "FINAL-TWENTY-LENS-REVIEW.json.sig"
        )
        retained_decision_input = copy_input(
            decision_input_path, inputs / "release-decision-input.json"
        )

        closure_summary = {
            "schema": "galadriel.exact-candidate-closure.v1",
            "release": VERSION,
            "author": AUTHOR,
            "candidate": {"commit": head, "tree": tree},
            "qualification": {
                "manifest_sha256": digest_file(
                    qualification_root / QUALIFICATION_MANIFEST
                )[0],
                "manifest_signature_sha256": digest_file(
                    qualification_root / QUALIFICATION_SIGNATURE
                )[0],
                "command_status": qualification["command_status"],
                "acceptance_status": acceptance["status"],
                "failed_criterion_ids": acceptance["failed_criterion_ids"],
            },
            "file_review": file_review,
            "task_dispositions": task_counts,
            "final_review": final_review_summary,
            "source_task_ledger_sha256": plan["source_task_ledger_sha256"],
            "source_plan_sha256": source_plan_sha256,
        }
        (output / "closure-summary.json").write_bytes(canonical_json(closure_summary))

        closure_manifest_path = output / CLOSURE_MANIFEST
        closure_manifest_path.write_bytes(
            canonical_json(
                {
                    "schema": "galadriel.tiered-artifact-manifest.v1",
                    "tier": "closure",
                    "candidate": {"commit": head, "tree": tree},
                    "artifacts": artifact_rows(
                        output,
                        {
                            CLOSURE_MANIFEST,
                            CLOSURE_SIGNATURE,
                            RELEASE_DECISION,
                            RELEASE_DECISION_SIGNATURE,
                            "SHA256SUMS",
                        },
                    ),
                }
            )
        )
        closure_signature_path = sign_file(
            closure_manifest_path, signing_key, "galadriel-closure-manifest"
        )
        verify_signature(
            closure_manifest_path,
            closure_signature_path,
            allowed_signers,
            "galadriel-closure-manifest",
        )
        verify_artifact_manifest(
            output,
            closure_manifest_path,
            expected_schema="galadriel.tiered-artifact-manifest.v1",
            forbidden_paths={
                CLOSURE_MANIFEST,
                CLOSURE_SIGNATURE,
                RELEASE_DECISION,
                RELEASE_DECISION_SIGNATURE,
                "SHA256SUMS",
            },
        )

        def signed_digest(path: Path) -> str:
            return digest_file(path)[0]

        decision = {
            "schema": "galadriel.release-decision.v2",
            "release": VERSION,
            "author": AUTHOR,
            "issued_at": utc_now(),
            "decision": decision_input["decision"],
            "publication_scope": decision_input["publication_scope"],
            "doi": None,
            "zenodo": None,
            "candidate": {"commit": head, "tree": tree},
            "source_task_ledger_sha256": plan["source_task_ledger_sha256"],
            "source_plan_sha256": source_plan_sha256,
            "qualification_manifest_sha256": signed_digest(
                qualification_root / QUALIFICATION_MANIFEST
            ),
            "qualification_manifest_signature_sha256": signed_digest(
                qualification_root / QUALIFICATION_SIGNATURE
            ),
            "completed_file_review_ledger_sha256": signed_digest(retained_ledger),
            "reviewed_task_dispositions_sha256": signed_digest(retained_dispositions),
            "reviewed_task_dispositions_signature_sha256": signed_digest(
                retained_dispositions_signature
            ),
            "final_twenty_lens_review_sha256": signed_digest(retained_review),
            "final_twenty_lens_review_signature_sha256": signed_digest(
                retained_review_signature
            ),
            "decision_input_sha256": signed_digest(retained_decision_input),
            "closure_manifest_sha256": signed_digest(closure_manifest_path),
            "closure_manifest_signature_sha256": signed_digest(closure_signature_path),
            "acceptance": {
                "record_sha256": signed_digest(
                    qualification_root / "candidate-acceptance.json"
                ),
                "status": acceptance["status"],
                "failed_criterion_ids": acceptance["failed_criterion_ids"],
                "failure_dispositions": decision_input[
                    "acceptance_failure_dispositions"
                ],
            },
            "closed_task_count": task_counts["total"],
            "complete_with_exclusions_task_count": task_counts[
                "complete_with_exclusions"
            ],
            "not_claimed_task_count": task_counts["not_claimed"],
            "removed_claim_ids": decision_input["removed_claim_ids"],
            "residual_risks": decision_input["residual_risks"],
        }
        decision_path = output / RELEASE_DECISION
        decision_path.write_bytes(canonical_json(decision))
        decision_signature_path = sign_file(
            decision_path, signing_key, "galadriel-release-decision"
        )
        verify_signature(
            decision_path,
            decision_signature_path,
            allowed_signers,
            "galadriel-release-decision",
        )

        rows = artifact_rows(output, {"SHA256SUMS"})
        with (output / "SHA256SUMS").open(
            "w", encoding="utf-8", newline="\n"
        ) as handle:
            for row in rows:
                handle.write(f"{row['sha256']}  {row['path']}\n")
        print(
            json.dumps(
                {
                    "candidate": head,
                    "tree": tree,
                    "decision": decision["decision"],
                    "closed_tasks": task_counts["total"],
                    "reviewed_files": file_review["reviewed_files"],
                    "acceptance": acceptance["status"],
                    "output": str(output),
                },
                sort_keys=True,
            )
        )
        return 0
    except (OSError, ReviewError, ValueError) as error:
        print(f"release finalization failed: {error}", file=sys.stderr)
        return 2
    finally:
        if trust_temporary is not None:
            trust_temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
