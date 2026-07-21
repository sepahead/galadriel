#!/usr/bin/env python3
"""Build and verify the signed Galadriel local-convergence record."""

from __future__ import annotations

import argparse
import copy
import hashlib
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

from common import ReviewError, canonical_json, loads_json
from freeze_audit_inputs import read_bounded_regular_file


PROJECT = "Galadriel"
VERSION = "0.9.0"
SCHEMA_ID = (
    "https://raw.githubusercontent.com/sepahead/galadriel/v0.9.0/"
    "release/0.9.0/local-convergence-schema.json"
)
SCHEMA_PATH = "release/0.9.0/local-convergence-schema.json"
SIGNATURE_NAMESPACE = "galadriel-local-convergence"
MAX_SCHEMA_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
MAX_ALLOWED_SIGNERS_BYTES = 4 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_AGGREGATE_ARTIFACT_BYTES = 128 * 1024 * 1024
HEX_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TOP_LEVEL_FIELDS = (
    "project",
    "release_target",
    "source_commit",
    "tree_clean",
    "tracked_files",
    "reviewed_files",
    "completed_tasks",
    "waves",
    "artifacts",
    "cross_repo_requirements",
    "ready_for_cross_repo_reconciliation",
)
WAVE_RANGES = (
    range(0, 12),
    range(12, 24),
    range(24, 36),
    range(36, 48),
    range(48, 60),
    range(60, 72),
    range(72, 84),
    range(84, 96),
    range(96, 108),
    range(108, 116),
)
COMPLETED_TASKS = tuple(f"T{index:03d}" for index in range(116))
CONVERGENCE_ARTIFACT_PATHS = tuple(
    sorted(
        (
            "RELEASE-DECISION.json",
            "RELEASE-DECISION.json.sig",
            "closure-summary.json",
            "inputs/FILE_REVIEW_LEDGER.completed.csv",
            "inputs/reviewed-task-dispositions.json",
            "inputs/reviewed-task-dispositions.json.sig",
            "inputs/FINAL-TWENTY-LENS-REVIEW.json",
            "inputs/FINAL-TWENTY-LENS-REVIEW.json.sig",
        )
    )
)
RESERVED_CONVERGENCE_NAMES = frozenset(
    {"local-convergence.json", "local-convergence.json.sig"}
)
ALLOWED_INPUT_ARTIFACT_PATHS = frozenset(
    path for path in CONVERGENCE_ARTIFACT_PATHS if path.startswith("inputs/")
)
WAVE_EVIDENCE = CONVERGENCE_ARTIFACT_PATHS
CROSS_REPO_REQUIREMENTS: tuple[dict[str, Any], ...] = (
    {
        "project": "pid-rs",
        "direction": "upstream_library",
        "classification": "required_optional_build_dependency",
        "dependency_pin_required_for_qualified_graphs": True,
        "pin": "1cd2424f7967e1752dcc8e53859e8fdad3566f51",
        "status": "LOCAL_PIN_VERIFIED_RECIPROCAL_NOT_CLAIMED",
        "conditions": [
            "Local qualification must verify the exact pid-core source, version, and enabled feature aliases used by Galadriel 0.9.0.",
            "Keep the parallel feature disabled and do not treat a shared implementation as independent replication evidence.",
            "Reciprocal final-candidate acceptance is not a publication prerequisite and remains unclaimed until a separately signed reconciliation exists.",
        ],
    },
    {
        "project": "NCP",
        "direction": "upstream_wire_transport",
        "classification": "required_optional_build_dependency",
        "dependency_pin_required_for_qualified_graphs": True,
        "pin": "2f5bd586d4bb20c90362bb6f5698b7f64057ba4e",
        "status": "LOCAL_PIN_VERIFIED_RECIPROCAL_NOT_CLAIMED",
        "conditions": [
            "Local qualification must verify wire-0.8 key and transport compatibility at the exact ncp-core and ncp-zenoh pin.",
            "Keep Galadriel's named sidecars outside normative SensorFrame semantics and do not claim wire-1.0 support.",
            "Reciprocal final-candidate acceptance is not a publication prerequisite and remains unclaimed until a separately signed reconciliation exists.",
        ],
    },
    {
        "project": "Crebain",
        "direction": "external_reference_producer",
        "classification": "optional_runtime_conformance",
        "dependency_pin_required_for_qualified_graphs": False,
        "pin": None,
        "status": "OPTIONAL_CONFORMANCE_ONLY",
        "conditions": [
            "Any live producer must be independently authorized and conform to both Galadriel sidecar contracts.",
            "Do not require Crebain code identity or claim reciprocal final-candidate qualification without a new exact pin and evidence.",
        ],
    },
    {
        "project": "Haldir",
        "direction": "prospective_downstream_authorization",
        "classification": "absent_runtime_edge",
        "dependency_pin_required_for_qualified_graphs": False,
        "pin": None,
        "status": "ABSENT_NOT_CLAIMED",
        "conditions": [
            "Do not advertise a Galadriel adapter, route, or authorization effect for 0.9.0.",
            "Any future integration must remain record-only or independently admitted and restrict-only.",
        ],
    },
    {
        "project": "Prisoma",
        "direction": "prospective_downstream_offline",
        "classification": "absent_runtime_edge",
        "dependency_pin_required_for_qualified_graphs": False,
        "pin": None,
        "status": "ABSENT_NOT_CLAIMED",
        "conditions": [
            "Do not advertise a Galadriel adapter, named-sidecar route, or runtime compatibility for 0.9.0.",
            "Any future offline covariate import must be immutable and must not imply independent-implementation replication.",
        ],
    },
    {
        "project": "Engram/Paper2Brain",
        "direction": "external_application_context",
        "classification": "absent_runtime_edge",
        "dependency_pin_required_for_qualified_graphs": False,
        "pin": None,
        "status": "ABSENT_NOT_CLAIMED",
        "conditions": [
            "Treat engram/ncp only as a configurable example realm; do not infer a Paper2Brain API, process, route, adapter, or runtime edge.",
            "Any future application integration requires a separately versioned and qualified contract.",
        ],
    },
    {
        "project": "ROS / ROS 2",
        "direction": "external_robotics_middleware",
        "classification": "absent_runtime_edge",
        "dependency_pin_required_for_qualified_graphs": False,
        "pin": None,
        "status": "ABSENT_NOT_CLAIMED",
        "conditions": [
            "Do not advertise a ROS dependency, message binding, topic, service, action, node, bag importer, bridge, or compatibility claim for 0.9.0.",
            "Any future middleware adapter requires explicit timing, frame, schema, replay, resource-bound, and qualification evidence.",
        ],
    },
    {
        "project": "external authority",
        "direction": "prospective_downstream_policy_control",
        "classification": "absent_command_edge",
        "dependency_pin_required_for_qualified_graphs": False,
        "pin": None,
        "status": "ABSENT_NOT_CLAIMED",
        "conditions": [
            "Galadriel must have no command credential, lease, watchdog, control, or authority path and must remain advisory-only.",
            "Any future consumer must begin record-only; a later effect requires independent admission and may only restrict existing authority.",
        ],
    },
)


def schema_document() -> dict[str, Any]:
    """Return the exact 0.9 adaptation of the supplied convergence schema."""

    digest_record = {
        "additionalProperties": False,
        "properties": {
            "path": {"minLength": 1, "type": "string"},
            "sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "size_bytes": {"minimum": 0, "type": "integer"},
        },
        "required": ["path", "sha256", "size_bytes"],
        "type": "object",
    }
    wave = {
        "additionalProperties": False,
        "properties": {
            "wave": {"maximum": 9, "minimum": 0, "type": "integer"},
            "task_ids": {
                "items": {"pattern": "^T[0-9]{3}$", "type": "string"},
                "minItems": 1,
                "type": "array",
                "uniqueItems": True,
            },
            "disposition": {"const": "WAVE_ACCEPTED"},
            "evidence": {
                "items": {"minLength": 1, "type": "string"},
                "minItems": 1,
                "type": "array",
                "uniqueItems": True,
            },
        },
        "required": ["wave", "task_ids", "disposition", "evidence"],
        "type": "object",
    }
    cross_requirement = {
        "additionalProperties": False,
        "properties": {
            "project": {
                "enum": [
                    "pid-rs",
                    "NCP",
                    "Crebain",
                    "Haldir",
                    "Prisoma",
                    "Engram/Paper2Brain",
                    "ROS / ROS 2",
                    "external authority",
                ],
                "type": "string",
            },
            "direction": {"minLength": 1, "type": "string"},
            "classification": {"minLength": 1, "type": "string"},
            "dependency_pin_required_for_qualified_graphs": {"type": "boolean"},
            "pin": {
                "anyOf": [
                    {"pattern": "^[0-9a-f]{40}$", "type": "string"},
                    {"type": "null"},
                ]
            },
            "status": {
                "enum": [
                    "LOCAL_PIN_VERIFIED_RECIPROCAL_NOT_CLAIMED",
                    "OPTIONAL_CONFORMANCE_ONLY",
                    "ABSENT_NOT_CLAIMED",
                ],
                "type": "string",
            },
            "conditions": {
                "items": {"minLength": 1, "type": "string"},
                "minItems": 1,
                "type": "array",
                "uniqueItems": True,
            },
        },
        "required": [
            "project",
            "direction",
            "classification",
            "dependency_pin_required_for_qualified_graphs",
            "pin",
            "status",
            "conditions",
        ],
        "type": "object",
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": SCHEMA_ID,
        "$comment": (
            "This preserves the supplied Galadriel convergence fields and task/wave "
            "counts while applying VERSION-ADAPTATION.md to release 0.9.0 and the "
            "approved exact candidate commit. T113 qualifies this candidate-bound "
            "schema, generator, validator, fixed requirement set, and negative tests; "
            "only after T114 review and the T115 decision are signed does finalization "
            "publish the all-task record. The emitted record is not evidence for its "
            "own creation. Schema validation fixes the portable structure; the signed "
            "Python semantic verifier is normative for relational and artifact-byte checks."
        ),
        "title": "Galadriel 0.9.0 local convergence manifest",
        "type": "object",
        "additionalProperties": False,
        "$defs": {
            "artifact": digest_record,
            "crossRequirement": cross_requirement,
            "wave": wave,
        },
        "properties": {
            "project": {"const": PROJECT},
            "release_target": {"const": VERSION},
            "source_commit": {
                "pattern": "^[0-9a-f]{40}$",
                "type": "string",
            },
            "tree_clean": {"const": True},
            "tracked_files": {"minimum": 1, "type": "integer"},
            "reviewed_files": {"minimum": 1, "type": "integer"},
            "completed_tasks": {
                "items": {"pattern": "^T[0-9]{3}$", "type": "string"},
                "maxItems": 116,
                "minItems": 116,
                "prefixItems": [{"const": task_id} for task_id in COMPLETED_TASKS],
                "type": "array",
                "uniqueItems": True,
            },
            "waves": {
                "items": {"$ref": "#/$defs/wave"},
                "maxItems": 10,
                "minItems": 10,
                "prefixItems": [
                    {
                        "const": {
                            "wave": wave_number,
                            "task_ids": [f"T{index:03d}" for index in indices],
                            "disposition": "WAVE_ACCEPTED",
                            "evidence": list(WAVE_EVIDENCE),
                        }
                    }
                    for wave_number, indices in enumerate(WAVE_RANGES)
                ],
                "type": "array",
            },
            "artifacts": {
                "items": {"$ref": "#/$defs/artifact"},
                "maxItems": len(CONVERGENCE_ARTIFACT_PATHS),
                "minItems": len(CONVERGENCE_ARTIFACT_PATHS),
                "type": "array",
                "uniqueItems": True,
            },
            "cross_repo_requirements": {
                "items": {"$ref": "#/$defs/crossRequirement"},
                "maxItems": len(CROSS_REPO_REQUIREMENTS),
                "minItems": len(CROSS_REPO_REQUIREMENTS),
                "prefixItems": [
                    {"const": copy.deepcopy(requirement)}
                    for requirement in CROSS_REPO_REQUIREMENTS
                ],
                "type": "array",
                "uniqueItems": True,
            },
            "ready_for_cross_repo_reconciliation": {"const": True},
        },
        "required": list(TOP_LEVEL_FIELDS),
    }


def validate_schema(schema: Any) -> None:
    if schema != schema_document():
        raise ReviewError(
            "local-convergence schema differs from the exact 0.9 adaptation contract"
        )


def artifact_path_parts(relative: str) -> tuple[str, ...]:
    """Return one unambiguous portable relative artifact path."""

    candidate = Path(relative)
    if (
        not relative
        or "\\" in relative
        or candidate.is_absolute()
        or candidate.as_posix() != relative
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ReviewError(f"local-convergence artifact path is unsafe: {relative}")
    parts = candidate.parts
    if any(part.casefold() in RESERVED_CONVERGENCE_NAMES for part in parts):
        raise ReviewError(
            f"local-convergence artifact path uses a reserved name: {relative}"
        )
    if parts[0].casefold() == "inputs" and relative not in ALLOWED_INPUT_ARTIFACT_PATHS:
        raise ReviewError(
            f"local-convergence artifact path uses the reserved input namespace: {relative}"
        )
    return parts


def read_bounded_artifact(
    root: Path,
    relative: str,
    *,
    max_bytes: int = MAX_ARTIFACT_BYTES,
    label: str = "local-convergence artifact",
) -> bytes:
    """Open one artifact through no-follow directory descriptors and bound its bytes."""

    parts = artifact_path_parts(relative)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    if no_follow is None or non_block is None or directory_flag is None:
        raise ReviewError("atomic no-follow artifact reads are unavailable")
    directory_flags = (
        os.O_RDONLY | no_follow | non_block | directory_flag | close_on_exec
    )
    file_flags = os.O_RDONLY | no_follow | non_block | close_on_exec
    try:
        directory_descriptor = os.open(root, directory_flags)
    except OSError as error:
        raise ReviewError(f"{label} root is missing or unsafe") from error
    directory_descriptors = [directory_descriptor]
    try:
        for part in parts[:-1]:
            try:
                next_descriptor = os.open(
                    part, directory_flags, dir_fd=directory_descriptor
                )
            except OSError as error:
                raise ReviewError(
                    f"{label} is missing or unsafe: {relative}"
                ) from error
            directory_descriptor = next_descriptor
            directory_descriptors.append(next_descriptor)
        try:
            descriptor = os.open(parts[-1], file_flags, dir_fd=directory_descriptor)
        except OSError as error:
            raise ReviewError(f"{label} is missing or unsafe: {relative}") from error
        try:
            handle = os.fdopen(descriptor, "rb", closefd=True)
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        with handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ReviewError(f"{label} is missing or unsafe: {relative}")
            if metadata.st_size > max_bytes:
                raise ReviewError(f"{label} exceeds the size limit: {relative}")
            data = handle.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ReviewError(f"{label} exceeds the size limit: {relative}")
            if len(data) != metadata.st_size:
                raise ReviewError(f"{label} changed while read: {relative}")
            return data
    finally:
        for owned_descriptor in reversed(directory_descriptors):
            try:
                os.close(owned_descriptor)
            except OSError:
                pass


def artifact_records(
    root: Path, relative_paths: tuple[str, ...]
) -> list[dict[str, Any]]:
    """Hash an exact ordered set of retained convergence evidence."""

    if len(relative_paths) != len(set(relative_paths)):
        raise ReviewError("local-convergence artifact path set contains duplicates")
    if list(relative_paths) != sorted(relative_paths):
        raise ReviewError("local-convergence artifact path set is not ordered")
    rows: list[dict[str, Any]] = []
    aggregate_size = 0
    for relative in relative_paths:
        data = read_bounded_artifact(root, relative)
        aggregate_size += len(data)
        if aggregate_size > MAX_AGGREGATE_ARTIFACT_BYTES:
            raise ReviewError(
                "local-convergence artifacts exceed the aggregate size limit"
            )
        rows.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
            }
        )
    return rows


def build_document(
    *,
    commit: str,
    file_review: dict[str, Any],
    task_dispositions: dict[str, Any],
    artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a convergence record from already validated finalizer inputs."""

    if HEX_COMMIT.fullmatch(commit) is None:
        raise ReviewError("local-convergence candidate commit is invalid")
    tracked = file_review.get("tracked_files")
    reviewed = file_review.get("reviewed_files")
    if (
        type(tracked) is not int
        or type(reviewed) is not int
        or tracked < 1
        or reviewed != tracked
    ):
        raise ReviewError("local convergence requires complete tracked-file review")
    dispositions = task_dispositions.get("dispositions")
    if not isinstance(dispositions, list) or len(dispositions) != 116:
        raise ReviewError("local convergence requires 116 reviewed task dispositions")
    completed = [item.get("task_id") for item in dispositions]
    if completed != list(COMPLETED_TASKS):
        raise ReviewError("local convergence task IDs are incomplete or reordered")
    if any(
        item.get("status") not in {"COMPLETE_WITH_EXCLUSIONS", "NOT_CLAIMED"}
        for item in dispositions
    ):
        raise ReviewError("local convergence contains an open task disposition")
    waves = [
        {
            "wave": wave,
            "task_ids": [f"T{index:03d}" for index in indices],
            "disposition": "WAVE_ACCEPTED",
            "evidence": list(WAVE_EVIDENCE),
        }
        for wave, indices in enumerate(WAVE_RANGES)
    ]
    return {
        "project": PROJECT,
        "release_target": VERSION,
        "source_commit": commit,
        "tree_clean": True,
        "tracked_files": tracked,
        "reviewed_files": reviewed,
        "completed_tasks": completed,
        "waves": waves,
        "artifacts": artifacts,
        "cross_repo_requirements": copy.deepcopy(list(CROSS_REPO_REQUIREMENTS)),
        "ready_for_cross_repo_reconciliation": True,
    }


def validate_document(
    document: Any,
    *,
    schema: Any,
    expected_commit: str,
    artifact_root: Path | None = None,
) -> None:
    """Enforce the JSON Schema contract plus exact cross-repository semantics."""

    validate_schema(schema)
    if type(document) is not dict or set(document) != set(TOP_LEVEL_FIELDS):
        raise ReviewError("local-convergence manifest has incorrect fields")
    if document["project"] != PROJECT or document["release_target"] != VERSION:
        raise ReviewError("local-convergence project or release target is incorrect")
    if (
        HEX_COMMIT.fullmatch(expected_commit) is None
        or document["source_commit"] != expected_commit
    ):
        raise ReviewError("local-convergence manifest targets another candidate")
    if document["tree_clean"] is not True:
        raise ReviewError("local-convergence manifest does not record a clean tree")
    tracked = document["tracked_files"]
    reviewed = document["reviewed_files"]
    if (
        type(tracked) is not int
        or type(reviewed) is not int
        or tracked < 1
        or reviewed != tracked
    ):
        raise ReviewError("local-convergence tracked-file review is incomplete")
    if document["completed_tasks"] != list(COMPLETED_TASKS):
        raise ReviewError("local-convergence completed task set is not exact")

    waves = document["waves"]
    if not isinstance(waves, list) or len(waves) != len(WAVE_RANGES):
        raise ReviewError("local-convergence manifest must contain ten waves")
    for wave, indices in enumerate(WAVE_RANGES):
        expected = {
            "wave": wave,
            "task_ids": [f"T{index:03d}" for index in indices],
            "disposition": "WAVE_ACCEPTED",
            "evidence": list(WAVE_EVIDENCE),
        }
        if waves[wave] != expected:
            raise ReviewError(f"local-convergence wave {wave} is not accepted exactly")

    artifacts = document["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise ReviewError("local-convergence manifest lacks retained artifacts")
    paths: list[str] = []
    for row in artifacts:
        if type(row) is not dict or set(row) != {"path", "sha256", "size_bytes"}:
            raise ReviewError("local-convergence artifact record is malformed")
        relative = row["path"]
        digest = row["sha256"]
        size = row["size_bytes"]
        if (
            not isinstance(relative, str)
            or Path(relative).is_absolute()
            or Path(relative).as_posix() != relative
            or any(part in {"", ".", ".."} for part in Path(relative).parts)
            or not isinstance(digest, str)
            or HEX_SHA256.fullmatch(digest) is None
            or type(size) is not int
            or size < 0
        ):
            raise ReviewError("local-convergence artifact identity is invalid")
        paths.append(relative)
    if len(paths) != len(set(paths)) or paths != sorted(paths):
        raise ReviewError("local-convergence artifacts must be unique and ordered")
    if tuple(paths) != CONVERGENCE_ARTIFACT_PATHS:
        raise ReviewError("local-convergence artifact path set is not exact")
    if sum(row["size_bytes"] for row in artifacts) > MAX_AGGREGATE_ARTIFACT_BYTES:
        raise ReviewError("local-convergence artifacts exceed the aggregate size limit")
    if artifact_root is not None:
        expected_rows = artifact_records(artifact_root, tuple(paths))
        if artifacts != expected_rows:
            raise ReviewError("local-convergence artifact bytes do not match")

    if document["cross_repo_requirements"] != list(CROSS_REPO_REQUIREMENTS):
        raise ReviewError("local-convergence cross-repository requirements drifted")
    if document["ready_for_cross_repo_reconciliation"] is not True:
        raise ReviewError("local-convergence manifest is not ready for reconciliation")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("schema", "write-schema", "verify"))
    parser.add_argument("--repo", default=".")
    parser.add_argument("--schema")
    parser.add_argument("--manifest")
    parser.add_argument("--signature")
    parser.add_argument("--allowed-signers")
    parser.add_argument("--expected-commit")
    parser.add_argument("--artifact-root")
    arguments = parser.parse_args()

    repo = Path(arguments.repo).resolve()
    schema_path = (
        Path(os.path.abspath(os.path.expanduser(arguments.schema)))
        if arguments.schema
        else repo / SCHEMA_PATH
    )
    try:
        if arguments.action == "write-schema":
            if arguments.schema:
                raise ReviewError(
                    "write-schema always targets the tracked release schema"
                )
            if schema_path.is_symlink():
                raise ReviewError("refusing to replace a symlinked release schema")
            schema_path.write_bytes(canonical_json(schema_document()))
            print(f"LOCAL_CONVERGENCE_SCHEMA_WRITTEN {schema_path}")
            return 0
        schema = loads_json(
            read_bounded_regular_file(
                schema_path,
                MAX_SCHEMA_BYTES,
                label="local-convergence schema",
                limit_label="schema-byte",
            )
        )
        validate_schema(schema)
        if arguments.action == "schema":
            print(f"LOCAL_CONVERGENCE_SCHEMA_OK {schema_path}")
            return 0
        if not all(
            (
                arguments.manifest,
                arguments.signature,
                arguments.allowed_signers,
                arguments.expected_commit,
                arguments.artifact_root,
            )
        ):
            raise ReviewError(
                "verify requires --manifest, --signature, --allowed-signers, "
                "--expected-commit, and --artifact-root"
            )
        manifest = Path(os.path.abspath(os.path.expanduser(arguments.manifest)))
        signature = Path(os.path.abspath(os.path.expanduser(arguments.signature)))
        allowed_signers = Path(
            os.path.abspath(os.path.expanduser(arguments.allowed_signers))
        )
        raw = read_bounded_regular_file(
            manifest,
            MAX_MANIFEST_BYTES,
            label="local-convergence manifest",
            limit_label="manifest-byte",
        )
        signature_bytes = read_bounded_regular_file(
            signature,
            MAX_SIGNATURE_BYTES,
            label="local-convergence signature",
            limit_label="signature-byte",
        )
        allowed_signer_bytes = read_bounded_regular_file(
            allowed_signers,
            MAX_ALLOWED_SIGNERS_BYTES,
            label="local-convergence allowed-signers file",
            limit_label="allowed-signers-byte",
        )
        from release_assurance import verify_signature

        with tempfile.TemporaryDirectory(
            prefix="galadriel-convergence-verify-"
        ) as directory:
            snapshot_root = Path(directory)
            manifest_snapshot = snapshot_root / "LOCAL-CONVERGENCE.json"
            signature_snapshot = snapshot_root / "LOCAL-CONVERGENCE.json.sig"
            signers_snapshot = snapshot_root / "ALLOWED_SIGNERS"
            manifest_snapshot.write_bytes(raw)
            signature_snapshot.write_bytes(signature_bytes)
            signers_snapshot.write_bytes(allowed_signer_bytes)
            os.chmod(signers_snapshot, 0o600)
            verify_signature(
                manifest_snapshot,
                signature_snapshot,
                signers_snapshot,
                SIGNATURE_NAMESPACE,
            )
        document = loads_json(raw)
        if canonical_json(document) != raw:
            raise ReviewError("local-convergence manifest is not canonical JSON")
        validate_document(
            document,
            schema=schema,
            expected_commit=arguments.expected_commit,
            artifact_root=Path(arguments.artifact_root).resolve(),
        )
    except (OSError, RecursionError, ReviewError, UnicodeError, ValueError) as error:
        print(f"local-convergence verification failed: {error}", file=sys.stderr)
        return 2
    print(f"LOCAL_CONVERGENCE_OK {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
