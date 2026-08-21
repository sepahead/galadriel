#!/usr/bin/env python3
"""Validate the CREBAIN categorical-MGW v3 JSON without third-party packages.

This module intentionally implements only the JSON Schema Draft 2020-12
keywords used by the checked-in study schema.  The schema is linted before an
instance is evaluated: an unknown keyword, malformed local reference, duplicate
JSON member, non-finite number, excessive numeric magnitude, or oversized input
is an error.  This is a wire-contract check, not a replacement for the Rust
semantic, algebraic, custody, or independent-Decimal checks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA = (
    ROOT
    / "crates/galadriel-justify/schemas/crebain-drone-mgw-study-v3.schema.json"
)
DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
MAX_SCHEMA_BYTES = 1_048_576
MAX_INSTANCE_BYTES = 4_194_304
MAX_JSON_DEPTH = 128
MAX_JSON_NODES = 500_000
MAX_INTEGER_MAGNITUDE = 9_007_199_254_740_991
EXPECTED_ANALYSIS_MANIFEST_SHA256 = (
    "4b0381beee855e7d624066ab04cfdc07920c6182951315b65ba48d99c1e86f90"
)
EXPECTED_PID_CORE_REFERENCE_ARTIFACTS = (
    {
        "kind": "method_catalog",
        "repository_path": "method-catalog.json",
        "schema": "pid-rs/method-catalog",
        "schema_revision": 1,
        "digest_scope": "sha256_of_canonical_file_bytes",
        "canonical_json_sha256": (
            "6e8fb1143019b3f2bffe982636586705d5e99cca5decfe17a810d694b50ed8aa"
        ),
        "role": "forensic_reference_only",
    },
    {
        "kind": "proposed_release_scope",
        "repository_path": "release-scope-1.0.json",
        "schema": "pid-rs/release-scope",
        "schema_revision": 1,
        "digest_scope": "sha256_of_canonical_file_bytes",
        "canonical_json_sha256": (
            "3322d66f9426f3f948704096506dc65a1b73ae39e94a08ba455d7941f92828b8"
        ),
        "role": "forensic_reference_only",
    },
)

# Annotation keywords are explicit members of this audited subset; they are
# type-checked during schema linting and intentionally have no assertion effect.
SUPPORTED_KEYWORDS = frozenset(
    {
        "$schema",
        "$id",
        "$defs",
        "$ref",
        "title",
        "description",
        "type",
        "const",
        "enum",
        "properties",
        "required",
        "additionalProperties",
        "allOf",
        "if",
        "then",
        "items",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minLength",
        "maxLength",
        "pattern",
        "minimum",
        "maximum",
    }
)
SUPPORTED_TYPES = frozenset(
    {"null", "boolean", "object", "array", "number", "integer", "string"}
)


class ContractError(RuntimeError):
    """A schema, JSON encoding, resource, or instance contract failed."""


@dataclass(frozen=True)
class SchemaIdentity:
    sha256: str
    size_bytes: int


def _display_path(path: tuple[object, ...]) -> str:
    if not path:
        return "$"
    rendered = "$"
    for component in path:
        if isinstance(component, int):
            rendered += f"[{component}]"
        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", component):
            rendered += f".{component}"
        else:
            rendered += f"[{component!r}]"
    return rendered


def _reject_nonfinite_constant(token: str) -> None:
    raise ContractError(f"non-standard JSON numeric token rejected: {token}")


def _parse_integer(token: str) -> int:
    try:
        value = int(token, 10)
    except ValueError as error:
        raise ContractError(f"invalid JSON integer: {token[:80]}") from error
    if abs(value) > MAX_INTEGER_MAGNITUDE:
        raise ContractError(
            "JSON integer exceeds the exact interoperable contract bound "
            f"{MAX_INTEGER_MAGNITUDE}"
        )
    return value


def _parse_float(token: str) -> float:
    try:
        value = float(token)
    except ValueError as error:
        raise ContractError(f"invalid JSON number: {token[:80]}") from error
    if not math.isfinite(value):
        raise ContractError(f"non-finite or overflowing JSON number rejected: {token[:80]}")
    return value


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON object member rejected: {key!r}")
        result[key] = value
    return result


def _walk_json_safety(value: Any) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ContractError(f"JSON document exceeds {MAX_JSON_NODES} value nodes")
        if depth > MAX_JSON_DEPTH:
            raise ContractError(f"JSON document exceeds nesting depth {MAX_JSON_DEPTH}")
        if isinstance(current, bool) or current is None or isinstance(current, str):
            continue
        if isinstance(current, int):
            if abs(current) > MAX_INTEGER_MAGNITUDE:
                raise ContractError("JSON integer exceeds the global magnitude bound")
            continue
        if isinstance(current, float):
            if not math.isfinite(current):
                raise ContractError("non-finite JSON number rejected")
            continue
        if isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
            continue
        if isinstance(current, dict):
            for key, item in current.items():
                if not isinstance(key, str):
                    raise ContractError("JSON object member name is not a string")
                stack.append((item, depth + 1))
            continue
        raise ContractError(f"non-JSON runtime value rejected: {type(current).__name__}")


def load_json_document(path: Path, *, maximum_bytes: int) -> tuple[Any, bytes]:
    """Read strict UTF-8 JSON under a byte bound and return value plus exact bytes."""

    try:
        size = path.stat().st_size
    except OSError as error:
        raise ContractError(f"cannot stat {path}: {error}") from error
    if size > maximum_bytes:
        raise ContractError(
            f"{path} is {size} bytes; maximum accepted size is {maximum_bytes}"
        )
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ContractError(f"cannot read {path}: {error}") from error
    if len(raw) != size:
        raise ContractError(f"{path} changed while it was read")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ContractError(f"UTF-8 BOM rejected in {path}")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ContractError(f"{path} is not strict UTF-8: {error}") from error
    try:
        value = json.loads(
            text,
            parse_constant=_reject_nonfinite_constant,
            parse_int=_parse_integer,
            parse_float=_parse_float,
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except ContractError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ContractError(f"invalid bounded JSON in {path}: {error}") from error
    _walk_json_safety(value)
    return value, raw


def schema_identity(raw: bytes) -> SchemaIdentity:
    return SchemaIdentity(hashlib.sha256(raw).hexdigest(), len(raw))


def _is_json_number(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float))


def _json_kind(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return type(value).__name__


def _json_equal(left: Any, right: Any) -> bool:
    if _is_json_number(left) and _is_json_number(right):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _json_equal(left[key], right[key]) for key in left
        )
    return left == right


def _require_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(f"schema keyword {label} must be an integer")
    return value


def _require_number(value: Any, label: str) -> int | float:
    if not _is_json_number(value) or not math.isfinite(float(value)):
        raise ContractError(f"schema keyword {label} must be a finite number")
    return value


def _lint_schema_node(node: Any, path: tuple[object, ...] = ()) -> None:
    if not isinstance(node, dict):
        raise ContractError(f"schema at {_display_path(path)} must be an object")
    unsupported = sorted(set(node) - SUPPORTED_KEYWORDS)
    if unsupported:
        raise ContractError(
            f"unsupported schema keyword(s) at {_display_path(path)}: "
            + ", ".join(unsupported)
        )

    for annotation in ("$schema", "$id", "title", "description"):
        if annotation in node and not isinstance(node[annotation], str):
            raise ContractError(
                f"schema keyword {annotation} at {_display_path(path)} must be a string"
            )

    if "$ref" in node:
        reference = node["$ref"]
        if not isinstance(reference, str) or not reference.startswith("#/"):
            raise ContractError(
                f"only non-empty local JSON Pointer $ref values are supported at {_display_path(path)}"
            )

    if "type" in node:
        declared = node["type"]
        if not isinstance(declared, str) or declared not in SUPPORTED_TYPES:
            raise ContractError(
                f"unsupported or malformed type at {_display_path(path)}: {declared!r}"
            )

    if "enum" in node:
        values = node["enum"]
        if not isinstance(values, list) or not values:
            raise ContractError(f"enum at {_display_path(path)} must be a non-empty array")
        _walk_json_safety(values)
        for index, value in enumerate(values):
            if any(_json_equal(value, prior) for prior in values[:index]):
                raise ContractError(f"enum at {_display_path(path)} contains duplicates")
    if "const" in node:
        _walk_json_safety(node["const"])

    if "$defs" in node:
        definitions = node["$defs"]
        if not isinstance(definitions, dict) or not definitions:
            raise ContractError(f"$defs at {_display_path(path)} must be a non-empty object")
        for name, subschema in definitions.items():
            if not isinstance(name, str) or not name:
                raise ContractError(f"$defs at {_display_path(path)} has an invalid name")
            _lint_schema_node(subschema, path + ("$defs", name))

    if "properties" in node:
        properties = node["properties"]
        if not isinstance(properties, dict):
            raise ContractError(f"properties at {_display_path(path)} must be an object")
        for name, subschema in properties.items():
            if not isinstance(name, str):
                raise ContractError(f"properties at {_display_path(path)} has a non-string name")
            _lint_schema_node(subschema, path + ("properties", name))

    if "required" in node:
        required = node["required"]
        if (
            not isinstance(required, list)
            or not all(isinstance(name, str) for name in required)
            or len(set(required)) != len(required)
        ):
            raise ContractError(
                f"required at {_display_path(path)} must be an array of unique strings"
            )
        properties = node.get("properties")
        if properties is None or any(name not in properties for name in required):
            raise ContractError(
                f"every required member at {_display_path(path)} must have a property schema"
            )

    if "additionalProperties" in node and not isinstance(
        node["additionalProperties"], bool
    ):
        raise ContractError(
            f"additionalProperties at {_display_path(path)} must be boolean in this subset"
        )

    if node.get("type") == "object":
        if node.get("additionalProperties") is not False:
            raise ContractError(
                f"closed-world object schema at {_display_path(path)} must set "
                "additionalProperties to false"
            )
        properties = node.get("properties")
        required = node.get("required")
        if not isinstance(properties, dict) or not isinstance(required, list):
            raise ContractError(
                f"closed-world object schema at {_display_path(path)} must declare "
                "properties and required"
            )
        if set(properties) != set(required):
            raise ContractError(
                f"closed-world object schema at {_display_path(path)} must make every "
                "declared property required"
            )

    if "items" in node:
        _lint_schema_node(node["items"], path + ("items",))

    if "allOf" in node:
        branches = node["allOf"]
        if not isinstance(branches, list) or not branches:
            raise ContractError(
                f"allOf at {_display_path(path)} must be a non-empty array"
            )
        for index, branch in enumerate(branches):
            _lint_schema_node(branch, path + ("allOf", index))

    if ("if" in node) != ("then" in node):
        raise ContractError(
            f"if and then at {_display_path(path)} must appear together in this subset"
        )
    if "if" in node:
        _lint_schema_node(node["if"], path + ("if",))
        _lint_schema_node(node["then"], path + ("then",))

    for keyword in ("minItems", "maxItems", "minLength", "maxLength"):
        if keyword in node and _require_integer(node[keyword], keyword) < 0:
            raise ContractError(f"{keyword} at {_display_path(path)} cannot be negative")
    if "minItems" in node and "maxItems" in node:
        if node["minItems"] > node["maxItems"]:
            raise ContractError(f"minItems exceeds maxItems at {_display_path(path)}")
    if "minLength" in node and "maxLength" in node:
        if node["minLength"] > node["maxLength"]:
            raise ContractError(f"minLength exceeds maxLength at {_display_path(path)}")
    if "uniqueItems" in node and not isinstance(node["uniqueItems"], bool):
        raise ContractError(f"uniqueItems at {_display_path(path)} must be boolean")

    if "pattern" in node:
        pattern = node["pattern"]
        if not isinstance(pattern, str):
            raise ContractError(f"pattern at {_display_path(path)} must be a string")
        try:
            re.compile(pattern)
        except re.error as error:
            raise ContractError(f"invalid pattern at {_display_path(path)}: {error}") from error

    for keyword in ("minimum", "maximum"):
        if keyword in node:
            _require_number(node[keyword], keyword)
    if "minimum" in node and "maximum" in node and node["minimum"] > node["maximum"]:
        raise ContractError(f"minimum exceeds maximum at {_display_path(path)}")


def _decode_pointer_token(token: str) -> str:
    result = ""
    index = 0
    while index < len(token):
        if token[index] != "~":
            result += token[index]
            index += 1
            continue
        if index + 1 >= len(token) or token[index + 1] not in "01":
            raise ContractError(f"malformed JSON Pointer escape in $ref token {token!r}")
        result += "~" if token[index + 1] == "0" else "/"
        index += 2
    return result


def _resolve_local_ref(root: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise ContractError(f"external or empty $ref rejected: {reference!r}")
    current: Any = root
    for raw_token in reference[2:].split("/"):
        token = _decode_pointer_token(raw_token)
        if not isinstance(current, dict) or token not in current:
            raise ContractError(f"unresolved local $ref: {reference}")
        current = current[token]
    if not isinstance(current, dict):
        raise ContractError(f"local $ref does not resolve to a schema object: {reference}")
    return current


def _iter_schema_nodes(node: dict[str, Any]) -> Iterable[dict[str, Any]]:
    yield node
    for subschema in node.get("$defs", {}).values():
        yield from _iter_schema_nodes(subschema)
    for subschema in node.get("properties", {}).values():
        yield from _iter_schema_nodes(subschema)
    if "items" in node:
        yield from _iter_schema_nodes(node["items"])
    for branch in node.get("allOf", []):
        yield from _iter_schema_nodes(branch)
    if "if" in node:
        yield from _iter_schema_nodes(node["if"])
        yield from _iter_schema_nodes(node["then"])


def lint_schema(schema: Any) -> dict[str, Any]:
    if not isinstance(schema, dict):
        raise ContractError("root schema must be an object")
    _lint_schema_node(schema)
    if schema.get("$schema") != DRAFT_2020_12:
        raise ContractError(f"root schema must declare exact Draft 2020-12 URI {DRAFT_2020_12}")
    if schema.get("type") != "object":
        raise ContractError("root schema must declare type object")
    if schema.get("additionalProperties") is not False:
        raise ContractError("root schema must close additional properties")
    for node in _iter_schema_nodes(schema):
        if "$ref" in node:
            _resolve_local_ref(schema, node["$ref"])
    return schema


def load_schema(path: Path = DEFAULT_SCHEMA) -> tuple[dict[str, Any], bytes]:
    value, raw = load_json_document(path, maximum_bytes=MAX_SCHEMA_BYTES)
    return lint_schema(value), raw


def _matches_type(instance: Any, declared: str) -> bool:
    if declared == "null":
        return instance is None
    if declared == "boolean":
        return isinstance(instance, bool)
    if declared == "object":
        return isinstance(instance, dict)
    if declared == "array":
        return isinstance(instance, list)
    if declared == "string":
        return isinstance(instance, str)
    if declared == "integer":
        return not isinstance(instance, bool) and isinstance(instance, int)
    if declared == "number":
        return _is_json_number(instance) and math.isfinite(float(instance))
    raise ContractError(f"internal error: unhandled declared type {declared!r}")


def _validate_instance(
    instance: Any,
    node: dict[str, Any],
    root: dict[str, Any],
    path: tuple[object, ...],
    active_refs: set[tuple[int, str]],
    depth: int,
) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ContractError(f"schema evaluation exceeds depth {MAX_JSON_DEPTH}")

    if "$ref" in node:
        reference = node["$ref"]
        key = (id(instance), reference)
        if key in active_refs:
            raise ContractError(f"recursive $ref evaluation rejected: {reference}")
        active_refs.add(key)
        try:
            _validate_instance(
                instance,
                _resolve_local_ref(root, reference),
                root,
                path,
                active_refs,
                depth + 1,
            )
        finally:
            active_refs.remove(key)

    for branch in node.get("allOf", []):
        _validate_instance(instance, branch, root, path, active_refs, depth + 1)

    if "if" in node:
        try:
            _validate_instance(instance, node["if"], root, path, active_refs, depth + 1)
        except ContractError:
            pass
        else:
            _validate_instance(instance, node["then"], root, path, active_refs, depth + 1)

    declared = node.get("type")
    if declared is not None and not _matches_type(instance, declared):
        raise ContractError(
            f"{_display_path(path)} must be {declared}, got {_json_kind(instance)}"
        )

    if "const" in node and not _json_equal(instance, node["const"]):
        raise ContractError(f"{_display_path(path)} does not match its required constant")
    if "enum" in node and not any(_json_equal(instance, item) for item in node["enum"]):
        raise ContractError(f"{_display_path(path)} is outside its declared enum")

    if isinstance(instance, dict):
        required = node.get("required", [])
        missing = [name for name in required if name not in instance]
        if missing:
            raise ContractError(
                f"{_display_path(path)} is missing required member(s): {', '.join(missing)}"
            )
        properties = node.get("properties", {})
        if node.get("additionalProperties") is False:
            extras = sorted(set(instance) - set(properties))
            if extras:
                raise ContractError(
                    f"{_display_path(path)} has undeclared member(s): {', '.join(extras)}"
                )
        for name, subschema in properties.items():
            if name in instance:
                _validate_instance(
                    instance[name],
                    subschema,
                    root,
                    path + (name,),
                    active_refs,
                    depth + 1,
                )

    if isinstance(instance, list):
        if "minItems" in node and len(instance) < node["minItems"]:
            raise ContractError(
                f"{_display_path(path)} has {len(instance)} items; minimum is {node['minItems']}"
            )
        if "maxItems" in node and len(instance) > node["maxItems"]:
            raise ContractError(
                f"{_display_path(path)} has {len(instance)} items; maximum is {node['maxItems']}"
            )
        if node.get("uniqueItems") is True:
            for index, value in enumerate(instance):
                if any(_json_equal(value, prior) for prior in instance[:index]):
                    raise ContractError(
                        f"{_display_path(path)} contains duplicate items at or before index {index}"
                    )
        if "items" in node:
            for index, value in enumerate(instance):
                _validate_instance(
                    value,
                    node["items"],
                    root,
                    path + (index,),
                    active_refs,
                    depth + 1,
                )

    if isinstance(instance, str):
        if "minLength" in node and len(instance) < node["minLength"]:
            raise ContractError(f"{_display_path(path)} is shorter than minLength")
        if "maxLength" in node and len(instance) > node["maxLength"]:
            raise ContractError(f"{_display_path(path)} is longer than maxLength")
        if "pattern" in node and re.search(node["pattern"], instance) is None:
            raise ContractError(f"{_display_path(path)} does not match its required pattern")

    if _is_json_number(instance):
        if not math.isfinite(float(instance)):
            raise ContractError(f"{_display_path(path)} is non-finite")
        if "minimum" in node and instance < node["minimum"]:
            raise ContractError(f"{_display_path(path)} is below its minimum")
        if "maximum" in node and instance > node["maximum"]:
            raise ContractError(f"{_display_path(path)} is above its maximum")


def validate_document(instance: Any, schema: dict[str, Any]) -> None:
    """Validate one already-parsed instance against a linted schema."""

    _walk_json_safety(instance)
    lint_schema(schema)
    _validate_instance(instance, schema, schema, (), set(), 0)


def validate_machine_schema_binding(instance: Any, schema_raw: bytes) -> None:
    """Bind the embedded machine-schema receipt to the exact checked bytes.

    Ordinary JSON Schema assertions cannot make an instance field equal to the
    digest of the schema document that is performing validation.  Keep that
    cross-document relation explicit and fail closed instead of pretending a
    ``pattern`` assertion proves byte identity.
    """

    if not isinstance(instance, dict):
        raise ContractError("machine-schema binding requires an object instance")
    receipt = instance.get("machine_schema")
    if not isinstance(receipt, dict):
        raise ContractError("$.machine_schema is required for byte binding")
    identity = schema_identity(schema_raw)
    if receipt.get("sha256") != identity.sha256:
        raise ContractError(
            "$.machine_schema.sha256 does not match the exact validation schema bytes"
        )
    if receipt.get("bytes") != identity.size_bytes:
        raise ContractError(
            "$.machine_schema.bytes does not match the exact validation schema size"
        )


def validate_semantic_identity_bindings(instance: Any) -> None:
    """Bind invariant cross-field identities that the supported schema subset cannot join."""

    if not isinstance(instance, dict):
        raise ContractError("semantic identity binding requires an object instance")
    fixture_identity = instance.get("fixture_identity")
    software_identity = instance.get("pid_core_software_identity")
    if not isinstance(fixture_identity, dict) or not isinstance(software_identity, dict):
        raise ContractError("fixture and pid-core software identities are required")
    if (
        fixture_identity.get("analysis_manifest_sha256")
        != EXPECTED_ANALYSIS_MANIFEST_SHA256
    ):
        raise ContractError(
            "$.fixture_identity.analysis_manifest_sha256 does not match the frozen manifest"
        )
    observed_references = software_identity.get("reference_artifacts")
    if observed_references != list(EXPECTED_PID_CORE_REFERENCE_ARTIFACTS):
        raise ContractError(
            "$.pid_core_software_identity.reference_artifacts does not match the exact "
            "ordered bc3 method-catalog/release-scope identity tuples"
        )


def check_paths(instance_path: Path, schema_path: Path = DEFAULT_SCHEMA) -> str:
    schema, schema_raw = load_schema(schema_path)
    instance, instance_raw = load_json_document(
        instance_path, maximum_bytes=MAX_INSTANCE_BYTES
    )
    validate_document(instance, schema)
    validate_machine_schema_binding(instance, schema_raw)
    validate_semantic_identity_bindings(instance)
    identity = schema_identity(schema_raw)
    return (
        "PASS CREBAIN categorical-MGW v3 JSON Schema validation: "
        f"schema_sha256={identity.sha256} schema_bytes={identity.size_bytes} "
        f"instance_sha256={hashlib.sha256(instance_raw).hexdigest()} "
        f"instance_bytes={len(instance_raw)}"
    )


def parse_args(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate one galadriel-crebain-mgw --format json document."
    )
    parser.add_argument("instance", type=Path, help="exact JSON output to validate")
    parser.add_argument(
        "--schema",
        type=Path,
        default=DEFAULT_SCHEMA,
        help=f"schema path (default: {DEFAULT_SCHEMA.relative_to(ROOT)})",
    )
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    options = parse_args(sys.argv[1:] if arguments is None else arguments)
    try:
        print(check_paths(options.instance, options.schema))
    except ContractError as error:
        print(f"FAIL CREBAIN categorical-MGW v3 JSON Schema validation: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
