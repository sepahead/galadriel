#!/usr/bin/env python3
"""Validate retained qualification artifacts with fixed resource bounds."""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import math
import tarfile
import tomllib
import urllib.parse
import uuid
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from common import ReviewError


VERSION = "0.9.0"
WORKSPACE_PACKAGE_NAMES = (
    "galadriel-cli",
    "galadriel-core",
    "galadriel-eval",
    "galadriel-justify",
    "galadriel-ncp",
    "galadriel-pid",
    "galadriel-sim",
)
DEFAULT_WORKSPACE_PACKAGE_NAMES = (
    "galadriel-cli",
    "galadriel-core",
    "galadriel-sim",
)
REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"

MAX_METADATA_BYTES = 64 * 1024 * 1024
MAX_LOCKFILE_BYTES = 16 * 1024 * 1024
MAX_SBOM_BYTES = 64 * 1024 * 1024
MAX_LICENSE_REPORT_BYTES = 16 * 1024 * 1024
MAX_LICENSE_LINE_BYTES = 4 * 1024 * 1024
MAX_CRATE_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_CRATE_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_CRATE_MEMBER_BYTES = 64 * 1024 * 1024
MAX_CRATE_MEMBERS = 4096
MAX_PACKAGE_COUNT = 10_000
MAX_GRAPH_EDGES = 250_000
MAX_FEATURE_COUNT = 100_000
MAX_TARGET_COUNT = 100_000
MAX_JSON_DEPTH = 256
MAX_JSON_NODES = 2_000_000
MAX_JSON_ERROR_CHARS = 512
MAX_JSON_CONTEXT_CHARS = 128
MAX_STRING_BYTES = 16 * 1024
MAX_ARCHIVE_PATH_BYTES = 1024
MAX_ARCHIVE_PATH_DEPTH = 64
MAX_LICENSE_LINES = 20_000
CARGO_DENY_HOST_FILTERED_SCOPE = "CARGO_DENY_HOST_FILTERED_GRAPH"
EXPECTED_HOST_FILTERED_LICENSE_PACKAGES = 382
EXPECTED_HOST_FILTERED_LICENSE_ASSIGNMENTS = 707
EXPECTED_HOST_FILTERED_LICENSE_PACKAGE_IDS_SHA256 = (
    "4d514cd4ce1e8b636396debb309dfe6d3847997b83263def0cdf596a96193665"
)
EXPECTED_HOST_FILTERED_LICENSE_SEMANTIC_SHA256 = (
    "4c6619d9403977a60e7cca82ce1446386934b8adacc71444504d753c9fce0fe7"
)
EXPECTED_LICENSE_ACCEPTED_HELP_COUNT = 375
EXPECTED_LICENSE_SKIPPED_NOTE_COUNT = 7

METADATA_ROOT_FIELDS = {
    "metadata",
    "packages",
    "resolve",
    "target_directory",
    "version",
    "workspace_default_members",
    "workspace_members",
    "workspace_root",
}
METADATA_PACKAGE_FIELDS = {
    "authors",
    "categories",
    "default_run",
    "dependencies",
    "description",
    "documentation",
    "edition",
    "features",
    "homepage",
    "id",
    "keywords",
    "license",
    "license_file",
    "links",
    "manifest_path",
    "metadata",
    "name",
    "publish",
    "readme",
    "repository",
    "rust_version",
    "source",
    "targets",
    "version",
}
METADATA_DEPENDENCY_FIELDS = {
    "features",
    "kind",
    "name",
    "optional",
    "registry",
    "rename",
    "req",
    "source",
    "target",
    "uses_default_features",
}
METADATA_DEPENDENCY_OPTIONAL_FIELDS = {"path"}
METADATA_TARGET_FIELDS = {
    "crate_types",
    "doc",
    "doctest",
    "edition",
    "kind",
    "name",
    "src_path",
    "test",
}
METADATA_TARGET_OPTIONAL_FIELDS = {"required-features"}
METADATA_RESOLVE_FIELDS = {"nodes", "root"}
METADATA_NODE_FIELDS = {"dependencies", "deps", "features", "id"}
METADATA_NODE_DEP_FIELDS = {"dep_kinds", "name", "pkg"}
METADATA_DEP_KIND_FIELDS = {"kind", "target"}

LockIdentity = tuple[str, str, str | None]
DeclarationKey = tuple[str, str | None, str | None, str | None]


@dataclass(frozen=True)
class CargoTargetComponent:
    """Identify one library or binary target in a workspace package."""

    name: str
    component_type: str
    source_path: str


@dataclass(frozen=True)
class CargoPackage:
    """Retain one exact Cargo package identity and its resolved attributes."""

    package_id: str
    name: str
    version: str
    source: str | None
    checksum: str | None
    manifest_path: str
    workspace: bool
    authors: tuple[str, ...]
    description: str | None
    documentation: str | None
    homepage: str | None
    repository: str | None
    links: str | None
    license: str | None
    license_file: str | None
    declared_features: tuple[str, ...]
    resolved_features: tuple[str, ...]
    dependencies: tuple[str, ...]
    normal_dependencies: tuple[str, ...]
    non_dev_dependencies: tuple[str, ...]
    target_components: tuple[CargoTargetComponent, ...]


@dataclass(frozen=True)
class ValidatedCargoGraph:
    """Hold the exact package and dependency graph for later cross-checks."""

    workspace_root: str
    target_directory: str
    packages: tuple[CargoPackage, ...]
    workspace_package_ids: tuple[str, ...]
    default_workspace_package_ids: tuple[str, ...]

    def package_by_id(self) -> dict[str, CargoPackage]:
        """Return the package map from the validated immutable rows."""

        return {package.package_id: package for package in self.packages}

    def package_by_name(self, name: str) -> CargoPackage:
        """Return one unique package with the specified name."""

        matches = [package for package in self.packages if package.name == name]
        if len(matches) != 1:
            raise ReviewError(f"Cargo graph does not contain one package named {name}")
        return matches[0]


def validate_cargo_graph_paths(
    graph: ValidatedCargoGraph,
    *,
    workspace_root: str | Path,
    target_directory: str | Path,
) -> None:
    """Bind reported Cargo paths to the exact qualification directories."""

    expected_workspace = str(
        _absolute_posix_path(str(workspace_root), "expected Cargo workspace root")
    )
    expected_target = str(
        _absolute_posix_path(str(target_directory), "expected Cargo target directory")
    )
    if graph.workspace_root != expected_workspace:
        raise ReviewError("Cargo metadata names another qualification workspace")
    if graph.target_directory != expected_target:
        raise ReviewError("Cargo metadata names another qualification target directory")


@dataclass(frozen=True)
class CrateArchiveSummary:
    """Describe one validated unpublished Cargo package archive."""

    crate: str
    version: str
    candidate_commit: str
    member_count: int
    uncompressed_member_bytes: int


@dataclass(frozen=True)
class SbomSummary:
    """Describe one validated CycloneDX package graph."""

    workspace_package: str
    component_count: int
    dependency_record_count: int


@dataclass(frozen=True)
class CycloneDxIdentity:
    """Hold deterministic candidate-bound CycloneDX metadata."""

    serial_number: str
    timestamp: str


@dataclass(frozen=True)
class LicensePolicySummary:
    """Describe the exact passing Cargo deny license-policy summary."""

    accepted_help_count: int
    skipped_note_count: int


@dataclass(frozen=True)
class LicenseInventorySummary:
    """Describe one explicit host-filtered Cargo deny package inventory."""

    scope: str
    package_count: int
    license_assignment_count: int


@dataclass(frozen=True)
class _LockDependencyIndex:
    """Provide bounded direct lookup for Cargo.lock dependency descriptors."""

    by_name: dict[str, tuple[LockIdentity, ...]]
    by_name_version: dict[tuple[str, str], tuple[LockIdentity, ...]]


@dataclass(frozen=True)
class _MetadataDeclarationIndex:
    """Provide direct lookup for resolved Cargo metadata dependency rows."""

    renamed: dict[DeclarationKey, tuple[int, ...]]
    unrenamed: dict[DeclarationKey, tuple[int, ...]]


def _require_exact_fields(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ReviewError(f"{context} has another field set")
    return value


def _require_string(
    value: Any,
    context: str,
    *,
    allow_empty: bool = False,
    reject_controls: bool = True,
) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        raise ReviewError(f"{context} is not a valid string")
    if len(value.encode("utf-8")) > MAX_STRING_BYTES:
        raise ReviewError(f"{context} exceeds the string-size bound")
    if (reject_controls and any(ord(character) < 0x20 for character in value)) or (
        not reject_controls
        and any(
            ord(character) < 0x20 and character not in "\t\n\r" for character in value
        )
    ):
        raise ReviewError(f"{context} contains a control character")
    return value


def _require_optional_string(
    value: Any, context: str, *, reject_controls: bool = True
) -> str | None:
    if value is None:
        return None
    return _require_string(value, context, reject_controls=reject_controls)


def _require_string_list(
    value: Any,
    context: str,
    *,
    maximum: int = MAX_FEATURE_COUNT,
    unique: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ReviewError(f"{context} is not a bounded list")
    result = tuple(_require_string(item, f"{context} entry") for item in value)
    if unique and len(result) != len(set(result)):
        raise ReviewError(f"{context} contains a duplicate")
    return result


def _json_integer(token: str) -> int:
    digits = token.lstrip("-")
    if not digits or len(digits) > 128:
        raise ValueError("JSON integer exceeds the decimal-digit bound")
    return int(token)


def _json_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise ValueError("JSON number is not finite")
    if value == 0.0 and any(character in "123456789" for character in token):
        raise ValueError("JSON number underflows binary64")
    return value


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _bounded_json_context(context: str) -> str:
    if len(context) <= MAX_JSON_CONTEXT_CHARS:
        return context
    return context[: MAX_JSON_CONTEXT_CHARS - 3] + "..."


def _bounded_json_error(error: BaseException) -> str:
    try:
        detail = str(error)
    except Exception:
        detail = type(error).__name__
    if len(detail) <= MAX_JSON_ERROR_CHARS:
        return detail
    return detail[: MAX_JSON_ERROR_CHARS - 3] + "..."


def _scan_json_string(text: str, start: int, context: str) -> int:
    index = start + 1
    while index < len(text):
        character = text[index]
        if character == '"':
            return index + 1
        if character == "\\":
            index += 2
        else:
            index += 1
    raise ReviewError(f"{context} has an unterminated JSON string")


def _preflight_json_bounds(text: str, context: str) -> None:
    """Bound JSON structure before the recursive standard parser sees it."""

    context = _bounded_json_context(context)
    stack: list[tuple[str, str]] = []
    root_state = "value"
    node_count = 0
    index = 0
    length = len(text)

    def skip_space(position: int) -> int:
        while position < length and text[position] in " \t\r\n":
            position += 1
        return position

    def replace_state(state: str) -> None:
        nonlocal root_state
        if stack:
            kind, _old_state = stack[-1]
            stack[-1] = (kind, state)
        else:
            root_state = state

    def complete_parent_value() -> None:
        nonlocal root_state
        if stack:
            kind, state = stack[-1]
            if kind == "array" and state in {"value", "value_or_end"}:
                stack[-1] = (kind, "comma_or_end")
                return
            if kind == "object" and state == "value":
                stack[-1] = (kind, "comma_or_end")
                return
            raise ReviewError(f"{context} has invalid JSON value placement")
        if root_state != "value":
            raise ReviewError(f"{context} has more than one JSON root")
        root_state = "done"

    def start_value(position: int) -> int:
        nonlocal node_count
        value_depth = len(stack) + 1
        if value_depth > MAX_JSON_DEPTH:
            raise ReviewError(f"{context} exceeds the JSON depth bound")
        node_count += 1
        if node_count > MAX_JSON_NODES:
            raise ReviewError(f"{context} exceeds the JSON node bound")
        complete_parent_value()
        character = text[position]
        if character == "{":
            stack.append(("object", "key_or_end"))
            return position + 1
        if character == "[":
            stack.append(("array", "value_or_end"))
            return position + 1
        if character == '"':
            return _scan_json_string(text, position, context)
        if character in "}],:":
            raise ReviewError(f"{context} has invalid JSON value syntax")
        end = position
        while end < length and text[end] not in " \t\r\n{}[],:":
            end += 1
        if end == position:
            raise ReviewError(f"{context} has invalid JSON value syntax")
        return end

    while True:
        index = skip_space(index)
        if not stack:
            if root_state == "value":
                if index >= length:
                    raise ReviewError(f"{context} has no JSON root")
                index = start_value(index)
                continue
            if index != length:
                raise ReviewError(f"{context} has trailing JSON data")
            return

        kind, state = stack[-1]
        if index >= length:
            raise ReviewError(f"{context} has an incomplete JSON container")
        character = text[index]

        if kind == "array":
            if state == "value_or_end" and character == "]":
                stack.pop()
                index += 1
                continue
            if state in {"value", "value_or_end"}:
                index = start_value(index)
                continue
            if state == "comma_or_end":
                if character == "]":
                    stack.pop()
                    index += 1
                    continue
                if character == ",":
                    replace_state("value")
                    index += 1
                    continue
            raise ReviewError(f"{context} has invalid JSON array syntax")

        if state == "key_or_end" and character == "}":
            stack.pop()
            index += 1
            continue
        if state in {"key", "key_or_end"}:
            if character != '"':
                raise ReviewError(f"{context} has an invalid JSON object key")
            index = _scan_json_string(text, index, context)
            replace_state("colon")
            continue
        if state == "colon":
            if character != ":":
                raise ReviewError(f"{context} has an invalid JSON object separator")
            replace_state("value")
            index += 1
            continue
        if state == "value":
            index = start_value(index)
            continue
        if state == "comma_or_end":
            if character == "}":
                stack.pop()
                index += 1
                continue
            if character == ",":
                replace_state("key")
                index += 1
                continue
        raise ReviewError(f"{context} has invalid JSON object syntax")


def _validate_json_bounds(value: Any, context: str) -> None:
    remaining = MAX_JSON_NODES
    stack: list[tuple[Any, int]] = [(iter((value,)), 1)]
    while stack:
        children, depth = stack[-1]
        try:
            item = next(children)
        except StopIteration:
            stack.pop()
            continue
        remaining -= 1
        if remaining < 0:
            raise ReviewError(f"{context} exceeds the JSON node bound")
        if depth > MAX_JSON_DEPTH:
            raise ReviewError(f"{context} exceeds the JSON depth bound")
        if isinstance(item, dict):
            stack.append((iter(item.values()), depth + 1))
        elif isinstance(item, list):
            stack.append((iter(item), depth + 1))


def _load_json_bytes(payload: bytes, maximum: int, context: str) -> Any:
    context = _bounded_json_context(context)
    if not isinstance(payload, bytes) or not payload or len(payload) > maximum:
        raise ReviewError(f"{context} has an invalid byte length")
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeError as error:
        detail = _bounded_json_error(error)
        raise ReviewError(f"{context} is not strict JSON: {detail}") from error
    _preflight_json_bounds(text, context)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_json_object,
            parse_int=_json_integer,
            parse_float=_json_float,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"nonstandard JSON constant: {token}")
            ),
        )
    except (MemoryError, OverflowError, RecursionError, ValueError) as error:
        detail = _bounded_json_error(error)
        raise ReviewError(f"{context} is not strict JSON: {detail}") from error
    _validate_json_bounds(value, context)
    return value


def load_bounded_json_document(
    payload: bytes,
    *,
    maximum: int,
    context: str,
) -> Any:
    """Decode one bounded JSON document with the artifact parser contract."""

    if type(maximum) is not int or maximum <= 0:
        raise ReviewError("JSON document byte limit is invalid")
    if not isinstance(context, str) or not context:
        raise ReviewError("JSON document context is invalid")
    return _load_json_bytes(payload, maximum, context)


def _is_lower_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def deterministic_cyclonedx_identity(
    *,
    candidate_commit: str,
    workspace_package: str,
    source_date_epoch: int,
) -> CycloneDxIdentity:
    """Derive exact CycloneDX identity fields for one candidate package."""

    if not _is_lower_hex(candidate_commit, 40):
        raise ReviewError("CycloneDX candidate commit is not a full SHA-1")
    workspace_package = _require_string(
        workspace_package,
        "CycloneDX workspace package",
    )
    if workspace_package not in WORKSPACE_PACKAGE_NAMES:
        raise ReviewError("CycloneDX workspace package is not exact")
    if (
        type(source_date_epoch) is not int
        or source_date_epoch < 0
        or source_date_epoch > 253_402_300_799
    ):
        raise ReviewError("CycloneDX source-date epoch is invalid")
    try:
        timestamp = dt.datetime.fromtimestamp(
            source_date_epoch,
            tz=dt.timezone.utc,
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OSError, OverflowError, ValueError) as error:
        raise ReviewError("CycloneDX source-date epoch is unsupported") from error
    identity_name = (
        f"https://github.com/sepahead/galadriel@{candidate_commit}"
        f"#crates/{workspace_package}"
    )
    return CycloneDxIdentity(
        serial_number=f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, identity_name)}",
        timestamp=timestamp,
    )


def _absolute_posix_path(value: Any, context: str) -> PurePosixPath:
    path_text = _require_string(value, context)
    path = PurePosixPath(path_text)
    if not path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise ReviewError(f"{context} is not an absolute normalized path")
    return path


def _expected_package_id(
    *,
    name: str,
    version: str,
    source: str | None,
    manifest_path: str,
) -> str:
    if source is None:
        return f"path+{Path(manifest_path).parent.as_uri()}#{version}"
    if source.startswith("git+"):
        base, separator, revision = source.rpartition("#")
        if separator != "#" or not _is_lower_hex(revision, 40):
            raise ReviewError(f"Git source lacks a terminal full revision: {source}")
        return f"{base}#{name}@{version}"
    return f"{source}#{name}@{version}"


def _validate_git_source(source: str) -> None:
    base, separator, commit = source.rpartition("#")
    if separator != "#" or not _is_lower_hex(commit, 40):
        raise ReviewError("Cargo.lock Git source lacks a terminal full revision")
    parsed = urllib.parse.urlsplit(base.removeprefix("git+"))
    query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or set(query) != {"rev"}
        or query["rev"] != [commit]
        or parsed.fragment
    ):
        raise ReviewError(
            "Cargo.lock Git source is not an exact credential-free revision"
        )


def _parse_lockfile(
    payload: bytes,
) -> tuple[dict[tuple[str, str, str | None], dict[str, Any]], int]:
    if (
        not isinstance(payload, bytes)
        or not payload
        or len(payload) > MAX_LOCKFILE_BYTES
    ):
        raise ReviewError("Cargo.lock has an invalid byte length")
    try:
        document = tomllib.loads(payload.decode("utf-8", "strict"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ReviewError(f"Cargo.lock is not strict TOML: {error}") from error
    if not isinstance(document, dict) or set(document) != {"version", "package"}:
        raise ReviewError("Cargo.lock has another root structure")
    if type(document["version"]) is not int or document["version"] != 4:
        raise ReviewError("Cargo.lock does not use exact lock format 4")
    packages = document["package"]
    if (
        not isinstance(packages, list)
        or not packages
        or len(packages) > MAX_PACKAGE_COUNT
    ):
        raise ReviewError("Cargo.lock package set is empty or oversized")

    result: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    dependency_count = 0
    for index, package_value in enumerate(packages):
        context = f"Cargo.lock package {index}"
        if not isinstance(package_value, dict):
            raise ReviewError(f"{context} is not an object")
        allowed = {"name", "version", "source", "checksum", "dependencies"}
        if not {"name", "version"}.issubset(package_value) or not set(
            package_value
        ).issubset(allowed):
            raise ReviewError(f"{context} has another field set")
        name = _require_string(package_value["name"], f"{context} name")
        version = _require_string(package_value["version"], f"{context} version")
        source = _require_optional_string(
            package_value.get("source"), f"{context} source"
        )
        checksum = _require_optional_string(
            package_value.get("checksum"), f"{context} checksum"
        )
        if source is None:
            if checksum is not None:
                raise ReviewError(f"{context} path package has a checksum")
        elif source == REGISTRY_SOURCE:
            if not _is_lower_hex(checksum, 64):
                raise ReviewError(f"{context} registry checksum is not exact")
        elif source.startswith("git+"):
            _validate_git_source(source)
            if checksum is not None:
                raise ReviewError(f"{context} Git package has a registry checksum")
        else:
            raise ReviewError(f"{context} has an unapproved source")

        dependencies = _require_string_list(
            package_value.get("dependencies", []),
            f"{context} dependencies",
            maximum=MAX_GRAPH_EDGES,
            unique=True,
        )
        dependency_count += len(dependencies)
        if dependency_count > MAX_GRAPH_EDGES:
            raise ReviewError("Cargo.lock exceeds the dependency-edge bound")
        identity = (name, version, source)
        if identity in result:
            raise ReviewError(f"Cargo.lock repeats package identity {identity}")
        result[identity] = {
            "name": name,
            "version": version,
            "source": source,
            "checksum": checksum,
            "dependencies": dependencies,
        }
    return result, dependency_count


def _validate_metadata_dependency(value: Any, context: str) -> None:
    if (
        not isinstance(value, dict)
        or not METADATA_DEPENDENCY_FIELDS.issubset(value)
        or not set(value).issubset(
            METADATA_DEPENDENCY_FIELDS | METADATA_DEPENDENCY_OPTIONAL_FIELDS
        )
    ):
        raise ReviewError(f"{context} has another field set")
    dependency = value
    _require_string(dependency["name"], f"{context} name")
    _require_optional_string(dependency["source"], f"{context} source")
    _require_string(dependency["req"], f"{context} requirement")
    if dependency["kind"] not in {None, "dev", "build"}:
        raise ReviewError(f"{context} has another dependency kind")
    _require_optional_string(dependency["rename"], f"{context} rename")
    _require_optional_string(dependency["target"], f"{context} target")
    _require_optional_string(dependency["registry"], f"{context} registry")
    if "path" in dependency:
        _absolute_posix_path(dependency["path"], f"{context} path")
    if type(dependency["optional"]) is not bool:
        raise ReviewError(f"{context} optional flag is not Boolean")
    if type(dependency["uses_default_features"]) is not bool:
        raise ReviewError(f"{context} default-feature flag is not Boolean")
    _require_string_list(
        dependency["features"],
        f"{context} features",
    )


def _target_components(value: Any, context: str) -> tuple[CargoTargetComponent, ...]:
    if not isinstance(value, list) or not value or len(value) > MAX_TARGET_COUNT:
        raise ReviewError(f"{context} targets are empty or oversized")
    result: list[CargoTargetComponent] = []
    for index, target_value in enumerate(value):
        target_context = f"{context} target {index}"
        if (
            not isinstance(target_value, dict)
            or not METADATA_TARGET_FIELDS.issubset(target_value)
            or not set(target_value).issubset(
                METADATA_TARGET_FIELDS | METADATA_TARGET_OPTIONAL_FIELDS
            )
        ):
            raise ReviewError(f"{target_context} has another field set")
        target = target_value
        name = _require_string(target["name"], f"{target_context} name")
        kinds = _require_string_list(
            target["kind"], f"{target_context} kinds", unique=True
        )
        _require_string_list(
            target["crate_types"],
            f"{target_context} crate types",
            unique=True,
        )
        if "required-features" in target:
            _require_string_list(
                target["required-features"],
                f"{target_context} required features",
                unique=True,
            )
        source_path = str(
            _absolute_posix_path(target["src_path"], f"{target_context} source path")
        )
        _require_string(target["edition"], f"{target_context} edition")
        for field in ("doc", "doctest", "test"):
            if type(target[field]) is not bool:
                raise ReviewError(f"{target_context} {field} flag is not Boolean")
        if "lib" in kinds:
            result.append(CargoTargetComponent(name, "library", source_path))
        elif "bin" in kinds:
            result.append(CargoTargetComponent(name, "application", source_path))
    return tuple(result)


def _validate_package_structure(value: Any, index: int) -> dict[str, Any]:
    context = f"Cargo metadata package {index}"
    package = _require_exact_fields(value, METADATA_PACKAGE_FIELDS, context)
    for field in ("name", "version", "id", "edition", "manifest_path"):
        _require_string(package[field], f"{context} {field}")
    for field in (
        "default_run",
        "documentation",
        "homepage",
        "license",
        "license_file",
        "links",
        "readme",
        "repository",
        "rust_version",
        "source",
    ):
        _require_optional_string(package[field], f"{context} {field}")
    _require_optional_string(
        package["description"],
        f"{context} description",
        reject_controls=False,
    )
    for field in ("authors", "categories", "keywords"):
        _require_string_list(package[field], f"{context} {field}", unique=True)
    if package["metadata"] is not None and not isinstance(package["metadata"], dict):
        raise ReviewError(f"{context} metadata is not an object or null")
    if package["publish"] is not None:
        _require_string_list(
            package["publish"], f"{context} publish registries", unique=True
        )
    features = package["features"]
    if not isinstance(features, dict) or len(features) > MAX_FEATURE_COUNT:
        raise ReviewError(f"{context} feature map is invalid")
    for feature, enables in features.items():
        _require_string(feature, f"{context} feature name")
        _require_string_list(
            enables,
            f"{context} feature {feature} values",
            unique=True,
        )
    dependencies = package["dependencies"]
    if not isinstance(dependencies, list) or len(dependencies) > MAX_GRAPH_EDGES:
        raise ReviewError(f"{context} dependency declarations are oversized")
    for dependency_index, dependency in enumerate(dependencies):
        _validate_metadata_dependency(
            dependency, f"{context} dependency {dependency_index}"
        )
    _target_components(package["targets"], context)
    return package


def _lock_dependency_index(
    lock_packages: Mapping[LockIdentity, dict[str, Any]],
) -> _LockDependencyIndex:
    by_name_lists: dict[str, list[LockIdentity]] = {}
    by_name_version_lists: dict[tuple[str, str], list[LockIdentity]] = {}
    for identity in lock_packages:
        by_name_lists.setdefault(identity[0], []).append(identity)
        by_name_version_lists.setdefault((identity[0], identity[1]), []).append(
            identity
        )
    return _LockDependencyIndex(
        by_name={key: tuple(identities) for key, identities in by_name_lists.items()},
        by_name_version={
            key: tuple(identities) for key, identities in by_name_version_lists.items()
        },
    )


def _resolve_lock_dependency(
    descriptor: str,
    index: _LockDependencyIndex,
) -> LockIdentity:
    parts = descriptor.split(" ")
    if len(parts) not in {1, 2} or any(not part for part in parts):
        raise ReviewError(
            f"Cargo.lock dependency descriptor is unsupported: {descriptor}"
        )
    matches = (
        index.by_name.get(parts[0], ())
        if len(parts) == 1
        else index.by_name_version.get((parts[0], parts[1]), ())
    )
    if len(matches) != 1:
        raise ReviewError(
            f"Cargo.lock dependency descriptor is ambiguous: {descriptor}"
        )
    return matches[0]


def _metadata_dependency_source_matches(
    declared_source: str | None, resolved_source: str | None
) -> bool:
    if declared_source == resolved_source:
        return True
    if (
        isinstance(declared_source, str)
        and isinstance(resolved_source, str)
        and declared_source.startswith("git+")
        and resolved_source.startswith(f"{declared_source}#")
    ):
        return True
    return False


def _metadata_dependency_name_matches(
    declaration: dict[str, Any],
    resolved_package: dict[str, Any],
    dependency_name: str,
) -> bool:
    rename = declaration["rename"]
    if rename is not None:
        return rename.replace("-", "_") == dependency_name
    if declaration["name"] != resolved_package["name"]:
        return False
    return any(
        dependency_name == target["name"]
        and any(kind in {"lib", "proc-macro"} for kind in target["kind"])
        for target in resolved_package["targets"]
    )


def _metadata_declaration_index(
    declarations: list[dict[str, Any]],
) -> _MetadataDeclarationIndex:
    renamed_lists: dict[DeclarationKey, list[int]] = {}
    unrenamed_lists: dict[DeclarationKey, list[int]] = {}
    for declaration_index, declaration in enumerate(declarations):
        rename = declaration["rename"]
        if rename is None:
            key = (
                declaration["name"],
                declaration["source"],
                declaration["kind"],
                declaration["target"],
            )
            unrenamed_lists.setdefault(key, []).append(declaration_index)
        else:
            key = (
                rename.replace("-", "_"),
                declaration["source"],
                declaration["kind"],
                declaration["target"],
            )
            renamed_lists.setdefault(key, []).append(declaration_index)
    return _MetadataDeclarationIndex(
        renamed={key: tuple(indices) for key, indices in renamed_lists.items()},
        unrenamed={key: tuple(indices) for key, indices in unrenamed_lists.items()},
    )


def _resolved_source_variants(source: str | None) -> tuple[str | None, ...]:
    if not isinstance(source, str) or not source.startswith("git+"):
        return (source,)
    base, separator, _commit = source.rpartition("#")
    if separator != "#":
        return (source,)
    return (source, base)


def _matching_metadata_declarations(
    index: _MetadataDeclarationIndex,
    *,
    resolved_package: dict[str, Any],
    dependency_name: str,
    dependency_kind: str | None,
    dependency_target: str | None,
    library_target_names: frozenset[str],
) -> set[int]:
    matches: set[int] = set()
    for source in _resolved_source_variants(resolved_package["source"]):
        renamed_key = (
            dependency_name,
            source,
            dependency_kind,
            dependency_target,
        )
        matches.update(index.renamed.get(renamed_key, ()))
        if dependency_name in library_target_names:
            unrenamed_key = (
                resolved_package["name"],
                source,
                dependency_kind,
                dependency_target,
            )
            matches.update(index.unrenamed.get(unrenamed_key, ()))
    return matches


def validate_cargo_metadata(
    metadata_bytes: bytes, cargo_lock_bytes: bytes
) -> ValidatedCargoGraph:
    """Validate exact all-feature metadata against the complete Cargo lock."""

    metadata_value = _load_json_bytes(
        metadata_bytes, MAX_METADATA_BYTES, "Cargo metadata"
    )
    metadata = _require_exact_fields(
        metadata_value, METADATA_ROOT_FIELDS, "Cargo metadata"
    )
    if type(metadata["version"]) is not int or metadata["version"] != 1:
        raise ReviewError("Cargo metadata does not use format version 1")
    if metadata["metadata"] is not None:
        raise ReviewError("Cargo metadata contains unexpected workspace metadata")
    workspace_root = str(
        _absolute_posix_path(metadata["workspace_root"], "Cargo workspace root")
    )
    target_directory = str(
        _absolute_posix_path(metadata["target_directory"], "Cargo target directory")
    )
    package_values = metadata["packages"]
    if (
        not isinstance(package_values, list)
        or not package_values
        or len(package_values) > MAX_PACKAGE_COUNT
    ):
        raise ReviewError("Cargo metadata package set is empty or oversized")
    lock_packages, _lock_dependency_count = _parse_lockfile(cargo_lock_bytes)
    if len(lock_packages) != len(package_values):
        raise ReviewError("Cargo metadata and Cargo.lock package counts differ")
    lock_dependency_index = _lock_dependency_index(lock_packages)

    structured_packages = [
        _validate_package_structure(value, index)
        for index, value in enumerate(package_values)
    ]
    package_values_by_id: dict[str, dict[str, Any]] = {}
    identity_to_id: dict[tuple[str, str, str | None], str] = {}
    for package in structured_packages:
        package_id = package["id"]
        name = package["name"]
        version = package["version"]
        source = package["source"]
        manifest_path = str(
            _absolute_posix_path(package["manifest_path"], f"{name} manifest path")
        )
        expected_id = _expected_package_id(
            name=name,
            version=version,
            source=source,
            manifest_path=manifest_path,
        )
        if package_id != expected_id:
            raise ReviewError(f"Cargo metadata package ID is inconsistent: {name}")
        identity = (name, version, source)
        if package_id in package_values_by_id or identity in identity_to_id:
            raise ReviewError(f"Cargo metadata repeats package identity {identity}")
        if identity not in lock_packages:
            raise ReviewError(
                f"Cargo metadata package is absent from Cargo.lock: {identity}"
            )
        package_values_by_id[package_id] = package
        identity_to_id[identity] = package_id
    if set(identity_to_id) != set(lock_packages):
        raise ReviewError("Cargo metadata package identities differ from Cargo.lock")
    dependency_library_target_names = {
        package_id: frozenset(
            target["name"]
            for target in package["targets"]
            if any(kind in {"lib", "proc-macro"} for kind in target["kind"])
        )
        for package_id, package in package_values_by_id.items()
    }

    workspace_members = _require_string_list(
        metadata["workspace_members"],
        "Cargo workspace members",
        maximum=MAX_PACKAGE_COUNT,
        unique=True,
    )
    default_members = _require_string_list(
        metadata["workspace_default_members"],
        "Cargo default workspace members",
        maximum=MAX_PACKAGE_COUNT,
        unique=True,
    )
    workspace_member_set = set(workspace_members)
    workspace_names = {
        package_values_by_id[package_id]["name"]
        for package_id in workspace_members
        if package_id in package_values_by_id
    }
    if len(workspace_names) != len(workspace_members):
        raise ReviewError("Cargo workspace members include an unknown package")
    if workspace_names != set(WORKSPACE_PACKAGE_NAMES):
        raise ReviewError("Cargo workspace package set is not exact")
    if {
        package_values_by_id[package_id]["name"]
        for package_id in default_members
        if package_id in package_values_by_id
    } != set(DEFAULT_WORKSPACE_PACKAGE_NAMES) or len(default_members) != len(
        DEFAULT_WORKSPACE_PACKAGE_NAMES
    ):
        raise ReviewError("Cargo default workspace package set is not exact")

    for package_id, package in package_values_by_id.items():
        workspace = package_id in workspace_member_set
        name = package["name"]
        if workspace:
            expected_manifest = (
                PurePosixPath(workspace_root) / "crates" / name / "Cargo.toml"
            )
            if (
                package["source"] is not None
                or package["version"] != VERSION
                or package["publish"] != []
                or PurePosixPath(package["manifest_path"]) != expected_manifest
            ):
                raise ReviewError(f"workspace package identity is invalid: {name}")
            if not _target_components(
                package["targets"], f"Cargo workspace package {name}"
            ):
                raise ReviewError(
                    f"workspace package has no library or binary target: {name}"
                )
        elif package["source"] is None:
            raise ReviewError(f"non-workspace package has a path source: {name}")

    resolve = _require_exact_fields(
        metadata["resolve"], METADATA_RESOLVE_FIELDS, "Cargo resolution"
    )
    if resolve["root"] is not None:
        raise ReviewError("virtual Cargo workspace has an unexpected resolve root")
    node_values = resolve["nodes"]
    if (
        not isinstance(node_values, list)
        or len(node_values) != len(package_values_by_id)
        or len(node_values) > MAX_PACKAGE_COUNT
    ):
        raise ReviewError("Cargo resolution node set is incomplete or oversized")

    nodes_by_id: dict[str, dict[str, Any]] = {}
    normal_dependencies: dict[str, tuple[str, ...]] = {}
    non_dev_dependencies: dict[str, tuple[str, ...]] = {}
    edge_count = 0
    for index, node_value in enumerate(node_values):
        context = f"Cargo resolution node {index}"
        node = _require_exact_fields(node_value, METADATA_NODE_FIELDS, context)
        node_id = _require_string(node["id"], f"{context} ID")
        if node_id not in package_values_by_id or node_id in nodes_by_id:
            raise ReviewError(f"{context} has an unknown or duplicate ID")
        dependencies = _require_string_list(
            node["dependencies"],
            f"{context} dependencies",
            maximum=MAX_GRAPH_EDGES,
            unique=True,
        )
        selected_features = _require_string_list(
            node["features"],
            f"{context} features",
            unique=True,
        )
        package = package_values_by_id[node_id]
        declared_features = set(package["features"])
        if not set(selected_features).issubset(declared_features):
            raise ReviewError(f"{context} selects an undeclared feature")
        if (
            node_id in workspace_member_set
            and set(selected_features) != declared_features
        ):
            raise ReviewError(f"{context} does not record all workspace features")

        dependency_rows = node["deps"]
        if (
            not isinstance(dependency_rows, list)
            or len(dependency_rows) > MAX_GRAPH_EDGES
        ):
            raise ReviewError(f"{context} dependency rows are oversized")
        dependency_row_keys: set[tuple[str, str]] = set()
        dependency_ids: set[str] = set()
        normal_ids: set[str] = set()
        non_dev_ids: set[str] = set()
        matched_declaration_indices: set[int] = set()
        declarations = package["dependencies"]
        declaration_index = _metadata_declaration_index(declarations)
        for dependency_index, dependency_value in enumerate(dependency_rows):
            dependency_context = f"{context} dependency {dependency_index}"
            dependency = _require_exact_fields(
                dependency_value,
                METADATA_NODE_DEP_FIELDS,
                dependency_context,
            )
            dependency_name = _require_string(
                dependency["name"], f"{dependency_context} name"
            )
            dependency_id = _require_string(
                dependency["pkg"], f"{dependency_context} package"
            )
            if dependency_id not in package_values_by_id:
                raise ReviewError(f"{dependency_context} targets an unknown package")
            resolved_dependency = package_values_by_id[dependency_id]
            key = (dependency_name, dependency_id)
            if key in dependency_row_keys:
                raise ReviewError(f"{dependency_context} is duplicated")
            dependency_row_keys.add(key)
            dependency_ids.add(dependency_id)
            dep_kinds = dependency["dep_kinds"]
            if not isinstance(dep_kinds, list) or not dep_kinds:
                raise ReviewError(f"{dependency_context} has no dependency kind")
            seen_kinds: set[tuple[str | None, str | None]] = set()
            for kind_index, kind_value in enumerate(dep_kinds):
                kind_context = f"{dependency_context} kind {kind_index}"
                kind = _require_exact_fields(
                    kind_value, METADATA_DEP_KIND_FIELDS, kind_context
                )
                if kind["kind"] not in {None, "dev", "build"}:
                    raise ReviewError(f"{kind_context} has another kind")
                target = _require_optional_string(
                    kind["target"], f"{kind_context} target"
                )
                kind_key = (kind["kind"], target)
                if kind_key in seen_kinds:
                    raise ReviewError(f"{kind_context} is duplicated")
                seen_kinds.add(kind_key)
                declaration_matches = _matching_metadata_declarations(
                    declaration_index,
                    resolved_package=resolved_dependency,
                    dependency_name=dependency_name,
                    dependency_kind=kind["kind"],
                    dependency_target=target,
                    library_target_names=dependency_library_target_names[dependency_id],
                )
                if not declaration_matches:
                    raise ReviewError(
                        f"{kind_context} has no matching package declaration"
                    )
                matched_declaration_indices.update(declaration_matches)
                if kind["kind"] is None:
                    normal_ids.add(dependency_id)
                if kind["kind"] != "dev":
                    non_dev_ids.add(dependency_id)
        if set(dependencies) != dependency_ids:
            raise ReviewError(f"{context} dependency views disagree")
        if node_id in workspace_member_set and matched_declaration_indices != set(
            range(len(declarations))
        ):
            raise ReviewError(
                f"{context} omits an all-feature workspace dependency declaration"
            )
        edge_count += len(dependency_ids)
        if edge_count > MAX_GRAPH_EDGES:
            raise ReviewError("Cargo resolution exceeds the dependency-edge bound")
        nodes_by_id[node_id] = {
            "dependencies": tuple(sorted(dependency_ids)),
            "features": tuple(selected_features),
        }
        normal_dependencies[node_id] = tuple(sorted(normal_ids))
        non_dev_dependencies[node_id] = tuple(sorted(non_dev_ids))
    if set(nodes_by_id) != set(package_values_by_id):
        raise ReviewError("Cargo resolution node identities differ from packages")

    for identity, lock_package in lock_packages.items():
        package_id = identity_to_id[identity]
        expected_dependency_ids = {
            identity_to_id[_resolve_lock_dependency(descriptor, lock_dependency_index)]
            for descriptor in lock_package["dependencies"]
        }
        if set(nodes_by_id[package_id]["dependencies"]) != expected_dependency_ids:
            raise ReviewError(
                f"Cargo resolution differs from Cargo.lock for {identity[0]}"
            )

    packages: list[CargoPackage] = []
    for package_id in sorted(package_values_by_id):
        package = package_values_by_id[package_id]
        identity = (package["name"], package["version"], package["source"])
        packages.append(
            CargoPackage(
                package_id=package_id,
                name=package["name"],
                version=package["version"],
                source=package["source"],
                checksum=lock_packages[identity]["checksum"],
                manifest_path=package["manifest_path"],
                workspace=package_id in workspace_member_set,
                authors=tuple(package["authors"]),
                description=package["description"],
                documentation=package["documentation"],
                homepage=package["homepage"],
                repository=package["repository"],
                links=package["links"],
                license=package["license"],
                license_file=package["license_file"],
                declared_features=tuple(sorted(package["features"])),
                resolved_features=tuple(nodes_by_id[package_id]["features"]),
                dependencies=tuple(nodes_by_id[package_id]["dependencies"]),
                normal_dependencies=normal_dependencies[package_id],
                non_dev_dependencies=non_dev_dependencies[package_id],
                target_components=_target_components(
                    package["targets"], f"Cargo package {package['name']}"
                ),
            )
        )
    return ValidatedCargoGraph(
        workspace_root=workspace_root,
        target_directory=target_directory,
        packages=tuple(packages),
        workspace_package_ids=tuple(sorted(workspace_members)),
        default_workspace_package_ids=tuple(sorted(default_members)),
    )


def _bounded_gzip_decompress(payload: bytes) -> bytes:
    if (
        not isinstance(payload, bytes)
        or not payload
        or len(payload) > MAX_CRATE_ARCHIVE_BYTES
    ):
        raise ReviewError("Cargo package archive has an invalid compressed size")
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    output = bytearray()
    try:
        for offset in range(0, len(payload), 64 * 1024):
            pending = payload[offset : offset + 64 * 1024]
            while pending:
                remaining = MAX_CRATE_UNCOMPRESSED_BYTES - len(output)
                chunk = decompressor.decompress(pending, remaining + 1)
                output.extend(chunk)
                if len(output) > MAX_CRATE_UNCOMPRESSED_BYTES:
                    raise ReviewError(
                        "Cargo package archive exceeds the uncompressed-size bound"
                    )
                next_pending = decompressor.unconsumed_tail
                if next_pending == pending:
                    raise ReviewError("Cargo package decompression made no progress")
                pending = next_pending
        remaining = MAX_CRATE_UNCOMPRESSED_BYTES - len(output)
        output.extend(decompressor.flush(remaining + 1))
    except zlib.error as error:
        raise ReviewError(f"Cargo package gzip stream is invalid: {error}") from error
    if len(output) > MAX_CRATE_UNCOMPRESSED_BYTES:
        raise ReviewError("Cargo package archive exceeds the uncompressed-size bound")
    if not decompressor.eof or decompressor.unused_data or decompressor.unconsumed_tail:
        raise ReviewError("Cargo package gzip stream has trailing or incomplete data")
    return bytes(output)


def _safe_archive_relative(name: str, prefix: str) -> str:
    if (
        not isinstance(name, str)
        or len(name.encode("utf-8")) > MAX_ARCHIVE_PATH_BYTES
        or "\\" in name
        or any(ord(character) < 0x20 for character in name)
        or not name.startswith(prefix)
    ):
        raise ReviewError(f"Cargo package has an unsafe member path: {name!r}")
    relative = name.removeprefix(prefix)
    path = PurePosixPath(relative)
    if (
        not relative
        or path.is_absolute()
        or len(path.parts) > MAX_ARCHIVE_PATH_DEPTH
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ReviewError(f"Cargo package has an unsafe member path: {name!r}")
    return relative


def _validated_candidate_files(
    candidate_files: Mapping[str, tuple[int, bytes]],
) -> dict[str, tuple[int, bytes]]:
    """Copy and validate the exact candidate file map one time."""

    if (
        not isinstance(candidate_files, Mapping)
        or not candidate_files
        or len(candidate_files) > MAX_CRATE_MEMBERS - 2
    ):
        raise ReviewError("Cargo package candidate file map is empty or oversized")
    items: list[tuple[Any, Any]] = []
    try:
        for item in candidate_files.items():
            if len(items) >= MAX_CRATE_MEMBERS - 2:
                raise ReviewError("Cargo package candidate file map is oversized")
            items.append(item)
    except ReviewError:
        raise
    except (AttributeError, RuntimeError, TypeError, ValueError) as error:
        raise ReviewError("Cargo package candidate file map is unstable") from error
    if len(items) != len(candidate_files):
        raise ReviewError("Cargo package candidate file map changed during its copy")

    result: dict[str, tuple[int, bytes]] = {}
    total_bytes = 0
    for raw_name, raw_entry in items:
        if not isinstance(raw_name, str):
            raise ReviewError("Cargo package candidate file path is not a string")
        name = _safe_archive_relative(f"candidate/{raw_name}", "candidate/")
        if name in result:
            raise ReviewError(f"Cargo package candidate file repeats a path: {name}")
        if name in {"Cargo.toml", ".cargo_vcs_info.json"}:
            raise ReviewError(
                f"Cargo package candidate file map contains a generated path: {name}"
            )
        if PurePosixPath(name).name == "Cargo.lock":
            raise ReviewError("Cargo package candidate file map contains Cargo.lock")
        if (
            not isinstance(raw_entry, tuple)
            or len(raw_entry) != 2
            or type(raw_entry[0]) is not int
            or raw_entry[0] not in {0o644, 0o755}
            or not isinstance(raw_entry[1], bytes)
            or len(raw_entry[1]) > MAX_CRATE_MEMBER_BYTES
        ):
            raise ReviewError(
                f"Cargo package candidate file has invalid mode or content: {name}"
            )
        total_bytes += len(raw_entry[1])
        if total_bytes > MAX_CRATE_UNCOMPRESSED_BYTES:
            raise ReviewError(
                "Cargo package candidate files exceed the aggregate size bound"
            )
        result[name] = raw_entry
    if "Cargo.toml.orig" not in result:
        raise ReviewError("Cargo package candidate file map omits Cargo.toml.orig")
    return result


def _crate_manifest_package(content: bytes, context: str) -> dict[str, Any]:
    try:
        manifest = tomllib.loads(content.decode("utf-8", "strict"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ReviewError(f"{context} is invalid: {error}") from error
    package = manifest.get("package") if isinstance(manifest, dict) else None
    if not isinstance(package, dict):
        raise ReviewError(f"{context} has no package table")
    return package


def validate_crate_archive(
    archive_bytes: bytes,
    *,
    crate_name: str,
    version: str,
    candidate_commit: str,
    candidate_files: Mapping[str, tuple[int, bytes]],
) -> CrateArchiveSummary:
    """Bind one unpublished Cargo package to exact candidate crate files."""

    crate_name = _require_string(crate_name, "Cargo package crate name")
    version = _require_string(version, "Cargo package version")
    if not _is_lower_hex(candidate_commit, 40):
        raise ReviewError("Cargo package candidate commit is not a full SHA-1")
    expected_candidate_files = _validated_candidate_files(candidate_files)
    expected_members = set(expected_candidate_files) | {
        "Cargo.toml",
        ".cargo_vcs_info.json",
    }
    prefix = f"{crate_name}-{version}/"
    raw_tar = _bounded_gzip_decompress(archive_bytes)
    members: dict[str, tarfile.TarInfo] = {}
    total_member_bytes = 0
    payload_end = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw_tar), mode="r:") as archive:
            for member in archive:
                if len(members) >= MAX_CRATE_MEMBERS:
                    raise ReviewError("Cargo package exceeds the member-count bound")
                relative = _safe_archive_relative(member.name, prefix)
                if relative in members:
                    raise ReviewError(
                        f"Cargo package repeats a member path: {relative}"
                    )
                if (
                    not member.isfile()
                    or member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE}
                    or member.linkname
                    or member.pax_headers
                    or member.size < 0
                    or member.size > MAX_CRATE_MEMBER_BYTES
                    or member.uid != 0
                    or member.gid != 0
                    or member.mode not in {0o644, 0o755}
                    or member.mode & 0o022
                ):
                    raise ReviewError(
                        f"Cargo package member has an unsafe type or metadata: {relative}"
                    )
                total_member_bytes += member.size
                if total_member_bytes > MAX_CRATE_UNCOMPRESSED_BYTES:
                    raise ReviewError(
                        "Cargo package exceeds the aggregate member-size bound"
                    )
                payload_end = max(
                    payload_end,
                    member.offset_data + ((member.size + 511) // 512) * 512,
                )
                members[relative] = member
            required = {"Cargo.toml", ".cargo_vcs_info.json"}
            if not required.issubset(members):
                raise ReviewError("Cargo package omits required metadata files")
            if any(PurePosixPath(name).name == "Cargo.lock" for name in members):
                raise ReviewError("unpublished Cargo package contains Cargo.lock")
            if set(members) != expected_members:
                missing = sorted(expected_members - set(members))
                extra = sorted(set(members) - expected_members)
                raise ReviewError(
                    "Cargo package member set differs from candidate files: "
                    f"missing={missing!r}, extra={extra!r}"
                )
            if (
                len(raw_tar) != payload_end + 1024
                or any(raw_tar[payload_end:])
                or len(raw_tar) % 512 != 0
            ):
                raise ReviewError(
                    "Cargo package tar stream has noncanonical trailing data"
                )

            extracted: dict[str, bytes] = {}
            for relative, member in members.items():
                handle = archive.extractfile(members[relative])
                if handle is None:
                    raise ReviewError(f"Cargo package member is unreadable: {relative}")
                content = handle.read(member.size + 1)
                if len(content) != member.size:
                    raise ReviewError(f"Cargo package member size changed: {relative}")
                if relative in expected_candidate_files:
                    expected_mode, expected_content = expected_candidate_files[relative]
                    if member.mode != expected_mode or content != expected_content:
                        raise ReviewError(
                            "Cargo package member differs from the candidate: "
                            f"{relative}"
                        )
                else:
                    if member.mode != 0o644:
                        raise ReviewError(
                            f"Cargo package generated member has another mode: {relative}"
                        )
                    extracted[relative] = content
    except (tarfile.TarError, OSError) as error:
        raise ReviewError(f"Cargo package tar stream is invalid: {error}") from error

    package = _crate_manifest_package(
        extracted["Cargo.toml"], "Cargo package generated manifest"
    )
    if (
        package.get("name") != crate_name
        or package.get("version") != version
        or package.get("publish") is not False
    ):
        raise ReviewError("Cargo package generated manifest identity is invalid")
    original_package = _crate_manifest_package(
        expected_candidate_files["Cargo.toml.orig"][1],
        "Cargo package original manifest",
    )
    original_version = original_package.get("version")
    if (
        original_package.get("name") != crate_name
        or original_package.get("publish") is not False
        or (original_version != version and original_version != {"workspace": True})
    ):
        raise ReviewError("Cargo package original manifest identity is invalid")

    vcs_value = _load_json_bytes(
        extracted[".cargo_vcs_info.json"],
        MAX_CRATE_MEMBER_BYTES,
        "Cargo package VCS record",
    )
    vcs = _require_exact_fields(
        vcs_value, {"git", "path_in_vcs"}, "Cargo package VCS record"
    )
    git = _require_exact_fields(vcs["git"], {"sha1"}, "Cargo package VCS Git record")
    if git["sha1"] != candidate_commit or vcs["path_in_vcs"] != f"crates/{crate_name}":
        raise ReviewError("Cargo package VCS identity is invalid")
    return CrateArchiveSummary(
        crate=crate_name,
        version=version,
        candidate_commit=candidate_commit,
        member_count=len(members),
        uncompressed_member_bytes=total_member_bytes,
    )


def _reachable_packages(
    graph: ValidatedCargoGraph,
    root_id: str,
    *,
    include_build_dependencies: bool,
) -> set[str]:
    packages = graph.package_by_id()
    if root_id not in packages:
        raise ReviewError("SBOM root does not identify a Cargo package")
    reached = {root_id}
    pending = [root_id]
    traversed_edges = 0
    while pending:
        package_id = pending.pop()
        package = packages[package_id]
        dependency_ids = (
            package.non_dev_dependencies
            if include_build_dependencies
            else package.normal_dependencies
        )
        for dependency_id in dependency_ids:
            traversed_edges += 1
            if traversed_edges > MAX_GRAPH_EDGES:
                raise ReviewError("SBOM reachability exceeds the graph-edge bound")
            if dependency_id not in packages:
                raise ReviewError("validated Cargo graph has an unknown dependency")
            if dependency_id not in reached:
                reached.add(dependency_id)
                pending.append(dependency_id)
    return reached


def _validate_sbom_timestamp(value: Any) -> None:
    text = _require_string(value, "CycloneDX metadata timestamp")
    try:
        timestamp = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReviewError("CycloneDX metadata timestamp is invalid") from error
    if timestamp.tzinfo is None or timestamp.utcoffset() != dt.timedelta(0):
        raise ReviewError(
            "CycloneDX metadata timestamp is not Coordinated Universal Time"
        )


def _sbom_package_reference_maps(
    graph: ValidatedCargoGraph,
    root_package: CargoPackage,
    root_reference_value: Any,
) -> tuple[dict[str, str], dict[str, str]]:
    """Map relocatable SBOM workspace references to validated Cargo identities."""

    root_reference = _require_string(
        root_reference_value, "CycloneDX root component reference"
    )
    base, separator, version = root_reference.rpartition("#")
    if separator != "#" or version != root_package.version:
        raise ReviewError("CycloneDX root component reference has another version")
    parsed = urllib.parse.urlsplit(base.removeprefix("path+"))
    try:
        decoded_path = urllib.parse.unquote(parsed.path, errors="strict")
    except UnicodeError as error:
        raise ReviewError("CycloneDX root component path is not valid UTF-8") from error
    package_path = _absolute_posix_path(decoded_path, "CycloneDX root component path")
    expected_package_path = package_path.parent.parent / "crates" / root_package.name
    if (
        not base.startswith("path+")
        or parsed.scheme != "file"
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or package_path != expected_package_path
        or f"path+{Path(decoded_path).as_uri()}" != base
    ):
        raise ReviewError("CycloneDX root component path is not canonical")

    sbom_workspace_root = package_path.parent.parent
    external_to_cargo: dict[str, str] = {}
    cargo_to_external: dict[str, str] = {}
    for package in graph.packages:
        if package.workspace:
            external_reference = (
                "path+"
                f"{Path(sbom_workspace_root / 'crates' / package.name).as_uri()}"
                f"#{package.version}"
            )
        else:
            external_reference = package.package_id
        if (
            external_reference in external_to_cargo
            or package.package_id in cargo_to_external
        ):
            raise ReviewError("CycloneDX package-reference map is ambiguous")
        external_to_cargo[external_reference] = package.package_id
        cargo_to_external[package.package_id] = external_reference
    if cargo_to_external[root_package.package_id] != root_reference:
        raise ReviewError("CycloneDX root component targets another package")
    return external_to_cargo, cargo_to_external


def _sbom_license_expression(package: CargoPackage) -> str | None:
    if package.license_file is not None:
        raise ReviewError(
            f"Cargo package uses an unsupported license file: {package.name}"
        )
    if package.license is None:
        return None
    parts = package.license.split("/")
    if len(parts) == 1:
        return package.license
    if any(not part for part in parts):
        raise ReviewError(f"Cargo package license is ambiguous: {package.name}")
    return " OR ".join(parts)


def _sbom_purl(
    package: CargoPackage,
    root_package: CargoPackage,
) -> str:
    base = f"pkg:cargo/{package.name}@{package.version}"
    if package.workspace:
        download_url = (
            "file://."
            if package.package_id == root_package.package_id
            else f"file://../{package.name}"
        )
        return f"{base}?download_url={download_url}"
    if package.source == REGISTRY_SOURCE:
        return base
    if package.source is None or not package.source.startswith("git+"):
        raise ReviewError(
            f"CycloneDX package has an unsupported source: {package.name}"
        )
    source_base, separator, commit = package.source.rpartition("#")
    if separator != "#" or not _is_lower_hex(commit, 40):
        raise ReviewError(f"CycloneDX Git package has another source: {package.name}")
    parsed = urllib.parse.urlsplit(source_base.removeprefix("git+"))
    if parsed.scheme != "https" or not parsed.netloc:
        raise ReviewError(f"CycloneDX Git package URL is invalid: {package.name}")
    repository = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, "", "")
    )
    vcs_url = urllib.parse.quote(
        f"git+{repository}@{commit}",
        safe="/:",
    )
    return f"{base}?vcs_url={vcs_url}"


def _sbom_external_references(package: CargoPackage) -> list[dict[str, str]]:
    references: list[dict[str, str]] = []
    for reference_type, value in (
        ("documentation", package.documentation),
        ("website", package.homepage),
        ("other", package.links),
        ("vcs", package.repository),
    ):
        if value is not None:
            references.append({"type": reference_type, "url": value})
    return references


def _expected_sbom_component(
    package: CargoPackage,
    root_package: CargoPackage,
    *,
    reference: str,
    component_type: str,
    scope: str,
) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": component_type,
        "bom-ref": reference,
    }
    if package.authors:
        component["author"] = ", ".join(package.authors)
    component["name"] = package.name
    component["version"] = package.version
    if package.description is not None:
        component["description"] = package.description.replace("\n", " ")
    component["scope"] = scope
    if package.checksum is not None:
        component["hashes"] = [{"alg": "SHA-256", "content": package.checksum}]
    license_expression = _sbom_license_expression(package)
    if license_expression is not None:
        component["licenses"] = [{"expression": license_expression}]
    component["purl"] = _sbom_purl(package, root_package)
    external_references = _sbom_external_references(package)
    if external_references:
        component["externalReferences"] = external_references
    return component


def _expected_sbom_targets(
    root_package: CargoPackage,
    root_reference: str,
    root_purl: str,
) -> list[dict[str, str]]:
    manifest_directory = PurePosixPath(root_package.manifest_path).parent
    targets: list[dict[str, str]] = []
    for index, target in enumerate(root_package.target_components):
        source_path = PurePosixPath(target.source_path)
        try:
            relative_source = source_path.relative_to(manifest_directory)
        except ValueError as error:
            raise ReviewError(
                "CycloneDX target source is outside its package directory"
            ) from error
        if not relative_source.parts or any(
            part in {"", ".", ".."} for part in relative_source.parts
        ):
            raise ReviewError("CycloneDX target source path is invalid")
        targets.append(
            {
                "type": target.component_type,
                "bom-ref": f"{root_reference} bin-target-{index}",
                "name": target.name,
                "version": root_package.version,
                "purl": f"{root_purl}#{relative_source.as_posix()}",
            }
        )
    return targets


def validate_cyclonedx_sbom(
    sbom_bytes: bytes,
    graph: ValidatedCargoGraph,
    *,
    workspace_package: str,
    candidate_commit: str,
    source_date_epoch: int,
) -> SbomSummary:
    """Validate one CycloneDX 1.5 graph against exact Cargo metadata."""

    workspace_package = _require_string(
        workspace_package, "CycloneDX workspace package"
    )
    root_package = graph.package_by_name(workspace_package)
    if not root_package.workspace:
        raise ReviewError("CycloneDX root package is not a workspace package")
    expected_identity = deterministic_cyclonedx_identity(
        candidate_commit=candidate_commit,
        workspace_package=workspace_package,
        source_date_epoch=source_date_epoch,
    )
    document_value = _load_json_bytes(sbom_bytes, MAX_SBOM_BYTES, "CycloneDX SBOM")
    document = _require_exact_fields(
        document_value,
        {
            "bomFormat",
            "components",
            "dependencies",
            "metadata",
            "serialNumber",
            "specVersion",
            "version",
        },
        "CycloneDX SBOM",
    )
    if (
        document["bomFormat"] != "CycloneDX"
        or document["specVersion"] != "1.5"
        or type(document["version"]) is not int
        or document["version"] != 1
    ):
        raise ReviewError("CycloneDX SBOM has another format or version")
    serial = _require_string(document["serialNumber"], "CycloneDX serial number")
    if serial != expected_identity.serial_number:
        raise ReviewError("CycloneDX serial number differs from the candidate")

    metadata = _require_exact_fields(
        document["metadata"],
        {"authors", "component", "properties", "timestamp", "tools"},
        "CycloneDX metadata",
    )
    _validate_sbom_timestamp(metadata["timestamp"])
    if metadata["timestamp"] != expected_identity.timestamp:
        raise ReviewError("CycloneDX timestamp differs from the source-date epoch")
    if metadata["tools"] != [
        {
            "vendor": "CycloneDX",
            "name": "cargo-cyclonedx",
            "version": "0.5.9",
        }
    ]:
        raise ReviewError("CycloneDX SBOM records another generator")
    if metadata["properties"] != [
        {"name": "cdx:rustc:sbom:target:all_targets", "value": "true"}
    ]:
        raise ReviewError("CycloneDX SBOM does not record the all-target scope")
    expected_authors = [{"name": author} for author in root_package.authors]
    if not expected_authors or metadata["authors"] != expected_authors:
        raise ReviewError("CycloneDX SBOM authors differ from Cargo metadata")

    root = metadata["component"]
    if not isinstance(root, dict):
        raise ReviewError("CycloneDX root component is not an object")
    external_to_cargo, cargo_to_external = _sbom_package_reference_maps(
        graph, root_package, root.get("bom-ref")
    )
    expected_root_type = (
        "application"
        if any(
            target.component_type == "application"
            for target in root_package.target_components
        )
        else "library"
    )
    root_reference = cargo_to_external[root_package.package_id]
    expected_root = _expected_sbom_component(
        root_package,
        root_package,
        reference=root_reference,
        component_type=expected_root_type,
        scope="required",
    )
    expected_root["components"] = _expected_sbom_targets(
        root_package,
        root_reference,
        expected_root["purl"],
    )
    if root != expected_root:
        raise ReviewError(
            "CycloneDX root or target identity differs from Cargo metadata"
        )

    package_map = graph.package_by_id()
    reachable = _reachable_packages(
        graph,
        root_package.package_id,
        include_build_dependencies=True,
    )
    required = _reachable_packages(
        graph,
        root_package.package_id,
        include_build_dependencies=False,
    )
    expected_component_ids = reachable - {root_package.package_id}
    components = document["components"]
    if (
        not isinstance(components, list)
        or len(components) != len(expected_component_ids)
        or len(components) > MAX_PACKAGE_COUNT
    ):
        raise ReviewError("CycloneDX component set is incomplete or oversized")
    component_ids: set[str] = set()
    for index, component in enumerate(components):
        context = f"CycloneDX component {index}"
        if not isinstance(component, dict):
            raise ReviewError(f"{context} is not an object")
        external_component_id = _require_string(
            component.get("bom-ref"), f"{context} reference"
        )
        component_id = external_to_cargo.get(external_component_id)
        if component_id is None:
            raise ReviewError(f"{context} is unknown or duplicated")
        if component_id in component_ids or component_id not in expected_component_ids:
            raise ReviewError(f"{context} is unknown or duplicated")
        component_ids.add(component_id)
        package = package_map[component_id]
        expected_component = _expected_sbom_component(
            package,
            root_package,
            reference=cargo_to_external[component_id],
            component_type="library",
            scope="required" if component_id in required else "excluded",
        )
        if component != expected_component:
            raise ReviewError(f"{context} identity differs from Cargo metadata")
    if component_ids != expected_component_ids:
        raise ReviewError("CycloneDX component identities differ from Cargo metadata")

    dependency_values = document["dependencies"]
    if (
        not isinstance(dependency_values, list)
        or len(dependency_values) != len(reachable)
        or len(dependency_values) > MAX_PACKAGE_COUNT
    ):
        raise ReviewError("CycloneDX dependency records are incomplete or oversized")
    dependency_ids: set[str] = set()
    for index, dependency_value in enumerate(dependency_values):
        context = f"CycloneDX dependency record {index}"
        if (
            not isinstance(dependency_value, dict)
            or "ref" not in dependency_value
            or not set(dependency_value).issubset({"ref", "dependsOn"})
        ):
            raise ReviewError(f"{context} has another structure")
        external_reference = _require_string(
            dependency_value["ref"], f"{context} reference"
        )
        reference = external_to_cargo.get(external_reference)
        if reference is None:
            raise ReviewError(f"{context} is unknown or duplicated")
        if reference in dependency_ids or reference not in reachable:
            raise ReviewError(f"{context} is unknown or duplicated")
        dependency_ids.add(reference)
        external_depends_on = _require_string_list(
            dependency_value.get("dependsOn", []),
            f"{context} dependencies",
            maximum=MAX_GRAPH_EDGES,
            unique=True,
        )
        try:
            depends_on = tuple(
                external_to_cargo[dependency] for dependency in external_depends_on
            )
        except KeyError as error:
            raise ReviewError(f"{context} targets an unknown package") from error
        expected = set(package_map[reference].non_dev_dependencies)
        if set(depends_on) != expected:
            raise ReviewError(f"{context} differs from Cargo metadata")
        expected_fields = {"ref", "dependsOn"} if expected else {"ref"}
        if set(dependency_value) != expected_fields:
            raise ReviewError(f"{context} has another field set")
    if dependency_ids != reachable:
        raise ReviewError("CycloneDX dependency identities differ from Cargo metadata")
    return SbomSummary(
        workspace_package=workspace_package,
        component_count=len(components),
        dependency_record_count=len(dependency_values),
    )


def _load_json_lines(payload: bytes) -> list[dict[str, Any]]:
    if (
        not isinstance(payload, bytes)
        or not payload
        or len(payload) > MAX_LICENSE_REPORT_BYTES
    ):
        raise ReviewError("Cargo deny license report has an invalid byte length")
    lines = payload.splitlines()
    if not lines or len(lines) > MAX_LICENSE_LINES:
        raise ReviewError("Cargo deny license report has an invalid line count")
    documents: list[dict[str, Any]] = []
    for index, line in enumerate(lines):
        if not line or len(line) > MAX_LICENSE_LINE_BYTES:
            raise ReviewError(
                f"Cargo deny license report line {index + 1} is empty or oversized"
            )
        value = _load_json_bytes(
            line, MAX_LICENSE_LINE_BYTES, f"Cargo deny license report line {index + 1}"
        )
        if not isinstance(value, dict):
            raise ReviewError(
                f"Cargo deny license report line {index + 1} is not an object"
            )
        documents.append(value)
    return documents


def validate_cargo_deny_license_policy_jsonl(
    report_bytes: bytes,
) -> LicensePolicySummary:
    """Require the exact passing summary from the Cargo deny policy check."""

    documents = _load_json_lines(report_bytes)
    if len(documents) != 1:
        raise ReviewError("Cargo deny license policy report must contain one summary")
    document = _require_exact_fields(
        documents[0], {"fields", "type"}, "Cargo deny license policy summary"
    )
    if document["type"] != "summary":
        raise ReviewError("Cargo deny license policy report is not a summary")
    fields = _require_exact_fields(
        document["fields"], {"licenses"}, "Cargo deny license policy fields"
    )
    licenses = _require_exact_fields(
        fields["licenses"],
        {"errors", "helps", "notes", "warnings"},
        "Cargo deny license policy counts",
    )
    if (
        any(type(licenses[field]) is not int for field in licenses)
        or licenses["errors"] != 0
        or licenses["warnings"] != 0
        or licenses["helps"] != EXPECTED_LICENSE_ACCEPTED_HELP_COUNT
        or licenses["notes"] != EXPECTED_LICENSE_SKIPPED_NOTE_COUNT
    ):
        raise ReviewError("Cargo deny license policy summary is not exact and passing")
    return LicensePolicySummary(
        accepted_help_count=licenses["helps"],
        skipped_note_count=licenses["notes"],
    )


def _cargo_deny_inventory_source(package: CargoPackage) -> str:
    base, separator, _fragment = package.package_id.rpartition("#")
    if separator != "#" or not base:
        raise ReviewError("validated Cargo package ID lacks an inventory source")
    return base


def _canonical_semantic_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _license_semantic_package_id(package: CargoPackage) -> str:
    """Remove qualification-root paths from workspace package identities."""

    if package.workspace:
        return f"workspace+crates/{package.name}#{package.name}@{package.version}"
    return package.package_id


def validate_cargo_deny_license_inventory(
    inventory_bytes: bytes,
    graph: ValidatedCargoGraph,
    *,
    scope: str,
) -> LicenseInventorySummary:
    """Validate the explicit host-filtered Cargo deny license inventory."""

    if scope != CARGO_DENY_HOST_FILTERED_SCOPE:
        raise ReviewError("Cargo deny license inventory has another scope")
    document_value = _load_json_bytes(
        inventory_bytes,
        MAX_LICENSE_REPORT_BYTES,
        "Cargo deny license inventory",
    )
    if (
        not isinstance(document_value, dict)
        or len(document_value) != EXPECTED_HOST_FILTERED_LICENSE_PACKAGES
    ):
        raise ReviewError("Cargo deny license inventory count is not exact")

    packages_by_identity = {
        (package.name, package.version, _cargo_deny_inventory_source(package)): package
        for package in graph.packages
    }
    if len(packages_by_identity) != len(graph.packages):
        raise ReviewError("validated Cargo graph repeats an inventory identity")

    observed_name_versions: set[tuple[str, str]] = set()
    observed_package_ids: set[str] = set()
    normalized_rows: list[dict[str, Any]] = []
    assignment_count = 0
    for raw_identity, raw_record in document_value.items():
        identity_text = _require_string(
            raw_identity, "Cargo deny license inventory identity"
        )
        parts = identity_text.split(" ", 2)
        if len(parts) != 3 or any(not part for part in parts):
            raise ReviewError(
                "Cargo deny license inventory identity has another format"
            )
        name = _require_string(parts[0], "Cargo deny inventory package name")
        version = _require_string(parts[1], "Cargo deny inventory package version")
        source = _require_string(parts[2], "Cargo deny inventory package source")
        name_version = (name, version)
        if name_version in observed_name_versions:
            raise ReviewError(
                "Cargo deny license inventory repeats a name-version identity"
            )
        observed_name_versions.add(name_version)
        package = packages_by_identity.get((name, version, source))
        if package is None:
            raise ReviewError(
                "Cargo deny license inventory contains an unknown package identity"
            )
        if package.package_id in observed_package_ids:
            raise ReviewError("Cargo deny license inventory repeats a package")
        observed_package_ids.add(package.package_id)

        record = _require_exact_fields(
            raw_record,
            {"licenses"},
            f"Cargo deny license inventory record for {name}",
        )
        licenses = _require_string_list(
            record["licenses"],
            f"Cargo deny license inventory licenses for {name}",
            maximum=256,
            unique=True,
        )
        if not licenses:
            raise ReviewError(
                f"Cargo deny license inventory has no evidence for {name}"
            )
        assignment_count += len(licenses)
        normalized_rows.append(
            {
                "package_id": _license_semantic_package_id(package),
                "licenses": sorted(licenses),
            }
        )
    if assignment_count != EXPECTED_HOST_FILTERED_LICENSE_ASSIGNMENTS:
        raise ReviewError("Cargo deny license assignment count is not exact")

    package_ids = sorted(
        _license_semantic_package_id(package)
        for package in packages_by_identity.values()
        if package.package_id in observed_package_ids
    )
    package_ids_digest = hashlib.sha256(
        _canonical_semantic_bytes(package_ids)
    ).hexdigest()
    if package_ids_digest != EXPECTED_HOST_FILTERED_LICENSE_PACKAGE_IDS_SHA256:
        raise ReviewError("Cargo deny license inventory package set is not exact")

    normalized_rows.sort(key=lambda row: row["package_id"])
    semantic_digest = hashlib.sha256(
        _canonical_semantic_bytes(normalized_rows)
    ).hexdigest()
    if semantic_digest != EXPECTED_HOST_FILTERED_LICENSE_SEMANTIC_SHA256:
        raise ReviewError("Cargo deny license inventory semantics are not exact")
    return LicenseInventorySummary(
        scope=scope,
        package_count=len(observed_package_ids),
        license_assignment_count=assignment_count,
    )
