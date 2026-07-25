#!/usr/bin/env python3
"""Verify strict, root-contained artifact identities in an evidence manifest."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from common import (
    ReviewError,
    RootedFileDigestRequest,
    canonical_relative_parts,
    digest_rooted_regular_files,
    load_json,
)


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_DEPTH = 16
MAX_MANIFEST_NODES = 32_768
MAX_ARTIFACTS = 4_096
MAX_DIRECTORY_ENTRIES = MAX_ARTIFACTS + 256
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_AGGREGATE_BYTES = 4 * 1024 * 1024 * 1024
MAX_PATH_BYTES = 4 * 1024
MAX_PATH_COMPONENT_BYTES = 255
MAX_PATH_DEPTH = 128


def verify_manifest(manifest_path: Path, root: Path) -> int:
    """Verify one bounded manifest through a held root descriptor."""

    manifest = load_json(
        manifest_path,
        max_bytes=MAX_MANIFEST_BYTES,
        max_depth=MAX_MANIFEST_DEPTH,
        max_nodes=MAX_MANIFEST_NODES,
        label="evidence manifest",
    )
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "artifacts"}:
        raise ReviewError("manifest must contain exactly schema and artifacts")
    if manifest["schema"] != "galadriel.evidence-manifest.v1":
        raise ReviewError("unsupported evidence-manifest schema")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list):
        raise ReviewError("artifacts must be an array")
    if not artifacts:
        raise ReviewError("artifacts must not be empty")
    if len(artifacts) > MAX_ARTIFACTS:
        raise ReviewError(f"artifacts exceed the {MAX_ARTIFACTS}-item limit")

    validated: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    aggregate_size = 0
    for index, item in enumerate(artifacts):
        if not isinstance(item, dict) or set(item) != {
            "path",
            "sha256",
            "size_bytes",
        }:
            raise ReviewError(f"artifact {index} has an invalid shape")
        relative = item["path"]
        expected_digest = item["sha256"]
        expected_size = item["size_bytes"]
        if not isinstance(relative, str):
            raise ReviewError(f"artifact {index} has an invalid path")
        canonical_relative_parts(
            relative,
            label=f"artifact {index} path",
            max_path_bytes=MAX_PATH_BYTES,
            max_component_bytes=MAX_PATH_COMPONENT_BYTES,
            max_depth=MAX_PATH_DEPTH,
        )
        if relative in seen:
            raise ReviewError(f"artifact {index} has a duplicate path")
        seen.add(relative)
        if not isinstance(expected_digest, str) or not SHA256.fullmatch(
            expected_digest
        ):
            raise ReviewError(f"artifact {relative!r} has an invalid SHA-256")
        if (
            not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size < 0
            or expected_size > MAX_ARTIFACT_BYTES
        ):
            raise ReviewError(f"artifact {relative!r} has an invalid size")
        aggregate_size += expected_size
        if aggregate_size > MAX_AGGREGATE_BYTES:
            raise ReviewError("artifacts exceed the aggregate byte limit")
        validated.append((relative, expected_digest, expected_size))

    requests = tuple(
        RootedFileDigestRequest(
            relative=relative,
            expected_size=expected_size,
            label=f"artifact {relative!r}",
            expected_sha256=expected_digest,
        )
        for relative, expected_digest, expected_size in validated
    )
    actual_digests = digest_rooted_regular_files(
        root,
        requests,
        label="evidence artifacts",
        max_files=MAX_ARTIFACTS,
        max_file_bytes=MAX_ARTIFACT_BYTES,
        max_aggregate_bytes=MAX_AGGREGATE_BYTES,
        max_path_bytes=MAX_PATH_BYTES,
        max_component_bytes=MAX_PATH_COMPONENT_BYTES,
        max_depth=MAX_PATH_DEPTH,
        max_directory_entries=MAX_DIRECTORY_ENTRIES,
    )
    for (relative, expected_digest, _expected_size), actual in zip(
        validated,
        actual_digests,
        strict=True,
    ):
        if actual.sha256 != expected_digest:
            raise ReviewError(
                f"digest {relative} expected={expected_digest} actual={actual.sha256}"
            )
    return len(validated)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    parser.add_argument("--root", default=".")
    arguments = parser.parse_args()

    try:
        verified = verify_manifest(
            Path(arguments.manifest),
            Path(arguments.root),
        )
    except (OSError, ReviewError) as error:
        print(f"evidence verification failed: {error}", file=sys.stderr)
        return 2

    print(f"VERIFIED {verified} artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
