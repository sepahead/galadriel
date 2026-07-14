#!/usr/bin/env python3
"""Verify strict, root-contained artifact identities in an evidence manifest."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

from common import ReviewError, contained_path, load_json


SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    parser.add_argument("--root", default=".")
    arguments = parser.parse_args()
    root = Path(arguments.root).resolve()

    try:
        manifest = load_json(Path(arguments.manifest))
        if not isinstance(manifest, dict) or set(manifest) != {"schema", "artifacts"}:
            raise ReviewError("manifest must contain exactly schema and artifacts")
        if manifest["schema"] != "galadriel.evidence-manifest.v1":
            raise ReviewError("unsupported evidence-manifest schema")
        if not isinstance(manifest["artifacts"], list):
            raise ReviewError("artifacts must be an array")
        if not manifest["artifacts"]:
            raise ReviewError("artifacts must not be empty")

        seen: set[str] = set()
        for index, item in enumerate(manifest["artifacts"]):
            if not isinstance(item, dict) or set(item) != {"path", "sha256", "size_bytes"}:
                raise ReviewError(f"artifact {index} has an invalid shape")
            relative = item["path"]
            expected_digest = item["sha256"]
            expected_size = item["size_bytes"]
            if not isinstance(relative, str) or relative in seen:
                raise ReviewError(f"artifact {index} has a duplicate or invalid path")
            seen.add(relative)
            if not isinstance(expected_digest, str) or not SHA256.fullmatch(expected_digest):
                raise ReviewError(f"artifact {relative!r} has an invalid SHA-256")
            if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 0:
                raise ReviewError(f"artifact {relative!r} has an invalid size")

            path = contained_path(root, relative)
            if not path.is_file():
                raise ReviewError(f"artifact is not a regular file: {relative}")
            actual_size = path.stat().st_size
            if actual_size != expected_size:
                raise ReviewError(
                    f"size {relative} expected={expected_size} actual={actual_size}"
                )
            actual_digest = sha256(path)
            if actual_digest != expected_digest:
                raise ReviewError(
                    f"digest {relative} expected={expected_digest} actual={actual_digest}"
                )
    except (OSError, ReviewError) as error:
        print(f"evidence verification failed: {error}", file=sys.stderr)
        return 2

    print(f"VERIFIED {len(manifest['artifacts'])} artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
