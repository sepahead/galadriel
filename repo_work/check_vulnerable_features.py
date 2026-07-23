#!/usr/bin/env python3
"""Assert the audited Zenoh compression advisory path remains disabled."""

from __future__ import annotations

import datetime as dt
import sys
from typing import Any

from check_public_api import bounded_diagnostic, release_tool_environment
from common import ReviewError, loads_json
from release_assurance import run_bounded_host_command


EXPIRY = dt.date(2026, 10, 1)
PACKAGE = "zenoh-transport"
PACKAGE_VERSION = "1.9.0"
PACKAGE_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
FORBIDDEN_FEATURE = "transport_compression"
CARGO_METADATA_COMMAND: tuple[str, ...] = (
    "cargo",
    "metadata",
    "--format-version",
    "1",
    "--locked",
    "--all-features",
    "--offline",
)
EXPECTED_FEATURES = frozenset(
    {
        "shared-memory",
        "transport_tcp",
        "transport_tls",
        "transport_udp",
        "zenoh-shm",
    }
)
METADATA_TIMEOUT_SECONDS = 120
MAX_METADATA_STDOUT_BYTES = 8 * 1024 * 1024
MAX_METADATA_STDERR_BYTES = 1024 * 1024


def validate_metadata(document: Any) -> None:
    """Fail unless resolved Zenoh transport nodes omit compression."""

    if not isinstance(document, dict):
        raise ValueError("Cargo metadata root is not an object")
    packages = document.get("packages")
    resolve = document.get("resolve")
    if not isinstance(packages, list) or not isinstance(resolve, dict):
        raise ValueError("Cargo metadata lacks packages or a resolved graph")
    nodes = resolve.get("nodes")
    if not isinstance(nodes, list):
        raise ValueError("Cargo metadata lacks resolved nodes")

    package_names: dict[str, str] = {}
    target_packages: list[dict[str, Any]] = []
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("Cargo metadata contains a malformed package")
        package_id = package.get("id")
        name = package.get("name")
        if (
            not isinstance(package_id, str)
            or not package_id
            or not isinstance(name, str)
        ):
            raise ValueError("Cargo metadata contains an invalid package identity")
        if package_id in package_names:
            raise ValueError("Cargo metadata contains a duplicate package identity")
        package_names[package_id] = name
        if name == PACKAGE:
            target_packages.append(package)

    if len(target_packages) != 1:
        raise ValueError(f"Cargo metadata must resolve exactly one {PACKAGE} package")
    target = target_packages[0]
    if (
        target.get("version") != PACKAGE_VERSION
        or target.get("source") != PACKAGE_SOURCE
    ):
        raise ValueError(f"Cargo metadata resolves an unexpected {PACKAGE} identity")
    target_id = target["id"]

    observed_node_ids: set[str] = set()
    target_features: list[str] | None = None
    for node in nodes:
        if not isinstance(node, dict):
            raise ValueError("Cargo metadata contains a malformed resolved node")
        package_id = node.get("id")
        features = node.get("features")
        if (
            not isinstance(package_id, str)
            or not isinstance(features, list)
            or any(not isinstance(feature, str) for feature in features)
        ):
            raise ValueError("Cargo metadata contains an invalid resolved node")
        if package_id not in package_names:
            raise ValueError("Cargo metadata resolves an unknown package identity")
        if package_id in observed_node_ids:
            raise ValueError("Cargo metadata contains a duplicate resolved node")
        observed_node_ids.add(package_id)
        if len(features) != len(set(features)):
            raise ValueError("Cargo metadata contains duplicate resolved features")
        if package_id == target_id:
            target_features = features
            if FORBIDDEN_FEATURE in features:
                raise ValueError(
                    f"RUSTSEC-2026-0041 mitigation invalid: {FORBIDDEN_FEATURE} is enabled"
                )

    if target_features is None:
        raise ValueError(f"Cargo metadata omits a resolved {PACKAGE} node")
    if set(target_features) != EXPECTED_FEATURES:
        raise ValueError(f"Cargo metadata resolves unexpected {PACKAGE} features")


def main() -> int:
    if dt.datetime.now(dt.timezone.utc).date() > EXPIRY:
        print(
            "RUSTSEC-2026-0041 exception expired; upgrade the dependency or renew with review",
            file=sys.stderr,
        )
        return 2
    try:
        process = run_bounded_host_command(
            CARGO_METADATA_COMMAND,
            context="vulnerable-feature Cargo metadata",
            environment=release_tool_environment(),
            max_stdout_bytes=MAX_METADATA_STDOUT_BYTES,
            max_stderr_bytes=MAX_METADATA_STDERR_BYTES,
            timeout_seconds=METADATA_TIMEOUT_SECONDS,
        )
        if process.returncode != 0:
            raise ReviewError(
                "Cargo metadata failed with "
                f"{process.returncode}: {bounded_diagnostic(process.stderr)}"
            )
        document = loads_json(process.stdout)
        validate_metadata(document)
    except (ReviewError, ValueError) as error:
        print(f"vulnerable feature assertion failed: {error}", file=sys.stderr)
        return 2
    print("vulnerable feature assertion verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
