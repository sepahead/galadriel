#!/usr/bin/env python3
"""Prove the Galadriel CLI's optional dependency boundaries from Cargo's graph."""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from common import ReviewError


PID_SOURCE = (
    "git+https://github.com/sepahead/pid-rs?"
    "rev=1cd2424f7967e1752dcc8e53859e8fdad3566f51"
    "#1cd2424f7967e1752dcc8e53859e8fdad3566f51"
)
NCP_SOURCE = (
    "git+https://github.com/sepahead/NCP?"
    "rev=2f5bd586d4bb20c90362bb6f5698b7f64057ba4e"
    "#2f5bd586d4bb20c90362bb6f5698b7f64057ba4e"
)
NCP_PIN = "2f5bd586d4bb20c90362bb6f5698b7f64057ba4e"
NCP_CONSUMER_TOOLING_MIN_COMMIT = "205384508d619923e05aef192bedaeb57cf665fc"
MAX_NCP_CONSUMER_BYTES = 16 * 1024
EXPECTED_NCP_CONSUMER_ROWS = (
    ("cargo_rev", "Cargo.toml", "v0.8.0", NCP_PIN),
    ("cargo_lock_rev", "Cargo.lock", "v0.8.0", NCP_PIN),
)
ZENOH_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"

EXPECTED_UPSTREAM_MANIFESTS = {
    "pid-core": {
        "version": "1.0.0",
        "source": PID_SOURCE,
        "features": {
            "default": frozenset(),
            "experimental-all": frozenset(
                {
                    "experimental-continuous",
                    "experimental-heuristics",
                    "experimental-hierarchy",
                    "experimental-hyperbolic",
                    "experimental-pipelines",
                    "research-mixed-dimension-pid3",
                }
            ),
            "experimental-continuous": frozenset(),
            "experimental-heuristics": frozenset({"experimental-continuous"}),
            "experimental-hierarchy": frozenset({"experimental-continuous"}),
            "experimental-hyperbolic": frozenset({"experimental-continuous"}),
            "experimental-pipelines": frozenset(
                {
                    "experimental-continuous",
                    "research-mixed-dimension-pid3",
                }
            ),
            "parallel": frozenset({"dep:rayon"}),
            "research-mixed-dimension-pid3": frozenset({"experimental-continuous"}),
        },
    },
    "pid-runlog": {
        "version": "1.0.0",
        "source": PID_SOURCE,
        "features": {},
    },
    "ncp-core": {
        "version": "0.8.0",
        "source": NCP_SOURCE,
        "features": {
            "default": frozenset(),
            "schema": frozenset({"dep:schemars"}),
            "ts": frozenset({"dep:ts-rs"}),
        },
    },
    "ncp-zenoh": {
        "version": "0.8.0",
        "source": NCP_SOURCE,
        "features": {"default": frozenset()},
    },
    "zenoh": {
        "version": "1.9.0",
        "source": ZENOH_SOURCE,
        "features": {},
    },
}
EXACT_UPSTREAM_FEATURE_MAPS = frozenset(
    {"pid-core", "pid-runlog", "ncp-core", "ncp-zenoh"}
)
EXPECTED_DEFAULT_MEMBERS = [
    "crates/galadriel-core",
    "crates/galadriel-sim",
    "crates/galadriel-cli",
]

PID_RESOLVED_FEATURES = frozenset(
    {
        "default",
        "experimental-continuous",
        "experimental-pipelines",
        "research-mixed-dimension-pid3",
    }
)
NCP_RESOLVED_FEATURES = frozenset({"default"})
ZENOH_RESOLVED_FEATURES = frozenset(
    {"shared-memory", "transport_tcp", "transport_tls", "transport_udp", "zenoh-shm"}
)
TOKIO_RESOLVED_FEATURES = frozenset(
    {
        "bytes",
        "default",
        "fs",
        "io-util",
        "libc",
        "macros",
        "mio",
        "net",
        "rt",
        "rt-multi-thread",
        "signal",
        "signal-hook-registry",
        "socket2",
        "sync",
        "time",
        "tokio-macros",
    }
)


@dataclass(frozen=True)
class Profile:
    """One exact feature selection and its dependency contract."""

    name: str
    cargo_arguments: tuple[str, ...]
    required: frozenset[str]
    forbidden: frozenset[str]
    exact_features: tuple[tuple[str, frozenset[str]], ...] = ()
    package: str = "galadriel-cli"


PROFILES = (
    Profile(
        "pure",
        (),
        frozenset({"galadriel-cli", "galadriel-core", "galadriel-sim"}),
        frozenset(
            {
                "galadriel-pid",
                "pid-core",
                "pid-runlog",
                "galadriel-ncp",
                "ncp-core",
                "ncp-zenoh",
                "zenoh",
                "tokio",
            }
        ),
    ),
    Profile(
        "pid",
        ("--features", "pid"),
        frozenset({"galadriel-pid", "pid-core", "pid-runlog"}),
        frozenset({"galadriel-ncp", "ncp-core", "ncp-zenoh", "zenoh", "tokio"}),
        (("pid-core", PID_RESOLVED_FEATURES),),
    ),
    Profile(
        "ncp",
        ("--features", "ncp"),
        frozenset({"galadriel-ncp", "ncp-core"}),
        frozenset(
            {
                "galadriel-pid",
                "pid-core",
                "pid-runlog",
                "ncp-zenoh",
                "zenoh",
                "tokio",
            }
        ),
        (("ncp-core", NCP_RESOLVED_FEATURES),),
    ),
    Profile(
        "ncp-live",
        ("--features", "ncp-live"),
        frozenset({"galadriel-ncp", "ncp-core", "ncp-zenoh", "zenoh", "tokio"}),
        frozenset({"galadriel-pid", "pid-core", "pid-runlog"}),
        (
            ("ncp-core", NCP_RESOLVED_FEATURES),
            ("ncp-zenoh", NCP_RESOLVED_FEATURES),
            ("zenoh", ZENOH_RESOLVED_FEATURES),
            ("tokio", TOKIO_RESOLVED_FEATURES),
        ),
    ),
    Profile(
        "all",
        ("--all-features",),
        frozenset(
            {
                "galadriel-pid",
                "pid-core",
                "pid-runlog",
                "galadriel-ncp",
                "ncp-core",
                "ncp-zenoh",
                "zenoh",
                "tokio",
            }
        ),
        frozenset(),
        (
            ("pid-core", PID_RESOLVED_FEATURES),
            ("ncp-core", NCP_RESOLVED_FEATURES),
            ("ncp-zenoh", NCP_RESOLVED_FEATURES),
            ("zenoh", ZENOH_RESOLVED_FEATURES),
            ("tokio", TOKIO_RESOLVED_FEATURES),
        ),
    ),
    Profile(
        "eval-member",
        (),
        frozenset(
            {
                "galadriel-eval",
                "galadriel-core",
                "galadriel-sim",
                "galadriel-pid",
                "pid-core",
                "pid-runlog",
                "galadriel-ncp",
                "ncp-core",
            }
        ),
        frozenset({"ncp-zenoh", "zenoh", "tokio"}),
        (
            ("pid-core", PID_RESOLVED_FEATURES),
            ("ncp-core", NCP_RESOLVED_FEATURES),
        ),
        "galadriel-eval",
    ),
    Profile(
        "justify-member",
        (),
        frozenset({"galadriel-justify", "galadriel-core", "pid-core", "pid-runlog"}),
        frozenset(
            {
                "galadriel-pid",
                "galadriel-ncp",
                "ncp-core",
                "ncp-zenoh",
                "zenoh",
                "tokio",
            }
        ),
        (("pid-core", PID_RESOLVED_FEATURES),),
        "galadriel-justify",
    ),
)


def parse_graph_output(profile: Profile, output: str) -> dict[str, frozenset[str]]:
    """Parse Cargo's package and unified-feature rows without trusting display order."""

    selected: dict[str, frozenset[str]] = {}
    exact_packages = {name for name, _features in profile.exact_features}
    for line in output.splitlines():
        if "\x1b" in line:
            raise ReviewError(
                f"feature graph {profile.name!r} emitted terminal control bytes"
            )
        package_text, separator, feature_text = line.partition("|")
        fields = package_text.split()
        if not separator or not fields:
            raise ReviewError(
                f"feature graph {profile.name!r} emitted a malformed row: "
                f"{line[:200]!r}"
            )
        name = fields[0]
        if feature_text.endswith(" (*)"):
            feature_text = feature_text[:-4]
        features = frozenset(filter(None, feature_text.split(",")))
        previous = selected.setdefault(name, features)
        if previous != features and name in exact_packages:
            raise ReviewError(
                f"feature graph {profile.name!r} reported inconsistent features for {name}"
            )
        selected[name] = previous | features
    return selected


def package_graph(repo: Path, profile: Profile) -> dict[str, frozenset[str]]:
    """Return packages and resolved features selected for one exact CLI profile."""

    environment = dict(os.environ)
    environment["CARGO_TERM_COLOR"] = "never"
    command = [
        "cargo",
        "tree",
        "-p",
        profile.package,
        "--no-default-features",
        *profile.cargo_arguments,
        "-e",
        "normal",
        "--locked",
        "--prefix",
        "none",
        "--format",
        "{p}|{f}",
    ]
    process = subprocess.run(
        command,
        cwd=repo,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        env=environment,
    )
    if process.returncode != 0:
        raise ReviewError(
            f"feature graph {profile.name!r} failed: {process.stderr.strip()}"
        )
    return parse_graph_output(profile, process.stdout)


def validate_profile_graph(profile: Profile, graph: dict[str, frozenset[str]]) -> None:
    """Enforce both package isolation and exact security-relevant feature sets."""

    selected = set(graph)
    missing = sorted(profile.required - selected)
    forbidden = sorted(profile.forbidden & selected)
    if missing or forbidden:
        raise ReviewError(
            f"feature graph {profile.name!r}: missing={missing}, forbidden={forbidden}"
        )
    for package, expected in profile.exact_features:
        actual = graph.get(package)
        if actual != expected:
            raise ReviewError(
                f"feature graph {profile.name!r} resolved {package} features "
                f"as {sorted(actual or ())}, expected {sorted(expected)}"
            )


def validate_upstream_package_records(packages: object) -> None:
    """Bind documented upstream feature aliases to the locked package manifests."""

    if not isinstance(packages, list):
        raise ReviewError("cargo metadata packages must be a list")
    by_name: dict[str, list[dict[str, object]]] = {}
    for package in packages:
        if isinstance(package, dict) and isinstance(package.get("name"), str):
            by_name.setdefault(package["name"], []).append(package)
    for name, expected in EXPECTED_UPSTREAM_MANIFESTS.items():
        records = by_name.get(name, [])
        if len(records) != 1:
            raise ReviewError(
                f"cargo metadata must contain exactly one locked {name} package"
            )
        package = records[0]
        if package.get("version") != expected["version"]:
            raise ReviewError(
                f"locked {name} version differs from the audited contract"
            )
        if package.get("source") != expected["source"]:
            raise ReviewError(f"locked {name} source differs from the audited contract")
        declared = package.get("features")
        if not isinstance(declared, dict):
            raise ReviewError(f"locked {name} feature manifest must be an object")
        if name in EXACT_UPSTREAM_FEATURE_MAPS and set(declared) != set(
            expected["features"]
        ):
            raise ReviewError(
                f"locked {name} feature aliases differ from the audited contract"
            )
        for feature, expected_members in expected["features"].items():
            members = declared.get(feature)
            if not isinstance(members, list) or not all(
                isinstance(member, str) for member in members
            ):
                raise ReviewError(
                    f"locked {name} feature {feature} must be a string list"
                )
            if frozenset(members) != expected_members:
                raise ReviewError(
                    f"locked {name} feature {feature} differs from the audited contract"
                )


def validate_upstream_manifests(repo: Path) -> None:
    """Read dependency feature declarations from Cargo's locked metadata."""

    process = subprocess.run(
        [
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--all-features",
        ],
        cwd=repo,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if process.returncode != 0:
        raise ReviewError(f"cargo metadata failed: {process.stderr.strip()}")
    try:
        metadata = json.loads(process.stdout)
    except json.JSONDecodeError as error:
        raise ReviewError(f"cargo metadata returned invalid JSON: {error}") from error
    if not isinstance(metadata, dict):
        raise ReviewError("cargo metadata root must be an object")
    validate_upstream_package_records(metadata.get("packages"))


def validate_manifest(repo: Path) -> None:
    """Reject feature aliases whose semantics drift from the audited contract."""

    with (repo / "Cargo.toml").open("rb") as handle:
        workspace_manifest = tomllib.load(handle)
    validate_workspace_manifest(workspace_manifest)
    with (repo / "crates/galadriel-cli/Cargo.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    expected = {
        "default": [],
        "pid": ["dep:galadriel-pid"],
        "ncp": ["dep:galadriel-ncp"],
        "ncp-live": ["ncp", "galadriel-ncp/zenoh", "dep:tokio"],
    }
    if manifest.get("features") != expected:
        raise ReviewError(
            "galadriel-cli feature aliases differ from the audited contract: "
            + json.dumps(manifest.get("features"), sort_keys=True)
        )


def validate_workspace_manifest(manifest: object) -> None:
    """Bind the default command to the three documented workspace members."""

    if not isinstance(manifest, dict) or not isinstance(
        manifest.get("workspace"), dict
    ):
        raise ReviewError("root Cargo manifest must contain a workspace table")
    default_members = manifest["workspace"].get("default-members")
    if default_members != EXPECTED_DEFAULT_MEMBERS:
        raise ReviewError(
            "workspace default-members differ from the audited contract: "
            + json.dumps(default_members, sort_keys=True)
        )


def parse_ncp_consumer_descriptor(document: str) -> tuple[tuple[str, ...], ...]:
    """Reject empty, unknown, legacy, or drifted NCP consumer declarations."""

    rows: list[tuple[str, ...]] = []
    for line_number, line in enumerate(document.splitlines(), start=1):
        payload = line.split("#", 1)[0].strip()
        if not payload:
            continue
        fields = tuple(payload.split())
        if len(fields) != 4 or fields[0] not in {"cargo_rev", "cargo_lock_rev"}:
            raise ReviewError(
                f".ncp-consumer line {line_number} is unknown or not revision-bound"
            )
        rows.append(fields)
    result = tuple(rows)
    if result != EXPECTED_NCP_CONSUMER_ROWS:
        raise ReviewError(
            ".ncp-consumer must contain the exact two recognized revision rows"
        )
    return result


def validate_ncp_consumer_descriptor(repo: Path) -> tuple[tuple[str, ...], ...]:
    """Bind the cross-consumer descriptor to the locally qualified dependency pin."""

    descriptor = repo / ".ncp-consumer"
    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    if no_follow is None or non_block is None:
        raise ReviewError("bounded no-follow .ncp-consumer reads are unavailable")
    flags = os.O_RDONLY | no_follow | non_block | getattr(os, "O_CLOEXEC", 0)
    try:
        file_descriptor = os.open(descriptor, flags)
    except OSError as error:
        raise ReviewError(".ncp-consumer is missing or unsafe") from error
    try:
        metadata = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > MAX_NCP_CONSUMER_BYTES
        ):
            raise ReviewError(".ncp-consumer is not a bounded regular file")
        payload = bytearray()
        while len(payload) <= MAX_NCP_CONSUMER_BYTES:
            chunk = os.read(
                file_descriptor,
                min(8192, MAX_NCP_CONSUMER_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) != metadata.st_size or len(payload) > MAX_NCP_CONSUMER_BYTES:
            raise ReviewError(".ncp-consumer changed while being read")
    finally:
        os.close(file_descriptor)
    rows = parse_ncp_consumer_descriptor(bytes(payload).decode("utf-8", "strict"))
    for _kind, relative, _tag, _revision in EXPECTED_NCP_CONSUMER_ROWS:
        declared = repo / relative
        if not declared.is_file() or declared.is_symlink():
            raise ReviewError(
                f".ncp-consumer declared path is missing or unsafe: {relative}"
            )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    arguments = parser.parse_args()
    repo = Path(arguments.repo).resolve()
    try:
        validate_manifest(repo)
        consumer_rows = validate_ncp_consumer_descriptor(repo)
        validate_upstream_manifests(repo)
        summaries: dict[str, dict[str, list[str] | int]] = {}
        for profile in PROFILES:
            graph = package_graph(repo, profile)
            validate_profile_graph(profile, graph)
            selected = set(graph)
            summaries[profile.name] = {
                "package_count": len(selected),
                "required": sorted(profile.required),
                "forbidden": sorted(profile.forbidden),
            }
    except (OSError, ReviewError, UnicodeError, ValueError) as error:
        print(f"feature graph check failed: {error}", file=sys.stderr)
        return 2
    report = {
        "schema": "galadriel.feature-graph-report.v1",
        "coordination": {
            "ncp_consumer_tooling_min_commit": NCP_CONSUMER_TOOLING_MIN_COMMIT,
            "ncp_dependency_pin": NCP_PIN,
            "ncp_consumer_rows": [
                {
                    "kind": kind,
                    "path": path,
                    "tag": tag,
                    "revision": revision,
                }
                for kind, path, tag, revision in consumer_rows
            ],
        },
        "profiles": summaries,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
