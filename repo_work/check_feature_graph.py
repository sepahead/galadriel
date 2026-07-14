#!/usr/bin/env python3
"""Prove the Galadriel CLI's optional dependency boundaries from Cargo's graph."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from common import ReviewError


@dataclass(frozen=True)
class Profile:
    """One exact feature selection and its dependency contract."""

    name: str
    cargo_arguments: tuple[str, ...]
    required: frozenset[str]
    forbidden: frozenset[str]


PROFILES = (
    Profile(
        "pure",
        (),
        frozenset({"galadriel-cli", "galadriel-core", "galadriel-sim"}),
        frozenset(
            {"galadriel-pid", "pid-core", "galadriel-ncp", "ncp-core", "ncp-zenoh", "zenoh", "tokio"}
        ),
    ),
    Profile(
        "pid",
        ("--features", "pid"),
        frozenset({"galadriel-pid", "pid-core"}),
        frozenset({"galadriel-ncp", "ncp-core", "ncp-zenoh", "zenoh", "tokio"}),
    ),
    Profile(
        "ncp",
        ("--features", "ncp"),
        frozenset({"galadriel-ncp", "ncp-core"}),
        frozenset({"galadriel-pid", "pid-core", "ncp-zenoh", "zenoh", "tokio"}),
    ),
    Profile(
        "ncp-live",
        ("--features", "ncp-live"),
        frozenset({"galadriel-ncp", "ncp-core", "ncp-zenoh", "zenoh", "tokio"}),
        frozenset({"galadriel-pid", "pid-core"}),
    ),
    Profile(
        "all",
        ("--all-features",),
        frozenset(
            {
                "galadriel-pid",
                "pid-core",
                "galadriel-ncp",
                "ncp-core",
                "ncp-zenoh",
                "zenoh",
                "tokio",
            }
        ),
        frozenset(),
    ),
)


def packages(repo: Path, profile: Profile) -> set[str]:
    """Return package names selected by Cargo for one CLI profile."""

    command = [
        "cargo",
        "tree",
        "-p",
        "galadriel-cli",
        "--no-default-features",
        *profile.cargo_arguments,
        "-e",
        "normal",
        "--locked",
        "--prefix",
        "none",
        "--format",
        "{p}",
    ]
    process = subprocess.run(
        command,
        cwd=repo,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if process.returncode != 0:
        raise ReviewError(
            f"feature graph {profile.name!r} failed: {process.stderr.strip()}"
        )
    selected: set[str] = set()
    for line in process.stdout.splitlines():
        fields = line.split()
        if fields:
            selected.add(fields[0])
    return selected


def validate_manifest(repo: Path) -> None:
    """Reject feature aliases whose semantics drift from the audited contract."""

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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    arguments = parser.parse_args()
    repo = Path(arguments.repo).resolve()
    try:
        validate_manifest(repo)
        summaries: dict[str, dict[str, list[str] | int]] = {}
        for profile in PROFILES:
            selected = packages(repo, profile)
            missing = sorted(profile.required - selected)
            forbidden = sorted(profile.forbidden & selected)
            if missing or forbidden:
                raise ReviewError(
                    f"feature graph {profile.name!r}: missing={missing}, forbidden={forbidden}"
                )
            summaries[profile.name] = {
                "package_count": len(selected),
                "required": sorted(profile.required),
                "forbidden": sorted(profile.forbidden),
            }
    except (OSError, ReviewError, tomllib.TOMLDecodeError) as error:
        print(f"feature graph check failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(summaries, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
