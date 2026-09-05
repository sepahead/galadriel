"""Check the independent native source graph without granting release authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tomllib

MAX_FILE_BYTES = 16 * 1024 * 1024
ADAPTER = "galadriel-local-adapter"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), "Expected a regular source file")
        require(info.st_size <= MAX_FILE_BYTES, "Source file exceeds its byte limit")
        data = stream.read(MAX_FILE_BYTES + 1)
    require(len(data) <= MAX_FILE_BYTES, "Source file grew beyond its byte limit")
    return data


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON member")
        result[key] = value
    return result


def document(path: Path):
    return json.loads(
        read(path), object_pairs_hook=object_pairs,
        parse_constant=lambda _: require(False, "Nonfinite JSON value"),
    )


def git_packages(lock: dict) -> dict[str, str]:
    result = {}
    for package in lock["package"]:
        source = package.get("source", "")
        if source.startswith("git+"):
            require(package["name"] not in result, "Duplicate Git package name")
            result[package["name"]] = source
    return result


def sdk_source(profile: dict) -> str:
    sdk = profile["sdk"]
    require(set(sdk) == {"name", "version", "repository", "revision"}, "SDK field roster")
    require(sdk["name"] == "ncp-local" and sdk["version"] == "1.0.0", "SDK package identity")
    require(sdk["repository"] == "https://github.com/sepahead/NCP", "SDK repository")
    require(re.fullmatch(r"[0-9a-f]{40}", sdk["revision"]) is not None, "SDK revision")
    return f"git+{sdk['repository']}?rev={sdk['revision']}#{sdk['revision']}"


def check_manifests(profile, root, manifest, root_lock, native_lock, policy):
    require(set(profile) == {
        "schema", "scope", "release_authority", "package_version", "sdk",
        "root_members", "root_git_pins", "files",
    }, "Profile field roster")
    require(profile["schema"] == "galadriel.local-adapter-source.v1", "Source profile schema")
    require(profile["scope"] == "experimental_source_only", "Source scope")
    require(profile["release_authority"] is False, "Source checks cannot authorize release")
    require(profile["package_version"] == "0.9.0", "Experimental package version")
    require(root["workspace"]["members"] == profile["root_members"], "Root member roster")
    require(len(profile["root_members"]) == 7, "Original seven-package root is required")
    require(f"crates/{ADAPTER}" in root["workspace"]["exclude"], "Adapter must be excluded")
    require(git_packages(root_lock) == profile["root_git_pins"], "Historical root Git pins")
    require(not any(p["name"] in {ADAPTER, "ncp-local"} for p in root_lock["package"]), "Native dependency entered root lock")
    require(manifest["package"]["name"] == ADAPTER, "Adapter package name")
    require(manifest["package"]["version"] == profile["package_version"], "Adapter version")
    require(manifest["package"]["publish"] is False, "Crate publication is forbidden")
    require(manifest["workspace"]["resolver"] == "2", "Independent workspace required")
    require(manifest["lints"]["rust"]["unsafe_code"] == "forbid", "Unsafe code policy")
    require(manifest["features"]["default"] == [], "Native feature must remain optional")
    require(manifest["features"] == {"default": [], "ncp-local": ["dep:ncp-local", "dep:serde", "dep:serde_json"]}, "Unexpected adapter feature surface")
    require(manifest["dependencies"]["galadriel-core"] == {"version": "=0.9.0", "path": "../galadriel-core"}, "Existing core dependency required")
    sdk = profile["sdk"]
    expected = {"version": "=1.0.0", "git": sdk["repository"], "rev": sdk["revision"], "optional": True}
    require(manifest["dependencies"]["ncp-local"] == expected, "Native SDK must use the exact public Git pin; sibling construction is not admissible")
    require(git_packages(native_lock) == {"ncp-local": sdk_source(profile)}, "Native lock Git source")
    require(policy["advisories"].get("ignore") == [], "Native policy cannot inherit unrelated exceptions")
    require(policy["sources"]["unknown-git"] == "deny", "Unknown Git source policy")
    require(policy["sources"]["allow-git"] == [sdk["repository"]], "Native Git allowlist")


def check_graph(metadata: dict, profile: dict, component: Path, *, native: bool):
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    require(len(packages) == len(metadata["packages"]), "Duplicate package identity")
    require(len(nodes) == len(metadata["resolve"]["nodes"]), "Duplicate resolve node")
    root = metadata["resolve"]["root"]
    require(metadata["workspace_members"] == [root], "Standalone workspace graph")
    require(packages[root]["name"] == ADAPTER, "Graph root identity")
    require(packages[root]["version"] == profile["package_version"], "Graph root version")
    require(Path(packages[root]["manifest_path"]) == component / "Cargo.toml", "Graph manifest identity")
    require(nodes[root]["features"] == (["ncp-local"] if native else []), "Exact adapter feature selection")
    todo, reached = [root], set()
    while todo:
        current = todo.pop()
        if current in reached:
            continue
        require(current in packages and current in nodes, "Incomplete dependency graph")
        reached.add(current)
        require(len(reached) <= 128, "Native graph package bound")
        todo.extend(dep["pkg"] for dep in nodes[current]["deps"])
    names = {packages[key]["name"] for key in reached}
    forbidden = {name for name in names if name.startswith(("pid-", "zenoh", "tokio", "ncp-core", "ncp-zenoh"))}
    require(not forbidden, "Native graph acquired an unrelated runtime dependency")
    require(("ncp-local" in names) is native, "Native feature graph mismatch")
    require("galadriel-core" in names, "Actual core is absent")
    for key in reached:
        package = packages[key]
        if package["name"] == "ncp-local":
            require(package["source"] == sdk_source(profile), "Native package source identity")
            require(package["version"] == profile["sdk"]["version"], "Resolved SDK version")
            require(nodes[key]["features"] == [], "Unexpected SDK feature selection")
        if package["name"] == "galadriel-core":
            require(package["source"] is None, "Core must be repository-owned source")
            require(package["version"] == "0.9.0", "Core package version")
            require(Path(package["manifest_path"]) == component.parent / "galadriel-core/Cargo.toml", "Exact core manifest path")
            require(nodes[key]["features"] == [], "Unexpected core feature selection")
        if package["source"] is None:
            expected = {ADAPTER: component / "Cargo.toml", "galadriel-core": component.parent / "galadriel-core/Cargo.toml"}
            require(package["name"] in expected, "Unlisted local dependency")
            require(Path(package["manifest_path"]) == expected[package["name"]], "Local core source path")
            require(package["version"] == "0.9.0", "Local package version")
        elif package["source"].startswith("git+"):
            require(package["name"] == "ncp-local" and package["source"] == sdk_source(profile), "Resolved SDK source")
        else:
            require(package["source"] == "registry+https://github.com/rust-lang/crates.io-index", "Unlisted registry source")
    return len(reached)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pure-metadata", type=Path, required=True)
    parser.add_argument("--native-metadata", type=Path, required=True)
    args = parser.parse_args()
    component = Path(__file__).resolve().parent
    root = component.parents[1]
    profile = document(component / "source-profile.json")
    toml = lambda p: tomllib.loads(read(p).decode("utf-8"))
    check_manifests(profile, toml(root / "Cargo.toml"), toml(component / "Cargo.toml"), toml(root / "Cargo.lock"), toml(component / "Cargo.lock"), toml(component / "deny.toml"))
    actual = set()
    for directory, children, files in os.walk(component, followlinks=False):
        children[:] = [name for name in children if name not in {"target", "__pycache__"}]
        require(not any((Path(directory) / name).is_symlink() for name in children), "Source directory symlink")
        actual.update(str((Path(directory) / name).relative_to(component)) for name in files)
    require(len(profile["files"]) == len(set(profile["files"])), "Duplicate source roster path")
    require(actual == set(profile["files"]), "Source file roster mismatch")
    hashes = {name: hashlib.sha256(read(component / name)).hexdigest() for name in sorted(actual)}
    counts = {"pure": check_graph(document(args.pure_metadata), profile, component, native=False), "native": check_graph(document(args.native_metadata), profile, component, native=True)}
    print(json.dumps({"status": "pass", "scope": profile["scope"], "release_authority": False, "source_sha256": hashes, "graph_counts": counts}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
