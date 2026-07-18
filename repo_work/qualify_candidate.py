#!/usr/bin/env python3
"""Qualify one clean signed Galadriel commit in an isolated worktree.

The runner never edits the candidate checkout. It creates a detached temporary
worktree at the exact subject commit, uses an isolated Cargo target directory,
retains complete per-command logs, inventories every tracked blob, emits
deterministic source/SBOM artifacts, and records failures instead of replacing
them with a pass/fail summary.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
import platform
import signal
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common import ReviewError, canonical_json, git, load_json, loads_json
from release_assurance import (
    assert_tracked_allowed_signer,
    derive_external_allowed_signers,
    evaluate_acceptance,
    sign_file,
    validate_evidence_config_binding,
    validate_mutation_evidence,
    verify_artifact_manifest,
    verify_signature,
)


SCHEMA = "galadriel.candidate-qualification.v2"
VERSION = "0.9.0"
ALLOWED_SIGNERS = "release/0.9.0/audit/ALLOWED_SIGNERS"


@dataclass(frozen=True)
class CommandSpec:
    """One shell-free qualification command."""

    name: str
    argv: tuple[str, ...]
    cwd: str = "."
    environment: tuple[tuple[str, str], ...] = ()
    timeout_seconds: int = 3_600


BASE_COMMANDS = (
    CommandSpec("git-fsck-strict", ("git", "fsck", "--strict", "--no-progress")),
    CommandSpec(
        "release-tool-tests",
        (
            "python3",
            "-m",
            "unittest",
            "-v",
            "scripts.tests.test_release_audit",
            "repo_work.tests.test_review_tools",
            "repo_work.tests.test_task_dispositions",
            "repo_work.tests.test_release_assurance",
        ),
    ),
    CommandSpec(
        "secure-deployment-check",
        ("python3", "scripts/secure_deployment.py", "check"),
    ),
    CommandSpec(
        "task-dispositions-verify",
        ("python3", "repo_work/build_task_dispositions.py", "verify"),
    ),
    CommandSpec(
        "release-audit-verify", ("python3", "scripts/release_audit.py", "verify")
    ),
    CommandSpec("format", ("cargo", "fmt", "--all", "--", "--check")),
    CommandSpec(
        "feature-graph-contract", ("python3", "repo_work/check_feature_graph.py")
    ),
    CommandSpec(
        "cli-pure-feature-graph",
        (
            "cargo",
            "check",
            "-p",
            "galadriel-cli",
            "--no-default-features",
            "--locked",
        ),
    ),
    CommandSpec(
        "cli-pid-feature-graph",
        (
            "cargo",
            "check",
            "-p",
            "galadriel-cli",
            "--no-default-features",
            "--features",
            "pid",
            "--locked",
        ),
    ),
    CommandSpec(
        "cli-ncp-feature-graph",
        (
            "cargo",
            "check",
            "-p",
            "galadriel-cli",
            "--no-default-features",
            "--features",
            "ncp",
            "--locked",
        ),
    ),
    CommandSpec(
        "cli-ncp-live-feature-graph",
        (
            "cargo",
            "check",
            "-p",
            "galadriel-cli",
            "--no-default-features",
            "--features",
            "ncp-live",
            "--locked",
        ),
    ),
    CommandSpec(
        "clippy-all-targets-features",
        (
            "cargo",
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--",
            "-D",
            "warnings",
        ),
    ),
    CommandSpec(
        "clippy-production-no-unwrap-expect-panic",
        (
            "cargo",
            "clippy",
            "--workspace",
            "--all-features",
            "--lib",
            "--bins",
            "--locked",
            "--",
            "-D",
            "clippy::unwrap_used",
            "-D",
            "clippy::expect_used",
            "-D",
            "clippy::panic",
        ),
    ),
    CommandSpec(
        "tests-all-features",
        ("cargo", "test", "--workspace", "--all-features", "--locked"),
    ),
    CommandSpec(
        "docs-all-features",
        (
            "cargo",
            "doc",
            "--workspace",
            "--all-features",
            "--no-deps",
            "--locked",
        ),
        environment=(("RUSTDOCFLAGS", "-D warnings"),),
    ),
    CommandSpec(
        "pure-core-no-default",
        (
            "cargo",
            "test",
            "-p",
            "galadriel-core",
            "--no-default-features",
            "--locked",
        ),
    ),
    CommandSpec(
        "core-release-tests",
        ("cargo", "test", "-p", "galadriel-core", "--release", "--locked"),
    ),
    CommandSpec(
        "pid-release-tests",
        ("cargo", "test", "-p", "galadriel-pid", "--release", "--locked"),
    ),
    CommandSpec(
        "evaluation-benchmark-build",
        (
            "cargo",
            "bench",
            "-p",
            "galadriel-eval",
            "--bench",
            "detectors",
            "--no-run",
            "--locked",
        ),
    ),
    CommandSpec(
        "current-stable-clippy",
        (
            "cargo",
            "+stable",
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--",
            "-D",
            "warnings",
        ),
    ),
    CommandSpec(
        "current-stable-tests",
        (
            "cargo",
            "+stable",
            "test",
            "--workspace",
            "--all-features",
            "--locked",
        ),
    ),
    CommandSpec(
        "dependency-policy-workspace",
        ("cargo", "deny", "--all-features", "--locked", "check"),
    ),
    CommandSpec(
        "vulnerable-feature-assertion",
        ("python3", "repo_work/check_vulnerable_features.py"),
    ),
    CommandSpec(
        "dependency-policy-fuzz",
        (
            "cargo",
            "deny",
            "--manifest-path",
            "fuzz/Cargo.toml",
            "--all-features",
            "--locked",
            "check",
            "--config",
            "fuzz/deny.toml",
        ),
    ),
    CommandSpec(
        "cargo-audit",
        (
            "cargo",
            "audit",
            "--no-yanked",
            "--ignore",
            "RUSTSEC-2026-0041",
            "--format",
            "json",
        ),
    ),
    CommandSpec(
        "public-api-snapshots",
        ("python3", "repo_work/check_public_api.py"),
    ),
)

DEEP_COMMANDS = (
    CommandSpec(
        "fuzz-ncp-decode-5000",
        (
            "cargo",
            "+nightly-2026-06-16",
            "fuzz",
            "run",
            "ncp_decode",
            "--",
            "-runs=5000",
            "-max_len=131072",
        ),
        timeout_seconds=1_800,
    ),
    CommandSpec(
        "fuzz-detector-boundaries-5000",
        (
            "cargo",
            "+nightly-2026-06-16",
            "fuzz",
            "run",
            "detector_boundaries",
            "--",
            "-runs=5000",
            "-max_len=131072",
        ),
        timeout_seconds=1_800,
    ),
)


def utc_now() -> str:
    """Return an unambiguous UTC timestamp."""

    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def digest_file(path: Path) -> tuple[str, int]:
    """Return a streaming SHA-256 and byte length."""

    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(block)
            digest.update(block)
    return digest.hexdigest(), size


def capture(argv: list[str], cwd: Path) -> str:
    """Capture one required identity command without shell interpretation."""

    process = subprocess.run(
        argv,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        text=True,
    )
    if process.returncode != 0:
        raise ReviewError(f"{' '.join(argv)} failed: {process.stdout.strip()}")
    return process.stdout.strip()


def run_command(
    spec: CommandSpec,
    *,
    worktree: Path,
    environment: dict[str, str],
    logs: Path,
    index: int,
) -> dict[str, Any]:
    """Run one command and retain complete combined output."""

    worktree = worktree.resolve()
    command_environment = dict(environment)
    command_environment.update(spec.environment)
    cwd = (worktree / spec.cwd).resolve()
    if cwd != worktree and worktree not in cwd.parents:
        raise ReviewError(f"command working directory escapes worktree: {spec.cwd}")
    log = logs / f"{index:02d}-{spec.name}.log"
    started_at = utc_now()
    started = time.monotonic()
    timed_out = False
    print(f"START {index:02d} {spec.name}", flush=True)
    with log.open("wb") as handle:
        header = {
            "argv": list(spec.argv),
            "cwd": spec.cwd,
            "environment_overrides": dict(spec.environment),
            "started_at": started_at,
            "timeout_seconds": spec.timeout_seconds,
        }
        handle.write(canonical_json(header))
        handle.write(b"--- combined stdout/stderr ---\n")
        handle.flush()
        process = subprocess.Popen(
            spec.argv,
            cwd=cwd,
            env=command_environment,
            stdin=subprocess.DEVNULL,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            returncode = process.wait(timeout=spec.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                returncode = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                returncode = process.wait()
            handle.write(
                f"\nQUALIFICATION_TIMEOUT after {spec.timeout_seconds} seconds\n".encode()
            )
    finished_at = utc_now()
    duration = time.monotonic() - started
    digest, size = digest_file(log)
    state = "PASS" if returncode == 0 and not timed_out else "FAIL"
    print(f"{state} {index:02d} {spec.name} ({duration:.1f}s)", flush=True)
    return {
        "name": spec.name,
        "argv": list(spec.argv),
        "cwd": spec.cwd,
        "environment_overrides": dict(spec.environment),
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": round(duration, 3),
        "timeout_seconds": spec.timeout_seconds,
        "timed_out": timed_out,
        "exit_code": returncode,
        "status": state,
        "log": log.relative_to(logs.parent).as_posix(),
        "log_sha256": digest,
        "log_size_bytes": size,
    }


def source_archive(repo: Path, commit: str, output: Path) -> dict[str, Any]:
    """Create and byte-verify a deterministic Git source archive."""

    prefix = f"galadriel-{VERSION}/"
    tar_path = output.with_suffix("")
    with tar_path.open("wb") as handle:
        process = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "archive",
                "--format=tar",
                f"--prefix={prefix}",
                commit,
            ],
            stdin=subprocess.DEVNULL,
            stdout=handle,
            stderr=subprocess.PIPE,
            check=False,
        )
    if process.returncode != 0:
        raise ReviewError(
            "git archive failed: " + process.stderr.decode("utf-8", "replace").strip()
        )
    with tar_path.open("rb") as source, output.open("wb") as destination:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=destination, mtime=0
        ) as compressed:
            shutil.copyfileobj(source, compressed)
    tar_path.unlink()

    expected_raw = bytes(
        git(repo, "ls-tree", "-rz", "-r", "--full-tree", commit, text=False)
    )
    expected: dict[str, tuple[str, str]] = {}
    for entry in expected_raw.split(b"\0"):
        if not entry:
            continue
        metadata, encoded_path = entry.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split()
        path = encoded_path.decode("utf-8", "surrogateescape")
        expected[path] = (mode, object_id)

    observed: set[str] = set()
    with tarfile.open(output, mode="r:gz") as archive:
        for member in archive:
            if member.isdir():
                continue
            if not member.name.startswith(prefix):
                raise ReviewError(
                    f"source archive entry lacks release prefix: {member.name}"
                )
            relative = member.name.removeprefix(prefix)
            if not relative or relative.startswith("/") or ".." in Path(relative).parts:
                raise ReviewError(f"unsafe source archive path: {member.name}")
            if relative in observed or relative not in expected:
                raise ReviewError(
                    f"unexpected or duplicate source archive path: {relative}"
                )
            observed.add(relative)
            mode, object_id = expected[relative]
            if mode == "160000":
                raise ReviewError(
                    "source archive qualification requires an explicit submodule bundle: "
                    + relative
                )
            blob = bytes(git(repo, "cat-file", "blob", object_id, text=False))
            if mode == "120000":
                archived = member.linkname.encode("utf-8", "surrogateescape")
            else:
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ReviewError(
                        f"source archive entry has no content: {relative}"
                    )
                archived = extracted.read()
            if archived != blob:
                raise ReviewError(
                    f"source archive content differs from Git blob: {relative}"
                )
    if observed != set(expected):
        missing = sorted(set(expected) - observed)
        raise ReviewError(f"source archive omits tracked paths: {missing[:10]}")
    digest, size = digest_file(output)
    return {
        "path": output.name,
        "sha256": digest,
        "size_bytes": size,
        "tracked_entries": len(observed),
        "prefix": prefix,
    }


def collect_sboms(
    worktree: Path, destination: Path, environment: dict[str, str]
) -> list[dict[str, Any]]:
    """Generate one CycloneDX document per workspace package and move it out."""

    process = subprocess.run(
        [
            "cargo",
            "cyclonedx",
            "--all-features",
            "--target",
            "all",
            "--format",
            "json",
            "--spec-version",
            "1.5",
            "--override-filename",
            f"galadriel-{VERSION}",
            "--quiet",
        ],
        cwd=worktree,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        text=True,
    )
    if process.returncode != 0:
        raise ReviewError(f"cargo cyclonedx failed: {process.stdout.strip()}")
    generated = sorted(worktree.glob(f"crates/*/galadriel-{VERSION}.json"))
    if len(generated) != 7:
        raise ReviewError(f"expected seven workspace SBOMs, found {len(generated)}")
    destination.mkdir(parents=True, exist_ok=False)
    rows: list[dict[str, Any]] = []
    for source in generated:
        crate = source.parent.name
        target = destination / f"{crate}.cdx.json"
        source.replace(target)
        digest, size = digest_file(target)
        rows.append(
            {
                "crate": crate,
                "path": target.relative_to(destination.parent).as_posix(),
                "sha256": digest,
                "size_bytes": size,
            }
        )
    return rows


def capture_report(
    argv: list[str],
    *,
    worktree: Path,
    environment: dict[str, str],
    output: Path,
    json_lines: bool,
) -> dict[str, Any]:
    """Retain and parse-check a standalone supply-chain JSON report."""

    process = subprocess.run(
        argv,
        cwd=worktree,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", "replace").strip()
        raise ReviewError(f"{' '.join(argv)} report failed: {detail}")
    if not process.stdout.strip():
        raise ReviewError(f"{' '.join(argv)} produced an empty report")
    try:
        if json_lines:
            documents = [
                loads_json(line)
                for line in process.stdout.splitlines()
                if line.strip()
            ]
            if not documents or not all(
                isinstance(document, dict) for document in documents
            ):
                raise ValueError("JSONL report must contain at least one object")
        else:
            document = loads_json(process.stdout)
            if not isinstance(document, dict):
                raise ValueError("JSON report must be an object")
    except (UnicodeError, ReviewError, ValueError) as error:
        raise ReviewError(
            f"{' '.join(argv)} produced invalid JSON evidence: {error}"
        ) from error
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(process.stdout)
    digest, size = digest_file(output)
    return {
        "argv": argv,
        "path": output.relative_to(output.parents[1]).as_posix(),
        "sha256": digest,
        "size_bytes": size,
        "stderr": process.stderr.decode("utf-8", "replace").strip(),
    }


def reproducible_source_archive(
    repo: Path, commit: str, output: Path, comparison_root: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the source archive twice and reject byte drift."""

    retained = source_archive(repo, commit, output)
    repeated_path = comparison_root / output.name
    repeated = source_archive(repo, commit, repeated_path)
    if (
        retained["sha256"] != repeated["sha256"]
        or retained["size_bytes"] != repeated["size_bytes"]
    ):
        raise ReviewError("two deterministic source-archive runs differ")
    return retained, {
        "kind": "source_archive",
        "name": output.name,
        "run_1_sha256": retained["sha256"],
        "run_2_sha256": repeated["sha256"],
        "size_bytes": retained["size_bytes"],
        "status": "IDENTICAL",
    }


def reproducible_packages(
    worktree: Path,
    metadata: dict[str, Any],
    destination: Path,
    comparison_root: Path,
    environment: dict[str, str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Create every workspace package twice and require byte identity."""

    worktree = worktree.resolve()
    workspace_ids = set(metadata.get("workspace_members", []))
    packages = sorted(
        (
            (package["name"], package["version"])
            for package in metadata.get("packages", [])
            if package.get("id") in workspace_ids
        ),
        key=lambda item: item[0],
    )
    if len(packages) != 7:
        raise ReviewError(f"expected seven workspace packages, found {len(packages)}")
    git_patch_paths: dict[str, tuple[str, Path]] = {}
    for package in metadata.get("packages", []):
        source = package.get("source")
        if not isinstance(source, str) or not source.startswith("git+"):
            continue
        name = package.get("name")
        manifest_path = package.get("manifest_path")
        if not isinstance(name, str) or not isinstance(manifest_path, str):
            raise ReviewError(
                "Git dependency metadata lacks a package name or manifest path"
            )
        package_path = Path(manifest_path).resolve().parent
        source_url = source.removeprefix("git+").split("?", 1)[0].split("#", 1)[0]
        previous = git_patch_paths.get(name)
        if previous is not None and previous != (source_url, package_path):
            raise ReviewError(f"cannot package two Git/path sources named {name}")
        if not (package_path / "Cargo.toml").is_file():
            raise ReviewError(f"Git dependency package path is missing: {package_path}")
        git_patch_paths[name] = (source_url, package_path)
    targets = [comparison_root / "package-run-1", comparison_root / "package-run-2"]
    packaging_worktrees = [
        comparison_root / "package-worktree-1",
        comparison_root / "package-worktree-2",
    ]
    commit = capture(["git", "rev-parse", "HEAD^{commit}"], worktree)
    original_lock = (worktree / "Cargo.lock").read_bytes()
    for target, package_worktree in zip(targets, packaging_worktrees, strict=True):
        clone = subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--no-checkout",
                "--shared",
                str(worktree),
                str(package_worktree),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            text=True,
        )
        if clone.returncode != 0:
            raise ReviewError(f"cannot create package worktree: {clone.stdout.strip()}")
        checkout = subprocess.run(
            ["git", "checkout", "--quiet", "--detach", commit],
            cwd=package_worktree,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            text=True,
        )
        if (
            checkout.returncode != 0
            or capture(["git", "rev-parse", "HEAD^{commit}"], package_worktree)
            != commit
        ):
            raise ReviewError(
                f"cannot check out exact package candidate: {checkout.stdout.strip()}"
            )
        package_paths = {
            name: (package_worktree / "crates" / name).resolve()
            for name, _version in packages
        }
        if any(not (path / "Cargo.toml").is_file() for path in package_paths.values()):
            raise ReviewError("package worktree omits a workspace manifest")
        for name, _version in packages:
            (package_worktree / "Cargo.lock").write_bytes(original_lock)
            if capture(
                ["git", "status", "--porcelain=v1", "--untracked-files=all"],
                package_worktree,
            ):
                raise ReviewError("package worktree is dirty before Cargo package")
            patch_arguments: list[str] = []
            for dependency_name, package_path in package_paths.items():
                if dependency_name == name:
                    continue
                patch_arguments.extend(
                    [
                        "--config",
                        f"patch.crates-io.{dependency_name}.path={json.dumps(str(package_path))}",
                    ]
                )
            for dependency_name, (source_url, package_path) in git_patch_paths.items():
                patch_arguments.extend(
                    [
                        "--config",
                        f"patch.crates-io.{dependency_name}.path={json.dumps(str(package_path))}",
                        "--config",
                        (
                            f"patch.{json.dumps(source_url)}.{dependency_name}.path="
                            f"{json.dumps(str(package_path))}"
                        ),
                    ]
                )
            process = subprocess.run(
                [
                    "cargo",
                    "package",
                    "-p",
                    name,
                    "--offline",
                    "--no-verify",
                    "--exclude-lockfile",
                    "--target-dir",
                    str(target),
                    *patch_arguments,
                ],
                cwd=package_worktree,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                text=True,
            )
            if process.returncode != 0:
                raise ReviewError(
                    f"cargo package -p {name} failed: {process.stdout.strip()}"
                )
        (package_worktree / "Cargo.lock").write_bytes(original_lock)
        if capture(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            package_worktree,
        ):
            raise ReviewError("package worktree did not return to the exact candidate")
    destination.mkdir(parents=True, exist_ok=False)
    retained_rows: list[dict[str, Any]] = []
    comparisons: list[dict[str, Any]] = []
    for name, version in packages:
        filename = f"{name}-{version}.crate"
        first = targets[0] / "package" / filename
        second = targets[1] / "package" / filename
        if not first.is_file() or not second.is_file():
            raise ReviewError(f"cargo package omitted {filename}")
        prefix = f"{name}-{version}/"
        for package_path in (first, second):
            with tarfile.open(package_path, mode="r:gz") as package_archive:
                members = {member.name: member for member in package_archive}
                if not members or any(
                    not member_name.startswith(prefix)
                    or ".." in Path(member_name).parts
                    for member_name in members
                ):
                    raise ReviewError(
                        f"cargo package has an unsafe or wrong prefix: {filename}"
                    )
                if f"{prefix}Cargo.lock" in members:
                    raise ReviewError(
                        f"unpublished package unexpectedly retained Cargo.lock: {filename}"
                    )
                vcs_member = members.get(f"{prefix}.cargo_vcs_info.json")
                if vcs_member is None:
                    raise ReviewError(
                        f"cargo package lacks candidate VCS provenance: {filename}"
                    )
                extracted = package_archive.extractfile(vcs_member)
                if extracted is None:
                    raise ReviewError(
                        f"cargo package VCS provenance is unreadable: {filename}"
                    )
                vcs = loads_json(extracted.read())
                git_identity = vcs.get("git") if isinstance(vcs, dict) else None
                if (
                    not isinstance(git_identity, dict)
                    or git_identity.get("sha1") != commit
                ):
                    raise ReviewError(
                        f"cargo package targets another candidate commit: {filename}"
                    )
        first_digest, first_size = digest_file(first)
        second_digest, second_size = digest_file(second)
        if first_digest != second_digest or first_size != second_size:
            raise ReviewError(f"two package runs differ for {filename}")
        retained = destination / filename
        shutil.copyfile(first, retained)
        retained_rows.append(
            {
                "crate": name,
                "version": version,
                "candidate_commit": commit,
                "package_kind": "cargo_package_unpublished_source",
                "lockfile_policy": "excluded; candidate Cargo.lock is retained in the source archive",
                "dependency_resolution": "offline temporary path overrides for locked unpublished workspace and Git dependencies",
                "path": retained.relative_to(destination.parent).as_posix(),
                "sha256": first_digest,
                "size_bytes": first_size,
            }
        )
        comparisons.append(
            {
                "kind": "cargo_package",
                "name": filename,
                "run_1_sha256": first_digest,
                "run_2_sha256": second_digest,
                "size_bytes": first_size,
                "status": "IDENTICAL",
            }
        )
    return retained_rows, comparisons


def artifact_rows(root: Path, excluded: set[str]) -> list[dict[str, Any]]:
    """Hash every regular retained artifact except explicitly self-referential files."""

    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ReviewError(f"qualification output contains a symlink: {relative}")
        if not path.is_file():
            continue
        if relative in excluded:
            continue
        digest, size = digest_file(path)
        rows.append({"path": relative, "sha256": digest, "size_bytes": size})
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--expected", required=True, help="exact candidate commit")
    parser.add_argument(
        "--out", required=True, help="new directory outside the repository"
    )
    parser.add_argument("--require-branch", default="main")
    parser.add_argument(
        "--signing-key",
        help=(
            "SSH signing-key handle used for the detached qualification-manifest "
            "signature (private key or agent-backed Ed25519 public key)"
        ),
    )
    parser.add_argument(
        "--mutation-evidence",
        help="signed exact-candidate broad and focused mutation manifest",
    )
    parser.add_argument("--mutation-evidence-signature")
    parser.add_argument(
        "--deep", action="store_true", help="run bounded fuzz campaigns"
    )
    parser.add_argument("--keep-going", action="store_true")
    parser.add_argument(
        "--evidence-config",
        default="evidence/galadriel-0.9-candidate.json",
        help="tracked evidence configuration, relative to the candidate root",
    )
    parser.add_argument("--skip-evidence", action="store_true")
    arguments = parser.parse_args()

    repo = Path(arguments.repo).resolve()
    output = Path(arguments.out).resolve()
    signing_key = (
        Path(arguments.signing_key).expanduser().resolve()
        if arguments.signing_key
        else None
    )
    mutation_evidence_path = (
        Path(arguments.mutation_evidence).resolve()
        if arguments.mutation_evidence
        else None
    )
    mutation_signature_path = (
        Path(arguments.mutation_evidence_signature).resolve()
        if arguments.mutation_evidence_signature
        else None
    )
    worktree: Path | None = None
    temporary: tempfile.TemporaryDirectory[str] | None = None
    results: list[dict[str, Any]] = []
    failure: str | None = None
    try:
        if output.exists() or output == repo or repo in output.parents:
            raise ReviewError("--out must be a new directory outside --repo")
        if signing_key is None or not signing_key.is_file():
            raise ReviewError("successful qualification requires --signing-key")
        if mutation_evidence_path is None or mutation_signature_path is None:
            raise ReviewError(
                "successful qualification requires signed exact-candidate mutation evidence"
            )
        if capture(["git", "status", "--porcelain=v1", "--untracked-files=all"], repo):
            raise ReviewError("candidate checkout is dirty")
        commit = capture(["git", "rev-parse", "HEAD^{commit}"], repo)
        if commit != arguments.expected:
            raise ReviewError(
                f"candidate mismatch: expected={arguments.expected} actual={commit}"
            )
        branch = capture(["git", "branch", "--show-current"], repo)
        if arguments.require_branch and branch != arguments.require_branch:
            raise ReviewError(
                f"candidate branch must be {arguments.require_branch!r}, got {branch!r}"
            )
        tree = capture(["git", "rev-parse", "HEAD^{tree}"], repo)
        source_date_epoch = capture(["git", "show", "-s", "--format=%ct", "HEAD"], repo)

        output.mkdir(parents=True, exist_ok=False)
        logs = output / "logs"
        logs.mkdir()
        inventory = output / "source-inventory"
        evidence_output = output / "candidate-evidence"
        temporary = tempfile.TemporaryDirectory(prefix="galadriel-qualification-")
        temporary_root = Path(temporary.name)
        worktree = temporary_root / "worktree"
        target = temporary_root / "target"
        external_allowed_signers = temporary_root / "EXTERNAL_ALLOWED_SIGNERS"
        expected_signer_metadata = derive_external_allowed_signers(
            signing_key, external_allowed_signers
        )
        add = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "worktree",
                "add",
                "--detach",
                "--force",
                str(worktree),
                commit,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            text=True,
        )
        if add.returncode != 0:
            raise ReviewError(
                f"cannot create detached candidate worktree: {add.stdout.strip()}"
            )
        assert_tracked_allowed_signer(
            worktree / ALLOWED_SIGNERS, expected_signer_metadata
        )
        mutation_document, mutation_artifacts = validate_mutation_evidence(
            mutation_evidence_path,
            mutation_signature_path,
            allowed_signers=external_allowed_signers,
            repo=repo,
            commit=commit,
            tree=tree,
        )
        mutation_output = output / "mutation"
        mutation_output.mkdir()
        shutil.copyfile(mutation_evidence_path, mutation_output / "manifest.json")
        shutil.copyfile(mutation_signature_path, mutation_output / "manifest.json.sig")
        retained_mutation_artifacts = []
        for source in mutation_artifacts:
            source_relative = source.relative_to(mutation_evidence_path.parent)
            target_artifact = mutation_output / source_relative
            target_artifact.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target_artifact)
            artifact_digest, artifact_size = digest_file(target_artifact)
            retained_mutation_artifacts.append(
                {
                    "path": target_artifact.relative_to(output).as_posix(),
                    "sha256": artifact_digest,
                    "size_bytes": artifact_size,
                }
            )
        mutation_record = {
            "manifest": "mutation/manifest.json",
            "manifest_sha256": digest_file(mutation_output / "manifest.json")[0],
            "signature": "mutation/manifest.json.sig",
            "candidate": mutation_document["candidate"],
            "baseline_commit": mutation_document["baseline_commit"],
            "shards": len(mutation_document["shards"]),
            "focused_checks": len(mutation_document["focused_checks"]),
            "run_receipts": 1,
            "status": "PASS",
            "artifacts": retained_mutation_artifacts,
        }

        environment = dict(os.environ)
        environment.update(
            {
                "CARGO_INCREMENTAL": "0",
                "CARGO_TARGET_DIR": str(target),
                "CARGO_TERM_COLOR": "never",
                "LC_ALL": "C",
                "SOURCE_DATE_EPOCH": source_date_epoch,
                "TZ": "UTC",
            }
        )
        command_specs = [
            CommandSpec(
                "verify-commit-signature-external-key",
                (
                    "git",
                    "-c",
                    f"gpg.ssh.allowedSignersFile={external_allowed_signers}",
                    "verify-commit",
                    "HEAD",
                ),
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
            *BASE_COMMANDS,
        ]
        evidence_config: Path | None = None
        if not arguments.skip_evidence:
            evidence_config = Path(arguments.evidence_config)
            if evidence_config.is_absolute() or ".." in evidence_config.parts:
                raise ReviewError("--evidence-config must be a contained relative path")
            command_specs.append(
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
                        evidence_config.as_posix(),
                        "--out",
                        str(evidence_output),
                    ),
                    timeout_seconds=7_200,
                )
            )
        if arguments.deep:
            command_specs.extend(DEEP_COMMANDS)

        for index, spec in enumerate(command_specs, 1):
            result = run_command(
                spec,
                worktree=worktree,
                environment=environment,
                logs=logs,
                index=index,
            )
            results.append(result)
            if result["status"] != "PASS" and not arguments.keep_going:
                break

        command_status = (
            "PASS"
            if all(result["status"] == "PASS" for result in results)
            and len(results) == len(command_specs)
            else "FAIL"
        )
        acceptance: dict[str, Any] | None = None
        config_binding: dict[str, Any] | None = None
        if command_status == "PASS" and not arguments.skip_evidence:
            assert evidence_config is not None
            config_binding = validate_evidence_config_binding(
                worktree / evidence_config,
                evidence_output,
                tracked_relative_path=evidence_config.as_posix(),
            )
            try:
                summary = load_json(evidence_output / "summary.json")
                accepted_config = load_json(evidence_output / "config.json")
                acceptance = evaluate_acceptance(summary, accepted_config)
            except ReviewError as error:
                acceptance = {
                    "schema": "galadriel.candidate-acceptance.v1",
                    "release": VERSION,
                    "partition": "holdout_results",
                    "status": "FAIL",
                    "failed_criterion_ids": [],
                    "evaluation_error": str(error),
                    "criteria": [],
                }
            (output / "candidate-acceptance.json").write_bytes(
                canonical_json(acceptance)
            )
        elif command_status == "PASS":
            acceptance = {
                "schema": "galadriel.candidate-acceptance.v1",
                "release": VERSION,
                "partition": "not_run",
                "status": "NOT_RUN",
                "failed_criterion_ids": [],
                "criteria": [],
            }
            (output / "candidate-acceptance.json").write_bytes(
                canonical_json(acceptance)
            )

        if command_status == "PASS":
            metadata = subprocess.run(
                [
                    "cargo",
                    "metadata",
                    "--locked",
                    "--all-features",
                    "--format-version=1",
                ],
                cwd=worktree,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if metadata.returncode != 0:
                raise ReviewError(
                    "cargo metadata failed: "
                    + metadata.stderr.decode("utf-8", "replace").strip()
                )
            (output / "cargo-metadata.json").write_bytes(metadata.stdout)
            metadata_document = loads_json(metadata.stdout)
            comparison_root = temporary_root / "reproducibility"
            comparison_root.mkdir()
            archive, archive_comparison = reproducible_source_archive(
                repo,
                commit,
                output / f"galadriel-{VERSION}.tar.gz",
                comparison_root,
            )
            packages, package_comparisons = reproducible_packages(
                worktree,
                metadata_document,
                output / "packages",
                comparison_root,
                environment,
            )
            sboms = collect_sboms(worktree, output / "sbom", environment)
            license_report = capture_report(
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
                worktree=worktree,
                environment=environment,
                output=output / "reports" / "license-report.jsonl",
                json_lines=True,
            )
            vulnerability_report = capture_report(
                [
                    "cargo",
                    "audit",
                    "--no-yanked",
                    "--ignore",
                    "RUSTSEC-2026-0041",
                    "--format",
                    "json",
                ],
                worktree=worktree,
                environment=environment,
                output=output / "reports" / "vulnerability-report.json",
                json_lines=False,
            )
            reproducibility = {
                "schema": "galadriel.reproducibility-comparison.v1",
                "candidate": {"commit": commit, "tree": tree},
                "status": "PASS",
                "comparisons": [archive_comparison, *package_comparisons],
            }
            (output / "REPRODUCIBILITY.json").write_bytes(
                canonical_json(reproducibility)
            )
            final_status = capture(
                ["git", "status", "--porcelain=v1", "--untracked-files=all"], worktree
            )
            if final_status:
                raise ReviewError(
                    f"detached candidate changed during qualification:\n{final_status}"
                )
        else:
            archive = None
            packages = []
            sboms = []
            license_report = None
            vulnerability_report = None
            reproducibility = None

        tools = {
            "git": capture(["git", "--version"], worktree),
            "rustc": capture(["rustc", "-Vv"], worktree),
            "cargo": capture(["cargo", "-Vv"], worktree),
            "rustc_current_stable": capture(["rustc", "+stable", "-Vv"], worktree),
            "cargo_current_stable": capture(["cargo", "+stable", "-Vv"], worktree),
            "rustc_fuzz_nightly": capture(
                ["rustc", "+nightly-2026-06-16", "-Vv"], worktree
            ),
            "python": capture(["python3", "--version"], worktree),
            "cargo_deny": capture(["cargo", "deny", "--version"], worktree),
            "cargo_audit": capture(["cargo", "audit", "--version"], worktree),
            "cargo_cyclonedx": capture(["cargo", "cyclonedx", "--version"], worktree),
            "cargo_public_api": capture(["cargo", "public-api", "--version"], worktree),
            "cargo_fuzz": capture(
                ["cargo", "+nightly-2026-06-16", "fuzz", "--version"], worktree
            ),
        }
        status = "PASS" if command_status == "PASS" and archive is not None else "FAIL"
        acceptance_status = None if acceptance is None else acceptance["status"]
        release_gate = (
            "PASS"
            if status == "PASS" and acceptance_status == "PASS"
            else "NARROWED_REVIEW_REQUIRED"
            if status == "PASS" and acceptance_status == "FAIL"
            else "FAIL"
        )
        qualification = {
            "schema": SCHEMA,
            "release": VERSION,
            "author": "Sepehr Mahmoudian",
            "doi": None,
            "zenodo": None,
            "status": status,
            "command_status": command_status,
            "release_gate": release_gate,
            "candidate": {
                "repository": capture(["git", "remote", "get-url", "origin"], repo),
                "branch": branch,
                "commit": commit,
                "tree": tree,
                "source_date_epoch": int(source_date_epoch),
            },
            "host": {
                "platform": platform.platform(),
                "machine": platform.machine(),
                "python_implementation": platform.python_implementation(),
            },
            "tools": tools,
            "environment_contract": {
                key: environment[key]
                for key in (
                    "CARGO_INCREMENTAL",
                    "CARGO_TERM_COLOR",
                    "LC_ALL",
                    "SOURCE_DATE_EPOCH",
                    "TZ",
                )
            },
            "deep_campaigns_requested": bool(arguments.deep),
            "evidence_config": None
            if arguments.skip_evidence
            else arguments.evidence_config,
            "commands": results,
            "acceptance": {
                "path": "candidate-acceptance.json",
                "status": acceptance_status,
                "failed_criterion_ids": []
                if acceptance is None
                else acceptance["failed_criterion_ids"],
            },
            "evidence_config_binding": config_binding,
            "source_archive": archive,
            "packages": packages,
            "sboms": sboms,
            "license_report": license_report,
            "vulnerability_report": vulnerability_report,
            "reproducibility": None
            if reproducibility is None
            else {
                "path": "REPRODUCIBILITY.json",
                "status": reproducibility["status"],
            },
            "mutation_evidence": mutation_record,
            "limitations": (
                "This is author-operated component/source qualification on the recorded host. "
                "It is not an independent clean-room reproduction, external deployment test, "
                "DOI/Zenodo archive, crates.io publication, or deployment-performance claim."
            ),
        }
        (output / "qualification.json").write_bytes(canonical_json(qualification))
        provenance = {
            "schema": "galadriel.slsa-provenance.v1",
            "release": VERSION,
            "subject": {"commit": commit, "tree": tree},
            "builder": {
                "kind": "author-operated isolated qualification worktree",
                "tools": tools,
            },
            "invocation": {
                "source_date_epoch": int(source_date_epoch),
                "deep_campaigns_requested": bool(arguments.deep),
                "evidence_config": None
                if arguments.skip_evidence
                else arguments.evidence_config,
            },
            "materials": {
                "source_archive_sha256": None if archive is None else archive["sha256"],
                "package_sha256": [package["sha256"] for package in packages],
                "sbom_sha256": [sbom["sha256"] for sbom in sboms],
            },
        }
        (output / "provenance.json").write_bytes(canonical_json(provenance))
        manifest_name = "QUALIFICATION-MANIFEST.json"
        signature_name = f"{manifest_name}.sig"
        manifest_rows = artifact_rows(
            output, {manifest_name, signature_name, "SHA256SUMS"}
        )
        manifest_path = output / manifest_name
        manifest_path.write_bytes(
            canonical_json(
                {
                    "schema": "galadriel.tiered-artifact-manifest.v1",
                    "tier": "qualification",
                    "candidate": {"commit": commit, "tree": tree},
                    "artifacts": manifest_rows,
                }
            )
        )
        signature_path = sign_file(
            manifest_path, signing_key, "galadriel-qualification-manifest"
        )
        verify_signature(
            manifest_path,
            signature_path,
            external_allowed_signers,
            "galadriel-qualification-manifest",
        )
        verify_artifact_manifest(
            output,
            manifest_path,
            expected_schema="galadriel.tiered-artifact-manifest.v1",
            forbidden_paths={manifest_name, signature_name, "SHA256SUMS"},
        )
        rows = artifact_rows(output, {"SHA256SUMS"})
        with (output / "SHA256SUMS").open(
            "w", encoding="utf-8", newline="\n"
        ) as handle:
            for row in rows:
                handle.write(f"{row['sha256']}  {row['path']}\n")
        return 0 if status == "PASS" else 1
    except (OSError, ReviewError, ValueError) as error:
        failure = str(error)
        print(f"candidate qualification failed: {failure}", file=sys.stderr)
        if output.is_dir() and not (output / "qualification.json").exists():
            failure_record = {
                "schema": SCHEMA,
                "release": VERSION,
                "author": "Sepehr Mahmoudian",
                "status": "FAIL",
                "error": failure,
                "commands": results,
            }
            (output / "qualification.json").write_bytes(canonical_json(failure_record))
        return 2
    finally:
        if worktree is not None and worktree.exists():
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "worktree",
                    "remove",
                    "--force",
                    str(worktree),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        if temporary is not None:
            temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
