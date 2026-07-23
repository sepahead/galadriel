#!/usr/bin/env python3
"""Reproduce an immutable Git baseline in a detached temporary worktree.

The current checkout may contain candidate work.  This utility never executes the
baseline gates there: it materializes the requested commit in a temporary
worktree, uses a separate Cargo target directory, and records every command and
result in deterministic JSON plus a complete UTF-8 log.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from common import ReviewError, canonical_json, git, safe_git_environment
from release_assurance import (
    run_bounded_host_command,
    sanitized_host_environment,
)


SCHEMA = "galadriel.baseline-reproduction.v1"
BASELINE_COMMAND_TIMEOUT_SECONDS = 60 * 60
MAX_BASELINE_COMMAND_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_BASELINE_LOG_BYTES = 512 * 1024 * 1024
METADATA_TIMEOUT_SECONDS = 10 * 60
MAX_METADATA_STDOUT_BYTES = 64 * 1024 * 1024
MAX_METADATA_STDERR_BYTES = 1024 * 1024


@dataclass(frozen=True)
class CommandSpec:
    """One shell-free command in the baseline reproduction plan."""

    name: str
    argv: tuple[str, ...]
    extra_env: tuple[tuple[str, str], ...] = ()


COMMANDS = (
    CommandSpec("git-status-before", ("git", "status", "--porcelain=v1")),
    CommandSpec(
        "git-show-signature", ("git", "show", "--show-signature", "--no-patch", "HEAD")
    ),
    CommandSpec("rustc-version", ("rustc", "-Vv")),
    CommandSpec("cargo-version", ("cargo", "-Vv")),
    CommandSpec(
        "cargo-metadata", ("cargo", "metadata", "--locked", "--format-version=1")
    ),
    CommandSpec("format", ("cargo", "fmt", "--all", "--", "--check")),
    CommandSpec(
        "tests-all-features",
        ("cargo", "test", "--workspace", "--all-features", "--locked"),
    ),
    CommandSpec(
        "clippy-all-features",
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
        "docs-all-features",
        ("cargo", "doc", "--workspace", "--all-features", "--no-deps", "--locked"),
        (("RUSTDOCFLAGS", "-Dwarnings"),),
    ),
    CommandSpec("git-diff-after", ("git", "diff", "--exit-code", "--")),
    CommandSpec("git-status-after", ("git", "status", "--porcelain=v1")),
)


def utc_now() -> str:
    """Return an unambiguous UTC timestamp for an execution event."""

    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def sha256(path: Path) -> str:
    """Hash an artifact without loading it into memory."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_log_header(handle: BinaryIO, label: str, value: str) -> None:
    """Write one length-delimited field to the human-readable log."""

    handle.write(f"[{label}] {value}\n".encode("utf-8", "replace"))


def assert_log_bound(handle: BinaryIO) -> None:
    """Reject a baseline log that exceeds its fixed aggregate byte bound."""

    if handle.tell() > MAX_BASELINE_LOG_BYTES:
        raise ReviewError(f"baseline log exceeds {MAX_BASELINE_LOG_BYTES} bytes")


def baseline_environment(
    source: dict[str, str],
    *,
    target: Path,
    source_date_epoch: int,
) -> dict[str, str]:
    """Build the baseline tool environment without ambient secret selectors."""

    environment = safe_git_environment(sanitized_host_environment(source))
    environment.update(
        {
            "CARGO_TARGET_DIR": str(target),
            "CARGO_TERM_COLOR": "never",
            "SOURCE_DATE_EPOCH": str(source_date_epoch),
        }
    )
    return environment


def run_command(
    spec: CommandSpec,
    *,
    checkout: Path,
    base_env: dict[str, str],
    log: BinaryIO,
) -> dict[str, object]:
    """Execute and record one command without shell interpretation."""

    environment = dict(base_env)
    environment.update(spec.extra_env)
    started = utc_now()
    write_log_header(log, "command", spec.name)
    write_log_header(log, "started_utc", started)
    write_log_header(log, "argv_json", json.dumps(spec.argv))
    if spec.extra_env:
        write_log_header(
            log, "extra_env_json", json.dumps(dict(spec.extra_env), sort_keys=True)
        )
    log.write(b"[combined_output_begin]\n")
    log.flush()
    process = run_bounded_host_command(
        spec.argv,
        cwd=checkout,
        environment=environment,
        context=f"baseline command {spec.name}",
        merge_stderr=True,
        max_stdout_bytes=MAX_BASELINE_COMMAND_OUTPUT_BYTES,
        max_stderr_bytes=0,
        timeout_seconds=BASELINE_COMMAND_TIMEOUT_SECONDS,
    )
    ended = utc_now()
    log.write(process.stdout)
    log.write(b"\n[combined_output_end]\n")
    write_log_header(log, "exit_code", str(process.returncode))
    write_log_header(log, "ended_utc", ended)
    log.write(b"\n")
    assert_log_bound(log)
    log.flush()
    return {
        "name": spec.name,
        "argv": list(spec.argv),
        "extra_env": dict(spec.extra_env),
        "started_utc": started,
        "ended_utc": ended,
        "exit_code": process.returncode,
    }


def resolve_commit(repo: Path, revision: str) -> tuple[str, str, int]:
    """Resolve and type-check a baseline revision and its source-date epoch."""

    commit = str(git(repo, "rev-parse", "--verify", f"{revision}^{{commit}}"))
    commit = commit.strip()
    tree = str(git(repo, "rev-parse", f"{commit}^{{tree}}"))
    epoch_text = str(git(repo, "show", "-s", "--format=%ct", commit)).strip()
    try:
        epoch = int(epoch_text)
    except ValueError as error:
        raise ReviewError("baseline commit timestamp is not an integer") from error
    return commit, tree.strip(), epoch


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".", help="source Git checkout")
    parser.add_argument("--commit", required=True, help="immutable baseline revision")
    parser.add_argument(
        "--out", required=True, help="output directory (must not exist)"
    )
    arguments = parser.parse_args()

    repo = Path(arguments.repo).resolve()
    output = Path(arguments.out).resolve()
    if output.exists():
        print(
            f"baseline reproduction failed: output already exists: {output}",
            file=sys.stderr,
        )
        return 2

    try:
        commit, tree, source_date_epoch = resolve_commit(repo, arguments.commit)
        output.mkdir(parents=True)
        log_path = output / "baseline.log"
        result_path = output / "baseline.json"
        metadata_path = output / "cargo-metadata.json"

        with tempfile.TemporaryDirectory(prefix="galadriel-baseline-") as temporary:
            temporary_root = Path(temporary)
            checkout = temporary_root / "checkout"
            target = temporary_root / "target"
            git(
                repo,
                "worktree",
                "add",
                "--detach",
                str(checkout),
                commit,
                max_bytes=1024 * 1024,
                timeout_seconds=120,
            )
            try:
                base_env = baseline_environment(
                    dict(os.environ),
                    target=target,
                    source_date_epoch=source_date_epoch,
                )
                commands: list[dict[str, object]] = []
                started = utc_now()
                with log_path.open("wb") as log:
                    write_log_header(log, "schema", SCHEMA)
                    write_log_header(log, "commit", commit)
                    write_log_header(log, "tree", tree)
                    write_log_header(log, "checkout", str(checkout))
                    write_log_header(log, "cargo_target_dir", str(target))
                    write_log_header(log, "source_date_epoch", str(source_date_epoch))
                    write_log_header(log, "platform", platform.platform())
                    write_log_header(log, "python", sys.version.replace("\n", " "))
                    log.write(b"\n")
                    for spec in COMMANDS:
                        commands.append(
                            run_command(
                                spec,
                                checkout=checkout,
                                base_env=base_env,
                                log=log,
                            )
                        )
                ended = utc_now()

                # Preserve the exact metadata payload separately while keeping its
                # command result in the complete execution log.  Re-run only this
                # read-only command because stdout was deliberately combined above.
                metadata = run_bounded_host_command(
                    ["cargo", "metadata", "--locked", "--format-version=1"],
                    cwd=checkout,
                    environment=base_env,
                    context="baseline Cargo metadata artifact",
                    max_stdout_bytes=MAX_METADATA_STDOUT_BYTES,
                    max_stderr_bytes=MAX_METADATA_STDERR_BYTES,
                    timeout_seconds=METADATA_TIMEOUT_SECONDS,
                )
                if metadata.returncode != 0:
                    raise ReviewError(
                        "cargo metadata artifact capture failed after its recorded gate: "
                        + metadata.stderr.decode("utf-8", "replace")[-1000:]
                    )
                metadata_path.write_bytes(metadata.stdout)

                result = {
                    "schema": SCHEMA,
                    "baseline": {"commit": commit, "tree": tree},
                    "started_utc": started,
                    "ended_utc": ended,
                    "host": {
                        "platform": platform.platform(),
                        "machine": platform.machine(),
                        "python": sys.version,
                    },
                    "environment": {
                        "cargo_target_isolated": True,
                        "source_date_epoch": source_date_epoch,
                        "cargo_term_color": "never",
                    },
                    "commands": commands,
                    "passed": all(command["exit_code"] == 0 for command in commands),
                    "artifacts": {
                        "baseline.log": {
                            "bytes": log_path.stat().st_size,
                            "sha256": sha256(log_path),
                        },
                        "cargo-metadata.json": {
                            "bytes": metadata_path.stat().st_size,
                            "sha256": sha256(metadata_path),
                        },
                    },
                }
                result_path.write_bytes(canonical_json(result))
                passed = bool(result["passed"])
            finally:
                git(
                    repo,
                    "worktree",
                    "remove",
                    "--force",
                    str(checkout),
                    max_bytes=1024 * 1024,
                    timeout_seconds=120,
                )
                shutil.rmtree(target, ignore_errors=True)
    except (OSError, ReviewError) as error:
        print(f"baseline reproduction failed: {error}", file=sys.stderr)
        return 2

    print(result_path)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
