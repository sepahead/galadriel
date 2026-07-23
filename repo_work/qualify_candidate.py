#!/usr/bin/env python3
"""Qualify one clean signed Galadriel commit in an isolated clone.

The runner never edits the candidate checkout. It creates a standalone temporary
clone at the exact subject commit, uses an isolated Cargo target directory,
retains complete per-command logs, inventories every tracked blob, emits
deterministic source/SBOM artifacts, and records failures instead of replacing
them with a pass/fail summary.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import errno
import functools
import gzip
import hashlib
import json
import os
import platform
import resource
import selectors
import select
import signal
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from common import (
    SAFE_GIT_CONFIGURATION,
    ReviewError,
    absolute_path_without_final_resolution,
    assert_no_replace_refs,
    canonical_json,
    git,
    git_bounded_output,
    loads_json,
    read_bounded_regular_file,
    safe_git_environment,
)
from qualification_artifacts import (
    CARGO_DENY_HOST_FILTERED_SCOPE,
    MAX_CRATE_ARCHIVE_BYTES,
    MAX_LICENSE_REPORT_BYTES,
    MAX_LOCKFILE_BYTES,
    MAX_SBOM_BYTES,
    deterministic_cyclonedx_identity,
    load_bounded_json_document,
    validate_cargo_deny_license_inventory,
    validate_cargo_deny_license_policy_jsonl,
    validate_cargo_graph_paths,
    validate_cargo_metadata,
    validate_crate_archive,
    validate_cyclonedx_sbom,
)
from release_assurance import (
    MAX_EVIDENCE_DOCUMENT_BYTES,
    MAX_MUTATION_EVIDENCE_BYTES,
    assert_tracked_allowed_signer,
    evaluate_acceptance,
    git_tree_inventory,
    refresh_canonical_origin_main,
    sign_file,
    snapshot_agent_backed_public_signing_key,
    snapshot_independent_allowed_signers,
    validate_evidence_config_bytes,
    validate_mutation_evidence,
    verify_artifact_manifest,
    verify_candidate_commit,
    verify_signature,
)


SCHEMA = "galadriel.candidate-qualification.v3"
VERSION = "0.9.0"
ALLOWED_SIGNERS = "release/0.9.0/audit/ALLOWED_SIGNERS"
QUALIFICATION_ENVIRONMENT_KEYS = (
    "CARGO_HOME",
    "CARGO_INCREMENTAL",
    "CARGO_TARGET_DIR",
    "CARGO_TERM_COLOR",
    "GIT_ATTR_NOSYSTEM",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_OPTIONAL_LOCKS",
    "GIT_TERMINAL_PROMPT",
    "HOME",
    "LC_ALL",
    "PATH",
    "RUSTUP_HOME",
    "SOURCE_DATE_EPOCH",
    "TMPDIR",
    "TZ",
)
ISOLATED_ENVIRONMENT_PATHS = ("CARGO_HOME", "CARGO_TARGET_DIR", "HOME", "TMPDIR")
QUALIFICATION_PATH_TOOLS = (
    "git",
    "python3",
    "rustc",
    "cargo",
    "rustup",
    "cargo-deny",
    "cargo-audit",
    "cargo-cyclonedx",
    "cargo-public-api",
    "cargo-fuzz",
    "ssh-keygen",
    "cc",
    "clang",
    "ar",
    "ld",
    "make",
    "cmake",
    "pkg-config",
)
QUALIFICATION_SYSTEM_PATHS = ("/bin", "/usr/sbin", "/sbin")
SANDBOX_SYSTEM_READ_PATHS = (
    "/Applications/Xcode.app",
    "/Library/Apple",
    "/Library/Developer",
    "/System",
    "/bin",
    "/dev",
    "/etc",
    "/private/etc",
    "/private/var/run",
    "/sbin",
    "/usr",
)
SANDBOX_EXECUTABLE = Path("/usr/bin/sandbox-exec")
ADVISORY_DB_URL = "https://github.com/RustSec/advisory-db"
ADVISORY_DB_COMMIT = "f981d991604f3e7d4a0eb94e559cb3e5a94a6dc2"
ADVISORY_DB_TREE = "26bea0ac10667f826b5522a828a27861ae4b5287"
ADVISORY_DB_DENY_DIRECTORY = "advisory-db-3157b0e258782691"
MAX_QUALIFICATION_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_QUALIFICATION_TIER_BYTES = 8 * 1024 * 1024 * 1024
MAX_QUALIFICATION_ENTRIES = 32_768
MAX_QUALIFICATION_DEPTH = 128
MAX_QUALIFICATION_EXECUTABLE_BYTES = 1024 * 1024 * 1024
MAX_CANDIDATE_EVIDENCE_BYTES = 4 * 1024 * 1024 * 1024
EXPECTED_CANDIDATE_EVIDENCE_FILES = frozenset(
    {
        "SHA256SUMS",
        "config.json",
        "manifest.json",
        "report.md",
        "summary.json",
        "trials.jsonl",
    }
)
PARSED_CANDIDATE_EVIDENCE_FILES = frozenset(
    {"config.json", "manifest.json", "summary.json"}
)
MAX_COMMAND_STREAM_BYTES = 64 * 1024 * 1024
MAX_CAPTURE_BYTES = 1024 * 1024
MAX_TRACKED_PROCESSES = 4_096
MAX_SYSTEM_PROCESSES = 32_768
MAX_OPEN_FILES = 1_024
MAX_CANDIDATE_PROCESSES = 2_048
MAX_AGGREGATE_RESIDENT_BYTES = 16 * 1024 * 1024 * 1024
MAX_FILESYSTEM_GROWTH_BYTES = 8 * 1024 * 1024 * 1024
MIN_FILESYSTEM_FREE_BYTES = 4 * 1024 * 1024 * 1024
COMMAND_CPU_GRACE_SECONDS = 60
LAUNCH_GATE_TIMEOUT_SECONDS = 10.0
PROCESS_POLL_INTERVAL_SECONDS = 0.05
PROCESS_CLEANUP_TIMEOUT_SECONDS = 5.0
RECEIPT_TRAILER_MARKER = b"\n--- receipt trailer ---\n"
RECEIPT_TRAILER_SCHEMA = "galadriel.command-receipt-trailer.v1"
CONTAINMENT_POLICY = "MACOS_PROCESS_GROUP_KQUEUE_SANDBOX_SCAN_V2"
CONTAINMENT_RESIDUAL = (
    "macOS process discovery is not atomic. A short-lived reparented process "
    "can exit between scans. A sandboxed process can request work from an "
    "existing external service. "
    "The process scan cannot attribute that external service work."
)
PROCESS_PROBE_DENY_SUFFIX = ".containment-deny"
PROCESS_PROBE_ALLOW_SUFFIX = ".containment-allow"
PROCESS_PROBE_BYTES = b"galadriel-process-containment-v2\n"
_PROFILE_FILESYSTEM_BASELINES: dict[Path, tuple[tuple[int, str, int], ...]] = {}
LAUNCH_GATE_SOURCE = (
    "import os,signal,sys\n"
    "os.kill(os.getpid(), signal.SIGSTOP)\n"
    "os.execvpe(sys.argv[2], sys.argv[2:], os.environ)\n"
)


@dataclass(frozen=True)
class CommandSpec:
    """One shell-free qualification command."""

    name: str
    argv: tuple[str, ...]
    cwd: str = "."
    environment: tuple[tuple[str, str], ...] = ()
    timeout_seconds: int = 3_600


@dataclass(frozen=True)
class BoundedProcessResult:
    """One bounded process result and its containment disposition."""

    returncode: int
    timed_out: bool
    stdout: bytes
    stderr: bytes
    output_limit_exceeded: bool
    containment_error: str | None


DEPENDENCY_FETCH_COMMAND_NAMES = frozenset(
    {
        "fetch-locked-dependencies",
        "fetch-locked-fuzz-dependencies",
    }
)


def execution_policy_contract(timeout_seconds: int) -> dict[str, Any]:
    """Return the exact inherited process and stream limits."""

    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise ReviewError("command timeout must be a positive integer")
    limits = {
        "core_bytes": 0,
        "cpu_seconds": timeout_seconds + COMMAND_CPU_GRACE_SECONDS,
        "file_bytes": MAX_QUALIFICATION_ARTIFACT_BYTES,
        "open_files": MAX_OPEN_FILES,
        "processes": MAX_CANDIDATE_PROCESSES,
    }
    return {
        "containment": CONTAINMENT_POLICY,
        "containment_residual": CONTAINMENT_RESIDUAL,
        "launch_gate": "STOP_BEFORE_CANDIDATE_EXEC",
        "limits": limits,
        "monitored_limits": {
            "aggregate_resident_bytes": MAX_AGGREGATE_RESIDENT_BYTES,
            "filesystem_growth_bytes": MAX_FILESYSTEM_GROWTH_BYTES,
            "minimum_filesystem_free_bytes": MIN_FILESYSTEM_FREE_BYTES,
            "tracked_processes": MAX_TRACKED_PROCESSES,
        },
        "stream_limit_bytes": MAX_COMMAND_STREAM_BYTES,
    }


def require_resource_limit_capacity(policy: Mapping[str, Any]) -> None:
    """Fail when inherited hard limits cannot apply the exact policy."""

    limits = policy["limits"]
    required = (
        ("CPU", resource.RLIMIT_CPU, limits["cpu_seconds"]),
        ("file size", resource.RLIMIT_FSIZE, limits["file_bytes"]),
        ("open files", resource.RLIMIT_NOFILE, limits["open_files"]),
        ("process count", resource.RLIMIT_NPROC, limits["processes"]),
    )
    for name, limit, value in required:
        _soft, hard = resource.getrlimit(limit)
        if hard != resource.RLIM_INFINITY and hard < value:
            raise ReviewError(
                f"inherited {name} hard limit is below the qualification contract"
            )


def apply_candidate_resource_limits(policy: Mapping[str, Any]) -> None:
    """Apply the exact inherited limits before candidate execution."""

    limits = policy["limits"]
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(
        resource.RLIMIT_CPU,
        (limits["cpu_seconds"], limits["cpu_seconds"]),
    )
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (limits["file_bytes"], limits["file_bytes"]),
    )
    resource.setrlimit(
        resource.RLIMIT_NOFILE,
        (limits["open_files"], limits["open_files"]),
    )
    resource.setrlimit(
        resource.RLIMIT_NPROC,
        (limits["processes"], limits["processes"]),
    )


def _pid_exists(pid: int) -> bool:
    """Return true when a process identifier still names a process."""

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def sandbox_process_probe_paths(profile: Path) -> tuple[Path, Path]:
    """Return the two exact process-identity probe paths for one profile."""

    return (
        Path(f"{profile}{PROCESS_PROBE_DENY_SUFFIX}"),
        Path(f"{profile}{PROCESS_PROBE_ALLOW_SUFFIX}"),
    )


def _probe_identity(path: Path) -> tuple[int, int, int, int, int, int]:
    """Return fields that detect replacement of one process probe."""

    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReviewError(
            f"process-containment probe is unavailable: {path}"
        ) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o400
        or metadata.st_uid != os.getuid()
        or metadata.st_size != len(PROCESS_PROBE_BYTES)
    ):
        raise ReviewError(f"process-containment probe is invalid: {path}")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


@dataclass(frozen=True)
class SandboxProcessIdentity:
    """One exact inherited sandbox identity used for survivor discovery."""

    deny_path: Path
    allow_path: Path
    deny_identity: tuple[int, int, int, int, int, int]
    allow_identity: tuple[int, int, int, int, int, int]
    profile_path: Path
    profile_identity: tuple[int, int, int, int, int, int]
    filesystem_baselines: tuple[tuple[int, str, int], ...]

    @classmethod
    def from_profile(cls, profile: Path) -> SandboxProcessIdentity:
        """Load and validate the probes bound to one applied profile."""

        deny_path, allow_path = sandbox_process_probe_paths(profile)
        profile_bytes = read_bounded_regular_file(
            profile,
            max_bytes=1024 * 1024,
            label="candidate sandbox profile",
        )
        required_rules = (
            (
                f"(deny file-read* (literal {json.dumps(str(deny_path.resolve()))}))\n"
            ).encode(),
            (
                "(allow file-read* "
                f"(literal {json.dumps(str(allow_path.resolve()))}))\n"
            ).encode(),
        )
        if any(rule not in profile_bytes for rule in required_rules):
            raise ReviewError(
                "candidate sandbox profile lacks its process-containment rules"
            )
        resolved_profile = profile.resolve(strict=True)
        baselines = _PROFILE_FILESYSTEM_BASELINES.get(resolved_profile)
        if baselines is None:
            writable_paths = _sandbox_writable_paths(profile_bytes)
            baselines = _filesystem_baselines(writable_paths)
        return cls(
            deny_path=deny_path.resolve(strict=True),
            allow_path=allow_path.resolve(strict=True),
            deny_identity=_probe_identity(deny_path),
            allow_identity=_probe_identity(allow_path),
            profile_path=resolved_profile,
            profile_identity=_profile_identity(resolved_profile),
            filesystem_baselines=baselines,
        )

    def validate(self) -> None:
        """Reject probe replacement before or during process discovery."""

        if (
            _probe_identity(self.deny_path) != self.deny_identity
            or _probe_identity(self.allow_path) != self.allow_identity
            or _profile_identity(self.profile_path) != self.profile_identity
        ):
            raise ReviewError(
                "process-containment profile or probe changed during execution"
            )

    def enforce_filesystem_bound(self) -> None:
        """Reject excessive aggregate growth on a writable filesystem."""

        for expected_device, sample_text, initial_free in self.filesystem_baselines:
            sample = Path(sample_text)
            metadata = sample.stat()
            if metadata.st_dev != expected_device:
                raise ReviewError("candidate writable filesystem identity changed")
            statistics = os.statvfs(sample)
            current_free = statistics.f_bavail * statistics.f_frsize
            if current_free < MIN_FILESYSTEM_FREE_BYTES:
                raise ReviewError(
                    "candidate writable filesystem crossed its free-space reserve"
                )
            if initial_free - current_free > MAX_FILESYSTEM_GROWTH_BYTES:
                raise ReviewError(
                    "candidate writable filesystem exceeds its growth bound"
                )


def _profile_identity(path: Path) -> tuple[int, int, int, int, int, int]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.getuid()
        or metadata.st_size <= 0
        or metadata.st_size > 1024 * 1024
    ):
        raise ReviewError("candidate sandbox profile identity is invalid")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _sandbox_writable_paths(profile_bytes: bytes) -> tuple[Path, ...]:
    """Parse the exact generated write-subpath rules without Scheme evaluation."""

    prefix = "(allow file-write* (subpath "
    suffix = "))"
    paths: list[Path] = []
    try:
        text = profile_bytes.decode("utf-8", "strict")
        for line in text.splitlines():
            if not line.startswith(prefix):
                continue
            if not line.endswith(suffix):
                raise ReviewError("candidate sandbox write rule is malformed")
            value = json.loads(line[len(prefix) : -len(suffix)])
            if not isinstance(value, str):
                raise ReviewError("candidate sandbox write rule is malformed")
            path = Path(value)
            if not path.is_absolute() or ".." in path.parts:
                raise ReviewError("candidate sandbox write path is invalid")
            paths.append(path)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReviewError("candidate sandbox write rules are invalid") from error
    if not paths or len(paths) != len(set(paths)) or len(paths) > 32:
        raise ReviewError("candidate sandbox write-path set is invalid")
    return tuple(paths)


def _existing_filesystem_sample(path: Path) -> Path:
    sample = path
    while not sample.exists():
        if sample.parent == sample:
            raise ReviewError("candidate writable filesystem has no existing root")
        sample = sample.parent
    if sample.is_symlink():
        raise ReviewError("candidate writable filesystem sample is a symbolic link")
    return sample.resolve(strict=True)


def _filesystem_baselines(
    writable_paths: tuple[Path, ...],
) -> tuple[tuple[int, str, int], ...]:
    by_device: dict[int, tuple[str, int]] = {}
    for path in writable_paths:
        sample = _existing_filesystem_sample(path)
        metadata = sample.stat()
        statistics = os.statvfs(sample)
        free_bytes = statistics.f_bavail * statistics.f_frsize
        if free_bytes < MIN_FILESYSTEM_FREE_BYTES:
            raise ReviewError(
                "candidate writable filesystem lacks the required free-space reserve"
            )
        existing = by_device.get(metadata.st_dev)
        row = (str(sample), free_bytes)
        if existing is None or row[0] < existing[0]:
            by_device[metadata.st_dev] = row
    return tuple(
        (device, sample, free_bytes)
        for device, (sample, free_bytes) in sorted(by_device.items())
    )


class _ProcBsdShortInfo(ctypes.Structure):
    """Public Darwin PROC_PIDT_SHORTBSDINFO layout."""

    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("parent_pid", ctypes.c_uint32),
        ("process_group", ctypes.c_uint32),
        ("status", ctypes.c_uint32),
        ("command", ctypes.c_char * 16),
        ("flags", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("real_uid", ctypes.c_uint32),
        ("real_gid", ctypes.c_uint32),
        ("saved_uid", ctypes.c_uint32),
        ("saved_gid", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
    ]


class _ProcTaskInfo(ctypes.Structure):
    """Public Darwin PROC_PIDTASKINFO layout."""

    _fields_ = [
        ("virtual_size", ctypes.c_uint64),
        ("resident_size", ctypes.c_uint64),
        ("total_user", ctypes.c_uint64),
        ("total_system", ctypes.c_uint64),
        ("threads_user", ctypes.c_uint64),
        ("threads_system", ctypes.c_uint64),
        ("policy", ctypes.c_int32),
        ("faults", ctypes.c_int32),
        ("pageins", ctypes.c_int32),
        ("copy_on_write_faults", ctypes.c_int32),
        ("messages_sent", ctypes.c_int32),
        ("messages_received", ctypes.c_int32),
        ("mach_syscalls", ctypes.c_int32),
        ("unix_syscalls", ctypes.c_int32),
        ("context_switches", ctypes.c_int32),
        ("thread_count", ctypes.c_int32),
        ("running_threads", ctypes.c_int32),
        ("priority", ctypes.c_int32),
    ]


class MacOSProcessContainment:
    """Track one candidate process tree with kqueue and libproc."""

    def __init__(
        self,
        root_pid: int,
        sandbox_identity: SandboxProcessIdentity | None = None,
    ) -> None:
        if platform.system() != "Darwin" or not hasattr(select, "kqueue"):
            raise ReviewError("qualification process containment requires macOS kqueue")
        if root_pid <= 1 or root_pid == os.getpid():
            raise ReviewError("qualification process root is invalid")
        try:
            self._libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            self._list_children = self._libproc.proc_listchildpids
            self._list_children.argtypes = [
                ctypes.c_int,
                ctypes.c_void_p,
                ctypes.c_int,
            ]
            self._list_children.restype = ctypes.c_int
            self._list_all = self._libproc.proc_listallpids
            self._list_all.argtypes = [ctypes.c_void_p, ctypes.c_int]
            self._list_all.restype = ctypes.c_int
            self._pid_info = self._libproc.proc_pidinfo
            self._pid_info.argtypes = [
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_uint64,
                ctypes.c_void_p,
                ctypes.c_int,
            ]
            self._pid_info.restype = ctypes.c_int
            self._sandbox = ctypes.CDLL(
                "/usr/lib/libsandbox.1.dylib",
                use_errno=True,
            )
            self._sandbox_check = self._sandbox.sandbox_check
            self._sandbox_check.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint64,
            ]
            self._sandbox_check.restype = ctypes.c_int
            self._queue = select.kqueue()
        except (AttributeError, OSError) as error:
            raise ReviewError(
                f"cannot initialize macOS process containment: {error}"
            ) from error
        self.root_pid = root_pid
        self._sandbox_identity = sandbox_identity
        self._tracked: set[int] = set()
        self._exited: set[int] = set()
        self._closed = False
        self._register(root_pid)
        self.refresh()

    def _process_info(self, pid: int) -> _ProcBsdShortInfo | None:
        info = _ProcBsdShortInfo()
        size = self._pid_info(
            pid,
            13,
            0,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if size == ctypes.sizeof(info) and info.pid == pid:
            return info
        if not _pid_exists(pid):
            return None
        return None

    def _sandbox_matches(self, pid: int) -> bool:
        identity = self._sandbox_identity
        if identity is None or pid <= 1 or pid == os.getpid():
            return False
        sandboxed = self._sandbox_check(pid, None, 0)
        if sandboxed != 1:
            return False
        deny = self._sandbox_check(
            pid,
            b"file-read-data",
            1,
            ctypes.c_char_p(os.fsencode(identity.deny_path)),
        )
        allow = self._sandbox_check(
            pid,
            b"file-read-data",
            1,
            ctypes.c_char_p(os.fsencode(identity.allow_path)),
        )
        if deny != 1 or allow != 0:
            return False
        info = self._process_info(pid)
        if info is None:
            if _pid_exists(pid):
                raise ReviewError("cannot inspect a matching sandbox process identity")
            return False
        return info.uid == os.getuid() and info.status != 5

    def _sandbox_pids(self) -> set[int]:
        identity = self._sandbox_identity
        if identity is None:
            return set()
        identity.validate()
        buffer = (ctypes.c_int * MAX_SYSTEM_PROCESSES)()
        count = self._list_all(buffer, ctypes.sizeof(buffer))
        if count < 0 or count >= MAX_SYSTEM_PROCESSES:
            raise ReviewError("system process inventory exceeds its containment bound")
        return {
            int(buffer[index])
            for index in range(count)
            if self._sandbox_matches(int(buffer[index]))
        }

    def _resident_size(self, pid: int) -> int:
        info = _ProcTaskInfo()
        size = self._pid_info(
            pid,
            4,
            0,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if size == ctypes.sizeof(info):
            return int(info.resident_size)
        process_info = self._process_info(pid)
        if process_info is not None and process_info.status == 5:
            return 0
        if pid == self.root_pid:
            try:
                exit_status = os.waitid(
                    os.P_PID,
                    pid,
                    os.WEXITED | os.WNOHANG | os.WNOWAIT,
                )
            except ChildProcessError:
                exit_status = None
            if exit_status is not None:
                return 0
        if not _pid_exists(pid):
            return 0
        process_status = (
            "unavailable" if process_info is None else str(process_info.status)
        )
        raise ReviewError(
            f"cannot measure candidate resident memory for process {pid} "
            f"with status {process_status}"
        )

    def enforce_resource_bounds(self) -> None:
        """Enforce monitored process, memory, and filesystem limits."""

        if self._sandbox_identity is None:
            return
        self._sandbox_identity.enforce_filesystem_bound()
        pids = {
            pid for pid in self._tracked if pid not in self._exited and _pid_exists(pid)
        } | self._sandbox_pids()
        if len(pids) > MAX_TRACKED_PROCESSES:
            raise ReviewError("candidate process count exceeds its monitored bound")
        resident_size = sum(self._resident_size(pid) for pid in pids)
        if resident_size > MAX_AGGREGATE_RESIDENT_BYTES:
            raise ReviewError("candidate resident memory exceeds its aggregate bound")

    def sandbox_is_armed(self) -> bool:
        """Return true when the stopped root has the exact applied sandbox."""

        return self._sandbox_identity is not None and self._sandbox_matches(
            self.root_pid
        )

    def _register(self, pid: int) -> None:
        if pid in self._tracked or pid in self._exited:
            return
        if (
            pid <= 1
            or pid == os.getpid()
            or len(self._tracked) >= MAX_TRACKED_PROCESSES
        ):
            raise ReviewError("candidate process tree exceeds its containment bound")
        event = select.kevent(
            pid,
            filter=select.KQ_FILTER_PROC,
            flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
            fflags=select.KQ_NOTE_FORK | select.KQ_NOTE_EXIT,
        )
        try:
            self._queue.control([event], 0, 0)
        except OSError as error:
            if error.errno == errno.ESRCH and not _pid_exists(pid):
                self._exited.add(pid)
                return
            raise ReviewError(
                f"cannot register candidate process {pid}: {error}"
            ) from error
        self._tracked.add(pid)

    def _children(self, pid: int) -> tuple[int, ...]:
        buffer = (ctypes.c_int * MAX_TRACKED_PROCESSES)()
        ctypes.set_errno(0)
        count = self._list_children(pid, buffer, ctypes.sizeof(buffer))
        if count < 0:
            error_number = ctypes.get_errno()
            if error_number == errno.ESRCH or not _pid_exists(pid):
                self._exited.add(pid)
                return ()
            raise ReviewError(
                f"cannot inspect candidate descendants for process {pid}: "
                f"{os.strerror(error_number)}"
            )
        if count >= MAX_TRACKED_PROCESSES:
            raise ReviewError("candidate process tree exceeds its containment bound")
        children = tuple(int(buffer[index]) for index in range(count))
        if any(child <= 1 or child == os.getpid() for child in children):
            raise ReviewError("candidate process tree contains an invalid identifier")
        return children

    def _drain_events(self) -> None:
        while True:
            try:
                events = self._queue.control(None, MAX_TRACKED_PROCESSES, 0)
            except OSError as error:
                raise ReviewError(
                    f"cannot inspect candidate process events: {error}"
                ) from error
            if not events:
                return
            for event in events:
                pid = int(event.ident)
                if event.fflags & select.KQ_NOTE_EXIT:
                    self._exited.add(pid)
            if len(events) < MAX_TRACKED_PROCESSES:
                return

    def refresh(self) -> None:
        """Register descendants that macOS exposes during bounded polling."""

        self._drain_events()
        for pid in self._sandbox_pids():
            self._register(pid)
        while True:
            before = len(self._tracked)
            for pid in tuple(self._tracked - self._exited):
                for child in self._children(pid):
                    self._register(child)
            self._drain_events()
            if len(self._tracked) == before:
                return

    def _live_pids(self) -> set[int]:
        self.refresh()
        tracked = {
            pid for pid in self._tracked if pid not in self._exited and _pid_exists(pid)
        }
        return tracked | self._sandbox_pids()

    @staticmethod
    def _signal_group(process_group: int, signal_number: int) -> None:
        try:
            os.killpg(process_group, signal_number)
        except ProcessLookupError:
            pass
        except PermissionError as error:
            raise ReviewError(
                "permission denied while stopping a candidate process group"
            ) from error

    @staticmethod
    def _group_exists(process_group: int) -> bool:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    @staticmethod
    def _signal_pids(pids: set[int], signal_number: int) -> None:
        for pid in sorted(pids, reverse=True):
            try:
                os.kill(pid, signal_number)
            except ProcessLookupError:
                pass
            except PermissionError as error:
                raise ReviewError(
                    f"permission denied while stopping candidate process {pid}"
                ) from error

    def terminate(self, grace_seconds: float = 2.0) -> bool:
        """Stop the original process group and every observed escaped process."""

        live = self._live_pids()
        group_live = self._group_exists(self.root_pid)
        had_live_process = bool(live) or group_live
        if group_live:
            self._signal_group(self.root_pid, signal.SIGTERM)
        self._signal_pids(live, signal.SIGTERM)
        deadline = time.monotonic() + grace_seconds
        while time.monotonic() < deadline:
            if not self._live_pids() and not self._group_exists(self.root_pid):
                return had_live_process
            time.sleep(PROCESS_POLL_INTERVAL_SECONDS)
        live = self._live_pids()
        if self._group_exists(self.root_pid):
            self._signal_group(self.root_pid, signal.SIGKILL)
        self._signal_pids(live, signal.SIGKILL)
        deadline = time.monotonic() + grace_seconds
        while time.monotonic() < deadline:
            if not self._live_pids() and not self._group_exists(self.root_pid):
                return had_live_process
            time.sleep(PROCESS_POLL_INTERVAL_SECONDS)
        if self._live_pids() or self._group_exists(self.root_pid):
            raise ReviewError("candidate command left a persistent process")
        return had_live_process

    def close(self) -> None:
        if not self._closed:
            self._queue.close()
            self._closed = True


def _launch_gate_argv(
    argv: list[str] | tuple[str, ...],
    environment: Mapping[str, str] | None,
) -> list[str]:
    """Wrap a command in a host-controlled stop-before-exec launch gate."""

    if not argv:
        raise ReviewError("qualification command is empty")
    path = None if environment is None else environment.get("PATH")
    python = shutil.which("python3", path=path)
    if python is None or not Path(python).is_absolute():
        raise ReviewError("qualification launch gate cannot resolve python3")
    return [
        python,
        "-I",
        "-c",
        LAUNCH_GATE_SOURCE,
        "qualification-launch-gate",
        *argv,
    ]


def _sandbox_identity_from_argv(
    argv: list[str] | tuple[str, ...],
) -> SandboxProcessIdentity | None:
    """Load the process identity for an exact sandbox-exec invocation."""

    if (
        len(argv) >= 4
        and argv[0] == str(SANDBOX_EXECUTABLE)
        and argv[1] == "-f"
        and Path(argv[2]).is_absolute()
    ):
        return SandboxProcessIdentity.from_profile(Path(argv[2]))
    return None


def _sandbox_armed_argv(
    argv: list[str] | tuple[str, ...],
    environment: Mapping[str, str] | None,
    sandbox_identity: SandboxProcessIdentity | None,
) -> list[str]:
    """Add a second stop gate after the exact sandbox profile applies."""

    if sandbox_identity is None:
        return list(argv)
    path = None if environment is None else environment.get("PATH")
    python = shutil.which("python3", path=path)
    if python is None or not Path(python).is_absolute():
        raise ReviewError("sandbox launch gate cannot resolve python3")
    return [
        argv[0],
        argv[1],
        argv[2],
        python,
        "-I",
        "-c",
        LAUNCH_GATE_SOURCE,
        "sandbox-launch-gate",
        *argv[3:],
    ]


def _wait_for_launch_gate(process: subprocess.Popen[bytes]) -> None:
    """Wait until the host launch gate stops before candidate execution."""

    deadline = time.monotonic() + LAUNCH_GATE_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            waited_pid, status = os.waitpid(process.pid, os.WNOHANG | os.WUNTRACED)
        except ChildProcessError as error:
            raise ReviewError("qualification launch gate disappeared") from error
        if waited_pid == 0:
            time.sleep(0.01)
            continue
        if os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGSTOP:
            return
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            process.returncode = os.waitstatus_to_exitcode(status)
            raise ReviewError("qualification launch gate exited before it armed")
        raise ReviewError("qualification launch gate entered an invalid state")
    raise ReviewError("qualification launch gate did not arm before its timeout")


def _emergency_stop(process: subprocess.Popen[bytes]) -> None:
    """Kill and reap a process when containment cannot arm."""

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired as error:
        raise ReviewError("qualification launch gate could not be reaped") from error


def run_bounded_process(
    argv: list[str] | tuple[str, ...],
    *,
    cwd: Path,
    environment: Mapping[str, str] | None,
    timeout_seconds: int,
    separate_stderr: bool,
    max_stdout_bytes: int = MAX_COMMAND_STREAM_BYTES,
    max_stderr_bytes: int = MAX_COMMAND_STREAM_BYTES,
) -> BoundedProcessResult:
    """Run one command with bounded streams and fail-closed descendant cleanup."""

    if (
        type(max_stdout_bytes) is not int
        or type(max_stderr_bytes) is not int
        or not 0 <= max_stdout_bytes <= MAX_COMMAND_STREAM_BYTES
        or not 0 <= max_stderr_bytes <= MAX_COMMAND_STREAM_BYTES
    ):
        raise ReviewError("qualification stream bound is invalid")
    policy = execution_policy_contract(timeout_seconds)
    require_resource_limit_capacity(policy)
    sandbox_identity = _sandbox_identity_from_argv(argv)
    armed_argv = _sandbox_armed_argv(argv, environment, sandbox_identity)
    process = subprocess.Popen(
        _launch_gate_argv(armed_argv, environment),
        cwd=cwd,
        env=None if environment is None else dict(environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE if separate_stderr else subprocess.STDOUT,
        start_new_session=True,
        preexec_fn=functools.partial(apply_candidate_resource_limits, policy),
    )
    tracker: MacOSProcessContainment | None = None
    try:
        _wait_for_launch_gate(process)
        tracker = MacOSProcessContainment(process.pid, sandbox_identity)
        os.kill(process.pid, signal.SIGCONT)
        if sandbox_identity is not None:
            _wait_for_launch_gate(process)
            tracker.refresh()
            if not tracker.sandbox_is_armed():
                raise ReviewError(
                    "candidate sandbox process identity did not arm before execution"
                )
            tracker.enforce_resource_bounds()
            os.kill(process.pid, signal.SIGCONT)
    except (OSError, ReviewError) as error:
        detail = str(error)
        if tracker is not None:
            try:
                tracker.terminate()
            except ReviewError as cleanup_error:
                detail = f"{detail}; cleanup failed: {cleanup_error}"
            finally:
                tracker.close()
        _emergency_stop(process)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
        return BoundedProcessResult(
            returncode=process.returncode if process.returncode is not None else 2,
            timed_out=False,
            stdout=b"",
            stderr=b"",
            output_limit_exceeded=False,
            containment_error=detail,
        )
    except BaseException as error:
        if tracker is not None:
            try:
                tracker.terminate()
            except BaseException as cleanup_error:
                if hasattr(error, "add_note"):
                    error.add_note(
                        "candidate launch cleanup also failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
            finally:
                tracker.close()
        try:
            _emergency_stop(process)
        except BaseException as cleanup_error:
            if hasattr(error, "add_note"):
                error.add_note(
                    "candidate launch reap also failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
        raise

    if process.stdout is None or (separate_stderr and process.stderr is None):
        tracker.terminate()
        tracker.close()
        raise ReviewError("qualification process streams are unavailable")
    streams: dict[int, tuple[str, Any]] = {
        process.stdout.fileno(): ("stdout", process.stdout)
    }
    if separate_stderr and process.stderr is not None:
        streams[process.stderr.fileno()] = ("stderr", process.stderr)
    selector = selectors.DefaultSelector()
    for descriptor, (_name, stream) in streams.items():
        os.set_blocking(descriptor, False)
        selector.register(stream, selectors.EVENT_READ)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    bounds = {"stdout": max_stdout_bytes, "stderr": max_stderr_bytes}
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    output_limit_exceeded = False
    containment_error: str | None = None
    cleanup_started = False
    cleanup_deadline: float | None = None
    try:
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            if process.poll() is not None and not cleanup_started:
                cleanup_started = True
                cleanup_deadline = now + PROCESS_CLEANUP_TIMEOUT_SECONDS
                try:
                    if tracker.terminate():
                        containment_error = (
                            "candidate command left a process after its root exited"
                        )
                except ReviewError as error:
                    containment_error = str(error)
            if now >= deadline and not timed_out:
                timed_out = True
                cleanup_started = True
                cleanup_deadline = now + PROCESS_CLEANUP_TIMEOUT_SECONDS
                try:
                    tracker.terminate()
                except ReviewError as error:
                    containment_error = str(error)
            if not cleanup_started:
                try:
                    tracker.refresh()
                    tracker.enforce_resource_bounds()
                except ReviewError as error:
                    containment_error = str(error)
                    cleanup_started = True
                    cleanup_deadline = (
                        time.monotonic() + PROCESS_CLEANUP_TIMEOUT_SECONDS
                    )
                    try:
                        tracker.terminate()
                    except ReviewError as cleanup_error:
                        containment_error = (
                            f"{containment_error}; cleanup failed: {cleanup_error}"
                        )
            if (
                cleanup_started
                and cleanup_deadline is not None
                and time.monotonic() >= cleanup_deadline
            ):
                detail = "candidate process streams remained open after cleanup"
                containment_error = (
                    detail
                    if containment_error is None
                    else f"{containment_error}; {detail}"
                )
                for key in tuple(selector.get_map().values()):
                    selector.unregister(key.fileobj)
                break
            active_deadline = (
                cleanup_deadline
                if cleanup_started and cleanup_deadline is not None
                else deadline
            )
            wait_seconds = min(
                PROCESS_POLL_INTERVAL_SECONDS,
                max(0.001, active_deadline - time.monotonic()),
            )
            for key, _events in selector.select(wait_seconds):
                name = streams[key.fd][0]
                try:
                    block = os.read(key.fd, 64 * 1024)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                remaining = bounds[name] - len(buffers[name])
                if len(block) > remaining:
                    if remaining > 0:
                        buffers[name].extend(block[:remaining])
                    output_limit_exceeded = True
                    if not cleanup_started:
                        cleanup_started = True
                        cleanup_deadline = (
                            time.monotonic() + PROCESS_CLEANUP_TIMEOUT_SECONDS
                        )
                        try:
                            tracker.terminate()
                        except ReviewError as error:
                            containment_error = str(error)
                else:
                    buffers[name].extend(block)
        try:
            returncode = process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                tracker.terminate()
            except ReviewError as error:
                containment_error = str(error)
            try:
                process.kill()
            except (PermissionError, ProcessLookupError) as error:
                detail = f"cannot stop candidate root process: {error}"
                containment_error = (
                    detail
                    if containment_error is None
                    else f"{containment_error}; {detail}"
                )
            try:
                returncode = process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                detail = "candidate root process remained live after cleanup"
                containment_error = (
                    detail
                    if containment_error is None
                    else f"{containment_error}; {detail}"
                )
                returncode = process.poll()
                if returncode is None:
                    returncode = 2
        try:
            tracker.enforce_resource_bounds()
            if tracker.terminate():
                detail = "candidate command left a process after its root exited"
                containment_error = (
                    detail
                    if containment_error is None
                    else f"{containment_error}; {detail}"
                )
        except ReviewError as error:
            containment_error = (
                str(error)
                if containment_error is None
                else f"{containment_error}; final cleanup failed: {error}"
            )
    except BaseException as error:
        try:
            tracker.terminate()
        except BaseException as cleanup_error:
            if hasattr(error, "add_note"):
                error.add_note(
                    f"candidate cleanup also failed: {type(cleanup_error).__name__}: "
                    f"{cleanup_error}"
                )
        try:
            process.kill()
        except (PermissionError, ProcessLookupError):
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            if hasattr(error, "add_note"):
                error.add_note("candidate root process could not be reaped")
        raise
    finally:
        selector.close()
        process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
        tracker.close()
    return BoundedProcessResult(
        returncode=returncode,
        timed_out=timed_out,
        stdout=bytes(buffers["stdout"]),
        stderr=bytes(buffers["stderr"]),
        output_limit_exceeded=output_limit_exceeded,
        containment_error=containment_error,
    )


def write_receipt_log(
    path: Path,
    framed_output: bytes,
    receipt: dict[str, Any],
) -> dict[str, Any]:
    """Append a canonical non-self-referential receipt trailer and hash the log."""

    if "log_sha256" in receipt or "log_size_bytes" in receipt:
        raise ReviewError("receipt trailer contains a self-referential log field")
    trailer = {
        "schema": RECEIPT_TRAILER_SCHEMA,
        "receipt": receipt,
    }
    path.write_bytes(framed_output + RECEIPT_TRAILER_MARKER + canonical_json(trailer))
    digest, size = digest_file(path)
    return {**receipt, "log_sha256": digest, "log_size_bytes": size}


@dataclass
class AuxiliaryRunner:
    """Run and retain one sandboxed artifact-generation process."""

    environment: dict[str, str]
    sandbox_profile: Path
    logs: Path
    receipts: list[dict[str, Any]]

    def run(
        self,
        name: str,
        argv: list[str],
        *,
        cwd: Path,
        timeout_seconds: int = 3_600,
    ) -> tuple[bytes, bytes]:
        """Run one command with bounded streams and retain its exact receipt."""

        started_at = utc_now()
        started = time.monotonic()
        policy_sha256, policy_size = digest_file(self.sandbox_profile)
        if policy_size <= 0 or policy_size > 1024 * 1024:
            raise ReviewError("artifact-generation sandbox policy size is invalid")
        sandbox = {
            "executor": str(SANDBOX_EXECUTABLE),
            "policy_sha256": policy_sha256,
            "network_policy": "DENY",
        }
        cargo_home_value = self.environment.get("CARGO_HOME")
        if not isinstance(cargo_home_value, str) or not cargo_home_value:
            raise ReviewError("artifact-generation environment lacks CARGO_HOME")
        cargo_home = Path(cargo_home_value)
        reject_cargo_configuration(cwd, cargo_home)
        try:
            process_result = run_bounded_process(
                sandboxed_argv(self.sandbox_profile, argv),
                cwd=cwd,
                environment=self.environment,
                timeout_seconds=timeout_seconds,
                separate_stderr=True,
            )
        except BaseException:
            reject_cargo_configuration(cwd, cargo_home)
            raise
        policy_error: ReviewError | None = None
        try:
            reject_cargo_configuration(cwd, cargo_home)
            if digest_file(self.sandbox_profile) != (policy_sha256, policy_size):
                raise ReviewError("artifact-generation sandbox policy changed")
        except ReviewError as error:
            policy_error = error
        finished_at = utc_now()
        duration = time.monotonic() - started
        stderr = process_result.stderr
        if policy_error is not None:
            stderr += f"\nARTIFACT_GENERATION_POLICY_FAILURE: {policy_error}\n".encode(
                "utf-8"
            )
        log = self.logs / f"{len(self.receipts) + 1:02d}-{name}.log"
        header = {
            "argv": argv,
            "cwd": str(cwd.resolve()),
            "sandbox": sandbox,
            "started_at": started_at,
            "timeout_seconds": timeout_seconds,
        }
        status = (
            "PASS"
            if process_result.returncode == 0
            and not process_result.timed_out
            and not process_result.output_limit_exceeded
            and process_result.containment_error is None
            and policy_error is None
            else "FAIL"
        )
        receipt = {
            "name": name,
            "argv": argv,
            "cwd": str(cwd.resolve()),
            "sandbox": sandbox,
            "execution_policy": execution_policy_contract(timeout_seconds),
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": round(duration, 3),
            "timeout_seconds": timeout_seconds,
            "timed_out": process_result.timed_out,
            "exit_code": process_result.returncode,
            "status": status,
            "log": log.relative_to(self.logs.parent).as_posix(),
            "stdout_sha256": hashlib.sha256(process_result.stdout).hexdigest(),
            "stdout_size_bytes": len(process_result.stdout),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "stderr_size_bytes": len(stderr),
        }
        receipt = write_receipt_log(
            log,
            canonical_json(header)
            + b"--- stdout ---\n"
            + process_result.stdout
            + b"\n--- stderr ---\n"
            + stderr,
            receipt,
        )
        self.receipts.append(receipt)
        if policy_error is not None:
            raise ReviewError(
                f"artifact-generation policy failed: {name}: {policy_error}"
            )
        if process_result.containment_error is not None:
            raise ReviewError(
                f"artifact-generation containment failed: {name}: "
                f"{process_result.containment_error}"
            )
        if process_result.output_limit_exceeded:
            raise ReviewError(f"artifact-generation output exceeds its bound: {name}")
        if process_result.timed_out:
            raise ReviewError(f"artifact-generation command timed out: {name}")
        if process_result.returncode != 0:
            detail = stderr.decode("utf-8", "replace").strip()
            if not detail:
                detail = process_result.stdout.decode("utf-8", "replace").strip()
            raise ReviewError(f"artifact-generation command failed: {name}: {detail}")
        return process_result.stdout, process_result.stderr


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
            "repo_work.tests.test_package_release_assets",
            "repo_work.tests.test_review_tools",
            "repo_work.tests.test_task_dispositions",
            "repo_work.tests.test_release_assurance",
            "repo_work.tests.test_finalize_qualification",
            "repo_work.tests.test_qualification_artifacts",
            "repo_work.tests.test_host_process_bounds",
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
        "local-convergence-schema",
        ("python3", "repo_work/local_convergence.py", "schema", "--repo", "."),
    ),
    CommandSpec(
        "frozen-audit-inputs-verify",
        (
            "python3",
            "repo_work/freeze_audit_inputs.py",
            "verify",
            "--repo",
            ".",
            "--out",
            "release/0.9.0/audit/FROZEN-AUDIT-INPUTS-0.9.0.json",
            "--allowed-signers",
            ALLOWED_SIGNERS,
        ),
    ),
    CommandSpec(
        "release-audit-verify", ("python3", "scripts/release_audit.py", "verify")
    ),
    CommandSpec("fetch-locked-dependencies", ("cargo", "fetch", "--locked")),
    CommandSpec(
        "fetch-locked-fuzz-dependencies",
        ("cargo", "fetch", "--locked", "--manifest-path", "fuzz/Cargo.toml"),
    ),
    CommandSpec("format", ("cargo", "fmt", "--all", "--check")),
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
        "pure-core-no-default-test",
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
        "pure-core-no-default-build",
        (
            "cargo",
            "build",
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
            "+1.97.1",
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
            "+1.97.1",
            "test",
            "--workspace",
            "--all-features",
            "--locked",
        ),
    ),
    CommandSpec(
        "dependency-policy-workspace",
        ("cargo", "deny", "--offline", "--all-features", "--locked", "check"),
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
            "--offline",
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
            "--no-fetch",
            "--stale",
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


def network_command_preconditions_met(
    spec: CommandSpec,
    prior_results: list[dict[str, Any]],
) -> bool:
    """Permit the locked fetch only after every prior preflight passes."""

    if spec.name not in DEPENDENCY_FETCH_COMMAND_NAMES:
        return True
    if not prior_results:
        raise ReviewError("locked dependency fetch has no prior preflight")
    statuses = [result.get("status") for result in prior_results]
    if any(status not in {"PASS", "FAIL"} for status in statuses):
        raise ReviewError("qualification preflight has an invalid status")
    return all(status == "PASS" for status in statuses)


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


def write_atomic_canonical_json(path: Path, value: Any) -> None:
    """Replace one host-owned JSON record with complete canonical bytes."""

    payload = canonical_json(value)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise ReviewError(f"cannot completely write {path.name}")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary_path, path)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_descriptor = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)
        raise


def qualification_environment_contract(source_date_epoch: str) -> dict[str, Any]:
    """Return the exact signed policy for candidate command environments."""

    return {
        "schema": "galadriel.qualification-environment.v1",
        "base_keys": list(QUALIFICATION_ENVIRONMENT_KEYS),
        "cargo_config_policy": "REJECT_FILE_DIRECTORY_OR_LINK",
        "host_tool_inputs": ["HOME", "PATH", "RUSTUP_HOME"],
        "git_configuration_policy": "NO_SYSTEM_OR_GLOBAL_CONFIGURATION",
        "path_policy": "RESOLVED_REQUIRED_TOOL_DIRECTORIES",
        "path_tools": list(QUALIFICATION_PATH_TOOLS),
        "rustup_home_policy": "RUSTUP_HOME_OR_HOME_DOT_RUSTUP",
        "isolated_paths": list(ISOLATED_ENVIRONMENT_PATHS),
        "fixed_values": {
            "CARGO_INCREMENTAL": "0",
            "CARGO_TERM_COLOR": "never",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "SOURCE_DATE_EPOCH": source_date_epoch,
            "TZ": "UTC",
        },
    }


def build_qualification_environment(
    source: Mapping[str, str],
    *,
    private_root: Path,
    target: Path,
    source_date_epoch: str,
    required_path_tools: tuple[str, ...] = QUALIFICATION_PATH_TOOLS,
) -> dict[str, str]:
    """Build a minimal environment with isolated writable state."""

    if (
        not required_path_tools
        or len(required_path_tools) != len(set(required_path_tools))
        or any(
            not name
            or "/" in name
            or "\\" in name
            or any(ord(character) < 0x20 for character in name)
            for name in required_path_tools
        )
    ):
        raise ReviewError("qualification required-tool set is invalid")
    path_value = source.get("PATH")
    if not path_value:
        raise ReviewError("qualification environment requires PATH")
    path_parts = path_value.split(os.pathsep)
    if any(not part or not Path(part).is_absolute() for part in path_parts):
        raise ReviewError(
            "qualification PATH must contain only absolute nonempty entries"
        )
    resolved_tool_directories: list[str] = []
    for name in required_path_tools:
        resolved = shutil.which(name, path=path_value)
        if resolved is None or not Path(resolved).is_absolute():
            raise ReviewError(
                f"qualification PATH does not resolve required tool {name}"
            )
        directory = str(Path(resolved).parent)
        if directory not in resolved_tool_directories:
            resolved_tool_directories.append(directory)
    for directory in QUALIFICATION_SYSTEM_PATHS:
        if Path(directory).is_dir() and directory not in resolved_tool_directories:
            resolved_tool_directories.append(directory)
    controlled_path = os.pathsep.join(resolved_tool_directories)

    rustup_value = source.get("RUSTUP_HOME")
    if rustup_value is None:
        source_home = source.get("HOME")
        if not source_home or not Path(source_home).is_absolute():
            raise ReviewError(
                "qualification environment requires an absolute host HOME"
            )
        rustup_path = Path(source_home) / ".rustup"
    else:
        rustup_path = Path(rustup_value)
        if not rustup_path.is_absolute():
            raise ReviewError("qualification RUSTUP_HOME must be absolute")
    rustup_path = rustup_path.resolve(strict=False)

    private_root = private_root.resolve()
    target = target.resolve(strict=False)
    if target == private_root or private_root not in target.parents:
        raise ReviewError("qualification target must be inside the private root")
    isolated = {
        "HOME": private_root / "home",
        "CARGO_HOME": private_root / "cargo-home",
        "CARGO_TARGET_DIR": target,
        "TMPDIR": private_root / "tmp",
    }
    for path in isolated.values():
        path.mkdir(mode=0o700, parents=False, exist_ok=False)

    environment = {
        "CARGO_HOME": str(isolated["CARGO_HOME"]),
        "CARGO_INCREMENTAL": "0",
        "CARGO_TARGET_DIR": str(isolated["CARGO_TARGET_DIR"]),
        "CARGO_TERM_COLOR": "never",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(isolated["HOME"]),
        "LC_ALL": "C",
        "PATH": controlled_path,
        "RUSTUP_HOME": str(rustup_path),
        "SOURCE_DATE_EPOCH": source_date_epoch,
        "TMPDIR": str(isolated["TMPDIR"]),
        "TZ": "UTC",
    }
    if tuple(environment) != QUALIFICATION_ENVIRONMENT_KEYS:
        raise ReviewError("qualification environment key order drifted")
    return environment


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ReviewError(
            f"cannot inspect Cargo configuration path {path}: {error}"
        ) from error


def reject_cargo_configuration(cwd: Path, cargo_home: Path) -> None:
    """Reject every ambient Cargo configuration file or link."""

    cwd = cwd.resolve()
    cargo_home = cargo_home.absolute()
    cargo_home_metadata = _lstat(cargo_home)
    if cargo_home_metadata is None or not stat.S_ISDIR(cargo_home_metadata.st_mode):
        raise ReviewError(
            f"isolated Cargo home is missing or not a direct directory: {cargo_home}"
        )
    search_directories = (cwd, *cwd.parents)
    cargo_directories = [directory / ".cargo" for directory in search_directories]
    cargo_directories.append(cargo_home)
    seen: set[Path] = set()
    for cargo_directory in cargo_directories:
        if cargo_directory in seen:
            continue
        seen.add(cargo_directory)
        metadata = _lstat(cargo_directory)
        if metadata is None:
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            raise ReviewError(
                f"Cargo configuration directory is not a direct directory: {cargo_directory}"
            )
        for name in ("config", "config.toml"):
            candidate = cargo_directory / name
            if _lstat(candidate) is not None:
                raise ReviewError(
                    f"ambient Cargo configuration is forbidden: {candidate}"
                )


def capture(
    argv: list[str],
    cwd: Path,
    *,
    environment: Mapping[str, str] | None = None,
    sandbox_profile: Path | None = None,
    timeout_seconds: int = 30,
    max_bytes: int = MAX_CAPTURE_BYTES,
) -> str:
    """Capture one required identity command without shell interpretation."""

    process = run_bounded_process(
        argv if sandbox_profile is None else sandboxed_argv(sandbox_profile, argv),
        cwd=cwd,
        environment=environment,
        timeout_seconds=timeout_seconds,
        separate_stderr=False,
        max_stdout_bytes=max_bytes,
    )
    output = process.stdout.decode("utf-8", "replace").strip()
    if process.containment_error is not None:
        raise ReviewError(
            f"{' '.join(argv)} containment failed: {process.containment_error}"
        )
    if process.output_limit_exceeded:
        raise ReviewError(f"{' '.join(argv)} output exceeds {max_bytes} bytes")
    if process.timed_out:
        raise ReviewError(f"{' '.join(argv)} timed out")
    if process.returncode != 0:
        raise ReviewError(f"{' '.join(argv)} failed: {output}")
    return output


def repository_control_snapshot(repo: Path) -> dict[str, str]:
    """Fingerprint candidate-relevant Git state without retaining configuration."""

    assert_no_replace_refs(repo)
    return {
        "head": str(git(repo, "rev-parse", "HEAD^{commit}")).strip(),
        "tree": str(git(repo, "rev-parse", "HEAD^{tree}")).strip(),
        "status_sha256": hashlib.sha256(
            bytes(
                git(
                    repo,
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=all",
                    "-z",
                    text=False,
                )
            )
        ).hexdigest(),
        "refs_sha256": hashlib.sha256(
            bytes(
                git(
                    repo,
                    "for-each-ref",
                    "--format=%(refname)%00%(objectname)%00%(objecttype)%00",
                    text=False,
                )
            )
        ).hexdigest(),
        "local_config_sha256": hashlib.sha256(
            bytes(git(repo, "config", "--local", "--null", "--list", text=False))
        ).hexdigest(),
    }


def _tree_metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Return fields that detect replacement or mutation during a tree walk."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _safe_tree_name(name: str, label: str) -> None:
    """Reject a directory entry name that cannot form a safe retained path."""

    try:
        name.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise ReviewError(f"{label} contains a non-UTF-8 path") from error
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or any(ord(character) < 0x20 for character in name)
    ):
        raise ReviewError(f"{label} contains an unsafe path")


def read_regular_descriptor(
    descriptor: int,
    *,
    expected_size: int,
    max_bytes: int,
    label: str,
) -> bytes:
    """Read one held regular-file descriptor through an exact byte bound."""

    if expected_size < 0 or expected_size > max_bytes:
        raise ReviewError(f"{label} exceeds its byte limit")
    os.lseek(descriptor, 0, os.SEEK_SET)
    payload = bytearray()
    while len(payload) <= expected_size:
        block = os.read(
            descriptor,
            min(1024 * 1024, expected_size + 1 - len(payload)),
        )
        if not block:
            break
        payload.extend(block)
        if len(payload) > expected_size:
            raise ReviewError(f"{label} changed size while read")
    if len(payload) != expected_size:
        raise ReviewError(f"{label} changed size while read")
    return bytes(payload)


def digest_regular_descriptor(
    descriptor: int,
    *,
    expected_size: int,
    label: str,
) -> tuple[str, int]:
    """Hash one held regular-file descriptor through its exact size."""

    digest = hashlib.sha256()
    size = 0
    os.lseek(descriptor, 0, os.SEEK_SET)
    while size <= expected_size:
        block = os.read(
            descriptor,
            min(1024 * 1024, expected_size + 1 - size),
        )
        if not block:
            break
        size += len(block)
        if size > expected_size:
            raise ReviewError(f"{label} changed size while hashed")
        digest.update(block)
    if size != expected_size:
        raise ReviewError(f"{label} changed size while hashed")
    return digest.hexdigest(), size


def walk_bounded_tree(
    root: Path,
    *,
    label: str,
    max_entries: int,
    max_depth: int,
    on_regular: Callable[[str, int, os.stat_result], None],
    on_directory: Callable[[str], None] | None = None,
    on_symlink: Callable[[str, str], None] | None = None,
    reject_empty_directories: bool = False,
    excluded_root_names: frozenset[str] = frozenset(),
) -> None:
    """Walk one bounded tree through held no-follow directory descriptors."""

    if max_entries <= 0 or max_depth < 0:
        raise ReviewError(f"{label} traversal limits are invalid")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise ReviewError(f"{label} no-follow traversal is unavailable")
    base_flags = os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0)
    try:
        root_descriptor = os.open(root, base_flags | directory_flag)
    except OSError as error:
        raise ReviewError(f"{label} root is missing or unsafe: {error}") from error
    root_before = os.fstat(root_descriptor)
    entry_count = 0

    def visit(
        directory_descriptor: int,
        prefix: tuple[str, ...],
        depth: int,
    ) -> None:
        nonlocal entry_count
        names: list[str] = []
        try:
            with os.scandir(directory_descriptor) as entries:
                for entry in entries:
                    name = entry.name
                    if not prefix and name in excluded_root_names:
                        continue
                    _safe_tree_name(name, label)
                    if entry_count + len(names) >= max_entries:
                        raise ReviewError(f"{label} exceeds its entry-count limit")
                    names.append(name)
        except ReviewError:
            raise
        except OSError as error:
            raise ReviewError(f"cannot completely inventory {label}") from error
        names.sort()
        entry_count += len(names)
        if prefix and reject_empty_directories and not names:
            raise ReviewError(
                f"{label} contains an empty directory: {'/'.join(prefix)}"
            )
        for name in names:
            relative_parts = (*prefix, name)
            relative = "/".join(relative_parts)
            try:
                before = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise ReviewError(
                    f"{label} entry changed during traversal: {relative}"
                ) from error
            if stat.S_ISDIR(before.st_mode):
                if depth >= max_depth:
                    raise ReviewError(f"{label} exceeds its directory-depth limit")
                try:
                    child_descriptor = os.open(
                        name,
                        base_flags | directory_flag,
                        dir_fd=directory_descriptor,
                    )
                except OSError as error:
                    raise ReviewError(
                        f"{label} directory changed during traversal: {relative}"
                    ) from error
                try:
                    opened = os.fstat(child_descriptor)
                    if _tree_metadata_identity(opened) != _tree_metadata_identity(
                        before
                    ):
                        raise ReviewError(
                            f"{label} directory changed during traversal: {relative}"
                        )
                    if on_directory is not None:
                        on_directory(relative)
                    visit(child_descriptor, relative_parts, depth + 1)
                    after = os.fstat(child_descriptor)
                    if _tree_metadata_identity(after) != _tree_metadata_identity(
                        opened
                    ):
                        raise ReviewError(
                            f"{label} directory changed during traversal: {relative}"
                        )
                finally:
                    os.close(child_descriptor)
                continue
            if stat.S_ISREG(before.st_mode):
                try:
                    descriptor = os.open(
                        name,
                        base_flags | getattr(os, "O_NONBLOCK", 0),
                        dir_fd=directory_descriptor,
                    )
                except OSError as error:
                    raise ReviewError(
                        f"{label} file changed during traversal: {relative}"
                    ) from error
                try:
                    opened = os.fstat(descriptor)
                    if not stat.S_ISREG(opened.st_mode) or _tree_metadata_identity(
                        opened
                    ) != _tree_metadata_identity(before):
                        raise ReviewError(
                            f"{label} file changed during traversal: {relative}"
                        )
                    on_regular(relative, descriptor, opened)
                    after = os.fstat(descriptor)
                    if _tree_metadata_identity(after) != _tree_metadata_identity(
                        opened
                    ):
                        raise ReviewError(
                            f"{label} file changed during traversal: {relative}"
                        )
                finally:
                    os.close(descriptor)
                continue
            if stat.S_ISLNK(before.st_mode) and on_symlink is not None:
                try:
                    target = os.readlink(name, dir_fd=directory_descriptor)
                    after = os.stat(
                        name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                except OSError as error:
                    raise ReviewError(
                        f"{label} link changed during traversal: {relative}"
                    ) from error
                if _tree_metadata_identity(after) != _tree_metadata_identity(before):
                    raise ReviewError(
                        f"{label} link changed during traversal: {relative}"
                    )
                on_symlink(relative, target)
                continue
            kind = "symbolic link" if stat.S_ISLNK(before.st_mode) else "special file"
            raise ReviewError(f"{label} contains a {kind}: {relative}")

    try:
        visit(root_descriptor, (), 0)
        root_after = os.fstat(root_descriptor)
        if _tree_metadata_identity(root_after) != _tree_metadata_identity(root_before):
            raise ReviewError(f"{label} root changed during traversal")
    finally:
        os.close(root_descriptor)


def verify_materialized_candidate(worktree: Path, commit: str, tree: str) -> None:
    """Require exact index and file bytes for one detached candidate clone."""

    assert_no_replace_refs(worktree)
    if str(git(worktree, "rev-parse", "HEAD^{commit}")).strip() != commit:
        raise ReviewError("standalone candidate clone has another commit")
    if str(git(worktree, "rev-parse", "HEAD^{tree}")).strip() != tree:
        raise ReviewError("standalone candidate clone has another tree")
    status = bytes(
        git(
            worktree,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "-z",
            text=False,
        )
    )
    if status:
        raise ReviewError("standalone candidate clone is not exact and clean")

    inventory = git_tree_inventory(worktree, commit)
    index_raw = bytes(git(worktree, "ls-files", "--stage", "-z", text=False))
    indexed: dict[str, tuple[str, str]] = {}
    for encoded in index_raw.split(b"\0"):
        if not encoded:
            continue
        metadata, path_bytes = encoded.split(b"\t", 1)
        mode, object_id, stage = metadata.decode("ascii").split()
        path = path_bytes.decode("utf-8", "surrogateescape")
        if stage != "0" or path in indexed:
            raise ReviewError(f"candidate index has a non-stage-zero entry: {path}")
        indexed[path] = (mode, object_id)
    expected_index = {
        path: (entry["mode"], entry["git_blob_id"]) for path, entry in inventory.items()
    }
    if indexed != expected_index:
        raise ReviewError("candidate index differs from the exact candidate tree")

    observed: set[str] = set()
    for path, entry in inventory.items():
        target = worktree / path
        try:
            metadata = target.lstat()
        except OSError as error:
            raise ReviewError(
                f"cannot inspect candidate path {path}: {error}"
            ) from error
        mode = entry["mode"]
        if mode == "120000":
            if not stat.S_ISLNK(metadata.st_mode):
                raise ReviewError(f"candidate symbolic link changed type: {path}")
            data = os.readlink(target).encode("utf-8", "surrogateescape")
        elif mode in {"100644", "100755"}:
            if not stat.S_ISREG(metadata.st_mode) or target.is_symlink():
                raise ReviewError(f"candidate file changed type: {path}")
            executable = bool(metadata.st_mode & 0o111)
            if executable != (mode == "100755"):
                raise ReviewError(f"candidate file changed executable mode: {path}")
            try:
                data = target.read_bytes()
            except OSError as error:
                raise ReviewError(
                    f"cannot read candidate path {path}: {error}"
                ) from error
        else:
            raise ReviewError(f"candidate tree has unsupported mode {mode}: {path}")
        if (
            len(data) != entry["bytes"]
            or hashlib.sha256(data).hexdigest() != entry["sha256"]
        ):
            raise ReviewError(f"candidate materialized bytes differ from Git: {path}")
        observed.add(path)

    materialized: set[str] = set()

    def record_materialized(
        relative: str,
        _descriptor: int,
        _metadata: os.stat_result,
    ) -> None:
        materialized.add(relative)

    def record_materialized_link(relative: str, _target: str) -> None:
        materialized.add(relative)

    walk_bounded_tree(
        worktree,
        label="materialized candidate clone",
        max_entries=MAX_QUALIFICATION_ENTRIES,
        max_depth=MAX_QUALIFICATION_DEPTH,
        on_regular=record_materialized,
        on_symlink=record_materialized_link,
        excluded_root_names=frozenset({".git"}),
    )
    if materialized != observed:
        raise ReviewError(
            "candidate clone has missing or additional materialized paths"
        )


def create_standalone_candidate_clone(
    repo: Path,
    destination: Path,
    *,
    commit: str,
    tree: str,
) -> None:
    """Create an independent no-local clone and verify its exact candidate bytes."""

    clone_argv = [
        "git",
        "--no-replace-objects",
        *SAFE_GIT_CONFIGURATION,
        "clone",
        "--no-local",
        "--no-checkout",
        "--origin",
        "origin",
        "--",
        str(repo),
        str(destination),
    ]
    process = run_bounded_process(
        clone_argv,
        cwd=repo.parent,
        environment=safe_git_environment(),
        timeout_seconds=600,
        separate_stderr=False,
    )
    if (
        process.returncode != 0
        or process.timed_out
        or process.output_limit_exceeded
        or process.containment_error is not None
    ):
        detail = process.stdout.decode("utf-8", "replace").strip()
        raise ReviewError(f"cannot create standalone candidate clone: {detail}")
    git(destination, "config", "--local", "core.hooksPath", os.devnull)
    git(destination, "config", "--local", "core.attributesFile", os.devnull)
    info_attributes = destination / ".git" / "info" / "attributes"
    if info_attributes.exists() or info_attributes.is_symlink():
        raise ReviewError("standalone candidate clone has repository-local attributes")
    local_configuration = bytes(
        git(destination, "config", "--local", "--null", "--list", text=False)
    )
    if b"filter." in local_configuration.lower():
        raise ReviewError("standalone candidate clone has a configured content filter")
    git(destination, "checkout", "--detach", "--force", commit)
    verify_materialized_candidate(destination, commit, tree)


def install_pinned_advisory_database(
    source: Path, cargo_home: Path
) -> tuple[dict[str, Any], tuple[Path, Path]]:
    """Install one exact RustSec database for cargo-audit and cargo-deny."""

    source = source.resolve()
    assert_no_replace_refs(source)
    if str(git(source, "status", "--porcelain=v1", "--untracked-files=all")).strip():
        raise ReviewError("RustSec advisory database source is dirty")
    if str(git(source, "rev-parse", "HEAD^{commit}")).strip() != ADVISORY_DB_COMMIT:
        raise ReviewError("RustSec advisory database source has another commit")
    if str(git(source, "rev-parse", "HEAD^{tree}")).strip() != ADVISORY_DB_TREE:
        raise ReviewError("RustSec advisory database source has another tree")
    origin = (
        str(git(source, "remote", "get-url", "origin")).strip().removesuffix(".git")
    )
    if origin != ADVISORY_DB_URL:
        raise ReviewError("RustSec advisory database source has another origin")

    audit_database = cargo_home / "advisory-db"
    deny_database = cargo_home / "advisory-dbs" / ADVISORY_DB_DENY_DIRECTORY
    deny_database.parent.mkdir(mode=0o700)
    create_standalone_candidate_clone(
        source,
        audit_database,
        commit=ADVISORY_DB_COMMIT,
        tree=ADVISORY_DB_TREE,
    )
    create_standalone_candidate_clone(
        source,
        deny_database,
        commit=ADVISORY_DB_COMMIT,
        tree=ADVISORY_DB_TREE,
    )
    inventory = git_tree_inventory(audit_database, ADVISORY_DB_COMMIT)
    inventory_rows = [
        {
            "path": path,
            "mode": item["mode"],
            "git_blob_id": item["git_blob_id"],
            "sha256": item["sha256"],
            "size_bytes": item["bytes"],
        }
        for path, item in sorted(inventory.items())
    ]
    return (
        {
            "url": ADVISORY_DB_URL,
            "commit": ADVISORY_DB_COMMIT,
            "tree": ADVISORY_DB_TREE,
            "inventory_sha256": hashlib.sha256(
                canonical_json(inventory_rows)
            ).hexdigest(),
            "entries": len(inventory_rows),
            "fetch_policy": "PINNED_OFFLINE_NO_FETCH",
        },
        (audit_database, deny_database),
    )


def qualification_tool_read_paths(
    environment: Mapping[str, str],
    *,
    host_home: Path,
) -> tuple[Path, ...]:
    """Return minimal non-system roots for resolved qualification tools."""

    system_roots = tuple(Path(path) for path in SANDBOX_SYSTEM_READ_PATHS)
    paths: set[Path] = set()
    for name in QUALIFICATION_PATH_TOOLS:
        invoked_text = shutil.which(name, path=environment["PATH"])
        if invoked_text is None:
            raise ReviewError(f"qualification PATH does not resolve {name}")
        invoked = Path(invoked_text)
        resolved = invoked.resolve(strict=True)
        for path in (invoked.parent.resolve(strict=True), resolved.parent):
            if any(path == root or root in path.parents for root in system_roots):
                continue
            if path == host_home or host_home in path.parents:
                paths.add(path)
                continue
            parts = path.parts
            if len(parts) >= 3 and parts[:2] == ("/", "opt"):
                paths.add(Path("/", "opt", parts[2]))
            elif len(parts) >= 3 and parts[:3] == ("/", "usr", "local"):
                paths.add(Path("/usr/local"))
            else:
                paths.add(path)
    return tuple(sorted(paths, key=lambda item: str(item)))


def render_candidate_sandbox_profile(
    *,
    worktree: Path,
    source_repo: Path,
    host_home: Path,
    read_only_paths: tuple[Path, ...] = (),
    writable_paths: tuple[Path, ...] = (),
    allowed_home_read_paths: tuple[Path, ...] = (),
    tool_read_paths: tuple[Path, ...] = (),
    denied_read_paths: tuple[Path, ...] = (),
    process_probe_paths: tuple[Path, Path],
    allow_network: bool = False,
) -> bytes:
    """Render one exact macOS candidate policy from normalized path bindings."""

    deny_probe, allow_probe = process_probe_paths
    system_read_paths = tuple(Path(path) for path in SANDBOX_SYSTEM_READ_PATHS)
    readable_paths = (
        *system_read_paths,
        worktree,
        *read_only_paths,
        *writable_paths,
        *allowed_home_read_paths,
        *tool_read_paths,
    )
    read_ancestors: set[Path] = set()
    for readable_path in readable_paths:
        ancestor = readable_path.parent
        while True:
            read_ancestors.add(ancestor)
            if ancestor == ancestor.parent:
                break
            ancestor = ancestor.parent
    rules = [
        "(version 1)",
        "(allow default)",
        "(deny file-read*)",
        "(deny file-write*)",
        '(allow file-write* (literal "/dev/null"))',
        f"(allow file-read* (literal {json.dumps(str(allow_probe))}))",
        f"(deny file-read* (subpath {json.dumps(str(host_home))}))",
        f"(deny file-write* (subpath {json.dumps(str(worktree))}))",
        f"(deny file-read* (subpath {json.dumps(str(source_repo))}))",
        f"(deny file-write* (subpath {json.dumps(str(source_repo))}))",
    ]
    if not allow_network:
        rules.append("(deny network*)")
    rules.extend(
        f"(allow file-write* (subpath {json.dumps(str(path))}))"
        for path in writable_paths
    )
    rules.extend(
        f"(deny file-write* (subpath {json.dumps(str(path))}))"
        for path in read_only_paths
    )
    rules.extend(
        f"(allow file-read* (literal {json.dumps(str(path))}))"
        for path in sorted(read_ancestors, key=lambda item: str(item))
    )
    rules.extend(
        f"(allow file-read* (subpath {json.dumps(str(path))}))"
        for path in readable_paths
    )
    rules.extend(
        f"(deny file-read* (subpath {json.dumps(str(path))}))"
        for path in denied_read_paths
    )
    rules.append(f"(deny file-read* (literal {json.dumps(str(deny_probe))}))")
    return "\n".join((*rules, "")).encode("utf-8")


def _create_process_probe(path: Path) -> None:
    """Create one immutable host-owned process-containment probe."""

    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o400)
        try:
            offset = 0
            while offset < len(PROCESS_PROBE_BYTES):
                written = os.write(descriptor, PROCESS_PROBE_BYTES[offset:])
                if written <= 0:
                    raise ReviewError(
                        "cannot completely write a process-containment probe"
                    )
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ReviewError(
            f"cannot create process-containment probe: {path}: {error}"
        ) from error
    if _probe_identity(path)[3] != len(PROCESS_PROBE_BYTES):
        raise ReviewError("process-containment probe has another size")


def write_candidate_sandbox_profile(
    destination: Path,
    *,
    worktree: Path,
    source_repo: Path,
    read_only_paths: tuple[Path, ...] = (),
    writable_paths: tuple[Path, ...] = (),
    allowed_home_read_paths: tuple[Path, ...] = (),
    tool_read_paths: tuple[Path, ...] = (),
    denied_read_paths: tuple[Path, ...] = (),
    allow_network: bool = False,
) -> str:
    """Write a macOS policy with an exact candidate-write allowlist."""

    if not SANDBOX_EXECUTABLE.is_file():
        raise ReviewError("qualification requires /usr/bin/sandbox-exec")
    worktree = worktree.resolve()
    source_repo = source_repo.resolve()
    resolved_read_only_paths = tuple(path.resolve() for path in read_only_paths)
    resolved_writable_paths = tuple(path.resolve() for path in writable_paths)
    resolved_home_read_paths = tuple(path.resolve() for path in allowed_home_read_paths)
    resolved_tool_read_paths = tuple(path.resolve() for path in tool_read_paths)
    resolved_denied_read_paths = tuple(path.resolve() for path in denied_read_paths)
    host_home = Path.home().resolve()
    process_probe_paths = sandbox_process_probe_paths(destination)
    for probe in process_probe_paths:
        _create_process_probe(probe)
    resolved_process_probe_paths = tuple(
        path.resolve(strict=True) for path in process_probe_paths
    )
    for path in resolved_writable_paths:
        if (
            path == worktree
            or worktree in path.parents
            or path in worktree.parents
            or path == source_repo
            or source_repo in path.parents
            or path in source_repo.parents
        ):
            raise ReviewError("sandbox writable path overlaps a source repository")
    for path in (*resolved_home_read_paths, *resolved_tool_read_paths):
        if (
            path == source_repo
            or source_repo in path.parents
            or path in source_repo.parents
        ):
            raise ReviewError("sandbox tool-read path overlaps the operator repository")
    profile = render_candidate_sandbox_profile(
        worktree=worktree,
        source_repo=source_repo,
        host_home=host_home,
        read_only_paths=resolved_read_only_paths,
        writable_paths=resolved_writable_paths,
        allowed_home_read_paths=resolved_home_read_paths,
        tool_read_paths=resolved_tool_read_paths,
        denied_read_paths=resolved_denied_read_paths,
        process_probe_paths=resolved_process_probe_paths,
        allow_network=allow_network,
    )
    destination.write_bytes(profile)
    os.chmod(destination, 0o600)
    _PROFILE_FILESYSTEM_BASELINES[destination.resolve(strict=True)] = (
        _filesystem_baselines(resolved_writable_paths)
    )
    return hashlib.sha256(profile).hexdigest()


def sandboxed_argv(profile: Path, argv: tuple[str, ...] | list[str]) -> list[str]:
    """Wrap one candidate-controlled command in the frozen host sandbox."""

    return [str(SANDBOX_EXECUTABLE), "-f", str(profile), *argv]


def executable_file_identity(path: Path) -> dict[str, Any]:
    """Bind one resolved executable to immutable bytes during the run."""

    invoked = path
    try:
        resolved = invoked.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise ReviewError(
            f"cannot inspect qualification executable {path}: {error}"
        ) from error
    if not resolved.is_file() or resolved.is_symlink():
        raise ReviewError(f"qualification executable is not a regular file: {resolved}")
    if not metadata.st_mode & stat.S_IXUSR:
        raise ReviewError(
            f"qualification executable is not owner-executable: {resolved}"
        )
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ReviewError(
            f"qualification executable is group- or world-writable: {resolved}"
        )
    if metadata.st_size <= 0 or metadata.st_size > MAX_QUALIFICATION_EXECUTABLE_BYTES:
        raise ReviewError(f"qualification executable size is invalid: {resolved}")
    digest, size = digest_file(resolved)
    try:
        metadata_after = resolved.stat()
    except OSError as error:
        raise ReviewError(
            f"cannot recheck qualification executable {resolved}: {error}"
        ) from error
    if (
        size != metadata.st_size
        or metadata_after.st_dev != metadata.st_dev
        or metadata_after.st_ino != metadata.st_ino
        or metadata_after.st_size != metadata.st_size
        or metadata_after.st_mtime_ns != metadata.st_mtime_ns
        or metadata_after.st_mode != metadata.st_mode
    ):
        raise ReviewError(f"qualification executable changed while hashed: {resolved}")
    return {
        "invoked_path": str(invoked),
        "resolved_path": str(resolved),
        "sha256": digest,
        "size_bytes": size,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
    }


def qualification_tool_files(
    environment: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Resolve and hash every executable used by qualification."""

    path = environment["PATH"]
    result: dict[str, dict[str, Any]] = {}
    for name in QUALIFICATION_PATH_TOOLS:
        resolved = shutil.which(name, path=path)
        if resolved is None:
            raise ReviewError(f"qualification PATH does not resolve {name}")
        result[name] = executable_file_identity(Path(resolved))
    result["sandbox-exec"] = executable_file_identity(SANDBOX_EXECUTABLE)
    rustup_commands = {
        "rustc-1.89.0": ["rustup", "which", "rustc", "--toolchain", "1.89.0"],
        "cargo-1.89.0": ["rustup", "which", "cargo", "--toolchain", "1.89.0"],
        "rustc-1.97.1": ["rustup", "which", "rustc", "--toolchain", "1.97.1"],
        "cargo-1.97.1": ["rustup", "which", "cargo", "--toolchain", "1.97.1"],
        "rustc-nightly-2026-06-16": [
            "rustup",
            "which",
            "rustc",
            "--toolchain",
            "nightly-2026-06-16",
        ],
        "cargo-nightly-2026-06-16": [
            "rustup",
            "which",
            "cargo",
            "--toolchain",
            "nightly-2026-06-16",
        ],
        "rustdoc-nightly-2026-06-16": [
            "rustup",
            "which",
            "rustdoc",
            "--toolchain",
            "nightly-2026-06-16",
        ],
        "rustdoc-1.89.0": [
            "rustup",
            "which",
            "rustdoc",
            "--toolchain",
            "1.89.0",
        ],
        "rustfmt-1.89.0": [
            "rustup",
            "which",
            "rustfmt",
            "--toolchain",
            "1.89.0",
        ],
        "clippy-driver-1.89.0": [
            "rustup",
            "which",
            "clippy-driver",
            "--toolchain",
            "1.89.0",
        ],
        "rustdoc-1.97.1": [
            "rustup",
            "which",
            "rustdoc",
            "--toolchain",
            "1.97.1",
        ],
        "clippy-driver-1.97.1": [
            "rustup",
            "which",
            "clippy-driver",
            "--toolchain",
            "1.97.1",
        ],
    }
    for name, argv in rustup_commands.items():
        output = capture(argv, Path.cwd(), environment=environment)
        if "\n" in output or not Path(output).is_absolute():
            raise ReviewError(f"rustup returned an invalid path for {name}")
        result[name] = executable_file_identity(Path(output))
    return result


def run_command(
    spec: CommandSpec,
    *,
    worktree: Path,
    commit: str,
    tree: str,
    clone_control: dict[str, str],
    sandbox_profile: Path,
    dependency_fetch_sandbox_profile: Path | None = None,
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
    policy_error: ReviewError | None = None
    output_limit_exceeded = False
    returncode = 2
    selected_sandbox_profile = (
        dependency_fetch_sandbox_profile
        if spec.name in DEPENDENCY_FETCH_COMMAND_NAMES
        and dependency_fetch_sandbox_profile is not None
        else sandbox_profile
    )
    selected_policy_sha256, selected_policy_size = digest_file(selected_sandbox_profile)
    if selected_policy_size <= 0 or selected_policy_size > 1024 * 1024:
        raise ReviewError("candidate sandbox policy has an invalid size")
    sandbox_execution = {
        "executor": str(SANDBOX_EXECUTABLE),
        "policy_sha256": selected_policy_sha256,
        "network_policy": (
            "LOCKED_DEPENDENCY_FETCH"
            if spec.name in DEPENDENCY_FETCH_COMMAND_NAMES
            else "DENY"
        ),
    }
    print(f"START {index:02d} {spec.name}", flush=True)
    header = {
        "argv": list(spec.argv),
        "cwd": spec.cwd,
        "environment_overrides": dict(spec.environment),
        "sandbox": sandbox_execution,
        "started_at": started_at,
        "timeout_seconds": spec.timeout_seconds,
    }
    combined_output = b""
    try:
        reject_cargo_configuration(cwd, Path(command_environment["CARGO_HOME"]))
        verify_materialized_candidate(worktree, commit, tree)
        if repository_control_snapshot(worktree) != clone_control:
            raise ReviewError("candidate clone Git control state changed")
    except ReviewError as error:
        policy_error = error
        combined_output = f"QUALIFICATION_POLICY_FAILURE: {error}\n".encode()
    if policy_error is None:
        process_result = run_bounded_process(
            sandboxed_argv(selected_sandbox_profile, spec.argv),
            cwd=cwd,
            environment=command_environment,
            timeout_seconds=spec.timeout_seconds,
            separate_stderr=False,
        )
        returncode = process_result.returncode
        timed_out = process_result.timed_out
        output_limit_exceeded = process_result.output_limit_exceeded
        combined_output = process_result.stdout
        if process_result.containment_error is not None:
            policy_error = ReviewError(process_result.containment_error)
        try:
            reject_cargo_configuration(cwd, Path(command_environment["CARGO_HOME"]))
            verify_materialized_candidate(worktree, commit, tree)
            if repository_control_snapshot(worktree) != clone_control:
                raise ReviewError("candidate clone Git control state changed")
            if digest_file(selected_sandbox_profile) != (
                selected_policy_sha256,
                selected_policy_size,
            ):
                raise ReviewError("candidate sandbox policy changed")
        except ReviewError as error:
            policy_error = error
            combined_output += f"\nQUALIFICATION_POLICY_FAILURE: {error}\n".encode(
                "utf-8"
            )
    finished_at = utc_now()
    duration = time.monotonic() - started
    state = (
        "PASS"
        if returncode == 0
        and not timed_out
        and not output_limit_exceeded
        and policy_error is None
        else "FAIL"
    )
    receipt = {
        "name": spec.name,
        "argv": list(spec.argv),
        "cwd": spec.cwd,
        "environment_overrides": dict(spec.environment),
        "sandbox": sandbox_execution,
        "execution_policy": execution_policy_contract(spec.timeout_seconds),
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": round(duration, 3),
        "timeout_seconds": spec.timeout_seconds,
        "timed_out": timed_out,
        "exit_code": returncode,
        "status": state,
        "log": log.relative_to(logs.parent).as_posix(),
        "combined_output_sha256": hashlib.sha256(combined_output).hexdigest(),
        "combined_output_size_bytes": len(combined_output),
    }
    receipt = write_receipt_log(
        log,
        canonical_json(header) + b"--- combined stdout/stderr ---\n" + combined_output,
        receipt,
    )
    print(f"{state} {index:02d} {spec.name} ({duration:.1f}s)", flush=True)
    return receipt


GIT_ARCHIVE_GLOBAL_ARGS = (
    "--no-replace-objects",
    "-c",
    "tar.umask=0022",
    "-c",
    "core.attributesFile=/dev/null",
)


def verify_source_archive(
    repo: Path,
    commit: str,
    output: Path,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Verify one compressed source archive against the exact Git tree."""

    prefix = f"galadriel-{VERSION}/"
    digest, size = digest_file(output)
    if size <= 0 or size > MAX_QUALIFICATION_ARTIFACT_BYTES:
        raise ReviewError("source archive compressed size is invalid")
    tar_digest = hashlib.sha256()
    tar_size = 0
    try:
        with gzip.open(output, "rb") as decompressed:
            while True:
                block = decompressed.read(1024 * 1024)
                if not block:
                    break
                tar_size += len(block)
                if tar_size > MAX_QUALIFICATION_ARTIFACT_BYTES:
                    raise ReviewError("source archive expands beyond its byte limit")
                tar_digest.update(block)
    except (OSError, EOFError) as error:
        raise ReviewError("source archive gzip stream is invalid") from error

    expected_raw = git_bounded_output(
        repo,
        *GIT_ARCHIVE_GLOBAL_ARGS,
        "ls-tree",
        "-rz",
        "-r",
        "--full-tree",
        commit,
        max_bytes=256 * 1024 * 1024,
        environment=None if environment is None else dict(environment),
    )
    expected: dict[str, tuple[str, str, str]] = {}
    for entry in expected_raw.split(b"\0"):
        if not entry:
            continue
        try:
            metadata, encoded_path = entry.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split()
            path = encoded_path.decode("utf-8", "strict")
        except (UnicodeError, ValueError) as error:
            raise ReviewError("candidate Git tree inventory is malformed") from error
        if path in expected:
            raise ReviewError(f"candidate tree contains a duplicate path: {path}")
        expected[path] = (mode, object_type, object_id)
    if len(expected) > MAX_QUALIFICATION_ENTRIES:
        raise ReviewError("candidate source tree exceeds its entry-count limit")

    expected_directories = {
        "/".join(Path(path).parts[:depth])
        for path in expected
        for depth in range(1, len(Path(path).parts))
    }
    commit_time_text = (
        git_bounded_output(
            repo,
            *GIT_ARCHIVE_GLOBAL_ARGS,
            "show",
            "-s",
            "--format=%ct",
            commit,
            max_bytes=128,
            environment=None if environment is None else dict(environment),
        )
        .decode("ascii", "strict")
        .strip()
    )
    if not commit_time_text.isascii() or not commit_time_text.isdecimal():
        raise ReviewError("source archive commit time is not a canonical integer")
    commit_time = int(commit_time_text)

    observed: set[str] = set()
    observed_directories: set[str] = set()
    root_name = prefix.removesuffix("/")
    entry_count = 0
    expanded_payload_size = 0
    try:
        archive_handle = tarfile.open(output, mode="r:gz")
    except (OSError, tarfile.TarError) as error:
        raise ReviewError("source archive tar stream is invalid") from error
    with archive_handle as archive:
        try:
            members = archive
            for member in members:
                entry_count += 1
                if entry_count > MAX_QUALIFICATION_ENTRIES:
                    raise ReviewError("source archive exceeds its entry-count limit")
                if member.name == root_name:
                    relative = ""
                elif member.name.startswith(prefix):
                    relative = member.name.removeprefix(prefix)
                else:
                    raise ReviewError(
                        f"source archive entry lacks release prefix: {member.name}"
                    )
                if (
                    relative.startswith("/")
                    or ".." in Path(relative).parts
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != "root"
                    or member.gname != "root"
                    or member.mtime != commit_time
                    or member.size < 0
                    or member.size > MAX_QUALIFICATION_ARTIFACT_BYTES
                ):
                    raise ReviewError(
                        "source archive entry has unsafe or noncanonical "
                        f"metadata: {member.name}"
                    )
                expanded_payload_size += member.size
                if expanded_payload_size > MAX_QUALIFICATION_TIER_BYTES:
                    raise ReviewError(
                        "source archive payload exceeds its aggregate limit"
                    )
                if member.isdir():
                    if (
                        member.mode != 0o755
                        or member.linkname
                        or (relative and relative not in expected_directories)
                        or relative in observed_directories
                    ):
                        raise ReviewError(
                            "source archive directory has another type or "
                            f"mode: {member.name}"
                        )
                    observed_directories.add(relative)
                    continue
                if not relative:
                    raise ReviewError(f"unsafe source archive path: {member.name}")
                if relative in observed or relative not in expected:
                    raise ReviewError(
                        f"unexpected or duplicate source archive path: {relative}"
                    )
                observed.add(relative)
                mode, object_type, object_id = expected[relative]
                if mode == "160000" or object_type == "commit":
                    raise ReviewError(
                        "source archive qualification requires an explicit "
                        f"submodule bundle: {relative}"
                    )
                if object_type != "blob":
                    raise ReviewError(
                        f"source archive Git object has another type: {relative}"
                    )
                blob = git_bounded_output(
                    repo,
                    *GIT_ARCHIVE_GLOBAL_ARGS,
                    "cat-file",
                    "blob",
                    object_id,
                    max_bytes=(1024 * 1024 if mode == "120000" else member.size + 1),
                    environment=None if environment is None else dict(environment),
                )
                if mode == "120000":
                    if not member.issym() or member.mode != 0o777 or member.size != 0:
                        raise ReviewError(
                            "source archive symbolic link has another type or "
                            f"mode: {relative}"
                        )
                    archived = member.linkname.encode("utf-8", "strict")
                else:
                    expected_mode = {
                        "100644": 0o644,
                        "100755": 0o755,
                    }.get(mode)
                    if (
                        expected_mode is None
                        or not member.isfile()
                        or member.mode != expected_mode
                        or member.linkname
                    ):
                        raise ReviewError(
                            f"source archive file has another type or mode: {relative}"
                        )
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise ReviewError(
                            f"source archive entry has no content: {relative}"
                        )
                    archived = extracted.read(member.size + 1)
                    if len(archived) != member.size:
                        raise ReviewError(
                            f"source archive entry size differs: {relative}"
                        )
                if archived != blob:
                    raise ReviewError(
                        f"source archive content differs from Git blob: {relative}"
                    )
        except (OSError, UnicodeError, tarfile.TarError) as error:
            raise ReviewError("source archive content is invalid") from error
    if observed != set(expected):
        missing = sorted(set(expected) - observed)
        raise ReviewError(f"source archive omits tracked paths: {missing[:10]}")
    if observed_directories != expected_directories | {""}:
        raise ReviewError(
            "source archive directory inventory differs from the Git tree"
        )
    return {
        "path": output.name,
        "sha256": digest,
        "size_bytes": size,
        "tar_sha256": tar_digest.hexdigest(),
        "tar_size_bytes": tar_size,
        "tracked_entries": len(observed),
        "prefix": prefix,
    }


def source_archive(
    repo: Path,
    commit: str,
    output: Path,
    environment: dict[str, str],
    *,
    auxiliary_runner: AuxiliaryRunner | None = None,
    receipt_name: str = "source-archive",
) -> dict[str, Any]:
    """Create and byte-verify a deterministic Git source archive."""

    prefix = f"galadriel-{VERSION}/"
    tar_path = output.with_suffix("")
    archive_argv = [
        "git",
        "-C",
        str(repo),
        *GIT_ARCHIVE_GLOBAL_ARGS,
        "archive",
        "--format=tar",
        f"--prefix={prefix}",
        commit,
    ]
    if auxiliary_runner is None:
        process = run_bounded_process(
            archive_argv,
            cwd=repo,
            environment=safe_git_environment(environment),
            timeout_seconds=3_600,
            separate_stderr=True,
        )
        if (
            process.returncode != 0
            or process.timed_out
            or process.output_limit_exceeded
            or process.containment_error is not None
        ):
            raise ReviewError(
                "git archive failed: "
                + process.stderr.decode("utf-8", "replace").strip()
            )
        tar_path.write_bytes(process.stdout)
    else:
        archive_bytes, _diagnostics = auxiliary_runner.run(
            receipt_name,
            archive_argv,
            cwd=repo,
        )
        tar_path.write_bytes(archive_bytes)
    tar_sha256, tar_size = digest_file(tar_path)
    with tar_path.open("rb") as source, output.open("wb") as destination:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=destination, mtime=0
        ) as compressed:
            shutil.copyfileobj(source, compressed)
    tar_path.unlink()

    verified = verify_source_archive(repo, commit, output, environment)
    if verified["tar_sha256"] != tar_sha256 or verified["tar_size_bytes"] != tar_size:
        raise ReviewError("source archive tar stream changed during compression")
    return verified


def collect_sboms(
    worktree: Path,
    destination: Path,
    environment: dict[str, str],
    *,
    commit: str,
    tree: str,
    comparison_root: Path,
    sandbox_profile: Path,
    auxiliary_runner: AuxiliaryRunner | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Build normalized CycloneDX documents twice and require byte identity."""

    source_date_text = environment.get("SOURCE_DATE_EPOCH")
    if (
        source_date_text is None
        or not source_date_text.isascii()
        or not source_date_text.isdigit()
    ):
        raise ReviewError("SBOM generation requires an integer source-date epoch")
    source_date_epoch = int(source_date_text)
    inventory = git_tree_inventory(worktree, commit)
    expected_crates = tuple(
        sorted(
            {
                path.split("/")[1]
                for path in inventory
                if path.startswith("crates/")
                and path.count("/") == 2
                and path.endswith("/Cargo.toml")
            }
        )
    )
    if len(expected_crates) != 7:
        raise ReviewError(
            f"expected seven workspace SBOM crates, found {len(expected_crates)}"
        )
    sbom_argv = [
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
    ]

    def normalize(
        payload: bytes,
        *,
        sbom_worktree: Path,
        crate: str,
    ) -> bytes:
        document = load_bounded_json_document(
            payload,
            maximum=MAX_SBOM_BYTES,
            context=f"CycloneDX SBOM for {crate}",
        )
        if not isinstance(document, dict):
            raise ReviewError(f"CycloneDX SBOM for {crate} is not an object")
        metadata = document.get("metadata")
        if not isinstance(metadata, dict):
            raise ReviewError(f"CycloneDX SBOM for {crate} has no metadata object")
        identity = deterministic_cyclonedx_identity(
            candidate_commit=commit,
            workspace_package=crate,
            source_date_epoch=source_date_epoch,
        )
        stable_root = Path(f"/galadriel-candidate/{commit}")
        replacements: dict[str, str] = {}
        for source_root in {
            sbom_worktree.absolute(),
            sbom_worktree.resolve(),
        }:
            replacements[str(source_root)] = str(stable_root)
            replacements[source_root.as_uri()] = stable_root.as_uri()
        ordered_replacements = tuple(
            sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True)
        )

        def replace_string(value: str) -> str:
            for source_root, retained_root in ordered_replacements:
                value = value.replace(source_root, retained_root)
            return value

        normalized: dict[str, Any] = {}
        pending: list[tuple[dict[str, Any] | list[Any], dict[str, Any] | list[Any]]] = [
            (document, normalized)
        ]
        while pending:
            source_container, retained_container = pending.pop()
            if isinstance(source_container, dict):
                if not isinstance(retained_container, dict):
                    raise ReviewError(
                        f"CycloneDX normalization changed a container for {crate}"
                    )
                for key, child in source_container.items():
                    normalized_key = replace_string(key)
                    if normalized_key in retained_container:
                        raise ReviewError(
                            f"CycloneDX path normalization collides for {crate}"
                        )
                    if isinstance(child, dict):
                        retained_child: dict[str, Any] | list[Any] = {}
                        retained_container[normalized_key] = retained_child
                        pending.append((child, retained_child))
                    elif isinstance(child, list):
                        retained_child = []
                        retained_container[normalized_key] = retained_child
                        pending.append((child, retained_child))
                    elif isinstance(child, str):
                        retained_container[normalized_key] = replace_string(child)
                    else:
                        retained_container[normalized_key] = child
            else:
                if not isinstance(retained_container, list):
                    raise ReviewError(
                        f"CycloneDX normalization changed a container for {crate}"
                    )
                for child in source_container:
                    if isinstance(child, dict):
                        retained_child = {}
                        retained_container.append(retained_child)
                        pending.append((child, retained_child))
                    elif isinstance(child, list):
                        retained_child = []
                        retained_container.append(retained_child)
                        pending.append((child, retained_child))
                    elif isinstance(child, str):
                        retained_container.append(replace_string(child))
                    else:
                        retained_container.append(child)
        if not isinstance(normalized, dict):
            raise ReviewError(f"CycloneDX SBOM for {crate} changed type")
        normalized_metadata = normalized.get("metadata")
        if not isinstance(normalized_metadata, dict):
            raise ReviewError(f"CycloneDX SBOM for {crate} lost its metadata")
        normalized["serialNumber"] = identity.serial_number
        normalized_metadata["timestamp"] = identity.timestamp
        encoded = canonical_json(normalized)
        if len(encoded) > MAX_SBOM_BYTES:
            raise ReviewError(f"normalized CycloneDX SBOM is too large: {crate}")
        if any(source_root.encode() in encoded for source_root in replacements):
            raise ReviewError(f"CycloneDX SBOM retains a run path: {crate}")
        return encoded

    normalized_runs: list[dict[str, bytes]] = []
    for run_index in (1, 2):
        sbom_worktree = comparison_root / f"sbom-worktree-{run_index}"
        create_standalone_candidate_clone(
            worktree,
            sbom_worktree,
            commit=commit,
            tree=tree,
        )
        reject_cargo_configuration(sbom_worktree, Path(environment["CARGO_HOME"]))
        receipt_name = f"cyclonedx-sboms-run-{run_index}"
        if auxiliary_runner is None:
            result = run_bounded_process(
                sandboxed_argv(sandbox_profile, sbom_argv),
                cwd=sbom_worktree,
                environment=environment,
                timeout_seconds=3_600,
                separate_stderr=False,
            )
            if (
                result.returncode != 0
                or result.timed_out
                or result.output_limit_exceeded
                or result.containment_error is not None
            ):
                detail = result.stdout.decode("utf-8", "replace").strip()
                raise ReviewError(f"cargo cyclonedx run {run_index} failed: {detail}")
        else:
            auxiliary_runner.run(
                receipt_name,
                sbom_argv,
                cwd=sbom_worktree,
            )
        reject_cargo_configuration(sbom_worktree, Path(environment["CARGO_HOME"]))
        generated = {
            crate: sbom_worktree / "crates" / crate / f"galadriel-{VERSION}.json"
            for crate in expected_crates
        }
        expected_untracked = {
            path.relative_to(sbom_worktree).as_posix() for path in generated.values()
        }
        tracked_status = str(
            git(sbom_worktree, "status", "--porcelain=v1", "--untracked-files=no")
        ).strip()
        untracked = {
            path
            for path in bytes(
                git(
                    sbom_worktree,
                    "ls-files",
                    "--others",
                    "--exclude-standard",
                    "-z",
                    text=False,
                )
            )
            .decode("utf-8", "strict")
            .split("\0")
            if path
        }
        if tracked_status or untracked != expected_untracked:
            raise ReviewError("SBOM generation changed another candidate path")
        normalized_run: dict[str, bytes] = {}
        for crate, source in generated.items():
            raw = read_bounded_regular_file(
                source,
                max_bytes=MAX_SBOM_BYTES,
                label=f"CycloneDX SBOM run {run_index} for {crate}",
            )
            normalized_run[crate] = normalize(
                raw,
                sbom_worktree=sbom_worktree,
                crate=crate,
            )
            source.unlink()
        verify_materialized_candidate(sbom_worktree, commit, tree)
        normalized_runs.append(normalized_run)

    destination.mkdir(parents=True, exist_ok=False)
    rows: list[dict[str, Any]] = []
    comparisons: list[dict[str, Any]] = []
    for crate in expected_crates:
        first = normalized_runs[0][crate]
        second = normalized_runs[1][crate]
        if first != second:
            raise ReviewError(f"two normalized CycloneDX runs differ for {crate}")
        target = destination / f"{crate}.cdx.json"
        target.write_bytes(first)
        digest, size = digest_file(target)
        rows.append(
            {
                "crate": crate,
                "path": target.relative_to(destination.parent).as_posix(),
                "sha256": digest,
                "size_bytes": size,
            }
        )
        comparisons.append(
            {
                "kind": "cyclonedx_sbom",
                "name": target.name,
                "run_1_sha256": hashlib.sha256(first).hexdigest(),
                "run_2_sha256": hashlib.sha256(second).hexdigest(),
                "size_bytes": len(first),
                "status": "IDENTICAL",
            }
        )
    return rows, comparisons


def capture_report(
    argv: list[str],
    *,
    worktree: Path,
    environment: dict[str, str],
    output: Path,
    json_lines: bool,
    report_stream: str,
    sandbox_profile: Path | None = None,
    auxiliary_runner: AuxiliaryRunner | None = None,
    receipt_name: str = "report",
) -> dict[str, Any]:
    """Retain and parse-check a report from one explicitly selected stream."""

    if report_stream not in {"stdout", "stderr"}:
        raise ReviewError("report_stream must be exactly 'stdout' or 'stderr'")

    reject_cargo_configuration(worktree, Path(environment["CARGO_HOME"]))
    if auxiliary_runner is not None:
        process_stdout, process_stderr = auxiliary_runner.run(
            receipt_name,
            argv,
            cwd=worktree,
        )
        process_returncode = 0
    else:
        process_argv = (
            argv if sandbox_profile is None else sandboxed_argv(sandbox_profile, argv)
        )
        process = run_bounded_process(
            process_argv,
            cwd=worktree,
            environment=environment,
            timeout_seconds=3_600,
            separate_stderr=True,
        )
        process_stdout = process.stdout
        process_stderr = process.stderr
        process_returncode = (
            process.returncode
            if not process.timed_out
            and not process.output_limit_exceeded
            and process.containment_error is None
            else 2
        )
    reject_cargo_configuration(worktree, Path(environment["CARGO_HOME"]))
    if process_returncode != 0:
        detail = process_stderr.decode("utf-8", "replace").strip()
        raise ReviewError(f"{' '.join(argv)} report failed: {detail}")
    command = " ".join(argv)
    report_payload = process_stdout if report_stream == "stdout" else process_stderr
    diagnostics_stream = "stderr" if report_stream == "stdout" else "stdout"
    diagnostics_payload = (
        process_stderr if diagnostics_stream == "stderr" else process_stdout
    )
    if not report_payload.strip():
        raise ReviewError(f"{command} produced an empty report on {report_stream}")
    if report_stream == "stderr" and process_stdout:
        raise ReviewError(
            f"{command} produced unexpected nonempty stdout alongside its stderr report"
        )
    try:
        if json_lines:
            documents = [
                loads_json(line) for line in report_payload.splitlines() if line.strip()
            ]
            if not documents or not all(
                isinstance(document, dict) for document in documents
            ):
                raise ValueError("JSONL report must contain at least one object")
        else:
            document = loads_json(report_payload)
            if not isinstance(document, dict):
                raise ValueError("JSON report must be an object")
    except (UnicodeError, ReviewError, ValueError) as error:
        raise ReviewError(
            f"{command} produced invalid JSON evidence on {report_stream}: {error}"
        ) from error
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(report_payload)
    digest, size = digest_file(output)
    return {
        "argv": argv,
        "path": output.relative_to(output.parents[1]).as_posix(),
        "sha256": digest,
        "size_bytes": size,
        "report_stream": report_stream,
        "receipt": receipt_name,
        "diagnostics": {
            "stream": diagnostics_stream,
            "text": diagnostics_payload.decode("utf-8", "replace").strip(),
            "sha256": hashlib.sha256(diagnostics_payload).hexdigest(),
            "size_bytes": len(diagnostics_payload),
        },
    }


def reproducible_source_archive(
    repo: Path,
    commit: str,
    output: Path,
    comparison_root: Path,
    environment: dict[str, str],
    *,
    auxiliary_runner: AuxiliaryRunner | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the source archive twice and reject byte drift."""

    retained = source_archive(
        repo,
        commit,
        output,
        environment,
        auxiliary_runner=auxiliary_runner,
        receipt_name="source-archive-run-1",
    )
    repeated_path = comparison_root / output.name
    repeated = source_archive(
        repo,
        commit,
        repeated_path,
        environment,
        auxiliary_runner=auxiliary_runner,
        receipt_name="source-archive-run-2",
    )
    if (
        retained["sha256"] != repeated["sha256"]
        or retained["size_bytes"] != repeated["size_bytes"]
        or retained["tar_sha256"] != repeated["tar_sha256"]
        or retained["tar_size_bytes"] != repeated["tar_size_bytes"]
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


def candidate_crate_file_maps(
    worktree: Path,
    commit: str,
    crates: tuple[str, ...],
) -> dict[str, dict[str, tuple[int, bytes]]]:
    """Map each tracked regular crate blob to its Cargo archive path."""

    inventory = git_tree_inventory(worktree, commit)
    result: dict[str, dict[str, tuple[int, bytes]]] = {crate: {} for crate in crates}
    crate_set = set(crates)
    for path, entry in sorted(inventory.items()):
        parts = path.split("/")
        if len(parts) < 3 or parts[0] != "crates" or parts[1] not in crate_set:
            continue
        mode_text = entry["mode"]
        if mode_text == "120000":
            continue
        if mode_text not in {"100644", "100755"}:
            raise ReviewError(f"candidate crate has an unsupported mode: {path}")
        crate = parts[1]
        archive_path = "/".join(parts[2:])
        if archive_path == "Cargo.toml":
            archive_path = "Cargo.toml.orig"
        crate_files = result[crate]
        if archive_path in crate_files:
            raise ReviewError(
                f"candidate crate archive path is duplicated: {crate}/{archive_path}"
            )
        content = read_bounded_regular_file(
            worktree / path,
            max_bytes=entry["bytes"],
            label=f"candidate crate file {path}",
        )
        if (
            len(content) != entry["bytes"]
            or hashlib.sha256(content).hexdigest() != entry["sha256"]
        ):
            raise ReviewError(f"candidate crate file differs from Git: {path}")
        crate_files[archive_path] = (
            0o755 if mode_text == "100755" else 0o644,
            content,
        )
    for crate, crate_files in result.items():
        if "Cargo.toml.orig" not in crate_files:
            raise ReviewError(f"candidate crate map omits Cargo.toml: {crate}")
    return result


def reproducible_packages(
    worktree: Path,
    metadata: dict[str, Any],
    destination: Path,
    comparison_root: Path,
    environment: dict[str, str],
    *,
    tree: str,
    sandbox_profile: Path,
    auxiliary_runner: AuxiliaryRunner | None = None,
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
    crate_file_maps = candidate_crate_file_maps(
        worktree,
        str(git(worktree, "rev-parse", "HEAD^{commit}")).strip(),
        tuple(name for name, _version in packages),
    )
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
    commit = str(git(worktree, "rev-parse", "HEAD^{commit}")).strip()
    original_lock = (worktree / "Cargo.lock").read_bytes()
    for run_index, (target, package_worktree) in enumerate(
        zip(targets, packaging_worktrees, strict=True), 1
    ):
        create_standalone_candidate_clone(
            worktree, package_worktree, commit=commit, tree=tree
        )
        package_paths = {
            name: (package_worktree / "crates" / name).resolve()
            for name, _version in packages
        }
        if any(not (path / "Cargo.toml").is_file() for path in package_paths.values()):
            raise ReviewError("package worktree omits a workspace manifest")
        for name, _version in packages:
            if (package_worktree / "Cargo.lock").read_bytes() != original_lock:
                raise ReviewError("package worktree lock differs before Cargo package")
            if str(
                git(
                    package_worktree,
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=all",
                )
            ).strip():
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
            reject_cargo_configuration(
                package_worktree, Path(environment["CARGO_HOME"])
            )
            package_argv = [
                "cargo",
                "package",
                "-p",
                name,
                "--locked",
                "--offline",
                "--no-verify",
                "--exclude-lockfile",
                "--target-dir",
                str(target),
                *patch_arguments,
            ]
            if auxiliary_runner is None:
                process = run_bounded_process(
                    sandboxed_argv(sandbox_profile, package_argv),
                    cwd=package_worktree,
                    environment=environment,
                    timeout_seconds=3_600,
                    separate_stderr=False,
                )
                package_returncode = (
                    process.returncode
                    if not process.timed_out
                    and not process.output_limit_exceeded
                    and process.containment_error is None
                    else 2
                )
                package_output = process.stdout.decode("utf-8", "replace")
            else:
                package_stdout, package_stderr = auxiliary_runner.run(
                    f"cargo-package-run-{run_index}-{name}",
                    package_argv,
                    cwd=package_worktree,
                )
                package_returncode = 0
                package_output = (package_stdout + package_stderr).decode(
                    "utf-8", "replace"
                )
            reject_cargo_configuration(
                package_worktree, Path(environment["CARGO_HOME"])
            )
            if package_returncode != 0:
                raise ReviewError(
                    f"cargo package -p {name} failed: {package_output.strip()}"
                )
            if (package_worktree / "Cargo.lock").read_bytes() != original_lock:
                raise ReviewError("cargo package changed the candidate lockfile")
            if str(
                git(
                    package_worktree,
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=all",
                )
            ).strip():
                raise ReviewError("cargo package changed another candidate path")
        if str(
            git(
                package_worktree,
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            )
        ).strip():
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
        for package_path in (first, second):
            package_bytes = read_bounded_regular_file(
                package_path,
                max_bytes=MAX_CRATE_ARCHIVE_BYTES,
                label=f"Cargo package {filename}",
            )
            validate_crate_archive(
                package_bytes,
                crate_name=name,
                version=version,
                candidate_commit=commit,
                candidate_files=crate_file_maps[name],
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
    aggregate_size = 0

    def retain(
        relative: str,
        descriptor: int,
        metadata: os.stat_result,
    ) -> None:
        nonlocal aggregate_size
        if metadata.st_size > MAX_QUALIFICATION_ARTIFACT_BYTES:
            raise ReviewError(
                f"qualification artifact exceeds the size limit: {relative}"
            )
        aggregate_size += metadata.st_size
        if aggregate_size > MAX_QUALIFICATION_TIER_BYTES:
            raise ReviewError("qualification output exceeds the aggregate size limit")
        if relative in excluded:
            return
        digest, size = digest_regular_descriptor(
            descriptor,
            expected_size=metadata.st_size,
            label=f"qualification artifact {relative}",
        )
        rows.append({"path": relative, "sha256": digest, "size_bytes": size})

    walk_bounded_tree(
        root,
        label="qualification output",
        max_entries=MAX_QUALIFICATION_ENTRIES,
        max_depth=MAX_QUALIFICATION_DEPTH,
        on_regular=retain,
        reject_empty_directories=True,
    )
    return rows


def external_input_path(
    value: str,
    *,
    repo: Path,
    label: str,
    directory: bool = False,
) -> Path:
    """Resolve one external input without accepting a final symbolic link."""

    repo = repo.resolve()
    expanded = Path(value).expanduser()
    absolute = Path(os.path.abspath(os.fspath(expanded)))
    path = absolute.parent.resolve() / absolute.name
    if path.is_symlink():
        raise ReviewError(f"{label} must not be a symbolic link")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ReviewError(f"cannot resolve {label}: {error}") from error
    expected_kind = resolved.is_dir() if directory else resolved.is_file()
    if not expected_kind or resolved.is_symlink():
        kind = "directory" if directory else "regular file"
        raise ReviewError(f"{label} must be an existing {kind}")
    if resolved == repo or repo in resolved.parents:
        raise ReviewError(f"{label} must be outside the candidate repository")
    return resolved


def snapshot_external_tree(
    source: Path,
    destination: Path,
    *,
    max_bytes: int,
    max_entries: int = 128,
    max_depth: int = 8,
) -> None:
    """Copy one bounded external evidence tree without following links."""

    if source.is_symlink() or not source.is_dir():
        raise ReviewError("external evidence root is missing or unsafe")
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    aggregate_size = 0

    def create_directory(relative: str) -> None:
        (destination / relative).mkdir(mode=0o700)

    def copy_regular(
        relative: str,
        descriptor: int,
        metadata: os.stat_result,
    ) -> None:
        nonlocal aggregate_size
        if metadata.st_size > max_bytes - aggregate_size:
            raise ReviewError("external evidence exceeds its aggregate byte limit")
        payload = read_regular_descriptor(
            descriptor,
            expected_size=metadata.st_size,
            max_bytes=max_bytes - aggregate_size,
            label=f"external evidence artifact {relative}",
        )
        destination_path = destination / relative
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            destination_descriptor = os.open(destination_path, flags, 0o600)
            try:
                offset = 0
                while offset < len(payload):
                    written = os.write(destination_descriptor, payload[offset:])
                    if written <= 0:
                        raise ReviewError(
                            f"cannot completely retain external evidence {relative}"
                        )
                    offset += written
            finally:
                os.close(destination_descriptor)
        except OSError as error:
            raise ReviewError(
                f"cannot retain external evidence artifact {relative}: {error}"
            ) from error
        aggregate_size += len(payload)

    walk_bounded_tree(
        source,
        label="external evidence",
        max_entries=max_entries,
        max_depth=max_depth,
        on_regular=copy_regular,
        on_directory=create_directory,
        reject_empty_directories=True,
    )


def candidate_evidence_inventory(
    root: Path,
    *,
    capture_json: bool,
) -> tuple[dict[str, tuple[str, int]], dict[str, bytes]]:
    """Validate one exact flat candidate-evidence tree through held descriptors."""

    records: dict[str, tuple[str, int]] = {}
    captured: dict[str, bytes] = {}
    aggregate_size = 0

    def inspect(
        relative: str,
        descriptor: int,
        metadata: os.stat_result,
    ) -> None:
        nonlocal aggregate_size
        if "/" in relative or relative not in EXPECTED_CANDIDATE_EVIDENCE_FILES:
            raise ReviewError(f"candidate evidence has an unexpected path: {relative}")
        if relative in records:
            raise ReviewError(f"candidate evidence has a duplicate path: {relative}")
        if metadata.st_size > MAX_QUALIFICATION_ARTIFACT_BYTES:
            raise ReviewError(
                f"candidate evidence file exceeds its byte limit: {relative}"
            )
        aggregate_size += metadata.st_size
        if aggregate_size > MAX_CANDIDATE_EVIDENCE_BYTES:
            raise ReviewError("candidate evidence exceeds its aggregate byte limit")
        if capture_json and relative in PARSED_CANDIDATE_EVIDENCE_FILES:
            if metadata.st_size > MAX_EVIDENCE_DOCUMENT_BYTES:
                raise ReviewError(
                    f"candidate evidence JSON exceeds its byte limit: {relative}"
                )
            captured[relative] = read_regular_descriptor(
                descriptor,
                expected_size=metadata.st_size,
                max_bytes=MAX_EVIDENCE_DOCUMENT_BYTES,
                label=f"candidate evidence {relative}",
            )
        records[relative] = digest_regular_descriptor(
            descriptor,
            expected_size=metadata.st_size,
            label=f"candidate evidence {relative}",
        )

    walk_bounded_tree(
        root,
        label="candidate evidence",
        max_entries=len(EXPECTED_CANDIDATE_EVIDENCE_FILES),
        max_depth=0,
        on_regular=inspect,
        reject_empty_directories=True,
    )
    if set(records) != EXPECTED_CANDIDATE_EVIDENCE_FILES:
        raise ReviewError("candidate evidence file set is not exact")
    if capture_json and set(captured) != PARSED_CANDIDATE_EVIDENCE_FILES:
        raise ReviewError("candidate evidence JSON file set is not exact")
    return records, captured


def snapshot_candidate_evidence(
    source: Path,
    destination: Path,
) -> dict[str, tuple[str, int]]:
    """Stream one exact candidate-evidence tree into a private host directory."""

    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    records: dict[str, tuple[str, int]] = {}
    aggregate_size = 0

    def copy_regular(
        relative: str,
        descriptor: int,
        metadata: os.stat_result,
    ) -> None:
        nonlocal aggregate_size
        if "/" in relative or relative not in EXPECTED_CANDIDATE_EVIDENCE_FILES:
            raise ReviewError(f"candidate evidence has an unexpected path: {relative}")
        if relative in records:
            raise ReviewError(f"candidate evidence has a duplicate path: {relative}")
        if metadata.st_size > MAX_QUALIFICATION_ARTIFACT_BYTES:
            raise ReviewError(
                f"candidate evidence file exceeds its byte limit: {relative}"
            )
        aggregate_size += metadata.st_size
        if aggregate_size > MAX_CANDIDATE_EVIDENCE_BYTES:
            raise ReviewError("candidate evidence exceeds its aggregate byte limit")
        destination_path = destination / relative
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        digest = hashlib.sha256()
        copied = 0
        try:
            output_descriptor = os.open(destination_path, flags, 0o600)
            try:
                os.lseek(descriptor, 0, os.SEEK_SET)
                while copied <= metadata.st_size:
                    block = os.read(
                        descriptor,
                        min(1024 * 1024, metadata.st_size + 1 - copied),
                    )
                    if not block:
                        break
                    copied += len(block)
                    if copied > metadata.st_size:
                        raise ReviewError(
                            f"candidate evidence changed size while copied: {relative}"
                        )
                    digest.update(block)
                    offset = 0
                    while offset < len(block):
                        written = os.write(output_descriptor, block[offset:])
                        if written <= 0:
                            raise ReviewError(
                                f"cannot retain candidate evidence: {relative}"
                            )
                        offset += written
            finally:
                os.close(output_descriptor)
        except OSError as error:
            raise ReviewError(
                f"cannot retain candidate evidence: {relative}"
            ) from error
        if copied != metadata.st_size:
            raise ReviewError(
                f"candidate evidence changed size while copied: {relative}"
            )
        records[relative] = (digest.hexdigest(), copied)

    walk_bounded_tree(
        source,
        label="candidate evidence",
        max_entries=len(EXPECTED_CANDIDATE_EVIDENCE_FILES),
        max_depth=0,
        on_regular=copy_regular,
        reject_empty_directories=True,
    )
    if set(records) != EXPECTED_CANDIDATE_EVIDENCE_FILES:
        raise ReviewError("candidate evidence file set is not exact")
    return records


def retain_candidate_evidence(source: Path, output_root: Path) -> dict[str, bytes]:
    """Replace candidate-writable evidence with one verified host snapshot."""

    snapshot = output_root / ".candidate-evidence-snapshot"
    quarantine = output_root / ".candidate-evidence-untrusted"
    if snapshot.exists() or quarantine.exists():
        raise ReviewError("candidate evidence snapshot path already exists")
    copied_records = snapshot_candidate_evidence(source, snapshot)
    snapshot_records, captured = candidate_evidence_inventory(
        snapshot, capture_json=True
    )
    if copied_records != snapshot_records:
        raise ReviewError("candidate evidence snapshot changed after copy")
    source_records, _ = candidate_evidence_inventory(source, capture_json=False)
    if source_records != snapshot_records:
        raise ReviewError("candidate evidence changed while being retained")
    try:
        os.rename(source, quarantine)
    except OSError as error:
        raise ReviewError("cannot quarantine candidate-writable evidence") from error
    quarantine_records, _ = candidate_evidence_inventory(quarantine, capture_json=False)
    if quarantine_records != snapshot_records:
        raise ReviewError("candidate evidence changed before quarantine")
    try:
        os.rename(snapshot, source)
    except OSError as error:
        raise ReviewError("cannot install retained candidate evidence") from error
    installed_records, installed = candidate_evidence_inventory(
        source, capture_json=True
    )
    if installed_records != snapshot_records or installed != captured:
        raise ReviewError("retained candidate evidence changed during installation")
    shutil.rmtree(quarantine)
    if quarantine.exists() or snapshot.exists():
        raise ReviewError("candidate evidence snapshot cleanup failed")
    return installed


def decode_candidate_evidence_json(payload: bytes, label: str) -> dict[str, Any]:
    """Decode one bounded candidate-evidence JSON object."""

    value = load_bounded_json_document(
        payload,
        maximum=MAX_EVIDENCE_DOCUMENT_BYTES,
        context=label,
    )
    if not isinstance(value, dict):
        raise ReviewError(f"{label} is not a JSON object")
    return value


def qualification_outcome(
    *,
    command_status: str,
    archive_present: bool,
    acceptance_status: str | None,
    deep_requested: bool,
) -> tuple[str, str]:
    """Return a non-release status unless every candidate gate was requested."""

    status = (
        "PASS"
        if command_status == "PASS" and archive_present and deep_requested
        else "FAIL"
    )
    release_gate = (
        "PASS"
        if status == "PASS" and acceptance_status == "PASS"
        else "NARROWED_REVIEW_REQUIRED"
        if status == "PASS" and acceptance_status == "FAIL"
        else "FAIL"
    )
    return status, release_gate


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
            "agent-backed Ed25519 public-key handle used for the detached "
            "qualification-manifest signature"
        ),
    )
    parser.add_argument(
        "--allowed-signers",
        required=True,
        help="independently obtained allowed-signers trust root",
    )
    parser.add_argument(
        "--advisory-db",
        required=True,
        help="clean external clone at the pinned RustSec advisory database commit",
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
    output = absolute_path_without_final_resolution(arguments.out)
    signing_key: Path | None = None
    allowed_signers_source: Path | None = None
    advisory_db_source: Path | None = None
    mutation_evidence_path: Path | None = None
    mutation_signature_path: Path | None = None
    worktree: Path | None = None
    temporary: tempfile.TemporaryDirectory[str] | None = None
    results: list[dict[str, Any]] = []
    auxiliary_receipts: list[dict[str, Any]] = []
    failure: str | None = None
    try:
        if os.path.lexists(output) or output == repo or repo in output.parents:
            raise ReviewError("--out must be a new directory outside --repo")
        if not arguments.signing_key:
            raise ReviewError("successful qualification requires --signing-key")
        signing_key = external_input_path(
            arguments.signing_key,
            repo=repo,
            label="signing-key public handle",
        )
        allowed_signers_source = external_input_path(
            arguments.allowed_signers,
            repo=repo,
            label="independent allowed-signers file",
        )
        advisory_db_source = external_input_path(
            arguments.advisory_db,
            repo=repo,
            label="RustSec advisory database",
            directory=True,
        )
        if arguments.mutation_evidence:
            mutation_evidence_path = external_input_path(
                arguments.mutation_evidence,
                repo=repo,
                label="mutation evidence manifest",
            )
        if arguments.mutation_evidence_signature:
            mutation_signature_path = external_input_path(
                arguments.mutation_evidence_signature,
                repo=repo,
                label="mutation evidence signature",
            )
        if mutation_evidence_path is None or mutation_signature_path is None:
            raise ReviewError(
                "successful qualification requires signed exact-candidate mutation evidence"
            )
        assert_no_replace_refs(repo)
        if str(git(repo, "status", "--porcelain=v1", "--untracked-files=all")).strip():
            raise ReviewError("candidate checkout is dirty")
        commit = str(git(repo, "rev-parse", "HEAD^{commit}")).strip()
        if commit != arguments.expected:
            raise ReviewError(
                f"candidate mismatch: expected={arguments.expected} actual={commit}"
            )
        branch = str(git(repo, "branch", "--show-current")).strip()
        if arguments.require_branch and branch != arguments.require_branch:
            raise ReviewError(
                f"candidate branch must be {arguments.require_branch!r}, got {branch!r}"
            )
        repository_identity, origin_main = refresh_canonical_origin_main(repo, commit)
        source_snapshot = repository_control_snapshot(repo)
        tree = str(git(repo, "rev-parse", "HEAD^{tree}")).strip()
        source_date_epoch = str(
            git(
                repo,
                "-c",
                "log.showSignature=false",
                "show",
                "-s",
                "--format=%ct",
                "HEAD",
            )
        ).strip()

        output.mkdir(parents=True, exist_ok=False)
        logs = output / "logs"
        logs.mkdir()
        inventory = output / "source-inventory"
        evidence_output = output / "candidate-evidence"
        temporary = tempfile.TemporaryDirectory(prefix="galadriel-qualification-")
        temporary_root = Path(temporary.name).resolve()
        worktree = temporary_root / "worktree"
        target = temporary_root / "target"
        signing_key, signing_key_signer = snapshot_agent_backed_public_signing_key(
            signing_key,
            temporary_root / "SIGNING_KEY.pub",
        )
        external_allowed_signers = temporary_root / "INDEPENDENT_ALLOWED_SIGNERS"
        expected_signer_metadata = snapshot_independent_allowed_signers(
            allowed_signers_source, external_allowed_signers
        )
        if signing_key_signer != expected_signer_metadata:
            raise ReviewError(
                "signing-key public handle differs from the independent trust root"
            )
        verify_candidate_commit(repo, commit, external_allowed_signers)
        create_standalone_candidate_clone(repo, worktree, commit=commit, tree=tree)
        assert_tracked_allowed_signer(
            worktree / ALLOWED_SIGNERS, expected_signer_metadata
        )
        clone_control = repository_control_snapshot(worktree)
        if mutation_evidence_path.parent != mutation_signature_path.parent:
            raise ReviewError(
                "mutation evidence manifest and signature must share one directory"
            )
        mutation_snapshot = temporary_root / "mutation-input"
        snapshot_external_tree(
            mutation_evidence_path.parent,
            mutation_snapshot,
            max_bytes=MAX_MUTATION_EVIDENCE_BYTES,
        )
        snapshotted_mutation_manifest = mutation_snapshot / mutation_evidence_path.name
        snapshotted_mutation_signature = (
            mutation_snapshot / mutation_signature_path.name
        )
        mutation_document, mutation_artifacts = validate_mutation_evidence(
            snapshotted_mutation_manifest,
            snapshotted_mutation_signature,
            allowed_signers=external_allowed_signers,
            repo=repo,
            commit=commit,
            tree=tree,
        )
        mutation_output = output / "mutation"
        mutation_output.mkdir()
        shutil.copyfile(
            snapshotted_mutation_manifest, mutation_output / "manifest.json"
        )
        shutil.copyfile(
            snapshotted_mutation_signature,
            mutation_output / "manifest.json.sig",
        )
        retained_mutation_artifacts = []
        for source in mutation_artifacts:
            source_relative = source.relative_to(mutation_snapshot)
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
            "run_receipts": 5,
            "status": "PASS",
            "artifacts": retained_mutation_artifacts,
        }

        environment = build_qualification_environment(
            os.environ,
            private_root=temporary_root,
            target=target,
            source_date_epoch=source_date_epoch,
        )
        advisory_source_path = advisory_db_source.resolve()
        advisory_source_snapshot = repository_control_snapshot(advisory_source_path)
        advisory_database, advisory_database_paths = install_pinned_advisory_database(
            advisory_source_path, Path(environment["CARGO_HOME"])
        )
        comparison_root = temporary_root / "reproducibility"
        sandbox_writable_paths = tuple(
            path.resolve()
            for path in (
                *(Path(environment[key]) for key in ISOLATED_ENVIRONMENT_PATHS),
                inventory,
                evidence_output,
                comparison_root,
            )
        )
        sandbox_read_only_paths = tuple(
            path.resolve()
            for path in (
                *advisory_database_paths,
                external_allowed_signers,
            )
        )
        host_home = Path.home().resolve()
        sandbox_tool_read_paths = qualification_tool_read_paths(
            environment,
            host_home=host_home,
        )
        rustup_home = Path(environment["RUSTUP_HOME"]).resolve()
        sandbox_home_tool_paths = {
            Path(entry).resolve()
            for entry in environment["PATH"].split(os.pathsep)
            if Path(entry).resolve() == host_home
            or host_home in Path(entry).resolve().parents
        }
        sandbox_home_read_paths = set(sandbox_home_tool_paths)
        if rustup_home == host_home or host_home in rustup_home.parents:
            sandbox_home_read_paths.add(rustup_home)
        sandbox_home_read_paths.update(
            path.resolve()
            for path in sandbox_writable_paths
            if path.resolve() == host_home or host_home in path.resolve().parents
        )
        resolved_sandbox_home_read_paths = tuple(
            sorted(sandbox_home_read_paths, key=lambda item: str(item))
        )
        sandbox_profile = temporary_root / "candidate.sb"
        sandbox_profile_sha256 = write_candidate_sandbox_profile(
            sandbox_profile,
            worktree=worktree,
            source_repo=repo,
            read_only_paths=sandbox_read_only_paths,
            writable_paths=sandbox_writable_paths,
            allowed_home_read_paths=resolved_sandbox_home_read_paths,
            tool_read_paths=sandbox_tool_read_paths,
            denied_read_paths=(advisory_source_path,),
        )
        dependency_fetch_sandbox_profile = temporary_root / "dependency-fetch.sb"
        dependency_fetch_sandbox_profile_sha256 = write_candidate_sandbox_profile(
            dependency_fetch_sandbox_profile,
            worktree=worktree,
            source_repo=repo,
            read_only_paths=sandbox_read_only_paths,
            writable_paths=sandbox_writable_paths,
            allowed_home_read_paths=resolved_sandbox_home_read_paths,
            tool_read_paths=sandbox_tool_read_paths,
            denied_read_paths=(advisory_source_path,),
            allow_network=True,
        )
        candidate_probe_paths = sandbox_process_probe_paths(sandbox_profile)
        dependency_fetch_probe_paths = sandbox_process_probe_paths(
            dependency_fetch_sandbox_profile
        )
        sandbox_output = output / "sandbox"
        sandbox_output.mkdir()
        retained_sandbox_profile = sandbox_output / "candidate.sb"
        retained_dependency_fetch_profile = sandbox_output / "dependency-fetch.sb"
        shutil.copyfile(sandbox_profile, retained_sandbox_profile)
        shutil.copyfile(
            dependency_fetch_sandbox_profile,
            retained_dependency_fetch_profile,
        )
        os.chmod(retained_sandbox_profile, 0o600)
        os.chmod(retained_dependency_fetch_profile, 0o600)
        if (
            digest_file(retained_sandbox_profile)[0] != sandbox_profile_sha256
            or digest_file(retained_dependency_fetch_profile)[0]
            != dependency_fetch_sandbox_profile_sha256
        ):
            raise ReviewError("retained sandbox policy differs from its applied bytes")
        sandbox_bindings = {
            "candidate_worktree": str(worktree.resolve()),
            "source_repository": str(repo.resolve()),
            "host_home": str(host_home),
            "private_root": str(temporary_root.resolve()),
            "isolated_home": environment["HOME"],
            "cargo_home": environment["CARGO_HOME"],
            "cargo_target_directory": environment["CARGO_TARGET_DIR"],
            "temporary_directory": environment["TMPDIR"],
            "source_inventory": str(inventory.resolve()),
            "candidate_evidence": str(evidence_output.resolve()),
            "reproducibility_root": str(comparison_root.resolve()),
            "advisory_source_denied_read": str(advisory_source_path),
            "advisory_databases": [str(path) for path in advisory_database_paths],
            "allowed_signers_snapshot": str(external_allowed_signers.resolve()),
            "rustup_home": str(rustup_home),
            "home_tool_paths": [
                str(path)
                for path in sorted(sandbox_home_tool_paths, key=lambda item: str(item))
            ],
            "tool_read_paths": [
                str(path)
                for path in sorted(sandbox_tool_read_paths, key=lambda item: str(item))
            ],
            "candidate_process_probe_deny": str(
                candidate_probe_paths[0].resolve(strict=True)
            ),
            "candidate_process_probe_allow": str(
                candidate_probe_paths[1].resolve(strict=True)
            ),
            "dependency_fetch_process_probe_deny": str(
                dependency_fetch_probe_paths[0].resolve(strict=True)
            ),
            "dependency_fetch_process_probe_allow": str(
                dependency_fetch_probe_paths[1].resolve(strict=True)
            ),
        }
        tool_files_before = qualification_tool_files(environment)
        reject_cargo_configuration(worktree, Path(environment["CARGO_HOME"]))
        command_specs = [
            CommandSpec(
                "verify-commit-signature-external-key",
                (
                    "git",
                    "--no-replace-objects",
                    *SAFE_GIT_CONFIGURATION,
                    "-c",
                    "gpg.format=ssh",
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
            if not network_command_preconditions_met(spec, results):
                break
            result = run_command(
                spec,
                worktree=worktree,
                commit=commit,
                tree=tree,
                clone_control=clone_control,
                sandbox_profile=sandbox_profile,
                dependency_fetch_sandbox_profile=dependency_fetch_sandbox_profile,
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
            retained_evidence = retain_candidate_evidence(evidence_output, output)
            tracked_config_bytes = read_bounded_regular_file(
                worktree / evidence_config,
                max_bytes=MAX_EVIDENCE_DOCUMENT_BYTES,
                label="tracked candidate evidence config",
            )
            config_binding = validate_evidence_config_bytes(
                tracked_config_bytes,
                retained_evidence["config.json"],
                retained_evidence["manifest.json"],
                tracked_relative_path=evidence_config.as_posix(),
            )
            try:
                summary = decode_candidate_evidence_json(
                    retained_evidence["summary.json"],
                    "candidate evidence summary",
                )
                accepted_config = decode_candidate_evidence_json(
                    retained_evidence["config.json"],
                    "accepted candidate evidence config",
                )
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
            cargo_home = Path(environment["CARGO_HOME"])
            auxiliary_logs = output / "auxiliary-logs"
            auxiliary_logs.mkdir()
            auxiliary_runner = AuxiliaryRunner(
                environment=environment,
                sandbox_profile=sandbox_profile,
                logs=auxiliary_logs,
                receipts=auxiliary_receipts,
            )
            reject_cargo_configuration(worktree, cargo_home)
            metadata_argv = [
                "cargo",
                "metadata",
                "--locked",
                "--offline",
                "--all-features",
                "--format-version=1",
            ]
            metadata_stdout, metadata_stderr = auxiliary_runner.run(
                "cargo-metadata",
                metadata_argv,
                cwd=worktree,
            )
            reject_cargo_configuration(worktree, cargo_home)
            if metadata_stderr:
                raise ReviewError(
                    "cargo metadata produced unexpected diagnostics: "
                    + metadata_stderr.decode("utf-8", "replace").strip()
                )
            metadata_path = output / "cargo-metadata.json"
            metadata_path.write_bytes(metadata_stdout)
            metadata_sha256, metadata_size = digest_file(metadata_path)
            cargo_metadata_record = {
                "argv": metadata_argv,
                "receipt": "cargo-metadata",
                "path": "cargo-metadata.json",
                "sha256": metadata_sha256,
                "size_bytes": metadata_size,
            }
            candidate_lock_bytes = read_bounded_regular_file(
                worktree / "Cargo.lock",
                max_bytes=MAX_LOCKFILE_BYTES,
                label="candidate Cargo.lock",
            )
            cargo_graph = validate_cargo_metadata(
                metadata_stdout,
                candidate_lock_bytes,
            )
            validate_cargo_graph_paths(
                cargo_graph,
                workspace_root=worktree,
                target_directory=Path(environment["CARGO_TARGET_DIR"]),
            )
            metadata_document = loads_json(metadata_stdout)
            comparison_root.mkdir()
            metadata_tool_input = comparison_root / "cargo-metadata.json"
            metadata_tool_input.write_bytes(metadata_stdout)
            if digest_file(metadata_tool_input) != (
                metadata_sha256,
                metadata_size,
            ):
                raise ReviewError("artifact-generation Cargo metadata copy changed")
            archive, archive_comparison = reproducible_source_archive(
                worktree,
                commit,
                output / f"galadriel-{VERSION}.tar.gz",
                comparison_root,
                environment,
                auxiliary_runner=auxiliary_runner,
            )
            packages, package_comparisons = reproducible_packages(
                worktree,
                metadata_document,
                output / "packages",
                comparison_root,
                environment,
                tree=tree,
                sandbox_profile=sandbox_profile,
                auxiliary_runner=auxiliary_runner,
            )
            reject_cargo_configuration(worktree, cargo_home)
            sboms, sbom_comparisons = collect_sboms(
                worktree,
                output / "sbom",
                environment,
                commit=commit,
                tree=tree,
                comparison_root=comparison_root,
                sandbox_profile=sandbox_profile,
                auxiliary_runner=auxiliary_runner,
            )
            for sbom in sboms:
                sbom_bytes = read_bounded_regular_file(
                    output / sbom["path"],
                    max_bytes=MAX_SBOM_BYTES,
                    label=f"CycloneDX SBOM for {sbom['crate']}",
                )
                validate_cyclonedx_sbom(
                    sbom_bytes,
                    cargo_graph,
                    workspace_package=sbom["crate"],
                    candidate_commit=commit,
                    source_date_epoch=int(source_date_epoch),
                )
            license_inventory = capture_report(
                [
                    "cargo",
                    "deny",
                    "--offline",
                    "--all-features",
                    "--locked",
                    "list",
                    "--metadata-path",
                    str(metadata_tool_input),
                    "--format",
                    "json",
                    "--layout",
                    "crate",
                ],
                worktree=worktree,
                environment=environment,
                output=output / "reports" / "license-inventory.json",
                json_lines=False,
                report_stream="stdout",
                sandbox_profile=sandbox_profile,
                auxiliary_runner=auxiliary_runner,
                receipt_name="license-inventory",
            )
            license_inventory["scope"] = CARGO_DENY_HOST_FILTERED_SCOPE
            validate_cargo_deny_license_inventory(
                read_bounded_regular_file(
                    output / "reports" / "license-inventory.json",
                    max_bytes=MAX_LICENSE_REPORT_BYTES,
                    label="Cargo deny license inventory",
                ),
                cargo_graph,
                scope=CARGO_DENY_HOST_FILTERED_SCOPE,
            )
            license_report = capture_report(
                [
                    "cargo",
                    "deny",
                    "--offline",
                    "--format",
                    "json",
                    "--all-features",
                    "--locked",
                    "check",
                    "--metadata-path",
                    str(metadata_tool_input),
                    "licenses",
                ],
                worktree=worktree,
                environment=environment,
                output=output / "reports" / "license-report.jsonl",
                json_lines=True,
                report_stream="stderr",
                sandbox_profile=sandbox_profile,
                auxiliary_runner=auxiliary_runner,
                receipt_name="license-report",
            )
            validate_cargo_deny_license_policy_jsonl(
                read_bounded_regular_file(
                    output / "reports" / "license-report.jsonl",
                    max_bytes=MAX_LICENSE_REPORT_BYTES,
                    label="Cargo deny license policy report",
                )
            )
            vulnerability_report = capture_report(
                [
                    "cargo",
                    "audit",
                    "--no-fetch",
                    "--stale",
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
                report_stream="stdout",
                sandbox_profile=sandbox_profile,
                auxiliary_runner=auxiliary_runner,
                receipt_name="vulnerability-report",
            )
            expected_package_receipts = tuple(
                f"cargo-package-run-{run_index}-{package['crate']}"
                for run_index in (1, 2)
                for package in packages
            )
            expected_auxiliary_receipts = (
                "cargo-metadata",
                "source-archive-run-1",
                "source-archive-run-2",
                *expected_package_receipts,
                "cyclonedx-sboms-run-1",
                "cyclonedx-sboms-run-2",
                "license-inventory",
                "license-report",
                "vulnerability-report",
            )
            if (
                len(expected_auxiliary_receipts) != 22
                or tuple(receipt.get("name") for receipt in auxiliary_receipts)
                != expected_auxiliary_receipts
            ):
                raise ReviewError(
                    "artifact-generation command receipt set or order drifted"
                )
            comparisons = [
                archive_comparison,
                *package_comparisons,
                *sbom_comparisons,
            ]
            if len(comparisons) != 15:
                raise ReviewError("reproducibility comparison count drifted")
            reproducibility = {
                "schema": "galadriel.reproducibility-comparison.v1",
                "candidate": {"commit": commit, "tree": tree},
                "status": "PASS",
                "comparisons": comparisons,
            }
            (output / "REPRODUCIBILITY.json").write_bytes(
                canonical_json(reproducibility)
            )
            verify_materialized_candidate(worktree, commit, tree)
            if repository_control_snapshot(worktree) != clone_control:
                raise ReviewError(
                    "standalone candidate clone changed during qualification"
                )
        else:
            archive = None
            cargo_metadata_record = None
            packages = []
            sboms = []
            sbom_comparisons = []
            license_report = None
            license_inventory = None
            vulnerability_report = None
            reproducibility = None

        reject_cargo_configuration(worktree, Path(environment["CARGO_HOME"]))

        def tool_output(argv: list[str]) -> str:
            return capture(
                argv,
                worktree,
                environment=environment,
                sandbox_profile=sandbox_profile,
            )

        tools = {
            "git": tool_output(["git", "--version"]),
            "rustc": tool_output(["rustc", "-Vv"]),
            "cargo": tool_output(["cargo", "-Vv"]),
            "rustc_current_stable": tool_output(["rustc", "+1.97.1", "-Vv"]),
            "cargo_current_stable": tool_output(["cargo", "+1.97.1", "-Vv"]),
            "rustc_fuzz_nightly": tool_output(["rustc", "+nightly-2026-06-16", "-Vv"]),
            "python": tool_output(["python3", "--version"]),
            "cargo_deny": tool_output(["cargo", "deny", "--version"]),
            "cargo_audit": tool_output(["cargo", "audit", "--version"]),
            "cargo_cyclonedx": tool_output(["cargo", "cyclonedx", "--version"]),
            "cargo_public_api": tool_output(["cargo", "public-api", "--version"]),
            "cargo_fuzz": tool_output(
                ["cargo", "+nightly-2026-06-16", "fuzz", "--version"]
            ),
        }
        reject_cargo_configuration(worktree, Path(environment["CARGO_HOME"]))
        acceptance_status = None if acceptance is None else acceptance["status"]
        status, release_gate = qualification_outcome(
            command_status=command_status,
            archive_present=archive is not None,
            acceptance_status=acceptance_status,
            deep_requested=bool(arguments.deep),
        )
        repository_identity_after, origin_main_after = refresh_canonical_origin_main(
            repo, commit
        )
        if repository_identity_after != repository_identity:
            raise ReviewError(
                "candidate repository identity changed during qualification"
            )
        source_snapshot_after = repository_control_snapshot(repo)
        if source_snapshot_after != source_snapshot:
            raise ReviewError("operator repository changed during qualification")
        if origin_main_after != origin_main:
            raise ReviewError("origin/main changed during qualification")
        advisory_source_snapshot_after = repository_control_snapshot(
            advisory_source_path
        )
        if advisory_source_snapshot_after != advisory_source_snapshot:
            raise ReviewError("advisory database source changed during qualification")
        for database_path in advisory_database_paths:
            verify_materialized_candidate(
                database_path, ADVISORY_DB_COMMIT, ADVISORY_DB_TREE
            )
        tool_files_after = qualification_tool_files(environment)
        if tool_files_after != tool_files_before:
            raise ReviewError("a qualification executable changed during the run")
        clone_control_after = repository_control_snapshot(worktree)
        if clone_control_after != clone_control:
            raise ReviewError("standalone candidate clone control state changed")
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
                "repository": repository_identity,
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
            "tool_files": {
                "status": "UNCHANGED",
                "executables": tool_files_before,
            },
            "environment_contract": qualification_environment_contract(
                source_date_epoch
            ),
            "sandbox": {
                "executor": str(SANDBOX_EXECUTABLE),
                "policy_path": "sandbox/candidate.sb",
                "policy_sha256": sandbox_profile_sha256,
                "dependency_fetch_policy_path": ("sandbox/dependency-fetch.sb"),
                "dependency_fetch_policy_sha256": (
                    dependency_fetch_sandbox_profile_sha256
                ),
                "candidate_source_write_policy": "DENY",
                "operator_repository_access_policy": "DENY_READ_AND_WRITE",
                "host_home_read_policy": "DENY_EXCEPT_REQUIRED_TOOL_INPUTS",
                "write_policy": "DENY_EXCEPT_DECLARED_PRIVATE_OUTPUTS",
                "network_policy": "DENY_EXCEPT_LOCKED_DEPENDENCY_FETCH",
                "process_containment_policy": CONTAINMENT_POLICY,
                "process_containment_limitation": CONTAINMENT_RESIDUAL,
                "bindings": sandbox_bindings,
            },
            "repository_control": {
                "status": "UNCHANGED",
                "origin_main": origin_main,
                "source_before": source_snapshot,
                "source_after": source_snapshot_after,
                "standalone_clone_before": clone_control,
                "standalone_clone_after": clone_control_after,
                "advisory_source_before": advisory_source_snapshot,
                "advisory_source_after": advisory_source_snapshot_after,
            },
            "advisory_database": advisory_database,
            "deep_campaigns_requested": bool(arguments.deep),
            "evidence_config": None
            if arguments.skip_evidence
            else arguments.evidence_config,
            "commands": results,
            "auxiliary_commands": auxiliary_receipts,
            "acceptance": {
                "path": "candidate-acceptance.json",
                "status": acceptance_status,
                "failed_criterion_ids": []
                if acceptance is None
                else acceptance["failed_criterion_ids"],
            },
            "evidence_config_binding": config_binding,
            "source_archive": archive,
            "cargo_metadata": cargo_metadata_record,
            "packages": packages,
            "sboms": sboms,
            "license_report": license_report,
            "license_inventory": license_inventory,
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
        if config_binding is None:
            raise ReviewError(
                "successful qualification lacks an evidence-config binding"
            )
        write_atomic_canonical_json(output / "qualification.json", qualification)
        provenance_products = artifact_rows(
            output,
            {
                "provenance.json",
                "QUALIFICATION-MANIFEST.json",
                "QUALIFICATION-MANIFEST.json.sig",
                "SHA256SUMS",
            },
        )
        provenance = {
            "schema": "galadriel.slsa-provenance.v2",
            "release": VERSION,
            "candidate": {
                "repository": repository_identity,
                "commit": commit,
                "tree": tree,
            },
            "builder": {
                "kind": "author-operated sandboxed standalone qualification clone",
                "tools": tools,
                "tool_file_inventory_sha256": hashlib.sha256(
                    canonical_json(tool_files_before)
                ).hexdigest(),
            },
            "invocation": {
                "source_date_epoch": int(source_date_epoch),
                "deep_campaigns_requested": bool(arguments.deep),
                "environment_contract_sha256": hashlib.sha256(
                    canonical_json(
                        qualification_environment_contract(source_date_epoch)
                    )
                ).hexdigest(),
                "command_receipts_sha256": hashlib.sha256(
                    canonical_json(results)
                ).hexdigest(),
                "auxiliary_receipts_sha256": hashlib.sha256(
                    canonical_json(auxiliary_receipts)
                ).hexdigest(),
                "sandbox_policy_sha256": sandbox_profile_sha256,
                "dependency_fetch_policy_sha256": (
                    dependency_fetch_sandbox_profile_sha256
                ),
                "network_policy": "DENY_EXCEPT_LOCKED_DEPENDENCY_FETCH",
            },
            "materials": {
                "candidate_cargo_lock_sha256": digest_file(worktree / "Cargo.lock")[0],
                "evidence_config": {
                    "path": arguments.evidence_config,
                    "sha256": config_binding["tracked_blob_sha256"],
                },
                "mutation_manifest_sha256": mutation_record["manifest_sha256"],
                "mutation_signature_sha256": digest_file(
                    mutation_output / "manifest.json.sig"
                )[0],
                "independent_allowed_signers_sha256": hashlib.sha256(
                    expected_signer_metadata
                ).hexdigest(),
                "advisory_database": advisory_database,
            },
            "products": provenance_products,
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
        repository_identity_final, origin_main_final = refresh_canonical_origin_main(
            repo, commit
        )
        if (
            repository_identity_final != repository_identity
            or origin_main_final != origin_main
            or repository_control_snapshot(repo) != source_snapshot
        ):
            raise ReviewError(
                "candidate repository changed before qualification return"
            )
        return 0 if status == "PASS" else 1
    except (OSError, ReviewError, ValueError) as error:
        failure = str(error)
        print(f"candidate qualification failed: {failure}", file=sys.stderr)
        if output.is_dir():
            failure_record = {
                "schema": SCHEMA,
                "release": VERSION,
                "author": "Sepehr Mahmoudian",
                "status": "FAIL",
                "error": failure,
                "commands": results,
            }
            write_atomic_canonical_json(
                output / "qualification.json",
                failure_record,
            )
        return 2
    finally:
        if temporary is not None:
            temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
