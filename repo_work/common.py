"""Shared, dependency-free helpers for release review utilities."""

from __future__ import annotations

import hashlib
import json
import math
import os
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Literal, Mapping, NamedTuple, Sequence, overload

if __package__:
    from .process_containment import (
        CANDIDATE_TREE_CONTAINMENT,
        HOST_PROCESS_CONTAINMENT_MODES,
        PROCESS_GROUP_CONTAINMENT,
        LinuxCandidateTreeContainment,
        ProcessContainmentError,
        ProcessFinalization,
        finalize_process_group,
        process_group_launch_arguments,
        root_process_exited,
    )
else:
    from process_containment import (
        CANDIDATE_TREE_CONTAINMENT,
        HOST_PROCESS_CONTAINMENT_MODES,
        PROCESS_GROUP_CONTAINMENT,
        LinuxCandidateTreeContainment,
        ProcessContainmentError,
        ProcessFinalization,
        finalize_process_group,
        process_group_launch_arguments,
        root_process_exited,
    )


class ReviewError(RuntimeError):
    """The checkout or review input violates the review contract."""


JSON_INTEGER_MAX_DIGITS = 128
JSON_INTEGER_ABSOLUTE_BOUND = 10**JSON_INTEGER_MAX_DIGITS - 1
MAX_GIT_CAPTURE_BYTES = 256 * 1024 * 1024
MAX_GIT_DIAGNOSTIC_BYTES = 64 * 1024
MAX_GIT_REPLACEMENT_REF_BYTES = 4 * 1024
DEFAULT_GIT_TIMEOUT_SECONDS = 120
MAX_GIT_TIMEOUT_SECONDS = 600
DEFAULT_HOST_COMMAND_TIMEOUT_SECONDS = 120
MAX_HOST_COMMAND_TIMEOUT_SECONDS = 86_400
HOST_COMMAND_STOP_TIMEOUT_SECONDS = 5
DEFAULT_HOST_COMMAND_STDOUT_BYTES = 1024 * 1024
DEFAULT_HOST_COMMAND_STDERR_BYTES = 64 * 1024
MAX_HOST_COMMAND_STDOUT_BYTES = 256 * 1024 * 1024
MAX_HOST_COMMAND_STDERR_BYTES = 256 * 1024 * 1024
MAX_HOST_COMMAND_STDIN_BYTES = 64 * 1024 * 1024
MAX_TRUSTED_EXECUTABLE_BYTES = 1024 * 1024 * 1024
SAFE_GIT_CONFIGURATION = (
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.attributesFile=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-c",
    "color.ui=false",
)
TRUSTED_DARWIN_GIT_PATHS = (
    Path("/Applications/Xcode.app/Contents/Developer/usr/bin/git"),
    Path("/Library/Developer/CommandLineTools/usr/bin/git"),
)
TRUSTED_SYSTEM_EXECUTABLE_PATHS = {
    "git": Path("/usr/bin/git"),
    "sandbox-exec": Path("/usr/bin/sandbox-exec"),
    "ssh-add": Path("/usr/bin/ssh-add"),
    "ssh-keygen": Path("/usr/bin/ssh-keygen"),
}
TRUSTED_EXECUTABLE_NAMES = frozenset(TRUSTED_SYSTEM_EXECUTABLE_PATHS)
SENSITIVE_ENVIRONMENT_FRAGMENTS = (
    "ACCESS_KEY",
    "API_KEY",
    "APIKEY",
    "AUTH",
    "COOKIE",
    "CREDENTIAL",
    "PASSWORD",
    "PASSWD",
    "PRIVATE_KEY",
    "SECRET",
    "SESSION",
    "TOKEN",
)
SENSITIVE_ENVIRONMENT_NAMES = frozenset(
    {
        "AWS_PROFILE",
        "CLOUDSDK_CONFIG",
        "DOCKER_CONFIG",
        "GPG_AGENT_INFO",
        "KUBECONFIG",
        "NETRC",
        "SSH_AGENT_PID",
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        "SSH_AUTH_SOCK",
        "DEVELOPER_DIR",
        "LIBPATH",
        "PKCS11_PROVIDER",
        "SHLIB_PATH",
        "SSH_SK_PROVIDER",
        "TOOLCHAINS",
    }
)
UNSAFE_ENVIRONMENT_PREFIXES = ("DYLD_", "LD_")


def _close_file_descriptors(
    descriptors: Sequence[int],
    *,
    context: str,
) -> None:
    """Close every descriptor without masking an active validation failure."""

    active_failure = sys.exc_info()[0] is not None
    first_error: OSError | None = None
    closed: set[int] = set()
    for descriptor in descriptors:
        if descriptor < 0 or descriptor in closed:
            continue
        closed.add(descriptor)
        try:
            os.close(descriptor)
        except OSError as error:
            if first_error is None:
                first_error = error
    if first_error is not None and not active_failure:
        raise ReviewError(f"{context} descriptor cleanup failed") from first_error


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object while rejecting duplicate member names."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReviewError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def reject_nonstandard_constant(value: str) -> Any:
    """Reject the non-JSON constants accepted by Python's decoder."""

    raise ValueError(f"nonstandard JSON constant: {value}")


def parse_finite_float(value: str) -> float:
    """Decode a JSON fraction only when it fits the finite float domain."""

    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"JSON number is outside the finite float range: {value!r}")
    mantissa = value.split("e", 1)[0].split("E", 1)[0]
    if parsed == 0.0 and any(character in "123456789" for character in mantissa):
        raise ValueError(f"JSON number is outside the finite float range: {value!r}")
    return parsed


def parse_bounded_integer(value: str) -> int:
    """Decode a valid JSON integer with a deterministic resource bound.

    JSON integers are exact and retained evidence legitimately contains unsigned 64-bit
    seeds above binary64's consecutive-integer range. Schema validators decide where a
    smaller numeric domain is required; this lexical bound prevents oversized integer
    tokens from becoming unbounded parser work.
    """

    digits = value.removeprefix("-")
    if len(digits) > JSON_INTEGER_MAX_DIGITS:
        raise ValueError(
            f"JSON integer exceeds {JSON_INTEGER_MAX_DIGITS} decimal digits"
        )
    return int(value)


def validate_json_number_bounds(value: Any) -> None:
    """Require generated JSON numbers to round-trip through :func:`loads_json`."""

    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        if abs(value) > JSON_INTEGER_ABSOLUTE_BOUND:
            raise ValueError(
                f"JSON integer exceeds {JSON_INTEGER_MAX_DIGITS} decimal digits"
            )
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON float is not finite")
        return
    if isinstance(value, dict):
        for item in value.values():
            validate_json_number_bounds(item)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            validate_json_number_bounds(item)


def loads_json(
    document: str | bytes,
    *,
    object_pairs_hook: Callable[[list[tuple[str, Any]]], Any] = reject_duplicate_pairs,
) -> Any:
    """Decode strict UTF-8 JSON with finite floats and bounded integer tokens."""

    if isinstance(document, bytes):
        try:
            document = document.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("JSON input is not valid UTF-8") from error
    return json.loads(
        document,
        object_pairs_hook=object_pairs_hook,
        parse_constant=reject_nonstandard_constant,
        parse_float=parse_finite_float,
        parse_int=parse_bounded_integer,
    )


def read_bounded_regular_file(path: Path, *, max_bytes: int, label: str) -> bytes:
    """Read one unchanged regular file without following its final component."""

    if max_bytes < 0:
        raise ReviewError(f"{label} byte limit must be nonnegative")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReviewError(f"cannot open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ReviewError(f"{label} is not a regular file: {path}")
        if before.st_size > max_bytes:
            raise ReviewError(f"{label} exceeds {max_bytes} bytes: {before.st_size}")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise ReviewError(f"{label} exceeds {max_bytes} bytes")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or len(data) != before.st_size:
            raise ReviewError(f"{label} changed while it was read")
        return data
    finally:
        _close_file_descriptors([descriptor], context=label)


def validate_json_structure(
    value: Any, *, max_depth: int, max_nodes: int, label: str
) -> None:
    """Bound the decoded JSON container depth and node count."""

    if max_depth < 0 or max_nodes < 1:
        raise ReviewError(f"{label} JSON structure limits are invalid")
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > max_nodes:
            raise ReviewError(f"{label} exceeds {max_nodes} JSON nodes")
        if isinstance(item, dict):
            if depth >= max_depth and item:
                raise ReviewError(f"{label} exceeds JSON depth {max_depth}")
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            if depth >= max_depth and item:
                raise ReviewError(f"{label} exceeds JSON depth {max_depth}")
            pending.extend((child, depth + 1) for child in item)


def load_json(
    path: Path,
    *,
    max_bytes: int | None = None,
    max_depth: int | None = None,
    max_nodes: int | None = None,
    label: str | None = None,
) -> Any:
    """Load strict UTF-8 JSON with optional deterministic resource bounds."""

    try:
        if max_bytes is None:
            document = path.read_bytes()
        else:
            document = read_bounded_regular_file(
                path, max_bytes=max_bytes, label=label or str(path)
            )
        value = loads_json(document)
        if (max_depth is None) != (max_nodes is None):
            raise ReviewError("JSON depth and node limits must be supplied together")
        if max_depth is not None and max_nodes is not None:
            validate_json_structure(
                value,
                max_depth=max_depth,
                max_nodes=max_nodes,
                label=label or str(path),
            )
        return value
    except ReviewError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError, MemoryError) as error:
        raise ReviewError(f"cannot load {path}: {error}") from error


def canonical_json(value: Any) -> bytes:
    """Return deterministic, human-readable UTF-8 JSON bytes."""

    try:
        validate_json_number_bounds(value)
        encoded = json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
    except ValueError as error:
        raise ReviewError(f"cannot encode canonical JSON: {error}") from error
    return (encoded + "\n").encode("utf-8")


class TrustedExecutableIdentity(NamedTuple):
    """One root-owned executable identity captured through a held descriptor."""

    path: str
    device: int
    inode: int
    mode: int
    links: int
    uid: int
    gid: int
    size: int
    modified_ns: int
    changed_ns: int
    sha256: str


def _trusted_executable_identity(path: Path) -> TrustedExecutableIdentity:
    """Capture one fixed executable without following a symbolic link."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ReviewError("trusted executable no-follow reads are unavailable")
    try:
        if path.resolve(strict=True) != path:
            raise ReviewError(f"trusted executable path is indirect: {path}")
        path_before = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0),
        )
    except ReviewError:
        raise
    except OSError as error:
        raise ReviewError(f"trusted executable is unavailable: {path}") from error
    try:
        before = os.fstat(descriptor)
        initial = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if initial != (
            path_before.st_dev,
            path_before.st_ino,
            path_before.st_mode,
            path_before.st_nlink,
            path_before.st_uid,
            path_before.st_gid,
            path_before.st_size,
            path_before.st_mtime_ns,
            path_before.st_ctime_ns,
        ):
            raise ReviewError(f"trusted executable changed before capture: {path}")
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink < 1
            or before.st_uid != 0
            or stat.S_IMODE(before.st_mode) & 0o022
            or not before.st_mode & stat.S_IXUSR
            or before.st_size <= 0
            or before.st_size > MAX_TRUSTED_EXECUTABLE_BYTES
        ):
            raise ReviewError(f"trusted executable identity is unsafe: {path}")
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > MAX_TRUSTED_EXECUTABLE_BYTES:
                raise ReviewError(f"trusted executable exceeds its byte limit: {path}")
            digest.update(block)
        after = os.fstat(descriptor)
        try:
            path_after = path.lstat()
        except OSError as error:
            raise ReviewError(f"trusted executable disappeared: {path}") from error
        final = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        path_final = (
            path_after.st_dev,
            path_after.st_ino,
            path_after.st_mode,
            path_after.st_nlink,
            path_after.st_uid,
            path_after.st_gid,
            path_after.st_size,
            path_after.st_mtime_ns,
            path_after.st_ctime_ns,
        )
        if initial != final or initial != path_final or total != before.st_size:
            raise ReviewError(f"trusted executable changed during capture: {path}")
        return TrustedExecutableIdentity(
            str(path),
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            digest.hexdigest(),
        )
    finally:
        _close_file_descriptors([descriptor], context="trusted executable")


def trusted_host_executable_path(name: str) -> Path:
    """Return one fixed, root-owned executable for a critical host tool."""

    if name not in TRUSTED_EXECUTABLE_NAMES:
        raise ReviewError(f"unknown trusted host executable: {name!r}")
    if name == "git" and sys.platform == "darwin":
        for candidate in TRUSTED_DARWIN_GIT_PATHS:
            try:
                candidate.lstat()
            except FileNotFoundError:
                continue
            except OSError as error:
                raise ReviewError(
                    f"cannot inspect trusted Git executable: {candidate}"
                ) from error
            _trusted_executable_identity(candidate)
            return candidate
        raise ReviewError("a direct Apple developer Git executable is unavailable")
    candidate = TRUSTED_SYSTEM_EXECUTABLE_PATHS[name]
    _trusted_executable_identity(candidate)
    return candidate


def _prepare_trusted_executables(
    arguments: Sequence[str],
    auxiliary_names: Sequence[str],
) -> tuple[list[str], tuple[tuple[str, Path, TrustedExecutableIdentity], ...]]:
    """Pin each critical executable and capture its pre-execution identity."""

    executed = list(arguments)
    records: list[tuple[str, Path, TrustedExecutableIdentity]] = []
    primary_name = Path(executed[0]).name
    names = list(auxiliary_names)
    if primary_name in TRUSTED_EXECUTABLE_NAMES:
        selected = trusted_host_executable_path(primary_name)
        if executed[0] not in {primary_name, str(selected)}:
            raise ReviewError(
                f"host command names an unapproved {primary_name} executable"
            )
        executed[0] = str(selected)
        names.insert(0, primary_name)
    if (
        any(name not in TRUSTED_EXECUTABLE_NAMES for name in names)
        or len(names) != len(set(names))
    ):
        raise ReviewError("trusted auxiliary executable set is invalid")
    for name in names:
        path = trusted_host_executable_path(name)
        records.append((name, path, _trusted_executable_identity(path)))
    return executed, tuple(records)


def _verify_trusted_executables(
    records: Sequence[tuple[str, Path, TrustedExecutableIdentity]],
) -> None:
    """Require every critical executable to retain its captured identity."""

    for name, path, expected in records:
        if _trusted_executable_identity(path) != expected:
            raise ReviewError(f"trusted {name} executable changed during execution")


class BoundedHostResult(NamedTuple):
    """One bounded host-command result."""

    returncode: int
    stdout: bytes
    stderr: bytes


_HOST_LAUNCH_SIGNAL_MASK_POISONED = False


class _LaunchSignalMask:
    """Own one temporary signal mask during a host launch."""

    def __init__(self, *, context: str, previous_mask: frozenset[int]) -> None:
        self.context = context
        self.previous_mask = previous_mask
        self.restored = True

    @classmethod
    def capture(cls, *, context: str) -> _LaunchSignalMask:
        """Capture the exact signal mask without changing it."""

        if _HOST_LAUNCH_SIGNAL_MASK_POISONED:
            raise ReviewError(
                "host launch is unavailable after signal-mask restoration failure"
            )
        try:
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        except (OSError, ValueError) as error:
            raise ReviewError(
                f"{context} cannot inspect its host launch signal mask"
            ) from error
        return cls(
            context=context,
            previous_mask=frozenset(int(value) for value in previous_mask),
        )

    def block(self) -> None:
        """Block catchable signals after the caller owns this object."""

        if not self.restored:
            raise ReviewError(f"{self.context} launch signal mask is already active")

        blocked_signals = {int(value) for value in signal.valid_signals()}
        blocked_signals.discard(int(signal.SIGKILL))
        blocked_signals.discard(int(signal.SIGSTOP))
        self.restored = False
        signal.pthread_sigmask(
            signal.SIG_BLOCK,
            blocked_signals,
        )
        current_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        expected_mask = self.previous_mask | blocked_signals
        if frozenset(int(value) for value in current_mask) != expected_mask:
            raise ReviewError(f"{self.context} did not block its launch signals")

    def restore(self) -> None:
        """Restore and verify the exact signal mask."""

        if self.restored:
            return
        restore_error: BaseException | None = None
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, self.previous_mask)
        except BaseException as error:
            restore_error = error

        verification_error: BaseException | None = None
        try:
            current_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        except BaseException as error:
            verification_error = error
        else:
            observed_mask = frozenset(int(value) for value in current_mask)
            if observed_mask == self.previous_mask:
                self.restored = True
            else:
                verification_error = ReviewError(
                    f"{self.context} did not restore its launch signal mask"
                )

        if restore_error is not None:
            if verification_error is not None and hasattr(restore_error, "add_note"):
                restore_error.add_note(
                    "launch signal-mask verification also failed: "
                    f"{type(verification_error).__name__}: {verification_error}"
                )
            if isinstance(restore_error, (OSError, ValueError)):
                raise ReviewError(
                    f"{self.context} cannot restore its launch signal mask"
                ) from restore_error
            raise restore_error
        if verification_error is not None:
            if isinstance(verification_error, ReviewError):
                raise verification_error
            raise ReviewError(
                f"{self.context} cannot verify its launch signal mask"
            ) from verification_error


_SUBPROCESS_POPEN_TYPE = subprocess.Popen


def _stop_mock_bounded_host_process(
    process: subprocess.Popen[bytes],
    context: str,
) -> None:
    """Keep deterministic signal coverage for a synthetic process test double."""

    signal_errors: list[OSError] = []

    def signal_active_group(signal_number: int) -> None:
        try:
            os.killpg(process.pid, signal_number)
        except ProcessLookupError:
            pass
        except OSError as group_error:
            signal_errors.append(group_error)
            try:
                process.send_signal(signal_number)
            except ProcessLookupError:
                pass
            except OSError as process_error:
                signal_errors.append(process_error)

    leader_stopped = False
    signal_active_group(signal.SIGTERM)
    try:
        process.wait(timeout=HOST_COMMAND_STOP_TIMEOUT_SECONDS)
        leader_stopped = True
    except (OSError, subprocess.TimeoutExpired) as error:
        if isinstance(error, OSError):
            signal_errors.append(error)
    signal_active_group(signal.SIGKILL)
    try:
        process.wait(timeout=HOST_COMMAND_STOP_TIMEOUT_SECONDS)
        leader_stopped = True
    except (OSError, subprocess.TimeoutExpired) as error:
        if isinstance(error, OSError):
            signal_errors.append(error)
    if not leader_stopped:
        error = ReviewError(f"{context} did not terminate within its stop bound")
        if signal_errors:
            raise error from signal_errors[-1]
        raise error


def _stop_bounded_host_process(
    process: subprocess.Popen[bytes],
    context: str,
    *,
    candidate_tree: LinuxCandidateTreeContainment | None = None,
    force_stop: bool = True,
) -> ProcessFinalization | None:
    """Stop, reap, and verify one isolated host command."""

    if not isinstance(process, _SUBPROCESS_POPEN_TYPE):
        _stop_mock_bounded_host_process(process, context)
        return None
    try:
        if candidate_tree is not None:
            return candidate_tree.finalize(process, force_stop=force_stop)
        return finalize_process_group(
            process,
            force_stop=force_stop,
            stop_timeout_seconds=HOST_COMMAND_STOP_TIMEOUT_SECONDS,
        )
    except ProcessContainmentError as error:
        raise ReviewError(f"{context} process containment failed: {error}") from error


def run_bounded_host_command(
    arguments: Sequence[str],
    *,
    context: str,
    stdin_document: bytes | None = None,
    environment: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    merge_stderr: bool = False,
    max_stdout_bytes: int = DEFAULT_HOST_COMMAND_STDOUT_BYTES,
    max_stderr_bytes: int = DEFAULT_HOST_COMMAND_STDERR_BYTES,
    timeout_seconds: int = DEFAULT_HOST_COMMAND_TIMEOUT_SECONDS,
    containment: str = PROCESS_GROUP_CONTAINMENT,
    trusted_auxiliary_executables: Sequence[str] = (),
) -> BoundedHostResult:
    """Run one host command with fixed time and stream-memory bounds.

    Process-group mode covers only the root and its original process group.
    It does not track a descendant that enters another session.
    Candidate-tree mode adds the declared Linux recursive cleanup controls.
    """

    global _HOST_LAUNCH_SIGNAL_MASK_POISONED

    if (
        isinstance(arguments, (str, bytes))
        or not arguments
        or any(
            not isinstance(argument, str) or "\0" in argument for argument in arguments
        )
        or not isinstance(context, str)
        or not context
        or type(merge_stderr) is not bool
        or containment not in HOST_PROCESS_CONTAINMENT_MODES
        or isinstance(trusted_auxiliary_executables, (str, bytes))
        or any(
            not isinstance(name, str) or not name
            for name in trusted_auxiliary_executables
        )
    ):
        raise ReviewError("host command arguments are invalid")
    if (
        type(max_stdout_bytes) is not int
        or max_stdout_bytes < 0
        or max_stdout_bytes > MAX_HOST_COMMAND_STDOUT_BYTES
        or type(max_stderr_bytes) is not int
        or max_stderr_bytes < 0
        or max_stderr_bytes > MAX_HOST_COMMAND_STDERR_BYTES
    ):
        raise ReviewError(f"{context} has invalid output byte limits")
    if (
        type(timeout_seconds) is not int
        or timeout_seconds < 1
        or timeout_seconds > MAX_HOST_COMMAND_TIMEOUT_SECONDS
    ):
        raise ReviewError(f"{context} has an invalid timeout")
    if stdin_document is not None:
        if not isinstance(stdin_document, bytes):
            raise ReviewError(f"{context} input is not bytes")
        if len(stdin_document) > MAX_HOST_COMMAND_STDIN_BYTES:
            raise ReviewError(f"{context} input exceeds its byte bound")
    if environment is not None and (
        not isinstance(environment, Mapping)
        or any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or "\0" in key
            or "\0" in value
            for key, value in environment.items()
        )
    ):
        raise ReviewError(f"{context} environment is invalid")
    if cwd is not None and (not isinstance(cwd, Path) or "\0" in os.fspath(cwd)):
        raise ReviewError(f"{context} working directory is invalid")
    executed_arguments, trusted_executables = _prepare_trusted_executables(
        arguments,
        trusted_auxiliary_executables,
    )

    candidate_tree: LinuxCandidateTreeContainment | None = None
    launch_signal_mask: _LaunchSignalMask | None = None
    stdin_file: Any | None = None
    process: subprocess.Popen[bytes] | None = None
    process_finalized = False
    selector: selectors.BaseSelector | None = None
    try:
        launch_signal_mask = _LaunchSignalMask.capture(context=context)
        launch_signal_mask.block()
        if containment == CANDIDATE_TREE_CONTAINMENT:
            candidate_tree = LinuxCandidateTreeContainment(
                context=context,
                stop_timeout_seconds=HOST_COMMAND_STOP_TIMEOUT_SECONDS,
            )
            candidate_tree.activate()
        stdin_file = tempfile.TemporaryFile()
        selector = selectors.DefaultSelector()
        if stdin_document is not None:
            stdin_file.write(stdin_document)
            stdin_file.seek(0)
            stdin: int | Any = stdin_file
        else:
            stdin = subprocess.DEVNULL
        try:
            if candidate_tree is None:
                launch_arguments = process_group_launch_arguments(
                    executed_arguments,
                    inherited_signal_mask=tuple(
                        sorted(launch_signal_mask.previous_mask)
                    ),
                )
            else:
                launch_arguments = candidate_tree.launch_arguments(
                    executed_arguments,
                    inherited_signal_mask=tuple(
                        sorted(launch_signal_mask.previous_mask)
                    ),
                )
            process = subprocess.Popen(
                launch_arguments,
                stdin=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
                cwd=cwd,
                env=sanitized_host_environment()
                if environment is None
                else dict(environment),
                shell=False,
                start_new_session=True,
            )
        except BaseException as error:
            try:
                launch_signal_mask.restore()
            except BaseException as cleanup_error:
                if hasattr(error, "add_note"):
                    error.add_note(
                        "host launch signal-mask restoration also failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
            raise
        launch_signal_mask.restore()
        if candidate_tree is not None:
            candidate_tree.arm(process)
        if process.stdout is None or (not merge_stderr and process.stderr is None):
            raise ReviewError(f"{context} did not provide bounded output streams")
        selector.register(
            process.stdout, selectors.EVENT_READ, ("stdout", process.stdout)
        )
        if process.stderr is not None:
            selector.register(
                process.stderr, selectors.EVENT_READ, ("stderr", process.stderr)
            )
        outputs = {"stdout": bytearray(), "stderr": bytearray()}
        limits = {
            "stdout": max_stdout_bytes,
            "stderr": max_stderr_bytes,
        }

        def capture_events(events: Sequence[tuple[Any, Any]]) -> None:
            for key, _event_mask in events:
                stream_name, stream = key.data
                output = outputs[stream_name]
                limit = limits[stream_name]
                read_size = min(64 * 1024, limit - len(output) + 1)
                chunk = os.read(stream.fileno(), read_size)
                if not chunk:
                    selector.unregister(stream)
                    continue
                output.extend(chunk)
                if len(output) > limit:
                    label = (
                        "standard output"
                        if stream_name == "stdout"
                        else "standard error"
                    )
                    raise ReviewError(f"{context} {label} exceeds {limit} bytes")

        def root_exited() -> bool:
            try:
                if candidate_tree is not None:
                    return candidate_tree.root_exited(process)
                return root_process_exited(process)
            except ProcessContainmentError as error:
                raise ReviewError(
                    f"{context} process containment failed: {error}"
                ) from error

        deadline = time.monotonic() + timeout_seconds
        while not root_exited():
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise ReviewError(
                    f"{context} timed out after {timeout_seconds} seconds"
                )
            wait_seconds = min(0.05, remaining_time)
            if selector.get_map():
                capture_events(selector.select(wait_seconds))
            else:
                time.sleep(wait_seconds)
        finalization = _stop_bounded_host_process(
            process,
            context,
            candidate_tree=candidate_tree,
            force_stop=False,
        )
        if finalization is None:
            raise ReviewError(f"{context} process finalization returned no result")
        process_finalized = True
        drain_deadline = time.monotonic() + HOST_COMMAND_STOP_TIMEOUT_SECONDS
        while selector.get_map():
            remaining_time = drain_deadline - time.monotonic()
            if remaining_time <= 0:
                raise ReviewError(
                    f"{context} process streams remained open after cleanup"
                )
            capture_events(selector.select(min(0.05, remaining_time)))
        if finalization.survivor_detected:
            raise ReviewError(f"{context} left a process after its root exited")
        return BoundedHostResult(
            finalization.returncode,
            bytes(outputs["stdout"]),
            bytes(outputs["stderr"]),
        )
    except ProcessContainmentError as error:
        cleanup_error: BaseException | None = None
        if process is not None and not process_finalized:
            try:
                _stop_bounded_host_process(
                    process,
                    context,
                    candidate_tree=candidate_tree,
                    force_stop=True,
                )
                process_finalized = True
            except BaseException as caught_cleanup_error:
                cleanup_error = caught_cleanup_error
        converted = ReviewError(f"{context} process containment failed: {error}")
        if cleanup_error is not None and hasattr(converted, "add_note"):
            converted.add_note(
                "host command cleanup also failed: "
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )
        raise converted from error
    except ReviewError as error:
        if process is not None and not process_finalized:
            try:
                _stop_bounded_host_process(
                    process,
                    context,
                    candidate_tree=candidate_tree,
                    force_stop=True,
                )
                process_finalized = True
            except BaseException as cleanup_error:
                if hasattr(error, "add_note"):
                    error.add_note(
                        "host command cleanup also failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
        raise
    except (OSError, ValueError) as error:
        cleanup_error: BaseException | None = None
        if process is not None and not process_finalized:
            try:
                _stop_bounded_host_process(
                    process,
                    context,
                    candidate_tree=candidate_tree,
                    force_stop=True,
                )
                process_finalized = True
            except BaseException as caught_cleanup_error:
                cleanup_error = caught_cleanup_error
        converted = ReviewError(f"cannot run {context}")
        if cleanup_error is not None and hasattr(converted, "add_note"):
            converted.add_note(
                "host command cleanup also failed: "
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )
        raise converted from error
    except BaseException as error:
        if process is not None and not process_finalized:
            try:
                _stop_bounded_host_process(
                    process,
                    context,
                    candidate_tree=candidate_tree,
                    force_stop=True,
                )
                process_finalized = True
            except BaseException as cleanup_error:
                if hasattr(error, "add_note"):
                    error.add_note(
                        "host command cleanup also failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
        raise
    finally:
        active_error = sys.exc_info()[1]
        cleanup_errors: list[BaseException] = []
        integrity_error: BaseException | None = None

        try:
            _verify_trusted_executables(trusted_executables)
        except BaseException as error:
            integrity_error = error

        def cleanup(action: Callable[[], None]) -> None:
            try:
                action()
            except BaseException as error:
                cleanup_errors.append(error)

        if selector is not None:
            cleanup(selector.close)
        if process is not None:
            if process.stdout is not None:
                cleanup(process.stdout.close)
            if process.stderr is not None:
                cleanup(process.stderr.close)
        if stdin_file is not None:
            cleanup(stdin_file.close)
        if launch_signal_mask is not None and not launch_signal_mask.restored:
            cleanup(launch_signal_mask.restore)
            if not launch_signal_mask.restored:
                _HOST_LAUNCH_SIGNAL_MASK_POISONED = True
                if candidate_tree is not None:
                    candidate_tree.invalidate_launch_signal_mask()
        if candidate_tree is not None:
            cleanup(lambda: candidate_tree.close(process_started=process is not None))
        if integrity_error is not None:
            if active_error is not None:
                if hasattr(active_error, "add_note"):
                    active_error.add_note(
                        "trusted executable verification also failed: "
                        f"{type(integrity_error).__name__}: {integrity_error}"
                    )
            else:
                if hasattr(integrity_error, "add_note"):
                    for cleanup_error in cleanup_errors:
                        integrity_error.add_note(
                            "host command resource cleanup also failed: "
                            f"{type(cleanup_error).__name__}: {cleanup_error}"
                        )
                raise integrity_error
        if cleanup_errors:
            if active_error is not None:
                if hasattr(active_error, "add_note"):
                    for cleanup_error in cleanup_errors:
                        active_error.add_note(
                            "host command resource cleanup also failed: "
                            f"{type(cleanup_error).__name__}: {cleanup_error}"
                        )
            else:
                error = ReviewError(f"{context} resource cleanup failed")
                if hasattr(error, "add_note"):
                    for cleanup_error in cleanup_errors[1:]:
                        error.add_note(
                            "additional host command resource cleanup failure: "
                            f"{type(cleanup_error).__name__}: {cleanup_error}"
                        )
                raise error from cleanup_errors[0]


@overload
def git(
    repo: Path,
    *arguments: str,
    text: Literal[True] = True,
    environment: dict[str, str] | None = None,
    max_bytes: int = MAX_GIT_CAPTURE_BYTES,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> str: ...


@overload
def git(
    repo: Path,
    *arguments: str,
    text: Literal[False],
    environment: dict[str, str] | None = None,
    max_bytes: int = MAX_GIT_CAPTURE_BYTES,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> bytes: ...


def git(
    repo: Path,
    *arguments: str,
    text: bool = True,
    environment: dict[str, str] | None = None,
    max_bytes: int = MAX_GIT_CAPTURE_BYTES,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> str | bytes:
    """Run Git with fixed configuration and a bounded standard output."""

    document = git_bounded_output(
        repo,
        *arguments,
        max_bytes=max_bytes,
        environment=environment,
        timeout_seconds=timeout_seconds,
    )
    if not text:
        return document
    try:
        return document.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ReviewError(
            f"git {' '.join(arguments)} produced non-UTF-8 output"
        ) from error


def git_bounded_output(
    repo: Path,
    *arguments: str,
    max_bytes: int,
    environment: dict[str, str] | None = None,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> bytes:
    """Run Git and return stdout only when it fits an exact byte bound."""

    if type(max_bytes) is not int or max_bytes < 0 or max_bytes > MAX_GIT_CAPTURE_BYTES:
        raise ReviewError(
            f"Git output byte limit must be an integer from 0 through "
            f"{MAX_GIT_CAPTURE_BYTES}"
        )
    if (
        type(timeout_seconds) is not int
        or timeout_seconds < 1
        or timeout_seconds > MAX_GIT_TIMEOUT_SECONDS
    ):
        raise ReviewError(
            "Git timeout must be an integer from 1 through "
            f"{MAX_GIT_TIMEOUT_SECONDS} seconds"
        )
    context = f"git {' '.join(arguments)}"
    process = run_bounded_host_command(
        [
            "git",
            "--no-replace-objects",
            *SAFE_GIT_CONFIGURATION,
            "-C",
            str(repo),
            *arguments,
        ],
        context=context,
        environment=safe_git_environment(environment),
        max_stdout_bytes=max_bytes,
        max_stderr_bytes=MAX_GIT_DIAGNOSTIC_BYTES,
        timeout_seconds=timeout_seconds,
    )
    if len(process.stderr) > MAX_GIT_DIAGNOSTIC_BYTES:
        raise ReviewError(
            f"{context} diagnostic output exceeds {MAX_GIT_DIAGNOSTIC_BYTES} bytes"
        )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", "replace")
        raise ReviewError(
            f"{context} failed with {process.returncode}: {detail.strip()}"
        )
    if len(process.stdout) > max_bytes:
        raise ReviewError(f"{context} output exceeds {max_bytes} bytes")
    return process.stdout


def safe_git_environment(
    environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Remove ambient Git selectors and user configuration from an environment."""

    result = sanitized_host_environment(environment)
    result.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    return result


def sanitized_host_environment(
    environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Remove ambient credential, agent, Git, and proxy selectors."""

    source = os.environ if environment is None else environment
    result: dict[str, str] = {}
    for key, value in source.items():
        normalized = key.upper()
        if (
            normalized.startswith("GIT_")
            or normalized.startswith(UNSAFE_ENVIRONMENT_PREFIXES)
            or normalized in SENSITIVE_ENVIRONMENT_NAMES
            or normalized.endswith("_PROXY")
            or any(
                fragment in normalized for fragment in SENSITIVE_ENVIRONMENT_FRAGMENTS
            )
        ):
            continue
        result[key] = value
    return result


def assert_no_replace_refs(repo: Path) -> None:
    """Reject a repository that contains any Git replacement reference."""

    references = git_bounded_output(
        repo,
        "for-each-ref",
        "--count=1",
        "--format=%(refname)",
        "refs/replace/",
        max_bytes=MAX_GIT_REPLACEMENT_REF_BYTES,
    )
    if references:
        try:
            reference = references.decode("utf-8", "strict").strip()
        except UnicodeDecodeError as error:
            raise ReviewError("Git replacement reference is not valid UTF-8") from error
        raise ReviewError(f"Git replacement references are forbidden: {reference}")


def absolute_path_without_final_resolution(value: str) -> Path:
    """Resolve a path's parent without dereferencing its final component."""

    absolute = Path(os.path.abspath(os.fspath(Path(value).expanduser())))
    return absolute.parent.resolve() / absolute.name


def contained_path(root: Path, relative: str) -> Path:
    """Return a lexical contained path while rejecting every symlink component."""

    candidate = Path(relative)
    if (
        not relative
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ReviewError(f"artifact path must be nonempty and relative: {relative!r}")
    resolved_root = root.resolve()
    lexical = resolved_root / candidate
    current = resolved_root
    for part in candidate.parts:
        current /= part
        if current.is_symlink():
            raise ReviewError(f"artifact path contains a symlink: {relative!r}")
    resolved = lexical.resolve()
    if resolved == resolved_root or resolved_root not in resolved.parents:
        raise ReviewError(f"artifact path escapes root: {relative!r}")
    return lexical


class RootedPathIdentity(NamedTuple):
    """Stable metadata used to detect a path or content replacement."""

    device: int
    inode: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int


class RootedFileDigest(NamedTuple):
    """One bounded digest read through a held root descriptor."""

    sha256: str
    size_bytes: int
    device: int
    inode: int


class RootedFileCapture(NamedTuple):
    """One bounded byte capture read through a held root descriptor."""

    data: bytes
    sha256: str
    size_bytes: int
    device: int
    inode: int


class RootedFileDigestRequest(NamedTuple):
    """One file request in a held-root digest transaction."""

    relative: str
    expected_size: int | None
    label: str
    expected_sha256: str | None = None


class RootedFileCaptureRequest(NamedTuple):
    """One file request in a held-root byte-capture transaction."""

    relative: str
    expected_size: int | None
    label: str
    expected_sha256: str | None = None
    expected_git_mode: str | None = None


class RootedFileBatchCapture(NamedTuple):
    """One immutable result from a held-root byte-capture transaction."""

    relative: str
    data: bytes
    sha256: str
    size_bytes: int
    file_identity: RootedPathIdentity
    directory_identities: tuple[tuple[str, RootedPathIdentity], ...]


class _RootedFileObservation(NamedTuple):
    """Internal identities and bytes from one rooted file read."""

    digest: RootedFileDigest
    data: bytes | None
    file_identity: RootedPathIdentity
    directory_identities: dict[str, RootedPathIdentity]


def rooted_path_identity(metadata: os.stat_result) -> RootedPathIdentity:
    """Return the metadata fields that bind one opened file-system object."""

    return RootedPathIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        links=metadata.st_nlink,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def canonical_relative_parts(
    value: str,
    *,
    label: str,
    max_path_bytes: int = 4 * 1024,
    max_component_bytes: int = 255,
    max_depth: int = 128,
) -> tuple[str, ...]:
    """Validate one canonical Portable Operating System Interface path."""

    if (
        type(label) is not str
        or not label
        or type(max_path_bytes) is not int
        or max_path_bytes < 1
        or type(max_component_bytes) is not int
        or max_component_bytes < 1
        or type(max_depth) is not int
        or max_depth < 1
    ):
        raise ReviewError("canonical path limits are invalid")
    if type(value) is not str or not value:
        raise ReviewError(f"{label} must be a nonempty relative path")
    if "\\" in value or "\x00" in value or value.startswith("/"):
        raise ReviewError(f"{label} is unsafe: {value!r}")
    parts = value.split("/")
    if (
        any(part in {"", ".", ".."} for part in parts)
        or PurePosixPath(value).as_posix() != value
    ):
        raise ReviewError(f"{label} is not canonical: {value!r}")
    if len(parts) > max_depth:
        raise ReviewError(f"{label} exceeds the {max_depth}-component limit")
    try:
        encoded_path = value.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise ReviewError(f"{label} is not valid UTF-8: {value!r}") from error
    if len(encoded_path) > max_path_bytes:
        raise ReviewError(f"{label} exceeds {max_path_bytes} UTF-8 bytes")
    for part in parts:
        encoded = part.encode("utf-8", "strict")
        if len(encoded) > max_component_bytes:
            raise ReviewError(
                f"{label} component exceeds {max_component_bytes} UTF-8 bytes"
            )
        if any(ord(character) < 32 or ord(character) == 127 for character in part):
            raise ReviewError(f"{label} contains a control character: {value!r}")
    return tuple(parts)


def _rooted_descriptor_flags(*, directory: bool) -> int:
    """Return the required nonblocking, no-follow descriptor flags."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    close_on_exec = getattr(os, "O_CLOEXEC", None)
    if (
        no_follow is None
        or non_block is None
        or directory_flag is None
        or close_on_exec is None
        or os.open not in os.supports_dir_fd
    ):
        raise ReviewError("descriptor-relative no-follow reads are unavailable")
    flags = os.O_RDONLY | no_follow | non_block | close_on_exec
    if directory:
        flags |= directory_flag
    return flags


def _open_root_directory(
    root: Path, *, label: str
) -> tuple[Path, int, RootedPathIdentity]:
    """Open one root directory without following its final component."""

    try:
        absolute = absolute_path_without_final_resolution(os.fspath(root))
    except (OSError, RuntimeError, ValueError) as error:
        raise ReviewError(f"{label} root path is missing or unsafe") from error
    try:
        descriptor = os.open(absolute, _rooted_descriptor_flags(directory=True))
    except OSError as error:
        raise ReviewError(f"{label} root is missing or unsafe: {absolute}") from error
    try:
        identity = rooted_path_identity(os.fstat(descriptor))
        if not stat.S_ISDIR(identity.mode):
            raise ReviewError(f"{label} root is not a directory: {absolute}")
    except BaseException:
        _close_file_descriptors([descriptor], context=f"{label} root")
        raise
    return absolute, descriptor, identity


def _require_exact_rooted_entry_name(
    descriptor: int,
    name: str,
    *,
    label: str,
    max_directory_entries: int,
) -> None:
    """Require the exact stored spelling of one opened path component."""

    count = 0
    with os.scandir(descriptor) as iterator:
        for entry in iterator:
            count += 1
            if count > max_directory_entries:
                raise ReviewError(f"{label} directory exceeds the entry-count limit")
            if entry.name == name:
                return
    raise ReviewError(f"{label} path does not use the stored canonical spelling")


def _digest_from_root_descriptor(
    root_descriptor: int,
    parts: tuple[str, ...],
    *,
    label: str,
    max_bytes: int,
    expected_size: int | None,
    expected_file: RootedPathIdentity | None = None,
    expected_directories: Mapping[str, RootedPathIdentity] | None = None,
    max_directory_entries: int = 32_768,
    require_exact_names: bool = True,
    capture_bytes: bool = False,
    observation_validator: Callable[[_RootedFileObservation], None] | None = None,
) -> _RootedFileObservation:
    """Hash one file while each path component remains open and unchanged."""

    if (
        type(max_bytes) is not int
        or max_bytes < 0
        or (
            expected_size is not None
            and (
                type(expected_size) is not int
                or expected_size < 0
                or expected_size > max_bytes
            )
        )
        or type(max_directory_entries) is not int
        or max_directory_entries < 1
        or type(require_exact_names) is not bool
        or type(capture_bytes) is not bool
        or (observation_validator is not None and not callable(observation_validator))
    ):
        raise ReviewError(f"{label} read limits are invalid")

    owned_directories: list[tuple[int, RootedPathIdentity]] = []
    observed_directories: dict[str, RootedPathIdentity] = {}
    file_descriptor = -1
    try:
        current = os.dup(root_descriptor)
        try:
            current_identity = rooted_path_identity(os.fstat(current))
            expected_root = (
                expected_directories.get("")
                if expected_directories is not None
                else None
            )
            if expected_root is not None and current_identity != expected_root:
                raise ReviewError(f"{label} root changed before it was read")
        except BaseException:
            _close_file_descriptors([current], context=f"{label} path")
            raise
        owned_directories.append((current, current_identity))
        observed_directories[""] = current_identity
        traversed: list[str] = []
        for part in parts[:-1]:
            traversed.append(part)
            relative = "/".join(traversed)
            if require_exact_names:
                _require_exact_rooted_entry_name(
                    current,
                    part,
                    label=label,
                    max_directory_entries=max_directory_entries,
                )
            next_descriptor = os.open(
                part,
                _rooted_descriptor_flags(directory=True),
                dir_fd=current,
            )
            try:
                identity = rooted_path_identity(os.fstat(next_descriptor))
                if not stat.S_ISDIR(identity.mode):
                    raise ReviewError(f"{label} directory is not regular: {relative}")
                expected_directory = (
                    expected_directories.get(relative)
                    if expected_directories is not None
                    else None
                )
                if expected_directory is not None and expected_directory != identity:
                    raise ReviewError(f"{label} directory changed: {relative}")
            except BaseException:
                _close_file_descriptors(
                    [next_descriptor],
                    context=f"{label} path",
                )
                raise
            owned_directories.append((next_descriptor, identity))
            observed_directories[relative] = identity
            current = next_descriptor

        if require_exact_names:
            _require_exact_rooted_entry_name(
                current,
                parts[-1],
                label=label,
                max_directory_entries=max_directory_entries,
            )
        file_descriptor = os.open(
            parts[-1],
            _rooted_descriptor_flags(directory=False),
            dir_fd=current,
        )
        before = rooted_path_identity(os.fstat(file_descriptor))
        if not stat.S_ISREG(before.mode) or before.links != 1:
            raise ReviewError(f"{label} is not one singly linked regular file")
        if expected_file is not None and before != expected_file:
            raise ReviewError(f"{label} changed before it was read")
        if before.size > max_bytes or (
            expected_size is not None and before.size != expected_size
        ):
            raise ReviewError(f"{label} size is outside its declared bound")

        digest = hashlib.sha256()
        captured = bytearray() if capture_bytes else None
        total = 0
        read_limit = before.size + 1
        while total < read_limit:
            block = os.read(
                file_descriptor,
                min(1024 * 1024, read_limit - total),
            )
            if not block:
                break
            total += len(block)
            if total > before.size or total > max_bytes:
                raise ReviewError(f"{label} grew while it was read")
            digest.update(block)
            if captured is not None:
                captured.extend(block)
        after = rooted_path_identity(os.fstat(file_descriptor))
        if total != before.size or after != before:
            raise ReviewError(f"{label} changed while it was read")
        for descriptor, expected in owned_directories:
            if rooted_path_identity(os.fstat(descriptor)) != expected:
                raise ReviewError(f"{label} path changed while it was read")
        observation = _RootedFileObservation(
            digest=RootedFileDigest(
                digest.hexdigest(),
                total,
                before.device,
                before.inode,
            ),
            data=bytes(captured) if captured is not None else None,
            file_identity=before,
            directory_identities=observed_directories,
        )
        if observation_validator is not None:
            observation_validator(observation)
        return observation
    except OSError as error:
        raise ReviewError(f"{label} is missing or unsafe: {error}") from error
    finally:
        _close_file_descriptors(
            [
                file_descriptor,
                *(descriptor for descriptor, _identity in reversed(owned_directories)),
            ],
            context=label,
        )


def _verify_rooted_file_identity(
    root_descriptor: int,
    parts: tuple[str, ...],
    *,
    label: str,
    expected_file: RootedPathIdentity,
    expected_directories: Mapping[str, RootedPathIdentity],
    max_directory_entries: int,
) -> None:
    """Verify one touched file path without reading its bytes again."""

    owned_directories: list[tuple[int, RootedPathIdentity]] = []
    file_descriptor = -1
    try:
        current = os.dup(root_descriptor)
        try:
            current_identity = rooted_path_identity(os.fstat(current))
            if expected_directories.get("") != current_identity:
                raise ReviewError(f"{label} root changed during the transaction")
        except BaseException:
            _close_file_descriptors([current], context=f"{label} path")
            raise
        owned_directories.append((current, current_identity))
        traversed: list[str] = []
        for part in parts[:-1]:
            traversed.append(part)
            relative = "/".join(traversed)
            _require_exact_rooted_entry_name(
                current,
                part,
                label=label,
                max_directory_entries=max_directory_entries,
            )
            next_descriptor = os.open(
                part,
                _rooted_descriptor_flags(directory=True),
                dir_fd=current,
            )
            try:
                identity = rooted_path_identity(os.fstat(next_descriptor))
                if (
                    not stat.S_ISDIR(identity.mode)
                    or expected_directories.get(relative) != identity
                ):
                    raise ReviewError(
                        f"{label} directory changed during the transaction: {relative}"
                    )
            except BaseException:
                _close_file_descriptors(
                    [next_descriptor],
                    context=f"{label} path",
                )
                raise
            owned_directories.append((next_descriptor, identity))
            current = next_descriptor

        _require_exact_rooted_entry_name(
            current,
            parts[-1],
            label=label,
            max_directory_entries=max_directory_entries,
        )
        file_descriptor = os.open(
            parts[-1],
            _rooted_descriptor_flags(directory=False),
            dir_fd=current,
        )
        current_file = rooted_path_identity(os.fstat(file_descriptor))
        if (
            not stat.S_ISREG(current_file.mode)
            or current_file.links != 1
            or current_file != expected_file
        ):
            raise ReviewError(f"{label} changed during the transaction")
        if rooted_path_identity(os.fstat(file_descriptor)) != expected_file:
            raise ReviewError(f"{label} changed during the transaction")
        for descriptor, expected in owned_directories:
            if rooted_path_identity(os.fstat(descriptor)) != expected:
                raise ReviewError(f"{label} path changed during the transaction")
    except OSError as error:
        raise ReviewError(f"{label} changed or became unsafe") from error
    finally:
        _close_file_descriptors(
            [
                file_descriptor,
                *(descriptor for descriptor, _identity in reversed(owned_directories)),
            ],
            context=label,
        )


def digest_rooted_regular_files(
    root: Path,
    requests: Sequence[RootedFileDigestRequest],
    *,
    label: str,
    max_files: int,
    max_file_bytes: int,
    max_aggregate_bytes: int,
    max_path_bytes: int = 4 * 1024,
    max_component_bytes: int = 255,
    max_depth: int = 128,
    max_directory_entries: int = 32_768,
) -> tuple[RootedFileDigest, ...]:
    """Hash one bounded file set in a held-root transaction."""

    limits = (
        max_files,
        max_file_bytes,
        max_aggregate_bytes,
        max_path_bytes,
        max_component_bytes,
        max_depth,
        max_directory_entries,
    )
    if (
        type(label) is not str
        or not label
        or any(type(value) is not int or value < 1 for value in limits)
        or isinstance(requests, (str, bytes, bytearray))
    ):
        raise ReviewError("rooted file transaction limits are invalid")
    try:
        request_count = len(requests)
    except TypeError as error:
        raise ReviewError("rooted file transaction requests are invalid") from error
    if request_count < 1:
        raise ReviewError(f"{label} file transaction must not be empty")
    if request_count > max_files:
        raise ReviewError(f"{label} exceeds the {max_files}-file limit")

    validated: list[tuple[RootedFileDigestRequest, tuple[str, ...]]] = []
    seen_paths: set[str] = set()
    declared_bytes = 0
    for index, request in enumerate(requests):
        if not isinstance(request, RootedFileDigestRequest):
            raise ReviewError(f"{label} request {index} is invalid")
        if type(request.label) is not str or not request.label:
            raise ReviewError(f"{label} request {index} has an invalid label")
        expected_sha256 = request.expected_sha256
        if expected_sha256 is not None and (
            type(expected_sha256) is not str
            or len(expected_sha256) != 64
            or any(character not in "0123456789abcdef" for character in expected_sha256)
        ):
            raise ReviewError(f"{request.label} expected digest is invalid")
        expected_size = request.expected_size
        if expected_size is not None and (
            type(expected_size) is not int
            or expected_size < 0
            or expected_size > max_file_bytes
        ):
            raise ReviewError(f"{request.label} expected size is invalid")
        parts = canonical_relative_parts(
            request.relative,
            label=f"{request.label} path",
            max_path_bytes=max_path_bytes,
            max_component_bytes=max_component_bytes,
            max_depth=max_depth,
        )
        if request.relative in seen_paths:
            raise ReviewError(f"{label} contains a duplicate path: {request.relative}")
        seen_paths.add(request.relative)
        if expected_size is not None:
            declared_bytes += expected_size
            if declared_bytes > max_aggregate_bytes:
                raise ReviewError(f"{label} exceeds the aggregate byte limit")
        validated.append((request, parts))

    absolute, root_descriptor, root_identity = _open_root_directory(
        root,
        label=label,
    )
    replacement_descriptor = -1
    touched_directories = {"": root_identity}
    touched_files: dict[str, RootedPathIdentity] = {}
    file_identities: set[tuple[int, int]] = set()
    digests: list[RootedFileDigest] = []
    actual_bytes = 0
    try:
        for request, parts in validated:

            def retain_observation(
                observation: _RootedFileObservation,
                *,
                current_request: RootedFileDigestRequest = request,
            ) -> None:
                nonlocal actual_bytes
                for relative, identity in observation.directory_identities.items():
                    previous = touched_directories.get(relative)
                    if previous is not None and previous != identity:
                        raise ReviewError(
                            f"{current_request.label} directory changed during "
                            f"the transaction: {relative or '.'}"
                        )
                    touched_directories[relative] = identity
                identity_key = (
                    observation.file_identity.device,
                    observation.file_identity.inode,
                )
                if identity_key in file_identities:
                    raise ReviewError(
                        f"{label} path resolves to a duplicate file identity: "
                        f"{current_request.relative}"
                    )
                file_identities.add(identity_key)
                touched_files[current_request.relative] = observation.file_identity
                actual_bytes += observation.digest.size_bytes
                if actual_bytes > max_aggregate_bytes:
                    raise ReviewError(f"{label} exceeds the aggregate byte limit")
                if (
                    current_request.expected_sha256 is not None
                    and observation.digest.sha256 != current_request.expected_sha256
                ):
                    raise ReviewError(
                        f"digest {current_request.relative} "
                        f"expected={current_request.expected_sha256} "
                        f"actual={observation.digest.sha256}"
                    )

            observation = _digest_from_root_descriptor(
                root_descriptor,
                parts,
                label=request.label,
                max_bytes=max_file_bytes,
                expected_size=request.expected_size,
                expected_directories=touched_directories,
                max_directory_entries=max_directory_entries,
                observation_validator=retain_observation,
            )
            digests.append(observation.digest)

        for request, parts in validated:
            _verify_rooted_file_identity(
                root_descriptor,
                parts,
                label=request.label,
                expected_file=touched_files[request.relative],
                expected_directories=touched_directories,
                max_directory_entries=max_directory_entries,
            )
        if rooted_path_identity(os.fstat(root_descriptor)) != root_identity:
            raise ReviewError(f"{label} root changed during the transaction")
        try:
            replacement_descriptor = os.open(
                absolute,
                _rooted_descriptor_flags(directory=True),
            )
        except OSError as error:
            raise ReviewError(
                f"{label} lexical root changed or became unsafe"
            ) from error
        if rooted_path_identity(os.fstat(replacement_descriptor)) != root_identity:
            raise ReviewError(
                f"{label} lexical root was replaced during the transaction"
            )
        return tuple(digests)
    except OSError as error:
        raise ReviewError(f"{label} changed or became unsafe") from error
    finally:
        _close_file_descriptors(
            [replacement_descriptor, root_descriptor],
            context=label,
        )


def _require_git_regular_mode(
    mode: int,
    expected_git_mode: str | None,
    *,
    label: str,
) -> None:
    """Require the declared Git regular-file executable semantics."""

    if expected_git_mode is None:
        return
    if expected_git_mode not in {"100644", "100755"}:
        raise ReviewError(f"{label} expected Git mode is invalid")
    executable = bool(mode & stat.S_IXUSR)
    if executable != (expected_git_mode == "100755"):
        raise ReviewError(f"{label} executable mode differs from the Git index")


def read_rooted_regular_files(
    root: Path,
    requests: Sequence[RootedFileCaptureRequest],
    *,
    label: str,
    max_files: int,
    max_file_bytes: int,
    max_aggregate_bytes: int,
    max_path_bytes: int = 4 * 1024,
    max_component_bytes: int = 255,
    max_depth: int = 128,
    max_directory_entries: int = 32_768,
) -> tuple[RootedFileBatchCapture, ...]:
    """Capture one bounded file set in a held-root transaction."""

    limits = (
        max_files,
        max_file_bytes,
        max_aggregate_bytes,
        max_path_bytes,
        max_component_bytes,
        max_depth,
        max_directory_entries,
    )
    if (
        type(label) is not str
        or not label
        or any(type(value) is not int or value < 1 for value in limits)
        or isinstance(requests, (str, bytes, bytearray))
    ):
        raise ReviewError("rooted byte-capture transaction limits are invalid")
    try:
        request_count = len(requests)
    except TypeError as error:
        raise ReviewError("rooted byte-capture requests are invalid") from error
    if request_count < 1:
        raise ReviewError(f"{label} file transaction must not be empty")
    if request_count > max_files:
        raise ReviewError(f"{label} exceeds the {max_files}-file limit")

    validated: list[tuple[RootedFileCaptureRequest, tuple[str, ...]]] = []
    seen_paths: set[str] = set()
    declared_bytes = 0
    for index, request in enumerate(requests):
        if not isinstance(request, RootedFileCaptureRequest):
            raise ReviewError(f"{label} request {index} is invalid")
        if type(request.label) is not str or not request.label:
            raise ReviewError(f"{label} request {index} has an invalid label")
        expected_sha256 = request.expected_sha256
        if expected_sha256 is not None and (
            type(expected_sha256) is not str
            or len(expected_sha256) != 64
            or any(character not in "0123456789abcdef" for character in expected_sha256)
        ):
            raise ReviewError(f"{request.label} expected digest is invalid")
        expected_size = request.expected_size
        if expected_size is not None and (
            type(expected_size) is not int
            or expected_size < 0
            or expected_size > max_file_bytes
        ):
            raise ReviewError(f"{request.label} expected size is invalid")
        if request.expected_git_mode not in {None, "100644", "100755"}:
            raise ReviewError(f"{request.label} expected Git mode is invalid")
        parts = canonical_relative_parts(
            request.relative,
            label=f"{request.label} path",
            max_path_bytes=max_path_bytes,
            max_component_bytes=max_component_bytes,
            max_depth=max_depth,
        )
        if request.relative in seen_paths:
            raise ReviewError(f"{label} contains a duplicate path: {request.relative}")
        seen_paths.add(request.relative)
        if expected_size is not None:
            declared_bytes += expected_size
            if declared_bytes > max_aggregate_bytes:
                raise ReviewError(f"{label} exceeds the aggregate byte limit")
        validated.append((request, parts))

    absolute, root_descriptor, root_identity = _open_root_directory(root, label=label)
    replacement_descriptor = -1
    touched_directories = {"": root_identity}
    touched_files: dict[str, RootedPathIdentity] = {}
    file_identities: set[tuple[int, int]] = set()
    captures: list[RootedFileBatchCapture] = []
    actual_bytes = 0
    try:
        for request, parts in validated:

            def retain_observation(
                observation: _RootedFileObservation,
                *,
                current_request: RootedFileCaptureRequest = request,
            ) -> None:
                nonlocal actual_bytes
                for relative, identity in observation.directory_identities.items():
                    previous = touched_directories.get(relative)
                    if previous is not None and previous != identity:
                        raise ReviewError(
                            f"{current_request.label} directory changed during "
                            f"the transaction: {relative or '.'}"
                        )
                    touched_directories[relative] = identity
                identity_key = (
                    observation.file_identity.device,
                    observation.file_identity.inode,
                )
                if identity_key in file_identities:
                    raise ReviewError(
                        f"{label} path resolves to a duplicate file identity: "
                        f"{current_request.relative}"
                    )
                file_identities.add(identity_key)
                touched_files[current_request.relative] = observation.file_identity
                _require_git_regular_mode(
                    observation.file_identity.mode,
                    current_request.expected_git_mode,
                    label=current_request.label,
                )
                actual_bytes += observation.digest.size_bytes
                if actual_bytes > max_aggregate_bytes:
                    raise ReviewError(f"{label} exceeds the aggregate byte limit")
                if (
                    current_request.expected_sha256 is not None
                    and observation.digest.sha256 != current_request.expected_sha256
                ):
                    raise ReviewError(
                        f"digest {current_request.relative} "
                        f"expected={current_request.expected_sha256} "
                        f"actual={observation.digest.sha256}"
                    )

            observation = _digest_from_root_descriptor(
                root_descriptor,
                parts,
                label=request.label,
                max_bytes=max_file_bytes,
                expected_size=request.expected_size,
                expected_directories=touched_directories,
                max_directory_entries=max_directory_entries,
                capture_bytes=True,
                observation_validator=retain_observation,
            )
            if observation.data is None:
                raise ReviewError(f"{request.label} did not produce a byte capture")
            captures.append(
                RootedFileBatchCapture(
                    relative=request.relative,
                    data=observation.data,
                    sha256=observation.digest.sha256,
                    size_bytes=observation.digest.size_bytes,
                    file_identity=observation.file_identity,
                    directory_identities=tuple(
                        sorted(observation.directory_identities.items())
                    ),
                )
            )

        for request, parts in validated:
            _verify_rooted_file_identity(
                root_descriptor,
                parts,
                label=request.label,
                expected_file=touched_files[request.relative],
                expected_directories=touched_directories,
                max_directory_entries=max_directory_entries,
            )
        if rooted_path_identity(os.fstat(root_descriptor)) != root_identity:
            raise ReviewError(f"{label} root changed during the transaction")
        try:
            replacement_descriptor = os.open(
                absolute,
                _rooted_descriptor_flags(directory=True),
            )
        except OSError as error:
            raise ReviewError(
                f"{label} lexical root changed or became unsafe"
            ) from error
        if rooted_path_identity(os.fstat(replacement_descriptor)) != root_identity:
            raise ReviewError(
                f"{label} lexical root was replaced during the transaction"
            )
        return tuple(captures)
    except OSError as error:
        raise ReviewError(f"{label} changed or became unsafe") from error
    finally:
        _close_file_descriptors(
            [replacement_descriptor, root_descriptor],
            context=label,
        )


def write_rooted_regular_file(
    root: Path,
    relative: str,
    data: bytes,
    *,
    expected: RootedFileBatchCapture,
    expected_git_mode: str,
    label: str,
    max_bytes: int,
    max_path_bytes: int = 4 * 1024,
    max_component_bytes: int = 255,
    max_depth: int = 128,
    max_directory_entries: int = 32_768,
) -> RootedFileBatchCapture:
    """Update one captured regular file without following a replaced path."""

    if (
        not isinstance(data, bytes)
        or type(max_bytes) is not int
        or max_bytes < 1
        or type(max_path_bytes) is not int
        or max_path_bytes < 1
        or type(max_component_bytes) is not int
        or max_component_bytes < 1
        or type(max_depth) is not int
        or max_depth < 1
        or type(max_directory_entries) is not int
        or max_directory_entries < 1
        or not isinstance(expected, RootedFileBatchCapture)
        or expected.relative != relative
        or expected_git_mode not in {"100644", "100755"}
        or type(label) is not str
        or not label
    ):
        raise ReviewError("rooted file write request is invalid")
    if len(data) > max_bytes:
        raise ReviewError(f"{label} output exceeds its byte limit")
    parts = canonical_relative_parts(
        relative,
        label=f"{label} path",
        max_path_bytes=max_path_bytes,
        max_component_bytes=max_component_bytes,
        max_depth=max_depth,
    )
    expected_directories = dict(expected.directory_identities)
    expected_directory_paths = {""}
    for index in range(1, len(parts)):
        expected_directory_paths.add("/".join(parts[:index]))
    if (
        len(expected_directories) != len(expected.directory_identities)
        or set(expected_directories) != expected_directory_paths
        or any(
            not isinstance(identity, RootedPathIdentity)
            or not stat.S_ISDIR(identity.mode)
            for identity in expected_directories.values()
        )
        or not isinstance(expected.file_identity, RootedPathIdentity)
        or not stat.S_ISREG(expected.file_identity.mode)
        or expected.file_identity.links != 1
        or expected.file_identity.size != expected.size_bytes
        or expected.size_bytes != len(expected.data)
        or expected.sha256 != hashlib.sha256(expected.data).hexdigest()
    ):
        raise ReviewError(f"{label} capture is invalid")
    _require_git_regular_mode(
        expected.file_identity.mode,
        expected_git_mode,
        label=label,
    )

    absolute, root_descriptor, root_identity = _open_root_directory(root, label=label)
    if root_identity != expected_directories[""]:
        _close_file_descriptors([root_descriptor], context=label)
        raise ReviewError(f"{label} root changed before it was written")
    replacement_descriptor = -1
    file_descriptor = -1
    check_descriptor = -1
    owned_directories: list[tuple[int, RootedPathIdentity]] = []
    final_identity = expected.file_identity
    try:
        current = os.dup(root_descriptor)
        try:
            current_identity = rooted_path_identity(os.fstat(current))
        except BaseException:
            _close_file_descriptors([current], context=f"{label} path")
            raise
        owned_directories.append((current, current_identity))
        traversed: list[str] = []
        for part in parts[:-1]:
            traversed.append(part)
            directory = "/".join(traversed)
            _require_exact_rooted_entry_name(
                current,
                part,
                label=label,
                max_directory_entries=max_directory_entries,
            )
            next_descriptor = os.open(
                part,
                _rooted_descriptor_flags(directory=True),
                dir_fd=current,
            )
            try:
                identity = rooted_path_identity(os.fstat(next_descriptor))
                if (
                    not stat.S_ISDIR(identity.mode)
                    or expected_directories.get(directory) != identity
                ):
                    raise ReviewError(
                        f"{label} directory changed before it was written: {directory}"
                    )
            except BaseException:
                _close_file_descriptors([next_descriptor], context=f"{label} path")
                raise
            owned_directories.append((next_descriptor, identity))
            current = next_descriptor

        _require_exact_rooted_entry_name(
            current,
            parts[-1],
            label=label,
            max_directory_entries=max_directory_entries,
        )
        write_flags = (
            os.O_RDWR
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        if (
            getattr(os, "O_NOFOLLOW", None) is None
            or getattr(os, "O_NONBLOCK", None) is None
            or getattr(os, "O_CLOEXEC", None) is None
        ):
            raise ReviewError("descriptor-relative no-follow writes are unavailable")
        file_descriptor = os.open(parts[-1], write_flags, dir_fd=current)
        before = rooted_path_identity(os.fstat(file_descriptor))
        if (
            not stat.S_ISREG(before.mode)
            or before.links != 1
            or before != expected.file_identity
        ):
            raise ReviewError(f"{label} changed before it was written")
        _require_git_regular_mode(before.mode, expected_git_mode, label=label)

        current_data = bytearray()
        while len(current_data) <= expected.size_bytes:
            block = os.read(
                file_descriptor,
                min(1024 * 1024, expected.size_bytes - len(current_data) + 1),
            )
            if not block:
                break
            current_data.extend(block)
        if bytes(current_data) != expected.data:
            raise ReviewError(f"{label} bytes changed before it was written")

        check_descriptor = os.open(
            parts[-1],
            _rooted_descriptor_flags(directory=False),
            dir_fd=current,
        )
        if rooted_path_identity(os.fstat(check_descriptor)) != before:
            raise ReviewError(f"{label} path changed before it was written")
        _close_file_descriptors([check_descriptor], context=label)
        check_descriptor = -1
        for descriptor, identity in owned_directories:
            if rooted_path_identity(os.fstat(descriptor)) != identity:
                raise ReviewError(f"{label} path changed before it was written")

        if expected.data != data:
            os.lseek(file_descriptor, 0, os.SEEK_SET)
            os.ftruncate(file_descriptor, 0)
            offset = 0
            while offset < len(data):
                written = os.write(file_descriptor, data[offset:])
                if written < 1:
                    raise ReviewError(f"{label} write made no progress")
                offset += written
            os.fsync(file_descriptor)
            final_identity = rooted_path_identity(os.fstat(file_descriptor))
            if (
                not stat.S_ISREG(final_identity.mode)
                or final_identity.links != 1
                or final_identity.device != before.device
                or final_identity.inode != before.inode
                or final_identity.size != len(data)
            ):
                raise ReviewError(f"{label} changed while it was written")
            _require_git_regular_mode(
                final_identity.mode,
                expected_git_mode,
                label=label,
            )
            os.lseek(file_descriptor, 0, os.SEEK_SET)
            read_back = bytearray()
            while len(read_back) <= len(data):
                block = os.read(
                    file_descriptor,
                    min(1024 * 1024, len(data) - len(read_back) + 1),
                )
                if not block:
                    break
                read_back.extend(block)
            if bytes(read_back) != data:
                raise ReviewError(f"{label} write verification failed")

        check_descriptor = os.open(
            parts[-1],
            _rooted_descriptor_flags(directory=False),
            dir_fd=current,
        )
        if rooted_path_identity(os.fstat(check_descriptor)) != final_identity:
            raise ReviewError(f"{label} path changed after it was written")
        for descriptor, identity in owned_directories:
            if rooted_path_identity(os.fstat(descriptor)) != identity:
                raise ReviewError(f"{label} path changed after it was written")
        if rooted_path_identity(os.fstat(root_descriptor)) != root_identity:
            raise ReviewError(f"{label} root changed after it was written")

        replacement_descriptor = os.open(
            absolute,
            _rooted_descriptor_flags(directory=True),
        )
        if rooted_path_identity(os.fstat(replacement_descriptor)) != root_identity:
            raise ReviewError(f"{label} lexical root was replaced during the write")
        verification = _digest_from_root_descriptor(
            replacement_descriptor,
            parts,
            label=label,
            max_bytes=max_bytes,
            expected_size=len(data),
            expected_file=final_identity,
            expected_directories=expected_directories,
            max_directory_entries=max_directory_entries,
            capture_bytes=True,
        )
        if verification.data != data:
            raise ReviewError(f"{label} lexical write verification failed")
        return RootedFileBatchCapture(
            relative=relative,
            data=data,
            sha256=verification.digest.sha256,
            size_bytes=verification.digest.size_bytes,
            file_identity=final_identity,
            directory_identities=tuple(sorted(expected_directories.items())),
        )
    except OSError as error:
        raise ReviewError(f"{label} changed or became unsafe") from error
    finally:
        _close_file_descriptors(
            [
                check_descriptor,
                file_descriptor,
                *(descriptor for descriptor, _identity in reversed(owned_directories)),
                replacement_descriptor,
                root_descriptor,
            ],
            context=label,
        )


def _read_rooted_regular_file(
    root: Path,
    relative: str,
    *,
    max_bytes: int,
    expected_size: int | None = None,
    label: str,
    max_path_bytes: int = 4 * 1024,
    max_component_bytes: int = 255,
    max_depth: int = 128,
    max_directory_entries: int = 32_768,
    capture_bytes: bool,
) -> tuple[RootedFileDigest, bytes | None]:
    """Read one canonical path through held, no-follow descriptors."""

    parts = canonical_relative_parts(
        relative,
        label=f"{label} path",
        max_path_bytes=max_path_bytes,
        max_component_bytes=max_component_bytes,
        max_depth=max_depth,
    )
    absolute, root_descriptor, root_identity = _open_root_directory(root, label=label)
    replacement_descriptor = -1
    try:
        observation = _digest_from_root_descriptor(
            root_descriptor,
            parts,
            label=label,
            max_bytes=max_bytes,
            expected_size=expected_size,
            max_directory_entries=max_directory_entries,
            capture_bytes=capture_bytes,
        )
        if rooted_path_identity(os.fstat(root_descriptor)) != root_identity:
            raise ReviewError(f"{label} root changed while it was read")
        try:
            replacement_descriptor = os.open(
                absolute, _rooted_descriptor_flags(directory=True)
            )
        except OSError as error:
            raise ReviewError(f"{label} root changed or became unsafe") from error
        if rooted_path_identity(os.fstat(replacement_descriptor)) != root_identity:
            raise ReviewError(f"{label} root was replaced while it was read")
        return observation.digest, observation.data
    except OSError as error:
        raise ReviewError(f"{label} changed or became unsafe") from error
    finally:
        _close_file_descriptors(
            [replacement_descriptor, root_descriptor],
            context=label,
        )


def digest_rooted_regular_file(
    root: Path,
    relative: str,
    *,
    max_bytes: int,
    expected_size: int | None = None,
    label: str,
    max_path_bytes: int = 4 * 1024,
    max_component_bytes: int = 255,
    max_depth: int = 128,
    max_directory_entries: int = 32_768,
) -> RootedFileDigest:
    """Hash one canonical path through held, no-follow descriptors."""

    result, _data = _read_rooted_regular_file(
        root,
        relative,
        max_bytes=max_bytes,
        expected_size=expected_size,
        label=label,
        max_path_bytes=max_path_bytes,
        max_component_bytes=max_component_bytes,
        max_depth=max_depth,
        max_directory_entries=max_directory_entries,
        capture_bytes=False,
    )
    return result


def read_rooted_regular_file(
    root: Path,
    relative: str,
    *,
    max_bytes: int,
    expected_size: int | None = None,
    label: str,
    max_path_bytes: int = 4 * 1024,
    max_component_bytes: int = 255,
    max_depth: int = 128,
    max_directory_entries: int = 32_768,
) -> RootedFileCapture:
    """Capture one canonical path through held, no-follow descriptors."""

    result, data = _read_rooted_regular_file(
        root,
        relative,
        max_bytes=max_bytes,
        expected_size=expected_size,
        label=label,
        max_path_bytes=max_path_bytes,
        max_component_bytes=max_component_bytes,
        max_depth=max_depth,
        max_directory_entries=max_directory_entries,
        capture_bytes=True,
    )
    if data is None:
        raise ReviewError(f"{label} did not produce a byte capture")
    return RootedFileCapture(
        data,
        result.sha256,
        result.size_bytes,
        result.device,
        result.inode,
    )


def digest_rooted_tree(
    root: Path,
    *,
    label: str,
    max_entries: int,
    max_depth: int,
    max_path_bytes: int,
    max_component_bytes: int,
    max_file_bytes: int,
    max_aggregate_bytes: int,
    reject_empty_directories: bool = True,
) -> dict[str, RootedFileDigest]:
    """Inventory and hash one complete, unchanged, no-follow directory tree."""

    limits = (
        max_entries,
        max_depth,
        max_path_bytes,
        max_component_bytes,
        max_file_bytes,
        max_aggregate_bytes,
    )
    if (
        any(type(value) is not int or value < 1 for value in limits)
        or type(reject_empty_directories) is not bool
    ):
        raise ReviewError(f"{label} tree limits are invalid")
    absolute, root_descriptor, root_identity = _open_root_directory(root, label=label)
    replacement_descriptor = -1

    def inventory() -> tuple[
        dict[str, RootedPathIdentity],
        dict[str, RootedPathIdentity],
    ]:
        directories = {"": rooted_path_identity(os.fstat(root_descriptor))}
        files: dict[str, RootedPathIdentity] = {}
        entry_count = 0
        aggregate_size = 0

        def visit(
            descriptor: int,
            prefix: tuple[str, ...],
            expected_directory: RootedPathIdentity,
        ) -> None:
            nonlocal entry_count, aggregate_size
            try:
                with os.scandir(descriptor) as iterator:
                    entries = []
                    for entry in iterator:
                        entry_count += 1
                        if entry_count > max_entries:
                            raise ReviewError(
                                f"{label} exceeds the {max_entries}-entry limit"
                            )
                        relative = "/".join((*prefix, entry.name))
                        parts = canonical_relative_parts(
                            relative,
                            label=f"{label} path",
                            max_path_bytes=max_path_bytes,
                            max_component_bytes=max_component_bytes,
                            max_depth=max_depth,
                        )
                        metadata = entry.stat(follow_symlinks=False)
                        entries.append(
                            (
                                relative,
                                entry.name,
                                parts,
                                rooted_path_identity(metadata),
                            )
                        )
            except OSError as error:
                raise ReviewError(f"cannot completely inventory {label}") from error

            if prefix and reject_empty_directories and not entries:
                raise ReviewError(
                    f"{label} contains an empty directory: {'/'.join(prefix)}"
                )
            for relative, name, parts, identity in sorted(entries):
                if stat.S_ISREG(identity.mode):
                    if identity.links != 1:
                        raise ReviewError(
                            f"{label} contains a multiply linked file: {relative}"
                        )
                    if identity.size > max_file_bytes:
                        raise ReviewError(
                            f"{label} file exceeds {max_file_bytes} bytes: {relative}"
                        )
                    aggregate_size += identity.size
                    if aggregate_size > max_aggregate_bytes:
                        raise ReviewError(f"{label} exceeds the aggregate byte limit")
                    files[relative] = identity
                    continue
                if stat.S_ISDIR(identity.mode):
                    if len(parts) > max_depth:
                        raise ReviewError(f"{label} exceeds the directory-depth limit")
                    try:
                        child = os.open(
                            name,
                            _rooted_descriptor_flags(directory=True),
                            dir_fd=descriptor,
                        )
                    except OSError as error:
                        raise ReviewError(
                            f"{label} directory changed or became unsafe: {relative}"
                        ) from error
                    try:
                        if rooted_path_identity(os.fstat(child)) != identity:
                            raise ReviewError(f"{label} directory changed: {relative}")
                        directories[relative] = identity
                        visit(child, parts, identity)
                    finally:
                        _close_file_descriptors(
                            [child],
                            context=f"{label} directory {relative}",
                        )
                    continue
                kind = "symlink" if stat.S_ISLNK(identity.mode) else "special file"
                raise ReviewError(f"{label} contains a {kind}: {relative}")
            if rooted_path_identity(os.fstat(descriptor)) != expected_directory:
                relative = "/".join(prefix) or "."
                raise ReviewError(f"{label} directory changed: {relative}")

        visit(root_descriptor, (), directories[""])
        return directories, files

    try:
        directories_before, files_before = inventory()
        digests: dict[str, RootedFileDigest] = {}
        for relative, identity in sorted(files_before.items()):
            parts = canonical_relative_parts(
                relative,
                label=f"{label} path",
                max_path_bytes=max_path_bytes,
                max_component_bytes=max_component_bytes,
                max_depth=max_depth,
            )
            digests[relative] = _digest_from_root_descriptor(
                root_descriptor,
                parts,
                label=f"{label} file {relative}",
                max_bytes=max_file_bytes,
                expected_size=identity.size,
                expected_file=identity,
                expected_directories=directories_before,
                max_directory_entries=max_entries,
                require_exact_names=False,
            ).digest
        directories_after, files_after = inventory()
        if (
            directories_after != directories_before
            or files_after != files_before
            or rooted_path_identity(os.fstat(root_descriptor)) != root_identity
        ):
            raise ReviewError(f"{label} changed while it was verified")
        try:
            replacement_descriptor = os.open(
                absolute, _rooted_descriptor_flags(directory=True)
            )
        except OSError as error:
            raise ReviewError(f"{label} root changed or became unsafe") from error
        if rooted_path_identity(os.fstat(replacement_descriptor)) != root_identity:
            raise ReviewError(f"{label} root was replaced while it was verified")
        return digests
    except OSError as error:
        raise ReviewError(f"{label} changed or became unsafe") from error
    finally:
        _close_file_descriptors(
            [replacement_descriptor, root_descriptor],
            context=label,
        )
