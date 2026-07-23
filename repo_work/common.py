"""Shared, dependency-free helpers for release review utilities."""

from __future__ import annotations

import json
import math
import os
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Literal, Mapping, NamedTuple, Sequence, overload


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
    }
)


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
        os.close(descriptor)


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


class BoundedHostResult(NamedTuple):
    """One bounded host-command result."""

    returncode: int
    stdout: bytes
    stderr: bytes


def _stop_bounded_host_process(process: subprocess.Popen[bytes], context: str) -> None:
    """Stop one isolated host-command process group within a fixed interval."""

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        try:
            process.wait(timeout=HOST_COMMAND_STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        try:
            process.wait(timeout=HOST_COMMAND_STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as error:
            raise ReviewError(
                f"{context} did not terminate within its stop bound"
            ) from error


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
) -> BoundedHostResult:
    """Run one host command with fixed time and stream-memory bounds."""

    if (
        isinstance(arguments, (str, bytes))
        or not arguments
        or any(
            not isinstance(argument, str) or "\0" in argument for argument in arguments
        )
        or not isinstance(context, str)
        or not context
        or type(merge_stderr) is not bool
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

    stdin_file = tempfile.TemporaryFile()
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    try:
        if stdin_document is not None:
            stdin_file.write(stdin_document)
            stdin_file.seek(0)
            stdin: int | Any = stdin_file
        else:
            stdin = subprocess.DEVNULL
        process = subprocess.Popen(
            list(arguments),
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
        deadline = time.monotonic() + timeout_seconds
        while selector.get_map():
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise ReviewError(
                    f"{context} timed out after {timeout_seconds} seconds"
                )
            events = selector.select(remaining_time)
            if not events:
                raise ReviewError(
                    f"{context} timed out after {timeout_seconds} seconds"
                )
            for key, _ in events:
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
        remaining_time = deadline - time.monotonic()
        if remaining_time <= 0 and process.poll() is None:
            raise ReviewError(f"{context} timed out after {timeout_seconds} seconds")
        try:
            returncode = process.wait(timeout=max(remaining_time, 0))
        except subprocess.TimeoutExpired as error:
            raise ReviewError(
                f"{context} timed out after {timeout_seconds} seconds"
            ) from error
        return BoundedHostResult(
            returncode,
            bytes(outputs["stdout"]),
            bytes(outputs["stderr"]),
        )
    except ReviewError:
        if process is not None:
            _stop_bounded_host_process(process, context)
        raise
    except (OSError, ValueError) as error:
        if process is not None:
            _stop_bounded_host_process(process, context)
        raise ReviewError(f"cannot run {context}") from error
    except BaseException:
        if process is not None:
            _stop_bounded_host_process(process, context)
        raise
    finally:
        selector.close()
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        stdin_file.close()


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
