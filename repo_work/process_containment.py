"""Dependency-free host process containment for release tools."""

from __future__ import annotations

import ctypes
import errno
import os
import select
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


PROCESS_GROUP_CONTAINMENT = "process-group"
CANDIDATE_TREE_CONTAINMENT = "candidate-tree"
PROCESS_GROUP_CONTAINMENT_SCOPE = frozenset({"root-process", "original-process-group"})
HOST_PROCESS_CONTAINMENT_MODES = frozenset(
    {PROCESS_GROUP_CONTAINMENT, CANDIDATE_TREE_CONTAINMENT}
)
PROCESS_POLL_INTERVAL_SECONDS = 0.05
PROCESS_TERM_GRACE_SECONDS = 0.5
LAUNCH_GATE_TIMEOUT_SECONDS = 10.0
CONTROL_PROBE_TIMEOUT_SECONDS = 2.0
MAX_PROC_STAT_BYTES = 16 * 1024
MAX_PROC_CHILDREN_BYTES = 4 * 1024 * 1024
MAX_PROCESS_INVENTORY = 65_536
PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37
REQUIRED_LINUX_WAITID_NAMES = (
    "CLD_DUMPED",
    "CLD_EXITED",
    "CLD_KILLED",
    "CLD_STOPPED",
    "P_PID",
    "WEXITED",
    "WNOHANG",
    "WNOWAIT",
    "WSTOPPED",
    "waitid",
)
REQUIRED_LINUX_POLL_NAMES = (
    "POLLERR",
    "POLLHUP",
    "POLLIN",
    "POLLNVAL",
    "poll",
)
REQUIRED_LINUX_PROCESS_NAMES = (
    "fork",
    "pidfd_open",
    "waitpid",
    "waitstatus_to_exitcode",
)
REQUIRED_LINUX_SIGNAL_NAMES = (
    "NSIG",
    "SIG_BLOCK",
    "SIG_SETMASK",
    "pidfd_send_signal",
    "pthread_sigmask",
    "valid_signals",
)
SIGNAL_MASK_GATE_SOURCE = (
    "import os,signal,sys\n"
    "parts=sys.argv[2].split(',') if sys.argv[2] else []\n"
    "mask=[int(value) for value in parts]\n"
    "if len(mask)!=len(set(mask)):raise ValueError('duplicate signal')\n"
    "signal.pthread_sigmask(signal.SIG_SETMASK,mask)\n"
)
PROCESS_GROUP_LAUNCH_GATE_SOURCE = (
    SIGNAL_MASK_GATE_SOURCE + "os.execvpe(sys.argv[3], sys.argv[3:], os.environ)\n"
)
LAUNCH_GATE_SOURCE = (
    SIGNAL_MASK_GATE_SOURCE
    + "os.kill(os.getpid(), signal.SIGSTOP)\n"
    + "os.execvpe(sys.argv[3], sys.argv[3:], os.environ)\n"
)


class ProcessContainmentError(RuntimeError):
    """A host process did not satisfy its containment contract."""


@dataclass(frozen=True)
class ProcessFinalization:
    """The reaped root status and survivor disposition."""

    returncode: int
    survivor_detected: bool


@dataclass(frozen=True)
class LinuxProcessIdentity:
    """One stable Linux process identity from procfs."""

    pid: int
    state: str
    parent_pid: int
    process_group: int
    session: int
    start_time: int


@dataclass(frozen=True)
class _ObservedExitStatus:
    """One non-reaping process-exit observation."""

    code: int
    status: int
    returncode: int


@dataclass
class _LinuxProcessHandle:
    """One Linux process identity held by a pidfd."""

    identity: LinuxProcessIdentity
    pidfd: int

    def close(self) -> None:
        if self.pidfd < 0:
            return
        descriptor = self.pidfd
        self.pidfd = -1
        _close_descriptor(
            descriptor,
            context=f"Linux process {self.identity.pid} pidfd",
        )


_SUBREAPER_LOCK = threading.Lock()
_SUBREAPER_POISONED = False


def _add_cleanup_note(
    primary_error: BaseException,
    *,
    context: str,
    cleanup_error: BaseException,
) -> None:
    if hasattr(primary_error, "add_note"):
        primary_error.add_note(
            f"{context} cleanup also failed: "
            f"{type(cleanup_error).__name__}: {cleanup_error}"
        )


def _close_descriptor(descriptor: int, *, context: str) -> None:
    """Close one owned descriptor exactly once."""

    try:
        os.close(descriptor)
    except OSError as error:
        raise ProcessContainmentError(f"cannot close {context}") from error


def _read_bounded_proc_file(path: Path, max_bytes: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(path, flags)
    try:
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            block = os.read(descriptor, min(64 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        document = b"".join(chunks)
        if len(document) > max_bytes:
            raise ProcessContainmentError(f"{path} exceeds its process inventory bound")
    except BaseException as error:
        try:
            _close_descriptor(descriptor, context=f"{path} descriptor")
        except BaseException as cleanup_error:
            _add_cleanup_note(
                error,
                context=f"{path} descriptor",
                cleanup_error=cleanup_error,
            )
        raise
    _close_descriptor(descriptor, context=f"{path} descriptor")
    return document


def _linux_process_identity(pid: int) -> LinuxProcessIdentity | None:
    try:
        document = _read_bounded_proc_file(
            Path("/proc") / str(pid) / "stat",
            MAX_PROC_STAT_BYTES,
        )
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno in {errno.ENOENT, errno.ESRCH}:
            return None
        raise ProcessContainmentError(
            f"cannot inspect Linux process {pid}: {error}"
        ) from error
    try:
        text = document.decode("ascii", "strict")
        opening = text.find("(")
        closing = text.rfind(")")
        if opening <= 0 or closing <= opening or not text[:opening].strip().isdigit():
            raise ValueError
        fields = text[closing + 1 :].strip().split()
        if len(fields) < 20:
            raise ValueError
        parsed_pid = int(text[:opening].strip())
        identity = LinuxProcessIdentity(
            pid=parsed_pid,
            state=fields[0],
            parent_pid=int(fields[1]),
            process_group=int(fields[2]),
            session=int(fields[3]),
            start_time=int(fields[19]),
        )
    except (UnicodeError, ValueError) as error:
        raise ProcessContainmentError(
            f"Linux process {pid} has malformed procfs identity"
        ) from error
    if identity.pid != pid:
        raise ProcessContainmentError(
            f"Linux process {pid} has an inconsistent procfs identity"
        )
    return identity


def _linux_direct_children() -> set[int]:
    task_root = Path("/proc/self/task")
    try:
        task_entries = tuple(task_root.iterdir())
    except OSError as error:
        raise ProcessContainmentError(
            f"cannot inspect Linux release-runner tasks: {error}"
        ) from error
    children: set[int] = set()
    for task in task_entries:
        if not task.name.isdigit():
            continue
        try:
            document = _read_bounded_proc_file(
                task / "children",
                MAX_PROC_CHILDREN_BYTES,
            )
        except FileNotFoundError:
            continue
        except OSError as error:
            if error.errno in {errno.ENOENT, errno.ESRCH}:
                continue
            raise ProcessContainmentError(
                f"cannot inspect Linux release-runner children: {error}"
            ) from error
        try:
            fields = document.decode("ascii", "strict").split()
        except UnicodeError as error:
            raise ProcessContainmentError(
                "Linux release-runner child inventory is not ASCII"
            ) from error
        if len(fields) > MAX_PROCESS_INVENTORY:
            raise ProcessContainmentError(
                "Linux release-runner child inventory exceeds its bound"
            )
        for field in fields:
            if not field.isdigit():
                raise ProcessContainmentError(
                    "Linux release-runner child inventory is malformed"
                )
            pid = int(field)
            if pid <= 1 or pid == os.getpid():
                raise ProcessContainmentError(
                    "Linux release-runner child inventory contains an invalid process"
                )
            children.add(pid)
    return children


def _linux_task_count() -> int:
    try:
        tasks = tuple(
            entry for entry in Path("/proc/self/task").iterdir() if entry.name.isdigit()
        )
    except OSError as error:
        raise ProcessContainmentError(
            f"cannot inspect Linux release-runner tasks: {error}"
        ) from error
    return len(tasks)


def _linux_group_members(process_group: int) -> set[int]:
    members: set[int] = set()
    inspected = 0
    try:
        entries = os.scandir("/proc")
    except OSError as error:
        raise ProcessContainmentError(
            f"cannot inspect Linux process groups: {error}"
        ) from error
    with entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            inspected += 1
            if inspected > MAX_PROCESS_INVENTORY:
                raise ProcessContainmentError(
                    "Linux process inventory exceeds its containment bound"
                )
            identity = _linux_process_identity(int(entry.name))
            if identity is not None and identity.process_group == process_group:
                members.add(identity.pid)
    return members


def _darwin_group_members(process_group: int) -> set[int]:
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        list_group = libproc.proc_listpgrppids
        list_group.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        list_group.restype = ctypes.c_int
    except (AttributeError, OSError) as error:
        raise ProcessContainmentError(
            f"cannot initialize macOS process-group inventory: {error}"
        ) from error
    buffer = (ctypes.c_int * MAX_PROCESS_INVENTORY)()
    ctypes.set_errno(0)
    count = list_group(process_group, buffer, ctypes.sizeof(buffer))
    if count < 0:
        error_number = ctypes.get_errno()
        if error_number == errno.ESRCH:
            return set()
        raise ProcessContainmentError(
            "cannot inspect macOS process group "
            f"{process_group}: {os.strerror(error_number)}"
        )
    if count >= MAX_PROCESS_INVENTORY:
        raise ProcessContainmentError(
            "macOS process-group inventory exceeds its containment bound"
        )
    return {int(buffer[index]) for index in range(count) if int(buffer[index]) > 1}


def process_group_members(process_group: int) -> set[int]:
    """Return every visible member of one process group."""

    if process_group <= 1:
        raise ProcessContainmentError("process-group identifier is invalid")
    if sys.platform.startswith("linux"):
        return _linux_group_members(process_group)
    if sys.platform == "darwin":
        return _darwin_group_members(process_group)
    raise ProcessContainmentError(
        f"process-group inventory is unsupported on {sys.platform}"
    )


def process_group_exists(process_group: int) -> bool:
    """Return true unless process-group extinction is proven by ESRCH."""

    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as error:
        raise ProcessContainmentError(
            f"cannot inspect process group {process_group}: {error}"
        ) from error
    return True


def _decode_waitid_exit(
    status: object,
    *,
    pid: int,
    context: str,
) -> _ObservedExitStatus:
    try:
        observed_pid = status.si_pid  # type: ignore[attr-defined]
        code = status.si_code  # type: ignore[attr-defined]
        exit_status = status.si_status  # type: ignore[attr-defined]
    except AttributeError as error:
        raise ProcessContainmentError(
            f"{context} returned an incomplete wait status"
        ) from error
    if (
        type(observed_pid) is not int
        or observed_pid != pid
        or type(code) is not int
        or type(exit_status) is not int
    ):
        raise ProcessContainmentError(f"{context} returned an invalid wait identity")
    if code == os.CLD_EXITED and 0 <= exit_status <= 255:
        returncode = exit_status
    elif (
        code == os.CLD_EXITED
        and sys.platform == "darwin"
        and 0 <= exit_status <= 0xFF_FFFF
    ):
        # Darwin waitid can retain status bits that waitpid discards.
        returncode = exit_status & 0xFF
    elif code in {os.CLD_KILLED, os.CLD_DUMPED} and 0 < exit_status < signal.NSIG:
        returncode = -exit_status
    else:
        raise ProcessContainmentError(f"{context} returned an invalid exit status")
    return _ObservedExitStatus(code, exit_status, returncode)


def _observe_nonreaping_exit(
    pid: int,
    *,
    context: str,
) -> _ObservedExitStatus | None:
    """Observe one exit status without releasing its process identifier."""

    try:
        status = os.waitid(
            os.P_PID,
            pid,
            os.WEXITED | os.WNOHANG | os.WNOWAIT,
        )
    except ChildProcessError as error:
        raise ProcessContainmentError(
            f"{context} wait status is unavailable"
        ) from error
    except OSError as error:
        raise ProcessContainmentError(
            f"cannot inspect {context} wait status"
        ) from error
    if status is None:
        return None
    return _decode_waitid_exit(status, pid=pid, context=context)


def _reap_exact_pid(
    pid: int,
    observed: _ObservedExitStatus,
    *,
    context: str,
) -> int:
    """Reap one observed child and require the same exact exit status."""

    try:
        waited_pid, wait_status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError as error:
        raise ProcessContainmentError(
            f"{context} wait status was lost before reaping"
        ) from error
    except OSError as error:
        raise ProcessContainmentError(f"cannot reap {context}") from error
    if waited_pid != pid:
        raise ProcessContainmentError(f"{context} was not ready for exact reaping")
    try:
        returncode = os.waitstatus_to_exitcode(wait_status)
    except ValueError as error:
        raise ProcessContainmentError(
            f"{context} returned a nonterminal wait status"
        ) from error
    if returncode != observed.returncode:
        raise ProcessContainmentError(f"{context} exit status changed before reaping")
    return returncode


def _reap_exact_process_root(
    process: subprocess.Popen[bytes],
    *,
    expected: _ObservedExitStatus | None = None,
    context: str,
) -> int:
    """Reap one process root without a subprocess ECHILD fallback."""

    if process.returncode is not None:
        raise ProcessContainmentError(
            f"{context} wait status was consumed before exact reaping"
        )
    observed = _observe_nonreaping_exit(process.pid, context=context)
    if observed is None:
        raise ProcessContainmentError(
            f"{context} has no observable terminal wait status"
        )
    if expected is not None and observed != expected:
        raise ProcessContainmentError(
            f"{context} exit status changed during containment"
        )
    returncode = _reap_exact_pid(
        process.pid,
        observed,
        context=context,
    )
    process.returncode = returncode
    return returncode


def root_process_exited(process: subprocess.Popen[bytes]) -> bool:
    """Observe root exit without reaping its process identifier."""

    if process.returncode is not None:
        raise ProcessContainmentError(
            "host command root wait status was consumed before containment completed"
        )
    if not all(
        hasattr(os, name)
        for name in ("P_PID", "WEXITED", "WNOHANG", "WNOWAIT", "waitid")
    ):
        raise ProcessContainmentError(
            "non-reaping root process observation is unavailable"
        )
    observed = _observe_nonreaping_exit(
        process.pid,
        context="host command root",
    )
    return observed is not None


def _signal_process_group(
    process: subprocess.Popen[bytes],
    signal_number: int,
) -> OSError | None:
    try:
        os.killpg(process.pid, signal_number)
        return None
    except ProcessLookupError:
        return None
    except OSError as group_error:
        try:
            os.kill(process.pid, signal_number)
        except ProcessLookupError:
            pass
        except OSError:
            pass
        return group_error


def _wait_for_group_state(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
) -> tuple[bool, set[int]]:
    while True:
        root_exited = root_process_exited(process)
        members = process_group_members(process.pid)
        members.discard(process.pid)
        if sys.platform.startswith("linux") and members:
            reaped_child = False
            for pid in sorted(members):
                identity = _linux_process_identity(pid)
                if (
                    identity is None
                    or identity.parent_pid != os.getpid()
                    or identity.state not in {"X", "Z"}
                ):
                    continue
                try:
                    waited_pid, _status = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    continue
                except OSError as error:
                    if error.errno in {errno.ECHILD, errno.ENOENT, errno.ESRCH}:
                        continue
                    raise ProcessContainmentError(
                        f"cannot reap host command group member {pid}: {error}"
                    ) from error
                if waited_pid == pid:
                    reaped_child = True
            if reaped_child:
                members = process_group_members(process.pid)
                members.discard(process.pid)
        if root_exited and not members:
            return True, members
        if time.monotonic() >= deadline:
            return root_exited, members
        time.sleep(PROCESS_POLL_INTERVAL_SECONDS)


def _verify_group_extinction(process_group: int, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    while process_group_exists(process_group):
        if time.monotonic() >= deadline:
            raise ProcessContainmentError(
                "host command process group did not become extinct"
            )
        time.sleep(PROCESS_POLL_INTERVAL_SECONDS)


def finalize_process_group(
    process: subprocess.Popen[bytes],
    *,
    force_stop: bool,
    stop_timeout_seconds: float,
) -> ProcessFinalization:
    """Stop, reap, and verify one original host-command process group."""

    if stop_timeout_seconds <= 0:
        raise ProcessContainmentError("host command stop timeout is invalid")
    initial_root_exited = root_process_exited(process)
    initial_members = process_group_members(process.pid)
    initial_members.discard(process.pid)
    survivor_detected = initial_root_exited and bool(initial_members)
    signal_error: OSError | None = None
    root_exited = initial_root_exited
    members = initial_members
    if force_stop or not root_exited or members:
        signal_error = _signal_process_group(process, signal.SIGTERM)
        root_exited, members = _wait_for_group_state(
            process,
            deadline=time.monotonic()
            + min(PROCESS_TERM_GRACE_SECONDS, stop_timeout_seconds),
        )
    if not root_exited or members:
        kill_error = _signal_process_group(process, signal.SIGKILL)
        if kill_error is not None:
            signal_error = kill_error
        root_exited, members = _wait_for_group_state(
            process,
            deadline=time.monotonic() + stop_timeout_seconds,
        )
    if not root_exited or members:
        error = ProcessContainmentError(
            "host command did not terminate within its stop bound"
        )
        if signal_error is not None:
            raise error from signal_error
        raise error
    returncode = _reap_exact_process_root(
        process,
        context="host command root",
    )
    _verify_group_extinction(process.pid, stop_timeout_seconds)
    return ProcessFinalization(returncode, survivor_detected)


def _prctl_get_child_subreaper() -> bool:
    try:
        prctl = ctypes.CDLL(None, use_errno=True).prctl
    except (AttributeError, OSError) as error:
        raise ProcessContainmentError(
            "cannot initialize Linux child-subreaper control"
        ) from error
    prctl.restype = ctypes.c_int
    value = ctypes.c_int()
    ctypes.set_errno(0)
    result = prctl(
        PR_GET_CHILD_SUBREAPER,
        ctypes.byref(value),
        0,
        0,
        0,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise ProcessContainmentError(
            f"cannot inspect Linux child-subreaper state: {os.strerror(error_number)}"
        )
    return bool(value.value)


def _prctl_set_child_subreaper(enabled: bool) -> None:
    try:
        prctl = ctypes.CDLL(None, use_errno=True).prctl
    except (AttributeError, OSError) as error:
        raise ProcessContainmentError(
            "cannot initialize Linux child-subreaper control"
        ) from error
    prctl.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = prctl(
        PR_SET_CHILD_SUBREAPER,
        int(enabled),
        0,
        0,
        0,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise ProcessContainmentError(
            f"cannot set Linux child-subreaper state: {os.strerror(error_number)}"
        )


def _pidfd_is_exited(pidfd: int) -> bool:
    if not all(hasattr(select, name) for name in REQUIRED_LINUX_POLL_NAMES):
        raise ProcessContainmentError("Linux pidfd polling is unavailable")
    try:
        poller = select.poll()
        poller.register(
            pidfd,
            select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL,
        )
        events = poller.poll(0)
    except (OSError, ValueError) as error:
        raise ProcessContainmentError(
            "cannot inspect a Linux process handle"
        ) from error
    if not events:
        return False
    if len(events) != 1 or events[0][0] != pidfd:
        raise ProcessContainmentError(
            "Linux process-handle polling returned an invalid identity"
        )
    event_mask = events[0][1]
    if event_mask & select.POLLNVAL:
        raise ProcessContainmentError("Linux process handle is invalid")
    if event_mask & select.POLLERR:
        raise ProcessContainmentError("Linux process-handle polling failed")
    unknown_events = event_mask & ~(select.POLLIN | select.POLLHUP)
    if unknown_events:
        raise ProcessContainmentError(
            "Linux process-handle polling returned an unknown event"
        )
    return bool(event_mask & (select.POLLIN | select.POLLHUP))


def _probe_linux_candidate_controls() -> None:
    """Probe required Linux controls and close the probe handle."""

    runner_pid = os.getpid()
    identity = _linux_process_identity(runner_pid)
    if (
        identity is None
        or identity.parent_pid != os.getppid()
        or identity.process_group != os.getpgrp()
        or identity.session != os.getsid(0)
        or identity.start_time <= 0
    ):
        raise ProcessContainmentError(
            "candidate-tree containment found invalid procfs identity"
        )
    if runner_pid not in _linux_group_members(identity.process_group):
        raise ProcessContainmentError(
            "candidate-tree containment cannot inventory its procfs process group"
        )
    try:
        pidfd = os.pidfd_open(runner_pid, 0)
    except OSError as error:
        raise ProcessContainmentError(
            "candidate-tree containment cannot open a probe pidfd"
        ) from error
    probe_descriptor = pidfd
    handle = _LinuxProcessHandle(identity, pidfd)
    try:
        signal.pidfd_send_signal(pidfd, 0)
        if _pidfd_is_exited(pidfd):
            raise ProcessContainmentError(
                "candidate-tree containment probe pidfd is unexpectedly ready"
            )
    except OSError as error:
        primary_error: BaseException = ProcessContainmentError(
            "candidate-tree containment cannot signal its probe pidfd"
        )
        try:
            handle.close()
        except BaseException as cleanup_error:
            _add_cleanup_note(
                primary_error,
                context="candidate-tree probe pidfd",
                cleanup_error=cleanup_error,
            )
        raise primary_error from error
    except BaseException as primary_error:
        try:
            handle.close()
        except BaseException as cleanup_error:
            _add_cleanup_note(
                primary_error,
                context="candidate-tree probe pidfd",
                cleanup_error=cleanup_error,
            )
        raise
    handle.close()
    try:
        os.fstat(probe_descriptor)
    except OSError as error:
        if error.errno == errno.EBADF:
            return
        raise ProcessContainmentError(
            "candidate-tree containment cannot verify probe pidfd cleanup"
        ) from error
    raise ProcessContainmentError(
        "candidate-tree containment probe pidfd remained open"
    )


def _terminate_waitid_probe_child(
    pid: int,
    handle: _LinuxProcessHandle | None,
) -> None:
    """Terminate and reap one trusted waitid probe child."""

    try:
        if handle is None:
            os.kill(pid, signal.SIGKILL)
        else:
            signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as error:
        raise ProcessContainmentError(
            "cannot terminate the waitid probe child"
        ) from error
    deadline = time.monotonic() + CONTROL_PROBE_TIMEOUT_SECONDS
    while True:
        try:
            waited_pid, _wait_status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return
        except OSError as error:
            raise ProcessContainmentError(
                "cannot reap the waitid probe child"
            ) from error
        if waited_pid == pid:
            return
        if time.monotonic() >= deadline:
            raise ProcessContainmentError(
                "waitid probe child cleanup exceeded its time bound"
            )
        time.sleep(0.01)


def _probe_linux_waitid_controls() -> None:
    """Probe non-reaping waitid behavior with one stopped trusted child."""

    global _SUBREAPER_POISONED

    blocked_signals = set(signal.valid_signals())
    blocked_signals.discard(signal.SIGKILL)
    blocked_signals.discard(signal.SIGSTOP)
    try:
        previous_mask = frozenset(
            int(value) for value in signal.pthread_sigmask(signal.SIG_BLOCK, ())
        )
    except (OSError, ValueError) as error:
        raise ProcessContainmentError(
            "candidate-tree containment cannot inspect its waitid probe signal mask"
        ) from error

    pid: int | None = None
    handle: _LinuxProcessHandle | None = None
    probe_descriptor: int | None = None
    mask_restored = True
    reaped = False
    primary_error: BaseException | None = None

    def restore_signal_mask() -> None:
        """Restore and verify the exact pre-probe signal mask."""

        nonlocal mask_restored
        if mask_restored:
            return
        restore_error: BaseException | None = None
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        except BaseException as error:
            restore_error = error

        verification_error: BaseException | None = None
        try:
            current_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        except BaseException as error:
            verification_error = error
        else:
            if frozenset(int(value) for value in current_mask) == previous_mask:
                mask_restored = True
            else:
                verification_error = ProcessContainmentError(
                    "candidate-tree waitid probe signal mask was not restored"
                )

        if restore_error is not None:
            if verification_error is not None:
                _add_cleanup_note(
                    restore_error,
                    context="candidate-tree waitid probe signal-mask verification",
                    cleanup_error=verification_error,
                )
            if isinstance(restore_error, (OSError, ValueError)):
                raise ProcessContainmentError(
                    "candidate-tree containment cannot restore its waitid probe signal mask"
                ) from restore_error
            raise restore_error
        if verification_error is not None:
            if isinstance(verification_error, ProcessContainmentError):
                raise verification_error
            raise ProcessContainmentError(
                "candidate-tree containment cannot verify its waitid probe signal mask"
            ) from verification_error

    try:
        mask_restored = False
        try:
            signal.pthread_sigmask(signal.SIG_BLOCK, blocked_signals)
        except (OSError, ValueError) as error:
            raise ProcessContainmentError(
                "candidate-tree containment cannot block signals for its waitid probe"
            ) from error
        try:
            current_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        except (OSError, ValueError) as error:
            raise ProcessContainmentError(
                "candidate-tree containment cannot verify its blocked waitid probe signal mask"
            ) from error
        expected_mask = previous_mask | {int(value) for value in blocked_signals}
        if frozenset(int(value) for value in current_mask) != expected_mask:
            raise ProcessContainmentError(
                "candidate-tree containment did not block its waitid probe signals"
            )
        try:
            pid = os.fork()
        except OSError as error:
            raise ProcessContainmentError(
                "candidate-tree containment cannot create its waitid probe"
            ) from error
        if pid == 0:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
                child_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
                if frozenset(int(value) for value in child_mask) != previous_mask:
                    os._exit(120)
                os.kill(os.getpid(), signal.SIGSTOP)
            except BaseException:
                os._exit(120)
            os._exit(0)
        restore_signal_mask()

        handle = _open_linux_process_handle(pid, required_parent=os.getpid())
        if handle is None:
            raise ProcessContainmentError(
                "candidate-tree containment lost its waitid probe child"
            )
        probe_descriptor = handle.pidfd
        deadline = time.monotonic() + CONTROL_PROBE_TIMEOUT_SECONDS
        while True:
            try:
                stopped = os.waitid(
                    os.P_PID,
                    pid,
                    os.WEXITED | os.WSTOPPED | os.WNOHANG | os.WNOWAIT,
                )
            except ChildProcessError as error:
                raise ProcessContainmentError(
                    "candidate-tree waitid probe status is unavailable"
                ) from error
            except OSError as error:
                raise ProcessContainmentError(
                    "candidate-tree containment cannot inspect its waitid probe"
                ) from error
            if stopped is not None:
                try:
                    stopped_pid = stopped.si_pid
                    stopped_code = stopped.si_code
                    stopped_status = stopped.si_status
                except AttributeError as error:
                    raise ProcessContainmentError(
                        "candidate-tree waitid probe returned an incomplete stop status"
                    ) from error
                if (
                    type(stopped_pid) is int
                    and stopped_pid == pid
                    and type(stopped_code) is int
                    and stopped_code == os.CLD_STOPPED
                    and type(stopped_status) is int
                    and stopped_status == signal.SIGSTOP
                ):
                    break
                if type(stopped_code) is int and stopped_code in {
                    os.CLD_EXITED,
                    os.CLD_KILLED,
                    os.CLD_DUMPED,
                }:
                    raise ProcessContainmentError(
                        "candidate-tree waitid probe exited before its gate"
                    )
                raise ProcessContainmentError(
                    "candidate-tree waitid probe returned an invalid stop status"
                )
            if time.monotonic() >= deadline:
                raise ProcessContainmentError(
                    "candidate-tree waitid probe did not stop within its time bound"
                )
            time.sleep(0.01)

        try:
            signal.pidfd_send_signal(handle.pidfd, signal.SIGCONT)
        except OSError as error:
            raise ProcessContainmentError(
                "candidate-tree containment cannot resume its waitid probe"
            ) from error
        deadline = time.monotonic() + CONTROL_PROBE_TIMEOUT_SECONDS
        while not _pidfd_is_exited(handle.pidfd):
            if time.monotonic() >= deadline:
                raise ProcessContainmentError(
                    "candidate-tree waitid probe did not exit within its time bound"
                )
            time.sleep(0.01)
        observed = _observe_nonreaping_exit(
            pid,
            context="candidate-tree waitid probe",
        )
        if observed is None or observed.returncode != 0:
            raise ProcessContainmentError(
                "candidate-tree waitid probe returned an invalid exit status"
            )
        _reap_exact_pid(
            pid,
            observed,
            context="candidate-tree waitid probe",
        )
        reaped = True
    except BaseException as error:
        primary_error = error
    finally:
        if pid is not None and pid > 0 and not reaped:
            try:
                _terminate_waitid_probe_child(pid, handle)
            except BaseException as cleanup_error:
                if primary_error is None:
                    primary_error = cleanup_error
                else:
                    _add_cleanup_note(
                        primary_error,
                        context="candidate-tree waitid probe child",
                        cleanup_error=cleanup_error,
                    )
        if handle is not None:
            try:
                handle.close()
            except BaseException as cleanup_error:
                if primary_error is None:
                    primary_error = cleanup_error
                else:
                    _add_cleanup_note(
                        primary_error,
                        context="candidate-tree waitid probe pidfd",
                        cleanup_error=cleanup_error,
                    )
        if probe_descriptor is not None:
            try:
                os.fstat(probe_descriptor)
            except OSError as cleanup_error:
                if cleanup_error.errno != errno.EBADF:
                    verification_error = ProcessContainmentError(
                        "candidate-tree containment cannot verify waitid probe pidfd cleanup"
                    )
                    if primary_error is None:
                        primary_error = verification_error
                    else:
                        _add_cleanup_note(
                            primary_error,
                            context="candidate-tree waitid probe pidfd",
                            cleanup_error=verification_error,
                        )
            else:
                verification_error = ProcessContainmentError(
                    "candidate-tree containment waitid probe pidfd remained open"
                )
                if primary_error is None:
                    primary_error = verification_error
                else:
                    _add_cleanup_note(
                        primary_error,
                        context="candidate-tree waitid probe pidfd",
                        cleanup_error=verification_error,
                    )
        if not mask_restored:
            try:
                restore_signal_mask()
            except BaseException as cleanup_error:
                if primary_error is None:
                    primary_error = cleanup_error
                else:
                    _add_cleanup_note(
                        primary_error,
                        context="candidate-tree waitid probe signal mask",
                        cleanup_error=cleanup_error,
                    )
        if not mask_restored:
            _SUBREAPER_POISONED = True
    if primary_error is not None:
        raise primary_error


def _open_linux_process_handle(
    pid: int,
    *,
    required_parent: int,
) -> _LinuxProcessHandle | None:
    before = _linux_process_identity(pid)
    if before is None:
        return None
    if before.parent_pid != required_parent:
        raise ProcessContainmentError(
            f"Linux process {pid} is not an adopted candidate child"
        )
    try:
        pidfd = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return None
    except OSError as error:
        raise ProcessContainmentError(
            f"cannot open a stable handle for Linux process {pid}: {error}"
        ) from error
    handle = _LinuxProcessHandle(before, pidfd)
    after = _linux_process_identity(pid)
    if after is None:
        handle.close()
        return None
    if (
        after.pid != before.pid
        or after.start_time != before.start_time
        or after.parent_pid != required_parent
    ):
        error = ProcessContainmentError(
            f"Linux process {pid} changed identity during containment"
        )
        try:
            handle.close()
        except BaseException as cleanup_error:
            _add_cleanup_note(
                error,
                context=f"Linux process {pid} pidfd",
                cleanup_error=cleanup_error,
            )
        raise error
    handle.identity = after
    return handle


def _require_default_sigchld() -> None:
    """Require the default child-status disposition."""

    try:
        child_disposition = signal.getsignal(signal.SIGCHLD)
    except (OSError, ValueError) as error:
        raise ProcessContainmentError(
            "candidate-tree containment cannot inspect SIGCHLD"
        ) from error
    if child_disposition != signal.SIG_DFL:
        raise ProcessContainmentError(
            "candidate-tree containment requires the default SIGCHLD disposition"
        )


def _encode_launch_signal_mask(inherited_signal_mask: Sequence[int]) -> str:
    """Validate and encode one exact inherited signal mask."""

    valid_signals = {int(value) for value in signal.valid_signals()}
    unmaskable_signals = {int(signal.SIGKILL), int(signal.SIGSTOP)}
    try:
        signal_mask = tuple(inherited_signal_mask)
    except TypeError as error:
        raise ProcessContainmentError("launch gate signal mask is invalid") from error
    if isinstance(inherited_signal_mask, (str, bytes)) or any(
        type(value) is not int for value in signal_mask
    ):
        raise ProcessContainmentError("launch gate signal mask is invalid")
    signal_mask_set = set(signal_mask)
    if (
        len(signal_mask_set) != len(signal_mask)
        or not signal_mask_set <= valid_signals
        or signal_mask_set & unmaskable_signals
    ):
        raise ProcessContainmentError("launch gate signal mask is invalid")
    return ",".join(str(value) for value in sorted(signal_mask))


def _signal_mask_launch_arguments(
    arguments: Sequence[str],
    *,
    inherited_signal_mask: Sequence[int],
    gate_name: str,
    gate_source: str,
) -> list[str]:
    """Wrap one command in an exact signal-mask restoration gate."""

    executable = Path(sys.executable)
    if not executable.is_absolute():
        raise ProcessContainmentError(
            f"{gate_name} launch gate requires an absolute Python executable"
        )
    return [
        str(executable),
        "-I",
        "-c",
        gate_source,
        f"{gate_name}-launch-gate",
        _encode_launch_signal_mask(inherited_signal_mask),
        *arguments,
    ]


def process_group_launch_arguments(
    arguments: Sequence[str],
    *,
    inherited_signal_mask: Sequence[int],
) -> list[str]:
    """Wrap one process-group command without changing its final arguments."""

    return _signal_mask_launch_arguments(
        arguments,
        inherited_signal_mask=inherited_signal_mask,
        gate_name="process-group",
        gate_source=PROCESS_GROUP_LAUNCH_GATE_SOURCE,
    )


class LinuxCandidateTreeContainment:
    """Contain one Linux candidate tree with a subreaper and pidfds."""

    def __init__(self, *, context: str, stop_timeout_seconds: float) -> None:
        self.context = context
        self.stop_timeout_seconds = stop_timeout_seconds
        self._active = False
        self._previous_subreaper = False
        self._root: _LinuxProcessHandle | None = None
        self._adopted: dict[int, _LinuxProcessHandle] = {}
        self._root_exit_status: _ObservedExitStatus | None = None
        self._integrity_error: ProcessContainmentError | None = None
        self._integrity_details: set[tuple[str, str]] = set()
        self._integrity_cleanup_details: set[tuple[str, str, str]] = set()
        self._group_anchor_safe = True
        self._cleanup_complete = False
        self._verified = False

    def _record_integrity_error(
        self,
        error: ProcessContainmentError,
        *,
        anchor_lost: bool,
    ) -> ProcessContainmentError:
        global _SUBREAPER_POISONED
        if anchor_lost:
            self._group_anchor_safe = False
        _SUBREAPER_POISONED = True
        detail = (type(error).__name__, str(error))
        if self._integrity_error is None:
            self._integrity_error = error
            self._integrity_details.add(detail)
        elif (
            self._integrity_error is not error
            and detail not in self._integrity_details
            and hasattr(
                self._integrity_error,
                "add_note",
            )
        ):
            self._integrity_error.add_note(
                f"candidate-tree integrity also failed: {type(error).__name__}: {error}"
            )
            self._integrity_details.add(detail)
        return self._integrity_error

    def _record_integrity_cleanup_error(
        self,
        integrity_error: ProcessContainmentError,
        *,
        context: str,
        cleanup_error: BaseException,
    ) -> None:
        """Retain one unique control-restoration failure."""

        detail = (context, type(cleanup_error).__name__, str(cleanup_error))
        if detail in self._integrity_cleanup_details:
            return
        self._integrity_cleanup_details.add(detail)
        _add_cleanup_note(
            integrity_error,
            context=context,
            cleanup_error=cleanup_error,
        )

    def _observe_sigchld_integrity(self) -> ProcessContainmentError | None:
        """Record a child-status disposition change and restore the safe default."""

        try:
            child_disposition = signal.getsignal(signal.SIGCHLD)
        except (OSError, ValueError):
            error = ProcessContainmentError(
                "candidate-tree containment cannot verify SIGCHLD integrity"
            )
            return self._record_integrity_error(error, anchor_lost=True)
        if child_disposition != signal.SIG_DFL:
            error = ProcessContainmentError(
                "candidate-tree SIGCHLD disposition changed during containment"
            )
            recorded = self._record_integrity_error(error, anchor_lost=True)
            try:
                signal.signal(signal.SIGCHLD, signal.SIG_DFL)
            except (OSError, RuntimeError, ValueError) as cleanup_error:
                self._record_integrity_cleanup_error(
                    recorded,
                    context="candidate-tree SIGCHLD disposition",
                    cleanup_error=cleanup_error,
                )
            return recorded
        return self._integrity_error

    def _observe_subreaper_integrity(self) -> ProcessContainmentError | None:
        """Record active child-subreaper drift and restore active control."""

        if not self._active:
            return self._integrity_error
        try:
            enabled = _prctl_get_child_subreaper()
        except ProcessContainmentError as control_error:
            error = ProcessContainmentError(
                "candidate-tree containment cannot verify active child-subreaper state"
            )
            recorded = self._record_integrity_error(error, anchor_lost=False)
            self._record_integrity_cleanup_error(
                recorded,
                context="candidate-tree child-subreaper inspection",
                cleanup_error=control_error,
            )
            self._restore_active_subreaper(recorded)
            return recorded
        if not enabled:
            error = ProcessContainmentError(
                "candidate-tree child-subreaper state changed during containment"
            )
            recorded = self._record_integrity_error(error, anchor_lost=False)
            self._restore_active_subreaper(recorded)
            return recorded
        return self._integrity_error

    def _restore_active_subreaper(
        self,
        integrity_error: ProcessContainmentError,
    ) -> None:
        """Restore active child-subreaper control after detected drift."""

        try:
            _prctl_set_child_subreaper(True)
            if not _prctl_get_child_subreaper():
                raise ProcessContainmentError(
                    "candidate-tree containment did not restore active "
                    "child-subreaper state"
                )
        except ProcessContainmentError as cleanup_error:
            self._record_integrity_cleanup_error(
                integrity_error,
                context="candidate-tree child-subreaper state",
                cleanup_error=cleanup_error,
            )

    def _observe_transaction_integrity(self) -> ProcessContainmentError | None:
        """Check each process-global control for one active transaction."""

        self._observe_sigchld_integrity()
        self._observe_subreaper_integrity()
        return self._integrity_error

    def _require_transaction_integrity(self) -> None:
        error = self._observe_transaction_integrity()
        if error is not None:
            raise error

    def _restore_failed_activation(
        self,
        primary_error: BaseException,
    ) -> None:
        """Restore process state after an activation exception."""

        global _SUBREAPER_POISONED
        if not self._active:
            return
        _SUBREAPER_POISONED = True
        restored = False
        try:
            current = _prctl_get_child_subreaper()
            if current != self._previous_subreaper:
                _prctl_set_child_subreaper(self._previous_subreaper)
            restored = _prctl_get_child_subreaper() == self._previous_subreaper
            if not restored:
                raise ProcessContainmentError(
                    "candidate-tree activation did not restore subreaper state"
                )
        except BaseException as cleanup_error:
            _add_cleanup_note(
                primary_error,
                context="candidate-tree activation",
                cleanup_error=cleanup_error,
            )
        finally:
            self._active = False
        if restored and self._integrity_error is None:
            _SUBREAPER_POISONED = False

    def activate(self) -> None:
        """Acquire exclusive process ownership before candidate spawn."""

        global _SUBREAPER_POISONED
        if self._active:
            raise ProcessContainmentError(
                "candidate-tree containment is already active"
            )
        if not sys.platform.startswith("linux"):
            raise ProcessContainmentError("candidate-tree containment requires Linux")
        if (
            not Path("/proc/self/task").is_dir()
            or not all(hasattr(os, name) for name in REQUIRED_LINUX_PROCESS_NAMES)
            or not all(hasattr(os, name) for name in REQUIRED_LINUX_WAITID_NAMES)
            or not all(hasattr(select, name) for name in REQUIRED_LINUX_POLL_NAMES)
            or not all(hasattr(signal, name) for name in REQUIRED_LINUX_SIGNAL_NAMES)
        ):
            raise ProcessContainmentError(
                "candidate-tree containment requires procfs, pidfds, poll, waitid, "
                "fork, and signal-mask control"
            )
        _require_default_sigchld()
        if not _SUBREAPER_LOCK.acquire(blocking=False):
            raise ProcessContainmentError(
                "candidate-tree containment ownership is already active"
            )
        try:
            if _SUBREAPER_POISONED:
                raise ProcessContainmentError(
                    "candidate-tree containment is unavailable after cleanup failure"
                )
            if _linux_task_count() != 1:
                raise ProcessContainmentError(
                    "candidate-tree containment requires a single-threaded runner"
                )
            if _linux_direct_children():
                raise ProcessContainmentError(
                    "candidate-tree containment found a pre-existing child process"
                )
            _probe_linux_candidate_controls()
            _probe_linux_waitid_controls()
            _require_default_sigchld()
            if _linux_direct_children():
                raise ProcessContainmentError(
                    "candidate-tree containment waitid probe left a child process"
                )
            self._previous_subreaper = _prctl_get_child_subreaper()
            self._active = True
            if not self._previous_subreaper:
                _prctl_set_child_subreaper(True)
            if not _prctl_get_child_subreaper():
                raise ProcessContainmentError(
                    "candidate-tree containment did not enable subreaper state"
                )
            self._require_transaction_integrity()
        except BaseException as error:
            self._restore_failed_activation(error)
            _SUBREAPER_LOCK.release()
            raise

    def launch_arguments(
        self,
        arguments: Sequence[str],
        *,
        inherited_signal_mask: Sequence[int],
    ) -> list[str]:
        """Wrap one candidate in a trusted stop-before-exec gate."""

        self._require_transaction_integrity()
        return _signal_mask_launch_arguments(
            arguments,
            inherited_signal_mask=inherited_signal_mask,
            gate_name="candidate-tree",
            gate_source=LAUNCH_GATE_SOURCE,
        )

    def invalidate_launch_signal_mask(self) -> None:
        """Make containment unavailable after signal-mask ownership fails."""

        self._record_integrity_error(
            ProcessContainmentError(
                "candidate-tree launch signal mask was not restored"
            ),
            anchor_lost=False,
        )

    def arm(self, process: subprocess.Popen[bytes]) -> None:
        """Capture the stopped root identity before candidate execution."""

        deadline = time.monotonic() + LAUNCH_GATE_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            try:
                status = os.waitid(
                    os.P_PID,
                    process.pid,
                    os.WEXITED | os.WSTOPPED | os.WNOHANG | os.WNOWAIT,
                )
            except ChildProcessError as error:
                raise ProcessContainmentError(
                    "candidate-tree launch gate disappeared"
                ) from error
            except OSError as error:
                raise ProcessContainmentError(
                    "cannot inspect the candidate-tree launch gate"
                ) from error
            if status is None:
                time.sleep(0.01)
                continue
            if status.si_pid != process.pid:
                raise ProcessContainmentError(
                    "candidate-tree launch gate returned an invalid process identity"
                )
            if status.si_code == os.CLD_STOPPED and status.si_status == signal.SIGSTOP:
                break
            if status.si_code in {os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED}:
                raise ProcessContainmentError(
                    "candidate-tree launch gate exited before containment armed"
                )
            raise ProcessContainmentError(
                "candidate-tree launch gate entered an invalid state"
            )
        else:
            raise ProcessContainmentError(
                "candidate-tree launch gate did not stop before its timeout"
            )
        identity = _linux_process_identity(process.pid)
        if (
            identity is None
            or identity.parent_pid != os.getpid()
            or identity.process_group != process.pid
            or identity.session != process.pid
        ):
            raise ProcessContainmentError(
                "candidate-tree launch gate has an invalid process identity"
            )
        root = _open_linux_process_handle(
            process.pid,
            required_parent=os.getpid(),
        )
        if root is None:
            raise ProcessContainmentError(
                "candidate-tree launch gate disappeared while containment armed"
            )
        self._root = root
        self._require_transaction_integrity()
        try:
            signal.pidfd_send_signal(root.pidfd, signal.SIGCONT)
        except OSError as error:
            raise ProcessContainmentError(
                "cannot resume the armed candidate-tree launch gate"
            ) from error
        self._require_transaction_integrity()

    def root_exited(self, process: subprocess.Popen[bytes]) -> bool:
        """Return true when the stable candidate root has exited."""

        integrity_error = self._observe_transaction_integrity()
        if process.returncode is not None:
            error = ProcessContainmentError(
                "candidate root wait status was consumed outside containment"
            )
            integrity_error = self._record_integrity_error(
                error,
                anchor_lost=True,
            )
        if self._root is None:
            raise ProcessContainmentError(
                "candidate-tree containment did not arm its root process"
            )
        try:
            exited = _pidfd_is_exited(self._root.pidfd)
        except ProcessContainmentError as error:
            if integrity_error is not None:
                raise integrity_error from error
            raise
        if exited:
            try:
                observed = _observe_nonreaping_exit(
                    process.pid,
                    context="candidate command root",
                )
                if observed is None:
                    raise ProcessContainmentError(
                        "candidate command root has no terminal wait status"
                    )
                if (
                    self._root_exit_status is not None
                    and observed != self._root_exit_status
                ):
                    raise ProcessContainmentError(
                        "candidate command root exit status changed during containment"
                    )
                self._root_exit_status = observed
            except ProcessContainmentError as error:
                integrity_error = self._record_integrity_error(
                    error,
                    anchor_lost=True,
                )
        final_integrity_error = self._observe_transaction_integrity()
        if integrity_error is None:
            integrity_error = final_integrity_error
        if integrity_error is not None:
            raise integrity_error
        return exited

    def _refresh_adopted(self, root_pid: int) -> None:
        for pid, handle in tuple(self._adopted.items()):
            if not _pidfd_is_exited(handle.pidfd):
                continue
            try:
                observed = _observe_nonreaping_exit(
                    pid,
                    context=f"adopted Linux process {pid}",
                )
                if observed is None:
                    raise ProcessContainmentError(
                        f"adopted Linux process {pid} has no terminal wait status"
                    )
                _reap_exact_pid(
                    pid,
                    observed,
                    context=f"adopted Linux process {pid}",
                )
            except ProcessContainmentError as error:
                recorded = self._record_integrity_error(
                    error,
                    anchor_lost=False,
                )
                if recorded is error:
                    raise
                raise recorded from error
            del self._adopted[pid]
            handle.close()
        for pid in _linux_direct_children():
            if pid == root_pid or pid in self._adopted:
                continue
            handle = _open_linux_process_handle(
                pid,
                required_parent=os.getpid(),
            )
            if handle is not None:
                self._adopted[pid] = handle

    @staticmethod
    def _signal_handle(
        handle: _LinuxProcessHandle,
        signal_number: int,
    ) -> OSError | None:
        try:
            signal.pidfd_send_signal(handle.pidfd, signal_number)
        except ProcessLookupError:
            return None
        except OSError as error:
            return error
        return None

    def _state(
        self,
        process: subprocess.Popen[bytes],
    ) -> tuple[bool, set[int], bool]:
        state_error = self._observe_transaction_integrity()
        root_exited = False
        try:
            root_exited = self.root_exited(process)
        except ProcessContainmentError as error:
            if state_error is None:
                state_error = error
            elif state_error is not error and hasattr(state_error, "add_note"):
                state_error.add_note(
                    "candidate root-state inspection also failed: "
                    f"{type(error).__name__}: {error}"
                )
        before_adopted_error = self._observe_transaction_integrity()
        if state_error is None:
            state_error = before_adopted_error
        try:
            self._refresh_adopted(process.pid)
        except ProcessContainmentError as error:
            if state_error is None:
                state_error = error
            elif state_error is not error and hasattr(state_error, "add_note"):
                state_error.add_note(
                    "candidate adopted-child inventory also failed: "
                    f"{type(error).__name__}: {error}"
                )
        before_group_error = self._observe_transaction_integrity()
        if state_error is None:
            state_error = before_group_error
        members: set[int] = set()
        if self._group_anchor_safe:
            try:
                members = process_group_members(process.pid)
                members.discard(process.pid)
            except ProcessContainmentError as error:
                if state_error is None:
                    state_error = error
                elif state_error is not error and hasattr(state_error, "add_note"):
                    state_error.add_note(
                        "candidate process-group inventory also failed: "
                        f"{type(error).__name__}: {error}"
                    )
        final_integrity_error = self._observe_transaction_integrity()
        if state_error is None:
            state_error = final_integrity_error
        if state_error is not None:
            raise state_error
        return root_exited, members, bool(self._adopted)

    def _signal_stable_targets(
        self,
        process: subprocess.Popen[bytes],
        signal_number: int,
    ) -> OSError | None:
        """Signal only identities that remain anchored by the unreaped root or pidfds."""

        last_error: OSError | None = None
        self._observe_transaction_integrity()
        if self._group_anchor_safe:
            error = _signal_process_group(process, signal_number)
            if error is not None:
                last_error = error
        if self._root is not None:
            error = self._signal_handle(self._root, signal_number)
            if error is not None:
                last_error = error
        for handle in tuple(self._adopted.values()):
            error = self._signal_handle(handle, signal_number)
            if error is not None:
                last_error = error
        self._observe_transaction_integrity()
        return last_error

    def _stop_stage(
        self,
        process: subprocess.Popen[bytes],
        signal_number: int,
        inventory_error: ProcessContainmentError | None = None,
    ) -> tuple[bool, OSError | None, ProcessContainmentError | None]:
        timeout_seconds = (
            min(PROCESS_TERM_GRACE_SECONDS, self.stop_timeout_seconds)
            if signal_number == signal.SIGTERM
            else self.stop_timeout_seconds
        )
        deadline = time.monotonic() + timeout_seconds
        last_error: OSError | None = None
        signaled = False
        while True:
            stopped = False
            try:
                root_exited, members, adopted = self._state(process)
                stopped = root_exited and not members and not adopted
            except ProcessContainmentError as error:
                if inventory_error is None:
                    inventory_error = error
                elif inventory_error is not error and hasattr(
                    inventory_error,
                    "add_note",
                ):
                    inventory_error.add_note(
                        "candidate process inventory also failed: "
                        f"{type(error).__name__}: {error}"
                    )
            if stopped and (inventory_error is None or signaled):
                return True, last_error, inventory_error
            error = self._signal_stable_targets(process, signal_number)
            if error is not None:
                last_error = error
            if inventory_error is None and self._integrity_error is not None:
                inventory_error = self._integrity_error
            signaled = True
            if stopped:
                return True, last_error, inventory_error
            if time.monotonic() >= deadline:
                return False, last_error, inventory_error
            time.sleep(PROCESS_POLL_INTERVAL_SECONDS)

    @staticmethod
    def _raise_inventory_failure(
        inventory_error: ProcessContainmentError,
        signal_error: OSError | None,
    ) -> None:
        error = ProcessContainmentError(
            "candidate command process inventory could not be verified"
        )
        if signal_error is not None and hasattr(error, "add_note"):
            error.add_note(
                "candidate termination signal also failed: "
                f"{type(signal_error).__name__}: {signal_error}"
            )
        raise error from inventory_error

    def _active_controls_restored_for_cleanup(self) -> bool:
        """Return true when cleanup can use the active transaction controls."""

        for _attempt in range(2):
            self._observe_transaction_integrity()
            if not self._group_anchor_safe:
                return False
            try:
                child_disposition = signal.getsignal(signal.SIGCHLD)
                child_subreaper = _prctl_get_child_subreaper()
            except (OSError, ValueError, ProcessContainmentError):
                continue
            if child_disposition == signal.SIG_DFL and child_subreaper:
                return True
        return False

    def _reap_root_after_integrity_failure(
        self,
        process: subprocess.Popen[bytes],
    ) -> None:
        """Reap one stable root after bounded cleanup without verifying the run."""

        integrity_error = self._integrity_error
        root = self._root
        if integrity_error is None or root is None:
            return
        if not self._active_controls_restored_for_cleanup():
            return
        try:
            if not _pidfd_is_exited(root.pidfd):
                return
            observed = _observe_nonreaping_exit(
                process.pid,
                context="candidate command root cleanup",
            )
            if observed is None:
                return
            if (
                self._root_exit_status is not None
                and observed != self._root_exit_status
            ):
                raise ProcessContainmentError(
                    "candidate command root exit status changed before cleanup"
                )
            self._root_exit_status = observed

            if not self._active_controls_restored_for_cleanup():
                return
            self._refresh_adopted(process.pid)
            if self._adopted:
                return

            if not self._active_controls_restored_for_cleanup():
                return
            members = process_group_members(process.pid)
            members.discard(process.pid)
            if members:
                return

            if not self._active_controls_restored_for_cleanup():
                return
            remaining = _linux_direct_children()
            remaining.discard(process.pid)
            if remaining:
                return

            if not self._active_controls_restored_for_cleanup():
                return
            _reap_exact_process_root(
                process,
                expected=self._root_exit_status,
                context="candidate command root cleanup",
            )
        except ProcessContainmentError as cleanup_error:
            self._record_integrity_cleanup_error(
                integrity_error,
                context="candidate-tree integrity-failure root",
                cleanup_error=cleanup_error,
            )
            return
        self._group_anchor_safe = False
        self._cleanup_complete = True

    def finalize(
        self,
        process: subprocess.Popen[bytes],
        *,
        force_stop: bool,
    ) -> ProcessFinalization:
        """Stop every candidate descendant, reap root last, and verify extinction."""

        if self._root is None:
            integrity_error = self._observe_transaction_integrity()
            if integrity_error is not None and not self._group_anchor_safe:
                raise integrity_error
            result = finalize_process_group(
                process,
                force_stop=True,
                stop_timeout_seconds=self.stop_timeout_seconds,
            )
            if _linux_direct_children():
                raise ProcessContainmentError(
                    "candidate-tree launch failure left a child process"
                )
            self._require_transaction_integrity()
            self._verified = True
            return result

        inventory_error: ProcessContainmentError | None = None
        try:
            initial_root_exited, initial_members, initial_adopted = self._state(process)
            survivor_detected = initial_root_exited and (
                bool(initial_members) or initial_adopted
            )
            stopped = (
                initial_root_exited and not initial_members and not initial_adopted
            )
        except ProcessContainmentError as error:
            inventory_error = error
            survivor_detected = False
            stopped = False
        signal_error: OSError | None = None
        if force_stop or not stopped or inventory_error is not None:
            stopped, signal_error, inventory_error = self._stop_stage(
                process,
                signal.SIGTERM,
                inventory_error,
            )
        if not stopped or inventory_error is not None:
            stopped, kill_error, inventory_error = self._stop_stage(
                process,
                signal.SIGKILL,
                inventory_error,
            )
            if kill_error is not None:
                signal_error = kill_error
        if inventory_error is not None:
            self._reap_root_after_integrity_failure(process)
            self._raise_inventory_failure(inventory_error, signal_error)
        if not stopped:
            error = ProcessContainmentError(
                "candidate command did not terminate within its stop bound"
            )
            if signal_error is not None:
                raise error from signal_error
            raise error
        self._require_transaction_integrity()
        try:
            remaining = _linux_direct_children()
        except ProcessContainmentError as error:
            _stopped, signal_error, inventory_error = self._stop_stage(
                process,
                signal.SIGTERM,
                error,
            )
            _stopped, kill_error, inventory_error = self._stop_stage(
                process,
                signal.SIGKILL,
                inventory_error,
            )
            if kill_error is not None:
                signal_error = kill_error
            if inventory_error is None:
                raise ProcessContainmentError(
                    "candidate command process inventory failure was lost"
                )
            self._raise_inventory_failure(inventory_error, signal_error)
        self._require_transaction_integrity()
        remaining.discard(process.pid)
        if remaining:
            inventory_error = ProcessContainmentError(
                "candidate command child inventory changed before root reaping"
            )
            _stopped, signal_error, inventory_error = self._stop_stage(
                process,
                signal.SIGTERM,
                inventory_error,
            )
            _stopped, kill_error, inventory_error = self._stop_stage(
                process,
                signal.SIGKILL,
                inventory_error,
            )
            if kill_error is not None:
                signal_error = kill_error
            if inventory_error is None:
                raise ProcessContainmentError(
                    "candidate command process inventory failure was lost"
                )
            self._raise_inventory_failure(inventory_error, signal_error)
        self._require_transaction_integrity()
        if self._root_exit_status is None:
            error = ProcessContainmentError(
                "candidate command root exit status was not retained"
            )
            raise self._record_integrity_error(
                error,
                anchor_lost=True,
            )
        try:
            returncode = _reap_exact_process_root(
                process,
                expected=self._root_exit_status,
                context="candidate command root",
            )
        except ProcessContainmentError as error:
            recorded = self._record_integrity_error(
                error,
                anchor_lost=True,
            )
            if recorded is error:
                raise
            raise recorded from error
        self._group_anchor_safe = False
        self._require_transaction_integrity()
        self._verified = True
        return ProcessFinalization(returncode, survivor_detected)

    def close(self, *, process_started: bool) -> None:
        """Restore subreaper state only after bounded process cleanup completes."""

        global _SUBREAPER_POISONED
        cleanup_errors: list[BaseException] = []
        if self._active:
            integrity_error = self._observe_transaction_integrity()
            if integrity_error is not None:
                cleanup_errors.append(integrity_error)
        for handle in tuple(self._adopted.values()):
            try:
                handle.close()
            except BaseException as error:
                cleanup_errors.append(error)
        self._adopted.clear()
        if self._root is not None:
            try:
                self._root.close()
            except BaseException as error:
                cleanup_errors.append(error)
            self._root = None
        if self._active:
            try:
                if process_started and not (self._verified or self._cleanup_complete):
                    cleanup_errors.append(
                        ProcessContainmentError(
                            "candidate-tree process extinction was not verified"
                        )
                    )
                    _SUBREAPER_POISONED = True
                else:
                    try:
                        current = _prctl_get_child_subreaper()
                        if current != self._previous_subreaper:
                            _prctl_set_child_subreaper(self._previous_subreaper)
                        if _prctl_get_child_subreaper() != self._previous_subreaper:
                            raise ProcessContainmentError(
                                "candidate-tree containment did not restore "
                                "subreaper state"
                            )
                    except BaseException as error:
                        cleanup_errors.append(error)
                        _SUBREAPER_POISONED = True
            finally:
                self._active = False
                _SUBREAPER_LOCK.release()
        if cleanup_errors:
            _SUBREAPER_POISONED = True
            error = ProcessContainmentError("candidate-tree containment cleanup failed")
            for cleanup_error in cleanup_errors[1:]:
                _add_cleanup_note(
                    error,
                    context="candidate-tree containment",
                    cleanup_error=cleanup_error,
                )
            raise error from cleanup_errors[0]
