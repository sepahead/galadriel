"""Regression tests for bounded release-tool host processes."""

from __future__ import annotations

import ast
import ctypes
import errno
import io
import os
import resource
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


TOOLS = Path(__file__).resolve().parents[1]
REPOSITORY = TOOLS.parent
sys.path.insert(0, str(TOOLS))

import check_public_api  # noqa: E402
import common as common_helpers  # noqa: E402
import process_containment  # noqa: E402
import reproduce_baseline  # noqa: E402
import run_broad_mutation  # noqa: E402
from common import (  # noqa: E402
    CANDIDATE_TREE_CONTAINMENT,
    ReviewError,
    run_bounded_host_command,
)
from release_assurance import BoundedHostResult  # noqa: E402


ASSIGNED_HOST_PROCESS_SCRIPTS = (
    "check_public_api.py",
    "check_vulnerable_features.py",
    "check_focused_mutation.py",
    "freeze_audit_inputs.py",
    "check_feature_graph.py",
    "reproduce_baseline.py",
    "run_broad_mutation.py",
)
REQUIRED_RUNNER_KEYWORDS = frozenset(
    {
        "context",
        "environment",
        "max_stdout_bytes",
        "max_stderr_bytes",
        "timeout_seconds",
    }
)
MUTATION_RUNNER_SCRIPTS = frozenset(
    {"check_focused_mutation.py", "run_broad_mutation.py"}
)


class HostProcessBoundTests(unittest.TestCase):
    """Keep each release-tool process behind the shared bounded runner."""

    def run_isolated_linux_harness(
        self, source: str
    ) -> subprocess.CompletedProcess[bytes]:
        """Run one containment failure in a disposable Linux process."""

        return subprocess.run(
            [sys.executable, "-B", "-I", "-c", source, str(TOOLS)],
            cwd=REPOSITORY,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
            start_new_session=True,
        )

    def test_isolated_linux_harness_disables_import_caches(self) -> None:
        completed = subprocess.CompletedProcess([], 0, b"", b"")
        with mock.patch.object(subprocess, "run", return_value=completed) as runner:
            self.assertIs(self.run_isolated_linux_harness("pass"), completed)
        self.assertEqual(
            runner.call_args.args[0][:4],
            [sys.executable, "-B", "-I", "-c"],
        )

    def test_assigned_scripts_have_no_direct_subprocess_invocation(self) -> None:
        for name in ASSIGNED_HOST_PROCESS_SCRIPTS:
            with self.subTest(name=name):
                tree = ast.parse((TOOLS / name).read_text(encoding="utf-8"))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        self.assertNotIn(
                            "subprocess",
                            {alias.name for alias in node.names},
                            name,
                        )
                    if isinstance(node, ast.ImportFrom):
                        self.assertNotEqual(node.module, "subprocess", name)
                    if (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name)
                    ):
                        self.assertNotEqual(node.func.value.id, "subprocess", name)

    def test_critical_host_tools_ignore_a_leading_path_shim(self) -> None:
        commands = (
            ("git", "--version"),
            ("ssh-keygen", "-?"),
            ("ssh-add", "-L"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "invoked"
            for name, argument in commands:
                shim = root / name
                shim.write_text(
                    f"#!/bin/sh\nprintf invoked > {marker}\nexit 0\n",
                    encoding="utf-8",
                )
                shim.chmod(0o700)
                result = run_bounded_host_command(
                    [name, argument],
                    context=f"trusted {name} shim fixture",
                    environment={"PATH": str(root)},
                    max_stdout_bytes=64 * 1024,
                    max_stderr_bytes=64 * 1024,
                    timeout_seconds=5,
                )
                self.assertIsInstance(result.returncode, int)
                self.assertFalse(marker.exists())
                shim.unlink()

    def test_unapproved_absolute_critical_tool_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_git = Path(directory) / "git"
            fake_git.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_git.chmod(0o700)
            with self.assertRaisesRegex(ReviewError, "unapproved git executable"):
                run_bounded_host_command(
                    [str(fake_git), "--version"],
                    context="unapproved Git fixture",
                    max_stdout_bytes=64,
                    max_stderr_bytes=64,
                    timeout_seconds=3,
                )

    def test_trusted_executable_postcheck_runs_after_command_failure(self) -> None:
        with (
            mock.patch.object(
                common_helpers,
                "_verify_trusted_executables",
                side_effect=ReviewError("trusted executable drift fixture"),
            ),
            self.assertRaisesRegex(ReviewError, "trusted executable drift fixture"),
        ):
            run_bounded_host_command(
                ["git", "--definitely-invalid-option"],
                context="trusted executable postcheck fixture",
                max_stdout_bytes=64 * 1024,
                max_stderr_bytes=64 * 1024,
                timeout_seconds=5,
            )

    def test_sanitized_environment_removes_loader_and_toolchain_selectors(self) -> None:
        cleaned = common_helpers.sanitized_host_environment(
            {
                "PATH": "/usr/bin",
                "DYLD_INSERT_LIBRARIES": "/tmp/injected.dylib",
                "LD_PRELOAD": "/tmp/injected.so",
                "DEVELOPER_DIR": "/tmp/developer",
                "TOOLCHAINS": "untrusted",
            }
        )
        self.assertEqual(cleaned, {"PATH": "/usr/bin"})

    def test_each_bounded_runner_call_declares_limits_and_environment(self) -> None:
        observed = 0
        for name in ASSIGNED_HOST_PROCESS_SCRIPTS:
            tree = ast.parse((TOOLS / name).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "run_bounded_host_command"
                ):
                    continue
                observed += 1
                keywords = {
                    keyword.arg for keyword in node.keywords if keyword.arg is not None
                }
                self.assertTrue(
                    REQUIRED_RUNNER_KEYWORDS <= keywords,
                    f"{name}:{node.lineno} lacks an explicit process bound",
                )
                if name in MUTATION_RUNNER_SCRIPTS:
                    self.assertIn(
                        "containment",
                        keywords,
                        f"{name}:{node.lineno} lacks candidate-tree containment",
                    )
        self.assertGreaterEqual(observed, 10)

    def test_release_tool_environment_removes_secret_selectors(self) -> None:
        source = {
            "PATH": "/fixture/bin",
            "HOME": "/fixture/home",
            "CARGO_HOME": "/fixture/cargo",
            "ANTHROPIC_API_KEY": "fixture-secret",
            "HTTPS_PROXY": "https://credential@example.invalid",
            "GIT_ASKPASS": "/fixture/askpass",
            "SSH_AUTH_SOCK": "/fixture/agent",
        }
        environment = check_public_api.release_tool_environment(source)
        self.assertEqual(environment["PATH"], source["PATH"])
        self.assertEqual(environment["CARGO_HOME"], source["CARGO_HOME"])
        self.assertEqual(environment["CARGO_TERM_COLOR"], "never")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertNotIn("ANTHROPIC_API_KEY", environment)
        self.assertNotIn("HTTPS_PROXY", environment)
        self.assertNotIn("GIT_ASKPASS", environment)
        self.assertNotIn("SSH_AUTH_SOCK", environment)
        self.assertNotIn("fixture-secret", environment.values())

    def test_public_api_capture_supplies_fixed_bounds(self) -> None:
        command = ["fixture-tool", "fixture-sensitive-argument"]
        with mock.patch.object(
            check_public_api,
            "run_bounded_host_command",
            return_value=BoundedHostResult(0, b"fixture output\n", b""),
        ) as runner:
            self.assertEqual(
                check_public_api.capture(command, repo=REPOSITORY),
                b"fixture output\n",
            )
        runner.assert_called_once()
        arguments = runner.call_args
        self.assertEqual(arguments.args[0], command)
        self.assertEqual(arguments.kwargs["cwd"], REPOSITORY)
        self.assertEqual(
            arguments.kwargs["timeout_seconds"],
            check_public_api.PUBLIC_API_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            arguments.kwargs["max_stdout_bytes"],
            check_public_api.MAX_PUBLIC_API_STDOUT_BYTES,
        )

        with (
            mock.patch.object(
                check_public_api,
                "run_bounded_host_command",
                return_value=BoundedHostResult(9, b"", b"controlled failure"),
            ),
            self.assertRaises(ReviewError) as raised,
        ):
            check_public_api.capture(command, repo=REPOSITORY)
        self.assertNotIn(command[1], str(raised.exception))
        self.assertNotIn("controlled failure", str(raised.exception))
        self.assertIn("stderr sha256=", str(raised.exception))

    def test_mutation_identity_keeps_exact_isolated_environment(self) -> None:
        environment = {
            "HOME": "/fixture/private-home",
            "PATH": "/fixture/bin",
        }
        with mock.patch.object(
            run_broad_mutation,
            "run_bounded_host_command",
            return_value=BoundedHostResult(0, b"fixture 1.0\n", b""),
        ) as runner:
            self.assertEqual(
                run_broad_mutation.exact_output(
                    ["fixture", "--version"],
                    root=REPOSITORY,
                    environment=environment,
                    context="fixture",
                ),
                "fixture 1.0",
            )
        self.assertEqual(runner.call_args.kwargs["environment"], environment)
        self.assertEqual(
            runner.call_args.kwargs["timeout_seconds"],
            run_broad_mutation.IDENTITY_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            runner.call_args.kwargs["containment"],
            CANDIDATE_TREE_CONTAINMENT,
        )

    def test_baseline_log_retains_bounded_combined_output(self) -> None:
        log = io.BytesIO()
        spec = reproduce_baseline.CommandSpec("fixture", ("fixture", "--check"))
        with mock.patch.object(
            reproduce_baseline,
            "run_bounded_host_command",
            return_value=BoundedHostResult(0, b"combined output\n", b""),
        ) as runner:
            record = reproduce_baseline.run_command(
                spec,
                checkout=REPOSITORY,
                base_env={"PATH": "/fixture/bin"},
                log=log,
            )
        self.assertEqual(record["exit_code"], 0)
        self.assertIn(b"[combined_output_begin]\ncombined output\n", log.getvalue())
        self.assertTrue(runner.call_args.kwargs["merge_stderr"])
        self.assertEqual(
            runner.call_args.kwargs["timeout_seconds"],
            reproduce_baseline.BASELINE_COMMAND_TIMEOUT_SECONDS,
        )

    def test_clean_root_returns_after_process_group_extinction(self) -> None:
        result = run_bounded_host_command(
            [sys.executable, "-I", "-c", "print('clean')"],
            context="clean process-group fixture",
            max_stdout_bytes=64,
            max_stderr_bytes=64,
            timeout_seconds=3,
        )
        self.assertEqual(result, BoundedHostResult(0, b"clean\n", b""))

    def test_nonzero_root_status_is_retained(self) -> None:
        result = run_bounded_host_command(
            [sys.executable, "-I", "-c", "raise SystemExit(7)"],
            context="nonzero process-group fixture",
            max_stdout_bytes=64,
            max_stderr_bytes=64,
            timeout_seconds=3,
        )
        self.assertEqual(result, BoundedHostResult(7, b"", b""))

    def test_process_group_gate_preserves_identity_arguments_and_masks(self) -> None:
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        blocked_signal = int(signal.SIGUSR1)
        expected_mask = frozenset(int(value) for value in original_mask) | {
            blocked_signal
        }
        observed_process: subprocess.Popen[bytes] | None = None
        actual_popen = common_helpers.subprocess.Popen
        source = """
import os
import signal
import sys

mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
fields = (
    str(os.getpid()),
    str(os.getpgrp()),
    str(os.getsid(0)),
    ",".join(str(int(value)) for value in sorted(mask)),
    repr(sys.argv[1:]),
)
print("|".join(fields))
"""

        def observe_process(*args: object, **kwargs: object) -> object:
            nonlocal observed_process
            observed_process = actual_popen(*args, **kwargs)
            return observed_process

        signal.pthread_sigmask(signal.SIG_BLOCK, {blocked_signal})
        try:
            with mock.patch.object(
                common_helpers.subprocess,
                "Popen",
                side_effect=observe_process,
            ):
                result = run_bounded_host_command(
                    [sys.executable, "-I", "-c", source, "alpha", ""],
                    context="process-group gate identity fixture",
                    max_stdout_bytes=512,
                    max_stderr_bytes=64,
                    timeout_seconds=3,
                )
            current_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        self.assertIsNotNone(observed_process)
        assert observed_process is not None
        fields = result.stdout.decode("ascii").rstrip("\n").split("|", 4)
        self.assertEqual(
            tuple(int(value) for value in fields[:3]),
            (observed_process.pid, observed_process.pid, observed_process.pid),
        )
        self.assertEqual(
            fields[3],
            ",".join(str(value) for value in sorted(expected_mask)),
        )
        self.assertEqual(fields[4], "['alpha', '']")
        self.assertEqual(
            frozenset(int(value) for value in current_mask),
            expected_mask,
        )

    def test_pending_sigint_after_process_group_spawn_cleans_owned_root(self) -> None:
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        original_handler = signal.getsignal(signal.SIGINT)
        original_poisoned = common_helpers._HOST_LAUNCH_SIGNAL_MASK_POISONED
        interruptible_mask = {
            int(value) for value in original_mask if int(value) != int(signal.SIGINT)
        }
        observed_process: subprocess.Popen[bytes] | None = None
        actual_popen = common_helpers.subprocess.Popen

        def interrupt_after_spawn(*args: object, **kwargs: object) -> object:
            nonlocal observed_process
            observed_process = actual_popen(*args, **kwargs)
            signal.raise_signal(signal.SIGINT)
            return observed_process

        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, interruptible_mask)
            signal.signal(signal.SIGINT, signal.default_int_handler)
            with (
                mock.patch.object(
                    common_helpers.subprocess,
                    "Popen",
                    side_effect=interrupt_after_spawn,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                run_bounded_host_command(
                    [sys.executable, "-I", "-c", "import time; time.sleep(20)"],
                    context="process-group launch interrupt fixture",
                    max_stdout_bytes=64,
                    max_stderr_bytes=64,
                    timeout_seconds=3,
                )
        finally:
            signal.signal(signal.SIGINT, original_handler)
            current_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
            signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)

        self.assertIsNotNone(observed_process)
        assert observed_process is not None
        self.assertIsNotNone(observed_process.returncode)
        with self.assertRaises(ProcessLookupError):
            os.kill(observed_process.pid, 0)
        with self.assertRaises(ProcessLookupError):
            os.killpg(observed_process.pid, 0)
        self.assertEqual(
            frozenset(int(value) for value in current_mask),
            frozenset(interruptible_mask),
        )
        self.assertEqual(
            common_helpers._HOST_LAUNCH_SIGNAL_MASK_POISONED,
            original_poisoned,
        )

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux containment test")
    def test_candidate_nonzero_root_status_is_retained(self) -> None:
        result = run_bounded_host_command(
            [sys.executable, "-I", "-c", "raise SystemExit(7)"],
            context="nonzero candidate-tree fixture",
            max_stdout_bytes=64,
            max_stderr_bytes=64,
            timeout_seconds=3,
            containment=CANDIDATE_TREE_CONTAINMENT,
        )
        self.assertEqual(result, BoundedHostResult(7, b"", b""))

    @unittest.skipUnless(sys.platform == "darwin", "Darwin waitid test")
    def test_darwin_waitid_status_bits_match_waitpid_exit_code(self) -> None:
        result = run_bounded_host_command(
            [sys.executable, "-I", "-c", "import os; os._exit(-1)"],
            context="Darwin waitid status fixture",
            max_stdout_bytes=64,
            max_stderr_bytes=64,
            timeout_seconds=3,
        )
        self.assertEqual(result, BoundedHostResult(255, b"", b""))

    def test_group_finalization_reaps_root_after_member_extinction(self) -> None:
        process = mock.Mock()
        process.pid = 84
        process.returncode = None
        events: list[str] = []

        def group_members(_process_group: int) -> set[int]:
            events.append("inventory")
            self.assertNotIn("reap", events)
            return {84, 85} if events.count("inventory") == 1 else {84}

        def reap(
            observed_process: subprocess.Popen[bytes],
            *,
            context: str,
        ) -> int:
            self.assertIs(observed_process, process)
            self.assertEqual(context, "host command root")
            events.append("reap")
            return 0

        with (
            mock.patch.object(
                process_containment,
                "root_process_exited",
                return_value=True,
            ),
            mock.patch.object(
                process_containment,
                "process_group_members",
                side_effect=group_members,
            ),
            mock.patch.object(
                process_containment,
                "_signal_process_group",
                return_value=None,
            ),
            mock.patch.object(
                process_containment,
                "_verify_group_extinction",
                side_effect=lambda *_arguments: events.append("verify"),
            ),
            mock.patch.object(
                process_containment,
                "_reap_exact_process_root",
                side_effect=reap,
            ),
        ):
            result = process_containment.finalize_process_group(
                process,
                force_stop=False,
                stop_timeout_seconds=3,
            )
        self.assertEqual(result, process_containment.ProcessFinalization(0, True))
        self.assertEqual(events, ["inventory", "inventory", "reap", "verify"])
        process.wait.assert_not_called()

    def test_process_group_scope_excludes_detached_sessions(self) -> None:
        self.assertEqual(
            process_containment.PROCESS_GROUP_CONTAINMENT_SCOPE,
            frozenset({"root-process", "original-process-group"}),
        )
        runner_contract = common_helpers.run_bounded_host_command.__doc__ or ""
        self.assertIn("does not track a descendant", runner_contract)

    def test_launch_gate_early_exit_observation_does_not_reap_root(self) -> None:
        tracker = process_containment.LinuxCandidateTreeContainment(
            context="early exit fixture",
            stop_timeout_seconds=3,
        )
        process = mock.Mock()
        process.pid = 88
        process.returncode = None
        status = mock.Mock(
            si_pid=process.pid,
            si_code=os.CLD_EXITED,
            si_status=7,
        )
        with (
            mock.patch.object(
                process_containment.os,
                "waitid",
                side_effect=(None, status),
            ) as waitid,
            mock.patch.object(process_containment.os, "waitpid") as waitpid,
            mock.patch.object(
                process_containment.time,
                "monotonic",
                return_value=0.0,
            ),
            mock.patch.object(process_containment.time, "sleep") as sleep,
            self.assertRaisesRegex(
                process_containment.ProcessContainmentError,
                "exited before containment armed",
            ),
        ):
            tracker.arm(process)
        waitpid.assert_not_called()
        self.assertEqual(
            waitid.call_args_list,
            [
                mock.call(
                    os.P_PID,
                    process.pid,
                    os.WEXITED | os.WSTOPPED | os.WNOHANG | os.WNOWAIT,
                ),
                mock.call(
                    os.P_PID,
                    process.pid,
                    os.WEXITED | os.WSTOPPED | os.WNOHANG | os.WNOWAIT,
                ),
            ],
        )
        sleep.assert_called_once_with(0.01)
        self.assertIsNone(process.returncode)

    def test_inventory_failure_still_signals_anchored_candidate_targets(self) -> None:
        tracker = process_containment.LinuxCandidateTreeContainment(
            context="inventory failure fixture",
            stop_timeout_seconds=0.01,
        )
        root_identity = process_containment.LinuxProcessIdentity(
            pid=84,
            state="S",
            parent_pid=os.getpid(),
            process_group=84,
            session=84,
            start_time=10,
        )
        adopted_identity = process_containment.LinuxProcessIdentity(
            pid=85,
            state="S",
            parent_pid=os.getpid(),
            process_group=85,
            session=85,
            start_time=11,
        )
        tracker._root = process_containment._LinuxProcessHandle(root_identity, 101)
        tracker._adopted[85] = process_containment._LinuxProcessHandle(
            adopted_identity,
            102,
        )
        process = mock.Mock()
        process.pid = root_identity.pid
        process.returncode = None
        inventory_error = process_containment.ProcessContainmentError(
            "injected process inventory failure"
        )
        with (
            mock.patch.object(
                tracker,
                "_state",
                side_effect=inventory_error,
            ),
            mock.patch.object(
                process_containment,
                "_signal_process_group",
                return_value=None,
            ) as signal_group,
            mock.patch.object(
                process_containment.signal,
                "pidfd_send_signal",
                create=True,
            ) as signal_pidfd,
            mock.patch.object(
                process_containment.time,
                "monotonic",
                side_effect=(0.0, 1.0, 2.0, 3.0),
            ),
            mock.patch.object(process_containment.time, "sleep"),
            self.assertRaisesRegex(
                process_containment.ProcessContainmentError,
                "inventory could not be verified",
            ) as raised,
        ):
            tracker.finalize(process, force_stop=False)
        self.assertIs(raised.exception.__cause__, inventory_error)
        self.assertEqual(
            signal_group.call_args_list,
            [
                mock.call(process, signal.SIGTERM),
                mock.call(process, signal.SIGKILL),
            ],
        )
        self.assertEqual(
            signal_pidfd.call_args_list,
            [
                mock.call(101, signal.SIGTERM),
                mock.call(102, signal.SIGTERM),
                mock.call(101, signal.SIGKILL),
                mock.call(102, signal.SIGKILL),
            ],
        )
        process.wait.assert_not_called()
        self.assertFalse(tracker._verified)
        tracker._root = None
        tracker._adopted.clear()

    def test_successful_root_with_same_group_survivor_fails_closed(self) -> None:
        child_source = """
import os
import signal
import time

signal.signal(signal.SIGTERM, signal.SIG_IGN)
for descriptor in (0, 1, 2):
    try:
        os.close(descriptor)
    except OSError:
        pass
time.sleep(20)
"""
        with tempfile.TemporaryDirectory() as directory:
            identity_path = Path(directory) / "identity"
            root_source = f"""
import os
import pathlib
import subprocess
import sys

child = subprocess.Popen([sys.executable, "-I", "-c", {child_source!r}])
pathlib.Path({str(identity_path)!r}).write_text(
    f"{{os.getpid()}} {{child.pid}}",
    encoding="ascii",
)
"""
            with self.assertRaisesRegex(
                ReviewError,
                "left a process after its root exited",
            ):
                run_bounded_host_command(
                    [sys.executable, "-I", "-c", root_source],
                    context="same-group survivor fixture",
                    max_stdout_bytes=64,
                    max_stderr_bytes=64,
                    timeout_seconds=5,
                )
            root_pid, child_pid = (
                int(value)
                for value in identity_path.read_text(encoding="ascii").split()
            )
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
            with self.assertRaises(ProcessLookupError):
                os.killpg(root_pid, 0)

    def test_root_exit_stops_child_that_holds_output_streams(self) -> None:
        child_source = """
import signal
import time

signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(20)
"""
        root_source = f"""
import subprocess
import sys

subprocess.Popen([sys.executable, "-I", "-c", {child_source!r}])
"""
        started = time.monotonic()
        with self.assertRaisesRegex(
            ReviewError,
            "left a process after its root exited",
        ):
            run_bounded_host_command(
                [sys.executable, "-I", "-c", root_source],
                context="open-stream survivor fixture",
                max_stdout_bytes=64,
                max_stderr_bytes=64,
                timeout_seconds=10,
            )
        self.assertLess(time.monotonic() - started, 5)

    def test_subreaper_control_uses_exact_prctl_arguments(self) -> None:
        get_call = mock.Mock()

        def get_state(*arguments: object) -> int:
            get_call(*arguments)
            state = ctypes.cast(
                arguments[1],
                ctypes.POINTER(ctypes.c_int),
            )
            state.contents.value = 1
            return 0

        get_prctl = mock.Mock(side_effect=get_state)
        get_library = mock.Mock()
        get_library.prctl = get_prctl
        with mock.patch.object(
            process_containment.ctypes,
            "CDLL",
            return_value=get_library,
        ) as load_library:
            self.assertTrue(process_containment._prctl_get_child_subreaper())
        load_library.assert_called_once_with(None, use_errno=True)
        self.assertIs(get_prctl.restype, ctypes.c_int)
        self.assertEqual(get_call.call_count, 1)
        get_arguments = get_call.call_args.args
        self.assertEqual(len(get_arguments), 5)
        self.assertEqual(
            get_arguments[0],
            process_containment.PR_GET_CHILD_SUBREAPER,
        )
        self.assertEqual(get_arguments[2:], (0, 0, 0))

        set_prctl = mock.Mock(return_value=0)
        set_library = mock.Mock()
        set_library.prctl = set_prctl
        with mock.patch.object(
            process_containment.ctypes,
            "CDLL",
            return_value=set_library,
        ):
            process_containment._prctl_set_child_subreaper(True)
        self.assertIs(set_prctl.restype, ctypes.c_int)
        set_prctl.assert_called_once_with(
            process_containment.PR_SET_CHILD_SUBREAPER,
            1,
            0,
            0,
            0,
        )

    def test_unarmed_candidate_root_uses_group_fallback(self) -> None:
        tracker = process_containment.LinuxCandidateTreeContainment(
            context="unarmed fixture",
            stop_timeout_seconds=3,
        )
        process = mock.Mock()
        expected = process_containment.ProcessFinalization(-9, False)
        with (
            mock.patch.object(
                process_containment,
                "finalize_process_group",
                return_value=expected,
            ) as finalize,
            mock.patch.object(
                process_containment,
                "_linux_direct_children",
                return_value=set(),
            ),
        ):
            self.assertEqual(tracker.finalize(process, force_stop=False), expected)
        finalize.assert_called_once_with(
            process,
            force_stop=True,
            stop_timeout_seconds=3,
        )
        self.assertTrue(tracker._verified)

    def test_candidate_launch_gate_executes_the_wrapped_command(self) -> None:
        tracker = process_containment.LinuxCandidateTreeContainment(
            context="launch argument fixture",
            stop_timeout_seconds=3,
        )
        wrapped = tracker.launch_arguments(
            ["/fixture/tool", "--check"],
            inherited_signal_mask=(int(signal.SIGUSR2), int(signal.SIGUSR1)),
        )
        self.assertEqual(wrapped[4], "candidate-tree-launch-gate")
        self.assertEqual(
            wrapped[5],
            ",".join(
                str(value)
                for value in sorted((int(signal.SIGUSR1), int(signal.SIGUSR2)))
            ),
        )
        self.assertEqual(wrapped[6:], ["/fixture/tool", "--check"])
        self.assertIn("pthread_sigmask(signal.SIG_SETMASK,mask)", wrapped[3])
        self.assertIn("sys.argv[3]", wrapped[3])
        self.assertNotIn("os.execvpe(sys.argv[1]", wrapped[3])

    def test_process_group_launch_gate_executes_exact_arguments(self) -> None:
        wrapped = process_containment.process_group_launch_arguments(
            ["/fixture/tool", "--check"],
            inherited_signal_mask=(int(signal.SIGUSR2), int(signal.SIGUSR1)),
        )
        self.assertEqual(wrapped[4], "process-group-launch-gate")
        self.assertEqual(
            wrapped[5],
            ",".join(
                str(value)
                for value in sorted((int(signal.SIGUSR1), int(signal.SIGUSR2)))
            ),
        )
        self.assertEqual(wrapped[6:], ["/fixture/tool", "--check"])
        self.assertIn("pthread_sigmask(signal.SIG_SETMASK,mask)", wrapped[3])
        self.assertNotIn("SIGSTOP", wrapped[3])
        self.assertIn("sys.argv[3]", wrapped[3])

    def test_candidate_launch_gate_rejects_invalid_signal_masks(self) -> None:
        tracker = process_containment.LinuxCandidateTreeContainment(
            context="launch signal-mask fixture",
            stop_timeout_seconds=3,
        )
        invalid_masks = (
            None,
            "2",
            (True,),
            ([int(signal.SIGINT)],),
            (int(signal.SIGINT), int(signal.SIGINT)),
            (-1,),
            (int(signal.SIGKILL),),
            (int(signal.SIGSTOP),),
        )
        for inherited_signal_mask in invalid_masks:
            with (
                self.subTest(inherited_signal_mask=inherited_signal_mask),
                self.assertRaisesRegex(
                    process_containment.ProcessContainmentError,
                    "signal mask is invalid",
                ),
            ):
                tracker.launch_arguments(
                    ["/fixture/tool", "--check"],
                    inherited_signal_mask=inherited_signal_mask,
                )

    def test_pending_launch_exception_cleans_owned_process_before_arm(self) -> None:
        tracker = mock.Mock()
        tracker.launch_arguments.return_value = ["/fixture/launch-gate"]
        launch_mask = mock.Mock()
        launch_mask.previous_mask = frozenset()
        launch_mask.restored = True
        process = mock.Mock()
        process.stdout = None
        process.stderr = None
        events: list[str] = []

        def spawn(*_args: object, **_kwargs: object) -> object:
            events.append("spawned")
            return process

        def deliver_pending_signal() -> None:
            events.append("signal-delivered")
            raise KeyboardInterrupt("injected pending signal")

        def clean_owned_process(
            observed_process: object,
            _context: str,
            **_kwargs: object,
        ) -> process_containment.ProcessFinalization:
            self.assertIs(observed_process, process)
            events.append("process-cleaned")
            return process_containment.ProcessFinalization(-9, False)

        launch_mask.restore.side_effect = deliver_pending_signal
        with (
            mock.patch.object(
                common_helpers,
                "LinuxCandidateTreeContainment",
                return_value=tracker,
            ),
            mock.patch.object(
                common_helpers._LaunchSignalMask,
                "capture",
                return_value=launch_mask,
            ),
            mock.patch.object(
                common_helpers.subprocess,
                "Popen",
                side_effect=spawn,
            ),
            mock.patch.object(
                common_helpers,
                "_stop_bounded_host_process",
                side_effect=clean_owned_process,
            ),
            self.assertRaisesRegex(KeyboardInterrupt, "injected pending signal"),
        ):
            run_bounded_host_command(
                ["/fixture/tool"],
                context="pending launch signal fixture",
                max_stdout_bytes=64,
                max_stderr_bytes=64,
                timeout_seconds=3,
                containment=CANDIDATE_TREE_CONTAINMENT,
            )
        self.assertEqual(events, ["spawned", "signal-delivered", "process-cleaned"])
        tracker.arm.assert_not_called()
        tracker.close.assert_called_once_with(process_started=True)

    def test_spawn_failure_precedes_signal_mask_restoration_failure(self) -> None:
        tracker = mock.Mock()
        tracker.launch_arguments.return_value = ["/fixture/launch-gate"]
        launch_mask = mock.Mock()
        launch_mask.previous_mask = frozenset()
        launch_mask.restored = True
        primary = OSError("injected spawn failure")
        restoration = ReviewError("injected mask restoration failure")
        launch_mask.restore.side_effect = restoration
        with (
            mock.patch.object(
                common_helpers,
                "LinuxCandidateTreeContainment",
                return_value=tracker,
            ),
            mock.patch.object(
                common_helpers._LaunchSignalMask,
                "capture",
                return_value=launch_mask,
            ),
            mock.patch.object(
                common_helpers.subprocess,
                "Popen",
                side_effect=primary,
            ),
            self.assertRaisesRegex(
                ReviewError, "cannot run spawn failure fixture"
            ) as raised,
        ):
            run_bounded_host_command(
                ["/fixture/tool"],
                context="spawn failure fixture",
                max_stdout_bytes=64,
                max_stderr_bytes=64,
                timeout_seconds=3,
                containment=CANDIDATE_TREE_CONTAINMENT,
            )
        self.assertIs(raised.exception.__cause__, primary)
        self.assertTrue(
            any(
                "signal-mask restoration also failed" in note
                for note in getattr(primary, "__notes__", ())
            )
        )
        tracker.arm.assert_not_called()
        tracker.close.assert_called_once_with(process_started=False)

    def test_mask_owner_exists_before_block_mutates_process_state(self) -> None:
        tracker = mock.Mock()
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        actual_sigmask = signal.pthread_sigmask
        mutation_observed = False

        def interrupt_after_block(how: int, mask: object) -> object:
            nonlocal mutation_observed
            result = actual_sigmask(how, mask)
            if how == signal.SIG_BLOCK and mask:
                mutation_observed = True
                raise KeyboardInterrupt("injected post-block interruption")
            return result

        try:
            with (
                mock.patch.object(
                    common_helpers,
                    "LinuxCandidateTreeContainment",
                    return_value=tracker,
                ),
                mock.patch.object(
                    common_helpers.signal,
                    "pthread_sigmask",
                    side_effect=interrupt_after_block,
                ),
                mock.patch.object(common_helpers.subprocess, "Popen") as popen,
                self.assertRaisesRegex(
                    KeyboardInterrupt,
                    "injected post-block interruption",
                ),
            ):
                run_bounded_host_command(
                    ["/fixture/tool"],
                    context="post-block interruption fixture",
                    max_stdout_bytes=64,
                    max_stderr_bytes=64,
                    timeout_seconds=3,
                    containment=CANDIDATE_TREE_CONTAINMENT,
                )
            current_mask = actual_sigmask(signal.SIG_BLOCK, ())
        finally:
            actual_sigmask(signal.SIG_SETMASK, original_mask)
        self.assertTrue(mutation_observed)
        self.assertEqual(
            frozenset(int(value) for value in current_mask),
            frozenset(int(value) for value in original_mask),
        )
        popen.assert_not_called()
        tracker.invalidate_launch_signal_mask.assert_not_called()
        tracker.close.assert_not_called()

    def test_unrestored_process_group_mask_poisons_host_launch(self) -> None:
        launch_mask = mock.Mock()
        launch_mask.previous_mask = frozenset()
        launch_mask.restored = False
        primary = KeyboardInterrupt("injected block failure")
        launch_mask.block.side_effect = primary
        launch_mask.restore.side_effect = ReviewError(
            "injected permanent mask restoration failure"
        )
        with mock.patch.object(
            common_helpers,
            "_HOST_LAUNCH_SIGNAL_MASK_POISONED",
            False,
        ):
            with (
                mock.patch.object(
                    common_helpers._LaunchSignalMask,
                    "capture",
                    return_value=launch_mask,
                ),
                mock.patch.object(common_helpers.subprocess, "Popen") as popen,
                self.assertRaisesRegex(
                    KeyboardInterrupt,
                    "injected block failure",
                ),
            ):
                run_bounded_host_command(
                    ["/fixture/tool"],
                    context="process-group mask failure fixture",
                    max_stdout_bytes=64,
                    max_stderr_bytes=64,
                    timeout_seconds=3,
                )
            poisoned = common_helpers._HOST_LAUNCH_SIGNAL_MASK_POISONED
            with self.assertRaisesRegex(
                ReviewError,
                "host launch is unavailable",
            ):
                common_helpers._LaunchSignalMask.capture(
                    context="poisoned process-group fixture"
                )
        self.assertTrue(poisoned)
        popen.assert_not_called()

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux containment test")
    def test_candidate_launch_preserves_parent_and_child_signal_masks(self) -> None:
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        blocked_signal = int(signal.SIGUSR1)
        expected_mask = frozenset(
            {*(int(value) for value in original_mask), blocked_signal}
        )
        signal.pthread_sigmask(signal.SIG_BLOCK, {blocked_signal})
        source = """
import signal

mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
print(",".join(str(int(value)) for value in sorted(mask)))
"""
        try:
            result = run_bounded_host_command(
                [sys.executable, "-I", "-c", source],
                context="candidate launch signal-mask fixture",
                max_stdout_bytes=256,
                max_stderr_bytes=64,
                timeout_seconds=3,
                containment=CANDIDATE_TREE_CONTAINMENT,
            )
            current_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
        expected_output = (
            ",".join(str(value) for value in sorted(expected_mask)) + "\n"
        ).encode("ascii")
        self.assertEqual(result, BoundedHostResult(0, expected_output, b""))
        self.assertEqual(
            frozenset(int(value) for value in current_mask),
            expected_mask,
        )

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux containment test")
    def test_pending_sigint_after_spawn_cleans_owned_candidate(self) -> None:
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        original_handler = signal.getsignal(signal.SIGINT)
        original_subreaper = process_containment._prctl_get_child_subreaper()
        original_poisoned = process_containment._SUBREAPER_POISONED
        interruptible_mask = {
            int(value) for value in original_mask if int(value) != int(signal.SIGINT)
        }
        observed: dict[str, subprocess.Popen[bytes]] = {}
        actual_popen = common_helpers.subprocess.Popen

        def interrupt_after_spawn(*args: object, **kwargs: object) -> object:
            process = actual_popen(*args, **kwargs)
            observed["process"] = process
            signal.raise_signal(signal.SIGINT)
            return process

        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, interruptible_mask)
            signal.signal(signal.SIGINT, signal.default_int_handler)
            with (
                mock.patch.object(
                    common_helpers.subprocess,
                    "Popen",
                    side_effect=interrupt_after_spawn,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                run_bounded_host_command(
                    [sys.executable, "-I", "-c", "import time; time.sleep(20)"],
                    context="candidate launch interrupt fixture",
                    max_stdout_bytes=64,
                    max_stderr_bytes=64,
                    timeout_seconds=3,
                    containment=CANDIDATE_TREE_CONTAINMENT,
                )
        finally:
            signal.signal(signal.SIGINT, original_handler)
            current_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
            signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)

        process = observed["process"]
        self.assertIsNotNone(process.returncode)
        self.assertIsNone(process_containment._linux_process_identity(process.pid))
        self.assertEqual(process_containment._linux_direct_children(), set())
        self.assertEqual(
            frozenset(int(value) for value in current_mask),
            frozenset(interruptible_mask),
        )
        self.assertEqual(
            process_containment._prctl_get_child_subreaper(),
            original_subreaper,
        )
        self.assertEqual(process_containment._SUBREAPER_POISONED, original_poisoned)

    def test_candidate_activation_closes_after_temporary_file_failure(self) -> None:
        tracker = mock.Mock()
        primary = OSError("injected temporary-file failure")
        with (
            mock.patch.object(
                common_helpers,
                "LinuxCandidateTreeContainment",
                return_value=tracker,
            ),
            mock.patch.object(
                common_helpers.tempfile,
                "TemporaryFile",
                side_effect=primary,
            ),
            self.assertRaises(ReviewError) as raised,
        ):
            run_bounded_host_command(
                [sys.executable, "-I", "-c", "raise SystemExit"],
                context="temporary-file failure fixture",
                max_stdout_bytes=64,
                max_stderr_bytes=64,
                timeout_seconds=3,
                containment=CANDIDATE_TREE_CONTAINMENT,
            )
        self.assertIs(raised.exception.__cause__, primary)
        tracker.activate.assert_called_once_with()
        tracker.close.assert_called_once_with(process_started=False)

    def test_candidate_activation_closes_after_selector_failure(self) -> None:
        tracker = mock.Mock()
        stdin_file = mock.Mock()
        primary = OSError("injected selector failure")
        with (
            mock.patch.object(
                common_helpers,
                "LinuxCandidateTreeContainment",
                return_value=tracker,
            ),
            mock.patch.object(
                common_helpers.tempfile,
                "TemporaryFile",
                return_value=stdin_file,
            ),
            mock.patch.object(
                common_helpers.selectors,
                "DefaultSelector",
                side_effect=primary,
            ),
            self.assertRaises(ReviewError) as raised,
        ):
            run_bounded_host_command(
                [sys.executable, "-I", "-c", "raise SystemExit"],
                context="selector failure fixture",
                max_stdout_bytes=64,
                max_stderr_bytes=64,
                timeout_seconds=3,
                containment=CANDIDATE_TREE_CONTAINMENT,
            )
        self.assertIs(raised.exception.__cause__, primary)
        stdin_file.close.assert_called_once_with()
        tracker.close.assert_called_once_with(process_started=False)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux containment test")
    def test_actual_initialization_failures_restore_subreaper_ownership(self) -> None:
        before = process_containment._prctl_get_child_subreaper()
        failures = (
            (common_helpers.tempfile, "TemporaryFile"),
            (common_helpers.selectors, "DefaultSelector"),
        )
        for owner, attribute in failures:
            with (
                self.subTest(attribute=attribute),
                mock.patch.object(
                    owner,
                    attribute,
                    side_effect=OSError("injected initialization failure"),
                ),
                self.assertRaises(ReviewError),
            ):
                run_bounded_host_command(
                    [sys.executable, "-I", "-c", "raise SystemExit"],
                    context=f"actual {attribute} failure fixture",
                    max_stdout_bytes=64,
                    max_stderr_bytes=64,
                    timeout_seconds=3,
                    containment=CANDIDATE_TREE_CONTAINMENT,
                )
            self.assertEqual(
                process_containment._prctl_get_child_subreaper(),
                before,
            )
            result = run_bounded_host_command(
                [sys.executable, "-I", "-c", "print('ready')"],
                context=f"post-{attribute} containment fixture",
                max_stdout_bytes=64,
                max_stderr_bytes=64,
                timeout_seconds=3,
                containment=CANDIDATE_TREE_CONTAINMENT,
            )
            self.assertEqual(result, BoundedHostResult(0, b"ready\n", b""))

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux containment test")
    def test_candidate_activation_rejects_busy_ownership_without_waiting(self) -> None:
        lock = mock.Mock()
        lock.acquire.return_value = False
        with (
            mock.patch.object(process_containment, "_SUBREAPER_LOCK", lock),
            mock.patch.object(common_helpers.subprocess, "Popen") as popen,
            self.assertRaisesRegex(
                ReviewError,
                "containment ownership is already active",
            ),
        ):
            run_bounded_host_command(
                [sys.executable, "-I", "-c", "raise SystemExit"],
                context="busy candidate containment fixture",
                max_stdout_bytes=64,
                max_stderr_bytes=64,
                timeout_seconds=3,
                containment=CANDIDATE_TREE_CONTAINMENT,
            )
        lock.acquire.assert_called_once_with(blocking=False)
        lock.release.assert_not_called()
        popen.assert_not_called()

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux containment test")
    def test_candidate_activation_rejects_nondefault_sigchld_before_spawn(self) -> None:
        with (
            mock.patch.object(
                process_containment.signal,
                "getsignal",
                return_value=signal.SIG_IGN,
            ) as get_disposition,
            mock.patch.object(common_helpers.subprocess, "Popen") as popen,
            self.assertRaisesRegex(
                ReviewError,
                "requires the default SIGCHLD disposition",
            ),
        ):
            run_bounded_host_command(
                [sys.executable, "-I", "-c", "raise SystemExit"],
                context="SIGCHLD disposition fixture",
                max_stdout_bytes=64,
                max_stderr_bytes=64,
                timeout_seconds=3,
                containment=CANDIDATE_TREE_CONTAINMENT,
            )
        get_disposition.assert_called_once_with(signal.SIGCHLD)
        popen.assert_not_called()

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux containment test")
    def test_activation_exception_after_subreaper_enable_restores_state(self) -> None:
        tracker = process_containment.LinuxCandidateTreeContainment(
            context="activation exception fixture",
            stop_timeout_seconds=3,
        )
        lock = mock.Mock()
        lock.acquire.return_value = True
        state = [False]

        def get_state() -> bool:
            return state[0]

        def set_state(enabled: bool) -> None:
            state[0] = enabled
            if enabled:
                raise KeyboardInterrupt("injected post-prctl interruption")

        with (
            mock.patch.object(process_containment, "_SUBREAPER_LOCK", lock),
            mock.patch.object(process_containment, "_SUBREAPER_POISONED", False),
            mock.patch.object(
                process_containment,
                "_linux_task_count",
                return_value=1,
            ),
            mock.patch.object(
                process_containment,
                "_linux_direct_children",
                return_value=set(),
            ),
            mock.patch.object(process_containment, "_probe_linux_candidate_controls"),
            mock.patch.object(process_containment, "_probe_linux_waitid_controls"),
            mock.patch.object(process_containment, "_require_default_sigchld"),
            mock.patch.object(
                process_containment,
                "_prctl_get_child_subreaper",
                side_effect=get_state,
            ),
            mock.patch.object(
                process_containment,
                "_prctl_set_child_subreaper",
                side_effect=set_state,
            ) as set_subreaper,
            self.assertRaisesRegex(
                KeyboardInterrupt,
                "post-prctl interruption",
            ),
        ):
            tracker.activate()
        self.assertFalse(state[0])
        self.assertFalse(tracker._active)
        self.assertFalse(process_containment._SUBREAPER_POISONED)
        self.assertEqual(
            set_subreaper.call_args_list,
            [mock.call(True), mock.call(False)],
        )
        lock.release.assert_called_once_with()

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux containment test")
    def test_candidate_control_probe_fails_before_spawn_and_closes_pidfd(self) -> None:
        opened_pidfds: list[int] = []
        actual_pidfd_open = process_containment.os.pidfd_open

        def record_pidfd(pid: int, flags: int) -> int:
            descriptor = actual_pidfd_open(pid, flags)
            opened_pidfds.append(descriptor)
            return descriptor

        with (
            mock.patch.object(
                process_containment.os,
                "pidfd_open",
                side_effect=record_pidfd,
            ),
            mock.patch.object(
                process_containment.select,
                "poll",
                side_effect=OSError("injected pidfd poll failure"),
            ),
            mock.patch.object(common_helpers.subprocess, "Popen") as popen,
            self.assertRaisesRegex(
                ReviewError,
                "cannot inspect a Linux process handle",
            ),
        ):
            run_bounded_host_command(
                [sys.executable, "-I", "-c", "raise SystemExit"],
                context="candidate control probe fixture",
                max_stdout_bytes=64,
                max_stderr_bytes=64,
                timeout_seconds=3,
                containment=CANDIDATE_TREE_CONTAINMENT,
            )
        popen.assert_not_called()
        self.assertEqual(len(opened_pidfds), 1)
        with self.assertRaises(OSError) as raised:
            os.fstat(opened_pidfds[0])
        self.assertEqual(raised.exception.errno, errno.EBADF)

        result = run_bounded_host_command(
            [sys.executable, "-I", "-c", "print('ready')"],
            context="post-probe containment fixture",
            max_stdout_bytes=64,
            max_stderr_bytes=64,
            timeout_seconds=3,
            containment=CANDIDATE_TREE_CONTAINMENT,
        )
        self.assertEqual(result, BoundedHostResult(0, b"ready\n", b""))

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux containment test")
    def test_waitid_probe_failure_cleans_child_and_fails_before_spawn(self) -> None:
        opened_pidfds: list[int] = []
        probe_children: list[int] = []
        actual_pidfd_open = process_containment.os.pidfd_open
        actual_fork = process_containment.os.fork

        def record_pidfd(pid: int, flags: int) -> int:
            descriptor = actual_pidfd_open(pid, flags)
            opened_pidfds.append(descriptor)
            return descriptor

        def record_fork() -> int:
            pid = actual_fork()
            if pid > 0:
                probe_children.append(pid)
            return pid

        with (
            mock.patch.object(
                process_containment.os,
                "pidfd_open",
                side_effect=record_pidfd,
            ),
            mock.patch.object(
                process_containment.os,
                "fork",
                side_effect=record_fork,
            ),
            mock.patch.object(
                process_containment.os,
                "waitid",
                side_effect=OSError("injected waitid probe failure"),
            ),
            mock.patch.object(common_helpers.subprocess, "Popen") as popen,
            self.assertRaisesRegex(
                ReviewError,
                "cannot inspect its waitid probe",
            ),
        ):
            run_bounded_host_command(
                [sys.executable, "-I", "-c", "raise SystemExit"],
                context="waitid control probe fixture",
                max_stdout_bytes=64,
                max_stderr_bytes=64,
                timeout_seconds=3,
                containment=CANDIDATE_TREE_CONTAINMENT,
            )
        popen.assert_not_called()
        self.assertEqual(len(probe_children), 1)
        self.assertEqual(len(opened_pidfds), 2)
        self.assertEqual(process_containment._linux_direct_children(), set())
        self.assertIsNone(
            process_containment._linux_process_identity(probe_children[0])
        )
        for descriptor in opened_pidfds:
            with self.assertRaises(OSError) as raised:
                os.fstat(descriptor)
            self.assertEqual(raised.exception.errno, errno.EBADF)

        result = run_bounded_host_command(
            [sys.executable, "-I", "-c", "print('ready')"],
            context="post-waitid-probe containment fixture",
            max_stdout_bytes=64,
            max_stderr_bytes=64,
            timeout_seconds=3,
            containment=CANDIDATE_TREE_CONTAINMENT,
        )
        self.assertEqual(result, BoundedHostResult(0, b"ready\n", b""))

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux containment test")
    def test_waitid_probe_restores_mask_after_post_block_interrupt(self) -> None:
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        actual_sigmask = signal.pthread_sigmask
        mutation_observed = False

        def interrupt_after_block(how: int, mask: object) -> object:
            nonlocal mutation_observed
            result = actual_sigmask(how, mask)
            if how == signal.SIG_BLOCK and mask and not mutation_observed:
                mutation_observed = True
                raise KeyboardInterrupt("injected waitid post-block interruption")
            return result

        try:
            with mock.patch.object(
                process_containment,
                "_SUBREAPER_POISONED",
                False,
            ):
                with (
                    mock.patch.object(
                        process_containment.signal,
                        "pthread_sigmask",
                        side_effect=interrupt_after_block,
                    ),
                    self.assertRaisesRegex(
                        KeyboardInterrupt,
                        "injected waitid post-block interruption",
                    ),
                ):
                    process_containment._probe_linux_waitid_controls()
                poisoned = process_containment._SUBREAPER_POISONED
                current_mask = actual_sigmask(signal.SIG_BLOCK, ())
        finally:
            actual_sigmask(signal.SIG_SETMASK, original_mask)
        self.assertTrue(mutation_observed)
        self.assertFalse(poisoned)
        self.assertEqual(
            frozenset(int(value) for value in current_mask),
            frozenset(int(value) for value in original_mask),
        )
        self.assertEqual(process_containment._linux_direct_children(), set())

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux containment test")
    def test_waitid_probe_poisons_after_unrestored_post_block_interrupt(self) -> None:
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        actual_sigmask = signal.pthread_sigmask
        mutation_observed = False

        def fail_restoration_after_block(how: int, mask: object) -> object:
            nonlocal mutation_observed
            if how == signal.SIG_SETMASK:
                raise OSError("injected waitid mask restoration failure")
            result = actual_sigmask(how, mask)
            if how == signal.SIG_BLOCK and mask and not mutation_observed:
                mutation_observed = True
                raise KeyboardInterrupt("injected waitid post-block interruption")
            return result

        try:
            with mock.patch.object(
                process_containment,
                "_SUBREAPER_POISONED",
                False,
            ):
                with (
                    mock.patch.object(
                        process_containment.signal,
                        "pthread_sigmask",
                        side_effect=fail_restoration_after_block,
                    ),
                    self.assertRaisesRegex(
                        KeyboardInterrupt,
                        "injected waitid post-block interruption",
                    ),
                ):
                    process_containment._probe_linux_waitid_controls()
                poisoned = process_containment._SUBREAPER_POISONED
        finally:
            actual_sigmask(signal.SIG_SETMASK, original_mask)
        self.assertTrue(mutation_observed)
        self.assertTrue(poisoned)
        self.assertEqual(process_containment._linux_direct_children(), set())

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux containment test")
    def test_sigchld_drift_before_root_exit_fails_closed_without_group_signal(
        self,
    ) -> None:
        source = r"""
import signal
import sys

sys.path.insert(0, sys.argv[1])
import common
import process_containment as containment

actual_arm = containment.LinuxCandidateTreeContainment.arm
observed = {}
group_signals = []

def arm(tracker, process):
    actual_arm(tracker, process)
    tracker.stop_timeout_seconds = 0.05
    observed["tracker"] = tracker
    if containment._pidfd_is_exited(tracker._root.pidfd):
        raise RuntimeError("candidate root exited before SIGCHLD drift")
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)

def record_group_signal(*arguments):
    group_signals.append(arguments)
    return None

containment.LinuxCandidateTreeContainment.arm = arm
containment._signal_process_group = record_group_signal
try:
    common.run_bounded_host_command(
        [
            sys.executable,
            "-I",
            "-c",
            "import time; time.sleep(0.4); raise SystemExit(7)",
        ],
        context="SIGCHLD pre-exit drift fixture",
        max_stdout_bytes=64,
        max_stderr_bytes=64,
        timeout_seconds=3,
        containment=containment.CANDIDATE_TREE_CONTAINMENT,
    )
except common.ReviewError as error:
    if "SIGCHLD disposition changed" not in str(error):
        raise RuntimeError(f"unexpected containment error: {error}") from error
else:
    raise RuntimeError("SIGCHLD drift did not fail closed")

tracker = observed.get("tracker")
if tracker is None:
    raise RuntimeError("containment did not arm its root")
if group_signals:
    raise RuntimeError("containment used a numeric process-group signal after drift")
if tracker._group_anchor_safe:
    raise RuntimeError("containment retained an unsafe process-group anchor")
if not containment._SUBREAPER_POISONED:
    raise RuntimeError("containment did not poison ownership after SIGCHLD drift")
if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
    raise RuntimeError("containment did not restore the safe SIGCHLD disposition")
"""
        result = self.run_isolated_linux_harness(source)
        self.assertEqual(
            result.returncode,
            0,
            (result.stdout + result.stderr).decode("utf-8", "replace"),
        )

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux containment test")
    def test_sigchld_drift_after_root_exit_fails_closed(
        self,
    ) -> None:
        source = r"""
import signal
import sys
import time

sys.path.insert(0, sys.argv[1])
import common
import process_containment as containment

actual_arm = containment.LinuxCandidateTreeContainment.arm
observed = {}
group_signals = []

def arm(tracker, process):
    actual_arm(tracker, process)
    tracker.stop_timeout_seconds = 0.05
    observed["tracker"] = tracker
    observed["process"] = process
    deadline = time.monotonic() + 2
    while not containment._pidfd_is_exited(tracker._root.pidfd):
        if time.monotonic() >= deadline:
            raise RuntimeError("candidate root did not exit before SIGCHLD drift")
        time.sleep(0.01)
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)

def record_group_signal(*arguments):
    group_signals.append(arguments)
    return None

containment.LinuxCandidateTreeContainment.arm = arm
containment._signal_process_group = record_group_signal
try:
    common.run_bounded_host_command(
        [sys.executable, "-I", "-c", "raise SystemExit(7)"],
        context="SIGCHLD post-exit drift fixture",
        max_stdout_bytes=64,
        max_stderr_bytes=64,
        timeout_seconds=3,
        containment=containment.CANDIDATE_TREE_CONTAINMENT,
    )
except common.ReviewError as error:
    if "SIGCHLD disposition changed" not in str(error):
        raise RuntimeError(f"unexpected containment error: {error}") from error
else:
    raise RuntimeError("post-exit SIGCHLD drift did not fail closed")

tracker = observed.get("tracker")
if tracker is None or tracker._integrity_error is None:
    raise RuntimeError("containment did not retain its integrity failure")
if tracker._root_exit_status is None or tracker._root_exit_status.returncode != 7:
    raise RuntimeError("containment did not retain the exact root exit status")
if group_signals:
    raise RuntimeError("containment used a numeric process-group signal after anchor loss")
if tracker._group_anchor_safe:
    raise RuntimeError("containment retained an unsafe process-group anchor")
if not containment._SUBREAPER_POISONED:
    raise RuntimeError("containment did not poison ownership after SIGCHLD drift")

process = observed["process"]
waited_pid, wait_status = containment.os.waitpid(process.pid, containment.os.WNOHANG)
if waited_pid != process.pid:
    raise RuntimeError("disposable harness could not reap its retained root anchor")
process.returncode = containment.os.waitstatus_to_exitcode(wait_status)
"""
        result = self.run_isolated_linux_harness(source)
        self.assertEqual(
            result.returncode,
            0,
            (result.stdout + result.stderr).decode("utf-8", "replace"),
        )

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux containment test")
    def test_lost_root_wait_status_fails_closed_without_group_signal(self) -> None:
        source = r"""
import signal
import sys
import time

sys.path.insert(0, sys.argv[1])
import common
import process_containment as containment

actual_arm = containment.LinuxCandidateTreeContainment.arm
observed = {}
group_signals = []

def arm(tracker, process):
    actual_arm(tracker, process)
    tracker.stop_timeout_seconds = 0.05
    observed["tracker"] = tracker
    observed["process"] = process
    deadline = time.monotonic() + 2
    while not containment._pidfd_is_exited(tracker._root.pidfd):
        if time.monotonic() >= deadline:
            raise RuntimeError("candidate root did not exit before external wait")
        time.sleep(0.01)
    waited_pid, wait_status = containment.os.waitpid(process.pid, 0)
    if waited_pid != process.pid:
        raise RuntimeError("external wait returned another process identity")
    observed["returncode"] = containment.os.waitstatus_to_exitcode(wait_status)

def record_group_signal(*arguments):
    group_signals.append(arguments)
    return None

containment.LinuxCandidateTreeContainment.arm = arm
containment._signal_process_group = record_group_signal
try:
    common.run_bounded_host_command(
        [sys.executable, "-I", "-c", "raise SystemExit(7)"],
        context="lost root wait-status fixture",
        max_stdout_bytes=64,
        max_stderr_bytes=64,
        timeout_seconds=3,
        containment=containment.CANDIDATE_TREE_CONTAINMENT,
    )
except common.ReviewError as error:
    if "wait status is unavailable" not in str(error):
        raise RuntimeError(f"unexpected containment error: {error}") from error
else:
    raise RuntimeError("lost root wait status did not fail closed")

tracker = observed.get("tracker")
if observed.get("returncode") != 7:
    raise RuntimeError("external wait did not observe the actual nonzero status")
if tracker is None or tracker._integrity_error is None:
    raise RuntimeError("containment did not retain its integrity failure")
if tracker._root_exit_status is not None:
    raise RuntimeError("containment invented a root exit status")
if group_signals:
    raise RuntimeError("containment used a numeric process-group signal after anchor loss")
if tracker._group_anchor_safe:
    raise RuntimeError("containment retained an unsafe process-group anchor")
if not containment._SUBREAPER_POISONED:
    raise RuntimeError("containment did not poison ownership after wait-status loss")
observed["process"].returncode = observed["returncode"]
"""
        result = self.run_isolated_linux_harness(source)
        self.assertEqual(
            result.returncode,
            0,
            (result.stdout + result.stderr).decode("utf-8", "replace"),
        )

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux containment test")
    def test_subreaper_drift_fails_after_stable_detached_child_cleanup(self) -> None:
        source = r"""
import os
import pathlib
import signal
import sys
import tempfile
import time

sys.path.insert(0, sys.argv[1])
import common
import process_containment as containment

actual_arm = containment.LinuxCandidateTreeContainment.arm
actual_set_subreaper = containment._prctl_set_child_subreaper
actual_signal_handle = containment.LinuxCandidateTreeContainment._signal_handle
before = containment._prctl_get_child_subreaper()
observed = {}
set_calls = []
stable_signal_pids = []

def set_subreaper(enabled):
    set_calls.append(enabled)
    actual_set_subreaper(enabled)

def signal_handle(handle, signal_number):
    stable_signal_pids.append(handle.identity.pid)
    return actual_signal_handle(handle, signal_number)

containment._prctl_set_child_subreaper = set_subreaper
containment.LinuxCandidateTreeContainment._signal_handle = staticmethod(signal_handle)

with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    ready_path = root / "ready"
    detached_path = root / "detached.pid"
    candidate_source = f'''\
import os
import pathlib
import signal
import time

signal.signal(signal.SIGTERM, signal.SIG_IGN)
pathlib.Path({str(ready_path)!r}).write_text("ready", encoding="ascii")
time.sleep(0.2)
first = os.fork()
if first == 0:
    os.setsid()
    second = os.fork()
    if second != 0:
        os._exit(0)
    pathlib.Path({str(detached_path)!r}).write_text(
        str(os.getpid()),
        encoding="ascii",
    )
    for descriptor in (0, 1, 2):
        try:
            os.close(descriptor)
        except OSError:
            pass
    time.sleep(20)
    os._exit(0)
time.sleep(20)
'''

    def arm(tracker, process):
        actual_arm(tracker, process)
        tracker.stop_timeout_seconds = 1.0
        observed["tracker"] = tracker
        observed["process"] = process
        deadline = time.monotonic() + 2
        while not ready_path.exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("candidate did not install its signal handler")
            time.sleep(0.01)
        set_subreaper(False)
        if containment._prctl_get_child_subreaper():
            raise RuntimeError("subreaper drift injection did not take effect")

    containment.LinuxCandidateTreeContainment.arm = arm
    started = time.monotonic()
    try:
        common.run_bounded_host_command(
            [sys.executable, "-I", "-c", candidate_source],
            context="child-subreaper drift fixture",
            max_stdout_bytes=64,
            max_stderr_bytes=64,
            timeout_seconds=5,
            containment=containment.CANDIDATE_TREE_CONTAINMENT,
        )
    except common.ReviewError as error:
        if "child-subreaper state changed" not in str(error):
            raise RuntimeError(f"unexpected containment error: {error}") from error
    else:
        raise RuntimeError("child-subreaper drift did not fail closed")
    elapsed = time.monotonic() - started
    if elapsed > 4:
        raise RuntimeError(f"detached-child cleanup exceeded its bound: {elapsed}")

    tracker = observed.get("tracker")
    process = observed.get("process")
    if tracker is None or process is None:
        raise RuntimeError("containment did not retain its armed root")
    if tracker._integrity_error is None:
        raise RuntimeError("containment did not retain its integrity failure")
    if "child-subreaper state changed" not in str(tracker._integrity_error):
        raise RuntimeError("containment replaced its first integrity failure")
    if not containment._SUBREAPER_POISONED:
        raise RuntimeError("containment did not poison subreaper ownership")
    if False not in set_calls or True not in set_calls[set_calls.index(False) + 1:]:
        raise RuntimeError("containment did not restore active subreaper control")
    if not detached_path.exists():
        raise RuntimeError("candidate did not create its delayed detached child")
    detached_pid = int(detached_path.read_text(encoding="ascii"))
    if detached_pid not in stable_signal_pids:
        raise RuntimeError("containment did not signal the detached stable identity")
    try:
        os.kill(detached_pid, 0)
    except ProcessLookupError:
        pass
    else:
        raise RuntimeError("detached stable identity survived containment cleanup")
    if process.returncode is None:
        raise RuntimeError("production cleanup did not reap the stable root")
    if not tracker._cleanup_complete or tracker._verified:
        raise RuntimeError("cleanup-only root reaping changed verification state")
    if containment._linux_direct_children():
        raise RuntimeError("production cleanup left a direct child")
    if containment._prctl_get_child_subreaper() != before:
        raise RuntimeError("production cleanup did not restore subreaper state")
    try:
        tracker._require_transaction_integrity()
    except containment.ProcessContainmentError as error:
        if error is not tracker._integrity_error:
            raise RuntimeError("containment replaced its sticky integrity error")
    else:
        raise RuntimeError("prior-state restoration erased the integrity failure")
"""
        result = self.run_isolated_linux_harness(source)
        self.assertEqual(
            result.returncode,
            0,
            (result.stdout + result.stderr).decode("utf-8", "replace"),
        )

    def test_containment_cleanup_does_not_mask_initialization_failure(self) -> None:
        tracker = mock.Mock()
        primary = OSError("injected initialization failure")
        cleanup = process_containment.ProcessContainmentError(
            "injected containment cleanup failure"
        )
        tracker.close.side_effect = cleanup
        with (
            mock.patch.object(
                common_helpers,
                "LinuxCandidateTreeContainment",
                return_value=tracker,
            ),
            mock.patch.object(
                common_helpers.tempfile,
                "TemporaryFile",
                side_effect=primary,
            ),
            self.assertRaises(ReviewError) as raised,
        ):
            run_bounded_host_command(
                [sys.executable, "-I", "-c", "raise SystemExit"],
                context="cleanup precedence fixture",
                max_stdout_bytes=64,
                max_stderr_bytes=64,
                timeout_seconds=3,
                containment=CANDIDATE_TREE_CONTAINMENT,
            )
        self.assertIs(raised.exception.__cause__, primary)
        self.assertTrue(
            any(
                "containment cleanup failure" in note
                for note in raised.exception.__notes__
            )
        )

    def test_cleanup_only_failure_fails_the_host_command(self) -> None:
        stdin_file = mock.Mock()
        cleanup = OSError("injected input cleanup failure")
        stdin_file.close.side_effect = cleanup
        with (
            mock.patch.object(
                common_helpers.tempfile,
                "TemporaryFile",
                return_value=stdin_file,
            ),
            self.assertRaisesRegex(
                ReviewError,
                "resource cleanup failed",
            ) as raised,
        ):
            run_bounded_host_command(
                [sys.executable, "-I", "-c", "print('complete')"],
                context="cleanup-only failure fixture",
                max_stdout_bytes=64,
                max_stderr_bytes=64,
                timeout_seconds=3,
            )
        self.assertIs(raised.exception.__cause__, cleanup)

    def test_proc_descriptor_cleanup_preserves_primary_failure(self) -> None:
        primary = OSError("injected procfs read failure")
        cleanup = OSError("injected procfs close failure")
        with (
            mock.patch.object(process_containment.os, "open", return_value=73),
            mock.patch.object(
                process_containment.os,
                "read",
                side_effect=primary,
            ),
            mock.patch.object(
                process_containment.os,
                "close",
                side_effect=cleanup,
            ) as close_descriptor,
            self.assertRaises(OSError) as raised,
        ):
            process_containment._read_bounded_proc_file(
                Path("/proc/fixture/stat"),
                64,
            )
        self.assertIs(raised.exception, primary)
        self.assertTrue(
            any("descriptor cleanup also failed" in note for note in primary.__notes__)
        )
        close_descriptor.assert_called_once_with(73)

    def test_pidfd_close_is_single_use_and_fails_closed(self) -> None:
        identity = process_containment.LinuxProcessIdentity(
            pid=71,
            state="S",
            parent_pid=1,
            process_group=71,
            session=71,
            start_time=10,
        )
        handle = process_containment._LinuxProcessHandle(identity, 91)
        with (
            mock.patch.object(
                process_containment.os,
                "close",
                side_effect=OSError("injected pidfd close failure"),
            ) as close_descriptor,
            self.assertRaisesRegex(
                process_containment.ProcessContainmentError,
                "cannot close Linux process 71 pidfd",
            ),
        ):
            handle.close()
        self.assertEqual(handle.pidfd, -1)
        handle.close()
        close_descriptor.assert_called_once_with(91)

    def test_subreaper_restore_failure_releases_and_poisons_ownership(self) -> None:
        tracker = process_containment.LinuxCandidateTreeContainment(
            context="restore failure fixture",
            stop_timeout_seconds=3,
        )
        tracker._active = True
        tracker._previous_subreaper = False
        lock = mock.Mock()
        restore_error = process_containment.ProcessContainmentError(
            "injected subreaper restore failure"
        )
        with (
            mock.patch.object(process_containment, "_SUBREAPER_LOCK", lock),
            mock.patch.object(process_containment, "_SUBREAPER_POISONED", False),
            mock.patch.object(
                process_containment,
                "_prctl_get_child_subreaper",
                return_value=True,
            ),
            mock.patch.object(
                process_containment,
                "_prctl_set_child_subreaper",
                side_effect=restore_error,
            ) as restore,
        ):
            with self.assertRaisesRegex(
                process_containment.ProcessContainmentError,
                "containment cleanup failed",
            ) as raised:
                tracker.close(process_started=False)
            poisoned = process_containment._SUBREAPER_POISONED
        self.assertIs(raised.exception.__cause__, restore_error)
        restore.assert_called_once_with(False)
        lock.release.assert_called_once_with()
        self.assertFalse(tracker._active)
        self.assertTrue(poisoned)

    def test_unverified_launch_mask_poisons_candidate_containment(self) -> None:
        tracker = process_containment.LinuxCandidateTreeContainment(
            context="launch signal-mask failure fixture",
            stop_timeout_seconds=3,
        )
        with mock.patch.object(process_containment, "_SUBREAPER_POISONED", False):
            tracker.invalidate_launch_signal_mask()
            poisoned = process_containment._SUBREAPER_POISONED
        self.assertTrue(poisoned)
        self.assertIsNotNone(tracker._integrity_error)
        self.assertIn("signal mask was not restored", str(tracker._integrity_error))

    @unittest.skipUnless(sys.platform == "darwin", "macOS rejection test")
    def test_candidate_tree_rejects_macos_before_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "started"
            source = (
                f"import pathlib;pathlib.Path({str(marker)!r}).write_text('started')"
            )
            with self.assertRaisesRegex(
                ReviewError,
                "candidate-tree containment requires Linux",
            ):
                run_bounded_host_command(
                    [sys.executable, "-I", "-c", source],
                    context="unsupported candidate-tree fixture",
                    max_stdout_bytes=64,
                    max_stderr_bytes=64,
                    timeout_seconds=3,
                    containment=CANDIDATE_TREE_CONTAINMENT,
                )
            self.assertFalse(marker.exists())

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux containment test")
    def test_candidate_tree_stops_double_forked_descendant(self) -> None:
        source = """
import os
import pathlib
import sys
import time

read_descriptor, write_descriptor = os.pipe()
first = os.fork()
if first == 0:
    os.close(read_descriptor)
    os.setsid()
    second = os.fork()
    if second != 0:
        os._exit(0)
    os.write(write_descriptor, str(os.getpid()).encode("ascii"))
    os.close(write_descriptor)
    for descriptor in (0, 1, 2):
        try:
            os.close(descriptor)
        except OSError:
            pass
    time.sleep(20)
    os._exit(0)
os.close(write_descriptor)
escaped_pid = os.read(read_descriptor, 64)
os.close(read_descriptor)
pathlib.Path(sys.argv[1]).write_bytes(escaped_pid)
os._exit(0)
"""
        libc = ctypes.CDLL(None, use_errno=True)

        def subreaper_state() -> int:
            state = ctypes.c_int()
            self.assertEqual(libc.prctl(37, ctypes.byref(state), 0, 0, 0), 0)
            return state.value

        before = subreaper_state()
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "escaped.pid"
            with self.assertRaisesRegex(
                ReviewError,
                "left a process after its root exited",
            ):
                run_bounded_host_command(
                    [sys.executable, "-I", "-c", source, str(pid_path)],
                    context="double-fork candidate fixture",
                    max_stdout_bytes=64,
                    max_stderr_bytes=64,
                    timeout_seconds=5,
                    containment=CANDIDATE_TREE_CONTAINMENT,
                )
            escaped_pid = int(pid_path.read_text(encoding="ascii"))
            with self.assertRaises(ProcessLookupError):
                os.kill(escaped_pid, 0)
        self.assertEqual(subreaper_state(), before)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux containment test")
    def test_candidate_tree_stops_detached_descendant_with_high_pidfds(self) -> None:
        soft_limit, _hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft_limit < 1152:
            self.skipTest("the file-descriptor limit cannot exercise high pidfds")

        held_descriptors: list[int] = []
        observed_pidfds: list[int] = []
        actual_pidfd_is_exited = process_containment._pidfd_is_exited
        try:
            while not held_descriptors or held_descriptors[-1] < 1050:
                try:
                    held_descriptors.append(os.open(os.devnull, os.O_RDONLY))
                except OSError as error:
                    if error.errno in {errno.EMFILE, errno.ENFILE}:
                        self.skipTest(
                            "available file descriptors cannot exercise high pidfds"
                        )
                    raise

            def observe_pidfd(pidfd: int) -> bool:
                observed_pidfds.append(pidfd)
                return actual_pidfd_is_exited(pidfd)

            child_source = """
import os
import signal
import time

signal.signal(signal.SIGTERM, signal.SIG_IGN)
for descriptor in (0, 1, 2):
    try:
        os.close(descriptor)
    except OSError:
        pass
time.sleep(20)
"""
            with tempfile.TemporaryDirectory() as directory:
                pid_path = Path(directory) / "detached.pid"
                root_source = f"""
import pathlib
import subprocess
import sys

child = subprocess.Popen(
    [sys.executable, "-I", "-c", {child_source!r}],
    start_new_session=True,
)
pathlib.Path({str(pid_path)!r}).write_text(str(child.pid), encoding="ascii")
"""
                with (
                    mock.patch.object(
                        process_containment,
                        "_pidfd_is_exited",
                        side_effect=observe_pidfd,
                    ),
                    self.assertRaisesRegex(
                        ReviewError,
                        "left a process after its root exited",
                    ),
                ):
                    run_bounded_host_command(
                        [sys.executable, "-I", "-c", root_source],
                        context="high-pidfd candidate fixture",
                        max_stdout_bytes=64,
                        max_stderr_bytes=64,
                        timeout_seconds=5,
                        containment=CANDIDATE_TREE_CONTAINMENT,
                    )
                detached_pid = int(pid_path.read_text(encoding="ascii"))
                with self.assertRaises(ProcessLookupError):
                    os.kill(detached_pid, 0)
            self.assertTrue(observed_pidfds)
            self.assertGreater(max(observed_pidfds), 1024)
        finally:
            for descriptor in reversed(held_descriptors):
                os.close(descriptor)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux containment test")
    def test_candidate_tree_rejects_preexisting_child_before_spawn(self) -> None:
        child = subprocess.Popen(
            [sys.executable, "-I", "-c", "import time; time.sleep(20)"]
        )
        try:
            with tempfile.TemporaryDirectory() as directory:
                marker = Path(directory) / "started"
                source = (
                    "import pathlib;"
                    f"pathlib.Path({str(marker)!r}).write_text('started')"
                )
                with self.assertRaisesRegex(
                    ReviewError,
                    "pre-existing child process",
                ):
                    run_bounded_host_command(
                        [sys.executable, "-I", "-c", source],
                        context="pre-existing child fixture",
                        max_stdout_bytes=64,
                        max_stderr_bytes=64,
                        timeout_seconds=3,
                        containment=CANDIDATE_TREE_CONTAINMENT,
                    )
                self.assertFalse(marker.exists())
        finally:
            child.send_signal(signal.SIGKILL)
            child.wait(timeout=3)


if __name__ == "__main__":
    unittest.main()
