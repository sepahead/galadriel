"""Regression tests for bounded release-tool host processes."""

from __future__ import annotations

import ast
import io
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


TOOLS = Path(__file__).resolve().parents[1]
REPOSITORY = TOOLS.parent
sys.path.insert(0, str(TOOLS))

import check_public_api  # noqa: E402
import reproduce_baseline  # noqa: E402
import run_broad_mutation  # noqa: E402
from common import ReviewError  # noqa: E402
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


class HostProcessBoundTests(unittest.TestCase):
    """Keep each release-tool process behind the shared bounded runner."""

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


if __name__ == "__main__":
    unittest.main()
