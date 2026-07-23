from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import release_audit, secure_deployment


class ReleaseAuditTests(unittest.TestCase):
    def test_secure_profile_json_parser_and_cli_fail_closed(self) -> None:
        invalid_documents = (
            b'{"value": NaN}',
            b'{"value": Infinity}',
            b'{"value": -Infinity}',
            b'{"value": 1e1000000}',
            b'{"value": 1e-1000000}',
            b'{"value": ' + b"9" * 5_000 + b"}",
            b"\xff",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "invalid.json"
            for document in invalid_documents:
                with self.subTest(document=document[:40]):
                    path.write_bytes(document)
                    with self.assertRaisesRegex(
                        secure_deployment.ProfileError, "cannot load"
                    ):
                        secure_deployment._load_json(path)

            path.write_bytes(b'{"value": 1, "value": 2}')
            with self.assertRaisesRegex(
                secure_deployment.ProfileError, "duplicate JSON object key"
            ):
                secure_deployment._load_json(path)

            path.write_bytes(b'{"value": ' + b"9" * 5_000 + b"}")
            output = root / "rendered"
            result = subprocess.run(
                [
                    sys.executable,
                    str(release_audit.ROOT / "scripts" / "secure_deployment.py"),
                    "render",
                    "--profile",
                    str(path),
                    "--output-dir",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("cannot load", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertFalse(output.exists())

        with self.assertRaisesRegex(
            secure_deployment.ProfileError, "cannot encode strict JSON"
        ):
            secure_deployment._json_bytes({"value": float("nan")})
        with self.assertRaisesRegex(
            secure_deployment.ProfileError, "cannot encode strict JSON"
        ):
            secure_deployment._json_bytes({"value": 10**128})

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema": 1, "schema": 2}\n', encoding="utf-8")
            with self.assertRaisesRegex(release_audit.AuditError, "duplicate JSON key"):
                release_audit.load_json(path)

    def test_nonfinite_and_oversized_json_numbers_are_rejected(self) -> None:
        invalid_documents = (
            '{"value": NaN}',
            '{"value": Infinity}',
            '{"value": -Infinity}',
            '{"value": 1e1000000}',
            '{"value": 1e-1000000}',
            '{"value": ' + "9" * 5_000 + "}",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            for document in invalid_documents:
                with self.subTest(document=document[:40]):
                    path.write_text(document, encoding="utf-8")
                    with self.assertRaisesRegex(
                        release_audit.AuditError, "cannot load"
                    ):
                        release_audit.load_json(path)

        for value in (float("nan"), float("inf"), -float("inf")):
            with self.subTest(canonical_value=value):
                with self.assertRaisesRegex(
                    release_audit.AuditError, "cannot encode canonical JSON"
                ):
                    release_audit.canonical_bytes({"value": value})
        with self.assertRaisesRegex(
            release_audit.AuditError, "cannot encode canonical JSON"
        ):
            release_audit.canonical_bytes({"value": 10**128})

    def test_canonical_json_is_order_independent_and_idempotent(self) -> None:
        first = {"z": [3, 2, 1], "a": {"right": 2, "left": 1}}
        second = {"a": {"left": 1, "right": 2}, "z": [3, 2, 1]}
        encoded = release_audit.canonical_bytes(first)
        self.assertEqual(encoded, release_audit.canonical_bytes(second))
        self.assertEqual(encoded, release_audit.canonical_bytes(json.loads(encoded)))

    def test_handoff_task_chain_is_complete_and_contiguous(self) -> None:
        tasks = release_audit.validate_tasks()
        self.assertEqual(len(tasks), 116)
        self.assertEqual(tasks[0]["id"], "T000")
        self.assertEqual(tasks[-1]["id"], "T115")
        self.assertEqual(tasks[-1]["dependencies"], ["T114"])

    def test_project_doi_or_zenodo_claim_is_rejected(self) -> None:
        inputs = copy.deepcopy(release_audit.load_json(release_audit.INPUTS))
        inputs["release"]["doi"] = "10.0000/not-issued"
        with self.assertRaisesRegex(release_audit.AuditError, "DOI or Zenodo"):
            release_audit.validate_inputs(inputs)

    def test_abbreviated_or_oversized_repository_revision_is_rejected(self) -> None:
        for revision in ("deadbeef", "0" * 41):
            with self.subTest(revision=revision):
                inputs = copy.deepcopy(release_audit.load_json(release_audit.INPUTS))
                inputs["repositories"][0]["commit"] = revision
                with self.assertRaisesRegex(release_audit.AuditError, "full revision"):
                    release_audit.validate_inputs(inputs)

    def test_source_ledger_never_claims_post_commit_completion(self) -> None:
        ledger = release_audit.validate_ledger(
            release_audit.validate_tasks(), release_audit.validate_claims()
        )
        self.assertEqual(
            ledger["status_counts"],
            {"OPEN": 107, "COMPLETE": 0, "NOT_CLAIMED": 9},
        )
        self.assertTrue(
            all(
                not task["post_commit_evidence"]
                and not task["post_commit_tests"]
                and not task["post_commit_findings"]
                for task in ledger["tasks"]
            )
        )

    def test_every_claim_has_a_frozen_tier_and_limit(self) -> None:
        claims = release_audit.validate_claims()
        self.assertGreater(len(claims), 0)
        self.assertTrue(
            all(claim["tier"] in release_audit.VALID_TIERS for claim in claims)
        )
        self.assertTrue(all(claim["limitations"] for claim in claims))
        self.assertFalse(
            any(claim["tier"] == "DEPLOYMENT_QUALIFIED" for claim in claims)
        )

    def test_threat_register_is_complete_and_bound_to_current_tasks(self) -> None:
        artifact = release_audit.validate_threat_register()
        document = release_audit.load_json(release_audit.THREAT_REGISTER)
        self.assertEqual(artifact["path"], "release/0.9.0/audit/threat-register.json")
        self.assertGreaterEqual(len(document["threats"]), 10)
        self.assertEqual(
            document["source"]["task_ledger_sha256"],
            release_audit.load_json(release_audit.TASKS)["source"][
                "task_ledger_sha256"
            ],
        )

    def test_threat_register_accepts_only_declared_lifecycle_states(self) -> None:
        current = release_audit.load_json(release_audit.THREAT_REGISTER)
        original_load = release_audit.load_json

        def load_with_status(path: Path, status: str) -> object:
            if path == release_audit.THREAT_REGISTER:
                document = copy.deepcopy(current)
                document["status"] = status
                return document
            return original_load(path)

        for status in sorted(release_audit.VALID_THREAT_REGISTER_STATUSES):
            with self.subTest(status=status):
                with patch.object(
                    release_audit,
                    "load_json",
                    side_effect=lambda path, status=status: load_with_status(
                        path, status
                    ),
                ):
                    release_audit.validate_threat_register()

        with patch.object(
            release_audit,
            "load_json",
            side_effect=lambda path: load_with_status(path, "UNSUPPORTED"),
        ):
            with self.assertRaisesRegex(
                release_audit.AuditError, "unsupported lifecycle status"
            ):
                release_audit.validate_threat_register()

    def test_ecosystem_cut_contains_each_observation_date(self) -> None:
        current = release_audit.load_json(release_audit.ECOSYSTEM_CUT)
        release_audit.validate_ecosystem_cut()
        original_load = release_audit.load_json

        def load_cut(document: object):
            return lambda path: (
                document if path == release_audit.ECOSYSTEM_CUT else original_load(path)
            )

        stale = copy.deepcopy(current)
        stale["inspected_at"] = "2026-07-22"
        with (
            patch.object(
                release_audit,
                "load_json",
                side_effect=load_cut(stale),
            ),
            self.assertRaisesRegex(
                release_audit.AuditError,
                "inspected_at predates observation ECO-012",
            ),
        ):
            release_audit.validate_ecosystem_cut()

        mixed_precision = copy.deepcopy(current)
        mixed_precision["observations"][0]["timestamp_precision"] = "second"
        with (
            patch.object(
                release_audit,
                "load_json",
                side_effect=load_cut(mixed_precision),
            ),
            self.assertRaisesRegex(
                release_audit.AuditError,
                "timestamp precision differs",
            ),
        ):
            release_audit.validate_ecosystem_cut()

    def test_release_publication_channel_is_exact(self) -> None:
        inputs = copy.deepcopy(release_audit.load_json(release_audit.INPUTS))
        self.assertEqual(
            inputs["release"]["publication_channel"],
            release_audit.PUBLICATION_CHANNEL,
        )
        inputs["release"]["publication_channel"] = "another channel"
        with self.assertRaisesRegex(
            release_audit.AuditError,
            "publication channel differs",
        ):
            release_audit.validate_inputs(inputs)

    def test_build_is_deterministic_and_covers_all_tasks(self) -> None:
        first_audit, first_ledger = release_audit.build_outputs()
        second_audit, second_ledger = release_audit.build_outputs()
        self.assertEqual(first_audit, second_audit)
        self.assertEqual(first_ledger, second_ledger)
        self.assertEqual(first_ledger["source_task_count"], 116)
        self.assertEqual(sum(first_ledger["status_counts"].values()), 116)
        self.assertEqual(first_ledger["status_counts"]["COMPLETE"], 0)
        covered = {entry["path"] for entry in first_audit["artifacts"]}
        self.assertEqual(
            first_audit["artifact_self_exclusions"],
            sorted(release_audit.AUDIT_SELF_EXCLUSIONS),
        )
        self.assertEqual(
            covered,
            release_audit.tracked_repository_paths()
            - release_audit.AUDIT_SELF_EXCLUSIONS,
        )
        ledger_entry = next(
            entry
            for entry in first_audit["artifacts"]
            if entry["path"] == "release/0.9.0/requirements-ledger.json"
        )
        ledger_bytes = release_audit.canonical_bytes(first_ledger)
        self.assertEqual(
            ledger_entry["sha256"], hashlib.sha256(ledger_bytes).hexdigest()
        )
        self.assertEqual(ledger_entry["size_bytes"], len(ledger_bytes))

    def test_workflow_actions_are_full_revisions_and_exactly_inventoried(self) -> None:
        inputs = release_audit.load_json(release_audit.INPUTS)
        recorded = {
            (entry["action"], entry["commit"]) for entry in inputs["github_actions"]
        }
        self.assertEqual(recorded, release_audit.workflow_action_refs())

        incomplete = copy.deepcopy(inputs)
        incomplete["github_actions"].pop()
        with self.assertRaisesRegex(
            release_audit.AuditError, "inventory differs from workflows"
        ):
            release_audit.validate_inputs(incomplete)


if __name__ == "__main__":
    unittest.main()
