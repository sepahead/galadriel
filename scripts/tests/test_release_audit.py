from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts import release_audit


class ReleaseAuditTests(unittest.TestCase):
    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema": 1, "schema": 2}\n', encoding="utf-8")
            with self.assertRaisesRegex(release_audit.AuditError, "duplicate JSON key"):
                release_audit.load_json(path)

    def test_canonical_json_is_order_independent_and_idempotent(self) -> None:
        first = {"z": [3, 2, 1], "a": {"right": 2, "left": 1}}
        second = {"a": {"left": 1, "right": 2}, "z": [3, 2, 1]}
        encoded = release_audit.canonical_bytes(first)
        self.assertEqual(encoded, release_audit.canonical_bytes(second))
        self.assertEqual(encoded, release_audit.canonical_bytes(json.loads(encoded)))

    def test_handoff_task_chain_is_complete_and_contiguous(self) -> None:
        tasks = release_audit.validate_tasks()
        self.assertEqual(len(tasks), 120)
        self.assertEqual(tasks[0]["id"], "T000")
        self.assertEqual(tasks[-1]["id"], "T119")
        self.assertEqual(tasks[-1]["dependencies"], ["T118"])

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

    def test_complete_task_without_machine_evidence_is_rejected(self) -> None:
        invalid = {
            "schema": "galadriel.task-dispositions.v1",
            "release": "0.9.0",
            "overrides": [
                {
                    "task_id": "T000",
                    "status": "COMPLETE",
                    "requirement_ids": ["GLD-090-AUD-001"],
                    "requirements": ["The release SHALL retain evidence."],
                    "evidence": [],
                    "tests": [],
                    "review": {},
                    "residual_risk": "None identified.",
                }
            ],
        }
        original = release_audit.DISPOSITIONS
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "invalid.json"
                path.write_text(json.dumps(invalid), encoding="utf-8")
                release_audit.DISPOSITIONS = path
                with self.assertRaisesRegex(release_audit.AuditError, "prohibited"):
                    release_audit.validate_ledger(release_audit.validate_tasks())
        finally:
            release_audit.DISPOSITIONS = original

    def test_every_claim_has_a_frozen_tier_and_limit(self) -> None:
        claims = release_audit.validate_claims()
        self.assertGreater(len(claims), 0)
        self.assertTrue(all(claim["tier"] in release_audit.VALID_TIERS for claim in claims))
        self.assertTrue(all(claim["limitations"] for claim in claims))
        self.assertFalse(any(claim["tier"] == "DEPLOYMENT_QUALIFIED" for claim in claims))

    def test_build_is_deterministic_and_covers_all_tasks(self) -> None:
        first_audit, first_ledger = release_audit.build_outputs()
        second_audit, second_ledger = release_audit.build_outputs()
        self.assertEqual(first_audit, second_audit)
        self.assertEqual(first_ledger, second_ledger)
        self.assertEqual(first_ledger["source_task_count"], 120)
        self.assertEqual(sum(first_ledger["status_counts"].values()), 120)


if __name__ == "__main__":
    unittest.main()
