"""Tests for the non-circular source task-closure plan."""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from repo_work import build_task_dispositions


class TaskClosurePlanTests(unittest.TestCase):
    def test_json_helpers_reject_nonfinite_and_oversized_numbers(self) -> None:
        target = build_task_dispositions.ROOT / "target"
        target.mkdir(exist_ok=True)
        invalid_documents = (
            '{"value": NaN}',
            '{"value": 1e1000000}',
            '{"value": 1e-1000000}',
            '{"value": ' + "9" * 5_000 + "}",
        )
        with tempfile.TemporaryDirectory(dir=target) as directory:
            path = Path(directory) / "invalid.json"
            for document in invalid_documents:
                with self.subTest(document=document[:40]):
                    path.write_text(document, encoding="utf-8")
                    with self.assertRaisesRegex(
                        build_task_dispositions.DispositionError, "cannot load"
                    ):
                        build_task_dispositions.load_json(path)

        for encoder in (
            build_task_dispositions.canonical_bytes,
            build_task_dispositions.compact_canonical_bytes,
        ):
            with self.subTest(encoder=encoder.__name__):
                with self.assertRaisesRegex(
                    build_task_dispositions.DispositionError,
                    "cannot encode canonical JSON",
                ):
                    encoder({"value": float("nan")})
                with self.assertRaisesRegex(
                    build_task_dispositions.DispositionError,
                    "cannot encode canonical JSON",
                ):
                    encoder({"value": 10**128})

    def test_static_plan_covers_t000_through_t115_without_complete_results(self) -> None:
        tasks = build_task_dispositions.validate_tasks()
        claims = build_task_dispositions.validate_claims()
        plan = build_task_dispositions.validate_plan(tasks, claims)

        self.assertEqual(
            [entry["task_id"] for entry in plan["tasks"]],
            [f"T{number:03d}" for number in range(116)],
        )
        self.assertEqual(
            sum(entry["status"] == "PENDING_POST_COMMIT" for entry in plan["tasks"]),
            107,
        )
        self.assertEqual(
            sum(entry["status"] == "NOT_CLAIMED" for entry in plan["tasks"]), 9
        )
        self.assertNotIn("COMPLETE", {entry["status"] for entry in plan["tasks"]})
        by_id = {entry["task_id"]: entry for entry in plan["tasks"]}
        for task_id in ("T096", "T097"):
            self.assertEqual(by_id[task_id]["status"], "NOT_CLAIMED")
            self.assertEqual(by_id[task_id]["claim_removal_links"], ["CLM-013"])

    def test_plan_contains_questions_not_synthesized_lens_findings(self) -> None:
        plan = build_task_dispositions.validate_plan()
        for entry in plan["tasks"]:
            with self.subTest(task=entry["task_id"]):
                review = entry["source_projection"]["twenty_lens_review"]
                self.assertEqual(
                    tuple(review), build_task_dispositions.LENSES
                )
                self.assertNotIn("review", entry)
                self.assertTrue(all(value["status"] == "OPEN" for value in review.values()))
                self.assertTrue(all(value["finding"] == "" for value in review.values()))
                self.assertTrue(all(value["evidence"] == "" for value in review.values()))

    def test_every_plan_entry_is_task_specific_and_has_rejection_cases(self) -> None:
        tasks = build_task_dispositions.validate_tasks()
        plan = build_task_dispositions.validate_plan(tasks)
        for task, entry in zip(tasks, plan["tasks"], strict=True):
            with self.subTest(task=task["id"]):
                self.assertTrue(all(task["id"] in item for item in entry["accepted_cases"]))
                self.assertTrue(
                    all(task["id"] in item["rejection_rule"] for item in entry["rejected_cases"])
                )
                self.assertTrue(
                    entry["evidence_types"]
                    == entry["source_projection"]["required_evidence"]
                )
                self.assertEqual(
                    set(entry["source_projection"]["twenty_lens_review"]),
                    set(build_task_dispositions.LENSES),
                )

    def test_not_claimed_set_is_exact_and_links_only_excluded_claims(self) -> None:
        claims = build_task_dispositions.validate_claims()
        plan = build_task_dispositions.validate_plan(claims=claims)
        actual = {
            entry["task_id"]: tuple(entry["claim_removal_links"])
            for entry in plan["tasks"]
            if entry["status"] == "NOT_CLAIMED"
        }
        self.assertEqual(actual, build_task_dispositions.NOT_CLAIMED_TASKS)
        self.assertTrue(
            all(
                claims[claim_id]["tier"] == "NOT_CLAIMED"
                for claim_ids in actual.values()
                for claim_id in claim_ids
            )
        )

    def test_source_lens_substitution_is_rejected(self) -> None:
        plan = copy.deepcopy(build_task_dispositions.load_json(build_task_dispositions.PLAN_PATH))
        plan["tasks"][0]["source_projection"]["twenty_lens_review"]["L01"]["question"] = (
            "Can a generic replacement question stand in for the exact immutable source lens?"
        )
        projection = plan["tasks"][0]["source_projection"]
        plan["tasks"][0]["source_projection_sha256"] = __import__("hashlib").sha256(
            build_task_dispositions.compact_canonical_bytes(projection)
        ).hexdigest()
        with self.assertRaisesRegex(
            build_task_dispositions.DispositionError, "source lens question changed"
        ):
            build_task_dispositions.validate_plan(document=plan)

    def test_source_dispositions_cannot_contain_future_results(self) -> None:
        original = build_task_dispositions.load_json(
            build_task_dispositions.SOURCE_DISPOSITIONS_PATH
        )
        invalid = copy.deepcopy(original)
        invalid["dispositions"] = [{"task_id": "T000", "status": "COMPLETE"}]
        original_loader = build_task_dispositions.load_json
        try:
            build_task_dispositions.load_json = lambda path: (
                invalid
                if path == build_task_dispositions.SOURCE_DISPOSITIONS_PATH
                else original_loader(path)
            )
            with self.assertRaisesRegex(
                build_task_dispositions.DispositionError, "must remain empty"
            ):
                build_task_dispositions.validate_source_dispositions()
        finally:
            build_task_dispositions.load_json = original_loader

    def test_static_plan_is_canonical_json(self) -> None:
        plan = build_task_dispositions.load_json(build_task_dispositions.PLAN_PATH)
        self.assertEqual(
            build_task_dispositions.PLAN_PATH.read_bytes(),
            build_task_dispositions.canonical_bytes(plan),
        )


if __name__ == "__main__":
    unittest.main()
