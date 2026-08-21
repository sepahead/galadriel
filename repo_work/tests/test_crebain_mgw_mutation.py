"""Hostile tests for the bounded CREBAIN MGW mutation gate."""

from __future__ import annotations

import copy
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import check_crebain_mgw_mutation as gate
from common import ReviewError, canonical_json


CARGO = "/toolchains/1.89.0/bin/cargo"
COMMIT = "1" * 40
TREE = "2" * 40


def span(line: int, start: int, end: int) -> dict[str, dict[str, int]]:
    return {
        "start": {"line": line, "column": start},
        "end": {"line": line, "column": end},
    }


def descriptor(
    *,
    function: str,
    return_type: str,
    line: int,
    transformation: str,
    replacement: str,
    genre: str,
) -> dict[str, Any]:
    return {
        "name": f"{gate.SOURCE_FILE}:{line}:5: {transformation}",
        "package": gate.PACKAGE,
        "file": gate.SOURCE_FILE,
        "function": {
            "function_name": function,
            "return_type": return_type,
            "span": {
                "start": {"line": line - 1, "column": 1},
                "end": {"line": line + 2, "column": 2},
            },
        },
        "span": span(line, 5, 7),
        "replacement": replacement,
        "genre": genre,
    }


def phase(phase_name: str, *, success: bool) -> dict[str, Any]:
    arguments = [
        CARGO,
        "test",
        *(["--no-run"] if phase_name == "Build" else []),
        "--verbose",
        f"--package={gate.PACKAGE}@{gate.PACKAGE_VERSION}",
        "--all-features",
        "--locked",
    ]
    if phase_name == "Test":
        arguments.extend(["--lib", gate.TEST_FILTER])
    return {
        "phase": phase_name,
        "duration": 0.25,
        "process_status": "Success" if success else {"Failure": 101},
        "argv": arguments,
    }


def fixture() -> tuple[
    dict[str, Any],
    dict[str, int],
    str,
    frozenset[tuple[str, str, str, str, str]],
]:
    caught = descriptor(
        function="max_abs",
        return_type="-> f64",
        line=100,
        transformation="replace max_abs -> f64 with 0.0",
        replacement="0.0",
        genre="FnValue",
    )
    unviable = descriptor(
        function="validate_rows",
        return_type="-> Result<ValidatedColumns>",
        line=200,
        transformation=(
            "replace validate_rows -> Result<ValidatedColumns> with "
            "Ok(Default::default())"
        ),
        replacement="Ok(Default::default())",
        genre="FnValue",
    )
    document = {
        "outcomes": [
            {
                "scenario": "Baseline",
                "summary": "Success",
                "log_path": "log/baseline.log",
                "diff_path": None,
                "phase_results": [
                    phase("Build", success=True),
                    phase("Test", success=True),
                ],
            },
            {
                "scenario": {"Mutant": caught},
                "summary": "CaughtMutant",
                "log_path": "log/caught.log",
                "diff_path": "diff/caught.diff",
                "phase_results": [
                    phase("Build", success=True),
                    phase("Test", success=False),
                ],
            },
            {
                "scenario": {"Mutant": unviable},
                "summary": "Unviable",
                "log_path": "log/unviable.log",
                "diff_path": "diff/unviable.diff",
                "phase_results": [phase("Build", success=False)],
            },
        ],
        "total_mutants": 2,
        "missed": 0,
        "caught": 1,
        "timeout": 0,
        "unviable": 1,
        "success": 0,
        "start_time": "2026-08-18T00:00:00Z",
        "end_time": "2026-08-18T00:01:00Z",
        "cargo_mutants_version": "27.1.0",
    }
    mutants = [
        gate._mutant(caught, "caught"),
        gate._mutant(unviable, "unviable"),
    ]
    counts = {
        "total_mutants": 2,
        "missed": 0,
        "caught": 1,
        "timeout": 0,
        "unviable": 1,
        "success": 0,
    }
    unviable_identity = frozenset({mutants[1].unviable_identity})
    return document, counts, gate.normalized_mutant_digest(mutants), unviable_identity


def validate_fixture(document: dict[str, Any]) -> dict[str, Any]:
    _original, counts, digest, unviable = fixture()
    return gate.validate_outcomes_document(
        document,
        expected_cargo_executable=CARGO,
        expected_counts=counts,
        expected_digest=digest,
        expected_unviable=unviable,
    )


class CrebainMgwMutationGateTest(unittest.TestCase):
    def test_reference_outcomes_pass_complete_contract(self) -> None:
        document, counts, digest, _unviable = fixture()
        result = validate_fixture(document)
        self.assertEqual(result["counts"], counts)
        self.assertEqual(result["normalized_mutants_sha256"], digest)
        self.assertEqual(result["unviable"], ["validate_rows"])

    def test_normalized_digest_allows_only_line_movement(self) -> None:
        document, _counts, digest, _unviable = fixture()
        shifted = copy.deepcopy(document)
        for outcome in shifted["outcomes"][1:]:
            mutant = outcome["scenario"]["Mutant"]
            old_line = mutant["span"]["start"]["line"]
            new_line = old_line + 400
            mutant["name"] = mutant["name"].replace(
                f":{old_line}:5:", f":{new_line}:5:", 1
            )
            for target in (mutant["span"], mutant["function"]["span"]):
                target["start"]["line"] += 400
                target["end"]["line"] += 400
        mutants = [
            gate._mutant(outcome["scenario"]["Mutant"], "shifted")
            for outcome in shifted["outcomes"][1:]
        ]
        self.assertEqual(gate.normalized_mutant_digest(mutants), digest)
        validate_fixture(shifted)

    def test_changed_transformation_fails_multiset_digest(self) -> None:
        document, _counts, _digest, _unviable = fixture()
        changed = copy.deepcopy(document)
        mutant = changed["outcomes"][1]["scenario"]["Mutant"]
        mutant["name"] = mutant["name"].replace("with 0.0", "with 1.0")
        mutant["replacement"] = "1.0"
        with self.assertRaisesRegex(ReviewError, "digest differs"):
            validate_fixture(changed)

    def test_unviable_reclassification_fails_allowlist(self) -> None:
        document, _counts, digest, unviable = fixture()
        changed = copy.deepcopy(document)
        outcome = changed["outcomes"][2]
        outcome["summary"] = "CaughtMutant"
        outcome["phase_results"] = [
            phase("Build", success=True),
            phase("Test", success=False),
        ]
        changed["caught"] = 2
        changed["unviable"] = 0
        counts = {
            "total_mutants": 2,
            "missed": 0,
            "caught": 2,
            "timeout": 0,
            "unviable": 0,
            "success": 0,
        }
        with self.assertRaisesRegex(ReviewError, "unviable allowlist differs"):
            gate.validate_outcomes_document(
                changed,
                expected_cargo_executable=CARGO,
                expected_counts=counts,
                expected_digest=digest,
                expected_unviable=unviable,
            )

    def test_missed_mutant_cannot_pass_with_consistent_counts(self) -> None:
        document, _counts, digest, unviable = fixture()
        changed = copy.deepcopy(document)
        changed["outcomes"][1]["summary"] = "MissedMutant"
        changed["outcomes"][1]["phase_results"][1] = phase(
            "Test", success=True
        )
        changed["caught"] = 0
        changed["missed"] = 1
        counts = {
            "total_mutants": 2,
            "missed": 1,
            "caught": 0,
            "timeout": 0,
            "unviable": 1,
            "success": 0,
        }
        with self.assertRaisesRegex(ReviewError, "missed, timed out, or survived"):
            gate.validate_outcomes_document(
                changed,
                expected_cargo_executable=CARGO,
                expected_counts=counts,
                expected_digest=digest,
                expected_unviable=unviable,
            )

    def test_wrong_test_filter_fails_phase_contract(self) -> None:
        document, _counts, _digest, _unviable = fixture()
        changed = copy.deepcopy(document)
        changed["outcomes"][1]["phase_results"][1]["argv"][-1] = "other::tests"
        with self.assertRaisesRegex(ReviewError, "another Cargo command"):
            validate_fixture(changed)

    def test_duplicate_descriptor_fails_even_when_counts_match(self) -> None:
        document, _counts, _digest, unviable = fixture()
        changed = copy.deepcopy(document)
        duplicate = copy.deepcopy(changed["outcomes"][1])
        duplicate["log_path"] = "log/duplicate.log"
        duplicate["diff_path"] = "diff/duplicate.diff"
        changed["outcomes"].insert(2, duplicate)
        changed["total_mutants"] = 3
        changed["caught"] = 2
        descriptor_value = duplicate["scenario"]["Mutant"]
        mutants = [
            gate._mutant(changed["outcomes"][1]["scenario"]["Mutant"], "one"),
            gate._mutant(descriptor_value, "two"),
            gate._mutant(changed["outcomes"][3]["scenario"]["Mutant"], "three"),
        ]
        counts = {
            "total_mutants": 3,
            "missed": 0,
            "caught": 2,
            "timeout": 0,
            "unviable": 1,
            "success": 0,
        }
        with self.assertRaisesRegex(ReviewError, "duplicates another descriptor"):
            gate.validate_outcomes_document(
                changed,
                expected_cargo_executable=CARGO,
                expected_counts=counts,
                expected_digest=gate.normalized_mutant_digest(mutants),
                expected_unviable=unviable,
            )

    def test_listing_rejects_duplicate_json_members(self) -> None:
        with self.assertRaisesRegex(ReviewError, "duplicate JSON key"):
            gate.validate_listing(
                b'[{"name":"first","name":"second"}]',
                expected_count=1,
                expected_digest="0" * 64,
            )

    def test_listing_binds_diff_header_and_digest(self) -> None:
        document, _counts, digest, _unviable = fixture()
        listing = []
        for outcome in document["outcomes"][1:]:
            item = copy.deepcopy(outcome["scenario"]["Mutant"])
            prefix = (
                f"{gate.SOURCE_FILE}:"
                f"{item['span']['start']['line']}:"
                f"{item['span']['start']['column']}: "
            )
            transformation = item["name"].removeprefix(prefix)
            item["diff"] = f"--- {gate.SOURCE_FILE}\n+++ {transformation}\n@@\n"
            listing.append(item)
        result = gate.validate_listing(
            canonical_json(listing), expected_count=2, expected_digest=digest
        )
        self.assertEqual(result, {"count": 2, "normalized_sha256": digest})
        listing[0]["diff"] = "--- wrong.rs\n+++ wrong\n"
        with self.assertRaisesRegex(ReviewError, "diff header"):
            gate.validate_listing(
                canonical_json(listing), expected_count=2, expected_digest=digest
            )

    def test_receipt_binds_outcome_bytes_command_and_candidate(self) -> None:
        outcome_document, counts, digest, unviable = fixture()
        outcome_bytes = canonical_json(outcome_document)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outcome_path = root / gate.OUTCOMES_RELATIVE
            outcome_path.parent.mkdir(parents=True)
            outcome_path.write_bytes(outcome_bytes)
            receipt = {
                "schema": gate.RECEIPT_SCHEMA,
                "candidate": {"commit": COMMIT, "tree": TREE},
                "github_run": {
                    "run_id": "123",
                    "run_attempt": "1",
                    "job": gate.GITHUB_JOB,
                    "workflow": "Deep quality",
                    "repository": "sepahead/galadriel",
                    "ref": "refs/heads/main",
                    "sha": COMMIT,
                },
                "environment_contract": gate.MUTATION_ENVIRONMENT_CONTRACT,
                "toolchain": {
                    "cargo": gate.CARGO_IDENTITY,
                    "cargo_executable": CARGO,
                    "cargo_mutants": gate.CARGO_MUTANTS_IDENTITY,
                    "rustc": gate.RUSTC_IDENTITY,
                },
                "selector": {
                    "package": gate.PACKAGE,
                    "source_file": gate.SOURCE_FILE,
                    "examine_re": gate.EXAMINE_RE,
                    "test_filter": gate.TEST_FILTER,
                },
                "command_argv": gate.mutation_command(),
                "listing": {
                    "count": counts["total_mutants"],
                    "normalized_sha256": digest,
                },
                "counts": counts,
                "normalized_mutants_sha256": digest,
                "unviable_functions": sorted(
                    identity[0] for identity in unviable
                ),
                "outcomes": {
                    "path": gate.OUTCOMES_RELATIVE,
                    "sha256": hashlib.sha256(outcome_bytes).hexdigest(),
                    "size_bytes": len(outcome_bytes),
                },
            }
            receipt_path = root / gate.RECEIPT_NAME
            receipt_path.write_bytes(canonical_json(receipt))
            gate.validate_receipt(
                receipt_path,
                root=root,
                commit=COMMIT,
                tree=TREE,
                expected_counts=counts,
                expected_digest=digest,
                expected_unviable=unviable,
            )

            changed = copy.deepcopy(receipt)
            changed["command_argv"][changed["command_argv"].index("1")] = "4"
            receipt_path.write_bytes(canonical_json(changed))
            with self.assertRaisesRegex(ReviewError, "another command"):
                gate.validate_receipt(
                    receipt_path,
                    root=root,
                    commit=COMMIT,
                    tree=TREE,
                    expected_counts=counts,
                    expected_digest=digest,
                    expected_unviable=unviable,
                )

            changed = copy.deepcopy(receipt)
            changed["candidate"]["tree"] = "3" * 40
            receipt_path.write_bytes(canonical_json(changed))
            with self.assertRaisesRegex(ReviewError, "another candidate"):
                gate.validate_receipt(
                    receipt_path,
                    root=root,
                    commit=COMMIT,
                    tree=TREE,
                    expected_counts=counts,
                    expected_digest=digest,
                    expected_unviable=unviable,
                )

    def test_github_provenance_binds_dedicated_job(self) -> None:
        environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_JOB": gate.GITHUB_JOB,
            "GITHUB_WORKFLOW": "Deep quality",
            "GITHUB_REPOSITORY": "sepahead/galadriel",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": COMMIT,
            "MUTATION_CANDIDATE_SHA": COMMIT,
        }
        result = gate.github_run_provenance(
            environment, COMMIT, expected_job=gate.GITHUB_JOB
        )
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["job"], gate.GITHUB_JOB)

        environment["GITHUB_JOB"] = "mutation-diff"
        with self.assertRaisesRegex(ReviewError, "job is not canonical"):
            gate.github_run_provenance(
                environment, COMMIT, expected_job=gate.GITHUB_JOB
            )


if __name__ == "__main__":
    unittest.main()
