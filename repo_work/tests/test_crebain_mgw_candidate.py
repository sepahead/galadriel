"""End-to-end test for the candidate-bound CREBAIN schema/Decimal gate."""

from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import check_crebain_mgw_candidate as candidate_gate


class CrebainMgwCandidateGateTest(unittest.TestCase):
    def test_actual_rust_output_passes_both_candidate_gates(self) -> None:
        receipt = candidate_gate.build_receipt()
        self.assertEqual(receipt["schema"], "galadriel.crebain-mgw-candidate-gate.v1")
        self.assertEqual(receipt["averaged_atom_components_compared"], 66)
        self.assertEqual(receipt["subset_mutual_informations_compared"], 10)
        self.assertEqual(receipt["pointwise_decimal_components_compared"], 0)
        self.assertTrue(receipt["schema_all_passed"])
        self.assertTrue(receipt["decimal_all_passed"])
        self.assertRegex(str(receipt["rust_output_sha256"]), r"^[0-9a-f]{64}$")
        self.assertGreater(receipt["rust_output_bytes"], 0)

    def test_cli_emits_one_canonical_receipt(self) -> None:
        receipt = {
            "schema": "galadriel.crebain-mgw-candidate-gate.v1",
            "schema_all_passed": True,
        }
        stdout = io.StringIO()
        with (
            mock.patch.object(candidate_gate, "build_receipt", return_value=receipt),
            redirect_stdout(stdout),
        ):
            self.assertEqual(candidate_gate.main(), 0)
        expected = json.dumps(
            receipt,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n"
        self.assertEqual(stdout.getvalue(), expected)


if __name__ == "__main__":
    unittest.main()
