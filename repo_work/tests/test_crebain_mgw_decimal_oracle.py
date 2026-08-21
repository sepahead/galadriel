"""Hostile controls for the separate CREBAIN categorical-MGW Decimal route."""

from __future__ import annotations

import hashlib
import json
import copy
import sys
import unittest
from decimal import Decimal, localcontext
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import check_crebain_mgw_decimal_oracle as oracle


def rust_document(result: dict[str, object]) -> dict[str, object]:
    pid2_names = ("red", "unq1", "unq2", "syn")
    source = {
        "kind": "workspace_git",
        "commit_sha1": oracle.PID_CORE_REVISION,
        "working_tree_scope": "crates/pid-core",
        "working_tree": "clean",
    }
    schema_bytes = (oracle.ROOT / oracle.RUST_STUDY_SCHEMA_PATH).read_bytes()
    document: dict[str, object] = {
        "schema": oracle.RUST_STUDY_SCHEMA,
        "machine_schema": {
            "identifier": oracle.RUST_STUDY_SCHEMA,
            "canonical_id": oracle.RUST_STUDY_SCHEMA_ID,
            "repository_path": oracle.RUST_STUDY_SCHEMA_PATH,
            "sha256": hashlib.sha256(schema_bytes).hexdigest(),
            "bytes": len(schema_bytes),
            "closed_world_required": True,
        },
        "fixture_identity": {
            "fixture_sha256": oracle.FIXTURE_SHA256,
            "producer_revision": oracle.CREBAIN_PRODUCER_REVISION,
            "actual_pid_core_version": oracle.PID_CORE_VERSION,
            "actual_pid_core_revision": oracle.PID_CORE_REVISION,
        },
        "sample_estimator_implementation_adaptation": {
            "selected_implementation_revision": oracle.PID_CORE_REVISION,
        },
        "pid_core_software_identity": {"source": source},
        "pid_core_source_reconciliation": {
            "expected_revision": oracle.PID_CORE_REVISION,
            "observed_source": source,
            "pid_core_package_subtree_clean_revision_matched": True,
        },
        "producer_source_errata": {
            "fixture_bytes_retained_unchanged": True,
            "entries": [
                {
                    "source_surface": "analysis_manifest",
                    "json_pointer": "/target_origin",
                },
                {
                    "source_surface": "analysis_manifest",
                    "json_pointer": "/method_exclusions/nis_and_correlation",
                },
                {
                    "source_surface": "fixture_rows",
                    "json_pointer": "/rows/*/fusion_receipt/{projection_count,common_projection_prior_id}",
                },
            ],
            "every_frozen_literal_matched_before_correction": True,
        },
        "primary_question": {
            "ordered_sources": oracle.SOURCE_ORDER[:2],
            "target": "horizontal_incursion",
            "paper_functional_id": oracle.PAPER_FUNCTIONAL_ID,
            "sample_estimator_route_id": oracle.SAMPLE_ESTIMATOR_ROUTE_ID,
            "upstream_implementation_method_catalog_id": (
                oracle.UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID
            ),
            "implementation_entry_point": oracle.PID2_IMPLEMENTATION_ENTRY_POINT,
        },
        "exploratory_question": {
            "ordered_sources": oracle.SOURCE_ORDER,
            "target": "volumetric_incursion",
            "paper_functional_id": oracle.PAPER_FUNCTIONAL_ID,
            "sample_estimator_route_id": oracle.SAMPLE_ESTIMATOR_ROUTE_ID,
            "upstream_implementation_method_catalog_id": (
                oracle.UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID
            ),
            "implementation_entry_point": oracle.PID3_IMPLEMENTATION_ENTRY_POINT,
        },
        "method_eligibility": [
            {"object_id": object_id, "object_kind": object_kind}
            for object_id, object_kind in zip(
                oracle.METHOD_OBJECT_IDS, oracle.METHOD_OBJECT_KINDS, strict=True
            )
        ],
        "estimand_graph": {
            "graph_id": "galadriel.crebain-mgw-estimand-graph.v2",
            "paper_functional_id": oracle.PAPER_FUNCTIONAL_ID,
            "sample_estimator_route_id": oracle.SAMPLE_ESTIMATOR_ROUTE_ID,
            "upstream_implementation_method_catalog_id": (
                oracle.UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID
            ),
            "pid2_implementation_entry_point": oracle.PID2_IMPLEMENTATION_ENTRY_POINT,
            "pid3_implementation_entry_point": oracle.PID3_IMPLEMENTATION_ENTRY_POINT,
            "nodes": [None] * 16,
            "edges": [None] * 24,
            "all_edge_endpoints_resolved": True,
            "declared_topological_order_validated": True,
            "question_method_and_graph_identities_reconciled": True,
            "operational_authority_node_or_edge_kind_absent": True,
        },
        "atom_interpretation": {
            "upstream_implementation_method_catalog_id": (
                oracle.UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID
            ),
            "pointwise_support_mass_and_averaging_matched": True,
            "canonical_pointwise_realization_order_matched": True,
            "every_retained_atom_interpretation_matched": True,
        },
        "resource_receipt": {
            "calls": [
                {
                    "preflight_passed": True,
                    "source_count": 2,
                    "implementation_entry_point": (
                        oracle.PID2_IMPLEMENTATION_ENTRY_POINT
                    ),
                }
                for _ in range(9)
            ]
        },
        "pid2": {
            name: {
                component: float(atom[component])
                for component in (
                    "informative_nats",
                    "misinformative_nats",
                    "net_nats",
                )
            }
            for name, atom in zip(pid2_names, result["pid2"]["atoms"], strict=True)
        },
        "pid3": {
            "antichains": [list(alpha) for alpha in oracle.PID3_ANTICHAINS],
            "atoms": [
                {
                    component: float(atom[component])
                    for component in (
                        "informative_nats",
                        "misinformative_nats",
                        "net_nats",
                    )
                }
                for atom in result["pid3"]["atoms"]
            ],
            "subset_mis": [float(value) for value in result["pid3"]["subset_mi_nats"]],
            "pointwise": [None] * 8,
        },
        "algebra_checks": {
            "all_passed": True,
            "fixed_source_sensitivity": {
                "rotated_pid3_minimum_net_antichain": [4],
                "rotated_pid3_minimum_net_nats": float(
                    result["theorem_controls"]["rotated_pid3_minimum_net_nats"]
                ),
            }
        },
    }
    document["pid2"]["pointwise"] = [None] * 4
    for field, value in zip(
        ("mi_s1_t", "mi_s2_t", "mi_s1s2_t"),
        result["pid2"]["subset_mi_nats"],
        strict=True,
    ):
        document["pid2"][field] = float(value)
    return document


def rust_bytes(document: dict[str, object]) -> bytes:
    return json.dumps(document, allow_nan=False, sort_keys=True).encode("utf-8")


class CrebainMgwDecimalOracleTest(unittest.TestCase):
    def test_declared_and_target_maps_fail_closed(self) -> None:
        document = json.loads(oracle.FIXTURE.read_bytes())
        rows = document["rows"]
        sources = [tuple(int(value) for value in row["sources"]) for row in rows]
        oracle._assert_declared_and_targets(rows, sources)

        wrong_horizontal = copy.deepcopy(rows)
        wrong_horizontal[0]["horizontal_incursion"] ^= 1
        with self.assertRaisesRegex(oracle.OracleError, "horizontal target"):
            oracle._assert_declared_and_targets(wrong_horizontal, sources)

        wrong_volumetric = copy.deepcopy(rows)
        wrong_volumetric[0]["volumetric_incursion"] ^= 1
        with self.assertRaisesRegex(oracle.OracleError, "volumetric target"):
            oracle._assert_declared_and_targets(wrong_volumetric, sources)

    def test_complete_coordinate_digest_and_reconstruction_are_frozen(self) -> None:
        with localcontext() as context:
            context.prec = oracle.PRECISION
            result = oracle.build_oracle()
        self.assertEqual(oracle._component_count(result), 66)
        self.assertEqual(
            hashlib.sha256(oracle.canonical_bytes(result)).hexdigest(),
            oracle.EXPECTED_ORACLE_SHA256,
        )
        self.assertEqual(len(result["pid2"]["subset_mi_nats"]), 3)
        self.assertEqual(len(result["pid3"]["subset_mi_nats"]), 7)
        self.assertEqual(
            result["theorem_controls"]["rotated_pid3_minimum_net_antichain_masks"],
            [4],
        )
        with localcontext() as context:
            context.prec = oracle.PRECISION
            self.assertEqual(
                Decimal(result["theorem_controls"]["rotated_pid3_minimum_net_nats"]),
                oracle.EXPECTED_ROTATED_PID3_MINIMUM_NET.quantize(
                    Decimal(1).scaleb(-oracle.OUTPUT_PLACES)
                ),
            )

    def test_fixed_sources_preserve_only_the_informative_atoms(self) -> None:
        document = json.loads(oracle.FIXTURE.read_bytes())
        rows = document["rows"]
        sources = [tuple(int(value) for value in row["sources"]) for row in rows]
        targets = [int(row["volumetric_incursion"]) for row in rows]
        rotated = targets[1:] + targets[:1]

        with localcontext() as context:
            context.prec = oracle.PRECISION
            original = oracle._mobius_atoms(
                list(zip(sources, targets, strict=True)), oracle.PID3_ANTICHAINS
            )
            control = oracle._mobius_atoms(
                list(zip(sources, rotated, strict=True)), oracle.PID3_ANTICHAINS
            )

        rounding_tolerance = Decimal("1e-75")
        self.assertLessEqual(
            max(
                abs(left.informative - right.informative)
                for left, right in zip(original, control, strict=True)
            ),
            rounding_tolerance,
        )
        self.assertTrue(
            any(
                left.misinformative != right.misinformative
                for left, right in zip(original, control, strict=True)
            )
        )
        self.assertTrue(
            any(
                left.net != right.net
                for left, right in zip(original, control, strict=True)
            )
        )
        minimum_index, minimum_atom = min(
            enumerate(control), key=lambda pair: pair[1].net
        )
        self.assertEqual(oracle.PID3_ANTICHAINS[minimum_index], (4,))
        with localcontext() as context:
            context.prec = oracle.PRECISION
            self.assertLessEqual(
                abs(minimum_atom.net - oracle.EXPECTED_ROTATED_PID3_MINIMUM_NET),
                Decimal("1e-70"),
            )

    def test_rust_json_comparator_is_coordinate_exact_and_fail_closed(self) -> None:
        with localcontext() as context:
            context.prec = oracle.PRECISION
            result = oracle.build_oracle()

        rust = rust_document(result)
        encoded = rust_bytes(rust)
        receipt = oracle.compare_rust_output(result, encoded)
        self.assertTrue(receipt["all_passed"])
        self.assertEqual(receipt["averaged_atom_components_compared"], 66)
        self.assertEqual(receipt["subset_mutual_informations_compared"], 10)
        self.assertEqual(receipt["rust_json_sha256"], hashlib.sha256(encoded).hexdigest())
        self.assertEqual(receipt["rust_json_bytes"], len(encoded))

        rust["pid3"]["atoms"][0]["net_nats"] += 1.0e-10
        with self.assertRaisesRegex(oracle.OracleError, "exceeded tolerance"):
            oracle.compare_rust_output(result, rust_bytes(rust))

    def test_rust_json_comparator_rejects_wrong_custody_and_cardinality(self) -> None:
        with localcontext() as context:
            context.prec = oracle.PRECISION
            result = oracle.build_oracle()
        baseline = rust_document(result)

        mutations = []
        wrong_schema = copy.deepcopy(baseline)
        wrong_schema["schema"] = "galadriel.crebain-drone-mgw-study.v1"
        mutations.append(("schema", wrong_schema))
        wrong_schema_receipt = copy.deepcopy(baseline)
        wrong_schema_receipt["machine_schema"]["sha256"] = "0" * 64
        mutations.append(("schema receipt", wrong_schema_receipt))
        wrong_fixture = copy.deepcopy(baseline)
        wrong_fixture["fixture_identity"]["fixture_sha256"] = "0" * 64
        mutations.append(("fixture", wrong_fixture))
        wrong_revision = copy.deepcopy(baseline)
        wrong_revision["fixture_identity"]["actual_pid_core_revision"] = "1" * 40
        mutations.append(("revision", wrong_revision))
        dirty_source = copy.deepcopy(baseline)
        dirty_source["pid_core_source_reconciliation"]["observed_source"][
            "working_tree"
        ] = "dirty"
        dirty_source["pid_core_software_identity"]["source"]["working_tree"] = "dirty"
        mutations.append(("source", dirty_source))
        extra_atom = copy.deepcopy(baseline)
        extra_atom["pid3"]["atoms"].append(copy.deepcopy(extra_atom["pid3"]["atoms"][0]))
        mutations.append(("extra atom", extra_atom))
        extra_mi = copy.deepcopy(baseline)
        extra_mi["pid3"]["subset_mis"].append(0.0)
        mutations.append(("extra MI", extra_mi))
        truncated_pointwise = copy.deepcopy(baseline)
        truncated_pointwise["pid2"]["pointwise"].pop()
        mutations.append(("truncated pointwise", truncated_pointwise))
        false_graph_receipt = copy.deepcopy(baseline)
        false_graph_receipt["estimand_graph"][
            "operational_authority_node_or_edge_kind_absent"
        ] = False
        mutations.append(("authority graph", false_graph_receipt))
        forked_graph_identity = copy.deepcopy(baseline)
        forked_graph_identity["estimand_graph"]["paper_functional_id"] = (
            "functional.provenance-fork"
        )
        mutations.append(("graph functional identity", forked_graph_identity))
        swapped_functional_role = copy.deepcopy(baseline)
        swapped_functional_role["method_eligibility"][0]["object_kind"] = (
            "sample_estimator_route"
        )
        mutations.append(("functional/sample-estimator role", swapped_functional_role))
        crossed_primary_entry_point = copy.deepcopy(baseline)
        crossed_primary_entry_point["primary_question"]["implementation_entry_point"] = (
            oracle.PID3_IMPLEMENTATION_ENTRY_POINT
        )
        mutations.append(("crossed PID entry point", crossed_primary_entry_point))
        invalid_resource_source_count = copy.deepcopy(baseline)
        invalid_resource_source_count["resource_receipt"]["calls"][0][
            "source_count"
        ] = 4
        mutations.append(("invalid resource source count", invalid_resource_source_count))
        crossed_resource_entry_point = copy.deepcopy(baseline)
        crossed_resource_entry_point["resource_receipt"]["calls"][0][
            "implementation_entry_point"
        ] = oracle.PID3_IMPLEMENTATION_ENTRY_POINT
        mutations.append(("crossed resource entry point", crossed_resource_entry_point))
        missing_erratum = copy.deepcopy(baseline)
        missing_erratum["producer_source_errata"]["entries"].pop()
        mutations.append(("producer source erratum", missing_erratum))
        reordered_methods = copy.deepcopy(baseline)
        reordered_methods["method_eligibility"][0], reordered_methods[
            "method_eligibility"
        ][1] = (
            reordered_methods["method_eligibility"][1],
            reordered_methods["method_eligibility"][0],
        )
        mutations.append(("method identity order", reordered_methods))

        for name, mutated in mutations:
            with self.subTest(name=name), self.assertRaises(oracle.OracleError):
                oracle.compare_rust_output(result, rust_bytes(mutated))

    def test_rust_json_comparator_rejects_duplicate_keys_and_huge_numbers(self) -> None:
        with localcontext() as context:
            context.prec = oracle.PRECISION
            result = oracle.build_oracle()
        baseline = rust_bytes(rust_document(result))
        duplicate = baseline.replace(
            b'{"algebra_checks":',
            b'{"schema":"duplicate","algebra_checks":',
            1,
        )
        with self.assertRaisesRegex(oracle.OracleError, "duplicate JSON key"):
            oracle.compare_rust_output(result, duplicate)

        huge = copy.deepcopy(rust_document(result))
        huge["pid2"]["red"]["net_nats"] = 10**1000
        with self.assertRaisesRegex(oracle.OracleError, "binary64 exponent envelope"):
            oracle.compare_rust_output(result, rust_bytes(huge))


if __name__ == "__main__":
    unittest.main()
