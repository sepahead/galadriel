"""Hostile controls for the closed CREBAIN categorical-MGW v3 JSON Schema."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import check_crebain_mgw_schema as checker


ROOT = Path(__file__).resolve().parents[2]
# This receipt is intentionally frozen after every reviewed schema edit.  It is
# not the Rust study-output digest and it is not a scientific-result oracle.
EXPECTED_SCHEMA_SHA256 = "075e8905a1972772a413e6b3a0928303aec4f1c547ddbd0c281226433fb86b88"
EXPECTED_SCHEMA_BYTES = 61857


class CrebainMgwSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        completed = subprocess.run(
            [
                "rustup",
                "run",
                "1.89.0",
                "cargo",
                "run",
                "--locked",
                "--offline",
                "-q",
                "-p",
                "galadriel-justify",
                "--bin",
                "galadriel-crebain-mgw",
                "--",
                "--format",
                "json",
            ],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=240,
        )
        if completed.returncode != 0:
            diagnostic = completed.stderr.decode("utf-8", "replace")[:4096]
            raise RuntimeError(
                "exact Rust schema fixture command failed with exit status "
                f"{completed.returncode}: {diagnostic}"
            )
        cls.actual_bytes = completed.stdout
        with tempfile.NamedTemporaryFile(suffix=".json") as output:
            output.write(cls.actual_bytes)
            output.flush()
            cls.actual, _ = checker.load_json_document(
                Path(output.name), maximum_bytes=checker.MAX_INSTANCE_BYTES
            )
        cls.schema, cls.schema_bytes = checker.load_schema()

    def assert_rejected(self, mutation: object, expression: str | None = None) -> None:
        with self.assertRaises(checker.ContractError) as caught:
            checker.validate_document(mutation, self.schema)
        if expression is not None:
            self.assertRegex(str(caught.exception), expression)

    def test_exact_binary_output_validates_and_schema_identity_is_frozen(self) -> None:
        checker.validate_document(self.actual, self.schema)
        checker.validate_machine_schema_binding(self.actual, self.schema_bytes)
        checker.validate_semantic_identity_bindings(self.actual)
        identity = checker.schema_identity(self.schema_bytes)
        self.assertEqual(identity.sha256, EXPECTED_SCHEMA_SHA256)
        self.assertEqual(identity.size_bytes, EXPECTED_SCHEMA_BYTES)

        with tempfile.NamedTemporaryFile(suffix=".json") as output:
            output.write(self.actual_bytes)
            output.flush()
            receipt = checker.check_paths(Path(output.name))
        self.assertIn(f"schema_sha256={EXPECTED_SCHEMA_SHA256}", receipt)
        self.assertIn(f"schema_bytes={EXPECTED_SCHEMA_BYTES}", receipt)
        self.assertIn(
            f"instance_sha256={hashlib.sha256(self.actual_bytes).hexdigest()}", receipt
        )
        self.assertIn(f"instance_bytes={len(self.actual_bytes)}", receipt)

    def test_machine_schema_digest_and_size_are_bound_to_exact_schema_bytes(self) -> None:
        wrong_digest = copy.deepcopy(self.actual)
        wrong_digest["machine_schema"]["sha256"] = "0" * 64
        checker.validate_document(wrong_digest, self.schema)
        with self.assertRaisesRegex(checker.ContractError, "sha256 does not match"):
            checker.validate_machine_schema_binding(wrong_digest, self.schema_bytes)

        wrong_size = copy.deepcopy(self.actual)
        wrong_size["machine_schema"]["bytes"] += 1
        checker.validate_document(wrong_size, self.schema)
        with self.assertRaisesRegex(checker.ContractError, "bytes does not match"):
            checker.validate_machine_schema_binding(wrong_size, self.schema_bytes)

    def test_manifest_and_pid_core_reference_identity_tuples_are_exact(self) -> None:
        wrong_manifest = copy.deepcopy(self.actual)
        wrong_manifest["fixture_identity"]["analysis_manifest_sha256"] = "0" * 64
        checker.validate_document(wrong_manifest, self.schema)
        with self.assertRaisesRegex(checker.ContractError, "frozen manifest"):
            checker.validate_semantic_identity_bindings(wrong_manifest)

        crossed_reference = copy.deepcopy(self.actual)
        crossed_reference["pid_core_software_identity"]["reference_artifacts"][0][
            "canonical_json_sha256"
        ] = crossed_reference["pid_core_software_identity"]["reference_artifacts"][1][
            "canonical_json_sha256"
        ]
        checker.validate_document(crossed_reference, self.schema)
        with self.assertRaisesRegex(checker.ContractError, "exact ordered bc3"):
            checker.validate_semantic_identity_bindings(crossed_reference)

        swapped_references = copy.deepcopy(self.actual)
        swapped_references["pid_core_software_identity"]["reference_artifacts"].reverse()
        checker.validate_document(swapped_references, self.schema)
        with self.assertRaisesRegex(checker.ContractError, "exact ordered bc3"):
            checker.validate_semantic_identity_bindings(swapped_references)

    def test_missing_and_extra_members_fail_at_root_and_nested_boundaries(self) -> None:
        missing = copy.deepcopy(self.actual)
        del missing["pid2"]
        self.assert_rejected(missing, "missing required member.*pid2")

        extra_root = copy.deepcopy(self.actual)
        extra_root["shape_sentinel"] = "not a schema"
        self.assert_rejected(extra_root, "undeclared member.*shape_sentinel")

        extra_nested = copy.deepcopy(self.actual)
        extra_nested["pid3"]["atoms"][0]["unreviewed_component"] = 0.0
        self.assert_rejected(extra_nested, "unreviewed_component")

    def test_every_declared_cardinality_guard_rejects_a_single_deletion(self) -> None:
        array_paths = (
            ("pid2", "pointwise"),
            ("pid3", "pointwise"),
            ("pid3", "atoms"),
            ("pid3", "antichains"),
            ("pid3", "subset_mis"),
            ("producer_source_errata", "entries"),
            ("method_eligibility",),
            ("estimand_graph", "nodes"),
            ("estimand_graph", "edges"),
            ("resource_receipt", "calls"),
        )
        for path in array_paths:
            with self.subTest(path=path):
                mutation = copy.deepcopy(self.actual)
                target = mutation
                for component in path:
                    target = target[component]
                target.pop()
                self.assert_rejected(mutation)

        pointwise_atom_mutation = copy.deepcopy(self.actual)
        pointwise_atom_mutation["pid3"]["pointwise"][0]["atoms"].pop()
        self.assert_rejected(pointwise_atom_mutation, "minimum")

    def test_wire_enum_and_important_constants_are_closed(self) -> None:
        mutations: list[tuple[str, object]] = []

        wrong_enum = copy.deepcopy(self.actual)
        wrong_enum["method_eligibility"][0]["object_kind"] = "pid"
        mutations.append(("enum|constant", wrong_enum))

        wrong_reference_role = copy.deepcopy(self.actual)
        wrong_reference_role["primary_question"]["reference_edges"][0]["role"] = (
            "defines_everything"
        )
        mutations.append(("enum", wrong_reference_role))

        wrong_graph_enum = copy.deepcopy(self.actual)
        wrong_graph_enum["estimand_graph"]["edges"][0]["kind"] = "authorizes"
        mutations.append(("enum", wrong_graph_enum))

        wrong_schema = copy.deepcopy(self.actual)
        wrong_schema["schema"] = "galadriel.crebain-drone-mgw-study.v1"
        mutations.append(("constant", wrong_schema))

        wrong_pid_revision = copy.deepcopy(self.actual)
        wrong_pid_revision["fixture_identity"]["actual_pid_core_revision"] = "0" * 40
        mutations.append(("constant", wrong_pid_revision))

        wrong_graph_id = copy.deepcopy(self.actual)
        wrong_graph_id["estimand_graph"]["graph_id"] = "graph-without-reviewed-boundary"
        mutations.append(("constant", wrong_graph_id))

        wrong_antichain_order = copy.deepcopy(self.actual)
        wrong_antichain_order["pid3"]["antichains"][0] = [7]
        mutations.append(("constant", wrong_antichain_order))

        for expression, mutation in mutations:
            with self.subTest(expression=expression):
                self.assert_rejected(mutation, expression)

    def test_functional_sample_estimator_and_arity_identities_cannot_cross(self) -> None:
        swapped_method_roles = copy.deepcopy(self.actual)
        swapped_method_roles["method_eligibility"][0]["object_kind"] = (
            "sample_estimator_route"
        )
        swapped_method_roles["method_eligibility"][1]["object_kind"] = "functional"
        self.assert_rejected(swapped_method_roles, "required constant")

        swapped_graph_roles = copy.deepcopy(self.actual)
        functional = next(
            node
            for node in swapped_graph_roles["estimand_graph"]["nodes"]
            if node["node_id"] == "functional.shared-exclusions.mgw-categorical"
        )
        sample_estimator = next(
            node
            for node in swapped_graph_roles["estimand_graph"]["nodes"]
            if node["node_id"] == "route.shared-exclusions.mgw-empirical-pmf"
        )
        functional["kind"], sample_estimator["kind"] = (
            sample_estimator["kind"],
            functional["kind"],
        )
        self.assert_rejected(swapped_graph_roles, "required constant")

        crossed_entry_points = copy.deepcopy(self.actual)
        submitted = next(
            edge
            for edge in crossed_entry_points["estimand_graph"]["edges"]
            if edge["kind"] == "submitted_to" and edge["from"] == "pmf.horizontal"
        )
        submitted["to"] = (
            "pid_core::stable::categorical::discrete_sxpid3_with_budget"
        )
        self.assert_rejected(crossed_entry_points, "required constant")

        crossed_resource_call = copy.deepcopy(self.actual)
        crossed_resource_call["resource_receipt"]["calls"][0][
            "implementation_entry_point"
        ] = "pid_core::stable::categorical::discrete_sxpid3_with_budget"
        self.assert_rejected(crossed_resource_call, "required constant")

    def test_types_bounds_patterns_and_duplicate_items_fail_closed(self) -> None:
        wrong_type = copy.deepcopy(self.actual)
        wrong_type["fixture_validation"]["row_count"] = "64"
        self.assert_rejected(wrong_type, "constant")

        wrong_probability = copy.deepcopy(self.actual)
        wrong_probability["pid2"]["pointwise"][0]["empirical_probability"] = 1.1
        self.assert_rejected(wrong_probability, "above its maximum")

        wrong_digest = copy.deepcopy(self.actual)
        wrong_digest["fixture_validation"]["row_order_sha256"] = "not-a-digest"
        self.assert_rejected(wrong_digest, "pattern")

        duplicate_method = copy.deepcopy(self.actual)
        duplicate_method["method_eligibility"][1] = copy.deepcopy(
            duplicate_method["method_eligibility"][0]
        )
        self.assert_rejected(duplicate_method, "duplicate items")

        huge_text = copy.deepcopy(self.actual)
        huge_text["interpretation_guard"] = "x" * 4097
        self.assert_rejected(huge_text, "maxLength")

    def test_nonfinite_overflowing_and_oversized_json_are_rejected_before_schema_use(self) -> None:
        for encoded in (b'{"x": NaN}', b'{"x": Infinity}', b'{"x": 1e9999}'):
            with self.subTest(encoded=encoded):
                with tempfile.NamedTemporaryFile(suffix=".json") as document:
                    document.write(encoded)
                    document.flush()
                    with self.assertRaises(checker.ContractError):
                        checker.load_json_document(
                            Path(document.name), maximum_bytes=checker.MAX_INSTANCE_BYTES
                        )

        huge_integer = b'{"x": 9007199254740992}'
        with tempfile.NamedTemporaryFile(suffix=".json") as document:
            document.write(huge_integer)
            document.flush()
            with self.assertRaisesRegex(checker.ContractError, "integer exceeds"):
                checker.load_json_document(
                    Path(document.name), maximum_bytes=checker.MAX_INSTANCE_BYTES
                )

        with tempfile.NamedTemporaryFile(suffix=".json") as document:
            document.write(b" " * (checker.MAX_INSTANCE_BYTES + 1))
            document.flush()
            with self.assertRaisesRegex(checker.ContractError, "maximum accepted size"):
                checker.load_json_document(
                    Path(document.name), maximum_bytes=checker.MAX_INSTANCE_BYTES
                )

        nonfinite_runtime = copy.deepcopy(self.actual)
        nonfinite_runtime["pid2"]["mi_s1_t"] = float("nan")
        self.assert_rejected(nonfinite_runtime, "non-finite")

    def test_duplicate_json_members_are_rejected_before_validation(self) -> None:
        duplicate = b'{"schema": 1, "schema": 2}'
        with tempfile.NamedTemporaryFile(suffix=".json") as document:
            document.write(duplicate)
            document.flush()
            with self.assertRaisesRegex(checker.ContractError, "duplicate JSON"):
                checker.load_json_document(
                    Path(document.name), maximum_bytes=checker.MAX_INSTANCE_BYTES
                )

    def test_hostile_schema_mutations_are_rejected_instead_of_ignored(self) -> None:
        unknown_keyword = copy.deepcopy(self.schema)
        unknown_keyword["properties"]["schema"]["patternProperties"] = {}
        with self.assertRaisesRegex(checker.ContractError, "unsupported schema keyword"):
            checker.lint_schema(unknown_keyword)

        unresolved_reference = copy.deepcopy(self.schema)
        unresolved_reference["properties"]["pid2"]["$ref"] = "#/$defs/Absent"
        with self.assertRaisesRegex(checker.ContractError, "unresolved local \\$ref"):
            checker.lint_schema(unresolved_reference)

        external_reference = copy.deepcopy(self.schema)
        external_reference["properties"]["pid2"]["$ref"] = (
            "https://example.invalid/schema.json"
        )
        with self.assertRaisesRegex(checker.ContractError, "only non-empty local"):
            checker.lint_schema(external_reference)

        malformed_required = copy.deepcopy(self.schema)
        malformed_required["required"].append("not_declared")
        with self.assertRaisesRegex(checker.ContractError, "must have a property schema"):
            checker.lint_schema(malformed_required)

        open_root = copy.deepcopy(self.schema)
        open_root["additionalProperties"] = True
        with self.assertRaisesRegex(checker.ContractError, "additionalProperties to false"):
            checker.lint_schema(open_root)

        open_nested = copy.deepcopy(self.schema)
        open_nested["$defs"]["AveragedAtom"]["additionalProperties"] = True
        with self.assertRaisesRegex(checker.ContractError, "additionalProperties to false"):
            checker.lint_schema(open_nested)

        optional_nested = copy.deepcopy(self.schema)
        optional_nested["$defs"]["AveragedAtom"]["required"].remove("net_nats")
        with self.assertRaisesRegex(checker.ContractError, "every declared property required"):
            checker.lint_schema(optional_nested)

        recursive_reference = copy.deepcopy(self.schema)
        recursive_reference["$defs"]["Pid2Result"] = {
            "$ref": "#/$defs/Pid2Result"
        }
        with self.assertRaisesRegex(checker.ContractError, "recursive \\$ref"):
            checker.validate_document(self.actual, recursive_reference)

        swapped_role_schema = copy.deepcopy(self.schema)
        functional_binding = swapped_role_schema["$defs"]["GraphNode"]["allOf"][0]
        functional_binding["then"]["properties"]["node_id"]["const"] = (
            "route.shared-exclusions.mgw-empirical-pmf"
        )
        with self.assertRaisesRegex(checker.ContractError, "required constant"):
            checker.validate_document(self.actual, swapped_role_schema)

        crossed_pair_schema = copy.deepcopy(self.schema)
        horizontal_binding = crossed_pair_schema["$defs"]["GraphEdge"]["allOf"][5]
        horizontal_binding["then"]["properties"]["to"]["const"] = (
            "pid_core::stable::categorical::discrete_sxpid3_with_budget"
        )
        with self.assertRaisesRegex(checker.ContractError, "required constant"):
            checker.validate_document(self.actual, crossed_pair_schema)

    def test_schema_encoding_with_duplicate_keyword_is_rejected(self) -> None:
        duplicate_schema = (
            b'{"$schema":"https://json-schema.org/draft/2020-12/schema",'
            b'"type":"object","type":"array","additionalProperties":false,'
            b'"properties":{},"required":[]}'
        )
        with tempfile.NamedTemporaryFile(suffix=".json") as document:
            document.write(duplicate_schema)
            document.flush()
            with self.assertRaisesRegex(checker.ContractError, "duplicate JSON"):
                checker.load_json_document(
                    Path(document.name), maximum_bytes=checker.MAX_SCHEMA_BYTES
                )


if __name__ == "__main__":
    unittest.main()
