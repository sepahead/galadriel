#!/usr/bin/env python3
"""Recompute the CREBAIN categorical MGW atoms without calling pid-rs.

This is a deliberately small, standard-library-only audit route.  It reads the
byte-bound fixture, evaluates the categorical shared-exclusions event-union
formula with 80-digit ``Decimal`` arithmetic, and performs Möbius inversion on
the Williams--Beer antichain order.  It is a law-specific corroboration, not a
second general-purpose PID implementation or a scientific validation theorem.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from dataclasses import dataclass
from decimal import Decimal, DecimalException, localcontext
from itertools import product
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "crates/galadriel-justify/fixtures/crebain_drone_mgw_v1.json"
FIXTURE_SHA256 = "82a837415b56c3646386a5c3e6fe28a492906c164edc461249bab7844aa4ebda"
RUST_STUDY_SCHEMA = "galadriel.crebain-drone-mgw-study.v2"
RUST_STUDY_SCHEMA_PATH = (
    "crates/galadriel-justify/schemas/crebain-drone-mgw-study-v2.schema.json"
)
RUST_STUDY_SCHEMA_ID = "https://raw.githubusercontent.com/sepahead/galadriel/v0.9.0/crates/galadriel-justify/schemas/crebain-drone-mgw-study-v2.schema.json"
CREBAIN_PRODUCER_REVISION = "6ef60fabbf8c8a8008e7a77304d3e095b6b9e91d"
PID_CORE_REVISION = "bc3aa80fb6025e709c2906a08bce25a4fac40578"
PID_CORE_VERSION = "0.9.0"
GALADRIEL_FUNCTIONAL_ALIAS = "functional.shared-exclusions.mgw-categorical"
UPSTREAM_METHOD_CATALOG_ID = "shared-exclusions.categorical"
PID2_EVALUATOR_ROUTE = (
    "pid_core::stable::categorical::discrete_sxpid2_with_budget"
)
PID3_EVALUATOR_ROUTE = (
    "pid_core::stable::categorical::discrete_sxpid3_with_budget"
)
SOURCE_ORDER = [
    "visual_north_plane_crossed",
    "radar_east_plane_crossed",
    "acoustic_up_plane_crossed",
]
METHOD_OBJECT_IDS = [
    "shared-exclusions.categorical",
    "pid-core/categorical-raw-row-plugin-mgw-pid2",
    "pid-core/categorical-raw-row-plugin-mgw-pid3",
    "pid.imin",
    "pid.broja-two-source-external",
    "pid.general-schick-poland-2021",
    "shared-exclusions.continuous-ehrlich-functional",
    "shared-exclusions.continuous-ehrlich-knn-estimator",
    "mutual-information.ksg1-report",
    "co-information.discrete",
    "o-information.discrete",
    "galadriel.normalized-innovation-squared",
    "galadriel.two-sided-cusum",
    "galadriel.signed-pearson-correlation",
    "infomorphic-objective.pnas-bivariate-2025",
    "infomorphic-objective.iclr-three-input-2025",
]
PRECISION = 80
OUTPUT_PLACES = 60
RUST_COMPARISON_TOLERANCE_NATS = Decimal("3e-16")

# A collection is a non-zero source-subset bit mask.  An antichain is a tuple
# of incomparable collections.  These orders match the public pid-core result
# coordinates, but the calculation below does not import or execute pid-core.
PID2_ANTICHAINS: tuple[tuple[int, ...], ...] = ((1, 2), (1,), (2,), (3,))
PID3_ANTICHAINS: tuple[tuple[int, ...], ...] = (
    (1,),
    (2,),
    (4,),
    (3,),
    (5,),
    (6,),
    (7,),
    (1, 2),
    (1, 4),
    (1, 6),
    (2, 4),
    (2, 5),
    (3, 4),
    (3, 5),
    (3, 6),
    (5, 6),
    (1, 2, 4),
    (3, 5, 6),
)

# SHA-256 of canonical JSON containing the 60-place decimal strings for every
# informative, misinformative, and net atom plus all non-empty subset MIs.  It
# is filled from the separately derived event-union route and locks its
# publication-facing coordinate order.  The value is checked in ``main``.
EXPECTED_ORACLE_SHA256 = "5aa7a1d92d4aaad9c056ede8a75bdc40abc1fa76634b02bba20aac5cc3913c19"
EXPECTED_ROTATED_PID3_MINIMUM_NET = Decimal(
    "-0.02148473827972452896597743606689315730151114691908696456285556543819270202994666"
)


class OracleError(RuntimeError):
    """A byte, law, lattice, or golden-output contract failed."""


@dataclass(frozen=True)
class Atom:
    informative: Decimal
    misinformative: Decimal

    @property
    def net(self) -> Decimal:
        return self.informative - self.misinformative


def _is_subset(left: int, right: int) -> bool:
    return left & ~right == 0


def _below(beta: tuple[int, ...], alpha: tuple[int, ...]) -> bool:
    """Return beta <= alpha in the Williams--Beer antichain order."""

    return all(any(_is_subset(b, a) for b in beta) for a in alpha)


def _matches_collection(
    candidate: tuple[int, ...], observed: tuple[int, ...], mask: int
) -> bool:
    return all(
        not (mask & (1 << index)) or candidate[index] == observed[index]
        for index in range(len(observed))
    )


def _matches_union(
    candidate: tuple[int, ...],
    observed: tuple[int, ...],
    antichain: tuple[int, ...],
) -> bool:
    return any(_matches_collection(candidate, observed, mask) for mask in antichain)


def _average_cumulative_terms(
    samples: Sequence[tuple[tuple[int, ...], int]],
    antichain: tuple[int, ...],
) -> Atom:
    joint = Counter(samples)
    sources = Counter(source for source, _target in samples)
    targets = Counter(target for _source, target in samples)
    total = Decimal(len(samples))
    informative = Decimal(0)
    misinformative = Decimal(0)

    for (observed_source, observed_target), outcome_count in sorted(joint.items()):
        union_count = sum(
            count
            for candidate, count in sources.items()
            if _matches_union(candidate, observed_source, antichain)
        )
        target_union_count = sum(
            count
            for (candidate, target), count in joint.items()
            if target == observed_target
            and _matches_union(candidate, observed_source, antichain)
        )
        if union_count <= 0 or target_union_count <= 0:
            raise OracleError("an observed event has zero empirical probability")

        p_union = Decimal(union_count) / total
        p_target = Decimal(targets[observed_target]) / total
        p_target_union = Decimal(target_union_count) / total
        weight = Decimal(outcome_count) / total
        informative += weight * (-p_union.ln())
        misinformative += weight * (p_target / p_target_union).ln()

    return Atom(informative, misinformative)


def _mobius_atoms(
    samples: Sequence[tuple[tuple[int, ...], int]],
    antichains: Sequence[tuple[int, ...]],
) -> list[Atom]:
    cumulatives = [_average_cumulative_terms(samples, alpha) for alpha in antichains]
    lower_sets = [
        {index for index, beta in enumerate(antichains) if _below(beta, alpha)}
        for alpha in antichains
    ]
    if any(index not in lower for index, lower in enumerate(lower_sets)):
        raise OracleError("antichain order is not reflexive")

    atoms: list[Atom | None] = [None] * len(antichains)
    for index in sorted(range(len(antichains)), key=lambda item: len(lower_sets[item])):
        strict_lower = lower_sets[index] - {index}
        if any(atoms[lower] is None for lower in strict_lower):
            raise OracleError("antichain order was not topologically sortable")
        atoms[index] = Atom(
            cumulatives[index].informative
            - sum(
                (atoms[lower].informative for lower in strict_lower if atoms[lower]),
                Decimal(0),
            ),
            cumulatives[index].misinformative
            - sum(
                (atoms[lower].misinformative for lower in strict_lower if atoms[lower]),
                Decimal(0),
            ),
        )
    return [atom for atom in atoms if atom is not None]


def _mutual_information(
    samples: Sequence[tuple[tuple[int, ...], int]], mask: int
) -> Decimal:
    projected = [
        (tuple(value for index, value in enumerate(source) if mask & (1 << index)), target)
        for source, target in samples
    ]
    joint = Counter(projected)
    sources = Counter(source for source, _target in projected)
    targets = Counter(target for _source, target in projected)
    total = Decimal(len(samples))
    result = Decimal(0)
    for (source, target), count in sorted(joint.items()):
        p_joint = Decimal(count) / total
        p_source = Decimal(sources[source]) / total
        p_target = Decimal(targets[target]) / total
        result += p_joint * (p_joint / (p_source * p_target)).ln()
    return result


def _quantized(value: Decimal) -> str:
    with localcontext() as context:
        context.prec = max(PRECISION, OUTPUT_PLACES + 20)
        quantum = Decimal(1).scaleb(-OUTPUT_PLACES)
        return format(value.quantize(quantum), "f")


def _atom_json(antichain: tuple[int, ...], atom: Atom) -> dict[str, object]:
    return {
        "antichain_masks": list(antichain),
        "informative_nats": _quantized(atom.informative),
        "misinformative_nats": _quantized(atom.misinformative),
        "net_nats": _quantized(atom.net),
    }


def _assert_reconstruction(
    atoms: Sequence[Atom],
    antichains: Sequence[tuple[int, ...]],
    subset_mis: Sequence[Decimal],
) -> None:
    tolerance = Decimal("1e-70")
    for subset_mask, expected in enumerate(subset_mis, start=1):
        reconstructed = sum(
            (
                atom.net
                for alpha, atom in zip(antichains, atoms, strict=True)
                if any(_is_subset(collection, subset_mask) for collection in alpha)
            ),
            Decimal(0),
        )
        if abs(reconstructed - expected) > tolerance:
            raise OracleError(
                f"subset {subset_mask} reconstruction differs by "
                f"{reconstructed - expected} nats"
            )


def _assert_declared_and_targets(
    rows: Sequence[dict[str, object]], sources: Sequence[tuple[int, int, int]]
) -> None:
    """Bind the dependency-disjoint route to the declared AND2/AND3 target maps."""

    for index, (row, source) in enumerate(zip(rows, sources, strict=True)):
        visual, radar, acoustic = source
        expected_horizontal = visual & radar
        expected_volumetric = visual & radar & acoustic
        if int(row["horizontal_incursion"]) != expected_horizontal:
            raise OracleError(
                f"row {index} horizontal target is not V AND R under the declared law"
            )
        if int(row["volumetric_incursion"]) != expected_volumetric:
            raise OracleError(
                f"row {index} volumetric target is not V AND R AND A under the declared law"
            )


def build_oracle() -> dict[str, object]:
    fixture_bytes = FIXTURE.read_bytes()
    observed_digest = hashlib.sha256(fixture_bytes).hexdigest()
    if observed_digest != FIXTURE_SHA256:
        raise OracleError(
            f"fixture SHA-256 mismatch: expected {FIXTURE_SHA256}, observed {observed_digest}"
        )
    document = json.loads(fixture_bytes)
    rows = document["rows"]
    if len(rows) != 64:
        raise OracleError(f"expected 64 fixture rows, observed {len(rows)}")

    sources = [tuple(int(value) for value in row["sources"]) for row in rows]
    expected_source_counts = Counter(
        {cell: 8 for cell in product((0, 1), repeat=3)}
    )
    if Counter(sources) != expected_source_counts:
        raise OracleError("fixture is not the declared balanced eight-cell source law")
    _assert_declared_and_targets(rows, sources)
    pid2_samples = [
        (source[:2], int(row["horizontal_incursion"]))
        for source, row in zip(sources, rows, strict=True)
    ]
    pid3_samples = [
        (source, int(row["volumetric_incursion"]))
        for source, row in zip(sources, rows, strict=True)
    ]
    rotated_pid3_targets = [target for _source, target in pid3_samples]
    rotated_pid3_targets = rotated_pid3_targets[1:] + rotated_pid3_targets[:1]
    rotated_pid3_samples = [
        (source, target)
        for source, target in zip(sources, rotated_pid3_targets, strict=True)
    ]

    pid2_atoms = _mobius_atoms(pid2_samples, PID2_ANTICHAINS)
    pid3_atoms = _mobius_atoms(pid3_samples, PID3_ANTICHAINS)
    rotated_pid3_atoms = _mobius_atoms(rotated_pid3_samples, PID3_ANTICHAINS)
    pid2_mis = [_mutual_information(pid2_samples, mask) for mask in range(1, 4)]
    pid3_mis = [_mutual_information(pid3_samples, mask) for mask in range(1, 8)]
    _assert_reconstruction(pid2_atoms, PID2_ANTICHAINS, pid2_mis)
    _assert_reconstruction(pid3_atoms, PID3_ANTICHAINS, pid3_mis)
    rotated_minimum_index, rotated_minimum_atom = min(
        enumerate(rotated_pid3_atoms), key=lambda pair: pair[1].net
    )
    if PID3_ANTICHAINS[rotated_minimum_index] != (4,) or abs(
        rotated_minimum_atom.net - EXPECTED_ROTATED_PID3_MINIMUM_NET
    ) > Decimal("1e-70"):
        raise OracleError(
            "fixed-source rotated PID3 negative-atom canary changed coordinate or value"
        )

    return {
        "schema": "galadriel.crebain-mgw-decimal-oracle.v1",
        "scientific_status": (
            "law-specific computational corroboration, not independent human review"
        ),
        "fixture_sha256": observed_digest,
        "decimal_precision": PRECISION,
        "reported_decimal_places": OUTPUT_PLACES,
        "pid2": {
            "atoms": [
                _atom_json(alpha, atom)
                for alpha, atom in zip(PID2_ANTICHAINS, pid2_atoms, strict=True)
            ],
            "subset_mi_nats": [_quantized(value) for value in pid2_mis],
        },
        "pid3": {
            "atoms": [
                _atom_json(alpha, atom)
                for alpha, atom in zip(PID3_ANTICHAINS, pid3_atoms, strict=True)
            ],
            "subset_mi_nats": [_quantized(value) for value in pid3_mis],
        },
        "theorem_controls": {
            "rotated_pid3_minimum_net_antichain_masks": list(
                PID3_ANTICHAINS[rotated_minimum_index]
            ),
            "rotated_pid3_minimum_net_nats": _quantized(rotated_minimum_atom.net),
            "boundary": (
                "fixed-source target rotation is a deterministic theorem control; "
                "it is not an inferential permutation test or application result"
            ),
        },
    }


def canonical_bytes(oracle: dict[str, object]) -> bytes:
    return json.dumps(
        oracle, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _component_count(oracle: dict[str, object]) -> int:
    return 3 * (
        len(oracle["pid2"]["atoms"]) + len(oracle["pid3"]["atoms"])
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise OracleError(f"Rust output contains duplicate JSON key {key!r}")
        result[key] = value
    return result


def _load_rust_json(rust_json_bytes: bytes) -> dict[str, object]:
    try:
        decoded = rust_json_bytes.decode("utf-8")
        document = json.loads(
            decoded,
            parse_float=Decimal,
            parse_int=Decimal,
            parse_constant=lambda value: (_ for _ in ()).throw(
                OracleError(f"Rust output contains non-standard numeric token {value}")
            ),
            object_pairs_hook=_unique_object,
        )
    except UnicodeDecodeError as error:
        raise OracleError(f"Rust output is not UTF-8: {error}") from error
    except json.JSONDecodeError as error:
        raise OracleError(f"Rust output is not valid JSON: {error}") from error
    if not isinstance(document, dict):
        raise OracleError("Rust output root is not a JSON object")
    return document


def _rust_number(value: object, path: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, Decimal):
        raise OracleError(f"Rust output {path} is not a JSON number")
    if not value.is_finite():
        raise OracleError(f"Rust output {path} is not finite")
    if not value.is_zero() and not (-400 <= value.adjusted() <= 308):
        raise OracleError(f"Rust output {path} is outside the finite binary64 exponent envelope")
    return value


def _require_equal(observed: object, expected: object, path: str) -> None:
    if observed != expected:
        raise OracleError(
            f"Rust output {path} differs: expected {expected!r}, observed {observed!r}"
        )


def _require_exact_length(value: object, expected: int, path: str) -> list[object]:
    if not isinstance(value, list):
        raise OracleError(f"Rust output {path} is not an array")
    if len(value) != expected:
        raise OracleError(
            f"Rust output {path} has {len(value)} entries; expected exactly {expected}"
        )
    return value


def compare_rust_output(
    oracle: dict[str, object], rust_json_bytes: bytes
) -> dict[str, object]:
    """Compare actual Galadriel JSON with the dependency-disjoint Decimal route."""

    rust_output = _load_rust_json(rust_json_bytes)
    _require_equal(rust_output["schema"], RUST_STUDY_SCHEMA, "schema")
    schema_receipt = rust_output["machine_schema"]
    _require_equal(
        schema_receipt["identifier"], RUST_STUDY_SCHEMA, "machine_schema.identifier"
    )
    _require_equal(
        schema_receipt["canonical_id"],
        RUST_STUDY_SCHEMA_ID,
        "machine_schema.canonical_id",
    )
    _require_equal(
        schema_receipt["repository_path"],
        RUST_STUDY_SCHEMA_PATH,
        "machine_schema.repository_path",
    )
    _require_equal(
        schema_receipt["closed_world_required"],
        True,
        "machine_schema.closed_world_required",
    )
    schema_bytes = (ROOT / RUST_STUDY_SCHEMA_PATH).read_bytes()
    _require_equal(
        schema_receipt["sha256"],
        hashlib.sha256(schema_bytes).hexdigest(),
        "machine_schema.sha256",
    )
    _require_equal(
        schema_receipt["bytes"], len(schema_bytes), "machine_schema.bytes"
    )
    fixture_identity = rust_output["fixture_identity"]
    _require_equal(
        fixture_identity["fixture_sha256"], oracle["fixture_sha256"],
        "fixture_identity.fixture_sha256",
    )
    _require_equal(
        fixture_identity["producer_revision"], CREBAIN_PRODUCER_REVISION,
        "fixture_identity.producer_revision",
    )
    _require_equal(
        fixture_identity["actual_pid_core_version"], PID_CORE_VERSION,
        "fixture_identity.actual_pid_core_version",
    )
    _require_equal(
        fixture_identity["actual_pid_core_revision"], PID_CORE_REVISION,
        "fixture_identity.actual_pid_core_revision",
    )
    reconciliation = rust_output["pid_core_source_reconciliation"]
    _require_equal(
        reconciliation["expected_revision"], PID_CORE_REVISION,
        "pid_core_source_reconciliation.expected_revision",
    )
    _require_equal(
        reconciliation["pid_core_package_subtree_clean_revision_matched"], True,
        "pid_core_source_reconciliation.pid_core_package_subtree_clean_revision_matched",
    )
    source = reconciliation["observed_source"]
    _require_equal(source["kind"], "workspace_git", "observed_source.kind")
    _require_equal(source["commit_sha1"], PID_CORE_REVISION, "observed_source.commit_sha1")
    _require_equal(
        source["working_tree_scope"], "crates/pid-core",
        "observed_source.working_tree_scope",
    )
    _require_equal(source["working_tree"], "clean", "observed_source.working_tree")
    _require_equal(
        rust_output["pid_core_software_identity"]["source"], source,
        "pid_core_software_identity.source",
    )
    errata = rust_output["producer_source_errata"]
    _require_equal(
        errata["fixture_bytes_retained_unchanged"],
        True,
        "producer_source_errata.fixture_bytes_retained_unchanged",
    )
    _require_equal(
        errata["every_frozen_literal_matched_before_correction"],
        True,
        "producer_source_errata.every_frozen_literal_matched_before_correction",
    )
    errata_entries = _require_exact_length(
        errata["entries"], 3, "producer_source_errata.entries"
    )
    _require_equal(
        [entry["json_pointer"] for entry in errata_entries],
        [
            "/target_origin",
            "/method_exclusions/nis_and_correlation",
            "/rows/*/fusion_receipt/{projection_count,common_projection_prior_id}",
        ],
        "producer_source_errata entry order",
    )
    _require_equal(
        [entry["source_surface"] for entry in errata_entries],
        ["analysis_manifest", "analysis_manifest", "fixture_rows"],
        "producer_source_errata source surfaces",
    )
    _require_equal(
        rust_output["primary_question"]["ordered_sources"], SOURCE_ORDER[:2],
        "primary_question.ordered_sources",
    )
    _require_equal(
        rust_output["exploratory_question"]["ordered_sources"], SOURCE_ORDER,
        "exploratory_question.ordered_sources",
    )
    _require_equal(
        rust_output["primary_question"]["target"], "horizontal_incursion",
        "primary_question.target",
    )
    _require_equal(
        rust_output["exploratory_question"]["target"], "volumetric_incursion",
        "exploratory_question.target",
    )
    _require_equal(
        rust_output["primary_question"]["upstream_method_catalog_id"],
        "shared-exclusions.categorical",
        "primary_question.upstream_method_catalog_id",
    )
    _require_equal(
        rust_output["exploratory_question"]["upstream_method_catalog_id"],
        "shared-exclusions.categorical",
        "exploratory_question.upstream_method_catalog_id",
    )
    method_rows = _require_exact_length(
        rust_output["method_eligibility"], 16, "method_eligibility"
    )
    _require_equal(
        [row["object_id"] for row in method_rows],
        METHOD_OBJECT_IDS,
        "method_eligibility object order",
    )
    graph = rust_output["estimand_graph"]
    _require_equal(
        graph["graph_id"], "galadriel.crebain-mgw-estimand-graph.v1",
        "estimand_graph.graph_id",
    )
    _require_equal(
        graph["galadriel_functional_alias"],
        GALADRIEL_FUNCTIONAL_ALIAS,
        "estimand_graph.galadriel_functional_alias",
    )
    _require_equal(
        graph["upstream_method_catalog_id"],
        UPSTREAM_METHOD_CATALOG_ID,
        "estimand_graph.upstream_method_catalog_id",
    )
    _require_equal(
        graph["pid2_evaluator_route"],
        PID2_EVALUATOR_ROUTE,
        "estimand_graph.pid2_evaluator_route",
    )
    _require_equal(
        graph["pid3_evaluator_route"],
        PID3_EVALUATOR_ROUTE,
        "estimand_graph.pid3_evaluator_route",
    )
    _require_exact_length(graph["nodes"], 14, "estimand_graph.nodes")
    _require_exact_length(graph["edges"], 20, "estimand_graph.edges")
    for field in (
        "all_edge_endpoints_resolved",
        "declared_topological_order_validated",
        "question_method_and_graph_identities_reconciled",
        "operational_authority_node_or_edge_kind_absent",
    ):
        _require_equal(graph[field], True, f"estimand_graph.{field}")
    interpretation = rust_output["atom_interpretation"]
    for field in (
        "pointwise_support_mass_and_averaging_matched",
        "canonical_pointwise_realization_order_matched",
        "every_retained_atom_interpretation_matched",
    ):
        _require_equal(interpretation[field], True, f"atom_interpretation.{field}")
    _require_equal(
        rust_output["algebra_checks"]["all_passed"], True,
        "algebra_checks.all_passed",
    )
    resource_calls = _require_exact_length(
        rust_output["resource_receipt"]["calls"], 9, "resource_receipt.calls"
    )
    if any(call.get("preflight_passed") is not True for call in resource_calls):
        raise OracleError("Rust output contains an unpassed categorical resource preflight")

    errors: list[tuple[str, Decimal]] = []

    def compare(path: str, observed: object, expected: str) -> None:
        errors.append((path, abs(_rust_number(observed, path) - Decimal(expected))))

    pid2_names = ("red", "unq1", "unq2", "syn")
    pid2_atoms = oracle["pid2"]["atoms"]
    for name, expected_atom in zip(pid2_names, pid2_atoms, strict=True):
        observed_atom = rust_output["pid2"][name]
        for component in ("informative_nats", "misinformative_nats", "net_nats"):
            compare(
                f"pid2.{name}.{component}",
                observed_atom[component],
                expected_atom[component],
            )
    for field, expected in zip(
        ("mi_s1_t", "mi_s2_t", "mi_s1s2_t"),
        oracle["pid2"]["subset_mi_nats"],
        strict=True,
    ):
        compare(f"pid2.{field}", rust_output["pid2"][field], expected)

    _require_exact_length(rust_output["pid2"]["pointwise"], 4, "pid2.pointwise")
    _require_exact_length(rust_output["pid3"]["pointwise"], 8, "pid3.pointwise")
    observed_antichains = _require_exact_length(
        rust_output["pid3"]["antichains"], 18, "pid3.antichains"
    )
    observed_pid3_atoms = _require_exact_length(
        rust_output["pid3"]["atoms"], 18, "pid3.atoms"
    )
    observed_pid3_mis = _require_exact_length(
        rust_output["pid3"]["subset_mis"], 7, "pid3.subset_mis"
    )
    expected_antichains = [list(alpha) for alpha in PID3_ANTICHAINS]
    if observed_antichains != expected_antichains:
        raise OracleError("Rust PID3 antichain order differs from the Decimal oracle")
    for index, expected_atom in enumerate(oracle["pid3"]["atoms"]):
        observed_atom = observed_pid3_atoms[index]
        for component in ("informative_nats", "misinformative_nats", "net_nats"):
            compare(
                f"pid3.atoms[{index}].{component}",
                observed_atom[component],
                expected_atom[component],
            )
    for index, expected in enumerate(oracle["pid3"]["subset_mi_nats"]):
        compare(
            f"pid3.subset_mis[{index}]",
            observed_pid3_mis[index],
            expected,
        )

    expected_control = oracle["theorem_controls"]
    observed_control = rust_output["algebra_checks"]["fixed_source_sensitivity"]
    if observed_control["rotated_pid3_minimum_net_antichain"] != expected_control[
        "rotated_pid3_minimum_net_antichain_masks"
    ]:
        raise OracleError("Rust fixed-source negative canary changed antichain")
    compare(
        "algebra_checks.fixed_source_sensitivity.rotated_pid3_minimum_net_nats",
        observed_control["rotated_pid3_minimum_net_nats"],
        expected_control["rotated_pid3_minimum_net_nats"],
    )

    maximum_path, maximum_error = max(errors, key=lambda item: item[1])
    if maximum_error > RUST_COMPARISON_TOLERANCE_NATS:
        raise OracleError(
            "Rust/Decimal comparison exceeded tolerance at "
            f"{maximum_path}: {maximum_error} > {RUST_COMPARISON_TOLERANCE_NATS}"
        )
    return {
        "schema": "galadriel.crebain-mgw-rust-decimal-comparison.v1",
        "rust_study_schema": RUST_STUDY_SCHEMA,
        "rust_json_sha256": hashlib.sha256(rust_json_bytes).hexdigest(),
        "rust_json_bytes": len(rust_json_bytes),
        "fixture_sha256": oracle["fixture_sha256"],
        "producer_revision": CREBAIN_PRODUCER_REVISION,
        "decimal_oracle_sha256": hashlib.sha256(canonical_bytes(oracle)).hexdigest(),
        "pid_core_revision": PID_CORE_REVISION,
        "pid_core_source_kind": "workspace_git",
        "pid_core_working_tree_scope": "crates/pid-core",
        "pid_core_source_working_tree": "clean",
        "averaged_atom_components_compared": _component_count(oracle),
        "subset_mutual_informations_compared": 10,
        "fixed_source_negative_canaries_compared": 1,
        "pointwise_decimal_components_compared": 0,
        "maximum_abs_error_path": maximum_path,
        "maximum_abs_error_nats": _quantized(maximum_error),
        "tolerance_nats": str(RUST_COMPARISON_TOLERANCE_NATS),
        "all_passed": True,
        "boundary": (
            "law-specific cross-route numerical corroboration over averaged atoms, subset "
            "mutual informations, and one negative theorem control; retained pointwise atoms "
            "are not separately recomputed by this Decimal route"
        ),
    }


def main(arguments: Sequence[str]) -> int:
    json_output = False
    rust_json_path: Path | None = None
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--json":
            json_output = True
            index += 1
        elif argument == "--rust-json" and index + 1 < len(arguments):
            rust_json_path = Path(arguments[index + 1])
            index += 2
        else:
            print(
                "usage: check_crebain_mgw_decimal_oracle.py [--json] [--rust-json PATH]",
                file=sys.stderr,
            )
            return 2
    try:
        with localcontext() as context:
            context.prec = PRECISION
            oracle = build_oracle()
            digest = hashlib.sha256(canonical_bytes(oracle)).hexdigest()
            if digest != EXPECTED_ORACLE_SHA256:
                raise OracleError(
                    "oracle coordinate digest mismatch: "
                    f"expected {EXPECTED_ORACLE_SHA256}, observed {digest}"
                )
            comparison = None
            if rust_json_path is not None:
                comparison = compare_rust_output(oracle, rust_json_path.read_bytes())
    except (KeyError, TypeError, ValueError, OSError, DecimalException, OracleError) as error:
        print(f"CREBAIN MGW Decimal oracle failed: {error}", file=sys.stderr)
        return 1

    if json_output:
        document = comparison if comparison is not None else oracle
        print(json.dumps(document, ensure_ascii=True, allow_nan=False, indent=2, sort_keys=True))
    elif comparison is not None:
        print(
            "CREBAIN MGW Rust/Decimal comparison: PASS "
            f"({_component_count(oracle)} averaged atom components; "
            f"maximum error {comparison['maximum_abs_error_nats']} nats)"
        )
    else:
        print(
            "CREBAIN MGW Decimal oracle: "
            f"PASS ({_component_count(oracle)} atom components; SHA-256 {digest})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
