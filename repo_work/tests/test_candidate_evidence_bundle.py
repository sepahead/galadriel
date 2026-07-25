"""Adversarial tests for candidate-evidence semantic reconstruction."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1]
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))

from common import ReviewError  # noqa: E402
import release_assurance as assurance  # noqa: E402


def compact_json(value: object) -> bytes:
    """Encode deterministic JSON bytes for one test artifact."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def small_config() -> dict[str, object]:
    """Return a small configuration for trial-record validation."""

    return {
        "study_id": "candidate-evidence-bounded-test",
        "base_seed": "81985529216486895",
        "base_seed_hex": "0x0123456789abcdef",
        "calibration_tracks": 1,
        "holdout_tracks": 1,
        "frames": 20,
        "dt_ms": 100,
        "assessment_step": 10,
        "alert_episode_reset_policy": "nominal_only",
        "attack_onset_frame": 10,
        "mission_frames": 20,
        "ordinary_missing_probability": 0.0,
        "autocorrelation_phis": [0.0],
        "covariance_scales": [1.0],
        "bootstrap_resamples": 4,
        "min_metric_eligible_tracks": 2,
        "detector": {"min_samples": 1, "max_seq_gap": 1},
        "correlation": {"min_samples": 1},
        "recorded_fixture": {"path": assurance.EVIDENCE_FIXTURE_PATH},
    }


def trial_record(
    expected: dict[str, object], config: dict[str, object]
) -> dict[str, object]:
    """Build one small internally consistent trial record."""

    synthetic = expected["source"] == "synthetic"
    detector = str(expected["detector"])
    if synthetic:
        frame_count = int(config["frames"])
        duration_ms = (frame_count - 1) * int(config["dt_ms"])
        realized, resets = assurance._expected_synthetic_observation_shape(
            expected,
            config,
        )
        sequence_offset = 0
        modalities = ["visual", "radar", "acoustic"]
    else:
        frame_count = 159
        duration_ms = 15_800
        realized = [
            {"modality": "visual", "observations": 159, "missing_frames": 0},
            {"modality": "acoustic", "observations": 158, "missing_frames": 1},
            {"modality": "radar", "observations": 159, "missing_frames": 0},
        ]
        resets = [
            {
                "frame_index": 97,
                "seq": 99,
                "timestamp_ms": 10_800,
                "reason": "sequence_or_timestamp_discontinuity",
            }
        ]
        sequence_offset = 2
        modalities = ["visual", "acoustic", "radar"]

    assessment_step = int(config["assessment_step"])
    assessments = (frame_count + assessment_step - 1) // assessment_step
    frame_start = assurance._expected_assessment_frame(
        1,
        step=assessment_step,
        frame_count=frame_count,
    )
    frame_end = assurance._expected_assessment_frame(
        assessments,
        step=assessment_step,
        frame_count=frame_count,
    )
    truth_class = str(expected["truth_class"])
    onset = expected["onset_frame"]
    unique_attribution = (
        truth_class == "attributed_inconsistency"
        and len(expected["truth_channels"]) == 1
    )
    expected_abstention = bool(expected["expected_abstention"])
    if detector == "nis_baseline":
        expected_abstention = False
    fused_missing = detector == "default_correlation_fusion" and (
        expected["condition"] == "provenance_missing_projection" or not synthetic
    )
    fused_rejected = (
        detector == "default_correlation_fusion"
        and expected["condition"] == "provenance_invalid_prior"
    )
    insufficient = assessments if fused_missing else 0
    rejected = assessments if fused_rejected else 0
    consistency = {
        "assessed": (
            assessments - insufficient - rejected
            if detector != "nis_baseline"
            else 0
        ),
        "insufficient_axis": 0,
        "missing_projection": insufficient,
        "extraction_error": rejected,
        "analysis_error": 0,
        "too_few_modalities": 0,
    }
    reasons: list[str] = []
    if not synthetic:
        reasons.append(
            "insufficient_duration: 15800 ms is below configured minimum 3600000 ms"
        )
        if detector == "default_correlation_fusion":
            reasons.append("missing_consistency_projection")
    if resets:
        reasons.append(f"detector_generation_resets:{len(resets)}")
    seed = expected["seed"]
    track_id = int(expected["track_id"])
    return {
        "schema": assurance.EVIDENCE_TRIAL_SCHEMA,
        "study_id": config["study_id"],
        "condition": expected["condition"],
        "experiment_kind": expected["experiment_kind"],
        "role": expected["role"],
        "source": expected["source"],
        "source_profile": (
            assurance.EVIDENCE_GENERATOR_PROFILE
            if synthetic
            else assurance.EVIDENCE_REPLAY_PROFILE
        ),
        "trial_index": expected["trial_index"],
        "seed": str(seed) if synthetic else None,
        "seed_hex": f"0x{int(seed):016x}" if synthetic else None,
        "track_id": track_id,
        "track_id_hex": f"0x{track_id:016x}",
        "detector": detector,
        "modalities": modalities,
        "truth": {
            "class": truth_class,
            "channels": expected["truth_channels"],
            "onset_frame": onset,
            "expected_abstention": expected_abstention,
        },
        "phi": expected["phi"],
        "covariance_scale": expected["covariance_scale"],
        "ordinary_missing_probability": expected["ordinary_missing_probability"],
        "frame_count": frame_count,
        "duration_ms": duration_ms,
        "assessment_step_frames": assessment_step,
        "alert_episode_reset_policy": config["alert_episode_reset_policy"],
        "assessments": assessments,
        "alert_episode_count": 0,
        "mission_alert": False,
        "first_alert_assessment": None,
        "pre_onset_alert": False if onset is not None else None,
        "first_post_onset_delay_frames": None,
        "first_post_onset_delay_ms": None,
        "attribution_emitted": False if onset is not None and unique_attribution else None,
        "attribution_correct": None,
        "insufficient_assessments": insufficient,
        "rejected_input_assessments": rejected,
        "abstention_assessments": insufficient + rejected,
        "abstention_fraction": (insufficient + rejected) / assessments,
        "startup_assessments": 0,
        "startup_abstention_assessments": 0,
        "startup_abstention_fraction": 0.0,
        "monitoring_assessments": assessments,
        "monitoring_abstention_assessments": insufficient + rejected,
        "monitoring_abstention_fraction": (insufficient + rejected) / assessments,
        "realized_modality_counts": realized,
        "detector_generation_resets": resets,
        "consistency": consistency,
        "evidence_status": "estimable" if synthetic else "not_estimable",
        "status_reasons": reasons,
        "alert_episodes": [],
        "trace": [
            {
                "assessment_start": 1,
                "assessment_end": assessments,
                "frame_start": frame_start,
                "frame_end": frame_end,
                "seq_start": frame_start + sequence_offset,
                "seq_end": frame_end + sequence_offset,
                "label": {
                    "state": (
                        "rejected_input"
                        if fused_rejected
                        else "insufficient_evidence" if fused_missing else "nominal"
                    ),
                    "classification": (
                        "invalid_consistency_input"
                        if fused_rejected
                        else "insufficient_evidence" if fused_missing else "nominal"
                    ),
                    "channels": [],
                },
            }
        ],
    }


def candidate_expectations() -> assurance.CandidateEvidenceExpectations:
    """Return stable independent candidate identities for unit tests."""

    return assurance.CandidateEvidenceExpectations(
        commit="1" * 40,
        tree="2" * 40,
        tracked_config_path="evidence/galadriel-0.9-candidate.json",
        tracked_config_bytes=b"tracked config bytes\n",
        workspace_manifest_sha256="3" * 64,
        cargo_lock_sha256="4" * 64,
        runner_binary_sha256="5" * 64,
        rustc_verbose="rustc 1.89.0 test\n",
        cargo_version="cargo 1.89.0 test",
        target_os="macos",
        target_arch="aarch64",
    )


def manifest_fixture(
    *,
    expected: assurance.CandidateEvidenceExpectations,
    config: dict[str, object],
    config_binding: dict[str, str],
    canonical_config_sha256: str,
    trial_records: list[dict[str, object]],
) -> dict[str, object]:
    """Build one exact manifest for the independent manifest validator."""

    synthetic_records = sum(row["source"] == "synthetic" for row in trial_records)
    recorded_records = sum(row["source"] == "recorded" for row in trial_records)
    return {
        "schema": assurance.EVIDENCE_MANIFEST_SCHEMA,
        "trial_schema": assurance.EVIDENCE_TRIAL_SCHEMA,
        "summary_schema": assurance.EVIDENCE_SUMMARY_SCHEMA,
        "generator_profile": assurance.EVIDENCE_GENERATOR_PROFILE,
        "recorded_replay_profile": assurance.EVIDENCE_REPLAY_PROFILE,
        "missingness_profile": assurance.EVIDENCE_MISSINGNESS_PROFILE,
        "acceptance_metric_profile": assurance.EVIDENCE_ACCEPTANCE_PROFILE,
        "bootstrap_profile": assurance.EVIDENCE_BOOTSTRAP_PROFILE,
        "study_id": config["study_id"],
        "base_seed_hex": config["base_seed_hex"],
        "git": {
            "commit": expected.commit,
            "tree": expected.tree,
            "dirty": False,
            "status_porcelain_v1": "",
        },
        "toolchain": {
            "rustc_verbose": expected.rustc_verbose,
            "cargo_version": expected.cargo_version,
            "package_version": assurance.VERSION,
            "build_profile": "release",
            "target_os": expected.target_os,
            "target_arch": expected.target_arch,
            "available_parallelism": 4,
        },
        "inputs": {
            "config_source_path": expected.tracked_config_path,
            "config_source_sha256": hashlib.sha256(
                expected.tracked_config_bytes
            ).hexdigest(),
            "canonical_config_sha256": canonical_config_sha256,
            "workspace_manifest_sha256": expected.workspace_manifest_sha256,
            "cargo_lock_sha256": expected.cargo_lock_sha256,
            "recorded_fixture_path": assurance.EVIDENCE_FIXTURE_PATH,
            "recorded_fixture_sha256": assurance.EVIDENCE_FIXTURE_SHA256,
            "runner_binary_sha256": expected.runner_binary_sha256,
        },
        "scope": list(assurance.EVIDENCE_SCOPE),
        "trial_records": len(trial_records),
        "synthetic_tracks": synthetic_records // 2,
        "recorded_tracks": recorded_records // 2,
        "dirty_override_used": False,
        "publication_source_policy": "require_clean",
        "accepted_config_profile": assurance.EVIDENCE_ACCEPTED_PROFILE,
        "accepted_config_digest": config_binding["accepted_semantic_digest"],
        "deterministic_time_policy": (
            "The artifacts do not store a wall-clock timestamp. Deterministic artifacts "
            "depend only on declared inputs and recorded tool and source provenance."
        ),
    }


def metric(
    value: float,
    interval: list[float],
    *,
    eligible: int = 100,
) -> dict[str, object]:
    """Build the acceptance fields used by one estimated metric."""

    return {
        "status": "estimated",
        "ci_status": "estimated",
        "eligible_tracks": eligible,
        "value": value,
        "ci95": interval,
    }


def acceptance_summary() -> dict[str, object]:
    """Build rows where only structural criteria 001 and 006 fail."""

    clean_hours = 100 * 3_599 / 36_000
    false_alert = metric(0.0, assurance._garwood_rate_ci(0, clean_hours))
    no_events = metric(0.0, list(assurance._wilson_ci(0, 100)))
    all_events = metric(1.0, list(assurance._wilson_ci(100, 100)))
    clean_abstention = metric(
        0.0,
        assurance._hoeffding_ci(0.0, 0.0, 1.0, 1.0 / 100.0),
    )
    passing_delay = metric(0.0, [0.0, 1.0])

    def row(
        condition: str,
        experiment_kind: str,
        detector: str,
        metrics: dict[str, dict[str, object]],
    ) -> dict[str, object]:
        return {
            "condition": condition,
            "experiment_kind": experiment_kind,
            "role": "holdout",
            "detector": detector,
            "phi": 0.0,
            "covariance_scale": 1.0,
            "metrics": metrics,
        }

    rows: list[dict[str, object]] = []
    for detector in ("nis_baseline", "default_correlation_fusion"):
        metrics = {
            "false_alerts_per_hour": copy.deepcopy(false_alert),
            "mission_probability_any_alert": copy.deepcopy(no_events),
        }
        if detector == "default_correlation_fusion":
            metrics["abstention_fraction"] = copy.deepcopy(clean_abstention)
        rows.append(
            row(
                "clean_autocorrelation_phi_0p000000_0000000000000000",
                "clean_autocorrelation",
                detector,
                metrics,
            )
        )
    for condition, kind, detectors in (
        (
            "attack_loud_acoustic",
            "targeted_attack",
            ("nis_baseline", "default_correlation_fusion"),
        ),
        (
            "attack_broad_degradation",
            "broad_degradation_attack",
            ("nis_baseline", "default_correlation_fusion"),
        ),
        (
            "attack_stealthy_acoustic",
            "targeted_attack",
            ("default_correlation_fusion",),
        ),
    ):
        for detector in detectors:
            metrics = {
                "conditional_detection_probability": copy.deepcopy(all_events),
                "conditional_delay_p95_ms": copy.deepcopy(passing_delay),
            }
            if detector == "default_correlation_fusion" and kind == "targeted_attack":
                metrics["conditional_attribution_error"] = copy.deepcopy(no_events)
            rows.append(row(condition, kind, detector, metrics))
    rows.append(
        row(
            "clean_ordinary_missingness",
            "ordinary_missingness",
            "default_correlation_fusion",
            {"abstention_fraction": copy.deepcopy(clean_abstention)},
        )
    )
    return {"holdout_results": rows}


def report_summary() -> dict[str, object]:
    """Build a compact summary that the report renderer accepts."""

    unavailable = {
        "status": "not_applicable",
        "value": None,
        "ci95": None,
        "ci_status": "not_applicable",
    }
    metrics = {
        name: copy.deepcopy(unavailable) for name in assurance.EVIDENCE_METRIC_NAMES
    }
    metrics["abstention_fraction"] = {
        "status": "estimated",
        "value": 0.0,
        "ci95": [0.0, 0.2],
        "ci_status": "estimated",
    }
    return {
        "schema": assurance.EVIDENCE_SUMMARY_SCHEMA,
        "study_id": "candidate-evidence-bounded-test",
        "holdout_results": [
            {
                "condition": "clean_test",
                "detector": "default_correlation_fusion",
                "exposure_hours": 1.0,
                "detector_generation_resets": 0,
                "tracks_with_detector_generation_resets": 0,
                "raw_counts": {"tracks": 2, "alert_episodes": 0},
                "metrics": metrics,
            }
        ],
        "recorded_fixture": {
            "evidence_status": "not_estimable",
            "observations": 1,
            "tracks": 1,
            "total_duration_ms": 0,
            "projection_observations": 0,
            "detector_generation_resets": 0,
            "tracks_with_detector_generation_resets": 0,
            "status_reasons": ["bounded test fixture"],
        },
        "limitations": ["This bounded unit fixture does not provide release evidence."],
    }


class BootstrapAndIntervalTests(unittest.TestCase):
    def test_splitmix64_has_the_runner_golden_sequence(self) -> None:
        rng = assurance._EvidenceBootstrapRng(0x0123_4567_89AB_CDEF)

        self.assertEqual(
            [rng.below(100) for _ in range(8)],
            [65, 43, 66, 40, 52, 46, 1, 9],
        )

    def test_splitmix64_rejects_the_biased_low_residue(self) -> None:
        rng = assurance._EvidenceBootstrapRng(0)
        threshold = ((-10) & 0xFFFF_FFFF_FFFF_FFFF) % 10
        self.assertEqual(threshold, 6)

        with mock.patch.object(rng, "next_u64", side_effect=[5, 26]) as draw:
            self.assertEqual(rng.below(10), 6)

        self.assertEqual(draw.call_count, 2)
        for invalid in (0, 0x1_0000_0000_0000_0000):
            with self.subTest(invalid=invalid), self.assertRaises(ReviewError):
                rng.below(invalid)

    def test_wilson_boundaries_enclose_points_and_are_symmetric(self) -> None:
        zero = assurance._wilson_ci(0, 100)
        complete = assurance._wilson_ci(100, 100)
        middle = assurance._wilson_ci(50, 100)

        self.assertEqual(zero[0], 0.0)
        self.assertEqual(complete[1], 1.0)
        self.assertAlmostEqual(zero[1], 1.0 - complete[0], places=15)
        self.assertLessEqual(middle[0], 0.5)
        self.assertGreaterEqual(middle[1], 0.5)
        for successes, trials in ((-1, 100), (101, 100), (0, 0)):
            with self.subTest(successes=successes, trials=trials):
                with self.assertRaises(ReviewError):
                    assurance._wilson_ci(successes, trials)


class TrialTopologyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = small_config()
        self.layout = assurance._expected_trial_layout(self.config)

    def test_small_records_validate_and_trace_mutations_fail_closed(self) -> None:
        expected = self.layout[0]
        valid = trial_record(expected, self.config)
        projection = assurance._validate_trial_record(
            valid,
            expected,
            self.config,
            record_index=1,
        )
        self.assertEqual(projection["condition"], expected["condition"])

        gap = copy.deepcopy(valid)
        gap["trace"][0]["assessment_start"] = 2
        with self.assertRaisesRegex(ReviewError, "gap, overlap, or invalid bound"):
            assurance._validate_trial_record(
                gap,
                expected,
                self.config,
                record_index=1,
            )

        inconsistent_state = copy.deepcopy(valid)
        inconsistent_state["trace"][0]["label"] = {
            "state": "insufficient_evidence",
            "classification": "insufficient_evidence",
            "channels": [],
        }
        with self.assertRaisesRegex(ReviewError, "does not match its trace"):
            assurance._validate_trial_record(
                inconsistent_state,
                expected,
                self.config,
                record_index=1,
            )

    def test_trial_booleans_do_not_accept_json_integers(self) -> None:
        expected = self.layout[0]
        valid = trial_record(expected, self.config)
        mutations = (
            ("trial index", lambda value: value.update(trial_index=False)),
            ("mission alert", lambda value: value.update(mission_alert=0)),
            (
                "truth abstention",
                lambda value: value["truth"].update(expected_abstention=0),
            ),
            (
                "episode count",
                lambda value: value.update(alert_episode_count=False),
            ),
            (
                "insufficient count",
                lambda value: value.update(insufficient_assessments=False),
            ),
        )
        for name, mutate in mutations:
            changed = copy.deepcopy(valid)
            mutate(changed)
            with self.subTest(name=name), self.assertRaises(ReviewError):
                assurance._validate_trial_record(
                    changed,
                    expected,
                    self.config,
                    record_index=1,
                )

    def test_attributed_alert_requires_a_nonempty_channel_set(self) -> None:
        with self.assertRaisesRegex(ReviewError, "attributed.*channel"):
            assurance._validate_trace_label(
                {
                    "state": "alert",
                    "classification": "attributed_inconsistency",
                    "channels": [],
                },
                "candidate evidence attributed alert",
            )

        self.assertEqual(
            assurance._validate_trace_label(
                {
                    "state": "alert",
                    "classification": "unclassified_anomaly",
                    "channels": [],
                },
                "candidate evidence unclassified alert",
            )["channels"],
            [],
        )

    def test_stream_requires_the_exact_detector_and_trial_order(self) -> None:
        records = [trial_record(expected, self.config) for expected in self.layout]
        records[0], records[1] = records[1], records[0]
        payload = b"".join(compact_json(record) + b"\n" for record in records)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "trials.jsonl").write_bytes(payload)
            with self.assertRaisesRegex(ReviewError, "another detector"):
                assurance._stream_validate_evidence_trials(
                    root,
                    expected_digest=hashlib.sha256(payload).hexdigest(),
                    expected_size=len(payload),
                    config=self.config,
                )

    def test_fusion_consistency_categories_must_match_trace_abstention(self) -> None:
        expected = next(
            row
            for row in self.layout
            if row["condition"] == "provenance_missing_projection"
            and row["detector"] == "default_correlation_fusion"
        )
        forged = trial_record(expected, self.config)
        assessments = forged["assessments"]
        forged["trace"][0]["label"] = {
            "state": "nominal",
            "classification": "nominal",
            "channels": [],
        }
        forged.update(
            insufficient_assessments=0,
            abstention_assessments=0,
            abstention_fraction=0.0,
            monitoring_abstention_assessments=0,
            monitoring_abstention_fraction=0.0,
        )
        forged["consistency"].update(
            assessed=assessments,
            missing_projection=0,
        )

        with self.assertRaisesRegex(
            ReviewError,
            "(?:provenance abstention|consistency counts contradict)",
        ):
            assurance._validate_trial_record(
                forged,
                expected,
                self.config,
                record_index=1,
            )

    def test_duplicate_json_keys_are_structural_errors(self) -> None:
        with self.assertRaisesRegex(ReviewError, "duplicate"):
            assurance._bounded_evidence_object(
                b'{"schema":"first","schema":"second"}',
                "duplicate-key candidate evidence",
            )


class ManifestAndChecksumTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = small_config()
        self.expected = candidate_expectations()
        layout = assurance._expected_trial_layout(self.config)
        self.records = [
            assurance._validate_trial_record(
                trial_record(expected, self.config),
                expected,
                self.config,
                record_index=index,
            )
            for index, expected in enumerate(layout, 1)
        ]
        self.binding = {"accepted_semantic_digest": "6" * 64}
        self.canonical_config_sha256 = "7" * 64
        self.manifest = manifest_fixture(
            expected=self.expected,
            config=self.config,
            config_binding=self.binding,
            canonical_config_sha256=self.canonical_config_sha256,
            trial_records=self.records,
        )

    def validate(self, value: dict[str, object]) -> dict[str, object]:
        return assurance._validate_evidence_manifest(
            value,
            expected=self.expected,
            config=self.config,
            config_binding=self.binding,
            canonical_config_sha256=self.canonical_config_sha256,
            trial_records=self.records,
        )

    def test_manifest_binds_commit_tree_and_runner_hash(self) -> None:
        self.assertEqual(self.validate(self.manifest), self.manifest)
        mutations = (
            ("commit", lambda value: value["git"].update(commit="8" * 40)),
            ("tree", lambda value: value["git"].update(tree="9" * 40)),
            (
                "runner",
                lambda value: value["inputs"].update(runner_binary_sha256="a" * 64),
            ),
        )
        for name, mutate in mutations:
            changed = copy.deepcopy(self.manifest)
            mutate(changed)
            with self.subTest(name=name), self.assertRaises(ReviewError):
                self.validate(changed)

    def test_manifest_booleans_and_counts_require_exact_json_types(self) -> None:
        mutations = (
            ("Git dirty", lambda value: value["git"].update(dirty=0)),
            (
                "dirty override",
                lambda value: value.update(dirty_override_used=0),
            ),
            ("recorded tracks", lambda value: value.update(recorded_tracks=True)),
        )
        for name, mutate in mutations:
            changed = copy.deepcopy(self.manifest)
            mutate(changed)
            with self.subTest(name=name), self.assertRaises(ReviewError):
                self.validate(changed)

    def test_sha256sums_requires_exact_order_and_content(self) -> None:
        artifacts = {
            name: {"sha256": f"{index:x}" * 64, "size_bytes": index}
            for index, name in enumerate(assurance.EVIDENCE_FILES, 1)
        }
        exact = b"".join(
            f"{artifacts[name]['sha256']}  {name}\n".encode("ascii")
            for name in assurance.EVIDENCE_CHECKSUM_FILES
        )
        assurance._validate_evidence_sha256sums(exact, artifacts)

        rows = exact.splitlines(keepends=True)
        for payload in (
            b"".join(reversed(rows)),
            exact.replace(b"config.json", b"other.json", 1),
            exact + rows[0],
        ):
            with self.subTest(payload=payload[:16]), self.assertRaises(ReviewError):
                assurance._validate_evidence_sha256sums(payload, artifacts)


class AcceptedConfigurationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.relative = "evidence/galadriel-0.9-candidate.json"
        self.source_bytes = (ROOT / self.relative).read_bytes()
        source = assurance._bounded_evidence_object(
            self.source_bytes,
            "tracked candidate evidence config test fixture",
        )
        self.accepted = assurance._accepted_evidence_config_from_source(source)

    def manifest_bytes(self, accepted_bytes: bytes) -> bytes:
        return compact_json(
            {
                "inputs": {
                    "config_source_path": self.relative,
                    "config_source_sha256": hashlib.sha256(
                        self.source_bytes
                    ).hexdigest(),
                    "canonical_config_sha256": hashlib.sha256(
                        accepted_bytes
                    ).hexdigest(),
                },
                "accepted_config_digest": self.accepted["canonical_digest"],
            }
        )

    def validate(self, accepted: dict[str, object]) -> dict[str, object]:
        accepted_bytes = compact_json(accepted)
        return assurance.validate_evidence_config_bytes(
            self.source_bytes,
            accepted_bytes,
            self.manifest_bytes(accepted_bytes),
            tracked_relative_path=self.relative,
        )

    def test_accepted_config_rejects_boolean_numeric_coercion(self) -> None:
        self.assertEqual(self.validate(self.accepted)["study_design_status"], "PASS")
        mutations = (
            (
                "integer",
                lambda value: value["release_suite"].update(axis_family_count=True),
            ),
            ("float", lambda value: value.update(sigma=True)),
        )
        for name, mutate in mutations:
            changed = copy.deepcopy(self.accepted)
            mutate(changed)
            with self.subTest(name=name), self.assertRaisesRegex(
                ReviewError,
                "not the exact derived object",
            ):
                self.validate(changed)


class SummaryAndAcceptanceTests(unittest.TestCase):
    def test_raw_count_and_metric_mutations_fail_semantic_equality(self) -> None:
        trusted = report_summary()
        raw_mutation = copy.deepcopy(trusted)
        raw_mutation["holdout_results"][0]["raw_counts"]["tracks"] = 3
        metric_mutation = copy.deepcopy(trusted)
        metric_mutation["holdout_results"][0]["metrics"]["abstention_fraction"][
            "value"
        ] = 0.01

        for name, supplied in (
            ("raw count", raw_mutation),
            ("metric", metric_mutation),
        ):
            with self.subTest(name=name), self.assertRaises(ReviewError):
                assurance._require_evidence_semantic_equality(
                    supplied,
                    trusted,
                    path="summary",
                )

    def test_acc_001_and_acc_006_remain_structural_negative_results(self) -> None:
        summary = acceptance_summary()
        result = assurance.evaluate_acceptance(
            summary,
            {"min_metric_eligible_tracks": 20},
        )

        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(
            result["failed_criterion_ids"],
            ["GLD-090-ACC-001", "GLD-090-ACC-006"],
        )
        criteria = {row["id"]: row for row in result["criteria"]}
        self.assertGreater(
            criteria["GLD-090-ACC-001"]["observations"][0]["decision_value"],
            0.10,
        )
        self.assertGreater(
            criteria["GLD-090-ACC-006"]["observations"][0]["decision_value"],
            0.05,
        )


class PublicBundleValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.expected = candidate_expectations()
        self.summary = report_summary()
        self.manifest = {
            "git": {
                "commit": self.expected.commit,
                "tree": self.expected.tree,
                "dirty": False,
            }
        }
        self.config = {"min_metric_eligible_tracks": 2}

    def inventory(self, documents: dict[str, bytes]) -> dict[str, SimpleNamespace]:
        return {
            name: SimpleNamespace(
                sha256=hashlib.sha256(documents[name]).hexdigest(),
                size_bytes=len(documents[name]),
            )
            for name in assurance.EVIDENCE_FILES
        }

    def run_bundle(
        self,
        *,
        supplied_summary: dict[str, object] | None = None,
        report: bytes | None = None,
    ) -> assurance.ValidatedCandidateEvidence:
        supplied_summary = supplied_summary or copy.deepcopy(self.summary)
        exact_report = assurance._render_evidence_report(self.summary, self.manifest)
        documents = {
            "config.json": compact_json(self.config),
            "manifest.json": compact_json({"bounded": "manifest"}),
            "report.md": exact_report if report is None else report,
            "summary.json": compact_json(supplied_summary),
            "trials.jsonl": b"{}\n",
            "SHA256SUMS": b"",
        }
        inventory = self.inventory(documents)
        documents["SHA256SUMS"] = b"".join(
            f"{inventory[name].sha256}  {name}\n".encode("ascii")
            for name in assurance.EVIDENCE_CHECKSUM_FILES
        )
        inventory = self.inventory(documents)
        captures = {
            name: SimpleNamespace(data=documents[name])
            for name in assurance.EVIDENCE_FILES
            if name != "trials.jsonl"
        }
        accepted = {
            "status": "FAIL",
            "failed_criterion_ids": ["GLD-090-ACC-001"],
        }
        with (
            mock.patch.object(
                assurance,
                "_candidate_evidence_tree",
                side_effect=[inventory, inventory],
            ),
            mock.patch.object(
                assurance,
                "_capture_candidate_evidence_documents",
                return_value=captures,
            ),
            mock.patch.object(
                assurance,
                "validate_evidence_config_bytes",
                return_value={"accepted_semantic_digest": "6" * 64},
            ),
            mock.patch.object(
                assurance,
                "_stream_validate_evidence_trials",
                return_value=(
                    [],
                    inventory["trials.jsonl"].sha256,
                    inventory["trials.jsonl"].size_bytes,
                ),
            ),
            mock.patch.object(
                assurance,
                "_validate_evidence_manifest",
                return_value=self.manifest,
            ),
            mock.patch.object(
                assurance,
                "_recompute_evidence_summary",
                return_value=self.summary,
            ),
            mock.patch.object(
                assurance,
                "evaluate_acceptance",
                return_value=accepted,
            ),
        ):
            return assurance.validate_candidate_evidence_bundle(
                Path("/bounded/unit/evidence"),
                expected=self.expected,
            )

    def test_public_validator_accepts_reconstructed_negative_evidence(self) -> None:
        result = self.run_bundle()

        self.assertEqual(result.summary, self.summary)
        self.assertEqual(result.acceptance["status"], "FAIL")
        self.assertRegex(result.semantic_sha256, r"[0-9a-f]{64}\Z")

    def test_public_validator_rejects_summary_and_report_mutations(self) -> None:
        changed_summary = copy.deepcopy(self.summary)
        changed_summary["holdout_results"][0]["raw_counts"]["tracks"] = 4
        with self.assertRaisesRegex(ReviewError, "summary (?:number|value) differs"):
            self.run_bundle(supplied_summary=changed_summary)

        changed_metric = copy.deepcopy(self.summary)
        changed_metric["holdout_results"][0]["metrics"]["abstention_fraction"][
            "value"
        ] = 0.125
        with self.assertRaisesRegex(ReviewError, "summary (?:number|value) differs"):
            self.run_bundle(supplied_summary=changed_metric)

        exact_report = assurance._render_evidence_report(self.summary, self.manifest)
        with self.assertRaisesRegex(ReviewError, "report differs"):
            self.run_bundle(report=exact_report + b"\nforged report line\n")

    def test_public_structural_failures_raise_review_error(self) -> None:
        invalid = self.expected._replace(commit="not-a-commit")
        with self.assertRaisesRegex(ReviewError, "expected Git identity"):
            assurance.validate_candidate_evidence_bundle(
                Path("/bounded/unit/evidence"),
                expected=invalid,
            )

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ReviewError):
                assurance.validate_candidate_evidence_bundle(
                    Path(directory),
                    expected=self.expected,
                )


if __name__ == "__main__":
    unittest.main()
