use galadriel_core::{
    AssessmentClassification, ClockDomain, DetectorConfig, Mirror, Modality, PidObservation,
    Sequence, TimestampMillis, TrackId, Verdict, JSON_SAFE_INTEGER_MAX,
};
use galadriel_local_adapter::{
    AdapterError, NisEvidenceParams, ScalarChannelParams, ScalarMonitor, RESEARCH_PROFILE,
};

fn config() -> DetectorConfig {
    DetectorConfig::standalone_advisory_v0_9().unwrap()
}

fn monitor(modalities: &[Modality], first: u64) -> ScalarMonitor {
    let channels: Vec<_> = modalities
        .iter()
        .map(|modality| ScalarChannelParams {
            modality: *modality,
            dof: 3,
        })
        .collect();
    ScalarMonitor::prepare(
        TrackId::new(7).unwrap(),
        ClockDomain::SimulationTime,
        Sequence::new(first).unwrap(),
        &channels,
        config(),
    )
    .unwrap()
}

fn sample(nis: f64) -> Option<NisEvidenceParams> {
    Some(NisEvidenceParams { nis, dof: 3 })
}

fn frame(
    monitor: &mut ScalarMonitor,
    sequence: u64,
    evidence: &[Option<NisEvidenceParams>],
) -> galadriel_local_adapter::ScalarAssessment {
    monitor
        .assess_frame(
            Sequence::new(sequence).unwrap(),
            TimestampMillis::new(sequence * 20).unwrap(),
            evidence,
        )
        .unwrap()
}

#[test]
fn synthetic_two_modality_control_invokes_and_matches_actual_engine() {
    let modalities = [Modality::Visual, Modality::Radar];
    let mut adapter = monitor(&modalities, 0);
    let mut direct = Mirror::for_exploratory_subset(config(), RESEARCH_PROFILE.capability());

    // These are synthetic component controls, never CREBAIN-produced evidence.
    for index in 0..96 {
        let nis = if index < 80 { 3.0 } else { 300.0 };
        let observed = frame(&mut adapter, index, &[sample(3.0), sample(nis)]);
        for (modality, value) in modalities.into_iter().zip([3.0, nis]) {
            let observation =
                PidObservation::try_scalar_raw(7, index * 20, index, modality, value, 3).unwrap();
            direct.ingest_checked(&observation).unwrap();
        }
        let expected = direct
            .assess(TrackId::new(7).unwrap(), Sequence::new(index).unwrap())
            .unwrap();
        assert_eq!(
            serde_json::to_value(observed.report().unwrap()).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
        assert_eq!(
            observed.classification(),
            AssessmentClassification::ExploratoryResearch(RESEARCH_PROFILE)
        );
        assert!(!observed.calibrated_posterior());
        assert!(observed.report().unwrap().assessment_binding().is_none());
        if index == 31 {
            assert_eq!(observed.report().unwrap().verdict(), &Verdict::Nominal);
        }
        if index == 95 {
            assert_eq!(
                observed.report().unwrap().verdict(),
                &Verdict::AttributedInconsistency {
                    channels: vec![Modality::Radar]
                }
            );
            assert!(observed
                .report()
                .unwrap()
                .channels()
                .iter()
                .all(|channel| channel.n() == 64));
        }
    }
}

#[test]
fn one_real_scalar_channel_cannot_create_a_second_modality() {
    let mut adapter = monitor(&[Modality::Radar], 0);
    for index in 0..64 {
        let result = frame(&mut adapter, index, &[sample(3.0)]);
        assert_eq!(
            result.report().unwrap().verdict(),
            &Verdict::InsufficientEvidence
        );
        assert_eq!(result.report().unwrap().channels().len(), 1);
    }
    assert_eq!(adapter.config().min_channels(), 2);
}

#[test]
fn warmup_insufficiency_stays_an_actual_detector_report() {
    let mut adapter = monitor(&[Modality::Visual, Modality::Radar], 0);
    let result = frame(&mut adapter, 0, &[sample(3.0), sample(3.0)]);
    assert_eq!(
        result.report().unwrap().verdict(),
        &Verdict::InsufficientEvidence
    );
    assert!(result.unavailable().is_empty());
    assert!(!adapter.is_retired());
}

#[test]
fn read_only_preflight_never_ingests_or_retires_a_window() {
    let mut adapter = monitor(&[Modality::Visual, Modality::Radar], 0);
    let sequence = Sequence::new(0).unwrap();
    let timestamp = TimestampMillis::new(0).unwrap();
    adapter
        .validate_frame(sequence, timestamp, &[sample(3.0), sample(3.0)])
        .unwrap();
    adapter
        .validate_frame(sequence, timestamp, &[sample(3.0), None])
        .unwrap();
    assert!(adapter
        .validate_frame(sequence, timestamp, &[sample(3.0), sample(f64::NAN)])
        .is_err());
    assert!(adapter
        .validate_frame(
            Sequence::new(1).unwrap(),
            timestamp,
            &[sample(3.0), sample(3.0)]
        )
        .is_err());
    assert!(!adapter.is_retired());
    let result = frame(&mut adapter, 0, &[sample(3.0), sample(3.0)]);
    assert!(result
        .report()
        .unwrap()
        .channels()
        .iter()
        .all(|channel| channel.n() == 1));
}

#[test]
fn missing_evidence_returns_no_nominal_report_and_retires_the_window() {
    let mut adapter = monitor(&[Modality::Visual, Modality::Radar], 0);
    for index in 0..32 {
        frame(&mut adapter, index, &[sample(3.0), sample(3.0)]);
    }
    let absent = frame(&mut adapter, 32, &[sample(3.0), None]);
    assert!(absent.report().is_none());
    assert_eq!(absent.unavailable(), &[Modality::Radar]);
    assert!(adapter.is_retired());
    assert!(matches!(
        adapter.assess_frame(
            Sequence::new(33).unwrap(),
            TimestampMillis::new(660).unwrap(),
            &[sample(3.0), sample(3.0)]
        ),
        Err(AdapterError::Retired)
    ));

    let mut fresh = monitor(&[Modality::Visual, Modality::Radar], 33);
    let result = frame(&mut fresh, 33, &[sample(3.0), sample(3.0)]);
    assert!(result
        .report()
        .unwrap()
        .channels()
        .iter()
        .all(|channel| channel.n() == 1));
    assert_eq!(
        result.report().unwrap().verdict(),
        &Verdict::InsufficientEvidence
    );
}

#[test]
fn available_zero_and_absent_scalar_remain_distinct() {
    let mut valid = monitor(&[Modality::Radar], 0);
    let zero = frame(&mut valid, 0, &[sample(0.0)]);
    assert_eq!(zero.report().unwrap().channels()[0].sum_nis(), 0.0);
    assert_eq!(zero.report().unwrap().channels()[0].n(), 1);
    let absent = frame(&mut valid, 1, &[None]);
    assert!(absent.report().is_none());
    assert_eq!(absent.unavailable(), &[Modality::Radar]);
}

#[test]
fn malformed_later_channel_does_not_partially_mutate_the_first_channel() {
    for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
        let mut adapter = monitor(&[Modality::Visual, Modality::Radar], 0);
        assert!(matches!(
            adapter.assess_frame(
                Sequence::new(0).unwrap(),
                TimestampMillis::new(0).unwrap(),
                &[sample(300.0), sample(invalid)]
            ),
            Err(AdapterError::InvalidObservation(_))
        ));
        let corrected = frame(&mut adapter, 0, &[sample(3.0), sample(3.0)]);
        assert!(corrected
            .report()
            .unwrap()
            .channels()
            .iter()
            .all(|channel| channel.n() == 1 && channel.sum_nis() == 3.0));
    }
}

#[test]
fn invalid_present_evidence_cannot_hide_behind_an_absent_peer() {
    let mut adapter = monitor(&[Modality::Visual, Modality::Radar], 0);
    assert!(matches!(
        adapter.assess_frame(
            Sequence::new(0).unwrap(),
            TimestampMillis::new(0).unwrap(),
            &[None, sample(f64::NAN)]
        ),
        Err(AdapterError::InvalidObservation(_))
    ));
    assert!(!adapter.is_retired());
    assert!(frame(&mut adapter, 0, &[sample(3.0), sample(3.0)])
        .report()
        .is_some());
}

#[test]
fn wrong_arity_and_changed_dof_fail_before_ingestion() {
    let mut adapter = monitor(&[Modality::Visual, Modality::Radar], 0);
    assert!(matches!(
        adapter.assess_frame(
            Sequence::new(0).unwrap(),
            TimestampMillis::new(0).unwrap(),
            &[sample(3.0)]
        ),
        Err(AdapterError::FrameArity { .. })
    ));
    assert!(matches!(
        adapter.assess_frame(
            Sequence::new(0).unwrap(),
            TimestampMillis::new(0).unwrap(),
            &[sample(3.0), Some(NisEvidenceParams { nis: 3.0, dof: 4 })]
        ),
        Err(AdapterError::DegreesOfFreedomChanged { .. })
    ));
    let result = frame(&mut adapter, 0, &[sample(3.0), sample(3.0)]);
    assert!(result
        .report()
        .unwrap()
        .channels()
        .iter()
        .all(|channel| channel.n() == 1));
}

#[test]
fn invalid_rosters_fail_before_detector_construction() {
    let prepare = |channels: &[ScalarChannelParams]| {
        ScalarMonitor::prepare(
            TrackId::new(7).unwrap(),
            ClockDomain::SimulationTime,
            Sequence::new(0).unwrap(),
            channels,
            config(),
        )
    };
    let channel = ScalarChannelParams {
        modality: Modality::Radar,
        dof: 3,
    };
    assert!(matches!(prepare(&[]), Err(AdapterError::ChannelCount(0))));
    assert!(matches!(
        prepare(&[channel; 7]),
        Err(AdapterError::ChannelCount(7))
    ));
    assert!(matches!(
        prepare(&[channel; 2]),
        Err(AdapterError::DuplicateModality(Modality::Radar))
    ));
    assert!(matches!(
        prepare(&[ScalarChannelParams { dof: 0, ..channel }]),
        Err(AdapterError::ZeroDegreesOfFreedom(Modality::Radar))
    ));
    assert!(prepare(&[channel]).is_ok());
}

#[test]
fn sequence_replay_gap_and_wrong_initial_position_retire_the_monitor() {
    for bad_sequence in [0, 2] {
        let mut adapter = monitor(&[Modality::Radar], 0);
        frame(&mut adapter, 0, &[sample(3.0)]);
        assert!(matches!(
            adapter.assess_frame(
                Sequence::new(bad_sequence).unwrap(),
                TimestampMillis::new(20).unwrap(),
                &[sample(3.0)]
            ),
            Err(AdapterError::SequenceDiscontinuity { .. })
        ));
        assert!(adapter.is_retired());
    }
    let mut adapter = monitor(&[Modality::Radar], 5);
    assert!(matches!(
        adapter.assess_frame(
            Sequence::new(0).unwrap(),
            TimestampMillis::new(0).unwrap(),
            &[sample(3.0)]
        ),
        Err(AdapterError::SequenceDiscontinuity {
            expected: 5,
            actual: 0
        })
    ));
    let mut valid = monitor(&[Modality::Radar], 5);
    assert!(frame(&mut valid, 5, &[sample(3.0)]).report().is_some());
}

#[test]
fn timestamp_regression_and_excess_gap_retire_the_monitor() {
    for bad_time in [0, 10_001] {
        let mut adapter = monitor(&[Modality::Radar], 0);
        frame(&mut adapter, 0, &[sample(3.0)]);
        assert!(matches!(
            adapter.assess_frame(
                Sequence::new(1).unwrap(),
                TimestampMillis::new(bad_time).unwrap(),
                &[sample(3.0)]
            ),
            Err(AdapterError::TimestampDiscontinuity)
        ));
        assert!(adapter.is_retired());
    }
    let mut valid = monitor(&[Modality::Radar], 0);
    frame(&mut valid, 0, &[sample(3.0)]);
    assert!(valid
        .assess_frame(
            Sequence::new(1).unwrap(),
            TimestampMillis::new(10_000).unwrap(),
            &[sample(3.0)]
        )
        .is_ok());
}

#[test]
fn exhausted_sequence_never_wraps_into_a_fresh_window() {
    let mut adapter = monitor(&[Modality::Radar], JSON_SAFE_INTEGER_MAX);
    adapter
        .assess_frame(
            Sequence::new(JSON_SAFE_INTEGER_MAX).unwrap(),
            TimestampMillis::new(0).unwrap(),
            &[sample(3.0)],
        )
        .unwrap();
    assert!(matches!(
        adapter.assess_frame(
            Sequence::new(0).unwrap(),
            TimestampMillis::new(20).unwrap(),
            &[sample(3.0)]
        ),
        Err(AdapterError::SequenceExhausted)
    ));
    assert!(adapter.is_retired());
}

#[test]
fn adapter_identity_binds_order_and_initial_position() {
    let first = monitor(&[Modality::Visual, Modality::Radar], 0);
    let same = monitor(&[Modality::Visual, Modality::Radar], 0);
    let reordered = monitor(&[Modality::Radar, Modality::Visual], 0);
    let later = monitor(&[Modality::Visual, Modality::Radar], 1);
    assert_eq!(first.adapter_identity(), same.adapter_identity());
    assert_ne!(first.adapter_identity(), reordered.adapter_identity());
    assert_ne!(first.adapter_identity(), later.adapter_identity());
}
