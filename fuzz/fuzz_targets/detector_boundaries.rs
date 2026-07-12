#![no_main]

use galadriel_core::{
    assess_default, consistency_channels_with_temporal_limits, CorrConfig, DetectorConfig, Mirror,
    Modality, PidObservation,
};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT_BYTES: usize = 128 * 1024;
const MAX_FUZZ_OBSERVATIONS: usize = 1_024;

fn u64_prefix(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0_u8; 8];
    let tail = data.get(offset..).unwrap_or_default();
    let available = tail.len().min(bytes.len());
    bytes[..available].copy_from_slice(&tail[..available]);
    u64::from_le_bytes(bytes)
}

fuzz_target!(|data: &[u8]| {
    let bounded = &data[..data.len().min(MAX_FUZZ_INPUT_BYTES)];
    let max_seq_gap = u64_prefix(bounded, 0);
    let max_timestamp_skew_ms = u64_prefix(bounded, 8);
    let max_inter_sample_gap_ms = u64_prefix(bounded, 16);

    let mut config = DetectorConfig::default();
    config.max_seq_gap = max_seq_gap;
    config.max_timestamp_skew_ms = max_timestamp_skew_ms;
    config.max_inter_sample_gap_ms = max_inter_sample_gap_ms;
    let _ = config.validate();

    let Ok(mut observations) = serde_json::from_slice::<Vec<PidObservation>>(bounded) else {
        return;
    };
    observations.truncate(MAX_FUZZ_OBSERVATIONS);
    for observation in &observations {
        let _ = observation.validate();
    }

    // Drive stateful sequence/timestamp reset paths using only configurations
    // admitted by the public validator.
    let default_config = DetectorConfig::default();
    if let Ok(mut mirror) = Mirror::new(default_config.clone()) {
        for observation in &observations {
            let _ = mirror.ingest(observation);
            let _ = mirror.assess(observation.track_id, observation.seq);
        }
    }

    let modalities = [Modality::Visual, Modality::Radar, Modality::Acoustic];
    let _ = consistency_channels_with_temporal_limits(
        &observations,
        &modalities,
        max_seq_gap,
        max_timestamp_skew_ms,
        max_inter_sample_gap_ms,
    );

    // Bound the expensive fused assessment while exercising projection provenance,
    // axis conflict, and fail-closed extraction behavior.
    let _ = assess_default(
        &observations,
        &modalities,
        &default_config,
        &CorrConfig::default(),
    );
});
