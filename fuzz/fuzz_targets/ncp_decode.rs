#![no_main]

use galadriel_ncp::{
    monitor::MonitorEnvelope,
    parse_jsonl_with_limits,
    registry::DeploymentRegistry,
    JsonlLimits, SidecarEnvelope, DEFAULT_MAX_JSONL_LINE_BYTES,
};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT_BYTES: usize = 128 * 1024;

fuzz_target!(|data: &[u8]| {
    let bounded = &data[..data.len().min(MAX_FUZZ_INPUT_BYTES)];

    if let Ok(envelope) = serde_json::from_slice::<SidecarEnvelope>(bounded) {
        let _ = envelope.validate();
        let _ = envelope.validate_for(&envelope.session_id, &envelope.producer_id);
        let _ = serde_json::to_vec(&envelope);
    }

    // Exercise the independent lifecycle/liveness wire contract as well as the
    // observation envelope. `decode` includes the pre-decode size gate and strict
    // semantic validation; a successful value must also round-trip without a
    // panic or an unbounded allocation.
    if let Ok(envelope) = MonitorEnvelope::decode(bounded) {
        let _ = envelope.validate();
        let _ = envelope.validate_for(&envelope.session_id, &envelope.producer_id);
        let _ = envelope.encode();
    }

    // Registry parsing is an operational trust boundary. Arbitrary bytes must
    // remain bounded by its document ceiling, strict unknown-field decoder, and
    // semantic/canonicalization checks.
    let _ = DeploymentRegistry::from_json(bounded);

    // Exercise bounded JSONL framing, duplicate-key rejection through typed
    // records, numeric identities, and per-(track, modality) sequence tracking.
    let limits =
        JsonlLimits::with_total_bytes(DEFAULT_MAX_JSONL_LINE_BYTES, 256, MAX_FUZZ_INPUT_BYTES)
            .expect("fixed fuzz limits are valid");
    let text = String::from_utf8_lossy(bounded);
    let _ = parse_jsonl_with_limits(&text, limits);
});
