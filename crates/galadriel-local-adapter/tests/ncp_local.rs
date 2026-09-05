#![cfg(feature = "ncp-local")]

use std::io::Cursor;
use std::process::{Command, Stdio};

use ::ncp_local::local::{
    local_digest, local_profile_digest, read_local_frame, write_local_frame, LocalBinding,
    LocalCode, LocalOperation, LocalOutcome, LocalOwner, LocalRequest, LocalResponse, LocalRole,
};
use ::ncp_local::local_data::{
    action_layout, observation_layout, ActionMode, BodyResult, InnovationSource, InnovationStatus,
    RunPlan, ScalarInnovation, Snapshot,
};
use galadriel_core::{ClockDomain, DetectorConfig, Modality, Sequence, TimestampMillis, TrackId};
use galadriel_local_adapter::ncp_local::{local_owner, NativeMonitor, APPLICATION_PROFILE};
use galadriel_local_adapter::{NisEvidenceParams, ScalarChannelParams, ScalarMonitor};
use serde_json::{json, Value};

const RUN: &str = "00000000-0000-4000-8000-000000000001";
const MONITOR: &str = "00000000-0000-4000-8000-000000000002";
const BODY: &str = "00000000-0000-4000-8000-000000000003";

fn plan(count: usize, steps: u64) -> RunPlan {
    RunPlan {
        schema: "ncp.local.plan.v1".into(),
        entity_ids: (0..count).map(|i| format!("entity_{i}")).collect(),
        planned_steps: steps,
        step_us: 20_000,
        resolution_us: 100,
        readout_delay_us: 1000,
        seed: 73,
        execution_mode: "direct_simulation".into(),
        capture_mode: "lossless_bounded".into(),
        monitor_mode: "record_only".into(),
        calibrated_posterior: false,
        observation_layout: observation_layout(),
        action_layout: action_layout(),
    }
}

fn preparation(plan: &RunPlan) -> Value {
    json!({"plan": plan, "application_profile": APPLICATION_PROFILE,
        "configuration": {"body_generation": BODY}})
}

fn request(
    binding: &LocalBinding,
    sequence: u64,
    operation: LocalOperation,
    body: Value,
) -> LocalRequest {
    let mut request = LocalRequest {
        schema: "ncp.local.request.v1".into(),
        profile_digest: binding.profile_digest.clone(),
        run_id: binding.run_id.clone(),
        generation: binding.generation.clone(),
        sequence,
        operation,
        body,
        request_digest: String::new(),
    };
    request.seal().unwrap();
    request
}

fn send(
    owner: &mut LocalOwner<NativeMonitor>,
    sequence: u64,
    operation: LocalOperation,
    body: Value,
) -> LocalResponse {
    let request = request(owner.binding(), sequence, operation, body);
    let bytes = owner
        .handle(&serde_json::to_vec(&request).unwrap())
        .unwrap();
    let response: LocalResponse = serde_json::from_slice(&bytes).unwrap();
    assert!(
        response.verify(owner.binding(), &request).is_ok(),
        "verification failed at {sequence}/{operation:?}: {response:?}"
    );
    response
}

fn acknowledge(owner: &mut LocalOwner<NativeMonitor>, response: &LocalResponse) {
    let ack = send(
        owner,
        response.sequence,
        LocalOperation::Ack,
        json!({"result_digest": response.result_digest}),
    );
    assert_eq!(ack.outcome, LocalOutcome::Acknowledged);
}

fn committed(
    owner: &mut LocalOwner<NativeMonitor>,
    sequence: u64,
    operation: LocalOperation,
    body: Value,
) -> LocalResponse {
    let response = send(owner, sequence, operation, body);
    assert_eq!(response.outcome, LocalOutcome::Committed, "{response:?}");
    acknowledge(owner, &response);
    response
}

fn prepared(plan: &RunPlan) -> LocalOwner<NativeMonitor> {
    let mut owner = local_owner(RUN.into(), MONITOR.into()).unwrap();
    let response = committed(&mut owner, 1, LocalOperation::Prepare, preparation(plan));
    assert_eq!(response.body["min_channels"], 2);
    assert_eq!(response.body["calibrated_posterior"], false);
    owner
}

fn seal_response(response: &mut LocalResponse) {
    let mut value = serde_json::to_value(&*response).unwrap();
    value.as_object_mut().unwrap().remove("result_digest");
    response.result_digest = local_digest("ncp.local.response.v1", &value).unwrap();
}

// Synthetic protocol controls, never labelled as CREBAIN-produced evidence.
fn body_result(
    plan: &RunPlan,
    step: u64,
    previous: &str,
    statuses: &[InnovationStatus],
) -> LocalResponse {
    let mut snapshot = Snapshot {
        schema: "ncp.local.snapshot.v1".into(),
        plan_digest: plan.digest().unwrap(),
        step,
        time_us: plan.time_us(step).unwrap(),
        entity_ids: plan.entity_ids.clone(),
        available: statuses
            .iter()
            .map(|status| *status != InnovationStatus::Unavailable)
            .collect(),
        values: vec![0.0; plan.entity_ids.len() * 6],
        innovations: plan
            .entity_ids
            .iter()
            .zip(statuses)
            .enumerate()
            .map(|(index, (id, status))| {
                let observed = *status == InnovationStatus::Observed;
                ScalarInnovation {
                    entity_id: id.clone(),
                    modality: "visual".into(),
                    dof: 3,
                    status: *status,
                    nis: observed.then_some(3.0 + index as f64),
                    source: observed.then(|| InnovationSource {
                        sensor_id: format!("visual_{index}"),
                        fusion_track_id: 17 + index as u64,
                        fusion_sequence: 100 + step,
                        measurement_time_us: plan.time_us(step).unwrap(),
                        residual_m: [(3.0 + index as f64).sqrt(), 0.0, 0.0],
                        covariance_m2: [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
                    }),
                }
            })
            .collect(),
        snapshot_digest: String::new(),
    };
    snapshot.seal(plan).unwrap();
    let result = BodyResult {
        schema: "ncp.local.body-result.v1".into(),
        plan_digest: plan.digest().unwrap(),
        step,
        source_snapshot_digest: previous.into(),
        neural_result_digest: "a".repeat(64),
        selected_modes: vec![ActionMode::ZeroAcceleration; plan.entity_ids.len()],
        proposed_values: vec![0.0; plan.entity_ids.len() * 3],
        applied_values: vec![0.0; plan.entity_ids.len() * 3],
        saturated: vec![false; plan.entity_ids.len()],
        snapshot,
    };
    result.validate(plan).unwrap();
    let mut response = LocalResponse {
        schema: "ncp.local.response.v1".into(),
        binding: LocalBinding {
            profile_digest: local_profile_digest().unwrap(),
            run_id: RUN.into(),
            generation: BODY.into(),
            role: LocalRole::Body,
        },
        sequence: step + 1,
        operation: LocalOperation::Step,
        request_digest: "b".repeat(64),
        outcome: LocalOutcome::Committed,
        code: LocalCode::Ok,
        body: serde_json::to_value(result).unwrap(),
        result_digest: String::new(),
    };
    seal_response(&mut response);
    response
}

fn assess(owner: &mut LocalOwner<NativeMonitor>, body: &LocalResponse) -> LocalResponse {
    committed(
        owner,
        body.sequence,
        LocalOperation::Assess,
        json!({"body_response": body}),
    )
}

fn snapshot_digest(body: &LocalResponse) -> &str {
    body.body["snapshot"]["snapshot_digest"].as_str().unwrap()
}

fn reseal_snapshot(plan: &RunPlan, body: &mut LocalResponse) {
    let mut snapshot: Snapshot = serde_json::from_value(body.body["snapshot"].clone()).unwrap();
    snapshot.seal(plan).unwrap();
    body.body["snapshot"] = serde_json::to_value(snapshot).unwrap();
    seal_response(body);
}

#[test]
fn actual_engine_probabilities_preserve_exact_ieee_bits_through_json() {
    for nis in [3.0, 4.0, 5.0] {
        let mut monitor = ScalarMonitor::prepare(
            TrackId::new(17).unwrap(),
            ClockDomain::SimulationTime,
            Sequence::new(101).unwrap(),
            &[ScalarChannelParams {
                modality: Modality::Visual,
                dof: 3,
            }],
            DetectorConfig::standalone_advisory_v0_9().unwrap(),
        )
        .unwrap();
        for step in 1..=96 {
            let result = monitor
                .assess_frame(
                    Sequence::new(100 + step).unwrap(),
                    TimestampMillis::new(step * 20).unwrap(),
                    &[Some(NisEvidenceParams { nis, dof: 3 })],
                )
                .unwrap();
            let original = serde_json::to_value(result.report().unwrap()).unwrap();
            let encoded = serde_json::to_vec(&original).unwrap();
            let decoded: Value = serde_json::from_slice(&encoded).unwrap();
            let before = original["channels"][0]["p_right"].as_f64().unwrap();
            let after = decoded["channels"][0]["p_right"].as_f64().unwrap();
            if before.to_bits() != after.to_bits() {
                eprintln!("original_report_json={}", String::from_utf8_lossy(&encoded));
            }
            assert_eq!(
                before.to_bits(),
                after.to_bits(),
                "step={step} nis={nis} before={before:?}/{:016x} after={after:?}/{:016x}",
                before.to_bits(),
                after.to_bits()
            );
        }
    }
}

#[test]
fn native_owner_runs_actual_engine_for_a_bounded_three_entity_roster() {
    let plan = plan(3, 96);
    let mut owner = prepared(&plan);
    let mut expected = ScalarMonitor::prepare(
        TrackId::new(17).unwrap(),
        ClockDomain::SimulationTime,
        Sequence::new(101).unwrap(),
        &[ScalarChannelParams {
            modality: Modality::Visual,
            dof: 3,
        }],
        DetectorConfig::standalone_advisory_v0_9().unwrap(),
    )
    .unwrap();
    let mut previous = "c".repeat(64);
    for step in 1..=96 {
        let body = body_result(&plan, step, &previous, &[InnovationStatus::Observed; 3]);
        let response = assess(&mut owner, &body);
        let real = expected
            .assess_frame(
                Sequence::new(100 + step).unwrap(),
                TimestampMillis::new(step * 20).unwrap(),
                &[Some(NisEvidenceParams { nis: 3.0, dof: 3 })],
            )
            .unwrap();
        let direct_json = serde_json::to_value(real.report().unwrap()).unwrap();
        let encoded = serde_json::to_vec(&direct_json).unwrap();
        let decoded: Value = serde_json::from_slice(&encoded).unwrap();
        if direct_json != decoded {
            let before = direct_json["channels"][0]["p_right"].as_f64().unwrap();
            let after = decoded["channels"][0]["p_right"].as_f64().unwrap();
            panic!(
                "float roundtrip before={before:?} {:016x} after={after:?} {:016x}",
                before.to_bits(),
                after.to_bits()
            );
        }
        assert_eq!(
            response.body["tracks"][0]["report"],
            serde_json::to_value(real.report().unwrap()).unwrap()
        );
        assert_eq!(response.body["body_result_digest"], body.result_digest);
        assert_eq!(response.body["snapshot_digest"], snapshot_digest(&body));
        assert_eq!(response.body["tracks"].as_array().unwrap().len(), 3);
        assert_eq!(response.body["calibrated_posterior"], false);
        assert!(serde_json::to_vec(&response).unwrap().len() < 16_384);
        previous = snapshot_digest(&body).into();
    }
    let finish = committed(
        &mut owner,
        98,
        LocalOperation::Finish,
        json!({"plan_digest": plan.digest().unwrap(), "completed_steps": 96}),
    );
    assert_eq!(finish.body["completed_steps"], 96);
}

#[test]
fn birth_and_missingness_never_fabricate_samples_or_restore_retired_windows() {
    let plan = plan(2, 4);
    let mut owner = prepared(&plan);
    let first = body_result(
        &plan,
        1,
        &"c".repeat(64),
        &[InnovationStatus::Birth, InnovationStatus::Observed],
    );
    let output = assess(&mut owner, &first);
    assert_eq!(output.body["tracks"][0]["status"], "not_ready");
    assert_eq!(output.body["tracks"][0]["reason"], "birth");
    assert!(output.body["tracks"][0]["report"].is_null());
    assert!(output.body["tracks"][0]["source"].is_null());
    let second = body_result(
        &plan,
        2,
        snapshot_digest(&first),
        &[InnovationStatus::Birth, InnovationStatus::Unavailable],
    );
    let output = assess(&mut owner, &second);
    assert_eq!(
        output.body["tracks"][1]["reason"],
        "missing_after_activation"
    );
    let third = body_result(
        &plan,
        3,
        snapshot_digest(&second),
        &[InnovationStatus::Observed; 2],
    );
    let output = assess(&mut owner, &third);
    assert_eq!(output.body["tracks"][0]["report"]["channels"][0]["n"], 1);
    assert_eq!(output.body["tracks"][0]["report"]["seq"], 103);
    assert_eq!(output.body["tracks"][1]["reason"], "retired_window");
    assert!(output.body["tracks"][1]["report"].is_null());
    let fourth = body_result(
        &plan,
        4,
        snapshot_digest(&third),
        &[InnovationStatus::Observed; 2],
    );
    let output = assess(&mut owner, &fourth);
    assert_eq!(output.body["tracks"][0]["report"]["channels"][0]["n"], 2);
    assert_eq!(output.body["tracks"][1]["status"], "retired");
}

#[test]
fn unavailability_before_first_observation_allows_fresh_activation() {
    let plan = plan(1, 2);
    let mut owner = prepared(&plan);
    let first = body_result(&plan, 1, &"c".repeat(64), &[InnovationStatus::Unavailable]);
    let output = assess(&mut owner, &first);
    assert_eq!(
        output.body["tracks"][0]["reason"],
        "unavailable_before_activation"
    );
    let second = body_result(
        &plan,
        2,
        snapshot_digest(&first),
        &[InnovationStatus::Observed],
    );
    let output = assess(&mut owner, &second);
    assert_eq!(output.body["tracks"][0]["report"]["channels"][0]["n"], 1);
}

#[test]
fn fresh_endpoint_generation_starts_an_empty_window_after_retirement() {
    let plan = plan(1, 2);
    let mut owner = prepared(&plan);
    let first = body_result(&plan, 1, &"c".repeat(64), &[InnovationStatus::Observed]);
    assess(&mut owner, &first);
    let missing = body_result(
        &plan,
        2,
        snapshot_digest(&first),
        &[InnovationStatus::Unavailable],
    );
    let retired = assess(&mut owner, &missing);
    assert_eq!(retired.body["tracks"][0]["status"], "retired");
    let mut fresh = local_owner(RUN.into(), "00000000-0000-4000-8000-000000000004".into()).unwrap();
    committed(&mut fresh, 1, LocalOperation::Prepare, preparation(&plan));
    let accepted = assess(&mut fresh, &first);
    assert_eq!(accepted.body["tracks"][0]["report"]["channels"][0]["n"], 1);
}

#[test]
fn corrupt_nested_response_rejects_before_any_detector_mutation() {
    let plan = plan(2, 1);
    let original = body_result(&plan, 1, &"c".repeat(64), &[InnovationStatus::Observed; 2]);
    for case in 0..13 {
        let mut owner = prepared(&plan);
        let mut bad = original.clone();
        match case {
            0 => bad.body["snapshot"]["innovations"][1]["nis"] = json!(99.0),
            1 => bad.binding.generation = MONITOR.into(),
            2 => bad.binding.run_id = BODY.into(),
            3 => bad.binding.role = LocalRole::Neural,
            4 => bad.schema = "other".into(),
            5 => bad.operation = LocalOperation::Prepare,
            6 => bad.outcome = LocalOutcome::Indeterminate,
            7 => bad.sequence += 1,
            8 => bad.body["schema"] = json!("other"),
            9 => bad.body["snapshot"]["innovations"][1]["dof"] = json!(4),
            10 => bad.body["snapshot"]["unexpected"] = json!(true),
            11 => bad.request_digest = "short".into(),
            12 => bad.body["applied_values"] = json!([100.0, 0.0, 0.0, 0.0, 0.0, 0.0]),
            _ => unreachable!(),
        }
        // Case zero isolates unsealed byte corruption. Others have coherent
        // outer digests but invalid identity, lifecycle, or application data.
        if case != 0 {
            seal_response(&mut bad);
        }
        let rejected = send(
            &mut owner,
            2,
            LocalOperation::Assess,
            json!({"body_response": bad}),
        );
        assert_eq!(
            rejected.outcome,
            LocalOutcome::RejectedBeforeExecution,
            "case {case}"
        );
        let accepted = assess(&mut owner, &original);
        for track in accepted.body["tracks"].as_array().unwrap() {
            assert_eq!(track["report"]["channels"][0]["n"], 1);
        }
    }
}

#[test]
fn validly_hashed_producer_identity_sequence_and_snapshot_forks_reject_before_ingestion() {
    let plan = plan(1, 2);
    for case in 0..4 {
        let mut owner = prepared(&plan);
        let first = body_result(&plan, 1, &"c".repeat(64), &[InnovationStatus::Observed]);
        assess(&mut owner, &first);
        let second = body_result(
            &plan,
            2,
            snapshot_digest(&first),
            &[InnovationStatus::Observed],
        );
        let mut bad = second.clone();
        match case {
            0 => bad.body["snapshot"]["innovations"][0]["source"]["sensor_id"] = json!("other"),
            1 => bad.body["snapshot"]["innovations"][0]["source"]["fusion_track_id"] = json!(90),
            2 => bad.body["snapshot"]["innovations"][0]["source"]["fusion_sequence"] = json!(103),
            3 => bad.body["source_snapshot_digest"] = json!("d".repeat(64)),
            _ => unreachable!(),
        }
        reseal_snapshot(&plan, &mut bad);
        let rejected = send(
            &mut owner,
            3,
            LocalOperation::Assess,
            json!({"body_response": bad}),
        );
        assert_eq!(rejected.outcome, LocalOutcome::RejectedBeforeExecution);
        let accepted = assess(&mut owner, &second);
        assert_eq!(accepted.body["tracks"][0]["report"]["channels"][0]["n"], 2);
    }
}

#[test]
fn unsupported_prepare_modes_and_launch_bindings_fail_before_preparation() {
    assert!(local_owner("bad".into(), MONITOR.into()).is_err());
    let plan = plan(1, 1);
    for case in 0..7 {
        let mut owner = local_owner(RUN.into(), MONITOR.into()).unwrap();
        let mut bad = preparation(&plan);
        match case {
            0 => bad["plan"]["execution_mode"] = json!("haldir_gated"),
            1 => bad["plan"]["monitor_mode"] = json!("deny_only"),
            2 => bad["plan"]["calibrated_posterior"] = json!(true),
            3 => bad["configuration"]["body_generation"] = json!(MONITOR),
            4 => bad["configuration"]["body_generation"] = json!("bad"),
            5 => bad["configuration"]["command"] = json!("inert-data"),
            6 => bad["application_profile"] = json!("default"),
            _ => unreachable!(),
        }
        let response = send(&mut owner, 1, LocalOperation::Prepare, bad);
        assert_eq!(response.outcome, LocalOutcome::RejectedBeforeExecution);
        committed(&mut owner, 1, LocalOperation::Prepare, preparation(&plan));
    }
}

#[test]
fn retained_result_replay_acknowledgement_and_role_boundary_never_rerun_engine() {
    let plan = plan(1, 2);
    let mut owner = prepared(&plan);
    let first = body_result(&plan, 1, &"c".repeat(64), &[InnovationStatus::Observed]);
    let request = request(
        owner.binding(),
        2,
        LocalOperation::Assess,
        json!({"body_response": first}),
    );
    let bytes = serde_json::to_vec(&request).unwrap();
    let exact = owner.handle(&bytes).unwrap();
    assert_eq!(owner.handle(&bytes).unwrap(), exact);
    let response: LocalResponse = serde_json::from_slice(&exact).unwrap();
    let lookup = request_for_lookup(owner.binding(), &request);
    let retrieved: LocalResponse =
        serde_json::from_slice(&owner.handle(&serde_json::to_vec(&lookup).unwrap()).unwrap())
            .unwrap();
    retrieved
        .verify_retrieved(owner.binding(), &request, &lookup)
        .unwrap();
    assert_eq!(retrieved, response);
    let second = body_result(
        &plan,
        2,
        snapshot_digest(&first),
        &[InnovationStatus::Observed],
    );
    let pending = send(
        &mut owner,
        3,
        LocalOperation::Assess,
        json!({"body_response": second}),
    );
    assert_eq!(pending.code, LocalCode::ResultPending);
    acknowledge(&mut owner, &response);
    let denied = send(&mut owner, 3, LocalOperation::Step, json!({}));
    assert_eq!(denied.code, LocalCode::Role);
    let completed = assess(&mut owner, &second);
    assert_eq!(completed.body["tracks"][0]["report"]["channels"][0]["n"], 2);
}

fn request_for_lookup(binding: &LocalBinding, original: &LocalRequest) -> LocalRequest {
    request(
        binding,
        original.sequence,
        LocalOperation::Result,
        json!({"request_digest": original.request_digest}),
    )
}

#[test]
fn finish_requires_exact_counts_and_abort_retires_endpoint() {
    let plan = plan(1, 1);
    let mut owner = prepared(&plan);
    let premature = send(
        &mut owner,
        2,
        LocalOperation::Finish,
        json!({"plan_digest": plan.digest().unwrap(), "completed_steps": 1}),
    );
    assert_eq!(premature.outcome, LocalOutcome::RejectedBeforeExecution);
    committed(&mut owner, 2, LocalOperation::Abort, json!({}));
    let late = body_result(&plan, 1, &"c".repeat(64), &[InnovationStatus::Observed]);
    let response = send(
        &mut owner,
        3,
        LocalOperation::Assess,
        json!({"body_response": late}),
    );
    assert_eq!(response.outcome, LocalOutcome::RejectedBeforeExecution);
    assert!(matches!(
        response.code,
        LocalCode::State | LocalCode::Retired
    ));
}

#[test]
fn finish_rejects_wrong_plan_count_and_extra_fields_before_closing() {
    let plan = plan(1, 1);
    let mut owner = prepared(&plan);
    let first = body_result(&plan, 1, &"c".repeat(64), &[InnovationStatus::Observed]);
    assess(&mut owner, &first);
    for bad in [
        json!({}),
        json!({"plan_digest": "d".repeat(64), "completed_steps": 1}),
        json!({"plan_digest": plan.digest().unwrap(), "completed_steps": 0}),
        json!({"plan_digest": plan.digest().unwrap(), "completed_steps": 1, "unknown": true}),
    ] {
        let rejected = send(&mut owner, 3, LocalOperation::Finish, bad);
        assert_eq!(rejected.outcome, LocalOutcome::RejectedBeforeExecution);
    }
    committed(
        &mut owner,
        3,
        LocalOperation::Finish,
        json!({"plan_digest": plan.digest().unwrap(), "completed_steps": 1}),
    );
}

#[test]
fn private_pipe_binary_runs_framed_prepare_and_rejects_unknown_launch_selectors() {
    let plan = plan(1, 1);
    let owner = local_owner(RUN.into(), MONITOR.into()).unwrap();
    let request = request(
        owner.binding(),
        1,
        LocalOperation::Prepare,
        preparation(&plan),
    );
    let bytes = serde_json::to_vec(&request).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_galadriel-ncp-local"))
        .args(["--run-id", RUN, "--generation", MONITOR])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    write_local_frame(&mut child.stdin.take().unwrap(), &bytes).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let mut reader = Cursor::new(output.stdout);
    let response: LocalResponse =
        serde_json::from_slice(&read_local_frame(&mut reader).unwrap().unwrap()).unwrap();
    response.verify(owner.binding(), &request).unwrap();
    assert_eq!(response.outcome, LocalOutcome::Committed);
    assert!(read_local_frame(&mut reader).unwrap().is_none());
    let rejected = Command::new(env!("CARGO_BIN_EXE_galadriel-ncp-local"))
        .args(["--run-id", RUN, "--generation", MONITOR, "--role", "body"])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
}

#[test]
fn private_pipe_binary_rejects_truncated_and_oversized_frames() {
    use std::io::Write;
    for bytes in [vec![0, 0], vec![0, 0, 0, 8, b'{'], vec![0, 1, 0, 1]] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_galadriel-ncp-local"))
            .args(["--run-id", RUN, "--generation", MONITOR])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&bytes).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.len() < 128);
    }
}
