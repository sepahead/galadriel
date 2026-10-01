//! Optional local NCP owner for bounded, record-only scalar diagnostics.
//!
//! The supervisor installs one run and endpoint generation. Preparation binds
//! the exact body generation and immutable plan. Local digests establish the
//! integrity of those supplied labels and bytes; they are not signatures.

use ::ncp_local::local::{
    local_profile_digest, LocalBackend, LocalBinding, LocalCode, LocalError, LocalOperation,
    LocalOutcome, LocalOwner, LocalResponse, LocalRole,
};
use ::ncp_local::local_data::{
    BodyResult, InnovationSource, InnovationStatus, PrepareData, RunPlan,
};
use galadriel_core::{
    AssessmentClassification, ClockDomain, DetectorConfig, Sequence, TimestampMillis, TrackId,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{NisEvidenceParams, ScalarChannelParams, ScalarMonitor, RESEARCH_PROFILE};

/// Exact experimental application profile. It has no command capability.
pub const APPLICATION_PROFILE: &str = "galadriel.scalar-nis-record-only.v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    body_generation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssessData {
    body_response: LocalResponse,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishData {
    plan_digest: String,
    completed_steps: u64,
}

enum TrackState {
    Waiting,
    Active {
        monitor: Box<ScalarMonitor>,
        sensor_id: String,
        fusion_track_id: u64,
    },
    Retired,
}

struct PreparedMonitor {
    plan: RunPlan,
    plan_digest: String,
    body_binding: LocalBinding,
    tracks: Vec<TrackState>,
    completed_steps: u64,
    previous_snapshot_digest: Option<String>,
}

/// Opaque application backend with one bounded detector per prepared entity.
///
/// Construct it through [`local_owner`]. The role and detector configuration
/// cannot be changed by a request. No monitor result permits a command.
pub struct NativeMonitor {
    installed: LocalBinding,
    config: DetectorConfig,
    prepared: Option<PreparedMonitor>,
    retired: bool,
}

/// Create one monitor owner under supervisor-issued run and generation labels.
///
/// The installed protocol digest and monitor role derive from compiled code.
/// This function opens no listener, file, network connection, or subprocess.
///
/// # Errors
/// Rejects invalid launch identities or an unavailable detector configuration.
pub fn local_owner(
    run_id: String,
    generation: String,
) -> Result<LocalOwner<NativeMonitor>, LocalError> {
    let installed = LocalBinding {
        profile_digest: local_profile_digest()?,
        run_id,
        generation,
        role: LocalRole::Monitor,
    };
    let config = DetectorConfig::standalone_advisory_v0_9().map_err(invalid)?;
    LocalOwner::new(
        installed.clone(),
        NativeMonitor {
            installed,
            config,
            prepared: None,
            retired: false,
        },
    )
}

fn invalid<T>(_: T) -> LocalError {
    LocalError(LocalCode::InvalidInput)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}

fn parse<T: serde::de::DeserializeOwned>(body: &Value) -> Result<T, LocalError> {
    serde_json::from_value(body.clone()).map_err(invalid)
}

fn scalar_monitor(
    source: &InnovationSource,
    config: DetectorConfig,
) -> Result<ScalarMonitor, LocalError> {
    ScalarMonitor::prepare(
        TrackId::new(source.fusion_track_id).map_err(invalid)?,
        ClockDomain::SimulationTime,
        Sequence::new(source.fusion_sequence).map_err(invalid)?,
        &[ScalarChannelParams {
            modality: galadriel_core::Modality::Visual,
            dof: 3,
        }],
        config,
    )
    .map_err(invalid)
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum TrackStatus {
    NotReady,
    Evaluated,
    Retired,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum AbstentionReason {
    Birth,
    UnavailableBeforeActivation,
    MissingAfterActivation,
    RetiredWindow,
}

#[derive(Serialize)]
struct TrackAssessment<'a> {
    entity_id: &'a str,
    source: Option<&'a InnovationSource>,
    modality: &'static str,
    dof: u8,
    status: TrackStatus,
    reason: Option<AbstentionReason>,
    adapter_digest: Option<String>,
    report: Option<Value>,
}

impl NativeMonitor {
    fn prepare_data(&self, body: &Value) -> Result<(PrepareData, LocalBinding), LocalError> {
        if self.prepared.is_some() {
            return Err(LocalError(LocalCode::State));
        }
        let data: PrepareData = parse(body)?;
        data.plan.validate()?;
        if data.application_profile != APPLICATION_PROFILE {
            return Err(LocalError(LocalCode::InvalidInput));
        }
        let configuration: Configuration = parse(&data.configuration)?;
        let binding = LocalBinding {
            profile_digest: self.installed.profile_digest.clone(),
            run_id: self.installed.run_id.clone(),
            generation: configuration.body_generation,
            role: LocalRole::Body,
        };
        binding.validate()?;
        if binding.generation == self.installed.generation {
            return Err(LocalError(LocalCode::Binding));
        }
        Ok((data, binding))
    }

    fn assessment_data(&self, body: &Value) -> Result<(AssessData, BodyResult), LocalError> {
        let prepared = self.prepared.as_ref().ok_or(LocalError(LocalCode::State))?;
        let data: AssessData = parse(body)?;
        let response = &data.body_response;
        response.verify_integrity(&prepared.body_binding)?;
        if response.operation != LocalOperation::Step
            || response.outcome != LocalOutcome::Committed
            || response.code != LocalCode::Ok
        {
            return Err(LocalError(LocalCode::InvalidInput));
        }
        let result: BodyResult = parse(&response.body)?;
        result.validate(&prepared.plan)?;
        if result.step != prepared.completed_steps + 1 || response.sequence != result.step + 1 {
            return Err(LocalError(LocalCode::State));
        }
        if prepared
            .previous_snapshot_digest
            .as_ref()
            .is_some_and(|previous| previous != &result.source_snapshot_digest)
        {
            return Err(LocalError(LocalCode::Binding));
        }
        let time = TimestampMillis::new(result.snapshot.time_us / 1000).map_err(invalid)?;
        for (track, innovation) in prepared.tracks.iter().zip(&result.snapshot.innovations) {
            let evidence = innovation.nis.map(|nis| NisEvidenceParams {
                nis,
                dof: innovation.dof,
            });
            match track {
                TrackState::Active {
                    monitor,
                    sensor_id,
                    fusion_track_id,
                } => {
                    if let Some(source) = &innovation.source {
                        if &source.sensor_id != sensor_id
                            || &source.fusion_track_id != fusion_track_id
                        {
                            return Err(LocalError(LocalCode::Binding));
                        }
                        monitor
                            .validate_frame(
                                Sequence::new(source.fusion_sequence).map_err(invalid)?,
                                time,
                                &[evidence],
                            )
                            .map_err(invalid)?;
                    }
                    // Absence has no producer sequence. Execution retires the
                    // window without inventing an observation or position.
                }
                TrackState::Waiting if innovation.status == InnovationStatus::Observed => {
                    let source = innovation
                        .source
                        .as_ref()
                        .ok_or(LocalError(LocalCode::InvalidInput))?;
                    scalar_monitor(source, self.config.clone())?
                        .validate_frame(
                            Sequence::new(source.fusion_sequence).map_err(invalid)?,
                            time,
                            &[evidence],
                        )
                        .map_err(invalid)?;
                }
                TrackState::Waiting | TrackState::Retired => (),
            }
        }
        Ok((data, result))
    }

    fn assess(&mut self, data: AssessData, result: BodyResult) -> Result<Value, LocalError> {
        let prepared = self.prepared.as_mut().ok_or(LocalError(LocalCode::State))?;
        let time = TimestampMillis::new(result.snapshot.time_us / 1000).map_err(invalid)?;
        let mut reports = Vec::with_capacity(prepared.tracks.len());
        for (track, innovation) in prepared.tracks.iter_mut().zip(&result.snapshot.innovations) {
            if matches!(track, TrackState::Waiting)
                && innovation.status == InnovationStatus::Observed
            {
                let source = innovation
                    .source
                    .as_ref()
                    .ok_or(LocalError(LocalCode::InvalidInput))?;
                *track = TrackState::Active {
                    monitor: Box::new(scalar_monitor(source, self.config.clone())?),
                    sensor_id: source.sensor_id.clone(),
                    fusion_track_id: source.fusion_track_id,
                };
            }
            let mut output = TrackAssessment {
                entity_id: &innovation.entity_id,
                source: innovation.source.as_ref(),
                modality: "visual",
                dof: 3,
                status: TrackStatus::NotReady,
                reason: None,
                adapter_digest: None,
                report: None,
            };
            match track {
                TrackState::Waiting => {
                    output.reason = Some(if innovation.status == InnovationStatus::Birth {
                        AbstentionReason::Birth
                    } else {
                        AbstentionReason::UnavailableBeforeActivation
                    });
                }
                TrackState::Retired => {
                    output.status = TrackStatus::Retired;
                    output.reason = Some(AbstentionReason::RetiredWindow);
                }
                TrackState::Active { monitor, .. } => {
                    let Some(source) = &innovation.source else {
                        output.adapter_digest = Some(hex(monitor.adapter_identity()));
                        output.status = TrackStatus::Retired;
                        output.reason = Some(AbstentionReason::MissingAfterActivation);
                        *track = TrackState::Retired;
                        reports.push(output);
                        continue;
                    };
                    let evidence = innovation.nis.map(|nis| NisEvidenceParams {
                        nis,
                        dof: innovation.dof,
                    });
                    let assessment = monitor
                        .assess_frame(
                            Sequence::new(source.fusion_sequence).map_err(invalid)?,
                            time,
                            &[evidence],
                        )
                        .map_err(invalid)?;
                    output.adapter_digest = Some(hex(assessment.adapter_identity()));
                    if let Some(report) = assessment.report() {
                        output.status = TrackStatus::Evaluated;
                        output.report = Some(serde_json::to_value(report).map_err(invalid)?);
                    } else {
                        output.status = TrackStatus::Retired;
                        output.reason = Some(AbstentionReason::MissingAfterActivation);
                        *track = TrackState::Retired;
                    }
                }
            }
            reports.push(output);
        }
        prepared.completed_steps = result.step;
        prepared.previous_snapshot_digest = Some(result.snapshot.snapshot_digest.clone());
        Ok(json!({
            "schema": "galadriel.local.assessment.v1",
            "application_profile": APPLICATION_PROFILE,
            "plan_digest": prepared.plan_digest,
            "step": result.step,
            "time_us": result.snapshot.time_us,
            "body_result_digest": data.body_response.result_digest,
            "snapshot_digest": result.snapshot.snapshot_digest,
            "classification": AssessmentClassification::ExploratoryResearch(RESEARCH_PROFILE),
            "configuration_digest": hex(self.config.identity().as_bytes()),
            "calibrated_posterior": false,
            "tracks": reports,
        }))
    }
}

impl LocalBackend for NativeMonitor {
    fn validate(&self, operation: LocalOperation, body: &Value) -> Result<(), LocalError> {
        if self.retired {
            return Err(LocalError(LocalCode::Retired));
        }
        match operation {
            LocalOperation::Prepare => self.prepare_data(body).map(|_| ()),
            LocalOperation::Assess => self.assessment_data(body).map(|_| ()),
            LocalOperation::Finish => {
                let prepared = self.prepared.as_ref().ok_or(LocalError(LocalCode::State))?;
                let finish: FinishData = parse(body)?;
                if finish.plan_digest != prepared.plan_digest
                    || finish.completed_steps != prepared.plan.planned_steps
                    || prepared.completed_steps != prepared.plan.planned_steps
                {
                    return Err(LocalError(LocalCode::State));
                }
                Ok(())
            }
            LocalOperation::Abort if body == &json!({}) => Ok(()),
            _ => Err(LocalError(LocalCode::Role)),
        }
    }

    fn execute(&mut self, operation: LocalOperation, body: &Value) -> Result<Value, LocalError> {
        // The trait is public, so direct callers also receive complete preflight.
        self.validate(operation, body)?;
        match operation {
            LocalOperation::Prepare => {
                let (data, body_binding) = self.prepare_data(body)?;
                let plan_digest = data.plan.digest()?;
                let count = data.plan.entity_ids.len();
                let result = json!({
                    "schema": "galadriel.local.prepared.v1",
                    "application_profile": APPLICATION_PROFILE,
                    "plan_digest": plan_digest,
                    "body_binding": body_binding,
                    "classification": AssessmentClassification::ExploratoryResearch(RESEARCH_PROFILE),
                    "configuration_digest": hex(self.config.identity().as_bytes()),
                    "min_channels": self.config.min_channels(),
                    "window_len": self.config.window_len(),
                    "calibrated_posterior": false,
                });
                self.prepared = Some(PreparedMonitor {
                    plan: data.plan,
                    plan_digest,
                    body_binding,
                    tracks: (0..count).map(|_| TrackState::Waiting).collect(),
                    completed_steps: 0,
                    previous_snapshot_digest: None,
                });
                Ok(result)
            }
            LocalOperation::Assess => {
                let (data, result) = self.assessment_data(body)?;
                self.assess(data, result)
            }
            LocalOperation::Finish => {
                let prepared = self.prepared.as_ref().ok_or(LocalError(LocalCode::State))?;
                let result = json!({
                    "schema": "galadriel.local.finished.v1",
                    "plan_digest": prepared.plan_digest,
                    "completed_steps": prepared.completed_steps,
                    "calibrated_posterior": false,
                });
                self.retire();
                Ok(result)
            }
            LocalOperation::Abort => {
                self.retire();
                Ok(json!({"schema": "galadriel.local.aborted.v1"}))
            }
            _ => Err(LocalError(LocalCode::Role)),
        }
    }

    fn retire(&mut self) {
        self.retired = true;
        self.prepared = None;
    }
}
