//! Record-only scalar NIS assessment of CREBAIN NCP 2 closed-loop runs.
//!
//! CREBAIN's `crebain-ncp-loop` runs controllers and simulated drone worlds, each with its own
//! NCP 2 session, and writes a `manifest.json` and one transcript for each session. Every world
//! step result holds the kernel's Kalman innovation diagnostics for each drone. [`assess_run`]
//! checks each world transcript with the NCP 2 verifier and the world's state chain, and then
//! feeds each drone's observed innovations, in step order, to Galadriel's scalar detector: one
//! [`ScalarMonitor`] for each drone track.
//!
//! A track waits until its first observed innovation, then runs until an innovation is missing,
//! which retires it for the rest of the run. Absence never becomes a fabricated observation.
//! The output is exploratory research evidence: it has no command capability and no calibrated
//! posterior, and the transcripts it reads are not signed.

use crate::{NisEvidenceParams, ScalarChannelParams, ScalarMonitor, RESEARCH_PROFILE};
use galadriel_core::{
    AssessmentClassification, ClockDomain, DetectorConfig, Modality, Sequence, TimestampMillis,
    TrackId,
};
use ncp::frame::{decode, Decoded, MAX_BOUND};
use ncp::transcript::{read, verify, RECEIVED, SENT};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// The application profile of this assessment.
pub const APPLICATION_PROFILE: &str = "galadriel.scalar-nis-loop.v1";
/// The largest world transcript that [`assess_run`] reads.
pub const MAX_TRANSCRIPT_BYTES: u64 = 256 * 1024 * 1024;
const BODY_APPLICATION: &str = "crebain.body";

/// A failed check of a run, with its reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct AssessError(pub String);

fn fail<T>(reason: impl Into<String>) -> Result<T, AssessError> {
    Err(AssessError(reason.into()))
}

fn because<E: std::fmt::Display>(what: &str) -> impl Fn(E) -> AssessError + '_ {
    move |error| AssessError(format!("{what}: {error}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_identity(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

struct Exchange {
    request: Decoded,
    response: Decoded,
}

impl Exchange {
    fn op(&self) -> &str {
        self.request.message["op"].as_str().unwrap_or_default()
    }
    fn body(&self) -> &Value {
        &self.request.message["body"]
    }
    fn result(&self) -> &Value {
        &self.response.message["body"]
    }
}

/// Read one world transcript: one client session of `crebain.body` whose every request got an
/// `ok` response. Returns the exchanges and the SHA-256 digest of the file.
fn exchanges(path: &Path, contract: &str) -> Result<(Vec<Exchange>, String), AssessError> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("?")
        .to_owned();
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_TRANSCRIPT_BYTES + 1).read_to_end(&mut bytes))
        .map_err(because(&name))?;
    if bytes.len() as u64 > MAX_TRANSCRIPT_BYTES {
        return fail(format!("{name}: larger than {MAX_TRANSCRIPT_BYTES} bytes"));
    }
    let report = verify(path, None).map_err(because(&name))?;
    // A transcript of version 2 ends with an end record; version 1 has none.
    if !report.ok() || (report.version >= 2 && !report.closed) {
        return fail(format!(
            "{name}: the transcript does not verify: {:?}",
            report.problems
        ));
    }
    match report.sessions.as_slice() {
        [session] if session.role == "client" && session.complete => {}
        sessions => {
            return fail(format!(
                "{name}: not one complete client session: {sessions:?}"
            ))
        }
    }
    let mut list = Vec::new();
    let mut pending: Option<Decoded> = None;
    for record in read(path).map_err(because(&name))?.records {
        let decoded = decode(record.frame, MAX_BOUND).map_err(because(&name))?;
        match (record.kind, pending.take()) {
            (SENT, None) => pending = Some(decoded),
            (RECEIVED, Some(request)) => list.push(Exchange {
                request,
                response: decoded,
            }),
            _ => return fail(format!("{name}: requests and responses do not alternate")),
        }
    }
    if pending.is_some() {
        return fail(format!("{name}: the last request has no response"));
    }
    for exchange in &list {
        let response = &exchange.response.message;
        if response["outcome"] != "ok" || response["request"] != exchange.request.identity.as_str()
        {
            return fail(format!(
                "{name}: seq {}: not an ok response to its request",
                exchange.request.message["seq"]
            ));
        }
    }
    let open = list
        .first()
        .ok_or_else(|| AssessError(format!("{name}: empty")))?;
    if open.op() != "open"
        || open.body()["application"] != BODY_APPLICATION
        || open.body()["contract"] != contract
    {
        return fail(format!(
            "{name}: the session does not open {BODY_APPLICATION} with the manifest's contract"
        ));
    }
    if list.last().map(|e| e.op() != "close").unwrap_or(true) {
        return fail(format!("{name}: the session does not end with close"));
    }
    Ok((list, hex(&Sha256::digest(&bytes))))
}

/// One observed innovation of one drone.
struct Sample {
    sensor_id: String,
    track: u64,
    sequence: u64,
    nis: f64,
    dof: u8,
}

/// The observed innovation of an entity row, or `None` when the row reports it unavailable.
fn sample(entity: &Value) -> Result<Option<Sample>, AssessError> {
    let evidence = &entity["evidence"];
    match evidence["status"].as_str() {
        Some("unavailable") => Ok(None),
        Some("observed") => {
            let s = &evidence["sample"];
            if s["modality"] != "visual" {
                return fail("only visual innovations are admitted");
            }
            Ok(Some(Sample {
                sensor_id: entity["sensor_id"]
                    .as_str()
                    .ok_or_else(|| AssessError("sensor_id".into()))?
                    .to_owned(),
                track: s["fusion_track_id"]
                    .as_u64()
                    .ok_or_else(|| AssessError("fusion_track_id".into()))?,
                sequence: s["fusion_sequence"]
                    .as_u64()
                    .ok_or_else(|| AssessError("fusion_sequence".into()))?,
                nis: s["nis"].as_f64().ok_or_else(|| AssessError("nis".into()))?,
                dof: s["degrees_of_freedom"]
                    .as_u64()
                    .and_then(|d| u8::try_from(d).ok())
                    .ok_or_else(|| AssessError("degrees_of_freedom".into()))?,
            }))
        }
        _ => fail("innovation evidence must be observed or unavailable"),
    }
}

enum TrackState {
    Waiting,
    Active {
        monitor: Box<ScalarMonitor>,
        sensor_id: String,
        track: u64,
    },
    Retired,
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
enum Abstention {
    UnavailableBeforeActivation,
    MissingAfterActivation,
    RetiredWindow,
}

#[derive(Serialize)]
struct TrackAssessment {
    drone_id: String,
    fusion_track_id: Option<u64>,
    fusion_sequence: Option<u64>,
    nis: Option<f64>,
    status: TrackStatus,
    reason: Option<Abstention>,
    adapter_digest: Option<String>,
    report: Option<Value>,
}

fn monitor(sample: &Sample, config: &DetectorConfig) -> Result<ScalarMonitor, AssessError> {
    ScalarMonitor::prepare(
        TrackId::new(sample.track).map_err(because("track"))?,
        ClockDomain::SimulationTime,
        Sequence::new(sample.sequence).map_err(because("sequence"))?,
        &[ScalarChannelParams {
            modality: Modality::Visual,
            dof: 3,
        }],
        config.clone(),
    )
    .map_err(because("monitor"))
}

/// Assess the steps of one world from its exchanges.
fn assess_world(
    list: &[Exchange],
    drone_ids: &[String],
    steps: u64,
    tick_ms: u64,
    config: &DetectorConfig,
) -> Result<Vec<Value>, AssessError> {
    if list.len() as u64 != steps + 4 {
        return fail(format!(
            "open, prepare, {steps} steps, finish, and close expected"
        ));
    }
    let prepare = &list[1];
    if prepare.op() != "prepare"
        || prepare.body()["drone_ids"] != json!(drone_ids)
        || prepare.body()["planned_steps"] != steps
        || prepare.body()["tick_ms"] != tick_ms
    {
        return fail("the prepare request does not match the manifest");
    }
    let mut state = prepare.result()["observation"]["state_digest"].clone();
    if !is_identity(&state) || prepare.result()["frame"]["state_digest"] != state {
        return fail("the prepare result has no consistent state digest");
    }
    let mut tracks: Vec<TrackState> = drone_ids.iter().map(|_| TrackState::Waiting).collect();
    let mut out = Vec::with_capacity(steps as usize);
    for (tick, exchange) in (1..).zip(&list[2..list.len() - 2]) {
        let result = exchange.result();
        let next = &result["observation"]["state_digest"];
        if exchange.op() != "step"
            || exchange.body()["tick_index"] != tick
            || exchange.body()["source_state_digest"] != state
            || result["frame"]["prior_state_digest"] != state
            || result["frame"]["state_digest"] != *next
            || result["observation"]["tick_index"] != tick
            || !is_identity(next)
        {
            return fail(format!("step {tick} does not continue the state chain"));
        }
        let innovations = &result["innovations"];
        let entities = innovations["entities"]
            .as_array()
            .ok_or_else(|| AssessError("innovation entities".into()))?;
        if innovations["tick_index"] != tick
            || entities.len() != drone_ids.len()
            || entities
                .iter()
                .zip(drone_ids)
                .any(|(e, id)| e["entity_id"] != id.as_str())
        {
            return fail(format!(
                "step {tick}: the innovations do not match the drones and the step"
            ));
        }
        let time = TimestampMillis::new(
            innovations["interval_end_ms"]
                .as_u64()
                .ok_or_else(|| AssessError("interval_end_ms".into()))?,
        )
        .map_err(because("time"))?;
        let mut reports = Vec::with_capacity(tracks.len());
        for ((track, entity), drone_id) in tracks.iter_mut().zip(entities).zip(drone_ids) {
            let observed = sample(entity)?;
            if let (TrackState::Waiting, Some(s)) = (&*track, &observed) {
                *track = TrackState::Active {
                    monitor: Box::new(monitor(s, config)?),
                    sensor_id: s.sensor_id.clone(),
                    track: s.track,
                };
            }
            let mut output = TrackAssessment {
                drone_id: drone_id.clone(),
                fusion_track_id: observed.as_ref().map(|s| s.track),
                fusion_sequence: observed.as_ref().map(|s| s.sequence),
                nis: observed.as_ref().map(|s| s.nis),
                status: TrackStatus::NotReady,
                reason: None,
                adapter_digest: None,
                report: None,
            };
            match track {
                TrackState::Waiting => {
                    output.reason = Some(Abstention::UnavailableBeforeActivation)
                }
                TrackState::Retired => {
                    output.status = TrackStatus::Retired;
                    output.reason = Some(Abstention::RetiredWindow);
                }
                TrackState::Active {
                    monitor,
                    sensor_id,
                    track: active,
                } => {
                    let Some(s) = &observed else {
                        output.adapter_digest = Some(hex(monitor.adapter_identity()));
                        output.status = TrackStatus::Retired;
                        output.reason = Some(Abstention::MissingAfterActivation);
                        *track = TrackState::Retired;
                        reports.push(serde_json::to_value(&output).map_err(because("report"))?);
                        continue;
                    };
                    if &s.sensor_id != sensor_id || s.track != *active {
                        return fail(format!(
                            "step {tick}: drone {drone_id} changed its sensor or track"
                        ));
                    }
                    let assessment = monitor
                        .assess_frame(
                            Sequence::new(s.sequence).map_err(because("sequence"))?,
                            time,
                            &[Some(NisEvidenceParams {
                                nis: s.nis,
                                dof: s.dof,
                            })],
                        )
                        .map_err(because(&format!("step {tick}: drone {drone_id}")))?;
                    output.adapter_digest = Some(hex(assessment.adapter_identity()));
                    if let Some(report) = assessment.report() {
                        output.status = TrackStatus::Evaluated;
                        output.report =
                            Some(serde_json::to_value(report).map_err(because("report"))?);
                    } else {
                        output.status = TrackStatus::Retired;
                        output.reason = Some(Abstention::MissingAfterActivation);
                        *track = TrackState::Retired;
                    }
                }
            }
            reports.push(serde_json::to_value(&output).map_err(because("report"))?);
        }
        out.push(json!({"tick_index": tick, "time_ms": time.get(), "state_digest": next, "tracks": reports}));
        state = next.clone();
    }
    let finish = &list[list.len() - 2];
    if finish.op() != "finish"
        || finish.body()["completed_steps"] != steps
        || finish.result()["finish"]["cleaned_up"] != true
        || finish.result()["finish"]["state_digest"] != state
    {
        return fail("the run does not finish cleanly from its last state");
    }
    Ok(out)
}

/// Check the world transcripts of the run in `dir` and assess every drone's innovations.
///
/// # Errors
/// Fails on any transcript, chain, or manifest mismatch, and on a detector input error.
pub fn assess_run(dir: &Path) -> Result<Value, AssessError> {
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(dir.join("manifest.json")).map_err(because("manifest.json"))?,
    )
    .map_err(because("manifest.json"))?;
    let steps = manifest["steps"]
        .as_u64()
        .filter(|s| (1..=1024).contains(s))
        .ok_or_else(|| AssessError("manifest steps".into()))?;
    let tick_ms = manifest["tick_ms"]
        .as_u64()
        .ok_or_else(|| AssessError("manifest tick_ms".into()))?;
    let contract = manifest["body_contract"]
        .as_str()
        .filter(|_| is_identity(&manifest["body_contract"]))
        .ok_or_else(|| AssessError("manifest body_contract".into()))?;
    let worlds = manifest["worlds"]
        .as_array()
        .filter(|w| !w.is_empty())
        .ok_or_else(|| AssessError("manifest worlds".into()))?;
    let config =
        DetectorConfig::standalone_advisory_v0_9().map_err(because("detector configuration"))?;
    let mut out = Vec::with_capacity(worlds.len());
    for (index, world) in worlds.iter().enumerate() {
        let name = world["transcript"]
            .as_str()
            .filter(|n| safe_name(n))
            .ok_or_else(|| AssessError(format!("world {index}: transcript name")))?;
        let drone_ids: Vec<String> =
            serde_json::from_value(world["drone_ids"].clone()).map_err(because("drone_ids"))?;
        let (list, digest) = exchanges(&dir.join(name), contract)?;
        let assessed = assess_world(&list, &drone_ids, steps, tick_ms, &config)
            .map_err(|AssessError(reason)| AssessError(format!("world {index}: {reason}")))?;
        out.push(json!({"world": index, "transcript": name, "transcript_sha256": digest, "drone_ids": drone_ids, "steps": assessed}));
    }
    Ok(json!({
        "schema": "galadriel.ncp-loop.assessment.v1",
        "application_profile": APPLICATION_PROFILE,
        "classification": AssessmentClassification::ExploratoryResearch(RESEARCH_PROFILE),
        "configuration_digest": hex(config.identity().as_bytes()),
        "min_channels": config.min_channels(),
        "window_len": config.window_len(),
        "calibrated_posterior": false,
        "body_contract": contract,
        "worlds": out,
    }))
}
