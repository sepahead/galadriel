//! The NCP 2 loop assessment against three recorded CREBAIN runs (`tests/fixtures`).

#![cfg(feature = "ncp-loop")]

use galadriel_local_adapter::ncp_loop::assess_run;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// A copy of a recorded run in a new directory, for a test that changes it.
fn copy(name: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "galadriel-ncp-loop-{}-{}-{name}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir(&dir).unwrap();
    for entry in fs::read_dir(fixture(name)).unwrap() {
        let path = entry.unwrap().path();
        fs::copy(&path, dir.join(path.file_name().unwrap())).unwrap();
    }
    dir
}

fn steps(report: &Value, world: usize) -> &Vec<Value> {
    report["worlds"][world]["steps"].as_array().unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn a_clean_run_is_evaluated_at_every_step_and_never_more_than_insufficient() {
    let report = assess_run(&fixture("loop-1x1")).unwrap();
    assert_eq!(report["schema"], "galadriel.ncp-loop.assessment.v1");
    assert_eq!(
        report["application_profile"],
        "galadriel.scalar-nis-loop.v1"
    );
    assert_eq!(report["calibrated_posterior"], false);
    assert_eq!(report["classification"]["class"], "exploratory_research");
    let manifest: Value =
        serde_json::from_slice(&fs::read(fixture("loop-1x1").join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(report["body_contract"], manifest["body_contract"]);
    let steps = steps(&report, 0);
    assert_eq!(steps.len(), 20);
    for (tick, step) in (1..).zip(steps) {
        assert_eq!(step["tick_index"], tick);
        let track = &step["tracks"][0];
        assert_eq!(track["drone_id"], "alpha");
        assert_eq!(track["status"], "evaluated");
        // One visual channel cannot reach the two channels that a verdict needs: fail closed.
        assert_eq!(
            track["report"]["verdict"]["verdict"],
            "insufficient_evidence"
        );
    }
}

#[test]
fn an_offset_shows_in_the_innovations_and_a_missing_measurement_retires_the_track() {
    let report = assess_run(&fixture("loop-1x1-faults")).unwrap();
    let steps = steps(&report, 0);
    assert_eq!(steps.len(), 40);
    let track = |tick: usize| &steps[tick - 1]["tracks"][0];
    let nis = |tick: usize| track(tick)["nis"].as_f64().unwrap();
    // The sensor gains an offset of 0.2 m at step 11 and loses it at step 21; the filter then
    // absorbs each change within a few steps.
    assert!(nis(11) > 5.0 * nis(10), "{} after {}", nis(11), nis(10));
    assert!(nis(21) > 5.0 * nis(20), "{} after {}", nis(21), nis(20));
    for tick in 1..30 {
        assert_eq!(track(tick)["status"], "evaluated", "step {tick}");
    }
    // The sensor gives no measurement at step 30: the track retires for the rest of the run, and
    // no observation is made up for it.
    assert_eq!(track(30)["status"], "retired");
    assert_eq!(track(30)["reason"], "missing_after_activation");
    assert!(track(30)["nis"].is_null());
    for tick in 31..=40 {
        assert_eq!(track(tick)["status"], "retired", "step {tick}");
        assert_eq!(track(tick)["reason"], "retired_window", "step {tick}");
        assert!(track(tick)["report"].is_null(), "step {tick}");
    }
}

#[test]
fn each_world_and_drone_is_assessed_separately() {
    let report = assess_run(&fixture("loop-2x3")).unwrap();
    let worlds = report["worlds"].as_array().unwrap();
    assert_eq!(worlds.len(), 2);
    assert_eq!(worlds[0]["drone_ids"], json!(["alpha", "bravo", "charlie"]));
    assert_eq!(worlds[1]["drone_ids"], json!(["delta", "echo"]));
    for (index, world) in worlds.iter().enumerate() {
        let drones = world["drone_ids"].as_array().unwrap();
        assert_eq!(steps(&report, index).len(), 10);
        for step in steps(&report, index) {
            let tracks = step["tracks"].as_array().unwrap();
            assert_eq!(tracks.len(), drones.len());
            for (track, drone) in tracks.iter().zip(drones) {
                assert_eq!(&track["drone_id"], drone);
                assert_eq!(track["status"], "evaluated");
            }
        }
        // The report names each transcript by the digest of its bytes.
        let name = world["transcript"].as_str().unwrap();
        let bytes = fs::read(fixture("loop-2x3").join(name)).unwrap();
        assert_eq!(world["transcript_sha256"], hex(&Sha256::digest(&bytes)));
    }
}

#[test]
fn a_changed_byte_of_a_world_transcript_is_refused() {
    let dir = copy("loop-1x1");
    let path = dir.join("world-0.ncpt");
    let mut bytes = fs::read(&path).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    fs::write(&path, bytes).unwrap();
    let error = assess_run(&dir).unwrap_err();
    assert!(error.0.contains("world-0.ncpt"), "{error}");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_world_transcript_without_its_end_record_is_refused() {
    let dir = copy("loop-1x1");
    let path = dir.join("world-0.ncpt");
    let bytes = fs::read(&path).unwrap();
    // The end record is 13 bytes of head and a 32-byte chain value.
    fs::write(&path, &bytes[..bytes.len() - 45]).unwrap();
    let error = assess_run(&dir).unwrap_err();
    assert!(error.0.contains("does not verify"), "{error}");
    fs::remove_dir_all(dir).unwrap();
}

/// A named change of a manifest.
type Change = (&'static str, fn(&mut Value));

#[test]
fn a_manifest_that_does_not_match_the_run_is_refused() {
    let changes: [Change; 5] = [
        ("steps", |m| m["steps"] = json!(21)),
        ("tick_ms", |m| m["tick_ms"] = json!(10)),
        ("body_contract", |m| {
            m["body_contract"] = json!("0".repeat(64))
        }),
        ("drone_ids", |m| {
            m["worlds"][0]["drone_ids"] = json!(["bravo"])
        }),
        ("transcript", |m| {
            m["worlds"][0]["transcript"] = json!("../world-0.ncpt")
        }),
    ];
    for (what, change) in changes {
        let dir = copy("loop-1x1");
        let path = dir.join("manifest.json");
        let mut manifest: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        change(&mut manifest);
        fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(assess_run(&dir).is_err(), "a changed {what} was accepted");
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn a_controller_transcript_is_not_a_world_transcript() {
    let dir = copy("loop-1x1");
    let path = dir.join("manifest.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    manifest["worlds"][0]["transcript"] = json!("controller-0.ncpt");
    fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let error = assess_run(&dir).unwrap_err();
    assert!(error.0.contains("controller-0.ncpt"), "{error}");
    fs::remove_dir_all(dir).unwrap();
}
