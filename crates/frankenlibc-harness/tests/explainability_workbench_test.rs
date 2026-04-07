//! Integration tests for bd-26xb.4 explainability workbench CLI.

use std::path::{Path, PathBuf};
use std::process::Command;

use frankenlibc_harness::structured_log::{
    ArtifactIndex, ArtifactJoinKeys, LogEntry, LogLevel, Outcome,
};

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn temp_dir() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "frankenlibc_explainability_workbench_cli_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create temp dir");
    path
}

struct SampleEntrySpec<'a> {
    trace_id: &'a str,
    scenario_id: &'a str,
    mode: &'a str,
    outcome: Outcome,
    action: &'a str,
    healing_action: &'a str,
    decision_id: u64,
    artifact_ref: &'a str,
}

fn sample_entry(spec: SampleEntrySpec<'_>) -> LogEntry {
    LogEntry::new(spec.trace_id, LogLevel::Info, "case_result")
        .with_bead("bd-26xb.4")
        .with_scenario_id(spec.scenario_id)
        .with_mode(spec.mode)
        .with_api("malloc", "allocator_elimination")
        .with_decision_path("validator->fingerprint->repair")
        .with_controller_id("runtime_math_kernel.v1")
        .with_decision_action(spec.action)
        .with_healing_action(spec.healing_action)
        .with_decision_id(spec.decision_id)
        .with_policy_id(9)
        .with_outcome(spec.outcome)
        .with_artifacts(vec![spec.artifact_ref.to_string()])
        .with_details(serde_json::json!({
            "failure_signature": format!("{}_signature", spec.mode),
        }))
}

#[test]
fn explainability_workbench_command_writes_joined_report() {
    let root = workspace_root();
    let temp = temp_dir();
    let log_path = temp.join("workbench.log.jsonl");
    let index_path = temp.join("workbench.artifacts.json");
    let output_path = temp.join("workbench.report.json");

    let strict = sample_entry(SampleEntrySpec {
        trace_id: "bd-26xb.4::demo::001",
        scenario_id: "demo",
        mode: "strict",
        outcome: Outcome::Fail,
        action: "Repair",
        healing_action: "ClampSize",
        decision_id: 501,
        artifact_ref: "artifacts/strict.log",
    });
    let hardened = sample_entry(SampleEntrySpec {
        trace_id: "bd-26xb.4::demo::002",
        scenario_id: "demo",
        mode: "hardened",
        outcome: Outcome::Pass,
        action: "Allow",
        healing_action: "None",
        decision_id: 502,
        artifact_ref: "artifacts/hardened.log",
    });
    std::fs::write(
        &log_path,
        format!(
            "{}\n{}\n",
            strict.to_jsonl().expect("strict jsonl"),
            hardened.to_jsonl().expect("hardened jsonl")
        ),
    )
    .expect("write log");

    let mut index = ArtifactIndex::new("demo", "bd-26xb.4");
    index.add_with_join_keys(
        "reports/root-cause.json",
        "report",
        "deadbeef",
        ArtifactJoinKeys {
            decision_ids: vec![501],
            ..ArtifactJoinKeys::default()
        },
    );
    std::fs::write(&index_path, index.to_json().expect("index json")).expect("write index");

    let harness_bin = std::env::var("CARGO_BIN_EXE_harness").expect("CARGO_BIN_EXE_harness");
    let run = Command::new(harness_bin)
        .current_dir(&root)
        .arg("explainability-workbench")
        .arg("--log")
        .arg(&log_path)
        .arg("--artifact-index")
        .arg(&index_path)
        .arg("--scenario-id")
        .arg("demo")
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&output_path)
        .output()
        .expect("run explainability workbench command");

    assert!(
        run.status.success(),
        "workbench command failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&output_path).expect("read output"))
            .expect("report json");
    assert_eq!(report["bead"].as_str(), Some("bd-26xb.4"));
    assert_eq!(report["scenarios"][0]["scenario_id"].as_str(), Some("demo"));
    assert_eq!(
        report["scenarios"][0]["mode_divergence"][0]["differing_fields"][0].as_str(),
        Some("outcome")
    );
    assert!(
        report["scenarios"][0]["artifact_links"]
            .as_array()
            .expect("artifact links")
            .iter()
            .any(|artifact| artifact["path"].as_str() == Some("reports/root-cause.json"))
    );
    assert_eq!(
        report["tooling_contract"]["default_enables_asupersync_tooling"].as_bool(),
        Some(true)
    );
    assert_eq!(
        report["tooling_contract"]["frankentui_feature_present"].as_bool(),
        Some(true)
    );
}
