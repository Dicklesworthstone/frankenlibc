//! Integration test: user workload vertical slice gate (bd-bp8fl.10.6).
//!
//! Validates that one selected workload is joined through workload matrix,
//! smoke replay, failure bundle, compatibility, freshness, and claim-gate
//! evidence without turning blocked evidence into user-facing support.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "scenario_id",
    "workload_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "symbol",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "decision_path",
    "healing_action",
    "latency_ns",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json file should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn load_manifest() -> serde_json::Value {
    load_json(&workspace_root().join("tests/conformance/user_workload_vertical_slice.v1.json"))
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn run_gate_with_manifest(
    manifest: &Path,
    prefix: &str,
) -> (PathBuf, PathBuf, PathBuf, std::process::Output) {
    let root = workspace_root();
    let temp = unique_temp_dir(prefix);
    let report = temp.join("user_workload_vertical_slice.report.json");
    let log = temp.join("user_workload_vertical_slice.log.jsonl");
    let index = temp.join("user_workload_vertical_slice.artifact_index.json");
    let output = Command::new(root.join("scripts/check_user_workload_vertical_slice.sh"))
        .env("USER_WORKLOAD_VERTICAL_SLICE_MANIFEST", manifest)
        .env("USER_WORKLOAD_VERTICAL_SLICE_REPORT", &report)
        .env("USER_WORKLOAD_VERTICAL_SLICE_LOG", &log)
        .env("USER_WORKLOAD_VERTICAL_SLICE_INDEX", &index)
        .output()
        .expect("gate script should execute");
    (report, log, index, output)
}

fn write_manifest_variant(
    original: &serde_json::Value,
    prefix: &str,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> PathBuf {
    let mut value = original.clone();
    mutate(&mut value);
    let dir = unique_temp_dir(prefix);
    let path = dir.join("user_workload_vertical_slice.v1.json");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&value).expect("variant manifest should serialize"),
    )
    .expect("variant manifest should write");
    path
}

fn assert_gate_fails_with(manifest: &Path, prefix: &str, expected_signature: &str) {
    let (report_path, _log_path, _index_path, output) = run_gate_with_manifest(manifest, prefix);
    assert!(
        !output.status.success(),
        "gate unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&report_path);
    let signatures = report["failure_signatures"]
        .as_array()
        .expect("failure_signatures should be array");
    assert!(
        signatures
            .iter()
            .any(|signature| signature.as_str() == Some(expected_signature)),
        "expected failure signature {expected_signature}; report={report:#?}"
    );
}

#[test]
fn manifest_selects_exactly_one_workload() {
    let manifest = load_manifest();
    assert_eq!(manifest["schema_version"].as_str(), Some("v1"));
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.10.6"));
    assert_eq!(
        manifest["selected_workload"]["id"].as_str(),
        Some("uwm-shell-coreutils")
    );
    assert!(
        manifest["selected_workload"]["why_real_user_decision"]
            .as_str()
            .is_some_and(|value| value.contains("Shell and coreutils")),
        "selected workload must explain the user decision"
    );
    let required_log_fields = manifest["required_log_fields"]
        .as_array()
        .expect("required_log_fields should be array");
    for field in REQUIRED_LOG_FIELDS {
        assert!(
            required_log_fields
                .iter()
                .any(|value| value.as_str() == Some(*field)),
            "required_log_fields missing {field}"
        );
    }
}

#[test]
fn selected_workload_resolves_to_matrix_and_smoke_cases() {
    let root = workspace_root();
    let manifest = load_manifest();
    let workload_matrix = load_json(
        &root.join(
            manifest["selected_workload"]["source_artifact"]
                .as_str()
                .unwrap(),
        ),
    );
    let selected_id = manifest["selected_workload"]["id"].as_str().unwrap();
    let selected_row = workload_matrix["workloads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"].as_str() == Some(selected_id))
        .expect("selected workload should exist in matrix");
    assert_eq!(
        selected_row["primary_domain"].as_str(),
        manifest["selected_workload"]["expected_primary_domain"].as_str()
    );
    assert_eq!(
        selected_row["runtime_modes"].as_array().unwrap().len(),
        2,
        "selected workload must cover strict and hardened"
    );
    assert_eq!(
        selected_row["replacement_levels"].as_array().unwrap().len(),
        4,
        "selected workload must preserve L0-L3 ambition"
    );

    let smoke = load_json(&root.join("tests/conformance/real_program_smoke_suite.v1.json"));
    let smoke_cases = smoke["cases"].as_array().unwrap();
    for binding in manifest["replay_bindings"].as_array().unwrap() {
        let case_id = binding["case_id"].as_str().unwrap();
        let smoke_case = smoke_cases
            .iter()
            .find(|case| case["case_id"].as_str() == Some(case_id))
            .expect("bound smoke case should exist");
        assert_eq!(
            smoke_case["workload_id"].as_str(),
            binding["smoke_workload_id"].as_str()
        );
        assert_eq!(smoke_case["runtime_mode"], binding["runtime_mode"]);
        assert_eq!(
            smoke_case["replacement_level"],
            binding["replacement_level"]
        );
    }
}

#[test]
fn replay_bindings_and_claim_gates_fail_closed() {
    let manifest = load_manifest();
    let bindings = manifest["replay_bindings"].as_array().unwrap();
    assert!(
        bindings
            .iter()
            .any(|binding| binding["path_kind"].as_str() == Some("direct")),
        "must include direct replay path"
    );
    assert!(
        bindings
            .iter()
            .any(|binding| binding["path_kind"].as_str() == Some("isolated")),
        "must include isolated replay path"
    );
    assert_eq!(
        manifest["expected_current_decision"]["status"].as_str(),
        Some("claim_blocked")
    );
    assert_eq!(
        manifest["expected_current_decision"]["support_claimed"].as_bool(),
        Some(false)
    );
    for gate in manifest["claim_gates"].as_array().unwrap() {
        assert_eq!(
            gate["blocks_missing_or_stale"].as_bool(),
            Some(true),
            "{} must block missing or stale evidence",
            gate["id"]
        );
    }
}

#[test]
fn gate_script_emits_report_log_and_artifact_index() {
    let root = workspace_root();
    let manifest_path = root.join("tests/conformance/user_workload_vertical_slice.v1.json");
    let (report_path, log_path, index_path, output) =
        run_gate_with_manifest(&manifest_path, "vertical-slice-pass");
    assert!(
        output.status.success(),
        "gate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&report_path);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["selected_workload_id"].as_str(),
        Some("uwm-shell-coreutils")
    );
    assert_eq!(report["replay_binding_count"].as_u64(), Some(2));
    assert_eq!(report["fixture_gate_count"].as_u64(), Some(3));
    assert_eq!(report["claim_gate_count"].as_u64(), Some(4));
    assert_eq!(report["negative_test_count"].as_u64(), Some(4));

    let log = std::fs::read_to_string(&log_path).expect("log should exist");
    let rows: Vec<serde_json::Value> = log
        .lines()
        .map(|line| serde_json::from_str(line).expect("log row should parse"))
        .collect();
    assert_eq!(rows.len(), 2, "one log row per replay binding");
    for row in rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing {field}");
        }
    }

    let index = load_json(&index_path);
    let kinds: Vec<_> = index["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|artifact| artifact["kind"].as_str())
        .collect();
    for required in [
        "manifest",
        "report",
        "log",
        "workload_matrix",
        "smoke_suite",
        "failure_bundle_policy",
        "compatibility_report",
        "claim_gate",
        "fixture_gate",
    ] {
        assert!(
            kinds.contains(&required),
            "artifact index missing {required}"
        );
    }
}

#[test]
fn gate_rejects_missing_selected_workload() {
    let manifest = load_manifest();
    let path = write_manifest_variant(&manifest, "vertical-slice-missing-workload", |value| {
        value["selected_workload"]["id"] = serde_json::Value::String("uwm-missing-row".to_owned());
    });
    assert_gate_fails_with(
        &path,
        "vertical-slice-missing-workload-run",
        "vertical_slice_missing_workload",
    );
}

#[test]
fn gate_rejects_stale_source_commit() {
    let manifest = load_manifest();
    let path = write_manifest_variant(&manifest, "vertical-slice-stale-source", |value| {
        value["freshness_policy"]["source_commit"] =
            serde_json::Value::String("deadbeef".to_owned());
    });
    assert_gate_fails_with(
        &path,
        "vertical-slice-stale-source-run",
        "vertical_slice_stale_source_commit",
    );
}

#[test]
fn gate_rejects_contradictory_claim_decision() {
    let manifest = load_manifest();
    let path = write_manifest_variant(&manifest, "vertical-slice-contradictory", |value| {
        value["expected_current_decision"]["support_claimed"] = serde_json::Value::Bool(true);
    });
    assert_gate_fails_with(
        &path,
        "vertical-slice-contradictory-run",
        "vertical_slice_contradictory_claim",
    );
}

#[test]
fn gate_rejects_missing_smoke_case() {
    let manifest = load_manifest();
    let path = write_manifest_variant(&manifest, "vertical-slice-missing-smoke", |value| {
        value["replay_bindings"][0]["case_id"] =
            serde_json::Value::String("missing_case".to_owned());
    });
    assert_gate_fails_with(
        &path,
        "vertical-slice-missing-smoke-run",
        "vertical_slice_missing_smoke_case",
    );
}
