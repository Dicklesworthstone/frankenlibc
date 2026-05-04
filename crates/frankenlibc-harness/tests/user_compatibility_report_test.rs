//! Integration test: user compatibility report gate (bd-bp8fl.10.8)
//!
//! Verifies that workload compatibility claims are generated from evidence and
//! fail closed when evidence is missing, stale, contradictory, unsupported, or
//! overridden by prose.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_REPORT_FIELDS: &[&str] = &[
    "workload_id",
    "environment_id",
    "runtime_mode",
    "replacement_level",
    "support_status",
    "semantic_status",
    "support_matrix_row",
    "oracle_kind",
    "failure_bundle_refs",
    "performance_budget_refs",
    "freshness_state",
    "known_limitations",
    "user_recommendation",
    "regeneration_command",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "report_id",
    "workload_id",
    "environment_id",
    "runtime_mode",
    "replacement_level",
    "oracle_kind",
    "expected_status",
    "actual_status",
    "evidence_refs",
    "freshness_state",
    "user_recommendation",
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

fn unique_temp_path(name: &str, extension: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "frankenlibc-{name}-{stamp}-{}.{}",
        std::process::id(),
        extension
    ))
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn write_json_fixture(name: &str, value: &serde_json::Value) -> PathBuf {
    let path = unique_temp_path(name, "json");
    std::fs::write(&path, serde_json::to_string_pretty(value).unwrap() + "\n")
        .expect("failed to write fixture");
    path
}

fn parse_stdout_report(output: &Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(
        parsed.is_ok(),
        "failed to parse gate stdout as JSON: {}\nstdout={stdout}\nstderr={stderr}",
        parsed.err().unwrap()
    );
    serde_json::from_str(&stdout).expect("gate stdout JSON parse was checked above")
}

fn run_gate_with_env(envs: &[(&str, &Path)]) -> Output {
    let root = workspace_root();
    let script = root.join("scripts/generate_user_compatibility_report.sh");
    let out_dir = unique_temp_path("user-compatibility-out", "dir");
    let mut command = Command::new(&script);
    command.current_dir(&root);
    command.env("FLC_COMPATIBILITY_OUT_DIR", &out_dir);
    for (key, value) in envs {
        command.env(key, value);
    }
    command
        .output()
        .expect("failed to run user compatibility report gate")
}

fn assert_gate_fails_with(output: &Output, signature: &str) -> serde_json::Value {
    assert!(
        !output.status.success(),
        "gate should fail with {signature}:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout_report(output);
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error.as_str().unwrap_or_default().contains(signature)),
        "errors should mention {signature}: {}",
        report["errors"]
    );
    report
}

#[test]
fn manifest_declares_report_schema_replays_and_log_contract() {
    let root = workspace_root();
    let manifest = load_json(&root.join("tests/conformance/user_compatibility_report.v1.json"));
    assert_eq!(manifest["schema_version"].as_str(), Some("v1"));
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.10.8"));

    for key in [
        "workload_matrix",
        "artifact_precedence",
        "semantic_contract_symbol_join",
        "support_matrix",
        "oracle_precedence",
        "replacement_levels",
        "ld_preload_smoke_summary",
        "perf_regression_prevention",
        "readme",
        "release_notes",
    ] {
        let rel = manifest["inputs"][key].as_str().expect("input path");
        assert!(root.join(rel).exists(), "missing input {key}: {rel}");
    }

    let fields: HashSet<_> = manifest["required_report_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(fields, REQUIRED_REPORT_FIELDS.iter().copied().collect());

    let log_fields: Vec<_> = manifest["required_log_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);

    let replay_kinds: HashSet<_> = manifest["replay_cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        replay_kinds,
        [
            "clean",
            "degraded",
            "blocked",
            "missing_evidence",
            "stale_evidence",
            "contradictory_evidence",
            "unsupported_workload",
            "prose_override"
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn gate_generates_current_report_and_log() {
    let root = workspace_root();
    let script = root.join("scripts/generate_user_compatibility_report.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "generate_user_compatibility_report.sh must be executable"
        );
    }

    let output = run_gate_with_env(&[]);
    assert!(
        output.status.success(),
        "user compatibility report gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout_report(&output);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["workload_count"].as_u64(), Some(11));
    assert_eq!(report["summary"]["report_row_count"].as_u64(), Some(11));
    assert_eq!(
        report["summary"]["ready_l0_with_limitations_count"].as_u64(),
        Some(11)
    );
    assert_eq!(
        report["summary"]["blocked_semantic_claim_count"].as_u64(),
        Some(11)
    );

    let row = &report["workloads"].as_array().unwrap()[0];
    for field in REQUIRED_REPORT_FIELDS {
        assert!(row.get(*field).is_some(), "report row missing {field}");
    }
    assert_eq!(
        row["support_status"].as_str(),
        Some("ready_l0_with_limitations")
    );
    assert_eq!(
        row["semantic_status"].as_str(),
        Some("blocked_full_semantic_replacement")
    );
    assert_eq!(
        row["user_recommendation"].as_str(),
        Some("try_l0_strict_or_hardened_with_limitations")
    );
    assert!(
        row["known_limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|limitation| limitation
                .as_str()
                .unwrap_or_default()
                .contains("Full standalone replacement is not supported")),
        "known limitations should expose replacement uncertainty: {}",
        row["known_limitations"]
    );

    let log_path_value = report["log_path"].as_str().expect("report log_path");
    let log_path = if Path::new(log_path_value).is_absolute() {
        PathBuf::from(log_path_value)
    } else {
        root.join(log_path_value)
    };
    assert!(log_path.exists(), "missing {}", log_path.display());
    let log_line = std::fs::read_to_string(&log_path)
        .expect("log should be readable")
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log should contain at least one row")
        .to_string();
    let event: serde_json::Value = serde_json::from_str(&log_line).expect("log row should parse");
    for key in REQUIRED_LOG_FIELDS {
        assert!(event.get(*key).is_some(), "log row missing {key}");
    }
}

#[test]
fn missing_workload_evidence_fails() {
    let root = workspace_root();
    let mut workload =
        load_json(&root.join("tests/conformance/user_workload_acceptance_matrix.v1.json"));
    workload["workloads"] = serde_json::json!([]);
    let fixture = write_json_fixture("compatibility-missing-workloads", &workload);

    let output = run_gate_with_env(&[("FLC_COMPATIBILITY_WORKLOAD_MATRIX", &fixture)]);
    let report = assert_gate_fails_with(&output, "workload matrix must contain workloads");
    assert_eq!(
        report["summary"]["missing_evidence_count"].as_u64(),
        Some(1)
    );
}

#[test]
fn stale_smoke_evidence_fails() {
    let root = workspace_root();
    let mut smoke = load_json(&root.join("tests/conformance/ld_preload_smoke_summary.v1.json"));
    smoke["summary"]["overall_failed"] = serde_json::json!(true);
    let fixture = write_json_fixture("compatibility-stale-smoke", &smoke);

    let output = run_gate_with_env(&[("FLC_COMPATIBILITY_SMOKE_SUMMARY", &fixture)]);
    let report = assert_gate_fails_with(&output, "ld_preload_smoke_summary must be green");
    assert_eq!(report["summary"]["stale_evidence_count"].as_u64(), Some(1));
}

#[test]
fn contradictory_semantic_support_rows_fail() {
    let root = workspace_root();
    let mut join = load_json(&root.join("tests/conformance/semantic_contract_symbol_join.v1.json"));
    join["summary"]["semantic_parity_blocker_count"] = serde_json::json!(0);
    let fixture = write_json_fixture("compatibility-contradictory-join", &join);

    let output = run_gate_with_env(&[("FLC_COMPATIBILITY_SEMANTIC_JOIN", &fixture)]);
    let report = assert_gate_fails_with(&output, "semantic blocker count");
    assert_eq!(
        report["summary"]["contradictory_evidence_count"].as_u64(),
        Some(1)
    );
}

#[test]
fn unsupported_replacement_level_fails() {
    let root = workspace_root();
    let mut levels = load_json(&root.join("tests/conformance/replacement_levels.json"));
    levels["current_level"] = serde_json::json!("L2");
    levels["release_tag_policy"]["current_release_level"] = serde_json::json!("L2");
    let fixture = write_json_fixture("compatibility-unsupported-level", &levels);

    let output = run_gate_with_env(&[("FLC_COMPATIBILITY_REPLACEMENT_LEVELS", &fixture)]);
    let report = assert_gate_fails_with(&output, "report environment replacement level");
    assert_eq!(
        report["summary"]["unsupported_workload_count"].as_u64(),
        Some(1)
    );
}

#[test]
fn readme_prose_override_fails() {
    let fixture = unique_temp_path("compatibility-readme-override", "md");
    std::fs::write(
        &fixture,
        "# Bad README\n\nAll workloads are fully supported by FrankenLibC.\n",
    )
    .expect("failed to write README fixture");

    let output = run_gate_with_env(&[("FLC_COMPATIBILITY_README", &fixture)]);
    let report = assert_gate_fails_with(&output, "README prose attempts to override");
    assert_eq!(
        report["summary"]["prose_override_claim_count"].as_u64(),
        Some(1)
    );
}

#[test]
fn release_prose_override_fails() {
    let fixture = unique_temp_path("compatibility-release-override", "md");
    std::fs::write(
        &fixture,
        "# Bad release notes\n\nFull standalone libc replacement today.\n",
    )
    .expect("failed to write release-notes fixture");

    let output = run_gate_with_env(&[("FLC_COMPATIBILITY_RELEASE_NOTES", &fixture)]);
    let report = assert_gate_fails_with(&output, "release notes prose attempts to override");
    assert_eq!(
        report["summary"]["prose_override_claim_count"].as_u64(),
        Some(1)
    );
}
