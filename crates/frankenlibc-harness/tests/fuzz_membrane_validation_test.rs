// fuzz_membrane_validation_test.rs — bd-1oz.4
// Integration tests for membrane fuzz target validation.

use std::path::Path;
use std::process::Command;

fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("JSON fixture must be readable");
    serde_json::from_str(&content).expect("JSON fixture must parse")
}

#[test]
fn membrane_validation_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_membrane_validation.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_fuzz_membrane_validation.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute membrane validation generator");
    assert!(
        output.status.success(),
        "Membrane validation generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn membrane_validation_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_membrane_validation.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-1oz.4"));
    assert!(data["validation_hash"].is_string());

    let summary = &data["summary"];
    assert!(!summary["readiness_pct"].is_null());
    assert!(!summary["total_gaps"].is_null());
    assert!(data["source_analysis"].is_object());
    assert!(data["fuzzing_strategies"].is_array());
    assert!(data["state_transitions"].is_array());
    assert!(data["cache_coherence"].is_array());
    assert!(data["invariant_checks"].is_array());
    assert!(data["gap_analysis"].is_array());
    assert!(data["success_criteria"].is_object());
    assert!(data["completion_debt_evidence"].is_object());
}

#[test]
fn membrane_validation_pipeline_exercised() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_membrane_validation.v1.json");
    let data = load_json(&report_path);

    let source = &data["source_analysis"];
    assert!(
        source["has_pipeline_creation"].as_bool().unwrap(),
        "ValidationPipeline not created in fuzz target"
    );
    assert!(
        source["has_outcome_checking"].as_bool().unwrap(),
        "Validation outcomes not checked in fuzz target"
    );
    assert!(
        source["has_fuzz_target"].as_bool().unwrap(),
        "Missing fuzz_target! macro"
    );
}

#[test]
fn membrane_validation_strategies_documented() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_membrane_validation.v1.json");
    let data = load_json(&report_path);

    let strategies = data["fuzzing_strategies"].as_array().unwrap();
    assert!(
        strategies.len() >= 3,
        "Only {} strategies documented (need >= 3)",
        strategies.len()
    );

    // At least one must be implemented
    let implemented = strategies
        .iter()
        .filter(|s| s["implemented"].as_bool().unwrap_or(false))
        .count();
    assert!(implemented >= 1, "No fuzzing strategies implemented");
}

#[test]
fn membrane_validation_lifecycle_fuzz_paths_present() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_membrane_validation.v1.json");
    let data = load_json(&report_path);

    let source = &data["source_analysis"];
    assert!(
        source["has_structured_input"].as_bool().unwrap(),
        "fuzz target must use structured arbitrary input"
    );
    assert!(
        source["has_allocation_lifecycle"].as_bool().unwrap(),
        "fuzz target must allocate and free through ValidationPipeline"
    );
    assert!(
        source["has_pointer_arithmetic"].as_bool().unwrap(),
        "fuzz target must derive in-allocation offsets"
    );
    assert!(
        source["has_near_miss_pointers"].as_bool().unwrap(),
        "fuzz target must derive near-miss pointers"
    );
    assert!(
        source["has_cache_revalidation"].as_bool().unwrap(),
        "fuzz target must revalidate the same live pointer"
    );
    assert!(
        source["has_double_free_path"].as_bool().unwrap(),
        "fuzz target must exercise double-free detection"
    );
    assert!(
        source["has_canary_corruption_path"].as_bool().unwrap(),
        "fuzz target must exercise trailing-canary corruption detection"
    );

    assert_eq!(data["summary"]["strategies_coverage"].as_str(), Some("4/5"));
    assert_eq!(
        data["summary"]["transitions_coverage"].as_str(),
        Some("3/4")
    );
    assert_eq!(data["summary"]["cache_coverage"].as_str(), Some("3/3"));
    assert_eq!(data["summary"]["invariants_coverage"].as_str(), Some("4/5"));
    assert_eq!(data["summary"]["total_gaps"].as_u64(), Some(3));
}

#[test]
fn membrane_validation_state_transitions_documented() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_membrane_validation.v1.json");
    let data = load_json(&report_path);

    let transitions = data["state_transitions"].as_array().unwrap();
    assert!(
        transitions.len() >= 3,
        "Only {} state transitions (need >= 3)",
        transitions.len()
    );

    for t in transitions {
        assert!(t["from_state"].is_string());
        assert!(t["to_state"].is_string());
        assert!(t["trigger"].is_string());
    }
}

#[test]
fn membrane_validation_gaps_analyzed() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_membrane_validation.v1.json");
    let data = load_json(&report_path);

    let readiness = data["summary"]["readiness_pct"].as_f64().unwrap();
    let gaps = data["gap_analysis"].as_array().unwrap();

    // If readiness < 100%, gaps must be documented
    if readiness < 100.0 {
        assert!(
            !gaps.is_empty(),
            "Readiness {}% but no gaps documented",
            readiness
        );
    }

    // Each gap must have required fields
    let valid_severities = ["low", "medium", "high"];
    for g in gaps {
        let severity = g["severity"].as_str().unwrap_or("?");
        assert!(
            valid_severities.contains(&severity),
            "Invalid gap severity: {}",
            severity
        );
        assert!(g["area"].is_string());
        assert!(g["item"].is_string());
    }
}

#[test]
fn membrane_validation_cwe_targets() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_membrane_validation.v1.json");
    let data = load_json(&report_path);

    let cwes = data["summary"]["cwe_targets"].as_array().unwrap();
    assert!(
        cwes.len() >= 2,
        "Only {} CWEs targeted (need >= 2)",
        cwes.len()
    );

    for cwe in cwes {
        let s = cwe.as_str().unwrap();
        assert!(s.starts_with("CWE-"), "Invalid CWE format: {}", s);
    }
}

#[test]
fn completion_debt_evidence_binds_fuzz_and_telemetry_items() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_membrane_validation.v1.json");
    let data = load_json(&report_path);
    let evidence = &data["completion_debt_evidence"];

    assert_eq!(evidence["bead"].as_str(), Some("bd-1oz.4.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-1oz.4"));
    assert_eq!(
        evidence["test_source"].as_str(),
        Some("crates/frankenlibc-harness/tests/fuzz_membrane_validation_test.rs")
    );

    let fuzz_primary = &evidence["fuzz_primary"];
    assert_eq!(fuzz_primary["target"].as_str(), Some("fuzz_membrane"));
    assert_eq!(
        fuzz_primary["target_source"].as_str(),
        Some("crates/frankenlibc-fuzz/fuzz_targets/fuzz_membrane.rs")
    );

    let required_tests = fuzz_primary["required_test_names"].as_array().unwrap();
    for name in [
        "membrane_validation_pipeline_exercised",
        "membrane_validation_strategies_documented",
        "membrane_validation_lifecycle_fuzz_paths_present",
        "membrane_validation_cwe_targets",
    ] {
        assert!(
            required_tests
                .iter()
                .any(|value| value.as_str() == Some(name)),
            "completion evidence missing required test {name}"
        );
    }

    let telemetry = &evidence["telemetry_primary"];
    assert_eq!(
        telemetry["default_report_path"].as_str(),
        Some("target/conformance/fuzz_membrane_validation.report.json")
    );
    assert_eq!(
        telemetry["default_log_path"].as_str(),
        Some("target/conformance/fuzz_membrane_validation.log.jsonl")
    );

    let required_events = telemetry["required_events"].as_array().unwrap();
    for event in [
        "fuzz_membrane_validation_started",
        "fuzz_membrane_validation_completed",
        "fuzz_membrane_validation_failed",
    ] {
        assert!(
            required_events
                .iter()
                .any(|value| value.as_str() == Some(event)),
            "telemetry evidence missing event {event}"
        );
    }
}

#[test]
fn checker_emits_completion_debt_report_and_log() {
    let root = repo_root();
    let unique = format!("fuzz_membrane_validation_test_{}", std::process::id());
    let gate_report = root
        .join("target/conformance")
        .join(format!("{unique}.report.json"));
    let gate_log = root
        .join("target/conformance")
        .join(format!("{unique}.log.jsonl"));

    let output = Command::new("bash")
        .arg(root.join("scripts/check_fuzz_membrane_validation.sh"))
        .current_dir(&root)
        .env("FRANKENLIBC_FUZZ_MEMBRANE_VALIDATION_REPORT", &gate_report)
        .env("FRANKENLIBC_FUZZ_MEMBRANE_VALIDATION_LOG", &gate_log)
        .env(
            "FRANKENLIBC_FUZZ_MEMBRANE_VALIDATION_TRACE_ID",
            "fuzz-membrane-validation-test",
        )
        .output()
        .expect("failed to execute membrane validation checker");
    assert!(
        output.status.success(),
        "Membrane validation checker failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&gate_report);
    assert_eq!(report["bead_id"].as_str(), Some("bd-1oz.4.1"));
    assert_eq!(report["target"].as_str(), Some("fuzz_membrane"));
    assert_eq!(report["outcome"].as_str(), Some("pass"));
    assert_eq!(report["failure_signature"].as_str(), Some("none"));
    assert!(
        report["artifact_refs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| {
                value.as_str() == Some("crates/frankenlibc-fuzz/fuzz_targets/fuzz_membrane.rs")
            })
    );

    let log = std::fs::read_to_string(&gate_log).expect("gate log must be readable");
    let rows = log.lines().collect::<Vec<_>>();
    assert_eq!(rows.len(), 2);
    let started: serde_json::Value = serde_json::from_str(rows[0]).unwrap();
    let completed: serde_json::Value = serde_json::from_str(rows[1]).unwrap();
    assert_eq!(
        started["event"].as_str(),
        Some("fuzz_membrane_validation_started")
    );
    assert_eq!(
        completed["event"].as_str(),
        Some("fuzz_membrane_validation_completed")
    );
    assert_eq!(completed["outcome"].as_str(), Some("pass"));
}
