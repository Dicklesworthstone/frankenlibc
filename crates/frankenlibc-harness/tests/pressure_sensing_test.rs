// pressure_sensing_test.rs — bd-w2c3.7.1
// Integration tests for the pressure sensing + overload state machine.
// Validates: module compiles, fixture artifact exists, scenario invariants hold.

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
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
}

#[test]
fn pressure_sensor_module_compiles() {
    let output = Command::new("cargo")
        .args(["check", "-p", "frankenlibc-membrane"])
        .current_dir(repo_root())
        .output()
        .expect("cargo check failed to execute");
    assert!(
        output.status.success(),
        "frankenlibc-membrane failed to compile:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn pressure_sensor_unit_tests_pass() {
    let output = Command::new("cargo")
        .args([
            "test",
            "-p",
            "frankenlibc-membrane",
            "--",
            "pressure_sensor::",
            "--nocapture",
        ])
        .current_dir(repo_root())
        .output()
        .expect("cargo test failed to execute");
    assert!(
        output.status.success(),
        "pressure_sensor unit tests failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn pressure_sensing_fixture_well_formed() {
    let root = repo_root();
    let fixture_path = root.join("tests/conformance/fixtures/pressure_sensing.json");
    assert!(
        fixture_path.exists(),
        "Fixture not found: {}",
        fixture_path.display()
    );

    let data = load_json(&fixture_path);

    // Check required top-level fields
    assert_eq!(
        data["family"].as_str(),
        Some("pressure_sensing"),
        "Wrong family"
    );
    assert_eq!(data["version"].as_str(), Some("v1"), "Wrong version");

    let cases = data["cases"].as_array().expect("Missing 'cases' array");
    assert!(
        cases.len() >= 8,
        "Expected at least 8 cases, got {}",
        cases.len()
    );

    // Check mode coverage
    let strict_count = cases
        .iter()
        .filter(|c| c["mode"].as_str() == Some("strict"))
        .count();
    let hardened_count = cases
        .iter()
        .filter(|c| c["mode"].as_str() == Some("hardened"))
        .count();
    assert!(
        strict_count >= 4,
        "Expected >=4 strict cases, got {strict_count}"
    );
    assert!(
        hardened_count >= 2,
        "Expected >=2 hardened cases, got {hardened_count}"
    );

    // Each case must have required fields
    for (i, case) in cases.iter().enumerate() {
        assert!(case["name"].as_str().is_some(), "Case {i} missing 'name'");
        assert!(
            case["function"].as_str().is_some(),
            "Case {i} missing 'function'"
        );
        assert!(case["mode"].as_str().is_some(), "Case {i} missing 'mode'");
    }
}

#[test]
fn pressure_sensing_scenario_invariants() {
    let root = repo_root();
    let scenario_path = root.join("tests/conformance/pressure_sensing_scenarios.v1.json");
    assert!(
        scenario_path.exists(),
        "Scenario fixture not found: {}",
        scenario_path.display()
    );

    let data = load_json(&scenario_path);

    // Check bead reference
    assert_eq!(
        data["bead"].as_str(),
        Some("bd-w2c3.7.1"),
        "Wrong bead reference"
    );

    // Check thresholds
    let thresholds = &data["thresholds"];
    let pe = thresholds["pressured_enter"].as_f64().unwrap();
    let px = thresholds["pressured_exit"].as_f64().unwrap();
    let oe = thresholds["overloaded_enter"].as_f64().unwrap();
    let ox = thresholds["overloaded_exit"].as_f64().unwrap();

    // Threshold ordering: exit < enter, pressured < overloaded
    assert!(
        px < pe,
        "pressured_exit ({px}) must be < pressured_enter ({pe})"
    );
    assert!(
        ox < oe,
        "overloaded_exit ({ox}) must be < overloaded_enter ({oe})"
    );
    assert!(
        pe < oe,
        "pressured_enter ({pe}) must be < overloaded_enter ({oe})"
    );

    // Check scenario count
    let scenarios = data["scenarios"]
        .as_array()
        .expect("Missing 'scenarios' array");
    assert!(
        scenarios.len() >= 4,
        "Expected at least 4 scenarios, got {}",
        scenarios.len()
    );

    // Each scenario must have an id and description
    for (i, s) in scenarios.iter().enumerate() {
        assert!(s["id"].as_str().is_some(), "Scenario {i} missing 'id'");
        assert!(
            s["description"].as_str().is_some(),
            "Scenario {i} missing 'description'"
        );
    }

    // Check summary
    let summary = &data["summary"];
    let scenario_count = summary["scenario_count"].as_u64().unwrap();
    assert_eq!(
        scenario_count as usize,
        scenarios.len(),
        "Summary scenario_count mismatch"
    );

    let regimes = summary["regimes_tested"]
        .as_array()
        .expect("Missing regimes_tested");
    assert_eq!(regimes.len(), 4, "Expected 4 regimes tested");
}

#[test]
fn pressure_sensing_gate_emits_structured_artifacts() {
    let root = repo_root();
    let script = root.join("scripts/check_pressure_sensing.sh");
    assert!(script.exists(), "Missing gate script: {}", script.display());

    let output = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run check_pressure_sensing.sh");
    assert!(
        output.status.success(),
        "check_pressure_sensing.sh failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/pressure_sensing.report.json");
    let log_path = root.join("target/conformance/pressure_sensing.log.jsonl");
    assert!(
        report_path.exists(),
        "Missing report: {}",
        report_path.display()
    );
    assert!(log_path.exists(), "Missing log: {}", log_path.display());

    let report = load_json(&report_path);
    for key in [
        "schema_version",
        "bead",
        "status",
        "summary",
        "thresholds",
        "scenarios",
        "findings",
        "artifacts_consumed",
        "artifacts_emitted",
        "tooling_contract",
    ] {
        assert!(report.get(key).is_some(), "report missing key: {key}");
    }
    assert_eq!(report["bead"].as_str(), Some("bd-w2c3.7.1"));
    assert_eq!(report["status"].as_str(), Some("pass"));

    let scenarios = report["scenarios"]
        .as_array()
        .expect("scenarios must be array");
    assert!(!scenarios.is_empty(), "scenarios must be non-empty");
    let scenario_count = report["summary"]["scenario_count"]
        .as_u64()
        .expect("summary.scenario_count must be u64");
    assert_eq!(
        scenario_count as usize,
        scenarios.len(),
        "summary.scenario_count should match scenarios length"
    );

    let tooling = report["tooling_contract"]
        .as_object()
        .expect("tooling_contract should be object");
    for key in [
        "has_asupersync_dependency",
        "asupersync_feature_present",
        "default_enables_asupersync_tooling",
        "frankentui_feature_present",
        "frankentui_dependency_set_complete",
    ] {
        assert_eq!(
            tooling.get(key).and_then(serde_json::Value::as_bool),
            Some(true),
            "tooling_contract expectation failed for key: {key}"
        );
    }

    let (line_count, errors) = frankenlibc_harness::structured_log::validate_log_file(&log_path)
        .expect("structured log should be readable");
    assert_eq!(
        line_count,
        scenarios.len(),
        "structured log should emit one event per scenario"
    );
    assert!(
        errors.is_empty(),
        "structured log validation errors: {errors:#?}"
    );

    let content = std::fs::read_to_string(&log_path).expect("failed to read structured log");
    let first = content
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log should contain at least one event");
    let row: serde_json::Value = serde_json::from_str(first).expect("first log row should be JSON");
    for key in [
        "trace_id",
        "mode",
        "api_family",
        "symbol",
        "decision_path",
        "healing_action",
        "errno",
        "latency_ns",
        "artifact_refs",
    ] {
        assert!(row.get(key).is_some(), "log row missing key: {key}");
    }
    assert_eq!(row["event"].as_str(), Some("pressure_sensing_scenario"));
    assert_eq!(row["api_family"].as_str(), Some("pressure_sensing"));
    let decision_path = row["decision_path"].as_str().unwrap_or_default();
    assert!(
        decision_path.contains("tooling_contract"),
        "decision_path should include tooling_contract, got {decision_path}"
    );
}
