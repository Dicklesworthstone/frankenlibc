// closure_sweep_test.rs — bd-w2c3.10.3
// Verifies that the closure sweep engine runs without errors and
// produces a valid report with all required fields.

use std::process::Command;

#[test]
fn closure_sweep_passes() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let script = repo_root.join("scripts/closure_sweep.py");
    assert!(
        script.exists(),
        "closure_sweep.py not found at {:?}",
        script
    );

    let output = Command::new("python3")
        .arg(&script)
        .current_dir(repo_root)
        .output()
        .expect("failed to run closure_sweep.py");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "Failed to parse closure sweep report: {}\nstdout: {}\nstderr: {}",
            e, stdout, stderr
        );
    });

    // Gate: status must be "pass" (zero errors)
    let status = report["status"].as_str().unwrap_or("unknown");
    assert_eq!(
        status, "pass",
        "Closure sweep failed.\nErrors: {}\nFindings: {}",
        report["summary"]["errors"],
        serde_json::to_string_pretty(&report["findings"]).unwrap_or_default()
    );

    // Validate required report fields
    let required_keys = [
        "schema_version",
        "bead",
        "summary",
        "findings",
        "coverage_gaps",
        "callthrough_gaps",
        "non_closure_reasons",
        "drift_gates_status",
        "open_gap_beads",
    ];
    for key in required_keys {
        assert!(
            report.get(key).is_some(),
            "Report missing required key: {key}"
        );
    }

    // Validate summary fields
    let summary = &report["summary"];
    assert_eq!(summary["errors"].as_u64().unwrap_or(999), 0);
    assert!(summary["coverage_pct"].as_u64().is_some());
    assert!(summary["callthrough_remaining"].as_u64().is_some());
    assert!(summary["open_gap_beads"].as_u64().is_some());
    assert!(summary["closure_ready"].is_boolean());

    // Validate drift gates are armed
    assert_eq!(
        report["drift_gates_status"].as_str().unwrap_or(""),
        "armed",
        "Drift gates must be armed"
    );
}

#[test]
fn closure_sweep_report_artifact_exists() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let report_path = repo_root.join("tests/conformance/closure_sweep_report.v1.json");
    assert!(
        report_path.exists(),
        "Closure sweep report artifact not found at {:?}",
        report_path
    );

    let content = std::fs::read_to_string(&report_path).expect("failed to read report");
    let report: serde_json::Value =
        serde_json::from_str(&content).expect("report is not valid JSON");

    assert_eq!(
        report["schema_version"].as_str().unwrap_or(""),
        "v1",
        "Report schema_version must be v1"
    );
    assert_eq!(
        report["bead"].as_str().unwrap_or(""),
        "bd-w2c3.10.3",
        "Report bead must be bd-w2c3.10.3"
    );
}
