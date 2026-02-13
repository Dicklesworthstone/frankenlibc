// conformance_coverage_gate_test.rs — bd-15n.3
// Verifies that the conformance coverage gate detects no regressions.

use std::process::Command;

#[test]
fn conformance_coverage_gate_no_regression() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let script = repo_root.join("scripts/conformance_coverage_gate.py");
    assert!(
        script.exists(),
        "conformance_coverage_gate.py not found at {:?}",
        script
    );

    let output = Command::new("python3")
        .arg(&script)
        .arg("check")
        .current_dir(repo_root)
        .output()
        .expect("failed to run conformance_coverage_gate.py");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let code = output.status.code().unwrap_or(-1);

    // Exit 0 = pass, exit 2 = baseline created (acceptable on first run)
    assert!(
        code == 0 || code == 2,
        "Coverage gate failed (exit {}). stdout:\n{}\nstderr:\n{}",
        code,
        stdout,
        stderr
    );

    if code == 0 {
        // Parse report and verify no errors
        let report: serde_json::Value =
            serde_json::from_str(&stdout).unwrap_or_else(|e| {
                panic!("Failed to parse coverage report: {}\nstdout: {}", e, stdout);
            });

        let errors = report["summary"]["errors"].as_u64().unwrap_or(999);
        assert_eq!(
            errors, 0,
            "Coverage gate found {} error(s). Findings:\n{}",
            errors,
            serde_json::to_string_pretty(&report["findings"]).unwrap_or_default()
        );
    }
}

#[test]
fn conformance_coverage_baseline_exists() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let baseline = repo_root.join("tests/conformance/conformance_coverage_baseline.v1.json");
    assert!(
        baseline.exists(),
        "Coverage baseline not found. Run: python3 scripts/conformance_coverage_gate.py update-baseline"
    );

    let content = std::fs::read_to_string(&baseline).expect("failed to read baseline");
    let data: serde_json::Value =
        serde_json::from_str(&content).expect("baseline is not valid JSON");

    // Verify baseline has expected structure
    assert!(
        data["summary"]["total_fixture_files"].as_u64().unwrap_or(0) > 0,
        "Baseline has 0 fixture files — likely corrupt"
    );
    assert!(
        data["summary"]["total_fixture_cases"].as_u64().unwrap_or(0) > 0,
        "Baseline has 0 fixture cases — likely corrupt"
    );
}
