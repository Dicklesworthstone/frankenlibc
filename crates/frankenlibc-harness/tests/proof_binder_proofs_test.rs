//! Integration test: proof binder verification and regression gate (bd-34s.5)
//!
//! Validates that:
//! 1. The gate script exists and is executable.
//! 2. The gate script runs successfully.
//! 3. The gate emits structured JSONL logs plus machine-readable JSON reports.
//! 4. The fresh validator snapshot matches the checked-in traceability snapshot.

use std::path::{Path, PathBuf};

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
    let content = std::fs::read_to_string(path).expect("json file should exist");
    serde_json::from_str(&content).expect("json should parse")
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_proof_binder.sh");
    assert!(script.exists(), "scripts/check_proof_binder.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_proof_binder.sh must be executable"
        );
    }
}

#[test]
fn gate_script_emits_logs_and_reports() {
    let root = workspace_root();
    let script = root.join("scripts/check_proof_binder.sh");

    let output = std::process::Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run proof binder gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = root.join("target/conformance/proof_binder_proofs.log.jsonl");
    let report_path = root.join("target/conformance/proof_binder_proofs.report.json");
    let validator_report_path =
        root.join("target/conformance/proof_binder_validation.current.v1.json");
    let baseline_path = root.join("tests/conformance/proof_traceability_check.json");

    let (line_count, errors) = frankenlibc_harness::structured_log::validate_log_file(&log_path)
        .expect("log file should be readable");
    assert!(
        errors.is_empty(),
        "structured log validation errors:\n{:#?}",
        errors
    );
    assert!(
        line_count >= 4,
        "expected multiple log lines (got {line_count})"
    );

    let log_body = std::fs::read_to_string(&log_path).expect("proof binder log should exist");
    let log_events: Vec<serde_json::Value> = log_body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log line should parse"))
        .collect();
    for expected_event in [
        "proof_binder.scope_boundary",
        "proof_binder.validator",
        "proof_binder.python_tests",
        "proof_binder.snapshot_regression",
        "proof_binder.summary",
    ] {
        assert!(
            log_events
                .iter()
                .any(|entry| entry["event"].as_str() == Some(expected_event)),
            "proof binder log should include {expected_event}"
        );
    }

    let report = load_json(&report_path);
    let validator_report = load_json(&validator_report_path);
    let baseline = load_json(&baseline_path);

    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-34s.5"));
    assert_eq!(report["summary"]["failed"].as_u64(), Some(0));
    assert_eq!(report["validator"]["ok"].as_bool(), Some(true));
    assert_eq!(report["python_tests"]["ok"].as_bool(), Some(true));
    assert_eq!(
        report["regression"]["baseline_matches"].as_bool(),
        Some(true)
    );
    assert_eq!(validator_report["binder_valid"].as_bool(), Some(true));

    assert_eq!(
        report["current_snapshot"]["total_obligations"].as_u64(),
        baseline["total_obligations"].as_u64()
    );
    assert_eq!(
        report["current_snapshot"]["valid_obligations"].as_u64(),
        baseline["valid_obligations"].as_u64()
    );
    assert_eq!(
        report["current_snapshot"]["invalid_obligations"].as_u64(),
        baseline["invalid_obligations"].as_u64()
    );
    assert_eq!(
        report["current_snapshot"]["total_violations"].as_u64(),
        baseline["total_violations"].as_u64()
    );
}
