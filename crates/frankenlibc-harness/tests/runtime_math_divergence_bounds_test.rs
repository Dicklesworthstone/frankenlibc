//! Integration test: runtime_math strict-vs-hardened divergence bounds (bd-2625)
//!
//! Validates that:
//! 1. The gate script exists and is executable.
//! 2. The gate script runs successfully.
//! 3. The gate emits structured JSONL logs and a JSON report.
//! 4. The report indicates zero failures and zero violations.

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
    let script = root.join("scripts/check_runtime_math_divergence_bounds.sh");
    assert!(
        script.exists(),
        "scripts/check_runtime_math_divergence_bounds.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_runtime_math_divergence_bounds.sh must be executable"
        );
    }
}

#[test]
fn gate_script_emits_logs_and_report() {
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_math_divergence_bounds.sh");

    let output = std::process::Command::new(&script)
        .current_dir(&root)
        .env("TMPDIR", root.join(".tmp"))
        .output()
        .expect("failed to run divergence bounds gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = root.join("target/conformance/runtime_math_divergence_bounds.log.jsonl");
    let report_path = root.join("target/conformance/runtime_math_divergence_bounds.report.json");

    let (line_count, errors) = frankenlibc_harness::structured_log::validate_log_file(&log_path)
        .expect("log file should be readable");
    assert!(
        errors.is_empty(),
        "structured log validation errors:\n{:#?}",
        errors
    );
    assert!(
        line_count >= 5,
        "expected multiple log lines (got {line_count})"
    );

    let report = load_json(&report_path);
    assert_eq!(
        report["schema_version"].as_str(),
        Some("v1"),
        "report schema_version must be v1"
    );
    assert_eq!(
        report["bead"].as_str(),
        Some("bd-2625"),
        "bead marker must match"
    );
    assert_eq!(
        report["summary"]["failed"].as_u64(),
        Some(0),
        "report indicates case failures"
    );
    assert_eq!(
        report["summary"]["violations"].as_u64(),
        Some(0),
        "report indicates divergence violations"
    );
    assert!(
        report["results"].as_array().is_some_and(|a| !a.is_empty()),
        "report must include per-case results"
    );
}
