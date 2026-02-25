//! Integration test: runtime_math decision-law linkage proofs (bd-7dw2)
//!
//! Validates that:
//! 1. The gate script exists and is executable.
//! 2. The gate script runs successfully.
//! 3. The gate emits structured JSONL logs and a JSON report.
//! 4. One log line and one report row exist per production module in the manifest.

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
    let script = root.join("scripts/check_runtime_math_linkage_proofs.sh");
    assert!(
        script.exists(),
        "scripts/check_runtime_math_linkage_proofs.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_runtime_math_linkage_proofs.sh must be executable"
        );
    }
}

#[test]
fn gate_script_emits_logs_and_report() {
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_math_linkage_proofs.sh");

    let output = std::process::Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run linkage proofs gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = root.join("target/conformance/runtime_math_linkage_proofs.log.jsonl");
    let report_path = root.join("target/conformance/runtime_math_linkage_proofs.report.json");

    let (line_count, errors) = frankenlibc_harness::structured_log::validate_log_file(&log_path)
        .expect("log file should be readable");
    assert!(
        errors.is_empty(),
        "structured log validation errors:\n{:#?}",
        errors
    );

    let manifest = load_json(&root.join("tests/runtime_math/production_kernel_manifest.v1.json"));
    let modules = manifest["production_modules"]
        .as_array()
        .expect("manifest.production_modules must be an array");
    let expected = modules.len();

    let report = load_json(&report_path);
    assert_eq!(
        report["schema_version"].as_str(),
        Some("v1"),
        "report schema_version must be v1"
    );
    assert_eq!(
        report["bead"].as_str(),
        Some("bd-7dw2"),
        "bead marker must match"
    );

    assert_eq!(
        report["summary"]["total_modules"].as_u64().unwrap() as usize,
        expected,
        "summary.total_modules mismatch"
    );
    assert_eq!(
        report["summary"]["failed"].as_u64().unwrap(),
        0,
        "report summary indicates failures"
    );
    assert_eq!(
        report["modules"].as_array().unwrap().len(),
        expected,
        "report must include one row per production module"
    );
    let log_body = std::fs::read_to_string(&log_path).expect("log file should be readable");
    let log_events: Vec<serde_json::Value> = log_body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log line should parse"))
        .collect();
    let step_count = log_events
        .iter()
        .filter(|entry| entry["event"].as_str() == Some("runtime_math.linkage_proof.step"))
        .count();
    let summary_count = log_events
        .iter()
        .filter(|entry| entry["event"].as_str() == Some("runtime_math.linkage_proof"))
        .count();
    assert_eq!(
        step_count, expected,
        "log must include one TRACE step per production module"
    );
    assert_eq!(
        summary_count, expected,
        "log must include one INFO summary per production module"
    );
    assert!(
        log_events.iter().any(|entry| {
            entry["event"].as_str() == Some("runtime_math.linkage_proof.boundary_assumption")
        }),
        "log should include boundary-assumption WARN events"
    );
    assert_eq!(
        line_count,
        log_events.len(),
        "validated line count should match parsed log lines"
    );
    assert!(
        line_count >= expected * 2,
        "log should include at least TRACE+INFO events per module"
    );
}
