//! Integration test: proof-chain E2E gate (bd-34s.6)
//!
//! Validates that:
//! 1. The gate script exists and is executable.
//! 2. The gate emits structured logs and a machine-readable report.
//! 3. Binder integrity, proof dashboard totals, and cross-report consistency all pass.

use std::path::{Path, PathBuf};
use std::process::Command;

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
    let script = root.join("scripts/check_proof_chain_e2e.sh");
    assert!(
        script.exists(),
        "scripts/check_proof_chain_e2e.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_proof_chain_e2e.sh must be executable"
        );
    }
}

#[test]
fn gate_script_emits_logs_and_reports() {
    let root = workspace_root();
    let script = root.join("scripts/check_proof_chain_e2e.sh");

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run proof-chain E2E gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = root.join("target/conformance/proof_chain_e2e.log.jsonl");
    let report_path = root.join("target/conformance/proof_chain_e2e.report.json");
    let binder_report_path =
        root.join("target/conformance/proof_chain_e2e.proof_binder.report.json");
    let cross_report_path =
        root.join("target/conformance/proof_chain_e2e.cross_report.current.v1.json");

    let (line_count, errors) = frankenlibc_harness::structured_log::validate_log_file(&log_path)
        .expect("log file should be readable");
    assert!(
        errors.is_empty(),
        "structured log validation errors:\n{:#?}",
        errors
    );
    assert!(
        line_count >= 5,
        "expected multiple proof-chain log lines (got {line_count})"
    );

    let log_body = std::fs::read_to_string(&log_path).expect("proof-chain log should exist");
    let log_events: Vec<serde_json::Value> = log_body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log line should parse"))
        .collect();
    for expected_event in [
        "proof_chain.scope_boundary",
        "proof_chain.proof_binder",
        "proof_chain.chain_integrity",
        "proof_chain.dashboard",
        "proof_chain.cross_report_consistency",
        "proof_chain.summary",
    ] {
        assert!(
            log_events
                .iter()
                .any(|entry| entry["event"].as_str() == Some(expected_event)),
            "proof-chain log should include {expected_event}"
        );
    }

    let report = load_json(&report_path);
    let binder_report = load_json(&binder_report_path);
    let cross_report = load_json(&cross_report_path);

    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-34s.6"));
    assert_eq!(report["summary"]["failed"].as_u64(), Some(0));
    assert_eq!(report["proof_binder"]["ok"].as_bool(), Some(true));
    assert_eq!(report["chain_integrity"]["ok"].as_bool(), Some(true));
    assert_eq!(report["dashboard"]["ok"].as_bool(), Some(true));
    assert_eq!(
        report["cross_report_consistency"]["ok"].as_bool(),
        Some(true)
    );
    assert!(
        report["dashboard"]["total_obligations"]
            .as_u64()
            .is_some_and(|count| count >= 20),
        "dashboard should cover the proof obligation set"
    );
    assert!(
        report["dashboard"]["owner_counts"]
            .as_object()
            .is_some_and(|owners| !owners.is_empty()),
        "dashboard should expose per-owner totals"
    );
    assert!(
        report["dashboard"]["status_counts"]
            .as_object()
            .is_some_and(|statuses| statuses.contains_key("in_progress")),
        "dashboard should expose in_progress totals"
    );

    assert_eq!(binder_report["summary"]["failed"].as_u64(), Some(0));
    assert_eq!(
        cross_report["summary"]["by_severity"]["critical"].as_u64(),
        Some(0)
    );
    assert_eq!(
        cross_report["summary"]["by_severity"]["error"].as_u64(),
        Some(0)
    );
}
