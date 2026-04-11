//! Integration test: docs reality drift guard (bd-3rf).
//!
//! Validates:
//! 1. Canonical `reality_report.v1.json` exists and has the expected schema.
//! 2. Drift guard script passes (support_matrix -> harness report -> docs).

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

#[test]
fn canonical_reality_report_schema_is_valid() {
    let root = workspace_root();
    let report_path = root.join("tests/conformance/reality_report.v1.json");

    assert!(
        report_path.exists(),
        "canonical report missing at {}",
        report_path.display()
    );

    let body = std::fs::read_to_string(&report_path).expect("report should be readable");
    let report: serde_json::Value =
        serde_json::from_str(&body).expect("report should be valid JSON");

    assert_eq!(
        report["schema_version"].as_str(),
        Some("v1"),
        "schema_version must be 'v1'"
    );
    assert!(
        report["generated_at_utc"].is_string(),
        "generated_at_utc must be a string"
    );
    assert!(
        report["total_exported"].is_u64(),
        "total_exported must be an unsigned integer"
    );
    assert!(report["counts"].is_object(), "counts must be an object");
    assert!(report["stubs"].is_array(), "stubs must be an array");

    for key in [
        "implemented",
        "raw_syscall",
        "wraps_host_libc",
        "glibc_call_through",
        "stub",
    ] {
        assert!(
            report["counts"][key].is_u64(),
            "counts.{key} must be an unsigned integer"
        );
    }
}

#[test]
fn support_matrix_docs_drift_guard_passes() {
    let root = workspace_root();
    let script = root.join("scripts/check_support_matrix_drift.sh");
    assert!(script.exists(), "missing script {}", script.display());

    let output = Command::new("bash")
        .arg(script)
        .current_dir(&root)
        .output()
        .expect("check_support_matrix_drift.sh should execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "support matrix/docs drift guard failed\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout,
        stderr
    );
}
