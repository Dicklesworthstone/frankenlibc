//! Integration test: docs reality drift guard (bd-3rf).
//!
//! Validates:
//! 1. Canonical `reality_report.v1.json` exists and has the expected schema.
//! 2. Drift guard script passes (support_matrix -> harness report -> docs).

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let harness_root = manifest.parent().ok_or_else(|| {
        test_error(format!(
            "{} has no harness-crate parent",
            manifest.display()
        ))
    })?;
    let workspace_root = harness_root.parent().ok_or_else(|| {
        test_error(format!(
            "{} has no workspace-root parent",
            harness_root.display()
        ))
    })?;
    Ok(workspace_root.to_path_buf())
}

fn load_json(path: &Path) -> TestResult<serde_json::Value> {
    let body = fs::read_to_string(path)
        .map_err(|source| test_error(format!("failed to read {}: {source}", path.display())))?;
    serde_json::from_str(&body).map_err(|source| {
        test_error(format!("failed to parse JSON {}: {source}", path.display())).into()
    })
}

#[test]
fn canonical_reality_report_schema_is_valid() -> TestResult {
    let root = workspace_root()?;
    let report_path = root.join("tests/conformance/reality_report.v1.json");

    assert!(
        report_path.exists(),
        "canonical report missing at {}",
        report_path.display()
    );

    let report = load_json(&report_path)?;

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
    Ok(())
}

#[test]
fn support_matrix_docs_drift_guard_passes() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_support_matrix_drift.sh");
    assert!(script.exists(), "missing script {}", script.display());

    let output = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        .output()
        .map_err(|source| {
            test_error(format!(
                "failed to execute support-matrix drift guard {}: {source}",
                script.display()
            ))
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "support matrix/docs drift guard failed\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout,
        stderr
    );
    Ok(())
}
