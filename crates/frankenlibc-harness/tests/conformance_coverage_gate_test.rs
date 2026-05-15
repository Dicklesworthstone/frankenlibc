// conformance_coverage_gate_test.rs — bd-15n.3
// Verifies that the conformance coverage gate detects no regressions.

use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "workspace root").into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn ensure_exists(path: &Path, description: &str) -> TestResult {
    if path.exists() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{description} not found at {}", path.display()),
        )
        .into())
    }
}

fn read_json(path: &Path, description: &str) -> TestResult<serde_json::Value> {
    let content = std::fs::read_to_string(path)?;
    serde_json::from_str(&content)
        .map_err(|err| invalid_data(format!("{description} is not valid JSON: {err}")).into())
}

fn required_summary_count(report: &serde_json::Value, field: &str) -> TestResult<u64> {
    report["summary"][field]
        .as_u64()
        .ok_or_else(|| invalid_data(format!("summary.{field} must be u64")).into())
}

#[test]
fn conformance_coverage_gate_no_regression() -> TestResult {
    let repo_root = workspace_root()?;

    let script = repo_root.join("scripts/conformance_coverage_gate.py");
    ensure_exists(&script, "conformance_coverage_gate.py")?;

    let output = Command::new("python3")
        .arg(&script)
        .arg("check")
        .current_dir(&repo_root)
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let code = output
        .status
        .code()
        .ok_or_else(|| invalid_data("conformance coverage gate terminated without exit code"))?;

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
        let report: serde_json::Value = serde_json::from_str(&stdout)
            .map_err(|err| invalid_data(format!("coverage report must parse: {err}")))?;

        let errors = required_summary_count(&report, "errors")?;
        let findings = serde_json::to_string_pretty(&report["findings"])?;
        assert_eq!(
            errors, 0,
            "Coverage gate found {errors} error(s). Findings:\n{findings}"
        );
    }
    Ok(())
}

#[test]
fn conformance_coverage_baseline_exists() -> TestResult {
    let repo_root = workspace_root()?;

    let baseline = repo_root.join("tests/conformance/conformance_coverage_baseline.v1.json");
    ensure_exists(&baseline, "coverage baseline")?;

    let data = read_json(&baseline, "coverage baseline")?;

    // Verify baseline has expected structure
    let total_fixture_files = required_summary_count(&data, "total_fixture_files")?;
    let total_fixture_cases = required_summary_count(&data, "total_fixture_cases")?;
    assert!(
        total_fixture_files > 0,
        "Baseline has 0 fixture files — likely corrupt"
    );
    assert!(
        total_fixture_cases > 0,
        "Baseline has 0 fixture cases — likely corrupt"
    );
    Ok(())
}
