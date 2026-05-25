//! bd-gq1kz7.10: Zero-host-reference nm/readelf gate preflight test.

use serde_json::Value;
use std::error::Error;
use std::path::Path;
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<std::path::PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate manifest should have crates parent")?
        .parent()
        .ok_or("crates directory should have workspace parent")?
        .to_path_buf())
}

#[test]
fn gate_script_exists() -> TestResult {
    let script = workspace_root()?.join("scripts/check_host_reference_gate.sh");
    assert!(script.exists(), "check_host_reference_gate.sh should exist");
    Ok(())
}

#[test]
fn gate_emits_valid_json() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_host_reference_gate.sh");

    let output = Command::new(&script).current_dir(&root).output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse as JSON (should not panic even on error status)
    let json: Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("gate output should be valid JSON: {e}\nOutput: {stdout}"))?;

    // Must have status field
    assert!(
        json.get("status").is_some(),
        "gate output must have 'status' field"
    );

    let status = json.get("status").and_then(Value::as_str).unwrap_or("");

    // If error (no artifact), that's valid output - skip remaining checks
    if status == "error" {
        eprintln!("gate returned error (no artifact available), skipping further checks");
        return Ok(());
    }

    // Must have summary when not error
    assert!(
        json.get("summary").is_some(),
        "gate output must have 'summary' field"
    );

    // Must have gate identifier
    assert_eq!(
        json.get("gate").and_then(Value::as_str),
        Some("bd-gq1kz7.10"),
        "gate output must identify as bd-gq1kz7.10"
    );

    Ok(())
}

#[test]
fn gate_classifies_unwinder_as_allowed() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_host_reference_gate.sh");

    let output = Command::new(&script).current_dir(&root).output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)?;

    // If no artifact, skip this test
    let status = json.get("status").and_then(Value::as_str).unwrap_or("");
    if status == "error" {
        eprintln!(
            "gate returned error (no artifact available), skipping unwinder classification check"
        );
        return Ok(());
    }

    // _Unwind_* symbols should be classified as allowed, not unknown or disallowed
    let unknown = json
        .get("unknown")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();

    let has_unwind_unknown = unknown.iter().any(|s| s.starts_with("_Unwind_"));
    assert!(
        !has_unwind_unknown,
        "_Unwind_* symbols should be classified as allowed, not unknown"
    );

    Ok(())
}
