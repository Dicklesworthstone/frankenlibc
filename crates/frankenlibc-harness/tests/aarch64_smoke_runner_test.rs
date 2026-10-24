//! bd-gq1kz7.12: Aarch64 smoke battery emulation runner contract test.

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
fn smoke_runner_script_exists() -> TestResult {
    let script = workspace_root()?.join("scripts/run_aarch64_smoke.sh");
    assert!(script.exists(), "run_aarch64_smoke.sh should exist");
    Ok(())
}

#[test]
fn smoke_runner_contract_is_valid_json() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/run_aarch64_smoke.sh");

    let output = Command::new(&script)
        .arg("contract")
        .current_dir(&root)
        .output()?;

    assert!(
        output.status.success(),
        "contract command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("contract should be valid JSON: {e}\nOutput: {stdout}"))?;

    assert_eq!(
        json.get("gate").and_then(Value::as_str),
        Some("bd-gq1kz7.12"),
        "contract must identify as bd-gq1kz7.12"
    );

    Ok(())
}

#[test]
fn smoke_runner_contract_has_required_fields() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/run_aarch64_smoke.sh");

    let output = Command::new(&script)
        .arg("contract")
        .current_dir(&root)
        .output()?;

    assert!(
        output.status.success(),
        "contract command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)?;

    let contract = json.get("contract").ok_or("missing contract field")?;

    assert!(
        contract.get("runner_types").is_some(),
        "contract must specify runner_types"
    );
    assert!(
        contract.get("environment").is_some(),
        "contract must specify environment vars"
    );
    assert!(
        contract.get("artifact").is_some(),
        "contract must specify artifact path"
    );
    assert!(
        contract.get("preflight_checks").is_some(),
        "contract must specify preflight_checks"
    );
    assert!(
        contract.get("timeout_behavior").is_some(),
        "contract must specify timeout_behavior"
    );
    assert!(
        contract.get("failure_evidence").is_some(),
        "contract must specify failure_evidence format"
    );
    assert_eq!(
        contract.get("runtime_modes"),
        Some(&serde_json::json!(["strict", "hardened"])),
        "both deployed runtime modes are required"
    );
    let checks = contract
        .get("preflight_checks")
        .and_then(Value::as_array)
        .ok_or("preflight_checks must be an array")?;
    for required in [
        "aarch64_shared_elf",
        "required_exports",
        "compiler_available",
    ] {
        assert!(
            checks.iter().any(|check| check.as_str() == Some(required)),
            "missing actual-artifact preflight: {required}"
        );
    }

    Ok(())
}

#[test]
fn smoke_runner_missing_artifact_cannot_pass_or_skip() -> TestResult {
    let root = workspace_root()?;
    for mode in ["preflight", "run"] {
        let output = Command::new(root.join("scripts/run_aarch64_smoke.sh"))
            .arg(mode)
            .env(
                "FRANKENLIBC_AARCH64_ARTIFACT",
                root.join("target/aarch64-deliberately-absent/missing.so"),
            )
            .current_dir(&root)
            .output()?;
        assert_eq!(output.status.code(), Some(2));
        let report: Value = serde_json::from_slice(&output.stdout).map_err(|error| {
            format!(
                "missing-artifact result must be JSON: {error}; stderr={}",
                String::from_utf8_lossy(&output.stderr)
            )
        })?;
        assert_eq!(report["status"], "blocked");
        assert_eq!(report["reason"], "artifact_missing");
        assert_eq!(report["processes_executed"], 0);
    }
    Ok(())
}

#[test]
fn smoke_runner_rejects_existing_non_elf_artifact() -> TestResult {
    let root = workspace_root()?;
    let output = Command::new(root.join("scripts/run_aarch64_smoke.sh"))
        .arg("run")
        .env("FRANKENLIBC_AARCH64_ARTIFACT", root.join("Cargo.toml"))
        .current_dir(&root)
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["status"], "blocked");
    assert_eq!(report["reason"], "not_elf64_little_endian");
    assert_eq!(report["processes_executed"], 0);
    Ok(())
}
