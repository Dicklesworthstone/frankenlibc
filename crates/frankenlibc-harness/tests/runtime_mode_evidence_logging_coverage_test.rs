use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest
        .parent()
        .and_then(Path::parent)
        .ok_or("workspace root")?
        .to_path_buf())
}

fn unique_dir(prefix: &str) -> TestResult<PathBuf> {
    let root = workspace_root()?;
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    );
    let dir = root
        .join("target")
        .join("test-runtime-mode-evidence")
        .join(format!("{prefix}-{suffix}"));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_gate_with_contract(contract: Option<&Path>) -> TestResult<Output> {
    let root = workspace_root()?;
    let mut command =
        Command::new(root.join("scripts/check_runtime_mode_evidence_logging_coverage.sh"));
    command.arg("--validate-only").current_dir(&root);
    if let Some(contract) = contract {
        let out_dir = unique_dir("gate-override")?;
        command
            .env("RUNTIME_MODE_EVIDENCE_LOGGING_COVERAGE_CONTRACT", contract)
            .env(
                "RUNTIME_MODE_EVIDENCE_LOGGING_COVERAGE_REPORT",
                out_dir.join("report.json"),
            )
            .env(
                "RUNTIME_MODE_EVIDENCE_LOGGING_COVERAGE_LOG",
                out_dir.join("log.jsonl"),
            );
    }
    Ok(command.output()?)
}

#[test]
fn runtime_mode_coverage_gate_passes_current_contract() -> TestResult {
    let output = run_gate_with_contract(None)?;
    assert!(
        output.status.success(),
        "coverage gate should pass\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn runtime_mode_coverage_gate_fails_when_startup_evidence_is_removed() -> TestResult {
    let root = workspace_root()?;
    let source = root.join("tests/conformance/runtime_mode_evidence_logging_coverage.v1.json");
    let mut contract: Value = serde_json::from_str(&std::fs::read_to_string(&source)?)?;
    let first_row = contract
        .get_mut("coverage_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| rows.first_mut())
        .and_then(Value::as_object_mut)
        .ok_or("coverage_rows[0] object")?;
    first_row.insert("logs_startup_mode".to_string(), json!(false));

    let dir = unique_dir("mutated-contract")?;
    let contract_path = dir.join("runtime_mode_evidence_logging_coverage.mutated.json");
    std::fs::write(
        &contract_path,
        serde_json::to_string_pretty(&contract)? + "\n",
    )?;

    let output = run_gate_with_contract(Some(&contract_path))?;
    assert!(
        !output.status.success(),
        "mutated contract should fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("startup_evidence_missing"),
        "failure should identify missing startup evidence\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn isolated_conformance_child_overrides_ambient_mode_and_logs_startup() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_dir("isolated-conformance")?;
    let fixture_dir = dir.join("fixtures");
    std::fs::create_dir_all(&fixture_dir)?;
    std::fs::write(
        fixture_dir.join("ctype_runtime_mode_probe.json"),
        serde_json::to_string_pretty(&json!({
            "version": "v1",
            "family": "ctype",
            "captured_at": "2026-05-06T00:00:00Z",
            "cases": [
                {
                    "name": "isdigit_0_runtime_mode_probe",
                    "function": "isdigit",
                    "spec_section": "POSIX.1-2017 isdigit",
                    "inputs": {"c": 48},
                    "expected_output": "1",
                    "expected_errno": 0,
                    "mode": "both"
                }
            ]
        }))? + "\n",
    )?;

    let matrix_path = dir.join("matrix.json");
    let log_path = dir.join("matrix.log.jsonl");
    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .arg("conformance-matrix")
        .arg("--fixture")
        .arg(&fixture_dir)
        .arg("--output")
        .arg(&matrix_path)
        .arg("--log")
        .arg(&log_path)
        .arg("--mode")
        .arg("hardened")
        .arg("--campaign")
        .arg("runtime_mode_mismatch_probe")
        .arg("--isolate")
        .arg("--fail-on-mismatch")
        .current_dir(&root)
        .env("FRANKENLIBC_MODE", "strict")
        .env("TZ", "Pacific/Auckland")
        .output()?;

    assert!(
        output.status.success(),
        "isolated conformance should override ambient FRANKENLIBC_MODE\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_body = std::fs::read_to_string(&log_path)?;
    let startup_rows: Vec<Value> = log_body
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert!(
        startup_rows.iter().any(|row| {
            row["event"] == "conformance.runtime_mode_startup"
                && row["mode"] == "hardened"
                && row["details"]["mode_source"] == "child_process_env"
                && row["details"]["mismatch_behavior"] == "runtime_mode_startup_mismatch"
                && row["details"]["ambient_tz_dependency"] == false
        }),
        "startup-mode log row missing or incomplete:\n{log_body}"
    );
    assert!(
        !log_body.contains("runtime_mode_startup_mismatch: expected"),
        "ambient strict mode leaked into isolated child:\n{log_body}"
    );
    Ok(())
}
