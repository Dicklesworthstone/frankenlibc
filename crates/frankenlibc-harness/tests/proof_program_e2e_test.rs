//! E2E gate tests for the WS7 proof-program reframe path (bd-e4phe.5).

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::other("workspace root should exist"))?
        .to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/proof_program_e2e.v1.json")
}

fn decision_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/proof_program_owner_decision.v1.json")
}

fn script_path(root: &Path) -> PathBuf {
    root.join("scripts/check_proof_program_e2e.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    let contents = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&contents)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let contents = std::fs::read_to_string(path)?;
    let mut rows = Vec::new();
    for line in contents.lines().filter(|line| !line.trim().is_empty()) {
        rows.push(serde_json::from_str(line)?);
    }
    Ok(rows)
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "proof-program-e2e-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_gate(
    root: &Path,
    out_dir: &Path,
    decision: Option<&Path>,
) -> TestResult<std::process::Output> {
    let mut command = Command::new("bash");
    command
        .arg(script_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_PROOF_PROGRAM_E2E_MANIFEST",
            manifest_path(root),
        )
        .env(
            "FRANKENLIBC_PROOF_PROGRAM_E2E_REPORT",
            out_dir.join("proof_program_e2e.report.json"),
        )
        .env(
            "FRANKENLIBC_PROOF_PROGRAM_E2E_LOG",
            out_dir.join("proof_program_e2e.log.jsonl"),
        );
    if let Some(decision) = decision {
        command.env("FRANKENLIBC_PROOF_PROGRAM_E2E_DECISION", decision);
    }
    Ok(command.output()?)
}

fn output_message(output: &std::process::Output) -> String {
    format!(
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let array = value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string array"))?;
    let mut set = BTreeSet::new();
    for item in array {
        set.insert(
            item.as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string"))?
                .to_string(),
        );
    }
    Ok(set)
}

#[test]
fn gate_manifest_binds_reframe_inputs_and_events() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&manifest_path(&root))?;
    assert_eq!(manifest["schema"].as_str(), Some("proof_program_e2e.v1"));
    assert_eq!(manifest["bead"].as_str(), Some("bd-e4phe.5"));
    assert_eq!(
        manifest["mode"].as_str(),
        Some("reframe_as_tested_invariant_catalogs")
    );
    assert_eq!(
        manifest["required_decision"]["mechanization_bead"].as_str(),
        Some("bd-e4phe.2")
    );
    assert_eq!(
        manifest["required_binder"]["expected_reframe_status"].as_str(),
        Some("deferred")
    );
    assert_eq!(
        string_set(&manifest["required_events"])?,
        BTreeSet::from([
            "proof_program_decision_validated".to_string(),
            "proof_program_binder_validated".to_string(),
            "proof_program_doc_language_validated".to_string()
        ])
    );
    Ok(())
}

#[test]
fn gate_emits_report_and_structured_log_for_reframe_path() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_gate(&root, &out_dir, None)?;
    assert!(
        output.status.success(),
        "proof-program e2e should pass:\n{}",
        output_message(&output)
    );

    let report = read_json(&out_dir.join("proof_program_e2e.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead"].as_str(), Some("bd-e4phe.5"));
    assert_eq!(report["summary"]["future_artifacts"].as_u64(), Some(4));
    assert_eq!(report["summary"]["obligations"].as_u64(), Some(24));
    assert_eq!(report["summary"]["source_refs"].as_u64(), Some(4));

    let rows = read_jsonl(&out_dir.join("proof_program_e2e.log.jsonl"))?;
    assert_eq!(rows.len(), 3, "one row per E2E stage");
    let events = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect::<BTreeSet<_>>();
    for event in [
        "proof_program_decision_validated",
        "proof_program_binder_validated",
        "proof_program_doc_language_validated",
    ] {
        assert!(events.contains(event), "missing event {event}");
    }
    let required_fields = string_set(&report["required_fields"])?;
    for row in rows {
        for field in &required_fields {
            assert!(row.get(field).is_some(), "log row missing {field}: {row}");
        }
        assert_eq!(row["status"].as_str(), Some("pass"));
        assert_eq!(
            row["claim_decision"].as_str(),
            Some("tested_invariant_catalog_only")
        );
    }
    Ok(())
}

#[test]
fn gate_rejects_fake_machine_checked_status() -> TestResult {
    let root = workspace_root()?;
    let mut decision = read_json(&decision_path(&root))?;
    decision["decision"]["machine_checked_formal_proof_status"] =
        Value::String("committed".to_string());
    decision["mechanization_deferral"]["required_future_artifacts"][0]["current_status"] =
        Value::String("verified".to_string());

    let out_dir = unique_output_dir(&root, "fake-proof")?;
    let stale_decision = out_dir.join("fake_decision.json");
    write_json(&stale_decision, &decision)?;

    let output = run_gate(&root, &out_dir, Some(&stale_decision))?;
    assert!(
        !output.status.success(),
        "fake machine-checked status should fail:\n{}",
        output_message(&output)
    );
    let message = output_message(&output);
    assert!(
        message.contains("machine_checked_formal_proof_status mismatch")
            && message.contains("future artifact not deferred"),
        "failure should identify proof overclaim drift"
    );
    Ok(())
}
