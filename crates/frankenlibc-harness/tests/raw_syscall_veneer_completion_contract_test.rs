//! Contract tests for bd-cj0.1 raw syscall veneer completion evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    message.into().into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| test_error("cannot resolve workspace root"))?
        .to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/raw_syscall_veneer_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_raw_syscall_veneer_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| test_error("value should be array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("array item should be string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()
}

const UNIT_PRIMARY_COMMAND: &str = "RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_raw_syscall_veneer_unit cargo test -p frankenlibc-core syscall -- --nocapture";
const E2E_PRIMARY_COMMAND: &str = "RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_raw_syscall_veneer_e2e cargo test -p frankenlibc-core --test syscall_veneer_test -- --nocapture";
const TELEMETRY_TEST_COMMAND: &str = "RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_raw_syscall_veneer_harness cargo test -p frankenlibc-harness --test raw_syscall_veneer_completion_contract_test -- --nocapture";
const TELEMETRY_CLIPPY_COMMAND: &str = "RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_raw_syscall_veneer_clippy cargo clippy -p frankenlibc-harness --test raw_syscall_veneer_completion_contract_test -- -D warnings";

fn required_commands(manifest: &Value, section: &str) -> TestResult<BTreeSet<String>> {
    string_set(&manifest["completion_debt_evidence"][section]["required_commands"])
}

fn set_required_command(manifest: &mut Value, section: &str, index: usize, command: &str) {
    manifest["completion_debt_evidence"][section]["required_commands"][index] =
        Value::String(command.to_string());
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before epoch: {err}")))?
        .as_nanos();
    let path = root.join("target/conformance").join(format!(
        "raw-syscall-veneer-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .env(
            "FRANKENLIBC_RAW_SYSCALL_VENEER_COMPLETION_CONTRACT",
            manifest,
        )
        .env("FRANKENLIBC_RAW_SYSCALL_VENEER_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_RAW_SYSCALL_VENEER_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_RAW_SYSCALL_VENEER_COMPLETION_LOG",
            out_dir.join("events.jsonl"),
        )
        .current_dir(root)
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn read_log_events(path: &Path) -> TestResult<BTreeSet<String>> {
    fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let row: Value = serde_json::from_str(line)?;
            row["event"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("log row missing event"))
        })
        .collect::<Result<BTreeSet<_>, _>>()
}

fn assert_file_line_ref_exists(root: &Path, value: &str) -> TestResult {
    let (path, line) = value
        .rsplit_once(':')
        .ok_or_else(|| test_error("file line ref should contain ':'"))?;
    let line_no: usize = line.parse()?;
    assert!(line_no > 0, "line ref must be positive");
    let full_path = root.join(path);
    assert!(full_path.is_file(), "file-line ref missing path {value}");
    let line_count = fs::read_to_string(full_path)?.lines().count();
    assert!(line_no <= line_count, "file-line ref outside file: {value}");
    Ok(())
}

#[test]
fn contract_anchors_raw_syscall_veneer_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["manifest_id"].as_str(),
        Some("raw-syscall-veneer-completion-contract")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-cj0"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-cj0.1"));
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items_closed"])?,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
    );
    assert!(
        manifest["completion_debt_evidence"]["next_audit_score_threshold"]
            .as_u64()
            .is_some_and(|threshold| threshold >= 800)
    );
    assert!(
        manifest["raw_veneer_expectations"]["minimum_integration_tests"]
            .as_u64()
            .is_some_and(|count| count >= 90)
    );
    assert_eq!(
        required_commands(&manifest, "unit_primary")?,
        BTreeSet::from([UNIT_PRIMARY_COMMAND.to_string()])
    );
    assert_eq!(
        required_commands(&manifest, "e2e_primary")?,
        BTreeSet::from([E2E_PRIMARY_COMMAND.to_string()])
    );
    assert_eq!(
        required_commands(&manifest, "telemetry_primary")?,
        BTreeSet::from([
            TELEMETRY_TEST_COMMAND.to_string(),
            TELEMETRY_CLIPPY_COMMAND.to_string(),
        ])
    );
    for reference in manifest["implementation_refs"]
        .as_array()
        .ok_or_else(|| test_error("implementation refs should be array"))?
    {
        assert_file_line_ref_exists(
            &root,
            reference
                .as_str()
                .ok_or_else(|| test_error("implementation ref should be string"))?,
        )?;
    }
    Ok(())
}

#[test]
fn checker_rejects_non_remote_rch_validation_commands() -> TestResult {
    let root = workspace_root()?;

    let mut missing_force = load_json(&manifest_path(&root))?;
    set_required_command(
        &mut missing_force,
        "unit_primary",
        0,
        &UNIT_PRIMARY_COMMAND.replacen("RCH_FORCE_REMOTE=true ", "", 1),
    );
    let out_dir = unique_output_dir(&root, "missing-force-remote")?;
    let mutated = out_dir.join("missing-force.json");
    write_json(&mutated, &missing_force)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("must set RCH_FORCE_REMOTE=true"),
        "{}",
        output_text(&output)
    );

    let mut missing_target = load_json(&manifest_path(&root))?;
    set_required_command(
        &mut missing_target,
        "e2e_primary",
        0,
        "RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env cargo test -p frankenlibc-core --test syscall_veneer_test -- --nocapture",
    );
    let out_dir = unique_output_dir(&root, "missing-target-dir")?;
    let mutated = out_dir.join("missing-target.json");
    write_json(&mutated, &missing_target)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr)
                .contains("must set isolated CARGO_TARGET_DIR"),
        "{}",
        output_text(&output)
    );

    let mut shell_wrapped = load_json(&manifest_path(&root))?;
    set_required_command(
        &mut shell_wrapped,
        "telemetry_primary",
        1,
        "RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- bash -c 'cargo clippy -p frankenlibc-harness --test raw_syscall_veneer_completion_contract_test -- -D warnings'",
    );
    let out_dir = unique_output_dir(&root, "shell-wrapped")?;
    let mutated = out_dir.join("shell-wrapped.json");
    write_json(&mutated, &shell_wrapped)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("must not shell-wrap cargo"),
        "{}",
        output_text(&output)
    );

    let mut local_fallback = load_json(&manifest_path(&root))?;
    set_required_command(
        &mut local_fallback,
        "telemetry_primary",
        0,
        &format!("{TELEMETRY_TEST_COMMAND} [RCH] local (remote execution failed)"),
    );
    let out_dir = unique_output_dir(&root, "local-fallback")?;
    let mutated = out_dir.join("local-fallback.json");
    write_json(&mutated, &local_fallback)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr)
                .contains("must not accept local rch fallback"),
        "{}",
        output_text(&output)
    );
    Ok(())
}

#[test]
fn source_artifacts_bind_raw_veneer_surfaces() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let artifacts = manifest["source_artifacts"]
        .as_array()
        .ok_or_else(|| test_error("source_artifacts should be array"))?;
    assert_eq!(artifacts.len(), 9);

    let ids = artifacts
        .iter()
        .map(|artifact| {
            artifact["artifact_id"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("source artifact id should be string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    assert_eq!(
        ids,
        BTreeSet::from([
            "completion_checker".to_string(),
            "completion_contract".to_string(),
            "completion_harness".to_string(),
            "core_syscall_integration_tests".to_string(),
            "core_syscall_unit_tests".to_string(),
            "raw_syscall_primitives".to_string(),
            "raw_syscall_unit_tests".to_string(),
            "typed_syscall_wrappers".to_string(),
            "verification_matrix_record".to_string(),
        ])
    );

    for artifact in artifacts {
        let path = artifact["path"]
            .as_str()
            .ok_or_else(|| test_error("source artifact path should be string"))?;
        let text = fs::read_to_string(root.join(path))?;
        for needle in artifact["required_needles"]
            .as_array()
            .ok_or_else(|| test_error("required_needles should be array"))?
        {
            let needle = needle
                .as_str()
                .ok_or_else(|| test_error("needle should be string"))?;
            assert!(
                text.contains(needle),
                "{path} should contain required needle {needle}"
            );
        }
    }
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS raw syscall veneer completion contract"));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_count"].as_u64(), Some(9));
    assert!(
        report["raw_syscall_primitive_count"]
            .as_u64()
            .is_some_and(|count| count >= 14)
    );
    assert!(
        report["typed_wrapper_count"]
            .as_u64()
            .is_some_and(|count| count >= 25)
    );
    assert!(
        report["integration_test_count"]
            .as_u64()
            .is_some_and(|count| count >= 90)
    );

    let events = read_log_events(&out_dir.join("events.jsonl"))?;
    for event in [
        "raw_syscall_veneer.source_artifacts_validated",
        "raw_syscall_veneer.expectations_validated",
        "raw_syscall_veneer.implementation_refs_validated",
        "raw_syscall_veneer.unit_binding_validated",
        "raw_syscall_veneer.e2e_binding_validated",
        "raw_syscall_veneer.telemetry_binding_validated",
        "raw_syscall_veneer.completion_contract_validated",
    ] {
        assert!(events.contains(event), "missing telemetry event {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_test_ref() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_test_refs"][0]["name"] =
        Value::String("definitely_missing_raw_syscall_unit_test".to_string());

    let out_dir = unique_output_dir(&root, "missing-unit-ref")?;
    let mutated = out_dir.join("mutated.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail mutated contract"
    );
    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or_else(|| test_error("errors should be array"))?
            .iter()
            .any(|item| item
                .as_str()
                .is_some_and(|text| text.contains("definitely_missing_raw_syscall_unit_test")))
    );
    let events = read_log_events(&out_dir.join("events.jsonl"))?;
    assert!(events.contains("raw_syscall_veneer.completion_contract_failed"));
    Ok(())
}

#[test]
fn checker_rejects_missing_source_needle() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["source_artifacts"][0]["required_needles"]
        .as_array_mut()
        .ok_or_else(|| test_error("required needles should be array"))?
        .push(Value::String(
            "definitely_missing_raw_syscall_source_needle".to_string(),
        ));

    let out_dir = unique_output_dir(&root, "missing-source-needle")?;
    let mutated = out_dir.join("mutated.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail mutated contract"
    );
    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or_else(|| test_error("errors should be array"))?
            .iter()
            .any(|item| item
                .as_str()
                .is_some_and(|text| text.contains("definitely_missing_raw_syscall_source_needle")))
    );
    let events = read_log_events(&out_dir.join("events.jsonl"))?;
    assert!(events.contains("raw_syscall_veneer.completion_contract_failed"));
    Ok(())
}
