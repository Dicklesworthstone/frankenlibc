//! Contract tests for bd-ef2.1 I/O raw veneer migration completion evidence.

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
    root.join("tests/conformance/io_raw_veneer_migration_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_io_raw_veneer_migration_completion_contract.sh")
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

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before epoch: {err}")))?
        .as_nanos();
    let path = root.join("target/conformance").join(format!(
        "io-raw-veneer-migration-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .env(
            "FRANKENLIBC_IO_RAW_VENEER_MIGRATION_COMPLETION_CONTRACT",
            manifest,
        )
        .env(
            "FRANKENLIBC_IO_RAW_VENEER_MIGRATION_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_IO_RAW_VENEER_MIGRATION_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_IO_RAW_VENEER_MIGRATION_COMPLETION_LOG",
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
fn contract_anchors_io_raw_veneer_migration_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["manifest_id"].as_str(),
        Some("io-raw-veneer-migration-completion-contract")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-ef2"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-ef2.1"));
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items_closed"])?,
        BTreeSet::from([
            "migrations.primary".to_string(),
            "telemetry.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.unit.primary".to_string(),
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
fn source_artifacts_bind_io_raw_veneer_surfaces() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let artifacts = manifest["source_artifacts"]
        .as_array()
        .ok_or_else(|| test_error("source_artifacts should be array"))?;
    assert_eq!(artifacts.len(), 10);

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
            "abi_io_raw_routes".to_string(),
            "abi_io_tests".to_string(),
            "abi_mmap_raw_routes".to_string(),
            "abi_mmap_tests".to_string(),
            "abi_unistd_raw_routes".to_string(),
            "abi_unistd_tests".to_string(),
            "completion_checker".to_string(),
            "completion_contract".to_string(),
            "completion_harness".to_string(),
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
        if let Some(forbidden) = artifact["forbidden_needles"].as_array() {
            for needle in forbidden {
                let needle = needle
                    .as_str()
                    .ok_or_else(|| test_error("forbidden needle should be string"))?;
                assert!(
                    !text.contains(needle),
                    "{path} should not contain forbidden route {needle}"
                );
            }
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
    assert!(stdout.contains("PASS io raw veneer migration completion contract"));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_count"].as_u64(), Some(10));
    assert!(
        report["raw_route_call_site_count"]
            .as_u64()
            .is_some_and(|count| count >= 17)
    );
    assert!(
        report["io_abi_test_count"]
            .as_u64()
            .is_some_and(|count| count >= 50)
    );
    assert!(
        report["mmap_abi_test_count"]
            .as_u64()
            .is_some_and(|count| count >= 20)
    );

    let events = read_log_events(&out_dir.join("events.jsonl"))?;
    for event in [
        "io_raw_veneer_migration.source_artifacts_validated",
        "io_raw_veneer_migration.expectations_validated",
        "io_raw_veneer_migration.implementation_refs_validated",
        "io_raw_veneer_migration.unit_binding_validated",
        "io_raw_veneer_migration.e2e_binding_validated",
        "io_raw_veneer_migration.migration_binding_validated",
        "io_raw_veneer_migration.telemetry_binding_validated",
        "io_raw_veneer_migration.completion_contract_validated",
    ] {
        assert!(events.contains(event), "missing telemetry event {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_direct_libc_syscall_route() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["source_artifacts"][0]["forbidden_needles"][0] =
        Value::String("syscall::sys_read".to_string());
    manifest["completion_debt_evidence"]["migrations_primary"]["forbidden_needles"][0] =
        Value::String("syscall::sys_read".to_string());
    manifest["migration_expectations"]["forbidden_runtime_route"] =
        Value::String("syscall::sys_read".to_string());

    let out_dir = unique_output_dir(&root, "forbidden-route")?;
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
                .is_some_and(|text| text.contains("syscall::sys_read")))
    );
    let events = read_log_events(&out_dir.join("events.jsonl"))?;
    assert!(events.contains("io_raw_veneer_migration.completion_contract_failed"));
    Ok(())
}

#[test]
fn checker_rejects_missing_migration_test_ref() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_test_refs"][0]["name"] =
        Value::String("definitely_missing_io_migration_test".to_string());

    let out_dir = unique_output_dir(&root, "missing-test-ref")?;
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
                .is_some_and(|text| text.contains("definitely_missing_io_migration_test")))
    );
    let events = read_log_events(&out_dir.join("events.jsonl"))?;
    assert!(events.contains("io_raw_veneer_migration.completion_contract_failed"));
    Ok(())
}
