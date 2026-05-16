//! Focused coverage for the workspace rustfmt quarantine gate.
//!
//! The gate is intentionally degraded: it passes only when live `cargo fmt
//! --check` drift exactly matches the checked-in quarantine artifact.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_LOG_FIELDS: [&str; 12] = [
    "trace_id",
    "bead_id",
    "command",
    "exit_status",
    "validation_scope",
    "owner",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest should have a parent"))?;
    Ok(crates_dir
        .parent()
        .ok_or_else(|| {
            io::Error::other("frankenlibc-harness manifest should live below workspace root")
        })?
        .to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/workspace_rustfmt_gate_health.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_workspace_rustfmt_gate_health.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "workspace_rustfmt_gate_health_{label}_{}_{}",
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_RUSTFMT_GATE_HEALTH", manifest)
        .env(
            "FRANKENLIBC_RUSTFMT_GATE_REPORT",
            out_dir.join("workspace_rustfmt_gate_health.report.json"),
        )
        .env(
            "FRANKENLIBC_RUSTFMT_GATE_LOG",
            out_dir.join("workspace_rustfmt_gate_health.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_RUSTFMT_GATE_OUTPUT",
            out_dir.join("workspace_rustfmt_gate_health.cargo-fmt.txt"),
        )
        .output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn string_array(value: &Value, field: &str) -> TestResult<Vec<String>> {
    Ok(value[field]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{field} array")))?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{field} string"))
                })
                .map(str::to_owned)
        })
        .collect::<Result<_, _>>()?)
}

fn assert_log_row_shape(row: &Value) {
    for field in REQUIRED_LOG_FIELDS {
        assert!(row.get(field).is_some(), "log row missing {field}: {row}");
    }
    assert_eq!(
        row["validation_scope"].as_str(),
        Some("workspace-rustfmt-quarantine")
    );
    assert_eq!(row["command"].as_str(), Some("cargo fmt --check"));
    assert_eq!(row["bead_id"].as_str(), Some("bd-bp8fl.7.1"));
    assert!(
        row["artifact_refs"]
            .as_array()
            .is_some_and(|refs| !refs.is_empty()),
        "artifact_refs must be a non-empty array: {row}"
    );
}

#[test]
fn manifest_declares_rustfmt_quarantine_contract() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&manifest_path(&root))?;

    assert_eq!(manifest["schema_version"].as_str(), Some("v1"));
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.7.1"));
    assert_eq!(manifest["status"].as_str(), Some("clean"));
    assert_eq!(manifest["refreshed_by"].as_str(), Some("bd-o63t6"));
    assert_eq!(
        manifest["validation_command"].as_str(),
        Some("bash scripts/check_workspace_rustfmt_gate_health.sh")
    );

    let required_fields = string_array(&manifest, "required_log_fields")?;
    assert_eq!(
        required_fields.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from(REQUIRED_LOG_FIELDS.map(str::to_owned))
    );

    let quarantine = &manifest["quarantine"];
    assert_eq!(quarantine["owner_bead"].as_str(), Some("bd-bp8fl.7.1"));
    let files = string_array(quarantine, "files")?;
    assert!(
        files.is_empty(),
        "clean rustfmt gate must have no drift files"
    );
    assert_eq!(
        quarantine["file_count"].as_u64(),
        Some(files.len() as u64),
        "file_count must match quarantine.files"
    );
    Ok(())
}

#[test]
fn checker_emits_pass_report_and_per_file_log_rows() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let manifest = read_json(&manifest_path(&root))?;
    let expected_files = string_array(&manifest["quarantine"], "files")?;

    let report = read_json(&out_dir.join("workspace_rustfmt_gate_health.report.json"))?;
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.7.1"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["command"].as_str(), Some("cargo fmt --check"));
    assert_eq!(
        report["validation_scope"].as_str(),
        Some("workspace-rustfmt-quarantine")
    );
    assert_eq!(report["failure_signature"].as_str(), Some("rustfmt_clean"));
    assert!(expected_files.is_empty());
    assert_eq!(report["expected_count"].as_u64(), Some(0));
    assert_eq!(report["actual_count"].as_u64(), Some(0));
    assert_eq!(
        report["extra_unquarantined"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(
        report["missing_from_live_drift"].as_array().map(Vec::len),
        Some(0)
    );
    assert!(
        report["artifact_refs"]
            .as_array()
            .is_some_and(|refs| refs.len() == 2)
    );

    let rows = read_jsonl(&out_dir.join("workspace_rustfmt_gate_health.log.jsonl"))?;
    assert_eq!(rows.len(), 1);
    for row in &rows {
        assert_log_row_shape(row);
        assert_eq!(
            row["failure_signature"].as_str(),
            Some("ok"),
            "clean pass row should be an ok row: {row}"
        );
        assert_eq!(row["expected"].as_str(), Some("no_tracked_rustfmt_drift"));
        assert_eq!(row["actual"].as_str(), Some("no_tracked_rustfmt_drift"));
    }

    Ok(())
}

#[test]
fn checker_rejects_stale_quarantine_file_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "stale_file")?;
    let mut manifest = read_json(&manifest_path(&root))?;
    let stale_file = "crates/frankenlibc-harness/tests/workspace_rustfmt_gate_health_test.rs";
    manifest["status"] = json!("quarantined");
    manifest["quarantine"]["files"] = json!([stale_file]);
    manifest["quarantine"]["file_count"] = json!(1);
    let mutated = out_dir.join("workspace_rustfmt_gate_health_stale_file.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject a stale quarantine binding:\n{}",
        output_text(&output)
    );

    let report = read_json(&out_dir.join("workspace_rustfmt_gate_health.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_eq!(
        report["failure_signature"].as_str(),
        Some("rustfmt_drift_set_mismatch")
    );
    assert!(
        report["missing_from_live_drift"]
            .as_array()
            .is_some_and(|missing| missing.iter().any(|path| path.as_str() == Some(stale_file))),
        "failure report should name stale drift file {stale_file}: {report}"
    );
    assert!(
        report["errors"]
            .as_array()
            .is_some_and(|errors| !errors.is_empty()),
        "failure report should include errors: {report}"
    );

    let rows = read_jsonl(&out_dir.join("workspace_rustfmt_gate_health.log.jsonl"))?;
    assert!(rows.iter().any(|row| {
        row["file_path"].as_str() == Some(stale_file)
            && matches!(
                row["failure_signature"].as_str(),
                Some("stale_quarantine_entry")
            )
            && row["expected"].as_str() == Some("present_in_rustfmt_drift")
            && row["actual"].as_str() == Some("absent_from_rustfmt_drift")
    }));
    for row in &rows {
        assert_log_row_shape(row);
    }

    Ok(())
}
