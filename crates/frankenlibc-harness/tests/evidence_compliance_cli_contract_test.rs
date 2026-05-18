//! Conformance gate for the harness binary `evidence-compliance`
//! subcommand.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use frankenlibc_harness::structured_log::{ArtifactIndex, LogEntry, LogLevel, Outcome, StreamKind};
use serde_json::Value;
use sha2::Digest;

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("evidence_compliance_cli_contract.v1.json")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {path:?}: {err}"))
}

fn parse_json(bytes: &[u8], label: &str) -> TestResult<Value> {
    serde_json::from_slice(bytes).map_err(|err| format!("parse {label}: {err}"))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or non-string `{field}`"))
}

fn json_bool(value: &Value, field: &str) -> TestResult<bool> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing or non-bool `{field}`"))
}

fn json_u64(value: &Value, field: &str) -> TestResult<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing or non-u64 `{field}`"))
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing or non-array `{field}`"))
}

fn cargo_target_dir_for_bin() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_TARGET_DIR") {
        PathBuf::from(path)
    } else if let Ok(path) = std::env::var("CARGO_MANIFEST_DIR") {
        Path::new(&path)
            .parent()
            .and_then(Path::parent)
            .map(|root| root.join("target"))
            .unwrap_or_else(|| PathBuf::from("target"))
    } else {
        PathBuf::from("target")
    }
}

fn find_harness_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_harness") {
        return Some(PathBuf::from(path));
    }

    let root = cargo_target_dir_for_bin();
    for profile in ["debug", "release"] {
        let candidate = root.join(profile).join("harness");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn unique_tmp_dir(label: &str) -> TestResult<PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| format!("clock: {err}"))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "frankenlibc_evidence_compliance_cli_contract_{label}_{}_{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|err| format!("create {dir:?}: {err}"))?;
    Ok(dir)
}

fn sha256_hex(path: &Path) -> TestResult<String> {
    let bytes = std::fs::read(path).map_err(|err| format!("read artifact {path:?}: {err}"))?;
    let digest = sha2::Sha256::digest(&bytes);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn write_valid_bundle(dir: &Path, label: &str) -> TestResult<(PathBuf, PathBuf)> {
    let artifact_path = dir.join("diagnostic.txt");
    std::fs::write(&artifact_path, b"diagnostic-bytes")
        .map_err(|err| format!("write artifact {artifact_path:?}: {err}"))?;

    let mut index = ArtifactIndex::new(format!("run-{label}"), "bd-cli-contract");
    index.add("diagnostic.txt", "diagnostic", sha256_hex(&artifact_path)?);
    let index_path = dir.join(format!("{label}.artifact_index.json"));
    std::fs::write(&index_path, index.to_json().map_err(|err| err.to_string())?)
        .map_err(|err| format!("write index {index_path:?}: {err}"))?;

    let line = LogEntry::new(
        format!("bd-cli-contract::{label}::001"),
        LogLevel::Info,
        "gate_result",
    )
    .with_stream(StreamKind::Release)
    .with_gate("evidence_compliance")
    .with_outcome(Outcome::Pass)
    .with_artifacts(vec!["diagnostic.txt".to_string()])
    .to_jsonl()
    .map_err(|err| err.to_string())?;
    let log_path = dir.join(format!("{label}.log.jsonl"));
    std::fs::write(&log_path, format!("{line}\n"))
        .map_err(|err| format!("write log {log_path:?}: {err}"))?;

    Ok((log_path, index_path))
}

fn write_failing_bundle(dir: &Path) -> TestResult<(PathBuf, PathBuf)> {
    let artifact_path = dir.join("failing-diagnostic.txt");
    std::fs::write(&artifact_path, b"diagnostic-bytes")
        .map_err(|err| format!("write artifact {artifact_path:?}: {err}"))?;

    let mut index = ArtifactIndex::new("run-failing", "bd-cli-contract");
    index.add(
        "failing-diagnostic.txt",
        "diagnostic",
        sha256_hex(&artifact_path)?,
    );
    let index_path = dir.join("failing.artifact_index.json");
    std::fs::write(&index_path, index.to_json().map_err(|err| err.to_string())?)
        .map_err(|err| format!("write index {index_path:?}: {err}"))?;

    let line = LogEntry::new(
        "bd-cli-contract::failing::001",
        LogLevel::Error,
        "test_failure",
    )
    .with_stream(StreamKind::E2e)
    .with_gate("e2e_suite")
    .with_outcome(Outcome::Fail)
    .to_jsonl()
    .map_err(|err| err.to_string())?;
    let log_path = dir.join("failing.log.jsonl");
    std::fs::write(&log_path, format!("{line}\n"))
        .map_err(|err| format!("write log {log_path:?}: {err}"))?;

    Ok((log_path, index_path))
}

fn run_evidence_compliance(
    bin: &Path,
    workspace_root_arg: &Path,
    log_path: &Path,
    index_path: &Path,
    output_path: Option<&Path>,
) -> TestResult<Output> {
    let mut cmd = Command::new(bin);
    cmd.arg("evidence-compliance")
        .arg("--workspace-root")
        .arg(workspace_root_arg)
        .arg("--log")
        .arg(log_path)
        .arg("--artifact-index")
        .arg(index_path);
    if let Some(path) = output_path {
        cmd.arg("--output").arg(path);
    }
    cmd.output().map_err(|err| format!("spawn harness: {err}"))
}

#[test]
fn manifest_anchors_evidence_compliance_subcommand() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    require(
        json_string(&manifest, "manifest_id")? == "evidence-compliance-cli-contract",
        "manifest_id",
    )?;
    require(
        json_string(&manifest, "subcommand_name")? == "evidence-compliance",
        "subcommand_name",
    )?;
    require(
        json_string(&manifest, "binary_target")? == "harness",
        "binary_target",
    )?;

    let required_flags: Vec<&str> = json_array(&manifest, "required_flags")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    require(
        required_flags == ["--log", "--artifact-index"],
        "required_flags must pin --log and --artifact-index",
    )
}

#[test]
fn manifest_policy_pins_cli_invariants() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let policy = manifest
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for field in [
        "must_register_evidence_compliance_subcommand",
        "must_require_log_and_artifact_index",
        "must_accept_workspace_root_for_artifact_resolution",
        "must_emit_triage_json_to_stdout_without_output",
        "must_create_output_parent_directories",
        "must_write_output_before_failure_exit",
        "must_fail_nonzero_on_violations",
        "must_include_required_violation_triage_fields",
    ] {
        require(json_bool(policy, field)?, field)?;
    }

    let output = manifest
        .get("output_contract")
        .ok_or_else(|| "missing output_contract".to_string())?;
    for field in [
        "stdout_when_output_omitted",
        "writes_output_before_failure_exit",
        "creates_output_parent_directories",
        "fails_nonzero_on_violations",
    ] {
        require(json_bool(output, field)?, field)?;
    }

    let required_output: Vec<&str> = json_array(output, "json_required_fields")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    require(
        required_output
            == [
                "ok",
                "violation_count",
                "log_path",
                "artifact_index_path",
                "violations",
            ],
        "json_required_fields must pin triage shape",
    )?;

    let required_violation: Vec<&str> = json_array(output, "violation_required_fields")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for field in [
        "violation_code",
        "offending_event",
        "expected_fields",
        "remediation_hint",
        "artifact_pointer",
        "line_number",
        "message",
    ] {
        require(required_violation.contains(&field), field)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_evidence_compliance_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|err| format!("read harness.rs: {err}"))?;
    require(
        src.contains("EvidenceCompliance {"),
        "harness.rs must declare EvidenceCompliance Command variant",
    )?;
    for field in ["workspace_root", "log", "artifact_index", "output"] {
        require(src.contains(field), field)?;
    }
    require(
        src.contains("validate_evidence_bundle"),
        "main() must call validate_evidence_bundle",
    )?;
    require(
        src.contains("evidence_report_to_triage_json"),
        "main() must render deterministic triage JSON",
    )
}

#[test]
fn cli_prints_triage_json_to_stdout_for_valid_bundle() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };

    let tmp = unique_tmp_dir("stdout_valid")?;
    let (log_path, index_path) = write_valid_bundle(&tmp, "stdout-valid")?;
    let run = run_evidence_compliance(&bin, &tmp, &log_path, &index_path, None)?;
    if !run.status.success() {
        return Err(format!(
            "evidence-compliance valid bundle failed: status={:?} stderr={}",
            run.status,
            String::from_utf8_lossy(&run.stderr)
        ));
    }

    let triage = parse_json(&run.stdout, "stdout triage")?;
    require(json_bool(&triage, "ok")?, "ok must be true")?;
    require(
        json_u64(&triage, "violation_count")? == 0,
        "violation_count must be zero",
    )?;
    require(
        json_string(&triage, "log_path")?.ends_with(".log.jsonl"),
        "log_path must be present",
    )?;
    require(
        json_string(&triage, "artifact_index_path")?.ends_with(".artifact_index.json"),
        "artifact_index_path must be present",
    )?;
    require(
        json_array(&triage, "violations")?.is_empty(),
        "violations must be empty",
    )
}

#[test]
fn cli_writes_output_before_nonzero_failure_exit() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };

    let tmp = unique_tmp_dir("failure_output")?;
    let (log_path, index_path) = write_failing_bundle(&tmp)?;
    let output_path = tmp.join("nested").join("triage").join("failure.json");
    let run = run_evidence_compliance(&bin, &tmp, &log_path, &index_path, Some(&output_path))?;
    require(
        !run.status.success(),
        "bad evidence bundle must return nonzero",
    )?;
    let stderr = String::from_utf8_lossy(&run.stderr);
    require(
        stderr.contains("Evidence compliance failed:"),
        format!("stderr must include failure diagnostic; stderr={stderr}"),
    )?;
    require(
        output_path.exists(),
        "triage output must be written before nonzero failure exit",
    )?;

    let triage = load_json(&output_path)?;
    require(!json_bool(&triage, "ok")?, "ok must be false")?;
    require(
        json_u64(&triage, "violation_count")? > 0,
        "violation_count must be positive",
    )?;
    let violations = json_array(&triage, "violations")?;
    require(!violations.is_empty(), "violations must not be empty")?;
    require(
        violations.iter().any(|violation| {
            violation.get("violation_code").and_then(Value::as_str)
                == Some("failure_event.missing_artifact_refs")
        }),
        "missing failure artifact refs must be reported",
    )?;
    for key in [
        "violation_code",
        "offending_event",
        "expected_fields",
        "remediation_hint",
        "artifact_pointer",
        "line_number",
        "message",
    ] {
        require(
            violations
                .iter()
                .all(|violation| violation.get(key).is_some()),
            key,
        )?;
    }
    Ok(())
}

#[test]
fn cli_creates_output_parent_directory_on_success() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };

    let tmp = unique_tmp_dir("success_output")?;
    let (log_path, index_path) = write_valid_bundle(&tmp, "success-output")?;
    let output_path = tmp.join("nested").join("success").join("triage.json");
    let run = run_evidence_compliance(&bin, &tmp, &log_path, &index_path, Some(&output_path))?;
    if !run.status.success() {
        return Err(format!(
            "evidence-compliance output bundle failed: status={:?} stderr={}",
            run.status,
            String::from_utf8_lossy(&run.stderr)
        ));
    }
    require(
        output_path.exists(),
        "success output must create parent directories and write JSON",
    )?;
    let triage = load_json(&output_path)?;
    require(json_bool(&triage, "ok")?, "ok must be true")?;
    require(
        json_u64(&triage, "violation_count")? == 0,
        "violation_count must be zero",
    )
}
