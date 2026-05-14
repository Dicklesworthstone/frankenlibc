//! Conformance gate for the harness binary `replay-classify`
//! subcommand (bd-tzx36).

use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

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
        .join("replay_classify_cli_contract.v1.json")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {path:?}: {err}"))
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

fn cargo_target_dir_for_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_TARGET_DIR") {
        PathBuf::from(p)
    } else if let Ok(p) = std::env::var("CARGO_MANIFEST_DIR") {
        Path::new(&p)
            .parent()
            .and_then(Path::parent)
            .map(|root| root.join("target"))
            .unwrap_or_else(|| PathBuf::from("target"))
    } else {
        PathBuf::from("target")
    }
}

fn find_harness_binary() -> Option<PathBuf> {
    let root = cargo_target_dir_for_bin();
    for prof in ["debug", "release"] {
        let candidate = root.join(prof).join("harness");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn unique_tmp(stem: &str) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("bd_tzx36_{stem}_{}_{ts}.jsonl", std::process::id())))
}

fn write_file(path: &Path, contents: &str) -> TestResult {
    let mut f = std::fs::File::create(path).map_err(|e| format!("create {path:?}: {e}"))?;
    f.write_all(contents.as_bytes())
        .map_err(|e| format!("write {path:?}: {e}"))
}

fn write_jsonl_value(path: &Path, value: &Value) -> TestResult {
    let file = std::fs::File::create(path).map_err(|e| format!("create {path:?}: {e}"))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, value)
        .map_err(|e| format!("serialize jsonl value to {path:?}: {e}"))?;
    writer
        .write_all(b"\n")
        .map_err(|e| format!("terminate jsonl value in {path:?}: {e}"))
}

fn read_jsonl_records(path: &Path) -> TestResult<Vec<Value>> {
    let body = std::fs::read_to_string(path).map_err(|e| format!("read jsonl {path:?}: {e}"))?;
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(|e| format!("parse jsonl {path:?}: {e}")))
        .collect()
}

fn read_single_jsonl_record(path: &Path) -> TestResult<Value> {
    let mut records = read_jsonl_records(path)?;
    require(records.len() == 1, "expected exactly 1 JSONL record")?;
    records
        .pop()
        .ok_or_else(|| "expected one JSONL record".to_string())
}

fn well_formed_record() -> Value {
    serde_json::json!({
        "schema_version": "v1",
        "trace_class": "stdio.fread_small",
        "virtual_time_seed": 0xdeadbeef_u64,
        "schedule_decisions": ["W:0", "R:0", "W:1"],
        "replay_inputs": ["target/conformance/stdio_fread_small.input.jsonl"],
        "expected_outputs": ["target/conformance/stdio_fread_small.expected.jsonl"],
        "artifact_refs": [
            "target/conformance/stdio_fread_small.input.jsonl",
            "target/conformance/stdio_fread_small.expected.jsonl",
            "target/conformance/stdio_fread_small.observed.jsonl",
        ],
        "source_commit": "1".repeat(40),
    })
}

fn expected_outputs(record: &Value) -> TestResult<Value> {
    record
        .get("expected_outputs")
        .cloned()
        .ok_or_else(|| "well-formed replay record must include expected_outputs".to_string())
}

fn remove_object_field(record: &mut Value, field: &str) -> TestResult {
    record
        .as_object_mut()
        .ok_or_else(|| "well-formed replay record must be an object".to_string())?
        .remove(field);
    Ok(())
}

#[test]
fn manifest_anchors_to_tzx36_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "replay-classify-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-tzx36", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "replay-classify",
        "subcommand_name",
    )?;
    Ok(())
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for (field, message) in [
        (
            "must_emit_exactly_one_jsonl_record",
            "must_emit_exactly_one_jsonl_record must be true",
        ),
        (
            "fail_closed_when_input_record_missing_required_field",
            "fail_closed_when_input_record_missing_required_field must be true",
        ),
        (
            "fail_closed_when_observed_missing_observed_outputs",
            "fail_closed_when_observed_missing_observed_outputs must be true",
        ),
        (
            "outcome_must_be_one_of_enum",
            "outcome_must_be_one_of_enum must be true",
        ),
        (
            "tool_failure_when_asupersync_unavailable",
            "tool_failure_when_asupersync_unavailable must be true",
        ),
        (
            "code_failure_signature_must_be_non_empty",
            "code_failure_signature_must_be_non_empty must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_replay_classify_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("ReplayClassify {"),
        "harness.rs must declare ReplayClassify Command variant",
    )?;
    require(
        src.contains("asupersync_lab_replay::{")
            && src.contains("validate_replay")
            && src.contains("classify_outcome")
            && src.contains("detect_asupersync_available"),
        "main() must import validate_replay + classify_outcome + detect_asupersync_available",
    )?;
    require(
        src.contains("\"kind\": \"replay_outcome\""),
        "ReplayClassify arm must emit kind=replay_outcome",
    )
}

fn run_cli(
    bin: &Path,
    input: &Path,
    observed: &Path,
    output: &Path,
    override_var: Option<&str>,
) -> TestResult<std::process::Output> {
    let mut cmd = Command::new(bin);
    cmd.arg("replay-classify")
        .arg("--input")
        .arg(input)
        .arg("--observed")
        .arg(observed)
        .arg("--output")
        .arg(output);
    if let Some(v) = override_var {
        cmd.arg("--override-var").arg(v);
    }
    cmd.output().map_err(|e| format!("spawn: {e}"))
}

#[test]
fn cli_pass_when_observed_matches_expected_and_lab_available() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let input = unique_tmp("pass_record")?;
    let observed = unique_tmp("pass_observed")?;
    let output = unique_tmp("pass_output")?;
    let rec = well_formed_record();
    write_jsonl_value(&input, &rec)?;
    let observed_outputs = expected_outputs(&rec)?;
    let observed_json = serde_json::json!({ "observed_outputs": observed_outputs });
    write_jsonl_value(&observed, &observed_json)?;

    let out = run_cli(&bin, &input, &observed, &output, Some("1"))?;
    if !out.status.success() {
        return Err(format!(
            "replay-classify failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_single_jsonl_record(&output)?;
    require(
        json_string(&parsed, "kind")? == "replay_outcome",
        "kind must be replay_outcome",
    )?;
    require(
        json_string(&parsed, "outcome")? == "pass",
        "well-formed matching outputs + lab available must yield outcome=pass",
    )?;
    require(
        parsed.get("asupersync_available").and_then(Value::as_bool) == Some(true),
        "override_var=1 must produce asupersync_available=true",
    )?;
    require(
        json_string(&parsed, "detection_reason")? == "env_override_enabled",
        "override_var=1 must yield detection_reason=env_override_enabled",
    )
}

#[test]
fn cli_tool_failure_when_lab_unavailable() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let input = unique_tmp("tool_record")?;
    let observed = unique_tmp("tool_observed")?;
    let output = unique_tmp("tool_output")?;
    let rec = well_formed_record();
    write_jsonl_value(&input, &rec)?;
    let empty: Vec<&str> = Vec::new();
    let observed_json = serde_json::json!({ "observed_outputs": empty });
    write_jsonl_value(&observed, &observed_json)?;

    let out = run_cli(&bin, &input, &observed, &output, Some("0"))?;
    if !out.status.success() {
        return Err(format!(
            "replay-classify failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_single_jsonl_record(&output)?;
    require(
        json_string(&parsed, "outcome")? == "tool_failure",
        "override_var=0 must force tool_failure regardless of observed outputs",
    )?;
    require(
        !json_string(&parsed, "reason")?.is_empty(),
        "tool_failure must carry non-empty `reason`",
    )?;
    require(
        parsed.get("asupersync_available").and_then(Value::as_bool) == Some(false),
        "override_var=0 must produce asupersync_available=false",
    )
}

#[test]
fn cli_code_failure_when_observed_diverges_and_lab_available() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let input = unique_tmp("code_record")?;
    let observed = unique_tmp("code_observed")?;
    let output = unique_tmp("code_output")?;
    let rec = well_formed_record();
    write_jsonl_value(&input, &rec)?;
    // Drop the only expected output and add an unexpected one.
    let observed_json =
        serde_json::json!({ "observed_outputs": ["target/conformance/unexpected.jsonl"] });
    write_jsonl_value(&observed, &observed_json)?;

    let out = run_cli(&bin, &input, &observed, &output, Some("1"))?;
    if !out.status.success() {
        return Err(format!(
            "replay-classify failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_single_jsonl_record(&output)?;
    require(
        json_string(&parsed, "outcome")? == "code_failure",
        "divergent observed outputs + lab available must yield code_failure",
    )?;
    require(
        !json_string(&parsed, "signature")?.is_empty(),
        "code_failure must carry non-empty `signature`",
    )
}

#[test]
fn cli_fails_closed_on_input_record_missing_required_field() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let input = unique_tmp("bad_record")?;
    let observed = unique_tmp("bad_observed")?;
    let output = unique_tmp("bad_output")?;
    let mut rec = well_formed_record();
    remove_object_field(&mut rec, "trace_class")?;
    write_jsonl_value(&input, &rec)?;
    let empty: Vec<&str> = Vec::new();
    let observed_json = serde_json::json!({ "observed_outputs": empty });
    write_jsonl_value(&observed, &observed_json)?;

    let out = run_cli(&bin, &input, &observed, &output, Some("1"))?;
    require(
        !out.status.success(),
        "replay-classify must exit non-zero when input record is missing a required field",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("missing string field `trace_class`"),
        "stderr must name the missing field",
    )
}

#[test]
fn cli_fails_closed_when_observed_missing_observed_outputs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let input = unique_tmp("ok_record")?;
    let observed = unique_tmp("missing_observed")?;
    let output = unique_tmp("missing_output")?;
    let rec = well_formed_record();
    write_jsonl_value(&input, &rec)?;
    write_file(&observed, "{\"unrelated\": 1}\n")?;

    let out = run_cli(&bin, &input, &observed, &output, Some("1"))?;
    require(
        !out.status.success(),
        "replay-classify must exit non-zero when --observed is missing observed_outputs",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("observed_outputs"),
        "stderr must mention observed_outputs",
    )
}
