//! Conformance gate for the harness binary `replay-classify`
//! subcommand (bd-tzx36).

use std::io::Write;
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
    for f in [
        "must_emit_exactly_one_jsonl_record",
        "fail_closed_when_input_record_missing_required_field",
        "fail_closed_when_observed_missing_observed_outputs",
        "outcome_must_be_one_of_enum",
        "tool_failure_when_asupersync_unavailable",
        "code_failure_signature_must_be_non_empty",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
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
    write_file(&input, &format!("{rec}\n"))?;
    let observed_outputs = rec.get("expected_outputs").cloned().unwrap();
    let observed_json = serde_json::json!({ "observed_outputs": observed_outputs });
    write_file(&observed, &format!("{observed_json}\n"))?;

    let out = run_cli(&bin, &input, &observed, &output, Some("1"))?;
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&observed);
    if !out.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!(
            "replay-classify failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let body = std::fs::read_to_string(&output).map_err(|e| format!("read jsonl: {e}"))?;
    let _ = std::fs::remove_file(&output);
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    require(
        lines.len() == 1,
        format!("expected exactly 1 JSONL record; got {}", lines.len()),
    )?;
    let parsed: Value = serde_json::from_str(lines[0]).map_err(|e| format!("parse: {e}"))?;
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
    write_file(&input, &format!("{rec}\n"))?;
    let empty: Vec<&str> = Vec::new();
    let observed_json = serde_json::json!({ "observed_outputs": empty });
    write_file(&observed, &format!("{observed_json}\n"))?;

    let out = run_cli(&bin, &input, &observed, &output, Some("0"))?;
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&observed);
    if !out.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!(
            "replay-classify failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let body = std::fs::read_to_string(&output).map_err(|e| format!("read jsonl: {e}"))?;
    let _ = std::fs::remove_file(&output);
    let parsed: Value = serde_json::from_str(body.trim()).map_err(|e| format!("parse: {e}"))?;
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
    write_file(&input, &format!("{rec}\n"))?;
    // Drop the only expected output and add an unexpected one.
    let observed_json =
        serde_json::json!({ "observed_outputs": ["target/conformance/unexpected.jsonl"] });
    write_file(&observed, &format!("{observed_json}\n"))?;

    let out = run_cli(&bin, &input, &observed, &output, Some("1"))?;
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&observed);
    if !out.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!(
            "replay-classify failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let body = std::fs::read_to_string(&output).map_err(|e| format!("read jsonl: {e}"))?;
    let _ = std::fs::remove_file(&output);
    let parsed: Value = serde_json::from_str(body.trim()).map_err(|e| format!("parse: {e}"))?;
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
    rec.as_object_mut().unwrap().remove("trace_class");
    write_file(&input, &format!("{rec}\n"))?;
    let empty: Vec<&str> = Vec::new();
    let observed_json = serde_json::json!({ "observed_outputs": empty });
    write_file(&observed, &format!("{observed_json}\n"))?;

    let out = run_cli(&bin, &input, &observed, &output, Some("1"))?;
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&observed);
    let _ = std::fs::remove_file(&output);
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
    write_file(&input, &format!("{}\n", well_formed_record()))?;
    write_file(&observed, "{\"unrelated\": 1}\n")?;

    let out = run_cli(&bin, &input, &observed, &output, Some("1"))?;
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&observed);
    let _ = std::fs::remove_file(&output);
    require(
        !out.status.success(),
        "replay-classify must exit non-zero when --observed is missing observed_outputs",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("observed_outputs"),
        "stderr must mention observed_outputs",
    )
}
