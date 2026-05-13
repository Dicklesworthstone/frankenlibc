//! Conformance gate for the harness binary `validate-runtime-evidence-rows`
//! subcommand (bd-7osqu).

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
        .join("validate_runtime_evidence_rows_cli_contract.v1.json")
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

fn json_u64(value: &Value, field: &str) -> TestResult<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing or non-u64 `{field}`"))
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
    if let Some(bin) = option_env!("CARGO_BIN_EXE_harness") {
        return Some(PathBuf::from(bin));
    }
    let root = cargo_target_dir_for_bin();
    for prof in ["debug", "release"] {
        let candidate = root.join(prof).join("harness");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn unique_tmp(stem: &str, ext: &str) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("bd_7osqu_{stem}_{}_{ts}.{ext}", std::process::id())))
}

fn write_jsonl(stem: &str, lines: &[&str]) -> TestResult<PathBuf> {
    let p = unique_tmp(stem, "jsonl")?;
    let body = lines.join("\n") + "\n";
    std::fs::write(&p, body).map_err(|e| format!("write {}: {e}", p.display()))?;
    Ok(p)
}

#[test]
fn manifest_anchors_to_7osqu_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "validate-runtime-evidence-rows-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-7osqu", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "validate-runtime-evidence-rows",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_membrane::runtime_math::evidence::validate_runtime_evidence_row_v1",
        "underlying_lib_function",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for f in [
        "must_emit_one_record_per_input_row_plus_summary",
        "summary_counts_match_per_row_aggregate",
        "valid_row_certified_with_null_error_kind",
        "missing_required_field_reports_field_name",
        "wrong_schema_value_reports_unexpected_value_on_schema",
        "wrong_type_reports_field_name",
        "empty_string_reports_field_name",
        "unparseable_jsonl_row_reports_json_parse_error",
        "deterministic_given_inputs",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_validate_runtime_evidence_rows_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("ValidateRuntimeEvidenceRows {"),
        "harness.rs must declare ValidateRuntimeEvidenceRows variant",
    )?;
    require(
        src.contains("evidence::validate_runtime_evidence_row_v1")
            || src.contains("validate_runtime_evidence_row_v1"),
        "match arm must import validate_runtime_evidence_row_v1",
    )?;
    require(
        src.contains("\"kind\": \"evidence_row_validation\"")
            && src.contains("\"kind\": \"evidence_row_validation_summary\""),
        "match arm must emit per-row + summary record kinds",
    )
}

fn run_cli(bin: &Path, jsonl: &Path, output: &Path) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("validate-runtime-evidence-rows")
        .arg("--jsonl")
        .arg(jsonl)
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn: {e}"))
}

fn read_records(out_path: &Path) -> TestResult<Vec<Value>> {
    let body = std::fs::read_to_string(out_path).map_err(|e| format!("read: {e}"))?;
    body.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(|e| format!("parse: {e}")))
        .collect()
}

const VALID_ROW: &str = r#"{"schema":"runtime_evidence.decision.v1","schema_version":1,"timestamp":"2026-05-13T00:00:00Z","trace_id":"abc-123","bead_id":"bd-7osqu","event":"runtime_evidence","mode":"strict","runtime_mode":"strict","validation_profile":"Full","decision_path":"membrane::handle","healing_action":"none","denied":false,"latency_ns":12345,"api_family":"file","symbol":"open","context":{"addr_hint_redacted":1024,"requested_bytes":256,"is_write":false,"bloom_negative":false,"contention_hint":0},"source_commit":"deadbeef","artifact_refs":["test"]}"#;

#[test]
fn cli_valid_row_certified() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let jsonl = write_jsonl("valid", &[VALID_ROW])?;
    let output = unique_tmp("valid", "jsonl")?;
    let out = run_cli(&bin, &jsonl, &output)?;
    let _ = std::fs::remove_file(&jsonl);
    if !out.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let recs = read_records(&output)?;
    let _ = std::fs::remove_file(&output);
    require(recs.len() == 2, "must emit row record + summary")?;
    require(
        json_bool(&recs[0], "valid")?,
        "valid row must be certified valid",
    )?;
    require(
        recs[0]
            .get("error_kind")
            .map(Value::is_null)
            .unwrap_or(false),
        "error_kind must be null on valid",
    )?;
    require(
        json_string(&recs[1], "kind")? == "evidence_row_validation_summary",
        "summary kind",
    )?;
    require(
        json_u64(&recs[1], "valid")? == 1
            && json_u64(&recs[1], "invalid")? == 0
            && json_u64(&recs[1], "total")? == 1,
        "summary counts",
    )
}

#[test]
fn cli_missing_required_field_reports_field() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    // Remove "bead_id" from the valid row to force a missing_required_field error.
    let mut row: serde_json::Value = serde_json::from_str(VALID_ROW).unwrap();
    row.as_object_mut().unwrap().remove("bead_id");
    let body = row.to_string();
    let jsonl = write_jsonl("missing", &[&body])?;
    let output = unique_tmp("missing", "jsonl")?;
    let out = run_cli(&bin, &jsonl, &output)?;
    let _ = std::fs::remove_file(&jsonl);
    if !out.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let recs = read_records(&output)?;
    let _ = std::fs::remove_file(&output);
    require(
        !json_bool(&recs[0], "valid")?,
        "row missing bead_id must be invalid",
    )?;
    require(
        json_string(&recs[0], "error_kind")? == "missing_required_field",
        "error_kind must be missing_required_field",
    )?;
    require(
        json_string(&recs[0], "error_field")? == "bead_id",
        "error_field must echo bead_id",
    )
}

#[test]
fn cli_wrong_schema_reports_unexpected_value() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let mut row: serde_json::Value = serde_json::from_str(VALID_ROW).unwrap();
    row["schema"] = serde_json::Value::String("wrong.schema.v1".to_string());
    let body = row.to_string();
    let jsonl = write_jsonl("schema", &[&body])?;
    let output = unique_tmp("schema", "jsonl")?;
    let out = run_cli(&bin, &jsonl, &output)?;
    let _ = std::fs::remove_file(&jsonl);
    if !out.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let recs = read_records(&output)?;
    let _ = std::fs::remove_file(&output);
    require(
        !json_bool(&recs[0], "valid")?,
        "wrong schema row must be invalid",
    )?;
    require(
        json_string(&recs[0], "error_kind")? == "unexpected_value",
        "error_kind must be unexpected_value",
    )?;
    require(
        json_string(&recs[0], "error_field")? == "schema",
        "error_field must echo schema",
    )
}

#[test]
fn cli_wrong_type_reports_field() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let mut row: serde_json::Value = serde_json::from_str(VALID_ROW).unwrap();
    row["denied"] = serde_json::Value::String("false".to_string());
    let body = row.to_string();
    let jsonl = write_jsonl("wrong_type", &[&body])?;
    let output = unique_tmp("wrong_type", "jsonl")?;
    let out = run_cli(&bin, &jsonl, &output)?;
    let _ = std::fs::remove_file(&jsonl);
    if !out.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let recs = read_records(&output)?;
    let _ = std::fs::remove_file(&output);
    require(
        !json_bool(&recs[0], "valid")?,
        "wrong-type denied field must be invalid",
    )?;
    require(
        json_string(&recs[0], "error_kind")? == "wrong_type",
        "error_kind must be wrong_type",
    )?;
    require(
        json_string(&recs[0], "error_field")? == "denied",
        "error_field must echo denied",
    )
}

#[test]
fn cli_empty_string_reports_field() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let mut row: serde_json::Value = serde_json::from_str(VALID_ROW).unwrap();
    row["source_commit"] = serde_json::Value::String(String::new());
    let body = row.to_string();
    let jsonl = write_jsonl("empty_string", &[&body])?;
    let output = unique_tmp("empty_string", "jsonl")?;
    let out = run_cli(&bin, &jsonl, &output)?;
    let _ = std::fs::remove_file(&jsonl);
    if !out.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let recs = read_records(&output)?;
    let _ = std::fs::remove_file(&output);
    require(
        !json_bool(&recs[0], "valid")?,
        "empty source_commit must be invalid",
    )?;
    require(
        json_string(&recs[0], "error_kind")? == "empty_string",
        "error_kind must be empty_string",
    )?;
    require(
        json_string(&recs[0], "error_field")? == "source_commit",
        "error_field must echo source_commit",
    )
}

#[test]
fn cli_unparseable_row_reports_json_parse_error() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let jsonl = write_jsonl("parse", &["not valid json"])?;
    let output = unique_tmp("parse", "jsonl")?;
    let out = run_cli(&bin, &jsonl, &output)?;
    let _ = std::fs::remove_file(&jsonl);
    if !out.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let recs = read_records(&output)?;
    let _ = std::fs::remove_file(&output);
    require(
        !json_bool(&recs[0], "valid")?,
        "unparseable row must be invalid",
    )?;
    require(
        json_string(&recs[0], "error_kind")? == "json_parse_error",
        "error_kind must be json_parse_error",
    )
}

#[test]
fn cli_summary_counts_match_per_row_aggregate() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    // Mix: 2 valid + 2 invalid + 1 parse error.
    let mut bad_field: serde_json::Value = serde_json::from_str(VALID_ROW).unwrap();
    bad_field.as_object_mut().unwrap().remove("bead_id");
    let mut bad_schema: serde_json::Value = serde_json::from_str(VALID_ROW).unwrap();
    bad_schema["schema"] = serde_json::Value::String("nope".to_string());
    let bad_field_str = bad_field.to_string();
    let bad_schema_str = bad_schema.to_string();
    let lines = [
        VALID_ROW,
        &bad_field_str,
        VALID_ROW,
        &bad_schema_str,
        "garbage",
    ];
    let jsonl = write_jsonl("mixed", &lines)?;
    let output = unique_tmp("mixed", "jsonl")?;
    let out = run_cli(&bin, &jsonl, &output)?;
    let _ = std::fs::remove_file(&jsonl);
    if !out.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let recs = read_records(&output)?;
    let _ = std::fs::remove_file(&output);
    require(recs.len() == 6, "must emit 5 row records + 1 summary")?;
    let mut valid = 0u64;
    let mut invalid = 0u64;
    for r in &recs[..5] {
        if json_bool(r, "valid")? {
            valid += 1;
        } else {
            invalid += 1;
        }
    }
    let summary = &recs[5];
    require(
        json_string(summary, "kind")? == "evidence_row_validation_summary",
        "summary kind",
    )?;
    require(
        json_u64(summary, "total")? == 5
            && json_u64(summary, "valid")? == valid
            && json_u64(summary, "invalid")? == invalid,
        format!(
            "summary counts: total={} valid={} invalid={} vs aggregate valid={valid} invalid={invalid}",
            json_u64(summary, "total")?,
            json_u64(summary, "valid")?,
            json_u64(summary, "invalid")?,
        ),
    )?;
    require(valid == 2 && invalid == 3, "expected 2 valid + 3 invalid")
}

#[test]
fn cli_deterministic_given_same_inputs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let jsonl = write_jsonl("det", &[VALID_ROW, "garbage"])?;
    let out_a = unique_tmp("det_a", "jsonl")?;
    let out_b = unique_tmp("det_b", "jsonl")?;
    let r_a = run_cli(&bin, &jsonl, &out_a)?;
    let r_b = run_cli(&bin, &jsonl, &out_b)?;
    let _ = std::fs::remove_file(&jsonl);
    require(
        r_a.status.success() && r_b.status.success(),
        "both runs must succeed",
    )?;
    let recs_a = read_records(&out_a)?;
    let recs_b = read_records(&out_b)?;
    let _ = std::fs::remove_file(&out_a);
    let _ = std::fs::remove_file(&out_b);
    require(
        recs_a == recs_b,
        "same inputs must produce identical output",
    )
}
