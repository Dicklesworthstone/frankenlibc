//! Conformance gate for the harness binary `decision-trace-minimize`
//! subcommand (bd-9y4c2).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use frankenlibc_harness::decision_trace_minimizer::{
    MINIMIZED_TRACE_REQUIRED_FIELDS, parse_minimized_trace_jsonl,
};
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
        .join("decision_trace_minimize_cli_contract.v1.json")
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

fn trace_row_json(decision_path: &str, strict: &str, hardened: &str, input_class: &str) -> Value {
    serde_json::json!({
        "schema_version": "v1",
        "scenario": "cli-smoke",
        "api_family": "stdio",
        "symbol": "fread",
        "decision_path": decision_path,
        "input_class": input_class,
        "mode_strict_decision": strict,
        "mode_hardened_decision": hardened,
        "source_commit": "abc1234567890abc1234567890abc1234567890a",
        "artifact_refs": ["target/conformance/replay.log.jsonl"],
    })
}

#[test]
fn manifest_anchors_to_9y4c2_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "decision-trace-minimize-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-9y4c2", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "decision-trace-minimize",
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
        "fail_closed_when_input_row_missing_required_field",
        "fail_closed_when_input_is_empty",
        "must_emit_exactly_one_output_jsonl_record",
        "output_must_round_trip_through_parse_minimized_trace_jsonl",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_decision_trace_minimize_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("DecisionTraceMinimize {"),
        "harness.rs must declare DecisionTraceMinimize Command variant",
    )?;
    require(
        src.contains("decision_trace_minimizer::{")
            && src.contains("minimize, serialize_minimized_trace_jsonl"),
        "main() must import minimize + serialize_minimized_trace_jsonl",
    )
}

fn write_jsonl(path: &Path, rows: &[Value]) -> TestResult {
    let mut f = std::fs::File::create(path).map_err(|e| format!("create temp: {e}"))?;
    for r in rows {
        writeln!(f, "{r}").map_err(|e| format!("write row: {e}"))?;
    }
    Ok(())
}

#[test]
fn cli_emits_round_trippable_minimized_trace_for_divergent_input() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    let input = std::env::temp_dir().join(format!("bd_9y4c2_in_{ts}.jsonl"));
    let output = std::env::temp_dir().join(format!("bd_9y4c2_out_{ts}.jsonl"));

    // Two rows with the same fingerprint key minus input_class:
    // the second has divergent strict/hardened decisions.
    let rows = vec![
        trace_row_json("fast", "Allow", "Allow", "typical"),
        trace_row_json("slow", "Allow", "Repair", "adversarial"),
    ];
    write_jsonl(&input, &rows)?;

    let out = Command::new(&bin)
        .arg("decision-trace-minimize")
        .arg("--input")
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    let _ = std::fs::remove_file(&input);
    if !out.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!(
            "decision-trace-minimize failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let body = std::fs::read_to_string(&output).map_err(|e| format!("read jsonl: {e}"))?;
    let _ = std::fs::remove_file(&output);
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    require(
        lines.len() == 1,
        format!("expected exactly 1 output record; got {}", lines.len()),
    )?;
    let parsed: Value = serde_json::from_str(lines[0]).map_err(|e| format!("parse output: {e}"))?;
    for f in MINIMIZED_TRACE_REQUIRED_FIELDS {
        require(
            parsed.get(*f).is_some(),
            format!("output record missing required field `{f}`"),
        )?;
    }
    // Round-trip back through the lib parser.
    let summary = parse_minimized_trace_jsonl(lines[0])
        .map_err(|e| format!("parse_minimized_trace_jsonl: {e}"))?;
    require(
        summary.has_divergence,
        "divergent input must produce has_divergence=true",
    )?;
    require(
        summary.minimized_rows_len >= 1,
        "minimized_rows_len must be >= 1",
    )?;
    require(
        !summary.expected_failure_signature.is_empty(),
        "expected_failure_signature must be non-empty for divergent input",
    )
}

#[test]
fn cli_rejects_empty_input() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    let input = std::env::temp_dir().join(format!("bd_9y4c2_empty_{ts}.jsonl"));
    let output = std::env::temp_dir().join(format!("bd_9y4c2_empty_out_{ts}.jsonl"));
    std::fs::write(&input, "").map_err(|e| format!("write: {e}"))?;
    let out = Command::new(&bin)
        .arg("decision-trace-minimize")
        .arg("--input")
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    require(
        !out.status.success(),
        "decision-trace-minimize must exit non-zero on empty input",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("zero TraceRow records"),
        "decision-trace-minimize must surface 'zero TraceRow records' on empty input",
    )
}

#[test]
fn cli_rejects_input_row_missing_required_field() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    let input = std::env::temp_dir().join(format!("bd_9y4c2_bad_{ts}.jsonl"));
    let output = std::env::temp_dir().join(format!("bd_9y4c2_bad_out_{ts}.jsonl"));
    // Missing `symbol` field.
    let bad = serde_json::json!({
        "schema_version": "v1",
        "scenario": "x",
        "api_family": "x",
        "decision_path": "x",
        "input_class": "x",
        "mode_strict_decision": "Allow",
        "mode_hardened_decision": "Allow",
        "source_commit": "abc1234567890abc1234567890abc1234567890a",
        "artifact_refs": [],
    });
    write_jsonl(&input, &[bad])?;
    let out = Command::new(&bin)
        .arg("decision-trace-minimize")
        .arg("--input")
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    require(
        !out.status.success(),
        "decision-trace-minimize must exit non-zero on missing field",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("missing string field `symbol`"),
        "decision-trace-minimize must name the missing field in the error",
    )
}
