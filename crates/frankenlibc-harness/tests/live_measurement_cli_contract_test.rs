//! Conformance gate for the harness binary `live-measurement`
//! subcommand (bd-uof80).
//!
//! Pins:
//! 1. Manifest anchors and policy invariants.
//! 2. The harness binary source registers the LiveMeasurement
//!    subcommand variant with the documented flag set.
//! 3. End-to-end: invokes the compiled binary via cargo run and
//!    asserts the emitted JSONL carries 3 records in the documented
//!    order with the documented field schema.

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
        .join("live_measurement_cli_contract.v1.json")
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

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing or non-array `{field}`"))
}

fn parse_jsonl_records(body: &str) -> TestResult<Vec<Value>> {
    let mut records = Vec::new();
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        let record = match serde_json::from_str(line) {
            Ok(record) => record,
            Err(_) => return Err("parse jsonl record".into()),
        };
        records.push(record);
    }
    Ok(records)
}

fn record_at(records: &[Value], index: usize) -> TestResult<&Value> {
    records
        .get(index)
        .ok_or_else(|| "missing JSONL record".to_string())
}

#[test]
fn manifest_anchors_to_uof80_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "live-measurement-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-uof80", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "live-measurement",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "binary_target")? == "harness",
        "binary_target",
    )?;
    require(
        json_string(&m, "underlying_bridge_function")?
            == "frankenlibc_harness::read_mostly_fast_path_prototype::run_live_measurement_pair_with_p99_delta",
        "underlying_bridge_function",
    )?;
    require(
        json_string(&m, "underlying_default_fingerprint_function")?
            == "frankenlibc_harness::read_mostly_fast_path_prototype::run_live_measurement_pair_with_p99_delta_and_detected_fingerprint",
        "underlying_default_fingerprint_function",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m.get("policy").ok_or("missing policy")?;
    for (field, message) in [
        (
            "fail_closed_when_source_commit_is_not_40_char_sha",
            "fail_closed_when_source_commit_is_not_40_char_sha must be true",
        ),
        (
            "fail_closed_when_underlying_bridge_errors",
            "fail_closed_when_underlying_bridge_errors must be true",
        ),
        (
            "must_emit_three_jsonl_records_in_fixed_order",
            "must_emit_three_jsonl_records_in_fixed_order must be true",
        ),
        (
            "default_path_must_route_through_environment_fingerprint",
            "default_path_must_route_through_environment_fingerprint must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_live_measurement_subcommand_with_documented_flags() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("LiveMeasurement {"),
        "harness.rs must declare the LiveMeasurement Command variant",
    )?;
    // The Cli macro derives flag names from field idents. Confirm
    // each flag's underlying field name is present.
    for anchor in [
        "        profile_id",
        "        n",
        "        seed",
        "        source_commit",
        "        output",
        "        environment_fingerprint",
    ] {
        require(
            src.contains(anchor),
            "LiveMeasurement variant missing field",
        )?;
    }
    require(
        src.contains("run_live_measurement_pair_with_p99_delta")
            && src.contains("run_live_measurement_pair_with_p99_delta_and_detected_fingerprint"),
        "main() arm must call both bridge variants (default-fp vs explicit-fp)",
    )
}

fn cargo_target_dir_for_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_TARGET_DIR") {
        PathBuf::from(p)
    } else if let Ok(p) = std::env::var("CARGO_MANIFEST_DIR") {
        // Fall back to the workspace `target/` next to the manifest dir.
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

#[test]
fn cli_emits_three_jsonl_records_in_documented_order() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;

    // The CI lane builds the binary via `cargo test`; if it's
    // not present here we skip rather than fail (the source-anchor
    // test above already protects the contract).
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };

    // Per-process scratch path so concurrent runs don't collide.
    let tmp = std::env::temp_dir().join(format!(
        "bd_uof80_cli_{}_{}.jsonl",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("clock: {e}"))?
            .as_nanos()
    ));

    let source_commit = "0".repeat(40);
    let pinned_fp = "linux-x86_64-cli-test";
    let output = Command::new(&bin)
        .arg("live-measurement")
        .arg("--profile-id")
        .arg("bd-uof80-cli")
        .arg("--n")
        .arg("5000")
        .arg("--seed")
        .arg("12345")
        .arg("--source-commit")
        .arg(&source_commit)
        .arg("--environment-fingerprint")
        .arg(pinned_fp)
        .arg("--output")
        .arg(&tmp)
        .output()
        .map_err(|e| format!("spawn harness: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "live-measurement subcommand failed: status={:?} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let body = std::fs::read_to_string(&tmp).map_err(|e| format!("read jsonl: {e}"))?;
    let parsed = parse_jsonl_records(&body)?;
    require(parsed.len() == 3, "expected exactly 3 JSONL records")?;
    let record0 = record_at(&parsed, 0)?;
    let record1 = record_at(&parsed, 1)?;
    let record2 = record_at(&parsed, 2)?;

    let contract = m
        .get("jsonl_output_contract")
        .ok_or_else(|| "missing jsonl_output_contract".to_string())?;
    let row_kind = json_string(contract, "row_kind_marker")?;
    let delta_kind = json_string(contract, "delta_kind_marker")?;

    require(
        json_string(record0, "kind")? == row_kind
            && record0.get("lane_id").and_then(Value::as_str) == Some("Conservative"),
        "record 0 must be conservative LiveMeasurementRow",
    )?;
    require(
        json_string(record1, "kind")? == row_kind
            && record1.get("lane_id").and_then(Value::as_str) == Some("Seqlock"),
        "record 1 must be seqlock LiveMeasurementRow",
    )?;
    require(
        json_string(record2, "kind")? == delta_kind,
        "record 2 must be P99Delta",
    )?;

    for f in json_array(contract, "row_required_fields")?
        .iter()
        .filter_map(Value::as_str)
    {
        require(record0.get(f).is_some(), "row 0 missing required field")?;
        require(record1.get(f).is_some(), "row 1 missing required field")?;
    }
    for f in json_array(contract, "delta_required_fields")?
        .iter()
        .filter_map(Value::as_str)
    {
        require(
            record2.get(f).is_some(),
            "delta record missing required field",
        )?;
    }

    // The --environment-fingerprint flag must propagate through to
    // both rows (this is the explicit-fp path).
    require(
        record0
            .get("environment_fingerprint")
            .and_then(Value::as_str)
            == Some(pinned_fp),
        "row 0 environment_fingerprint must equal CLI flag value",
    )?;
    require(
        record1
            .get("environment_fingerprint")
            .and_then(Value::as_str)
            == Some(pinned_fp),
        "row 1 environment_fingerprint must equal CLI flag value",
    )?;
    // source_commit must propagate verbatim.
    require(
        record0.get("source_commit").and_then(Value::as_str) == Some(source_commit.as_str()),
        "row 0 source_commit must equal CLI flag value",
    )
}

#[test]
fn cli_rejects_bad_source_commit_before_running_lanes() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let tmp =
        std::env::temp_dir().join(format!("bd_uof80_cli_bad_sha_{}.jsonl", std::process::id()));
    let output = Command::new(&bin)
        .arg("live-measurement")
        .arg("--profile-id")
        .arg("bad-sha")
        .arg("--n")
        .arg("5000")
        .arg("--seed")
        .arg("1")
        .arg("--source-commit")
        .arg("not-a-sha")
        .arg("--output")
        .arg(&tmp)
        .output()
        .map_err(|e| format!("spawn harness: {e}"))?;
    require(
        !output.status.success(),
        "live-measurement must exit non-zero on bad --source-commit",
    )?;
    require(
        String::from_utf8_lossy(&output.stderr).contains("40-char ascii-hex SHA"),
        "live-measurement must surface the 40-char SHA requirement on bad --source-commit",
    )
}
