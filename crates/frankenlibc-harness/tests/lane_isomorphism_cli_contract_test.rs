//! Conformance gate for the harness binary `lane-isomorphism`
//! subcommand (bd-r0315).

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
        .join("lane_isomorphism_cli_contract.v1.json")
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

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing or non-array `{field}`"))
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
    Ok(std::env::temp_dir().join(format!("bd_r0315_{stem}_{}_{ts}.jsonl", std::process::id())))
}

fn read_record(out_path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(out_path).map_err(|e| format!("read jsonl: {e}"))?;
    let records: Vec<&str> = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    require(
        records.len() == 1,
        format!(
            "{} must contain exactly one JSONL record, found {}",
            out_path.display(),
            records.len()
        ),
    )?;
    let record = records
        .first()
        .ok_or_else(|| "missing JSONL record after record-count check".to_string())?;
    serde_json::from_str(record).map_err(|e| format!("parse jsonl: {e}"))
}

#[test]
fn manifest_anchors_to_r0315_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "lane-isomorphism-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-r0315", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "lane-isomorphism",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_harness::read_mostly_fast_path_prototype::isomorphism_witness",
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
        "must_emit_exactly_one_jsonl_record",
        "outcomes_identical_must_be_true_for_well_formed_inputs",
        "conservative_outcome_length_must_equal_writes_times_reads_per_phase",
        "seqlock_outcome_length_must_equal_writes_times_reads_per_phase",
        "fail_closed_on_empty_writes",
        "fail_closed_on_zero_reads_per_phase",
        "writes_array_in_output_must_echo_parsed_input",
    ] {
        require(json_bool(policy, f)?, "policy invariant must be true")?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_lane_isomorphism_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("LaneIsomorphism {"),
        "harness.rs must declare LaneIsomorphism Command variant",
    )?;
    require(
        src.contains("read_mostly_fast_path_prototype::isomorphism_witness"),
        "main() must import read_mostly_fast_path_prototype::isomorphism_witness",
    )?;
    require(
        src.contains("\"kind\": \"isomorphism_report\""),
        "LaneIsomorphism arm must emit kind=isomorphism_report",
    )
}

#[test]
fn cli_emits_one_record_with_identical_outcomes_and_expected_lengths() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let tmp = unique_tmp("ok")?;
    let out = Command::new(&bin)
        .arg("lane-isomorphism")
        .arg("--initial")
        .arg("17")
        .arg("--writes")
        .arg("1,2,3,4,5,6,7")
        .arg("--reads-per-phase")
        .arg("3")
        .arg("--output")
        .arg(&tmp)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "lane-isomorphism failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_record(&tmp)?;
    require(
        json_string(&parsed, "kind")? == "isomorphism_report",
        "kind must be isomorphism_report",
    )?;
    require(
        json_u64(&parsed, "initial")? == 17,
        "initial must round-trip",
    )?;
    require(
        json_u64(&parsed, "reads_per_phase")? == 3,
        "reads_per_phase must round-trip",
    )?;
    let echoed = json_array(&parsed, "writes")?;
    require(
        echoed
            .iter()
            .filter_map(Value::as_u64)
            .collect::<Vec<u64>>()
            == vec![1, 2, 3, 4, 5, 6, 7],
        "writes array must echo the parsed input",
    )?;
    let cons = json_array(&parsed, "conservative_outcomes")?;
    let seq = json_array(&parsed, "seqlock_outcomes")?;
    require(
        cons.len() == 7 * 3 && seq.len() == 7 * 3,
        format!(
            "outcome length must equal writes×reads_per_phase (21); got cons={} seq={}",
            cons.len(),
            seq.len()
        ),
    )?;
    require(
        parsed.get("outcomes_identical").and_then(Value::as_bool) == Some(true),
        "well-formed inputs must produce outcomes_identical=true",
    )
}

#[test]
fn cli_fails_closed_on_empty_writes() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let tmp = unique_tmp("empty")?;
    let out = Command::new(&bin)
        .arg("lane-isomorphism")
        .arg("--writes")
        .arg("")
        .arg("--reads-per-phase")
        .arg("4")
        .arg("--output")
        .arg(&tmp)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    require(
        !out.status.success(),
        "lane-isomorphism must exit non-zero on empty --writes",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("at least one u32 token"),
        "stderr must explain that --writes requires at least one token",
    )
}

#[test]
fn cli_fails_closed_on_zero_reads_per_phase() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let tmp = unique_tmp("zero_reads")?;
    let out = Command::new(&bin)
        .arg("lane-isomorphism")
        .arg("--writes")
        .arg("1,2,3")
        .arg("--reads-per-phase")
        .arg("0")
        .arg("--output")
        .arg(&tmp)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    require(
        !out.status.success(),
        "lane-isomorphism must exit non-zero on --reads-per-phase=0",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("--reads-per-phase must be > 0"),
        "stderr must explain why --reads-per-phase=0 is rejected",
    )
}

#[test]
fn cli_fails_closed_on_non_u32_write_token() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let tmp = unique_tmp("bad_token")?;
    let out = Command::new(&bin)
        .arg("lane-isomorphism")
        .arg("--writes")
        .arg("1,not-a-number,3")
        .arg("--reads-per-phase")
        .arg("2")
        .arg("--output")
        .arg(&tmp)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    require(
        !out.status.success(),
        "lane-isomorphism must exit non-zero on non-u32 --writes token",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("non-u32 token `not-a-number`"),
        "stderr must name the offending --writes token",
    )
}
