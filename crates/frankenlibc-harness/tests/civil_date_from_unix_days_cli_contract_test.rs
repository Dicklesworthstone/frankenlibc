//! Conformance gate for the harness binary `civil-date-from-unix-days`
//! subcommand (bd-9ws64).

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
        .join("civil_date_from_unix_days_cli_contract.v1.json")
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

fn json_i64(value: &Value, field: &str) -> TestResult<i64> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("missing or non-i64 `{field}`"))
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

fn unique_tmp(stem: &str) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!(
        "bd_9ws64_{stem}_{}_{ts}.jsonl",
        std::process::id()
    )))
}

fn run_cli(bin: &Path, unix_days: i64, output: &Path) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("civil-date-from-unix-days")
        .arg(format!("--unix-days={unix_days}"))
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn: {e}"))
}

fn read_record(out_path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(out_path).map_err(|e| format!("read: {e}"))?;
    serde_json::from_str(body.trim()).map_err(|e| format!("parse: {e}"))
}

fn run_and_parse(bin: &Path, unix_days: i64, label: &str) -> TestResult<Value> {
    let output = unique_tmp(label)?;
    let out = run_cli(bin, unix_days, &output)?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = read_record(&output)?;
    let _ = std::fs::remove_file(&output);
    Ok(parsed)
}

#[test]
fn manifest_anchors_to_9ws64_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "civil-date-from-unix-days-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-9ws64", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "civil-date-from-unix-days",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_membrane::util::civil_date_from_unix_days",
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
        "echoes_unix_days_into_output_record",
        "deterministic_given_inputs",
        "day_zero_is_1970_01_01_unix_epoch",
        "day_minus_one_is_1969_12_31",
        "first_post_epoch_leap_day_unix_789_is_1972_02_29",
        "y2k_leap_day_unix_11016_is_2000_02_29",
        "y2038_boundary_unix_24855_is_2038_01_19",
        "year_month_day_match_expected_anchor_table",
        "month_is_in_1_through_12",
        "day_is_in_1_through_31",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_civil_date_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("CivilDateFromUnixDays {"),
        "harness.rs must declare CivilDateFromUnixDays variant",
    )?;
    require(
        src.contains("util::civil_date_from_unix_days")
            || src.contains("civil_date_from_unix_days"),
        "match arm must import civil_date_from_unix_days",
    )?;
    require(
        src.contains("\"kind\": \"civil_date\""),
        "CivilDateFromUnixDays arm must emit kind=civil_date",
    )
}

#[test]
fn cli_anchor_table_matches_manifest() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let anchors = manifest
        .get("expected_anchor_table")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing expected_anchor_table".to_string())?;
    require(
        anchors.len() >= 11,
        format!("expected at least 11 anchors, got {}", anchors.len()),
    )?;
    for anchor in anchors {
        let unix_days = json_i64(anchor, "unix_days")?;
        let parsed = run_and_parse(&bin, unix_days, &format!("anchor_{unix_days}"))?;
        require(
            json_string(&parsed, "kind")? == "civil_date",
            "kind must be civil_date",
        )?;
        require(
            json_i64(&parsed, "unix_days")? == unix_days,
            format!("unix_days must echo {unix_days}"),
        )?;
        require(
            json_i64(&parsed, "year")? == json_i64(anchor, "year")?,
            format!("year mismatch for unix_days={unix_days}"),
        )?;
        require(
            json_u64(&parsed, "month")? == json_u64(anchor, "month")?,
            format!("month mismatch for unix_days={unix_days}"),
        )?;
        require(
            json_u64(&parsed, "day")? == json_u64(anchor, "day")?,
            format!("day mismatch for unix_days={unix_days}"),
        )?;
    }
    Ok(())
}

#[test]
fn cli_pins_unix_epoch_and_negative_day() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let epoch = run_and_parse(&bin, 0, "epoch")?;
    require(
        json_i64(&epoch, "year")? == 1970
            && json_u64(&epoch, "month")? == 1
            && json_u64(&epoch, "day")? == 1,
        "unix day 0 must be 1970-01-01",
    )?;
    let previous = run_and_parse(&bin, -1, "negative")?;
    require(
        json_i64(&previous, "year")? == 1969
            && json_u64(&previous, "month")? == 12
            && json_u64(&previous, "day")? == 31,
        "unix day -1 must be 1969-12-31",
    )
}

#[test]
fn cli_pins_leap_days_and_y2038_boundary() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    for (unix_days, year, month, day) in [
        (789, 1972, 2, 29),
        (11_016, 2000, 2, 29),
        (24_855, 2038, 1, 19),
    ] {
        let parsed = run_and_parse(&bin, unix_days, &format!("special_{unix_days}"))?;
        require(
            json_i64(&parsed, "year")? == year
                && json_u64(&parsed, "month")? == month
                && json_u64(&parsed, "day")? == day,
            format!("unix day {unix_days} must be {year:04}-{month:02}-{day:02}"),
        )?;
    }
    Ok(())
}

#[test]
fn cli_month_and_day_stay_in_civil_ranges() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    for unix_days in [-146_097, -36_525, -365, -1, 0, 365, 11_016, 20_586, 24_855, 146_097] {
        let parsed = run_and_parse(&bin, unix_days, &format!("range_{unix_days}"))?;
        let month = json_u64(&parsed, "month")?;
        let day = json_u64(&parsed, "day")?;
        require(
            (1..=12).contains(&month),
            format!("month out of range for unix_days={unix_days}: {month}"),
        )?;
        require(
            (1..=31).contains(&day),
            format!("day out of range for unix_days={unix_days}: {day}"),
        )?;
    }
    Ok(())
}

#[test]
fn cli_deterministic_given_same_inputs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let a = run_and_parse(&bin, 20_586, "det_a")?;
    let b = run_and_parse(&bin, 20_586, "det_b")?;
    require(a == b, "same unix_days must produce identical output")
}
