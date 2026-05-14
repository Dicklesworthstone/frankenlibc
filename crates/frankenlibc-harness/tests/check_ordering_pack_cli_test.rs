//! Contract gate for the harness `pack-check-ordering` subcommand (bd-6x28i).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const DEFAULT_STAGE_ARGS: [&str; 7] = [
    "null",
    "tls-cache",
    "bloom",
    "arena",
    "fingerprint",
    "canary",
    "bounds",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn harness_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_harness"))
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

fn json_string_array(value: &Value, field: &str) -> TestResult<Vec<String>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing or non-array `{field}`"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("non-string entry in `{field}`"))
        })
        .collect()
}

fn run_pack(stage_args: &[&str]) -> TestResult<Output> {
    let mut cmd = Command::new(harness_bin());
    cmd.arg("pack-check-ordering");
    for stage_arg in stage_args {
        cmd.arg("--stage").arg(stage_arg);
    }
    cmd.output().map_err(|err| format!("spawn harness: {err}"))
}

fn parse_single_stdout_record(output: &Output) -> TestResult<Value> {
    if !output.status.success() {
        return Err(format!(
            "pack-check-ordering failed: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    require(
        output.stderr.is_empty(),
        format!(
            "pack-check-ordering should not emit stderr on success; got {}",
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    match lines.as_slice() {
        [record] => {
            serde_json::from_str(record).map_err(|err| format!("parse stdout JSONL: {err}"))
        }
        _ => Err(format!(
            "expected exactly one JSONL record; got {}",
            lines.len()
        )),
    }
}

#[test]
fn harness_source_registers_pack_check_ordering_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|err| format!("read harness.rs: {err}"))?;
    for needle in [
        "PackCheckOrdering {",
        "pack_ordering",
        "unpack_ordering",
        "\"kind\": \"check_ordering_pack\"",
    ] {
        require(
            src.contains(needle),
            format!("missing source anchor {needle}"),
        )?;
    }
    Ok(())
}

#[test]
fn default_order_repeated_flags_pins_packed_value() -> TestResult {
    let record = parse_single_stdout_record(&run_pack(&DEFAULT_STAGE_ARGS)?)?;
    require(
        json_string(&record, "kind")? == "check_ordering_pack",
        "kind must be check_ordering_pack",
    )?;
    require(
        json_string_array(&record, "stages")? == DEFAULT_STAGE_ARGS,
        "stages must preserve the requested order",
    )?;
    require(
        json_u64(&record, "packed_u64")? == 106_181_136,
        "default order should pack to decimal 106181136",
    )?;
    require(
        json_string(&record, "packed_hex")? == "0x0000000006543210",
        "default order should pack to 0x0000000006543210",
    )?;
    require(
        json_string_array(&record, "unpacked_round_trip")? == DEFAULT_STAGE_ARGS,
        "unpacked round-trip must match default order",
    )?;
    require(json_bool(&record, "round_trip_ok")?, "round_trip_ok")
}

#[test]
fn comma_separated_default_order_matches_repeated_flags() -> TestResult {
    let repeated = parse_single_stdout_record(&run_pack(&DEFAULT_STAGE_ARGS)?)?;
    let comma = parse_single_stdout_record(&run_pack(&[
        "null,tls-cache,bloom,arena,fingerprint,canary,bounds",
    ])?)?;
    require(
        json_u64(&comma, "packed_u64")? == json_u64(&repeated, "packed_u64")?,
        "comma-separated and repeated forms must pack identically",
    )?;
    require(
        json_string_array(&comma, "stages")? == DEFAULT_STAGE_ARGS,
        "comma-separated form must parse canonical stage names",
    )
}

#[test]
fn non_default_permutation_round_trips() -> TestResult {
    let requested = [
        "bounds",
        "canary",
        "fingerprint",
        "arena",
        "bloom",
        "tls-cache",
        "null",
    ];
    let record = parse_single_stdout_record(&run_pack(&requested)?)?;
    require(
        json_string_array(&record, "stages")? == requested,
        "stages must preserve non-default permutation",
    )?;
    require(
        json_string_array(&record, "unpacked_round_trip")? == requested,
        "unpacked_round_trip must match non-default permutation",
    )?;
    require(json_bool(&record, "round_trip_ok")?, "round_trip_ok")
}

#[test]
fn unknown_stage_name_fails_closed() -> TestResult {
    let output = run_pack(&[
        "null",
        "tls-cache",
        "bloom",
        "arena",
        "fingerprint",
        "canary",
        "bogus",
    ])?;
    require(!output.status.success(), "unknown stage must exit non-zero")?;
    require(
        String::from_utf8_lossy(&output.stderr).contains("unknown check stage"),
        "stderr must explain unknown check stage",
    )
}

#[test]
fn wrong_length_sequence_fails_closed() -> TestResult {
    let output = run_pack(&["null,tls-cache,bloom,arena,fingerprint,canary"])?;
    require(!output.status.success(), "wrong length must exit non-zero")?;
    require(
        String::from_utf8_lossy(&output.stderr).contains("requires exactly 7 stages"),
        "stderr must explain required stage count",
    )
}

#[test]
fn duplicate_stage_sequence_fails_closed() -> TestResult {
    let output = run_pack(&[
        "null",
        "null",
        "bloom",
        "arena",
        "fingerprint",
        "canary",
        "bounds",
    ])?;
    require(
        !output.status.success(),
        "duplicate stage must exit non-zero",
    )?;
    require(
        String::from_utf8_lossy(&output.stderr).contains("duplicate check stage"),
        "stderr must explain duplicate stage",
    )
}
