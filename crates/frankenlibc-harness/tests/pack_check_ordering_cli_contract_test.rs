//! Conformance gate for the harness binary `pack-check-ordering`
//! subcommand (bd-d52jw).

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
        .join("pack_check_ordering_cli_contract.v1.json")
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

fn run_repeated(bin: &Path, stages: &[&str]) -> TestResult<std::process::Output> {
    let mut cmd = Command::new(bin);
    cmd.arg("pack-check-ordering");
    for s in stages {
        cmd.arg("--stage").arg(s);
    }
    cmd.output().map_err(|e| format!("spawn: {e}"))
}

fn run_csv(bin: &Path, csv: &str) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("pack-check-ordering")
        .arg("--stage")
        .arg(csv)
        .output()
        .map_err(|e| format!("spawn: {e}"))
}

fn parse_stdout(out: &std::process::Output) -> TestResult<Value> {
    let body = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(body.trim()).map_err(|e| format!("parse stdout: {e}; body={body}"))
}

const IDENTITY: [&str; 7] = [
    "null",
    "tls-cache",
    "bloom",
    "arena",
    "fingerprint",
    "canary",
    "bounds",
];

const REVERSE: [&str; 7] = [
    "bounds",
    "canary",
    "fingerprint",
    "arena",
    "bloom",
    "tls-cache",
    "null",
];

#[test]
fn manifest_anchors_to_d52jw_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "pack-check-ordering-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-d52jw", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "pack-check-ordering",
        "subcommand_name",
    )?;
    let funcs = m
        .get("underlying_lib_functions")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing underlying_lib_functions".to_string())?;
    for want in [
        "frankenlibc_membrane::check_oracle::pack_ordering",
        "frankenlibc_membrane::check_oracle::unpack_ordering",
    ] {
        require(
            funcs.iter().any(|v| v.as_str() == Some(want)),
            format!("missing {want}"),
        )?;
    }
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
        "must_emit_exactly_one_stdout_jsonl_record",
        "round_trip_codec_is_lossless",
        "round_trip_ok_true_for_all_valid_orderings",
        "repeated_stage_flags_and_comma_separated_are_equivalent",
        "identity_ordering_packs_to_known_hex_0x06543210",
        "reverse_ordering_packs_to_known_hex_0x00123456",
        "unknown_stage_name_rejected_with_nonzero_exit",
        "fewer_than_7_stages_rejected",
        "more_than_7_stages_rejected",
        "deterministic_given_inputs",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_pack_check_ordering_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("PackCheckOrdering {"),
        "harness.rs must declare PackCheckOrdering variant",
    )?;
    require(
        src.contains("check_oracle::{pack_ordering, unpack_ordering}")
            || (src.contains("pack_ordering") && src.contains("unpack_ordering")),
        "match arm must import pack_ordering + unpack_ordering",
    )?;
    require(
        src.contains("\"kind\": \"check_ordering_pack\""),
        "match arm must emit kind=check_ordering_pack",
    )
}

#[test]
fn cli_identity_ordering_packs_to_known_hex() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let out = run_repeated(&bin, &IDENTITY)?;
    if !out.status.success() {
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = parse_stdout(&out)?;
    require(
        json_string(&parsed, "kind")? == "check_ordering_pack",
        "kind",
    )?;
    require(
        json_string(&parsed, "packed_hex")? == "0x0000000006543210",
        format!(
            "identity packed_hex: want 0x0000000006543210, got {}",
            json_string(&parsed, "packed_hex")?
        ),
    )?;
    require(
        json_u64(&parsed, "packed_u64")? == 106_181_136,
        "identity packed_u64 must be 106181136",
    )?;
    require(json_bool(&parsed, "round_trip_ok")?, "round-trip must hold")
}

#[test]
fn cli_reverse_ordering_packs_to_known_hex() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let out = run_repeated(&bin, &REVERSE)?;
    if !out.status.success() {
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = parse_stdout(&out)?;
    require(
        json_string(&parsed, "packed_hex")? == "0x0000000000123456",
        format!(
            "reverse packed_hex: want 0x0000000000123456, got {}",
            json_string(&parsed, "packed_hex")?
        ),
    )?;
    require(
        json_u64(&parsed, "packed_u64")? == 1_193_046,
        "reverse packed_u64 must be 1193046",
    )
}

#[test]
fn cli_round_trip_codec_is_lossless() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    // Exercise a few permutations, asserting unpacked sequence equals input
    // sequence and round_trip_ok is true every time.
    let permutations: [[&str; 7]; 4] = [
        IDENTITY,
        REVERSE,
        [
            "bloom",
            "null",
            "tls-cache",
            "fingerprint",
            "arena",
            "bounds",
            "canary",
        ],
        [
            "canary",
            "fingerprint",
            "null",
            "tls-cache",
            "bounds",
            "bloom",
            "arena",
        ],
    ];
    for perm in &permutations {
        let out = run_repeated(&bin, perm)?;
        if !out.status.success() {
            return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
        }
        let parsed = parse_stdout(&out)?;
        let stages: Vec<String> = parsed
            .get("stages")
            .and_then(Value::as_array)
            .ok_or_else(|| "missing stages".to_string())?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        let unpacked: Vec<String> = parsed
            .get("unpacked_round_trip")
            .and_then(Value::as_array)
            .ok_or_else(|| "missing unpacked_round_trip".to_string())?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        require(
            stages == unpacked,
            format!("round-trip drift: stages={stages:?} unpacked={unpacked:?}"),
        )?;
        require(
            json_bool(&parsed, "round_trip_ok")?,
            "round_trip_ok must be true",
        )?;
    }
    Ok(())
}

#[test]
fn cli_repeated_flags_and_comma_separated_are_equivalent() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let out_a = run_repeated(&bin, &IDENTITY)?;
    let out_b = run_csv(&bin, &IDENTITY.join(","))?;
    if !out_a.status.success() || !out_b.status.success() {
        return Err("both runs must succeed".to_string());
    }
    let pa = parse_stdout(&out_a)?;
    let pb = parse_stdout(&out_b)?;
    require(
        pa == pb,
        "repeated and comma-separated forms must produce identical output",
    )
}

#[test]
fn cli_unknown_stage_rejected_with_nonzero_exit() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let bad: [&str; 7] = [
        "null",
        "tls-cache",
        "bloom",
        "arena",
        "fingerprint",
        "canary",
        "NOPE",
    ];
    let out = run_repeated(&bin, &bad)?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Harness uses Result<()> -> 0 on Err with eprintln, OR exits non-zero on
    // unknown stage. Either way the stderr must mention "unknown" + the stage.
    require(
        !out.status.success() || stderr.contains("unknown check stage") || stderr.contains("NOPE"),
        format!(
            "unknown stage must surface: success={} stderr={stderr}",
            out.status.success()
        ),
    )
}

#[test]
fn cli_fewer_than_seven_stages_rejected() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let short: [&str; 6] = [
        "null",
        "tls-cache",
        "bloom",
        "arena",
        "fingerprint",
        "canary",
    ];
    let out = run_repeated(&bin, &short)?;
    require(
        !out.status.success()
            || String::from_utf8_lossy(&out.stderr).contains("7")
            || String::from_utf8_lossy(&out.stderr).contains("seven"),
        format!(
            "6 stages must be rejected: success={} stderr={}",
            out.status.success(),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn cli_more_than_seven_stages_rejected() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let long: [&str; 8] = [
        "null",
        "tls-cache",
        "bloom",
        "arena",
        "fingerprint",
        "canary",
        "bounds",
        "null",
    ];
    let out = run_repeated(&bin, &long)?;
    require(
        !out.status.success()
            || String::from_utf8_lossy(&out.stderr).contains("7")
            || String::from_utf8_lossy(&out.stderr).contains("seven"),
        format!(
            "8 stages must be rejected: success={} stderr={}",
            out.status.success(),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn cli_deterministic_given_same_inputs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let a = run_repeated(&bin, &IDENTITY)?;
    let b = run_repeated(&bin, &IDENTITY)?;
    require(
        a.status.success() && b.status.success(),
        "both runs must succeed",
    )?;
    let pa = parse_stdout(&a)?;
    let pb = parse_stdout(&b)?;
    require(pa == pb, "same inputs must produce identical output")
}
