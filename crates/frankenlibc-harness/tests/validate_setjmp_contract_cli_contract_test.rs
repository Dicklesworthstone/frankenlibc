//! Conformance gate for the harness binary `validate-setjmp-contract`
//! subcommand (bd-b5gfg).

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
        .join("validate_setjmp_contract_cli_contract.v1.json")
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

fn read_record(path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(path).map_err(|e| format!("read jsonl: {e}"))?;
    let records: Vec<&str> = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    require(
        records.len() == 1,
        format!(
            "{} must contain exactly one JSONL record, found {}",
            path.display(),
            records.len()
        ),
    )?;
    let record = records
        .first()
        .ok_or_else(|| "missing JSONL record after record-count check".to_string())?;
    serde_json::from_str(record).map_err(|e| format!("parse: {e}"))
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
    Ok(std::env::temp_dir().join(format!("bd_b5gfg_{stem}_{}_{ts}.jsonl", std::process::id())))
}

#[test]
fn manifest_anchors_to_b5gfg_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "validate-setjmp-contract-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-b5gfg", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "validate-setjmp-contract",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "default_contract_path")?
            == "tests/conformance/setjmp_semantics_contract.v1.json",
        "default_contract_path",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m.get("policy").ok_or("missing policy")?;
    for (field, message) in [
        (
            "must_emit_exactly_one_jsonl_record",
            "must_emit_exactly_one_jsonl_record must be true",
        ),
        (
            "ok_true_iff_parse_and_intrinsic_both_pass",
            "ok_true_iff_parse_and_intrinsic_both_pass must be true",
        ),
        (
            "exit_non_zero_when_ok_false",
            "exit_non_zero_when_ok_false must be true",
        ),
        (
            "intrinsic_errors_must_be_empty_array_when_ok_true",
            "intrinsic_errors_must_be_empty_array_when_ok_true must be true",
        ),
        (
            "canonical_artifact_must_pass_validate_intrinsic",
            "canonical_artifact_must_pass_validate_intrinsic must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_validate_setjmp_contract_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("ValidateSetjmpContract {"),
        "harness.rs must declare ValidateSetjmpContract Command variant",
    )?;
    require(
        src.contains("setjmp_contract::parse_contract_str"),
        "main() must import setjmp_contract::parse_contract_str",
    )?;
    require(
        src.contains("\"kind\": \"setjmp_contract_validation\""),
        "ValidateSetjmpContract arm must emit kind=setjmp_contract_validation",
    )
}

#[test]
fn cli_passes_on_canonical_artifact() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("ok")?;
    let root = workspace_root()?;
    let out = Command::new(&bin)
        .arg("validate-setjmp-contract")
        .arg("--contract")
        .arg(root.join("tests/conformance/setjmp_semantics_contract.v1.json"))
        .arg("--output")
        .arg(&output)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "validate-setjmp-contract failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_record(&output)?;
    require(
        json_string(&parsed, "kind")? == "setjmp_contract_validation",
        "kind must be setjmp_contract_validation",
    )?;
    require(
        json_bool(&parsed, "ok")?,
        "canonical artifact must produce ok=true",
    )?;
    let intrinsic_errors = parsed
        .get("intrinsic_errors")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing intrinsic_errors array".to_string())?;
    require(
        intrinsic_errors.is_empty(),
        "intrinsic_errors must be empty when ok=true",
    )
}

#[test]
fn cli_fails_closed_on_corrupt_json() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let contract = unique_tmp("corrupt_in")?;
    std::fs::write(&contract, "this is not json").map_err(|e| format!("write: {e}"))?;
    let output = unique_tmp("corrupt_out")?;
    let out = Command::new(&bin)
        .arg("validate-setjmp-contract")
        .arg("--contract")
        .arg(&contract)
        .arg("--output")
        .arg(&output)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    require(
        !out.status.success(),
        "validate-setjmp-contract must exit non-zero on corrupt JSON",
    )?;
    let parsed = read_record(&output)?;
    require(
        !json_bool(&parsed, "ok")?,
        "corrupt JSON must produce ok=false",
    )?;
    require(
        !json_string(&parsed, "parse_error")?.is_empty(),
        "corrupt JSON record must carry non-empty `parse_error`",
    )
}

#[test]
fn cli_fails_closed_on_well_formed_json_with_wrong_bead() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let contract = unique_tmp("wrong_bead_in")?;
    // Minimum-shape contract that parses but fails validate_intrinsic
    // because the bead is wrong (must be bd-2xp3) — also missing
    // required symbols → multiple intrinsic errors.
    let body = r#"{
        "schema_version": "v1",
        "bead": "bd-wrong",
        "symbols": {
            "phase1_deferred": [],
            "phase2_target": [],
            "support_matrix_visible_now": []
        },
        "abi_semantics_matrix": [],
        "signal_mask_contract": {
            "pairing_rules": [],
            "phase1_enforcement": ""
        },
        "support_matrix_caveats": {
            "user_visible_notes": [],
            "waiver_policy_symbols": [],
            "owner_bead": "",
            "expires_utc": ""
        },
        "parity_checks": {
            "required_gate": "",
            "required_test": "",
            "required_logs": []
        },
        "summary": {
            "total_symbols": 0,
            "deferred_symbols": 0,
            "phase2_target_symbols": 0,
            "required_signal_mask_rules": 0
        }
    }"#;
    std::fs::write(&contract, body).map_err(|e| format!("write: {e}"))?;
    let output = unique_tmp("wrong_bead_out")?;
    let out = Command::new(&bin)
        .arg("validate-setjmp-contract")
        .arg("--contract")
        .arg(&contract)
        .arg("--output")
        .arg(&output)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    require(
        !out.status.success(),
        "validate-setjmp-contract must exit non-zero when validate_intrinsic returns errors",
    )?;
    let parsed = read_record(&output)?;
    require(
        !json_bool(&parsed, "ok")?,
        "intrinsic failure must produce ok=false",
    )?;
    let intrinsic_errors = parsed
        .get("intrinsic_errors")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing intrinsic_errors array".to_string())?;
    require(
        !intrinsic_errors.is_empty(),
        "intrinsic failure must produce non-empty intrinsic_errors",
    )?;
    require(
        intrinsic_errors
            .iter()
            .any(|e| e.as_str().is_some_and(|s| s.contains("bd-2xp3"))),
        "intrinsic_errors must mention the bead invariant",
    )
}
