//! Conformance gate for the harness binary `compute-certificate-hash`
//! subcommand (bd-ohq9t).

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
        .join("compute_certificate_hash_cli_contract.v1.json")
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
    Ok(std::env::temp_dir().join(format!("bd_ohq9t_{stem}_{}_{ts}.{ext}", std::process::id())))
}

fn write_matrix(stem: &str, matrix: &Value) -> TestResult<PathBuf> {
    let p = unique_tmp(stem, "json")?;
    std::fs::write(&p, matrix.to_string()).map_err(|e| format!("write: {e}"))?;
    Ok(p)
}

fn run_cli(
    bin: &Path,
    gram_matrix: &Path,
    monomial_degree: u32,
    barrier_budget_milli: i64,
    output: &Path,
) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("compute-certificate-hash")
        .arg("--gram-matrix")
        .arg(gram_matrix)
        .arg("--monomial-degree")
        .arg(monomial_degree.to_string())
        .arg(format!("--barrier-budget-milli={barrier_budget_milli}"))
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn: {e}"))
}

fn read_record(path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
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

fn run_and_parse(
    bin: &Path,
    matrix: &Value,
    monomial_degree: u32,
    barrier_budget_milli: i64,
    label: &str,
) -> TestResult<Value> {
    let m_path = write_matrix(label, matrix)?;
    let output = unique_tmp(label, "jsonl")?;
    let out = run_cli(bin, &m_path, monomial_degree, barrier_budget_milli, &output)?;
    if !out.status.success() {
        return Err("compute-certificate-hash CLI invocation must succeed".into());
    }
    let parsed = read_record(&output)?;
    Ok(parsed)
}

#[test]
fn manifest_anchors_to_ohq9t_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "compute-certificate-hash-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-ohq9t", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "compute-certificate-hash",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_membrane::runtime_math::sos_barrier::compute_certificate_hash",
        "underlying_lib_function",
    )
}

#[test]
fn manifest_required_flags_pin_cli_surface() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let flags = m
        .get("required_flags")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing required_flags".to_string())?;
    for flag in [
        "--gram-matrix",
        "--monomial-degree",
        "--barrier-budget-milli",
        "--output",
    ] {
        require(
            flags.iter().any(|value| value.as_str() == Some(flag)),
            format!("required_flags must include {flag}"),
        )?;
    }
    require(
        flags.len() == 4,
        format!("compute-certificate-hash required_flags drifted: {flags:?}"),
    )
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
            "echoes_inputs_into_output_record",
            "echoes_inputs_into_output_record must be true",
        ),
        (
            "deterministic_given_inputs",
            "deterministic_given_inputs must be true",
        ),
        (
            "hash_hex_is_64_lowercase_hex_chars",
            "hash_hex_is_64_lowercase_hex_chars must be true",
        ),
        (
            "different_gram_matrix_yields_different_hash",
            "different_gram_matrix_yields_different_hash must be true",
        ),
        (
            "different_monomial_degree_yields_different_hash",
            "different_monomial_degree_yields_different_hash must be true",
        ),
        (
            "different_barrier_budget_yields_different_hash",
            "different_barrier_budget_yields_different_hash must be true",
        ),
        (
            "supported_dims_2_through_8_succeed",
            "supported_dims_2_through_8_succeed must be true",
        ),
        (
            "unsupported_dim_is_rejected",
            "unsupported_dim_is_rejected must be true",
        ),
        (
            "non_square_matrix_is_rejected",
            "non_square_matrix_is_rejected must be true",
        ),
        (
            "d4_anchor_hash_matches_expected",
            "d4_anchor_hash_matches_expected must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_compute_certificate_hash_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("ComputeCertificateHash {"),
        "harness.rs must declare ComputeCertificateHash variant",
    )?;
    require(
        src.contains("sos_barrier::compute_certificate_hash"),
        "match arm must import compute_certificate_hash",
    )?;
    require(
        src.contains("\"kind\": \"certificate_hash\""),
        "match arm must emit kind=certificate_hash",
    )
}

#[test]
fn cli_d4_anchor_hash_matches_expected() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let anchor = manifest
        .get("expected_d4_anchor")
        .ok_or_else(|| "missing expected_d4_anchor".to_string())?;
    let matrix = anchor
        .get("gram_matrix")
        .ok_or_else(|| "missing gram_matrix".to_string())?;
    let monomial_degree_u64 = anchor
        .get("monomial_degree")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing monomial_degree".to_string())?;
    let monomial_degree = u32::try_from(monomial_degree_u64)
        .map_err(|_| "monomial_degree out of u32 range".to_string())?;
    let budget = anchor
        .get("barrier_budget_milli")
        .and_then(Value::as_i64)
        .ok_or_else(|| "missing barrier_budget_milli".to_string())?;
    let want_hash = anchor
        .get("expected_hash_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing expected_hash_hex".to_string())?;
    let parsed = run_and_parse(&bin, matrix, monomial_degree, budget, "anchor")?;
    require(json_string(&parsed, "kind")? == "certificate_hash", "kind")?;
    require(json_u64(&parsed, "dim")? == 4, "dim must be 4")?;
    let got = json_string(&parsed, "hash_hex")?;
    require(
        got == want_hash,
        format!("hash drift: want={want_hash} got={got}"),
    )
}

#[test]
fn cli_hash_hex_is_64_lowercase_hex_chars() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let parsed = run_and_parse(
        &bin,
        &serde_json::json!([[1, 0, 0], [0, 1, 0], [0, 0, 1]]),
        2,
        500,
        "fmt",
    )?;
    let hex = json_string(&parsed, "hash_hex")?;
    require(hex.len() == 64, format!("hash_hex len={}", hex.len()))?;
    require(
        hex.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "lowercase hex required",
    )
}

#[test]
fn cli_different_inputs_yield_different_hashes() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let m1 = serde_json::json!([[1, 0], [0, 1]]);
    let m2 = serde_json::json!([[1, 0], [0, 2]]);
    let base = run_and_parse(&bin, &m1, 2, 100, "base")?;
    let diff_mat = run_and_parse(&bin, &m2, 2, 100, "diff_mat")?;
    let diff_deg = run_and_parse(&bin, &m1, 3, 100, "diff_deg")?;
    let diff_bud = run_and_parse(&bin, &m1, 2, 200, "diff_bud")?;
    let b = json_string(&base, "hash_hex")?.to_string();
    require(
        json_string(&diff_mat, "hash_hex")? != b,
        "different gram_matrix must produce different hash",
    )?;
    require(
        json_string(&diff_deg, "hash_hex")? != b,
        "different monomial_degree must produce different hash",
    )?;
    require(
        json_string(&diff_bud, "hash_hex")? != b,
        "different barrier_budget must produce different hash",
    )
}

#[test]
fn cli_supported_dims_2_through_8_succeed() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    for d in 2..=8 {
        let mut rows = Vec::with_capacity(d);
        for i in 0..d {
            let row: Vec<i64> = (0..d).map(|j| if i == j { 1i64 } else { 0i64 }).collect();
            rows.push(row);
        }
        let m: Value = serde_json::json!(rows);
        let label = match d {
            2 => "d_2",
            3 => "d_3",
            4 => "d_4",
            5 => "d_5",
            6 => "d_6",
            7 => "d_7",
            8 => "d_8",
            _ => "d_unknown",
        };
        let parsed = run_and_parse(&bin, &m, 2, 0, label)?;
        require(
            json_u64(&parsed, "dim")? as usize == d,
            "dim must echo input dimension",
        )?;
        let h = json_string(&parsed, "hash_hex")?;
        require(h.len() == 64, "hash len must be 64")?;
    }
    Ok(())
}

#[test]
fn cli_unsupported_dim_is_rejected() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let m: Value = serde_json::json!([[1]]);
    let m_path = write_matrix("d1", &m)?;
    let output = unique_tmp("d1", "jsonl")?;
    let out = run_cli(&bin, &m_path, 2, 0, &output)?;
    require(!out.status.success(), "D=1 must exit non-zero")?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    require(
        stderr.contains("unsupported gram_matrix dim"),
        "stderr must mention unsupported dim",
    )
}

#[test]
fn cli_non_square_matrix_is_rejected() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    // 3 rows but 4 columns -> non-square.
    let m: Value = serde_json::json!([[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0]]);
    let m_path = write_matrix("nonsq", &m)?;
    let output = unique_tmp("nonsq", "jsonl")?;
    let out = run_cli(&bin, &m_path, 2, 0, &output)?;
    require(
        !out.status.success(),
        "non-square matrix must exit non-zero",
    )
}

#[test]
fn cli_deterministic_given_same_inputs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let m = serde_json::json!([[1, 2, 3], [4, 5, 6], [7, 8, 9]]);
    let a = run_and_parse(&bin, &m, 3, 12345, "det_a")?;
    let b = run_and_parse(&bin, &m, 3, 12345, "det_b")?;
    require(a == b, "same inputs must produce identical output")
}
