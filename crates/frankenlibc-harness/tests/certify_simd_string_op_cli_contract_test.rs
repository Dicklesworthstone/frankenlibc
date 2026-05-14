//! Conformance gate for the harness binary `certify-simd-string-op`
//! subcommand (bd-63sqn).

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
        .join("certify_simd_string_op_cli_contract.v1.json")
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

fn unique_tmp(stem: &str) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("bd_63sqn_{stem}_{}_{ts}.jsonl", std::process::id())))
}

#[test]
fn manifest_anchors_to_63sqn_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "certify-simd-string-op-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-63sqn", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "certify-simd-string-op",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_membrane::runtime_math::clifford::certify_simd_string_operation",
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
    for (field, message) in [
        (
            "must_emit_exactly_one_jsonl_record",
            "policy.must_emit_exactly_one_jsonl_record must be true",
        ),
        (
            "echoes_inputs_into_output_record",
            "policy.echoes_inputs_into_output_record must be true",
        ),
        (
            "deterministic_given_inputs",
            "policy.deterministic_given_inputs must be true",
        ),
        (
            "scalar_self_witness_certifies_equivalent",
            "policy.scalar_self_witness_certifies_equivalent must be true",
        ),
        (
            "memcpy_with_overlap_rejected_via_pin_parity_witness",
            "policy.memcpy_with_overlap_rejected_via_pin_parity_witness must be true",
        ),
        (
            "memcpy_without_overlap_certifies_equivalent_for_supported_isas",
            "policy.memcpy_without_overlap_certifies_equivalent_for_supported_isas must be true",
        ),
        (
            "strlen_does_not_require_dst_or_overlap_inputs",
            "policy.strlen_does_not_require_dst_or_overlap_inputs must be true",
        ),
        (
            "isa_label_and_architecture_fields_pin_dispatch_family",
            "policy.isa_label_and_architecture_fields_pin_dispatch_family must be true",
        ),
        (
            "rejection_records_emit_nonempty_rationale_string",
            "policy.rejection_records_emit_nonempty_rationale_string must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_certify_simd_string_op_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("CertifySimdStringOp {"),
        "harness.rs must declare CertifySimdStringOp Command variant",
    )?;
    require(
        src.contains("clifford::certify_simd_string_operation"),
        "match arm must import clifford::certify_simd_string_operation",
    )?;
    require(
        src.contains("\"kind\": \"simd_string_certificate\""),
        "CertifySimdStringOp arm must emit kind=simd_string_certificate",
    )
}

#[allow(clippy::too_many_arguments)]
fn run_cli(
    bin: &Path,
    operation: &str,
    isa: &str,
    src_addr: Option<usize>,
    dst_addr: Option<usize>,
    len: Option<usize>,
    overlap: bool,
    output: &Path,
) -> TestResult<std::process::Output> {
    let mut cmd = Command::new(bin);
    cmd.arg("certify-simd-string-op")
        .arg("--operation")
        .arg(operation)
        .arg("--candidate-isa")
        .arg(isa);
    if let Some(s) = src_addr {
        cmd.arg("--src-addr").arg(s.to_string());
    }
    if let Some(d) = dst_addr {
        cmd.arg("--dst-addr").arg(d.to_string());
    }
    if let Some(l) = len {
        cmd.arg("--len").arg(l.to_string());
    }
    if overlap {
        cmd.arg("--overlap");
    }
    cmd.arg("--output").arg(output);
    cmd.output().map_err(|e| format!("spawn: {e}"))
}

fn read_record(out_path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(out_path).map_err(|e| format!("read: {e}"))?;
    serde_json::from_str(body.trim()).map_err(|e| format!("parse: {e}"))
}

#[test]
fn cli_scalar_self_witness_certifies_equivalent() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("scalar_self")?;
    let out = run_cli(
        &bin,
        "memcpy",
        "scalar",
        Some(4096),
        Some(8192),
        Some(256),
        false,
        &output,
    )?;
    if !out.status.success() {
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = read_record(&output)?;
    require(
        json_string(&parsed, "kind")? == "simd_string_certificate",
        "kind",
    )?;
    require(
        json_bool(&parsed, "equivalent")?,
        "scalar self-witness must be equivalent",
    )?;
    require(
        json_string(&parsed, "architecture")? == "portable",
        "scalar architecture must be portable",
    )?;
    require(
        json_u64(&parsed, "lane_bytes")? == 1,
        "scalar lane_bytes must be 1",
    )
}

#[test]
fn cli_memcpy_avx2_overlap_rejected() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("memcpy_overlap")?;
    // Overlapping source/dest for memcpy -> Pin parity witness forbids.
    let out = run_cli(
        &bin,
        "memcpy",
        "avx2",
        Some(4096),
        Some(4112),
        Some(1024),
        true,
        &output,
    )?;
    if !out.status.success() {
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = read_record(&output)?;
    require(
        !json_bool(&parsed, "equivalent")?,
        "memcpy overlap must be rejected",
    )?;
    let rationale = json_string(&parsed, "rationale")?;
    require(
        !rationale.is_empty(),
        "rejection must include non-empty rationale",
    )?;
    require(
        rationale.contains("overlap") || rationale.contains("parity"),
        format!("rationale should reference overlap/parity: {rationale}"),
    )
}

#[test]
fn cli_memcpy_avx2_without_overlap_certifies_equivalent() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("memcpy_clean")?;
    let out = run_cli(
        &bin,
        "memcpy",
        "avx2",
        Some(4096),
        Some(12288),
        Some(1024),
        false,
        &output,
    )?;
    if !out.status.success() {
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = read_record(&output)?;
    require(
        json_bool(&parsed, "equivalent")?,
        "memcpy avx2 disjoint regions must be equivalent",
    )?;
    require(
        json_string(&parsed, "architecture")? == "x86_64",
        "avx2 architecture must be x86_64",
    )?;
    require(
        json_u64(&parsed, "lane_bytes")? == 32,
        "avx2 lane_bytes must be 32",
    )
}

#[test]
fn cli_strlen_omits_dst_and_overlap() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("strlen")?;
    // strlen needs src+len but not dst or overlap.
    let out = run_cli(
        &bin,
        "strlen",
        "sse4.2",
        Some(4096),
        None,
        Some(64),
        false,
        &output,
    )?;
    if !out.status.success() {
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = read_record(&output)?;
    require(
        json_string(&parsed, "operation")? == "strlen",
        "operation must echo strlen",
    )?;
    require(
        json_u64(&parsed, "lane_bytes")? == 16,
        "sse4.2 lane_bytes must be 16",
    )
}

#[test]
fn cli_isa_label_and_architecture_pin_dispatch_family() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    for (isa, want_arch, want_lane, stem, failure, arch_msg, lane_msg, candidate_msg) in [
        (
            "scalar",
            "portable",
            1u64,
            "isa_scalar",
            "scalar ISA command failed",
            "scalar architecture must be portable",
            "scalar lane_bytes must be 1",
            "candidate_isa must echo scalar",
        ),
        (
            "sse4.2",
            "x86_64",
            16,
            "isa_sse42",
            "sse4.2 ISA command failed",
            "sse4.2 architecture must be x86_64",
            "sse4.2 lane_bytes must be 16",
            "candidate_isa must echo sse4.2",
        ),
        (
            "avx2",
            "x86_64",
            32,
            "isa_avx2",
            "avx2 ISA command failed",
            "avx2 architecture must be x86_64",
            "avx2 lane_bytes must be 32",
            "candidate_isa must echo avx2",
        ),
        (
            "neon",
            "aarch64",
            16,
            "isa_neon",
            "neon ISA command failed",
            "neon architecture must be aarch64",
            "neon lane_bytes must be 16",
            "candidate_isa must echo neon",
        ),
    ] {
        let output = unique_tmp(stem)?;
        let out = run_cli(
            &bin,
            "memcmp",
            isa,
            Some(4096),
            Some(8192),
            Some(128),
            false,
            &output,
        )?;
        if !out.status.success() {
            return Err(failure.into());
        }
        let parsed = read_record(&output)?;
        require(json_string(&parsed, "architecture")? == want_arch, arch_msg)?;
        require(json_u64(&parsed, "lane_bytes")? == want_lane, lane_msg)?;
        require(json_string(&parsed, "candidate_isa")? == isa, candidate_msg)?;
    }
    Ok(())
}

#[test]
fn cli_deterministic_given_same_inputs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let a = unique_tmp("det_a")?;
    let b = unique_tmp("det_b")?;
    let out_a = run_cli(
        &bin,
        "memcpy",
        "avx2",
        Some(4096),
        Some(12288),
        Some(2048),
        false,
        &a,
    )?;
    let out_b = run_cli(
        &bin,
        "memcpy",
        "avx2",
        Some(4096),
        Some(12288),
        Some(2048),
        false,
        &b,
    )?;
    require(
        out_a.status.success() && out_b.status.success(),
        "both runs must succeed",
    )?;
    let pa = read_record(&a)?;
    let pb = read_record(&b)?;
    require(pa == pb, "same inputs must produce identical output")
}

#[test]
fn cli_echoes_inputs_into_record() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("echo")?;
    let out = run_cli(
        &bin,
        "memcmp",
        "neon",
        Some(11111),
        Some(22222),
        Some(333),
        false,
        &output,
    )?;
    require(
        out.status.success(),
        format!("stderr={}", String::from_utf8_lossy(&out.stderr)),
    )?;
    let parsed = read_record(&output)?;
    require(
        json_string(&parsed, "operation")? == "memcmp",
        "operation must echo",
    )?;
    require(
        json_string(&parsed, "candidate_isa")? == "neon",
        "candidate_isa must echo",
    )?;
    require(
        json_u64(&parsed, "src_addr")? == 11_111,
        "src_addr must echo",
    )?;
    require(
        json_u64(&parsed, "dst_addr")? == 22_222,
        "dst_addr must echo",
    )?;
    require(json_u64(&parsed, "len")? == 333, "len must echo")?;
    require(!json_bool(&parsed, "overlap")?, "overlap must echo false")
}
