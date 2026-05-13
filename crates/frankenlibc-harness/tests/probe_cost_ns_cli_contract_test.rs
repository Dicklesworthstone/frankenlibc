//! Conformance gate for the harness binary `probe-cost-ns` subcommand
//! (bd-9axxf).

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
        .join("probe_cost_ns_cli_contract.v1.json")
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
    Ok(std::env::temp_dir().join(format!("bd_9axxf_{stem}_{}_{ts}.jsonl", std::process::id())))
}

#[test]
fn manifest_anchors_to_9axxf_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "probe-cost-ns-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-9axxf", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "probe-cost-ns",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_membrane::runtime_math::design::probe_cost_ns",
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
        "echoes_probe_name_into_output_record",
        "deterministic_given_inputs",
        "all_seventeen_probes_have_a_finite_cost",
        "loss_minimizer_is_lowest_cost_probe",
        "persistence_is_highest_cost_probe",
        "unknown_probe_name_is_rejected_with_nonzero_exit",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_probe_cost_ns_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("ProbeCostNs {"),
        "harness.rs must declare ProbeCostNs Command variant",
    )?;
    require(
        src.contains("design::probe_cost_ns"),
        "match arm must import design::probe_cost_ns",
    )?;
    require(
        src.contains("\"kind\": \"probe_cost_ns\""),
        "ProbeCostNs arm must emit kind=probe_cost_ns",
    )
}

fn run_cli(bin: &Path, probe: &str, output: &Path) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("probe-cost-ns")
        .arg("--probe")
        .arg(probe)
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn: {e}"))
}

fn read_record(out_path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(out_path).map_err(|e| format!("read: {e}"))?;
    serde_json::from_str(body.trim()).map_err(|e| format!("parse: {e}"))
}

fn run_and_parse(bin: &Path, probe: &str, label: &str) -> TestResult<Value> {
    let output = unique_tmp(label)?;
    let out = run_cli(bin, probe, &output)?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = read_record(&output)?;
    let _ = std::fs::remove_file(&output);
    Ok(parsed)
}

#[test]
fn cli_all_seventeen_probes_emit_finite_costs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let table = manifest
        .get("expected_costs_ns")
        .and_then(Value::as_object)
        .ok_or_else(|| "missing expected_costs_ns".to_string())?;
    require(
        table.len() == 17,
        format!("expected 17 probes, got {}", table.len()),
    )?;
    for (probe, want_cost) in table {
        let want = want_cost
            .as_u64()
            .ok_or_else(|| format!("expected_costs_ns.{probe} must be u64"))?;
        let parsed = run_and_parse(&bin, probe, &format!("probe_{probe}"))?;
        require(
            json_string(&parsed, "kind")? == "probe_cost_ns",
            "kind must be probe_cost_ns",
        )?;
        require(
            json_string(&parsed, "probe")? == probe,
            format!("probe must echo {probe}"),
        )?;
        let got = json_u64(&parsed, "cost_ns")?;
        require(
            got == want,
            format!("probe={probe}: cost_ns table drift: want={want} got={got}"),
        )?;
    }
    Ok(())
}

#[test]
fn cli_loss_minimizer_is_lowest_cost() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let parsed = run_and_parse(&bin, "loss-minimizer", "lowest")?;
    let cost = json_u64(&parsed, "cost_ns")?;
    require(
        cost == 6,
        format!("loss-minimizer cost must be 6, got {cost}"),
    )?;
    let other_probes = [
        "spectral",
        "anytime",
        "cvar",
        "bridge",
        "large-deviations",
        "hji",
        "mean-field",
        "padic",
        "symplectic",
        "higher-topos",
        "commitment-audit",
        "changepoint",
        "conformal",
        "coupling",
    ];
    for o in other_probes {
        let p = run_and_parse(&bin, o, &format!("vs_{o}"))?;
        let c = json_u64(&p, "cost_ns")?;
        require(
            c >= cost,
            format!("loss-minimizer (cost={cost}) must be <= {o} (cost={c})"),
        )?;
    }
    Ok(())
}

#[test]
fn cli_persistence_is_highest_cost() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let parsed = run_and_parse(&bin, "persistence", "highest")?;
    let cost = json_u64(&parsed, "cost_ns")?;
    require(
        cost == 30,
        format!("persistence cost must be 30, got {cost}"),
    )?;
    let other_probes = [
        "spectral",
        "rough-path",
        "anytime",
        "cvar",
        "bridge",
        "large-deviations",
        "hji",
        "mean-field",
        "padic",
        "symplectic",
        "higher-topos",
        "commitment-audit",
        "changepoint",
        "conformal",
        "loss-minimizer",
        "coupling",
    ];
    for o in other_probes {
        let p = run_and_parse(&bin, o, &format!("vs_{o}"))?;
        let c = json_u64(&p, "cost_ns")?;
        require(
            c <= cost,
            format!("persistence (cost={cost}) must be >= {o} (cost={c})"),
        )?;
    }
    Ok(())
}

#[test]
fn cli_unknown_probe_is_rejected_with_nonzero_exit() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("unknown")?;
    let out = run_cli(&bin, "totally-not-a-real-probe", &output)?;
    let _ = std::fs::remove_file(&output);
    require(
        !out.status.success(),
        format!(
            "unknown probe must fail; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        ),
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    require(
        stderr.contains("unknown probe"),
        format!("stderr must mention unknown probe: {stderr}"),
    )
}

#[test]
fn cli_deterministic_given_same_inputs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let a = run_and_parse(&bin, "hji", "det_a")?;
    let b = run_and_parse(&bin, "hji", "det_b")?;
    require(a == b, "same inputs must produce identical output")
}
