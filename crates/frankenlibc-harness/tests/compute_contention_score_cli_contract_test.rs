//! Conformance gate for the harness binary `compute-contention-score`
//! subcommand (bd-rnlv2).

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
        .join("compute_contention_score_cli_contract.v1.json")
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

fn approx_eq(a: f64, b: f64) -> bool {
    (a - b).abs() <= 1.0e-12
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

fn json_f64(value: &Value, field: &str) -> TestResult<f64> {
    value
        .get(field)
        .and_then(Value::as_f64)
        .ok_or_else(|| format!("missing or non-f64 `{field}`"))
}

fn object_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a Value> {
    value.get(field).ok_or_else(|| format!("missing `{field}`"))
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
    Ok(std::env::temp_dir().join(format!("bd_rnlv2_{stem}_{}_{ts}.{ext}", std::process::id())))
}

fn write_json(stem: &str, value: &Value) -> TestResult<PathBuf> {
    let path = unique_tmp(stem, "json")?;
    std::fs::write(&path, value.to_string())
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(path)
}

fn read_record(out_path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(out_path).map_err(|e| format!("read: {e}"))?;
    serde_json::from_str(body.trim()).map_err(|e| format!("parse: {e}"))
}

#[derive(Default)]
struct DiagPaths {
    seqlock: Option<PathBuf>,
    ebr: Option<PathBuf>,
    fc: Option<PathBuf>,
}

fn run_cli(bin: &Path, paths: &DiagPaths, output: &Path) -> TestResult<std::process::Output> {
    let mut cmd = Command::new(bin);
    cmd.arg("compute-contention-score");
    if let Some(path) = &paths.seqlock {
        cmd.arg("--seqlock-diag").arg(path);
    }
    if let Some(path) = &paths.ebr {
        cmd.arg("--ebr-diag").arg(path);
    }
    if let Some(path) = &paths.fc {
        cmd.arg("--fc-diag").arg(path);
    }
    cmd.arg("--output").arg(output);
    cmd.output().map_err(|e| format!("spawn: {e}"))
}

fn run_and_parse(bin: &Path, paths: &DiagPaths, label: &str) -> TestResult<Value> {
    let output = unique_tmp(label, "jsonl")?;
    let out = run_cli(bin, paths, &output)?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = read_record(&output)?;
    let _ = std::fs::remove_file(&output);
    Ok(parsed)
}

fn full_sample_paths(manifest: &Value) -> TestResult<DiagPaths> {
    let sample = object_field(manifest, "expected_full_sample")?;
    Ok(DiagPaths {
        seqlock: Some(write_json("seqlock", object_field(sample, "seqlock")?)?),
        ebr: Some(write_json("ebr", object_field(sample, "ebr")?)?),
        fc: Some(write_json("fc", object_field(sample, "flat_combining")?)?),
    })
}

fn cleanup_paths(paths: &DiagPaths) {
    if let Some(path) = &paths.seqlock {
        let _ = std::fs::remove_file(path);
    }
    if let Some(path) = &paths.ebr {
        let _ = std::fs::remove_file(path);
    }
    if let Some(path) = &paths.fc {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn manifest_anchors_to_rnlv2_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "compute-contention-score-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-rnlv2", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "compute-contention-score",
        "subcommand_name",
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
        "all_diagnostics_are_optional",
        "score_zero_when_no_diagnostics_present",
        "concepts_present_flags_match_inputs",
        "breakdown_matches_library_formulas",
        "score_is_mean_of_present_components",
        "deterministic_given_inputs",
        "invalid_diagnostic_json_is_rejected",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_compute_contention_score_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("ComputeContentionScore {"),
        "harness.rs must declare ComputeContentionScore variant",
    )?;
    require(
        src.contains("compute_contention_score") && src.contains("compute_contention_breakdown"),
        "match arm must import contention score and breakdown helpers",
    )?;
    require(
        src.contains("\"kind\": \"contention_score\""),
        "ComputeContentionScore arm must emit kind=contention_score",
    )
}

#[test]
fn cli_no_diagnostics_emits_zero_score_and_absent_flags() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let parsed = run_and_parse(&bin, &DiagPaths::default(), "none")?;
    require(
        json_string(&parsed, "kind")? == "contention_score",
        "kind must be contention_score",
    )?;
    require(
        approx_eq(json_f64(&parsed, "score")?, 0.0),
        "score must be zero",
    )?;
    let concepts = object_field(&parsed, "concepts_present")?;
    require(
        !json_bool(concepts, "seqlock")?
            && !json_bool(concepts, "ebr")?
            && !json_bool(concepts, "flat_combining")?,
        "all concept flags must be false",
    )
}

#[test]
fn cli_full_sample_matches_manifest_breakdown_and_score() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let paths = full_sample_paths(&manifest)?;
    let parsed = run_and_parse(&bin, &paths, "full")?;
    cleanup_paths(&paths);

    let sample = object_field(&manifest, "expected_full_sample")?;
    let expected_breakdown = object_field(sample, "expected_breakdown")?;
    let actual_breakdown = object_field(&parsed, "breakdown")?;
    for field in [
        "seqlock_cache_miss_ratio",
        "seqlock_contention_per_write",
        "ebr_pinned_fraction",
        "flat_combining_ops_per_pass",
        "flat_combining_efficiency_loss",
    ] {
        require(
            approx_eq(
                json_f64(actual_breakdown, field)?,
                json_f64(expected_breakdown, field)?,
            ),
            format!("{field} drifted"),
        )?;
    }
    require(
        approx_eq(
            json_f64(&parsed, "score")?,
            json_f64(sample, "expected_score")?,
        ),
        "contention score drifted",
    )?;
    let concepts = object_field(&parsed, "concepts_present")?;
    require(
        json_bool(concepts, "seqlock")?
            && json_bool(concepts, "ebr")?
            && json_bool(concepts, "flat_combining")?,
        "all concept flags must be true for full sample",
    )
}

#[test]
fn cli_optional_subset_sets_only_present_concept_flags() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let sample = object_field(&manifest, "expected_full_sample")?;
    let paths = DiagPaths {
        seqlock: Some(write_json(
            "subset_seqlock",
            object_field(sample, "seqlock")?,
        )?),
        ebr: None,
        fc: None,
    };
    let parsed = run_and_parse(&bin, &paths, "subset")?;
    cleanup_paths(&paths);
    let concepts = object_field(&parsed, "concepts_present")?;
    require(
        json_bool(concepts, "seqlock")?
            && !json_bool(concepts, "ebr")?
            && !json_bool(concepts, "flat_combining")?,
        "only seqlock concept should be present",
    )?;
    let breakdown = object_field(&parsed, "breakdown")?;
    require(
        approx_eq(json_f64(breakdown, "seqlock_cache_miss_ratio")?, 0.25)
            && approx_eq(json_f64(breakdown, "seqlock_contention_per_write")?, 0.75),
        "seqlock-only breakdown drifted",
    )
}

#[test]
fn cli_invalid_diagnostic_json_is_rejected() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let bad = unique_tmp("bad", "json")?;
    std::fs::write(&bad, "{not-json").map_err(|e| format!("write {}: {e}", bad.display()))?;
    let output = unique_tmp("bad_output", "jsonl")?;
    let paths = DiagPaths {
        seqlock: Some(bad.clone()),
        ebr: None,
        fc: None,
    };
    let out = run_cli(&bin, &paths, &output)?;
    let _ = std::fs::remove_file(&bad);
    let _ = std::fs::remove_file(&output);
    require(
        !out.status.success(),
        format!(
            "invalid diagnostic JSON must fail; stderr={}",
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
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let paths = full_sample_paths(&manifest)?;
    let a = run_and_parse(&bin, &paths, "det_a")?;
    let b = run_and_parse(&bin, &paths, "det_b")?;
    cleanup_paths(&paths);
    require(a == b, "same diagnostics must produce identical output")
}

#[test]
fn diagnostic_structs_are_deserializable_for_cli_inputs() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let sample = object_field(&manifest, "expected_full_sample")?;
    let _seqlock: frankenlibc_membrane::seqlock::SeqLockDiagnostics =
        serde_json::from_value(object_field(sample, "seqlock")?.clone())
            .map_err(|e| format!("seqlock deserialize: {e}"))?;
    let _ebr: frankenlibc_membrane::ebr::EbrDiagnostics =
        serde_json::from_value(object_field(sample, "ebr")?.clone())
            .map_err(|e| format!("ebr deserialize: {e}"))?;
    let _fc: frankenlibc_membrane::flat_combining::FlatCombinerDiagnostics =
        serde_json::from_value(object_field(sample, "flat_combining")?.clone())
            .map_err(|e| format!("flat_combining deserialize: {e}"))?;
    Ok(())
}
