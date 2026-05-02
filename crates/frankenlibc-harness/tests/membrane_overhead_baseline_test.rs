//! Integration test: membrane overhead baseline gate (bd-bp8fl.8.2).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, String>;

const REQUIRED_STAGES: &[&str] = &[
    "null_check",
    "tls_cache",
    "bloom_filter",
    "arena_lookup",
    "fingerprint_check",
    "canary_check",
    "bounds_check",
    "full_validation_path",
];

const REQUIRED_BENCHMARKS: &[&str] = &[
    "stage_null_check",
    "stage_tls_cache_hit",
    "stage_bloom_hit",
    "stage_arena_lookup",
    "stage_fingerprint_verify",
    "stage_canary_verify",
    "stage_bounds_check",
    "validate_null",
    "validate_foreign",
    "validate_known",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn load_json(path: &Path) -> TestResult<serde_json::Value> {
    let content =
        std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    serde_json::from_str(&content).map_err(|err| format!("{}: {err}", path.display()))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

#[test]
fn committed_artifact_covers_every_membrane_stage() -> TestResult {
    let root = workspace_root()?;
    let artifact = load_json(&root.join("tests/conformance/membrane_overhead_baseline.v1.json"))?;

    require(
        artifact["schema_version"].as_u64() == Some(1),
        "schema_version must be 1",
    )?;
    require(
        artifact["bead"].as_str() == Some("bd-bp8fl.8.2"),
        "bead must be bd-bp8fl.8.2",
    )?;

    let covered_stages: HashSet<_> = artifact["stage_coverage"]
        .as_array()
        .ok_or_else(|| "stage_coverage must be array".to_string())?
        .iter()
        .filter_map(|row| row["stage"].as_str())
        .collect();
    for stage in REQUIRED_STAGES {
        require(
            covered_stages.contains(stage),
            format!("stage_coverage missing {stage}"),
        )?;
    }

    let benchmark_names: HashSet<_> = artifact["benchmarks"]
        .as_array()
        .ok_or_else(|| "benchmarks must be array".to_string())?
        .iter()
        .filter_map(|row| row["name"].as_str())
        .collect();
    for benchmark in REQUIRED_BENCHMARKS {
        require(
            benchmark_names.contains(benchmark),
            format!("benchmark missing {benchmark}"),
        )?;
    }
    Ok(())
}

#[test]
fn perf_baseline_and_spec_are_synchronized() -> TestResult {
    let root = workspace_root()?;
    let artifact = load_json(&root.join("tests/conformance/membrane_overhead_baseline.v1.json"))?;
    let baseline = load_json(&root.join("scripts/perf_baseline.json"))?;
    let spec = load_json(&root.join("tests/conformance/perf_baseline_spec.json"))?;

    let membrane_suite = spec["benchmark_suites"]["suites"]
        .as_array()
        .ok_or_else(|| "benchmark_suites.suites must be array".to_string())?
        .iter()
        .find(|suite| suite["id"].as_str() == Some("membrane"))
        .ok_or_else(|| "membrane suite missing".to_string())?;
    let spec_benchmarks: Vec<_> = membrane_suite["benchmarks"]
        .as_array()
        .ok_or_else(|| "membrane benchmarks must be array".to_string())?
        .iter()
        .filter_map(|bench| bench["name"].as_str())
        .collect();
    require(
        spec_benchmarks == REQUIRED_BENCHMARKS,
        "membrane suite benchmark list must match artifact scope",
    )?;

    for row in artifact["benchmarks"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        for mode in ["strict", "hardened"] {
            let artifact_p50 = row["baseline"][mode]["p50_ns_op"]
                .as_f64()
                .ok_or_else(|| format!("{name}/{mode}: missing artifact p50"))?;
            let committed_p50 = baseline["baseline_p50_ns_op"]["membrane"][mode][name]
                .as_f64()
                .ok_or_else(|| format!("{name}/{mode}: missing perf_baseline p50"))?;
            require(
                (artifact_p50 - committed_p50).abs() <= 0.0005,
                format!("{name}/{mode}: p50 mismatch"),
            )?;
        }
    }
    Ok(())
}

#[test]
fn gate_script_emits_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_membrane_overhead_baseline.sh");
    require(script.exists(), format!("missing {}", script.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)
            .map_err(|err| format!("{}: {err}", script.display()))?
            .permissions();
        require(
            perms.mode() & 0o111 != 0,
            "check_membrane_overhead_baseline.sh must be executable",
        )?;
    }

    let report = root.join("target/conformance/membrane_overhead_baseline.test.report.json");
    let log = root.join("target/conformance/membrane_overhead_baseline.test.log.jsonl");
    let output = Command::new(&script)
        .current_dir(&root)
        .env("FRANKENLIBC_MEMBRANE_OVERHEAD_REPORT", &report)
        .env("FRANKENLIBC_MEMBRANE_OVERHEAD_LOG", &log)
        .output()
        .map_err(|err| format!("failed to run membrane overhead gate: {err}"))?;
    require(
        output.status.success(),
        format!(
            "membrane overhead gate failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;

    let report_json = load_json(&report)?;
    require(
        report_json["status"].as_str() == Some("pass"),
        "report status must be pass",
    )?;
    require(log.exists(), "jsonl log must exist")?;
    let row_count = std::fs::read_to_string(&log)
        .map_err(|err| format!("{}: {err}", log.display()))?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    require(
        row_count == REQUIRED_BENCHMARKS.len() * 2,
        "jsonl log must include every benchmark/mode row",
    )
}
