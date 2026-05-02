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

const REQUIRED_RECORD_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "benchmark_id",
    "validation_path",
    "runtime_mode",
    "input_shape",
    "sample_count",
    "warmup_ms",
    "latency_ns",
    "variance",
    "environment",
    "source_commit",
    "target_dir",
    "threshold",
    "decision",
    "artifact_refs",
    "failure_signature",
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

fn close_enough(left: f64, right: f64) -> bool {
    (left - right).abs() <= 0.0005
}

fn readme_target_ns(row: &serde_json::Value, mode: &str) -> Option<f64> {
    row["readme_target_ns"]
        .as_f64()
        .or_else(|| row["readme_target_ns"][mode].as_f64())
}

fn expected_decision(latency_ns: f64, threshold: f64) -> &'static str {
    if latency_ns <= threshold {
        "pass"
    } else {
        "captured_over_target_for_optimization"
    }
}

fn expected_failure_signature(decision: &str) -> &'static str {
    if decision == "pass" {
        "none"
    } else {
        "target_exceeded_baseline_only"
    }
}

fn artifact_contract_errors(artifact: &serde_json::Value) -> Vec<String> {
    let mut errors = Vec::new();
    let source_commit = artifact["source_commit"].as_str().unwrap_or_default();
    if source_commit.len() != 40 || !source_commit.chars().all(|ch| ch.is_ascii_hexdigit()) {
        errors.push("source_commit must be a 40-character git commit".to_string());
    }

    let Some(benchmarks) = artifact["benchmarks"].as_array() else {
        return vec!["benchmarks must be array".to_string()];
    };
    let Some(records) = artifact["benchmark_records"].as_array() else {
        return vec!["benchmark_records must be array".to_string()];
    };
    let Some(target_dirs) = artifact["measurement_environment"]["target_dirs"].as_object() else {
        errors.push("measurement_environment.target_dirs must be object".to_string());
        return errors;
    };
    let warmup_ms = artifact["measurement_environment"]["criterion"]["warm_up_time_ms"]
        .as_i64()
        .unwrap_or_default();
    let variance_policy = artifact["variance_policy"]["kind"]
        .as_str()
        .unwrap_or_default();

    for benchmark in REQUIRED_BENCHMARKS {
        let Some(row) = benchmarks
            .iter()
            .find(|candidate| candidate["name"].as_str() == Some(*benchmark))
        else {
            errors.push(format!("missing benchmark {benchmark}"));
            continue;
        };

        for mode in ["strict", "hardened"] {
            let Some(metrics) = row["baseline"][mode].as_object() else {
                errors.push(format!("{benchmark}/{mode}: missing baseline metrics"));
                continue;
            };
            let Some(latency_ns) = metrics.get("p50_ns_op").and_then(|value| value.as_f64()) else {
                errors.push(format!("{benchmark}/{mode}: missing p50"));
                continue;
            };
            let Some(p95_ns) = metrics.get("p95_ns_op").and_then(|value| value.as_f64()) else {
                errors.push(format!("{benchmark}/{mode}: missing p95"));
                continue;
            };
            let Some(p99_ns) = metrics.get("p99_ns_op").and_then(|value| value.as_f64()) else {
                errors.push(format!("{benchmark}/{mode}: missing p99"));
                continue;
            };
            let Some(threshold) = readme_target_ns(row, mode) else {
                errors.push(format!("{benchmark}/{mode}: missing threshold"));
                continue;
            };

            let Some(record) = records.iter().find(|candidate| {
                candidate["benchmark"].as_str() == Some(*benchmark)
                    && candidate["runtime_mode"].as_str() == Some(mode)
            }) else {
                errors.push(format!("{benchmark}/{mode}: missing benchmark_record"));
                continue;
            };

            for field in REQUIRED_RECORD_FIELDS {
                if record.get(*field).is_none() {
                    errors.push(format!("{benchmark}/{mode}: missing {field}"));
                }
            }

            let expected_trace_id = format!("bd-bp8fl.8.2::{mode}::{benchmark}");
            let expected_benchmark_id = format!("membrane.{benchmark}.{mode}");
            let expected_target_dir = target_dirs
                .get(mode)
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            let decision = expected_decision(latency_ns, threshold);

            if record["trace_id"].as_str() != Some(expected_trace_id.as_str()) {
                errors.push(format!("{benchmark}/{mode}: trace_id mismatch"));
            }
            if record["benchmark_id"].as_str() != Some(expected_benchmark_id.as_str()) {
                errors.push(format!("{benchmark}/{mode}: benchmark_id mismatch"));
            }
            if record["validation_path"].as_str() != row["stage"].as_str() {
                errors.push(format!("{benchmark}/{mode}: validation_path mismatch"));
            }
            if !record["input_shape"].is_object() {
                errors.push(format!("{benchmark}/{mode}: input_shape must be object"));
            }
            if record["sample_count"].as_i64()
                != metrics.get("samples").and_then(|value| value.as_i64())
            {
                errors.push(format!("{benchmark}/{mode}: sample_count mismatch"));
            }
            if record["warmup_ms"].as_i64() != Some(warmup_ms) {
                errors.push(format!("{benchmark}/{mode}: warmup_ms mismatch"));
            }
            if !close_enough(record["latency_ns"].as_f64().unwrap_or(-1.0), latency_ns) {
                errors.push(format!("{benchmark}/{mode}: latency_ns mismatch"));
            }
            if record["source_commit"].as_str() != Some(source_commit) {
                errors.push(format!(
                    "{benchmark}/{mode}: source_commit is stale or mismatched"
                ));
            }
            if record["target_dir"].as_str() != Some(expected_target_dir) {
                errors.push(format!("{benchmark}/{mode}: target_dir mismatch"));
            }
            if !close_enough(record["threshold"].as_f64().unwrap_or(-1.0), threshold) {
                errors.push(format!("{benchmark}/{mode}: threshold mismatch"));
            }
            if record["decision"].as_str() != Some(decision) {
                errors.push(format!("{benchmark}/{mode}: decision mismatch"));
            }
            if record["failure_signature"].as_str() != Some(expected_failure_signature(decision)) {
                errors.push(format!("{benchmark}/{mode}: failure_signature mismatch"));
            }
            if record["artifact_refs"]
                .as_array()
                .map(|refs| refs.len() >= 3)
                != Some(true)
            {
                errors.push(format!("{benchmark}/{mode}: artifact_refs incomplete"));
            }

            let variance = &record["variance"];
            let expected_p95_spread = p95_ns - latency_ns;
            let expected_p99_spread = p99_ns - latency_ns;
            if variance["policy"].as_str() != Some(variance_policy) {
                errors.push(format!("{benchmark}/{mode}: variance policy mismatch"));
            }
            if !close_enough(
                variance["p95_minus_p50_ns"].as_f64().unwrap_or(-1.0),
                expected_p95_spread,
            ) {
                errors.push(format!("{benchmark}/{mode}: p95 variance mismatch"));
            }
            if !close_enough(
                variance["p99_minus_p50_ns"].as_f64().unwrap_or(-1.0),
                expected_p99_spread,
            ) {
                errors.push(format!("{benchmark}/{mode}: p99 variance mismatch"));
            }
            if variance["p95_minus_p50_ns"].as_f64().unwrap_or(-1.0) < 0.0
                || variance["p99_minus_p50_ns"].as_f64().unwrap_or(-1.0) < 0.0
            {
                errors.push(format!("{benchmark}/{mode}: variance must be non-negative"));
            }
        }
    }

    errors
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
fn committed_artifact_records_have_complete_baseline_contract() -> TestResult {
    let root = workspace_root()?;
    let artifact = load_json(&root.join("tests/conformance/membrane_overhead_baseline.v1.json"))?;
    let errors = artifact_contract_errors(&artifact);
    require(
        errors.is_empty(),
        format!("artifact contract errors:\n{}", errors.join("\n")),
    )?;
    require(
        artifact["benchmark_records"].as_array().map(Vec::len)
            == Some(REQUIRED_BENCHMARKS.len() * 2),
        "benchmark_records must include every benchmark/mode pair",
    )
}

#[test]
fn artifact_contract_rejects_missing_mode_coverage() -> TestResult {
    let root = workspace_root()?;
    let mut artifact =
        load_json(&root.join("tests/conformance/membrane_overhead_baseline.v1.json"))?;
    let records = artifact["benchmark_records"]
        .as_array_mut()
        .ok_or_else(|| "benchmark_records must be array".to_string())?;
    records.retain(|record| {
        !(record["benchmark"].as_str() == Some("validate_known")
            && record["runtime_mode"].as_str() == Some("hardened"))
    });
    let errors = artifact_contract_errors(&artifact);
    require(
        errors
            .iter()
            .any(|error| error.contains("validate_known/hardened: missing benchmark_record")),
        format!("missing-mode negative test did not fail as expected: {errors:?}"),
    )
}

#[test]
fn artifact_contract_rejects_stale_source_commit() -> TestResult {
    let root = workspace_root()?;
    let mut artifact =
        load_json(&root.join("tests/conformance/membrane_overhead_baseline.v1.json"))?;
    artifact["benchmark_records"][0]["source_commit"] =
        serde_json::Value::String("0000000000000000000000000000000000000000".to_string());
    let errors = artifact_contract_errors(&artifact);
    require(
        errors
            .iter()
            .any(|error| error.contains("source_commit is stale or mismatched")),
        format!("stale-source negative test did not fail as expected: {errors:?}"),
    )
}

#[test]
fn artifact_contract_rejects_variance_policy_regression() -> TestResult {
    let root = workspace_root()?;
    let mut artifact =
        load_json(&root.join("tests/conformance/membrane_overhead_baseline.v1.json"))?;
    artifact["benchmark_records"][0]["variance"]["p95_minus_p50_ns"] =
        serde_json::Value::from(-1.0);
    let errors = artifact_contract_errors(&artifact);
    require(
        errors
            .iter()
            .any(|error| error.contains("p95 variance mismatch"))
            || errors
                .iter()
                .any(|error| error.contains("variance must be non-negative")),
        format!("variance negative test did not fail as expected: {errors:?}"),
    )
}

#[test]
fn artifact_contract_rejects_threshold_decision_drift() -> TestResult {
    let root = workspace_root()?;
    let mut artifact =
        load_json(&root.join("tests/conformance/membrane_overhead_baseline.v1.json"))?;
    artifact["benchmark_records"][0]["decision"] =
        serde_json::Value::String("captured_over_target_for_optimization".to_string());
    let errors = artifact_contract_errors(&artifact);
    require(
        errors
            .iter()
            .any(|error| error.contains("decision mismatch")),
        format!("decision negative test did not fail as expected: {errors:?}"),
    )
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

    let artifact_benchmarks = artifact["benchmarks"]
        .as_array()
        .ok_or_else(|| "artifact benchmarks must be array".to_string())?;
    for row in artifact_benchmarks {
        let name = row["name"]
            .as_str()
            .ok_or_else(|| "artifact benchmark row missing name".to_string())?;
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
    )?;

    let log_content =
        std::fs::read_to_string(&log).map_err(|err| format!("{}: {err}", log.display()))?;
    for line in log_content.lines().filter(|line| !line.trim().is_empty()) {
        let row: serde_json::Value =
            serde_json::from_str(line).map_err(|err| format!("bad jsonl row: {err}: {line}"))?;
        for field in REQUIRED_RECORD_FIELDS {
            require(
                row.get(*field).is_some(),
                format!("jsonl row missing {field}: {line}"),
            )?;
        }
        require(
            row["trace_id"]
                .as_str()
                .map(|trace_id| trace_id.starts_with("bd-bp8fl.8.2::"))
                == Some(true),
            format!("jsonl trace_id not scoped to bead: {line}"),
        )?;
        require(
            row["runtime_mode"].as_str() == Some("strict")
                || row["runtime_mode"].as_str() == Some("hardened"),
            format!("jsonl runtime_mode invalid: {line}"),
        )?;
        require(
            row["latency_ns"].as_f64().is_some(),
            format!("jsonl latency_ns missing: {line}"),
        )?;
        require(
            row["variance"].is_object(),
            format!("jsonl variance missing: {line}"),
        )?;
    }
    Ok(())
}
