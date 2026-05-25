//! bd-38x82.5: Hardened mode same-harness 2x benchmark contract.

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const LIVE_GATE_ENV: &str = "FRANKENLIBC_REQUIRE_LIVE_HARDENED_2X_GATE";
const MAX_STRICT_HARDENED_RATIO: f64 = 2.0;
const MISSING_ARTIFACT_SIGNATURE: &str = "missing_benchmark_artifact";
const RATIO_REGRESSION_SIGNATURE: &str = "hardened_2x_regression";
const WORKLOAD_MISMATCH_SIGNATURE: &str = "strict_hardened_workload_mismatch";
const REQUIRED_COMMON_SYMBOLS: [&str; 2] = ["memcpy", "malloc/free"];

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| test_error("crate manifest should have crates parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have workspace parent"))?
        .to_path_buf())
}

fn bench_artifact_path(root: &Path) -> PathBuf {
    root.join("target/conformance/bd-wpr1n/smoke/strict_hardened_membrane_overhead.v1.json")
}

fn glibc_baseline_artifact_path(root: &Path) -> PathBuf {
    root.join("artifacts/perf/glibc-baseline.md")
}

fn validate_live_hardened_2x_contract(
    artifact_path: &Path,
    baseline_path: &Path,
) -> TestResult<usize> {
    if !artifact_path.exists() {
        return Err(test_error(format!(
            "{MISSING_ARTIFACT_SIGNATURE}: {}",
            artifact_path.display()
        )));
    }
    if !baseline_path.exists() {
        return Err(test_error(format!(
            "missing_glibc_baseline_artifact: {}",
            baseline_path.display()
        )));
    }

    let artifact: Value = serde_json::from_str(&fs::read_to_string(artifact_path)?)?;
    let baseline = fs::read_to_string(baseline_path)?;
    validate_hardened_2x_contract(&artifact, &baseline)
}

fn validate_hardened_2x_contract(artifact: &Value, baseline_markdown: &str) -> TestResult<usize> {
    let host_means = host_glibc_mean_by_symbol(baseline_markdown)?;
    let records = artifact
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("benchmark artifact must contain records array"))?;

    let mut checked = 0usize;
    for symbol in REQUIRED_COMMON_SYMBOLS {
        if !host_means.contains_key(symbol) {
            return Err(test_error(format!(
                "missing host glibc context baseline for {symbol}"
            )));
        }

        let strict = mode_record_for_symbol(records, "strict", symbol)?;
        let hardened = mode_record_for_symbol(records, "hardened", symbol)?;
        if strict.workload != hardened.workload {
            return Err(test_error(format!(
                "{WORKLOAD_MISMATCH_SIGNATURE}: {symbol} strict workload {:?} does not match hardened workload {:?}",
                strict.workload, hardened.workload
            )));
        }

        let max_allowed = MAX_STRICT_HARDENED_RATIO * strict.mean_ns_op;
        if hardened.mean_ns_op > max_allowed {
            return Err(test_error(format!(
                "{RATIO_REGRESSION_SIGNATURE}: {symbol} hardened mean_ns_op {:.3} exceeds {MAX_STRICT_HARDENED_RATIO:.1}x strict same-harness mean {:.3}",
                hardened.mean_ns_op, strict.mean_ns_op
            )));
        }
        checked += 1;
    }

    Ok(checked)
}

#[derive(Debug, Clone, PartialEq)]
struct ModeRecord {
    workload: String,
    mean_ns_op: f64,
}

fn mode_record_for_symbol(
    records: &[Value],
    runtime_mode: &str,
    symbol: &str,
) -> TestResult<ModeRecord> {
    let record = records
        .iter()
        .find(|record| {
            record.get("runtime_mode").and_then(Value::as_str) == Some(runtime_mode)
                && record.get("symbol").and_then(Value::as_str) == Some(symbol)
        })
        .ok_or_else(|| test_error(format!("missing {runtime_mode} row for {symbol}")))?;
    let workload = record
        .get("workload")
        .and_then(Value::as_str)
        .ok_or_else(|| test_error(format!("missing {runtime_mode} workload for {symbol}")))?;
    let mean_ns_op = record
        .get("mean_ns_op")
        .and_then(Value::as_f64)
        .ok_or_else(|| test_error(format!("missing {runtime_mode} mean_ns_op for {symbol}")))?;

    Ok(ModeRecord {
        workload: workload.to_owned(),
        mean_ns_op,
    })
}

fn host_glibc_mean_by_symbol(markdown: &str) -> TestResult<BTreeMap<String, f64>> {
    let mut means = BTreeMap::new();
    for line in markdown.lines() {
        if !line.contains("GLIBC_BASELINE_BENCH") || !line.contains(" impl=host_glibc ") {
            continue;
        }
        let symbol = extract_raw_row_field(line, "symbol")
            .ok_or_else(|| test_error("host glibc baseline row missing symbol"))?;
        let mean = extract_raw_row_field(line, "mean_ns_op")
            .ok_or_else(|| test_error(format!("{symbol} host glibc row missing mean_ns_op")))?
            .parse::<f64>()
            .map_err(|err| test_error(format!("{symbol} host glibc mean_ns_op invalid: {err}")))?;
        means.insert(symbol, mean);
    }

    if means.is_empty() {
        return Err(test_error("host glibc baseline has no raw benchmark rows"));
    }
    Ok(means)
}

fn extract_raw_row_field(line: &str, field: &str) -> Option<String> {
    let marker = format!("{field}=");
    let rest = line.split_once(&marker)?.1;
    if let Some(quoted) = rest.strip_prefix('"') {
        return quoted.split_once('"').map(|(value, _)| value.to_owned());
    }
    rest.split_whitespace()
        .next()
        .map(|value| value.trim_end_matches(',').to_owned())
}

fn fixture_artifact(
    memcpy_strict_mean: f64,
    memcpy_hardened_mean: f64,
    malloc_strict_mean: f64,
    malloc_hardened_mean: f64,
) -> Value {
    json!({
        "schema_version": "v1",
        "records": [
            {
                "runtime_mode": "strict",
                "symbol": "memcpy",
                "workload": "64-byte copy plus membrane decision",
                "mean_ns_op": memcpy_strict_mean
            },
            {
                "runtime_mode": "hardened",
                "symbol": "memcpy",
                "workload": "64-byte copy plus membrane decision",
                "mean_ns_op": memcpy_hardened_mean
            },
            {
                "runtime_mode": "strict",
                "symbol": "malloc/free",
                "workload": "small allocation lifetime plus membrane decision",
                "mean_ns_op": malloc_strict_mean
            },
            {
                "runtime_mode": "hardened",
                "symbol": "malloc/free",
                "workload": "small allocation lifetime plus membrane decision",
                "mean_ns_op": malloc_hardened_mean
            }
        ]
    })
}

fn fixture_glibc_baseline() -> &'static str {
    r#"
GLIBC_BASELINE_BENCH profile_id=memcpy_4096 impl=host_glibc api_family=string symbol=memcpy workload="4096 byte copy" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=32 p50_ns_op=36.398 p95_ns_op=42.500 p99_ns_op=130.000 mean_ns_op=40.000 throughput_ops_s=30389129.737 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=tests/conformance/fixtures/string_memory_full
GLIBC_BASELINE_BENCH profile_id=malloc_free_64 impl=host_glibc api_family=malloc symbol=malloc/free workload="64 byte allocate-free cycle" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=35 p50_ns_op=5.705 p95_ns_op=20.000 p99_ns_op=70.000 mean_ns_op=10.000 throughput_ops_s=189859938.236 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=crates/frankenlibc-core/src/malloc
"#
}

#[test]
fn strict_hardened_benchmark_harness_exists() -> TestResult {
    let bench_path = workspace_root()?
        .join("crates/frankenlibc-bench/benches/strict_hardened_overhead_harness.rs");
    assert!(
        bench_path.exists(),
        "strict_hardened_overhead_harness.rs should exist"
    );
    Ok(())
}

#[test]
fn glibc_baseline_benchmark_exists() -> TestResult {
    let bench_path =
        workspace_root()?.join("crates/frankenlibc-bench/benches/glibc_baseline_bench.rs");
    assert!(bench_path.exists(), "glibc_baseline_bench.rs should exist");
    Ok(())
}

#[test]
fn live_gate_rejects_missing_benchmark_artifact() -> TestResult {
    let root = workspace_root()?;
    let missing = root.join("target/conformance/bd-38x82.5/missing-overhead.json");
    let err = validate_live_hardened_2x_contract(&missing, &glibc_baseline_artifact_path(&root))
        .expect_err("missing benchmark artifacts must fail closed");

    assert!(
        err.to_string().contains(MISSING_ARTIFACT_SIGNATURE),
        "{err}"
    );
    Ok(())
}

#[test]
fn contract_accepts_valid_same_harness_2x_fixture() -> TestResult {
    let checked = validate_hardened_2x_contract(
        &fixture_artifact(40.0, 79.0, 10.0, 19.0),
        fixture_glibc_baseline(),
    )?;

    assert_eq!(checked, REQUIRED_COMMON_SYMBOLS.len());
    Ok(())
}

#[test]
fn contract_rejects_same_harness_2x_regression_fixture() {
    let err = validate_hardened_2x_contract(
        &fixture_artifact(40.0, 79.0, 10.0, 21.0),
        fixture_glibc_baseline(),
    )
    .expect_err("hardened rows above 2x strict same-harness rows must fail");

    assert!(err.to_string().contains(RATIO_REGRESSION_SIGNATURE));
}

#[test]
fn contract_rejects_strict_hardened_workload_mismatch() {
    let artifact = json!({
        "schema_version": "v1",
        "records": [
            {
                "runtime_mode": "strict",
                "symbol": "memcpy",
                "workload": "4096 byte copy",
                "mean_ns_op": 40.0
            },
            {
                "runtime_mode": "hardened",
                "symbol": "memcpy",
                "workload": "64-byte copy plus membrane decision",
                "mean_ns_op": 41.0
            },
            {
                "runtime_mode": "strict",
                "symbol": "malloc/free",
                "workload": "small allocation lifetime plus membrane decision",
                "mean_ns_op": 10.0
            },
            {
                "runtime_mode": "hardened",
                "symbol": "malloc/free",
                "workload": "small allocation lifetime plus membrane decision",
                "mean_ns_op": 11.0
            }
        ]
    });
    let err = validate_hardened_2x_contract(&artifact, fixture_glibc_baseline())
        .expect_err("strict and hardened rows must use the same workload");

    assert!(err.to_string().contains(WORKLOAD_MISMATCH_SIGNATURE));
}

#[test]
fn hardened_mode_2x_bound_coverage_report() -> TestResult {
    let root = workspace_root()?;
    let live_gate_required = std::env::var_os(LIVE_GATE_ENV).is_some();
    let status = if live_gate_required {
        validate_live_hardened_2x_contract(
            &bench_artifact_path(&root),
            &glibc_baseline_artifact_path(&root),
        )?;
        "implemented"
    } else {
        "blocked_pending_live_benchmark_artifact"
    };

    eprintln!(
        "{}",
        json!({
            "family": "hardened-2x-bound",
            "reference": "strict_same_harness",
            "host_glibc_context": true,
            "tests": 7,
            "status": status,
            "implemented": live_gate_required,
            "live_gate_env": LIVE_GATE_ENV,
            "max_strict_hardened_ratio": MAX_STRICT_HARDENED_RATIO
        })
    );
    Ok(())
}
