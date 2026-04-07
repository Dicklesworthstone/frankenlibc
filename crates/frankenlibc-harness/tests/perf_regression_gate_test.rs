//! Integration test: Perf regression attribution gate contract (bd-w2c3.8.3)
//!
//! Validates that:
//! 1. Perf regression attribution policy JSON exists and is valid.
//! 2. Threshold evaluator resolves mode/benchmark thresholds deterministically.
//! 3. Regression classification logic is stable.
//! 4. Attribution map covers baseline benchmark IDs.
//! 5. Logging + summary contracts are complete.
//! 6. E2E intentional-regression scenario and gate script pass.
//!
//! Run: cargo test -p frankenlibc-harness --test perf_regression_gate_test

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_policy() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/perf_regression_attribution.v1.json");
    let content = std::fs::read_to_string(&path)
        .expect("tests/conformance/perf_regression_attribution.v1.json should exist");
    serde_json::from_str(&content)
        .expect("tests/conformance/perf_regression_attribution.v1.json should be valid JSON")
}

fn load_baseline() -> serde_json::Value {
    let path = workspace_root().join("scripts/perf_baseline.json");
    let content = std::fs::read_to_string(&path).expect("scripts/perf_baseline.json should exist");
    serde_json::from_str(&content).expect("scripts/perf_baseline.json should be valid JSON")
}

fn resolve_threshold(policy: &serde_json::Value, mode: &str, benchmark_id: &str) -> Option<f64> {
    policy["threshold_policy"]["per_benchmark_overrides"][benchmark_id][mode]
        .as_f64()
        .or_else(|| policy["threshold_policy"]["per_mode_max_regression_pct"][mode].as_f64())
        .or_else(|| policy["threshold_policy"]["default_max_regression_pct"].as_f64())
}

fn resolve_warning_threshold(
    policy: &serde_json::Value,
    mode: &str,
    benchmark_id: &str,
) -> Option<f64> {
    policy["warning_policy"]["per_benchmark_overrides"][benchmark_id][mode]
        .as_f64()
        .or_else(|| policy["warning_policy"]["per_mode_warning_pct"][mode].as_f64())
        .or_else(|| policy["warning_policy"]["default_warning_pct"].as_f64())
}

fn classify_regression(
    observed: f64,
    baseline: f64,
    target: f64,
    warning_pct: f64,
    threshold_pct: f64,
) -> &'static str {
    let warning_threshold = baseline * (1.0 + warning_pct / 100.0);
    let threshold = baseline * (1.0 + threshold_pct / 100.0);
    let warning_hit = observed > warning_threshold;
    let baseline_ok = observed <= threshold;
    let target_ok = observed <= target;
    match (baseline_ok, target_ok) {
        (true, true) if warning_hit => "baseline_warning",
        (true, true) => "ok",
        (false, true) => "baseline_regression",
        (true, false) => "target_budget_violation",
        (false, false) => "baseline_and_budget_violation",
    }
}

fn resolve_suspect_component(policy: &serde_json::Value, benchmark_id: &str) -> String {
    policy["attribution"]["suspect_component_map"][benchmark_id]
        .as_str()
        .map(str::to_owned)
        .or_else(|| {
            policy["attribution"]["unknown_component_label"]
                .as_str()
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown_component".to_string())
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("frankenlibc-{label}-{nanos}"));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

#[cfg(unix)]
fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut perms = fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("set permissions");
}

#[test]
fn policy_exists_and_valid() {
    let policy = load_policy();
    assert!(
        policy["schema_version"].is_number(),
        "Missing schema_version"
    );
    assert!(
        policy["threshold_policy"].is_object(),
        "Missing threshold_policy"
    );
    assert!(policy["attribution"].is_object(), "Missing attribution");
    assert!(
        policy["logging_contract"].is_object(),
        "Missing logging_contract"
    );
    assert!(
        policy["auto_throttle_policy"].is_object(),
        "Missing auto_throttle_policy"
    );
    assert!(policy["triage_guide"].is_object(), "Missing triage_guide");
    assert!(
        policy["intentional_regression_scenario"].is_object(),
        "Missing intentional_regression_scenario"
    );
}

#[test]
fn threshold_resolver_deterministic() {
    let policy = load_policy();
    let default_pct = policy["threshold_policy"]["default_max_regression_pct"]
        .as_f64()
        .unwrap();

    let decide_strict = resolve_threshold(&policy, "strict", "runtime_math/decide").unwrap();
    assert_eq!(
        decide_strict, 20.0,
        "runtime_math/decide should resolve strict per-mode threshold"
    );

    let observe_strict = resolve_threshold(&policy, "strict", "runtime_math/observe_fast").unwrap();
    assert_eq!(
        observe_strict, 10.0,
        "runtime_math/observe_fast should resolve benchmark override"
    );

    let unknown = resolve_threshold(&policy, "strict", "unknown/bench").unwrap();
    assert_eq!(
        unknown, default_pct,
        "unknown benchmark should fall back to default threshold"
    );
}

#[test]
fn warning_threshold_resolver_deterministic() {
    let policy = load_policy();
    let default_pct = policy["warning_policy"]["default_warning_pct"]
        .as_f64()
        .unwrap();

    let decide_strict =
        resolve_warning_threshold(&policy, "strict", "runtime_math/decide").unwrap();
    assert_eq!(
        decide_strict, 5.0,
        "runtime_math/decide should resolve strict per-mode warning threshold"
    );

    let observe_strict =
        resolve_warning_threshold(&policy, "strict", "runtime_math/observe_fast").unwrap();
    assert_eq!(
        observe_strict, 4.0,
        "runtime_math/observe_fast should resolve warning benchmark override"
    );

    let unknown = resolve_warning_threshold(&policy, "strict", "unknown/bench").unwrap();
    assert_eq!(
        unknown, default_pct,
        "unknown benchmark should fall back to warning default threshold"
    );
}

#[test]
fn regression_classifier_stable() {
    assert_eq!(
        classify_regression(100.0, 100.0, 120.0, 5.0, 20.0),
        "ok",
        "within warning threshold and target"
    );
    assert_eq!(
        classify_regression(107.0, 100.0, 120.0, 5.0, 20.0),
        "baseline_warning",
        "exceeds warning threshold but not blocking threshold"
    );
    assert_eq!(
        classify_regression(121.0, 100.0, 200.0, 5.0, 20.0),
        "baseline_regression",
        "exceeds baseline threshold only"
    );
    assert_eq!(
        classify_regression(80.0, 70.0, 75.0, 5.0, 20.0),
        "target_budget_violation",
        "within baseline threshold but above target budget"
    );
    assert_eq!(
        classify_regression(121.0, 100.0, 90.0, 5.0, 20.0),
        "baseline_and_budget_violation",
        "exceeds both baseline threshold and target budget"
    );
}

#[test]
fn attribution_map_covers_baseline_benchmarks() {
    let policy = load_policy();
    let baseline = load_baseline();

    let mut required = HashSet::new();
    let suites = baseline["baseline_p50_ns_op"]
        .as_object()
        .expect("baseline_p50_ns_op must be object");
    for (suite, modes) in suites {
        let mode_obj = modes
            .as_object()
            .expect("baseline suite mode map must be object");
        for benches in mode_obj.values() {
            let bench_obj = benches
                .as_object()
                .expect("baseline bench map must be object");
            for bench in bench_obj.keys() {
                required.insert(format!("{suite}/{bench}"));
            }
        }
    }

    for benchmark_id in &required {
        let suspect = resolve_suspect_component(&policy, benchmark_id);
        assert_ne!(
            suspect, "unknown_component",
            "{benchmark_id} must have explicit suspect component mapping"
        );
    }
}

#[test]
fn logging_contract_complete() {
    let policy = load_policy();
    let required_fields: HashSet<&str> = policy["logging_contract"]["required_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    for field in [
        "timestamp",
        "trace_id",
        "event",
        "mode",
        "benchmark_id",
        "threshold",
        "observed",
        "regression_class",
        "suspect_component",
        "confidence",
        "commit_window",
        "host_state",
        "throttle_action",
    ] {
        assert!(
            required_fields.contains(field),
            "logging_contract.required_fields missing {field}"
        );
    }
}

#[test]
fn auto_throttle_contract_complete() {
    let policy = load_policy();
    let auto = &policy["auto_throttle_policy"];
    let required_log_fields: HashSet<&str> = auto["required_log_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    for field in [
        "event",
        "trace_id",
        "host_state",
        "throttle_action",
        "load1",
        "cpus",
        "threshold",
        "max_load_factor",
        "load_source",
    ] {
        assert!(
            required_log_fields.contains(field),
            "auto_throttle_policy.required_log_fields missing {field}"
        );
    }

    let required_report_fields: HashSet<&str> = auto["required_report_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    for field in [
        "status",
        "host_state",
        "throttle_action",
        "host_context",
        "summary",
        "event_log_path",
    ] {
        assert!(
            required_report_fields.contains(field),
            "auto_throttle_policy.required_report_fields missing {field}"
        );
    }

    assert_eq!(
        auto["scenario"]["script"].as_str(),
        Some("scripts/e2e_perf_regression_scenario.sh")
    );
    assert_eq!(auto["scenario"]["scenario"].as_str(), Some("overloaded"));
}

#[test]
fn triage_contract_complete() {
    let policy = load_policy();
    let classes: HashSet<&str> = policy["attribution"]["regression_classes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    for class in [
        "ok",
        "baseline_warning",
        "baseline_regression",
        "target_budget_violation",
        "baseline_and_budget_violation",
    ] {
        assert!(classes.contains(class), "missing regression class {class}");
    }

    let triage = policy["triage_guide"].as_object().unwrap();
    for class in [
        "baseline_warning",
        "baseline_regression",
        "target_budget_violation",
        "baseline_and_budget_violation",
    ] {
        let entry = &triage[class];
        assert!(
            entry["actions"].is_array() && !entry["actions"].as_array().unwrap().is_empty(),
            "triage_guide.{class}.actions must be non-empty"
        );
        assert!(
            entry["commands"].is_array() && !entry["commands"].as_array().unwrap().is_empty(),
            "triage_guide.{class}.commands must be non-empty"
        );
    }
}

#[test]
fn summary_consistent() {
    let policy = load_policy();
    let summary = &policy["summary"];

    let mapped = policy["attribution"]["suspect_component_map"]
        .as_object()
        .unwrap()
        .len();
    let classes = policy["attribution"]["regression_classes"]
        .as_array()
        .unwrap()
        .len();
    let required_log_fields = policy["logging_contract"]["required_fields"]
        .as_array()
        .unwrap()
        .len();
    let playbooks = policy["triage_guide"].as_object().unwrap().len();
    let auto_throttle_actions = policy["auto_throttle_policy"]["actions"]
        .as_array()
        .unwrap()
        .len();

    let expected = HashMap::from([
        ("mapped_benchmarks", mapped),
        ("regression_classes", classes),
        ("required_log_fields", required_log_fields),
        ("triage_playbooks", playbooks),
        ("auto_throttle_actions", auto_throttle_actions),
    ]);

    for (key, actual) in expected {
        let claimed = summary[key].as_u64().unwrap() as usize;
        assert_eq!(claimed, actual, "{key} mismatch");
    }
}

#[test]
fn gate_scripts_exist_and_executable() {
    let root = workspace_root();
    for script in [
        "scripts/check_perf_regression_gate.sh",
        "scripts/e2e_perf_regression_scenario.sh",
        "scripts/check_benchmark_gate.sh",
    ] {
        let path = root.join(script);
        assert!(path.exists(), "{script} must exist");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&path).unwrap().permissions();
            assert!(perms.mode() & 0o111 != 0, "{script} must be executable");
        }
    }
}

#[test]
fn e2e_intentional_regression_script_passes() {
    let root = workspace_root();
    let status = std::process::Command::new("bash")
        .arg(root.join("scripts/e2e_perf_regression_scenario.sh"))
        .arg("--scenario")
        .arg("regression")
        .current_dir(&root)
        .status()
        .expect("failed to run scripts/e2e_perf_regression_scenario.sh");
    assert!(
        status.success(),
        "scripts/e2e_perf_regression_scenario.sh should pass"
    );
}

#[test]
fn e2e_overloaded_host_script_passes() {
    let root = workspace_root();
    let status = std::process::Command::new("bash")
        .arg(root.join("scripts/e2e_perf_regression_scenario.sh"))
        .arg("--scenario")
        .arg("overloaded")
        .current_dir(&root)
        .status()
        .expect("failed to run overloaded auto-throttle scenario");
    assert!(
        status.success(),
        "scripts/e2e_perf_regression_scenario.sh --scenario overloaded should pass"
    );
}

#[test]
fn full_gate_script_passes() {
    let root = workspace_root();
    let status = std::process::Command::new("bash")
        .arg(root.join("scripts/check_perf_regression_gate.sh"))
        .current_dir(&root)
        .status()
        .expect("failed to run scripts/check_perf_regression_gate.sh");
    assert!(
        status.success(),
        "scripts/check_perf_regression_gate.sh should pass"
    );
}

#[test]
fn benchmark_gate_wrapper_invokes_rch_with_expected_contract() {
    let root = workspace_root();
    let temp = temp_dir("benchmark-gate-wrapper");
    let fake_bin = temp.join("bin");
    let rch_log = temp.join("rch.log");
    fs::create_dir_all(&fake_bin).expect("create fake bin");

    let fake_rch = fake_bin.join("rch");
    fs::write(
        &fake_rch,
        r#"#!/usr/bin/env bash
printf '%s\n' "$@" >"${RCH_LOG}"
"#,
    )
    .expect("write fake rch");
    #[cfg(unix)]
    set_executable(&fake_rch);

    let output = std::process::Command::new("bash")
        .arg(root.join("scripts/check_benchmark_gate.sh"))
        .current_dir(&root)
        .env("PATH", format!("{}:/usr/bin:/bin", fake_bin.display()))
        .env("RCH_LOG", &rch_log)
        .env("FRANKENLIBC_PERF_MAX_REGRESSION_PCT", "17")
        .env("FRANKENLIBC_PERF_ALLOW_TARGET_VIOLATION", "0")
        .env("FRANKENLIBC_PERF_SKIP_OVERLOADED", "0")
        .env("FRANKENLIBC_PERF_ENABLE_KERNEL_SUITE", "1")
        .env("FRANKENLIBC_PERF_REPORT", "target/conformance/perf_gate.wrapper.report.json")
        .env("FRANKENLIBC_PERF_EVENT_LOG", "target/conformance/perf_gate.wrapper.log.jsonl")
        .output()
        .expect("run benchmark gate wrapper");

    assert!(
        output.status.success(),
        "check_benchmark_gate.sh should pass with fake rch\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let logged = fs::read_to_string(&rch_log).expect("read fake rch log");
    assert!(logged.contains("exec"), "rch wrapper should call exec");
    assert!(
        logged.contains("FRANKENLIBC_PERF_MAX_REGRESSION_PCT=17"),
        "rch call should forward max regression override"
    );
    assert!(
        logged.contains("FRANKENLIBC_PERF_ALLOW_TARGET_VIOLATION=0"),
        "rch call should forward target-violation policy"
    );
    assert!(
        logged.contains("FRANKENLIBC_PERF_SKIP_OVERLOADED=0"),
        "rch call should forward overload policy"
    );
    assert!(
        logged.contains("FRANKENLIBC_PERF_ENABLE_KERNEL_SUITE=1"),
        "rch call should forward kernel-suite toggle"
    );
    assert!(
        logged.contains("FRANKENLIBC_PERF_REPORT=target/conformance/perf_gate.wrapper.report.json"),
        "rch call should forward perf report path"
    );
    assert!(
        logged.contains("FRANKENLIBC_PERF_EVENT_LOG=target/conformance/perf_gate.wrapper.log.jsonl"),
        "rch call should forward perf event log path"
    );
    assert!(
        logged.contains("scripts/perf_gate.sh"),
        "rch call should route through scripts/perf_gate.sh"
    );
}
