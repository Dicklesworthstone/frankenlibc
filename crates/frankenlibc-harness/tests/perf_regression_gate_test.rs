//! Integration test: Perf regression attribution gate contract (bd-30o.3)
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
use std::path::{Path, PathBuf};

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
        "mode",
        "benchmark_id",
        "threshold",
        "observed",
        "regression_class",
        "suspect_component",
    ] {
        assert!(
            required_fields.contains(field),
            "logging_contract.required_fields missing {field}"
        );
    }
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

    let expected = HashMap::from([
        ("mapped_benchmarks", mapped),
        ("regression_classes", classes),
        ("required_log_fields", required_log_fields),
        ("triage_playbooks", playbooks),
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
        .current_dir(&root)
        .status()
        .expect("failed to run scripts/e2e_perf_regression_scenario.sh");
    assert!(
        status.success(),
        "scripts/e2e_perf_regression_scenario.sh should pass"
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
