// perf_regression_prevention_test.rs — bd-1qfc
// Integration tests for the performance regression prevention system.
// Validates: report generation, report schema, bench file coverage,
// baseline coverage for enforced suites, gate feature completeness,
// and config consistency.

use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
}

fn generated_report_path(root: &Path, label: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after UNIX_EPOCH")
        .as_nanos();
    let out_dir = root.join("target/conformance");
    std::fs::create_dir_all(&out_dir)
        .unwrap_or_else(|e| panic!("Failed to create {}: {}", out_dir.display(), e));
    out_dir.join(format!(
        "perf_regression_prevention_{label}_{}_{}.json",
        std::process::id(),
        stamp
    ))
}

#[test]
fn prevention_report_generates_successfully() {
    let root = repo_root();
    let report_path = generated_report_path(&root, "generated");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_perf_regression_prevention.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute prevention validator");
    assert!(
        output.status.success(),
        "Prevention validator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        report_path.exists(),
        "Report not generated at {}",
        report_path.display()
    );
}

#[test]
fn prevention_report_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/perf_regression_prevention.v1.json");
    assert!(
        report_path.exists(),
        "Committed report missing at {}",
        report_path.display()
    );
    let data = load_json(&report_path);

    assert_eq!(
        data["schema_version"].as_str(),
        Some("v1"),
        "Wrong schema version"
    );
    assert_eq!(
        data["bead"].as_str(),
        Some("bd-1qfc"),
        "Wrong bead reference"
    );

    // Check summary fields
    let summary = &data["summary"];
    let required_fields = [
        "total_suites_in_spec",
        "suites_with_bench_files",
        "suites_enforced_in_gate",
        "suites_with_full_baselines",
        "baseline_slot_fill_pct",
        "hotpath_symbol_coverage_pct",
        "total_hotpath_symbols",
    ];
    for field in &required_fields {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }

    // Check sections exist
    assert!(
        data["bench_file_inventory"].is_array(),
        "Missing bench_file_inventory"
    );
    assert!(
        data["baseline_coverage"].is_array(),
        "Missing baseline_coverage"
    );
    assert!(data["gate_wiring"].is_object(), "Missing gate_wiring");
    assert!(
        data["hotpath_symbol_coverage"].is_object(),
        "Missing hotpath_symbol_coverage"
    );
    assert!(
        data["config_consistency"].is_object(),
        "Missing config_consistency"
    );
}

#[test]
fn prevention_all_spec_suites_have_bench_files() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/perf_regression_prevention.v1.json");
    let data = load_json(&report_path);

    let inventory = data["bench_file_inventory"].as_array().unwrap();
    for suite in inventory {
        let suite_id = suite["suite_id"].as_str().unwrap();
        assert!(
            suite["exists"].as_bool().unwrap(),
            "Spec suite '{}' missing bench file",
            suite_id
        );
    }
}

#[test]
fn prevention_enforced_suites_have_baselines() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/perf_regression_prevention.v1.json");
    let data = load_json(&report_path);

    let inventory = data["bench_file_inventory"].as_array().unwrap();
    let enforced_ids: Vec<&str> = inventory
        .iter()
        .filter(|s| s["enforced_in_gate"].as_bool().unwrap_or(false))
        .map(|s| s["suite_id"].as_str().unwrap())
        .collect();

    let baseline_cov = data["baseline_coverage"].as_array().unwrap();
    for suite in baseline_cov {
        let suite_id = suite["suite_id"].as_str().unwrap();
        if enforced_ids.contains(&suite_id) {
            let cov = suite["coverage_pct"].as_f64().unwrap();
            assert!(
                cov >= 100.0,
                "Enforced suite '{}' has incomplete baselines ({}%)",
                suite_id,
                cov
            );
        }
    }
}

#[test]
fn prevention_gate_has_required_features() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/perf_regression_prevention.v1.json");
    let data = load_json(&report_path);

    let gate = &data["gate_wiring"];
    assert!(gate["exists"].as_bool().unwrap(), "perf_gate.sh not found");

    let features = gate["features"].as_object().unwrap();
    for (feature, present) in features {
        assert!(
            present.as_bool().unwrap(),
            "perf_gate.sh missing feature: {}",
            feature
        );
    }
}

#[test]
fn prevention_config_no_issues() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/perf_regression_prevention.v1.json");
    let data = load_json(&report_path);

    let config = &data["config_consistency"];
    let issues = config["issues"].as_array().unwrap();
    assert!(issues.is_empty(), "Config consistency issues: {:?}", issues);

    let expired = config["expired_waivers"].as_u64().unwrap();
    assert_eq!(expired, 0, "Found {expired} expired waiver(s)");
}
