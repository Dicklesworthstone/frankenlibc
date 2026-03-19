// fuzz_phase2_targets_test.rs — bd-1oz.7
// Integration tests for phase-2 fuzz readiness and nightly policy coverage.

use std::path::Path;
use std::process::Command;

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

#[test]
fn phase2_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase2_targets.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_fuzz_phase2_targets.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute phase-2 target generator");
    assert!(
        output.status.success(),
        "Phase-2 target generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn phase2_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase2_targets.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-1oz.7"));
    assert!(data["validation_hash"].is_string());
    assert!(data["target_assessments"].is_array());
    assert!(data["smoke_test_configs"].is_object());
    assert!(data["nightly_policy"].is_object());
    assert!(data["coverage_summary"].is_object());
}

#[test]
fn phase2_targets_cover_required_transition_families() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase2_targets.v1.json");
    let data = load_json(&report_path);

    let families = data["coverage_summary"]["transition_families"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    for required in ["resolver", "locale", "runtime-math"] {
        assert!(
            families.contains(required),
            "missing transition family: {required}"
        );
    }
}

#[test]
fn phase2_targets_are_smoke_viable() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase2_targets.v1.json");
    let data = load_json(&report_path);

    let targets = data["target_assessments"].as_array().unwrap();
    assert_eq!(targets.len(), 4, "expected 4 phase-2 targets");
    for target in targets {
        let name = target["target"].as_str().unwrap_or("unknown");
        assert!(
            target["smoke_viable"].as_bool().unwrap(),
            "target {name} is not smoke-viable"
        );
    }
}

#[test]
fn phase2_nightly_policy_matches_target_inventory() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase2_targets.v1.json");
    let data = load_json(&report_path);

    let targets = data["target_assessments"].as_array().unwrap();
    let target_names = targets
        .iter()
        .map(|item| item["target"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    let policy_targets = data["nightly_policy"]["required_targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        data["nightly_policy"]["target_group"].as_str(),
        Some("phase2")
    );
    assert_eq!(data["nightly_policy"]["max_crashes"].as_u64(), Some(0));
    assert_eq!(target_names, policy_targets);
}

#[test]
fn phase2_readiness_thresholds_are_reasonable() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase2_targets.v1.json");
    let data = load_json(&report_path);

    let summary = &data["summary"];
    assert!(
        summary["average_readiness_score"].as_f64().unwrap() >= 70.0,
        "average readiness should stay above 70"
    );
    assert!(
        summary["total_symbols_covered"].as_u64().unwrap() >= 10,
        "phase-2 report should cover at least 10 symbols"
    );
}
