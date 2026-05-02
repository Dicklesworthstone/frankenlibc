//! Integration test: family coverage thresholds (bd-bp8fl.4.3).
//!
//! This verifies that the threshold artifact is regenerated from current
//! fixture coverage inputs, preserves every exported target family, and emits
//! structured per-family claim-gate decisions.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(rel: &str) -> serde_json::Value {
    let path = workspace_root().join(rel);
    let content = std::fs::read_to_string(&path).expect("artifact should be readable");
    serde_json::from_str(&content).expect("artifact should be valid JSON")
}

fn threshold_doc() -> serde_json::Value {
    load_json("tests/conformance/family_coverage_thresholds.v1.json")
}

#[test]
fn artifact_shape_and_counts_are_consistent() {
    let doc = threshold_doc();
    assert_eq!(doc["schema_version"].as_str(), Some("v1"));
    assert_eq!(doc["bead"].as_str(), Some("bd-bp8fl.4.3"));
    assert!(doc["inputs"].is_object(), "inputs must be present");
    assert!(
        doc["input_digests"].is_object(),
        "input_digests must be present"
    );
    assert!(
        doc["coverage_model"].is_object(),
        "coverage_model must be present"
    );
    assert!(
        doc["threshold_policy"].is_object(),
        "threshold_policy must be present"
    );
    assert!(
        doc["gaps_requiring_fixture_beads"].is_array(),
        "gaps_requiring_fixture_beads must be present"
    );

    let records = doc["threshold_records"].as_array().unwrap();
    let summary = &doc["summary"];
    assert_eq!(
        summary["family_count"].as_u64().unwrap() as usize,
        records.len(),
        "family_count must match threshold_records length"
    );

    let pass_count = records
        .iter()
        .filter(|row| row["decision"].as_str() == Some("pass"))
        .count();
    let fail_count = records
        .iter()
        .filter(|row| row["decision"].as_str() == Some("fail"))
        .count();
    let not_applicable_count = records
        .iter()
        .filter(|row| row["decision"].as_str() == Some("not_applicable"))
        .count();
    assert_eq!(summary["pass_count"].as_u64().unwrap() as usize, pass_count);
    assert_eq!(summary["fail_count"].as_u64().unwrap() as usize, fail_count);
    assert_eq!(
        summary["not_applicable_count"].as_u64().unwrap() as usize,
        not_applicable_count
    );
    if fail_count > 0 {
        assert_eq!(
            summary["claim_gate_decision"].as_str(),
            Some("blocked"),
            "failing thresholds must block readiness claims"
        );
    }
}

#[test]
fn every_target_family_has_threshold_record() {
    let doc = threshold_doc();
    let symbol_coverage = load_json("tests/conformance/symbol_fixture_coverage.v1.json");

    let expected: BTreeSet<String> = symbol_coverage["families"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["target_total"].as_u64().unwrap_or(0) > 0)
        .filter_map(|row| row["module"].as_str().map(String::from))
        .collect();
    let actual: BTreeSet<String> = doc["threshold_records"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["family_id"].as_str().map(String::from))
        .collect();
    assert_eq!(
        expected, actual,
        "threshold records must not hide any exported target family"
    );
}

#[test]
fn threshold_records_expose_required_evidence_axes() {
    let doc = threshold_doc();
    let required_record_keys = [
        "family_id",
        "threshold_id",
        "symbol_count",
        "fixture_count",
        "coverage",
        "thresholds",
        "mode_coverage",
        "replacement_level_coverage",
        "hard_parts_risk",
        "user_workload_exposure",
        "freshness_state",
        "decision",
        "failure_signature",
        "artifact_refs",
    ];
    let required_coverage_keys = [
        "target_coverage_pct",
        "direct_coverage_pct",
        "isolated_coverage_pct",
        "strict_mode_coverage_pct",
        "hardened_mode_coverage_pct",
        "dual_mode_coverage_pct",
        "l0_replacement_pct",
        "l1_replacement_pct",
        "l2_replacement_pct",
        "l3_replacement_pct",
    ];

    for row in doc["threshold_records"].as_array().unwrap() {
        for key in required_record_keys {
            assert!(row.get(key).is_some(), "{} missing {key}", row["family_id"]);
        }
        for key in required_coverage_keys {
            assert!(
                row["coverage"].get(key).is_some(),
                "{} missing coverage.{key}",
                row["family_id"]
            );
        }
        for level in ["L0", "L1", "L2", "L3"] {
            assert!(
                row["replacement_level_coverage"].get(level).is_some(),
                "{} missing replacement level {level}",
                row["family_id"]
            );
        }
        if row["decision"].as_str() == Some("fail") {
            assert_ne!(
                row["failure_signature"].as_str(),
                Some("none"),
                "{} failing row must include failure_signature",
                row["family_id"]
            );
        }
    }
}

#[test]
fn gaps_match_failing_threshold_records() {
    let doc = threshold_doc();
    let fail_ids: BTreeSet<String> = doc["threshold_records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["decision"].as_str() == Some("fail"))
        .filter_map(|row| row["family_id"].as_str().map(String::from))
        .collect();
    let gap_ids: BTreeSet<String> = doc["gaps_requiring_fixture_beads"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["family_id"].as_str().map(String::from))
        .collect();
    assert_eq!(
        fail_ids, gap_ids,
        "gap rows must correspond exactly to failing families"
    );
}

#[test]
fn generator_self_test_and_canonical_check_pass() {
    let root = workspace_root();
    let script = root.join("scripts/generate_family_coverage_thresholds.py");
    assert!(script.exists(), "generator script must exist");

    let self_test = Command::new("python3")
        .arg(&script)
        .arg("--self-test")
        .current_dir(&root)
        .output()
        .expect("generator self-test should run");
    assert!(
        self_test.status.success(),
        "generator self-test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&self_test.stdout),
        String::from_utf8_lossy(&self_test.stderr)
    );

    let check = Command::new("python3")
        .arg(&script)
        .arg("--check")
        .arg("--output")
        .arg("tests/conformance/family_coverage_thresholds.v1.json")
        .current_dir(&root)
        .output()
        .expect("generator canonical check should run");
    assert!(
        check.status.success(),
        "generator canonical check failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn shell_gate_passes_and_emits_report() {
    let root = workspace_root();
    let script = root.join("scripts/check_family_coverage_thresholds.sh");
    assert!(script.exists(), "shell gate must exist");

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("check_family_coverage_thresholds.sh should execute");
    assert!(
        output.status.success(),
        "threshold gate failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/family_coverage_thresholds.report.json");
    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&report_path).expect("threshold report should exist"),
    )
    .expect("threshold report should be valid JSON");
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.4.3"));
}
