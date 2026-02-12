//! Integration test: Symbol fixture coverage matrix (bd-15n.1)
//!
//! Validates that:
//! 1. The canonical artifact exists and has required schema fields.
//! 2. Summary totals are consistent with symbol/family rows.
//! 3. Uncovered/weak family lists are consistent with family coverage math.
//! 4. Generator + drift-check scripts exist and are executable.
//! 5. Drift-check script passes on clean checkout.

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

fn load_artifact() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/symbol_fixture_coverage.v1.json");
    let content =
        std::fs::read_to_string(&path).expect("symbol_fixture_coverage.v1.json should exist");
    serde_json::from_str(&content).expect("symbol_fixture_coverage.v1.json should be valid JSON")
}

#[test]
fn artifact_exists_and_valid() {
    let doc = load_artifact();

    assert_eq!(
        doc["schema_version"].as_u64(),
        Some(1),
        "schema_version must be 1"
    );
    assert_eq!(doc["bead"].as_str(), Some("bd-15n.1"), "bead id mismatch");
    assert!(doc["summary"].is_object(), "Missing summary");
    assert!(doc["families"].is_array(), "Missing families[]");
    assert!(doc["symbols"].is_array(), "Missing symbols[]");
    assert!(
        doc["uncovered_target_families"].is_array(),
        "Missing uncovered_target_families[]"
    );
    assert!(
        doc["weak_target_families"].is_array(),
        "Missing weak_target_families[]"
    );
    assert!(doc["ownership_map"].is_array(), "Missing ownership_map[]");
}

#[test]
fn summary_counts_consistent() {
    let doc = load_artifact();
    let summary = &doc["summary"];
    let symbols = doc["symbols"].as_array().unwrap();
    let families = doc["families"].as_array().unwrap();

    assert_eq!(
        summary["total_exported_symbols"].as_u64().unwrap() as usize,
        symbols.len(),
        "total_exported_symbols mismatch"
    );

    let covered_exported = symbols
        .iter()
        .filter(|row| row["covered"].as_bool().unwrap_or(false))
        .count();
    assert_eq!(
        summary["covered_exported_symbols"].as_u64().unwrap() as usize,
        covered_exported,
        "covered_exported_symbols mismatch"
    );

    let target_total: u64 = families
        .iter()
        .map(|row| row["target_total"].as_u64().unwrap_or(0))
        .sum();
    let target_covered: u64 = families
        .iter()
        .map(|row| row["target_covered"].as_u64().unwrap_or(0))
        .sum();
    let target_uncovered: u64 = families
        .iter()
        .map(|row| row["target_uncovered"].as_u64().unwrap_or(0))
        .sum();

    assert_eq!(
        summary["target_total_symbols"].as_u64().unwrap(),
        target_total,
        "target_total_symbols mismatch"
    );
    assert_eq!(
        summary["target_covered_symbols"].as_u64().unwrap(),
        target_covered,
        "target_covered_symbols mismatch"
    );
    assert_eq!(
        summary["target_uncovered_symbols"].as_u64().unwrap(),
        target_uncovered,
        "target_uncovered_symbols mismatch"
    );
}

#[test]
fn uncovered_and_weak_lists_consistent() {
    let doc = load_artifact();
    let summary = &doc["summary"];
    let families = doc["families"].as_array().unwrap();

    let expected_uncovered: std::collections::BTreeSet<String> = families
        .iter()
        .filter(|row| {
            row["target_total"].as_u64().unwrap_or(0) > 0
                && row["target_covered"].as_u64().unwrap_or(0) == 0
        })
        .filter_map(|row| row["module"].as_str().map(String::from))
        .collect();
    let actual_uncovered: std::collections::BTreeSet<String> = doc["uncovered_target_families"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["module"].as_str().map(String::from))
        .collect();
    assert_eq!(
        expected_uncovered, actual_uncovered,
        "uncovered_target_families must match family rows"
    );

    let weak_threshold = summary["weak_family_threshold_pct"].as_f64().unwrap();
    let expected_weak: std::collections::BTreeSet<String> = families
        .iter()
        .filter(|row| {
            let total = row["target_total"].as_u64().unwrap_or(0);
            let pct = row["target_coverage_pct"].as_f64().unwrap_or(0.0);
            total > 0 && pct > 0.0 && pct < weak_threshold
        })
        .filter_map(|row| row["module"].as_str().map(String::from))
        .collect();
    let actual_weak: std::collections::BTreeSet<String> = doc["weak_target_families"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["module"].as_str().map(String::from))
        .collect();
    assert_eq!(
        expected_weak, actual_weak,
        "weak_target_families must match family rows"
    );
}

#[test]
fn scripts_exist_and_executable() {
    let root = workspace_root();
    let scripts = [
        "scripts/generate_symbol_fixture_coverage.py",
        "scripts/check_symbol_fixture_coverage.sh",
    ];

    for rel in scripts {
        let path = root.join(rel);
        assert!(path.exists(), "{rel} must exist");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&path).unwrap().permissions();
            assert!(perms.mode() & 0o111 != 0, "{rel} must be executable");
        }
    }
}

#[test]
fn drift_gate_script_passes() {
    let root = workspace_root();
    let script = root.join("scripts/check_symbol_fixture_coverage.sh");
    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("check_symbol_fixture_coverage.sh should execute");

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "check_symbol_fixture_coverage.sh failed\nstatus={:?}\nstdout:\n{}\nstderr:\n{}",
            output.status, stdout, stderr
        );
    }
}
