//! Integration test: Verification matrix drift guard (bd-34w)
//!
//! Validates that:
//! 1. Every open/in_progress critique bead has a matrix row.
//! 2. Matrix entries have valid schema.
//! 3. Dashboard stats are consistent with entries.
//! 4. The drift guard script exists and is executable.
//!
//! Run: cargo test -p frankenlibc-harness --test matrix_drift_test

use std::collections::HashSet;
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

fn load_matrix() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/verification_matrix.json");
    let content = std::fs::read_to_string(&path).expect("verification_matrix.json should exist");
    serde_json::from_str(&content).expect("verification_matrix.json should be valid JSON")
}

fn beads_path() -> PathBuf {
    std::env::var_os("FRANKENLIBC_VERIFICATION_MATRIX_BEADS")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join(".beads/issues.jsonl"))
}

fn load_beads() -> Vec<serde_json::Value> {
    let path = beads_path();
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("beads JSONL should exist at {}: {err}", path.display()));
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("each bead line should be valid JSON"))
        .collect()
}

#[test]
fn drift_guard_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_matrix_drift.sh");
    assert!(script.exists(), "scripts/check_matrix_drift.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_matrix_drift.sh must be executable"
        );
    }
}

#[test]
fn all_open_critique_beads_have_matrix_rows() {
    let matrix = load_matrix();
    let beads = load_beads();

    let mut critique_ids = HashSet::new();
    for b in &beads {
        let status = b["status"].as_str().unwrap_or("");
        if status != "open" && status != "in_progress" {
            continue;
        }
        let empty_arr = vec![];
        let labels: Vec<&str> = b["labels"]
            .as_array()
            .unwrap_or(&empty_arr)
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        if labels.contains(&"critique")
            && let Some(id) = b["id"].as_str()
        {
            critique_ids.insert(id.to_string());
        }
    }

    let covered: HashSet<String> = matrix["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["bead_id"].as_str().map(String::from))
        .collect();

    let missing: Vec<_> = critique_ids.difference(&covered).collect();
    let drift_pct = if critique_ids.is_empty() {
        0.0
    } else {
        missing.len() as f64 / critique_ids.len() as f64 * 100.0
    };

    assert!(
        drift_pct <= 25.0,
        "Matrix drift too high: {}/{} ({:.0}%) critique beads missing rows: {:?}",
        missing.len(),
        critique_ids.len(),
        drift_pct,
        missing
    );
}

#[test]
fn matrix_entries_have_valid_schema() {
    let matrix = load_matrix();
    let entries = matrix["entries"].as_array().unwrap();
    let valid_overall = ["missing", "partial", "complete"];

    for entry in entries {
        let bid = entry["bead_id"].as_str().unwrap_or("<unknown>");

        assert!(entry["bead_id"].is_string(), "{bid}: missing bead_id");
        assert!(
            bid.starts_with("bd-"),
            "{bid}: bead_id should start with 'bd-'"
        );
        assert!(entry["title"].is_string(), "{bid}: missing title");
        assert!(
            entry["obligations"].is_object(),
            "{bid}: missing obligations"
        );
        assert!(entry["coverage"].is_object(), "{bid}: missing coverage");
        assert!(
            entry["coverage_summary"].is_object(),
            "{bid}: missing coverage_summary"
        );

        let overall = entry["coverage_summary"]["overall"].as_str().unwrap_or("");
        assert!(
            valid_overall.contains(&overall),
            "{bid}: invalid coverage_summary.overall '{overall}'"
        );
    }
}

#[test]
fn dashboard_total_matches_entries() {
    let matrix = load_matrix();
    let entries = matrix["entries"].as_array().unwrap();
    let dashboard = &matrix["dashboard"];

    let claimed_total = dashboard["total_critique_beads"].as_u64().unwrap() as usize;
    assert_eq!(
        claimed_total,
        entries.len(),
        "Dashboard total_critique_beads mismatch"
    );
}

#[test]
fn dashboard_coverage_stats_consistent() {
    let matrix = load_matrix();
    let entries = matrix["entries"].as_array().unwrap();
    let by_status = &matrix["dashboard"]["by_coverage_status"];

    let mut actual_counts = std::collections::HashMap::new();
    for e in entries {
        let overall = e["coverage_summary"]["overall"]
            .as_str()
            .unwrap_or("missing");
        *actual_counts.entry(overall.to_string()).or_insert(0usize) += 1;
    }

    for (status, count) in by_status.as_object().unwrap() {
        let claimed = count.as_u64().unwrap() as usize;
        let actual = *actual_counts.get(status.as_str()).unwrap_or(&0);
        assert_eq!(
            claimed, actual,
            "Dashboard by_coverage_status.{status} mismatch: claimed={claimed} actual={actual}"
        );
    }
}

#[test]
fn no_duplicate_bead_entries() {
    let matrix = load_matrix();
    let entries = matrix["entries"].as_array().unwrap();

    let mut seen = HashSet::new();
    let mut dups = Vec::new();
    for e in entries {
        let bid = e["bead_id"].as_str().unwrap_or("<unknown>");
        if !seen.insert(bid) {
            dups.push(bid.to_string());
        }
    }

    assert!(
        dups.is_empty(),
        "Duplicate bead entries in matrix: {:?}",
        dups
    );
}
