//! Integration test: feature parity gap grouping gate (bd-bp8fl.3.1)
//!
//! Validates that all feature_parity_gap_ledger.v1.json gaps are grouped into
//! actionable batches exactly once, with explicit owner/evidence dimensions.

use std::collections::{HashMap, HashSet};
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

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

#[test]
fn artifact_exists_and_has_required_shape() {
    let root = workspace_root();
    let artifact = load_json(&root.join("tests/conformance/feature_parity_gap_groups.v1.json"));
    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-bp8fl.3.1"));
    assert!(artifact["inputs"].is_object(), "inputs must be object");
    assert!(
        artifact["batch_policy"].is_object(),
        "batch_policy must be object"
    );
    assert!(artifact["batches"].is_array(), "batches must be array");
    assert!(artifact["summary"].is_object(), "summary must be object");

    let batches = artifact["batches"].as_array().unwrap();
    assert!(batches.len() >= 10, "batches should not collapse the plan");
    for batch in batches {
        let batch_id = batch["batch_id"].as_str().unwrap_or("<missing batch_id>");
        for field in [
            "title",
            "feature_parity_sections",
            "symbol_family",
            "evidence_artifacts",
            "source_owner",
            "priority",
            "gap_count",
            "gap_ids",
            "actionable_next_step",
        ] {
            assert!(!batch[field].is_null(), "{batch_id}: missing {field}");
        }
        assert!(
            !batch["feature_parity_sections"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{batch_id}: feature_parity_sections must not be empty"
        );
        assert!(
            !batch["evidence_artifacts"].as_array().unwrap().is_empty(),
            "{batch_id}: evidence_artifacts must not be empty"
        );
    }
}

#[test]
fn batches_cover_every_ledger_gap_exactly_once() {
    let root = workspace_root();
    let artifact = load_json(&root.join("tests/conformance/feature_parity_gap_groups.v1.json"));
    let ledger = load_json(&root.join("tests/conformance/feature_parity_gap_ledger.v1.json"));

    let ledger_ids: HashSet<String> = ledger["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|gap| gap["gap_id"].as_str().unwrap().to_string())
        .collect();

    let mut seen = HashSet::new();
    let mut duplicates = Vec::new();
    for batch in artifact["batches"].as_array().unwrap() {
        let gap_ids = batch["gap_ids"].as_array().unwrap();
        assert_eq!(
            batch["gap_count"].as_u64(),
            Some(gap_ids.len() as u64),
            "{}: gap_count mismatch",
            batch["batch_id"].as_str().unwrap()
        );
        for gap_id in gap_ids {
            let id = gap_id.as_str().unwrap().to_string();
            if !seen.insert(id.clone()) {
                duplicates.push(id);
            }
        }
    }

    let missing: Vec<_> = ledger_ids.difference(&seen).collect();
    let extra: Vec<_> = seen.difference(&ledger_ids).collect();
    assert!(duplicates.is_empty(), "duplicate gap ids: {duplicates:?}");
    assert!(missing.is_empty(), "missing gap ids: {missing:?}");
    assert!(extra.is_empty(), "unknown gap ids: {extra:?}");
}

#[test]
fn summary_counts_match_ledger_and_batches() {
    let root = workspace_root();
    let artifact = load_json(&root.join("tests/conformance/feature_parity_gap_groups.v1.json"));
    let ledger = load_json(&root.join("tests/conformance/feature_parity_gap_ledger.v1.json"));

    let batches = artifact["batches"].as_array().unwrap();
    let batched_gap_count: usize = batches
        .iter()
        .map(|batch| batch["gap_ids"].as_array().unwrap().len())
        .sum();
    let ledger_gaps = ledger["gaps"].as_array().unwrap();

    let mut by_section: HashMap<String, u64> = HashMap::new();
    for gap in ledger_gaps {
        let section = gap["section"].as_str().unwrap_or("machine_delta");
        *by_section.entry(section.to_string()).or_insert(0) += 1;
    }

    let summary = artifact["summary"].as_object().unwrap();
    assert_eq!(
        summary.get("ledger_gap_count").and_then(|v| v.as_u64()),
        Some(ledger_gaps.len() as u64)
    );
    assert_eq!(
        summary.get("batch_count").and_then(|v| v.as_u64()),
        Some(batches.len() as u64)
    );
    assert_eq!(
        summary.get("batched_gap_count").and_then(|v| v.as_u64()),
        Some(batched_gap_count as u64)
    );
    assert_eq!(
        summary.get("by_feature_parity_section").unwrap(),
        &serde_json::to_value(by_section).unwrap()
    );
}

#[test]
fn gate_script_passes_and_emits_structured_report_and_log() {
    let root = workspace_root();
    let script = root.join("scripts/check_feature_parity_gap_groups.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_feature_parity_gap_groups.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run feature parity gap groups gate");
    assert!(
        output.status.success(),
        "feature parity gap groups gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/feature_parity_gap_groups.report.json");
    let log_path = root.join("target/conformance/feature_parity_gap_groups.log.jsonl");
    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.3.1"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    for check in [
        "json_parse",
        "top_level_shape",
        "batch_schema",
        "unique_batch_ids",
        "exact_gap_coverage",
        "summary_counts",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "report checks.{check} should pass"
        );
    }

    let log_line = std::fs::read_to_string(&log_path)
        .expect("log should be readable")
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log should contain at least one row")
        .to_string();
    let event: serde_json::Value = serde_json::from_str(&log_line).expect("log row should parse");
    for key in [
        "trace_id",
        "bead_id",
        "scenario_id",
        "runtime_mode",
        "replacement_level",
        "api_family",
        "symbol",
        "oracle_kind",
        "expected",
        "actual",
        "errno",
        "decision_path",
        "healing_action",
        "latency_ns",
        "artifact_refs",
        "source_commit",
        "target_dir",
        "failure_signature",
    ] {
        assert!(event.get(key).is_some(), "structured log row missing {key}");
    }
}
