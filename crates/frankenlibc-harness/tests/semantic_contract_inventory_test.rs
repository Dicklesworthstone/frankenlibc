//! Integration test: semantic contract inventory gate (bd-bp8fl.1.1)
//!
//! Validates that the inventory seeded from support_semantic_overlay.v1.json is
//! source-linked, summary-consistent, and backed by a deterministic report/log
//! script.
//!
//! Run:
//!   cargo test -p frankenlibc-harness --test semantic_contract_inventory_test

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
    let artifact = load_json(&root.join("tests/conformance/semantic_contract_inventory.v1.json"));

    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-bp8fl.1.1"));
    assert!(artifact["entries"].is_array(), "entries must be array");
    assert!(
        artifact["semantic_contract_classes"].is_object(),
        "semantic_contract_classes must be object"
    );
    assert!(
        artifact["claim_policy"].is_object(),
        "claim_policy must be object"
    );
    assert!(artifact["summary"].is_object(), "summary must be object");

    let entries = artifact["entries"].as_array().unwrap();
    assert!(
        entries.len() >= 10,
        "inventory must preserve at least the seed overlay entries"
    );

    for row in entries {
        let id = row["id"].as_str().unwrap_or("<missing id>");
        for field in [
            "surface",
            "symbols",
            "module",
            "source_path",
            "source_line",
            "line_marker",
            "support_matrix_status",
            "semantic_class",
            "contract_kind",
            "current_behavior",
            "user_risk",
            "required_followup",
            "evidence_artifacts",
        ] {
            assert!(!row[field].is_null(), "{id}: missing {field}");
        }
    }
}

#[test]
fn seed_overlay_entries_are_all_covered() {
    let root = workspace_root();
    let artifact = load_json(&root.join("tests/conformance/semantic_contract_inventory.v1.json"));
    let seed = load_json(&root.join("tests/conformance/support_semantic_overlay.v1.json"));

    let seed_ids: HashSet<String> = seed["audited_entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap().to_string())
        .collect();
    let inventory_seed_ids: HashSet<String> = artifact["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["seed_overlay_id"].as_str().map(str::to_owned))
        .collect();

    let missing: Vec<_> = seed_ids.difference(&inventory_seed_ids).collect();
    assert!(missing.is_empty(), "missing seed overlay ids: {missing:?}");
}

#[test]
fn summary_counts_match_entries_and_sources_are_linked() {
    let root = workspace_root();
    let artifact = load_json(&root.join("tests/conformance/semantic_contract_inventory.v1.json"));
    let entries = artifact["entries"].as_array().unwrap();
    let summary = artifact["summary"].as_object().unwrap();

    let mut by_class: HashMap<String, u64> = HashMap::new();
    let mut by_source: HashMap<String, u64> = HashMap::new();
    let mut ids = HashSet::new();

    for row in entries {
        let id = row["id"].as_str().unwrap();
        assert!(ids.insert(id.to_string()), "duplicate inventory id {id}");

        let class = row["semantic_class"].as_str().unwrap();
        *by_class.entry(class.to_string()).or_insert(0) += 1;

        let source_path = row["source_path"].as_str().unwrap();
        *by_source.entry(source_path.to_string()).or_insert(0) += 1;

        let source = root.join(source_path);
        assert!(source.exists(), "{id}: missing source {}", source.display());
        let source_text = std::fs::read_to_string(&source).expect("source should be readable");
        let marker = row["line_marker"].as_str().unwrap();
        assert!(
            source_text.contains(marker),
            "{id}: source {} missing marker {marker:?}",
            source.display()
        );
    }

    assert_eq!(
        summary.get("entry_count").and_then(|v| v.as_u64()),
        Some(entries.len() as u64),
        "summary.entry_count mismatch"
    );
    assert_eq!(
        summary.get("by_semantic_class").unwrap(),
        &serde_json::to_value(by_class).unwrap(),
        "summary.by_semantic_class mismatch"
    );
    assert_eq!(
        summary.get("by_source_path").unwrap(),
        &serde_json::to_value(by_source).unwrap(),
        "summary.by_source_path mismatch"
    );
}

#[test]
fn gate_script_passes_and_emits_structured_report_and_log() {
    let root = workspace_root();
    let script = root.join("scripts/check_semantic_contract_inventory.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_semantic_contract_inventory.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run semantic contract inventory gate");
    assert!(
        output.status.success(),
        "semantic contract inventory gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/semantic_contract_inventory.report.json");
    let log_path = root.join("target/conformance/semantic_contract_inventory.log.jsonl");
    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.1.1"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    for check in [
        "json_parse",
        "top_level_shape",
        "entries_present",
        "entry_schema",
        "unique_ids",
        "seed_overlay_coverage",
        "summary_counts",
        "source_summary_counts",
        "source_markers",
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
