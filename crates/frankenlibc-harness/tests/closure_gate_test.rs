//! Integration test: Closure evidence gate (bd-4rl)
//!
//! Validates that:
//! 1. The closure evidence schema exists and is valid JSON.
//! 2. Every required evidence field is defined in the schema.
//! 3. Legacy-exempt list is well-formed (and, when using beads, only covers closed critique beads).
//! 4. Non-exempt closed critique beads have matrix entries with evidence.
//! 5. The CI gate script exists and is executable.
//! 6. Matrix rows have the evidence fields the schema requires.
//!
//! Source selection:
//! - FRANKENLIBC_CLOSURE_GATE_SOURCE=beads uses .beads/issues.jsonl for closed-critique detection.
//! - Default (matrix) uses tests/conformance/verification_matrix.json to avoid stale beads in rch.
//!
//! Run: cargo test -p frankenlibc-harness --test closure_gate_test

use std::collections::{HashMap, HashSet};
use std::env;
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

fn schema_path() -> PathBuf {
    workspace_root().join("tests/conformance/closure_evidence_schema.json")
}

fn matrix_path() -> PathBuf {
    workspace_root().join("tests/conformance/verification_matrix.json")
}

fn beads_path() -> PathBuf {
    workspace_root().join(".beads/issues.jsonl")
}

fn load_schema() -> serde_json::Value {
    let path = schema_path();
    let content =
        std::fs::read_to_string(&path).expect("closure_evidence_schema.json should exist");
    serde_json::from_str(&content).expect("closure_evidence_schema.json should be valid JSON")
}

fn load_matrix() -> serde_json::Value {
    let path = matrix_path();
    let content = std::fs::read_to_string(&path).expect("verification_matrix.json should exist");
    serde_json::from_str(&content).expect("verification_matrix.json should be valid JSON")
}

fn load_beads_latest() -> HashMap<String, serde_json::Value> {
    let path = beads_path();
    let content = std::fs::read_to_string(&path).expect(".beads/issues.jsonl should exist");
    let mut beads = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let bead: serde_json::Value =
            serde_json::from_str(line).expect("each bead line should be valid JSON");
        if let Some(id) = bead["id"].as_str() {
            beads.insert(id.to_string(), bead);
        }
    }
    beads
}

fn has_label(value: &serde_json::Value, label: &str) -> bool {
    value
        .as_array()
        .is_some_and(|labels| labels.iter().any(|v| v.as_str() == Some(label)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClosureGateSource {
    Matrix,
    Beads,
}

fn closure_gate_source() -> ClosureGateSource {
    match env::var("FRANKENLIBC_CLOSURE_GATE_SOURCE")
        .unwrap_or_else(|_| "matrix".to_string())
        .to_lowercase()
        .as_str()
    {
        "matrix" => ClosureGateSource::Matrix,
        "beads" => ClosureGateSource::Beads,
        other => {
            panic!("invalid FRANKENLIBC_CLOSURE_GATE_SOURCE={other} (expected 'matrix' or 'beads')")
        }
    }
}

fn closed_critique_from_beads(beads: &HashMap<String, serde_json::Value>) -> HashSet<String> {
    beads
        .values()
        .filter(|b| b["status"].as_str() == Some("closed") && has_label(&b["labels"], "critique"))
        .filter_map(|b| b["id"].as_str().map(String::from))
        .collect()
}

fn closed_critique_from_matrix(matrix: &serde_json::Value) -> HashSet<String> {
    matrix["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| {
            entry["status"].as_str() == Some("closed") && has_label(&entry["labels"], "critique")
        })
        .filter_map(|entry| entry["bead_id"].as_str().map(String::from))
        .collect()
}

fn closed_critique_bead_ids() -> HashSet<String> {
    match closure_gate_source() {
        ClosureGateSource::Matrix => closed_critique_from_matrix(&load_matrix()),
        ClosureGateSource::Beads => closed_critique_from_beads(&load_beads_latest()),
    }
}

#[test]
fn schema_exists_and_valid() {
    let schema = load_schema();
    assert!(
        schema["schema_version"].is_number(),
        "Missing schema_version"
    );
    assert!(
        schema["evidence_requirements"].is_object(),
        "Missing evidence_requirements"
    );
    assert!(schema["legacy_exempt"].is_array(), "Missing legacy_exempt");
    assert!(schema["enforcement"].is_object(), "Missing enforcement");
    assert!(schema["paths"].is_object(), "Missing paths");
}

#[test]
fn schema_has_required_evidence_fields() {
    let schema = load_schema();
    let reqs = schema["evidence_requirements"].as_object().unwrap();

    let expected = [
        "matrix_entry",
        "test_commands",
        "artifact_references",
        "coverage_not_missing",
        "close_blockers_empty",
    ];

    for field in &expected {
        assert!(
            reqs.contains_key(*field),
            "evidence_requirements missing '{field}'"
        );
        let req = &reqs[*field];
        assert!(
            req["required"].is_boolean(),
            "{field}: missing 'required' boolean"
        );
        assert!(
            req["description"].is_string(),
            "{field}: missing 'description'"
        );
    }
}

#[test]
fn legacy_exempt_only_contains_closed_critique_beads() {
    let schema = load_schema();
    let exempt_list = schema["legacy_exempt"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();
    let exempt: HashSet<String> = exempt_list.iter().map(|v| (*v).to_string()).collect();

    if closure_gate_source() == ClosureGateSource::Matrix {
        assert_eq!(
            exempt.len(),
            exempt_list.len(),
            "legacy_exempt contains duplicate entries"
        );
        return;
    }

    let closed_critique = closed_critique_bead_ids();

    let invalid: Vec<_> = exempt.difference(&closed_critique).collect();
    assert!(
        invalid.is_empty(),
        "Legacy-exempt beads that are not closed critique beads: {:?}",
        invalid
    );
}

#[test]
fn non_exempt_closed_beads_have_matrix_entries() {
    if closure_gate_source() == ClosureGateSource::Matrix {
        return;
    }

    let schema = load_schema();
    let matrix = load_matrix();

    let exempt: HashSet<String> = schema["legacy_exempt"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let matrix_ids: HashSet<String> = matrix["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["bead_id"].as_str().map(String::from))
        .collect();

    let mut missing = Vec::new();
    let closed_critique = closed_critique_bead_ids();
    for bid in closed_critique {
        if !exempt.contains(&bid) && !matrix_ids.contains(&bid) {
            missing.push(bid);
        }
    }

    assert!(
        missing.is_empty(),
        "Non-exempt closed critique beads without matrix entries: {:?}",
        missing
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_closure_gate.sh");
    assert!(script.exists(), "scripts/check_closure_gate.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_closure_gate.sh must be executable"
        );
    }
}

#[test]
fn matrix_rows_have_evidence_fields() {
    let matrix = load_matrix();
    let entries = matrix["entries"].as_array().unwrap();

    let required_row_fields = ["unit_cmds", "e2e_cmds", "artifact_paths", "close_blockers"];

    for entry in entries {
        let bid = entry["bead_id"].as_str().unwrap_or("<unknown>");
        let row = &entry["row"];
        assert!(row.is_object(), "{bid}: missing row object");

        for field in &required_row_fields {
            assert!(
                !row[field].is_null(),
                "{bid}: row missing required field '{field}'"
            );
        }

        assert!(
            entry["coverage_summary"].is_object(),
            "{bid}: missing coverage_summary"
        );
        let overall = entry["coverage_summary"]["overall"].as_str().unwrap_or("");
        assert!(
            ["missing", "partial", "complete"].contains(&overall),
            "{bid}: invalid coverage_summary.overall '{overall}'"
        );
    }
}

#[test]
fn non_exempt_closed_beads_have_evidence() {
    let schema = load_schema();
    let matrix = load_matrix();

    let exempt: HashSet<String> = schema["legacy_exempt"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let matrix_map: std::collections::HashMap<String, &serde_json::Value> = matrix["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["bead_id"].as_str().map(|id| (id.to_string(), e)))
        .collect();

    let mut violations = Vec::new();
    let closed_critique = closed_critique_bead_ids();
    for bid in closed_critique {
        if exempt.contains(&bid) {
            continue;
        }
        if let Some(entry) = matrix_map.get(&bid) {
            let row = &entry["row"];
            let cs = &entry["coverage_summary"];

            let unit_cmds = row["unit_cmds"].as_array().is_none_or(|a| a.is_empty());
            let e2e_cmds = row["e2e_cmds"].as_array().is_none_or(|a| a.is_empty());
            if unit_cmds && e2e_cmds {
                violations.push(format!("{bid}: no test commands"));
            }

            let artifacts = row["artifact_paths"]
                .as_array()
                .is_none_or(|a| a.is_empty());
            let log_refs = row["log_schema_refs"]
                .as_array()
                .is_none_or(|a| a.is_empty());
            if artifacts && log_refs {
                violations.push(format!("{bid}: no artifact references"));
            }

            if cs["overall"].as_str() == Some("missing") {
                violations.push(format!("{bid}: coverage_summary is 'missing'"));
            }

            let blockers = row["close_blockers"]
                .as_array()
                .is_some_and(|a| !a.is_empty());
            if blockers {
                violations.push(format!("{bid}: has close_blockers"));
            }
        } else {
            violations.push(format!("{bid}: no matrix entry"));
        }
    }

    assert!(
        violations.is_empty(),
        "Non-exempt closed beads with evidence violations:\n{}",
        violations.join("\n")
    );
}
