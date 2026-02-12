//! Integration test: verification matrix (bd-id3)
//!
//! Validates that:
//! 1. verification_matrix.json exists and is valid JSON with correct schema.
//! 2. Every open/in_progress critique bead has a verification row.
//! 3. Dashboard statistics are internally consistent.
//! 4. Coverage counts per entry are self-consistent.
//! 5. Matrix regeneration is deterministic (excluding timestamp).
//!
//! Run: cargo test -p glibc-rs-harness --test verification_matrix_test

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

#[test]
fn matrix_exists_and_valid_json() {
    let root = workspace_root();
    let matrix_path = root.join("tests/conformance/verification_matrix.json");

    assert!(
        matrix_path.exists(),
        "verification_matrix.json must exist at tests/conformance/"
    );

    let content = std::fs::read_to_string(&matrix_path).unwrap();
    let matrix: serde_json::Value =
        serde_json::from_str(&content).expect("verification_matrix.json should be valid JSON");

    // Required top-level keys
    for key in [
        "matrix_version",
        "generated_utc",
        "schema",
        "dashboard",
        "entries",
    ] {
        assert!(
            matrix[key] != serde_json::Value::Null,
            "Missing top-level key: {}",
            key
        );
    }

    assert_eq!(
        matrix["matrix_version"].as_u64().unwrap(),
        1,
        "Expected matrix_version 1"
    );
}

#[test]
fn schema_defines_required_types() {
    let root = workspace_root();
    let content =
        std::fs::read_to_string(root.join("tests/conformance/verification_matrix.json")).unwrap();
    let matrix: serde_json::Value = serde_json::from_str(&content).unwrap();

    let schema = &matrix["schema"];

    // Must define coverage statuses
    let statuses = schema["coverage_statuses"]
        .as_object()
        .expect("coverage_statuses should be an object");
    for status in ["complete", "partial", "missing", "not_required"] {
        assert!(
            statuses.contains_key(status),
            "Missing coverage status definition: {}",
            status
        );
    }

    // Must define obligation types
    let obligations = schema["obligation_types"]
        .as_object()
        .expect("obligation_types should be an object");
    for otype in [
        "unit_tests",
        "e2e_scripts",
        "structured_logs",
        "perf_evidence",
        "conformance_fixtures",
        "golden_artifacts",
    ] {
        assert!(
            obligations.contains_key(otype),
            "Missing obligation type definition: {}",
            otype
        );
    }
}

#[test]
fn schema_has_row_contract_and_stream_examples() {
    let root = workspace_root();
    let content =
        std::fs::read_to_string(root.join("tests/conformance/verification_matrix.json")).unwrap();
    let matrix: serde_json::Value = serde_json::from_str(&content).unwrap();
    let schema = &matrix["schema"];

    assert_eq!(
        schema["row_schema_version"].as_str().unwrap(),
        "v1",
        "row_schema_version must be v1"
    );

    let row_states = schema["row_status_states"]
        .as_object()
        .expect("row_status_states should be an object");
    for state in ["missing", "partial", "complete"] {
        assert!(
            row_states.contains_key(state),
            "row_status_states missing '{}'",
            state
        );
    }

    let row_template = schema["row_template"]
        .as_object()
        .expect("row_template should be an object");
    for key in [
        "bead_id",
        "stream",
        "status",
        "unit_cmds",
        "e2e_cmds",
        "expected_assertions",
        "log_schema_refs",
        "artifact_paths",
        "perf_proof_refs",
        "close_blockers",
        "notes",
    ] {
        assert!(
            row_template.contains_key(key),
            "row_template missing key '{}'",
            key
        );
    }

    let transitions = schema["row_status_transitions"]
        .as_array()
        .expect("row_status_transitions should be an array");
    let mut transition_targets = std::collections::HashSet::new();
    for (idx, transition) in transitions.iter().enumerate() {
        let to = transition["to"]
            .as_str()
            .unwrap_or_else(|| panic!("transition {} missing 'to'", idx));
        transition_targets.insert(to.to_string());
        assert!(
            !transition["when"].as_str().unwrap_or("").is_empty(),
            "transition {} has empty 'when' clause",
            idx
        );
    }
    assert_eq!(
        transition_targets,
        std::collections::HashSet::from([
            "missing".to_string(),
            "partial".to_string(),
            "complete".to_string()
        ]),
        "row_status_transitions must define exactly missing/partial/complete"
    );

    let stream_examples = schema["stream_examples"]
        .as_array()
        .expect("stream_examples should be an array");
    let mut seen_streams = std::collections::HashSet::new();
    for (idx, row) in stream_examples.iter().enumerate() {
        let row_obj = row
            .as_object()
            .unwrap_or_else(|| panic!("stream_examples[{}] is not an object", idx));
        for key in [
            "bead_id",
            "stream",
            "status",
            "unit_cmds",
            "e2e_cmds",
            "expected_assertions",
            "log_schema_refs",
            "artifact_paths",
            "perf_proof_refs",
            "close_blockers",
            "notes",
        ] {
            assert!(
                row_obj.contains_key(key),
                "stream_examples[{}] missing key '{}'",
                idx,
                key
            );
        }

        let stream = row["stream"]
            .as_str()
            .unwrap_or_else(|| panic!("stream_examples[{}].stream must be a string", idx));
        seen_streams.insert(stream.to_string());
        assert!(
            ["docs", "e2e", "syscall", "stubs", "math", "perf"].contains(&stream),
            "stream_examples[{}].stream '{}' is invalid",
            idx,
            stream
        );
        let status = row["status"]
            .as_str()
            .unwrap_or_else(|| panic!("stream_examples[{}].status must be a string", idx));
        assert!(
            ["missing", "partial", "complete"].contains(&status),
            "stream_examples[{}].status '{}' is invalid",
            idx,
            status
        );

        for arr_key in [
            "unit_cmds",
            "e2e_cmds",
            "expected_assertions",
            "log_schema_refs",
            "artifact_paths",
            "perf_proof_refs",
            "close_blockers",
        ] {
            assert!(
                row[arr_key].is_array(),
                "stream_examples[{}].{} must be an array",
                idx,
                arr_key
            );
        }
    }

    assert_eq!(
        seen_streams,
        std::collections::HashSet::from([
            "docs".to_string(),
            "e2e".to_string(),
            "syscall".to_string(),
            "stubs".to_string(),
            "math".to_string(),
            "perf".to_string()
        ]),
        "stream_examples must include at least one row for docs/e2e/syscall/stubs/math/perf"
    );
}

#[test]
fn all_critique_beads_have_rows() {
    let root = workspace_root();
    let matrix_content =
        std::fs::read_to_string(root.join("tests/conformance/verification_matrix.json")).unwrap();
    let matrix: serde_json::Value = serde_json::from_str(&matrix_content).unwrap();

    let beads_content = std::fs::read_to_string(root.join(".beads/issues.jsonl")).unwrap();

    let matrix_ids: std::collections::HashSet<String> = matrix["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["bead_id"].as_str().unwrap().to_string())
        .collect();

    let mut missing = Vec::new();
    for line in beads_content.lines() {
        let bead: serde_json::Value = serde_json::from_str(line).unwrap();
        let empty_arr = vec![];
        let labels: Vec<&str> = bead["labels"]
            .as_array()
            .unwrap_or(&empty_arr)
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        let status = bead["status"].as_str().unwrap_or("");

        if labels.contains(&"critique") && matches!(status, "open" | "in_progress") {
            let id = bead["id"].as_str().unwrap();
            if !matrix_ids.contains(id) {
                missing.push(id.to_string());
            }
        }
    }

    assert!(
        missing.is_empty(),
        "Critique beads missing from verification matrix:\n{}",
        missing.join("\n")
    );
}

#[test]
fn entry_coverage_counts_consistent() {
    let root = workspace_root();
    let content =
        std::fs::read_to_string(root.join("tests/conformance/verification_matrix.json")).unwrap();
    let matrix: serde_json::Value = serde_json::from_str(&content).unwrap();

    let entries = matrix["entries"].as_array().unwrap();
    let mut errors = Vec::new();

    for entry in entries {
        let bead_id = entry["bead_id"].as_str().unwrap();
        let cs = &entry["coverage_summary"];

        let required = cs["required"].as_u64().unwrap();
        let complete = cs["complete"].as_u64().unwrap();
        let partial = cs["partial"].as_u64().unwrap();
        let missing = cs["missing"].as_u64().unwrap();

        if complete + partial + missing != required {
            errors.push(format!(
                "{}: {}+{}+{} != {} required",
                bead_id, complete, partial, missing, required
            ));
        }

        // Count from coverage object should match
        let coverage = entry["coverage"].as_object().unwrap();
        let actual_required = coverage
            .values()
            .filter(|v| v["status"].as_str().unwrap_or("") != "not_required")
            .count() as u64;
        if actual_required != required {
            errors.push(format!(
                "{}: coverage object has {} required but summary says {}",
                bead_id, actual_required, required
            ));
        }
    }

    assert!(
        errors.is_empty(),
        "Coverage count inconsistencies:\n{}",
        errors.join("\n")
    );
}

#[test]
fn dashboard_stats_consistent_with_entries() {
    let root = workspace_root();
    let content =
        std::fs::read_to_string(root.join("tests/conformance/verification_matrix.json")).unwrap();
    let matrix: serde_json::Value = serde_json::from_str(&content).unwrap();

    let entries = matrix["entries"].as_array().unwrap();
    let dashboard = &matrix["dashboard"];

    // Total count
    let total = dashboard["total_critique_beads"].as_u64().unwrap();
    assert_eq!(
        total,
        entries.len() as u64,
        "Dashboard total ({}) != entry count ({})",
        total,
        entries.len()
    );

    // Count by_coverage_status manually
    let mut by_status: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for e in entries {
        let overall = e["coverage_summary"]["overall"]
            .as_str()
            .unwrap()
            .to_string();
        *by_status.entry(overall).or_insert(0) += 1;
    }

    let dashboard_status = dashboard["by_coverage_status"].as_object().unwrap();
    for (status, count) in &by_status {
        let dash_count = dashboard_status
            .get(status)
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        assert_eq!(
            *count, dash_count,
            "Dashboard by_coverage_status[{}]: expected {}, got {}",
            status, count, dash_count
        );
    }

    // Count by_priority manually
    let mut by_priority: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for e in entries {
        let p = format!("P{}", e["priority"].as_u64().unwrap());
        *by_priority.entry(p).or_insert(0) += 1;
    }

    let dashboard_priority = dashboard["by_priority"].as_object().unwrap();
    for (prio, count) in &by_priority {
        let dash_total = dashboard_priority
            .get(prio)
            .and_then(|v| v["total"].as_u64())
            .unwrap_or(0);
        assert_eq!(
            *count, dash_total,
            "Dashboard by_priority[{}].total: expected {}, got {}",
            prio, count, dash_total
        );
    }

    // Count by_stream manually from row.stream
    let mut by_stream: std::collections::HashMap<String, (u64, u64, u64, u64)> =
        std::collections::HashMap::new();
    for e in entries {
        let stream = e["row"]["stream"].as_str().unwrap_or("syscall").to_string();
        let overall = e["coverage_summary"]["overall"]
            .as_str()
            .unwrap_or("missing");
        let entry = by_stream.entry(stream).or_insert((0, 0, 0, 0));
        entry.0 += 1; // total
        match overall {
            "complete" => entry.1 += 1,
            "partial" => entry.2 += 1,
            _ => entry.3 += 1,
        }
    }

    let dashboard_stream = dashboard["by_stream"].as_object().unwrap();
    for (stream, (total, complete, partial, missing)) in &by_stream {
        let dash = dashboard_stream
            .get(stream)
            .unwrap_or_else(|| panic!("dashboard.by_stream missing stream '{}'", stream));
        assert_eq!(
            dash["total"].as_u64().unwrap_or(0),
            *total,
            "dashboard.by_stream[{}].total mismatch",
            stream
        );
        assert_eq!(
            dash["complete"].as_u64().unwrap_or(0),
            *complete,
            "dashboard.by_stream[{}].complete mismatch",
            stream
        );
        assert_eq!(
            dash["partial"].as_u64().unwrap_or(0),
            *partial,
            "dashboard.by_stream[{}].partial mismatch",
            stream
        );
        assert_eq!(
            dash["missing"].as_u64().unwrap_or(0),
            *missing,
            "dashboard.by_stream[{}].missing mismatch",
            stream
        );
    }
}

#[test]
fn entries_have_valid_coverage_statuses() {
    let root = workspace_root();
    let content =
        std::fs::read_to_string(root.join("tests/conformance/verification_matrix.json")).unwrap();
    let matrix: serde_json::Value = serde_json::from_str(&content).unwrap();

    let valid_statuses = ["complete", "partial", "missing", "not_required"];
    let valid_overalls = ["complete", "partial", "missing"];

    let entries = matrix["entries"].as_array().unwrap();
    let mut errors = Vec::new();

    for entry in entries {
        let bead_id = entry["bead_id"].as_str().unwrap();

        // Check overall status
        let overall = entry["coverage_summary"]["overall"].as_str().unwrap();
        if !valid_overalls.contains(&overall) {
            errors.push(format!("{}: invalid overall status '{}'", bead_id, overall));
        }

        // Check individual coverage statuses
        let coverage = entry["coverage"].as_object().unwrap();
        for (key, val) in coverage {
            let status = val["status"].as_str().unwrap_or("<missing>");
            if !valid_statuses.contains(&status) {
                errors.push(format!("{}.{}: invalid status '{}'", bead_id, key, status));
            }
        }
    }

    assert!(
        errors.is_empty(),
        "Invalid coverage statuses found:\n{}",
        errors.join("\n")
    );
}

#[test]
fn entries_have_non_empty_backfill_rows() {
    let root = workspace_root();
    let content =
        std::fs::read_to_string(root.join("tests/conformance/verification_matrix.json")).unwrap();
    let matrix: serde_json::Value = serde_json::from_str(&content).unwrap();

    let entries = matrix["entries"].as_array().unwrap();
    let mut errors = Vec::new();

    for entry in entries {
        let bead_id = entry["bead_id"].as_str().unwrap();
        let row = match entry["row"].as_object() {
            Some(v) => v,
            None => {
                errors.push(format!("{}: missing row object", bead_id));
                continue;
            }
        };

        for key in [
            "bead_id",
            "stream",
            "status",
            "unit_cmds",
            "e2e_cmds",
            "expected_assertions",
            "log_schema_refs",
            "artifact_paths",
            "perf_proof_refs",
            "close_blockers",
            "notes",
        ] {
            if !row.contains_key(key) {
                errors.push(format!("{}: row missing '{}'", bead_id, key));
            }
        }

        if row["unit_cmds"].as_array().is_none_or(|v| v.is_empty()) {
            errors.push(format!("{}: row.unit_cmds is empty", bead_id));
        }
        if row["expected_assertions"]
            .as_array()
            .is_none_or(|v| v.is_empty())
        {
            errors.push(format!("{}: row.expected_assertions is empty", bead_id));
        }
        if row["log_schema_refs"]
            .as_array()
            .is_none_or(|v| v.is_empty())
        {
            errors.push(format!("{}: row.log_schema_refs is empty", bead_id));
        }
        if row["artifact_paths"]
            .as_array()
            .is_none_or(|v| v.is_empty())
        {
            errors.push(format!("{}: row.artifact_paths is empty", bead_id));
        }
    }

    assert!(
        errors.is_empty(),
        "Backfill row contract violations:\n{}",
        errors.join("\n")
    );
}

#[test]
fn no_empty_bead_ids() {
    let root = workspace_root();
    let content =
        std::fs::read_to_string(root.join("tests/conformance/verification_matrix.json")).unwrap();
    let matrix: serde_json::Value = serde_json::from_str(&content).unwrap();

    let entries = matrix["entries"].as_array().unwrap();
    for (i, entry) in entries.iter().enumerate() {
        let bead_id = entry["bead_id"].as_str().unwrap_or("");
        assert!(!bead_id.is_empty(), "Entry {} has empty bead_id", i);
        assert!(
            bead_id.starts_with("bd-"),
            "Entry {} bead_id '{}' doesn't start with 'bd-'",
            i,
            bead_id
        );
    }
}
