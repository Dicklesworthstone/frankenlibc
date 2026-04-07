//! Integration test: docs env mismatch + governance gate (bd-29b.2, bd-3rw.3)
//!
//! Validates that:
//! 1. Docs inventory and mismatch report files exist and are valid JSON.
//! 2. Every mismatch row is fully classified with remediation action.
//! 3. unresolved_ambiguous list is empty.
//! 4. Major documentation surfaces have explicit source-of-truth ownership.
//! 5. Structured governance trace rows exist for every governed section.
//! 6. Gate script exists, is executable, and passes.

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
    let content = std::fs::read_to_string(path).expect("json file should exist");
    serde_json::from_str(&content).expect("json should parse")
}

#[test]
fn docs_inventory_exists_and_has_expected_shape() {
    let root = workspace_root();
    let docs_inventory = load_json(&root.join("tests/conformance/docs_env_inventory.v1.json"));
    assert_eq!(
        docs_inventory["schema_version"].as_str(),
        Some("v1"),
        "docs inventory schema_version must be v1"
    );
    assert!(
        docs_inventory["docs_files"].is_array(),
        "docs_files must be array"
    );
    assert!(docs_inventory["keys"].is_array(), "keys must be array");
    assert!(
        docs_inventory["summary"].is_object(),
        "summary must be object"
    );
    assert!(
        docs_inventory["docs_files"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row.as_str() == Some("DEPLOYMENT.md"))),
        "docs inventory must include DEPLOYMENT.md once the deployment surface is materialized"
    );
}

#[test]
fn mismatch_report_is_fully_classified() {
    let root = workspace_root();
    let report = load_json(&root.join("tests/conformance/env_docs_code_mismatch_report.v1.json"));

    assert_eq!(
        report["schema_version"].as_str(),
        Some("v1"),
        "mismatch report schema_version must be v1"
    );

    let classes = report["classifications"]
        .as_array()
        .expect("classifications must be array");
    for row in classes {
        let key = row["env_key"].as_str().unwrap_or("<unknown>");
        let class = row["mismatch_class"].as_str().unwrap_or("");
        assert!(
            matches!(
                class,
                "missing_in_docs" | "missing_in_code" | "semantic_drift"
            ),
            "{key}: invalid mismatch_class '{class}'"
        );
        assert!(
            row["remediation_action"]
                .as_str()
                .is_some_and(|v| !v.is_empty()),
            "{key}: remediation_action must be non-empty"
        );
        assert!(row["details"].is_string(), "{key}: details must be string");
        assert!(row["evidence"].is_array(), "{key}: evidence must be array");
    }
}

#[test]
fn mismatch_summary_counts_are_zero() {
    let root = workspace_root();
    let report = load_json(&root.join("tests/conformance/env_docs_code_mismatch_report.v1.json"));
    let summary = report["summary"]
        .as_object()
        .expect("summary must be object");

    for key in [
        "missing_in_docs_count",
        "missing_in_code_count",
        "semantic_drift_count",
    ] {
        let value = summary
            .get(key)
            .and_then(|v| v.as_u64())
            .unwrap_or(u64::MAX);
        assert_eq!(value, 0, "{key} must be zero, got {value}");
    }
}

#[test]
fn unresolved_ambiguous_is_empty() {
    let root = workspace_root();
    let report = load_json(&root.join("tests/conformance/env_docs_code_mismatch_report.v1.json"));
    let unresolved = report["unresolved_ambiguous"]
        .as_array()
        .expect("unresolved_ambiguous must be array");
    assert!(
        unresolved.is_empty(),
        "unresolved_ambiguous must be empty, got: {unresolved:?}"
    );
}

#[test]
fn source_of_truth_map_covers_major_surfaces() {
    let root = workspace_root();
    let map = load_json(&root.join("tests/conformance/docs_source_of_truth_map.v1.json"));

    assert_eq!(
        map["schema_version"].as_str(),
        Some("v1"),
        "source-of-truth map schema_version must be v1"
    );
    assert_eq!(
        map["bead"].as_str(),
        Some("bd-3rw.3"),
        "source-of-truth map must be tied to bd-3rw.3"
    );

    let surfaces = map["surfaces"].as_array().expect("surfaces must be array");
    let required = [
        "README",
        "ARCHITECTURE",
        "DEPLOYMENT",
        "SECURITY",
        "API",
        "TROUBLESHOOTING",
    ];
    for surface_id in required {
        assert!(
            surfaces
                .iter()
                .any(|row| row["surface_id"].as_str() == Some(surface_id)),
            "surface {surface_id} must exist in governance map"
        );
    }

    let summary = map["summary"].as_object().expect("summary must be object");
    assert_eq!(
        summary
            .get("missing_section_count")
            .and_then(|v| v.as_u64()),
        Some(0),
        "all governed sections should be fresh"
    );
}

#[test]
fn readme_smoke_status_is_backed_by_canonical_smoke_artifact() {
    let root = workspace_root();
    let map = load_json(&root.join("tests/conformance/docs_source_of_truth_map.v1.json"));
    let surfaces = map["surfaces"].as_array().expect("surfaces must be array");

    let readme_surface = surfaces
        .iter()
        .find(|surface| surface["surface_id"].as_str() == Some("README"))
        .expect("README surface must exist");
    let sections = readme_surface["sections"]
        .as_array()
        .expect("README sections must be array");
    let smoke_section = sections
        .iter()
        .find(|section| section["section_id"].as_str() == Some("smoke-status-and-claim-governance"))
        .expect("README governance must include smoke-status-and-claim-governance");

    assert!(
        smoke_section["source_artifacts"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .any(|value| {
                value.as_str() == Some("tests/conformance/ld_preload_smoke_summary.v1.json")
            }),
        "README smoke governance section must include the canonical smoke summary artifact"
    );
    assert!(
        smoke_section["update_triggers"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .any(|value| value.as_str() == Some("scripts/check_claim_reconciliation.sh")),
        "README smoke governance section must be guarded by check_claim_reconciliation.sh"
    );
}

#[test]
fn deployment_surface_is_materialized_to_dedicated_doc() {
    let root = workspace_root();
    let map = load_json(&root.join("tests/conformance/docs_source_of_truth_map.v1.json"));
    let surfaces = map["surfaces"].as_array().expect("surfaces must be array");

    let deployment_surface = surfaces
        .iter()
        .find(|surface| surface["surface_id"].as_str() == Some("DEPLOYMENT"))
        .expect("DEPLOYMENT surface must exist");

    assert_eq!(
        deployment_surface["target_path"].as_str(),
        Some("DEPLOYMENT.md"),
        "deployment surface target_path must be DEPLOYMENT.md"
    );
    assert_eq!(
        deployment_surface["future_target_path"].as_str(),
        Some("DEPLOYMENT.md"),
        "deployment surface future_target_path must stay DEPLOYMENT.md"
    );

    let sections = deployment_surface["sections"]
        .as_array()
        .expect("DEPLOYMENT sections must be array");
    let interpose = sections
        .iter()
        .find(|section| section["section_id"].as_str() == Some("interpose-workflows"))
        .expect("DEPLOYMENT surface must include interpose-workflows");

    assert!(
        interpose["backing_paths"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row.as_str() == Some("DEPLOYMENT.md"))),
        "interpose-workflows backing_paths must include DEPLOYMENT.md"
    );
}

#[test]
fn governed_sections_have_sources_owners_and_triggers() {
    let root = workspace_root();
    let map = load_json(&root.join("tests/conformance/docs_source_of_truth_map.v1.json"));
    let surfaces = map["surfaces"].as_array().expect("surfaces must be array");

    for surface in surfaces {
        let surface_id = surface["surface_id"].as_str().unwrap_or("<unknown>");
        assert!(
            surface["target_path"]
                .as_str()
                .is_some_and(|v| !v.is_empty()),
            "{surface_id}: target_path must be non-empty"
        );
        assert!(
            surface["future_target_path"]
                .as_str()
                .is_some_and(|v| !v.is_empty()),
            "{surface_id}: future_target_path must be non-empty"
        );

        let sections = surface["sections"]
            .as_array()
            .expect("sections must be array");
        assert!(
            !sections.is_empty(),
            "{surface_id}: sections must be non-empty"
        );

        for section in sections {
            let section_id = section["section_id"].as_str().unwrap_or("<unknown>");
            assert!(
                section["owner"].as_str().is_some_and(|v| !v.is_empty()),
                "{surface_id}/{section_id}: owner must be non-empty"
            );
            assert!(
                section["review_policy"]
                    .as_str()
                    .is_some_and(|v| !v.is_empty()),
                "{surface_id}/{section_id}: review_policy must be non-empty"
            );
            assert_eq!(
                section["freshness_status"].as_str(),
                Some("fresh"),
                "{surface_id}/{section_id}: freshness_status must be fresh"
            );
            assert!(
                section["backing_paths"]
                    .as_array()
                    .is_some_and(|v| !v.is_empty()),
                "{surface_id}/{section_id}: backing_paths must be non-empty"
            );
            assert!(
                section["source_artifacts"]
                    .as_array()
                    .is_some_and(|v| !v.is_empty()),
                "{surface_id}/{section_id}: source_artifacts must be non-empty"
            );
            assert!(
                section["update_triggers"]
                    .as_array()
                    .is_some_and(|v| !v.is_empty()),
                "{surface_id}/{section_id}: update_triggers must be non-empty"
            );
            assert!(
                section["missing_inputs"]
                    .as_array()
                    .is_some_and(|v| v.is_empty()),
                "{surface_id}/{section_id}: missing_inputs must be empty"
            );
        }
    }
}

#[test]
fn governance_trace_rows_cover_every_section() {
    let root = workspace_root();
    let map = load_json(&root.join("tests/conformance/docs_source_of_truth_map.v1.json"));
    let sections: usize = map["surfaces"]
        .as_array()
        .expect("surfaces must be array")
        .iter()
        .map(|surface| {
            surface["sections"]
                .as_array()
                .expect("sections must be array")
                .len()
        })
        .sum();

    let trace_path = root.join("tests/conformance/docs_source_of_truth_trace.v1.jsonl");
    let trace = std::fs::read_to_string(&trace_path).expect("trace file should exist");
    let rows: Vec<serde_json::Value> = trace
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("trace row must parse"))
        .collect();

    assert_eq!(
        rows.len(),
        sections,
        "trace row count must match governed section count"
    );

    for row in &rows {
        assert_eq!(row["bead_id"].as_str(), Some("bd-3rw.3"));
        for key in [
            "trace_id",
            "doc_surface",
            "doc_section",
            "source_artifact",
            "freshness_status",
            "owner",
            "review_policy",
            "update_trigger",
        ] {
            assert!(
                row[key].as_str().is_some_and(|v| !v.is_empty()),
                "trace row missing non-empty {key}"
            );
        }
        assert_eq!(row["freshness_status"].as_str(), Some("fresh"));
        assert!(
            row["artifact_refs"]
                .as_array()
                .is_some_and(|v| !v.is_empty()),
            "trace row artifact_refs must be non-empty array"
        );
    }
}

#[test]
fn gate_script_exists_and_is_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_docs_env_mismatch.sh");
    assert!(
        script.exists(),
        "scripts/check_docs_env_mismatch.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_docs_env_mismatch.sh must be executable"
        );
    }
}

#[test]
fn gate_script_passes() {
    let root = workspace_root();
    let script = root.join("scripts/check_docs_env_mismatch.sh");
    let output = Command::new("bash")
        .arg(script)
        .current_dir(&root)
        .output()
        .expect("check_docs_env_mismatch.sh should execute");

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "check_docs_env_mismatch.sh failed\nstatus={:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout,
            stderr
        );
    }
}
