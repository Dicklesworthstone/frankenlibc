//! Integration test: docs env mismatch + governance gate (bd-29b.2, bd-3rw.3)
//!
//! Validates that:
//! 1. Docs inventory and mismatch report files exist and are valid JSON.
//! 2. Every mismatch row is fully classified with remediation action.
//! 3. unresolved_ambiguous list is empty.
//! 4. Major documentation surfaces have explicit source-of-truth ownership.
//! 5. Structured governance trace rows exist for every governed section.
//! 6. Gate script exists, is executable, and passes.

use std::collections::{BTreeMap, BTreeSet};
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

fn non_empty_string(value: &serde_json::Value, label: &str) -> String {
    assert!(value.is_string(), "{label} must be a string");
    let s = value.as_str().unwrap_or("");
    assert!(!s.is_empty(), "{label} must be non-empty string");
    s.to_string()
}

fn string_vec(value: &serde_json::Value, label: &str) -> Vec<String> {
    assert!(value.is_array(), "{label} must be array");
    let rows = value.as_array().map(Vec::as_slice).unwrap_or(&[]);
    assert!(!rows.is_empty(), "{label} must be non-empty");
    rows.iter()
        .enumerate()
        .map(|(idx, row)| non_empty_string(row, &format!("{label}[{idx}]")))
        .collect()
}

fn string_set(value: &serde_json::Value, label: &str) -> BTreeSet<String> {
    string_vec(value, label).into_iter().collect()
}

#[derive(Debug)]
struct ExpectedTraceRow {
    surface_id: String,
    section_title: String,
    source_artifact: String,
    update_trigger: String,
    owner: String,
    review_policy: String,
    freshness_status: String,
    artifact_refs: BTreeSet<String>,
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
    let surfaces = map["surfaces"].as_array().expect("surfaces must be array");
    let sections: usize = surfaces
        .iter()
        .map(|surface| {
            surface["sections"]
                .as_array()
                .expect("sections must be array")
                .len()
        })
        .sum();

    let mut expected_by_trace_id = BTreeMap::new();
    for surface in surfaces {
        let surface_id = non_empty_string(&surface["surface_id"], "surface_id");
        for section in surface["sections"]
            .as_array()
            .expect("sections must be array")
        {
            let section_id =
                non_empty_string(&section["section_id"], &format!("{surface_id}.section_id"));
            let trace_id = format!(
                "bd-3rw.3::{}::{}",
                surface_id.to_ascii_lowercase(),
                section_id
            );
            let source_artifacts = string_vec(
                &section["source_artifacts"],
                &format!("{surface_id}/{section_id}.source_artifacts"),
            );
            let update_triggers = string_vec(
                &section["update_triggers"],
                &format!("{surface_id}/{section_id}.update_triggers"),
            );
            let mut artifact_refs = string_set(
                &section["backing_paths"],
                &format!("{surface_id}/{section_id}.backing_paths"),
            );
            artifact_refs.extend(source_artifacts.iter().cloned());

            assert!(
                expected_by_trace_id
                    .insert(
                        trace_id,
                        ExpectedTraceRow {
                            surface_id: surface_id.clone(),
                            section_title: non_empty_string(
                                &section["section_title"],
                                &format!("{surface_id}/{section_id}.section_title"),
                            ),
                            source_artifact: source_artifacts[0].clone(),
                            update_trigger: update_triggers[0].clone(),
                            owner: non_empty_string(
                                &section["owner"],
                                &format!("{surface_id}/{section_id}.owner"),
                            ),
                            review_policy: non_empty_string(
                                &section["review_policy"],
                                &format!("{surface_id}/{section_id}.review_policy"),
                            ),
                            freshness_status: non_empty_string(
                                &section["freshness_status"],
                                &format!("{surface_id}/{section_id}.freshness_status"),
                            ),
                            artifact_refs,
                        },
                    )
                    .is_none(),
                "{surface_id}/{section_id}: duplicate derived trace_id"
            );
        }
    }

    let sections_from_expected = expected_by_trace_id.len();
    assert_eq!(
        sections_from_expected, sections,
        "derived trace row count must match governed section count"
    );

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

    let mut seen_trace_ids = BTreeSet::new();
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

        let trace_id = row["trace_id"].as_str().expect("checked above");
        assert!(
            seen_trace_ids.insert(trace_id.to_string()),
            "duplicate trace_id in docs governance trace: {trace_id}"
        );
        let Some(expected) = expected_by_trace_id.get(trace_id) else {
            assert!(
                expected_by_trace_id.contains_key(trace_id),
                "trace row {trace_id} has no source-map section"
            );
            continue;
        };
        assert_eq!(
            row["doc_surface"].as_str(),
            Some(expected.surface_id.as_str()),
            "{trace_id}: doc_surface must match source map surface_id"
        );
        assert_eq!(
            row["doc_section"].as_str(),
            Some(expected.section_title.as_str()),
            "{trace_id}: doc_section must match source map section_title"
        );
        assert_eq!(
            row["source_artifact"].as_str(),
            Some(expected.source_artifact.as_str()),
            "{trace_id}: source_artifact must match first source map source_artifacts row"
        );
        assert_eq!(
            row["update_trigger"].as_str(),
            Some(expected.update_trigger.as_str()),
            "{trace_id}: update_trigger must match first source map update_triggers row"
        );
        assert_eq!(
            row["owner"].as_str(),
            Some(expected.owner.as_str()),
            "{trace_id}: owner must match source map owner"
        );
        assert_eq!(
            row["review_policy"].as_str(),
            Some(expected.review_policy.as_str()),
            "{trace_id}: review_policy must match source map review_policy"
        );
        assert_eq!(
            row["freshness_status"].as_str(),
            Some(expected.freshness_status.as_str()),
            "{trace_id}: freshness_status must match source map freshness_status"
        );
        let actual_artifact_refs =
            string_set(&row["artifact_refs"], &format!("{trace_id}.artifact_refs"));
        assert_eq!(
            actual_artifact_refs, expected.artifact_refs,
            "{trace_id}: artifact_refs must equal source map source_artifacts plus backing_paths"
        );
    }

    assert_eq!(
        seen_trace_ids.len(),
        expected_by_trace_id.len(),
        "trace must include exactly one row per source-map section"
    );
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
