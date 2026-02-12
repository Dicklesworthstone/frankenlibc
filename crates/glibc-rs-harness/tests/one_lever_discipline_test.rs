//! Integration test: One-lever discipline guard (bd-22p)
//!
//! Validates that:
//! 1. The discipline spec exists and defines lever categories.
//! 2. Every opportunity matrix entry has a valid lever_category.
//! 3. No bead references multiple lever categories without a waiver.
//! 4. The summary is consistent with the categories.
//! 5. The gate script exists and is executable.
//! 6. Category taxonomy covers standard optimization types.
//!
//! Run: cargo test -p glibc-rs-harness --test one_lever_discipline_test

use std::collections::{HashMap, HashSet};
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

fn load_discipline() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/one_lever_discipline.json");
    let content = std::fs::read_to_string(&path).expect("one_lever_discipline.json should exist");
    serde_json::from_str(&content).expect("one_lever_discipline.json should be valid JSON")
}

fn load_opportunity_matrix() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/opportunity_matrix.json");
    let content = std::fs::read_to_string(&path).expect("opportunity_matrix.json should exist");
    serde_json::from_str(&content).expect("opportunity_matrix.json should be valid JSON")
}

#[test]
fn spec_exists_and_valid() {
    let spec = load_discipline();
    assert!(spec["schema_version"].is_number(), "Missing schema_version");
    assert!(
        spec["lever_categories"].is_object(),
        "Missing lever_categories"
    );
    assert!(
        spec["lever_categories"]["categories"].is_object(),
        "Missing lever_categories.categories"
    );
    assert!(spec["enforcement"].is_object(), "Missing enforcement");
    assert!(spec["summary"].is_object(), "Missing summary");
}

#[test]
fn categories_have_required_fields() {
    let spec = load_discipline();
    let cats = spec["lever_categories"]["categories"].as_object().unwrap();

    assert!(!cats.is_empty(), "No categories defined");

    for (name, cat) in cats {
        assert!(
            cat["description"].is_string(),
            "{name}: missing description"
        );
        assert!(cat["examples"].is_array(), "{name}: missing examples");
        let examples = cat["examples"].as_array().unwrap();
        assert!(!examples.is_empty(), "{name}: examples array is empty");
    }
}

#[test]
fn summary_consistent() {
    let spec = load_discipline();
    let cats = spec["lever_categories"]["categories"].as_object().unwrap();
    let summary = &spec["summary"];

    let total = summary["total_categories"].as_u64().unwrap() as usize;
    assert_eq!(total, cats.len(), "total_categories mismatch");

    let cat_list: HashSet<String> = summary["category_list"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let actual_cats: HashSet<String> = cats.keys().cloned().collect();
    assert_eq!(cat_list, actual_cats, "category_list mismatch");
}

#[test]
fn all_entries_have_valid_lever_category() {
    let spec = load_discipline();
    let matrix = load_opportunity_matrix();

    let valid_cats: HashSet<String> = spec["lever_categories"]["categories"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();

    let entries = matrix["entries"].as_array().unwrap();
    let mut missing = Vec::new();
    let mut invalid = Vec::new();

    for entry in entries {
        let eid = entry["id"].as_str().unwrap_or("?");
        match entry["lever_category"].as_str() {
            None => missing.push(eid.to_string()),
            Some(cat) if !valid_cats.contains(cat) => invalid.push(format!("{eid}: '{cat}'")),
            _ => {}
        }
    }

    assert!(
        missing.is_empty(),
        "Entries missing lever_category: {:?}",
        missing
    );
    assert!(
        invalid.is_empty(),
        "Entries with invalid lever_category: {:?}",
        invalid
    );
}

#[test]
fn no_multi_lever_beads_without_waiver() {
    let matrix = load_opportunity_matrix();
    let entries = matrix["entries"].as_array().unwrap();

    let mut bead_levers: HashMap<String, HashSet<String>> = HashMap::new();
    for entry in entries {
        if let (Some(bead), Some(lever)) =
            (entry["bead_id"].as_str(), entry["lever_category"].as_str())
        {
            bead_levers
                .entry(bead.to_string())
                .or_default()
                .insert(lever.to_string());
        }
    }

    let mut violations = Vec::new();
    for (bead, levers) in &bead_levers {
        if levers.len() > 1 {
            // Check for waiver
            let has_waiver = entries.iter().any(|e| {
                e["bead_id"].as_str() == Some(bead) && e["justification_waiver"].is_string()
            });
            if !has_waiver {
                violations.push(format!("{bead}: {:?}", levers.iter().collect::<Vec<_>>()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Beads with multiple levers and no waiver: {:?}",
        violations
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_one_lever_discipline.sh");
    assert!(
        script.exists(),
        "scripts/check_one_lever_discipline.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_one_lever_discipline.sh must be executable"
        );
    }
}

#[test]
fn taxonomy_covers_standard_types() {
    let spec = load_discipline();
    let cats: HashSet<String> = spec["lever_categories"]["categories"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();

    let required = [
        "stub_elimination",
        "callthrough_removal",
        "simd_acceleration",
        "cache_optimization",
        "subsystem_implementation",
    ];

    for r in &required {
        assert!(cats.contains(*r), "Missing required category: {r}");
    }
}
