//! Integration test: One-lever discipline guard (bd-22p)
//!
//! Validates that:
//! 1. The discipline spec exists and defines lever categories.
//! 2. Every opportunity matrix entry has a valid lever_category.
//! 3. Every opportunity carries golden verification, rollback, and attribution metadata.
//! 4. No bead references multiple lever categories without a waiver.
//! 5. The summary is consistent with the categories.
//! 6. The gate script exists and is executable.
//! 7. Category taxonomy covers standard optimization types.
//!
//! Run: cargo test -p frankenlibc-harness --test one_lever_discipline_test

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
    assert!(spec["entry_contract"].is_object(), "Missing entry_contract");
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
fn entry_contract_declares_required_wave_metadata() {
    let spec = load_discipline();
    let contract = &spec["entry_contract"];

    let required: HashSet<String> = contract["required_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|value| value.as_str().map(String::from))
        .collect();
    let golden_fields: HashSet<String> = contract["golden_output_verification_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|value| value.as_str().map(String::from))
        .collect();
    let rollback_fields: HashSet<String> = contract["rollback_instruction_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|value| value.as_str().map(String::from))
        .collect();
    let attribution_fields: HashSet<String> = contract["attribution_metadata_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|value| value.as_str().map(String::from))
        .collect();

    for field in [
        "lever_category",
        "golden_output_verification",
        "rollback_instructions",
        "attribution_metadata",
    ] {
        assert!(required.contains(field), "Missing required field: {field}");
    }

    for field in ["artifact_refs", "verification_command", "invariants"] {
        assert!(
            golden_fields.contains(field),
            "Missing golden_output_verification field: {field}"
        );
    }

    for field in [
        "strategy",
        "command",
        "expected_revert_scope",
        "artifact_regeneration_commands",
    ] {
        assert!(
            rollback_fields.contains(field),
            "Missing rollback_instruction field: {field}"
        );
    }

    for field in [
        "opportunity_owner",
        "selection_basis",
        "baseline_artifacts",
        "profile_artifacts",
    ] {
        assert!(
            attribution_fields.contains(field),
            "Missing attribution_metadata field: {field}"
        );
    }
}

#[test]
fn summary_consistent() {
    let spec = load_discipline();
    let cats = spec["lever_categories"]["categories"].as_object().unwrap();
    let contract = &spec["entry_contract"];
    let summary = &spec["summary"];

    let total = summary["total_categories"].as_u64().unwrap() as usize;
    assert_eq!(total, cats.len(), "total_categories mismatch");

    let required_fields = contract["required_fields"].as_array().unwrap().len();
    let claimed_required = summary["required_entry_fields"].as_u64().unwrap() as usize;
    assert_eq!(
        claimed_required, required_fields,
        "required_entry_fields mismatch"
    );

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
fn all_entries_have_required_wave_metadata() {
    let root = workspace_root();
    let matrix = load_opportunity_matrix();
    let entries = matrix["entries"].as_array().unwrap();

    for entry in entries {
        let eid = entry["id"].as_str().unwrap_or("?");

        let golden = entry["golden_output_verification"]
            .as_object()
            .unwrap_or_else(|| panic!("{eid}: missing golden_output_verification"));
        let artifact_refs = golden["artifact_refs"]
            .as_array()
            .unwrap_or_else(|| panic!("{eid}: missing golden_output_verification.artifact_refs"));
        assert!(
            !artifact_refs.is_empty(),
            "{eid}: artifact_refs must not be empty"
        );
        for artifact in artifact_refs {
            let artifact = artifact
                .as_str()
                .unwrap_or_else(|| panic!("{eid}: artifact_refs entries must be strings"));
            assert!(
                root.join(artifact).exists(),
                "{eid}: referenced artifact does not exist: {artifact}"
            );
        }
        let verification_command = golden["verification_command"]
            .as_str()
            .unwrap_or_else(|| panic!("{eid}: missing verification_command"));
        assert!(
            !verification_command.trim().is_empty(),
            "{eid}: verification_command must not be empty"
        );
        let invariants = golden["invariants"]
            .as_array()
            .unwrap_or_else(|| panic!("{eid}: missing invariants"));
        assert!(
            !invariants.is_empty(),
            "{eid}: invariants must not be empty"
        );

        let rollback = entry["rollback_instructions"]
            .as_object()
            .unwrap_or_else(|| panic!("{eid}: missing rollback_instructions"));
        let rollback_command = rollback["command"]
            .as_str()
            .unwrap_or_else(|| panic!("{eid}: missing rollback command"));
        assert!(
            rollback_command.contains("git revert"),
            "{eid}: rollback command must use git revert"
        );
        let regeneration_commands = rollback["artifact_regeneration_commands"]
            .as_array()
            .unwrap_or_else(|| panic!("{eid}: missing artifact_regeneration_commands"));
        assert!(
            !regeneration_commands.is_empty(),
            "{eid}: artifact_regeneration_commands must not be empty"
        );
        assert!(
            rollback["expected_revert_scope"]
                .as_str()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false),
            "{eid}: expected_revert_scope must be non-empty"
        );
        assert!(
            rollback["strategy"]
                .as_str()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false),
            "{eid}: strategy must be non-empty"
        );

        let attribution = entry["attribution_metadata"]
            .as_object()
            .unwrap_or_else(|| panic!("{eid}: missing attribution_metadata"));
        assert!(
            attribution["selection_basis"]
                .as_str()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false),
            "{eid}: selection_basis must be non-empty"
        );
        for field in ["baseline_artifacts", "profile_artifacts"] {
            let refs = attribution[field]
                .as_array()
                .unwrap_or_else(|| panic!("{eid}: missing {field}"));
            assert!(!refs.is_empty(), "{eid}: {field} must not be empty");
            for artifact in refs {
                let artifact = artifact
                    .as_str()
                    .unwrap_or_else(|| panic!("{eid}: {field} entries must be strings"));
                assert!(
                    root.join(artifact).exists(),
                    "{eid}: referenced {field} artifact does not exist: {artifact}"
                );
            }
        }
        assert!(
            attribution["opportunity_owner"]
                .as_str()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false),
            "{eid}: opportunity_owner must be non-empty"
        );
    }
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
