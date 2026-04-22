//! Integration test: Isomorphism proof protocol (bd-2bd)
//!
//! Validates that:
//! 1. The protocol JSON exists and is valid.
//! 2. All six proof categories are defined with checks and golden formats.
//! 3. Proof template has required fields and valid statuses.
//! 4. Example proof satisfies the template.
//! 5. Applicable modules reference valid ABI modules.
//! 6. Proof artifacts exist, are listed in the protocol, and validate their hashes.
//! 7. Summary statistics are consistent.
//! 8. The CI gate script exists and is executable.
//!
//! Run: cargo test -p frankenlibc-harness --test isomorphism_proof_test

use sha2::{Digest, Sha256};
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

fn load_protocol() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/isomorphism_proof_protocol.json");
    let content =
        std::fs::read_to_string(&path).expect("isomorphism_proof_protocol.json should exist");
    serde_json::from_str(&content).expect("isomorphism_proof_protocol.json should be valid JSON")
}

fn sha256_hex(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|_| panic!("failed reading {}", path.display()));
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_digest(&hasher.finalize())
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn load_matrix() -> serde_json::Value {
    let path = workspace_root().join("support_matrix.json");
    let content = std::fs::read_to_string(&path).expect("support_matrix.json should exist");
    serde_json::from_str(&content).expect("support_matrix.json should be valid JSON")
}

#[test]
fn protocol_exists_and_valid() {
    let proto = load_protocol();
    assert!(
        proto["schema_version"].is_number(),
        "Missing schema_version"
    );
    assert!(
        proto["proof_categories"].is_object(),
        "Missing proof_categories"
    );
    assert!(
        proto["proof_template"].is_object(),
        "Missing proof_template"
    );
    assert!(proto["enforcement"].is_object(), "Missing enforcement");
    assert!(
        proto["applicable_modules"].is_object(),
        "Missing applicable_modules"
    );
    assert!(
        proto["existing_proofs"].is_array(),
        "Missing existing_proofs"
    );
    assert!(proto["summary"].is_object(), "Missing summary");
}

#[test]
fn all_proof_categories_defined() {
    let proto = load_protocol();
    let cats = proto["proof_categories"].as_object().unwrap();

    let expected = [
        "ordering",
        "tie_breaking",
        "fp_behavior",
        "rng_behavior",
        "side_effects",
        "memory_semantics",
    ];

    for cat_name in &expected {
        assert!(
            cats.contains_key(*cat_name),
            "Missing proof category: {cat_name}"
        );
        let cat = &cats[*cat_name];
        assert!(
            cat["description"].is_string(),
            "{cat_name}: missing description"
        );
        let checks = cat["required_checks"].as_array().unwrap();
        assert!(!checks.is_empty(), "{cat_name}: empty required_checks");
        assert!(
            cat["golden_format"].is_string(),
            "{cat_name}: missing golden_format"
        );
    }
}

#[test]
fn proof_template_complete() {
    let proto = load_protocol();
    let template = &proto["proof_template"];

    let required = template["required_fields"].as_array().unwrap();
    let required_strs: HashSet<&str> = required.iter().filter_map(|v| v.as_str()).collect();

    for field in [
        "lever_id",
        "bead_id",
        "functions",
        "categories",
        "golden_commands",
        "golden_artifacts",
        "golden_hash",
        "proof_status",
        "rollback_instructions",
        "attribution_metadata",
    ] {
        assert!(
            required_strs.contains(field),
            "required_fields missing: {field}"
        );
    }

    // Valid statuses
    let statuses: HashSet<&str> = template["proof_statuses"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    for st in ["pending", "verified", "failed", "waived"] {
        assert!(statuses.contains(st), "proof_statuses missing: {st}");
    }
}

#[test]
fn example_satisfies_template() {
    let proto = load_protocol();
    let template = &proto["proof_template"];
    let example = &template["example"];

    assert!(!example.is_null(), "Missing example proof");

    let required = template["required_fields"].as_array().unwrap();
    for field in required {
        let field_str = field.as_str().unwrap();
        assert!(
            !example[field_str].is_null(),
            "Example missing required field: {field_str}"
        );
    }

    // Example proof_status must be a valid status
    let statuses: HashSet<&str> = template["proof_statuses"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    let example_status = example["proof_status"].as_str().unwrap();
    assert!(
        statuses.contains(example_status),
        "Example proof_status \"{example_status}\" not in valid statuses"
    );

    // Example categories must reference defined categories
    let cats: HashSet<&str> = proto["proof_categories"]
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    for cat in example["categories"].as_array().unwrap() {
        let cat_str = cat.as_str().unwrap();
        assert!(
            cats.contains(cat_str),
            "Example references undefined category: {cat_str}"
        );
    }

    assert!(
        example["golden_artifacts"].as_array().is_some(),
        "Example must contain golden_artifacts"
    );
    assert!(
        example["rollback_instructions"].is_object(),
        "Example must contain rollback_instructions"
    );
    assert!(
        example["attribution_metadata"].is_object(),
        "Example must contain attribution_metadata"
    );
}

#[test]
fn applicable_modules_valid() {
    let proto = load_protocol();
    let matrix = load_matrix();

    let valid_modules: HashSet<String> = matrix["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["module"].as_str().map(String::from))
        .collect();

    let applicable = &proto["applicable_modules"];
    let mut all_modules = Vec::new();

    for priority in ["high_priority", "medium_priority", "low_priority"] {
        let entries = applicable[priority].as_array().unwrap();
        for entry in entries {
            let module = entry["module"].as_str().unwrap();
            assert!(
                valid_modules.contains(module),
                "{module} ({priority}): not a valid ABI module"
            );
            assert!(
                entry["reason"].is_string(),
                "{module} ({priority}): missing reason"
            );
            all_modules.push(module.to_string());
        }
    }

    // No duplicates
    let unique: HashSet<&str> = all_modules.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        unique.len(),
        all_modules.len(),
        "Duplicate modules in applicable_modules"
    );
}

#[test]
fn proof_directory_exists_and_records_validate() {
    let root = workspace_root();
    let proto = load_protocol();
    let template = &proto["proof_template"];

    let required: Vec<String> = template["required_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|value| value.as_str().map(String::from))
        .collect();
    let valid_statuses: HashSet<&str> = template["proof_statuses"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|value| value.as_str())
        .collect();
    let valid_categories: HashSet<&str> = proto["proof_categories"]
        .as_object()
        .unwrap()
        .keys()
        .map(|key| key.as_str())
        .collect();

    let proof_dir = root.join(proto["enforcement"]["proof_directory"].as_str().unwrap());
    assert!(proof_dir.is_dir(), "proof directory must exist");

    let listed_proofs = proto["existing_proofs"].as_array().unwrap();
    assert!(
        !listed_proofs.is_empty(),
        "existing_proofs must not be empty"
    );
    let listed_paths: HashSet<String> = listed_proofs
        .iter()
        .map(|value| value["proof_path"].as_str().unwrap().to_string())
        .collect();

    let mut discovered_paths = HashSet::new();
    for entry in std::fs::read_dir(&proof_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let relative = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        discovered_paths.insert(relative.clone());
        assert!(
            listed_paths.contains(&relative),
            "proof file missing from existing_proofs: {relative}"
        );

        let content = std::fs::read_to_string(&path).unwrap();
        let proof: serde_json::Value = serde_json::from_str(&content).unwrap();
        for field in &required {
            assert!(
                !proof[field].is_null(),
                "{} missing required field {}",
                relative,
                field
            );
        }

        let proof_status = proof["proof_status"].as_str().unwrap();
        assert!(
            valid_statuses.contains(proof_status),
            "{} invalid proof_status {}",
            relative,
            proof_status
        );

        let categories = proof["categories"].as_array().unwrap();
        assert!(
            !categories.is_empty(),
            "{} categories must not be empty",
            relative
        );
        for category in categories {
            let category = category.as_str().unwrap();
            assert!(
                valid_categories.contains(category),
                "{} references unknown category {}",
                relative,
                category
            );
        }

        let golden_artifacts = proof["golden_artifacts"].as_array().unwrap();
        assert!(
            !golden_artifacts.is_empty(),
            "{} golden_artifacts must not be empty",
            relative
        );
        for artifact in golden_artifacts {
            let artifact_path = artifact["path"].as_str().unwrap();
            let expected_sha = artifact["sha256"].as_str().unwrap();
            let full_path = root.join(artifact_path);
            assert!(
                full_path.exists(),
                "{} references missing golden artifact {}",
                relative,
                artifact_path
            );
            let actual_sha = format!("sha256:{}", sha256_hex(&full_path));
            assert_eq!(
                actual_sha, expected_sha,
                "{} hash mismatch for {}",
                relative, artifact_path
            );
        }

        let rollback = proof["rollback_instructions"].as_object().unwrap();
        let rollback_command = rollback["command"].as_str().unwrap();
        assert!(
            rollback_command.contains("git revert"),
            "{} rollback command must use git revert",
            relative
        );
        let regeneration_commands = rollback["artifact_regeneration_commands"]
            .as_array()
            .unwrap();
        assert!(
            !regeneration_commands.is_empty(),
            "{} artifact_regeneration_commands must not be empty",
            relative
        );

        let attribution = proof["attribution_metadata"].as_object().unwrap();
        for field in ["baseline_artifacts", "profile_artifacts"] {
            let refs = attribution[field].as_array().unwrap();
            assert!(!refs.is_empty(), "{} {} must not be empty", relative, field);
            for artifact in refs {
                let artifact = artifact.as_str().unwrap();
                assert!(
                    root.join(artifact).exists(),
                    "{} references missing attribution artifact {}",
                    relative,
                    artifact
                );
            }
        }
    }

    assert_eq!(
        discovered_paths, listed_paths,
        "existing_proofs must match proof directory contents"
    );
}

#[test]
fn summary_consistent() {
    let proto = load_protocol();
    let summary = &proto["summary"];
    let cats = proto["proof_categories"].as_object().unwrap();
    let applicable = &proto["applicable_modules"];
    let proofs = proto["existing_proofs"].as_array().unwrap();

    assert_eq!(
        summary["total_categories"].as_u64().unwrap() as usize,
        cats.len(),
        "total_categories mismatch"
    );

    for (priority, key) in [
        ("high_priority", "high_priority_modules"),
        ("medium_priority", "medium_priority_modules"),
        ("low_priority", "low_priority_modules"),
    ] {
        let claimed = summary[key].as_u64().unwrap() as usize;
        let actual = applicable[priority].as_array().unwrap().len();
        assert_eq!(claimed, actual, "{key} mismatch");
    }

    assert_eq!(
        summary["existing_proof_count"].as_u64().unwrap() as usize,
        proofs.len(),
        "existing_proof_count mismatch"
    );
    assert_eq!(
        summary["enforcement_status"].as_str().unwrap(),
        "artifacts_present",
        "enforcement_status must reflect proof artifact presence"
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_isomorphism_proof.sh");
    assert!(
        script.exists(),
        "scripts/check_isomorphism_proof.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_isomorphism_proof.sh must be executable"
        );
    }
}
