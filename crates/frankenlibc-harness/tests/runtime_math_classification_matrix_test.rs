//! Integration test: runtime_math classification matrix integrity (bd-2k6b)
//!
//! Validates that:
//! 1. The matrix artifact exists and is valid JSON.
//! 2. Matrix module coverage matches governance + linkage + manifest sources.
//! 3. Classification/rationale/linkage fields match source-of-truth artifacts.
//! 4. Research entries include explicit transition notes.
//! 5. Summary statistics are internally consistent.
//! 6. Gate script exists, is executable, and emits structured logs.

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

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json file should exist");
    serde_json::from_str(&content).expect("json should parse")
}

fn load_matrix() -> serde_json::Value {
    load_json(
        &workspace_root().join("tests/runtime_math/runtime_math_classification_matrix.v1.json"),
    )
}

fn load_governance() -> serde_json::Value {
    load_json(&workspace_root().join("tests/conformance/math_governance.json"))
}

fn load_linkage() -> serde_json::Value {
    load_json(&workspace_root().join("tests/runtime_math/runtime_math_linkage.v1.json"))
}

fn load_manifest() -> serde_json::Value {
    load_json(&workspace_root().join("tests/runtime_math/production_kernel_manifest.v1.json"))
}

#[test]
fn matrix_exists_and_valid() {
    let matrix = load_matrix();
    assert_eq!(
        matrix["schema_version"].as_str(),
        Some("v1"),
        "schema_version must be v1"
    );
    assert_eq!(
        matrix["bead"].as_str(),
        Some("bd-2k6b"),
        "bead marker must match"
    );
    assert!(matrix["sources"].is_object(), "sources missing");
    assert!(matrix["modules"].is_array(), "modules must be an array");
    assert!(matrix["summary"].is_object(), "summary must be an object");
}

#[test]
fn matrix_module_coverage_matches_sources() {
    let matrix = load_matrix();
    let gov = load_governance();
    let link = load_linkage();
    let manifest = load_manifest();

    let matrix_modules: HashSet<String> = matrix["modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["module"].as_str().map(String::from))
        .collect();

    let mut expected = HashSet::new();

    for entries in gov["classifications"].as_object().unwrap().values() {
        for entry in entries.as_array().unwrap() {
            if let Some(module) = entry["module"].as_str() {
                expected.insert(module.to_string());
            }
        }
    }

    for (module, _) in link["modules"].as_object().unwrap() {
        expected.insert(module.clone());
    }

    for module in manifest["production_modules"].as_array().unwrap() {
        expected.insert(module.as_str().unwrap().to_string());
    }
    for module in manifest["research_only_modules"].as_array().unwrap() {
        expected.insert(module.as_str().unwrap().to_string());
    }

    assert_eq!(
        matrix_modules, expected,
        "matrix modules must match governance+linkage+manifest union"
    );
}

#[test]
fn matrix_rows_match_governance_and_linkage() {
    let matrix = load_matrix();
    let gov = load_governance();
    let link = load_linkage();
    let manifest = load_manifest();

    let mut gov_map: HashMap<String, (String, String, String)> = HashMap::new();
    for (tier, entries) in gov["classifications"].as_object().unwrap() {
        for (i, entry) in entries.as_array().unwrap().iter().enumerate() {
            let module = entry["module"].as_str().unwrap().to_string();
            let rationale = entry["rationale"].as_str().unwrap().to_string();
            let rationale_ref = format!(
                "tests/conformance/math_governance.json#/classifications/{tier}/{i}/rationale"
            );
            gov_map.insert(module, (tier.clone(), rationale, rationale_ref));
        }
    }

    let mut link_map: HashMap<String, (String, String)> = HashMap::new();
    for (module, meta) in link["modules"].as_object().unwrap() {
        let status = meta["linkage_status"].as_str().unwrap().to_string();
        let target = meta["decision_target"].as_str().unwrap().to_string();
        link_map.insert(module.clone(), (status, target));
    }

    let prod: HashSet<String> = manifest["production_modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    let research_only: HashSet<String> = manifest["research_only_modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    for row in matrix["modules"].as_array().unwrap() {
        let module = row["module"].as_str().unwrap();
        let (exp_tier, exp_rationale, exp_ref) = gov_map
            .get(module)
            .unwrap_or_else(|| panic!("{module} missing from governance map"));
        let (exp_link_status, exp_target) = link_map
            .get(module)
            .unwrap_or_else(|| panic!("{module} missing from linkage map"));

        assert_eq!(
            row["classification"].as_str(),
            Some(exp_tier.as_str()),
            "{module}: tier mismatch"
        );
        assert_eq!(
            row["rationale"].as_str(),
            Some(exp_rationale.as_str()),
            "{module}: rationale mismatch"
        );
        assert_eq!(
            row["rationale_ref"].as_str(),
            Some(exp_ref.as_str()),
            "{module}: rationale_ref mismatch"
        );

        assert_eq!(
            row["linkage_status"].as_str(),
            Some(exp_link_status.as_str()),
            "{module}: linkage_status mismatch"
        );
        assert_eq!(
            row["decision_target"].as_str(),
            Some(exp_target.as_str()),
            "{module}: decision_target mismatch"
        );

        let exp_target_ref = format!(
            "tests/runtime_math/runtime_math_linkage.v1.json#/modules/{module}/decision_target"
        );
        assert_eq!(
            row["decision_target_ref"].as_str(),
            Some(exp_target_ref.as_str()),
            "{module}: decision_target_ref mismatch"
        );

        assert_eq!(
            row["in_production_manifest"].as_bool(),
            Some(prod.contains(module)),
            "{module}: in_production_manifest mismatch"
        );
        assert_eq!(
            row["in_research_only_manifest"].as_bool(),
            Some(research_only.contains(module)),
            "{module}: in_research_only_manifest mismatch"
        );
    }
}

#[test]
fn research_rows_have_transition_notes() {
    let matrix = load_matrix();

    for row in matrix["modules"].as_array().unwrap() {
        let module = row["module"].as_str().unwrap();
        let cls = row["classification"].as_str().unwrap_or("");
        let transition = row["transition"].as_object().unwrap();

        if cls == "research" {
            let note = transition["note"].as_str().unwrap_or("").trim();
            assert!(
                !note.is_empty(),
                "{module}: research entry requires non-empty transition.note"
            );
            let stage = transition["target_stage"].as_str().unwrap_or("");
            assert!(
                stage == "research_only" || stage == "deprecated" || stage == "removed",
                "{module}: research transition.target_stage must be research_only/deprecated/removed"
            );
        } else {
            assert_eq!(
                transition["target_stage"].as_str(),
                Some("production"),
                "{module}: production tier must keep transition.target_stage=production"
            );
        }
    }
}

#[test]
fn summary_consistent() {
    let matrix = load_matrix();
    let summary = matrix["summary"].as_object().unwrap();
    let modules = matrix["modules"].as_array().unwrap();

    let total = modules.len();
    assert_eq!(
        summary["total_modules"].as_u64().unwrap() as usize,
        total,
        "summary.total_modules mismatch"
    );

    let mut class_counts = HashMap::new();
    let mut link_counts = HashMap::new();
    let mut research_in_prod = 0usize;

    for row in modules {
        let cls = row["classification"].as_str().unwrap().to_string();
        *class_counts.entry(cls).or_insert(0usize) += 1;

        let link = row["linkage_status"].as_str().unwrap().to_string();
        *link_counts.entry(link).or_insert(0usize) += 1;

        if row["classification"].as_str() == Some("research")
            && row["in_production_manifest"].as_bool() == Some(true)
        {
            research_in_prod += 1;
        }
    }

    let summary_class = summary["classification_counts"].as_object().unwrap();
    for tier in ["production_core", "production_monitor", "research"] {
        let claimed = summary_class[tier].as_u64().unwrap() as usize;
        let actual = *class_counts.get(tier).unwrap_or(&0);
        assert_eq!(claimed, actual, "classification_counts.{tier} mismatch");
    }

    let summary_link = summary["linkage_status_counts"].as_object().unwrap();
    for status in ["Production", "ResearchOnly"] {
        let claimed = summary_link[status].as_u64().unwrap() as usize;
        let actual = *link_counts.get(status).unwrap_or(&0);
        assert_eq!(claimed, actual, "linkage_status_counts.{status} mismatch");
    }

    assert_eq!(
        summary["research_modules_currently_in_production_manifest"]
            .as_u64()
            .unwrap() as usize,
        research_in_prod,
        "research_modules_currently_in_production_manifest mismatch"
    );
}

#[test]
fn manifest_references_matrix() {
    let manifest = load_manifest();
    assert_eq!(
        manifest["classification_matrix_ref"].as_str(),
        Some("tests/runtime_math/runtime_math_classification_matrix.v1.json"),
        "production manifest must reference classification matrix"
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_math_classification_matrix.sh");
    assert!(
        script.exists(),
        "scripts/check_runtime_math_classification_matrix.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_runtime_math_classification_matrix.sh must be executable"
        );
    }
}

#[test]
fn gate_script_emits_structured_logs() {
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_math_classification_matrix.sh");

    let output = std::process::Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run classification matrix gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = root.join("target/conformance/runtime_math_classification_matrix.log.jsonl");
    let content = std::fs::read_to_string(&log_path).expect("structured log file should exist");

    let mut count = 0usize;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line).expect("log line must be valid json");
        assert_eq!(
            v["event"].as_str(),
            Some("runtime_math.classification_decision"),
            "event mismatch"
        );
        assert!(v["module"].as_str().is_some(), "module missing");
        assert!(v["decision"].as_str().is_some(), "decision missing");
        assert!(
            v["rationale_ref"].as_str().is_some(),
            "rationale_ref missing"
        );
        count += 1;
    }

    let matrix = load_matrix();
    assert_eq!(
        count,
        matrix["modules"].as_array().unwrap().len(),
        "log line count must equal matrix module count"
    );
}
