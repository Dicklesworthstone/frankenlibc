//! Integration test: Replacement levels maturity model (bd-2bu)
//!
//! Validates that:
//! 1. The replacement levels JSON exists and is valid.
//! 2. All four levels (L0–L3) are defined with required fields.
//! 3. Current assessment matches support_matrix.json counts.
//! 4. Status progression is monotonically non-decreasing.
//! 5. Gate criteria monotonically tighten across levels.
//! 6. Transition requirements reference consecutive levels.
//! 7. The CI gate script exists and is executable.
//! 8. README replacement-level claim matches current_level.
//! 9. Release tag policy is aligned with current_level.
//!
//! Run: cargo test -p glibc-rs-harness --test replacement_levels_test

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

fn load_levels() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/replacement_levels.json");
    let content = std::fs::read_to_string(&path).expect("replacement_levels.json should exist");
    serde_json::from_str(&content).expect("replacement_levels.json should be valid JSON")
}

fn load_matrix() -> serde_json::Value {
    let path = workspace_root().join("support_matrix.json");
    let content = std::fs::read_to_string(&path).expect("support_matrix.json should exist");
    serde_json::from_str(&content).expect("support_matrix.json should be valid JSON")
}

fn load_readme() -> String {
    let path = workspace_root().join("README.md");
    std::fs::read_to_string(&path).expect("README.md should exist")
}

#[test]
fn levels_exists_and_valid() {
    let lvl = load_levels();
    assert!(lvl["schema_version"].is_number(), "Missing schema_version");
    assert!(lvl["levels"].is_array(), "Missing levels array");
    assert!(
        lvl["current_assessment"].is_object(),
        "Missing current_assessment"
    );
    assert!(lvl["current_level"].is_string(), "Missing current_level");
    assert!(
        lvl["transition_requirements"].is_object(),
        "Missing transition_requirements"
    );
}

#[test]
fn all_four_levels_defined() {
    let lvl = load_levels();
    let levels = lvl["levels"].as_array().unwrap();

    assert_eq!(levels.len(), 4, "Expected exactly 4 levels");

    let expected = ["L0", "L1", "L2", "L3"];
    let found: Vec<&str> = levels.iter().filter_map(|l| l["level"].as_str()).collect();
    assert_eq!(found, expected, "Levels must be L0, L1, L2, L3 in order");

    let required_fields = [
        "level",
        "name",
        "description",
        "deployment",
        "host_glibc_required",
        "gate_criteria",
        "status",
    ];

    for entry in levels {
        let lid = entry["level"].as_str().unwrap_or("?");
        for field in &required_fields {
            assert!(
                !entry[field].is_null(),
                "{lid}: missing required field \"{field}\""
            );
        }

        // Gate criteria sub-fields
        let gc = &entry["gate_criteria"];
        for gf in [
            "max_callthrough_pct",
            "max_stub_pct",
            "min_implemented_pct",
            "e2e_smoke_required",
        ] {
            assert!(!gc[gf].is_null(), "{lid}: gate_criteria missing \"{gf}\"");
        }
    }
}

#[test]
fn assessment_matches_support_matrix() {
    let lvl = load_levels();
    let matrix = load_matrix();

    let symbols = matrix["symbols"].as_array().unwrap();
    let assessment = &lvl["current_assessment"];

    // Count statuses from matrix
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut module_counts: HashMap<(String, String), usize> = HashMap::new();

    for sym in symbols {
        let status = sym["status"].as_str().unwrap_or("Unknown").to_string();
        let module = sym["module"].as_str().unwrap_or("unknown").to_string();
        *counts.entry(status.clone()).or_default() += 1;
        *module_counts.entry((status, module)).or_default() += 1;
    }

    let matrix_total = symbols.len();
    let claimed_total = assessment["total_symbols"].as_u64().unwrap() as usize;
    assert_eq!(
        claimed_total, matrix_total,
        "total_symbols mismatch: claimed={claimed_total} matrix={matrix_total}"
    );

    for (status_key, json_key) in [
        ("Implemented", "implemented"),
        ("RawSyscall", "raw_syscall"),
        ("GlibcCallThrough", "callthrough"),
        ("Stub", "stub"),
    ] {
        let actual = *counts.get(status_key).unwrap_or(&0);
        let claimed = assessment[json_key].as_u64().unwrap() as usize;
        assert_eq!(
            claimed, actual,
            "{json_key}: claimed={claimed} matrix={actual}"
        );
    }

    // Check callthrough breakdown
    let ct_breakdown = assessment["callthrough_breakdown"].as_object().unwrap();
    for (module, claimed_val) in ct_breakdown {
        let claimed = claimed_val.as_u64().unwrap() as usize;
        let actual = *module_counts
            .get(&("GlibcCallThrough".to_string(), module.clone()))
            .unwrap_or(&0);
        assert_eq!(
            claimed, actual,
            "callthrough_breakdown.{module}: claimed={claimed} matrix={actual}"
        );
    }

    // Check stub breakdown
    let stub_breakdown = assessment["stub_breakdown"].as_object().unwrap();
    for (module, claimed_val) in stub_breakdown {
        let claimed = claimed_val.as_u64().unwrap() as usize;
        let actual = *module_counts
            .get(&("Stub".to_string(), module.clone()))
            .unwrap_or(&0);
        assert_eq!(
            claimed, actual,
            "stub_breakdown.{module}: claimed={claimed} matrix={actual}"
        );
    }
}

#[test]
fn status_progression_consistent() {
    let lvl = load_levels();
    let levels = lvl["levels"].as_array().unwrap();

    let status_order: HashMap<&str, usize> = [
        ("achieved", 0),
        ("in_progress", 1),
        ("planned", 2),
        ("roadmap", 3),
    ]
    .into_iter()
    .collect();

    let valid_statuses: HashSet<&str> = ["achieved", "in_progress", "planned", "roadmap"]
        .into_iter()
        .collect();

    let mut prev_order: Option<usize> = None;
    let mut prev_level = "";

    for entry in levels {
        let lid = entry["level"].as_str().unwrap_or("?");
        let status = entry["status"].as_str().unwrap_or("unknown");

        assert!(
            valid_statuses.contains(status),
            "{lid}: invalid status \"{status}\""
        );

        let order = status_order[status];
        if let Some(po) = prev_order {
            assert!(
                order >= po,
                "{lid} ({status}) is less mature than {prev_level} — status should be monotonically non-decreasing"
            );
        }
        prev_order = Some(order);
        prev_level = lid;
    }

    // current_level must have status "achieved"
    let current = lvl["current_level"].as_str().unwrap_or("");
    let current_entry = levels.iter().find(|e| e["level"].as_str() == Some(current));
    assert!(
        current_entry.is_some(),
        "current_level={current} not found in levels"
    );
    assert_eq!(
        current_entry.unwrap()["status"].as_str().unwrap_or(""),
        "achieved",
        "current_level={current} must have status \"achieved\""
    );
}

#[test]
fn gate_criteria_monotonically_tighten() {
    let lvl = load_levels();
    let levels = lvl["levels"].as_array().unwrap();

    let mut prev_callthrough: Option<(String, u64)> = None;
    let mut prev_stub: Option<(String, u64)> = None;
    let mut prev_implemented: Option<(String, u64)> = None;

    for entry in levels {
        let lid = entry["level"].as_str().unwrap_or("?").to_string();
        let gc = &entry["gate_criteria"];

        if let Some(val) = gc["max_callthrough_pct"].as_u64() {
            if let Some((ref prev_lid, prev_val)) = prev_callthrough {
                assert!(
                    val <= prev_val,
                    "max_callthrough_pct: {lid}={val} > {prev_lid}={prev_val} (should be non-increasing)"
                );
            }
            prev_callthrough = Some((lid.clone(), val));
        }

        if let Some(val) = gc["max_stub_pct"].as_u64() {
            if let Some((ref prev_lid, prev_val)) = prev_stub {
                assert!(
                    val <= prev_val,
                    "max_stub_pct: {lid}={val} > {prev_lid}={prev_val} (should be non-increasing)"
                );
            }
            prev_stub = Some((lid.clone(), val));
        }

        if let Some(val) = gc["min_implemented_pct"].as_u64() {
            if let Some((ref prev_lid, prev_val)) = prev_implemented {
                assert!(
                    val >= prev_val,
                    "min_implemented_pct: {lid}={val} < {prev_lid}={prev_val} (should be non-decreasing)"
                );
            }
            prev_implemented = Some((lid.clone(), val));
        }
    }
}

#[test]
fn transition_requirements_reference_consecutive_levels() {
    let lvl = load_levels();
    let transitions = lvl["transition_requirements"].as_object().unwrap();

    let expected_keys = ["L0_to_L1", "L1_to_L2", "L2_to_L3"];
    for key in &expected_keys {
        assert!(
            transitions.contains_key(*key),
            "Missing transition_requirements.{key}"
        );
        let reqs = transitions[*key].as_array().unwrap();
        assert!(!reqs.is_empty(), "transition_requirements.{key} is empty");
        for req in reqs {
            assert!(
                req.is_string() && !req.as_str().unwrap().is_empty(),
                "transition_requirements.{key}: each requirement must be a non-empty string"
            );
        }
    }
}

#[test]
fn percentages_consistent() {
    let lvl = load_levels();
    let assessment = &lvl["current_assessment"];

    let total = assessment["total_symbols"].as_u64().unwrap() as f64;
    assert!(total > 0.0, "total_symbols must be > 0");

    let implemented = assessment["implemented"].as_u64().unwrap() as f64;
    let raw_syscall = assessment["raw_syscall"].as_u64().unwrap() as f64;
    let callthrough = assessment["callthrough"].as_u64().unwrap() as f64;
    let stub = assessment["stub"].as_u64().unwrap() as f64;

    // Counts must sum to total
    let sum = implemented + raw_syscall + callthrough + stub;
    assert_eq!(
        sum as u64, total as u64,
        "Status counts ({sum}) don't sum to total ({total})"
    );

    // Percentages must be roughly correct (within 1% due to rounding)
    let check_pct = |name: &str, count: f64, claimed_pct: u64| {
        let actual_pct = (count * 100.0 / total).round() as u64;
        let diff = actual_pct.abs_diff(claimed_pct);
        assert!(
            diff <= 1,
            "{name}_pct: claimed={claimed_pct} computed={actual_pct} (diff={diff} > 1)"
        );
    };

    check_pct(
        "implemented",
        implemented,
        assessment["implemented_pct"].as_u64().unwrap(),
    );
    check_pct(
        "raw_syscall",
        raw_syscall,
        assessment["raw_syscall_pct"].as_u64().unwrap(),
    );
    check_pct(
        "callthrough",
        callthrough,
        assessment["callthrough_pct"].as_u64().unwrap(),
    );
    check_pct("stub", stub, assessment["stub_pct"].as_u64().unwrap());
}

#[test]
fn claim_drift_guard_consistent_with_readme_and_release_policy() {
    let lvl = load_levels();
    let readme = load_readme();

    let levels = lvl["levels"].as_array().unwrap();
    let current = lvl["current_level"].as_str().unwrap_or("");
    let current_entry = levels
        .iter()
        .find(|e| e["level"].as_str() == Some(current))
        .expect("current_level must exist in levels[]");
    let current_name = current_entry["name"]
        .as_str()
        .expect("current level must have a name");

    let expected_claim =
        format!("Declared replacement level claim: **{current} — {current_name}**.");
    assert!(
        readme.contains(&expected_claim),
        "README replacement-level claim line missing/stale: {expected_claim}"
    );
    assert_eq!(
        readme
            .matches("Declared replacement level claim: **")
            .count(),
        1,
        "README must contain exactly one replacement-level claim line"
    );

    let policy = lvl["release_tag_policy"]
        .as_object()
        .expect("release_tag_policy must be an object");
    assert!(
        policy.contains_key("tag_format")
            && policy["tag_format"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
        "release_tag_policy.tag_format must be a non-empty string"
    );

    let suffixes = policy["level_tag_suffix"]
        .as_object()
        .expect("release_tag_policy.level_tag_suffix must be an object");
    for lid in ["L0", "L1", "L2", "L3"] {
        let expected = format!("-{lid}");
        let actual = suffixes
            .get(lid)
            .and_then(|v| v.as_str())
            .unwrap_or("<missing>");
        assert_eq!(
            actual, expected,
            "release_tag_policy.level_tag_suffix.{lid} must equal {expected}"
        );
    }

    let claimed_release_level = policy["current_release_level"].as_str().unwrap_or("");
    assert_eq!(
        claimed_release_level, current,
        "release_tag_policy.current_release_level must match current_level"
    );

    let example = policy["current_release_tag_example"].as_str().unwrap_or("");
    assert!(
        !example.is_empty(),
        "release_tag_policy.current_release_tag_example must be non-empty"
    );
    assert!(
        example.ends_with(&format!("-{current}")),
        "current_release_tag_example must end with -{current}, got {example}"
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_replacement_levels.sh");
    assert!(
        script.exists(),
        "scripts/check_replacement_levels.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_replacement_levels.sh must be executable"
        );
    }
}
