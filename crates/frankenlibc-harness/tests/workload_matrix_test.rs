//! Integration test: Hard-parts workload matrix (bd-3u0)
//!
//! Validates that:
//! 1. The workload matrix JSON exists and is valid.
//! 2. All workloads have required fields and reference valid ABI modules.
//! 3. Replacement blockers match support_matrix non-replaceable status truth.
//! 4. Subsystem impact counts match actual blocker references.
//! 5. Every milestone maps to at least one workload.
//! 6. Summary statistics are consistent.
//! 7. The CI gate script exists and is executable.
//!
//! Run: cargo test -p frankenlibc-harness --test workload_matrix_test

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

fn load_workloads() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/workload_matrix.json");
    let content = std::fs::read_to_string(&path).expect("workload_matrix.json should exist");
    serde_json::from_str(&content).expect("workload_matrix.json should be valid JSON")
}

fn load_support_matrix() -> serde_json::Value {
    let path = workspace_root().join("support_matrix.json");
    let content = std::fs::read_to_string(&path).expect("support_matrix.json should exist");
    serde_json::from_str(&content).expect("support_matrix.json should be valid JSON")
}

#[test]
fn matrix_exists_and_valid() {
    let wl = load_workloads();
    assert!(wl["schema_version"].is_number(), "Missing schema_version");
    assert!(wl["workloads"].is_array(), "Missing workloads");
    assert!(
        wl["subsystem_impact"].is_object(),
        "Missing subsystem_impact"
    );
    assert!(
        wl["milestone_mapping"].is_object(),
        "Missing milestone_mapping"
    );
    assert!(wl["summary"].is_object(), "Missing summary");
}

#[test]
fn workloads_have_required_fields() {
    let wl = load_workloads();
    let matrix = load_support_matrix();

    let valid_modules: HashSet<String> = matrix["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["module"].as_str().map(String::from))
        .collect();

    let workloads = wl["workloads"].as_array().unwrap();
    let required = [
        "id",
        "binary",
        "description",
        "category",
        "required_modules",
        "blocked_by",
        "interpose_ready",
        "replace_ready",
        "priority_impact",
    ];

    let mut ids_seen = HashSet::new();

    for entry in workloads {
        let wid = entry["id"].as_str().unwrap_or("?");

        for field in &required {
            assert!(!entry[field].is_null(), "{wid}: missing field \"{field}\"");
        }

        // Check modules are valid
        for mod_val in entry["required_modules"].as_array().unwrap() {
            let module = mod_val.as_str().unwrap();
            assert!(
                valid_modules.contains(module),
                "{wid}: invalid module \"{module}\""
            );
        }

        // Unique IDs
        assert!(ids_seen.insert(wid.to_string()), "{wid}: duplicate ID");
    }
}

#[test]
fn subsystem_impact_consistent() {
    let wl = load_workloads();
    let workloads = wl["workloads"].as_array().unwrap();
    let impact = wl["subsystem_impact"].as_object().unwrap();

    let valid_ids: HashSet<String> = workloads
        .iter()
        .filter_map(|w| w["id"].as_str().map(String::from))
        .collect();

    // Build actual blocker map
    let mut actual: HashMap<String, HashSet<String>> = HashMap::new();
    for w in workloads {
        let wid = w["id"].as_str().unwrap().to_string();
        for mod_val in w["blocked_by"].as_array().unwrap() {
            let module = mod_val.as_str().unwrap().to_string();
            actual.entry(module).or_default().insert(wid.clone());
        }
    }

    for (module, info) in impact {
        if module == "description" {
            continue;
        }
        let claimed_count = info["blocked_workloads"].as_u64().unwrap() as usize;
        let claimed_ids: HashSet<String> = info["workload_ids"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();

        let actual_ids = actual.get(module).cloned().unwrap_or_default();

        assert_eq!(
            claimed_count,
            actual_ids.len(),
            "{module}: claimed {claimed_count} blocked, actual {}",
            actual_ids.len()
        );
        assert_eq!(claimed_ids, actual_ids, "{module}: workload ID mismatch");

        // All referenced IDs must exist
        for wid in &claimed_ids {
            assert!(
                valid_ids.contains(wid),
                "{module}: references nonexistent workload {wid}"
            );
        }
    }
}

#[test]
fn replacement_blockers_match_support_matrix() {
    let wl = load_workloads();
    let matrix = load_support_matrix();
    let blocker_statuses = ["WrapsHostLibc", "GlibcCallThrough", "Stub"];
    let mut module_counts: HashMap<String, HashMap<String, usize>> = HashMap::new();

    for symbol in matrix["symbols"].as_array().unwrap() {
        let status = symbol["status"].as_str().unwrap_or("");
        if !blocker_statuses.contains(&status) {
            continue;
        }
        let module = symbol["module"].as_str().unwrap_or("unknown").to_string();
        *module_counts
            .entry(module)
            .or_default()
            .entry(status.to_string())
            .or_default() += 1;
    }

    for workload in wl["workloads"].as_array().unwrap() {
        let wid = workload["id"].as_str().unwrap_or("?");
        let mut seen_modules = HashSet::new();
        let required_modules: Vec<_> = workload["required_modules"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str())
            .filter(|module| seen_modules.insert((*module).to_string()))
            .collect();

        let expected_modules: Vec<String> = required_modules
            .iter()
            .filter(|module| {
                module_counts
                    .get(**module)
                    .is_some_and(|counts| counts.values().sum::<usize>() > 0)
            })
            .map(|module| (*module).to_string())
            .collect();

        let actual_modules: Vec<String> = workload["blocked_by"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str().map(String::from))
            .collect();
        assert_eq!(
            actual_modules, expected_modules,
            "{wid}: blocked_by must match support_matrix replacement blockers"
        );

        let mut expected_blockers = Vec::new();
        for module in &expected_modules {
            let counts = module_counts.get(module.as_str()).unwrap();
            for status in blocker_statuses {
                let count = counts.get(status).copied().unwrap_or(0);
                if count > 0 {
                    expected_blockers.push(format!("{module} ({count} {status})"));
                }
            }
        }
        let actual_blockers: Vec<String> = workload["replace_blockers"]
            .as_array()
            .expect("replace_blockers must be an array")
            .iter()
            .filter_map(|value| value.as_str().map(String::from))
            .collect();
        assert_eq!(
            actual_blockers, expected_blockers,
            "{wid}: replace_blockers must match support_matrix status counts"
        );

        assert_eq!(
            workload["replace_ready"].as_bool(),
            Some(expected_modules.is_empty()),
            "{wid}: replace_ready must reflect replacement blocker presence"
        );
    }
}

#[test]
fn milestones_reference_valid_workloads() {
    let wl = load_workloads();
    let valid_ids: HashSet<String> = wl["workloads"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|w| w["id"].as_str().map(String::from))
        .collect();

    let milestones = wl["milestone_mapping"]["milestones"].as_array().unwrap();

    for ms in milestones {
        let bead = ms["bead"].as_str().unwrap_or("?");
        for wid_val in ms["unblocks_workloads"].as_array().unwrap() {
            let wid = wid_val.as_str().unwrap();
            assert!(
                valid_ids.contains(wid),
                "Milestone {bead}: references nonexistent workload {wid}"
            );
        }
    }
}

#[test]
fn summary_consistent() {
    let wl = load_workloads();
    let workloads = wl["workloads"].as_array().unwrap();
    let summary = &wl["summary"];

    let total = workloads.len();
    let interpose_ready = workloads
        .iter()
        .filter(|w| w["interpose_ready"].as_bool() == Some(true))
        .count();
    let replace_ready = workloads
        .iter()
        .filter(|w| w["replace_ready"].as_bool() == Some(true))
        .count();
    let mut blocker_counts: HashMap<String, usize> = HashMap::new();
    let mut workload_blocker_counts: HashMap<String, usize> = HashMap::new();

    assert_eq!(
        summary["total_workloads"].as_u64().unwrap() as usize,
        total,
        "total_workloads mismatch"
    );
    assert_eq!(
        summary["interpose_ready"].as_u64().unwrap() as usize,
        interpose_ready,
        "interpose_ready mismatch"
    );
    assert_eq!(
        summary["replace_ready"].as_u64().unwrap() as usize,
        replace_ready,
        "replace_ready mismatch"
    );
    assert_eq!(
        summary["replace_blocked"].as_u64().unwrap() as usize,
        total - replace_ready,
        "replace_blocked mismatch"
    );

    // Category counts
    let mut cats: HashMap<String, usize> = HashMap::new();
    for w in workloads {
        let c = w["category"].as_str().unwrap_or("unknown");
        *cats.entry(c.to_string()).or_default() += 1;

        let wid = w["id"].as_str().unwrap_or("?").to_string();
        let blocked_by = w["blocked_by"].as_array().unwrap();
        workload_blocker_counts.insert(wid, blocked_by.len());
        for module in blocked_by {
            let module = module.as_str().unwrap_or("unknown");
            *blocker_counts.entry(module.to_string()).or_default() += 1;
        }
    }
    let claimed_cats = summary["categories"].as_object().unwrap();
    for (c, count) in &cats {
        let claimed = claimed_cats[c].as_u64().unwrap() as usize;
        assert_eq!(
            claimed, *count,
            "categories.{c}: claimed={claimed} actual={count}"
        );
    }

    if blocker_counts.is_empty() {
        assert!(
            summary["top_blocker"].is_null(),
            "top_blocker must be null when no blockers remain"
        );
    } else {
        let (module, count) = blocker_counts
            .iter()
            .max_by(|(left_module, left_count), (right_module, right_count)| {
                left_count
                    .cmp(right_count)
                    .then_with(|| left_module.cmp(right_module))
            })
            .unwrap();
        let expected = format!("{module} (blocks {count} workloads)");
        assert_eq!(
            summary["top_blocker"].as_str(),
            Some(expected.as_str()),
            "top_blocker mismatch"
        );
    }

    if workload_blocker_counts.values().all(|count| *count == 0) {
        assert!(
            summary["most_blocked_workload"].is_null(),
            "most_blocked_workload must be null when no blockers remain"
        );
    }
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_workload_matrix.sh");
    assert!(
        script.exists(),
        "scripts/check_workload_matrix.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_workload_matrix.sh must be executable"
        );
    }
}
