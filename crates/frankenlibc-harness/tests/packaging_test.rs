//! Integration test: Packaging specification (bd-30h)
//!
//! Validates that:
//! 1. The packaging spec JSON exists and is valid.
//! 2. Both artifacts (interpose/replace) are defined with correct contracts.
//! 3. Assessment counts match support_matrix.json.
//! 4. Replace blockers match actual WrapsHostLibc+GlibcCallThrough+Stub symbols.
//! 5. Feature gates are documented.
//! 6. Matrix applicability rule is correct.
//! 7. The CI gate script exists and is executable.
//!
//! Run: cargo test -p frankenlibc-harness --test packaging_test

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

fn load_spec() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/packaging_spec.json");
    let content = std::fs::read_to_string(&path).expect("packaging_spec.json should exist");
    serde_json::from_str(&content).expect("packaging_spec.json should be valid JSON")
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
fn spec_exists_and_valid() {
    let spec = load_spec();
    assert!(spec["schema_version"].is_number(), "Missing schema_version");
    assert!(spec["artifacts"].is_object(), "Missing artifacts");
    assert!(
        spec["current_assessment"].is_object(),
        "Missing current_assessment"
    );
    assert!(
        spec["naming_convention"].is_object(),
        "Missing naming_convention"
    );
    assert!(spec["feature_gates"].is_object(), "Missing feature_gates");
    assert!(
        spec["matrix_applicability"].is_object(),
        "Missing matrix_applicability"
    );
}

#[test]
fn both_artifacts_defined_with_correct_contracts() {
    let spec = load_spec();
    let artifacts = spec["artifacts"].as_object().unwrap();

    let required_fields = [
        "name",
        "artifact_name",
        "description",
        "build_command",
        "output_path",
        "host_glibc_required",
        "allowed_statuses",
        "replacement_levels",
        "cargo_profile",
        "crate_type",
        "guarantee",
    ];

    for artifact_id in ["interpose", "replace"] {
        assert!(
            artifacts.contains_key(artifact_id),
            "Missing artifact: {artifact_id}"
        );
        let art = &artifacts[artifact_id];
        for field in &required_fields {
            assert!(
                !art[field].is_null(),
                "{artifact_id}: missing field \"{field}\""
            );
        }
    }

    // Interpose: allows all statuses, requires host glibc
    let interpose = &artifacts["interpose"];
    let interpose_allowed: HashSet<String> = interpose["allowed_statuses"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    for status in [
        "Implemented",
        "RawSyscall",
        "WrapsHostLibc",
        "GlibcCallThrough",
        "Stub",
    ] {
        assert!(
            interpose_allowed.contains(status),
            "interpose: allowed_statuses missing {status}"
        );
    }
    assert!(
        interpose["host_glibc_required"].as_bool() == Some(true),
        "interpose: host_glibc_required should be true"
    );

    // Replace: only standalone statuses, no host glibc
    let replace = &artifacts["replace"];
    let replace_allowed: HashSet<String> = replace["allowed_statuses"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    assert!(
        !replace_allowed.contains("WrapsHostLibc"),
        "replace: allowed_statuses must not include WrapsHostLibc"
    );
    assert!(
        !replace_allowed.contains("GlibcCallThrough"),
        "replace: allowed_statuses must not include GlibcCallThrough"
    );
    assert!(
        !replace_allowed.contains("Stub"),
        "replace: allowed_statuses must not include Stub"
    );
    assert!(
        replace["host_glibc_required"].as_bool() == Some(false),
        "replace: host_glibc_required should be false"
    );
}

#[test]
fn assessment_matches_matrix() {
    let spec = load_spec();
    let matrix = load_matrix();

    let symbols = matrix["symbols"].as_array().unwrap();
    let assessment = &spec["current_assessment"];

    // Total
    let total = symbols.len();
    let claimed_total = assessment["total_symbols"].as_u64().unwrap() as usize;
    assert_eq!(
        claimed_total, total,
        "total_symbols: spec={claimed_total} matrix={total}"
    );

    // Status distribution
    let mut counts: HashMap<String, usize> = HashMap::new();
    for sym in symbols {
        let st = sym["status"].as_str().unwrap_or("Unknown");
        *counts.entry(st.to_string()).or_default() += 1;
    }

    let dist = assessment["symbol_distribution"].as_object().unwrap();
    for (st, claimed_val) in dist {
        let claimed = claimed_val.as_u64().unwrap() as usize;
        let actual = *counts.get(st.as_str()).unwrap_or(&0);
        assert_eq!(
            claimed, actual,
            "symbol_distribution.{st}: spec={claimed} matrix={actual}"
        );
    }

    // interpose_ready = total
    let interpose_ready = assessment["interpose_ready"].as_u64().unwrap() as usize;
    assert_eq!(
        interpose_ready, total,
        "interpose_ready should equal total_symbols"
    );

    // replace_ready = Implemented + RawSyscall
    let impl_count =
        counts.get("Implemented").unwrap_or(&0) + counts.get("RawSyscall").unwrap_or(&0);
    let replace_ready = assessment["replace_ready"].as_u64().unwrap() as usize;
    assert_eq!(
        replace_ready, impl_count,
        "replace_ready: spec={replace_ready} expected={impl_count}"
    );

    // replace_blocked = WrapsHostLibc + GlibcCallThrough + Stub
    let blocked_count = counts.get("WrapsHostLibc").unwrap_or(&0)
        + counts.get("GlibcCallThrough").unwrap_or(&0)
        + counts.get("Stub").unwrap_or(&0);
    let replace_blocked = assessment["replace_blocked"].as_u64().unwrap() as usize;
    assert_eq!(
        replace_blocked, blocked_count,
        "replace_blocked: spec={replace_blocked} expected={blocked_count}"
    );
}

#[test]
fn replace_blockers_match_matrix() {
    let spec = load_spec();
    let matrix = load_matrix();

    let symbols = matrix["symbols"].as_array().unwrap();
    let blockers = &spec["artifacts"]["replace"]["blockers"];

    // Count WrapsHostLibc + GlibcCallThrough by module from matrix
    let mut ct_by_mod: HashMap<String, usize> = HashMap::new();
    let mut stub_by_mod: HashMap<String, usize> = HashMap::new();

    for sym in symbols {
        let status = sym["status"].as_str().unwrap_or("");
        let module = sym["module"].as_str().unwrap_or("unknown");
        match status {
            "WrapsHostLibc" => {
                *ct_by_mod.entry(module.to_string()).or_default() += 1;
            }
            "GlibcCallThrough" => {
                *ct_by_mod.entry(module.to_string()).or_default() += 1;
            }
            "Stub" => {
                *stub_by_mod.entry(module.to_string()).or_default() += 1;
            }
            _ => {}
        }
    }

    // Verify WrapsHostLibc breakdown
    let wraps_claimed = blockers["WrapsHostLibc_remaining"].as_object().unwrap();
    for (m, claimed_val) in wraps_claimed {
        let claimed = claimed_val.as_u64().unwrap() as usize;
        let actual = *ct_by_mod.get(m.as_str()).unwrap_or(&0);
        assert_eq!(
            claimed, actual,
            "WrapsHostLibc_remaining.{m}: spec={claimed} matrix={actual}"
        );
    }

    // Verify CallThrough breakdown
    let ct_claimed = blockers["GlibcCallThrough_remaining"].as_object().unwrap();
    for (m, claimed_val) in ct_claimed {
        let claimed = claimed_val.as_u64().unwrap() as usize;
        let actual = *ct_by_mod.get(m.as_str()).unwrap_or(&0);
        assert_eq!(
            claimed, actual,
            "GlibcCallThrough_remaining.{m}: spec={claimed} matrix={actual}"
        );
    }

    // Verify Stub breakdown
    let stub_claimed = blockers["Stub_remaining"].as_object().unwrap();
    for (m, claimed_val) in stub_claimed {
        let claimed = claimed_val.as_u64().unwrap() as usize;
        let actual = *stub_by_mod.get(m.as_str()).unwrap_or(&0);
        assert_eq!(
            claimed, actual,
            "Stub_remaining.{m}: spec={claimed} matrix={actual}"
        );
    }

    // Total
    let total_claimed = blockers["total_symbols_to_migrate"].as_u64().unwrap() as usize;
    let total_actual: usize =
        ct_by_mod.values().sum::<usize>() + stub_by_mod.values().sum::<usize>();
    assert_eq!(
        total_claimed, total_actual,
        "total_symbols_to_migrate: spec={total_claimed} matrix={total_actual}"
    );
}

#[test]
fn feature_gates_documented() {
    let spec = load_spec();
    let gates = spec["feature_gates"].as_object().unwrap();

    // Must have at least default + standalone
    assert!(
        gates.contains_key("default"),
        "Missing feature_gates.default"
    );
    assert!(
        gates.contains_key("standalone"),
        "Missing feature_gates.standalone"
    );

    for (name, gate) in gates {
        assert!(
            gate["description"].is_string(),
            "feature_gates.{name}: missing description"
        );
    }
}

#[test]
fn support_matrix_artifact_applicability_matches_spec() {
    let spec = load_spec();
    let matrix = load_matrix();

    let app = matrix["taxonomy"]["artifact_applicability"]
        .as_object()
        .expect("support_matrix.taxonomy.artifact_applicability should exist");

    let interpose_decl: HashSet<String> = app["Interpose"]
        .as_array()
        .expect("artifact_applicability.Interpose should be an array")
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    let replace_decl: HashSet<String> = app["Replace"]
        .as_array()
        .expect("artifact_applicability.Replace should be an array")
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let interpose_expected: HashSet<String> = spec["artifacts"]["interpose"]["allowed_statuses"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    let replace_expected: HashSet<String> = spec["artifacts"]["replace"]["allowed_statuses"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    assert_eq!(
        interpose_decl, interpose_expected,
        "support_matrix Interpose applicability must match packaging spec"
    );
    assert_eq!(
        replace_decl, replace_expected,
        "support_matrix Replace applicability must match packaging spec"
    );

    let rule = app["rule"].as_str().unwrap_or("");
    assert!(
        !rule.trim().is_empty(),
        "support_matrix artifact applicability rule should be non-empty"
    );
}

#[test]
fn matrix_applicability_rule_correct() {
    let spec = load_spec();
    let matrix = load_matrix();

    let symbols = matrix["symbols"].as_array().unwrap();
    let interpose_allowed: HashSet<String> = spec["artifacts"]["interpose"]["allowed_statuses"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    let replace_allowed: HashSet<String> = spec["artifacts"]["replace"]["allowed_statuses"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    // Every symbol should be applicable to interpose
    for sym in symbols {
        let status = sym["status"].as_str().unwrap_or("Unknown");
        let name = sym["symbol"].as_str().unwrap_or("?");
        assert!(
            interpose_allowed.contains(status),
            "{name}: status {status} not in interpose allowed_statuses"
        );
    }

    // Only Implemented+RawSyscall should be applicable to replace
    for sym in symbols {
        let status = sym["status"].as_str().unwrap_or("Unknown");
        let name = sym["symbol"].as_str().unwrap_or("?");
        if replace_allowed.contains(status) {
            assert!(
                status == "Implemented" || status == "RawSyscall",
                "{name}: replace-applicable status should be Implemented or RawSyscall, got {status}"
            );
        }
    }
}

#[test]
fn readme_aligns_with_packaging_spec() {
    let spec = load_spec();
    let readme = load_readme();

    let interpose = &spec["artifacts"]["interpose"];
    let replace = &spec["artifacts"]["replace"];

    let required_literals = [
        interpose["build_command"].as_str().unwrap(),
        interpose["output_path"].as_str().unwrap(),
        interpose["artifact_name"].as_str().unwrap(),
        replace["artifact_name"].as_str().unwrap(),
    ];

    for lit in required_literals {
        assert!(
            readme.contains(lit),
            "README should contain packaging literal: {lit}"
        );
    }

    let interpose_deploy = interpose["deployment"].as_str().unwrap();
    if let Some((preload_prefix, _)) = interpose_deploy.split_once(' ') {
        assert!(
            readme.contains(preload_prefix),
            "README missing deployment prefix: {preload_prefix}"
        );
    }

    let hardened_deploy = interpose["deployment_modes"]["hardened"].as_str().unwrap();
    if let Some((hardened_prefix, _)) = hardened_deploy.split_once(' ') {
        assert!(
            readme.contains(hardened_prefix),
            "README missing hardened prefix: {hardened_prefix}"
        );
    }

    for rule_fragment in [
        "`Implemented` + `RawSyscall` symbols apply to both artifacts.",
        "`WrapsHostLibc` + `GlibcCallThrough` + `Stub` symbols apply to `Interpose` only.",
    ] {
        assert!(
            readme.contains(rule_fragment),
            "README missing applicability fragment: {rule_fragment}"
        );
    }
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_packaging.sh");
    assert!(script.exists(), "scripts/check_packaging.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_packaging.sh must be executable"
        );
    }
}
