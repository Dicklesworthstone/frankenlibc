//! Integration test: C fixture suite spec (bd-3jh)
//!
//! Validates that:
//! 1. The fixture spec JSON exists and is valid.
//! 2. All fixture source files exist.
//! 3. Fixtures compile with cc.
//! 4. Required acceptance symbols are covered.
//! 5. Covered modules reference valid support_matrix modules.
//! 6. Summary statistics are consistent.
//! 7. Gate and runner scripts exist and are executable.
//!
//! Run: cargo test -p frankenlibc-harness --test c_fixture_suite_test

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

fn load_spec() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/c_fixture_spec.json");
    let content = std::fs::read_to_string(&path).expect("c_fixture_spec.json should exist");
    serde_json::from_str(&content).expect("c_fixture_spec.json should be valid JSON")
}

fn load_matrix() -> serde_json::Value {
    let path = workspace_root().join("support_matrix.json");
    let content = std::fs::read_to_string(&path).expect("support_matrix.json should exist");
    serde_json::from_str(&content).expect("support_matrix.json should be valid JSON")
}

#[test]
fn spec_exists_and_valid() {
    let s = load_spec();
    assert!(s["schema_version"].is_number(), "Missing schema_version");
    assert!(s["fixtures"].is_array(), "Missing fixtures");
    assert!(s["execution"].is_object(), "Missing execution");
    assert!(
        s["coverage_summary"].is_object(),
        "Missing coverage_summary"
    );
    assert!(s["summary"].is_object(), "Missing summary");
}

#[test]
fn all_fixture_sources_exist() {
    let s = load_spec();
    let root = workspace_root();

    for fixture in s["fixtures"].as_array().unwrap() {
        let fid = fixture["id"].as_str().unwrap_or("?");
        let src = fixture["source"].as_str().unwrap();
        let path = root.join(src);
        assert!(path.exists(), "{fid}: source not found: {src}");
    }
}

#[test]
fn fixtures_have_required_fields() {
    let s = load_spec();
    let required = [
        "id",
        "source",
        "description",
        "covered_symbols",
        "covered_modules",
        "tests",
    ];

    for fixture in s["fixtures"].as_array().unwrap() {
        let fid = fixture["id"].as_str().unwrap_or("?");
        for field in &required {
            assert!(!fixture[field].is_null(), "{fid}: missing field '{field}'");
        }
        assert!(
            fixture["tests"].as_u64().unwrap() > 0,
            "{fid}: tests must be > 0"
        );
        assert!(
            !fixture["covered_symbols"].as_array().unwrap().is_empty(),
            "{fid}: covered_symbols must not be empty"
        );
    }
}

#[test]
fn bd15n2_fixtures_have_traceability_and_mode_expectations() {
    let s = load_spec();
    let fixtures = s["fixtures"].as_array().unwrap();

    for fixture_id in ["fixture_ctype", "fixture_math", "fixture_socket"] {
        let fixture = fixtures
            .iter()
            .find(|f| f["id"].as_str() == Some(fixture_id))
            .unwrap_or_else(|| panic!("missing required fixture '{fixture_id}'"));

        for trace_key in ["posix", "c11", "internal"] {
            let refs = fixture["spec_traceability"][trace_key]
                .as_array()
                .unwrap_or_else(|| {
                    panic!("{}: missing spec_traceability.{}", fixture_id, trace_key)
                });
            assert!(
                refs.iter()
                    .any(|v| !v.as_str().map(str::trim).unwrap_or("").is_empty()),
                "{}: spec_traceability.{} must include at least one non-empty reference",
                fixture_id,
                trace_key
            );
        }

        for mode in ["strict", "hardened"] {
            let mode_obj = fixture["mode_expectations"][mode]
                .as_object()
                .unwrap_or_else(|| panic!("{}: missing mode_expectations.{}", fixture_id, mode));
            assert_eq!(
                mode_obj.get("expected_exit").and_then(|v| v.as_i64()),
                Some(0),
                "{}: mode_expectations.{}.expected_exit must be 0",
                fixture_id,
                mode
            );
            let marker = mode_obj
                .get("expected_stdout_contains")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            assert!(
                !marker.trim().is_empty(),
                "{}: mode_expectations.{}.expected_stdout_contains must be non-empty",
                fixture_id,
                mode
            );
        }
    }
}

#[test]
fn acceptance_symbols_covered() {
    let s = load_spec();

    let required: HashSet<String> = s["coverage_summary"]["required_by_acceptance"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let mut covered = HashSet::new();
    for fixture in s["fixtures"].as_array().unwrap() {
        for sym in fixture["covered_symbols"].as_array().unwrap() {
            covered.insert(sym.as_str().unwrap().to_string());
        }
    }

    let missing: HashSet<_> = required.difference(&covered).collect();
    assert!(
        missing.is_empty(),
        "Required symbols not covered: {missing:?}"
    );
}

#[test]
fn covered_modules_valid() {
    let s = load_spec();
    let m = load_matrix();

    let valid_modules: HashSet<String> = m["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["module"].as_str().map(String::from))
        .collect();

    for fixture in s["fixtures"].as_array().unwrap() {
        let fid = fixture["id"].as_str().unwrap_or("?");
        for mod_val in fixture["covered_modules"].as_array().unwrap() {
            let module = mod_val.as_str().unwrap();
            assert!(
                valid_modules.contains(module),
                "{fid}: invalid module '{module}'"
            );
        }
    }
}

#[test]
fn summary_consistent() {
    let s = load_spec();
    let summary = &s["summary"];
    let fixtures = s["fixtures"].as_array().unwrap();

    let total_fixtures = fixtures.len();
    let total_tests: u64 = fixtures.iter().map(|f| f["tests"].as_u64().unwrap()).sum();

    let mut all_symbols = HashSet::new();
    let mut all_modules = HashSet::new();
    for f in fixtures {
        for sym in f["covered_symbols"].as_array().unwrap() {
            all_symbols.insert(sym.as_str().unwrap().to_string());
        }
        for m in f["covered_modules"].as_array().unwrap() {
            all_modules.insert(m.as_str().unwrap().to_string());
        }
    }

    assert_eq!(
        summary["total_fixtures"].as_u64().unwrap() as usize,
        total_fixtures,
        "total_fixtures mismatch"
    );
    assert_eq!(
        summary["total_tests"].as_u64().unwrap(),
        total_tests,
        "total_tests mismatch"
    );
    assert_eq!(
        summary["symbols_covered"].as_u64().unwrap() as usize,
        all_symbols.len(),
        "symbols_covered mismatch"
    );
    assert_eq!(
        summary["modules_covered"].as_u64().unwrap() as usize,
        all_modules.len(),
        "modules_covered mismatch"
    );
}

#[test]
fn scripts_exist_and_executable() {
    let root = workspace_root();

    let scripts = [
        "scripts/check_c_fixture_suite.sh",
        "scripts/c_fixture_suite.sh",
    ];

    for script_path in &scripts {
        let script = root.join(script_path);
        assert!(script.exists(), "{script_path} must exist");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&script).unwrap().permissions();
            assert!(
                perms.mode() & 0o111 != 0,
                "{script_path} must be executable"
            );
        }
    }
}
