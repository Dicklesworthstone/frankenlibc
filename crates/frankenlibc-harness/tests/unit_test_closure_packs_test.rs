// unit_test_closure_packs_test.rs — bd-w2c3.9.1
// Validates unit test closure packs for weak/complex families.
// Ensures required families have fixtures with strict/hardened cases.

use std::collections::{BTreeSet, HashSet};
use std::path::Path;

fn fixture_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/conformance/fixtures")
}

fn load_fixture(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
}

fn startup_report_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target/conformance/bd-320s_startup_fixture_report.v1.json")
}

#[test]
fn all_required_families_have_fixtures() {
    let dir = fixture_dir();
    let required_families: Vec<&str> = vec![
        "startup_ops",
        "loader_edges",
        "resolv/dns",
        "locale_ops",
        "iconv/phase1",
        "signal_ops",
        "setjmp_ops",
        "sysv_ipc_ops",
        "backtrace_ops",
        "session_ops",
        "spawn_exec_ops",
        "regex_glob_ops",
    ];

    let mut found_families = HashSet::new();
    for entry in std::fs::read_dir(&dir).expect("can't read fixture dir") {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            let data = load_fixture(&path);
            let family = data["family"]
                .as_str()
                .unwrap_or_else(|| path.file_stem().unwrap().to_str().unwrap());
            found_families.insert(family.to_string());
        }
    }

    let mut missing = Vec::new();
    for fam in &required_families {
        if !found_families.contains(*fam) {
            missing.push(*fam);
        }
    }

    assert!(
        missing.is_empty(),
        "Missing required family fixtures: {:?}\nFound families: {:?}",
        missing,
        found_families
    );
}

#[test]
fn new_closure_packs_have_cases() {
    let dir = fixture_dir();
    let new_packs = [
        "setjmp_ops.json",
        "sysv_ipc_ops.json",
        "backtrace_ops.json",
        "session_ops.json",
        "loader_edges.json",
        "spawn_exec_ops.json",
        "regex_glob_ops.json",
    ];

    for name in &new_packs {
        let path = dir.join(name);
        assert!(path.exists(), "Pack fixture {} not found", name);

        let data = load_fixture(&path);
        let cases = data["cases"].as_array().unwrap_or_else(|| {
            panic!("{} missing 'cases' array", name);
        });
        assert!(!cases.is_empty(), "{} has empty cases array", name);

        // Each case must have required fields
        for (i, case) in cases.iter().enumerate() {
            assert!(
                case["name"].as_str().is_some(),
                "{} case {} missing 'name'",
                name,
                i
            );
            assert!(
                case["function"].as_str().is_some(),
                "{} case {} missing 'function'",
                name,
                i
            );
            assert!(
                case["mode"].as_str().is_some(),
                "{} case {} missing 'mode'",
                name,
                i
            );
        }
    }
}

#[test]
fn closure_packs_have_strict_and_hardened_cases() {
    let dir = fixture_dir();
    let packs_requiring_both_modes = [
        "setjmp_ops.json",
        "sysv_ipc_ops.json",
        "backtrace_ops.json",
        "session_ops.json",
        "loader_edges.json",
        "spawn_exec_ops.json",
        "regex_glob_ops.json",
    ];

    for name in &packs_requiring_both_modes {
        let path = dir.join(name);
        let data = load_fixture(&path);
        let cases = data["cases"].as_array().unwrap();

        let strict_count = cases
            .iter()
            .filter(|c| c["mode"].as_str() == Some("strict"))
            .count();
        let hardened_count = cases
            .iter()
            .filter(|c| c["mode"].as_str() == Some("hardened"))
            .count();

        assert!(strict_count > 0, "{} has no strict-mode cases", name);
        assert!(hardened_count > 0, "{} has no hardened-mode cases", name);
    }
}

#[test]
fn startup_fixture_expansion_covers_invariant_matrix() {
    let fixture_path = fixture_dir().join("startup_ops.json");
    let data = load_fixture(&fixture_path);
    let cases = data["cases"]
        .as_array()
        .expect("startup_ops.json must contain a cases array");

    let case_names: HashSet<&str> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    let required_names = [
        "startup_phase0_rejects_unterminated_argv_strict",
        "startup_phase0_rejects_unterminated_argv_hardened",
        "startup_phase0_rejects_unterminated_envp_strict",
        "startup_phase0_rejects_unterminated_envp_hardened",
        "startup_phase0_rejects_unterminated_auxv_strict",
        "startup_phase0_rejects_unterminated_auxv_hardened",
        "startup_snapshot_secure_mode_nonsecure_strict",
        "startup_snapshot_secure_mode_secure_hardened",
        "libc_start_main_default_owned_no_host_delegate_strict",
        "libc_start_main_phase0_disabled_fallback_host_strict",
        "libc_start_main_phase0_unsafe_envp_fallback_host_strict",
        "libc_start_main_phase0_missing_main_no_fallback_strict",
    ];

    let missing: Vec<&str> = required_names
        .iter()
        .copied()
        .filter(|name| !case_names.contains(name))
        .collect();
    assert!(
        missing.is_empty(),
        "startup fixture expansion missing required cases: {missing:?}"
    );

    let strict_count = cases
        .iter()
        .filter(|c| c["mode"].as_str() == Some("strict"))
        .count();
    let hardened_count = cases
        .iter()
        .filter(|c| c["mode"].as_str() == Some("hardened"))
        .count();
    assert!(
        strict_count >= 5 && hardened_count >= 5,
        "startup fixture coverage should include rich strict+hardened sets; strict={strict_count}, hardened={hardened_count}"
    );

    let mut invariant_ids = BTreeSet::new();
    for case in &required_names {
        if case.contains("argv") {
            invariant_ids.insert("argv");
        }
        if case.contains("envp") {
            invariant_ids.insert("envp");
        }
        if case.contains("auxv") {
            invariant_ids.insert("auxv");
        }
        if case.contains("secure_mode") {
            invariant_ids.insert("secure_mode");
        }
        if case.contains("fallback") {
            invariant_ids.insert("host_fallback_boundary");
        }
    }

    let report = serde_json::json!({
        "schema_version": "v1",
        "bead_id": "bd-320s",
        "fixture_file": "tests/conformance/fixtures/startup_ops.json",
        "trace_id": "bd-320s::startup-fixture-report::001",
        "summary": {
            "strict_cases": strict_count,
            "hardened_cases": hardened_count,
            "required_case_count": required_names.len(),
            "missing_case_count": missing.len()
        },
        "invariant_ids": invariant_ids,
        "artifact_refs": [
            "tests/conformance/fixtures/startup_ops.json",
            "crates/frankenlibc-harness/tests/unit_test_closure_packs_test.rs"
        ]
    });

    let report_path = startup_report_path();
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)
            .expect("startup fixture report directory must be creatable");
    }
    std::fs::write(
        &report_path,
        serde_json::to_string_pretty(&report).expect("report serialization should succeed"),
    )
    .expect("startup fixture report should be written");
    assert!(
        report_path.exists(),
        "startup fixture report artifact was not created"
    );
}

#[test]
fn total_fixture_count_meets_minimum() {
    let dir = fixture_dir();
    let mut total_files = 0;
    let mut total_cases = 0;

    for entry in std::fs::read_dir(&dir).expect("can't read fixture dir") {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            total_files += 1;
            let data = load_fixture(&path);
            if let Some(cases) = data["cases"].as_array() {
                total_cases += cases.len();
            }
        }
    }

    // Minimum thresholds from bd-w2c3.9.1
    assert!(
        total_files >= 45,
        "Expected at least 45 fixture files, got {total_files}"
    );
    assert!(
        total_cases >= 400,
        "Expected at least 400 total cases, got {total_cases}"
    );
}
