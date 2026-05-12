//! Integration test: Stub fallback contracts (bd-2y6)
//!
//! Validates that:
//! 1. stub_contracts.json exists and is valid JSON.
//! 2. Every contract has the required schema fields.
//! 3. All Stub symbols from support_matrix.json are covered.
//! 4. No contract declares panics or todo!().
//! 5. Every contracted symbol exists in the ABI source.
//! 6. Summary statistics are consistent with contract entries.
//!
//! Run: cargo test -p frankenlibc-harness --test stub_contract_test

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

fn load_contracts() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/stub_contracts.json");
    let content = std::fs::read_to_string(&path).expect("stub_contracts.json should exist");
    serde_json::from_str(&content).expect("stub_contracts.json should be valid JSON")
}

fn load_matrix() -> serde_json::Value {
    let path = workspace_root().join("support_matrix.json");
    let content = std::fs::read_to_string(&path).expect("support_matrix.json should exist");
    serde_json::from_str(&content).expect("support_matrix.json should be valid JSON")
}

fn stub_symbols_from_matrix(matrix: &serde_json::Value) -> HashSet<String> {
    matrix["symbols"]
        .as_array()
        .expect("support_matrix.symbols should be an array")
        .iter()
        .filter(|entry| entry["status"].as_str() == Some("Stub"))
        .filter_map(|entry| entry["symbol"].as_str().map(String::from))
        .collect()
}

#[test]
fn contracts_file_exists_and_valid() {
    let contracts = load_contracts();
    assert!(
        contracts["contract_version"].is_number(),
        "Missing contract_version"
    );
    assert!(contracts["contracts"].is_array(), "Missing contracts array");
    assert!(contracts["summary"].is_object(), "Missing summary object");
}

#[test]
fn contract_schema_complete() {
    let contracts = load_contracts();
    let entries = contracts["contracts"].as_array().unwrap();
    assert!(!entries.is_empty(), "Contracts array should not be empty");

    let required_fields = [
        "symbol",
        "matrix_status",
        "actual_status",
        "module",
        "behavior",
        "rationale",
    ];
    let behavior_fields = ["description", "panics", "calls_todo", "deterministic"];

    for entry in entries {
        let sym = entry["symbol"].as_str().unwrap_or("<unknown>");

        for field in &required_fields {
            assert!(
                !entry[field].is_null(),
                "{sym}: missing required field '{field}'"
            );
        }

        let behavior = &entry["behavior"];
        for field in &behavior_fields {
            assert!(
                !behavior[field].is_null(),
                "{sym}: behavior missing '{field}'"
            );
        }
    }
}

#[test]
fn all_stub_symbols_covered() {
    let contracts = load_contracts();
    let matrix = load_matrix();

    let stub_symbols = stub_symbols_from_matrix(&matrix);

    // Collect contracted symbols
    let contracted: HashSet<String> = contracts["contracts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["symbol"].as_str().map(String::from))
        .collect();

    let missing: Vec<_> = stub_symbols.difference(&contracted).collect();
    assert!(
        missing.is_empty(),
        "Stub symbols missing from contracts: {:?}",
        missing
    );
}

#[test]
fn no_panics_or_todo() {
    let contracts = load_contracts();
    let entries = contracts["contracts"].as_array().unwrap();

    for entry in entries {
        let sym = entry["symbol"].as_str().unwrap_or("<unknown>");
        let behavior = &entry["behavior"];

        assert_eq!(
            behavior["panics"].as_bool(),
            Some(false),
            "{sym}: must not declare panics=true"
        );
        assert_eq!(
            behavior["calls_todo"].as_bool(),
            Some(false),
            "{sym}: must not declare calls_todo=true"
        );
        assert_eq!(
            behavior["deterministic"].as_bool(),
            Some(true),
            "{sym}: must be deterministic"
        );
    }
}

#[test]
fn contracted_symbols_exist_in_abi_source() {
    let contracts = load_contracts();
    let entries = contracts["contracts"].as_array().unwrap();
    let abi_src = workspace_root().join("crates/frankenlibc-abi/src");

    for entry in entries {
        let sym = entry["symbol"].as_str().unwrap();
        let module = entry["module"].as_str().unwrap();
        let src_file = abi_src.join(format!("{module}.rs"));

        assert!(
            src_file.exists(),
            "{sym}: ABI module file {module}.rs not found"
        );

        let content = std::fs::read_to_string(&src_file).unwrap();
        let pattern = format!("fn {sym}(");
        assert!(
            content.contains(&pattern),
            "{sym}: extern \"C\" fn not found in {module}.rs"
        );
    }
}

#[test]
fn summary_stats_consistent() {
    let contracts = load_contracts();
    let entries = contracts["contracts"].as_array().unwrap();
    let summary = &contracts["summary"];

    let total = summary["total_stub_symbols"].as_u64().unwrap() as usize;
    assert_eq!(total, entries.len(), "total_stub_symbols mismatch");

    let implemented = summary["actually_implemented"].as_u64().unwrap() as usize;
    let actual_implemented = entries
        .iter()
        .filter(|e| e["actual_status"].as_str() == Some("Implemented"))
        .count();
    assert_eq!(
        implemented, actual_implemented,
        "actually_implemented mismatch"
    );

    let panics_count = summary["panics_on_call"].as_u64().unwrap() as usize;
    let actual_panics = entries
        .iter()
        .filter(|e| e["behavior"]["panics"].as_bool() == Some(true))
        .count();
    assert_eq!(panics_count, actual_panics, "panics_on_call mismatch");

    let todo_count = summary["calls_todo"].as_u64().unwrap() as usize;
    let actual_todo = entries
        .iter()
        .filter(|e| e["behavior"]["calls_todo"].as_bool() == Some(true))
        .count();
    assert_eq!(todo_count, actual_todo, "calls_todo mismatch");

    assert_eq!(
        summary["all_deterministic"].as_bool(),
        Some(true),
        "all_deterministic should be true"
    );
}

#[test]
fn matrix_corrections_documented() {
    let contracts = load_contracts();
    let summary = &contracts["summary"];

    let corrections = summary["matrix_corrections_needed"]
        .as_array()
        .expect("matrix_corrections_needed should be an array");

    // Every actually-implemented stub should have a correction entry
    let entries = contracts["contracts"].as_array().unwrap();
    let needs_correction: Vec<&str> = entries
        .iter()
        .filter(|e| e["matrix_status"].as_str() != e["actual_status"].as_str())
        .filter_map(|e| e["symbol"].as_str())
        .collect();

    let corrected: HashSet<&str> = corrections
        .iter()
        .filter_map(|c| c["symbol"].as_str())
        .collect();

    for sym in &needs_correction {
        assert!(
            corrected.contains(sym),
            "{sym}: needs correction but not in matrix_corrections_needed"
        );
    }

    // Each correction should have from/to/evidence
    for c in corrections {
        let sym = c["symbol"].as_str().unwrap_or("<unknown>");
        assert!(c["from"].is_string(), "{sym}: correction missing 'from'");
        assert!(c["to"].is_string(), "{sym}: correction missing 'to'");
        assert!(
            c["evidence"].is_string(),
            "{sym}: correction missing 'evidence'"
        );
    }
}
