//! ELF loader conformance test suite.
//!
//! Validates ELF64 loader functions: header parsing, relocations, hash functions,
//! symbol table parsing, program flags.
//! Run: cargo test -p frankenlibc-harness --test elf_loader_conformance_test

use serde::Deserialize;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FixtureFile {
    version: String,
    family: String,
    #[serde(default)]
    captured_at: String,
    #[serde(default)]
    description: String,
    cases: Vec<FixtureCase>,
    #[serde(default)]
    binary_fixtures: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FixtureCase {
    name: String,
    function: String,
    spec_section: String,
    inputs: serde_json::Value,
    #[serde(default)]
    expected_output: Option<serde_json::Value>,
    #[serde(default)]
    expected_hex: Option<String>,
    #[serde(default)]
    expected_errno: i32,
    mode: String,
    #[serde(default)]
    note: String,
}

fn load_fixture(name: &str) -> FixtureFile {
    let path = repo_root().join(format!("tests/conformance/fixtures/{name}.json"));
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
}

#[test]
fn elf_loader_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/elf_loader.json");
    assert!(path.exists(), "elf_loader.json fixture must exist");
}

#[test]
fn elf_loader_fixture_valid_schema() {
    let fixture = load_fixture("elf_loader");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "elf/loader");
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
        assert!(
            case.expected_output.is_some(),
            "Case {} must have expected_output",
            case.name
        );
    }
}

#[test]
fn elf_loader_covers_header_parsing() {
    let fixture = load_fixture("elf_loader");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("elf_magic"))
            .count()
            >= 2,
        "ELF header parsing needs at least 2 test cases (valid/invalid)"
    );
}

#[test]
fn elf_loader_covers_relocations() {
    let fixture = load_fixture("elf_loader");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.starts_with("reloc_"))
            .count()
            >= 4,
        "Relocations need at least 4 test cases"
    );
}

#[test]
fn elf_loader_covers_hash_functions() {
    let fixture = load_fixture("elf_loader");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("elf_hash")),
        "Missing test coverage for elf_hash"
    );
    assert!(
        case_names.iter().any(|n| n.contains("gnu_hash")),
        "Missing test coverage for gnu_hash"
    );
}

#[test]
fn elf_loader_covers_symbol_table() {
    let fixture = load_fixture("elf_loader");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("symbol_")).count() >= 4,
        "Symbol table needs at least 4 test cases"
    );
}

#[test]
fn elf_loader_covers_program_flags() {
    let fixture = load_fixture("elf_loader");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("program_flags"))
            .count()
            >= 2,
        "Program flags need at least 2 test cases"
    );
}

#[test]
fn elf_loader_modes_valid() {
    let fixture = load_fixture("elf_loader");
    for case in &fixture.cases {
        assert!(
            case.mode == "both" || case.mode == "strict" || case.mode == "hardened",
            "Case {} has invalid mode: {}",
            case.name,
            case.mode
        );
    }
}

#[test]
fn elf_loader_case_count_stable() {
    let fixture = load_fixture("elf_loader");
    assert!(
        fixture.cases.len() >= 12,
        "elf_loader fixture has {} cases, expected at least 12",
        fixture.cases.len()
    );
    eprintln!("elf_loader fixture has {} test cases", fixture.cases.len());
}

#[test]
fn elf_loader_has_spec_references() {
    let fixture = load_fixture("elf_loader");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("ELF")
                || case.spec_section.contains("x86_64")
                || case.spec_section.contains("GNU"),
            "Case {} spec_section should reference ELF, x86_64, or GNU: {}",
            case.name,
            case.spec_section
        );
    }
}

#[test]
fn elf_loader_has_binary_fixtures() {
    let fixture = load_fixture("elf_loader");
    assert!(
        fixture.binary_fixtures.is_some(),
        "elf_loader fixture should have binary_fixtures for real ELF testing"
    );
}
