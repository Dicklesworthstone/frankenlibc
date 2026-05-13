//! Deterministic ISO C99 wide scanf alias fixture coverage for isoc_abi.
//!
//! The executable alias behavior lives in
//! `crates/frankenlibc-abi/tests/isoc_abi_test.rs`, with base wide-scanf
//! behavior in `crates/frankenlibc-abi/tests/wchar_abi_test.rs`. This
//! harness-level test binds those behaviors to the exported-symbol fixture
//! matrix so the critical `isoc_abi` coverage gap cannot silently regress.

use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ISOC_WIDE_SCANF_SYMBOLS: [&str; 5] = [
    "__isoc99_fwscanf",
    "__isoc99_swscanf",
    "__isoc99_vfwscanf",
    "__isoc99_vswscanf",
    "__isoc99_vwscanf",
];

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
    captured_at: String,
    description: String,
    spec_reference: String,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FixtureCase {
    name: String,
    function: String,
    spec_section: String,
    inputs: serde_json::Value,
    expected_output: ExpectedOutput,
    expected_errno: i32,
    mode: String,
    note: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ExpectedOutput {
    status: String,
    #[serde(default)]
    return_value: serde_json::Value,
    #[serde(default)]
    assignments: serde_json::Value,
    failure_signature: String,
}

fn load_fixture() -> FixtureFile {
    let path = repo_root().join("tests/conformance/fixtures/isoc_wide_scanf_ops.json");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|err| panic!("invalid JSON in {}: {err}", path.display()))
}

fn load_json(path: &str) -> serde_json::Value {
    let path = repo_root().join(path);
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|err| panic!("invalid JSON in {}: {err}", path.display()))
}

#[test]
fn isoc_wide_scanf_fixture_exists_and_names_scope() {
    let fixture_path = repo_root().join("tests/conformance/fixtures/isoc_wide_scanf_ops.json");
    assert!(
        fixture_path.exists(),
        "isoc_wide_scanf_ops fixture must exist"
    );

    let fixture = load_fixture();
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "isoc_wide_scanf_ops");
    assert!(
        fixture.description.contains("ISO C99")
            && fixture.description.contains("__isoc99")
            && fixture.description.contains("wide scanf"),
        "fixture description must bind ISO C99 wide scanf alias behavior"
    );
    assert!(
        fixture.spec_reference.contains("ISO C99")
            && fixture.spec_reference.contains("POSIX")
            && fixture.spec_reference.contains("glibc"),
        "fixture must cite ISO C99, POSIX, and glibc compatibility"
    );
}

#[test]
fn isoc_wide_scanf_fixture_covers_every_uncovered_isoc_symbol() {
    let fixture = load_fixture();
    let declared: BTreeSet<&str> = fixture
        .cases
        .iter()
        .map(|case| case.function.as_str())
        .collect();
    let expected: BTreeSet<&str> = ISOC_WIDE_SCANF_SYMBOLS.into_iter().collect();
    assert_eq!(
        declared, expected,
        "isoc_wide_scanf_ops must cover exactly the remaining isoc_abi wide scanf symbols"
    );
    assert_eq!(
        fixture.cases.len(),
        ISOC_WIDE_SCANF_SYMBOLS.len(),
        "isoc_wide_scanf_ops should bind one deterministic case per remaining symbol"
    );
}

#[test]
fn isoc_wide_scanf_cases_are_deterministic_and_mode_paired() {
    let fixture = load_fixture();
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "case name must not be empty");
        assert!(
            ISOC_WIDE_SCANF_SYMBOLS.contains(&case.function.as_str()),
            "unexpected isoc wide scanf function {}",
            case.function
        );
        assert!(
            case.mode == "both",
            "isoc wide scanf fixtures should be strict/hardened paired"
        );
        assert_eq!(
            case.expected_output.status, "pass",
            "case {} must bind a successful compatibility result",
            case.name
        );
        assert!(
            !case.expected_output.failure_signature.is_empty(),
            "case {} must bind a failure-signature classifier",
            case.name
        );
        assert_eq!(
            case.expected_errno, 0,
            "case {} should not depend on errno mutation",
            case.name
        );
        assert!(
            case.inputs.get("wide_format").is_some(),
            "case {} must bind a wide format",
            case.name
        );
        assert!(
            case.spec_section.contains("ISO C99"),
            "case {} must cite the ISO C99 alias entrypoint",
            case.name
        );
        assert!(
            case.note.contains("isoc_abi_test::") || case.note.contains("wchar_abi_test::"),
            "case {} must cite executable ABI or base wide-scanf coverage",
            case.name
        );
    }
}

#[test]
fn isoc_wide_scanf_fixture_is_backed_by_existing_tests() {
    let root = repo_root();
    let isoc_test =
        std::fs::read_to_string(root.join("crates/frankenlibc-abi/tests/isoc_abi_test.rs"))
            .expect("read isoc_abi unit test");
    let needle = "isoc99_swscanf_parses_wide_integer";
    assert!(
        isoc_test.contains(needle),
        "missing isoc test anchor {needle}"
    );

    let isoc_source = std::fs::read_to_string(root.join("crates/frankenlibc-abi/src/isoc_abi.rs"))
        .expect("read isoc_abi source");
    for needle in [
        "fn __isoc99_fwscanf",
        "fn __isoc99_vwscanf",
        "fn __isoc99_vfwscanf",
        "fn __isoc99_vswscanf",
        "unsafe { vfwscanf(stream, format, ap) }",
        "unsafe { vwscanf(format, ap) }",
        "unsafe { vswscanf(s, format, ap) }",
    ] {
        assert!(
            isoc_source.contains(needle),
            "missing isoc source forwarding anchor {needle}"
        );
    }

    let wchar_test =
        std::fs::read_to_string(root.join("crates/frankenlibc-abi/tests/wchar_abi_test.rs"))
            .expect("read wchar_abi unit test");
    for needle in [
        "swscanf_parses_integer",
        "wide_vscanf_null_va_list_fails_closed",
    ] {
        assert!(
            wchar_test.contains(needle),
            "missing wchar test anchor {needle}"
        );
    }
}

#[test]
fn symbol_fixture_coverage_counts_isoc_wide_scanf_fixture() {
    let matrix = load_json("tests/conformance/symbol_fixture_coverage.v1.json");
    let symbols = matrix["symbols"]
        .as_array()
        .expect("symbol_fixture_coverage.symbols must be an array");

    for symbol in ISOC_WIDE_SCANF_SYMBOLS {
        let row = symbols
            .iter()
            .find(|row| row["module"] == "isoc_abi" && row["symbol"] == symbol)
            .unwrap_or_else(|| panic!("missing isoc_abi symbol row for {symbol}"));
        assert!(
            row["fixture_case_count"].as_u64().unwrap_or(0) >= 1,
            "symbol_fixture_coverage must count isoc_wide_scanf_ops fixture case for {symbol}"
        );
        let fixture_files = row["fixture_files"]
            .as_array()
            .unwrap_or_else(|| panic!("fixture_files missing for {symbol}"));
        assert!(
            fixture_files
                .iter()
                .any(|file| file == "isoc_wide_scanf_ops.json"),
            "symbol_fixture_coverage must cite isoc_wide_scanf_ops.json for {symbol}"
        );
    }

    let uncovered = matrix["uncovered_target_families"]
        .as_array()
        .expect("uncovered_target_families must be an array");
    assert!(
        uncovered
            .iter()
            .all(|family| family["module"].as_str() != Some("isoc_abi")),
        "isoc_abi should not remain a critical uncovered target family after isoc_wide_scanf_ops fixture"
    );
}
