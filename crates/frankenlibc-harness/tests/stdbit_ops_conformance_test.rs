//! C23 stdbit.h operation conformance test suite.
//!
//! Validates executable fixture coverage for representative unsigned-int bit operations.
//! Run: cargo test -p frankenlibc-harness --test stdbit_ops_conformance_test

use frankenlibc_fixture_exec::execute_fixture_case;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
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
    #[serde(default)]
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
    #[serde(default)]
    expected_output: Option<String>,
    #[serde(default)]
    expected_errno: i32,
    mode: String,
    #[serde(default)]
    note: String,
}

fn load_fixture() -> Result<FixtureFile, String> {
    let path = repo_root().join("tests/conformance/fixtures/stdbit_ops.json");
    let content = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|err| format!("invalid JSON in {}: {err}", path.display()))
}

#[test]
fn stdbit_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/stdbit_ops.json");
    assert!(path.exists(), "stdbit_ops.json fixture must exist");
}

#[test]
fn stdbit_ops_fixture_valid_schema() -> Result<(), String> {
    let fixture = load_fixture()?;

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "stdbit/ops");
    assert!(
        !fixture.description.is_empty(),
        "fixture should describe its scope"
    );
    assert!(
        fixture.spec_reference.contains("C23"),
        "fixture should cite the C23 stdbit contract"
    );
    assert!(!fixture.cases.is_empty(), "fixture must have test cases");

    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "case name must not be empty");
        assert!(!case.function.is_empty(), "function must not be empty");
        assert!(
            case.function.starts_with("stdc_"),
            "case {} should target a stdbit function",
            case.name
        );
        assert!(
            case.spec_section.contains("C23"),
            "case {} spec_section should reference C23: {}",
            case.name,
            case.spec_section
        );
        assert!(
            case.expected_output.is_some(),
            "case {} must have expected_output",
            case.name
        );
        assert_eq!(case.expected_errno, 0, "stdbit cases do not set errno");
        assert_eq!(case.mode, "both", "stdbit cases should run in both modes");
    }

    Ok(())
}

#[test]
fn stdbit_ops_covers_unsigned_int_operations() -> Result<(), String> {
    let fixture = load_fixture()?;
    let functions: BTreeSet<&str> = fixture
        .cases
        .iter()
        .map(|case| case.function.as_str())
        .collect();
    let required = [
        "stdc_leading_zeros_ui",
        "stdc_leading_ones_ui",
        "stdc_trailing_zeros_ui",
        "stdc_trailing_ones_ui",
        "stdc_first_leading_zero_ui",
        "stdc_first_leading_one_ui",
        "stdc_first_trailing_zero_ui",
        "stdc_first_trailing_one_ui",
        "stdc_count_ones_ui",
        "stdc_count_zeros_ui",
        "stdc_has_single_bit_ui",
        "stdc_bit_width_ui",
        "stdc_bit_floor_ui",
        "stdc_bit_ceil_ui",
    ];

    for function in required {
        assert!(
            functions.contains(function),
            "missing stdbit unsigned-int fixture coverage for {function}"
        );
    }

    Ok(())
}

#[test]
fn stdbit_ops_fixture_cases_match_execute_fixture_case() -> Result<(), String> {
    let fixture = load_fixture()?;

    for case in &fixture.cases {
        let expected_output = case
            .expected_output
            .as_deref()
            .ok_or_else(|| format!("case {} missing expected_output", case.name))?;
        let modes: &[&str] = if case.mode.eq_ignore_ascii_case("both") {
            &["strict", "hardened"]
        } else {
            &[case.mode.as_str()]
        };

        for mode in modes {
            let result =
                execute_fixture_case(&case.function, &case.inputs, mode).map_err(|err| {
                    format!(
                        "fixture case {} ({mode}) failed to execute: {err}",
                        case.name
                    )
                })?;
            assert_eq!(
                result.impl_output, expected_output,
                "fixture expected_output mismatch for {} ({mode})",
                case.name
            );
            assert!(
                result.host_parity,
                "stdbit fixture should be internally parity-classified for {} ({mode})",
                case.name
            );
        }
    }

    Ok(())
}
