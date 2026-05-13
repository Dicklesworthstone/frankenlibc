//! Deterministic POSIX/GNU `<fenv.h>` fixture coverage for fenv_abi.
//!
//! The executable ABI and glibc differential behavior lives in
//! `crates/frankenlibc-abi/tests/fenv_abi_test.rs` and
//! `crates/frankenlibc-abi/tests/conformance_diff_fenv.rs`. This
//! harness-level test binds that behavior to the exported-symbol fixture
//! matrix so the critical `fenv_abi` coverage gap cannot silently regress.

use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const FENV_SYMBOLS: [&str; 11] = [
    "feclearexcept",
    "fegetenv",
    "fegetexceptflag",
    "fegetround",
    "feholdexcept",
    "feraiseexcept",
    "fesetenv",
    "fesetexceptflag",
    "fesetround",
    "fetestexcept",
    "feupdateenv",
];

const EXCEPTION_SYMBOLS: [&str; 5] = [
    "feclearexcept",
    "fegetexceptflag",
    "feraiseexcept",
    "fesetexceptflag",
    "fetestexcept",
];

const ENV_POINTER_SYMBOLS: [&str; 5] = [
    "fegetenv",
    "fegetexceptflag",
    "feholdexcept",
    "fesetenv",
    "feupdateenv",
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
    fenv_flags_after: serde_json::Value,
    #[serde(default)]
    rounding_mode_after: serde_json::Value,
    #[serde(default)]
    reported_flags: Vec<String>,
    #[serde(default)]
    excluded_flags: Vec<String>,
    #[serde(default)]
    saved_flags: Vec<String>,
    #[serde(default)]
    saved_rounding_mode: Option<String>,
}

fn load_fixture() -> FixtureFile {
    let path = repo_root().join("tests/conformance/fixtures/fenv_ops.json");
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
fn fenv_ops_fixture_exists_and_names_scope() {
    let fixture_path = repo_root().join("tests/conformance/fixtures/fenv_ops.json");
    assert!(fixture_path.exists(), "fenv_ops.json fixture must exist");

    let fixture = load_fixture();
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "fenv_ops");
    assert!(
        fixture.description.contains("<fenv.h>")
            && fixture.description.contains("floating-point environment"),
        "fixture description must bind fenv.h floating-point environment behavior"
    );
    assert!(
        fixture.spec_reference.contains("POSIX")
            && fixture.spec_reference.contains("glibc")
            && fixture.spec_reference.contains("IEEE-754"),
        "fixture must cite POSIX, glibc, and IEEE-754 fenv behavior"
    );
}

#[test]
fn fenv_ops_fixture_covers_every_exported_fenv_symbol() {
    let fixture = load_fixture();
    let declared: BTreeSet<&str> = fixture
        .cases
        .iter()
        .map(|case| case.function.as_str())
        .collect();
    let expected: BTreeSet<&str> = FENV_SYMBOLS.into_iter().collect();
    assert_eq!(
        declared, expected,
        "fenv_ops fixture must cover exactly the exported fenv_abi symbols"
    );
    assert_eq!(
        fixture.cases.len(),
        FENV_SYMBOLS.len(),
        "fenv_ops should bind one deterministic case per exported symbol"
    );
}

#[test]
fn fenv_ops_fixture_cases_are_deterministic_and_mode_paired() {
    let fixture = load_fixture();
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "case name must not be empty");
        assert!(
            FENV_SYMBOLS.contains(&case.function.as_str()),
            "unexpected fenv_ops function {}",
            case.function
        );
        assert!(
            case.mode == "both",
            "fenv_ops fixtures should be strict/hardened paired"
        );
        assert_eq!(
            case.expected_output.status, "pass",
            "case {} must bind a successful glibc-compatible result",
            case.name
        );
        assert_eq!(
            case.expected_errno, 0,
            "case {} should not depend on errno mutation",
            case.name
        );
        assert!(
            case.spec_section.contains("POSIX"),
            "case {} must cite the POSIX fenv entrypoint",
            case.name
        );
        assert!(
            case.note.contains("fenv_abi_test::") || case.note.contains("conformance_diff_fenv::"),
            "case {} must cite executable ABI or differential coverage",
            case.name
        );

        if EXCEPTION_SYMBOLS.contains(&case.function.as_str()) {
            assert!(
                case.inputs.get("pre_raise_flags").is_some()
                    || case.inputs.get("raise_mask").is_some()
                    || case.inputs.get("saved_flags").is_some(),
                "case {} must bind exception-flag state",
                case.name
            );
        }

        if ENV_POINTER_SYMBOLS.contains(&case.function.as_str()) {
            assert!(
                case.inputs.get("fenv_t_bytes").is_some()
                    || case.inputs.get("fexcept_t_bytes").is_some(),
                "case {} must bind pointer payload size",
                case.name
            );
        }
    }
}

#[test]
fn fenv_ops_fixture_is_backed_by_existing_diff_and_unit_tests() {
    let root = repo_root();
    let diff_test =
        std::fs::read_to_string(root.join("crates/frankenlibc-abi/tests/conformance_diff_fenv.rs"))
            .expect("read fenv differential test");
    for needle in [
        "diff_round_modes_roundtrip",
        "diff_exception_flags_roundtrip",
        "diff_fegetenv_fesetenv_roundtrip",
        "fenv_diff_coverage_report",
    ] {
        assert!(
            diff_test.contains(needle),
            "missing fenv diff test anchor {needle}"
        );
    }

    let unit_test =
        std::fs::read_to_string(root.join("crates/frankenlibc-abi/tests/fenv_abi_test.rs"))
            .expect("read fenv_abi unit test");
    for needle in [
        "exception_flags_raise_and_clear",
        "exceptflag_round_trip_restores_flag_bits",
        "fesetround_all_modes_round_trip",
        "fegetenv_and_fesetenv_restore_rounding_state",
        "feholdexcept_and_feupdateenv_round_trip_saved_exceptions",
        "fetestexcept_returns_only_requested_flags",
        "environment_access_rejects_tracked_short_buffers",
    ] {
        assert!(
            unit_test.contains(needle),
            "missing fenv_abi test anchor {needle}"
        );
    }
}

#[test]
fn symbol_fixture_coverage_counts_fenv_ops_fixture() {
    let matrix = load_json("tests/conformance/symbol_fixture_coverage.v1.json");
    let symbols = matrix["symbols"]
        .as_array()
        .expect("symbol_fixture_coverage.symbols must be an array");

    for symbol in FENV_SYMBOLS {
        let row = symbols
            .iter()
            .find(|row| row["module"] == "fenv_abi" && row["symbol"] == symbol)
            .unwrap_or_else(|| panic!("missing fenv_abi symbol row for {symbol}"));
        assert!(
            row["fixture_case_count"].as_u64().unwrap_or(0) >= 1,
            "symbol_fixture_coverage must count fenv_ops fixture case for {symbol}"
        );
        let fixture_files = row["fixture_files"]
            .as_array()
            .unwrap_or_else(|| panic!("fixture_files missing for {symbol}"));
        assert!(
            fixture_files.iter().any(|file| file == "fenv_ops.json"),
            "symbol_fixture_coverage must cite fenv_ops.json for {symbol}"
        );
    }

    let uncovered = matrix["uncovered_target_families"]
        .as_array()
        .expect("uncovered_target_families must be an array");
    assert!(
        uncovered
            .iter()
            .all(|family| family["module"].as_str() != Some("fenv_abi")),
        "fenv_abi should not remain a critical uncovered target family after fenv_ops fixture"
    );
}
