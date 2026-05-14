//! Deterministic BSD/GNU `<err.h>` fixture coverage for err_abi.
//!
//! The executable differential behavior lives in
//! `crates/frankenlibc-abi/tests/conformance_diff_err_h.rs` and
//! `crates/frankenlibc-abi/tests/err_abi_test.rs`. This harness-level test
//! binds that behavior to the exported-symbol fixture matrix so the critical
//! `err_abi` coverage gap cannot silently regress.

use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ERR_SYMBOLS: [&str; 12] = [
    "err", "errc", "errx", "verr", "verrc", "verrx", "vwarn", "vwarnc", "vwarnx", "warn", "warnc",
    "warnx",
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
    stderr_body: String,
    with_errno: bool,
    #[serde(default)]
    explicit_code: bool,
    #[serde(default)]
    va_list: bool,
    exits: bool,
    #[serde(default)]
    exit_status: Option<i32>,
}

fn load_fixture() -> Result<FixtureFile, String> {
    let path = repo_root().join("tests/conformance/fixtures/err_ops.json");
    let content = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|err| format!("invalid JSON in {}: {err}", path.display()))
}

fn load_json(path: &str) -> Result<serde_json::Value, String> {
    let path = repo_root().join(path);
    let content = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|err| format!("invalid JSON in {}: {err}", path.display()))
}

#[test]
fn err_ops_fixture_exists_and_names_scope() -> Result<(), String> {
    let fixture_path = repo_root().join("tests/conformance/fixtures/err_ops.json");
    assert!(fixture_path.exists(), "err_ops.json fixture must exist");

    let fixture = load_fixture()?;
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "err_ops");
    assert!(
        fixture.description.contains("<err.h>") && fixture.description.contains("stderr"),
        "fixture description must bind err.h stderr behavior"
    );
    assert!(
        fixture.spec_reference.contains("err(3)") && fixture.spec_reference.contains("glibc"),
        "fixture must cite BSD err(3) and glibc compatibility"
    );
    Ok(())
}

#[test]
fn err_ops_fixture_covers_every_exported_err_symbol() -> Result<(), String> {
    let fixture = load_fixture()?;
    let declared: BTreeSet<&str> = fixture
        .cases
        .iter()
        .map(|case| case.function.as_str())
        .collect();
    let expected: BTreeSet<&str> = ERR_SYMBOLS.into_iter().collect();
    assert_eq!(
        declared, expected,
        "err_ops fixture must cover exactly the exported err_abi symbols"
    );
    Ok(())
}

#[test]
fn err_ops_fixture_cases_are_deterministic_and_mode_paired() -> Result<(), String> {
    let fixture = load_fixture()?;
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "case name must not be empty");
        assert!(
            ERR_SYMBOLS.contains(&case.function.as_str()),
            "unexpected err_ops function {}",
            case.function
        );
        assert!(
            case.mode == "both",
            "err_ops fixtures should be strict/hardened paired"
        );
        assert!(
            !case.expected_output.stderr_body.is_empty(),
            "case {} must bind stderr body output",
            case.name
        );
        assert!(
            case.expected_output.stderr_body.ends_with('\n'),
            "case {} stderr body must include final newline",
            case.name
        );
        assert!(
            case.inputs.get("format").is_some(),
            "case {} must bind an input format string",
            case.name
        );

        let is_exit = matches!(
            case.function.as_str(),
            "err" | "errc" | "errx" | "verr" | "verrc" | "verrx"
        );
        assert_eq!(
            case.expected_output.exits, is_exit,
            "case {} exit classification drifted",
            case.name
        );
        if is_exit {
            assert!(
                case.expected_output.exit_status.unwrap_or(0) > 0,
                "case {} must bind a positive exit status",
                case.name
            );
        }

        let is_explicit_code = matches!(
            case.function.as_str(),
            "warnc" | "vwarnc" | "errc" | "verrc"
        );
        assert_eq!(
            case.expected_output.explicit_code, is_explicit_code,
            "case {} explicit-code classification drifted",
            case.name
        );
    }
    Ok(())
}

#[test]
fn err_ops_fixture_is_backed_by_existing_diff_and_unit_tests() -> Result<(), String> {
    let root = repo_root();
    let diff_test = std::fs::read_to_string(
        root.join("crates/frankenlibc-abi/tests/conformance_diff_err_h.rs"),
    )
    .map_err(|err| format!("failed to read err.h differential test: {err}"))?;
    for needle in [
        "diff_warnx_message_body",
        "diff_warnx_formatted_args",
        "diff_warn_errno_suffix",
        "diff_errx_exit_and_body",
        "diff_progname_source_matches_glibc",
    ] {
        assert!(
            diff_test.contains(needle),
            "missing diff test anchor {needle}"
        );
    }

    let unit_test =
        std::fs::read_to_string(root.join("crates/frankenlibc-abi/tests/err_abi_test.rs"))
            .map_err(|err| format!("failed to read err_abi unit test: {err}"))?;
    for needle in [
        "test_warnc_uses_explicit_code_not_global_errno",
        "test_vwarn_with_message",
        "test_vwarnx_with_message",
        "test_vwarnc_preserves_global_errno",
        "err_set_exit_hook_runs_before_errx_in_child",
    ] {
        assert!(
            unit_test.contains(needle),
            "missing err_abi test anchor {needle}"
        );
    }
    Ok(())
}

#[test]
fn symbol_fixture_coverage_counts_err_ops_fixture() -> Result<(), String> {
    let matrix = load_json("tests/conformance/symbol_fixture_coverage.v1.json")?;
    let symbols = matrix["symbols"]
        .as_array()
        .ok_or_else(|| "symbol_fixture_coverage.symbols must be an array".to_string())?;

    for symbol in ERR_SYMBOLS {
        let row = symbols
            .iter()
            .find(|row| row["module"] == "err_abi" && row["symbol"] == symbol)
            .ok_or_else(|| format!("missing err_abi symbol row for {symbol}"))?;
        assert!(
            row["fixture_case_count"].as_u64().unwrap_or(0) >= 1,
            "symbol_fixture_coverage must count err_ops fixture case for {symbol}"
        );
        let fixture_files = row["fixture_files"]
            .as_array()
            .ok_or_else(|| format!("fixture_files missing for {symbol}"))?;
        assert!(
            fixture_files.iter().any(|file| file == "err_ops.json"),
            "symbol_fixture_coverage must cite err_ops.json for {symbol}"
        );
    }

    let uncovered = matrix["uncovered_target_families"]
        .as_array()
        .ok_or_else(|| "uncovered_target_families must be an array".to_string())?;
    assert!(
        uncovered
            .iter()
            .all(|family| family["module"].as_str() != Some("err_abi")),
        "err_abi should not remain a critical uncovered target family after err_ops fixture"
    );
    Ok(())
}
