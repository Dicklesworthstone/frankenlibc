//! Harness coverage for the bd-1sp.10 Alien CS E2E shell gate.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| test_error("crate manifest should have crates parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have workspace parent"))?
        .to_path_buf())
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_alien_cs_e2e.sh")
}

fn read_text(path: &Path) -> TestResult<String> {
    std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_contains(haystack: &str, needle: &str, context: &str) {
    assert!(
        haystack.contains(needle),
        "{context} missing required marker `{needle}`"
    );
}

fn validate_checker_contract(source: &str) -> Vec<&'static str> {
    let required = [
        ("bead binding", "bd-1sp.10"),
        ("validate-only mode", "--validate-only"),
        ("rch mode", "--rch"),
        ("local fallback mode", "--local"),
        ("remote-only cargo policy", "RCH_REQUIRE_REMOTE=1"),
        ("rch cargo delegation", "rch exec -- cargo test"),
        ("membrane package", "-p frankenlibc-membrane"),
        ("e2e test file", "--test alien_cs_e2e_test"),
        (
            "e2e test filter",
            "alien_cs_e2e_matrix_emits_structured_artifacts",
        ),
        (
            "missing rch failure",
            "rch not available; rerun with --local only for manual fallback",
        ),
        (
            "artifact report path",
            "tests/conformance/alien_cs_e2e_report.v1.json",
        ),
        (
            "artifact trace path",
            "tests/conformance/alien_cs_e2e_trace.v1.jsonl",
        ),
        (
            "report schema assertion",
            "report.get(\"schema_version\") != \"v1\"",
        ),
        (
            "report bead assertion",
            "report.get(\"bead_id\") != \"bd-1sp.10\"",
        ),
        ("trace row count assertion", "len(trace_rows) != 25"),
        (
            "trace api family assertion",
            "row.get(\"api_family\") != \"alien_cs\"",
        ),
        (
            "final pass marker",
            "PASS: Alien CS E2E report + trace validated",
        ),
    ];

    required
        .iter()
        .filter_map(|(name, needle)| (!source.contains(needle)).then_some(*name))
        .collect()
}

#[test]
fn checker_script_defaults_to_remote_cargo_gate() -> TestResult {
    let root = workspace_root()?;
    let checker = checker_path(&root);
    let source = read_text(&checker)?;
    assert!(
        checker.is_file(),
        "missing checker script at {}",
        checker.display()
    );

    let failures = validate_checker_contract(&source);
    assert!(
        failures.is_empty(),
        "checker contract drifted: {failures:?}"
    );

    assert!(
        !source.contains("exec rch exec -- cargo test"),
        "checker must validate artifacts after remote cargo succeeds"
    );
    assert_contains(
        &source,
        "elif [[ \"${MODE}\" == \"local\" ]]; then",
        "checker source",
    );

    for rel in [
        "crates/frankenlibc-membrane/tests/alien_cs_e2e_test.rs",
        "tests/conformance/alien_cs_e2e_report.v1.json",
        "tests/conformance/alien_cs_e2e_trace.v1.jsonl",
    ] {
        assert!(root.join(rel).is_file(), "{rel} must exist");
    }

    Ok(())
}

#[test]
fn contract_validation_rejects_bare_default_cargo_drift() -> TestResult {
    let root = workspace_root()?;
    let source = read_text(&checker_path(&root))?;
    let mutated = source
        .replace("RCH_REQUIRE_REMOTE=1", "# missing remote-only cargo policy")
        .replace("rch exec -- cargo test", "cargo test");
    let failures = validate_checker_contract(&mutated);
    assert!(
        failures.contains(&"remote-only cargo policy"),
        "contract validator should reject a missing remote-only marker"
    );
    assert!(
        failures.contains(&"rch cargo delegation"),
        "contract validator should reject bare default cargo drift"
    );
    Ok(())
}

#[test]
fn validate_only_mode_checks_existing_artifacts_without_cargo() -> TestResult {
    let root = workspace_root()?;
    let output = Command::new("bash")
        .arg(checker_path(&root))
        .arg("--validate-only")
        .current_dir(&root)
        .output()?;
    assert!(
        output.status.success(),
        "validate-only gate failed: {}",
        output_text(&output)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for marker in [
        "=== Alien CS E2E Gate (bd-1sp.10) ===",
        "PASS: Alien CS E2E report + trace validated",
        "REPORT=tests/conformance/alien_cs_e2e_report.v1.json",
        "TRACE=tests/conformance/alien_cs_e2e_trace.v1.jsonl",
    ] {
        assert_contains(&stdout, marker, "checker stdout");
    }

    Ok(())
}
