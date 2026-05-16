//! Meta-gate: every I/O-bearing CLI contract manifest (`io_pattern`
//! present and non-empty) must have a paired gate test with at least four
//! `#[test]` functions (bd-w4z7c). The baseline paired-gate rule requires
//! three tests; I/O-bearing subcommands need an extra check because they
//! validate file/stdin/stdout behavior, not only manifest/source wiring.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const MIN_IO_PATTERN_TEST_FUNCTIONS: usize = 4;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn paired_gate_test_name(manifest_name: &str) -> TestResult<String> {
    manifest_name
        .strip_suffix(".v1.json")
        .map(|stem| format!("{stem}_test.rs"))
        .ok_or_else(|| format!("{manifest_name}: expected .v1.json suffix"))
}

fn count_test_attributes(body: &str) -> usize {
    body.lines()
        .filter(|line| line.trim_start().starts_with("#[test]"))
        .count()
}

#[test]
fn io_pattern_cli_contracts_have_four_or_more_paired_gate_tests() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let tests_dir = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("tests");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked_manifests = 0usize;
    let mut checked_io_manifests = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with("_cli_contract.v1.json") {
            continue;
        }

        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let manifest: Value =
            serde_json::from_str(&body).map_err(|e| format!("parse {name}: {e}"))?;
        checked_manifests += 1;
        let Some(io_pattern) = manifest.get("io_pattern").and_then(Value::as_str) else {
            continue;
        };
        if io_pattern.is_empty() {
            continue;
        }
        checked_io_manifests += 1;

        let test_name = paired_gate_test_name(name)?;
        let test_path = tests_dir.join(&test_name);
        let test_body = match std::fs::read_to_string(&test_path) {
            Ok(body) => body,
            Err(error) => {
                violations.push(format!(
                    "{name}: io_pattern=`{io_pattern}` but paired gate `{test_name}` is unreadable: {error}"
                ));
                continue;
            }
        };
        let test_count = count_test_attributes(&test_body);
        if test_count < MIN_IO_PATTERN_TEST_FUNCTIONS {
            violations.push(format!(
                "{name}: io_pattern=`{io_pattern}`, paired gate `{test_name}` declares {test_count} #[test] function(s); minimum is {MIN_IO_PATTERN_TEST_FUNCTIONS}"
            ));
        }
    }

    assert!(
        checked_manifests >= 30,
        "expected at least 30 cli_contract manifests; found {checked_manifests}"
    );
    assert!(
        checked_io_manifests >= 40,
        "expected at least 40 io_pattern cli_contract manifests; found {checked_io_manifests}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} I/O paired-gate test-count violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn test_attribute_counter_ignores_comments_and_counts_indented_attributes() {
    let body = "\
#[test]
fn manifest_shape() {}
    #[test]
    fn source_registration() {}
// #[test]
fn helper() {}
#[ignore]
#[test]
fn behavioral_io_case() {}
";
    assert_eq!(count_test_attributes(body), 3);
    assert_eq!(count_test_attributes("fn helper() {}\n// #[test]\n"), 0);
}

#[test]
fn paired_gate_test_name_maps_cli_contract_manifest_name() -> TestResult {
    assert_eq!(
        paired_gate_test_name("decode_evidence_cli_contract.v1.json")?,
        "decode_evidence_cli_contract_test.rs"
    );
    assert!(paired_gate_test_name("decode_evidence_cli_contract.json").is_err());
    Ok(())
}
