//! Meta-gate: every CLI flag declared in a
//! `tests/conformance/*_cli_contract.v1.json` manifest's `required_flags`
//! array must be named by its paired
//! `crates/frankenlibc-harness/tests/*_cli_contract_test.rs` gate
//! (bd-ll5ed). This catches manifest-only required-flag drift where a
//! new mandatory CLI argument is added to the contract but never pinned
//! by the executable gate.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

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

fn quoted_flag(flag: &str) -> String {
    format!("\"{flag}\"")
}

#[test]
fn every_manifest_required_flag_is_named_by_paired_gate() -> TestResult {
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
    let mut checked_flags = 0usize;
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
        let Some(flags) = manifest.get("required_flags").and_then(Value::as_array) else {
            continue;
        };

        let test_name = paired_gate_test_name(name)?;
        let test_path = tests_dir.join(&test_name);
        let test_body = match std::fs::read_to_string(&test_path) {
            Ok(body) => body,
            Err(error) => {
                violations.push(format!(
                    "{name}: paired gate `{test_name}` is unreadable: {error}"
                ));
                checked_manifests += 1;
                continue;
            }
        };

        for flag in flags {
            checked_flags += 1;
            let Some(flag) = flag.as_str() else {
                violations.push(format!("{name}: required_flags contains non-string entry"));
                continue;
            };
            let quoted = quoted_flag(flag);
            if !test_body.contains(&quoted) {
                violations.push(format!(
                    "{name}: required flag `{flag}` is not named as {quoted} in paired gate `{test_name}`"
                ));
            }
        }
        checked_manifests += 1;
    }

    assert!(
        checked_manifests >= 60,
        "expected at least 60 cli_contract manifests; found {checked_manifests}"
    );
    assert!(
        checked_flags >= 120,
        "expected at least 120 required CLI flags; found {checked_flags}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired gate required-flags coverage violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn paired_gate_test_name_maps_cli_contract_manifest_name() -> TestResult {
    assert_eq!(
        paired_gate_test_name("civil_date_from_unix_days_cli_contract.v1.json")?,
        "civil_date_from_unix_days_cli_contract_test.rs"
    );
    assert!(paired_gate_test_name("civil_date_from_unix_days_cli_contract.json").is_err());
    Ok(())
}

#[test]
fn quoted_flag_matches_literal_rust_string_form() {
    assert_eq!(quoted_flag("--unix-days"), "\"--unix-days\"");
}
