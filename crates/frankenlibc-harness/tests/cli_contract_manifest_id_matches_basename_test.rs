//! Meta-gate: every `*_cli_contract.v1.json` manifest under
//! `tests/conformance/` has a `manifest_id` field whose kebab-case
//! value, when re-spelled in snake_case (`-` -> `_`), equals the file
//! basename (without `.v1.json`) (bd-wj0rn). Catches manifests whose
//! `manifest_id` drifted from the filename during rename/refactor.

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

fn kebab_to_snake(s: &str) -> String {
    s.replace('-', "_")
}

#[test]
fn every_cli_contract_manifest_id_matches_basename() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with("_cli_contract.v1.json") {
            continue;
        }
        let basename = name.strip_suffix(".v1.json").expect("checked above");
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let manifest: Value =
            serde_json::from_str(&body).map_err(|e| format!("parse {name}: {e}"))?;
        let Some(manifest_id) = manifest.get("manifest_id").and_then(Value::as_str) else {
            violations.push(format!("{name}: missing manifest_id field"));
            checked += 1;
            continue;
        };
        let expected_snake = basename;
        let actual_snake = kebab_to_snake(manifest_id);
        if actual_snake != expected_snake {
            violations.push(format!(
                "{name}: manifest_id `{manifest_id}` snake-form `{actual_snake}` != basename `{expected_snake}`"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} cli_contract manifest_id/basename violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn kebab_to_snake_handles_canonical_forms() {
    assert_eq!(kebab_to_snake("foo-bar-baz"), "foo_bar_baz");
    assert_eq!(kebab_to_snake("already_snake"), "already_snake");
    assert_eq!(kebab_to_snake(""), "");
    assert_eq!(kebab_to_snake("single"), "single");
}
