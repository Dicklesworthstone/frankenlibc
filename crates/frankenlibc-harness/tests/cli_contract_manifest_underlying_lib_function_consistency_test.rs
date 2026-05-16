//! Meta-gate: when a `*_cli_contract.v1.json` manifest declares the
//! legacy singular `underlying_lib_function` alias, it must match the first
//! entry in canonical `underlying_lib_functions` (bd-25ide). The older gate
//! only proves the singular value appears somewhere in the plural list; this
//! pins the deterministic primary mapping used by dashboards and reviewers.

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

fn manifest_json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[test]
fn singular_underlying_lib_function_matches_first_plural_entry() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked_aliases = 0usize;
    let mut checked_manifests = 0usize;
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

        let Some(singular_value) = manifest.get("underlying_lib_function") else {
            continue;
        };
        checked_aliases += 1;
        let Some(singular) = singular_value.as_str() else {
            violations.push(format!(
                "{name}: underlying_lib_function is {}, expected string",
                manifest_json_type(singular_value)
            ));
            continue;
        };

        let Some(plural_value) = manifest.get("underlying_lib_functions") else {
            violations.push(format!(
                "{name}: has singular underlying_lib_function but missing underlying_lib_functions"
            ));
            continue;
        };
        let Some(plural) = plural_value.as_array() else {
            violations.push(format!(
                "{name}: underlying_lib_functions is {}, expected array",
                manifest_json_type(plural_value)
            ));
            continue;
        };
        let Some(first_value) = plural.first() else {
            violations.push(format!(
                "{name}: underlying_lib_functions is empty while singular alias is `{singular}`"
            ));
            continue;
        };
        let Some(first) = first_value.as_str() else {
            violations.push(format!(
                "{name}: underlying_lib_functions[0] is {}, expected string",
                manifest_json_type(first_value)
            ));
            continue;
        };
        if singular != first {
            violations.push(format!(
                "{name}: underlying_lib_function `{singular}` does not match first underlying_lib_functions entry `{first}`"
            ));
        }
    }

    assert!(
        checked_manifests >= 30,
        "expected at least 30 cli_contract manifests; found {checked_manifests}"
    );
    assert!(
        checked_aliases >= 20,
        "expected at least 20 manifests with underlying_lib_function alias; found {checked_aliases}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} singular/plural primary mapping violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
