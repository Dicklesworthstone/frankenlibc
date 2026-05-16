//! Meta-gate: when a `tests/conformance/*_cli_contract.v1.json` manifest
//! declares both `underlying_lib_function` (singular alias) and
//! `underlying_lib_functions` (plural canonical), the singular value must
//! appear in the plural array (bd-vw5vh). Also forbids new manifests from
//! using singular-only — the canonical form is the plural.

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

#[test]
fn singular_underlying_lib_function_must_appear_in_plural_list_when_both_present() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut consolidation_violations: Vec<String> = Vec::new();
    let mut singular_only: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(stem) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !stem.ends_with("_cli_contract.v1.json") {
            continue;
        }
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let manifest: Value =
            serde_json::from_str(&body).map_err(|e| format!("parse {path:?}: {e}"))?;
        let singular = manifest
            .get("underlying_lib_function")
            .and_then(Value::as_str);
        let plural = manifest
            .get("underlying_lib_functions")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect::<Vec<_>>()
            });

        match (singular, plural.as_ref()) {
            (Some(s), Some(plural_vec)) => {
                if !plural_vec.iter().any(|p| p == s) {
                    consolidation_violations.push(format!(
                        "{stem}: singular underlying_lib_function=`{s}` not present in plural list {plural_vec:?}"
                    ));
                }
            }
            (Some(_), None) => singular_only.push(stem.to_string()),
            _ => {}
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if !consolidation_violations.is_empty() {
        return Err(format!(
            "{} singular/plural underlying_lib_function consolidation violation(s):\n  {}",
            consolidation_violations.len(),
            consolidation_violations.join("\n  ")
        ));
    }

    const LEGACY_SINGULAR_ONLY_CEILING: usize = 0;
    if singular_only.len() > LEGACY_SINGULAR_ONLY_CEILING {
        return Err(format!(
            "{} manifest(s) use singular-only underlying_lib_function (ceiling {LEGACY_SINGULAR_ONLY_CEILING}); migrate to plural underlying_lib_functions:\n  {}",
            singular_only.len(),
            singular_only.join("\n  ")
        ));
    }
    Ok(())
}
