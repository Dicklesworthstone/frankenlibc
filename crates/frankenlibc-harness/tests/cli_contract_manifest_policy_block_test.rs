//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest must
//! declare a non-empty `policy` JSON object containing at least one bool
//! invariant (bd-g7o1e). Catches manifests committed without an enforceable
//! policy contract.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const LEGACY_POLICY_MISSING_CEILING: usize = 0;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_manifest_declares_nonempty_policy_block() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut missing: Vec<String> = Vec::new();
    let mut wrong_shape: Vec<String> = Vec::new();
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
        match manifest.get("policy") {
            None => missing.push(stem.to_string()),
            Some(Value::Object(map)) if map.is_empty() => missing.push(stem.to_string()),
            Some(Value::Object(map)) => {
                let bool_count = map.values().filter(|v| v.is_boolean()).count();
                if bool_count == 0 {
                    wrong_shape.push(format!(
                        "{stem}: policy object has {} keys but zero bool invariants",
                        map.len()
                    ));
                }
            }
            Some(other) => wrong_shape.push(format!(
                "{stem}: policy field is {} (expected JSON object)",
                match other {
                    Value::Null => "null",
                    Value::Bool(_) => "bool",
                    Value::Number(_) => "number",
                    Value::String(_) => "string",
                    Value::Array(_) => "array",
                    Value::Object(_) => "object",
                }
            )),
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if !wrong_shape.is_empty() {
        return Err(format!(
            "{} CLI contract manifest policy shape violation(s):\n  {}",
            wrong_shape.len(),
            wrong_shape.join("\n  ")
        ));
    }

    if missing.len() > LEGACY_POLICY_MISSING_CEILING {
        return Err(format!(
            "{} CLI contract manifest(s) with missing or empty policy block (ceiling {LEGACY_POLICY_MISSING_CEILING}):\n  {}",
            missing.len(),
            missing.join("\n  ")
        ));
    }
    Ok(())
}
