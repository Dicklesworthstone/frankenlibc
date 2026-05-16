//! Meta-gate: every bool policy invariant in
//! `tests/conformance/*_cli_contract.v1.json` must be `true` (bd-3n4rm).
//!
//! Convention: a manifest declares the positive invariants the gate test
//! enforces. A `false` value documents a behavior we explicitly do NOT
//! want — that should be expressed in `rejected_evidence_kinds` instead.
//! Catches accidentally-false invariants where someone meant to assert
//! the opposite.

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
fn every_policy_bool_invariant_is_true() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut total_invariants = 0usize;
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
        let Some(policy) = manifest.get("policy").and_then(Value::as_object) else {
            continue;
        };
        for (key, value) in policy {
            if let Some(b) = value.as_bool() {
                total_invariants += 1;
                if !b {
                    violations.push(format!(
                        "{stem}: policy.{key}=false (express negative behaviors via rejected_evidence_kinds instead)"
                    ));
                }
            }
        }
    }

    assert!(
        total_invariants >= 100,
        "expected at least 100 total bool invariants across the corpus; found {total_invariants}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} false policy invariant(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
