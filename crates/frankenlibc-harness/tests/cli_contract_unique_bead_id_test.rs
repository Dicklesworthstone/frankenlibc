//! Meta-gate: each `bd-*` bead id anchors at most one
//! `*_cli_contract.v1.json` manifest under `tests/conformance/`
//! (bd-cvucw). Catches accidental bead-id reuse during retrofit /
//! batch-rebase. Two legacy classes are ratcheted as exempt:
//! - `bd-yjz2d` — peer batch-rebase bead used across 8+ manifests
//! - `bd-2tq.4` — pre-existing duplicate pair predating this gate
//!
//! New bead-id collisions fail-closed.

use std::collections::HashMap;
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
fn no_two_cli_contract_manifests_share_the_same_bead_id() -> TestResult {
    const LEGACY_SHARED_BEAD_IDS: &[&str] = &["bd-yjz2d", "bd-2tq.4"];

    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut bead_to_files: HashMap<String, Vec<String>> = HashMap::new();
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
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let manifest: Value =
            serde_json::from_str(&body).map_err(|e| format!("parse {name}: {e}"))?;
        let Some(bead) = manifest.get("bead").and_then(Value::as_str) else {
            continue;
        };
        if !bead.starts_with("bd-") {
            continue;
        }
        bead_to_files
            .entry(bead.to_string())
            .or_default()
            .push(name.to_string());
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests with bd-* bead ids; found {checked}"
    );

    let mut violations: Vec<String> = Vec::new();
    for (bead, files) in &bead_to_files {
        if files.len() > 1 && !LEGACY_SHARED_BEAD_IDS.contains(&bead.as_str()) {
            violations.push(format!(
                "{bead}: shared by {} manifests: {}",
                files.len(),
                files.join(", ")
            ));
        }
    }

    if !violations.is_empty() {
        violations.sort();
        return Err(format!(
            "{} bead-id collision(s) outside the legacy exempt set:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
