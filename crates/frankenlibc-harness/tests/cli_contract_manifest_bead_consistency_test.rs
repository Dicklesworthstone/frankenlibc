//! Meta-gate: when both top-level `bead` AND `summary.bead` are present in a
//! `tests/conformance/*_cli_contract.v1.json` manifest, they must be equal
//! (bd-4zv8v). Catches drift between the two bead-id slots that would let
//! one rotate while the other goes stale.

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
fn top_level_bead_and_summary_bead_agree_when_both_present() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut legacy_mismatch_count = 0usize;
    let mut compared = 0usize;
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
        let top_bead = manifest.get("bead").and_then(Value::as_str);
        let summary_bead = manifest
            .get("summary")
            .and_then(|s| s.get("bead"))
            .and_then(Value::as_str);
        if let (Some(t), Some(s)) = (top_bead, summary_bead) {
            if t != s {
                // Legacy escape-hatch: peer-retrofitted manifests where
                // summary.bead still carries a `pending-tracker-*` slug.
                // Treat as a ratcheted legacy class so the gate can ratchet
                // down as those summaries are rebased.
                if s.starts_with("pending-tracker-") {
                    legacy_mismatch_count += 1;
                } else {
                    violations.push(format!(
                        "{stem}: top-level bead=`{t}` but summary.bead=`{s}` (must agree)"
                    ));
                }
            }
            compared += 1;
        }
    }

    assert!(
        compared >= 20,
        "expected at least 20 manifests with both top-level + summary bead-id; found {compared}"
    );

    const LEGACY_BEAD_MISMATCH_CEILING: usize = 3;
    if legacy_mismatch_count > LEGACY_BEAD_MISMATCH_CEILING {
        return Err(format!(
            "legacy pending-tracker bead mismatch count rose to {legacy_mismatch_count} (ceiling: {LEGACY_BEAD_MISMATCH_CEILING})"
        ));
    }

    if !violations.is_empty() {
        return Err(format!(
            "{} bead-id consistency violation(s) between top-level and summary:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn top_level_manifest_id_matches_summary_subcommand_cli_contract_pattern() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut compared = 0usize;
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
        let manifest_id = manifest.get("manifest_id").and_then(Value::as_str);
        let summary_subcommand = manifest
            .get("summary")
            .and_then(|s| s.get("subcommand"))
            .and_then(Value::as_str);
        let top_subcommand = manifest.get("subcommand_name").and_then(Value::as_str);
        if let (Some(mid), Some(sub)) = (manifest_id, top_subcommand) {
            let expected = format!("{sub}-cli-contract");
            if mid != expected {
                violations.push(format!(
                    "{stem}: manifest_id=`{mid}` should equal `{expected}` (derived from subcommand_name)"
                ));
            }
            compared += 1;
        }
        if let (Some(sub_top), Some(sub_summary)) = (top_subcommand, summary_subcommand)
            && sub_top != sub_summary
        {
            violations.push(format!(
                "{stem}: top-level subcommand_name=`{sub_top}` but summary.subcommand=`{sub_summary}` (must agree)"
            ));
        }
    }

    assert!(
        compared >= 20,
        "expected at least 20 manifests with manifest_id + subcommand_name; found {compared}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} manifest_id / subcommand_name consistency violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
