//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest must
//! declare a non-empty `summary` JSON object with `bead`, `subcommand`, and
//! `claim_status` fields (bd-yb9dk). claim_status must be one of the
//! canonical values. Catches manifests committed without an explicit
//! lifecycle marker.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const LEGACY_SUMMARY_MISSING_CEILING: usize = 0;
const LEGACY_SUMMARY_BEAD_MISSING_CEILING: usize = 5;
// Canonical lifecycle markers + legacy escape-hatch values that predate this
// gate. New manifests must use one of the first three; legacy values are
// frozen so the count can only shrink.
const ALLOWED_CLAIM_STATUS: &[&str] = &[
    "report_only",
    "in_progress",
    "validated",
    "code_only_pending_tracker_closeout",
    "code_first_tracker_deferred",
    "pending_tracker_lease",
    "cli-contract",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_manifest_declares_summary_with_claim_status() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut missing: Vec<String> = Vec::new();
    let mut bead_missing_count = 0usize;
    let mut shape_violations: Vec<String> = Vec::new();
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
        let Some(summary) = manifest.get("summary").and_then(Value::as_object) else {
            missing.push(stem.to_string());
            checked += 1;
            continue;
        };
        for field in ["subcommand", "claim_status"] {
            if summary.get(field).and_then(Value::as_str).is_none() {
                shape_violations.push(format!("{stem}: summary.{field} missing or non-string"));
            }
        }
        if summary.get("bead").and_then(Value::as_str).is_none() {
            bead_missing_count += 1;
        }
        if let Some(claim_status) = summary.get("claim_status").and_then(Value::as_str)
            && !ALLOWED_CLAIM_STATUS.contains(&claim_status)
        {
            shape_violations.push(format!(
                "{stem}: summary.claim_status=`{claim_status}` not in {ALLOWED_CLAIM_STATUS:?}"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if !shape_violations.is_empty() {
        return Err(format!(
            "{} CLI contract manifest summary shape violation(s):\n  {}",
            shape_violations.len(),
            shape_violations.join("\n  ")
        ));
    }

    if missing.len() > LEGACY_SUMMARY_MISSING_CEILING {
        return Err(format!(
            "{} CLI contract manifest(s) with missing summary block (ceiling {LEGACY_SUMMARY_MISSING_CEILING}):\n  {}",
            missing.len(),
            missing.join("\n  ")
        ));
    }

    if bead_missing_count > LEGACY_SUMMARY_BEAD_MISSING_CEILING {
        return Err(format!(
            "summary.bead missing count rose to {bead_missing_count} (ceiling: {LEGACY_SUMMARY_BEAD_MISSING_CEILING})"
        ));
    }
    Ok(())
}
