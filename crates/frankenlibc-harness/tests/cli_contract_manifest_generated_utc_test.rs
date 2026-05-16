//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest must
//! declare `generated_utc` matching the basic ISO-8601 UTC shape
//! `YYYY-MM-DDThh:mm:ssZ` (bd-du8d5). Catches malformed/missing timestamps
//! that break downstream report tooling.

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

fn is_iso_utc(ts: &str) -> bool {
    let bytes = ts.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return false;
    }
    for &i in &[0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !bytes[i].is_ascii_digit() {
            return false;
        }
    }
    true
}

#[test]
fn every_cli_contract_manifest_declares_iso_utc_timestamp() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
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
        let ts = manifest
            .get("generated_utc")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !is_iso_utc(ts) {
            violations.push(format!(
                "{stem}: generated_utc=`{ts}` is not basic ISO-8601 UTC (YYYY-MM-DDThh:mm:ssZ)"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} CLI contract manifest generated_utc violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn iso_utc_validator_accepts_canonical_forms_and_rejects_garbage() {
    assert!(is_iso_utc("2026-05-13T00:00:00Z"));
    assert!(is_iso_utc("2026-12-31T23:59:59Z"));
    assert!(!is_iso_utc(""));
    assert!(!is_iso_utc("2026-05-13"));
    assert!(!is_iso_utc("2026-05-13T00:00:00"));
    assert!(!is_iso_utc("2026-05-13T00:00:00.000Z"));
    assert!(!is_iso_utc("yesterday at noon"));
}
