//! Meta-gate: in every `*_cli_contract.v1.json` manifest,
//! `manifest_id` appears in the JSON file lexically before
//! `subcommand_name` (bd-jq9hr). Catches ad-hoc field reordering
//! during retrofit. Canonical order is identity/anchor first
//! (manifest_id, bead, generated_utc), then descriptive
//! (subcommand_name, binary_target, purpose), then contract details.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn find_first_field_offset(body: &str, key: &str) -> Option<usize> {
    let needle = format!("\"{key}\"");
    body.find(&needle)
}

#[test]
fn every_cli_contract_manifest_id_appears_before_subcommand_name() -> TestResult {
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
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let mid_off = find_first_field_offset(&body, "manifest_id");
        let sub_off = find_first_field_offset(&body, "subcommand_name");
        match (mid_off, sub_off) {
            (Some(m), Some(s)) if m < s => {}
            (Some(m), Some(s)) => violations.push(format!(
                "{name}: manifest_id at offset {m} but subcommand_name at offset {s} (manifest_id should come first)"
            )),
            (None, _) => violations.push(format!("{name}: no `manifest_id` key found")),
            (_, None) => violations.push(format!("{name}: no `subcommand_name` key found")),
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} field-order violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
