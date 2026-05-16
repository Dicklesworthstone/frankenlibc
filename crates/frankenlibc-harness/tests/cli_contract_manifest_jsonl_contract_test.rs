//! Meta-gate: when a `tests/conformance/*_cli_contract.v1.json` manifest
//! declares a `jsonl_output_contract` block, it must be a JSON object with
//! both a `record_count` field and at least one `required_fields*` array
//! (bd-u3ycx). Catches malformed JSONL output declarations.

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
fn jsonl_output_contract_when_present_has_record_count_and_required_fields() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut declared = 0usize;
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
        let Some(block) = manifest.get("jsonl_output_contract") else {
            continue;
        };
        let Some(obj) = block.as_object() else {
            violations.push(format!(
                "{stem}: jsonl_output_contract must be a JSON object"
            ));
            continue;
        };
        if !obj.contains_key("record_count") {
            violations.push(format!(
                "{stem}: jsonl_output_contract missing `record_count` field"
            ));
        }
        // required_fields family is present in most manifests, but some
        // multi-record contracts split into per-record blocks like
        // {summary_required_fields, per_row_required_fields,
        // per_repair_required_fields, error_fields, row_required_fields}
        // — accept any *_fields or *_field_markers key.
        let has_required_fields_family = obj.keys().any(|k| {
            k.contains("required_fields") || k.ends_with("_fields") || k.ends_with("_field_markers")
        });
        if !has_required_fields_family {
            violations.push(format!(
                "{stem}: jsonl_output_contract has no *_fields key family"
            ));
        }
        declared += 1;
    }

    assert!(
        declared >= 10,
        "expected at least 10 manifests with jsonl_output_contract; found {declared}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} jsonl_output_contract structural violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
