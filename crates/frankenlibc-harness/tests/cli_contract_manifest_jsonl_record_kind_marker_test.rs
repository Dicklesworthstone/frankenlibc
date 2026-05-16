//! Meta-gate: every `*_cli_contract.v1.json` manifest that declares a
//! `jsonl_output_contract` must expose at least one non-empty record-kind
//! discriminator (bd-aek1x). Most manifests use `record_kind_marker`; a few
//! multi-record or older contracts use explicit per-record marker names.

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

fn is_record_kind_marker_key(key: &str) -> bool {
    key == "record_kind_marker"
        || key.ends_with("_record_kind_marker")
        || key.ends_with("_kind_marker")
        || matches!(
            key,
            "record_kind"
                | "required_kind"
                | "record_schema_marker"
                | "detect_kind"
                | "validate_kind"
        )
}

fn marker_value_error(key: &str, value: &Value) -> Option<String> {
    match value {
        Value::String(s) if !s.trim().is_empty() => None,
        Value::String(_) => Some(format!("{key} is empty")),
        other => Some(format!("{key} is {other:?}, expected non-empty string")),
    }
}

#[test]
fn every_jsonl_output_contract_declares_record_kind_discriminator() -> TestResult {
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
        let manifest: Value =
            serde_json::from_str(&body).map_err(|e| format!("parse {name}: {e}"))?;
        let Some(jsonl_contract) = manifest.get("jsonl_output_contract") else {
            continue;
        };
        let Some(object) = jsonl_contract.as_object() else {
            violations.push(format!("{name}: jsonl_output_contract must be an object"));
            continue;
        };

        checked += 1;
        let mut marker_count = 0usize;
        for (key, value) in object {
            if !is_record_kind_marker_key(key) {
                continue;
            }
            marker_count += 1;
            if let Some(message) = marker_value_error(key, value) {
                violations.push(format!("{name}: {message}"));
            }
        }
        if marker_count == 0 {
            violations.push(format!(
                "{name}: jsonl_output_contract has no record-kind discriminator"
            ));
        }
    }

    assert!(
        checked >= 30,
        "expected at least 30 jsonl_output_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} jsonl record-kind discriminator violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn record_kind_marker_key_classifier_accepts_current_manifest_shapes() {
    for key in [
        "record_kind_marker",
        "per_row_record_kind_marker",
        "summary_record_kind_marker",
        "row_kind_marker",
        "delta_kind_marker",
        "record_kind",
        "required_kind",
        "record_schema_marker",
        "detect_kind",
        "validate_kind",
    ] {
        assert!(is_record_kind_marker_key(key), "{key}");
    }
}

#[test]
fn marker_value_validator_rejects_blank_or_non_string_markers() {
    assert!(marker_value_error("record_kind_marker", &Value::from("event")).is_none());
    assert!(marker_value_error("record_kind_marker", &Value::from("   ")).is_some());
    assert!(marker_value_error("record_kind_marker", &Value::Bool(true)).is_some());
    assert!(marker_value_error("record_kind_marker", &Value::Null).is_some());
}
