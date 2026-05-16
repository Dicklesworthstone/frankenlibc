//! Meta-gate: when a `*_cli_contract.v1.json` manifest declares
//! `jsonl_output_contract`, it must have `required_fields` as a
//! non-empty array of strings (bd-q30iu). Catches manifests that
//! drop the required-fields classifier. Ten legacy manifests are
//! ratcheted as exempt.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const LEGACY_MANIFESTS_WITHOUT_REQUIRED_FIELDS: &[&str] = &[
    "decision_trace_minimize_cli_contract.v1.json",
    "decode_decision_payload_cli_contract.v1.json",
    "env_fingerprint_cli_contract.v1.json",
    "evidence_ring_stress_cli_contract.v1.json",
    "generate_repair_payloads_cli_contract.v1.json",
    "live_measurement_cli_contract.v1.json",
    "replay_classify_cli_contract.v1.json",
    "validate_runtime_evidence_rows_cli_contract.v1.json",
    "validate_setjmp_contract_cli_contract.v1.json",
    "verify_pcpt_cli_contract.v1.json",
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
fn every_cli_contract_jsonl_output_contract_has_required_fields_array() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut legacy_count = 0usize;
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
        let Some(jsonl) = manifest.get("jsonl_output_contract") else {
            continue;
        };
        checked += 1;
        let ok = matches!(
            jsonl.get("required_fields"),
            Some(Value::Array(a)) if !a.is_empty() && a.iter().all(|v| matches!(v, Value::String(s) if !s.is_empty()))
        );
        if !ok {
            if LEGACY_MANIFESTS_WITHOUT_REQUIRED_FIELDS.contains(&name) {
                legacy_count += 1;
            } else {
                violations.push(format!(
                    "{name}: jsonl_output_contract.required_fields missing/empty/non-string"
                ));
            }
        }
    }

    assert!(
        checked >= 20,
        "expected at least 20 jsonl_output_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} jsonl required_fields violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }

    if legacy_count > LEGACY_MANIFESTS_WITHOUT_REQUIRED_FIELDS.len() {
        return Err(format!(
            "legacy manifests missing required_fields rose to {legacy_count} (ceiling: {})",
            LEGACY_MANIFESTS_WITHOUT_REQUIRED_FIELDS.len()
        ));
    }
    Ok(())
}
