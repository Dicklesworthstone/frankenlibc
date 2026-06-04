//! Meta-gate: every top-level key in `tests/conformance/*_cli_contract.v1.json`
//! must be in the canonical KNOWN_TOP_LEVEL_KEYS allow-list (bd-yjodm). New
//! keys (added by extension manifests) must be added explicitly here. Catches
//! typos like `sumary`, `manifset_id`, or `default_step` that would silently
//! bypass strict-key gates by inventing a near-duplicate name.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const KNOWN_TOP_LEVEL_KEYS: &[&str] = &[
    "artifact_index_contract",
    "bead",
    "binary_target",
    "canonical_manifest_id",
    "canonical_manifest_path",
    "default_artifact_index_path",
    "default_bead_id",
    "default_binder_log_path",
    "default_binder_report_path",
    "default_c_fixture_spec",
    "default_campaign",
    "default_conformance_matrix",
    "default_contract_path",
    "default_cross_report_path",
    "default_feasibility_artifact_path",
    "default_fixture",
    "default_inputs",
    "default_iters",
    "default_log_path",
    "default_mode",
    "default_out_dir",
    "default_output",
    "default_output_path",
    "default_output_paths",
    "default_paths",
    "default_report_path",
    "default_run_id",
    "default_samples",
    "default_seed_hex",
    "default_sensitivity_artifact_path",
    "default_steps",
    "default_support_matrix",
    "default_trend_stride",
    "default_validator_report_path",
    "default_warmup_iters",
    "default_workspace_root",
    "discretization_constants",
    "env_contract",
    "env_override",
    "execution_lane",
    "expected_action_table",
    "expected_anchor_table",
    "expected_class_table",
    "expected_costs_ns",
    "expected_d4_anchor",
    "expected_full_sample",
    "expected_identity_packed_hex",
    "expected_identity_packed_u64",
    "expected_reverse_packed_hex",
    "expected_reverse_packed_u64",
    "generated_utc",
    "input_contract",
    "input_flags",
    "input_record_required_fields",
    "input_row_required_fields",
    "io_pattern",
    "json_output_contract",
    "jsonl_output_contract",
    "kind",
    "log_contract",
    "manifest_id",
    "markdown_output_contract",
    "mode_enum",
    "modes",
    "observed_record_required_fields",
    "optional_flags",
    "orchestrator_pattern",
    "out_dir_layout",
    "output_contract",
    "output_file_contract",
    "output_jsonl_required_fields_const",
    "output_record_required_fields",
    "payload_size_bytes",
    "plain_report_contract",
    "policy",
    "purpose",
    "rejected_evidence_kinds",
    "repair_max_degree_v1",
    "report_contract",
    "required_flags",
    "required_gate_cases",
    "required_log_events",
    "runtime_contract",
    "schema_version",
    "single_scenario_probe",
    "source_commit",
    "special_test_functions",
    "stage_name_enum",
    "stdin_contract",
    "stdout_output_contract",
    "subcommand_name",
    "summary",
    "supported_cap_values",
    "type",
    "underlying_bridge_function",
    "underlying_default_fingerprint_function",
    "underlying_lib_function",
    "underlying_lib_functions",
    "underlying_serializer_function",
    "valid_outcomes",
    "visibility",
    "write_count_cap",
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
fn known_top_level_keys_allow_list_is_alphabetized() {
    let mut prev: Option<&str> = None;
    for key in KNOWN_TOP_LEVEL_KEYS {
        if let Some(p) = prev {
            assert!(
                p < key,
                "KNOWN_TOP_LEVEL_KEYS must be alphabetized: `{p}` should precede `{key}` (or this is a duplicate)"
            );
        }
        prev = Some(key);
    }
}

#[test]
fn every_cli_contract_manifest_top_level_key_is_in_allow_list() -> TestResult {
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
        let Some(obj) = manifest.as_object() else {
            continue;
        };
        for key in obj.keys() {
            if !KNOWN_TOP_LEVEL_KEYS.contains(&key.as_str()) {
                violations.push(format!(
                    "{stem}: top-level key `{key}` is not in KNOWN_TOP_LEVEL_KEYS allow-list — add it explicitly if intentional"
                ));
            }
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} unknown top-level key(s) outside the allow-list:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
