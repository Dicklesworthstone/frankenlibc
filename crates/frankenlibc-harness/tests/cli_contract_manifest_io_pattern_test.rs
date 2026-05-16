//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest must
//! declare a non-empty `io_pattern` snake_case string (bd-hb3bu), and every
//! present `io_pattern` must be one of the canonical IO contract shapes
//! (bd-7c6hh). Catches manifests that don't document their stdin/stdout/output
//! file shape, plus typo-driven IO taxonomy drift.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const LEGACY_IO_PATTERN_MISSING_CEILING: usize = 27;
const PRESENT_IO_PATTERN_FLOOR: usize = 40;
const KNOWN_IO_PATTERNS: &[&str] = &[
    "binary_evidence_records_to_decode_report",
    "environment_fingerprint_probe_to_single_jsonl_record",
    "fixture_directory_to_markdown_json_and_suite_conformance_report",
    "fixture_template_directory_to_refreshed_fixture_directory",
    "five_output_files_no_stdout_jsonl",
    "json_report_file_plus_jsonl_log_file",
    "jsonl_log_plus_json_report_no_stdout_jsonl",
    "jsonl_log_plus_json_report_plus_nested_binder_and_cross_report_artifacts",
    "jsonl_log_plus_json_report_plus_two_json_artifacts",
    "jsonl_log_plus_json_report_plus_validator_snapshot",
    "jsonl_trace_rows_to_single_minimized_trace_jsonl",
    "markdown_to_stdout_or_paired_md_plus_json_to_output_path",
    "out_dir_bundle_no_stdout_jsonl",
    "output_file_json_blob_no_stdout",
    "output_file_single_jsonl_record_no_stdout",
    "replay_expected_observed_jsonl_to_outcome_jsonl",
    "stdout_one_jsonl_record_no_output_file_flag",
    "stdout_one_pretty_json_record_no_output_file_flag",
    "stdout_plain_report_no_output_file",
    "structured_jsonl_log_plus_json_report",
    "support_matrix_plus_fixture_catalog_plus_conformance_matrix_plus_c_fixture_spec_to_markdown_and_json_traceability_matrix",
    "support_matrix_plus_fixture_catalog_plus_conformance_matrix_plus_c_fixture_spec_to_posix_obligation_json_report",
    "support_matrix_plus_fixture_catalog_plus_conformance_matrix_to_posix_coverage_json_report",
    "support_matrix_plus_fixture_catalog_plus_conformance_matrix_to_prioritized_errno_edge_json_report",
    "yaml_or_json_manifest_to_json_report_plus_structured_jsonl_log_plus_artifact_index",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn is_snake_case(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn is_known_io_pattern(s: &str) -> bool {
    KNOWN_IO_PATTERNS.contains(&s)
}

#[test]
fn every_cli_contract_manifest_declares_canonical_snake_case_io_pattern() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut missing: Vec<String> = Vec::new();
    let mut shape_violations: Vec<String> = Vec::new();
    let mut unknown_patterns: Vec<String> = Vec::new();
    let mut checked = 0usize;
    let mut present = 0usize;
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
        match manifest.get("io_pattern").and_then(Value::as_str) {
            None => missing.push(stem.to_string()),
            Some("") => missing.push(stem.to_string()),
            Some(s) => {
                present += 1;
                if !is_snake_case(s) {
                    shape_violations.push(format!("{stem}: io_pattern=`{s}` is not snake_case"));
                } else if !is_known_io_pattern(s) {
                    unknown_patterns.push(format!(
                        "{stem}: io_pattern=`{s}` is not in the canonical IO pattern set"
                    ));
                }
            }
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );
    assert!(
        present >= PRESENT_IO_PATTERN_FLOOR,
        "expected at least {PRESENT_IO_PATTERN_FLOOR} CLI contract manifests with io_pattern; found {present}"
    );

    if !shape_violations.is_empty() {
        return Err(format!(
            "{} CLI contract manifest io_pattern shape violation(s):\n  {}",
            shape_violations.len(),
            shape_violations.join("\n  ")
        ));
    }

    if !unknown_patterns.is_empty() {
        return Err(format!(
            "{} CLI contract manifest unknown io_pattern value(s):\n  {}",
            unknown_patterns.len(),
            unknown_patterns.join("\n  ")
        ));
    }

    if missing.len() > LEGACY_IO_PATTERN_MISSING_CEILING {
        return Err(format!(
            "{} CLI contract manifest(s) with missing or empty io_pattern (ceiling {LEGACY_IO_PATTERN_MISSING_CEILING}):\n  {}",
            missing.len(),
            missing.join("\n  ")
        ));
    }
    Ok(())
}
