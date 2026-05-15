//! Completion contract tests for bd-epeg.1.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CONTRACT_REL: &str =
    "tests/conformance/franken_kernel_integration_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_franken_kernel_integration_completion_contract.sh";
const EXPECTED_MISSING_ITEMS: [&str; 2] = ["tests.unit.primary", "tests.e2e.primary"];
const REQUIRED_ID_TYPES: [&str; 4] = ["TraceId", "DecisionId", "PolicyId", "SchemaVersion"];
const REQUIRED_EVIDENCE_FIELDS: [&str; 12] = [
    "trace_id",
    "decision_id",
    "policy_id",
    "schema_version",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "artifact_refs",
];
const REQUIRED_TRACE_SCOPES: [&str; 8] = [
    "tsm::pointer_validation::",
    "runtime_math::decision_card::",
    "runtime_math::runtime_evidence::",
    "runtime_math::decision::",
    "membrane::heal::",
    "membrane::metrics::",
    "alien_cs::metric::",
    "alien_cs::snapshot::",
];
const REQUIRED_REPORT_FIELDS: [&str; 20] = [
    "timestamp",
    "trace_id",
    "level",
    "event",
    "bead_id",
    "completion_debt_bead",
    "mode",
    "runtime_mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "decision_id",
    "policy_id",
    "schema_version",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "workspace root").into())
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn load_manifest(root: &Path) -> TestResult<Value> {
    load_json(&root.join(CONTRACT_REL))
}

fn array<'a>(value: &'a Value, key: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing array `{key}`").into())
}

fn string_array(value: &Value, key: &str) -> TestResult<Vec<String>> {
    Ok(array(value, key)?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect())
}

fn output_dir(root: &Path, suffix: &str) -> TestResult<PathBuf> {
    let base = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("target"));
    let dir = base
        .join("conformance")
        .join("franken_kernel_integration_completion_contract")
        .join(suffix);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(
    root: &Path,
    contract: &Path,
    suffix: &str,
) -> TestResult<(Output, PathBuf, PathBuf)> {
    let dir = output_dir(root, suffix)?;
    let report = dir.join("report.json");
    let log = dir.join("events.jsonl");
    let output = Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .env("FRANKEN_KERNEL_INTEGRATION_COMPLETION_CONTRACT", contract)
        .env("FRANKEN_KERNEL_INTEGRATION_COMPLETION_REPORT", &report)
        .env("FRANKEN_KERNEL_INTEGRATION_COMPLETION_LOG", &log)
        .output()?;
    Ok((output, report, log))
}

fn read_log_rows(path: &Path) -> TestResult<Vec<Value>> {
    let content = std::fs::read_to_string(path)?;
    let rows = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()?;
    Ok(rows)
}

fn source_text(root: &Path, source_paths: &Value, source: &str) -> TestResult<String> {
    let rel = source_paths[source]
        .as_str()
        .ok_or_else(|| format!("missing source path for {source}"))?;
    Ok(std::fs::read_to_string(root.join(rel))?)
}

#[test]
fn manifest_binds_unit_and_e2e_audit_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_manifest(&root)?;
    assert_eq!(
        manifest["schema_version"],
        "franken_kernel_integration_completion_contract.v1"
    );
    assert_eq!(manifest["bead"], "bd-epeg");
    assert_eq!(manifest["completion_debt_bead"], "bd-epeg.1");
    assert!(
        manifest["next_audit_score_threshold"]
            .as_u64()
            .is_some_and(|threshold| threshold >= 800),
        "completion contract should target a passing audit score"
    );

    let audit_items = string_array(&manifest["audit"], "missing_items")?;
    for expected in EXPECTED_MISSING_ITEMS {
        assert!(
            audit_items.iter().any(|item| item == expected),
            "missing audit item {expected}"
        );
    }

    let coverage = array(&manifest, "completion_coverage")?;
    for expected in EXPECTED_MISSING_ITEMS {
        let section = coverage
            .iter()
            .find(|item| item["missing_item_id"] == expected)
            .ok_or_else(|| format!("missing coverage for {expected}"))?;
        assert_eq!(section["status"], "covered");
        assert!(
            section
                .get("implementation_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| !refs.is_empty()),
            "{expected} must cite implementation refs"
        );
        assert!(
            section
                .get("test_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| !refs.is_empty()),
            "{expected} must cite tests"
        );
        for command in section["validation_commands"]
            .as_array()
            .ok_or("validation_commands should be an array")?
            .iter()
            .filter_map(Value::as_str)
        {
            if command.contains("cargo ") {
                assert!(
                    command.contains("rch "),
                    "cargo validation commands must be routed through rch: {command}"
                );
                assert!(
                    command.contains("CARGO_TARGET_DIR="),
                    "rch cargo command must use an isolated target dir: {command}"
                );
            }
        }
    }

    Ok(())
}

#[test]
fn kernel_contract_names_canonical_fallback_types_and_fields() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_manifest(&root)?;
    let contract = &manifest["kernel_adoption_contract"];
    assert_eq!(contract["external_schema_forking_allowed"], false);
    assert_eq!(contract["standalone_fallback_required"], true);
    assert_eq!(contract["cx_fallback_type"], "ValidationSecurityContext");

    let id_types = string_array(contract, "canonical_id_types")?;
    for id_type in REQUIRED_ID_TYPES {
        assert!(
            id_types.iter().any(|item| item == id_type),
            "missing canonical id type {id_type}"
        );
    }

    let fields = string_array(contract, "required_evidence_fields")?;
    for field in REQUIRED_EVIDENCE_FIELDS {
        assert!(
            fields.iter().any(|item| item == field),
            "missing evidence field {field}"
        );
    }

    let scopes = string_array(contract, "required_trace_scopes")?;
    for scope in REQUIRED_TRACE_SCOPES {
        assert!(
            scopes.iter().any(|item| item == scope),
            "missing trace scope {scope}"
        );
    }

    Ok(())
}

#[test]
fn source_refs_and_named_tests_exist() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_manifest(&root)?;
    let source_paths = &manifest["source_paths"];

    for reference in array(&manifest, "implementation_refs")? {
        let path = reference["path"]
            .as_str()
            .ok_or("implementation ref path must be a string")?;
        let line = reference["line"]
            .as_u64()
            .ok_or("implementation ref line must be a positive integer")?;
        let anchor = reference["anchor"]
            .as_str()
            .ok_or("implementation ref anchor must be a string")?;
        let text = std::fs::read_to_string(root.join(path))?;
        let line_count = text.lines().count() as u64;
        assert!(
            (1..=line_count).contains(&line),
            "{path}:{line} outside file"
        );
        assert!(text.contains(anchor), "{path} missing anchor {anchor}");
    }

    let ids_text = source_text(&root, source_paths, "ids")?;
    for name in [
        "scoped_trace_ids_use_canonical_separator_and_hex_width",
        "zero_decision_id_does_not_emit_trace_id",
        "policy_id_wrapper_preserves_assignment_status",
        "membrane_schema_version_is_stable",
    ] {
        assert!(ids_text.contains(&format!("fn {name}")), "missing {name}");
    }

    let ptr_text = source_text(&root, source_paths, "ptr_validator")?;
    for name in [
        "validation_log_export_includes_trace_and_decision_ids",
        "security_context_default_deny_is_fail_closed",
    ] {
        assert!(ptr_text.contains(&format!("fn {name}")), "missing {name}");
    }

    let runtime_mod_text = source_text(&root, source_paths, "runtime_math_mod")?;
    for name in [
        "runtime_kernel_framework_exports_structured_decision_card_json",
        "runtime_kernel_framework_exports_runtime_math_jsonl_logs",
        "runtime_math_log_jsonl_export_contains_required_runtime_decision_fields",
    ] {
        assert!(
            runtime_mod_text.contains(&format!("fn {name}")),
            "missing {name}"
        );
    }

    Ok(())
}

#[test]
fn checker_emits_structured_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let contract = root.join(CONTRACT_REL);
    let (output, report_path, log_path) = run_checker(&root, &contract, "positive")?;
    assert!(
        output.status.success(),
        "checker failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path)?;
    assert_eq!(report["status"], "pass");
    assert_eq!(
        report["event"],
        "franken_kernel_integration_completion_contract_validated"
    );
    assert_eq!(report["bead_id"], "bd-epeg");
    assert_eq!(report["completion_debt_bead"], "bd-epeg.1");
    assert_eq!(report["schema_version"], "1.0");
    assert_eq!(report["mode"], "strict");
    assert_eq!(report["runtime_mode"], "strict");
    assert_eq!(report["api_family"], "franken_kernel_adoption");
    assert_eq!(report["symbol"], "franken_kernel::canonical_ids");
    assert_eq!(report["failure_signature"], "none");
    for field in REQUIRED_REPORT_FIELDS {
        assert!(report.get(field).is_some(), "missing report field {field}");
    }
    assert!(
        report["counts"]["unit_test_count"].as_u64().unwrap_or(0) >= 13,
        "unit test count should cover canonical ID/schema unit evidence"
    );
    assert!(
        report["counts"]["e2e_test_count"].as_u64().unwrap_or(0) >= 9,
        "e2e test count should cover structured export evidence"
    );

    let rows = read_log_rows(&log_path)?;
    assert_eq!(rows.len(), 1);
    let line = std::fs::read_to_string(&log_path)?;
    validate_log_line(line.trim(), 1).map_err(|errors| format!("{errors:?}"))?;
    assert_eq!(rows[0]["outcome"], "pass");

    Ok(())
}

#[test]
fn checker_rejects_missing_canonical_id_source_anchor() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_manifest(&root)?;
    let anchors = manifest["source_anchors"]["ids"]
        .as_array_mut()
        .ok_or("ids anchors should be an array")?;
    let index = anchors
        .iter()
        .position(|item| item.as_str() == Some("pub struct DecisionId(u64);"))
        .ok_or("expected DecisionId anchor")?;
    anchors[index] = Value::String("pub struct ForkedDecisionId(u64);".to_string());

    let dir = output_dir(&root, "negative")?;
    let mutated = dir.join("mutated_contract.json");
    std::fs::write(&mutated, serde_json::to_string_pretty(&manifest)? + "\n")?;

    let (output, report_path, log_path) = run_checker(&root, &mutated, "negative")?;
    assert!(
        !output.status.success(),
        "checker should fail for missing canonical ID anchor"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ForkedDecisionId"),
        "stderr should name the missing forked anchor: {stderr}"
    );
    let report = load_json(&report_path)?;
    assert_eq!(report["status"], "fail");
    assert_eq!(report["failure_signature"], "contract_validation_failed");
    let rows = read_log_rows(&log_path)?;
    assert_eq!(rows[0]["outcome"], "fail");
    let log_content = std::fs::read_to_string(&log_path)?;
    let first_log_row = log_content.lines().next().ok_or("missing log row")?;
    validate_log_line(first_log_row, 1).map_err(|errors| format!("{errors:?}"))?;

    Ok(())
}
