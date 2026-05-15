//! Completion contract tests for bd-w2c3.9.3.1.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::Value;

type TestError = Box<dyn std::error::Error>;
type TestResult = Result<(), TestError>;

const CONTRACT_REL: &str =
    "tests/conformance/structured_log_artifact_index_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_structured_log_artifact_index_completion_contract.sh";
const EXPECTED_MISSING_ITEMS: [&str; 5] = [
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
    "migrations.primary",
    "telemetry.primary",
];
const REQUIRED_TELEMETRY_FIELDS: [&str; 10] = [
    "trace_id",
    "span_id",
    "controller_id",
    "decision_id",
    "policy_id",
    "evidence_seqno",
    "artifact_refs",
    "failure_signature",
    "latency_ns",
    "source_commit",
];

fn workspace_root() -> Result<PathBuf, TestError> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest.parent().ok_or_else(|| {
        format!(
            "harness manifest directory has no parent: {}",
            manifest.display()
        )
    })?;
    let repo_root = workspace_root.parent().ok_or_else(|| {
        format!(
            "workspace root has no repository parent: {}",
            workspace_root.display()
        )
    })?;
    Ok(repo_root.to_path_buf())
}

fn load_json(path: &Path) -> Result<Value, TestError> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn load_manifest(root: &Path) -> Result<Value, TestError> {
    load_json(&root.join(CONTRACT_REL))
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, TestError> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing array `{key}`").into())
}

fn string_array(value: &Value, key: &str) -> Result<Vec<String>, TestError> {
    Ok(array(value, key)?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect())
}

fn output_dir(root: &Path, suffix: &str) -> Result<PathBuf, TestError> {
    let base = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("target"));
    let dir = base
        .join("conformance")
        .join("structured_log_artifact_index_completion_contract")
        .join(suffix);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(
    root: &Path,
    contract: &Path,
    suffix: &str,
) -> Result<(Output, PathBuf, PathBuf), TestError> {
    let dir = output_dir(root, suffix)?;
    let report = dir.join("report.json");
    let log = dir.join("events.jsonl");
    let output = Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .env("STRUCTURED_LOG_ARTIFACT_INDEX_CONTRACT", contract)
        .env("STRUCTURED_LOG_ARTIFACT_INDEX_REPORT", &report)
        .env("STRUCTURED_LOG_ARTIFACT_INDEX_LOG", &log)
        .output()?;
    Ok((output, report, log))
}

fn read_log_rows(path: &Path) -> Result<Vec<Value>, TestError> {
    let content = std::fs::read_to_string(path)?;
    let rows = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()?;
    Ok(rows)
}

#[test]
fn manifest_binds_all_audit_gaps_to_refs_and_tests() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_manifest(&root)?;

    assert_eq!(
        manifest["schema_version"],
        "structured_log_artifact_index_completion_contract.v1"
    );
    assert_eq!(manifest["bead"], "bd-w2c3.9.3");
    assert_eq!(manifest["completion_debt_bead"], "bd-w2c3.9.3.1");

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
                .get("validation_command")
                .and_then(Value::as_str)
                .is_some_and(|cmd| cmd.contains("rch exec") || cmd.contains("scripts/check_")),
            "{expected} must cite an rch/checker validation command"
        );
    }

    for field in REQUIRED_TELEMETRY_FIELDS {
        let telemetry = coverage
            .iter()
            .find(|item| item["missing_item_id"] == "telemetry.primary")
            .ok_or("telemetry coverage missing")?;
        let fields = string_array(telemetry, "required_fields")?;
        assert!(fields.iter().any(|item| item == field), "missing {field}");
    }

    let refs = array(&manifest, "implementation_refs")?;
    for reference in refs {
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

    Ok(())
}

#[test]
fn checker_emits_joinable_report_and_valid_structured_log_row() -> TestResult {
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
    assert_eq!(report["failure_signature"], "none");
    assert_eq!(report["summary"]["missing_items_covered"], 5);
    assert!(
        report["summary"]["test_ref_count"]
            .as_u64()
            .is_some_and(|count| count >= 10),
        "contract should bind at least ten test refs"
    );

    let rows = read_log_rows(&log_path)?;
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(
        row["event"],
        "structured_log_artifact_index_completion_contract_validated"
    );
    assert_eq!(row["outcome"], "pass");
    assert_eq!(row["failure_signature"], "none");
    assert!(
        row["trace_id"]
            .as_str()
            .is_some_and(|id| { id.starts_with("bd-w2c3.9.3.1::artifact-index-contract::") })
    );
    for field in REQUIRED_TELEMETRY_FIELDS {
        assert!(row.get(field).is_some(), "log row missing {field}");
    }
    let serialized = serde_json::to_string(row)?;
    validate_log_line(&serialized, 1).map_err(|errors| {
        std::io::Error::other(format!("checker log row failed validation: {errors:?}"))
    })?;

    Ok(())
}

#[test]
fn checker_fails_closed_when_migration_or_telemetry_coverage_is_removed() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_manifest(&root)?;
    let coverage = manifest["completion_coverage"]
        .as_array_mut()
        .ok_or("completion_coverage must be an array")?;
    coverage.retain(|item| item["missing_item_id"] != "migrations.primary");
    let telemetry = coverage
        .iter_mut()
        .find(|item| item["missing_item_id"] == "telemetry.primary")
        .ok_or("telemetry coverage missing")?;
    let telemetry_fields = telemetry["required_fields"]
        .as_array_mut()
        .ok_or("telemetry fields missing")?;
    telemetry_fields.retain(|item| item != "decision_id");

    let dir = output_dir(&root, "negative")?;
    let bad_manifest = dir.join("missing_migration_and_decision_id.json");
    std::fs::write(&bad_manifest, serde_json::to_string_pretty(&manifest)?)?;

    let (output, report_path, log_path) = run_checker(&root, &bad_manifest, "negative")?;
    assert!(
        !output.status.success(),
        "checker must fail closed for malformed completion contract"
    );
    let report = load_json(&report_path)?;
    assert_eq!(report["status"], "fail");
    assert_eq!(
        report["failure_signature"],
        "structured_log_artifact_index_contract_invalid"
    );
    let errors = report["errors"]
        .as_array()
        .ok_or("failure report should carry errors")?;
    assert!(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|err| err.contains("migrations.primary")),
        "failure should mention missing migration coverage"
    );
    assert!(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|err| err.contains("decision_id")),
        "failure should mention missing telemetry decision_id"
    );

    let rows = read_log_rows(&log_path)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["event"],
        "structured_log_artifact_index_completion_contract_failed"
    );
    assert_eq!(
        rows[0]["failure_signature"],
        "structured_log_artifact_index_contract_invalid"
    );

    Ok(())
}
