//! Completion contract tests for bd-b5a.3.1.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CONTRACT_REL: &str = "tests/conformance/e2e_pack_ci_flake_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_e2e_pack_ci_flake_completion_contract.sh";
const EXPECTED_MISSING_ITEMS: [&str; 2] = ["tests.unit.primary", "tests.e2e.primary"];
const REQUIRED_ARTIFACTS: [&str; 5] = [
    "trace.jsonl",
    "artifact_index.json",
    "mode_pair_report.json",
    "scenario_pack_report.json",
    "flake_quarantine_report.json",
];
const REQUIRED_REPORT_FIELDS: [&str; 17] = [
    "timestamp",
    "trace_id",
    "span_id",
    "level",
    "event",
    "bead_id",
    "completion_debt_bead",
    "mode",
    "runtime_mode",
    "scenario_pack",
    "retry_count",
    "flake_score",
    "artifact_refs",
    "verdict",
    "latency_ns",
    "source_commit",
    "failure_signature",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest should have a parent"))?;
    let root = crates_dir.parent().ok_or_else(|| {
        io::Error::other("frankenlibc-harness manifest should live below workspace root")
    })?;
    Ok(root.to_path_buf())
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
        .join("e2e_pack_ci_flake_completion_contract")
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
        .env("E2E_PACK_CI_FLAKE_COMPLETION_CONTRACT", contract)
        .env("E2E_PACK_CI_FLAKE_COMPLETION_REPORT", &report)
        .env("E2E_PACK_CI_FLAKE_COMPLETION_LOG", &log)
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
        "e2e_pack_ci_flake_completion_contract.v1"
    );
    assert_eq!(manifest["bead"], "bd-b5a.3");
    assert_eq!(manifest["completion_debt_bead"], "bd-b5a.3.1");
    assert!(
        manifest["next_audit_score_threshold"]
            .as_u64()
            .is_some_and(|threshold| threshold >= 800),
        "completion contract should target a passing audit score"
    );

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
            }
        }
    }

    let gate = &manifest["gate_contract"];
    let packs = string_array(gate, "required_scenario_packs")?;
    for pack in ["smoke", "stress", "fault", "stability"] {
        assert!(packs.iter().any(|item| item == pack), "missing pack {pack}");
    }

    let artifacts = string_array(gate, "required_artifacts")?;
    for artifact in REQUIRED_ARTIFACTS {
        assert!(
            artifacts.iter().any(|item| item == artifact),
            "missing artifact {artifact}"
        );
    }

    let reporting = &manifest["reporting"];
    let fields = string_array(reporting, "required_fields")?;
    for field in REQUIRED_REPORT_FIELDS {
        assert!(fields.iter().any(|item| item == field), "missing {field}");
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

    let unit_text = source_text(&root, source_paths, "flake_policy_unit_tests")?;
    for name in [
        "test_all_pass_not_flaky",
        "test_fail_then_pass_is_flaky",
        "test_quarantined_flake_when_threshold_breached",
        "test_retry_on_nonzero_enabled",
        "test_retry_on_nonzero_disabled_respects_allowlist",
        "test_retry_stops_at_max",
        "test_classify_json_output",
        "test_should_retry_cli",
    ] {
        assert!(unit_text.contains(&format!("def {name}")), "missing {name}");
    }

    let e2e_text = source_text(&root, source_paths, "e2e_suite_harness")?;
    for name in [
        "e2e_suite_runs_and_produces_jsonl",
        "e2e_suite_supports_manifest_dry_run",
        "e2e_artifact_index_valid",
        "e2e_mode_pair_report_valid",
        "e2e_quarantine_and_pack_reports_valid",
        "check_e2e_suite_emits_completion_debt_report_and_log",
        "completion_debt_checker_rejects_stale_test_binding",
    ] {
        assert!(e2e_text.contains(&format!("fn {name}")), "missing {name}");
    }

    Ok(())
}

#[test]
fn checker_emits_report_log_and_runs_flake_policy_unit_tests() -> TestResult {
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
    assert_eq!(report["completion_debt_bead"], "bd-b5a.3.1");
    assert_eq!(report["summary"]["missing_items_covered"], 2);
    assert!(
        report["summary"]["test_ref_count"]
            .as_u64()
            .is_some_and(|count| count >= 18),
        "contract should bind unit and e2e test refs"
    );
    assert_eq!(
        report["summary"]["flake_policy_unit_result"]["exit_code"].as_i64(),
        Some(0)
    );

    let rows = read_log_rows(&log_path)?;
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(
        row["event"],
        "e2e_pack_ci_flake_completion_contract_validated"
    );
    assert_eq!(row["verdict"], "pass");
    assert_eq!(row["failure_signature"], "none");
    assert_eq!(row["completion_debt_bead"], "bd-b5a.3.1");
    assert_eq!(row["scenario_pack"], "all");
    assert!(
        row["artifact_refs"].is_array(),
        "artifact refs must be array"
    );
    let serialized = serde_json::to_string(row)?;
    validate_log_line(&serialized, 1).map_err(|errors| {
        std::io::Error::other(format!("checker log row failed validation: {errors:?}"))
    })?;

    Ok(())
}

#[test]
fn checker_rejects_missing_unit_binding_or_ci_gate() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_manifest(&root)?;
    let coverage = manifest["completion_coverage"]
        .as_array_mut()
        .ok_or("completion_coverage must be an array")?;
    let unit = coverage
        .iter_mut()
        .find(|item| item["missing_item_id"] == "tests.unit.primary")
        .ok_or("unit coverage missing")?;
    unit["test_refs"]
        .as_array_mut()
        .ok_or("unit test refs missing")?
        .retain(|item| item["name"] != "test_quarantined_flake_when_threshold_breached");
    manifest["gate_contract"]["ci_gate"]["required_scripts"] = serde_json::json!([]);

    let dir = output_dir(&root, "missing-unit-ci")?;
    let bad_manifest = dir.join("missing_unit_and_ci.json");
    std::fs::write(
        &bad_manifest,
        serde_json::to_string_pretty(&manifest)? + "\n",
    )?;

    let (output, report_path, log_path) = run_checker(&root, &bad_manifest, "missing-unit-ci")?;
    assert!(
        !output.status.success(),
        "checker must fail closed when unit or CI bindings are removed"
    );
    let report = load_json(&report_path)?;
    assert_eq!(report["status"], "fail");
    assert_eq!(
        report["failure_signature"],
        "e2e_pack_ci_flake_contract_invalid"
    );
    let errors = report["errors"]
        .as_array()
        .ok_or("failure report should carry errors")?;
    assert!(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|err| err.contains("test_quarantined_flake_when_threshold_breached")),
        "failure should mention the removed quarantine test"
    );
    assert!(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|err| err.contains("scripts/check_e2e_suite.sh")),
        "failure should mention the missing CI gate"
    );

    let rows = read_log_rows(&log_path)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["event"],
        "e2e_pack_ci_flake_completion_contract_failed"
    );
    assert_eq!(
        rows[0]["failure_signature"],
        "e2e_pack_ci_flake_contract_invalid"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_e2e_artifact_contract() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_manifest(&root)?;
    manifest["gate_contract"]["required_artifacts"]
        .as_array_mut()
        .ok_or("required artifacts missing")?
        .retain(|item| item != "flake_quarantine_report.json");

    let dir = output_dir(&root, "missing-artifact")?;
    let bad_manifest = dir.join("missing_artifact.json");
    std::fs::write(
        &bad_manifest,
        serde_json::to_string_pretty(&manifest)? + "\n",
    )?;

    let (output, report_path, _log_path) = run_checker(&root, &bad_manifest, "missing-artifact")?;
    assert!(
        !output.status.success(),
        "checker must fail closed when an E2E artifact contract is removed"
    );
    let report = load_json(&report_path)?;
    let errors = report["errors"]
        .as_array()
        .ok_or("failure report should carry errors")?;
    assert!(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|err| err.contains("flake_quarantine_report.json")),
        "failure should mention the missing quarantine artifact"
    );

    Ok(())
}
