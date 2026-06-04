//! Contract tests for bd-gtf.5.1 L2 partial-replacement completion evidence.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const EXPECTED_MISSING_ITEMS: &[(&str, &str)] = &[
    ("unit_primary", "tests.unit.primary"),
    ("e2e_primary", "tests.e2e.primary"),
    ("fuzz_primary", "tests.fuzz.primary"),
    ("conformance_primary", "tests.conformance.primary"),
    ("telemetry_primary", "telemetry.primary"),
];

const EXPECTED_PASS_TELEMETRY_EVENTS: &[&str] = &[
    "l2_partial_replace_completion_contract_validated",
    "l2_partial_replace_summary",
    "standalone_readiness_matrix_replayed",
    "standalone_artifact_validate_only_replayed",
    "standalone_dependency_policy_blockers_preserved",
];

const EXPECTED_TELEMETRY_FIELDS: &[&str] = &[
    "timestamp",
    "trace_id",
    "event",
    "level",
    "bead_id",
    "completion_debt_bead",
    "original_bead",
    "status",
    "source_commit",
    "missing_items_bound",
    "test_refs",
    "l2_summary",
    "readiness_gate_report",
    "readiness_gate_log",
    "artifact_gate_report",
    "artifact_gate_log",
    "artifact_refs",
    "failure_signature",
];

const EXPECTED_FUZZ_MUTATION_TARGETS: &[&str] = &[
    "completion_debt_evidence.required_log_fields",
    "completion_debt_evidence.required_l2_obligation_ids",
    "completion_debt_evidence.required_negative_claim_tests",
    "completion_debt_evidence.telemetry_primary.required_fields",
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

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/l2_partial_replace_completion_contract.v1.json")
}

fn matrix_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/standalone_readiness_proof_matrix.v1.json")
}

fn levels_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/replacement_levels.json")
}

fn artifact_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/standalone_replacement_artifact.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_l2_partial_replace_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let array = value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string array"))?;
    let mut set = BTreeSet::new();
    for item in array {
        set.insert(
            item.as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string"))?
                .to_string(),
        );
    }
    Ok(set)
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "l2-partial-replace-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(
    root: &Path,
    contract: &Path,
    matrix: &Path,
    levels: &Path,
    artifact: &Path,
    out_dir: &Path,
) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_L2_PARTIAL_REPLACE_COMPLETION_CONTRACT",
            contract,
        )
        .env("FRANKENLIBC_L2_PARTIAL_REPLACE_READINESS_MATRIX", matrix)
        .env("FRANKENLIBC_L2_PARTIAL_REPLACE_REPLACEMENT_LEVELS", levels)
        .env(
            "FRANKENLIBC_L2_PARTIAL_REPLACE_STANDALONE_ARTIFACT",
            artifact,
        )
        .env(
            "FRANKENLIBC_L2_PARTIAL_REPLACE_COMPLETION_REPORT",
            out_dir.join("l2_partial_replace_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_L2_PARTIAL_REPLACE_COMPLETION_LOG",
            out_dir.join("l2_partial_replace_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_L2_PARTIAL_REPLACE_READINESS_REPORT",
            out_dir.join("l2_partial_replace_completion_contract.standalone_readiness.report.json"),
        )
        .env(
            "FRANKENLIBC_L2_PARTIAL_REPLACE_READINESS_LOG",
            out_dir.join("l2_partial_replace_completion_contract.standalone_readiness.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_L2_PARTIAL_REPLACE_ARTIFACT_REPORT",
            out_dir.join("l2_partial_replace_completion_contract.standalone_artifact.report.json"),
        )
        .env(
            "FRANKENLIBC_L2_PARTIAL_REPLACE_ARTIFACT_LOG",
            out_dir.join("l2_partial_replace_completion_contract.standalone_artifact.log.jsonl"),
        )
        .output()?)
}

fn assert_file_line_ref_exists(root: &Path, file_line_ref: &str) -> TestResult {
    let (path, line) = file_line_ref.rsplit_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "file-line ref should contain ':'",
        )
    })?;
    let line_no: usize = line.parse()?;
    assert!(line_no > 0, "file-line ref line must be positive");
    let full_path = root.join(path);
    assert!(
        full_path.is_file(),
        "file-line ref path should exist: {file_line_ref}"
    );
    let text = std::fs::read_to_string(full_path)?;
    let lines: Vec<_> = text.lines().collect();
    assert!(
        line_no <= lines.len(),
        "file-line ref outside file: {file_line_ref}"
    );
    assert!(
        !lines[line_no - 1].trim().is_empty(),
        "file-line ref should not cite a blank line: {file_line_ref}"
    );
    Ok(())
}

fn source_texts(root: &Path, manifest: &Value) -> TestResult<BTreeMap<String, String>> {
    let sources = manifest["completion_debt_evidence"]["test_sources"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test_sources object"))?;
    let mut texts = BTreeMap::new();
    for (key, path) in sources {
        let path = path
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source path string"))?;
        texts.insert(key.clone(), std::fs::read_to_string(root.join(path))?);
    }
    Ok(texts)
}

fn assert_test_refs_exist(
    section_name: &str,
    section: &Value,
    sources: &BTreeMap<String, String>,
) -> TestResult {
    let refs = section["required_test_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test refs array"))?;
    assert!(!refs.is_empty(), "{section_name} should name test refs");
    for test_ref in refs {
        let source = test_ref["source"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source string"))?;
        let name = test_ref["name"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test name string"))?;
        let text = sources
            .get(source)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source declared"))?;
        assert!(
            text.contains(&format!("fn {name}")) || text.contains(&format!("def {name}")),
            "{section_name} references missing test {source}::{name}"
        );
    }
    Ok(())
}

fn checker_output_message(output: &std::process::Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_report_error_contains(report: &Value, needle: &str) {
    assert!(
        report["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|error| error.as_str().is_some_and(|text| text.contains(needle))),
        "failure report should include {needle}: {report}"
    );
}

fn run_passing_checker(root: &Path, label: &str) -> TestResult<PathBuf> {
    let out_dir = unique_output_dir(root, label)?;
    let output = run_checker(
        root,
        &contract_path(root),
        &matrix_path(root),
        &levels_path(root),
        &artifact_path(root),
        &out_dir,
    )?;
    assert!(
        output.status.success(),
        "checker should pass:\n{}",
        checker_output_message(&output)
    );
    Ok(out_dir)
}

#[test]
fn manifest_binds_unit_e2e_fuzz_conformance_and_telemetry_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    let matrix = read_json(&matrix_path(&root))?;
    let levels = read_json(&levels_path(&root))?;
    let artifact = read_json(&artifact_path(&root))?;

    assert_eq!(manifest["bead"].as_str(), Some("bd-gtf.5"));
    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(evidence["bead"].as_str(), Some("bd-gtf.5.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-gtf.5"));
    assert!(
        evidence["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "completion evidence should target a passing next-audit score"
    );

    for file_line_ref in evidence["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "refs array"))?
    {
        assert_file_line_ref_exists(
            &root,
            file_line_ref
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref string"))?,
        )?;
    }

    let proof_rows: BTreeSet<_> = matrix["proof_rows"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "proof rows"))?
        .iter()
        .filter_map(|row| row["proof_row_id"].as_str().map(ToOwned::to_owned))
        .collect();
    assert_eq!(
        string_set(&evidence["required_proof_row_ids"])?,
        proof_rows,
        "completion manifest should bind every standalone readiness proof row"
    );
    assert_eq!(
        string_set(&evidence["required_log_fields"])?,
        string_set(&matrix["required_log_fields"])?,
        "completion manifest should bind every readiness log field"
    );

    let mut l2_obligations = BTreeSet::new();
    let mut obligations = BTreeSet::new();
    let mut negative_tests = BTreeSet::new();
    for obligation in matrix["obligations"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "obligations"))?
    {
        let id = obligation["id"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "obligation id"))?
            .to_string();
        if obligation["level"].as_str() == Some("L2") {
            l2_obligations.insert(id.clone());
        }
        obligations.insert(id);
        for negative in obligation["negative_claim_tests"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "negative tests"))?
        {
            negative_tests.insert(
                negative["id"]
                    .as_str()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "negative claim id"))?
                    .to_string(),
            );
        }
    }
    assert_eq!(
        string_set(&evidence["required_l2_obligation_ids"])?,
        l2_obligations,
        "completion manifest should bind every L2 obligation"
    );
    assert_eq!(
        string_set(&evidence["required_obligation_ids"])?,
        obligations,
        "completion manifest should bind every readiness obligation"
    );
    assert_eq!(
        string_set(&evidence["required_negative_claim_tests"])?,
        negative_tests,
        "completion manifest should bind every negative overclaim test"
    );

    let expectations = &evidence["minimum_l2_expectations"];
    let summary = &matrix["summary"];
    let proof_row_count = summary["proof_row_count"]
        .as_u64()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "proof_row_count"))?;
    let obligation_count = summary["obligation_count"]
        .as_u64()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "obligation_count"))?;
    let negative_claim_test_count = summary["negative_claim_test_count"]
        .as_u64()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "negative_claim_test_count"))?;
    let current_level_must_remain = expectations["current_level_must_remain"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "current_level_must_remain"))?;
    assert_eq!(
        expectations["proof_row_count"].as_u64(),
        Some(proof_row_count)
    );
    assert_eq!(
        expectations["obligation_count"].as_u64(),
        Some(obligation_count)
    );
    assert_eq!(
        expectations["negative_claim_test_count"].as_u64(),
        Some(negative_claim_test_count)
    );
    assert_eq!(
        expectations["l2_current_claim_status"].as_str(),
        matrix["claim_policy"]["l2_current_claim_status"].as_str()
    );
    assert_eq!(
        levels["current_level"].as_str(),
        Some(current_level_must_remain)
    );
    assert_eq!(
        artifact["artifact_policy"]["ld_preload_substitutes_allowed"].as_bool(),
        Some(false)
    );

    let sources = source_texts(&root, &manifest)?;
    for (section, missing_item) in EXPECTED_MISSING_ITEMS {
        let section_value = &evidence[*section];
        assert_eq!(
            section_value["missing_item_id"].as_str(),
            Some(*missing_item)
        );
        assert!(
            section_value["next_audit_score_threshold"]
                .as_u64()
                .unwrap_or(0)
                >= 800,
            "{section} should carry a passing next-audit threshold"
        );
        assert_test_refs_exist(section, section_value, &sources)?;
    }

    for section in [
        "unit_primary",
        "e2e_primary",
        "fuzz_primary",
        "conformance_primary",
        "telemetry_primary",
    ] {
        for command in evidence[section]["required_commands"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let command = command
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "command string"))?;
            assert!(
                !command.contains("cargo ") || command.contains("rch exec --"),
                "cargo validation commands must be routed through rch: {command}"
            );
        }
    }

    let fuzz_targets = string_set(&evidence["required_fuzz_mutation_targets"])?;
    for expected in EXPECTED_FUZZ_MUTATION_TARGETS {
        assert!(
            fuzz_targets.contains(*expected),
            "fuzz primary should mutate {expected}"
        );
    }

    let telemetry_events = string_set(&evidence["telemetry_primary"]["required_events"])?;
    for expected in EXPECTED_PASS_TELEMETRY_EVENTS {
        assert!(
            telemetry_events.contains(*expected),
            "telemetry should require {expected}"
        );
    }
    let telemetry_fields = string_set(&evidence["telemetry_primary"]["required_fields"])?;
    for expected in EXPECTED_TELEMETRY_FIELDS {
        assert!(
            telemetry_fields.contains(*expected),
            "telemetry should require field {expected}"
        );
    }

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "pass")?;
    let report_path = out_dir.join("l2_partial_replace_completion_contract.report.json");
    let log_path = out_dir.join("l2_partial_replace_completion_contract.log.jsonl");
    let report = read_json(&report_path)?;
    let events = read_jsonl(&log_path)?;

    assert_eq!(
        report["schema_version"].as_str(),
        Some("l2_partial_replace_completion_contract.report.v1")
    );
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-gtf.5.1"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["proof_row_count"].as_u64(), Some(14));
    assert_eq!(report["summary"]["l2_obligation_count"].as_u64(), Some(6));
    assert_eq!(
        report["summary"]["artifact_claim_status"].as_str(),
        Some("schema_validated")
    );

    let emitted: BTreeSet<_> = events
        .iter()
        .filter_map(|event| event["event"].as_str())
        .collect();
    for expected in EXPECTED_PASS_TELEMETRY_EVENTS {
        assert!(
            emitted.contains(expected),
            "checker log should emit {expected}"
        );
    }
    for event in events {
        for field in EXPECTED_TELEMETRY_FIELDS {
            assert!(
                event.get(*field).is_some(),
                "telemetry event should include {field}"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_replays_standalone_readiness_gate_and_preserves_l2_blockers() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "readiness-replay")?;
    let report = read_json(&out_dir.join("l2_partial_replace_completion_contract.report.json"))?;
    let readiness_report = read_json(
        &out_dir.join("l2_partial_replace_completion_contract.standalone_readiness.report.json"),
    )?;
    let readiness_log = read_jsonl(
        &out_dir.join("l2_partial_replace_completion_contract.standalone_readiness.log.jsonl"),
    )?;

    assert_eq!(readiness_report["status"].as_str(), Some("pass"));
    assert_eq!(readiness_report["proof_row_count"].as_u64(), Some(14));
    assert_eq!(readiness_report["obligation_count"].as_u64(), Some(12));
    assert_eq!(
        readiness_report["negative_claim_test_count"].as_u64(),
        Some(12)
    );
    assert_eq!(
        report["summary"]["replacement_current_level"].as_str(),
        Some("L1")
    );
    assert_eq!(
        report["summary"]["replacement_l2_status"].as_str(),
        Some("planned")
    );
    assert_eq!(report["summary"]["l2_obligation_count"].as_u64(), Some(6));

    assert_eq!(
        readiness_log.len(),
        14,
        "readiness replay should emit one row per proof row"
    );
    let l2_rows = readiness_log
        .iter()
        .filter(|row| row["replacement_level"].as_str() == Some("L2"))
        .count();
    assert_eq!(l2_rows, 9, "readiness replay should bind all L2 proof rows");
    for row in readiness_log {
        assert_eq!(row["actual_decision"].as_str(), Some("claim_blocked"));
    }

    Ok(())
}

#[test]
fn checker_replays_standalone_artifact_validate_only_gate() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "artifact-validate-only")?;
    let artifact_report = read_json(
        &out_dir.join("l2_partial_replace_completion_contract.standalone_artifact.report.json"),
    )?;
    let artifact_log = read_jsonl(
        &out_dir.join("l2_partial_replace_completion_contract.standalone_artifact.log.jsonl"),
    )?;

    assert_eq!(artifact_report["status"].as_str(), Some("pass"));
    assert_eq!(artifact_report["mode"].as_str(), Some("validate-only"));
    assert_eq!(
        artifact_report["claim_status"].as_str(),
        Some("schema_validated")
    );
    assert_eq!(
        artifact_report["artifact_state"]["status"].as_str(),
        Some("not_checked")
    );
    assert_eq!(artifact_log.len(), 1);
    assert_eq!(
        artifact_log[0]["event"].as_str(),
        Some("manifest_validated")
    );
    for field in artifact_report["required_log_fields"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required log fields"))?
    {
        let field = field
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "field string"))?;
        assert!(
            artifact_log[0].get(field).is_some(),
            "artifact validate-only log should include {field}"
        );
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_required_log_field_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-log-field")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let fields = manifest["completion_debt_evidence"]["required_log_fields"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "log fields array"))?;
    if let Some(index) = fields
        .iter()
        .position(|value| matches!(value.as_str(), Some("failure_signature")))
    {
        fields.remove(index);
    }
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(
        &root,
        &bad_contract,
        &matrix_path(&root),
        &levels_path(&root),
        &artifact_path(&root),
        &out_dir,
    )?;
    assert!(
        !output.status.success(),
        "checker should reject missing log field:\n{}",
        checker_output_message(&output)
    );
    let report = read_json(&out_dir.join("l2_partial_replace_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_report_error_contains(&report, "required_log_fields");
    assert_report_error_contains(&report, "failure_signature");
    Ok(())
}

#[test]
fn checker_rejects_missing_l2_obligation_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-l2-obligation")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let obligations = manifest["completion_debt_evidence"]["required_l2_obligation_ids"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "L2 obligations array"))?;
    obligations.retain(|row| row.as_str() != Some("l2-host-dependency-allowlist"));
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(
        &root,
        &bad_contract,
        &matrix_path(&root),
        &levels_path(&root),
        &artifact_path(&root),
        &out_dir,
    )?;
    assert!(
        !output.status.success(),
        "checker should reject missing L2 obligation:\n{}",
        checker_output_message(&output)
    );
    let report = read_json(&out_dir.join("l2_partial_replace_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_report_error_contains(&report, "required_l2_obligation_ids");
    assert_report_error_contains(&report, "l2-host-dependency-allowlist");
    Ok(())
}

#[test]
fn checker_rejects_missing_fuzz_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-fuzz-binding")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let targets = manifest["completion_debt_evidence"]["required_fuzz_mutation_targets"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "fuzz targets array"))?;
    targets
        .retain(|row| row.as_str() != Some("completion_debt_evidence.required_l2_obligation_ids"));
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(
        &root,
        &bad_contract,
        &matrix_path(&root),
        &levels_path(&root),
        &artifact_path(&root),
        &out_dir,
    )?;
    assert!(
        !output.status.success(),
        "checker should reject missing fuzz mutation target:\n{}",
        checker_output_message(&output)
    );
    let report = read_json(&out_dir.join("l2_partial_replace_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_report_error_contains(&report, "required_fuzz_mutation_targets");
    assert_report_error_contains(
        &report,
        "completion_debt_evidence.required_l2_obligation_ids",
    );
    Ok(())
}
