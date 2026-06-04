//! Contract tests for bd-bp8fl.6.3.1 L1 CRT/startup/TLS completion.

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
    ("conformance_primary", "tests.conformance.primary"),
    ("telemetry_primary", "telemetry.primary"),
];

const EXPECTED_TELEMETRY_EVENTS: &[&str] = &[
    "l1_crt_startup_tls_completion_contract_validated",
    "l1_crt_startup_tls_summary",
    "replacement_levels_l1_gate_replayed",
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
    "l1_summary",
    "replacement_gate_report",
    "replacement_gate_log",
    "artifact_refs",
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

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/l1_crt_startup_tls_completion_contract.v1.json")
}

fn matrix_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/l1_crt_startup_tls_proof_matrix.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_l1_crt_startup_tls_completion_contract.sh")
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
        "l1-crt-startup-tls-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(
    root: &Path,
    contract: &Path,
    matrix: &Path,
    out_dir: &Path,
) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_L1_CRT_STARTUP_TLS_COMPLETION_CONTRACT",
            contract,
        )
        .env("FRANKENLIBC_L1_CRT_STARTUP_TLS_MATRIX", matrix)
        .env(
            "FRANKENLIBC_L1_CRT_STARTUP_TLS_COMPLETION_REPORT",
            out_dir.join("l1_crt_startup_tls_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_L1_CRT_STARTUP_TLS_COMPLETION_LOG",
            out_dir.join("l1_crt_startup_tls_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_L1_CRT_STARTUP_TLS_REPLACEMENT_REPORT",
            out_dir.join("l1_crt_startup_tls_completion_contract.replacement_levels.report.json"),
        )
        .env(
            "FRANKENLIBC_L1_CRT_STARTUP_TLS_REPLACEMENT_LOG",
            out_dir.join("l1_crt_startup_tls_completion_contract.replacement_levels.log.jsonl"),
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

fn run_passing_checker(root: &Path, label: &str) -> TestResult<PathBuf> {
    let out_dir = unique_output_dir(root, label)?;
    let output = run_checker(root, &contract_path(root), &matrix_path(root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker should pass:\n{}",
        checker_output_message(&output)
    );
    Ok(out_dir)
}

#[test]
fn manifest_binds_unit_e2e_conformance_and_telemetry_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    let matrix = read_json(&matrix_path(&root))?;

    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.6.3"));
    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(evidence["bead"].as_str(), Some("bd-bp8fl.6.3.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-bp8fl.6.3"));
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

    assert_eq!(
        string_set(&evidence["required_proof_row_ids"])?,
        string_set(&matrix["required_proof_row_ids"])?,
        "completion manifest should bind every proof row"
    );
    assert_eq!(
        string_set(&evidence["required_log_fields"])?,
        string_set(&matrix["required_log_fields"])?,
        "completion manifest should bind every proof log field"
    );
    let blocked_rows: BTreeSet<_> = matrix["proof_rows"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "proof rows"))?
        .iter()
        .filter(|row| row["promotion_decision"].as_str() == Some("claim_blocked"))
        .filter_map(|row| row["id"].as_str().map(ToOwned::to_owned))
        .collect();
    assert_eq!(
        string_set(&evidence["required_blocked_rows"])?,
        blocked_rows,
        "completion manifest should bind every claim-blocked row"
    );
    let negative_tests: BTreeSet<_> = matrix["negative_claim_tests"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "negative tests"))?
        .iter()
        .filter_map(|row| row["id"].as_str().map(ToOwned::to_owned))
        .collect();
    assert_eq!(
        string_set(&evidence["required_negative_claim_tests"])?,
        negative_tests,
        "completion manifest should bind every negative claim test"
    );

    let expectations = &evidence["minimum_l1_expectations"];
    let summary = &matrix["summary"];
    let required_row_count = summary["required_row_count"]
        .as_u64()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required_row_count"))?;
    let satisfied_row_count = summary["satisfied_row_count"]
        .as_u64()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "satisfied_row_count"))?;
    let blocked_row_count = summary["blocked_row_count"]
        .as_u64()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "blocked_row_count"))?;
    assert_eq!(
        expectations["proof_row_count"].as_u64(),
        Some(required_row_count)
    );
    assert_eq!(
        expectations["satisfied_row_count"].as_u64(),
        Some(satisfied_row_count)
    );
    assert_eq!(
        expectations["blocked_row_count"].as_u64(),
        Some(blocked_row_count)
    );
    assert_eq!(
        expectations["current_gate_status"].as_str(),
        summary["current_gate_status"].as_str()
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

    let telemetry_events = string_set(&evidence["telemetry_primary"]["required_events"])?;
    for expected in EXPECTED_TELEMETRY_EVENTS {
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
    let report_path = out_dir.join("l1_crt_startup_tls_completion_contract.report.json");
    let log_path = out_dir.join("l1_crt_startup_tls_completion_contract.log.jsonl");
    let report = read_json(&report_path)?;
    let events = read_jsonl(&log_path)?;

    assert_eq!(
        report["schema_version"].as_str(),
        Some("l1_crt_startup_tls_completion_contract.report.v1")
    );
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.6.3.1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["proof_row_count"].as_u64(), Some(11));
    assert_eq!(report["summary"]["satisfied_row_count"].as_u64(), Some(11));
    assert_eq!(report["summary"]["blocked_row_count"].as_u64(), Some(0));

    let emitted: BTreeSet<_> = events
        .iter()
        .filter_map(|event| event["event"].as_str())
        .collect();
    for expected in EXPECTED_TELEMETRY_EVENTS {
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
fn checker_replays_replacement_level_gate_and_preserves_l1_blockers() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "replacement-replay")?;
    let report = read_json(&out_dir.join("l1_crt_startup_tls_completion_contract.report.json"))?;
    let replacement_report = read_json(
        &out_dir.join("l1_crt_startup_tls_completion_contract.replacement_levels.report.json"),
    )?;
    let replacement_log = read_jsonl(
        &out_dir.join("l1_crt_startup_tls_completion_contract.replacement_levels.log.jsonl"),
    )?;

    assert_eq!(replacement_report["status"].as_str(), Some("pass"));
    assert_eq!(replacement_report["current_level"].as_str(), Some("L1"));
    assert_eq!(
        replacement_report["objective_gate_status"].as_str(),
        Some("pass")
    );
    assert_eq!(
        replacement_report["l1_crt_startup_tls_proof_matrix"]["current_gate_status"].as_str(),
        Some("pass")
    );
    assert_eq!(
        replacement_report["summary"]["l1_crt_promotion_decisions"]
            .get("claim_blocked")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        0
    );
    assert_eq!(
        report["summary"]["replacement_current_level"].as_str(),
        Some("L1")
    );
    assert_eq!(
        report["summary"]["replacement_objective_gate_status"].as_str(),
        Some("pass")
    );

    let l1_rows: Vec<_> = replacement_log
        .iter()
        .filter(|row| row["source"].as_str() == Some("l1_crt_startup_tls_proof_matrix"))
        .collect();
    assert_eq!(
        l1_rows.len(),
        22,
        "replacement replay should emit one strict and one hardened row per proof row"
    );
    let blocked_rows = string_set(&report["summary"]["blocked_rows"])?;
    let blocked_log_rows = l1_rows
        .iter()
        .filter(|row| {
            row["outcome"].as_str() == Some("claim_blocked")
                && row["proof_row_id"]
                    .as_str()
                    .is_some_and(|row_id| blocked_rows.contains(row_id))
        })
        .count();
    assert_eq!(
        blocked_log_rows, 0,
        "fully satisfied proof matrix should not emit blocked strict/hardened rows"
    );

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

    let output = run_checker(&root, &bad_contract, &matrix_path(&root), &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing log field:\n{}",
        checker_output_message(&output)
    );
    let report = read_json(&out_dir.join("l1_crt_startup_tls_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|error| error
                .as_str()
                .is_some_and(|text| text.contains("required_log_fields"))),
        "failure report should explain missing required_log_fields"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_proof_row_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-proof-row")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let rows = manifest["completion_debt_evidence"]["required_proof_row_ids"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "proof rows array"))?;
    rows.retain(|row| row.as_str() != Some("failure_diagnostics"));
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &matrix_path(&root), &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing proof row binding:\n{}",
        checker_output_message(&output)
    );
    let report = read_json(&out_dir.join("l1_crt_startup_tls_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|error| error
                .as_str()
                .is_some_and(|text| text.contains("required_proof_row_ids"))),
        "failure report should explain missing required_proof_row_ids"
    );
    Ok(())
}
