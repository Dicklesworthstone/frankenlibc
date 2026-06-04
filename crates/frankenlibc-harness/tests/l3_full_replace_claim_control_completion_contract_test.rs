//! Contract tests for bd-gtf.6.1 L3 full-replacement claim-control completion evidence.

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

const EXPECTED_CLAIM_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "release_claim_id",
    "replacement_level",
    "required_evidence",
    "present_evidence",
    "expected_decision",
    "actual_decision",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

const EXPECTED_PASS_TELEMETRY_EVENTS: &[&str] = &[
    "l3_full_replace_completion_contract_validated",
    "l3_full_replace_summary",
    "release_claim_current_l1_replayed",
    "release_claim_l3_overclaim_blocked",
    "release_dossier_policy_bound",
    "standalone_l3_blockers_preserved",
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
    "l3_summary",
    "current_claim_report",
    "current_claim_log",
    "l3_overclaim_report",
    "l3_overclaim_log",
    "readiness_gate_report",
    "readiness_gate_log",
    "artifact_refs",
    "failure_signature",
];

const EXPECTED_FUZZ_MUTATION_TARGETS: &[&str] = &[
    "completion_debt_evidence.required_claim_log_fields",
    "completion_debt_evidence.required_l3_obligation_ids",
    "completion_debt_evidence.required_l3_release_claim_failure_signatures",
    "completion_debt_evidence.telemetry_primary.required_fields",
    "synthetic_claims.claimed_level",
    "release_dossier.FLC_RELEASE_DOSSIER_RELEASE_NOTES_LIMIT",
];

const EXPECTED_L3_FAILURE_SIGNATURES: &[&str] = &[
    "release_claim_missing_l2_evidence",
    "release_claim_missing_l3_evidence",
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
    root.join("tests/conformance/l3_full_replace_claim_control_completion_contract.v1.json")
}

fn matrix_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/standalone_readiness_proof_matrix.v1.json")
}

fn levels_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/replacement_levels.json")
}

fn dossier_report_path(root: &Path) -> PathBuf {
    root.join("tests/release/dossier_validation_report.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_l3_full_replace_claim_control_completion_contract.sh")
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
        "l3-full-replace-completion-{label}-{}-{nanos}",
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
    dossier_report: &Path,
    out_dir: &Path,
) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_L3_FULL_REPLACE_COMPLETION_CONTRACT",
            contract,
        )
        .env("FRANKENLIBC_L3_FULL_REPLACE_READINESS_MATRIX", matrix)
        .env("FRANKENLIBC_L3_FULL_REPLACE_REPLACEMENT_LEVELS", levels)
        .env(
            "FRANKENLIBC_L3_FULL_REPLACE_DOSSIER_REPORT",
            dossier_report,
        )
        .env(
            "FRANKENLIBC_L3_FULL_REPLACE_COMPLETION_REPORT",
            out_dir.join("l3_full_replace_claim_control_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_L3_FULL_REPLACE_COMPLETION_LOG",
            out_dir.join("l3_full_replace_claim_control_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_L3_FULL_REPLACE_CURRENT_CLAIM_REPORT",
            out_dir.join("l3_full_replace_claim_control_completion_contract.current_claim.report.json"),
        )
        .env(
            "FRANKENLIBC_L3_FULL_REPLACE_CURRENT_CLAIM_LOG",
            out_dir.join("l3_full_replace_claim_control_completion_contract.current_claim.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_L3_FULL_REPLACE_OVERCLAIM_CLAIMS",
            out_dir.join("l3_full_replace_claim_control_completion_contract.l3_overclaim.claims.json"),
        )
        .env(
            "FRANKENLIBC_L3_FULL_REPLACE_OVERCLAIM_REPORT",
            out_dir.join("l3_full_replace_claim_control_completion_contract.l3_overclaim.report.json"),
        )
        .env(
            "FRANKENLIBC_L3_FULL_REPLACE_OVERCLAIM_LOG",
            out_dir.join("l3_full_replace_claim_control_completion_contract.l3_overclaim.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_L3_FULL_REPLACE_READINESS_REPORT",
            out_dir.join("l3_full_replace_claim_control_completion_contract.standalone_readiness.report.json"),
        )
        .env(
            "FRANKENLIBC_L3_FULL_REPLACE_READINESS_LOG",
            out_dir.join("l3_full_replace_claim_control_completion_contract.standalone_readiness.log.jsonl"),
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
        &dossier_report_path(root),
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
    let dossier = read_json(&dossier_report_path(&root))?;

    assert_eq!(manifest["bead"].as_str(), Some("bd-gtf.6"));
    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(evidence["bead"].as_str(), Some("bd-gtf.6.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-gtf.6"));
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
        string_set(&evidence["required_claim_log_fields"])?,
        EXPECTED_CLAIM_LOG_FIELDS
            .iter()
            .map(|field| (*field).to_string())
            .collect(),
        "completion manifest should bind release claim log fields"
    );

    let mut l3_obligations = BTreeSet::new();
    let mut l3_negative_tests = BTreeSet::new();
    let mut l3_proof_rows = 0_u64;
    for row in matrix["proof_rows"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "proof rows"))?
    {
        if row["replacement_level"].as_str() == Some("L3") {
            l3_proof_rows += 1;
            assert_eq!(row["actual_decision"].as_str(), Some("claim_blocked"));
        }
    }
    for obligation in matrix["obligations"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "obligations"))?
    {
        if obligation["level"].as_str() == Some("L3") {
            let id = obligation["id"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "obligation id"))?
                .to_string();
            l3_obligations.insert(id);
            assert_eq!(obligation["current_state"].as_str(), Some("blocked"));
            for negative in obligation["negative_claim_tests"]
                .as_array()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "negative tests"))?
            {
                l3_negative_tests.insert(
                    negative["id"]
                        .as_str()
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "negative claim id")
                        })?
                        .to_string(),
                );
            }
        }
    }
    assert_eq!(
        string_set(&evidence["required_l3_obligation_ids"])?,
        l3_obligations,
        "completion manifest should bind every L3 obligation"
    );
    assert_eq!(
        string_set(&evidence["required_l3_negative_claim_tests"])?,
        l3_negative_tests,
        "completion manifest should bind every L3 negative overclaim test"
    );

    let expectations = &evidence["minimum_l3_expectations"];
    let matrix_proof_row_count = matrix["summary"]["proof_row_count"]
        .as_u64()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "matrix proof row count"))?;
    let current_level_must_remain = expectations["current_level_must_remain"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "current level expectation"))?;
    let current_release_level_must_remain = expectations["current_release_level_must_remain"]
        .as_str()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "current release level expectation",
            )
        })?;
    let l3_replacement_level_status = expectations["l3_replacement_level_status"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "L3 replacement status"))?;
    assert_eq!(
        expectations["proof_row_count"].as_u64(),
        Some(matrix_proof_row_count)
    );
    assert_eq!(
        expectations["l3_proof_row_count"].as_u64(),
        Some(l3_proof_rows)
    );
    assert_eq!(
        expectations["l3_current_claim_status"].as_str(),
        matrix["claim_policy"]["l3_current_claim_status"].as_str()
    );
    assert_eq!(
        levels["current_level"].as_str(),
        Some(current_level_must_remain)
    );
    assert_eq!(
        levels["release_tag_policy"]["current_release_level"].as_str(),
        Some(current_release_level_must_remain)
    );
    let l3_level = levels["levels"]
        .as_array()
        .and_then(|levels| {
            levels
                .iter()
                .find(|level| level["level"].as_str() == Some("L3"))
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "L3 level"))?;
    assert_eq!(
        l3_level["status"].as_str(),
        Some(l3_replacement_level_status)
    );
    assert_eq!(l3_level["host_glibc_required"].as_bool(), Some(false));
    assert_eq!(dossier["status"].as_str(), Some("pass"));
    assert!(dossier["release_notes_hook"].is_object());

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

    let signatures = string_set(&evidence["required_l3_release_claim_failure_signatures"])?;
    for expected in EXPECTED_L3_FAILURE_SIGNATURES {
        assert!(
            signatures.contains(*expected),
            "L3 overclaim should require {expected}"
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
    let report_path = out_dir.join("l3_full_replace_claim_control_completion_contract.report.json");
    let log_path = out_dir.join("l3_full_replace_claim_control_completion_contract.log.jsonl");
    let report = read_json(&report_path)?;
    let events = read_jsonl(&log_path)?;

    assert_eq!(
        report["schema_version"].as_str(),
        Some("l3_full_replace_claim_control_completion_contract.report.v1")
    );
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-gtf.6.1"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["l3_obligation_count"].as_u64(), Some(6));
    assert_eq!(report["summary"]["l3_proof_row_count"].as_u64(), Some(5));
    assert_eq!(
        report["summary"]["l3_overclaim_status"].as_str(),
        Some("fail")
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
fn checker_replays_current_l1_and_blocks_l3_overclaim() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "claim-replay")?;
    let current_report = read_json(
        &out_dir
            .join("l3_full_replace_claim_control_completion_contract.current_claim.report.json"),
    )?;
    let current_log = read_jsonl(
        &out_dir.join("l3_full_replace_claim_control_completion_contract.current_claim.log.jsonl"),
    )?;
    let l3_report = read_json(
        &out_dir.join("l3_full_replace_claim_control_completion_contract.l3_overclaim.report.json"),
    )?;
    let l3_log = read_jsonl(
        &out_dir.join("l3_full_replace_claim_control_completion_contract.l3_overclaim.log.jsonl"),
    )?;

    assert_eq!(current_report["status"].as_str(), Some("pass"));
    assert!(
        !current_log.is_empty(),
        "current L1 claim log should emit rows"
    );
    for row in &current_log {
        assert_eq!(row["actual_decision"].as_str(), Some("claim_allowed"));
        for field in EXPECTED_CLAIM_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "current log missing {field}");
        }
    }

    assert_eq!(l3_report["status"].as_str(), Some("fail"));
    assert_eq!(
        l3_log.len(),
        1,
        "synthetic L3 overclaim should emit one row"
    );
    let row = &l3_log[0];
    assert_eq!(row["replacement_level"].as_str(), Some("L3"));
    assert_eq!(row["actual_decision"].as_str(), Some("claim_blocked"));
    let signature = row["failure_signature"].as_str().unwrap_or_default();
    for expected in EXPECTED_L3_FAILURE_SIGNATURES {
        assert!(
            signature.contains(expected),
            "L3 overclaim signature should include {expected}: {signature}"
        );
    }

    Ok(())
}

#[test]
fn checker_preserves_l3_roadmap_and_standalone_blockers() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "l3-blockers")?;
    let report =
        read_json(&out_dir.join("l3_full_replace_claim_control_completion_contract.report.json"))?;
    let readiness_report = read_json(&out_dir.join(
        "l3_full_replace_claim_control_completion_contract.standalone_readiness.report.json",
    ))?;
    let readiness_log =
        read_jsonl(&out_dir.join(
            "l3_full_replace_claim_control_completion_contract.standalone_readiness.log.jsonl",
        ))?;

    assert_eq!(readiness_report["status"].as_str(), Some("pass"));
    assert_eq!(readiness_report["proof_row_count"].as_u64(), Some(14));
    assert_eq!(readiness_report["obligation_count"].as_u64(), Some(12));
    assert_eq!(
        report["summary"]["replacement_current_level"].as_str(),
        Some("L1")
    );
    assert_eq!(
        report["summary"]["replacement_current_release_level"].as_str(),
        Some("L1")
    );
    assert_eq!(
        report["summary"]["replacement_l3_status"].as_str(),
        Some("roadmap")
    );
    assert_eq!(
        report["summary"]["replacement_l3_host_glibc_required"].as_bool(),
        Some(false)
    );
    assert_eq!(
        report["summary"]["replacement_l3_blocker_count"].as_u64(),
        Some(5)
    );

    let l3_rows = readiness_log
        .iter()
        .filter(|row| row["replacement_level"].as_str() == Some("L3"))
        .count();
    assert_eq!(l3_rows, 5, "readiness replay should bind all L3 proof rows");
    for row in readiness_log {
        assert_eq!(row["actual_decision"].as_str(), Some("claim_blocked"));
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_required_claim_log_field_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-claim-log-field")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let fields = manifest["completion_debt_evidence"]["required_claim_log_fields"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "claim fields array"))?;
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
        &dossier_report_path(&root),
        &out_dir,
    )?;
    assert!(
        !output.status.success(),
        "checker should reject missing claim log field:\n{}",
        checker_output_message(&output)
    );
    let report =
        read_json(&out_dir.join("l3_full_replace_claim_control_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_report_error_contains(&report, "required_claim_log_fields");
    assert_report_error_contains(&report, "failure_signature");
    Ok(())
}

#[test]
fn checker_rejects_missing_l3_obligation_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-l3-obligation")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let obligations = manifest["completion_debt_evidence"]["required_l3_obligation_ids"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "L3 obligations array"))?;
    obligations.retain(|row| row.as_str() != Some("l3-zero-host-glibc"));
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(
        &root,
        &bad_contract,
        &matrix_path(&root),
        &levels_path(&root),
        &dossier_report_path(&root),
        &out_dir,
    )?;
    assert!(
        !output.status.success(),
        "checker should reject missing L3 obligation:\n{}",
        checker_output_message(&output)
    );
    let report =
        read_json(&out_dir.join("l3_full_replace_claim_control_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_report_error_contains(&report, "required_l3_obligation_ids");
    assert_report_error_contains(&report, "l3-zero-host-glibc");
    Ok(())
}

#[test]
fn checker_rejects_missing_l3_release_claim_signature_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-l3-signature")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let signatures =
        manifest["completion_debt_evidence"]["required_l3_release_claim_failure_signatures"]
            .as_array_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "signatures array"))?;
    signatures.retain(|row| row.as_str() != Some("release_claim_missing_l3_evidence"));
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(
        &root,
        &bad_contract,
        &matrix_path(&root),
        &levels_path(&root),
        &dossier_report_path(&root),
        &out_dir,
    )?;
    assert!(
        !output.status.success(),
        "checker should reject missing L3 failure signature:\n{}",
        checker_output_message(&output)
    );
    let report =
        read_json(&out_dir.join("l3_full_replace_claim_control_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_report_error_contains(&report, "required_l3_release_claim_failure_signatures");
    assert_report_error_contains(&report, "release_claim_missing_l3_evidence");
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
        .retain(|row| row.as_str() != Some("completion_debt_evidence.required_l3_obligation_ids"));
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(
        &root,
        &bad_contract,
        &matrix_path(&root),
        &levels_path(&root),
        &dossier_report_path(&root),
        &out_dir,
    )?;
    assert!(
        !output.status.success(),
        "checker should reject missing fuzz mutation target:\n{}",
        checker_output_message(&output)
    );
    let report =
        read_json(&out_dir.join("l3_full_replace_claim_control_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_report_error_contains(&report, "required_fuzz_mutation_targets");
    assert_report_error_contains(
        &report,
        "completion_debt_evidence.required_l3_obligation_ids",
    );
    Ok(())
}
