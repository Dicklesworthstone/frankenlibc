//! Contract tests for bd-id3.1 verification matrix completion evidence.

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
    ("telemetry_primary", "telemetry.primary"),
];

const EXPECTED_PASS_EVENTS: &[&str] = &[
    "verification_matrix_completion_contract_validated",
    "verification_matrix_summary",
    "verification_matrix_gate_replayed",
    "verification_matrix_dashboard_validated",
    "verification_matrix_rows_validated",
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
    "matrix_summary",
    "verification_gate_transcript",
    "artifact_refs",
    "failure_signature",
];

const EXPECTED_FUZZ_TARGETS: &[&str] = &[
    "completion_debt_evidence.required_top_level_keys",
    "completion_debt_evidence.required_row_template_fields",
    "completion_debt_evidence.required_stream_examples",
    "completion_debt_evidence.telemetry_primary.required_fields",
    "verification_matrix.dashboard.by_stream",
    "verification_matrix.entries.row.artifact_paths",
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
    root.join("tests/conformance/verification_matrix_completion_contract.v1.json")
}

fn matrix_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/verification_matrix.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_verification_matrix_completion_contract.sh")
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
        "verification-matrix-completion-{label}-{}-{nanos}",
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
            "FRANKENLIBC_VERIFICATION_MATRIX_COMPLETION_CONTRACT",
            contract,
        )
        .env("FRANKENLIBC_VERIFICATION_MATRIX_COMPLETION_MATRIX", matrix)
        .env(
            "FRANKENLIBC_VERIFICATION_MATRIX_COMPLETION_REPORT",
            out_dir.join("verification_matrix_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_VERIFICATION_MATRIX_COMPLETION_LOG",
            out_dir.join("verification_matrix_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_VERIFICATION_MATRIX_COMPLETION_GATE_TRANSCRIPT",
            out_dir.join("verification_matrix_completion_contract.gate.txt"),
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
    let full_path = root.join(path);
    assert!(
        line_no > 0 && full_path.is_file(),
        "file-line ref should exist: {file_line_ref}"
    );
    let contents = std::fs::read_to_string(full_path)?;
    let lines: Vec<_> = contents.lines().collect();
    assert!(
        line_no <= lines.len() && !lines[line_no - 1].trim().is_empty(),
        "file-line ref should point at a non-empty line: {file_line_ref}"
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
fn manifest_binds_unit_e2e_and_telemetry_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    let matrix = read_json(&matrix_path(&root))?;
    let evidence = &manifest["completion_debt_evidence"];

    assert_eq!(manifest["bead"].as_str(), Some("bd-id3"));
    assert_eq!(evidence["bead"].as_str(), Some("bd-id3.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-id3"));
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

    let schema = &matrix["schema"];
    let row_template_keys: BTreeSet<_> = schema["row_template"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "row_template object"))?
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        string_set(&evidence["required_row_template_fields"])?,
        row_template_keys
    );

    let streams: BTreeSet<_> = schema["stream_examples"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stream_examples array"))?
        .iter()
        .filter_map(|row| row["stream"].as_str().map(ToOwned::to_owned))
        .collect();
    assert_eq!(
        string_set(&evidence["required_stream_examples"])?,
        streams,
        "completion manifest should bind every stream example"
    );

    let expectations = &evidence["minimum_expectations"];
    assert_eq!(expectations["matrix_version"], matrix["matrix_version"]);
    let matrix_entries = matrix["entries"].as_array().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "matrix entries should be an array",
        )
    })?;
    let matrix_entry_count = u64::try_from(matrix_entries.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "matrix entry count should fit in u64",
        )
    })?;
    assert_eq!(
        expectations["entry_count"].as_u64(),
        Some(matrix_entry_count)
    );
    assert_eq!(
        expectations["total_critique_beads"].as_u64(),
        matrix["dashboard"]["total_critique_beads"].as_u64()
    );

    let sources = source_texts(&root, &manifest)?;
    for (section, missing_item) in EXPECTED_MISSING_ITEMS {
        let section_value = &evidence[*section];
        assert_eq!(
            section_value["missing_item_id"].as_str(),
            Some(*missing_item)
        );
        assert_test_refs_exist(section, section_value, &sources)?;
        for command in section_value["required_commands"]
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
    for expected in EXPECTED_FUZZ_TARGETS {
        assert!(
            fuzz_targets.contains(*expected),
            "fuzz primary should mutate {expected}"
        );
    }
    let telemetry_events = string_set(&evidence["telemetry_primary"]["required_events"])?;
    for expected in EXPECTED_PASS_EVENTS {
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
    let report_path = out_dir.join("verification_matrix_completion_contract.report.json");
    let log_path = out_dir.join("verification_matrix_completion_contract.log.jsonl");
    let report = read_json(&report_path)?;
    let events = read_jsonl(&log_path)?;

    assert_eq!(
        report["schema_version"].as_str(),
        Some("verification_matrix_completion_contract.report.v1")
    );
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-id3.1"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["entry_count"].as_u64(), Some(119));
    assert_eq!(
        report["summary"]["verification_gate_status"].as_str(),
        Some("pass")
    );

    let emitted: BTreeSet<_> = events
        .iter()
        .filter_map(|event| event["event"].as_str())
        .collect();
    for expected in EXPECTED_PASS_EVENTS {
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
fn checker_replays_verification_matrix_gate() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "gate-replay")?;
    let transcript =
        std::fs::read_to_string(out_dir.join("verification_matrix_completion_contract.gate.txt"))?;
    assert!(transcript.contains("PASS: Matrix file exists and parses as valid JSON"));
    assert!(transcript.contains("PASS: Schema structure is valid"));
    assert!(
        transcript.contains("PASS: All open/in_progress critique beads have verification rows")
    );
    assert!(transcript.contains("check_verification_matrix: PASS"));
    Ok(())
}

#[test]
fn checker_validates_dashboard_and_rows() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "dashboard-rows")?;
    let report = read_json(&out_dir.join("verification_matrix_completion_contract.report.json"))?;
    let summary = &report["summary"];

    assert_eq!(summary["entry_count"].as_u64(), Some(119));
    assert_eq!(summary["total_critique_beads"].as_u64(), Some(119));
    assert_eq!(summary["by_coverage_status"]["complete"].as_u64(), Some(42));
    assert_eq!(summary["by_coverage_status"]["partial"].as_u64(), Some(1));
    assert_eq!(summary["by_coverage_status"]["missing"].as_u64(), Some(76));
    assert_eq!(summary["unit_required"].as_u64(), Some(119));
    assert_eq!(summary["e2e_required"].as_u64(), Some(59));
    assert_eq!(summary["structured_logs_required"].as_u64(), Some(116));
    assert_eq!(summary["row_contract_errors"].as_u64(), Some(0));
    Ok(())
}

#[test]
fn checker_rejects_missing_row_template_field_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-row-template-field")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let fields = manifest["completion_debt_evidence"]["required_row_template_fields"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "row fields array"))?;
    fields.retain(|row| row.as_str() != Some("artifact_paths"));
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &matrix_path(&root), &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing row template field:\n{}",
        checker_output_message(&output)
    );
    let report = read_json(&out_dir.join("verification_matrix_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|error| error
                .as_str()
                .is_some_and(|text| text.contains("row_template fields"))),
        "failure report should explain row_template field drift"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_field_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-telemetry-field")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let fields = manifest["completion_debt_evidence"]["telemetry_primary"]["required_fields"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "telemetry fields array"))?;
    fields.retain(|row| !matches!(row.as_str(), Some("failure_signature")));
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &matrix_path(&root), &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing telemetry field:\n{}",
        checker_output_message(&output)
    );
    let report = read_json(&out_dir.join("verification_matrix_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|error| error
                .as_str()
                .is_some_and(|text| text.contains("telemetry_primary.required_fields"))),
        "failure report should explain missing telemetry field"
    );
    Ok(())
}
