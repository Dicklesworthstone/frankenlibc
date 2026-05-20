//! Contract tests for bd-w2c3.2.4 replacement-surface completion evidence.

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
    ("integration_primary", "tests.integration.primary"),
    ("e2e_primary", "tests.e2e.primary"),
    ("migrations_primary", "migrations.primary"),
];

const EXPECTED_EVENTS: &[&str] = &[
    "replacement_surface_completion_contract_validated",
    "replacement_surface_summary",
    "replacement_levels_gate_replayed",
    "callthrough_census_gate_replayed",
    "residual_callthrough_gate_replayed",
];

const EXPECTED_FIELDS: &[&str] = &[
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
    "surface_summary",
    "replacement_levels_report",
    "callthrough_census_report",
    "residual_callthrough_report",
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
    root.join("tests/conformance/replacement_surface_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_replacement_surface_completion_contract.sh")
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
        "replacement-surface-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_REPLACEMENT_SURFACE_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_REPLACEMENT_SURFACE_COMPLETION_REPORT",
            out_dir.join("replacement_surface_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_REPLACEMENT_SURFACE_COMPLETION_LOG",
            out_dir.join("replacement_surface_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_REPLACEMENT_SURFACE_COMPLETION_LEVELS_REPORT",
            out_dir.join("replacement_surface_completion_contract.replacement_levels.report.json"),
        )
        .env(
            "FRANKENLIBC_REPLACEMENT_SURFACE_COMPLETION_LEVELS_LOG",
            out_dir.join("replacement_surface_completion_contract.replacement_levels.log.jsonl"),
        )
        .output()?)
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
    let output = run_checker(root, &contract_path(root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker should pass:\n{}",
        checker_output_message(&output)
    );
    Ok(out_dir)
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

#[test]
fn manifest_binds_unit_integration_e2e_and_migration_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    let support = read_json(&root.join("support_matrix.json"))?;
    let levels = read_json(&root.join("tests/conformance/replacement_levels.json"))?;
    let census = read_json(&root.join("tests/conformance/callthrough_census.v1.json"))?;
    let residual = read_json(
        &root.join("tests/conformance/residual_replacement_callthrough_blockers.v1.json"),
    )?;

    assert_eq!(manifest["bead"].as_str(), Some("bd-w2c3.2"));
    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(evidence["bead"].as_str(), Some("bd-w2c3.2.4"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-w2c3.2"));

    let refs = evidence["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "implementation_refs array"))?;
    assert!(
        refs.len() >= 30,
        "completion evidence should cite concrete source lines"
    );
    for file_line in refs {
        assert_file_line_ref_exists(
            &root,
            file_line
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "file line string"))?,
        )?;
    }

    let sources = source_texts(&root, &manifest)?;
    for (section_name, missing_item) in EXPECTED_MISSING_ITEMS {
        let section = &evidence[*section_name];
        assert_eq!(
            section["missing_item_id"].as_str(),
            Some(*missing_item),
            "{section_name} must bind the expected missing item"
        );
        assert_test_refs_exist(section_name, section, &sources)?;
        let commands = section["required_commands"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "commands array"))?;
        assert!(!commands.is_empty(), "{section_name} should name commands");
        for command in commands {
            let command = command
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "command string"))?;
            assert!(
                !command.contains("cargo ") || command.contains("rch exec --"),
                "{section_name} cargo commands must be routed through rch: {command}"
            );
        }
    }

    let truth = &evidence["required_surface_truth"];
    assert_eq!(truth["current_level"].as_str(), Some("L1"));
    assert_eq!(truth["current_release_level"].as_str(), Some("L1"));
    assert_eq!(
        levels["current_level"].as_str(),
        truth["current_level"].as_str()
    );
    assert_eq!(
        levels["release_tag_policy"]["current_release_level"].as_str(),
        truth["current_release_level"].as_str()
    );
    assert_eq!(
        census["source"]["derived_callthrough_symbols"].as_u64(),
        Some(0)
    );
    assert_eq!(census["summary"]["symbol_count"].as_u64(), Some(0));
    assert_eq!(
        residual["current_truth"]["residual_forbidden_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        residual["current_truth"]["claim_status"].as_str(),
        Some("replacement_callthrough_blockers_cleared")
    );

    let mut counts = BTreeMap::<String, usize>::new();
    for symbol in support["symbols"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "support symbols"))?
    {
        let status = symbol["status"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "status string"))?;
        *counts.entry(status.to_string()).or_default() += 1;
    }
    assert_eq!(counts.get("WrapsHostLibc").copied().unwrap_or(0), 0);
    assert_eq!(counts.get("GlibcCallThrough").copied().unwrap_or(0), 0);
    assert!(
        support["taxonomy"]["artifact_applicability"]["rule"]
            .as_str()
            .unwrap_or_default()
            .contains("Interpose-only"),
        "support taxonomy must retain artifact applicability split"
    );

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "report")?;
    let report = read_json(&out_dir.join("replacement_surface_completion_contract.report.json"))?;
    let log = read_jsonl(&out_dir.join("replacement_surface_completion_contract.log.jsonl"))?;

    assert_eq!(
        report["schema_version"].as_str(),
        Some("replacement_surface_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-w2c3.2.4"));
    assert_eq!(
        string_set(&report["missing_items_bound"])?,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|(_, item)| item.to_string())
            .collect()
    );
    assert!(
        report["test_refs"].as_array().map_or(0, Vec::len) >= 15,
        "report should carry referenced tests"
    );
    assert_eq!(
        report["surface_summary"]["replacement_levels"]["current_level"].as_str(),
        Some("L1")
    );
    assert_eq!(
        report["surface_summary"]["callthrough_census"]["summary"]["symbol_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        report["surface_summary"]["residual_callthrough"]["summary"]["residual_forbidden_count"]
            .as_u64(),
        Some(0)
    );

    let events: BTreeSet<_> = log
        .iter()
        .filter_map(|row| row["event"].as_str())
        .map(str::to_string)
        .collect();
    for expected in EXPECTED_EVENTS {
        assert!(
            events.contains(*expected),
            "completion log missing event {expected}: {events:?}"
        );
    }
    for row in &log {
        for field in EXPECTED_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing field {field}");
        }
        assert_eq!(row["status"].as_str(), Some("pass"));
        assert_eq!(row["completion_debt_bead"].as_str(), Some("bd-w2c3.2.4"));
    }
    Ok(())
}

#[test]
fn checker_replays_replacement_gates_and_preserves_l1_claim_control() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "gates")?;
    let report = read_json(&out_dir.join("replacement_surface_completion_contract.report.json"))?;
    let levels_report = read_json(
        &out_dir.join("replacement_surface_completion_contract.replacement_levels.report.json"),
    )?;
    let callthrough_report =
        read_json(&root.join("target/conformance/callthrough_census.report.json"))?;
    let residual_report = read_json(
        &root.join("target/conformance/residual_replacement_callthrough_blockers.report.json"),
    )?;

    assert_eq!(levels_report["status"].as_str(), Some("pass"));
    assert_eq!(levels_report["current_level"].as_str(), Some("L1"));
    assert_eq!(
        levels_report["summary"]["objective_outcomes"]["pass"].as_u64(),
        Some(8),
        "L1 objective gate should report all current obligations passing"
    );
    assert_eq!(
        levels_report["summary"]["objective_outcomes"]["blocked"]
            .as_u64()
            .unwrap_or_default(),
        0,
        "L1 objective blockers should be cleared in current L1 state"
    );
    assert_eq!(
        callthrough_report["summary"]["symbol_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        residual_report["summary"]["replacement_total_call_throughs"].as_u64(),
        Some(0)
    );
    assert_eq!(
        residual_report["summary"]["interpose_total_call_throughs"].as_u64(),
        Some(0)
    );
    assert_eq!(
        report["surface_summary"]["support"]["status_counts"]["Implemented"].as_u64(),
        Some(3705)
    );
    assert_eq!(
        report["surface_summary"]["support"]["status_counts"]["RawSyscall"].as_u64(),
        Some(414)
    );
    Ok(())
}

#[test]
fn checker_rejects_bare_cargo_required_command() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_commands"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "commands array"))?
        .push(Value::String(
            "cargo test -p frankenlibc-harness --test replacement_surface_completion_contract_test"
                .to_string(),
        ));
    let out_dir = unique_output_dir(&root, "bare-cargo")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject bare cargo command"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("contract_validation_failed")
            || String::from_utf8_lossy(&output.stdout).contains("contract_validation_failed"),
        "checker should report contract validation failure:\n{}",
        checker_output_message(&output)
    );
    let failure_report =
        read_json(&out_dir.join("replacement_surface_completion_contract.report.json"))?;
    assert_eq!(failure_report["status"].as_str(), Some("fail"));
    assert_eq!(
        failure_report["failure_signature"].as_str(),
        Some("contract_validation_failed")
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_required_event_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    let events = manifest["completion_debt_evidence"]["telemetry"]["required_events"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "events array"))?;
    events.retain(|event| event.as_str() != Some("replacement_levels_gate_replayed"));
    let out_dir = unique_output_dir(&root, "missing-event")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing telemetry event binding"
    );
    assert!(
        checker_output_message(&output).contains("contract_validation_failed"),
        "checker should report contract validation failure:\n{}",
        checker_output_message(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_stale_file_line_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["implementation_refs"][0] =
        Value::String("support_matrix.json:999999".to_string());
    let out_dir = unique_output_dir(&root, "stale-ref")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject stale file-line binding"
    );
    assert!(
        checker_output_message(&output).contains("contract_validation_failed"),
        "checker should report contract validation failure:\n{}",
        checker_output_message(&output)
    );
    Ok(())
}
