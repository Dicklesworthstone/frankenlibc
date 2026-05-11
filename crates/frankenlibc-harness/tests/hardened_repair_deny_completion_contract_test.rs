//! Completion-contract tests for bd-w2c3.3.2.1 hardened repair/deny evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CONTRACT_REL: &str = "tests/conformance/hardened_repair_deny_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_hardened_repair_deny_completion_contract.sh";
const EXPECTED_EVENTS: &[&str] = &[
    "hardened_repair_deny_contract_validated",
    "hardened_repair_deny_matrix_validated",
    "hardened_repair_deny_gate_replayed",
    "hardened_repair_deny_completion_summary",
];
const EXPECTED_MISSING_ITEMS: &[&str] = &["tests.unit.primary", "tests.e2e.primary"];

static CHECKER_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn checker_lock() -> MutexGuard<'static, ()> {
    CHECKER_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("manifest should have a crates parent"))?;
    let root = crates_dir
        .parent()
        .ok_or_else(|| io::Error::other("manifest should live under workspace root"))?;
    Ok(root.to_path_buf())
}

fn workspace_relative_path(root: &Path, path: &str) -> TestResult<PathBuf> {
    let relative = Path::new(path);
    let has_escape = relative.is_absolute()
        || relative
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::Prefix(_)));
    if has_escape {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("path must stay under workspace root: {path}"),
        )
        .into());
    }
    Ok(root.join(relative))
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = root.join("target/conformance").join(format!(
        "hardened-repair-deny-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .current_dir(root)
        .env("FRANKENLIBC_HARDENED_REPAIR_DENY_CONTRACT", contract)
        .env("FRANKENLIBC_HARDENED_REPAIR_DENY_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_HARDENED_REPAIR_DENY_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_HARDENED_REPAIR_DENY_LOG",
            out_dir.join("events.jsonl"),
        )
        .output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
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

fn assert_file_line_ref_exists(root: &Path, ref_obj: &Value) -> TestResult {
    let path = ref_obj["path"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref path missing"))?;
    let line = ref_obj["line"]
        .as_u64()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref line missing"))?;
    let anchor = ref_obj["anchor"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref anchor missing"))?;
    assert!(line > 0, "line must be positive for {path}");
    let full_path = workspace_relative_path(root, path)?;
    assert!(full_path.is_file(), "ref path should be a file: {path}");
    let text = std::fs::read_to_string(&full_path)?;
    let lines: Vec<_> = text.lines().collect();
    assert!(
        (line as usize) <= lines.len() && !lines[line as usize - 1].trim().is_empty(),
        "ref line outside file or blank: {path}:{line}"
    );
    assert!(text.contains(anchor), "{path} missing anchor {anchor}");
    Ok(())
}

fn function_exists(source_text: &str, name: &str) -> bool {
    source_text.contains(&format!("fn {name}")) || source_text.contains(&format!("def {name}"))
}

#[test]
fn manifest_binds_hardened_repair_deny_unit_and_e2e_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("hardened_repair_deny_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-w2c3.3.2"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-w2c3.3.2.1")
    );

    let missing = string_set(&manifest["audit"]["missing_items"])?;
    assert_eq!(
        missing,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source_artifacts missing"))?;
    for path in source_artifacts.values() {
        let rel = path.as_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "source path must be string")
        })?;
        assert!(
            workspace_relative_path(&root, rel)?.is_file(),
            "source artifact should exist: {rel}"
        );
    }

    let matrix_truth = &manifest["required_source_truth"]["matrix"];
    assert_eq!(matrix_truth["entry_count"].as_u64(), Some(15));
    assert_eq!(matrix_truth["repair_entries"].as_u64(), Some(9));
    assert_eq!(matrix_truth["deny_entries"].as_u64(), Some(6));
    let decisions = string_set(&matrix_truth["required_decisions"])?;
    assert_eq!(
        decisions,
        ["Deny", "Repair"].into_iter().map(String::from).collect()
    );

    let refs = manifest["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "implementation_refs"))?;
    assert!(refs.len() >= 12, "expected concrete source refs");
    for ref_obj in refs {
        assert_file_line_ref_exists(&root, ref_obj)?;
    }

    for source in manifest["test_sources"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test_sources missing"))?
        .values()
    {
        let path = source["path"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test source path"))?;
        let text = std::fs::read_to_string(workspace_relative_path(&root, path)?)?;
        for test_ref in source["required_test_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required_test_refs"))?
            .iter()
            .filter_map(Value::as_str)
        {
            assert!(
                function_exists(&text, test_ref),
                "test source {path} should define {test_ref}"
            );
        }
    }

    let coverage = manifest["completion_coverage"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "completion_coverage"))?;
    let covered = coverage
        .iter()
        .map(|section| {
            section["missing_item_id"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(covered, missing);
    for section in coverage {
        assert_eq!(section["status"].as_str(), Some("covered"));
        assert!(
            section["test_refs"]
                .as_array()
                .is_some_and(|refs| !refs.is_empty()),
            "coverage section should cite tests"
        );
        for command in section["validation_commands"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "validation commands"))?
            .iter()
            .filter_map(Value::as_str)
        {
            if command.contains("cargo ") {
                assert!(
                    command.starts_with("rch exec -- "),
                    "cargo validation must use rch: {command}"
                );
            }
        }
    }

    Ok(())
}

#[test]
fn checker_validates_matrix_and_emits_report_log() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "valid")?;
    let output = run_checker(&root, &root.join(CONTRACT_REL), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("hardened_repair_deny_completion_contract.report.v1")
    );
    assert_eq!(report["source_bead"].as_str(), Some("bd-w2c3.3.2"));
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-w2c3.3.2.1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["entry_count"].as_u64(), Some(15));
    assert_eq!(report["summary"]["repair_entries"].as_u64(), Some(9));
    assert_eq!(report["summary"]["deny_entries"].as_u64(), Some(6));
    assert!(
        report["summary"]["policy_mapping_sha256"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64),
        "policy hash should be a 64-char digest"
    );

    let events = read_jsonl(&out_dir.join("events.jsonl"))?;
    assert_eq!(events.len(), EXPECTED_EVENTS.len());
    let event_names = events
        .iter()
        .filter_map(|event| event["event"].as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        event_names,
        EXPECTED_EVENTS.iter().copied().collect::<BTreeSet<_>>()
    );
    assert!(events.iter().all(|event| {
        event["status"].as_str() == Some("pass")
            && event["source_bead"].as_str() == Some("bd-w2c3.3.2")
            && event["completion_debt_bead"].as_str() == Some("bd-w2c3.3.2.1")
    }));

    Ok(())
}

#[test]
fn checker_rejects_matrix_count_drift() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    manifest["required_source_truth"]["matrix"]["entry_count"] = Value::from(999);

    let out_dir = unique_output_dir(&root, "count-drift")?;
    let contract = out_dir.join("mutated_contract.json");
    write_json(&contract, &manifest)?;
    let output = run_checker(&root, &contract, &out_dir)?;

    assert!(!output.status.success(), "{}", output_text(&output));
    let combined = output_text(&output);
    assert!(
        combined.contains("matrix summary entry_count drift"),
        "unexpected failure text: {combined}"
    );
    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_validation_command() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    manifest["completion_coverage"][0]["validation_commands"][3] =
        Value::from("cargo test -p frankenlibc-harness --test hardened_repair_deny_matrix_test");

    let out_dir = unique_output_dir(&root, "bare-cargo")?;
    let contract = out_dir.join("mutated_contract.json");
    write_json(&contract, &manifest)?;
    let output = run_checker(&root, &contract, &out_dir)?;

    assert!(!output.status.success(), "{}", output_text(&output));
    let combined = output_text(&output);
    assert!(
        combined.contains("cargo validation command must use rch"),
        "unexpected failure text: {combined}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_required_telemetry_event() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    let events = manifest["telemetry_contract"]["required_events"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required_events"))?;
    events.retain(|event| event.as_str() != Some("hardened_repair_deny_completion_summary"));

    let out_dir = unique_output_dir(&root, "event-drift")?;
    let contract = out_dir.join("mutated_contract.json");
    write_json(&contract, &manifest)?;
    let output = run_checker(&root, &contract, &out_dir)?;

    assert!(!output.status.success(), "{}", output_text(&output));
    let combined = output_text(&output);
    assert!(
        combined.contains("telemetry_contract.required_events mismatch"),
        "unexpected failure text: {combined}"
    );
    Ok(())
}
