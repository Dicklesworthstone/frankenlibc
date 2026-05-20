//! Completion-contract tests for bd-w2c3.3.4 strict/hardened semantic closure.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CONTRACT_REL: &str =
    "tests/conformance/strict_hardened_semantic_closure_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_strict_hardened_semantic_closure_completion_contract.sh";
const EXPECTED_EVENTS: &[&str] = &[
    "strict_hardened_contract_validated",
    "strict_hardened_source_truth_validated",
    "strict_hardened_source_gates_replayed",
    "strict_hardened_completion_summary",
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
        "strict-hardened-semantic-closure-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .current_dir(root)
        .env(
            "FRANKENLIBC_STRICT_HARDENED_SEMANTIC_CLOSURE_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_STRICT_HARDENED_SEMANTIC_CLOSURE_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_STRICT_HARDENED_SEMANTIC_CLOSURE_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_STRICT_HARDENED_SEMANTIC_CLOSURE_LOG",
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
fn manifest_binds_track2_unit_and_e2e_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("strict_hardened_semantic_closure_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-w2c3.3"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-w2c3.3.4")
    );
    assert!(
        manifest["audit"]["next_audit_score_threshold"]
            .as_u64()
            .unwrap_or_default()
            >= 800
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

    let refs = manifest["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "implementation_refs"))?;
    assert!(refs.len() >= 30, "expected concrete source refs");
    for ref_obj in refs {
        assert_file_line_ref_exists(&root, ref_obj)?;
    }

    let mut source_texts = std::collections::BTreeMap::new();
    for source in manifest["test_sources"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test_sources missing"))?
        .values()
    {
        let path = source["path"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test source path"))?;
        let text = std::fs::read_to_string(workspace_relative_path(&root, path)?)?;
        source_texts.insert(path.to_string(), text);
        for test_ref in source["required_test_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required_test_refs"))?
            .iter()
            .filter_map(Value::as_str)
        {
            assert!(
                source_texts
                    .values()
                    .any(|text| function_exists(text, test_ref)),
                "test source should define {test_ref}"
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
fn checker_replays_track2_source_gates_and_emits_report() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "valid")?;
    let output = run_checker(&root, &root.join(CONTRACT_REL), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("strict_hardened_semantic_closure_completion_contract.report.v1")
    );
    assert_eq!(report["source_bead"].as_str(), Some("bd-w2c3.3"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-w2c3.3.4"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["summary"]["mode_semantics_families"].as_u64(),
        Some(20)
    );
    assert_eq!(
        report["summary"]["hardened_matrix_entries"].as_u64(),
        Some(15)
    );
    assert_eq!(
        report["summary"]["strict_hardened_e2e_scenarios"].as_u64(),
        Some(10)
    );
    assert_eq!(
        report["summary"]["runtime_mode_evidence_rows"].as_u64(),
        Some(7)
    );
    assert_eq!(
        report["summary"]["semantic_inventory_entries"].as_u64(),
        Some(19)
    );
    assert_eq!(
        report["source_gate_outputs"]
            .as_object()
            .map(serde_json::Map::len),
        Some(7)
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
            && event["source_bead"].as_str() == Some("bd-w2c3.3")
            && event["completion_debt_bead"].as_str() == Some("bd-w2c3.3.4")
    }));

    Ok(())
}

#[test]
fn checker_rejects_hardened_matrix_count_drift() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    manifest["required_source_truth"]["hardened_repair_deny_matrix"]["entry_count"] =
        Value::from(999_u64);

    let out_dir = unique_output_dir(&root, "matrix-drift")?;
    let contract = out_dir.join("mutated_contract.json");
    write_json(&contract, &manifest)?;
    let output = run_checker(&root, &contract, &out_dir)?;

    assert!(!output.status.success(), "{}", output_text(&output));
    let combined = output_text(&output);
    assert!(
        combined.contains("hardened matrix entry_count drift"),
        "unexpected failure text: {combined}"
    );
    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_validation_command() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    manifest["completion_coverage"][0]["validation_commands"][3] = Value::from(
        "cargo test -p frankenlibc-harness --test strict_hardened_semantic_closure_completion_contract_test",
    );

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
