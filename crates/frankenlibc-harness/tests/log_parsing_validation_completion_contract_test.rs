//! Log parsing validation completion contract tests for bd-2icq.19.1.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CONTRACT_REL: &str = "tests/conformance/log_parsing_validation_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_log_parsing_validation_completion_contract.sh";
const EXPECTED_SCHEMA: &str = "log_parsing_validation_completion_contract.v1";
const EXPECTED_MISSING_ITEMS: &[&str] = &["telemetry.primary", "tests.unit.primary"];
const EXPECTED_EVENTS: &[&str] = &[
    "log_parsing_source_bound",
    "log_parsing_unit_bound",
    "log_parsing_telemetry_bound",
    "log_parsing_completion_summary",
];
const FORBIDDEN_COMMAND_SUBSTRINGS: &[&str] = &["git reset --hard", "git clean -fd", "rm -rf"];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("manifest should have a crates parent"))?;
    let root = crates_dir
        .parent()
        .ok_or_else(|| io::Error::other("manifest should live under the workspace root"))?;
    Ok(root.to_path_buf())
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let mut rows = Vec::new();
    for line in std::fs::read_to_string(path)?.lines() {
        if line.trim().is_empty() {
            continue;
        }
        rows.push(serde_json::from_str(line)?);
    }
    Ok(rows)
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
        "log-parsing-validation-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .current_dir(root)
        .env("FRANKENLIBC_LOG_PARSING_COMPLETION_CONTRACT", contract)
        .env(
            "FRANKENLIBC_LOG_PARSING_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_LOG_PARSING_COMPLETION_LOG",
            out_dir.join("events.jsonl"),
        )
        .output()?)
}

fn string_set(values: &Value) -> TestResult<BTreeSet<String>> {
    let array = values
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string array"))?;
    let mut set = BTreeSet::new();
    for value in array {
        set.insert(
            value
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string"))?
                .to_string(),
        );
    }
    Ok(set)
}

fn assert_file_line_ref_exists(root: &Path, file_line_ref: &Value) -> TestResult {
    let path = file_line_ref["path"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref path missing"))?;
    let line = file_line_ref["line"]
        .as_u64()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref line missing"))?;
    let anchor = file_line_ref["anchor"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref anchor missing"))?;
    assert!(line > 0, "line must be positive for {path}");
    let full_path = root.join(path);
    assert!(full_path.is_file(), "ref path should exist: {path}");
    let text = std::fs::read_to_string(&full_path)?;
    let lines: Vec<_> = text.lines().collect();
    assert!(
        (line as usize) <= lines.len(),
        "ref line outside file: {path}:{line}"
    );
    assert!(
        lines[(line - 1) as usize].contains(anchor),
        "{path}:{line} should contain anchor {anchor}"
    );
    assert!(text.contains(anchor), "{path} missing anchor {anchor}");
    Ok(())
}

#[test]
fn manifest_binds_unit_and_telemetry_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;

    assert_eq!(manifest["schema_version"].as_str(), Some(EXPECTED_SCHEMA));
    assert_eq!(manifest["bead"].as_str(), Some("bd-2icq.19"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-2icq.19.1")
    );

    let audit_items = string_set(&manifest["audit"]["missing_items"])?;
    assert_eq!(
        audit_items,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );

    let source_paths = manifest["source_paths"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source_paths missing"))?;
    for path in source_paths.values() {
        let rel = path.as_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "source path must be string")
        })?;
        assert!(root.join(rel).exists(), "source path should exist: {rel}");
    }

    let refs = manifest["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "implementation_refs missing"))?;
    assert!(
        refs.len() >= 15,
        "expected concrete parser, validator, stats, test, and completion refs"
    );
    for item in refs {
        assert_file_line_ref_exists(&root, item)?;
    }

    let coverage = manifest["completion_coverage"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "completion_coverage missing"))?;
    let covered_items = coverage
        .iter()
        .map(|section| {
            section["missing_item_id"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        covered_items,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );

    for section in coverage {
        assert_eq!(section["status"].as_str(), Some("covered"));
        assert!(
            section["implementation_refs"]
                .as_array()
                .is_some_and(|refs| !refs.is_empty()),
            "coverage section should cite implementation refs"
        );
        assert!(
            section["test_refs"]
                .as_array()
                .is_some_and(|refs| !refs.is_empty()),
            "coverage section should cite test refs"
        );
        for command in section["validation_commands"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "commands missing"))?
        {
            let command = command.as_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "command must be string")
            })?;
            for forbidden in FORBIDDEN_COMMAND_SUBSTRINGS {
                assert!(
                    !command.contains(forbidden),
                    "validation command must not contain {forbidden}: {command}"
                );
            }
            if command.contains("cargo ") {
                assert!(
                    command.contains("rch exec --"),
                    "cargo validation command must use rch: {command}"
                );
            }
        }
    }

    let telemetry = &manifest["telemetry_contract"];
    let required_events = string_set(&telemetry["required_events"])?;
    assert_eq!(
        required_events,
        EXPECTED_EVENTS
            .iter()
            .map(|event| (*event).to_string())
            .collect()
    );
    assert_eq!(
        telemetry["expected_summary"]["total_entries"].as_u64(),
        Some(3)
    );
    Ok(())
}

#[test]
fn checker_emits_structured_unit_and_telemetry_evidence() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &root.join(CONTRACT_REL), &out_dir)?;
    assert!(
        output.status.success(),
        "checker should pass\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = read_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("log_parsing_validation_completion_report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead"].as_str(), Some("bd-2icq.19"));
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-2icq.19.1")
    );

    let unit_tests = report["unit_test_inventory"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unit inventory missing"))?;
    assert!(
        unit_tests.len() >= 5,
        "expected runtime, hook, malformed, non-strict, and stats unit tests"
    );

    let summary = &report["telemetry_summary"];
    assert_eq!(summary["total_entries"].as_u64(), Some(3));
    assert_eq!(summary["runtime_entries"].as_u64(), Some(2));
    assert_eq!(summary["hook_entries"].as_u64(), Some(1));
    assert_eq!(summary["parser_error_count"].as_u64(), Some(1));
    assert_eq!(summary["validation_issue_count"].as_u64(), Some(0));
    assert_eq!(summary["by_call"]["malloc"].as_u64(), Some(1));
    assert_eq!(summary["by_call"]["free"].as_u64(), Some(1));
    assert_eq!(summary["by_call"]["__hook_event__"].as_u64(), Some(1));
    assert_eq!(summary["by_action"]["ClampSize"].as_u64(), Some(1));
    assert_eq!(summary["by_action"]["hook_enable"].as_u64(), Some(1));

    let rows = read_jsonl(&out_dir.join("events.jsonl"))?;
    let events = rows
        .iter()
        .map(|row| row["event"].as_str().unwrap_or_default().to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        events,
        EXPECTED_EVENTS
            .iter()
            .map(|event| (*event).to_string())
            .collect()
    );
    for (index, line) in std::fs::read_to_string(out_dir.join("events.jsonl"))?
        .lines()
        .enumerate()
    {
        let row = validate_log_line(line, index + 1)
            .map_err(|errors| io::Error::other(format!("structured log errors: {errors:?}")))?;
        assert_eq!(row.bead_id.as_deref(), Some("bd-2icq.19.1"));
        assert_eq!(
            row.gate.as_deref(),
            Some("log_parsing_validation_completion_contract")
        );
        assert_eq!(row.failure_signature.as_deref(), Some("none"));
        assert!(
            row.artifact_refs
                .as_ref()
                .is_some_and(|refs| refs.len() >= 3),
            "structured completion rows should cite contract, report, and log artifacts"
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_test_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    let coverage = manifest["completion_coverage"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "coverage missing"))?;
    let unit_section = coverage
        .iter_mut()
        .find(|section| section["missing_item_id"].as_str() == Some("tests.unit.primary"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unit section missing"))?;
    unit_section["test_refs"] = Value::Array(Vec::new());

    let out_dir = unique_output_dir(&root, "missing-unit")?;
    let broken_contract = out_dir.join("missing-unit-contract.json");
    write_json(&broken_contract, &manifest)?;
    let output = run_checker(&root, &broken_contract, &out_dir)?;

    assert!(
        !output.status.success(),
        "checker should fail when unit test refs are removed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("test_refs"),
        "stderr should explain missing test refs\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
