//! Completion-contract tests for bd-w2c3.5.2.1 cohomology/cross-family evidence.

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
    "tests/conformance/runtime_math_cohomology_cross_family_completion_contract.v1.json";
const CHECKER_REL: &str =
    "scripts/check_runtime_math_cohomology_cross_family_completion_contract.sh";
const EXPECTED_EVENTS: &[&str] = &[
    "runtime_math_cohomology_completion_contract_validated",
    "runtime_math_cohomology_source_gate_bound",
    "runtime_math_cohomology_unit_e2e_bound",
    "runtime_math_cohomology_completion_summary",
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
        "runtime-math-cohomology-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .current_dir(root)
        .env("FRANKENLIBC_RUNTIME_MATH_COHOMOLOGY_CONTRACT", contract)
        .env("FRANKENLIBC_RUNTIME_MATH_COHOMOLOGY_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_RUNTIME_MATH_COHOMOLOGY_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_RUNTIME_MATH_COHOMOLOGY_LOG",
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
    source_text.contains(&format!("fn {name}("))
        || source_text.contains(&format!("fn {name}<"))
        || source_text.contains(&format!("def {name}("))
}

#[test]
fn manifest_binds_cohomology_unit_and_e2e_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("runtime_math_cohomology_cross_family_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-w2c3.5.2"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-w2c3.5.2.1")
    );
    assert!(
        manifest["audit"]["next_audit_score_threshold"]
            .as_u64()
            .unwrap_or(0)
            >= 800
    );
    assert_eq!(
        string_set(&manifest["audit"]["missing_items"])?,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );

    for path in manifest["source_artifacts"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source_artifacts object"))?
        .values()
        .filter_map(Value::as_str)
    {
        assert!(
            workspace_relative_path(&root, path)?.is_file(),
            "source artifact should exist: {path}"
        );
    }

    let checker_truth = &manifest["required_source_truth"]["source_checker"];
    for case_id in [
        "strict_consistency",
        "strict_replay_corruption",
        "hardened_consistency",
        "hardened_replay_corruption",
    ] {
        assert!(
            checker_truth["required_case_ids"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|value| value.as_str() == Some(case_id)),
            "manifest should bind source checker case {case_id}"
        );
    }
    assert_eq!(
        checker_truth["expected_thresholds"]["strict_failures_max"].as_u64(),
        Some(0)
    );
    assert_eq!(
        checker_truth["expected_thresholds"]["hardened_failures_max"].as_u64(),
        Some(0)
    );

    let sheaf_truth = &manifest["required_source_truth"]["sheaf_artifact"];
    assert_eq!(sheaf_truth["bead"].as_str(), Some("bd-249m.7"));
    assert_eq!(sheaf_truth["h1_zero"].as_bool(), Some(true));
    assert_eq!(
        sheaf_truth["required_cover_ids"].as_array().map(Vec::len),
        Some(7)
    );

    let refs = manifest["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "implementation_refs array"))?;
    assert!(refs.len() >= 16, "expected concrete implementation refs");
    for ref_obj in refs {
        assert_file_line_ref_exists(&root, ref_obj)?;
    }

    for source in manifest["test_sources"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test_sources object"))?
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
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "completion_coverage array"))?;
    let covered = coverage
        .iter()
        .map(|section| section["missing_item_id"].as_str().unwrap_or_default())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        covered,
        EXPECTED_MISSING_ITEMS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
    );
    for section in coverage {
        assert_eq!(section["status"].as_str(), Some("covered"));
        for command in section["validation_commands"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "validation commands"))?
            .iter()
            .filter_map(Value::as_str)
        {
            if command.contains("cargo ") {
                assert!(
                    command.starts_with("rch exec -- ") || command.starts_with("rch cargo "),
                    "cargo validation must use rch: {command}"
                );
            }
        }
    }

    Ok(())
}

#[test]
fn checker_emits_report_log_and_validates_source_gate() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "valid")?;
    let output = run_checker(&root, &root.join(CONTRACT_REL), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("runtime_math_cohomology_cross_family_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-w2c3.5.2"));
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-w2c3.5.2.1")
    );
    assert_eq!(report["summary"]["error_count"].as_u64(), Some(0));
    assert!(
        report["summary"]["test_ref_count"].as_u64().unwrap_or(0) >= 15,
        "completion contract should bind source and completion tests"
    );
    assert_eq!(report["source_summary"]["case_count"].as_u64(), Some(4));
    assert_eq!(
        report["source_summary"]["runtime_policy_test_count"].as_u64(),
        Some(5)
    );
    assert_eq!(
        report["source_summary"]["cohomology_unit_count"].as_u64(),
        Some(4)
    );
    assert_eq!(
        report["source_summary"]["open_cover_count"].as_u64(),
        Some(7)
    );

    let rows = read_jsonl(&out_dir.join("events.jsonl"))?;
    assert_eq!(rows.len(), EXPECTED_EVENTS.len());
    let seen = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(seen, EXPECTED_EVENTS.iter().copied().collect());
    for row in &rows {
        for field in [
            "timestamp",
            "trace_id",
            "level",
            "event",
            "bead_id",
            "original_bead",
            "completion_debt_bead",
            "mode",
            "api_family",
            "symbol",
            "decision_path",
            "healing_action",
            "errno",
            "latency_ns",
            "artifact_refs",
            "status",
            "failure_signature",
        ] {
            assert!(row.get(field).is_some(), "log row missing {field}");
        }
        assert_eq!(row["api_family"].as_str(), Some("runtime_math"));
        assert_eq!(row["status"].as_str(), Some("pass"));
    }
    let (line_count, errors) =
        frankenlibc_harness::structured_log::validate_log_file(&out_dir.join("events.jsonl"))?;
    assert_eq!(line_count, rows.len());
    assert!(
        errors.is_empty(),
        "completion log should satisfy structured log validator: {errors:#?}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_case_id() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-case")?;
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    let cases = manifest["required_source_truth"]["source_checker"]["required_case_ids"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required_case_ids array"))?;
    cases.retain(|value| value.as_str() != Some("hardened_replay_corruption"));

    let tampered = out_dir.join("tampered_contract.json");
    write_json(&tampered, &manifest)?;
    let output = run_checker(&root, &tampered, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail without all source checker cases"
    );
    assert!(
        output_text(&output).contains("required_source_truth.source_checker.required_case_ids"),
        "{}",
        output_text(&output)
    );

    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_validation_command() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "bad-command")?;
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    let commands = manifest["completion_coverage"][0]["validation_commands"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "validation commands array"))?;
    commands.push(Value::String(
        "cargo test -p frankenlibc-harness --test runtime_math_cohomology_cross_family_test"
            .to_string(),
    ));

    let tampered = out_dir.join("tampered_contract.json");
    write_json(&tampered, &manifest)?;
    let output = run_checker(&root, &tampered, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail on non-rch cargo validation"
    );
    assert!(
        output_text(&output).contains("cargo validation must be rch-backed"),
        "{}",
        output_text(&output)
    );

    Ok(())
}
