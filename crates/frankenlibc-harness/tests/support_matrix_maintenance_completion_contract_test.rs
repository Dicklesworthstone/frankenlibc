//! Contract tests for bd-3g4p.1 support-matrix maintenance completion evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

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
    root.join("tests/conformance/support_matrix_maintenance_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_support_matrix_maintenance_completion_contract.sh")
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
            format!("path should stay under workspace root: {path}"),
        )
        .into());
    }
    Ok(root.join(relative))
}

fn read_json(path: &Path) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &serde_json::Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<serde_json::Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn string_set(value: &serde_json::Value) -> TestResult<BTreeSet<String>> {
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

fn source_texts(root: &Path, manifest: &serde_json::Value) -> TestResult<BTreeMap<String, String>> {
    let sources = manifest["completion_debt_evidence"]["test_sources"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test_sources object"))?;
    let mut texts = BTreeMap::new();
    for (key, path) in sources {
        let path = path
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source path string"))?;
        texts.insert(
            key.clone(),
            std::fs::read_to_string(workspace_relative_path(root, path)?)?,
        );
    }
    Ok(texts)
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
    let full_path = workspace_relative_path(root, path)?;
    assert!(
        full_path.is_file(),
        "file-line ref path should exist: {file_line_ref}"
    );
    let contents = std::fs::read_to_string(full_path)?;
    let lines: Vec<_> = contents.lines().collect();
    assert!(
        line_no <= lines.len() && !lines[line_no - 1].trim().is_empty(),
        "file-line ref should point to a non-empty line: {file_line_ref}"
    );
    Ok(())
}

fn assert_test_refs_exist(
    section: &serde_json::Value,
    source_texts: &BTreeMap<String, String>,
) -> TestResult<BTreeSet<String>> {
    let refs = section["required_test_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required_test_refs array"))?;
    let mut names = BTreeSet::new();
    for test_ref in refs {
        let source = test_ref["source"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test source"))?;
        let name = test_ref["name"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test name"))?;
        let text = source_texts
            .get(source)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source not loaded"))?;
        assert!(
            text.contains(&format!("fn {name}")),
            "{source} should contain test function {name}"
        );
        names.insert(format!("{source}::{name}"));
    }
    Ok(names)
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "support-matrix-maintenance-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn checker_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_SUPPORT_MATRIX_COMPLETION_CONTRACT", contract)
        .env(
            "FRANKENLIBC_SUPPORT_MATRIX_COMPLETION_REPORT",
            out_dir.join("support_matrix_maintenance_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_SUPPORT_MATRIX_COMPLETION_LOG",
            out_dir.join("support_matrix_maintenance_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn checker_output_message(output: &std::process::Output) -> String {
    format!(
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn contract_binds_unit_e2e_and_conformance_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    assert_eq!(manifest["bead"].as_str(), Some("bd-3g4p"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-3g4p.1"));
    assert!(manifest["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800);

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(
        string_set(&evidence["missing_items"])?,
        BTreeSet::from([
            "tests.conformance.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
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

    let policy = &evidence["maintenance_policy"];
    assert_eq!(policy["required_schema"].as_str(), Some("v1"));
    assert_eq!(policy["required_bead"].as_str(), Some("bd-3g4p"));
    assert!(policy["minimum_total_symbols"].as_u64().unwrap_or(0) >= 4000);
    assert_eq!(policy["maximum_status_invalid"].as_u64(), Some(0));
    assert_eq!(policy["required_native_coverage_pct"].as_f64(), Some(100.0));

    let sources = source_texts(&root, &manifest)?;
    let unit_refs = assert_test_refs_exist(&evidence["unit_primary"], &sources)?;
    for expected in [
        "existing_harness_test::maintenance_report_schema_complete",
        "existing_harness_test::maintenance_report_has_no_invalid_status_rows",
        "completion_harness_test::generator_self_test_succeeds",
    ] {
        assert!(unit_refs.contains(expected), "missing unit ref {expected}");
    }
    let e2e_refs = assert_test_refs_exist(&evidence["e2e_primary"], &sources)?;
    for expected in [
        "existing_harness_test::maintenance_gate_emits_structured_logs_with_required_fields",
        "existing_harness_test::maintenance_gate_fails_on_canonical_stable_section_drift",
        "completion_harness_test::checker_emits_report_log_and_runs_existing_gate",
    ] {
        assert!(e2e_refs.contains(expected), "missing e2e ref {expected}");
    }
    let conformance_refs = assert_test_refs_exist(&evidence["conformance_primary"], &sources)?;
    assert!(
        conformance_refs
            .contains("existing_harness_test::maintenance_report_generates_successfully"),
        "conformance refs should include generated-vs-canonical report proof"
    );
    assert!(
        conformance_refs
            .contains("completion_harness_test::checker_emits_report_log_and_runs_existing_gate"),
        "conformance refs should include completion checker proof"
    );

    Ok(())
}

#[test]
fn generator_self_test_succeeds() -> TestResult {
    let root = workspace_root()?;
    let output = Command::new("python3")
        .arg(root.join("scripts/generate_support_matrix_maintenance.py"))
        .arg("--self-test")
        .current_dir(&root)
        .output()?;
    assert!(
        output.status.success(),
        "self-test failed: {}",
        checker_output_message(&output)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Self-test: PASS"),
        "self-test output should include PASS: {stdout}"
    );
    Ok(())
}

#[test]
fn checker_emits_report_log_and_runs_existing_gate() -> TestResult {
    let _guard = checker_lock();
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed: {}",
        checker_output_message(&output)
    );

    let report =
        read_json(&out_dir.join("support_matrix_maintenance_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-3g4p.1"));
    assert!(report["summary"]["total_symbols"].as_u64().unwrap_or(0) >= 4000);
    assert_eq!(report["summary"]["status_invalid"].as_u64(), Some(0));
    assert!(report["summary"]["fixture_linked"].as_u64().unwrap_or(0) >= 400);
    assert_eq!(
        report["summary"]["native_coverage_pct"].as_f64(),
        Some(100.0)
    );

    let rows =
        read_jsonl(&out_dir.join("support_matrix_maintenance_completion_contract.log.jsonl"))?;
    assert_eq!(
        rows.len(),
        3,
        "checker should emit one row per missing test item"
    );
    let events = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect::<BTreeSet<_>>();
    for event in [
        "support_matrix_maintenance_units_validated",
        "support_matrix_maintenance_e2e_validated",
        "support_matrix_maintenance_conformance_validated",
    ] {
        assert!(events.contains(event), "missing event {event}");
    }

    let required_fields = string_set(&report["required_fields"])?;
    for row in rows {
        for field in &required_fields {
            assert!(
                row.get(field).is_some(),
                "structured log row missing field {field}: {row}"
            );
        }
        assert_eq!(row["status"].as_str(), Some("pass"));
        assert!(
            row["trace_id"]
                .as_str()
                .is_some_and(|trace_id| trace_id.starts_with("bd-3g4p.1:"))
        );
    }

    Ok(())
}

#[test]
fn checker_rejects_stale_conformance_threshold() -> TestResult {
    let _guard = checker_lock();
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["maintenance_policy"]["minimum_fixture_linked"] =
        serde_json::Value::from(999_999);

    let out_dir = unique_output_dir(&root, "stale-threshold")?;
    let stale_contract = out_dir.join("stale_support_matrix_maintenance_contract.json");
    write_json(&stale_contract, &manifest)?;

    let output = run_checker(&root, &stale_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject impossible fixture threshold"
    );
    let combined = checker_output_message(&output);
    assert!(
        combined.contains("canonical fixture_linked below minimum"),
        "checker output should name stale threshold: {combined}"
    );

    let report =
        read_json(&out_dir.join("support_matrix_maintenance_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "errors array"))?
            .iter()
            .any(|item| item
                .as_str()
                .unwrap_or("")
                .contains("canonical fixture_linked below minimum")),
        "report should retain stale threshold error"
    );

    Ok(())
}
