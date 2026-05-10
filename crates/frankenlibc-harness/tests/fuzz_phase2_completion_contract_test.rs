//! Contract tests for bd-1oz.7.1 fuzz phase-2 completion evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
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
    root.join("tests/conformance/fuzz_phase2_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_fuzz_phase2_completion_contract.sh")
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

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "fuzz-phase2-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_FUZZ_PHASE2_CONTRACT", contract)
        .env(
            "FRANKENLIBC_FUZZ_PHASE2_REPORT",
            out_dir.join("fuzz_phase2_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_FUZZ_PHASE2_LOG",
            out_dir.join("fuzz_phase2_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn run_passing_checker(root: &Path, label: &str) -> TestResult<PathBuf> {
    let out_dir = unique_output_dir(root, label)?;
    let output = run_checker(root, &contract_path(root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(out_dir)
}

fn checker_output_message(output: &std::process::Output) -> String {
    format!(
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
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

#[test]
fn contract_binds_phase2_targets_ci_and_existing_tests() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    assert_eq!(manifest["bead"].as_str(), Some("bd-1oz.7"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-1oz.7.1")
    );
    assert!(manifest["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800);

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(
        string_set(&evidence["missing_items"])?,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.conformance.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.fuzz.primary".to_string(),
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

    let policy = &evidence["phase2_policy"];
    assert_eq!(policy["required_targets"].as_array().unwrap().len(), 4);
    assert_eq!(
        string_set(&policy["required_transition_families"])?,
        BTreeSet::from([
            "locale".to_string(),
            "resolver".to_string(),
            "runtime-math".to_string(),
        ])
    );
    assert_eq!(policy["runs_per_target"].as_u64(), Some(1_000_000));
    assert_eq!(policy["max_crashes"].as_u64(), Some(0));

    let sources = source_texts(&root, &manifest)?;
    let unit_refs = assert_test_refs_exist(&evidence["unit_primary"], &sources)?;
    for expected in [
        "existing_harness_test::phase2_report_generates_successfully",
        "existing_harness_test::phase2_schema_complete",
        "existing_harness_test::phase2_targets_cover_required_transition_families",
        "existing_harness_test::phase2_targets_are_smoke_viable",
        "existing_harness_test::phase2_nightly_policy_matches_target_inventory",
        "existing_harness_test::phase2_readiness_thresholds_are_reasonable",
        "completion_harness_test::contract_binds_phase2_targets_ci_and_existing_tests",
    ] {
        assert!(unit_refs.contains(expected), "missing unit ref {expected}");
    }
    let e2e_refs = assert_test_refs_exist(&evidence["e2e_primary"], &sources)?;
    assert!(e2e_refs.contains(
        "existing_harness_test::fuzz_nightly_build_check_fallback_writes_phase2_summary"
    ));
    assert!(
        e2e_refs.contains(
            "completion_harness_test::checker_emits_report_log_and_replays_existing_gate"
        )
    );
    assert!(e2e_refs.contains("completion_harness_test::checker_rejects_missing_required_target"));
    Ok(())
}

#[test]
fn checker_emits_report_log_and_replays_existing_gate() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "pass")?;
    let report = read_json(&out_dir.join("fuzz_phase2_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-1oz.7.1"));
    assert_eq!(report["summary"]["target_count"].as_u64(), Some(4));
    assert_eq!(
        report["summary"]["runs_per_target"].as_u64(),
        Some(1_000_000)
    );
    assert_eq!(report["summary"]["max_crashes"].as_i64(), Some(0));
    assert!(report["summary"]["symbol_count"].as_u64().unwrap_or(0) >= 10);

    let rows = read_jsonl(&out_dir.join("fuzz_phase2_completion_contract.log.jsonl"))?;
    assert_eq!(
        rows.len(),
        5,
        "checker should emit one row per completion item"
    );
    let events = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect::<BTreeSet<_>>();
    for event in [
        "fuzz_phase2_units_validated",
        "fuzz_phase2_e2e_validated",
        "fuzz_phase2_fuzz_inventory_validated",
        "fuzz_phase2_conformance_validated",
        "fuzz_phase2_telemetry_validated",
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
                .is_some_and(|trace_id| trace_id.starts_with("bd-1oz.7.1:"))
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_required_target() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["phase2_policy"]["required_targets"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required_targets array"))?
        .push(serde_json::Value::String(
            "definitely_missing_fuzz_target".to_string(),
        ));

    let out_dir = unique_output_dir(&root, "missing-target")?;
    let stale_contract = out_dir.join("stale_contract.json");
    write_json(&stale_contract, &manifest)?;
    let output = run_checker(&root, &stale_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing target:\n{}",
        checker_output_message(&output)
    );
    assert!(
        checker_output_message(&output)
            .contains("required phase2 targets do not match report targets"),
        "failure should identify target inventory drift"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_field() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["telemetry_primary"]["required_fields"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required_fields array"))?
        .retain(|field| field.as_str() != Some("trace_id"));

    let out_dir = unique_output_dir(&root, "missing-field")?;
    let stale_contract = out_dir.join("stale_contract.json");
    write_json(&stale_contract, &manifest)?;
    let output = run_checker(&root, &stale_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing telemetry field:\n{}",
        checker_output_message(&output)
    );
    assert!(
        checker_output_message(&output).contains("telemetry required_fields mismatch"),
        "failure should identify telemetry drift"
    );
    Ok(())
}

#[test]
fn checker_rejects_local_cargo_unit_command() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_commands"][0] =
        serde_json::Value::String(
            "cargo test -p frankenlibc-harness --test fuzz_phase2_targets_test".to_string(),
        );

    let out_dir = unique_output_dir(&root, "local-cargo")?;
    let stale_contract = out_dir.join("stale_contract.json");
    write_json(&stale_contract, &manifest)?;
    let output = run_checker(&root, &stale_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject local cargo validation command:\n{}",
        checker_output_message(&output)
    );
    assert!(
        checker_output_message(&output).contains("cargo command must be rch-backed"),
        "failure should identify rch validation requirement"
    );
    Ok(())
}
