//! Contract tests for bd-w2c3.7.4 Track 6 compute-pressure graceful degradation evidence.

use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
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
    root.join("tests/conformance/compute_pressure_graceful_degradation_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_compute_pressure_graceful_degradation_completion_contract.sh")
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
        "compute-pressure-graceful-degradation-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_COMPUTE_PRESSURE_GRACEFUL_DEGRADATION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_COMPUTE_PRESSURE_GRACEFUL_DEGRADATION_REPORT",
            out_dir.join("compute_pressure_graceful_degradation_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_COMPUTE_PRESSURE_GRACEFUL_DEGRADATION_LOG",
            out_dir.join("compute_pressure_graceful_degradation_completion_contract.log.jsonl"),
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

fn checker_output_message(output: &Output) -> String {
    format!(
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
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

fn assert_test_ref_exists(
    root: &Path,
    test_sources: &serde_json::Map<String, serde_json::Value>,
    source: &str,
    name: &str,
) -> TestResult {
    let source_path = test_sources
        .get(source)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test source not found"))?;
    let text = std::fs::read_to_string(workspace_relative_path(root, source_path)?)?;
    assert!(
        text.contains(&format!("fn {name}")),
        "{source} should contain test function {name}"
    );
    Ok(())
}

#[test]
fn contract_binds_track6_unit_and_e2e_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema"].as_str(),
        Some("compute_pressure_graceful_degradation_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-w2c3.7"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-w2c3.7.4")
    );
    assert!(
        manifest["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "completion evidence should force a passing next audit score"
    );

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(
        string_set(&evidence["missing_items"])?,
        BTreeSet::from([
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

    assert_eq!(
        string_set(&evidence["pressure_sensing"]["required_regimes"])?,
        BTreeSet::from([
            "Nominal".to_string(),
            "Overloaded".to_string(),
            "Pressured".to_string(),
            "Recovery".to_string(),
        ])
    );
    assert_eq!(
        string_set(&evidence["pressure_sensing"]["required_modes"])?,
        BTreeSet::from(["hardened".to_string(), "strict".to_string()])
    );
    assert_eq!(
        string_set(&evidence["backpressure"]["required_ring_ids"])?,
        BTreeSet::from([
            "membrane.validation_log_ring".to_string(),
            "runtime_math.decision_card_ring".to_string(),
            "runtime_math.evidence_symbol_ring".to_string(),
            "stdio.evidence_row_ring".to_string(),
            "structured_log.event_ring".to_string(),
        ])
    );

    let test_sources = evidence["test_sources"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test_sources object"))?;
    for section_name in ["unit_primary", "e2e_primary"] {
        for test_ref in evidence[section_name]["required_test_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required_test_refs array"))?
        {
            let source = test_ref["source"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test source"))?;
            let name = test_ref["name"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test name"))?;
            assert_test_ref_exists(&root, test_sources, source, name)?;
        }
    }

    Ok(())
}

#[test]
fn checker_emits_graceful_degradation_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "ok")?;
    let report = read_json(
        &out_dir.join("compute_pressure_graceful_degradation_completion_contract.report.json"),
    )?;
    assert_eq!(
        report["schema"].as_str(),
        Some("compute_pressure_graceful_degradation_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-w2c3.7"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-w2c3.7.4"));
    assert_eq!(
        report["summary"]["pressure"]["scenario_count"].as_u64(),
        Some(5)
    );
    assert!(
        report["summary"]["pressure"]["fixture_cases"]
            .as_u64()
            .is_some_and(|count| count >= 8),
        "pressure fixture should cover strict and hardened cases"
    );
    assert_eq!(
        report["summary"]["backpressure"]["ring_path_count"].as_u64(),
        Some(5)
    );

    let rows = read_jsonl(
        &out_dir.join("compute_pressure_graceful_degradation_completion_contract.log.jsonl"),
    )?;
    assert_eq!(rows.len(), 5, "checker should emit all telemetry rows");
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect();
    for event in [
        "compute_pressure_graceful_degradation_sources_validated",
        "compute_pressure_graceful_degradation_unit_bindings_validated",
        "compute_pressure_graceful_degradation_e2e_bindings_validated",
        "compute_pressure_graceful_degradation_backpressure_validated",
        "compute_pressure_graceful_degradation_completion_contract_validated",
    ] {
        assert!(events.contains(event), "missing event {event}");
    }
    for row in &rows {
        for field in [
            "trace_id",
            "completion_debt_bead",
            "original_bead",
            "mode",
            "api_family",
            "symbol",
            "decision_path",
            "healing_action",
            "errno",
            "latency_ns",
            "overload_state",
            "degradation_active",
            "overload_policy",
            "artifact_refs",
            "failure_signature",
        ] {
            assert!(row.get(field).is_some(), "row missing field {field}");
        }
        assert_eq!(row["status"].as_str(), Some("pass"));
        assert_eq!(row["completion_debt_bead"].as_str(), Some("bd-w2c3.7.4"));
        assert_eq!(row["failure_signature"].as_str(), Some("none"));
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_overloaded_regime() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-overloaded")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let regimes = manifest["completion_debt_evidence"]["pressure_sensing"]["required_regimes"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "regimes array"))?;
    regimes.retain(|row| !matches!(row.as_str(), Some("Overloaded")));
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing overloaded regime:\n{}",
        checker_output_message(&output)
    );
    let report = read_json(
        &out_dir.join("compute_pressure_graceful_degradation_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|error| error
                .as_str()
                .is_some_and(|text| text.contains("required_regimes"))),
        "failure report should explain required regime drift"
    );
    Ok(())
}

#[test]
fn checker_rejects_unrouted_cargo_command() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "local-cargo")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_commands"][0] =
        serde_json::Value::String(
            "cargo test -p frankenlibc-membrane pressure_sensor:: -- --nocapture".to_string(),
        );
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject local cargo command:\n{}",
        checker_output_message(&output)
    );
    let report = read_json(
        &out_dir.join("compute_pressure_graceful_degradation_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|error| error
                .as_str()
                .is_some_and(|text| text.contains("offload through rch"))),
        "failure report should explain rch offload requirement"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_backpressure_ring_path() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-ring")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let rings = manifest["completion_debt_evidence"]["backpressure"]["required_ring_ids"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ring ids array"))?;
    rings.retain(|row| !matches!(row.as_str(), Some("structured_log.event_ring")));
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing ring path:\n{}",
        checker_output_message(&output)
    );
    let report = read_json(
        &out_dir.join("compute_pressure_graceful_degradation_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|error| error
                .as_str()
                .is_some_and(|text| text.contains("required_ring_ids"))),
        "failure report should explain ring path drift"
    );
    Ok(())
}
