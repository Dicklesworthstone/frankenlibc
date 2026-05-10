//! Contract tests for bd-w2c3.7.2.1 family degradation policy completion evidence.

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
    root.join("tests/conformance/family_degradation_policy_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_family_degradation_policy_completion_contract.sh")
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
        "family-degradation-policy-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_FAMILY_DEGRADATION_POLICY_CONTRACT", contract)
        .env(
            "FRANKENLIBC_FAMILY_DEGRADATION_POLICY_REPORT",
            out_dir.join("family_degradation_policy_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_FAMILY_DEGRADATION_POLICY_LOG",
            out_dir.join("family_degradation_policy_completion_contract.log.jsonl"),
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
fn contract_binds_policy_table_units_and_overload_telemetry() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    assert_eq!(manifest["bead"].as_str(), Some("bd-w2c3.7.2"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-w2c3.7.2.1")
    );
    assert!(
        manifest["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "completion evidence should force a passing next audit score"
    );

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(
        string_set(&evidence["missing_items"])?,
        BTreeSet::from([
            "telemetry.primary".to_string(),
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

    let sources = source_texts(&root, &manifest)?;
    let unit_refs = assert_test_refs_exist(&evidence["unit_primary"], &sources)?;
    assert!(unit_refs.contains("policy_table_source::strict_repair_is_rejected"));
    assert!(
        unit_refs
            .contains("runtime_math_source::overloaded_regime_applies_mode_specific_safe_fallback")
    );
    assert!(unit_refs.contains(
        "runtime_math_source::runtime_math_log_jsonl_exports_pressure_and_overload_policy_events"
    ));

    let telemetry_events = string_set(&evidence["telemetry_primary"]["required_events"])?;
    for event in [
        "runtime_decision",
        "runtime_pressure_sensor",
        "runtime_overload_policy_applied",
    ] {
        assert!(
            telemetry_events.contains(event),
            "missing telemetry event {event}"
        );
    }
    let telemetry_fields = string_set(&evidence["telemetry_primary"]["required_fields"])?;
    for field in [
        "trace_id",
        "decision_path",
        "healing_action",
        "latency_ns",
        "overload_state",
        "degradation_active",
        "overload_policy",
        "policy_id",
        "failure_signature",
    ] {
        assert!(
            telemetry_fields.contains(field),
            "missing telemetry field {field}"
        );
    }
    Ok(())
}

#[test]
fn checker_emits_completion_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "ok")?;
    let report =
        read_json(&out_dir.join("family_degradation_policy_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert!(
        report["summary"]["policy_table_tests"]
            .as_u64()
            .is_some_and(|count| count >= 10),
        "report should count policy-table positive and negative tests"
    );
    assert_eq!(
        report["summary"]["admission_policy_table_rows"].as_u64(),
        Some(1)
    );
    assert_eq!(
        report["summary"]["controller_manifest_policy_table_rows"].as_u64(),
        Some(1)
    );

    let rows =
        read_jsonl(&out_dir.join("family_degradation_policy_completion_contract.log.jsonl"))?;
    assert!(rows.len() >= 4, "checker should emit telemetry rows");
    assert!(rows.iter().any(|row| matches!(
        (
            row.get("event").and_then(serde_json::Value::as_str),
            row.get("status").and_then(serde_json::Value::as_str),
            row.get("failure_signature")
                .and_then(serde_json::Value::as_str),
        ),
        (
            Some("family_degradation_policy_completion_contract_validated"),
            Some("pass"),
            Some("none")
        )
    )));
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
            "policy_id",
            "artifact_refs",
            "failure_signature",
        ] {
            assert!(row.get(field).is_some(), "row missing field {field}");
        }
        assert_eq!(row["completion_debt_bead"].as_str(), Some("bd-w2c3.7.2.1"));
        assert_eq!(row["original_bead"].as_str(), Some("bd-w2c3.7.2"));
    }
    Ok(())
}

#[test]
fn checker_validates_policy_audit_and_admission_bindings() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "bindings")?;
    let report =
        read_json(&out_dir.join("family_degradation_policy_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));

    let proof_script =
        std::fs::read_to_string(root.join("scripts/check_proof_carrying_policy_audit.sh"))?;
    assert!(proof_script.contains("--validate-only"));
    assert!(proof_script.contains("exec rch exec -- cargo test"));

    let admission_report =
        read_json(&root.join("tests/runtime_math/admission_gate_report.v1.json"))?;
    let policy_row = admission_report["admission_ledger"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|row| row["module"].as_str() == Some("policy_table"))
        .expect("policy_table admission row should exist");
    assert_eq!(policy_row["tier"].as_str(), Some("production_core"));
    assert_eq!(policy_row["admission_status"].as_str(), Some("ADMITTED"));
    assert_eq!(policy_row["in_production_manifest"].as_bool(), Some(true));
    Ok(())
}

#[test]
fn checker_rejects_missing_overload_policy_event() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-event")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let events = manifest["completion_debt_evidence"]["telemetry_primary"]["required_events"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "events array"))?;
    events.retain(|row| !matches!(row.as_str(), Some("runtime_overload_policy_applied")));
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing telemetry event:\n{}",
        checker_output_message(&output)
    );
    let report =
        read_json(&out_dir.join("family_degradation_policy_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|error| error
                .as_str()
                .is_some_and(|text| text.contains("required_events"))),
        "failure report should explain missing required_events"
    );
    Ok(())
}

#[test]
fn checker_rejects_local_cargo_unit_command() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "local-cargo")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_commands"][0] =
        serde_json::Value::String(
            "cargo test -p frankenlibc-membrane runtime_math::policy_table::tests".to_string(),
        );
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject local cargo command:\n{}",
        checker_output_message(&output)
    );
    let report =
        read_json(&out_dir.join("family_degradation_policy_completion_contract.report.json"))?;
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
