//! Contract tests for bd-bp8fl.3.7.1 reverse-loader standalone completion evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

static SCRIPT_LOCK: Mutex<()> = Mutex::new(());

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
    root.join("tests/conformance/reverse_loader_process_abi_standalone_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_reverse_loader_process_abi_standalone_completion_contract.sh")
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
        "reverse-loader-standalone-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_REVERSE_LOADER_COMPLETION_CONTRACT", contract)
        .env(
            "FRANKENLIBC_REVERSE_LOADER_COMPLETION_REPORT",
            out_dir.join("reverse_loader_process_abi_standalone_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_REVERSE_LOADER_COMPLETION_LOG",
            out_dir.join("reverse_loader_process_abi_standalone_completion_contract.log.jsonl"),
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

fn parse_stdout_report(output: &std::process::Output) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_slice(&output.stdout)?)
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
fn contract_binds_reverse_loader_gate_symbols_and_existing_tests() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.3.7"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.3.7.1")
    );
    assert!(manifest["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800);

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(
        string_set(&evidence["missing_items"])?,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.conformance.primary".to_string(),
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

    let policy = &evidence["gate_policy"];
    assert_eq!(policy["required_gap_count"].as_u64(), Some(10));
    assert_eq!(policy["required_structured_log_rows"].as_u64(), Some(20));
    assert_eq!(
        string_set(&policy["required_runtime_modes"])?,
        BTreeSet::from(["hardened".to_string(), "strict".to_string()])
    );
    assert_eq!(
        policy["required_negative_smoke_id"].as_str(),
        Some("standalone.loader_process_negative_missing_obligation")
    );
    assert_eq!(
        policy["required_evidence_kind"].as_str(),
        Some("standalone_link_run_and_versioned_symbol_gate")
    );

    let sources = source_texts(&root, &manifest)?;
    let unit_refs = assert_test_refs_exist(&evidence["unit_primary"], &sources)?;
    for expected in [
        "base_harness_test::gate_artifact_preserves_loader_process_gap_contract",
        "base_harness_test::stale_source_commit_policy_blocks_reverse_loader_gate_evidence",
        "base_harness_test::checker_rejects_missing_gap_row",
        "base_harness_test::checker_rejects_missing_versioned_symbol",
        "completion_harness_test::contract_binds_reverse_loader_gate_symbols_and_existing_tests",
    ] {
        assert!(unit_refs.contains(expected), "missing unit ref {expected}");
    }
    let conformance_refs = assert_test_refs_exist(&evidence["conformance_primary"], &sources)?;
    assert!(
        conformance_refs.contains("base_harness_test::checker_passes_and_emits_report_and_logs")
    );
    assert!(
        conformance_refs
            .contains("completion_harness_test::checker_emits_report_log_and_replays_base_gates")
    );

    for command in evidence["unit_primary"]["required_commands"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(
            evidence["conformance_primary"]["required_commands"]
                .as_array()
                .into_iter()
                .flatten(),
        )
    {
        let command = command
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "command string"))?;
        if command.contains("cargo") {
            assert!(
                command.contains("rch exec --"),
                "cargo command must go through rch: {command}"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_emits_report_log_and_replays_base_gates() -> TestResult {
    let _guard = match SCRIPT_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "positive")?;
    let report = read_json(
        &out_dir.join("reverse_loader_process_abi_standalone_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.3.7.1")
    );
    assert_eq!(report["original_bead"].as_str(), Some("bd-bp8fl.3.7"));
    assert_eq!(report["summary"]["gap_count"].as_u64(), Some(10));
    assert_eq!(
        report["summary"]["structured_log_row_count"].as_u64(),
        Some(20)
    );
    assert!(
        report["summary"]["versioned_symbol_requirement_count"]
            .as_u64()
            .unwrap_or(0)
            >= 20,
        "completion report should count versioned symbol requirements"
    );
    assert_eq!(
        report["summary"]["standalone_claim_status"].as_str(),
        Some("schema_validated")
    );
    assert_eq!(
        report["summary"]["standalone_artifact_status"].as_str(),
        Some("missing")
    );

    let rows = read_jsonl(
        &out_dir.join("reverse_loader_process_abi_standalone_completion_contract.log.jsonl"),
    )?;
    let required_fields = string_set(&report["required_fields"])?;
    let mut events = BTreeSet::new();
    for row in rows {
        for field in &required_fields {
            assert!(
                row.get(field).is_some(),
                "log row missing field {field}: {row}"
            );
        }
        events.insert(
            row["event"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "event string"))?
                .to_string(),
        );
        assert_eq!(row["status"].as_str(), Some("pass"));
        assert_eq!(row["failure_signature"].as_str(), Some("none"));
    }
    assert_eq!(events, string_set(&report["required_events"])?);

    let base_report = read_json(
        &root.join("target/conformance/reverse_loader_process_abi_standalone_gate.report.json"),
    )?;
    assert_eq!(base_report["status"].as_str(), Some("pass"));
    assert_eq!(
        base_report["checks"]["versioned_symbol_binding"].as_str(),
        Some("pass")
    );
    assert_eq!(
        base_report["checks"]["structured_log"].as_str(),
        Some("pass")
    );
    let smoke_report =
        read_json(&root.join("target/conformance/standalone_link_run_smoke.report.json"))?;
    assert_eq!(smoke_report["status"].as_str(), Some("pass"));
    assert_eq!(
        smoke_report["claim_status"].as_str(),
        Some("schema_validated")
    );

    Ok(())
}

#[test]
fn checker_rejects_stale_implementation_ref() -> TestResult {
    let _guard = match SCRIPT_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let root = workspace_root()?;
    let mut contract = read_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["implementation_refs"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "refs array"))?
        .push(serde_json::Value::String(
            "tests/conformance/reverse_loader_process_abi_standalone_gate.v1.json:999999"
                .to_string(),
        ));

    let out_dir = unique_output_dir(&root, "bad-ref")?;
    let bad_path = out_dir.join("bad-ref.json");
    write_json(&bad_path, &contract)?;
    let output = run_checker(&root, &bad_path, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail on stale implementation ref"
    );
    let report = parse_stdout_report(&output)?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let message = checker_output_message(&output);
    assert!(
        message.contains("implementation ref does not point to non-empty line"),
        "failure should name stale implementation ref: {message}"
    );

    Ok(())
}

#[test]
fn checker_rejects_bare_cargo_command() -> TestResult {
    let _guard = match SCRIPT_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let root = workspace_root()?;
    let mut contract = read_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["unit_primary"]["required_commands"][0] =
        serde_json::Value::String(
            "cargo test -p frankenlibc-harness --test reverse_loader_process_abi_standalone_gate_test"
                .to_string(),
        );

    let out_dir = unique_output_dir(&root, "bare-cargo")?;
    let bad_path = out_dir.join("bare-cargo.json");
    write_json(&bad_path, &contract)?;
    let output = run_checker(&root, &bad_path, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail on bare cargo command"
    );
    let report = parse_stdout_report(&output)?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let message = checker_output_message(&output);
    assert!(
        message.contains("bare cargo"),
        "failure should name bare cargo command: {message}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_completion_telemetry_event() -> TestResult {
    let _guard = match SCRIPT_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let root = workspace_root()?;
    let mut contract = read_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["telemetry_primary"]["required_events"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required_events array"))?
        .pop();

    let out_dir = unique_output_dir(&root, "missing-event")?;
    let bad_path = out_dir.join("missing-event.json");
    write_json(&bad_path, &contract)?;
    let output = run_checker(&root, &bad_path, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail when telemetry event coverage drifts"
    );
    let report = parse_stdout_report(&output)?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let message = checker_output_message(&output);
    assert!(
        message.contains("telemetry required_events mismatch"),
        "failure should name telemetry event drift: {message}"
    );

    Ok(())
}
