//! Contract tests for bd-5vr.6.1 runtime-math unit coverage completion evidence.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::other("workspace root should exist"))?
        .to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/runtime_math_unit_coverage_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_runtime_math_unit_coverage_completion_contract.sh")
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

fn workspace_relative_path(root: &Path, rel: &str) -> PathBuf {
    let path = Path::new(rel);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "runtime-math-unit-coverage-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_RUNTIME_MATH_UNIT_COVERAGE_CONTRACT", contract)
        .env(
            "FRANKENLIBC_RUNTIME_MATH_UNIT_COVERAGE_REPORT",
            out_dir.join("runtime_math_unit_coverage_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RUNTIME_MATH_UNIT_COVERAGE_LOG",
            out_dir.join("runtime_math_unit_coverage_completion_contract.log.jsonl"),
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

fn source_texts(root: &Path, manifest: &Value) -> TestResult<BTreeMap<String, String>> {
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
            std::fs::read_to_string(workspace_relative_path(root, path))?,
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
    let full_path = workspace_relative_path(root, path);
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
    section: &Value,
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
            text.contains(&format!("fn {name}(")) || text.contains(&format!("fn {name}<")),
            "{source} should contain test function {name}"
        );
        names.insert(format!("{source}::{name}"));
    }
    Ok(names)
}

fn assert_rch_backed_commands(section: &Value) -> TestResult {
    for command in section["required_commands"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let command = command
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "command string"))?;
        if command.contains("cargo ") {
            assert!(
                command.contains("rch exec") || command.starts_with("rch cargo "),
                "cargo validation must be rch-backed: {command}"
            );
        }
    }
    Ok(())
}

#[test]
fn manifest_binds_unit_e2e_property_coverage() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("runtime_math_unit_coverage_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-5vr.6"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-5vr.6.1")
    );
    assert!(
        manifest["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "completion evidence should target a passing next audit score"
    );

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(
        string_set(&evidence["missing_items"])?,
        BTreeSet::from([
            "tests.e2e.primary".to_string(),
            "tests.property.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
    );

    let groups = manifest["source_contract"]["coverage_groups"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "coverage groups array"))?;
    let group_names = groups
        .iter()
        .map(|group| {
            group["name"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "coverage group name"))
                .map(str::to_string)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    for expected in [
        "per_kernel_correctness",
        "numerical_stability",
        "certificate_verification",
        "property_coverage",
        "deterministic_e2e",
    ] {
        assert!(group_names.contains(expected), "missing group {expected}");
    }

    let sources = source_texts(&root, &manifest)?;
    for group in groups {
        for file_line_ref in group["implementation_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "implementation refs"))?
        {
            assert_file_line_ref_exists(
                &root,
                file_line_ref.as_str().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "file-line ref string")
                })?,
            )?;
        }
        assert_test_refs_exist(group, &sources)?;
    }

    for artifact in manifest["source_contract"]["required_artifacts"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifacts array"))?
    {
        let artifact = artifact
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact string"))?;
        assert!(
            workspace_relative_path(&root, artifact).is_file(),
            "required artifact should exist: {artifact}"
        );
    }

    let unit_refs = assert_test_refs_exist(&evidence["unit_primary"], &sources)?;
    for expected in [
        "risk::recomputes_on_cadence_boundary",
        "control::limits_remain_bounded_under_long_trace",
        "bandit::ucb_cache_isolated_per_family",
        "sos_barrier::certificate_tamper_is_detected",
        "runtime_math_mod::deterministic_replay_produces_identical_decisions_and_evidence",
    ] {
        assert!(unit_refs.contains(expected), "missing unit ref {expected}");
    }

    let property_refs = assert_test_refs_exist(&evidence["property_primary"], &sources)?;
    for expected in [
        "lattice::prop_join_commutative",
        "fingerprint::prop_canary_detects_any_byte_flip",
        "check_oracle::prop_oracle_total_calls_monotonic",
        "bloom::prop_insert_is_monotonic",
    ] {
        assert!(
            property_refs.contains(expected),
            "missing property ref {expected}"
        );
    }

    let e2e_refs = assert_test_refs_exist(&evidence["e2e_primary"], &sources)?;
    for expected in [
        "hji_gate::gate_script_emits_logs_and_report",
        "linkage_gate::gate_script_emits_logs_and_report",
        "classification_gate::gate_script_emits_structured_logs",
        "determinism_gate::runtime_math_kernel_snapshot_golden_checksum_matches_manifest",
        "completion_harness::checker_emits_report_log_and_validates_coverage",
    ] {
        assert!(e2e_refs.contains(expected), "missing e2e ref {expected}");
    }

    assert_rch_backed_commands(&evidence["unit_primary"])?;
    assert_rch_backed_commands(&evidence["property_primary"])?;
    assert_rch_backed_commands(&evidence["e2e_primary"])?;
    Ok(())
}

#[test]
fn checker_emits_report_log_and_validates_coverage() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "pass")?;
    let report =
        read_json(&out_dir.join("runtime_math_unit_coverage_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-5vr.6.1"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-5vr.6"));
    assert!(
        report["coverage_group_count"].as_u64().unwrap_or(0) >= 5,
        "report should include all coverage groups"
    );
    assert!(
        report["unit_test_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unit refs"))?
            .len()
            >= 19,
        "report should include unit refs"
    );
    assert!(
        report["property_test_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "property refs"))?
            .len()
            >= 10,
        "report should include property refs"
    );
    assert!(
        report["e2e_test_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "e2e refs"))?
            .len()
            >= 8,
        "report should include e2e refs"
    );
    assert!(
        report["errors"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "errors array"))?
            .is_empty(),
        "passing report should not contain errors"
    );

    let rows =
        read_jsonl(&out_dir.join("runtime_math_unit_coverage_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(
        row["event"].as_str(),
        Some("runtime_math_unit_coverage_completion_contract_validated")
    );
    assert_eq!(row["status"].as_str(), Some("pass"));
    assert_eq!(row["failure_signature"].as_str(), Some("none"));
    for field in [
        "trace_id",
        "completion_debt_bead",
        "original_bead",
        "source_commit",
        "coverage_group_count",
        "unit_test_refs",
        "e2e_test_refs",
        "property_test_refs",
        "artifact_refs",
    ] {
        assert!(row.get(field).is_some(), "log row should include {field}");
    }
    Ok(())
}

#[test]
fn checker_rejects_stale_unit_test_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_test_refs"][0]["name"] =
        Value::String("missing_runtime_math_unit_test".to_string());

    let out_dir = unique_output_dir(&root, "stale-unit-test")?;
    let mutated = out_dir.join("contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject stale unit test binding"
    );
    let report =
        read_json(&out_dir.join("runtime_math_unit_coverage_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let errors = serde_json::to_string(&report["errors"])?;
    assert!(
        errors.contains("missing test"),
        "expected missing-test failure, got {}",
        checker_output_message(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_stale_property_test_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["property_primary"]["required_test_refs"][0]["name"] =
        Value::String("missing_lattice_property_test".to_string());

    let out_dir = unique_output_dir(&root, "stale-property-test")?;
    let mutated = out_dir.join("contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject stale property test binding"
    );
    let report =
        read_json(&out_dir.join("runtime_math_unit_coverage_completion_contract.report.json"))?;
    let errors = serde_json::to_string(&report["errors"])?;
    assert!(errors.contains("missing test"));
    Ok(())
}

#[test]
fn checker_rejects_local_cargo_command() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_commands"][0] =
        Value::String("cargo test -p frankenlibc-membrane runtime_math::risk::tests".to_string());

    let out_dir = unique_output_dir(&root, "local-cargo")?;
    let mutated = out_dir.join("contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject local cargo command"
    );
    let report =
        read_json(&out_dir.join("runtime_math_unit_coverage_completion_contract.report.json"))?;
    let errors = serde_json::to_string(&report["errors"])?;
    assert!(errors.contains("cargo command must be rch-backed"));
    Ok(())
}

#[test]
fn checker_rejects_missing_artifact_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["source_contract"]["required_artifacts"][0] =
        Value::String("tests/runtime_math/missing_runtime_math_manifest.json".to_string());

    let out_dir = unique_output_dir(&root, "missing-artifact")?;
    let mutated = out_dir.join("contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing artifact binding"
    );
    let report =
        read_json(&out_dir.join("runtime_math_unit_coverage_completion_contract.report.json"))?;
    let errors = serde_json::to_string(&report["errors"])?;
    assert!(errors.contains("required artifact missing"));
    Ok(())
}

#[test]
fn checker_rejects_invalid_file_line_ref() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["source_contract"]["coverage_groups"][0]["implementation_refs"][0] =
        Value::String("crates/frankenlibc-membrane/src/runtime_math/risk.rs:999999".to_string());

    let out_dir = unique_output_dir(&root, "bad-ref")?;
    let mutated = out_dir.join("contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject invalid file-line ref"
    );
    let report =
        read_json(&out_dir.join("runtime_math_unit_coverage_completion_contract.report.json"))?;
    let errors = serde_json::to_string(&report["errors"])?;
    assert!(errors.contains("file-line ref should point to a non-empty line"));
    Ok(())
}
