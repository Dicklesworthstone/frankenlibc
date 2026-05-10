//! Contract tests for bd-1iya.1 runtime-math profile-gate completion evidence.

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
    root.join("tests/conformance/runtime_math_profile_gate_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_runtime_math_profile_gate_completion_contract.sh")
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
        "runtime-math-profile-gate-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_RUNTIME_MATH_PROFILE_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_RUNTIME_MATH_PROFILE_COMPLETION_REPORT",
            out_dir.join("runtime_math_profile_gate_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RUNTIME_MATH_PROFILE_COMPLETION_LOG",
            out_dir.join("runtime_math_profile_gate_completion_contract.log.jsonl"),
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

#[test]
fn contract_binds_feature_architecture_and_unit_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    assert_eq!(manifest["bead"].as_str(), Some("bd-1iya"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-1iya.1"));
    assert!(
        manifest["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "completion evidence should force a passing next audit score"
    );

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(
        string_set(&evidence["missing_items"])?,
        BTreeSet::from([
            "flag.architecture".to_string(),
            "tests.unit.primary".to_string()
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

    let artifacts = evidence["artifacts"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifacts object"))?;
    for path in artifacts.values() {
        let path = path
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact path"))?;
        assert!(
            workspace_relative_path(&root, path)?.is_file(),
            "artifact should exist: {path}"
        );
    }

    let flag = &evidence["flag_architecture"];
    assert_eq!(flag["missing_item_id"].as_str(), Some("flag.architecture"));
    assert_eq!(
        string_set(&flag["default_feature_set"])?,
        BTreeSet::from(["runtime-math-production".to_string()])
    );
    assert_eq!(
        string_set(&flag["optional_feature_set"])?,
        BTreeSet::from(["runtime-math-research".to_string()])
    );

    let bindings = string_set(&flag["required_feature_bindings"])?;
    for binding in [
        "default = [\"runtime-math-production\"]",
        "runtime-math-production = []",
        "runtime-math-research = [\"runtime-math-production\"]",
    ] {
        assert!(bindings.contains(binding), "missing binding {binding}");
    }

    let source_texts = source_texts(&root, &manifest)?;
    let names = assert_test_refs_exist(&evidence["unit_primary"], &source_texts)?;
    assert!(
        names.contains("profile_gate_test::manifest_feature_sets_match_membrane_cargo_features")
    );
    assert!(names.contains(
        "completion_contract_test::contract_binds_feature_architecture_and_unit_evidence"
    ));

    for command in evidence["unit_primary"]["required_commands"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "commands array"))?
    {
        let command = command
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "command string"))?;
        assert!(
            command.contains("rch exec"),
            "cargo command should be offloaded through rch: {command}"
        );
    }
    Ok(())
}

#[test]
fn checker_emits_profile_completion_report_and_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "ok")?;

    let report =
        read_json(&out_dir.join("runtime_math_profile_gate_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        string_set(&report["summary"]["default_feature_set"])?,
        BTreeSet::from(["runtime-math-production".to_string()])
    );
    assert_eq!(
        string_set(&report["summary"]["optional_feature_set"])?,
        BTreeSet::from(["runtime-math-research".to_string()])
    );
    assert_eq!(
        report["summary"]["required_feature_binding_count"].as_u64(),
        Some(3)
    );
    assert_eq!(
        report["summary"]["verification_matrix_status"].as_str(),
        Some("complete")
    );

    let rows =
        read_jsonl(&out_dir.join("runtime_math_profile_gate_completion_contract.log.jsonl"))?;
    assert!(rows.len() >= 3, "checker should emit telemetry rows");
    assert!(rows.iter().any(|row| matches!(
        (
            row.get("event").and_then(serde_json::Value::as_str),
            row.get("status").and_then(serde_json::Value::as_str),
            row.get("failure_signature")
                .and_then(serde_json::Value::as_str),
        ),
        (
            Some("runtime_math_profile_gate_completion_contract_validated"),
            Some("pass"),
            Some("none")
        )
    )));
    for row in &rows {
        for field in [
            "timestamp",
            "trace_id",
            "event",
            "completion_debt_bead",
            "original_bead",
            "source_commit",
            "status",
            "mode",
            "api_family",
            "symbol",
            "outcome",
            "errno",
            "timing_ns",
            "artifact_refs",
            "failure_signature",
        ] {
            assert!(row.get(field).is_some(), "row missing field {field}");
        }
        assert_eq!(row["completion_debt_bead"].as_str(), Some("bd-1iya.1"));
        assert_eq!(row["original_bead"].as_str(), Some("bd-1iya"));
        assert_eq!(row["api_family"].as_str(), Some("runtime_math"));
    }
    Ok(())
}

#[test]
fn checker_validates_existing_profile_gate_and_ci_bindings() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "bindings")?;
    let report =
        read_json(&out_dir.join("runtime_math_profile_gate_completion_contract.report.json"))?;
    assert_eq!(report["summary"]["profile_matrix_count"].as_u64(), Some(3));

    let script = std::fs::read_to_string(root.join("scripts/check_runtime_math_profile_gates.sh"))?;
    assert!(script.contains("runtime_math_profile_gates.log.jsonl"));
    assert!(script.contains("runtime_math_profile_gates.report.json"));
    assert!(script.contains("--features runtime-math-research"));
    assert!(script.contains("--no-default-features"));
    assert!(script.contains("expect_success=False"));

    let ci_script = std::fs::read_to_string(root.join("scripts/ci.sh"))?;
    assert!(ci_script.contains("scripts/check_runtime_math_profile_gates.sh"));
    Ok(())
}

#[test]
fn checker_rejects_missing_research_feature_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-feature-binding")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let bindings =
        manifest["completion_debt_evidence"]["flag_architecture"]["required_feature_bindings"]
            .as_array_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "feature binding array"))?;
    bindings.retain(|row| {
        !matches!(
            row.as_str(),
            Some("runtime-math-research = [\"runtime-math-production\"]")
        )
    });
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing feature binding:\n{}",
        checker_output_message(&output)
    );
    let report =
        read_json(&out_dir.join("runtime_math_profile_gate_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|error| error
                .as_str()
                .is_some_and(|text| text.contains("required_feature_bindings"))),
        "failure report should explain missing feature binding"
    );
    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_command() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "non-rch-command")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_commands"][0] =
        serde_json::Value::String(
            "cargo test -p frankenlibc-harness --test runtime_math_profile_gates_test".to_string(),
        );
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject non-rch cargo command:\n{}",
        checker_output_message(&output)
    );
    let report =
        read_json(&out_dir.join("runtime_math_profile_gate_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|error| error
                .as_str()
                .is_some_and(|text| text.contains("offload cargo through rch"))),
        "failure report should name non-rch command"
    );
    Ok(())
}
