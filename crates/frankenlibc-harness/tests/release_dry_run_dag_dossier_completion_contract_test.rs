//! Completion-contract tests for bd-w2c3.10.2.1 release dry-run DAG evidence.

use std::collections::BTreeSet;
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
        .ok_or_else(|| io::Error::other("manifest should have a parent"))?;
    Ok(crates_dir
        .parent()
        .ok_or_else(|| io::Error::other("crate should live below workspace root"))?
        .to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/release_dry_run_dag_dossier_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_release_dry_run_dag_dossier_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn read_jsonl(path: &Path) -> TestResult<Vec<serde_json::Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn write_json(path: &Path, value: &serde_json::Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
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
    artifacts: &serde_json::Map<String, serde_json::Value>,
    test_ref: &serde_json::Value,
) -> TestResult {
    let source = test_ref["source"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test source"))?;
    let name = test_ref["name"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test name"))?;
    let source_path = artifacts
        .get(source)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source artifact path"))?;
    let source_text = std::fs::read_to_string(workspace_relative_path(root, source_path)?)?;
    assert!(
        source_text.contains(&format!("fn {name}")),
        "{source} should contain test function {name}"
    );
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out_dir = root.join("target/conformance").join(format!(
        "release-dry-run-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&out_dir)?;
    Ok(out_dir)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_RELEASE_DRY_RUN_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_RELEASE_DRY_RUN_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_RELEASE_DRY_RUN_COMPLETION_REPORT",
            out_dir.join("release_dry_run_dag_dossier_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RELEASE_DRY_RUN_COMPLETION_LOG",
            out_dir.join("release_dry_run_dag_dossier_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn run_passing_checker(root: &Path, label: &str) -> TestResult<PathBuf> {
    let out_dir = unique_out_dir(root, label)?;
    let output = run_checker(root, &contract_path(root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(out_dir)
}

#[test]
fn manifest_binds_release_dry_run_completion_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("release_dry_run_dag_dossier_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-w2c3.10.2"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-w2c3.10.2.1")
    );
    assert!(
        manifest["next_audit_score_threshold"]
            .as_u64()
            .unwrap_or_default()
            >= 800
    );

    let artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source_artifacts object"))?;
    for (artifact_id, path) in artifacts {
        let path = path
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact path string"))?;
        assert!(
            workspace_relative_path(&root, path)?.is_file(),
            "artifact {artifact_id} should exist at {path}"
        );
    }

    for file_line_ref in manifest["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "implementation refs"))?
    {
        assert_file_line_ref_exists(
            &root,
            file_line_ref
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref string"))?,
        )?;
    }

    let bindings = manifest["missing_item_bindings"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing_item_bindings array"))?;
    let binding_ids: BTreeSet<_> = bindings
        .iter()
        .filter_map(|binding| binding["id"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(
        binding_ids,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.conformance.primary".to_string(),
        ])
    );

    for binding in bindings {
        let refs = binding["required_test_refs"].as_array().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "required_test_refs array")
        })?;
        assert!(!refs.is_empty(), "each binding should cite tests");
        for test_ref in refs {
            assert_test_ref_exists(&root, artifacts, test_ref)?;
        }
    }
    Ok(())
}

#[test]
fn contract_requires_release_gate_dag_and_dossier_conformance() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    let contract = &manifest["release_dry_run_contract"];
    let expected_sequence = string_set(&contract["expected_gate_sequence"])?;
    assert_eq!(expected_sequence.len(), 9);

    let dag = read_json(&root.join("tests/conformance/release_gate_dag.v1.json"))?;
    let gates = dag["gates"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "gates array"))?;
    let actual_sequence: BTreeSet<_> = gates
        .iter()
        .map(|gate| {
            gate["gate_name"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "gate_name"))
                .map(str::to_owned)
        })
        .collect::<Result<_, _>>()?;
    assert_eq!(actual_sequence, expected_sequence);
    assert_eq!(
        contract["required_dossier_fields"]
            .as_array()
            .unwrap()
            .len(),
        12,
        "dossier schema should be fully pinned"
    );
    assert!(
        contract["required_log_fields"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("resume_token")),
        "log schema should require resume token"
    );
    assert_eq!(contract["fail_fast_gate"].as_str(), Some("e2e"));
    Ok(())
}

#[test]
fn checker_runs_release_dry_run_and_emits_report_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "pass")?;
    let report_path = out_dir.join("release_dry_run_dag_dossier_completion_contract.report.json");
    let log_path = out_dir.join("release_dry_run_dag_dossier_completion_contract.log.jsonl");
    let report = read_json(&report_path)?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_summary"]["gate_count"].as_u64(), Some(9));
    assert_eq!(report["completion_summary"]["failed"].as_u64(), Some(0));
    assert!(
        report["generated_dossier"]["summary"]["verdict"].as_str() == Some("PASS"),
        "generated dossier should pass"
    );
    let events = read_jsonl(&log_path)?;
    let event_names: BTreeSet<_> = events
        .iter()
        .filter_map(|event| event["event"].as_str().map(str::to_owned))
        .collect();
    for required in [
        "release_dry_run_manifest_verified",
        "release_dry_run_dossier_replayed",
        "release_dry_run_fail_fast_resume_verified",
        "release_dry_run_source_checker_replayed",
        "release_dry_run_completion_contract_pass",
    ] {
        assert!(event_names.contains(required), "missing event {required}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_gate_from_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "negative")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["release_dry_run_contract"]["expected_gate_sequence"] = serde_json::json!([
        "lint",
        "unit",
        "conformance",
        "conformance_coverage",
        "claim_reconciliation",
        "e2e",
        "perf",
        "docs_reports"
    ]);
    let bad_contract = out_dir.join("bad.release_dry_run_dag_dossier_completion_contract.v1.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject a contract with a missing release_dossier gate"
    );
    let report =
        read_json(&out_dir.join("release_dry_run_dag_dossier_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let errors = report["errors"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "errors array"))?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .unwrap_or_default()
            .contains("gate sequence mismatch")),
        "negative report should explain the gate sequence mismatch"
    );
    Ok(())
}
