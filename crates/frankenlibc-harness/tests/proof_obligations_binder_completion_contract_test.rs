//! Contract tests for bd-5fw.4.1 proof-obligations binder completion evidence.

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
    root.join("tests/conformance/proof_obligations_binder_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_proof_obligations_binder_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    let contents = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&contents)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let contents = std::fs::read_to_string(path)?;
    let mut rows = Vec::new();
    for line in contents.lines().filter(|line| !line.trim().is_empty()) {
        rows.push(serde_json::from_str(line)?);
    }
    Ok(rows)
}

fn workspace_relative_path(root: &Path, rel: &str) -> TestResult<PathBuf> {
    let path = Path::new(rel);
    let full = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    Ok(full)
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

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "proof-obligations-binder-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_PROOF_BINDER_COMPLETION_CONTRACT", contract)
        .env(
            "FRANKENLIBC_PROOF_BINDER_COMPLETION_REPORT",
            out_dir.join("proof_obligations_binder_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_PROOF_BINDER_COMPLETION_LOG",
            out_dir.join("proof_obligations_binder_completion_contract.log.jsonl"),
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
            std::fs::read_to_string(workspace_relative_path(root, path)?)?,
        );
    }
    Ok(texts)
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
fn contract_binds_proof_binder_e2e_and_telemetry() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    assert_eq!(manifest["bead"].as_str(), Some("bd-5fw.4"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-5fw.4.1")
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

    let policy = &evidence["proof_binder_contract"];
    assert!(policy["minimum_obligations"].as_u64().unwrap_or(0) >= 24);
    assert!(policy["minimum_categories"].as_u64().unwrap_or(0) >= 14);
    assert!(policy["minimum_source_refs"].as_u64().unwrap_or(0) >= 60);
    assert!(
        policy["minimum_unique_evidence_artifacts"]
            .as_u64()
            .unwrap_or(0)
            >= 20
    );
    assert!(policy["minimum_unique_gate_scripts"].as_u64().unwrap_or(0) >= 10);

    let sources = source_texts(&root, &manifest)?;
    let e2e_refs = assert_test_refs_exist(&evidence["e2e_primary"], &sources)?;
    for expected in [
        "proof_traceability_test::gate_artifact_is_well_formed",
        "proof_traceability_test::every_binder_source_ref_resolves_in_current_tree",
        "proof_traceability_test::validation_envelope_matches_binder",
        "proof_traceability_test::evidence_artifacts_resolve_in_current_tree",
        "fpg_proof_core_test::gate_artifact_is_well_formed",
        "completion_harness_test::checker_emits_report_log_and_replays_static_gates",
        "completion_harness_test::every_proof_obligation_is_discharged_or_honestly_deferred",
    ] {
        assert!(e2e_refs.contains(expected), "missing e2e ref {expected}");
    }

    for command in evidence["e2e_primary"]["required_commands"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "commands array"))?
    {
        let command = command
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "command string"))?;
        if command.contains("cargo test") {
            assert!(
                command.contains("rch exec"),
                "cargo validation must be rch-backed: {command}"
            );
        }
    }
    Ok(())
}

#[test]
fn every_proof_obligation_is_discharged_or_honestly_deferred() -> TestResult {
    let root = workspace_root()?;
    let contract = read_json(&contract_path(&root))?;
    let binder = read_json(&root.join("tests/conformance/proof_obligations_binder.v1.json"))?;
    let decision = read_json(&root.join("tests/conformance/proof_program_owner_decision.v1.json"))?;

    let policy =
        &contract["completion_debt_evidence"]["proof_binder_contract"]["resolution_policy"];
    assert_eq!(
        decision["decision"]["choice"].as_str(),
        policy["decision_choice"].as_str(),
        "binder resolution policy should point at the recorded WS7 owner decision"
    );
    assert_eq!(
        binder["resolution_policy"]["decision_artifact"].as_str(),
        policy["decision_artifact"].as_str(),
        "binder should cite the proof-program owner decision artifact"
    );

    let allowed_statuses = string_set(&policy["allowed_final_statuses"])?;
    let required_deferred_fields = string_set(&policy["deferred_required_fields"])?;
    let obligations = binder["obligations"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "obligations array"))?;
    let minimum_resolved = policy["minimum_resolved_obligations"]
        .as_u64()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "minimum_resolved_obligations"))?
        as usize;
    assert!(
        obligations.len() >= minimum_resolved,
        "all proof obligations should be resolved by discharge or explicit deferral"
    );

    let mut deferred = 0usize;
    let mut discharged = 0usize;
    for obligation in obligations {
        let id = obligation["id"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "obligation id"))?;
        let status = obligation["status"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "obligation status"))?;
        assert!(
            allowed_statuses.contains(status),
            "{id} must be discharged or deferred, not {status}"
        );

        match status {
            "deferred" => {
                deferred += 1;
                for field in &required_deferred_fields {
                    let value = obligation
                        .get(field.as_str())
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .trim();
                    assert!(!value.is_empty(), "{id} deferred field {field} must be set");
                }
                let reason = obligation["deferred_reason"].as_str().unwrap_or_default();
                assert!(
                    reason.contains("bd-e4phe.1") && reason.contains("machine-checked"),
                    "{id} deferred_reason should cite the owner decision and machine-checking gap"
                );
                assert_eq!(
                    obligation["target_bead"].as_str(),
                    Some("bd-e4phe.2"),
                    "{id} should target the future mechanization bead"
                );
            }
            "discharged" => {
                discharged += 1;
                assert!(
                    obligation["evidence_artifacts"]
                        .as_array()
                        .is_some_and(|artifacts| !artifacts.is_empty()),
                    "{id} discharged obligations need evidence artifacts"
                );
                assert!(
                    obligation["verification_command"]
                        .as_str()
                        .is_some_and(|command| !command.trim().is_empty()),
                    "{id} discharged obligations need a verification command"
                );
            }
            _ => unreachable!("allowed_statuses was checked above"),
        }
    }

    assert_eq!(
        deferred + discharged,
        obligations.len(),
        "every obligation must have an explicit final disposition"
    );
    assert_eq!(
        deferred,
        obligations.len(),
        "bd-e4phe.1 selected conservative deferral until machine-checked artifacts exist"
    );
    Ok(())
}

#[test]
fn checker_emits_report_log_and_replays_static_gates() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "pass")?;
    let report =
        read_json(&out_dir.join("proof_obligations_binder_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-5fw.4.1"));
    assert_eq!(report["bead"].as_str(), Some("bd-5fw.4"));
    assert_eq!(report["summary"]["obligation_count"].as_u64(), Some(24));
    assert_eq!(report["summary"]["category_count"].as_u64(), Some(14));
    assert!(report["summary"]["source_ref_count"].as_u64().unwrap_or(0) >= 60);
    assert_eq!(report["summary"]["proof_core_rows"].as_u64(), Some(7));

    let rows = read_jsonl(&out_dir.join("proof_obligations_binder_completion_contract.log.jsonl"))?;
    assert_eq!(
        rows.len(),
        3,
        "checker should emit one row per completion item"
    );
    let events = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect::<BTreeSet<_>>();
    for event in [
        "proof_obligations_binder_contract_validated",
        "proof_obligations_binder_e2e_validated",
        "proof_obligations_binder_telemetry_validated",
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
                .is_some_and(|trace_id| trace_id.starts_with("bd-5fw.4.1:"))
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_required_obligation() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["proof_binder_contract"]["required_obligation_ids"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "obligation ids array"))?
        .push(Value::String("PO-DOES-NOT-EXIST".to_string()));

    let out_dir = unique_output_dir(&root, "missing-obligation")?;
    let stale_contract = out_dir.join("stale_contract.json");
    write_json(&stale_contract, &manifest)?;
    let output = run_checker(&root, &stale_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing obligation:\n{}",
        checker_output_message(&output)
    );
    assert!(
        checker_output_message(&output).contains("PO-DOES-NOT-EXIST"),
        "failure should identify obligation drift"
    );
    Ok(())
}

#[test]
fn checker_rejects_local_cargo_validation_command() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["e2e_primary"]["required_commands"][2] = Value::String(
        "cargo test -p frankenlibc-harness --test proof_traceability_freshness_test".to_string(),
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
        checker_output_message(&output).contains("telemetry required_fields missing trace_id"),
        "failure should identify telemetry drift"
    );
    Ok(())
}
