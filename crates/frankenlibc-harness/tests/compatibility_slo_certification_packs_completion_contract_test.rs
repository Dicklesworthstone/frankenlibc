use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

static CHECKER_LOCK: Mutex<()> = Mutex::new(());

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory has workspace parent")
        .parent()
        .expect("workspace parent has repo parent")
        .to_path_buf()
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/compatibility_slo_certification_packs_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_compatibility_slo_certification_packs_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "compatibility_slo_certification_packs_completion_contract_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_COMPAT_CERT_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_COMPAT_CERT_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_COMPAT_CERT_COMPLETION_REPORT",
            out_dir.join("compatibility_slo_certification_packs_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_COMPAT_CERT_COMPLETION_LOG",
            out_dir.join("compatibility_slo_certification_packs_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn run_checker_serial(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    run_checker(root, contract, out_dir)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

fn string_values(value: &Value) -> TestResult<Vec<String>> {
    let array = value.as_array().ok_or("expected array")?;
    let mut values = Vec::with_capacity(array.len());
    for item in array {
        values.push(item.as_str().ok_or("expected string item")?.to_string());
    }
    Ok(values)
}

#[test]
fn manifest_binds_unit_and_e2e_completion_evidence() -> TestResult {
    let root = repo_root();
    let manifest = load_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("compatibility_slo_certification_packs_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-26xb.3"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-26xb.3.1")
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts object")?;
    for required in [
        "release_dossier_validator",
        "release_dossier_report",
        "release_dossier_gate",
        "release_dossier_harness",
        "workload_compatibility_contract",
        "workload_compatibility_gate",
        "workload_compatibility_harness",
        "user_compatibility_report",
        "completion_checker",
        "completion_harness_test",
    ] {
        let path = source_artifacts[required].as_str().ok_or("source path")?;
        assert!(root.join(path).exists(), "source artifact missing: {path}");
    }

    let bindings = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings array")?;
    let unit = bindings
        .iter()
        .find(|item| item["id"].as_str() == Some("tests.unit.primary"))
        .ok_or("tests.unit.primary binding")?;
    let e2e = bindings
        .iter()
        .find(|item| item["id"].as_str() == Some("tests.e2e.primary"))
        .ok_or("tests.e2e.primary binding")?;
    assert_eq!(unit["kind"].as_str(), Some("unit"));
    assert_eq!(e2e["kind"].as_str(), Some("e2e"));

    let unit_tests: Vec<_> = unit["required_test_refs"]
        .as_array()
        .ok_or("unit test refs")?
        .iter()
        .filter_map(|item| item.as_str())
        .collect();
    for required in [
        "dossier_artifact_results_have_required_fields",
        "dossier_integrity_index_consistent",
        "dossier_compatibility_policy_present",
        "checker_validates_compatibility_slo_certification_contract",
        "checker_rejects_missing_release_artifact_binding",
    ] {
        assert!(
            unit_tests.contains(&required),
            "missing unit ref {required}"
        );
    }

    let e2e_tests: Vec<_> = e2e["required_test_refs"]
        .as_array()
        .ok_or("e2e test refs")?
        .iter()
        .filter_map(|item| item.as_str())
        .collect();
    for required in [
        "dossier_validator_produces_valid_report",
        "dossier_validator_release_notes_hook_tracks_closed_beads",
        "dossier_validator_release_notes_hook_invalid_limit_falls_back_to_default",
        "workload_compatibility_dossier_test",
    ] {
        assert!(e2e_tests.contains(&required), "missing e2e ref {required}");
    }

    let release_report = load_json(&root.join("tests/release/dossier_validation_report.v1.json"))?;
    assert_eq!(release_report["status"].as_str(), Some("pass"));
    assert_eq!(release_report["verdict"].as_str(), Some("PASS"));
    assert_eq!(
        release_report["summary"]["total_artifacts"].as_u64(),
        Some(15)
    );
    assert_eq!(
        release_report["summary"]["critical_missing"].as_u64(),
        Some(0)
    );
    assert_eq!(
        release_report["release_notes_hook"]["summary"]["selected"].as_u64(),
        Some(8)
    );

    let workload =
        load_json(&root.join("tests/conformance/workload_compatibility_dossier.v1.json"))?;
    assert!(
        workload["required_dossier_fields"]
            .as_array()
            .ok_or("required_dossier_fields")?
            .iter()
            .any(|item| item.as_str() == Some("user_recommendation"))
    );

    let user_report = load_json(&root.join("tests/conformance/user_compatibility_report.v1.json"))?;
    assert!(
        user_report["required_report_fields"]
            .as_array()
            .ok_or("required_report_fields")?
            .iter()
            .any(|item| item.as_str() == Some("regeneration_command"))
    );

    Ok(())
}

#[test]
fn checker_validates_compatibility_slo_certification_contract() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker_serial(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("PASS: compatibility SLO certification-pack completion contract")
    );

    let report = load_json(
        &out_dir.join("compatibility_slo_certification_packs_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-26xb.3"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-26xb.3.1"));
    assert_eq!(report["summary"]["release_artifacts"].as_u64(), Some(15));
    assert_eq!(
        report["summary"]["valid_release_artifacts"].as_u64(),
        Some(14)
    );
    assert_eq!(report["summary"]["critical_missing"].as_u64(), Some(0));
    assert_eq!(
        report["summary"]["release_note_candidates"].as_u64(),
        Some(8)
    );
    assert_eq!(report["summary"]["source_artifacts"].as_u64(), Some(10));

    Ok(())
}

#[test]
fn checker_emits_completion_report_and_jsonl() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker_serial(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(
        &out_dir.join("compatibility_slo_certification_packs_completion_contract.report.json"),
    )?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("compatibility_slo_certification_packs_completion_contract.report.v1")
    );
    let events = string_values(&report["events"])?;
    for event in [
        "compatibility_slo_certification_completion_summary",
        "compatibility_slo_certification_release_dossier_artifacts",
        "compatibility_slo_certification_source_bindings",
        "compatibility_slo_certification_test_bindings",
        "compatibility_slo_certification_completion_contract_pass",
    ] {
        assert!(events.iter().any(|value| value == event), "missing {event}");
    }

    let rows = read_jsonl(
        &out_dir.join("compatibility_slo_certification_packs_completion_contract.log.jsonl"),
    )?;
    assert_eq!(rows.len(), 5, "checker should emit five telemetry rows");
    for row in rows {
        for field in [
            "timestamp",
            "event",
            "bead_id",
            "source_bead",
            "completion_debt_bead",
            "status",
            "outcome",
            "source_commit",
            "schema_version",
            "artifact_refs",
            "test_refs",
            "release_artifact_ids",
            "certification_pack_fields",
            "failure_signature",
        ] {
            assert!(!row[field].is_null(), "log row missing {field}: {row}");
        }
        assert_eq!(row["status"].as_str(), Some("pass"));
        assert_eq!(row["failure_signature"].as_str(), Some("none"));
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_release_artifact_binding() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_artifact")?;
    let mut manifest = load_json(&contract_path(&root))?;
    let ids = manifest["completion_debt_evidence"]["required_release_dossier_contract"]
        ["required_artifact_ids"]
        .as_array_mut()
        .ok_or("required_artifact_ids array")?;
    ids.retain(|item| item.as_str() != Some("release_gate_dag"));
    let mutated = out_dir.join("missing_release_artifact_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker_serial(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing release artifact binding:\n{}",
        output_text(&output)
    );
    let stderr_stdout = output_text(&output);
    assert!(
        stderr_stdout.contains("required_release_dossier_contract.required_artifact_ids")
            && stderr_stdout.contains("release_gate_dag"),
        "unexpected rejection output:\n{stderr_stdout}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_source_test_ref() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_test_ref")?;
    let mut manifest = load_json(&contract_path(&root))?;
    let refs = manifest["completion_debt_evidence"]["test_sources"]["release_dossier_harness"]
        ["required_test_refs"]
        .as_array_mut()
        .ok_or("required_test_refs array")?;
    refs.retain(|item| item.as_str() != Some("dossier_integrity_index_consistent"));
    let mutated = out_dir.join("missing_source_test_ref_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker_serial(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing source test ref:\n{}",
        output_text(&output)
    );
    let stderr_stdout = output_text(&output);
    assert!(
        stderr_stdout.contains("test_sources.release_dossier_harness.required_test_refs")
            && stderr_stdout.contains("dossier_integrity_index_consistent"),
        "unexpected rejection output:\n{stderr_stdout}"
    );

    Ok(())
}

#[test]
fn checker_rejects_unimplemented_telemetry_event() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "bad_event")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["telemetry_events"][0] = json!("todo_unimplemented_event");
    let mutated = out_dir.join("bad_telemetry_event_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker_serial(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject unknown telemetry event:\n{}",
        output_text(&output)
    );
    let stderr_stdout = output_text(&output);
    assert!(
        stderr_stdout.contains("unsupported event")
            && stderr_stdout.contains("todo_unimplemented_event"),
        "unexpected rejection output:\n{stderr_stdout}"
    );

    Ok(())
}
