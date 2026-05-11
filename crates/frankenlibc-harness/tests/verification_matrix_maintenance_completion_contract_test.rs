use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory has workspace parent")
        .parent()
        .expect("workspace parent has repo root")
        .to_path_buf()
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/verification_matrix_maintenance_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_verification_matrix_maintenance_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
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

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "verification-matrix-maintenance-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    let beads_fixture = out_dir.join("verification_matrix_maintenance_empty_beads.jsonl");
    std::fs::write(&beads_fixture, "")?;
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_VERIFY_MATRIX_MAINT_CONTRACT", contract)
        .env("FRANKENLIBC_VERIFY_MATRIX_MAINT_OUT_DIR", out_dir)
        .env("FRANKENLIBC_VERIFY_MATRIX_MAINT_BEADS", beads_fixture)
        .env(
            "FRANKENLIBC_VERIFY_MATRIX_MAINT_REPORT",
            out_dir.join("verification_matrix_maintenance_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_VERIFY_MATRIX_MAINT_LOG",
            out_dir.join("verification_matrix_maintenance_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_VERIFY_MATRIX_MAINT_SYNC_TRANSCRIPT",
            out_dir.join("verification_matrix_maintenance_completion_contract.sync.txt"),
        )
        .env(
            "FRANKENLIBC_VERIFY_MATRIX_MAINT_MATRIX_TRANSCRIPT",
            out_dir.join("verification_matrix_maintenance_completion_contract.matrix.txt"),
        )
        .env(
            "FRANKENLIBC_VERIFY_MATRIX_MAINT_DRIFT_TRANSCRIPT",
            out_dir.join("verification_matrix_maintenance_completion_contract.drift.txt"),
        )
        .output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn string_set(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("expected array")
        .iter()
        .map(|item| item.as_str().expect("expected string").to_string())
        .collect()
}

fn assert_checker_failed(output: &Output) {
    assert!(
        !output.status.success(),
        "checker unexpectedly passed:\n{}",
        output_text(output)
    );
}

#[test]
fn manifest_binds_verification_matrix_maintenance_evidence() -> TestResult {
    let root = repo_root();
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("verification_matrix_maintenance_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-1o4k"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-1o4k.1"));
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items_closed"]),
        BTreeSet::from([
            "tests.integration.primary".to_string(),
            "tests.conformance.primary".to_string(),
        ])
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?;
    for (artifact_id, path) in source_artifacts {
        let rel = path.as_str().ok_or("source artifact path must be string")?;
        assert!(
            root.join(rel).is_file(),
            "source artifact {artifact_id} missing at {rel}"
        );
    }

    let contract = &manifest["required_matrix_contract"];
    assert_eq!(contract["matrix_version"].as_u64(), Some(1));
    assert_eq!(contract["row_schema_version"].as_str(), Some("v1"));
    assert_eq!(contract["entry_count"].as_u64(), Some(118));
    assert_eq!(contract["total_critique_beads"].as_u64(), Some(118));
    assert_eq!(contract["coverage_counts"]["complete"].as_u64(), Some(41));
    assert_eq!(contract["coverage_counts"]["partial"].as_u64(), Some(1));
    assert_eq!(contract["coverage_counts"]["missing"].as_u64(), Some(76));

    let integration_names: BTreeSet<_> =
        manifest["completion_debt_evidence"]["integration_primary"]["required_test_refs"]
            .as_array()
            .ok_or("integration required test refs must be array")?
            .iter()
            .map(|entry| entry["name"].as_str().expect("test name").to_string())
            .collect();
    assert!(integration_names.contains("all_critique_beads_have_rows"));
    assert!(integration_names.contains("dashboard_coverage_stats_consistent"));
    assert!(integration_names.contains("checker_replays_sync_and_matrix_gates"));

    let conformance_names: BTreeSet<_> =
        manifest["completion_debt_evidence"]["conformance_primary"]["required_test_refs"]
            .as_array()
            .ok_or("conformance required test refs must be array")?
            .iter()
            .map(|entry| entry["name"].as_str().expect("test name").to_string())
            .collect();
    assert!(conformance_names.contains("matrix_exists_and_valid_json"));
    assert!(conformance_names.contains("verification_matrix_artifact_is_present_and_well_formed"));

    Ok(())
}

#[test]
fn checker_validates_matrix_maintenance_contract_and_emits_report_log() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "valid")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(
        &out_dir.join("verification_matrix_maintenance_completion_contract.report.json"),
    )?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("verification_matrix_maintenance_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-1o4k"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-1o4k.1"));
    assert_eq!(report["matrix_summary"]["entry_count"].as_u64(), Some(118));
    assert_eq!(
        report["matrix_summary"]["missing_open_critique_rows"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(report["gate_results"].as_array().map(Vec::len), Some(3));
    assert_eq!(
        report["integration_bindings"].as_array().map(Vec::len),
        Some(11)
    );
    assert_eq!(
        report["conformance_bindings"].as_array().map(Vec::len),
        Some(10)
    );
    assert_eq!(report["events"].as_array().map(Vec::len), Some(5));

    for (file, sentinel) in [
        (
            "verification_matrix_maintenance_completion_contract.matrix.txt",
            "check_verification_matrix: PASS",
        ),
        (
            "verification_matrix_maintenance_completion_contract.drift.txt",
            "check_matrix_drift: PASS",
        ),
    ] {
        let text = std::fs::read_to_string(out_dir.join(file))?;
        assert!(text.contains(sentinel), "{file} missing {sentinel}");
    }

    let rows =
        read_jsonl(&out_dir.join("verification_matrix_maintenance_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = rows
        .iter()
        .map(|row| row["event"].as_str().unwrap().to_string())
        .collect();
    for event in [
        "verification_matrix_maintenance_integration_bindings_verified",
        "verification_matrix_maintenance_conformance_bindings_verified",
        "verification_matrix_maintenance_gates_replayed",
        "verification_matrix_maintenance_contract_verified",
        "verification_matrix_maintenance_completion_contract_pass",
    ] {
        assert!(events.contains(event), "missing event {event}");
    }
    for row in rows {
        for field in [
            "timestamp",
            "trace_id",
            "event",
            "bead_id",
            "source_bead",
            "completion_debt_bead",
            "source_commit",
            "status",
            "outcome",
            "artifact_refs",
            "failure_signature",
            "details",
        ] {
            assert!(!row[field].is_null(), "log row missing {field}: {row}");
        }
    }

    Ok(())
}

#[test]
fn checker_replays_sync_and_matrix_gates() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "gates")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let sync_text = std::fs::read_to_string(
        out_dir.join("verification_matrix_maintenance_completion_contract.sync.txt"),
    )?;
    assert!(
        sync_text.trim().is_empty(),
        "sync --check should produce no drift transcript: {sync_text}"
    );
    let matrix_text = std::fs::read_to_string(
        out_dir.join("verification_matrix_maintenance_completion_contract.matrix.txt"),
    )?;
    assert!(matrix_text.contains("check_verification_matrix: PASS"));
    let drift_text = std::fs::read_to_string(
        out_dir.join("verification_matrix_maintenance_completion_contract.drift.txt"),
    )?;
    assert!(drift_text.contains("Missing rows: 0"));
    assert!(drift_text.contains("check_matrix_drift: PASS"));

    Ok(())
}

#[test]
fn checker_rejects_matrix_count_drift() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "count-drift")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_matrix_contract"]["entry_count"] = json!(9999);
    let mutated = out_dir.join("verification_matrix_maintenance_count_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(
        &out_dir.join("verification_matrix_maintenance_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"].to_string().contains("entry_count drift"),
        "report should cite matrix count drift: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_sync_helper_token() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing-token")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_matrix_contract"]["required_source_text"]["sync_helper"]
        .as_array_mut()
        .expect("sync helper needles array")
        .push(json!(
            "sync helper must emit this intentionally missing completion-token"
        ));
    let mutated = out_dir.join("verification_matrix_maintenance_missing_token.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(
        &out_dir.join("verification_matrix_maintenance_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"].to_string().contains("sync_helper"),
        "report should cite missing sync helper token: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_local_cargo_command() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "local-cargo")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["integration_primary"]["required_commands"] =
        json!(["cargo test -p frankenlibc-harness --test verification_matrix_test"]);
    let mutated = out_dir.join("verification_matrix_maintenance_local_cargo.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(
        &out_dir.join("verification_matrix_maintenance_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"].to_string().contains("rch-backed"),
        "report should cite local cargo command drift: {report}"
    );

    Ok(())
}
