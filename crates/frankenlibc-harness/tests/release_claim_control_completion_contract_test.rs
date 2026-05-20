use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
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
    root.join("tests/conformance/release_claim_control_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_release_claim_control_completion_contract.sh")
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
        "release-claim-control-completion-{label}-{}-{nanos}",
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
            "FRANKENLIBC_RELEASE_CLAIM_CONTROL_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_RELEASE_CLAIM_CONTROL_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_RELEASE_CLAIM_CONTROL_COMPLETION_REPORT",
            out_dir.join("release_claim_control_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RELEASE_CLAIM_CONTROL_COMPLETION_LOG",
            out_dir.join("release_claim_control_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_RELEASE_CLAIM_CONTROL_CURRENT_CLAIM_REPORT",
            out_dir.join("release_claim_control_completion_contract.current_claim.report.json"),
        )
        .env(
            "FRANKENLIBC_RELEASE_CLAIM_CONTROL_CURRENT_CLAIM_LOG",
            out_dir.join("release_claim_control_completion_contract.current_claim.log.jsonl"),
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

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let items = value.as_array().ok_or("expected array")?;
    let mut strings = BTreeSet::new();
    for item in items {
        strings.insert(item.as_str().ok_or("expected string")?.to_string());
    }
    Ok(strings)
}

fn assert_checker_failed(output: &Output) {
    assert!(
        !output.status.success(),
        "checker unexpectedly passed:\n{}",
        output_text(output)
    );
}

#[test]
fn manifest_binds_release_claim_control_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("release_claim_control_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-w2c3.10"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-w2c3.10.4")
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

    let missing_items: BTreeSet<_> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings must be array")?
        .iter()
        .filter_map(|item| item["id"].as_str().map(str::to_string))
        .collect();
    assert_eq!(
        missing_items,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.e2e.primary".to_string(),
        ])
    );

    let release = &manifest["required_release_control_contract"];
    assert_eq!(
        release["replacement_levels"]["current_level"].as_str(),
        Some("L1")
    );
    assert_eq!(
        release["replacement_levels"]["current_release_level"].as_str(),
        Some("L1")
    );
    assert_eq!(
        release["support_matrix_maintenance"]["native_coverage_pct"].as_f64(),
        Some(100.0)
    );
    assert_eq!(release["release_dossier"]["verdict"].as_str(), Some("PASS"));
    assert_eq!(
        release["claim_reconciliation"]["summary"]["total_findings"].as_u64(),
        Some(0)
    );
    assert_eq!(
        release["closure_sweep"]["summary"]["closure_ready"].as_bool(),
        Some(false)
    );
    assert_eq!(
        string_set(&release["release_claim_gate"]["fail_closed_signatures"])?,
        BTreeSet::from([
            "release_claim_missing_l2_evidence".to_string(),
            "release_claim_missing_l3_evidence".to_string(),
        ])
    );

    Ok(())
}

#[test]
fn checker_validates_release_claim_control_contract_and_emits_report_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "valid")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("release_claim_control_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("release_claim_control_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-w2c3.10"));
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-w2c3.10.4")
    );
    assert_eq!(
        report["release_control_summary"]["replacement_levels"]["current_level"].as_str(),
        Some("L1")
    );
    assert_eq!(
        report["release_control_summary"]["support_matrix_maintenance"]["status_counts"]
            ["Implemented"]
            .as_u64(),
        Some(3705)
    );
    assert_eq!(
        report["release_control_summary"]["release_claim_gate"]["status"].as_str(),
        Some("pass")
    );
    assert_eq!(
        report["source_gate_results"]["release_claim_current_policy"]["status"].as_str(),
        Some("pass")
    );

    let rows = read_jsonl(&out_dir.join("release_claim_control_completion_contract.log.jsonl"))?;
    let mut events = BTreeSet::new();
    for row in &rows {
        events.insert(row["event"].as_str().ok_or("event")?.to_string());
    }
    for event in [
        "release_claim_control_manifest_verified",
        "replacement_levels_policy_verified",
        "support_matrix_maintenance_bound",
        "release_dossier_policy_bound",
        "claim_reconciliation_bound",
        "closure_protocol_bound",
        "release_claim_current_policy_replayed",
        "release_claim_control_completion_contract_pass",
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
            "status",
            "outcome",
            "artifact_refs",
            "failure_signature",
            "details",
        ] {
            assert!(!row[field].is_null(), "log row missing {field}: {row}");
        }
    }

    let current_claim = read_json(
        &out_dir.join("release_claim_control_completion_contract.current_claim.report.json"),
    )?;
    assert_eq!(current_claim["status"].as_str(), Some("pass"));
    assert_eq!(current_claim["current_release_level"].as_str(), Some("L1"));

    Ok(())
}

#[test]
fn checker_rejects_missing_required_test_binding() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing-test")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let refs = manifest["missing_item_bindings"][0]["required_test_refs"]
        .as_array_mut()
        .ok_or("unit test refs must be array")?;
    refs.retain(|item| {
        item["name"].as_str() != Some("claim_drift_guard_consistent_with_readme_and_release_policy")
    });
    let mutated = out_dir.join("release_claim_control_missing_test.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("release_claim_control_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("missing_item_bindings.tests.unit.primary.required_test_refs"),
        "{}",
        output_text(&output)
    );

    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_command() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "bare-cargo")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["missing_item_bindings"][0]["required_commands"][0] = json!(
        "cargo test -p frankenlibc-harness --test release_claim_control_completion_contract_test"
    );
    let mutated = out_dir.join("release_claim_control_bare_cargo.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("release_claim_control_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("cargo command must be rch-backed"),
        "{}",
        output_text(&output)
    );

    Ok(())
}

#[test]
fn checker_rejects_wrong_current_level_expectation() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "wrong-level")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_release_control_contract"]["replacement_levels"]["current_level"] =
        json!("L0");
    let mutated = out_dir.join("release_claim_control_wrong_level.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("release_claim_control_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("replacement_levels.current_level"),
        "{}",
        output_text(&output)
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_release_claim_log_field_binding() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing-log-field")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let fields =
        manifest["required_release_control_contract"]["release_claim_gate"]["required_log_fields"]
            .as_array_mut()
            .ok_or("required log fields must be array")?;
    let removed = fields
        .pop()
        .ok_or("required log fields must not be empty")?;
    assert_eq!(removed.as_str(), Some("failure_signature"));
    let mutated = out_dir.join("release_claim_control_missing_log_field.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("release_claim_control_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("release_claim_gate.required_log_fields"),
        "{}",
        output_text(&output)
    );

    Ok(())
}
