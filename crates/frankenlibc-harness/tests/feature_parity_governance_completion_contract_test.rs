use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = manifest_dir
        .parent()
        .ok_or("crate directory must have workspace parent")?;
    let repo_root = workspace_dir
        .parent()
        .ok_or("workspace parent must have repo root")?;
    Ok(repo_root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/feature_parity_governance_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_feature_parity_governance_completion_contract.sh")
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
        "feature-parity-governance-completion-{label}-{}-{nanos}",
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
            "FRANKENLIBC_FEATURE_PARITY_GOVERNANCE_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_FEATURE_PARITY_GOVERNANCE_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_FEATURE_PARITY_GOVERNANCE_COMPLETION_REPORT",
            out_dir.join("feature_parity_governance_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_FEATURE_PARITY_GOVERNANCE_COMPLETION_LOG",
            out_dir.join("feature_parity_governance_completion_contract.log.jsonl"),
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

fn string_set(value: &Value, context: &str) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| format!("{context} must be an array"))?
        .iter()
        .enumerate()
        .map(|(index, item)| -> TestResult<String> {
            Ok(item
                .as_str()
                .ok_or_else(|| format!("{context}[{index}] must be a string"))?
                .to_string())
        })
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
fn manifest_binds_track0_governance_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("feature_parity_governance_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-w2c3.1"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-w2c3.1.4")
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
            "tests.conformance.primary".to_string(),
        ])
    );

    let track0 = &manifest["required_track0_contract"];
    assert_eq!(
        string_set(
            &track0["child_beads"],
            "required_track0_contract.child_beads"
        )?,
        BTreeSet::from([
            "bd-w2c3.1.1".to_string(),
            "bd-w2c3.1.2".to_string(),
            "bd-w2c3.1.3".to_string(),
        ])
    );
    assert_eq!(
        track0["ledger_expectations"]["gap_count"].as_u64(),
        Some(110)
    );
    assert_eq!(track0["drift_expectations"]["fail_count"].as_u64(), Some(0));
    assert_eq!(
        track0["coverage_expectations"]["uncovered_gaps"].as_u64(),
        Some(0)
    );

    Ok(())
}

#[test]
fn checker_validates_track0_governance_contract_and_emits_report_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "valid")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        read_json(&out_dir.join("feature_parity_governance_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("feature_parity_governance_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-w2c3.1"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-w2c3.1.4"));
    assert_eq!(report["track0_summary"]["ledger_gaps"].as_u64(), Some(110));
    assert_eq!(
        report["track0_summary"]["drift_diagnostics"].as_u64(),
        Some(110)
    );
    assert_eq!(
        report["track0_summary"]["coverage_uncovered_gaps"].as_u64(),
        Some(0)
    );
    assert_eq!(
        report["source_gate_results"]["gap_ledger"]["status"].as_str(),
        Some("pass")
    );
    assert_eq!(
        report["source_gate_results"]["drift"]["status"].as_str(),
        Some("pass")
    );
    assert_eq!(
        report["source_gate_results"]["coverage"]["status"].as_str(),
        Some("pass")
    );

    let rows =
        read_jsonl(&out_dir.join("feature_parity_governance_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = rows
        .iter()
        .enumerate()
        .map(|(index, row)| -> TestResult<String> {
            Ok(row["event"]
                .as_str()
                .ok_or_else(|| format!("log row {index} event must be a string: {row}"))?
                .to_string())
        })
        .collect::<TestResult<_>>()?;
    for event in [
        "track0_governance_gap_ledger_verified",
        "track0_governance_drift_gate_verified",
        "track0_governance_coverage_gate_verified",
        "track0_governance_completion_contract_pass",
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

    Ok(())
}

#[test]
fn checker_rejects_missing_required_conformance_command() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing-command")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let commands = manifest["missing_item_bindings"][2]["required_commands"]
        .as_array_mut()
        .ok_or("conformance commands must be array")?;
    commands.retain(|command| {
        command.as_str() != Some("bash scripts/check_feature_parity_gap_ledger.sh")
    });
    let mutated = out_dir.join("feature_parity_governance_missing_command.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("feature_parity_governance_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("missing_item_bindings.tests.conformance.primary.required_commands"),
        "report should cite missing conformance command: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_required_test_ref() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing-test")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let refs = manifest["missing_item_bindings"][1]["required_test_refs"]
        .as_array_mut()
        .ok_or("e2e refs must be array")?;
    refs.retain(|entry| {
        entry["name"].as_str() != Some("gate_fails_when_unresolved_drift_loses_owner")
    });
    let mutated = out_dir.join("feature_parity_governance_missing_test.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("feature_parity_governance_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("gate_fails_when_unresolved_drift_loses_owner"),
        "report should cite missing e2e binding: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_dashboard_section() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing-section")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_track0_contract"]["required_dashboard_sections"]
        .as_array_mut()
        .ok_or("dashboard sections must be array")?
        .push(json!("## Missing Governance Section"));
    let mutated = out_dir.join("feature_parity_governance_missing_section.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("feature_parity_governance_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("dashboard missing required section"),
        "report should cite missing dashboard section: {report}"
    );

    Ok(())
}
