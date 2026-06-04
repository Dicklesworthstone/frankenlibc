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
    root.join("tests/conformance/feature_parity_gap_ledger_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_feature_parity_gap_ledger_completion_contract.sh")
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
        "feature-parity-gap-ledger-completion-{label}-{}-{nanos}",
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
            "FRANKENLIBC_FEATURE_PARITY_GAP_LEDGER_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_FEATURE_PARITY_GAP_LEDGER_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_FEATURE_PARITY_GAP_LEDGER_COMPLETION_REPORT",
            out_dir.join("feature_parity_gap_ledger_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_FEATURE_PARITY_GAP_LEDGER_COMPLETION_LOG",
            out_dir.join("feature_parity_gap_ledger_completion_contract.log.jsonl"),
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
fn manifest_binds_gap_ledger_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("feature_parity_gap_ledger_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-w2c3.1.1"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-w2c3.1.1.1")
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

    let contract = &manifest["required_gap_ledger_contract"];
    assert_eq!(contract["schema_version"].as_str(), Some("v1"));
    assert_eq!(contract["bead"].as_str(), Some("bd-w2c3.1.1"));
    assert_eq!(contract["row_count"].as_u64(), Some(170));
    assert_eq!(contract["gap_count"].as_u64(), Some(110));
    assert_eq!(contract["delta_count"].as_u64(), Some(5));
    assert_eq!(contract["parse_error_count"].as_u64(), Some(0));
    assert_eq!(contract["done_evidence_audit_count"].as_u64(), Some(60));
    assert_eq!(
        string_set(&contract["required_ledger_arrays"])?,
        BTreeSet::from([
            "rows".to_string(),
            "deltas".to_string(),
            "gaps".to_string(),
            "done_evidence_audit".to_string(),
            "parse_errors".to_string(),
        ])
    );

    Ok(())
}

#[test]
fn checker_validates_gap_ledger_contract_and_emits_report_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "valid")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        read_json(&out_dir.join("feature_parity_gap_ledger_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("feature_parity_gap_ledger_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-w2c3.1.1"));
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-w2c3.1.1.1")
    );
    assert_eq!(
        report["gap_ledger_summary"]["row_count"].as_u64(),
        Some(170)
    );
    assert_eq!(
        report["gap_ledger_summary"]["gap_count"].as_u64(),
        Some(110)
    );
    assert_eq!(
        report["gap_ledger_summary"]["done_evidence_audit_count"].as_u64(),
        Some(60)
    );
    assert_eq!(
        report["gap_ledger_summary"]["done_log_row_count"].as_u64(),
        Some(60)
    );
    assert_eq!(report["source_gate"]["status"].as_str(), Some("pass"));

    let rows =
        read_jsonl(&out_dir.join("feature_parity_gap_ledger_completion_contract.log.jsonl"))?;
    let mut events = BTreeSet::new();
    for row in &rows {
        events.insert(row["event"].as_str().ok_or("event")?.to_string());
    }
    for event in [
        "gap_ledger_completion_manifest_verified",
        "gap_ledger_completion_source_gate_verified",
        "gap_ledger_completion_artifact_verified",
        "gap_ledger_completion_contract_pass",
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
fn checker_rejects_missing_required_test_binding() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing-test")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let refs = manifest["missing_item_bindings"][1]["required_test_refs"]
        .as_array_mut()
        .ok_or("e2e refs must be array")?;
    refs.retain(|entry| {
        entry["name"].as_str() != Some("gate_script_emits_done_evidence_log_and_report")
    });
    let mutated = out_dir.join("feature_parity_gap_ledger_missing_test.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("feature_parity_gap_ledger_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("gate_script_emits_done_evidence_log_and_report"),
        "report should cite missing e2e binding: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_command() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "non-rch")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["missing_item_bindings"][0]["required_commands"][0] = json!(
        "cargo test -p frankenlibc-harness --test feature_parity_gap_ledger_completion_contract_test"
    );
    let mutated = out_dir.join("feature_parity_gap_ledger_non_rch_command.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("feature_parity_gap_ledger_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("cargo command must be rch-backed"),
        "report should cite non-rch cargo command: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_wrong_gap_count() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "wrong-gap-count")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_gap_ledger_contract"]["gap_count"] = json!(109);
    let mutated = out_dir.join("feature_parity_gap_ledger_wrong_gap_count.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("feature_parity_gap_ledger_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"].to_string().contains("ledger gap count"),
        "report should cite gap-count mismatch: {report}"
    );

    Ok(())
}
