use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate directory should have workspace parent")?;
    let root = crate_dir
        .parent()
        .ok_or("workspace parent should have repo parent")?;
    Ok(root.to_path_buf())
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/br_exact_id_split_brain_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_br_exact_id_split_brain_completion_contract.sh")
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "br_exact_id_split_brain_completion_contract_{label}_{}_{}",
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
        .env("FRANKENLIBC_BR_EXACT_ID_COMPLETION_CONTRACT", contract)
        .env(
            "FRANKENLIBC_BR_EXACT_ID_COMPLETION_ALLOW_DEGRADED_TRACKER",
            "1",
        )
        .env(
            "FRANKENLIBC_BR_EXACT_ID_COMPLETION_REPORT",
            out_dir.join("br_exact_id_split_brain_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_BR_EXACT_ID_COMPLETION_LOG",
            out_dir.join("br_exact_id_split_brain_completion_contract.log.jsonl"),
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

fn log_records(path: &Path) -> TestResult<Vec<Value>> {
    let text = std::fs::read_to_string(path)?;
    text.lines()
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

#[test]
fn manifest_binds_exact_id_commands_and_missing_items() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("br_exact_id_split_brain_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-uaut8"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-uaut8.1")
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?;
    for (artifact_id, path) in source_artifacts {
        let path = path.as_str().ok_or("artifact path must be string")?;
        assert!(
            root.join(path).exists(),
            "source artifact {artifact_id} missing at {path}"
        );
    }

    let probe_ids: Vec<&str> = manifest["live_read_only_probe_contract"]["required_probe_ids"]
        .as_array()
        .ok_or("required_probe_ids must be array")?
        .iter()
        .filter_map(|id| id.as_str())
        .collect();
    for required in ["bd-bp8fl.2.1", "bd-bp8fl.10", "bd-bp8fl.2.7", "bd-rm999"] {
        assert!(probe_ids.contains(&required), "missing probe id {required}");
    }

    let exact_commands: Vec<&str> = manifest["live_read_only_probe_contract"]
        ["exact_id_probe_commands"]
        .as_array()
        .ok_or("exact_id_probe_commands must be array")?
        .iter()
        .filter_map(|command| command.as_str())
        .collect();
    assert!(exact_commands.contains(&"br show <id> --json"));
    assert!(exact_commands.contains(&"br --no-db show <id> --json"));

    let item_ids: Vec<&str> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings must be array")?
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect();
    for required in [
        "tests.unit.primary",
        "tests.e2e.primary",
        "tests.conformance.primary",
    ] {
        assert!(
            item_ids.contains(&required),
            "missing item binding {required}"
        );
    }

    let test_source = std::fs::read_to_string(root.join(file!()))?;
    for test_ref in manifest["completion_debt_evidence"]["required_test_refs"]
        .as_array()
        .ok_or("required_test_refs must be array")?
    {
        let test_ref = test_ref.as_str().ok_or("test ref must be string")?;
        assert!(
            test_source.contains(test_ref),
            "required test ref {test_ref} missing from this test source"
        );
    }

    Ok(())
}

#[test]
fn checker_replays_live_read_only_tracker_commands() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "live")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("br_exact_id_split_brain_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("br_exact_id_split_brain_completion_contract.report.v1")
    );
    assert_eq!(report["original_bead"].as_str(), Some("bd-uaut8"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-uaut8.1"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["exact_id_probe_count"].as_u64(), Some(4));
    assert_eq!(
        report["summary"]["read_only_tracker_commands_only"].as_bool(),
        Some(true)
    );

    for probe in report["live_read_only_probes"]
        .as_array()
        .ok_or("live_read_only_probes must be array")?
    {
        assert_eq!(probe["status_agrees"].as_bool(), Some(true));
        assert!(probe["db_status"].as_str().is_some());
        assert_eq!(probe["db_status"], probe["no_db_status"]);
    }

    Ok(())
}

#[test]
fn checker_validates_source_artifacts_and_structured_logs() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "logs")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("br_exact_id_split_brain_completion_contract.report.json"))?;
    assert_eq!(report["summary"]["source_contract_count"].as_u64(), Some(2));
    assert_eq!(report["summary"]["missing_item_count"].as_u64(), Some(3));
    assert!(
        report["summary"]["log_row_count"]
            .as_u64()
            .unwrap_or_default()
            >= 13,
        "expected source, exact-id, graph, and health log rows"
    );

    let records =
        log_records(&out_dir.join("br_exact_id_split_brain_completion_contract.log.jsonl"))?;
    let events: Vec<&str> = records
        .iter()
        .filter_map(|record| record["event"].as_str())
        .collect();
    for event in [
        "br_exact_id_completion_source_gate",
        "br_exact_id_completion_named_probe",
        "br_exact_id_completion_graph_probe",
        "br_exact_id_completion_health_probe",
    ] {
        assert!(events.contains(&event), "missing event {event}");
    }

    for (index, record) in records.iter().enumerate() {
        for field in [
            "timestamp",
            "trace_id",
            "level",
            "event",
            "bead_id",
            "stream",
            "gate",
            "scenario_id",
            "runtime_mode",
            "replacement_level",
            "api_family",
            "symbol",
            "oracle_kind",
            "expected",
            "actual",
            "source_commit",
            "target_dir",
            "failure_signature",
            "artifact_refs",
        ] {
            assert!(record.get(field).is_some(), "row {index} missing {field}");
        }
        let line = serde_json::to_string(record)?;
        validate_log_line(&line, index + 1).map_err(|errors| {
            std::io::Error::other(format!("structured log row {index} rejected: {errors:?}"))
        })?;
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_exact_id_probe() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_probe")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["live_read_only_probe_contract"]["required_probe_ids"] =
        json!(["bd-bp8fl.2.1", "bd-bp8fl.10", "bd-bp8fl.2.7"]);
    let bad_contract = out_dir.join("missing_probe_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing probe\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("bd-rm999"),
        "error should name the missing probe"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_source_discrepancy() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_discrepancy")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["source_contracts"][0]["required_discrepancies"] =
        json!(["exact_id_split_brain", "missing_new_discrepancy"]);
    let bad_contract = out_dir.join("missing_discrepancy_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing source discrepancy\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("missing_new_discrepancy"),
        "error should name the missing discrepancy"
    );

    Ok(())
}
