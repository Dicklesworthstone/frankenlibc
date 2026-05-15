use serde_json::Value;
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CONTRACT_REL: &str = "tests/conformance/br_db_repair_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_br_db_repair_completion_contract.sh";
const EXPECTED_EVENTS: &[&str] = &[
    "br_db_repair_completion_contract_validated",
    "source_contract_replayed",
    "read_only_probe_contract_checked",
    "missing_item_bindings_validated",
];
const CRITICAL_DISCREPANCIES: &[&str] = &[
    "db_jsonl_count_mismatch",
    "stale_blocked_cache",
    "conflicting_ready_lists",
    "timeout",
];

fn repo_root() -> TestResult<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| io::Error::other("crate directory has workspace parent"))?
        .parent()
        .ok_or_else(|| io::Error::other("workspace parent has repo parent"))?
        .to_path_buf();
    Ok(root)
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let text = std::fs::read_to_string(path)?;
    text.lines()
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

fn contract_path(root: &Path) -> PathBuf {
    root.join(CONTRACT_REL)
}

fn checker_path(root: &Path) -> PathBuf {
    root.join(CHECKER_REL)
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "br_db_repair_completion_contract_{label}_{}_{}",
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
        .env("FRANKENLIBC_BR_DB_REPAIR_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_BR_DB_REPAIR_COMPLETION_TARGET_DIR", out_dir)
        .env(
            "FRANKENLIBC_BR_DB_REPAIR_COMPLETION_REPORT",
            out_dir.join("br_db_repair_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_BR_DB_REPAIR_COMPLETION_LOG",
            out_dir.join("br_db_repair_completion_contract.log.jsonl"),
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

fn passing_checker(root: &Path, label: &str) -> TestResult<PathBuf> {
    let out = unique_out_dir(root, label)?;
    let output = run_checker(root, &contract_path(root), &out)?;
    assert!(output.status.success(), "{}", output_text(&output));
    Ok(out)
}

fn mutated_contract(
    root: &Path,
    label: &str,
    mutate: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let mut contract = load_json(&contract_path(root))?;
    mutate(&mut contract)?;
    let out = unique_out_dir(root, label)?;
    let path = out.join("mutated_contract.json");
    write_json(&path, &contract)?;
    Ok(path)
}

fn assert_checker_fails(root: &Path, contract: &Path, label: &str, expected: &str) -> TestResult {
    let out = unique_out_dir(root, label)?;
    let output = run_checker(root, contract, &out)?;
    assert!(!output.status.success(), "checker unexpectedly passed");
    assert!(
        output_text(&output).contains(expected),
        "expected failure text {expected}; {}",
        output_text(&output)
    );
    Ok(())
}

#[test]
fn manifest_binds_tracker_repair_sources_and_missing_items() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("br_db_repair_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-bp8fl.2.1"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.2.1.1")
    );

    for path in manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?
        .values()
    {
        let path = path.as_str().ok_or("source artifact path string")?;
        assert!(root.join(path).is_file(), "missing source artifact {path}");
    }

    let source_contracts = manifest["source_contracts"]
        .as_array()
        .ok_or("source_contracts must be array")?;
    let source_ids: BTreeSet<_> = source_contracts
        .iter()
        .filter_map(|source| source["id"].as_str())
        .collect();
    assert!(source_ids.contains("tracker_health_report"));
    assert!(source_ids.contains("br_bv_disagreement_dashboard"));

    for source in source_contracts {
        let required: BTreeSet<_> = source["required_discrepancies"]
            .as_array()
            .ok_or("required_discrepancies array")?
            .iter()
            .filter_map(|item| item.as_str())
            .collect();
        for discrepancy in CRITICAL_DISCREPANCIES {
            assert!(
                required.contains(discrepancy),
                "{} must require {discrepancy}",
                source["id"]
            );
        }
    }

    let item_ids: BTreeSet<_> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings must be array")?
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect();
    for item in [
        "tests.unit.primary",
        "tests.e2e.primary",
        "telemetry.primary",
    ] {
        assert!(item_ids.contains(item), "missing binding {item}");
    }

    let allowed_commands = manifest["read_only_probe_contract"]["allowed_commands"]
        .as_array()
        .ok_or("allowed commands array")?;
    for command in allowed_commands {
        let command = command.as_str().ok_or("command string")?;
        assert!(!command.contains("br sync --flush-only"));
        assert!(!command.contains("br close"));
        assert!(!command.contains("rm -rf"));
    }
    Ok(())
}

#[test]
fn checker_replays_source_contracts_and_emits_telemetry() -> TestResult {
    let root = repo_root()?;
    let out = passing_checker(&root, "pass")?;
    let report = load_json(&out.join("br_db_repair_completion_contract.report.json"))?;
    let log = read_jsonl(&out.join("br_db_repair_completion_contract.log.jsonl"))?;

    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-bp8fl.2.1"));
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.2.1.1")
    );
    assert_eq!(report["summary"]["source_contract_count"].as_u64(), Some(2));
    assert_eq!(report["summary"]["missing_item_count"].as_u64(), Some(3));
    assert_eq!(
        report["summary"]["destructive_commands_blocked"].as_bool(),
        Some(true)
    );

    let events: BTreeSet<_> = log.iter().filter_map(|row| row["event"].as_str()).collect();
    for event in EXPECTED_EVENTS {
        assert!(events.contains(event), "missing event {event}");
    }
    assert!(log.len() >= 5);
    Ok(())
}

#[test]
fn checker_preserves_tracker_failure_as_tooling_not_code_failure() -> TestResult {
    let root = repo_root()?;
    let out = passing_checker(&root, "tooling")?;
    let report = load_json(&out.join("br_db_repair_completion_contract.report.json"))?;
    assert_eq!(
        report["summary"]["tool_failures_are_tracker_evidence"].as_bool(),
        Some(true)
    );

    let source_contracts = report["source_contracts"]
        .as_array()
        .ok_or("source_contracts must be array")?;
    let tracker = source_contracts
        .iter()
        .find(|row| row["id"].as_str() == Some("tracker_health_report"))
        .ok_or("tracker source result missing")?;
    let tracker_report_path = tracker["checker_report"]
        .as_str()
        .ok_or("tracker checker_report must be string")?;
    let tracker_report = load_json(&root.join(tracker_report_path))?;
    assert_eq!(
        tracker_report["summary"]["tool_failures_are_not_code_failures"].as_bool(),
        Some(true)
    );

    let dashboard = source_contracts
        .iter()
        .find(|row| row["id"].as_str() == Some("br_bv_disagreement_dashboard"))
        .ok_or("dashboard source result missing")?;
    let dashboard_report_path = dashboard["checker_report"]
        .as_str()
        .ok_or("dashboard checker_report must be string")?;
    let dashboard_report = load_json(&root.join(dashboard_report_path))?;
    assert_eq!(
        dashboard_report["summary"]["tool_failures_are_not_code_failures"].as_bool(),
        Some(true)
    );
    assert!(
        dashboard_report["summary"]["blocked_claim_rows"]
            .as_u64()
            .unwrap_or_default()
            >= 1,
        "dashboard must preserve blocked claim rows for tracker failures"
    );
    Ok(())
}

#[test]
fn checker_rejects_destructive_probe_command() -> TestResult {
    let root = repo_root()?;
    let mutated = mutated_contract(&root, "destructive", |contract| {
        contract["read_only_probe_contract"]["allowed_commands"]
            .as_array_mut()
            .ok_or("allowed commands must be array")?
            .push(Value::String("br sync --flush-only --json".to_string()));
        Ok(())
    })?;
    assert_checker_fails(&root, &mutated, "destructive-fail", "destructive command")
}

#[test]
fn checker_rejects_missing_critical_discrepancy() -> TestResult {
    let root = repo_root()?;
    let mutated = mutated_contract(&root, "missing-discrepancy", |contract| {
        let source = &mut contract["source_contracts"][0]["required_discrepancies"];
        source
            .as_array_mut()
            .ok_or("required discrepancies must be array")?
            .retain(|item| item.as_str() != Some("stale_blocked_cache"));
        Ok(())
    })?;
    assert_checker_fails(
        &root,
        &mutated,
        "missing-discrepancy-fail",
        "critical discrepancies",
    )
}

#[test]
fn checker_rejects_missing_telemetry_binding() -> TestResult {
    let root = repo_root()?;
    let mutated = mutated_contract(&root, "missing-telemetry", |contract| {
        let items = contract["missing_item_bindings"]
            .as_array_mut()
            .ok_or("missing item bindings must be array")?;
        items.retain(|item| item["id"].as_str() != Some("telemetry.primary"));
        Ok(())
    })?;
    assert_checker_fails(
        &root,
        &mutated,
        "missing-telemetry-fail",
        "missing_item_bindings must include",
    )
}
