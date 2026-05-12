//! Completion contract tests for bd-1j4.5.1 integrated hard-parts evidence.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

static CHECKER_LOCK: Mutex<()> = Mutex::new(());

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/hard_parts_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_hard_parts_completion_contract.sh")
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

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "hard-parts-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_HARD_PARTS_COMPLETION_CONTRACT", contract)
        .env(
            "FRANKENLIBC_HARD_PARTS_COMPLETION_REPORT",
            out_dir.join("hard_parts_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_HARD_PARTS_COMPLETION_LOG",
            out_dir.join("hard_parts_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn checker_message(output: &std::process::Output) -> String {
    format!(
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn run_passing_checker(root: &Path, label: &str) -> TestResult<PathBuf> {
    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let out_dir = unique_out_dir(root, label)?;
    let output = run_checker(root, &contract_path(root), &out_dir)?;
    assert!(output.status.success(), "{}", checker_message(&output));
    Ok(out_dir)
}

fn string_set(value: &serde_json::Value) -> BTreeSet<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn manifest_binds_bd1j45_completion_items() -> TestResult {
    let root = workspace_root();
    let contract = read_json(&contract_path(&root))?;

    assert_eq!(
        contract["schema_version"].as_str(),
        Some("hard_parts_completion_contract.v1")
    );
    assert_eq!(contract["bead"].as_str(), Some("bd-1j4.5"));
    assert_eq!(
        contract["completion_debt_bead"].as_str(),
        Some("bd-1j4.5.1")
    );

    let evidence = &contract["completion_debt_evidence"];
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-1j4.5"));
    assert_eq!(evidence["next_audit_score_threshold"].as_u64(), Some(800));

    let missing_items: BTreeSet<String> = evidence["missing_item_bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|binding| {
            binding["missing_item_id"]
                .as_str()
                .expect("missing item id")
                .to_string()
        })
        .collect();
    assert_eq!(
        missing_items,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.fuzz.primary".to_string(),
            "tests.conformance.primary".to_string(),
            "telemetry.primary".to_string(),
        ])
    );

    let subsystems = string_set(&evidence["conformance_primary"]["required_subsystems"]);
    for required in ["startup", "threading", "resolver", "nss", "locale", "iconv"] {
        assert!(subsystems.contains(required));
    }
    assert_eq!(
        evidence["fuzz_primary"]["corpus_requirements"]
            .as_array()
            .unwrap()
            .len(),
        7
    );

    Ok(())
}

#[test]
fn checker_passes_and_emits_report_log() -> TestResult {
    let root = workspace_root();
    let out_dir = run_passing_checker(&root, "pass")?;
    let report = read_json(&out_dir.join("hard_parts_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["event"].as_str(),
        Some("hard_parts_completion.completion_contract_validated")
    );
    assert!(report["unit_test_ref_count"].as_u64().unwrap_or_default() >= 6);
    assert!(report["e2e_artifact_count"].as_u64().unwrap_or_default() >= 4);
    assert!(
        report["fuzz_corpus_seed_count"]
            .as_u64()
            .unwrap_or_default()
            >= 35
    );
    assert!(
        report["conformance_test_ref_count"]
            .as_u64()
            .unwrap_or_default()
            >= 5
    );
    assert_eq!(
        report["component_contract_count"]
            .as_u64()
            .unwrap_or_default(),
        4
    );

    let rows = read_jsonl(&out_dir.join("hard_parts_completion_contract.log.jsonl"))?;
    let events: BTreeSet<String> = rows
        .iter()
        .filter_map(|row| row["event"].as_str().map(str::to_string))
        .collect();
    for required in [
        "hard_parts_completion.source_ref",
        "hard_parts_completion.missing_item_bound",
        "hard_parts_completion.component_contract_bound",
        "hard_parts_completion.fuzz_corpus_bound",
        "hard_parts_completion.conformance_artifact_bound",
        "hard_parts_completion.completion_contract_validated",
    ] {
        assert!(
            events.contains(required),
            "missing telemetry event {required}: {events:?}"
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_fuzz_corpus_binding() -> TestResult {
    let root = workspace_root();
    let mut contract = read_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["fuzz_primary"]["corpus_requirements"]
        .as_array_mut()
        .unwrap()
        .retain(|requirement| requirement["artifact"].as_str() != Some("fuzz_setjmp_corpus"));

    let out_dir = unique_out_dir(&root, "missing-fuzz-corpus")?;
    let tampered = out_dir.join("contract.json");
    write_json(&tampered, &contract)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &tampered, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for missing fuzz corpus binding"
    );
    let message = checker_message(&output);
    assert!(
        message.contains("fuzz corpus requirements"),
        "unexpected checker output: {message}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_required_subsystem() -> TestResult {
    let root = workspace_root();
    let mut contract = read_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["conformance_primary"]["required_subsystems"]
        .as_array_mut()
        .unwrap()
        .retain(|subsystem| subsystem.as_str() != Some("iconv"));

    let out_dir = unique_out_dir(&root, "missing-subsystem")?;
    let tampered = out_dir.join("contract.json");
    write_json(&tampered, &contract)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &tampered, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for missing required subsystem binding"
    );
    let message = checker_message(&output);
    assert!(
        message.contains("required subsystems"),
        "unexpected checker output: {message}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_field() -> TestResult {
    let root = workspace_root();
    let mut contract = read_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["telemetry_primary"]["required_fields"]
        .as_array_mut()
        .unwrap()
        .retain(|field| field.as_str() != Some("failure_signature"));

    let out_dir = unique_out_dir(&root, "missing-telemetry")?;
    let tampered = out_dir.join("contract.json");
    write_json(&tampered, &contract)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &tampered, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for missing telemetry field"
    );
    let fields = string_set(
        &read_json(&out_dir.join("hard_parts_completion_contract.report.json"))?["missing_items"],
    );
    assert!(fields.contains("telemetry.primary"));
    let message = checker_message(&output);
    assert!(
        message.contains("telemetry fields missing"),
        "unexpected checker output: {message}"
    );
    Ok(())
}
