//! Completion contract tests for bd-1j4.2.1 RTLD phase-1 evidence.

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
    root.join("tests/conformance/rtld_phase1_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_rtld_phase1_completion_contract.sh")
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
        "rtld-phase1-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_RTLD_PHASE1_CONTRACT", contract)
        .env(
            "FRANKENLIBC_RTLD_PHASE1_REPORT",
            out_dir.join("rtld_phase1_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RTLD_PHASE1_LOG",
            out_dir.join("rtld_phase1_completion_contract.log.jsonl"),
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
fn manifest_binds_rtld_phase1_completion_items() -> TestResult {
    let root = workspace_root();
    let contract = read_json(&contract_path(&root))?;

    assert_eq!(
        contract["schema_version"].as_str(),
        Some("rtld_phase1_completion_contract.v1")
    );
    assert_eq!(contract["bead"].as_str(), Some("bd-1j4.2"));
    assert_eq!(
        contract["completion_debt_bead"].as_str(),
        Some("bd-1j4.2.1")
    );

    let evidence = &contract["completion_debt_evidence"];
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-1j4.2"));
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

    let relocation_cases: BTreeSet<String> =
        evidence["conformance_primary"]["required_elf_loader_cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|case| case.as_str().unwrap().to_string())
            .collect();
    for required in [
        "reloc_r_x86_64_none",
        "reloc_r_x86_64_64",
        "reloc_r_x86_64_relative",
        "reloc_r_x86_64_glob_dat",
        "reloc_r_x86_64_jump_slot",
    ] {
        assert!(relocation_cases.contains(required));
    }

    Ok(())
}

#[test]
fn checker_passes_and_emits_report_log() -> TestResult {
    let root = workspace_root();
    let out_dir = run_passing_checker(&root, "pass")?;
    let report = read_json(&out_dir.join("rtld_phase1_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["event"].as_str(),
        Some("rtld_phase1.completion_contract_validated")
    );
    assert!(report["unit_test_ref_count"].as_u64().unwrap_or_default() >= 8);
    assert!(report["elf_loader_case_count"].as_u64().unwrap_or_default() >= 17);
    assert!(
        report["loader_audit_row_count"]
            .as_u64()
            .unwrap_or_default()
            >= 8
    );
    assert!(
        report["fuzz_corpus_seed_count"]
            .as_u64()
            .unwrap_or_default()
            >= 4
    );
    assert!(
        report["conformance_test_ref_count"]
            .as_u64()
            .unwrap_or_default()
            >= 5
    );

    let rows = read_jsonl(&out_dir.join("rtld_phase1_completion_contract.log.jsonl"))?;
    let events: BTreeSet<String> = rows
        .iter()
        .filter_map(|row| row["event"].as_str().map(str::to_string))
        .collect();
    for required in [
        "rtld_phase1.source_ref",
        "rtld_phase1.missing_item_bound",
        "rtld_phase1.fuzz_corpus_bound",
        "rtld_phase1.elf_loader_case_bound",
        "rtld_phase1.loader_audit_bound",
        "rtld_phase1.completion_contract_validated",
    ] {
        assert!(
            events.contains(required),
            "missing telemetry event {required}: {events:?}"
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_relocation_fixture_case() -> TestResult {
    let root = workspace_root();
    let mut contract = read_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["conformance_primary"]["required_elf_loader_cases"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::Value::String(
            "reloc_r_x86_64_definitely_missing".to_string(),
        ));

    let out_dir = unique_out_dir(&root, "missing-reloc-case")?;
    let tampered = out_dir.join("contract.json");
    write_json(&tampered, &contract)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &tampered, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for missing relocation fixture case"
    );
    let report = read_json(&out_dir.join("rtld_phase1_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let message = checker_message(&output);
    assert!(
        message.contains("elf_loader case missing"),
        "unexpected checker output: {message}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event() -> TestResult {
    let root = workspace_root();
    let mut contract = read_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["telemetry_primary"]["required_events"]
        .as_array_mut()
        .unwrap()
        .retain(|event| event.as_str() != Some("rtld_phase1.loader_audit_bound"));

    let out_dir = unique_out_dir(&root, "missing-telemetry-event")?;
    let tampered = out_dir.join("contract.json");
    write_json(&tampered, &contract)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &tampered, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for missing telemetry event"
    );
    let report = read_json(&out_dir.join("rtld_phase1_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let items = string_set(&report["missing_items"]);
    assert!(items.contains("telemetry.primary"));
    let message = checker_message(&output);
    assert!(
        message.contains("telemetry events missing"),
        "unexpected checker output: {message}"
    );
    Ok(())
}
