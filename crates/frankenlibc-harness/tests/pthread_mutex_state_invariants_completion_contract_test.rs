//! Completion contract tests for bd-19j.1 pthread mutex state invariants.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

static CHECKER_LOCK: Mutex<()> = Mutex::new(());

fn workspace_root() -> TestResult<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = manifest_dir
        .parent()
        .ok_or("crate directory must have workspace parent")?;
    let root = workspace_dir
        .parent()
        .ok_or("workspace parent must have repo root")?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/pthread_mutex_state_invariants_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_pthread_mutex_state_invariants_completion_contract.sh")
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
        "pthread-mutex-state-invariants-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_PTHREAD_MUTEX_STATE_INVARIANTS_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_PTHREAD_MUTEX_STATE_INVARIANTS_REPORT",
            out_dir.join("pthread_mutex_state_invariants_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_PTHREAD_MUTEX_STATE_INVARIANTS_LOG",
            out_dir.join("pthread_mutex_state_invariants_completion_contract.log.jsonl"),
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

fn string_set(value: &serde_json::Value, context: &str) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| format!("{context} must be an array"))?
        .iter()
        .enumerate()
        .map(|(index, value)| -> TestResult<String> {
            Ok(value
                .as_str()
                .ok_or_else(|| format!("{context}[{index}] must be a string"))?
                .to_string())
        })
        .collect()
}

#[test]
fn manifest_binds_bd19j_completion_items() -> TestResult {
    let root = workspace_root()?;
    let contract = read_json(&contract_path(&root))?;

    assert_eq!(
        contract["schema_version"].as_str(),
        Some("pthread_mutex_state_invariants_completion_contract.v1")
    );
    assert_eq!(contract["bead"].as_str(), Some("bd-19j"));
    assert_eq!(contract["completion_debt_bead"].as_str(), Some("bd-19j.1"));

    let evidence = &contract["completion_debt_evidence"];
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-19j"));
    assert_eq!(evidence["next_audit_score_threshold"].as_u64(), Some(800));

    let missing_items: BTreeSet<String> = evidence["missing_item_bindings"]
        .as_array()
        .ok_or("completion_debt_evidence.missing_item_bindings must be array")?
        .iter()
        .map(|binding| {
            Ok(binding["missing_item_id"]
                .as_str()
                .ok_or("missing_item_bindings entry missing item id")?
                .to_string())
        })
        .collect::<TestResult<_>>()?;
    assert_eq!(
        missing_items,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.golden.primary".to_string(),
            "telemetry.primary".to_string(),
        ])
    );

    let transition_ids: BTreeSet<String> = evidence["golden_primary"]["state_transitions"]
        .as_array()
        .ok_or("golden_primary.state_transitions must be array")?
        .iter()
        .enumerate()
        .map(|(index, transition)| -> TestResult<String> {
            Ok(transition["id"]
                .as_str()
                .ok_or_else(|| {
                    format!("golden_primary.state_transitions[{index}].id must be string")
                })?
                .to_string())
        })
        .collect::<TestResult<_>>()?;
    assert_eq!(
        transition_ids,
        BTreeSet::from([
            "init-default-to-unlocked".to_string(),
            "lock-unlocked-fast-path".to_string(),
            "lock-contended-slow-path".to_string(),
            "trylock-locked-is-ebusy".to_string(),
            "unlock-owned-releases".to_string(),
            "destroy-unlocked-is-terminal".to_string(),
        ])
    );

    Ok(())
}

#[test]
fn checker_passes_and_emits_report_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "pass")?;
    let report =
        read_json(&out_dir.join("pthread_mutex_state_invariants_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["event"].as_str(),
        Some("pthread_mutex_state_invariants.completion_contract_validated")
    );
    assert_eq!(report["golden_transition_count"].as_u64(), Some(6));
    assert!(
        report["unit_test_ref_count"].as_u64().unwrap_or_default() >= 6,
        "unit refs should bind existing mutex state tests"
    );
    assert!(
        report["fixture_case_count"].as_u64().unwrap_or_default() >= 7,
        "fixture cases should cover fast, slow, alias, and destroy rows"
    );

    let rows =
        read_jsonl(&out_dir.join("pthread_mutex_state_invariants_completion_contract.log.jsonl"))?;
    let events: BTreeSet<String> = rows
        .iter()
        .filter_map(|row| row["event"].as_str().map(str::to_string))
        .collect();
    for required in [
        "pthread_mutex_state_invariants.source_ref",
        "pthread_mutex_state_invariants.golden_transition",
        "pthread_mutex_state_invariants.telemetry_contract",
        "pthread_mutex_state_invariants.completion_contract_validated",
    ] {
        assert!(
            events.contains(required),
            "missing telemetry event {required}: {events:?}"
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_golden_transition() -> TestResult {
    let root = workspace_root()?;
    let mut contract = read_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["golden_primary"]["state_transitions"]
        .as_array_mut()
        .ok_or("golden_primary.state_transitions must be array")?
        .retain(|transition| transition["id"].as_str() != Some("lock-contended-slow-path"));

    let out_dir = unique_out_dir(&root, "missing-transition")?;
    let tampered = out_dir.join("contract.json");
    write_json(&tampered, &contract)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &tampered, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for missing golden transition"
    );
    let report =
        read_json(&out_dir.join("pthread_mutex_state_invariants_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let message = checker_message(&output);
    assert!(
        message.contains("golden transition IDs"),
        "unexpected checker output: {message}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_field() -> TestResult {
    let root = workspace_root()?;
    let mut contract = read_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["telemetry_primary"]["required_fields"]
        .as_array_mut()
        .ok_or("telemetry_primary.required_fields must be array")?
        .retain(|field| !matches!(field.as_str(), Some("failure_signature")));

    let out_dir = unique_out_dir(&root, "missing-telemetry")?;
    let tampered = out_dir.join("contract.json");
    write_json(&tampered, &contract)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &tampered, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for missing telemetry field"
    );
    let report =
        read_json(&out_dir.join("pthread_mutex_state_invariants_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let fields = string_set(&report["missing_items"], "report.missing_items")?;
    assert!(fields.contains("telemetry.primary"));
    let message = checker_message(&output);
    assert!(
        message.contains("telemetry fields missing"),
        "unexpected checker output: {message}"
    );
    Ok(())
}
