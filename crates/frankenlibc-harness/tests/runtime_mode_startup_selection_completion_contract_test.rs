use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

static CHECKER_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn checker_lock() -> MutexGuard<'static, ()> {
    CHECKER_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn repo_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate directory must have workspace parent")?
        .parent()
        .ok_or("workspace parent must have repo parent")?
        .to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/runtime_mode_startup_selection_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_runtime_mode_startup_selection_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
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
        "runtime_mode_startup_selection_completion_contract_{label}_{}_{}",
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
        .env(
            "FRANKENLIBC_RUNTIME_MODE_STARTUP_SELECTION_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_RUNTIME_MODE_STARTUP_SELECTION_COMPLETION_REPORT",
            out_dir.join("runtime_mode_startup_selection_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RUNTIME_MODE_STARTUP_SELECTION_COMPLETION_LOG",
            out_dir.join("runtime_mode_startup_selection_completion_contract.log.jsonl"),
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
    let body = std::fs::read_to_string(path)?;
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

#[test]
fn manifest_binds_unit_and_e2e_items() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("runtime_mode_startup_selection_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-oai.1"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-oai.1.1")
    );

    let missing_items: BTreeSet<_> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings must be array")?
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect();
    assert_eq!(
        missing_items,
        BTreeSet::from(["tests.e2e.primary", "tests.unit.primary"])
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?;
    for (name, rel) in source_artifacts {
        let rel = rel.as_str().ok_or("source artifact path must be string")?;
        assert!(root.join(rel).is_file(), "source artifact {name} missing");
    }

    assert_eq!(
        manifest["startup_mode_contract"]["env_key"].as_str(),
        Some("FRANKENLIBC_MODE")
    );
    assert_eq!(
        manifest["startup_mode_contract"]["immutable_after_first_resolution"].as_bool(),
        Some(true)
    );
    assert_eq!(
        manifest["startup_mode_contract"]["thread_local_cache_state"].as_str(),
        Some("MODE_THREAD_LOCAL_CACHE")
    );

    Ok(())
}

#[test]
fn startup_contract_names_runtime_policy_sources() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;
    let policy_path = manifest["source_artifacts"]["runtime_policy"]
        .as_str()
        .ok_or("runtime_policy source artifact missing")?;
    let policy_text = std::fs::read_to_string(root.join(policy_path))?;

    for anchor in manifest["source_anchors"]["runtime_policy"]
        .as_array()
        .ok_or("runtime_policy anchors must be array")?
    {
        let anchor = anchor.as_str().ok_or("anchor must be string")?;
        assert!(
            policy_text.contains(anchor),
            "runtime_policy source is missing anchor: {anchor}"
        );
    }

    let unit_refs = manifest["completion_coverage"]["unit"]["runtime_policy_inline_tests"]
        .as_array()
        .ok_or("runtime policy test refs must be array")?;
    for test_name in unit_refs {
        let test_name = test_name.as_str().ok_or("test name must be string")?;
        assert!(
            policy_text.contains(&format!("fn {test_name}")),
            "runtime_policy source is missing test ref {test_name}"
        );
    }

    Ok(())
}

#[test]
fn checker_emits_structured_completion_evidence() -> TestResult {
    let _lock = checker_lock();
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("runtime_mode_startup_selection_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("runtime_mode_startup_selection_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["failure_signature"].as_str(), Some("none"));
    assert_eq!(
        report["summary"]["env_key"].as_str(),
        Some("FRANKENLIBC_MODE")
    );
    assert_eq!(report["summary"]["missing_item_count"].as_u64(), Some(2));
    assert_eq!(report["summary"]["unit_test_ref_count"].as_u64(), Some(9));
    assert_eq!(report["summary"]["e2e_test_ref_count"].as_u64(), Some(4));
    assert_eq!(
        report["summary"]["ambient_tz_dependent_row_count"].as_u64(),
        Some(0)
    );

    let records =
        log_records(&out_dir.join("runtime_mode_startup_selection_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = records
        .iter()
        .filter_map(|record| record["event"].as_str())
        .collect();
    assert_eq!(
        events,
        BTreeSet::from([
            "runtime_mode_startup_selection_contract_validated",
            "runtime_mode_startup_selection_e2e_bindings",
            "runtime_mode_startup_selection_summary",
            "runtime_mode_startup_selection_unit_bindings"
        ])
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_runtime_policy_anchor() -> TestResult {
    let _lock = checker_lock();
    let root = repo_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    let anchors = manifest["source_anchors"]["runtime_policy"]
        .as_array_mut()
        .ok_or("runtime_policy anchors must be array")?;
    anchors[0] = Value::String("missing runtime mode startup anchor".to_string());

    let out_dir = unique_out_dir(&root, "fail")?;
    let mutated = out_dir.join("runtime_mode_startup_selection_completion_contract.mutated.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "mutated contract should fail\n{}",
        output_text(&output)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("source_anchor_missing"),
        "failure should identify missing source anchor\n{}",
        output_text(&output)
    );

    Ok(())
}
