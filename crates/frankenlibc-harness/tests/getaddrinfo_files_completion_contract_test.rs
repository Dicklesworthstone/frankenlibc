//! Completion-contract tests for bd-66s.1 getaddrinfo/getnameinfo files evidence.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

static CHECKER_LOCK: Mutex<()> = Mutex::new(());

fn workspace_root() -> TestResult<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest_dir.parent().ok_or_else(|| {
        test_error(format!(
            "{} has no parent directory",
            manifest_dir.display()
        ))
    })?;
    let root = crates_dir
        .parent()
        .ok_or_else(|| test_error(format!("{} has no parent directory", crates_dir.display())))?;
    Ok(root.to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/getaddrinfo_files_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_getaddrinfo_files_completion_contract.sh")
}

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    message.into().into()
}

fn load_json(path: &Path) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn load_jsonl(path: &Path) -> TestResult<Vec<serde_json::Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn write_json(path: &Path, value: &serde_json::Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "getaddrinfo-files-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_GETADDRINFO_FILES_COMPLETION_CONTRACT",
            manifest,
        )
        .env("FRANKENLIBC_GETADDRINFO_FILES_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_GETADDRINFO_FILES_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_GETADDRINFO_FILES_COMPLETION_LOG",
            out_dir.join("events.jsonl"),
        )
        .output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn string_set(value: &serde_json::Value) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| test_error("expected array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| test_error("expected string"))
                .map(str::to_string)
        })
        .collect::<Result<_, _>>()
}

fn mutated_manifest(
    root: &Path,
    label: &str,
    manifest: &serde_json::Value,
) -> TestResult<(PathBuf, PathBuf)> {
    let out_dir = unique_output_dir(root, label)?;
    let path = out_dir.join("contract.json");
    write_json(&path, manifest)?;
    Ok((path, out_dir))
}

fn failure_signature(report: &serde_json::Value) -> String {
    report["failure_signature"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

#[test]
fn manifest_binds_bd66s_completion_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("getaddrinfo_files_completion_contract.v1")
    );
    assert_eq!(manifest["bead_id"].as_str(), Some("bd-66s.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-66s"));
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items_closed"])?,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "telemetry.primary".to_string(),
        ])
    );
    assert_eq!(
        manifest["unit_primary"]["required_tests"]
            .as_array()
            .map(Vec::len),
        Some(9)
    );
    assert_eq!(
        string_set(&manifest["e2e_primary"]["required_scenarios"])?,
        BTreeSet::from([
            "nss-numeric-hosts-bypass".to_string(),
            "nss-hosts-files-only".to_string(),
            "nss-services-files-only".to_string(),
        ])
    );
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_report_log() -> TestResult {
    let root = workspace_root()?;
    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("PASS getaddrinfo files completion contract"),
        "{}",
        output_text(&output)
    );

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("getaddrinfo_files_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead_id"].as_str(), Some("bd-66s.1"));
    assert_eq!(report["source_count"].as_u64(), Some(8));
    assert_eq!(report["unit_test_count"].as_u64(), Some(9));
    assert_eq!(report["e2e_scenario_count"].as_u64(), Some(3));
    assert_eq!(report["telemetry_event_count"].as_u64(), Some(5));
    assert_eq!(report["failure_signature"].as_str(), Some("none"));

    let events = load_jsonl(&out_dir.join("events.jsonl"))?;
    let names = events
        .iter()
        .filter_map(|row| row["event"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    for required in [
        "getaddrinfo_files_completion.source_artifacts",
        "getaddrinfo_files_completion.unit_bindings",
        "getaddrinfo_files_completion.e2e_bindings",
        "getaddrinfo_files_completion.telemetry_bindings",
        "getaddrinfo_files_completion.validated",
    ] {
        assert!(names.contains(required), "missing event {required}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["unit_primary"]["required_tests"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_tests should be array"))?
        .retain(|row| row["name"].as_str() != Some("getaddrinfo_uses_overridden_hosts_backend"));
    let (path, out_dir) = mutated_manifest(&root, "missing-unit", &manifest)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &path, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("report.json"))?;
    assert!(failure_signature(&report).contains("missing_unit_binding"));
    Ok(())
}

#[test]
fn checker_rejects_missing_e2e_scenario() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["e2e_primary"]["required_scenarios"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_scenarios should be array"))?
        .retain(|name| name.as_str() != Some("nss-hosts-files-only"));
    let (path, out_dir) = mutated_manifest(&root, "missing-e2e", &manifest)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &path, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("report.json"))?;
    assert!(failure_signature(&report).contains("missing_e2e_binding"));
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["telemetry_primary"]["required_events"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_events should be array"))?
        .retain(|name| name.as_str() != Some("getaddrinfo_files_completion.telemetry_bindings"));
    let (path, out_dir) = mutated_manifest(&root, "missing-telemetry", &manifest)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &path, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("report.json"))?;
    assert!(failure_signature(&report).contains("missing_telemetry_binding"));
    Ok(())
}
