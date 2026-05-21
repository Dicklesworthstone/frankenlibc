//! Host-delegation census gate for bd-smp21.1.

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_ANCHORS: &[&str] = &[
    "__libc_start_main",
    "dladdr",
    "dlclose",
    "dl_iterate_phdr",
    "dlopen",
    "dlsym",
    "pthread_create",
    "pthread_detach",
    "pthread_join",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate should live under crates/")
        .parent()
        .expect("crates/ should live under workspace root")
        .to_path_buf()
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn unique_output_path(root: &Path, label: &str, extension: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    root.join("target/conformance").join(format!(
        "host-delegation-census-{label}-{}-{stamp}.{extension}",
        std::process::id()
    ))
}

fn artifact(root: &Path) -> PathBuf {
    root.join("tests/conformance/host_delegation_census.v1.json")
}

#[test]
fn artifact_has_required_shape_and_anchors() -> TestResult {
    let root = workspace_root();
    let data = load_json(&artifact(&root))?;

    assert_eq!(
        data["schema_version"].as_str(),
        Some("host_delegation_census.v1")
    );
    assert_eq!(data["bead"].as_str(), Some("bd-smp21.1"));
    assert!(data["detector"].is_object(), "detector must be object");
    assert!(data["policy"].is_object(), "policy must be object");
    assert!(data["summary"].is_object(), "summary must be object");
    assert!(
        data["symbol_census"].is_array(),
        "symbol_census must be array"
    );
    assert!(
        data["callsite_census"].is_array(),
        "callsite_census must be array"
    );

    let anchors: BTreeSet<_> = data["required_anchor_symbols"]
        .as_array()
        .expect("required anchors should be array")
        .iter()
        .filter(|row| row["present"].as_bool() == Some(true))
        .filter_map(|row| row["symbol"].as_str())
        .collect();
    for required in REQUIRED_ANCHORS {
        assert!(
            anchors.contains(required),
            "host delegation census missing required anchor {required}"
        );
    }
    Ok(())
}

#[test]
fn symbol_and_callsite_counts_are_self_consistent() -> TestResult {
    let root = workspace_root();
    let data = load_json(&artifact(&root))?;
    let symbols = data["symbol_census"]
        .as_array()
        .expect("symbol census should be an array");
    let callsites = data["callsite_census"]
        .as_array()
        .expect("callsite census should be an array");

    assert_eq!(
        data["summary"]["host_delegating_symbol_count"].as_u64(),
        Some(symbols.len() as u64)
    );
    assert_eq!(
        data["summary"]["host_delegation_callsite_count"].as_u64(),
        Some(callsites.len() as u64)
    );

    let mut referenced_callsite_ids = BTreeSet::new();
    for symbol in symbols {
        let ids = symbol["callsite_ids"]
            .as_array()
            .expect("symbol callsite_ids should be array");
        assert_eq!(
            symbol["callsite_count"].as_u64(),
            Some(ids.len() as u64),
            "symbol callsite_count should match ids for {:?}",
            symbol["symbol"]
        );
        for id in ids {
            referenced_callsite_ids.insert(
                id.as_str()
                    .expect("callsite id should be string")
                    .to_string(),
            );
        }
    }

    let actual_callsite_ids: BTreeSet<_> = callsites
        .iter()
        .map(|row| {
            row["id"]
                .as_str()
                .expect("callsite id should be string")
                .to_string()
        })
        .collect();
    assert_eq!(referenced_callsite_ids, actual_callsite_ids);
    Ok(())
}

#[test]
fn callsites_reference_existing_nonblank_source_lines() -> TestResult {
    let root = workspace_root();
    let data = load_json(&artifact(&root))?;
    for row in data["callsite_census"]
        .as_array()
        .expect("callsite census should be an array")
    {
        let path = row["path"].as_str().expect("path should be string");
        let line = row["line"].as_u64().expect("line should be u64") as usize;
        assert!(line > 0, "line should be positive");
        let full_path = root.join(path);
        assert!(full_path.is_file(), "missing callsite file {path}");
        let text = std::fs::read_to_string(full_path)?;
        let lines: Vec<_> = text.lines().collect();
        assert!(
            line <= lines.len(),
            "callsite line out of range: {path}:{line}"
        );
        assert!(
            !lines[line - 1].trim().is_empty(),
            "callsite should not cite blank line: {path}:{line}"
        );
    }
    Ok(())
}

#[test]
fn generator_check_mode_rederives_artifact() -> TestResult {
    let root = workspace_root();
    let output = Command::new("python3")
        .arg("scripts/generate_host_delegation_census.py")
        .arg("--check")
        .current_dir(&root)
        .output()?;
    assert!(
        output.status.success(),
        "generator check failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn gate_script_passes_and_emits_report_and_log() -> TestResult {
    let root = workspace_root();
    let report = unique_output_path(&root, "report", "json");
    let log = unique_output_path(&root, "log", "jsonl");
    let output = Command::new("bash")
        .arg("scripts/check_host_delegation_census.sh")
        .env("FRANKENLIBC_HOST_DELEGATION_CENSUS_REPORT", &report)
        .env("FRANKENLIBC_HOST_DELEGATION_CENSUS_LOG", &log)
        .current_dir(&root)
        .output()?;
    assert!(
        output.status.success(),
        "gate failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = load_json(&report)?;
    assert_eq!(
        report_json["schema_version"].as_str(),
        Some("host_delegation_census.report.v1")
    );
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    let log_line = std::fs::read_to_string(log)?
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log should contain a row")
        .to_string();
    let log_json: Value = serde_json::from_str(&log_line)?;
    assert_eq!(
        log_json["event"].as_str(),
        Some("host_delegation_census_validated")
    );
    assert_eq!(log_json["failure_signature"].as_str(), Some("none"));
    Ok(())
}
