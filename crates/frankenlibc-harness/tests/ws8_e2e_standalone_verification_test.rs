//! bd-38x82.6: End-to-end L3 standalone verification contract tests.

use serde_json::Value;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate manifest should have crates parent")?
        .parent()
        .ok_or("crates directory should have workspace parent")?
        .to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/ws8_e2e_standalone_verification.v1.json")
}

fn script_path(root: &Path) -> PathBuf {
    root.join("scripts/check_ws8_e2e_standalone_verification.sh")
}

#[test]
fn manifest_anchors_ws8_e2e_standalone_verification() -> TestResult {
    let root = workspace_root()?;
    let manifest_file = manifest_path(&root);
    assert!(manifest_file.exists(), "manifest file must exist");

    let content = std::fs::read_to_string(&manifest_file)?;
    let json: Value = serde_json::from_str(&content)?;

    assert_eq!(
        json.get("manifest_id").and_then(Value::as_str),
        Some("ws8-e2e-standalone-verification"),
        "manifest_id must match"
    );
    assert_eq!(
        json.get("bead_id").and_then(Value::as_str),
        Some("bd-38x82.6"),
        "bead_id must match bd-38x82.6"
    );
    assert_eq!(
        json.get("parent_bead").and_then(Value::as_str),
        Some("bd-38x82"),
        "parent_bead must be bd-38x82"
    );

    Ok(())
}

#[test]
fn manifest_declares_both_architectures() -> TestResult {
    let root = workspace_root()?;
    let content = std::fs::read_to_string(manifest_path(&root))?;
    let json: Value = serde_json::from_str(&content)?;

    let archs = json
        .pointer("/scope/architectures")
        .and_then(Value::as_array)
        .ok_or("architectures array must exist")?;

    let arch_strs: Vec<&str> = archs.iter().filter_map(Value::as_str).collect();
    assert!(arch_strs.contains(&"x86_64"), "must support x86_64");
    assert!(arch_strs.contains(&"aarch64"), "must support aarch64");

    Ok(())
}

#[test]
fn manifest_anchors_all_ws8_companion_beads() -> TestResult {
    let root = workspace_root()?;
    let content = std::fs::read_to_string(manifest_path(&root))?;
    let json: Value = serde_json::from_str(&content)?;

    let companions = json
        .pointer("/scope/companion_beads")
        .and_then(Value::as_array)
        .ok_or("companion_beads array must exist")?;

    let bead_ids: Vec<&str> = companions
        .iter()
        .filter_map(|c| c.get("bead_id").and_then(Value::as_str))
        .collect();

    assert!(bead_ids.contains(&"bd-38x82.1"), "must include bd-38x82.1");
    assert!(bead_ids.contains(&"bd-38x82.2"), "must include bd-38x82.2");
    assert!(bead_ids.contains(&"bd-38x82.3"), "must include bd-38x82.3");
    assert!(bead_ids.contains(&"bd-38x82.4"), "must include bd-38x82.4");
    assert!(bead_ids.contains(&"bd-38x82.5"), "must include bd-38x82.5");

    Ok(())
}

#[test]
fn e2e_verification_script_exists_and_is_executable() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let root = workspace_root()?;
    let script = script_path(&root);
    assert!(script.exists(), "verification script must exist");

    let perms = std::fs::metadata(&script)?.permissions();
    assert!(perms.mode() & 0o111 != 0, "script must be executable");
    Ok(())
}

#[test]
fn e2e_verification_runs_and_passes() -> TestResult {
    let root = workspace_root()?;
    let script = script_path(&root);

    let output = Command::new(&script)
        .arg("--json")
        .current_dir(&root)
        .output()?;

    assert!(
        output.status.success(),
        "script should exit successfully: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: Value = serde_json::from_str(&stdout)?;

    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["architectures"]["x86_64"]["status"].as_str(),
        Some("pass")
    );
    assert_eq!(
        report["architectures"]["aarch64"]["status"].as_str(),
        Some("pass")
    );

    let summary = &report["summary"];
    assert_eq!(summary["scenarios_failed"].as_i64(), Some(0));
    assert!(summary["scenarios_passed"].as_i64().unwrap_or(0) >= 6);

    Ok(())
}

#[test]
fn e2e_report_and_log_contain_required_fields() -> TestResult {
    let root = workspace_root()?;
    let script = script_path(&root);
    let report_file =
        root.join("target/conformance/ws8_e2e/ws8_e2e_standalone_verification.report.json");
    let log_file =
        root.join("target/conformance/ws8_e2e/ws8_e2e_standalone_verification.log.jsonl");

    if !report_file.exists() || !log_file.exists() {
        let output = Command::new(&script)
            .arg("--check")
            .current_dir(&root)
            .output()?;
        assert!(output.status.success(), "script should run successfully");
    }

    assert!(report_file.exists(), "report file must exist");
    assert!(log_file.exists(), "log file must exist");

    let report_content = std::fs::read_to_string(&report_file)?;
    let report: Value = serde_json::from_str(&report_content)?;

    assert_eq!(report["bead_id"].as_str(), Some("bd-38x82.6"));
    assert_eq!(report["status"].as_str(), Some("pass"));

    let log_content = std::fs::read_to_string(&log_file)?;
    let mut log_count = 0;
    for line in log_content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: Value = serde_json::from_str(line)?;
        assert_eq!(entry["bead_id"].as_str(), Some("bd-38x82.6"));
        assert!(entry.get("trace_id").is_some());
        assert!(entry.get("event").is_some());
        assert!(entry.get("status").is_some());
        log_count += 1;
    }
    assert!(log_count >= 6, "must have log entries for all scenarios");

    Ok(())
}
