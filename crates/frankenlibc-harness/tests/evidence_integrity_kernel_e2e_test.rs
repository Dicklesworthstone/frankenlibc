//! WS-0 end-to-end Evidence Integrity Kernel harness tests for bd-3yr14.10.
//!
//! These tests drive `scripts/check_evidence_integrity_kernel_e2e.sh` in
//! `--quick` mode (no rch cargo build) and assert that the harness reports a
//! deterministic pass over every EIK scenario: happy, regression, tamper,
//! freshness, drift, edge, and unit-tests.

use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const EXPECTED_SCENARIOS: [&str; 7] = [
    "happy",
    "regression",
    "tamper",
    "freshness",
    "drift",
    "edge",
    "unit-tests",
];

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| test_error("cannot resolve workspace root"))?
        .to_path_buf())
}

fn harness_path(root: &Path) -> PathBuf {
    root.join("scripts/check_evidence_integrity_kernel_e2e.sh")
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before epoch: {err}")))?
        .as_nanos();
    let dir = root
        .join("target/conformance")
        .join(format!("eik-e2e-{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn output_text(output: &Output) -> String {
    format!(
        "exit={:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
}

fn run_harness(root: &Path, out_dir: &Path, args: &[&str]) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(harness_path(root))
        .args(args)
        .current_dir(root)
        .env("FRANKENLIBC_EIK_E2E_OUT_DIR", out_dir)
        .env("FRANKENLIBC_EIK_E2E_TRACE_ID", "bd-3yr14.10-rust-test");
    Ok(command.output()?)
}

#[test]
fn harness_script_exists_and_is_executable() -> TestResult {
    let root = workspace_root()?;
    let path = harness_path(&root);
    let metadata = fs::metadata(&path)
        .map_err(|err| test_error(format!("harness script missing: {err}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert!(
            metadata.permissions().mode() & 0o111 != 0,
            "harness script must be executable"
        );
    }
    assert!(metadata.is_file(), "harness path must be a file");
    Ok(())
}

#[test]
fn harness_lists_every_eik_scenario() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "list")?;
    let output = run_harness(&root, &out_dir, &["--list"])?;
    assert!(output.status.success(), "{}", output_text(&output));
    let catalog: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(catalog["bead_id"], "bd-3yr14.10");
    let listed: Vec<String> = catalog["scenarios"]
        .as_array()
        .ok_or_else(|| test_error("catalog.scenarios must be an array"))?
        .iter()
        .map(|entry| entry["id"].as_str().unwrap_or_default().to_string())
        .collect();
    for scenario in EXPECTED_SCENARIOS {
        assert!(
            listed.iter().any(|id| id == scenario),
            "catalog missing scenario {scenario}: {listed:?}"
        );
    }
    Ok(())
}

#[test]
fn quick_run_passes_every_eik_scenario() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "quick")?;
    let output = run_harness(&root, &out_dir, &["--quick"])?;
    assert!(output.status.success(), "{}", output_text(&output));

    // The machine-readable summary must agree with the process exit code.
    let summary: Value =
        serde_json::from_str(&fs::read_to_string(out_dir.join("e2e_summary.json"))?)?;
    assert_eq!(summary["schema_version"], "evidence_integrity_kernel_e2e_report.v1");
    assert_eq!(summary["bead_id"], "bd-3yr14.10");
    assert_eq!(summary["status"], "pass", "{}", output_text(&output));
    assert_eq!(summary["quick_mode"], true);
    assert_eq!(summary["scenarios_total"], 7);
    assert_eq!(summary["scenarios_failed"], 0);
    assert_eq!(summary["assertions_failed"], 0);
    assert!(
        summary["assertions_passed"].as_u64().unwrap_or(0) >= 30,
        "expected a substantial assertion count, got {}",
        summary["assertions_passed"]
    );
    Ok(())
}

#[test]
fn quick_run_emits_a_begin_and_passing_end_for_each_scenario() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "log")?;
    let output = run_harness(&root, &out_dir, &["--quick"])?;
    assert!(output.status.success(), "{}", output_text(&output));

    let log = fs::read_to_string(out_dir.join("e2e.log.jsonl"))?;
    let events: Vec<Value> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert!(!events.is_empty(), "harness produced no JSON-line events");
    assert!(
        events.iter().all(|event| event["event"] == "eik_e2e_step"),
        "every log line must be a structured eik_e2e_step event"
    );

    for scenario in EXPECTED_SCENARIOS {
        let has_begin = events
            .iter()
            .any(|event| event["scenario"] == scenario && event["step"] == "begin");
        let end_passes = events.iter().any(|event| {
            event["scenario"] == scenario
                && event["step"] == "end"
                && event["outcome"] == "pass"
        });
        assert!(has_begin, "scenario {scenario} never logged a begin event");
        assert!(end_passes, "scenario {scenario} did not log a passing end event");
    }

    // No step anywhere in a deterministic --quick run may report a failure.
    assert!(
        !events.iter().any(|event| event["outcome"] == "fail"),
        "a --quick run must not contain any failing step"
    );
    Ok(())
}
