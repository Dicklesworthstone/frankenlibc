//! Integration test: property-suite evidence gate (bd-2tq.3)
//!
//! Validates:
//! 1. The property-suite gate script exists and is executable.
//! 2. Smoke-mode execution emits a valid report and structured log.
//! 3. Default command rendering does not force a synthetic `CARGO_HOME`,
//!    which would break local `rch` fallback in network-restricted runs.

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

#[test]
fn gate_script_exists_and_is_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_property_suite.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_property_suite.sh must be executable"
        );
    }
}

#[test]
fn gate_script_smoke_passes_and_emits_artifacts() {
    let root = workspace_root();
    let script = root.join("scripts/check_property_suite.sh");
    let artifact_basename = format!("property_suite_smoke_{}", std::process::id());

    let output = Command::new(&script)
        .current_dir(&root)
        .env("FRANKENLIBC_PROPTEST_CASES", "64")
        .env("ARTIFACT_BASENAME", &artifact_basename)
        .env("RCH_TARGET_DIR", format!("/tmp/{artifact_basename}_target"))
        .env("RCH_CARGO_HOME", "")
        .output()
        .expect("failed to run property suite gate");

    assert!(
        output.status.success(),
        "property suite gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join(format!(
        "target/conformance/{artifact_basename}.report.json"
    ));
    let log_path = root.join(format!("target/conformance/{artifact_basename}.log.jsonl"));
    let test_output_path = root.join(format!(
        "target/conformance/{artifact_basename}.test_output.log"
    ));

    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());
    assert!(
        test_output_path.exists(),
        "missing {}",
        test_output_path.display()
    );

    let (line_count, errors) = frankenlibc_harness::structured_log::validate_log_file(&log_path)
        .expect("structured log should be readable");
    assert!(
        errors.is_empty(),
        "structured log validation errors:\n{:#?}",
        errors
    );
    assert_eq!(line_count, 7, "expected one log row per property suite");

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead_id"].as_str(), Some("bd-2tq.3"));
    assert_eq!(report["gate"].as_str(), Some("check_property_suite"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["proptest_cases"].as_u64(), Some(64));

    let suites = report["tests"].as_array().expect("tests should be array");
    assert_eq!(suites.len(), 7, "expected seven property suites");
    for suite in suites {
        assert_eq!(suite["status"].as_str(), Some("pass"));
        let command = suite["command"].as_str().expect("command must be string");
        assert!(
            command.contains("cargo test --locked"),
            "gate command should pin Cargo.lock: {command}"
        );
        assert!(
            !command.contains("CARGO_HOME="),
            "default smoke command should not force CARGO_HOME: {command}"
        );
    }

    let log_body = std::fs::read_to_string(&log_path).expect("log file should exist");
    let log_entries: Vec<serde_json::Value> = log_body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log line should parse"))
        .collect();
    assert_eq!(
        log_entries.len(),
        7,
        "expected seven structured log entries"
    );
    for entry in &log_entries {
        assert_eq!(entry["event"].as_str(), Some("property_suite"));
        assert_eq!(entry["outcome"].as_str(), Some("pass"));
        assert!(entry["trace_id"].is_string(), "trace_id missing");
        assert!(entry["artifact_refs"].is_array(), "artifact_refs missing");
    }

    let test_output = std::fs::read_to_string(&test_output_path).expect("test output should exist");
    assert!(
        test_output.contains("cargo test --locked"),
        "test output transcript should include locked cargo commands"
    );
    assert!(
        test_output.contains("CARGO_HOME=<default>"),
        "test output transcript should record default cargo-home behavior"
    );
}
