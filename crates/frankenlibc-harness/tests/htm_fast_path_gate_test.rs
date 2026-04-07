//! Integration test: HTM fast-path evidence gate (bd-1sp.6)
//!
//! Validates that:
//! 1. The HTM gate script exists and is executable.
//! 2. The gate script runs successfully.
//! 3. The gate emits structured JSONL logs and a JSON report.
//! 4. The report proves the HTM fast path stays an optional optimization for
//!    `memcpy`, `malloc_stats_combiner`, and `pthread_mutex_lock`.

use std::path::{Path, PathBuf};

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
    let content = std::fs::read_to_string(path).expect("json file should exist");
    serde_json::from_str(&content).expect("json should parse")
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_htm_fast_path.sh");
    assert!(script.exists(), "scripts/check_htm_fast_path.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_htm_fast_path.sh must be executable"
        );
    }
}

#[test]
fn gate_script_emits_logs_and_report() {
    let root = workspace_root();
    let script = root.join("scripts/check_htm_fast_path.sh");

    let output = std::process::Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run HTM fast-path gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = root.join("target/conformance/htm_fast_path.log.jsonl");
    let report_path = root.join("target/conformance/htm_fast_path.report.json");

    let (line_count, errors) = frankenlibc_harness::structured_log::validate_log_file(&log_path)
        .expect("log file should be readable");
    assert!(
        errors.is_empty(),
        "structured log validation errors:\n{:#?}",
        errors
    );
    assert!(
        line_count >= 8,
        "expected multiple HTM log lines (got {line_count})"
    );

    let log_body = std::fs::read_to_string(&log_path).expect("HTM log should be readable");
    let log_events: Vec<serde_json::Value> = log_body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log line should parse"))
        .collect();
    assert!(
        log_events
            .iter()
            .any(|entry| entry["event"].as_str() == Some("htm.fast_path.test_command")),
        "HTM gate should emit test command events"
    );
    assert!(
        log_events
            .iter()
            .any(|entry| entry["event"].as_str() == Some("htm.fast_path.integration_marker")),
        "HTM gate should emit integration marker events"
    );
    assert!(
        log_events
            .iter()
            .any(|entry| entry["event"].as_str() == Some("htm.fast_path.summary")),
        "HTM gate should emit a summary event"
    );

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-1sp.6"));
    assert_eq!(report["summary"]["failed"].as_u64(), Some(0));
    assert_eq!(
        report["pure_optimization_contract"]["correctness_independent_of_htm"].as_bool(),
        Some(true)
    );
    assert_eq!(
        report["integration"]["runtime_rtm_detection_present"].as_bool(),
        Some(true)
    );
    assert_eq!(
        report["integration"]["adaptive_cooldown_present"].as_bool(),
        Some(true)
    );

    let site_markers = report["integration"]["site_markers"]
        .as_array()
        .expect("site_markers should be an array");
    for symbol in ["memcpy", "malloc_stats_combiner", "pthread_mutex_lock"] {
        assert!(
            site_markers.iter().any(|entry| {
                entry["symbol"].as_str() == Some(symbol) && entry["present"].as_bool() == Some(true)
            }),
            "missing HTM site marker for {symbol}"
        );
    }

    let tests = report["tests"]
        .as_array()
        .expect("tests should be an array");
    assert!(
        tests
            .iter()
            .any(|entry| entry["id"].as_str() == Some("controller_unit_tests")),
        "HTM controller unit test check should be recorded"
    );
    assert!(
        tests
            .iter()
            .any(|entry| entry["id"].as_str() == Some("memcpy_strict")),
        "strict memcpy HTM check should be recorded"
    );
    assert!(
        tests
            .iter()
            .any(|entry| entry["id"].as_str() == Some("pthread_mutex_lock_hardened")),
        "hardened pthread HTM check should be recorded"
    );
}
