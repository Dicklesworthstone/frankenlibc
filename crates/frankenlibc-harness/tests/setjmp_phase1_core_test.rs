//! Integration test: setjmp phase-1 core gate artifacts for bd-146t.
//!
//! Validates:
//! 1. `scripts/check_setjmp_phase1_core.sh` is executable and succeeds.
//! 2. Gate emits deterministic report/log artifacts in target + tests/cve_arena outputs.
//! 3. Log rows include decision-path/healing fields for strict+hardened scenarios.

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .expect("harness crate parent")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

#[test]
fn gate_script_passes_and_emits_artifacts() {
    let root = workspace_root();
    let script = root.join("scripts/check_setjmp_phase1_core.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_setjmp_phase1_core.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run setjmp phase-1 core gate");
    assert!(
        output.status.success(),
        "setjmp phase-1 core gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/setjmp_phase1_core.report.json");
    let log_path = root.join("target/conformance/setjmp_phase1_core.log.jsonl");
    let unit_log_path = root.join("target/conformance/setjmp_phase1_core.test_output.log");
    let cve_trace_path = root.join("tests/cve_arena/results/bd-146t/trace.jsonl");
    let cve_index_path = root.join("tests/cve_arena/results/bd-146t/artifact_index.json");

    for path in [
        &report_path,
        &log_path,
        &unit_log_path,
        &cve_trace_path,
        &cve_index_path,
    ] {
        assert!(path.exists(), "missing {}", path.display());
    }

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-146t"));

    for check in [
        "phase1_capture_restore",
        "longjmp_zero_normalization",
        "nested_context_ids",
        "foreign_context_guard",
        "corruption_guard_hardened",
        "mode_mismatch_guard",
        "summary_consistent",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "report checks.{check} should be pass"
        );
    }

    let mut saw_pass = false;
    let mut saw_deny = false;
    let rows: Vec<serde_json::Value> = std::fs::read_to_string(&log_path)
        .expect("log should be readable")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log row should parse"))
        .collect();

    assert_eq!(rows.len(), 6, "expected 6 deterministic log rows");
    for row in rows {
        for key in [
            "timestamp",
            "trace_id",
            "event",
            "bead_id",
            "stream",
            "gate",
            "scenario_id",
            "mode",
            "api_family",
            "symbol",
            "decision_path",
            "healing_action",
            "outcome",
            "errno",
            "latency_ns",
            "artifact_refs",
        ] {
            assert!(row.get(key).is_some(), "log row missing {key}");
        }
        assert_eq!(row["bead_id"].as_str(), Some("bd-146t"));
        assert_eq!(row["api_family"].as_str(), Some("setjmp"));
        assert!(
            row["trace_id"]
                .as_str()
                .map(|v| v.starts_with("bd-146t::"))
                .unwrap_or(false),
            "trace_id should start with bd-146t::"
        );
        match row["outcome"].as_str() {
            Some("pass") => saw_pass = true,
            Some("deny") => saw_deny = true,
            other => panic!("unexpected outcome: {:?}", other),
        }
    }
    assert!(saw_pass, "expected at least one pass row");
    assert!(saw_deny, "expected at least one deny row");

    let unit_log = std::fs::read_to_string(&unit_log_path).expect("unit log should be readable");
    for test_name in [
        "phase1_capture_and_restore_roundtrip_in_strict_mode",
        "phase1_longjmp_zero_normalizes_to_one",
        "phase1_nested_capture_assigns_distinct_context_ids",
        "phase1_hardened_rejects_corrupted_context",
        "phase1_rejects_mode_mismatch_between_capture_and_restore",
        "phase1_rejects_foreign_thread_restore_attempts",
    ] {
        assert!(
            unit_log.contains(test_name),
            "unit test output missing {test_name}"
        );
    }

    let index = load_json(&cve_index_path);
    assert_eq!(index["index_version"].as_i64(), Some(1));
    assert_eq!(index["bead_id"].as_str(), Some("bd-146t"));

    let artifacts = index["artifacts"]
        .as_array()
        .expect("artifacts should be array");
    assert!(
        artifacts.len() >= 5,
        "artifact index should contain >=5 entries"
    );
    for artifact in artifacts {
        assert!(
            artifact["path"].is_string(),
            "artifact.path should be string"
        );
        assert!(
            artifact["kind"].is_string(),
            "artifact.kind should be string"
        );
        assert!(
            artifact["sha256"].is_string(),
            "artifact.sha256 should be string"
        );
    }
}
