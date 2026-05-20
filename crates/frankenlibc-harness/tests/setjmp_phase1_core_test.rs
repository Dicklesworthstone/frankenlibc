//! Integration test: setjmp phase-1 core gate artifacts for bd-146t.
//!
//! Validates:
//! 1. `scripts/check_setjmp_phase1_core.sh` is executable and succeeds.
//! 2. Gate emits deterministic report/log artifacts in target + tests/cve_arena outputs.
//! 3. Log rows include decision-path/healing fields for strict+hardened scenarios.

use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let root = Path::new(manifest)
        .parent()
        .ok_or("harness crate parent")?
        .parent()
        .ok_or("workspace root")?
        .to_path_buf();
    Ok(root)
}

fn load_json(path: &Path) -> TestResult<serde_json::Value> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn load_text(path: &Path) -> TestResult<String> {
    Ok(std::fs::read_to_string(path)?)
}

#[test]
fn gate_script_locks_rch_and_local_mode_contract() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_setjmp_phase1_core.sh");
    let text = load_text(&script)?;

    for required in [
        "RUN_MODE=\"rch\"",
        "--rch",
        "--local",
        "RCH_REQUIRE_REMOTE=1",
        "rch exec -- cargo test -p frankenlibc-core phase1_ -- --nocapture",
        "cargo test -p frankenlibc-core phase1_ -- --nocapture",
        "bd-146t",
        "target/conformance/setjmp_phase1_core.report.json",
        "target/conformance/setjmp_phase1_core.log.jsonl",
        "target/conformance/setjmp_phase1_core.test_output.log",
        "tests/cve_arena/results/bd-146t/trace.jsonl",
        "tests/cve_arena/results/bd-146t/artifact_index.json",
    ] {
        assert!(
            text.contains(required),
            "gate script should contain contract fragment {required:?}"
        );
    }

    for test_name in [
        "phase1_capture_and_restore_roundtrip_in_strict_mode",
        "phase1_longjmp_zero_normalizes_to_one",
        "phase1_nested_capture_assigns_distinct_context_ids",
        "phase1_hardened_rejects_corrupted_context",
        "phase1_rejects_mode_mismatch_between_capture_and_restore",
        "phase1_rejects_foreign_thread_restore_attempts",
    ] {
        assert!(
            text.contains(test_name),
            "gate script should assert required unit test output {test_name}"
        );
    }

    let help = Command::new(&script)
        .arg("--help")
        .current_dir(&root)
        .output()?;
    assert!(
        help.status.success(),
        "setjmp phase-1 core gate --help failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&help.stdout),
        String::from_utf8_lossy(&help.stderr)
    );
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help_text.contains("--rch"));
    assert!(help_text.contains("--local"));
    assert!(help_text.contains("default"));

    Ok(())
}

#[test]
fn gate_script_passes_and_emits_artifacts() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_setjmp_phase1_core.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)?.permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_setjmp_phase1_core.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .arg("--local")
        .current_dir(&root)
        .output()?;
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

    let report = load_json(&report_path)?;
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
    let log_text = std::fs::read_to_string(&log_path)?;
    let rows: Vec<serde_json::Value> = log_text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str::<serde_json::Value>(line)?))
        .collect::<TestResult<Vec<_>>>()?;

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
        match row.get("outcome").and_then(serde_json::Value::as_str) {
            Some("pass") => saw_pass = true,
            Some("deny") => saw_deny = true,
            _ => return Err("unexpected outcome in setjmp phase-1 log row".into()),
        }
    }
    assert!(saw_pass, "expected at least one pass row");
    assert!(saw_deny, "expected at least one deny row");

    let unit_log = std::fs::read_to_string(&unit_log_path)?;
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

    let index = load_json(&cve_index_path)?;
    assert_eq!(index["index_version"].as_i64(), Some(1));
    assert_eq!(index["bead_id"].as_str(), Some("bd-146t"));

    let artifacts = index
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts should be array")?;
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

    Ok(())
}
