//! Integration test: runtime-math cohomology cross-family gate for bd-w2c3.5.2.
//!
//! Validates that:
//! 1. `scripts/check_runtime_math_cohomology_cross_family.sh` is executable.
//! 2. Gate emits deterministic report + structured JSONL artifacts.
//! 3. Strict+hardened scenarios are both present and passing.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

fn script_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock_scripts() -> MutexGuard<'static, ()> {
    script_lock().lock().unwrap_or_else(|e| e.into_inner())
}

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
fn gate_script_passes_and_emits_expected_artifacts() {
    let _guard = lock_scripts();
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_math_cohomology_cross_family.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_runtime_math_cohomology_cross_family.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run cohomology cross-family gate");
    assert!(
        output.status.success(),
        "cohomology cross-family gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path =
        root.join("target/conformance/runtime_math_cohomology_cross_family.report.json");
    let log_path = root.join("target/conformance/runtime_math_cohomology_cross_family.log.jsonl");
    let test_log_path =
        root.join("target/conformance/runtime_math_cohomology_cross_family.test_output.log");

    for path in [&report_path, &log_path, &test_log_path] {
        assert!(path.exists(), "missing {}", path.display());
    }

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-w2c3.5.2"));
    assert_eq!(
        report["summary"]["failed_checks"].as_u64(),
        Some(0),
        "all cohomology cross-family checks should pass"
    );
    for check in [
        "strict_cross_family_consistency",
        "strict_corruption_replay_detection",
        "hardened_cross_family_consistency",
        "hardened_corruption_replay_detection",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "report checks.{check} should be pass"
        );
    }

    let run_id = report["run_id"]
        .as_str()
        .expect("report.run_id should be present");

    let (line_count, errors) = frankenlibc_harness::structured_log::validate_log_file(&log_path)
        .expect("structured log should be readable");
    assert!(
        line_count >= 4,
        "expected at least 4 structured log rows, got {line_count}"
    );
    assert!(errors.is_empty(), "structured log errors: {errors:#?}");

    let rows: Vec<serde_json::Value> = std::fs::read_to_string(&log_path)
        .expect("log should be readable")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("log row should parse"))
        .filter(|row| {
            row["trace_id"]
                .as_str()
                .is_some_and(|trace| trace.contains(run_id))
        })
        .collect();
    assert_eq!(rows.len(), 4, "expected 4 rows for run_id {run_id}");

    let mut strict_seen = 0usize;
    let mut hardened_seen = 0usize;
    for row in rows {
        for key in [
            "trace_id",
            "mode",
            "api_family",
            "symbol",
            "decision_path",
            "healing_action",
            "errno",
            "latency_ns",
            "artifact_refs",
        ] {
            assert!(row.get(key).is_some(), "log row missing {key}");
        }
        assert_eq!(row["bead_id"].as_str(), Some("bd-w2c3.5.2"));
        assert_eq!(row["outcome"].as_str(), Some("pass"));
        match row["mode"].as_str() {
            Some("strict") => strict_seen += 1,
            Some("hardened") => hardened_seen += 1,
            other => panic!("unexpected mode: {:?}", other),
        }
    }
    assert_eq!(strict_seen, 2, "expected exactly two strict-mode rows");
    assert_eq!(hardened_seen, 2, "expected exactly two hardened-mode rows");

    let test_output =
        std::fs::read_to_string(&test_log_path).expect("test output log should be readable");
    for test_name in [
        "cross_family_overlap_tracks_string_resolver_consistently",
        "cohomology_overlap_replay_detects_corrupted_witness",
        "cross_family_overlap_tracks_string_resolver_consistently_hardened",
        "cohomology_overlap_replay_detects_corrupted_witness_hardened",
    ] {
        assert!(
            test_output.contains(test_name),
            "gate test output missing {test_name}"
        );
    }
}
