//! Integration test: bd-1f35 pthread strict+hardened stress artifact gate.

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
    let content = std::fs::read_to_string(path).expect("json file should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

#[test]
fn thread_stress_gate_emits_valid_bd1f35_artifacts() {
    let root = workspace_root();
    let script = root.join("scripts/check_bd1f35_thread_stress.sh");
    let spec_path = root.join("tests/conformance/pthread_thread_stress_scenarios.v1.json");
    assert!(script.exists(), "missing {}", script.display());
    assert!(spec_path.exists(), "missing {}", spec_path.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_bd1f35_thread_stress.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .env("FRANKENLIBC_THREAD_STRESS_SEED", "5151")
        .env("FLC_BD1F35_FANOUT_ITERS", "2")
        .env("FLC_BD1F35_DETACH_JOIN_ITERS", "2")
        .current_dir(&root)
        .output()
        .expect("failed to run bd-1f35 thread stress gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let out_dir = root.join("tests/cve_arena/results/bd-1f35");
    let trace_path = out_dir.join("trace.jsonl");
    let index_path = out_dir.join("artifact_index.json");
    let report_path = out_dir.join("report.json");

    assert!(trace_path.exists(), "missing {}", trace_path.display());
    assert!(index_path.exists(), "missing {}", index_path.display());
    assert!(report_path.exists(), "missing {}", report_path.display());

    let trace = std::fs::read_to_string(&trace_path).expect("trace should be readable");
    let mut result_rows = 0usize;
    let mut strict_seen = false;
    let mut hardened_seen = false;
    for raw in trace.lines() {
        if raw.trim().is_empty() {
            continue;
        }
        let row: serde_json::Value =
            serde_json::from_str(raw).expect("trace line should be valid json");
        assert!(row["timestamp"].is_string());
        assert!(row["trace_id"].is_string());
        assert!(row["level"].is_string());
        assert!(row["event"].is_string());
        assert!(row["scenario_id"].is_string());
        assert!(row["op_counts"].is_object());
        assert!(row["failure_marker"].is_string());
        if row["event"].as_str() == Some("test_result") {
            result_rows += 1;
            match row["mode"].as_str() {
                Some("strict") => strict_seen = true,
                Some("hardened") => hardened_seen = true,
                other => panic!("unexpected mode in test_result row: {other:?}"),
            }
            assert!(row["artifact_refs"].is_array());
        }
    }

    assert!(result_rows >= 8, "expected at least 8 test_result rows");
    assert!(strict_seen, "strict mode test_result rows missing");
    assert!(hardened_seen, "hardened mode test_result rows missing");

    let spec = load_json(&spec_path);
    assert_eq!(spec["schema_version"].as_str(), Some("v1"));
    assert_eq!(spec["bead"].as_str(), Some("bd-1f35"));
    assert_eq!(spec["summary"]["scenario_count"].as_i64(), Some(4));

    let index = load_json(&index_path);
    assert_eq!(index["index_version"].as_i64(), Some(1));
    assert_eq!(index["bead_id"].as_str(), Some("bd-1f35"));
    let artifacts = index["artifacts"].as_array().expect("artifacts should be array");
    assert!(!artifacts.is_empty(), "artifact index should not be empty");

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-1f35"));
    assert_eq!(report["summary"]["fail_count"].as_i64(), Some(0));
    assert!(report["mode_profiles"]["strict"].is_object());
    assert!(report["mode_profiles"]["hardened"].is_object());
    assert_eq!(report["replay_controls"]["fanout_iters"].as_i64(), Some(2));
    assert_eq!(
        report["replay_controls"]["detach_join_iters"].as_i64(),
        Some(2)
    );
}
