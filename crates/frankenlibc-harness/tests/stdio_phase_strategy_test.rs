//! Integration test: stdio phase-strategy gate artifacts for bd-24ug.
//!
//! Validates:
//! 1. `tests/conformance/stdio_phase_strategy.v1.json` exists and has required shape.
//! 2. `scripts/check_stdio_phase_strategy.sh` is executable and succeeds.
//! 3. Gate emits deterministic report/log artifacts in target + tests/cve_arena outputs.

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
fn artifact_exists_and_has_required_shape() {
    let root = workspace_root();
    let artifact_path = root.join("tests/conformance/stdio_phase_strategy.v1.json");
    assert!(artifact_path.exists(), "missing {}", artifact_path.display());

    let artifact = load_json(&artifact_path);
    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-24ug"));
    assert!(artifact["phase_split"].is_object(), "phase_split must be object");
    assert!(
        artifact["migration_plan"]["phases"].is_array(),
        "migration_plan.phases must be array"
    );
    assert!(artifact["summary"].is_object(), "summary must be object");

    let phase1 = artifact["phase_split"]["phase1_required"]["symbols"]
        .as_array()
        .expect("phase1 symbols should be array");
    let deferred = artifact["phase_split"]["deferred_surface"]["symbols"]
        .as_array()
        .expect("deferred symbols should be array");
    assert!(!phase1.is_empty(), "phase1 symbols should be non-empty");
    assert!(!deferred.is_empty(), "deferred symbols should be non-empty");
}

#[test]
fn gate_script_passes_and_emits_artifacts() {
    let root = workspace_root();
    let script = root.join("scripts/check_stdio_phase_strategy.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_stdio_phase_strategy.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run stdio phase strategy gate");
    assert!(
        output.status.success(),
        "stdio phase strategy gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/stdio_phase_strategy.report.json");
    let log_path = root.join("target/conformance/stdio_phase_strategy.log.jsonl");
    let cve_trace_path = root.join("tests/cve_arena/results/bd-24ug/trace.jsonl");
    let cve_index_path = root.join("tests/cve_arena/results/bd-24ug/artifact_index.json");

    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());
    assert!(cve_trace_path.exists(), "missing {}", cve_trace_path.display());
    assert!(cve_index_path.exists(), "missing {}", cve_index_path.display());

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-24ug"));
    for check in [
        "artifact_schema",
        "support_matrix_alignment",
        "phase_partition_complete",
        "migration_plan_valid",
        "summary_consistent",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "report checks.{check} should be pass"
        );
    }

    for path in [&log_path, &cve_trace_path] {
        let line = std::fs::read_to_string(path)
            .expect("log should be readable")
            .lines()
            .find(|l| !l.trim().is_empty())
            .expect("log should contain at least one row")
            .to_string();
        let event: serde_json::Value = serde_json::from_str(&line).expect("log row should parse");
        for key in [
            "timestamp",
            "trace_id",
            "level",
            "event",
            "bead_id",
            "stream",
            "gate",
            "outcome",
            "artifact_refs",
        ] {
            assert!(event.get(key).is_some(), "log row missing {key}");
        }
        assert_eq!(event["bead_id"].as_str(), Some("bd-24ug"));
        assert!(
            event["trace_id"]
                .as_str()
                .map(|v| v.starts_with("bd-24ug::"))
                .unwrap_or(false),
            "trace_id should start with bd-24ug::"
        );
    }

    let index = load_json(&cve_index_path);
    assert_eq!(index["index_version"].as_i64(), Some(1));
    assert_eq!(index["bead_id"].as_str(), Some("bd-24ug"));
    let artifacts = index["artifacts"].as_array().expect("artifacts should be array");
    assert!(artifacts.len() >= 4, "artifact index should contain >=4 entries");
    for artifact in artifacts {
        assert!(artifact["path"].is_string(), "artifact.path should be string");
        assert!(artifact["kind"].is_string(), "artifact.kind should be string");
        assert!(artifact["sha256"].is_string(), "artifact.sha256 should be string");
    }
}
