//! Integration test: setjmp fixture-pack gate artifacts for bd-ahjd.
//!
//! Validates:
//! 1. `tests/conformance/fixtures/setjmp_nested_edges.json` exists and has required shape.
//! 2. `scripts/check_setjmp_fixture_pack.sh` is executable and succeeds.
//! 3. Gate emits deterministic report/log artifacts in target + tests/cve_arena outputs.

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
fn artifact_exists_and_has_required_shape() {
    let root = workspace_root();
    let artifact_path = root.join("tests/conformance/fixtures/setjmp_nested_edges.json");
    assert!(
        artifact_path.exists(),
        "missing {}",
        artifact_path.display()
    );

    let artifact = load_json(&artifact_path);
    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-ahjd"));
    assert_eq!(artifact["family"].as_str(), Some("setjmp_nested_edges"));

    let programs = artifact["program_scenarios"]
        .as_array()
        .expect("program_scenarios should be array");
    assert!(
        !programs.is_empty(),
        "program_scenarios should be non-empty"
    );

    for row in programs {
        assert!(
            row.get("scenario_id")
                .and_then(serde_json::Value::as_str)
                .is_some(),
            "program scenario missing scenario_id"
        );
        assert!(
            row.get("source")
                .and_then(serde_json::Value::as_str)
                .is_some(),
            "program scenario missing source"
        );
        assert!(
            row.get("expected")
                .and_then(serde_json::Value::as_object)
                .is_some(),
            "program scenario missing expected profiles"
        );
    }

    let unsupported = artifact["unsupported_scenarios"]
        .as_array()
        .expect("unsupported_scenarios should be array");
    assert!(
        !unsupported.is_empty(),
        "unsupported_scenarios should be non-empty"
    );

    for row in unsupported {
        assert_eq!(
            row["expected_outcome"].as_str(),
            Some("unsupported_deferred"),
            "unsupported scenarios must declare unsupported_deferred outcome"
        );
        assert!(
            row.get("expected_errno")
                .and_then(serde_json::Value::as_str)
                .is_some(),
            "unsupported scenario missing expected_errno"
        );
    }

    let triage_doc_rel = artifact["triage_doc"]
        .as_str()
        .expect("triage_doc should be a string");
    let triage_doc = root.join(triage_doc_rel);
    assert!(triage_doc.exists(), "missing {}", triage_doc.display());
}

#[test]
fn gate_script_passes_and_emits_artifacts() {
    let root = workspace_root();
    let script = root.join("scripts/check_setjmp_fixture_pack.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_setjmp_fixture_pack.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run setjmp fixture-pack gate");
    assert!(
        output.status.success(),
        "setjmp fixture-pack gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/setjmp_fixture_pack.report.json");
    let log_path = root.join("target/conformance/setjmp_fixture_pack.log.jsonl");
    let cve_trace_path = root.join("tests/cve_arena/results/bd-ahjd/trace.jsonl");
    let cve_index_path = root.join("tests/cve_arena/results/bd-ahjd/artifact_index.json");

    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());
    assert!(
        cve_trace_path.exists(),
        "missing {}",
        cve_trace_path.display()
    );
    assert!(
        cve_index_path.exists(),
        "missing {}",
        cve_index_path.display()
    );

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-ahjd"));

    for check in [
        "artifact_schema",
        "program_fixture_execution",
        "strict_hardened_profiles",
        "unsupported_semantics_documented",
        "triage_doc_present",
        "summary_consistent",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "report checks.{check} should be pass"
        );
    }

    let log_content = std::fs::read_to_string(&log_path).expect("log should be readable");
    let rows: Vec<serde_json::Value> = log_content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log row should parse"))
        .collect();

    assert!(!rows.is_empty(), "log should contain rows");

    let mut saw_pass = false;
    let mut saw_unsupported = false;

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
            "jump_depth",
            "mask_state",
            "outcome",
            "latency_ns",
            "artifact_refs",
        ] {
            assert!(row.get(key).is_some(), "log row missing {key}");
        }

        assert_eq!(row["bead_id"].as_str(), Some("bd-ahjd"));
        assert_eq!(row["api_family"].as_str(), Some("setjmp"));
        assert!(
            row["trace_id"]
                .as_str()
                .map(|v| v.starts_with("bd-ahjd::"))
                .unwrap_or(false),
            "trace_id should start with bd-ahjd::"
        );

        match row["outcome"].as_str() {
            Some("pass") => saw_pass = true,
            Some("unsupported_deferred") => saw_unsupported = true,
            other => panic!("unexpected outcome in log: {:?}", other),
        }
    }

    assert!(saw_pass, "expected at least one pass outcome row");
    assert!(
        saw_unsupported,
        "expected at least one unsupported_deferred outcome row"
    );

    let index = load_json(&cve_index_path);
    assert_eq!(index["index_version"].as_i64(), Some(1));
    assert_eq!(index["bead_id"].as_str(), Some("bd-ahjd"));

    let artifacts = index["artifacts"]
        .as_array()
        .expect("artifacts should be array");
    assert!(
        artifacts.len() >= 5,
        "artifact index should contain >=5 entries"
    );
}
