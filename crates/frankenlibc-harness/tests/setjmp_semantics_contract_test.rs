//! Integration test: setjmp semantics contract gate artifacts for bd-2xp3.
//!
//! Validates:
//! 1. `tests/conformance/setjmp_semantics_contract.v1.json` exists and parses.
//! 2. `scripts/check_setjmp_semantics_contract.sh` is executable and succeeds.
//! 3. Gate emits deterministic report/log artifacts in target + tests/cve_arena outputs.

use frankenlibc_harness::setjmp_contract::parse_contract_str;
use std::collections::BTreeSet;
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
fn artifact_exists_and_validates_intrinsic_contract() {
    let root = workspace_root();
    let artifact_path = root.join("tests/conformance/setjmp_semantics_contract.v1.json");
    assert!(
        artifact_path.exists(),
        "missing {}",
        artifact_path.display()
    );

    let artifact_raw =
        std::fs::read_to_string(&artifact_path).expect("artifact should be readable");
    let contract = parse_contract_str(&artifact_raw).expect("artifact should parse as contract");
    contract
        .validate_intrinsic()
        .expect("intrinsic contract validation should pass");

    let support_path = root.join("support_matrix.json");
    let support = load_json(&support_path);
    let support_symbols: BTreeSet<String> = support["symbols"]
        .as_array()
        .expect("support_matrix symbols should be array")
        .iter()
        .filter_map(|row| row.get("symbol").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect();

    contract
        .validate_support_alignment(&support_symbols)
        .expect("support-matrix alignment validation should pass");
}

#[test]
fn gate_script_passes_and_emits_artifacts() {
    let root = workspace_root();
    let script = root.join("scripts/check_setjmp_semantics_contract.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_setjmp_semantics_contract.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run setjmp semantics contract gate");
    assert!(
        output.status.success(),
        "setjmp semantics contract gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/setjmp_semantics_contract.report.json");
    let log_path = root.join("target/conformance/setjmp_semantics_contract.log.jsonl");
    let cve_trace_path = root.join("tests/cve_arena/results/bd-2xp3/trace.jsonl");
    let cve_index_path = root.join("tests/cve_arena/results/bd-2xp3/artifact_index.json");

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
    assert_eq!(report["bead"].as_str(), Some("bd-2xp3"));
    for check in [
        "artifact_schema",
        "semantics_matrix",
        "signal_mask_contract",
        "support_matrix_alignment",
        "stub_and_waiver_alignment",
        "fixture_alignment",
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
            "mode",
            "api_family",
            "symbol",
            "outcome",
            "errno",
            "latency_ns",
            "artifact_refs",
        ] {
            assert!(event.get(key).is_some(), "log row missing {key}");
        }
        assert_eq!(event["bead_id"].as_str(), Some("bd-2xp3"));
        assert_eq!(event["api_family"].as_str(), Some("setjmp"));
        assert_eq!(event["symbol"].as_str(), Some("setjmp_contract"));
        assert!(
            event["trace_id"]
                .as_str()
                .map(|v| v.starts_with("bd-2xp3::"))
                .unwrap_or(false),
            "trace_id should start with bd-2xp3::"
        );
    }

    let index = load_json(&cve_index_path);
    assert_eq!(index["index_version"].as_i64(), Some(1));
    assert_eq!(index["bead_id"].as_str(), Some("bd-2xp3"));
    let artifacts = index["artifacts"]
        .as_array()
        .expect("artifacts should be array");
    assert!(
        artifacts.len() >= 4,
        "artifact index should contain >=4 entries"
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
