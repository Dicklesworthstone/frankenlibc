//! Integration test: FEATURE_PARITY gap ledger extractor (bd-w2c3.1.1)
//!
//! Validates that:
//! 1. Gap ledger artifact exists and has expected schema.
//! 2. Row IDs are stable-format + unique and parser errors are empty.
//! 3. Generator self-tests pass (malformed rows / duplicates / status transitions).
//! 4. Gate script is executable and succeeds.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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

fn unique_temp_path(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("frankenlibc-{name}-{stamp}-{}", std::process::id()))
}

#[test]
fn artifact_exists_and_valid() {
    let root = workspace_root();
    let path = root.join("tests/conformance/feature_parity_gap_ledger.v1.json");
    let doc = load_json(&path);

    assert_eq!(doc["schema_version"].as_str(), Some("v1"));
    assert_eq!(doc["bead"].as_str(), Some("bd-w2c3.1.1"));
    assert!(doc["rows"].is_array());
    assert!(doc["deltas"].is_array());
    assert!(doc["gaps"].is_array());
    assert!(doc["done_evidence_audit"].is_array());
    assert!(doc["summary"].is_object());
}

#[test]
fn row_ids_are_unique_and_parser_errors_empty() {
    let root = workspace_root();
    let path = root.join("tests/conformance/feature_parity_gap_ledger.v1.json");
    let doc = load_json(&path);

    let rows = doc["rows"].as_array().unwrap();
    let parse_errors = doc["parse_errors"].as_array().unwrap();
    assert!(
        parse_errors.is_empty(),
        "parse_errors must be empty for canonical artifact"
    );
    assert!(!rows.is_empty(), "rows must be non-empty");

    let mut seen = HashSet::new();
    for row in rows {
        let row_id = row["row_id"].as_str().expect("row_id must be string");
        assert!(row_id.starts_with("fp-"), "row_id must use fp-* prefix");
        assert!(
            seen.insert(row_id.to_string()),
            "row_id must be unique, duplicate={row_id}"
        );
        assert!(
            row["provenance"]["path"].as_str().is_some(),
            "row must include provenance.path"
        );
        assert!(
            row["provenance"]["line"].as_u64().is_some(),
            "row must include provenance.line"
        );
    }
}

#[test]
fn done_rows_have_evidence_audit_records() {
    let root = workspace_root();
    let path = root.join("tests/conformance/feature_parity_gap_ledger.v1.json");
    let doc = load_json(&path);

    let rows = doc["rows"].as_array().expect("rows must be an array");
    let done_rows = rows
        .iter()
        .filter(|row| row["status"].as_str() == Some("DONE"))
        .count();
    let audit = doc["done_evidence_audit"]
        .as_array()
        .expect("done_evidence_audit must be an array");
    assert_eq!(
        audit.len(),
        done_rows,
        "every DONE ledger row must have an evidence audit row"
    );
    assert!(
        audit
            .iter()
            .any(|row| row["audit_status"].as_str() == Some("fail")),
        "canonical audit should preserve and expose invalid DONE evidence rows"
    );

    for row in audit {
        let row_id = row["ledger_row_id"]
            .as_str()
            .expect("ledger_row_id must be string");
        assert!(row_id.starts_with("fp-"));
        assert!(
            row["freshness_state"].is_string(),
            "{row_id}: freshness_state must be present"
        );
        assert!(row["expected"].is_object(), "{row_id}: expected missing");
        assert!(row["actual"].is_object(), "{row_id}: actual missing");
        assert!(
            row["artifact_refs"].is_array(),
            "{row_id}: artifact_refs missing"
        );
        assert!(
            row["failure_signature"].is_string(),
            "{row_id}: failure_signature missing"
        );
    }
}

#[test]
fn generator_self_tests_pass() {
    let root = workspace_root();
    let script = root.join("scripts/generate_feature_parity_gap_ledger.py");

    let output = std::process::Command::new("python3")
        .arg(&script)
        .arg("--self-test")
        .current_dir(&root)
        .output()
        .expect("failed to run feature parity generator self-tests");

    assert!(
        output.status.success(),
        "generator self-tests failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn gate_script_exists_and_succeeds() {
    let root = workspace_root();
    let script = root.join("scripts/check_feature_parity_gap_ledger.sh");
    assert!(
        script.exists(),
        "scripts/check_feature_parity_gap_ledger.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_feature_parity_gap_ledger.sh must be executable"
        );
    }

    let output = std::process::Command::new(&script)
        .current_dir(&root)
        .env(
            "FLC_FP_DONE_EVIDENCE_LOG",
            unique_temp_path("done-evidence.log.jsonl"),
        )
        .env(
            "FLC_FP_DONE_EVIDENCE_REPORT",
            unique_temp_path("done-evidence.report.json"),
        )
        .output()
        .expect("failed to run feature parity gap ledger gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn gate_script_emits_done_evidence_log_and_report() {
    let root = workspace_root();
    let script = root.join("scripts/check_feature_parity_gap_ledger.sh");
    let log_path = unique_temp_path("done-evidence.log.jsonl");
    let report_path = unique_temp_path("done-evidence.report.json");

    let output = std::process::Command::new(&script)
        .current_dir(&root)
        .env("FLC_FP_DONE_EVIDENCE_LOG", &log_path)
        .env("FLC_FP_DONE_EVIDENCE_REPORT", &report_path)
        .output()
        .expect("failed to run feature parity gap ledger gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_text = std::fs::read_to_string(&log_path).expect("DONE evidence log missing");
    let mut parsed_log_rows = 0usize;
    for raw in log_text.lines() {
        let event: serde_json::Value =
            serde_json::from_str(raw).expect("log row must parse as JSON");
        for key in [
            "trace_id",
            "bead_id",
            "ledger_row_id",
            "evidence_ref",
            "freshness_state",
            "expected",
            "actual",
            "source_commit",
            "artifact_refs",
            "failure_signature",
        ] {
            assert!(event.get(key).is_some(), "log row missing key `{key}`");
        }
        parsed_log_rows += 1;
    }
    assert!(parsed_log_rows > 0, "DONE evidence log must be non-empty");

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.3.2"));
    assert!(
        report["summary"]["audited_done_row_count"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "report must include audited DONE rows"
    );
    assert!(
        report["invalid_done_rows"].is_array(),
        "report must list invalid DONE rows"
    );
}
