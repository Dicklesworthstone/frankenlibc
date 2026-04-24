//! Integration tests for bd-2tq.5 errno + edge-case report artifacts.

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
fn errno_edge_report_generates_expected_schema() {
    let root = workspace_root();
    let root_prefix = format!("{}/", root.display());
    let out = root.join("target/conformance/errno_edge_report.current.v1.json");
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).expect("create output directory");
    }

    let harness_bin = std::env::var("CARGO_BIN_EXE_harness").expect("CARGO_BIN_EXE_harness");
    let output = Command::new(harness_bin)
        .current_dir(&root)
        .arg("errno-edge-report")
        .arg("--support-matrix")
        .arg(root.join("support_matrix.json"))
        .arg("--fixture")
        .arg(root.join("tests/conformance/fixtures"))
        .arg("--conformance-matrix")
        .arg(root.join("tests/conformance/conformance_matrix.v1.json"))
        .arg("--output")
        .arg(&out)
        .output()
        .expect("run errno edge report command");

    assert!(
        output.status.success(),
        "errno edge report generation failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out.exists(), "missing report output: {}", out.display());

    let report = load_json(&out);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-2tq.5"));

    let summary = report["summary"].as_object().expect("summary object");
    for required in [
        "tracked_symbols",
        "total_edge_cases",
        "errno_cases",
        "covered_edge_cases",
        "failing_edge_cases",
        "execution_error_cases",
        "missing_execution_cases",
        "symbols_with_failures",
    ] {
        assert!(
            summary.contains_key(required),
            "missing summary field {required}"
        );
    }

    let rows = report["rows"].as_array().expect("rows should be array");
    assert!(
        !rows.is_empty(),
        "rows array should contain at least one prioritized edge case"
    );
    for row in rows {
        assert!(row["priority_score"].is_u64(), "priority_score must be u64");
        assert!(row["trace_id"].is_string(), "trace_id must be string");
        assert!(row["symbol"].is_string(), "symbol must be string");
        assert!(
            row["symbol_family"].is_string(),
            "symbol_family must be string"
        );
        assert!(
            row["runtime_mode"].is_string(),
            "runtime_mode must be string"
        );
        assert!(row["case_id"].is_string(), "case_id must be string");
        assert!(row["edge_class"].is_string(), "edge_class must be string");
        assert!(
            row["expected_errno"].is_i64() || row["expected_errno"].is_u64(),
            "expected_errno must be integer"
        );
        assert!(row["status"].is_string(), "status must be string");
        assert!(
            row["failure_kind"].is_string(),
            "failure_kind must be string"
        );
        assert!(row["diff_ref"].is_string(), "diff_ref must be string");
        assert!(
            row["artifact_refs"].is_array(),
            "artifact_refs must be array"
        );
        assert!(row["triage_steps"].is_array(), "triage_steps must be array");
        assert!(
            !row["triage_steps"].as_array().unwrap().is_empty(),
            "triage_steps must not be empty"
        );

        for artifact_ref in row["artifact_refs"].as_array().unwrap() {
            let artifact_ref = artifact_ref
                .as_str()
                .expect("artifact_refs entries must be strings");
            assert!(
                !artifact_ref.starts_with(&root_prefix),
                "artifact refs must stay repo-relative, found absolute path: {artifact_ref}"
            );
        }
    }
}

#[test]
fn errno_edge_gate_script_passes() {
    let root = workspace_root();
    let script = root.join("scripts/check_errno_edge_report.sh");
    assert!(script.exists(), "missing script {}", script.display());

    let output = Command::new("bash")
        .arg(script)
        .current_dir(&root)
        .output()
        .expect("check_errno_edge_report.sh should execute");

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "errno edge gate failed\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout,
            stderr
        );
    }
}

#[test]
fn canonical_errno_edge_report_keeps_posix_pthread_cond_rows_out_of_unsupported() {
    let root = workspace_root();
    let report = load_json(&root.join("tests/conformance/errno_edge_report.v1.json"));
    let rows = report["rows"].as_array().expect("rows should be array");

    let pthread_cond_rows = rows
        .iter()
        .filter(|row| {
            row["symbol"]
                .as_str()
                .is_some_and(|symbol| symbol.starts_with("pthread_cond_"))
                && row["artifact_refs"].as_array().is_some_and(|refs| {
                    refs.iter().any(|artifact| {
                        artifact.as_str() == Some("tests/conformance/fixtures/pthread_cond.json")
                    })
                })
        })
        .collect::<Vec<_>>();

    assert!(
        !pthread_cond_rows.is_empty(),
        "expected pthread_cond rows in canonical errno-edge report"
    );

    for row in pthread_cond_rows {
        let symbol = row["symbol"].as_str().unwrap_or("<unknown>");
        let case_id = row["case_id"].as_str().unwrap_or("<unknown>");
        let runtime_mode = row["runtime_mode"].as_str().unwrap_or("<unknown>");

        assert_eq!(
            row["status"].as_str(),
            Some("pass"),
            "pthread_cond errno-edge row regressed: {symbol}::{case_id}::{runtime_mode}"
        );
        assert_ne!(
            row["failure_kind"].as_str(),
            Some("unsupported_function"),
            "pthread_cond errno-edge row should not be classified as unsupported: {symbol}::{case_id}::{runtime_mode}"
        );
        assert!(
            row["diff_ref"]
                .as_str()
                .unwrap_or_default()
                .starts_with("conformance_matrix::trace_id::franken_shadow::pthread/cond::"),
            "pthread_cond errno-edge row should point at a concrete conformance trace: {symbol}::{case_id}::{runtime_mode}"
        );
    }
}
