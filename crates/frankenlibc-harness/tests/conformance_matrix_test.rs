//! Integration test: conformance matrix gate (bd-l93x.2)
//!
//! Validates:
//! 1. Baseline conformance matrix artifact exists and has required schema.
//! 2. Summary counts are consistent with case rows.
//! 3. Canonical non-pass rows include divergence metadata when present.
//! 4. Gate script executes and emits deterministic report/log artifacts.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{fs, io::Write};

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
    let artifact_path = root.join("tests/conformance/conformance_matrix.v1.json");
    assert!(
        artifact_path.exists(),
        "missing {}",
        artifact_path.display()
    );

    let artifact = load_json(&artifact_path);
    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-l93x.2"));
    assert!(artifact["summary"].is_object(), "summary must be object");
    assert!(
        artifact["symbol_matrix"].is_array(),
        "symbol_matrix must be array"
    );
    assert!(artifact["cases"].is_array(), "cases must be array");
}

#[test]
fn summary_counts_match_case_rows() {
    let root = workspace_root();
    let artifact = load_json(&root.join("tests/conformance/conformance_matrix.v1.json"));

    let rows = artifact["cases"].as_array().expect("cases should be array");
    let summary = artifact["summary"]
        .as_object()
        .expect("summary should be object");

    let total = rows.len() as u64;
    let passed = rows
        .iter()
        .filter(|row| row["status"].as_str() == Some("pass"))
        .count() as u64;
    let failed = rows
        .iter()
        .filter(|row| {
            matches!(
                row["status"].as_str(),
                Some("fail") | Some("timeout") | Some("crash")
            )
        })
        .count() as u64;
    let errors = rows
        .iter()
        .filter(|row| row["status"].as_str() == Some("error"))
        .count() as u64;

    assert_eq!(
        summary.get("total_cases").and_then(|v| v.as_u64()),
        Some(total),
        "summary.total_cases mismatch"
    );
    assert_eq!(
        summary.get("passed").and_then(|v| v.as_u64()),
        Some(passed),
        "summary.passed mismatch"
    );
    assert_eq!(
        summary.get("failed").and_then(|v| v.as_u64()),
        Some(failed),
        "summary.failed mismatch"
    );
    assert_eq!(
        summary.get("errors").and_then(|v| v.as_u64()),
        Some(errors),
        "summary.errors mismatch"
    );
}

#[test]
fn non_pass_rows_include_diff_metadata() {
    let root = workspace_root();
    let artifact = load_json(&root.join("tests/conformance/conformance_matrix.v1.json"));
    let rows = artifact["cases"].as_array().expect("cases should be array");

    let mut checked = 0usize;
    for row in rows {
        let status = row["status"].as_str().unwrap_or("");
        if status == "pass" {
            continue;
        }
        checked += 1;
        assert!(
            row.get("diff_offset").is_some(),
            "non-pass row missing diff_offset: {}",
            row["trace_id"].as_str().unwrap_or("<unknown>")
        );
        assert!(
            row.get("expected_output").is_some() && row.get("actual_output").is_some(),
            "non-pass row missing expected/actual outputs"
        );
    }
    if checked == 0 {
        let summary = artifact["summary"]
            .as_object()
            .expect("summary should be object");
        assert_eq!(
            summary.get("failed").and_then(|v| v.as_u64()),
            Some(0),
            "all-pass canonical matrix should report zero failures"
        );
        assert_eq!(
            summary.get("errors").and_then(|v| v.as_u64()),
            Some(0),
            "all-pass canonical matrix should report zero execution errors"
        );
    }
}

#[test]
fn canonical_matrix_keeps_pthread_cond_cases_covered() {
    let root = workspace_root();
    let artifact = load_json(&root.join("tests/conformance/conformance_matrix.v1.json"));
    let rows = artifact["cases"].as_array().expect("cases should be array");

    let expected_symbols = BTreeSet::from([
        "pthread_cond_broadcast",
        "pthread_cond_destroy",
        "pthread_cond_init",
        "pthread_cond_signal",
        "pthread_cond_timedwait",
        "pthread_cond_wait",
    ]);

    let pthread_cond_rows = rows
        .iter()
        .filter(|row| {
            row["symbol"]
                .as_str()
                .is_some_and(|symbol| expected_symbols.contains(symbol))
        })
        .collect::<Vec<_>>();

    assert!(
        pthread_cond_rows.len() >= 48,
        "expected canonical matrix to include the full pthread_cond fixture family"
    );

    let present_symbols = pthread_cond_rows
        .iter()
        .filter_map(|row| row["symbol"].as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        present_symbols, expected_symbols,
        "canonical matrix lost part of the pthread_cond family"
    );

    for row in pthread_cond_rows {
        let trace_id = row["trace_id"].as_str().unwrap_or("<unknown>");
        assert_eq!(
            row["status"].as_str(),
            Some("pass"),
            "pthread_cond row regressed: {trace_id}"
        );
        assert!(
            row.get("error").is_none() || row["error"].is_null(),
            "pthread_cond row should not report an execution error: {trace_id}"
        );
        assert!(
            !row["actual_output"]
                .as_str()
                .unwrap_or_default()
                .starts_with("unsupported:"),
            "pthread_cond row should not fall back to unsupported output: {trace_id}"
        );
    }
}

#[test]
fn gate_script_passes_and_emits_artifacts() {
    let root = workspace_root();
    let script = root.join("scripts/check_conformance_matrix.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_conformance_matrix.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run conformance matrix gate");
    assert!(
        output.status.success(),
        "conformance matrix gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/conformance_matrix.report.json");
    let log_path = root.join("target/conformance/conformance_matrix.log.jsonl");
    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-l93x.2"));
    for check in [
        "matrix_shape_valid",
        "no_pass_to_nonpass_regressions",
        "no_missing_baseline_cases",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "report checks.{check} should be pass"
        );
    }

    let log_line = std::fs::read_to_string(&log_path)
        .expect("log should be readable")
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log should contain at least one row")
        .to_string();
    let event: serde_json::Value = serde_json::from_str(&log_line).expect("log row should parse");
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
        "case_count",
        "pass_count",
        "fail_count",
        "error_count",
    ] {
        assert!(event.get(key).is_some(), "structured log row missing {key}");
    }
}

#[test]
fn isolated_case_runner_surfaces_timeout_and_crash_rows() {
    let root = workspace_root();
    let out_dir = root.join("target/conformance");
    fs::create_dir_all(&out_dir).expect("create target/conformance");

    let fixture_path = out_dir.join("conformance_matrix_isolated_fixture.v1.json");
    let mut fixture_file = fs::File::create(&fixture_path).expect("create fixture");
    fixture_file
        .write_all(
            br#"{
  "version":"v1",
  "family":"isolation/harness",
  "captured_at":"2026-02-25T00:00:00Z",
  "cases":[
    {"name":"ok_strlen","function":"strlen","spec_section":"POSIX strlen","inputs":{"s":[97,0]},"expected_output":"1","expected_errno":0,"mode":"strict"},
    {"name":"timeout_case","function":"__harness_test_timeout","spec_section":"N/A","inputs":{},"expected_output":"n/a","expected_errno":0,"mode":"strict"},
    {"name":"crash_case","function":"__harness_test_crash","spec_section":"N/A","inputs":{},"expected_output":"n/a","expected_errno":0,"mode":"strict"}
  ]
}"#,
        )
        .expect("write fixture");

    let output_path = out_dir.join("conformance_matrix.isolated_test.v1.json");
    let harness_bin = std::env::var("CARGO_BIN_EXE_harness").expect("CARGO_BIN_EXE_harness");
    let output = Command::new(harness_bin)
        .current_dir(&root)
        .arg("conformance-matrix")
        .arg("--fixture")
        .arg(fixture_path.parent().expect("fixture parent"))
        .arg("--output")
        .arg(&output_path)
        .arg("--mode")
        .arg("strict")
        .arg("--campaign")
        .arg("isolation-test")
        .arg("--isolate")
        .arg("--case-timeout-ms")
        .arg("1000")
        .output()
        .expect("run isolated conformance matrix");
    assert!(
        output.status.success(),
        "isolated matrix run failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let matrix = load_json(&output_path);
    let rows = matrix["cases"].as_array().expect("cases array");

    let timeout = rows
        .iter()
        .find(|row| row["symbol"].as_str() == Some("__harness_test_timeout"))
        .expect("timeout row");
    assert_eq!(timeout["status"].as_str(), Some("timeout"));
    assert!(
        timeout.get("diff_offset").is_some(),
        "timeout row should include diff_offset"
    );
    assert!(
        timeout.get("expected_output").is_some() && timeout.get("actual_output").is_some(),
        "timeout row should include expected/actual outputs"
    );

    let crash = rows
        .iter()
        .find(|row| row["symbol"].as_str() == Some("__harness_test_crash"))
        .expect("crash row");
    assert_eq!(crash["status"].as_str(), Some("crash"));
    assert!(
        crash.get("diff_offset").is_some(),
        "crash row should include diff_offset"
    );
    assert!(
        crash.get("expected_output").is_some() && crash.get("actual_output").is_some(),
        "crash row should include expected/actual outputs"
    );
}
