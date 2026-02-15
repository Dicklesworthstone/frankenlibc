//! Integration test: feature parity fail-fast drift gate (bd-w2c3.1.2)

use std::path::{Path, PathBuf};
use std::process::Command;
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

fn unique_temp_path(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("frankenlibc-{name}-{stamp}-{}", std::process::id()))
}

fn parse_event_line(stdout: &str) -> serde_json::Value {
    for line in stdout.lines().rev() {
        let trimmed = line.trim();
        if !trimmed.starts_with('{') {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed)
            && value.get("trace_id").is_some()
            && value.get("artifact_refs").is_some()
        {
            return value;
        }
    }
    panic!("structured event line not found in stdout:\n{stdout}");
}

#[test]
fn gate_passes_and_emits_required_diagnostic_schema() {
    let root = workspace_root();
    let script = root.join("scripts/check_feature_parity_drift.sh");
    assert!(script.exists(), "missing script {}", script.display());

    let out_path = unique_temp_path("fp-drift-pass.json");
    let output = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        .env("FLC_FP_DRIFT_DIAGNOSTICS", &out_path)
        .output()
        .expect("failed to run feature parity drift gate");

    assert!(
        output.status.success(),
        "gate should pass with canonical ownership\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_text = std::fs::read_to_string(&out_path).expect("drift diagnostics output missing");
    let report: serde_json::Value =
        serde_json::from_str(&report_text).expect("drift diagnostics JSON must parse");
    let diagnostics = report["diagnostics"]
        .as_array()
        .expect("diagnostics must be an array");
    assert!(!diagnostics.is_empty(), "diagnostics must be non-empty");

    for row in diagnostics {
        assert!(row["gap_id"].is_string(), "gap_id must be present");
        assert!(row["owner_bead"].is_string(), "owner_bead must be present");
        assert!(
            row["source_file"].is_string(),
            "source_file must be present"
        );
        assert!(
            row["expected_vs_actual"].is_object(),
            "expected_vs_actual must be present"
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let event = parse_event_line(&stdout);
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
        assert!(
            event.get(key).is_some(),
            "structured event missing key `{key}`"
        );
    }
}

#[test]
fn gate_fails_when_unresolved_drift_loses_owner() {
    let root = workspace_root();
    let script = root.join("scripts/check_feature_parity_drift.sh");
    assert!(script.exists(), "missing script {}", script.display());

    let issues_src = root.join(".beads/issues.jsonl");
    let issues_mut = unique_temp_path("issues-mut.jsonl");
    let mut lines_out = Vec::new();
    for raw in std::fs::read_to_string(&issues_src)
        .expect("issues.jsonl missing")
        .lines()
    {
        if raw.trim().is_empty() {
            continue;
        }
        let mut row: serde_json::Value =
            serde_json::from_str(raw).expect("issues.jsonl line must be valid JSON");
        if row["id"].as_str() == Some("bd-w2c3.10.1") {
            row["status"] = serde_json::Value::String("closed".to_string());
            row["closed_at"] = serde_json::Value::String("2026-02-13T00:00:00Z".to_string());
        }
        lines_out.push(serde_json::to_string(&row).unwrap());
    }
    std::fs::write(&issues_mut, lines_out.join("\n") + "\n")
        .expect("failed to write mutated issues");

    let out_path = unique_temp_path("fp-drift-fail.json");
    let output = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        .env("FLC_FP_ISSUES_JSONL", &issues_mut)
        .env("FLC_FP_DRIFT_DIAGNOSTICS", &out_path)
        .output()
        .expect("failed to run feature parity drift gate with mutated ownership");

    assert!(
        !output.status.success(),
        "gate should fail when ownership is dropped\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_text = std::fs::read_to_string(&out_path).expect("drift diagnostics output missing");
    let report: serde_json::Value =
        serde_json::from_str(&report_text).expect("drift diagnostics JSON must parse");
    let summary = report["summary"]
        .as_object()
        .expect("summary must be object");
    let fail_count = summary
        .get("fail_count")
        .and_then(|v| v.as_u64())
        .expect("summary.fail_count must be u64");
    assert!(
        fail_count > 0,
        "fail_count must be > 0 when ownership is dropped"
    );

    let diagnostics = report["diagnostics"]
        .as_array()
        .expect("diagnostics must be an array");
    assert!(
        diagnostics.iter().any(|row| {
            row["owner_bead"].as_str() == Some("bd-w2c3.10.1")
                && row["status"].as_str() == Some("fail")
        }),
        "expected at least one failed diagnostic for closed owner bead bd-w2c3.10.1"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let event = parse_event_line(&stdout);
    assert_eq!(
        event["errno"].as_i64(),
        Some(1),
        "errno should be 1 on fail"
    );
}
