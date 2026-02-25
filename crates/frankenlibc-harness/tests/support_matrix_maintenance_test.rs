// support_matrix_maintenance_test.rs — bd-3g4p
// Integration tests for the automated support matrix maintenance system.
// Validates: report generation, report schema, status validation coverage,
// conformance linkage coverage, and module coverage completeness.

use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
}

fn load_jsonl(path: &Path) -> Vec<serde_json::Value> {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("Invalid JSONL line in {}: {}", path.display(), e))
        })
        .collect()
}

fn gate_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn run_support_matrix_gate(trace_symbol_events: bool) -> std::process::Output {
    let root = repo_root();
    let script_path = root.join("scripts/check_support_matrix_maintenance.sh");
    let mut command = Command::new("bash");
    command.arg(script_path).current_dir(&root);
    if trace_symbol_events {
        command.env("FRANKENLIBC_SYMBOL_GATE_TRACE", "1");
    } else {
        command.env_remove("FRANKENLIBC_SYMBOL_GATE_TRACE");
    }
    command
        .output()
        .expect("failed to execute support matrix maintenance gate")
}

#[test]
fn maintenance_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/support_matrix_maintenance_report.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_support_matrix_maintenance.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute maintenance validator");
    assert!(
        output.status.success(),
        "Maintenance validator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        report_path.exists(),
        "Report not generated at {}",
        report_path.display()
    );
}

#[test]
fn maintenance_report_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/support_matrix_maintenance_report.v1.json");
    if !report_path.exists() {
        // Generate it if missing
        let _ = Command::new("python3")
            .args([
                root.join("scripts/generate_support_matrix_maintenance.py")
                    .to_str()
                    .unwrap(),
                "-o",
                report_path.to_str().unwrap(),
            ])
            .current_dir(&root)
            .output();
    }
    let data = load_json(&report_path);

    // Check top-level fields
    assert_eq!(
        data["schema_version"].as_str(),
        Some("v1"),
        "Wrong schema version"
    );
    assert_eq!(
        data["bead"].as_str(),
        Some("bd-3g4p"),
        "Wrong bead reference"
    );

    // Check summary fields
    let summary = &data["summary"];
    let required_fields = [
        "total_symbols",
        "status_validated",
        "status_invalid",
        "status_skipped",
        "status_valid_pct",
        "fixture_linked",
        "fixture_unlinked",
        "fixture_coverage_pct",
    ];
    for field in &required_fields {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }

    // Check sections exist
    assert!(
        data["status_distribution"].is_object(),
        "Missing status_distribution"
    );
    assert!(
        data["module_coverage"].is_object(),
        "Missing module_coverage"
    );
    assert!(
        data["status_validation_issues"].is_array(),
        "Missing status_validation_issues"
    );
    assert!(
        data["unlinked_symbols"].is_array(),
        "Missing unlinked_symbols"
    );
}

#[test]
fn maintenance_status_validation_above_threshold() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/support_matrix_maintenance_report.v1.json");
    let data = load_json(&report_path);

    let valid_pct = data["summary"]["status_valid_pct"].as_f64().unwrap();
    assert!(
        valid_pct >= 80.0,
        "Status validation {valid_pct}% below 80% threshold"
    );

    let total = data["summary"]["total_symbols"].as_u64().unwrap();
    assert!(
        total >= 200,
        "Expected at least 200 symbols in matrix, got {total}"
    );
}

#[test]
fn maintenance_module_coverage_consistent() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/support_matrix_maintenance_report.v1.json");
    let data = load_json(&report_path);

    let module_cov = data["module_coverage"].as_object().unwrap();
    let mut total_from_modules: u64 = 0;
    for (_mod_name, info) in module_cov {
        let t = info["total"].as_u64().unwrap();
        let l = info["linked"].as_u64().unwrap();
        total_from_modules += t;
        assert!(
            l <= t,
            "Module {} has more linked ({l}) than total ({t})",
            _mod_name
        );
        let pct = info["coverage_pct"].as_f64().unwrap();
        assert!(
            (0.0..=100.0).contains(&pct),
            "Module {} coverage {pct}% out of range",
            _mod_name
        );
    }

    let total_from_summary = data["summary"]["total_symbols"].as_u64().unwrap();
    assert_eq!(
        total_from_modules, total_from_summary,
        "Module total ({total_from_modules}) != summary total ({total_from_summary})"
    );
}

#[test]
fn maintenance_gate_emits_structured_logs_with_required_fields() {
    let _guard = gate_test_lock();
    let output = run_support_matrix_gate(false);
    assert!(
        output.status.code().is_some(),
        "Gate process terminated without an exit code"
    );

    let root = repo_root();
    let log_path = root.join("target/conformance/support_matrix_maintenance.log.jsonl");
    assert!(
        log_path.exists(),
        "Structured log missing at {}",
        log_path.display()
    );

    let events = load_jsonl(&log_path);
    assert!(
        !events.is_empty(),
        "Structured log must contain at least one event"
    );

    for event in &events {
        for key in [
            "timestamp",
            "trace_id",
            "level",
            "event",
            "mode",
            "api_family",
            "symbol",
            "outcome",
            "errno",
            "artifact_refs",
            "details",
        ] {
            assert!(
                event.get(key).is_some(),
                "Structured event missing key `{key}`: {event:?}"
            );
        }
    }

    assert!(
        events
            .iter()
            .any(|event| event["event"].as_str() == Some("coverage_summary")
                && event["level"].as_str() == Some("info")),
        "Missing INFO coverage_summary event"
    );
    let glibc_callthrough_issue_levels: Vec<&str> = events
        .iter()
        .filter(|event| event["event"].as_str() == Some("status_validation_issue"))
        .filter(|event| event["details"]["status"].as_str() == Some("GlibcCallThrough"))
        .filter_map(|event| event["level"].as_str())
        .collect();
    assert!(
        glibc_callthrough_issue_levels
            .iter()
            .all(|level| *level == "warn"),
        "GlibcCallThrough status_validation_issue events must be WARN"
    );
    let gate_result = events
        .iter()
        .find(|event| event["event"].as_str() == Some("gate_result"))
        .expect("Missing gate_result event");
    assert!(
        matches!(gate_result["outcome"].as_str(), Some("pass" | "fail")),
        "gate_result.outcome must be pass|fail"
    );
    if !output.status.success() {
        assert!(
            events
                .iter()
                .any(|event| event["level"].as_str() == Some("error")),
            "Expected ERROR events when gate command exits non-zero"
        );
    }
    assert!(
        !events
            .iter()
            .any(|event| event["level"].as_str() == Some("trace")),
        "TRACE events must be opt-in only"
    );
}

#[test]
fn maintenance_gate_trace_flag_emits_symbol_status_snapshot_events() {
    let _guard = gate_test_lock();
    let output = run_support_matrix_gate(true);
    assert!(
        output.status.code().is_some(),
        "Gate process terminated without an exit code"
    );

    let root = repo_root();
    let log_path = root.join("target/conformance/support_matrix_maintenance.log.jsonl");
    assert!(
        log_path.exists(),
        "Structured log missing at {}",
        log_path.display()
    );

    let events = load_jsonl(&log_path);
    assert!(
        events.iter().any(|event| {
            event["level"].as_str() == Some("trace")
                && event["event"].as_str() == Some("symbol_status_snapshot")
        }),
        "Expected TRACE symbol_status_snapshot events when FRANKENLIBC_SYMBOL_GATE_TRACE=1"
    );
}
