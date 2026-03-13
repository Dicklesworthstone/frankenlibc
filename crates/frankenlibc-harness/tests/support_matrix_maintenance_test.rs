// support_matrix_maintenance_test.rs — bd-3g4p
// Integration tests for the automated support matrix maintenance system.
// Validates: report generation, report schema, status validation coverage,
// conformance linkage coverage, and module coverage completeness.

use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

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

fn canonical_report_path() -> std::path::PathBuf {
    repo_root().join("tests/conformance/support_matrix_maintenance_report.v1.json")
}

fn unique_generated_report_path(tag: &str) -> std::path::PathBuf {
    let root = repo_root();
    let out_dir = root.join("target/conformance");
    std::fs::create_dir_all(&out_dir)
        .unwrap_or_else(|e| panic!("Failed to create {}: {}", out_dir.display(), e));
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    out_dir.join(format!("{tag}.{}.{}.json", std::process::id(), nanos))
}

fn generate_maintenance_report(output_path: &Path) -> std::process::Output {
    let root = repo_root();
    Command::new("python3")
        .args([
            root.join("scripts/generate_support_matrix_maintenance.py")
                .to_str()
                .unwrap(),
            "-o",
            output_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute maintenance validator")
}

fn stable_report_sections(report: &serde_json::Value) -> serde_json::Value {
    let mut stable = serde_json::Map::new();
    // These are the current-state sections. We intentionally exclude the
    // generator's baseline-relative transition fields (`generated_at`, `trend`,
    // `reclassified_symbols`, and parts of `policy_checks`) because they depend
    // on which prior report is used as the baseline.
    for key in [
        "schema_version",
        "bead",
        "summary",
        "coverage_dashboard",
        "status_distribution",
        "module_coverage",
        "symbol_status_map",
        "status_validation_issues",
        "unlinked_symbols",
    ] {
        stable.insert(
            key.to_owned(),
            report
                .get(key)
                .unwrap_or_else(|| panic!("report missing stable section `{key}`"))
                .clone(),
        );
    }
    serde_json::Value::Object(stable)
}

fn gate_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn run_support_matrix_gate_with_canonical(
    trace_symbol_events: bool,
    canonical_override: Option<&Path>,
) -> std::process::Output {
    let root = repo_root();
    let script_path = root.join("scripts/check_support_matrix_maintenance.sh");
    let mut command = Command::new("bash");
    command.arg(script_path).current_dir(&root);
    if trace_symbol_events {
        command.env("FRANKENLIBC_SYMBOL_GATE_TRACE", "1");
    } else {
        command.env_remove("FRANKENLIBC_SYMBOL_GATE_TRACE");
    }
    if let Some(path) = canonical_override {
        command.env("FRANKENLIBC_MAINTENANCE_CANONICAL_REPORT", path);
    } else {
        command.env_remove("FRANKENLIBC_MAINTENANCE_CANONICAL_REPORT");
    }
    command
        .output()
        .expect("failed to execute support matrix maintenance gate")
}

fn run_support_matrix_gate(trace_symbol_events: bool) -> std::process::Output {
    run_support_matrix_gate_with_canonical(trace_symbol_events, None)
}

const IO_INTERNAL_NATIVE_SYMBOLS: &[&str] = &[
    "_IO_fclose",
    "_IO_fdopen",
    "_IO_fflush",
    "_IO_flush_all",
    "_IO_fgetpos",
    "_IO_fgetpos64",
    "_IO_fgets",
    "_IO_fopen",
    "_IO_fputs",
    "_IO_fread",
    "_IO_fsetpos",
    "_IO_fsetpos64",
    "_IO_ftell",
    "_IO_fwrite",
    "_IO_fprintf",
    "_IO_printf",
    "_IO_setbuffer",
    "_IO_setvbuf",
    "_IO_sprintf",
    "_IO_sscanf",
    "_IO_ungetc",
    "_IO_vfprintf",
    "_IO_vsprintf",
];

#[test]
fn maintenance_report_generates_successfully() {
    let canonical_path = canonical_report_path();
    assert!(
        canonical_path.exists(),
        "canonical report missing at {}",
        canonical_path.display()
    );

    let generated_path = unique_generated_report_path("support_matrix_maintenance_test");
    let output = generate_maintenance_report(&generated_path);
    assert!(
        output.status.success(),
        "Maintenance validator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        generated_path.exists(),
        "Report not generated at {}",
        generated_path.display()
    );

    let canonical = load_json(&canonical_path);
    let generated = load_json(&generated_path);
    assert_eq!(
        stable_report_sections(&generated),
        stable_report_sections(&canonical),
        "generated maintenance report stable sections drift from canonical artifact"
    );
}

#[test]
fn maintenance_report_schema_complete() {
    let report_path = canonical_report_path();
    assert!(
        report_path.exists(),
        "canonical report missing at {}",
        report_path.display()
    );
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
fn maintenance_report_marks_io_internal_native_symbols_implemented() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/support_matrix_maintenance_report.v1.json");
    let data = load_json(&report_path);
    let symbol_status_map = data["symbol_status_map"]
        .as_object()
        .expect("symbol_status_map should be an object");

    for symbol in IO_INTERNAL_NATIVE_SYMBOLS {
        let status = symbol_status_map
            .get(*symbol)
            .and_then(serde_json::Value::as_str);
        assert_eq!(
            status,
            Some("Implemented"),
            "expected {symbol} to be Implemented in support_matrix_maintenance_report.v1.json"
        );
    }
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

#[test]
fn maintenance_gate_does_not_rewrite_canonical_report() {
    let _guard = gate_test_lock();
    let canonical_path = canonical_report_path();
    let before = std::fs::read_to_string(&canonical_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", canonical_path.display(), e));

    let output = run_support_matrix_gate(false);
    assert!(
        output.status.code().is_some(),
        "Gate process terminated without an exit code"
    );

    let after = std::fs::read_to_string(&canonical_path)
        .unwrap_or_else(|e| panic!("Failed to re-read {}: {}", canonical_path.display(), e));
    assert_eq!(
        before, after,
        "support matrix maintenance gate must not rewrite the canonical maintenance report"
    );
}

#[test]
fn maintenance_gate_fails_on_canonical_stable_section_drift() {
    let _guard = gate_test_lock();
    let mutated_canonical_path =
        unique_generated_report_path("support_matrix_maintenance_bad_canonical");
    let mut mutated = load_json(&canonical_report_path());
    let original_total = mutated["summary"]["total_symbols"]
        .as_u64()
        .expect("summary.total_symbols should be numeric");
    mutated["summary"]["total_symbols"] = serde_json::Value::from(original_total + 1);
    std::fs::write(
        &mutated_canonical_path,
        serde_json::to_vec_pretty(&mutated).expect("mutated canonical report should serialize"),
    )
    .unwrap_or_else(|e| {
        panic!(
            "Failed to write {}: {}",
            mutated_canonical_path.display(),
            e
        )
    });

    let output = run_support_matrix_gate_with_canonical(false, Some(&mutated_canonical_path));
    assert!(
        !output.status.success(),
        "gate should fail when canonical stable sections drift\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = repo_root().join("target/conformance/support_matrix_maintenance.log.jsonl");
    let events = load_jsonl(&log_path);
    let drift_event = events
        .iter()
        .find(|event| event["event"].as_str() == Some("canonical_stable_sections"))
        .expect("expected canonical_stable_sections event");
    assert_eq!(drift_event["level"].as_str(), Some("error"));
    assert_eq!(drift_event["outcome"].as_str(), Some("fail"));
    assert!(
        drift_event["details"]["mismatched_keys"]
            .as_array()
            .map(|keys| keys.iter().any(|key| key.as_str() == Some("summary")))
            .unwrap_or(false),
        "expected summary drift to be reported in mismatched_keys"
    );
}
