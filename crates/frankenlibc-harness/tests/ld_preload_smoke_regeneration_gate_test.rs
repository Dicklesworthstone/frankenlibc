//! Integration test: adversarial LD_PRELOAD smoke regeneration gate (bd-3yr14.6).
//!
//! The broad smoke battery is intentionally not run here. These tests feed
//! synthetic smoke reports into validate-only mode so the gate comparison logic
//! is fast, deterministic, and still fail-closed on summary drift.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

const CONTRACT_PATH: &str = "tests/conformance/ld_preload_smoke_regeneration_gate.v1.json";
const CANONICAL_SUMMARY_PATH: &str = "tests/conformance/ld_preload_smoke_summary.v1.json";
const GATE_SCRIPT: &str = "scripts/check_ld_preload_smoke_regeneration.sh";
const LEGACY_ADVERSARIAL_GATE_SCRIPT: &str = "scripts/check_adversarial_smoke_lane.sh";

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn write_json(path: &Path, value: &Value) {
    let content = serde_json::to_string_pretty(value).expect("json should serialize");
    std::fs::write(path, format!("{content}\n")).expect("write json");
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn smoke_case(mode: &str, case: &str, status: &str) -> Value {
    json!({
        "mode": mode,
        "case": case,
        "status": status,
        "workload": if case.starts_with("stress_") { "stress" } else { "smoke" },
        "startup_path": "coreutils_dynamic_startup",
        "failure_signature": "none",
        "signature_guard_triggered": false,
        "parity_required": mode == "strict",
        "parity_pass": true,
        "perf_required": mode == "strict",
        "perf_pass": true,
        "latency_ratio_ppm": 1000000,
        "baseline_rc": if status == "skip" { -1 } else { 0 },
        "preload_rc": if status == "skip" { -1 } else { 0 },
        "stdout_match": true,
        "stderr_match": true,
        "baseline_latency_ns": if status == "skip" { 0 } else { 1000 },
        "preload_latency_ns": if status == "skip" { 0 } else { 1000 },
        "valgrind_checked": false,
        "valgrind_pass": true
    })
}

fn failing_smoke_case(
    mode: &str,
    case: &str,
    signature_guard_triggered: bool,
    perf_failure: bool,
) -> Value {
    let mut case = smoke_case(mode, case, "fail");
    case["failure_signature"] = json!(if signature_guard_triggered {
        "signature_guard"
    } else {
        "perf_regression"
    });
    case["signature_guard_triggered"] = json!(signature_guard_triggered);
    case["perf_required"] = json!(perf_failure);
    case["perf_pass"] = json!(!perf_failure);
    case["preload_rc"] = json!(if signature_guard_triggered { 134 } else { 0 });
    case["latency_ratio_ppm"] = json!(if perf_failure { 3_000_000 } else { 1_000_000 });
    case
}

fn fake_cases(canonical: &Value) -> Vec<Value> {
    let mut cases = Vec::new();
    for mode in ["strict", "hardened"] {
        let passes = canonical["modes"][mode]["passes"]
            .as_u64()
            .expect("canonical passes") as usize;
        let fails = canonical["modes"][mode]["fails"]
            .as_u64()
            .expect("canonical fails") as usize;
        let skips = canonical["modes"][mode]["skips"]
            .as_u64()
            .expect("canonical skips") as usize;
        let signature_guard_failures = canonical["modes"][mode]["signature_guard_failures"]
            .as_u64()
            .expect("canonical signature_guard_failures")
            as usize;
        let perf_failures = canonical["modes"][mode]["perf_failures"]
            .as_u64()
            .expect("canonical perf_failures") as usize;
        let strict_parity_failures = canonical["modes"][mode]["strict_parity_failures"]
            .as_u64()
            .expect("canonical strict_parity_failures")
            as usize;
        let valgrind_failures = canonical["modes"][mode]["valgrind_failures"]
            .as_u64()
            .expect("canonical valgrind_failures") as usize;
        assert_eq!(
            strict_parity_failures + valgrind_failures,
            0,
            "synthetic smoke fixture only models signature-guard and perf failures"
        );
        assert_eq!(
            fails,
            signature_guard_failures + perf_failures,
            "synthetic failure split must match canonical {mode} fail count"
        );
        assert_eq!(
            skips, 2,
            "canonical synthetic smoke fixture expects two optional skips per mode"
        );
        for index in 0..passes {
            cases.push(smoke_case(
                mode,
                &format!("synthetic_pass_{index:02}"),
                "pass",
            ));
        }
        for index in 0..signature_guard_failures {
            cases.push(failing_smoke_case(
                mode,
                &format!("synthetic_signature_guard_fail_{index:02}"),
                true,
                false,
            ));
        }
        for index in 0..perf_failures {
            cases.push(failing_smoke_case(
                mode,
                &format!("synthetic_perf_fail_{index:02}"),
                false,
                true,
            ));
        }
        for case in ["redis_cli_version", "nginx_version"] {
            cases.push(smoke_case(mode, case, "skip"));
        }
    }
    cases
}

fn fake_report(canonical: &Value) -> Value {
    let cases = fake_cases(canonical);
    json!({
        "schema_version": "v1",
        "bead_id": "bd-3yr14.6",
        "run_id": "synthetic-smoke-regeneration",
        "lib_path": "/tmp/frankenlibc/libfrankenlibc_abi.so",
        "timeout_seconds": canonical["timeout_seconds"],
        "stress_iters": canonical["stress_iters"],
        "enforce_parity_modes": ["strict"],
        "enforce_perf_modes": ["strict"],
        "perf_ratio_max_ppm": 2000000,
        "valgrind_policy": "off",
        "summary": canonical["summary"],
        "modes": {
            "strict": {
                "total_cases": canonical["modes"]["strict"]["total_cases"],
                "passes": canonical["modes"]["strict"]["passes"],
                "fails": canonical["modes"]["strict"]["fails"],
                "skips": canonical["modes"]["strict"]["skips"],
                "signature_guard_failures": canonical["modes"]["strict"]["signature_guard_failures"],
                "strict_parity_failures": canonical["modes"]["strict"]["strict_parity_failures"],
                "perf_failures": canonical["modes"]["strict"]["perf_failures"],
                "valgrind_failures": canonical["modes"]["strict"]["valgrind_failures"],
                "failure_signature_counts": {}
            },
            "hardened": {
                "total_cases": canonical["modes"]["hardened"]["total_cases"],
                "passes": canonical["modes"]["hardened"]["passes"],
                "fails": canonical["modes"]["hardened"]["fails"],
                "skips": canonical["modes"]["hardened"]["skips"],
                "signature_guard_failures": canonical["modes"]["hardened"]["signature_guard_failures"],
                "strict_parity_failures": canonical["modes"]["hardened"]["strict_parity_failures"],
                "perf_failures": canonical["modes"]["hardened"]["perf_failures"],
                "valgrind_failures": canonical["modes"]["hardened"]["valgrind_failures"],
                "failure_signature_counts": {}
            }
        },
        "cases": cases
    })
}

fn fake_trace(report: &Value) -> String {
    let mut rows = Vec::new();
    rows.push(json!({
        "timestamp": "2026-05-21T00:00:00Z",
        "event": "suite_start",
        "mode": "all",
        "case": "all",
        "status": "running",
        "run_id": "synthetic-smoke-regeneration"
    }));
    for case in report["cases"].as_array().expect("cases") {
        let status = case["status"].as_str().expect("status");
        let event = match status {
            "pass" => "case_pass",
            "fail" => "case_fail",
            "skip" => "case_skip_optional_binary_missing",
            _ => "case_fail",
        };
        rows.push(json!({
            "timestamp": "2026-05-21T00:00:00Z",
            "event": event,
            "mode": case["mode"],
            "case": case["case"],
            "status": status,
            "run_id": "synthetic-smoke-regeneration"
        }));
    }
    rows.push(json!({
        "timestamp": "2026-05-21T00:00:00Z",
        "event": "suite_end",
        "mode": "all",
        "case": "all",
        "status": "pass",
        "run_id": "synthetic-smoke-regeneration"
    }));
    rows.into_iter()
        .map(|row| serde_json::to_string(&row).expect("trace row serializes"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn run_gate(
    temp: &Path,
    report: &Path,
    trace: &Path,
    canonical: Option<&Path>,
) -> (PathBuf, PathBuf, Output) {
    let root = workspace_root();
    let gate_report = temp.join("gate.report.json");
    let gate_log = temp.join("gate.log.jsonl");
    let mut command = Command::new(root.join(GATE_SCRIPT));
    command
        .arg("--validate-only")
        .arg("--report")
        .arg(report)
        .arg("--trace")
        .arg(trace)
        .current_dir(&root)
        .env("FRANKENLIBC_LD_PRELOAD_SMOKE_REGEN_REPORT", &gate_report)
        .env("FRANKENLIBC_LD_PRELOAD_SMOKE_REGEN_LOG", &gate_log);
    if let Some(path) = canonical {
        command.env("FRANKENLIBC_LD_PRELOAD_SMOKE_CANONICAL", path);
    }
    let output = command.output().expect("gate script should execute");
    (gate_report, gate_log, output)
}

#[test]
fn manifest_pins_run_and_validate_only_contracts() {
    let root = workspace_root();
    let manifest = load_json(&root.join(CONTRACT_PATH));
    assert_eq!(manifest["schema_version"].as_str(), Some("v1"));
    assert_eq!(
        manifest["manifest_id"].as_str(),
        Some("ld-preload-smoke-regeneration-gate")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-3yr14.6"));
    assert_eq!(
        manifest["inputs"]["canonical_summary"].as_str(),
        Some(CANONICAL_SUMMARY_PATH)
    );
    assert_eq!(
        manifest["inputs"]["gate_script"].as_str(),
        Some(GATE_SCRIPT)
    );
    assert_eq!(
        manifest["run_mode_contract"]["build_tool"].as_str(),
        Some("rch exec -- cargo build -p frankenlibc-abi --release")
    );
    assert_eq!(
        manifest["run_mode_contract"]["bare_cargo_allowed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        manifest["run_mode_contract"]["local_rch_fallback_allowed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        manifest["validate_only_contract"]["report_env"].as_str(),
        Some("FRANKENLIBC_LD_PRELOAD_SMOKE_REPORT")
    );
}

#[test]
fn gate_script_is_executable() {
    let root = workspace_root();
    let mode = std::fs::metadata(root.join(GATE_SCRIPT))
        .expect("gate script metadata")
        .permissions()
        .mode();
    assert_ne!(mode & 0o111, 0, "gate script must be executable");
}

#[test]
fn run_mode_forwards_target_dir_without_clobbering_rch_allowlist() {
    let root = workspace_root();
    let script = std::fs::read_to_string(root.join(GATE_SCRIPT)).expect("gate script readable");
    assert!(
        script.contains("case \",${RCH_ENV_ALLOWLIST:-},\" in"),
        "run mode should inspect RCH_ENV_ALLOWLIST as a comma-delimited token list"
    );
    assert!(
        script.contains("*,CARGO_TARGET_DIR,*)"),
        "run mode should detect an existing CARGO_TARGET_DIR token"
    );
    assert!(
        script.contains("export RCH_ENV_ALLOWLIST=\"${RCH_ENV_ALLOWLIST},CARGO_TARGET_DIR\""),
        "run mode should append CARGO_TARGET_DIR instead of clobbering a pre-existing allowlist"
    );
}

#[test]
fn default_run_id_is_process_unique() {
    let root = workspace_root();
    let script = std::fs::read_to_string(root.join(GATE_SCRIPT)).expect("gate script readable");
    assert!(
        script.contains(
            "RUN_ID=\"${FRANKENLIBC_LD_PRELOAD_SMOKE_REGEN_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}\""
        ),
        "default run id should include the process id so concurrent same-second runs do not share a run directory"
    );
}

#[test]
fn run_mode_forwards_gate_run_id_to_smoke_runner() {
    let root = workspace_root();
    let script = std::fs::read_to_string(root.join(GATE_SCRIPT)).expect("gate script readable");
    assert!(
        script.contains("FRANKENLIBC_SMOKE_RUN_ID=\"${RUN_ID}\""),
        "run mode must bind the child smoke report/trace run id to the gate run id"
    );
}

#[test]
fn legacy_adversarial_gate_requires_numeric_skip_counts() {
    let root = workspace_root();
    let script = std::fs::read_to_string(root.join(LEGACY_ADVERSARIAL_GATE_SCRIPT))
        .expect("legacy adversarial gate script readable");
    assert!(
        script.contains("require_count \"committed skip count\" \"${COMMITTED_SKIPS}\""),
        "legacy adversarial gate must fail closed when committed skips are missing or malformed"
    );
    assert!(
        script.contains("require_count \"fresh skip count\" \"${FRESH_SKIPS}\""),
        "legacy adversarial gate must fail closed when fresh skips are missing or malformed"
    );
    assert!(
        script.contains("DIVERGENCE: skip count differs"),
        "legacy adversarial gate must compare numeric skip counts"
    );
    assert!(
        !script.contains("skip-divergence check omitted"),
        "legacy adversarial gate must not silently omit skip divergence"
    );
}

#[test]
fn legacy_adversarial_gate_requires_total_cases_to_include_skips() {
    let root = workspace_root();
    let script = std::fs::read_to_string(root.join(LEGACY_ADVERSARIAL_GATE_SCRIPT))
        .expect("legacy adversarial gate script readable");
    assert!(
        script
            .contains("COMMITTED_TOTAL=\"$(extract_count \"${COMMITTED_SUMMARY}\" total_cases)\""),
        "legacy adversarial gate must read the committed total_cases field"
    );
    assert!(
        script.contains("FRESH_TOTAL=\"$(extract_count \"${FRESH_REPORT}\" total_cases)\""),
        "legacy adversarial gate must read the fresh total_cases field"
    );
    assert!(
        script.contains(
            "require_total_consistency \"committed summary\" \"${COMMITTED_TOTAL}\" \"${COMMITTED_PASSES}\" \"${COMMITTED_FAILS}\" \"${COMMITTED_SKIPS}\""
        ),
        "committed total_cases must equal passes + fails + skips"
    );
    assert!(
        script.contains(
            "require_total_consistency \"fresh report\" \"${FRESH_TOTAL}\" \"${FRESH_PASSES}\" \"${FRESH_FAILS}\" \"${FRESH_SKIPS}\""
        ),
        "fresh total_cases must equal passes + fails + skips"
    );
    assert!(
        script.contains("DIVERGENCE: total count differs"),
        "legacy adversarial gate must compare total_cases"
    );
    assert!(
        script.contains("\"total_cases\": ${FRESH_TOTAL}"),
        "regenerated legacy summaries must preserve the verified fresh total instead of passes + fails"
    );
    assert!(
        !script.contains("\"total_cases\": $((FRESH_PASSES + FRESH_FAILS)),"),
        "regeneration must not omit skipped cases from total_cases"
    );
}

#[test]
fn validate_only_accepts_report_matching_committed_summary() -> TestResult {
    let root = workspace_root();
    let canonical = load_json(&root.join(CANONICAL_SUMMARY_PATH));
    let report_value = fake_report(&canonical);
    let temp = unique_temp_dir("ld-preload-smoke-regeneration-pass");
    let report = temp.join("abi_compat_report.json");
    let trace = temp.join("trace.jsonl");
    write_json(&report, &report_value);
    std::fs::write(&trace, fake_trace(&report_value)).expect("write trace");

    let (gate_report, gate_log, output) = run_gate(&temp, &report, &trace, None);
    if !output.status.success() {
        return Err(format!(
            "gate should pass\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let gate = load_json(&gate_report);
    assert_eq!(gate["status"].as_str(), Some("pass"));
    assert_eq!(
        gate["checks"]["regenerated_summary_matches_committed"],
        true
    );
    let log = std::fs::read_to_string(gate_log).expect("gate log readable");
    assert!(
        log.contains("\"event\": \"smoke_case_pass\"")
            || log.contains("\"event\":\"smoke_case_pass\""),
        "gate log should include case pass rows"
    );
    Ok(())
}

#[test]
fn validate_only_rejects_stale_mode_failure_counters() -> TestResult {
    let root = workspace_root();
    let canonical = load_json(&root.join(CANONICAL_SUMMARY_PATH));
    let mut report_value = fake_report(&canonical);
    let strict_signature_guard_failures = canonical["modes"]["strict"]["signature_guard_failures"]
        .as_u64()
        .expect("canonical strict signature guard failures");
    report_value["modes"]["strict"]["signature_guard_failures"] =
        json!(strict_signature_guard_failures + 1);

    let temp = unique_temp_dir("ld-preload-smoke-regeneration-mode-counters");
    let report = temp.join("abi_compat_report.json");
    let trace = temp.join("trace.jsonl");
    write_json(&report, &report_value);
    std::fs::write(&trace, fake_trace(&report_value)).expect("write trace");

    let (gate_report, _gate_log, output) = run_gate(&temp, &report, &trace, None);
    assert!(
        !output.status.success(),
        "gate should fail when per-mode failure counters disagree with cases"
    );
    let gate = load_json(&gate_report);
    assert_eq!(gate["status"].as_str(), Some("fail"));
    assert!(
        gate["errors"].as_array().unwrap().iter().any(|error| error
            .as_str()
            .unwrap_or("")
            .contains("smoke_report.modes.strict.signature_guard_failures")),
        "failure should identify the stale strict-mode counter"
    );
    Ok(())
}

#[test]
fn validate_only_rejects_regenerated_smoke_summary_drift() -> TestResult {
    let root = workspace_root();
    let canonical = load_json(&root.join(CANONICAL_SUMMARY_PATH));
    let mut report_value = fake_report(&canonical);
    report_value["cases"][0]["status"] = json!("fail");
    report_value["cases"][0]["failure_signature"] = json!("startup_abort");
    report_value["cases"][0]["preload_rc"] = json!(134);
    report_value["summary"]["passes"] = json!(canonical["summary"]["passes"].as_u64().unwrap() - 1);
    report_value["summary"]["fails"] = json!(1);
    report_value["summary"]["overall_failed"] = json!(true);
    report_value["modes"]["strict"]["passes"] =
        json!(canonical["modes"]["strict"]["passes"].as_u64().unwrap() - 1);
    report_value["modes"]["strict"]["fails"] = json!(1);

    let temp = unique_temp_dir("ld-preload-smoke-regeneration-drift");
    let report = temp.join("abi_compat_report.json");
    let trace = temp.join("trace.jsonl");
    write_json(&report, &report_value);
    std::fs::write(&trace, fake_trace(&report_value)).expect("write trace");

    let (gate_report, _gate_log, output) = run_gate(&temp, &report, &trace, None);
    assert!(
        !output.status.success(),
        "gate should fail on regenerated summary drift"
    );
    let gate = load_json(&gate_report);
    assert_eq!(gate["status"].as_str(), Some("fail"));
    assert!(
        gate["comparison"]["drift_count"].as_u64().unwrap() >= 1,
        "drift_count should be non-zero"
    );
    Ok(())
}

#[test]
fn validate_only_rejects_hand_edited_committed_summary_without_matching_report() -> TestResult {
    let root = workspace_root();
    let canonical = load_json(&root.join(CANONICAL_SUMMARY_PATH));
    let report_value = fake_report(&canonical);
    let temp = unique_temp_dir("ld-preload-smoke-regeneration-hand-edit");
    let report = temp.join("abi_compat_report.json");
    let trace = temp.join("trace.jsonl");
    let edited_canonical = temp.join("ld_preload_smoke_summary.v1.json");
    let mut mutated = canonical.clone();
    mutated["summary"]["passes"] = json!(canonical["summary"]["passes"].as_u64().unwrap() + 1);
    write_json(&report, &report_value);
    std::fs::write(&trace, fake_trace(&report_value)).expect("write trace");
    write_json(&edited_canonical, &mutated);

    let (gate_report, _gate_log, output) =
        run_gate(&temp, &report, &trace, Some(&edited_canonical));
    assert!(
        !output.status.success(),
        "gate should fail when committed summary is hand-edited without matching regeneration"
    );
    let gate = load_json(&gate_report);
    assert_eq!(gate["status"].as_str(), Some("fail"));
    assert!(
        gate["errors"].as_array().unwrap().iter().any(|error| error
            .as_str()
            .unwrap_or("")
            .contains("canonical.summary.passes")
            || error.as_str().unwrap_or("").contains("diverges")),
        "failure should identify canonical inconsistency or regeneration drift"
    );
    Ok(())
}

#[test]
fn validate_only_rejects_hand_edited_canonical_mode_failure_counters() -> TestResult {
    let root = workspace_root();
    let canonical = load_json(&root.join(CANONICAL_SUMMARY_PATH));
    let report_value = fake_report(&canonical);
    let temp = unique_temp_dir("ld-preload-smoke-regeneration-canonical-mode-counters");
    let report = temp.join("abi_compat_report.json");
    let trace = temp.join("trace.jsonl");
    let edited_canonical = temp.join("ld_preload_smoke_summary.v1.json");
    let mut mutated = canonical.clone();
    let strict_signature_guard_failures = canonical["modes"]["strict"]["signature_guard_failures"]
        .as_u64()
        .expect("canonical strict signature guard failures");
    mutated["modes"]["strict"]["signature_guard_failures"] =
        json!(strict_signature_guard_failures + 1);
    write_json(&report, &report_value);
    std::fs::write(&trace, fake_trace(&report_value)).expect("write trace");
    write_json(&edited_canonical, &mutated);

    let (gate_report, _gate_log, output) =
        run_gate(&temp, &report, &trace, Some(&edited_canonical));
    assert!(
        !output.status.success(),
        "gate should fail when canonical per-mode failure counters are stale"
    );
    let gate = load_json(&gate_report);
    assert_eq!(gate["status"].as_str(), Some("fail"));
    assert!(
        gate["comparison"]["drift"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["field"]
                .as_str()
                .unwrap_or("")
                .contains("modes.strict.signature_guard_failures")),
        "failure should identify the stale canonical strict-mode failure counter"
    );
    Ok(())
}

#[test]
fn validate_only_rejects_trace_missing_workload_case() -> TestResult {
    let root = workspace_root();
    let canonical = load_json(&root.join(CANONICAL_SUMMARY_PATH));
    let report_value = fake_report(&canonical);
    let temp = unique_temp_dir("ld-preload-smoke-regeneration-missing-trace");
    let report = temp.join("abi_compat_report.json");
    let trace = temp.join("trace.jsonl");
    write_json(&report, &report_value);
    let mut trace_text = fake_trace(&report_value)
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    trace_text.retain(|line| !line.contains("synthetic_pass_00"));
    std::fs::write(&trace, trace_text.join("\n") + "\n").expect("write trace");

    let (gate_report, _gate_log, output) = run_gate(&temp, &report, &trace, None);
    assert!(
        !output.status.success(),
        "gate should fail when trace omits a workload case"
    );
    let gate = load_json(&gate_report);
    assert_eq!(gate["status"].as_str(), Some("fail"));
    assert!(
        gate["errors"].as_array().unwrap().iter().any(|error| error
            .as_str()
            .unwrap_or("")
            .contains("trace missing 1 case event")),
        "failure should identify missing trace coverage"
    );
    Ok(())
}

#[test]
fn validate_only_rejects_trace_multiplicity_shortfall_for_duplicate_cases() -> TestResult {
    let root = workspace_root();
    let canonical = load_json(&root.join(CANONICAL_SUMMARY_PATH));
    let mut report_value = fake_report(&canonical);
    let first_case = report_value["cases"][0].clone();
    report_value["cases"][1] = first_case;

    let temp = unique_temp_dir("ld-preload-smoke-regeneration-trace-multiplicity");
    let report = temp.join("abi_compat_report.json");
    let trace = temp.join("trace.jsonl");
    write_json(&report, &report_value);

    let mut removed_one_duplicate = false;
    let trace_text = fake_trace(&report_value)
        .lines()
        .filter(|line| {
            if !removed_one_duplicate && line.contains("\"case\":\"synthetic_pass_00\"") {
                removed_one_duplicate = true;
                return false;
            }
            true
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(&trace, trace_text).expect("write trace");

    let (gate_report, _gate_log, output) = run_gate(&temp, &report, &trace, None);
    assert!(
        !output.status.success(),
        "gate should fail when trace has fewer matching case events than the report"
    );
    let gate = load_json(&gate_report);
    assert_eq!(gate["status"].as_str(), Some("fail"));
    assert!(
        gate["errors"].as_array().unwrap().iter().any(|error| {
            let error = error.as_str().unwrap_or("");
            error.contains("trace missing 1 case event")
                && error.contains("synthetic_pass_00")
                && error.contains("expected 2, saw 1")
        }),
        "failure should identify the duplicate case trace multiplicity shortfall"
    );
    Ok(())
}
