use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    message.into().into()
}

fn repo_root() -> TestResult<PathBuf> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| test_error("crate directory must have workspace parent"))?;
    let repo = workspace
        .parent()
        .ok_or_else(|| test_error("workspace parent must have repo parent"))?;
    Ok(repo.to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/tsm_overhead_evidence_report.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_tsm_overhead_evidence_report.sh")
}

fn overhead_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/strict_hardened_membrane_overhead_budget_golden.v1.json")
}

fn contention_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/tsm_contention_e2e_lane.v1.json")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "tsm_overhead_evidence_report_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(
    root: &Path,
    manifest: &Path,
    overhead: Option<&Path>,
    contention: Option<&Path>,
    out_dir: &Path,
) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_MANIFEST",
            manifest,
        )
        .env("FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_JSON",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_MD",
            out_dir.join("report.md"),
        )
        .env(
            "FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_LOG",
            out_dir.join("events.jsonl"),
        );
    if let Some(path) = overhead {
        command.env("FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_OVERHEAD", path);
    }
    if let Some(path) = contention {
        command.env("FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_CONTENTION", path);
    }
    Ok(command.output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn string_set(value: &Value, key: &str) -> TestResult<BTreeSet<String>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("{key} must be an array")))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error(format!("{key} item must be string")))
        })
        .collect()
}

fn failure_signatures(report: &Value) -> TestResult<BTreeSet<String>> {
    report
        .get("errors")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("errors must be an array"))?
        .iter()
        .map(|row| {
            row.get("failure_signature")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| test_error("error row missing failure_signature"))
        })
        .collect()
}

#[test]
fn manifest_pins_report_contract_and_source_artifacts() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&manifest_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("tsm_overhead_evidence_report.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-hdflr"));
    assert_eq!(
        manifest["source_artifacts"]["overhead_budget_evidence"]["path"].as_str(),
        Some("tests/conformance/strict_hardened_membrane_overhead_budget_golden.v1.json")
    );
    assert_eq!(
        manifest["source_artifacts"]["contention_lane_contract"]["path"].as_str(),
        Some("tests/conformance/tsm_contention_e2e_lane.v1.json")
    );
    assert_eq!(
        manifest["source_artifacts"]["overhead_budget_evidence"]["schema_golden_allowed"].as_bool(),
        Some(true)
    );

    let sections = string_set(&manifest["report_contract"], "required_sections")?;
    for section in [
        "Source Evidence",
        "Budget Matrix",
        "Worst Offenders",
        "Runtime Math Telemetry",
        "Contention Lane Evidence",
        "Reviewer Checklist",
        "Failure Details",
    ] {
        assert!(sections.contains(section), "missing section {section}");
    }

    let failures = string_set(&manifest, "fail_closed_signatures")?;
    for signature in [
        "missing_evidence",
        "budget_regression",
        "stale_source_commit",
        "smoke_claim_upgrade",
        "invalid_contention_lane",
    ] {
        assert!(
            failures.contains(signature),
            "missing failure signature {signature}"
        );
    }
    Ok(())
}

#[test]
fn checker_renders_pass_report_checklist_and_structured_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &manifest_path(&root), None, None, &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("tsm_overhead_evidence_report.output.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["public_claim_allowed"].as_bool(), Some(false));
    assert_eq!(report["family_rows"].as_array().map(Vec::len), Some(14));
    assert_eq!(
        report["budget_summary"]["failing_budget_rows"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        report["contention_summary"]["permissioned_large_host_present"].as_bool(),
        Some(false)
    );
    assert!(
        report["claim_blockers"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item
                .as_str()
                .is_some_and(|text| text.contains("schema-golden"))))
    );

    let markdown = std::fs::read_to_string(out_dir.join("report.md"))?;
    for section in [
        "# TSM Overhead Evidence Report",
        "## Budget Matrix",
        "## Worst Offenders",
        "## Runtime Math Telemetry",
        "## Contention Lane Evidence",
        "## Reviewer Checklist",
    ] {
        assert!(markdown.contains(section), "markdown missing {section}");
    }
    assert!(markdown.contains("Public performance claim: BLOCKED"));
    assert!(markdown.contains("runtime_math | hardened"));

    let log = std::fs::read_to_string(out_dir.join("events.jsonl"))?;
    let rows: Vec<Value> = log
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(rows.len(), 5);
    for (index, line) in log.lines().enumerate() {
        validate_log_line(line, index + 1).map_err(|errors| {
            std::io::Error::other(format!("structured log row failed validation: {errors:?}"))
        })?;
    }
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect();
    assert!(events.contains("tsm_overhead_reviewer_checklist_rendered"));
    Ok(())
}

#[test]
fn checker_rejects_budget_failures_and_exposes_failing_rows() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "budget_fail")?;
    let mut overhead = load_json(&overhead_path(&root))?;
    let records = overhead["records"]
        .as_array_mut()
        .ok_or_else(|| test_error("records must be array"))?;
    records[0]["p99_ns_op"] = json!(25.0);
    let overhead_file = out_dir.join("budget_fail.json");
    write_json(&overhead_file, &overhead)?;

    let output = run_checker(
        &root,
        &manifest_path(&root),
        Some(&overhead_file),
        Some(&contention_path(&root)),
        &out_dir,
    )?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(failure_signatures(&report)?.contains("budget_regression"));
    assert_eq!(
        report["budget_summary"]["failing_budget_rows"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    let markdown = std::fs::read_to_string(out_dir.join("report.md"))?;
    assert!(markdown.contains("budget_regression"));
    assert!(markdown.contains("string_memory | strict"));
    Ok(())
}

#[test]
fn checker_rejects_missing_evidence() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing")?;
    let missing = out_dir.join("missing-overhead.json");
    let output = run_checker(
        &root,
        &manifest_path(&root),
        Some(&missing),
        Some(&contention_path(&root)),
        &out_dir,
    )?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("report.json"))?;
    assert!(failure_signatures(&report)?.contains("missing_evidence"));
    Ok(())
}

#[test]
fn checker_rejects_stale_source_when_live_freshness_is_required() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "stale")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["source_artifacts"]["overhead_budget_evidence"]["schema_golden_allowed"] =
        Value::Bool(false);
    let manifest_file = out_dir.join("live-required-manifest.json");
    write_json(&manifest_file, &manifest)?;

    let output = run_checker(
        &root,
        &manifest_file,
        Some(&overhead_path(&root)),
        Some(&contention_path(&root)),
        &out_dir,
    )?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("report.json"))?;
    assert!(failure_signatures(&report)?.contains("stale_source_commit"));
    Ok(())
}

#[test]
fn checker_renders_mixed_smoke_and_permissioned_lanes_deterministically() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "mixed_lanes")?;
    let mut contention = load_json(&contention_path(&root))?;
    contention["permissioned_fixture"] = json!({
        "schema_version": "tsm_contention_e2e_evidence.v1",
        "bead_id": "bd-rakj1",
        "lane_id": "permissioned_large_host",
        "evidence_class": "permissioned_large_host_release",
        "can_upgrade_public_readiness": true,
        "worker_identity": "deterministic-large-host-fixture",
        "cpu_logical_cores": 96,
        "memory_gib": 384,
        "numa_topology": "2-nodes",
        "thread_count": 96,
        "duration_ms": 12000,
        "operation_mix": [
            "abi_malloc_free",
            "abi_memcpy_memset",
            "tls_cache_validation",
            "bloom_page_oracle_lookup",
            "runtime_math_decision",
            "metrics_counter_sample"
        ],
        "p50_latency_ns": 800,
        "p95_latency_ns": 1400,
        "p99_latency_ns": 1900,
        "repair_count": 0,
        "deny_count": 0,
        "tls_cache_hits": 1200,
        "tls_cache_misses": 80,
        "bloom_positive_count": 900,
        "page_oracle_hits": 900,
        "runtime_decision_count": 1280,
        "source_commit": "permissioned-fixture",
        "target_dir": "/data/tmp/rch_target_frankenlibc_DarkShore_tsm_contention_fixture",
        "raw_log_paths": [
            "target/conformance/tsm_contention_e2e_lane_permissioned.log.jsonl"
        ],
        "artifact_refs": [
            "target/conformance/tsm_contention_e2e_lane_permissioned.report.json"
        ],
        "readiness_claim": "large_host_release_candidate"
    });
    let contention_file = out_dir.join("contention-with-permissioned.json");
    write_json(&contention_file, &contention)?;

    let output = run_checker(
        &root,
        &manifest_path(&root),
        Some(&overhead_path(&root)),
        Some(&contention_file),
        &out_dir,
    )?;
    assert!(output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["contention_summary"]["permissioned_large_host_present"].as_bool(),
        Some(true)
    );
    let lanes = report["contention_rows"]
        .as_array()
        .ok_or_else(|| test_error("contention_rows must be array"))?;
    assert_eq!(lanes.len(), 2);
    assert_eq!(lanes[0]["lane_id"].as_str(), Some("smoke_small_host"));
    assert_eq!(
        lanes[1]["lane_id"].as_str(),
        Some("permissioned_large_host")
    );

    let markdown = std::fs::read_to_string(out_dir.join("report.md"))?;
    assert!(markdown.contains("smoke_small_host | smoke_shape_only"));
    assert!(markdown.contains("permissioned_large_host | permissioned_large_host_release"));
    Ok(())
}
