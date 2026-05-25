//! Integration tests for the WS-8 standalone replacement soak runner (bd-38x82.4).

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MANIFEST_REL: &str = "tests/conformance/ws8_soak.v1.json";
const RUNNER_REL: &str = "scripts/run_ws8_soak.sh";

struct SoakRun {
    output: Output,
    report_path: PathBuf,
    log_path: PathBuf,
}

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    std::io::Error::other(message.into()).into()
}

fn repo_root() -> TestResult<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| test_error("could not derive workspace root"))
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "ws8_soak_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn string_set(value: &Value, field: &str) -> TestResult<BTreeSet<String>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("{field} must be an array")))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error(format!("{field} entries must be strings")))
        })
        .collect()
}

fn run_soak(root: &Path, label: &str, mode: &str, manifest: Option<&Path>) -> TestResult<SoakRun> {
    let out = unique_out_dir(root, label)?;
    let report = out.join("ws8_soak.report.json");
    let log = out.join("ws8_soak.log.jsonl");
    let target = out.join("target");
    let mut command = Command::new(root.join(RUNNER_REL));
    command
        .arg(mode)
        .current_dir(root)
        .env("WS8_SOAK_REPORT", &report)
        .env("WS8_SOAK_LOG", &log)
        .env("WS8_SOAK_TARGET_ROOT", &target)
        .env("WS8_SOAK_RUN_ID", label)
        .env("WS8_SOAK_DURATION_SECONDS", "0")
        .env("WS8_SOAK_MAX_ITERATIONS", "1");
    if let Some(manifest) = manifest {
        command.env("WS8_SOAK_MANIFEST", manifest);
    } else {
        command.env("WS8_SOAK_MANIFEST", root.join(MANIFEST_REL));
    }
    let output = command.output()?;
    Ok(SoakRun {
        output,
        report_path: report,
        log_path: log,
    })
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn log_records(path: &Path) -> TestResult<Vec<Value>> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?)
}

#[test]
fn manifest_declares_full_24h_standalone_soak_contract() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&root.join(MANIFEST_REL))?;

    assert_eq!(manifest["schema_version"].as_str(), Some("ws8_soak.v1"));
    assert_eq!(manifest["bead"].as_str(), Some("bd-38x82.4"));
    assert_eq!(manifest["parent_bead"].as_str(), Some("bd-38x82"));
    assert_eq!(
        manifest["soak_policy"]["duration_seconds"].as_u64(),
        Some(86_400)
    );
    assert_eq!(
        manifest["soak_policy"]["require_current_standalone_artifact"].as_bool(),
        Some(true)
    );
    assert_eq!(
        manifest["soak_policy"]["required_artifact_name"].as_str(),
        Some("libfrankenlibc_replace.so")
    );
    assert_eq!(
        manifest["soak_policy"]["ld_preload_evidence_accepted"].as_bool(),
        Some(false)
    );
    assert_eq!(
        manifest["inputs"]["standalone_link_run_smoke_runner"].as_str(),
        Some("scripts/check_standalone_link_run_smoke.sh")
    );

    let report_fields = string_set(&manifest, "required_report_fields")?;
    for field in [
        "schema_version",
        "proof_status",
        "duration_seconds_required",
        "duration_seconds_observed",
        "iteration_count",
        "summary",
        "iterations",
        "failure_signatures",
        "next_safe_action",
    ] {
        assert!(
            report_fields.contains(field),
            "missing report field {field}"
        );
    }

    let summary_fields = string_set(&manifest, "required_summary_fields")?;
    for field in [
        "positive_candidate_divergences",
        "negative_candidate_leaks",
        "baseline_failures",
        "runner_failures",
        "crash_count",
        "claim_blocked_iterations",
        "current_artifact_iterations",
    ] {
        assert!(
            summary_fields.contains(field),
            "missing summary field {field}"
        );
    }
    Ok(())
}

#[test]
fn validate_only_checks_contract_without_claiming_soak_evidence() -> TestResult {
    let root = repo_root()?;
    let run = run_soak(&root, "validate-only", "--validate-only", None)?;
    assert!(
        run.output.status.success(),
        "validate-only failed: {}",
        output_text(&run.output)
    );
    let report = load_json(&run.report_path)?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("ws8_soak.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["proof_status"].as_str(), Some("contract_validated"));
    assert_eq!(report["mode"].as_str(), Some("--validate-only"));
    assert_eq!(report["iteration_count"].as_u64(), Some(0));
    assert_eq!(
        report["contract_duration_seconds"].as_u64(),
        Some(86_400),
        "validate-only still carries the real soak duration"
    );

    let records = log_records(&run.log_path)?;
    assert!(
        records
            .iter()
            .any(|row| row["event"].as_str() == Some("soak_summary")),
        "summary event missing"
    );
    Ok(())
}

#[test]
fn smoke_mode_replays_standalone_gate_validate_only_as_orchestrator_check() -> TestResult {
    let root = repo_root()?;
    let run = run_soak(&root, "smoke", "--smoke", None)?;
    assert!(
        run.output.status.success(),
        "smoke failed: {}",
        output_text(&run.output)
    );
    let report = load_json(&run.report_path)?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["proof_status"].as_str(),
        Some("orchestrator_smoke_passed")
    );
    assert_eq!(report["iteration_count"].as_u64(), Some(1));
    assert_eq!(
        report["iterations"][0]["runner_mode"].as_str(),
        Some("--validate-only")
    );
    assert_eq!(
        report["iterations"][0]["runner_claim_status"].as_str(),
        Some("schema_validated")
    );
    assert_eq!(
        report["iterations"][0]["runner_failure_tolerated"].as_bool(),
        Some(true),
        "smoke mode should tolerate the legacy nested L0 guard while preserving the full-run fail-closed path"
    );
    assert_eq!(report["summary"]["runner_failures"].as_u64(), Some(0));
    assert_eq!(
        report["summary"]["positive_candidate_divergences"].as_u64(),
        Some(0)
    );
    assert_eq!(report["summary"]["crash_count"].as_u64(), Some(0));
    assert!(
        report["artifact_refs"]
            .as_array()
            .is_some_and(|refs| refs.iter().any(|value| value
                .as_str()
                .is_some_and(|path| path.ends_with("standalone_link_run_smoke.report.json")))),
        "smoke report should cite nested standalone smoke report"
    );
    Ok(())
}

#[test]
fn manifest_with_short_contract_duration_fails_closed() -> TestResult {
    let root = repo_root()?;
    let mut manifest = load_json(&root.join(MANIFEST_REL))?;
    manifest["soak_policy"]["duration_seconds"] = Value::from(10);
    let out = unique_out_dir(&root, "mutated-manifest")?;
    let mutated = out.join("ws8_soak.short.v1.json");
    write_json(&mutated, &manifest)?;

    let run = run_soak(&root, "short-contract", "--validate-only", Some(&mutated))?;
    assert!(
        !run.output.status.success(),
        "short duration contract unexpectedly passed"
    );
    let report = load_json(&run.report_path)?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["failure_signatures"]
            .as_array()
            .is_some_and(|items| items.iter().any(|value| value
                .as_str()
                .is_some_and(|signature| signature == "ws8_soak_duration_too_short"))),
        "duration failure signature missing: {report:#}"
    );
    Ok(())
}
