//! Integration tests for the RCH remote-admissibility preflight.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CONTRACT_REL: &str = "tests/conformance/rch_remote_admissibility_preflight.v1.json";
const CHECKER_REL: &str = "scripts/check_rch_remote_admissibility.sh";
const VALIDATION_COMMAND: &str = "cargo check -p frankenlibc-abi --features=standalone";

const REQUIRED_REPORT_FIELDS: &[&str] = &[
    "schema_version",
    "bead",
    "contract_bead",
    "generated_at_utc",
    "source_commit",
    "current_head",
    "report_path",
    "log_path",
    "validation_command",
    "required_remote_env",
    "dry_run",
    "status",
    "failure_signatures",
    "proof_disposition",
    "approval_packet_command",
    "approval_packet_report_path",
    "approval_packet_markdown_path",
    "approval_readiness_summary",
    "operator_message",
    "local_fallback_policy",
    "status_on_current_blocked_state",
    "report_contract_fields",
    "negative_controls",
    "contract_status",
    "contract_errors",
];

const REQUIRED_CONTROL_IDS: &[&str] = &[
    "local_fallback_signature_blocks",
    "remote_required_refusal_sample_is_blocker_evidence",
    "leading_command_separator_not_forwarded",
    "diagnose_failure_blocks",
    "admissible_without_failures_passes",
    "missing_report_field_fails",
    "output_path_mismatch_fails",
    "log_path_mismatch_fails",
    "missing_required_signature_current_state_fails",
    "admissible_current_state_is_not_blocked",
];

struct PreflightRun {
    output: Output,
    report_path: PathBuf,
    log_path: PathBuf,
}

fn repo_root() -> TestResult<PathBuf> {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| io::Error::other("crate directory should have workspace parent"))?;
    let root = crates_dir
        .parent()
        .ok_or_else(|| io::Error::other("workspace parent should have repo parent"))?;
    Ok(root.to_path_buf())
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn repo_relative(root: &Path, path: &Path) -> TestResult<String> {
    Ok(path
        .strip_prefix(root)?
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/"))
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "rch_remote_admissibility_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn prepare_contract(root: &Path, out: &Path) -> TestResult<(PathBuf, PathBuf, PathBuf)> {
    let report = out.join("rch_remote_admissibility.report.json");
    let log = out.join("rch_remote_admissibility.log.jsonl");
    let mut contract = load_json(&root.join(CONTRACT_REL))?;
    contract["report_contract"]["output_path"] = json!(repo_relative(root, &report)?);
    contract["report_contract"]["log_path"] = json!(repo_relative(root, &log)?);
    let contract_path = out.join("rch_remote_admissibility.contract.json");
    write_json(&contract_path, &contract)?;
    Ok((contract_path, report, log))
}

fn write_dry_run(path: &Path, text: &str) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, text)?;
    Ok(())
}

fn run_preflight(root: &Path, label: &str, dry_run_text: &str) -> TestResult<PreflightRun> {
    let out = unique_out_dir(root, label)?;
    let dry_run = out.join("rch_diagnose_dry_run.sample.out");
    let (contract, report, log) = prepare_contract(root, &out)?;
    write_dry_run(&dry_run, dry_run_text)?;

    let output = Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .arg(VALIDATION_COMMAND)
        .current_dir(root)
        .env("FRANKENLIBC_RCH_PREFLIGHT_CONTRACT", &contract)
        .env("FRANKENLIBC_RCH_PREFLIGHT_OUT_DIR", &out)
        .env("FRANKENLIBC_RCH_PREFLIGHT_REPORT", &report)
        .env("FRANKENLIBC_RCH_PREFLIGHT_LOG", &log)
        .env("FRANKENLIBC_RCH_PREFLIGHT_DRY_RUN_OUTPUT", &dry_run)
        .env(
            "FRANKENLIBC_RCH_PACKET_REPORT",
            out.join("approval_packet.report.json"),
        )
        .env(
            "FRANKENLIBC_RCH_PACKET_MARKDOWN",
            out.join("approval_packet.approval.md"),
        )
        .output()?;

    Ok(PreflightRun {
        output,
        report_path: report,
        log_path: log,
    })
}

fn admissible_dry_run() -> &'static str {
    "Would offload: YES\nWorker selection: ts1\nCommand classified for remote execution\n"
}

fn blocked_dry_run() -> &'static str {
    concat!(
        "Would offload: YES\n",
        "Skip: worker selection skipped (no admissible workers: critical_pressure=7)\n"
    )
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::other(format!("{field} must be an array")).into())
}

fn string_array_set(value: &Value, field: &str) -> TestResult<BTreeSet<String>> {
    json_array(value, field)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| io::Error::other(format!("{field} entries must be strings")).into())
        })
        .collect()
}

fn control_status(report: &Value, control_id: &str) -> TestResult<String> {
    json_array(report, "negative_controls")?
        .iter()
        .find(|control| control["control_id"].as_str() == Some(control_id))
        .and_then(|control| control["status"].as_str())
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other(format!("missing negative control {control_id}")).into())
}

#[test]
fn manifest_declares_remote_required_contract_and_controls() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&root.join(CONTRACT_REL))?;

    assert_eq!(
        manifest["manifest_id"].as_str(),
        Some("rch_remote_admissibility_preflight")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-rchk0.95"));
    assert_eq!(
        manifest["preflight_contract"]["required_remote_env"].as_str(),
        Some("RCH_REQUIRE_REMOTE=1")
    );
    assert_eq!(
        manifest["preflight_contract"]["local_fallback_policy"].as_str(),
        Some("[RCH] local is never accepted as validation proof.")
    );

    let fields = string_array_set(&manifest["report_contract"], "must_materialize")?;
    for field in REQUIRED_REPORT_FIELDS {
        assert!(fields.contains(*field), "missing report field {field}");
    }

    let controls: BTreeSet<_> = json_array(&manifest, "negative_controls")?
        .iter()
        .filter_map(|control| control["control_id"].as_str().map(str::to_owned))
        .collect();
    for control in REQUIRED_CONTROL_IDS {
        assert!(controls.contains(*control), "missing control {control}");
    }
    Ok(())
}

#[test]
fn admissible_dry_run_reports_validation_proof() -> TestResult {
    let root = repo_root()?;
    let run = run_preflight(&root, "admissible", admissible_dry_run())?;
    assert!(run.output.status.success(), "{}", output_text(&run.output));

    let report = load_json(&run.report_path)?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("rch_remote_admissibility_preflight.v1")
    );
    assert_eq!(report["contract_status"].as_str(), Some("pass"));
    assert_eq!(report["status"].as_str(), Some("admissible"));
    assert_eq!(
        report["validation_command"].as_str(),
        Some(VALIDATION_COMMAND)
    );
    assert_eq!(
        report["status_on_current_blocked_state"].as_str(),
        Some("not_current_blocked_state")
    );
    assert_eq!(
        report["proof_disposition"]["evidence_kind"].as_str(),
        Some("validation_proof")
    );
    assert_eq!(
        report["proof_disposition"]["counts_as_validation_proof"].as_bool(),
        Some(true)
    );
    assert_eq!(
        report["proof_disposition"]["counts_as_blocker_evidence"].as_bool(),
        Some(false)
    );
    assert!(json_array(&report, "failure_signatures")?.is_empty());

    for control in REQUIRED_CONTROL_IDS {
        assert_eq!(
            control_status(&report, control)?,
            "pass",
            "negative control {control} should pass"
        );
    }
    Ok(())
}

#[test]
fn blocked_dry_run_reports_blocker_evidence_and_required_signatures() -> TestResult {
    let root = repo_root()?;
    let run = run_preflight(&root, "blocked", blocked_dry_run())?;
    assert_eq!(
        run.output.status.code(),
        Some(2),
        "{}",
        output_text(&run.output)
    );

    let report = load_json(&run.report_path)?;
    assert_eq!(report["contract_status"].as_str(), Some("pass"));
    assert_eq!(report["status"].as_str(), Some("blocked"));
    assert_eq!(
        report["status_on_current_blocked_state"].as_str(),
        Some("blocked")
    );
    assert_eq!(
        report["proof_disposition"]["evidence_kind"].as_str(),
        Some("blocker_evidence")
    );
    assert_eq!(
        report["proof_disposition"]["counts_as_validation_proof"].as_bool(),
        Some(false)
    );
    assert_eq!(
        report["proof_disposition"]["counts_as_blocker_evidence"].as_bool(),
        Some(true)
    );
    assert_eq!(
        report["proof_disposition"]["remote_refusal_reason"].as_str(),
        Some("no_admissible_workers")
    );

    let signatures = string_array_set(&report, "failure_signatures")?;
    for signature in [
        "critical_pressure",
        "no_admissible_workers",
        "worker_selection_skipped",
    ] {
        assert!(signatures.contains(signature), "missing {signature}");
    }

    let log_text = std::fs::read_to_string(&run.log_path)?;
    let event: Value = serde_json::from_str(
        log_text
            .lines()
            .next()
            .ok_or_else(|| io::Error::other("preflight log must have an event"))?,
    )?;
    assert_eq!(event["status"].as_str(), Some("blocked"));
    assert_eq!(
        event["validation_command"].as_str(),
        Some(VALIDATION_COMMAND)
    );
    assert_eq!(event["failure_signatures"], report["failure_signatures"]);
    Ok(())
}
