//! Integration tests for the CI RCH cargo-policy guard.

use serde_json::Value;
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MANIFEST_REL: &str = "tests/conformance/ci_rch_cargo_policy.v1.json";
const CHECKER_REL: &str = "scripts/check_ci_rch_cargo_policy.sh";
const CI_SCRIPT_REL: &str = "scripts/ci.sh";

const REQUIRED_REPORT_FIELDS: &[&str] = &[
    "schema_version",
    "manifest",
    "ci_script",
    "bead",
    "status",
    "errors",
    "negative_controls",
    "generated_at",
    "report_path",
    "log_path",
    "report_contract_fields",
    "contract_status",
    "contract_errors",
];

const REQUIRED_CONTROL_SIGNATURES: &[(&str, &str)] = &[
    ("negative_bare_cargo_check", "bare_cargo_validation_command"),
    ("negative_missing_remote_env", "missing_remote_env"),
    ("negative_missing_target_dir", "missing_target_dir_env"),
    ("negative_missing_policy_gate", "ci_policy_gate_not_wired"),
];

struct PolicyRun {
    output: Output,
    report_path: PathBuf,
    log_path: PathBuf,
    ci_script_path: PathBuf,
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

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "ci_rch_cargo_policy_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn write_ci_script(root: &Path, out: &Path, suffix: &str) -> TestResult<PathBuf> {
    let mut text = std::fs::read_to_string(root.join(CI_SCRIPT_REL))?;
    if !suffix.is_empty() {
        text.push('\n');
        text.push_str(suffix);
        text.push('\n');
    }
    let path = out.join("ci.sh");
    std::fs::write(&path, text)?;
    Ok(path)
}

fn repo_relative(root: &Path, path: &Path) -> TestResult<String> {
    Ok(path
        .strip_prefix(root)?
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/"))
}

fn run_policy_checker(root: &Path, label: &str, ci_script_suffix: &str) -> TestResult<PolicyRun> {
    let out = unique_out_dir(root, label)?;
    let report = out.join("ci_rch_cargo_policy.report.json");
    let log = out.join("ci_rch_cargo_policy.log.jsonl");
    let ci_script = write_ci_script(root, &out, ci_script_suffix)?;

    let output = Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .arg("--validate-only")
        .current_dir(root)
        .env(
            "FRANKENLIBC_CI_RCH_CARGO_POLICY_MANIFEST",
            root.join(MANIFEST_REL),
        )
        .env("FRANKENLIBC_CI_RCH_CARGO_POLICY_SCRIPT", &ci_script)
        .env("FRANKENLIBC_CI_RCH_CARGO_POLICY_OUT_DIR", &out)
        .env("FRANKENLIBC_CI_RCH_CARGO_POLICY_REPORT", &report)
        .env("FRANKENLIBC_CI_RCH_CARGO_POLICY_LOG", &log)
        .output()?;

    Ok(PolicyRun {
        output,
        report_path: report,
        log_path: log,
        ci_script_path: ci_script,
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

fn error_signatures(report: &Value) -> TestResult<BTreeSet<String>> {
    json_array(report, "errors")?
        .iter()
        .map(|entry| {
            entry
                .get("failure_signature")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| io::Error::other("error row must have failure_signature").into())
        })
        .collect()
}

fn log_records(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

#[test]
fn manifest_declares_rch_policy_and_report_contract() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&root.join(MANIFEST_REL))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("ci_rch_cargo_policy.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-dgxsh"));
    assert_eq!(
        manifest["policy"]["remote_wrapper"].as_str(),
        Some("run_remote_cargo")
    );
    assert_eq!(
        manifest["policy"]["required_remote_env"].as_str(),
        Some("RCH_REQUIRE_REMOTE=1")
    );
    assert_eq!(
        manifest["policy"]["required_launcher"].as_str(),
        Some("rch exec -- env")
    );
    assert_eq!(
        manifest["policy"]["protected_subcommands"],
        serde_json::json!(["build", "check", "clippy", "test"])
    );
    assert_eq!(
        manifest["policy"]["allowed_local_cargo_subcommands"],
        serde_json::json!(["fmt"])
    );

    let fields = string_array_set(&manifest["report_contract"], "must_materialize")?;
    for field in REQUIRED_REPORT_FIELDS {
        assert!(fields.contains(*field), "missing report field {field}");
    }

    let controls: BTreeSet<_> = json_array(&manifest, "negative_controls")?
        .iter()
        .filter_map(|control| control["id"].as_str().map(str::to_owned))
        .collect();
    for (control_id, _) in REQUIRED_CONTROL_SIGNATURES {
        assert!(controls.contains(*control_id), "missing {control_id}");
    }

    for command in json_array(&manifest, "required_validation_commands")? {
        let command = command
            .as_str()
            .ok_or_else(|| io::Error::other("validation commands must be strings"))?;
        assert!(
            !command.contains("cargo check")
                && !command.contains("cargo clippy")
                && !command.contains("cargo test")
                && !command.contains("cargo build"),
            "static policy validation must not run cargo-backed command: {command}"
        );
    }
    Ok(())
}

#[test]
fn current_ci_script_reports_passing_rch_policy() -> TestResult {
    let root = repo_root()?;
    let run = run_policy_checker(&root, "pass", "")?;
    assert!(run.output.status.success(), "{}", output_text(&run.output));

    let report = load_json(&run.report_path)?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("ci_rch_cargo_policy.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["contract_status"].as_str(), Some("pass"));
    assert_eq!(report["bead"].as_str(), Some("bd-dgxsh"));
    assert_eq!(
        report["ci_script"].as_str(),
        Some(repo_relative(&root, &run.ci_script_path)?.as_str())
    );
    assert_eq!(
        report["report_path"].as_str(),
        Some(repo_relative(&root, &run.report_path)?.as_str())
    );
    assert_eq!(
        report["log_path"].as_str(),
        Some(repo_relative(&root, &run.log_path)?.as_str())
    );
    assert!(json_array(&report, "errors")?.is_empty());
    assert!(json_array(&report, "contract_errors")?.is_empty());

    let controls = json_array(&report, "negative_controls")?;
    assert_eq!(controls.len(), REQUIRED_CONTROL_SIGNATURES.len());
    for (control_id, signature) in REQUIRED_CONTROL_SIGNATURES {
        let row = controls
            .iter()
            .find(|row| row["control_id"].as_str() == Some(*control_id))
            .ok_or_else(|| io::Error::other(format!("missing control {control_id}")))?;
        assert_eq!(row["status"].as_str(), Some("pass"));
        assert_eq!(row["expected_failure_signature"].as_str(), Some(*signature));
    }

    let records = log_records(&run.log_path)?;
    assert_eq!(
        records.first().and_then(|record| record["event"].as_str()),
        Some("ci_rch_cargo_policy_validated")
    );
    assert_eq!(
        records
            .first()
            .and_then(|record| record["contract_status"].as_str()),
        Some("pass")
    );
    Ok(())
}

#[test]
fn bare_cargo_validation_in_ci_script_is_rejected() -> TestResult {
    let root = repo_root()?;
    let run = run_policy_checker(&root, "bare-cargo", "cargo check --workspace --all-targets")?;
    assert!(
        !run.output.status.success(),
        "mutated CI script should fail:\n{}",
        output_text(&run.output)
    );

    let report = load_json(&run.report_path)?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_eq!(report["contract_status"].as_str(), Some("pass"));
    assert!(error_signatures(&report)?.contains("bare_cargo_validation_command"));
    assert!(
        String::from_utf8_lossy(&run.output.stderr).contains("bare_cargo_validation_command"),
        "{}",
        output_text(&run.output)
    );

    let records = log_records(&run.log_path)?;
    assert_eq!(
        records.first().and_then(|record| record["event"].as_str()),
        Some("ci_rch_cargo_policy_failed")
    );
    assert_eq!(
        records
            .first()
            .and_then(|record| record["failure_count"].as_u64()),
        Some(1)
    );
    Ok(())
}
