//! Integration tests for the RCH validation debt ledger checker.

use serde_json::Value;
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const LEDGER_REL: &str = "tests/conformance/rch_validation_debt_ledger.v1.json";
const CHECKER_REL: &str = "scripts/check_rch_validation_debt_ledger.sh";

const REQUIRED_REPORT_FIELDS: &[&str] = &[
    "schema_version",
    "source",
    "status",
    "entry_count",
    "failure_count",
    "failures",
    "events",
    "report_path",
    "log_path",
    "report_contract_fields",
    "contract_status",
    "contract_errors",
];

const REQUIRED_CONTROL_NAMES: &[&str] = &[
    "negative_missing_remote_command",
    "negative_local_fallback_accepted",
    "negative_complete_without_remote_proof",
    "negative_wrong_blocker",
    "negative_report_output_path_mismatch",
    "negative_report_log_path_mismatch",
    "negative_report_contract_missing_required_field",
    "negative_missing_report_field",
];

struct LedgerRun {
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
        "rch_validation_debt_ledger_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, label: &str, ledger: &Path) -> TestResult<LedgerRun> {
    let out = unique_out_dir(root, label)?;
    let report = out.join("rch_validation_debt_ledger.report.json");
    let log = out.join("rch_validation_debt_ledger.log.jsonl");
    let output = Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .current_dir(root)
        .env("FRANKENLIBC_RCH_VALIDATION_DEBT_LEDGER", ledger)
        .env("FRANKENLIBC_RCH_VALIDATION_DEBT_OUT_DIR", &out)
        .output()?;

    Ok(LedgerRun {
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

fn log_records(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn failure_signatures(report: &Value) -> TestResult<BTreeSet<String>> {
    json_array(report, "failures")?
        .iter()
        .map(|entry| {
            entry
                .get("failure_signature")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| io::Error::other("failure row must have failure_signature").into())
        })
        .collect()
}

fn control_names(report: &Value) -> TestResult<BTreeSet<String>> {
    json_array(report, "events")?
        .iter()
        .filter(|event| event["event"].as_str() == Some("negative_control"))
        .map(|event| {
            event
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| io::Error::other("negative_control event must have name").into())
        })
        .collect()
}

#[test]
fn ledger_declares_static_replay_contract() -> TestResult {
    let root = repo_root()?;
    let ledger = load_json(&root.join(LEDGER_REL))?;

    assert_eq!(
        ledger["schema_version"].as_str(),
        Some("rch_validation_debt_ledger.v1")
    );
    assert_eq!(ledger["ledger_kind"].as_str(), Some("static_replay_plan"));
    assert_eq!(ledger["bead"].as_str(), Some("bd-5d3aa"));
    assert_eq!(ledger["blocker_bead"].as_str(), Some("bd-716tv"));
    assert_eq!(
        ledger["claim_policy"]["claim_allowed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        ledger["local_fallback_policy"]["accept_local_cargo"].as_bool(),
        Some(false)
    );
    assert_eq!(
        ledger["local_fallback_policy"]["required_remote_env"].as_str(),
        Some("RCH_REQUIRE_REMOTE=1")
    );

    let rejected = string_array_set(&ledger["local_fallback_policy"], "rejected_markers")?;
    assert!(rejected.contains("[RCH] local"));
    assert!(rejected.contains("remote required; refusing local fallback"));

    assert_eq!(
        ledger["report_contract"]["output_path"].as_str(),
        Some("target/conformance/rch_validation_debt_ledger.report.json")
    );
    assert_eq!(
        ledger["report_contract"]["log_path"].as_str(),
        Some("target/conformance/rch_validation_debt_ledger.log.jsonl")
    );
    let report_fields = string_array_set(&ledger["report_contract"], "must_materialize")?;
    for field in REQUIRED_REPORT_FIELDS {
        assert!(
            report_fields.contains(*field),
            "missing report field {field}"
        );
    }
    let report_controls = string_array_set(&ledger["report_contract"], "negative_controls")?;
    for control in [
        "negative_report_output_path_mismatch",
        "negative_report_log_path_mismatch",
        "negative_report_contract_missing_required_field",
        "negative_missing_report_field",
    ] {
        assert!(report_controls.contains(control), "missing {control}");
    }

    let expected_beads = string_array_set(&ledger, "expected_pending_beads")?;
    let entries = json_array(&ledger, "entries")?;
    assert_eq!(entries.len(), expected_beads.len());
    assert_eq!(entries.len(), 18);
    let mut seen = BTreeSet::new();
    for entry in entries {
        let bead = entry["bead_id"]
            .as_str()
            .ok_or_else(|| io::Error::other("entry must have bead_id"))?;
        seen.insert(bead.to_owned());
        assert_eq!(entry["blocker_bead"].as_str(), Some("bd-716tv"));
        assert_eq!(
            entry["replay_status"].as_str(),
            Some("pending_rch_admissibility")
        );
        assert!(entry["remote_proof"].is_null());

        let commit = entry["source_commit"]
            .as_str()
            .ok_or_else(|| io::Error::other("entry must have source_commit"))?;
        assert_eq!(commit.len(), 40, "source_commit must be full SHA");
        assert!(commit.chars().all(|ch| ch.is_ascii_hexdigit()));

        for command in json_array(entry, "remote_validation_commands")? {
            let command = command.as_str().ok_or_else(|| {
                io::Error::other("remote_validation_commands entries must be strings")
            })?;
            assert!(command.contains("RCH_REQUIRE_REMOTE=1"));
            assert!(command.contains("rch exec"));
            assert!(command.contains("cargo "));
            assert!(
                !command.contains("[RCH] local"),
                "remote command must not embed fallback output"
            );
        }
        for check in json_array(entry, "static_checks")? {
            let command = check["command"]
                .as_str()
                .ok_or_else(|| io::Error::other("static check must have command"))?;
            assert!(!command.contains("rch exec"));
            assert!(!command.contains("cargo "));
            assert_eq!(check["status"].as_str(), Some("pass"));
        }
    }
    assert_eq!(seen, expected_beads);
    Ok(())
}

#[test]
fn checker_reports_passing_debt_ledger_and_controls() -> TestResult {
    let root = repo_root()?;
    let run = run_checker(&root, "pass", &root.join(LEDGER_REL))?;
    assert!(run.output.status.success(), "{}", output_text(&run.output));

    let report = load_json(&run.report_path)?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("rch_validation_debt_ledger.report.v1")
    );
    assert_eq!(report["source"].as_str(), Some(LEDGER_REL));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["entry_count"].as_u64(), Some(18));
    assert_eq!(report["failure_count"].as_u64(), Some(0));
    assert!(json_array(&report, "failures")?.is_empty());
    assert_eq!(
        report["report_path"].as_str(),
        Some(repo_relative(&root, &run.report_path)?.as_str())
    );
    assert_eq!(
        report["log_path"].as_str(),
        Some(repo_relative(&root, &run.log_path)?.as_str())
    );
    assert_eq!(report["contract_status"].as_str(), Some("pass"));
    assert!(json_array(&report, "contract_errors")?.is_empty());

    let fields = string_array_set(&report, "report_contract_fields")?;
    for field in REQUIRED_REPORT_FIELDS {
        assert!(fields.contains(*field), "missing report field {field}");
    }

    let controls = control_names(&report)?;
    for control in REQUIRED_CONTROL_NAMES {
        assert!(controls.contains(*control), "missing control {control}");
    }
    for event in json_array(&report, "events")? {
        if event["event"].as_str() == Some("negative_control") {
            assert_eq!(event["status"].as_str(), Some("pass"));
        }
    }

    let records = log_records(&run.log_path)?;
    assert_eq!(
        records.first().and_then(|record| record["event"].as_str()),
        Some("ledger_validated")
    );
    assert_eq!(
        records.first().and_then(|record| record["status"].as_str()),
        Some("pass")
    );
    assert_eq!(records.len(), REQUIRED_CONTROL_NAMES.len() + 1);
    Ok(())
}

#[test]
fn checker_rejects_ledger_without_remote_commands() -> TestResult {
    let root = repo_root()?;
    let out = unique_out_dir(&root, "missing-remote-command-ledger")?;
    let ledger_path = out.join("rch_validation_debt_ledger.mutated.json");
    let mut ledger = load_json(&root.join(LEDGER_REL))?;
    ledger["entries"][0]["remote_validation_commands"] = serde_json::json!([]);
    write_json(&ledger_path, &ledger)?;

    let run = run_checker(&root, "missing-remote-command", &ledger_path)?;
    assert!(
        !run.output.status.success(),
        "mutated ledger should fail:\n{}",
        output_text(&run.output)
    );

    let report = load_json(&run.report_path)?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_eq!(report["contract_status"].as_str(), Some("fail"));
    assert!(failure_signatures(&report)?.contains("missing_remote_command"));
    assert!(
        String::from_utf8_lossy(&run.output.stdout).contains("missing_remote_command"),
        "{}",
        output_text(&run.output)
    );

    let records = log_records(&run.log_path)?;
    assert_eq!(
        records.first().and_then(|record| record["event"].as_str()),
        Some("ledger_validated")
    );
    assert_eq!(
        records.first().and_then(|record| record["status"].as_str()),
        Some("fail")
    );
    Ok(())
}
