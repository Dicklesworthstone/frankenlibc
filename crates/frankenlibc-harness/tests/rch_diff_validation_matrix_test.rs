//! Integration tests for the RCH diff validation matrix checker.

use serde_json::Value;
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CONTRACT_REL: &str = "tests/conformance/rch_diff_validation_matrix.v1.json";
const CHECKER_REL: &str = "scripts/check_rch_diff_validation_matrix.sh";

const REQUIRED_REPORT_FIELDS: &[&str] = &[
    "sample_matrix",
    "current_diff_entries",
    "current_diff_matrix",
    "current_diff_untracked_count",
    "current_static_checks",
    "current_remote_preflight_commands",
    "current_remote_cargo_commands",
    "static_checks",
    "remote_preflight_commands",
    "remote_cargo_commands",
    "negative_controls",
];

const REQUIRED_RULE_IDS: &[&str] = &[
    "abi-resolver-owned-tls",
    "standalone-tls-removal-harness-test",
    "standalone-tls-removal-manifest",
    "harness-cli-contract-test",
    "rch-diff-validation-matrix-tooling",
];

const REQUIRED_NEGATIVE_CONTROLS: &[&str] = &[
    "unknown_path_fails",
    "untracked_unknown_path_fails",
    "bare_cargo_command_fails",
    "workspace_command_fails",
];

struct MatrixRun {
    output: Output,
    report_path: PathBuf,
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

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "rch_diff_validation_matrix_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, label: &str, contract: &Path) -> TestResult<MatrixRun> {
    let out = unique_out_dir(root, label)?;
    let report = out.join("rch_diff_validation_matrix.report.json");
    let output = Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .current_dir(root)
        .env("FRANKENLIBC_RCH_DIFF_MATRIX_CONTRACT", contract)
        .env("FRANKENLIBC_RCH_DIFF_MATRIX_REPORT", &report)
        .output()?;

    Ok(MatrixRun {
        output,
        report_path: report,
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

fn command_uses_remote_marker(command: &str) -> bool {
    command.contains("RCH_REQUIRE_REMOTE=1") || command.contains("RCH_FORCE_REMOTE=true")
}

fn error_strings(report: &Value) -> TestResult<BTreeSet<String>> {
    json_array(report, "errors")?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| io::Error::other("errors entries must be strings").into())
        })
        .collect()
}

#[test]
fn manifest_declares_diff_matrix_policy_and_rules() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&root.join(CONTRACT_REL))?;

    assert_eq!(manifest["schema_version"].as_str(), Some("v1"));
    assert_eq!(
        manifest["manifest_id"].as_str(),
        Some("rch_diff_validation_matrix")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-5ci21"));
    assert_eq!(manifest["follow_up_bead"].as_str(), Some("bd-3wmqw"));
    assert_eq!(manifest["source_commit"].as_str(), Some("current"));

    assert_eq!(
        manifest["inputs"]["rch_validation_lane_plan"].as_str(),
        Some("tests/conformance/rch_validation_lane_plan.v1.json")
    );
    assert_eq!(
        manifest["inputs"]["rch_remote_admissibility_preflight"].as_str(),
        Some("scripts/check_rch_remote_admissibility.sh")
    );

    assert_eq!(
        manifest["policy"]["all_cargo_commands_must_be_remote_only"].as_bool(),
        Some(true)
    );
    assert_eq!(
        manifest["policy"]["local_cargo_is_invalid_proof"].as_bool(),
        Some(true)
    );
    assert_eq!(
        manifest["policy"]["reject_workspace_wide_commands"].as_bool(),
        Some(true)
    );
    assert_eq!(
        manifest["policy"]["include_untracked_current_diff"].as_bool(),
        Some(true)
    );
    assert_eq!(
        manifest["policy"]["current_diff_is_informational"].as_bool(),
        Some(true)
    );
    let remote_markers = string_array_set(&manifest["policy"], "remote_env_markers")?;
    assert!(remote_markers.contains("RCH_REQUIRE_REMOTE=1"));
    assert!(remote_markers.contains("RCH_FORCE_REMOTE=true"));

    let sample_paths = string_array_set(&manifest, "sample_paths")?;
    assert!(sample_paths.contains("crates/frankenlibc-abi/src/resolv_abi.rs"));
    assert!(
        sample_paths
            .contains("crates/frankenlibc-harness/tests/cli_contract_future_untracked_test.rs")
    );

    let rules: BTreeSet<_> = json_array(&manifest, "path_rules")?
        .iter()
        .filter_map(|rule| rule["rule_id"].as_str().map(str::to_owned))
        .collect();
    for rule_id in REQUIRED_RULE_IDS {
        assert!(rules.contains(*rule_id), "missing path rule {rule_id}");
    }

    let controls: BTreeSet<_> = json_array(&manifest, "negative_controls")?
        .iter()
        .filter_map(|control| control["control_id"].as_str().map(str::to_owned))
        .collect();
    for control in REQUIRED_NEGATIVE_CONTROLS {
        assert!(controls.contains(*control), "missing control {control}");
    }

    assert_eq!(
        manifest["report_contract"]["output_path"].as_str(),
        Some("target/conformance/rch_diff_validation_matrix.report.json")
    );
    let report_fields = string_array_set(&manifest["report_contract"], "must_materialize")?;
    for field in REQUIRED_REPORT_FIELDS {
        assert!(
            report_fields.contains(*field),
            "missing report field {field}"
        );
    }
    assert_eq!(
        manifest["validation"]["cargo_required"].as_bool(),
        Some(false)
    );
    Ok(())
}

#[test]
fn checker_reports_passing_matrix_and_remote_lanes() -> TestResult {
    let root = repo_root()?;
    let run = run_checker(&root, "pass", &root.join(CONTRACT_REL))?;
    assert!(run.output.status.success(), "{}", output_text(&run.output));

    let report = load_json(&run.report_path)?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("rch_diff_validation_matrix.report.v1")
    );
    assert_eq!(report["bead"].as_str(), Some("bd-5ci21"));
    assert_eq!(report["follow_up_bead"].as_str(), Some("bd-3wmqw"));
    assert_eq!(report["status"].as_str(), Some("pass"));

    let sample_paths = json_array(&report, "sample_paths")?;
    let sample_matrix = json_array(&report, "sample_matrix")?;
    assert_eq!(sample_matrix.len(), sample_paths.len());
    assert_eq!(sample_matrix.len(), 4);
    assert!(!json_array(&report, "static_checks")?.is_empty());

    for command in json_array(&report, "remote_preflight_commands")? {
        let command = command
            .as_str()
            .ok_or_else(|| io::Error::other("preflight command must be string"))?;
        assert!(command_uses_remote_marker(command));
        assert!(command.contains("check_rch_remote_admissibility.sh"));
        assert!(
            !command.starts_with("cargo "),
            "preflight must not be bare cargo"
        );
    }
    for command in json_array(&report, "remote_cargo_commands")? {
        let command = command
            .as_str()
            .ok_or_else(|| io::Error::other("remote cargo command must be string"))?;
        assert!(command_uses_remote_marker(command));
        assert!(command.contains("rch exec"));
        assert!(command.contains("cargo "));
        assert!(
            !command.contains("--workspace"),
            "sample lanes must stay focused"
        );
    }

    for entry in json_array(&report, "current_diff_entries")? {
        let status = entry["status"]
            .as_str()
            .ok_or_else(|| io::Error::other("current diff entry must have status"))?;
        assert!(
            status == "tracked_modified" || status == "untracked",
            "unexpected current diff status {status}"
        );
    }

    let controls = json_array(&report, "negative_controls")?;
    assert_eq!(controls.len(), REQUIRED_NEGATIVE_CONTROLS.len());
    for control in REQUIRED_NEGATIVE_CONTROLS {
        let row = controls
            .iter()
            .find(|row| row["control_id"].as_str() == Some(*control))
            .ok_or_else(|| io::Error::other(format!("missing control {control}")))?;
        assert_eq!(row["status"].as_str(), Some("pass"));
    }
    assert!(json_array(&report, "errors")?.is_empty());
    Ok(())
}

#[test]
fn checker_rejects_bare_cargo_matrix_command() -> TestResult {
    let root = repo_root()?;
    let out = unique_out_dir(&root, "bare-cargo-contract")?;
    let contract_path = out.join("rch_diff_validation_matrix.mutated.json");
    let mut contract = load_json(&root.join(CONTRACT_REL))?;
    contract["path_rules"][0]["remote_cargo_commands"][0] =
        serde_json::json!("cargo check -p frankenlibc-abi");
    write_json(&contract_path, &contract)?;

    let run = run_checker(&root, "bare-cargo", &contract_path)?;
    assert!(
        !run.output.status.success(),
        "mutated matrix should fail:\n{}",
        output_text(&run.output)
    );

    let report = load_json(&run.report_path)?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        error_strings(&report)?
            .iter()
            .any(|error| error.contains("bare_cargo_command")),
        "expected bare_cargo_command in report errors: {report:#}"
    );
    assert!(
        String::from_utf8_lossy(&run.output.stdout).contains("bare_cargo_command"),
        "{}",
        output_text(&run.output)
    );
    Ok(())
}
