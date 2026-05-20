//! Integration tests for the main-only branch/worktree guard.

use serde_json::Value;
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MANIFEST_REL: &str = "tests/conformance/main_only_worktree_guard.v1.json";
const CHECKER_REL: &str = "scripts/check_main_only_worktree_guard.sh";

const REQUIRED_REPORT_FIELDS: &[&str] = &[
    "schema_version",
    "manifest",
    "bead",
    "status",
    "source_commit",
    "current_state",
    "negative_controls",
    "errors",
    "generated_at",
    "report_path",
    "log_path",
    "report_contract_fields",
    "contract_status",
    "contract_errors",
];

const REQUIRED_CONTROL_IDS: &[&str] = &[
    "negative_current_branch_feature",
    "negative_extra_local_branch",
    "negative_extra_linked_worktree",
    "negative_detached_root_worktree",
    "negative_stale_legacy_mirror_ref",
];

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

fn repo_relative(root: &Path, path: &Path) -> TestResult<String> {
    Ok(path
        .strip_prefix(root)?
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/"))
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "main_only_worktree_guard_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
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

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn run_checker(root: &Path, label: &str) -> TestResult<(Output, PathBuf, PathBuf)> {
    let out = unique_out_dir(root, label)?;
    let report = out.join("main_only_worktree_guard.report.json");
    let log = out.join("main_only_worktree_guard.log.jsonl");
    let output = Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .arg("--validate-only")
        .current_dir(root)
        .env("FRANKENLIBC_MAIN_ONLY_WORKTREE_OUT_DIR", &out)
        .env("FRANKENLIBC_MAIN_ONLY_WORKTREE_REPORT", &report)
        .env("FRANKENLIBC_MAIN_ONLY_WORKTREE_LOG", &log)
        .output()?;
    Ok((output, report, log))
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
fn manifest_declares_main_only_policy_and_report_contract() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&root.join(MANIFEST_REL))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("main_only_worktree_guard.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-kt64l"));
    assert_eq!(
        manifest["policy"]["required_current_branch"].as_str(),
        Some("main")
    );
    assert_eq!(
        manifest["policy"]["allowed_local_branches"],
        serde_json::json!(["main"])
    );
    assert_eq!(
        manifest["policy"]["expected_worktree_count"].as_u64(),
        Some(1)
    );
    assert_eq!(
        manifest["policy"]["required_worktree_branch"].as_str(),
        Some("refs/heads/main")
    );
    assert_eq!(
        manifest["policy"]["require_legacy_mirror_sync"].as_bool(),
        Some(true)
    );

    let fields = string_array_set(&manifest["report_contract"], "must_materialize")?;
    for field in REQUIRED_REPORT_FIELDS {
        assert!(fields.contains(*field), "missing report field {field}");
    }

    let commands = string_array_set(&manifest, "required_validation_commands")?;
    assert!(
        commands
            .iter()
            .any(|command| command
                == "bash scripts/check_main_only_worktree_guard.sh --validate-only")
    );
    assert!(
        commands.iter().all(|command| !command.contains("cargo ")),
        "main-only guard validation must stay no-cargo"
    );

    let controls: BTreeSet<_> = json_array(&manifest, "negative_controls")?
        .iter()
        .filter_map(|control| control["id"].as_str().map(str::to_owned))
        .collect();
    for control in REQUIRED_CONTROL_IDS {
        assert!(controls.contains(*control), "missing control {control}");
    }
    Ok(())
}

#[test]
fn checker_reports_current_main_only_state_and_synced_mirror() -> TestResult {
    let root = repo_root()?;
    let (output, report_path, log_path) = run_checker(&root, "current")?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(&report_path)?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("main_only_worktree_guard.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["contract_status"].as_str(), Some("pass"));
    assert_eq!(report["bead"].as_str(), Some("bd-kt64l"));
    assert_eq!(
        report["report_path"].as_str(),
        Some(repo_relative(&root, &report_path)?.as_str())
    );
    assert_eq!(
        report["log_path"].as_str(),
        Some(repo_relative(&root, &log_path)?.as_str())
    );
    assert_eq!(
        report["current_state"]["current_branch"].as_str(),
        Some("main")
    );
    assert_eq!(
        report["current_state"]["local_branches"],
        serde_json::json!(["main"])
    );
    assert_eq!(
        report["current_state"]["remote_refs"]["origin/main"],
        report["current_state"]["remote_refs"]["origin/master"]
    );
    assert_eq!(
        json_array(&report["current_state"], "worktrees")?.len(),
        1,
        "current checkout must expose exactly one worktree"
    );
    assert!(json_array(&report, "errors")?.is_empty());
    assert!(json_array(&report, "contract_errors")?.is_empty());

    let report_fields = string_array_set(&report, "report_contract_fields")?;
    for field in REQUIRED_REPORT_FIELDS {
        assert!(
            report_fields.contains(*field),
            "missing report field {field}"
        );
    }
    Ok(())
}

#[test]
fn checker_negative_controls_cover_branch_worktree_and_mirror_drift() -> TestResult {
    let root = repo_root()?;
    let (output, report_path, log_path) = run_checker(&root, "controls")?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(&report_path)?;
    for control in REQUIRED_CONTROL_IDS {
        assert_eq!(
            control_status(&report, control)?,
            "pass",
            "negative control {control} should pass"
        );
    }

    let log_text = std::fs::read_to_string(&log_path)?;
    let events = log_text
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()?;
    assert!(
        events.iter().any(|event| {
            event["event"].as_str() == Some("main_only_worktree_guard_validated")
                && event["status"].as_str() == Some("pass")
        }),
        "log must include the pass validation event"
    );
    for control in REQUIRED_CONTROL_IDS {
        assert!(
            events.iter().any(|event| {
                event["event"].as_str() == Some("main_only_worktree_negative_control")
                    && event["control_id"].as_str() == Some(control)
                    && event["status"].as_str() == Some("pass")
            }),
            "log must include passing event for {control}"
        );
    }
    Ok(())
}
