//! Integration tests for the change-surface validation planner (bd-zaijr5).

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MANIFEST_REL: &str = "tests/conformance/change_surface_validation_planner.v1.json";
const PLANNER_REL: &str = "scripts/plan_change_surface_validation.sh";

struct PlannerRun {
    output: Output,
    manifest_path: PathBuf,
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

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "change_surface_validation_planner_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_planner(
    root: &Path,
    label: &str,
    paths: &[String],
    extra_args: &[String],
) -> TestResult<PlannerRun> {
    let out = unique_out_dir(root, label)?;
    let manifest_path = out.join("validation_manifest.json");
    let log_path = out.join("events.log.jsonl");
    let mut command = Command::new("bash");
    command
        .arg(root.join(PLANNER_REL))
        .arg("--bead")
        .arg("bd-zaijr5")
        .arg("--manifest")
        .arg(root.join(MANIFEST_REL))
        .arg("--output")
        .arg(&manifest_path)
        .arg("--log")
        .arg(&log_path)
        .current_dir(root);
    for arg in extra_args {
        command.arg(arg);
    }
    for path in paths {
        command.arg(path);
    }
    let output = command.output()?;
    Ok(PlannerRun {
        output,
        manifest_path,
        log_path,
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
        .ok_or_else(|| test_error(format!("{field} must be an array")))
}

fn string_set(value: &Value, field: &str) -> TestResult<BTreeSet<String>> {
    json_array(value, field)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error(format!("{field} entries must be strings")))
        })
        .collect()
}

fn command_proof_classes(report: &Value) -> TestResult<BTreeSet<String>> {
    json_array(report, "commands")?
        .iter()
        .map(|entry| {
            entry["proof_class"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("command.proof_class must be string"))
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
fn contract_declares_validation_manifest_and_remote_policy() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&root.join(MANIFEST_REL))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("change_surface_validation_planner.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-zaijr5"));
    assert_eq!(
        manifest["output_schema"].as_str(),
        Some("validation_manifest.v1")
    );
    assert_eq!(
        manifest["proof_policy"]["cargo_requires_rch"].as_bool(),
        Some(true)
    );
    assert_eq!(
        manifest["proof_policy"]["required_remote_env"],
        serde_json::json!(["RCH_REQUIRE_REMOTE=1"])
    );
    assert_eq!(
        manifest["proof_policy"]["required_launcher"].as_str(),
        Some("rch exec -- env")
    );
    assert_eq!(
        manifest["proof_policy"]["required_target_dir_env"].as_str(),
        Some("CARGO_TARGET_DIR=")
    );
    assert_eq!(
        manifest["proof_policy"]["local_fallback_invalid"].as_bool(),
        Some(true)
    );

    let categories = string_set(&manifest["classification_contract"], "supported_categories")?;
    for category in [
        "tracker",
        "rust_crate_code",
        "rust_crate_test",
        "script",
        "contract",
        "conformance_json",
        "docs",
        "other",
    ] {
        assert!(categories.contains(category), "missing category {category}");
    }

    let required_failures = string_set(&manifest, "required_failure_signatures")?;
    for signature in [
        "invalid_changed_path",
        "bare_local_cargo_proof",
        "missing_remote_env",
        "missing_rch_exec_env",
        "missing_isolated_target_dir",
        "local_fallback_marker",
    ] {
        assert!(
            required_failures.contains(signature),
            "missing failure signature {signature}"
        );
    }
    Ok(())
}

#[test]
fn planner_classifies_sample_cases_and_emits_manifest_contract() -> TestResult {
    let root = repo_root()?;
    let contract = read_json(&root.join(MANIFEST_REL))?;
    let cases = json_array(&contract, "sample_cases")?;
    assert!(
        cases.len() >= 7,
        "sample cases must cover all requested surfaces"
    );

    for case in cases {
        let case_id = case["case_id"]
            .as_str()
            .ok_or_else(|| test_error("case_id must be string"))?;
        let paths: Vec<String> = json_array(case, "changed_paths")?
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| test_error("changed_paths entries must be strings"))
            })
            .collect::<TestResult<_>>()?;
        let run = run_planner(&root, case_id, &paths, &[])?;
        assert!(
            run.output.status.success(),
            "planner failed for case {case_id}: {}",
            output_text(&run.output)
        );

        let report = read_json(&run.manifest_path)?;
        assert_eq!(
            report["schema_version"].as_str(),
            Some("validation_manifest.v1")
        );
        assert_eq!(report["bead_id"].as_str(), Some("bd-zaijr5"));
        assert_eq!(report["status"].as_str(), Some("pass"));
        assert_eq!(
            report["changed_paths"].as_array().map(Vec::len),
            Some(paths.len()),
            "changed paths mismatch for {case_id}"
        );

        let categories = string_set(&report["surface_summary"], "categories")?;
        for expected in json_array(case, "expected_categories")? {
            let expected = expected
                .as_str()
                .ok_or_else(|| test_error("expected_categories entries must be strings"))?;
            assert!(
                categories.contains(expected),
                "{case_id}: expected category {expected}, got {categories:?}"
            );
        }

        let crates = string_set(&report["surface_summary"], "crates")?;
        for expected in json_array(case, "expected_crates")? {
            let expected = expected
                .as_str()
                .ok_or_else(|| test_error("expected_crates entries must be strings"))?;
            assert!(
                crates.contains(expected),
                "{case_id}: expected crate {expected}, got {crates:?}"
            );
        }

        let proof_classes = command_proof_classes(&report)?;
        for expected in json_array(case, "expected_proof_classes")? {
            let expected = expected
                .as_str()
                .ok_or_else(|| test_error("expected_proof_classes entries must be strings"))?;
            assert!(
                proof_classes.contains(expected),
                "{case_id}: expected proof class {expected}, got {proof_classes:?}"
            );
        }

        assert_eq!(
            report["surface_summary"]["cargo_required"].as_bool(),
            case["expected_cargo_required"].as_bool(),
            "{case_id}: cargo_required mismatch"
        );
        assert_eq!(
            report["surface_summary"]["mixed"].as_bool(),
            case["expected_mixed"].as_bool(),
            "{case_id}: mixed mismatch"
        );
        assert_eq!(
            report["surface_summary"]["tracker_only"].as_bool(),
            case["expected_tracker_only"].as_bool(),
            "{case_id}: tracker_only mismatch"
        );

        assert!(
            report["agent_mail_handoff"]["body_md"]
                .as_str()
                .is_some_and(|body| body.contains("validation_manifest.v1")),
            "{case_id}: handoff body missing schema"
        );
        assert!(
            report["close_reason_snippet"]
                .as_str()
                .is_some_and(|snippet| snippet.contains("validation_manifest.v1")),
            "{case_id}: close reason snippet missing schema"
        );

        let events = log_records(&run.log_path)?;
        assert!(
            events
                .iter()
                .any(|event| event["event"].as_str() == Some("planner_summary")),
            "{case_id}: planner_summary log event missing"
        );
    }
    Ok(())
}

#[test]
fn remote_cargo_commands_are_rch_only_and_target_dir_isolated() -> TestResult {
    let root = repo_root()?;
    let paths = vec!["crates/frankenlibc-core/src/string/mod.rs".to_owned()];
    let run = run_planner(&root, "remote-policy", &paths, &[])?;
    assert!(run.output.status.success(), "{}", output_text(&run.output));
    let report = read_json(&run.manifest_path)?;
    let commands = json_array(&report, "commands")?;

    let mut remote_count = 0;
    for command in commands {
        let text = command["command"]
            .as_str()
            .ok_or_else(|| test_error("command must be string"))?;
        let is_cargo = ["cargo check", "cargo clippy", "cargo test", "cargo build"]
            .iter()
            .any(|needle| text.contains(needle));
        if !is_cargo {
            continue;
        }
        remote_count += 1;
        assert!(
            text.contains("RCH_REQUIRE_REMOTE=1"),
            "cargo command must require remote: {text}"
        );
        assert!(
            text.contains("rch exec -- env"),
            "cargo command must use rch exec -- env: {text}"
        );
        assert!(
            text.contains("CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-zaijr5-"),
            "cargo command must isolate target dir: {text}"
        );
        assert_eq!(command["requires_rch_remote"].as_bool(), Some(true));
        assert_eq!(command["reject_local_fallback"].as_bool(), Some(true));
        assert!(
            command["forbidden_output_markers"]
                .as_array()
                .is_some_and(|markers| markers
                    .iter()
                    .any(|marker| marker.as_str() == Some("[RCH] local"))),
            "remote command must carry forbidden local marker"
        );
        assert!(
            command["reason"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "command reason missing"
        );
        assert!(
            command["expected_scope"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "command expected_scope missing"
        );
        assert!(
            command["target_dir_isolation_guidance"]
                .as_str()
                .is_some_and(|value| value.contains("CARGO_TARGET_DIR")),
            "target-dir guidance missing"
        );
    }
    assert!(
        remote_count >= 3,
        "expected check/test/clippy remote cargo commands"
    );
    Ok(())
}

#[test]
fn planner_rejects_invalid_paths_and_local_fallback_markers() -> TestResult {
    let root = repo_root()?;
    let invalid_paths = vec!["../outside.rs".to_owned()];
    let invalid = run_planner(&root, "invalid-path", &invalid_paths, &[])?;
    assert!(
        !invalid.output.status.success(),
        "invalid path unexpectedly passed"
    );
    let invalid_report = read_json(&invalid.manifest_path)?;
    assert!(
        string_set(&invalid_report, "failure_signatures")?.contains("invalid_changed_path"),
        "invalid path signature missing: {invalid_report:#}"
    );

    let proof_dir = unique_out_dir(&root, "fallback-proof")?;
    let proof_log = proof_dir.join("rch-output.log");
    std::fs::write(&proof_log, "starting\n[RCH] local fallback selected\n")?;
    let proof_arg = vec![
        "--proof-log".to_owned(),
        proof_log.to_string_lossy().to_string(),
    ];
    let paths = vec!["crates/frankenlibc-core/src/string/mod.rs".to_owned()];
    let fallback = run_planner(&root, "fallback", &paths, &proof_arg)?;
    assert!(
        !fallback.output.status.success(),
        "local fallback proof marker unexpectedly passed"
    );
    let fallback_report = read_json(&fallback.manifest_path)?;
    assert!(
        string_set(&fallback_report, "failure_signatures")?.contains("local_fallback_marker"),
        "fallback signature missing: {fallback_report:#}"
    );
    let records = log_records(&fallback.log_path)?;
    assert!(
        records
            .iter()
            .any(|event| event["event"].as_str() == Some("proof_log_rejected")),
        "proof_log_rejected event missing"
    );
    Ok(())
}
