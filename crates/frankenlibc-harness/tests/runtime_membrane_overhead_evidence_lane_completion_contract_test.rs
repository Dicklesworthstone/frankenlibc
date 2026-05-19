use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::Value;
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

fn contract_path(root: &Path) -> PathBuf {
    root.join(
        "tests/conformance/runtime_membrane_overhead_evidence_lane_completion_contract.v1.json",
    )
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_runtime_membrane_overhead_evidence_lane_completion_contract.sh")
}

fn contention_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/tsm_contention_e2e_lane.v1.json")
}

fn issues_path(root: &Path) -> PathBuf {
    root.join(".beads/issues.jsonl")
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
        "runtime_membrane_overhead_completion_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(
    root: &Path,
    contract: &Path,
    issues: Option<&Path>,
    out_dir: &Path,
) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_RUNTIME_MEMBRANE_OVERHEAD_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_RUNTIME_MEMBRANE_OVERHEAD_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_RUNTIME_MEMBRANE_OVERHEAD_COMPLETION_REPORT",
            out_dir.join("completion.report.json"),
        )
        .env(
            "FRANKENLIBC_RUNTIME_MEMBRANE_OVERHEAD_COMPLETION_LOG",
            out_dir.join("completion.log.jsonl"),
        );
    if let Some(path) = issues {
        command.env(
            "FRANKENLIBC_RUNTIME_MEMBRANE_OVERHEAD_COMPLETION_ISSUES",
            path,
        );
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

fn json_array<'a>(value: &'a Value, key: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("{key} must be an array")))
}

fn string_set(value: &Value, key: &str) -> TestResult<BTreeSet<String>> {
    json_array(value, key)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error(format!("{key} item must be string")))
        })
        .collect()
}

fn failure_signatures(report: &Value) -> TestResult<BTreeSet<String>> {
    json_array(report, "errors")?
        .iter()
        .map(|row| {
            row.get("failure_signature")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| test_error("error row missing failure_signature"))
        })
        .collect()
}

fn write_contract_variant(
    root: &Path,
    label: &str,
    mutate: impl FnOnce(&mut Value, &Path) -> TestResult,
) -> TestResult<(PathBuf, PathBuf)> {
    let out_dir = unique_out_dir(root, label)?;
    let mut contract = load_json(&contract_path(root))?;
    mutate(&mut contract, &out_dir)?;
    let path = out_dir.join(format!("{label}.json"));
    write_json(&path, &contract)?;
    Ok((path, out_dir))
}

fn write_closed_child_issues_snapshot(root: &Path, out_dir: &Path) -> TestResult<PathBuf> {
    let required = ["bd-e1eko", "bd-rakj1", "bd-hdflr"];
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    for line in std::fs::read_to_string(issues_path(root))?.lines() {
        let mut row: Value = serde_json::from_str(line)?;
        if let Some(id) = row["id"].as_str().map(str::to_owned)
            && required.contains(&id.as_str())
        {
            row["status"] = Value::String("closed".to_string());
            if row["closed_at"].is_null() {
                row["closed_at"] = Value::String("2026-05-18T00:00:00Z".to_string());
            }
            seen.insert(id);
        }
        rows.push(serde_json::to_string(&row)?);
    }
    for id in required {
        if !seen.contains(id) {
            rows.push(format!(
                r#"{{"id":"{id}","title":"synthetic closed child","status":"closed","closed_at":"2026-05-18T00:00:00Z"}}"#
            ));
        }
    }
    let issues = out_dir.join("closed-child-issues.jsonl");
    std::fs::write(&issues, rows.join("\n") + "\n")?;
    Ok(issues)
}

#[test]
fn manifest_binds_children_policies_and_rch_proof_shape() -> TestResult {
    let root = repo_root()?;
    let contract = load_json(&contract_path(&root))?;
    assert_eq!(
        contract["schema_version"].as_str(),
        Some("runtime_membrane_overhead_evidence_lane_completion_contract.v1")
    );
    assert_eq!(contract["bead"].as_str(), Some("bd-owqho"));

    let child_ids: BTreeSet<_> = json_array(&contract, "child_artifacts")?
        .iter()
        .filter_map(|child| child["bead"].as_str())
        .collect();
    assert_eq!(
        child_ids,
        BTreeSet::from(["bd-e1eko", "bd-hdflr", "bd-rakj1"])
    );
    assert_eq!(
        contract["closure_policy"]["public_claim_must_remain_blocked_without_permissioned_evidence"].as_bool(),
        Some(true)
    );
    assert_eq!(
        contract["closure_policy"]["no_local_cargo_proof_counted"].as_bool(),
        Some(true)
    );

    let commands: Vec<_> = json_array(&contract, "required_remote_validation_commands")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for required in ["cargo test", "cargo check", "cargo clippy"] {
        assert!(
            commands.iter().any(|command| command.contains(required)),
            "missing {required} command"
        );
    }
    for command in commands {
        assert!(command.contains("RCH_REQUIRE_REMOTE=1"));
        assert!(command.contains("rch exec -- cargo"));
        assert!(!command.contains("[RCH] local"));
    }

    let events = string_set(&contract, "structured_log_events")?;
    assert!(events.contains("runtime_membrane_overhead_completion_contract_validated"));
    Ok(())
}

#[test]
fn checker_replays_children_and_blocks_public_claims() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "pass")?;
    let issues = write_closed_child_issues_snapshot(&root, &out_dir)?;
    let output = run_checker(&root, &contract_path(&root), Some(&issues), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(&out_dir.join("completion.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("runtime_membrane_overhead_evidence_lane_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["children_verified"].as_array().map(Vec::len),
        Some(3)
    );
    assert_eq!(report["replay_reports"].as_array().map(Vec::len), Some(3));
    assert_eq!(report["errors"].as_array().map(Vec::len), Some(0));

    let hdflr = json_array(&report, "replay_reports")?
        .iter()
        .find(|row| row["bead"].as_str() == Some("bd-hdflr"))
        .ok_or_else(|| test_error("bd-hdflr replay missing"))?;
    assert_eq!(
        hdflr["report_json"]["public_claim_allowed"].as_bool(),
        Some(false)
    );
    assert!(
        hdflr["report_json"]["claim_blockers"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item
                .as_str()
                .is_some_and(|text| text.contains("permissioned large-host"))))
    );

    let log = std::fs::read_to_string(out_dir.join("completion.log.jsonl"))?;
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
    assert!(events.contains("runtime_membrane_overhead_completion_checkers_replayed"));
    Ok(())
}

#[test]
fn checker_rejects_missing_child_artifact() -> TestResult {
    let root = repo_root()?;
    let (contract, out_dir) = write_contract_variant(&root, "missing_child", |value, out| {
        value["child_artifacts"][0]["artifact_path"] =
            Value::String(out.join("missing.json").to_string_lossy().into_owned());
        Ok(())
    })?;
    let output = run_checker(&root, &contract, None, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("completion.report.json"))?;
    assert!(failure_signatures(&report)?.contains("missing_evidence"));
    Ok(())
}

#[test]
fn checker_rejects_non_remote_validation_command() -> TestResult {
    let root = repo_root()?;
    let (contract, out_dir) = write_contract_variant(&root, "local_command", |value, _out| {
        value["required_remote_validation_commands"][0] =
            Value::String("cargo test -p frankenlibc-harness".to_string());
        Ok(())
    })?;
    let output = run_checker(&root, &contract, None, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("completion.report.json"))?;
    assert!(failure_signatures(&report)?.contains("missing_rch_remote"));
    Ok(())
}

#[test]
fn checker_rejects_open_child_bead_status() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "open_child")?;
    let mut rows = Vec::new();
    for line in std::fs::read_to_string(issues_path(&root))?.lines() {
        let mut row: Value = serde_json::from_str(line)?;
        if row["id"].as_str() == Some("bd-hdflr") {
            row["status"] = Value::String("open".to_string());
        }
        rows.push(serde_json::to_string(&row)?);
    }
    let issues = out_dir.join("issues.jsonl");
    std::fs::write(&issues, rows.join("\n") + "\n")?;

    let output = run_checker(&root, &contract_path(&root), Some(&issues), &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("completion.report.json"))?;
    assert!(failure_signatures(&report)?.contains("child_not_closed"));
    Ok(())
}

#[test]
fn checker_rejects_smoke_claim_upgrade_in_contention_child() -> TestResult {
    let root = repo_root()?;
    let (contract, out_dir) = write_contract_variant(&root, "smoke_upgrade", |value, out| {
        let mut contention = load_json(&contention_path(&root))?;
        contention["smoke_fixture"]["can_upgrade_public_readiness"] = Value::Bool(true);
        contention["smoke_fixture"]["readiness_claim"] =
            Value::String("public_readiness".to_string());
        let contention_file = out.join("contention-smoke-upgrade.json");
        write_json(&contention_file, &contention)?;
        value["child_artifacts"][1]["artifact_path"] =
            Value::String(contention_file.to_string_lossy().into_owned());
        Ok(())
    })?;
    let output = run_checker(&root, &contract, None, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("completion.report.json"))?;
    let signatures = failure_signatures(&report)?;
    assert!(
        signatures.contains("smoke_claim_upgrade") || signatures.contains("checker_replay_failed")
    );
    Ok(())
}
