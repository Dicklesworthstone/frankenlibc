use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_LOG_FIELDS: [&str; 12] = [
    "trace_id",
    "bead_id",
    "dependency_state",
    "tracker_state",
    "workstream",
    "required_tests",
    "required_e2e",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
    "next_safe_action",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest should have a parent"))?;
    let root = crates_dir.parent().ok_or_else(|| {
        io::Error::other("frankenlibc-harness manifest should live below workspace root")
    })?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/agent_handoff_checklist.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_agent_handoff_checklist.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "agent_handoff_checklist_{label}_{}_{}",
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_AGENT_HANDOFF_CHECKLIST", contract)
        .env("FRANKENLIBC_AGENT_HANDOFF_TARGET_DIR", out_dir)
        .env(
            "FRANKENLIBC_AGENT_HANDOFF_REPORT",
            out_dir.join("agent_handoff_checklist.report.json"),
        )
        .env(
            "FRANKENLIBC_AGENT_HANDOFF_LOG",
            out_dir.join("agent_handoff_checklist.log.jsonl"),
        )
        .output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn git_head(root: &Path) -> TestResult<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(output_text(&output)).into());
    }
    let head = String::from_utf8(output.stdout)?.trim().to_owned();
    if head.is_empty() {
        return Err(io::Error::other("git rev-parse HEAD returned empty output").into());
    }
    Ok(head)
}

fn string_set(value: &Value, field: &str) -> TestResult<BTreeSet<String>> {
    Ok(value[field]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{field} array")))?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{field} string"))
                })
                .map(str::to_owned)
        })
        .collect::<Result<_, _>>()?)
}

fn assert_log_row_shape(row: &Value) {
    for field in REQUIRED_LOG_FIELDS {
        assert!(row.get(field).is_some(), "log row missing {field}: {row}");
    }
    for field in ["required_tests", "required_e2e", "artifact_refs"] {
        assert!(
            row[field].as_array().is_some_and(|items| !items.is_empty()),
            "log row {field} must be a non-empty array: {row}"
        );
    }
    for field in [
        "trace_id",
        "bead_id",
        "dependency_state",
        "tracker_state",
        "workstream",
        "source_commit",
        "target_dir",
        "failure_signature",
        "next_safe_action",
    ] {
        assert!(
            row[field].as_str().is_some_and(|value| !value.is_empty()),
            "log row {field} must be a non-empty string: {row}"
        );
    }
}

#[test]
fn manifest_binds_agent_handoff_workflow_contract() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(manifest["schema_version"].as_str(), Some("v1"));
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.12"));
    assert_eq!(
        manifest["trace_id"].as_str(),
        Some("bd-bp8fl-12-agent-handoff-checklist-v1")
    );

    let sections = string_set(&manifest, "required_checklist_sections")?;
    assert_eq!(sections.len(), 14);
    for section in [
        "onboarding_docs",
        "br_ready_list_show_state",
        "bv_robot_triage_insights",
        "file_reservations",
        "exact_work_surface",
        "unit_tests",
        "e2e_or_harness_scripts",
        "structured_logs",
        "rch_target_dir_policy",
        "commit_push_expectations",
        "closure_notes",
    ] {
        assert!(sections.contains(section), "missing section {section}");
    }

    let log_fields = string_set(&manifest, "required_structured_log_fields")?;
    assert_eq!(
        log_fields,
        BTreeSet::from(REQUIRED_LOG_FIELDS.map(str::to_owned))
    );

    let branch_ids: BTreeSet<&str> = manifest["branch_dispatch"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "branch_dispatch array"))?
        .iter()
        .filter_map(|branch| branch["branch_id"].as_str())
        .collect();
    assert_eq!(
        branch_ids,
        BTreeSet::from([
            "normal_tracker_state",
            "stale_tracker_state",
            "no_db_fallback",
            "already_shipped_but_open_dotted_id",
            "unrelated_dirty_files",
            "pre_existing_workspace_failures",
            "blocked_bead",
        ])
    );

    let negative_cases = manifest["negative_test_cases"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "negative_test_cases array"))?;
    assert_eq!(negative_cases.len(), 3);
    let signatures: BTreeSet<&str> = negative_cases
        .iter()
        .filter_map(|case| case["failure_signature"].as_str())
        .collect();
    assert!(signatures.contains("missing_required_tests"));
    assert!(signatures.contains("missing_artifact_refs"));
    assert!(signatures.contains("stale_source_of_truth_no_next_action"));

    let generated = string_set(&manifest["closure_contract"], "generated_artifacts")?;
    assert!(generated.contains("tests/conformance/agent_handoff_checklist.v1.json"));
    assert!(generated.contains("target/conformance/agent_handoff_checklist.report.json"));
    assert!(generated.contains("target/conformance/agent_handoff_checklist.log.jsonl"));
    assert!(
        manifest["closure_contract"]["unrelated_changes_note"]
            .as_str()
            .is_some_and(|note| note.contains("not reverted")),
        "closure contract must preserve unrelated changes"
    );

    Ok(())
}

#[test]
fn checker_emits_pass_report_and_structured_log_rows() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("agent_handoff_checklist.report.json"))?;
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.12"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["branch_count"].as_u64(), Some(7));
    assert_eq!(report["section_count"].as_u64(), Some(14));
    assert_eq!(
        report["dry_run_transcripts"]
            .as_array()
            .map(|rows| rows.len()),
        Some(2)
    );
    assert_eq!(
        report["negative_test_results"]
            .as_array()
            .map(|rows| rows.len()),
        Some(3)
    );
    assert_eq!(
        report["artifact_refs"].as_array().map(|refs| refs.len()),
        Some(3)
    );

    let checks = report["checks"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "checks object"))?;
    assert_eq!(checks.len(), 16);
    for (name, status) in checks {
        assert_eq!(
            status.as_str(),
            Some("pass"),
            "checker subcheck {name} should pass"
        );
    }

    let rows = read_jsonl(&out_dir.join("agent_handoff_checklist.log.jsonl"))?;
    assert_eq!(rows.len(), 9);
    let expected_commit = git_head(&root)?;
    for row in &rows {
        assert_log_row_shape(row);
        assert_eq!(
            row["source_commit"].as_str(),
            Some(expected_commit.as_str()),
            "log row must bind the real source commit, not a placeholder: {row}"
        );
        assert_ne!(
            row["source_commit"].as_str(),
            Some("source-commit-placeholder"),
            "log row leaked placeholder source_commit: {row}"
        );
    }
    let branch_rows = rows
        .iter()
        .filter(|row| row["bead_id"].as_str() == Some("bd-bp8fl.12"))
        .count();
    assert_eq!(branch_rows, 7);
    assert!(rows.iter().any(|row| {
        row["trace_id"]
            .as_str()
            .is_some_and(|trace| trace.ends_with("::normal_tracker_state"))
    }));
    assert!(rows.iter().any(|row| {
        row["trace_id"]
            .as_str()
            .is_some_and(|trace| trace.ends_with("::stale_tracker_handoff"))
    }));

    Ok(())
}

#[test]
fn checker_rejects_required_section_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "section_drift")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_checklist_sections"] = json!(["onboarding_docs"]);
    let mutated = out_dir.join("agent_handoff_checklist_missing_sections.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject required section drift:\n{}",
        output_text(&output)
    );

    let report = read_json(&out_dir.join("agent_handoff_checklist.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_eq!(
        report["checks"]["required_sections_declared"].as_str(),
        Some("fail")
    );
    assert!(
        report["errors"]
            .as_array()
            .is_some_and(|errors| !errors.is_empty()),
        "failure report should contain errors: {report}"
    );

    let rows = read_jsonl(&out_dir.join("agent_handoff_checklist.log.jsonl"))?;
    assert_eq!(rows.len(), 9);
    for row in &rows {
        assert_log_row_shape(row);
    }

    Ok(())
}
