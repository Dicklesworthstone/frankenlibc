//! Integration test: workstream done-template gate (bd-bp8fl.11)
//!
//! Run:
//!   cargo test -p frankenlibc-harness --test workstream_done_templates_test

use std::collections::HashSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static SCRIPT_LOCK: Mutex<()> = Mutex::new(());

const REQUIRED_WORKSTREAMS: &[&str] = &[
    "semantic_overlay",
    "tracker_repair",
    "feature_parity_audit",
    "fixture_packs",
    "hard_parts_parity",
    "replacement_levels",
    "validation_hygiene",
    "performance_optimization",
    "formal_runtime_math_evidence",
    "user_workload_diagnostics",
];

const REQUIRED_TEMPLATE_SECTIONS: &[&str] = &[
    "start_conditions",
    "blocked_by_checks",
    "expected_touched_files",
    "required_unit_test_classes",
    "required_e2e_fixture_harness_scripts",
    "structured_log_fields",
    "artifact_freshness_rules",
    "user_facing_claim_gates",
    "closure_commands",
    "known_limitations_policy",
    "non_goals",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "workstream",
    "scenario_id",
    "required_evidence",
    "present_evidence",
    "missing_evidence",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

const REQUIRED_HANDOFF_SECTIONS: &[&str] = &[
    "onboarding_docs",
    "br_ready_list_show_state",
    "bv_robot_triage_insights",
    "dependency_and_parent_checks",
    "stale_db_jsonl_symptoms",
    "file_reservations",
    "exact_work_surface",
    "expected_artifacts",
    "unit_tests",
    "e2e_or_harness_scripts",
    "structured_logs",
    "rch_target_dir_policy",
    "commit_push_expectations",
    "closure_notes",
];

const REQUIRED_HANDOFF_COMMANDS: &[&str] = &[
    "br --no-db ready --json",
    "br --no-db list --status open --json",
    "br --no-db list --status in_progress --json",
    "br --no-db show <bead-id> --json",
    "br --no-db update <bead-id> --status=in_progress --json",
    "bv --robot-triage",
    "bv --robot-insights",
];

const REQUIRED_HANDOFF_BRANCHES: &[&str] = &[
    "normal_tracker_state",
    "stale_tracker_state",
    "no_db_fallback",
    "already_shipped_but_open_dotted_id",
    "unrelated_dirty_files",
    "pre_existing_workspace_failures",
    "blocked_bead",
];

const REQUIRED_HANDOFF_LOG_FIELDS: &[&str] = &[
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

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}

fn ensure(condition: bool, message: impl Into<String>) -> Result<(), Box<dyn Error>> {
    if condition {
        Ok(())
    } else {
        Err(test_error(message))
    }
}

fn ensure_eq<T>(actual: T, expected: T, context: impl Into<String>) -> Result<(), Box<dyn Error>>
where
    T: std::fmt::Debug + PartialEq,
{
    if actual == expected {
        Ok(())
    } else {
        Err(test_error(format!(
            "{}: expected {expected:?}, got {actual:?}",
            context.into()
        )))
    }
}

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| test_error("manifest should be under crates/frankenlibc-harness"))?;
    Ok(root.to_path_buf())
}

fn unique_temp_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(std::env::temp_dir().join(format!("frankenlibc-{name}-{stamp}-{}", std::process::id())))
}

fn load_json(path: &Path) -> Result<serde_json::Value, Box<dyn Error>> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn parse_stdout_report(output: &Output) -> Result<serde_json::Value, Box<dyn Error>> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(serde_json::from_str(&stdout)?)
}

fn string_array(value: &serde_json::Value, context: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let array = value
        .as_array()
        .ok_or_else(|| test_error(format!("{context} must be an array")))?;
    array
        .iter()
        .enumerate()
        .map(|(index, item)| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| test_error(format!("{context}[{index}] must be a string")))
        })
        .collect()
}

fn required_template_sections() -> Vec<String> {
    REQUIRED_TEMPLATE_SECTIONS
        .iter()
        .map(|value| (*value).to_string())
        .collect()
}

fn required_log_fields() -> Vec<String> {
    REQUIRED_LOG_FIELDS
        .iter()
        .map(|value| (*value).to_string())
        .collect()
}

fn required_handoff_sections() -> Vec<String> {
    REQUIRED_HANDOFF_SECTIONS
        .iter()
        .map(|value| (*value).to_string())
        .collect()
}

fn required_handoff_commands() -> Vec<String> {
    REQUIRED_HANDOFF_COMMANDS
        .iter()
        .map(|value| (*value).to_string())
        .collect()
}

fn required_handoff_log_fields() -> Vec<String> {
    REQUIRED_HANDOFF_LOG_FIELDS
        .iter()
        .map(|value| (*value).to_string())
        .collect()
}

fn ensure_string(value: &serde_json::Value, context: &str) -> Result<(), Box<dyn Error>> {
    ensure(
        value.as_str().map(|item| !item.is_empty()).unwrap_or(false),
        format!("{context} must be a non-empty string"),
    )
}

#[test]
fn artifact_covers_every_workstream_with_required_sections() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let artifact = load_json(&root.join("tests/conformance/workstream_done_templates.v1.json"))?;

    ensure_eq(
        artifact["schema_version"].as_str(),
        Some("v1"),
        "schema_version",
    )?;
    ensure_eq(artifact["bead"].as_str(), Some("bd-bp8fl.11"), "bead")?;
    ensure_eq(
        string_array(
            &artifact["required_template_sections"],
            "required_template_sections",
        )?,
        required_template_sections(),
        "required_template_sections",
    )?;
    ensure_eq(
        string_array(
            &artifact["required_structured_log_fields"],
            "required_structured_log_fields",
        )?,
        required_log_fields(),
        "required_structured_log_fields",
    )?;
    ensure_eq(
        artifact["claim_policy"]["templates_are_minimums_not_scope_reductions"].as_bool(),
        Some(true),
        "templates_are_minimums_not_scope_reductions",
    )?;
    ensure_eq(
        artifact["claim_policy"]["missing_required_evidence_blocks_closure"].as_bool(),
        Some(true),
        "missing_required_evidence_blocks_closure",
    )?;

    let templates = artifact["templates"]
        .as_array()
        .ok_or_else(|| test_error("templates must be an array"))?;
    let workstreams: HashSet<_> = templates
        .iter()
        .map(|row| {
            row["workstream"]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| test_error("template workstream must be a string"))
        })
        .collect::<Result<_, _>>()?;
    ensure_eq(
        workstreams.len(),
        templates.len(),
        "workstream ids must be unique",
    )?;
    for required in REQUIRED_WORKSTREAMS {
        ensure(
            workstreams.contains(*required),
            format!("missing workstream template {required}"),
        )?;
    }

    for template in templates {
        let workstream = template["workstream"]
            .as_str()
            .ok_or_else(|| test_error("template workstream must be a string"))?;
        for section in REQUIRED_TEMPLATE_SECTIONS {
            let section_value = template
                .get(*section)
                .ok_or_else(|| test_error(format!("{workstream}: missing section {section}")))?;
            ensure(
                section_value
                    .as_array()
                    .map(|items| !items.is_empty())
                    .unwrap_or(false),
                format!("{workstream}: section {section} must be a non-empty array"),
            )?;
        }
        ensure_eq(
            string_array(
                &template["structured_log_fields"],
                "template.structured_log_fields",
            )?,
            required_log_fields(),
            format!("{workstream}: structured log fields"),
        )?;
        let commands =
            string_array(&template["closure_commands"], "template.closure_commands")?.join("\n");
        ensure(
            commands.contains("ubs <changed-files>"),
            "missing UBS command",
        )?;
        ensure(
            commands.contains("br --no-db close <bead-id>"),
            "missing no-db close command",
        )?;
    }

    let examples = artifact["dry_run_examples"]
        .as_array()
        .ok_or_else(|| test_error("dry_run_examples must be an array"))?;
    ensure(
        examples.len() >= 3,
        "dry_run_examples must have at least three rows",
    )?;
    let example_workstreams: HashSet<_> = examples
        .iter()
        .map(|row| {
            row["workstream"]
                .as_str()
                .ok_or_else(|| test_error("example workstream must be a string"))
        })
        .collect::<Result<_, _>>()?;
    ensure(
        example_workstreams.len() >= 3,
        "dry_run_examples must cover at least three workstreams",
    )?;
    ensure(
        examples
            .iter()
            .any(|row| row["expected_outcome"].as_str() == Some("close_allowed")),
        "dry_run_examples must include close_allowed",
    )?;
    ensure(
        examples
            .iter()
            .any(|row| row["expected_outcome"].as_str() == Some("close_blocked")),
        "dry_run_examples must include close_blocked",
    )?;

    let handoff = artifact["implementation_handoff_checklist"]
        .as_object()
        .ok_or_else(|| test_error("implementation_handoff_checklist must be an object"))?;
    ensure_eq(
        handoff.get("bead").and_then(serde_json::Value::as_str),
        Some("bd-bp8fl.12"),
        "handoff bead",
    )?;
    ensure_eq(
        string_array(
            &artifact["implementation_handoff_checklist"]["required_sections"],
            "handoff.required_sections",
        )?,
        required_handoff_sections(),
        "handoff required_sections",
    )?;
    ensure_eq(
        string_array(
            &artifact["implementation_handoff_checklist"]["required_br_bv_commands"],
            "handoff.required_br_bv_commands",
        )?,
        required_handoff_commands(),
        "handoff required_br_bv_commands",
    )?;
    ensure_eq(
        string_array(
            &artifact["implementation_handoff_checklist"]["required_log_fields"],
            "handoff.required_log_fields",
        )?,
        required_handoff_log_fields(),
        "handoff required_log_fields",
    )?;
    ensure_eq(
        artifact["implementation_handoff_checklist"]["policy"]["one_bead_at_a_time"].as_bool(),
        Some(true),
        "handoff one_bead_at_a_time policy",
    )?;
    ensure_eq(
        artifact["implementation_handoff_checklist"]["policy"]["rch_exec_cargo_required"].as_bool(),
        Some(true),
        "handoff rch_exec_cargo_required policy",
    )?;
    ensure_eq(
        artifact["implementation_handoff_checklist"]["policy"]["unrelated_dirty_files_are_preserved"]
            .as_bool(),
        Some(true),
        "handoff unrelated dirty file policy",
    )?;

    let branches = artifact["implementation_handoff_checklist"]["branches"]
        .as_array()
        .ok_or_else(|| test_error("handoff branches must be an array"))?;
    let branch_ids: HashSet<_> = branches
        .iter()
        .map(|row| {
            row["branch_id"]
                .as_str()
                .ok_or_else(|| test_error("handoff branch_id must be a string"))
        })
        .collect::<Result<_, _>>()?;
    ensure_eq(
        branch_ids.len(),
        branches.len(),
        "handoff branch ids must be unique",
    )?;
    for required in REQUIRED_HANDOFF_BRANCHES {
        ensure(
            branch_ids.contains(required),
            format!("missing handoff branch {required}"),
        )?;
    }
    for branch in branches {
        let branch_id = branch["branch_id"]
            .as_str()
            .ok_or_else(|| test_error("handoff branch_id must be a string"))?;
        for key in [
            "dependency_state",
            "tracker_state",
            "workstream",
            "next_safe_action",
            "source_commit_policy",
            "target_dir_policy",
            "commit_push_expectations",
            "closure_notes",
            "failure_signature",
        ] {
            ensure_string(
                branch
                    .get(key)
                    .ok_or_else(|| test_error(format!("{branch_id}: missing {key}")))?,
                &format!("{branch_id}.{key}"),
            )?;
        }
        for key in [
            "pre_claim_checks",
            "required_tests",
            "required_e2e",
            "artifact_refs",
        ] {
            ensure(
                !string_array(
                    branch
                        .get(key)
                        .ok_or_else(|| test_error(format!("{branch_id}: missing {key}")))?,
                    &format!("{branch_id}.{key}"),
                )?
                .is_empty(),
                format!("{branch_id}.{key} must not be empty"),
            )?;
        }
        let action = branch["next_safe_action"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase();
        ensure(
            !action.contains("idle") && !action.contains("ask user"),
            format!("{branch_id}: next_safe_action must not idle"),
        )?;
    }

    let transcripts = artifact["implementation_handoff_checklist"]["dry_run_transcripts"]
        .as_array()
        .ok_or_else(|| test_error("handoff dry_run_transcripts must be an array"))?;
    ensure(
        transcripts.len() >= 2,
        "handoff dry_run_transcripts must include at least two examples",
    )?;
    let transcript_ids: HashSet<_> = transcripts
        .iter()
        .map(|row| {
            row["scenario_id"]
                .as_str()
                .ok_or_else(|| test_error("handoff transcript scenario_id must be a string"))
        })
        .collect::<Result<_, _>>()?;
    ensure(
        transcript_ids.contains("clean_ready_handoff"),
        "missing clean_ready_handoff transcript",
    )?;
    ensure(
        transcript_ids.contains("stale_tracker_handoff"),
        "missing stale_tracker_handoff transcript",
    )?;
    for transcript in transcripts {
        let scenario = transcript["scenario_id"]
            .as_str()
            .ok_or_else(|| test_error("handoff transcript scenario_id must be a string"))?;
        for key in [
            "bead_id",
            "dependency_state",
            "tracker_state",
            "workstream",
            "source_commit",
            "target_dir",
            "failure_signature",
            "next_safe_action",
        ] {
            ensure_string(
                transcript
                    .get(key)
                    .ok_or_else(|| test_error(format!("{scenario}: missing {key}")))?,
                &format!("{scenario}.{key}"),
            )?;
        }
        for key in [
            "commands",
            "observations",
            "required_tests",
            "required_e2e",
            "artifact_refs",
        ] {
            ensure(
                !string_array(
                    transcript
                        .get(key)
                        .ok_or_else(|| test_error(format!("{scenario}: missing {key}")))?,
                    &format!("{scenario}.{key}"),
                )?
                .is_empty(),
                format!("{scenario}.{key} must not be empty"),
            )?;
        }
        ensure(
            transcript["next_safe_action"]
                .as_str()
                .is_some_and(|action| !action.to_ascii_lowercase().contains("idle")),
            format!("{scenario}: next_safe_action must not idle"),
        )?;
    }

    Ok(())
}

#[test]
fn gate_script_passes_and_emits_structured_report_and_log() -> Result<(), Box<dyn Error>> {
    let _guard = match SCRIPT_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let root = workspace_root()?;
    let script = root.join("scripts/check_workstream_done_templates.sh");
    ensure(
        script.exists(),
        format!("missing script {}", script.display()),
    )?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)?.permissions();
        ensure(
            perms.mode() & 0o111 != 0,
            "check_workstream_done_templates.sh must be executable",
        )?;
    }

    let output = Command::new(&script).current_dir(&root).output()?;
    ensure(
        output.status.success(),
        format!(
            "workstream done-template gate failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    let report = parse_stdout_report(&output)?;
    ensure_eq(
        report["schema_version"].as_str(),
        Some("v1"),
        "report schema_version",
    )?;
    ensure_eq(report["bead"].as_str(), Some("bd-bp8fl.11"), "report bead")?;
    ensure_eq(report["status"].as_str(), Some("pass"), "report status")?;
    ensure_eq(
        report["summary"]["template_count"].as_u64(),
        Some(REQUIRED_WORKSTREAMS.len() as u64),
        "template_count",
    )?;
    ensure_eq(
        report["checks"]["template_sections_complete"].as_str(),
        Some("pass"),
        "template_sections_complete",
    )?;
    ensure_eq(
        report["checks"]["checklist_replay_is_fail_closed"].as_str(),
        Some("pass"),
        "checklist_replay_is_fail_closed",
    )?;
    ensure_eq(
        report["checks"]["implementation_handoff_checklist_complete"].as_str(),
        Some("pass"),
        "implementation_handoff_checklist_complete",
    )?;
    ensure_eq(
        report["checks"]["handoff_transcripts_choose_next_safe_action"].as_str(),
        Some("pass"),
        "handoff_transcripts_choose_next_safe_action",
    )?;
    ensure_eq(
        report["summary"]["handoff_branch_count"].as_u64(),
        Some(REQUIRED_HANDOFF_BRANCHES.len() as u64),
        "handoff_branch_count",
    )?;

    let report_path = root.join("target/conformance/workstream_done_templates.report.json");
    let log_path = root.join("target/conformance/workstream_done_templates.log.jsonl");
    let disk_report = load_json(&report_path)?;
    ensure_eq(
        disk_report["status"].as_str(),
        Some("pass"),
        "disk report status",
    )?;
    let log_content = std::fs::read_to_string(&log_path)?;
    let mut saw_blocked_replay = false;
    let mut saw_handoff_branch = false;
    let mut saw_stale_handoff = false;
    let mut row_count = 0usize;
    for line in log_content.lines() {
        row_count += 1;
        let row: serde_json::Value = serde_json::from_str(line)?;
        for field in REQUIRED_LOG_FIELDS {
            ensure(
                row.get(*field).is_some(),
                format!("log row missing required field {field}: {row}"),
            )?;
        }
        if row["event"].as_str() == Some("workstream_done_checklist_replay")
            && row["failure_signature"].as_str() == Some("done_checklist_missing_evidence")
        {
            saw_blocked_replay = true;
        }
        if matches!(
            row["event"].as_str(),
            Some("implementation_handoff_branch" | "implementation_handoff_transcript")
        ) {
            saw_handoff_branch = true;
            for field in REQUIRED_HANDOFF_LOG_FIELDS {
                ensure(
                    row.get(*field).is_some(),
                    format!("handoff log row missing required field {field}: {row}"),
                )?;
            }
            if row["tracker_state"].as_str() == Some("db_stale_or_timeout")
                && row["next_safe_action"]
                    .as_str()
                    .is_some_and(|action| action.contains("JSONL") || action.contains("no-db"))
            {
                saw_stale_handoff = true;
            }
        }
    }
    ensure(
        row_count >= REQUIRED_WORKSTREAMS.len() + 3,
        "gate log must include template and replay rows",
    )?;
    ensure(
        saw_blocked_replay,
        "gate log must include a blocked replay scenario",
    )?;
    ensure(
        saw_handoff_branch,
        "gate log must include implementation handoff rows",
    )?;
    ensure(
        saw_stale_handoff,
        "gate log must include stale-tracker next_safe_action evidence",
    )?;

    Ok(())
}

#[test]
fn gate_script_rejects_missing_template_sections() -> Result<(), Box<dyn Error>> {
    let _guard = match SCRIPT_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let root = workspace_root()?;
    let mut artifact =
        load_json(&root.join("tests/conformance/workstream_done_templates.v1.json"))?;
    artifact["templates"][0]
        .as_object_mut()
        .ok_or_else(|| test_error("first template must be an object"))?
        .remove("closure_commands");

    let bad_path = unique_temp_path("workstream-template-missing-section.json")?;
    std::fs::write(&bad_path, serde_json::to_vec_pretty(&artifact)?)?;
    let output = Command::new(root.join("scripts/check_workstream_done_templates.sh"))
        .current_dir(&root)
        .env("FLC_WORKSTREAM_DONE_TEMPLATES", &bad_path)
        .output()?;
    ensure(
        !output.status.success(),
        "gate should fail when a required section is missing",
    )?;
    let report = parse_stdout_report(&output)?;
    ensure_eq(
        report["status"].as_str(),
        Some("fail"),
        "bad section status",
    )?;
    ensure_eq(
        report["checks"]["template_sections_complete"].as_str(),
        Some("fail"),
        "bad section check",
    )?;
    let errors = report["errors"]
        .as_array()
        .ok_or_else(|| test_error("errors must be an array"))?;
    ensure(
        errors
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|error| error.contains("closure_commands")),
        "failure should name the missing closure_commands section",
    )?;

    Ok(())
}

#[test]
fn gate_script_rejects_toothless_blocked_replay() -> Result<(), Box<dyn Error>> {
    let _guard = match SCRIPT_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let root = workspace_root()?;
    let mut artifact =
        load_json(&root.join("tests/conformance/workstream_done_templates.v1.json"))?;
    let replay = artifact["checklist_replay_scenarios"][0]
        .as_object_mut()
        .ok_or_else(|| test_error("first replay scenario must be an object"))?;
    replay.insert(
        "expected_outcome".to_string(),
        serde_json::Value::String("close_blocked".to_string()),
    );
    replay.insert(
        "missing_evidence".to_string(),
        serde_json::Value::Array(Vec::new()),
    );

    let bad_path = unique_temp_path("workstream-template-toothless-replay.json")?;
    std::fs::write(&bad_path, serde_json::to_vec_pretty(&artifact)?)?;
    let output = Command::new(root.join("scripts/check_workstream_done_templates.sh"))
        .current_dir(&root)
        .env("FLC_WORKSTREAM_DONE_TEMPLATES", &bad_path)
        .output()?;
    ensure(
        !output.status.success(),
        "gate should fail when close_blocked has no missing evidence",
    )?;
    let report = parse_stdout_report(&output)?;
    ensure_eq(report["status"].as_str(), Some("fail"), "bad replay status")?;
    ensure_eq(
        report["checks"]["checklist_replay_is_fail_closed"].as_str(),
        Some("fail"),
        "bad replay check",
    )?;

    Ok(())
}

#[test]
fn gate_script_rejects_handoff_without_next_safe_action() -> Result<(), Box<dyn Error>> {
    let _guard = match SCRIPT_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let root = workspace_root()?;
    let mut artifact =
        load_json(&root.join("tests/conformance/workstream_done_templates.v1.json"))?;
    artifact["implementation_handoff_checklist"]["branches"][0]
        .as_object_mut()
        .ok_or_else(|| test_error("first handoff branch must be an object"))?
        .insert(
            "next_safe_action".to_string(),
            serde_json::Value::String(String::new()),
        );

    let bad_path = unique_temp_path("workstream-template-handoff-no-action.json")?;
    std::fs::write(&bad_path, serde_json::to_vec_pretty(&artifact)?)?;
    let output = Command::new(root.join("scripts/check_workstream_done_templates.sh"))
        .current_dir(&root)
        .env("FLC_WORKSTREAM_DONE_TEMPLATES", &bad_path)
        .output()?;
    ensure(
        !output.status.success(),
        "gate should fail when handoff branch lacks next_safe_action",
    )?;
    let report = parse_stdout_report(&output)?;
    ensure_eq(
        report["status"].as_str(),
        Some("fail"),
        "handoff missing action status",
    )?;
    ensure_eq(
        report["checks"]["implementation_handoff_checklist_complete"].as_str(),
        Some("fail"),
        "handoff missing action check",
    )?;

    Ok(())
}
