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
    }
    ensure(
        row_count >= REQUIRED_WORKSTREAMS.len() + 3,
        "gate log must include template and replay rows",
    )?;
    ensure(
        saw_blocked_replay,
        "gate log must include a blocked replay scenario",
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
