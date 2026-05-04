//! Integration test: changed-surface validation checklist gate (bd-bp8fl.7.4)
//!
//! The checklist makes bead closure evidence explicit for each staged file:
//! targeted cargo gates, UBS, fixture/e2e replay, regenerated artifacts, br/bv
//! graph health, and unrelated-failure notes.

use serde_json::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "changed_file",
    "validation_command",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

const REQUIRED_CHANGED_FILES: &[&str] = &[
    ".beads/issues.jsonl",
    "crates/frankenlibc-harness/tests/changed_surface_validation_checklist_test.rs",
    "scripts/check_changed_surface_validation_checklist.sh",
    "tests/conformance/changed_surface_validation_checklist.v1.json",
];

const REQUIRED_SCENARIO_CLASSES: &[&str] = &[
    "complete",
    "missing_changed_file",
    "missing_targeted_test",
    "stale_artifact",
    "skipped_ubs_without_justification",
    "missing_unrelated_failure_note",
    "missing_log_artifact_refs",
];

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let root = Path::new(manifest)
        .parent()
        .ok_or_else(|| test_error("crate manifest should have a crates/ parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have a workspace parent"))?
        .to_path_buf();
    Ok(root)
}

fn artifact_path() -> TestResult<PathBuf> {
    Ok(workspace_root()?.join("tests/conformance/changed_surface_validation_checklist.v1.json"))
}

fn script_path() -> TestResult<PathBuf> {
    Ok(workspace_root()?.join("scripts/check_changed_surface_validation_checklist.sh"))
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn unique_output_dir(root: &Path, prefix: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let dir = root
        .join("target/conformance")
        .join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_gate(config: Option<&Path>, output_dir: &Path) -> TestResult<std::process::Output> {
    let root = workspace_root()?;
    let report = output_dir.join("changed_surface_validation_checklist.report.json");
    let log = output_dir.join("changed_surface_validation_checklist.log.jsonl");
    let mut command = Command::new("bash");
    command
        .arg(script_path()?)
        .current_dir(&root)
        .env(
            "FRANKENLIBC_CHANGED_SURFACE_VALIDATION_TARGET_DIR",
            output_dir,
        )
        .env("FRANKENLIBC_CHANGED_SURFACE_VALIDATION_REPORT", &report)
        .env("FRANKENLIBC_CHANGED_SURFACE_VALIDATION_LOG", &log);
    if let Some(config) = config {
        command.env("FRANKENLIBC_CHANGED_SURFACE_VALIDATION_CHECKLIST", config);
    }
    Ok(command.output()?)
}

fn write_mutation(root: &Path, name: &str, mutate: impl FnOnce(&mut Value)) -> TestResult<PathBuf> {
    let mut doc = load_json(&artifact_path()?)?;
    mutate(&mut doc);
    let dir = unique_output_dir(root, "changed-surface-validation-mutated")?;
    let path = dir.join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(&doc)?)?;
    Ok(path)
}

#[test]
fn artifact_declares_changed_surface_contract() -> TestResult {
    let doc = load_json(&artifact_path()?)?;
    assert_eq!(doc["schema_version"].as_str(), Some("v1"));
    assert_eq!(doc["bead"].as_str(), Some("bd-bp8fl.7.4"));
    assert_eq!(
        doc["trace_id"].as_str(),
        Some("bd-bp8fl-7-4-changed-surface-validation-checklist-v1")
    );
    assert_eq!(
        doc["artifact_freshness"]["freshness_state"].as_str(),
        Some("current")
    );

    let fields: Vec<_> = doc["required_log_fields"]
        .as_array()
        .ok_or_else(|| test_error("required_log_fields should be array"))?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("required_log_fields entries should be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(fields, REQUIRED_LOG_FIELDS);

    let required_files: HashSet<_> = doc["required_changed_files"]
        .as_array()
        .ok_or_else(|| test_error("required_changed_files should be array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for path in REQUIRED_CHANGED_FILES {
        assert!(
            required_files.contains(path),
            "missing required file {path}"
        );
    }
    Ok(())
}

#[test]
fn every_changed_file_has_closure_validation_rows() -> TestResult {
    let doc = load_json(&artifact_path()?)?;
    let rows = doc["changed_files"]
        .as_array()
        .ok_or_else(|| test_error("changed_files should be array"))?;
    assert_eq!(rows.len(), REQUIRED_CHANGED_FILES.len());

    for row in rows {
        let changed_file = row["changed_file"]
            .as_str()
            .ok_or_else(|| test_error("changed_file should be string"))?;
        assert!(
            REQUIRED_CHANGED_FILES.contains(&changed_file),
            "unexpected changed file {changed_file}"
        );
        let cargo = row["targeted_cargo_commands"].as_array().unwrap();
        let cargo_skip = row["targeted_cargo_skip_justification"]
            .as_str()
            .unwrap_or("");
        assert!(
            !cargo.is_empty() || !cargo_skip.is_empty(),
            "{changed_file}: targeted cargo proof or justification missing"
        );
        assert!(
            row["ubs_command"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
                || row["ubs_skip_justification"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty()),
            "{changed_file}: UBS proof or justification missing"
        );
        assert!(
            !row["fixture_e2e_scripts"].as_array().unwrap().is_empty(),
            "{changed_file}: fixture/e2e replay missing"
        );
        assert!(
            !row["artifact_regeneration_commands"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{changed_file}: artifact regeneration command missing"
        );
        assert!(
            !row["br_bv_commands"].as_array().unwrap().is_empty(),
            "{changed_file}: br/bv graph check missing"
        );
        assert!(
            row["unrelated_failure_note"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "{changed_file}: unrelated failure note missing"
        );
        assert!(
            !row["artifact_refs"].as_array().unwrap().is_empty(),
            "{changed_file}: artifact refs missing"
        );
    }
    Ok(())
}

#[test]
fn fixture_replay_scenarios_cover_fail_closed_paths() -> TestResult {
    let doc = load_json(&artifact_path()?)?;
    let scenarios = doc["fixture_replay_scenarios"]
        .as_array()
        .ok_or_else(|| test_error("fixture_replay_scenarios should be array"))?;
    let classes: HashSet<_> = scenarios
        .iter()
        .filter_map(|scenario| scenario["classification"].as_str())
        .collect();
    for class in REQUIRED_SCENARIO_CLASSES {
        assert!(classes.contains(class), "missing scenario class {class}");
    }
    Ok(())
}

#[test]
fn gate_script_emits_report_and_structured_log() -> TestResult {
    let root = workspace_root()?;
    let output_dir = unique_output_dir(&root, "changed-surface-validation")?;
    let output = run_gate(None, &output_dir)?;
    assert!(
        output.status.success(),
        "changed-surface validation gate failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&output_dir.join("changed_surface_validation_checklist.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["changed_file_count"].as_u64(), Some(4));

    let log_content =
        std::fs::read_to_string(output_dir.join("changed_surface_validation_checklist.log.jsonl"))?;
    let rows: Vec<Value> = log_content
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert!(rows.len() >= REQUIRED_CHANGED_FILES.len() + REQUIRED_SCENARIO_CLASSES.len());
    for row in &rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "missing log field {field}");
        }
    }
    Ok(())
}

#[test]
fn gate_rejects_missing_changed_file_and_stale_artifact() -> TestResult {
    let root = workspace_root()?;
    let mutations = [
        write_mutation(&root, "missing-file", |doc| {
            doc["changed_files"]
                .as_array_mut()
                .expect("changed_files should be array")
                .retain(|row| row["changed_file"].as_str() != Some(".beads/issues.jsonl"));
        })?,
        write_mutation(&root, "stale-artifact", |doc| {
            doc["artifact_freshness"]["freshness_state"] = Value::String("stale".to_owned());
        })?,
    ];

    for mutation in mutations {
        let output_dir = unique_output_dir(&root, "changed-surface-validation-negative")?;
        let output = run_gate(Some(&mutation), &output_dir)?;
        assert!(
            !output.status.success(),
            "mutation should fail closed: {}",
            mutation.display()
        );
        let report =
            load_json(&output_dir.join("changed_surface_validation_checklist.report.json"))?;
        assert_eq!(report["status"].as_str(), Some("fail"));
    }
    Ok(())
}

#[test]
fn gate_rejects_missing_targeted_ubs_and_unrelated_failure_evidence() -> TestResult {
    let root = workspace_root()?;
    let mutations = [
        write_mutation(&root, "missing-targeted-cargo", |doc| {
            let rows = doc["changed_files"].as_array_mut().unwrap();
            let row = rows
                .iter_mut()
                .find(|row| {
                    row["changed_file"].as_str()
                        == Some(
                            "crates/frankenlibc-harness/tests/changed_surface_validation_checklist_test.rs",
                        )
                })
                .unwrap();
            row["targeted_cargo_commands"] = Value::Array(vec![]);
            row["targeted_cargo_skip_justification"] = Value::String(String::new());
        })?,
        write_mutation(&root, "missing-ubs", |doc| {
            let rows = doc["changed_files"].as_array_mut().unwrap();
            let row = rows
                .iter_mut()
                .find(|row| {
                    row["changed_file"].as_str()
                        == Some("scripts/check_changed_surface_validation_checklist.sh")
                })
                .unwrap();
            row["ubs_command"] = Value::String(String::new());
            row["ubs_skip_justification"] = Value::String(String::new());
        })?,
        write_mutation(&root, "missing-unrelated-note", |doc| {
            let rows = doc["changed_files"].as_array_mut().unwrap();
            let row = rows
                .iter_mut()
                .find(|row| {
                    row["changed_file"].as_str()
                        == Some("tests/conformance/changed_surface_validation_checklist.v1.json")
                })
                .unwrap();
            row["unrelated_failure_note"] = Value::String(String::new());
        })?,
    ];

    for mutation in mutations {
        let output_dir = unique_output_dir(&root, "changed-surface-validation-negative")?;
        let output = run_gate(Some(&mutation), &output_dir)?;
        assert!(
            !output.status.success(),
            "mutation should fail closed: {}",
            mutation.display()
        );
        let report =
            load_json(&output_dir.join("changed_surface_validation_checklist.report.json"))?;
        assert_eq!(report["status"].as_str(), Some("fail"));
    }
    Ok(())
}
