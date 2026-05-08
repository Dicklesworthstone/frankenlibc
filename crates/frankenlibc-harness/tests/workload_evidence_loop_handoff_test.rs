//! Integration test: workload evidence loop handoff recipe (bd-fp4tm.6).

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_STAGE_IDS: &[&str] = &[
    "freshness",
    "reproducer",
    "latency_join",
    "dossier",
    "epic_closeout",
];

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| test_error("crate manifest should have crates parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have workspace parent"))?
        .to_path_buf())
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn json_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("missing JSON field {key}")))
}

fn json_field_mut<'a>(value: &'a mut Value, key: &str) -> TestResult<&'a mut Value> {
    value
        .get_mut(key)
        .ok_or_else(|| test_error(format!("missing JSON field {key}")))
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

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn run_gate(root: &Path, recipe: &Path, dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join("scripts/check_workload_evidence_loop_handoff.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_WORKLOAD_LOOP_HANDOFF_RECIPE", recipe)
        .env("FRANKENLIBC_WORKLOAD_LOOP_HANDOFF_OUT_DIR", dir)
        .env(
            "FRANKENLIBC_WORKLOAD_LOOP_HANDOFF_REPORT",
            dir.join("handoff.report.json"),
        )
        .env(
            "FRANKENLIBC_WORKLOAD_LOOP_HANDOFF_LOG",
            dir.join("handoff.log.jsonl"),
        )
        .output()?)
}

fn base_recipe(root: &Path) -> TestResult<Value> {
    load_json(&root.join("tests/conformance/workload_evidence_loop_handoff.v1.json"))
}

#[test]
fn recipe_declares_required_loop_stages() -> TestResult {
    let root = workspace_root()?;
    let recipe = base_recipe(&root)?;
    assert_eq!(recipe["schema_version"].as_str(), Some("v1"));
    assert_eq!(recipe["bead"].as_str(), Some("bd-fp4tm.6"));
    let stages: BTreeSet<_> = json_field(&recipe, "stages")?
        .as_array()
        .ok_or_else(|| test_error("stages should be array"))?
        .iter()
        .filter_map(|stage| stage.get("id").and_then(Value::as_str))
        .collect();
    for stage_id in REQUIRED_STAGE_IDS {
        assert!(stages.contains(stage_id), "missing stage {stage_id}");
    }
    Ok(())
}

#[test]
fn gate_script_is_executable() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_workload_evidence_loop_handoff.sh");
    assert!(script.exists(), "missing {}", script.display());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)?.permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_workload_evidence_loop_handoff.sh must be executable"
        );
    }
    Ok(())
}

#[test]
fn handoff_gate_accepts_committed_recipe() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-loop-handoff-pass")?;
    let recipe = root.join("tests/conformance/workload_evidence_loop_handoff.v1.json");
    let output = run_gate(&root, &recipe, &dir)?;
    assert!(
        output.status.success(),
        "handoff gate failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&dir.join("handoff.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["summary"]["stage_count"].as_u64(),
        Some(REQUIRED_STAGE_IDS.len() as u64)
    );
    let log_rows = std::fs::read_to_string(dir.join("handoff.log.jsonl"))?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(log_rows.len(), REQUIRED_STAGE_IDS.len());
    Ok(())
}

#[test]
fn bare_cargo_command_fails_closed() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-loop-handoff-bare-cargo")?;
    let mut recipe = base_recipe(&root)?;
    let first_lane = json_field(&recipe, "cargo_validation_lanes")?
        .as_array()
        .and_then(|lanes| lanes.first())
        .ok_or_else(|| test_error("missing cargo lane"))?
        .clone();
    let mut bad_lane = first_lane;
    *json_field_mut(&mut bad_lane, "command")? = json!("cargo test -p frankenlibc-harness");
    let lanes = json_field_mut(&mut recipe, "cargo_validation_lanes")?
        .as_array_mut()
        .ok_or_else(|| test_error("cargo lanes should be array"))?;
    *lanes
        .get_mut(0)
        .ok_or_else(|| test_error("missing first cargo lane"))? = bad_lane;
    let bad_recipe = dir.join("bad_bare_cargo.json");
    write_json(&bad_recipe, &recipe)?;
    let output = run_gate(&root, &bad_recipe, &dir)?;
    assert!(!output.status.success(), "bare cargo command should fail");
    let report = load_json(&dir.join("handoff.report.json"))?;
    assert!(
        json_field(&report, "errors")?
            .as_array()
            .ok_or_else(|| test_error("errors should be array"))?
            .iter()
            .any(|item| item
                .as_str()
                .is_some_and(|line| line.contains("handoff_bare_cargo_command")))
    );
    Ok(())
}

#[test]
fn generated_artifact_without_validator_fails_closed() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-loop-handoff-missing-validator")?;
    let mut recipe = base_recipe(&root)?;
    let stages = json_field_mut(&mut recipe, "stages")?
        .as_array_mut()
        .ok_or_else(|| test_error("stages should be array"))?;
    let first_stage = stages
        .first_mut()
        .ok_or_else(|| test_error("missing first stage"))?;
    let first_artifact = json_field_mut(first_stage, "generated_artifacts")?
        .as_array_mut()
        .and_then(|artifacts| artifacts.first_mut())
        .ok_or_else(|| test_error("missing generated artifact"))?;
    first_artifact
        .as_object_mut()
        .ok_or_else(|| test_error("artifact should be object"))?
        .remove("validator");
    let bad_recipe = dir.join("bad_missing_validator.json");
    write_json(&bad_recipe, &recipe)?;
    let output = run_gate(&root, &bad_recipe, &dir)?;
    assert!(
        !output.status.success(),
        "artifact without validator should fail"
    );
    let report = load_json(&dir.join("handoff.report.json"))?;
    assert!(
        json_field(&report, "errors")?
            .as_array()
            .ok_or_else(|| test_error("errors should be array"))?
            .iter()
            .any(|item| item
                .as_str()
                .is_some_and(|line| line.contains("handoff_artifact_missing_validator")))
    );
    Ok(())
}

#[test]
fn bare_bv_and_db_backed_br_commands_fail_closed() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-loop-handoff-bad-tracker")?;
    let mut recipe = base_recipe(&root)?;
    let stages = json_field_mut(&mut recipe, "stages")?
        .as_array_mut()
        .ok_or_else(|| test_error("stages should be array"))?;
    let closeout = stages
        .iter_mut()
        .find(|stage| stage.get("id").and_then(Value::as_str) == Some("epic_closeout"))
        .ok_or_else(|| test_error("missing epic closeout stage"))?;
    let validators = json_field_mut(closeout, "validators")?
        .as_array_mut()
        .ok_or_else(|| test_error("validators should be array"))?;
    let graph_health = validators
        .get_mut(0)
        .ok_or_else(|| test_error("missing graph health validator"))?;
    *json_field_mut(graph_health, "command")? = json!("br dep cycles --json");
    let triage = validators
        .get_mut(1)
        .ok_or_else(|| test_error("missing triage validator"))?;
    *json_field_mut(triage, "command")? = json!("bv");
    let bad_recipe = dir.join("bad_tracker.json");
    write_json(&bad_recipe, &recipe)?;
    let output = run_gate(&root, &bad_recipe, &dir)?;
    assert!(
        !output.status.success(),
        "bare bv and db-backed br commands should fail"
    );
    let report = load_json(&dir.join("handoff.report.json"))?;
    let errors = json_field(&report, "errors")?
        .as_array()
        .ok_or_else(|| test_error("errors should be array"))?;
    assert!(errors.iter().any(|item| {
        item.as_str()
            .is_some_and(|line| line.contains("handoff_bare_bv_command"))
    }));
    assert!(errors.iter().any(|item| {
        item.as_str()
            .is_some_and(|line| line.contains("handoff_missing_no_db_command"))
    }));
    Ok(())
}
