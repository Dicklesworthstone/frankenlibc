//! Remote-only rch lane contract gate for high-core validation (bd-brysl).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MANIFEST_PATH: &str = "tests/conformance/high_core_validation_shards.v1.json";
const CONTRACT_PATH: &str = "tests/conformance/high_core_validation_rch_lane_contract.v1.json";
const PLANNER_SCRIPT: &str = "scripts/plan_high_core_validation_shards.sh";
const CHECKER_SCRIPT: &str = "scripts/check_high_core_validation_rch_lane_contract.sh";

struct CheckerRun {
    report: PathBuf,
    events: PathBuf,
    output: Output,
}

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            test_error(format!(
                "could not derive workspace root from {}",
                manifest_dir.display()
            ))
        })
}

fn unique_temp_dir(label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock before Unix epoch: {err}")))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "frankenlibc-{label}-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)
        .map_err(|err| test_error(format!("create {} failed: {err}", dir.display())))?;
    Ok(dir)
}

fn load_json(path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&body)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    let body = serde_json::to_string_pretty(value)
        .map_err(|err| test_error(format!("serialize {} failed: {err}", path.display())))?;
    std::fs::write(path, format!("{body}\n"))
        .map_err(|err| test_error(format!("write {} failed: {err}", path.display())))
}

fn committed_manifest_path() -> TestResult<PathBuf> {
    Ok(workspace_root()?.join(MANIFEST_PATH))
}

fn committed_contract_path() -> TestResult<PathBuf> {
    Ok(workspace_root()?.join(CONTRACT_PATH))
}

fn assert_success(output: &Output) -> TestResult {
    if output.status.success() {
        Ok(())
    } else {
        Err(test_error(format!(
            "command failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

fn run_planner(label: &str) -> TestResult<PathBuf> {
    let root = workspace_root()?;
    let dir = unique_temp_dir(label)?;
    let plan = dir.join("shard_plan.report.json");
    let log = dir.join("events.log.jsonl");
    let output = Command::new("bash")
        .arg(root.join(PLANNER_SCRIPT))
        .env(
            "HIGH_CORE_VALIDATION_SHARD_MANIFEST",
            committed_manifest_path()?,
        )
        .env(
            "HIGH_CORE_VALIDATION_RCH_LANE_CONTRACT",
            committed_contract_path()?,
        )
        .env("HIGH_CORE_VALIDATION_SHARD_PLAN", &plan)
        .env("HIGH_CORE_VALIDATION_SHARD_LOG", &log)
        .env("HIGH_CORE_VALIDATION_SHARD_LANES", "8")
        .current_dir(&root)
        .output()
        .map_err(|err| test_error(format!("failed to run shard planner: {err}")))?;
    assert_success(&output)?;
    Ok(plan)
}

fn run_checker(
    manifest: &Path,
    plan: Option<&Path>,
    output_capture: Option<&Path>,
    label: &str,
) -> TestResult<CheckerRun> {
    let root = workspace_root()?;
    let dir = unique_temp_dir(label)?;
    let report = dir.join("rch_lane_contract.report.json");
    let events = dir.join("rch_lane_contract.events.log.jsonl");
    let mut command = Command::new("bash");
    command
        .arg(root.join(CHECKER_SCRIPT))
        .arg("--validate-only")
        .env("HIGH_CORE_VALIDATION_SHARD_MANIFEST", manifest)
        .env(
            "HIGH_CORE_VALIDATION_RCH_LANE_CONTRACT",
            committed_contract_path()?,
        )
        .env("HIGH_CORE_VALIDATION_RCH_LANE_REPORT", &report)
        .env("HIGH_CORE_VALIDATION_RCH_LANE_EVENTS", &events)
        .current_dir(&root);
    if let Some(plan_path) = plan {
        command.env("HIGH_CORE_VALIDATION_SHARD_PLAN", plan_path);
    }
    if let Some(output_path) = output_capture {
        command.env("HIGH_CORE_VALIDATION_RCH_OUTPUTS", output_path);
    }
    let output = command
        .output()
        .map_err(|err| test_error(format!("failed to run rch lane checker: {err}")))?;
    Ok(CheckerRun {
        report,
        events,
        output,
    })
}

fn write_manifest_variant(
    label: &str,
    mutate: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let mut manifest = load_json(&committed_manifest_path()?)?;
    mutate(&mut manifest)?;
    let dir = unique_temp_dir(label)?;
    let path = dir.join("high_core_validation_shards.v1.json");
    write_json(&path, &manifest)?;
    Ok(path)
}

fn units_mut(manifest: &mut Value) -> TestResult<&mut Vec<Value>> {
    manifest
        .get_mut("units")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("manifest.units must be a mutable array"))
}

fn first_unit_with_kind_mut<'a>(manifest: &'a mut Value, kind: &str) -> TestResult<&'a mut Value> {
    units_mut(manifest)?
        .iter_mut()
        .find(|unit| unit.get("execution_kind").and_then(Value::as_str) == Some(kind))
        .ok_or_else(|| test_error(format!("manifest should contain {kind} unit")))
}

fn remove_command_token(unit: &mut Value, token: &str) -> TestResult {
    let command = unit
        .get_mut("command_template")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("unit.command_template must be mutable array"))?;
    let old_len = command.len();
    command.retain(|item| item.as_str() != Some(token));
    if command.len() == old_len {
        return Err(test_error(format!(
            "token {token} should have been removed"
        )));
    }
    Ok(())
}

fn expect_failure_signature(run: &CheckerRun, signature: &str) -> TestResult<Value> {
    if run.output.status.success() {
        return Err(test_error(format!(
            "checker unexpectedly passed for {signature}: stdout={} stderr={}",
            String::from_utf8_lossy(&run.output.stdout),
            String::from_utf8_lossy(&run.output.stderr)
        )));
    }
    let report = load_json(&run.report)?;
    let signatures = report
        .get("failure_signatures")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("report.failure_signatures must be array"))?;
    if signatures
        .iter()
        .any(|entry| entry.as_str() == Some(signature))
    {
        Ok(report)
    } else {
        Err(test_error(format!(
            "expected signature {signature}; report={report:#?}"
        )))
    }
}

#[test]
fn checker_accepts_committed_manifest_and_annotated_plan() -> TestResult {
    let plan_path = run_planner("hcvs-rch-lane-plan")?;
    let plan = load_json(&plan_path)?;
    assert_eq!(
        plan["source_rch_lane_contract"].as_str(),
        Some(CONTRACT_PATH)
    );
    assert_eq!(
        plan["rch_lane_contract"]["contract_id"].as_str(),
        Some("high-core-validation-rch-lane-contract")
    );

    let mut remote_count = 0;
    let mut local_count = 0;
    for lane in plan["lanes"]
        .as_array()
        .ok_or_else(|| test_error("plan.lanes must be array"))?
    {
        for unit in lane["units"]
            .as_array()
            .ok_or_else(|| test_error("lane.units must be array"))?
        {
            let execution_kind = unit["execution_kind"]
                .as_str()
                .ok_or_else(|| test_error("unit.execution_kind must be string"))?;
            let proof_class = unit["proof_class"]
                .as_str()
                .ok_or_else(|| test_error("unit.proof_class must be string"))?;
            assert!(unit.get("proof_annotation").is_some());
            assert!(unit.get("rerun_command").is_some());
            match execution_kind {
                "remote_rch" => {
                    remote_count += 1;
                    assert_eq!(proof_class, "remote_only_rch_proof");
                    assert_eq!(unit["local_fallback_invalid"].as_bool(), Some(true));
                }
                "local_metadata" => {
                    local_count += 1;
                    assert_eq!(proof_class, "cheap_local_metadata_check");
                    assert_eq!(unit["local_fallback_invalid"].as_bool(), Some(false));
                }
                other => return Err(test_error(format!("unexpected execution kind {other}"))),
            }
        }
    }
    assert!(remote_count > 0, "remote proof lanes are required");
    assert!(local_count > 0, "local metadata lanes are required");

    let run = run_checker(
        &committed_manifest_path()?,
        Some(&plan_path),
        None,
        "hcvs-rch-lane-pass",
    )?;
    assert_success(&run.output)?;
    let report = load_json(&run.report)?;
    assert_eq!(report["status"].as_str(), Some("passed"));
    let events = std::fs::read_to_string(&run.events)
        .map_err(|err| test_error(format!("read {} failed: {err}", run.events.display())))?;
    assert!(events.contains("rch_lane_contract_validated"));
    Ok(())
}

#[test]
fn checker_rejects_remote_lane_missing_no_self_healing_env() -> TestResult {
    let manifest_path = write_manifest_variant("hcvs-rch-missing-env", |manifest| {
        let unit = first_unit_with_kind_mut(manifest, "remote_rch")?;
        remove_command_token(unit, "RCH_NO_SELF_HEALING=1")
    })?;
    let run = run_checker(&manifest_path, None, None, "hcvs-rch-missing-env")?;
    let report = expect_failure_signature(&run, "missing_required_env")?;
    let violation = report["violations"]
        .as_array()
        .and_then(|items| items.first())
        .ok_or_else(|| test_error("violation is required"))?;
    assert!(violation["unit_id"].as_str().is_some());
    assert!(
        violation["rerun_command"]
            .as_str()
            .is_some_and(|command| command.contains("rch"))
    );
    Ok(())
}

#[test]
fn checker_rejects_bare_cargo_template() -> TestResult {
    let manifest_path = write_manifest_variant("hcvs-rch-bare-cargo", |manifest| {
        let unit = first_unit_with_kind_mut(manifest, "remote_rch")?;
        unit["command_template"] = json!(["cargo", "test", "-p", "frankenlibc-harness"]);
        Ok(())
    })?;
    let run = run_checker(&manifest_path, None, None, "hcvs-rch-bare-cargo")?;
    expect_failure_signature(&run, "bare_cargo_command")?;
    Ok(())
}

#[test]
fn checker_rejects_bash_wrapped_cargo_template() -> TestResult {
    let manifest_path = write_manifest_variant("hcvs-rch-bash-cargo", |manifest| {
        let unit = first_unit_with_kind_mut(manifest, "remote_rch")?;
        unit["command_template"] = json!([
            "env",
            "RCH_FORCE_REMOTE=true",
            "RCH_NO_SELF_HEALING=1",
            "rch",
            "--no-self-healing",
            "exec",
            "--",
            "bash",
            "-c",
            "cargo test -p frankenlibc-harness"
        ]);
        Ok(())
    })?;
    let run = run_checker(&manifest_path, None, None, "hcvs-rch-bash-cargo")?;
    expect_failure_signature(&run, "bash_wrapped_cargo")?;
    Ok(())
}

#[test]
fn checker_rejects_local_metadata_cargo() -> TestResult {
    let manifest_path = write_manifest_variant("hcvs-rch-local-cargo", |manifest| {
        let unit = first_unit_with_kind_mut(manifest, "local_metadata")?;
        unit["command_template"] = json!(["cargo", "test", "-p", "frankenlibc-harness"]);
        Ok(())
    })?;
    let run = run_checker(&manifest_path, None, None, "hcvs-rch-local-cargo")?;
    expect_failure_signature(&run, "cargo_in_local_metadata")?;
    Ok(())
}

#[test]
fn checker_rejects_rch_local_fallback_output() -> TestResult {
    let dir = unique_temp_dir("hcvs-rch-local-output")?;
    let output_path = dir.join("rch-output.txt");
    std::fs::write(&output_path, "[RCH] local (remote execution failed)\n")
        .map_err(|err| test_error(format!("write {} failed: {err}", output_path.display())))?;
    let run = run_checker(
        &committed_manifest_path()?,
        None,
        Some(&output_path),
        "hcvs-rch-local-output",
    )?;
    expect_failure_signature(&run, "rch_local_fallback")?;
    Ok(())
}
