use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CONTRACT_REL: &str = "tests/conformance/ws9_e2e_anti_recurrence_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_ws9_e2e_anti_recurrence.sh";

fn repo_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| io::Error::other("crate directory should have workspace parent"))?
        .parent()
        .ok_or_else(|| io::Error::other("workspace parent should have repo parent"))?
        .to_path_buf())
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<Vec<_>, _>>()?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "ws9_e2e_anti_recurrence_{label}_{}_{}",
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn repo_join(root: &Path, rel: &str) -> TestResult<PathBuf> {
    let components = Path::new(rel)
        .components()
        .filter_map(|component| match component {
            Component::Normal(segment) => Some(Ok(segment.to_os_string())),
            Component::CurDir => None,
            _ => Some(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsafe repo-relative path: {rel}"),
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if components.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty repo-relative path").into());
    }
    let mut path = root.to_path_buf();
    path.extend(components);
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(repo_join(root, CHECKER_REL)?)
        .current_dir(root)
        .env("FRANKENLIBC_WS9_E2E_CONTRACT", contract)
        .env("FRANKENLIBC_WS9_E2E_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_WS9_E2E_REPORT",
            out_dir.join("ws9_e2e_anti_recurrence.report.json"),
        )
        .env(
            "FRANKENLIBC_WS9_E2E_LOG",
            out_dir.join("ws9_e2e_anti_recurrence.log.jsonl"),
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

fn field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("missing {key}")))
        .map_err(Into::into)
}

fn str_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    field(value, key)?
        .as_str()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{key} should be string"),
            )
        })
        .map_err(Into::into)
}

fn array_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Vec<Value>> {
    field(value, key)?
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{key} should be array")))
        .map_err(Into::into)
}

fn object_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a serde_json::Map<String, Value>> {
    field(value, key)?
        .as_object()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{key} should be object"),
            )
        })
        .map_err(Into::into)
}

fn string_set(value: &Value, key: &str) -> TestResult<BTreeSet<String>> {
    Ok(array_field(value, key)?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "array item should be string")
                })
                .map(str::to_owned)
        })
        .collect::<Result<BTreeSet<_>, _>>()?)
}

fn contract_path(root: &Path) -> TestResult<PathBuf> {
    repo_join(root, CONTRACT_REL)
}

#[test]
fn ws9_e2e_contract_binds_child_gates_and_e2e_surfaces() -> TestResult {
    let root = repo_root()?;
    let contract = read_json(&contract_path(&root)?)?;

    assert_eq!(
        str_field(&contract, "schema_version").ok(),
        Some("ws9_e2e_anti_recurrence_completion_contract.v1")
    );
    assert_eq!(str_field(&contract, "bead_id").ok(), Some("bd-iu3fb.5"));
    assert_eq!(str_field(&contract, "parent_bead").ok(), Some("bd-iu3fb"));

    let source_artifacts = object_field(&contract, "source_artifacts")?;
    for expected in [
        "bead_closure_freshness_script",
        "bead_closure_freshness_policy",
        "proof_carrying_completion_contract",
        "queue_empty_trigger_script",
        "queue_empty_trigger_completion_contract",
        "milestone_closure_script",
        "milestone_vision_goals",
        "ws9_e2e_script",
        "ws9_e2e_contract",
        "ws9_e2e_test",
    ] {
        let spec = source_artifacts
            .get(expected)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing source artifact"))?;
        let path = str_field(spec, "path")?;
        assert!(
            repo_join(&root, path)?.exists(),
            "missing source artifact {expected}: {path}"
        );
    }

    let scenarios = array_field(&contract, "required_scenarios")?;
    let scenario_ids: BTreeSet<_> = scenarios
        .iter()
        .filter_map(|scenario| scenario.get("id").and_then(Value::as_str))
        .collect();
    for expected in [
        "faked_closure_rejected",
        "queue_empty_triggers_reality_check",
        "unmet_milestone_blocks_closure",
        "ws9_child_companion_tests_pass",
    ] {
        assert!(
            scenario_ids.contains(expected),
            "missing scenario {expected}"
        );
    }

    let companion_tests = array_field(&contract, "companion_unit_tests")?;
    let child_beads: BTreeSet<_> = companion_tests
        .iter()
        .filter_map(|test| test.get("bead_id").and_then(Value::as_str))
        .collect();
    for expected in ["bd-iu3fb.1", "bd-iu3fb.2", "bd-iu3fb.3", "bd-iu3fb.5"] {
        assert!(
            child_beads.contains(expected),
            "missing companion test for {expected}"
        );
    }

    for command in array_field(&contract, "validation_commands")?
        .iter()
        .filter_map(Value::as_str)
    {
        if command.contains("cargo ") {
            assert!(
                command.contains("rch exec -- cargo "),
                "cargo validation command must use rch: {command}"
            );
        }
    }

    Ok(())
}

#[test]
fn ws9_e2e_checker_accepts_contract_and_emits_structured_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root)?, &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report_path = out_dir.join("ws9_e2e_anti_recurrence.report.json");
    let log_path = out_dir.join("ws9_e2e_anti_recurrence.log.jsonl");
    let report = read_json(&report_path)?;
    assert_eq!(
        str_field(&report, "schema_version").ok(),
        Some("ws9_e2e_anti_recurrence.report.v1")
    );
    assert_eq!(str_field(&report, "bead_id").ok(), Some("bd-iu3fb.5"));
    assert_eq!(str_field(&report, "status").ok(), Some("pass"));
    assert_eq!(array_field(&report, "scenario_results")?.len(), 4);

    let scenarios: BTreeSet<_> = array_field(&report, "scenario_results")?
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_str))
        .collect();
    for expected in [
        "faked_closure_rejected",
        "queue_empty_triggers_reality_check",
        "unmet_milestone_blocks_closure",
        "ws9_child_companion_tests_pass",
    ] {
        assert!(
            scenarios.contains(expected),
            "missing scenario result {expected}"
        );
    }

    let log_rows = read_jsonl(&log_path)?;
    let required_fields = string_set(
        &read_json(&contract_path(&root)?)?,
        "structured_log_required_fields",
    )?;
    for row in &log_rows {
        for field in &required_fields {
            assert!(
                row.get(field).is_some(),
                "log row missing field {field}: {row}"
            );
        }
    }

    let events: BTreeSet<_> = log_rows
        .iter()
        .filter_map(|row| row.get("event").and_then(Value::as_str))
        .collect();
    for expected in [
        "ws9_contract_validated",
        "ws9_faked_closure_rejected",
        "ws9_queue_empty_trigger_fired",
        "ws9_unmet_milestone_blocked",
        "ws9_child_companion_tests_pass",
        "ws9_e2e_complete",
    ] {
        assert!(events.contains(expected), "missing log event {expected}");
    }

    Ok(())
}

#[test]
fn ws9_e2e_checker_rejects_contract_missing_required_scenario() -> TestResult {
    let root = repo_root()?;
    let mut contract = read_json(&contract_path(&root)?)?;
    let _ = field(&contract, "required_scenarios")?;
    contract
        .as_object_mut()
        .ok_or("contract should be object")?
        .insert(
            "required_scenarios".to_string(),
            json!([
                {"id": "faked_closure_rejected"},
                {"id": "unmet_milestone_blocks_closure"},
                {"id": "ws9_child_companion_tests_pass"}
            ]),
        );

    let out_dir = unique_out_dir(&root, "missing-scenario")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &contract)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success());

    let report = read_json(&out_dir.join("ws9_e2e_anti_recurrence.report.json"))?;
    let scenario_rejection_seen = array_field(&report, "errors")?
        .iter()
        .filter_map(Value::as_str)
        .any(|error| error.contains("required_scenarios mismatch"));
    assert!(
        scenario_rejection_seen,
        "missing scenario rejection absent in {report}"
    );

    Ok(())
}
