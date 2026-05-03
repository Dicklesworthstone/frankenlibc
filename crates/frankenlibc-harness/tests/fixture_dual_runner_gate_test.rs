//! Integration test: fixture dual-runner gate (bd-bp8fl.4.2).

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_MANIFEST_FIELDS: &[&str] = &[
    "direct_runner",
    "isolated_runner",
    "runtime_mode",
    "replacement_level",
    "oracle_kind",
    "expected",
    "timeout_ms",
    "environment",
    "cleanup",
    "artifact_paths",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "fixture_id",
    "runner_kind",
    "runtime_mode",
    "replacement_level",
    "expected",
    "actual",
    "errno",
    "duration_ms",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

const EXPECTED_FIXTURES: &[&str] = &[
    "ctype_ops",
    "dirent_ops",
    "memory_ops",
    "socket_ops",
    "time_ops",
    "wide_string_ops",
];

const EXPECTED_FAILURES: &[&str] = &[
    "direct_runner_mismatch",
    "isolated_runner_timeout",
    "stale_artifact",
    "isolated_runner_missing",
    "env_cleanup_missing",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn gate_path() -> PathBuf {
    workspace_root().join("tests/conformance/fixture_dual_runner_gate.v1.json")
}

fn script_path() -> PathBuf {
    workspace_root().join("scripts/check_fixture_dual_runner_gate.sh")
}

fn invalid_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn unique_temp_dir(name: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| invalid_data(format!("system time before UNIX_EPOCH: {err}")))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("frankenlibc-{name}-{stamp}-{}", std::process::id())))
}

fn run_gate(config: Option<&Path>, out_dir: &Path) -> TestResult<Output> {
    let root = workspace_root();
    let mut command = Command::new("bash");
    command
        .arg(script_path())
        .current_dir(&root)
        .env("FRANKENLIBC_FIXTURE_DUAL_RUNNER_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_FIXTURE_DUAL_RUNNER_REPORT",
            out_dir.join("fixture-dual-runner.report.json"),
        )
        .env(
            "FRANKENLIBC_FIXTURE_DUAL_RUNNER_LOG",
            out_dir.join("fixture-dual-runner.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_FIXTURE_DUAL_RUNNER_TARGET_DIR",
            "test-target-dir",
        );
    if let Some(config) = config {
        command.env("FRANKENLIBC_FIXTURE_DUAL_RUNNER_GATE", config);
    }
    Ok(command.output()?)
}

fn field<'a>(value: &'a Value, name: &str) -> TestResult<&'a Value> {
    value
        .get(name)
        .ok_or_else(|| invalid_data(format!("missing JSON field {name:?}")).into())
}

fn field_str<'a>(value: &'a Value, name: &str) -> TestResult<&'a str> {
    field(value, name)?
        .as_str()
        .ok_or_else(|| invalid_data(format!("JSON field {name:?} must be a string")).into())
}

fn field_array<'a>(value: &'a Value, name: &str) -> TestResult<&'a Vec<Value>> {
    field(value, name)?
        .as_array()
        .ok_or_else(|| invalid_data(format!("JSON field {name:?} must be an array")).into())
}

fn field_array_mut<'a>(value: &'a mut Value, name: &str) -> TestResult<&'a mut Vec<Value>> {
    value
        .get_mut(name)
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid_data(format!("JSON field {name:?} must be an array")).into())
}

fn field_object<'a>(
    value: &'a Value,
    name: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    field(value, name)?
        .as_object()
        .ok_or_else(|| invalid_data(format!("JSON field {name:?} must be an object")).into())
}

fn field_u64(value: &Value, name: &str) -> TestResult<u64> {
    field(value, name)?
        .as_u64()
        .ok_or_else(|| invalid_data(format!("JSON field {name:?} must be a u64")).into())
}

fn workspace_file(relative: &str) -> TestResult<PathBuf> {
    let relative_path = Path::new(relative);
    if relative_path.is_absolute()
        || relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invalid_data(format!("workspace path {relative:?} is not relative")).into());
    }
    Ok(workspace_root().join(relative_path))
}

#[test]
fn artifact_requires_direct_and_isolated_fixture_paths() -> TestResult {
    let root = workspace_root();
    let gate = load_json(&gate_path())?;
    assert_eq!(field_str(&gate, "schema_version")?, "v1");
    assert_eq!(field_str(&gate, "bead")?, "bd-bp8fl.4.2");

    let expected_manifest_fields = REQUIRED_MANIFEST_FIELDS
        .iter()
        .map(|field| Value::String((*field).to_owned()))
        .collect::<Vec<_>>();
    assert_eq!(
        field_array(&gate, "required_manifest_fields")?,
        &expected_manifest_fields
    );

    let expected_log_fields = REQUIRED_LOG_FIELDS
        .iter()
        .map(|field| Value::String((*field).to_owned()))
        .collect::<Vec<_>>();
    assert_eq!(
        field_array(&gate, "required_log_fields")?,
        &expected_log_fields
    );

    let ci = field_object(&gate, "ci_integration")?;
    assert_eq!(ci.get("required").and_then(Value::as_bool), Some(true));
    let ci_file = ci
        .get("ci_file")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_data("ci_file must be a string"))?;
    let gate_script = ci
        .get("gate_script")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_data("gate_script must be a string"))?;
    assert!(
        workspace_file(gate_script)?.exists(),
        "{gate_script} must exist"
    );
    let ci_text = std::fs::read_to_string(workspace_file(ci_file)?)?;
    assert!(
        ci_text.contains(gate_script),
        "{ci_file} must invoke {gate_script}"
    );

    let fixtures = field_array(&gate, "fixture_families")?;
    assert_eq!(fixtures.len(), EXPECTED_FIXTURES.len());
    let ids = fixtures
        .iter()
        .map(|family| field_str(family, "fixture_id"))
        .collect::<TestResult<BTreeSet<_>>>()?;
    assert_eq!(
        ids,
        EXPECTED_FIXTURES.iter().copied().collect::<BTreeSet<_>>()
    );

    for family in fixtures {
        let fixture_id = field_str(family, "fixture_id")?;
        for field in REQUIRED_MANIFEST_FIELDS {
            assert!(family.get(*field).is_some(), "{fixture_id} missing {field}");
        }
        let modes = field_array(family, "runtime_modes")?
            .iter()
            .map(|mode| {
                mode.as_str()
                    .ok_or_else(|| invalid_data("runtime mode must be a string").into())
            })
            .collect::<TestResult<BTreeSet<_>>>()?;
        assert_eq!(modes, ["hardened", "strict"].into_iter().collect());

        let fixture_manifest = field_str(family, "fixture_manifest")?;
        let fixture_doc = load_json(&workspace_file(fixture_manifest)?)?;
        assert!(
            !field_array(&fixture_doc, "cases")?.is_empty(),
            "{fixture_id} fixture cases must not be empty"
        );

        let test_file = field_str(family, "test_file")?;
        let test_text = std::fs::read_to_string(workspace_file(test_file)?)?;
        for fragment in field_array(family, "required_direct_tokens")? {
            let fragment = fragment
                .as_str()
                .ok_or_else(|| invalid_data("direct token must be a string"))?;
            assert!(
                test_text.contains(fragment),
                "{fixture_id} missing direct fragment {fragment:?}"
            );
        }
        for fragment in field_array(family, "required_isolated_tokens")? {
            let fragment = fragment
                .as_str()
                .ok_or_else(|| invalid_data("isolated token must be a string"))?;
            assert!(
                test_text.contains(fragment),
                "{fixture_id} missing isolated fragment {fragment:?}"
            );
        }
    }

    let scenarios = field_array(&gate, "replay_scenarios")?;
    assert_eq!(scenarios.len(), 6);
    let allowed = scenarios
        .iter()
        .filter(|scenario| matches!(field_str(scenario, "expected_decision"), Ok("allow")))
        .count();
    let blocked = scenarios
        .iter()
        .filter(|scenario| matches!(field_str(scenario, "expected_decision"), Ok("block")))
        .count();
    assert_eq!(allowed, 1);
    assert_eq!(blocked, 5);
    let failures = scenarios
        .iter()
        .map(|scenario| field_str(scenario, "expected_failure_signature"))
        .collect::<TestResult<BTreeSet<_>>>()?;
    for failure in EXPECTED_FAILURES {
        assert!(
            failures.contains(failure),
            "scenario set must exercise {failure}"
        );
    }

    assert!(root.exists(), "workspace root must exist");
    Ok(())
}

#[test]
fn gate_script_passes_and_emits_dual_runner_log_rows() -> TestResult {
    let script = script_path();
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)?.permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_fixture_dual_runner_gate.sh must be executable"
        );
    }

    let out_dir = unique_temp_dir("fixture-dual-runner-pass")?;
    let output = run_gate(None, &out_dir)?;
    assert!(
        output.status.success(),
        "gate should pass\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("fixture-dual-runner.report.json"))?;
    assert_eq!(field_str(&report, "status")?, "pass");
    let summary = field_object(&report, "summary")?;
    assert_eq!(
        field_u64(field(&report, "summary")?, "fixture_family_count")?,
        6
    );
    assert_eq!(field_u64(field(&report, "summary")?, "scenario_count")?, 6);
    assert_eq!(
        field_u64(field(&report, "summary")?, "allowed_scenario_count")?,
        1
    );
    assert_eq!(
        field_u64(field(&report, "summary")?, "blocked_scenario_count")?,
        5
    );
    assert!(summary.contains_key("fixture_family_count"));
    assert!(field_array(&report, "errors")?.is_empty());

    let log_text = std::fs::read_to_string(out_dir.join("fixture-dual-runner.log.jsonl"))?;
    let mut rows = Vec::new();
    for line in log_text.lines().filter(|line| !line.trim().is_empty()) {
        rows.push(serde_json::from_str::<Value>(line)?);
    }
    assert!(rows.len() >= 18, "family and replay rows must be logged");
    let mut runner_kinds = BTreeSet::new();
    let mut failure_signatures = BTreeSet::new();
    for row in &rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing {field}");
        }
        runner_kinds.insert(field_str(row, "runner_kind")?);
        failure_signatures.insert(field_str(row, "failure_signature")?);
        assert_eq!(field_str(row, "bead_id")?, "bd-bp8fl.4.2");
        assert_eq!(field_str(row, "target_dir")?, "test-target-dir");
    }
    assert!(runner_kinds.contains("direct"));
    assert!(runner_kinds.contains("isolated"));
    assert!(runner_kinds.contains("direct+isolated"));
    for failure in EXPECTED_FAILURES {
        assert!(
            failure_signatures.contains(failure),
            "log must include {failure}"
        );
    }
    Ok(())
}

#[test]
fn gate_fails_closed_when_isolated_runner_binding_disappears() -> TestResult {
    let mut gate = load_json(&gate_path())?;
    let families = field_array_mut(&mut gate, "fixture_families")?;
    let family = families
        .iter_mut()
        .find(|family| matches!(field_str(family, "fixture_id"), Ok("memory_ops")))
        .ok_or_else(|| invalid_data("memory_ops fixture family must exist"))?;
    let family_object = family
        .as_object_mut()
        .ok_or_else(|| invalid_data("fixture family must be an object"))?;
    family_object.insert(
        "required_isolated_tokens".to_owned(),
        Value::Array(vec![Value::String(
            "missing-isolated-subprocess-fragment".to_owned(),
        )]),
    );

    let out_dir = unique_temp_dir("fixture-dual-runner-fail")?;
    std::fs::create_dir_all(&out_dir)?;
    let mutated_gate = out_dir.join("mutated-fixture-dual-runner.json");
    std::fs::write(&mutated_gate, serde_json::to_string_pretty(&gate)?)?;

    let output = run_gate(Some(&mutated_gate), &out_dir)?;
    assert!(
        !output.status.success(),
        "gate should fail when isolated runner evidence disappears\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&out_dir.join("fixture-dual-runner.report.json"))?;
    assert_eq!(field_str(&report, "status")?, "fail");
    let errors = field_array(&report, "errors")?;
    assert!(
        errors.iter().any(|error| matches!(
            error.as_str(),
            Some(message) if message.contains("isolated_runner_missing")
        )),
        "missing isolated subprocess evidence must fail closed"
    );
    Ok(())
}
