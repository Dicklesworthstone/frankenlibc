//! Completion-contract tests for bd-bp8fl.2.8.1 hard-parts replay wiring evidence.

use serde_json::{Value, json};
use std::collections::HashSet;
use std::error::Error;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_CHILDREN: &[&str] = &[
    "bd-bp8fl.5.1",
    "bd-bp8fl.5.2",
    "bd-bp8fl.5.3",
    "bd-bp8fl.5.4",
    "bd-bp8fl.5.5",
    "bd-bp8fl.5.6",
    "bd-bp8fl.5.7",
    "bd-bp8fl.5.8",
];

const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "source_replay_validated",
    "dependency_wiring_verified",
    "hard_parts_replay_wiring_completion_contract_validated",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/hard_parts_replay_wiring_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_hard_parts_replay_wiring_completion_contract.sh")
}

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn unique_temp_dir(label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before UNIX_EPOCH: {err}")))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "frankenlibc-{label}-{stamp}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    let content = serde_json::to_string_pretty(value)
        .map_err(|err| test_error(format!("{} serialization failed: {err}", path.display())))?;
    std::fs::write(path, format!("{content}\n"))
        .map_err(|err| test_error(format!("{} write failed: {err}", path.display())))
}

#[cfg(unix)]
fn symlink_dir(source: &Path, link: &Path) -> TestResult {
    std::os::unix::fs::symlink(source, link).map_err(|err| {
        test_error(format!(
            "failed to symlink {} -> {}: {err}",
            link.display(),
            source.display()
        ))
    })
}

fn hard_parts_tracker_ids() -> HashSet<&'static str> {
    let mut ids = HashSet::from(["bd-bp8fl.2.8", "bd-bp8fl.5.9"]);
    ids.extend(REQUIRED_CHILDREN.iter().copied());
    ids
}

fn write_minimal_tracker_fixture(source_root: &Path, fixture_root: &Path) -> TestResult {
    let ids = hard_parts_tracker_ids();
    let source = source_root.join(".beads/issues.jsonl");
    let target_dir = fixture_root.join(".beads");
    let target = target_dir.join("issues.jsonl");
    std::fs::create_dir_all(&target_dir)?;

    let content = std::fs::read_to_string(&source).unwrap_or_default();
    let mut found = HashSet::new();
    let mut rows = Vec::new();
    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        let row = serde_json::from_str::<Value>(line).map_err(|err| {
            test_error(format!(
                "{} contains invalid JSONL row: {err}",
                source.display()
            ))
        })?;
        if let Some(id) = row.get("id").and_then(Value::as_str)
            && ids.contains(id)
        {
            rows.push(line.to_string());
            found.insert(id.to_string());
        }
    }

    if found.len() != ids.len() {
        rows = synthetic_tracker_fixture_rows()?;
    }
    let mut file = std::fs::File::create(&target)
        .map_err(|err| test_error(format!("{} create failed: {err}", target.display())))?;
    for row in rows {
        writeln!(file, "{row}")?;
    }
    Ok(())
}

fn synthetic_issue(
    id: &str,
    title: &str,
    priority: u64,
    dependency_ids: &[&str],
) -> TestResult<String> {
    let dependencies = dependency_ids
        .iter()
        .map(|depends_on_id| {
            json!({
                "issue_id": id,
                "depends_on_id": depends_on_id,
                "type": "blocks",
                "created_at": "2026-05-10T00:00:00Z",
                "created_by": "fixture",
                "metadata": "{}",
                "thread_id": "",
            })
        })
        .collect::<Vec<_>>();
    let row = json!({
        "id": id,
        "title": title,
        "description": "minimal hard-parts replay wiring completion test fixture",
        "status": "closed",
        "priority": priority,
        "issue_type": "task",
        "created_at": "2026-05-10T00:00:00Z",
        "created_by": "fixture",
        "updated_at": "2026-05-10T00:00:00Z",
        "closed_at": "2026-05-10T00:00:00Z",
        "labels": ["hard-parts", "replay"],
        "dependencies": dependencies,
    });
    serde_json::to_string(&row)
        .map_err(|err| test_error(format!("synthetic tracker row serialization failed: {err}")))
}

fn synthetic_tracker_fixture_rows() -> TestResult<Vec<String>> {
    let mut rows = vec![
        synthetic_issue(
            "bd-bp8fl.2.8",
            "After tracker repair wire remaining hard-parts beads to failure replay gate",
            0,
            &["bd-bp8fl.5.9"],
        )?,
        synthetic_issue(
            "bd-bp8fl.5.9",
            "Standardize failure injection and replay fixtures for hard-parts campaigns",
            1,
            &[],
        )?,
    ];
    for child in REQUIRED_CHILDREN {
        rows.push(synthetic_issue(
            child,
            "Hard-parts child fixture pack",
            1,
            &["bd-bp8fl.5.9"],
        )?);
    }
    Ok(rows)
}

fn prepare_checker_fixture_root(source_root: &Path, label: &str) -> TestResult<PathBuf> {
    let fixture_root = unique_temp_dir(label)?;
    let scripts_dir = fixture_root.join("scripts");
    let tests_dir = fixture_root.join("tests");
    std::fs::create_dir_all(&scripts_dir)?;
    std::fs::create_dir_all(&tests_dir)?;
    std::fs::copy(
        checker_path(source_root),
        scripts_dir.join("check_hard_parts_replay_wiring_completion_contract.sh"),
    )?;
    std::fs::copy(
        source_root.join("scripts/check_hard_parts_failure_replay_gate.sh"),
        scripts_dir.join("check_hard_parts_failure_replay_gate.sh"),
    )?;
    std::fs::copy(
        source_root.join("scripts/check_hard_parts_e2e.sh"),
        scripts_dir.join("check_hard_parts_e2e.sh"),
    )?;
    symlink_dir(
        &source_root.join("tests/conformance"),
        &tests_dir.join("conformance"),
    )?;
    symlink_dir(&source_root.join("crates"), &fixture_root.join("crates"))?;
    write_minimal_tracker_fixture(source_root, &fixture_root)?;
    Ok(fixture_root)
}

fn field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("{context}.{key} is missing")))
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    field(value, key, context)?
        .as_str()
        .ok_or_else(|| test_error(format!("{context}.{key} must be a string")))
}

fn array_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Vec<Value>> {
    field(value, key, context)?
        .as_array()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an array")))
}

fn object_field<'a>(
    value: &'a Value,
    key: &str,
    context: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    field(value, key, context)?
        .as_object()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an object")))
}

fn run_checker(root: &Path, manifest: Option<&Path>, out_dir: &Path) -> TestResult<Output> {
    let mut command = Command::new("bash");
    let path = std::env::var("PATH").unwrap_or_default();
    let augmented_path = format!("{path}:/home/ubuntu/.local/bin:/usr/local/bin:/usr/bin:/bin");
    command
        .arg(checker_path(root))
        .current_dir(root)
        .env("PATH", augmented_path)
        .env("FRANKENLIBC_HARD_PARTS_REPLAY_WIRING_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_HARD_PARTS_REPLAY_WIRING_REPORT",
            out_dir.join("completion.report.json"),
        )
        .env(
            "FRANKENLIBC_HARD_PARTS_REPLAY_WIRING_LOG",
            out_dir.join("completion.log.jsonl"),
        )
        .env("FRANKENLIBC_HARD_PARTS_REPLAY_WIRING_TARGET_DIR", out_dir);
    if let Some(manifest) = manifest {
        command.env("FRANKENLIBC_HARD_PARTS_REPLAY_WIRING_CONTRACT", manifest);
    }
    command
        .output()
        .map_err(|err| test_error(format!("failed to run completion checker: {err}")))
}

fn run_negative_case(root: &Path, case_name: &str, manifest: &Value) -> TestResult<Value> {
    let out_dir = unique_temp_dir(case_name)?;
    let fixture = out_dir.join(format!("{case_name}.manifest.json"));
    write_json(&fixture, manifest)?;
    let output = run_checker(root, Some(&fixture), &out_dir)?;
    if output.status.success() {
        return Err(test_error(format!(
            "{case_name}: checker should fail\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    load_json(&out_dir.join("completion.report.json"))
}

fn expect_failure_signature(report: &Value, expected: &str) -> TestResult {
    let errors = array_field(report, "errors", "report")?;
    let matched = errors
        .iter()
        .filter_map(|row| row.get("failure_signature").and_then(Value::as_str))
        .any(|found| found.eq(expected));
    if matched {
        Ok(())
    } else {
        Err(test_error(format!(
            "report should contain failure signature {expected}: {report:#?}"
        )))
    }
}

#[test]
fn manifest_binds_replay_gate_and_dependency_wiring() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;

    assert_eq!(
        string_field(&manifest, "schema_version", "manifest")?,
        "hard_parts_replay_wiring_completion_contract.v1"
    );
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-bp8fl.2.8.1"
    );
    assert_eq!(
        string_field(&manifest, "original_bead", "manifest")?,
        "bd-bp8fl.2.8"
    );
    assert_eq!(
        string_field(&manifest, "replay_gate_bead", "manifest")?,
        "bd-bp8fl.5.9"
    );

    let source_artifacts = array_field(&manifest, "source_artifacts", "manifest")?;
    let source_paths = source_artifacts
        .iter()
        .map(|artifact| string_field(artifact, "path", "source_artifacts[]"))
        .collect::<TestResult<Vec<_>>>()?;
    for required in [
        "tests/conformance/hard_parts_failure_replay_gate.v1.json",
        "scripts/check_hard_parts_failure_replay_gate.sh",
        "crates/frankenlibc-harness/tests/hard_parts_failure_replay_gate_test.rs",
        "tests/conformance/hard_parts_dependency_matrix.v1.json",
        "crates/frankenlibc-harness/tests/hard_parts_dependency_matrix_test.rs",
    ] {
        assert!(
            source_paths.contains(&required),
            "missing source artifact {required}"
        );
        assert!(
            root.join(required).exists(),
            "source artifact must exist: {required}"
        );
    }

    let dependency_wiring = object_field(&manifest, "dependency_wiring", "manifest")?;
    assert_eq!(
        dependency_wiring.get("gate_bead").and_then(Value::as_str),
        Some("bd-bp8fl.5.9")
    );
    let children = dependency_wiring
        .get("required_closed_children")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("required_closed_children must be array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| test_error("required_closed_children entries must be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(children, REQUIRED_CHILDREN);

    let binding = array_field(&manifest, "missing_item_bindings", "manifest")?
        .iter()
        .find(|row| row.get("spec_item").and_then(Value::as_str) == Some("tests.unit.primary"))
        .ok_or_else(|| test_error("tests.unit.primary binding missing"))?;
    assert!(
        array_field(binding, "test_refs", "tests.unit.primary")?
            .iter()
            .any(|value| value.as_str().is_some_and(
                |path| path.ends_with("hard_parts_replay_wiring_completion_contract_test.rs")
            ))
    );

    Ok(())
}

#[test]
fn checker_replays_source_gate_and_verifies_tracker_wiring() -> TestResult {
    let root =
        prepare_checker_fixture_root(&workspace_root(), "hard-parts-replay-wiring-fixture-pass")?;
    let out_dir = unique_temp_dir("hard-parts-replay-wiring-pass")?;
    let output = run_checker(&root, None, &out_dir)?;
    assert!(
        output.status.success(),
        "completion checker should pass\nreport={}\nstdout={}\nstderr={}",
        std::fs::read_to_string(out_dir.join("completion.report.json"))
            .unwrap_or_else(|err| format!("<missing report: {err}>")),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("completion.report.json"))?;
    assert_eq!(string_field(&report, "status", "report")?, "pass");
    let summary = field(&report, "summary", "report")?;
    assert_eq!(
        summary.get("source_replay_status").and_then(Value::as_str),
        Some("pass")
    );
    assert_eq!(
        summary.get("dependency_edge_count").and_then(Value::as_u64),
        Some(REQUIRED_CHILDREN.len() as u64)
    );
    assert_eq!(
        field(&report, "dependency_wiring", "report")?
            .get("cycle_count")
            .and_then(Value::as_u64),
        Some(0)
    );

    let source_replay = object_field(&report, "source_replay", "report")?;
    for field_name in ["checker", "report", "log", "status", "summary"] {
        assert!(
            source_replay.contains_key(field_name),
            "source_replay missing {field_name}"
        );
    }

    let log_text = std::fs::read_to_string(out_dir.join("completion.log.jsonl"))?;
    let log_rows = log_text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let events = log_rows
        .iter()
        .map(|row| string_field(row, "event", "log"))
        .collect::<TestResult<Vec<_>>>()?;
    for required in REQUIRED_EVENTS {
        assert!(
            events.contains(required),
            "missing completion event {required}"
        );
    }
    for row in log_rows {
        for field_name in [
            "timestamp",
            "trace_id",
            "bead_id",
            "event",
            "status",
            "artifact_refs",
            "source_commit",
            "target_dir",
            "failure_signature",
        ] {
            assert!(
                row.get(field_name).is_some(),
                "log row missing {field_name}"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_rejects_destructive_tracker_command() -> TestResult {
    let root = prepare_checker_fixture_root(
        &workspace_root(),
        "hard-parts-replay-wiring-fixture-destructive",
    )?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let commands = manifest
        .get_mut("dependency_wiring")
        .and_then(Value::as_object_mut)
        .and_then(|wiring| wiring.get_mut("read_only_commands"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("read_only_commands must be mutable array"))?;
    commands.push(Value::String(
        "br dep add bd-bp8fl.5.1 bd-bp8fl.5.9 --no-db --json".to_string(),
    ));
    let report = run_negative_case(&root, "hard-parts-replay-wiring-destructive", &manifest)?;
    expect_failure_signature(&report, "destructive_tracker_command")
}

#[test]
fn checker_rejects_missing_dependency_wiring() -> TestResult {
    let root = prepare_checker_fixture_root(
        &workspace_root(),
        "hard-parts-replay-wiring-fixture-missing-dep",
    )?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let children = manifest
        .get_mut("dependency_wiring")
        .and_then(Value::as_object_mut)
        .and_then(|wiring| wiring.get_mut("required_closed_children"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("required_closed_children must be mutable array"))?;
    children.pop();
    children.push(Value::String("bd-bp8fl.5.missing".to_string()));
    let report = run_negative_case(&root, "hard-parts-replay-wiring-missing-dep", &manifest)?;
    expect_failure_signature(&report, "missing_tracker_dependency")
}

#[test]
fn checker_rejects_missing_unit_binding() -> TestResult {
    let root = prepare_checker_fixture_root(
        &workspace_root(),
        "hard-parts-replay-wiring-fixture-missing-unit",
    )?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest
        .as_object_mut()
        .ok_or_else(|| test_error("manifest must be object"))?
        .insert(
            "missing_item_bindings".to_string(),
            Value::Array(Vec::new()),
        );
    let report = run_negative_case(&root, "hard-parts-replay-wiring-missing-unit", &manifest)?;
    expect_failure_signature(&report, "missing_completion_binding")
}
