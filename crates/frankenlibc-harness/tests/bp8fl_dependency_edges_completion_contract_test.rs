//! Contract tests for bd-bp8fl.2.9.1 dependency-edge completion evidence.

use serde_json::Value;
use serde_json::json;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const EXPECTED_EDGES: &[(&str, &str, &str)] = &[
    (
        "readme-release-examples-consume-compatibility-report",
        "bd-bp8fl.10.4",
        "bd-bp8fl.10.8",
    ),
    (
        "release-tags-consume-standalone-readiness-matrix",
        "bd-bp8fl.6.4",
        "bd-bp8fl.6.6",
    ),
    (
        "first-optimization-consumes-workload-performance-budgets",
        "bd-bp8fl.8.4",
        "bd-bp8fl.8.6",
    ),
];

const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "read_only_policy_validated",
    "missing_item_bindings_validated",
    "dependency_edges_verified",
    "tracker_cycles_verified",
    "bv_cycle_break_verified",
    "bp8fl_dependency_edges_completion_contract_validated",
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
    root.join("tests/conformance/bp8fl_dependency_edges_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_bp8fl_dependency_edges_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
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

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "bp8fl-dependency-edges-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker_with_fixture(
    root: &Path,
    contract: &Path,
    out_dir: &Path,
    fixture: Option<&Path>,
) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(checker_path(root))
        .arg(contract)
        .arg(out_dir)
        .current_dir(root)
        .env("TMPDIR", "/data/tmp");
    if let Some(fixture) = fixture {
        command.env(
            "FRANKENLIBC_BP8FL_DEPENDENCY_EDGES_TRACKER_FIXTURE",
            fixture,
        );
    }
    Ok(command.output()?)
}

fn write_tracker_fixture(root: &Path, out_dir: &Path) -> TestResult<PathBuf> {
    let close_reason = "Wired the three requested dependency edges using br dep add --no-db: \
bd-bp8fl.10.4 depends on bd-bp8fl.10.8, bd-bp8fl.6.4 depends on \
bd-bp8fl.6.6, and bd-bp8fl.8.4 depends on bd-bp8fl.8.6. Validation: \
br dep cycles --no-db --json returned count 0; bv --robot-insights cycle_break \
reported state available, cycle_count 0, advisory 'No cycles detected - \
dependency graph is a proper DAG.'";
    let fixture = json!({
        "shows": {
            "bd-bp8fl.2.9": [{
                "id": "bd-bp8fl.2.9",
                "status": "closed",
                "close_reason": close_reason
            }],
            "bd-bp8fl.10.4": [{
                "id": "bd-bp8fl.10.4",
                "status": "closed",
                "dependencies": [{"id": "bd-bp8fl.10.8", "dependency_type": "blocks"}]
            }],
            "bd-bp8fl.10.8": [{
                "id": "bd-bp8fl.10.8",
                "status": "closed",
                "dependents": [{"id": "bd-bp8fl.10.4", "dependency_type": "blocks"}]
            }],
            "bd-bp8fl.6.4": [{
                "id": "bd-bp8fl.6.4",
                "status": "closed",
                "dependencies": [{"id": "bd-bp8fl.6.6", "dependency_type": "blocks"}]
            }],
            "bd-bp8fl.6.6": [{
                "id": "bd-bp8fl.6.6",
                "status": "closed",
                "dependents": [{"id": "bd-bp8fl.6.4", "dependency_type": "blocks"}]
            }],
            "bd-bp8fl.8.4": [{
                "id": "bd-bp8fl.8.4",
                "status": "closed",
                "dependencies": [{"id": "bd-bp8fl.8.6", "dependency_type": "blocks"}]
            }],
            "bd-bp8fl.8.6": [{
                "id": "bd-bp8fl.8.6",
                "status": "closed",
                "dependents": [{"id": "bd-bp8fl.8.4", "dependency_type": "blocks"}]
            }]
        },
        "cycles": {
            "cycles": [],
            "count": 0
        },
        "bv_insights": {
            "advanced_insights": {
                "cycle_break": {
                    "status": {"state": "available"},
                    "cycle_count": 0,
                    "advisory": "No cycles detected - dependency graph is a proper DAG."
                }
            }
        }
    });
    let path = out_dir.join("tracker-fixture.json");
    write_json(&path, &fixture)?;
    assert!(
        path.strip_prefix(root).is_ok(),
        "fixture should remain below workspace root"
    );
    Ok(path)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let array = value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string array"))?;
    let mut set = BTreeSet::new();
    for item in array {
        set.insert(
            item.as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string"))?
                .to_string(),
        );
    }
    Ok(set)
}

fn assert_checker_failed(output: &Output) {
    assert!(
        !output.status.success(),
        "checker unexpectedly passed\n{}",
        output_text(output)
    );
}

fn mutated_contract(
    root: &Path,
    out_dir: &Path,
    label: &str,
    mutator: impl FnOnce(&mut Value),
) -> TestResult<PathBuf> {
    let mut manifest = read_json(&contract_path(root))?;
    mutator(&mut manifest);
    let path = out_dir.join(format!("{label}.contract.json"));
    write_json(&path, &manifest)?;
    Ok(path)
}

fn report_path(out_dir: &Path) -> PathBuf {
    out_dir.join("bp8fl_dependency_edges_completion_contract.report.json")
}

fn log_path(out_dir: &Path) -> PathBuf {
    out_dir.join("bp8fl_dependency_edges_completion_contract.log.jsonl")
}

fn failure_signatures(report: &Value) -> BTreeSet<String> {
    match report["errors"].as_array() {
        Some(errors) => errors
            .iter()
            .filter_map(|row| row["failure_signature"].as_str())
            .map(ToString::to_string)
            .collect(),
        None => BTreeSet::new(),
    }
}

#[test]
fn manifest_binds_dependency_edges_and_completion_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("bp8fl_dependency_edges_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.2.9.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-bp8fl.2.9"));
    assert_eq!(
        manifest["dependency_edges"]["required_dependency_type"].as_str(),
        Some("blocks")
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_array()
        .expect("source_artifacts should be an array");
    assert_eq!(source_artifacts.len(), 20);
    for artifact in source_artifacts {
        let rel = artifact["path"]
            .as_str()
            .expect("source artifact path should be a string");
        assert!(
            root.join(rel).exists(),
            "source artifact should exist: {rel}"
        );
    }

    let edges = manifest["dependency_edges"]["edges"]
        .as_array()
        .expect("dependency edges should be an array");
    let actual_edges = edges
        .iter()
        .map(|edge| {
            (
                edge["edge_id"].as_str().unwrap().to_string(),
                edge["source"].as_str().unwrap().to_string(),
                edge["target"].as_str().unwrap().to_string(),
            )
        })
        .collect::<BTreeSet<_>>();
    let expected_edges = EXPECTED_EDGES
        .iter()
        .map(|(edge_id, source, target)| {
            (
                (*edge_id).to_string(),
                (*source).to_string(),
                (*target).to_string(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_edges, expected_edges);

    let bindings = manifest["completion_debt_evidence"]["missing_item_bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|binding| binding["spec_item"].as_str().unwrap().to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        bindings,
        BTreeSet::from([
            "tests.e2e.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
    );

    let e2e_binding = manifest["completion_debt_evidence"]["missing_item_bindings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|binding| binding["spec_item"].as_str() == Some("tests.e2e.primary"))
        .expect("e2e binding should exist");
    let commands = string_set(&e2e_binding["required_commands"])?;
    assert!(commands.contains("br dep cycles --no-db --json"));
    assert!(commands.contains("bv --robot-insights"));
    assert!(
        commands
            .iter()
            .any(|command| command.starts_with("rch exec --") && command.contains("cargo test"))
    );

    Ok(())
}

#[test]
fn checker_verifies_tracker_edges_fixture_and_emits_report_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "positive")?;
    let fixture = write_tracker_fixture(&root, &out_dir)?;
    let output = run_checker_with_fixture(&root, &contract_path(&root), &out_dir, Some(&fixture))?;
    assert!(
        output.status.success(),
        "checker should pass\n{}",
        output_text(&output)
    );

    let report = read_json(&report_path(&out_dir))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead_id"].as_str(), Some("bd-bp8fl.2.9.1"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-bp8fl.2.9"));
    assert_eq!(report["summary"]["required_edge_count"].as_u64(), Some(3));
    assert_eq!(report["summary"]["verified_edge_count"].as_u64(), Some(3));
    assert_eq!(report["summary"]["cycle_count"].as_u64(), Some(0));
    assert_eq!(report["summary"]["bv_cycle_count"].as_u64(), Some(0));

    let report_edges = report["dependency_edges"]
        .as_array()
        .expect("report dependency_edges should be an array");
    assert_eq!(report_edges.len(), 3);
    for edge in report_edges {
        assert_eq!(edge["dependency_type"].as_str(), Some("blocks"));
        assert_eq!(edge["source_status"].as_str(), Some("closed"));
        assert_eq!(edge["target_status"].as_str(), Some("closed"));
        assert_eq!(edge["forward_edge_present"].as_bool(), Some(true));
        assert_eq!(edge["reverse_edge_present"].as_bool(), Some(true));
    }

    let log_rows = read_jsonl(&log_path(&out_dir))?;
    let events = log_rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect::<BTreeSet<_>>();
    for required in REQUIRED_EVENTS {
        assert!(
            events.contains(required),
            "log should contain event {required}; got {events:?}"
        );
    }
    for row in log_rows {
        for field in manifest_required_log_fields(&root)? {
            assert!(
                row.get(&field).is_some(),
                "log row should contain required field {field}: {row}"
            );
        }
    }

    Ok(())
}

fn manifest_required_log_fields(root: &Path) -> TestResult<Vec<String>> {
    let manifest = read_json(&contract_path(root))?;
    Ok(
        manifest["completion_output_contract"]["required_log_fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| field.as_str().unwrap().to_string())
            .collect(),
    )
}

#[test]
fn checker_rejects_destructive_tracker_command() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "destructive")?;
    let fixture = write_tracker_fixture(&root, &out_dir)?;
    let contract = mutated_contract(&root, &out_dir, "destructive", |manifest| {
        manifest["dependency_edges"]["read_only_commands"]
            .as_array_mut()
            .unwrap()
            .push(Value::String(
                "br dep add bd-bp8fl.10.4 bd-bp8fl.10.8 --no-db --json".to_string(),
            ));
    })?;
    let output = run_checker_with_fixture(&root, &contract, &out_dir, Some(&fixture))?;
    assert_checker_failed(&output);
    let report = read_json(&report_path(&out_dir))?;
    assert!(failure_signatures(&report).contains("destructive_tracker_command"));
    Ok(())
}

#[test]
fn checker_rejects_missing_dependency_edge() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-edge")?;
    let fixture = write_tracker_fixture(&root, &out_dir)?;
    let contract = mutated_contract(&root, &out_dir, "missing-edge", |manifest| {
        manifest["dependency_edges"]["edges"][0]["target"] =
            Value::String("bd-bp8fl.no-such-edge".to_string());
    })?;
    let output = run_checker_with_fixture(&root, &contract, &out_dir, Some(&fixture))?;
    assert_checker_failed(&output);
    let report = read_json(&report_path(&out_dir))?;
    assert!(
        failure_signatures(&report).contains("missing_tracker_dependency")
            || failure_signatures(&report).contains("tracker_command_failed")
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-unit-binding")?;
    let fixture = write_tracker_fixture(&root, &out_dir)?;
    let contract = mutated_contract(&root, &out_dir, "missing-unit-binding", |manifest| {
        let bindings = manifest["completion_debt_evidence"]["missing_item_bindings"]
            .as_array_mut()
            .unwrap();
        bindings.retain(|binding| binding["spec_item"].as_str() != Some("tests.unit.primary"));
    })?;
    let output = run_checker_with_fixture(&root, &contract, &out_dir, Some(&fixture))?;
    assert_checker_failed(&output);
    let report = read_json(&report_path(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_completion_binding"));
    Ok(())
}
