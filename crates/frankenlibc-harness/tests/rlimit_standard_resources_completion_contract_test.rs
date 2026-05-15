use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const STANDARD_RESOURCES: &[&str] = &[
    "RLIMIT_CPU",
    "RLIMIT_FSIZE",
    "RLIMIT_DATA",
    "RLIMIT_STACK",
    "RLIMIT_CORE",
    "RLIMIT_RSS",
    "RLIMIT_NPROC",
    "RLIMIT_NOFILE",
    "RLIMIT_MEMLOCK",
    "RLIMIT_AS",
    "RLIMIT_LOCKS",
    "RLIMIT_SIGPENDING",
    "RLIMIT_MSGQUEUE",
    "RLIMIT_NICE",
    "RLIMIT_RTPRIO",
    "RLIMIT_RTTIME",
];

const FORMERLY_REJECTED: &[&str] = &[
    "RLIMIT_RSS",
    "RLIMIT_NPROC",
    "RLIMIT_MEMLOCK",
    "RLIMIT_LOCKS",
    "RLIMIT_SIGPENDING",
    "RLIMIT_MSGQUEUE",
    "RLIMIT_NICE",
    "RLIMIT_RTPRIO",
    "RLIMIT_RTTIME",
];

const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "completion_bindings_validated",
    "validator_source_validated",
    "unit_test_bindings_validated",
    "rlimit_standard_resources_completion_contract_pass",
];

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("missing workspace root")?
        .to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/rlimit_standard_resources_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_rlimit_standard_resources_completion_contract.sh")
}

fn report_path(out_dir: &Path) -> PathBuf {
    out_dir.join("rlimit_standard_resources_completion_contract.report.json")
}

fn log_path(out_dir: &Path) -> PathBuf {
    out_dir.join("rlimit_standard_resources_completion_contract.log.jsonl")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?)
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let array = value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected array"))?;
    Ok(array
        .iter()
        .map(|item| {
            item.as_str()
                .map(ToString::to_string)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string"))
        })
        .collect::<Result<_, _>>()?)
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = root
        .join("target/conformance")
        .join(format!("rlimit-standard-resources-{label}-{nanos}"));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> io::Result<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .arg(contract)
        .env(
            "FRANKENLIBC_RLIMIT_STANDARD_RESOURCES_COMPLETION_OUT_DIR",
            out_dir,
        )
        .current_dir(root)
        .output()
}

fn mutated_contract(
    root: &Path,
    out_dir: &Path,
    label: &str,
    mutate: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let mut manifest = read_json(&contract_path(root))?;
    mutate(&mut manifest)?;
    let path = out_dir.join(format!(
        "rlimit_standard_resources_completion_contract.{label}.json"
    ));
    std::fs::write(&path, serde_json::to_string_pretty(&manifest)? + "\n")?;
    Ok(path)
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_checker_failed(output: &Output) {
    assert!(
        !output.status.success(),
        "checker unexpectedly passed\n{}",
        output_text(output)
    );
}

fn failure_signatures(report: &Value) -> BTreeSet<String> {
    report["errors"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry["signature"].as_str())
        .map(ToString::to_string)
        .collect()
}

#[test]
fn manifest_binds_rlimit_standard_resource_unit_item() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("rlimit_standard_resources_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-0ul0z.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-0ul0z"));
    assert_eq!(
        manifest["trace_id"].as_str(),
        Some("bd-0ul0z.1::rlimit-standard-resources::v1")
    );
    assert!(
        manifest["completion_debt_evidence"]["next_audit_score_threshold"]
            .as_u64()
            .unwrap_or(0)
            >= 800
    );

    let bindings = manifest["completion_debt_evidence"]["missing_item_bindings"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing bindings"))?;
    assert_eq!(bindings.len(), 1);
    assert_eq!(
        bindings[0]["spec_item"].as_str(),
        Some("tests.unit.primary")
    );

    let runtime = &manifest["rlimit_standard_resource_contract"];
    assert_eq!(
        string_set(&runtime["required_standard_resources"])?,
        STANDARD_RESOURCES
            .iter()
            .map(|resource| resource.to_string())
            .collect()
    );
    assert_eq!(
        string_set(&runtime["formerly_rejected_resources"])?,
        FORMERLY_REJECTED
            .iter()
            .map(|resource| resource.to_string())
            .collect()
    );
    assert_eq!(
        runtime["validator_expression"].as_str(),
        Some("(RLIMIT_CPU..=RLIMIT_MAX_VALID).contains(&resource)")
    );

    let artifacts = manifest["source_artifacts"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source_artifacts array"))?;
    for artifact in artifacts {
        let path = artifact["path"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact path missing"))?;
        assert!(root.join(path).exists(), "missing source artifact {path}");
    }

    let events = string_set(&manifest["completion_output_contract"]["required_events"])?;
    assert_eq!(
        events,
        REQUIRED_EVENTS
            .iter()
            .map(|event| event.to_string())
            .collect()
    );
    Ok(())
}

#[test]
fn checker_validates_rlimit_standard_resources_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&report_path(&out_dir))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["binding_count"].as_u64(), Some(1));
    assert_eq!(
        report["summary"]["standard_resource_count"].as_u64(),
        Some(16)
    );
    assert_eq!(
        report["summary"]["formerly_rejected_resource_count"].as_u64(),
        Some(9)
    );
    assert_eq!(report["summary"]["unit_group_count"].as_u64(), Some(3));
    let errors = report["errors"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "report errors array"))?;
    assert!(errors.is_empty());

    let rows = read_jsonl(&log_path(&out_dir))?;
    let events: BTreeSet<String> = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .map(ToString::to_string)
        .collect();
    for event in REQUIRED_EVENTS {
        assert!(events.contains(*event), "missing event {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-unit")?;
    let contract = mutated_contract(&root, &out_dir, "missing-unit", |manifest| {
        manifest["completion_debt_evidence"]["missing_item_bindings"] = json!([]);
        Ok(())
    })?;

    let output = run_checker(&root, &contract, &out_dir)?;
    assert_checker_failed(&output);

    let report = read_json(&report_path(&out_dir))?;
    let signatures = failure_signatures(&report);
    assert!(signatures.contains("missing_completion_binding"));
    Ok(())
}

#[test]
fn checker_rejects_missing_formerly_rejected_resource() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-resource")?;
    let contract = mutated_contract(&root, &out_dir, "missing-resource", |manifest| {
        let resources =
            manifest["rlimit_standard_resource_contract"]["formerly_rejected_resources"]
                .as_array_mut()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "formerly_rejected_resources array",
                    )
                })?;
        resources.retain(|resource| resource.as_str() != Some("RLIMIT_RTTIME"));
        Ok(())
    })?;

    let output = run_checker(&root, &contract, &out_dir)?;
    assert_checker_failed(&output);

    let report = read_json(&report_path(&out_dir))?;
    let signatures = failure_signatures(&report);
    assert!(signatures.contains("resource_set_drift"));
    Ok(())
}

#[test]
fn checker_rejects_unit_test_binding_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "unit-drift")?;
    let contract = mutated_contract(&root, &out_dir, "unit-drift", |manifest| {
        manifest["rlimit_standard_resource_contract"]["required_unit_test_groups"][0]["tests"][0] =
            json!("missing_valid_resource_test");
        Ok(())
    })?;

    let output = run_checker(&root, &contract, &out_dir)?;
    assert_checker_failed(&output);

    let report = read_json(&report_path(&out_dir))?;
    let signatures = failure_signatures(&report);
    assert!(signatures.contains("unit_binding_drift"));
    Ok(())
}
