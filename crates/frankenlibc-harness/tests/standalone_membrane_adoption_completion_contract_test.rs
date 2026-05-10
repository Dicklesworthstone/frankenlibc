//! Standalone membrane adoption completion-debt contract (bd-2yx2 / bd-2yx2.1).

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

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

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/standalone_membrane_adoption_completion_contract.v1.json")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn unique_output_dir(root: &Path, prefix: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let path = root
        .join("target/conformance")
        .join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn string_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| test_error(format!("missing string field {field}")))
}

fn array_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("missing array field {field}")))
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join("scripts/check_standalone_membrane_adoption_completion_contract.sh"))
        .current_dir(root)
        .env("STANDALONE_MEMBRANE_COMPLETION_CONTRACT", contract)
        .env("STANDALONE_MEMBRANE_COMPLETION_OUT_DIR", out_dir)
        .env(
            "STANDALONE_MEMBRANE_COMPLETION_REPORT",
            out_dir.join("standalone_membrane_adoption_completion_contract.report.json"),
        )
        .env(
            "STANDALONE_MEMBRANE_COMPLETION_LOG",
            out_dir.join("standalone_membrane_adoption_completion_contract.log.jsonl"),
        )
        .output()?)
}

#[test]
fn manifest_anchors_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(string_field(&manifest, "schema_version")?, "v1");
    assert_eq!(
        string_field(&manifest, "manifest_id")?,
        "standalone-membrane-adoption-completion-contract"
    );
    assert_eq!(string_field(&manifest, "bead")?, "bd-2yx2");
    assert_eq!(
        string_field(&manifest, "completion_debt_bead")?,
        "bd-2yx2.1"
    );
    Ok(())
}

#[test]
fn source_artifacts_are_file_backed() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let artifacts = manifest
        .get("source_artifacts")
        .and_then(Value::as_object)
        .ok_or_else(|| test_error("missing source_artifacts"))?;
    for (artifact_id, path_value) in artifacts {
        let path = path_value
            .as_str()
            .ok_or_else(|| test_error(format!("{artifact_id} path must be string")))?;
        assert!(root.join(path).is_file(), "{artifact_id} missing {path}");
    }
    Ok(())
}

#[test]
fn workspace_contract_binds_standalone_crate() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let workspace = std::fs::read_to_string(root.join("Cargo.toml"))?;
    let membrane_manifest =
        std::fs::read_to_string(root.join("crates/frankenlibc-membrane/Cargo.toml"))?;
    let membrane_lib =
        std::fs::read_to_string(root.join("crates/frankenlibc-membrane/src/lib.rs"))?;
    let contract = manifest
        .get("workspace_contract")
        .ok_or_else(|| test_error("missing workspace_contract"))?;
    assert!(workspace.contains(string_field(contract, "member")?));
    assert!(workspace.contains(string_field(contract, "workspace_dependency")?));
    assert!(membrane_manifest.contains("name = \"frankenlibc-membrane\""));
    for needle in array_field(contract, "required_features")? {
        let needle = needle
            .as_str()
            .ok_or_else(|| test_error("feature needle must be string"))?;
        assert!(membrane_manifest.contains(needle), "missing {needle}");
    }
    for needle in array_field(contract, "required_lib_needles")? {
        let needle = needle
            .as_str()
            .ok_or_else(|| test_error("lib needle must be string"))?;
        assert!(membrane_lib.contains(needle), "missing {needle}");
    }
    Ok(())
}

#[test]
fn adoption_edges_bind_workspace_consumers() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    for edge in array_field(&manifest, "adoption_edges")? {
        let manifest_path = string_field(edge, "manifest")?;
        let dependency = string_field(edge, "dependency")?;
        let source = std::fs::read_to_string(root.join(manifest_path))?;
        assert!(
            source.contains(dependency),
            "{} missing {dependency}",
            string_field(edge, "consumer")?
        );
    }
    Ok(())
}

#[test]
fn unit_primary_binds_membrane_unit_tests() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let unit = manifest
        .get("unit_primary")
        .ok_or_else(|| test_error("missing unit_primary"))?;
    assert_eq!(string_field(unit, "missing_item_id")?, "tests.unit.primary");
    let source = std::fs::read_to_string(root.join(string_field(unit, "test_file")?))?;
    for name in array_field(unit, "required_test_names")? {
        let name = name
            .as_str()
            .ok_or_else(|| test_error("test name must be string"))?;
        assert!(source.contains(&format!("fn {name}(")), "missing {name}");
    }
    Ok(())
}

#[test]
fn e2e_primary_scenarios_are_remote_cargo_commands() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let e2e = manifest
        .get("e2e_primary")
        .ok_or_else(|| test_error("missing e2e_primary"))?;
    assert_eq!(string_field(e2e, "missing_item_id")?, "tests.e2e.primary");
    let ids: BTreeSet<_> = array_field(e2e, "scenarios")?
        .iter()
        .filter_map(|scenario| scenario.get("scenario_id").and_then(Value::as_str))
        .collect();
    for scenario in [
        "standalone_membrane_package_checks_all_targets",
        "standalone_membrane_unit_tests_run_without_downstream_packages",
        "standalone_membrane_clippy_is_warning_clean",
    ] {
        assert!(ids.contains(scenario), "missing scenario {scenario}");
    }
    for scenario in array_field(e2e, "scenarios")? {
        let command = string_field(scenario, "command")?;
        assert!(command.starts_with("rch cargo "));
        assert!(command.contains("-p frankenlibc-membrane"));
    }
    Ok(())
}

#[test]
fn checker_accepts_manifest_and_emits_report() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "standalone-membrane-ok")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report =
        load_json(&out_dir.join("standalone_membrane_adoption_completion_contract.report.json"))?;
    assert_eq!(string_field(&report, "status")?, "pass");
    assert_eq!(
        string_field(&report, "schema_version")?,
        "standalone_membrane_adoption_completion_contract.report.v1"
    );
    assert_eq!(
        report.get("adoption_edge_count").and_then(Value::as_u64),
        Some(5)
    );
    assert_eq!(
        report
            .get("unit_required_test_count")
            .and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        report.get("e2e_scenario_count").and_then(Value::as_u64),
        Some(3)
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_workspace_member() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "standalone-membrane-fail-member")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["workspace_contract"]["member"] = json!("crates/missing-membrane");
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;
    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing workspace member"
    );
    let report =
        load_json(&out_dir.join("standalone_membrane_adoption_completion_contract.report.json"))?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("workspace member missing"))),
        "report should name missing workspace member: {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_adoption_edge() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "standalone-membrane-fail-edge")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let edge = manifest["adoption_edges"][0]
        .as_object_mut()
        .ok_or_else(|| test_error("first adoption edge should be object"))?;
    edge.insert(
        "dependency".to_string(),
        json!("frankenlibc-membrane = { workspace = false }"),
    );
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;
    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing adoption edge"
    );
    let report =
        load_json(&out_dir.join("standalone_membrane_adoption_completion_contract.report.json"))?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("missing dependency edge"))),
        "report should name missing adoption edge: {errors:?}"
    );
    Ok(())
}
