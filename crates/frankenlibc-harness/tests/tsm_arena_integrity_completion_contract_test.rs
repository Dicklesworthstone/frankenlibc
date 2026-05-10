//! TSM arena/fingerprint/canary/bounds completion-debt contract (bd-32e.2 / bd-32e.2.1).

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
    root.join("tests/conformance/tsm_arena_integrity_completion_contract.v1.json")
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

fn object_field<'a>(
    value: &'a Value,
    field: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| test_error(format!("missing object field {field}")))
}

fn source_artifact_path(manifest: &Value, artifact_id: &str) -> TestResult<String> {
    object_field(manifest, "source_artifacts")?
        .get(artifact_id)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| test_error(format!("missing source_artifacts.{artifact_id}")))
}

fn string_set(values: &[Value]) -> TestResult<BTreeSet<String>> {
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| test_error("array entry should be string"))
        })
        .collect()
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join("scripts/check_tsm_arena_integrity_completion_contract.sh"))
        .current_dir(root)
        .env("TSM_ARENA_INTEGRITY_COMPLETION_CONTRACT", contract)
        .env("TSM_ARENA_INTEGRITY_COMPLETION_OUT_DIR", out_dir)
        .env(
            "TSM_ARENA_INTEGRITY_COMPLETION_REPORT",
            out_dir.join("tsm_arena_integrity_completion_contract.report.json"),
        )
        .env(
            "TSM_ARENA_INTEGRITY_COMPLETION_LOG",
            out_dir.join("tsm_arena_integrity_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn run_bad_manifest(root: &Path, manifest: &Value, out_dir: &Path) -> TestResult<Value> {
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, manifest)?;
    let output = run_checker(root, &bad_manifest, out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject bad manifest stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    load_json(&out_dir.join("tsm_arena_integrity_completion_contract.report.json"))
}

#[test]
fn manifest_anchors_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(string_field(&manifest, "schema_version")?, "v1");
    assert_eq!(
        string_field(&manifest, "manifest_id")?,
        "tsm-arena-integrity-completion-contract"
    );
    assert_eq!(string_field(&manifest, "bead")?, "bd-32e.2");
    assert_eq!(
        string_field(&manifest, "completion_debt_bead")?,
        "bd-32e.2.1"
    );
    Ok(())
}

#[test]
fn source_artifacts_are_file_backed() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    for (artifact_id, path_value) in object_field(&manifest, "source_artifacts")? {
        let path = path_value
            .as_str()
            .ok_or_else(|| test_error(format!("{artifact_id} path must be string")))?;
        assert!(root.join(path).is_file(), "{artifact_id} missing {path}");
    }
    Ok(())
}

#[test]
fn implementation_contract_binds_stage_tokens() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let implementation = manifest
        .get("implementation_contract")
        .ok_or_else(|| test_error("missing implementation_contract"))?;
    let ptr_validator =
        std::fs::read_to_string(root.join(source_artifact_path(&manifest, "ptr_validator")?))?;
    let arena = std::fs::read_to_string(root.join(source_artifact_path(&manifest, "arena")?))?;
    let fingerprint =
        std::fs::read_to_string(root.join(source_artifact_path(&manifest, "fingerprint")?))?;

    let labels = string_set(array_field(implementation, "stage_labels")?)?;
    for label in ["arena_lookup", "fingerprint", "canary", "bounds"] {
        assert!(labels.contains(label), "missing stage label {label}");
        assert!(
            ptr_validator.contains(&format!("\"{label}\"")),
            "ptr_validator missing label {label}"
        );
    }

    let paths = string_set(array_field(implementation, "stage_paths")?)?;
    for path in [
        "pipeline::stage4::arena",
        "pipeline::stage5::fingerprint",
        "pipeline::stage6::canary",
        "pipeline::stage7::bounds",
    ] {
        assert!(paths.contains(path), "missing stage path {path}");
        assert!(
            ptr_validator.contains(&format!("\"{path}\"")),
            "ptr_validator missing path {path}"
        );
    }

    for needle in array_field(implementation, "ptr_validator_needles")? {
        let needle = needle
            .as_str()
            .ok_or_else(|| test_error("ptr_validator needle must be string"))?;
        assert!(ptr_validator.contains(needle), "missing {needle}");
    }
    for needle in array_field(implementation, "arena_needles")? {
        let needle = needle
            .as_str()
            .ok_or_else(|| test_error("arena needle must be string"))?;
        assert!(arena.contains(needle), "missing {needle}");
    }
    for needle in array_field(implementation, "fingerprint_needles")? {
        let needle = needle
            .as_str()
            .ok_or_else(|| test_error("fingerprint needle must be string"))?;
        assert!(fingerprint.contains(needle), "missing {needle}");
    }
    Ok(())
}

#[test]
fn unit_primary_binds_arena_fingerprint_and_validator_tests() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let unit = manifest
        .get("unit_primary")
        .ok_or_else(|| test_error("missing unit_primary"))?;
    assert_eq!(string_field(unit, "missing_item_id")?, "tests.unit.primary");

    let mut source_texts = std::collections::BTreeMap::new();
    for source in ["arena", "fingerprint", "ptr_validator"] {
        source_texts.insert(
            source,
            std::fs::read_to_string(root.join(source_artifact_path(&manifest, source)?))?,
        );
    }
    let mut seen_sources = BTreeSet::new();
    for test_ref in array_field(unit, "required_test_refs")? {
        let source = string_field(test_ref, "source")?;
        let name = string_field(test_ref, "name")?;
        seen_sources.insert(source.to_string());
        let text = source_texts
            .get(source)
            .ok_or_else(|| test_error(format!("undeclared source {source}")))?;
        assert!(
            text.contains(&format!("fn {name}")),
            "missing {source}::{name}"
        );
    }
    for source in ["arena", "fingerprint", "ptr_validator"] {
        assert!(seen_sources.contains(source), "unit refs missing {source}");
    }
    for command in array_field(unit, "required_commands")? {
        let command = command
            .as_str()
            .ok_or_else(|| test_error("unit command must be string"))?;
        assert!(
            command.starts_with("rch cargo "),
            "unit command must use rch: {command}"
        );
    }
    Ok(())
}

#[test]
fn e2e_primary_binds_public_pipeline_tests() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let e2e = manifest
        .get("e2e_primary")
        .ok_or_else(|| test_error("missing e2e_primary"))?;
    assert_eq!(string_field(e2e, "missing_item_id")?, "tests.e2e.primary");
    let source =
        std::fs::read_to_string(root.join(source_artifact_path(&manifest, "tsm_pipeline_e2e")?))?;
    let refs = array_field(e2e, "required_test_refs")?;
    assert!(refs.len() >= 8, "expected broad e2e anchor set");
    for test_ref in refs {
        let name = string_field(test_ref, "name")?;
        assert!(source.contains(&format!("fn {name}")), "missing {name}");
    }
    for command in array_field(e2e, "required_commands")? {
        let command = command
            .as_str()
            .ok_or_else(|| test_error("e2e command must be string"))?;
        assert!(
            command.starts_with("rch cargo "),
            "e2e command must use rch: {command}"
        );
        assert!(
            command.contains("--test tsm_pipeline_e2e_test"),
            "e2e command should target public TSM pipeline test: {command}"
        );
    }
    Ok(())
}

#[test]
fn checker_accepts_manifest_and_emits_report() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "tsm-arena-integrity-ok")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&out_dir.join("tsm_arena_integrity_completion_contract.report.json"))?;
    assert_eq!(string_field(&report, "status")?, "pass");
    assert_eq!(
        string_field(&report, "schema_version")?,
        "tsm_arena_integrity_completion_contract.report.v1"
    );
    assert_eq!(
        report.get("stage_path_count").and_then(Value::as_u64),
        Some(4)
    );
    assert_eq!(
        report
            .get("unit_required_test_count")
            .and_then(Value::as_u64),
        Some(14)
    );
    assert_eq!(
        report
            .get("e2e_required_test_count")
            .and_then(Value::as_u64),
        Some(8)
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_bounds_stage_path() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "tsm-arena-integrity-fail-bounds")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["implementation_contract"]["stage_paths"] = json!([
        "pipeline::stage4::arena",
        "pipeline::stage5::fingerprint",
        "pipeline::stage6::canary"
    ]);
    let report = run_bad_manifest(&root, &manifest, &out_dir)?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors
            .iter()
            .any(|error| error.as_str().is_some_and(|text| text
                .contains("implementation_contract.stage_paths missing pipeline::stage7::bounds"))),
        "report should name missing bounds path: {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_anchor() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "tsm-arena-integrity-fail-unit")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["unit_primary"]["required_test_refs"][0]["name"] =
        json!("missing_arena_integrity_unit_test");
    let report = run_bad_manifest(&root, &manifest, &out_dir)?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("unit_primary references missing test"))),
        "report should name missing unit anchor: {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_e2e_anchor() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "tsm-arena-integrity-fail-e2e")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["e2e_primary"]["required_test_refs"][0]["name"] =
        json!("missing_tsm_pipeline_e2e_test");
    let report = run_bad_manifest(&root, &manifest, &out_dir)?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("e2e_primary references missing test"))),
        "report should name missing e2e anchor: {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_stale_fingerprint_constant() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "tsm-arena-integrity-fail-fingerprint")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["implementation_contract"]["fingerprint_needles"][0] =
        json!("pub const FINGERPRINT_SIZE: usize = 16;");
    let report = run_bad_manifest(&root, &manifest, &out_dir)?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("fingerprint source missing needle"))),
        "report should name stale fingerprint constant: {errors:?}"
    );
    Ok(())
}
