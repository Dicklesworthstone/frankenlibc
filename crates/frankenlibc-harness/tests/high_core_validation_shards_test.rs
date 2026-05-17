//! High-core validation shard manifest contract (bd-z71ti).
//!
//! The manifest is intentionally small but strict: it gives future planner and
//! merge work a stable schema for shardable validation lanes, artifact
//! contracts, cost hints, and the rch-only rule for cargo-backed proof.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MANIFEST_PATH: &str = "tests/conformance/high_core_validation_shards.v1.json";
const REQUIRED_CATEGORIES: &[&str] = &[
    "cli_contract_meta_gates",
    "completion_contract_gates",
    "ld_preload_smoke",
    "support_matrix_gates",
    "focused_harness_tests",
];
const REQUIRED_RESULT_FIELDS: &[&str] = &[
    "run_id",
    "unit_id",
    "shard_id",
    "command_template",
    "status",
    "exit_code",
    "duration_ms",
    "artifact_refs",
    "failure_signature",
];
const COST_CLASSES: &[&str] = &["cheap", "medium", "expensive"];

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

fn load_manifest() -> TestResult<Value> {
    let root = workspace_root()?;
    let path = root.join(MANIFEST_PATH);
    let body = std::fs::read_to_string(&path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&body)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn field<'a>(value: &'a Value, name: &str, context: &str) -> TestResult<&'a Value> {
    value
        .get(name)
        .ok_or_else(|| test_error(format!("{context}.{name} is required")))
}

fn string_field<'a>(value: &'a Value, name: &str, context: &str) -> TestResult<&'a str> {
    field(value, name, context)?
        .as_str()
        .ok_or_else(|| test_error(format!("{context}.{name} must be a string")))
}

fn array_field<'a>(value: &'a Value, name: &str, context: &str) -> TestResult<&'a Vec<Value>> {
    field(value, name, context)?
        .as_array()
        .ok_or_else(|| test_error(format!("{context}.{name} must be an array")))
}

fn object_field<'a>(
    value: &'a Value,
    name: &str,
    context: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    field(value, name, context)?
        .as_object()
        .ok_or_else(|| test_error(format!("{context}.{name} must be an object")))
}

fn u64_field(value: &Value, name: &str, context: &str) -> TestResult<u64> {
    field(value, name, context)?
        .as_u64()
        .ok_or_else(|| test_error(format!("{context}.{name} must be a nonnegative integer")))
}

fn string_array(value: &Value, name: &str, context: &str) -> TestResult<Vec<String>> {
    array_field(value, name, context)?
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error(format!("{context}.{name}[{idx}] must be a string")))
        })
        .collect()
}

fn contains_all(actual: &[String], required: &[&str], context: &str) -> TestResult {
    let actual_set: BTreeSet<&str> = actual.iter().map(String::as_str).collect();
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|item| !actual_set.contains(item))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(test_error(format!("{context} missing {missing:?}")))
    }
}

fn validate_command_template(unit_id: &str, unit: &Value) -> TestResult {
    let execution_kind = string_field(unit, "execution_kind", unit_id)?;
    if !matches!(execution_kind, "remote_rch" | "local_metadata") {
        return Err(test_error(format!(
            "{unit_id}.execution_kind must be remote_rch or local_metadata"
        )));
    }

    let command = string_array(unit, "command_template", unit_id)?;
    if command.is_empty() || command.iter().any(|part| part.trim().is_empty()) {
        return Err(test_error(format!(
            "{unit_id}.command_template must contain non-empty tokens"
        )));
    }

    let command_set: BTreeSet<&str> = command.iter().map(String::as_str).collect();
    let uses_cargo = command.iter().any(|part| part == "cargo");
    let uses_rch = command.iter().any(|part| part == "rch");
    if execution_kind == "remote_rch" {
        for required in [
            "rch",
            "--no-self-healing",
            "exec",
            "RCH_FORCE_REMOTE=true",
            "RCH_NO_SELF_HEALING=1",
        ] {
            if !command_set.contains(required) {
                return Err(test_error(format!(
                    "{unit_id}.command_template missing remote rch contract token {required}"
                )));
            }
        }
    }
    if uses_cargo && (execution_kind != "remote_rch" || !uses_rch) {
        return Err(test_error(format!(
            "{unit_id}.command_template uses cargo without remote rch contract"
        )));
    }
    Ok(())
}

fn validate_cost(unit_id: &str, unit: &Value) -> TestResult {
    let cost = object_field(unit, "estimated_cost", unit_id)?;
    let cost_value = Value::Object(cost.clone());
    let cost_class = string_field(&cost_value, "cost_class", unit_id)?;
    if !COST_CLASSES.contains(&cost_class) {
        return Err(test_error(format!(
            "{unit_id}.estimated_cost.cost_class invalid: {cost_class}"
        )));
    }
    let cost_points = u64_field(&cost_value, "cost_points", unit_id)?;
    let wall_seconds = u64_field(&cost_value, "estimated_wall_seconds", unit_id)?;
    let parallelism = u64_field(&cost_value, "parallelism", unit_id)?;
    if !(1..=1000).contains(&cost_points) {
        return Err(test_error(format!(
            "{unit_id}.estimated_cost.cost_points must be 1..=1000"
        )));
    }
    if !(1..=7200).contains(&wall_seconds) {
        return Err(test_error(format!(
            "{unit_id}.estimated_cost.estimated_wall_seconds must be 1..=7200"
        )));
    }
    if !(1..=64).contains(&parallelism) {
        return Err(test_error(format!(
            "{unit_id}.estimated_cost.parallelism must be 1..=64"
        )));
    }
    Ok(())
}

fn validate_resource_hints(unit_id: &str, unit: &Value) -> TestResult {
    let hints = Value::Object(object_field(unit, "resource_hints", unit_id)?.clone());
    for field_name in ["max_lanes", "target_memory_mb", "timeout_seconds"] {
        if u64_field(&hints, field_name, unit_id)? == 0 {
            return Err(test_error(format!(
                "{unit_id}.resource_hints.{field_name} must be positive"
            )));
        }
    }
    Ok(())
}

fn validate_artifacts(unit_id: &str, unit: &Value) -> TestResult {
    let artifacts = array_field(unit, "artifacts", unit_id)?;
    if artifacts.is_empty() {
        return Err(test_error(format!(
            "{unit_id}.artifacts must declare at least one output artifact"
        )));
    }

    let mut saw_report = false;
    let mut saw_jsonl = false;
    let mut paths = BTreeSet::new();
    for (idx, artifact) in artifacts.iter().enumerate() {
        let context = format!("{unit_id}.artifacts[{idx}]");
        let kind = string_field(artifact, "kind", &context)?;
        let path = string_field(artifact, "path", &context)?;
        if !matches!(kind, "json_report" | "jsonl_log" | "stdout" | "stderr") {
            return Err(test_error(format!("{context}.kind invalid: {kind}")));
        }
        if !(path.starts_with("target/") || path.starts_with("tests/conformance/")) {
            return Err(test_error(format!(
                "{context}.path must be repo-relative target/ or tests/conformance/ artifact"
            )));
        }
        if !paths.insert(path.to_owned()) {
            return Err(test_error(format!(
                "{unit_id}.artifacts duplicate path {path}"
            )));
        }
        saw_report |= kind == "json_report";
        saw_jsonl |= kind == "jsonl_log";
        field(artifact, "required", &context)?
            .as_bool()
            .ok_or_else(|| test_error(format!("{context}.required must be boolean")))?;
    }

    if !saw_report || !saw_jsonl {
        return Err(test_error(format!(
            "{unit_id}.artifacts must include json_report and jsonl_log"
        )));
    }
    Ok(())
}

fn validate_source_refs(root: &Path, unit_id: &str, unit: &Value) -> TestResult {
    for source_ref in string_array(unit, "source_refs", unit_id)? {
        let path = root.join(&source_ref);
        if !path.exists() {
            return Err(test_error(format!(
                "{unit_id}.source_refs path does not exist: {source_ref}"
            )));
        }
    }
    Ok(())
}

fn validate_manifest(root: &Path, manifest: &Value) -> TestResult {
    if string_field(manifest, "schema_version", "manifest")? != "v1" {
        return Err(test_error("manifest.schema_version must be v1"));
    }
    if string_field(manifest, "bead", "manifest")? != "bd-z71ti" {
        return Err(test_error("manifest.bead must be bd-z71ti"));
    }

    let categories = string_array(manifest, "categories", "manifest")?;
    contains_all(&categories, REQUIRED_CATEGORIES, "manifest.categories")?;

    let planner = field(manifest, "planner_contract", "manifest")?;
    if string_field(planner, "input_manifest", "planner_contract")? != MANIFEST_PATH {
        return Err(test_error(
            "planner_contract.input_manifest must point at committed manifest",
        ));
    }
    contains_all(
        &string_array(planner, "required_result_fields", "planner_contract")?,
        REQUIRED_RESULT_FIELDS,
        "planner_contract.required_result_fields",
    )?;
    contains_all(
        &string_array(planner, "required_unit_fields", "planner_contract")?,
        &[
            "unit_id",
            "category",
            "execution_kind",
            "command_template",
            "estimated_cost",
            "resource_hints",
            "artifacts",
        ],
        "planner_contract.required_unit_fields",
    )?;

    let remote_policy = field(manifest, "remote_execution_policy", "manifest")?;
    for field_name in ["cargo_requires_rch", "local_metadata_may_not_run_cargo"] {
        if field(remote_policy, field_name, "remote_execution_policy")?.as_bool() != Some(true) {
            return Err(test_error(format!(
                "remote_execution_policy.{field_name} must be true"
            )));
        }
    }
    contains_all(
        &string_array(remote_policy, "required_env", "remote_execution_policy")?,
        &["RCH_FORCE_REMOTE=true", "RCH_NO_SELF_HEALING=1"],
        "remote_execution_policy.required_env",
    )?;
    contains_all(
        &string_array(
            remote_policy,
            "required_rch_args",
            "remote_execution_policy",
        )?,
        &["--no-self-healing", "exec"],
        "remote_execution_policy.required_rch_args",
    )?;

    let units = array_field(manifest, "units", "manifest")?;
    if units.len() < REQUIRED_CATEGORIES.len() {
        return Err(test_error(
            "manifest.units must cover every required category",
        ));
    }

    let mut unit_ids = BTreeSet::new();
    let mut covered_categories = BTreeSet::new();
    for unit in units {
        let unit_id = string_field(unit, "unit_id", "unit")?;
        if !unit_id.starts_with("hcvs-") {
            return Err(test_error(format!(
                "{unit_id}.unit_id must start with hcvs-"
            )));
        }
        if !unit_ids.insert(unit_id.to_owned()) {
            return Err(test_error(format!("duplicate unit_id {unit_id}")));
        }
        let category = string_field(unit, "category", unit_id)?;
        if !REQUIRED_CATEGORIES.contains(&category) {
            return Err(test_error(format!(
                "{unit_id}.category invalid: {category}"
            )));
        }
        covered_categories.insert(category.to_owned());
        if string_field(unit, "description", unit_id)?.trim().len() < 20 {
            return Err(test_error(format!("{unit_id}.description is too short")));
        }
        validate_command_template(unit_id, unit)?;
        validate_cost(unit_id, unit)?;
        validate_resource_hints(unit_id, unit)?;
        validate_artifacts(unit_id, unit)?;
        validate_source_refs(root, unit_id, unit)?;
    }

    for category in REQUIRED_CATEGORIES {
        if !covered_categories.contains(*category) {
            return Err(test_error(format!(
                "manifest.units missing required category {category}"
            )));
        }
    }
    Ok(())
}

fn expect_invalid(
    mut manifest: Value,
    mutate: impl FnOnce(&mut Value) -> TestResult,
    expected: &str,
) -> TestResult {
    mutate(&mut manifest)?;
    let root = workspace_root()?;
    match validate_manifest(&root, &manifest) {
        Ok(()) => Err(test_error(format!(
            "mutated manifest unexpectedly passed; expected {expected}"
        ))),
        Err(err) => {
            let actual = err.to_string();
            if actual.contains(expected) {
                Ok(())
            } else {
                Err(test_error(format!(
                    "expected error containing {expected:?}, got {actual:?}"
                )))
            }
        }
    }
}

fn units_mut(manifest: &mut Value) -> TestResult<&mut Vec<Value>> {
    manifest
        .get_mut("units")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("manifest.units must be a mutable array"))
}

#[test]
fn committed_manifest_is_self_contained_and_planner_ready() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_manifest()?;
    validate_manifest(&root, &manifest)
}

#[test]
fn manifest_rejects_duplicate_unit_ids() -> TestResult {
    let manifest = load_manifest()?;
    expect_invalid(
        manifest,
        |value| {
            let units = units_mut(value)?;
            let first_id = string_field(&units[0], "unit_id", "unit")?.to_owned();
            units[1]["unit_id"] = Value::String(first_id);
            Ok(())
        },
        "duplicate unit_id",
    )
}

#[test]
fn manifest_rejects_missing_artifact_declarations() -> TestResult {
    let manifest = load_manifest()?;
    expect_invalid(
        manifest,
        |value| {
            units_mut(value)?[0]["artifacts"] = Value::Array(Vec::new());
            Ok(())
        },
        "artifacts must declare at least one output artifact",
    )
}

#[test]
fn manifest_rejects_invalid_cost_fields() -> TestResult {
    let manifest = load_manifest()?;
    expect_invalid(
        manifest,
        |value| {
            units_mut(value)?[0]["estimated_cost"]["cost_points"] = Value::from(0);
            Ok(())
        },
        "cost_points must be 1..=1000",
    )
}

#[test]
fn manifest_rejects_local_cargo_command_templates() -> TestResult {
    let manifest = load_manifest()?;
    expect_invalid(
        manifest,
        |value| {
            let unit = &mut units_mut(value)?[0];
            unit["execution_kind"] = Value::String("local_metadata".to_owned());
            unit["command_template"] =
                serde_json::json!(["cargo", "test", "-p", "frankenlibc-harness"]);
            Ok(())
        },
        "uses cargo without remote rch contract",
    )
}
