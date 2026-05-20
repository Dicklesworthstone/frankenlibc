//! Freshness-state schema gate for bd-3yr14.1.

use frankenlibc_harness::freshness_state::{
    CHAIN_HASH_FIELD, FRESHNESS_STATE_FIELD, GENERATED_AT_FIELD, GENERATOR_COMMAND_FIELD,
    REQUIRED_FRESHNESS_STATE_FIELDS, SOURCE_COMMIT_FIELD, TOOL_VERSION_FIELD,
    validate_freshness_state,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| test_error("crate manifest should have crates parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have workspace parent"))?
        .to_path_buf())
}

fn schema_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/freshness_state_schema.v1.json")
}

fn load_schema() -> TestResult<Value> {
    let root = workspace_root()?;
    let path = schema_path(&root);
    let content = std::fs::read_to_string(&path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| test_error(format!("{context}.{key} must be a string")))
}

fn object_field<'a>(
    value: &'a mut Value,
    key: &str,
    context: &str,
) -> TestResult<&'a mut serde_json::Map<String, Value>> {
    value
        .get_mut(key)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error(format!("{context}.{key} must be an object")))
}

fn expect_valid(value: &Value) -> TestResult {
    validate_freshness_state(value)
        .map_err(|violations| test_error(format!("freshness_state violations: {violations:?}")))
}

fn failure_signatures(
    result: Result<(), Vec<frankenlibc_harness::freshness_state::FreshnessStateViolation>>,
) -> BTreeSet<String> {
    result
        .expect_err("fixture should fail freshness_state validation")
        .into_iter()
        .map(|violation| violation.failure_signature)
        .collect()
}

#[test]
fn schema_declares_required_freshness_state_fields() -> TestResult {
    let schema = load_schema()?;
    assert_eq!(
        string_field(&schema, "schema_version", "schema")?,
        "freshness_state_schema.v1"
    );
    assert_eq!(string_field(&schema, "bead_id", "schema")?, "bd-3yr14.1");
    assert_eq!(
        string_field(&schema, "artifact_field", "schema")?,
        FRESHNESS_STATE_FIELD
    );

    let required = schema
        .get("required_fields")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("schema.required_fields must be an array"))?;
    let names: Vec<_> = required
        .iter()
        .map(|row| string_field(row, "name", "required_fields[]"))
        .collect::<TestResult<_>>()?;
    assert_eq!(names, REQUIRED_FRESHNESS_STATE_FIELDS.to_vec());

    let failure_signatures: BTreeSet<_> = required
        .iter()
        .map(|row| string_field(row, "failure_signature", "required_fields[]"))
        .collect::<TestResult<_>>()?;
    for field in REQUIRED_FRESHNESS_STATE_FIELDS {
        assert!(
            failure_signatures.contains(format!("missing_freshness_state_{field}").as_str()),
            "missing field failure signature for {field}"
        );
    }

    expect_valid(&schema)?;
    Ok(())
}

#[test]
fn schema_gate_accepts_complete_artifact() -> TestResult {
    let schema = load_schema()?;
    let fixture = schema
        .get("positive_fixture")
        .ok_or_else(|| test_error("schema.positive_fixture is missing"))?;
    expect_valid(fixture)?;
    Ok(())
}

#[test]
fn schema_gate_rejects_artifact_without_freshness_state() {
    let signatures = failure_signatures(validate_freshness_state(&serde_json::json!({
        "schema_version": "example.v1"
    })));
    assert!(signatures.contains("missing_freshness_state"));
}

#[test]
fn schema_gate_rejects_artifact_missing_any_required_field() -> TestResult {
    let schema = load_schema()?;
    let base_fixture = schema
        .get("positive_fixture")
        .cloned()
        .ok_or_else(|| test_error("schema.positive_fixture is missing"))?;
    let negative_fixtures = schema
        .get("negative_fixtures")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("schema.negative_fixtures must be an array"))?;

    for fixture in negative_fixtures {
        let remove_field = string_field(fixture, "remove_field", "negative_fixtures[]")?;
        let expected = string_field(fixture, "failure_signature", "negative_fixtures[]")?;
        let mut mutated = base_fixture.clone();
        object_field(&mut mutated, FRESHNESS_STATE_FIELD, "positive_fixture")?.remove(remove_field);

        let signatures = failure_signatures(validate_freshness_state(&mutated));
        assert!(
            signatures.contains(expected),
            "missing {remove_field} should emit {expected}; got {signatures:?}"
        );
    }
    Ok(())
}

#[test]
fn schema_gate_rejects_invalid_field_shapes() -> TestResult {
    let schema = load_schema()?;
    let mut fixture = schema
        .get("positive_fixture")
        .cloned()
        .ok_or_else(|| test_error("schema.positive_fixture is missing"))?;
    let state = object_field(&mut fixture, FRESHNESS_STATE_FIELD, "positive_fixture")?;
    state.insert(
        GENERATED_AT_FIELD.to_string(),
        Value::String("today".into()),
    );
    state.insert(
        SOURCE_COMMIT_FIELD.to_string(),
        Value::String("not-a-sha".into()),
    );
    state.insert(
        GENERATOR_COMMAND_FIELD.to_string(),
        Value::String("".into()),
    );
    state.insert(TOOL_VERSION_FIELD.to_string(), Value::String("".into()));
    state.insert(CHAIN_HASH_FIELD.to_string(), Value::String("1234".into()));

    let signatures = failure_signatures(validate_freshness_state(&fixture));
    for expected in [
        "invalid_freshness_state_generated_at_utc",
        "invalid_freshness_state_source_commit",
        "missing_freshness_state_generator_command",
        "missing_freshness_state_tool_version",
        "invalid_freshness_state_chain_hash",
    ] {
        assert!(
            signatures.contains(expected),
            "invalid fixture should emit {expected}; got {signatures:?}"
        );
    }
    Ok(())
}
