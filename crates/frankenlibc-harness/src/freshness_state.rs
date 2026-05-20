//! Freshness-state validation for canonical conformance artifacts.

use serde_json::{Map, Value};

pub const FRESHNESS_STATE_FIELD: &str = "freshness_state";
pub const GENERATED_AT_FIELD: &str = "generated_at_utc";
pub const SOURCE_COMMIT_FIELD: &str = "source_commit";
pub const GENERATOR_COMMAND_FIELD: &str = "generator_command";
pub const TOOL_VERSION_FIELD: &str = "tool_version";
pub const CHAIN_HASH_FIELD: &str = "chain_hash";
pub const REQUIRED_FRESHNESS_STATE_FIELDS: [&str; 5] = [
    GENERATED_AT_FIELD,
    SOURCE_COMMIT_FIELD,
    GENERATOR_COMMAND_FIELD,
    TOOL_VERSION_FIELD,
    CHAIN_HASH_FIELD,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FreshnessStateViolation {
    pub failure_signature: String,
    pub field: Option<String>,
    pub message: String,
}

impl FreshnessStateViolation {
    fn missing_container() -> Self {
        Self {
            failure_signature: "missing_freshness_state".to_string(),
            field: None,
            message: "artifact must contain a freshness_state object".to_string(),
        }
    }

    fn missing_field(field: &str) -> Self {
        Self {
            failure_signature: format!("missing_freshness_state_{field}"),
            field: Some(field.to_string()),
            message: format!("freshness_state.{field} is required"),
        }
    }

    fn invalid_field(field: &str, message: impl Into<String>) -> Self {
        Self {
            failure_signature: format!("invalid_freshness_state_{field}"),
            field: Some(field.to_string()),
            message: message.into(),
        }
    }
}

pub fn validate_freshness_state(artifact: &Value) -> Result<(), Vec<FreshnessStateViolation>> {
    let Some(state) = artifact.get(FRESHNESS_STATE_FIELD) else {
        return Err(vec![FreshnessStateViolation::missing_container()]);
    };
    let Some(state) = state.as_object() else {
        return Err(vec![FreshnessStateViolation::missing_container()]);
    };

    let violations = validate_freshness_state_object(state);
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

pub fn validate_freshness_state_object(state: &Map<String, Value>) -> Vec<FreshnessStateViolation> {
    let mut violations = Vec::new();

    for field in REQUIRED_FRESHNESS_STATE_FIELDS {
        match required_string(state, field) {
            Some(value) => validate_field_shape(field, value, &mut violations),
            None => violations.push(FreshnessStateViolation::missing_field(field)),
        }
    }

    violations
}

fn required_string<'a>(state: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    state
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn validate_field_shape(field: &str, value: &str, violations: &mut Vec<FreshnessStateViolation>) {
    match field {
        GENERATED_AT_FIELD if !is_utc_timestamp(value) => {
            violations.push(FreshnessStateViolation::invalid_field(
                field,
                "generated_at_utc must use YYYY-MM-DDTHH:MM:SSZ UTC form",
            ));
        }
        SOURCE_COMMIT_FIELD if !is_hex_len(value, 40) => {
            violations.push(FreshnessStateViolation::invalid_field(
                field,
                "source_commit must be a 40-character git commit hex id",
            ));
        }
        CHAIN_HASH_FIELD if !is_hex_len(value, 64) => {
            violations.push(FreshnessStateViolation::invalid_field(
                field,
                "chain_hash must be a 64-character hex digest",
            ));
        }
        GENERATOR_COMMAND_FIELD | TOOL_VERSION_FIELD => {}
        _ => {}
    }
}

fn is_hex_len(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != "YYYY-MM-DDTHH:MM:SSZ".len() {
        return false;
    }
    for index in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !bytes[index].is_ascii_digit() {
            return false;
        }
    }
    bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn complete_artifact() -> Value {
        json!({
            "freshness_state": {
                "generated_at_utc": "2026-05-20T23:20:00Z",
                "source_commit": "1111111111111111111111111111111111111111",
                "generator_command": "cargo run -p frankenlibc-harness -- freshness-state",
                "tool_version": "frankenlibc-harness 0.1.0",
                "chain_hash": "15694b99216cc19a2942993b6b5055ac68aa58217efcb6be71b17cdb0f6da3d3"
            }
        })
    }

    #[test]
    fn complete_freshness_state_is_valid() {
        assert_eq!(validate_freshness_state(&complete_artifact()), Ok(()));
    }

    #[test]
    fn missing_container_is_rejected() {
        let error = validate_freshness_state(&json!({})).expect_err("missing container");
        assert_eq!(error[0].failure_signature, "missing_freshness_state");
    }

    #[test]
    fn malformed_source_commit_is_rejected() {
        let mut artifact = complete_artifact();
        artifact["freshness_state"][SOURCE_COMMIT_FIELD] = json!("not-a-commit");
        let error = validate_freshness_state(&artifact).expect_err("invalid commit");
        assert!(error.iter().any(
            |violation| violation.failure_signature == "invalid_freshness_state_source_commit"
        ));
    }
}
