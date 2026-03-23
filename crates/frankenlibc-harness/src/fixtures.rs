//! Fixture loading and management.

use serde::de::Deserializer;
use serde::{Deserialize, Serialize};

/// A single fixture test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureCase {
    /// Case identifier.
    pub name: String,
    /// Function being tested.
    pub function: String,
    /// POSIX/C spec section reference.
    pub spec_section: String,
    /// Input parameters (serialized).
    pub inputs: serde_json::Value,
    /// Expected output (serialized as string for comparison).
    #[serde(deserialize_with = "deserialize_expected_output")]
    pub expected_output: String,
    /// Expected errno after call.
    #[serde(default)]
    pub expected_errno: i32,
    /// Whether this tests strict or hardened behavior.
    pub mode: String,
}

/// A collection of fixture cases for a function family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureSet {
    /// Schema version.
    pub version: String,
    /// Function family name.
    pub family: String,
    /// UTC timestamp of capture.
    pub captured_at: String,
    /// Individual test cases.
    pub cases: Vec<FixtureCase>,
}

impl FixtureSet {
    /// Load fixture set from JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize fixture set to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Load fixture set from a file path.
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let set = Self::from_json(&content)?;
        Ok(set)
    }
}

fn deserialize_expected_output<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(normalize_expected_output_value(&value))
}

pub(crate) fn normalize_expected_output_value(value: &serde_json::Value) -> String {
    if let Some(text) = value.as_str() {
        return text.to_string();
    }
    serde_json::to_string(value).unwrap_or_else(|_| String::from("null"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_case_parses_non_string_expected_output() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"resolv/dns",
                "captured_at":"2026-02-13T00:00:00Z",
                "cases":[
                    {
                        "name":"typed_expected",
                        "function":"ResolverConfig::default",
                        "spec_section":"resolver(5)",
                        "inputs":{},
                        "expected_output":{"attempts":2,"nameservers":["127.0.0.1"]},
                        "mode":"strict"
                    }
                ]
            }"#,
        )
        .expect("fixture should deserialize");

        assert_eq!(
            fixture.cases[0].expected_output,
            r#"{"attempts":2,"nameservers":["127.0.0.1"]}"#
        );
    }

    #[test]
    fn fixture_case_defaults_missing_errno_to_zero() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"elf/loader",
                "captured_at":"2026-02-13T00:00:00Z",
                "cases":[
                    {
                        "name":"missing_errno",
                        "function":"Elf64Header::parse",
                        "spec_section":"ELF64 Header",
                        "inputs":{"magic":[127,69,76,70]},
                        "expected_output":"Ok",
                        "mode":"strict"
                    }
                ]
            }"#,
        )
        .expect("fixture should deserialize");

        assert_eq!(fixture.cases[0].expected_errno, 0);
    }

    #[test]
    fn fixture_case_explicit_errno() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"errno/ops",
                "captured_at":"2026-02-13T00:00:00Z",
                "cases":[
                    {
                        "name":"einval",
                        "function":"strtol",
                        "spec_section":"POSIX.1 strtol",
                        "inputs":{"str":"abc","base":10},
                        "expected_output":"0",
                        "expected_errno":22,
                        "mode":"strict"
                    }
                ]
            }"#,
        )
        .expect("fixture should deserialize");

        assert_eq!(fixture.cases[0].expected_errno, 22);
    }

    #[test]
    fn fixture_expected_output_null_normalizes_to_string() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"misc",
                "captured_at":"2026-02-13T00:00:00Z",
                "cases":[
                    {
                        "name":"null_output",
                        "function":"test",
                        "spec_section":"test",
                        "inputs":{},
                        "expected_output":null,
                        "mode":"strict"
                    }
                ]
            }"#,
        )
        .expect("fixture should deserialize");

        assert_eq!(fixture.cases[0].expected_output, "null");
    }

    #[test]
    fn fixture_expected_output_integer_normalizes() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"math/ops",
                "captured_at":"2026-02-13T00:00:00Z",
                "cases":[
                    {
                        "name":"int_result",
                        "function":"abs",
                        "spec_section":"POSIX.1 abs",
                        "inputs":{"x":-5},
                        "expected_output":5,
                        "mode":"strict"
                    }
                ]
            }"#,
        )
        .expect("fixture should deserialize");

        assert_eq!(fixture.cases[0].expected_output, "5");
    }

    #[test]
    fn fixture_expected_output_boolean_normalizes() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"misc",
                "captured_at":"2026-02-13T00:00:00Z",
                "cases":[
                    {
                        "name":"bool_result",
                        "function":"test",
                        "spec_section":"test",
                        "inputs":{},
                        "expected_output":true,
                        "mode":"strict"
                    }
                ]
            }"#,
        )
        .expect("fixture should deserialize");

        assert_eq!(fixture.cases[0].expected_output, "true");
    }

    #[test]
    fn fixture_expected_output_array_normalizes() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"string/ops",
                "captured_at":"2026-02-13T00:00:00Z",
                "cases":[
                    {
                        "name":"array_result",
                        "function":"memcpy",
                        "spec_section":"POSIX.1 memcpy",
                        "inputs":{},
                        "expected_output":[65,66,67],
                        "mode":"strict"
                    }
                ]
            }"#,
        )
        .expect("fixture should deserialize");

        assert_eq!(fixture.cases[0].expected_output, "[65,66,67]");
    }

    #[test]
    fn fixture_set_metadata() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"string/strlen",
                "captured_at":"2026-02-08T00:00:00Z",
                "cases":[]
            }"#,
        )
        .expect("fixture should deserialize");

        assert_eq!(fixture.version, "v1");
        assert_eq!(fixture.family, "string/strlen");
        assert_eq!(fixture.captured_at, "2026-02-08T00:00:00Z");
        assert!(fixture.cases.is_empty());
    }

    #[test]
    fn fixture_multiple_cases() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"string/ops",
                "captured_at":"2026-02-08T00:00:00Z",
                "cases":[
                    {"name":"a","function":"strlen","spec_section":"POSIX","inputs":{},"expected_output":"5","mode":"strict"},
                    {"name":"b","function":"strcmp","spec_section":"POSIX","inputs":{},"expected_output":"0","mode":"hardened"},
                    {"name":"c","function":"strcat","spec_section":"POSIX","inputs":{},"expected_output":"ab","mode":"both"}
                ]
            }"#,
        )
        .expect("fixture should deserialize");

        assert_eq!(fixture.cases.len(), 3);
        assert_eq!(fixture.cases[0].mode, "strict");
        assert_eq!(fixture.cases[1].mode, "hardened");
        assert_eq!(fixture.cases[2].mode, "both");
    }

    #[test]
    fn fixture_roundtrip_serialization() {
        let original = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"test",
                "captured_at":"2026-01-01T00:00:00Z",
                "cases":[
                    {"name":"rt","function":"test","spec_section":"test","inputs":{"x":1},"expected_output":"ok","expected_errno":0,"mode":"strict"}
                ]
            }"#,
        )
        .expect("fixture should deserialize");

        let json = original.to_json().unwrap();
        let restored = FixtureSet::from_json(&json).unwrap();
        assert_eq!(restored.version, original.version);
        assert_eq!(restored.family, original.family);
        assert_eq!(restored.cases.len(), 1);
        assert_eq!(restored.cases[0].name, "rt");
        assert_eq!(restored.cases[0].expected_output, "ok");
    }

    #[test]
    fn fixture_invalid_json_returns_error() {
        let result = FixtureSet::from_json("not json");
        assert!(result.is_err());
    }

    #[test]
    fn fixture_missing_required_field_returns_error() {
        let result = FixtureSet::from_json(
            r#"{"version":"v1","family":"test"}"#, // missing captured_at and cases
        );
        assert!(result.is_err());
    }

    #[test]
    fn normalize_expected_output_string() {
        let v = serde_json::json!("hello");
        assert_eq!(normalize_expected_output_value(&v), "hello");
    }

    #[test]
    fn normalize_expected_output_object() {
        let v = serde_json::json!({"key": "val"});
        assert_eq!(normalize_expected_output_value(&v), r#"{"key":"val"}"#);
    }

    #[test]
    fn normalize_expected_output_float() {
        let v = serde_json::json!(3.14);
        assert_eq!(normalize_expected_output_value(&v), "3.14");
    }
}
