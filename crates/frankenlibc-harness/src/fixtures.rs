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
}
