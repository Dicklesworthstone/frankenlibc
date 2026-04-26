//! Fixture loading and management.

use serde::de::Deserializer;
use serde::{Deserialize, Serialize};

/// A single fixture test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "RawFixtureCase")]
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

#[derive(Debug, Clone, Deserialize)]
struct RawFixtureCase {
    name: String,
    function: String,
    spec_section: String,
    inputs: serde_json::Value,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    expected_output: Option<serde_json::Value>,
    #[serde(default)]
    expected_output_bytes: Option<serde_json::Value>,
    #[serde(default)]
    expected_output_pattern: Option<serde_json::Value>,
    #[serde(default)]
    expected_return: Option<serde_json::Value>,
    #[serde(default)]
    expected_values: Option<serde_json::Value>,
    #[serde(default)]
    expected_n_value: Option<serde_json::Value>,
    #[serde(default)]
    expected_errno: i32,
    mode: String,
}

fn deserialize_present_value<'de, D>(deserializer: D) -> Result<Option<serde_json::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    serde_json::Value::deserialize(deserializer).map(Some)
}

impl TryFrom<RawFixtureCase> for FixtureCase {
    type Error = String;

    fn try_from(raw: RawFixtureCase) -> Result<Self, Self::Error> {
        let expected_output = expected_output_from_raw_case(&raw).ok_or_else(|| {
            format!(
                "fixture case {} is missing an expected output contract",
                raw.name
            )
        })?;

        Ok(Self {
            name: raw.name,
            function: raw.function,
            spec_section: raw.spec_section,
            inputs: raw.inputs,
            expected_output,
            expected_errno: raw.expected_errno,
            mode: raw.mode,
        })
    }
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
        match serde_json::from_str(json) {
            Ok(set) => Ok(set),
            Err(primary_err) => {
                let value: serde_json::Value = serde_json::from_str(json)?;
                StructuredFixtureSet::try_from_value(&value)
                    .ok_or(primary_err)
                    .map(StructuredFixtureSet::into_fixture_set)
            }
        }
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

#[derive(Debug, Clone, Deserialize)]
struct StructuredProgramScenario {
    scenario_id: String,
    source: String,
    #[serde(default)]
    expected: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
struct StructuredUnsupportedScenario {
    scenario_id: String,
    #[serde(default)]
    expected_outcome: String,
    #[serde(default)]
    expected_errno: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
struct StructuredFixtureSet {
    #[serde(default)]
    version: String,
    #[serde(default)]
    schema_version: String,
    family: String,
    captured_at: String,
    #[serde(default)]
    program_scenarios: Vec<StructuredProgramScenario>,
    #[serde(default)]
    unsupported_scenarios: Vec<StructuredUnsupportedScenario>,
}

impl StructuredFixtureSet {
    fn try_from_value(value: &serde_json::Value) -> Option<Self> {
        value.get("family")?;
        if value.get("program_scenarios").is_none() && value.get("unsupported_scenarios").is_none()
        {
            return None;
        }
        serde_json::from_value(value.clone()).ok()
    }

    fn into_fixture_set(self) -> FixtureSet {
        let version = if self.version.is_empty() {
            self.schema_version
        } else {
            self.version
        };

        let mut cases = Vec::new();

        for scenario in self.program_scenarios {
            cases.push(FixtureCase {
                name: scenario.scenario_id,
                function: self.family.clone(),
                spec_section: scenario.source,
                inputs: serde_json::json!({
                    "scenario_kind": "program",
                    "expected": scenario.expected,
                }),
                expected_output: String::from("structured_program_scenario"),
                expected_errno: 0,
                mode: String::from("both"),
            });
        }

        for scenario in self.unsupported_scenarios {
            cases.push(FixtureCase {
                name: scenario.scenario_id,
                function: self.family.clone(),
                spec_section: String::from("unsupported_deferred"),
                inputs: serde_json::json!({
                    "scenario_kind": "unsupported",
                    "expected_outcome": scenario.expected_outcome,
                    "expected_errno": scenario.expected_errno,
                }),
                expected_output: normalize_expected_output_value(&scenario.expected_errno),
                expected_errno: 0,
                mode: String::from("both"),
            });
        }

        FixtureSet {
            version,
            family: self.family,
            captured_at: self.captured_at,
            cases,
        }
    }
}

pub(crate) fn normalize_expected_output_value(value: &serde_json::Value) -> String {
    if let Some(text) = value.as_str() {
        return text.to_string();
    }
    serde_json::to_string(value).unwrap_or_else(|_| String::from("null"))
}

fn expected_output_from_raw_case(raw: &RawFixtureCase) -> Option<String> {
    if let Some(value) = &raw.expected_output {
        return Some(normalize_expected_output_value(value));
    }

    if let (Some(expected_return), Some(expected_values)) =
        (&raw.expected_return, &raw.expected_values)
    {
        return Some(format_return_and_values(expected_return, expected_values));
    }

    if let Some(value) = &raw.expected_output_bytes {
        return Some(normalize_expected_output_value(value));
    }

    if let Some(value) = &raw.expected_output_pattern {
        return Some(normalize_expected_output_value(value));
    }

    if let Some(value) = &raw.expected_return {
        if raw.function == "snprintf"
            && raw.inputs.get("size").and_then(serde_json::Value::as_u64) == Some(0)
        {
            return Some(String::new());
        }
        return Some(normalize_expected_output_value(value));
    }

    raw.expected_n_value
        .as_ref()
        .map(normalize_expected_output_value)
}

fn format_return_and_values(
    expected_return: &serde_json::Value,
    expected_values: &serde_json::Value,
) -> String {
    let values = expected_values
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(format_sequence_expected_value)
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_else(|| normalize_expected_output_value(expected_values));

    format!(
        "{}:[{}]",
        normalize_expected_output_value(expected_return),
        values
    )
}

fn format_sequence_expected_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => format!("\"{text}\""),
        serde_json::Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                integer.to_string()
            } else if let Some(integer) = number.as_u64() {
                integer.to_string()
            } else if let Some(float) = number.as_f64() {
                format_float_expected_value(float)
            } else {
                number.to_string()
            }
        }
        _ => normalize_expected_output_value(value),
    }
}

fn format_float_expected_value(float: f64) -> String {
    let rounded = (float * 1e6).round() / 1e6;
    if rounded == 0.0 {
        return "0".to_string();
    }

    let abs = rounded.abs();
    let text = if !(1e-4..1e9).contains(&abs) {
        format!("{rounded:e}")
    } else {
        format!("{rounded}")
    };
    trim_float_decimal_zeros(&text)
}

fn trim_float_decimal_zeros(text: &str) -> String {
    let (mantissa, exponent) = text
        .split_once('e')
        .or_else(|| text.split_once('E'))
        .map_or((text, ""), |(head, tail)| (head, tail));
    let trimmed = if mantissa.contains('.') {
        mantissa.trim_end_matches('0').trim_end_matches('.')
    } else {
        mantissa
    };
    if exponent.is_empty() {
        trimmed.to_string()
    } else {
        format!("{trimmed}e{exponent}")
    }
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
    fn structured_fixture_set_preserves_unsupported_expected_errno_in_inputs() {
        let fixture = FixtureSet::from_json(
            r#"{
                "schema_version":"structured-v1",
                "family":"setjmp_nested_edges",
                "captured_at":"2026-04-25T00:00:00Z",
                "program_scenarios":[
                    {
                        "scenario_id":"nested_two_level_longjmp",
                        "source":"tests/integration/fixture_setjmp_nested.c",
                        "expected":{"strict":{"exit_code":0},"hardened":{"exit_code":0}}
                    }
                ],
                "unsupported_scenarios":[
                    {
                        "scenario_id":"cross_thread_longjmp",
                        "expected_outcome":"unsupported_deferred",
                        "expected_errno":"ENOSYS"
                    }
                ]
            }"#,
        )
        .expect("structured fixture should deserialize");

        assert_eq!(fixture.version, "structured-v1");
        assert_eq!(fixture.cases.len(), 2);
        assert_eq!(
            fixture.cases[0].expected_output,
            "structured_program_scenario"
        );
        assert_eq!(fixture.cases[1].expected_output, "ENOSYS");
        assert_eq!(
            fixture.cases[1].inputs.get("expected_errno"),
            Some(&serde_json::json!("ENOSYS"))
        );
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
    fn fixture_case_accepts_expected_return_and_values_contract() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"scanf_conformance",
                "captured_at":"2026-04-14T00:00:00Z",
                "cases":[
                    {
                        "name":"sscanf_pair",
                        "function":"sscanf",
                        "spec_section":"C11 7.21.6.2",
                        "inputs":{"input":"42 ok","format":"%d %s"},
                        "expected_return":2,
                        "expected_values":[42,"ok"],
                        "mode":"strict"
                    }
                ]
            }"#,
        )
        .expect("fixture should deserialize");

        assert_eq!(fixture.cases[0].expected_output, "2:[42,\"ok\"]");
    }

    #[test]
    fn fixture_return_values_preserve_float_exponents() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"scanf_conformance",
                "captured_at":"2026-04-14T00:00:00Z",
                "cases":[
                    {
                        "name":"sscanf_float_exp",
                        "function":"sscanf",
                        "spec_section":"C11 7.21.6.2",
                        "inputs":{"input":"1.5e10","format":"%f"},
                        "expected_return":1,
                        "expected_values":[1.5e10],
                        "mode":"strict"
                    }
                ]
            }"#,
        )
        .expect("fixture should deserialize");

        assert_eq!(fixture.cases[0].expected_output, "1:[1.5e10]");
    }

    #[test]
    fn fixture_case_accepts_expected_return_only_contract() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"errno_ops",
                "captured_at":"2026-04-15T00:50:00Z",
                "cases":[
                    {
                        "name":"strerror_r_null_buffer",
                        "function":"strerror_r",
                        "spec_section":"POSIX.1 strerror_r",
                        "inputs":{"errnum":22,"buf":null},
                        "expected_return":22,
                        "mode":"strict"
                    }
                ]
            }"#,
        )
        .expect("fixture should deserialize");

        assert_eq!(fixture.cases[0].expected_output, "22");
    }

    #[test]
    fn fixture_case_accepts_expected_bytes_contract() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"printf_conformance",
                "captured_at":"2026-04-14T00:00:00Z",
                "cases":[
                    {
                        "name":"sprintf_c_nul",
                        "function":"sprintf",
                        "spec_section":"C11 7.21.6.1",
                        "inputs":{"format":"a%cb","args":[0]},
                        "expected_output_bytes":[97,0,98],
                        "mode":"strict"
                    }
                ]
            }"#,
        )
        .expect("fixture should deserialize");

        assert_eq!(fixture.cases[0].expected_output, "[97,0,98]");
    }

    #[test]
    fn fixture_case_accepts_expected_pattern_contract() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"printf_conformance",
                "captured_at":"2026-04-14T00:00:00Z",
                "cases":[
                    {
                        "name":"sprintf_p_basic",
                        "function":"sprintf",
                        "spec_section":"C11 7.21.6.1",
                        "inputs":{"format":"%p","args":["0x12345678"]},
                        "expected_output_pattern":"^0x[0-9a-f]+$",
                        "mode":"strict"
                    }
                ]
            }"#,
        )
        .expect("fixture should deserialize");

        assert_eq!(fixture.cases[0].expected_output, "^0x[0-9a-f]+$");
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
        let v = serde_json::json!(2.5);
        assert_eq!(normalize_expected_output_value(&v), "2.5");
    }
}
