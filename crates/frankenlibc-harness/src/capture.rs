//! Host glibc fixture capture.
//!
//! Runs test vectors against the host glibc and serializes
//! inputs/outputs as JSON fixtures for later verification.

use std::path::Path;

use crate::fixtures::FixtureSet;
use frankenlibc_fixture_exec::execute_fixture_case;
use serde::{Deserialize, Serialize};

/// A captured operation with its input/output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedOperation {
    /// Function name (e.g., "memcpy", "strlen").
    pub function: String,
    /// Input parameters as serialized values.
    pub inputs: serde_json::Value,
    /// Expected output from host glibc.
    pub output: serde_json::Value,
    /// errno value after the call (0 if none).
    pub errno_after: i32,
}

/// Capture a set of operations against host glibc.
///
/// Returns serialized fixture data suitable for writing to JSON.
pub fn capture_operations(ops: &[CapturedOperation]) -> String {
    serde_json::to_string_pretty(ops).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}

/// Capture summary for one fixture set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaptureStats {
    /// Number of cases seen in the source fixture set.
    pub total_cases: usize,
    /// Number of strict/both cases refreshed with host output.
    pub refreshed_cases: usize,
    /// Number of strict/both cases skipped due to unsupported host capture.
    pub skipped_cases: usize,
    /// Human-readable capture warnings.
    pub warnings: Vec<String>,
}

/// Captured fixture artifact written by the capture command.
#[derive(Debug, Clone)]
pub struct CapturedFixtureSet {
    /// Output file name (for example `string_ops.json`).
    pub file_name: String,
    /// Refreshed fixture set.
    pub fixture_set: FixtureSet,
    /// Capture summary stats.
    pub stats: CaptureStats,
}

/// Refresh fixture cases for a given family filter by re-running strict host capture.
///
/// The filter matches either the fixture `family` field or the JSON filename stem,
/// case-insensitively. Use `"all"` to capture every fixture set in `template_dir`.
pub fn capture_family_fixtures(
    template_dir: &Path,
    family_filter: &str,
) -> Result<Vec<CapturedFixtureSet>, String> {
    let mut captured = Vec::new();
    let mut entries = std::fs::read_dir(template_dir)
        .map_err(|err| format!("failed reading {}: {err}", template_dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    entries.sort();

    for path in entries {
        let Some(file_name) = path
            .file_name()
            .and_then(|value| value.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        let file_stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or_default();

        let fixture_set = match FixtureSet::from_file(&path) {
            Ok(fixture_set) => fixture_set,
            Err(_) => continue,
        };

        if !matches_family_filter(&fixture_set.family, file_stem, family_filter) {
            continue;
        }

        let (fixture_set, stats) = recapture_fixture_set(&fixture_set);
        captured.push(CapturedFixtureSet {
            file_name,
            fixture_set,
            stats,
        });
    }

    if captured.is_empty() {
        return Err(format!(
            "no fixture templates matching family='{family_filter}' under {}",
            template_dir.display()
        ));
    }

    Ok(captured)
}

fn matches_family_filter(family: &str, file_stem: &str, family_filter: &str) -> bool {
    let filter = family_filter.to_ascii_lowercase();
    if filter == "all" {
        return true;
    }

    let family_l = family.to_ascii_lowercase();
    let file_l = file_stem.to_ascii_lowercase();
    family_l.contains(&filter) || file_l.contains(&filter)
}

fn recapture_fixture_set(source: &FixtureSet) -> (FixtureSet, CaptureStats) {
    let mut stats = CaptureStats {
        total_cases: source.cases.len(),
        ..CaptureStats::default()
    };

    let mut refreshed = source.clone();
    for case in &mut refreshed.cases {
        if !case.mode.eq_ignore_ascii_case("strict") && !case.mode.eq_ignore_ascii_case("both") {
            continue;
        }

        match execute_fixture_case(&case.function, &case.inputs, "strict") {
            Ok(run) if run.host_output != "SKIP" => {
                case.expected_output = run.host_output;
                stats.refreshed_cases += 1;
            }
            Ok(run) => {
                stats.skipped_cases += 1;
                stats.warnings.push(format!(
                    "{}:{} host capture skipped ({})",
                    source.family, case.name, run.host_output
                ));
            }
            Err(err) => {
                stats.skipped_cases += 1;
                stats.warnings.push(format!(
                    "{}:{} capture error: {}",
                    source.family, case.name, err
                ));
            }
        }
    }

    (refreshed, stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_set_from_case(
        mode: &str,
        function: &str,
        expected_output: &str,
    ) -> Result<FixtureSet, serde_json::Error> {
        FixtureSet::from_json(&format!(
            r#"{{
                "version":"v1",
                "family":"string/narrow",
                "captured_at":"2026-02-13T00:00:00Z",
                "cases":[
                    {{
                        "name":"sample",
                        "function":"{function}",
                        "spec_section":"POSIX sample",
                        "inputs":{{"src":[65,66,67,68],"dst_len":4,"n":4}},
                        "expected_output":"{expected_output}",
                        "expected_errno":0,
                        "mode":"{mode}"
                    }}
                ]
            }}"#
        ))
    }

    #[test]
    fn strict_case_is_refreshed_from_host_output() -> Result<(), serde_json::Error> {
        let fixture = fixture_set_from_case("strict", "memcpy", "stale")?;
        let (recaptured, stats) = recapture_fixture_set(&fixture);

        assert_eq!(stats.total_cases, 1);
        assert_eq!(stats.refreshed_cases, 1);
        assert_eq!(stats.skipped_cases, 0);
        assert_eq!(recaptured.cases[0].expected_output, "[65, 66, 67, 68]");
        Ok(())
    }

    #[test]
    fn hardened_case_is_left_untouched() -> Result<(), serde_json::Error> {
        let fixture = fixture_set_from_case("hardened", "memcpy", "keep_me")?;
        let (recaptured, stats) = recapture_fixture_set(&fixture);

        assert_eq!(stats.total_cases, 1);
        assert_eq!(stats.refreshed_cases, 0);
        assert_eq!(stats.skipped_cases, 0);
        assert_eq!(recaptured.cases[0].expected_output, "keep_me");
        Ok(())
    }

    #[test]
    fn strict_unsupported_case_adds_warning_and_keeps_expected_output()
    -> Result<(), serde_json::Error> {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"string/narrow",
                "captured_at":"2026-02-13T00:00:00Z",
                "cases":[
                    {
                        "name":"unsupported",
                        "function":"unsupported_function",
                        "spec_section":"POSIX sample",
                        "inputs":{},
                        "expected_output":"unchanged",
                        "expected_errno":0,
                        "mode":"strict"
                    }
                ]
            }"#,
        )?;

        let (recaptured, stats) = recapture_fixture_set(&fixture);

        assert_eq!(stats.refreshed_cases, 0);
        assert_eq!(stats.skipped_cases, 1);
        assert_eq!(recaptured.cases[0].expected_output, "unchanged");
        assert_eq!(stats.warnings.len(), 1);
        Ok(())
    }

    #[test]
    fn family_filter_matches_family_or_filename() {
        assert!(matches_family_filter(
            "string/narrow",
            "string_ops",
            "string"
        ));
        assert!(matches_family_filter("memory_ops", "memory_ops", "memory"));
        assert!(matches_family_filter(
            "stdio_file_ops",
            "stdio_file_ops",
            "all"
        ));
        assert!(!matches_family_filter("allocator", "allocator", "pthread"));
    }
}
