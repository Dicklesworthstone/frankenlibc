//! Host glibc fixture capture.
//!
//! Runs test vectors against the host glibc and serializes
//! inputs/outputs as JSON fixtures for later verification.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::fixtures::{CaptureHost, FixtureSet};
use frankenlibc_fixture_exec::execute_fixture_case;
use serde::{Deserialize, Serialize};

/// Optional UTC timestamp override for reproducible fixture capture runs.
pub const CAPTURE_TIMESTAMP_ENV: &str = "FRANKENLIBC_CAPTURE_TIMESTAMP_UTC";

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct CaptureMetadata {
    captured_at: String,
    capture_host: CaptureHost,
}

/// Refresh fixture cases for a given family filter by re-running strict host capture.
///
/// The filter matches either the fixture `family` field or the JSON filename stem,
/// case-insensitively. Use `"all"` to capture every fixture set in `template_dir`.
pub fn capture_family_fixtures(
    template_dir: &Path,
    family_filter: &str,
) -> Result<Vec<CapturedFixtureSet>, String> {
    let metadata = detect_capture_metadata()?;
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

        let (fixture_set, stats) = recapture_fixture_set(&fixture_set, &metadata);
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

fn detect_capture_metadata() -> Result<CaptureMetadata, String> {
    Ok(CaptureMetadata {
        captured_at: capture_timestamp_utc()?,
        capture_host: detect_capture_host(),
    })
}

/// Detect the stable host identity used as the strict-mode glibc oracle.
pub fn detect_capture_host() -> CaptureHost {
    let kernel = detect_kernel_release();
    let glibc_version = detect_glibc_version();
    let arch = std::env::consts::ARCH.to_string();
    let fingerprint = format!("kernel={kernel};glibc={glibc_version};arch={arch}");
    CaptureHost {
        kernel,
        glibc_version,
        arch,
        fingerprint,
    }
}

/// Return the capture timestamp in UTC, honoring [`CAPTURE_TIMESTAMP_ENV`].
pub fn capture_timestamp_utc() -> Result<String, String> {
    if let Ok(value) = std::env::var(CAPTURE_TIMESTAMP_ENV) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            validate_capture_timestamp_utc(trimmed)?;
            return Ok(trimmed.to_string());
        }
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system clock is before UNIX_EPOCH: {err}"))?;
    Ok(format_utc_from_unix_seconds(now.as_secs()))
}

fn validate_capture_timestamp_utc(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    let valid_shape = bytes.len() == 20
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':')
        && bytes.get(19) == Some(&b'Z')
        && bytes
            .iter()
            .enumerate()
            .all(|(idx, byte)| matches!(idx, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit());
    if valid_shape {
        Ok(())
    } else {
        Err(format!(
            "{CAPTURE_TIMESTAMP_ENV} must use YYYY-MM-DDTHH:MM:SSZ, got {value:?}"
        ))
    }
}

fn format_utc_from_unix_seconds(seconds: u64) -> String {
    let days = seconds / 86_400;
    let seconds_of_day = seconds % 86_400;
    let days_i64 = i64::try_from(days).unwrap_or(i64::MAX);
    let (year, month, day) = civil_from_days(days_i64);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    let month: u32 = u32::try_from(month).unwrap_or_default();
    let day: u32 = u32::try_from(day).unwrap_or_default();
    (year, month, day)
}

fn detect_kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| String::from("unknown"))
}

fn detect_glibc_version() -> String {
    match std::process::Command::new("ldd").arg("--version").output() {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout
                .lines()
                .find(|line| !line.trim().is_empty())
                .map(parse_glibc_version_line)
                .unwrap_or_else(|| String::from("unknown"))
        }
        _ => String::from("unknown"),
    }
}

fn parse_glibc_version_line(line: &str) -> String {
    let trimmed = line.trim();
    trimmed
        .split_whitespace()
        .last()
        .filter(|token| token.chars().any(|c| c.is_ascii_digit()))
        .unwrap_or(trimmed)
        .to_string()
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

fn recapture_fixture_set(
    source: &FixtureSet,
    metadata: &CaptureMetadata,
) -> (FixtureSet, CaptureStats) {
    let mut stats = CaptureStats {
        total_cases: source.cases.len(),
        ..CaptureStats::default()
    };

    let mut refreshed = source.clone();
    refreshed.captured_at = metadata.captured_at.clone();
    refreshed.capture_host = Some(metadata.capture_host.clone());
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

    fn test_metadata() -> CaptureMetadata {
        CaptureMetadata {
            captured_at: "2026-05-21T08:45:30Z".to_string(),
            capture_host: CaptureHost {
                kernel: "6.8.0-test".to_string(),
                glibc_version: "2.39".to_string(),
                arch: "x86_64".to_string(),
                fingerprint: "kernel=6.8.0-test;glibc=2.39;arch=x86_64".to_string(),
            },
        }
    }

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
        let metadata = test_metadata();
        let (recaptured, stats) = recapture_fixture_set(&fixture, &metadata);

        assert_eq!(stats.total_cases, 1);
        assert_eq!(stats.refreshed_cases, 1);
        assert_eq!(stats.skipped_cases, 0);
        assert_eq!(recaptured.cases[0].expected_output, "[65, 66, 67, 68]");
        assert_eq!(recaptured.captured_at, metadata.captured_at);
        assert_eq!(recaptured.capture_host, Some(metadata.capture_host));
        Ok(())
    }

    #[test]
    fn hardened_case_is_left_untouched() -> Result<(), serde_json::Error> {
        let fixture = fixture_set_from_case("hardened", "memcpy", "keep_me")?;
        let (recaptured, stats) = recapture_fixture_set(&fixture, &test_metadata());

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

        let (recaptured, stats) = recapture_fixture_set(&fixture, &test_metadata());

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

    #[test]
    fn glibc_version_parser_prefers_last_numeric_token() {
        assert_eq!(
            parse_glibc_version_line("ldd (Debian GLIBC 2.36-9+deb12u10) 2.36"),
            "2.36"
        );
        assert_eq!(parse_glibc_version_line("musl libc"), "musl libc");
    }

    #[test]
    fn unix_timestamp_formatter_emits_utc_iso8601() {
        assert_eq!(format_utc_from_unix_seconds(0), "1970-01-01T00:00:00Z");
        assert_eq!(
            format_utc_from_unix_seconds(1_748_592_330),
            "2025-05-30T08:05:30Z"
        );
    }

    #[test]
    fn capture_timestamp_validator_requires_utc_shape() {
        assert!(validate_capture_timestamp_utc("2026-05-21T08:45:30Z").is_ok());
        assert!(validate_capture_timestamp_utc("2026-05-21 08:45:30").is_err());
    }
}
