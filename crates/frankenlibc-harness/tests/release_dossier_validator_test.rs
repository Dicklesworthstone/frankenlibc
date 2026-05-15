// release_dossier_validator_test.rs — bd-5fw.3
// Verifies that the release dossier validator runs, produces a valid report,
// and enforces integrity checking with SHA256 checksums.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct TestFailure(String);

impl fmt::Display for TestFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TestFailure {}

fn test_failure(message: impl Into<String>) -> TestFailure {
    TestFailure(message.into())
}

fn value_object<'a>(
    value: &'a serde_json::Value,
    name: &str,
) -> TestResult<&'a serde_json::Map<String, serde_json::Value>> {
    value
        .as_object()
        .ok_or_else(|| test_failure(format!("{name} must be an object")).into())
}

fn value_array<'a>(
    value: &'a serde_json::Value,
    name: &str,
) -> TestResult<&'a Vec<serde_json::Value>> {
    value
        .as_array()
        .ok_or_else(|| test_failure(format!("{name} must be an array")).into())
}

fn value_str<'a>(value: &'a serde_json::Value, name: &str) -> TestResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| test_failure(format!("{name} must be a string")).into())
}

fn value_u64(value: &serde_json::Value, name: &str) -> TestResult<u64> {
    value
        .as_u64()
        .ok_or_else(|| test_failure(format!("{name} must be an unsigned integer")).into())
}

fn repo_root() -> TestResult<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crate_dir = manifest_dir
        .parent()
        .ok_or_else(|| test_failure("manifest dir must have a crate parent"))?;
    let repo_root = crate_dir
        .parent()
        .ok_or_else(|| test_failure("crate dir must have a repo parent"))?;
    Ok(repo_root.to_path_buf())
}

fn unique_temp_path(prefix: &str, suffix: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| test_failure(format!("system clock drifted before unix epoch: {e}")))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("{prefix}-{}-{nanos}{suffix}", std::process::id())))
}

fn parse_validator_report(
    stdout: &str,
    stderr: &str,
    context: &str,
) -> TestResult<serde_json::Value> {
    let report = serde_json::from_str(stdout).map_err(|e| {
        Box::new(test_failure(format!(
            "{context}: {e}\nstdout: {stdout}\nstderr: {stderr}"
        ))) as Box<dyn std::error::Error>
    })?;
    Ok(report)
}

fn read_json_file(path: &Path) -> TestResult<serde_json::Value> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

#[test]
fn dossier_validator_produces_valid_report() -> TestResult {
    let repo_root = repo_root()?;

    let script = repo_root.join("scripts/release_dossier_validator.py");
    assert!(
        script.exists(),
        "release_dossier_validator.py not found at {:?}",
        script
    );

    let output = Command::new("python3")
        .arg(&script)
        .current_dir(&repo_root)
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let report = parse_validator_report(
        &stdout,
        &stderr,
        "failed to parse release dossier validator report",
    )?;
    assert!(
        output.status.success(),
        "release_dossier_validator.py should succeed for the checked-in repo state\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    // Required report fields
    let required_keys = [
        "schema_version",
        "bead",
        "status",
        "verdict",
        "summary",
        "artifact_results",
        "integrity_index",
        "findings",
        "compatibility_policy",
        "dossier_manifest_version",
        "release_notes_hook",
    ];
    for key in required_keys {
        assert!(
            report.get(key).is_some(),
            "Report missing required key: {key}"
        );
    }

    // Summary fields
    let summary = &report["summary"];
    assert!(summary["total_artifacts"].as_u64().unwrap_or(0) > 0);
    assert!(summary["valid"].as_u64().is_some());
    assert!(summary["missing"].as_u64().is_some());
    assert!(summary["critical_missing"].as_u64().is_some());
    assert!(summary["errors"].as_u64().is_some());
    assert!(summary["warnings"].as_u64().is_some());
    assert!(summary["release_note_candidates"].as_u64().is_some());
    assert_eq!(
        report["status"].as_str(),
        Some("pass"),
        "checked-in repo state should produce a passing release dossier"
    );
    assert_eq!(
        report["verdict"].as_str(),
        Some("PASS"),
        "checked-in repo state should produce a PASS dossier verdict"
    );
    assert_eq!(
        summary["errors"].as_u64(),
        Some(0),
        "checked-in repo state should not emit dossier validation errors"
    );
    assert_eq!(
        summary["critical_missing"].as_u64(),
        Some(0),
        "checked-in repo state should not have critical dossier gaps"
    );

    let release_notes_hook = value_object(&report["release_notes_hook"], "release_notes_hook")?;
    assert!(
        release_notes_hook.contains_key("source_path"),
        "release_notes_hook missing source_path"
    );
    assert!(
        release_notes_hook.contains_key("entries"),
        "release_notes_hook missing entries"
    );
    assert!(
        release_notes_hook.contains_key("release_notes_markdown"),
        "release_notes_hook missing release_notes_markdown"
    );

    // Verdict must be a known value
    let verdict = value_str(&report["verdict"], "verdict")?;
    assert!(
        ["PASS", "FAIL", "FAIL_CRITICAL"].contains(&verdict),
        "Unknown verdict: {verdict}"
    );

    let reality_report = report["artifact_results"]
        .as_array()
        .and_then(|results| {
            results
                .iter()
                .find(|entry| entry["id"].as_str() == Some("reality_report"))
        })
        .ok_or_else(|| test_failure("dossier should contain a reality_report artifact result"))?;
    assert_eq!(
        reality_report["status"].as_str(),
        Some("VALID"),
        "reality_report artifact should validate cleanly"
    );
    assert_eq!(
        reality_report["schema_valid"].as_bool(),
        Some(true),
        "reality_report artifact should satisfy schema validation"
    );
    Ok(())
}

#[test]
fn dossier_artifact_results_have_required_fields() -> TestResult {
    let repo_root = repo_root()?;

    let report_path = repo_root.join("tests/release/dossier_validation_report.v1.json");
    assert!(
        report_path.exists(),
        "Dossier report artifact not found at {:?}",
        report_path
    );

    let report = read_json_file(&report_path)?;

    let results = value_array(&report["artifact_results"], "artifact_results")?;
    assert!(!results.is_empty(), "artifact_results must be non-empty");

    for r in results {
        assert!(r["id"].as_str().is_some(), "result missing id");
        assert!(r["path"].as_str().is_some(), "result missing path");
        assert!(r["kind"].as_str().is_some(), "result missing kind");
        assert!(r["required"].is_boolean(), "result missing required");
        assert!(r["critical"].is_boolean(), "result missing critical");

        let st = value_str(&r["status"], "artifact status")?;
        assert!(
            ["VALID", "PRESENT", "MISSING"].contains(&st),
            "Unknown artifact status: {st}"
        );

        // Valid/present artifacts must have SHA256
        if st != "MISSING" {
            assert!(
                r["sha256"].as_str().is_some(),
                "Present artifact {} missing sha256",
                r["id"]
            );
            let sha = value_str(&r["sha256"], "artifact sha256")?;
            assert_eq!(sha.len(), 64, "SHA256 must be 64 hex chars for {}", r["id"]);
        }
    }
    Ok(())
}

#[test]
fn dossier_integrity_index_consistent() -> TestResult {
    let repo_root = repo_root()?;

    let report_path = repo_root.join("tests/release/dossier_validation_report.v1.json");
    let report = read_json_file(&report_path)?;

    let index = value_object(&report["integrity_index"], "integrity_index")?;
    let results = value_array(&report["artifact_results"], "artifact_results")?;

    // Every non-missing artifact must be in the integrity index
    for r in results {
        if r["status"].as_str() != Some("MISSING") {
            let id = value_str(&r["id"], "artifact id")?;
            assert!(
                index.contains_key(id),
                "Artifact '{id}' is present but missing from integrity_index"
            );

            // Checksums must match
            let idx_entry = &index[id];
            assert_eq!(
                r["sha256"].as_str(),
                idx_entry["sha256"].as_str(),
                "SHA256 mismatch for {id} between artifact_results and integrity_index"
            );
        }
    }

    // No critical missing
    assert_eq!(
        value_u64(&report["summary"]["critical_missing"], "critical_missing")?,
        0,
        "No critical artifacts should be missing"
    );
    Ok(())
}

#[test]
fn dossier_compatibility_policy_present() -> TestResult {
    let repo_root = repo_root()?;

    let report_path = repo_root.join("tests/release/dossier_validation_report.v1.json");
    let report = read_json_file(&report_path)?;

    let policy = value_object(&report["compatibility_policy"], "compatibility_policy")?;
    assert!(policy.contains_key("format"), "policy missing 'format'");
    assert!(
        policy.contains_key("schema_versions"),
        "policy missing 'schema_versions'"
    );
    assert!(
        policy.contains_key("integrity"),
        "policy missing 'integrity'"
    );
    Ok(())
}

#[test]
fn dossier_validator_release_notes_hook_tracks_closed_beads() -> TestResult {
    let repo_root = repo_root()?;
    let script = repo_root.join("scripts/release_dossier_validator.py");
    let issues_path = unique_temp_path("release-dossier-issues", ".jsonl")?;

    std::fs::write(
        &issues_path,
        concat!(
            "{\"id\":\"bd-early\",\"title\":\"Older closure\",\"status\":\"closed\",\"issue_type\":\"task\",\"closed_at\":\"2026-04-01T00:00:00Z\",\"close_reason\":\"older result\"}\n",
            "{\"id\":\"bd-open\",\"title\":\"Still open\",\"status\":\"open\",\"issue_type\":\"task\",\"updated_at\":\"2026-04-02T00:00:00Z\"}\n",
            "not-json\n",
            "{\"id\":\"bd-late\",\"title\":\"Latest closure\",\"status\":\"closed\",\"issue_type\":\"task\",\"closed_at\":\"2026-04-03T00:00:00Z\",\"description\":\"latest result from description fallback\"}\n"
        ),
    )?;

    let output = Command::new("python3")
        .arg(&script)
        .env("FLC_RELEASE_DOSSIER_ISSUES_JSONL", &issues_path)
        .env("FLC_RELEASE_DOSSIER_RELEASE_NOTES_LIMIT", "1")
        .current_dir(&repo_root)
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let report = parse_validator_report(
        &stdout,
        &stderr,
        "failed to parse dossier report with custom issues file",
    )?;

    let hook = value_object(&report["release_notes_hook"], "release_notes_hook")?;
    assert_eq!(
        hook["summary"]["closed_total"].as_u64(),
        Some(2),
        "hook should count only closed issues"
    );
    assert_eq!(
        hook["summary"]["selected"].as_u64(),
        Some(1),
        "hook should respect FLC_RELEASE_DOSSIER_RELEASE_NOTES_LIMIT"
    );
    assert_eq!(
        hook["summary"]["invalid_rows"].as_u64(),
        Some(1),
        "hook should report invalid JSONL rows"
    );

    let entries = value_array(&hook["entries"], "entries")?;
    assert_eq!(
        entries.len(),
        1,
        "selection limit should keep one release-note entry"
    );
    let latest = &entries[0];
    assert_eq!(latest["id"].as_str(), Some("bd-late"));
    assert_eq!(
        latest["close_reason"].as_str(),
        Some("latest result from description fallback"),
        "description should be used when close_reason is absent"
    );

    let markdown = value_str(&hook["release_notes_markdown"], "release_notes_markdown")?;
    assert!(
        markdown.contains("bd-late"),
        "release_notes_markdown should render the selected entry"
    );

    let findings = value_array(&report["findings"], "findings")?;
    assert!(
        findings.iter().any(|finding| {
            finding["message"]
                .as_str()
                .map(|message| message.contains("Release-notes hook skipped 1 invalid row(s)"))
                .unwrap_or(false)
        }),
        "validator should emit a warning when the issues JSONL contains invalid rows"
    );
    Ok(())
}

#[test]
fn dossier_validator_release_notes_hook_invalid_limit_falls_back_to_default() -> TestResult {
    let repo_root = repo_root()?;
    let script = repo_root.join("scripts/release_dossier_validator.py");
    let issues_path = unique_temp_path("release-dossier-invalid-limit", ".jsonl")?;

    std::fs::write(
        &issues_path,
        concat!(
            "{\"id\":\"bd-1\",\"title\":\"First closure\",\"status\":\"closed\",\"issue_type\":\"task\",\"closed_at\":\"2026-04-01T00:00:00Z\",\"close_reason\":\"first result\"}\n",
            "{\"id\":\"bd-2\",\"title\":\"Second closure\",\"status\":\"closed\",\"issue_type\":\"task\",\"closed_at\":\"2026-04-02T00:00:00Z\",\"close_reason\":\"second result\"}\n"
        ),
    )?;

    let output = Command::new("python3")
        .arg(&script)
        .env("FLC_RELEASE_DOSSIER_ISSUES_JSONL", &issues_path)
        .env("FLC_RELEASE_DOSSIER_RELEASE_NOTES_LIMIT", "not-a-number")
        .current_dir(&repo_root)
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let report = parse_validator_report(
        &stdout,
        &stderr,
        "failed to parse dossier report with invalid limit",
    )?;

    let hook = value_object(&report["release_notes_hook"], "release_notes_hook")?;
    assert_eq!(
        hook["selection_policy"]["limit"].as_u64(),
        Some(8),
        "invalid release-notes limit should fall back to the default"
    );
    assert_eq!(
        hook["summary"]["selected"].as_u64(),
        Some(2),
        "fallback limit should still include the available closed beads"
    );

    let findings = value_array(&report["findings"], "findings")?;
    assert!(
        findings.iter().any(|finding| {
            finding["message"]
                .as_str()
                .map(|message| {
                    message.contains("FLC_RELEASE_DOSSIER_RELEASE_NOTES_LIMIT")
                        && message.contains("using default 8")
                })
                .unwrap_or(false)
        }),
        "validator should emit a warning when the release-notes limit is invalid"
    );
    Ok(())
}
