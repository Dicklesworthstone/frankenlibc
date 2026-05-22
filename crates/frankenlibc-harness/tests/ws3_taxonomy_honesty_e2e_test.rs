//! WS-3 taxonomy-honesty E2E completion gate for bd-smp21.5.

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CONTRACT_PATH: &str =
    "tests/conformance/ws3_taxonomy_honesty_e2e_completion_contract.v1.json";
const SCRIPT_PATH: &str = "scripts/check_ws3_taxonomy_honesty_e2e.sh";

const REQUIRED_EVENTS: &[&str] = &[
    "host_delegation_census_replayed",
    "implemented_host_delegation_checked",
    "readme_native_badge_checked",
    "replacement_levels_gate_replayed",
    "ws3_taxonomy_honesty_e2e_validated",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "timestamp",
    "trace_id",
    "event",
    "level",
    "bead_id",
    "status",
    "source_commit",
    "failure_signature",
    "summary",
    "artifact_refs",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate should live under crates/")
        .parent()
        .expect("crates/ should live under workspace root")
        .to_path_buf()
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn unique_target_path(root: &Path, label: &str, extension: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    root.join("target/conformance").join(format!(
        "ws3-taxonomy-honesty-{label}-{}-{stamp}.{extension}",
        std::process::id()
    ))
}

fn gate_paths(
    root: &Path,
    label: &str,
) -> (
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
) {
    (
        unique_target_path(root, &format!("{label}-report"), "json"),
        unique_target_path(root, &format!("{label}-log"), "jsonl"),
        unique_target_path(root, &format!("{label}-host-report"), "json"),
        unique_target_path(root, &format!("{label}-host-log"), "jsonl"),
        unique_target_path(root, &format!("{label}-generated-census"), "json"),
        unique_target_path(root, &format!("{label}-levels-report"), "json"),
        unique_target_path(root, &format!("{label}-levels-log"), "jsonl"),
    )
}

fn run_gate(root: &Path, label: &str, extra_env: &[(&str, &Path)]) -> TestResult<Output> {
    let (report, log, host_report, host_log, generated_census, levels_report, levels_log) =
        gate_paths(root, label);
    let mut command = Command::new(root.join(SCRIPT_PATH));
    command.current_dir(root);
    command.env("FRANKENLIBC_WS3_TAXONOMY_HONESTY_REPORT", &report);
    command.env("FRANKENLIBC_WS3_TAXONOMY_HONESTY_LOG", &log);
    command.env("FRANKENLIBC_WS3_TAXONOMY_HONESTY_HOST_REPORT", &host_report);
    command.env("FRANKENLIBC_WS3_TAXONOMY_HONESTY_HOST_LOG", &host_log);
    command.env(
        "FRANKENLIBC_WS3_TAXONOMY_HONESTY_GENERATED_CENSUS",
        &generated_census,
    );
    command.env(
        "FRANKENLIBC_WS3_TAXONOMY_HONESTY_LEVELS_REPORT",
        &levels_report,
    );
    command.env("FRANKENLIBC_WS3_TAXONOMY_HONESTY_LEVELS_LOG", &levels_log);
    for (key, value) in extra_env {
        command.env(key, value);
    }
    Ok(command.output()?)
}

fn read_latest_report(root: &Path, label: &str) -> TestResult<Value> {
    let dir = root.join("target/conformance");
    let prefix = format!("ws3-taxonomy-honesty-{label}-report-");
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&prefix) && name.ends_with(".json") {
            candidates.push(entry.path());
        }
    }
    candidates.sort();
    let path = candidates
        .last()
        .ok_or_else(|| format!("missing report for label {label}"))?;
    load_json(path)
}

fn read_latest_log(root: &Path, label: &str) -> TestResult<Vec<Value>> {
    let dir = root.join("target/conformance");
    let prefix = format!("ws3-taxonomy-honesty-{label}-log-");
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&prefix) && name.ends_with(".jsonl") {
            candidates.push(entry.path());
        }
    }
    candidates.sort();
    let path = candidates
        .last()
        .ok_or_else(|| format!("missing log for label {label}"))?;
    let content = std::fs::read_to_string(path)?;
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

#[test]
fn contract_binds_gate_sources_events_and_expected_counts() -> TestResult {
    let root = workspace_root();
    let contract = load_json(&root.join(CONTRACT_PATH))?;

    assert_eq!(
        contract["schema_version"].as_str(),
        Some("ws3_taxonomy_honesty_e2e_completion_contract.v1")
    );
    assert_eq!(contract["bead"].as_str(), Some("bd-smp21.5"));
    assert_eq!(
        contract["source_artifacts"]["completion_gate"].as_str(),
        Some(SCRIPT_PATH)
    );
    assert_eq!(
        contract["source_artifacts"]["completion_harness"].as_str(),
        Some("crates/frankenlibc-harness/tests/ws3_taxonomy_honesty_e2e_test.rs")
    );

    let summary = &contract["completion_debt_evidence"]["required_summary"];
    assert_eq!(summary["total_symbols"].as_u64(), Some(4119));
    assert_eq!(summary["implemented"].as_u64(), Some(2368));
    assert_eq!(summary["raw_syscall"].as_u64(), Some(414));
    assert_eq!(summary["native"].as_u64(), Some(2782));
    assert_eq!(summary["wraps_host_libc"].as_u64(), Some(1337));
    assert_eq!(summary["glibc_callthrough"].as_u64(), Some(0));
    assert_eq!(summary["stub"].as_u64(), Some(0));
    assert_eq!(summary["native_pct"].as_f64(), Some(67.5));

    let events: BTreeSet<_> = contract["completion_debt_evidence"]["required_events"]
        .as_array()
        .expect("required_events should be array")
        .iter()
        .map(|event| event.as_str().expect("event should be string"))
        .collect();
    for event in REQUIRED_EVENTS {
        assert!(events.contains(event), "missing required event {event}");
    }
    assert!(events.contains("ws3_taxonomy_honesty_e2e_failed"));

    let fields: BTreeSet<_> = contract["completion_debt_evidence"]["required_log_fields"]
        .as_array()
        .expect("required_log_fields should be array")
        .iter()
        .map(|field| field.as_str().expect("field should be string"))
        .collect();
    for field in REQUIRED_LOG_FIELDS {
        assert!(fields.contains(field), "missing required log field {field}");
    }
    Ok(())
}

#[test]
fn gate_passes_current_taxonomy_and_emits_jsonl() -> TestResult {
    let root = workspace_root();
    let script = root.join(SCRIPT_PATH);
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)?.permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_ws3_taxonomy_honesty_e2e.sh must be executable"
        );
    }

    let output = run_gate(&root, "pass", &[])?;
    assert!(
        output.status.success(),
        "taxonomy honesty gate failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = read_latest_report(&root, "pass")?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("ws3_taxonomy_honesty_e2e.report.v1")
    );
    assert_eq!(report["bead"].as_str(), Some("bd-smp21.5"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["total_symbols"].as_u64(), Some(4119));
    assert_eq!(report["summary"]["implemented"].as_u64(), Some(2368));
    assert_eq!(report["summary"]["raw_syscall"].as_u64(), Some(414));
    assert_eq!(report["summary"]["native"].as_u64(), Some(2782));
    assert_eq!(report["summary"]["wraps_host_libc"].as_u64(), Some(1337));
    assert_eq!(report["summary"]["glibc_callthrough"].as_u64(), Some(0));
    assert_eq!(report["summary"]["stub"].as_u64(), Some(0));
    assert_eq!(report["summary"]["native_pct"].as_f64(), Some(67.5));
    assert_eq!(
        report["summary"]["implemented_host_delegation_count"].as_u64(),
        Some(0)
    );

    let checks = report["checks"].as_array().expect("checks should be array");
    assert!(
        checks
            .iter()
            .all(|check| check["status"].as_str() == Some("pass")),
        "all checks should pass: {checks:#?}"
    );

    let log = read_latest_log(&root, "pass")?;
    let events: BTreeSet<_> = log.iter().filter_map(|row| row["event"].as_str()).collect();
    for event in REQUIRED_EVENTS {
        assert!(events.contains(event), "missing event {event}");
    }
    for row in log {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing {field}");
        }
        assert_eq!(row["bead_id"].as_str(), Some("bd-smp21.5"));
    }
    Ok(())
}

#[test]
fn gate_rejects_stale_readme_native_badge() -> TestResult {
    let root = workspace_root();
    let readme = std::fs::read_to_string(root.join("README.md"))?;
    let stale = readme.replace("native_coverage-67.5%25", "native_coverage-100%25");
    assert_ne!(readme, stale, "README fixture should be mutated");
    let stale_path = unique_target_path(&root, "stale-readme", "md");
    if let Some(parent) = stale_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&stale_path, stale)?;

    let output = run_gate(
        &root,
        "stale",
        &[("FRANKENLIBC_WS3_TAXONOMY_HONESTY_README", &stale_path)],
    )?;
    assert!(
        !output.status.success(),
        "stale README badge should fail\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = read_latest_report(&root, "stale")?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_eq!(
        report["failure_signature"].as_str(),
        Some("readme_native_coverage_badge_matches_support_matrix")
    );
    let badge_check = report["checks"]
        .as_array()
        .expect("checks should be array")
        .iter()
        .find(|check| {
            check["name"].as_str() == Some("readme_native_coverage_badge_matches_support_matrix")
        })
        .expect("badge check should exist");
    assert_eq!(badge_check["status"].as_str(), Some("fail"));
    assert_eq!(badge_check["details"]["badge_pct"].as_f64(), Some(100.0));
    assert_eq!(
        badge_check["details"]["expected_native_pct"].as_f64(),
        Some(67.5)
    );
    Ok(())
}
