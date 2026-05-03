//! Integration test: deterministic real-program smoke suite gate (bd-bp8fl.10.2)
//!
//! Validates the L0/L1 real-program smoke manifest, structured log contract,
//! skip/block handling, artifact writing, and stale-result rejection.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_DOMAINS: &[&str] = &[
    "shell_coreutils",
    "build_tool",
    "resolver_nss",
    "locale_iconv",
    "stdio_file",
    "threaded",
    "failure_unsupported",
    "standalone_future",
];

const REQUIRED_CASE_FIELDS: &[&str] = &[
    "case_id",
    "workload_id",
    "domain",
    "command",
    "argv",
    "env",
    "timeout_ms",
    "runtime_mode",
    "replacement_level",
    "artifact_kind",
    "expected",
    "allowed_divergence",
    "cleanup",
    "oracle_kind",
    "support_claim",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "workload_id",
    "command",
    "runtime_mode",
    "replacement_level",
    "oracle_kind",
    "expected_status",
    "actual_status",
    "errno",
    "duration_ms",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn load_manifest() -> serde_json::Value {
    load_json(&workspace_root().join("tests/conformance/real_program_smoke_suite.v1.json"))
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn run_gate(
    mode: &str,
    prefix: &str,
    extra_env: &[(&str, &Path)],
    force_missing_artifacts: bool,
) -> (PathBuf, PathBuf, PathBuf, std::process::Output) {
    let root = workspace_root();
    let temp = unique_temp_dir(prefix);
    let out_dir = temp.join("target");
    let report = temp.join("real_program_smoke_suite.report.json");
    let log = temp.join("real_program_smoke_suite.log.jsonl");
    let mut command = Command::new(root.join("scripts/check_real_program_smoke_suite.sh"));
    command
        .arg(mode)
        .current_dir(&root)
        .env("REAL_PROGRAM_SMOKE_TARGET_DIR", &out_dir)
        .env("REAL_PROGRAM_SMOKE_REPORT", &report)
        .env("REAL_PROGRAM_SMOKE_LOG", &log)
        .env("REAL_PROGRAM_SMOKE_RUN_ID", prefix)
        .env_remove("LD_PRELOAD")
        .env_remove("FRANKENLIBC_SMOKE_LIB_PATH")
        .env_remove("FRANKENLIBC_STANDALONE_LIB");
    if force_missing_artifacts {
        command.env("REAL_PROGRAM_SMOKE_IGNORE_DEFAULT_ARTIFACTS", "1");
    }
    for (key, value) in extra_env {
        command.env(key, value);
    }
    let output = command
        .output()
        .expect("real-program smoke gate should execute");
    (temp, report, log, output)
}

#[test]
fn manifest_defines_case_schema_and_log_contract() {
    let manifest = load_manifest();
    assert_eq!(manifest["schema_version"].as_str(), Some("v1"));
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.10.2"));
    assert_eq!(
        manifest["result_policy"]["unsupported_or_skipped_claims_support"].as_bool(),
        Some(false)
    );
    assert_eq!(
        manifest["result_policy"]["dry_run_claims_support"].as_bool(),
        Some(false)
    );

    let case_fields: Vec<_> = manifest["required_case_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(case_fields, REQUIRED_CASE_FIELDS);

    let log_fields: Vec<_> = manifest["required_log_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);
}

#[test]
fn cases_cover_required_domains_modes_levels_and_artifact_kinds() {
    let manifest = load_manifest();
    let cases = manifest["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 18);

    let mut domains: HashMap<String, u64> = HashMap::new();
    let mut modes = HashSet::new();
    let mut levels = HashSet::new();
    let mut artifact_kinds = HashSet::new();
    let mut support_never = 0_u64;
    let mut ids = HashSet::new();

    for case in cases {
        let case_id = case["case_id"].as_str().unwrap();
        assert!(ids.insert(case_id), "duplicate case_id {case_id}");
        for field in REQUIRED_CASE_FIELDS {
            assert!(!case[*field].is_null(), "{case_id}: missing {field}");
        }
        let domain = case["domain"].as_str().unwrap();
        *domains.entry(domain.to_string()).or_default() += 1;
        modes.insert(case["runtime_mode"].as_str().unwrap());
        levels.insert(case["replacement_level"].as_str().unwrap());
        artifact_kinds.insert(case["artifact_kind"].as_str().unwrap());
        if case["support_claim"].as_str() == Some("never") {
            support_never += 1;
        }
        assert_eq!(
            case["cleanup"]["policy"].as_str(),
            Some("case_dir_scoped"),
            "{case_id}: artifacts must be case-scoped"
        );
        assert!(
            case["timeout_ms"].as_u64().unwrap() <= 15_000,
            "{case_id}: timeout must remain bounded"
        );
    }

    for domain in REQUIRED_DOMAINS {
        assert!(domains.contains_key(*domain), "missing domain {domain}");
    }
    assert!(modes.contains("strict"));
    assert!(modes.contains("hardened"));
    assert!(levels.contains("L0"));
    assert!(levels.contains("L1"));
    assert!(artifact_kinds.contains("ld_preload_interpose"));
    assert!(artifact_kinds.contains("standalone_direct_link_future"));
    assert_eq!(
        manifest["summary"]["required_domain_coverage"],
        serde_json::to_value(domains).unwrap()
    );
    assert_eq!(
        manifest["summary"]["non_support_claim_policy_rows"].as_u64(),
        Some(support_never)
    );
}

#[test]
fn run_mode_writes_artifacts_and_blocks_claims_without_current_artifacts() {
    let (_temp, report_path, log_path, output) = run_gate("--run", "real-program-run", &[], true);
    assert!(
        output.status.success(),
        "real-program smoke gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.10.2"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["cases"].as_u64(), Some(18));
    assert_eq!(report["summary"]["failed"].as_u64(), Some(0));
    assert_eq!(
        report["summary"]["non_support_statuses_do_not_claim_support"].as_bool(),
        Some(true)
    );
    assert_eq!(report["summary"]["support_claimed"].as_u64(), Some(0));
    assert!(
        report["summary"]["claim_blocked"].as_u64().unwrap() >= 2,
        "missing artifacts should block at least standalone/interpose claim rows"
    );

    let rows = report["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 18);
    assert!(rows.iter().any(|row| {
        row["artifact_refs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| {
                value
                    .as_str()
                    .unwrap_or_default()
                    .ends_with("baseline.result.json")
            })
    }));
    for row in rows {
        if row["actual_status"].as_str() != Some("pass") {
            assert_eq!(
                row["support_claimed"].as_bool(),
                Some(false),
                "{} must not claim support from non-pass status",
                row["case_id"].as_str().unwrap()
            );
        }
    }

    let log = std::fs::read_to_string(&log_path).expect("log should be readable");
    let events: Vec<serde_json::Value> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log row should parse"))
        .collect();
    assert!(!events.is_empty(), "log should contain rows");
    for event in &events {
        for field in REQUIRED_LOG_FIELDS {
            assert!(event.get(*field).is_some(), "log row missing {field}");
        }
        if event["actual_status"].as_str() != Some("pass") {
            assert_eq!(event["support_claimed"].as_bool(), Some(false));
        }
    }
}

#[test]
fn validate_only_rejects_stale_prior_report() {
    let temp = unique_temp_dir("real-program-stale-prior");
    let prior = temp.join("prior.report.json");
    std::fs::write(
        &prior,
        r#"{"schema_version":"v1","source_commit":"definitely-not-current"}"#,
    )
    .expect("write stale prior report");

    let (_temp, report_path, log_path, output) = run_gate(
        "--validate-only",
        "real-program-validate",
        &[("REAL_PROGRAM_SMOKE_PRIOR_REPORT", &prior)],
        true,
    );
    assert!(
        output.status.success(),
        "validate-only gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["summary"]["stale_prior_result_rejected"].as_bool(),
        Some(true)
    );
    assert_eq!(report["summary"]["support_claimed"].as_u64(), Some(0));
    assert_eq!(report["summary"]["validated"].as_u64(), Some(18));

    let log = std::fs::read_to_string(&log_path).expect("log should be readable");
    assert!(
        log.lines().any(|line| {
            let row: serde_json::Value = serde_json::from_str(line).unwrap();
            row["event"].as_str() == Some("stale_result_rejected")
                && row["actual_status"].as_str() == Some("claim_blocked")
                && row["support_claimed"].as_bool() == Some(false)
        }),
        "validate-only log should include stale_result_rejected"
    );
}

#[test]
fn gate_script_exists_and_is_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_real_program_smoke_suite.sh");
    assert!(script.exists(), "gate script must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_real_program_smoke_suite.sh must be executable"
        );
    }
}
