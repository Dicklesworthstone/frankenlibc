//! Integration test: deterministic real-program smoke suite gate (bd-bp8fl.10.2)
//!
//! Validates the L0/L1 real-program smoke manifest, structured log contract,
//! skip/block handling, artifact writing, and stale-result rejection.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
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
    "artifact_hashes",
    "source_commit",
    "target_dir",
    "bundle_id",
    "failure_class",
    "next_safe_action",
    "failure_signature",
];

const REQUIRED_FAILURE_CLASSES: &[&str] = &[
    "symbol_missing",
    "semantic_divergence",
    "resolver_nss",
    "locale_iconv",
    "allocator_ownership",
    "timeout_failure",
];

const REQUIRED_BUNDLE_FIELDS: &[&str] = &[
    "schema_version",
    "bundle_id",
    "bead_id",
    "workload_id",
    "case_id",
    "command",
    "cwd",
    "environment",
    "loaded_libraries",
    "replacement_level",
    "runtime_mode",
    "semantic_overlay_rows",
    "missing_symbols",
    "unsupported_symbols",
    "fixture_diffs",
    "logs",
    "stdout",
    "stderr",
    "failure_signature",
    "failure_class",
    "next_safe_action",
    "regeneration_command",
    "source_commit",
    "target_dir",
    "artifact_refs",
    "redaction",
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

fn is_hex_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn git_head(root: &Path) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .expect("git rev-parse HEAD should run");
    assert!(
        output.status.success(),
        "git rev-parse HEAD failed with status {}",
        output.status
    );
    let stdout = String::from_utf8(output.stdout).expect("git rev-parse HEAD should emit UTF-8");
    let head = stdout.trim().to_owned();
    assert!(
        is_hex_commit(&head),
        "git HEAD should be a 40-hex commit, got {head:?}"
    );
    head
}

fn assert_source_commit_freshness_policy(manifest: &serde_json::Value) {
    assert_eq!(
        manifest["source_commit_freshness_policy"],
        serde_json::json!({
            "recorded_source_commit_field": "source_commit",
            "comparison_target": "current git HEAD",
            "stale_result": "block_real_program_smoke_evidence",
            "real_program_smoke_evidence_allowed_when_stale": false,
            "rejected_evidence_kind": "stale_source_commit",
        })
    );
}

fn write_json(path: &Path, value: &serde_json::Value) {
    let content = serde_json::to_string_pretty(value).expect("json should serialize");
    std::fs::write(path, format!("{content}\n")).expect("write json");
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

fn fake_ldd_failure_path(temp: &Path) -> OsString {
    let fake_bin = temp.join("fake-bin");
    std::fs::create_dir_all(&fake_bin).expect("create fake bin dir");
    let fake_ldd = fake_bin.join("ldd");
    std::fs::write(&fake_ldd, "#!/bin/sh\necho ldd probe failed >&2\nexit 42\n")
        .expect("write fake ldd");
    let chmod = Command::new("chmod")
        .arg("+x")
        .arg(&fake_ldd)
        .output()
        .expect("chmod should run");
    assert!(
        chmod.status.success(),
        "chmod failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&chmod.stdout),
        String::from_utf8_lossy(&chmod.stderr)
    );
    let mut path = OsString::from(fake_bin);
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    path
}

fn run_gate(
    mode: &str,
    prefix: &str,
    extra_env: &[(&str, String)],
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

fn build_dummy_standalone_artifact(prefix: &str) -> (PathBuf, PathBuf) {
    let temp = unique_temp_dir(prefix);
    let source = temp.join("dummy_replace.c");
    let artifact = temp.join("libfrankenlibc_replace.so");
    std::fs::write(&source, "void frankenlibc_replace_smoke_anchor(void) {}\n")
        .expect("write dummy standalone source");
    let output = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg(&source)
        .arg("-o")
        .arg(&artifact)
        .output()
        .expect("cc should build dummy standalone artifact");
    assert!(
        output.status.success(),
        "dummy standalone artifact build failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (temp, artifact)
}

#[test]
fn manifest_defines_case_schema_and_log_contract() {
    let manifest = load_manifest();
    assert_eq!(manifest["schema_version"].as_str(), Some("v1"));
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.10.2"));
    let source_commit = manifest["source_commit"]
        .as_str()
        .expect("source_commit should be present");
    assert_eq!(source_commit, "current");
    assert_source_commit_freshness_policy(&manifest);
    assert_eq!(
        manifest["freshness"]["required_source_commit"].as_str(),
        Some("current")
    );
    assert!(
        manifest["freshness"]["source_commit_policy"]
            .as_str()
            .unwrap()
            .contains("current git HEAD"),
        "manifest must require checker-side current-HEAD freshness"
    );
    assert_eq!(
        manifest["result_policy"]["unsupported_or_skipped_claims_support"].as_bool(),
        Some(false)
    );
    assert_eq!(
        manifest["result_policy"]["dry_run_claims_support"].as_bool(),
        Some(false)
    );
    let dependency_probe_tools: HashSet<_> = manifest["artifact_policy"]["dependency_probe_tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool.as_str().unwrap())
        .collect();
    assert!(
        dependency_probe_tools.contains("readelf") && dependency_probe_tools.contains("ldd"),
        "standalone real-program dependency probes must include readelf and ldd"
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
fn stale_source_commit_policy_blocks_real_program_smoke_evidence() {
    let root = workspace_root();
    let manifest = load_manifest();
    let source_commit = manifest["source_commit"]
        .as_str()
        .expect("source_commit should be present");
    assert!(
        source_commit == "current" || is_hex_commit(source_commit),
        "source_commit should be 'current' or a 40-hex commit, got {source_commit:?}"
    );
    let current_head = git_head(&root);
    assert_source_commit_freshness_policy(&manifest);
    if source_commit != "current" && source_commit != current_head {
        let policy = &manifest["source_commit_freshness_policy"];
        assert_eq!(
            policy["stale_result"].as_str(),
            Some("block_real_program_smoke_evidence"),
            "stale source commits must block real-program smoke evidence"
        );
        assert_eq!(
            policy["real_program_smoke_evidence_allowed_when_stale"].as_bool(),
            Some(false),
            "stale source commits must not allow real-program smoke evidence"
        );
        assert_eq!(
            policy["rejected_evidence_kind"].as_str(),
            Some("stale_source_commit"),
            "stale source commits must use stale_source_commit"
        );
    }
}

#[test]
fn manifest_defines_failure_bundle_schema_and_fixture_classes() {
    let manifest = load_manifest();
    let policy = &manifest["failure_bundle_policy"];
    assert_eq!(policy["bead"].as_str(), Some("bd-bp8fl.10.3"));
    assert_eq!(
        policy["bundle_filename"].as_str(),
        Some("failure.bundle.json")
    );

    let bundle_fields: Vec<_> = policy["required_bundle_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(bundle_fields, REQUIRED_BUNDLE_FIELDS);

    let required_classes: HashSet<_> = policy["required_failure_classes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|class| class.as_str().unwrap())
        .collect();
    let fixture_classes: HashSet<_> = policy["synthetic_failure_cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["failure_class"].as_str().unwrap())
        .collect();
    for class in REQUIRED_FAILURE_CLASSES {
        assert!(required_classes.contains(class), "missing class {class}");
        assert!(
            fixture_classes.contains(class),
            "missing fixture for class {class}"
        );
        assert!(
            policy["next_safe_actions"][*class]["bead"].is_string(),
            "{class}: missing next safe bead"
        );
    }
    assert_eq!(
        manifest["summary"]["failure_bundle_schema_fields"].as_u64(),
        Some(REQUIRED_BUNDLE_FIELDS.len() as u64)
    );
    assert_eq!(
        manifest["summary"]["failure_bundle_fixture_case_count"].as_u64(),
        Some(REQUIRED_FAILURE_CLASSES.len() as u64)
    );
}

#[test]
fn cases_cover_required_domains_modes_levels_and_artifact_kinds() {
    let manifest = load_manifest();
    let cases = manifest["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 20);

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
    assert!(artifact_kinds.contains("standalone_direct_link_real_program"));
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
    assert_eq!(report["summary"]["cases"].as_u64(), Some(20));
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
    assert!(
        report["summary"]["failure_bundles"].as_u64().unwrap() >= 2,
        "claim-blocked workload rows should emit failure bundles"
    );

    let rows = report["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 20);
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
            assert!(
                row["bundle_id"].as_str().unwrap_or_default() != "none",
                "{} must point at a failure bundle",
                row["case_id"].as_str().unwrap()
            );
            assert!(
                row["artifact_refs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|value| value
                        .as_str()
                        .unwrap_or_default()
                        .ends_with("failure.bundle.json")),
                "{} must include the bundle artifact",
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
        assert!(
            event["artifact_hashes"].as_object().is_some(),
            "log row should include artifact hashes"
        );
        if event["actual_status"].as_str() != Some("pass") {
            assert_eq!(event["support_claimed"].as_bool(), Some(false));
        }
    }

    let first_bundle_ref = rows
        .iter()
        .flat_map(|row| row["artifact_refs"].as_array().unwrap())
        .filter_map(|value| value.as_str())
        .find(|path| path.ends_with("failure.bundle.json"))
        .expect("at least one failure bundle should be referenced");
    let bundle = load_json(&workspace_root().join(first_bundle_ref));
    for field in REQUIRED_BUNDLE_FIELDS {
        assert!(bundle.get(*field).is_some(), "bundle missing {field}");
    }
    assert_eq!(bundle["support_claimed"].as_bool(), None);
    assert!(
        bundle["next_safe_action"]["bead"]
            .as_str()
            .unwrap()
            .starts_with("bd-"),
        "bundle must name a next safe bead"
    );
}

#[test]
fn validate_only_rejects_stale_recorded_source_commit() {
    let temp = unique_temp_dir("real-program-stale-recorded-source-commit");
    let manifest_path = temp.join("real_program_smoke_suite.stale_recorded.json");
    let mut manifest = load_manifest();
    manifest["source_commit"] =
        serde_json::Value::String("0000000000000000000000000000000000000000".to_owned());
    write_json(&manifest_path, &manifest);

    let (_temp, report_path, _log_path, output) = run_gate(
        "--validate-only",
        "real-program-stale-recorded-source",
        &[(
            "REAL_PROGRAM_SMOKE_MANIFEST",
            manifest_path.display().to_string(),
        )],
        true,
    );
    assert!(
        !output.status.success(),
        "validate-only should reject stale recorded source_commit:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path);
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_eq!(
        report["checks"]["recorded_source_commit_freshness"].as_str(),
        Some("fail")
    );
    let errors = report["errors"].as_array().unwrap();
    assert!(
        errors.iter().any(|error| error.as_str()
            == Some("source_commit must be 'current' or match current git HEAD")),
        "report should explain the stale recorded source_commit failure"
    );
}

#[test]
fn validate_only_rejects_missing_source_commit_freshness_policy() {
    let temp = unique_temp_dir("real-program-missing-source-policy-manifest");
    let manifest_path = temp.join("real_program_smoke_suite.missing_policy.json");
    let mut manifest = load_manifest();
    manifest
        .as_object_mut()
        .expect("manifest should be object")
        .remove("source_commit_freshness_policy");
    write_json(&manifest_path, &manifest);

    let (_temp, report_path, _log_path, output) = run_gate(
        "--validate-only",
        "real-program-missing-source-policy",
        &[(
            "REAL_PROGRAM_SMOKE_MANIFEST",
            manifest_path.display().to_string(),
        )],
        true,
    );
    assert!(
        !output.status.success(),
        "validate-only should reject missing source_commit_freshness_policy:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path);
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_eq!(
        report["checks"]["source_commit_freshness_policy"].as_str(),
        Some("fail")
    );
    let errors = report["errors"].as_array().unwrap();
    assert!(
        errors.iter().any(|error| error.as_str()
            == Some("source_commit_freshness_policy does not match script contract")),
        "report should explain the source_commit_freshness_policy failure"
    );
}

#[test]
fn current_standalone_artifact_rows_block_host_glibc_dependency() {
    let (_artifact_temp, artifact) =
        build_dummy_standalone_artifact("real-program-dummy-standalone");
    let (_temp, report_path, log_path, output) = run_gate(
        "--run",
        "real-program-standalone-current",
        &[("FRANKENLIBC_STANDALONE_LIB", artifact.display().to_string())],
        true,
    );
    assert!(
        output.status.success(),
        "real-program smoke gate with standalone artifact failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["artifact_state"]["standalone"]["status"].as_str(),
        Some("current")
    );
    let rows: Vec<_> = report["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| {
            row["case_id"]
                .as_str()
                .unwrap()
                .starts_with("standalone_real_program_argv_env")
        })
        .collect();
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(row["actual_status"].as_str(), Some("claim_blocked"));
        assert_eq!(row["support_claimed"].as_bool(), Some(false));
        assert_eq!(
            row["failure_signature"].as_str(),
            Some("host_glibc_dependency_detected")
        );
        let refs = row["artifact_refs"].as_array().unwrap();
        assert!(
            refs.iter().any(|value| value
                .as_str()
                .unwrap_or_default()
                .ends_with("dependency_scan.json")),
            "standalone rows should include dependency scan artifact"
        );
        let hashes = row["artifact_hashes"].as_object().unwrap();
        assert!(
            hashes.keys().any(|path| path.ends_with("candidate.bin")),
            "standalone row should hash the linked candidate"
        );
    }

    let log = std::fs::read_to_string(&log_path).expect("log should be readable");
    let events: Vec<serde_json::Value> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log row should parse"))
        .collect();
    let blocked_events: Vec<_> = events
        .iter()
        .filter(|event| event["event"].as_str() == Some("standalone_host_dependency_blocked"))
        .collect();
    assert_eq!(blocked_events.len(), 2);
    for event in blocked_events {
        assert_eq!(
            event["failure_signature"].as_str(),
            Some("host_glibc_dependency_detected")
        );
        assert!(
            event["command"]
                .as_str()
                .unwrap()
                .contains("libfrankenlibc_replace.so"),
            "logged command should name the standalone artifact"
        );
        let hashes = event["artifact_hashes"].as_object().unwrap();
        assert!(
            hashes
                .keys()
                .any(|path| path.ends_with("libfrankenlibc_replace.so")),
            "log should hash the standalone artifact"
        );
    }
}

#[test]
fn current_standalone_artifact_rows_block_dependency_inspector_failure() {
    if Command::new("cc").arg("--version").output().is_err() {
        return;
    }

    let (artifact_temp, artifact) =
        build_dummy_standalone_artifact("real-program-dummy-standalone-ldd-failure");
    let fake_path = fake_ldd_failure_path(&artifact_temp)
        .to_string_lossy()
        .into_owned();
    let (_temp, report_path, log_path, output) = run_gate(
        "--run",
        "real-program-standalone-ldd-failure",
        &[
            ("PATH", fake_path),
            ("FRANKENLIBC_STANDALONE_LIB", artifact.display().to_string()),
        ],
        true,
    );
    assert!(
        output.status.success(),
        "real-program smoke gate with failing ldd failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["artifact_state"]["standalone"]["status"].as_str(),
        Some("current")
    );
    let rows: Vec<_> = report["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| {
            row["case_id"]
                .as_str()
                .unwrap()
                .starts_with("standalone_real_program_argv_env")
        })
        .collect();
    assert_eq!(rows.len(), 2);
    for row in &rows {
        assert_eq!(row["actual_status"].as_str(), Some("claim_blocked"));
        assert_eq!(row["support_claimed"].as_bool(), Some(false));
        assert_eq!(
            row["failure_signature"].as_str(),
            Some("dependency_inspector_failed")
        );
        let scan_ref = row["artifact_refs"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str())
            .find(|path| path.ends_with("dependency_scan.json"))
            .expect("standalone rows should include dependency scan artifact");
        let scan = load_json(&workspace_root().join(scan_ref));
        assert_eq!(scan["ldd"]["returncode"].as_i64(), Some(42));
        assert_eq!(
            scan["dependency_probe_failures"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|value| value.as_str())
                .collect::<Vec<_>>(),
            vec!["ldd"]
        );
    }

    let log = std::fs::read_to_string(&log_path).expect("log should be readable");
    let events: Vec<serde_json::Value> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log row should parse"))
        .collect();
    let blocked_events: Vec<_> = events
        .iter()
        .filter(|event| event["event"].as_str() == Some("standalone_host_dependency_blocked"))
        .collect();
    assert_eq!(blocked_events.len(), 2);
    for event in blocked_events {
        assert_eq!(
            event["failure_signature"].as_str(),
            Some("dependency_inspector_failed")
        );
        assert_eq!(event["actual_status"].as_str(), Some("claim_blocked"));
    }
}

#[test]
fn validate_only_rejects_stale_manifest_source_commit() {
    let temp = unique_temp_dir("real-program-stale-source-commit-manifest");
    let manifest_path = temp.join("real_program_smoke_suite.stale.json");
    let mut manifest = load_manifest();
    manifest["freshness"]["required_source_commit"] =
        serde_json::Value::String("0000000000000000000000000000000000000000".to_owned());
    write_json(&manifest_path, &manifest);

    let (_temp, report_path, _log_path, output) = run_gate(
        "--validate-only",
        "real-program-stale-source-commit",
        &[(
            "REAL_PROGRAM_SMOKE_MANIFEST",
            manifest_path.display().to_string(),
        )],
        true,
    );
    assert!(
        !output.status.success(),
        "validate-only should reject stale manifest source commits:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path);
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_eq!(
        report["checks"]["source_commit_freshness"].as_str(),
        Some("fail")
    );
    let errors = report["errors"].as_array().unwrap();
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .unwrap_or_default()
            .contains("freshness.required_source_commit")),
        "report should explain the stale source-commit policy failure"
    );
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
        &[(
            "REAL_PROGRAM_SMOKE_PRIOR_REPORT",
            prior.display().to_string(),
        )],
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
        report["checks"]["source_commit_freshness_policy"].as_str(),
        Some("pass")
    );
    assert_eq!(
        report["checks"]["recorded_source_commit_freshness"].as_str(),
        Some("pass")
    );
    assert_eq!(
        report["summary"]["stale_prior_result_rejected"].as_bool(),
        Some(true)
    );
    assert_eq!(report["summary"]["support_claimed"].as_u64(), Some(0));
    assert_eq!(report["summary"]["validated"].as_u64(), Some(20));

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
fn bundle_fixture_mode_covers_required_classes_and_redacts_runner_env() {
    let (_temp, report_path, log_path, output) = run_gate(
        "--bundle-fixtures",
        "real-program-bundles",
        &[(
            "REAL_PROGRAM_SECRET_TOKEN",
            "super-secret-value".to_string(),
        )],
        true,
    );
    assert!(
        output.status.success(),
        "bundle fixture gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["summary"]["failure_bundles"].as_u64(),
        Some(REQUIRED_FAILURE_CLASSES.len() as u64)
    );

    let classes: HashSet<_> = report["summary"]["failure_classes"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    for class in REQUIRED_FAILURE_CLASSES {
        assert!(classes.contains(class), "missing emitted class {class}");
    }

    for row in report["rows"].as_array().unwrap() {
        assert_eq!(row["support_claimed"].as_bool(), Some(false));
        assert_ne!(row["bundle_id"].as_str(), Some("none"));
        let bundle_ref = row["artifact_refs"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str())
            .find(|path| path.ends_with("failure.bundle.json"))
            .expect("bundle fixture row should reference failure.bundle.json");
        let bundle = load_json(&workspace_root().join(bundle_ref));
        for field in REQUIRED_BUNDLE_FIELDS {
            assert!(bundle.get(*field).is_some(), "bundle missing {field}");
        }
        assert!(
            bundle["redaction"]["redacted_keys"]
                .as_array()
                .unwrap()
                .iter()
                .any(|key| matches!(key.as_str(), Some("REAL_PROGRAM_SECRET_TOKEN"))),
            "secret runner env key should be redacted"
        );
        assert!(
            !serde_json::to_string(&bundle)
                .unwrap()
                .contains("super-secret-value"),
            "bundle must not leak secret env values"
        );
        assert!(
            !bundle["semantic_overlay_rows"]
                .as_array()
                .unwrap()
                .is_empty(),
            "bundle should include semantic overlay context"
        );
    }

    let log = std::fs::read_to_string(&log_path).expect("log should be readable");
    for line in log.lines().filter(|line| !line.trim().is_empty()) {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing {field}");
        }
        assert!(row["artifact_hashes"].as_object().is_some());
        assert_ne!(row["bundle_id"].as_str(), Some("none"));
        assert!(classes.contains(row["failure_class"].as_str().unwrap()));
        assert!(row["next_safe_action"].as_str().unwrap().contains(" "));
    }
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
