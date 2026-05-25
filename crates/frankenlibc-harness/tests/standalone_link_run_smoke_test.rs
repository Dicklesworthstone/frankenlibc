//! Integration test: standalone link/run smoke gate (bd-bp8fl.6.2)
//!
//! Validates the direct-link smoke manifest and gate without treating
//! LD_PRELOAD interpose evidence as a replacement-level proof.

use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "smoke_id",
    "compiler",
    "link_args",
    "runtime_mode",
    "replacement_level",
    "expected_status",
    "actual_status",
    "loader_error",
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
    load_json(&workspace_root().join("tests/conformance/standalone_link_run_smoke.v1.json"))
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
            "stale_result": "block_standalone_link_run_smoke_evidence",
            "standalone_smoke_evidence_allowed_when_stale": false,
            "rejected_evidence_kind": "stale_source_commit",
        })
    );
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

fn write_json(path: &Path, value: &serde_json::Value) {
    let content = serde_json::to_string_pretty(value).expect("json should serialize");
    std::fs::write(path, format!("{content}\n")).expect("write json");
}

fn run_gate_with_manifest(
    mode: &str,
    prefix: &str,
    manifest_override: Option<&Path>,
) -> (PathBuf, PathBuf, PathBuf, std::process::Output) {
    let root = workspace_root();
    let temp = unique_temp_dir(prefix);
    let out_dir = temp.join("target");
    let report = temp.join("standalone_link_run_smoke.report.json");
    let log = temp.join("standalone_link_run_smoke.log.jsonl");
    let mut command = Command::new(root.join("scripts/check_standalone_link_run_smoke.sh"));
    command
        .arg(mode)
        .current_dir(&root)
        .env("STANDALONE_SMOKE_TARGET_DIR", &out_dir)
        .env("STANDALONE_SMOKE_REPORT", &report)
        .env("STANDALONE_SMOKE_LOG", &log)
        .env("STANDALONE_SMOKE_RUN_ID", prefix)
        .env_remove("FRANKENLIBC_STANDALONE_LIB")
        .env_remove("LD_PRELOAD");
    if let Some(manifest) = manifest_override {
        command.env("STANDALONE_SMOKE_MANIFEST", manifest);
    }
    let output = command
        .output()
        .expect("standalone link-run smoke gate should execute");
    (temp, report, log, output)
}

fn run_gate(mode: &str, prefix: &str) -> (PathBuf, PathBuf, PathBuf, std::process::Output) {
    run_gate_with_manifest(mode, prefix, None)
}

#[test]
fn manifest_defines_required_rows_and_log_contract() {
    let manifest = load_manifest();
    assert_eq!(manifest["schema_version"].as_str(), Some("v1"));
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.6.2"));
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
        manifest["current_claim_policy"]["ld_preload_evidence_accepted"].as_bool(),
        Some(false)
    );
    assert_eq!(
        manifest["current_claim_policy"]["missing_or_stale_candidate_result"].as_str(),
        Some("claim_blocked")
    );
    assert_eq!(
        manifest["current_claim_policy"]["host_glibc_dependency_result"].as_str(),
        Some("claim_blocked")
    );
    let allowed_levels: HashSet<_> =
        manifest["current_claim_policy"]["current_levels_allowed_without_standalone_claim"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry.as_str().unwrap())
            .collect();
    assert_eq!(allowed_levels, HashSet::from(["L0", "L1"]));
    let failure_signatures: HashSet<_> = manifest["expected_failure_classifications"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["failure_signature"].as_str().unwrap())
        .collect();
    assert!(
        failure_signatures.contains("artifact_dependency_inspection_failed"),
        "manifest should classify dependency inspection failures"
    );

    let log_fields: Vec<_> = manifest["required_log_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);

    let rows = manifest["smoke_rows"].as_array().unwrap();
    assert_eq!(rows.len(), 10);
    let categories: HashSet<_> = rows
        .iter()
        .map(|row| row["category"].as_str().unwrap())
        .collect();
    for category in [
        "minimal",
        "stdio_file",
        "pthread_tls",
        "resolver_locale",
        "negative_missing_obligation",
        "loader_symbol_bootstrap",
        "vm_syscall_ipc",
        "diagnostics_session",
        "profiling_fenv",
        "loader_process_negative_missing_obligation",
    ] {
        assert!(categories.contains(category), "missing category {category}");
    }

    for row in rows {
        let smoke_id = row["smoke_id"].as_str().unwrap();
        for field in [
            "source_filename",
            "c_source",
            "replacement_level",
            "runtime_modes",
            "link_command",
            "runtime_env",
            "expected_loader_startup",
            "symbol_version_requirements",
            "expected_output",
            "cleanup",
        ] {
            assert!(!row[field].is_null(), "{smoke_id}: missing {field}");
        }
        assert_eq!(
            row["runtime_modes"].as_array().unwrap().len(),
            2,
            "{smoke_id}: strict+hardened modes required"
        );
        assert!(
            row["runtime_env"]["forbidden"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value.as_str() == Some("LD_PRELOAD")),
            "{smoke_id}: LD_PRELOAD must be forbidden"
        );
    }
}

#[test]
fn stale_source_commit_policy_blocks_standalone_smoke_evidence() {
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
            Some("block_standalone_link_run_smoke_evidence"),
            "stale source commits must block standalone smoke evidence"
        );
        assert_eq!(
            policy["standalone_smoke_evidence_allowed_when_stale"].as_bool(),
            Some(false),
            "stale source commits must not allow standalone smoke evidence"
        );
        assert_eq!(
            policy["rejected_evidence_kind"].as_str(),
            Some("stale_source_commit"),
            "stale source commits must use stale_source_commit"
        );
    }
}

#[test]
fn validate_only_rejects_stale_recorded_source_commit() {
    let temp = unique_temp_dir("standalone-stale-recorded-source-commit");
    let manifest_path = temp.join("standalone_link_run_smoke.stale_recorded.json");
    let mut manifest = load_manifest();
    manifest["source_commit"] =
        serde_json::Value::String("0000000000000000000000000000000000000000".to_owned());
    write_json(&manifest_path, &manifest);

    let (_gate_temp, report_path, _log_path, output) = run_gate_with_manifest(
        "--validate-only",
        "standalone-stale-recorded-source-commit",
        Some(&manifest_path),
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
fn validate_only_rejects_stale_manifest_source_commit() {
    let temp = unique_temp_dir("standalone-stale-source-commit-manifest");
    let manifest_path = temp.join("standalone_link_run_smoke.stale.json");
    let mut manifest = load_manifest();
    manifest["freshness"]["required_source_commit"] =
        serde_json::Value::String("0000000000000000000000000000000000000000".to_owned());
    write_json(&manifest_path, &manifest);

    let (_gate_temp, report_path, _log_path, output) = run_gate_with_manifest(
        "--validate-only",
        "standalone-stale-source-commit",
        Some(&manifest_path),
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
fn validate_only_rejects_missing_source_commit_freshness_policy() {
    let temp = unique_temp_dir("standalone-missing-source-policy-manifest");
    let manifest_path = temp.join("standalone_link_run_smoke.missing_policy.json");
    let mut manifest = load_manifest();
    manifest
        .as_object_mut()
        .expect("manifest should be object")
        .remove("source_commit_freshness_policy");
    write_json(&manifest_path, &manifest);

    let (_gate_temp, report_path, _log_path, output) = run_gate_with_manifest(
        "--validate-only",
        "standalone-missing-source-policy",
        Some(&manifest_path),
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
fn loader_process_owner_rows_cover_all_gap_ids() {
    let manifest = load_manifest();
    let owner_group = manifest["owner_family_groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["owner_bead"].as_str() == Some("bd-bp8fl.3.7"))
        .expect("bd-bp8fl.3.7 owner group should be declared");
    assert_eq!(
        owner_group["batch_id"].as_str(),
        Some("fpg-reverse-loader-process-abi")
    );

    let expected_gap_ids: HashSet<_> = owner_group["gap_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(expected_gap_ids.len(), 10);

    let mut positive_gap_ids = HashSet::new();
    let mut negative_gap_ids = HashSet::new();
    let mut owner_rows = 0;
    for row in manifest["smoke_rows"].as_array().unwrap() {
        if row["owner_bead"].as_str() != Some("bd-bp8fl.3.7") {
            continue;
        }
        owner_rows += 1;
        assert_eq!(
            row["runtime_modes"].as_array().unwrap().len(),
            2,
            "{} must cover strict+hardened",
            row["smoke_id"].as_str().unwrap()
        );
        let target = if row["negative_case"].as_bool().unwrap_or(false) {
            &mut negative_gap_ids
        } else {
            &mut positive_gap_ids
        };
        for gap_id in row["feature_gap_ids"].as_array().unwrap() {
            target.insert(gap_id.as_str().unwrap());
        }
    }

    assert_eq!(owner_rows, 5);
    assert_eq!(
        positive_gap_ids, expected_gap_ids,
        "positive rows must preserve every loader/process ABI gap id"
    );
    assert_eq!(
        negative_gap_ids, expected_gap_ids,
        "negative row must fail closed for every loader/process ABI gap id"
    );
}

#[test]
fn link_commands_are_direct_and_case_isolated() {
    let manifest = load_manifest();
    for row in manifest["smoke_rows"].as_array().unwrap() {
        let smoke_id = row["smoke_id"].as_str().unwrap();
        let command = &row["link_command"];
        assert_eq!(
            command["profile"].as_str(),
            Some("standalone_direct_link"),
            "{smoke_id}: wrong link profile"
        );
        let candidate = command["candidate_template"].as_array().unwrap();
        assert!(
            candidate
                .iter()
                .any(|token| matches!(token.as_str(), Some("${standalone_library}"))),
            "{smoke_id}: candidate command must link the standalone library directly"
        );
        assert!(
            candidate
                .iter()
                .any(|token| token.as_str().unwrap_or_default().contains("-Wl,-rpath")),
            "{smoke_id}: candidate command must pin the standalone library rpath"
        );
        let serialized = serde_json::to_string(row).unwrap();
        assert!(
            !serialized.contains("LD_PRELOAD="),
            "{smoke_id}: command must not set LD_PRELOAD"
        );
        assert_eq!(
            row["cleanup"]["policy"].as_str(),
            Some("case_dir_scoped"),
            "{smoke_id}: artifacts must be case scoped"
        );
    }
}

#[test]
fn failure_classification_and_stale_rejection_are_declared() {
    let manifest = load_manifest();
    let classifications: HashSet<_> = manifest["expected_failure_classifications"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["failure_signature"].as_str().unwrap())
        .collect();
    for signature in [
        "standalone_artifact_missing",
        "standalone_artifact_stale",
        "wrong_artifact_profile",
        "host_glibc_dependency",
        "missing_obligation",
        "loader_startup_failure",
        "symbol_version_mismatch",
    ] {
        assert!(
            classifications.contains(signature),
            "missing failure classification {signature}"
        );
    }
    assert_eq!(
        manifest["artifact_policy"]["stale_if_older_than_head"].as_bool(),
        Some(true)
    );
    assert_eq!(
        manifest["artifact_policy"]["required_artifact_name"].as_str(),
        Some("libfrankenlibc_replace.so")
    );
    let probe_tools: HashSet<_> = manifest["artifact_policy"]["host_dependency_probe_tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry.as_str().unwrap())
        .collect();
    assert!(probe_tools.contains("readelf -d"));
    assert!(probe_tools.contains("ldd"));
}

#[test]
fn dry_run_blocks_l2_claim_without_candidate_artifact() {
    let (_temp, report_path, log_path, output) = run_gate("--dry-run", "standalone-dry-run");
    assert!(
        output.status.success(),
        "dry-run gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path);
    let levels = load_json(&workspace_root().join("tests/conformance/replacement_levels.json"));
    let expected_candidate_rows = load_manifest()["smoke_rows"].as_array().unwrap().len() * 2;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["current_level"], levels["current_level"]);
    assert_eq!(report["claim_status"].as_str(), Some("claim_blocked"));
    assert_eq!(
        report["ld_preload_evidence_accepted"].as_bool(),
        Some(false)
    );
    assert_eq!(
        report["checks"]["source_commit_freshness_policy"].as_str(),
        Some("pass")
    );
    assert_eq!(report["artifact_state"]["status"].as_str(), Some("missing"));
    assert_eq!(
        report["summary"]["candidate_blocked"].as_u64(),
        Some(expected_candidate_rows as u64),
        "all strict+hardened candidate rows should fail closed without artifact"
    );

    let log = std::fs::read_to_string(&log_path).expect("log should be readable");
    let mut candidate_rows = 0;
    for line in log.lines().filter(|line| !line.trim().is_empty()) {
        let row: serde_json::Value = serde_json::from_str(line).expect("log line should parse");
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing {field}");
        }
        let link_args = row["link_args"].as_array().unwrap();
        assert!(
            link_args
                .iter()
                .all(|arg| !arg.as_str().unwrap_or_default().contains("LD_PRELOAD")),
            "standalone gate must not smuggle LD_PRELOAD into link args"
        );
        if row["event"].as_str() == Some("candidate_direct_link") {
            candidate_rows += 1;
            assert_eq!(row["actual_status"].as_str(), Some("claim_blocked"));
        }
    }
    assert_eq!(candidate_rows, expected_candidate_rows);
}

#[test]
fn dry_run_blocks_host_libc_dependent_candidate_artifact() {
    if Command::new("cc").arg("--version").output().is_err() {
        return;
    }

    let root = workspace_root();
    let temp = unique_temp_dir("standalone-host-dependent-artifact");
    let source = temp.join("host_dependent.c");
    let artifact = temp.join("libfrankenlibc_replace.so");
    std::fs::write(
        &source,
        "#include <stdio.h>\nint frankenlibc_host_dep_sample(void) { puts(\"host-libc\"); return 0; }\n",
    )
    .expect("write host-dependent source");
    let cc_output = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg(&source)
        .arg("-o")
        .arg(&artifact)
        .output()
        .expect("cc should run");
    if !cc_output.status.success() {
        return;
    }

    let out_dir = temp.join("target");
    let report = temp.join("standalone_link_run_smoke.report.json");
    let log = temp.join("standalone_link_run_smoke.log.jsonl");
    let output = Command::new(root.join("scripts/check_standalone_link_run_smoke.sh"))
        .arg("--dry-run")
        .current_dir(&root)
        .env("STANDALONE_SMOKE_TARGET_DIR", &out_dir)
        .env("STANDALONE_SMOKE_REPORT", &report)
        .env("STANDALONE_SMOKE_LOG", &log)
        .env("STANDALONE_SMOKE_RUN_ID", "standalone-host-dependent")
        .env("FRANKENLIBC_STANDALONE_LIB", &artifact)
        .env_remove("LD_PRELOAD")
        .output()
        .expect("standalone link-run smoke gate should execute");
    assert!(
        output.status.success(),
        "dry-run gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = load_json(&report);
    let expected_candidate_rows = load_manifest()["smoke_rows"].as_array().unwrap().len() * 2;
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(report_json["claim_status"].as_str(), Some("claim_blocked"));
    assert_eq!(
        report_json["artifact_state"]["status"].as_str(),
        Some("host_dependent")
    );
    assert_eq!(
        report_json["artifact_state"]["failure_signature"].as_str(),
        Some("host_glibc_dependency")
    );
    assert_eq!(
        report_json["summary"]["candidate_blocked"].as_u64(),
        Some(expected_candidate_rows as u64)
    );

    let log = std::fs::read_to_string(&log).expect("log should be readable");
    let rows: Vec<serde_json::Value> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log line should parse"))
        .collect();
    assert!(rows.iter().any(|row| {
        row["event"].as_str() == Some("candidate_direct_link")
            && row["actual_status"].as_str() == Some("claim_blocked")
            && matches!(
                row["failure_signature"].as_str(),
                Some("host_glibc_dependency")
            )
    }));
}

#[test]
fn dry_run_blocks_wrong_profile_candidate_artifact() {
    let root = workspace_root();
    let temp = unique_temp_dir("standalone-wrong-profile-artifact");
    let artifact = temp.join("libfrankenlibc_abi.so");
    std::fs::write(&artifact, b"not a replacement artifact").expect("write wrong-profile artifact");

    let out_dir = temp.join("target");
    let report = temp.join("standalone_link_run_smoke.report.json");
    let log = temp.join("standalone_link_run_smoke.log.jsonl");
    let output = Command::new(root.join("scripts/check_standalone_link_run_smoke.sh"))
        .arg("--dry-run")
        .current_dir(&root)
        .env("STANDALONE_SMOKE_TARGET_DIR", &out_dir)
        .env("STANDALONE_SMOKE_REPORT", &report)
        .env("STANDALONE_SMOKE_LOG", &log)
        .env("STANDALONE_SMOKE_RUN_ID", "standalone-wrong-profile")
        .env("FRANKENLIBC_STANDALONE_LIB", &artifact)
        .env_remove("LD_PRELOAD")
        .output()
        .expect("standalone link-run smoke gate should execute");
    assert!(
        output.status.success(),
        "dry-run gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = load_json(&report);
    let expected_candidate_rows = load_manifest()["smoke_rows"].as_array().unwrap().len() * 2;
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(report_json["claim_status"].as_str(), Some("claim_blocked"));
    assert_eq!(
        report_json["artifact_state"]["status"].as_str(),
        Some("wrong_profile")
    );
    assert_eq!(
        report_json["artifact_state"]["failure_signature"].as_str(),
        Some("wrong_artifact_profile")
    );
    assert_eq!(
        report_json["summary"]["candidate_blocked"].as_u64(),
        Some(expected_candidate_rows as u64)
    );

    let log = std::fs::read_to_string(&log).expect("log should be readable");
    let rows: Vec<serde_json::Value> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log line should parse"))
        .collect();
    assert!(rows.iter().any(|row| {
        row["event"].as_str() == Some("candidate_direct_link")
            && row["actual_status"].as_str() == Some("claim_blocked")
            && matches!(
                row["failure_signature"].as_str(),
                Some("wrong_artifact_profile")
            )
    }));
}

#[test]
fn dry_run_blocks_stale_candidate_artifact() {
    let root = workspace_root();
    let temp = unique_temp_dir("standalone-stale-artifact");
    let artifact = temp.join("libfrankenlibc_replace.so");
    std::fs::write(&artifact, b"stale replacement artifact").expect("write stale artifact");
    let touch = Command::new("touch")
        .arg("-t")
        .arg("200001010000.00")
        .arg(&artifact)
        .output()
        .expect("touch should run");
    assert!(
        touch.status.success(),
        "touch failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&touch.stdout),
        String::from_utf8_lossy(&touch.stderr)
    );

    let out_dir = temp.join("target");
    let report = temp.join("standalone_link_run_smoke.report.json");
    let log = temp.join("standalone_link_run_smoke.log.jsonl");
    let output = Command::new(root.join("scripts/check_standalone_link_run_smoke.sh"))
        .arg("--dry-run")
        .current_dir(&root)
        .env("STANDALONE_SMOKE_TARGET_DIR", &out_dir)
        .env("STANDALONE_SMOKE_REPORT", &report)
        .env("STANDALONE_SMOKE_LOG", &log)
        .env("STANDALONE_SMOKE_RUN_ID", "standalone-stale-artifact")
        .env("FRANKENLIBC_STANDALONE_LIB", &artifact)
        .env_remove("LD_PRELOAD")
        .output()
        .expect("standalone link-run smoke gate should execute");
    assert!(
        output.status.success(),
        "dry-run gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = load_json(&report);
    let expected_candidate_rows = load_manifest()["smoke_rows"].as_array().unwrap().len() * 2;
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(report_json["claim_status"].as_str(), Some("claim_blocked"));
    assert_eq!(
        report_json["artifact_state"]["status"].as_str(),
        Some("stale")
    );
    assert_eq!(
        report_json["artifact_state"]["failure_signature"].as_str(),
        Some("standalone_artifact_stale")
    );
    assert_eq!(
        report_json["summary"]["candidate_blocked"].as_u64(),
        Some(expected_candidate_rows as u64)
    );

    let log = std::fs::read_to_string(&log).expect("log should be readable");
    let rows: Vec<serde_json::Value> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log line should parse"))
        .collect();
    assert!(rows.iter().any(|row| {
        row["event"].as_str() == Some("candidate_direct_link")
            && row["actual_status"].as_str() == Some("claim_blocked")
            && matches!(
                row["failure_signature"].as_str(),
                Some("standalone_artifact_stale")
            )
    }));
}

#[test]
fn dry_run_blocks_candidate_artifact_when_ldd_probe_fails() {
    if Command::new("cc").arg("--version").output().is_err() {
        return;
    }

    let root = workspace_root();
    let temp = unique_temp_dir("standalone-ldd-probe-failed");
    let source = temp.join("sample.c");
    let artifact = temp.join("libfrankenlibc_replace.so");
    std::fs::write(
        &source,
        "int frankenlibc_probe_sample(void) { return 0; }\n",
    )
    .expect("write sample source");
    let cc_output = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg(&source)
        .arg("-o")
        .arg(&artifact)
        .output()
        .expect("cc should run");
    if !cc_output.status.success() {
        return;
    }

    let out_dir = temp.join("target");
    let report = temp.join("standalone_link_run_smoke.report.json");
    let log = temp.join("standalone_link_run_smoke.log.jsonl");
    let output = Command::new(root.join("scripts/check_standalone_link_run_smoke.sh"))
        .arg("--dry-run")
        .current_dir(&root)
        .env("PATH", fake_ldd_failure_path(&temp))
        .env("STANDALONE_SMOKE_TARGET_DIR", &out_dir)
        .env("STANDALONE_SMOKE_REPORT", &report)
        .env("STANDALONE_SMOKE_LOG", &log)
        .env("STANDALONE_SMOKE_RUN_ID", "standalone-ldd-probe-failed")
        .env("FRANKENLIBC_STANDALONE_LIB", &artifact)
        .env_remove("LD_PRELOAD")
        .output()
        .expect("standalone link-run smoke gate should execute");
    assert!(
        output.status.success(),
        "dry-run gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = load_json(&report);
    let expected_candidate_rows = load_manifest()["smoke_rows"].as_array().unwrap().len() * 2;
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(report_json["claim_status"].as_str(), Some("claim_blocked"));
    assert_eq!(
        report_json["artifact_state"]["status"].as_str(),
        Some("inspection_failed")
    );
    assert_eq!(
        report_json["artifact_state"]["failure_signature"].as_str(),
        Some("artifact_dependency_inspection_failed")
    );
    assert_eq!(
        report_json["summary"]["candidate_blocked"].as_u64(),
        Some(expected_candidate_rows as u64)
    );

    let log = std::fs::read_to_string(&log).expect("log should be readable");
    let rows: Vec<serde_json::Value> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log line should parse"))
        .collect();
    assert!(rows.iter().any(|row| {
        row["event"].as_str() == Some("candidate_direct_link")
            && row["actual_status"].as_str() == Some("claim_blocked")
            && matches!(
                row["failure_signature"].as_str(),
                Some("artifact_dependency_inspection_failed")
            )
    }));
}

#[test]
fn run_mode_compiles_baseline_programs_and_emits_artifacts() {
    if Command::new("cc").arg("--version").output().is_err() {
        return;
    }

    let (_temp, report_path, log_path, output) = run_gate("--run", "standalone-run");
    assert!(
        output.status.success(),
        "run gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path);
    let expected_rows = load_manifest()["smoke_rows"].as_array().unwrap().len();
    let expected_candidate_rows = expected_rows * 2;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["summary"]["rows"].as_u64(),
        Some(expected_rows as u64)
    );
    assert_eq!(report["summary"]["baseline_failed"].as_u64(), Some(0));
    assert_eq!(
        report["summary"]["baseline_passed"].as_u64(),
        Some(expected_rows as u64),
        "all C fixtures should compile and pass against the host baseline"
    );
    assert_eq!(
        report["summary"]["candidate_blocked"].as_u64(),
        Some(expected_candidate_rows as u64)
    );

    let rows = report["rows"].as_array().unwrap();
    for row in rows {
        let refs = row["artifact_refs"].as_array().unwrap();
        assert!(
            refs.iter()
                .any(|value| value.as_str().unwrap_or_default().ends_with(".c")),
            "{} should include source artifact refs",
            row["smoke_id"].as_str().unwrap()
        );
    }

    let log = std::fs::read_to_string(&log_path).expect("log should be readable");
    let rows: Vec<serde_json::Value> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log line should parse"))
        .collect();
    assert!(
        rows.iter()
            .any(|row| row["event"].as_str() == Some("baseline_compile_run")),
        "run log must include baseline compile/run events"
    );
    assert!(
        rows.iter().any(|row| matches!(
            row["failure_signature"].as_str(),
            Some("standalone_artifact_missing")
        )),
        "run log must explain missing standalone artifact"
    );
    assert!(
        rows.iter().any(|row| {
            row["bead_id"].as_str() == Some("bd-bp8fl.3.7")
                && row["event"].as_str() == Some("candidate_direct_link")
        }),
        "run log must include bd-bp8fl.3.7 candidate evidence rows"
    );
}

#[test]
fn gate_script_exists_and_is_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_standalone_link_run_smoke.sh");
    assert!(script.exists(), "gate script must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_standalone_link_run_smoke.sh must be executable"
        );
    }
}
