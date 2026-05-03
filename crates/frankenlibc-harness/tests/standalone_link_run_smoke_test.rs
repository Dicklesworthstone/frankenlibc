//! Integration test: standalone link/run smoke gate (bd-bp8fl.6.2)
//!
//! Validates the direct-link smoke manifest and gate without treating
//! LD_PRELOAD interpose evidence as a replacement-level proof.

use std::collections::HashSet;
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

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn run_gate(mode: &str, prefix: &str) -> (PathBuf, PathBuf, PathBuf, std::process::Output) {
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
    let output = command
        .output()
        .expect("standalone link-run smoke gate should execute");
    (temp, report, log, output)
}

#[test]
fn manifest_defines_required_rows_and_log_contract() {
    let manifest = load_manifest();
    assert_eq!(manifest["schema_version"].as_str(), Some("v1"));
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.6.2"));
    assert_eq!(
        manifest["current_claim_policy"]["ld_preload_evidence_accepted"].as_bool(),
        Some(false)
    );
    assert_eq!(
        manifest["current_claim_policy"]["missing_or_stale_candidate_result"].as_str(),
        Some("claim_blocked")
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
                .any(|token| token.as_str() == Some("${standalone_library}")),
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
    let expected_candidate_rows = load_manifest()["smoke_rows"].as_array().unwrap().len() * 2;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["current_level"].as_str(), Some("L0"));
    assert_eq!(report["claim_status"].as_str(), Some("claim_blocked"));
    assert_eq!(
        report["ld_preload_evidence_accepted"].as_bool(),
        Some(false)
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
        rows.iter()
            .any(|row| row["failure_signature"].as_str() == Some("standalone_artifact_missing")),
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
