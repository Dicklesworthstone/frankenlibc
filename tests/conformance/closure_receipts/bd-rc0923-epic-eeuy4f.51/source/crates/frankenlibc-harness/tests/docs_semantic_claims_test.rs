//! Integration test: README/FEATURE_PARITY semantic claim gate (bd-bp8fl.1.4)
//!
//! Verifies that docs separate support taxonomy from semantic parity and fail
//! closed when prose tries to advance unsupported replacement claims.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_FIELDS: &[&str] = &[
    "symbol_status",
    "semantic_parity_status",
    "oracle_kind",
    "replacement_level",
    "evidence_artifact",
    "freshness_state",
    "known_limitation",
    "user_recommendation",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "doc_surface",
    "symbol_or_section",
    "previous_claim",
    "generated_claim",
    "evidence_refs",
    "source_commit",
    "failure_signature",
];

fn gate_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn unique_temp_path(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("frankenlibc-{name}-{stamp}-{}", std::process::id()))
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn parse_stdout_report(output: &Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(
        parsed.is_ok(),
        "failed to parse gate stdout as JSON: {}\nstdout={stdout}\nstderr={stderr}",
        parsed.err().unwrap()
    );
    serde_json::from_str(&stdout).expect("gate stdout JSON parse was checked above")
}

fn run_gate_with_env(envs: &[(&str, &Path)]) -> Output {
    let root = workspace_root();
    let script = root.join("scripts/check_docs_semantic_claims.sh");
    let mut command = Command::new(&script);
    command.current_dir(&root);
    for (key, value) in envs {
        command.env(key, value);
    }
    command
        .output()
        .expect("failed to run docs semantic claims gate")
}

#[test]
fn artifact_declares_claim_fields_inputs_replays_and_log_contract() {
    let root = workspace_root();
    let artifact = load_json(&root.join("tests/conformance/docs_semantic_claims.v1.json"));
    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-bp8fl.1.4"));

    for key in [
        "readme",
        "feature_parity",
        "support_matrix",
        "support_semantic_overlay",
        "semantic_contract_inventory",
        "semantic_contract_symbol_join",
        "oracle_precedence",
        "replacement_levels",
    ] {
        let rel = artifact["inputs"][key].as_str().expect("input path");
        assert!(root.join(rel).exists(), "missing input {key}: {rel}");
    }

    let fields: HashSet<_> = artifact["required_claim_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap())
        .collect();
    assert_eq!(fields, REQUIRED_FIELDS.iter().copied().collect());

    let log_fields: Vec<_> = artifact["required_log_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);

    let replay_kinds: HashSet<_> = artifact["replay_cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        replay_kinds,
        [
            "clean",
            "forbidden_claim",
            "missing_field",
            "stale_artifact"
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn gate_passes_current_docs_and_emits_report_and_log() {
    let _guard = gate_mutex().lock().unwrap();
    let root = workspace_root();
    let script = root.join("scripts/check_docs_semantic_claims.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_docs_semantic_claims.sh must be executable"
        );
    }

    let output = run_gate_with_env(&[]);
    assert!(
        output.status.success(),
        "docs semantic claims gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = parse_stdout_report(&output);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["summary"]["required_claim_field_count"].as_u64(),
        Some(8)
    );
    assert_eq!(
        report["summary"]["semantic_parity_blocker_count"].as_u64(),
        Some(19)
    );
    assert_eq!(
        report["summary"]["taxonomy_semantic_conflict_count"].as_u64(),
        Some(19)
    );
    assert_eq!(report["summary"]["forbidden_claim_count"].as_u64(), Some(0));

    let log_path = root.join("target/conformance/docs_semantic_claims.log.jsonl");
    assert!(log_path.exists(), "missing {}", log_path.display());
    let log_line = std::fs::read_to_string(&log_path)
        .expect("log should be readable")
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log should contain at least one row")
        .to_string();
    let event: serde_json::Value = serde_json::from_str(&log_line).expect("log row should parse");
    for key in REQUIRED_LOG_FIELDS {
        assert!(event.get(*key).is_some(), "log row missing {key}");
    }
}

#[test]
fn missing_claim_field_fails() {
    let _guard = gate_mutex().lock().unwrap();
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("README.md")).unwrap();
    let mutated = source.replace("| `user_recommendation` |", "| `user_guidance` |");
    let readme = unique_temp_path("docs-semantic-missing-field.md");
    std::fs::write(&readme, mutated).expect("failed to write README fixture");

    let output = run_gate_with_env(&[("FLC_DOCS_SEMANTIC_README", &readme)]);
    assert!(
        !output.status.success(),
        "missing claim field should fail:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout_report(&output);
    assert_eq!(report["checks"]["docs_claim_fields"].as_str(), Some("fail"));
    assert!(report["errors"].as_array().unwrap().iter().any(|error| {
        error
            .as_str()
            .unwrap_or_default()
            .contains("user_recommendation")
    }));
}

#[test]
fn forbidden_full_replacement_claim_fails() {
    let _guard = gate_mutex().lock().unwrap();
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("FEATURE_PARITY.md")).unwrap();
    let mutated = format!("{source}\n\nStub: 0 proves full standalone replacement today.\n");
    let feature = unique_temp_path("docs-semantic-forbidden-claim.md");
    std::fs::write(&feature, mutated).expect("failed to write FEATURE fixture");

    let output = run_gate_with_env(&[("FLC_DOCS_SEMANTIC_FEATURE_PARITY", &feature)]);
    assert!(
        !output.status.success(),
        "forbidden replacement claim should fail:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout_report(&output);
    assert_eq!(
        report["checks"]["forbidden_claim_patterns"].as_str(),
        Some("fail")
    );
    assert!(
        report["summary"]["forbidden_claim_count"].as_u64().unwrap() >= 1,
        "forbidden claim fixture should produce at least one finding"
    );
}

#[test]
fn stale_semantic_join_fails() {
    let _guard = gate_mutex().lock().unwrap();
    let root = workspace_root();
    let canonical = root.join("tests/conformance/semantic_contract_symbol_join.v1.json");
    let mut join = load_json(&canonical);
    join["summary"]["semantic_parity_blocker_count"] = serde_json::json!(0);
    let stale = unique_temp_path("docs-semantic-stale-join.json");
    std::fs::write(&stale, serde_json::to_string_pretty(&join).unwrap() + "\n")
        .expect("failed to write stale join fixture");

    let output = run_gate_with_env(&[("FLC_DOCS_SEMANTIC_JOIN", &stale)]);
    assert!(
        !output.status.success(),
        "stale semantic join should fail:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout_report(&output);
    assert_eq!(
        report["checks"]["semantic_evidence_freshness"].as_str(),
        Some("fail")
    );
}

#[test]
fn stale_overlay_taxonomy_counts_fails() {
    let _guard = gate_mutex().lock().unwrap();
    let root = workspace_root();
    let canonical = root.join("tests/conformance/support_semantic_overlay.v1.json");
    let mut overlay = load_json(&canonical);
    let current = overlay["support_matrix_snapshot"]["status_counts"]["Implemented"]
        .as_u64()
        .unwrap_or(0);
    overlay["support_matrix_snapshot"]["status_counts"]["Implemented"] =
        serde_json::json!(current + 1);
    let stale = unique_temp_path("docs-semantic-stale-overlay.json");
    std::fs::write(
        &stale,
        serde_json::to_string_pretty(&overlay).unwrap() + "\n",
    )
    .expect("failed to write stale overlay fixture");

    let output = run_gate_with_env(&[("FLC_DOCS_SEMANTIC_OVERLAY", &stale)]);
    // Retain the adversarial fixture with the gate evidence.
    assert!(
        !output.status.success(),
        "stale semantic overlay status_counts should fail:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout_report(&output);
    assert_eq!(
        report["checks"]["numeric_claim_freshness"].as_str(),
        Some("fail")
    );
    assert!(report["errors"].as_array().unwrap().iter().any(|error| {
        error
            .as_str()
            .unwrap_or_default()
            .contains("does not match support_matrix.json")
    }));
}

#[test]
fn declared_source_identity_survives_a_worker_without_matching_git_metadata() {
    let _guard = gate_mutex().lock().unwrap();
    let root = workspace_root();
    let absent_git = unique_temp_path("docs-semantic-absent-git");
    let source = "6188b9db38dd0a6bf8673fc40e70b0a90a531cf5";
    for declared in [source.to_string(), format!("{source}-dirty")] {
        let output = Command::new(root.join("scripts/check_docs_semantic_claims.sh"))
            .current_dir(&root)
            .env("GIT_DIR", &absent_git)
            .env("RCH_BUILD_SOURCE", &declared)
            .output()
            .expect("docs gate should execute");
        let report = parse_stdout_report(&output);
        assert!(output.status.success(), "{declared}: {report}");
        assert_eq!(report["checks"]["source_identity"], "pass");
        assert_eq!(report["source_commit"], source);
        let events =
            std::fs::read_to_string(root.join("target/conformance/docs_semantic_claims.log.jsonl"))
                .unwrap();
        for event in events.lines() {
            let event: serde_json::Value = serde_json::from_str(event).unwrap();
            assert_eq!(event["source_commit"], source);
        }
    }
}

#[test]
fn malformed_declared_source_fails_instead_of_using_worker_head() {
    let _guard = gate_mutex().lock().unwrap();
    let root = workspace_root();
    for declared in [
        "",
        "6188b9db",
        "g188b9db38dd0a6bf8673fc40e70b0a90a531cf5",
        "6188b9db38dd0a6bf8673fc40e70b0a90a531cf5-dirty-dirty",
    ] {
        let output = Command::new(root.join("scripts/check_docs_semantic_claims.sh"))
            .current_dir(&root)
            .env("RCH_BUILD_SOURCE", declared)
            .output()
            .expect("docs gate should execute");
        let report = parse_stdout_report(&output);
        assert_eq!(output.status.code(), Some(1), "{declared}: {report}");
        assert_eq!(report["checks"]["source_identity"], "fail");
        assert_eq!(report["source_commit"], "unknown");
    }
}

#[test]
fn undeclared_source_requires_an_observed_git_head() {
    let _guard = gate_mutex().lock().unwrap();
    let root = workspace_root();
    let head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&root)
        .output()
        .expect("git should execute");
    let (expected_head, fallback_git_dir) = if head.status.success() {
        (
            String::from_utf8_lossy(&head.stdout).trim().to_string(),
            None,
        )
    } else {
        let git_dir = unique_temp_path("docs-semantic-temp-git");
        let status = Command::new("git")
            .args(["init", "--bare"])
            .arg(&git_dir)
            .status()
            .expect("git init should execute");
        assert!(status.success());
        let tree = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["write-tree"])
            .output()
            .expect("git write-tree should execute");
        assert!(tree.status.success());
        let tree_sha = String::from_utf8_lossy(&tree.stdout).trim().to_string();
        let commit = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@example.com")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@example.com")
            .args(["commit-tree", &tree_sha, "-m", "init"])
            .output()
            .expect("git commit-tree should execute");
        assert!(commit.status.success());
        let commit_sha = String::from_utf8_lossy(&commit.stdout).trim().to_string();
        let update = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["update-ref", "HEAD", &commit_sha])
            .status()
            .expect("git update-ref should execute");
        assert!(update.success());
        (commit_sha, Some(git_dir))
    };
    let mut cmd = Command::new(root.join("scripts/check_docs_semantic_claims.sh"));
    cmd.current_dir(&root).env_remove("RCH_BUILD_SOURCE");
    if let Some(git_dir) = &fallback_git_dir {
        cmd.env("GIT_DIR", git_dir);
    }
    let output = cmd.output().expect("docs gate should execute");
    let report = parse_stdout_report(&output);
    assert!(output.status.success(), "{report}");
    assert_eq!(report["checks"]["source_identity"], "pass");
    assert_eq!(
        report["source_commit"].as_str(),
        Some(expected_head.as_str())
    );

    let output = Command::new(root.join("scripts/check_docs_semantic_claims.sh"))
        .current_dir(&root)
        .env_remove("RCH_BUILD_SOURCE")
        .env("GIT_DIR", unique_temp_path("docs-semantic-absent-git"))
        .output()
        .expect("docs gate should execute");
    let report = parse_stdout_report(&output);
    assert_eq!(output.status.code(), Some(1), "{report}");
    assert_eq!(report["checks"]["source_identity"], "fail");
    assert_eq!(report["source_commit"], "unknown");
}

#[test]
fn operator_guides_reject_planted_l1_and_stale_claims() {
    let _guard = gate_mutex().lock().unwrap();
    let root = workspace_root();
    let cases = [
        (
            "FLC_DOCS_SEMANTIC_DEPLOYMENT",
            "DEPLOYMENT.md",
            "Current Level: L1 hardened interposition ready for production.",
        ),
        (
            "FLC_DOCS_SEMANTIC_COMPATIBILITY",
            "docs/planning/COMPATIBILITY.md",
            "Canonical Declared Level: L1 hardened interpose.",
        ),
        (
            "FLC_DOCS_SEMANTIC_PARITY_COVERAGE",
            "docs/planning/PARITY-COVERAGE.md",
            "100% of targeted user-space APIs are implemented and scripts/run_aarch64_smoke.sh Currently runs a static system-libc program.",
        ),
        (
            "FLC_DOCS_SEMANTIC_SECURITY",
            "SECURITY.md",
            "Every exported ABI entrypoint runs the full TSM validation pipeline unconditionally.",
        ),
    ];

    for (env_key, rel_path, planted_claim) in cases {
        let source = std::fs::read_to_string(root.join(rel_path)).unwrap();
        let mutated = format!("{source}\n\n{planted_claim}\n");
        let temp = unique_temp_path("docs-semantic-operator-planted.md");
        std::fs::write(&temp, mutated).expect("failed to write operator guide fixture");

        let output = run_gate_with_env(&[(env_key, &temp)]);
        assert!(
            !output.status.success(),
            "planted claim in {rel_path} should fail:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let report = parse_stdout_report(&output);
        assert_eq!(
            report["checks"]["forbidden_claim_patterns"].as_str(),
            Some("fail"),
            "{rel_path}: {report}"
        );
    }
}

#[test]
fn operator_guides_reject_missing_l0_scope_phrase() {
    let _guard = gate_mutex().lock().unwrap();
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("DEPLOYMENT.md")).unwrap();
    let mutated = source.replace(
        "Current declared level: `L0`",
        "Current declared scope: interpose",
    );
    let temp = unique_temp_path("docs-semantic-deployment-missing-l0.md");
    std::fs::write(&temp, mutated).expect("failed to write DEPLOYMENT fixture");

    let output = run_gate_with_env(&[("FLC_DOCS_SEMANTIC_DEPLOYMENT", &temp)]);
    assert!(
        !output.status.success(),
        "missing L0 phrase in DEPLOYMENT.md should fail:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout_report(&output);
    assert_eq!(
        report["checks"]["operator_guides_surface"].as_str(),
        Some("fail")
    );
}

#[test]
fn readme_rejects_planted_stale_dns_nss_build_allocator_and_fingerprint_claims() {
    let _guard = gate_mutex().lock().unwrap();
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("README.md")).unwrap();
    let planted_lines = [
        "The resolver only talks to local files. A full NSS / DNS backend is a future milestone.",
        "Modules that export only tuple-based `gethostbyname4_r` are not supported.",
        "Native-thread cleanup/unwind and stdio/poll cancellation are not implemented.",
        "LTO, codegen-units=1 and strip are untried tuning.",
        "The header layout is [hash:8][generation:4] at p - 12.",
        "The deployed malloc calls the core slab allocator directly.",
        "The checked baseline meets the < 20 ns strict and < 200 ns hardened budget.",
    ];

    for planted in planted_lines {
        let mutated = format!("{source}\n\n{planted}\n");
        let temp = unique_temp_path("docs-semantic-readme-planted.md");
        std::fs::write(&temp, mutated).expect("failed to write README fixture");

        let output = run_gate_with_env(&[("FLC_DOCS_SEMANTIC_README", &temp)]);
        assert!(
            !output.status.success(),
            "planted README contradiction `{planted}` should fail:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let report = parse_stdout_report(&output);
        assert_eq!(
            report["checks"]["forbidden_claim_patterns"].as_str(),
            Some("fail"),
            "planted `{planted}`: {report}"
        );
    }
}

#[test]
fn readme_rejects_removal_of_required_semantic_architecture_facts() {
    let _guard = gate_mutex().lock().unwrap();
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("README.md")).unwrap();
    for needle in [
        "build_elf.rs",
        "version_scripts/fromfp.map",
        "[hash:8][generation:8][size:8]",
        "tries `gethostbyname4_r` first (`nss_module.rs`)",
    ] {
        let mutated = source.replace(needle, "removed_architecture_fact_placeholder");
        let temp = unique_temp_path("docs-semantic-readme-missing-fact.md");
        std::fs::write(&temp, mutated).expect("failed to write README fixture");

        let output = run_gate_with_env(&[("FLC_DOCS_SEMANTIC_README", &temp)]);
        assert!(
            !output.status.success(),
            "removing `{needle}` from README should fail:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let report = parse_stdout_report(&output);
        assert_eq!(
            report["checks"]["semantic_architecture_facts"].as_str(),
            Some("fail"),
            "missing `{needle}`: {report}"
        );
    }
}

#[test]
fn dated_historical_snapshots_remain_permitted() {
    let _guard = gate_mutex().lock().unwrap();
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("README.md")).unwrap();
    let mutated = format!(
        "{source}\n\nHistorical snapshot note (2026-05-04): former [hash:8][generation:4] header at p - 12 and old 2,829 native count are historical and not current.\n"
    );
    let temp = unique_temp_path("docs-semantic-readme-dated-history.md");
    std::fs::write(&temp, mutated).expect("failed to write README fixture");

    let output = run_gate_with_env(&[("FLC_DOCS_SEMANTIC_README", &temp)]);
    let report = parse_stdout_report(&output);
    assert!(
        output.status.success(),
        "dated historical reference should remain permitted:\n{report}"
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
}
