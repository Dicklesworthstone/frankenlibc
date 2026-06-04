//! Integration test: E2E suite infrastructure (bd-2ez)
//!
//! Validates that:
//! 1. e2e_suite.sh exists and is executable.
//! 2. check_e2e_suite.sh exists and is executable.
//! 3. validate_e2e_manifest.py + manifest catalog exist and are valid.
//! 4. The suite produces valid JSONL structured logs.
//! 5. Artifact index format is correct.
//!
//! Note: This tests the E2E *infrastructure*, not program pass rates.
//! LD_PRELOAD timeouts are expected during the interpose phase.
//!
//! Run: cargo test -p frankenlibc-harness --test e2e_suite_test

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn latest_run_dir(root: &Path, parent: &str, prefix: &str) -> Option<PathBuf> {
    let run_root = root.join(parent);
    if !run_root.exists() {
        return None;
    }
    let mut runs: Vec<_> = std::fs::read_dir(&run_root)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
        .collect();
    runs.sort_by(|a, b| {
        let a_mtime = a.metadata().and_then(|m| m.modified()).ok();
        let b_mtime = b.metadata().and_then(|m| m.modified()).ok();
        a_mtime
            .cmp(&b_mtime)
            .then_with(|| a.file_name().cmp(&b.file_name()))
    });
    runs.last().map(|e| e.path())
}

fn latest_e2e_seed_run_dir(root: &Path, seed: &str) -> Option<PathBuf> {
    let e2e_dir = root.join("target/e2e_suite");
    if !e2e_dir.exists() {
        return None;
    }

    let suffix = format!("-s{seed}");
    let mut runs: Vec<_> = std::fs::read_dir(&e2e_dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.starts_with("e2e-") && name.ends_with(&suffix)
        })
        .collect();
    runs.sort_by_key(|e| e.file_name());
    runs.last().map(|e| e.path())
}

#[test]
fn e2e_suite_script_exists() {
    let root = workspace_root();
    let script = root.join("scripts/e2e_suite.sh");
    assert!(script.exists(), "scripts/e2e_suite.sh must exist");

    // Check executable bit
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(perms.mode() & 0o111 != 0, "e2e_suite.sh must be executable");
    }
}

#[test]
fn check_e2e_suite_script_exists() {
    let root = workspace_root();
    let script = root.join("scripts/check_e2e_suite.sh");
    assert!(script.exists(), "scripts/check_e2e_suite.sh must exist");
}

#[test]
fn ld_preload_smoke_script_exists() {
    let root = workspace_root();
    let script = root.join("scripts/ld_preload_smoke.sh");
    assert!(script.exists(), "scripts/ld_preload_smoke.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "ld_preload_smoke.sh must be executable"
        );
    }
}

#[test]
fn ld_preload_smoke_script_declares_abi_parity_contract() {
    let root = workspace_root();
    let script = root.join("scripts/ld_preload_smoke.sh");
    let content = std::fs::read_to_string(&script).expect("ld_preload_smoke.sh should be readable");

    for needle in [
        "ENFORCE_PARITY_MODES",
        "ENFORCE_PERF_MODES",
        "PERF_RATIO_MAX_PPM",
        "VALGRIND_POLICY",
        "FAILURE_SIGNATURE_DENYLIST",
        "startup_troubleshooting.md",
        "signature_guard_triggered",
        "classify_failure_signature",
        "case_startup_path",
        "rch is required for cargo build offload",
        "abi_compat_report.json",
        "CASE_TSV",
        "BEAD_ID",
        "case_skip_optional_binary_missing",
    ] {
        assert!(
            content.contains(needle),
            "ld_preload_smoke.sh missing expected contract marker: {}",
            needle
        );
    }
}

#[test]
fn ld_preload_smoke_report_schema_valid_when_present() {
    let root = workspace_root();
    let Some(run_dir) = latest_run_dir(&root, "target/ld_preload_smoke", "20") else {
        // Smoke suite may not have been run in this environment.
        return;
    };

    let report_path = run_dir.join("abi_compat_report.json");
    if !report_path.exists() {
        return;
    }

    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&report_path).expect("abi_compat_report.json should be readable"),
    )
    .expect("abi_compat_report.json should be valid JSON");

    assert_eq!(
        report["schema_version"].as_str(),
        Some("v1"),
        "expected v1 schema"
    );
    let bead_id = report["bead_id"].as_str().unwrap_or_default();
    assert!(
        bead_id == "bd-18qq.6" || bead_id == "bd-1ah8",
        "expected bead id linkage to bd-18qq.6 or bd-1ah8, got {}",
        bead_id
    );
    assert!(report["summary"].is_object(), "summary must be an object");
    assert!(report["modes"].is_object(), "modes must be an object");
    assert!(report["cases"].is_array(), "cases must be an array");

    for mode in ["strict", "hardened"] {
        let mode_obj = &report["modes"][mode];
        assert!(mode_obj.is_object(), "missing modes.{} object", mode);
        for field in [
            "total_cases",
            "passes",
            "fails",
            "skips",
            "strict_parity_failures",
        ] {
            assert!(
                mode_obj[field].is_number(),
                "modes.{}.{} must be numeric",
                mode,
                field
            );
        }
        for optional_field in ["perf_failures", "valgrind_failures"] {
            if !mode_obj[optional_field].is_null() {
                assert!(
                    mode_obj[optional_field].is_number(),
                    "modes.{}.{} must be numeric when present",
                    mode,
                    optional_field
                );
            }
        }
    }

    if let Some(first_case) = report["cases"].as_array().and_then(|cases| cases.first()) {
        for field in [
            "workload",
            "startup_path",
            "failure_signature",
            "signature_guard_triggered",
        ] {
            assert!(first_case.get(field).is_some(), "case missing {}", field);
        }
        assert!(
            first_case["signature_guard_triggered"].is_boolean(),
            "case.signature_guard_triggered must be boolean"
        );
    }

    let trace_path = run_dir.join("trace.jsonl");
    if trace_path.exists() {
        let content = std::fs::read_to_string(&trace_path).expect("trace.jsonl should be readable");
        let mut lines = 0usize;
        for line in content.lines().filter(|l| !l.trim().is_empty()) {
            let obj: serde_json::Value =
                serde_json::from_str(line).expect("trace.jsonl must contain valid JSON lines");
            for field in [
                "timestamp",
                "trace_id",
                "level",
                "event",
                "bead_id",
                "run_id",
                "mode",
                "case",
                "status",
                "workload",
                "startup_path",
                "failure_signature",
            ] {
                assert!(obj[field].is_string(), "trace line missing {}", field);
            }
            assert!(
                obj["timing"].is_object(),
                "trace line missing timing object"
            );
            if !obj["api_family"].is_null() {
                for field in ["api_family", "symbol", "decision_path", "healing_action"] {
                    assert!(obj[field].is_string(), "trace line missing {}", field);
                }
                assert!(obj["errno"].is_number(), "trace line missing errno");
                assert!(
                    obj["latency_ns"].is_number(),
                    "trace line missing latency_ns"
                );
                assert!(
                    obj["artifact_refs"].is_array(),
                    "trace line missing artifact_refs"
                );
                if obj["event"]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("case_")
                    && !obj["signature_guard_triggered"].is_null()
                {
                    assert!(
                        obj["signature_guard_triggered"].is_u64()
                            || obj["signature_guard_triggered"].is_i64(),
                        "case event signature_guard_triggered should be numeric when present"
                    );
                }
            }
            lines += 1;
        }
        assert!(lines > 0, "trace.jsonl should contain at least one event");
    }
}

#[test]
fn e2e_manifest_validator_and_catalog_exist() {
    let root = workspace_root();
    let validator = root.join("scripts/validate_e2e_manifest.py");
    let manifest = root.join("tests/conformance/e2e_scenario_manifest.v1.json");
    assert!(
        validator.exists(),
        "scripts/validate_e2e_manifest.py must exist"
    );
    assert!(
        manifest.exists(),
        "tests/conformance/e2e_scenario_manifest.v1.json must exist"
    );

    let output = Command::new("python3")
        .arg(&validator)
        .arg("validate")
        .arg("--manifest")
        .arg(&manifest)
        .output()
        .expect("validate_e2e_manifest.py should execute");
    assert!(
        output.status.success(),
        "manifest validation should pass, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn e2e_suite_runs_and_produces_jsonl() {
    let root = workspace_root();
    let seed = "43001";

    // Run just the fault scenario with a very short timeout
    let output = Command::new("bash")
        .arg(root.join("scripts/e2e_suite.sh"))
        .arg("fault")
        .arg("strict")
        .env("TIMEOUT_SECONDS", "2")
        .env("FRANKENLIBC_E2E_SEED", seed)
        .output()
        .expect("e2e_suite.sh should execute");

    // The suite may fail (timeouts expected), but it should run
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("E2E Suite v1"), "Should print suite header");

    if let Some(latest) = latest_e2e_seed_run_dir(&root, seed) {
        let trace_path = latest.join("trace.jsonl");
        if trace_path.exists() {
            let content = std::fs::read_to_string(&trace_path).unwrap();
            let mut valid_lines = 0;
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let obj: serde_json::Value =
                    serde_json::from_str(line).expect("trace.jsonl should contain valid JSON");
                assert!(obj["timestamp"].is_string(), "Missing timestamp");
                assert!(obj["trace_id"].is_string(), "Missing trace_id");
                assert!(obj["level"].is_string(), "Missing level");
                assert!(obj["event"].is_string(), "Missing event");

                let tid = obj["trace_id"].as_str().unwrap();
                assert!(tid.contains("::"), "trace_id should contain ::");
                assert!(
                    tid.starts_with("bd-2ez::"),
                    "trace_id should start with bd-2ez::"
                );
                let event = obj["event"].as_str().unwrap();
                if event.starts_with("case_") || event == "manifest_case" {
                    assert!(obj["mode"].is_string(), "{event} must include mode field");
                    assert!(
                        obj["scenario_id"].is_string(),
                        "{event} must include scenario_id field"
                    );
                    assert!(
                        obj["scenario_pack"].is_string(),
                        "{event} must include scenario_pack field"
                    );
                    assert!(
                        obj["expected_outcome"].is_string(),
                        "{event} must include expected_outcome field"
                    );
                    assert!(
                        obj["artifact_policy"].is_object(),
                        "{event} must include artifact_policy object"
                    );
                    assert!(
                        obj["retry_count"].is_i64() || obj["retry_count"].is_u64(),
                        "{event} must include retry_count integer"
                    );
                    assert!(
                        obj["flake_score"].is_number(),
                        "{event} must include flake_score number"
                    );
                    assert!(
                        obj["artifact_refs"].is_array(),
                        "{event} must include artifact_refs array"
                    );
                    assert!(
                        obj["verdict"].is_string(),
                        "{event} must include verdict string"
                    );
                    if event.starts_with("case_") {
                        assert!(
                            obj["replay_key"].is_string(),
                            "{event} must include replay_key"
                        );
                        assert!(
                            obj["env_fingerprint"].is_string(),
                            "{event} must include env_fingerprint"
                        );
                    }
                }
                if event == "mode_pair_result" {
                    assert!(
                        obj["mode_pair_result"].is_string(),
                        "mode_pair_result event must include result"
                    );
                    assert!(
                        obj["drift_flags"].is_array(),
                        "mode_pair_result event must include drift_flags array"
                    );
                }
                valid_lines += 1;
            }
            assert!(
                valid_lines >= 2,
                "Expected at least suite_start + suite_end, got {} lines",
                valid_lines
            );
        }
    }
}

#[test]
fn e2e_suite_supports_manifest_dry_run() {
    let root = workspace_root();
    let script = root.join("scripts/e2e_suite.sh");

    let output = Command::new("bash")
        .arg(&script)
        .arg("--dry-run-manifest")
        .arg("fault")
        .arg("strict")
        .env("TIMEOUT_SECONDS", "1")
        .output()
        .expect("e2e_suite.sh should support manifest dry-run");

    assert!(
        output.status.success(),
        "manifest dry-run should pass, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[MANIFEST]"),
        "dry-run should print manifest entries"
    );
}

#[test]
fn e2e_artifact_index_valid() {
    let root = workspace_root();
    let script = root.join("scripts/e2e_suite.sh");
    let seed = "902";
    let _ = Command::new("bash")
        .arg(&script)
        .arg("fault")
        .env("TIMEOUT_SECONDS", "1")
        .env("FRANKENLIBC_E2E_SEED", seed)
        .output()
        .expect("e2e_suite.sh should execute for artifact index validation");

    let e2e_dir = root.join("target/e2e_suite");
    if !e2e_dir.exists() {
        return;
    }

    let mut runs: Vec<_> = std::fs::read_dir(&e2e_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.starts_with("e2e-") && name.ends_with(&format!("-s{seed}"))
        })
        .collect();
    runs.sort_by_key(|e| e.file_name());

    if let Some(latest) = runs.last() {
        let index_path = latest.path().join("artifact_index.json");
        if index_path.exists() {
            let content = std::fs::read_to_string(&index_path).unwrap();
            let idx: serde_json::Value =
                serde_json::from_str(&content).expect("artifact_index.json should be valid JSON");

            assert_eq!(
                idx["index_version"].as_u64().unwrap(),
                1,
                "Expected index_version 1"
            );
            assert_eq!(
                idx["bead_id"].as_str().unwrap(),
                "bd-2ez",
                "Expected bead_id bd-2ez"
            );
            assert!(idx["run_id"].is_string(), "Expected run_id string");
            assert!(
                idx["retention_policy"].is_object(),
                "Expected retention_policy object"
            );
            assert!(idx["artifacts"].is_array(), "Expected artifacts array");

            let artifacts = idx["artifacts"].as_array().unwrap();
            let mut joined_artifacts = 0usize;
            let mut trace_log_joined = false;
            for art in artifacts {
                assert!(art["path"].is_string(), "Artifact missing path");
                assert!(art["kind"].is_string(), "Artifact missing kind");
                assert!(
                    art["retention_tier"].is_string(),
                    "Artifact missing retention_tier"
                );
                assert!(art["sha256"].is_string(), "Artifact missing sha256");
                if let Some(join_keys) = art.get("join_keys") {
                    assert!(join_keys.is_object(), "join_keys must be an object");
                    let trace_ids = join_keys["trace_ids"]
                        .as_array()
                        .expect("join_keys.trace_ids must be an array when present");
                    if !trace_ids.is_empty() {
                        joined_artifacts += 1;
                        for trace_id in trace_ids {
                            let trace_id = trace_id
                                .as_str()
                                .expect("trace_ids entries must be strings");
                            assert!(
                                trace_id.contains("::"),
                                "artifact join trace_id should be canonical: {trace_id}"
                            );
                        }
                        if art["path"].as_str() == Some("trace.jsonl") {
                            trace_log_joined = true;
                        }
                    }
                }
            }
            assert!(
                joined_artifacts > 0,
                "artifact index should include at least one joined artifact entry"
            );
            assert!(
                trace_log_joined,
                "trace.jsonl entry should carry join_keys.trace_ids"
            );
        }
    }
}

#[test]
fn e2e_mode_pair_report_valid() {
    let root = workspace_root();
    let script = root.join("scripts/e2e_suite.sh");
    let seed = "889";
    let _ = Command::new("bash")
        .arg(&script)
        .arg("fault")
        .env("TIMEOUT_SECONDS", "1")
        .env("FRANKENLIBC_E2E_SEED", seed)
        .output()
        .expect("e2e_suite.sh should execute for mode-pair report");

    let e2e_dir = root.join("target/e2e_suite");
    if !e2e_dir.exists() {
        return; // No runs yet
    }

    let mut runs: Vec<_> = std::fs::read_dir(&e2e_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.starts_with("e2e-") && name.ends_with(&format!("-s{seed}"))
        })
        .collect();
    runs.sort_by_key(|e| e.file_name());

    if let Some(latest) = runs.last() {
        let report_path = latest.path().join("mode_pair_report.json");
        assert!(
            report_path.exists(),
            "mode_pair_report.json should exist for non-dry-run runs"
        );
        let content = std::fs::read_to_string(&report_path).unwrap();
        let report: serde_json::Value =
            serde_json::from_str(&content).expect("mode_pair_report.json should be valid JSON");

        assert_eq!(
            report["schema_version"].as_str().unwrap(),
            "v1",
            "Expected schema_version v1"
        );
        assert!(report["run_id"].is_string(), "Expected run_id string");
        assert!(report["pairs"].is_array(), "Expected pairs array");

        let pairs = report["pairs"].as_array().unwrap();
        assert!(
            !pairs.is_empty(),
            "mode_pair_report should contain at least one scenario pair"
        );
        for pair in pairs {
            assert!(pair["scenario_id"].is_string(), "Pair missing scenario_id");
            assert!(
                pair["mode_pair_result"].is_string(),
                "Pair missing mode_pair_result"
            );
            let pair_result = pair["mode_pair_result"].as_str().unwrap();
            assert!(
                ["match", "mismatch", "incomplete"].contains(&pair_result),
                "unexpected mode_pair_result value: {pair_result}"
            );
            assert!(pair["drift_flags"].is_array(), "Pair missing drift_flags");
        }
    }
}

#[test]
fn e2e_quarantine_and_pack_reports_valid() {
    let root = workspace_root();
    let script = root.join("scripts/e2e_suite.sh");
    let seed = "901";
    let _ = Command::new("bash")
        .arg(&script)
        .arg("fault")
        .env("TIMEOUT_SECONDS", "1")
        .env("FRANKENLIBC_E2E_SEED", seed)
        .env("FRANKENLIBC_E2E_RETRY_MAX", "1")
        .output()
        .expect("e2e_suite.sh should execute for quarantine/pack reports");

    let e2e_dir = root.join("target/e2e_suite");
    if !e2e_dir.exists() {
        return;
    }

    let mut runs: Vec<_> = std::fs::read_dir(&e2e_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.starts_with("e2e-") && name.ends_with(&format!("-s{seed}"))
        })
        .collect();
    runs.sort_by_key(|e| e.file_name());

    if let Some(latest) = runs.last() {
        let quarantine_report = latest.path().join("flake_quarantine_report.json");
        let pack_report = latest.path().join("scenario_pack_report.json");
        assert!(
            quarantine_report.exists(),
            "flake_quarantine_report.json should exist"
        );
        assert!(
            pack_report.exists(),
            "scenario_pack_report.json should exist"
        );

        let q: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&quarantine_report).unwrap())
                .expect("flake_quarantine_report.json should be valid JSON");
        assert_eq!(
            q["schema_version"].as_str().unwrap(),
            "v1",
            "quarantine report schema version must be v1"
        );
        assert!(
            q["quarantined_cases"].is_array(),
            "quarantine report must include quarantined_cases array"
        );
        assert!(
            q["remediation_workflow"].is_array(),
            "quarantine report must include remediation_workflow array"
        );

        let p: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&pack_report).unwrap())
                .expect("scenario_pack_report.json should be valid JSON");
        assert_eq!(
            p["schema_version"].as_str().unwrap(),
            "v1",
            "pack report schema version must be v1"
        );
        let packs = p["packs"]
            .as_array()
            .expect("scenario pack report must include packs array");
        assert!(
            !packs.is_empty(),
            "scenario pack report must include at least one pack row"
        );
        for pack in packs {
            assert!(
                pack["scenario_pack"].is_string(),
                "pack row missing scenario_pack"
            );
            assert!(pack["counts"].is_object(), "pack row missing counts");
            assert!(
                pack["thresholds"].is_object(),
                "pack row missing thresholds"
            );
            assert!(pack["verdict"].is_string(), "pack row missing verdict");
        }
    }
}

#[test]
fn replay_keys_are_deterministic_for_same_seed_and_manifest() {
    let root = workspace_root();
    let script = root.join("scripts/e2e_suite.sh");
    let seed = "777";

    let run_dry = |script: &PathBuf, seed: &str| {
        Command::new("bash")
            .arg(script)
            .arg("--dry-run-manifest")
            .arg("fault")
            .arg("strict")
            .env("FRANKENLIBC_E2E_SEED", seed)
            .output()
            .expect("dry-run manifest should execute")
    };

    let out1 = run_dry(&script, seed);
    assert!(
        out1.status.success(),
        "first dry-run should pass: {}",
        String::from_utf8_lossy(&out1.stderr)
    );
    sleep(Duration::from_secs(1));
    let out2 = run_dry(&script, seed);
    assert!(
        out2.status.success(),
        "second dry-run should pass: {}",
        String::from_utf8_lossy(&out2.stderr)
    );

    let e2e_dir = root.join("target/e2e_suite");
    let mut runs: Vec<_> = std::fs::read_dir(&e2e_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.starts_with("e2e-") && name.ends_with(&format!("-s{seed}"))
        })
        .collect();
    runs.sort_by_key(|e| e.file_name());
    assert!(
        runs.len() >= 2,
        "expected at least two dry-run outputs for deterministic replay-key test"
    );

    let latest = runs[runs.len() - 1].path().join("trace.jsonl");
    let previous = runs[runs.len() - 2].path().join("trace.jsonl");

    fn replay_key_map(trace_path: &Path) -> BTreeMap<String, String> {
        let content = std::fs::read_to_string(trace_path).expect("trace.jsonl should exist");
        let mut map = BTreeMap::new();
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let obj: serde_json::Value = serde_json::from_str(line).expect("valid JSONL line");
            if obj["event"].as_str() == Some("manifest_case")
                && obj["mode"].as_str() == Some("strict")
            {
                map.insert(
                    obj["scenario_id"].as_str().unwrap().to_string(),
                    obj["replay_key"].as_str().unwrap().to_string(),
                );
            }
        }
        map
    }

    let first_keys = replay_key_map(&previous);
    let second_keys = replay_key_map(&latest);
    assert!(
        !first_keys.is_empty(),
        "expected non-empty replay-key map from dry-run trace"
    );
    assert_eq!(
        first_keys, second_keys,
        "replay keys should be identical for same seed + manifest"
    );
}

#[test]
fn e2e_suite_supports_scenario_filter() {
    let root = workspace_root();
    let script = root.join("scripts/e2e_suite.sh");

    // Verify that passing a scenario class filter works
    let output = Command::new("bash")
        .arg(&script)
        .arg("smoke")
        .arg("strict")
        .env("TIMEOUT_SECONDS", "1")
        .output()
        .expect("e2e_suite.sh should execute with filters");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should only run smoke, not stress or fault
    assert!(
        stdout.contains("scenario=smoke"),
        "Should show smoke scenario filter"
    );
    assert!(
        !stdout.contains("[FAIL] stress/"),
        "Should not run stress scenarios when filtered to smoke"
    );
    assert!(
        !stdout.contains("[FAIL] fault/"),
        "Should not run fault scenarios when filtered to smoke"
    );
}

fn read_e2e_manifest(root: &Path) -> serde_json::Value {
    let manifest = root.join("tests/conformance/e2e_scenario_manifest.v1.json");
    serde_json::from_str(
        &std::fs::read_to_string(&manifest).expect("e2e scenario manifest should be readable"),
    )
    .expect("e2e scenario manifest should be valid JSON")
}

fn json_string_set(value: &serde_json::Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("value should be an array")
        .iter()
        .map(|item| {
            item.as_str()
                .expect("array entries should be strings")
                .to_string()
        })
        .collect()
}

fn assert_file_line_ref_exists(root: &Path, file_line_ref: &str) {
    let (path, line) = file_line_ref
        .rsplit_once(':')
        .expect("file-line ref should contain ':'");
    let line_no: usize = line.parse().expect("file-line ref has non-numeric line");
    assert!(line_no > 0, "file-line ref line must be positive");
    let full_path = root.join(path);
    assert!(
        full_path.exists(),
        "file-line ref path should exist: {file_line_ref}"
    );
    let line_count = std::fs::read_to_string(&full_path)
        .expect("referenced file should be readable")
        .lines()
        .count();
    assert!(
        line_no <= line_count,
        "file-line ref outside file: {file_line_ref}"
    );
}

#[test]
fn completion_debt_evidence_binds_missing_audit_items() {
    let root = workspace_root();
    let manifest = read_e2e_manifest(&root);
    let evidence = &manifest["completion_debt_evidence"];

    assert_eq!(evidence["bead"].as_str(), Some("bd-2ez.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-2ez"));
    assert!(
        evidence["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "completion evidence should target a passing next audit score"
    );

    let test_source = evidence["test_source"]
        .as_str()
        .expect("test_source should be a string");
    let test_source_text =
        std::fs::read_to_string(root.join(test_source)).expect("test_source should be readable");

    let required_sections = [
        ("unit_primary", "tests.unit.primary"),
        ("e2e_primary", "tests.e2e.primary"),
        ("telemetry_primary", "telemetry.primary"),
    ];
    for (section, missing_item_id) in required_sections {
        let section_value = &evidence[section];
        assert_eq!(
            section_value["missing_item_id"].as_str(),
            Some(missing_item_id),
            "{section} should bind the audit missing item"
        );
        assert!(
            section_value["next_audit_score_threshold"]
                .as_u64()
                .unwrap_or(0)
                >= 800,
            "{section} should carry the next audit threshold"
        );
        let required_test_names = section_value["required_test_names"]
            .as_array()
            .expect("required_test_names should be an array");
        assert!(
            !required_test_names.is_empty(),
            "{section} should name at least one test"
        );
        for name in required_test_names {
            let name = name.as_str().expect("test names should be strings");
            assert!(
                test_source_text.contains(&format!("fn {name}")),
                "completion evidence references missing test: {name}"
            );
        }
    }

    let refs = evidence["implementation_refs"]
        .as_array()
        .expect("implementation_refs should be an array");
    assert!(
        refs.len() >= 6,
        "implementation refs should cover suite, checker, and manifest surfaces"
    );
    for file_line_ref in refs {
        assert_file_line_ref_exists(
            &root,
            file_line_ref
                .as_str()
                .expect("implementation refs should be strings"),
        );
    }

    let telemetry = &evidence["telemetry_primary"];
    let required_events = json_string_set(&telemetry["required_events"]);
    for event in [
        "suite_start",
        "manifest_case",
        "case_start",
        "case_attempt",
        "mode_pair_result",
        "suite_end",
        "e2e_suite_completion_debt_validated",
    ] {
        assert!(
            required_events.contains(event),
            "telemetry evidence should require event {event}"
        );
    }

    let required_fields = json_string_set(&telemetry["required_fields"]);
    for field in [
        "timestamp",
        "trace_id",
        "event",
        "bead_id",
        "mode",
        "scenario_id",
        "scenario_pack",
        "artifact_refs",
        "replay_key",
        "env_fingerprint",
        "latency_ns",
    ] {
        assert!(
            required_fields.contains(field),
            "telemetry evidence should require field {field}"
        );
    }
}

#[test]
fn check_e2e_suite_emits_completion_debt_report_and_log() {
    let root = workspace_root();
    let report = root.join("target/conformance/e2e_suite_completion_debt.test.report.json");
    let log = root.join("target/conformance/e2e_suite_completion_debt.test.log.jsonl");

    let output = Command::new("bash")
        .arg(root.join("scripts/check_e2e_suite.sh"))
        .env("FRANKENLIBC_E2E_COMPLETION_ONLY", "1")
        .env("FRANKENLIBC_E2E_COMPLETION_REPORT", &report)
        .env("FRANKENLIBC_E2E_COMPLETION_LOG", &log)
        .output()
        .expect("completion-only e2e checker should execute");
    assert!(
        output.status.success(),
        "completion-only checker should pass, stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&report).expect("completion report should be readable"),
    )
    .expect("completion report should be valid JSON");
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(
        report_json["completion_debt_bead"].as_str(),
        Some("bd-2ez.1")
    );
    assert_eq!(report_json["original_bead"].as_str(), Some("bd-2ez"));
    assert!(
        report_json["missing_items"]
            .as_array()
            .expect("missing_items should be an array")
            .iter()
            .any(|item| item.as_str() == Some("tests.e2e.primary")),
        "report should bind tests.e2e.primary"
    );

    let log_content = std::fs::read_to_string(&log).expect("completion log should be readable");
    let log_row: serde_json::Value =
        serde_json::from_str(log_content.trim()).expect("completion log should be valid JSONL");
    assert_eq!(
        log_row["event"].as_str(),
        Some("e2e_suite_completion_debt_validated")
    );
    assert_eq!(log_row["completion_debt_bead"].as_str(), Some("bd-2ez.1"));
    assert_eq!(log_row["original_bead"].as_str(), Some("bd-2ez"));
    assert!(
        log_row["artifact_refs"]
            .as_array()
            .expect("artifact_refs should be an array")
            .iter()
            .any(|item| {
                item.as_str()
                    == Some("target/conformance/e2e_suite_completion_debt.test.report.json")
            }),
        "completion log should point at the report artifact"
    );
}

#[test]
fn completion_debt_checker_rejects_stale_test_binding() {
    let root = workspace_root();
    let mut manifest = read_e2e_manifest(&root);
    manifest["completion_debt_evidence"]["unit_primary"]["required_test_names"] =
        serde_json::json!(["stale_missing_test_name"]);

    let stale_manifest = root.join("target/conformance/e2e_suite_completion_debt.stale.json");
    let stale_report = root.join("target/conformance/e2e_suite_completion_debt.stale.report.json");
    let stale_log = root.join("target/conformance/e2e_suite_completion_debt.stale.log.jsonl");
    std::fs::create_dir_all(
        stale_manifest
            .parent()
            .expect("stale manifest should have parent"),
    )
    .expect("target conformance directory should be creatable");
    std::fs::write(
        &stale_manifest,
        serde_json::to_string_pretty(&manifest).unwrap() + "\n",
    )
    .expect("stale manifest should be writable");

    let output = Command::new("bash")
        .arg(root.join("scripts/check_e2e_suite.sh"))
        .env("FRANKENLIBC_E2E_COMPLETION_ONLY", "1")
        .env("FRANKENLIBC_E2E_COMPLETION_MANIFEST", &stale_manifest)
        .env("FRANKENLIBC_E2E_COMPLETION_REPORT", &stale_report)
        .env("FRANKENLIBC_E2E_COMPLETION_LOG", &stale_log)
        .output()
        .expect("completion-only e2e checker should execute");
    assert!(
        !output.status.success(),
        "stale completion evidence should fail validation"
    );
    let merged = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        merged.contains("references missing test stale_missing_test_name"),
        "checker should explain stale test binding, got: {merged}"
    );
}
