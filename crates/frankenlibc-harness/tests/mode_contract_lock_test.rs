//! Integration test: mode contract lock gate (bd-w2c3.3.3)
//!
//! Validates:
//! 1. mode_contract_lock artifact exists and has required contract/provenance fields.
//! 2. startup/reentrant test anchors are declared.
//! 3. check_mode_contract_lock.sh exists, is executable, and passes.
//! 4. gate emits deterministic report + structured provenance log.
//!
//! Run:
//!   cargo test -p frankenlibc-harness --test mode_contract_lock_test

use std::path::{Path, PathBuf};
use std::process::Command;

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

#[test]
fn artifact_contract_shape_is_valid() {
    let root = workspace_root();
    let artifact_path = root.join("tests/conformance/mode_contract_lock.v1.json");
    let artifact = load_json(&artifact_path);

    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-w2c3.3.3"));
    assert_eq!(
        artifact["env_contract"]["env_key"].as_str(),
        Some("FRANKENLIBC_MODE")
    );
    assert_eq!(
        artifact["env_contract"]["allowed_values"]
            .as_array()
            .map(|v| v.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>()),
        Some(vec!["strict", "hardened"])
    );
    assert_eq!(
        artifact["env_contract"]["default_value"].as_str(),
        Some("strict")
    );

    let required = artifact["required_provenance_fields"]
        .as_array()
        .expect("required_provenance_fields must be array");
    let required_set: std::collections::HashSet<&str> =
        required.iter().filter_map(|v| v.as_str()).collect();
    for field in [
        "trace_id",
        "mode",
        "api_family",
        "symbol",
        "decision_path",
        "healing_action",
        "errno",
        "latency_ns",
        "artifact_refs",
        "resolved_mode",
        "mode_source",
        "mode_cache_state",
    ] {
        assert!(
            required_set.contains(field),
            "required_provenance_fields missing {field}"
        );
    }
}

#[test]
fn startup_reentrant_anchors_are_declared() {
    let root = workspace_root();
    let artifact_path = root.join("tests/conformance/mode_contract_lock.v1.json");
    let artifact = load_json(&artifact_path);
    let anchors = artifact["startup_reentrant_test_anchors"]
        .as_array()
        .expect("startup_reentrant_test_anchors must be array");
    assert!(!anchors.is_empty(), "anchors must not be empty");

    let mut names = std::collections::HashSet::new();
    for anchor in anchors {
        let name = anchor["name"]
            .as_str()
            .expect("anchor.name must be string")
            .to_string();
        let path = anchor["path"].as_str().expect("anchor.path must be string");
        assert_eq!(path, "crates/frankenlibc-membrane/src/config.rs");
        names.insert(name);
    }

    for required_name in [
        "runtime_mode_parser_is_strict_or_hardened_only",
        "cached_mode_is_process_sticky_until_cache_reset",
        "resolving_state_returns_strict_safe_default",
    ] {
        assert!(
            names.contains(required_name),
            "missing startup/reentrant anchor {required_name}"
        );
    }
}

#[test]
fn gate_script_passes_and_emits_provenance_artifacts() {
    let root = workspace_root();
    let script = root.join("scripts/check_mode_contract_lock.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_mode_contract_lock.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run mode contract lock gate");
    assert!(
        output.status.success(),
        "mode contract lock gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/mode_contract_lock.report.json");
    let log_path = root.join("target/conformance/mode_contract_lock.log.jsonl");
    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-w2c3.3.3"));
    assert_eq!(
        report["checks"]["artifact_shape"].as_str(),
        Some("pass"),
        "artifact_shape check should pass"
    );
    assert_eq!(
        report["checks"]["runtime_inventory_alignment"].as_str(),
        Some("pass"),
        "runtime inventory alignment check should pass"
    );
    assert_eq!(
        report["checks"]["docs_inventory_alignment"].as_str(),
        Some("pass"),
        "docs inventory alignment check should pass"
    );

    let log_content = std::fs::read_to_string(&log_path).expect("log should be readable");
    let first = log_content
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log must contain at least one row");
    let event: serde_json::Value = serde_json::from_str(first).expect("log row must be json");
    for key in [
        "trace_id",
        "mode",
        "api_family",
        "symbol",
        "decision_path",
        "healing_action",
        "errno",
        "latency_ns",
        "artifact_refs",
        "resolved_mode",
        "mode_source",
        "mode_cache_state",
    ] {
        assert!(
            event.get(key).is_some(),
            "structured provenance log missing field {key}"
        );
    }
}
