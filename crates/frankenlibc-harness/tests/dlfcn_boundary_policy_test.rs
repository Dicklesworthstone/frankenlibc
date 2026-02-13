//! Integration test: dlfcn boundary policy gate (bd-33zg)
//!
//! Validates:
//! 1. dlfcn boundary policy artifact exists and has required contract sections.
//! 2. check_dlfcn_boundary_policy.sh exists, is executable, and passes.
//! 3. gate emits report + structured log + artifact index with SHA256 evidence.
//!
//! Run:
//!   cargo test -p frankenlibc-harness --test dlfcn_boundary_policy_test

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
    let artifact_path = root.join("tests/conformance/dlfcn_boundary_policy.v1.json");
    assert!(
        artifact_path.exists(),
        "missing {}",
        artifact_path.display()
    );

    let artifact = load_json(&artifact_path);
    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-33zg"));

    let symbols = artifact["surface_classification"]["symbols"]
        .as_array()
        .expect("surface_classification.symbols must be array");
    let as_symbols: Vec<&str> = symbols.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(as_symbols, vec!["dlopen", "dlsym", "dlclose", "dlerror"]);

    let approved = artifact["guard_rails"]["approved_host_calls"]
        .as_object()
        .expect("guard_rails.approved_host_calls must be object");
    for key in ["dlopen", "dlsym", "dlclose"] {
        assert!(
            approved.contains_key(key),
            "approved_host_calls missing {key}"
        );
    }

    let required_log_fields = artifact["structured_log_required_fields"]
        .as_array()
        .expect("structured_log_required_fields must be array");
    let log_field_set: std::collections::HashSet<&str> = required_log_fields
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    for key in [
        "timestamp",
        "trace_id",
        "level",
        "event",
        "bead_id",
        "stream",
        "gate",
        "mode",
        "api_family",
        "symbol",
        "outcome",
        "errno",
        "latency_ns",
        "artifact_refs",
    ] {
        assert!(
            log_field_set.contains(key),
            "structured_log_required_fields missing {key}"
        );
    }
}

#[test]
fn gate_script_passes_and_emits_artifacts() {
    let root = workspace_root();
    let script = root.join("scripts/check_dlfcn_boundary_policy.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_dlfcn_boundary_policy.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run dlfcn boundary policy gate");
    assert!(
        output.status.success(),
        "dlfcn boundary policy gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/dlfcn_boundary_policy.report.json");
    let log_path = root.join("target/conformance/dlfcn_boundary_policy.log.jsonl");
    let artifact_index_path =
        root.join("target/conformance/dlfcn_boundary_policy.artifact_index.json");
    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());
    assert!(
        artifact_index_path.exists(),
        "missing {}",
        artifact_index_path.display()
    );

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-33zg"));
    for key in [
        "policy_shape",
        "approved_host_calls",
        "forbidden_fallback_paths",
        "support_matrix_alignment",
        "mode_semantics_alignment",
        "replacement_profile_alignment",
        "docs_alignment",
    ] {
        assert_eq!(
            report["checks"][key].as_str(),
            Some("pass"),
            "report checks.{key} should be pass"
        );
    }

    let log_row = std::fs::read_to_string(&log_path)
        .expect("log should be readable")
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log must contain at least one row")
        .to_string();
    let event: serde_json::Value = serde_json::from_str(&log_row).expect("log row must be json");
    for key in [
        "timestamp",
        "trace_id",
        "level",
        "event",
        "bead_id",
        "stream",
        "gate",
        "mode",
        "api_family",
        "symbol",
        "outcome",
        "errno",
        "latency_ns",
        "artifact_refs",
    ] {
        assert!(event.get(key).is_some(), "structured log missing {key}");
    }

    let index = load_json(&artifact_index_path);
    assert_eq!(index["index_version"].as_u64(), Some(1));
    assert_eq!(index["bead_id"].as_str(), Some("bd-33zg"));

    let artifacts = index["artifacts"]
        .as_array()
        .expect("artifact index artifacts must be array");
    assert_eq!(artifacts.len(), 3, "artifact index should list 3 artifacts");

    let mut kinds = std::collections::HashSet::new();
    for artifact in artifacts {
        let kind = artifact["kind"]
            .as_str()
            .expect("artifact kind must be string");
        kinds.insert(kind.to_string());

        let sha = artifact["sha256"]
            .as_str()
            .expect("artifact sha256 must be string");
        assert_eq!(sha.len(), 64, "sha256 must be 64 hex chars");
        assert!(
            sha.chars().all(|c| c.is_ascii_hexdigit()),
            "sha256 must be hex"
        );
    }

    for kind in ["golden", "report", "log"] {
        assert!(kinds.contains(kind), "artifact index missing kind {kind}");
    }
}
