//! Integration test: setjmp semantics contract gate artifacts for bd-2xp3.
//!
//! Validates:
//! 1. `tests/conformance/setjmp_semantics_contract.v1.json` exists and parses.
//! 2. `scripts/check_setjmp_semantics_contract.sh` is executable and succeeds.
//! 3. Gate emits deterministic report/log artifacts in target + tests/cve_arena outputs.

use frankenlibc_harness::setjmp_contract::parse_contract_str;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let harness_root = manifest.parent().ok_or_else(|| {
        test_error(format!(
            "{} has no harness-crate parent",
            manifest.display()
        ))
    })?;
    let workspace_root = harness_root.parent().ok_or_else(|| {
        test_error(format!(
            "{} has no workspace-root parent",
            harness_root.display()
        ))
    })?;
    Ok(workspace_root.to_path_buf())
}

fn load_json(path: &Path) -> TestResult<serde_json::Value> {
    let content = fs::read_to_string(path)
        .map_err(|source| test_error(format!("failed to read {}: {source}", path.display())))?;
    serde_json::from_str(&content).map_err(|source| {
        test_error(format!("failed to parse JSON {}: {source}", path.display())).into()
    })
}

fn json_array<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> TestResult<&'a [serde_json::Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| test_error(format!("{field} must be an array")).into())
}

fn first_non_empty_jsonl_row(path: &Path) -> TestResult<String> {
    let content = fs::read_to_string(path)
        .map_err(|source| test_error(format!("failed to read {}: {source}", path.display())))?;
    content
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            test_error(format!(
                "{} must contain at least one JSONL row",
                path.display()
            ))
            .into()
        })
}

#[test]
fn artifact_exists_and_validates_intrinsic_contract() -> TestResult {
    let root = workspace_root()?;
    let artifact_path = root.join("tests/conformance/setjmp_semantics_contract.v1.json");
    assert!(
        artifact_path.exists(),
        "missing {}",
        artifact_path.display()
    );

    let artifact_raw = fs::read_to_string(&artifact_path).map_err(|source| {
        test_error(format!(
            "failed to read setjmp contract artifact {}: {source}",
            artifact_path.display()
        ))
    })?;
    let contract = parse_contract_str(&artifact_raw).map_err(|source| {
        test_error(format!(
            "failed to parse setjmp contract artifact {}: {source}",
            artifact_path.display()
        ))
    })?;
    contract.validate_intrinsic().map_err(|source| {
        test_error(format!(
            "setjmp intrinsic contract validation failed for {}: {source:?}",
            artifact_path.display()
        ))
    })?;

    let support_path = root.join("support_matrix.json");
    let support = load_json(&support_path)?;
    let support_symbols: BTreeSet<String> = json_array(
        support
            .get("symbols")
            .ok_or_else(|| test_error("support_matrix.symbols is missing"))?,
        "support_matrix.symbols",
    )?
    .iter()
    .filter_map(|row| row.get("symbol").and_then(serde_json::Value::as_str))
    .map(str::to_string)
    .collect();

    contract
        .validate_support_alignment(&support_symbols)
        .map_err(|source| {
            test_error(format!(
                "setjmp support-matrix alignment validation failed for {}: {source:?}",
                support_path.display()
            ))
        })?;
    Ok(())
}

#[test]
fn gate_script_passes_and_emits_artifacts() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_setjmp_semantics_contract.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&script)
            .map_err(|source| test_error(format!("failed to stat {}: {source}", script.display())))?
            .permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_setjmp_semantics_contract.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .map_err(|source| {
            test_error(format!(
                "failed to run setjmp semantics contract gate {}: {source}",
                script.display()
            ))
        })?;
    assert!(
        output.status.success(),
        "setjmp semantics contract gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/setjmp_semantics_contract.report.json");
    let log_path = root.join("target/conformance/setjmp_semantics_contract.log.jsonl");
    let cve_trace_path = root.join("tests/cve_arena/results/bd-2xp3/trace.jsonl");
    let cve_index_path = root.join("tests/cve_arena/results/bd-2xp3/artifact_index.json");

    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());
    assert!(
        cve_trace_path.exists(),
        "missing {}",
        cve_trace_path.display()
    );
    assert!(
        cve_index_path.exists(),
        "missing {}",
        cve_index_path.display()
    );

    let report = load_json(&report_path)?;
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-2xp3"));
    for check in [
        "artifact_schema",
        "semantics_matrix",
        "signal_mask_contract",
        "support_matrix_alignment",
        "stub_and_waiver_alignment",
        "fixture_alignment",
        "summary_consistent",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "report checks.{check} should be pass"
        );
    }

    for path in [&log_path, &cve_trace_path] {
        let line = first_non_empty_jsonl_row(path)?;
        let event: serde_json::Value = serde_json::from_str(&line).map_err(|source| {
            test_error(format!(
                "failed to parse first JSONL row from {}: {source}; row={line}",
                path.display()
            ))
        })?;
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
            assert!(event.get(key).is_some(), "log row missing {key}");
        }
        assert_eq!(event["bead_id"].as_str(), Some("bd-2xp3"));
        assert_eq!(event["api_family"].as_str(), Some("setjmp"));
        assert_eq!(event["symbol"].as_str(), Some("setjmp_contract"));
        assert!(
            event["trace_id"]
                .as_str()
                .is_some_and(|v| v.starts_with("bd-2xp3::")),
            "trace_id should start with bd-2xp3::"
        );
    }

    let index = load_json(&cve_index_path)?;
    assert_eq!(index["index_version"].as_i64(), Some(1));
    assert_eq!(index["bead_id"].as_str(), Some("bd-2xp3"));
    let artifacts = json_array(
        index
            .get("artifacts")
            .ok_or_else(|| test_error("artifact index missing artifacts"))?,
        "artifact index artifacts",
    )?;
    assert!(
        artifacts.len() >= 4,
        "artifact index should contain >=4 entries"
    );
    for artifact in artifacts {
        assert!(
            artifact["path"].is_string(),
            "artifact.path should be string"
        );
        assert!(
            artifact["kind"].is_string(),
            "artifact.kind should be string"
        );
        assert!(
            artifact["sha256"].is_string(),
            "artifact.sha256 should be string"
        );
    }
    Ok(())
}
