//! Integration test: hard-parts docs/parity/support/reality truth reconciliation gate (bd-8sho).

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

fn json_u64(value: &serde_json::Value, field: &str) -> TestResult<u64> {
    value
        .as_u64()
        .ok_or_else(|| test_error(format!("{field} must be a u64")).into())
}

#[test]
fn hard_parts_truth_artifact_has_expected_schema() -> TestResult {
    let root = workspace_root()?;
    let path = root.join("tests/conformance/hard_parts_truth_table.v1.json");
    assert!(path.exists(), "missing {}", path.display());

    let doc = load_json(&path)?;
    assert_eq!(doc["schema_version"].as_str(), Some("v1"));
    assert_eq!(doc["bead"].as_str(), Some("bd-8sho"));
    assert!(doc["generated_at"].is_string());
    assert!(doc["sources"].is_object());
    assert!(doc["reality_snapshot"].is_object());
    assert!(doc["subsystems"].is_array());
    assert!(doc["contradictions"].is_array());
    assert!(doc["summary"].is_object());

    let subsystems = json_array(&doc["subsystems"], "subsystems")?;
    assert_eq!(subsystems.len(), 6, "expected six hard-part subsystem rows");

    let contradiction_count = json_u64(
        &doc["summary"]["contradiction_count"],
        "summary.contradiction_count",
    )?;
    assert_eq!(contradiction_count, 0, "contradiction count must be zero");
    Ok(())
}

#[test]
fn hard_parts_truth_guard_script_passes() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_hard_parts_truth.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&script)
            .map_err(|source| test_error(format!("failed to stat {}: {source}", script.display())))?
            .permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_hard_parts_truth.sh must be executable"
        );
    }

    let output = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        .output()
        .map_err(|source| {
            test_error(format!(
                "failed to run hard-parts truth guard {}: {source}",
                script.display()
            ))
        })?;

    assert!(
        output.status.success(),
        "hard-parts truth guard failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
