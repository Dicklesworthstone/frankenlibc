//! Meta-gate: every `*_cli_contract.v1.json` manifest body contains no
//! JSON-escaped Windows path-separator (`\\`) sequences (bd-gsw2h).
//! All manifest paths must remain POSIX-style forward-slash paths so
//! Linux harness consumers and report renderers do not drift.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

const JSON_ESCAPED_BACKSLASH: &str = r"\\";

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn cli_contract_manifest_paths(root: &Path) -> TestResult<Vec<PathBuf>> {
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.ends_with("_cli_contract.v1.json") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn first_json_escaped_backslash_offset(body: &str) -> Option<usize> {
    body.find(JSON_ESCAPED_BACKSLASH)
}

#[test]
fn no_cli_contract_manifest_contains_json_escaped_windows_backslash() -> TestResult {
    let root = workspace_root()?;
    let manifest_paths = cli_contract_manifest_paths(&root)?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for path in manifest_paths {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        if let Some(offset) = first_json_escaped_backslash_offset(&body) {
            violations.push(format!(
                "{name}: byte {offset} contains JSON-escaped backslash sequence (`\\\\`)"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} CLI contract manifest Windows-backslash violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn json_escaped_backslash_detector_covers_path_shapes() {
    assert!(
        first_json_escaped_backslash_offset(r#"{"path":"C:\\tmp\\cli_contract.v1.json"}"#)
            .is_some()
    );
    assert!(
        first_json_escaped_backslash_offset(
            r#"{"path":"tests\\conformance\\foo_cli_contract.v1.json"}"#
        )
        .is_some()
    );
    assert!(
        first_json_escaped_backslash_offset(
            r#"{"path":"tests/conformance/foo_cli_contract.v1.json"}"#
        )
        .is_none()
    );
    assert!(first_json_escaped_backslash_offset(r#"{"note":"line\nbreak escape only"}"#).is_none());
}
