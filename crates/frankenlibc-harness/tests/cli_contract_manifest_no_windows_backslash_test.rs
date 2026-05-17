//! Meta-gate: no `tests/conformance/*_cli_contract.v1.json`
//! manifest contains a JSON-escaped backslash sequence (`\\`)
//! (bd-gsw2h). CLI contract manifests must use POSIX-style forward
//! slash paths so evidence remains portable across hosts.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn contains_json_escaped_backslash(body: &str) -> bool {
    body.contains("\\\\")
}

#[test]
fn no_cli_contract_manifest_contains_windows_backslash() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with("_cli_contract.v1.json") {
            continue;
        }
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        if contains_json_escaped_backslash(&body) {
            violations.push(format!("{name}: contains JSON-escaped backslash sequence"));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 CLI contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} CLI contract manifest backslash violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn backslash_detector_matches_json_escaped_separator() {
    assert!(contains_json_escaped_backslash(r#"{"path":"foo\\bar"}"#));
    assert!(!contains_json_escaped_backslash(r#"{"path":"foo/bar"}"#));
    assert!(!contains_json_escaped_backslash(
        r#"{"summary":"plain text"}"#
    ));
}
