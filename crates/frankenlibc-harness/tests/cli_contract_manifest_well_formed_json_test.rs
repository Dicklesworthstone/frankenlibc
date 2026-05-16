//! Meta-gate: every `*_cli_contract.v1.json` manifest under
//! `tests/conformance/` is well-formed JSON with no UTF-8 BOM, no
//! trailing garbage after the closing `}`, and parses cleanly via
//! `serde_json::from_str` (bd-n5yk9). Defense-in-depth against silent
//! corruption from accidental concatenation, CRLF/BOM rewrites, or
//! truncated writes.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn trailing_garbage_after_close_brace(body: &str) -> Option<&str> {
    let trimmed = body.trim_end();
    if let Some(idx) = trimmed.rfind('}') {
        let after = &trimmed[idx + 1..];
        if !after.is_empty() {
            return Some(after);
        }
    }
    None
}

#[test]
fn every_cli_contract_manifest_is_well_formed_json() -> TestResult {
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
        let bytes = std::fs::read(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        if bytes.starts_with(UTF8_BOM) {
            violations.push(format!("{name}: starts with UTF-8 BOM"));
            continue;
        }
        let body =
            std::str::from_utf8(&bytes).map_err(|e| format!("{name}: not valid UTF-8: {e}"))?;
        match serde_json::from_str::<Value>(body) {
            Ok(_) => {}
            Err(e) => violations.push(format!("{name}: serde_json::from_str failed: {e}")),
        }
        if let Some(garbage) = trailing_garbage_after_close_brace(body) {
            violations.push(format!(
                "{name}: has trailing garbage after closing brace: {garbage:?}"
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
            "{} cli_contract manifest well-formed-JSON violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn trailing_garbage_detector_handles_canonical_forms() {
    assert_eq!(trailing_garbage_after_close_brace("{}\n"), None);
    assert_eq!(trailing_garbage_after_close_brace("{\"a\":1}"), None);
    assert_eq!(
        trailing_garbage_after_close_brace("{}garbage"),
        Some("garbage")
    );
    assert_eq!(trailing_garbage_after_close_brace("{} {}"), None); // trim eats trailing space
    // rfind picks the LAST `}`, so doubled closing braces are not flagged
    // by this detector — JSON parsing catches the structural error instead.
    assert_eq!(trailing_garbage_after_close_brace("{}}"), None);
    assert_eq!(trailing_garbage_after_close_brace("{}x"), Some("x"));
}
