//! Meta-gate: no `*_cli_contract.v1.json` file under
//! `tests/conformance/` contains `//` line-comments or `/* ... */`
//! block-comments (bd-mrqcj). JSON proper has no comment syntax; this
//! is defense-in-depth against accidentally introducing JSONC-style
//! comments that would silently break strict parsers. We do the check
//! at the raw-byte level so the violation is caught even before
//! serde_json refuses to parse.

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

/// Returns the first line and column (1-based) where a `//` line-
/// comment or `/* ... */` block-comment marker appears outside of
/// any JSON string literal, or `None` if no comment marker is found.
/// String-aware so legitimate `"//"` inside a JSON string value
/// doesn't trigger.
fn find_comment_marker(body: &str) -> Option<(usize, usize)> {
    let mut in_string = false;
    let mut escape = false;
    let mut line = 1usize;
    let mut col = 1usize;
    let mut prev: Option<char> = None;
    for c in body.chars() {
        if !in_string
            && let Some(p) = prev
            && p == '/'
            && (c == '/' || c == '*')
        {
            return Some((line, col.saturating_sub(1)));
        }
        if c == '\n' {
            line += 1;
            col = 1;
            prev = Some(c);
            continue;
        }
        if escape {
            escape = false;
            prev = Some(c);
            col += 1;
            continue;
        }
        match c {
            '"' => in_string = !in_string,
            '\\' if in_string => escape = true,
            _ => {}
        }
        prev = Some(c);
        col += 1;
    }
    None
}

#[test]
fn no_cli_contract_manifest_contains_json_comment_marker() -> TestResult {
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
        if let Some((line, col)) = find_comment_marker(&body) {
            violations.push(format!(
                "{name}: comment marker found at line {line}, col {col} (JSON does not support comments)"
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
            "{} cli_contract manifest comment-marker violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn comment_marker_finder_handles_canonical_forms() {
    assert!(find_comment_marker("{\"a\":1}").is_none());
    assert!(find_comment_marker("{\n  \"a\": 1\n}").is_none());
    assert!(find_comment_marker("{\"u\":\"https://example.com\"}").is_none());
    assert!(find_comment_marker("// comment\n{}").is_some());
    assert!(find_comment_marker("{} // trailing").is_some());
    assert!(find_comment_marker("{ /* inline */ \"a\":1 }").is_some());
}
