//! Meta-gate: paired `*_cli_contract_test.rs` files must not call raw
//! `panic!` directly (bd-795fi). Gate tests should propagate contextual
//! failures through `TestResult` instead of aborting from ad-hoc panic sites.

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

fn starts_raw_string(bytes: &[u8], index: usize) -> Option<usize> {
    let raw_start = match bytes.get(index) {
        Some(b'r') => index + 1,
        Some(b'b') if bytes.get(index + 1) == Some(&b'r') => index + 2,
        _ => return None,
    };
    let mut quote = raw_start;
    while bytes.get(quote) == Some(&b'#') {
        quote += 1;
    }
    if bytes.get(quote) != Some(&b'"') {
        return None;
    }

    let hash_count = quote - raw_start;
    let mut cursor = quote + 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            let hashes_end = cursor + 1 + hash_count;
            if hashes_end <= bytes.len()
                && bytes[cursor + 1..hashes_end]
                    .iter()
                    .all(|byte| *byte == b'#')
            {
                return Some(hashes_end);
            }
        }
        cursor += 1;
    }
    Some(bytes.len())
}

fn line_has_raw_panic_macro(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut cursor = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    while cursor < bytes.len() {
        if !in_string {
            if bytes.get(cursor) == Some(&b'/') && bytes.get(cursor + 1) == Some(&b'/') {
                return false;
            }
            if bytes[cursor..].starts_with(b"panic!(") {
                return true;
            }
            if let Some(next) = starts_raw_string(bytes, cursor) {
                cursor = next;
                continue;
            }
            if bytes[cursor] == b'"' {
                in_string = true;
                escaped = false;
            }
            cursor += 1;
            continue;
        }

        if escaped {
            escaped = false;
        } else if bytes[cursor] == b'\\' {
            escaped = true;
        } else if bytes[cursor] == b'"' {
            in_string = false;
        }
        cursor += 1;
    }
    false
}

fn raw_panic_locations(body: &str) -> Vec<usize> {
    body.lines()
        .enumerate()
        .filter_map(|(index, line)| line_has_raw_panic_macro(line).then_some(index + 1))
        .collect()
}

#[test]
fn every_paired_gate_test_avoids_raw_panic_macro() -> TestResult {
    let root = workspace_root()?;
    let tests_dir = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("tests");
    let entries =
        std::fs::read_dir(&tests_dir).map_err(|e| format!("read_dir {tests_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(stem) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !stem.ends_with("_cli_contract_test.rs") {
            continue;
        }
        if stem.starts_with("cli_contract_") || stem.starts_with("harness_subcommand_") {
            continue;
        }

        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let lines = raw_panic_locations(&body);
        if !lines.is_empty() {
            violations.push(format!(
                "{stem}: raw panic! macro call(s) at line(s) {lines:?}; return TestResult errors instead"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 paired CLI contract gate tests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired gate raw-panic violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn raw_panic_scanner_ignores_comments_and_string_literals() {
    let body = r##"
fn helper() {
    // panic!("commented panic is fine");
    let plain = "panic!(inside a string)";
    let raw = r#"panic!(inside a raw string)"#;
    panic!("raw macro call");
}
"##;
    assert_eq!(raw_panic_locations(body), vec![6]);
    assert!(line_has_raw_panic_macro("    panic!(\"direct\");"));
    assert!(!line_has_raw_panic_macro("    // panic!(\"comment\");"));
    assert!(!line_has_raw_panic_macro("    let s = \"panic!(string)\";"));
}
