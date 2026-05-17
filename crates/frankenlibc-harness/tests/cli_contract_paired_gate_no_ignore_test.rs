//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` declares an `#[ignore]`
//! attribute (bd-nlvof). Catches accidentally-disabled gate tests
//! that would silently pass without actually running. If a gate
//! genuinely needs to be skipped temporarily, route the skip through
//! a `cfg!()` guard or `TestResult::Ok(())` early-return — never via
//! `#[ignore]`.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

#[derive(Clone, Copy)]
enum ScanState {
    Code,
    BlockComment { depth: usize },
    String { escaped: bool },
    RawString { hashes: usize },
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn raw_string_start(bytes: &[u8], index: usize) -> Option<(usize, usize)> {
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
    Some((quote + 1, quote - raw_start))
}

fn line_starts_ignore_attribute(line: &str) -> bool {
    let Some(rest) = line.trim_start().strip_prefix("#[ignore") else {
        return false;
    };
    matches!(rest.trim_start().chars().next(), Some(']' | '=' | '('))
}

fn scan_line(line: &str, mut state: ScanState) -> (bool, ScanState) {
    let found = matches!(state, ScanState::Code) && line_starts_ignore_attribute(line);
    let bytes = line.as_bytes();
    let mut cursor = 0usize;

    while cursor < bytes.len() {
        match state {
            ScanState::Code => {
                if bytes.get(cursor) == Some(&b'/') && bytes.get(cursor + 1) == Some(&b'/') {
                    return (found, ScanState::Code);
                }
                if bytes.get(cursor) == Some(&b'/') && bytes.get(cursor + 1) == Some(&b'*') {
                    state = ScanState::BlockComment { depth: 1 };
                    cursor += 2;
                    continue;
                }
                if let Some((next, hashes)) = raw_string_start(bytes, cursor) {
                    state = ScanState::RawString { hashes };
                    cursor = next;
                    continue;
                }
                if bytes[cursor] == b'"' {
                    state = ScanState::String { escaped: false };
                }
                cursor += 1;
            }
            ScanState::BlockComment { depth } => {
                if bytes.get(cursor) == Some(&b'/') && bytes.get(cursor + 1) == Some(&b'*') {
                    state = ScanState::BlockComment { depth: depth + 1 };
                    cursor += 2;
                } else if bytes.get(cursor) == Some(&b'*') && bytes.get(cursor + 1) == Some(&b'/') {
                    state = if depth == 1 {
                        ScanState::Code
                    } else {
                        ScanState::BlockComment { depth: depth - 1 }
                    };
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            ScanState::String { escaped } => {
                if escaped {
                    state = ScanState::String { escaped: false };
                } else if bytes[cursor] == b'\\' {
                    state = ScanState::String { escaped: true };
                } else if bytes[cursor] == b'"' {
                    state = ScanState::Code;
                }
                cursor += 1;
            }
            ScanState::RawString { hashes } => {
                if bytes[cursor] == b'"' {
                    let hashes_end = cursor + 1 + hashes;
                    if hashes_end <= bytes.len()
                        && bytes[cursor + 1..hashes_end]
                            .iter()
                            .all(|byte| *byte == b'#')
                    {
                        state = ScanState::Code;
                        cursor = hashes_end;
                        continue;
                    }
                }
                cursor += 1;
            }
        }
    }

    if matches!(state, ScanState::String { escaped: true }) {
        state = ScanState::String { escaped: false };
    }
    (found, state)
}

fn count_ignore_attributes(body: &str) -> usize {
    let mut state = ScanState::Code;
    let mut count = 0usize;
    for line in body.lines() {
        let (found, next) = scan_line(line, state);
        count += usize::from(found);
        state = next;
    }
    count
}

#[test]
fn no_paired_gate_test_declares_ignore_attribute() -> TestResult {
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
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let count = count_ignore_attributes(&body);
        if count > 0 {
            violations.push(format!("{stem}: declares {count} `#[ignore]` attribute(s)"));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 paired CLI contract gate tests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired gate test #[ignore] violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn ignore_attribute_counter_handles_canonical_forms() {
    assert_eq!(count_ignore_attributes("#[ignore]\nfn t() {}"), 1);
    assert_eq!(
        count_ignore_attributes("  #[ignore = \"flaky\"]\nfn t() {}"),
        1
    );
    assert_eq!(count_ignore_attributes("// #[ignore]\nfn t() {}"), 0);
    assert_eq!(count_ignore_attributes("/*\n#[ignore]\n*/\nfn t() {}"), 0);
    assert_eq!(
        count_ignore_attributes("let text = \"\\\n#[ignore]\\\n\";\nfn t() {}"),
        0
    );
    assert_eq!(
        count_ignore_attributes("let text = r#\"\n#[ignore]\n\"#;\nfn t() {}"),
        0
    );
    assert_eq!(count_ignore_attributes("fn t() {}"), 0);
}
