//! Meta-gate: paired `*_cli_contract_test.rs` files must not call raw
//! `panic!` directly (bd-795fi), declare `#[should_panic]` (bd-elzky), or
//! call `.unwrap()` directly (bd-tp45o). Gate tests should propagate
//! contextual failures through `TestResult` instead of aborting from
//! ad-hoc panic sites.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

#[derive(Clone, Copy)]
enum AttributeScanState {
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

fn starts_raw_string(bytes: &[u8], index: usize) -> Option<usize> {
    let (mut cursor, hash_count) = raw_string_start(bytes, index)?;
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

fn line_starts_should_panic_attribute(line: &str) -> bool {
    let Some(rest) = line.trim_start().strip_prefix("#[should_panic") else {
        return false;
    };
    matches!(rest.trim_start().chars().next(), Some(']' | '=' | '('))
}

fn scan_should_panic_line(line: &str, mut state: AttributeScanState) -> (bool, AttributeScanState) {
    let found =
        matches!(state, AttributeScanState::Code) && line_starts_should_panic_attribute(line);
    let bytes = line.as_bytes();
    let mut cursor = 0usize;

    while cursor < bytes.len() {
        match state {
            AttributeScanState::Code => {
                if bytes.get(cursor) == Some(&b'/') && bytes.get(cursor + 1) == Some(&b'/') {
                    return (found, AttributeScanState::Code);
                }
                if bytes.get(cursor) == Some(&b'/') && bytes.get(cursor + 1) == Some(&b'*') {
                    state = AttributeScanState::BlockComment { depth: 1 };
                    cursor += 2;
                    continue;
                }
                if let Some((next, hashes)) = raw_string_start(bytes, cursor) {
                    state = AttributeScanState::RawString { hashes };
                    cursor = next;
                    continue;
                }
                if bytes[cursor] == b'"' {
                    state = AttributeScanState::String { escaped: false };
                }
                cursor += 1;
            }
            AttributeScanState::BlockComment { depth } => {
                if bytes.get(cursor) == Some(&b'/') && bytes.get(cursor + 1) == Some(&b'*') {
                    state = AttributeScanState::BlockComment { depth: depth + 1 };
                    cursor += 2;
                } else if bytes.get(cursor) == Some(&b'*') && bytes.get(cursor + 1) == Some(&b'/') {
                    state = if depth == 1 {
                        AttributeScanState::Code
                    } else {
                        AttributeScanState::BlockComment { depth: depth - 1 }
                    };
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            AttributeScanState::String { escaped } => {
                if escaped {
                    state = AttributeScanState::String { escaped: false };
                } else if bytes[cursor] == b'\\' {
                    state = AttributeScanState::String { escaped: true };
                } else if bytes[cursor] == b'"' {
                    state = AttributeScanState::Code;
                }
                cursor += 1;
            }
            AttributeScanState::RawString { hashes } => {
                if bytes[cursor] == b'"' {
                    let hashes_end = cursor + 1 + hashes;
                    if hashes_end <= bytes.len()
                        && bytes[cursor + 1..hashes_end]
                            .iter()
                            .all(|byte| *byte == b'#')
                    {
                        state = AttributeScanState::Code;
                        cursor = hashes_end;
                        continue;
                    }
                }
                cursor += 1;
            }
        }
    }

    if matches!(state, AttributeScanState::String { escaped: true }) {
        state = AttributeScanState::String { escaped: false };
    }
    (found, state)
}

fn should_panic_attribute_locations(body: &str) -> Vec<usize> {
    let mut state = AttributeScanState::Code;
    let mut lines = Vec::new();
    for (index, line) in body.lines().enumerate() {
        let (found, next) = scan_should_panic_line(line, state);
        if found {
            lines.push(index + 1);
        }
        state = next;
    }
    lines
}

fn method_call_starts_at(bytes: &[u8], index: usize, method: &[u8]) -> bool {
    if !bytes[index..].starts_with(method) {
        return false;
    }
    let mut cursor = index + method.len();
    while matches!(bytes.get(cursor), Some(byte) if byte.is_ascii_whitespace()) {
        cursor += 1;
    }
    bytes.get(cursor) == Some(&b'(')
}

fn scan_method_call_line(
    line: &str,
    mut state: AttributeScanState,
    method: &[u8],
) -> (bool, AttributeScanState) {
    let bytes = line.as_bytes();
    let mut cursor = 0usize;

    while cursor < bytes.len() {
        match state {
            AttributeScanState::Code => {
                if bytes.get(cursor) == Some(&b'/') && bytes.get(cursor + 1) == Some(&b'/') {
                    return (false, AttributeScanState::Code);
                }
                if bytes.get(cursor) == Some(&b'/') && bytes.get(cursor + 1) == Some(&b'*') {
                    state = AttributeScanState::BlockComment { depth: 1 };
                    cursor += 2;
                    continue;
                }
                if method_call_starts_at(bytes, cursor, method) {
                    return (true, state);
                }
                if let Some((next, hashes)) = raw_string_start(bytes, cursor) {
                    state = AttributeScanState::RawString { hashes };
                    cursor = next;
                    continue;
                }
                if bytes[cursor] == b'"' {
                    state = AttributeScanState::String { escaped: false };
                }
                cursor += 1;
            }
            AttributeScanState::BlockComment { depth } => {
                if bytes.get(cursor) == Some(&b'/') && bytes.get(cursor + 1) == Some(&b'*') {
                    state = AttributeScanState::BlockComment { depth: depth + 1 };
                    cursor += 2;
                } else if bytes.get(cursor) == Some(&b'*') && bytes.get(cursor + 1) == Some(&b'/') {
                    state = if depth == 1 {
                        AttributeScanState::Code
                    } else {
                        AttributeScanState::BlockComment { depth: depth - 1 }
                    };
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            AttributeScanState::String { escaped } => {
                if escaped {
                    state = AttributeScanState::String { escaped: false };
                } else if bytes[cursor] == b'\\' {
                    state = AttributeScanState::String { escaped: true };
                } else if bytes[cursor] == b'"' {
                    state = AttributeScanState::Code;
                }
                cursor += 1;
            }
            AttributeScanState::RawString { hashes } => {
                if bytes[cursor] == b'"' {
                    let hashes_end = cursor + 1 + hashes;
                    if hashes_end <= bytes.len()
                        && bytes[cursor + 1..hashes_end]
                            .iter()
                            .all(|byte| *byte == b'#')
                    {
                        state = AttributeScanState::Code;
                        cursor = hashes_end;
                        continue;
                    }
                }
                cursor += 1;
            }
        }
    }

    if matches!(state, AttributeScanState::String { escaped: true }) {
        state = AttributeScanState::String { escaped: false };
    }
    (false, state)
}

fn method_call_locations(body: &str, method: &[u8]) -> Vec<usize> {
    let mut state = AttributeScanState::Code;
    let mut lines = Vec::new();
    for (index, line) in body.lines().enumerate() {
        let (found, next) = scan_method_call_line(line, state, method);
        if found {
            lines.push(index + 1);
        }
        state = next;
    }
    lines
}

fn unwrap_call_locations(body: &str) -> Vec<usize> {
    method_call_locations(body, b".unwrap")
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
fn every_paired_gate_test_avoids_should_panic_attribute() -> TestResult {
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
        let lines = should_panic_attribute_locations(&body);
        if !lines.is_empty() {
            violations.push(format!(
                "{stem}: #[should_panic] attribute(s) at line(s) {lines:?}; return TestResult errors instead"
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
            "{} paired gate should-panic violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn every_paired_gate_test_avoids_unwrap_call() -> TestResult {
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
        let lines = unwrap_call_locations(&body);
        if !lines.is_empty() {
            violations.push(format!(
                "{stem}: .unwrap() call(s) at line(s) {lines:?}; return TestResult errors instead"
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
            "{} paired gate unwrap violation(s):\n  {}",
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

#[test]
fn should_panic_scanner_handles_canonical_forms() {
    assert_eq!(
        should_panic_attribute_locations("#[should_panic]\nfn test_case() {}"),
        vec![1]
    );
    assert_eq!(
        should_panic_attribute_locations("#[should_panic(expected = \"boom\")]\nfn test_case() {}"),
        vec![1]
    );
    assert_eq!(
        should_panic_attribute_locations("// #[should_panic]\nfn test_case() {}"),
        Vec::<usize>::new()
    );
    assert_eq!(
        should_panic_attribute_locations("/*\n#[should_panic]\n*/\nfn test_case() {}"),
        Vec::<usize>::new()
    );
    assert_eq!(
        should_panic_attribute_locations(
            "let text = \"\\\n#[should_panic]\\\n\";\nfn test_case() {}"
        ),
        Vec::<usize>::new()
    );
    assert_eq!(
        should_panic_attribute_locations(
            "let text = r#\"\n#[should_panic]\n\"#;\nfn test_case() {}"
        ),
        Vec::<usize>::new()
    );
}

#[test]
fn unwrap_scanner_handles_canonical_forms() {
    let body = r##"
fn helper() -> TestResult {
    let plain = "value.unwrap()";
    let raw = r#"value.unwrap()"#;
    // value.unwrap()
    /*
    value.unwrap()
    */
    value.unwrap();
    value
        .unwrap ();
    value.unwrap_err();
    Ok(())
}
"##;
    assert_eq!(unwrap_call_locations(body), vec![9, 11]);
    assert_eq!(
        unwrap_call_locations("/*\nvalue.unwrap()\n*/\nfn test_case() {}"),
        Vec::<usize>::new()
    );
    assert_eq!(
        unwrap_call_locations("let text = \"\\\nvalue.unwrap()\\\n\";\nfn test_case() {}"),
        Vec::<usize>::new()
    );
    assert_eq!(
        unwrap_call_locations("let text = r#\"\nvalue.unwrap()\n\"#;\nfn test_case() {}"),
        Vec::<usize>::new()
    );
}
