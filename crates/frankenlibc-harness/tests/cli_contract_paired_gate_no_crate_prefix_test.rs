//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` uses the `crate::` prefix
//! (bd-rm4e5). Integration tests under `tests/` live outside the
//! crate's namespace — `crate::foo` resolves to a confusing
//! "test-binary's crate" path rather than the crate under test. Use
//! `frankenlibc_harness::foo` (or another workspace crate name) for
//! cross-crate references instead.

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

fn count_crate_prefix_uses(body: &str) -> usize {
    // Match `crate::` with non-identifier char before it (or BOL).
    let mut n = 0usize;
    let bytes = body.as_bytes();
    let needle = b"crate::";
    for i in 0..bytes.len().saturating_sub(needle.len()) {
        if &bytes[i..i + needle.len()] != needle {
            continue;
        }
        let prev_ok = if i == 0 {
            true
        } else {
            let p = bytes[i - 1];
            !(p.is_ascii_alphanumeric() || p == b'_')
        };
        if prev_ok {
            n += 1;
        }
    }
    n
}

#[test]
fn no_paired_gate_test_uses_crate_prefix() -> TestResult {
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
        let count = count_crate_prefix_uses(&body);
        if count > 0 {
            violations.push(format!("{stem}: {count} `crate::` reference(s)"));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 paired CLI contract gate tests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired gate `crate::` violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn crate_prefix_counter_handles_canonical_forms() {
    assert_eq!(count_crate_prefix_uses("use crate::foo;"), 1);
    assert_eq!(count_crate_prefix_uses("crate::foo + crate::bar"), 2);
    // Edge case: `::crate::` is detected because `::` is non-identifier; the
    // detector matches the standalone `crate::` token regardless of context.
    assert_eq!(
        count_crate_prefix_uses("use frankenlibc_harness::crate::foo;"),
        1
    );
    assert_eq!(count_crate_prefix_uses("use my_crate::foo;"), 0);
    assert_eq!(count_crate_prefix_uses("xcrate::foo"), 0);
    assert_eq!(count_crate_prefix_uses("// crate::foo"), 1);
    assert_eq!(count_crate_prefix_uses("ok"), 0);
}
