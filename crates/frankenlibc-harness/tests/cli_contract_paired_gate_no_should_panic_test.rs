//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` declares a `#[should_panic]`
//! attribute (bd-elzky). Gate tests must report failures via
//! `TestResult`, not via expected panics, because panic-based
//! assertions don't preserve the violation context needed for
//! forensic triage of conformance regressions.

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

fn count_should_panic_attributes(body: &str) -> usize {
    body.lines()
        .filter(|line| line.trim_start().starts_with("#[should_panic"))
        .count()
}

#[test]
fn no_paired_gate_test_declares_should_panic_attribute() -> TestResult {
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
        let count = count_should_panic_attributes(&body);
        if count > 0 {
            violations.push(format!(
                "{stem}: declares {count} `#[should_panic]` attribute(s)"
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
            "{} paired gate test #[should_panic] violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn should_panic_counter_handles_canonical_forms() {
    assert_eq!(
        count_should_panic_attributes("#[should_panic]\nfn t() {}"),
        1
    );
    assert_eq!(
        count_should_panic_attributes("  #[should_panic(expected = \"x\")]\nfn t() {}"),
        1
    );
    assert_eq!(
        count_should_panic_attributes("// #[should_panic]\nfn t() {}"),
        0
    );
    assert_eq!(count_should_panic_attributes("fn t() {}"), 0);
}
