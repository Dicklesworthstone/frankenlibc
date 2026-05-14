//! Guardrails for CLI contract tests.
//!
//! The CLI contract test family should fail with ordinary `Result` errors so a
//! malformed harness response reports the exact contract breach instead of a
//! test-side panic.

use std::io;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const FORBIDDEN_SURFACES: [&str; 3] = [".unwrap(", ".expect(", "panic!("];

fn harness_tests_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn is_cli_contract_test(path: &Path) -> bool {
    match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => {
            name.ends_with("_cli_contract_test.rs") || name == "check_ordering_pack_cli_test.rs"
        }
        None => false,
    }
}

fn cli_contract_tests() -> TestResult<Vec<PathBuf>> {
    let tests_dir = harness_tests_dir();
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(&tests_dir)? {
        let path = entry?.path();
        if is_cli_contract_test(&path) {
            paths.push(path);
        }
    }
    paths.sort();
    if paths.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no CLI contract tests found under {}", tests_dir.display()),
        )
        .into());
    }
    Ok(paths)
}

fn relative_to_tests_dir(path: &Path) -> String {
    let tests_dir = harness_tests_dir();
    match path.strip_prefix(&tests_dir) {
        Ok(relative) => relative.display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

#[test]
fn cli_contract_tests_avoid_direct_panic_surfaces() -> TestResult {
    let mut violations = Vec::new();
    for path in cli_contract_tests()? {
        let text = std::fs::read_to_string(&path)?;
        for (line_index, line) in text.lines().enumerate() {
            for needle in FORBIDDEN_SURFACES {
                if line.contains(needle) {
                    violations.push(format!(
                        "{}:{} contains `{needle}`: {}",
                        relative_to_tests_dir(&path),
                        line_index + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "CLI contract tests must use checked Result paths, not direct panic surfaces:\n{}",
                violations.join("\n")
            ),
        )
        .into())
    }
}
