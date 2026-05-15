//! Guardrails for CLI contract tests.
//!
//! The CLI contract test family should fail with ordinary `Result` errors so a
//! malformed harness response reports the exact contract breach instead of a
//! test-side panic.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const FORBIDDEN_SURFACES: [&str; 3] = [".unwrap(", ".expect(", "panic!("];
const COMPLETION_CONTRACT_PANIC_SURFACES: [&str; 6] = [
    ".unwrap(",
    ".expect(",
    "panic!(",
    "unreachable!(",
    "todo!(",
    "unimplemented!(",
];
// Ratchet ceilings are the current measured inventory. Cleanup waves should lower
// these numbers after replacing direct panics with checked `Result` paths.
const COMPLETION_CONTRACT_TOTAL_SURFACE_CEILING: usize = 600;
const COMPLETION_CONTRACT_SURFACE_CEILINGS: [(&str, usize); 6] = [
    (".unwrap(", 271),
    (".expect(", 326),
    ("panic!(", 1),
    ("unreachable!(", 2),
    ("todo!(", 0),
    ("unimplemented!(", 0),
];

#[derive(Debug)]
struct PanicSurface {
    file: String,
    line_number: usize,
    needle: &'static str,
    source: String,
}

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

fn is_completion_contract_test(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with("_completion_contract_test.rs"))
}

fn harness_test_files(
    description: &str,
    include_path: impl Fn(&Path) -> bool,
) -> TestResult<Vec<PathBuf>> {
    let tests_dir = harness_tests_dir();
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(&tests_dir)? {
        let path = entry?.path();
        if include_path(&path) {
            paths.push(path);
        }
    }
    paths.sort();
    if paths.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no {description} found under {}", tests_dir.display()),
        )
        .into());
    }
    Ok(paths)
}

fn cli_contract_tests() -> TestResult<Vec<PathBuf>> {
    harness_test_files("CLI contract tests", is_cli_contract_test)
}

fn completion_contract_tests() -> TestResult<Vec<PathBuf>> {
    harness_test_files("completion contract tests", is_completion_contract_test)
}

fn relative_to_tests_dir(path: &Path) -> String {
    let tests_dir = harness_tests_dir();
    match path.strip_prefix(&tests_dir) {
        Ok(relative) => relative.display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

fn panic_surface_inventory(
    paths: Vec<PathBuf>,
    needles: &'static [&'static str],
) -> TestResult<Vec<PanicSurface>> {
    let mut inventory = Vec::new();
    for path in paths {
        let relative_path = relative_to_tests_dir(&path);
        let text = std::fs::read_to_string(&path)?;
        for (line_index, line) in text.lines().enumerate() {
            for &needle in needles {
                if line.contains(needle) {
                    inventory.push(PanicSurface {
                        file: relative_path.clone(),
                        line_number: line_index + 1,
                        needle,
                        source: line.trim().to_string(),
                    });
                }
            }
        }
    }
    Ok(inventory)
}

fn surface_count(inventory: &[PanicSurface], needle: &str) -> usize {
    inventory
        .iter()
        .filter(|surface| surface.needle == needle)
        .count()
}

fn top_surface_files(inventory: &[PanicSurface], limit: usize) -> String {
    let mut counts_by_file = BTreeMap::new();
    for surface in inventory {
        *counts_by_file.entry(surface.file.clone()).or_insert(0usize) += 1;
    }

    let mut counts: Vec<(String, usize)> = counts_by_file.into_iter().collect();
    counts.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    counts
        .into_iter()
        .take(limit)
        .map(|(file, count)| format!("{count:>4} {file}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn sample_surfaces(inventory: &[PanicSurface], limit: usize) -> String {
    inventory
        .iter()
        .take(limit)
        .map(|surface| {
            format!(
                "{}:{} contains `{}`: {}",
                surface.file, surface.line_number, surface.needle, surface.source
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn cli_contract_tests_avoid_direct_panic_surfaces() -> TestResult {
    let violations = panic_surface_inventory(cli_contract_tests()?, &FORBIDDEN_SURFACES)?;

    if violations.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "CLI contract tests must use checked Result paths, not direct panic surfaces:\n{}",
                sample_surfaces(&violations, violations.len())
            ),
        )
        .into())
    }
}

#[test]
fn completion_contract_panic_surface_inventory_does_not_grow() -> TestResult {
    let inventory = panic_surface_inventory(
        completion_contract_tests()?,
        &COMPLETION_CONTRACT_PANIC_SURFACES,
    )?;
    let mut violations = Vec::new();

    if inventory.len() > COMPLETION_CONTRACT_TOTAL_SURFACE_CEILING {
        violations.push(format!(
            "total direct panic surfaces grew from {} to {}",
            COMPLETION_CONTRACT_TOTAL_SURFACE_CEILING,
            inventory.len()
        ));
    }

    for (needle, ceiling) in COMPLETION_CONTRACT_SURFACE_CEILINGS {
        let actual = surface_count(&inventory, needle);
        if actual > ceiling {
            violations.push(format!(
                "`{needle}` count grew from baseline {ceiling} to {actual}"
            ));
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "completion contract direct panic-surface inventory regressed:\n{}\n\nTop files:\n{}\n\nSample surfaces:\n{}",
                violations.join("\n"),
                top_surface_files(&inventory, 15),
                sample_surfaces(&inventory, 25)
            ),
        )
        .into())
    }
}
