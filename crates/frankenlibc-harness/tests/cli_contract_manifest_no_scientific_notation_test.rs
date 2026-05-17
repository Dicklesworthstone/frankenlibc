//! Meta-gate: no `*_cli_contract.v1.json` manifest contains a JSON
//! number written in scientific notation (`e+`, `e-`, `E+`, `E-`)
//! (bd-ipr2p). Manifest numbers are mostly small counts and limits —
//! scientific notation indicates a serializer bug (e.g. a u64 that
//! overflowed into f64) or accidental floating-point conversion that
//! loses precision for round-trip equality checks downstream.

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

/// String-aware scanner that flags `e+`/`e-`/`E+`/`E-` between a
/// digit and a sign-or-digit, ignoring matches inside JSON string
/// literals (so a substring like `"e+rror"` doesn't trip).
fn contains_scientific_notation(body: &str) -> bool {
    let mut in_string = false;
    let mut escape = false;
    let bytes = body.as_bytes();
    for i in 0..bytes.len() {
        let c = bytes[i];
        if escape {
            escape = false;
            continue;
        }
        if c == b'\\' && in_string {
            escape = true;
            continue;
        }
        if c == b'"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if (c == b'e' || c == b'E') && i > 0 && i + 1 < bytes.len() {
            let prev = bytes[i - 1];
            let next = bytes[i + 1];
            if prev.is_ascii_digit() && (next == b'+' || next == b'-' || next.is_ascii_digit()) {
                return true;
            }
        }
    }
    false
}

#[test]
fn no_cli_contract_manifest_contains_scientific_notation() -> TestResult {
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
        if contains_scientific_notation(&body) {
            violations.push(format!(
                "{name}: contains scientific-notation number (e+/e-/E+/E- after digit)"
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
            "{} scientific-notation violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn scientific_notation_detector_handles_canonical_forms() {
    assert!(contains_scientific_notation("1e10"));
    assert!(contains_scientific_notation("3.14e+5"));
    assert!(contains_scientific_notation("9.8E-3"));
    assert!(!contains_scientific_notation("3.14"));
    assert!(!contains_scientific_notation("\"prefix\""));
    assert!(!contains_scientific_notation("\"contains e+rror\""));
    assert!(!contains_scientific_notation("\"1e10 inside string\""));
}
