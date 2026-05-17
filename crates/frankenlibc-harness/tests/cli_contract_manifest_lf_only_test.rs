//! Meta-gate: no `*_cli_contract.v1.json` file under
//! `tests/conformance/` contains CRLF line endings (bd-2rq1q). LF-
//! only is the project's POSIX convention; CRLF lines slip in from
//! Windows editors and break diff-friendly review tooling.

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

fn count_crlf_lines(bytes: &[u8]) -> usize {
    let mut n = 0usize;
    for window in bytes.windows(2) {
        if window == b"\r\n" {
            n += 1;
        }
    }
    n
}

#[test]
fn no_cli_contract_manifest_contains_crlf_line_endings() -> TestResult {
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
        let n = count_crlf_lines(&bytes);
        if n > 0 {
            violations.push(format!("{name}: {n} CRLF line ending(s)"));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} cli_contract manifest CRLF violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
