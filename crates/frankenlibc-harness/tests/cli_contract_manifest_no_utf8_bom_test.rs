//! Meta-gate: no `*_cli_contract.v1.json` file under
//! `tests/conformance/` starts with a UTF-8 BOM (bd-wa2cg). JSON's
//! strict-mode parsers reject BOM-prefixed bytes per RFC 8259 §8.1;
//! defense-in-depth against editor-introduced corruption.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn no_cli_contract_manifest_starts_with_utf8_bom() -> TestResult {
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
        if bytes.starts_with(UTF8_BOM) {
            violations.push(format!("{name}: starts with UTF-8 BOM"));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} cli_contract manifest UTF-8 BOM violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
