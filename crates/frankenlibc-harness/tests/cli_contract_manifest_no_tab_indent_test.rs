//! Meta-gate: no `*_cli_contract.v1.json` manifest uses leading
//! tab characters for indentation (bd-2q5tj). Tabs render
//! inconsistently across editors, break JSON canonicalization
//! assumptions in downstream consumers, and cause spurious diffs
//! when contributors with different tab widths reformat files.
//! All manifests must use the canonical 2-space indentation.

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

fn has_tab_indented_line(body: &str) -> bool {
    body.lines().any(|line| line.starts_with('\t'))
}

#[test]
fn no_cli_contract_manifest_uses_tab_indentation() -> TestResult {
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
        if has_tab_indented_line(&body) {
            violations.push(format!(
                "{name}: has line(s) starting with tab character (must use spaces)"
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
            "{} manifest tab-indent violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn tab_indent_detector_handles_canonical_forms() {
    assert!(has_tab_indented_line("\t\"key\": \"value\""));
    assert!(has_tab_indented_line("  spaces ok\n\ttab here"));
    assert!(!has_tab_indented_line("  \"key\": \"value\""));
    assert!(!has_tab_indented_line("{\n  \"key\": 1\n}"));
}
