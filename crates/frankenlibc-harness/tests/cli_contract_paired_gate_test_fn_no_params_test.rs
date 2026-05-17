//! Meta-gate: in every paired `*_cli_contract_test.rs`, every `fn`
//! declared immediately under a `#[test]` attribute takes zero
//! parameters (bd-dit8c). Catches accidental refactor leftover where
//! a helper signature ended up under a `#[test]` (which the Rust test
//! framework would reject at compile time, but this gate fails-fast
//! with a clearer message at the source-shape level).

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

fn test_fns_with_params(body: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let lines: Vec<&str> = body.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if !line.trim_start().starts_with("#[test]") {
            continue;
        }
        // Find next non-blank, non-attribute line.
        let mut j = i + 1;
        while j < lines.len() {
            let t = lines[j].trim_start();
            if t.is_empty() || t.starts_with("#[") {
                j += 1;
                continue;
            }
            break;
        }
        if j >= lines.len() {
            continue;
        }
        let fn_line = lines[j].trim_start();
        if let Some(rest) = fn_line.strip_prefix("fn ")
            && let Some(open) = rest.find('(')
            && let Some(close) = rest[open + 1..].find(')')
        {
            let params = rest[open + 1..open + 1 + close].trim();
            if !params.is_empty() {
                let fn_name = rest[..open].trim();
                hits.push(format!("{fn_name}({params})"));
            }
        }
    }
    hits
}

#[test]
fn no_paired_gate_test_fn_takes_parameters() -> TestResult {
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
        let hits = test_fns_with_params(&body);
        if !hits.is_empty() {
            violations.push(format!(
                "{stem}: {} #[test] fn(s) with parameters: {hits:?}",
                hits.len()
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
            "{} paired gate #[test] fn-with-params violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn test_fn_param_detector_handles_canonical_forms() {
    let no_params = "#[test]\nfn t() {}\n";
    assert!(test_fns_with_params(no_params).is_empty());
    let with_params = "#[test]\nfn t(x: &str) {}\n";
    assert_eq!(test_fns_with_params(with_params).len(), 1);
    let with_result = "#[test]\nfn t() -> TestResult {}\n";
    assert!(test_fns_with_params(with_result).is_empty());
    let nested_attr = "#[test]\n#[ignore]\nfn t() {}\n";
    assert!(test_fns_with_params(nested_attr).is_empty());
}
