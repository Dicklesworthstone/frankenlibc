//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` mutates or overrides the working
//! directory (bd-92g0t). Paired CLI contract gates should pass explicit
//! paths to the harness and avoid hidden cwd coupling; integration/e2e lanes
//! need an explicit manifest classification before they may opt into cwd
//! control.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn tracked_paired_gate_paths(root: &Path) -> TestResult<Vec<PathBuf>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "ls-files",
            "--",
            "crates/frankenlibc-harness/tests/*_cli_contract_test.rs",
        ])
        .output()
        .map_err(|e| format!("git ls-files failed to start: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "git ls-files failed with status {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let tracked: Vec<PathBuf> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| root.join(line))
        .collect();
    if !tracked.is_empty() {
        return Ok(tracked);
    }

    checked_out_paired_gate_paths(root)
}

fn checked_out_paired_gate_paths(root: &Path) -> TestResult<Vec<PathBuf>> {
    let test_dir = root.join("crates/frankenlibc-harness/tests");
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(&test_dir).map_err(|e| format!("read_dir {test_dir:?}: {e}"))? {
        let entry = entry.map_err(|e| format!("read_dir entry {test_dir:?}: {e}"))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.ends_with("_cli_contract_test.rs") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn strip_comments_and_string_literals(body: &str) -> String {
    let mut stripped = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut in_string = false;
    let mut in_char = false;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
                stripped.push('\n');
            } else {
                stripped.push(' ');
            }
            continue;
        }
        if in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
                stripped.push(' ');
                stripped.push(' ');
            } else if ch == '\n' {
                stripped.push('\n');
            } else {
                stripped.push(' ');
            }
            continue;
        }
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            stripped.push(if ch == '\n' { '\n' } else { ' ' });
            continue;
        }
        if in_char {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '\'' {
                in_char = false;
            }
            stripped.push(if ch == '\n' { '\n' } else { ' ' });
            continue;
        }

        if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            in_line_comment = true;
            stripped.push(' ');
            stripped.push(' ');
        } else if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            in_block_comment = true;
            stripped.push(' ');
            stripped.push(' ');
        } else if ch == '"' {
            in_string = true;
            stripped.push(' ');
        } else if ch == '\'' {
            in_char = true;
            stripped.push(' ');
        } else {
            stripped.push(ch);
        }
    }

    stripped
}

fn current_dir_mutation_needles() -> Vec<String> {
    vec![
        ["std", "::", "env", "::", "set_current_dir"].concat(),
        ["env", "::", "set_current_dir"].concat(),
        ["Command", "::", "current_dir"].concat(),
        [".", "current_dir", "("].concat(),
    ]
}

fn current_dir_mutation_hazards(body: &str) -> Vec<String> {
    let searchable = strip_comments_and_string_literals(body);
    current_dir_mutation_needles()
        .into_iter()
        .filter(|needle| searchable.contains(needle))
        .collect()
}

fn contains_current_dir_mutation_hazard(body: &str) -> bool {
    !current_dir_mutation_hazards(body).is_empty()
}

fn manifest_path_for_gate(root: &Path, gate_path: &Path) -> Option<PathBuf> {
    let name = gate_path.file_name()?.to_str()?;
    let manifest_name = name.strip_suffix("_test.rs")?.to_owned() + ".v1.json";
    Some(root.join("tests").join("conformance").join(manifest_name))
}

fn value_has_integration_lane(value: &Value) -> bool {
    match value {
        Value::String(text) => {
            let lower = text.to_ascii_lowercase();
            lower.contains("integration") || lower.contains("e2e")
        }
        Value::Array(items) => items.iter().any(value_has_integration_lane),
        Value::Object(map) => map.values().any(value_has_integration_lane),
        _ => false,
    }
}

fn manifest_explicitly_allows_current_dir(root: &Path, gate_path: &Path) -> TestResult<bool> {
    let Some(manifest_path) = manifest_path_for_gate(root, gate_path) else {
        return Ok(false);
    };
    if !manifest_path.is_file() {
        return Ok(false);
    }
    let body = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("read manifest {manifest_path:?}: {e}"))?;
    let manifest: Value = serde_json::from_str(&body)
        .map_err(|e| format!("parse manifest {manifest_path:?}: {e}"))?;

    let explicit_allow = manifest
        .get("policy")
        .and_then(|policy| policy.get("allow_current_dir_mutation"))
        .and_then(Value::as_bool)
        == Some(true);
    Ok(explicit_allow && value_has_integration_lane(&manifest))
}

#[test]
fn no_paired_cli_contract_gate_mutates_current_dir() -> TestResult {
    let root = workspace_root()?;
    let paths = tracked_paired_gate_paths(&root)?;
    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for path in paths {
        let Some(stem) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let hazards = current_dir_mutation_hazards(&body);
        if !hazards.is_empty() && !manifest_explicitly_allows_current_dir(&root, &path)? {
            violations.push(format!("{stem}: {}", hazards.join(", ")));
        }
        checked += 1;
    }

    assert!(
        checked >= 60,
        "expected at least 60 tracked paired CLI contract gate tests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired gate current-dir mutation violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn current_dir_mutation_detector_handles_canonical_spellings() {
    let std_env_set_current_dir = ["std", "::", "env", "::", "set_current_dir"].concat();
    let env_set_current_dir = ["env", "::", "set_current_dir"].concat();
    let command_assoc_current_dir = ["Command", "::", "current_dir"].concat();
    let command_method_current_dir = [".", "current_dir", "("].concat();

    assert!(contains_current_dir_mutation_hazard(&format!(
        "{std_env_set_current_dir}(&root)?;"
    )));
    assert!(contains_current_dir_mutation_hazard(&format!(
        "{env_set_current_dir}(\"/tmp\")?;"
    )));
    assert!(contains_current_dir_mutation_hazard(&format!(
        "let _ = {command_assoc_current_dir}(&mut cmd, root);"
    )));
    assert!(contains_current_dir_mutation_hazard(&format!(
        "Command::new(bin){command_method_current_dir}&root);"
    )));
}

#[test]
fn current_dir_mutation_detector_ignores_comments_and_literals() {
    let std_env_set_current_dir = ["std", "::", "env", "::", "set_current_dir"].concat();
    let command_method_current_dir = [".", "current_dir", "("].concat();

    assert!(!contains_current_dir_mutation_hazard(&format!(
        "// {std_env_set_current_dir}(&root)?;"
    )));
    assert!(!contains_current_dir_mutation_hazard(&format!(
        "/* Command::new(bin){command_method_current_dir}&root); */"
    )));
    assert!(!contains_current_dir_mutation_hazard(&format!(
        "let text = \"Command::new(bin){command_method_current_dir}&root);\";"
    )));
    assert!(!contains_current_dir_mutation_hazard(
        "let field = 'c'; let current_dir_label = \"documented\";"
    ));
}
