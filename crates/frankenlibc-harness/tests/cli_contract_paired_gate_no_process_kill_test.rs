//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` terminates processes
//! (bd-gt20s). Static CLI contract gates should only run the harness
//! subcommand under test; process termination probes belong in
//! explicit integration/e2e lanes with isolated artifacts.

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

fn paired_gate_paths(root: &Path) -> TestResult<Vec<PathBuf>> {
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

fn strip_line_comments(body: &str) -> String {
    let mut stripped = String::with_capacity(body.len());
    for line in body.lines() {
        let bytes = line.as_bytes();
        let mut cut = bytes.len();
        let mut idx = 0usize;
        let mut in_string = false;
        let mut escaped = false;
        while idx + 1 < bytes.len() {
            let b = bytes[idx];
            if in_string {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'"' {
                    in_string = false;
                }
            } else if b == b'"' {
                in_string = true;
            } else if b == b'/' && bytes[idx + 1] == b'/' {
                cut = idx;
                break;
            }
            idx += 1;
        }
        stripped.push_str(&line[..cut]);
        stripped.push('\n');
    }
    stripped
}

fn process_termination_needles() -> Vec<String> {
    vec![
        ["std", "::", "process", "::", "exit"].concat(),
        ["Child", "::", "kill"].concat(),
        [".", "kill", "("].concat(),
        ["libc", "::", "kill"].concat(),
        ["nix", "::", "sys", "::", "signal", "::", "kill"].concat(),
        ["Command", "::", "new", "(\"", "kill", "\")"].concat(),
        ["Command", "::", "new", "(\"", "p", "kill", "\")"].concat(),
        ["Command", "::", "new", "(\"", "kill", "all", "\")"].concat(),
    ]
}

fn process_termination_hazards(body: &str) -> Vec<String> {
    let searchable = strip_line_comments(body);
    process_termination_needles()
        .into_iter()
        .filter(|needle| searchable.contains(needle))
        .collect()
}

fn contains_process_termination_hazard(body: &str) -> bool {
    !process_termination_hazards(body).is_empty()
}

#[test]
fn no_paired_cli_contract_gate_terminates_processes() -> TestResult {
    let root = workspace_root()?;
    let paths = paired_gate_paths(&root)?;
    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for path in paths {
        let Some(stem) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let hazards = process_termination_hazards(&body);
        if !hazards.is_empty() {
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
            "{} paired gate process-termination API violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn process_termination_detector_handles_canonical_spellings() {
    let process_exit = ["std", "::", "process", "::", "exit"].concat();
    let child_kill = ["child", ".", "kill", "()"].concat();
    let child_assoc_kill = ["Child", "::", "kill"].concat();
    let libc_kill = ["libc", "::", "kill"].concat();
    let nix_kill = ["nix", "::", "sys", "::", "signal", "::", "kill"].concat();
    let kill_command = ["Command", "::", "new", "(\"", "kill", "\")"].concat();
    let pkill_command = ["Command", "::", "new", "(\"", "p", "kill", "\")"].concat();
    let killall_command = ["Command", "::", "new", "(\"", "kill", "all", "\")"].concat();

    assert!(contains_process_termination_hazard(&format!(
        "{process_exit}(1);"
    )));
    assert!(contains_process_termination_hazard(&format!(
        "let _ = {child_kill};"
    )));
    assert!(contains_process_termination_hazard(&format!(
        "let _ = {child_assoc_kill}(&mut child);"
    )));
    assert!(contains_process_termination_hazard(&format!(
        "let _ = {libc_kill}(pid, 9);"
    )));
    assert!(contains_process_termination_hazard(&format!(
        "let _ = {nix_kill}(pid, signal);"
    )));
    assert!(contains_process_termination_hazard(&format!(
        "let _ = {kill_command}.arg(\"-9\").arg(pid);"
    )));
    assert!(contains_process_termination_hazard(&format!(
        "let _ = {pkill_command}.arg(\"name\");"
    )));
    assert!(contains_process_termination_hazard(&format!(
        "let _ = {killall_command}.arg(\"name\");"
    )));
}

#[test]
fn process_termination_detector_ignores_comments_and_normal_spawns() {
    let process_exit = ["std", "::", "process", "::", "exit"].concat();
    let child_kill = ["child", ".", "kill", "()"].concat();

    assert!(!contains_process_termination_hazard(&format!(
        "// {process_exit}(1);"
    )));
    assert!(!contains_process_termination_hazard(&format!(
        "// let _ = {child_kill};"
    )));
    assert!(!contains_process_termination_hazard(
        "Command::new(&harness).arg(\"--output\").arg(&report);"
    ));
    assert!(!contains_process_termination_hazard(
        "let kill_switch_label = \"documented but not executable\";"
    ));
}
