//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` opens network sockets or uses
//! network-capable client helpers (bd-e8xvs). CLI contract gates must
//! stay deterministic and offline; networked behavior belongs in an
//! explicit integration/e2e lane with artifacts.

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

fn network_hazard_needles() -> Vec<String> {
    vec![
        ["std", "::", "net", "::"].concat(),
        ["Tcp", "Stream"].concat(),
        ["Tcp", "Listener"].concat(),
        ["Udp", "Socket"].concat(),
        ["Unix", "Stream"].concat(),
        ["req", "west", "::"].concat(),
        ["ure", "q", "::"].concat(),
        ["hyper", "::"].concat(),
        ["curl", "::"].concat(),
        ["surf", "::"].concat(),
        ["isahc", "::"].concat(),
        ["url", "::", "Url"].concat(),
        ["Url", "::", "parse"].concat(),
        ["http", "::", "Uri"].concat(),
        ["Command", "::", "new", "(\"", "curl", "\")"].concat(),
        ["Command", "::", "new", "(\"", "wget", "\")"].concat(),
        ["Command", "::", "new", "(\"", "nc", "\")"].concat(),
        ["Command", "::", "new", "(\"", "netcat", "\")"].concat(),
    ]
}

fn network_socket_hazards(body: &str) -> Vec<String> {
    let searchable = strip_line_comments(body);
    network_hazard_needles()
        .into_iter()
        .filter(|needle| searchable.contains(needle))
        .collect()
}

fn contains_network_socket_hazard(body: &str) -> bool {
    !network_socket_hazards(body).is_empty()
}

#[test]
fn no_paired_cli_contract_gate_opens_network_socket() -> TestResult {
    let root = workspace_root()?;
    let paths = paired_gate_paths(&root)?;
    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for path in paths {
        let Some(stem) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let hazards = network_socket_hazards(&body);
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
            "{} paired gate network-capable API violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn network_socket_detector_handles_canonical_spellings() {
    let tcp_stream = ["std", "::", "net", "::", "Tcp", "Stream", "::connect"].concat();
    let tcp_listener = ["Tcp", "Listener", "::bind"].concat();
    let udp_socket = ["Udp", "Socket", "::bind"].concat();
    let reqwest_get = ["req", "west", "::", "blocking", "::get"].concat();
    let url_literal = ["https", "://", "example.invalid"].concat();
    let curl_command = ["Command", "::", "new", "(\"", "curl", "\")"].concat();

    assert!(contains_network_socket_hazard(&format!(
        "let _ = {tcp_stream}(\"127.0.0.1:80\");"
    )));
    assert!(contains_network_socket_hazard(&format!(
        "let _ = {tcp_listener}(\"127.0.0.1:0\");"
    )));
    assert!(contains_network_socket_hazard(&format!(
        "let _ = {udp_socket}(\"127.0.0.1:0\");"
    )));
    assert!(contains_network_socket_hazard(&format!(
        "let _ = {reqwest_get}(\"{url_literal}\");"
    )));
    assert!(contains_network_socket_hazard(&format!(
        "let _ = {curl_command}.arg(\"{url_literal}\");"
    )));
}

#[test]
fn network_socket_detector_ignores_comments_and_offline_command_spawns() {
    let tcp_stream = ["std", "::", "net", "::", "Tcp", "Stream", "::connect"].concat();
    let url_literal = ["https", "://", "example.invalid"].concat();

    assert!(!contains_network_socket_hazard(&format!(
        "// let _ = {tcp_stream}(\"127.0.0.1:80\");"
    )));
    assert!(!contains_network_socket_hazard(
        "Command::new(&harness).arg(\"--output\").arg(&report);"
    ));
    assert!(!contains_network_socket_hazard(&format!(
        "let _doc = \"offline fixture mentions {url_literal}\";"
    )));
}
