//! Host-delegation census gate for bd-smp21.1.

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_ANCHORS: &[&str] = &[
    "__libc_start_main",
    "dladdr",
    "dlclose",
    "dl_iterate_phdr",
    "dlopen",
    "dlsym",
    "pthread_create",
    "pthread_detach",
    "pthread_join",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate should live under crates/")
        .parent()
        .expect("crates/ should live under workspace root")
        .to_path_buf()
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn unique_output_path(root: &Path, label: &str, extension: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    root.join("target/conformance").join(format!(
        "host-delegation-census-{label}-{}-{stamp}.{extension}",
        std::process::id()
    ))
}

fn unique_synthetic_source_dir(root: &Path, label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    root.join("target/conformance").join(format!(
        "host-delegation-census-{label}-{}-{stamp}",
        std::process::id()
    ))
}

fn artifact(root: &Path) -> PathBuf {
    root.join("tests/conformance/host_delegation_census.v1.json")
}

#[test]
fn artifact_has_required_shape_and_anchors() -> TestResult {
    let root = workspace_root();
    let data = load_json(&artifact(&root))?;

    assert_eq!(
        data["schema_version"].as_str(),
        Some("host_delegation_census.v1")
    );
    assert_eq!(data["bead"].as_str(), Some("bd-smp21.1"));
    assert!(data["detector"].is_object(), "detector must be object");
    assert!(data["policy"].is_object(), "policy must be object");
    assert!(data["summary"].is_object(), "summary must be object");
    assert!(
        data["symbol_census"].is_array(),
        "symbol_census must be array"
    );
    assert!(
        data["callsite_census"].is_array(),
        "callsite_census must be array"
    );
    let unknown_calls = data["unknown_call_edges"]
        .as_array()
        .expect("unknown_call_edges must be array");

    let anchors: BTreeSet<_> = data["required_anchor_symbols"]
        .as_array()
        .expect("required anchors should be array")
        .iter()
        .filter(|row| row["present"].as_bool() == Some(true))
        .filter_map(|row| row["symbol"].as_str())
        .collect();
    for required in REQUIRED_ANCHORS {
        assert!(
            anchors.contains(required),
            "host delegation census missing required anchor {required}"
        );
    }
    assert_eq!(
        data["summary"]["required_anchor_present_count"].as_u64(),
        Some(REQUIRED_ANCHORS.len() as u64),
        "all required anchors must remain present"
    );

    let exported_count = data["summary"]["exported_symbol_count"]
        .as_u64()
        .expect("exported_symbol_count should be u64");
    let unknown_count = data["summary"]["unknown_call_edge_count"]
        .as_u64()
        .expect("unknown_call_edge_count should be u64");
    let exported_unknown_count = data["summary"]["exported_symbol_with_unknown_call_edge_count"]
        .as_u64()
        .expect("exported_symbol_with_unknown_call_edge_count should be u64");
    assert_eq!(unknown_count, unknown_calls.len() as u64);
    assert!(
        unknown_count < exported_count,
        "unknown-edge volume exploded: {unknown_count} edges for {exported_count} exports"
    );
    assert!(
        exported_unknown_count.saturating_mul(10) < exported_count,
        "unknown edges directly affect too much of the ABI: {exported_unknown_count} of \
         {exported_count} exports"
    );
    Ok(())
}

#[test]
fn symbol_and_callsite_counts_are_self_consistent() -> TestResult {
    let root = workspace_root();
    let data = load_json(&artifact(&root))?;
    let symbols = data["symbol_census"]
        .as_array()
        .expect("symbol census should be an array");
    let callsites = data["callsite_census"]
        .as_array()
        .expect("callsite census should be an array");

    assert_eq!(
        data["summary"]["host_delegating_symbol_count"].as_u64(),
        Some(symbols.len() as u64)
    );
    assert_eq!(
        data["summary"]["host_delegation_callsite_count"].as_u64(),
        Some(callsites.len() as u64)
    );

    let mut referenced_callsite_ids = BTreeSet::new();
    for symbol in symbols {
        let ids = symbol["callsite_ids"]
            .as_array()
            .expect("symbol callsite_ids should be array");
        assert_eq!(
            symbol["callsite_count"].as_u64(),
            Some(ids.len() as u64),
            "symbol callsite_count should match ids for {:?}",
            symbol["symbol"]
        );
        for id in ids {
            referenced_callsite_ids.insert(
                id.as_str()
                    .expect("callsite id should be string")
                    .to_string(),
            );
        }
    }

    let actual_callsite_ids: BTreeSet<_> = callsites
        .iter()
        .map(|row| {
            row["id"]
                .as_str()
                .expect("callsite id should be string")
                .to_string()
        })
        .collect();
    for row in callsites {
        assert_eq!(
            row["host_symbol"], row["exported_symbol"],
            "only same-symbol terminal host evidence may drive status derivation"
        );
        let path = row["reachability_path"]
            .as_array()
            .expect("reachability_path should be an array");
        assert!(!path.is_empty(), "reachability_path must not be empty");
        assert_eq!(path.first(), Some(&row["exported_function_id"]));
        assert_eq!(path.last(), Some(&row["helper_function_id"]));
        assert_eq!(
            row["reachability_hops"].as_u64(),
            Some(path.len().saturating_sub(1) as u64)
        );
    }
    assert_eq!(
        actual_callsite_ids.len(),
        callsites.len(),
        "callsite ids should be globally unique"
    );
    assert_eq!(referenced_callsite_ids, actual_callsite_ids);
    Ok(())
}

#[test]
fn callsites_reference_existing_nonblank_source_lines() -> TestResult {
    let root = workspace_root();
    let data = load_json(&artifact(&root))?;
    for row in data["callsite_census"]
        .as_array()
        .expect("callsite census should be an array")
    {
        let path = row["path"].as_str().expect("path should be string");
        let line = row["line"].as_u64().expect("line should be u64") as usize;
        assert!(line > 0, "line should be positive");
        let full_path = root.join(path);
        assert!(full_path.is_file(), "missing callsite file {path}");
        let text = std::fs::read_to_string(full_path)?;
        let lines: Vec<_> = text.lines().collect();
        assert!(
            line <= lines.len(),
            "callsite line out of range: {path}:{line}"
        );
        assert!(
            !lines[line - 1].trim().is_empty(),
            "callsite should not cite blank line: {path}:{line}"
        );
    }
    Ok(())
}

#[test]
fn generator_check_mode_rederives_artifact() -> TestResult {
    let root = workspace_root();
    let output = Command::new("python3")
        .arg("scripts/generate_host_delegation_census.py")
        .arg("--check")
        .current_dir(&root)
        .output()?;
    assert!(
        output.status.success(),
        "generator check failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn generator_detects_host_calls_on_opening_brace_line() -> TestResult {
    let root = workspace_root();
    let source_dir = unique_synthetic_source_dir(&root, "same-line-source");
    std::fs::create_dir_all(&source_dir)?;
    let source_path = source_dir.join("same_line_abi.rs");
    std::fs::write(
        &source_path,
        r#"
#[unsafe(no_mangle)]
pub extern "C" fn direct_same_line() -> i32 { let _ = resolve_host_symbol_raw("direct_same_line"); 0 }
fn host_alias_same_line() -> i32 { let _ = resolve_host_symbol_raw("alias_same_line"); 0 }
#[unsafe(no_mangle)]
pub extern "C" fn alias_same_line() -> i32 { host_alias_same_line() }
fn private_host_helper() -> i32 { let _ = resolve_host_symbol_raw("via_private_helper"); 0 }
#[unsafe(no_mangle)]
pub extern "C" fn via_private_helper() -> i32 { private_host_helper() }
fn nested_terminal_helper() -> i32 { let _ = resolve_host_symbol_raw("via_nested_private_helper"); 0 }
fn nested_mid_helper() -> i32 { nested_terminal_helper() }
#[unsafe(no_mangle)]
pub extern "C" fn via_nested_private_helper() -> i32 { nested_mid_helper() }
#[unsafe(no_mangle)]
pub extern "C" fn remove() -> i32 { let _ = resolve_host_symbol_raw("remove_target"); 0 }
#[unsafe(no_mangle)]
pub extern "C" fn method_only_remove() -> i32 { let mut values = vec![1]; values.remove(0); 0 }
fn host_dladdr_cached() -> i32 { 0 }
#[unsafe(no_mangle)]
pub extern "C" fn dladdr() -> i32 { host_dladdr_cached() }
pub extern "C" fn rust_visible_only() -> i32 { let _ = resolve_host_symbol_raw("rust_visible_only"); 0 }
"#,
    )?;
    let output_path = unique_output_path(&root, "same-line-output", "json");

    let output = Command::new("python3")
        .arg("scripts/generate_host_delegation_census.py")
        .arg("--abi-source-dir")
        .arg(&source_dir)
        .arg("--output")
        .arg(&output_path)
        .current_dir(&root)
        .output()?;
    assert!(
        output.status.success(),
        "generator failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let data = load_json(&output_path)?;
    let symbols = data["symbol_census"]
        .as_array()
        .expect("symbol census should be an array");
    let direct = symbols
        .iter()
        .find(|row| row["symbol"].as_str() == Some("direct_same_line"))
        .expect("same-line direct host call should be detected");
    assert_eq!(direct["callsite_count"].as_u64(), Some(1));

    let static_helper = symbols
        .iter()
        .find(|row| row["symbol"].as_str() == Some("dladdr"))
        .expect("same-line static host helper call should be detected");
    assert_eq!(
        static_helper["callsite_count"].as_u64(),
        Some(1),
        "a helper declaration must not be counted as a callsite"
    );

    let alias = symbols
        .iter()
        .find(|row| row["symbol"].as_str() == Some("alias_same_line"))
        .expect("same-line alias to host-delegating symbol should be detected");
    let hosts: BTreeSet<_> = alias["host_symbols"]
        .as_array()
        .expect("host symbols should be array")
        .iter()
        .filter_map(|row| row.as_str())
        .collect();
    assert!(
        hosts.contains("alias_same_line"),
        "the terminal host symbol should propagate without helper names"
    );

    let via_private = symbols
        .iter()
        .find(|row| row["symbol"].as_str() == Some("via_private_helper"))
        .expect("exported ABI symbol reaching a private host helper should be detected");
    let private_hosts: BTreeSet<_> = via_private["host_symbols"]
        .as_array()
        .expect("host symbols should be array")
        .iter()
        .filter_map(|row| row.as_str())
        .collect();
    assert!(
        private_hosts.contains("via_private_helper"),
        "private helper host symbol should propagate to exported ABI symbol"
    );

    let via_nested = symbols
        .iter()
        .find(|row| row["symbol"].as_str() == Some("via_nested_private_helper"))
        .expect("exported ABI symbol reaching a nested private host helper should be detected");
    let nested_hosts: BTreeSet<_> = via_nested["host_symbols"]
        .as_array()
        .expect("host symbols should be array")
        .iter()
        .filter_map(|row| row.as_str())
        .collect();
    assert!(
        nested_hosts.contains("via_nested_private_helper"),
        "multi-hop private helper host symbol should propagate to exported ABI symbol"
    );
    let nested_path: BTreeSet<_> = data["callsite_census"]
        .as_array()
        .expect("callsite census should be array")
        .iter()
        .filter(|row| row["exported_symbol"].as_str() == Some("via_nested_private_helper"))
        .flat_map(|row| {
            row["reachability_path"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|value| value.as_str())
        })
        .collect();
    assert!(
        nested_path
            .iter()
            .any(|value| value.contains("nested_mid_helper"))
            && nested_path
                .iter()
                .any(|value| value.contains("nested_terminal_helper")),
        "the reachability witness should include intermediate and terminal helpers"
    );
    assert!(
        !symbols
            .iter()
            .any(|row| row["symbol"].as_str() == Some("method_only_remove")),
        "dotted method calls must not be treated as libc symbol aliases"
    );
    assert!(
        !symbols
            .iter()
            .any(|row| row["symbol"].as_str() == Some("rust_visible_only")),
        "a mangled pub extern function without an export attribute is not an ABI export"
    );
    Ok(())
}

#[test]
fn generator_scopes_duplicate_helpers_and_resolves_qualified_calls() -> TestResult {
    let root = workspace_root();
    let source_dir = unique_synthetic_source_dir(&root, "module-qualified-source");
    std::fs::create_dir_all(&source_dir)?;
    std::fs::write(
        source_dir.join("alpha_abi.rs"),
        r#"
pub(crate) fn shared_helper() -> i32 { let _ = resolve_host_symbol_raw("alpha_export"); 0 }
#[unsafe(no_mangle)]
pub extern "C" fn alpha_export() -> i32 { shared_helper() }
"#,
    )?;
    std::fs::write(
        source_dir.join("beta_abi.rs"),
        r#"
pub(crate) fn shared_helper() -> i32 { let _ = resolve_host_symbol_raw("beta_export"); 0 }
pub(crate) fn qualified_helper() -> i32 { let _ = resolve_host_symbol_raw("qualified_beta_export"); 0 }
#[unsafe(no_mangle)]
pub extern "C" fn beta_export() -> i32 { shared_helper() }
"#,
    )?;
    std::fs::write(
        source_dir.join("gamma_abi.rs"),
        r#"
#[unsafe(no_mangle)]
pub extern "C" fn qualified_beta_export() -> i32 { crate::beta_abi::qualified_helper() }
#[unsafe(no_mangle)]
pub extern "C" fn unresolved_unqualified_export() -> i32 { shared_helper() }
"#,
    )?;
    std::fs::write(
        source_dir.join("delta_abi.rs"),
        r#"
#[cfg(target_arch = "x86_64")]
fn cfg_helper() -> i32 { let _ = resolve_host_symbol_raw("ambiguous_local_export"); 0 }
#[cfg(target_arch = "aarch64")]
fn cfg_helper() -> i32 { let _ = resolve_host_symbol_raw("ambiguous_local_export"); 0 }
#[unsafe(no_mangle)]
pub extern "C" fn ambiguous_local_export() -> i32 { cfg_helper() }
"#,
    )?;
    std::fs::write(
        source_dir.join("epsilon_abi.rs"),
        r#"
fn host_dlopen() -> i32 { let _ = resolve_host_symbol_raw("shadowed_export"); 0 }
#[unsafe(no_mangle)]
pub extern "C" fn shadowed_export() -> i32 {
    let host_dlopen: fn() -> i32 = || 0;
    host_dlopen()
}
"#,
    )?;
    let output_path = unique_output_path(&root, "module-qualified-output", "json");

    let output = Command::new("python3")
        .arg("scripts/generate_host_delegation_census.py")
        .arg("--abi-source-dir")
        .arg(&source_dir)
        .arg("--output")
        .arg(&output_path)
        .current_dir(&root)
        .output()?;
    assert!(
        output.status.success(),
        "generator failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let data = load_json(&output_path)?;
    let symbols = data["symbol_census"]
        .as_array()
        .expect("symbol census should be an array");
    let host_symbols = |symbol: &str| -> BTreeSet<String> {
        symbols
            .iter()
            .find(|row| row["symbol"].as_str() == Some(symbol))
            .unwrap_or_else(|| panic!("missing host-delegating symbol {symbol}"))["host_symbols"]
            .as_array()
            .expect("host symbols should be an array")
            .iter()
            .filter_map(|row| row.as_str())
            .map(str::to_owned)
            .collect()
    };

    let alpha_hosts = host_symbols("alpha_export");
    assert!(alpha_hosts.contains("alpha_export"));
    assert!(
        !alpha_hosts.contains("beta_export"),
        "same-named beta helper must not contaminate alpha_export"
    );

    let beta_hosts = host_symbols("beta_export");
    assert!(beta_hosts.contains("beta_export"));
    assert!(
        !beta_hosts.contains("alpha_export"),
        "same-named alpha helper must not contaminate beta_export"
    );

    let qualified_hosts = host_symbols("qualified_beta_export");
    assert!(qualified_hosts.contains("qualified_beta_export"));
    assert!(
        !qualified_hosts.contains("alpha_export"),
        "qualified beta call must resolve exactly to beta_abi::qualified_helper"
    );
    assert!(
        data["callsite_census"]
            .as_array()
            .expect("callsite census should be an array")
            .iter()
            .any(|row| {
                row["exported_symbol"].as_str() == Some("qualified_beta_export")
                    && row["helper_function_id"]
                        .as_str()
                        .is_some_and(|value| value.starts_with("beta_abi::qualified_helper@"))
            }),
        "qualified propagation must retain module-qualified helper provenance"
    );

    assert!(
        !symbols
            .iter()
            .any(|row| row["symbol"].as_str() == Some("unresolved_unqualified_export")),
        "an unqualified nonlocal call must not be guessed from duplicate bare names"
    );
    let unknown_calls = data["unknown_call_edges"]
        .as_array()
        .expect("unknown_call_edges should be an array");
    assert!(
        !unknown_calls
            .iter()
            .any(|row| row["target_expression"].as_str() == Some("shared_helper")),
        "a bare name must not be guessed across sibling modules or create a false ambiguity"
    );

    assert!(
        !symbols
            .iter()
            .any(|row| row["symbol"].as_str() == Some("ambiguous_local_export")),
        "a cfg-ambiguous local call must not choose an arbitrary implementation"
    );
    let ambiguous = unknown_calls
        .iter()
        .find(|row| {
            row["target_expression"].as_str() == Some("cfg_helper")
                && row["caller_exported_symbol"].as_str() == Some("ambiguous_local_export")
        })
        .expect("cfg-ambiguous local helper call should be explicit unknown evidence");
    assert_eq!(
        ambiguous["reason"].as_str(),
        Some("ambiguous_unqualified_local_target")
    );
    assert_eq!(
        ambiguous["candidate_function_ids"]
            .as_array()
            .expect("ambiguous candidate ids should be an array")
            .len(),
        2
    );
    assert!(
        !symbols
            .iter()
            .any(|row| row["symbol"].as_str() == Some("shadowed_export")),
        "a let-bound function pointer must shadow a same-named module item"
    );
    assert!(
        !unknown_calls
            .iter()
            .any(|row| { row["caller_exported_symbol"].as_str() == Some("shadowed_export") }),
        "lexical shadowing must not create unknown call-graph evidence"
    );
    Ok(())
}

#[test]
fn gate_script_passes_and_emits_report_and_log() -> TestResult {
    let root = workspace_root();
    let report = unique_output_path(&root, "report", "json");
    let log = unique_output_path(&root, "log", "jsonl");
    let output = Command::new("bash")
        .arg("scripts/check_host_delegation_census.sh")
        .env("FRANKENLIBC_HOST_DELEGATION_CENSUS_REPORT", &report)
        .env("FRANKENLIBC_HOST_DELEGATION_CENSUS_LOG", &log)
        .current_dir(&root)
        .output()?;
    assert!(
        output.status.success(),
        "gate failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = load_json(&report)?;
    assert_eq!(
        report_json["schema_version"].as_str(),
        Some("host_delegation_census.report.v1")
    );
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    let log_line = std::fs::read_to_string(log)?
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log should contain a row")
        .to_string();
    let log_json: Value = serde_json::from_str(&log_line)?;
    assert_eq!(
        log_json["event"].as_str(),
        Some("host_delegation_census_validated")
    );
    assert_eq!(log_json["failure_signature"].as_str(), Some("none"));
    Ok(())
}
