//! Integration test: Replacement profile guard (bd-130)
//!
//! Validates that:
//! 1. replacement_profile.json exists and is valid JSON.
//! 2. All ABI modules with libc/host-wrapper call-throughs are in the interpose allowlist.
//! 3. No pthread call-through exists outside pthread_abi.rs.
//! 4. The call-through census in the profile matches reality.
//! 5. Zero-unapproved fixture pack covers all callthrough families in both modes.
//! 6. replacement guard report/log include symbol->module->path diagnostics.
//! 7. The replacement guard script exists and is executable.
//!
//! Run: cargo test -p frankenlibc-harness --test replacement_guard_test

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_profile() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/replacement_profile.json");
    let content = std::fs::read_to_string(&path).expect("replacement_profile.json should exist");
    serde_json::from_str(&content).expect("replacement_profile.json should be valid JSON")
}

fn load_fixture_pack() -> serde_json::Value {
    let path =
        workspace_root().join("tests/conformance/replacement_zero_unapproved_fixtures.v1.json");
    let content = std::fs::read_to_string(&path)
        .expect("replacement_zero_unapproved_fixtures.v1.json should exist");
    serde_json::from_str(&content)
        .expect("replacement_zero_unapproved_fixtures.v1.json should be valid JSON")
}

/// Extract a libc:: function call name from a line fragment starting at "libc::"
fn extract_libc_call(fragment: &str) -> Option<&str> {
    // fragment starts right after "libc::"
    // We want: lowercase identifier followed by '('
    let bytes = fragment.as_bytes();
    let mut end = 0;
    for &b in bytes {
        if b.is_ascii_lowercase() || b == b'_' || (end > 0 && b.is_ascii_digit()) {
            end += 1;
        } else {
            break;
        }
    }
    if end == 0 {
        return None;
    }
    // Check that the next non-whitespace character is '('
    let rest = &fragment[end..];
    let rest_trimmed = rest.trim_start();
    if rest_trimmed.starts_with('(') {
        Some(&fragment[..end])
    } else {
        None
    }
}

/// Scan an ABI source file for call-throughs:
///   - libc::<function>(...)
///   - host_pthread_<wrapper>(...)
///
/// excluding raw syscall and `_sym` wrapper internals.
fn scan_call_throughs(content: &str) -> Vec<(usize, String)> {
    let mut results = Vec::new();

    for (lineno, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        let mut search_from = 0;
        while let Some(pos) = line[search_from..].find("libc::") {
            let abs_pos = search_from + pos;
            let after = &line[abs_pos + 6..];
            if let Some(func_name) = extract_libc_call(after)
                && func_name != "syscall"
            {
                results.push((lineno + 1, func_name.to_string()));
            }
            search_from = abs_pos + 6;
        }

        if trimmed.contains("fn host_pthread_") {
            continue;
        }
        let mut host_search_from = 0;
        while let Some(pos) = line[host_search_from..].find("host_pthread_") {
            let abs_pos = host_search_from + pos;
            let after = &line[abs_pos + "host_pthread_".len()..];
            let bytes = after.as_bytes();
            let mut end = 0;
            for &b in bytes {
                if b.is_ascii_lowercase() || b == b'_' || (end > 0 && b.is_ascii_digit()) {
                    end += 1;
                } else {
                    break;
                }
            }
            if end > 0 {
                let wrapped = &after[..end];
                let rest = after[end..].trim_start();
                if rest.starts_with('(') && !wrapped.ends_with("_sym") {
                    results.push((lineno + 1, format!("pthread_{wrapped}")));
                }
            }
            host_search_from = abs_pos + "host_pthread_".len();
        }
    }
    results
}

fn forbidden_mutex_symbols() -> HashSet<&'static str> {
    HashSet::from([
        "pthread_mutex_init",
        "pthread_mutex_destroy",
        "pthread_mutex_lock",
        "pthread_mutex_trylock",
        "pthread_mutex_unlock",
    ])
}

#[test]
fn profile_exists_and_valid() {
    let profile = load_profile();
    assert!(
        profile["profile_version"].is_number(),
        "Missing profile_version"
    );
    assert!(profile["profiles"].is_object(), "Missing profiles");
    assert!(
        profile["interpose_allowlist"].is_object(),
        "Missing interpose_allowlist"
    );
    assert!(
        profile["detection_rules"].is_object(),
        "Missing detection_rules"
    );
    assert!(
        profile["replacement_forbidden"].is_object(),
        "Missing replacement_forbidden"
    );
}

#[test]
fn guard_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_replacement_guard.sh");
    assert!(
        script.exists(),
        "scripts/check_replacement_guard.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_replacement_guard.sh must be executable"
        );
    }
}

#[test]
fn interpose_allowlist_covers_all_call_through_modules() {
    let profile = load_profile();
    let abi_src = workspace_root().join("crates/frankenlibc-abi/src");

    let allowlist: HashSet<String> = profile["interpose_allowlist"]["modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let mut modules_with_ct: HashMap<String, usize> = HashMap::new();

    for entry in std::fs::read_dir(&abi_src).unwrap() {
        let entry = entry.unwrap();
        let fname = entry.file_name().to_string_lossy().to_string();
        if !fname.ends_with("_abi.rs") {
            continue;
        }
        let module = fname.trim_end_matches(".rs").to_string();
        let content = std::fs::read_to_string(entry.path()).unwrap();
        let calls = scan_call_throughs(&content);
        if !calls.is_empty() {
            modules_with_ct.insert(module, calls.len());
        }
    }

    let mut missing = Vec::new();
    for module in modules_with_ct.keys() {
        if !allowlist.contains(module) {
            missing.push(format!("{} ({} calls)", module, modules_with_ct[module]));
        }
    }

    assert!(
        missing.is_empty(),
        "Modules with call-throughs not in interpose allowlist: {:?}",
        missing
    );
}

#[test]
fn no_pthread_mutex_call_throughs_in_replacement_paths() {
    let abi_src = workspace_root().join("crates/frankenlibc-abi/src");
    let forbidden = forbidden_mutex_symbols();
    let mut violations = Vec::new();

    for entry in std::fs::read_dir(&abi_src).unwrap() {
        let entry = entry.unwrap();
        let fname = entry.file_name().to_string_lossy().to_string();
        if !fname.ends_with("_abi.rs") {
            continue;
        }
        let content = std::fs::read_to_string(entry.path()).unwrap();
        for (lineno, func) in scan_call_throughs(&content) {
            if forbidden.contains(func.as_str()) {
                violations.push(format!("{fname}:{lineno} {func}"));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "forbidden pthread_mutex call-throughs detected: {:?}",
        violations
    );
}

#[test]
fn no_pthread_calls_outside_pthread_abi() {
    let abi_src = workspace_root().join("crates/frankenlibc-abi/src");
    let mut violations = Vec::new();

    for entry in std::fs::read_dir(&abi_src).unwrap() {
        let entry = entry.unwrap();
        let fname = entry.file_name().to_string_lossy().to_string();
        if !fname.ends_with(".rs") || fname == "pthread_abi.rs" {
            continue;
        }
        let content = std::fs::read_to_string(entry.path()).unwrap();
        for (lineno, line) in content.lines().enumerate() {
            if line.trim().starts_with("//") {
                continue;
            }
            let mut pos = 0;
            while let Some(idx) = line[pos..].find("libc::pthread_") {
                let abs = pos + idx;
                let after = &line[abs + 6..]; // skip "libc::"
                if let Some(func) = extract_libc_call(after) {
                    violations.push(format!("{}:{} libc::{}", fname, lineno + 1, func));
                }
                pos = abs + 14;
            }
            if line.contains("fn host_pthread_") {
                continue;
            }
            let mut host_pos = 0;
            while let Some(idx) = line[host_pos..].find("host_pthread_") {
                let abs = host_pos + idx;
                let after = &line[abs + "host_pthread_".len()..];
                let mut end = 0;
                for &b in after.as_bytes() {
                    if b.is_ascii_lowercase() || b == b'_' || (end > 0 && b.is_ascii_digit()) {
                        end += 1;
                    } else {
                        break;
                    }
                }
                if end > 0 {
                    let wrapped = &after[..end];
                    let rest = after[end..].trim_start();
                    if rest.starts_with('(') && !wrapped.ends_with("_sym") {
                        violations.push(format!(
                            "{}:{} host_pthread_{}",
                            fname,
                            lineno + 1,
                            wrapped
                        ));
                    }
                }
                host_pos = abs + "host_pthread_".len();
            }
        }
    }

    assert!(
        violations.is_empty(),
        "pthread call-throughs outside pthread_abi.rs: {:?}",
        violations
    );
}

#[test]
fn call_through_census_matches_reality() {
    let profile = load_profile();
    let abi_src = workspace_root().join("crates/frankenlibc-abi/src");
    let census = &profile["call_through_census"]["modules"];

    for entry in std::fs::read_dir(&abi_src).unwrap() {
        let entry = entry.unwrap();
        let fname = entry.file_name().to_string_lossy().to_string();
        if !fname.ends_with("_abi.rs") {
            continue;
        }
        let module = fname.trim_end_matches(".rs");
        let content = std::fs::read_to_string(entry.path()).unwrap();
        let calls = scan_call_throughs(&content);

        if let Some(census_entry) = census.get(module) {
            let census_count = census_entry["count"].as_u64().unwrap() as usize;
            let actual = calls.len();
            let ratio = if census_count > 0 {
                actual as f64 / census_count as f64
            } else if actual > 0 {
                f64::INFINITY
            } else {
                1.0
            };
            assert!(
                (0.5..=2.0).contains(&ratio),
                "{}: census says {} but found {} call-throughs (ratio {:.2})",
                module,
                census_count,
                actual,
                ratio
            );
        }
    }
}

#[test]
fn replacement_profile_has_both_modes() {
    let profile = load_profile();
    let profiles = profile["profiles"].as_object().unwrap();

    assert!(
        profiles.contains_key("interpose"),
        "Missing interpose profile"
    );
    assert!(
        profiles.contains_key("replacement"),
        "Missing replacement profile"
    );

    assert_eq!(
        profile["profiles"]["interpose"]["call_through_allowed"].as_bool(),
        Some(true),
        "Interpose mode should allow call-through"
    );
    assert_eq!(
        profile["profiles"]["replacement"]["call_through_allowed"].as_bool(),
        Some(false),
        "Replacement mode should forbid call-through"
    );

    let forbidden = profile["replacement_forbidden"]["mutex_symbols"]
        .as_array()
        .expect("replacement_forbidden.mutex_symbols must be an array");
    let expected = forbidden_mutex_symbols();
    let actual: HashSet<String> = forbidden
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();

    assert_eq!(
        actual.len(),
        expected.len(),
        "replacement_forbidden.mutex_symbols should list all tracked mutex symbols"
    );
    for symbol in expected {
        assert!(
            actual.contains(symbol),
            "replacement_forbidden.mutex_symbols missing {symbol}"
        );
    }

    let families = profile["callthrough_families"]["modules"]
        .as_array()
        .expect("callthrough_families.modules must be an array");
    let family_set: HashSet<String> = families
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    let expected_families = HashSet::from(["stdio_abi".to_string(), "dlfcn_abi".to_string()]);
    assert_eq!(
        family_set, expected_families,
        "callthrough_families.modules must track current stdio/dlfcn callthrough families"
    );

    let fixture_pack = profile["zero_unapproved_fixture_pack"]["path"]
        .as_str()
        .expect("zero_unapproved_fixture_pack.path must be string");
    assert_eq!(
        fixture_pack,
        "tests/conformance/replacement_zero_unapproved_fixtures.v1.json"
    );
}

#[test]
fn raw_syscalls_are_not_flagged() {
    let abi_src = workspace_root().join("crates/frankenlibc-abi/src");
    let mut syscall_count = 0;

    for entry in std::fs::read_dir(&abi_src).unwrap() {
        let entry = entry.unwrap();
        if !entry.file_name().to_string_lossy().ends_with(".rs") {
            continue;
        }
        let content = std::fs::read_to_string(entry.path()).unwrap();
        for line in content.lines() {
            if line.trim().starts_with("//") {
                continue;
            }
            let mut pos = 0;
            while let Some(idx) = line[pos..].find("libc::syscall(") {
                syscall_count += 1;
                pos += idx + 14;
            }
        }
    }

    assert!(
        syscall_count >= 10,
        "Expected at least 10 raw syscall sites, found {}",
        syscall_count
    );
}

#[test]
fn callthrough_families_match_support_matrix() {
    let profile = load_profile();
    let root = workspace_root();
    let support_path = root.join("support_matrix.json");
    let support: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&support_path).expect("support_matrix.json should exist"),
    )
    .expect("support_matrix.json should parse");

    let declared_modules: HashSet<String> = profile["callthrough_families"]["modules"]
        .as_array()
        .expect("callthrough_families.modules must be array")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();

    let matrix_modules: HashSet<String> = support["symbols"]
        .as_array()
        .expect("support_matrix symbols must be array")
        .iter()
        .filter(|row| row["status"].as_str() == Some("GlibcCallThrough"))
        .filter_map(|row| row["module"].as_str().map(str::to_string))
        .collect();

    assert_eq!(
        declared_modules, matrix_modules,
        "replacement_profile.callthrough_families.modules must match GlibcCallThrough modules in support_matrix"
    );

    let allowlist: HashSet<String> = profile["interpose_allowlist"]["modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    for module in &declared_modules {
        assert!(
            allowlist.contains(module),
            "callthrough family {module} missing from interpose allowlist"
        );
    }
}

#[test]
fn fixture_pack_covers_all_callthrough_families_in_both_modes() {
    let profile = load_profile();
    let fixtures = load_fixture_pack();

    assert_eq!(fixtures["schema_version"].as_str(), Some("v1"));
    assert_eq!(fixtures["bead"].as_str(), Some("bd-27kh"));

    let fixture_rows = fixtures["fixtures"]
        .as_array()
        .expect("fixtures must be an array");
    assert!(!fixture_rows.is_empty(), "fixtures must not be empty");

    let profile_modules: HashSet<String> = profile["callthrough_families"]["modules"]
        .as_array()
        .expect("callthrough_families.modules must be array")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();

    let mut mode_counts = HashMap::<String, usize>::new();
    let mut module_modes = HashMap::<String, HashSet<String>>::new();
    for row in fixture_rows {
        let mode = row["mode"].as_str().expect("fixture.mode must be string");
        let module = row["module"]
            .as_str()
            .expect("fixture.module must be string");
        let expected = row["expected_outcome"]
            .as_str()
            .expect("fixture.expected_outcome must be string");
        match mode {
            "interpose" => assert_eq!(expected, "allowed"),
            "replacement" => assert_eq!(expected, "forbidden"),
            _ => panic!("unexpected fixture mode: {mode}"),
        }
        *mode_counts.entry(mode.to_string()).or_default() += 1;
        module_modes
            .entry(module.to_string())
            .or_default()
            .insert(mode.to_string());
    }

    for module in &profile_modules {
        let modes = module_modes
            .get(module)
            .unwrap_or_else(|| panic!("missing fixture coverage for module {module}"));
        assert!(
            modes.contains("interpose") && modes.contains("replacement"),
            "module {module} must be covered in both interpose and replacement fixtures"
        );
    }

    let summary = fixtures["summary"]
        .as_object()
        .expect("summary must be object");
    assert_eq!(
        summary.get("fixture_count").and_then(|v| v.as_u64()),
        Some(fixture_rows.len() as u64),
        "summary.fixture_count mismatch"
    );
    assert_eq!(
        summary
            .get("interpose_allowed_count")
            .and_then(|v| v.as_u64()),
        Some(*mode_counts.get("interpose").unwrap_or(&0) as u64),
        "summary.interpose_allowed_count mismatch"
    );
    assert_eq!(
        summary
            .get("replacement_forbidden_count")
            .and_then(|v| v.as_u64()),
        Some(*mode_counts.get("replacement").unwrap_or(&0) as u64),
        "summary.replacement_forbidden_count mismatch"
    );
}

#[test]
fn guard_emits_symbol_module_path_diagnostics() {
    let root = workspace_root();
    let script = root.join("scripts/check_replacement_guard.sh");
    let output = Command::new(&script)
        .arg("interpose")
        .current_dir(&root)
        .output()
        .expect("failed to run check_replacement_guard.sh");
    assert!(
        output.status.success(),
        "replacement guard script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/replacement_guard.report.json");
    let log_path = root.join("target/conformance/replacement_guard.log.jsonl");
    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());

    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&report_path).expect("report should be readable"),
    )
    .expect("report should parse");
    assert!(
        report["module_counts"].is_object(),
        "module_counts must be object"
    );
    assert!(
        report["violations_detail"].is_array(),
        "violations_detail must be array"
    );
    assert!(
        report["mutex_violations_detail"].is_array(),
        "mutex_violations_detail must be array"
    );

    let first_log = std::fs::read_to_string(&log_path)
        .expect("log should be readable")
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log should include at least one row")
        .to_string();
    let row: serde_json::Value = serde_json::from_str(&first_log).expect("log row should parse");
    for key in [
        "trace_id",
        "mode",
        "gate_name",
        "module",
        "line",
        "symbol",
        "status",
        "reason",
        "artifact_ref",
    ] {
        assert!(row.get(key).is_some(), "structured log row missing {key}");
    }
}
