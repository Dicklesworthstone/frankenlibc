// support_matrix_maintenance_test.rs — bd-3g4p
// Integration tests for the automated support matrix maintenance system.
// Validates: report generation, report schema, status validation coverage,
// conformance linkage coverage, and module coverage completeness.

use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("failed to read JSON file");
    serde_json::from_str(&content).expect("invalid JSON file")
}

fn load_jsonl(path: &Path) -> Vec<serde_json::Value> {
    let content = std::fs::read_to_string(path).expect("failed to read JSONL file");
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("invalid JSONL line"))
        .collect()
}

fn canonical_report_path() -> std::path::PathBuf {
    repo_root().join("tests/conformance/support_matrix_maintenance_report.v1.json")
}

fn host_delegation_census_path() -> std::path::PathBuf {
    repo_root().join("tests/conformance/host_delegation_census.v1.json")
}

fn unique_generated_report_path(tag: &str) -> std::path::PathBuf {
    let root = repo_root();
    let out_dir = root.join("target/conformance");
    std::fs::create_dir_all(&out_dir).expect("failed to create target/conformance");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    out_dir.join(format!("{tag}.{}.{}.json", std::process::id(), nanos))
}

fn generate_maintenance_report(output_path: &Path) -> std::process::Output {
    let root = repo_root();
    Command::new("python3")
        .args([
            root.join("scripts/generate_support_matrix_maintenance.py")
                .to_str()
                .unwrap(),
            "-o",
            output_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute maintenance validator")
}

fn generate_maintenance_report_with_proof_manifest(
    output_path: &Path,
    proof_manifest_path: &Path,
) -> std::process::Output {
    let root = repo_root();
    Command::new("python3")
        .args([
            root.join("scripts/generate_support_matrix_maintenance.py")
                .to_str()
                .unwrap(),
            "-o",
            output_path.to_str().unwrap(),
            "--promotion-proof-manifest",
            proof_manifest_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute maintenance validator")
}

fn generate_maintenance_report_with_previous_and_triage(
    output_path: &Path,
    previous_report_path: &Path,
    promotion_triage_path: Option<&Path>,
) -> std::process::Output {
    let root = repo_root();
    let mut command = Command::new("python3");
    command.args([
        root.join("scripts/generate_support_matrix_maintenance.py")
            .to_str()
            .unwrap(),
        "-o",
        output_path.to_str().unwrap(),
        "--previous-report",
        previous_report_path.to_str().unwrap(),
    ]);
    if let Some(path) = promotion_triage_path {
        command.args(["--promotion-triage-report", path.to_str().unwrap()]);
    }
    command
        .current_dir(&root)
        .output()
        .expect("failed to execute maintenance validator")
}

fn generate_promotion_triage_report() -> std::path::PathBuf {
    let root = repo_root();
    let output = Command::new("bash")
        .arg(root.join("scripts/check_support_matrix_promotion_triage.sh"))
        .current_dir(&root)
        .output()
        .expect("failed to execute promotion triage checker");
    assert!(
        output.status.success(),
        "promotion triage checker failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    root.join("target/conformance/support_matrix_promotion_triage.v1.json")
}

fn stable_report_sections(report: &serde_json::Value) -> serde_json::Value {
    let mut stable = serde_json::Map::new();
    // These are the current-state sections. We intentionally exclude the
    // generator's baseline-relative transition fields (`generated_at`, `trend`,
    // `reclassified_symbols`, and parts of `policy_checks`) because they depend
    // on which prior report is used as the baseline.
    for key in [
        "schema_version",
        "bead",
        "summary",
        "coverage_dashboard",
        "status_distribution",
        "module_coverage",
        "symbol_status_map",
        "status_validation_issues",
        "unlinked_symbols",
    ] {
        stable.insert(
            key.to_owned(),
            report
                .get(key)
                .expect("report missing stable section")
                .clone(),
        );
    }
    serde_json::Value::Object(stable)
}

fn gate_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn run_support_matrix_gate_with_canonical(
    trace_symbol_events: bool,
    canonical_override: Option<&Path>,
) -> std::process::Output {
    let root = repo_root();
    let script_path = root.join("scripts/check_support_matrix_maintenance.sh");
    let mut command = Command::new("bash");
    command.arg(script_path).current_dir(&root);
    if trace_symbol_events {
        command.env("FRANKENLIBC_SYMBOL_GATE_TRACE", "1");
    } else {
        command.env_remove("FRANKENLIBC_SYMBOL_GATE_TRACE");
    }
    command.env_remove("FRANKENLIBC_PROMOTION_TRIAGE_OUT_DIR");
    command.env_remove("FRANKENLIBC_PROMOTION_TRIAGE_MAINTENANCE_REPORT");
    command.env_remove("FRANKENLIBC_PROMOTION_TRIAGE_REPORT");
    if let Some(path) = canonical_override {
        command.env("FRANKENLIBC_MAINTENANCE_CANONICAL_REPORT", path);
    } else {
        command.env_remove("FRANKENLIBC_MAINTENANCE_CANONICAL_REPORT");
    }
    command
        .output()
        .expect("failed to execute support matrix maintenance gate")
}

fn run_support_matrix_gate(trace_symbol_events: bool) -> std::process::Output {
    run_support_matrix_gate_with_canonical(trace_symbol_events, None)
}

const IMPLEMENTED_NATIVE_SAMPLE_SYMBOLS: &[&str] = &[
    "__b64_ntop",
    "__ctype_b_loc",
    "__errno_location",
    "__finite",
    "__fpclassify",
    "__h_errno_location",
    "__isinf",
    "__isnan",
    "__libc_current_sigrtmax",
    "__libc_current_sigrtmin",
    "abs",
    "a64l",
];

const HOST_WRAPPED_SYMBOLS: &[&str] = &[
    "__libc_start_main",
    "malloc",
    "pthread_create",
    "pthread_join",
    "pthread_detach",
    "dlopen",
    "dlsym",
    "dlclose",
    "dl_iterate_phdr",
    "dladdr",
    "_IO_fclose",
    "_IO_fopen",
    "_IO_printf",
    "_IO_flockfile",
    "_IO_funlockfile",
    "_IO_ftrylockfile",
];

const MATH_PROMOTION_TRANCHE_SYMBOLS: &[&str] = &[
    "acos", "asin", "exp", "fmod", "lgamma", "log", "log10", "pow", "tgamma",
];
const ERR_PROMOTION_TRANCHE_SYMBOLS: &[&str] = &[
    "err", "errc", "errx", "verr", "verrc", "verrx", "vwarn", "vwarnc", "vwarnx", "warn", "warnc",
    "warnx",
];
const LOCALE_PROMOTION_TRANCHE_SYMBOLS: &[&str] = &["catclose", "catgets", "catopen"];
const RESOLV_PROMOTION_TRANCHE_SYMBOLS: &[&str] = &["getprotobyname", "getprotobynumber"];

#[test]
fn maintenance_report_generates_successfully() {
    let canonical_path = canonical_report_path();
    assert!(
        canonical_path.exists(),
        "canonical report missing at {}",
        canonical_path.display()
    );

    let generated_path = unique_generated_report_path("support_matrix_maintenance_test");
    let output = generate_maintenance_report(&generated_path);
    assert!(
        output.status.success(),
        "Maintenance validator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        generated_path.exists(),
        "Report not generated at {}",
        generated_path.display()
    );

    let canonical = load_json(&canonical_path);
    let generated = load_json(&generated_path);
    assert_eq!(
        stable_report_sections(&generated),
        stable_report_sections(&canonical),
        "generated maintenance report stable sections drift from canonical artifact"
    );
}

#[test]
fn maintenance_report_schema_complete() {
    let report_path = canonical_report_path();
    assert!(
        report_path.exists(),
        "canonical report missing at {}",
        report_path.display()
    );
    let data = load_json(&report_path);

    // Check top-level fields
    assert_eq!(
        data["schema_version"].as_str(),
        Some("v1"),
        "Wrong schema version"
    );
    assert_eq!(
        data["bead"].as_str(),
        Some("bd-3g4p"),
        "Wrong bead reference"
    );

    // Check summary fields
    let summary = &data["summary"];
    let required_fields = [
        "total_symbols",
        "status_validated",
        "status_invalid",
        "status_skipped",
        "status_valid_pct",
        "fixture_linked",
        "fixture_unlinked",
        "fixture_coverage_pct",
    ];
    for field in &required_fields {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }

    // Check sections exist
    assert!(
        data["status_distribution"].is_object(),
        "Missing status_distribution"
    );
    assert!(
        data["module_coverage"].is_object(),
        "Missing module_coverage"
    );
    assert!(
        data["status_validation_issues"].is_array(),
        "Missing status_validation_issues"
    );
    assert!(
        data["unlinked_symbols"].is_array(),
        "Missing unlinked_symbols"
    );
}

#[test]
fn support_matrix_embedded_counts_match_symbol_rows() {
    let matrix = load_json(&repo_root().join("support_matrix.json"));
    let symbols = matrix["symbols"]
        .as_array()
        .expect("support_matrix.symbols must be an array");
    let mut counts = std::collections::BTreeMap::<&str, u64>::new();
    for symbol in symbols {
        let status = symbol["status"]
            .as_str()
            .expect("support_matrix symbol status must be a string");
        *counts.entry(status).or_default() += 1;
    }

    assert_eq!(
        matrix["total_exported"].as_u64(),
        Some(symbols.len() as u64),
        "support_matrix.total_exported must match symbols.len()"
    );
    assert_eq!(
        matrix["summary"]["total"].as_u64(),
        Some(symbols.len() as u64),
        "support_matrix.summary.total must match symbols.len()"
    );

    for (json_key, status) in [
        ("implemented", "Implemented"),
        ("raw_syscall", "RawSyscall"),
        ("wraps_host_libc", "WrapsHostLibc"),
        ("glibc_call_through", "GlibcCallThrough"),
        ("stub", "Stub"),
    ] {
        let actual = counts.get(status).copied().unwrap_or_default();
        assert_eq!(
            matrix[json_key].as_u64(),
            Some(actual),
            "support_matrix.{json_key} must be derived from symbols[].status"
        );
        assert_eq!(
            matrix["counts"][json_key].as_u64(),
            Some(actual),
            "support_matrix.counts.{json_key} must be derived from symbols[].status"
        );
        assert_eq!(
            matrix["summary"][json_key].as_u64(),
            Some(actual),
            "support_matrix.summary.{json_key} must be derived from symbols[].status"
        );
    }
}

#[test]
fn generated_maintenance_dashboard_counts_match_symbol_rows() {
    let matrix = load_json(&repo_root().join("support_matrix.json"));
    let symbols = matrix["symbols"]
        .as_array()
        .expect("support_matrix.symbols must be an array");
    let mut counts = std::collections::BTreeMap::<&str, u64>::new();
    for symbol in symbols {
        let status = symbol["status"]
            .as_str()
            .expect("support_matrix symbol status must be a string");
        *counts.entry(status).or_default() += 1;
    }

    let generated_path = unique_generated_report_path("support_matrix_count_dashboard_test");
    let output = generate_maintenance_report(&generated_path);
    assert!(
        output.status.success(),
        "Maintenance validator failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&generated_path);
    let dashboard_counts = report["coverage_dashboard"]["status_counts"]
        .as_object()
        .expect("coverage_dashboard.status_counts must be an object");
    for status in [
        "Implemented",
        "RawSyscall",
        "WrapsHostLibc",
        "GlibcCallThrough",
        "Stub",
    ] {
        let actual = counts.get(status).copied().unwrap_or_default();
        assert_eq!(
            dashboard_counts
                .get(status)
                .and_then(serde_json::Value::as_u64),
            Some(actual),
            "generated maintenance dashboard count for {status} must be derived from symbols[].status"
        );
    }
}

#[test]
fn maintenance_status_validation_above_threshold() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/support_matrix_maintenance_report.v1.json");
    let data = load_json(&report_path);

    let valid_pct = data["summary"]["status_valid_pct"].as_f64().unwrap();
    assert!(
        valid_pct >= 80.0,
        "Status validation {valid_pct}% below 80% threshold"
    );

    let total = data["summary"]["total_symbols"].as_u64().unwrap();
    assert!(
        total >= 200,
        "Expected at least 200 symbols in matrix, got {total}"
    );
}

#[test]
fn maintenance_report_has_no_invalid_status_rows() {
    let report_path = canonical_report_path();
    let data = load_json(&report_path);

    let invalid = data["summary"]["status_invalid"]
        .as_u64()
        .expect("summary.status_invalid must be a u64");
    assert_eq!(
        invalid, 0,
        "support matrix maintenance report should not carry invalid status rows"
    );

    let issues = data["status_validation_issues"]
        .as_array()
        .expect("status_validation_issues should be an array");
    let invalid_issues: Vec<&serde_json::Value> = issues
        .iter()
        .filter(|issue| issue["valid"].as_bool() == Some(false))
        .collect();
    assert!(
        invalid_issues.is_empty(),
        "unexpected invalid status issues remain: {invalid_issues:?}"
    );
}

#[test]
fn maintenance_module_coverage_consistent() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/support_matrix_maintenance_report.v1.json");
    let data = load_json(&report_path);

    let module_cov = data["module_coverage"].as_object().unwrap();
    let mut total_from_modules: u64 = 0;
    for (_mod_name, info) in module_cov {
        let t = info["total"].as_u64().unwrap();
        let l = info["linked"].as_u64().unwrap();
        total_from_modules += t;
        assert!(
            l <= t,
            "Module {} has more linked ({l}) than total ({t})",
            _mod_name
        );
        let pct = info["coverage_pct"].as_f64().unwrap();
        assert!(
            (0.0..=100.0).contains(&pct),
            "Module {} coverage {pct}% out of range",
            _mod_name
        );
    }

    let total_from_summary = data["summary"]["total_symbols"].as_u64().unwrap();
    assert_eq!(
        total_from_modules, total_from_summary,
        "Module total ({total_from_modules}) != summary total ({total_from_summary})"
    );
}

#[test]
fn maintenance_report_marks_native_sample_symbols_implemented() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/support_matrix_maintenance_report.v1.json");
    let data = load_json(&report_path);
    let symbol_status_map = data["symbol_status_map"]
        .as_object()
        .expect("symbol_status_map should be an object");

    for symbol in IMPLEMENTED_NATIVE_SAMPLE_SYMBOLS {
        let status = symbol_status_map
            .get(*symbol)
            .and_then(serde_json::Value::as_str);
        assert_eq!(
            status,
            Some("Implemented"),
            "expected {symbol} to be Implemented in support_matrix_maintenance_report.v1.json"
        );
    }
}

#[test]
fn maintenance_report_reclassifies_host_delegating_symbols() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/support_matrix_maintenance_report.v1.json");
    let data = load_json(&report_path);
    let symbol_status_map = data["symbol_status_map"]
        .as_object()
        .expect("symbol_status_map should be an object");

    let wraps_count = data["coverage_dashboard"]["status_counts"]["WrapsHostLibc"]
        .as_u64()
        .expect("WrapsHostLibc count should be numeric");
    assert!(
        wraps_count > 0,
        "support matrix should expose a non-empty host-backed taxonomy bucket"
    );

    for symbol in HOST_WRAPPED_SYMBOLS {
        let status = symbol_status_map
            .get(*symbol)
            .and_then(serde_json::Value::as_str);
        assert_eq!(
            status,
            Some("WrapsHostLibc"),
            "expected {symbol} to be reclassified out of Implemented"
        );
    }

    let issues = data["status_validation_issues"]
        .as_array()
        .expect("status_validation_issues should be an array");
    let implemented_host_delegation: Vec<&serde_json::Value> = issues
        .iter()
        .filter(|issue| issue["status"].as_str() == Some("Implemented"))
        .filter(|issue| {
            issue["findings"].as_array().is_some_and(|findings| {
                findings.iter().any(|finding| {
                    finding.as_str() == Some("Implemented but host delegation detected")
                })
            })
        })
        .collect();
    assert!(
        implemented_host_delegation.is_empty(),
        "Implemented rows must not delegate to host libc: {implemented_host_delegation:?}"
    );
}

#[test]
fn maintenance_report_has_no_implemented_host_census_symbols() {
    let report = load_json(&canonical_report_path());
    let census = load_json(&host_delegation_census_path());
    let symbol_status_map = report["symbol_status_map"]
        .as_object()
        .expect("symbol_status_map should be an object");
    let host_symbols: std::collections::BTreeSet<&str> = census["symbol_census"]
        .as_array()
        .expect("symbol_census should be an array")
        .iter()
        .filter_map(|row| row["symbol"].as_str())
        .collect();

    let implemented_host_symbols: Vec<&str> = host_symbols
        .iter()
        .copied()
        .filter(|symbol| {
            symbol_status_map
                .get(*symbol)
                .and_then(serde_json::Value::as_str)
                == Some("Implemented")
        })
        .collect();
    assert!(
        implemented_host_symbols.is_empty(),
        "host-delegating census symbols must be reclassified out of Implemented: {implemented_host_symbols:?}"
    );
}

#[test]
fn math_abi_promotion_tranche_manifest_has_strict_and_hardened_proof() {
    let root = repo_root();
    let manifest = load_json(&root.join("tests/conformance/math_abi_promotion_tranche.v1.json"));
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("math_abi_promotion_tranche.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-h1fbda"));

    let policy_modes: std::collections::BTreeSet<&str> = manifest["policy"]["required_modes"]
        .as_array()
        .expect("required_modes should be an array")
        .iter()
        .map(|mode| mode.as_str().expect("mode should be a string"))
        .collect();
    assert_eq!(
        policy_modes,
        std::collections::BTreeSet::from(["hardened", "strict"])
    );

    let symbols = manifest["symbols"]
        .as_array()
        .expect("symbols should be an array");
    let manifest_symbols: std::collections::BTreeSet<&str> = symbols
        .iter()
        .map(|row| row["symbol"].as_str().expect("symbol should be a string"))
        .collect();
    let expected_symbols: std::collections::BTreeSet<&str> =
        MATH_PROMOTION_TRANCHE_SYMBOLS.iter().copied().collect();
    assert_eq!(manifest_symbols, expected_symbols);

    for row in symbols {
        assert_eq!(row["module"].as_str(), Some("math_abi"));
        assert_eq!(row["decision"].as_str(), Some("proven"));
        for mode in ["strict", "hardened"] {
            let key = format!("{mode}_conformance");
            let proof = &row[&key];
            assert!(
                proof["total"].as_u64().unwrap_or_default() > 0,
                "{} must have {mode} conformance rows",
                row["symbol"]
            );
            assert_eq!(proof["failed"].as_u64(), Some(0));
            assert_eq!(proof["errors"].as_u64(), Some(0));
            assert_eq!(proof["passed"].as_u64(), proof["total"].as_u64());
        }
    }
}

#[test]
fn err_abi_promotion_tranche_manifest_has_strict_and_hardened_proof() {
    let root = repo_root();
    let manifest = load_json(&root.join("tests/conformance/err_abi_promotion_tranche.v1.json"));
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("err_abi_promotion_tranche.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-5tgwug"));
    assert_eq!(
        manifest["policy"]["classification"].as_str(),
        Some("native-err-formatting-with-runtime-io-bridge")
    );

    let policy_modes: std::collections::BTreeSet<&str> = manifest["policy"]["required_modes"]
        .as_array()
        .expect("required_modes should be an array")
        .iter()
        .map(|mode| mode.as_str().expect("mode should be a string"))
        .collect();
    assert_eq!(
        policy_modes,
        std::collections::BTreeSet::from(["hardened", "strict"])
    );

    let accepted_symbols: std::collections::BTreeSet<&str> =
        manifest["policy"]["accepted_host_symbols"]
            .as_array()
            .expect("accepted_host_symbols should be an array")
            .iter()
            .map(|symbol| symbol.as_str().expect("host symbol should be a string"))
            .collect();
    for helper in [
        "__errno_location",
        "get_progname",
        "sys_read_fd",
        "write_err_message",
        "vformat_and_write",
    ] {
        assert!(
            accepted_symbols.contains(helper),
            "err_abi proof must explicitly account for {helper}"
        );
    }

    let symbols = manifest["symbols"]
        .as_array()
        .expect("symbols should be an array");
    let manifest_symbols: std::collections::BTreeSet<&str> = symbols
        .iter()
        .map(|row| row["symbol"].as_str().expect("symbol should be a string"))
        .collect();
    let expected_symbols: std::collections::BTreeSet<&str> =
        ERR_PROMOTION_TRANCHE_SYMBOLS.iter().copied().collect();
    assert_eq!(manifest_symbols, expected_symbols);

    for row in symbols {
        assert_eq!(row["module"].as_str(), Some("err_abi"));
        assert_eq!(row["decision"].as_str(), Some("proven"));
        for mode in ["strict", "hardened"] {
            let key = format!("{mode}_conformance");
            let proof = &row[&key];
            assert!(
                proof["total"].as_u64().unwrap_or_default() > 0,
                "{} must have {mode} conformance rows",
                row["symbol"]
            );
            assert_eq!(proof["failed"].as_u64(), Some(0));
            assert_eq!(proof["errors"].as_u64(), Some(0));
            assert_eq!(proof["passed"].as_u64(), proof["total"].as_u64());
        }
    }
}

#[test]
fn locale_abi_promotion_tranche_manifest_has_strict_and_hardened_proof() {
    let root = repo_root();
    let manifest = load_json(&root.join("tests/conformance/locale_abi_promotion_tranche.v1.json"));
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("locale_abi_promotion_tranche.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-5tgwug"));
    assert_eq!(
        manifest["policy"]["classification"].as_str(),
        Some("native-locale-catalog-with-errno-bridge")
    );

    let policy_modes: std::collections::BTreeSet<&str> = manifest["policy"]["required_modes"]
        .as_array()
        .expect("required_modes should be an array")
        .iter()
        .map(|mode| mode.as_str().expect("mode should be a string"))
        .collect();
    assert_eq!(
        policy_modes,
        std::collections::BTreeSet::from(["hardened", "strict"])
    );

    let accepted_symbols: std::collections::BTreeSet<&str> =
        manifest["policy"]["accepted_host_symbols"]
            .as_array()
            .expect("accepted_host_symbols should be an array")
            .iter()
            .map(|symbol| symbol.as_str().expect("host symbol should be a string"))
            .collect();
    for helper in [
        "__errno_location",
        "load_host_symbol",
        "sys_read_fd",
        "write_host_errno_if_available",
    ] {
        assert!(
            accepted_symbols.contains(helper),
            "locale_abi proof must explicitly account for {helper}"
        );
    }

    let symbols = manifest["symbols"]
        .as_array()
        .expect("symbols should be an array");
    let manifest_symbols: std::collections::BTreeSet<&str> = symbols
        .iter()
        .map(|row| row["symbol"].as_str().expect("symbol should be a string"))
        .collect();
    let expected_symbols: std::collections::BTreeSet<&str> =
        LOCALE_PROMOTION_TRANCHE_SYMBOLS.iter().copied().collect();
    assert_eq!(manifest_symbols, expected_symbols);

    for row in symbols {
        assert_eq!(row["module"].as_str(), Some("locale_abi"));
        assert_eq!(row["decision"].as_str(), Some("proven"));
        for mode in ["strict", "hardened"] {
            let key = format!("{mode}_conformance");
            let proof = &row[&key];
            assert!(
                proof["total"].as_u64().unwrap_or_default() > 0,
                "{} must have {mode} conformance rows",
                row["symbol"]
            );
            assert_eq!(proof["failed"].as_u64(), Some(0));
            assert_eq!(proof["errors"].as_u64(), Some(0));
            assert_eq!(proof["passed"].as_u64(), proof["total"].as_u64());
        }
    }
}

#[test]
fn resolv_abi_promotion_tranche_manifest_has_strict_and_hardened_proof() {
    let root = repo_root();
    let manifest = load_json(&root.join("tests/conformance/resolv_abi_promotion_tranche.v1.json"));
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("resolv_abi_promotion_tranche.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-5tgwug"));
    assert_eq!(
        manifest["policy"]["classification"].as_str(),
        Some("native-protocol-database-with-errno-bridge")
    );

    let policy_modes: std::collections::BTreeSet<&str> = manifest["policy"]["required_modes"]
        .as_array()
        .expect("required_modes should be an array")
        .iter()
        .map(|mode| mode.as_str().expect("mode should be a string"))
        .collect();
    assert_eq!(
        policy_modes,
        std::collections::BTreeSet::from(["hardened", "strict"])
    );

    let accepted_symbols: std::collections::BTreeSet<&str> =
        manifest["policy"]["accepted_host_symbols"]
            .as_array()
            .expect("accepted_host_symbols should be an array")
            .iter()
            .map(|symbol| symbol.as_str().expect("host symbol should be a string"))
            .collect();
    for helper in [
        "__errno_location",
        "load_host_symbol",
        "read",
        "sys_read_fd",
        "write_host_errno_if_available",
    ] {
        assert!(
            accepted_symbols.contains(helper),
            "resolv_abi proof must explicitly account for {helper}"
        );
    }

    let symbols = manifest["symbols"]
        .as_array()
        .expect("symbols should be an array");
    let manifest_symbols: std::collections::BTreeSet<&str> = symbols
        .iter()
        .map(|row| row["symbol"].as_str().expect("symbol should be a string"))
        .collect();
    let expected_symbols: std::collections::BTreeSet<&str> =
        RESOLV_PROMOTION_TRANCHE_SYMBOLS.iter().copied().collect();
    assert_eq!(manifest_symbols, expected_symbols);

    for row in symbols {
        assert_eq!(row["module"].as_str(), Some("resolv_abi"));
        assert_eq!(row["decision"].as_str(), Some("proven"));
        for mode in ["strict", "hardened"] {
            let key = format!("{mode}_conformance");
            let proof = &row[&key];
            assert!(
                proof["total"].as_u64().unwrap_or_default() > 0,
                "{} must have {mode} conformance rows",
                row["symbol"]
            );
            assert_eq!(proof["failed"].as_u64(), Some(0));
            assert_eq!(proof["errors"].as_u64(), Some(0));
            assert_eq!(proof["passed"].as_u64(), proof["total"].as_u64());
        }
    }
}

#[test]
fn generated_report_accepts_math_abi_errno_bridge_tranche() {
    let generated_path = unique_generated_report_path("math_abi_promotion_tranche");
    let output = generate_maintenance_report(&generated_path);
    assert!(
        output.status.success(),
        "Maintenance validator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&generated_path);
    let issues = report["status_validation_issues"]
        .as_array()
        .expect("status_validation_issues should be an array");

    for symbol in MATH_PROMOTION_TRANCHE_SYMBOLS {
        let rows: Vec<&serde_json::Value> = issues
            .iter()
            .filter(|issue| issue["symbol"].as_str() == Some(*symbol))
            .collect();
        assert!(
            rows.iter()
                .all(|issue| issue["valid"].as_bool() == Some(true)),
            "{symbol} should not remain invalid after math ABI proof: {rows:?}"
        );
        assert!(
            rows.iter().any(|issue| {
                issue["warnings"].as_array().is_some_and(|warnings| {
                    warnings.iter().any(|warning| {
                        warning.as_str()
                            == Some("host delegation census covered by promotion proof manifest")
                    })
                })
            }),
            "{symbol} should keep an auditable proof-manifest warning"
        );
    }
}

#[test]
fn generated_report_accepts_err_abi_runtime_io_bridge_tranche() {
    let generated_path = unique_generated_report_path("err_abi_promotion_tranche");
    let output = generate_maintenance_report(&generated_path);
    assert!(
        output.status.success(),
        "Maintenance validator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&generated_path);
    let issues = report["status_validation_issues"]
        .as_array()
        .expect("status_validation_issues should be an array");

    for symbol in ERR_PROMOTION_TRANCHE_SYMBOLS {
        let rows: Vec<&serde_json::Value> = issues
            .iter()
            .filter(|issue| issue["symbol"].as_str() == Some(*symbol))
            .collect();
        assert!(
            rows.iter()
                .all(|issue| issue["valid"].as_bool() == Some(true)),
            "{symbol} should not remain invalid after err ABI proof: {rows:?}"
        );
        assert!(
            rows.iter().any(|issue| {
                issue["warnings"].as_array().is_some_and(|warnings| {
                    warnings.iter().any(|warning| {
                        warning.as_str()
                            == Some("host delegation census covered by promotion proof manifest")
                    })
                })
            }),
            "{symbol} should keep an auditable proof-manifest warning"
        );
    }
}

#[test]
fn generated_report_accepts_locale_abi_catalog_bridge_tranche() {
    let generated_path = unique_generated_report_path("locale_abi_promotion_tranche");
    let output = generate_maintenance_report(&generated_path);
    assert!(
        output.status.success(),
        "Maintenance validator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&generated_path);
    let issues = report["status_validation_issues"]
        .as_array()
        .expect("status_validation_issues should be an array");

    for symbol in LOCALE_PROMOTION_TRANCHE_SYMBOLS {
        let rows: Vec<&serde_json::Value> = issues
            .iter()
            .filter(|issue| issue["symbol"].as_str() == Some(*symbol))
            .collect();
        assert!(
            rows.iter()
                .all(|issue| issue["valid"].as_bool() == Some(true)),
            "{symbol} should not remain invalid after locale ABI proof: {rows:?}"
        );
        assert!(
            rows.iter().any(|issue| {
                issue["warnings"].as_array().is_some_and(|warnings| {
                    warnings.iter().any(|warning| {
                        warning.as_str()
                            == Some("host delegation census covered by promotion proof manifest")
                    })
                })
            }),
            "{symbol} should keep an auditable proof-manifest warning"
        );
    }
}

#[test]
fn generated_report_accepts_resolv_abi_protocol_bridge_tranche() {
    let generated_path = unique_generated_report_path("resolv_abi_promotion_tranche");
    let output = generate_maintenance_report(&generated_path);
    assert!(
        output.status.success(),
        "Maintenance validator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&generated_path);
    let issues = report["status_validation_issues"]
        .as_array()
        .expect("status_validation_issues should be an array");

    for symbol in RESOLV_PROMOTION_TRANCHE_SYMBOLS {
        let rows: Vec<&serde_json::Value> = issues
            .iter()
            .filter(|issue| issue["symbol"].as_str() == Some(*symbol))
            .collect();
        assert!(
            rows.iter()
                .all(|issue| issue["valid"].as_bool() == Some(true)),
            "{symbol} should not remain invalid after resolv ABI proof: {rows:?}"
        );
        assert!(
            rows.iter().any(|issue| {
                issue["warnings"].as_array().is_some_and(|warnings| {
                    warnings.iter().any(|warning| {
                        warning.as_str()
                            == Some("host delegation census covered by promotion proof manifest")
                    })
                })
            }),
            "{symbol} should keep an auditable proof-manifest warning"
        );
    }
}

#[test]
fn fixture_coverage_ratchet_reports_module_mode_and_proof_class_deltas() {
    let triage_path = generate_promotion_triage_report();
    let previous_report_path = unique_generated_report_path("fixture_ratchet_selected_previous");
    let previous = serde_json::json!({
        "symbol_status_map": {
            "acos": "WrapsHostLibc",
            "__adjtimex": "WrapsHostLibc",
            "__asprintf_chk": "WrapsHostLibc",
            "__assert": "WrapsHostLibc"
        },
        "coverage_dashboard": {
            "status_counts": {
                "Implemented": 0,
                "RawSyscall": 0,
                "WrapsHostLibc": 4,
                "GlibcCallThrough": 0,
                "Stub": 0
            },
            "native_coverage_pct": 0.0
        }
    });
    std::fs::write(
        &previous_report_path,
        serde_json::to_vec_pretty(&previous).expect("previous report should serialize"),
    )
    .expect("failed to write selected previous report");

    let generated_path = unique_generated_report_path("fixture_coverage_ratchet");
    let output = generate_maintenance_report_with_previous_and_triage(
        &generated_path,
        &previous_report_path,
        Some(&triage_path),
    );
    assert!(
        output.status.success(),
        "Maintenance validator failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&generated_path);
    let ratchet = &report["fixture_coverage_ratchet"];
    assert_eq!(
        ratchet["schema_version"].as_str(),
        Some("fixture_coverage_ratchet.v1")
    );
    assert_eq!(ratchet["bead"].as_str(), Some("bd-8t1chf"));
    assert_eq!(
        ratchet["promotion_triage_manifest_loaded"].as_bool(),
        Some(true)
    );

    let module_deltas = ratchet["module_deltas"]
        .as_object()
        .expect("module_deltas should be an object");
    for module in [
        "math_abi",
        "glibc_internal_abi",
        "unistd_abi",
        "rpc_abi",
        "stdlib_abi",
        "wchar_abi",
        "fortify_abi",
        "stdio_abi",
    ] {
        let entry = module_deltas
            .get(module)
            .unwrap_or_else(|| panic!("missing ratchet module entry for {module}"));
        assert!(
            entry["mode_deltas"]["strict"].is_object(),
            "{module} missing strict mode delta"
        );
        assert!(
            entry["mode_deltas"]["hardened"].is_object(),
            "{module} missing hardened mode delta"
        );
        assert!(
            entry["proof_class_counts"].is_object(),
            "{module} missing proof class counts"
        );
    }

    let math_proofs = &ratchet["proof_manifest_by_module"]["math_abi"];
    assert!(
        math_proofs["strict_hardened_symbol_count"]
            .as_u64()
            .unwrap_or_default()
            >= MATH_PROMOTION_TRANCHE_SYMBOLS.len() as u64,
        "math_abi pilot proof manifest should expose strict+hardened proven symbols"
    );
    let err_proofs = &ratchet["proof_manifest_by_module"]["err_abi"];
    assert!(
        err_proofs["strict_hardened_symbol_count"]
            .as_u64()
            .unwrap_or_default()
            >= ERR_PROMOTION_TRANCHE_SYMBOLS.len() as u64,
        "err_abi proof manifest should expose strict+hardened proven symbols"
    );
    let locale_proofs = &ratchet["proof_manifest_by_module"]["locale_abi"];
    assert!(
        locale_proofs["strict_hardened_symbol_count"]
            .as_u64()
            .unwrap_or_default()
            >= LOCALE_PROMOTION_TRANCHE_SYMBOLS.len() as u64,
        "locale_abi proof manifest should expose strict+hardened proven symbols"
    );
    let resolv_proofs = &ratchet["proof_manifest_by_module"]["resolv_abi"];
    assert!(
        resolv_proofs["strict_hardened_symbol_count"]
            .as_u64()
            .unwrap_or_default()
            >= RESOLV_PROMOTION_TRANCHE_SYMBOLS.len() as u64,
        "resolv_abi proof manifest should expose strict+hardened proven symbols"
    );
    let malloc_violations = ratchet["module_deltas"]["malloc_abi"]["violating_symbols"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !malloc_violations
            .iter()
            .any(|symbol| symbol.as_str() == Some("malloc_info")),
        "malloc_info should be downgraded instead of counted as an implemented-promotion violation"
    );
    assert_eq!(
        ratchet["module_deltas"]["math_abi"]["proof_class_counts"]
            ["strict_hardened_conformance_proof"]
            .as_u64(),
        Some(1),
        "selected math_abi promotion should be backed by strict+hardened proof"
    );
    assert_eq!(
        ratchet["module_deltas"]["glibc_internal_abi"]["proof_class_counts"]
            ["documented_no_fixture_rationale"]
            .as_u64(),
        Some(1),
        "selected glibc_internal_abi promotion should carry scanner rationale"
    );
}

#[test]
fn fixture_coverage_ratchet_flags_evidence_free_implemented_promotion() {
    let previous_report_path = unique_generated_report_path("fixture_ratchet_previous_report");
    let previous = serde_json::json!({
        "symbol_status_map": {
            "__ctype_b_loc": "WrapsHostLibc"
        },
        "coverage_dashboard": {
            "status_counts": {
                "Implemented": 0,
                "RawSyscall": 0,
                "WrapsHostLibc": 1,
                "GlibcCallThrough": 0,
                "Stub": 0
            },
            "native_coverage_pct": 0.0
        }
    });
    std::fs::write(
        &previous_report_path,
        serde_json::to_vec_pretty(&previous).expect("previous report should serialize"),
    )
    .expect("failed to write previous report");

    let generated_path = unique_generated_report_path("fixture_ratchet_mutation");
    let output = generate_maintenance_report_with_previous_and_triage(
        &generated_path,
        &previous_report_path,
        None,
    );
    assert!(
        output.status.success(),
        "Maintenance validator should emit ratchet findings rather than crash:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&generated_path);
    let ratchet_policy = &report["policy_checks"]["fixture_coverage_ratchet"];
    assert_eq!(ratchet_policy["status"].as_str(), Some("fail"));
    assert!(
        ratchet_policy["violation_count"]
            .as_u64()
            .unwrap_or_default()
            >= 1,
        "evidence-free promotion should create a ratchet violation"
    );

    let violations = report["fixture_coverage_ratchet"]["violations"]
        .as_array()
        .expect("ratchet violations should be an array");
    let ctype_violation = violations
        .iter()
        .find(|row| row["symbol"].as_str() == Some("__ctype_b_loc"))
        .expect("__ctype_b_loc mutation should be reported as a violation");
    assert_eq!(
        ctype_violation["proof_class"].as_str(),
        Some("missing_fixture_evidence")
    );
    let missing: std::collections::BTreeSet<&str> = ctype_violation["missing_evidence"]
        .as_array()
        .expect("missing_evidence should be an array")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert_eq!(
        missing,
        std::collections::BTreeSet::from([
            "missing_strict_fixture",
            "missing_hardened_fixture",
            "strict_conformance_not_passing",
            "hardened_conformance_not_passing",
        ])
    );
}

#[test]
fn scanner_classifies_host_census_body_and_alternate_pattern_findings() {
    let generated_path = unique_generated_report_path("scanner_classification");
    let output = generate_maintenance_report(&generated_path);
    assert!(
        output.status.success(),
        "Maintenance validator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&generated_path);
    let issues = report["status_validation_issues"]
        .as_array()
        .expect("status_validation_issues should be an array");

    let find_issue = |symbol: &str| {
        issues
            .iter()
            .find(|issue| issue["symbol"].as_str() == Some(symbol))
            .unwrap_or_else(|| panic!("missing scanner issue for {symbol}"))
    };

    let proofed = find_issue("acos");
    assert_eq!(
        proofed["issue_class"].as_str(),
        Some("promotion_proof_accepted")
    );
    assert_eq!(
        proofed["scanner_bucket"].as_str(),
        Some("native_proven_errno_bridge")
    );
    assert_eq!(proofed["valid"].as_bool(), Some(true));

    let body_delegation = find_issue("__isoc99_sscanf");
    assert_eq!(
        body_delegation["issue_class"].as_str(),
        Some("true_host_delegation")
    );
    assert_eq!(
        body_delegation["scanner_bucket"].as_str(),
        Some("source_level_host_call")
    );
    assert_eq!(body_delegation["valid"].as_bool(), Some(false));

    let census_only = find_issue("__adjtimex");
    assert_eq!(
        census_only["issue_class"].as_str(),
        Some("host_census_unverified")
    );
    assert_eq!(
        census_only["scanner_bucket"].as_str(),
        Some("census_only_host_reachability")
    );

    let alternate_pattern = find_issue("__after_morecore_hook");
    assert_eq!(
        alternate_pattern["issue_class"].as_str(),
        Some("alternate_pattern_unresolved")
    );
    assert_eq!(
        alternate_pattern["scanner_bucket"].as_str(),
        Some("generated_or_alias_pattern")
    );
}

#[test]
fn math_abi_promotion_proof_manifest_requires_both_modes() {
    let root = repo_root();
    let manifest_path = root.join("tests/conformance/math_abi_promotion_tranche.v1.json");
    let mut manifest = load_json(&manifest_path);
    let symbols = manifest["symbols"]
        .as_array_mut()
        .expect("symbols should be an array");
    let acos = symbols
        .iter_mut()
        .find(|row| row["symbol"].as_str() == Some("acos"))
        .expect("acos proof row should exist");
    acos["hardened_conformance"]["total"] = serde_json::json!(0);
    acos["hardened_conformance"]["passed"] = serde_json::json!(0);

    let broken_manifest_path = unique_generated_report_path("math_abi_broken_proof_manifest");
    std::fs::write(
        &broken_manifest_path,
        serde_json::to_string_pretty(&manifest).expect("manifest should serialize"),
    )
    .expect("failed to write broken proof manifest");

    let generated_path = unique_generated_report_path("math_abi_broken_proof_report");
    let output =
        generate_maintenance_report_with_proof_manifest(&generated_path, &broken_manifest_path);
    assert!(
        output.status.success(),
        "Maintenance validator should emit findings rather than crash:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&generated_path);
    let issues = report["status_validation_issues"]
        .as_array()
        .expect("status_validation_issues should be an array");
    let acos_issue = issues
        .iter()
        .find(|issue| issue["symbol"].as_str() == Some("acos"))
        .expect("acos should return to invalid census status when hardened proof is missing");
    assert_eq!(acos_issue["valid"].as_bool(), Some(false));
    assert!(
        acos_issue["findings"].as_array().is_some_and(|findings| {
            findings.iter().any(|finding| {
                finding.as_str() == Some("Implemented but host delegation census detected")
            })
        }),
        "missing hardened proof should not suppress host census finding: {acos_issue:?}"
    );
}

#[test]
fn maintenance_gate_emits_structured_logs_with_required_fields() {
    let _guard = gate_test_lock();
    let output = run_support_matrix_gate(false);
    assert!(
        output.status.code().is_some(),
        "Gate process terminated without an exit code"
    );

    let root = repo_root();
    let log_path = root.join("target/conformance/support_matrix_maintenance.log.jsonl");
    assert!(
        log_path.exists(),
        "Structured log missing at {}",
        log_path.display()
    );

    let events = load_jsonl(&log_path);
    assert!(
        !events.is_empty(),
        "Structured log must contain at least one event"
    );

    for event in &events {
        for key in [
            "timestamp",
            "trace_id",
            "level",
            "event",
            "mode",
            "api_family",
            "symbol",
            "outcome",
            "errno",
            "artifact_refs",
            "details",
        ] {
            assert!(
                event.get(key).is_some(),
                "Structured event missing key `{key}`: {event:?}"
            );
        }
    }

    assert!(
        events
            .iter()
            .any(|event| event["event"].as_str() == Some("coverage_summary")
                && event["level"].as_str() == Some("info")),
        "Missing INFO coverage_summary event"
    );
    let glibc_callthrough_issue_levels: Vec<&str> = events
        .iter()
        .filter(|event| event["event"].as_str() == Some("status_validation_issue"))
        .filter(|event| event["details"]["status"].as_str() == Some("GlibcCallThrough"))
        .filter_map(|event| event["level"].as_str())
        .collect();
    assert!(
        glibc_callthrough_issue_levels
            .iter()
            .all(|level| *level == "warn"),
        "GlibcCallThrough status_validation_issue events must be WARN"
    );
    let gate_result = events
        .iter()
        .find(|event| event["event"].as_str() == Some("gate_result"))
        .expect("Missing gate_result event");
    assert!(
        matches!(gate_result["outcome"].as_str(), Some("pass" | "fail")),
        "gate_result.outcome must be pass|fail"
    );
    if !output.status.success() {
        assert!(
            events
                .iter()
                .any(|event| event["level"].as_str() == Some("error")),
            "Expected ERROR events when gate command exits non-zero"
        );
    }
    assert!(
        !events
            .iter()
            .any(|event| event["level"].as_str() == Some("trace")),
        "TRACE events must be opt-in only"
    );
}

#[test]
fn maintenance_gate_loads_promotion_triage_manifest() {
    let _guard = gate_test_lock();
    let output = run_support_matrix_gate(false);
    assert!(
        output.status.code().is_some(),
        "Gate process terminated without an exit code"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Promotion triage report:"),
        "gate should announce the generated promotion triage report\nstdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );

    let generated_report = load_json(
        &repo_root().join("target/conformance/support_matrix_maintenance.generated.json"),
    );
    let ratchet = &generated_report["fixture_coverage_ratchet"];
    assert_eq!(
        ratchet["promotion_triage_manifest_loaded"].as_bool(),
        Some(true)
    );
    assert!(
        ratchet["module_deltas"].is_object(),
        "triage-loaded ratchet should include module-level deltas"
    );
    assert!(
        ratchet["summary"]["implemented_promotion_delta"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "current support-matrix promotion wave should remain visible to the ratchet"
    );
    assert_eq!(
        generated_report["policy_checks"]["fixture_coverage_ratchet"]
            ["promotion_triage_manifest_loaded"]
            .as_bool(),
        Some(true)
    );
}

#[test]
fn maintenance_gate_trace_flag_emits_symbol_status_snapshot_events() {
    let _guard = gate_test_lock();
    let output = run_support_matrix_gate(true);
    assert!(
        output.status.code().is_some(),
        "Gate process terminated without an exit code"
    );

    let root = repo_root();
    let log_path = root.join("target/conformance/support_matrix_maintenance.log.jsonl");
    assert!(
        log_path.exists(),
        "Structured log missing at {}",
        log_path.display()
    );

    let events = load_jsonl(&log_path);
    assert!(
        events.iter().any(|event| {
            event["level"].as_str() == Some("trace")
                && event["event"].as_str() == Some("symbol_status_snapshot")
        }),
        "Expected TRACE symbol_status_snapshot events when FRANKENLIBC_SYMBOL_GATE_TRACE=1"
    );
}

#[test]
fn maintenance_gate_does_not_rewrite_canonical_report() {
    let _guard = gate_test_lock();
    let canonical_path = canonical_report_path();
    let before = std::fs::read_to_string(&canonical_path).expect("failed to read canonical report");

    let output = run_support_matrix_gate(false);
    assert!(
        output.status.code().is_some(),
        "Gate process terminated without an exit code"
    );

    let after =
        std::fs::read_to_string(&canonical_path).expect("failed to re-read canonical report");
    assert_eq!(
        before, after,
        "support matrix maintenance gate must not rewrite the canonical maintenance report"
    );
}

#[test]
fn maintenance_gate_fails_on_canonical_stable_section_drift() {
    let _guard = gate_test_lock();
    let mutated_canonical_path =
        unique_generated_report_path("support_matrix_maintenance_bad_canonical");
    let mut mutated = load_json(&canonical_report_path());
    let original_total = mutated["summary"]["total_symbols"]
        .as_u64()
        .expect("summary.total_symbols should be numeric");
    mutated["summary"]["total_symbols"] = serde_json::Value::from(original_total + 1);
    std::fs::write(
        &mutated_canonical_path,
        serde_json::to_vec_pretty(&mutated).expect("mutated canonical report should serialize"),
    )
    .expect("failed to write mutated canonical report");

    let output = run_support_matrix_gate_with_canonical(false, Some(&mutated_canonical_path));
    assert!(
        !output.status.success(),
        "gate should fail when canonical stable sections drift\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = repo_root().join("target/conformance/support_matrix_maintenance.log.jsonl");
    let events = load_jsonl(&log_path);
    let drift_event = events
        .iter()
        .find(|event| event["event"].as_str() == Some("canonical_stable_sections"))
        .expect("expected canonical_stable_sections event");
    assert_eq!(drift_event["level"].as_str(), Some("error"));
    assert_eq!(drift_event["outcome"].as_str(), Some("fail"));
    assert!(
        drift_event["details"]["mismatched_keys"]
            .as_array()
            .map(|keys| keys.iter().any(|key| key.as_str() == Some("summary")))
            .unwrap_or(false),
        "expected summary drift to be reported in mismatched_keys"
    );
}
