//! Integration test: standalone compiler-runtime blocker diagnostics (bd-zyck1.87).
//!
//! Keeps the libgcc/unwind diagnostic artifact tied to the current forge blocker
//! snapshot and prevents report-only investigation rows from silently becoming
//! replacement-level promotion evidence.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const DIAGNOSTIC_PATH: &str =
    "tests/conformance/standalone_compiler_runtime_blocker_diagnostics.v1.json";
const EXPERIMENT_PATH: &str = "tests/conformance/standalone_compiler_runtime_experiment.v1.json";
const HOST_PROBE_PLAN_PATH: &str =
    "tests/conformance/standalone_host_dependency_probe_plan.v1.json";

const EXPECTED_UNWIND_SYMBOLS: &[&str] = &[
    "_Unwind_Backtrace@GCC_3.3",
    "_Unwind_DeleteException@GCC_3.0",
    "_Unwind_GetDataRelBase@GCC_3.0",
    "_Unwind_GetIP@GCC_3.0",
    "_Unwind_GetIPInfo@GCC_4.2.0",
    "_Unwind_GetLanguageSpecificData@GCC_3.0",
    "_Unwind_GetRegionStart@GCC_3.0",
    "_Unwind_GetTextRelBase@GCC_3.0",
    "_Unwind_RaiseException@GCC_3.0",
    "_Unwind_Resume@GCC_3.0",
    "_Unwind_SetGR@GCC_3.0",
    "_Unwind_SetIP@GCC_3.0",
];

const EXPECTED_LIBGCC_VERSION_REQUIREMENTS: &[&str] = &[
    "libgcc_s.so.1:GCC_3.0",
    "libgcc_s.so.1:GCC_3.3",
    "libgcc_s.so.1:GCC_4.2.0",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn load_json(root: &Path, rel: &str) -> TestResult<Value> {
    let path = root.join(rel);
    let content =
        std::fs::read_to_string(&path).map_err(|err| format!("{}: {err}", path.display()))?;
    serde_json::from_str(&content).map_err(|err| format!("{}: {err}", path.display()))
}

fn get_path<'a>(mut value: &'a Value, dotted: &str) -> TestResult<&'a Value> {
    for segment in dotted.split('.') {
        value = value
            .get(segment)
            .ok_or_else(|| format!("{dotted}: missing segment {segment}"))?;
    }
    Ok(value)
}

fn as_str<'a>(value: &'a Value, ctx: &str) -> TestResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| format!("{ctx} must be a string"))
}

fn as_bool(value: &Value, ctx: &str) -> TestResult<bool> {
    value
        .as_bool()
        .ok_or_else(|| format!("{ctx} must be a bool"))
}

fn as_array<'a>(value: &'a Value, ctx: &str) -> TestResult<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| format!("{ctx} must be an array"))
}

fn string_vec(value: &Value, ctx: &str) -> TestResult<Vec<String>> {
    as_array(value, ctx)?
        .iter()
        .enumerate()
        .map(|(idx, item)| as_str(item, &format!("{ctx}[{idx}]")).map(str::to_owned))
        .collect()
}

fn string_set(value: &Value, ctx: &str) -> TestResult<BTreeSet<String>> {
    Ok(string_vec(value, ctx)?.into_iter().collect())
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn ensure_eq<T>(left: T, right: T, context: impl Into<String>) -> TestResult
where
    T: PartialEq + std::fmt::Debug,
{
    if left == right {
        Ok(())
    } else {
        Err(format!("{}: left={left:?} right={right:?}", context.into()))
    }
}

fn exact_set(expected: &[&str]) -> BTreeSet<String> {
    expected.iter().map(|value| (*value).to_owned()).collect()
}

fn unique_temp_dir(prefix: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system clock before Unix epoch: {err}"))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    Ok(dir)
}

fn write_executable(path: &Path, content: &str) -> TestResult {
    std::fs::write(path, content).map_err(|err| format!("{}: {err}", path.display()))?;
    let chmod = Command::new("chmod")
        .arg("+x")
        .arg(path)
        .output()
        .map_err(|err| format!("chmod {}: {err}", path.display()))?;
    ensure(
        chmod.status.success(),
        format!(
            "chmod {} failed: stdout={} stderr={}",
            path.display(),
            String::from_utf8_lossy(&chmod.stdout),
            String::from_utf8_lossy(&chmod.stderr)
        ),
    )
}

fn fake_experiment_probe_path(temp: &Path) -> TestResult<OsString> {
    let fake_bin = temp.join("fake-experiment-bin");
    std::fs::create_dir_all(&fake_bin).map_err(|err| format!("{}: {err}", fake_bin.display()))?;
    write_executable(
        &fake_bin.join("readelf"),
        r#"#!/bin/sh
artifact=""
for arg in "$@"; do
  artifact="$arg"
done
if [ "$1" = "-d" ]; then
  if echo "$artifact" | grep -q 'panic-abort-compiler-runtime-minimized'; then
    cat <<'EOF'
Dynamic section at offset 0x1000 contains 2 entries:
 0x0000000000000001 (NEEDED)             Shared library: [ld-linux-x86-64.so.2]
EOF
  else
    cat <<'EOF'
Dynamic section at offset 0x1000 contains 3 entries:
 0x0000000000000001 (NEEDED)             Shared library: [libgcc_s.so.1]
 0x0000000000000001 (NEEDED)             Shared library: [ld-linux-x86-64.so.2]
EOF
  fi
  exit 0
fi
if [ "$1" = "-Ws" ]; then
  cat <<'EOF'
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     1: 0000000000001000     1 FUNC    GLOBAL DEFAULT   10 __libc_start_main
     2: 0000000000001001     1 FUNC    GLOBAL DEFAULT   10 malloc
     3: 0000000000001002     1 FUNC    GLOBAL DEFAULT   10 free
     4: 0000000000001003     1 FUNC    GLOBAL DEFAULT   10 printf
     5: 0000000000001004     1 FUNC    GLOBAL DEFAULT   10 pthread_create
     6: 0000000000001005     1 FUNC    GLOBAL DEFAULT   10 getaddrinfo
     7: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __tls_get_addr@GLIBC_2.3
EOF
  exit 0
fi
if [ "$1" = "--version-info" ]; then
  if echo "$artifact" | grep -q 'panic-abort-compiler-runtime-minimized'; then
    cat <<'EOF'
Version needs section '.gnu.version_r' contains 1 entry:
 Addr: 0x0000000000001000  Offset: 0x00001000  Link: 7 (.dynstr)
  0x0010: Version: 1  File: ld-linux-x86-64.so.2  Cnt: 1
  0x0040:   Name: GLIBC_2.3  Flags: none  Version: 4
EOF
  else
    cat <<'EOF'
Version needs section '.gnu.version_r' contains 2 entries:
 Addr: 0x0000000000001000  Offset: 0x00001000  Link: 7 (.dynstr)
  0x0000: Version: 1  File: libgcc_s.so.1  Cnt: 1
  0x0020:   Name: GCC_3.0  Flags: none  Version: 5
  0x0010: Version: 1  File: ld-linux-x86-64.so.2  Cnt: 1
  0x0040:   Name: GLIBC_2.3  Flags: none  Version: 4
EOF
  fi
  exit 0
fi
echo unexpected readelf invocation "$@" >&2
exit 2
"#,
    )?;
    write_executable(
        &fake_bin.join("nm"),
        r#"#!/bin/sh
artifact=""
for arg in "$@"; do
  artifact="$arg"
done
if echo "$artifact" | grep -q 'panic-abort-compiler-runtime-minimized'; then
  cat <<'EOF'
                 U __tls_get_addr@GLIBC_2.3
EOF
else
  cat <<'EOF'
                 U _Unwind_Resume@GCC_3.0
                 U __tls_get_addr@GLIBC_2.3
EOF
fi
"#,
    )?;
    write_executable(
        &fake_bin.join("ldd"),
        r#"#!/bin/sh
artifact="$1"
if echo "$artifact" | grep -q 'panic-abort-compiler-runtime-minimized'; then
  cat <<'EOF'
	linux-vdso.so.1 (0x00007fff00000000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f0000000000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f0000000000)
EOF
else
  cat <<'EOF'
	linux-vdso.so.1 (0x00007fff00000000)
	libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007f0000000000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f0000000000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f0000000000)
EOF
fi
"#,
    )?;
    let mut path = OsString::from(fake_bin);
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    Ok(path)
}

fn lane_by_id<'a>(report: &'a Value, lane_id: &str) -> TestResult<&'a Value> {
    as_array(&report["lanes"], "lanes")?
        .iter()
        .find(|lane| lane["lane_id"].as_str() == Some(lane_id))
        .ok_or_else(|| format!("missing experiment lane {lane_id}"))
}

#[test]
fn compiler_runtime_diagnostic_contract_is_report_only() -> TestResult {
    let root = workspace_root()?;
    let diagnostic = load_json(&root, DIAGNOSTIC_PATH)?;

    ensure_eq(
        as_str(&diagnostic["schema_version"], "schema_version")?,
        "v1",
        "schema_version",
    )?;
    ensure_eq(
        as_str(&diagnostic["manifest_id"], "manifest_id")?,
        "standalone-compiler-runtime-blocker-diagnostics",
        "manifest_id",
    )?;
    ensure_eq(as_str(&diagnostic["bead"], "bead")?, "bd-zyck1.87", "bead")?;
    ensure_eq(
        as_str(&diagnostic["source_commit"], "source_commit")?,
        "current",
        "source_commit",
    )?;

    let policy = &diagnostic["report_policy"];
    ensure(
        !as_bool(&policy["promotion_allowed"], "promotion_allowed")?,
        "promotion must be disabled",
    )?;
    ensure(
        !as_bool(
            &policy["replacement_level_change_allowed"],
            "replacement_level_change_allowed",
        )?,
        "replacement level changes must be disabled",
    )?;
    ensure(
        !as_bool(
            &policy["default_build_profile_change_allowed"],
            "default_build_profile_change_allowed",
        )?,
        "default build profile changes must be disabled",
    )?;
    ensure(
        !as_bool(
            &policy["panic_strategy_change_allowed"],
            "panic_strategy_change_allowed",
        )?,
        "panic strategy changes must be disabled",
    )?;
    ensure(
        as_bool(
            &policy["non_baseline_experiments_require_separate_bead"],
            "non_baseline_experiments_require_separate_bead",
        )?,
        "non-baseline experiments must require a separate bead",
    )?;
    ensure_eq(
        as_str(&policy["stale_result"], "stale_result")?,
        "block_compiler_runtime_blocker_diagnostics",
        "stale_result",
    )
}

#[test]
fn compiler_runtime_experiment_manifest_is_report_only_and_opt_in() -> TestResult {
    let root = workspace_root()?;
    let diagnostic = load_json(&root, DIAGNOSTIC_PATH)?;
    let experiment = load_json(&root, EXPERIMENT_PATH)?;

    ensure_eq(
        as_str(
            &diagnostic["inputs"]["standalone_compiler_runtime_experiment"],
            "diagnostic.inputs.standalone_compiler_runtime_experiment",
        )?,
        EXPERIMENT_PATH,
        "diagnostic experiment input",
    )?;
    ensure_eq(
        as_str(&experiment["schema_version"], "experiment.schema_version")?,
        "v1",
        "experiment schema_version",
    )?;
    ensure_eq(
        as_str(&experiment["manifest_id"], "experiment.manifest_id")?,
        "standalone-compiler-runtime-experiment",
        "experiment manifest_id",
    )?;
    ensure_eq(
        as_str(&experiment["bead"], "experiment.bead")?,
        "bd-zyck1.88",
        "experiment bead",
    )?;

    let policy = &experiment["report_policy"];
    ensure(
        as_bool(&policy["report_only"], "report_only")?,
        "report only",
    )?;
    for key in [
        "promotion_allowed",
        "replacement_level_change_allowed",
        "default_forge_path_change_allowed",
        "default_build_profile_change_allowed",
    ] {
        ensure(
            !as_bool(&policy[key], key)?,
            format!("{key} must be disabled"),
        )?;
    }
    ensure_eq(
        as_str(&policy["required_mode"], "required_mode")?,
        "--compiler-runtime-experiment",
        "required mode",
    )?;

    let lanes = as_array(&experiment["experiment_lanes"], "experiment_lanes")?;
    ensure_eq(lanes.len(), 2, "experiment_lanes.len")?;
    let baseline = lanes
        .iter()
        .find(|lane| lane["lane_id"].as_str() == Some("baseline-release-standalone"))
        .ok_or_else(|| "missing baseline lane".to_string())?;
    ensure_eq(
        as_str(&baseline["panic_strategy"], "baseline.panic_strategy")?,
        "implicit-unwind",
        "baseline panic strategy",
    )?;
    ensure_eq(
        as_str(
            &baseline["expected_claim_status"],
            "baseline.expected_claim_status",
        )?,
        "claim_blocked",
        "baseline expected claim status",
    )?;

    let abort = lanes
        .iter()
        .find(|lane| lane["lane_id"].as_str() == Some("panic-abort-compiler-runtime-minimized"))
        .ok_or_else(|| "missing panic-abort lane".to_string())?;
    ensure_eq(
        as_str(&abort["panic_strategy"], "abort.panic_strategy")?,
        "abort",
        "abort panic strategy",
    )?;
    ensure_eq(
        as_str(
            &abort["env"]["CARGO_PROFILE_RELEASE_PANIC"],
            "abort.env.CARGO_PROFILE_RELEASE_PANIC",
        )?,
        "abort",
        "abort profile env",
    )?;
    ensure_eq(
        as_str(
            &abort["expected_claim_status"],
            "abort.expected_claim_status",
        )?,
        "report_only",
        "abort expected claim status",
    )
}

#[test]
fn compiler_runtime_profile_records_build_and_link_knobs() -> TestResult {
    let root = workspace_root()?;
    let diagnostic = load_json(&root, DIAGNOSTIC_PATH)?;
    let profile = &diagnostic["toolchain_profile"];

    ensure_eq(
        as_str(&profile["cargo_package"], "cargo_package")?,
        "frankenlibc-abi",
        "cargo_package",
    )?;
    ensure_eq(
        as_str(&profile["cargo_profile"], "cargo_profile")?,
        "release",
        "cargo_profile",
    )?;
    ensure_eq(
        string_vec(&profile["cargo_features"], "cargo_features")?,
        vec!["standalone".to_owned()],
        "cargo_features",
    )?;
    ensure_eq(
        as_str(&profile["target_triple"], "target_triple")?,
        "x86_64-unknown-linux-gnu",
        "target_triple",
    )?;
    ensure_eq(
        as_str(&profile["rust_toolchain_channel"], "rust_toolchain_channel")?,
        "nightly-2026-04-28",
        "rust_toolchain_channel",
    )?;
    ensure(
        as_str(
            &profile["panic_strategy"]["current"],
            "panic_strategy.current",
        )? == "implicit-unwind",
        "current panic strategy must stay implicit-unwind",
    )?;
    ensure(
        !as_bool(
            &profile["panic_strategy"]["default_change_allowed"],
            "panic_strategy.default_change_allowed",
        )?,
        "panic strategy default changes must not be allowed by this artifact",
    )?;

    let build_command = string_vec(&profile["build_command"], "build_command")?;
    ensure_eq(
        build_command,
        vec![
            "rch".to_owned(),
            "exec".to_owned(),
            "--".to_owned(),
            "cargo".to_owned(),
            "build".to_owned(),
            "-p".to_owned(),
            "frankenlibc-abi".to_owned(),
            "--release".to_owned(),
            "--features=standalone".to_owned(),
        ],
        "build_command",
    )?;

    let link_args = as_array(&profile["relevant_link_args"], "relevant_link_args")?;
    ensure_eq(link_args.len(), 1, "relevant_link_args.len")?;
    ensure_eq(
        as_str(&link_args[0]["source"], "link_args[0].source")?,
        "crates/frankenlibc-abi/build.rs",
        "link arg source",
    )?;
    ensure_eq(
        as_str(&link_args[0]["arg"], "link_args[0].arg")?,
        "-Wl,--version-script=crates/frankenlibc-abi/version_scripts/libc.map",
        "version script link arg",
    )
}

#[test]
fn compiler_runtime_diagnostic_matches_current_forge_snapshot() -> TestResult {
    let root = workspace_root()?;
    let diagnostic = load_json(&root, DIAGNOSTIC_PATH)?;
    let plan = load_json(&root, HOST_PROBE_PLAN_PATH)?;
    let snapshot = get_path(
        &plan,
        "current_forge_blocker_projection.current_forge_blocker_value_snapshot",
    )?;

    ensure_eq(
        as_str(
            &diagnostic["inputs"]["standalone_host_dependency_probe_plan"],
            "inputs.standalone_host_dependency_probe_plan",
        )?,
        HOST_PROBE_PLAN_PATH,
        "host probe plan input",
    )?;
    ensure_eq(
        as_str(
            &diagnostic["current_forge_evidence"]["latest_probe_claim_status"],
            "latest_probe_claim_status",
        )?,
        as_str(&snapshot["claim_status"], "snapshot.claim_status")?,
        "claim_status",
    )?;
    ensure_eq(
        as_str(
            &diagnostic["current_forge_evidence"]["latest_probe_failure_signature"],
            "latest_probe_failure_signature",
        )?,
        as_str(&snapshot["failure_signature"], "snapshot.failure_signature")?,
        "failure_signature",
    )?;

    let observed_needed = string_set(
        &diagnostic["current_forge_evidence"]["evidence_command_results"]["readelf_dynamic"]["observed_needed_libraries"],
        "readelf_dynamic.observed_needed_libraries",
    )?;
    let snapshot_needed = string_set(&snapshot["needed_libraries"], "snapshot.needed_libraries")?;
    ensure_eq(observed_needed, snapshot_needed, "needed libraries")?;

    let observed_resolved = string_set(
        &diagnostic["current_forge_evidence"]["evidence_command_results"]["ldd"]["observed_host_resolved_libraries"],
        "ldd.observed_host_resolved_libraries",
    )?;
    let snapshot_resolved = string_set(
        &snapshot["host_resolved_libraries"],
        "snapshot.host_resolved_libraries",
    )?;
    ensure_eq(
        observed_resolved,
        snapshot_resolved,
        "host resolved libraries",
    )
}

#[test]
fn compiler_runtime_blocker_rows_pin_libgcc_and_unwind_values() -> TestResult {
    let root = workspace_root()?;
    let diagnostic = load_json(&root, DIAGNOSTIC_PATH)?;
    let mappings = as_array(&diagnostic["blocker_mappings"], "blocker_mappings")?;
    ensure_eq(mappings.len(), 2, "blocker_mappings.len")?;

    let libgcc = mappings
        .iter()
        .find(|row| row["blocker_id"].as_str() == Some("libgcc-runtime-dependency"))
        .ok_or_else(|| "missing libgcc-runtime-dependency mapping".to_string())?;
    ensure_eq(
        as_str(&libgcc["blocking_reason"], "libgcc.blocking_reason")?,
        "libgcc_runtime_dependency",
        "libgcc blocking reason",
    )?;
    ensure_eq(
        string_vec(
            &libgcc["observed_values"]["needed_libraries"],
            "libgcc.needed_libraries",
        )?,
        vec!["libgcc_s.so.1".to_owned()],
        "libgcc needed libraries",
    )?;
    ensure_eq(
        string_set(
            &libgcc["observed_values"]["host_version_requirements"],
            "libgcc.host_version_requirements",
        )?,
        exact_set(EXPECTED_LIBGCC_VERSION_REQUIREMENTS),
        "libgcc version requirements",
    )?;

    let unwind = mappings
        .iter()
        .find(|row| row["blocker_id"].as_str() == Some("undefined-unwind-symbols"))
        .ok_or_else(|| "missing undefined-unwind-symbols mapping".to_string())?;
    ensure_eq(
        as_str(&unwind["blocking_reason"], "unwind.blocking_reason")?,
        "undefined_unwind_symbols",
        "unwind blocking reason",
    )?;
    ensure_eq(
        string_set(
            &unwind["observed_values"]["undefined_unwind_symbols"],
            "unwind.undefined_unwind_symbols",
        )?,
        exact_set(EXPECTED_UNWIND_SYMBOLS),
        "unwind symbols",
    )?;
    ensure_eq(
        diagnostic["summary"]["undefined_unwind_symbol_count"].as_u64(),
        Some(EXPECTED_UNWIND_SYMBOLS.len() as u64),
        "summary.undefined_unwind_symbol_count",
    )
}

#[test]
fn compiler_runtime_experiment_matrix_keeps_non_baseline_lanes_report_only() -> TestResult {
    let root = workspace_root()?;
    let diagnostic = load_json(&root, DIAGNOSTIC_PATH)?;
    let experiments = as_array(&diagnostic["experiment_matrix"], "experiment_matrix")?;
    ensure(
        experiments.len() >= 3,
        "experiment_matrix must include baseline and at least two follow-up lanes",
    )?;

    let baseline = experiments
        .iter()
        .find(|row| row["experiment_id"].as_str() == Some("baseline-release-standalone"))
        .ok_or_else(|| "missing baseline-release-standalone experiment".to_string())?;
    ensure_eq(
        as_str(&baseline["status"], "baseline.status")?,
        "observed_baseline",
        "baseline status",
    )?;
    ensure_eq(
        as_str(&baseline["panic_strategy"], "baseline.panic_strategy")?,
        "implicit-unwind",
        "baseline panic strategy",
    )?;

    let no_default_libs = experiments
        .iter()
        .find(|row| row["experiment_id"].as_str() == Some("standalone-final-link-no-default-libs"))
        .ok_or_else(|| "missing standalone-final-link-no-default-libs experiment".to_string())?;
    ensure_eq(
        as_str(&no_default_libs["status"], "no_default_libs.status")?,
        "observed_ineffective_report_only",
        "no-default-libs status",
    )?;
    ensure_eq(
        as_str(
            &no_default_libs["observed_link_arg"],
            "no_default_libs.observed_link_arg",
        )?,
        "-C link-arg=-nostdlib",
        "observed no-default-libs link arg",
    )?;
    ensure_eq(
        as_str(
            &no_default_libs["observed_forge_claim_status"],
            "no_default_libs.observed_forge_claim_status",
        )?,
        "claim_blocked",
        "observed no-default-libs forge claim status",
    )?;
    ensure_eq(
        as_str(
            &no_default_libs["observed_delta_classification"],
            "no_default_libs.observed_delta_classification",
        )?,
        "unchanged",
        "no-default-libs delta classification",
    )?;
    ensure(
        string_set(
            &no_default_libs["observed_needed_libraries"],
            "no_default_libs.observed_needed_libraries",
        )?
        .contains("ld-linux-x86-64.so.2"),
        "no-default-libs row must retain ld-linux direct dependency",
    )?;
    ensure(
        string_set(
            &no_default_libs["observed_host_resolved_libraries"],
            "no_default_libs.observed_host_resolved_libraries",
        )?
        .contains("libc.so.6"),
        "no-default-libs row must retain host libc resolution",
    )?;
    ensure_eq(
        as_str(
            &diagnostic["summary"]["final_link_no_default_libs_status"],
            "summary.final_link_no_default_libs_status",
        )?,
        "observed_ineffective_report_only",
        "summary final-link no-default-libs status",
    )?;

    for experiment in experiments {
        if experiment["experiment_id"].as_str() == Some("baseline-release-standalone") {
            continue;
        }
        ensure_eq(
            as_str(
                &experiment["expected_claim_status"],
                "experiment.expected_claim_status",
            )?,
            "report_only",
            format!(
                "{} expected_claim_status",
                as_str(&experiment["experiment_id"], "experiment_id")?
            ),
        )?;
        ensure(
            as_bool(
                &experiment["must_not_change_default_profile"],
                "experiment.must_not_change_default_profile",
            )?,
            format!(
                "{} must not change default profile",
                as_str(&experiment["experiment_id"], "experiment_id")?
            ),
        )?;
    }
    Ok(())
}

#[test]
fn compiler_runtime_experiment_gate_reports_lane_deltas_without_promotion() -> TestResult {
    let root = workspace_root()?;
    let temp = unique_temp_dir("compiler-runtime-experiment-gate")?;
    let source_so = temp.join("fake-libfrankenlibc_abi.so");
    std::fs::write(&source_so, b"fake elf inspected by fake tools")
        .map_err(|err| format!("{}: {err}", source_so.display()))?;
    let out_dir = temp.join("out");
    let target_root = temp.join("targets");
    let report = temp.join("standalone_compiler_runtime_experiment.report.json");
    let log = temp.join("standalone_compiler_runtime_experiment.log.jsonl");
    let fake_path = fake_experiment_probe_path(&temp)?;

    let output = Command::new(root.join("scripts/check_standalone_replacement_artifact.sh"))
        .arg("--compiler-runtime-experiment")
        .current_dir(&root)
        .env("STANDALONE_REPLACEMENT_OUT_DIR", &out_dir)
        .env(
            "STANDALONE_COMPILER_RUNTIME_EXPERIMENT_TARGET_ROOT",
            &target_root,
        )
        .env("STANDALONE_COMPILER_RUNTIME_EXPERIMENT_REPORT", &report)
        .env("STANDALONE_COMPILER_RUNTIME_EXPERIMENT_LOG", &log)
        .env("STANDALONE_COMPILER_RUNTIME_EXPERIMENT_SKIP_BUILD", "1")
        .env("STANDALONE_REPLACEMENT_SOURCE_LIB", &source_so)
        .env("PATH", fake_path)
        .env_remove("FRANKENLIBC_STANDALONE_LIB")
        .env_remove("LD_PRELOAD")
        .output()
        .map_err(|err| format!("compiler runtime experiment gate failed to start: {err}"))?;
    ensure(
        output.status.success(),
        format!(
            "compiler runtime experiment gate failed\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;

    let report_json = load_json(&root, report.to_str().ok_or("report path must be UTF-8")?)?;
    ensure_eq(
        as_str(&report_json["status"], "report.status")?,
        "pass",
        "report status",
    )?;
    ensure_eq(
        as_str(&report_json["claim_status"], "report.claim_status")?,
        "report_only",
        "report claim_status",
    )?;

    let baseline = lane_by_id(&report_json, "baseline-release-standalone")?;
    ensure_eq(
        as_str(&baseline["claim_status"], "baseline.claim_status")?,
        "claim_blocked",
        "baseline claim_status",
    )?;
    ensure(
        string_set(&baseline["needed_libraries"], "baseline.needed_libraries")?
            .contains("libgcc_s.so.1"),
        "baseline should retain libgcc_s.so.1",
    )?;
    ensure(
        string_set(
            &baseline["undefined_unwind_symbols"],
            "baseline.undefined_unwind_symbols",
        )?
        .contains("_Unwind_Resume@GCC_3.0"),
        "baseline should retain _Unwind_Resume",
    )?;

    let abort = lane_by_id(&report_json, "panic-abort-compiler-runtime-minimized")?;
    ensure_eq(
        as_str(&abort["claim_status"], "abort.claim_status")?,
        "report_only",
        "abort claim_status",
    )?;
    ensure_eq(
        as_str(
            &abort["env"]["CARGO_PROFILE_RELEASE_PANIC"],
            "abort.env.CARGO_PROFILE_RELEASE_PANIC",
        )?,
        "abort",
        "abort env",
    )?;
    ensure(
        as_str(&abort["cargo_target_dir"], "abort.cargo_target_dir")?
            .contains("panic-abort-compiler-runtime-minimized"),
        "abort lane should use its own CARGO_TARGET_DIR",
    )?;
    ensure(
        !string_set(&abort["needed_libraries"], "abort.needed_libraries")?
            .contains("libgcc_s.so.1"),
        "abort lane fake evidence should remove libgcc_s.so.1",
    )?;
    ensure(
        string_set(
            &abort["undefined_unwind_symbols"],
            "abort.undefined_unwind_symbols",
        )?
        .is_empty(),
        "abort lane fake evidence should remove unwind symbols",
    )?;

    let comparison = &report_json["comparison"];
    ensure_eq(
        as_str(
            &comparison["delta_classification"],
            "comparison.delta_classification",
        )?,
        "improvement",
        "comparison delta classification",
    )?;
    ensure(
        string_set(
            &comparison["removed_needed_libraries"],
            "comparison.removed_needed_libraries",
        )?
        .contains("libgcc_s.so.1"),
        "comparison should record removed libgcc_s.so.1",
    )?;
    ensure(
        string_set(
            &comparison["removed_undefined_unwind_symbols"],
            "comparison.removed_undefined_unwind_symbols",
        )?
        .contains("_Unwind_Resume@GCC_3.0"),
        "comparison should record removed _Unwind_Resume",
    )?;
    ensure(
        string_set(
            &comparison["removed_version_requirements"],
            "comparison.removed_version_requirements",
        )?
        .contains("libgcc_s.so.1:GCC_3.0"),
        "comparison should record removed libgcc version requirement",
    )?;
    ensure(
        log.exists(),
        format!("experiment log should exist at {}", log.display()),
    )
}
