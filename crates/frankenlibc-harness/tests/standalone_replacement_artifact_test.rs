//! Integration tests for the standalone replacement artifact forge gate.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "event",
    "mode",
    "artifact_path",
    "artifact_status",
    "claim_status",
    "source_commit",
    "artifact_sha256",
    "command",
    "exit_code",
    "failure_signature",
    "artifact_refs",
];

const REQUIRED_REPORT_FIELDS: &[&str] = &[
    "artifact_state.dependency_breakdown.needed_libraries",
    "artifact_state.dependency_breakdown.ldd_libraries",
    "artifact_state.dependency_breakdown.host_needed_libraries",
    "artifact_state.dependency_breakdown.undefined_symbols",
    "artifact_state.dependency_breakdown.undefined_unwind_symbols",
    "artifact_state.dependency_breakdown.undefined_glibc_symbols",
    "artifact_state.dependency_breakdown.undefined_tls_symbols",
    "artifact_state.dependency_breakdown.version_needs",
    "artifact_state.dependency_breakdown.host_version_requirements",
    "artifact_state.dependency_breakdown.loader_needed",
    "artifact_state.dependency_breakdown.blocking_reasons",
    "artifact_state.dependency_breakdown.blocker_catalog",
    "tool_evidence.*.exit_code",
    "tool_evidence.*.timed_out",
    "tool_evidence.*.timeout_secs",
    "tool_evidence.*.path",
    "artifact_state.dependency_breakdown.host_direct_needed_libraries",
    "artifact_state.dependency_breakdown.host_resolved_libraries",
    "artifact_state.sampled_symbols_present",
    "artifact_state.symbol_samples",
    "claim_status",
    "source_commit",
    "artifact_state.status",
    "artifact_state.failure_signature",
    "artifact_state.host_glibc_dependency",
    "artifact_state.path",
    "artifact_state.sha256",
    "artifact_state.mtime",
];

const REQUIRED_EVIDENCE_FILES: &[&str] = &[
    "build.stdout.txt",
    "build.stderr.txt",
    "artifact.sha256",
    "artifact.readelf.dynamic.txt",
    "artifact.readelf.symbols.txt",
    "artifact.readelf.version.txt",
    "artifact.nm.dynamic.txt",
    "artifact.ldd.txt",
];

const REQUIRED_TOOLS: &[&str] = &["rch", "cargo", "readelf", "nm", "ldd"];

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn string_set(value: &serde_json::Value) -> HashSet<String> {
    value
        .as_array()
        .expect("value should be an array")
        .iter()
        .map(|entry| entry.as_str().expect("entry should be string").to_owned())
        .collect()
}

fn symbol_sample_map(value: &serde_json::Value) -> HashSet<String> {
    value
        .as_object()
        .expect("symbol_samples should be an object")
        .iter()
        .filter_map(|(symbol, present)| {
            present.as_bool().unwrap_or(false).then_some(symbol.clone())
        })
        .collect()
}

fn manifest() -> serde_json::Value {
    load_json(&workspace_root().join("tests/conformance/standalone_replacement_artifact.v1.json"))
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn fake_ldd_failure_path(temp: &Path) -> OsString {
    let fake_bin = temp.join("fake-bin");
    std::fs::create_dir_all(&fake_bin).expect("create fake bin dir");
    let fake_ldd = fake_bin.join("ldd");
    std::fs::write(&fake_ldd, "#!/bin/sh\necho ldd probe failed >&2\nexit 42\n")
        .expect("write fake ldd");
    let chmod = Command::new("chmod")
        .arg("+x")
        .arg(&fake_ldd)
        .output()
        .expect("chmod should run");
    assert!(
        chmod.status.success(),
        "chmod failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&chmod.stdout),
        String::from_utf8_lossy(&chmod.stderr)
    );
    let mut path = OsString::from(fake_bin);
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    path
}

fn fake_dependency_probe_path(temp: &Path) -> OsString {
    let fake_bin = temp.join("fake-probe-bin");
    std::fs::create_dir_all(&fake_bin).expect("create fake probe bin dir");
    std::fs::write(
        fake_bin.join("readelf"),
        r#"#!/bin/sh
if [ "$1" = "-d" ]; then
  cat <<'EOF'
Dynamic section at offset 0x1000 contains 3 entries:
 0x0000000000000001 (NEEDED)             Shared library: [libgcc_s.so.1]
 0x0000000000000001 (NEEDED)             Shared library: [ld-linux-x86-64.so.2]
EOF
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
     7: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.2.5
     8: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __tls_get_addr@GLIBC_2.3
     9: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND _Unwind_Resume@GCC_3.0
EOF
  exit 0
fi
if [ "$1" = "--version-info" ]; then
  cat <<'EOF'
Version needs section '.gnu.version_r' contains 2 entries:
 Addr: 0x0000000000001000  Offset: 0x00001000  Link: 7 (.dynstr)
  000000: Version: 1  File: libgcc_s.so.1  Cnt: 2
  0x0020:   Name: GCC_3.0  Flags: none  Version: 5
  0x0030:   Name: GCC_3.3  Flags: none  Version: 6
  0x0010: Version: 1  File: ld-linux-x86-64.so.2  Cnt: 1
  0x0040:   Name: GLIBC_2.3  Flags: none  Version: 4
EOF
  exit 0
fi
echo unexpected readelf invocation "$@" >&2
exit 2
"#,
    )
    .expect("write fake readelf");
    std::fs::write(
        fake_bin.join("nm"),
        r#"#!/bin/sh
cat <<'EOF'
                 U _Unwind_Resume@GCC_3.0
                 U __tls_get_addr@GLIBC_2.3
                 U printf@GLIBC_2.2.5
EOF
"#,
    )
    .expect("write fake nm");
    std::fs::write(
        fake_bin.join("ldd"),
        r#"#!/bin/sh
cat <<'EOF'
	linux-vdso.so.1 (0x00007fff00000000)
	libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007f0000000000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f0000000000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f0000000000)
EOF
"#,
    )
    .expect("write fake ldd");
    for tool in ["readelf", "nm", "ldd"] {
        let chmod = Command::new("chmod")
            .arg("+x")
            .arg(fake_bin.join(tool))
            .output()
            .expect("chmod should run");
        assert!(
            chmod.status.success(),
            "chmod failed for {tool}:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&chmod.stdout),
            String::from_utf8_lossy(&chmod.stderr)
        );
    }
    let mut path = OsString::from(fake_bin);
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    path
}

fn fake_missing_sample_probe_path(temp: &Path) -> OsString {
    let fake_bin = temp.join("fake-missing-sample-bin");
    std::fs::create_dir_all(&fake_bin).expect("create fake probe bin dir");
    std::fs::write(
        fake_bin.join("readelf"),
        r#"#!/bin/sh
if [ "$1" = "-d" ]; then
  cat <<'EOF'
Dynamic section at offset 0x1000 contains 1 entry:
 0x000000000000000e (SONAME)             Library soname: [libfrankenlibc_replace.so]
EOF
  exit 0
fi
if [ "$1" = "-Ws" ]; then
  cat <<'EOF'
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     1: 0000000000002000     1 FUNC    GLOBAL DEFAULT   10 frankenlibc_private_only
EOF
  exit 0
fi
if [ "$1" = "--version-info" ]; then
  echo 'No version information found in this file.'
  exit 0
fi
echo unexpected readelf invocation "$@" >&2
exit 2
"#,
    )
    .expect("write fake readelf");
    std::fs::write(
        fake_bin.join("nm"),
        "0000000000002000 T frankenlibc_private_only\n",
    )
    .expect("write fake nm");
    std::fs::write(fake_bin.join("ldd"), "statically linked\n").expect("write fake ldd");
    for tool in ["readelf", "nm", "ldd"] {
        let chmod = Command::new("chmod")
            .arg("+x")
            .arg(fake_bin.join(tool))
            .output()
            .expect("chmod should run");
        assert!(
            chmod.status.success(),
            "chmod failed for {tool}:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&chmod.stdout),
            String::from_utf8_lossy(&chmod.stderr)
        );
    }
    let mut path = OsString::from(fake_bin);
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    path
}

fn fake_inspection_probe_failure_path(temp: &Path, failing_probe: &str) -> OsString {
    let fake_bin = temp.join(format!("fake-{failing_probe}-probe-bin"));
    std::fs::create_dir_all(&fake_bin).expect("create fake probe bin dir");
    std::fs::write(
        fake_bin.join("readelf"),
        format!(
            r#"#!/bin/sh
if [ "$1" = "-d" ]; then
  cat <<'EOF'
Dynamic section at offset 0x1000 contains 1 entry:
 0x000000000000000e (SONAME)             Library soname: [libfrankenlibc_replace.so]
EOF
  exit 0
fi
if [ "$1" = "-Ws" ]; then
  if [ "{failing_probe}" = "readelf-symbols" ]; then
    echo readelf symbols probe failed >&2
    exit 43
  fi
  cat <<'EOF'
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     1: 0000000000001000     1 FUNC    GLOBAL DEFAULT   10 __libc_start_main
     2: 0000000000001001     1 FUNC    GLOBAL DEFAULT   10 malloc
     3: 0000000000001002     1 FUNC    GLOBAL DEFAULT   10 free
     4: 0000000000001003     1 FUNC    GLOBAL DEFAULT   10 printf
     5: 0000000000001004     1 FUNC    GLOBAL DEFAULT   10 pthread_create
     6: 0000000000001005     1 FUNC    GLOBAL DEFAULT   10 getaddrinfo
EOF
  exit 0
fi
if [ "$1" = "--version-info" ]; then
  if [ "{failing_probe}" = "readelf-version" ]; then
    echo readelf version probe failed >&2
    exit 44
  fi
  echo 'No version information found in this file.'
  exit 0
fi
echo unexpected readelf invocation "$@" >&2
exit 2
"#
        ),
    )
    .expect("write fake readelf");
    std::fs::write(
        fake_bin.join("nm"),
        format!(
            r#"#!/bin/sh
if [ "{failing_probe}" = "nm" ]; then
  echo nm probe failed >&2
  exit 45
fi
cat <<'EOF'
0000000000001000 T __libc_start_main
0000000000001001 T malloc
0000000000001002 T free
0000000000001003 T printf
0000000000001004 T pthread_create
0000000000001005 T getaddrinfo
EOF
"#
        ),
    )
    .expect("write fake nm");
    std::fs::write(
        fake_bin.join("ldd"),
        r#"#!/bin/sh
echo '	statically linked'
exit 0
"#,
    )
    .expect("write fake ldd");
    for tool in ["readelf", "nm", "ldd"] {
        let chmod = Command::new("chmod")
            .arg("+x")
            .arg(fake_bin.join(tool))
            .output()
            .expect("chmod should run");
        assert!(
            chmod.status.success(),
            "chmod failed for {tool}:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&chmod.stdout),
            String::from_utf8_lossy(&chmod.stderr)
        );
    }
    let mut path = OsString::from(fake_bin);
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    path
}

fn host_tool_path(tool: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(tool);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn write_executable(path: &Path, content: impl AsRef<[u8]>) {
    std::fs::write(path, content).expect("write executable");
    let chmod = Command::new("chmod")
        .arg("+x")
        .arg(path)
        .output()
        .expect("chmod should run");
    assert!(
        chmod.status.success(),
        "chmod failed for {}:\nstdout={}\nstderr={}",
        path.display(),
        String::from_utf8_lossy(&chmod.stdout),
        String::from_utf8_lossy(&chmod.stderr)
    );
}

fn write_host_tool_proxy(fake_bin: &Path, tool: &str) -> bool {
    let Some(host_path) = host_tool_path(tool) else {
        return false;
    };
    write_executable(
        &fake_bin.join(tool),
        format!("#!/bin/sh\nexec {} \"$@\"\n", host_path.display()),
    );
    true
}

fn fake_missing_inspection_tool_path(temp: &Path, missing_tool: &str) -> Option<OsString> {
    let fake_bin = temp.join(format!("fake-missing-{missing_tool}-bin"));
    std::fs::create_dir_all(&fake_bin).expect("create missing-tool fake bin dir");
    for tool in ["bash", "python3", "dirname", "mkdir", "cat"] {
        if !write_host_tool_proxy(&fake_bin, tool) {
            return None;
        }
    }
    if missing_tool != "readelf" {
        write_executable(
            &fake_bin.join("readelf"),
            r#"#!/bin/sh
if [ "$1" = "-d" ]; then
  cat <<'EOF'
Dynamic section at offset 0x1000 contains 1 entry:
 0x000000000000000e (SONAME)             Library soname: [libfrankenlibc_replace.so]
EOF
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
EOF
  exit 0
fi
if [ "$1" = "--version-info" ]; then
  echo 'No version information found in this file.'
  exit 0
fi
echo unexpected readelf invocation "$@" >&2
exit 2
"#,
        );
    }
    if missing_tool != "nm" {
        write_executable(
            &fake_bin.join("nm"),
            r#"#!/bin/sh
cat <<'EOF'
0000000000001000 T __libc_start_main
0000000000001001 T malloc
0000000000001002 T free
0000000000001003 T printf
0000000000001004 T pthread_create
0000000000001005 T getaddrinfo
EOF
"#,
        );
    }
    if missing_tool != "ldd" {
        write_executable(
            &fake_bin.join("ldd"),
            r#"#!/bin/sh
echo '	statically linked'
exit 0
"#,
        );
    }
    Some(OsString::from(fake_bin))
}

fn fake_timeout_inspection_probe_path(temp: &Path, timeout_probe: &str) -> OsString {
    let fake_bin = temp.join(format!("fake-timeout-{timeout_probe}-probe-bin"));
    std::fs::create_dir_all(&fake_bin).expect("create timeout probe fake bin dir");
    std::fs::write(
        fake_bin.join("readelf"),
        format!(
            r#"#!/bin/sh
if [ "$1" = "-d" ]; then
  if [ "{timeout_probe}" = "readelf-dynamic" ]; then
    sleep 2
  fi
  cat <<'EOF'
Dynamic section at offset 0x1000 contains 1 entry:
 0x000000000000000e (SONAME)             Library soname: [libfrankenlibc_replace.so]
EOF
  exit 0
fi
if [ "$1" = "-Ws" ]; then
  if [ "{timeout_probe}" = "readelf-symbols" ]; then
    sleep 2
  fi
  cat <<'EOF'
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     1: 0000000000001000     1 FUNC    GLOBAL DEFAULT   10 __libc_start_main
     2: 0000000000001001     1 FUNC    GLOBAL DEFAULT   10 malloc
     3: 0000000000001002     1 FUNC    GLOBAL DEFAULT   10 free
     4: 0000000000001003     1 FUNC    GLOBAL DEFAULT   10 printf
     5: 0000000000001004     1 FUNC    GLOBAL DEFAULT   10 pthread_create
     6: 0000000000001005     1 FUNC    GLOBAL DEFAULT   10 getaddrinfo
EOF
  exit 0
fi
if [ "$1" = "--version-info" ]; then
  if [ "{timeout_probe}" = "readelf-version" ]; then
    sleep 2
  fi
  echo 'No version information found in this file.'
  exit 0
fi
echo unexpected readelf invocation "$@" >&2
exit 2
"#
        ),
    )
    .expect("write timeout readelf");
    std::fs::write(
        fake_bin.join("nm"),
        format!(
            r#"#!/bin/sh
if [ "{timeout_probe}" = "nm" ]; then
  sleep 2
fi
cat <<'EOF'
0000000000001000 T __libc_start_main
0000000000001001 T malloc
0000000000001002 T free
0000000000001003 T printf
0000000000001004 T pthread_create
0000000000001005 T getaddrinfo
EOF
"#
        ),
    )
    .expect("write timeout nm");
    std::fs::write(
        fake_bin.join("ldd"),
        format!(
            r#"#!/bin/sh
if [ "{timeout_probe}" = "ldd" ]; then
  sleep 2
fi
echo '	statically linked'
exit 0
"#
        ),
    )
    .expect("write timeout ldd");
    for tool in ["readelf", "nm", "ldd"] {
        let chmod = Command::new("chmod")
            .arg("+x")
            .arg(fake_bin.join(tool))
            .output()
            .expect("chmod should run");
        assert!(
            chmod.status.success(),
            "chmod failed for {tool}:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&chmod.stdout),
            String::from_utf8_lossy(&chmod.stderr)
        );
    }
    let mut path = OsString::from(fake_bin);
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    path
}

fn run_gate_with_env(
    mode: &str,
    prefix: &str,
    envs: &[(&str, &str)],
) -> (PathBuf, PathBuf, PathBuf, std::process::Output) {
    let root = workspace_root();
    let temp = unique_temp_dir(prefix);
    let out_dir = temp.join("out");
    let cargo_target = temp.join("cargo-target");
    let report = temp.join("standalone_replacement_artifact.report.json");
    let log = temp.join("standalone_replacement_artifact.log.jsonl");
    let mut command = Command::new(root.join("scripts/check_standalone_replacement_artifact.sh"));
    command
        .arg(mode)
        .current_dir(&root)
        .env("STANDALONE_REPLACEMENT_OUT_DIR", &out_dir)
        .env("STANDALONE_REPLACEMENT_CARGO_TARGET_DIR", &cargo_target)
        .env("STANDALONE_REPLACEMENT_REPORT", &report)
        .env("STANDALONE_REPLACEMENT_LOG", &log)
        .env_remove("FRANKENLIBC_STANDALONE_LIB")
        .env_remove("LD_PRELOAD");
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command
        .output()
        .expect("standalone replacement artifact gate should run");
    (temp, report, log, output)
}

fn run_gate(mode: &str, prefix: &str) -> (PathBuf, PathBuf, PathBuf, std::process::Output) {
    run_gate_with_env(mode, prefix, &[])
}

fn write_manifest_variant(prefix: &str, mut mutate: impl FnMut(&mut serde_json::Value)) -> PathBuf {
    let dir = unique_temp_dir(prefix);
    let path = dir.join("standalone_replacement_artifact.v1.json");
    let mut value = manifest();
    mutate(&mut value);
    let content = serde_json::to_string_pretty(&value).expect("manifest variant should serialize");
    std::fs::write(&path, format!("{content}\n")).expect("write manifest variant");
    path
}

#[test]
fn manifest_matches_forge_contract() {
    let manifest = manifest();
    assert_eq!(manifest["schema_version"].as_str(), Some("v1"));
    assert_eq!(manifest["bead"].as_str(), Some("bd-srtkq"));
    assert_eq!(
        manifest["manifest_id"].as_str(),
        Some("standalone-replacement-artifact")
    );
    assert_eq!(
        manifest["inputs"],
        serde_json::json!({
            "packaging_spec": "tests/conformance/packaging_spec.json",
            "replacement_levels": "tests/conformance/replacement_levels.json",
            "standalone_link_run_smoke": "tests/conformance/standalone_link_run_smoke.v1.json",
        })
    );
    assert_eq!(
        manifest["summary"],
        serde_json::json!({
            "bead": "bd-srtkq",
            "row_count": 1,
            "ld_preload_substitutes_for_standalone": false,
            "next_consumers": [
                "bd-4xk24",
                "tests/conformance/standalone_link_run_smoke.v1.json",
            ],
        })
    );
    assert_eq!(
        manifest["artifact_policy"],
        serde_json::json!({
            "canonical_artifact_name": "libfrankenlibc_replace.so",
            "source_cdylib_name": "libfrankenlibc_abi.so",
            "cargo_package": "frankenlibc-abi",
            "cargo_profile": "release",
            "cargo_features": ["standalone"],
            "default_cargo_target_dir": "target/standalone_replacement_artifact/cargo-target",
            "artifact_env": "FRANKENLIBC_STANDALONE_LIB",
            "source_artifact_env": "STANDALONE_REPLACEMENT_SOURCE_LIB",
            "cargo_target_dir_env": "STANDALONE_REPLACEMENT_CARGO_TARGET_DIR",
            "build_command_env": "STANDALONE_REPLACEMENT_BUILD_CMD",
            "skip_build_env": "STANDALONE_REPLACEMENT_SKIP_BUILD",
            "stale_if_older_than_head": true,
            "ld_preload_substitutes_allowed": false,
        })
    );
    assert_eq!(
        manifest["artifact_policy"]["canonical_artifact_name"].as_str(),
        Some("libfrankenlibc_replace.so")
    );
    assert_eq!(
        manifest["artifact_policy"]["source_cdylib_name"].as_str(),
        Some("libfrankenlibc_abi.so")
    );
    assert_eq!(
        manifest["artifact_policy"]["ld_preload_substitutes_allowed"].as_bool(),
        Some(false)
    );
    let tools: Vec<_> = manifest
        .get("required_tools")
        .and_then(serde_json::Value::as_array)
        .expect("required_tools should be an array")
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(tools, REQUIRED_TOOLS);
    let hash_policy = manifest
        .get("hash_evidence_policy")
        .and_then(serde_json::Value::as_object)
        .expect("hash_evidence_policy should be an object");
    assert_eq!(
        hash_policy
            .get("algorithm")
            .and_then(serde_json::Value::as_str),
        Some("sha256")
    );
    assert_eq!(
        hash_policy
            .get("implementation")
            .and_then(serde_json::Value::as_str),
        Some("python3 hashlib.sha256")
    );
    assert_eq!(
        hash_policy
            .get("reported_field")
            .and_then(serde_json::Value::as_str),
        Some("artifact_state.sha256")
    );
    assert_eq!(
        hash_policy
            .get("evidence_file")
            .and_then(serde_json::Value::as_str),
        Some("artifact.sha256")
    );
    let symbol_samples: Vec<_> = manifest["symbol_samples"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(
        symbol_samples,
        [
            "__libc_start_main",
            "malloc",
            "free",
            "printf",
            "pthread_create",
            "getaddrinfo",
        ]
    );

    let fields: Vec<_> = manifest["required_log_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(fields, REQUIRED_LOG_FIELDS);

    let report_fields: Vec<_> = manifest["required_report_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(report_fields, REQUIRED_REPORT_FIELDS);

    let evidence_files: Vec<_> = manifest
        .get("required_evidence_files")
        .and_then(serde_json::Value::as_array)
        .expect("required_evidence_files should be an array")
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(evidence_files, REQUIRED_EVIDENCE_FILES);

    let timeout_policy = &manifest["inspection_timeout_policy"];
    assert_eq!(
        timeout_policy["env"].as_str(),
        Some("STANDALONE_REPLACEMENT_INSPECTION_TIMEOUT_SECS")
    );
    assert_eq!(timeout_policy["default_secs"].as_i64(), Some(60));
    assert_eq!(timeout_policy["min_secs"].as_i64(), Some(1));
    assert_eq!(timeout_policy["max_secs"].as_i64(), Some(300));
    assert_eq!(timeout_policy["timeout_exit_code"].as_i64(), Some(124));
    assert_eq!(
        timeout_policy["reported_field"].as_str(),
        Some("tool_evidence.*.timeout_secs")
    );

    let classifications: HashSet<_> = manifest["expected_failure_classifications"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["failure_signature"].as_str().unwrap())
        .collect();
    let classification_results: HashMap<_, _> = manifest["expected_failure_classifications"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["failure_signature"].as_str().unwrap(),
                entry["expected_result"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        classification_results,
        HashMap::from([
            ("standalone_artifact_missing", "claim_blocked"),
            ("standalone_artifact_stale", "claim_blocked"),
            ("wrong_artifact_profile", "claim_blocked"),
            ("non_elf_artifact", "fail"),
            ("host_glibc_dependency", "claim_blocked"),
            ("artifact_dependency_inspection_failed", "claim_blocked"),
            ("symbol_evidence_missing", "claim_blocked"),
        ])
    );
    for signature in [
        "standalone_artifact_missing",
        "standalone_artifact_stale",
        "wrong_artifact_profile",
        "non_elf_artifact",
        "host_glibc_dependency",
        "artifact_dependency_inspection_failed",
        "symbol_evidence_missing",
    ] {
        assert!(classifications.contains(signature), "missing {signature}");
    }
    assert_eq!(
        manifest["claim_policy"]["current_level_must_remain"].as_str(),
        Some("L0")
    );
    assert_eq!(
        manifest["claim_policy"]["successful_forge_is_not_promotion"].as_bool(),
        Some(true)
    );
    let claim_unblocked_only_when: Vec<_> = manifest["claim_policy"]["claim_unblocked_only_when"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(
        claim_unblocked_only_when,
        [
            "artifact_status=current",
            "artifact_name=libfrankenlibc_replace.so",
            "readelf_dynamic_status=pass",
            "ldd_status=pass",
            "host_glibc_dependency=false",
            "sampled_symbols_present=true",
            "source_commit matches HEAD",
        ]
    );

    let blocker_catalog_contract = manifest
        .get("blocker_catalog_contract")
        .and_then(serde_json::Value::as_object)
        .expect("blocker_catalog_contract should be an object");
    assert_eq!(
        blocker_catalog_contract["required_row_fields"],
        serde_json::json!([
            "owner_surface",
            "severity",
            "evidence_fields",
            "next_action"
        ])
    );
    let definitions = blocker_catalog_contract["definitions"]
        .as_object()
        .expect("blocker catalog definitions should be an object");
    assert_eq!(definitions.len(), 10);
    for reason in [
        "host_needed_libraries_present",
        "host_direct_needed_libraries_present",
        "host_resolved_libraries_present",
        "host_loader_dependency",
        "host_libc_dependency",
        "libgcc_runtime_dependency",
        "undefined_unwind_symbols",
        "undefined_glibc_symbols",
        "undefined_tls_symbols",
        "host_version_requirements",
    ] {
        assert!(
            definitions.contains_key(reason),
            "missing blocker catalog definition for {reason}"
        );
        let row = &definitions[reason];
        assert_eq!(row["severity"].as_str(), Some("claim_blocking"));
        assert!(
            row["owner_surface"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "catalog definition {reason} should name owner_surface"
        );
        assert!(
            row["evidence_fields"]
                .as_array()
                .is_some_and(|fields| !fields.is_empty()),
            "catalog definition {reason} should cite evidence_fields"
        );
        assert!(
            row["next_action"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "catalog definition {reason} should include next_action"
        );
    }
    assert_eq!(
        definitions["undefined_tls_symbols"]["owner_surface"].as_str(),
        Some("tls_startup")
    );
    assert_eq!(
        definitions["host_version_requirements"]["owner_surface"].as_str(),
        Some("symbol_versioning")
    );
}

#[test]
fn validate_only_rejects_required_tools_contract_drift() {
    let manifest_path =
        write_manifest_variant("standalone-artifact-tools-drift-manifest", |manifest| {
            manifest["required_tools"] =
                serde_json::json!(["rch", "cargo", "readelf", "nm", "ldd", "sha256"]);
        });
    let manifest_env = manifest_path.to_string_lossy().into_owned();
    let envs = [("STANDALONE_REPLACEMENT_MANIFEST", manifest_env.as_str())];
    let (_temp, report, _log, output) =
        run_gate_with_env("--validate-only", "standalone-artifact-tools-drift", &envs);
    assert!(
        !output.status.success(),
        "required_tools drift should fail closed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report_json = load_json(&report);
    assert_eq!(report_json["status"].as_str(), Some("fail"));
    let errors = report_json["errors"]
        .as_array()
        .expect("errors should be an array");
    assert!(
        errors
            .iter()
            .any(|error| error.as_str() == Some("required_tools do not match script contract")),
        "expected required_tools contract error: {errors:?}"
    );
}

#[test]
fn validate_only_rejects_hash_evidence_policy_contract_drift() {
    let manifest_path = write_manifest_variant(
        "standalone-artifact-hash-policy-drift-manifest",
        |manifest| {
            manifest["hash_evidence_policy"]["implementation"] =
                serde_json::Value::String("sha256sum executable".to_owned());
        },
    );
    let manifest_env = manifest_path.to_string_lossy().into_owned();
    let envs = [("STANDALONE_REPLACEMENT_MANIFEST", manifest_env.as_str())];
    let (_temp, report, _log, output) = run_gate_with_env(
        "--validate-only",
        "standalone-artifact-hash-policy-drift",
        &envs,
    );
    assert!(
        !output.status.success(),
        "hash_evidence_policy drift should fail closed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report_json = load_json(&report);
    assert_eq!(report_json["status"].as_str(), Some("fail"));
    let errors = report_json["errors"]
        .as_array()
        .expect("errors should be an array");
    assert!(
        errors.iter().any(|error| {
            error.as_str() == Some("hash_evidence_policy does not match script contract")
        }),
        "expected hash_evidence_policy contract error: {errors:?}"
    );
}

#[test]
fn validate_only_rejects_symbol_samples_contract_drift() {
    let manifest_path = write_manifest_variant(
        "standalone-artifact-symbol-samples-drift-manifest",
        |manifest| {
            manifest["symbol_samples"] =
                serde_json::json!(["__libc_start_main", "malloc", "free", "printf"]);
        },
    );
    let manifest_env = manifest_path.to_string_lossy().into_owned();
    let envs = [("STANDALONE_REPLACEMENT_MANIFEST", manifest_env.as_str())];
    let (_temp, report, _log, output) = run_gate_with_env(
        "--validate-only",
        "standalone-artifact-symbol-samples-drift",
        &envs,
    );
    assert!(
        !output.status.success(),
        "symbol_samples drift should fail closed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report_json = load_json(&report);
    assert_eq!(report_json["status"].as_str(), Some("fail"));
    let errors = report_json["errors"]
        .as_array()
        .expect("errors should be an array");
    assert!(
        errors
            .iter()
            .any(|error| error.as_str() == Some("symbol_samples do not match script contract")),
        "expected symbol_samples contract error: {errors:?}"
    );
}

#[test]
fn validate_only_rejects_artifact_policy_contract_drift() {
    let manifest_path =
        write_manifest_variant("standalone-artifact-policy-drift-manifest", |manifest| {
            manifest["artifact_policy"]["cargo_package"] =
                serde_json::Value::String("frankenlibc".to_owned());
            manifest["artifact_policy"]["cargo_profile"] =
                serde_json::Value::String("dev".to_owned());
            manifest["artifact_policy"]["artifact_env"] =
                serde_json::Value::String("FRANKENLIBC_LD_PRELOAD_LIB".to_owned());
            manifest["artifact_policy"]["stale_if_older_than_head"] =
                serde_json::Value::Bool(false);
            manifest["artifact_policy"]["ld_preload_substitutes_allowed"] =
                serde_json::Value::Bool(true);
        });
    let manifest_env = manifest_path.to_string_lossy().into_owned();
    let envs = [("STANDALONE_REPLACEMENT_MANIFEST", manifest_env.as_str())];
    let (_temp, report, _log, output) =
        run_gate_with_env("--validate-only", "standalone-artifact-policy-drift", &envs);
    assert!(
        !output.status.success(),
        "artifact_policy drift should fail closed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report_json = load_json(&report);
    assert_eq!(report_json["status"].as_str(), Some("fail"));
    let errors = report_json["errors"]
        .as_array()
        .expect("errors should be an array");
    assert!(
        errors
            .iter()
            .any(|error| error.as_str() == Some("artifact_policy does not match script contract")),
        "expected artifact_policy contract error: {errors:?}"
    );
}

#[test]
fn validate_only_rejects_manifest_identity_contract_drift() {
    let manifest_path = write_manifest_variant("standalone-identity-drift-manifest", |manifest| {
        manifest["manifest_id"] =
            serde_json::Value::String("standalone-replacement-artifact-v2".to_owned());
        manifest["inputs"]["packaging_spec"] =
            serde_json::Value::String("tests/conformance/packaging_spec.next.json".to_owned());
        manifest["inputs"]["standalone_link_run_smoke"] = serde_json::Value::String(
            "tests/conformance/ld_preload_smoke_summary.v1.json".to_owned(),
        );
        manifest["summary"]["row_count"] = serde_json::Value::Number(2.into());
        manifest["summary"]["ld_preload_substitutes_for_standalone"] =
            serde_json::Value::Bool(true);
        manifest["summary"]["next_consumers"] = serde_json::json!([
            "bd-4xk24",
            "tests/conformance/ld_preload_smoke_summary.v1.json",
        ]);
    });
    let manifest_env = manifest_path.to_string_lossy().into_owned();
    let envs = [("STANDALONE_REPLACEMENT_MANIFEST", manifest_env.as_str())];
    let (_temp, report, _log, output) =
        run_gate_with_env("--validate-only", "standalone-identity-drift", &envs);
    assert!(
        !output.status.success(),
        "manifest identity drift should fail closed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report_json = load_json(&report);
    assert_eq!(report_json["status"].as_str(), Some("fail"));
    let errors = report_json["errors"]
        .as_array()
        .expect("errors should be an array");
    for expected in [
        "manifest_id does not match script contract",
        "inputs do not match script contract",
        "summary does not match script contract",
    ] {
        assert!(
            errors.iter().any(|error| error.as_str() == Some(expected)),
            "expected {expected}: {errors:?}"
        );
    }
}

#[test]
fn validate_only_rejects_required_evidence_files_contract_drift() {
    let manifest_path = write_manifest_variant(
        "standalone-artifact-evidence-files-drift-manifest",
        |manifest| {
            manifest["required_evidence_files"] = serde_json::json!([
                "build.stdout.txt",
                "build.stderr.txt",
                "artifact.readelf.dynamic.txt",
                "artifact.readelf.symbols.txt",
                "artifact.readelf.version.txt",
                "artifact.nm.dynamic.txt",
                "artifact.ldd.txt"
            ]);
        },
    );
    let manifest_env = manifest_path.to_string_lossy().into_owned();
    let envs = [("STANDALONE_REPLACEMENT_MANIFEST", manifest_env.as_str())];
    let (_temp, report, _log, output) = run_gate_with_env(
        "--validate-only",
        "standalone-artifact-evidence-files-drift",
        &envs,
    );
    assert!(
        !output.status.success(),
        "required_evidence_files drift should fail closed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report_json = load_json(&report);
    assert_eq!(report_json["status"].as_str(), Some("fail"));
    let errors = report_json["errors"]
        .as_array()
        .expect("errors should be an array");
    assert!(
        errors.iter().any(|error| {
            error.as_str() == Some("required_evidence_files do not match script contract")
        }),
        "expected required_evidence_files contract error: {errors:?}"
    );
}

#[test]
fn validate_only_rejects_failure_classification_contract_drift() {
    let manifest_path = write_manifest_variant(
        "standalone-artifact-failure-classification-drift-manifest",
        |manifest| {
            let classifications = manifest["expected_failure_classifications"]
                .as_array_mut()
                .expect("expected_failure_classifications should be an array");
            classifications.retain(|entry| {
                let Some(name) = entry["failure_signature"].as_str() else {
                    return true;
                };
                !matches!(name, "symbol_evidence_missing")
            });
            for entry in classifications {
                let Some(name) = entry["failure_signature"].as_str() else {
                    continue;
                };
                if matches!(name, "non_elf_artifact") {
                    entry["expected_result"] =
                        serde_json::Value::String("claim_blocked".to_owned());
                }
            }
        },
    );
    let manifest_env = manifest_path.to_string_lossy().into_owned();
    let envs = [("STANDALONE_REPLACEMENT_MANIFEST", manifest_env.as_str())];
    let (_temp, report, _log, output) = run_gate_with_env(
        "--validate-only",
        "standalone-artifact-failure-classification-drift",
        &envs,
    );
    assert!(
        !output.status.success(),
        "failure classification drift should fail closed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report_json = load_json(&report);
    assert_eq!(report_json["status"].as_str(), Some("fail"));
    let errors = report_json["errors"]
        .as_array()
        .expect("errors should be an array");
    assert!(
        errors.iter().any(|error| {
            error.as_str() == Some("expected_failure_classifications do not match script contract")
        }),
        "expected expected_failure_classifications contract error: {errors:?}"
    );
}

#[test]
fn validate_only_rejects_claim_policy_contract_drift() {
    let manifest_path = write_manifest_variant(
        "standalone-artifact-claim-policy-drift-manifest",
        |manifest| {
            manifest["claim_policy"]["current_level_must_remain"] =
                serde_json::Value::String("L1".to_owned());
            manifest["claim_policy"]["successful_forge_is_not_promotion"] =
                serde_json::Value::Bool(false);
            let criteria = manifest["claim_policy"]["claim_unblocked_only_when"]
                .as_array_mut()
                .expect("claim_unblocked_only_when should be an array");
            criteria.retain(|value| value.as_str() != Some("source_commit matches HEAD"));
        },
    );
    let manifest_env = manifest_path.to_string_lossy().into_owned();
    let envs = [("STANDALONE_REPLACEMENT_MANIFEST", manifest_env.as_str())];
    let (_temp, report, _log, output) = run_gate_with_env(
        "--validate-only",
        "standalone-artifact-claim-policy-drift",
        &envs,
    );
    assert!(
        !output.status.success(),
        "claim_policy drift should fail closed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report_json = load_json(&report);
    assert_eq!(report_json["status"].as_str(), Some("fail"));
    let errors = report_json["errors"]
        .as_array()
        .expect("errors should be an array");
    assert!(
        errors
            .iter()
            .any(|error| error.as_str() == Some("claim_policy does not match script contract")),
        "expected claim_policy contract error: {errors:?}"
    );
}

#[test]
fn validate_only_rejects_blocker_catalog_contract_drift() {
    let manifest_path = write_manifest_variant(
        "standalone-artifact-blocker-catalog-drift-manifest",
        |manifest| {
            manifest["blocker_catalog_contract"]["definitions"]["undefined_tls_symbols"]["owner_surface"] =
                serde_json::Value::String("generic_tls".to_owned());
            let required = manifest["blocker_catalog_contract"]["required_row_fields"]
                .as_array_mut()
                .expect("required_row_fields should be an array");
            required.retain(|field| field.as_str() != Some("next_action"));
        },
    );
    let manifest_env = manifest_path.to_string_lossy().into_owned();
    let envs = [("STANDALONE_REPLACEMENT_MANIFEST", manifest_env.as_str())];
    let (_temp, report, _log, output) = run_gate_with_env(
        "--validate-only",
        "standalone-artifact-blocker-catalog-drift",
        &envs,
    );
    assert!(
        !output.status.success(),
        "blocker_catalog_contract drift should fail closed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report_json = load_json(&report);
    assert_eq!(report_json["status"].as_str(), Some("fail"));
    let errors = report_json["errors"]
        .as_array()
        .expect("errors should be an array");
    assert!(
        errors.iter().any(|error| {
            error.as_str() == Some("blocker_catalog_contract does not match script contract")
        }),
        "expected blocker_catalog_contract error: {errors:?}"
    );
}

#[test]
fn invalid_inspection_timeout_override_fails_validate_only() {
    let (_temp, report, _log, output) = run_gate_with_env(
        "--validate-only",
        "standalone-artifact-invalid-timeout",
        &[("STANDALONE_REPLACEMENT_INSPECTION_TIMEOUT_SECS", "0")],
    );
    assert!(
        !output.status.success(),
        "invalid timeout override should fail closed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&report);
    assert_eq!(report["status"].as_str(), Some("fail"));
    let errors = report["errors"]
        .as_array()
        .expect("errors should be an array");
    assert!(
        errors.iter().any(|error| error.as_str().is_some_and(
            |message| message.contains("STANDALONE_REPLACEMENT_INSPECTION_TIMEOUT_SECS")
        )),
        "expected timeout env error, got {errors:?}"
    );
}

#[test]
fn validate_only_writes_report_and_required_log_fields() {
    let (_temp, report, log, output) = run_gate("--validate-only", "standalone-artifact-validate");
    assert!(
        output.status.success(),
        "validate-only failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&report);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["claim_status"].as_str(), Some("schema_validated"));
    assert_eq!(
        report["artifact_state"]["status"].as_str(),
        Some("not_checked")
    );
    assert_eq!(
        report["artifact_state"]["sampled_symbols_present"].as_bool(),
        Some(false)
    );
    assert!(symbol_sample_map(&report["artifact_state"]["symbol_samples"]).is_empty());
    assert!(report["source_commit"].as_str().is_some());
    assert!(report["artifact_state"]["host_glibc_dependency"].is_null());
    assert!(report["artifact_state"]["path"].is_null());
    assert!(report["artifact_state"]["sha256"].is_null());
    assert!(report["artifact_state"]["mtime"].is_null());

    let log = std::fs::read_to_string(log).expect("log should be readable");
    let rows: Vec<serde_json::Value> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log line should parse"))
        .collect();
    assert_eq!(rows.len(), 1);
    for field in REQUIRED_LOG_FIELDS {
        assert!(rows[0].get(*field).is_some(), "log row missing {field}");
    }
}

#[test]
fn check_mode_reports_missing_artifact_as_claim_blocked() {
    let (_temp, report, _log, output) = run_gate("--check", "standalone-artifact-missing");
    assert!(
        output.status.success(),
        "check mode should pass as a gate while blocking claims\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&report);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["claim_status"].as_str(), Some("claim_blocked"));
    assert_eq!(report["artifact_state"]["status"].as_str(), Some("missing"));
    assert_eq!(
        report["artifact_state"]["failure_signature"].as_str(),
        Some("standalone_artifact_missing")
    );
    assert_eq!(
        report["artifact_state"]["sampled_symbols_present"].as_bool(),
        Some(false)
    );
    assert!(symbol_sample_map(&report["artifact_state"]["symbol_samples"]).is_empty());
    assert!(report["source_commit"].as_str().is_some());
    assert!(report["artifact_state"]["host_glibc_dependency"].is_null());
    assert!(
        report["artifact_state"]["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("libfrankenlibc_replace.so"))
    );
    assert!(report["artifact_state"]["sha256"].is_null());
    assert!(report["artifact_state"]["mtime"].is_null());
}

#[test]
fn forge_mode_can_materialize_a_supplied_shared_object_for_fast_tests() {
    if Command::new("cc").arg("--version").output().is_err() {
        return;
    }

    let root = workspace_root();
    let temp = unique_temp_dir("standalone-artifact-forge");
    let source_c = temp.join("sample.c");
    let source_so = temp.join("libfrankenlibc_abi.so");
    std::fs::write(
        &source_c,
        "int frankenlibc_sample_symbol(void) { return 7; }\n",
    )
    .expect("write sample source");
    let cc_output = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg(&source_c)
        .arg("-o")
        .arg(&source_so)
        .output()
        .expect("cc should run");
    if !cc_output.status.success() {
        return;
    }

    let out_dir = temp.join("out");
    let cargo_target = temp.join("cargo-target");
    let report = temp.join("standalone_replacement_artifact.report.json");
    let log = temp.join("standalone_replacement_artifact.log.jsonl");
    let output = Command::new(root.join("scripts/check_standalone_replacement_artifact.sh"))
        .arg("--forge")
        .current_dir(&root)
        .env("STANDALONE_REPLACEMENT_OUT_DIR", &out_dir)
        .env("STANDALONE_REPLACEMENT_CARGO_TARGET_DIR", &cargo_target)
        .env("STANDALONE_REPLACEMENT_REPORT", &report)
        .env("STANDALONE_REPLACEMENT_LOG", &log)
        .env("STANDALONE_REPLACEMENT_SOURCE_LIB", &source_so)
        .env("STANDALONE_REPLACEMENT_SKIP_BUILD", "1")
        .env_remove("LD_PRELOAD")
        .output()
        .expect("forge mode should run");
    assert!(
        output.status.success(),
        "forge mode failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let forged = cargo_target.join("release/libfrankenlibc_replace.so");
    assert!(
        forged.exists(),
        "forge should materialize canonical artifact"
    );
    let report = load_json(&report);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["artifact_state"]["status"].as_str(), Some("current"));
    assert!(
        report["source_commit"]
            .as_str()
            .is_some_and(|commit| !commit.is_empty())
    );
    assert!(
        report["artifact_state"]["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("libfrankenlibc_replace.so"))
    );
    assert!(
        report["artifact_state"]["sha256"]
            .as_str()
            .is_some_and(|hash| {
                hash.len() == 64 && hash.chars().all(|ch| ch.is_ascii_hexdigit())
            })
    );
    assert!(
        report["artifact_state"]["mtime"]
            .as_i64()
            .is_some_and(|mtime| mtime > 0)
    );
    assert!(
        matches!(
            report["claim_status"].as_str(),
            Some("claim_blocked") | Some("artifact_current")
        ),
        "sample artifact may block claims, but the forge itself should classify it"
    );
    let tool_evidence = report["tool_evidence"]
        .as_object()
        .expect("tool evidence should be an object");
    assert!(
        !tool_evidence.is_empty(),
        "forge should emit inspection tool evidence"
    );
    for (filename, evidence) in tool_evidence {
        assert_eq!(
            evidence["timeout_secs"].as_i64(),
            Some(60),
            "{filename}: default inspection timeout should be recorded"
        );
    }
}

#[test]
fn forge_mode_stamps_materialized_artifact_from_old_source() {
    if Command::new("cc").arg("--version").output().is_err() {
        return;
    }

    let root = workspace_root();
    let temp = unique_temp_dir("standalone-artifact-old-source-forge");
    let source_c = temp.join("sample.c");
    let source_so = temp.join("libfrankenlibc_abi.so");
    std::fs::write(
        &source_c,
        "int frankenlibc_old_source_symbol(void) { return 11; }\n",
    )
    .expect("write sample source");
    let cc_output = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg(&source_c)
        .arg("-o")
        .arg(&source_so)
        .output()
        .expect("cc should run");
    if !cc_output.status.success() {
        return;
    }
    let touch_output = Command::new("touch")
        .arg("-d")
        .arg("@1")
        .arg(&source_so)
        .output();
    let Ok(touch_output) = touch_output else {
        return;
    };
    if !touch_output.status.success() {
        return;
    }

    let out_dir = temp.join("out");
    let cargo_target = temp.join("cargo-target");
    let report = temp.join("standalone_replacement_artifact.report.json");
    let log = temp.join("standalone_replacement_artifact.log.jsonl");
    let output = Command::new(root.join("scripts/check_standalone_replacement_artifact.sh"))
        .arg("--forge")
        .current_dir(&root)
        .env("STANDALONE_REPLACEMENT_OUT_DIR", &out_dir)
        .env("STANDALONE_REPLACEMENT_CARGO_TARGET_DIR", &cargo_target)
        .env("STANDALONE_REPLACEMENT_REPORT", &report)
        .env("STANDALONE_REPLACEMENT_LOG", &log)
        .env("STANDALONE_REPLACEMENT_SOURCE_LIB", &source_so)
        .env("STANDALONE_REPLACEMENT_SKIP_BUILD", "1")
        .env_remove("LD_PRELOAD")
        .output()
        .expect("forge mode should run");
    assert!(
        output.status.success(),
        "forge mode failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["artifact_state"]["status"].as_str(), Some("current"));
    assert_ne!(
        report["artifact_state"]["failure_signature"].as_str(),
        Some("standalone_artifact_stale")
    );
    let mtime = report["artifact_state"]["mtime"]
        .as_i64()
        .expect("artifact mtime should be recorded");
    let head_epoch = report["head_epoch"]
        .as_i64()
        .expect("head epoch should be recorded");
    assert!(
        mtime >= head_epoch,
        "forged artifact mtime {mtime} should be at least HEAD epoch {head_epoch}"
    );
}

#[test]
fn forge_mode_reports_host_dependency_breakdown() {
    if Command::new("cc").arg("--version").output().is_err() {
        return;
    }

    let root = workspace_root();
    let temp = unique_temp_dir("standalone-artifact-dependency-breakdown");
    let source_c = temp.join("sample.c");
    let source_so = temp.join("libfrankenlibc_abi.so");
    std::fs::write(
        &source_c,
        "int frankenlibc_sample_symbol(void) { return 7; }\n",
    )
    .expect("write sample source");
    let cc_output = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg(&source_c)
        .arg("-o")
        .arg(&source_so)
        .output()
        .expect("cc should run");
    if !cc_output.status.success() {
        return;
    }

    let out_dir = temp.join("out");
    let cargo_target = temp.join("cargo-target");
    let report = temp.join("standalone_replacement_artifact.report.json");
    let log = temp.join("standalone_replacement_artifact.log.jsonl");
    let output = Command::new(root.join("scripts/check_standalone_replacement_artifact.sh"))
        .arg("--forge")
        .current_dir(&root)
        .env("PATH", fake_dependency_probe_path(&temp))
        .env("STANDALONE_REPLACEMENT_OUT_DIR", &out_dir)
        .env("STANDALONE_REPLACEMENT_CARGO_TARGET_DIR", &cargo_target)
        .env("STANDALONE_REPLACEMENT_REPORT", &report)
        .env("STANDALONE_REPLACEMENT_LOG", &log)
        .env("STANDALONE_REPLACEMENT_SOURCE_LIB", &source_so)
        .env("STANDALONE_REPLACEMENT_SKIP_BUILD", "1")
        .env_remove("LD_PRELOAD")
        .output()
        .expect("forge mode should run");
    assert!(
        output.status.success(),
        "forge mode should keep the gate pass/claim blocked for host dependencies:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = load_json(&report);
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(report_json["claim_status"].as_str(), Some("claim_blocked"));
    assert_eq!(
        report_json["artifact_state"]["status"].as_str(),
        Some("current")
    );
    assert_eq!(
        report_json["artifact_state"]["failure_signature"].as_str(),
        Some("host_glibc_dependency")
    );
    assert_eq!(
        report_json["artifact_state"]["host_glibc_dependency"].as_bool(),
        Some(true)
    );
    assert_eq!(
        report_json["artifact_state"]["sampled_symbols_present"].as_bool(),
        Some(true)
    );
    let samples = symbol_sample_map(&report_json["artifact_state"]["symbol_samples"]);
    for symbol in [
        "__libc_start_main",
        "malloc",
        "free",
        "printf",
        "pthread_create",
        "getaddrinfo",
    ] {
        assert!(samples.contains(symbol), "missing sampled symbol {symbol}");
    }

    let breakdown = &report_json["artifact_state"]["dependency_breakdown"];
    let needed = string_set(&breakdown["needed_libraries"]);
    assert!(needed.contains("libgcc_s.so.1"));
    assert!(needed.contains("ld-linux-x86-64.so.2"));

    let host_needed = string_set(&breakdown["host_needed_libraries"]);
    assert!(host_needed.contains("libgcc_s.so.1"));
    assert!(host_needed.contains("libc.so.6"));
    assert!(host_needed.contains("ld-linux-x86-64.so.2"));

    let host_direct_needed = string_set(&breakdown["host_direct_needed_libraries"]);
    assert!(host_direct_needed.contains("libgcc_s.so.1"));
    assert!(host_direct_needed.contains("ld-linux-x86-64.so.2"));
    assert!(!host_direct_needed.contains("libc.so.6"));

    let host_resolved = string_set(&breakdown["host_resolved_libraries"]);
    assert!(host_resolved.contains("libgcc_s.so.1"));
    assert!(host_resolved.contains("libc.so.6"));
    assert!(host_resolved.contains("/lib64/ld-linux-x86-64.so.2"));

    let undefined = string_set(&breakdown["undefined_symbols"]);
    assert!(undefined.contains("_Unwind_Resume@GCC_3.0"));
    assert!(undefined.contains("__tls_get_addr@GLIBC_2.3"));
    assert!(undefined.contains("printf@GLIBC_2.2.5"));

    let unwind = string_set(&breakdown["undefined_unwind_symbols"]);
    assert!(unwind.contains("_Unwind_Resume@GCC_3.0"));
    let glibc = string_set(&breakdown["undefined_glibc_symbols"]);
    assert!(glibc.contains("__tls_get_addr@GLIBC_2.3"));
    assert!(glibc.contains("printf@GLIBC_2.2.5"));
    let tls = string_set(&breakdown["undefined_tls_symbols"]);
    assert!(tls.contains("__tls_get_addr@GLIBC_2.3"));
    let libgcc_versions = string_set(&breakdown["version_needs"]["libgcc_s.so.1"]);
    assert!(libgcc_versions.contains("GCC_3.0"));
    assert!(libgcc_versions.contains("GCC_3.3"));
    let loader_versions = string_set(&breakdown["version_needs"]["ld-linux-x86-64.so.2"]);
    assert!(loader_versions.contains("GLIBC_2.3"));
    let host_versions = string_set(&breakdown["host_version_requirements"]);
    assert!(host_versions.contains("libgcc_s.so.1:GCC_3.0"));
    assert!(host_versions.contains("libgcc_s.so.1:GCC_3.3"));
    assert!(host_versions.contains("ld-linux-x86-64.so.2:GLIBC_2.3"));
    assert_eq!(breakdown["loader_needed"].as_bool(), Some(true));

    let reasons = string_set(&breakdown["blocking_reasons"]);
    for reason in [
        "host_needed_libraries_present",
        "host_direct_needed_libraries_present",
        "host_resolved_libraries_present",
        "host_loader_dependency",
        "host_libc_dependency",
        "libgcc_runtime_dependency",
        "undefined_unwind_symbols",
        "undefined_glibc_symbols",
        "undefined_tls_symbols",
        "host_version_requirements",
    ] {
        assert!(reasons.contains(reason), "missing {reason}");
    }

    let catalog = breakdown["blocker_catalog"]
        .as_object()
        .expect("blocker_catalog should be an object");
    for reason in &reasons {
        assert!(
            catalog.contains_key(reason),
            "missing blocker_catalog row for {reason}"
        );
        let row = &catalog[reason];
        assert_eq!(row["severity"].as_str(), Some("claim_blocking"));
        assert!(
            row["owner_surface"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "catalog row {reason} should name an owner surface"
        );
        assert!(
            row["next_action"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "catalog row {reason} should include next action"
        );
        assert!(
            row["evidence_fields"]
                .as_array()
                .is_some_and(|fields| !fields.is_empty()),
            "catalog row {reason} should cite evidence fields"
        );
    }
    assert_eq!(
        catalog["host_loader_dependency"]["owner_surface"].as_str(),
        Some("loader_startup")
    );
    assert_eq!(
        catalog["host_direct_needed_libraries_present"]["owner_surface"].as_str(),
        Some("direct_dynamic_dependencies")
    );
    assert_eq!(
        catalog["undefined_tls_symbols"]["owner_surface"].as_str(),
        Some("tls_startup")
    );
    assert_eq!(
        catalog["host_version_requirements"]["owner_surface"].as_str(),
        Some("symbol_versioning")
    );
}

#[test]
fn forge_mode_blocks_artifact_when_sampled_symbols_are_missing() {
    if Command::new("cc").arg("--version").output().is_err() {
        return;
    }

    let root = workspace_root();
    let temp = unique_temp_dir("standalone-artifact-missing-sampled-symbols");
    let source_c = temp.join("sample.c");
    let source_so = temp.join("libfrankenlibc_abi.so");
    std::fs::write(
        &source_c,
        "int frankenlibc_private_only(void) { return 7; }\n",
    )
    .expect("write sample source");
    let cc_output = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg(&source_c)
        .arg("-o")
        .arg(&source_so)
        .output()
        .expect("cc should run");
    if !cc_output.status.success() {
        return;
    }

    let out_dir = temp.join("out");
    let cargo_target = temp.join("cargo-target");
    let report = temp.join("standalone_replacement_artifact.report.json");
    let log = temp.join("standalone_replacement_artifact.log.jsonl");
    let output = Command::new(root.join("scripts/check_standalone_replacement_artifact.sh"))
        .arg("--forge")
        .current_dir(&root)
        .env("PATH", fake_missing_sample_probe_path(&temp))
        .env("STANDALONE_REPLACEMENT_OUT_DIR", &out_dir)
        .env("STANDALONE_REPLACEMENT_CARGO_TARGET_DIR", &cargo_target)
        .env("STANDALONE_REPLACEMENT_REPORT", &report)
        .env("STANDALONE_REPLACEMENT_LOG", &log)
        .env("STANDALONE_REPLACEMENT_SOURCE_LIB", &source_so)
        .env("STANDALONE_REPLACEMENT_SKIP_BUILD", "1")
        .env_remove("LD_PRELOAD")
        .output()
        .expect("forge mode should run");
    assert!(
        output.status.success(),
        "forge mode should keep gate pass/claim blocked for missing sampled symbols:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = load_json(&report);
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(report_json["claim_status"].as_str(), Some("claim_blocked"));
    assert_eq!(
        report_json["artifact_state"]["status"].as_str(),
        Some("current")
    );
    assert_eq!(
        report_json["artifact_state"]["failure_signature"].as_str(),
        Some("symbol_evidence_missing")
    );
    assert_eq!(
        report_json["artifact_state"]["host_glibc_dependency"].as_bool(),
        Some(false)
    );
    assert_eq!(
        report_json["artifact_state"]["sampled_symbols_present"].as_bool(),
        Some(false)
    );
    assert!(symbol_sample_map(&report_json["artifact_state"]["symbol_samples"]).is_empty());
    assert!(
        string_set(&report_json["artifact_state"]["dependency_breakdown"]["blocking_reasons"])
            .is_empty()
    );
}

#[test]
fn forge_mode_blocks_artifact_when_required_symbol_probe_fails() {
    if Command::new("cc").arg("--version").output().is_err() {
        return;
    }

    let root = workspace_root();
    let temp = unique_temp_dir("standalone-artifact-symbol-probe-failed");
    let source_c = temp.join("sample.c");
    let source_so = temp.join("libfrankenlibc_abi.so");
    std::fs::write(
        &source_c,
        "int frankenlibc_sample_symbol(void) { return 7; }\n",
    )
    .expect("write sample source");
    let cc_output = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg(&source_c)
        .arg("-o")
        .arg(&source_so)
        .output()
        .expect("cc should run");
    if !cc_output.status.success() {
        return;
    }

    for (probe, evidence_file) in [
        ("readelf-symbols", "artifact.readelf.symbols.txt"),
        ("readelf-version", "artifact.readelf.version.txt"),
        ("nm", "artifact.nm.dynamic.txt"),
    ] {
        let out_dir = temp.join(format!("{probe}-out"));
        let cargo_target = temp.join(format!("{probe}-cargo-target"));
        let report = temp.join(format!("{probe}.report.json"));
        let log = temp.join(format!("{probe}.log.jsonl"));
        let output = Command::new(root.join("scripts/check_standalone_replacement_artifact.sh"))
            .arg("--forge")
            .current_dir(&root)
            .env("PATH", fake_inspection_probe_failure_path(&temp, probe))
            .env("STANDALONE_REPLACEMENT_OUT_DIR", &out_dir)
            .env("STANDALONE_REPLACEMENT_CARGO_TARGET_DIR", &cargo_target)
            .env("STANDALONE_REPLACEMENT_REPORT", &report)
            .env("STANDALONE_REPLACEMENT_LOG", &log)
            .env("STANDALONE_REPLACEMENT_SOURCE_LIB", &source_so)
            .env("STANDALONE_REPLACEMENT_SKIP_BUILD", "1")
            .env_remove("LD_PRELOAD")
            .output()
            .expect("forge mode should run");
        assert!(
            output.status.success(),
            "forge mode should keep gate pass/claim blocked for {probe} failure:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let report_json = load_json(&report);
        assert_eq!(report_json["status"].as_str(), Some("pass"), "{probe}");
        assert_eq!(
            report_json["claim_status"].as_str(),
            Some("claim_blocked"),
            "{probe}"
        );
        assert_eq!(
            report_json["artifact_state"]["status"].as_str(),
            Some("inspection_failed"),
            "{probe}"
        );
        assert_eq!(
            report_json["artifact_state"]["failure_signature"].as_str(),
            Some("artifact_dependency_inspection_failed"),
            "{probe}"
        );
        assert!(
            report_json["tool_evidence"][evidence_file]["exit_code"]
                .as_i64()
                .is_some_and(|code| code != 0),
            "{probe}: expected failing tool_evidence exit code"
        );
    }
}

#[test]
fn forge_mode_blocks_artifact_when_required_inspection_tool_is_missing() {
    if Command::new("cc").arg("--version").output().is_err() {
        return;
    }

    let root = workspace_root();
    let temp = unique_temp_dir("standalone-artifact-missing-inspection-tool");
    let source_c = temp.join("sample.c");
    let source_so = temp.join("libfrankenlibc_abi.so");
    std::fs::write(
        &source_c,
        "int frankenlibc_sample_symbol(void) { return 7; }\n",
    )
    .expect("write sample source");
    let cc_output = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg(&source_c)
        .arg("-o")
        .arg(&source_so)
        .output()
        .expect("cc should run");
    if !cc_output.status.success() {
        return;
    }

    for (missing_tool, evidence_file) in [
        ("readelf", "artifact.readelf.dynamic.txt"),
        ("nm", "artifact.nm.dynamic.txt"),
        ("ldd", "artifact.ldd.txt"),
    ] {
        let out_dir = temp.join(format!("missing-{missing_tool}-out"));
        let cargo_target = temp.join(format!("missing-{missing_tool}-cargo-target"));
        let report = temp.join(format!("missing-{missing_tool}.report.json"));
        let log = temp.join(format!("missing-{missing_tool}.log.jsonl"));
        let Some(fake_path) = fake_missing_inspection_tool_path(&temp, missing_tool) else {
            return;
        };
        let output = Command::new(root.join("scripts/check_standalone_replacement_artifact.sh"))
            .arg("--forge")
            .current_dir(&root)
            .env("PATH", fake_path)
            .env("STANDALONE_REPLACEMENT_OUT_DIR", &out_dir)
            .env("STANDALONE_REPLACEMENT_CARGO_TARGET_DIR", &cargo_target)
            .env("STANDALONE_REPLACEMENT_REPORT", &report)
            .env("STANDALONE_REPLACEMENT_LOG", &log)
            .env("STANDALONE_REPLACEMENT_SOURCE_LIB", &source_so)
            .env("STANDALONE_REPLACEMENT_SKIP_BUILD", "1")
            .env_remove("LD_PRELOAD")
            .output()
            .expect("forge mode should run");
        assert!(
            output.status.success(),
            "forge mode should keep gate pass/claim blocked when {missing_tool} is missing:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let report_json = load_json(&report);
        assert_eq!(
            report_json["status"].as_str(),
            Some("pass"),
            "{missing_tool}"
        );
        assert_eq!(
            report_json["claim_status"].as_str(),
            Some("claim_blocked"),
            "{missing_tool}"
        );
        assert_eq!(
            report_json["artifact_state"]["status"].as_str(),
            Some("inspection_failed"),
            "{missing_tool}"
        );
        assert_eq!(
            report_json["artifact_state"]["failure_signature"].as_str(),
            Some("artifact_dependency_inspection_failed"),
            "{missing_tool}"
        );
        assert_eq!(
            report_json["tool_evidence"][evidence_file]["exit_code"].as_i64(),
            Some(127),
            "{missing_tool}: expected missing tool to be recorded as exit 127"
        );
        assert_eq!(
            report_json["tool_evidence"][evidence_file]["timed_out"].as_bool(),
            Some(false),
            "{missing_tool}: missing tool should not be reported as timeout"
        );
        let evidence_path = PathBuf::from(
            report_json["tool_evidence"][evidence_file]["path"]
                .as_str()
                .expect("tool evidence path should be present"),
        );
        let evidence = std::fs::read_to_string(evidence_path).expect("tool evidence should exist");
        assert!(
            evidence.contains(missing_tool),
            "{missing_tool}: missing tool evidence should name the executable"
        );
        assert!(log.exists(), "{missing_tool}: log should be written");
    }
}

#[test]
fn forge_mode_blocks_artifact_when_required_inspection_probe_times_out() {
    if Command::new("cc").arg("--version").output().is_err() {
        return;
    }

    let root = workspace_root();
    let temp = unique_temp_dir("standalone-artifact-inspection-timeout");
    let source_c = temp.join("sample.c");
    let source_so = temp.join("libfrankenlibc_abi.so");
    std::fs::write(
        &source_c,
        "int frankenlibc_sample_symbol(void) { return 7; }\n",
    )
    .expect("write sample source");
    let cc_output = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg(&source_c)
        .arg("-o")
        .arg(&source_so)
        .output()
        .expect("cc should run");
    if !cc_output.status.success() {
        return;
    }

    for (probe, evidence_file) in [
        ("readelf-dynamic", "artifact.readelf.dynamic.txt"),
        ("readelf-symbols", "artifact.readelf.symbols.txt"),
        ("readelf-version", "artifact.readelf.version.txt"),
        ("nm", "artifact.nm.dynamic.txt"),
        ("ldd", "artifact.ldd.txt"),
    ] {
        let out_dir = temp.join(format!("timeout-{probe}-out"));
        let cargo_target = temp.join(format!("timeout-{probe}-cargo-target"));
        let report = temp.join(format!("timeout-{probe}.report.json"));
        let log = temp.join(format!("timeout-{probe}.log.jsonl"));
        let output = Command::new(root.join("scripts/check_standalone_replacement_artifact.sh"))
            .arg("--forge")
            .current_dir(&root)
            .env("PATH", fake_timeout_inspection_probe_path(&temp, probe))
            .env("STANDALONE_REPLACEMENT_OUT_DIR", &out_dir)
            .env("STANDALONE_REPLACEMENT_CARGO_TARGET_DIR", &cargo_target)
            .env("STANDALONE_REPLACEMENT_REPORT", &report)
            .env("STANDALONE_REPLACEMENT_LOG", &log)
            .env("STANDALONE_REPLACEMENT_SOURCE_LIB", &source_so)
            .env("STANDALONE_REPLACEMENT_SKIP_BUILD", "1")
            .env("STANDALONE_REPLACEMENT_INSPECTION_TIMEOUT_SECS", "1")
            .env_remove("LD_PRELOAD")
            .output()
            .expect("forge mode should run");
        assert!(
            output.status.success(),
            "forge mode should keep gate pass/claim blocked when {probe} times out:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let report_json = load_json(&report);
        assert_eq!(report_json["status"].as_str(), Some("pass"), "{probe}");
        assert_eq!(
            report_json["claim_status"].as_str(),
            Some("claim_blocked"),
            "{probe}"
        );
        assert_eq!(
            report_json["artifact_state"]["status"].as_str(),
            Some("inspection_failed"),
            "{probe}"
        );
        assert_eq!(
            report_json["artifact_state"]["failure_signature"].as_str(),
            Some("artifact_dependency_inspection_failed"),
            "{probe}"
        );
        assert_eq!(
            report_json["tool_evidence"][evidence_file]["exit_code"].as_i64(),
            Some(124),
            "{probe}: expected timeout to be recorded as exit 124"
        );
        assert_eq!(
            report_json["tool_evidence"][evidence_file]["timed_out"].as_bool(),
            Some(true),
            "{probe}: expected timed_out=true"
        );
        assert_eq!(
            report_json["tool_evidence"][evidence_file]["timeout_secs"].as_i64(),
            Some(1),
            "{probe}: expected override timeout budget to be recorded"
        );
        assert!(log.exists(), "{probe}: log should be written");
    }
}

#[test]
fn forge_mode_blocks_artifact_when_ldd_probe_fails() {
    if Command::new("cc").arg("--version").output().is_err() {
        return;
    }

    let root = workspace_root();
    let temp = unique_temp_dir("standalone-artifact-ldd-probe-failed");
    let source_c = temp.join("sample.c");
    let source_so = temp.join("libfrankenlibc_abi.so");
    std::fs::write(
        &source_c,
        "int frankenlibc_sample_symbol(void) { return 7; }\n",
    )
    .expect("write sample source");
    let cc_output = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg(&source_c)
        .arg("-o")
        .arg(&source_so)
        .output()
        .expect("cc should run");
    if !cc_output.status.success() {
        return;
    }

    let out_dir = temp.join("out");
    let cargo_target = temp.join("cargo-target");
    let report = temp.join("standalone_replacement_artifact.report.json");
    let log = temp.join("standalone_replacement_artifact.log.jsonl");
    let output = Command::new(root.join("scripts/check_standalone_replacement_artifact.sh"))
        .arg("--forge")
        .current_dir(&root)
        .env("PATH", fake_ldd_failure_path(&temp))
        .env("STANDALONE_REPLACEMENT_OUT_DIR", &out_dir)
        .env("STANDALONE_REPLACEMENT_CARGO_TARGET_DIR", &cargo_target)
        .env("STANDALONE_REPLACEMENT_REPORT", &report)
        .env("STANDALONE_REPLACEMENT_LOG", &log)
        .env("STANDALONE_REPLACEMENT_SOURCE_LIB", &source_so)
        .env("STANDALONE_REPLACEMENT_SKIP_BUILD", "1")
        .env_remove("LD_PRELOAD")
        .output()
        .expect("forge mode should run");
    assert!(
        output.status.success(),
        "forge mode with failing ldd should keep gate pass/claim blocked:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = load_json(&report);
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(report_json["claim_status"].as_str(), Some("claim_blocked"));
    assert_eq!(
        report_json["artifact_state"]["status"].as_str(),
        Some("inspection_failed")
    );
    assert_eq!(
        report_json["artifact_state"]["failure_signature"].as_str(),
        Some("artifact_dependency_inspection_failed")
    );
    assert_eq!(
        report_json["tool_evidence"]["artifact.ldd.txt"]["exit_code"].as_i64(),
        Some(42)
    );

    let log = std::fs::read_to_string(log).expect("log should be readable");
    let rows: Vec<serde_json::Value> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log line should parse"))
        .collect();
    assert!(rows.iter().any(|row| {
        row["event"].as_str() == Some("artifact_inspected")
            && row["artifact_status"].as_str() == Some("inspection_failed")
            && row["claim_status"].as_str() == Some("claim_blocked")
            && matches!(
                row["failure_signature"].as_str(),
                Some("artifact_dependency_inspection_failed")
            )
    }));
}

#[test]
fn gate_script_exists_and_is_executable() {
    let script = workspace_root().join("scripts/check_standalone_replacement_artifact.sh");
    assert!(script.exists(), "gate script must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_standalone_replacement_artifact.sh must be executable"
        );
    }
}
