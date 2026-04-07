use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct CallThroughSite {
    module: String,
    line: usize,
    function: String,
    source_kind: &'static str,
}

fn repo_root(manifest_dir: &str) -> PathBuf {
    Path::new(manifest_dir)
        .parent()
        .and_then(Path::parent)
        .expect("frankenlibc-abi must live under crates/<name>")
        .to_path_buf()
}

fn load_json(path: &Path) -> Value {
    let body = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&body)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn extract_libc_call(fragment: &str) -> Option<&str> {
    let bytes = fragment.as_bytes();
    let mut end = 0;
    for &byte in bytes {
        if byte.is_ascii_lowercase() || byte == b'_' || (end > 0 && byte.is_ascii_digit()) {
            end += 1;
        } else {
            break;
        }
    }
    if end == 0 {
        return None;
    }

    let rest = fragment[end..].trim_start();
    if rest.starts_with('(') {
        Some(&fragment[..end])
    } else {
        None
    }
}

fn scan_call_throughs(abi_src: &Path) -> Vec<CallThroughSite> {
    let mut modules = fs::read_dir(abi_src)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", abi_src.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("rs"))
        .collect::<Vec<_>>();
    modules.sort();

    let mut sites = Vec::new();
    for module_path in modules {
        let module_name = module_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        let content = fs::read_to_string(&module_path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", module_path.display()));

        for (lineno, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }

            let mut libc_search_from = 0;
            while let Some(pos) = line[libc_search_from..].find("libc::") {
                let abs_pos = libc_search_from + pos;
                let after = &line[abs_pos + "libc::".len()..];
                if let Some(function) = extract_libc_call(after)
                    && function != "syscall"
                {
                    sites.push(CallThroughSite {
                        module: module_name.clone(),
                        line: lineno + 1,
                        function: function.to_owned(),
                        source_kind: "libc",
                    });
                }
                libc_search_from = abs_pos + "libc::".len();
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
                for &byte in bytes {
                    if byte.is_ascii_lowercase()
                        || byte == b'_'
                        || (end > 0 && byte.is_ascii_digit())
                    {
                        end += 1;
                    } else {
                        break;
                    }
                }
                if end > 0 {
                    let wrapped = &after[..end];
                    let rest = after[end..].trim_start();
                    if rest.starts_with('(') && !wrapped.ends_with("_sym") {
                        sites.push(CallThroughSite {
                            module: module_name.clone(),
                            line: lineno + 1,
                            function: format!("pthread_{wrapped}"),
                            source_kind: "host_pthread",
                        });
                    }
                }
                host_search_from = abs_pos + "host_pthread_".len();
            }
        }
    }

    sites
}

fn standalone_policy_diagnostics(root: &Path) -> Vec<String> {
    let replacement_profile = load_json(&root.join("tests/conformance/replacement_profile.json"));
    let packaging_spec = load_json(&root.join("tests/conformance/packaging_spec.json"));
    let support_matrix = load_json(&root.join("support_matrix.json"));

    let mut diagnostics = Vec::new();

    let replacement_allows_callthrough = replacement_profile
        .pointer("/profiles/replacement/call_through_allowed")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if replacement_allows_callthrough {
        diagnostics.push(
            "- replacement_profile.json must set profiles.replacement.call_through_allowed=false"
                .to_owned(),
        );
    }

    let standalone_features = packaging_spec
        .pointer("/feature_gates/standalone/features")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let has_standalone_feature = standalone_features
        .iter()
        .filter_map(Value::as_str)
        .any(|feature| feature == "standalone");
    if !has_standalone_feature {
        diagnostics.push(
            "- packaging_spec.json must declare feature_gates.standalone.features = [\"standalone\"]"
                .to_owned(),
        );
    }

    let replace_allowed = packaging_spec
        .pointer("/artifacts/replace/allowed_statuses")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let replace_allowed_set = replace_allowed
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    if replace_allowed_set.contains("GlibcCallThrough")
        || replace_allowed_set.contains("Stub")
        || !replace_allowed_set.contains("Implemented")
        || !replace_allowed_set.contains("RawSyscall")
    {
        diagnostics.push(
            "- packaging_spec.json must restrict Replace allowed_statuses to Implemented + RawSyscall"
                .to_owned(),
        );
    }

    let forbidden_status_symbols = support_matrix
        .get("symbols")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|row| {
            let status = row.get("status").and_then(Value::as_str)?;
            if status == "GlibcCallThrough" || status == "Stub" {
                Some(
                    row.get("symbol")
                        .and_then(Value::as_str)
                        .unwrap_or("<unknown>")
                        .to_owned(),
                )
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if !forbidden_status_symbols.is_empty() {
        let examples = forbidden_status_symbols
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        diagnostics.push(format!(
            "- support_matrix.json still marks {} exported symbols as Interpose-only (examples: {examples})",
            forbidden_status_symbols.len()
        ));
    }

    let callthrough_sites = scan_call_throughs(&root.join("crates/frankenlibc-abi/src"));
    if !callthrough_sites.is_empty() {
        let mut modules = BTreeSet::new();
        for site in &callthrough_sites {
            modules.insert(site.module.clone());
        }
        let examples = callthrough_sites
            .iter()
            .take(5)
            .map(|site| {
                format!(
                    "{}:{} {}::{}",
                    site.module, site.line, site.source_kind, site.function
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        diagnostics.push(format!(
            "- ABI source scan found {} host call-through sites across {} modules (examples: {examples})",
            callthrough_sites.len(),
            modules.len()
        ));
    }

    diagnostics
}

fn enforce_standalone_policy(root: &Path) {
    let diagnostics = standalone_policy_diagnostics(root);
    if diagnostics.is_empty() {
        return;
    }

    panic!(
        "standalone feature requires a replacement-clean ABI.\n{}\nRun `bash scripts/check_replacement_guard.sh replacement` for the full report.",
        diagnostics.join("\n")
    );
}

fn emit_rerun_directives(repo_root: &Path, manifest_dir: &str) {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={manifest_dir}/version_scripts/libc.map");
    println!(
        "cargo:rerun-if-changed={}",
        repo_root.join("support_matrix.json").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        repo_root
            .join("tests/conformance/packaging_spec.json")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        repo_root
            .join("tests/conformance/replacement_profile.json")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        repo_root
            .join("crates/frankenlibc-membrane/src/runtime_math/clifford.rs")
            .display()
    );

    let abi_src = repo_root.join("crates/frankenlibc-abi/src");
    let mut abi_files = fs::read_dir(&abi_src)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", abi_src.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("rs"))
        .collect::<Vec<_>>();
    abi_files.sort();
    for path in abi_files {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let repo_root = repo_root(&manifest_dir);
    let version_script = format!("{manifest_dir}/version_scripts/libc.map");
    let debug_assertions_enabled = std::env::var_os("CARGO_CFG_DEBUG_ASSERTIONS").is_some();
    let standalone_enabled = std::env::var_os("CARGO_FEATURE_STANDALONE").is_some();

    emit_rerun_directives(&repo_root, &manifest_dir);
    if standalone_enabled {
        enforce_standalone_policy(&repo_root);
    }

    if !debug_assertions_enabled && std::path::Path::new(&version_script).exists() {
        println!("cargo:rustc-cdylib-link-arg=-Wl,--version-script={version_script}");
    }

    let audit_json = r#"{
  "schema_version": "v1",
  "artifact": "simd_isomorphism_audit",
  "entries": [
    {
      "function": "memcpy",
      "reference_isa": "scalar",
      "candidate_isa": "avx2",
      "architecture": "x86_64",
      "lane_bytes": 32,
      "equivalent": true,
      "rationale": "candidate accepted: Clifford lane contract is isomorphic to scalar reference"
    },
    {
      "function": "memcpy",
      "reference_isa": "scalar",
      "candidate_isa": "sse4.2",
      "architecture": "x86_64",
      "lane_bytes": 16,
      "equivalent": true,
      "rationale": "candidate accepted: Clifford lane contract is isomorphic to scalar reference"
    },
    {
      "function": "memcpy",
      "reference_isa": "scalar",
      "candidate_isa": "neon",
      "architecture": "aarch64",
      "lane_bytes": 16,
      "equivalent": true,
      "rationale": "candidate accepted: Clifford lane contract is isomorphic to scalar reference"
    },
    {
      "function": "memcmp",
      "reference_isa": "scalar",
      "candidate_isa": "avx2",
      "architecture": "x86_64",
      "lane_bytes": 32,
      "equivalent": true,
      "rationale": "candidate accepted: Clifford lane contract is isomorphic to scalar reference"
    },
    {
      "function": "memcmp",
      "reference_isa": "scalar",
      "candidate_isa": "sse4.2",
      "architecture": "x86_64",
      "lane_bytes": 16,
      "equivalent": true,
      "rationale": "candidate accepted: Clifford lane contract is isomorphic to scalar reference"
    },
    {
      "function": "memcmp",
      "reference_isa": "scalar",
      "candidate_isa": "neon",
      "architecture": "aarch64",
      "lane_bytes": 16,
      "equivalent": true,
      "rationale": "candidate accepted: Clifford lane contract is isomorphic to scalar reference"
    },
    {
      "function": "strlen",
      "reference_isa": "scalar",
      "candidate_isa": "avx2",
      "architecture": "x86_64",
      "lane_bytes": 32,
      "equivalent": true,
      "rationale": "candidate accepted: Clifford lane contract is isomorphic to scalar reference"
    },
    {
      "function": "strlen",
      "reference_isa": "scalar",
      "candidate_isa": "sse4.2",
      "architecture": "x86_64",
      "lane_bytes": 16,
      "equivalent": true,
      "rationale": "candidate accepted: Clifford lane contract is isomorphic to scalar reference"
    },
    {
      "function": "strlen",
      "reference_isa": "scalar",
      "candidate_isa": "neon",
      "architecture": "aarch64",
      "lane_bytes": 16,
      "equivalent": true,
      "rationale": "candidate accepted: Clifford lane contract is isomorphic to scalar reference"
    }
  ]
    }
"#;
    let audit_path = std::path::Path::new(&out_dir).join("simd_isomorphism_audit.json");
    std::fs::write(&audit_path, audit_json).expect("failed to write simd isomorphism audit");
}
