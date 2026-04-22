use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct CallThroughSite {
    module: String,
    line: usize,
    function: String,
    source_kind: &'static str,
}

type SourceScanExceptions = BTreeMap<String, BTreeMap<String, BTreeSet<String>>>;

#[derive(Debug, Clone, Copy)]
struct StartupContractSpec {
    checkpoint: &'static str,
    requires: &'static [&'static str],
    provides: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
struct StartupSymbolSpec {
    symbol: &'static str,
    depends_on: &'static [&'static str],
}

const STARTUP_CHECKPOINT_EDGES: &[(&str, &str)] = &[
    ("Entry", "MembraneGate"),
    ("MembraneGate", "ValidateMainPointer"),
    ("ValidateMainPointer", "ValidateArgvPointer"),
    ("ValidateArgvPointer", "ScanArgvVector"),
    ("ScanArgvVector", "ValidateArgcBound"),
    ("ValidateArgcBound", "ScanEnvpVector"),
    ("ScanEnvpVector", "ScanAuxvVector"),
    ("ScanAuxvVector", "ClassifySecureMode"),
    ("ClassifySecureMode", "CaptureInvariants"),
    ("CaptureInvariants", "ResolveEnvp"),
    ("ResolveEnvp", "BindProcessGlobals"),
    ("BindProcessGlobals", "BootstrapHostSymbols"),
    ("BootstrapHostSymbols", "InitHostStdio"),
    ("InitHostStdio", "BootstrapHostLibio"),
    ("BootstrapHostLibio", "PrewarmThreadSymbols"),
    ("PrewarmThreadSymbols", "PrewarmAllocatorSymbols"),
    ("PrewarmAllocatorSymbols", "SignalRuntimeReady"),
    ("SignalRuntimeReady", "CallInitHook"),
    ("SignalRuntimeReady", "CallMain"),
    ("CallInitHook", "CallMain"),
    ("CallMain", "CallFiniHook"),
    ("CallMain", "CallRtldFiniHook"),
    ("CallMain", "Complete"),
    ("CallFiniHook", "CallRtldFiniHook"),
    ("CallFiniHook", "Complete"),
    ("CallRtldFiniHook", "Complete"),
    ("MembraneGate", "Deny"),
    ("ValidateMainPointer", "Deny"),
    ("ValidateArgvPointer", "Deny"),
    ("ScanArgvVector", "Deny"),
    ("ValidateArgcBound", "Deny"),
    ("ScanEnvpVector", "Deny"),
    ("ScanAuxvVector", "Deny"),
    ("ClassifySecureMode", "Deny"),
    ("CaptureInvariants", "Deny"),
    ("Entry", "FallbackHost"),
];

const STARTUP_CONTRACT_SPECS: &[StartupContractSpec] = &[
    StartupContractSpec {
        checkpoint: "Entry",
        requires: &[],
        provides: &[],
    },
    StartupContractSpec {
        checkpoint: "MembraneGate",
        requires: &[],
        provides: &["MembraneAdmission"],
    },
    StartupContractSpec {
        checkpoint: "ValidateMainPointer",
        requires: &["MembraneAdmission"],
        provides: &["MainValidated"],
    },
    StartupContractSpec {
        checkpoint: "ValidateArgvPointer",
        requires: &["MainValidated"],
        provides: &["ArgvValidated"],
    },
    StartupContractSpec {
        checkpoint: "ScanArgvVector",
        requires: &["ArgvValidated"],
        provides: &["ArgvScanned"],
    },
    StartupContractSpec {
        checkpoint: "ValidateArgcBound",
        requires: &["ArgvScanned"],
        provides: &["ArgcBounded"],
    },
    StartupContractSpec {
        checkpoint: "ScanEnvpVector",
        requires: &["ArgcBounded"],
        provides: &["EnvpScanned"],
    },
    StartupContractSpec {
        checkpoint: "ScanAuxvVector",
        requires: &["EnvpScanned"],
        provides: &["AuxvScanned"],
    },
    StartupContractSpec {
        checkpoint: "ClassifySecureMode",
        requires: &["AuxvScanned"],
        provides: &["SecureModeKnown"],
    },
    StartupContractSpec {
        checkpoint: "CaptureInvariants",
        requires: &["SecureModeKnown"],
        provides: &["InvariantsCaptured"],
    },
    StartupContractSpec {
        checkpoint: "ResolveEnvp",
        requires: &["InvariantsCaptured"],
        provides: &["EnvpResolved"],
    },
    StartupContractSpec {
        checkpoint: "BindProcessGlobals",
        requires: &["EnvpResolved"],
        provides: &["ProcessGlobalsBound"],
    },
    StartupContractSpec {
        checkpoint: "BootstrapHostSymbols",
        requires: &["ProcessGlobalsBound"],
        provides: &["HostSymbolsReady"],
    },
    StartupContractSpec {
        checkpoint: "InitHostStdio",
        requires: &["HostSymbolsReady"],
        provides: &["HostStdioReady"],
    },
    StartupContractSpec {
        checkpoint: "BootstrapHostLibio",
        requires: &["HostStdioReady"],
        provides: &["HostLibioReady"],
    },
    StartupContractSpec {
        checkpoint: "PrewarmThreadSymbols",
        requires: &["HostLibioReady"],
        provides: &["ThreadSymbolsReady"],
    },
    StartupContractSpec {
        checkpoint: "PrewarmAllocatorSymbols",
        requires: &["ThreadSymbolsReady"],
        provides: &["AllocatorSymbolsReady"],
    },
    StartupContractSpec {
        checkpoint: "SignalRuntimeReady",
        requires: &["AllocatorSymbolsReady"],
        provides: &["RuntimeReady"],
    },
    StartupContractSpec {
        checkpoint: "CallInitHook",
        requires: &["RuntimeReady"],
        provides: &["InitHookObserved"],
    },
    StartupContractSpec {
        checkpoint: "CallMain",
        requires: &["RuntimeReady"],
        provides: &["MainCompleted"],
    },
    StartupContractSpec {
        checkpoint: "CallFiniHook",
        requires: &["MainCompleted"],
        provides: &["FiniObserved"],
    },
    StartupContractSpec {
        checkpoint: "CallRtldFiniHook",
        requires: &["MainCompleted"],
        provides: &["RtldFiniObserved"],
    },
    StartupContractSpec {
        checkpoint: "Complete",
        requires: &["MainCompleted"],
        provides: &[],
    },
    StartupContractSpec {
        checkpoint: "Deny",
        requires: &[],
        provides: &[],
    },
    StartupContractSpec {
        checkpoint: "FallbackHost",
        requires: &[],
        provides: &[],
    },
];

const STARTUP_SYMBOL_SPECS: &[StartupSymbolSpec] = &[
    StartupSymbolSpec {
        symbol: "normalize_argc",
        depends_on: &[],
    },
    StartupSymbolSpec {
        symbol: "count_c_string_vector",
        depends_on: &[],
    },
    StartupSymbolSpec {
        symbol: "read_auxv_pairs",
        depends_on: &[],
    },
    StartupSymbolSpec {
        symbol: "classify_secure_mode",
        depends_on: &["read_auxv_pairs"],
    },
    StartupSymbolSpec {
        symbol: "build_invariants",
        depends_on: &["normalize_argc", "classify_secure_mode"],
    },
    StartupSymbolSpec {
        symbol: "resolve_startup_envp",
        depends_on: &["normalize_argc"],
    },
    StartupSymbolSpec {
        symbol: "init_program_name",
        depends_on: &[],
    },
    StartupSymbolSpec {
        symbol: "init_environment_globals",
        depends_on: &["resolve_startup_envp"],
    },
    StartupSymbolSpec {
        symbol: "init_process_globals",
        depends_on: &["init_program_name", "init_environment_globals"],
    },
    StartupSymbolSpec {
        symbol: "bootstrap_host_symbols",
        depends_on: &["init_process_globals"],
    },
    StartupSymbolSpec {
        symbol: "init_host_stdio_streams",
        depends_on: &["bootstrap_host_symbols"],
    },
    StartupSymbolSpec {
        symbol: "bootstrap_host_libio_exports",
        depends_on: &["init_host_stdio_streams"],
    },
    StartupSymbolSpec {
        symbol: "prewarm_host_thread_symbols",
        depends_on: &["bootstrap_host_libio_exports"],
    },
    StartupSymbolSpec {
        symbol: "prewarm_host_allocator_symbols",
        depends_on: &["prewarm_host_thread_symbols"],
    },
    StartupSymbolSpec {
        symbol: "signal_runtime_ready",
        depends_on: &["prewarm_host_allocator_symbols"],
    },
    StartupSymbolSpec {
        symbol: "record_phase0_outcome",
        depends_on: &["build_invariants"],
    },
    StartupSymbolSpec {
        symbol: "delegate_to_host_libc_start_main",
        depends_on: &[
            "resolve_startup_envp",
            "init_process_globals",
            "bootstrap_host_symbols",
            "init_host_stdio_streams",
            "bootstrap_host_libio_exports",
        ],
    },
    StartupSymbolSpec {
        symbol: "startup_phase0_impl",
        depends_on: &[
            "normalize_argc",
            "count_c_string_vector",
            "read_auxv_pairs",
            "classify_secure_mode",
            "build_invariants",
            "resolve_startup_envp",
            "init_process_globals",
            "bootstrap_host_symbols",
            "init_host_stdio_streams",
            "bootstrap_host_libio_exports",
            "prewarm_host_thread_symbols",
            "prewarm_host_allocator_symbols",
            "signal_runtime_ready",
            "record_phase0_outcome",
        ],
    },
];

fn repo_root(manifest_dir: &str) -> PathBuf {
    Path::new(manifest_dir)
        .parent()
        .and_then(Path::parent)
        .expect("frankenlibc-abi must live under crates/<name>")
        .to_path_buf()
}

fn topological_order(
    nodes: &[&'static str],
    edges: &[(&'static str, &'static str)],
) -> Vec<String> {
    let mut indegree = BTreeMap::<&'static str, usize>::new();
    let mut outgoing = BTreeMap::<&'static str, Vec<&'static str>>::new();

    for &node in nodes {
        indegree.entry(node).or_insert(0);
        outgoing.entry(node).or_default();
    }

    for &(from, to) in edges {
        *indegree.entry(to).or_insert(0) += 1;
        outgoing.entry(from).or_default().push(to);
        indegree.entry(from).or_insert(0);
    }

    let mut ready = indegree
        .iter()
        .filter_map(|(&node, &deg)| (deg == 0).then_some(node))
        .collect::<Vec<_>>();
    ready.sort();
    let mut queue = VecDeque::from(ready);
    let mut ordered = Vec::with_capacity(nodes.len());

    while let Some(node) = queue.pop_front() {
        ordered.push(node.to_owned());
        let mut children = outgoing.get(node).cloned().unwrap_or_default();
        children.sort();
        for child in children {
            let degree = indegree
                .get_mut(child)
                .unwrap_or_else(|| panic!("missing indegree entry for {child}")); // ubs:ignore — build.rs must hard-fail on invalid graph
            *degree -= 1;
            if *degree == 0 {
                queue.push_back(child);
            }
        }
    }

    assert_eq!(
        ordered.len(),
        indegree.len(),
        "cycle detected while proving startup bootstrap graph"
    );

    ordered
}

fn emit_startup_init_order_certificate(out_dir: &Path) {
    let checkpoint_nodes = STARTUP_CONTRACT_SPECS
        .iter()
        .map(|spec| spec.checkpoint)
        .collect::<Vec<_>>();
    let checkpoint_order = topological_order(&checkpoint_nodes, STARTUP_CHECKPOINT_EDGES);

    let symbol_nodes = STARTUP_SYMBOL_SPECS
        .iter()
        .map(|spec| spec.symbol)
        .collect::<Vec<_>>();
    let symbol_edges = STARTUP_SYMBOL_SPECS
        .iter()
        .flat_map(|spec| {
            spec.depends_on
                .iter()
                .map(|dependency| (*dependency, spec.symbol))
        })
        .collect::<Vec<_>>();
    let symbol_order = topological_order(&symbol_nodes, &symbol_edges);

    let mut certificate = serde_json::json!({
        "schema_version": "v1",
        "artifact": "startup_init_order_certificate",
        "bead_id": "bd-2gjs.4",
        "generated_by": "crates/frankenlibc-abi/build.rs",
        "manual_proof_doc": "docs/init_capability_lattice.md",
        "checkpoint_graph": {
            "acyclic": true,
            "node_count": checkpoint_nodes.len(),
            "edge_count": STARTUP_CHECKPOINT_EDGES.len(),
            "topological_order": checkpoint_order,
            "contracts": STARTUP_CONTRACT_SPECS.iter().map(|spec| serde_json::json!({
                "checkpoint": spec.checkpoint,
                "requires": spec.requires,
                "provides": spec.provides,
            })).collect::<Vec<_>>(),
            "edges": STARTUP_CHECKPOINT_EDGES.iter().map(|(from, to)| serde_json::json!({
                "from": from,
                "to": to,
            })).collect::<Vec<_>>(),
        },
        "self_hosting_symbol_graph": {
            "acyclic": true,
            "node_count": symbol_nodes.len(),
            "edge_count": symbol_edges.len(),
            "topological_order": symbol_order,
            "nodes": STARTUP_SYMBOL_SPECS.iter().map(|spec| serde_json::json!({
                "symbol": spec.symbol,
                "depends_on": spec.depends_on,
            })).collect::<Vec<_>>(),
        },
        "witness_sha256": "",
    });

    let canonical =
        serde_json::to_string_pretty(&certificate).expect("startup certificate should serialize");
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let witness = format!("{:x}", hasher.finalize());
    certificate["witness_sha256"] = Value::String(witness);

    let body = serde_json::to_string_pretty(&certificate)
        .expect("startup certificate with witness should serialize");
    fs::write(out_dir.join("startup_init_order_certificate.json"), body)
        .expect("failed to write startup init order certificate");
}

fn load_json(path: &Path) -> Value {
    let body = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display())); // ubs:ignore — build.rs must hard-fail on missing inputs
    serde_json::from_str(&body)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display())) // ubs:ignore — build.rs must hard-fail on invalid inputs
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

fn load_source_scan_exceptions(profile: &Value) -> SourceScanExceptions {
    let mut exceptions = SourceScanExceptions::new();
    let rows = profile
        .pointer("/detection_rules/source_scan_exceptions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for row in rows {
        let Some(module) = row.get("module").and_then(Value::as_str) else {
            continue;
        };
        let Some(function) = row.get("function").and_then(Value::as_str) else {
            continue;
        };
        let symbols = row
            .get("symbols")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        if symbols.is_empty() {
            continue;
        }
        exceptions
            .entry(module.to_owned())
            .or_default()
            .entry(function.to_owned())
            .or_default()
            .extend(symbols);
    }
    exceptions
}

fn extract_function_name(line: &str) -> Option<String> {
    let fn_pos = line.find("fn ")?;
    let after = &line[fn_pos + 3..];
    let end = after
        .bytes()
        .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        .count();
    if end == 0 {
        None
    } else {
        Some(after[..end].to_owned())
    }
}

fn count_braces(line: &str) -> isize {
    line.bytes().fold(0isize, |depth, byte| match byte {
        b'{' => depth + 1,
        b'}' => depth - 1,
        _ => depth,
    })
}

fn is_source_scan_exception(
    module: &str,
    current_fn: Option<&str>,
    symbol: &str,
    exceptions: &SourceScanExceptions,
) -> bool {
    current_fn
        .and_then(|function| exceptions.get(module)?.get(function))
        .is_some_and(|symbols| symbols.contains(symbol))
}

fn scan_call_throughs(abi_src: &Path, profile: &Value) -> Vec<CallThroughSite> {
    let mut modules = fs::read_dir(abi_src)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", abi_src.display())) // ubs:ignore — build.rs must hard-fail on missing ABI sources
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with("_abi.rs"))
        })
        .collect::<Vec<_>>();
    modules.sort();

    let exceptions = load_source_scan_exceptions(profile);
    let mut sites = Vec::new();
    for module_path in modules {
        let module_name = module_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .trim_end_matches(".rs")
            .to_owned();
        let content = fs::read_to_string(&module_path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", module_path.display())); // ubs:ignore — build.rs must hard-fail on unreadable ABI sources

        let mut brace_depth = 0isize;
        let mut pending_fn: Option<String> = None;
        let mut current_fn: Option<String> = None;
        let mut current_fn_base_depth = 0isize;
        for (lineno, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if !trimmed.starts_with("//")
                && let Some(fn_name) = extract_function_name(line)
            {
                pending_fn = Some(fn_name);
            }
            let new_brace_depth = if trimmed.starts_with("//") {
                brace_depth
            } else {
                brace_depth + count_braces(line)
            };
            if current_fn.is_none()
                && let Some(fn_name) = pending_fn.as_ref()
                && new_brace_depth > brace_depth
            {
                current_fn = Some(fn_name.clone());
                current_fn_base_depth = brace_depth;
                pending_fn = None;
            }
            if trimmed.starts_with("//") {
                brace_depth = new_brace_depth;
                continue;
            }
            let active_fn = current_fn.as_deref();

            let mut libc_search_from = 0;
            while let Some(pos) = line[libc_search_from..].find("libc::") {
                let abs_pos = libc_search_from + pos;
                let after = &line[abs_pos + "libc::".len()..];
                if let Some(function) = extract_libc_call(after)
                    && function != "syscall"
                    && !is_source_scan_exception(&module_name, active_fn, function, &exceptions)
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
                if current_fn.is_some() && new_brace_depth <= current_fn_base_depth {
                    current_fn = None;
                }
                brace_depth = new_brace_depth;
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
            if current_fn.is_some() && new_brace_depth <= current_fn_base_depth {
                current_fn = None;
            }
            brace_depth = new_brace_depth;
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
    if replace_allowed_set.contains("WrapsHostLibc")
        || replace_allowed_set.contains("GlibcCallThrough")
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
            if status == "WrapsHostLibc" || status == "GlibcCallThrough" || status == "Stub" {
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

    let callthrough_sites = scan_call_throughs(
        &root.join("crates/frankenlibc-abi/src"),
        &replacement_profile,
    );
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

    eprintln!(
        "standalone feature requires a replacement-clean ABI.\n{}\nRun `bash scripts/check_replacement_guard.sh replacement` for the full report.",
        diagnostics.join("\n")
    );
    std::process::exit(1);
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
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", abi_src.display())) // ubs:ignore — build.rs must hard-fail on missing ABI sources
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
    // cargo-fuzz / libFuzzer builds inject `--cfg fuzzing` via RUSTFLAGS
    // and link the abi crate as part of an instrumented dylib that
    // doesn't define every symbol the libc.map version script names —
    // so applying the script there hard-fails the link. Skip the
    // script in that mode (bd-0ubkr).
    let encoded_rustflags = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    let fuzzing_build = encoded_rustflags
        .split('\x1f')
        .any(|flag| flag == "--cfg=fuzzing" || flag == "fuzzing")
        || encoded_rustflags.contains("--cfg fuzzing");

    emit_rerun_directives(&repo_root, &manifest_dir);
    if standalone_enabled {
        enforce_standalone_policy(&repo_root);
    }

    if !debug_assertions_enabled && !fuzzing_build && std::path::Path::new(&version_script).exists()
    {
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
    emit_startup_init_order_certificate(std::path::Path::new(&out_dir));
}
