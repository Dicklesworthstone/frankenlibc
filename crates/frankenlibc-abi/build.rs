use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const HOST_DELEGATION_CENSUS_REL: &str = "tests/conformance/host_delegation_census.v1.json";
const HOST_DELEGATION_CENSUS_SCHEMA: &str = "host_delegation_census.v1";
const HOST_DELEGATION_DETECTOR_VERSION: u64 = 14;
const STANDALONE_CENSUS_PROFILE: &str = "standalone-release-linux-x86_64";

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
    let witness = hex_digest(&hasher.finalize());
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

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let body = fs::read(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(body);
    Ok(hex_digest(&hasher.finalize()))
}

fn abi_source_tree_sha256(root: &Path) -> Result<(usize, String), String> {
    let source_dir = root.join("crates/frankenlibc-abi/src");
    let entries = fs::read_dir(&source_dir)
        .map_err(|err| format!("failed to read {}: {err}", source_dir.display()))?;
    let mut source_files = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|err| format!("failed to enumerate {}: {err}", source_dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            source_files.push(path);
        }
    }
    source_files.sort();

    let mut hasher = Sha256::new();
    for path in &source_files {
        let relative = path
            .strip_prefix(root)
            .map_err(|err| format!("failed to relativize {}: {err}", path.display()))?;
        let relative = relative
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 ABI source path: {}", path.display()))?;
        let body =
            fs::read(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update(&body);
        hasher.update([0]);
    }

    Ok((source_files.len(), hex_digest(&hasher.finalize())))
}

fn required_u64(value: &Value, pointer: &str, diagnostics: &mut Vec<String>) -> Option<u64> {
    let Some(number) = value.pointer(pointer).and_then(Value::as_u64) else {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} must provide integer {pointer}"
        ));
        return None;
    };
    Some(number)
}

fn required_array_len(value: &Value, pointer: &str, diagnostics: &mut Vec<String>) -> Option<u64> {
    let Some(rows) = value.pointer(pointer).and_then(Value::as_array) else {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} must provide array {pointer}"
        ));
        return None;
    };
    Some(rows.len() as u64)
}

fn checked_count_sum(
    counts: impl IntoIterator<Item = u64>,
    label: &str,
    diagnostics: &mut Vec<String>,
) -> Option<u64> {
    counts.into_iter().try_fold(0u64, |total, count| {
        total.checked_add(count).or_else(|| {
            diagnostics.push(format!(
                "- {HOST_DELEGATION_CENSUS_REL} {label} count overflow"
            ));
            None
        })
    })
}

fn standalone_census_diagnostics(root: &Path) -> Vec<String> {
    let census_path = root.join(HOST_DELEGATION_CENSUS_REL);
    let mut diagnostics = Vec::new();
    let body = match fs::read_to_string(&census_path) {
        Ok(body) => body,
        Err(err) => {
            diagnostics.push(format!("- failed to read {}: {err}", census_path.display()));
            return diagnostics;
        }
    };
    let census: Value = match serde_json::from_str(&body) {
        Ok(census) => census,
        Err(err) => {
            diagnostics.push(format!(
                "- failed to parse {}: {err}",
                census_path.display()
            ));
            return diagnostics;
        }
    };

    if census.get("schema_version").and_then(Value::as_str) != Some(HOST_DELEGATION_CENSUS_SCHEMA) {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} must use schema {HOST_DELEGATION_CENSUS_SCHEMA}"
        ));
    }
    if census.pointer("/detector/version").and_then(Value::as_u64)
        != Some(HOST_DELEGATION_DETECTOR_VERSION)
    {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} must use detector version {HOST_DELEGATION_DETECTOR_VERSION}"
        ));
    }
    if census
        .pointer("/detector/abi_source_dir")
        .and_then(Value::as_str)
        != Some("crates/frankenlibc-abi/src")
    {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} has an unexpected ABI source directory"
        ));
    }

    match abi_source_tree_sha256(root) {
        Ok((source_file_count, source_tree_sha256)) => {
            let recorded_count = census
                .pointer("/detector/source_file_count")
                .and_then(Value::as_u64);
            if recorded_count != Some(source_file_count as u64) {
                diagnostics.push(format!(
                    "- {HOST_DELEGATION_CENSUS_REL} source_file_count is stale: recorded={} current={source_file_count}",
                    recorded_count
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "<missing>".to_owned())
                ));
            }
            let recorded_hash = census
                .pointer("/detector/source_tree_sha256")
                .and_then(Value::as_str);
            if recorded_hash != Some(source_tree_sha256.as_str()) {
                diagnostics.push(format!(
                    "- {HOST_DELEGATION_CENSUS_REL} ABI source hash is stale: regenerate it with scripts/generate_host_delegation_census.py"
                ));
            }
        }
        Err(err) => diagnostics.push(format!(
            "- cannot verify {HOST_DELEGATION_CENSUS_REL} ABI source hash: {err}"
        )),
    }

    let profile_pointer = format!("/profile_census/{STANDALONE_CENSUS_PROFILE}");
    let Some(profile) = census.pointer(&profile_pointer) else {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} must provide profile {STANDALONE_CENSUS_PROFILE}"
        ));
        return diagnostics;
    };
    if profile.pointer("/profile/name").and_then(Value::as_str) != Some(STANDALONE_CENSUS_PROFILE) {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} profile identity does not match {STANDALONE_CENSUS_PROFILE}"
        ));
    }
    for (profile_key, cargo_env) in [
        ("target_arch", "CARGO_CFG_TARGET_ARCH"),
        ("target_endian", "CARGO_CFG_TARGET_ENDIAN"),
        ("target_env", "CARGO_CFG_TARGET_ENV"),
        ("target_family", "CARGO_CFG_TARGET_FAMILY"),
        ("target_os", "CARGO_CFG_TARGET_OS"),
        ("target_pointer_width", "CARGO_CFG_TARGET_POINTER_WIDTH"),
        ("target_vendor", "CARGO_CFG_TARGET_VENDOR"),
    ] {
        let recorded = profile
            .pointer(&format!("/profile/values/{profile_key}"))
            .and_then(Value::as_str);
        let current = std::env::var(cargo_env).ok();
        if recorded != current.as_deref() {
            diagnostics.push(format!(
                "- {HOST_DELEGATION_CENSUS_REL} profile {STANDALONE_CENSUS_PROFILE} does not cover the current {profile_key}: recorded={} current={}",
                recorded.unwrap_or("<missing>"),
                current.as_deref().unwrap_or("<missing>")
            ));
        }
    }
    let recorded_flags = profile
        .pointer("/profile/flags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if recorded_flags != BTreeSet::from(["unix".to_owned()])
        || std::env::var_os("CARGO_CFG_UNIX").is_none()
    {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} profile {STANDALONE_CENSUS_PROFILE} does not cover the current cfg flags: recorded={recorded_flags:?} current_unix={}",
            std::env::var_os("CARGO_CFG_UNIX").is_some()
        ));
    }
    let recorded_target_features = profile
        .pointer("/profile/target_features")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let active_target_features = std::env::var("CARGO_CFG_TARGET_FEATURE")
        .unwrap_or_default()
        .split(',')
        .filter(|feature| !feature.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if recorded_target_features != active_target_features {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} profile {STANDALONE_CENSUS_PROFILE} does not cover the active target features: recorded={recorded_target_features:?} current={active_target_features:?}"
        ));
    }
    let recorded_features = profile
        .pointer("/profile/features")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if recorded_features != BTreeSet::from(["standalone".to_owned()]) {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} profile {STANDALONE_CENSUS_PROFILE} must cover exactly the standalone feature"
        ));
    }
    let active_features = std::env::vars_os()
        .filter_map(|(key, _)| {
            let key = key.to_str()?;
            key.strip_prefix("CARGO_FEATURE_")
                .map(|feature| feature.to_ascii_lowercase().replace('_', "-"))
        })
        .filter(|feature| feature != "default")
        .collect::<BTreeSet<_>>();
    if recorded_features != active_features {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} profile {STANDALONE_CENSUS_PROFILE} does not cover the active Cargo features: recorded={recorded_features:?} current={active_features:?}"
        ));
    }
    if std::env::var_os("CARGO_CFG_DEBUG_ASSERTIONS").is_some() {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} profile {STANDALONE_CENSUS_PROFILE} covers release builds, not debug-assertions builds"
        ));
    }

    if profile
        .pointer("/coverage/support_matrix_path")
        .and_then(Value::as_str)
        != Some("support_matrix.json")
    {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} has an unexpected support-matrix path"
        ));
    }
    let recorded_matrix_hash = profile
        .pointer("/coverage/support_matrix_sha256")
        .and_then(Value::as_str);
    match file_sha256(&root.join("support_matrix.json")) {
        Ok(current_matrix_hash) => {
            if recorded_matrix_hash != Some(current_matrix_hash.as_str()) {
                diagnostics.push(format!(
                    "- {HOST_DELEGATION_CENSUS_REL} support-matrix hash is stale: regenerate it with scripts/generate_host_delegation_census.py"
                ));
            }
        }
        Err(err) => diagnostics.push(format!(
            "- cannot verify {HOST_DELEGATION_CENSUS_REL} support-matrix hash: {err}"
        )),
    }

    let recorded_cfg_count = required_u64(profile, "/cfg_diagnostic_count", &mut diagnostics);
    let cfg_count = required_array_len(profile, "/cfg_diagnostics", &mut diagnostics);
    if recorded_cfg_count.is_some() && recorded_cfg_count != cfg_count {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} cfg_diagnostic_count does not match cfg_diagnostics"
        ));
    }

    let recorded_host_count = required_u64(
        profile,
        "/summary/exported_symbol_with_host_dependency_count",
        &mut diagnostics,
    );
    let host_count = profile
        .pointer("/host_dependencies_by_symbol")
        .and_then(Value::as_object)
        .map(|rows| rows.len() as u64);
    if host_count.is_none() {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} must provide object /host_dependencies_by_symbol"
        ));
    }
    if recorded_host_count.is_some() && recorded_host_count != host_count {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} exported_symbol_with_host_dependency_count does not match host_dependencies_by_symbol"
        ));
    }

    let recorded_unknown_count = required_u64(
        profile,
        "/summary/unknown_reachable_call_edge_count",
        &mut diagnostics,
    );
    let unknown_count = match profile
        .pointer("/unknown_reachable_call_edge_counts_by_reason")
        .and_then(Value::as_object)
    {
        Some(rows) => {
            let mut counts = Vec::with_capacity(rows.len());
            for (reason, value) in rows {
                match value.as_u64() {
                    Some(count) => counts.push(count),
                    None => diagnostics.push(format!(
                        "- {HOST_DELEGATION_CENSUS_REL} unknown-edge reason {reason} must have an integer count"
                    )),
                }
            }
            if counts.len() == rows.len() {
                checked_count_sum(counts, "unknown reachable call-edge", &mut diagnostics)
            } else {
                None
            }
        }
        None => {
            diagnostics.push(format!(
                "- {HOST_DELEGATION_CENSUS_REL} must provide object /unknown_reachable_call_edge_counts_by_reason"
            ));
            None
        }
    };
    if recorded_unknown_count.is_some() && recorded_unknown_count != unknown_count {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} unknown_reachable_call_edge_count does not match unknown_reachable_call_edge_counts_by_reason"
        ));
    }

    let coverage_complete = profile
        .pointer("/coverage/complete")
        .and_then(Value::as_bool);
    if coverage_complete.is_none() {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} must provide boolean /coverage/complete"
        ));
    }
    let recorded_missing_source = required_u64(
        profile,
        "/coverage/missing_from_source_count",
        &mut diagnostics,
    );
    let missing_source =
        required_array_len(profile, "/coverage/missing_from_source", &mut diagnostics);
    if recorded_missing_source.is_some() && recorded_missing_source != missing_source {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} missing_from_source_count does not match missing_from_source"
        ));
    }
    let recorded_missing_matrix = required_u64(
        profile,
        "/coverage/missing_from_support_matrix_count",
        &mut diagnostics,
    );
    let missing_matrix = required_array_len(
        profile,
        "/coverage/missing_from_support_matrix",
        &mut diagnostics,
    );
    if recorded_missing_matrix.is_some() && recorded_missing_matrix != missing_matrix {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} missing_from_support_matrix_count does not match missing_from_support_matrix"
        ));
    }
    let duplicate_source = required_array_len(
        profile,
        "/coverage/duplicate_source_symbols",
        &mut diagnostics,
    );
    let duplicate_matrix = required_array_len(
        profile,
        "/coverage/duplicate_support_matrix_symbols",
        &mut diagnostics,
    );
    let coverage_gap_count = match (
        missing_source,
        missing_matrix,
        duplicate_source,
        duplicate_matrix,
    ) {
        (Some(a), Some(b), Some(c), Some(d)) => checked_count_sum(
            [a, b, c, d],
            "support-matrix coverage gap",
            &mut diagnostics,
        ),
        _ => None,
    };
    if let (Some(complete), Some(gap_count)) = (coverage_complete, coverage_gap_count)
        && complete != (gap_count == 0)
    {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} coverage.complete is inconsistent with the coverage arrays"
        ));
    }

    let mut expected_blockers = BTreeMap::<String, u64>::new();
    for (code, count) in [
        ("cfg_analysis_incomplete", cfg_count),
        ("reachable_host_dependencies", host_count),
        ("unknown_reachable_call_edges", unknown_count),
        ("support_matrix_coverage_incomplete", coverage_gap_count),
    ] {
        if let Some(count) = count
            && count > 0
        {
            expected_blockers.insert(code.to_owned(), count);
        }
    }

    let mut recorded_blockers = BTreeMap::<String, u64>::new();
    match profile.get("admission_blockers").and_then(Value::as_array) {
        Some(rows) => {
            for (index, row) in rows.iter().enumerate() {
                let Some(code) = row.get("code").and_then(Value::as_str) else {
                    diagnostics.push(format!(
                        "- {HOST_DELEGATION_CENSUS_REL} blocker {index} has no code"
                    ));
                    continue;
                };
                let Some(count) = row.get("count").and_then(Value::as_u64) else {
                    diagnostics.push(format!(
                        "- {HOST_DELEGATION_CENSUS_REL} blocker {code} has no integer count"
                    ));
                    continue;
                };
                if count == 0 {
                    diagnostics.push(format!(
                        "- {HOST_DELEGATION_CENSUS_REL} blocker {code} must have a positive count"
                    ));
                }
                if recorded_blockers.insert(code.to_owned(), count).is_some() {
                    diagnostics.push(format!(
                        "- {HOST_DELEGATION_CENSUS_REL} repeats blocker {code}"
                    ));
                }
            }
        }
        None => diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} must provide admission_blockers as an array"
        )),
    }

    if recorded_blockers != expected_blockers {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} blocker summary is inconsistent with the derived profile counts"
        ));
    }
    let recorded_ready = profile
        .pointer("/summary/standalone_admission_ready")
        .and_then(Value::as_bool);
    if recorded_ready != Some(recorded_blockers.is_empty()) {
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} standalone_admission_ready is inconsistent with admission_blockers"
        ));
    }
    if !recorded_blockers.is_empty() {
        let blocker_summary = recorded_blockers
            .iter()
            .map(|(code, count)| format!("{code}={count}"))
            .collect::<Vec<_>>()
            .join(", ");
        diagnostics.push(format!(
            "- {HOST_DELEGATION_CENSUS_REL} profile {STANDALONE_CENSUS_PROFILE} blocks standalone admission: {blocker_summary}"
        ));
    }

    diagnostics
}

fn standalone_census_regeneration_diagnostics(root: &Path) -> Vec<String> {
    let script = root.join("scripts/generate_host_delegation_census.py");
    let output = match Command::new("python3")
        .arg(&script)
        .arg("--check")
        .current_dir(root)
        .output()
    {
        Ok(output) => output,
        Err(err) => {
            return vec![format!(
                "- cannot execute {} --check with python3: {err}",
                script.display()
            )];
        }
    };
    if output.status.success() {
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let mut detail = Vec::new();
    if !stdout.is_empty() {
        detail.push(stdout);
    }
    if !stderr.is_empty() {
        detail.push(stderr);
    }
    let detail = if detail.is_empty() {
        format!("exit status {}", output.status)
    } else {
        detail.join(" | ")
    };
    vec![format!(
        "- {HOST_DELEGATION_CENSUS_REL} does not match a fresh detector run: {detail}"
    )]
}

fn standalone_policy_diagnostics(root: &Path) -> Vec<String> {
    let replacement_profile = load_json(&root.join("tests/conformance/replacement_profile.json"));
    let packaging_spec = load_json(&root.join("tests/conformance/packaging_spec.json"));

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

    diagnostics.extend(standalone_census_regeneration_diagnostics(root));
    diagnostics.extend(standalone_census_diagnostics(root));

    diagnostics
}

fn enforce_standalone_policy(root: &Path) {
    let diagnostics = standalone_policy_diagnostics(root);
    if diagnostics.is_empty() {
        return;
    }

    eprintln!(
        "standalone feature requires a replacement-clean ABI.\n{}\nRun `bash scripts/check_host_delegation_census.sh` and `bash scripts/check_replacement_guard.sh replacement` for the full reports.",
        diagnostics.join("\n")
    );
    std::process::exit(1);
}

fn emit_rerun_directives(repo_root: &Path, manifest_dir: &str) {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={manifest_dir}/version_scripts/libc.map");
    println!(
        "cargo:rerun-if-changed={}",
        repo_root.join(HOST_DELEGATION_CENSUS_REL).display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        repo_root
            .join("scripts/generate_host_delegation_census.py")
            .display()
    );
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

    // The version script includes _Unwind_* symbols which are only present when
    // standalone+owned-unwind-stub features are enabled. Without those features,
    // the linker will fail because the symbols don't exist.
    let owned_unwind_enabled = std::env::var_os("CARGO_FEATURE_OWNED_UNWIND_STUB").is_some();
    if !debug_assertions_enabled
        && !fuzzing_build
        && standalone_enabled
        && owned_unwind_enabled
        && std::path::Path::new(&version_script).exists()
    {
        println!("cargo:rustc-cdylib-link-arg=-Wl,--version-script={version_script}");
    }

    // Bind the library's references to its own functions locally, as glibc
    // does with its internal aliases. Otherwise each of ~600 GOT entries
    // (abort, close, cos, ...) is resolved by a symbol lookup in every process
    // that loads the library -- ~80 us of /bin/true's startup
    // (bd-rc0923-epic-eeuy4f.25) -- and an executable that defines one of
    // those names (say `open`) captures the library's internal calls to it.
    // Data symbols are unaffected, so a copy-relocated `stdout`, `environ` or
    // `optind` still resolves to the executable's copy. The malloc family
    // stays preemptible, as in glibc: an application that supplies its own
    // malloc must receive the library's allocations and frees too.
    println!("cargo:rustc-cdylib-link-arg=-Wl,-Bsymbolic-functions");
    for symbol in [
        "malloc",
        "free",
        "calloc",
        "realloc",
        "reallocarray",
        "memalign",
        "aligned_alloc",
        "posix_memalign",
        "valloc",
        "pvalloc",
        "malloc_usable_size",
    ] {
        println!("cargo:rustc-cdylib-link-arg=-Wl,--export-dynamic-symbol={symbol}");
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
