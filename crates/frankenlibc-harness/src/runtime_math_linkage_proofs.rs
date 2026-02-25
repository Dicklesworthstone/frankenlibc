//! Runtime-math decision-law linkage proof gate.
//!
//! Bead: `bd-7dw2`
//!
//! Goal:
//! - Prove every *production* runtime_math module is actually wired into the
//!   runtime decision law (directly in `decide()` or indirectly via fusion
//!   inputs updated by `observe_validation_result()`).
//! - Detect "ornamental" modules that are declared/updated but never influence
//!   decisions (or any other joinable outcome surface).
//!
//! This gate is intentionally source-of-truth driven:
//! - Production set comes from `tests/runtime_math/production_kernel_manifest.v1.json`.
//! - Linkage ledger comes from `tests/runtime_math/runtime_math_linkage.v1.json`.
//! - Wiring is proven against the canonical implementation source:
//!   `crates/frankenlibc-membrane/src/runtime_math/mod.rs`.

use crate::structured_log::{LogEmitter, LogEntry, LogLevel, Outcome, StreamKind};
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::Path;

const BEAD_ID: &str = "bd-7dw2";
const GATE: &str = "runtime_math_linkage_proofs";
const RUN_ID: &str = "rtm-linkage-proofs";

#[derive(Debug, Serialize)]
pub struct RuntimeMathLinkageProofSummary {
    pub total_modules: usize,
    pub passed: usize,
    pub failed: usize,
}

#[derive(Debug, Serialize)]
pub struct RuntimeMathModuleLinkageResult {
    pub module: String,
    pub linkage_status: String,
    pub decision_target: String,
    pub field_name: String,
    pub decide_field_hit: bool,
    pub observe_field_hit: bool,
    pub snapshot_field_hit: bool,
    pub cached_outputs: Vec<String>,
    pub cached_outputs_used_in_decide: Vec<String>,
    pub cached_outputs_used_in_fusion_inputs: Vec<String>,
    pub influence_ok: bool,
    pub failures: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RuntimeMathLinkageProofReport {
    pub schema_version: &'static str,
    pub bead: &'static str,
    pub generated_at: String,
    pub sources: RuntimeMathLinkageProofSources,
    pub summary: RuntimeMathLinkageProofSummary,
    pub modules: Vec<RuntimeMathModuleLinkageResult>,
}

#[derive(Debug, Serialize)]
pub struct RuntimeMathLinkageProofSources {
    pub production_manifest: String,
    pub linkage_ledger: String,
    pub runtime_math_mod_rs: String,
    pub log_path: String,
    pub report_path: String,
}

pub fn run_and_write(
    workspace_root: &Path,
    log_path: &Path,
    report_path: &Path,
) -> Result<RuntimeMathLinkageProofReport, Box<dyn std::error::Error>> {
    let manifest_path =
        workspace_root.join("tests/runtime_math/production_kernel_manifest.v1.json");
    let linkage_path = workspace_root.join("tests/runtime_math/runtime_math_linkage.v1.json");
    let mod_rs_path = workspace_root.join("crates/frankenlibc-membrane/src/runtime_math/mod.rs");

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path)?)?;
    let linkage: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&linkage_path)?)?;
    let mod_rs = std::fs::read_to_string(&mod_rs_path)?;

    let production_modules: Vec<String> = manifest["production_modules"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("manifest.production_modules must be an array"))?
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| {
                    std::io::Error::other("manifest.production_modules entries must be strings")
                })
                .map(|s| s.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;

    let linkage_modules = linkage["modules"]
        .as_object()
        .ok_or_else(|| std::io::Error::other("linkage.modules must be an object"))?;

    let struct_src = slice_struct_runtime_kernel(&mod_rs)?;
    let decide_src = slice_between(
        &mod_rs,
        "pub fn decide(&self, mode: SafetyLevel, ctx: RuntimeContext) -> RuntimeDecision {",
        "/// Return the current contextual check ordering for a given family/context.",
    )?;
    let observe_src = slice_between(
        &mod_rs,
        "pub fn observe_validation_result(",
        "/// Record overlap information for cross-shard consistency checks.",
    )?;
    let snapshot_src = slice_between(
        &mod_rs,
        "pub fn snapshot(&self, mode: SafetyLevel) -> RuntimeKernelSnapshot",
        "fn resample_high_order_kernels(&self, mode: SafetyLevel, ctx: RuntimeContext) {",
    )?;

    let decide_cached_reads = collect_cached_load_names(decide_src);
    let fusion_inputs = collect_fusion_input_cached_loads(observe_src)?;

    std::fs::create_dir_all(
        log_path
            .parent()
            .ok_or_else(|| std::io::Error::other("log_path must have a parent directory"))?,
    )?;
    std::fs::create_dir_all(
        report_path
            .parent()
            .ok_or_else(|| std::io::Error::other("report_path must have a parent directory"))?,
    )?;

    let mut emitter = LogEmitter::to_file(log_path, BEAD_ID, RUN_ID)?;
    emitter.emit_entry(
        LogEntry::new(
            "",
            LogLevel::Warn,
            "runtime_math.linkage_proof.boundary_assumption",
        )
        .with_stream(StreamKind::Release)
        .with_gate(GATE)
        .with_outcome(Outcome::Pass)
        .with_controller_id("source_parser")
        .with_details(serde_json::json!({
            "assumption": "source slicing markers in runtime_math/mod.rs remain stable across refactors",
            "decision_path": "proof->linkage->boundary_assumption",
        })),
    )?;

    let mut results = Vec::with_capacity(production_modules.len());
    let mut passed = 0usize;
    let mut failed = 0usize;

    for module in &production_modules {
        let meta = linkage_modules
            .get(module)
            .ok_or_else(|| format!("linkage ledger missing module: {module}"))?;
        let linkage_status = meta["linkage_status"]
            .as_str()
            .unwrap_or("UNKNOWN")
            .to_string();
        let decision_target = meta["decision_target"].as_str().unwrap_or("").to_string();

        emitter.emit_entry(
            LogEntry::new("", LogLevel::Trace, "runtime_math.linkage_proof.step")
                .with_stream(StreamKind::Release)
                .with_gate(GATE)
                .with_outcome(Outcome::Pass)
                .with_controller_id(module.clone())
                .with_details(serde_json::json!({
                    "module": module,
                    "linkage_status": linkage_status.clone(),
                    "decision_target": decision_target.clone(),
                    "decision_path": "proof->linkage->module_step"
                })),
        )?;

        let mut failures = Vec::new();
        if linkage_status != "Production" {
            failures.push(format!(
                "linkage_status must be Production for production module (got {linkage_status})"
            ));
        }
        if decision_target.is_empty() {
            failures.push("decision_target missing/empty in linkage ledger".to_string());
        }

        let field_name = match map_module_to_field_name(&mod_rs, struct_src, module) {
            Ok(v) => v,
            Err(e) => {
                failures.push(format!(
                    "failed to map module to RuntimeMathKernel field: {e}"
                ));
                String::new()
            }
        };

        let decide_field_hit =
            !field_name.is_empty() && contains_self_field_access(decide_src, &field_name);
        let observe_field_hit =
            !field_name.is_empty() && contains_self_field_access(observe_src, &field_name);
        let snapshot_field_hit =
            !field_name.is_empty() && contains_self_field_access(snapshot_src, &field_name);

        let mut cached_outputs = BTreeSet::new();
        if !field_name.is_empty() {
            if let Some(win) =
                window_after_first_occurrence(observe_src, &format!("self.{field_name}"), 1200)
            {
                cached_outputs.extend(collect_cached_store_names(win));
            }
            if let Some(win) =
                window_after_first_occurrence(decide_src, &format!("self.{field_name}"), 1200)
            {
                cached_outputs.extend(collect_cached_store_names(win));
            }
        }
        let cached_outputs: Vec<String> = cached_outputs.into_iter().collect();

        let cached_outputs_used_in_decide: Vec<String> = cached_outputs
            .iter()
            .filter(|name| decide_cached_reads.contains(*name))
            .cloned()
            .collect();
        let cached_outputs_used_in_fusion_inputs: Vec<String> = cached_outputs
            .iter()
            .filter(|name| fusion_inputs.contains(*name))
            .cloned()
            .collect();

        let influence_ok = decide_field_hit
            || !cached_outputs_used_in_decide.is_empty()
            || !cached_outputs_used_in_fusion_inputs.is_empty();

        emitter.emit_entry(
            LogEntry::new("", LogLevel::Debug, "runtime_math.linkage_proof.mapping")
                .with_stream(StreamKind::Release)
                .with_gate(GATE)
                .with_outcome(Outcome::Pass)
                .with_controller_id(module.clone())
                .with_details(serde_json::json!({
                    "module": module,
                    "field_name": field_name.clone(),
                    "decide_field_hit": decide_field_hit,
                    "observe_field_hit": observe_field_hit,
                    "snapshot_field_hit": snapshot_field_hit,
                    "cached_outputs_count": cached_outputs.len(),
                    "decision_path": "proof->linkage->mapping",
                })),
        )?;

        if field_name.is_empty() {
            failures.push("module has no resolved field_name (cannot prove wiring)".to_string());
        }
        if !influence_ok {
            failures.push(
                "no decision-law influence detected (not used in decide and not fed into fusion inputs)"
                    .to_string(),
            );
        }

        let outcome = if failures.is_empty() {
            passed += 1;
            "pass"
        } else {
            failed += 1;
            "fail"
        };

        if failures.is_empty()
            && !decide_field_hit
            && cached_outputs_used_in_decide.is_empty()
            && cached_outputs_used_in_fusion_inputs.len() <= 1
        {
            emitter.emit_entry(
                LogEntry::new(
                    "",
                    LogLevel::Warn,
                    "runtime_math.linkage_proof.boundary_assumption",
                )
                .with_stream(StreamKind::Release)
                .with_gate(GATE)
                .with_outcome(Outcome::Pass)
                .with_controller_id(module.clone())
                .with_details(serde_json::json!({
                    "module": module,
                    "field_name": field_name.clone(),
                    "decide_field_hit": decide_field_hit,
                    "cached_outputs_used_in_decide": cached_outputs_used_in_decide.clone(),
                    "cached_outputs_used_in_fusion_inputs": cached_outputs_used_in_fusion_inputs.clone(),
                    "decision_path": "proof->linkage->boundary_assumption"
                })),
            )?;
        }
        if !failures.is_empty() {
            emitter.emit_entry(
                LogEntry::new("", LogLevel::Error, "runtime_math.linkage_proof.failure")
                    .with_stream(StreamKind::Release)
                    .with_gate(GATE)
                    .with_outcome(Outcome::Fail)
                    .with_controller_id(module.clone())
                    .with_details(serde_json::json!({
                        "module": module,
                        "field_name": field_name.clone(),
                        "influence_ok": influence_ok,
                        "failures": failures.clone(),
                        "decision_path": "proof->linkage->failure"
                    })),
            )?;
        }

        let res = RuntimeMathModuleLinkageResult {
            module: module.clone(),
            linkage_status: linkage_status.clone(),
            decision_target: decision_target.clone(),
            field_name: field_name.clone(),
            decide_field_hit,
            observe_field_hit,
            snapshot_field_hit,
            cached_outputs: cached_outputs.clone(),
            cached_outputs_used_in_decide: cached_outputs_used_in_decide.clone(),
            cached_outputs_used_in_fusion_inputs: cached_outputs_used_in_fusion_inputs.clone(),
            influence_ok,
            failures: failures.clone(),
        };
        results.push(res);

        let entry = LogEntry::new("", LogLevel::Info, "runtime_math.linkage_proof")
            .with_bead(BEAD_ID)
            .with_stream(StreamKind::Release)
            .with_gate(GATE)
            .with_outcome(if outcome == "pass" {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_controller_id(module.clone())
            .with_artifacts(vec![
                rel_path(workspace_root, &mod_rs_path),
                rel_path(workspace_root, report_path),
            ])
            .with_details(serde_json::json!({
                "module": module,
                "linkage_status": linkage_status,
                "decision_target": decision_target,
                "field_name": field_name,
                "decide_field_hit": decide_field_hit,
                "observe_field_hit": observe_field_hit,
                "snapshot_field_hit": snapshot_field_hit,
                "cached_outputs": cached_outputs,
                "cached_outputs_used_in_decide": cached_outputs_used_in_decide,
                "cached_outputs_used_in_fusion_inputs": cached_outputs_used_in_fusion_inputs,
                "influence_ok": influence_ok,
                "failures": failures,
            }));
        emitter.emit_entry(entry)?;
    }

    emitter.flush()?;

    let report = RuntimeMathLinkageProofReport {
        schema_version: "v1",
        bead: BEAD_ID,
        generated_at: crate::structured_log::LogEntry::new(
            "bd-7dw2::gen::000",
            LogLevel::Info,
            "generated",
        )
        .timestamp,
        sources: RuntimeMathLinkageProofSources {
            production_manifest: rel_path(workspace_root, &manifest_path),
            linkage_ledger: rel_path(workspace_root, &linkage_path),
            runtime_math_mod_rs: rel_path(workspace_root, &mod_rs_path),
            log_path: rel_path(workspace_root, log_path),
            report_path: rel_path(workspace_root, report_path),
        },
        summary: RuntimeMathLinkageProofSummary {
            total_modules: production_modules.len(),
            passed,
            failed,
        },
        modules: results,
    };

    std::fs::write(report_path, serde_json::to_string_pretty(&report)?)?;

    Ok(report)
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn slice_struct_runtime_kernel(src: &str) -> Result<&str, Box<dyn std::error::Error>> {
    let start = src
        .find("pub struct RuntimeMathKernel {")
        .ok_or_else(|| std::io::Error::other("RuntimeMathKernel struct not found"))?;
    let tail = &src[start..];
    let end = tail.find("impl RuntimeMathKernel").ok_or_else(|| {
        std::io::Error::other("RuntimeMathKernel impl block not found after struct")
    })?;
    Ok(&tail[..end])
}

fn slice_between<'a>(
    src: &'a str,
    start_marker: &str,
    end_marker: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    let start = src
        .find(start_marker)
        .ok_or_else(|| std::io::Error::other(format!("start marker not found: {start_marker}")))?;
    let tail = &src[start..];
    let end = tail
        .find(end_marker)
        .ok_or_else(|| std::io::Error::other(format!("end marker not found: {end_marker}")))?;
    Ok(&tail[..end])
}

fn rel_path(workspace_root: &Path, path: &Path) -> String {
    path.strip_prefix(workspace_root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn window_after_first_occurrence<'a>(
    haystack: &'a str,
    needle: &str,
    window_len: usize,
) -> Option<&'a str> {
    let pos = haystack.find(needle)?;
    let end = haystack.len().min(pos.saturating_add(window_len));
    Some(&haystack[pos..end])
}

fn contains_self_field_access(src: &str, field: &str) -> bool {
    // Fast path: common single-line access.
    if src.contains(&format!("self.{field}")) {
        return true;
    }

    // Slow path: method-chains formatted as:
    //   let x = self
    //       .field
    //       .method(...)
    let needle = format!(".{field}");
    let mut i = 0usize;
    while let Some(pos) = src[i..].find(&needle) {
        let abs = i + pos;
        let window_start = abs.saturating_sub(96);
        let prefix = &src[window_start..abs];
        if prefix.contains("self") {
            return true;
        }
        i = abs + needle.len();
    }
    false
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn collect_cached_store_names(src: &str) -> BTreeSet<String> {
    collect_cached_names_with_method(src, "store")
}

fn collect_cached_load_names(src: &str) -> BTreeSet<String> {
    collect_cached_names_with_method(src, "load")
}

fn collect_cached_names_with_method(src: &str, method: &str) -> BTreeSet<String> {
    let bytes = src.as_bytes();
    let mut out = BTreeSet::new();
    let mut i = 0usize;
    let needle = b"self.cached_";
    while i < bytes.len() {
        let pos = match bytes[i..].windows(needle.len()).position(|w| w == needle) {
            Some(p) => i + p,
            None => break,
        };
        let mut j = pos + b"self.".len();
        let name_start = j;
        while j < bytes.len() && is_ident_char(bytes[j]) {
            j += 1;
        }
        if j == name_start {
            i = pos + 1;
            continue;
        }
        let name = &src[name_start..j];

        let mut k = skip_ws(bytes, j);
        // Optional indexing: cached_x[..]
        while k < bytes.len() && bytes[k] == b'[' {
            if let Some(close_rel) = src[k..].find(']') {
                k += close_rel + 1;
            } else {
                break;
            }
            k = skip_ws(bytes, k);
        }
        k = skip_ws(bytes, k);
        if k < bytes.len() && bytes[k] == b'.' {
            let tail = &src[k + 1..];
            if tail.starts_with(method) {
                out.insert(name.to_string());
            }
        }
        i = j;
    }
    out
}

fn collect_fusion_input_cached_loads(
    observe_src: &str,
) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let base_block = slice_between(
        observe_src,
        "let base_severity: [u8; BASE_SEVERITY_LEN] = [",
        "];",
    )?;
    let meta_block = slice_between(
        observe_src,
        "let mut severity = [0u8; fusion::SIGNALS];",
        "let summary = {",
    )?;
    let mut out = collect_cached_load_names(base_block);
    out.extend(collect_cached_load_names(meta_block));
    Ok(out)
}

fn map_module_to_field_name(
    full_src: &str,
    struct_src: &str,
    module: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Special cases: modules referenced via module path without `use self::<mod>::Type`.
    match module {
        "evidence" => return Ok("evidence_log".to_string()),
        "policy_table" => return Ok("policy_lookup".to_string()),
        _ => {}
    }

    // Fast path: many modules use the module name as the field name.
    if struct_src.contains(&format!("\n    {module}:")) {
        return Ok(module.to_string());
    }

    let types = find_use_stmt_types(full_src, module);
    if types.is_empty() {
        return Err(
            std::io::Error::other(format!("no `use self::{module}::...` statement found")).into(),
        );
    }

    // Prefer controller-ish types; fall back to any imported identifiers.
    let preferred: Vec<String> = types
        .iter()
        .filter(|t| {
            t.ends_with("Controller")
                || t.ends_with("Monitor")
                || t.ends_with("Router")
                || t.ends_with("Oracle")
                || t.ends_with("Engine")
                || t.ends_with("Compositor")
                || t.ends_with("Detector")
                || t.ends_with("Chooser")
                || t.ends_with("Generator")
                || t.ends_with("Tuner")
                || t.ends_with("Lookup")
                || t.ends_with("Normalizer")
                || t.ends_with("Monitor")
        })
        .cloned()
        .collect();
    let candidates = if preferred.is_empty() {
        types
    } else {
        preferred
    };

    for ty in &candidates {
        if let Some(field) = find_field_name_by_type(struct_src, ty) {
            return Ok(field);
        }
    }

    Err(std::io::Error::other(format!(
        "could not locate RuntimeMathKernel field matching imported types for module {module}: {candidates:?}"
    ))
    .into())
}

fn find_use_stmt_types(src: &str, module: &str) -> Vec<String> {
    let needle = format!("use self::{module}::");
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(pos) = src[i..].find(&needle) {
        let start = i + pos + needle.len();
        let tail = &src[start..];
        // Stop at the first ';' after the use statement.
        let stmt_end = match tail.find(';') {
            Some(e) => start + e,
            None => break,
        };
        let stmt = src[start..stmt_end].trim();

        if let Some(brace_start) = stmt.find('{') {
            if let Some(brace_end) = stmt.rfind('}') {
                let inner = &stmt[brace_start + 1..brace_end];
                for part in inner.split(',') {
                    let t = part.trim();
                    if !t.is_empty() {
                        out.push(t.to_string());
                    }
                }
            }
        } else {
            // Single identifier import.
            let t = stmt.trim();
            if !t.is_empty() {
                out.push(t.to_string());
            }
        }

        i = stmt_end + 1;
    }

    out.sort();
    out.dedup();
    out
}

fn find_field_name_by_type(struct_src: &str, ty: &str) -> Option<String> {
    let pos = struct_src.find(ty)?;
    let line_start = struct_src[..pos].rfind('\n').map(|p| p + 1).unwrap_or(0);
    let line_end = struct_src[pos..]
        .find('\n')
        .map(|p| pos + p)
        .unwrap_or(struct_src.len());
    let line = struct_src[line_start..line_end].trim_start();
    let field = line.split(':').next()?.trim();
    if field.is_empty() {
        None
    } else {
        Some(field.to_string())
    }
}
