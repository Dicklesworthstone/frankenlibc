//! Runtime-math strict-vs-hardened divergence bounds gate.
//!
//! Bead: `bd-2625`
//!
//! Goal:
//! - Make strict vs hardened divergence in the runtime_math decision surface explicit,
//!   explainable, and regression-checked.
//! - Encode a small, curated divergence matrix (`tests/runtime_math/runtime_math_divergence_bounds.v1.json`)
//!   and fail deterministically when forbidden divergence patterns appear.
//!
//! Scope:
//! - This gate validates the *runtime_math controller output* (`profile` + `MembraneAction`)
//!   for paired modes on representative contexts.
//! - It does NOT claim full libc semantic equivalence; downstream conformance fixtures
//!   remain the authority for user-visible behavior.

use crate::structured_log::{LogEmitter, LogEntry, LogLevel, Outcome, StreamKind};
use frankenlibc_membrane::{
    ApiFamily, HealingAction, MembraneAction, RuntimeContext, RuntimeMathKernel, SafetyLevel,
    ValidationProfile,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

const BEAD_ID: &str = "bd-2625";
const GATE: &str = "runtime_math_divergence_bounds";
const RUN_ID: &str = "rtm-divergence-bounds";

const MATRIX_REL_PATH: &str = "tests/runtime_math/runtime_math_divergence_bounds.v1.json";

#[derive(Debug, Deserialize)]
struct DivergenceBoundsMatrix {
    schema_version: String,
    bead: String,
    generated_at: String,
    description: String,
    mode_pair: [String; 2],
    forbidden_divergences: Vec<DivergenceRule>,
    #[serde(default)]
    evaluation_cases: Vec<DivergenceCase>,
    #[serde(default)]
    required_cases: Vec<RequiredCase>,
}

#[derive(Debug, Deserialize)]
struct DivergenceRule {
    id: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct DivergenceCase {
    id: String,
    family: String,
    description: String,
    ctx: DivergenceCtx,
}

#[derive(Debug, Deserialize)]
struct RequiredCase {
    id: String,
    family: String,
    description: String,
    ctx: DivergenceCtx,
    expect: RequiredExpectations,
}

#[derive(Debug, Deserialize)]
struct RequiredExpectations {
    strict: ExpectedDecision,
    hardened: ExpectedDecision,
}

#[derive(Debug, Deserialize)]
struct ExpectedDecision {
    profile: String,
    action: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DivergenceCtx {
    addr_hint: usize,
    requested_bytes: usize,
    is_write: bool,
    contention_hint: u16,
    bloom_negative: bool,
}

#[derive(Debug, Serialize)]
pub struct RuntimeMathDivergenceBoundsSummary {
    pub total_cases: usize,
    pub required_cases: usize,
    pub passed: usize,
    pub failed: usize,
    pub violations: usize,
}

#[derive(Debug, Serialize)]
pub struct CaseViolation {
    pub rule_id: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct DecisionSummary {
    pub profile: String,
    pub action: String,
    pub policy_id: u32,
    pub risk_upper_bound_ppm: u32,
}

#[derive(Debug, Serialize)]
pub struct RuntimeMathDivergenceCaseResult {
    pub case_id: String,
    pub description: String,
    pub family: String,
    pub ctx: DivergenceCtx,
    pub strict: DecisionSummary,
    pub hardened: DecisionSummary,
    pub violations: Vec<CaseViolation>,
    pub ok: bool,
}

#[derive(Debug, Serialize)]
pub struct RuntimeMathDivergenceBoundsSources {
    pub matrix: String,
    pub runtime_math_mod_rs: String,
    pub log_path: String,
    pub report_path: String,
}

#[derive(Debug, Serialize)]
pub struct RuntimeMathDivergenceBoundsReport {
    pub schema_version: &'static str,
    pub bead: &'static str,
    pub generated_at: String,
    pub sources: RuntimeMathDivergenceBoundsSources,
    pub matrix_schema_version: String,
    pub matrix_generated_at: String,
    pub summary: RuntimeMathDivergenceBoundsSummary,
    pub results: Vec<RuntimeMathDivergenceCaseResult>,
}

pub fn run_and_write(
    workspace_root: &Path,
    log_path: &Path,
    report_path: &Path,
) -> Result<RuntimeMathDivergenceBoundsReport, Box<dyn std::error::Error>> {
    let matrix_path = workspace_root.join(MATRIX_REL_PATH);
    let mod_rs_path = workspace_root.join("crates/frankenlibc-membrane/src/runtime_math/mod.rs");

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

    let matrix: DivergenceBoundsMatrix = {
        let content = std::fs::read_to_string(&matrix_path).map_err(|e| {
            std::io::Error::other(format!(
                "failed to read divergence bounds matrix '{}': {e}",
                matrix_path.display()
            ))
        })?;
        serde_json::from_str(&content).map_err(|e| {
            std::io::Error::other(format!(
                "failed to parse divergence bounds matrix '{}': {e}",
                matrix_path.display()
            ))
        })?
    };

    if matrix.schema_version != "v1" {
        return Err(std::io::Error::other(format!(
            "unsupported divergence matrix schema_version '{}'",
            matrix.schema_version
        ))
        .into());
    }
    if matrix.bead != BEAD_ID {
        return Err(std::io::Error::other(format!(
            "matrix bead mismatch: expected '{BEAD_ID}', got '{}'",
            matrix.bead
        ))
        .into());
    }
    if matrix.mode_pair != ["strict".to_string(), "hardened".to_string()] {
        return Err(std::io::Error::other(format!(
            "matrix mode_pair mismatch: expected ['strict','hardened'], got {:?}",
            matrix.mode_pair
        ))
        .into());
    }

    let mut emitter = LogEmitter::to_file(log_path, BEAD_ID, RUN_ID)?;

    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "runtime_math.divergence_bounds.start")
            .with_stream(StreamKind::Unit)
            .with_gate(GATE)
            .with_outcome(Outcome::Pass)
            .with_controller_id("gate_start")
            .with_details(serde_json::json!({
                "matrix": MATRIX_REL_PATH,
                "matrix_description": matrix.description,
                "cases": {
                    "evaluation": matrix.evaluation_cases.len(),
                    "required": matrix.required_cases.len(),
                }
            })),
    )?;

    let mut results = Vec::new();
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut violations = 0usize;

    for case in matrix.evaluation_cases.iter() {
        let res = run_case(
            &matrix,
            case.id.clone(),
            case.description.clone(),
            &case.family,
            &case.ctx,
        )?;
        violations += res.violations.len();
        if res.ok {
            passed += 1;
            emitter.emit_entry(case_log_entry(&res, Outcome::Pass))?;
        } else {
            failed += 1;
            emitter.emit_entry(case_log_entry(&res, Outcome::Fail))?;
        }
        results.push(res);
    }

    for case in matrix.required_cases.iter() {
        let mut res = run_case(
            &matrix,
            case.id.clone(),
            case.description.clone(),
            &case.family,
            &case.ctx,
        )?;
        // Apply exact required expectations (profile+action) on top of forbidden divergence rules.
        let strict_expected = parse_expected(&case.expect.strict)?;
        let hardened_expected = parse_expected(&case.expect.hardened)?;

        let strict_match = res.strict.profile == strict_expected.profile
            && res.strict.action == strict_expected.action;
        if !strict_match {
            res.violations.push(CaseViolation {
                rule_id: "required.strict_exact".to_string(),
                message: format!(
                    "strict decision mismatch: expected profile='{}' action='{}', got profile='{}' action='{}'",
                    strict_expected.profile, strict_expected.action, res.strict.profile, res.strict.action
                ),
            });
        }

        let hardened_match = res.hardened.profile == hardened_expected.profile
            && res.hardened.action == hardened_expected.action;
        if !hardened_match {
            res.violations.push(CaseViolation {
                rule_id: "required.hardened_exact".to_string(),
                message: format!(
                    "hardened decision mismatch: expected profile='{}' action='{}', got profile='{}' action='{}'",
                    hardened_expected.profile, hardened_expected.action, res.hardened.profile, res.hardened.action
                ),
            });
        }

        res.ok = res.violations.is_empty();
        violations += res.violations.len();
        if res.ok {
            passed += 1;
            emitter.emit_entry(case_log_entry(&res, Outcome::Pass))?;
        } else {
            failed += 1;
            emitter.emit_entry(case_log_entry(&res, Outcome::Fail))?;
        }
        results.push(res);
    }

    emitter.flush()?;

    let report = RuntimeMathDivergenceBoundsReport {
        schema_version: "v1",
        bead: BEAD_ID,
        generated_at: LogEntry::new("bd-2625::gen::000", LogLevel::Info, "generated").timestamp,
        sources: RuntimeMathDivergenceBoundsSources {
            matrix: rel_path(workspace_root, &matrix_path),
            runtime_math_mod_rs: rel_path(workspace_root, &mod_rs_path),
            log_path: rel_path(workspace_root, log_path),
            report_path: rel_path(workspace_root, report_path),
        },
        matrix_schema_version: matrix.schema_version,
        matrix_generated_at: matrix.generated_at,
        summary: RuntimeMathDivergenceBoundsSummary {
            total_cases: matrix.evaluation_cases.len() + matrix.required_cases.len(),
            required_cases: matrix.required_cases.len(),
            passed,
            failed,
            violations,
        },
        results,
    };

    std::fs::write(report_path, serde_json::to_string_pretty(&report)?)?;
    Ok(report)
}

fn run_case(
    matrix: &DivergenceBoundsMatrix,
    case_id: String,
    description: String,
    family: &str,
    ctx: &DivergenceCtx,
) -> Result<RuntimeMathDivergenceCaseResult, Box<dyn std::error::Error>> {
    let api_family = parse_family(family)?;
    let ctx_runtime = RuntimeContext {
        family: api_family,
        addr_hint: ctx.addr_hint,
        requested_bytes: ctx.requested_bytes,
        is_write: ctx.is_write,
        contention_hint: ctx.contention_hint,
        bloom_negative: ctx.bloom_negative,
    };

    let strict_kernel = RuntimeMathKernel::new_for_mode(SafetyLevel::Strict);
    let hardened_kernel = RuntimeMathKernel::new_for_mode(SafetyLevel::Hardened);

    let strict_decision = strict_kernel.decide(SafetyLevel::Strict, ctx_runtime);
    let hardened_decision = hardened_kernel.decide(SafetyLevel::Hardened, ctx_runtime);

    let strict = DecisionSummary {
        profile: profile_string(strict_decision.profile),
        action: action_string(strict_decision.action),
        policy_id: strict_decision.policy_id,
        risk_upper_bound_ppm: strict_decision.risk_upper_bound_ppm,
    };
    let hardened = DecisionSummary {
        profile: profile_string(hardened_decision.profile),
        action: action_string(hardened_decision.action),
        policy_id: hardened_decision.policy_id,
        risk_upper_bound_ppm: hardened_decision.risk_upper_bound_ppm,
    };

    let mut violations = Vec::new();
    for rule in &matrix.forbidden_divergences {
        // Treat empty descriptions as config errors; descriptions are part of the self-documenting contract.
        if rule.description.trim().is_empty() {
            violations.push(CaseViolation {
                rule_id: "matrix.rule_missing_description".to_string(),
                message: format!(
                    "forbidden_divergences rule '{}' is missing a description",
                    rule.id
                ),
            });
            continue;
        }
        if let Some(msg) = check_forbidden_rule(&rule.id, &strict, &hardened) {
            violations.push(CaseViolation {
                rule_id: rule.id.clone(),
                message: msg,
            });
        }
    }

    let ok = violations.is_empty();
    Ok(RuntimeMathDivergenceCaseResult {
        case_id,
        description,
        family: family.to_string(),
        ctx: DivergenceCtx {
            addr_hint: ctx.addr_hint,
            requested_bytes: ctx.requested_bytes,
            is_write: ctx.is_write,
            contention_hint: ctx.contention_hint,
            bloom_negative: ctx.bloom_negative,
        },
        strict,
        hardened,
        violations,
        ok,
    })
}

fn case_log_entry(res: &RuntimeMathDivergenceCaseResult, outcome: Outcome) -> LogEntry {
    LogEntry::new("", LogLevel::Info, "runtime_math.divergence_bounds.case")
        .with_stream(StreamKind::Unit)
        .with_gate(GATE)
        .with_outcome(outcome)
        .with_controller_id("divergence_bounds")
        .with_details(serde_json::json!({
            "case_id": res.case_id,
            "description": res.description,
            "mode_pair": ["strict","hardened"],
            "api_family": res.family,
            "ctx": {
                "addr_hint": res.ctx.addr_hint,
                "requested_bytes": res.ctx.requested_bytes,
                "is_write": res.ctx.is_write,
                "contention_hint": res.ctx.contention_hint,
                "bloom_negative": res.ctx.bloom_negative,
            },
            "strict": res.strict,
            "hardened": res.hardened,
            "violations": res.violations,
        }))
}

fn check_forbidden_rule(
    rule_id: &str,
    strict: &DecisionSummary,
    hardened: &DecisionSummary,
) -> Option<String> {
    match rule_id {
        "hardened_profile_less_conservative" => {
            if strict.profile == "full" && hardened.profile == "fast" {
                return Some(
                    "hardened selected Fast profile while strict selected Full".to_string(),
                );
            }
        }
        "hardened_denies_when_strict_allows" => {
            if strict.action == "allow" && hardened.action == "deny" {
                return Some("hardened Deny while strict Allow".to_string());
            }
        }
        "hardened_allows_when_strict_fullvalidates" => {
            if strict.action == "full_validate" && hardened.action == "allow" {
                return Some("hardened Allow while strict FullValidate".to_string());
            }
        }
        _ => {
            // Unknown rules are treated as configuration errors (fail loud).
            return Some(format!("unknown forbidden divergence rule id '{rule_id}'"));
        }
    }
    None
}

struct ParsedExpected {
    profile: String,
    action: String,
}

fn parse_expected(exp: &ExpectedDecision) -> Result<ParsedExpected, Box<dyn std::error::Error>> {
    let profile = match exp.profile.as_str() {
        "fast" | "Fast" => "fast".to_string(),
        "full" | "Full" => "full".to_string(),
        other => {
            return Err(
                std::io::Error::other(format!("unknown expected profile '{other}'")).into(),
            );
        }
    };
    // We validate the action string syntax; mapping is performed by comparison
    // to the normalized decision surface strings.
    let action = match exp.action.as_str() {
        "allow" | "full_validate" | "deny" => exp.action.clone(),
        a if a.starts_with("repair:") => exp.action.clone(),
        other => {
            return Err(std::io::Error::other(format!("unknown expected action '{other}'")).into());
        }
    };
    Ok(ParsedExpected { profile, action })
}

fn parse_family(family: &str) -> Result<ApiFamily, Box<dyn std::error::Error>> {
    Ok(match family {
        "pointer_validation" => ApiFamily::PointerValidation,
        "allocator" => ApiFamily::Allocator,
        "string_memory" => ApiFamily::StringMemory,
        "stdio" => ApiFamily::Stdio,
        "threading" => ApiFamily::Threading,
        "resolver" => ApiFamily::Resolver,
        "math_fenv" => ApiFamily::MathFenv,
        "loader" => ApiFamily::Loader,
        "stdlib" => ApiFamily::Stdlib,
        "ctype" => ApiFamily::Ctype,
        "time" => ApiFamily::Time,
        "signal" => ApiFamily::Signal,
        "io_fd" => ApiFamily::IoFd,
        "socket" => ApiFamily::Socket,
        "locale" => ApiFamily::Locale,
        "termios" => ApiFamily::Termios,
        "inet" => ApiFamily::Inet,
        "process" => ApiFamily::Process,
        "virtual_memory" => ApiFamily::VirtualMemory,
        "poll" => ApiFamily::Poll,
        other => return Err(std::io::Error::other(format!("unknown api family '{other}'")).into()),
    })
}

fn profile_string(profile: ValidationProfile) -> String {
    match profile {
        ValidationProfile::Fast => "fast".to_string(),
        ValidationProfile::Full => "full".to_string(),
    }
}

fn action_string(action: MembraneAction) -> String {
    match action {
        MembraneAction::Allow => "allow".to_string(),
        MembraneAction::FullValidate => "full_validate".to_string(),
        MembraneAction::Deny => "deny".to_string(),
        MembraneAction::Repair(heal) => format!("repair:{}", healing_action_id(heal)),
    }
}

fn healing_action_id(action: HealingAction) -> &'static str {
    match action {
        HealingAction::ClampSize { .. } => "clamp_size",
        HealingAction::TruncateWithNull { .. } => "truncate_with_null",
        HealingAction::IgnoreDoubleFree => "ignore_double_free",
        HealingAction::IgnoreForeignFree => "ignore_foreign_free",
        HealingAction::ReallocAsMalloc { .. } => "realloc_as_malloc",
        HealingAction::ReturnSafeDefault => "return_safe_default",
        HealingAction::UpgradeToSafeVariant => "upgrade_to_safe_variant",
        HealingAction::None => "none",
    }
}

fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}
