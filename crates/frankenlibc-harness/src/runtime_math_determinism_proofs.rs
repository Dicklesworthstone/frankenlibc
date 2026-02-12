//! Runtime-math determinism + invariant regression proof gate.
//!
//! Bead: `bd-1fk1`
//!
//! Goal:
//! - Provide deterministic, integration-level regression tests for the runtime_math
//!   decision law and observe pipeline.
//! - Catch nondeterminism (sampling drift, ordering instability) and basic invariant
//!   violations (NaN/Inf, ppm bounds, monotone counters) before integration.
//!
//! This gate is intentionally deterministic:
//! - No timestamps in decisions; deterministic RNG drives inputs.
//! - Two fresh kernels are driven identically and must match exactly.

use crate::structured_log::{LogEmitter, LogEntry, LogLevel, Outcome, StreamKind};
use frankenlibc_membrane::runtime_math::RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION;
use frankenlibc_membrane::{
    ApiFamily, MembraneAction, RuntimeContext, RuntimeMathKernel, SafetyLevel,
};
use serde::Serialize;
use std::path::Path;

const BEAD_ID: &str = "bd-1fk1";
const GATE: &str = "runtime_math_determinism_proofs";
const RUN_ID: &str = "rtm-determinism-proofs";

const SEED: u64 = 0xDEAD_BEEF;
const STEPS: u32 = 512;

const SCENARIO_FAMILIES: &[ApiFamily] = &[
    ApiFamily::PointerValidation,
    ApiFamily::Allocator,
    ApiFamily::StringMemory,
    ApiFamily::Threading,
    ApiFamily::Socket,
    ApiFamily::Inet,
    ApiFamily::Time,
];

#[derive(Debug, Serialize)]
pub struct RuntimeMathDeterminismProofSummary {
    pub modes: usize,
    pub passed: usize,
    pub failed: usize,
}

#[derive(Debug, Serialize)]
pub struct InvariantCheckResult {
    pub invariant_id: String,
    pub ok: bool,
    pub before: serde_json::Value,
    pub after: serde_json::Value,
    pub failures: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RuntimeMathModeDeterminismResult {
    pub mode: String,
    pub seed: u64,
    pub steps: u32,
    pub initial_snapshot_equal: bool,
    pub decision_mismatches: u32,
    pub ordering_mismatches: u32,
    pub final_snapshot_equal: bool,
    pub invariant_checks: Vec<InvariantCheckResult>,
    pub failures: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RuntimeMathDeterminismProofReport {
    pub schema_version: &'static str,
    pub bead: &'static str,
    pub generated_at: String,
    pub sources: RuntimeMathDeterminismProofSources,
    pub summary: RuntimeMathDeterminismProofSummary,
    pub modes: Vec<RuntimeMathModeDeterminismResult>,
}

#[derive(Debug, Serialize)]
pub struct RuntimeMathDeterminismProofSources {
    pub runtime_math_mod_rs: String,
    pub log_path: String,
    pub report_path: String,
}

pub fn run_and_write(
    workspace_root: &Path,
    log_path: &Path,
    report_path: &Path,
) -> Result<RuntimeMathDeterminismProofReport, Box<dyn std::error::Error>> {
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

    let mut emitter = LogEmitter::to_file(log_path, BEAD_ID, RUN_ID)?;

    let mut results = Vec::new();
    let mut passed = 0usize;
    let mut failed = 0usize;

    for mode in [SafetyLevel::Strict, SafetyLevel::Hardened] {
        let res = run_mode(&mut emitter, mode, SEED, STEPS)?;
        if res.failures.is_empty() {
            passed += 1;
        } else {
            failed += 1;
        }
        results.push(res);
    }

    emitter.flush()?;

    let report = RuntimeMathDeterminismProofReport {
        schema_version: "v1",
        bead: BEAD_ID,
        generated_at: LogEntry::new("bd-1fk1::gen::000", LogLevel::Info, "generated").timestamp,
        sources: RuntimeMathDeterminismProofSources {
            runtime_math_mod_rs: rel_path(workspace_root, &mod_rs_path),
            log_path: rel_path(workspace_root, log_path),
            report_path: rel_path(workspace_root, report_path),
        },
        summary: RuntimeMathDeterminismProofSummary {
            modes: 2,
            passed,
            failed,
        },
        modes: results,
    };

    std::fs::write(report_path, serde_json::to_string_pretty(&report)?)?;
    Ok(report)
}

fn run_mode(
    emitter: &mut LogEmitter,
    mode: SafetyLevel,
    seed: u64,
    steps: u32,
) -> Result<RuntimeMathModeDeterminismResult, Box<dyn std::error::Error>> {
    let mode_str = match mode {
        SafetyLevel::Strict => "strict",
        SafetyLevel::Hardened => "hardened",
        SafetyLevel::Off => "off",
    }
    .to_string();

    let mut failures = Vec::new();

    let k1 = RuntimeMathKernel::new_for_mode(mode);
    let k2 = RuntimeMathKernel::new_for_mode(mode);

    let snap1_before = k1.snapshot(mode);
    let snap2_before = k2.snapshot(mode);
    let initial_snapshot_equal = snap1_before == snap2_before;
    if !initial_snapshot_equal {
        failures.push("initial snapshot mismatch between two fresh kernels".to_string());
    }

    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "runtime_math.determinism.mode_start")
            .with_stream(StreamKind::Unit)
            .with_gate(GATE)
            .with_mode(mode_str.clone())
            .with_outcome(Outcome::Pass)
            .with_controller_id("mode_start")
            .with_details(serde_json::json!({
                "seed": seed,
                "steps": steps,
            })),
    )?;

    let mut decision_mismatches = 0u32;
    let mut ordering_mismatches = 0u32;

    let mode_tag = match mode {
        SafetyLevel::Strict => 1u64,
        SafetyLevel::Hardened => 2u64,
        SafetyLevel::Off => 3u64,
    };
    let mut rng = seed ^ mode_tag;

    for i in 0..steps {
        let family = SCENARIO_FAMILIES[(i as usize) % SCENARIO_FAMILIES.len()];
        let r = next_u64(&mut rng);

        let ctx = RuntimeContext {
            family,
            addr_hint: (r as usize) & !0xfff,
            requested_bytes: ((r >> 16) as usize) & 0x3fff,
            is_write: (r & 1) == 0,
            contention_hint: ((r >> 32) as u16) & 0x03ff,
            bloom_negative: (r & 0x10) != 0,
        };

        let d1 = k1.decide(mode, ctx);
        let d2 = k2.decide(mode, ctx);
        if d1 != d2 {
            decision_mismatches += 1;
            failures.push(format!("decision mismatch at step {i}: {d1:?} != {d2:?}"));
            emitter.emit_entry(
                LogEntry::new("", LogLevel::Error, "runtime_math.determinism.decision_mismatch")
                    .with_stream(StreamKind::Unit)
                    .with_gate(GATE)
                    .with_mode(mode_str.clone())
                    .with_outcome(Outcome::Fail)
                    .with_controller_id("decision_law")
                    .with_details(serde_json::json!({
                        "step": i,
                        "ctx": {
                            "family": format!("{family:?}"),
                            "addr_hint": ctx.addr_hint,
                            "requested_bytes": ctx.requested_bytes,
                            "is_write": ctx.is_write,
                            "contention_hint": ctx.contention_hint,
                            "bloom_negative": ctx.bloom_negative,
                        },
                        "left": format!("{d1:?}"),
                        "right": format!("{d2:?}"),
                    })),
            )?;
            break;
        }

        // Deterministically exercise contextual check oracle wiring.
        let aligned = (ctx.addr_hint & 0x7) == 0;
        let recent_page = !ctx.bloom_negative;
        let o1 = k1.check_ordering(family, aligned, recent_page);
        let o2 = k2.check_ordering(family, aligned, recent_page);
        if o1 != o2 {
            ordering_mismatches += 1;
            failures.push(format!("check ordering mismatch at step {i}: {o1:?} != {o2:?}"));
        }
        let exit_stage = if i % 13 == 0 { Some((i as usize) % 4) } else { None };
        k1.note_check_order_outcome(mode, family, aligned, recent_page, &o1, exit_stage);
        k2.note_check_order_outcome(mode, family, aligned, recent_page, &o2, exit_stage);

        let estimated_cost_ns = if d1.profile.requires_full() { 120 } else { 12 };
        let adverse = matches!(d1.action, MembraneAction::Repair(_) | MembraneAction::Deny);
        k1.observe_validation_result(mode, ctx.family, d1.profile, estimated_cost_ns, adverse);
        k2.observe_validation_result(mode, ctx.family, d2.profile, estimated_cost_ns, adverse);

        // Deterministically exercise overlap-consistency monitoring.
        if i % 17 == 0 {
            let left = (r as usize) & 0x0f;
            let right = ((r >> 8) as usize) & 0x0f;
            let witness = next_u64(&mut rng);
            let _ = k1.note_overlap(left, right, witness);
            let _ = k2.note_overlap(left, right, witness);
        }
    }

    let snap1_after = k1.snapshot(mode);
    let snap2_after = k2.snapshot(mode);
    let final_snapshot_equal = snap1_after == snap2_after;
    if !final_snapshot_equal {
        failures.push("final snapshot mismatch between identically-driven kernels".to_string());
    }

    let mut invariant_checks = Vec::new();
    invariant_checks.extend(check_snapshot_invariants(&snap1_before, &snap1_after));

    for check in &invariant_checks {
        emitter.emit_entry(
            LogEntry::new("", LogLevel::Info, "runtime_math.invariant_check")
                .with_stream(StreamKind::Unit)
                .with_gate(GATE)
                .with_mode(mode_str.clone())
                .with_outcome(if check.ok { Outcome::Pass } else { Outcome::Fail })
                .with_controller_id(check.invariant_id.clone())
                .with_details(serde_json::json!({
                    "state_before": check.before,
                    "state_after": check.after,
                    "invariant_result": if check.ok { "pass" } else { "fail" },
                    "failures": check.failures,
                })),
        )?;
        if !check.ok {
            failures.push(format!("invariant failed: {}", check.invariant_id));
        }
    }

    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "runtime_math.determinism.mode_finish")
            .with_stream(StreamKind::Unit)
            .with_gate(GATE)
            .with_mode(mode_str.clone())
            .with_outcome(if failures.is_empty() {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_controller_id("mode_finish")
            .with_details(serde_json::json!({
                "initial_snapshot_equal": initial_snapshot_equal,
                "decision_mismatches": decision_mismatches,
                "ordering_mismatches": ordering_mismatches,
                "final_snapshot_equal": final_snapshot_equal,
                "failure_count": failures.len(),
            })),
    )?;

    Ok(RuntimeMathModeDeterminismResult {
        mode: mode_str,
        seed,
        steps,
        initial_snapshot_equal,
        decision_mismatches,
        ordering_mismatches,
        final_snapshot_equal,
        invariant_checks,
        failures,
    })
}

fn check_snapshot_invariants(
    before: &frankenlibc_membrane::runtime_math::RuntimeKernelSnapshot,
    after: &frankenlibc_membrane::runtime_math::RuntimeKernelSnapshot,
) -> Vec<InvariantCheckResult> {
    let mut out = Vec::new();

    // Schema invariants.
    {
        let ok = after.schema_version == RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION;
        out.push(InvariantCheckResult {
            invariant_id: "snapshot.schema_version_matches_constant".to_string(),
            ok,
            before: serde_json::json!({"schema_version": before.schema_version}),
            after: serde_json::json!({"schema_version": after.schema_version}),
            failures: if ok {
                Vec::new()
            } else {
                vec![format!(
                    "schema_version mismatch: expected {expected} got {got}",
                    expected = RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION,
                    got = after.schema_version
                )]
            },
        });
    }

    // Monotone counters.
    {
        let ok = after.decisions >= before.decisions;
        out.push(InvariantCheckResult {
            invariant_id: "snapshot.decisions_monotone".to_string(),
            ok,
            before: serde_json::json!({"decisions": before.decisions}),
            after: serde_json::json!({"decisions": after.decisions}),
            failures: if ok {
                Vec::new()
            } else {
                vec![format!(
                    "decisions not monotone: before={} after={}",
                    before.decisions, after.decisions
                )]
            },
        });
    }
    {
        let ok = after.evidence_seqno >= before.evidence_seqno;
        out.push(InvariantCheckResult {
            invariant_id: "snapshot.evidence_seqno_monotone".to_string(),
            ok,
            before: serde_json::json!({"evidence_seqno": before.evidence_seqno}),
            after: serde_json::json!({"evidence_seqno": after.evidence_seqno}),
            failures: if ok {
                Vec::new()
            } else {
                vec![format!(
                    "evidence_seqno not monotone: before={} after={}",
                    before.evidence_seqno, after.evidence_seqno
                )]
            },
        });
    }

    // PPM bounds.
    {
        let mut failures = Vec::new();
        if after.full_validation_trigger_ppm > 1_000_000 {
            failures.push(format!(
                "full_validation_trigger_ppm out of range: {}",
                after.full_validation_trigger_ppm
            ));
        }
        if after.repair_trigger_ppm > 1_000_000 {
            failures.push(format!(
                "repair_trigger_ppm out of range: {}",
                after.repair_trigger_ppm
            ));
        }
        if after.sampled_risk_bonus_ppm > 1_000_000 {
            failures.push(format!(
                "sampled_risk_bonus_ppm out of range: {}",
                after.sampled_risk_bonus_ppm
            ));
        }
        if after.loss_posterior_adverse_ppm > 1_000_000 {
            failures.push(format!(
                "loss_posterior_adverse_ppm out of range: {}",
                after.loss_posterior_adverse_ppm
            ));
        }
        if after.loss_recommended_action > 3 {
            failures.push(format!(
                "loss_recommended_action out of range: {}",
                after.loss_recommended_action
            ));
        }
        if after.loss_competing_action > 3 {
            failures.push(format!(
                "loss_competing_action out of range: {}",
                after.loss_competing_action
            ));
        }
        let ok = failures.is_empty();
        out.push(InvariantCheckResult {
            invariant_id: "snapshot.ppm_and_action_bounds".to_string(),
            ok,
            before: serde_json::json!({
                "full_validation_trigger_ppm": before.full_validation_trigger_ppm,
                "repair_trigger_ppm": before.repair_trigger_ppm,
                "sampled_risk_bonus_ppm": before.sampled_risk_bonus_ppm,
                "loss_posterior_adverse_ppm": before.loss_posterior_adverse_ppm,
                "loss_recommended_action": before.loss_recommended_action,
                "loss_competing_action": before.loss_competing_action,
            }),
            after: serde_json::json!({
                "full_validation_trigger_ppm": after.full_validation_trigger_ppm,
                "repair_trigger_ppm": after.repair_trigger_ppm,
                "sampled_risk_bonus_ppm": after.sampled_risk_bonus_ppm,
                "loss_posterior_adverse_ppm": after.loss_posterior_adverse_ppm,
                "loss_recommended_action": after.loss_recommended_action,
                "loss_competing_action": after.loss_competing_action,
            }),
            failures,
        });
    }

    // All f64 fields in RuntimeKernelSnapshot must remain finite (no NaN/Inf).
    {
        let mut bad = Vec::new();
        let mut check = |name: &str, v: f64| {
            if !v.is_finite() {
                bad.push(format!("{name} is not finite: {v}"));
            }
        };

        check("spectral_edge_ratio", after.spectral_edge_ratio);
        check("signature_anomaly_score", after.signature_anomaly_score);
        check("persistence_entropy", after.persistence_entropy);
        check("anytime_max_e_value", after.anytime_max_e_value);
        check("bridge_transport_distance", after.bridge_transport_distance);
        check("hji_safety_value", after.hji_safety_value);
        check("mfg_mean_contention", after.mfg_mean_contention);
        check("padic_ultrametric_distance", after.padic_ultrametric_distance);
        check("symplectic_energy", after.symplectic_energy);
        check("topos_violation_rate", after.topos_violation_rate);
        check("audit_martingale_value", after.audit_martingale_value);
        check("changepoint_posterior_short_mass", after.changepoint_posterior_short_mass);
        check("conformal_empirical_coverage", after.conformal_empirical_coverage);
        check("sparse_l1_energy", after.sparse_l1_energy);
        check("sparse_residual_ewma", after.sparse_residual_ewma);
        check("microlocal_failure_rate", after.microlocal_failure_rate);
        check("serre_max_differential", after.serre_max_differential);
        check("clifford_grade2_energy", after.clifford_grade2_energy);
        check("clifford_parity_imbalance", after.clifford_parity_imbalance);
        check(
            "ktheory_max_transport_distance",
            after.ktheory_max_transport_distance,
        );
        check("covering_coverage_fraction", after.covering_coverage_fraction);
        check("tstructure_max_violation_rate", after.tstructure_max_violation_rate);
        check("atiyah_bott_euler_weight", after.atiyah_bott_euler_weight);
        check("pomdp_optimality_gap", after.pomdp_optimality_gap);
        check("sos_max_stress", after.sos_max_stress);
        check("admm_primal_dual_gap", after.admm_primal_dual_gap);
        check("obstruction_norm", after.obstruction_norm);
        check("operator_norm_spectral_radius", after.operator_norm_spectral_radius);
        check("provenance_shannon_entropy", after.provenance_shannon_entropy);
        check("provenance_renyi_h2", after.provenance_renyi_h2);
        check("grobner_violation_rate", after.grobner_violation_rate);
        check("grothendieck_violation_rate", after.grothendieck_violation_rate);
        check("malliavin_sensitivity_norm", after.malliavin_sensitivity_norm);
        check("malliavin_fragility_index", after.malliavin_fragility_index);
        check("info_geo_geodesic_distance", after.info_geo_geodesic_distance);
        check(
            "info_geo_max_controller_distance",
            after.info_geo_max_controller_distance,
        );
        check(
            "matrix_conc_spectral_deviation",
            after.matrix_conc_spectral_deviation,
        );
        check(
            "matrix_conc_bernstein_bound",
            after.matrix_conc_bernstein_bound,
        );
        check(
            "wasserstein_aggregate_distance",
            after.wasserstein_aggregate_distance,
        );
        check(
            "wasserstein_max_controller_distance",
            after.wasserstein_max_controller_distance,
        );
        check("mmd_squared", after.mmd_squared);
        check("mmd_mean_shift_norm", after.mmd_mean_shift_norm);
        check("pac_bayes_bound", after.pac_bayes_bound);
        check("pac_bayes_kl_divergence", after.pac_bayes_kl_divergence);
        check("pac_bayes_empirical_error", after.pac_bayes_empirical_error);
        check("stein_ksd_squared", after.stein_ksd_squared);
        check("stein_max_score_deviation", after.stein_max_score_deviation);
        check("lyapunov_exponent", after.lyapunov_exponent);
        check("lyapunov_expansion_ratio", after.lyapunov_expansion_ratio);
        check("rademacher_complexity", after.rademacher_complexity);
        check("rademacher_gen_gap_bound", after.rademacher_gen_gap_bound);
        check("transfer_entropy_max_te", after.transfer_entropy_max_te);
        check("transfer_entropy_mean_te", after.transfer_entropy_mean_te);
        check("hodge_inconsistency_ratio", after.hodge_inconsistency_ratio);
        check("hodge_curl_energy", after.hodge_curl_energy);
        check("doob_drift_rate", after.doob_drift_rate);
        check("doob_max_drift", after.doob_max_drift);
        check("fano_mean_mi", after.fano_mean_mi);
        check("fano_mean_bound", after.fano_mean_bound);
        check("dobrushin_max_contraction", after.dobrushin_max_contraction);
        check("dobrushin_mean_contraction", after.dobrushin_mean_contraction);
        check("azuma_max_exceedance", after.azuma_max_exceedance);
        check("azuma_mean_exceedance", after.azuma_mean_exceedance);
        check("renewal_max_age_ratio", after.renewal_max_age_ratio);
        check("renewal_mean_time", after.renewal_mean_time);
        check("lz_max_complexity_ratio", after.lz_max_complexity_ratio);
        check("lz_mean_complexity_ratio", after.lz_mean_complexity_ratio);
        check("ito_qv_max_per_step", after.ito_qv_max_per_step);
        check("ito_qv_mean_per_step", after.ito_qv_mean_per_step);
        check("borel_cantelli_max_rate", after.borel_cantelli_max_rate);
        check("borel_cantelli_mean_rate", after.borel_cantelli_mean_rate);
        check("ou_min_theta", after.ou_min_theta);
        check("ou_mean_theta", after.ou_mean_theta);
        check("hurst_max", after.hurst_max);
        check("hurst_mean", after.hurst_mean);
        check("dispersion_max", after.dispersion_max);
        check("dispersion_mean", after.dispersion_mean);
        check("birkhoff_max_gap", after.birkhoff_max_gap);
        check("birkhoff_mean_gap", after.birkhoff_mean_gap);
        check("coupling_divergence_bound", after.coupling_divergence_bound);
        check(
            "coupling_certification_margin",
            after.coupling_certification_margin,
        );
        check("spectral_gap_max_eigenvalue", after.spectral_gap_max_eigenvalue);
        check(
            "spectral_gap_mean_eigenvalue",
            after.spectral_gap_mean_eigenvalue,
        );
        check("submodular_coverage_ratio", after.submodular_coverage_ratio);
        check(
            "bifurcation_max_sensitivity",
            after.bifurcation_max_sensitivity,
        );
        check(
            "bifurcation_mean_sensitivity",
            after.bifurcation_mean_sensitivity,
        );
        check("entropy_rate_bits", after.entropy_rate_bits);
        check("entropy_rate_ratio", after.entropy_rate_ratio);
        check(
            "alpha_investing_empirical_fdr",
            after.alpha_investing_empirical_fdr,
        );

        let ok = bad.is_empty();
        out.push(InvariantCheckResult {
            invariant_id: "snapshot.f64_fields_finite".to_string(),
            ok,
            before: serde_json::json!({}),
            after: serde_json::json!({"bad_count": bad.len()}),
            failures: bad,
        });
    }

    out
}

fn next_u64(state: &mut u64) -> u64 {
    // PCG-style LCG; deterministic and cheap.
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}
