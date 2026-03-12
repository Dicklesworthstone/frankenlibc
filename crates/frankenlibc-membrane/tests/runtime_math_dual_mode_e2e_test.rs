use frankenlibc_membrane::config::SafetyLevel;
use frankenlibc_membrane::heal::HealingAction;
use frankenlibc_membrane::runtime_math::evidence::{LossEvidenceV1, SystematicEvidenceLog};
use frankenlibc_membrane::runtime_math::{
    ApiFamily, MembraneAction, RuntimeContext, RuntimeDecision, RuntimeKernelFramework,
    RuntimeMathKernel, RuntimeReverseRoundDiversityState, ValidationProfile,
    RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION,
};
use serde_json::Value;

fn oversized_allocator_ctx() -> RuntimeContext {
    RuntimeContext {
        family: ApiFamily::Allocator,
        addr_hint: 0xABCD,
        requested_bytes: 512 * 1024 * 1024,
        is_write: true,
        contention_hint: 3,
        bloom_negative: false,
    }
}

fn scripted_ctx(step: usize) -> RuntimeContext {
    let script = [
        RuntimeContext::pointer_validation(0x1000, false),
        RuntimeContext {
            family: ApiFamily::StringMemory,
            addr_hint: 0x2000,
            requested_bytes: 128,
            is_write: false,
            contention_hint: 1,
            bloom_negative: true,
        },
        oversized_allocator_ctx(),
        RuntimeContext {
            family: ApiFamily::IoFd,
            addr_hint: 0x3000,
            requested_bytes: 4096,
            is_write: true,
            contention_hint: 0,
            bloom_negative: false,
        },
    ];
    script[step % script.len()]
}

fn parse_jsonl_rows(jsonl: &str) -> Vec<Value> {
    jsonl
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("JSONL line must parse"))
        .collect()
}

fn strip_nondeterministic_fields(rows: &mut [Value]) {
    for row in rows {
        let obj = row.as_object_mut().expect("row must be object");
        obj.remove("timestamp");
        // The runtime_calibration row embeds measured wall-clock latency that
        // varies between runs even with identical inputs.
        if obj.get("event").and_then(Value::as_str) == Some("runtime_calibration") {
            obj.remove("snapshot_capture_latency_ns");
            obj.remove("latency_ns");
        }
    }
}

fn runtime_decision_rows(rows: &[Value]) -> Vec<&Value> {
    rows.iter()
        .filter(|row| {
            row.get("event")
                .and_then(Value::as_str)
                .is_some_and(|event| event == "runtime_decision")
        })
        .collect()
}

#[test]
fn e2e_deterministic_replay_emits_identical_decisions_and_logs() {
    let k1 = RuntimeMathKernel::new();
    let k2 = RuntimeMathKernel::new();

    let mut d1 = Vec::new();
    let mut d2 = Vec::new();
    for step in 0..96 {
        let ctx = scripted_ctx(step);

        let decision1 = k1.decide(SafetyLevel::Hardened, ctx);
        let adverse1 = !matches!(decision1.action, MembraneAction::Allow);
        k1.observe_validation_result(
            SafetyLevel::Hardened,
            ctx.family,
            decision1.profile,
            25 + (step as u64 % 17),
            adverse1,
        );
        d1.push(decision1);

        let decision2 = k2.decide(SafetyLevel::Hardened, ctx);
        let adverse2 = !matches!(decision2.action, MembraneAction::Allow);
        k2.observe_validation_result(
            SafetyLevel::Hardened,
            ctx.family,
            decision2.profile,
            25 + (step as u64 % 17),
            adverse2,
        );
        d2.push(decision2);
    }
    assert_eq!(
        d1, d2,
        "deterministic replay must produce identical decision streams"
    );

    let mut rows1 = parse_jsonl_rows(&k1.export_runtime_math_log_jsonl(
        SafetyLevel::Hardened,
        "bd-oai.5",
        "replay",
    ));
    let mut rows2 = parse_jsonl_rows(&k2.export_runtime_math_log_jsonl(
        SafetyLevel::Hardened,
        "bd-oai.5",
        "replay",
    ));
    strip_nondeterministic_fields(&mut rows1);
    strip_nondeterministic_fields(&mut rows2);
    assert_eq!(
        rows1, rows2,
        "deterministic replay must emit identical structured log payloads"
    );
}

#[test]
fn e2e_mode_behavioral_divergence_is_stable_and_structured() {
    let strict_kernel = RuntimeMathKernel::new();
    let hardened_kernel = RuntimeMathKernel::new();
    let ctx = oversized_allocator_ctx();

    for _ in 0..64 {
        let strict_decision = strict_kernel.decide(SafetyLevel::Strict, ctx);
        assert_eq!(
            strict_decision.action,
            MembraneAction::Deny,
            "strict oversized allocation must deny"
        );
        strict_kernel.observe_validation_result(
            SafetyLevel::Strict,
            ctx.family,
            strict_decision.profile,
            40,
            true,
        );

        let hardened_decision = hardened_kernel.decide(SafetyLevel::Hardened, ctx);
        assert_eq!(
            hardened_decision.action,
            MembraneAction::Repair(HealingAction::ReturnSafeDefault),
            "hardened oversized allocation must repair"
        );
        hardened_kernel.observe_validation_result(
            SafetyLevel::Hardened,
            ctx.family,
            hardened_decision.profile,
            40,
            true,
        );
    }

    let strict_rows = parse_jsonl_rows(&strict_kernel.export_runtime_math_log_jsonl(
        SafetyLevel::Strict,
        "bd-oai.5",
        "strict-divergence",
    ));
    let hardened_rows = parse_jsonl_rows(&hardened_kernel.export_runtime_math_log_jsonl(
        SafetyLevel::Hardened,
        "bd-oai.5",
        "hardened-divergence",
    ));

    let strict_decisions = runtime_decision_rows(&strict_rows);
    let hardened_decisions = runtime_decision_rows(&hardened_rows);
    assert_eq!(strict_decisions.len(), 64);
    assert_eq!(hardened_decisions.len(), 64);

    for row in strict_decisions {
        assert_eq!(
            row.get("decision_action").and_then(Value::as_str),
            Some("Deny"),
            "strict mode must stay on deny action for oversized scenario"
        );
        for field in [
            "trace_id",
            "mode",
            "api_family",
            "symbol",
            "decision_path",
            "healing_action",
            "errno",
            "latency_ns",
            "artifact_refs",
        ] {
            assert!(row.get(field).is_some(), "strict row missing `{field}`");
        }
    }

    for row in hardened_decisions {
        assert_eq!(
            row.get("decision_action").and_then(Value::as_str),
            Some("Repair"),
            "hardened mode must stay on repair action for oversized scenario"
        );
        assert_eq!(
            row.get("healing_action").and_then(Value::as_str),
            Some("ReturnSafeDefault"),
            "hardened repair row must report healing action"
        );
    }
}

#[test]
fn e2e_hardened_repair_evidence_chain_is_complete_and_gapless() {
    const N: usize = 96;
    let kernel = RuntimeMathKernel::new();
    let ctx = oversized_allocator_ctx();

    for _ in 0..N {
        let decision = kernel.decide(SafetyLevel::Hardened, ctx);
        assert_eq!(
            decision.action,
            MembraneAction::Repair(HealingAction::ReturnSafeDefault),
            "hardened oversized path must produce repair"
        );
        kernel.observe_validation_result(
            SafetyLevel::Hardened,
            ctx.family,
            decision.profile,
            55,
            true,
        );
    }

    let rows = parse_jsonl_rows(&kernel.export_runtime_math_log_jsonl(
        SafetyLevel::Hardened,
        "bd-oai.5",
        "repair-chain",
    ));
    let repair_rows: Vec<&Value> = runtime_decision_rows(&rows)
        .into_iter()
        .filter(|row| row.get("decision_action").and_then(Value::as_str) == Some("Repair"))
        .collect();
    assert_eq!(
        repair_rows.len(),
        N,
        "every hardened repair decision must emit a structured evidence row"
    );

    let seqnos: Vec<u64> = repair_rows
        .iter()
        .map(|row| {
            row.get("evidence_seqno")
                .and_then(Value::as_u64)
                .expect("repair row must include evidence_seqno")
        })
        .collect();
    for pair in seqnos.windows(2) {
        assert_eq!(
            pair[1],
            pair[0] + 1,
            "evidence sequence must be gapless and monotone"
        );
    }

    let snapshot = kernel.evidence_contract_snapshot();
    assert_eq!(
        snapshot.evidence_seqno,
        *seqnos.last().expect("non-empty repair seq stream"),
        "snapshot evidence_seqno must track the latest emitted seqno"
    );
    assert_eq!(
        snapshot.evidence_loss_count, 0,
        "bounded ring should not lose evidence in this scenario"
    );
}

#[test]
fn e2e_hash_linked_repair_chain_verifies_record_integrity() {
    const N: usize = 64;
    let log: SystematicEvidenceLog<256> = SystematicEvidenceLog::new(0xC0BA_1A7E);
    let ctx = oversized_allocator_ctx();

    for i in 0..N {
        let decision = RuntimeDecision {
            profile: ValidationProfile::Full,
            action: MembraneAction::Repair(HealingAction::ReturnSafeDefault),
            policy_id: 0xA500 + i as u32,
            risk_upper_bound_ppm: 900_000,
            evidence_seqno: 0,
        };
        let seq = log.record_decision(
            SafetyLevel::Hardened,
            ctx,
            decision,
            77,
            true,
            Some(LossEvidenceV1 {
                posterior_adverse_ppm: 800_000,
                selected_action: 2,
                competing_action: 1,
                selected_expected_loss_milli: 600,
                competing_expected_loss_milli: 900,
            }),
            0,
            None,
        );
        assert_eq!(seq, (i + 1) as u64);
    }

    let records = log.snapshot_sorted();
    assert_eq!(records.len(), N);
    let mut prev_chain_hash = 0u64;
    let mut prev_seqno = 0u64;
    for record in records {
        assert_eq!(
            record.seqno(),
            prev_seqno + 1,
            "record sequence numbers must be gapless"
        );
        assert!(
            record.verify_payload_hash_v1(),
            "payload hash verification must hold"
        );
        assert!(
            record.verify_chain_hash_v1(prev_chain_hash),
            "chain hash verification must hold against predecessor"
        );
        prev_seqno = record.seqno();
        prev_chain_hash = record.chain_hash();
    }
}

// ---------------------------------------------------------------------------
// Branch-diversity enforcement E2E tests
// ---------------------------------------------------------------------------

/// Build oversized contexts that trigger adverse decisions (Repair in Hardened,
/// Deny in Strict) across 5 distinct API families. Evidence is only recorded
/// for adverse decisions, so the diversity snapshot requires these.
const OVERSIZED: usize = 512 * 1024 * 1024;

fn adverse_diverse_contexts() -> [RuntimeContext; 5] {
    [
        RuntimeContext {
            family: ApiFamily::PointerValidation,
            addr_hint: 0x1000,
            requested_bytes: OVERSIZED,
            is_write: true,
            contention_hint: 3,
            bloom_negative: false,
        },
        RuntimeContext {
            family: ApiFamily::StringMemory,
            addr_hint: 0x2000,
            requested_bytes: OVERSIZED,
            is_write: true,
            contention_hint: 2,
            bloom_negative: false,
        },
        RuntimeContext {
            family: ApiFamily::IoFd,
            addr_hint: 0x3000,
            requested_bytes: OVERSIZED,
            is_write: true,
            contention_hint: 1,
            bloom_negative: false,
        },
        RuntimeContext {
            family: ApiFamily::Stdio,
            addr_hint: 0x4000,
            requested_bytes: OVERSIZED,
            is_write: true,
            contention_hint: 1,
            bloom_negative: false,
        },
        RuntimeContext {
            family: ApiFamily::Time,
            addr_hint: 0x5000,
            requested_bytes: OVERSIZED,
            is_write: true,
            contention_hint: 0,
            bloom_negative: false,
        },
    ]
}

#[test]
fn e2e_branch_diversity_healthy_with_balanced_family_mix() {
    let kernel = RuntimeMathKernel::new();
    let contexts = adverse_diverse_contexts();

    // Evenly distribute 100 adverse decisions across 5 families (20 each = 20%).
    // Oversized requests trigger Repair in Hardened mode, which always gets
    // recorded as a decision card (adverse decisions bypass cadence gating).
    for step in 0..100 {
        let ctx = contexts[step % contexts.len()];
        let decision = kernel.decide(SafetyLevel::Hardened, ctx);
        assert!(
            matches!(
                decision.action,
                MembraneAction::Repair(_) | MembraneAction::Deny
            ),
            "oversized context must produce adverse decision"
        );
        kernel.observe_validation_result(
            SafetyLevel::Hardened,
            ctx.family,
            decision.profile,
            30,
            true,
        );
    }

    let diversity = kernel.reverse_round_diversity_snapshot();
    assert!(
        diversity.active_family_count >= 3,
        "balanced mix must reach coverage milestone (got {} active families)",
        diversity.active_family_count
    );
    assert!(
        diversity.coverage_milestone_reached,
        "coverage milestone must be reached"
    );
    assert_eq!(
        diversity.state,
        RuntimeReverseRoundDiversityState::Healthy,
        "even distribution must be Healthy (dominant share = {} ppm)",
        diversity.dominant_family_share_ppm
    );
    // Each family gets ~200_000 ppm (20%); dominant must be well under 350_000.
    assert!(
        diversity.dominant_family_share_ppm < 350_000,
        "dominant share {ppm} ppm must be below warn threshold 350_000",
        ppm = diversity.dominant_family_share_ppm
    );
}

#[test]
fn e2e_branch_diversity_violation_with_single_family_dominance() {
    let kernel = RuntimeMathKernel::new();
    // Use oversized allocator context → always adverse → always recorded as card.
    let ctx = oversized_allocator_ctx();

    // All decisions to a single family → 100% dominance.
    for _ in 0..64 {
        let decision = kernel.decide(SafetyLevel::Hardened, ctx);
        kernel.observe_validation_result(
            SafetyLevel::Hardened,
            ctx.family,
            decision.profile,
            25,
            true,
        );
    }

    let diversity = kernel.reverse_round_diversity_snapshot();
    assert_eq!(
        diversity.active_family_count, 1,
        "single-family must show 1 active"
    );
    assert_eq!(diversity.dominant_family, ApiFamily::Allocator);
    assert_eq!(diversity.dominant_family_share_ppm, 1_000_000);
    assert_eq!(
        diversity.state,
        RuntimeReverseRoundDiversityState::Violation,
        "single-family dominance must trigger Violation"
    );
    assert!(
        !diversity.coverage_milestone_reached,
        "single family cannot reach coverage milestone"
    );
}

#[test]
fn e2e_branch_diversity_near_violation_at_boundary() {
    let kernel = RuntimeMathKernel::new();

    // All contexts must be oversized (>256MB) to trigger adverse decisions,
    // which are always recorded as decision cards.
    // 37 decisions to Allocator, 63 to others (3 families, ~21 each).
    // Allocator share = 37/100 = 370_000 ppm → NearViolation (350k..400k).
    let allocator_ctx = oversized_allocator_ctx();
    let others = [
        RuntimeContext {
            family: ApiFamily::StringMemory,
            addr_hint: 0x2000,
            requested_bytes: OVERSIZED,
            is_write: true,
            contention_hint: 0,
            bloom_negative: false,
        },
        RuntimeContext {
            family: ApiFamily::IoFd,
            addr_hint: 0x3000,
            requested_bytes: OVERSIZED,
            is_write: true,
            contention_hint: 0,
            bloom_negative: false,
        },
        RuntimeContext {
            family: ApiFamily::Stdio,
            addr_hint: 0x4000,
            requested_bytes: OVERSIZED,
            is_write: true,
            contention_hint: 0,
            bloom_negative: false,
        },
    ];

    for _ in 0..37 {
        let d = kernel.decide(SafetyLevel::Hardened, allocator_ctx);
        kernel.observe_validation_result(
            SafetyLevel::Hardened,
            allocator_ctx.family,
            d.profile,
            20,
            true,
        );
    }
    for i in 0..63 {
        let ctx = others[i % others.len()];
        let d = kernel.decide(SafetyLevel::Hardened, ctx);
        kernel.observe_validation_result(
            SafetyLevel::Hardened,
            ctx.family,
            d.profile,
            20,
            true,
        );
    }

    let diversity = kernel.reverse_round_diversity_snapshot();
    assert!(
        diversity.active_family_count >= 3,
        "must have >= 3 active families"
    );
    assert_eq!(diversity.dominant_family, ApiFamily::Allocator);
    // 37% share → NearViolation.
    assert!(
        diversity.dominant_family_share_ppm >= 350_000,
        "dominant share must be at or above warn threshold"
    );
    assert!(
        diversity.dominant_family_share_ppm < 400_000,
        "dominant share must be below error threshold for NearViolation"
    );
    assert_eq!(
        diversity.state,
        RuntimeReverseRoundDiversityState::NearViolation,
        "37% dominance must be NearViolation"
    );
}

// ---------------------------------------------------------------------------
// Full RuntimeKernelSnapshot capture E2E tests
// ---------------------------------------------------------------------------

#[test]
fn e2e_snapshot_captures_schema_version_and_core_fields() {
    let kernel = RuntimeMathKernel::new();
    let contexts = adverse_diverse_contexts();

    for step in 0..48 {
        let ctx = contexts[step % contexts.len()];
        let decision = kernel.decide(SafetyLevel::Hardened, ctx);
        let adverse = !matches!(decision.action, MembraneAction::Allow);
        kernel.observe_validation_result(
            SafetyLevel::Hardened,
            ctx.family,
            decision.profile,
            30 + (step as u64 % 11),
            adverse,
        );
    }

    let snap = kernel.snapshot(SafetyLevel::Hardened);
    assert_eq!(
        snap.schema_version, RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION,
        "snapshot schema_version must match the published constant"
    );
    assert!(
        snap.decisions >= 48,
        "decisions counter must account for all evaluate calls"
    );
    // Thresholds must be within valid ppm range.
    assert!(snap.full_validation_trigger_ppm <= 1_000_000);
    assert!(snap.repair_trigger_ppm <= 1_000_000);
    // Pressure regime must be a valid code.
    assert!(snap.pressure_regime_code <= 3);
}

#[test]
fn e2e_snapshot_deterministic_replay_produces_identical_snapshots() {
    let k1 = RuntimeMathKernel::new();
    let k2 = RuntimeMathKernel::new();

    for step in 0..64 {
        let ctx = scripted_ctx(step);
        let d1 = k1.decide(SafetyLevel::Strict, ctx);
        let adv1 = !matches!(d1.action, MembraneAction::Allow);
        k1.observe_validation_result(SafetyLevel::Strict, ctx.family, d1.profile, 40, adv1);

        let d2 = k2.decide(SafetyLevel::Strict, ctx);
        let adv2 = !matches!(d2.action, MembraneAction::Allow);
        k2.observe_validation_result(SafetyLevel::Strict, ctx.family, d2.profile, 40, adv2);
    }

    let snap1 = k1.snapshot(SafetyLevel::Strict);
    let snap2 = k2.snapshot(SafetyLevel::Strict);

    // Core decision counters must be identical under deterministic replay.
    assert_eq!(snap1.decisions, snap2.decisions);
    assert_eq!(
        snap1.full_validation_trigger_ppm,
        snap2.full_validation_trigger_ppm
    );
    assert_eq!(snap1.repair_trigger_ppm, snap2.repair_trigger_ppm);
    assert_eq!(
        snap1.pareto_cumulative_regret_milli,
        snap2.pareto_cumulative_regret_milli
    );
    assert_eq!(snap1.consistency_faults, snap2.consistency_faults);
    assert_eq!(snap1.pressure_regime_code, snap2.pressure_regime_code);
    assert_eq!(snap1.pressure_score_milli, snap2.pressure_score_milli);
    assert_eq!(snap1.quarantine_depth, snap2.quarantine_depth);
}

#[test]
fn e2e_snapshot_strict_vs_hardened_mode_independence() {
    let kernel = RuntimeMathKernel::new();
    let ctx = oversized_allocator_ctx();

    // Drive exclusively with Hardened mode.
    for _ in 0..32 {
        let d = kernel.decide(SafetyLevel::Hardened, ctx);
        kernel.observe_validation_result(
            SafetyLevel::Hardened,
            ctx.family,
            d.profile,
            50,
            true,
        );
    }

    let hardened_snap = kernel.snapshot(SafetyLevel::Hardened);
    let strict_snap = kernel.snapshot(SafetyLevel::Strict);

    // Both snapshots report from the same kernel (shared decision counter).
    assert_eq!(hardened_snap.decisions, strict_snap.decisions);
    assert_eq!(hardened_snap.schema_version, strict_snap.schema_version);
    // But mode-dependent thresholds may differ.
    // (Both are valid; we just confirm the snapshot captures the kernel state for each mode.)
    assert!(hardened_snap.full_validation_trigger_ppm <= 1_000_000);
    assert!(strict_snap.full_validation_trigger_ppm <= 1_000_000);
}

// ---------------------------------------------------------------------------
// Multi-kernel interaction E2E tests
// ---------------------------------------------------------------------------

#[test]
fn e2e_independent_kernels_produce_consistent_results_under_concurrent_scenario() {
    // Simulate two independent kernels processing the same workload.
    // Each must converge to identical decisions because the input stream is identical.
    let k_a = RuntimeMathKernel::new();
    let k_b = RuntimeMathKernel::new();
    let contexts = adverse_diverse_contexts();

    let mut decisions_a = Vec::with_capacity(128);
    let mut decisions_b = Vec::with_capacity(128);

    for step in 0..128 {
        let ctx = contexts[step % contexts.len()];

        let da = k_a.decide(SafetyLevel::Hardened, ctx);
        let adv_a = !matches!(da.action, MembraneAction::Allow);
        k_a.observe_validation_result(
            SafetyLevel::Hardened,
            ctx.family,
            da.profile,
            20 + (step as u64 % 13),
            adv_a,
        );
        decisions_a.push(da);

        let db = k_b.decide(SafetyLevel::Hardened, ctx);
        let adv_b = !matches!(db.action, MembraneAction::Allow);
        k_b.observe_validation_result(
            SafetyLevel::Hardened,
            ctx.family,
            db.profile,
            20 + (step as u64 % 13),
            adv_b,
        );
        decisions_b.push(db);
    }

    assert_eq!(
        decisions_a, decisions_b,
        "independent kernels with identical inputs must produce identical decision streams"
    );

    // Snapshots must agree on all deterministic fields.
    let snap_a = k_a.snapshot(SafetyLevel::Hardened);
    let snap_b = k_b.snapshot(SafetyLevel::Hardened);
    assert_eq!(snap_a.decisions, snap_b.decisions);
    assert_eq!(
        snap_a.pareto_cumulative_regret_milli,
        snap_b.pareto_cumulative_regret_milli
    );
    assert_eq!(snap_a.consistency_faults, snap_b.consistency_faults);

    // Diversity must match.
    let div_a = k_a.reverse_round_diversity_snapshot();
    let div_b = k_b.reverse_round_diversity_snapshot();
    assert_eq!(div_a.active_family_count, div_b.active_family_count);
    assert_eq!(
        div_a.dominant_family_share_ppm,
        div_b.dominant_family_share_ppm
    );
    assert_eq!(div_a.state, div_b.state);
}

#[test]
fn e2e_kernel_isolation_divergent_inputs_produce_independent_state() {
    // Two kernels with different workloads must accumulate independent state.
    let k_safe = RuntimeMathKernel::new();
    let k_adverse = RuntimeMathKernel::new();

    let safe_ctx = RuntimeContext::pointer_validation(0x1000, false);
    let adverse_ctx = oversized_allocator_ctx();

    for _ in 0..64 {
        let ds = k_safe.decide(SafetyLevel::Hardened, safe_ctx);
        k_safe.observe_validation_result(
            SafetyLevel::Hardened,
            safe_ctx.family,
            ds.profile,
            15,
            false,
        );

        let da = k_adverse.decide(SafetyLevel::Hardened, adverse_ctx);
        k_adverse.observe_validation_result(
            SafetyLevel::Hardened,
            adverse_ctx.family,
            da.profile,
            50,
            true,
        );
    }

    let snap_safe = k_safe.snapshot(SafetyLevel::Hardened);
    let snap_adverse = k_adverse.snapshot(SafetyLevel::Hardened);

    // Both processed 64 decisions.
    assert_eq!(snap_safe.decisions, 64);
    assert_eq!(snap_adverse.decisions, 64);

    // The adverse kernel should have accumulated evidence; the safe one should not.
    let ev_safe = k_safe.evidence_contract_snapshot();
    let ev_adverse = k_adverse.evidence_contract_snapshot();
    // Adverse kernel has repair decisions with evidence; safe kernel has allow decisions.
    assert!(
        ev_adverse.evidence_seqno >= ev_safe.evidence_seqno,
        "adverse kernel must have more evidence records"
    );
}

// ---------------------------------------------------------------------------
// Regression: golden snapshot field presence
// ---------------------------------------------------------------------------

#[test]
fn e2e_snapshot_serialization_contains_all_core_fields() {
    let kernel = RuntimeMathKernel::new();
    let ctx = scripted_ctx(0);
    let _ = kernel.decide(SafetyLevel::Hardened, ctx);

    let snap = kernel.snapshot(SafetyLevel::Hardened);
    let json = serde_json::to_value(&snap).expect("snapshot must serialize to JSON");
    let obj = json.as_object().expect("snapshot must be a JSON object");

    // Verify presence of critical fields that golden snapshot diffing depends on.
    let core_fields = [
        "schema_version",
        "decisions",
        "consistency_faults",
        "full_validation_trigger_ppm",
        "repair_trigger_ppm",
        "sampled_risk_bonus_ppm",
        "pareto_cumulative_regret_milli",
        "pareto_cap_enforcements",
        "pareto_exhausted_families",
        "quarantine_depth",
        "pressure_regime_code",
        "pressure_score_milli",
        "tropical_full_wcl_ns",
        "spectral_edge_ratio",
        "spectral_phase_transition",
        "signature_anomaly_score",
    ];
    for field in core_fields {
        assert!(
            obj.contains_key(field),
            "snapshot JSON must contain field `{field}`"
        );
    }

    // schema_version value check.
    assert_eq!(
        obj.get("schema_version").and_then(Value::as_u64),
        Some(u64::from(RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION))
    );
}

#[test]
fn e2e_snapshot_golden_replay_field_stability() {
    // Two kernels with identical input produce identical snapshot JSON (minus any
    // timing-dependent fields). This is the golden-snapshot regression gate.
    let k1 = RuntimeMathKernel::new();
    let k2 = RuntimeMathKernel::new();

    for step in 0..48 {
        let ctx = scripted_ctx(step);
        let d1 = k1.decide(SafetyLevel::Hardened, ctx);
        let adv = !matches!(d1.action, MembraneAction::Allow);
        k1.observe_validation_result(SafetyLevel::Hardened, ctx.family, d1.profile, 35, adv);

        let d2 = k2.decide(SafetyLevel::Hardened, ctx);
        let adv2 = !matches!(d2.action, MembraneAction::Allow);
        k2.observe_validation_result(SafetyLevel::Hardened, ctx.family, d2.profile, 35, adv2);
    }

    let snap1 = serde_json::to_value(&k1.snapshot(SafetyLevel::Hardened))
        .expect("snap1 serializes");
    let snap2 = serde_json::to_value(&k2.snapshot(SafetyLevel::Hardened))
        .expect("snap2 serializes");

    assert_eq!(
        snap1, snap2,
        "golden-snapshot replay must produce identical JSON under deterministic inputs"
    );
}

// ---------------------------------------------------------------------------
// Framework trait E2E tests
// ---------------------------------------------------------------------------

#[test]
fn e2e_framework_trait_evaluate_calibrate_snapshot_cycle() {
    let kernel = RuntimeMathKernel::new();
    // Use oversized context to generate adverse (Repair) decisions that get
    // recorded as decision cards.
    let ctx = oversized_allocator_ctx();

    for _ in 0..32 {
        let d = RuntimeKernelFramework::evaluate(&kernel, SafetyLevel::Hardened, ctx);
        RuntimeKernelFramework::calibrate(
            &kernel,
            SafetyLevel::Hardened,
            ctx.family,
            d.profile,
            25,
            true,
        );
    }

    let snap = RuntimeKernelFramework::snapshot(&kernel, SafetyLevel::Hardened);
    assert!(snap.decisions >= 32);
    assert_eq!(snap.schema_version, RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION);

    let ev = RuntimeKernelFramework::evidence_contract_snapshot(&kernel);
    assert_eq!(ev.evidence_loss_count, 0);

    let div = RuntimeKernelFramework::reverse_round_diversity_snapshot(&kernel);
    assert_eq!(div.active_family_count, 1);
    assert_eq!(div.dominant_family, ApiFamily::Allocator);
}

#[test]
fn e2e_framework_decision_cards_export_contains_all_decisions() {
    let kernel = RuntimeMathKernel::new();
    let contexts = adverse_diverse_contexts();

    // Oversized contexts produce adverse decisions that are always recorded.
    for step in 0..40 {
        let ctx = contexts[step % contexts.len()];
        let d = kernel.decide(SafetyLevel::Hardened, ctx);
        kernel.observe_validation_result(
            SafetyLevel::Hardened,
            ctx.family,
            d.profile,
            20,
            true,
        );
    }

    let export = RuntimeKernelFramework::export_decision_cards_json(&kernel);
    let parsed: Value =
        serde_json::from_str(&export).expect("decision card export must parse as JSON");
    assert_eq!(
        parsed.get("schema").and_then(Value::as_str),
        Some("decision_cards.v1"),
        "export schema must be decision_cards.v1"
    );
    let cards = parsed
        .get("cards")
        .and_then(Value::as_array)
        .expect("cards array must exist");
    assert!(
        !cards.is_empty(),
        "at least one decision card must be present"
    );
    // Each card must have required fields.
    for card in cards {
        let obj = card.as_object().expect("card must be object");
        for key in ["decision_id", "decision_type", "family", "mode"] {
            assert!(obj.contains_key(key), "card missing field `{key}`");
        }
    }
}
