use frankenlibc_membrane::config::SafetyLevel;
use frankenlibc_membrane::heal::HealingAction;
use frankenlibc_membrane::runtime_math::evidence::{LossEvidenceV1, SystematicEvidenceLog};
use frankenlibc_membrane::runtime_math::{
    ApiFamily, MembraneAction, RuntimeContext, RuntimeDecision, RuntimeMathKernel,
    ValidationProfile,
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

fn strip_timestamps(rows: &mut [Value]) {
    for row in rows {
        row.as_object_mut()
            .expect("row must be object")
            .remove("timestamp");
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
    strip_timestamps(&mut rows1);
    strip_timestamps(&mut rows2);
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
