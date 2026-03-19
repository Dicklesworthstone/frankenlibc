//! Standalone membrane demo: wrap any C library call with TSM safety.
//!
//! This example demonstrates using the Transparent Safety Membrane (TSM)
//! independently of the full FrankenLibC stack. The membrane can validate,
//! heal, and audit operations on any C library — not just glibc.
//!
//! # Run
//!
//! ```bash
//! cargo run -p frankenlibc-membrane --example standalone_membrane
//! ```
//!
//! # What it shows
//!
//! 1. Safety lattice classification of pointer regions
//! 2. Healing policy decisions for invalid operations
//! 3. Evidence ledger collection with JSONL export
//! 4. Metrics snapshot for observability
//! 5. Redaction policy for privacy-safe evidence

use frankenlibc_membrane::{
    DecisionId, EvidenceCategory, EvidenceLedger, HealingAction, HealingPolicy, MembraneMetrics,
    PolicyId, RedactionPolicy, SafetyLevel, SafetyState, TraceId, ValidationEvidence,
};

fn main() {
    println!("=== FrankenLibC Membrane — Standalone Demo ===\n");

    // ─── 1. Safety lattice ─────────────────────────────────────────
    println!("1. Safety State Lattice");
    let state_a = SafetyState::Valid;
    let state_b = SafetyState::Quarantined;
    let joined = state_a.join(state_b);
    println!("   join(Valid, Quarantined) = {joined:?}");
    println!("   Monotonic: safety only gets more restrictive.\n");

    // ─── 2. Healing policy ─────────────────────────────────────────
    println!("2. Healing Policy Decisions");
    let policy = HealingPolicy::new();

    // Simulate a buffer overflow that hardened mode would clamp
    let action = policy.heal_copy_bounds(1024, Some(512), Some(512));
    println!("   copy(1024 bytes, 512 avail) -> {action:?}");
    policy.record(&action);

    // Simulate a string overflow
    let action = policy.heal_string_bounds(256, Some(64));
    println!("   strcpy(256 chars, 64 dst) -> {action:?}");
    policy.record(&action);

    // Simulate a double-free (no-op in strict, healed in hardened)
    let action = HealingAction::IgnoreDoubleFree;
    policy.record(&action);
    println!("   double-free -> {action:?}");
    println!();

    // ─── 3. Metrics ────────────────────────────────────────────────
    println!("3. Membrane Metrics");
    let metrics = MembraneMetrics::new();
    MembraneMetrics::inc(&metrics.validations);
    MembraneMetrics::inc(&metrics.validations);
    MembraneMetrics::inc(&metrics.tls_cache_hits);
    MembraneMetrics::inc(&metrics.bloom_hits);
    MembraneMetrics::inc(&metrics.heals);
    let snap = metrics.snapshot();
    println!("   validations: {}", snap.validations);
    println!(
        "   tls_cache_hit_rate: {:.0}%",
        snap.tls_cache_hit_rate() * 100.0
    );
    println!("   heals: {}", snap.heals);
    println!();

    // ─── 4. Evidence ledger ────────────────────────────────────────
    println!("4. Evidence Ledger (unified collection)");
    let ledger = EvidenceLedger::with_config(256, RedactionPolicy::RedactPointers);

    // Record a metrics snapshot
    ledger.record_metrics_snapshot(
        &snap,
        TraceId::new("demo::metrics::001".to_string()),
        "membrane",
    );

    // Record a healing action
    ledger.record_healing(
        &HealingAction::ClampSize {
            requested: 1024,
            clamped: 512,
        },
        TraceId::new("demo::heal::001".to_string()),
        DecisionId::from_raw(1),
        "string_memory",
        "memcpy",
    );

    // Record a validation decision
    ledger.record_validation(ValidationEvidence {
        trace_id: TraceId::new("demo::validate::001".to_string()),
        decision_id: DecisionId::from_raw(2),
        policy_id: PolicyId::from_raw(1),
        api_family: "allocator".to_string(),
        symbol: "malloc".to_string(),
        decision_path: "tsm::validate::full".to_string(),
        outcome: "allow".to_string(),
        errno_val: 0,
        latency_ns: 42,
        details_json: "{\"size\":4096,\"alignment\":16}".to_string(),
    });

    println!("   appended: {} records", ledger.total_appended());
    println!("   retained: {} records", ledger.retained_count());

    // Show correlation
    let index = ledger.correlation_index();
    println!("   distinct trace_ids: {}", index.len());

    // OTLP stub
    let otlp = ledger.otlp_export_stub();
    println!(
        "   categories: metrics={}, healing={}, validation={}",
        otlp.category_counts[0], otlp.category_counts[1], otlp.category_counts[2]
    );
    println!();

    // ─── 5. JSONL export ───────────────────────────────────────────
    println!("5. JSONL Export (first 2 lines, redacted)");
    let jsonl = ledger.export_jsonl();
    for (i, line) in jsonl.lines().take(2).enumerate() {
        // Pretty-truncate for display (char-boundary safe)
        let display = if line.len() > 120 {
            let end = line
                .char_indices()
                .map(|(i, _)| i)
                .take_while(|&i| i <= 120)
                .last()
                .unwrap_or(0);
            format!("{}...", &line[..end])
        } else {
            line.to_string()
        };
        println!("   [{i}] {display}");
    }
    println!();

    // ─── 6. Filtered export ────────────────────────────────────────
    println!("6. Filtered Export (healing actions only)");
    let healing_jsonl = ledger.export_jsonl_filtered(EvidenceCategory::HealingAction);
    let healing_count = healing_jsonl.lines().filter(|l| !l.is_empty()).count();
    println!("   healing records: {healing_count}");
    println!();

    // ─── 7. Runtime mode awareness ────────────────────────────────
    println!("7. Runtime Mode");
    let mode = SafetyLevel::default();
    println!("   default mode: {mode:?}");
    println!("   heals_enabled: {}", mode.heals_enabled());
    println!("   validation_enabled: {}", mode.validation_enabled());
    println!();

    println!("=== Demo complete. The membrane works standalone! ===");
}
