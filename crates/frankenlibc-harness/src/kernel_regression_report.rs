//! Strict-vs-hardened regression report for runtime_math kernels.
//!
//! This is harness/tooling code, not part of libc runtime. It intentionally:
//! - runs in two separate processes (strict + hardened) because mode is process-immutable
//! - emits machine-readable JSON for per-mode metrics
//! - renders a combined Markdown report that makes latency/safety tradeoffs obvious

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use frankenlibc_membrane::config::{SafetyLevel, safety_level};
use frankenlibc_membrane::{
    ApiFamily, MembraneAction, RuntimeContext, RuntimeDecision, RuntimeMathKernel,
};
use serde::{Deserialize, Serialize};

const DEFAULT_SEED: u64 = 0xDEAD_BEEF;
const DEFAULT_STEPS: u32 = 256;

const SCENARIO_FAMILIES: &[ApiFamily] = &[
    ApiFamily::PointerValidation,
    ApiFamily::Allocator,
    ApiFamily::StringMemory,
    ApiFamily::Threading,
    ApiFamily::Socket,
    ApiFamily::Inet,
    ApiFamily::Time,
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MicrobenchConfig {
    pub warmup_iters: u64,
    pub sample_count: usize,
    pub sample_iters: u64,
}

impl Default for MicrobenchConfig {
    fn default() -> Self {
        Self {
            warmup_iters: 10_000,
            sample_count: 25,
            sample_iters: 50_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    pub samples: usize,
    pub p50_ns_op: f64,
    pub p95_ns_op: f64,
    pub p99_ns_op: f64,
    pub mean_ns_op: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelBenchSuite {
    pub decide: LatencyStats,
    pub decide_observe: LatencyStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelActionStats {
    pub decisions: u64,
    pub profile_fast: u64,
    pub profile_full: u64,
    pub action_allow: u64,
    pub action_full_validate: u64,
    pub action_repair: u64,
    pub action_deny: u64,
    pub repair_by_action: BTreeMap<String, u64>,
    pub deny_rate: f64,
    pub repair_rate: f64,
    pub full_profile_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelRiskStats {
    pub mean_risk_ppm: f64,
    pub p95_risk_ppm: u32,
    pub p99_risk_ppm: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParetoTrendPoint {
    pub step: u32,
    pub regret_milli: u64,
    pub cap_enforcements: u64,
    pub exhausted_families: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelSnapshotKey {
    pub full_validation_trigger_ppm: u32,
    pub repair_trigger_ppm: u32,
    pub sampled_risk_bonus_ppm: u32,
    pub pareto_cumulative_regret_milli: u64,
    pub pareto_cap_enforcements: u64,
    pub pareto_exhausted_families: u32,
    pub quarantine_depth: usize,
    pub tropical_full_wcl_ns: u64,
    pub alpha_investing_wealth_milli: u64,
    pub alpha_investing_rejections: u64,
    pub alpha_investing_empirical_fdr: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelModeMetrics {
    pub mode: String,
    pub seed: u64,
    pub steps: u32,
    pub bench: KernelBenchSuite,
    pub actions: KernelActionStats,
    pub risk: KernelRiskStats,
    pub snapshot: KernelSnapshotKey,
    pub pareto_trend: Vec<ParetoTrendPoint>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelRegressionReport {
    pub strict: KernelModeMetrics,
    pub hardened: KernelModeMetrics,
}

#[derive(Debug, Clone, Copy)]
pub struct ModeRunConfig {
    pub seed: u64,
    pub steps: u32,
    pub microbench: MicrobenchConfig,
    pub trend_stride: u32,
}

impl Default for ModeRunConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            steps: DEFAULT_STEPS,
            microbench: MicrobenchConfig::default(),
            trend_stride: 32,
        }
    }
}

pub fn collect_mode_metrics(
    expected_mode: SafetyLevel,
    cfg: ModeRunConfig,
) -> Result<KernelModeMetrics, String> {
    let mode = safety_level();
    if mode != expected_mode {
        return Err(format!(
            "expected GLIBC_RUST_MODE={expected:?} but config resolved to {got:?}",
            expected = expected_mode,
            got = mode
        ));
    }

    let bench = run_microbench(mode, cfg.microbench);

    let kernel = RuntimeMathKernel::new();
    let mut actions = ActionStatsBuilder::default();
    let mut risks: Vec<u32> = Vec::with_capacity(cfg.steps as usize);
    let mut pareto_trend = Vec::new();

    let stride = cfg.trend_stride.max(1);

    let mut rng = cfg.seed;
    for i in 0..cfg.steps {
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

        let d = kernel.decide(mode, ctx);
        actions.observe(d);
        risks.push(d.risk_upper_bound_ppm);

        // Exercise the regret controller (Pareto) and other observe-driven kernels.
        let estimated_cost_ns = if d.profile.requires_full() { 120 } else { 12 };
        let adverse = matches!(d.action, MembraneAction::Repair(_) | MembraneAction::Deny);
        kernel.observe_validation_result(ctx.family, d.profile, estimated_cost_ns, adverse);

        // Deterministically exercise overlap-consistency monitoring.
        if i % 17 == 0 {
            let left = (r as usize) & 0x0f;
            let right = ((r >> 8) as usize) & 0x0f;
            let witness = next_u64(&mut rng);
            let _ = kernel.note_overlap(left, right, witness);
        }

        if i % stride == 0 || i + 1 == cfg.steps {
            let snap = kernel.snapshot(mode);
            pareto_trend.push(ParetoTrendPoint {
                step: i + 1,
                regret_milli: snap.pareto_cumulative_regret_milli,
                cap_enforcements: snap.pareto_cap_enforcements,
                exhausted_families: snap.pareto_exhausted_families,
            });
        }
    }

    let action_stats = actions.finish();
    let risk_stats = compute_risk_stats(&risks);

    let snap = kernel.snapshot(mode);
    let snapshot_key = KernelSnapshotKey {
        full_validation_trigger_ppm: snap.full_validation_trigger_ppm,
        repair_trigger_ppm: snap.repair_trigger_ppm,
        sampled_risk_bonus_ppm: snap.sampled_risk_bonus_ppm,
        pareto_cumulative_regret_milli: snap.pareto_cumulative_regret_milli,
        pareto_cap_enforcements: snap.pareto_cap_enforcements,
        pareto_exhausted_families: snap.pareto_exhausted_families,
        quarantine_depth: snap.quarantine_depth,
        tropical_full_wcl_ns: snap.tropical_full_wcl_ns,
        alpha_investing_wealth_milli: snap.alpha_investing_wealth_milli,
        alpha_investing_rejections: snap.alpha_investing_rejections,
        alpha_investing_empirical_fdr: snap.alpha_investing_empirical_fdr,
    };

    let notes = vec![
        String::from(
            "Latency stats are best-effort microbench samples; use scripts/perf_gate.sh for gated regressions.",
        ),
        String::from(
            "Approachability signals are not currently exported in RuntimeKernelSnapshot schema; report omits them if absent.",
        ),
    ];

    Ok(KernelModeMetrics {
        mode: match mode {
            SafetyLevel::Strict => String::from("strict"),
            SafetyLevel::Hardened => String::from("hardened"),
            SafetyLevel::Off => String::from("off"),
        },
        seed: cfg.seed,
        steps: cfg.steps,
        bench,
        actions: action_stats,
        risk: risk_stats,
        snapshot: snapshot_key,
        pareto_trend,
        notes,
    })
}

pub fn render_regression_markdown(report: &KernelRegressionReport) -> String {
    let s = &report.strict;
    let h = &report.hardened;

    let mut out = String::new();
    use std::fmt::Write as _;

    writeln!(out, "# runtime_math Strict vs Hardened Regression Report").ok();
    writeln!(out).ok();
    writeln!(
        out,
        "- Scenario: seed=0x{seed:016X} steps={steps}",
        seed = s.seed,
        steps = s.steps
    )
    .ok();
    writeln!(
        out,
        "- Generated: per-mode subprocess run (mode is process-immutable)"
    )
    .ok();
    writeln!(out).ok();

    writeln!(out, "## Latency (ns/op)").ok();
    writeln!(out).ok();
    writeln!(
        out,
        "| Bench | strict p50 | strict p95 | hardened p50 | hardened p95 | delta p50 | delta p95 |"
    )
    .ok();
    writeln!(
        out,
        "|------|------------:|-----------:|-------------:|------------:|----------:|----------:|"
    )
    .ok();
    render_latency_row(&mut out, "decide", &s.bench.decide, &h.bench.decide);
    render_latency_row(
        &mut out,
        "decide+observe",
        &s.bench.decide_observe,
        &h.bench.decide_observe,
    );
    writeln!(out).ok();
    writeln!(
        out,
        "- Budgets: strict <20ns, hardened <200ns (targets; gating enforced via perf scripts)."
    )
    .ok();
    writeln!(out).ok();

    writeln!(out, "## Safety Routing").ok();
    writeln!(out).ok();
    writeln!(out, "| Metric | strict | hardened |").ok();
    writeln!(out, "|--------|-------:|---------:|").ok();
    writeln!(
        out,
        "| decisions | {} | {} |",
        s.actions.decisions, h.actions.decisions
    )
    .ok();
    writeln!(
        out,
        "| full_profile_rate | {:.4} | {:.4} |",
        s.actions.full_profile_rate, h.actions.full_profile_rate
    )
    .ok();
    writeln!(
        out,
        "| repair_rate | {:.6} | {:.6} |",
        s.actions.repair_rate, h.actions.repair_rate
    )
    .ok();
    writeln!(
        out,
        "| deny_rate | {:.6} | {:.6} |",
        s.actions.deny_rate, h.actions.deny_rate
    )
    .ok();
    writeln!(
        out,
        "| mean_risk_ppm | {:.1} | {:.1} |",
        s.risk.mean_risk_ppm, h.risk.mean_risk_ppm
    )
    .ok();
    writeln!(
        out,
        "| p95_risk_ppm | {} | {} |",
        s.risk.p95_risk_ppm, h.risk.p95_risk_ppm
    )
    .ok();
    writeln!(
        out,
        "| p99_risk_ppm | {} | {} |",
        s.risk.p99_risk_ppm, h.risk.p99_risk_ppm
    )
    .ok();
    writeln!(out).ok();

    if !h.actions.repair_by_action.is_empty() {
        writeln!(out, "### Hardened Repair Mix").ok();
        writeln!(out).ok();
        writeln!(out, "| HealingAction | count |").ok();
        writeln!(out, "|--------------|------:|").ok();
        for (k, v) in &h.actions.repair_by_action {
            writeln!(out, "| {k} | {v} |").ok();
        }
        writeln!(out).ok();
    }

    writeln!(out, "## Pareto Regret (Trend)").ok();
    writeln!(out).ok();
    writeln!(out, "| step | strict regret_milli | hardened regret_milli | strict exhausted | hardened exhausted |").ok();
    writeln!(
        out,
        "|-----:|-------------------:|---------------------:|----------------:|------------------:|"
    )
    .ok();

    let n = s.pareto_trend.len().max(h.pareto_trend.len());
    for idx in 0..n {
        let sp = s.pareto_trend.get(idx);
        let hp = h.pareto_trend.get(idx);
        let step = sp
            .map(|p| p.step)
            .or_else(|| hp.map(|p| p.step))
            .unwrap_or(0);
        let s_reg = sp.map(|p| p.regret_milli).unwrap_or(0);
        let h_reg = hp.map(|p| p.regret_milli).unwrap_or(0);
        let s_ex = sp.map(|p| p.exhausted_families).unwrap_or(0);
        let h_ex = hp.map(|p| p.exhausted_families).unwrap_or(0);
        writeln!(out, "| {step} | {s_reg} | {h_reg} | {s_ex} | {h_ex} |").ok();
    }
    writeln!(out).ok();

    writeln!(out, "## Alpha-Investing (FDR)").ok();
    writeln!(out).ok();
    writeln!(out, "| Metric | strict | hardened |").ok();
    writeln!(out, "|--------|-------:|---------:|").ok();
    writeln!(
        out,
        "| wealth_milli | {} | {} |",
        s.snapshot.alpha_investing_wealth_milli, h.snapshot.alpha_investing_wealth_milli
    )
    .ok();
    writeln!(
        out,
        "| rejections | {} | {} |",
        s.snapshot.alpha_investing_rejections, h.snapshot.alpha_investing_rejections
    )
    .ok();
    writeln!(
        out,
        "| empirical_fdr | {:.6} | {:.6} |",
        s.snapshot.alpha_investing_empirical_fdr, h.snapshot.alpha_investing_empirical_fdr
    )
    .ok();
    writeln!(out).ok();

    writeln!(out, "## Notes").ok();
    for note in s.notes.iter().chain(h.notes.iter()) {
        writeln!(out, "- {note}").ok();
    }

    out
}

fn render_latency_row(
    out: &mut String,
    label: &str,
    strict: &LatencyStats,
    hardened: &LatencyStats,
) {
    use std::fmt::Write as _;
    let delta_p50 = pct_delta(strict.p50_ns_op, hardened.p50_ns_op);
    let delta_p95 = pct_delta(strict.p95_ns_op, hardened.p95_ns_op);
    writeln!(
        out,
        "| {label} | {:.3} | {:.3} | {:.3} | {:.3} | {delta_p50} | {delta_p95} |",
        strict.p50_ns_op, strict.p95_ns_op, hardened.p50_ns_op, hardened.p95_ns_op
    )
    .ok();
}

fn pct_delta(base: f64, current: f64) -> String {
    if base <= 0.0 {
        return String::from("n/a");
    }
    let pct = ((current - base) / base) * 100.0;
    format!("{pct:+.2}%")
}

#[derive(Default)]
struct ActionStatsBuilder {
    decisions: u64,
    profile_fast: u64,
    profile_full: u64,
    action_allow: u64,
    action_full_validate: u64,
    action_repair: u64,
    action_deny: u64,
    repair_by_action: BTreeMap<String, u64>,
}

impl ActionStatsBuilder {
    fn observe(&mut self, d: RuntimeDecision) {
        self.decisions = self.decisions.saturating_add(1);
        match d.profile {
            frankenlibc_membrane::ValidationProfile::Fast => self.profile_fast += 1,
            frankenlibc_membrane::ValidationProfile::Full => self.profile_full += 1,
        }
        match d.action {
            MembraneAction::Allow => self.action_allow += 1,
            MembraneAction::FullValidate => self.action_full_validate += 1,
            MembraneAction::Repair(action) => {
                self.action_repair += 1;
                let k = format!("{action:?}");
                *self.repair_by_action.entry(k).or_insert(0) += 1;
            }
            MembraneAction::Deny => self.action_deny += 1,
        }
    }

    fn finish(self) -> KernelActionStats {
        let denom = self.decisions.max(1) as f64;
        KernelActionStats {
            decisions: self.decisions,
            profile_fast: self.profile_fast,
            profile_full: self.profile_full,
            action_allow: self.action_allow,
            action_full_validate: self.action_full_validate,
            action_repair: self.action_repair,
            action_deny: self.action_deny,
            repair_by_action: self.repair_by_action,
            deny_rate: (self.action_deny as f64) / denom,
            repair_rate: (self.action_repair as f64) / denom,
            full_profile_rate: (self.profile_full as f64) / denom,
        }
    }
}

fn compute_risk_stats(samples_ppm: &[u32]) -> KernelRiskStats {
    if samples_ppm.is_empty() {
        return KernelRiskStats {
            mean_risk_ppm: 0.0,
            p95_risk_ppm: 0,
            p99_risk_ppm: 0,
        };
    }
    let mean = samples_ppm.iter().map(|&v| v as f64).sum::<f64>() / samples_ppm.len() as f64;
    let mut sorted = samples_ppm.to_vec();
    sorted.sort_unstable();
    KernelRiskStats {
        mean_risk_ppm: mean,
        p95_risk_ppm: percentile_u32_sorted(&sorted, 0.95),
        p99_risk_ppm: percentile_u32_sorted(&sorted, 0.99),
    }
}

fn percentile_u32_sorted(sorted: &[u32], p: f64) -> u32 {
    debug_assert!((0.0..=1.0).contains(&p));
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn run_microbench(mode: SafetyLevel, cfg: MicrobenchConfig) -> KernelBenchSuite {
    let decide = bench_decide(mode, cfg);
    let decide_observe = bench_decide_observe(mode, cfg);
    KernelBenchSuite {
        decide,
        decide_observe,
    }
}

fn bench_decide(mode: SafetyLevel, cfg: MicrobenchConfig) -> LatencyStats {
    let kernel = RuntimeMathKernel::new();
    let ctx = RuntimeContext::pointer_validation(0x1234_5678, false);

    for _ in 0..cfg.warmup_iters {
        std::hint::black_box(kernel.decide(mode, ctx));
    }

    let mut samples = Vec::with_capacity(cfg.sample_count);
    for _ in 0..cfg.sample_count {
        let start = Instant::now();
        for _ in 0..cfg.sample_iters {
            std::hint::black_box(kernel.decide(mode, ctx));
        }
        let dur = start.elapsed().max(Duration::from_nanos(1));
        samples.push(dur.as_nanos() as f64 / cfg.sample_iters as f64);
    }
    stats_from_samples(samples)
}

fn bench_decide_observe(mode: SafetyLevel, cfg: MicrobenchConfig) -> LatencyStats {
    let kernel = RuntimeMathKernel::new();
    let ctx = RuntimeContext::pointer_validation(0x1234_5678, false);

    for _ in 0..cfg.warmup_iters {
        let d = kernel.decide(mode, ctx);
        let cost = if d.profile.requires_full() { 120 } else { 12 };
        let adverse = matches!(d.action, MembraneAction::Repair(_) | MembraneAction::Deny);
        kernel.observe_validation_result(ctx.family, d.profile, cost, adverse);
    }

    let mut samples = Vec::with_capacity(cfg.sample_count);
    for _ in 0..cfg.sample_count {
        let start = Instant::now();
        for _ in 0..cfg.sample_iters {
            let d = kernel.decide(mode, ctx);
            let cost = if d.profile.requires_full() { 120 } else { 12 };
            let adverse = matches!(d.action, MembraneAction::Repair(_) | MembraneAction::Deny);
            kernel.observe_validation_result(ctx.family, d.profile, cost, adverse);
        }
        let dur = start.elapsed().max(Duration::from_nanos(1));
        samples.push(dur.as_nanos() as f64 / cfg.sample_iters as f64);
    }
    stats_from_samples(samples)
}

fn stats_from_samples(mut samples: Vec<f64>) -> LatencyStats {
    if samples.is_empty() {
        return LatencyStats {
            samples: 0,
            p50_ns_op: 0.0,
            p95_ns_op: 0.0,
            p99_ns_op: 0.0,
            mean_ns_op: 0.0,
        };
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    LatencyStats {
        samples: samples.len(),
        p50_ns_op: percentile_f64_sorted(&samples, 0.50),
        p95_ns_op: percentile_f64_sorted(&samples, 0.95),
        p99_ns_op: percentile_f64_sorted(&samples, 0.99),
        mean_ns_op: mean,
    }
}

fn percentile_f64_sorted(sorted: &[f64], p: f64) -> f64 {
    debug_assert!((0.0..=1.0).contains(&p));
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn next_u64(state: &mut u64) -> u64 {
    // Deterministic LCG, aligned with harness snapshot generator.
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}
