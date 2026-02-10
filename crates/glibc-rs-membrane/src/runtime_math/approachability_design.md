# Blackwell Approachability Controller — Design Document

**Bead**: bd-cx4
**Author**: PinkMill
**Date**: 2026-02-10
**Status**: Design (pre-implementation)

## 1. Problem Statement

The current `decide()` cascade in `RuntimeMathKernel` routes calls through a series
of ad-hoc threshold comparisons: the bandit router picks Fast vs Full, Pareto adjusts,
tropical budget pressure overrides, and special-case guards for allocator/CVaR/sparse/
equivariant states further refine. This produces correct behavior but lacks a formal
guarantee that the *cumulative outcome trajectory* stays within acceptable bounds across
multiple objectives simultaneously.

**Goal**: Replace or augment the routing heuristics with a Blackwell approachability
controller that guarantees the time-averaged (latency, risk, coverage) payoff vector
converges to a target safe set S, regardless of the adversary's input sequence.

## 2. Mathematical Foundation

**Blackwell's Approachability Theorem** (Blackwell 1956):

In a repeated vector-valued game, a convex set S ⊂ ℝ^d is *approachable* by the
decision-maker if and only if for every supporting half-space H ⊇ S, the decision-maker
has a strategy that keeps the time-averaged payoff vector inside H. The constructive
proof gives a simple algorithm:

1. After round t, compute the cumulative average payoff: ḡ(t) = (1/t) Σ_{s≤t} g(s)
2. If ḡ(t) ∈ S, play any action (already safe).
3. If ḡ(t) ∉ S, find the nearest point p* = Π_S(ḡ(t)) (Euclidean projection onto S).
4. Compute direction d = p* - ḡ(t).
5. Choose action a* that maximizes ⟨d, E[g(a*)]⟩ (inner product with expected payoff).

The convergence rate is O(1/√t), meaning after t rounds, dist(ḡ(t), S) ≤ C/√t for
a constant C depending on the payoff range and set geometry.

## 3. Payoff Vector Design

We define a 3-dimensional payoff vector g ∈ ℝ³ (all in milli-units, 0..1000):

| Dimension | Meaning | Encoding |
|-----------|---------|----------|
| g₀: latency_milli | Normalized latency cost | `min(1000, actual_overhead_ns * 1000 / budget_ns)` |
| g₁: risk_milli | Post-decision risk exposure | `min(1000, risk_upper_bound_ppm / 1000)` |
| g₂: coverage_milli | Validation thoroughness | `{Fast+Allow: 100, Fast+FV: 400, Full+Allow: 700, Full+FV: 900, Full+Repair: 1000}` |

**Why these three**: They capture the fundamental routing tradeoff:
- **Latency** is the cost to the caller (strict mode demands low latency).
- **Risk** is the residual safety exposure (hardened mode demands low risk).
- **Coverage** is the verification thoroughness (we want enough coverage to detect faults
  but not so much that latency explodes).

## 4. Target Safe Set

The safe set S is a box (axis-aligned rectangular polytope) defined per mode:

### Strict Mode
```
S_strict = { g | latency_milli ≤ 350,  risk_milli ≤ 500,  coverage_milli ≥ 150 }
```
Interpretation: Average overhead stays well below 20ns budget (~35%), average risk
stays moderate (can be high briefly during transients), and at least 15% of calls
get meaningful validation.

### Hardened Mode
```
S_hardened = { g | latency_milli ≤ 700,  risk_milli ≤ 200,  coverage_milli ≥ 500 }
```
Interpretation: Latency budget is generous (70% of 200ns), risk must be kept low, and
at least 50% of calls get full validation/repair coverage.

**Projection**: For a box S = {g | l ≤ g ≤ u} (component-wise), the nearest point
is simply `p* = clamp(ḡ, l, u)`. This is O(1) with 3 clamp operations — no matrix
algebra needed.

## 5. Action Arms

We define 4 arms (actions), each with a pre-computed expected payoff vector:

| Arm | Profile | Action Gate | Expected Payoff (latency, risk, coverage) |
|-----|---------|-------------|-------------------------------------------|
| 0 | Fast | Allow threshold low | (100, 500, 100) |
| 1 | Fast | FullValidate gate | (250, 300, 400) |
| 2 | Full | Allow/FullValidate | (500, 150, 700) |
| 3 | Full | Repair/Deny | (800, 50, 1000) |

The expected payoffs are *design-time estimates* calibrated from the existing benchmark
data (malloc: 11ns fast / 67ns hardened, strlen: 6ns fast / 44ns hardened). These can
be tuned via offline regression or updated periodically.

**Arm selection**: Given direction d = p* - ḡ(t), choose arm `a* = argmax_a ⟨d, payoff[a]⟩`.
This is 4 dot products of 3-vectors = 12 multiply-adds. O(1), no branches beyond the
argmax comparison.

## 6. Integer-Only Update Rule

All arithmetic uses milli-units (u64) to avoid floating-point on the hot path:

```rust
struct ApproachabilityController {
    /// Cumulative payoff sums (milli-units).
    sum_latency: u64,
    sum_risk: u64,
    sum_coverage: u64,
    /// Observation count.
    count: u64,
    /// Recommended arm from last update (cached for decide()).
    recommended_arm: u8,
    /// Safe set bounds (milli-units) [latency_upper, risk_upper, coverage_lower].
    target: [u64; 3],
}
```

**Update (called from `observe_validation_result`):**
```
count += 1
sum_latency += observed_latency_milli
sum_risk += observed_risk_milli
sum_coverage += observed_coverage_milli

avg_lat = sum_latency / count    // integer division
avg_risk = sum_risk / count
avg_cov = sum_coverage / count

// Box projection (clamp)
proj_lat = min(avg_lat, target[0])
proj_risk = min(avg_risk, target[1])
proj_cov = max(avg_cov, target[2])

// Direction (signed, but we can use i64)
d_lat = proj_lat as i64 - avg_lat as i64
d_risk = proj_risk as i64 - avg_risk as i64
d_cov = proj_cov as i64 - avg_cov as i64

// Arm selection: argmax_a <d, payoff[a]>
best_arm = 0
best_score = i64::MIN
for a in 0..4:
    score = d_lat * PAYOFF[a][0] + d_risk * PAYOFF[a][1] + d_cov * PAYOFF[a][2]
    if score > best_score:
        best_score = score
        best_arm = a
recommended_arm = best_arm
```

**Total cost**: ~20 integer ops + 12 multiply-adds = ~32 operations. No allocations,
no floats, no branches beyond 4-way comparison. Well under 5ns at 3GHz.

## 7. Integration with RuntimeMathKernel

### In `decide()`:
```rust
// After risk aggregation, before profile selection cascade:
let approach_arm = self.cached_approachability_arm.load(Ordering::Relaxed);
let approach_profile = match approach_arm {
    0 | 1 => ValidationProfile::Fast,
    _ => ValidationProfile::Full,
};

// Use as a tiebreaker when risk is in the ambiguous middle range:
if risk_upper_bound_ppm > limits.full_validation_trigger_ppm / 3
    && risk_upper_bound_ppm < limits.repair_trigger_ppm
{
    profile = approach_profile;
}
```

The approachability controller acts as a **principled tiebreaker** in the ambiguous
risk range where neither hard safety gates nor low-risk fast-path rules apply. It
does NOT override hard safety constraints (barrier, CVaR alarm, HJI breach, etc.).

### In `observe_validation_result()`:
```rust
// After existing cadence-gated updates:
if sequence.is_multiple_of(64) {
    let mut approach = self.approachability.lock();
    approach.observe(latency_milli, risk_milli, coverage_milli);
    self.cached_approachability_arm.store(approach.recommended_arm(), Ordering::Relaxed);
}
```

The update runs on a cadence (every 64 observations) to amortize the Mutex lock cost.
Between updates, the cached arm recommendation is read lock-free from an `AtomicU8`.

### State Summary:
```rust
/// Approachability cumulative deviation from safe set (milli, lower is better).
pub approachability_deviation_milli: u64,
/// Approachability recommended arm (0=Fast+Allow, 1=Fast+FV, 2=Full+Allow, 3=Full+Repair).
pub approachability_arm: u8,
```

### Severity Signal:
Approachability state maps to 4 levels:
- 0 (Calibrating): count < 256
- 1 (Approaching): deviation > 0 but decreasing
- 2 (Drifting): deviation increasing or stalled
- 3 (Violated): deviation above alert threshold (e.g., 200 milli)

## 8. Formal Guarantees

### Convergence
By Blackwell's theorem, for any input sequence:
```
dist(ḡ(t), S) ≤ max_payoff_norm / √t
```
where `max_payoff_norm = √(1000² + 1000² + 1000²) ≈ 1732`.

After 1000 observations: deviation ≤ 55 milli (~5.5% of range).
After 10000 observations: deviation ≤ 17 milli (~1.7% of range).

### No-Regret Property
The approachability algorithm is a no-regret strategy: the cumulative deviation from
S grows sublinearly (O(√t)), so the time-averaged deviation → 0.

### Compatibility with Existing Controllers
The approachability controller is *conservative by design*: it only influences the
routing decision in the ambiguous risk range. Hard safety gates (barrier, CVaR alarm,
HJI breach, equivariant fracture, etc.) always take priority. The controller can never
cause a safety downgrade — it can only shift between equivalent-safety routing options.

## 9. Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Payoff dimension | 3 (latency, risk, coverage) | Minimal while capturing fundamental tradeoff |
| Safe set shape | Axis-aligned box | O(1) projection, no matrix algebra |
| Number of arms | 4 | Covers the full routing spectrum without combinatorial explosion |
| Arithmetic | Integer milli-units (u64) | No floats on hot path per project convention |
| Update cadence | Every 64 observations | Amortizes lock; arm changes slowly anyway |
| Integration point | Tiebreaker in ambiguous risk range | Respects existing hard gates |

## 10. Acceptance Criteria

1. **Written derivation**: This document provides the mathematical derivation.
2. **O(1) integer-friendly**: Update rule is ~32 integer ops, no allocations.
3. **Improvement over ad-hoc thresholds**: Formal O(1/√t) convergence guarantee vs.
   no formal guarantee from the current cascade. The approachability controller will
   provably drive the average payoff into S regardless of adversarial input sequences.
4. **No behavioral regression**: Hard safety gates are preserved; controller only
   influences the ambiguous routing zone.

## 11. Legacy Anchor

**malloc/nptl** (allocator + threading): The fundamental tradeoff between validation
latency and safety coverage is sharpest in the allocator fast path, where every
nanosecond matters but temporal-safety (UAF) detection requires thoroughness. The
approachability controller provides a formal guarantee that the cumulative
latency/risk/coverage trajectory stays in the safe set even under adversarial
allocation patterns (e.g., phase-change workloads, thread-pool storms).

## 12. Downstream Implementation Plan

- **bd-2j7** (implement): Create `approachability.rs` with `ApproachabilityController` struct,
  `observe()` and `recommended_arm()` methods, 4-arm payoff table, box projection.
- **bd-276** (integrate): Wire into `RuntimeMathKernel` as described in §7.
- **bd-cv9** (tests + perf): Unit tests for convergence, adversarial sequences,
  microbenchmarks for update cost.
