# Localization Fixed-Point Chooser — Design Document

**Bead**: bd-15q
**Authors**: PinkMill (v1), GentleOwl (v2: mode-aware weights, artifact format, signal derivation)
**Date**: 2026-02-10
**Status**: Design (pre-implementation)

## 1. Problem Statement

The `decide()` cascade in `RuntimeMathKernel` routes calls through layered heuristics.
The Atiyah-Bott localization controller (`atiyah_bott.rs`) already *detects* when
anomaly signal concentrates at a few controllers. But it doesn't *act* on this —
it only contributes a bonus to the risk sum.

The localization chooser complements this by using the localization principle for
*policy selection*: when risk localizes at specific failure modes, the routing
policy should specialize to handle those modes rather than applying a generic
risk-proportional response.

**Current gap**: The decide() profile selection currently operates through a
cascade of `if`-chain overrides. Each monitor contributes a bonus, bonuses sum
to `risk_upper_bound_ppm`, and then various threshold gates choose Fast/Full.
This is linear in monitor count and cannot capture interaction effects. The
localization chooser provides a *structured alternative* — a small fixed-point
lookup that uses summary signals rather than the full bonus cascade.

## 2. Mathematical Foundation

**Atiyah-Bott Localization** (1967): The global integral of an equivariant class
localizes to a weighted sum over fixed points:

```
∫_M ω = Σ_{p ∈ M^G} ω(p) / e_G(T_p M)
```

Translating to policy selection: the "global" optimal routing policy is
well-approximated by a weighted sum of *fixed-point policies* — specialized
configurations that are optimal under specific, stereotyped conditions.

Each fixed-point policy p has:
- A **payoff profile**: how it performs across different state dimensions.
- An **Euler weight** e(p): how "typical" the conditions for p are.
  Higher weight = p is the default/normal choice; lower weight = p handles
  extreme/unusual conditions.

Selection: choose the fixed point that maximizes the localized objective:
```
chosen = argmax_p  Σ_j  signal[j] × profile[p][j]  /  euler[p]
```

The division by euler[p] means extreme policies (low Euler weight) need
*strong* signal evidence to be selected over the default.

## 3. Fixed-Point Policies (Arms)

We define 5 fixed-point policies covering the full routing spectrum:

| Arm | Name           | Profile        | Action     | When Optimal |
|-----|----------------|----------------|------------|--------------|
| 0   | Minimal        | Fast           | Allow      | Low risk, no anomalies |
| 1   | Cautious       | Fast           | Allow (FV gate) | Moderate risk, good coverage |
| 2   | Thorough       | Full           | FullValidate | Elevated risk, concentrated anomaly |
| 3   | Protective     | Full           | Repair     | High risk, localized fault (hardened only) |
| 4   | Lockdown       | Full           | Deny       | Extreme risk, system unstable |

**Arm → RuntimeDecision mapping**:

```rust
fn arm_to_decision(arm: u8, mode: SafetyLevel) -> (ValidationProfile, MembraneAction) {
    match arm {
        0 => (Fast, Allow),
        1 => (Fast, Allow),             // Cautious: Allow but lower FV trigger
        2 => (Full, FullValidate),
        3 if mode.heals_enabled() => (Full, Repair(UpgradeToSafeVariant)),
        3 => (Full, FullValidate),      // strict degrades Protective → Thorough
        4 if mode.heals_enabled() => (Full, Repair(ReturnSafeDefault)),
        4 => (Full, Deny),              // strict: hard deny
        _ => (Fast, Allow),
    }
}
```

**Key constraint**: Arm 3 (Protective) ONLY maps to Repair in hardened mode.
In strict mode, Protective degrades to FullValidate (no repair capability).
Arm 4 (Lockdown) maps to the strongest possible action per mode.

## 4. Mode-Aware Euler Weights

Euler weights control how easily each arm is selected. They differ between
strict and hardened mode to reflect the different operating philosophies:

| Arm | Name       | Strict Euler | Hardened Euler | Rationale |
|-----|------------|-------------|---------------|-----------|
| 0   | Minimal    | 5           | 3             | Strict defaults to minimal; hardened is less eager |
| 1   | Cautious   | 4           | 4             | Common fallback in both modes |
| 2   | Thorough   | 2           | 3             | Hardened is more willing to escalate to Full |
| 3   | Protective | 1           | 2             | Hardened enables repair, so Protective is more accessible |
| 4   | Lockdown   | 1           | 1             | Always requires extreme evidence |

**Strict** bias: Minimal (weight 5) strongly dominates. Getting to Full requires
significant evidence. This preserves the <20ns latency budget.

**Hardened** bias: Weights are more uniform. Thorough and Protective are
reachable with moderate evidence. This aligns with the 200ns budget and
repair-enabled posture.

```rust
const STRICT_EULER: [i32; 5]   = [5, 4, 2, 1, 1];
const HARDENED_EULER: [i32; 5]  = [3, 4, 3, 2, 1];
```

## 5. State Signals

5 summary signals derived from cached atomics (all 0..3 encoding):

| Signal | Source | Derivation | Meaning |
|--------|--------|-----------|---------|
| `risk_signal` | `risk_upper_bound_ppm` | 0: <50k, 1: <150k, 2: <300k, 3: ≥300k | Overall risk level |
| `concentration_signal` | `cached_atiyah_bott_state` | Direct 0..3 load | Anomaly localization |
| `stability_signal` | `cached_operator_norm_state`, `cached_lyapunov_state` | max(op_norm, lyapunov) | Ensemble stability |
| `coverage_signal` | `cached_covering_state`, `cached_submodular_state` | max(covering, submodular) | Validation coverage |
| `budget_signal` | `TROPICAL_METRICS.fast_wcl_ns`, `full_wcl_ns` | See derivation below | Latency budget pressure |

### Signal Derivation Rules (All Integer)

```rust
fn derive_signals(
    risk_ppm: u32,
    atiyah_bott: u8,
    operator_norm: u8,
    lyapunov: u8,
    covering: u8,
    submodular: u8,
    fast_over: bool,
    full_over: bool,
) -> [i32; 5] {
    let risk_signal = if risk_ppm >= 300_000 { 3 }
                      else if risk_ppm >= 150_000 { 2 }
                      else if risk_ppm >= 50_000 { 1 }
                      else { 0 };
    let concentration_signal = atiyah_bott as i32;
    let stability_signal = operator_norm.max(lyapunov) as i32;
    let coverage_signal = covering.max(submodular) as i32;
    let budget_signal = match (fast_over, full_over) {
        (true, true) => 3,   // Both paths over budget
        (false, true) => 2,  // Full over budget only
        (true, false) => 1,  // Fast over budget only (unusual)
        _ => 0,              // All within budget
    };
    [risk_signal, concentration_signal, stability_signal,
     coverage_signal, budget_signal]
}
```

All signal derivations use only integer comparisons and `u8::max()`. No
floating-point. Each signal is clamped to 0..3.

## 6. Localization Profile Matrix

A 5×5 matrix of i32 weights encoding each arm's affinity for each signal level:

```
              risk  conc  stab  cov   budget
Minimal     [  -3,   -2,    3,   -1,    3  ]   // good when stable, low risk, budget ok
Cautious    [   1,   -1,    1,    1,    1  ]   // moderate across the board
Thorough    [   2,    2,   -1,    2,   -1  ]   // good when risk/conc high, coverage needed
Protective  [   3,    3,   -2,    1,   -2  ]   // good when localized fault, high risk
Lockdown    [   3,    1,   -3,   -1,   -3  ]   // extreme: high risk, unstable, budget gone
```

**Reading the matrix**: Row = arm, column = signal dimension.
- Minimal scores highest when stability is high (+3), budget is clear (+3),
  and risk is low (risk signal 0 × -3 = 0).
- Protective scores highest when risk is high (3×3 = 9) and concentration
  is high (3×3 = 9), but is penalized by stability costs.

Negative affinity means the arm is *penalized* when that signal is high.
Positive affinity means the arm is *rewarded*.

```rust
const PROFILE_MATRIX: [[i32; 5]; 5] = [
    [-3, -2,  3, -1,  3],  // Minimal
    [ 1, -1,  1,  1,  1],  // Cautious
    [ 2,  2, -1,  2, -1],  // Thorough
    [ 3,  3, -2,  1, -2],  // Protective
    [ 3,  1, -3, -1, -3],  // Lockdown
];
```

## 7. O(1) Integer Selection Rule

```rust
fn select_arm(signals: &[i32; 5], euler: &[i32; 5]) -> u8 {
    let mut best_arm = 0u8;
    let mut best_score = i32::MIN;
    for arm in 0..5u8 {
        let raw: i32 = (0..5).map(|j| PROFILE_MATRIX[arm as usize][j] * signals[j]).sum();
        // Scale by 256 before dividing by Euler weight to preserve precision.
        let score = raw.saturating_mul(256) / euler[arm as usize];
        if score > best_score {
            best_score = score;
            best_arm = arm;
        }
    }
    best_arm
}
```

Total: 25 multiply-adds + 5 scaled divisions + 5-way argmax = ~35 integer ops.
The ×256 scaling avoids rounding loss in the integer division.

**Tie-breaking**: First arm wins (lowest index = most conservative). This ensures
Minimal is chosen over Cautious in perfectly nominal conditions.

## 8. Offline Artifact Format

The localization table is a compile-time constant — no file I/O or runtime
parsing needed. The artifact is embedded directly in Rust source:

```rust
/// Localization chooser offline artifact.
///
/// All fields are compile-time constants. The version field enables
/// future schema evolution without breaking snapshot compatibility.
#[derive(Debug, Clone, Copy)]
pub struct LocalizationTable {
    /// Schema version (bump on any change to arms/weights/signals).
    pub version: u32,

    /// Number of arms (fixed-point policies).
    pub arm_count: usize,

    /// Number of signal dimensions.
    pub signal_count: usize,

    /// Profile affinity matrix: [arm_count × signal_count], row-major.
    /// profile_matrix[arm][signal] = affinity weight.
    pub profile_matrix: [[i32; 5]; 5],

    /// Euler weights per mode.
    pub strict_euler: [i32; 5],
    pub hardened_euler: [i32; 5],

    /// Integer scale factor for division precision.
    pub scale: i32,
}

/// V1 localization table.
pub const LOCALIZATION_TABLE_V1: LocalizationTable = LocalizationTable {
    version: 1,
    arm_count: 5,
    signal_count: 5,
    profile_matrix: [
        [-3, -2,  3, -1,  3],
        [ 1, -1,  1,  1,  1],
        [ 2,  2, -1,  2, -1],
        [ 3,  3, -2,  1, -2],
        [ 3,  1, -3, -1, -3],
    ],
    strict_euler: [5, 4, 2, 1, 1],
    hardened_euler: [3, 4, 3, 2, 1],
    scale: 256,
};
```

**Schema evolution**: The version field allows downstream consumers (snapshot,
frankentui) to handle format changes. Version bumps follow the additive-only
rule from bd-1az.

**Future extensibility**: If the arm set or signal count grows, a new
`LOCALIZATION_TABLE_V2` constant is defined alongside V1. The controller
selects the active version at initialization.

## 9. Integration Plan

### Step 1: Controller Module

Create `crates/glibc-rs-membrane/src/runtime_math/localization_chooser.rs`.

Following the 8-step registration pattern from bd-2vf:

**State enum** (maps to severity code for fusion vector):
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LocalizationChooserState {
    #[default]
    Calibrating = 0,   // Insufficient observations
    Minimal = 1,       // Arm 0 selected (nominal)
    Elevated = 2,      // Arm 2/3 selected (Thorough/Protective)
    Critical = 3,      // Arm 4 selected (Lockdown)
}
```

**Key fields**:
```rust
pub struct LocalizationChooser {
    observation_count: u64,
    current_arm: u8,            // 0..4
    table: LocalizationTable,   // compile-time constant ref
}
```

**observe_and_update()**: Called on cadence (every 64 observations) with the
5 derived signal values. Runs the select_arm computation and updates state.

### Step 2: Wiring into decide()

The localization chooser produces a *recommendation* (arm 0..4) that is
cached in `cached_localization_chooser_arm: AtomicU8`.

In the `decide()` flow, after the bonus aggregation and before the final
profile assignment, the cached arm provides a structured recommendation:

```rust
// Localization chooser recommendation (cadence-gated).
let loc_arm = self.cached_localization_chooser_arm.load(Ordering::Relaxed);
let loc_state = self.cached_localization_chooser_state.load(Ordering::Relaxed);
// Only apply when chooser is calibrated (state > 0) and in the ambiguous
// risk range where the cascade heuristics could go either way.
if loc_state > 0
    && risk_upper_bound_ppm >= limits.full_validation_trigger_ppm / 4
    && risk_upper_bound_ppm < limits.full_validation_trigger_ppm
{
    match loc_arm {
        2 | 3 | 4 => profile = ValidationProfile::Full,
        _ => {}  // Minimal/Cautious: don't override
    }
}
```

**Key rule**: The localization chooser can only *escalate* (Fast → Full),
never de-escalate. This preserves the monotone escalation invariant.

### Step 3: Fusion Severity Vector

Add `cached_localization_chooser_state: AtomicU8` to the kernel and wire
into the fusion severity vector at the next available index. Bump
`META_SEVERITY_LEN` accordingly.

### Step 4: Snapshot Fields

```rust
pub localization_chooser_arm: u8,
pub localization_chooser_score_spread: i32,  // max_score - min_score
```

The score spread measures how decisive the selection is. A large spread
means one arm strongly dominates; a small spread means the state is ambiguous.

## 10. Cadence and Cost

- **Cadence**: Every 64 observations (matches typical meta-controller cadence).
- **Cost per evaluation**: ~35 integer ops = <5ns on modern hardware.
- **Cached outputs**: `AtomicU8` for arm (0..4) and state (0..3).
- **No floating-point**: All computation is `i32` multiply-add + integer divide.
- **No allocations**: Fixed-size arrays only.

## 11. Legacy Anchors

The 5 arms correspond to concrete glibc failure scenarios:

| Arm | glibc Scenario | Example |
|-----|---------------|---------|
| Minimal | Normal operation | Standard `malloc`/`free` cycle, all pointers valid |
| Cautious | Moderate load | High contention on threading primitives, `pthread_mutex_lock` |
| Thorough | Concentrated fault | Single API family (e.g., resolver) consistently failing |
| Protective | Localized corruption | `dl-lookup.c` symbol resolution corrupted, repair possible |
| Lockdown | System instability | Multiple subsystems (alloc + string + thread) simultaneously failing |

## 12. Acceptance Criteria

1. Arm set with clear mapping to `(ValidationProfile, MembraneAction)` per mode.
2. Mode-aware Euler weights (strict biases Minimal; hardened biases Thorough).
3. Integer scoring rule with O(1) cost, no float, no alloc.
4. Concrete signal derivation from existing cached atomics.
5. Offline artifact format as compile-time Rust constant.
6. Integration plan following bd-2vf 8-step registration pattern.
7. Monotone escalation only (chooser can escalate, never de-escalate).

---

## Appendix: Worked Example

**Scenario**: Strict mode, allocator family, operator_norm=Critical (3),
atiyah_bott=Localized (2), risk_ppm=180,000, all within budget.

Signals: `[2, 2, 3, 0, 0]` (risk=2, conc=2, stab=3, cov=0, budget=0)

Scores (×256 / euler):
```
Minimal:    (-3×2 + -2×2 + 3×3 + -1×0 + 3×0) × 256 / 5 = (-6-4+9) × 256/5 = -1×256/5 = -51
Cautious:   (1×2 + -1×2 + 1×3 + 1×0 + 1×0) × 256 / 4 = (2-2+3) × 256/4 = 3×256/4 = 192
Thorough:   (2×2 + 2×2 + -1×3 + 2×0 + -1×0) × 256 / 2 = (4+4-3) × 256/2 = 5×256/2 = 640
Protective: (3×2 + 3×2 + -2×3 + 1×0 + -2×0) × 256 / 1 = (6+6-6) × 256/1 = 6×256 = 1536
Lockdown:   (3×2 + 1×2 + -3×3 + -1×0 + -3×0) × 256 / 1 = (6+2-9) × 256/1 = -1×256 = -256
```

Winner: **Protective** (score 1536). This is correct — concentrated anomaly
(conc=2) with high risk (2) and unstable dynamics (stab=3) should trigger
protective action. In strict mode, Protective degrades to FullValidate.
In hardened mode, Protective maps to Repair(UpgradeToSafeVariant).
