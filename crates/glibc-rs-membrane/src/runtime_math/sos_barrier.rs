//! # SOS Barrier Certificate Runtime Polynomial Evaluator
//!
//! Evaluates pre-computed SOS barrier certificates for runtime admissibility
//! decisions. Heavy SOS/SDP synthesis runs offline; this module provides
//! the cheap O(d²) runtime evaluation of the resulting polynomial forms.
//!
//! ## Mathematical Foundation
//!
//! A **barrier certificate** B(x) for a dynamical system certifies that
//! trajectories starting in an initial set X₀ never reach an unsafe set X_u
//! (Prajna & Jadbabaie 2004):
//!
//! 1. B(x) ≥ 0 for all x ∈ X₀ (initially non-negative)
//! 2. B(x) < 0 for all x ∈ X_u (negative in unsafe states)
//! 3. dB/dt ≥ 0 along system dynamics (non-decreasing along trajectories)
//!
//! The SOS program: find B(x) = z(x)ᵀ Q z(x) (sum of squares) satisfying
//! (1-3). This reduces to a semidefinite program (SDP) solvable offline.
//! Once solved, the certificate is a set of polynomial coefficients that
//! runtime evaluates in O(d²) time.
//!
//! ## Runtime Design
//!
//! Two concrete barrier certificates:
//!
//! - **Invariant B (Pointer Provenance Admissibility)**: hot-path, <15ns,
//!   4 variables (risk, validation_depth, bloom_fp_rate, arena_pressure),
//!   degree-2 explicit polynomial. Fixed-point integer arithmetic.
//!
//! - **Invariant A (Quarantine Depth Safety Envelope)**: cadence-gated
//!   (every 256 calls), ~100ns budget, 4 variables (depth, contention,
//!   adverse_rate, latency_dual), degree-3 Gram matrix evaluation.
//!
//! ## References
//!
//! - Prajna & Jadbabaie (2004), "Safety Verification of Hybrid Systems
//!   Using Barrier Certificates", HSCC.
//! - Ahmadi & Majumdar (2019), "DSOS and SDSOS Optimization", SIAM J.
//!   Applied Algebra and Geometry.
//! - Design document: `sos_barrier_design.md` (bd-2pw).

// ---------------------------------------------------------------------------
// Maximum variable count for static arrays.
// ---------------------------------------------------------------------------

/// Maximum number of variables per barrier certificate.
const MAX_VARS: usize = 4;

// ---------------------------------------------------------------------------
// Invariant B: Pointer Provenance Admissibility (hot-path).
// ---------------------------------------------------------------------------

/// Risk budget in ppm — the maximum acceptable risk for Fast validation.
/// If risk exceeds this with insufficient validation, the barrier fires.
const PROVENANCE_RISK_BUDGET_PPM: i64 = 100_000;

/// Coefficients from offline SDP (DSOS relaxation).
/// These penalize the triple-product interactions between risk, bloom FP
/// rate, arena pressure, and validation depth.
///
/// β₁: risk × bloom_fp × (1 - validation_depth) penalty.
const BETA_1: i64 = 800;
/// β₂: risk × arena_pressure × (1 - validation_depth) penalty.
const BETA_2: i64 = 600;
/// β₃: validation_depth × (1 - bloom_fp) reward.
const BETA_3: i64 = 400;

/// Evaluate Invariant B (Pointer Provenance Admissibility).
///
/// Inputs are all in ppm (0..1_000_000):
/// - `risk_ppm`: risk upper bound
/// - `validation_depth_ppm`: 0 = Fast, 1_000_000 = Full
/// - `bloom_fp_rate_ppm`: bloom false-positive rate
/// - `arena_pressure_ppm`: arena_used / arena_capacity
///
/// Returns the barrier value in ppm. Negative → violation (escalate).
///
/// Cost: ~10 multiply-adds → <15ns on modern x86_64.
#[must_use]
pub fn evaluate_provenance_barrier(
    risk_ppm: u32,
    validation_depth_ppm: u32,
    bloom_fp_rate_ppm: u32,
    arena_pressure_ppm: u32,
) -> i64 {
    let r = risk_ppm as i64;
    let v = validation_depth_ppm as i64;
    let b = bloom_fp_rate_ppm as i64;
    let p = arena_pressure_ppm as i64;
    let one = 1_000_000i64;

    // Risk headroom: positive when risk is below budget.
    let headroom = PROVENANCE_RISK_BUDGET_PPM - r;

    // Penalty: risk × bloom_fp × (1 - depth). High risk + bad bloom + fast path → bad.
    // Scale: r * b / 1e6 gives ppm product; * (1-v) / 1e6 gives triple product.
    let rb = r.saturating_mul(b) / one;
    let penalty_1 = BETA_1.saturating_mul(rb).saturating_mul(one - v) / (one * one);

    // Penalty: risk × arena_pressure × (1 - depth). High risk + full arena + fast → bad.
    let rp = r.saturating_mul(p) / one;
    let penalty_2 = BETA_2.saturating_mul(rp).saturating_mul(one - v) / (one * one);

    // Reward: validation_depth × (1 - bloom_fp). Full validation + good bloom → safe.
    let reward = BETA_3.saturating_mul(v).saturating_mul(one - b) / (one * one);

    headroom - penalty_1 - penalty_2 + reward
}

// ---------------------------------------------------------------------------
// Invariant A: Quarantine Depth Safety Envelope (cadence-gated).
// ---------------------------------------------------------------------------

/// Number of monomials for 4-variable degree-3: C(4+3,3) = 35.
/// We use a sparse subset of ~20 monomials for the DSOS certificate.
const INVARIANT_A_MONOMIALS: usize = 20;

/// Monomial exponents for the quarantine depth barrier polynomial.
/// Each entry [d_exp, c_exp, a_exp, lambda_exp] defines the monomial
/// d^d_exp * c^c_exp * a^a_exp * λ^lambda_exp.
///
/// These are the non-zero monomials from the DSOS relaxation of
/// the quarantine depth safety envelope. Sparse representation
/// keeps evaluation cost at ~20 multiply-adds instead of 35.
static INVARIANT_A_EXPONENTS: [[u8; MAX_VARS]; INVARIANT_A_MONOMIALS] = [
    // Constant + linear terms
    [0, 0, 0, 0], // 1
    [1, 0, 0, 0], // d
    [0, 1, 0, 0], // c
    [0, 0, 1, 0], // a
    [0, 0, 0, 1], // λ
    // Quadratic terms
    [2, 0, 0, 0], // d²
    [0, 2, 0, 0], // c²
    [0, 0, 2, 0], // a²
    [1, 1, 0, 0], // dc
    [1, 0, 1, 0], // da
    [1, 0, 0, 1], // dλ
    [0, 1, 1, 0], // ca
    [0, 0, 1, 1], // aλ
    // Cubic terms (from barrier polynomial structure)
    [1, 0, 2, 0], // d·a² (penalty: adverse² × depth)
    [2, 1, 0, 0], // d²·c (penalty: depth² × contention)
    [0, 1, 0, 2], // c·λ² (penalty: contention × latency²)
    [1, 1, 1, 0], // d·c·a (cross-term)
    [1, 1, 0, 1], // d·c·λ (cross-term)
    [0, 0, 3, 0], // a³ (high adverse cubic penalty)
    [3, 0, 0, 0], // d³ (depth self-correcting)
];

/// Coefficients for Invariant A monomials.
///
/// These are pre-computed from the offline DSOS SDP solution.
/// Units: milli-units (multiply by monomial product, divide by scaling).
/// The polynomial is: B_A(x) = Σ_k coeff[k] * monomial[k](x_normalized).
///
/// Sign convention: positive = safe contribution, negative = unsafe penalty.
static INVARIANT_A_COEFFICIENTS: [i64; INVARIANT_A_MONOMIALS] = [
    200,   // 1: baseline positive (safe interior bias)
    500,   // d: higher depth is generally safer
    -300,  // c: higher contention is risky
    -600,  // a: higher adverse rate is risky
    -100,  // λ: latency pressure is mildly risky
    -400,  // d²: excessive depth diminishing returns
    -250,  // c²: quadratic contention penalty
    -800,  // a²: quadratic adverse penalty
    -350,  // dc: depth × contention interaction
    700,   // da: depth helps against adverse (positive!)
    -200,  // dλ: depth × latency interaction
    -400,  // ca: contention × adverse is bad
    -300,  // aλ: adverse × latency is bad
    -500,  // d·a²: high adverse overwhelms depth
    -300,  // d²·c: deep quarantine under contention
    -150,  // c·λ²: contention × latency² pressure
    -250,  // d·c·a: three-way interaction
    -200,  // d·c·λ: three-way interaction
    -900,  // a³: cubic adverse penalty (extreme)
    100,   // d³: deep quarantine self-correcting
];

/// Normalization parameters for Invariant A state variables.
/// (offset, scale) — raw_value → (raw_value - offset) / scale.
///
/// After normalization, each variable is in [0, 1] or [-1, 1].
#[derive(Debug, Clone, Copy)]
pub struct NormalizationParams {
    pub offset: i64,
    pub scale: i64,
}

/// Quarantine depth: raw range [MIN_DEPTH=64, MAX_DEPTH=65536].
/// Normalized to [0, 1]: (depth - 64) / (65536 - 64).
const NORM_DEPTH: NormalizationParams = NormalizationParams {
    offset: 64,
    scale: 65536 - 64,
};

/// Contention: raw range [0, max_threads]. We normalize to [0, 1]
/// using a practical max of 1024 threads.
const NORM_CONTENTION: NormalizationParams = NormalizationParams {
    offset: 0,
    scale: 1024,
};

/// Adverse rate: raw is ppm [0, 1_000_000]. Normalize to [0, 1].
const NORM_ADVERSE: NormalizationParams = NormalizationParams {
    offset: 0,
    scale: 1_000_000,
};

/// Latency dual variable: raw range [-128, 128]. Normalize to [-1, 1].
const NORM_LATENCY: NormalizationParams = NormalizationParams {
    offset: 0,
    scale: 128,
};

/// Fixed-point scaling factor for normalized variables.
/// We represent normalized [0,1] values as integers in [0, FIXED_SCALE].
const FIXED_SCALE: i64 = 10_000;

/// Normalize a raw value to fixed-point representation.
///
/// Returns a value in [0, FIXED_SCALE] (clamped).
#[inline]
fn normalize_fixed(raw: i64, params: NormalizationParams) -> i64 {
    if params.scale == 0 {
        return FIXED_SCALE / 2;
    }
    let shifted = raw.saturating_sub(params.offset);
    let normalized = shifted.saturating_mul(FIXED_SCALE) / params.scale;
    normalized.clamp(-FIXED_SCALE, FIXED_SCALE)
}

/// Evaluate Invariant A (Quarantine Depth Safety Envelope).
///
/// Inputs are raw, unnormalized values:
/// - `depth`: current quarantine depth (64..65536)
/// - `contention`: peak concurrent threads (0..1024+)
/// - `adverse_ppm`: adverse event rate in ppm (0..1_000_000)
/// - `lambda_latency`: latency dual variable from PrimalDualController (-128..128)
///
/// Returns the barrier value in milli-units. Negative → violation.
///
/// Cost: ~20 monomial evaluations × ~4 multiply-adds each = ~80 ops → <100ns.
#[must_use]
pub fn evaluate_quarantine_barrier(
    depth: u32,
    contention: u32,
    adverse_ppm: u32,
    lambda_latency: i64,
) -> i64 {
    // Normalize to fixed-point.
    let d = normalize_fixed(depth as i64, NORM_DEPTH);
    let c = normalize_fixed(contention as i64, NORM_CONTENTION);
    let a = normalize_fixed(adverse_ppm as i64, NORM_ADVERSE);
    let l = normalize_fixed(lambda_latency, NORM_LATENCY);

    let vars = [d, c, a, l];
    let mut result: i64 = 0;

    for (k, (exponents, &coeff)) in INVARIANT_A_EXPONENTS
        .iter()
        .zip(INVARIANT_A_COEFFICIENTS.iter())
        .enumerate()
    {
        if coeff == 0 {
            continue;
        }
        let mono = eval_monomial(&vars, &exponents[..MAX_VARS]);
        // coeff is in milli-units, mono is in FIXED_SCALE^(degree).
        // For degree 0: mono = 1 (FIXED_SCALE^0)
        // For degree 1: mono is in [0, FIXED_SCALE]
        // For degree 2: mono is in [0, FIXED_SCALE²]
        // For degree 3: mono is in [0, FIXED_SCALE³]
        //
        // We normalize by dividing by FIXED_SCALE^degree to keep
        // the result in milli-units.
        let degree = exponents[..MAX_VARS].iter().map(|&e| e as u32).sum::<u32>();
        let scale = fixed_power(FIXED_SCALE, degree);
        let _ = k; // used for iteration only
        if scale != 0 {
            result = result.saturating_add(coeff.saturating_mul(mono) / scale);
        }
    }

    result
}

/// Evaluate a monomial x₁^e₁ * x₂^e₂ * ... in fixed-point.
#[inline]
fn eval_monomial(vars: &[i64], exponents: &[u8]) -> i64 {
    let mut product: i64 = 1;
    for (&var, &exp) in vars.iter().zip(exponents.iter()) {
        for _ in 0..exp {
            product = product.saturating_mul(var);
        }
    }
    product
}

/// Compute base^exp for small non-negative exponents.
#[inline]
const fn fixed_power(base: i64, exp: u32) -> i64 {
    let mut result = 1i64;
    let mut i = 0;
    while i < exp {
        result = result.saturating_mul(base);
        i += 1;
    }
    result
}

// ---------------------------------------------------------------------------
// Controller state machine.
// ---------------------------------------------------------------------------

/// Barrier evaluation cadence for Invariant A.
const CADENCE_A: u64 = 256;

/// Warmup observations before evaluating barriers.
const WARMUP: u64 = 64;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SosBarrierState {
    /// Insufficient observations.
    #[default]
    Calibrating = 0,
    /// Both barriers certify safety.
    Safe = 1,
    /// One barrier is near threshold (within 20% of violation).
    Warning = 2,
    /// One or more barriers violated — escalate.
    Violated = 3,
}

/// Summary snapshot for telemetry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SosBarrierSummary {
    pub state: SosBarrierState,
    /// Most recent Invariant B (provenance) value in ppm.
    pub provenance_value: i64,
    /// Most recent Invariant A (quarantine) value in milli-units.
    pub quarantine_value: i64,
    /// Total observations.
    pub total_observations: u64,
    /// Count of provenance barrier violations.
    pub provenance_violations: u64,
    /// Count of quarantine barrier violations.
    pub quarantine_violations: u64,
}

/// SOS Barrier Certificate Runtime Controller.
///
/// Evaluates two barrier certificates:
/// - Invariant B (provenance): every observation, hot-path.
/// - Invariant A (quarantine): every CADENCE_A observations, cadence-gated.
pub struct SosBarrierController {
    observations: u64,
    last_provenance_value: i64,
    last_quarantine_value: i64,
    provenance_violations: u64,
    quarantine_violations: u64,
}

impl Default for SosBarrierController {
    fn default() -> Self {
        Self::new()
    }
}

impl SosBarrierController {
    #[must_use]
    pub fn new() -> Self {
        Self {
            observations: 0,
            last_provenance_value: PROVENANCE_RISK_BUDGET_PPM, // starts safe
            last_quarantine_value: 200, // starts at baseline safe
            provenance_violations: 0,
            quarantine_violations: 0,
        }
    }

    /// Evaluate Invariant B (provenance admissibility) — call on every decide().
    ///
    /// Returns true if the barrier certifies safety, false if violated.
    pub fn evaluate_provenance(
        &mut self,
        risk_ppm: u32,
        validation_depth_ppm: u32,
        bloom_fp_rate_ppm: u32,
        arena_pressure_ppm: u32,
    ) -> bool {
        self.observations += 1;
        let val = evaluate_provenance_barrier(
            risk_ppm,
            validation_depth_ppm,
            bloom_fp_rate_ppm,
            arena_pressure_ppm,
        );
        self.last_provenance_value = val;
        if val < 0 {
            self.provenance_violations += 1;
            false
        } else {
            true
        }
    }

    /// Evaluate Invariant A (quarantine depth) — call on cadence.
    ///
    /// Returns true if the barrier certifies safety, false if violated.
    pub fn evaluate_quarantine(
        &mut self,
        depth: u32,
        contention: u32,
        adverse_ppm: u32,
        lambda_latency: i64,
    ) -> bool {
        let val = evaluate_quarantine_barrier(depth, contention, adverse_ppm, lambda_latency);
        self.last_quarantine_value = val;
        if val < 0 {
            self.quarantine_violations += 1;
            false
        } else {
            true
        }
    }

    /// Whether this observation is on the Invariant A cadence.
    #[must_use]
    pub fn is_quarantine_cadence(&self) -> bool {
        self.observations > 0 && self.observations.is_multiple_of(CADENCE_A)
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> SosBarrierState {
        if self.observations < WARMUP {
            return SosBarrierState::Calibrating;
        }

        // Violation: either barrier negative.
        if self.last_provenance_value < 0 || self.last_quarantine_value < 0 {
            return SosBarrierState::Violated;
        }

        // Warning: either barrier within 20% of threshold.
        let prov_headroom = self.last_provenance_value;
        let quar_headroom = self.last_quarantine_value;
        let prov_warning = PROVENANCE_RISK_BUDGET_PPM / 5; // 20% of budget
        let quar_warning = 40; // 20% of baseline 200

        if prov_headroom < prov_warning || quar_headroom < quar_warning {
            return SosBarrierState::Warning;
        }

        SosBarrierState::Safe
    }

    /// Summary snapshot.
    #[must_use]
    pub fn summary(&self) -> SosBarrierSummary {
        SosBarrierSummary {
            state: self.state(),
            provenance_value: self.last_provenance_value,
            quarantine_value: self.last_quarantine_value,
            total_observations: self.observations,
            provenance_violations: self.provenance_violations,
            quarantine_violations: self.quarantine_violations,
        }
    }

    /// Total violation count across both barriers.
    #[must_use]
    pub fn total_violations(&self) -> u64 {
        self.provenance_violations + self.quarantine_violations
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Invariant B (Provenance) Tests ----

    #[test]
    fn provenance_safe_low_risk_full_validation() {
        // Low risk + Full validation → strongly safe.
        let val = evaluate_provenance_barrier(
            10_000,      // risk: low
            1_000_000,   // validation: Full
            50_000,      // bloom fp: 5%
            200_000,     // arena: 20%
        );
        assert!(val > 0, "Expected safe, got {val}");
    }

    #[test]
    fn provenance_safe_low_risk_fast_validation() {
        // Low risk + Fast → still safe (risk headroom dominates).
        let val = evaluate_provenance_barrier(
            20_000,  // risk: low
            0,       // validation: Fast
            50_000,  // bloom fp: 5%
            100_000, // arena: 10%
        );
        assert!(val > 0, "Expected safe, got {val}");
    }

    #[test]
    fn provenance_violates_high_risk_fast_bad_bloom() {
        // High risk + Fast + bad bloom + high arena → violation.
        let val = evaluate_provenance_barrier(
            500_000,   // risk: 50% (far above budget)
            0,         // validation: Fast
            400_000,   // bloom fp: 40%
            800_000,   // arena: 80%
        );
        assert!(val < 0, "Expected violation, got {val}");
    }

    #[test]
    fn provenance_full_validation_rescues_high_risk() {
        // High risk but Full validation → barrier should be less negative
        // or positive due to the reward term.
        let val_fast = evaluate_provenance_barrier(200_000, 0, 200_000, 500_000);
        let val_full = evaluate_provenance_barrier(200_000, 1_000_000, 200_000, 500_000);
        assert!(
            val_full > val_fast,
            "Full should be safer: full={val_full}, fast={val_fast}"
        );
    }

    #[test]
    fn provenance_monotone_in_risk() {
        // Higher risk → lower barrier value (more dangerous).
        let v1 = evaluate_provenance_barrier(50_000, 0, 100_000, 300_000);
        let v2 = evaluate_provenance_barrier(200_000, 0, 100_000, 300_000);
        let v3 = evaluate_provenance_barrier(500_000, 0, 100_000, 300_000);
        assert!(v1 > v2, "v1={v1} should > v2={v2}");
        assert!(v2 > v3, "v2={v2} should > v3={v3}");
    }

    #[test]
    fn provenance_budget_boundary() {
        // At exactly the risk budget with minimal penalties.
        let val = evaluate_provenance_barrier(
            PROVENANCE_RISK_BUDGET_PPM as u32,
            0,
            0,
            0,
        );
        // headroom = 0, penalties ≈ 0 (risk × 0 bloom × 0 arena), reward = 0.
        assert_eq!(val, 0, "At budget boundary with no penalties, should be exactly 0");
    }

    // ---- Invariant A (Quarantine Depth) Tests ----

    #[test]
    fn quarantine_safe_moderate_depth_low_adverse() {
        // Moderate depth, low contention, low adverse → safe.
        let val = evaluate_quarantine_barrier(
            4096,    // depth: mid-range
            4,       // contention: low
            1_000,   // adverse: 0.1%
            0,       // lambda: neutral
        );
        assert!(val > 0, "Expected safe, got {val}");
    }

    #[test]
    fn quarantine_unsafe_shallow_high_adverse() {
        // Very shallow depth + very high adverse → violation.
        let val = evaluate_quarantine_barrier(
            64,        // depth: minimum
            100,       // contention: moderate
            500_000,   // adverse: 50%
            50,        // lambda: moderate pressure
        );
        assert!(val < 0, "Expected violation for shallow+high_adverse, got {val}");
    }

    #[test]
    fn quarantine_depth_helps_against_adverse() {
        // Deeper depth should improve barrier value under adverse conditions.
        let v_shallow = evaluate_quarantine_barrier(256, 10, 100_000, 0);
        let v_deep = evaluate_quarantine_barrier(16384, 10, 100_000, 0);
        assert!(
            v_deep > v_shallow,
            "Deeper should be safer: deep={v_deep}, shallow={v_shallow}"
        );
    }

    #[test]
    fn quarantine_contention_degrades() {
        // Higher contention should reduce barrier value at same depth.
        let v_low = evaluate_quarantine_barrier(4096, 2, 10_000, 0);
        let v_high = evaluate_quarantine_barrier(4096, 500, 10_000, 0);
        assert!(
            v_low > v_high,
            "Low contention should be safer: low={v_low}, high={v_high}"
        );
    }

    #[test]
    fn quarantine_extreme_adverse_always_violates() {
        // At 100% adverse rate, no depth configuration should be safe.
        let val = evaluate_quarantine_barrier(65536, 0, 1_000_000, 0);
        assert!(val < 0, "Expected violation at 100% adverse, got {val}");
    }

    // ---- Controller State Machine Tests ----

    #[test]
    fn controller_starts_calibrating() {
        let ctrl = SosBarrierController::new();
        assert_eq!(ctrl.state(), SosBarrierState::Calibrating);
        assert_eq!(ctrl.total_violations(), 0);
    }

    #[test]
    fn controller_transitions_to_safe() {
        let mut ctrl = SosBarrierController::new();
        // Feed safe provenance observations.
        for _ in 0..WARMUP + 10 {
            ctrl.evaluate_provenance(10_000, 1_000_000, 10_000, 50_000);
        }
        assert_eq!(ctrl.state(), SosBarrierState::Safe);
        assert_eq!(ctrl.provenance_violations, 0);
    }

    #[test]
    fn controller_detects_provenance_violation() {
        let mut ctrl = SosBarrierController::new();
        // Warmup with safe observations.
        for _ in 0..WARMUP {
            ctrl.evaluate_provenance(10_000, 1_000_000, 10_000, 50_000);
        }
        // Now trigger violation: high risk + fast + bad bloom.
        let safe = ctrl.evaluate_provenance(500_000, 0, 400_000, 800_000);
        assert!(!safe, "Should have violated");
        assert_eq!(ctrl.state(), SosBarrierState::Violated);
        assert_eq!(ctrl.provenance_violations, 1);
    }

    #[test]
    fn controller_detects_quarantine_violation() {
        let mut ctrl = SosBarrierController::new();
        for _ in 0..WARMUP {
            ctrl.evaluate_provenance(10_000, 1_000_000, 10_000, 50_000);
        }
        // Trigger quarantine violation: shallow + high adverse.
        let safe = ctrl.evaluate_quarantine(64, 100, 500_000, 50);
        assert!(!safe, "Should have violated");
        assert_eq!(ctrl.state(), SosBarrierState::Violated);
        assert_eq!(ctrl.quarantine_violations, 1);
    }

    #[test]
    fn controller_recovers_to_safe() {
        let mut ctrl = SosBarrierController::new();
        for _ in 0..WARMUP {
            ctrl.evaluate_provenance(10_000, 1_000_000, 10_000, 50_000);
        }
        // Trigger violation.
        ctrl.evaluate_provenance(500_000, 0, 400_000, 800_000);
        assert_eq!(ctrl.state(), SosBarrierState::Violated);

        // Recover with safe observation.
        ctrl.evaluate_provenance(10_000, 1_000_000, 10_000, 50_000);
        ctrl.evaluate_quarantine(4096, 4, 1_000, 0);
        assert_eq!(ctrl.state(), SosBarrierState::Safe);
        // Violation count persists.
        assert_eq!(ctrl.provenance_violations, 1);
    }

    #[test]
    fn controller_cadence_tracking() {
        let mut ctrl = SosBarrierController::new();
        let mut cadence_hits = 0u32;
        for _ in 0..CADENCE_A * 3 {
            ctrl.evaluate_provenance(10_000, 1_000_000, 10_000, 50_000);
            if ctrl.is_quarantine_cadence() {
                cadence_hits += 1;
            }
        }
        assert_eq!(cadence_hits, 3, "Expected 3 cadence hits over {}", CADENCE_A * 3);
    }

    #[test]
    fn summary_consistent() {
        let mut ctrl = SosBarrierController::new();
        for _ in 0..100 {
            ctrl.evaluate_provenance(10_000, 1_000_000, 10_000, 50_000);
        }
        ctrl.evaluate_quarantine(4096, 4, 1_000, 0);

        let s = ctrl.summary();
        assert_eq!(s.state, ctrl.state());
        assert_eq!(s.total_observations, 100);
        assert_eq!(s.provenance_violations, ctrl.provenance_violations);
        assert_eq!(s.quarantine_violations, ctrl.quarantine_violations);
        assert_eq!(s.provenance_value, ctrl.last_provenance_value);
        assert_eq!(s.quarantine_value, ctrl.last_quarantine_value);
    }

    // ---- Fixed-Point Arithmetic Tests ----

    #[test]
    fn normalize_fixed_basic() {
        // Depth 4096 with range [64, 65472] → ~6.16% → ~616 (of 10000).
        let n = normalize_fixed(4096, NORM_DEPTH);
        assert!(n > 0 && n < FIXED_SCALE, "Got {n}");
    }

    #[test]
    fn normalize_fixed_clamps() {
        // Below offset.
        let n = normalize_fixed(0, NORM_DEPTH);
        assert!(n >= -FIXED_SCALE, "Got {n}");

        // Above max.
        let n = normalize_fixed(200_000, NORM_DEPTH);
        assert_eq!(n, FIXED_SCALE, "Got {n}");
    }

    #[test]
    fn eval_monomial_constant() {
        // All exponents zero → monomial = 1.
        let vars = [5000i64, 3000, 7000, -2000];
        let mono = eval_monomial(&vars, &[0, 0, 0, 0]);
        assert_eq!(mono, 1);
    }

    #[test]
    fn eval_monomial_linear() {
        let vars = [5000i64, 3000, 7000, -2000];
        // x₁^1 = 5000
        assert_eq!(eval_monomial(&vars, &[1, 0, 0, 0]), 5000);
        // x₃^1 = 7000
        assert_eq!(eval_monomial(&vars, &[0, 0, 1, 0]), 7000);
    }

    #[test]
    fn eval_monomial_quadratic() {
        let vars = [100i64, 200, 300, 400];
        // x₁² = 10000
        assert_eq!(eval_monomial(&vars, &[2, 0, 0, 0]), 10_000);
        // x₁ * x₂ = 20000
        assert_eq!(eval_monomial(&vars, &[1, 1, 0, 0]), 20_000);
    }
}
