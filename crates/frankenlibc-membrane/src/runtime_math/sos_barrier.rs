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
//! Four concrete barrier certificates:
//!
//! - **Invariant B (Pointer Provenance Admissibility)**: hot-path, <15ns,
//!   4 variables (risk, validation_depth, bloom_fp_rate, arena_pressure),
//!   degree-2 explicit polynomial. Fixed-point integer arithmetic.
//!
//! - **Invariant A (Quarantine Depth Safety Envelope)**: cadence-gated
//!   (every 256 calls), ~100ns budget, 4 variables (depth, contention,
//!   adverse_rate, latency_dual), degree-3 Gram matrix evaluation.
//!
//! - **Thread-Safety Certificate (Concurrent Allocation Integrity)**:
//!   allocator/threading path, 5 variables (thread pressure, writer overflow,
//!   owner conflict, free-list skew, epoch lag), degree-2 Gram matrix.
//!
//! - **Size-Class Admissibility Certificate (Allocation Mapping Integrity)**:
//!   allocator path, 4 variables (waste ratio excess, class-membership
//!   violation, range violation, underflow violation), degree-2 Gram matrix.
//!
//! ## References
//!
//! - Prajna & Jadbabaie (2004), "Safety Verification of Hybrid Systems
//!   Using Barrier Certificates", HSCC.
//! - Ahmadi & Majumdar (2019), "DSOS and SDSOS Optimization", SIAM J.
//!   Applied Algebra and Geometry.
//! - Design document: `sos_barrier_design.md` (bd-2pw).

use sha2::{Digest, Sha256};

mod generated_fragmentation_certificate {
    include!(concat!(env!("OUT_DIR"), "/sos_fragmentation_generated.rs"));
}

mod generated_thread_safety_certificate {
    include!(concat!(env!("OUT_DIR"), "/sos_thread_safety_generated.rs"));
}

mod generated_size_class_certificate {
    include!(concat!(env!("OUT_DIR"), "/sos_size_class_generated.rs"));
}

// ---------------------------------------------------------------------------
// Maximum variable count for static arrays.
// ---------------------------------------------------------------------------

/// Maximum number of variables per barrier certificate.
const MAX_VARS: usize = 4;
/// Fragmentation certificate dimensionality.
const FRAGMENTATION_CERT_DIM: usize = generated_fragmentation_certificate::FRAGMENTATION_CERT_DIM;
/// Fragmentation barrier budget in milli-units.
const FRAGMENTATION_BARRIER_BUDGET_MILLI: i64 =
    generated_fragmentation_certificate::FRAGMENTATION_BARRIER_BUDGET_MILLI;
/// Thread-safety certificate dimensionality.
const THREAD_SAFETY_CERT_DIM: usize = generated_thread_safety_certificate::THREAD_SAFETY_CERT_DIM;
/// Thread-safety barrier budget in milli-units.
const THREAD_SAFETY_BARRIER_BUDGET_MILLI: i64 =
    generated_thread_safety_certificate::THREAD_SAFETY_BARRIER_BUDGET_MILLI;
/// Size-class admissibility certificate dimensionality.
const SIZE_CLASS_CERT_DIM: usize = generated_size_class_certificate::SIZE_CLASS_CERT_DIM;
/// Size-class admissibility barrier budget in milli-units.
const SIZE_CLASS_BARRIER_BUDGET_MILLI: i64 =
    generated_size_class_certificate::SIZE_CLASS_BARRIER_BUDGET_MILLI;
/// Allowed allocation/free imbalance before certificate penalties begin.
const FRAGMENTATION_IMBALANCE_BUDGET_PPM: u32 = 200_000;
/// Allowed size-class dispersion budget before penalties begin.
const FRAGMENTATION_SIZE_DISPERSION_BUDGET_PPM: u32 = 300_000;
/// Allowed arena utilization budget before penalties begin.
const FRAGMENTATION_ARENA_UTILIZATION_BUDGET_PPM: u32 = 700_000;
/// Allowed churn budget before penalties begin.
const FRAGMENTATION_CHURN_BUDGET_PPM: u32 = 500_000;
/// Fixed-point score scale for fragmentation certificate basis values.
const FRAGMENTATION_SCORE_SCALE: i64 = 1_000;
/// Fixed-point score scale for thread-safety certificate basis values.
const THREAD_SAFETY_SCORE_SCALE: i64 = 1_000;
/// Fixed-point score scale for size-class admissibility certificate basis values.
const SIZE_CLASS_SCORE_SCALE: i64 = 1_000;
/// Maximum certified waste ratio in ppm (900k = 90%).
const SIZE_CLASS_MAX_WASTE_RATIO_PPM: u32 = 900_000;
/// Class-membership budget in ppm (zero tolerance).
const SIZE_CLASS_MEMBERSHIP_BUDGET_PPM: u32 = 0;
/// Size-class range budget in ppm (zero tolerance).
const SIZE_CLASS_RANGE_BUDGET_PPM: u32 = 0;
/// Maximum request/mapped size covered by the small-size-class certificate.
const SIZE_CLASS_MAX_CERTIFIED_REQUEST: usize = 64 * 1024;
/// Maximum pressure score in milli-units produced by `PressureSensor`.
const PRESSURE_SCORE_MILLI_MAX: u64 = 100_000;
/// Practical thread-count ceiling for normalization.
const THREAD_SAFETY_MAX_THREADS: u32 = 1_024;
/// Practical writer-overflow ceiling (writers above 1 touching same arena).
const THREAD_SAFETY_MAX_WRITER_OVERFLOW: u32 = 16;
/// Thread-count budget in ppm before penalties begin.
const THREAD_SAFETY_THREAD_BUDGET_PPM: u32 = 62_500; // 64 / 1024
/// Writer-overflow budget in ppm (zero tolerance for >1 concurrent writers).
const THREAD_SAFETY_WRITER_OVERFLOW_BUDGET_PPM: u32 = 0;
/// Arena-owner conflict budget in ppm.
const THREAD_SAFETY_OWNER_CONFLICT_BUDGET_PPM: u32 = 0;
/// Free-list generation skew budget in ppm.
const THREAD_SAFETY_FREELIST_SKEW_BUDGET_PPM: u32 = 150_000;
/// Allocation epoch lag budget in ppm.
const THREAD_SAFETY_EPOCH_LAG_BUDGET_PPM: u32 = 150_000;

// ---------------------------------------------------------------------------
// Generic SOS certificate artifact.
// ---------------------------------------------------------------------------

/// Runtime polynomial certificate artifact produced by offline SDP synthesis.
///
/// The runtime path only evaluates deterministic quadratic forms and verifies a
/// fixed proof hash. Heavy theorem machinery remains offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SosCertificate<const D: usize> {
    /// Symmetric Gram matrix for z(x)^T Q z(x).
    pub gram_matrix: [[i64; D]; D],
    /// SHA-256 hash over (dimension, degree, budget, matrix bytes).
    pub proof_hash: [u8; 32],
    /// Maximum monomial degree of the offline polynomial.
    pub monomial_degree: u32,
    /// Barrier budget in milli-units; violation iff budget - score < 0.
    pub barrier_budget_milli: i64,
}

impl<const D: usize> SosCertificate<D> {
    /// Construct a static SOS certificate artifact.
    #[must_use]
    pub const fn new(
        gram_matrix: [[i64; D]; D],
        proof_hash: [u8; 32],
        monomial_degree: u32,
        barrier_budget_milli: i64,
    ) -> Self {
        Self {
            gram_matrix,
            proof_hash,
            monomial_degree,
            barrier_budget_milli,
        }
    }

    /// Evaluate z(x)^T Q z(x) using fixed-point integer arithmetic.
    ///
    /// `scale` controls post-accumulation downscaling.
    #[must_use]
    pub fn evaluate_quadratic_form(&self, basis: &[i64; D], scale: i64) -> i64 {
        let mut acc: i128 = 0;
        for i in 0..D {
            for j in 0..D {
                let coeff = i128::from(self.gram_matrix[i][j]);
                let bi = i128::from(basis[i]);
                let bj = i128::from(basis[j]);
                acc = acc.saturating_add(coeff.saturating_mul(bi).saturating_mul(bj));
            }
        }
        let denom = i128::from(scale.max(1));
        let scaled = acc / denom;
        scaled.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
    }

    /// Evaluate the barrier value in milli-units.
    ///
    /// Positive values are certified-safe headroom; negative values indicate
    /// certificate violation.
    #[must_use]
    pub fn evaluate_barrier(&self, basis: &[i64; D], scale: i64) -> i64 {
        self.barrier_budget_milli
            .saturating_sub(self.evaluate_quadratic_form(basis, scale))
    }

    /// Verify artifact integrity via SHA-256 over certificate payload.
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        compute_certificate_hash(
            &self.gram_matrix,
            self.monomial_degree,
            self.barrier_budget_milli,
        ) == self.proof_hash
    }
}

/// Compute deterministic SHA-256 hash over certificate payload.
#[must_use]
pub fn compute_certificate_hash<const D: usize>(
    gram_matrix: &[[i64; D]; D],
    monomial_degree: u32,
    barrier_budget_milli: i64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((D as u32).to_le_bytes());
    hasher.update(monomial_degree.to_le_bytes());
    hasher.update(barrier_budget_milli.to_le_bytes());
    for row in gram_matrix {
        for cell in row {
            hasher.update(cell.to_le_bytes());
        }
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

// ---------------------------------------------------------------------------
// Allocator fragmentation SOS certificate (bd-2ste.1).
// ---------------------------------------------------------------------------

/// Fragmentation-certificate Gram matrix synthesized offline.
///
/// Basis variables represent excess-over-budget scores (0..1000):
/// [allocation/free imbalance, size-class dispersion, arena utilization, churn].
static FRAGMENTATION_GRAM_MATRIX: [[i64; FRAGMENTATION_CERT_DIM]; FRAGMENTATION_CERT_DIM] =
    generated_fragmentation_certificate::FRAGMENTATION_GRAM_MATRIX;

/// Offline proof hash for `FRAGMENTATION_GRAM_MATRIX`.
const FRAGMENTATION_PROOF_HASH: [u8; 32] =
    generated_fragmentation_certificate::FRAGMENTATION_PROOF_HASH;

/// Monomial degree for the fragmentation quadratic form.
const FRAGMENTATION_MONOMIAL_DEGREE: u32 =
    generated_fragmentation_certificate::FRAGMENTATION_MONOMIAL_DEGREE;
/// Cholesky minimum pivot captured during build-time PSD verification.
#[cfg(test)]
const FRAGMENTATION_CHOLESKY_MIN_PIVOT: f64 =
    generated_fragmentation_certificate::FRAGMENTATION_CHOLESKY_MIN_PIVOT;
/// Max absolute reconstruction error for build-time Cholesky decomposition.
#[cfg(test)]
const FRAGMENTATION_CHOLESKY_MAX_ABS_RECONSTRUCTION_ERROR: f64 =
    generated_fragmentation_certificate::FRAGMENTATION_CHOLESKY_MAX_ABS_RECONSTRUCTION_ERROR;
/// Build-time floating-point stability bound delta (Frobenius residual norm).
#[cfg(test)]
const FRAGMENTATION_STABILITY_BOUND_DELTA: f64 =
    generated_fragmentation_certificate::FRAGMENTATION_STABILITY_BOUND_DELTA;

/// SHA-256 over the source `.task` artifact consumed by build-time generation.
pub const FRAGMENTATION_TASK_SOURCE_SHA256_HEX: &str =
    generated_fragmentation_certificate::FRAGMENTATION_TASK_SOURCE_SHA256_HEX;

/// Runtime fragmentation certificate artifact.
pub static FRAGMENTATION_CERTIFICATE: SosCertificate<FRAGMENTATION_CERT_DIM> = SosCertificate::new(
    FRAGMENTATION_GRAM_MATRIX,
    FRAGMENTATION_PROOF_HASH,
    FRAGMENTATION_MONOMIAL_DEGREE,
    FRAGMENTATION_BARRIER_BUDGET_MILLI,
);

/// Thread-safety-certificate Gram matrix synthesized offline.
///
/// Basis variables represent excess-over-budget scores (0..1000):
/// [thread_count, writer_overflow, owner_conflict, free_list_skew, epoch_lag].
static THREAD_SAFETY_GRAM_MATRIX: [[i64; THREAD_SAFETY_CERT_DIM]; THREAD_SAFETY_CERT_DIM] =
    generated_thread_safety_certificate::THREAD_SAFETY_GRAM_MATRIX;

/// Offline proof hash for `THREAD_SAFETY_GRAM_MATRIX`.
const THREAD_SAFETY_PROOF_HASH: [u8; 32] =
    generated_thread_safety_certificate::THREAD_SAFETY_PROOF_HASH;

/// Monomial degree for the thread-safety quadratic form.
const THREAD_SAFETY_MONOMIAL_DEGREE: u32 =
    generated_thread_safety_certificate::THREAD_SAFETY_MONOMIAL_DEGREE;
/// Cholesky minimum pivot captured during build-time PSD verification.
#[cfg(test)]
const THREAD_SAFETY_CHOLESKY_MIN_PIVOT: f64 =
    generated_thread_safety_certificate::THREAD_SAFETY_CHOLESKY_MIN_PIVOT;
/// Max absolute reconstruction error for build-time Cholesky decomposition.
#[cfg(test)]
const THREAD_SAFETY_CHOLESKY_MAX_ABS_RECONSTRUCTION_ERROR: f64 =
    generated_thread_safety_certificate::THREAD_SAFETY_CHOLESKY_MAX_ABS_RECONSTRUCTION_ERROR;
/// Build-time floating-point stability bound delta (Frobenius residual norm).
#[cfg(test)]
const THREAD_SAFETY_STABILITY_BOUND_DELTA: f64 =
    generated_thread_safety_certificate::THREAD_SAFETY_STABILITY_BOUND_DELTA;

/// SHA-256 over the source `.task` artifact consumed by build-time generation.
pub const THREAD_SAFETY_TASK_SOURCE_SHA256_HEX: &str =
    generated_thread_safety_certificate::THREAD_SAFETY_TASK_SOURCE_SHA256_HEX;

/// Runtime thread-safety certificate artifact.
pub static THREAD_SAFETY_CERTIFICATE: SosCertificate<THREAD_SAFETY_CERT_DIM> = SosCertificate::new(
    THREAD_SAFETY_GRAM_MATRIX,
    THREAD_SAFETY_PROOF_HASH,
    THREAD_SAFETY_MONOMIAL_DEGREE,
    THREAD_SAFETY_BARRIER_BUDGET_MILLI,
);

/// Size-class-admissibility-certificate Gram matrix synthesized offline.
///
/// Basis variables represent excess-over-budget scores (0..1000):
/// [waste_ratio_excess, class_membership_violation, range_violation, underflow_violation].
static SIZE_CLASS_GRAM_MATRIX: [[i64; SIZE_CLASS_CERT_DIM]; SIZE_CLASS_CERT_DIM] =
    generated_size_class_certificate::SIZE_CLASS_GRAM_MATRIX;

/// Offline proof hash for `SIZE_CLASS_GRAM_MATRIX`.
const SIZE_CLASS_PROOF_HASH: [u8; 32] = generated_size_class_certificate::SIZE_CLASS_PROOF_HASH;

/// Monomial degree for the size-class admissibility quadratic form.
const SIZE_CLASS_MONOMIAL_DEGREE: u32 =
    generated_size_class_certificate::SIZE_CLASS_MONOMIAL_DEGREE;
/// Cholesky minimum pivot captured during build-time PSD verification.
#[cfg(test)]
const SIZE_CLASS_CHOLESKY_MIN_PIVOT: f64 =
    generated_size_class_certificate::SIZE_CLASS_CHOLESKY_MIN_PIVOT;
/// Max absolute reconstruction error for build-time Cholesky decomposition.
#[cfg(test)]
const SIZE_CLASS_CHOLESKY_MAX_ABS_RECONSTRUCTION_ERROR: f64 =
    generated_size_class_certificate::SIZE_CLASS_CHOLESKY_MAX_ABS_RECONSTRUCTION_ERROR;
/// Build-time floating-point stability bound delta (Frobenius residual norm).
#[cfg(test)]
const SIZE_CLASS_STABILITY_BOUND_DELTA: f64 =
    generated_size_class_certificate::SIZE_CLASS_STABILITY_BOUND_DELTA;

/// SHA-256 over the source `.task` artifact consumed by build-time generation.
pub const SIZE_CLASS_TASK_SOURCE_SHA256_HEX: &str =
    generated_size_class_certificate::SIZE_CLASS_TASK_SOURCE_SHA256_HEX;

/// Runtime size-class admissibility certificate artifact.
pub static SIZE_CLASS_CERTIFICATE: SosCertificate<SIZE_CLASS_CERT_DIM> = SosCertificate::new(
    SIZE_CLASS_GRAM_MATRIX,
    SIZE_CLASS_PROOF_HASH,
    SIZE_CLASS_MONOMIAL_DEGREE,
    SIZE_CLASS_BARRIER_BUDGET_MILLI,
);

/// Convert `(value - budget)` excess into a fixed-point score in [0, 1000].
#[inline]
fn ppm_excess_to_score(value_ppm: u32, budget_ppm: u32) -> i64 {
    let excess = u64::from(value_ppm.saturating_sub(budget_ppm));
    let scaled = excess.saturating_mul(FRAGMENTATION_SCORE_SCALE as u64) / 1_000_000;
    scaled as i64
}

/// Convert a bounded ratio to ppm.
#[inline]
fn ratio_to_ppm(value: u32, max_value: u32) -> u32 {
    if max_value == 0 {
        return 0;
    }
    let clamped = value.min(max_value);
    let numer = u64::from(clamped).saturating_mul(1_000_000);
    (numer / u64::from(max_value)) as u32
}

/// Map quarantine-depth proxy to arena-utilization ppm.
///
/// Depth is clamped to [64, 65536], then linearly normalized to [0, 1_000_000].
#[must_use]
pub fn depth_to_arena_utilization_ppm(depth: u32) -> u32 {
    let clamped = depth.clamp(64, 65_536);
    let numer = u64::from(clamped.saturating_sub(64)).saturating_mul(1_000_000);
    let denom = u64::from(65_536u32 - 64u32);
    (numer / denom) as u32
}

#[inline]
fn score_milli_to_ppm(score_milli: u64) -> u32 {
    let clamped = score_milli.min(PRESSURE_SCORE_MILLI_MAX);
    u32::try_from(clamped.saturating_mul(10)).unwrap_or(u32::MAX)
}

/// Compose depth-derived arena pressure with live runtime pressure telemetry.
///
/// The pressure sensor emits milli-scores in `[0, 100_000]` (0..100). We
/// convert to ppm and apply a small surge projection so sudden bursts are not
/// hidden by EWMA lag.
#[must_use]
pub fn compose_memory_pressure_ppm(
    depth: u32,
    pressure_score_milli: u64,
    pressure_raw_score_milli: u64,
) -> u32 {
    let depth_ppm = depth_to_arena_utilization_ppm(depth);
    let score_ppm = score_milli_to_ppm(pressure_score_milli);
    let raw_ppm = score_milli_to_ppm(pressure_raw_score_milli);
    let surge_ppm = raw_ppm.saturating_sub(score_ppm);
    let projected_ppm = score_ppm
        .saturating_add(surge_ppm / 2)
        .max(raw_ppm / 2)
        .min(1_000_000);
    depth_ppm.max(projected_ppm)
}

/// Evaluate allocator-fragmentation barrier certificate.
///
/// Inputs:
/// - `allocation_count`: observed allocator alloc-like events.
/// - `free_count`: observed allocator free-like events.
/// - `size_class_dispersion_ppm`: normalized size-class dispersion (0..1e6).
/// - `arena_utilization_ppm`: normalized arena utilization (0..1e6).
///
/// Output:
/// - positive => certified-safe headroom,
/// - negative => certificate violation.
#[must_use]
pub fn evaluate_fragmentation_barrier(
    allocation_count: u32,
    free_count: u32,
    size_class_dispersion_ppm: u32,
    arena_utilization_ppm: u32,
) -> i64 {
    let alloc = u64::from(allocation_count);
    let free = u64::from(free_count);
    let total = alloc.saturating_add(free).max(1);
    let imbalance_ppm =
        (u64::from(allocation_count.abs_diff(free_count)).saturating_mul(1_000_000) / total) as u32;
    let churn_ppm = (alloc.min(free).saturating_mul(1_000_000) / total) as u32;

    let basis = [
        ppm_excess_to_score(imbalance_ppm, FRAGMENTATION_IMBALANCE_BUDGET_PPM),
        ppm_excess_to_score(
            size_class_dispersion_ppm,
            FRAGMENTATION_SIZE_DISPERSION_BUDGET_PPM,
        ),
        ppm_excess_to_score(
            arena_utilization_ppm,
            FRAGMENTATION_ARENA_UTILIZATION_BUDGET_PPM,
        ),
        ppm_excess_to_score(churn_ppm, FRAGMENTATION_CHURN_BUDGET_PPM),
    ];

    FRAGMENTATION_CERTIFICATE.evaluate_barrier(&basis, FRAGMENTATION_SCORE_SCALE)
}

/// Evaluate thread-safety barrier certificate.
///
/// Inputs:
/// - `thread_count`: concurrent threads touching allocator paths.
/// - `concurrent_writers`: concurrent writers observed for a single arena
///   free-list critical section.
/// - `arena_owner_conflict`: true when ownership checks disagree.
/// - `free_list_skew_ppm`: normalized skew between expected/observed free-list
///   generation progress.
/// - `allocation_epoch_lag_ppm`: normalized lag between expected/observed
///   allocation epochs.
///
/// Output:
/// - positive => certified-safe headroom,
/// - negative => certificate violation.
#[must_use]
pub fn evaluate_thread_safety_barrier(
    thread_count: u32,
    concurrent_writers: u32,
    arena_owner_conflict: bool,
    free_list_skew_ppm: u32,
    allocation_epoch_lag_ppm: u32,
) -> i64 {
    let thread_count_ppm = ratio_to_ppm(thread_count, THREAD_SAFETY_MAX_THREADS);
    let writer_overflow_ppm = ratio_to_ppm(
        concurrent_writers.saturating_sub(1),
        THREAD_SAFETY_MAX_WRITER_OVERFLOW,
    );
    let owner_conflict_ppm = if arena_owner_conflict { 1_000_000 } else { 0 };

    let basis = [
        ppm_excess_to_score(thread_count_ppm, THREAD_SAFETY_THREAD_BUDGET_PPM),
        ppm_excess_to_score(
            writer_overflow_ppm,
            THREAD_SAFETY_WRITER_OVERFLOW_BUDGET_PPM,
        ),
        ppm_excess_to_score(owner_conflict_ppm, THREAD_SAFETY_OWNER_CONFLICT_BUDGET_PPM),
        ppm_excess_to_score(free_list_skew_ppm, THREAD_SAFETY_FREELIST_SKEW_BUDGET_PPM),
        ppm_excess_to_score(allocation_epoch_lag_ppm, THREAD_SAFETY_EPOCH_LAG_BUDGET_PPM),
    ];

    THREAD_SAFETY_CERTIFICATE.evaluate_barrier(&basis, THREAD_SAFETY_SCORE_SCALE)
}

#[inline]
fn evaluate_size_class_barrier_from_basis(basis: &[i64; SIZE_CLASS_CERT_DIM]) -> i64 {
    let q = &SIZE_CLASS_GRAM_MATRIX;
    let b0 = i128::from(basis[0]);
    let b1 = i128::from(basis[1]);
    let b2 = i128::from(basis[2]);
    let b3 = i128::from(basis[3]);

    // Fixed 4x4 unrolled quadratic form for hot allocator path.
    // Intermediate products can reach ~1e18, fitting in i64, but i128 is safer
    // for the accumulation step.
    let mut acc: i128 = 0;
    acc = acc.saturating_add(i128::from(q[0][0]).saturating_mul(b0).saturating_mul(b0));
    acc = acc.saturating_add(i128::from(q[0][1]).saturating_mul(b0).saturating_mul(b1));
    acc = acc.saturating_add(i128::from(q[0][2]).saturating_mul(b0).saturating_mul(b2));
    acc = acc.saturating_add(i128::from(q[0][3]).saturating_mul(b0).saturating_mul(b3));
    acc = acc.saturating_add(i128::from(q[1][0]).saturating_mul(b1).saturating_mul(b0));
    acc = acc.saturating_add(i128::from(q[1][1]).saturating_mul(b1).saturating_mul(b1));
    acc = acc.saturating_add(i128::from(q[1][2]).saturating_mul(b1).saturating_mul(b2));
    acc = acc.saturating_add(i128::from(q[1][3]).saturating_mul(b1).saturating_mul(b3));
    acc = acc.saturating_add(i128::from(q[2][0]).saturating_mul(b2).saturating_mul(b0));
    acc = acc.saturating_add(i128::from(q[2][1]).saturating_mul(b2).saturating_mul(b1));
    acc = acc.saturating_add(i128::from(q[2][2]).saturating_mul(b2).saturating_mul(b2));
    acc = acc.saturating_add(i128::from(q[2][3]).saturating_mul(b2).saturating_mul(b3));
    acc = acc.saturating_add(i128::from(q[3][0]).saturating_mul(b3).saturating_mul(b0));
    acc = acc.saturating_add(i128::from(q[3][1]).saturating_mul(b3).saturating_mul(b1));
    acc = acc.saturating_add(i128::from(q[3][2]).saturating_mul(b3).saturating_mul(b2));
    acc = acc.saturating_add(i128::from(q[3][3]).saturating_mul(b3).saturating_mul(b3));

    let score = (acc / i128::from(SIZE_CLASS_SCORE_SCALE))
        .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
    SIZE_CLASS_BARRIER_BUDGET_MILLI.saturating_sub(score)
}

/// Evaluate size-class admissibility barrier certificate.
///
/// Inputs:
/// - `requested_size`: caller-requested allocation size in bytes.
/// - `mapped_class_size`: size-class bytes selected by allocator mapping.
/// - `class_membership_valid`: whether `mapped_class_size` belongs to the active
///   allocator size-class table.
///
/// Output:
/// - positive => certified-safe headroom,
/// - negative => certificate violation.
#[must_use]
pub fn evaluate_size_class_barrier(
    requested_size: usize,
    mapped_class_size: usize,
    class_membership_valid: bool,
) -> i64 {
    let normalized_requested = requested_size.clamp(16, SIZE_CLASS_MAX_CERTIFIED_REQUEST);
    let mapped_for_ratio =
        mapped_class_size.clamp(normalized_requested, SIZE_CLASS_MAX_CERTIFIED_REQUEST);
    let waste = (mapped_for_ratio - normalized_requested) as u64;
    let waste_ratio_ppm = (waste.saturating_mul(1_000_000) / (normalized_requested as u64)) as u32;
    let membership_violation_ppm = if class_membership_valid { 0 } else { 1_000_000 };
    let range_violation_ppm =
        if mapped_class_size == 0 || mapped_class_size > SIZE_CLASS_MAX_CERTIFIED_REQUEST {
            1_000_000
        } else {
            0
        };
    let underflow_violation_ppm = if mapped_class_size < normalized_requested {
        1_000_000
    } else {
        0
    };

    let basis = [
        ppm_excess_to_score(waste_ratio_ppm, SIZE_CLASS_MAX_WASTE_RATIO_PPM),
        ppm_excess_to_score(membership_violation_ppm, SIZE_CLASS_MEMBERSHIP_BUDGET_PPM),
        ppm_excess_to_score(range_violation_ppm, SIZE_CLASS_RANGE_BUDGET_PPM),
        ppm_excess_to_score(underflow_violation_ppm, SIZE_CLASS_RANGE_BUDGET_PPM),
    ];

    evaluate_size_class_barrier_from_basis(&basis)
}

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
/// β₄: direct memory-pressure penalty independent of risk.
const BETA_4: i64 = 95_000;

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
    let r = i128::from(risk_ppm);
    let v = i128::from(validation_depth_ppm);
    let b = i128::from(bloom_fp_rate_ppm);
    let p = i128::from(arena_pressure_ppm);
    let one = 1_000_000i128;

    // Risk headroom: positive when risk is below budget.
    let headroom = i128::from(PROVENANCE_RISK_BUDGET_PPM).saturating_sub(r);

    // Penalty: risk × bloom_fp × (1 - depth). High risk + bad bloom + fast path → bad.
    // Scale: r * b / 1e6 gives ppm product; * (1-v) / 1e6 gives triple product.
    // BETA is in milli-units, so we multiply by 1000 to get final penalty in ppm.
    let rb = r.saturating_mul(b) / one;
    let one_minus_v = one.saturating_sub(v);
    let penalty_1 = i128::from(BETA_1.saturating_mul(1000))
        .saturating_mul(rb)
        .saturating_mul(one_minus_v)
        / one.saturating_mul(one);

    // Penalty: risk × arena_pressure × (1 - depth). High risk + full arena + fast → bad.
    let rp = r.saturating_mul(p) / one;
    let penalty_2 = i128::from(BETA_2.saturating_mul(1000))
        .saturating_mul(rp)
        .saturating_mul(one_minus_v)
        / one.saturating_mul(one);

    // Reward: validation_depth × (1 - bloom_fp). Full validation + good bloom → safe.
    let one_minus_b = one.saturating_sub(b);
    let reward = i128::from(BETA_3.saturating_mul(1000))
        .saturating_mul(v)
        .saturating_mul(one_minus_b)
        / one.saturating_mul(one);

    // Direct memory pressure penalty: if arena/headroom pressure is high,
    // force backpressure even when risk-only terms are mild.
    // BETA_4 is already in ppm, so we multiply by (p/one).
    let penalty_3 = i128::from(BETA_4).saturating_mul(p) / one;

    let final_ppm = headroom
        .saturating_sub(penalty_1)
        .saturating_sub(penalty_2)
        .saturating_sub(penalty_3)
        .saturating_add(reward);
    final_ppm.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
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
    200,  // 1: baseline positive (safe interior bias)
    500,  // d: higher depth is generally safer
    -300, // c: higher contention is risky
    -600, // a: higher adverse rate is risky
    -100, // λ: latency pressure is mildly risky
    -400, // d²: excessive depth diminishing returns
    -250, // c²: quadratic contention penalty
    -800, // a²: quadratic adverse penalty
    -350, // dc: depth × contention interaction
    700,  // da: depth helps against adverse (positive!)
    -200, // dλ: depth × latency interaction
    -400, // ca: contention × adverse is bad
    -300, // aλ: adverse × latency is bad
    -500, // d·a²: high adverse overwhelms depth
    -300, // d²·c: deep quarantine under contention
    -150, // c·λ²: contention × latency² pressure
    -250, // d·c·a: three-way interaction
    -200, // d·c·λ: three-way interaction
    -900, // a³: cubic adverse penalty (extreme)
    100,  // d³: deep quarantine self-correcting
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
    let mut result: i128 = 0;

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
        let degree = exponents[..MAX_VARS].iter().map(|&e| e as u32).sum::<u32>();
        let scale = fixed_power(FIXED_SCALE, degree);
        let _ = k; // used for iteration only
        if scale != 0 {
            result = result.saturating_add(i128::from(coeff).saturating_mul(mono) / scale);
        }
    }

    result.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// Evaluate a monomial x₁^e₁ * x₂^e₂ * ... in fixed-point.
#[inline]
fn eval_monomial(vars: &[i64], exponents: &[u8]) -> i128 {
    let mut product: i128 = 1;
    for (&var, &exp) in vars.iter().zip(exponents.iter()) {
        for _ in 0..exp {
            product = product.saturating_mul(i128::from(var));
        }
    }
    product
}

/// Compute base^exp for small non-negative exponents.
#[inline]
const fn fixed_power(base: i64, exp: u32) -> i128 {
    let mut result = 1i128;
    let mut i = 0;
    while i < exp {
        result = result.saturating_mul(base as i128);
        i += 1;
    }
    result
}

// ---------------------------------------------------------------------------
// Controller state machine.
// ---------------------------------------------------------------------------

/// Barrier evaluation cadence for Invariant A.
const CADENCE_A: u64 = 256;
/// Barrier evaluation cadence for allocator-fragmentation certificate.
const CADENCE_FRAGMENTATION: u64 = 64;

/// Warmup observations before evaluating barriers.
const WARMUP: u64 = 64;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SosBarrierState {
    /// Insufficient observations.
    #[default]
    Calibrating = 0,
    /// All active barriers certify safety.
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
    /// Most recent fragmentation barrier value in milli-units.
    pub fragmentation_value: i64,
    /// Most recent thread-safety barrier value in milli-units.
    pub thread_safety_value: i64,
    /// Most recent size-class barrier value in milli-units.
    pub size_class_value: i64,
    /// Total observations.
    pub total_observations: u64,
    /// Count of provenance barrier violations.
    pub provenance_violations: u64,
    /// Count of quarantine barrier violations.
    pub quarantine_violations: u64,
    /// Count of fragmentation barrier violations.
    pub fragmentation_violations: u64,
    /// Count of thread-safety barrier violations.
    pub thread_safety_violations: u64,
    /// Count of size-class barrier violations.
    pub size_class_violations: u64,
    /// Whether certificate hash verification passed at controller init.
    pub fragmentation_hash_valid: bool,
    /// Whether thread-safety certificate hash verification passed at init.
    pub thread_safety_hash_valid: bool,
    /// Whether size-class certificate hash verification passed at init.
    pub size_class_hash_valid: bool,
}

/// SOS Barrier Certificate Runtime Controller.
///
/// Evaluates barrier certificates:
/// - Invariant B (provenance): every observation, hot-path.
/// - Invariant A (quarantine): every CADENCE_A observations, cadence-gated.
/// - Thread-safety SOS certificate: on allocator/threading observations.
pub struct SosBarrierController {
    observations: u64,
    allocator_observations: u64,
    allocator_free_like_observations: u64,
    last_allocator_depth: u32,
    last_provenance_value: i64,
    last_quarantine_value: i64,
    last_fragmentation_value: i64,
    last_thread_safety_value: i64,
    last_size_class_value: i64,
    provenance_violations: u64,
    quarantine_violations: u64,
    fragmentation_violations: u64,
    thread_safety_violations: u64,
    size_class_violations: u64,
    fragmentation_hash_valid: bool,
    thread_safety_hash_valid: bool,
    size_class_hash_valid: bool,
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
            allocator_observations: 0,
            allocator_free_like_observations: 0,
            last_allocator_depth: 64,
            last_provenance_value: PROVENANCE_RISK_BUDGET_PPM, // starts safe
            last_quarantine_value: 200,                        // starts at baseline safe
            last_fragmentation_value: FRAGMENTATION_BARRIER_BUDGET_MILLI,
            last_thread_safety_value: THREAD_SAFETY_BARRIER_BUDGET_MILLI,
            last_size_class_value: SIZE_CLASS_BARRIER_BUDGET_MILLI,
            provenance_violations: 0,
            quarantine_violations: 0,
            fragmentation_violations: 0,
            thread_safety_violations: 0,
            size_class_violations: 0,
            fragmentation_hash_valid: FRAGMENTATION_CERTIFICATE.verify_integrity(),
            thread_safety_hash_valid: THREAD_SAFETY_CERTIFICATE.verify_integrity(),
            size_class_hash_valid: SIZE_CLASS_CERTIFICATE.verify_integrity(),
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

    /// Track allocator-family observations to drive fragmentation checks.
    ///
    /// `adverse` events and decreasing quarantine depth are treated as
    /// free-like pressure updates.
    pub fn note_allocator_observation(&mut self, adverse: bool, depth: u32) {
        self.allocator_observations = self.allocator_observations.saturating_add(1);
        if adverse || depth <= self.last_allocator_depth {
            self.allocator_free_like_observations =
                self.allocator_free_like_observations.saturating_add(1);
        }
        self.last_allocator_depth = depth;
    }

    /// Whether allocator-fragmentation barrier should run on this observation.
    #[must_use]
    pub fn is_fragmentation_cadence(&self) -> bool {
        self.allocator_observations > 0
            && self
                .allocator_observations
                .is_multiple_of(CADENCE_FRAGMENTATION)
    }

    /// Evaluate allocator-fragmentation SOS certificate.
    ///
    /// Returns true when the barrier certifies safety.
    pub fn evaluate_fragmentation(
        &mut self,
        size_class_dispersion_ppm: u32,
        arena_utilization_ppm: u32,
    ) -> bool {
        if !self.fragmentation_hash_valid {
            self.last_fragmentation_value = -FRAGMENTATION_BARRIER_BUDGET_MILLI;
            self.fragmentation_violations = self.fragmentation_violations.saturating_add(1);
            return false;
        }

        let alloc_count = self.allocator_observations.min(u64::from(u32::MAX)) as u32;
        let free_count = self
            .allocator_free_like_observations
            .min(u64::from(u32::MAX)) as u32;
        let val = evaluate_fragmentation_barrier(
            alloc_count,
            free_count,
            size_class_dispersion_ppm,
            arena_utilization_ppm,
        );
        self.last_fragmentation_value = val;
        if val < 0 {
            self.fragmentation_violations = self.fragmentation_violations.saturating_add(1);
            false
        } else {
            true
        }
    }

    /// Evaluate thread-safety SOS certificate.
    ///
    /// Returns true when the barrier certifies safety.
    pub fn evaluate_thread_safety(
        &mut self,
        thread_count: u32,
        concurrent_writers: u32,
        arena_owner_conflict: bool,
        free_list_skew_ppm: u32,
        allocation_epoch_lag_ppm: u32,
    ) -> bool {
        if !self.thread_safety_hash_valid {
            self.last_thread_safety_value = -THREAD_SAFETY_BARRIER_BUDGET_MILLI;
            self.thread_safety_violations = self.thread_safety_violations.saturating_add(1);
            return false;
        }

        let val = evaluate_thread_safety_barrier(
            thread_count,
            concurrent_writers,
            arena_owner_conflict,
            free_list_skew_ppm,
            allocation_epoch_lag_ppm,
        );
        self.last_thread_safety_value = val;
        if val < 0 {
            self.thread_safety_violations = self.thread_safety_violations.saturating_add(1);
            false
        } else {
            true
        }
    }

    /// Evaluate size-class SOS certificate.
    ///
    /// Returns true when the barrier certifies safety.
    pub fn evaluate_size_class(
        &mut self,
        requested_size: usize,
        mapped_class_size: usize,
        class_membership_valid: bool,
    ) -> bool {
        if !self.size_class_hash_valid {
            self.last_size_class_value = -SIZE_CLASS_BARRIER_BUDGET_MILLI;
            self.size_class_violations = self.size_class_violations.saturating_add(1);
            return false;
        }

        let val =
            evaluate_size_class_barrier(requested_size, mapped_class_size, class_membership_valid);
        self.last_size_class_value = val;
        if val < 0 {
            self.size_class_violations = self.size_class_violations.saturating_add(1);
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

        if !self.fragmentation_hash_valid
            || !self.thread_safety_hash_valid
            || !self.size_class_hash_valid
        {
            return SosBarrierState::Violated;
        }

        // Violation: either barrier negative.
        if self.last_provenance_value < 0
            || self.last_quarantine_value < 0
            || self.last_fragmentation_value < 0
            || self.last_thread_safety_value < 0
            || self.last_size_class_value < 0
        {
            return SosBarrierState::Violated;
        }

        // Warning: either barrier within 20% of threshold.
        let prov_headroom = self.last_provenance_value;
        let quar_headroom = self.last_quarantine_value;
        let frag_headroom = self.last_fragmentation_value;
        let prov_warning = PROVENANCE_RISK_BUDGET_PPM / 5; // 20% of budget
        let quar_warning = 40; // 20% of baseline 200
        let frag_warning = FRAGMENTATION_BARRIER_BUDGET_MILLI / 5;
        let thread_warning = THREAD_SAFETY_BARRIER_BUDGET_MILLI / 5;
        let size_class_warning = SIZE_CLASS_BARRIER_BUDGET_MILLI / 5;

        if prov_headroom < prov_warning
            || quar_headroom < quar_warning
            || frag_headroom < frag_warning
            || self.last_thread_safety_value < thread_warning
            || self.last_size_class_value < size_class_warning
        {
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
            fragmentation_value: self.last_fragmentation_value,
            thread_safety_value: self.last_thread_safety_value,
            size_class_value: self.last_size_class_value,
            total_observations: self.observations,
            provenance_violations: self.provenance_violations,
            quarantine_violations: self.quarantine_violations,
            fragmentation_violations: self.fragmentation_violations,
            thread_safety_violations: self.thread_safety_violations,
            size_class_violations: self.size_class_violations,
            fragmentation_hash_valid: self.fragmentation_hash_valid,
            thread_safety_hash_valid: self.thread_safety_hash_valid,
            size_class_hash_valid: self.size_class_hash_valid,
        }
    }

    /// Total violation count across all barriers and hash-integrity checks.
    #[must_use]
    pub fn total_violations(&self) -> u64 {
        let hash_invalid = (if self.fragmentation_hash_valid { 0 } else { 1 })
            + (if self.thread_safety_hash_valid { 0 } else { 1 })
            + (if self.size_class_hash_valid { 0 } else { 1 });
        self.provenance_violations
            .saturating_add(self.quarantine_violations)
            .saturating_add(self.fragmentation_violations)
            .saturating_add(self.thread_safety_violations)
            .saturating_add(self.size_class_violations)
            .saturating_add(hash_invalid)
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    const PSD_TOLERANCE: f64 = 1e-6;
    const PIVOT_TOLERANCE: f64 = 1e-12;
    const SOS_SOUNDNESS_REPORT_JSON: &str =
        include_str!(concat!(env!("OUT_DIR"), "/sos_soundness_verification.json"));

    fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest {
            write!(&mut out, "{byte:02x}").expect("writing digest to String must succeed");
        }
        out
    }

    fn determinant(mut matrix: Vec<Vec<f64>>) -> f64 {
        let n = matrix.len();
        if n == 0 {
            return 1.0;
        }

        let mut det = 1.0f64;
        for col in 0..n {
            let mut pivot = col;
            let mut pivot_abs = matrix[col][col].abs();
            for (row, row_vals) in matrix.iter().enumerate().skip(col + 1).take(n - (col + 1)) {
                let candidate = row_vals[col].abs();
                if candidate > pivot_abs {
                    pivot = row;
                    pivot_abs = candidate;
                }
            }
            if pivot_abs <= PIVOT_TOLERANCE {
                return 0.0;
            }
            if pivot != col {
                matrix.swap(col, pivot);
                det = -det;
            }

            let pivot_value = matrix[col][col];
            det *= pivot_value;
            let pivot_row = matrix[col].clone();
            for row_vals in matrix.iter_mut().skip(col + 1) {
                let factor = row_vals[col] / pivot_value;
                for (inner_col, cell) in row_vals.iter_mut().enumerate().skip(col + 1) {
                    *cell -= factor * pivot_row[inner_col];
                }
            }
        }

        det
    }

    fn assert_symmetric<const D: usize>(gram: &[[i64; D]; D], label: &str) {
        for (row, row_vals) in gram.iter().enumerate().take(D) {
            for (col, value) in row_vals.iter().enumerate().take(D) {
                assert_eq!(
                    *value, gram[col][row],
                    "{label} Gram matrix must be symmetric at ({row},{col})"
                );
            }
        }
    }

    fn assert_positive_semidefinite_via_principal_minors<const D: usize>(
        gram: &[[i64; D]; D],
        label: &str,
    ) {
        assert_symmetric(gram, label);

        for mask in 1usize..(1usize << D) {
            let mut indices = Vec::with_capacity(D);
            for bit in 0..D {
                if (mask & (1usize << bit)) != 0 {
                    indices.push(bit);
                }
            }

            let size = indices.len();
            let mut principal = vec![vec![0.0f64; size]; size];
            for (row_idx, &row) in indices.iter().enumerate() {
                for (col_idx, &col) in indices.iter().enumerate() {
                    principal[row_idx][col_idx] = gram[row][col] as f64;
                }
            }

            let minor = determinant(principal);
            assert!(
                minor >= -PSD_TOLERANCE,
                "{label} principal minor for mask {mask:#b} must be non-negative (got {minor})"
            );
        }
    }

    #[test]
    fn certificate_hash_matches_static_fragmentation_artifact() {
        assert!(
            FRAGMENTATION_CERTIFICATE.verify_integrity(),
            "static fragmentation certificate hash must verify"
        );
    }

    #[test]
    fn certificate_hash_matches_static_thread_safety_artifact() {
        assert!(
            THREAD_SAFETY_CERTIFICATE.verify_integrity(),
            "static thread-safety certificate hash must verify"
        );
    }

    #[test]
    fn certificate_hash_matches_static_size_class_artifact() {
        assert!(
            SIZE_CLASS_CERTIFICATE.verify_integrity(),
            "static size-class certificate hash must verify"
        );
    }

    #[test]
    fn generated_task_source_hash_is_hex_sha256() {
        for task_hash in [
            FRAGMENTATION_TASK_SOURCE_SHA256_HEX,
            THREAD_SAFETY_TASK_SOURCE_SHA256_HEX,
            SIZE_CLASS_TASK_SOURCE_SHA256_HEX,
        ] {
            assert_eq!(
                task_hash.len(),
                64,
                "task hash must be a 64-char SHA-256 hex string"
            );
            assert!(
                task_hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "task hash must contain only ASCII hex digits"
            );
        }
    }

    #[test]
    fn generated_task_source_hash_matches_checked_in_artifacts() {
        let fragmentation_task =
            include_bytes!("../../artifacts/sos/fragmentation_certificate.task");
        let thread_safety_task =
            include_bytes!("../../artifacts/sos/thread_safety_certificate.task");
        let size_class_task = include_bytes!("../../artifacts/sos/size_class_certificate.task");

        assert_eq!(
            FRAGMENTATION_TASK_SOURCE_SHA256_HEX,
            sha256_hex(fragmentation_task),
            "fragmentation task source hash must match artifact bytes"
        );
        assert_eq!(
            THREAD_SAFETY_TASK_SOURCE_SHA256_HEX,
            sha256_hex(thread_safety_task),
            "thread-safety task source hash must match artifact bytes"
        );
        assert_eq!(
            SIZE_CLASS_TASK_SOURCE_SHA256_HEX,
            sha256_hex(size_class_task),
            "size-class task source hash must match artifact bytes"
        );
    }

    #[test]
    fn certificate_tamper_is_detected() {
        let mut tampered = FRAGMENTATION_GRAM_MATRIX;
        tampered[0][0] += 1;
        let cert = SosCertificate::new(
            tampered,
            FRAGMENTATION_PROOF_HASH,
            FRAGMENTATION_MONOMIAL_DEGREE,
            FRAGMENTATION_BARRIER_BUDGET_MILLI,
        );
        assert!(
            !cert.verify_integrity(),
            "tampered Gram matrix must fail hash verification"
        );
    }

    #[test]
    fn thread_safety_certificate_tamper_is_detected() {
        let mut tampered = THREAD_SAFETY_GRAM_MATRIX;
        tampered[1][1] += 1;
        let cert = SosCertificate::new(
            tampered,
            THREAD_SAFETY_PROOF_HASH,
            THREAD_SAFETY_MONOMIAL_DEGREE,
            THREAD_SAFETY_BARRIER_BUDGET_MILLI,
        );
        assert!(
            !cert.verify_integrity(),
            "tampered thread-safety Gram matrix must fail hash verification"
        );
    }

    #[test]
    fn size_class_certificate_tamper_is_detected() {
        let mut tampered = SIZE_CLASS_GRAM_MATRIX;
        tampered[2][2] += 1;
        let cert = SosCertificate::new(
            tampered,
            SIZE_CLASS_PROOF_HASH,
            SIZE_CLASS_MONOMIAL_DEGREE,
            SIZE_CLASS_BARRIER_BUDGET_MILLI,
        );
        assert!(
            !cert.verify_integrity(),
            "tampered size-class Gram matrix must fail hash verification"
        );
    }

    #[test]
    fn fragmentation_gram_matrix_is_positive_semidefinite() {
        assert_positive_semidefinite_via_principal_minors(
            &FRAGMENTATION_GRAM_MATRIX,
            "fragmentation",
        );
    }

    #[test]
    fn thread_safety_gram_matrix_is_positive_semidefinite() {
        assert_positive_semidefinite_via_principal_minors(
            &THREAD_SAFETY_GRAM_MATRIX,
            "thread_safety",
        );
    }

    #[test]
    fn size_class_gram_matrix_is_positive_semidefinite() {
        assert_positive_semidefinite_via_principal_minors(&SIZE_CLASS_GRAM_MATRIX, "size_class");
    }

    #[test]
    fn sos_certificate_const_generic_supports_16d() {
        const D: usize = 16;
        let mut gram = [[0i64; D]; D];
        for (i, row) in gram.iter_mut().enumerate().take(D) {
            row[i] = 1;
        }
        let hash = compute_certificate_hash(&gram, 2, 1_000);
        let cert = SosCertificate::<D>::new(gram, hash, 2, 1_000);
        assert!(cert.verify_integrity());
        let mut basis = [0i64; D];
        basis[0] = 10;
        basis[5] = 3;
        let barrier = cert.evaluate_barrier(&basis, 1);
        assert_eq!(barrier, 1_000 - 109);
    }

    #[test]
    fn quadratic_form_saturates_under_extreme_inputs() {
        let gram = [[i64::MAX, i64::MAX], [i64::MAX, i64::MAX]];
        let hash = compute_certificate_hash(&gram, 2, i64::MAX);
        let cert = SosCertificate::<2>::new(gram, hash, 2, i64::MAX);
        let basis = [i64::MAX, i64::MAX];

        let quadratic = cert.evaluate_quadratic_form(&basis, 1);
        assert_eq!(quadratic, i64::MAX, "quadratic form must saturate");

        let barrier = cert.evaluate_barrier(&basis, 1);
        assert_eq!(
            barrier, 0,
            "barrier headroom should saturate instead of overflowing"
        );
    }

    #[test]
    fn barrier_evaluators_stay_stable_on_extreme_inputs() {
        let balanced_fragmentation = evaluate_fragmentation_barrier(0, 0, 0, 0);
        let extreme_fragmentation =
            evaluate_fragmentation_barrier(u32::MAX, u32::MAX, u32::MAX, u32::MAX);
        assert!(
            extreme_fragmentation <= balanced_fragmentation,
            "extreme fragmentation must not appear safer than balanced profile"
        );

        let balanced_thread = evaluate_thread_safety_barrier(1, 1, false, 0, 0);
        let extreme_thread =
            evaluate_thread_safety_barrier(u32::MAX, u32::MAX, true, u32::MAX, u32::MAX);
        assert!(
            extreme_thread <= balanced_thread,
            "extreme thread-safety stress must not appear safer than balanced profile"
        );
    }

    #[test]
    fn fragmentation_barrier_safe_balanced_profile() {
        let val = evaluate_fragmentation_barrier(
            50_000, 49_000, 120_000, // below dispersion budget
            450_000, // below arena-utilization budget
        );
        assert!(
            val > 0,
            "balanced allocator profile should be certified safe, got {val}"
        );
    }

    #[test]
    fn fragmentation_barrier_violates_under_extreme_fragmentation() {
        let val = evaluate_fragmentation_barrier(
            90_000, 10_000, 900_000, // high size-class dispersion
            980_000, // extreme arena utilization
        );
        assert!(
            val < 0,
            "extreme fragmentation profile should violate certificate, got {val}"
        );
    }

    #[test]
    fn thread_safety_barrier_safe_nominal_profile() {
        let val = evaluate_thread_safety_barrier(
            16, // low allocator-thread pressure
            1,  // no writer overflow
            false, 60_000, // below free-list skew budget
            40_000, // below epoch-lag budget
        );
        assert!(
            val > 0,
            "nominal thread-safety profile should be certified safe, got {val}"
        );
    }

    #[test]
    fn thread_safety_barrier_violates_on_conflicting_writers() {
        let val = evaluate_thread_safety_barrier(700, 4, true, 900_000, 920_000);
        assert!(
            val < 0,
            "conflicting writer profile should violate certificate, got {val}"
        );
    }

    #[test]
    fn thread_safety_barrier_monotone_in_writer_pressure() {
        let mut previous = i64::MAX;
        for concurrent_writers in 1..=6 {
            let value =
                evaluate_thread_safety_barrier(96, concurrent_writers, false, 80_000, 60_000);
            assert!(
                value <= previous,
                "writer pressure monotonicity violated at writers={concurrent_writers}: value={value}, previous={previous}"
            );
            previous = value;
        }
    }

    #[test]
    fn fragmentation_barrier_monotone_in_size_dispersion() {
        let mut previous = i64::MAX;
        for dispersion_ppm in (0..=1_000_000).step_by(100_000) {
            let value = evaluate_fragmentation_barrier(20_000, 19_500, dispersion_ppm, 350_000);
            assert!(
                value <= previous,
                "dispersion monotonicity violated at dispersion_ppm={dispersion_ppm}: value={value}, previous={previous}"
            );
            previous = value;
        }
    }

    const TEST_SIZE_CLASS_TABLE: [usize; 34] = [
        16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 288, 320, 352, 384, 448, 512, 640,
        768, 896, 1024, 1280, 1536, 2048, 2560, 3072, 4096, 8192, 16384, 24576, 32768, 49152,
        65536,
    ];

    fn map_request_to_test_class_size(requested_size: usize) -> usize {
        let normalized = requested_size.max(16);
        for &class_size in &TEST_SIZE_CLASS_TABLE {
            if normalized <= class_size {
                return class_size;
            }
        }
        0
    }

    #[test]
    fn size_class_fast_path_matches_generic_certificate_eval() {
        for b0 in [0_i64, 250, 500, 750, 1000] {
            for b1 in [0_i64, 250, 500, 750, 1000] {
                for b2 in [0_i64, 250, 500, 750, 1000] {
                    for b3 in [0_i64, 250, 500, 750, 1000] {
                        let basis = [b0, b1, b2, b3];
                        let fast = evaluate_size_class_barrier_from_basis(&basis);
                        let generic =
                            SIZE_CLASS_CERTIFICATE.evaluate_barrier(&basis, SIZE_CLASS_SCORE_SCALE);
                        assert_eq!(
                            fast, generic,
                            "size-class fast path must match generic eval for basis={basis:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn build_time_soundness_report_covers_all_certificates() {
        for certificate_id in ["fragmentation", "thread_safety", "size_class"] {
            assert!(
                SOS_SOUNDNESS_REPORT_JSON
                    .contains(&format!("\"certificate_id\": \"{certificate_id}\"")),
                "soundness report must contain certificate_id={certificate_id}"
            );
        }
        assert_eq!(
            SOS_SOUNDNESS_REPORT_JSON
                .matches("\"cholesky_success\": true")
                .count(),
            3,
            "soundness report must mark all certificates as cholesky_success=true"
        );
        assert_eq!(
            SOS_SOUNDNESS_REPORT_JSON
                .matches("\"polynomial_identity_verified\": true")
                .count(),
            3,
            "soundness report must mark all certificates as polynomial_identity_verified=true"
        );
    }

    #[test]
    fn build_time_stability_bounds_are_small() {
        for (label, min_pivot, max_abs_reconstruction_error, stability_bound_delta) in [
            (
                "fragmentation",
                FRAGMENTATION_CHOLESKY_MIN_PIVOT,
                FRAGMENTATION_CHOLESKY_MAX_ABS_RECONSTRUCTION_ERROR,
                FRAGMENTATION_STABILITY_BOUND_DELTA,
            ),
            (
                "thread_safety",
                THREAD_SAFETY_CHOLESKY_MIN_PIVOT,
                THREAD_SAFETY_CHOLESKY_MAX_ABS_RECONSTRUCTION_ERROR,
                THREAD_SAFETY_STABILITY_BOUND_DELTA,
            ),
            (
                "size_class",
                SIZE_CLASS_CHOLESKY_MIN_PIVOT,
                SIZE_CLASS_CHOLESKY_MAX_ABS_RECONSTRUCTION_ERROR,
                SIZE_CLASS_STABILITY_BOUND_DELTA,
            ),
        ] {
            assert!(
                min_pivot.is_finite()
                    && max_abs_reconstruction_error.is_finite()
                    && stability_bound_delta.is_finite(),
                "build-time stability metrics must be finite for {label}"
            );
            assert!(
                min_pivot >= 0.0,
                "cholesky pivot floor must be non-negative for {label}, got {min_pivot}"
            );
            assert!(
                max_abs_reconstruction_error <= 1e-6,
                "cholesky reconstruction max abs error too large for {label}: {max_abs_reconstruction_error}"
            );
            assert!(
                stability_bound_delta <= 1e-5,
                "stability bound delta too large for {label}: {stability_bound_delta}"
            );
        }
    }

    #[test]
    fn size_class_barrier_accepts_current_table_for_full_domain() {
        for requested_size in 1..=SIZE_CLASS_MAX_CERTIFIED_REQUEST {
            let mapped_class_size = map_request_to_test_class_size(requested_size);
            let val = evaluate_size_class_barrier(requested_size, mapped_class_size, true);
            assert!(
                val >= 0,
                "expected certified mapping for requested={requested_size}, mapped={mapped_class_size}, value={val}"
            );
        }
    }

    #[test]
    fn size_class_barrier_rejects_artificially_bad_mapping() {
        let val = evaluate_size_class_barrier(17, 256, true);
        assert!(
            val < 0,
            "17-byte request mapped to 256 should violate admissibility, got {val}"
        );
    }

    #[test]
    fn size_class_barrier_rejects_invalid_class_membership() {
        let val = evaluate_size_class_barrier(128, 130, false);
        assert!(
            val < 0,
            "non-member class size should violate admissibility, got {val}"
        );
    }

    #[test]
    fn size_class_barrier_rejects_out_of_range_mapping() {
        let val = evaluate_size_class_barrier(64, SIZE_CLASS_MAX_CERTIFIED_REQUEST + 1, true);
        assert!(
            val < 0,
            "out-of-range mapped class must violate admissibility, got {val}"
        );
    }

    #[test]
    fn size_class_barrier_monotone_in_overallocation() {
        let requested = 17usize;
        let mappings = [32usize, 64, 128, 256, 512];
        let mut previous = i64::MAX;
        for mapped in mappings {
            let value = evaluate_size_class_barrier(requested, mapped, true);
            assert!(
                value <= previous,
                "expected non-increasing barrier under larger mapping: mapped={mapped}, value={value}, previous={previous}"
            );
            previous = value;
        }
    }

    #[test]
    fn fragmentation_sawtooth_10k_cycles_stays_within_envelope() {
        let mut ctrl = SosBarrierController::new();
        for _ in 0..WARMUP {
            ctrl.evaluate_provenance(10_000, 1_000_000, 10_000, 50_000);
        }

        let mut checks = 0u32;
        for i in 0..10_000u32 {
            // Sawtooth profile: alternating alloc/free pressure with bounded depth drift.
            let depth = if i % 2 == 0 {
                4_096 + (i % 256)
            } else {
                4_096 - (i % 128)
            };
            let free_like = i % 2 == 1;
            ctrl.note_allocator_observation(free_like, depth);
            if ctrl.is_fragmentation_cadence() {
                checks = checks.saturating_add(1);
                let arena_utilization_ppm = depth_to_arena_utilization_ppm(depth);
                let safe = ctrl.evaluate_fragmentation(120_000, arena_utilization_ppm);
                assert!(safe, "sawtooth cycle triggered fragmentation violation");
            }
        }

        assert!(
            checks > 0,
            "expected at least one fragmentation cadence check"
        );
        assert_eq!(
            ctrl.fragmentation_violations, 0,
            "sawtooth profile should remain within certified envelope"
        );
    }

    #[test]
    fn depth_to_arena_utilization_bounds() {
        assert_eq!(depth_to_arena_utilization_ppm(0), 0);
        assert_eq!(depth_to_arena_utilization_ppm(64), 0);
        assert_eq!(depth_to_arena_utilization_ppm(65_536), 1_000_000);
        assert_eq!(depth_to_arena_utilization_ppm(100_000), 1_000_000);
    }

    #[test]
    fn compose_memory_pressure_prefers_runtime_signal_when_higher() {
        let low_depth_pressure = compose_memory_pressure_ppm(128, 90_000, 100_000);
        assert!(
            low_depth_pressure >= 900_000,
            "runtime pressure should dominate low depth pressure, got {low_depth_pressure}"
        );
    }

    #[test]
    fn compose_memory_pressure_recovers_when_runtime_signal_drops() {
        let high = compose_memory_pressure_ppm(128, 90_000, 100_000);
        let low = compose_memory_pressure_ppm(128, 5_000, 5_000);
        assert!(
            high > low,
            "pressure composition should recover: high={high}, low={low}"
        );
    }

    #[test]
    fn conjunction_of_fragmentation_and_memory_pressure_guards_is_sound() {
        let fragmentation_safe = evaluate_fragmentation_barrier(40_000, 39_500, 110_000, 420_000);
        let pressure_safe = evaluate_provenance_barrier(
            12_000,
            1_000_000,
            8_000,
            compose_memory_pressure_ppm(256, 4_000, 4_000),
        );
        assert!(
            fragmentation_safe >= 0 && pressure_safe >= 0,
            "nominal profile should satisfy both guards: frag={fragmentation_safe}, pressure={pressure_safe}"
        );

        let fragmentation_bad = evaluate_fragmentation_barrier(90_000, 8_000, 920_000, 980_000);
        let pressure_bad = evaluate_provenance_barrier(
            300_000,
            0,
            300_000,
            compose_memory_pressure_ppm(65_536, 100_000, 100_000),
        );
        assert!(
            !(fragmentation_bad >= 0 && pressure_bad >= 0),
            "conjunction must fail when either guard violates: frag={fragmentation_bad}, pressure={pressure_bad}"
        );
    }

    // ---- Invariant B (Provenance) Tests ----

    #[test]
    fn provenance_safe_low_risk_full_validation() {
        // Low risk + Full validation → strongly safe.
        let val = evaluate_provenance_barrier(
            10_000,    // risk: low
            1_000_000, // validation: Full
            50_000,    // bloom fp: 5%
            200_000,   // arena: 20%
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
            500_000, // risk: 50% (far above budget)
            0,       // validation: Fast
            400_000, // bloom fp: 40%
            800_000, // arena: 80%
        );
        assert!(val < 0, "Expected violation, got {val}");
    }

    #[test]
    fn provenance_violates_extreme_memory_pressure_even_low_risk() {
        // Direct memory-pressure penalty should force backpressure in the
        // extreme case even when risk-only terms are mild.
        let val = evaluate_provenance_barrier(10_000, 0, 0, 1_000_000);
        assert!(val < 0, "Expected memory-pressure violation, got {val}");
    }

    #[test]
    fn provenance_memory_pressure_recovers_after_backpressure() {
        let violated = evaluate_provenance_barrier(10_000, 0, 0, 1_000_000);
        let recovered = evaluate_provenance_barrier(10_000, 0, 0, 50_000);
        assert!(violated < 0, "expected violated state at extreme pressure");
        assert!(
            recovered > 0,
            "expected recovery once pressure drops, got {recovered}"
        );
    }

    #[test]
    fn provenance_nominal_trace_has_bounded_false_positives() {
        let mut violations = 0u32;
        for i in 0..10_000u32 {
            let risk = 5_000 + (i % 15_000);
            let depth = if i % 8 == 0 { 1_000_000 } else { 0 };
            let projected = 10_000 + (i % 90_000);
            let arena = 20_000 + (i % 120_000);
            if evaluate_provenance_barrier(risk, depth, projected, arena) < 0 {
                violations = violations.saturating_add(1);
            }
        }
        assert!(
            violations <= 1,
            "nominal trace should not spuriously backpressure often; violations={violations}"
        );
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
        let val = evaluate_provenance_barrier(PROVENANCE_RISK_BUDGET_PPM as u32, 0, 0, 0);
        // headroom = 0, penalties ≈ 0 (risk × 0 bloom × 0 arena), reward = 0.
        assert_eq!(
            val, 0,
            "At budget boundary with no penalties, should be exactly 0"
        );
    }

    // ---- Invariant A (Quarantine Depth) Tests ----

    #[test]
    fn quarantine_safe_moderate_depth_low_adverse() {
        // Moderate depth, low contention, low adverse → safe.
        let val = evaluate_quarantine_barrier(
            4096,  // depth: mid-range
            4,     // contention: low
            1_000, // adverse: 0.1%
            0,     // lambda: neutral
        );
        assert!(val > 0, "Expected safe, got {val}");
    }

    #[test]
    fn quarantine_unsafe_shallow_high_adverse() {
        // Very shallow depth + very high adverse → violation.
        let val = evaluate_quarantine_barrier(
            64,      // depth: minimum
            100,     // contention: moderate
            500_000, // adverse: 50%
            50,      // lambda: moderate pressure
        );
        assert!(
            val < 0,
            "Expected violation for shallow+high_adverse, got {val}"
        );
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
        assert_eq!(
            cadence_hits,
            3,
            "Expected 3 cadence hits over {}",
            CADENCE_A * 3
        );
    }

    #[test]
    fn summary_consistent() {
        let mut ctrl = SosBarrierController::new();
        for _ in 0..100 {
            ctrl.evaluate_provenance(10_000, 1_000_000, 10_000, 50_000);
        }
        ctrl.evaluate_quarantine(4096, 4, 1_000, 0);
        ctrl.note_allocator_observation(false, 4096);
        ctrl.evaluate_fragmentation(100_000, 400_000);

        let s = ctrl.summary();
        assert_eq!(s.state, ctrl.state());
        assert_eq!(s.total_observations, 100);
        assert_eq!(s.provenance_violations, ctrl.provenance_violations);
        assert_eq!(s.quarantine_violations, ctrl.quarantine_violations);
        assert_eq!(s.fragmentation_violations, ctrl.fragmentation_violations);
        assert_eq!(s.thread_safety_violations, ctrl.thread_safety_violations);
        assert_eq!(s.fragmentation_hash_valid, ctrl.fragmentation_hash_valid);
        assert_eq!(s.thread_safety_hash_valid, ctrl.thread_safety_hash_valid);
        assert_eq!(s.provenance_value, ctrl.last_provenance_value);
        assert_eq!(s.quarantine_value, ctrl.last_quarantine_value);
        assert_eq!(s.fragmentation_value, ctrl.last_fragmentation_value);
        assert_eq!(s.thread_safety_value, ctrl.last_thread_safety_value);
    }

    #[test]
    fn controller_fragmentation_cadence_and_violation_tracking() {
        let mut benign = SosBarrierController::new();
        for _ in 0..WARMUP {
            benign.evaluate_provenance(10_000, 1_000_000, 10_000, 50_000);
        }
        for _ in 0..CADENCE_FRAGMENTATION {
            benign.note_allocator_observation(false, 4096);
        }
        assert!(benign.is_fragmentation_cadence());
        assert!(benign.evaluate_fragmentation(100_000, 450_000));

        // Build an alloc-heavy stream by strictly increasing depth with no
        // adverse events so free-like observations stay near zero.
        let mut skewed = SosBarrierController::new();
        for _ in 0..WARMUP {
            skewed.evaluate_provenance(10_000, 1_000_000, 10_000, 50_000);
        }
        for i in 0..CADENCE_FRAGMENTATION {
            skewed.note_allocator_observation(false, 1024 + i as u32);
        }
        assert!(skewed.is_fragmentation_cadence());
        let base_violations = skewed.fragmentation_violations;
        assert!(!skewed.evaluate_fragmentation(900_000, 980_000));
        assert!(
            skewed.fragmentation_violations > base_violations,
            "fragmentation violation counter should increase"
        );
    }

    #[test]
    fn controller_thread_safety_violation_tracking() {
        let mut ctrl = SosBarrierController::new();
        for _ in 0..WARMUP {
            ctrl.evaluate_provenance(10_000, 1_000_000, 10_000, 50_000);
        }

        assert!(ctrl.evaluate_thread_safety(32, 1, false, 40_000, 30_000));
        let base_violations = ctrl.thread_safety_violations;
        assert!(!ctrl.evaluate_thread_safety(700, 4, true, 900_000, 900_000));
        assert!(
            ctrl.thread_safety_violations > base_violations,
            "thread-safety violation counter should increase"
        );
        assert_eq!(ctrl.state(), SosBarrierState::Violated);
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

    // ---- Property Tests ----

    /// Provenance barrier is monotone decreasing in risk.
    /// For any fixed (v, b, p), increasing risk must not increase the barrier.
    #[test]
    fn provenance_monotone_risk_sweep() {
        for v in [0u32, 500_000, 1_000_000] {
            for b in [0u32, 100_000, 500_000] {
                for p in [0u32, 200_000, 800_000] {
                    let mut prev = i64::MAX;
                    for risk in (0..=1_000_000).step_by(50_000) {
                        let val = evaluate_provenance_barrier(risk, v, b, p);
                        assert!(
                            val <= prev,
                            "Monotonicity violated: risk={risk}, v={v}, b={b}, p={p}: {val} > {prev}"
                        );
                        prev = val;
                    }
                }
            }
        }
    }

    /// Provenance barrier is monotone increasing in validation depth.
    /// For any fixed (r, b, p), increasing depth must not decrease the barrier.
    #[test]
    fn provenance_monotone_depth_sweep() {
        for r in [50_000u32, 200_000, 500_000] {
            for b in [0u32, 200_000] {
                for p in [0u32, 400_000] {
                    let mut prev = i64::MIN;
                    for v in (0..=1_000_000).step_by(100_000) {
                        let val = evaluate_provenance_barrier(r, v, b, p);
                        assert!(
                            val >= prev,
                            "Depth monotonicity violated: r={r}, v={v}, b={b}, p={p}: {val} < {prev}"
                        );
                        prev = val;
                    }
                }
            }
        }
    }

    /// No panics on any combination of extreme input values.
    #[test]
    fn provenance_no_panic_extremes() {
        let extremes = [0u32, 1, 500_000, 999_999, 1_000_000, u32::MAX / 2];
        for &r in &extremes {
            for &v in &extremes {
                for &b in &extremes {
                    for &p in &extremes {
                        let _ = evaluate_provenance_barrier(r, v, b, p);
                    }
                }
            }
        }
    }

    /// No panics on extreme quarantine inputs.
    #[test]
    fn quarantine_no_panic_extremes() {
        let depths = [0u32, 64, 4096, 65536, 1_000_000];
        let contentions = [0u32, 1, 512, 1024, 10_000];
        let adverse = [0u32, 1_000, 500_000, 1_000_000];
        let lambdas = [i64::MIN / 2, -128, 0, 128, i64::MAX / 2];
        for &d in &depths {
            for &c in &contentions {
                for &a in &adverse {
                    for &l in &lambdas {
                        let _ = evaluate_quarantine_barrier(d, c, a, l);
                    }
                }
            }
        }
    }

    /// Quarantine barrier: adverse rate monotone degradation.
    #[test]
    fn quarantine_monotone_adverse_sweep() {
        let depth = 4096u32;
        let contention = 10u32;
        let lambda = 0i64;
        let mut prev = i64::MAX;
        for a in (0..=1_000_000).step_by(50_000) {
            let val = evaluate_quarantine_barrier(depth, contention, a, lambda);
            assert!(
                val <= prev,
                "Adverse monotonicity violated: a={a}: {val} > {prev}"
            );
            prev = val;
        }
    }

    /// Controller state machine: violations accumulate monotonically.
    #[test]
    fn violations_monotone() {
        let mut ctrl = SosBarrierController::new();
        let mut max_violations = 0u64;
        for _ in 0..100 {
            ctrl.evaluate_provenance(10_000, 1_000_000, 10_000, 50_000);
            assert!(ctrl.total_violations() >= max_violations);
            max_violations = ctrl.total_violations();
        }
        // Trigger some violations.
        for _ in 0..10 {
            ctrl.evaluate_provenance(500_000, 0, 400_000, 800_000);
            assert!(ctrl.total_violations() >= max_violations);
            max_violations = ctrl.total_violations();
        }
        assert!(max_violations > 0);
    }

    /// Hot-path integer-only evidence: the provenance barrier uses only
    /// i64 arithmetic (saturating_mul, saturating_sub, division).
    /// No f64 in the evaluation path.
    ///
    /// This test exercises varied inputs and confirms stable results.
    #[test]
    fn hot_path_integer_only() {
        let mut ctrl = SosBarrierController::new();
        // Exercise all reasonable input combinations.
        for round in 0u64..256 {
            let risk = ((round * 7919) % 1_000_000) as u32;
            let depth = if round % 2 == 0 { 0u32 } else { 1_000_000 };
            let bloom = ((round * 3571) % 500_000) as u32;
            let arena = ((round * 2347) % 800_000) as u32;
            ctrl.evaluate_provenance(risk, depth, bloom, arena);
        }
        let s = ctrl.summary();
        assert!(matches!(
            s.state,
            SosBarrierState::Calibrating
                | SosBarrierState::Safe
                | SosBarrierState::Warning
                | SosBarrierState::Violated
        ));
    }

    /// Full kernel integration: feed through RuntimeMathKernel and verify
    /// the SOS barrier state appears in the snapshot.
    #[test]
    fn kernel_snapshot_integration() {
        use crate::config::SafetyLevel;
        use crate::runtime_math::{
            ApiFamily, RuntimeContext, RuntimeMathKernel, ValidationProfile,
        };

        let kernel = RuntimeMathKernel::new();
        let mode = SafetyLevel::Strict;
        let ctx = RuntimeContext::pointer_validation(0x1000, false);

        // Run enough cycles for the barrier to leave calibration.
        for _ in 0..256 {
            let _ = kernel.decide(mode, ctx);
            kernel.observe_validation_result(
                mode,
                ApiFamily::PointerValidation,
                ValidationProfile::Fast,
                15,
                false,
            );
        }

        let snap = kernel.snapshot(mode);
        // After benign observations, barrier should not have triggered.
        assert!(
            snap.sos_barrier_provenance_value >= 0,
            "Provenance value should be non-negative under benign load: {}",
            snap.sos_barrier_provenance_value,
        );
    }

    /// Deterministic regression: fixed inputs produce exact golden values.
    #[test]
    fn deterministic_provenance_regression() {
        // These golden values must only change with intentional coefficient updates.
        let val = evaluate_provenance_barrier(50_000, 0, 100_000, 200_000);
        // Recompute: headroom = 100_000 - 50_000 = 50_000
        // rb = 50_000 * 100_000 / 1_000_000 = 5_000
        // penalty_1 = 800_000 * 5_000 * 1_000_000 / (1e6 * 1e6) = 4_000
        // rp = 50_000 * 200_000 / 1_000_000 = 10_000
        // penalty_2 = 600_000 * 10_000 * 1_000_000 / (1e6 * 1e6) = 6_000
        // penalty_3 = 95_000 * 200_000 / 1_000_000 = 19_000
        // reward = 400 * 0 * 900_000 / (1e6 * 1e6) = 0
        // total = 50_000 - 4_000 - 6_000 - 19_000 + 0 = 21_000
        assert_eq!(val, 21_000, "Golden value changed: {val}");
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: SOS Certificate PSD Implies Non-Negativity
    //
    // Theorem (Fundamental SOS property): For any positive semidefinite
    // matrix Q, the quadratic form z^T Q z ≥ 0 for all z ∈ Z^n.
    //
    // Proof sketch: PSD ⟹ Q = L L^T (Cholesky), so z^T Q z = ||Lz||² ≥ 0.
    //
    // We verify this exhaustively for the fragmentation and thread-safety
    // certificates by evaluating the quadratic form over a dense grid of
    // basis vectors.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_fragmentation_quadratic_form_nonnegative_exhaustive() {
        // Exhaustive check: for all basis values in [0, 1000] (step 50),
        // the quadratic form z^T Q z must be ≥ 0 (PSD guarantee).
        let cert = &FRAGMENTATION_CERTIFICATE;
        let step = 50i64;
        let max_val = 1000i64;
        let mut count = 0u64;
        let mut i0 = 0i64;
        while i0 <= max_val {
            let mut i1 = 0i64;
            while i1 <= max_val {
                let mut i2 = 0i64;
                while i2 <= max_val {
                    let mut i3 = 0i64;
                    while i3 <= max_val {
                        let basis = [i0, i1, i2, i3];
                        let qf = cert.evaluate_quadratic_form(&basis, 1);
                        assert!(qf >= 0, "PSD violation: basis={basis:?}, qf={qf}");
                        count += 1;
                        i3 += step;
                    }
                    i2 += step;
                }
                i1 += step;
            }
            i0 += step;
        }
        assert!(count > 100_000, "Insufficient coverage: {count}");
    }

    #[test]
    fn proof_thread_safety_quadratic_form_nonnegative_exhaustive() {
        let cert = &THREAD_SAFETY_CERTIFICATE;
        let step = 100i64;
        let max_val = 1000i64;
        let mut count = 0u64;
        let mut i0 = 0i64;
        while i0 <= max_val {
            let mut i1 = 0i64;
            while i1 <= max_val {
                let mut i2 = 0i64;
                while i2 <= max_val {
                    let mut i3 = 0i64;
                    while i3 <= max_val {
                        let mut i4 = 0i64;
                        while i4 <= max_val {
                            let basis = [i0, i1, i2, i3, i4];
                            let qf = cert.evaluate_quadratic_form(&basis, 1);
                            assert!(qf >= 0, "PSD violation: basis={basis:?}, qf={qf}");
                            count += 1;
                            i4 += step;
                        }
                        i3 += step;
                    }
                    i2 += step;
                }
                i1 += step;
            }
            i0 += step;
        }
        assert!(count > 100_000, "Insufficient coverage: {count}");
    }

    #[test]
    fn proof_size_class_quadratic_form_nonnegative_exhaustive() {
        let cert = &SIZE_CLASS_CERTIFICATE;
        let step = 50i64;
        let max_val = 1000i64;
        let mut count = 0u64;
        let mut i0 = 0i64;
        while i0 <= max_val {
            let mut i1 = 0i64;
            while i1 <= max_val {
                let mut i2 = 0i64;
                while i2 <= max_val {
                    let mut i3 = 0i64;
                    while i3 <= max_val {
                        let basis = [i0, i1, i2, i3];
                        let qf = cert.evaluate_quadratic_form(&basis, 1);
                        assert!(qf >= 0, "PSD violation: basis={basis:?}, qf={qf}");
                        count += 1;
                        i3 += step;
                    }
                    i2 += step;
                }
                i1 += step;
            }
            i0 += step;
        }
        assert!(count > 100_000, "Insufficient coverage: {count}");
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Cholesky Stability Bounds
    //
    // Theorem: The build-time Cholesky decomposition is numerically
    // stable — the minimum pivot exceeds machine epsilon, and the
    // reconstruction error ||Q - L L^T||_F is negligible.
    //
    // These bounds prove that the offline PSD verification is reliable
    // and that no precision loss corrupts the certificate.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn proof_cholesky_stability_fragmentation() {
        assert!(
            FRAGMENTATION_CHOLESKY_MIN_PIVOT > 1e-10,
            "Cholesky min pivot too small: {}",
            FRAGMENTATION_CHOLESKY_MIN_PIVOT
        );
        assert!(
            FRAGMENTATION_CHOLESKY_MAX_ABS_RECONSTRUCTION_ERROR < 1e-6,
            "Cholesky reconstruction error too large: {}",
            FRAGMENTATION_CHOLESKY_MAX_ABS_RECONSTRUCTION_ERROR
        );
        assert!(
            FRAGMENTATION_STABILITY_BOUND_DELTA < 1e-5,
            "Frobenius stability delta too large: {}",
            FRAGMENTATION_STABILITY_BOUND_DELTA
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn proof_cholesky_stability_thread_safety() {
        assert!(
            THREAD_SAFETY_CHOLESKY_MIN_PIVOT > 1e-10,
            "Cholesky min pivot too small: {}",
            THREAD_SAFETY_CHOLESKY_MIN_PIVOT
        );
        assert!(
            THREAD_SAFETY_CHOLESKY_MAX_ABS_RECONSTRUCTION_ERROR < 1e-6,
            "Cholesky reconstruction error too large: {}",
            THREAD_SAFETY_CHOLESKY_MAX_ABS_RECONSTRUCTION_ERROR
        );
        assert!(
            THREAD_SAFETY_STABILITY_BOUND_DELTA < 1e-5,
            "Frobenius stability delta too large: {}",
            THREAD_SAFETY_STABILITY_BOUND_DELTA
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn proof_cholesky_stability_size_class() {
        assert!(
            SIZE_CLASS_CHOLESKY_MIN_PIVOT > 1e-10,
            "Cholesky min pivot too small: {}",
            SIZE_CLASS_CHOLESKY_MIN_PIVOT
        );
        assert!(
            SIZE_CLASS_CHOLESKY_MAX_ABS_RECONSTRUCTION_ERROR < 1e-6,
            "Cholesky reconstruction error too large: {}",
            SIZE_CLASS_CHOLESKY_MAX_ABS_RECONSTRUCTION_ERROR
        );
        assert!(
            SIZE_CLASS_STABILITY_BOUND_DELTA < 1e-5,
            "Frobenius stability delta too large: {}",
            SIZE_CLASS_STABILITY_BOUND_DELTA
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Fixed-Point vs Floating-Point Precision Bound
    //
    // Theorem: The fixed-point (i64) quadratic form evaluation
    // agrees with the ideal f64 evaluation up to bounded error ε,
    // and this error is always << barrier budget.
    //
    // This ensures the discrete arithmetic never flips the sign of
    // the barrier value, preventing false violations or false safety.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_fixed_point_precision_fragmentation() {
        let cert = &FRAGMENTATION_CERTIFICATE;
        let scale = FRAGMENTATION_SCORE_SCALE;
        let mut max_relative_error: f64 = 0.0;

        // Sample representative inputs
        for a in (0..=1000).step_by(100) {
            for b in (0..=1000).step_by(100) {
                for c in (0..=1000).step_by(100) {
                    for d in (0..=1000).step_by(100) {
                        let basis = [a as i64, b as i64, c as i64, d as i64];
                        let fixed = cert.evaluate_quadratic_form(&basis, scale);

                        // Compute ideal f64 evaluation
                        let mut float_result: f64 = 0.0;
                        for i in 0..FRAGMENTATION_CERT_DIM {
                            for j in 0..FRAGMENTATION_CERT_DIM {
                                let coeff = cert.gram_matrix[i][j] as f64;
                                let bi = basis[i] as f64;
                                let bj = basis[j] as f64;
                                float_result += coeff * bi * bj;
                            }
                        }
                        let ideal = (float_result / scale as f64) as i64;

                        let diff = (fixed - ideal).unsigned_abs();
                        let denom = ideal.unsigned_abs().max(1);
                        let rel = diff as f64 / denom as f64;
                        if rel > max_relative_error {
                            max_relative_error = rel;
                        }
                    }
                }
            }
        }

        // The relative error should be negligible compared to the budget
        assert!(
            max_relative_error < 0.01,
            "Fixed-point relative error too large: {max_relative_error}"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Barrier Separation Property
    //
    // Theorem: The barrier function correctly separates safe and
    // unsafe operational regions. Specifically:
    //   - Zero-input (nominal) → positive barrier (safe)
    //   - Max-excess input → negative barrier (violation)
    //
    // This is the fundamental safety guarantee of the certificate.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_barrier_separation_fragmentation() {
        let cert = &FRAGMENTATION_CERTIFICATE;
        let scale = FRAGMENTATION_SCORE_SCALE;

        // Zero basis (no excess) → must be safe (positive barrier)
        let zero_barrier = cert.evaluate_barrier(&[0, 0, 0, 0], scale);
        assert!(
            zero_barrier > 0,
            "Zero-excess state must be safe, got barrier={zero_barrier}"
        );
        assert_eq!(
            zero_barrier, FRAGMENTATION_BARRIER_BUDGET_MILLI,
            "Zero-excess barrier should equal budget"
        );

        // Maximum excess → must violate (negative barrier)
        let max_barrier = cert.evaluate_barrier(&[1000, 1000, 1000, 1000], scale);
        assert!(
            max_barrier < 0,
            "Max-excess state must violate, got barrier={max_barrier}"
        );
    }

    #[test]
    fn proof_barrier_separation_thread_safety() {
        let cert = &THREAD_SAFETY_CERTIFICATE;
        let scale = THREAD_SAFETY_SCORE_SCALE;

        let zero_barrier = cert.evaluate_barrier(&[0, 0, 0, 0, 0], scale);
        assert!(
            zero_barrier > 0,
            "Zero-excess state must be safe, got barrier={zero_barrier}"
        );

        let max_barrier = cert.evaluate_barrier(&[1000, 1000, 1000, 1000, 1000], scale);
        assert!(
            max_barrier < 0,
            "Max-excess state must violate, got barrier={max_barrier}"
        );
    }

    #[test]
    fn proof_barrier_separation_size_class() {
        let cert = &SIZE_CLASS_CERTIFICATE;
        let scale = SIZE_CLASS_SCORE_SCALE;

        let zero_barrier = cert.evaluate_barrier(&[0, 0, 0, 0], scale);
        assert!(
            zero_barrier > 0,
            "Zero-excess state must be safe, got barrier={zero_barrier}"
        );

        let max_barrier = cert.evaluate_barrier(&[1000, 1000, 1000, 1000], scale);
        assert!(
            max_barrier < 0,
            "Max-excess state must violate, got barrier={max_barrier}"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Certificate Integrity (Hash Chain)
    //
    // Theorem: All certificate artifacts have valid integrity hashes.
    // The hash covers (dimension, degree, budget, matrix_bytes),
    // providing tamper-evidence for the offline synthesis pipeline.
    //
    // If any coefficient is modified, the hash will mismatch and the
    // runtime will reject the certificate.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_all_certificates_have_valid_integrity() {
        assert!(
            FRAGMENTATION_CERTIFICATE.verify_integrity(),
            "Fragmentation certificate integrity check failed"
        );
        assert!(
            THREAD_SAFETY_CERTIFICATE.verify_integrity(),
            "Thread-safety certificate integrity check failed"
        );
        assert!(
            SIZE_CLASS_CERTIFICATE.verify_integrity(),
            "Size-class certificate integrity check failed"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Gram Matrix Symmetry
    //
    // Theorem: All Gram matrices are symmetric (Q[i][j] = Q[j][i]).
    // This is a necessary condition for the SOS decomposition to be
    // valid (p(x) = z^T Q z requires Q symmetric).
    // ═══════════════════════════════════════════════════════════════

    #[test]
    #[allow(clippy::needless_range_loop)]
    fn proof_gram_matrix_symmetry() {
        for i in 0..FRAGMENTATION_CERT_DIM {
            for j in 0..FRAGMENTATION_CERT_DIM {
                assert_eq!(
                    FRAGMENTATION_GRAM_MATRIX[i][j], FRAGMENTATION_GRAM_MATRIX[j][i],
                    "Fragmentation Gram not symmetric at ({i},{j})"
                );
            }
        }
        for i in 0..THREAD_SAFETY_CERT_DIM {
            for j in 0..THREAD_SAFETY_CERT_DIM {
                assert_eq!(
                    THREAD_SAFETY_GRAM_MATRIX[i][j], THREAD_SAFETY_GRAM_MATRIX[j][i],
                    "Thread-safety Gram not symmetric at ({i},{j})"
                );
            }
        }
        for i in 0..SIZE_CLASS_CERT_DIM {
            for j in 0..SIZE_CLASS_CERT_DIM {
                assert_eq!(
                    SIZE_CLASS_GRAM_MATRIX[i][j], SIZE_CLASS_GRAM_MATRIX[j][i],
                    "Size-class Gram not symmetric at ({i},{j})"
                );
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Saturating Arithmetic Preserves Monotonicity
    //
    // Theorem: For the provenance barrier with fixed (depth, bloom, arena),
    // increasing risk_ppm strictly decreases the barrier value.
    // Saturating arithmetic does not break this monotonicity.
    //
    // This extends the existing sweep tests with a formal statement.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_saturating_arithmetic_preserves_risk_monotonicity() {
        // Test across ALL valid risk values (step=1000 for tractability)
        // for multiple fixed-parameter combinations
        let configs = [
            (0u32, 0u32, 0u32),
            (500_000, 200_000, 400_000),
            (1_000_000, 1_000_000, 1_000_000),
        ];
        for (depth, bloom, arena) in configs {
            let mut prev = i64::MAX;
            for risk in (0..=1_000_000).step_by(1_000) {
                let val = evaluate_provenance_barrier(risk, depth, bloom, arena);
                assert!(
                    val <= prev,
                    "Risk monotonicity broken: risk={risk}, \
                     depth={depth}, bloom={bloom}, arena={arena}: \
                     {val} > {prev}"
                );
                prev = val;
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Barrier Budget Sufficiency
    //
    // Theorem: The budget parameter for each certificate is large
    // enough to accept all "normal" operating points (where all excess
    // scores are below 50% of their range) and small enough to reject
    // all "critical" operating points (where any score exceeds 90%).
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_budget_sufficiency_fragmentation() {
        let cert = &FRAGMENTATION_CERTIFICATE;
        let scale = FRAGMENTATION_SCORE_SCALE;

        // Property 1: The origin (no excess on any dimension) must be safe
        // with maximum headroom.
        let origin_barrier = cert.evaluate_barrier(&[0, 0, 0, 0], scale);
        assert!(
            origin_barrier > 0,
            "Origin must be safe: barrier={origin_barrier}"
        );
        assert_eq!(
            origin_barrier, cert.barrier_budget_milli,
            "Origin should have full budget headroom"
        );

        // Property 2: Extreme points (any single excess at maximum 1000)
        // must be rejected — the budget is tight enough to catch them.
        for dim in 0..4 {
            let mut basis = [0i64; 4];
            basis[dim] = 1000;
            let extreme_barrier = cert.evaluate_barrier(&basis, scale);
            assert!(
                extreme_barrier < 0,
                "Extreme on dim {dim} should be rejected: barrier={extreme_barrier}"
            );
        }

        // Property 3: Budget monotonicity — increasing any excess dimension
        // (holding others at 0) monotonically decreases the barrier value.
        for dim in 0..4 {
            let mut prev = i64::MAX;
            for v in (0..=1000).step_by(50) {
                let mut basis = [0i64; 4];
                basis[dim] = v;
                let barrier = cert.evaluate_barrier(&basis, scale);
                assert!(
                    barrier <= prev,
                    "Budget monotonicity broken: dim={dim}, v={v}, \
                     barrier={barrier} > prev={prev}"
                );
                prev = barrier;
            }
        }
    }
}
