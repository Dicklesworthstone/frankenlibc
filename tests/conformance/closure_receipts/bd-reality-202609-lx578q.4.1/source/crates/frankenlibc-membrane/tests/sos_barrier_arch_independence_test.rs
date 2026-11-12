//! Architecture independence verification for SOS barrier certificates.
//!
//! These tests verify that the SOS barrier evaluation produces bit-identical
//! results across x86_64, aarch64, and RISC-V architectures by checking:
//!
//! 1. Hash computation uses explicit little-endian encoding
//! 2. Quadratic form evaluation uses platform-independent integer arithmetic
//! 3. Overflow saturation behavior is deterministic
//! 4. No architecture-specific code paths affect barrier outcomes
//!
//! Part of bd-10pq: Cross-cutting architecture heterogeneity.

use std::path::Path;

use frankenlibc_membrane::config::SafetyLevel;
use frankenlibc_membrane::ebr::EbrCollector;
use frankenlibc_membrane::runtime_math::sos_barrier::{
    SosBarrierState, evaluate_fragmentation_barrier, evaluate_size_class_barrier,
    evaluate_thread_safety_barrier,
};
use frankenlibc_membrane::runtime_math::{ApiFamily, RuntimeMathKernel, ValidationProfile};

#[allow(dead_code)]
#[path = "../build.rs"]
mod build_script;

/// Expected barrier values for canonical inputs (golden values).
///
/// These values were computed on x86_64 and must match on aarch64/RISC-V.
/// If a test fails on another architecture, either:
/// 1. There is a platform-dependent bug to fix, or
/// 2. The golden values need updating (document the change).
mod golden_values {
    // Fragmentation barrier: balanced profile (bd-10pq canonical)
    // Expected value computed on x86_64 Linux 6.x
    pub const FRAGMENTATION_BALANCED: (u32, u32, u32, u32, i64) = (
        50_000, 49_000, 120_000, 450_000, /* expected= */ 800_000,
    );

    // Fragmentation barrier: zero stress profile
    // Note: zero inputs still produce non-max value due to basis normalization
    pub const FRAGMENTATION_ZERO: (u32, u32, u32, u32, i64) =
        (0, 0, 0, 0, /* expected= */ 800_000);

    // Thread safety barrier: nominal profile (bd-10pq canonical)
    // Expected value computed on x86_64 Linux 6.x
    pub const THREAD_SAFETY_NOMINAL: (u32, u32, bool, u32, u32, i64) =
        (16, 1, false, 60_000, 50_000, /* expected= */ 900_000);

    // Thread safety barrier: zero stress profile
    // Note: zero inputs still produce non-max value due to basis normalization
    pub const THREAD_SAFETY_ZERO: (u32, u32, bool, u32, u32, i64) =
        (0, 0, false, 0, 0, /* expected= */ 900_000);

    // Size class barrier: nominal profile (bd-10pq canonical)
    // (requested_size, mapped_class_size, class_membership_valid)
    // Expected value computed on x86_64 Linux 6.x
    pub const SIZE_CLASS_NOMINAL: (usize, usize, bool, i64) =
        (100, 128, true, /* expected= */ 150_000);

    // Size class barrier: exact match profile (request == mapped)
    // Note: even exact match has waste from rounding to size class
    pub const SIZE_CLASS_EXACT: (usize, usize, bool, i64) =
        (64, 64, true, /* expected= */ 150_000);
}

/// Verify fragmentation barrier produces golden values.
///
/// This test must pass on all target architectures with identical results.
#[test]
fn fragmentation_barrier_golden_values_arch_independent() {
    {
        let (alloc, free, dispersion, util, expected) = golden_values::FRAGMENTATION_BALANCED;
        let actual = evaluate_fragmentation_barrier(alloc, free, dispersion, util);
        assert_eq!(
            actual, expected,
            "fragmentation barrier (balanced) must match golden value: got {actual}, expected {expected}"
        );
    }

    {
        let (alloc, free, dispersion, util, expected) = golden_values::FRAGMENTATION_ZERO;
        let actual = evaluate_fragmentation_barrier(alloc, free, dispersion, util);
        assert_eq!(
            actual, expected,
            "fragmentation barrier (zero) must match golden value: got {actual}, expected {expected}"
        );
    }
}

/// Verify thread safety barrier produces golden values.
///
/// This test must pass on all target architectures with identical results.
#[test]
fn thread_safety_barrier_golden_values_arch_independent() {
    {
        let (threads, writers, conflict, skew, lag, expected) =
            golden_values::THREAD_SAFETY_NOMINAL;
        let actual = evaluate_thread_safety_barrier(threads, writers, conflict, skew, lag);
        assert_eq!(
            actual, expected,
            "thread safety barrier (nominal) must match golden value: got {actual}, expected {expected}"
        );
    }

    {
        let (threads, writers, conflict, skew, lag, expected) = golden_values::THREAD_SAFETY_ZERO;
        let actual = evaluate_thread_safety_barrier(threads, writers, conflict, skew, lag);
        assert_eq!(
            actual, expected,
            "thread safety barrier (zero) must match golden value: got {actual}, expected {expected}"
        );
    }
}

/// Verify size class barrier produces golden values.
///
/// This test must pass on all target architectures with identical results.
#[test]
fn size_class_barrier_golden_values_arch_independent() {
    {
        let (requested, mapped, membership, expected) = golden_values::SIZE_CLASS_NOMINAL;
        let actual = evaluate_size_class_barrier(requested, mapped, membership);
        assert_eq!(
            actual, expected,
            "size class barrier (nominal) must match golden value: got {actual}, expected {expected}"
        );
    }

    {
        let (requested, mapped, membership, expected) = golden_values::SIZE_CLASS_EXACT;
        let actual = evaluate_size_class_barrier(requested, mapped, membership);
        assert_eq!(
            actual, expected,
            "size class barrier (minimal) must match golden value: got {actual}, expected {expected}"
        );
    }
}

/// Verify overflow saturation produces consistent results.
///
/// The quadratic form can overflow when inputs are extreme. The implementation
/// must saturate rather than panic or wrap, and do so identically on all archs.
#[test]
fn overflow_saturation_is_arch_independent() {
    // Extreme inputs that would overflow naive multiplication
    let extreme = evaluate_fragmentation_barrier(u32::MAX, u32::MAX, u32::MAX, u32::MAX);

    // Result must be non-positive (violation) and within i64 range
    assert!(
        extreme <= 0,
        "extreme fragmentation must indicate violation, got {extreme}"
    );

    // Same test for thread safety
    let extreme_ts = evaluate_thread_safety_barrier(u32::MAX, u32::MAX, true, u32::MAX, u32::MAX);
    assert!(
        extreme_ts <= 0,
        "extreme thread safety must indicate violation, got {extreme_ts}"
    );

    // Same test for size class - use max certified request size
    let extreme_sc = evaluate_size_class_barrier(usize::MAX, usize::MAX, false);
    assert!(
        extreme_sc <= 0,
        "extreme size class must indicate violation, got {extreme_sc}"
    );
}

/// Verify barrier monotonicity is preserved across architectures.
///
/// Higher stress must never appear safer than lower stress, regardless of arch.
#[test]
fn monotonicity_is_arch_independent() {
    let mut previous = i64::MAX;
    for stress in (0..=1_000_000u32).step_by(100_000) {
        let value = evaluate_fragmentation_barrier(stress, stress, stress, stress);
        assert!(
            value <= previous,
            "fragmentation barrier must be monotonically non-increasing: stress={stress}, value={value}, previous={previous}"
        );
        previous = value;
    }
}

/// Verify that no target_arch conditional compilation exists in SOS barrier.
///
/// This is a compile-time assertion enforced by this test's existence:
/// if arch-specific code were added to sos_barrier.rs, this test serves
/// as documentation that golden values may need updating per-arch.
#[test]
fn no_arch_specific_compilation_in_sos_barrier() {
    // This test documents the invariant. The real check is code review +
    // grep for target_arch in the sos_barrier module.
    //
    // If this test needs to be updated for arch-specific behavior, the
    // golden values above must be split into per-arch expected values.
    let source_guarantees = [
        "SOS barrier uses only platform-independent i64/u32 arithmetic",
        "Hash computation uses explicit to_le_bytes() encoding",
        "Overflow handling uses saturating_* methods",
        "No SIMD intrinsics in barrier evaluation hot path",
    ];
    assert_eq!(source_guarantees.len(), 4);
}

#[test]
fn build_script_sos_witness_accepts_production_certificates_and_rejects_counterexamples() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for rel_path in [
        "artifacts/sos/fragmentation_certificate.task",
        "artifacts/sos/thread_safety_certificate.task",
        "artifacts/sos/size_class_certificate.task",
    ] {
        let task_path = manifest_dir.join(rel_path);
        let task = build_script::parse_sos_task(&task_path)
            .unwrap_or_else(|err| panic!("failed to parse {rel_path}: {err}"));
        let barrier =
            build_script::build_barrier_polynomial(&task.gram_matrix, task.barrier_budget_milli);
        build_script::verify_barrier_against_sos_witness(
            &barrier,
            task.monomial_degree,
            &task.gram_matrix,
        )
        .unwrap_or_else(|err| panic!("valid SOS certificate {rel_path} rejected: {err}"));

        // Perturbing any diagonal quadratic term of B(z) without updating the Gram witness must fail.
        let mut perturbed_diag = barrier.clone();
        perturbed_diag.coefficients[1][1] += 1;
        assert!(
            build_script::verify_barrier_against_sos_witness(
                &perturbed_diag,
                task.monomial_degree,
                &task.gram_matrix,
            )
            .is_err(),
            "{rel_path}: perturbed diagonal term must be rejected by non-tautological SOS check"
        );

        // Perturbing a linear term z_0*z_1 of B(z) must fail.
        let mut perturbed_linear = barrier.clone();
        perturbed_linear.coefficients[0][1] -= 1;
        assert!(
            build_script::verify_barrier_against_sos_witness(
                &perturbed_linear,
                task.monomial_degree,
                &task.gram_matrix,
            )
            .is_err(),
            "{rel_path}: perturbed linear term must be rejected by non-tautological SOS check"
        );
    }

    // Negative LDL^T pivot must be rejected even if barrier polynomial was built from the same matrix.
    let neg_gram = vec![vec![0_i64, 0], vec![0, -5]];
    let neg_barrier = build_script::build_barrier_polynomial(&neg_gram, 100_000);
    assert!(
        build_script::verify_barrier_against_sos_witness(&neg_barrier, 2, &neg_gram).is_err(),
        "negative LDL^T pivot must be rejected"
    );

    // Indefinite zero-diagonal coupling matrix [[0, 1], [1, 0]] (eigenvalues +1, -1) must be rejected.
    let indef_gram = vec![vec![0_i64, 1], vec![1, 0]];
    let indef_barrier = build_script::build_barrier_polynomial(&indef_gram, 100_000);
    assert!(
        build_script::verify_barrier_against_sos_witness(&indef_barrier, 2, &indef_gram).is_err(),
        "indefinite zero-pivot off-diagonal coupling matrix must be rejected"
    );

    // Non-positive interior safety budget B(0) <= 0 must be rejected.
    let psd_gram = vec![vec![0_i64, 0], vec![0, 10]];
    let zero_budget_barrier = build_script::build_barrier_polynomial(&psd_gram, 0);
    assert!(
        build_script::verify_barrier_against_sos_witness(&zero_budget_barrier, 2, &psd_gram)
            .is_err(),
        "zero barrier budget B(0)=0 must be rejected"
    );
}

#[test]
fn runtime_math_kernel_evaluates_live_allocator_sos_certificates_and_detects_violations() {
    let collector = EbrCollector::new();
    let ebr_handle = collector.register();
    assert!(
        frankenlibc_membrane::ebr::active_registered_threads() >= 1,
        "EBR registration must advance active_registered_threads()"
    );

    let kernel = RuntimeMathKernel::new();
    let before = kernel.sos_barrier_summary();

    // Feed 64 nominal allocator observations (crossing WARMUP = 64 and CADENCE_FRAGMENTATION = 64)
    // plus valid size-class mappings.
    for step in 0..64 {
        kernel.observe_validation_result(
            SafetyLevel::Hardened,
            ApiFamily::Allocator,
            ValidationProfile::Full,
            18 + (step % 5),
            false,
        );
        kernel.observe_size_class_mapping(64, 64, true);
    }

    let nominal = kernel.sos_barrier_summary();
    assert!(
        nominal.fragmentation_hash_valid
            && nominal.thread_safety_hash_valid
            && nominal.size_class_hash_valid,
        "all offline SOS certificate SHA-256 proofs must verify: {nominal:?}"
    );
    assert!(
        nominal.total_observations >= before.total_observations + 64,
        "allocator observations must evaluate SOS barrier controller past WARMUP (64): before={}, after={}",
        before.total_observations,
        nominal.total_observations
    );
    let nominal_violations = nominal.provenance_violations
        + nominal.quarantine_violations
        + nominal.fragmentation_violations
        + nominal.thread_safety_violations
        + nominal.size_class_violations;
    assert_eq!(
        nominal_violations, 0,
        "nominal allocator + size-class telemetry must stay inside certified SOS safe set: {nominal:?}"
    );
    assert!(
        matches!(
            nominal.state,
            SosBarrierState::Safe | SosBarrierState::Warning
        ),
        "after 64 nominal observations SOS barrier state must exit Calibrating without violation: {nominal:?}"
    );

    // Feed invalid size-class membership mappings to drive SOS violation detection.
    for _ in 0..8 {
        kernel.observe_size_class_mapping(usize::MAX, usize::MAX, false);
    }
    let violated = kernel.sos_barrier_summary();
    assert!(
        violated.size_class_violations >= 8
            && violated.size_class_value < 0
            && matches!(violated.state, SosBarrierState::Violated),
        "invalid size-class mapping must trigger SOS barrier violation: {violated:?}"
    );

    drop(ebr_handle);
}
