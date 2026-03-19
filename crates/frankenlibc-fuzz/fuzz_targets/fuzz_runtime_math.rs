#![no_main]
//! Structure-aware fuzz target for the runtime math decision kernel.
//!
//! Exercises `RuntimeMathKernel::decide` and `observe_validation_result`
//! across API families, modes, contention hints, and adverse outcomes.
//! Invariants:
//! - No panics across repeated decision/observation cycles
//! - Risk bounds remain within ppm range
//! - Repair/full-validate actions always imply full validation
//!
//! Bead: bd-1oz.7

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_membrane::{
    ApiFamily, MembraneAction, RuntimeContext, RuntimeMathKernel, SafetyLevel,
};

#[derive(Debug, Arbitrary)]
struct RuntimeMathFuzzInput {
    family: u8,
    mode: u8,
    addr_hint: u64,
    requested_bytes: u16,
    contention_hint: u16,
    cost_seed: u16,
    iterations: u8,
    adverse_mask: u32,
    is_write: bool,
    bloom_negative: bool,
}

fuzz_target!(|input: RuntimeMathFuzzInput| {
    let mode = match input.mode % 3 {
        0 => SafetyLevel::Strict,
        1 => SafetyLevel::Hardened,
        _ => SafetyLevel::Off,
    };
    let _bounded_hint_len = input.addr_hint.to_le_bytes().len().min(8);
    let kernel = RuntimeMathKernel::new_for_mode(mode);
    let iterations = usize::from(input.iterations).min(15) + 1;
    let mut addr_hint = input.addr_hint as usize;

    for step in 0..iterations {
        let family = api_family((usize::from(input.family) + step) % ApiFamily::COUNT);
        let requested_bytes = usize::from(input.requested_bytes).saturating_add(step * 17);
        let ctx = RuntimeContext {
            family,
            addr_hint,
            requested_bytes,
            is_write: if step.is_multiple_of(2) {
                input.is_write
            } else {
                !input.is_write
            },
            contention_hint: input.contention_hint.wrapping_add(step as u16),
            bloom_negative: if step.is_multiple_of(3) {
                input.bloom_negative
            } else {
                !input.bloom_negative
            },
        };

        let decision = kernel.decide(mode, ctx);
        let mirror_kernel = RuntimeMathKernel::new_for_mode(mode);
        let mirror_decision = mirror_kernel.decide(mode, ctx);
        assert_eq!(
            decision.profile, mirror_decision.profile,
            "determinism: profile should be stable for identical seed context"
        );
        assert_eq!(
            decision.action, mirror_decision.action,
            "determinism: action should be stable for identical seed context"
        );
        assert!(
            decision.risk_upper_bound_ppm <= 1_000_000,
            "risk bound out of range: {}",
            decision.risk_upper_bound_ppm
        );
        match decision.action {
            MembraneAction::FullValidate | MembraneAction::Repair(_) => {
                assert!(
                    decision.requires_full_validation(),
                    "full-validation action must require full validation"
                );
            }
            MembraneAction::Allow | MembraneAction::Deny => {}
        }

        let estimated_cost_ns = 1 + (u64::from(input.cost_seed) + step as u64 * 13) % 5_000;
        let adverse = ((input.adverse_mask >> (step % 32)) & 1) == 1;
        kernel.observe_validation_result(
            mode,
            family,
            decision.profile,
            estimated_cost_ns,
            adverse,
        );

        addr_hint = addr_hint.rotate_left(5) ^ requested_bytes ^ step;
    }
});

fn api_family(index: usize) -> ApiFamily {
    match index {
        0 => ApiFamily::PointerValidation,
        1 => ApiFamily::Allocator,
        2 => ApiFamily::StringMemory,
        3 => ApiFamily::Stdio,
        4 => ApiFamily::Threading,
        5 => ApiFamily::Resolver,
        6 => ApiFamily::MathFenv,
        7 => ApiFamily::Loader,
        8 => ApiFamily::Stdlib,
        9 => ApiFamily::Ctype,
        10 => ApiFamily::Time,
        11 => ApiFamily::Signal,
        12 => ApiFamily::IoFd,
        13 => ApiFamily::Socket,
        14 => ApiFamily::Locale,
        15 => ApiFamily::Termios,
        16 => ApiFamily::Inet,
        17 => ApiFamily::Process,
        18 => ApiFamily::VirtualMemory,
        _ => ApiFamily::Poll,
    }
}
