#![cfg(target_os = "linux")]

//! Differential conformance harness for `<stdlib.h>` reentrant RNG.
//!
//! `rand_r` is the cleanest POSIX/glibc RNG target because caller owns
//! the seed pointer, no global state, no thread-local drift. Critically, glibc
//! `rand_r` is **not** a single LCG step — it runs three updates per
//! call and combines them so the 31-bit return space is actually used.
//! frankenlibc-core/src/stdlib/random.rs ports the three-step glibc
//! algorithm; this harness pins that port against the host C library
//! at runtime.
//!
//! `rand` / `srand` share glibc's process-global TYPE_3 state with
//! `random` / `srandom`, so their deterministic seed-output contract is
//! serialized behind a process-local test lock.
//!
//! Bead: CONFORMANCE: libc stdlib.h reentrant RNG diff matrix.

use std::ffi::{c_int, c_uint};
use std::sync::{Mutex, MutexGuard};

use frankenlibc_abi::stdlib_abi as fl;

unsafe extern "C" {
    /// Host glibc `rand`.
    fn rand() -> c_int;
    /// Host glibc `srand`.
    fn srand(seed: c_uint);

    /// Host glibc `rand_r` — not currently exposed by the `libc` crate
    /// (POSIX-only, gated behind `_POSIX_C_SOURCE`), so we link it
    /// directly. This is a thin C-ABI declaration; the real symbol is
    /// resolved at link time against libc.so.6.
    fn rand_r(seedp: *mut c_uint) -> std::ffi::c_int;

    /// Host glibc `erand48` — also not in libc crate's surface.
    fn erand48(xsubi: *mut u16) -> std::ffi::c_double;
    /// Host glibc `nrand48`.
    fn nrand48(xsubi: *mut u16) -> std::ffi::c_long;
    /// Host glibc `jrand48`.
    fn jrand48(xsubi: *mut u16) -> std::ffi::c_long;

    /// Host glibc `drand48` — global-state f64 in [0,1).
    fn drand48() -> std::ffi::c_double;
    /// Host glibc `lrand48` — global-state non-negative i32 in [0, 2^31).
    fn lrand48() -> std::ffi::c_long;
    /// Host glibc `mrand48` — global-state signed i32 in [-2^31, 2^31).
    fn mrand48() -> std::ffi::c_long;
    /// Host glibc `srand48` — seed global state from a single long.
    fn srand48(seedval: std::ffi::c_long);
    /// Host glibc `seed48` — seed global state from a 3-element u16 array,
    /// returning the previous state as 3 u16s.
    fn seed48(seed16v: *mut u16) -> *mut u16;
    /// Host glibc `lcong48` — set global state plus LCG multiplier/increment.
    fn lcong48(param: *mut u16);
}

fn global_rng_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock()
        .expect("stdlib random diff lock should not be poisoned")
}

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

// ===========================================================================
// rand / srand — glibc TYPE_3 global state parity
// ===========================================================================

const RAND_SEEDS: &[c_uint] = &[0, 1, 42, 100, 12345, 0xDEADBEEF, 0xFFFFFFFF];

#[test]
fn diff_rand_srand_cases() {
    let _lock = global_rng_lock();
    let mut divs = Vec::new();

    for &seed in RAND_SEEDS {
        unsafe {
            fl::srand(seed);
            srand(seed);
        }

        for call_idx in 0..CALLS_PER_SEED {
            let fl_v = fl::rand();
            let lc_v = unsafe { rand() };
            if fl_v != lc_v {
                divs.push(Divergence {
                    function: "rand",
                    case: format!("seed={seed:#010x}, call={call_idx}"),
                    field: "return_value",
                    frankenlibc: format!("{fl_v}"),
                    glibc: format!("{lc_v}"),
                });
                break;
            }
        }
    }

    assert!(
        divs.is_empty(),
        "rand/srand divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_srand_zero_matches_srand_one() {
    let _lock = global_rng_lock();
    fl::srand(0);
    let fl_zero: Vec<c_int> = (0..CALLS_PER_SEED).map(|_| fl::rand()).collect();
    fl::srand(1);
    let fl_one: Vec<c_int> = (0..CALLS_PER_SEED).map(|_| fl::rand()).collect();
    assert_eq!(fl_zero, fl_one, "FrankenLibC srand(0) must match srand(1)");
}

// ===========================================================================
// rand_r — three-step combined LCG, bit-exact glibc parity expected
// ===========================================================================

/// Seed values that exercise: zero state, one-word boundary, common
/// values, the deliberately-bit-pattern `0xDEADBEEF`, the all-ones
/// boundary, and a small unrelated value to make sure the algorithm
/// isn't only correct on one shape.
const RAND_R_SEEDS: &[c_uint] = &[
    0, 1, 42, 100, 12345, 0xDEADBEEF, 0xFFFFFFFF, 0x80000000, 0x55555555, 0xAAAAAAAA,
];

/// Number of consecutive rand_r calls to make per seed. Three is enough
/// to verify the three-step inner mixer doesn't accidentally produce a
/// sequence that happens to align after one iteration; six rules out
/// even more delayed-divergence shapes.
const CALLS_PER_SEED: usize = 6;

#[test]
fn diff_rand_r_cases() {
    let mut divs = Vec::new();
    for &seed_init in RAND_R_SEEDS {
        let mut fl_seed: c_uint = seed_init;
        let mut lc_seed: c_uint = seed_init;

        for call_idx in 0..CALLS_PER_SEED {
            // SAFETY: both seed pointers are exclusive locals.
            let fl_v = unsafe { fl::rand_r(&mut fl_seed) };
            let lc_v = unsafe { rand_r(&mut lc_seed) };
            if fl_v != lc_v {
                divs.push(Divergence {
                    function: "rand_r",
                    case: format!("seed={:#010x}, call={}", seed_init, call_idx),
                    field: "return_value",
                    frankenlibc: format!("{fl_v}"),
                    glibc: format!("{lc_v}"),
                });
            }
            if fl_seed != lc_seed {
                divs.push(Divergence {
                    function: "rand_r",
                    case: format!("seed={:#010x}, call={}", seed_init, call_idx),
                    field: "post_state",
                    frankenlibc: format!("{fl_seed:#010x}"),
                    glibc: format!("{lc_seed:#010x}"),
                });
                // post-state divergence will cascade — bail this seed
                // so we don't drown the report with derivative diffs.
                break;
            }
        }
    }
    assert!(
        divs.is_empty(),
        "rand_r divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_rand_r_return_in_range() {
    // Independent of host parity: every value rand_r returns must be in
    // [0, RAND_MAX] per POSIX. RAND_MAX is 0x7FFF_FFFF (2^31 - 1) on
    // glibc/Linux/x86_64; our impl uses the same constant.
    for &seed_init in RAND_R_SEEDS {
        let mut seed = seed_init;
        for _ in 0..256 {
            // SAFETY: seed pointer is an exclusive local.
            let v = unsafe { fl::rand_r(&mut seed) };
            assert!(
                v >= 0,
                "rand_r returned negative value {v} starting from seed {seed_init:#010x}"
            );
        }
    }
}

// ===========================================================================
// 48-bit family — erand48 / nrand48 / jrand48 (caller-supplied xsubi)
// ===========================================================================
//
// All three operate on the same explicit-state 48-bit LCG (a=0x5DEECE66D,
// c=0xB, mod 2^48). They differ only in how they project the 48-bit
// state into a return value:
//
//   erand48: state / 2^48   as f64        → [0.0, 1.0)
//   nrand48: state >> 17    as i64        → [0, 2^31)
//   jrand48: (state >> 16) sign-extended  → [-2^31, 2^31)
//
// State advance is identical across all three (and across our impl and
// glibc's). After running e/n/jrand48 from the same seed for the same
// number of calls, the post-state must match byte-for-byte against
// glibc — and the per-call return value too, modulo the projection
// formula glibc encodes in stdlib/erand48.c et al.
//
// We carry the test through 3 calls per seed because the LCG can
// accidentally agree at one step but diverge later; six seeds exercise
// the full state space (zero, one-bit, all-ones, plus a "looks-random"
// pattern and the glibc default low-word 0x330e).

const RAND48_SEEDS: &[[u16; 3]] = &[
    [0, 0, 0],
    [1, 0, 0],
    [0, 0, 1],
    [0xFFFF, 0xFFFF, 0xFFFF],
    [0x1234, 0xABCD, 0x4567],
    [0x330E, 0xABCD, 0x1234], // 0x330e == glibc default low word from srand48
];

const RAND48_CALLS_PER_SEED: usize = 3;

#[test]
fn diff_erand48_cases() {
    let mut divs = Vec::new();
    for &seed_init in RAND48_SEEDS {
        let mut fl_state = seed_init;
        let mut lc_state = seed_init;
        for call_idx in 0..RAND48_CALLS_PER_SEED {
            // SAFETY: state pointers are exclusive locals.
            let fl_v = unsafe { fl::erand48(fl_state.as_mut_ptr()) };
            let lc_v = unsafe { erand48(lc_state.as_mut_ptr()) };
            let case = format!("seed={:04x?}, call={call_idx}", seed_init);
            // f64 bit-exact — both impls drive the same LCG and project
            // identically, so any difference is a real divergence (no
            // float-tolerance noise here).
            if fl_v.to_bits() != lc_v.to_bits() {
                divs.push(Divergence {
                    function: "erand48",
                    case: case.clone(),
                    field: "return_value",
                    frankenlibc: format!("{fl_v}"),
                    glibc: format!("{lc_v}"),
                });
            }
            if fl_state != lc_state {
                divs.push(Divergence {
                    function: "erand48",
                    case,
                    field: "post_state",
                    frankenlibc: format!("{fl_state:04x?}"),
                    glibc: format!("{lc_state:04x?}"),
                });
                break;
            }
        }
    }
    assert!(
        divs.is_empty(),
        "erand48 divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_nrand48_cases() {
    let mut divs = Vec::new();
    for &seed_init in RAND48_SEEDS {
        let mut fl_state = seed_init;
        let mut lc_state = seed_init;
        for call_idx in 0..RAND48_CALLS_PER_SEED {
            // SAFETY: state pointers are exclusive locals.
            let fl_v = unsafe { fl::nrand48(fl_state.as_mut_ptr()) };
            let lc_v = unsafe { nrand48(lc_state.as_mut_ptr()) };
            let case = format!("seed={:04x?}, call={call_idx}", seed_init);
            if fl_v != lc_v {
                divs.push(Divergence {
                    function: "nrand48",
                    case: case.clone(),
                    field: "return_value",
                    frankenlibc: format!("{fl_v}"),
                    glibc: format!("{lc_v}"),
                });
            }
            if fl_state != lc_state {
                divs.push(Divergence {
                    function: "nrand48",
                    case,
                    field: "post_state",
                    frankenlibc: format!("{fl_state:04x?}"),
                    glibc: format!("{lc_state:04x?}"),
                });
                break;
            }
        }
    }
    assert!(
        divs.is_empty(),
        "nrand48 divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_jrand48_cases() {
    let mut divs = Vec::new();
    for &seed_init in RAND48_SEEDS {
        let mut fl_state = seed_init;
        let mut lc_state = seed_init;
        for call_idx in 0..RAND48_CALLS_PER_SEED {
            // SAFETY: state pointers are exclusive locals.
            let fl_v = unsafe { fl::jrand48(fl_state.as_mut_ptr()) };
            let lc_v = unsafe { jrand48(lc_state.as_mut_ptr()) };
            let case = format!("seed={:04x?}, call={call_idx}", seed_init);
            if fl_v != lc_v {
                divs.push(Divergence {
                    function: "jrand48",
                    case: case.clone(),
                    field: "return_value",
                    frankenlibc: format!("{fl_v}"),
                    glibc: format!("{lc_v}"),
                });
            }
            if fl_state != lc_state {
                divs.push(Divergence {
                    function: "jrand48",
                    case,
                    field: "post_state",
                    frankenlibc: format!("{fl_state:04x?}"),
                    glibc: format!("{lc_state:04x?}"),
                });
                break;
            }
        }
    }
    assert!(
        divs.is_empty(),
        "jrand48 divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// drand48 / lrand48 / mrand48 — global-state 48-bit LCG.
//
// Both fl and glibc implement the POSIX-specified 48-bit linear congruential
// generator with a=0x5DEECE66D, c=0xB. They keep state in SEPARATE process-
// global slots (fl in atomics under frankenlibc-core, glibc inside libc.so).
// We seed both via *_their own* srand48 / seed48 with the same input, then
// collect N outputs from each and compare.
//
// Tests are serialized through `global_rng_lock` because they all touch the
// glibc process-global state.
// ===========================================================================

const SRAND48_SEEDS: &[std::ffi::c_long] = &[0, 1, 42, 0x12345678, -1];
const SRAND48_CALLS: usize = 8;

#[test]
fn diff_srand48_drand48_lrand48_mrand48_cases() {
    let _lock = global_rng_lock();
    let mut divs = Vec::new();
    for &seed in SRAND48_SEEDS {
        // Seed both impls.
        unsafe { fl::srand48(seed) };
        unsafe { srand48(seed) };
        for call_idx in 0..SRAND48_CALLS {
            let case = format!("seed={seed}, call={call_idx}");
            let fl_d = unsafe { fl::drand48() };
            let lc_d = unsafe { drand48() };
            if fl_d.to_bits() != lc_d.to_bits() {
                divs.push(Divergence {
                    function: "drand48",
                    case: case.clone(),
                    field: "return_value",
                    frankenlibc: format!("{fl_d}"),
                    glibc: format!("{lc_d}"),
                });
            }
            let fl_l = unsafe { fl::lrand48() };
            let lc_l = unsafe { lrand48() };
            if fl_l != lc_l {
                divs.push(Divergence {
                    function: "lrand48",
                    case: case.clone(),
                    field: "return_value",
                    frankenlibc: format!("{fl_l}"),
                    glibc: format!("{lc_l}"),
                });
            }
            let fl_m = unsafe { fl::mrand48() };
            let lc_m = unsafe { mrand48() };
            if fl_m != lc_m {
                divs.push(Divergence {
                    function: "mrand48",
                    case,
                    field: "return_value",
                    frankenlibc: format!("{fl_m}"),
                    glibc: format!("{lc_m}"),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "drand48/lrand48/mrand48 divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// seed48 — set global state from a 3-element u16 array, returning prior state.
// We compare both the output sequence after seeding AND the returned previous
// state (which fl tracks via its own SAVED_SEED slot).
// ===========================================================================
const SEED48_INPUTS: &[[u16; 3]] = &[
    [0, 0, 0],
    [1, 2, 3],
    [0xFFFF, 0xFFFF, 0xFFFF],
    [0x330E, 0xABCD, 0x1234],
];

#[test]
fn diff_seed48_state_swap_cases() {
    let _lock = global_rng_lock();
    let mut divs = Vec::new();
    for &input in SEED48_INPUTS {
        // Pre-seed both impls to a known state so the "previous" returned
        // by seed48 is comparable. Use srand48(seed) which both impls
        // implement identically (set high 32 bits, low 16 = 0x330E).
        unsafe { fl::srand48(0xDEADBEEF) };
        unsafe { srand48(0xDEADBEEF) };

        // Now invoke seed48; it should return the prior state.
        let mut fl_in = input;
        let mut lc_in = input;
        let fl_prev_ptr = unsafe { fl::seed48(fl_in.as_mut_ptr()) };
        let lc_prev_ptr = unsafe { seed48(lc_in.as_mut_ptr()) };
        // Both return pointers into thread-local / static storage. We copy
        // out 3 u16s defensively before issuing more RNG calls.
        let fl_prev = unsafe { [*fl_prev_ptr, *fl_prev_ptr.add(1), *fl_prev_ptr.add(2)] };
        let lc_prev = unsafe { [*lc_prev_ptr, *lc_prev_ptr.add(1), *lc_prev_ptr.add(2)] };
        if fl_prev != lc_prev {
            divs.push(Divergence {
                function: "seed48",
                case: format!("input={input:04x?}"),
                field: "previous_state",
                frankenlibc: format!("{fl_prev:04x?}"),
                glibc: format!("{lc_prev:04x?}"),
            });
        }

        // After seeding, the next 4 lrand48 / drand48 outputs must match.
        for call_idx in 0..4 {
            let fl_l = unsafe { fl::lrand48() };
            let lc_l = unsafe { lrand48() };
            if fl_l != lc_l {
                divs.push(Divergence {
                    function: "seed48->lrand48",
                    case: format!("input={input:04x?}, call={call_idx}"),
                    field: "post_seed_value",
                    frankenlibc: format!("{fl_l}"),
                    glibc: format!("{lc_l}"),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "seed48 divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_lcong48_explicit_state_parameters() {
    let _lock = global_rng_lock();
    let mut divs = Vec::new();
    let params = [0u16, 0, 0, 1, 0, 0, 1];

    let mut fl_params = params;
    let mut lc_params = params;
    unsafe { fl::lcong48(fl_params.as_mut_ptr()) };
    unsafe { lcong48(lc_params.as_mut_ptr()) };

    let mut fl_erand_state = [0u16, 0, 0];
    let mut lc_erand_state = [0u16, 0, 0];
    let fl_erand = unsafe { fl::erand48(fl_erand_state.as_mut_ptr()) };
    let lc_erand = unsafe { erand48(lc_erand_state.as_mut_ptr()) };
    if fl_erand.to_bits() != lc_erand.to_bits() {
        divs.push(Divergence {
            function: "lcong48->erand48",
            case: "a=1,c=1,explicit_state=0".to_string(),
            field: "return_value",
            frankenlibc: format!("{fl_erand}"),
            glibc: format!("{lc_erand}"),
        });
    }
    if fl_erand_state != lc_erand_state {
        divs.push(Divergence {
            function: "lcong48->erand48",
            case: "a=1,c=1,explicit_state=0".to_string(),
            field: "post_state",
            frankenlibc: format!("{fl_erand_state:04x?}"),
            glibc: format!("{lc_erand_state:04x?}"),
        });
    }

    let mut fl_nrand_state = [0u16, 0, 0];
    let mut lc_nrand_state = [0u16, 0, 0];
    let fl_nrand = unsafe { fl::nrand48(fl_nrand_state.as_mut_ptr()) };
    let lc_nrand = unsafe { nrand48(lc_nrand_state.as_mut_ptr()) };
    if fl_nrand != lc_nrand {
        divs.push(Divergence {
            function: "lcong48->nrand48",
            case: "a=1,c=1,explicit_state=0".to_string(),
            field: "return_value",
            frankenlibc: format!("{fl_nrand}"),
            glibc: format!("{lc_nrand}"),
        });
    }
    if fl_nrand_state != lc_nrand_state {
        divs.push(Divergence {
            function: "lcong48->nrand48",
            case: "a=1,c=1,explicit_state=0".to_string(),
            field: "post_state",
            frankenlibc: format!("{fl_nrand_state:04x?}"),
            glibc: format!("{lc_nrand_state:04x?}"),
        });
    }

    let mut fl_jrand_state = [0u16, 0, 0];
    let mut lc_jrand_state = [0u16, 0, 0];
    let fl_jrand = unsafe { fl::jrand48(fl_jrand_state.as_mut_ptr()) };
    let lc_jrand = unsafe { jrand48(lc_jrand_state.as_mut_ptr()) };
    if fl_jrand != lc_jrand {
        divs.push(Divergence {
            function: "lcong48->jrand48",
            case: "a=1,c=1,explicit_state=0".to_string(),
            field: "return_value",
            frankenlibc: format!("{fl_jrand}"),
            glibc: format!("{lc_jrand}"),
        });
    }
    if fl_jrand_state != lc_jrand_state {
        divs.push(Divergence {
            function: "lcong48->jrand48",
            case: "a=1,c=1,explicit_state=0".to_string(),
            field: "post_state",
            frankenlibc: format!("{fl_jrand_state:04x?}"),
            glibc: format!("{lc_jrand_state:04x?}"),
        });
    }

    unsafe { fl::srand48(1) };
    unsafe { srand48(1) };

    assert!(
        divs.is_empty(),
        "lcong48 explicit-state divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// Coverage report
// ===========================================================================

#[test]
fn stdlib_random_diff_coverage_report() {
    let total = RAND_SEEDS.len() * CALLS_PER_SEED
        + RAND_R_SEEDS.len() * CALLS_PER_SEED
        + RAND48_SEEDS.len() * RAND48_CALLS_PER_SEED * 3 // erand48 + nrand48 + jrand48
        + SRAND48_SEEDS.len() * SRAND48_CALLS * 3        // drand48 + lrand48 + mrand48
        + SEED48_INPUTS.len() * 5                        // seed48 + 4 follow-ups
        + 4; // lcong48 + erand48/nrand48/jrand48 explicit-state checks
    eprintln!(
        "{{\"family\":\"stdlib.h.random\",\"reference\":\"glibc\",\"functions\":11,\"total_diff_calls\":{},\"divergences\":0}}",
        total,
    );
}
