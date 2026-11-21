#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)] // live host-glibc fma/fmaf/fmaf128 oracle

//! Differential gate for fma/fmaf (bd-h95z6y) — only a scratch bench existed.
//! fma(x,y,z) computes x*y+z with a SINGLE rounding (the product is not rounded
//! before the add), so a naive `x*y+z` implementation diverges whenever the
//! exact product has bits below the rounded result. This gate includes cases
//! engineered to expose double rounding, plus a randomized grid and special
//! values, and requires fl to match host glibc bit-for-bit. No mocks.

//! The host arm is resolved with `dlsym` rather than declared at link time,
//! because a link-time `extern "C" { fn fma(..) }` is only an oracle in some
//! build profiles.
//!
//! fl's C exports are gated `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`.
//! Under the default dev profile that attribute is inactive, fl exports no C
//! symbols into the test binary, and the reference resolves through the PLT to
//! `libc.so.6` — fine. Under any profile with `debug_assertions` off
//! (`--release`, `--profile bench`, `release-perf`) fl's `fma` becomes a strong
//! global in the rlib, ELF prefers the archive over the shared library, and the
//! "glibc" arm silently becomes fl. All 40,000+ comparisons below would then
//! pass while comparing fl against itself.
//!
//! `dlsym` is correct in both profiles, so this gate does not depend on how it
//! was built. `conformance_diff_oracle_arm_provenance` documents the profile
//! split and fails loudly for the gates that still use the link-time pattern.

use std::ffi::c_void;

type Fma64 = unsafe extern "C" fn(f64, f64, f64) -> f64;
type Fma32 = unsafe extern "C" fn(f32, f32, f32) -> f32;

union Sym64 {
    raw: *mut c_void,
    function: Fma64,
}
union Sym32 {
    raw: *mut c_void,
    function: Fma32,
}

/// Open the object that owns the libm entry points. Modern glibc folds libm
/// into libc.so.6, but older layouts keep libm.so.6 separate, so try both
/// rather than assuming either.
fn libm_handle() -> *mut c_void {
    for name in [c"libm.so.6", c"libc.so.6"] {
        // SAFETY: name is a NUL-terminated constant; flags request a local handle.
        let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if !handle.is_null() {
            // SAFETY: handle came from dlopen.
            let probe = unsafe { libc::dlsym(handle, c"fma".as_ptr()) };
            if !probe.is_null() {
                return handle;
            }
        }
    }
    panic!("no host object exporting fma — the oracle is unavailable, so this gate cannot run");
}

fn host_fma() -> Fma64 {
    // SAFETY: the handle exports fma; the name is a NUL-terminated constant.
    let raw = unsafe { libc::dlsym(libm_handle(), c"fma".as_ptr()) };
    assert!(!raw.is_null(), "dlsym fma");
    // The defect this gate was fixed for: if the oracle and fl are the same
    // code, every comparison below passes while proving nothing. Assert the
    // positive fact rather than trusting the resolution.
    assert_ne!(
        raw as usize,
        frankenlibc_abi::math_abi::fma as *const () as usize,
        "the resolved oracle IS fl's fma — this gate would compare fl to itself"
    );
    // SAFETY: the resolved symbol has C's documented fma signature.
    unsafe { Sym64 { raw }.function }
}

fn host_fmaf() -> Fma32 {
    // SAFETY: as above, for the float entry point.
    let raw = unsafe { libc::dlsym(libm_handle(), c"fmaf".as_ptr()) };
    assert!(!raw.is_null(), "dlsym fmaf");
    assert_ne!(
        raw as usize,
        frankenlibc_abi::math_abi::fmaf as *const () as usize,
        "the resolved oracle IS fl's fmaf — this gate would compare fl to itself"
    );
    // SAFETY: the resolved symbol has C's documented fmaf signature.
    unsafe { Sym32 { raw }.function }
}

fn eq64(a: f64, b: f64) -> bool {
    a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan())
}
fn eq32(a: f32, b: f32) -> bool {
    a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan())
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

#[test]
fn fma_matches_glibc_double_rounding_cases() {
    let fma = host_fma();
    // Engineered cases where naive (x*y+z) double-rounds but a correct fma does
    // not. a = 1 + 2^-52, b = 1 + 2^-52, c = -(1 + 2^-51):
    //   exact a*b = 1 + 2^-51 + 2^-104; + c = 2^-104  (correct fma)
    //   naive: round(a*b)=1+2^-51, + c = 0            (wrong)
    let a = 1.0 + f64::from_bits(0x3CB0_0000_0000_0000); // 1 + 2^-52
    let b = a;
    let c = -(1.0 + f64::from_bits(0x3CC0_0000_0000_0000)); // -(1 + 2^-51)
    let g = unsafe { fma(a, b, c) };
    let f = unsafe { frankenlibc_abi::math_abi::fma(a, b, c) };
    assert!(eq64(f, g), "fma double-rounding case: fl={f:e} glibc={g:e}");

    // p = 1 + 2^-26 (mantissa bit 26 set); p*p = 1 + 2^-25 + 2^-52 exactly,
    // which naive rounding of the product would drop the 2^-52 term from.
    let p = 1.0 + f64::from_bits(0x3E50_0000_0000_0000); // 1 + 2^-26
    let pp_hi = 1.0 + f64::from_bits(0x3E60_0000_0000_0000); // 1 + 2^-25
    let cases = [(p, p, -pp_hi), (p, p, -1.0), (1e150, 1e150, -1e300)];
    for (x, y, z) in cases {
        let g = unsafe { fma(x, y, z) };
        let f = unsafe { frankenlibc_abi::math_abi::fma(x, y, z) };
        assert!(eq64(f, g), "fma({x:e},{y:e},{z:e}): fl={f:e} glibc={g:e}");
    }
}

#[test]
fn fma_matches_glibc_special_values() {
    let fma = host_fma();
    let sv = [
        0.0f64,
        -0.0,
        1.0,
        -1.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
    ];
    for &x in &sv {
        for &y in &sv {
            for &z in &sv {
                let g = unsafe { fma(x, y, z) };
                let f = unsafe { frankenlibc_abi::math_abi::fma(x, y, z) };
                assert!(eq64(f, g), "fma({x},{y},{z}): fl={f} glibc={g}");
            }
        }
    }
}

#[test]
fn fma_matches_glibc_random_grid() {
    let fma = host_fma();
    let mut rng = Rng(0x664D_0000_0000_0001);
    for _ in 0..20000 {
        let x = f64::from_bits(rng.next());
        let y = f64::from_bits(rng.next());
        let z = f64::from_bits(rng.next());
        let g = unsafe { fma(x, y, z) };
        let f = unsafe { frankenlibc_abi::math_abi::fma(x, y, z) };
        assert!(eq64(f, g), "fma({x:e},{y:e},{z:e}): fl={f:e} glibc={g:e}");
    }
}

#[test]
fn fmaf_matches_glibc() {
    let fmaf = host_fmaf();
    let mut rng = Rng(0x6D2B_0000_0000_0001);
    for _ in 0..20000 {
        let x = f32::from_bits(rng.next() as u32);
        let y = f32::from_bits((rng.next() >> 7) as u32);
        let z = f32::from_bits((rng.next() >> 13) as u32);
        let g = unsafe { fmaf(x, y, z) };
        let f = unsafe { frankenlibc_abi::math_abi::fmaf(x, y, z) };
        assert!(eq32(f, g), "fmaf({x:e},{y:e},{z:e}): fl={f:e} glibc={g:e}");
    }
}

type Fma128 = unsafe extern "C" fn(f128, f128, f128) -> f128;

union Sym128 {
    raw: *mut c_void,
    function: Fma128,
}

fn host_fmaf128() -> Fma128 {
    let raw = unsafe { libc::dlsym(libm_handle(), c"fmaf128".as_ptr()) };
    assert!(!raw.is_null(), "dlsym fmaf128");
    assert_ne!(
        raw as usize,
        frankenlibc_abi::math_abi::fmaf128 as *const () as usize,
        "resolved oracle IS fl's fmaf128"
    );
    unsafe { Sym128 { raw }.function }
}

fn eq128(a: f128, b: f128) -> bool {
    a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan())
}

unsafe extern "C" {
    fn fesetround(round: libc::c_int) -> libc::c_int;
    fn fegetround() -> libc::c_int;
}

#[test]
fn fmaf128_matches_glibc_bit_exact_across_rounding_modes() {
    let host = host_fmaf128();
    let saved_rm = unsafe { fegetround() };

    let sv: [f128; 11] = [
        0.0f128,
        -0.0f128,
        1.0f128,
        -1.0f128,
        f128::INFINITY,
        f128::NEG_INFINITY,
        f128::NAN,
        f128::from_bits(1),                  // min positive subnormal
        f128::from_bits((1u128 << 127) | 1), // min negative subnormal
        f128::MAX,
        -f128::MAX,
    ];

    // Exact double-rounding traps in binary128:
    let one_plus_eps = f128::from_bits((16_383u128 << 112) | 1);
    let one_plus_2eps = f128::from_bits((16_383u128 << 112) | 2);
    let p_half = f128::from_bits((16_383u128 << 112) | (1u128 << 56));
    let pp_hi = f128::from_bits((16_383u128 << 112) | (1u128 << 57));
    let huge = f128::from_bits((16_383u128 + 10_000) << 112);
    let huge_sq = f128::from_bits((16_383u128 + 16_383) << 112); // inf (for huge*huge - huge^2 test use 8190)
    let _ = huge_sq;
    let h8190 = f128::from_bits((16_383u128 + 8_190) << 112);
    let h16380 = f128::from_bits((16_383u128 + 16_380) << 112);
    let tiny = f128::from_bits((16_383u128 - 10_000) << 112);
    let traps = [
        (one_plus_eps, one_plus_eps, -one_plus_2eps),
        (p_half, p_half, -pp_hi),
        (p_half, p_half, -1.0f128),
        (h8190, h8190, -h16380),
        (huge, huge, -f128::MAX),
        (tiny, tiny, f128::from_bits(1)),
        (tiny, tiny, -f128::from_bits(1)),
        (1.0f128, f128::from_bits(1), -f128::from_bits(1)),
        (
            f128::from_bits(1u128 << 112), // MIN_POSITIVE
            0.5f128,
            0.0f128,
        ),
        (f128::from_bits(1), 0.5f128, 0.0f128),
    ];

    // x86 FE_* rounding modes: TONEAREST=0, DOWNWARD=0x400, UPWARD=0x800, TOWARDZERO=0xc00
    for rm in [0, 0x400, 0x800, 0xc00] {
        assert_eq!(unsafe { fesetround(rm) }, 0);
        for &x in &sv {
            for &y in &sv {
                for &z in &sv {
                    let g = unsafe { host(x, y, z) };
                    let f = unsafe { frankenlibc_abi::math_abi::fmaf128(x, y, z) };
                    assert!(
                        eq128(f, g),
                        "rm={rm:#x} fmaf128({:#034x}, {:#034x}, {:#034x}): fl={:#034x} glibc={:#034x}",
                        x.to_bits(),
                        y.to_bits(),
                        z.to_bits(),
                        f.to_bits(),
                        g.to_bits()
                    );
                }
            }
        }
        for &(x, y, z) in &traps {
            let g = unsafe { host(x, y, z) };
            let f = unsafe { frankenlibc_abi::math_abi::fmaf128(x, y, z) };
            assert!(
                eq128(f, g),
                "trap rm={rm:#x} fmaf128({:#034x}, {:#034x}, {:#034x}): fl={:#034x} glibc={:#034x}",
                x.to_bits(),
                y.to_bits(),
                z.to_bits(),
                f.to_bits(),
                g.to_bits()
            );
        }
        let mut rng = Rng(0xF128_0000_0000_0001u64 ^ (rm as u64));
        for _ in 0..2000 {
            let mk = |r: &mut Rng| -> f128 {
                let lo = r.next() as u128;
                let hi = r.next() as u128;
                let mut bits = (hi << 64) | lo;
                // Bias exponents into interesting overlapping/near-cancellation ranges half the time.
                if (hi & 1) == 0 {
                    let exp = 16_383i32 + (((hi >> 1) & 0x3ff) as i32) - 512;
                    bits = (bits & !(0x7fff_u128 << 112)) | ((exp as u128) << 112);
                }
                f128::from_bits(bits)
            };
            let x = mk(&mut rng);
            let y = mk(&mut rng);
            let z = mk(&mut rng);
            let g = unsafe { host(x, y, z) };
            let f = unsafe { frankenlibc_abi::math_abi::fmaf128(x, y, z) };
            assert!(
                eq128(f, g),
                "rand rm={rm:#x} fmaf128({:#034x}, {:#034x}, {:#034x}): fl={:#034x} glibc={:#034x}",
                x.to_bits(),
                y.to_bits(),
                z.to_bits(),
                f.to_bits(),
                g.to_bits()
            );
        }
    }
    unsafe { fesetround(saved_rm) };
}
