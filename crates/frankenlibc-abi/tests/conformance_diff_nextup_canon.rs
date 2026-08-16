//! Conformance gate for C23 nextup/nextdown/canonicalize (+f32) vs host glibc.
//! glibc may expose these as IFUNCs (a raw fn pointer hits the resolver), so the
//! expected (bits/ret) tuples are GROUND TRUTH captured from a gcc -fno-builtin
//! program that calls them directly. fl is exercised via Rust paths. Covers
//! ±0, ±inf, the subnormal/zero boundary, MAX, quiet NaN, and SIGNALING NaN
//! (which nextup/nextdown/canonicalize all quiet — set the mantissa MSB).
//!
//! ## Live arm added 2026-08-16 (bd-v0388t)
//!
//! The header above says "GROUND TRUTH captured from a gcc -fno-builtin
//! program", and that is the whole problem: captured once, offline, and frozen.
//! The test is named `nextup_canonicalize_matches_glibc` and never called glibc.
//! The IFUNC worry the header cites is real but it argues for `dlsym`, which
//! resolves through the resolver exactly as a normal call does — not for
//! freezing literals.
//!
//! The tables are KEPT and a dlsym arm runs the same inputs, in both the value
//! test and the FE_INVALID one. All seven entry points live in `libm.so.6` on
//! this host, including `canonicalizef128`.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]
use frankenlibc_abi::math_abi as fl;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type Unary64 = unsafe extern "C" fn(f64) -> f64;
type Unary32 = unsafe extern "C" fn(f32) -> f32;
type Canon64 = unsafe extern "C" fn(*mut f64, *const f64) -> core::ffi::c_int;
type Canon32 = unsafe extern "C" fn(*mut f32, *const f32) -> core::ffi::c_int;
type Canon128 = unsafe extern "C" fn(*mut f128, *const f128) -> core::ffi::c_int;

struct HostArm {
    nextup: Unary64,
    nextdown: Unary64,
    nextupf: Unary32,
    nextdownf: Unary32,
    canonicalize: Canon64,
    canonicalizef: Canon32,
    canonicalizef128: Canon128,
}

fn host() -> HostArm {
    // SAFETY: every signature below matches the C declaration in <math.h>. The
    // canonicalize family takes both operands by pointer, so the f128 entry
    // point raises no argument-passing question.
    unsafe {
        HostArm {
            nextup: dlsym_oracle::host_fn(c"nextup", fl::nextup as *const ()),
            nextdown: dlsym_oracle::host_fn(c"nextdown", fl::nextdown as *const ()),
            nextupf: dlsym_oracle::host_fn(c"nextupf", fl::nextupf as *const ()),
            nextdownf: dlsym_oracle::host_fn(c"nextdownf", fl::nextdownf as *const ()),
            canonicalize: dlsym_oracle::host_fn(c"canonicalize", fl::canonicalize as *const ()),
            canonicalizef: dlsym_oracle::host_fn(c"canonicalizef", fl::canonicalizef as *const ()),
            canonicalizef128: dlsym_oracle::host_fn(
                c"canonicalizef128",
                fl::canonicalizef128 as *const (),
            ),
        }
    }
}

// (x_bits, nextup_bits, nextdown_bits)
const NU64: &[(u64, u64, u64)] = &[
    (0x0000000000000000, 0x0000000000000001, 0x8000000000000001),
    (0x8000000000000000, 0x0000000000000001, 0x8000000000000001),
    (0x3ff0000000000000, 0x3ff0000000000001, 0x3fefffffffffffff),
    (0xbff0000000000000, 0xbfefffffffffffff, 0xbff0000000000001),
    (0x7ff0000000000000, 0x7ff0000000000000, 0x7fefffffffffffff),
    (0xfff0000000000000, 0xffefffffffffffff, 0xfff0000000000000),
    (0x7ff8000000000000, 0x7ff8000000000000, 0x7ff8000000000000),
    (0xfff8000000000000, 0xfff8000000000000, 0xfff8000000000000),
    (0x0000000000000001, 0x0000000000000002, 0x0000000000000000),
    (0x8000000000000001, 0x8000000000000000, 0x8000000000000002),
    (0x0010000000000000, 0x0010000000000001, 0x000fffffffffffff),
    (0x7fefffffffffffff, 0x7ff0000000000000, 0x7feffffffffffffe),
    (0xffefffffffffffff, 0xffeffffffffffffe, 0xfff0000000000000),
    (0x3fe0000000000000, 0x3fe0000000000001, 0x3fdfffffffffffff),
    (0x7ff4000000000000, 0x7ffc000000000000, 0x7ffc000000000000),
    (0x7ffc000000000000, 0x7ffc000000000000, 0x7ffc000000000000),
];
const NU32: &[(u32, u32, u32)] = &[
    (0x00000000, 0x00000001, 0x80000001),
    (0x80000000, 0x00000001, 0x80000001),
    (0x3f800000, 0x3f800001, 0x3f7fffff),
    (0xbf800000, 0xbf7fffff, 0xbf800001),
    (0x7f800000, 0x7f800000, 0x7f7fffff),
    (0xff800000, 0xff7fffff, 0xff800000),
    (0x7fc00000, 0x7fc00000, 0x7fc00000),
    (0x00000001, 0x00000002, 0x00000000),
    (0x80000001, 0x80000000, 0x80000002),
    (0x7f7fffff, 0x7f800000, 0x7f7ffffe),
    (0x7fa00000, 0x7fe00000, 0x7fe00000),
];
// (x_bits, ret, out_bits)
const CN64: &[(u64, i32, u64)] = &[
    (0x0000000000000000, 0, 0x0000000000000000),
    (0x8000000000000000, 0, 0x8000000000000000),
    (0x3ff0000000000000, 0, 0x3ff0000000000000),
    (0xbff0000000000000, 0, 0xbff0000000000000),
    (0x7ff0000000000000, 0, 0x7ff0000000000000),
    (0xfff0000000000000, 0, 0xfff0000000000000),
    (0x7ff8000000000000, 0, 0x7ff8000000000000),
    (0xfff8000000000000, 0, 0xfff8000000000000),
    (0x0000000000000001, 0, 0x0000000000000001),
    (0x8000000000000001, 0, 0x8000000000000001),
    (0x0010000000000000, 0, 0x0010000000000000),
    (0x7fefffffffffffff, 0, 0x7fefffffffffffff),
    (0xffefffffffffffff, 0, 0xffefffffffffffff),
    (0x3fe0000000000000, 0, 0x3fe0000000000000),
    (0x7ff4000000000000, 0, 0x7ffc000000000000),
    (0x7ffc000000000000, 0, 0x7ffc000000000000),
];
const CN32: &[(u32, i32, u32)] = &[
    (0x00000000, 0, 0x00000000),
    (0x80000000, 0, 0x80000000),
    (0x3f800000, 0, 0x3f800000),
    (0xbf800000, 0, 0xbf800000),
    (0x7f800000, 0, 0x7f800000),
    (0xff800000, 0, 0xff800000),
    (0x7fc00000, 0, 0x7fc00000),
    (0x00000001, 0, 0x00000001),
    (0x80000001, 0, 0x80000001),
    (0x7f7fffff, 0, 0x7f7fffff),
    (0x7fa00000, 0, 0x7fe00000),
];
const CN128: &[(u128, i32, u128)] = &[
    (
        0x00000000000000000000000000000000,
        0,
        0x00000000000000000000000000000000,
    ),
    (
        0x80000000000000000000000000000000,
        0,
        0x80000000000000000000000000000000,
    ),
    (
        0x3fff0000000000000000000000000000,
        0,
        0x3fff0000000000000000000000000000,
    ),
    (
        0xbfff0000000000000000000000000000,
        0,
        0xbfff0000000000000000000000000000,
    ),
    (
        0x7fff0000000000000000000000000000,
        0,
        0x7fff0000000000000000000000000000,
    ),
    (
        0xffff0000000000000000000000000000,
        0,
        0xffff0000000000000000000000000000,
    ),
    (
        0x7fff8000000000000000000000000000,
        0,
        0x7fff8000000000000000000000000000,
    ),
    (
        0xffff8000000000000000000000000000,
        0,
        0xffff8000000000000000000000000000,
    ),
    (
        0x00000000000000000000000000000001,
        0,
        0x00000000000000000000000000000001,
    ),
    (
        0x80000000000000000000000000000001,
        0,
        0x80000000000000000000000000000001,
    ),
    (
        0x00010000000000000000000000000000,
        0,
        0x00010000000000000000000000000000,
    ),
    (
        0x7ffeffffffffffffffffffffffffffff,
        0,
        0x7ffeffffffffffffffffffffffffffff,
    ),
    (
        0xfffeffffffffffffffffffffffffff,
        0,
        0xfffeffffffffffffffffffffffffff,
    ),
    (
        0x3ffe0000000000000000000000000000,
        0,
        0x3ffe0000000000000000000000000000,
    ),
    (
        0x7fff4000000000000000000000000000,
        0,
        0x7fffc000000000000000000000000000,
    ),
    (
        0xffff4000000000000000000000000000,
        0,
        0xffffc000000000000000000000000000,
    ),
];

unsafe extern "C" {
    fn feclearexcept(excepts: core::ffi::c_int) -> core::ffi::c_int;
    fn fetestexcept(excepts: core::ffi::c_int) -> core::ffi::c_int;
}
const FE_INVALID: core::ffi::c_int = 0x1;

/// The value table above pins that a SIGNALING NaN comes back QUIETED. It does
/// NOT pin the accompanying FE_INVALID, and fl raised nothing while still
/// passing — an unchecked divergence sitting behind a green gate.
///
/// Ground truth from the host, values and flags together:
///
/// ```text
///   nextup  (sNaN 0x7ff4000000000000) -> 0x7ffc000000000000  flags 0x1
///   nextdown(sNaN 0x7ff4000000000000) -> 0x7ffc000000000000  flags 0x1
///   nextupf (sNaN 0x7fa00000)         -> 0x7fe00000          flags 0x1
///   nextup  (qNaN 0x7ff8000000000000) -> unchanged           flags 0x0
/// ```
///
/// The quiet-NaN rows are the control: a blanket "always raise invalid on NaN"
/// would satisfy the signaling rows and fail these. bd-4ojokx.
#[test]
fn signaling_nan_operand_raises_invalid_quiet_does_not() {
    fn flags_after<T>(f: impl FnOnce() -> T) -> core::ffi::c_int {
        unsafe { feclearexcept(FE_INVALID) };
        let _ = core::hint::black_box(f());
        unsafe { fetestexcept(FE_INVALID) }
    }

    let snan64 = f64::from_bits(0x7ff4000000000000);
    let qnan64 = f64::from_bits(0x7ff8000000000000);
    let snan32 = f32::from_bits(0x7fa00000);
    let qnan32 = f32::from_bits(0x7fc00000);

    assert_eq!(flags_after(|| unsafe { fl::nextup(snan64) }), FE_INVALID, "nextup(sNaN)");
    assert_eq!(
        flags_after(|| unsafe { fl::nextdown(snan64) }),
        FE_INVALID,
        "nextdown(sNaN)"
    );
    assert_eq!(
        flags_after(|| unsafe { fl::nextupf(snan32) }),
        FE_INVALID,
        "nextupf(sNaN)"
    );
    assert_eq!(
        flags_after(|| unsafe { fl::nextdownf(snan32) }),
        FE_INVALID,
        "nextdownf(sNaN)"
    );

    assert_eq!(flags_after(|| unsafe { fl::nextup(qnan64) }), 0, "nextup(qNaN)");
    assert_eq!(flags_after(|| unsafe { fl::nextdown(qnan64) }), 0, "nextdown(qNaN)");
    assert_eq!(flags_after(|| unsafe { fl::nextupf(qnan32) }), 0, "nextupf(qNaN)");
    assert_eq!(flags_after(|| unsafe { fl::nextdownf(qnan32) }), 0, "nextdownf(qNaN)");

    // The same eight calls through the live host arm. The flag ground truth in
    // this test's doc comment was, like the value tables, read off the host once
    // and frozen; both arms share one thread's FPU status word, so running them
    // through the same `flags_after` harness compares the rule rather than the
    // transcript of it.
    let h = host();
    // SAFETY: each call takes a live float by value and returns one.
    for (name, got, want) in [
        ("nextup(sNaN)", flags_after(|| unsafe { (h.nextup)(snan64) }), FE_INVALID),
        ("nextdown(sNaN)", flags_after(|| unsafe { (h.nextdown)(snan64) }), FE_INVALID),
        ("nextupf(sNaN)", flags_after(|| unsafe { (h.nextupf)(snan32) }), FE_INVALID),
        ("nextdownf(sNaN)", flags_after(|| unsafe { (h.nextdownf)(snan32) }), FE_INVALID),
        ("nextup(qNaN)", flags_after(|| unsafe { (h.nextup)(qnan64) }), 0),
        ("nextdown(qNaN)", flags_after(|| unsafe { (h.nextdown)(qnan64) }), 0),
        ("nextupf(qNaN)", flags_after(|| unsafe { (h.nextupf)(qnan32) }), 0),
        ("nextdownf(qNaN)", flags_after(|| unsafe { (h.nextdownf)(qnan32) }), 0),
    ] {
        assert_eq!(
            got, want,
            "live glibc {name} raised FE_INVALID={got:#x}, fl's rule expects {want:#x} — \
             a divergence here means the frozen flag ground truth no longer describes the host"
        );
    }
}

#[test]
fn nextup_canonicalize_matches_glibc() {
    let mut div: Vec<String> = Vec::new();
    for &(xb, up, dn) in NU64 {
        let x = f64::from_bits(xb);
        let fu = unsafe { fl::nextup(x) }.to_bits();
        let fd = unsafe { fl::nextdown(x) }.to_bits();
        if fu != up {
            div.push(format!(
                "nextup(0x{:016x}): fl=0x{:016x} glibc=0x{:016x}",
                xb, fu, up
            ));
        }
        if fd != dn {
            div.push(format!(
                "nextdown(0x{:016x}): fl=0x{:016x} glibc=0x{:016x}",
                xb, fd, dn
            ));
        }
    }
    for &(xb, up, dn) in NU32 {
        let x = f32::from_bits(xb);
        let fu = unsafe { fl::nextupf(x) }.to_bits();
        let fd = unsafe { fl::nextdownf(x) }.to_bits();
        if fu != up {
            div.push(format!(
                "nextupf(0x{:08x}): fl=0x{:08x} glibc=0x{:08x}",
                xb, fu, up
            ));
        }
        if fd != dn {
            div.push(format!(
                "nextdownf(0x{:08x}): fl=0x{:08x} glibc=0x{:08x}",
                xb, fd, dn
            ));
        }
    }
    for &(xb, ret, out) in CN64 {
        let x = f64::from_bits(xb);
        let mut o = 99.0f64;
        let r = unsafe { fl::canonicalize(&mut o, &x) };
        let ob = o.to_bits();
        if r != ret || ob != out {
            div.push(format!(
                "canonicalize(0x{:016x}): fl=ret{}/0x{:016x} glibc=ret{}/0x{:016x}",
                xb, r, ob, ret, out
            ));
        }
    }
    for &(xb, ret, out) in CN32 {
        let x = f32::from_bits(xb);
        let mut o = 99.0f32;
        let r = unsafe { fl::canonicalizef(&mut o, &x) };
        let ob = o.to_bits();
        if r != ret || ob != out {
            div.push(format!(
                "canonicalizef(0x{:08x}): fl=ret{}/0x{:08x} glibc=ret{}/0x{:08x}",
                xb, r, ob, ret, out
            ));
        }
    }
    for &(xb, ret, out) in CN128 {
        let x = f128::from_bits(xb);
        let mut o = 99.0f128;
        let r = unsafe { fl::canonicalizef128(&mut o, &x) };
        let ob = o.to_bits();
        if r != ret || ob != out {
            div.push(format!(
                "canonicalizef128(0x{:032x}): fl=ret{}/0x{:032x} glibc=ret{}/0x{:032x}",
                xb, r, ob, ret, out
            ));
        }
    }
    assert!(
        div.is_empty(),
        "nextup/canonicalize divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}

/// The same tables, against the glibc that is actually running.
///
/// Two lists again: fl-vs-live is the parity claim in this file's name, and
/// live-vs-golden identifies a host that moved (which would leave the frozen
/// test above green while this one goes red).
#[test]
fn nextup_canonicalize_matches_live_glibc_on_the_same_inputs() {
    let h = host();
    let mut fl_vs_live: Vec<String> = Vec::new();
    let mut host_moved: Vec<String> = Vec::new();
    let mut compared = 0usize;

    for &(xb, up, dn) in NU64 {
        let x = f64::from_bits(xb);
        let (fu, fd) = unsafe { (fl::nextup(x).to_bits(), fl::nextdown(x).to_bits()) };
        // SAFETY: plain f64 in, f64 out.
        let (hu, hd) = unsafe { ((h.nextup)(x).to_bits(), (h.nextdown)(x).to_bits()) };
        compared += 1;
        if (fu, fd) != (hu, hd) {
            fl_vs_live.push(format!(
                "next{{up,down}}(0x{xb:016x}): fl=0x{fu:016x}/0x{fd:016x} live=0x{hu:016x}/0x{hd:016x}"
            ));
        }
        if (hu, hd) != (up, dn) {
            host_moved.push(format!(
                "next{{up,down}}(0x{xb:016x}): live=0x{hu:016x}/0x{hd:016x} golden=0x{up:016x}/0x{dn:016x}"
            ));
        }
    }
    for &(xb, up, dn) in NU32 {
        let x = f32::from_bits(xb);
        let (fu, fd) = unsafe { (fl::nextupf(x).to_bits(), fl::nextdownf(x).to_bits()) };
        // SAFETY: plain f32 in, f32 out.
        let (hu, hd) = unsafe { ((h.nextupf)(x).to_bits(), (h.nextdownf)(x).to_bits()) };
        compared += 1;
        if (fu, fd) != (hu, hd) {
            fl_vs_live.push(format!(
                "next{{up,down}}f(0x{xb:08x}): fl=0x{fu:08x}/0x{fd:08x} live=0x{hu:08x}/0x{hd:08x}"
            ));
        }
        if (hu, hd) != (up, dn) {
            host_moved.push(format!(
                "next{{up,down}}f(0x{xb:08x}): live=0x{hu:08x}/0x{hd:08x} golden=0x{up:08x}/0x{dn:08x}"
            ));
        }
    }
    for &(xb, ret, out) in CN64 {
        let x = f64::from_bits(xb);
        let mut o = 99.0f64;
        let r = unsafe { fl::canonicalize(&mut o, &x) };
        let mut ho = 99.0f64;
        // SAFETY: both operands are live f64s passed by pointer.
        let hr = unsafe { (h.canonicalize)(&mut ho, &x) };
        compared += 1;
        if (r, o.to_bits()) != (hr, ho.to_bits()) {
            fl_vs_live.push(format!(
                "canonicalize(0x{xb:016x}): fl=ret{r}/0x{:016x} live=ret{hr}/0x{:016x}",
                o.to_bits(),
                ho.to_bits()
            ));
        }
        if (hr, ho.to_bits()) != (ret, out) {
            host_moved.push(format!(
                "canonicalize(0x{xb:016x}): live=ret{hr}/0x{:016x} golden=ret{ret}/0x{out:016x}",
                ho.to_bits()
            ));
        }
    }
    for &(xb, ret, out) in CN32 {
        let x = f32::from_bits(xb);
        let mut o = 99.0f32;
        let r = unsafe { fl::canonicalizef(&mut o, &x) };
        let mut ho = 99.0f32;
        // SAFETY: both operands are live f32s passed by pointer.
        let hr = unsafe { (h.canonicalizef)(&mut ho, &x) };
        compared += 1;
        if (r, o.to_bits()) != (hr, ho.to_bits()) {
            fl_vs_live.push(format!(
                "canonicalizef(0x{xb:08x}): fl=ret{r}/0x{:08x} live=ret{hr}/0x{:08x}",
                o.to_bits(),
                ho.to_bits()
            ));
        }
        if (hr, ho.to_bits()) != (ret, out) {
            host_moved.push(format!(
                "canonicalizef(0x{xb:08x}): live=ret{hr}/0x{:08x} golden=ret{ret}/0x{out:08x}",
                ho.to_bits()
            ));
        }
    }
    for &(xb, ret, out) in CN128 {
        let x = f128::from_bits(xb);
        let mut o = 99.0f128;
        let r = unsafe { fl::canonicalizef128(&mut o, &x) };
        let mut ho = 99.0f128;
        // SAFETY: both operands are live f128s passed by pointer.
        let hr = unsafe { (h.canonicalizef128)(&mut ho, &x) };
        compared += 1;
        if (r, o.to_bits()) != (hr, ho.to_bits()) {
            fl_vs_live.push(format!(
                "canonicalizef128(0x{xb:032x}): fl=ret{r}/0x{:032x} live=ret{hr}/0x{:032x}",
                o.to_bits(),
                ho.to_bits()
            ));
        }
        if (hr, ho.to_bits()) != (ret, out) {
            host_moved.push(format!(
                "canonicalizef128(0x{xb:032x}): live=ret{hr}/0x{:032x} golden=ret{ret}/0x{out:032x}",
                ho.to_bits()
            ));
        }
    }

    // A zero divergence count is only evidence if every row was actually run.
    let expected = NU64.len() + NU32.len() + CN64.len() + CN32.len() + CN128.len();
    assert_eq!(compared, expected, "not every row reached the live arm");
    assert!(
        fl_vs_live.is_empty() && host_moved.is_empty(),
        "nextup/canonicalize: {} fl-vs-live divergence(s), {} row(s) where LIVE GLIBC differs \
         from the frozen golden (that second list means the host moved, not fl):\n  {}\n  {}",
        fl_vs_live.len(),
        host_moved.len(),
        fl_vs_live.join("\n  "),
        host_moved.join("\n  ")
    );
}
