#![cfg(target_os = "linux")]
// `c_variadic` is STABLE on the local toolchain (since 1.100.0-nightly) but not
// on the rch build workers, which run an older nightly and reject the variadic
// shim below with E0658. The attribute enables it there; on a newer toolchain it
// is merely a `stable_features` warning, which the allow silences. Do not remove
// either line until the whole fleet has moved past 1.100.
#![allow(stable_features)]
#![feature(c_variadic)]
#![allow(unsafe_code)] // live host-glibc snprintf oracle resolved by dlsym

//! Differential gate for the `%f` / `%.Nf` snprintf fast path (bd-4vwb9q).
//!
//! `snprintf` carries a chain of `exact_direct_*_format` probes that return
//! before `runtime_policy::entrypoint_scope`. Every integer and string
//! conversion had one; the float conversions had none, so they fell through the
//! whole chain and paid the full parse + membrane + segment pipeline. Fitting
//! the published `snprintf_float` medians against precision separates that cost
//! from digit generation:
//!
//!   fl    = 180.94 ns fixed + 4.104 ns/digit
//!   glibc =  93.44 ns fixed + 6.245 ns/digit
//!
//! fl's per-digit cost already beats glibc's, so the 1.56-1.78x loss is entirely
//! the 87.5 ns fixed term. `exact_direct_f_format` removes it.
//!
//! THIS GATE EXISTS TO HOLD THE BYTES. The fast path must be byte-identical to
//! what the general path produced, for every value and every destination size,
//! or it is a correctness regression dressed as a speedup. It compares fl's
//! `snprintf` against host glibc's on BOTH the return value (the length that
//! WOULD have been written) and the full destination buffer including the
//! terminator and the bytes past it.
//!
//! THE ORACLE IS RESOLVED WITH `dlsym`, NOT DECLARED AT LINK TIME. A link-time
//! `extern "C" { fn snprintf(..) }` in an abi test binary is not reliably glibc:
//! `catopen` and `fma` are both confirmed cases where such a reference bound
//! locally in a plain `cargo test`, leaving the gate comparing fl against
//! itself while passing. `catopen`'s hid a live errno divergence for months.
//! See bd-v0388t.

use std::ffi::{CStr, c_char, c_int, c_void};

type Snprintf = unsafe extern "C" fn(*mut c_char, usize, *const c_char, ...) -> c_int;

union Sym {
    raw: *mut c_void,
    function: Snprintf,
}

fn host_snprintf() -> Snprintf {
    // SAFETY: the name is a NUL-terminated constant; RTLD_LOCAL keeps the handle
    // out of the global namespace.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6 — the oracle is unavailable");
    // SAFETY: handle came from dlopen; the name is a NUL-terminated constant.
    let raw = unsafe { libc::dlsym(handle, c"snprintf".as_ptr()) };
    assert!(!raw.is_null(), "dlsym snprintf");
    assert_ne!(
        raw as usize,
        frankenlibc_abi::stdio_abi::snprintf as *const () as usize,
        "the resolved oracle IS fl's snprintf — this gate would compare fl to itself"
    );
    // SAFETY: the resolved symbol has C's documented snprintf signature.
    unsafe { Sym { raw }.function }
}

/// Fill pattern, so a fast path that writes one byte too many is visible.
const FILL: u8 = 0x5A;
const CAP: usize = 384;

fn render_fl(fmt: &CStr, value: f64, size: usize) -> (c_int, [u8; CAP]) {
    let mut buf = [FILL; CAP];
    // SAFETY: `size <= CAP`, so the callee's writable region is in bounds.
    let rc = unsafe {
        frankenlibc_abi::stdio_abi::snprintf(buf.as_mut_ptr().cast::<c_char>(), size, fmt.as_ptr(), value)
    };
    (rc, buf)
}

fn render_host(f: Snprintf, fmt: &CStr, value: f64, size: usize) -> (c_int, [u8; CAP]) {
    let mut buf = [FILL; CAP];
    // SAFETY: as above, for the dlsym'd host entry point.
    let rc = unsafe { f(buf.as_mut_ptr().cast::<c_char>(), size, fmt.as_ptr(), value) };
    (rc, buf)
}

fn formats() -> Vec<(std::ffi::CString, &'static str)> {
    let mut v = vec![(std::ffi::CString::new("%f").unwrap(), "%f")];
    for p in 0..=12 {
        // 0 and >9 are outside the fast path and must still agree — that is the
        // point of including them, since a probe that accepted them would be a
        // silent divergence rather than a missed optimisation.
        v.push((
            std::ffi::CString::new(format!("%.{p}f")).unwrap(),
            Box::leak(format!("%.{p}f").into_boxed_str()),
        ));
    }
    v
}

fn values() -> Vec<f64> {
    let mut v = vec![
        0.0,
        -0.0,
        1.0,
        -1.0,
        0.5,
        -0.5,
        0.25,
        0.125,
        // The money case the fast path exists for: not integral, not dyadic.
        1234.56,
        -1234.56,
        0.1,
        0.2,
        0.3,
        2.675,   // classic round-half-to-even trap: exact value is below the tie
        1.005,   // ditto
        8.835,   // ditto
        0.5e-3,
        99.995,
        1e15,
        1e16,
        1e17,
        1e18,
        1e19,
        1e20,
        1e300,
        f64::MAX,
        f64::MIN_POSITIVE,
        f64::from_bits(1), // smallest subnormal
        -f64::from_bits(1),
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        -f64::NAN,
    ];
    // Deterministic bit-pattern sweep: exercises exponents the curated list misses.
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    for _ in 0..600 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let x = f64::from_bits(state);
        if x.is_finite() {
            v.push(x);
        }
        // Also a tame magnitude, where the fast path is actually taken.
        v.push(((state >> 11) as f64) / 1024.0);
    }
    v
}

#[test]
fn snprintf_fixed_matches_glibc_bytes_and_return_value() {
    let host = host_snprintf();
    let mut compared = 0usize;
    for (fmt, label) in formats() {
        for &value in &values() {
            // Sizes bracket truncation: 0 writes nothing, 1 writes only the NUL.
            for &size in &[0usize, 1, 2, 5, 8, 12, 24, 64, CAP] {
                let (frc, fbuf) = render_fl(&fmt, value, size);
                let (grc, gbuf) = render_host(host, &fmt, value, size);
                assert_eq!(
                    frc, grc,
                    "{label} of {value:?} [{:#018x}] size {size}: return fl={frc} glibc={grc}",
                    value.to_bits()
                );
                assert_eq!(
                    fbuf, gbuf,
                    "{label} of {value:?} [{:#018x}] size {size}: destination bytes differ\n \
                     fl   ={:?}\n glibc={:?}",
                    value.to_bits(),
                    &fbuf[..size.min(48)],
                    &gbuf[..size.min(48)]
                );
                compared += 1;
            }
        }
    }
    // A zero only counts if the runner did work: assert the positive fact.
    assert!(
        compared > 100_000,
        "only {compared} comparisons ran — the grid collapsed"
    );
    println!("compared {compared} (format, value, size) triples against host glibc");
}

/// The probe must DECLINE anything it cannot render identically. These formats
/// carry a width, a flag, a length modifier or a different conversion, so they
/// have to keep taking the general path — and still match glibc.
#[test]
fn adjacent_float_formats_still_match_glibc() {
    let host = host_snprintf();
    let specs = [
        "%10.2f", "%-10.2f", "%+.2f", "% .2f", "%010.2f", "%#.2f", "%.10f", "%.15f", "%.0f",
        "%e", "%.2e", "%g", "%.2g", "%a", "%.2a", "%E", "%G", "%Lf",
    ];
    for spec in specs {
        let fmt = std::ffi::CString::new(spec).unwrap();
        for &value in &[0.0f64, -0.0, 1234.56, -1234.56, 0.1, 1e19, f64::INFINITY, f64::NAN] {
            if spec == "%Lf" {
                continue; // long double: different argument width, not this lane
            }
            for &size in &[0usize, 1, 8, 64, CAP] {
                let (frc, fbuf) = render_fl(&fmt, value, size);
                let (grc, gbuf) = render_host(host, &fmt, value, size);
                assert_eq!(frc, grc, "{spec} of {value:?} size {size}: return value");
                assert_eq!(fbuf, gbuf, "{spec} of {value:?} size {size}: destination bytes");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// bd-5pfs0p: the same probe on sprintf and vsnprintf.
//
// vsnprintf is the one that can go wrong in a way snprintf cannot. On x86-64 a
// `double` variadic argument is passed in an SSE register and recorded in the
// FP half of the register save area, indexed by `fp_offset` (@4) in 16-byte
// slots; `gp_offset` (@0) is NOT advanced by it. Every pre-existing vsnprintf
// probe reads through `va_read_one_gp`, which for a float argument returns an
// unrelated integer -- silently, with a plausible-looking result. The arm below
// exists specifically to catch that substitution.
//
// It was deferred once for lack of a way to build a real va_list from Rust.
// `c_variadic` is stable as of 1.100.0-nightly, so `variadic_shim` below forges
// one the way a C caller would, and the deferral no longer applies.

#[test]
fn sprintf_fixed_matches_glibc() {
    let host = host_snprintf();
    // sprintf's destination is unbounded, so compare against snprintf with a
    // size large enough that no truncation occurs -- same bytes, same return.
    for (fmt, label) in formats() {
        for &value in &values() {
            let mut fbuf = [FILL; CAP];
            // SAFETY: CAP exceeds the longest %.Nf rendering for N <= 12.
            let frc = unsafe {
                frankenlibc_abi::stdio_abi::sprintf(
                    fbuf.as_mut_ptr().cast::<c_char>(),
                    fmt.as_ptr(),
                    value,
                )
            };
            let (grc, gbuf) = render_host(host, &fmt, value, CAP);
            assert_eq!(
                frc, grc,
                "sprintf {label} of {value:?} [{:#018x}]: return fl={frc} glibc={grc}",
                value.to_bits()
            );
            let n = grc.max(0) as usize;
            assert_eq!(
                &fbuf[..=n], &gbuf[..=n],
                "sprintf {label} of {value:?} [{:#018x}]: bytes differ",
                value.to_bits()
            );
        }
    }
}


/// Forge a real va_list the way a C caller would, and hand it to fl's
/// `vsnprintf`. `c_variadic` is stable, so this needs no feature gate.
///
/// Verified against glibc's own `vsnprintf` before being trusted here: the same
/// shim shape returns `"1234.56"` for `("%.2f", 1234.56)` and `"7-2.500"` for
/// `("%d-%.3f", 7, 2.5)`, i.e. it handles a lone double and a mixed
/// integer-then-double frame, which is the case that separates the FP and GP
/// register save areas.
unsafe extern "C" fn fl_vsnprintf_shim(
    buf: *mut c_char,
    n: usize,
    fmt: *const c_char,
    mut ap: ...
) -> c_int {
    // SAFETY: the caller passes exactly the arguments `fmt` names.
    unsafe {
        frankenlibc_abi::stdio_abi::vsnprintf(buf, n, fmt, &mut ap as *mut _ as *mut c_void)
    }
}

#[test]
fn vsnprintf_fixed_reads_the_fp_register_save_area() {
    let host = host_snprintf();
    let mut compared = 0usize;
    for (fmt, label) in formats() {
        for &value in &values() {
            for &size in &[0usize, 1, 8, 24, CAP] {
                let mut fbuf = [FILL; CAP];
                // SAFETY: exactly one f64 is passed, matching `fmt`.
                let frc = unsafe {
                    fl_vsnprintf_shim(fbuf.as_mut_ptr().cast::<c_char>(), size, fmt.as_ptr(), value)
                };
                let (grc, gbuf) = render_host(host, &fmt, value, size);
                assert_eq!(
                    frc, grc,
                    "vsnprintf {label} of {value:?} [{:#018x}] size {size}: return fl={frc} \
                     glibc={grc} — a wrong value here usually means the double was read from the \
                     GP register save area instead of the FP one",
                    value.to_bits()
                );
                assert_eq!(
                    fbuf, gbuf,
                    "vsnprintf {label} of {value:?} [{:#018x}] size {size}: destination bytes differ",
                    value.to_bits()
                );
                compared += 1;
            }
        }
    }
    assert!(compared > 50_000, "only {compared} vsnprintf comparisons ran");
    println!("vsnprintf: compared {compared} triples against host glibc");
}
