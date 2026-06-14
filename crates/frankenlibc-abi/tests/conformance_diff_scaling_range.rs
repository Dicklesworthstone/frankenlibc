#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

//! Conformance gate for the exact range-error contract of the binary-scaling
//! family (scalbn / scalbln / ldexp + f32) against host glibc.
//!
//! The existing math-errno gate only checks n = ±100000 (well inside i32), which
//! leaves two subtle, regression-prone invariants unpinned:
//!
//!   1. The i64 exponent of scalbln/scalblnf is CLAMPED to the i32 range before
//!      the libm ldexp call. A naive `n as i32` would overflow-wrap, silently
//!      turning scalbln(1, 2^31) (glibc: +inf) into 0. This gate pins the clamp.
//!
//!   2. glibc sets ERANGE on underflow ONLY when the result is exactly 0 — NOT
//!      for a subnormal result, even an inexact one (scalbn(1.5, -1074) loses a
//!      bit but still raises no ERANGE). fl's `scaling_range_error` must match:
//!      ERANGE iff result is ±inf or 0 (and the input was finite & nonzero).
//!
//! Golden values captured from this host's glibc via a gcc -lm oracle.

use frankenlibc_abi::{errno_abi, math_abi as fa};

const ERANGE: i32 = 34;

fn clr() {
    unsafe { errno_abi::set_abi_errno(0) };
}
fn erange() -> bool {
    unsafe { *errno_abi::__errno_location() == ERANGE }
}

#[test]
fn scaling_range_matches_glibc() {
    let mut div: Vec<String> = Vec::new();
    let inf = f64::INFINITY.to_bits();
    let inff = f32::INFINITY.to_bits();

    macro_rules! chk64 {
        ($lbl:literal, $want_bits:expr, $want_er:expr, $call:expr) => {{
            clr();
            let r: f64 = unsafe { $call };
            let (gb, ge) = (r.to_bits(), erange());
            if gb != $want_bits || ge != $want_er {
                div.push(format!(
                    "{}: bits={:016x}/er={} want bits={:016x}/er={}",
                    $lbl, gb, ge, $want_bits, $want_er
                ));
            }
        }};
    }
    macro_rules! chk32 {
        ($lbl:literal, $want_bits:expr, $want_er:expr, $call:expr) => {{
            clr();
            let r: f32 = unsafe { $call };
            let (gb, ge) = (r.to_bits(), erange());
            if gb != $want_bits || ge != $want_er {
                div.push(format!(
                    "{}: bits={:08x}/er={} want bits={:08x}/er={}",
                    $lbl, gb, ge, $want_bits, $want_er
                ));
            }
        }};
    }

    // --- (1) i64 exponent clamp: n beyond ±2^31 must NOT overflow-wrap ---
    chk64!("scalbln(1,LMAX)", inf, true, fa::scalbln(1.0, i64::MAX));
    chk64!("scalbln(1,LMIN)", 0u64, true, fa::scalbln(1.0, i64::MIN));
    chk64!("scalbln(1,2^31)", inf, true, fa::scalbln(1.0, 2147483648));
    chk64!("scalbln(1,-2^31-1)", 0u64, true, fa::scalbln(1.0, -2147483649));
    chk64!("scalbln(0,LMAX)", 0u64, false, fa::scalbln(0.0, i64::MAX)); // 0 stays 0, no err
    chk64!(
        "scalbln(inf,LMIN)",
        inf,
        false,
        fa::scalbln(f64::INFINITY, i64::MIN) // inf stays inf, no err
    );
    chk32!("scalblnf(1,LMAX)", inff, true, fa::scalblnf(1.0, i64::MAX));
    chk32!("scalblnf(1,2^31)", inff, true, fa::scalblnf(1.0, 2147483648));
    chk32!("scalblnf(1,LMIN)", 0u32, true, fa::scalblnf(1.0, i64::MIN));

    // --- (2) underflow ERANGE only on result==0, never on subnormal ---
    // 2^-1050: exact subnormal, no ERANGE. (bits = 1<<(1074-1050) = 1<<24)
    chk64!("scalbn(1,-1050)", 1u64 << 24, false, fa::scalbn(1.0, -1050));
    // 2^-1074: smallest subnormal, exact, no ERANGE.
    chk64!("scalbn(1,-1074)", 1u64, false, fa::scalbn(1.0, -1074));
    // 2^-1075: underflows to 0 -> ERANGE.
    chk64!("scalbn(1,-1075)", 0u64, true, fa::scalbn(1.0, -1075));
    // 1.5*2^-1074: INEXACT subnormal (rounds to 2^-1073), still NO ERANGE.
    chk64!(
        "scalbn(1.5,-1074)",
        2u64,
        false,
        fa::scalbn(1.5, -1074)
    );
    // smallest normal, exact, no ERANGE.
    chk64!(
        "scalbn(1,-1022)",
        f64::MIN_POSITIVE.to_bits(),
        false,
        fa::scalbn(1.0, -1022)
    );
    // overflow to inf -> ERANGE.
    chk64!("scalbn(1,1024)", inf, true, fa::scalbn(1.0, 1024));
    // ldexp shares the path.
    chk64!("ldexp(1,-1075)", 0u64, true, fa::ldexp(1.0, -1075));
    chk64!(
        "ldexp(1,-1074)",
        1u64,
        false,
        fa::ldexp(1.0, -1074)
    );

    // f32 subnormal boundary: 2^-149 smallest subnormal, exact, no ERANGE; 2^-150 -> 0.
    chk32!("scalbnf(1,-149)", 1u32, false, fa::scalbnf(1.0, -149));
    chk32!("scalbnf(1,-150)", 0u32, true, fa::scalbnf(1.0, -150));
    chk32!("scalbnf(1,128)", inff, true, fa::scalbnf(1.0, 128));

    assert!(
        div.is_empty(),
        "scaling range-error divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
