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
//!
//! ## Live arm added 2026-08-16 (bd-v0388t)
//!
//! Captured, then frozen: the test was named `scaling_range_matches_glibc` and
//! never called glibc. The risk is concentrated in the half of each row that is
//! an ERRNO, which is precisely the shape that hid the `catopen` defect this
//! audit found — both arms return the same value and only the errno differs, so
//! nothing looks wrong until a caller branches on it.
//!
//! The goldens are KEPT and every row now also runs through dlsym-resolved
//! `scalbn`/`scalbln`/`ldexp` (+f32), reading GLIBC's errno slot rather than
//! fl's. The two implementations keep separate errno storage, so using fl's
//! location for the host arm would have compared fl against itself in exactly
//! the field under test.

use frankenlibc_abi::{errno_abi, math_abi as fa};
use std::os::raw::{c_int, c_long};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

const ERANGE: i32 = 34;

fn clr() {
    unsafe { errno_abi::set_abi_errno(0) };
}
fn erange() -> bool {
    unsafe { *errno_abi::__errno_location() == ERANGE }
}

type Scalbn64 = unsafe extern "C" fn(f64, c_int) -> f64;
type Scalbln64 = unsafe extern "C" fn(f64, c_long) -> f64;
type Scalbn32 = unsafe extern "C" fn(f32, c_int) -> f32;
type Scalbln32 = unsafe extern "C" fn(f32, c_long) -> f32;
type ErrnoLocationFn = unsafe extern "C" fn() -> *mut c_int;

struct HostArm {
    scalbn: Scalbn64,
    scalbln: Scalbln64,
    ldexp: Scalbn64,
    scalbnf: Scalbn32,
    scalblnf: Scalbln32,
    errno_location: ErrnoLocationFn,
}

fn host() -> HostArm {
    // SAFETY: every signature below matches the C declaration in <math.h>, and
    // __errno_location's in <errno.h>.
    unsafe {
        HostArm {
            scalbn: dlsym_oracle::host_fn(c"scalbn", fa::scalbn as *const ()),
            scalbln: dlsym_oracle::host_fn(c"scalbln", fa::scalbln as *const ()),
            ldexp: dlsym_oracle::host_fn(c"ldexp", fa::ldexp as *const ()),
            scalbnf: dlsym_oracle::host_fn(c"scalbnf", fa::scalbnf as *const ()),
            scalblnf: dlsym_oracle::host_fn(c"scalblnf", fa::scalblnf as *const ()),
            errno_location: dlsym_oracle::host_fn(
                c"__errno_location",
                errno_abi::__errno_location as *const (),
            ),
        }
    }
}

impl HostArm {
    fn clear_errno(&self) {
        // SAFETY: the resolved location is glibc's per-thread errno slot.
        unsafe { *(self.errno_location)() = 0 };
    }
    fn erange(&self) -> bool {
        // SAFETY: as above.
        unsafe { *(self.errno_location)() == ERANGE }
    }
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
    chk64!(
        "scalbln(1,-2^31-1)",
        0u64,
        true,
        fa::scalbln(1.0, -2147483649)
    );
    chk64!("scalbln(0,LMAX)", 0u64, false, fa::scalbln(0.0, i64::MAX)); // 0 stays 0, no err
    chk64!(
        "scalbln(inf,LMIN)",
        inf,
        false,
        fa::scalbln(f64::INFINITY, i64::MIN) // inf stays inf, no err
    );
    chk32!("scalblnf(1,LMAX)", inff, true, fa::scalblnf(1.0, i64::MAX));
    chk32!(
        "scalblnf(1,2^31)",
        inff,
        true,
        fa::scalblnf(1.0, 2147483648)
    );
    chk32!("scalblnf(1,LMIN)", 0u32, true, fa::scalblnf(1.0, i64::MIN));

    // --- (2) underflow ERANGE only on result==0, never on subnormal ---
    // 2^-1050: exact subnormal, no ERANGE. (bits = 1<<(1074-1050) = 1<<24)
    chk64!("scalbn(1,-1050)", 1u64 << 24, false, fa::scalbn(1.0, -1050));
    // 2^-1074: smallest subnormal, exact, no ERANGE.
    chk64!("scalbn(1,-1074)", 1u64, false, fa::scalbn(1.0, -1074));
    // 2^-1075: underflows to 0 -> ERANGE.
    chk64!("scalbn(1,-1075)", 0u64, true, fa::scalbn(1.0, -1075));
    // 1.5*2^-1074: INEXACT subnormal (rounds to 2^-1073), still NO ERANGE.
    chk64!("scalbn(1.5,-1074)", 2u64, false, fa::scalbn(1.5, -1074));
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
    chk64!("ldexp(1,-1074)", 1u64, false, fa::ldexp(1.0, -1074));

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

/// The same rows, value AND errno, against the glibc that is actually running.
#[test]
fn scaling_range_matches_live_glibc_on_the_same_rows() {
    let h = host();
    let mut fl_vs_live: Vec<String> = Vec::new();
    let mut compared = 0usize;

    macro_rules! both64 {
        ($lbl:literal, $fl:expr, $host:expr) => {{
            clr();
            let fr: f64 = unsafe { $fl };
            let fe = erange();
            h.clear_errno();
            // SAFETY: the host arm's signature was checked at resolution.
            let hr: f64 = unsafe { $host };
            let he = h.erange();
            compared += 1;
            if (fr.to_bits(), fe) != (hr.to_bits(), he) {
                fl_vs_live.push(format!(
                    "{}: fl bits={:016x}/erange={} live bits={:016x}/erange={}",
                    $lbl,
                    fr.to_bits(),
                    fe,
                    hr.to_bits(),
                    he
                ));
            }
        }};
    }
    macro_rules! both32 {
        ($lbl:literal, $fl:expr, $host:expr) => {{
            clr();
            let fr: f32 = unsafe { $fl };
            let fe = erange();
            h.clear_errno();
            // SAFETY: the host arm's signature was checked at resolution.
            let hr: f32 = unsafe { $host };
            let he = h.erange();
            compared += 1;
            if (fr.to_bits(), fe) != (hr.to_bits(), he) {
                fl_vs_live.push(format!(
                    "{}: fl bits={:08x}/erange={} live bits={:08x}/erange={}",
                    $lbl,
                    fr.to_bits(),
                    fe,
                    hr.to_bits(),
                    he
                ));
            }
        }};
    }

    // (1) the i64 exponent clamp. glibc's scalbln takes a C `long`, so these
    // rows pass the same bit pattern to both arms and the clamp is compared
    // rather than assumed.
    both64!("scalbln(1,LMAX)", fa::scalbln(1.0, i64::MAX), (h.scalbln)(1.0, c_long::MAX));
    both64!("scalbln(1,LMIN)", fa::scalbln(1.0, i64::MIN), (h.scalbln)(1.0, c_long::MIN));
    both64!("scalbln(1,2^31)", fa::scalbln(1.0, 2147483648), (h.scalbln)(1.0, 2147483648));
    both64!(
        "scalbln(1,-2^31-1)",
        fa::scalbln(1.0, -2147483649),
        (h.scalbln)(1.0, -2147483649)
    );
    both64!("scalbln(0,LMAX)", fa::scalbln(0.0, i64::MAX), (h.scalbln)(0.0, c_long::MAX));
    both64!(
        "scalbln(inf,LMIN)",
        fa::scalbln(f64::INFINITY, i64::MIN),
        (h.scalbln)(f64::INFINITY, c_long::MIN)
    );
    both32!("scalblnf(1,LMAX)", fa::scalblnf(1.0, i64::MAX), (h.scalblnf)(1.0, c_long::MAX));
    both32!(
        "scalblnf(1,2^31)",
        fa::scalblnf(1.0, 2147483648),
        (h.scalblnf)(1.0, 2147483648)
    );
    both32!("scalblnf(1,LMIN)", fa::scalblnf(1.0, i64::MIN), (h.scalblnf)(1.0, c_long::MIN));

    // (2) ERANGE on underflow only when the result is exactly 0.
    both64!("scalbn(1,-1050)", fa::scalbn(1.0, -1050), (h.scalbn)(1.0, -1050));
    both64!("scalbn(1,-1074)", fa::scalbn(1.0, -1074), (h.scalbn)(1.0, -1074));
    both64!("scalbn(1,-1075)", fa::scalbn(1.0, -1075), (h.scalbn)(1.0, -1075));
    both64!("scalbn(1.5,-1074)", fa::scalbn(1.5, -1074), (h.scalbn)(1.5, -1074));
    both64!("scalbn(1,-1022)", fa::scalbn(1.0, -1022), (h.scalbn)(1.0, -1022));
    both64!("scalbn(1,1024)", fa::scalbn(1.0, 1024), (h.scalbn)(1.0, 1024));
    both64!("ldexp(1,-1075)", fa::ldexp(1.0, -1075), (h.ldexp)(1.0, -1075));
    both64!("ldexp(1,-1074)", fa::ldexp(1.0, -1074), (h.ldexp)(1.0, -1074));
    both32!("scalbnf(1,-149)", fa::scalbnf(1.0, -149), (h.scalbnf)(1.0, -149));
    both32!("scalbnf(1,-150)", fa::scalbnf(1.0, -150), (h.scalbnf)(1.0, -150));
    both32!("scalbnf(1,128)", fa::scalbnf(1.0, 128), (h.scalbnf)(1.0, 128));

    // The golden test above covers 20 rows; a live run that silently covered
    // fewer would be the same "green while testing nothing" this gate exists to
    // rule out.
    assert_eq!(compared, 20, "not every row reached the live arm");
    assert!(
        fl_vs_live.is_empty(),
        "scaling range: {} row(s) where fl and the running glibc disagree on value or ERANGE:\n  {}",
        fl_vs_live.len(),
        fl_vs_live.join("\n  ")
    );
}
