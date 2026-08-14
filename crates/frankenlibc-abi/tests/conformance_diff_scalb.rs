#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

//! Differential conformance gate for the obsolete SVID `scalb`/`scalbf`/`scalbl`.
//!
//! glibc implements `__ieee754_scalb`: a NON-INTEGER binary exponent yields
//! NaN + FE_INVALID, and an infinite exponent uses the `x*fn` / `x/(-fn)` forms.
//! fl previously computed `x * 2.0.powf(exp)`, which returned a bogus *finite*
//! value for non-integer exponents (`scalb(3, 2.5)` -> 16.97 instead of NaN,
//! `scalb(0, 2.5)` -> 0 instead of NaN) and never raised FE_INVALID. This test
//! compares the exact result bits, FE_INVALID flag, and errno against host glibc.

use frankenlibc_abi::errno_abi;
use frankenlibc_abi::math_abi::{
    __scalb_finite as fl_scalb_finite, __scalbf_finite as fl_scalbf_finite, scalbl as fl_scalbl,
};
use frankenlibc_abi::unistd_abi::{scalb as fl_scalb, scalbf as fl_scalbf};

const FE_INVALID: i32 = 0x01;

unsafe extern "C" {
    fn scalb(x: f64, fn_: f64) -> f64;
    fn scalbf(x: f32, fn_: f32) -> f32;
    fn feclearexcept(e: i32) -> i32;
    fn fetestexcept(e: i32) -> i32;
    #[link_name = "__errno_location"]
    fn host_errno_location() -> *mut i32;
}

type Obs64 = (u64, bool, i32);
type Obs32 = (u32, bool, i32);
type ScalbFinite64Fn = unsafe extern "C" fn(f64, f64) -> f64;
type ScalbFinite32Fn = unsafe extern "C" fn(f32, f32) -> f32;

const LIBM_SO_6: &std::ffi::CStr = c"libm.so.6";
const GLIBC_2_15: &std::ffi::CStr = c"GLIBC_2.15";

fn clear_host_errno() {
    unsafe { *host_errno_location() = 0 };
}

fn read_host_errno() -> i32 {
    unsafe { *host_errno_location() }
}

fn clear_fl_errno() {
    unsafe { errno_abi::set_abi_errno(0) };
}

fn read_fl_errno() -> i32 {
    unsafe { *errno_abi::__errno_location() }
}

/// (result bits, INVALID raised, errno) for a host call.
fn host64(x: f64, e: f64) -> Obs64 {
    unsafe {
        clear_host_errno();
        feclearexcept(FE_INVALID);
        let r = scalb(x, e);
        (
            r.to_bits(),
            fetestexcept(FE_INVALID) != 0,
            read_host_errno(),
        )
    }
}
fn fl64(x: f64, e: f64) -> Obs64 {
    unsafe {
        clear_fl_errno();
        feclearexcept(FE_INVALID);
        let r = fl_scalb(x, e);
        (r.to_bits(), fetestexcept(FE_INVALID) != 0, read_fl_errno())
    }
}
fn host32(x: f32, e: f32) -> Obs32 {
    unsafe {
        clear_host_errno();
        feclearexcept(FE_INVALID);
        let r = scalbf(x, e);
        (
            r.to_bits(),
            fetestexcept(FE_INVALID) != 0,
            read_host_errno(),
        )
    }
}
fn fl32(x: f32, e: f32) -> Obs32 {
    unsafe {
        clear_fl_errno();
        feclearexcept(FE_INVALID);
        let r = fl_scalbf(x, e);
        (r.to_bits(), fetestexcept(FE_INVALID) != 0, read_fl_errno())
    }
}

fn host_scalb_finite_symbols() -> (ScalbFinite64Fn, ScalbFinite32Fn) {
    let handle = unsafe { libc::dlopen(LIBM_SO_6.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libm.so.6 failed");

    let finite64 = unsafe { libc::dlvsym(handle, c"__scalb_finite".as_ptr(), GLIBC_2_15.as_ptr()) };
    let finite32 =
        unsafe { libc::dlvsym(handle, c"__scalbf_finite".as_ptr(), GLIBC_2_15.as_ptr()) };
    assert!(
        !finite64.is_null(),
        "dlvsym __scalb_finite@GLIBC_2.15 failed"
    );
    assert!(
        !finite32.is_null(),
        "dlvsym __scalbf_finite@GLIBC_2.15 failed"
    );

    // SAFETY: dlvsym resolved the documented GLIBC_2.15 scalar signatures.
    // ubs:ignore — the versioned host ABI fixes both raw-pointer signatures.
    unsafe { (std::mem::transmute(finite64), std::mem::transmute(finite32)) }
}

fn host_finite64(function: ScalbFinite64Fn, x: f64, e: f64) -> Obs64 {
    unsafe {
        clear_host_errno();
        feclearexcept(FE_INVALID);
        let r = function(x, e);
        (
            r.to_bits(),
            fetestexcept(FE_INVALID) != 0,
            read_host_errno(),
        )
    }
}

fn fl_finite64(x: f64, e: f64) -> Obs64 {
    unsafe {
        clear_fl_errno();
        feclearexcept(FE_INVALID);
        let r = fl_scalb_finite(x, e);
        (r.to_bits(), fetestexcept(FE_INVALID) != 0, read_fl_errno())
    }
}

fn host_finite32(function: ScalbFinite32Fn, x: f32, e: f32) -> Obs32 {
    unsafe {
        clear_host_errno();
        feclearexcept(FE_INVALID);
        let r = function(x, e);
        (
            r.to_bits(),
            fetestexcept(FE_INVALID) != 0,
            read_host_errno(),
        )
    }
}

fn fl_finite32(x: f32, e: f32) -> Obs32 {
    unsafe {
        clear_fl_errno();
        feclearexcept(FE_INVALID);
        let r = fl_scalbf_finite(x, e);
        (r.to_bits(), fetestexcept(FE_INVALID) != 0, read_fl_errno())
    }
}

fn nan_eq_bits(a: u64, b: u64) -> bool {
    // Both NaN (any payload) counts as equal; otherwise exact bit match.
    if (a & 0x7ff0_0000_0000_0000 == 0x7ff0_0000_0000_0000)
        && (a & 0x000f_ffff_ffff_ffff != 0)
        && (b & 0x7ff0_0000_0000_0000 == 0x7ff0_0000_0000_0000)
        && (b & 0x000f_ffff_ffff_ffff != 0)
    {
        return true;
    }
    a == b
}
fn nan_eq_bits32(a: u32, b: u32) -> bool {
    if (a & 0x7f80_0000 == 0x7f80_0000)
        && (a & 0x007f_ffff != 0)
        && (b & 0x7f80_0000 == 0x7f80_0000)
        && (b & 0x007f_ffff != 0)
    {
        return true;
    }
    a == b
}

#[test]
fn scalb_matches_glibc() {
    let xs = [
        0.0f64,
        -0.0,
        1.0,
        -1.0,
        3.0,
        -5.0,
        1.5,
        7.0,
        2.0,
        1e300,
        1e-300,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        f64::MIN_POSITIVE,
        0.9,
        123.456,
    ];
    let es = [
        0.0f64,
        1.0,
        2.0,
        3.0,
        -2.0,
        -4.0,
        1023.0,
        1024.0,
        -1074.0,
        -1075.0,
        2.5,
        0.5,
        -2.5,
        0.9,
        -0.1,
        70000.0,
        -70000.0,
        65000.0,
        65001.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
    ];

    let mut div: Vec<String> = Vec::new();
    for &x in &xs {
        for &e in &es {
            // f64 / scalb
            let (hb, hi, he) = host64(x, e);
            let (fb, fi, fe) = fl64(x, e);
            if !nan_eq_bits(hb, fb) || hi != fi || he != fe {
                div.push(format!(
                    "scalb({x}, {e}): fl bits={fb:016x} inv={fi} errno={fe}, glibc bits={hb:016x} inv={hi} errno={he}"
                ));
            }
            // long-double scalbl shares the f64 surface in fl; glibc scalb is the oracle.
            unsafe {
                clear_fl_errno();
                feclearexcept(FE_INVALID);
                let r = fl_scalbl(x, e);
                let (lb, li, le) = (r.to_bits(), fetestexcept(FE_INVALID) != 0, read_fl_errno());
                if !nan_eq_bits(hb, lb) || hi != li || he != le {
                    div.push(format!(
                        "scalbl({x}, {e}): fl bits={lb:016x} inv={li} errno={le}, glibc bits={hb:016x} inv={hi} errno={he}"
                    ));
                }
            }
            // f32 / scalbf
            let (xf, ef) = (x as f32, e as f32);
            let (hb32, hi32, he32) = host32(xf, ef);
            let (fb32, fi32, fe32) = fl32(xf, ef);
            if !nan_eq_bits32(hb32, fb32) || hi32 != fi32 || he32 != fe32 {
                div.push(format!(
                    "scalbf({xf}, {ef}): fl bits={fb32:08x} inv={fi32} errno={fe32}, glibc bits={hb32:08x} inv={hi32} errno={he32}"
                ));
            }
        }
    }
    assert!(
        div.is_empty(),
        "scalb/scalbf/scalbl divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}

#[test]
fn scalb_finite_aliases_match_versioned_glibc_without_errno() {
    let (host64, host32) = host_scalb_finite_symbols();
    let xs = [
        0.0f64,
        -0.0,
        1.0,
        -1.0,
        3.0,
        -5.0,
        1.5,
        1e300,
        1e-300,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        f64::MIN_POSITIVE,
    ];
    let es = [
        0.0f64,
        1.0,
        -2.0,
        1024.0,
        -1075.0,
        2.5,
        -2.5,
        70000.0,
        -70000.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
    ];

    let mut div = Vec::new();
    for &x in &xs {
        for &e in &es {
            let (host_bits, host_invalid, host_errno) = host_finite64(host64, x, e);
            let (fl_bits, fl_invalid, fl_errno) = fl_finite64(x, e);
            if !nan_eq_bits(host_bits, fl_bits) || host_invalid != fl_invalid || fl_errno != 0 {
                div.push(format!(
                    "__scalb_finite({x}, {e}): fl bits={fl_bits:016x} inv={fl_invalid} errno={fl_errno}, glibc bits={host_bits:016x} inv={host_invalid} errno={host_errno}"
                ));
            }

            let (xf, ef) = (x as f32, e as f32);
            let (host_bits, host_invalid, host_errno) = host_finite32(host32, xf, ef);
            let (fl_bits, fl_invalid, fl_errno) = fl_finite32(xf, ef);
            if !nan_eq_bits32(host_bits, fl_bits) || host_invalid != fl_invalid || fl_errno != 0 {
                div.push(format!(
                    "__scalbf_finite({xf}, {ef}): fl bits={fl_bits:08x} inv={fl_invalid} errno={fl_errno}, glibc bits={host_bits:08x} inv={host_invalid} errno={host_errno}"
                ));
            }
        }
    }

    assert!(
        div.is_empty(),
        "__scalb_finite/__scalbf_finite divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
