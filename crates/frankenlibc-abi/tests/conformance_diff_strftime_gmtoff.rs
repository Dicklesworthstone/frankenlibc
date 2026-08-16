#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strftime oracle

//! `strftime` `%z` (UTC offset) parity vs host glibc (bd-2g7oyh.NEW).
//!
//! glibc formats `%z` as ±HHMM from the broken-down time's `tm_gmtoff` field,
//! regardless of how it was set (localtime, `strptime %z`, or by hand). fl
//! previously hardcoded "+0000". This gate fills `tm_gmtoff` with a range of
//! offsets and compares the rendered `%z` (alone and embedded) against the live
//! host.
//!
//! Out of scope (documented divergence): `%Z` (timezone name) reads the opaque
//! `tm_zone` pointer and, when null, falls back to the process timezone — both
//! beyond fl's UTC-only, never-dereference-tm_zone model.

use frankenlibc_abi::time_abi as fl;
use std::ffi::{CString, c_char};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

/// The host arms are resolved with `dlsym`, not declared at link time. fl exports
/// all three of these symbols into this test binary, so link-time references can
/// bind to fl and leave BOTH arms as fl -- green while comparing nothing, which is
/// exactly how the `%z` defect this gate pins would have been able to regress
/// unnoticed (bd-v0388t).
///
/// `gmtime_r` and `setlocale` are resolved through the host too, even though they
/// are setup rather than the comparison. The broken-down time they produce is the
/// SHARED INPUT to both arms, so taking it from fl would make the gate's premise
/// depend on the implementation under test: a bug in fl's `gmtime_r` would hand
/// both arms the same malformed `tm` and the `%z` comparison would agree on
/// nonsense.
type StrftimeFn = unsafe extern "C" fn(*mut c_char, usize, *const c_char, *const libc::tm) -> usize;
type GmtimeRFn = unsafe extern "C" fn(*const i64, *mut libc::tm) -> *mut libc::tm;
type SetlocaleFn = unsafe extern "C" fn(i32, *const c_char) -> *mut c_char;

fn host_strftime() -> StrftimeFn {
    // SAFETY: the signature matches C's strftime exactly.
    unsafe {
        dlsym_oracle::host_fn(
            c"strftime",
            frankenlibc_abi::time_abi::strftime as *const (),
        )
    }
}

fn host_gmtime_r() -> GmtimeRFn {
    // SAFETY: the signature matches POSIX's gmtime_r exactly.
    unsafe {
        dlsym_oracle::host_fn(
            c"gmtime_r",
            frankenlibc_abi::time_abi::gmtime_r as *const (),
        )
    }
}

fn host_setlocale() -> SetlocaleFn {
    // SAFETY: the signature matches C's setlocale exactly.
    unsafe {
        dlsym_oracle::host_fn(
            c"setlocale",
            frankenlibc_abi::locale_abi::setlocale as *const (),
        )
    }
}

fn render(eng: u8, fmt: &str, tm: &libc::tm) -> String {
    let cf = CString::new(fmt).unwrap();
    let mut buf = vec![0i8; 96];
    let n = if eng == 0 {
        unsafe { fl::strftime(buf.as_mut_ptr(), 96, cf.as_ptr(), tm) }
    } else {
        unsafe { host_strftime()(buf.as_mut_ptr(), 96, cf.as_ptr(), tm) }
    };
    String::from_utf8_lossy(&buf[..n].iter().map(|&b| b as u8).collect::<Vec<_>>()).into_owned()
}

#[test]
fn strftime_gmtoff_z_matches_glibc() {
    let loc = CString::new("C").unwrap();
    unsafe { host_setlocale()(6, loc.as_ptr()) };

    let t = 1_718_450_000i64;
    let mut base: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { host_gmtime_r()(&t, &mut base) };

    // Whole-hour, half-hour, quarter-hour, negative, and sub-minute offsets.
    let offsets: [i64; 11] = [
        0, 3600, -3600, 19800, -28800, -1800, 34200, 50400, -43200, 900, -45900,
    ];
    for off in offsets {
        let mut tm = base;
        tm.tm_gmtoff = off;
        tm.tm_zone = std::ptr::null(); // %z is independent of the name
        for fmt in ["%z", "%H:%M:%S %z", "[%z]"] {
            let a = render(0, fmt, &tm);
            let b = render(1, fmt, &tm);
            assert_eq!(a, b, "strftime({fmt:?}) gmtoff={off}: fl={a:?} glibc={b:?}");
        }
    }
}
