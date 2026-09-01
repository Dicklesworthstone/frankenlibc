#![cfg(target_os = "linux")]

//! Differential gate for `adjtime(3)`, plus the arithmetic underneath it
//! (bd-xh08pf).
//!
//! ## Why this file is shaped the way it is
//!
//! `adjtime` has two halves and only one of them can be driven from a test.
//!
//! * The READING half — `adjtime(NULL, &olddelta)` — asks the kernel for the
//!   remaining single-shot offset and converts it to a `struct timeval`. That is
//!   read-only and safe to run anywhere, so it is compared against live glibc
//!   directly.
//! * The SETTING half — `adjtime(&delta, ..)` — converts the caller's timeval to
//!   microseconds and then asks the kernel to SLEW THE SYSTEM CLOCK. These tests
//!   run on shared rch build workers. Nothing here calls it with a delta the
//!   conversion accepts.
//!
//! That leaves one setting-side behaviour that is both reachable and harmless:
//! a delta too large to express in microseconds is rejected with `EINVAL`
//! *before* any clock syscall. Both implementations do that, so it is gated
//! differentially, and it is the only route by which the setting-side conversion
//! is observable at all through the public entry point.
//!
//! The rest of that conversion — the signed-`tv_usec` case and the negative
//! normalization — is covered through `#[doc(hidden)]` hooks on the pure integer
//! helpers. Those two assertions are the last of the 54 tests bd-xh08pf
//! enumerated; they had lived in an inline `#[cfg(test)]` block inside a
//! `#[cfg(not(test))]` module and had never run.
//!
//! The host arm is resolved with `dlsym`. fl exports `adjtime` under
//! `#[no_mangle]` in release builds, so a link-time declaration in a release
//! test binary would bind to fl and compare fl against itself (bd-v0388t).

use std::ffi::{c_int, c_void};

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::glibc_internal_abi as fl;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type AdjtimeFn = unsafe extern "C" fn(*const c_void, *mut c_void) -> c_int;
type ErrnoLocationFn = unsafe extern "C" fn() -> *mut c_int;

fn host_adjtime() -> AdjtimeFn {
    // SAFETY: the signature matches C's `int adjtime(const struct timeval *,
    // struct timeval *)`; the pointers are opaque here.
    unsafe { dlsym_oracle::host_fn(c"adjtime", fl::adjtime as *const ()) }
}

/// glibc's errno slot, which is NOT fl's — the two keep separate storage, and
/// EINVAL is the entire point of the overflow cases below.
fn host_errno() -> ErrnoLocationFn {
    // SAFETY: signature matches C's `__errno_location`.
    unsafe { dlsym_oracle::host_fn(c"__errno_location", __errno_location as *const ()) }
}

/// A delta whose microsecond count cannot fit in a `long`, so the conversion
/// must refuse it before anything reaches the kernel.
///
/// `tv_sec * 1_000_000` overflows `i64` for anything past roughly 9.2e12
/// seconds; these are far beyond that, and one of them is `i64::MAX` itself.
const UNREPRESENTABLE_SECONDS: &[i64] = &[1 << 62, -(1 << 62), i64::MAX, i64::MIN + 1];

#[derive(PartialEq, Eq, Debug)]
struct AdjtimeOutcome {
    rc: c_int,
    errno: c_int,
}

fn run_overflow_case(
    adjtime: AdjtimeFn,
    errno_location: ErrnoLocationFn,
    tv_sec: i64,
) -> AdjtimeOutcome {
    let delta = libc::timeval {
        tv_sec: tv_sec as _,
        tv_usec: 0,
    };
    let mut old = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    // SAFETY: both pointers address live locals; the call is rejected before any
    // clock syscall, which is the property under test.
    unsafe {
        *errno_location() = 0;
        let rc = adjtime(
            (&raw const delta).cast::<c_void>(),
            (&raw mut old).cast::<c_void>(),
        );
        let errno = *errno_location();
        AdjtimeOutcome {
            rc,
            errno: if rc == 0 { 0 } else { errno },
        }
    }
}

#[test]
fn adjtime_rejects_an_unrepresentable_delta_like_glibc() {
    let host = host_adjtime();
    let host_errno_location = host_errno();
    let mut divergences = Vec::new();

    for &tv_sec in UNREPRESENTABLE_SECONDS {
        let f = run_overflow_case(fl::adjtime, __errno_location, tv_sec);
        let h = run_overflow_case(host, host_errno_location, tv_sec);
        if f != h {
            divergences.push(format!("tv_sec={tv_sec}: fl={f:?} glibc={h:?}"));
        }
        // And state the contract, so a future in which BOTH accepted the delta
        // — and therefore both tried to slew the clock — still fails here.
        assert_eq!(
            h,
            AdjtimeOutcome {
                rc: -1,
                errno: libc::EINVAL
            },
            "glibc no longer rejects tv_sec={tv_sec}; this gate is now asking the \
             kernel to adjust the clock on a shared build worker and must be \
             changed, not re-baselined"
        );
    }
    assert!(
        divergences.is_empty(),
        "adjtime overflow rejection diverges from live glibc:\n  {}",
        divergences.join("\n  ")
    );
}

#[test]
fn adjtime_read_only_query_matches_glibc() {
    let host = host_adjtime();

    let mut fl_old = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut host_old = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    // SAFETY: a NULL delta is the documented read-only form; both output
    // pointers address live locals.
    let (fl_rc, host_rc) = unsafe {
        (
            fl::adjtime(std::ptr::null(), (&raw mut fl_old).cast::<c_void>()),
            host(std::ptr::null(), (&raw mut host_old).cast::<c_void>()),
        )
    };

    assert_eq!(fl_rc, host_rc, "adjtime(NULL, &old) return value");
    // Both arms ask the same kernel for the same value microseconds apart, so
    // they must agree. A pending single-shot offset is normally 0 on an idle
    // machine; the assertion is still worth making, because the two READ it
    // through different code (fl issues ADJ_OFFSET_SS_READ itself).
    assert_eq!(
        (fl_old.tv_sec, fl_old.tv_usec),
        (host_old.tv_sec, host_old.tv_usec),
        "adjtime(NULL, &old) reported different remaining offsets"
    );
    assert!(
        (0..1_000_000).contains(&fl_old.tv_usec),
        "tv_usec must be normalized into [0, 1e6), got {}",
        fl_old.tv_usec
    );
}

// ---------------------------------------------------------------------------
// The pure conversions, via the `#[doc(hidden)]` hooks.
//
// These are the two assertions that stood in the dead `adjtime_abi_tests` block.
// They are NOT differential and cannot be: reaching the same arithmetic in glibc
// requires a delta it accepts, and a delta it accepts is one the kernel acts on.
// ---------------------------------------------------------------------------

#[test]
fn timeval_to_offset_micros_handles_signed_microseconds() {
    // glibc's own `struct timeval` normalization allows a negative `tv_usec`
    // against a positive `tv_sec`; 1s - 250ms is 750 000 µs, not 1 250 000.
    assert_eq!(
        fl::adjtime_timeval_to_offset_micros_for_tests(1, -250_000),
        Some(750_000)
    );
    assert_eq!(
        fl::adjtime_timeval_to_offset_micros_for_tests(0, 0),
        Some(0)
    );
    assert_eq!(
        fl::adjtime_timeval_to_offset_micros_for_tests(-1, 250_000),
        Some(-750_000)
    );
    // The overflow branch the differential test above exercises through the
    // public entry point, asserted here on the conversion itself.
    for &tv_sec in UNREPRESENTABLE_SECONDS {
        assert_eq!(
            fl::adjtime_timeval_to_offset_micros_for_tests(tv_sec, 0),
            None,
            "tv_sec={tv_sec} must not convert"
        );
    }
}

#[test]
fn offset_micros_to_timeval_normalizes_negative_offsets() {
    // Euclidean, not truncating: -1 µs is (-1 s, +999 999 µs), which is what a
    // `struct timeval` consumer expects. Truncating division would give
    // (0, -1) and a reader computing `sec * 1e6 + usec` would still get -1, but
    // `tv_usec` would be out of its documented [0, 1e6) range.
    assert_eq!(
        fl::adjtime_offset_micros_to_timeval_for_tests(-1),
        (-1, 999_999)
    );
    assert_eq!(fl::adjtime_offset_micros_to_timeval_for_tests(0), (0, 0));
    assert_eq!(fl::adjtime_offset_micros_to_timeval_for_tests(1), (0, 1));
    assert_eq!(
        fl::adjtime_offset_micros_to_timeval_for_tests(-1_000_000),
        (-1, 0)
    );
    assert_eq!(
        fl::adjtime_offset_micros_to_timeval_for_tests(-1_000_001),
        (-2, 999_999)
    );
}

/// The two halves must be inverses wherever the value is representable, which is
/// the property neither original test stated and the one a caller depends on:
/// `adjtime(&d, &old)` hands back a `d` it can hand straight back in.
#[test]
fn the_two_conversions_round_trip() {
    for offset in [
        0_i64,
        1,
        -1,
        999_999,
        -999_999,
        1_000_000,
        -1_000_000,
        1_234_567,
        -1_234_567,
        i64::from(i32::MAX),
        -i64::from(i32::MAX),
    ] {
        let (sec, usec) = fl::adjtime_offset_micros_to_timeval_for_tests(offset);
        assert!(
            (0..1_000_000).contains(&usec),
            "offset {offset} produced an unnormalized tv_usec {usec}"
        );
        assert_eq!(
            fl::adjtime_timeval_to_offset_micros_for_tests(sec, usec),
            Some(offset),
            "offset {offset} did not survive the round trip through ({sec}, {usec})"
        );
    }
}
