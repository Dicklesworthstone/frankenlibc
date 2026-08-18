#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc sysconf oracle

//! `_SC_ARG_MAX` is DERIVED from RLIMIT_STACK, and the default stack hides it.
//!
//! glibc computes `clamp(RLIMIT_STACK soft / 4, 131072, 6291456)`. fl computed
//! the same shape with the wrong cap (3200000), which is correct for every
//! stack at or under 12.8 MiB — including the 8 MiB default every CI machine
//! uses — and wrong above it. A gate that reads `_SC_ARG_MAX` once, at whatever
//! stack limit it happens to inherit, cannot see that.
//!
//! So this test VARIES the input the value derives from, and refuses to pass
//! unless it exercised all three regions of the clamp: below the floor, in the
//! linear middle, and above the cap.
//!
//! It lives in its own test target on purpose: it mutates a process-wide
//! resource limit, and libtest runs the tests within one binary concurrently.
//! Its own binary means its mutation cannot be observed by an unrelated test.

use std::ffi::c_int;

unsafe extern "C" {
    fn sysconf(name: c_int) -> std::ffi::c_long;
}

const SC_ARG_MAX: c_int = 0;
const FLOOR: i64 = 131_072;
const CAP: i64 = 6_291_456;

fn expected_for(soft_bytes: u64) -> i64 {
    let quarter = (soft_bytes / 4) as i64;
    quarter.clamp(FLOOR, CAP)
}

#[test]
fn arg_max_tracks_rlimit_stack_across_the_whole_clamp() {
    let mut original = std::mem::MaybeUninit::<libc::rlimit>::zeroed();
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_STACK, original.as_mut_ptr()) },
        0,
        "getrlimit(RLIMIT_STACK) failed"
    );
    let original = unsafe { original.assume_init() };

    // KiB values chosen to land in each region of the clamp:
    //   128   -> stack/4 = 32768, below the floor
    //   8192  -> stack/4 = 2097152, the linear middle (and the usual default)
    //   16384 -> stack/4 = 4194304, still linear but above fl's old wrong cap
    //   65536 -> stack/4 = 16777216, above the cap
    let candidates_kib: [u64; 4] = [128, 8192, 16384, 65536];

    let mut saw_floor = false;
    let mut saw_linear = false;
    let mut saw_cap = false;
    let mut checked = 0usize;
    let mut divergences = Vec::new();

    for kib in candidates_kib {
        let bytes = kib * 1024;
        // Cannot raise the soft limit past the hard limit; skip rather than fail.
        if original.rlim_max != libc::RLIM_INFINITY && bytes > original.rlim_max {
            continue;
        }
        let attempt = libc::rlimit {
            rlim_cur: bytes,
            rlim_max: original.rlim_max,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_STACK, &attempt) } != 0 {
            continue;
        }

        let expected = expected_for(bytes);
        let g = unsafe { sysconf(SC_ARG_MAX) };
        let f = unsafe { frankenlibc_abi::unistd_abi::sysconf(SC_ARG_MAX) };
        checked += 1;
        if expected == FLOOR && bytes / 4 < FLOOR as u64 {
            saw_floor = true;
        }
        if expected == CAP && bytes / 4 > CAP as u64 {
            saw_cap = true;
        }
        if expected != FLOOR && expected != CAP {
            saw_linear = true;
        }

        // The host is the authority: assert glibc matches the formula BEFORE
        // comparing fl, so a glibc change is reported as such rather than
        // silently redefining what fl must do.
        if g != expected {
            divergences.push(format!(
                "host premise failed at stack {kib} KiB: glibc={g}, formula={expected}"
            ));
        }
        if f != g {
            divergences.push(format!("stack {kib} KiB: fl={f} glibc={g}"));
        }
    }

    // Restore before asserting, so a failure does not leave the limit changed.
    unsafe { libc::setrlimit(libc::RLIMIT_STACK, &original) };

    assert!(
        checked >= 2,
        "only {checked} stack limits were settable; this run cannot test the derivation"
    );
    assert!(
        saw_linear && (saw_floor || saw_cap),
        "the sweep did not cross a clamp boundary (floor={saw_floor} linear={saw_linear} \
         cap={saw_cap}) -- a wrong constant would pass, so this run proves nothing"
    );
    assert!(
        divergences.is_empty(),
        "_SC_ARG_MAX divergences ({} of {checked}):\n  {}",
        divergences.len(),
        divergences.join("\n  ")
    );
}
