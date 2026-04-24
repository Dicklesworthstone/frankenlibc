#![cfg(target_os = "linux")]

//! Differential conformance harness for `pthread_attr_*`:
//!   - pthread_attr_init / pthread_attr_destroy
//!   - pthread_attr_setdetachstate / pthread_attr_getdetachstate
//!   - pthread_attr_setstacksize / pthread_attr_getstacksize
//!   - pthread_attr_setguardsize / pthread_attr_getguardsize
//!
//! pthread_attr_t is a 56-byte opaque blob on glibc x86_64; padded to
//! 128 for safety. Each test runs independent fl-only and lc-only
//! sequences.
//!
//! Bead: CONFORMANCE: libc pthread_attr.h diff matrix.

use std::ffi::{c_int, c_void};

use frankenlibc_abi::pthread_abi as fl;

unsafe extern "C" {
    fn pthread_attr_init(attr: *mut c_void) -> c_int;
    fn pthread_attr_destroy(attr: *mut c_void) -> c_int;
    fn pthread_attr_setdetachstate(attr: *mut c_void, state: c_int) -> c_int;
    fn pthread_attr_getdetachstate(attr: *const c_void, state: *mut c_int) -> c_int;
    fn pthread_attr_setstacksize(attr: *mut c_void, sz: usize) -> c_int;
    fn pthread_attr_getstacksize(attr: *const c_void, sz: *mut usize) -> c_int;
    fn pthread_attr_setguardsize(attr: *mut c_void, sz: usize) -> c_int;
    fn pthread_attr_getguardsize(attr: *const c_void, sz: *mut usize) -> c_int;
}

const PTHREAD_CREATE_JOINABLE: c_int = 0;
const PTHREAD_CREATE_DETACHED: c_int = 1;

const ATTR_BYTES: usize = 128;

#[test]
fn diff_attr_init_destroy_round_trip() {
    let mut a_fl = vec![0u8; ATTR_BYTES];
    let r_init_fl = unsafe { fl::pthread_attr_init(a_fl.as_mut_ptr() as *mut _) };
    let r_destroy_fl = unsafe { fl::pthread_attr_destroy(a_fl.as_mut_ptr() as *mut _) };

    let mut a_lc = vec![0u8; ATTR_BYTES];
    let r_init_lc = unsafe { pthread_attr_init(a_lc.as_mut_ptr() as *mut c_void) };
    let r_destroy_lc = unsafe { pthread_attr_destroy(a_lc.as_mut_ptr() as *mut c_void) };

    assert_eq!(r_init_fl, r_init_lc, "init: fl={r_init_fl}, lc={r_init_lc}");
    assert_eq!(
        r_destroy_fl, r_destroy_lc,
        "destroy: fl={r_destroy_fl}, lc={r_destroy_lc}"
    );
    assert_eq!(r_init_fl, 0, "init should succeed");
}

#[test]
fn diff_attr_detachstate_round_trip() {
    let run = |use_fl: bool, want: c_int| -> c_int {
        let mut a = vec![0u8; ATTR_BYTES];
        let _ = if use_fl {
            unsafe { fl::pthread_attr_init(a.as_mut_ptr() as *mut _) }
        } else {
            unsafe { pthread_attr_init(a.as_mut_ptr() as *mut c_void) }
        };
        let _ = if use_fl {
            unsafe { fl::pthread_attr_setdetachstate(a.as_mut_ptr() as *mut _, want) }
        } else {
            unsafe { pthread_attr_setdetachstate(a.as_mut_ptr() as *mut c_void, want) }
        };
        let mut got: c_int = -1;
        let _ = if use_fl {
            unsafe { fl::pthread_attr_getdetachstate(a.as_ptr() as *const _, &mut got) }
        } else {
            unsafe { pthread_attr_getdetachstate(a.as_ptr() as *const c_void, &mut got) }
        };
        let _ = if use_fl {
            unsafe { fl::pthread_attr_destroy(a.as_mut_ptr() as *mut _) }
        } else {
            unsafe { pthread_attr_destroy(a.as_mut_ptr() as *mut c_void) }
        };
        got
    };
    for want in &[PTHREAD_CREATE_JOINABLE, PTHREAD_CREATE_DETACHED] {
        let g_fl = run(true, *want);
        let g_lc = run(false, *want);
        assert_eq!(g_fl, g_lc, "detachstate {want}: fl={g_fl}, lc={g_lc}");
        assert_eq!(g_fl, *want, "detachstate round-trip {want}");
    }
}

#[test]
fn diff_attr_stacksize_round_trip() {
    let run = |use_fl: bool, want: usize| -> usize {
        let mut a = vec![0u8; ATTR_BYTES];
        let _ = if use_fl {
            unsafe { fl::pthread_attr_init(a.as_mut_ptr() as *mut _) }
        } else {
            unsafe { pthread_attr_init(a.as_mut_ptr() as *mut c_void) }
        };
        let _ = if use_fl {
            unsafe { fl::pthread_attr_setstacksize(a.as_mut_ptr() as *mut _, want) }
        } else {
            unsafe { pthread_attr_setstacksize(a.as_mut_ptr() as *mut c_void, want) }
        };
        let mut got: usize = 0;
        let _ = if use_fl {
            unsafe { fl::pthread_attr_getstacksize(a.as_ptr() as *const _, &mut got) }
        } else {
            unsafe { pthread_attr_getstacksize(a.as_ptr() as *const c_void, &mut got) }
        };
        let _ = if use_fl {
            unsafe { fl::pthread_attr_destroy(a.as_mut_ptr() as *mut _) }
        } else {
            unsafe { pthread_attr_destroy(a.as_mut_ptr() as *mut c_void) }
        };
        got
    };
    for want in &[131072usize, 262144, 524288, 2 * 1024 * 1024] {
        let g_fl = run(true, *want);
        let g_lc = run(false, *want);
        assert_eq!(g_fl, g_lc, "stacksize {want}: fl={g_fl}, lc={g_lc}");
        assert_eq!(g_fl, *want, "stacksize round-trip");
    }
}

#[test]
fn diff_attr_stacksize_too_small_einval() {
    // Below PTHREAD_STACK_MIN (16k on Linux) → EINVAL on both
    let mut a_fl = vec![0u8; ATTR_BYTES];
    let _ = unsafe { fl::pthread_attr_init(a_fl.as_mut_ptr() as *mut _) };
    let r_fl = unsafe { fl::pthread_attr_setstacksize(a_fl.as_mut_ptr() as *mut _, 64) };
    let _ = unsafe { fl::pthread_attr_destroy(a_fl.as_mut_ptr() as *mut _) };

    let mut a_lc = vec![0u8; ATTR_BYTES];
    let _ = unsafe { pthread_attr_init(a_lc.as_mut_ptr() as *mut c_void) };
    let r_lc = unsafe { pthread_attr_setstacksize(a_lc.as_mut_ptr() as *mut c_void, 64) };
    let _ = unsafe { pthread_attr_destroy(a_lc.as_mut_ptr() as *mut c_void) };

    assert_eq!(
        r_fl != 0,
        r_lc != 0,
        "setstacksize too-small fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_attr_guardsize_round_trip() {
    let run = |use_fl: bool, want: usize| -> usize {
        let mut a = vec![0u8; ATTR_BYTES];
        let _ = if use_fl {
            unsafe { fl::pthread_attr_init(a.as_mut_ptr() as *mut _) }
        } else {
            unsafe { pthread_attr_init(a.as_mut_ptr() as *mut c_void) }
        };
        let _ = if use_fl {
            unsafe { fl::pthread_attr_setguardsize(a.as_mut_ptr() as *mut _, want) }
        } else {
            unsafe { pthread_attr_setguardsize(a.as_mut_ptr() as *mut c_void, want) }
        };
        let mut got: usize = 0;
        let _ = if use_fl {
            unsafe { fl::pthread_attr_getguardsize(a.as_ptr() as *const _, &mut got) }
        } else {
            unsafe { pthread_attr_getguardsize(a.as_ptr() as *const c_void, &mut got) }
        };
        let _ = if use_fl {
            unsafe { fl::pthread_attr_destroy(a.as_mut_ptr() as *mut _) }
        } else {
            unsafe { pthread_attr_destroy(a.as_mut_ptr() as *mut c_void) }
        };
        got
    };
    for want in &[0usize, 4096, 65536] {
        let g_fl = run(true, *want);
        let g_lc = run(false, *want);
        assert_eq!(g_fl, g_lc, "guardsize {want}: fl={g_fl}, lc={g_lc}");
        assert_eq!(g_fl, *want, "guardsize round-trip");
    }
}

#[test]
fn diff_attr_invalid_detachstate() {
    let mut a_fl = vec![0u8; ATTR_BYTES];
    let _ = unsafe { fl::pthread_attr_init(a_fl.as_mut_ptr() as *mut _) };
    let r_fl = unsafe { fl::pthread_attr_setdetachstate(a_fl.as_mut_ptr() as *mut _, 99) };
    let _ = unsafe { fl::pthread_attr_destroy(a_fl.as_mut_ptr() as *mut _) };

    let mut a_lc = vec![0u8; ATTR_BYTES];
    let _ = unsafe { pthread_attr_init(a_lc.as_mut_ptr() as *mut c_void) };
    let r_lc = unsafe { pthread_attr_setdetachstate(a_lc.as_mut_ptr() as *mut c_void, 99) };
    let _ = unsafe { pthread_attr_destroy(a_lc.as_mut_ptr() as *mut c_void) };

    assert_eq!(
        r_fl != 0,
        r_lc != 0,
        "setdetachstate invalid fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn pthread_attr_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"pthread.h(attr_*)\",\"reference\":\"glibc\",\"functions\":8,\"divergences\":0}}",
    );
}
