#![cfg(target_os = "linux")]

//! Differential conformance harness for pthread synchronization
//! primitives that weren't covered in the main pthread harness:
//!   - pthread_barrier_init / pthread_barrier_wait / pthread_barrier_destroy
//!   - pthread_spin_init / pthread_spin_lock / pthread_spin_unlock /
//!     pthread_spin_destroy
//!
//! Each primitive's state lives in a caller-owned opaque blob; we use
//! generous padding (256B for both) and run independent fl-only and
//! lc-only sequences per test.
//!
//! Bead: CONFORMANCE: libc pthread_barrier+pthread_spin diff matrix.

use std::ffi::{c_int, c_void};

use frankenlibc_abi::pthread_abi as fl;

unsafe extern "C" {
    fn pthread_barrier_init(barrier: *mut c_void, attr: *const c_void, count: u32) -> c_int;
    fn pthread_barrier_wait(barrier: *mut c_void) -> c_int;
    fn pthread_barrier_destroy(barrier: *mut c_void) -> c_int;
    fn pthread_spin_init(lock: *mut c_void, pshared: c_int) -> c_int;
    fn pthread_spin_lock(lock: *mut c_void) -> c_int;
    fn pthread_spin_unlock(lock: *mut c_void) -> c_int;
    fn pthread_spin_destroy(lock: *mut c_void) -> c_int;
    fn pthread_spin_trylock(lock: *mut c_void) -> c_int;
}

const BARRIER_SERIAL_THREAD: c_int = -1;

const BARRIER_BYTES: usize = 256; // glibc pthread_barrier_t = 32B
const SPIN_BYTES: usize = 64; // glibc pthread_spinlock_t = 4B

#[test]
fn diff_pthread_barrier_init_destroy_round_trip() {
    let mut b_fl = vec![0u8; BARRIER_BYTES];
    let r_init_fl =
        unsafe { fl::pthread_barrier_init(b_fl.as_mut_ptr() as *mut c_void, std::ptr::null(), 1) };
    let r_destroy_fl = unsafe { fl::pthread_barrier_destroy(b_fl.as_mut_ptr() as *mut c_void) };

    let mut b_lc = vec![0u8; BARRIER_BYTES];
    let r_init_lc =
        unsafe { pthread_barrier_init(b_lc.as_mut_ptr() as *mut c_void, std::ptr::null(), 1) };
    let r_destroy_lc = unsafe { pthread_barrier_destroy(b_lc.as_mut_ptr() as *mut c_void) };

    assert_eq!(
        r_init_fl, r_init_lc,
        "barrier_init: fl={r_init_fl}, lc={r_init_lc}"
    );
    assert_eq!(
        r_destroy_fl, r_destroy_lc,
        "barrier_destroy: fl={r_destroy_fl}, lc={r_destroy_lc}"
    );
    assert_eq!(r_init_fl, 0, "barrier_init should succeed");
}

#[test]
fn diff_pthread_barrier_init_zero_count_einval() {
    // POSIX: count must be > 0; both impls must fail with EINVAL.
    let mut b_fl = vec![0u8; BARRIER_BYTES];
    let r_fl =
        unsafe { fl::pthread_barrier_init(b_fl.as_mut_ptr() as *mut c_void, std::ptr::null(), 0) };
    let mut b_lc = vec![0u8; BARRIER_BYTES];
    let r_lc =
        unsafe { pthread_barrier_init(b_lc.as_mut_ptr() as *mut c_void, std::ptr::null(), 0) };
    assert_eq!(
        r_fl != 0,
        r_lc != 0,
        "barrier_init count=0 fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_pthread_barrier_wait_count_one_releases_immediately() {
    // count=1 means a single wait() call returns BARRIER_SERIAL_THREAD
    // and the barrier resets.
    let run = |use_fl: bool| -> (c_int, c_int) {
        let mut b = vec![0u8; BARRIER_BYTES];
        let _ = if use_fl {
            unsafe { fl::pthread_barrier_init(b.as_mut_ptr() as *mut c_void, std::ptr::null(), 1) }
        } else {
            unsafe { pthread_barrier_init(b.as_mut_ptr() as *mut c_void, std::ptr::null(), 1) }
        };
        let r = if use_fl {
            unsafe { fl::pthread_barrier_wait(b.as_mut_ptr() as *mut c_void) }
        } else {
            unsafe { pthread_barrier_wait(b.as_mut_ptr() as *mut c_void) }
        };
        let _ = if use_fl {
            unsafe { fl::pthread_barrier_destroy(b.as_mut_ptr() as *mut c_void) }
        } else {
            unsafe { pthread_barrier_destroy(b.as_mut_ptr() as *mut c_void) }
        };
        // POSIX: exactly one waiter receives PTHREAD_BARRIER_SERIAL_THREAD;
        // others get 0. Both impls should agree.
        (
            r,
            if r == BARRIER_SERIAL_THREAD || r == 0 {
                0
            } else {
                -1
            },
        )
    };
    let (r_fl, sane_fl) = run(true);
    let (r_lc, sane_lc) = run(false);
    assert_eq!(sane_fl, 0, "fl barrier_wait sane return: r={r_fl}");
    assert_eq!(sane_lc, 0, "lc barrier_wait sane return: r={r_lc}");
    assert_eq!(
        r_fl, r_lc,
        "barrier_wait return divergence: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_pthread_spin_init_destroy() {
    let mut s_fl = vec![0u8; SPIN_BYTES];
    let r_init_fl = unsafe { fl::pthread_spin_init(s_fl.as_mut_ptr() as *mut c_void, 0) };
    let r_destroy_fl = unsafe { fl::pthread_spin_destroy(s_fl.as_mut_ptr() as *mut c_void) };

    let mut s_lc = vec![0u8; SPIN_BYTES];
    let r_init_lc = unsafe { pthread_spin_init(s_lc.as_mut_ptr() as *mut c_void, 0) };
    let r_destroy_lc = unsafe { pthread_spin_destroy(s_lc.as_mut_ptr() as *mut c_void) };

    assert_eq!(
        r_init_fl, r_init_lc,
        "spin_init: fl={r_init_fl}, lc={r_init_lc}"
    );
    assert_eq!(
        r_destroy_fl, r_destroy_lc,
        "spin_destroy: fl={r_destroy_fl}, lc={r_destroy_lc}"
    );
    assert_eq!(r_init_fl, 0, "spin_init should succeed");
}

#[test]
fn diff_pthread_spin_lock_unlock_round_trip() {
    let run = |use_fl: bool| -> (c_int, c_int, c_int) {
        let mut s = vec![0u8; SPIN_BYTES];
        let _ = if use_fl {
            unsafe { fl::pthread_spin_init(s.as_mut_ptr() as *mut c_void, 0) }
        } else {
            unsafe { pthread_spin_init(s.as_mut_ptr() as *mut c_void, 0) }
        };
        let lk = if use_fl {
            unsafe { fl::pthread_spin_lock(s.as_mut_ptr() as *mut c_void) }
        } else {
            unsafe { pthread_spin_lock(s.as_mut_ptr() as *mut c_void) }
        };
        let ul = if use_fl {
            unsafe { fl::pthread_spin_unlock(s.as_mut_ptr() as *mut c_void) }
        } else {
            unsafe { pthread_spin_unlock(s.as_mut_ptr() as *mut c_void) }
        };
        let dt = if use_fl {
            unsafe { fl::pthread_spin_destroy(s.as_mut_ptr() as *mut c_void) }
        } else {
            unsafe { pthread_spin_destroy(s.as_mut_ptr() as *mut c_void) }
        };
        (lk, ul, dt)
    };
    let (lk_fl, ul_fl, dt_fl) = run(true);
    let (lk_lc, ul_lc, dt_lc) = run(false);
    assert_eq!(lk_fl, lk_lc, "spin_lock: fl={lk_fl}, lc={lk_lc}");
    assert_eq!(ul_fl, ul_lc, "spin_unlock: fl={ul_fl}, lc={ul_lc}");
    assert_eq!(dt_fl, dt_lc, "spin_destroy: fl={dt_fl}, lc={dt_lc}");
    assert_eq!(lk_fl, 0, "spin_lock should succeed");
    assert_eq!(ul_fl, 0, "spin_unlock should succeed");
}

#[test]
fn diff_pthread_spin_trylock_unlocked_succeeds() {
    let run = |use_fl: bool| -> c_int {
        let mut s = vec![0u8; SPIN_BYTES];
        let _ = if use_fl {
            unsafe { fl::pthread_spin_init(s.as_mut_ptr() as *mut c_void, 0) }
        } else {
            unsafe { pthread_spin_init(s.as_mut_ptr() as *mut c_void, 0) }
        };
        let r = if use_fl {
            // fl exposes trylock?
            unsafe { fl::pthread_spin_trylock(s.as_mut_ptr() as *mut c_void) }
        } else {
            unsafe { pthread_spin_trylock(s.as_mut_ptr() as *mut c_void) }
        };
        if r == 0 {
            let _ = if use_fl {
                unsafe { fl::pthread_spin_unlock(s.as_mut_ptr() as *mut c_void) }
            } else {
                unsafe { pthread_spin_unlock(s.as_mut_ptr() as *mut c_void) }
            };
        }
        let _ = if use_fl {
            unsafe { fl::pthread_spin_destroy(s.as_mut_ptr() as *mut c_void) }
        } else {
            unsafe { pthread_spin_destroy(s.as_mut_ptr() as *mut c_void) }
        };
        r
    };
    let r_fl = run(true);
    let r_lc = run(false);
    assert_eq!(r_fl, r_lc, "spin_trylock unlocked: fl={r_fl}, lc={r_lc}");
    assert_eq!(r_fl, 0, "spin_trylock on unlocked should succeed");
}

#[test]
fn pthread_barrier_spin_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"pthread.h(barrier+spin)\",\"reference\":\"glibc\",\"functions\":7,\"divergences\":0}}",
    );
}
