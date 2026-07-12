#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc clock-variant-wait oracle

//! Differential gate for the clockid validation of the clock-variant waits
//! (bd-44y7sl): pthread_mutex_clocklock, pthread_cond_clockwait,
//! pthread_rwlock_clockrdlock/clockwrlock, sem_clockwait. glibc accepts ONLY
//! CLOCK_REALTIME and CLOCK_MONOTONIC (lll_futex_supported_clockid); any other
//! clock — even a kernel-valid one like CLOCK_BOOTTIME or
//! CLOCK_PROCESS_CPUTIME_ID — must be rejected with EINVAL *before* the wait.
//! fl previously routed those through clock_gettime and accepted them. The
//! clockid check happens before the primitive is touched, so static-initialized
//! primitives suffice. The pthread_* fns return EINVAL directly; sem_clockwait
//! returns -1 with errno == EINVAL. No mocks.

use std::ffi::{c_int, c_void};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn pthread_mutex_clocklock(
            m: *mut libc::pthread_mutex_t,
            c: c_int,
            t: *const libc::timespec,
        ) -> c_int;
        pub fn pthread_cond_clockwait(
            c: *mut libc::pthread_cond_t,
            m: *mut libc::pthread_mutex_t,
            clk: c_int,
            t: *const libc::timespec,
        ) -> c_int;
        pub fn pthread_rwlock_clockrdlock(
            rw: *mut libc::pthread_rwlock_t,
            c: c_int,
            t: *const libc::timespec,
        ) -> c_int;
        pub fn pthread_rwlock_clockwrlock(
            rw: *mut libc::pthread_rwlock_t,
            c: c_int,
            t: *const libc::timespec,
        ) -> c_int;
        pub fn sem_clockwait(s: *mut c_void, c: c_int, t: *const libc::timespec) -> c_int;
        pub fn sem_init(s: *mut c_void, pshared: c_int, value: c_int) -> c_int;
        pub fn __errno_location() -> *mut c_int;
    }
}
use frankenlibc_abi::{glibc_internal_abi as flg, pthread_abi as flp};

const BAD_CLOCKS: [c_int; 4] = [libc::CLOCK_PROCESS_CPUTIME_ID, libc::CLOCK_BOOTTIME, -1, 99];

fn future() -> libc::timespec {
    libc::timespec {
        tv_sec: i64::MAX / 2,
        tv_nsec: 0,
    }
}

#[test]
fn clock_variant_waits_reject_bad_clockid_like_glibc() {
    let at = future();
    for &clk in &BAD_CLOCKS {
        // pthread_mutex_clocklock
        let mut gm: libc::pthread_mutex_t = unsafe { std::mem::zeroed() };
        let mut fm: libc::pthread_mutex_t = unsafe { std::mem::zeroed() };
        let g_ml = unsafe { g::pthread_mutex_clocklock(&mut gm, clk, &at) };
        let f_ml = unsafe { flp::pthread_mutex_clocklock(&mut fm, clk, &at) };
        assert_eq!(
            f_ml, g_ml,
            "mutex_clocklock clk={clk}: fl={f_ml} glibc={g_ml}"
        );
        assert_eq!(g_ml, libc::EINVAL, "glibc rejects clk={clk}");

        // pthread_rwlock_clockrdlock / clockwrlock
        let mut grw: libc::pthread_rwlock_t = unsafe { std::mem::zeroed() };
        let mut frw: libc::pthread_rwlock_t = unsafe { std::mem::zeroed() };
        let g_rd = unsafe { g::pthread_rwlock_clockrdlock(&mut grw, clk, &at) };
        let f_rd = unsafe { flp::pthread_rwlock_clockrdlock(&mut frw, clk, &at) };
        assert_eq!(
            f_rd, g_rd,
            "rwlock_clockrdlock clk={clk}: fl={f_rd} glibc={g_rd}"
        );
        let g_wr = unsafe { g::pthread_rwlock_clockwrlock(&mut grw, clk, &at) };
        let f_wr = unsafe { flp::pthread_rwlock_clockwrlock(&mut frw, clk, &at) };
        assert_eq!(
            f_wr, g_wr,
            "rwlock_clockwrlock clk={clk}: fl={f_wr} glibc={g_wr}"
        );

        // pthread_cond_clockwait
        let mut gc: libc::pthread_cond_t = unsafe { std::mem::zeroed() };
        let mut gcm: libc::pthread_mutex_t = unsafe { std::mem::zeroed() };
        let mut fc: libc::pthread_cond_t = unsafe { std::mem::zeroed() };
        let mut fcm: libc::pthread_mutex_t = unsafe { std::mem::zeroed() };
        let g_cw = unsafe { g::pthread_cond_clockwait(&mut gc, &mut gcm, clk, &at) };
        let f_cw = unsafe { flp::pthread_cond_clockwait(&mut fc, &mut fcm, clk, &at) };
        assert_eq!(
            f_cw, g_cw,
            "cond_clockwait clk={clk}: fl={f_cw} glibc={g_cw}"
        );

        // sem_clockwait (returns -1 + errno)
        let mut gs = [0u8; 64];
        let mut fs = [0u8; 64];
        unsafe { g::sem_init(gs.as_mut_ptr() as *mut c_void, 0, 0) };
        unsafe { g::sem_init(fs.as_mut_ptr() as *mut c_void, 0, 0) };
        unsafe { *g::__errno_location() = 0 };
        let g_sw = unsafe { g::sem_clockwait(gs.as_mut_ptr() as *mut c_void, clk, &at) };
        let g_se = unsafe { *g::__errno_location() };
        unsafe { *g::__errno_location() = 0 };
        let f_sw = unsafe {
            flg::sem_clockwait(
                fs.as_mut_ptr() as *mut c_void,
                clk,
                &at as *const _ as *const c_void,
            )
        };
        let f_se = unsafe { *g::__errno_location() };
        assert_eq!(
            (f_sw, f_se),
            (g_sw, g_se),
            "sem_clockwait clk={clk}: fl=({f_sw},{f_se}) glibc=({g_sw},{g_se})"
        );
    }
}
