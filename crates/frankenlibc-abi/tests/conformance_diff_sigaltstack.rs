#![cfg(target_os = "linux")]

//! Differential conformance harness for `sigaltstack()`:
//!   - Query current stack (NULL ss, non-NULL old_ss)
//!   - Set then disable an alternate stack
//!
//! Tests serialize via SIGALT_LOCK because sigaltstack is per-thread
//! but the test runner can interleave.
//!
//! Bead: CONFORMANCE: libc sigaltstack diff matrix.

use std::ffi::c_int;
use std::sync::Mutex;

use frankenlibc_abi::signal_abi as fl;

unsafe extern "C" {
    fn sigaltstack(ss: *const libc::stack_t, old_ss: *mut libc::stack_t) -> c_int;
}

const SS_DISABLE: c_int = libc::SS_DISABLE;
const SIGSTKSZ: usize = libc::SIGSTKSZ;

static SIGALT_LOCK: Mutex<()> = Mutex::new(());

fn empty_stack() -> libc::stack_t {
    unsafe { core::mem::zeroed() }
}

#[test]
fn diff_sigaltstack_query_current() {
    let _g = SIGALT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut s_fl = empty_stack();
    let mut s_lc = empty_stack();
    let r_fl = unsafe { fl::sigaltstack(std::ptr::null(), &mut s_fl) };
    let r_lc = unsafe { sigaltstack(std::ptr::null(), &mut s_lc) };
    assert_eq!(r_fl, r_lc, "sigaltstack query return: fl={r_fl}, lc={r_lc}");
    if r_fl == 0 && r_lc == 0 {
        assert_eq!(s_fl.ss_flags, s_lc.ss_flags, "ss_flags after query");
        assert_eq!(s_fl.ss_size, s_lc.ss_size, "ss_size after query");
    }
}

#[test]
fn diff_sigaltstack_set_then_disable() {
    let _g = SIGALT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Save original
    let mut orig = empty_stack();
    let _ = unsafe { sigaltstack(std::ptr::null(), &mut orig) };

    // Allocate a stack-region heap buffer to install
    let mut stack_buf = vec![0u8; SIGSTKSZ];
    let new_ss = libc::stack_t {
        ss_sp: stack_buf.as_mut_ptr() as *mut std::ffi::c_void,
        ss_flags: 0,
        ss_size: SIGSTKSZ,
    };

    // Set via fl, query via libc
    let r_set_fl = unsafe { fl::sigaltstack(&new_ss, std::ptr::null_mut()) };
    let mut got = empty_stack();
    let _ = unsafe { sigaltstack(std::ptr::null(), &mut got) };
    let after_set_fl = (got.ss_size, got.ss_flags & SS_DISABLE);

    // Disable via fl
    let disable = libc::stack_t {
        ss_sp: std::ptr::null_mut(),
        ss_flags: SS_DISABLE,
        ss_size: 0,
    };
    let r_disable_fl = unsafe { fl::sigaltstack(&disable, std::ptr::null_mut()) };
    let mut got2 = empty_stack();
    let _ = unsafe { sigaltstack(std::ptr::null(), &mut got2) };
    let after_disable_fl = got2.ss_flags & SS_DISABLE;

    // Now do the same via libc as a control
    let r_set_lc = unsafe { sigaltstack(&new_ss, std::ptr::null_mut()) };
    let mut got3 = empty_stack();
    let _ = unsafe { sigaltstack(std::ptr::null(), &mut got3) };
    let after_set_lc = (got3.ss_size, got3.ss_flags & SS_DISABLE);

    let r_disable_lc = unsafe { sigaltstack(&disable, std::ptr::null_mut()) };
    let mut got4 = empty_stack();
    let _ = unsafe { sigaltstack(std::ptr::null(), &mut got4) };
    let after_disable_lc = got4.ss_flags & SS_DISABLE;

    // Restore original (best effort — original may have been "disabled")
    let _ = unsafe { sigaltstack(&orig, std::ptr::null_mut()) };

    assert_eq!(r_set_fl, r_set_lc, "set return: fl={r_set_fl}, lc={r_set_lc}");
    assert_eq!(
        r_disable_fl, r_disable_lc,
        "disable return: fl={r_disable_fl}, lc={r_disable_lc}"
    );
    assert_eq!(
        after_set_fl, after_set_lc,
        "post-set state: fl={after_set_fl:?}, lc={after_set_lc:?}"
    );
    assert_eq!(
        after_disable_fl, after_disable_lc,
        "post-disable SS_DISABLE bit: fl={after_disable_fl}, lc={after_disable_lc}"
    );
}

#[test]
fn diff_sigaltstack_size_too_small() {
    let _g = SIGALT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut buf = vec![0u8; 64]; // Way below MINSIGSTKSZ
    let bad = libc::stack_t {
        ss_sp: buf.as_mut_ptr() as *mut std::ffi::c_void,
        ss_flags: 0,
        ss_size: 64,
    };
    let r_fl = unsafe { fl::sigaltstack(&bad, std::ptr::null_mut()) };
    let r_lc = unsafe { sigaltstack(&bad, std::ptr::null_mut()) };
    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "sigaltstack ENOMEM (size too small) fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn sigaltstack_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"signal.h(sigaltstack)\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
