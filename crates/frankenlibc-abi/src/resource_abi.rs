//! ABI layer for `<sys/resource.h>` functions (`getrlimit`, `setrlimit`).
//!
//! Validates via `frankenlibc_core::resource` helpers, then calls `libc`.

use std::ffi::c_int;

use frankenlibc_core::errno;
use frankenlibc_core::resource as res_core;
use frankenlibc_core::syscall as raw_syscall;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::runtime_policy;

#[inline]
unsafe fn raw_prlimit64(
    resource: c_int,
    new_limit: *const libc::rlimit,
    old_limit: *mut libc::rlimit,
) -> c_int {
    match unsafe {
        raw_syscall::sys_prlimit64(
            0, // pid = 0 means current process
            resource as u32,
            new_limit as *const u8,
            old_limit as *mut u8,
        )
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// getrlimit
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getrlimit(resource: c_int, rlim: *mut libc::rlimit) -> c_int {
    let (_mode, decision) =
        runtime_policy::decide(ApiFamily::IoFd, resource as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if rlim.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if !res_core::valid_resource(resource) {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { raw_prlimit64(resource, std::ptr::null(), rlim) };
    let adverse = rc != 0;
    // errno is set internally by raw_prlimit64 on failure
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// setrlimit
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setrlimit(resource: c_int, rlim: *const libc::rlimit) -> c_int {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::IoFd, resource as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if rlim.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if !res_core::valid_resource(resource) {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    // In hardened mode, clamp soft to hard if soft > hard.
    let effective_rlim = if mode.heals_enabled() {
        let r = unsafe { *rlim };
        if r.rlim_cur > r.rlim_max {
            let mut clamped = r;
            clamped.rlim_cur = clamped.rlim_max;
            let rc = unsafe { raw_prlimit64(resource, &clamped, std::ptr::null_mut()) };
            let adverse = rc != 0;
            // errno is set internally by raw_prlimit64 on failure
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, adverse);
            return rc;
        }
        rlim
    } else {
        rlim
    };

    let rc = unsafe { raw_prlimit64(resource, effective_rlim, std::ptr::null_mut()) };
    let adverse = rc != 0;
    // errno is set internally by raw_prlimit64 on failure
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, adverse);
    rc
}
