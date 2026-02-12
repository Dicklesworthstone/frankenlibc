//! ABI layer for `<sys/resource.h>` functions (`getrlimit`, `setrlimit`).
//!
//! Validates via `frankenlibc_core::resource` helpers, then calls `libc`.

use std::ffi::c_int;

use frankenlibc_core::errno;
use frankenlibc_core::resource as res_core;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

// ---------------------------------------------------------------------------
// getrlimit
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getrlimit(resource: c_int, rlim: *mut libc::rlimit) -> c_int {
    let (_mode, decision) =
        runtime_policy::decide(ApiFamily::IoFd, resource as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
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

    let rc = unsafe { libc::getrlimit(resource as libc::__rlimit_resource_t, rlim) };
    let adverse = rc != 0;
    if adverse {
        unsafe { set_abi_errno(errno::EINVAL) };
    }
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// setrlimit
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setrlimit(resource: c_int, rlim: *const libc::rlimit) -> c_int {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::IoFd, resource as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
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
            let boxed = Box::new(clamped);
            let ptr: *const libc::rlimit = &*boxed;
            let rc = unsafe { libc::setrlimit(resource as libc::__rlimit_resource_t, ptr) };
            let adverse = rc != 0;
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, adverse);
            return rc;
        }
        rlim
    } else {
        rlim
    };

    let rc = unsafe { libc::setrlimit(resource as libc::__rlimit_resource_t, effective_rlim) };
    let adverse = rc != 0;
    if adverse {
        unsafe { set_abi_errno(errno::EINVAL) };
    }
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, adverse);
    rc
}
