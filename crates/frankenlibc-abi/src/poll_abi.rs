//! ABI layer for I/O multiplexing functions.
//!
//! Provides the POSIX I/O multiplexing surface: poll, ppoll, select, pselect.
//! All functions route through the membrane RuntimeMathKernel under
//! `ApiFamily::Poll`.

use std::ffi::c_int;
use std::os::raw::c_long;

use frankenlibc_core::poll as poll_core;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

// ---------------------------------------------------------------------------
// poll
// ---------------------------------------------------------------------------

/// POSIX `poll` — wait for events on file descriptors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poll(fds: *mut libc::pollfd, nfds: libc::nfds_t, timeout: c_int) -> c_int {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Poll, fds as usize, nfds as usize, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Poll, decision.profile, 20, true);
        unsafe { set_abi_errno(libc::EPERM) };
        return -1;
    }

    let actual_nfds = if mode.heals_enabled() && !poll_core::valid_nfds(nfds) {
        let clamped = poll_core::clamp_poll_nfds(nfds);
        global_healing_policy().record(&HealingAction::ClampSize {
            requested: nfds as usize,
            clamped: clamped as usize,
        });
        clamped
    } else {
        nfds
    };

    let rc = unsafe { libc::syscall(libc::SYS_poll as c_long, fds, actual_nfds, timeout) as c_int };
    let adverse = rc < 0;
    if adverse {
        unsafe { set_abi_errno(libc::EINVAL) };
    }
    runtime_policy::observe(ApiFamily::Poll, decision.profile, 20, adverse);
    rc
}

// ---------------------------------------------------------------------------
// ppoll
// ---------------------------------------------------------------------------

/// POSIX `ppoll` — poll with signal mask and timespec timeout.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ppoll(
    fds: *mut libc::pollfd,
    nfds: libc::nfds_t,
    timeout_ts: *const libc::timespec,
    sigmask: *const libc::sigset_t,
) -> c_int {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Poll, fds as usize, nfds as usize, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Poll, decision.profile, 25, true);
        unsafe { set_abi_errno(libc::EPERM) };
        return -1;
    }

    let actual_nfds = if mode.heals_enabled() && !poll_core::valid_nfds(nfds) {
        let clamped = poll_core::clamp_poll_nfds(nfds);
        global_healing_policy().record(&HealingAction::ClampSize {
            requested: nfds as usize,
            clamped: clamped as usize,
        });
        clamped
    } else {
        nfds
    };

    // Use SYS_ppoll with sigset size parameter.
    let sigset_size = core::mem::size_of::<libc::sigset_t>();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_ppoll as c_long,
            fds,
            actual_nfds,
            timeout_ts,
            sigmask,
            sigset_size,
        ) as c_int
    };
    let adverse = rc < 0;
    if adverse {
        unsafe { set_abi_errno(libc::EINVAL) };
    }
    runtime_policy::observe(ApiFamily::Poll, decision.profile, 25, adverse);
    rc
}

// ---------------------------------------------------------------------------
// select
// ---------------------------------------------------------------------------

/// POSIX `select` — synchronous I/O multiplexing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn select(
    nfds: c_int,
    readfds: *mut libc::fd_set,
    writefds: *mut libc::fd_set,
    exceptfds: *mut libc::fd_set,
    timeout: *mut libc::timeval,
) -> c_int {
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Poll,
        readfds as usize,
        nfds as usize,
        true,
        false,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Poll, decision.profile, 25, true);
        unsafe { set_abi_errno(libc::EPERM) };
        return -1;
    }

    let actual_nfds = if mode.heals_enabled() && !poll_core::valid_select_nfds(nfds) {
        let clamped = poll_core::clamp_select_nfds(nfds);
        global_healing_policy().record(&HealingAction::ClampSize {
            requested: nfds as usize,
            clamped: clamped as usize,
        });
        clamped
    } else {
        nfds
    };

    let rc = unsafe {
        libc::syscall(
            libc::SYS_select as c_long,
            actual_nfds,
            readfds,
            writefds,
            exceptfds,
            timeout,
        ) as c_int
    };
    let adverse = rc < 0;
    if adverse {
        unsafe { set_abi_errno(libc::EINVAL) };
    }
    runtime_policy::observe(ApiFamily::Poll, decision.profile, 25, adverse);
    rc
}

// ---------------------------------------------------------------------------
// pselect
// ---------------------------------------------------------------------------

/// POSIX `pselect` — select with signal mask and timespec timeout.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pselect(
    nfds: c_int,
    readfds: *mut libc::fd_set,
    writefds: *mut libc::fd_set,
    exceptfds: *mut libc::fd_set,
    timeout: *const libc::timespec,
    sigmask: *const libc::sigset_t,
) -> c_int {
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Poll,
        readfds as usize,
        nfds as usize,
        true,
        false,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Poll, decision.profile, 30, true);
        unsafe { set_abi_errno(libc::EPERM) };
        return -1;
    }

    let actual_nfds = if mode.heals_enabled() && !poll_core::valid_select_nfds(nfds) {
        let clamped = poll_core::clamp_select_nfds(nfds);
        global_healing_policy().record(&HealingAction::ClampSize {
            requested: nfds as usize,
            clamped: clamped as usize,
        });
        clamped
    } else {
        nfds
    };

    // pselect6 expects a struct { sigset_t*, size_t } as the last parameter.
    let sigset_size = core::mem::size_of::<libc::sigset_t>();
    let sig_data: [usize; 2] = [sigmask as usize, sigset_size];
    let sig_ptr = if sigmask.is_null() {
        std::ptr::null::<[usize; 2]>()
    } else {
        &sig_data as *const [usize; 2]
    };

    let rc = unsafe {
        libc::syscall(
            libc::SYS_pselect6 as c_long,
            actual_nfds,
            readfds,
            writefds,
            exceptfds,
            timeout,
            sig_ptr,
        ) as c_int
    };
    let adverse = rc < 0;
    if adverse {
        unsafe { set_abi_errno(libc::EINVAL) };
    }
    runtime_policy::observe(ApiFamily::Poll, decision.profile, 30, adverse);
    rc
}
