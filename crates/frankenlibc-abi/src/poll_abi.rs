//! ABI layer for I/O multiplexing functions.
//!
//! Provides the POSIX I/O multiplexing surface: poll, ppoll, select, pselect.
//! All functions route through the membrane RuntimeMathKernel under
//! `ApiFamily::Poll`.

use std::ffi::c_int;
use std::os::raw::c_long;

use frankenlibc_core::errno;
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
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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

// ---------------------------------------------------------------------------
// epoll_create / epoll_create1
// ---------------------------------------------------------------------------

/// Linux `epoll_create` — open an epoll file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn epoll_create(size: c_int) -> c_int {
    // size is ignored but must be > 0 for compatibility.
    if size <= 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    // Modern kernels ignore size; use epoll_create1(0) internally.
    let rc = unsafe { libc::syscall(libc::SYS_epoll_create1 as c_long, 0) as c_int };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::ENOMEM);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// Linux `epoll_create1` — open an epoll file descriptor with flags.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn epoll_create1(flags: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_epoll_create1 as c_long, flags) as c_int };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EINVAL);
        unsafe { set_abi_errno(e) };
    }
    rc
}

// ---------------------------------------------------------------------------
// epoll_ctl
// ---------------------------------------------------------------------------

/// Linux `epoll_ctl` — control interface for an epoll file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn epoll_ctl(
    epfd: c_int,
    op: c_int,
    fd: c_int,
    event: *mut libc::epoll_event,
) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_epoll_ctl as c_long, epfd, op, fd, event) as c_int };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EBADF);
        unsafe { set_abi_errno(e) };
    }
    rc
}

// ---------------------------------------------------------------------------
// epoll_wait / epoll_pwait
// ---------------------------------------------------------------------------

/// Linux `epoll_wait` — wait for events on an epoll file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn epoll_wait(
    epfd: c_int,
    events: *mut libc::epoll_event,
    maxevents: c_int,
    timeout: c_int,
) -> c_int {
    if events.is_null() || maxevents <= 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    let rc = unsafe {
        libc::syscall(
            libc::SYS_epoll_pwait as c_long,
            epfd,
            events,
            maxevents,
            timeout,
            std::ptr::null::<libc::sigset_t>(),
            core::mem::size_of::<libc::sigset_t>(),
        ) as c_int
    };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EBADF);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// Linux `epoll_pwait` — wait for events with signal mask.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn epoll_pwait(
    epfd: c_int,
    events: *mut libc::epoll_event,
    maxevents: c_int,
    timeout: c_int,
    sigmask: *const libc::sigset_t,
) -> c_int {
    if events.is_null() || maxevents <= 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    let rc = unsafe {
        libc::syscall(
            libc::SYS_epoll_pwait as c_long,
            epfd,
            events,
            maxevents,
            timeout,
            sigmask,
            core::mem::size_of::<libc::sigset_t>(),
        ) as c_int
    };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EBADF);
        unsafe { set_abi_errno(e) };
    }
    rc
}

// ---------------------------------------------------------------------------
// eventfd
// ---------------------------------------------------------------------------

/// Linux `eventfd` — create a file descriptor for event notification.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn eventfd(initval: u32, flags: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_eventfd2 as c_long, initval, flags) as c_int };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EINVAL);
        unsafe { set_abi_errno(e) };
    }
    rc
}

// ---------------------------------------------------------------------------
// timerfd_create / timerfd_settime / timerfd_gettime
// ---------------------------------------------------------------------------

/// Linux `timerfd_create` — create a timer file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timerfd_create(clockid: c_int, flags: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_timerfd_create as c_long, clockid, flags) as c_int };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EINVAL);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// Linux `timerfd_settime` — arm/disarm a timer file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timerfd_settime(
    fd: c_int,
    flags: c_int,
    new_value: *const libc::itimerspec,
    old_value: *mut libc::itimerspec,
) -> c_int {
    if new_value.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    let rc = unsafe {
        libc::syscall(
            libc::SYS_timerfd_settime as c_long,
            fd,
            flags,
            new_value,
            old_value,
        ) as c_int
    };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EBADF);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// Linux `timerfd_gettime` — get current setting of a timer file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timerfd_gettime(fd: c_int, curr_value: *mut libc::itimerspec) -> c_int {
    if curr_value.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    let rc = unsafe { libc::syscall(libc::SYS_timerfd_gettime as c_long, fd, curr_value) as c_int };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EBADF);
        unsafe { set_abi_errno(e) };
    }
    rc
}

// ---------------------------------------------------------------------------
// sched_yield / prctl
// ---------------------------------------------------------------------------

/// POSIX `sched_yield` — yield the processor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_yield() -> c_int {
    unsafe { libc::syscall(libc::SYS_sched_yield as c_long) as c_int }
}

/// Linux `prctl` — operations on a process.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn prctl(
    option: c_int,
    arg2: libc::c_ulong,
    arg3: libc::c_ulong,
    arg4: libc::c_ulong,
    arg5: libc::c_ulong,
) -> c_int {
    let rc = unsafe {
        libc::syscall(libc::SYS_prctl as c_long, option, arg2, arg3, arg4, arg5) as c_int
    };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EINVAL);
        unsafe { set_abi_errno(e) };
    }
    rc
}
