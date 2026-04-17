//! ABI layer for I/O multiplexing functions.
//!
//! Provides the POSIX I/O multiplexing surface: poll, ppoll, select, pselect.
//! All functions route through the membrane RuntimeMathKernel under
//! `ApiFamily::Poll`.

use std::ffi::c_int;

use frankenlibc_core::errno;
use frankenlibc_core::poll as poll_core;
use frankenlibc_core::syscall as raw_syscall;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::runtime_policy;

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

    let actual_nfds = if !poll_core::valid_nfds(nfds) {
        if mode.heals_enabled() {
            let clamped = poll_core::clamp_poll_nfds(nfds);
            global_healing_policy().record(&HealingAction::ClampSize {
                requested: nfds as usize,
                clamped: clamped as usize,
            });
            clamped
        } else {
            unsafe { set_abi_errno(errno::EINVAL) };
            runtime_policy::observe(ApiFamily::Poll, decision.profile, 20, true);
            return -1;
        }
    } else {
        nfds
    };

    // SYS_poll doesn't exist on aarch64; use SYS_ppoll with timeout conversion.
    #[cfg(target_arch = "x86_64")]
    let result = unsafe { raw_syscall::sys_poll(fds as *mut u8, actual_nfds as usize, timeout) };
    #[cfg(not(target_arch = "x86_64"))]
    let result = {
        // Convert millisecond timeout to timespec for ppoll.
        let (ts_ptr, ts_storage);
        if timeout < 0 {
            ts_storage = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let _ = &ts_storage; // suppress unused warning
            ts_ptr = std::ptr::null::<libc::timespec>();
        } else {
            ts_storage = libc::timespec {
                tv_sec: (timeout / 1000) as libc::time_t,
                tv_nsec: ((timeout % 1000) as i64) * 1_000_000,
            };
            ts_ptr = &ts_storage as *const libc::timespec;
        }
        unsafe {
            raw_syscall::sys_ppoll(
                fds as *mut u8,
                actual_nfds as usize,
                ts_ptr as *const u8,
                std::ptr::null(),
                0,
            )
        }
    };
    let (rc, adverse) = match result {
        Ok(n) => (n, false),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            (-1, true)
        }
    };
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

    let actual_nfds = if !poll_core::valid_nfds(nfds) {
        if mode.heals_enabled() {
            let clamped = poll_core::clamp_poll_nfds(nfds);
            global_healing_policy().record(&HealingAction::ClampSize {
                requested: nfds as usize,
                clamped: clamped as usize,
            });
            clamped
        } else {
            unsafe { set_abi_errno(errno::EINVAL) };
            runtime_policy::observe(ApiFamily::Poll, decision.profile, 25, true);
            return -1;
        }
    } else {
        nfds
    };

    // Use SYS_ppoll with sigset size parameter.
    let sigset_size = core::mem::size_of::<libc::c_ulong>();
    let (rc, adverse) = match unsafe {
        raw_syscall::sys_ppoll(
            fds as *mut u8,
            actual_nfds as usize,
            timeout_ts as *const u8,
            sigmask as *const u8,
            sigset_size,
        )
    } {
        Ok(n) => (n, false),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            (-1, true)
        }
    };
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

    let actual_nfds = if !poll_core::valid_select_nfds(nfds) {
        if mode.heals_enabled() {
            let clamped = poll_core::clamp_select_nfds(nfds);
            global_healing_policy().record(&HealingAction::ClampSize {
                requested: nfds as usize,
                clamped: clamped as usize,
            });
            clamped
        } else {
            unsafe { set_abi_errno(errno::EINVAL) };
            runtime_policy::observe(ApiFamily::Poll, decision.profile, 25, true);
            return -1;
        }
    } else {
        nfds
    };

    // SYS_select doesn't exist on aarch64; use SYS_pselect6 with timeout conversion.
    #[cfg(target_arch = "x86_64")]
    let result = unsafe {
        raw_syscall::sys_select(
            actual_nfds,
            readfds as *mut u8,
            writefds as *mut u8,
            exceptfds as *mut u8,
            timeout as *mut u8,
        )
    };
    #[cfg(not(target_arch = "x86_64"))]
    let result = {
        // Convert timeval to timespec for pselect6 and mirror the remaining
        // timeout back into the caller's timeval (select() semantics).
        let mut ts_storage = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let ts_ptr = if timeout.is_null() {
            std::ptr::null::<libc::timespec>()
        } else {
            let tv = unsafe { &*timeout };
            ts_storage = libc::timespec {
                tv_sec: tv.tv_sec,
                tv_nsec: tv.tv_usec * 1000,
            };
            &ts_storage as *const libc::timespec
        };
        let res = unsafe {
            raw_syscall::sys_pselect6(
                actual_nfds,
                readfds as *mut u8,
                writefds as *mut u8,
                exceptfds as *mut u8,
                ts_ptr as *const u8,
                std::ptr::null(),
            )
        };
        if !timeout.is_null() {
            let tv = unsafe { &mut *timeout };
            tv.tv_sec = ts_storage.tv_sec;
            tv.tv_usec = (ts_storage.tv_nsec / 1000) as libc::suseconds_t;
        }
        res
    };
    let (rc, adverse) = match result {
        Ok(n) => (n, false),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            (-1, true)
        }
    };
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

    let actual_nfds = if !poll_core::valid_select_nfds(nfds) {
        if mode.heals_enabled() {
            let clamped = poll_core::clamp_select_nfds(nfds);
            global_healing_policy().record(&HealingAction::ClampSize {
                requested: nfds as usize,
                clamped: clamped as usize,
            });
            clamped
        } else {
            unsafe { set_abi_errno(errno::EINVAL) };
            runtime_policy::observe(ApiFamily::Poll, decision.profile, 30, true);
            return -1;
        }
    } else {
        nfds
    };

    // pselect6 expects a struct { sigset_t*, size_t } as the last parameter.
    let sigset_size = core::mem::size_of::<libc::c_ulong>();
    let sig_data: [usize; 2] = [sigmask as usize, sigset_size];
    let sig_ptr = if sigmask.is_null() {
        std::ptr::null::<[usize; 2]>()
    } else {
        &sig_data as *const [usize; 2]
    };

    let (rc, adverse) = match unsafe {
        raw_syscall::sys_pselect6(
            actual_nfds,
            readfds as *mut u8,
            writefds as *mut u8,
            exceptfds as *mut u8,
            timeout as *const u8,
            sig_ptr as *const u8,
        )
    } {
        Ok(n) => (n, false),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            (-1, true)
        }
    };
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
    match raw_syscall::sys_epoll_create1(0) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `epoll_create1` — open an epoll file descriptor with flags.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn epoll_create1(flags: c_int) -> c_int {
    match raw_syscall::sys_epoll_create1(flags) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe { raw_syscall::sys_epoll_ctl(epfd, op, fd, event as *mut u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    if maxevents <= 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    if events.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    match unsafe {
        raw_syscall::sys_epoll_pwait(
            epfd,
            events as *mut u8,
            maxevents,
            timeout,
            std::ptr::null(),
            core::mem::size_of::<libc::c_ulong>(),
        )
    } {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    if maxevents <= 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    if events.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    match unsafe {
        raw_syscall::sys_epoll_pwait(
            epfd,
            events as *mut u8,
            maxevents,
            timeout,
            sigmask as *const u8,
            core::mem::size_of::<libc::c_ulong>(),
        )
    } {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// eventfd
// ---------------------------------------------------------------------------

/// Linux `eventfd` — create a file descriptor for event notification.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn eventfd(initval: u32, flags: c_int) -> c_int {
    match raw_syscall::sys_eventfd2(initval, flags) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// timerfd_create / timerfd_settime / timerfd_gettime
// ---------------------------------------------------------------------------

/// Linux `timerfd_create` — create a timer file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timerfd_create(clockid: c_int, flags: c_int) -> c_int {
    match raw_syscall::sys_timerfd_create(clockid, flags) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe {
        raw_syscall::sys_timerfd_settime(fd, flags, new_value as *const u8, old_value as *mut u8)
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `timerfd_gettime` — get current setting of a timer file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timerfd_gettime(fd: c_int, curr_value: *mut libc::itimerspec) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Time,
        curr_value as usize,
        std::mem::size_of::<libc::itimerspec>(),
        true,
        curr_value.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Time, decision.profile, 5, true);
        return -1;
    }

    if curr_value.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Time, decision.profile, 5, true);
        return -1;
    }
    match unsafe { raw_syscall::sys_timerfd_gettime(fd, curr_value as *mut u8) } {
        Ok(()) => {
            runtime_policy::observe(ApiFamily::Time, decision.profile, 5, false);
            0
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::Time, decision.profile, 5, true);
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// sched_yield / prctl
// ---------------------------------------------------------------------------

/// POSIX `sched_yield` — yield the processor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_yield() -> c_int {
    raw_syscall::sys_sched_yield();
    0
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
    match raw_syscall::sys_prctl(
        option,
        arg2 as usize,
        arg3 as usize,
        arg4 as usize,
        arg5 as usize,
    ) {
        Ok(rc) => rc,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}
