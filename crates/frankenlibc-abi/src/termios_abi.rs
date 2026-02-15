//! ABI layer for `<termios.h>` functions.
//!
//! Terminal attribute manipulation via `ioctl`/`libc` syscalls.
//! Pure-logic helpers (baud rate extraction, cfmakeraw) delegate
//! to `frankenlibc_core::termios`.

use std::ffi::c_int;

use frankenlibc_core::errno;
use frankenlibc_core::syscall;
use frankenlibc_core::termios as termios_core;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

// ---------------------------------------------------------------------------
// tcgetattr
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tcgetattr(fd: c_int, termios_p: *mut libc::termios) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Termios, fd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
        return -1;
    }

    if termios_p.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
        return -1;
    }

    let rc = match unsafe { syscall::sys_ioctl(fd, libc::TCGETS as usize, termios_p as usize) } {
        Ok(_) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    let adverse = rc != 0;
    // libc sets errno on failure (EBADF, ENOTTY, etc.) — do not overwrite.
    runtime_policy::observe(ApiFamily::Termios, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// tcsetattr
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tcsetattr(
    fd: c_int,
    optional_actions: c_int,
    termios_p: *const libc::termios,
) -> c_int {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Termios, fd as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
        return -1;
    }

    if termios_p.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
        return -1;
    }

    let act = if !termios_core::valid_optional_actions(optional_actions) {
        if mode.heals_enabled() {
            termios_core::TCSANOW // default to immediate in hardened mode
        } else {
            unsafe { set_abi_errno(errno::EINVAL) };
            runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
            return -1;
        }
    } else {
        optional_actions
    };

    let request = match act {
        termios_core::TCSANOW => libc::TCSETS,
        termios_core::TCSADRAIN => libc::TCSETSW,
        termios_core::TCSAFLUSH => libc::TCSETSF,
        _ => libc::TCSETS,
    };
    let rc = match unsafe { syscall::sys_ioctl(fd, request as usize, termios_p as usize) } {
        Ok(_) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    let adverse = rc != 0;
    // libc sets errno on failure (EBADF, ENOTTY, EINTR, etc.) — do not overwrite.
    runtime_policy::observe(ApiFamily::Termios, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// cfgetispeed
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfgetispeed(termios_p: *const libc::termios) -> u32 {
    if termios_p.is_null() {
        return 0;
    }
    unsafe { (*termios_p).c_cflag & termios_core::CBAUD }
}

// ---------------------------------------------------------------------------
// cfgetospeed
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfgetospeed(termios_p: *const libc::termios) -> u32 {
    if termios_p.is_null() {
        return 0;
    }
    unsafe { (*termios_p).c_cflag & termios_core::CBAUD }
}

// ---------------------------------------------------------------------------
// cfsetispeed
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetispeed(termios_p: *mut libc::termios, speed: u32) -> c_int {
    if termios_p.is_null() {
        return -1;
    }
    if !termios_core::valid_baud_rate(speed) {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    unsafe {
        let next = (*termios_p).c_cflag & !termios_core::CBAUD | (speed & termios_core::CBAUD);
        (*termios_p).c_cflag = next as libc::tcflag_t;
    }
    0
}

// ---------------------------------------------------------------------------
// cfsetospeed
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetospeed(termios_p: *mut libc::termios, speed: u32) -> c_int {
    if termios_p.is_null() {
        return -1;
    }
    if !termios_core::valid_baud_rate(speed) {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    unsafe {
        let next = (*termios_p).c_cflag & !termios_core::CBAUD | (speed & termios_core::CBAUD);
        (*termios_p).c_cflag = next as libc::tcflag_t;
    }
    0
}

// ---------------------------------------------------------------------------
// tcdrain
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tcdrain(fd: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Termios, fd as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
        return -1;
    }
    let rc = match unsafe { syscall::sys_ioctl(fd, libc::TCSBRK as usize, 1usize) } {
        Ok(_) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::Termios, decision.profile, 8, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// tcflush
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tcflush(fd: c_int, queue_selector: c_int) -> c_int {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Termios, fd as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
        return -1;
    }

    let sel = if !termios_core::valid_queue_selector(queue_selector) {
        if mode.heals_enabled() {
            termios_core::TCIOFLUSH // flush both in hardened mode
        } else {
            unsafe { set_abi_errno(errno::EINVAL) };
            runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
            return -1;
        }
    } else {
        queue_selector
    };

    let rc = match unsafe { syscall::sys_ioctl(fd, libc::TCFLSH as usize, sel as usize) } {
        Ok(_) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::Termios, decision.profile, 8, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// tcflow
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tcflow(fd: c_int, action: c_int) -> c_int {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Termios, fd as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
        return -1;
    }

    if !termios_core::valid_flow_action(action) {
        if mode.heals_enabled() {
            runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
            return 0; // no-op in hardened mode
        }
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
        return -1;
    }

    let rc = match unsafe { syscall::sys_ioctl(fd, libc::TCXONC as usize, action as usize) } {
        Ok(_) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::Termios, decision.profile, 8, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// tcsendbreak
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tcsendbreak(fd: c_int, duration: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Termios, fd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
        return -1;
    }
    let rc = match unsafe {
        syscall::sys_ioctl(fd, libc::TCSBRK as usize, duration as libc::c_long as usize)
    } {
        Ok(_) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::Termios, decision.profile, 8, rc != 0);
    rc
}
