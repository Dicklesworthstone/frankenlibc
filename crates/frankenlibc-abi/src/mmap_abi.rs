//! ABI layer for virtual memory management functions.
//!
//! Provides the POSIX virtual memory surface: mmap, munmap, mprotect,
//! msync, madvise. All functions route through the membrane RuntimeMathKernel
//! under `ApiFamily::VirtualMemory`.

use std::ffi::{c_int, c_void};
use std::os::raw::c_long;

use frankenlibc_core::errno;
use frankenlibc_core::mmap;
use frankenlibc_core::syscall;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

// ---------------------------------------------------------------------------
// mmap
// ---------------------------------------------------------------------------

/// POSIX `mmap` — map files or devices into memory.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mmap(
    addr: *mut c_void,
    length: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: i64,
) -> *mut c_void {
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::VirtualMemory,
        addr as usize,
        length,
        true,
        false,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 40, true);
        unsafe { set_abi_errno(libc::EPERM) };
        return mmap::MAP_FAILED as *mut c_void;
    }

    if !mmap::valid_mmap_length(length) {
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 40, true);
        return mmap::MAP_FAILED as *mut c_void;
    }

    // Sanitize in hardened mode.
    let (actual_prot, actual_flags) = if mode.heals_enabled() {
        let p = if !mmap::valid_prot(prot) {
            let sanitized = mmap::PROT_READ;
            global_healing_policy().record(&HealingAction::ClampSize {
                requested: prot as usize,
                clamped: sanitized as usize,
            });
            sanitized
        } else {
            prot
        };
        let f = if !mmap::valid_map_flags(flags) {
            let sanitized = mmap::sanitize_map_flags(flags);
            global_healing_policy().record(&HealingAction::ClampSize {
                requested: flags as usize,
                clamped: sanitized as usize,
            });
            sanitized
        } else {
            flags
        };
        (p, f)
    } else {
        (prot, flags)
    };

    let result = unsafe {
        syscall::sys_mmap(
            addr as *mut u8,
            length,
            actual_prot,
            actual_flags,
            fd,
            offset,
        )
    };

    match result {
        Ok(ptr) => {
            runtime_policy::observe(
                ApiFamily::VirtualMemory,
                decision.profile,
                runtime_policy::scaled_cost(40, length),
                false,
            );
            ptr as *mut c_void
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(
                ApiFamily::VirtualMemory,
                decision.profile,
                runtime_policy::scaled_cost(40, length),
                true,
            );
            mmap::MAP_FAILED as *mut c_void
        }
    }
}

// ---------------------------------------------------------------------------
// munmap
// ---------------------------------------------------------------------------

/// POSIX `munmap` — unmap a region of memory.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn munmap(addr: *mut c_void, length: usize) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::VirtualMemory,
        addr as usize,
        length,
        true,
        false,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 20, true);
        unsafe { set_abi_errno(libc::EPERM) };
        return -1;
    }

    let rc = match unsafe { syscall::sys_munmap(addr as *mut u8, length) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 20, rc < 0);
    rc
}

// ---------------------------------------------------------------------------
// mprotect
// ---------------------------------------------------------------------------

/// POSIX `mprotect` — set protection on a region of memory.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mprotect(addr: *mut c_void, length: usize, prot: c_int) -> c_int {
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::VirtualMemory,
        addr as usize,
        length,
        true,
        false,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 20, true);
        unsafe { set_abi_errno(libc::EPERM) };
        return -1;
    }

    let actual_prot = if mode.heals_enabled() && !mmap::valid_prot(prot) {
        let sanitized = mmap::PROT_NONE;
        global_healing_policy().record(&HealingAction::ClampSize {
            requested: prot as usize,
            clamped: sanitized as usize,
        });
        sanitized
    } else {
        prot
    };

    let rc = match unsafe { syscall::sys_mprotect(addr as *mut u8, length, actual_prot) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 20, rc < 0);
    rc
}

// ---------------------------------------------------------------------------
// msync
// ---------------------------------------------------------------------------

/// POSIX `msync` — synchronize a file with a memory map.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn msync(addr: *mut c_void, length: usize, flags: c_int) -> c_int {
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::VirtualMemory,
        addr as usize,
        length,
        true,
        false,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 25, true);
        unsafe { set_abi_errno(libc::EPERM) };
        return -1;
    }

    let actual_flags = if mode.heals_enabled() && !mmap::valid_msync_flags(flags) {
        let sanitized = mmap::sanitize_msync_flags(flags);
        global_healing_policy().record(&HealingAction::ClampSize {
            requested: flags as usize,
            clamped: sanitized as usize,
        });
        sanitized
    } else {
        flags
    };

    let rc = match unsafe { syscall::sys_msync(addr as *mut u8, length, actual_flags) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 25, rc < 0);
    rc
}

// ---------------------------------------------------------------------------
// madvise
// ---------------------------------------------------------------------------

/// POSIX `madvise` — advise the kernel about memory usage patterns.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn madvise(addr: *mut c_void, length: usize, advice: c_int) -> c_int {
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::VirtualMemory,
        addr as usize,
        length,
        false,
        false,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 15, true);
        unsafe { set_abi_errno(libc::EPERM) };
        return -1;
    }

    let actual_advice = if mode.heals_enabled() && !mmap::valid_madvise(advice) {
        let sanitized = mmap::sanitize_madvise(advice);
        global_healing_policy().record(&HealingAction::ClampSize {
            requested: advice as usize,
            clamped: sanitized as usize,
        });
        sanitized
    } else {
        advice
    };

    let rc = match unsafe { syscall::sys_madvise(addr as *mut u8, length, actual_advice) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 15, rc < 0);
    rc
}

// ---------------------------------------------------------------------------
// mlock / munlock / mlockall / munlockall
// ---------------------------------------------------------------------------

/// POSIX `mlock` — lock a range of memory.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mlock(addr: *const c_void, len: usize) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_mlock as c_long, addr, len) as c_int };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::ENOMEM);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// POSIX `munlock` — unlock a range of memory.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn munlock(addr: *const c_void, len: usize) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_munlock as c_long, addr, len) as c_int };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::ENOMEM);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// POSIX `mlockall` — lock all of the calling process's virtual memory.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mlockall(flags: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_mlockall as c_long, flags) as c_int };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::ENOMEM);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// POSIX `munlockall` — unlock all of the calling process's virtual memory.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn munlockall() -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_munlockall as c_long) as c_int };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::ENOMEM);
        unsafe { set_abi_errno(e) };
    }
    rc
}

// ---------------------------------------------------------------------------
// mremap — RawSyscall
// ---------------------------------------------------------------------------

/// Linux `mremap` — remap a virtual memory address.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mremap(
    old_address: *mut c_void,
    old_size: usize,
    new_size: usize,
    flags: c_int,
) -> *mut c_void {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::VirtualMemory,
        old_address as usize,
        new_size,
        true,
        true,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 15, true);
        unsafe { set_abi_errno(errno::ENOMEM) };
        return libc::MAP_FAILED;
    }

    let rc = unsafe {
        libc::syscall(libc::SYS_mremap as c_long, old_address, old_size, new_size, flags)
    };
    if rc == libc::MAP_FAILED as c_long {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::ENOMEM);
        unsafe { set_abi_errno(e) };
        runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 15, true);
        libc::MAP_FAILED
    } else {
        runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 15, false);
        rc as *mut c_void
    }
}
