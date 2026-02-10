//! ABI layer for virtual memory management functions.
//!
//! Provides the POSIX virtual memory surface: mmap, munmap, mprotect,
//! msync, madvise. All functions route through the membrane RuntimeMathKernel
//! under `ApiFamily::VirtualMemory`.

use std::ffi::{c_int, c_void};
use std::os::raw::c_long;

use glibc_rs_core::mmap;
use glibc_rs_membrane::heal::{HealingAction, global_healing_policy};
use glibc_rs_membrane::runtime_math::{ApiFamily, MembraneAction};

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
#[unsafe(no_mangle)]
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

    let rc = unsafe {
        libc::syscall(
            libc::SYS_mmap as c_long,
            addr,
            length,
            actual_prot,
            actual_flags,
            fd,
            offset,
        ) as *mut c_void
    };

    let adverse = rc as usize == mmap::MAP_FAILED;
    if adverse {
        unsafe { set_abi_errno(libc::ENOMEM) };
    }
    runtime_policy::observe(
        ApiFamily::VirtualMemory,
        decision.profile,
        runtime_policy::scaled_cost(40, length),
        adverse,
    );
    rc
}

// ---------------------------------------------------------------------------
// munmap
// ---------------------------------------------------------------------------

/// POSIX `munmap` — unmap a region of memory.
#[unsafe(no_mangle)]
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

    let rc = unsafe { libc::syscall(libc::SYS_munmap as c_long, addr, length) as c_int };
    let adverse = rc < 0;
    if adverse {
        unsafe { set_abi_errno(libc::EINVAL) };
    }
    runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 20, adverse);
    rc
}

// ---------------------------------------------------------------------------
// mprotect
// ---------------------------------------------------------------------------

/// POSIX `mprotect` — set protection on a region of memory.
#[unsafe(no_mangle)]
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

    let rc =
        unsafe { libc::syscall(libc::SYS_mprotect as c_long, addr, length, actual_prot) as c_int };
    let adverse = rc < 0;
    if adverse {
        unsafe { set_abi_errno(libc::EINVAL) };
    }
    runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 20, adverse);
    rc
}

// ---------------------------------------------------------------------------
// msync
// ---------------------------------------------------------------------------

/// POSIX `msync` — synchronize a file with a memory map.
#[unsafe(no_mangle)]
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

    let rc =
        unsafe { libc::syscall(libc::SYS_msync as c_long, addr, length, actual_flags) as c_int };
    let adverse = rc < 0;
    if adverse {
        unsafe { set_abi_errno(libc::EINVAL) };
    }
    runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 25, adverse);
    rc
}

// ---------------------------------------------------------------------------
// madvise
// ---------------------------------------------------------------------------

/// POSIX `madvise` — advise the kernel about memory usage patterns.
#[unsafe(no_mangle)]
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

    let rc =
        unsafe { libc::syscall(libc::SYS_madvise as c_long, addr, length, actual_advice) as c_int };
    let adverse = rc < 0;
    if adverse {
        unsafe { set_abi_errno(libc::EINVAL) };
    }
    runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 15, adverse);
    rc
}
