//! ABI layer for selected `<stdio.h>` functions.
//!
//! Bootstrap scope:
//! - `putchar`
//! - `puts`
//! - `getchar`
//! - `fflush`

use std::ffi::{CStr, c_char, c_int};

use glibc_rs_membrane::heal::{HealingAction, global_healing_policy};
use glibc_rs_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::malloc_abi::known_remaining;
use crate::runtime_policy;
use crate::unistd_abi::{sys_read_fd, sys_write_fd};

fn repair_enabled(heals_enabled: bool, action: MembraneAction) -> bool {
    heals_enabled || matches!(action, MembraneAction::Repair(_))
}

unsafe fn scan_c_str_len(ptr: *const c_char, bound: Option<usize>) -> (usize, bool) {
    match bound {
        Some(limit) => {
            for i in 0..limit {
                // SAFETY: caller bounds reads through `limit`.
                if unsafe { *ptr.add(i) } == 0 {
                    return (i, true);
                }
            }
            (limit, false)
        }
        None => {
            // SAFETY: caller guarantees NUL-terminated C string in unbounded mode.
            let len = unsafe { CStr::from_ptr(ptr) }.to_bytes().len();
            (len, true)
        }
    }
}

/// POSIX `putchar`.
///
/// # Safety
///
/// C ABI entrypoint; no additional safety preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn putchar(c: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, 0, 1, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return libc::EOF;
    }

    let byte = c as u8;
    // SAFETY: writing one byte from stack-local storage.
    let rc = unsafe { sys_write_fd(libc::STDOUT_FILENO, (&byte as *const u8).cast(), 1) };
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, rc != 1);
    if rc == 1 { byte as c_int } else { libc::EOF }
}

/// POSIX `puts`.
///
/// # Safety
///
/// `s` must point to a readable C string, unless null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn puts(s: *const c_char) -> c_int {
    if s.is_null() {
        return libc::EOF;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdio,
        s as usize,
        0,
        false,
        known_remaining(s as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return libc::EOF;
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let bound = if repair {
        known_remaining(s as usize)
    } else {
        None
    };
    // SAFETY: strict uses standard C-string contract; hardened bounds by allocator metadata.
    let (len, terminated) = unsafe { scan_c_str_len(s, bound) };
    if !terminated && repair {
        global_healing_policy().record(&HealingAction::TruncateWithNull {
            requested: bound.unwrap_or(len).saturating_add(1),
            truncated: len,
        });
    }

    // SAFETY: string slice pointer and length validated above.
    let rc_body = unsafe { sys_write_fd(libc::STDOUT_FILENO, s.cast(), len) };
    let newline = [b'\n'];
    // SAFETY: writing one-byte newline from local buffer.
    let rc_nl = unsafe { sys_write_fd(libc::STDOUT_FILENO, newline.as_ptr().cast(), 1) };
    let adverse = rc_body < 0 || rc_nl != 1 || (!terminated && repair);
    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(10, len.saturating_add(1)),
        adverse,
    );

    if rc_body < 0 || rc_nl != 1 {
        libc::EOF
    } else {
        0
    }
}

/// POSIX `getchar`.
///
/// # Safety
///
/// C ABI entrypoint; no additional safety preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getchar() -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, 0, 1, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return libc::EOF;
    }

    let mut byte = [0_u8; 1];
    // SAFETY: reading one byte into stack-local buffer.
    let rc = unsafe { sys_read_fd(libc::STDIN_FILENO, byte.as_mut_ptr().cast(), 1) };
    let adverse = rc != 1;
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, adverse);
    if adverse { libc::EOF } else { byte[0] as c_int }
}

/// POSIX `fflush`.
///
/// # Safety
///
/// `stream` may be null or a valid `FILE*` from the active process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fflush(stream: *mut libc::FILE) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Stdio, stream as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 4, true);
        return libc::EOF;
    }

    // Bootstrap behavior: no internal buffering yet, so flushing is a no-op.
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 4, false);
    0
}
