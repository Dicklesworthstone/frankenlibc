//! ABI layer for `<setjmp.h>`/`<signal.h>` non-local jump entrypoints.
//!
//! Phase-1 contract:
//! - Capture (`setjmp`, `_setjmp`, `sigsetjmp`) is wired through deterministic
//!   metadata capture in `frankenlibc-core`.
//! - Restore (`longjmp`, `_longjmp`, `siglongjmp`) validates invariants through
//!   the same metadata and then terminates explicitly because true stack
//!   transfer remains deferred to the unsafe backend stage.
//!
//! This keeps behavior explicit and auditable: there is no silent call-through
//! to host `setjmp` symbols and no silent fallback.

use std::collections::HashMap;
use std::ffi::{c_int, c_void};
use std::sync::{Mutex, OnceLock};

use frankenlibc_core::errno;
use frankenlibc_core::setjmp::{
    JmpBuf, Phase1JumpError, Phase1Mode, phase1_longjmp_restore, phase1_setjmp_capture,
};
use frankenlibc_membrane::config::SafetyLevel;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

#[derive(Debug, Clone)]
struct JumpRegistryEntry {
    env: JmpBuf,
    capture_mode: SafetyLevel,
    savemask: bool,
    context_id: u64,
    generation: u64,
}

fn registry() -> &'static Mutex<HashMap<usize, JumpRegistryEntry>> {
    static REGISTRY: OnceLock<Mutex<HashMap<usize, JumpRegistryEntry>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn safety_to_phase1(mode: SafetyLevel) -> Phase1Mode {
    match mode {
        SafetyLevel::Hardened => Phase1Mode::Hardened,
        SafetyLevel::Strict | SafetyLevel::Off => Phase1Mode::Strict,
    }
}

fn phase1_error_errno(err: Phase1JumpError) -> c_int {
    match err {
        Phase1JumpError::UninitializedContext | Phase1JumpError::ModeMismatch => errno::EINVAL,
        Phase1JumpError::ForeignContext => errno::EPERM,
        Phase1JumpError::CorruptedContext => errno::EFAULT,
    }
}

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { crate::errno_abi::__errno_location() };
    unsafe { *p = val };
}

fn capture_env(env_addr: usize, mode: SafetyLevel, savemask: bool) -> Result<c_int, c_int> {
    if env_addr == 0 {
        return Err(errno::EFAULT);
    }

    let mut jump_env = JmpBuf::default();
    let capture = phase1_setjmp_capture(&mut jump_env, safety_to_phase1(mode));
    let entry = JumpRegistryEntry {
        env: jump_env,
        capture_mode: mode,
        savemask,
        context_id: capture.context_id,
        generation: capture.generation,
    };

    let mut guard = registry().lock().unwrap_or_else(|e| e.into_inner());
    guard.insert(env_addr, entry);
    Ok(0)
}

fn restore_env(env_addr: usize, val: c_int, mode: SafetyLevel) -> Result<(i32, bool), c_int> {
    if env_addr == 0 {
        return Err(errno::EFAULT);
    }

    let entry = {
        let guard = registry().lock().unwrap_or_else(|e| e.into_inner());
        guard.get(&env_addr).cloned()
    }
    .ok_or(errno::EINVAL)?;

    if entry.capture_mode != mode {
        return Err(errno::EINVAL);
    }
    if entry.context_id == 0 || entry.generation == 0 {
        return Err(errno::EINVAL);
    }

    let phase_mode = safety_to_phase1(mode);
    let restore =
        phase1_longjmp_restore(&entry.env, val, phase_mode).map_err(phase1_error_errno)?;
    let mask_restored = entry.savemask;
    Ok((restore.return_value, mask_restored))
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeferredTransferPanic {
    errno: c_int,
    reason: &'static str,
    normalized_value: i32,
    mask_restored: bool,
}

#[cfg(test)]
fn terminate_deferred_transfer(
    errno_val: c_int,
    reason: &'static str,
    normalized_value: i32,
    mask_restored: bool,
) -> ! {
    // SAFETY: test-only path still writes errno through libc ABI slot.
    unsafe { set_abi_errno(errno_val) };
    std::panic::panic_any(DeferredTransferPanic {
        errno: errno_val,
        reason,
        normalized_value,
        mask_restored,
    });
}

#[cfg(not(test))]
fn terminate_deferred_transfer(
    errno_val: c_int,
    _reason: &'static str,
    _normalized_value: i32,
    _mask_restored: bool,
) -> ! {
    // SAFETY: writes thread-local errno before explicit process termination.
    unsafe { set_abi_errno(errno_val) };
    // SAFETY: explicit deterministic termination for deferred non-local transfer.
    unsafe { libc::abort() }
}

fn capture_entrypoint(env: *mut c_void, savemask: bool) -> c_int {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Signal, env as usize, 0, true, env.is_null(), 0);
    if matches!(decision.action, MembraneAction::Deny) {
        // SAFETY: writes thread-local errno for denied call.
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 20, true);
        return -1;
    }

    match capture_env(env as usize, mode, savemask) {
        Ok(ret) => {
            runtime_policy::observe(ApiFamily::Signal, decision.profile, 20, false);
            ret
        }
        Err(err) => {
            // SAFETY: writes thread-local errno for invalid pointer.
            unsafe { set_abi_errno(err) };
            runtime_policy::observe(ApiFamily::Signal, decision.profile, 20, true);
            -1
        }
    }
}

fn restore_entrypoint(env: *mut c_void, val: c_int, is_signal_variant: bool) -> ! {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Signal, env as usize, 0, true, env.is_null(), 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 20, true);
        terminate_deferred_transfer(errno::EPERM, "denied_by_runtime_policy", 0, false);
    }

    match restore_env(env as usize, val, mode) {
        Ok((normalized_value, mask_restored)) => {
            // Restore path is wired and validated, but true stack transfer is
            // still deferred to the backend implementation stage.
            runtime_policy::observe(ApiFamily::Signal, decision.profile, 20, true);
            let reason = if is_signal_variant {
                "deferred_siglongjmp_transfer_backend"
            } else {
                "deferred_longjmp_transfer_backend"
            };
            terminate_deferred_transfer(errno::ENOSYS, reason, normalized_value, mask_restored);
        }
        Err(err) => {
            runtime_policy::observe(ApiFamily::Signal, decision.profile, 20, true);
            terminate_deferred_transfer(err, "invalid_or_foreign_jump_context", 0, false);
        }
    }
}

/// C ABI `setjmp` entrypoint.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setjmp(env: *mut c_void) -> c_int {
    capture_entrypoint(env, false)
}

/// C ABI `_setjmp` entrypoint.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _setjmp(env: *mut c_void) -> c_int {
    capture_entrypoint(env, false)
}

/// C ABI `sigsetjmp` entrypoint.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigsetjmp(env: *mut c_void, savemask: c_int) -> c_int {
    capture_entrypoint(env, savemask != 0)
}

/// C ABI `longjmp` entrypoint.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn longjmp(env: *mut c_void, val: c_int) -> ! {
    restore_entrypoint(env, val, false)
}

/// C ABI `_longjmp` entrypoint.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _longjmp(env: *mut c_void, val: c_int) -> ! {
    restore_entrypoint(env, val, false)
}

/// C ABI `siglongjmp` entrypoint.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn siglongjmp(env: *mut c_void, val: c_int) -> ! {
    restore_entrypoint(env, val, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn panic_payload_to_str(payload: Box<dyn std::any::Any + Send>) -> String {
        if let Some(v) = payload.downcast_ref::<DeferredTransferPanic>() {
            return format!(
                "errno={} reason={} value={} mask_restored={}",
                v.errno, v.reason, v.normalized_value, v.mask_restored
            );
        }
        if let Some(v) = payload.downcast_ref::<String>() {
            return v.clone();
        }
        if let Some(v) = payload.downcast_ref::<&'static str>() {
            return (*v).to_string();
        }
        "<non-string panic payload>".to_string()
    }

    fn lookup_entry(env_addr: usize) -> JumpRegistryEntry {
        let guard = registry().lock().unwrap_or_else(|e| e.into_inner());
        guard.get(&env_addr).cloned().expect("entry should exist")
    }

    #[test]
    fn capture_env_records_registry_entry_and_context_metadata() {
        let mut marker = 7u64;
        let env_addr = (&mut marker as *mut u64).cast::<c_void>() as usize;
        let ret = capture_env(env_addr, SafetyLevel::Strict, false).unwrap();
        assert_eq!(ret, 0);

        let entry = lookup_entry(env_addr);
        assert_eq!(entry.capture_mode, SafetyLevel::Strict);
        assert!(!entry.savemask);
        assert!(entry.context_id > 0);
        assert!(entry.generation > 0);
    }

    #[test]
    fn sigsetjmp_capture_tracks_mask_flag() {
        let mut marker = 9u64;
        let env_addr = (&mut marker as *mut u64).cast::<c_void>() as usize;
        let ret = capture_env(env_addr, SafetyLevel::Hardened, true).unwrap();
        assert_eq!(ret, 0);

        let entry = lookup_entry(env_addr);
        assert_eq!(entry.capture_mode, SafetyLevel::Hardened);
        assert!(entry.savemask);
    }

    #[test]
    fn restore_env_normalizes_zero_to_one_and_reports_mask_restore() {
        let mut marker = 11u64;
        let env_addr = (&mut marker as *mut u64).cast::<c_void>() as usize;
        capture_env(env_addr, SafetyLevel::Strict, true).unwrap();

        let (normalized_value, mask_restored) =
            restore_env(env_addr, 0, SafetyLevel::Strict).unwrap();
        assert_eq!(normalized_value, 1);
        assert!(mask_restored);
    }

    #[test]
    fn restore_env_missing_context_returns_einval() {
        let missing_env = 0xDEADBEEFu64 as usize;
        let err = restore_env(missing_env, 7, SafetyLevel::Strict).unwrap_err();
        assert_eq!(err, errno::EINVAL);
    }

    #[test]
    fn longjmp_entrypoint_terminates_with_enosys_payload_in_tests() {
        let mut marker = 13u64;
        let env_ptr = (&mut marker as *mut u64).cast::<c_void>();
        capture_entrypoint(env_ptr, false);

        let result = std::panic::catch_unwind(|| {
            restore_entrypoint(env_ptr, 0, false);
        });
        let payload = result.expect_err("longjmp should terminate deferred path");
        let msg = panic_payload_to_str(payload);
        assert!(
            msg.contains("errno=38"),
            "expected ENOSYS payload, got {msg}"
        );
        assert!(
            msg.contains("value=1"),
            "expected normalized value payload, got {msg}"
        );
        assert!(
            msg.contains("deferred_longjmp_transfer_backend"),
            "expected backend-deferred reason, got {msg}"
        );
    }

    #[test]
    fn siglongjmp_entrypoint_terminates_with_mask_restore_metadata_in_tests() {
        let mut marker = 17u64;
        let env_ptr = (&mut marker as *mut u64).cast::<c_void>();
        capture_entrypoint(env_ptr, true);

        let result = std::panic::catch_unwind(|| {
            restore_entrypoint(env_ptr, 5, true);
        });
        let payload = result.expect_err("siglongjmp should terminate deferred path");
        let msg = panic_payload_to_str(payload);
        assert!(
            msg.contains("errno=38"),
            "expected ENOSYS payload, got {msg}"
        );
        assert!(
            msg.contains("mask_restored=true"),
            "expected mask restore metadata, got {msg}"
        );
        assert!(
            msg.contains("deferred_siglongjmp_transfer_backend"),
            "expected siglongjmp deferred reason, got {msg}"
        );
    }
}
