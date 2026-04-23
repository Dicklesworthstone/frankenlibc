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

use std::ffi::{c_int, c_void};

#[cfg(any(debug_assertions, test))]
use std::collections::HashMap;
#[cfg(any(debug_assertions, test))]
use std::sync::{Mutex, OnceLock};

#[cfg(any(debug_assertions, test))]
use crate::errno_abi::set_abi_errno;
#[cfg(any(debug_assertions, test))]
use crate::runtime_policy;
#[cfg(any(debug_assertions, test))]
use frankenlibc_core::errno;
#[cfg(any(debug_assertions, test))]
use frankenlibc_core::setjmp::{
    JmpBuf, Phase1JumpError, Phase1Mode, phase1_longjmp_restore, phase1_setjmp_capture,
};
#[cfg(any(debug_assertions, test))]
use frankenlibc_membrane::config::SafetyLevel;
#[cfg(any(debug_assertions, test))]
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

#[cfg(any(debug_assertions, test))]
#[derive(Debug, Clone)]
struct JumpRegistryEntry {
    env: JmpBuf,
    capture_mode: SafetyLevel,
    savemask: bool,
}

#[cfg(any(debug_assertions, test))]
fn registry() -> &'static Mutex<HashMap<usize, JumpRegistryEntry>> {
    static REGISTRY: OnceLock<Mutex<HashMap<usize, JumpRegistryEntry>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(any(debug_assertions, test))]
fn safety_to_phase1(mode: SafetyLevel) -> Phase1Mode {
    match mode {
        SafetyLevel::Hardened => Phase1Mode::Hardened,
        SafetyLevel::Strict | SafetyLevel::Off => Phase1Mode::Strict,
    }
}

#[cfg(any(debug_assertions, test))]
fn phase1_error_errno(err: Phase1JumpError) -> c_int {
    match err {
        Phase1JumpError::UninitializedContext | Phase1JumpError::ModeMismatch => errno::EINVAL,
        Phase1JumpError::ForeignContext => errno::EPERM,
        Phase1JumpError::CorruptedContext => errno::EFAULT,
    }
}

#[cfg(any(debug_assertions, test))]
fn capture_env(env_addr: usize, mode: SafetyLevel, savemask: bool) -> Result<c_int, c_int> {
    if env_addr == 0 {
        return Err(errno::EFAULT);
    }

    let mut jump_env = JmpBuf::default();
    let _capture = phase1_setjmp_capture(&mut jump_env, safety_to_phase1(mode));
    let entry = JumpRegistryEntry {
        env: jump_env.clone(),
        capture_mode: mode,
        savemask,
    };

    // Synchronize the captured metadata to the C caller's buffer.
    let bytes = jump_env.to_bytes();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), env_addr as *mut u8, bytes.len());
    }

    let mut guard = registry().lock().unwrap_or_else(|e| e.into_inner());
    guard.insert(env_addr, entry);
    Ok(0)
}

#[cfg(any(debug_assertions, test))]
fn restore_env(env_addr: usize, val: c_int, mode: SafetyLevel) -> Result<(i32, bool), c_int> {
    if env_addr == 0 {
        return Err(errno::EFAULT);
    }

    // Load the jump buffer from C memory to check for tampering or copying.
    let mut mem_bytes = [0u8; 128]; // JMPBUF_REGISTER_COUNT * 8
    unsafe {
        std::ptr::copy_nonoverlapping(env_addr as *const u8, mem_bytes.as_mut_ptr(), 128);
    }
    let entry = {
        let guard = registry().lock().unwrap_or_else(|e| e.into_inner());
        guard.get(&env_addr).cloned()
    }
    .ok_or(errno::EINVAL)?;

    // Core validation: the metadata in the C buffer must match our registry.
    // If they mismatch, the buffer was tampered with or we are at the wrong address.
    // We use a private helper or accessor in core to get this metadata safely.
    // (Note: env.context_id() is private in core, but we can compare to_bytes).
    if entry.env.to_bytes() != mem_bytes {
        return Err(errno::EFAULT);
    }

    if entry.capture_mode != mode {
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
#[cfg(any(debug_assertions, test))]
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

#[cfg(all(not(test), any(debug_assertions, test)))]
fn terminate_deferred_transfer(
    errno_val: c_int,
    _reason: &'static str,
    _normalized_value: i32,
    _mask_restored: bool,
) -> ! {
    // SAFETY: writes thread-local errno before explicit process termination.
    unsafe { set_abi_errno(errno_val) };
    std::process::abort()
}

#[cfg(any(debug_assertions, test))]
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

#[cfg(any(debug_assertions, test))]
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

// ===========================================================================
// Native x86_64 setjmp/longjmp via global_asm!
// ===========================================================================
//
// jmp_buf layout (our own, self-consistent under LD_PRELOAD):
//   [0]:  rbx         (8 bytes)
//   [8]:  rbp         (8 bytes)
//   [16]: r12         (8 bytes)
//   [24]: r13         (8 bytes)
//   [32]: r14         (8 bytes)
//   [40]: r15         (8 bytes)
//   [48]: rsp         (8 bytes, caller's stack pointer)
//   [56]: rip         (8 bytes, return address)
//   [64]: savemask    (4 bytes, int flag)
//   [72]: saved_mask  (128 bytes, __sigset_t for signal mask)
//
// Total: 200 bytes — matches glibc's sizeof(sigjmp_buf) on x86_64.
//
// Under LD_PRELOAD, both setjmp and longjmp are our implementations,
// so the jmp_buf layout only needs to be self-consistent.

#[cfg(not(debug_assertions))]
core::arch::global_asm!(
    // __sigsetjmp(env: *mut c_void, savemask: c_int) -> c_int
    // rdi = env, esi = savemask
    ".global __sigsetjmp",
    ".global sigsetjmp",
    ".global setjmp",
    ".global _setjmp",
    ".type __sigsetjmp, @function",
    ".type sigsetjmp, @function",
    ".type setjmp, @function",
    ".type _setjmp, @function",
    // setjmp = __sigsetjmp(env, 1)
    "setjmp:",
    "  mov esi, 1",
    "  jmp __sigsetjmp",
    // _setjmp = __sigsetjmp(env, 0)
    "_setjmp:",
    "  xor esi, esi",
    "  jmp __sigsetjmp",
    // sigsetjmp = __sigsetjmp
    "sigsetjmp:",
    "__sigsetjmp:",
    // Save callee-saved registers
    "  mov [rdi + 0],  rbx",
    "  mov [rdi + 8],  rbp",
    "  mov [rdi + 16], r12",
    "  mov [rdi + 24], r13",
    "  mov [rdi + 32], r14",
    "  mov [rdi + 40], r15",
    // Save caller's rsp (rsp currently points at return address)
    "  lea rax, [rsp + 8]",
    "  mov [rdi + 48], rax",
    // Save return address
    "  mov rax, [rsp]",
    "  mov [rdi + 56], rax",
    // Save savemask flag
    "  mov [rdi + 64], esi",
    // If savemask == 0, skip signal mask save
    "  test esi, esi",
    "  jz 2f",
    // Save signal mask: rt_sigprocmask(SIG_BLOCK=0, NULL, &env[72], 8)
    "  push rdi",
    "  lea rdx, [rdi + 72]", // old mask output
    "  xor edi, edi",        // how = SIG_BLOCK (just query)
    "  xor esi, esi",        // new = NULL
    "  mov r10d, 8",         // sigsetsize
    "  mov eax, 14",         // SYS_rt_sigprocmask
    "  syscall",
    "  pop rdi",
    "2:",
    // Return 0 (direct call from setjmp always returns 0)
    "  xor eax, eax",
    "  ret",
    // longjmp(env: *mut c_void, val: c_int) -> !
    // rdi = env, esi = val
    ".global longjmp",
    ".global _longjmp",
    ".global siglongjmp",
    ".type longjmp, @function",
    ".type _longjmp, @function",
    ".type siglongjmp, @function",
    // All variants share the same implementation
    "siglongjmp:",
    "_longjmp:",
    "longjmp:",
    // Normalize return value: if val==0, return 1
    "  mov eax, esi",
    "  test eax, eax",
    "  jnz 3f",
    "  mov eax, 1",
    "3:",
    // Save return value and env pointer in caller-saved regs
    "  mov r8d, eax", // return value
    "  mov r9, rdi",  // env pointer
    // Check savemask flag
    "  mov ecx, [rdi + 64]",
    "  test ecx, ecx",
    "  jz 4f",
    // Restore signal mask: rt_sigprocmask(SIG_SETMASK=2, &env[72], NULL, 8)
    "  lea rsi, [rdi + 72]", // new mask = &env[72]
    "  mov edi, 2",          // how = SIG_SETMASK
    "  xor edx, edx",        // old = NULL
    "  mov r10d, 8",         // sigsetsize
    "  mov eax, 14",         // SYS_rt_sigprocmask
    "  syscall",
    "  mov rdi, r9", // restore env pointer
    "4:",
    // Restore callee-saved registers
    "  mov rbx, [rdi + 0]",
    "  mov rbp, [rdi + 8]",
    "  mov r12, [rdi + 16]",
    "  mov r13, [rdi + 24]",
    "  mov r14, [rdi + 32]",
    "  mov r15, [rdi + 40]",
    // Load return address before restoring rsp
    "  mov rcx, [rdi + 56]",
    // Restore stack pointer
    "  mov rsp, [rdi + 48]",
    // Set return value
    "  mov eax, r8d",
    // Jump to saved return address (appears as setjmp returning val)
    "  jmp rcx",
);

// Rust-callable wrappers that dispatch to either our global_asm symbols
// (release) or the deterministic phase-1 capture/restore path (debug/test).
// These are needed because other modules (e.g., glibc_internal_abi) call
// these as Rust functions.

#[cfg(not(debug_assertions))]
unsafe extern "C" {
    #[link_name = "setjmp"]
    fn asm_setjmp(env: *mut c_void) -> c_int;
    #[link_name = "_setjmp"]
    fn asm__setjmp(env: *mut c_void) -> c_int;
    #[link_name = "__sigsetjmp"]
    fn asm_sigsetjmp(env: *mut c_void, savemask: c_int) -> c_int;
    #[link_name = "longjmp"]
    fn asm_longjmp(env: *mut c_void, val: c_int) -> !;
    #[link_name = "_longjmp"]
    fn asm__longjmp(env: *mut c_void, val: c_int) -> !;
    #[link_name = "siglongjmp"]
    fn asm_siglongjmp(env: *mut c_void, val: c_int) -> !;
}

#[cfg(not(debug_assertions))]
pub unsafe extern "C" fn setjmp(env: *mut c_void) -> c_int {
    unsafe { asm_setjmp(env) }
}

#[cfg(not(debug_assertions))]
pub unsafe extern "C" fn _setjmp(env: *mut c_void) -> c_int {
    unsafe { asm__setjmp(env) }
}

#[cfg(not(debug_assertions))]
pub unsafe extern "C" fn sigsetjmp(env: *mut c_void, savemask: c_int) -> c_int {
    unsafe { asm_sigsetjmp(env, savemask) }
}

#[cfg(not(debug_assertions))]
pub unsafe extern "C" fn longjmp(env: *mut c_void, val: c_int) -> ! {
    unsafe { asm_longjmp(env, val) }
}

#[cfg(not(debug_assertions))]
pub unsafe extern "C" fn _longjmp(env: *mut c_void, val: c_int) -> ! {
    unsafe { asm__longjmp(env, val) }
}

#[cfg(not(debug_assertions))]
pub unsafe extern "C" fn siglongjmp(env: *mut c_void, val: c_int) -> ! {
    unsafe { asm_siglongjmp(env, val) }
}

// In debug/test builds, use the deterministic phase-1 path instead of
// host delegation so verification stays on FrankenLibC-owned behavior.
#[cfg(debug_assertions)]
pub unsafe extern "C" fn setjmp(env: *mut c_void) -> c_int {
    capture_entrypoint(env, false)
}

#[cfg(debug_assertions)]
pub unsafe extern "C" fn _setjmp(env: *mut c_void) -> c_int {
    capture_entrypoint(env, false)
}

#[cfg(debug_assertions)]
pub unsafe extern "C" fn sigsetjmp(env: *mut c_void, savemask: c_int) -> c_int {
    capture_entrypoint(env, savemask != 0)
}

#[cfg(debug_assertions)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn longjmp(env: *mut c_void, val: c_int) -> ! {
    restore_entrypoint(env, val, false)
}

#[cfg(debug_assertions)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _longjmp(env: *mut c_void, val: c_int) -> ! {
    restore_entrypoint(env, val, false)
}

#[cfg(debug_assertions)]
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
        let mut marker = [0u64; 16]; // 128 bytes
        let env_addr = marker.as_mut_ptr().cast::<c_void>() as usize;
        let _entry = RegistryEntryGuard { env_addr };
        let ret = capture_env(env_addr, SafetyLevel::Strict, false).unwrap();
        assert_eq!(ret, 0);

        let entry = lookup_entry(env_addr);
        assert_eq!(entry.capture_mode, SafetyLevel::Strict);
        assert!(!entry.savemask);
    }

    #[test]
    fn sigsetjmp_capture_tracks_mask_flag() {
        let mut marker = [0u64; 16];
        let env_addr = marker.as_mut_ptr().cast::<c_void>() as usize;
        let _entry = RegistryEntryGuard { env_addr };
        let ret = capture_env(env_addr, SafetyLevel::Hardened, true).unwrap();
        assert_eq!(ret, 0);

        let entry = lookup_entry(env_addr);
        assert_eq!(entry.capture_mode, SafetyLevel::Hardened);
        assert!(entry.savemask);
    }

    #[test]
    fn restore_env_normalizes_zero_to_one_and_reports_mask_restore() {
        let mut marker = [0u64; 16];
        let env_addr = marker.as_mut_ptr().cast::<c_void>() as usize;
        let _entry = RegistryEntryGuard { env_addr };
        capture_env(env_addr, SafetyLevel::Strict, true).unwrap();

        let (normalized_value, mask_restored) =
            restore_env(env_addr, 0, SafetyLevel::Strict).unwrap();
        assert_eq!(normalized_value, 1);
        assert!(mask_restored);
    }

    #[test]
    fn restore_env_missing_context_returns_einval() {
        let mut valid_but_missing = [0u64; 16];
        let missing_env = valid_but_missing.as_mut_ptr().cast::<c_void>() as usize;
        // Pre-clean: a stale entry at this address (from a prior test on
        // the same worker that allocated `marker` in the same stack
        // frame) would make this test fail because lookup would succeed
        // when it should not. (bd-7v4oe)
        {
            let mut guard = registry().lock().unwrap_or_else(|e| e.into_inner());
            guard.remove(&missing_env);
        }
        let err = restore_env(missing_env, 7, SafetyLevel::Strict).unwrap_err();
        assert_eq!(err, errno::EINVAL);
    }

    /// RAII guard that removes the test's registry entry on drop.
    ///
    /// Without this, sequential tests on the same parallel worker
    /// reuse the same stack addresses for `marker`, leaving the
    /// registry populated with the prior test's entry. Under
    /// `--test-threads=N` >= 4 a stale entry can cause restore_env
    /// to compare freshly-captured mem_bytes against the old
    /// entry's bytes (caching/ordering on the cross-thread mutex)
    /// and return EFAULT instead of triggering the deferred-ENOSYS
    /// panic the tests assert on. (bd-7v4oe)
    struct RegistryEntryGuard {
        env_addr: usize,
    }
    impl Drop for RegistryEntryGuard {
        fn drop(&mut self) {
            let mut guard = registry().lock().unwrap_or_else(|e| e.into_inner());
            guard.remove(&self.env_addr);
        }
    }

    #[test]
    fn longjmp_entrypoint_terminates_with_enosys_payload_in_tests() {
        let mut marker = [0u64; 16];
        let env_ptr = marker.as_mut_ptr().cast::<c_void>();
        let _entry = RegistryEntryGuard {
            env_addr: env_ptr as usize,
        };
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
        let mut marker = [0u64; 16];
        let env_ptr = marker.as_mut_ptr().cast::<c_void>();
        let _entry = RegistryEntryGuard {
            env_addr: env_ptr as usize,
        };
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
