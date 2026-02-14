//! Non-local jumps.
//!
//! Implements `<setjmp.h>` functions. NOTE: Real implementations of setjmp/longjmp
//! inherently require unsafe code to manipulate the call stack. These stubs
//! capture the interface; the actual implementation will need `unsafe` blocks
//! in the membrane/FFI layer.

use std::sync::atomic::{AtomicU64, Ordering};

const JMPBUF_REGISTER_COUNT: usize = 16;
const REG_MAGIC: usize = 0;
const REG_CONTEXT_ID: usize = 1;
const REG_GENERATION: usize = 2;
const REG_OWNER_THREAD: usize = 3;
const REG_MODE_TAG: usize = 4;
const REG_GUARD: usize = 5;
const PHASE1_MAGIC: u64 = 0x4652_414e_4b45_4e31; // "FRANKEN1"
const PHASE1_GUARD_SALT: u64 = 0x9E37_79B9_7F4A_7C15;
const MODE_TAG_STRICT: u64 = 0x5354_5249_4354_0001;
const MODE_TAG_HARDENED: u64 = 0x4841_5244_454E_0002;

static NEXT_CONTEXT_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_THREAD_ID: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static THREAD_SLOT_ID: u64 = NEXT_THREAD_ID.fetch_add(1, Ordering::Relaxed);
}

fn current_thread_id() -> u64 {
    THREAD_SLOT_ID.with(|id| *id)
}

fn mode_tag(mode: Phase1Mode) -> u64 {
    match mode {
        Phase1Mode::Strict => MODE_TAG_STRICT,
        Phase1Mode::Hardened => MODE_TAG_HARDENED,
    }
}

fn normalize_longjmp_value(value: i32) -> i32 {
    if value == 0 { 1 } else { value }
}

fn compute_guard(context_id: u64, generation: u64, owner_thread: u64, mode: Phase1Mode) -> u64 {
    context_id
        .rotate_left(17)
        .wrapping_add(generation.rotate_left(33))
        ^ owner_thread.rotate_left(7)
        ^ mode_tag(mode).rotate_left(11)
        ^ PHASE1_GUARD_SALT
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase1Mode {
    Strict,
    Hardened,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase1JumpError {
    UninitializedContext,
    ForeignContext,
    CorruptedContext,
    ModeMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase1Capture {
    pub context_id: u64,
    pub generation: u64,
    pub owner_thread: u64,
    pub mode: Phase1Mode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase1Restore {
    pub context_id: u64,
    pub generation: u64,
    pub owner_thread: u64,
    pub requested_value: i32,
    pub return_value: i32,
    pub mode: Phase1Mode,
}

/// Opaque jump buffer that stores the execution context.
#[derive(Debug, Clone, Default)]
pub struct JmpBuf {
    _registers: [u64; JMPBUF_REGISTER_COUNT],
}

impl JmpBuf {
    fn context_id(&self) -> u64 {
        self._registers[REG_CONTEXT_ID]
    }

    fn generation(&self) -> u64 {
        self._registers[REG_GENERATION]
    }

    fn owner_thread(&self) -> u64 {
        self._registers[REG_OWNER_THREAD]
    }

    fn mode_tag(&self) -> u64 {
        self._registers[REG_MODE_TAG]
    }

    fn guard(&self) -> u64 {
        self._registers[REG_GUARD]
    }

    fn is_initialized(&self) -> bool {
        self._registers[REG_MAGIC] == PHASE1_MAGIC
            && self.context_id() != 0
            && self.generation() != 0
            && self.owner_thread() != 0
    }

    fn write_phase1_metadata(
        &mut self,
        context_id: u64,
        generation: u64,
        owner_thread: u64,
        mode: Phase1Mode,
    ) {
        self._registers[REG_MAGIC] = PHASE1_MAGIC;
        self._registers[REG_CONTEXT_ID] = context_id;
        self._registers[REG_GENERATION] = generation;
        self._registers[REG_OWNER_THREAD] = owner_thread;
        self._registers[REG_MODE_TAG] = mode_tag(mode);
        self._registers[REG_GUARD] = compute_guard(context_id, generation, owner_thread, mode);
    }
}

fn validate_phase1_env(env: &JmpBuf, mode: Phase1Mode) -> Result<(), Phase1JumpError> {
    if !env.is_initialized() {
        return Err(Phase1JumpError::UninitializedContext);
    }

    if env.mode_tag() != mode_tag(mode) {
        return Err(Phase1JumpError::ModeMismatch);
    }

    let owner_thread = env.owner_thread();
    if owner_thread != current_thread_id() {
        return Err(Phase1JumpError::ForeignContext);
    }

    let expected_guard = compute_guard(env.context_id(), env.generation(), owner_thread, mode);
    if env.guard() != expected_guard {
        return Err(Phase1JumpError::CorruptedContext);
    }

    Ok(())
}

/// Phase-1 safe capture primitive for jump-buffer metadata.
///
/// This function does **not** perform true non-local stack capture. It records
/// deterministic context metadata and invariants in the jump buffer, which is
/// used by phase-1 guard checks until ABI-level non-local transfer is wired.
pub fn phase1_setjmp_capture(env: &mut JmpBuf, mode: Phase1Mode) -> Phase1Capture {
    let context_id = NEXT_CONTEXT_ID.fetch_add(1, Ordering::Relaxed);
    let generation = env.generation().wrapping_add(1).max(1);
    let owner_thread = current_thread_id();
    env.write_phase1_metadata(context_id, generation, owner_thread, mode);
    Phase1Capture {
        context_id,
        generation,
        owner_thread,
        mode,
    }
}

/// Phase-1 safe restore primitive for jump-buffer metadata.
///
/// Validates context invariants and computes the C-visible return value rule
/// (`longjmp(..., 0)` appears as `1` to the resumed `setjmp` frame).
pub fn phase1_longjmp_restore(
    env: &JmpBuf,
    value: i32,
    mode: Phase1Mode,
) -> Result<Phase1Restore, Phase1JumpError> {
    validate_phase1_env(env, mode)?;
    Ok(Phase1Restore {
        context_id: env.context_id(),
        generation: env.generation(),
        owner_thread: env.owner_thread(),
        requested_value: value,
        return_value: normalize_longjmp_value(value),
        mode,
    })
}

/// Saves the current execution context into `env`.
///
/// Equivalent to C `setjmp`. Returns 0 when called directly.
/// When restored via [`longjmp`], returns the value passed to `longjmp`.
///
/// NOTE: This will need unsafe implementation for actual stack manipulation.
pub fn setjmp(_env: &mut JmpBuf) -> i32 {
    todo!("POSIX setjmp: implementation pending (requires unsafe for real impl)")
}

/// Restores the execution context saved in `env`.
///
/// Equivalent to C `longjmp`. `val` is the value that `setjmp` will appear
/// to return (if `val` is 0, `setjmp` returns 1 instead).
///
/// NOTE: This will need unsafe implementation for actual stack manipulation.
pub fn longjmp(_env: &JmpBuf, _val: i32) -> ! {
    todo!("POSIX longjmp: implementation pending (requires unsafe for real impl)")
}

#[cfg(test)]
fn debug_corrupt_guard_for_tests(env: &mut JmpBuf) {
    env._registers[REG_GUARD] ^= 0xA5A5_A5A5_A5A5_A5A5;
}

#[cfg(test)]
mod tests {
    use super::*;
    const SETJMP_TEST_SEED: i32 = 0x1FF3;

    fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
        if let Some(msg) = payload.downcast_ref::<String>() {
            return msg.clone();
        }
        if let Some(msg) = payload.downcast_ref::<&'static str>() {
            return (*msg).to_string();
        }
        "<non-string panic payload>".to_string()
    }

    fn assert_placeholder_contract_panic(
        subsystem: &str,
        clause: &str,
        evidence_path: &str,
        expected_fragment: &str,
        result: std::thread::Result<()>,
    ) {
        let context = format!("[{subsystem}] {clause} ({evidence_path})");
        let payload = result.expect_err(&format!("{context}: expected panic"));
        let msg = panic_message(payload);
        assert!(
            msg.contains(expected_fragment),
            "{context}: panic message mismatch, got: {msg}"
        );
    }

    #[test]
    fn jmpbuf_layout_is_stable_for_placeholder_contract() {
        assert_eq!(
            std::mem::size_of::<JmpBuf>(),
            JMPBUF_REGISTER_COUNT * std::mem::size_of::<u64>()
        );
        assert_eq!(std::mem::align_of::<JmpBuf>(), std::mem::align_of::<u64>());
    }

    #[test]
    fn phase1_capture_and_restore_roundtrip_in_strict_mode() {
        let mut env = JmpBuf::default();
        let capture = phase1_setjmp_capture(&mut env, Phase1Mode::Strict);
        let restore = phase1_longjmp_restore(&env, 42, Phase1Mode::Strict).unwrap();
        assert_eq!(restore.context_id, capture.context_id);
        assert_eq!(restore.generation, capture.generation);
        assert_eq!(restore.owner_thread, capture.owner_thread);
        assert_eq!(restore.requested_value, 42);
        assert_eq!(restore.return_value, 42);
    }

    #[test]
    fn phase1_longjmp_zero_normalizes_to_one() {
        let mut env = JmpBuf::default();
        phase1_setjmp_capture(&mut env, Phase1Mode::Strict);
        let restore = phase1_longjmp_restore(&env, 0, Phase1Mode::Strict).unwrap();
        assert_eq!(restore.requested_value, 0);
        assert_eq!(restore.return_value, 1);
    }

    #[test]
    fn phase1_nested_capture_assigns_distinct_context_ids() {
        let mut outer = JmpBuf::default();
        let mut inner = JmpBuf::default();
        let outer_capture = phase1_setjmp_capture(&mut outer, Phase1Mode::Strict);
        let inner_capture = phase1_setjmp_capture(&mut inner, Phase1Mode::Strict);
        assert_ne!(outer_capture.context_id, inner_capture.context_id);
        assert_eq!(outer_capture.generation, 1);
        assert_eq!(inner_capture.generation, 1);
    }

    #[test]
    fn phase1_hardened_rejects_corrupted_context() {
        let mut env = JmpBuf::default();
        phase1_setjmp_capture(&mut env, Phase1Mode::Hardened);
        debug_corrupt_guard_for_tests(&mut env);
        let err = phase1_longjmp_restore(&env, 9, Phase1Mode::Hardened).unwrap_err();
        assert_eq!(err, Phase1JumpError::CorruptedContext);
    }

    #[test]
    fn phase1_rejects_mode_mismatch_between_capture_and_restore() {
        let mut env = JmpBuf::default();
        phase1_setjmp_capture(&mut env, Phase1Mode::Strict);
        let err = phase1_longjmp_restore(&env, 3, Phase1Mode::Hardened).unwrap_err();
        assert_eq!(err, Phase1JumpError::ModeMismatch);
    }

    #[test]
    fn phase1_rejects_foreign_thread_restore_attempts() {
        let mut env = JmpBuf::default();
        phase1_setjmp_capture(&mut env, Phase1Mode::Strict);
        let env_for_thread = env.clone();
        let err = std::thread::spawn(move || {
            phase1_longjmp_restore(&env_for_thread, 1, Phase1Mode::Strict).unwrap_err()
        })
        .join()
        .unwrap();
        assert_eq!(err, Phase1JumpError::ForeignContext);
    }

    #[test]
    fn setjmp_placeholder_panics_with_explicit_contract_message() {
        let mut env = JmpBuf::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = setjmp(&mut env);
        }));
        assert_placeholder_contract_panic(
            "setjmp",
            "placeholder-must-explicitly-advertise-unsafe-boundary",
            "crates/frankenlibc-core/src/setjmp/mod.rs",
            "POSIX setjmp: implementation pending",
            result,
        );
    }

    #[test]
    fn longjmp_placeholder_panics_with_explicit_contract_message() {
        let env = JmpBuf::default();
        let result = std::panic::catch_unwind(|| {
            longjmp(&env, SETJMP_TEST_SEED);
        });
        assert_placeholder_contract_panic(
            "setjmp",
            "placeholder-must-explicitly-advertise-unsafe-boundary",
            "crates/frankenlibc-core/src/setjmp/mod.rs",
            "POSIX longjmp: implementation pending",
            result,
        );
    }

    #[test]
    fn longjmp_placeholder_panics_when_val_zero() {
        let env = JmpBuf::default();
        let result = std::panic::catch_unwind(|| {
            longjmp(&env, 0);
        });
        assert_placeholder_contract_panic(
            "setjmp",
            "longjmp-zero-remains-unimplemented-contract-placeholder",
            "crates/frankenlibc-core/src/setjmp/mod.rs",
            "POSIX longjmp: implementation pending",
            result,
        );
    }
}
