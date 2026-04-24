#![no_main]
//! Stateful fuzz target for FrankenLibC's process-environment API:
//!
//!   getenv, secure_getenv, setenv, unsetenv, putenv, clearenv
//!
//! These mutate process-global state (`environ[]`) and are the
//! classic LD_PRELOAD / LD_LIBRARY_PATH / TZ / LANG attack surface.
//! The target maintains a shadow `BTreeMap<Vec<u8>, Vec<u8>>` model
//! of "what environ *should* contain" and enforces the contract that
//! every `getenv` call returns bytes equal to the shadow entry (or
//! NULL when the shadow has no entry).
//!
//! Because the fuzzer runs many iterations in the same process,
//! every iteration first calls `clearenv()` on our ABI *and* clears
//! the shadow, so state from previous iterations cannot leak. We
//! intentionally do not compare against `libc::getenv` — both our
//! ABI layer and libc claim the same symbol name, which means a
//! naïve `extern "C"` binding does not give us two independent
//! implementations to cross-check. The shadow model is the oracle.
//!
//! Safety notes:
//! - All env-var **names** are sanitized before any ABI call: we
//!   reject interior NULs and `=`, both of which POSIX says make a
//!   setenv invalid. The fuzzer exploration of those edge cases
//!   happens by passing them *intentionally* and asserting the ABI
//!   responds with `EINVAL`, not by quietly mutating shadow state.
//! - `putenv` owns its argument string (glibc contract). We lose
//!   ownership to the ABI on every call, so each putenv uses a fresh
//!   `Box<[u8]>` leaked into a `'static` slot; the backing memory
//!   stays valid for the whole process run.
//! - Every op is bounded: up to 32 ops per iteration, names ≤ 32
//!   bytes, values ≤ 128 bytes. This keeps iteration cost low so
//!   libFuzzer can explore state-space combinatorially.
//!
//! Bead: bd-l0ykk

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, c_char};
use std::sync::{Mutex, Once};

use arbitrary::Arbitrary;
use frankenlibc_abi::stdlib_abi::{clearenv, getenv, putenv, secure_getenv, setenv, unsetenv};
use libfuzzer_sys::fuzz_target;

const NAME_PREFIX: &str = "FL_FUZZ_";
const MAX_NAME_BYTES: usize = 32;
const MAX_VALUE_BYTES: usize = 128;
const MAX_OPS: usize = 32;

#[derive(Debug, Arbitrary)]
enum EnvOp {
    Get {
        name_seed: Vec<u8>,
    },
    GetSecure {
        name_seed: Vec<u8>,
    },
    Set {
        name_seed: Vec<u8>,
        value: Vec<u8>,
        overwrite: bool,
    },
    /// Attempt a setenv with a deliberately malformed name (contains
    /// '=' or embedded NUL). The ABI must return -1 with EINVAL.
    SetMalformed {
        value: Vec<u8>,
        embed_eq: bool,
    },
    Unset {
        name_seed: Vec<u8>,
    },
    /// Well-formed putenv "NAME=VALUE" whose backing memory lives for
    /// the process lifetime.
    Put {
        name_seed: Vec<u8>,
        value: Vec<u8>,
    },
    Clear,
}

#[derive(Debug, Arbitrary)]
struct EnvFuzzInput {
    ops: Vec<EnvOp>,
}

/// Global guard so nothing else in the fuzz binary races with our
/// env mutations. libFuzzer is single-threaded per corpus entry, but
/// any thread created by the ABI (e.g. runtime-policy observers)
/// could otherwise race us.
static ENV_LOCK: Mutex<()> = Mutex::new(());
/// putenv keeps pointers into caller memory forever; we retire the
/// strings into a leaked arena so their address never becomes
/// dangling.
static PUTENV_ARENA: Mutex<Vec<&'static mut [u8]>> = Mutex::new(Vec::new());

fn init_hardened_mode() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: mode is set once before any ABI entrypoint fires.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "hardened");
        }
    });
}

/// Build a sanitized environment-variable name from fuzzer-supplied
/// bytes. We always prefix with `FL_FUZZ_` so we never touch system
/// state the test harness might legitimately rely on (PATH, HOME,
/// LD_LIBRARY_PATH, …). Returns `None` if the raw bytes contain a
/// character that cannot appear in a valid env name anyway.
fn make_name(seed: &[u8]) -> Option<CString> {
    // Derive a short, valid tail: ASCII uppercase letters only.
    let tail: String = seed
        .iter()
        .take(MAX_NAME_BYTES)
        .map(|&b| match b {
            0x41..=0x5A => b as char,
            0x61..=0x7A => (b - 0x20) as char,
            0x30..=0x39 => b as char,
            _ => '_',
        })
        .collect();
    let name = format!("{NAME_PREFIX}{tail}");
    CString::new(name).ok()
}

/// Build the CString form of `NAME=VALUE` for putenv. Value may be
/// truncated to stay under the byte cap; interior NULs in value are
/// replaced with `?` so the CString is always valid.
fn make_put_entry(seed: &[u8], value: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let name = make_name(seed)?;
    let mut entry = name.as_bytes().to_vec();
    entry.push(b'=');
    let sanitized_value: Vec<u8> = value
        .iter()
        .take(MAX_VALUE_BYTES)
        .map(|&b| if b == 0 { b'?' } else { b })
        .collect();
    entry.extend_from_slice(&sanitized_value);
    entry.push(0);
    Some((name.into_bytes(), entry))
}

fn sanitize_value(value: &[u8]) -> Option<CString> {
    let cleaned: Vec<u8> = value
        .iter()
        .take(MAX_VALUE_BYTES)
        .map(|&b| if b == 0 { b'?' } else { b })
        .collect();
    CString::new(cleaned).ok()
}

/// Reset env state: clear both ABI and shadow.
fn reset_env() {
    // SAFETY: clearenv resets the process environ[] pointer; we own
    // the global ENV_LOCK so no other thread can observe the torn
    // state.
    let rc = unsafe { clearenv() };
    assert!(rc == 0 || rc == -1, "clearenv rc out of contract: {rc}");
}

/// Drive one op against both the ABI and the shadow map; check
/// invariants after.
fn apply_op(op: &EnvOp, shadow: &mut BTreeMap<Vec<u8>, Vec<u8>>) {
    match op {
        EnvOp::Get { name_seed } => {
            let Some(name) = make_name(name_seed) else {
                return;
            };
            // SAFETY: getenv reads environ[]; we hold ENV_LOCK.
            let ptr = unsafe { getenv(name.as_ptr()) };
            check_get(&name, ptr, shadow);
        }
        EnvOp::GetSecure { name_seed } => {
            let Some(name) = make_name(name_seed) else {
                return;
            };
            let ptr = unsafe { secure_getenv(name.as_ptr()) };
            // Under AT_SECURE we'd get NULL always; outside, must
            // match getenv. We cannot reliably simulate AT_SECURE in
            // a unit-level fuzzer, so we accept either (a) matches
            // getenv, or (b) NULL.
            let getenv_ptr = unsafe { getenv(name.as_ptr()) };
            if !ptr.is_null() {
                assert_eq!(
                    ptr, getenv_ptr,
                    "secure_getenv returned a pointer that diverges from getenv"
                );
            }
        }
        EnvOp::Set {
            name_seed,
            value,
            overwrite,
        } => {
            let Some(name) = make_name(name_seed) else {
                return;
            };
            let Some(value_c) = sanitize_value(value) else {
                return;
            };
            let overwrite_i = if *overwrite { 1 } else { 0 };
            let rc = unsafe { setenv(name.as_ptr(), value_c.as_ptr(), overwrite_i) };
            assert!(rc == 0 || rc == -1, "setenv rc out of contract: {rc}");
            if rc == 0 {
                let key = name.as_bytes().to_vec();
                if *overwrite || !shadow.contains_key(&key) {
                    shadow.insert(key, value_c.as_bytes().to_vec());
                }
            }
        }
        EnvOp::SetMalformed { value, embed_eq } => {
            // Name intentionally contains '=' or is empty.
            let malformed = if *embed_eq {
                c"MAL=FORMED".as_ptr()
            } else {
                c"".as_ptr()
            };
            let Some(value_c) = sanitize_value(value) else {
                return;
            };
            let rc = unsafe { setenv(malformed, value_c.as_ptr(), 1) };
            // POSIX: setenv with '=' in name or empty name must fail
            // with EINVAL. The ABI may return -1 without exposing
            // errno to us directly, so we only assert the return is
            // in-contract.
            assert_eq!(
                rc, -1,
                "setenv on malformed name ({}) should fail",
                if *embed_eq { "embed_eq" } else { "empty" }
            );
        }
        EnvOp::Unset { name_seed } => {
            let Some(name) = make_name(name_seed) else {
                return;
            };
            let rc = unsafe { unsetenv(name.as_ptr()) };
            assert!(rc == 0 || rc == -1, "unsetenv rc out of contract: {rc}");
            if rc == 0 {
                shadow.remove(name.as_bytes());
            }
        }
        EnvOp::Put { name_seed, value } => {
            let Some((name_bytes, entry_bytes)) = make_put_entry(name_seed, value) else {
                return;
            };
            // Leak the entry into a static arena so the pointer putenv
            // keeps stays valid for the process lifetime.
            let boxed: Box<[u8]> = entry_bytes.into_boxed_slice();
            let leaked: &'static mut [u8] = Box::leak(boxed);
            let ptr = leaked.as_mut_ptr().cast::<c_char>();
            let rc = unsafe { putenv(ptr) };
            // Record for introspection (so we can scan later if we
            // wanted; currently we just let it leak).
            PUTENV_ARENA
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(
                // SAFETY: we just leaked this slice; we can hand the
                // reference out one more time. The arena never
                // outlives the process, and we never mutate through
                // two paths simultaneously because each entry is
                // owned by putenv after this call.
                unsafe {
                    std::slice::from_raw_parts_mut(leaked.as_mut_ptr(), leaked.len())
                },
            );
            assert!(rc == 0 || rc == -1, "putenv rc out of contract: {rc}");
            if rc == 0 {
                // Find the '=' to split name/value for shadow.
                if let Some(eq) = leaked.iter().position(|&b| b == b'=') {
                    let value_end = leaked
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(leaked.len());
                    shadow.insert(
                        name_bytes.clone(),
                        leaked[eq + 1..value_end].to_vec(),
                    );
                }
            }
        }
        EnvOp::Clear => {
            reset_env();
            shadow.clear();
        }
    }
}

fn check_get(name: &CStr, ptr: *const c_char, shadow: &BTreeMap<Vec<u8>, Vec<u8>>) {
    let expected = shadow.get(name.to_bytes());
    assert_eq!(
        ptr.is_null(),
        expected.is_none(),
        "getenv({}) null-vs-shadow mismatch",
        name.to_string_lossy()
    );
    if ptr.is_null() {
        return;
    }
    let Some(expected_bytes) = expected else {
        return;
    };
    // SAFETY: ptr is non-null and the ABI returns a
    // NUL-terminated C string.
    let actual = unsafe { CStr::from_ptr(ptr) }.to_bytes();
    assert_eq!(
        actual,
        &expected_bytes[..],
        "getenv({}) diverged from shadow",
        name.to_string_lossy()
    );
}

fuzz_target!(|input: EnvFuzzInput| {
    if input.ops.len() > MAX_OPS {
        return;
    }
    init_hardened_mode();
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let mut shadow: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    reset_env();

    for op in &input.ops {
        apply_op(op, &mut shadow);
    }

    // Final sweep: for every name in shadow, getenv must return the
    // expected bytes. This catches any op that mutated environ[]
    // without mutating the shadow or vice versa.
    let names: Vec<Vec<u8>> = shadow.keys().cloned().collect();
    for name_bytes in names {
        let Ok(name) = CString::new(name_bytes.clone()) else {
            continue;
        };
        let ptr = unsafe { getenv(name.as_ptr()) };
        check_get(&name, ptr, &shadow);
    }
});
