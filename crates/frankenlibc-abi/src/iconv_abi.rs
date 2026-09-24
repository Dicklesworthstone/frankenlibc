//! ABI layer for `<iconv.h>` phase-1 conversions.
//!
//! Supported encoding names:
//! - `UTF-8`
//! - `ISO-8859-1` / `LATIN1`
//! - `UTF-16LE`
//! - `UTF-32`
//!
//! This module provides deterministic error semantics (`E2BIG`, `EILSEQ`, `EINVAL`)
//! and tracks descriptor validity to avoid invalid/double-close behavior.

use std::ffi::{c_char, c_int, c_void};
use std::slice;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use frankenlibc_core::errno;
use frankenlibc_core::iconv::{self, IconvDescriptor};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::malloc_abi::known_remaining;
use crate::runtime_policy;
use crate::util::{ArtifactHashMap, artifact_hash_map, scan_c_string};

/// Read a user-supplied C string pointer with a known-region bound so a
/// non-NUL-terminated argument cannot walk arbitrary process memory through
/// `CStr::from_ptr`. Returns `None` for null or unterminated input.
///
/// Mirrors the locale_abi defense (bd-z4k96): an attacker-controlled or
/// corrupted encoding-name pointer must not crash or leak memory across the
/// libc.so boundary.
#[inline]
unsafe fn read_bounded_cstr(ptr: *const c_char) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return None;
    }
    let (len, terminated) = unsafe { scan_c_string(ptr, known_remaining(ptr as usize)) };
    if !terminated {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr as *const u8, len) };
    Some(bytes.to_vec())
}

const ICONV_ERROR_VALUE: usize = usize::MAX;

fn iconv_error_handle() -> *mut c_void {
    ICONV_ERROR_VALUE as *mut c_void
}

fn iconv_error_return() -> usize {
    ICONV_ERROR_VALUE
}

/// Returns whether hardened mode must reject an iconv encoding pair before
/// descriptor creation.
///
/// ISO-2022-JP and UTF-7 are implemented for strict compatibility, but the
/// hardened phase-1 contract deliberately keeps their stateful decoder paths
/// out of the trusted conversion surface. Normalize exactly as core iconv does
/// so punctuation and case variants cannot bypass the policy.
#[must_use]
pub fn hardened_iconv_open_denied(tocode: &[u8], fromcode: &[u8]) -> bool {
    fn normalized_is_deferred(raw: &[u8]) -> bool {
        let normalized: Vec<u8> = raw
            .iter()
            .filter(|&&byte| !matches!(byte, b'-' | b'_' | b' ' | b'\t'))
            .map(|byte| byte.to_ascii_uppercase())
            .collect();
        matches!(normalized.as_slice(), b"ISO2022JP" | b"UTF7")
    }

    normalized_is_deferred(tocode) || normalized_is_deferred(fromcode)
}

type IconvHandle = Arc<Mutex<IconvDescriptor>>;

static ICONV_HANDLES: OnceLock<Mutex<ArtifactHashMap<usize, IconvHandle>>> = OnceLock::new();

fn handles() -> &'static Mutex<ArtifactHashMap<usize, IconvHandle>> {
    ICONV_HANDLES.get_or_init(|| Mutex::new(artifact_hash_map()))
}

fn lock_handles() -> MutexGuard<'static, ArtifactHashMap<usize, IconvHandle>> {
    handles()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

fn lock_descriptor(handle: &IconvHandle) -> MutexGuard<'_, IconvDescriptor> {
    handle.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// What an `iconv_t` points at: glibc's `struct __gconv_info` with one
/// step. Programs built against glibc peek into it; iconv(1) (glibc >= 2.41)
/// decides its `-c` exit status from `__data[i].__flags` bit 30
/// ("encountered illegal input"), which is set when an //IGNORE conversion
/// skips input. fl keeps its descriptor in the registry keyed by this block's
/// address.
#[repr(C)]
struct GconvInfoShim {
    nsteps: usize,
    steps: *const GconvStepShim,
    data: [GconvStepDataShim; 1],
}

/// glibc's `struct __gconv_step_data` (48 bytes).
#[repr(C)]
struct GconvStepDataShim {
    outbuf: *mut u8,
    outbufend: *mut u8,
    flags: c_int,
    invocation_counter: c_int,
    internal_use: c_int,
    statep: *mut c_void,
    state: [u8; 8],
}

/// glibc's `struct __gconv_step`, all fields empty.
#[repr(C)]
struct GconvStepShim {
    fields: [usize; 13],
}

#[repr(transparent)]
struct SyncStep(GconvStepShim);
// SAFETY: immutable, zero-filled.
unsafe impl Sync for SyncStep {}
static EMPTY_GCONV_STEP: SyncStep = SyncStep(GconvStepShim { fields: [0; 13] });

/// `__GCONV_IS_LAST`, set on the final step like glibc.
const GCONV_IS_LAST: c_int = 0x0001;
/// glibc's internal "encountered illegal input" step flag (bit 30).
const GCONV_ENCOUNTERED_ILLEGAL_INPUT: c_int = 0x4000_0000;

fn register_handle(descriptor: IconvDescriptor) -> *mut c_void {
    let shim = Box::new(GconvInfoShim {
        nsteps: 1,
        steps: &EMPTY_GCONV_STEP.0,
        data: [GconvStepDataShim {
            outbuf: std::ptr::null_mut(),
            outbufend: std::ptr::null_mut(),
            flags: GCONV_IS_LAST,
            invocation_counter: 0,
            internal_use: 0,
            statep: std::ptr::null_mut(),
            state: [0; 8],
        }],
    });
    let raw = Box::into_raw(shim).cast::<c_void>();
    lock_handles().insert(raw as usize, Arc::new(Mutex::new(descriptor)));
    raw
}

fn lookup_handle(ptr: *mut c_void) -> Option<IconvHandle> {
    lock_handles().get(&(ptr as usize)).cloned()
}

/// Mark the handle's step as having skipped illegal input.
///
/// SAFETY: `ptr` is a live handle from `register_handle`.
unsafe fn note_illegal_input(ptr: *mut c_void) {
    unsafe { (*ptr.cast::<GconvInfoShim>()).data[0].flags |= GCONV_ENCOUNTERED_ILLEGAL_INPUT };
}

/// SAFETY: callers only release a handle after removing its registry entry,
/// which proves the block is live and not yet released.
unsafe fn release_raw_handle(ptr: *mut c_void) {
    unsafe { drop(Box::from_raw(ptr.cast::<GconvInfoShim>())) };
}

unsafe fn apply_progress(
    inbuf: *mut *mut c_char,
    inbytesleft: *mut usize,
    outbuf: *mut *mut c_char,
    outbytesleft: *mut usize,
    in_consumed: usize,
    out_written: usize,
) {
    if !inbuf.is_null() && !inbytesleft.is_null() {
        let in_cur = unsafe { *inbuf };
        if !in_cur.is_null() {
            let in_left = unsafe { *inbytesleft };
            unsafe {
                *inbuf = in_cur.add(in_consumed);
                *inbytesleft = in_left.saturating_sub(in_consumed);
            }
        }
    }

    if !outbuf.is_null() && !outbytesleft.is_null() {
        let out_cur = unsafe { *outbuf };
        if !out_cur.is_null() {
            let out_left = unsafe { *outbytesleft };
            unsafe {
                *outbuf = out_cur.add(out_written);
                *outbytesleft = out_left.saturating_sub(out_written);
            }
        }
    }
}

/// Replace an empty charset name with `nl_langinfo(CODESET)`, keeping any
/// `//` suffix.
unsafe fn resolve_locale_charset(code: Vec<u8>) -> Vec<u8> {
    let name_len = code.windows(2).position(|w| w == b"//").unwrap_or(code.len());
    if name_len != 0 {
        return code;
    }
    let codeset = unsafe { crate::locale_abi::nl_langinfo(libc::CODESET) };
    let Some(mut name) = (unsafe { read_bounded_cstr(codeset) }) else {
        return code;
    };
    name.extend_from_slice(&code);
    name
}

/// `iconv_open(tocode, fromcode)` -> descriptor or `(iconv_t)-1` with errno.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iconv_open(tocode: *const c_char, fromcode: *const c_char) -> *mut c_void {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Locale,
        tocode as usize,
        0,
        false,
        tocode.is_null() || fromcode.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        // SAFETY: sets thread-local errno.
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 8, true);
        return iconv_error_handle();
    }

    if tocode.is_null() || fromcode.is_null() {
        // SAFETY: sets thread-local errno.
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 8, true);
        return iconv_error_handle();
    }

    // Bounded reads reject non-NUL-terminated pointers at the boundary
    // instead of walking memory through CStr::from_ptr. Same defense
    // class as bd-z4k96 for setlocale/textdomain/bindtextdomain/newlocale.
    let Some(to) = (unsafe { read_bounded_cstr(tocode) }) else {
        // SAFETY: sets thread-local errno.
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 8, true);
        return iconv_error_handle();
    };
    let Some(from) = (unsafe { read_bounded_cstr(fromcode) }) else {
        // SAFETY: sets thread-local errno.
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 8, true);
        return iconv_error_handle();
    };

    // An empty charset name (before any `//` suffix) means the current
    // locale's codeset, as in glibc; iconv(1) relies on it when -f or -t is
    // omitted.
    let to = unsafe { resolve_locale_charset(to) };
    let from = unsafe { resolve_locale_charset(from) };

    if frankenlibc_membrane::config::safety_level().heals_enabled()
        && hardened_iconv_open_denied(&to, &from)
    {
        // Hardened mode excludes these stateful decoder paths by contract.
        // SAFETY: sets thread-local errno.
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 12, true);
        return iconv_error_handle();
    }

    match iconv::iconv_open_detailed(&to, &from) {
        Ok((desc, _dispatch)) => {
            let raw = register_handle(desc);
            runtime_policy::observe(ApiFamily::Locale, decision.profile, 12, false);
            raw
        }
        Err(err) => {
            runtime_policy::observe(ApiFamily::Locale, decision.profile, 12, true);
            let errno_code = match err.policy {
                iconv::IconvFallbackPolicy::ExcludedCodecFamily => errno::EINVAL,
                iconv::IconvFallbackPolicy::UnsupportedCodec => errno::EINVAL,
            };
            // SAFETY: sets thread-local errno.
            unsafe { set_abi_errno(errno_code) };
            iconv_error_handle()
        }
    }
}

/// `iconv(cd, inbuf, inbytesleft, outbuf, outbytesleft)` conversion entrypoint.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iconv(
    cd: *mut c_void,
    inbuf: *mut *mut c_char,
    inbytesleft: *mut usize,
    outbuf: *mut *mut c_char,
    outbytesleft: *mut usize,
) -> usize {
    let requested = if inbytesleft.is_null() {
        0
    } else {
        // SAFETY: guarded by null check above.
        unsafe { *inbytesleft }
    };
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Locale,
        cd as usize,
        requested,
        true,
        cd.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        // SAFETY: sets thread-local errno.
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(
            ApiFamily::Locale,
            decision.profile,
            runtime_policy::scaled_cost(8, requested),
            true,
        );
        return iconv_error_return();
    }

    if cd.is_null() || cd == iconv_error_handle() {
        // SAFETY: sets thread-local errno.
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(
            ApiFamily::Locale,
            decision.profile,
            runtime_policy::scaled_cost(8, requested),
            true,
        );
        return iconv_error_return();
    }

    let Some(handle) = lookup_handle(cd) else {
        // SAFETY: sets thread-local errno.
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(
            ApiFamily::Locale,
            decision.profile,
            runtime_policy::scaled_cost(8, requested),
            true,
        );
        return iconv_error_return();
    };

    if !inbuf.is_null() {
        // SAFETY: guarded by the null check above.
        let in_ptr = unsafe { *inbuf };
        if !in_ptr.is_null() && inbytesleft.is_null() {
            // SAFETY: sets thread-local errno.
            unsafe { set_abi_errno(errno::EFAULT) };
            runtime_policy::observe(
                ApiFamily::Locale,
                decision.profile,
                runtime_policy::scaled_cost(8, requested),
                true,
            );
            return iconv_error_return();
        }
    }

    let input_opt = if inbuf.is_null() {
        None
    } else {
        // SAFETY: inbuf is non-null.
        let in_ptr = unsafe { *inbuf };
        if in_ptr.is_null() {
            None
        } else {
            // SAFETY: inbytesleft is validated for null in this path too.
            if inbytesleft.is_null() {
                None
            } else {
                let in_left = unsafe { *inbytesleft };
                Some(unsafe { slice::from_raw_parts(in_ptr.cast::<u8>(), in_left) })
            }
        }
    };

    // Reset mode permits omitting both output arguments entirely, but partially
    // specified output state is still a caller bug and must not be treated as a
    // successful no-op.
    if input_opt.is_none() {
        let output_args_mixed = outbuf.is_null() != outbytesleft.is_null();
        let output_ptr_missing = !outbuf.is_null() && unsafe { (*outbuf).is_null() };
        if output_args_mixed || output_ptr_missing {
            // SAFETY: sets thread-local errno.
            unsafe { set_abi_errno(errno::EFAULT) };
            runtime_policy::observe(
                ApiFamily::Locale,
                decision.profile,
                runtime_policy::scaled_cost(8, requested),
                true,
            );
            return iconv_error_return();
        }
    }

    // outbuf and outbytesleft can only be null if inbuf or *inbuf is null (reset path).
    // If both are null, we pass an empty slice to the core, which will skip BOM emission.
    let mut out_dummy = [0u8; 0];
    let output = if outbuf.is_null() || outbytesleft.is_null() {
        if input_opt.is_some() {
            // Mandatory for conversion path.
            // SAFETY: sets thread-local errno.
            unsafe { set_abi_errno(errno::EFAULT) };
            runtime_policy::observe(
                ApiFamily::Locale,
                decision.profile,
                runtime_policy::scaled_cost(8, requested),
                true,
            );
            return iconv_error_return();
        }
        &mut out_dummy[..]
    } else {
        // SAFETY: guarded by null checks above.
        let out_ptr = unsafe { *outbuf };
        if out_ptr.is_null() {
            if input_opt.is_some() {
                // SAFETY: sets thread-local errno.
                unsafe { set_abi_errno(errno::EFAULT) };
                runtime_policy::observe(
                    ApiFamily::Locale,
                    decision.profile,
                    runtime_policy::scaled_cost(8, requested),
                    true,
                );
                return iconv_error_return();
            }
            &mut out_dummy[..]
        } else {
            let out_left = unsafe { *outbytesleft };
            unsafe { slice::from_raw_parts_mut(out_ptr.cast::<u8>(), out_left) }
        }
    };

    let mut descriptor = lock_descriptor(&handle);
    match iconv::iconv(&mut descriptor, input_opt, output) {
        Ok(result) => {
            // SAFETY: progress fields are validated by core conversion logic.
            unsafe {
                apply_progress(
                    inbuf,
                    inbytesleft,
                    outbuf,
                    outbytesleft,
                    result.in_consumed,
                    result.out_written,
                )
            };
            let consumed = result.in_consumed;
            runtime_policy::observe(
                ApiFamily::Locale,
                decision.profile,
                runtime_policy::scaled_cost(10, consumed),
                false,
            );
            result.non_reversible
        }
        Err(err) => {
            if err.code == errno::EILSEQ && descriptor.ignores_errors() {
                // SAFETY: `cd` resolved to a live registry entry above.
                unsafe { note_illegal_input(cd) };
            }
            // SAFETY: progress fields are validated by core conversion logic.
            unsafe {
                apply_progress(
                    inbuf,
                    inbytesleft,
                    outbuf,
                    outbytesleft,
                    err.in_consumed,
                    err.out_written,
                )
            };
            let consumed = err.in_consumed;
            // SAFETY: sets thread-local errno.
            unsafe { set_abi_errno(err.code) };
            runtime_policy::observe(
                ApiFamily::Locale,
                decision.profile,
                runtime_policy::scaled_cost(10, consumed),
                true,
            );
            iconv_error_return()
        }
    }
}

/// `iconv_close(cd)` -> `0` on success, `-1` with errno on failure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iconv_close(cd: *mut c_void) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Locale, cd as usize, 0, false, cd.is_null(), 0);
    if matches!(decision.action, MembraneAction::Deny) {
        // SAFETY: sets thread-local errno.
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, true);
        return -1;
    }

    if cd.is_null() || cd == iconv_error_handle() {
        // SAFETY: sets thread-local errno.
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, true);
        return -1;
    }

    let handle = {
        let mut handles_guard = lock_handles();
        match handles_guard.remove(&(cd as usize)) {
            Some(handle) => handle,
            None => {
                // SAFETY: sets thread-local errno.
                unsafe { set_abi_errno(errno::EBADF) };
                runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, true);
                return -1;
            }
        }
    };

    // SAFETY: registry removal above proves the handle block is still live
    // and has not been released by an earlier close.
    unsafe { release_raw_handle(cd) };

    let rc = match Arc::try_unwrap(handle) {
        Ok(descriptor) => {
            let descriptor = descriptor
                .into_inner()
                .unwrap_or_else(|poison| poison.into_inner());
            iconv::iconv_close(descriptor)
        }
        Err(active_handle) => {
            drop(active_handle);
            0
        }
    };
    runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, rc != 0);
    rc
}

// BURN-DOWN MAP for the dead inline `#[cfg(test)] mod tests` that stood here
// until 2026-09-01 (bd-xh08pf). `lib.rs` declares this module
// `#[cfg(not(test))] pub mod iconv_abi;`, so that block compiled in neither
// build: its seven `#[test]` fns had never run. Where each went, and why:
//
//   iconv_open_and_close_roundtrip
//   iconv_open_accepts_utf32_encoding
//   iconv_converts_and_updates_pointers
//     RETIRED as exact duplicates. tests/iconv_abi_test.rs already contains
//     `iconv_open_utf8_to_utf16le`, `iconv_open_utf8_to_utf32` and
//     `iconv_ascii_to_utf16le`, each asserting the same handle/`in_left`/
//     `out_left`/byte conditions on the same codec pairs, with more input.
//
//   iconv_reports_e2big_with_partial_progress -> tests/iconv_abi_test.rs::
//     iconv_e2big_partial_progress, which covered every assertion EXCEPT the
//     errno one. That test now asserts `errno == E2BIG` as well, which is the
//     only thing the dead version added.
//
//   iconv_invalid_handle_sets_ebadf -> tests/iconv_abi_test.rs::
//     iconv_invalid_handle_returns_error, same story: it checked the return
//     value and not the errno, so the errno assertion moved into it. Not made
//     differential — glibc dereferences a bogus `iconv_t` and segfaults, so
//     EBADF here is an fl hardening contract with no host arm to compare to.
//
//   hardened_iconv_policy_rejects_deferred_codec_aliases_only ->
//     tests/iconv_abi_test.rs::hardened_iconv_policy_normalizes_deferred_codec_aliases
//     (`hardened_iconv_open_denied` is already `pub`, so this is a relocation)
//     plus ::hardened_mode_rejects_deferred_codec_alias_through_iconv_open,
//     which is the assertion the original was missing: the predicate being
//     correct proves nothing unless `iconv_open` actually consults it.
//
//   iconv_null_inbuf_emits_bom_for_utf32
//     RETIRED because it was WRONG, and finding that out is the whole return on
//     this burn-down. It asserted that a reset call emits the 4-byte UTF-32 BOM
//     immediately. Host glibc writes nothing on that call and defers the BOM to
//     the first conversion; fl also failed the reset with E2BIG when fewer than
//     4 bytes were free, which glibc never does. Core is fixed (see the reset
//     branch of `frankenlibc_core::iconv::iconv`) and the contract is now pinned
//     against a dlsym-resolved host arm in
//     tests/conformance_diff_iconv_reset_bom.rs, which also pins the other half
//     of the split: the stateful ISO-2022 destinations DO emit their
//     return-to-initial-state sequence on the same call.
