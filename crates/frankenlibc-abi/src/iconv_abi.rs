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

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void};
use std::slice;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use frankenlibc_core::errno;
use frankenlibc_core::iconv::{self, IconvDescriptor};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::malloc_abi::known_remaining;
use crate::runtime_policy;
use crate::util::scan_c_string;

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

type IconvHandle = Arc<Mutex<IconvDescriptor>>;

static ICONV_HANDLES: OnceLock<Mutex<HashMap<usize, IconvHandle>>> = OnceLock::new();

fn handles() -> &'static Mutex<HashMap<usize, IconvHandle>> {
    ICONV_HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_handles() -> MutexGuard<'static, HashMap<usize, IconvHandle>> {
    handles()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

fn lock_descriptor(handle: &IconvHandle) -> MutexGuard<'_, IconvDescriptor> {
    handle.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn register_handle(descriptor: IconvDescriptor) -> *mut c_void {
    let handle = Arc::new(Mutex::new(descriptor));
    let raw = Arc::into_raw(Arc::clone(&handle)) as *mut c_void;
    lock_handles().insert(raw as usize, handle);
    raw
}

fn lookup_handle(ptr: *mut c_void) -> Option<IconvHandle> {
    lock_handles().get(&(ptr as usize)).cloned()
}

unsafe fn release_raw_handle(ptr: *mut c_void) {
    // SAFETY: callers only release raw handles after removing a matching entry
    // from the registry, which proves the raw Arc strong reference is live and
    // has not been consumed by a prior close.
    unsafe { drop(Arc::from_raw(ptr.cast::<Mutex<IconvDescriptor>>())) };
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

    // SAFETY: registry removal above proves the raw Arc strong reference is
    // still live and has not been consumed by an earlier close.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn c_ptr(bytes: &'static [u8]) -> *const c_char {
        bytes.as_ptr().cast::<c_char>()
    }

    unsafe fn abi_errno() -> i32 {
        // SAFETY: errno ABI is always available in this crate.
        unsafe { *crate::errno_abi::__errno_location() }
    }

    #[test]
    fn iconv_open_and_close_roundtrip() {
        // SAFETY: static C strings and valid descriptor lifecycle.
        unsafe {
            let cd = iconv_open(c_ptr(b"UTF-16LE\0"), c_ptr(b"UTF-8\0"));
            assert!(!cd.is_null());
            assert_ne!(cd, iconv_error_handle());
            assert_eq!(iconv_close(cd), 0);
        }
    }

    #[test]
    fn iconv_open_accepts_utf32_encoding() {
        // SAFETY: static C strings.
        unsafe {
            let cd = iconv_open(c_ptr(b"UTF-32\0"), c_ptr(b"UTF-8\0"));
            assert!(!cd.is_null());
            assert_ne!(cd, iconv_error_handle());
            assert_eq!(iconv_close(cd), 0);
        }
    }

    #[test]
    fn iconv_converts_and_updates_pointers() {
        // SAFETY: all pointers are derived from valid local buffers.
        unsafe {
            let cd = iconv_open(c_ptr(b"UTF-16LE\0"), c_ptr(b"UTF-8\0"));
            assert_ne!(cd, iconv_error_handle());

            let mut input = b"AB".to_vec();
            let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
            let mut in_left = input.len();

            let mut output = [0u8; 8];
            let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
            let mut out_left = output.len();

            let rc = iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left);
            assert_eq!(rc, 0);
            assert_eq!(in_left, 0);
            assert_eq!(out_left, 4);
            assert_eq!(&output[..4], &[0x41, 0x00, 0x42, 0x00]);

            assert_eq!(iconv_close(cd), 0);
        }
    }

    #[test]
    fn iconv_reports_e2big_with_partial_progress() {
        // SAFETY: all pointers are derived from valid local buffers.
        unsafe {
            let cd = iconv_open(c_ptr(b"UTF-16LE\0"), c_ptr(b"UTF-8\0"));
            assert_ne!(cd, iconv_error_handle());

            let mut input = b"AB".to_vec();
            let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
            let mut in_left = input.len();

            let mut output = [0u8; 2];
            let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
            let mut out_left = output.len();

            let rc = iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left);
            assert_eq!(rc, iconv_error_return());
            assert_eq!(abi_errno(), iconv::ICONV_E2BIG);
            assert_eq!(in_left, 1);
            assert_eq!(out_left, 0);
            assert_eq!(&output, &[0x41, 0x00]);

            assert_eq!(iconv_close(cd), 0);
        }
    }

    #[test]
    fn iconv_invalid_handle_sets_ebadf() {
        // SAFETY: function validates handle before dereference.
        unsafe {
            let mut input = b"A".to_vec();
            let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
            let mut in_left = input.len();
            let mut output = [0u8; 8];
            let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
            let mut out_left = output.len();

            let rc = iconv(
                0x1234usize as *mut c_void,
                &mut in_ptr,
                &mut in_left,
                &mut out_ptr,
                &mut out_left,
            );
            assert_eq!(rc, iconv_error_return());
            assert_eq!(abi_errno(), errno::EBADF);
        }
    }

    #[test]
    fn iconv_null_inbuf_emits_bom_for_utf32() {
        // SAFETY: valid buffers and descriptor lifecycle.
        unsafe {
            let cd = iconv_open(c_ptr(b"UTF-32\0"), c_ptr(b"UTF-8\0"));
            assert!(!cd.is_null());

            let mut output = [0u8; 16];
            let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
            let mut out_left = output.len();

            // Null inbuf pointer should trigger BOM emission for UTF-32
            let rc = iconv(
                cd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut out_ptr,
                &mut out_left,
            );
            assert_eq!(rc, 0);
            assert_eq!(out_left, 12); // 16 - 4
            assert_eq!(&output[..4], &[0xFF, 0xFE, 0x00, 0x00]);

            assert_eq!(iconv_close(cd), 0);
        }
    }
}
