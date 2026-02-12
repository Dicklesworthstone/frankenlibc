//! ABI layer for `<iconv.h>` phase-1 conversions.
//!
//! Supported encoding names:
//! - `UTF-8`
//! - `ISO-8859-1` / `LATIN1`
//! - `UTF-16LE`
//!
//! This module provides deterministic error semantics (`E2BIG`, `EILSEQ`, `EINVAL`)
//! and tracks descriptor validity to avoid invalid/double-close behavior.

use std::collections::HashSet;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::slice;
use std::sync::{Mutex, OnceLock};

use frankenlibc_core::errno;
use frankenlibc_core::iconv::{self, IconvDescriptor};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

const ICONV_ERROR_VALUE: usize = usize::MAX;

fn iconv_error_handle() -> *mut c_void {
    ICONV_ERROR_VALUE as *mut c_void
}

fn iconv_error_return() -> usize {
    ICONV_ERROR_VALUE
}

static ICONV_HANDLES: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();

fn handles() -> &'static Mutex<HashSet<usize>> {
    ICONV_HANDLES.get_or_init(|| Mutex::new(HashSet::new()))
}

fn register_handle(ptr: *mut c_void) {
    if let Ok(mut set) = handles().lock() {
        set.insert(ptr as usize);
    }
}

fn unregister_handle(ptr: *mut c_void) -> bool {
    handles()
        .lock()
        .map(|mut set| set.remove(&(ptr as usize)))
        .unwrap_or(false)
}

fn is_known_handle(ptr: *mut c_void) -> bool {
    handles()
        .lock()
        .map(|set| set.contains(&(ptr as usize)))
        .unwrap_or(false)
}

unsafe fn set_abi_errno(val: c_int) {
    // SAFETY: __errno_location returns a valid TLS pointer for this thread.
    let p = unsafe { super::errno_abi::__errno_location() };
    // SAFETY: pointer is valid for write per errno ABI contract.
    unsafe { *p = val };
}

unsafe fn apply_progress(
    inbuf: *mut *mut c_char,
    inbytesleft: *mut usize,
    outbuf: *mut *mut c_char,
    outbytesleft: *mut usize,
    in_consumed: usize,
    out_written: usize,
) {
    // SAFETY: callers validate pointer arguments before invoking this helper.
    let in_cur = unsafe { *inbuf };
    // SAFETY: callers validate pointer arguments before invoking this helper.
    let out_cur = unsafe { *outbuf };
    // SAFETY: callers validate pointer arguments before invoking this helper.
    let in_left = unsafe { *inbytesleft };
    // SAFETY: callers validate pointer arguments before invoking this helper.
    let out_left = unsafe { *outbytesleft };

    // SAFETY: conversion core guarantees consumed/written never exceed provided lengths.
    unsafe {
        *inbuf = in_cur.add(in_consumed);
        *inbytesleft = in_left - in_consumed;
        *outbuf = out_cur.add(out_written);
        *outbytesleft = out_left - out_written;
    }
}

/// `iconv_open(tocode, fromcode)` -> descriptor or `(iconv_t)-1` with errno.
#[unsafe(no_mangle)]
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

    // SAFETY: non-null pointers are treated as C strings by iconv contract.
    let to = unsafe { CStr::from_ptr(tocode) }.to_bytes();
    // SAFETY: non-null pointers are treated as C strings by iconv contract.
    let from = unsafe { CStr::from_ptr(fromcode) }.to_bytes();

    match iconv::iconv_open(to, from) {
        Some(desc) => {
            let raw = Box::into_raw(Box::new(desc)).cast::<c_void>();
            register_handle(raw);
            runtime_policy::observe(ApiFamily::Locale, decision.profile, 12, false);
            raw
        }
        None => {
            runtime_policy::observe(ApiFamily::Locale, decision.profile, 12, true);
            // SAFETY: sets thread-local errno.
            unsafe { set_abi_errno(errno::EINVAL) };
            iconv_error_handle()
        }
    }
}

/// `iconv(cd, inbuf, inbytesleft, outbuf, outbytesleft)` conversion entrypoint.
#[unsafe(no_mangle)]
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

    if cd.is_null() || cd == iconv_error_handle() || !is_known_handle(cd) {
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

    // POSIX reset path: if inbuf is null or *inbuf is null, reset shift state.
    // Phase-1 encodings are stateless, so this is a no-op success.
    if inbuf.is_null() || inbytesleft.is_null() {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 4, false);
        return 0;
    }
    // SAFETY: guarded by null check above.
    let in_ptr = unsafe { *inbuf };
    if in_ptr.is_null() {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 4, false);
        return 0;
    }

    if outbuf.is_null() || outbytesleft.is_null() {
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
    // SAFETY: guarded by null checks above.
    let out_ptr = unsafe { *outbuf };
    if out_ptr.is_null() {
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

    // SAFETY: pointers were validated for null; lengths come from caller contract.
    let in_left = unsafe { *inbytesleft };
    // SAFETY: pointers were validated for null; lengths come from caller contract.
    let out_left = unsafe { *outbytesleft };
    // SAFETY: slices are bounded by caller-provided remaining lengths.
    let input = unsafe { slice::from_raw_parts(in_ptr.cast::<u8>(), in_left) };
    // SAFETY: slices are bounded by caller-provided remaining lengths.
    let output = unsafe { slice::from_raw_parts_mut(out_ptr.cast::<u8>(), out_left) };
    // SAFETY: handle validity is checked via registry before cast.
    let descriptor = unsafe { &mut *cd.cast::<IconvDescriptor>() };

    match iconv::iconv(descriptor, input, output) {
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
            runtime_policy::observe(
                ApiFamily::Locale,
                decision.profile,
                runtime_policy::scaled_cost(10, in_left),
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
            // SAFETY: sets thread-local errno.
            unsafe { set_abi_errno(err.code) };
            runtime_policy::observe(
                ApiFamily::Locale,
                decision.profile,
                runtime_policy::scaled_cost(10, in_left),
                true,
            );
            iconv_error_return()
        }
    }
}

/// `iconv_close(cd)` -> `0` on success, `-1` with errno on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iconv_close(cd: *mut c_void) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Locale, cd as usize, 0, false, cd.is_null(), 0);
    if matches!(decision.action, MembraneAction::Deny) {
        // SAFETY: sets thread-local errno.
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, true);
        return -1;
    }

    if cd.is_null() || cd == iconv_error_handle() || !unregister_handle(cd) {
        // SAFETY: sets thread-local errno.
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, true);
        return -1;
    }

    // SAFETY: registry removal above guarantees unique ownership for this descriptor.
    let boxed = unsafe { Box::from_raw(cd.cast::<IconvDescriptor>()) };
    let rc = iconv::iconv_close(*boxed);
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
    fn iconv_open_rejects_unsupported_encoding() {
        // SAFETY: static C strings.
        unsafe {
            let cd = iconv_open(c_ptr(b"UTF-32\0"), c_ptr(b"UTF-8\0"));
            assert_eq!(cd, iconv_error_handle());
            assert_eq!(abi_errno(), errno::EINVAL);
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
}
