//! ABI layer for `<dlfcn.h>` functions.
//!
//! Dynamic linker interface: `dlopen`, `dlsym`, `dlclose`, `dlerror`.
//! Delegates to system `libdl` via `libc`, with membrane validation
//! and flag checking via `frankenlibc_core::dlfcn`.

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_core::dlfcn as dlfcn_core;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

// ---------------------------------------------------------------------------
// Thread-local dlerror state
// ---------------------------------------------------------------------------

std::thread_local! {
    static DLERROR_MSG: std::cell::Cell<*const c_char> = const { std::cell::Cell::new(std::ptr::null()) };
}

/// Set the thread-local dlerror message.
fn set_dlerror(msg: &'static [u8]) {
    DLERROR_MSG.with(|cell| cell.set(msg.as_ptr() as *const c_char));
}

/// Clear the thread-local dlerror message.
fn clear_dlerror() {
    DLERROR_MSG.with(|cell| cell.set(std::ptr::null()));
}

// ---------------------------------------------------------------------------
// dlopen
// ---------------------------------------------------------------------------

/// Open a shared object.
///
/// If `filename` is null, returns a handle to the main program. Otherwise
/// loads the named shared object. `flags` must have exactly one of
/// `RTLD_LAZY` or `RTLD_NOW` set; additional modifier flags are allowed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Loader, filename as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        set_dlerror(dlfcn_core::ERR_NOT_FOUND);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    // Validate flags via core.
    if !dlfcn_core::valid_flags(flags) {
        if mode.heals_enabled() {
            // Hardened mode: default to RTLD_NOW | RTLD_LOCAL.
            let healed_flags = dlfcn_core::RTLD_NOW;
            clear_dlerror();
            let handle = unsafe { libc::dlopen(filename, healed_flags) };
            let adverse = handle.is_null();
            if adverse {
                set_dlerror(dlfcn_core::ERR_NOT_FOUND);
            }
            runtime_policy::observe(ApiFamily::Loader, decision.profile, 12, adverse);
            return handle;
        }
        set_dlerror(dlfcn_core::ERR_INVALID_FLAGS);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    clear_dlerror();
    let handle = unsafe { libc::dlopen(filename, flags) };
    let adverse = handle.is_null();
    if adverse {
        set_dlerror(dlfcn_core::ERR_NOT_FOUND);
    }
    runtime_policy::observe(ApiFamily::Loader, decision.profile, 12, adverse);
    handle
}

// ---------------------------------------------------------------------------
// dlsym
// ---------------------------------------------------------------------------

/// Find a symbol in a shared object.
///
/// `handle` may be a real handle from `dlopen`, or one of the pseudo-handles
/// `RTLD_DEFAULT` / `RTLD_NEXT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Loader, handle as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    if symbol.is_null() {
        set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    clear_dlerror();
    let sym = unsafe { libc::dlsym(handle, symbol) };
    let adverse = sym.is_null();
    if adverse {
        set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
    }
    runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
    sym
}

// ---------------------------------------------------------------------------
// dlclose
// ---------------------------------------------------------------------------

/// Close a shared object handle.
///
/// Returns 0 on success, non-zero on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlclose(handle: *mut c_void) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Loader, handle as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return -1;
    }

    if handle.is_null() {
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return -1;
    }

    clear_dlerror();
    let rc = unsafe { libc::dlclose(handle) };
    let adverse = rc != 0;
    if adverse {
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
    }
    runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
    rc
}

// ---------------------------------------------------------------------------
// dlerror
// ---------------------------------------------------------------------------

/// Return a human-readable error message for the last `dlopen`, `dlsym`,
/// or `dlclose` failure. Returns null if no error has occurred since the
/// last call to `dlerror`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlerror() -> *const c_char {
    let msg = DLERROR_MSG.with(|cell| cell.get());
    // Per POSIX: calling dlerror() clears the error state.
    clear_dlerror();
    msg
}
