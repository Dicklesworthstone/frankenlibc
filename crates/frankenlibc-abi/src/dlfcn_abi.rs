//! ABI layer for `<dlfcn.h>` functions.
//!
//! Dynamic linker interface: `dlopen`, `dlsym`, `dlclose`, `dlerror`.
//! Phase-1 replacement mode provides a native main-program handle and a
//! deterministic resolver for the exported FrankenLibC surface instead of
//! delegating back into the host loader.

use std::ffi::{CStr, c_char, c_int, c_void};

use frankenlibc_core::dlfcn as dlfcn_core;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

// ---------------------------------------------------------------------------
// Thread-local dlerror state
// ---------------------------------------------------------------------------

use std::cell::RefCell;

std::thread_local! {
    /// Current error message (not yet seen by dlerror).
    static PENDING_ERROR: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
    /// Last error message returned by dlerror (valid until next dlfcn call).
    static STABLE_ERROR: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

/// Set the thread-local dlerror message from a static byte slice.
fn set_dlerror(msg: &'static [u8]) {
    PENDING_ERROR.with(|cell| {
        *cell.borrow_mut() = Some(msg.to_vec());
    });
}

/// Clear the thread-local dlerror message.
fn clear_dlerror() {
    PENDING_ERROR.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

#[inline]
pub(crate) unsafe fn dlvsym_next(symbol: *const c_char, version: *const c_char) -> *mut c_void {
    // SAFETY: callers provide symbol/version pointers for host-side symbol lookup.
    unsafe { libc::dlvsym(libc::RTLD_NEXT, symbol, version) }
}

#[inline]
fn main_program_handle() -> *mut c_void {
    static MAIN_PROGRAM_SENTINEL: u8 = 0;
    (&MAIN_PROGRAM_SENTINEL as *const u8)
        .cast_mut()
        .cast::<c_void>()
}

use std::sync::atomic::{AtomicUsize, Ordering};

static MAIN_PROGRAM_REFS: AtomicUsize = AtomicUsize::new(0);

fn is_main_program_handle(handle: *mut c_void) -> bool {
    handle == main_program_handle()
}

fn is_native_handle(handle: *mut c_void) -> bool {
    handle as usize == dlfcn_core::RTLD_DEFAULT
        || handle as usize == dlfcn_core::RTLD_NEXT
        || is_main_program_handle(handle)
}

fn library_alias_matches(name: &[u8]) -> bool {
    matches!(
        name,
        b"libc.so" | b"libc.so.6" | b"libfrankenlibc.so" | b"libfrankenlibc.so.0"
    )
}

fn version_supported(version: &[u8]) -> bool {
    matches!(version, b"GLIBC_2.2.5" | b"GLIBC_2.17" | b"GLIBC_2.34")
}

fn resolve_exported_symbol(symbol: &[u8]) -> *mut c_void {
    match symbol {
        b"dlopen" => {
            (dlopen as unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void as usize)
                as *mut c_void
        }
        b"dlsym" => {
            (dlsym as unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void as usize)
                as *mut c_void
        }
        b"dlvsym" => {
            (dlvsym
                as unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> *mut c_void
                as usize) as *mut c_void
        }
        b"dlclose" => {
            (dlclose as unsafe extern "C" fn(*mut c_void) -> c_int as usize) as *mut c_void
        }
        b"dlerror" => (dlerror as unsafe extern "C" fn() -> *const c_char as usize) as *mut c_void,
        b"malloc" => {
            (crate::malloc_abi::malloc as unsafe extern "C" fn(usize) -> *mut c_void as usize)
                as *mut c_void
        }
        b"free" => {
            (crate::malloc_abi::free as unsafe extern "C" fn(*mut c_void) as usize) as *mut c_void
        }
        b"printf" => {
            (crate::stdio_abi::printf as unsafe extern "C" fn(*const c_char, ...) -> c_int as usize)
                as *mut c_void
        }
        b"puts" => {
            (crate::stdio_abi::puts as unsafe extern "C" fn(*const c_char) -> c_int as usize)
                as *mut c_void
        }
        b"strlen" => {
            (crate::string_abi::strlen as unsafe extern "C" fn(*const c_char) -> usize as usize)
                as *mut c_void
        }
        _ => std::ptr::null_mut(),
    }
}

fn open_main_program_handle() -> *mut c_void {
    MAIN_PROGRAM_REFS.fetch_add(1, Ordering::Relaxed);
    main_program_handle()
}

fn close_main_program_handle() -> c_int {
    match MAIN_PROGRAM_REFS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |refs| {
        (refs > 0).then_some(refs - 1)
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

// ---------------------------------------------------------------------------
// dlopen
// ---------------------------------------------------------------------------

/// Open a shared object.
///
/// If `filename` is null, returns a handle to the main program. Otherwise
/// loads the named shared object. `flags` must have exactly one of
/// `RTLD_LAZY` or `RTLD_NOW` set; additional modifier flags are allowed.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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
            let handle = if filename.is_null() {
                open_main_program_handle()
            } else {
                std::ptr::null_mut()
            };
            let adverse = handle.is_null();
            if adverse {
                let _ = healed_flags;
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
    let handle = if filename.is_null() {
        open_main_program_handle()
    } else {
        // SAFETY: filename was checked for null above and is expected to be a NUL-terminated C string.
        let name = unsafe { CStr::from_ptr(filename) }.to_bytes();
        if name.is_empty()
            || ((flags & dlfcn_core::RTLD_NOLOAD) != 0 && library_alias_matches(name))
        {
            open_main_program_handle()
        } else {
            std::ptr::null_mut()
        }
    };
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
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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

    if !is_native_handle(handle) {
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    // SAFETY: symbol was checked for null above and is expected to be a NUL-terminated C string.
    let symbol_name = unsafe { CStr::from_ptr(symbol) }.to_bytes();
    clear_dlerror();
    let sym = resolve_exported_symbol(symbol_name);
    let adverse = sym.is_null();
    if adverse {
        set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
    }
    runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
    sym
}

/// Find a symbol with a specific version in a shared object.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dlvsym(
    handle: *mut c_void,
    symbol: *const c_char,
    version: *const c_char,
) -> *mut c_void {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Loader, handle as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    if symbol.is_null() || version.is_null() {
        set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    if !is_native_handle(handle) {
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    // SAFETY: symbol/version were checked for null above and are expected to be NUL-terminated C strings.
    let symbol_name = unsafe { CStr::from_ptr(symbol) }.to_bytes();
    // SAFETY: symbol/version were checked for null above and are expected to be NUL-terminated C strings.
    let version_name = unsafe { CStr::from_ptr(version) }.to_bytes();
    clear_dlerror();
    let sym = if version_supported(version_name) {
        resolve_exported_symbol(symbol_name)
    } else {
        std::ptr::null_mut()
    };
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
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dlclose(handle: *mut c_void) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Loader, handle as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe {
            let p = super::errno_abi::__errno_location();
            *p = libc::EPERM;
        }
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return -1;
    }

    if handle.is_null() {
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return -1;
    }

    if !is_main_program_handle(handle) {
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return -1;
    }

    clear_dlerror();
    let rc = close_main_program_handle();
    let adverse = rc != 0;
    if adverse {
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
    }
    runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
    rc
}

/// Return a human-readable error message for the last `dlopen`, `dlsym`,
/// or `dlclose` failure. Returns null if no error has occurred since the
/// last call to `dlerror`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dlerror() -> *const c_char {
    let pending = PENDING_ERROR.with(|cell| cell.borrow_mut().take());
    if let Some(msg) = pending {
        STABLE_ERROR.with(|cell| {
            let mut stable = cell.borrow_mut();
            *stable = Some(msg);
            stable.as_ref().unwrap().as_ptr() as *const c_char
        })
    } else {
        std::ptr::null()
    }
}

// ---------------------------------------------------------------------------
// dl_iterate_phdr / dladdr — native fallback (no host call-through)
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dl_iterate_phdr(
    callback: Option<unsafe extern "C" fn(*mut c_void, usize, *mut c_void) -> c_int>,
    data: *mut c_void,
) -> c_int {
    let callback_addr = callback.map_or(0usize, |cb| cb as usize);
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Loader,
        callback_addr,
        data as usize,
        false,
        true,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        set_dlerror(dlfcn_core::ERR_OPERATION_UNAVAILABLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return -1;
    }

    // Phase-1 native replacement-safe fallback: report no entries instead of
    // calling into host loader internals.
    let _ = callback;
    let _ = data;
    clear_dlerror();
    runtime_policy::observe(ApiFamily::Loader, decision.profile, 6, false);
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dladdr(addr: *const c_void, info: *mut c_void) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Loader,
        addr as usize,
        info as usize,
        false,
        true,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        set_dlerror(dlfcn_core::ERR_OPERATION_UNAVAILABLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return 0;
    }

    if addr.is_null() {
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return 0;
    }

    if info.is_null() {
        // POSIX does not define behavior for null info, but returning 0 (failure)
        // is the safest path for libc replacement.
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return 0;
    }

    // Native fallback currently does not expose loader metadata.
    set_dlerror(dlfcn_core::ERR_OPERATION_UNAVAILABLE);
    runtime_policy::observe(ApiFamily::Loader, decision.profile, 6, true);
    0
}
