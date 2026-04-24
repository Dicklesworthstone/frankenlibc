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

use std::cell::Cell;

// Thread-local dlerror state using `Cell` with static pointers.
//
// `RefCell` panics on reentrant `borrow_mut()`, which happens during early
// startup when `dlsym` → `set_dlerror` → TLS init → `dlsym` → `clear_dlerror`
// creates a reentrant access.  `Cell` with simple pointer `get`/`set` is
// reentry-safe and avoids heap allocation entirely since all error messages
// are `&'static [u8]`.
std::thread_local! {
    /// Pending error: pointer to static NUL-terminated error message, or null.
    static PENDING_PTR: Cell<*const u8> = const { Cell::new(std::ptr::null()) };
    /// Stable pointer returned by dlerror() — valid until next dlfcn call.
    static STABLE_PTR: Cell<*const u8> = const { Cell::new(std::ptr::null()) };
}

/// Set the thread-local dlerror message from a static byte slice.
fn set_dlerror(msg: &'static [u8]) {
    let _ = PENDING_PTR.try_with(|cell| cell.set(msg.as_ptr()));
}

/// Clear the thread-local dlerror message.
fn clear_dlerror() {
    let _ = PENDING_PTR.try_with(|cell| cell.set(std::ptr::null()));
}

#[inline]
pub(crate) unsafe fn dlvsym_next(symbol: *const c_char, version: *const c_char) -> *mut c_void {
    // SAFETY: callers provide symbol/version pointers for host-side symbol lookup.
    unsafe { crate::host_resolve::host_dlvsym_next_raw(symbol, version) }
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

fn is_rtld_default(handle: *mut c_void) -> bool {
    handle as usize == dlfcn_core::RTLD_DEFAULT
}

fn is_rtld_next(handle: *mut c_void) -> bool {
    handle as usize == dlfcn_core::RTLD_NEXT
}

fn is_native_handle(handle: *mut c_void) -> bool {
    is_rtld_default(handle) || is_rtld_next(handle) || is_main_program_handle(handle)
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

unsafe fn host_dlsym(handle: *mut c_void, symbol: *const c_char) -> Option<*mut c_void> {
    type DlsymFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
    let addr = crate::host_resolve::resolve_host_symbol_raw("dlsym")?;
    // SAFETY: resolved symbol address is the host dlsym with the expected ABI.
    let host_dlsym: DlsymFn = unsafe { core::mem::transmute(addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
    Some(unsafe { host_dlsym(handle, symbol) })
}

unsafe fn host_dlvsym(
    handle: *mut c_void,
    symbol: *const c_char,
    version: *const c_char,
) -> Option<*mut c_void> {
    type DlvsymFn = unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> *mut c_void;
    let addr = crate::host_resolve::resolve_host_symbol_raw("dlvsym")?;
    // SAFETY: resolved symbol address is the host dlvsym with the expected ABI.
    let host_dlvsym: DlvsymFn = unsafe { core::mem::transmute(addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
    Some(unsafe { host_dlvsym(handle, symbol, version) })
}

unsafe fn resolve_main_program_symbol(symbol: *const c_char, symbol_name: &[u8]) -> *mut c_void {
    let sym = resolve_exported_symbol(symbol_name);
    if !sym.is_null() {
        return sym;
    }
    unsafe { host_dlsym(libc::RTLD_DEFAULT, symbol) }.unwrap_or(std::ptr::null_mut())
}

unsafe fn resolve_main_program_versioned_symbol(
    symbol: *const c_char,
    version: *const c_char,
    symbol_name: &[u8],
    version_name: &[u8],
) -> *mut c_void {
    if version_supported(version_name) {
        let native = resolve_exported_symbol(symbol_name);
        if !native.is_null() {
            return native;
        }
    }
    unsafe { host_dlvsym(libc::RTLD_DEFAULT, symbol, version) }.unwrap_or(std::ptr::null_mut())
}

fn open_main_program_handle() -> *mut c_void {
    MAIN_PROGRAM_REFS.fetch_add(1, Ordering::Relaxed);
    main_program_handle()
}

fn close_main_program_handle() -> c_int {
    match MAIN_PROGRAM_REFS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |refs| {
        if refs > 0 { Some(refs - 1) } else { None }
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
    if runtime_policy::bootstrap_passthrough_active() {
        if filename.is_null() {
            clear_dlerror();
            return open_main_program_handle();
        }
        if !dlfcn_core::valid_flags(flags) {
            set_dlerror(dlfcn_core::ERR_INVALID_FLAGS);
            return std::ptr::null_mut();
        }
        let name = unsafe { CStr::from_ptr(filename) }.to_bytes();
        if name.is_empty()
            || ((flags & dlfcn_core::RTLD_NOLOAD) != 0 && library_alias_matches(name))
        {
            clear_dlerror();
            return open_main_program_handle();
        }
        // During bootstrap, delegate to host dlopen for actual .so loading.
        type DlopenFn = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
        if let Some(addr) = crate::host_resolve::resolve_host_symbol_raw("dlopen") {
            let host_dlopen: DlopenFn = unsafe { core::mem::transmute(addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
            let handle = unsafe { host_dlopen(filename, flags) };
            if handle.is_null() {
                set_dlerror(dlfcn_core::ERR_NOT_FOUND);
            } else {
                clear_dlerror();
            }
            return handle;
        }
        set_dlerror(dlfcn_core::ERR_NOT_FOUND);
        return std::ptr::null_mut();
    }

    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Loader, filename as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        set_dlerror(dlfcn_core::ERR_NOT_FOUND);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }
    let (name_len, terminated) = unsafe {
        crate::util::scan_c_string(
            filename,
            crate::malloc_abi::known_remaining(filename as usize),
        )
    };
    if !terminated && mode.heals_enabled() {
        set_dlerror(dlfcn_core::ERR_NOT_FOUND);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }
    let _name = unsafe { std::slice::from_raw_parts(filename as *const u8, name_len) };
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
        let name = unsafe { CStr::from_ptr(filename) }.to_bytes();
        if name.is_empty()
            || ((flags & dlfcn_core::RTLD_NOLOAD) != 0 && library_alias_matches(name))
        {
            open_main_program_handle()
        } else {
            // Delegate to host libc's dlopen for actual shared object loading.
            // Our dlopen cannot load ELF files natively — the host's dynamic
            // linker handles symbol resolution, relocations, and dependency loading.
            type DlopenFn = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
            if let Some(addr) = crate::host_resolve::resolve_host_symbol_raw("dlopen") {
                let host_dlopen: DlopenFn = unsafe { core::mem::transmute(addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
                let handle = unsafe { host_dlopen(filename, flags) };
                if handle.is_null() {
                    set_dlerror(dlfcn_core::ERR_NOT_FOUND);
                } else {
                    clear_dlerror();
                }
                handle
            } else {
                set_dlerror(dlfcn_core::ERR_NOT_FOUND);
                std::ptr::null_mut()
            }
        }
    };
    let adverse = handle.is_null();
    if adverse && filename.is_null() {
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
    if runtime_policy::bootstrap_passthrough_active() {
        if symbol.is_null() {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
            return std::ptr::null_mut();
        }
        if !is_main_program_handle(handle) {
            let host_handle = if is_rtld_default(handle) {
                libc::RTLD_DEFAULT
            } else if is_rtld_next(handle) {
                libc::RTLD_NEXT
            } else {
                handle
            };
            let sym = unsafe { host_dlsym(host_handle, symbol) }.unwrap_or(std::ptr::null_mut());
            if sym.is_null() {
                set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
            } else {
                clear_dlerror();
            }
            return sym;
        }
        let symbol_name = unsafe { CStr::from_ptr(symbol) }.to_bytes();
        let sym = unsafe { resolve_main_program_symbol(symbol, symbol_name) };
        if sym.is_null() {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        } else {
            clear_dlerror();
        }
        return sym;
    }

    let (mode, decision) =
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

    let (symbol_len, terminated) = unsafe {
        crate::util::scan_c_string(symbol, crate::malloc_abi::known_remaining(symbol as usize))
    };
    if !terminated && mode.heals_enabled() {
        set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }
    let symbol_name = unsafe { std::slice::from_raw_parts(symbol as *const u8, symbol_len) };

    if is_rtld_next(handle) || is_rtld_default(handle) {
        let host_handle = if is_rtld_default(handle) {
            libc::RTLD_DEFAULT
        } else {
            libc::RTLD_NEXT
        };
        let sym = unsafe { host_dlsym(host_handle, symbol) }.unwrap_or_else(|| {
            if is_rtld_default(handle) {
                resolve_exported_symbol(symbol_name)
            } else {
                std::ptr::null_mut()
            }
        });
        let adverse = sym.is_null();
        if adverse {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        } else {
            clear_dlerror();
        }
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
        return sym;
    }

    if !is_native_handle(handle) {
        // Handle is from host dlopen — delegate to host dlsym.
        type DlsymFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
        if let Some(addr) = crate::host_resolve::resolve_host_symbol_raw("dlsym") {
            // SAFETY: resolved symbol address is the host dlsym with the expected ABI.
            let host_dlsym: DlsymFn = unsafe { core::mem::transmute(addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
            let sym = unsafe { host_dlsym(handle, symbol) };
            let adverse = sym.is_null();
            if adverse {
                set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
            } else {
                clear_dlerror();
            }
            runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
            return sym;
        }
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    clear_dlerror();
    let sym = unsafe { resolve_main_program_symbol(symbol, symbol_name) };

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
    if runtime_policy::bootstrap_passthrough_active() {
        if symbol.is_null() || version.is_null() {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
            return std::ptr::null_mut();
        }
        if !is_main_program_handle(handle) {
            let host_handle = if is_rtld_default(handle) {
                libc::RTLD_DEFAULT
            } else if is_rtld_next(handle) {
                libc::RTLD_NEXT
            } else {
                handle
            };
            let sym = unsafe { host_dlvsym(host_handle, symbol, version) }
                .unwrap_or(std::ptr::null_mut());
            if sym.is_null() {
                set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
            } else {
                clear_dlerror();
            }
            return sym;
        }
        let symbol_name = unsafe { CStr::from_ptr(symbol) }.to_bytes();
        let version_name = unsafe { CStr::from_ptr(version) }.to_bytes();
        let sym = unsafe {
            resolve_main_program_versioned_symbol(symbol, version, symbol_name, version_name)
        };
        return if sym.is_null() {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
            std::ptr::null_mut()
        } else {
            clear_dlerror();
            sym
        };
    }

    let (mode, decision) =
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

    let (symbol_len, symbol_terminated) = unsafe {
        crate::util::scan_c_string(symbol, crate::malloc_abi::known_remaining(symbol as usize))
    };
    let (version_len, version_terminated) = unsafe {
        crate::util::scan_c_string(
            version,
            crate::malloc_abi::known_remaining(version as usize),
        )
    };
    if (!symbol_terminated || !version_terminated) && mode.heals_enabled() {
        set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    let symbol_name = unsafe { std::slice::from_raw_parts(symbol as *const u8, symbol_len) };
    let version_name = unsafe { std::slice::from_raw_parts(version as *const u8, version_len) };

    if is_rtld_next(handle) || is_rtld_default(handle) {
        let host_handle = if is_rtld_default(handle) {
            libc::RTLD_DEFAULT
        } else {
            libc::RTLD_NEXT
        };
        let sym = unsafe { host_dlvsym(host_handle, symbol, version) }.unwrap_or_else(|| {
            if is_rtld_default(handle) && version_supported(version_name) {
                resolve_exported_symbol(symbol_name)
            } else {
                std::ptr::null_mut()
            }
        });
        let adverse = sym.is_null();
        if adverse {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        } else {
            clear_dlerror();
        }
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
        return sym;
    }

    if !is_native_handle(handle) {
        // Handle is from host dlopen — delegate to host dlvsym.
        let sym = unsafe { host_dlvsym(handle, symbol, version) }.unwrap_or(std::ptr::null_mut());
        let adverse = sym.is_null();
        if adverse {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        } else {
            clear_dlerror();
        }
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
        return sym;
    }

    clear_dlerror();
    let sym = unsafe {
        resolve_main_program_versioned_symbol(symbol, version, symbol_name, version_name)
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
    if runtime_policy::bootstrap_passthrough_active() {
        if handle.is_null() {
            set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
            return -1;
        }
        if is_main_program_handle(handle) {
            let rc = close_main_program_handle();
            if rc == 0 {
                clear_dlerror();
            } else {
                if runtime_policy::mode().heals_enabled() {
                    clear_dlerror();
                    return 0;
                }
                set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
            }
            return rc;
        }
        // Non-main-program handle during bootstrap: delegate to host dlclose.
        type DlcloseFn = unsafe extern "C" fn(*mut c_void) -> c_int;
        if let Some(addr) = crate::host_resolve::resolve_host_symbol_raw("dlclose") {
            let host_dlclose: DlcloseFn = unsafe { core::mem::transmute(addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
            let rc = unsafe { host_dlclose(handle) };
            if rc == 0 {
                clear_dlerror();
            } else {
                set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
            }
            return rc;
        }
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        return -1;
    }

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
        // Handle from host dlopen — delegate to host dlclose.
        type DlcloseFn = unsafe extern "C" fn(*mut c_void) -> c_int;
        if let Some(addr) = crate::host_resolve::resolve_host_symbol_raw("dlclose") {
            let host_dlclose: DlcloseFn = unsafe { core::mem::transmute(addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
            let rc = unsafe { host_dlclose(handle) };
            let adverse = rc != 0;
            runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
            if adverse && runtime_policy::mode().heals_enabled() {
                clear_dlerror();
                return 0;
            }
            return rc;
        }
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
    if adverse && runtime_policy::mode().heals_enabled() {
        clear_dlerror();
        return 0;
    }
    rc
}

/// Return a human-readable error message for the last `dlopen`, `dlsym`,
/// or `dlclose` failure. Returns null if no error has occurred since the
/// last call to `dlerror`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dlerror() -> *const c_char {
    let ptr = PENDING_PTR
        .try_with(|cell| {
            let p = cell.get();
            cell.set(std::ptr::null()); // consume the error
            p
        })
        .unwrap_or(std::ptr::null());
    if ptr.is_null() {
        return std::ptr::null();
    }
    // Move to stable slot so the pointer remains valid until next dlfcn call.
    let _ = STABLE_PTR.try_with(|cell| cell.set(ptr));
    ptr as *const c_char
}

// ---------------------------------------------------------------------------
// dl_iterate_phdr / dladdr — native fallback (no host call-through)
// ---------------------------------------------------------------------------

/// `dl_iterate_phdr` — enumerate loaded shared objects.
///
/// Delegates to the host dynamic linker so that libgcc exception-unwinding,
/// backtrace libraries, and any caller that enumerates DSOs works correctly.
/// Uses the cached host address (resolved during bootstrap) to avoid recursion
/// into resolve_host_symbol_raw.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dl_iterate_phdr(
    callback: Option<unsafe extern "C" fn(*mut libc::dl_phdr_info, usize, *mut c_void) -> c_int>,
    data: *mut c_void,
) -> c_int {
    type DlIteratePhdrFn = unsafe extern "C" fn(
        Option<unsafe extern "C" fn(*mut libc::dl_phdr_info, usize, *mut c_void) -> c_int>,
        *mut c_void,
    ) -> c_int;
    if callback.is_none() {
        return 0;
    }
    let host_addr = crate::host_resolve::host_dl_iterate_phdr_cached().or_else(|| {
        crate::host_resolve::bootstrap_host_symbols();
        crate::host_resolve::host_dl_iterate_phdr_cached()
    });
    if let Some(addr) = host_addr {
        let host_fn: DlIteratePhdrFn = unsafe { core::mem::transmute(addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
        return unsafe { host_fn(callback, data) };
    }
    // During early bootstrap before symbols are resolved, return 0 (no entries).
    0
}

/// `dladdr` — resolve address to shared object info.
///
/// Delegates to the host dynamic linker for correct DSO metadata.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dladdr(addr: *const c_void, info: *mut c_void) -> c_int {
    if addr.is_null() || info.is_null() {
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        return 0;
    }
    type DladdrFn = unsafe extern "C" fn(*const c_void, *mut c_void) -> c_int;
    if let Some(host_addr) = crate::host_resolve::host_dladdr_cached() {
        let host_fn: DladdrFn = unsafe { core::mem::transmute(host_addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
        let rc = unsafe { host_fn(addr, info) };
        if rc != 0 {
            clear_dlerror();
            return rc;
        }
    }
    set_dlerror(dlfcn_core::ERR_OPERATION_UNAVAILABLE);
    0
}
