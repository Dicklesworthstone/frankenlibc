//! ABI layer for `<dlfcn.h>` functions.
//!
//! Dynamic linker interface: `dlopen`, `dlsym`, `dlclose`, `dlerror`.
//! Phase-1 replacement mode provides a native main-program handle and a
//! deterministic resolver for the exported FrankenLibC surface instead of
//! delegating back into the host loader.

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_core::dlfcn as dlfcn_core;
#[cfg(feature = "standalone")]
use frankenlibc_core::elf::ElfLoader;
#[cfg(feature = "standalone")]
use frankenlibc_core::elf::{Elf64ProgramHeader, ProgramType};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

// ---------------------------------------------------------------------------
// Thread-local dlerror state
// ---------------------------------------------------------------------------

#[cfg(not(feature = "owned-tls-cache"))]
use std::cell::Cell;

#[cfg(feature = "owned-tls-cache")]
#[derive(Clone, Copy, Default)]
struct DlErrorState {
    pending: usize,
    stable: usize,
}

#[cfg(feature = "owned-tls-cache")]
static DLERROR_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<DlErrorState> =
    crate::owned_tls_cache::OwnedTlsCache::new(DlErrorState::default);

// Thread-local dlerror state using `Cell` with static pointers.
//
// `RefCell` panics on reentrant `borrow_mut()`, which happens during early
// startup when `dlsym` → `set_dlerror` → TLS init → `dlsym` → `clear_dlerror`
// creates a reentrant access.  `Cell` with simple pointer `get`/`set` is
// reentry-safe and avoids heap allocation entirely since all error messages
// are `&'static [u8]`.
#[cfg(not(feature = "owned-tls-cache"))]
std::thread_local! {
    /// Pending error: pointer to static NUL-terminated error message, or null.
    static PENDING_PTR: Cell<*const u8> = const { Cell::new(std::ptr::null()) };
    /// Stable pointer returned by dlerror() — valid until next dlfcn call.
    static STABLE_PTR: Cell<*const u8> = const { Cell::new(std::ptr::null()) };
}

/// Set the thread-local dlerror message from a static byte slice.
fn set_dlerror(msg: &'static [u8]) {
    #[cfg(feature = "owned-tls-cache")]
    {
        DLERROR_OWNED_TLS.with(|state| state.pending = msg.as_ptr() as usize);
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        let _ = PENDING_PTR.try_with(|cell| cell.set(msg.as_ptr()));
    }
}

/// Record a host-owned dlerror string (valid until the host's next dlerror on
/// this thread, which is also glibc's lifetime rule for the returned text).
#[cfg(not(feature = "standalone"))]
fn set_dlerror_host(msg: *const c_char) {
    #[cfg(feature = "owned-tls-cache")]
    {
        DLERROR_OWNED_TLS.with(|state| state.pending = msg as usize);
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        let _ = PENDING_PTR.try_with(|cell| cell.set(msg.cast::<u8>()));
    }
}

/// Interpose-mode host `dlopen`, carrying the host's own error text through to
/// our `dlerror` (e.g. "libfoo.so: cannot open shared object file: ...")
/// instead of a generic message.
#[cfg(not(feature = "standalone"))]
unsafe fn host_dlopen_with_error(filename: *const c_char, flags: c_int) -> *mut c_void {
    type DlopenFn = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
    type DlerrorFn = unsafe extern "C" fn() -> *const c_char;
    let Some(addr) = crate::host_resolve::resolve_host_symbol_raw("dlopen") else {
        set_dlerror(dlfcn_core::ERR_NOT_FOUND);
        return std::ptr::null_mut();
    };
    let host_dlopen: DlopenFn = unsafe { core::mem::transmute(addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
    let handle = unsafe { host_dlopen(filename, flags) };
    if !handle.is_null() {
        clear_dlerror();
        return handle;
    }
    let host_msg = crate::host_resolve::resolve_host_symbol_raw("dlerror").map(|addr| {
        let host_dlerror: DlerrorFn = unsafe { core::mem::transmute(addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
        unsafe { host_dlerror() }
    });
    match host_msg {
        Some(msg) if !msg.is_null() => set_dlerror_host(msg),
        _ => set_dlerror(dlfcn_core::ERR_NOT_FOUND),
    }
    std::ptr::null_mut()
}

/// Pathname `dlopen` in interpose builds: the native loader is authoritative
/// for objects it fully supports; anything it cannot load (initial-exec TLS,
/// dependencies already owned by the host `ld.so`, unsupported relocations,
/// or a missing file) goes to the host loader, which is still in the process
/// at L0/L1. Failing instead broke every Python C extension import
/// (bd-rc0923-epic-eeuy4f.3). Standalone builds never reach this function.
#[cfg(not(feature = "standalone"))]
unsafe fn dlopen_pathname(name: &[u8], filename: *const c_char, flags: c_int) -> *mut c_void {
    if let Some(handle) = load_native_dso(name, flags) {
        clear_dlerror();
        return handle;
    }
    // Only host-coupled regular files (or paths that do not exist, which the
    // host reports precisely) go to the host: a FIFO or device would block or
    // have side effects, and a self-contained object the native loader
    // rejected as invalid must stay rejected.
    // SAFETY: `filename` is a bounded NUL-terminated string; `st` is a
    // correctly sized stat buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let stat_rc = unsafe {
        frankenlibc_core::syscall::sys_newfstatat(
            libc::AT_FDCWD,
            filename.cast::<u8>(),
            (&raw mut st).cast::<u8>(),
            0,
        )
    };
    let host_may_try = match stat_rc {
        Ok(()) => {
            (st.st_mode & libc::S_IFMT) == libc::S_IFREG && host_may_load_declined_object(name)
        }
        Err(e) => e == libc::ENOENT || e == libc::ENOTDIR,
    };
    if !host_may_try {
        set_dlerror(dlfcn_core::ERR_NOT_FOUND);
        return std::ptr::null_mut();
    }
    NATIVE_PATHNAME_FALLBACKS.fetch_add(1, Ordering::Relaxed);
    unsafe { host_dlopen_with_error(filename, flags) }
}

/// Count of pathname loads the native loader declined and the host served.
#[cfg(not(feature = "standalone"))]
static NATIVE_PATHNAME_FALLBACKS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[cfg(not(feature = "standalone"))]
#[doc(hidden)]
pub fn native_pathname_fallback_count() -> u64 {
    NATIVE_PATHNAME_FALLBACKS.load(Ordering::Relaxed)
}

/// Clear the thread-local dlerror message.
fn clear_dlerror() {
    #[cfg(feature = "owned-tls-cache")]
    {
        DLERROR_OWNED_TLS.with(|state| state.pending = 0);
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        let _ = PENDING_PTR.try_with(|cell| cell.set(std::ptr::null()));
    }
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
    is_rtld_default(handle)
        || is_rtld_next(handle)
        || is_main_program_handle(handle)
        || native_dso_id_from_handle(handle).is_some()
}

fn library_alias_matches(name: &[u8]) -> bool {
    matches!(
        name,
        b"libc.so" | b"libc.so.6" | b"libfrankenlibc.so" | b"libfrankenlibc.so.0"
    )
}

unsafe fn bounded_cstr_bytes<'a>(ptr: *const c_char) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: ptr is a caller-supplied C string pointer; known_remaining
    // bounds tracked malloc-backed storage before the scan can cross it.
    let (len, terminated) = unsafe {
        crate::util::scan_c_string(ptr, crate::malloc_abi::known_remaining(ptr as usize))
    };
    if !terminated {
        return None;
    }
    // SAFETY: scan_c_string observed len readable bytes before the terminator.
    Some(unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), len) })
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
        b"dl_iterate_phdr" => dl_iterate_phdr as *const () as *mut c_void,
        b"dladdr" => dladdr as *const () as *mut c_void,
        b"malloc" => {
            (crate::malloc_abi::malloc as unsafe extern "C" fn(usize) -> *mut c_void as usize)
                as *mut c_void
        }
        b"free" => {
            (crate::malloc_abi::free as unsafe extern "C" fn(*mut c_void) as usize) as *mut c_void
        }
        b"memcpy" => {
            (crate::string_abi::memcpy
                as unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> *mut c_void
                as usize) as *mut c_void
        }
        b"memmove" => {
            (crate::string_abi::memmove
                as unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> *mut c_void
                as usize) as *mut c_void
        }
        b"memset" => {
            (crate::string_abi::memset
                as unsafe extern "C" fn(*mut c_void, c_int, usize) -> *mut c_void
                as usize) as *mut c_void
        }
        b"printf" => {
            (crate::stdio_abi::printf as unsafe extern "C-unwind" fn(*const c_char, ...) -> c_int
                as usize) as *mut c_void
        }
        b"puts" => {
            (crate::stdio_abi::puts as unsafe extern "C-unwind" fn(*const c_char) -> c_int as usize)
                as *mut c_void
        }
        b"strlen" => {
            (crate::string_abi::strlen as unsafe extern "C" fn(*const c_char) -> usize as usize)
                as *mut c_void
        }
        b"strcmp" => {
            (crate::string_abi::strcmp
                as unsafe extern "C" fn(*const c_char, *const c_char) -> c_int
                as usize) as *mut c_void
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

/// The program's definition of data symbol `name`: the first definition in
/// the global scope (the executable, then fl itself when preloaded), unless
/// that is host libc's own copy — which only happens when neither the
/// program nor fl exports the symbol (e.g. unit-test binaries) and must not
/// shadow fl's statics. Null when there is no such definition, and in
/// standalone builds. Used for program-settable variables such as
/// `argp_program_version_hook`, whose executable definition interposes fl's
/// copy for every reference except fl's own direct ones.
pub(crate) unsafe fn program_data_symbol(name: &core::ffi::CStr) -> *mut c_void {
    let Some(found) = (unsafe { host_dlsym(libc::RTLD_DEFAULT, name.as_ptr()) }) else {
        return std::ptr::null_mut();
    };
    let host_own = name
        .to_str()
        .ok()
        .and_then(crate::host_resolve::resolve_host_symbol_raw);
    if found.is_null() || host_own == Some(found as usize) {
        return std::ptr::null_mut();
    }
    found
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
    let _ = MAIN_PROGRAM_REFS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |refs| {
        if refs > 0 { Some(refs - 1) } else { None }
    });
    0
}

#[path = "dlfcn_native.rs"]
mod native;
#[cfg(not(feature = "standalone"))]
use native::host_may_load_declined_object;
use native::{
    close_native_dso, load_native_dso, native_dso_id_from_handle, resolve_native_dso_symbol,
};

#[doc(hidden)]
pub use native::native_dso_handle_for_tests;

#[cfg(not(feature = "standalone"))]
fn is_pathname(name: &[u8]) -> bool {
    name.contains(&b'/')
}

// ---------------------------------------------------------------------------
// dlopen
// ---------------------------------------------------------------------------

/// Open a shared object.
///
/// If `filename` is null, returns a handle to the main program. Otherwise
/// loads the named shared object. `flags` must have exactly one of
/// `RTLD_LAZY` or `RTLD_NOW` set; additional modifier flags are allowed.
#[allow(unreachable_code)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void {
    #[cfg(feature = "standalone")]
    {
        // There is no host loader to repair a rejected native transaction.
        // Validate flags even for the main-program handle, before side effects.
        if !dlfcn_core::valid_flags(flags) {
            set_dlerror(dlfcn_core::ERR_INVALID_FLAGS);
            return std::ptr::null_mut();
        }
        if filename.is_null() {
            clear_dlerror();
            return open_main_program_handle();
        }
        // SAFETY: this is the ABI's existing bounded caller-string reader.
        let Some(name) = (unsafe { bounded_cstr_bytes(filename) }) else {
            set_dlerror(dlfcn_core::ERR_NOT_FOUND);
            return std::ptr::null_mut();
        };
        if name.is_empty()
            || ((flags & dlfcn_core::RTLD_NOLOAD) != 0 && library_alias_matches(name))
        {
            clear_dlerror();
            return open_main_program_handle();
        }
        return match load_native_dso(name, flags) {
            Some(handle) => {
                clear_dlerror();
                handle
            }
            None => {
                set_dlerror(dlfcn_core::ERR_NOT_FOUND);
                std::ptr::null_mut()
            }
        };
    }
    #[cfg(not(feature = "standalone"))]
    {
        // SAFETY: forward the original ABI arguments to the interpose path.
        unsafe { dlopen_interpose(filename, flags) }
    }
}

// Keep host-only names out of standalone type checking, not merely behind
// an unreachable early return. Interpose/bootstrap behavior is unchanged.
#[cfg(not(feature = "standalone"))]
unsafe fn dlopen_interpose(filename: *const c_char, flags: c_int) -> *mut c_void {
    if runtime_policy::bootstrap_passthrough_active() {
        if filename.is_null() {
            clear_dlerror();
            return open_main_program_handle();
        }
        if !dlfcn_core::valid_flags(flags) {
            set_dlerror(dlfcn_core::ERR_INVALID_FLAGS);
            return std::ptr::null_mut();
        }
        let Some(name) = (unsafe { bounded_cstr_bytes(filename) }) else {
            set_dlerror(dlfcn_core::ERR_NOT_FOUND);
            return std::ptr::null_mut();
        };
        if name.is_empty()
            || ((flags & dlfcn_core::RTLD_NOLOAD) != 0 && library_alias_matches(name))
        {
            clear_dlerror();
            return open_main_program_handle();
        }
        if is_pathname(name) {
            return unsafe { dlopen_pathname(name, filename, flags) };
        }
        // During bootstrap, delegate to host dlopen for actual .so loading.
        return unsafe { host_dlopen_with_error(filename, flags) };
    }

    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Loader, filename as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        set_dlerror(dlfcn_core::ERR_NOT_FOUND);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }
    let name_bytes = if filename.is_null() {
        b"".as_slice()
    } else {
        let Some(bytes) = (unsafe { bounded_cstr_bytes(filename) }) else {
            set_dlerror(dlfcn_core::ERR_NOT_FOUND);
            runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
            return std::ptr::null_mut();
        };
        bytes
    };
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
        // Use the bounded `name_bytes` slice instead of re-scanning via
        // CStr::from_ptr which has no length bound. (REVIEW round 4.)
        let name = name_bytes;
        if name.is_empty()
            || ((flags & dlfcn_core::RTLD_NOLOAD) != 0 && library_alias_matches(name))
        {
            open_main_program_handle()
        } else if is_pathname(name) {
            unsafe { dlopen_pathname(name, filename, flags) }
        } else {
            // Bare SONAME search/dependency loading remains delegated while
            // pathname DSOs try the native loader first (see dlopen_pathname).
            unsafe { host_dlopen_with_error(filename, flags) }
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
#[allow(unreachable_code)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void {
    // Standalone lookups stay entirely within the owned loader namespace.
    #[cfg(feature = "standalone")]
    {
        if symbol.is_null() {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
            return std::ptr::null_mut();
        }
        let (symbol_len, symbol_terminated) = unsafe {
            crate::util::scan_c_string(symbol, crate::malloc_abi::known_remaining(symbol as usize))
        };
        if !symbol_terminated {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
            return std::ptr::null_mut();
        }
        let symbol_name = unsafe { std::slice::from_raw_parts(symbol as *const u8, symbol_len) };
        // Builtins retain their existing precedence. An explicit main handle
        // additionally sees live GLOBAL plugins, but never LOCAL-only objects.
        if is_main_program_handle(handle) || is_rtld_default(handle) {
            let sym = resolve_exported_symbol(symbol_name);
            if !sym.is_null() {
                clear_dlerror();
                return sym;
            }
            if is_main_program_handle(handle)
                && let Some(Some(address)) = resolve_native_dso_symbol(handle, symbol_name, None)
            {
                // A resolved IFUNC is allowed to return NULL without an error.
                clear_dlerror();
                return address;
            }
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
            return std::ptr::null_mut();
        }
        if let Some(symbol) = resolve_native_dso_symbol(handle, symbol_name, None) {
            return match symbol {
                Some(address) => {
                    clear_dlerror();
                    address
                }
                None => {
                    set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
                    std::ptr::null_mut()
                }
            };
        }
        // An unknown or stale handle is never handed to a host resolver.
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        return std::ptr::null_mut();
    }
    #[cfg(not(feature = "standalone"))]
    if runtime_policy::bootstrap_passthrough_active() {
        if symbol.is_null() {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
            return std::ptr::null_mut();
        }
        let (symbol_len, symbol_terminated) = unsafe {
            crate::util::scan_c_string(symbol, crate::malloc_abi::known_remaining(symbol as usize))
        };
        if !symbol_terminated {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
            return std::ptr::null_mut();
        }
        let symbol_name = unsafe { std::slice::from_raw_parts(symbol as *const u8, symbol_len) };
        if !is_main_program_handle(handle) {
            if let Some(native_sym) = resolve_native_dso_symbol(handle, symbol_name, None) {
                return if let Some(sym) = native_sym {
                    clear_dlerror();
                    sym
                } else {
                    set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
                    std::ptr::null_mut()
                };
            }
            if native_dso_id_from_handle(handle).is_some() {
                set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
                return std::ptr::null_mut();
            }
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
        let sym = unsafe { resolve_main_program_symbol(symbol, symbol_name) };
        if sym.is_null() {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        } else {
            clear_dlerror();
        }
        return sym;
    }

    let (_mode, decision) =
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
    // Reject non-NUL-terminated symbols in EVERY mode. The original guard
    // only fired in hardened mode and let strict mode fall through to
    // host_dlsym(symbol)/CStr::from_ptr(symbol) — both unbounded reads of
    // user-supplied memory. (REVIEW round 4: same defense class as bd-z4k96.)
    if !terminated {
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

    if let Some(native_sym) = resolve_native_dso_symbol(handle, symbol_name, None) {
        // NULL can be a successful IFUNC result; absence is represented by None.
        let adverse = native_sym.is_none();
        let sym = native_sym.unwrap_or(std::ptr::null_mut());
        if adverse {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        } else {
            clear_dlerror();
        }
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
        return sym;
    }

    if native_dso_id_from_handle(handle).is_some() {
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
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
#[allow(unreachable_code)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dlvsym(
    handle: *mut c_void,
    symbol: *const c_char,
    version: *const c_char,
) -> *mut c_void {
    // Native handles use their own version tables, not the libc export list.
    #[cfg(feature = "standalone")]
    {
        if symbol.is_null() || version.is_null() {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
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
        if !symbol_terminated || !version_terminated {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
            return std::ptr::null_mut();
        }
        let symbol_name = unsafe { std::slice::from_raw_parts(symbol as *const u8, symbol_len) };
        let version_name = unsafe { std::slice::from_raw_parts(version as *const u8, version_len) };
        // The libc-version allowlist applies only to this exported-symbol scope.
        if is_main_program_handle(handle) || is_rtld_default(handle) {
            if version_supported(version_name) {
                let sym = resolve_exported_symbol(symbol_name);
                if !sym.is_null() {
                    clear_dlerror();
                    return sym;
                }
            }
            // Plugin versions are defined by the object's own version table,
            // not the GLIBC allowlist used for the builtin export surface.
            if is_main_program_handle(handle)
                && let Some(Some(address)) =
                    resolve_native_dso_symbol(handle, symbol_name, Some(version_name))
            {
                clear_dlerror();
                return address;
            }
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
            return std::ptr::null_mut();
        }
        if let Some(symbol) = resolve_native_dso_symbol(handle, symbol_name, Some(version_name)) {
            return match symbol {
                Some(address) => {
                    clear_dlerror();
                    address
                }
                None => {
                    set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
                    std::ptr::null_mut()
                }
            };
        }
        // Reject foreign and stale handles without host delegation.
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        return std::ptr::null_mut();
    }
    #[cfg(not(feature = "standalone"))]
    if runtime_policy::bootstrap_passthrough_active() {
        if symbol.is_null() || version.is_null() {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
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
        if !symbol_terminated || !version_terminated {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
            return std::ptr::null_mut();
        }
        let symbol_name = unsafe { std::slice::from_raw_parts(symbol as *const u8, symbol_len) };
        let version_name = unsafe { std::slice::from_raw_parts(version as *const u8, version_len) };
        if !is_main_program_handle(handle) {
            if let Some(native_sym) =
                resolve_native_dso_symbol(handle, symbol_name, Some(version_name))
            {
                return if let Some(sym) = native_sym {
                    clear_dlerror();
                    sym
                } else {
                    set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
                    std::ptr::null_mut()
                };
            }
            if native_dso_id_from_handle(handle).is_some() {
                set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
                return std::ptr::null_mut();
            }
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

    let (symbol_len, symbol_terminated) = unsafe {
        crate::util::scan_c_string(symbol, crate::malloc_abi::known_remaining(symbol as usize))
    };
    let (version_len, version_terminated) = unsafe {
        crate::util::scan_c_string(
            version,
            crate::malloc_abi::known_remaining(version as usize),
        )
    };
    // Reject unterminated caller strings in every mode. Passing these through
    // to host dlvsym would let the dynamic linker walk beyond known allocation
    // bounds before it finds an accidental NUL.
    if !symbol_terminated || !version_terminated {
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

    if let Some(native_sym) = resolve_native_dso_symbol(handle, symbol_name, Some(version_name)) {
        // NULL can be a successful IFUNC result; absence is represented by None.
        let adverse = native_sym.is_none();
        let sym = native_sym.unwrap_or(std::ptr::null_mut());
        if adverse {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        } else {
            clear_dlerror();
        }
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
        return sym;
    }

    if native_dso_id_from_handle(handle).is_some() {
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
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
#[allow(unreachable_code)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dlclose(handle: *mut c_void) -> c_int {
    // Close owned handles through the native dependency/lifecycle collector.
    #[cfg(feature = "standalone")]
    {
        if handle.is_null() {
            set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
            return -1;
        }
        if is_main_program_handle(handle) {
            let rc = close_main_program_handle();
            if rc == 0 {
                clear_dlerror();
            } else {
                set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
            }
            return rc;
        }
        if let Some(rc) = close_native_dso(handle) {
            if rc == 0 {
                clear_dlerror();
            } else {
                set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
            }
            return rc;
        }
        // A foreign or stale handle cannot name a host-owned object here.
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        return -1;
    }
    #[cfg(not(feature = "standalone"))]
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
        if let Some(rc) = close_native_dso(handle) {
            if rc == 0 {
                clear_dlerror();
            } else {
                set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
            }
            return rc;
        }
        if native_dso_id_from_handle(handle).is_some() {
            set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
            return -1;
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

    if let Some(rc) = close_native_dso(handle) {
        let adverse = rc != 0;
        if adverse {
            set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        } else {
            clear_dlerror();
        }
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
        return rc;
    }

    if native_dso_id_from_handle(handle).is_some() {
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
    #[cfg(feature = "owned-tls-cache")]
    let ptr = DLERROR_OWNED_TLS.with(|state| {
        let ptr = state.pending as *const u8;
        state.pending = 0;
        if !ptr.is_null() {
            state.stable = ptr as usize;
            return state.stable as *const u8;
        }
        ptr
    });

    #[cfg(not(feature = "owned-tls-cache"))]
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
    #[cfg(not(feature = "owned-tls-cache"))]
    let _ = STABLE_PTR.try_with(|cell| cell.set(ptr));
    ptr as *const c_char
}

// ---------------------------------------------------------------------------
// dl_iterate_phdr / dladdr — native fallback (no host call-through)
// ---------------------------------------------------------------------------

/// `dl_iterate_phdr` — enumerate loaded shared objects.
///
/// Preserve the existing host/startup prefix and append the native load map.
/// Native membership is pinned before invoking either prefix or user code;
/// iteration itself holds neither native loader lock across those callbacks.
/// The cached host address avoids recursively resolving this same symbol.
#[allow(clippy::needless_return)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn dl_iterate_phdr(
    callback: Option<
        unsafe extern "C-unwind" fn(*mut libc::dl_phdr_info, usize, *mut c_void) -> c_int,
    >,
    data: *mut c_void,
) -> c_int {
    #[cfg(feature = "standalone")]
    {
        return unsafe { native::iterate_phdr(callback, data, Some(standalone_dl_iterate_phdr)) };
    }
    #[cfg(not(feature = "standalone"))]
    {
        type DlIteratePhdrFn = unsafe extern "C-unwind" fn(
            Option<
                unsafe extern "C-unwind" fn(*mut libc::dl_phdr_info, usize, *mut c_void) -> c_int,
            >,
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
            return unsafe { native::iterate_phdr(callback, data, Some(host_fn)) };
        }
        // Native mappings remain visible even without a host prefix.
        unsafe { native::iterate_phdr(callback, data, None) }
    }
}

#[cfg(feature = "standalone")]
const STANDALONE_DL_ITERATE_MAX_OBJECTS: usize = 256;
#[cfg(feature = "standalone")]
const STANDALONE_PAGE_MASK: u64 = !0xfff;

#[cfg(feature = "standalone")]
#[derive(Clone, Copy)]
struct StandaloneMapEntry {
    start: usize,
    offset: u64,
}

#[cfg(feature = "standalone")]
struct StandaloneMapObject {
    path: String,
    entries: Vec<StandaloneMapEntry>,
}

#[cfg(feature = "standalone")]
struct StandalonePhdrObject {
    base: usize,
    name: Vec<u8>,
    phdrs: Vec<libc::Elf64_Phdr>,
}

#[cfg(feature = "standalone")]
unsafe extern "C-unwind" fn standalone_dl_iterate_phdr(
    callback: Option<
        unsafe extern "C-unwind" fn(*mut libc::dl_phdr_info, usize, *mut c_void) -> c_int,
    >,
    data: *mut c_void,
) -> c_int {
    let Some(callback) = callback else {
        return 0;
    };

    for object in standalone_phdr_objects() {
        let mut info = libc::dl_phdr_info {
            dlpi_addr: object.base as libc::Elf64_Addr,
            dlpi_name: object.name.as_ptr().cast::<c_char>(),
            dlpi_phdr: object.phdrs.as_ptr(),
            dlpi_phnum: object.phdrs.len() as libc::Elf64_Half,
            dlpi_adds: 0,
            dlpi_subs: 0,
            dlpi_tls_modid: 0,
            dlpi_tls_data: std::ptr::null_mut(),
        };
        let rc = unsafe { callback(&mut info, core::mem::size_of::<libc::dl_phdr_info>(), data) };
        if rc != 0 {
            return rc;
        }
    }

    0
}

#[cfg(feature = "standalone")]
fn standalone_phdr_objects() -> Vec<StandalonePhdrObject> {
    let Some(map_objects) = standalone_map_objects() else {
        return Vec::new();
    };
    let mut objects = Vec::new();

    for map_object in map_objects
        .into_iter()
        .take(STANDALONE_DL_ITERATE_MAX_OBJECTS)
    {
        let Ok(bytes) = std::fs::read(&map_object.path) else {
            continue;
        };
        let Ok(loaded) = ElfLoader::new(0).parse(&bytes) else {
            continue;
        };
        let Some(base) = standalone_load_base(&loaded.program_headers, &map_object.entries) else {
            continue;
        };
        let phdrs = loaded
            .program_headers
            .iter()
            .map(libc_phdr_from_clean_room_header)
            .collect::<Vec<_>>();
        if phdrs.is_empty() {
            continue;
        }

        let mut name = map_object.path.into_bytes();
        name.push(0);
        objects.push(StandalonePhdrObject { base, name, phdrs });
    }

    objects
}

#[cfg(feature = "standalone")]
fn standalone_map_objects() -> Option<Vec<StandaloneMapObject>> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    let mut objects = Vec::<StandaloneMapObject>::new();

    for line in maps.lines() {
        let Some(entry) = frankenlibc_core::proc_maps::parse_maps_line(line) else {
            continue;
        };
        let Some(path) = entry.path else {
            continue;
        };
        if entry.inode == 0
            || !entry.perms.contains('r')
            || !path.starts_with('/')
            || path.ends_with(" (deleted)")
        {
            continue;
        }

        if let Some(existing) = objects.iter_mut().find(|object| object.path == path) {
            existing.entries.push(StandaloneMapEntry {
                start: entry.start,
                offset: entry.offset,
            });
            continue;
        }

        objects.push(StandaloneMapObject {
            path: path.to_owned(),
            entries: vec![StandaloneMapEntry {
                start: entry.start,
                offset: entry.offset,
            }],
        });
    }

    Some(objects)
}

#[cfg(feature = "standalone")]
fn standalone_load_base(
    phdrs: &[Elf64ProgramHeader],
    entries: &[StandaloneMapEntry],
) -> Option<usize> {
    for entry in entries {
        for phdr in phdrs.iter().filter(|phdr| phdr.is_load()) {
            if page_floor(phdr.p_offset) != entry.offset {
                continue;
            }
            let vaddr = usize::try_from(page_floor(phdr.p_vaddr)).ok()?;
            if let Some(base) = entry.start.checked_sub(vaddr) {
                return Some(base);
            }
        }
    }

    let min_load_vaddr = phdrs
        .iter()
        .filter(|phdr| phdr.is_load())
        .filter_map(|phdr| usize::try_from(page_floor(phdr.p_vaddr)).ok())
        .min()?;
    entries
        .iter()
        .find(|entry| entry.offset == 0)
        .and_then(|entry| entry.start.checked_sub(min_load_vaddr))
}

#[cfg(feature = "standalone")]
fn page_floor(value: u64) -> u64 {
    value & STANDALONE_PAGE_MASK
}

#[cfg(feature = "standalone")]
fn libc_phdr_from_clean_room_header(phdr: &Elf64ProgramHeader) -> libc::Elf64_Phdr {
    libc::Elf64_Phdr {
        p_type: program_type_to_raw(phdr.p_type),
        p_flags: phdr.p_flags.0,
        p_offset: phdr.p_offset as libc::Elf64_Off,
        p_vaddr: phdr.p_vaddr as libc::Elf64_Addr,
        p_paddr: phdr.p_paddr as libc::Elf64_Addr,
        p_filesz: phdr.p_filesz as libc::Elf64_Xword,
        p_memsz: phdr.p_memsz as libc::Elf64_Xword,
        p_align: phdr.p_align as libc::Elf64_Xword,
    }
}

#[cfg(feature = "standalone")]
fn program_type_to_raw(program_type: ProgramType) -> u32 {
    match program_type {
        ProgramType::Null => 0,
        ProgramType::Load => 1,
        ProgramType::Dynamic => 2,
        ProgramType::Interp => 3,
        ProgramType::Note => 4,
        ProgramType::Shlib => 5,
        ProgramType::Phdr => 6,
        ProgramType::Tls => 7,
        ProgramType::GnuEhFrame => 0x6474_e550,
        ProgramType::GnuStack => 0x6474_e551,
        ProgramType::GnuRelro => 0x6474_e552,
        ProgramType::GnuProperty => 0x6474_e553,
        ProgramType::Unknown(raw) => raw,
    }
}

/// `dladdr` — resolve address to shared object info.
///
/// Delegates to the host dynamic linker for correct DSO metadata.
#[allow(clippy::needless_return)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dladdr(addr: *const c_void, info: *mut c_void) -> c_int {
    if addr.is_null() || info.is_null() {
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        return 0;
    }
    // Standalone objects use the same retained native metadata as interpose.
    #[cfg(feature = "standalone")]
    {
        if unsafe { native::native_address_info(addr, info.cast::<libc::Dl_info>()) } {
            clear_dlerror();
            return 1;
        }
        set_dlerror(dlfcn_core::ERR_OPERATION_UNAVAILABLE);
        return 0;
    }
    #[cfg(not(feature = "standalone"))]
    {
        type DladdrFn = unsafe extern "C" fn(*const c_void, *mut c_void) -> c_int;
        if let Some(host_addr) = crate::host_resolve::host_dladdr_cached() {
            let host_fn: DladdrFn = unsafe { core::mem::transmute(host_addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
            let rc = unsafe { host_fn(addr, info) };
            if rc != 0 {
                clear_dlerror();
                return rc;
            }
        }
        // Host ld.so does not know the ABI loader's anonymous mappings.
        // Query native metadata only after the host call has released its lock.
        if unsafe { native::native_address_info(addr, info.cast::<libc::Dl_info>()) } {
            clear_dlerror();
            return 1;
        }
        set_dlerror(dlfcn_core::ERR_OPERATION_UNAVAILABLE);
        0
    }
}

// ---------------------------------------------------------------------------
// __libc_dlopen_mode / __libc_dlsym / __libc_dlclose
// (glibc internal aliases used by NSS, libidn, locale modules, audit hooks)
// ---------------------------------------------------------------------------

/// glibc internal `__libc_dlopen_mode(filename, mode)` — private
/// alias for [`dlopen`]. glibc-internal subsystems (NSS, libidn,
/// locale modules, audit hooks) link against this name to
/// dlopen-style load DSOs without entering the public name
/// namespace. The `mode` argument matches the public dlopen flags
/// (`RTLD_NOW | RTLD_LAZY | RTLD_GLOBAL | RTLD_LOCAL` etc.).
///
/// # Safety
///
/// Same as [`dlopen`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dlopen_mode(filename: *const c_char, mode: c_int) -> *mut c_void {
    unsafe { dlopen(filename, mode) }
}

/// glibc internal `__libc_dlsym(handle, name)` — private alias for
/// [`dlsym`].
///
/// # Safety
///
/// Same as [`dlsym`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void {
    unsafe { dlsym(handle, name) }
}

/// glibc internal `__libc_dlclose(handle)` — private alias for
/// [`dlclose`].
///
/// # Safety
///
/// Same as [`dlclose`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dlclose(handle: *mut c_void) -> c_int {
    unsafe { dlclose(handle) }
}
