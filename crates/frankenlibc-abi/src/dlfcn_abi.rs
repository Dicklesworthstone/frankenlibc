//! ABI layer for `<dlfcn.h>` functions.
//!
//! Dynamic linker interface: `dlopen`, `dlsym`, `dlclose`, `dlerror`.
//! Phase-1 replacement mode provides a native main-program handle and a
//! deterministic resolver for the exported FrankenLibC surface instead of
//! delegating back into the host loader.

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_core::dlfcn as dlfcn_core;
#[cfg(feature = "standalone")]
use frankenlibc_core::elf::{Elf64Header, Elf64ProgramHeader, ElfType, ProgramType};
#[cfg(feature = "standalone")]
use frankenlibc_core::proc_maps::MapsEntry;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

// ---------------------------------------------------------------------------
// Thread-local dlerror state
// ---------------------------------------------------------------------------

#[cfg(not(feature = "owned-tls-cache"))]
use std::cell::Cell;

#[derive(Clone, Copy, Default)]
struct DlErrorState {
    pending: usize,
    stable: usize,
}

static DLERROR_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<DlErrorState> =
    crate::owned_tls_cache::OwnedTlsCache::new(DlErrorState::default);

// Hosted dlerror state uses `Cell` with simple pointer get/set operations.
//
// `RefCell` panics on reentrant `borrow_mut()`, which happens during early
// startup when `dlsym` → `set_dlerror` → TLS init → `dlsym` → `clear_dlerror`
// creates a reentrant access. The hosted fast path therefore does not borrow
// or allocate. Native clones must use lifecycle-owned records instead: their
// inherited compiler TLS still belongs to the creator. Keep the creator's
// existing pending error and returned pointer in its original hosted record.
#[cfg(not(feature = "owned-tls-cache"))]
std::thread_local! {
    /// Pending error: pointer to static NUL-terminated error message, or null.
    static PENDING_PTR: Cell<*const u8> = const { Cell::new(std::ptr::null()) };
    /// Stable pointer returned by dlerror() — retired by the next dlerror call.
    static STABLE_PTR: Cell<*const u8> = const { Cell::new(std::ptr::null()) };
}

/// Publish only into the calling thread's error record. Static diagnostics,
/// borrowed host diagnostics, and successful calls must select the same owner.
fn set_dlerror_pointer(msg: *const u8) {
    #[cfg(not(feature = "owned-tls-cache"))]
    if !crate::owned_tls_cache::uses_owned_tls() {
        let _ = PENDING_PTR.try_with(|cell| cell.set(msg));
        return;
    }
    DLERROR_OWNED_TLS.with(|state| state.pending = msg as usize);
}

/// Set the thread-local dlerror message from a static byte slice.
fn set_dlerror(msg: &'static [u8]) {
    set_dlerror_pointer(msg.as_ptr());
}

/// Record a host-owned dlerror string (valid until the host's next dlerror on
/// this thread, which is also glibc's lifetime rule for the returned text).
#[cfg(not(feature = "standalone"))]
fn set_dlerror_host(msg: *const c_char) {
    set_dlerror_pointer(msg.cast::<u8>());
}

/// Interpose-mode host `dlopen`, carrying the host's own error text through to
/// our `dlerror` (e.g. "libfoo.so: cannot open shared object file: ...")
/// instead of a generic message.
#[cfg(not(feature = "standalone"))]
unsafe fn host_dlopen_with_error(filename: *const c_char, flags: c_int) -> *mut c_void {
    type DlopenFn = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
    let Some(addr) = crate::host_resolve::resolve_host_symbol_raw("dlopen") else {
        set_dlerror(dlfcn_core::ERR_NOT_FOUND);
        return std::ptr::null_mut();
    };
    let host_dlopen: DlopenFn = unsafe { core::mem::transmute(addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
    // RTLD_DEEPBIND puts the object's own dependencies -- libc.so.6 among
    // them -- ahead of the global scope that holds fl, so the host loader
    // would bind its malloc/free/stdio to glibc's while the rest of the
    // process uses fl's: two C runtimes sharing pointers, and the first
    // cross-heap free aborts (PHP loads every extension this way:
    // `php -r 'echo 1;'` died in munmap_chunk). One libc per process wins
    // over deep binding's precedence for clashing names, as with every
    // interposed allocator.
    let flags = flags & !dlfcn_core::RTLD_DEEPBIND;
    let handle = unsafe { host_dlopen(filename, flags) };
    // SAFETY: the result and any pending diagnostic belong to this host loader.
    unsafe { host_open_result(handle) }
}

/// Share the host error lifetime between ordinary and namespace-aware loads.
#[cfg(not(feature = "standalone"))]
unsafe fn host_open_result(handle: *mut c_void) -> *mut c_void {
    type DlerrorFn = unsafe extern "C" fn() -> *const c_char;
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

/// A non-base namespace belongs entirely to the host loader in interpose
/// builds. Preserve all flags: the base-namespace DEEPBIND adjustment must not
/// turn an explicitly isolated load into a shared-runtime load.
#[cfg(not(feature = "standalone"))]
unsafe fn host_dlmopen_with_error(
    lmid: libc::c_long,
    filename: *const c_char,
    flags: c_int,
) -> *mut c_void {
    type DlmopenFn = unsafe extern "C" fn(libc::c_long, *const c_char, c_int) -> *mut c_void;
    let Some(addr) = crate::host_resolve::resolve_host_symbol_raw("dlmopen") else {
        set_dlerror(dlfcn_core::ERR_OPERATION_UNAVAILABLE);
        return std::ptr::null_mut();
    };
    // SAFETY: the host symbol has dlmopen's GNU C ABI. Its namespace IDs and
    // returned opaque handles are interpreted only by the owning host loader.
    let host_dlmopen: DlmopenFn = unsafe { core::mem::transmute(addr) };
    let handle = unsafe { host_dlmopen(lmid, filename, flags) };
    // SAFETY: consume the diagnostic on the same hosted thread as the call.
    unsafe { host_open_result(handle) }
}

/// Pathname `dlopen` in interpose builds: the native loader is authoritative
/// for objects it fully supports; anything it cannot load (initial-exec TLS,
/// dependencies already owned by the host `ld.so`, unsupported relocations,
/// or a missing file) goes to the host loader, which is still in the process
/// at L0/L1. Failing instead broke every Python C extension import
/// (bd-rc0923-epic-eeuy4f.3). Standalone builds never reach this function.
#[cfg(not(feature = "standalone"))]
unsafe fn dlopen_pathname(name: &[u8], filename: *const c_char, flags: c_int) -> *mut c_void {
    let mut declined = None;
    if let Some(handle) = native::load_native_dso_with_declined(name, flags, &mut declined) {
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
            (st.st_mode & libc::S_IFMT) == libc::S_IFREG
                && match declined {
                    Some(declined)
                        if (st.st_dev, st.st_ino) == (declined.device(), declined.inode()) =>
                    {
                        declined
                            .parsed_host_verdict()
                            .unwrap_or_else(|| host_may_load_declined_object(name))
                    }
                    _ => host_may_load_declined_object(name),
                }
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
    set_dlerror_pointer(std::ptr::null());
}

/// Read only the hosted creator's record before an internal loader operation
/// that could invalidate borrowed host text. Native workers must never enter
/// that operation, even if their own record is empty.
#[cfg(not(feature = "standalone"))]
pub(super) fn hosted_dlerror_pointer_outstanding() -> bool {
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        PENDING_PTR
            .try_with(|pointer| !pointer.get().is_null())
            .unwrap_or(true)
            || STABLE_PTR
                .try_with(|pointer| !pointer.get().is_null())
                .unwrap_or(true)
    }
    #[cfg(feature = "owned-tls-cache")]
    {
        DLERROR_OWNED_TLS
            .try_peek(|state| state.pending != 0 || state.stable != 0)
            .unwrap_or(false)
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
        b"dlinfo" => crate::glibc_internal_abi::dlinfo as *const () as *mut c_void,
        b"dladdr1" => crate::glibc_internal_abi::dladdr1 as *const () as *mut c_void,
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

/// Standalone public lookups share the native import provider/version map.
/// A known name with an unsupported version must not reach the older generic
/// builtin allowlist. Public loader entrypoints still use their public wrappers.
#[cfg(feature = "standalone")]
fn resolve_standalone_export(symbol: &[u8], version: Option<&[u8]>) -> Option<*mut c_void> {
    let name = std::str::from_utf8(symbol).ok()?;
    let version_name = version.map(std::str::from_utf8).transpose().ok()?;
    if let Some(address) = native::runtime_export(name, version_name) {
        return address.map(|address| address as *mut c_void);
    }
    if version.is_some_and(|version| !version_supported(version)) {
        return None;
    }
    let address = resolve_exported_symbol(symbol);
    (!address.is_null()).then_some(address)
}

#[cfg(not(feature = "standalone"))]
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
    #[cfg(feature = "standalone")]
    {
        let _ = name;
        std::ptr::null_mut()
    }
    #[cfg(not(feature = "standalone"))]
    {
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
}

#[cfg(not(feature = "standalone"))]
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

/// Search the host prefix through a real main-program handle. RTLD_DEFAULT
/// is not interchangeable: a lookup through it may retain the provider as a
/// dependency of the caller, defeating a later dlclose of a GLOBAL plugin.
/// Some(NULL) is a successful IFUNC result; None is an actual lookup miss.
#[cfg(not(feature = "standalone"))]
unsafe fn host_main_program_symbol(
    symbol: *const c_char,
    version: Option<*const c_char>,
) -> Option<*mut c_void> {
    type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
    type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
    type Error = unsafe extern "C" fn() -> *const c_char;
    type Lookup = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
    type VersionedLookup =
        unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> *mut c_void;

    // Resolve every entry point before clearing the host's thread-local error;
    // resolving a helper must not contaminate the result of the actual lookup.
    let open = crate::host_resolve::resolve_host_symbol_raw("dlopen")?;
    let close = crate::host_resolve::resolve_host_symbol_raw("dlclose")?;
    let error = crate::host_resolve::resolve_host_symbol_raw("dlerror")?;
    let lookup = crate::host_resolve::resolve_host_symbol_raw(if version.is_some() {
        "dlvsym"
    } else {
        "dlsym"
    })?;
    // SAFETY: these are host-owned symbols with the declared C ABI signatures.
    let open: Open = unsafe { core::mem::transmute(open) };
    let close: Close = unsafe { core::mem::transmute(close) };
    let error: Error = unsafe { core::mem::transmute(error) };
    let main = unsafe { open(std::ptr::null(), dlfcn_core::RTLD_NOW) };
    if main.is_null() {
        let _ = unsafe { error() };
        return None;
    }
    let _ = unsafe { error() };
    // SAFETY: the public ABI has bounded both strings, and main is a live host
    // handle. No native registry lock is held across the host/IFUNC callbacks.
    let address = unsafe {
        if let Some(version) = version {
            let lookup: VersionedLookup = core::mem::transmute(lookup);
            lookup(main, symbol, version)
        } else {
            let lookup: Lookup = core::mem::transmute(lookup);
            lookup(main, symbol)
        }
    };
    let failed = !unsafe { error() }.is_null();
    // Balance the temporary reference. Capture lookup status before dlclose
    // can change the host error state; never infer failure from address == 0.
    let _ = unsafe { close(main) };
    (!failed).then_some(address)
}

unsafe fn resolve_main_program_symbol(
    symbol: *const c_char,
    symbol_name: &[u8],
) -> Option<*mut c_void> {
    #[cfg(feature = "standalone")]
    let _ = symbol;
    let sym = resolve_exported_symbol(symbol_name);
    if !sym.is_null() {
        return Some(sym);
    }
    #[cfg(not(feature = "standalone"))]
    if let Some(sym) = unsafe { host_main_program_symbol(symbol, None) } {
        return Some(sym);
    }
    // Host-owned globals retain their prefix precedence. Native GLOBAL
    // objects then participate in promotion order, with LOCAL objects excluded.
    resolve_native_dso_symbol(main_program_handle(), symbol_name, None).flatten()
}

// This API family has its own compatibility versions. Outer None means a
// different symbol; Some(None) is a recognized name with an unsupported
// version. Do not fall through to the generic GLIBC builtin allowlist then.
fn introspection_export(symbol: &[u8], version: &[u8]) -> Option<Option<*mut c_void>> {
    let name = match symbol {
        b"dlinfo" => "dlinfo",
        b"dladdr1" => "dladdr1",
        _ => return None,
    };
    let supported = std::str::from_utf8(version)
        .ok()
        .and_then(|version| native::info_resolver_address(name, Some(version)));
    // Return the public wrapper, not the private plugin bridge: unversioned
    // and compatibility-version lookups must name the same public function.
    Some(supported.map(|_| resolve_exported_symbol(symbol)))
}

unsafe fn resolve_main_program_versioned_symbol(
    symbol: *const c_char,
    version: *const c_char,
    symbol_name: &[u8],
    version_name: &[u8],
) -> Option<*mut c_void> {
    #[cfg(feature = "standalone")]
    let _ = (symbol, version);
    if let Some(result) = introspection_export(symbol_name, version_name) {
        return result;
    }
    if version_supported(version_name) {
        let native = resolve_exported_symbol(symbol_name);
        if !native.is_null() {
            return Some(native);
        }
    }
    #[cfg(not(feature = "standalone"))]
    if let Some(sym) = unsafe { host_main_program_symbol(symbol, Some(version)) } {
        return Some(sym);
    }
    resolve_native_dso_symbol(main_program_handle(), symbol_name, Some(version_name)).flatten()
}

fn open_main_program_handle() -> *mut c_void {
    MAIN_PROGRAM_REFS.fetch_add(1, Ordering::Relaxed);
    main_program_handle()
}

fn close_main_program_handle() -> c_int {
    let _ = MAIN_PROGRAM_REFS.try_update(Ordering::Relaxed, Ordering::Relaxed, |refs| {
        if refs > 0 { Some(refs - 1) } else { None }
    });
    0
}

#[path = "dlfcn_native.rs"]
mod native;
pub(crate) use native::fork_prepare as native_fork_prepare;
#[cfg(not(feature = "standalone"))]
use native::host_may_load_declined_object;
#[cfg(feature = "standalone")]
use native::load_native_dso;
#[cfg(not(test))]
pub(crate) use native::{ThreadExitForkGuard, lock_thread_exit_for_fork};
use native::{close_native_dso, native_dso_id_from_handle, resolve_native_dso_symbol};
pub(crate) use native::{
    drain_current_thread_tls_destructors, prepare_native_public_tls_destructors,
    register_native_public_tls_destructor,
};
pub(crate) use native::{find_native_object, native_address_info_extra, query_object_info};

#[cfg(any(feature = "standalone", feature = "conformance-testing"))]
pub(crate) fn native_tls_address(module_id: usize, offset: usize) -> *mut c_void {
    native::tls_address(module_id, offset)
}

#[doc(hidden)]
pub use native::native_dso_handle_for_tests;

#[cfg(not(feature = "standalone"))]
fn is_pathname(name: &[u8]) -> bool {
    name.contains(&b'/')
}

/// A pathname-loaded native object must retain its identity when reopened by
/// SONAME. Only an absent native name may use the existing host search path;
/// a rejected reopen must not be rescued by loading a second host-owned copy.
#[cfg(not(feature = "standalone"))]
unsafe fn dlopen_soname(name: &[u8], filename: *const c_char, flags: c_int) -> *mut c_void {
    match native::reopen_native_soname(name, flags) {
        native::NativeReopen::Opened(handle) => {
            clear_dlerror();
            handle
        }
        native::NativeReopen::Rejected => {
            set_dlerror(dlfcn_core::ERR_NOT_FOUND);
            std::ptr::null_mut()
        }
        // SAFETY: the caller validated the original bounded C string and flags.
        native::NativeReopen::Missing => unsafe { host_dlopen_with_error(filename, flags) },
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

/// Shared implementation for the GNU dlmopen export. Namespace identity is
/// part of the request: only LM_ID_BASE may enter the native base loader.
/// Other namespaces must never silently reuse base handles or global state.
pub(crate) unsafe fn open_namespace(
    lmid: libc::c_long,
    filename: *const c_char,
    flags: c_int,
) -> *mut c_void {
    if lmid == 0 {
        // SAFETY: LM_ID_BASE retains the existing dlopen argument contract.
        return unsafe { dlopen(filename, flags) };
    }

    #[cfg(feature = "standalone")]
    {
        let _ = (filename, flags);
        // The owned loader currently has one namespace. Report that boundary
        // instead of returning a successful base-namespace alias.
        set_dlerror(dlfcn_core::ERR_OPERATION_UNAVAILABLE);
        std::ptr::null_mut()
    }
    #[cfg(not(feature = "standalone"))]
    {
        // Native clones still share their creator's compiler TLS. Entering
        // host ld.so here would mutate the creator's loader/allocator state.
        if frankenlibc_core::pthread::thread::current_thread_handle().is_some()
            || crate::malloc_abi::raw_shared_tls_clone_active()
        {
            set_dlerror(dlfcn_core::ERR_OPERATION_UNAVAILABLE);
            return std::ptr::null_mut();
        }
        // GNU documents at most 16 namespaces, including LM_ID_BASE. Reject
        // IDs outside that public range before entering the host: some GNU
        // versions leave loader state locked after an invalid-target error.
        // Live IDs within the range remain the host's responsibility, including
        // namespaces created externally and discovered through dlinfo.
        const HOST_NAMESPACE_LIMIT: libc::c_long = 16;
        if lmid < -1 || lmid >= HOST_NAMESPACE_LIMIT {
            set_dlerror(b"invalid target namespace in dlmopen()\0");
            return std::ptr::null_mut();
        }
        // SAFETY: use the same caller-string validation as public dlopen.
        if !filename.is_null() && unsafe { bounded_cstr_bytes(filename) }.is_none() {
            set_dlerror(dlfcn_core::ERR_NOT_FOUND);
            return std::ptr::null_mut();
        }
        let decision = if runtime_policy::bootstrap_passthrough_active() {
            None
        } else {
            let (_, decision) =
                runtime_policy::decide(ApiFamily::Loader, filename as usize, 0, false, true, 0);
            Some(decision)
        };
        if let Some(decision) = &decision
            && matches!(decision.action, MembraneAction::Deny)
        {
            set_dlerror(dlfcn_core::ERR_NOT_FOUND);
            runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
            return std::ptr::null_mut();
        }
        // SAFETY: the non-null filename was bounded above; null filenames and
        // invalid/nonexistent namespace IDs retain the host's error contract.
        // No native registry lock crosses host constructors or finalizers.
        let handle = unsafe { host_dlmopen_with_error(lmid, filename, flags) };
        if let Some(decision) = decision {
            runtime_policy::observe(ApiFamily::Loader, decision.profile, 12, handle.is_null());
        }
        handle
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
        return unsafe { dlopen_soname(name, filename, flags) };
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
            unsafe { dlopen_soname(name, filename, flags) }
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
        // Builtins retain their existing precedence. Public standalone main
        // and DEFAULT lookups then search GLOBAL plugins. DEFAULT retains its
        // successful provider for the program; explicit handles do not.
        // Native import bridges keep their caller-relative scope and lifetime.
        if is_main_program_handle(handle) || is_rtld_default(handle) {
            if let Some(address) = resolve_standalone_export(symbol_name, None) {
                clear_dlerror();
                return address;
            }
            let global = if is_rtld_default(handle) {
                native::resolve_program_default_symbol(symbol_name, None)
            } else {
                resolve_native_dso_symbol(handle, symbol_name, None)
            };
            if let Some(Some(address)) = global {
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
        let resolved = unsafe { resolve_main_program_symbol(symbol, symbol_name) };
        if resolved.is_none() {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        } else {
            clear_dlerror();
        }
        return resolved.unwrap_or(std::ptr::null_mut());
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
        #[cfg(feature = "standalone")]
        let sym = if is_rtld_default(handle) {
            resolve_exported_symbol(symbol_name)
        } else {
            std::ptr::null_mut()
        };
        #[cfg(not(feature = "standalone"))]
        let sym = {
            let host_handle = if is_rtld_default(handle) {
                libc::RTLD_DEFAULT
            } else {
                libc::RTLD_NEXT
            };
            unsafe { host_dlsym(host_handle, symbol) }.unwrap_or_else(|| {
                if is_rtld_default(handle) {
                    resolve_exported_symbol(symbol_name)
                } else {
                    std::ptr::null_mut()
                }
            })
        };
        let adverse = sym.is_null();
        if adverse {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        } else {
            clear_dlerror();
        }
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
        return sym;
    }

    // The explicit main handle must search builtins/host globals before
    // native globals. Ordinary owned handles keep their dependency scope.
    if !is_main_program_handle(handle)
        && let Some(native_sym) = resolve_native_dso_symbol(handle, symbol_name, None)
    {
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
        #[cfg(not(feature = "standalone"))]
        {
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
        }
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    let resolved = unsafe { resolve_main_program_symbol(symbol, symbol_name) };
    let adverse = resolved.is_none();
    if adverse {
        set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
    } else {
        clear_dlerror();
    }
    runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
    resolved.unwrap_or(std::ptr::null_mut())
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
            if let Some(result) = introspection_export(symbol_name, version_name) {
                return match result {
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
            if let Some(address) = resolve_standalone_export(symbol_name, Some(version_name)) {
                clear_dlerror();
                return address;
            }
            // Plugin versions are defined by the object's own version table,
            // not the GLIBC allowlist used for the builtin export surface.
            let global = if is_rtld_default(handle) {
                native::resolve_program_default_symbol(symbol_name, Some(version_name))
            } else {
                resolve_native_dso_symbol(handle, symbol_name, Some(version_name))
            };
            if let Some(Some(address)) = global {
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
        let resolved = unsafe {
            resolve_main_program_versioned_symbol(symbol, version, symbol_name, version_name)
        };
        if resolved.is_none() {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        } else {
            clear_dlerror();
        }
        return resolved.unwrap_or(std::ptr::null_mut());
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
        #[cfg(feature = "standalone")]
        let sym = if is_rtld_default(handle) && version_supported(version_name) {
            resolve_exported_symbol(symbol_name)
        } else {
            std::ptr::null_mut()
        };
        #[cfg(not(feature = "standalone"))]
        let sym = {
            let host_handle = if is_rtld_default(handle) {
                libc::RTLD_DEFAULT
            } else {
                libc::RTLD_NEXT
            };
            unsafe { host_dlvsym(host_handle, symbol, version) }.unwrap_or_else(|| {
                if is_rtld_default(handle) && version_supported(version_name) {
                    resolve_exported_symbol(symbol_name)
                } else {
                    std::ptr::null_mut()
                }
            })
        };
        let adverse = sym.is_null();
        if adverse {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        } else {
            clear_dlerror();
        }
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
        return sym;
    }

    if !is_main_program_handle(handle)
        && let Some(native_sym) = resolve_native_dso_symbol(handle, symbol_name, Some(version_name))
    {
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
        #[cfg(not(feature = "standalone"))]
        {
            // Handle is from host dlopen — delegate to host dlvsym.
            let sym =
                unsafe { host_dlvsym(handle, symbol, version) }.unwrap_or(std::ptr::null_mut());
            let adverse = sym.is_null();
            if adverse {
                set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
            } else {
                clear_dlerror();
            }
            runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
            return sym;
        }
        #[cfg(feature = "standalone")]
        {
            set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
            runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
            return std::ptr::null_mut();
        }
    }

    let resolved = unsafe {
        resolve_main_program_versioned_symbol(symbol, version, symbol_name, version_name)
    };
    let adverse = resolved.is_none();
    if adverse {
        set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
    } else {
        clear_dlerror();
    }
    runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
    resolved.unwrap_or(std::ptr::null_mut())
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
        #[cfg(not(feature = "standalone"))]
        {
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
    #[cfg(not(feature = "owned-tls-cache"))]
    if !crate::owned_tls_cache::uses_owned_tls() {
        let ptr = PENDING_PTR
            .try_with(|cell| cell.replace(std::ptr::null()))
            .unwrap_or(std::ptr::null());
        // The next explicit dlerror call retires our previous returned-pointer
        // marker, including when there is no new error. Other loader calls
        // leave this conservative marker intact; internal preparation must
        // not release it on the caller's behalf.
        let _ = STABLE_PTR.try_with(|cell| cell.set(ptr));
        return ptr.cast::<c_char>();
    }

    DLERROR_OWNED_TLS.with(|state| {
        let ptr = state.pending;
        state.pending = 0;
        state.stable = ptr;
        ptr as *const c_char
    })
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
const STANDALONE_DL_ITERATE_MAX_PHDRS: usize = 4096;

#[cfg(feature = "standalone")]
struct StandalonePhdrObject {
    base: usize,
    source_table: usize,
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
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return Vec::new();
    };
    let entries = maps
        .lines()
        .filter_map(frankenlibc_core::proc_maps::parse_maps_line)
        .collect::<Vec<_>>();
    // Auxv identifies the executable and vDSO independently of their names
    // and the continued existence of their backing files. Preserve caller errno
    // when an optional auxv entry such as `AT_SYSINFO_EHDR` is absent.
    let main_phdr =
        unsafe { crate::stdlib_abi::getauxval_preserving_errno(libc::AT_PHDR) } as usize;
    let main_count =
        unsafe { crate::stdlib_abi::getauxval_preserving_errno(libc::AT_PHNUM) } as usize;
    let vdso =
        unsafe { crate::stdlib_abi::getauxval_preserving_errno(libc::AT_SYSINFO_EHDR) } as usize;
    let mut objects = Vec::<StandalonePhdrObject>::new();
    if let Some(main) = standalone_main_phdr_object(&entries, main_phdr, main_count) {
        objects.push(main);
    }

    // Reserve the bounded prefix's first entries for the process-lifetime
    // executable and vDSO, even when many file-backed images are present.
    for entry in entries
        .iter()
        .filter(|entry| vdso != 0 && entry.start == vdso)
        .chain(
            entries
                .iter()
                .filter(|entry| vdso == 0 || entry.start != vdso),
        )
    {
        if objects.len() == STANDALONE_DL_ITERATE_MAX_OBJECTS {
            break;
        }
        if entry.offset != 0
            || !entry.perms.contains('r')
            || !(entry.inode != 0
                || (vdso != 0 && entry.start == vdso && entry.path == Some("[vdso]")))
        {
            continue;
        }
        let Some(object) = standalone_mapped_phdr_object(entry, &entries) else {
            continue;
        };
        if objects
            .iter()
            .any(|existing| existing.source_table == object.source_table)
        {
            continue;
        }
        let mut object = object;
        if object.source_table == main_phdr && object.phdrs.len() == main_count {
            // dl_iterate_phdr(3): the executable is first with an empty name.
            object.name = vec![0];
            objects.insert(0, object);
        } else if vdso != 0 && entry.start == vdso {
            // Both supported Linux ABIs (x86_64 and aarch64) use this name.
            object.name = b"linux-vdso.so.1\0".to_vec();
            let after_main = usize::from(objects.first().is_some_and(|first| first.name == [0]));
            objects.insert(after_main, object);
        } else {
            objects.push(object);
        }
    }

    objects
}

#[cfg(feature = "standalone")]
fn standalone_main_phdr_object(
    entries: &[MapsEntry<'_>],
    table: usize,
    count: usize,
) -> Option<StandalonePhdrObject> {
    let stride = unsafe { crate::stdlib_abi::getauxval_preserving_errno(libc::AT_PHENT) } as usize;
    if table == 0
        || count == 0
        || count > STANDALONE_DL_ITERATE_MAX_PHDRS
        || stride != Elf64ProgramHeader::SIZE
        || !table.is_multiple_of(std::mem::align_of::<libc::Elf64_Phdr>())
    {
        return None;
    }
    let origin = entries
        .iter()
        .find(|entry| entry.start <= table && table < entry.end)?;
    let offset = origin.offset.checked_add((table - origin.start) as u64)?;
    let length = count.checked_mul(stride)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).ok()?;
    bytes.resize(length, 0);
    standalone_copy_mapped(entries, origin, table, offset, &mut bytes)?;
    let mut headers = Vec::new();
    headers.try_reserve_exact(count).ok()?;
    for bytes in bytes.chunks_exact(stride) {
        headers.push(Elf64ProgramHeader::parse(bytes).ok()?);
    }
    let phdrs = headers
        .iter()
        .map(libc_phdr_from_clean_room_header)
        .collect::<Vec<_>>();
    let entry = unsafe { crate::stdlib_abi::getauxval_preserving_errno(libc::AT_ENTRY) } as usize;
    // The executable's ELF header need not itself be mapped. The shared
    // startup helper derives bias from PT_PHDR, or proves fixed ET_EXEC when
    // PT_PHDR is absent. The published program headers always come from the
    // live auxv table, including when that fallback reads the file's ELF header.
    let base = crate::startup_abi::executable_load_bias(table, &phdrs, Some(entry)).ok()?;
    if !standalone_loads_match_mappings(base, &headers, table, offset, length, origin, entries) {
        return None;
    }
    Some(StandalonePhdrObject {
        base,
        source_table: table,
        name: vec![0],
        phdrs,
    })
}

#[cfg(feature = "standalone")]
fn standalone_mapped_phdr_object(
    origin: &MapsEntry<'_>,
    entries: &[MapsEntry<'_>],
) -> Option<StandalonePhdrObject> {
    // /proc/self/maps is an address/identity index, never a reason to reopen
    // its path. An unlink, rename, replacement, or memfd must not change the
    // metadata describing code already mapped into this process.
    let mut header_bytes = [0u8; Elf64Header::SIZE];
    standalone_copy_mapped(entries, origin, origin.start, 0, &mut header_bytes)?;
    let header = Elf64Header::parse(&header_bytes).ok()?;
    let native_machine = if cfg!(target_arch = "x86_64") {
        62
    } else {
        183
    };
    if !matches!(header.e_type, ElfType::Exec | ElfType::Dyn)
        || header.e_machine.to_u16() != native_machine
        || header.e_ident[6] != 1
        || header.e_version != 1
        || usize::from(header.e_ehsize) != Elf64Header::SIZE
        || usize::from(header.e_phentsize) != Elf64ProgramHeader::SIZE
        || header.e_phnum == 0
        || usize::from(header.e_phnum) > STANDALONE_DL_ITERATE_MAX_PHDRS
        || header.e_phoff < Elf64Header::SIZE as u64
    {
        return None;
    }
    let table_len = usize::from(header.e_phnum).checked_mul(Elf64ProgramHeader::SIZE)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(table_len).ok()?;
    bytes.resize(table_len, 0);
    // e_phoff is a file offset, not a virtual offset from the ELF header.
    // The table can occupy a different PT_LOAD. The decoded load geometry
    // must bind each candidate to this particular header and load bias.
    'candidate: for mapping in entries {
        if mapping.inode != origin.inode
            || mapping.dev != origin.dev
            || (origin.inode == 0 && mapping.path != origin.path)
            || !mapping.perms.contains('r')
        {
            continue;
        }
        let Some(delta) = header
            .e_phoff
            .checked_sub(mapping.offset)
            .and_then(|offset| usize::try_from(offset).ok())
        else {
            continue;
        };
        let Some(table) = mapping
            .start
            .checked_add(delta)
            .filter(|table| *table < mapping.end)
        else {
            continue;
        };
        if standalone_copy_mapped(entries, origin, table, header.e_phoff, &mut bytes).is_none() {
            continue;
        }
        let mut headers = Vec::new();
        headers
            .try_reserve_exact(usize::from(header.e_phnum))
            .ok()?;
        for bytes in bytes.chunks_exact(Elf64ProgramHeader::SIZE) {
            let Ok(header) = Elf64ProgramHeader::parse(bytes) else {
                continue 'candidate;
            };
            headers.push(header);
        }
        let Some(base) = standalone_load_base(&header, &headers, table, origin, entries) else {
            continue;
        };
        let mut name = origin.path.unwrap_or("").as_bytes().to_vec();
        name.push(0);
        let phdrs = headers
            .iter()
            .map(libc_phdr_from_clean_room_header)
            .collect();
        return Some(StandalonePhdrObject {
            base,
            source_table: table,
            name,
            phdrs,
        });
    }
    None
}

#[cfg(feature = "standalone")]
fn standalone_load_base(
    header: &Elf64Header,
    phdrs: &[Elf64ProgramHeader],
    table: usize,
    origin: &MapsEntry<'_>,
    entries: &[MapsEntry<'_>],
) -> Option<usize> {
    let table_len = usize::from(header.e_phnum).checked_mul(Elf64ProgramHeader::SIZE)?;
    for first in phdrs.iter().filter(|phdr| {
        phdr.is_load() && phdr.p_offset == 0 && phdr.p_filesz >= Elf64Header::SIZE as u64
    }) {
        let Some(base) = origin
            .start
            .checked_sub(usize::try_from(first.p_vaddr).ok()?)
        else {
            continue;
        };
        if header.is_executable() && base != 0 {
            continue;
        }
        if standalone_loads_match_mappings(
            base,
            phdrs,
            table,
            header.e_phoff,
            table_len,
            origin,
            entries,
        ) {
            return Some(base);
        }
    }
    None
}

#[cfg(feature = "standalone")]
fn standalone_loads_match_mappings(
    base: usize,
    phdrs: &[Elf64ProgramHeader],
    table: usize,
    table_offset: u64,
    table_len: usize,
    origin: &MapsEntry<'_>,
    entries: &[MapsEntry<'_>],
) -> bool {
    let Some(table_end) = table_offset.checked_add(table_len as u64) else {
        return false;
    };
    let mut table_is_loaded = false;
    let valid = phdrs.iter().filter(|phdr| phdr.is_load()).all(|phdr| {
        let Some(start) = usize::try_from(phdr.p_vaddr)
            .ok()
            .and_then(|v| base.checked_add(v))
        else {
            return false;
        };
        let (Ok(filesz), Ok(memsz)) = (
            usize::try_from(phdr.p_filesz),
            usize::try_from(phdr.p_memsz),
        ) else {
            return false;
        };
        let Some(file_end) = phdr.p_offset.checked_add(phdr.p_filesz) else {
            return false;
        };
        if filesz > memsz
            || !phdr.is_valid_alignment()
            || (phdr.p_align > 1 && phdr.p_vaddr % phdr.p_align != phdr.p_offset % phdr.p_align)
            || !standalone_mapped_range(entries, None, start, memsz, None, phdr.p_flags.0)
            || !standalone_mapped_range(
                entries,
                Some(origin),
                start,
                filesz,
                Some(phdr.p_offset),
                phdr.p_flags.0,
            )
        {
            return false;
        }
        if phdr.p_flags.is_readable()
            && phdr.p_offset <= table_offset
            && table_end <= file_end
            && usize::try_from(table_offset - phdr.p_offset)
                .ok()
                .and_then(|offset| start.checked_add(offset))
                == Some(table)
        {
            table_is_loaded = true;
        }
        true
    });
    valid && table_is_loaded
}

#[cfg(feature = "standalone")]
fn standalone_mapped_range(
    entries: &[MapsEntry<'_>],
    origin: Option<&MapsEntry<'_>>,
    start: usize,
    bytes: usize,
    offset: Option<u64>,
    flags: u32,
) -> bool {
    let Some(end) = start.checked_add(bytes) else {
        return false;
    };
    let mut cursor = start;
    while cursor < end {
        let Some(entry) = entries
            .iter()
            .find(|entry| entry.start <= cursor && cursor < entry.end)
        else {
            return false;
        };
        if (flags & libc::PF_R != 0 && !entry.perms.contains('r'))
            || (flags & libc::PF_X != 0 && !entry.perms.contains('x'))
            || origin.is_some_and(|origin| {
                origin.inode != entry.inode
                    || origin.dev != entry.dev
                    || (origin.inode == 0 && origin.path != entry.path)
            })
        {
            return false;
        }
        if let Some(offset) = offset {
            let expected = offset.checked_add((cursor - start) as u64);
            let actual = entry.offset.checked_add((cursor - entry.start) as u64);
            if expected.is_none() || expected != actual {
                return false;
            }
        }
        cursor = end.min(entry.end);
    }
    true
}

#[cfg(feature = "standalone")]
fn standalone_copy_mapped(
    entries: &[MapsEntry<'_>],
    origin: &MapsEntry<'_>,
    address: usize,
    offset: u64,
    destination: &mut [u8],
) -> Option<()> {
    if !standalone_mapped_range(
        entries,
        Some(origin),
        address,
        destination.len(),
        Some(offset),
        libc::PF_R,
    ) {
        return None;
    }
    // SAFETY: the destination is exclusively borrowed initialized storage.
    // The source remains an integer address passed to the existing raw kernel
    // copy. A concurrent unmap/protection change or a partial read fails closed
    // without constructing a Rust reference to possibly vanished memory.
    unsafe {
        crate::io_abi::iov_snapshot::copy_user_bytes_raw(
            address as *const u8,
            destination.as_mut_ptr(),
            destination.len(),
        )
    }
    .ok()
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
/// Per glibc `dladdr(3)`, `dladdr` never modifies `dlerror()`.
#[allow(clippy::needless_return)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dladdr(addr: *const c_void, info: *mut c_void) -> c_int {
    if addr.is_null() || info.is_null() {
        return 0;
    }
    // Standalone objects use the same retained native metadata as interpose.
    #[cfg(feature = "standalone")]
    {
        if unsafe { native::native_address_info(addr, info.cast::<libc::Dl_info>()) } {
            return 1;
        }
        return 0;
    }
    #[cfg(not(feature = "standalone"))]
    {
        type DladdrFn = unsafe extern "C" fn(*const c_void, *mut c_void) -> c_int;
        if let Some(host_addr) = crate::host_resolve::host_dladdr_cached() {
            let host_fn: DladdrFn = unsafe { core::mem::transmute(host_addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
            let rc = unsafe { host_fn(addr, info) };
            if rc != 0 {
                return rc;
            }
        }
        // Host ld.so does not know the ABI loader's anonymous mappings.
        // Query native metadata only after the host call has released its lock.
        if unsafe { native::native_address_info(addr, info.cast::<libc::Dl_info>()) } {
            return 1;
        }
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
