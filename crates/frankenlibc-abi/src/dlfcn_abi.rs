//! ABI layer for `<dlfcn.h>` functions.
//!
//! Dynamic linker interface: `dlopen`, `dlsym`, `dlclose`, `dlerror`.
//! Phase-1 replacement mode provides a native main-program handle and a
//! deterministic resolver for the exported FrankenLibC surface instead of
//! delegating back into the host loader.

use std::ffi::{c_char, c_int, c_void};
use std::sync::{Mutex, OnceLock};

use frankenlibc_core::dlfcn as dlfcn_core;
use frankenlibc_core::elf::{
    ElfLoader, LoadedObject, PltBindingPolicy, RelocationResult, SymbolLookup,
};
use frankenlibc_core::syscall as raw_syscall;
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

const NATIVE_DSO_HANDLE_TAG: usize = 0x4d;
const NATIVE_DSO_HANDLE_MASK: usize = 0xff;

#[derive(Debug)]
struct NativeDso {
    id: usize,
    base: usize,
    map_len: usize,
    object: LoadedObject,
}

static NATIVE_DSOS: OnceLock<Mutex<Vec<NativeDso>>> = OnceLock::new();
static NEXT_NATIVE_DSO_ID: AtomicUsize = AtomicUsize::new(1);

fn native_dso_registry() -> &'static Mutex<Vec<NativeDso>> {
    NATIVE_DSOS.get_or_init(|| Mutex::new(Vec::new()))
}

fn native_dso_handle(id: usize) -> *mut c_void {
    ((id << 8) | NATIVE_DSO_HANDLE_TAG) as *mut c_void
}

fn native_dso_id_from_handle(handle: *mut c_void) -> Option<usize> {
    let raw = handle as usize;
    if raw & NATIVE_DSO_HANDLE_MASK == NATIVE_DSO_HANDLE_TAG {
        Some(raw >> 8)
    } else {
        None
    }
}

#[doc(hidden)]
pub fn native_dso_handle_for_tests(handle: *mut c_void) -> bool {
    let Some(id) = native_dso_id_from_handle(handle) else {
        return false;
    };
    native_dso_registry()
        .lock()
        .map(|dsos| dsos.iter().any(|dso| dso.id == id))
        .unwrap_or(false)
}

fn is_pathname(name: &[u8]) -> bool {
    name.contains(&b'/')
}

fn load_native_dso(name: &[u8], flags: c_int) -> Option<*mut c_void> {
    if (flags & dlfcn_core::RTLD_NOLOAD) != 0 {
        return None;
    }
    let path = std::str::from_utf8(name).ok()?;
    let bytes = std::fs::read(path).ok()?;

    let preview_loader = ElfLoader::new(0);
    let preview_object = preview_loader.parse(&bytes).ok()?;
    if !native_dso_object_supported(&preview_object) {
        return None;
    }
    let image = preview_loader
        .materialize_load_image(&bytes, &preview_object)
        .ok()?;
    if image.low_vaddr != 0 || image.memory.is_empty() {
        return None;
    }

    let map_len = image.memory.len();
    // SAFETY: anonymous private mapping, initially writable for loader relocation.
    let base = match unsafe {
        raw_syscall::sys_mmap(
            std::ptr::null_mut(),
            map_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    } {
        Ok(ptr) => ptr,
        Err(_) => return None,
    };

    let loaded = (|| {
        // SAFETY: sys_mmap returned a valid mapping of map_len bytes above.
        let memory = unsafe { core::slice::from_raw_parts_mut(base, map_len) };
        memory.copy_from_slice(&image.memory);

        let loader = ElfLoader::new(base as u64);
        let object = loader.parse(&bytes).ok()?;
        let registry = native_dso_registry().lock().ok()?;
        let resolver = NativeDsoResolver {
            dsos: registry.as_slice(),
        };
        let relocation_report = loader.apply_relocations_with_policy(
            &object,
            memory,
            &resolver,
            PltBindingPolicy::Eager,
        );
        if !relocation_report_succeeded(&relocation_report.events) {
            return None;
        }
        drop(registry);

        for segment in &image.segments {
            let offset = usize::try_from(segment.map_addr).ok()?;
            // SAFETY: segment.map_addr is bounded by the materialized load image.
            let addr = unsafe { base.add(offset) };
            let len = usize::try_from(segment.map_size).ok()?;
            // SAFETY: addr/len are page-aligned mapping decisions from the ELF load image.
            if unsafe { raw_syscall::sys_mprotect(addr, len, segment.prot) }.is_err() {
                return None;
            }
        }

        if let Some(relro_range) = image.relro_range {
            let relro_start = relro_range.start & !0xfff;
            let relro_end = (relro_range.end + 0xfff) & !0xfff;
            if relro_end > relro_start {
                // SAFETY: RELRO range is derived from the materialized load image.
                let addr = unsafe { base.add(relro_start) };
                // SAFETY: RELRO is page-rounded and contained in the anonymous DSO mapping.
                if unsafe {
                    raw_syscall::sys_mprotect(addr, relro_end - relro_start, libc::PROT_READ)
                }
                .is_err()
                {
                    return None;
                }
            }
        }

        let id = NEXT_NATIVE_DSO_ID.fetch_add(1, Ordering::Relaxed);
        native_dso_registry().lock().ok()?.push(NativeDso {
            id,
            base: base as usize,
            map_len,
            object,
        });
        Some(native_dso_handle(id))
    })();

    if loaded.is_none() {
        // SAFETY: base/map_len came from the successful sys_mmap call above.
        let _ = unsafe { raw_syscall::sys_munmap(base, map_len) };
    }

    loaded
}

fn native_dso_object_supported(object: &LoadedObject) -> bool {
    object.needed_libraries.is_empty()
        && object.tls_segment.is_none()
        && object.legacy_init.is_none()
        && object.legacy_fini.is_none()
        && object.init_array.is_empty()
        && object.fini_array.is_empty()
        && !object.has_unsupported_relocations()
}

fn relocation_report_succeeded(events: &[frankenlibc_core::elf::RelocationTraceEvent]) -> bool {
    events.iter().all(|event| {
        matches!(
            event.result,
            RelocationResult::Applied | RelocationResult::Skipped
        )
    })
}

struct NativeDsoResolver<'a> {
    dsos: &'a [NativeDso],
}

impl SymbolLookup for NativeDsoResolver<'_> {
    fn lookup(&self, name: &str) -> Option<u64> {
        self.lookup_versioned(name, None)
    }

    fn lookup_versioned(&self, name: &str, version: Option<&str>) -> Option<u64> {
        for dso in self.dsos {
            if let Some(symbol) = dso.object.lookup_symbol_versioned(name, version) {
                return Some(dso.object.base + symbol.st_value);
            }
        }
        let exported = resolve_exported_symbol(name.as_bytes());
        if exported.is_null() {
            None
        } else {
            Some(exported as u64)
        }
    }
}

fn resolve_native_dso_symbol(
    handle: *mut c_void,
    symbol_name: &[u8],
    version_name: Option<&[u8]>,
) -> Option<Option<*mut c_void>> {
    let id = native_dso_id_from_handle(handle)?;
    let symbol = std::str::from_utf8(symbol_name).ok()?;
    let version = match version_name {
        Some(bytes) => Some(std::str::from_utf8(bytes).ok()?),
        None => None,
    };
    let dsos = native_dso_registry().lock().ok()?;
    let dso = dsos.iter().find(|dso| dso.id == id)?;
    Some(
        dso.object
            .lookup_symbol_versioned(symbol, version)
            .map(|sym| (dso.object.base + sym.st_value) as *mut c_void),
    )
}

fn close_native_dso(handle: *mut c_void) -> Option<c_int> {
    let id = native_dso_id_from_handle(handle)?;
    let mut dsos = native_dso_registry().lock().ok()?;
    let index = dsos.iter().position(|dso| dso.id == id)?;
    let dso = dsos.swap_remove(index);
    // SAFETY: base/map_len were created by load_native_dso and are still owned by this handle.
    match unsafe { raw_syscall::sys_munmap(dso.base as *mut u8, dso.map_len) } {
        Ok(()) => Some(0),
        Err(_) => Some(-1),
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
    // In standalone mode, only NULL filename (main program) is supported
    #[cfg(feature = "standalone")]
    {
        if filename.is_null() {
            clear_dlerror();
            return open_main_program_handle();
        }
        if !dlfcn_core::valid_flags(flags) {
            set_dlerror(dlfcn_core::ERR_INVALID_FLAGS);
            return std::ptr::null_mut();
        }
        // Standalone mode: dynamic loading not supported
        set_dlerror(dlfcn_core::ERR_OPERATION_UNAVAILABLE);
        return std::ptr::null_mut();
    }
    #[cfg(not(feature = "standalone"))]
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
            if let Some(handle) = load_native_dso(name, flags) {
                clear_dlerror();
                return handle;
            }
            set_dlerror(dlfcn_core::ERR_NOT_FOUND);
            return std::ptr::null_mut();
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
            if let Some(handle) = load_native_dso(name, flags) {
                clear_dlerror();
                handle
            } else {
                set_dlerror(dlfcn_core::ERR_NOT_FOUND);
                std::ptr::null_mut()
            }
        } else {
            // Bare SONAME search/dependency loading remains delegated while
            // pathname DSOs use the native loader path above.
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
#[allow(unreachable_code)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void {
    // Standalone mode: only resolve exported symbols for main program handle
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
        // In standalone mode, only main program handle and RTLD_DEFAULT are valid
        if is_main_program_handle(handle) || is_rtld_default(handle) {
            let sym = resolve_exported_symbol(symbol_name);
            if sym.is_null() {
                set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
            } else {
                clear_dlerror();
            }
            return sym;
        }
        // Other handles not supported in standalone mode
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
        let sym = native_sym.unwrap_or(std::ptr::null_mut());
        let adverse = sym.is_null();
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
    // Standalone mode: only resolve exported symbols for main program handle
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
        // In standalone mode, only main program handle and RTLD_DEFAULT are valid
        if is_main_program_handle(handle) || is_rtld_default(handle) {
            if version_supported(version_name) {
                let sym = resolve_exported_symbol(symbol_name);
                if !sym.is_null() {
                    clear_dlerror();
                    return sym;
                }
            }
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
            return std::ptr::null_mut();
        }
        // Other handles not supported in standalone mode
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
        let sym = native_sym.unwrap_or(std::ptr::null_mut());
        let adverse = sym.is_null();
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
    // Standalone mode: only main program handle is valid
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
        // Other handles not supported in standalone mode
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
/// Delegates to the host dynamic linker so that libgcc exception-unwinding,
/// backtrace libraries, and any caller that enumerates DSOs works correctly.
/// Uses the cached host address (resolved during bootstrap) to avoid recursion
/// into resolve_host_symbol_raw.
#[allow(clippy::needless_return)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dl_iterate_phdr(
    callback: Option<unsafe extern "C" fn(*mut libc::dl_phdr_info, usize, *mut c_void) -> c_int>,
    data: *mut c_void,
) -> c_int {
    // Standalone mode: no DSOs to enumerate
    #[cfg(feature = "standalone")]
    {
        let _ = (callback, data);
        return 0;
    }
    #[cfg(not(feature = "standalone"))]
    {
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
    // Standalone mode: no DSO metadata available
    #[cfg(feature = "standalone")]
    {
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
