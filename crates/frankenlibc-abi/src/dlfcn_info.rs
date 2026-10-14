//! Introspection of native handles, without passing private IDs to host ld.so.
//!
//! Returned strings, link maps and program headers belong to a loaded object.
//! They are stable across registry growth/reopens, but NOT across its unload.
//! The five public link_map fields describe the owned segment of the link map;
//! they are not host-private link_map objects and must not enter host ld.so.
//! Inspection neither promotes visibility nor adds lifetime edges. In
//! particular, TLS_DATA observes this thread's block without allocating one.
//! The mapped dynamic table retains this loader's unrelocated pointer values:
//! consumers must add l_addr to address-valued tags. As with GNU link_map,
//! traversing l_next/l_prev concurrently with loading/unloading is not safe;
//! use the existing snapshot-pinned dl_iterate_phdr API for that purpose.

use std::cell::UnsafeCell;
use std::ffi::{CStr, CString, c_char, c_int, c_long, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use frankenlibc_core::dlfcn as core;
use frankenlibc_core::elf::{LoadedObject, ProgramType};

use super::super as abi;
use super::{NATIVE_DSOS, NativeDso, OPERATIONS, ifunc, native_dso_id_from_handle, tls};

const ERR_REQUEST: &[u8] = b"unsupported dlinfo request\0";
const ERR_OUTPUT: &[u8] = b"invalid dlinfo output buffer\0";
const ERR_QUERY: &[u8] = b"dlinfo query failed\0";
type Outcome = Result<c_int, &'static [u8]>;

/// Public ELF64 link_map prefix. Address-valued words have the C pointer/Addr
/// layout on supported 64-bit targets. Keep exposed addresses as integers so
/// the owning Metadata is Send without claiming foreign pointers are Send.
/// C may read these five fields; private glibc link_map extensions do not exist.
#[derive(Debug, Default)]
#[repr(C)]
struct LinkMap {
    l_addr: usize,
    l_name: usize,
    l_ld: usize,
    l_next: usize,
    l_prev: usize,
}

#[derive(Debug)]
pub(super) struct Metadata {
    // C retains raw aliases while the loader updates the list links.
    map: Box<UnsafeCell<LinkMap>>,
    origin: CString,
    symbols: Option<SymbolTable>,
}

impl Metadata {
    pub(super) fn new(object: &LoadedObject, name: &CStr, bytes: &[u8]) -> Option<Self> {
        let path = Path::new(std::ffi::OsStr::from_bytes(name.to_bytes()));
        let origin = CString::new(path.parent()?.as_os_str().as_bytes()).ok()?;
        let dynamic = object.program_headers.iter()
            .find(|header| header.p_type == ProgramType::Dynamic)
            .map(|header| object.base.checked_add(header.p_vaddr))
            .unwrap_or(Some(0))?;
        Some(Self {
            map: Box::new(UnsafeCell::new(LinkMap {
                l_addr: usize::try_from(object.base).ok()?,
                l_name: name.as_ptr() as usize,
                l_ld: usize::try_from(dynamic).ok()?,
                ..LinkMap::default()
            })),
            origin,
            symbols: SymbolTable::parse(object, bytes)?,
        })
    }

    pub(super) fn address(&self) -> *mut c_void {
        self.map.get().cast()
    }

    pub(super) fn symbol(&self, index: usize) -> *mut c_void {
        self.symbols.as_ref().filter(|table| index < table.count)
            .map_or(std::ptr::null_mut(), |table| (table.address + index * 24) as *mut c_void)
    }
}

/// The core's Elf64Symbol is NOT repr(C). Return actual serialized ELF64
/// records from the loaded PT_LOAD image, not a cast of that Rust struct and
/// not a temporary copy. Verify the file view matches the core's selected
/// table before ever exposing its address; section headers are not required.
#[derive(Debug)]
struct SymbolTable { address: usize, count: usize }

impl SymbolTable {
    fn parse(object: &LoadedObject, bytes: &[u8]) -> Option<Option<Self>> {
        let Some(dynamic) = object.program_headers.iter()
            .find(|header| header.p_type == ProgramType::Dynamic)
        else { return Some(None); };
        let start = usize::try_from(dynamic.p_offset).ok()?;
        let len = usize::try_from(dynamic.p_filesz).ok()?;
        let entries = bytes.get(start..start.checked_add(len)?)?;
        if entries.len() % 16 != 0 { return None; }
        let mut table = None;
        let mut entry_size = None;
        let mut terminated = false;
        for entry in entries.chunks_exact(16) {
            let tag = i64::from_le_bytes(entry[..8].try_into().ok()?);
            let value = u64::from_le_bytes(entry[8..].try_into().ok()?);
            if tag == 0 { terminated = true; break; }
            let field = match tag { 6 => &mut table, 11 => &mut entry_size, _ => continue };
            if field.is_some_and(|old| old != value) { return None; }
            *field = Some(value);
        }
        if !terminated { return None; }
        let Some(table) = table else { return Some(None); };
        if entry_size != Some(24) || table % 8 != 0 { return None; }
        let size = object.dynsym.len().checked_mul(24)?;
        let size64 = u64::try_from(size).ok()?;
        // A file-backed PT_LOAD range must contain the WHOLE table. A value
        // naming a hole, .bss, overflow, or the end of the file cannot escape.
        let file_offset = object.program_headers.iter().find_map(|header| {
            if !header.is_load() { return None; }
            let delta = table.checked_sub(header.p_vaddr)?;
            if delta.checked_add(size64)? > header.p_filesz { return None; }
            header.p_offset.checked_add(delta)
        })?;
        let file_offset = usize::try_from(file_offset).ok()?;
        let records = bytes.get(file_offset..file_offset.checked_add(size)?)?;
        for (record, symbol) in records.chunks_exact(24).zip(&object.dynsym) {
            if u32::from_le_bytes(record[..4].try_into().ok()?) != symbol.st_name
                || record[4] != symbol.st_info || record[5] != symbol.st_other
                || u16::from_le_bytes(record[6..8].try_into().ok()?) != symbol.st_shndx
                || u64::from_le_bytes(record[8..16].try_into().ok()?) != symbol.st_value
                || u64::from_le_bytes(record[16..24].try_into().ok()?) != symbol.st_size
            { return None; }
        }
        let address = usize::try_from(object.base.checked_add(table)?).ok()?;
        address.checked_add(size)?;
        Some(Some(Self { address, count: object.dynsym.len() }))
    }
}

/// Called under both loader locks after publication/retirement, before any
/// callbacks. No allocation and no foreign callback occurs. Boxing prevents
/// growing or compacting Vec<NativeDso> from invalidating a saved link map.
pub(super) fn refresh_links(dsos: &mut [NativeDso]) {
    for index in 0..dsos.len() {
        let previous = index.checked_sub(1)
            .map_or(0, |previous| dsos[previous].info.address() as usize);
        let next = dsos.get(index + 1).map_or(0, |next| next.info.address() as usize);
        // SAFETY: both loader locks serialize these writes. UnsafeCell keeps
        // the exposed raw aliases valid without creating exclusive references
        // to their pointee. Callers must not traverse links concurrently.
        let map = dsos[index].info.map.get();
        unsafe { (*map).l_prev = previous; (*map).l_next = next; }
    }
}

fn output_fits(result: *mut c_void, size: usize) -> bool {
    !result.is_null() && !crate::malloc_abi::known_remaining(result as usize)
        .is_some_and(|remaining| remaining < size)
}

unsafe fn store<T>(result: *mut c_void, value: T) -> Outcome {
    if !output_fits(result, std::mem::size_of::<T>()) {
        return Err(ERR_OUTPUT);
    }
    // SAFETY: the caller provides writable request-specific storage. Tracked
    // allocations are additionally bounded; untracked storage retains the C
    // API's size precondition. Unaligned writes avoid imposing extra alignment.
    unsafe { result.cast::<T>().write_unaligned(value) };
    Ok(0)
}

unsafe fn inspect(dso: &NativeDso, request: c_int, result: *mut c_void) -> Outcome {
    match request {
        // Only the base native namespace exists; dlmopen namespaces are not
        // invented by this query. Foreign namespaces are queried on the host.
        1 => unsafe { store(result, 0 as c_long) }, // RTLD_DI_LMID
        2 => unsafe { store(result, dso.info.address()) }, // RTLD_DI_LINKMAP
        6 => { // RTLD_DI_ORIGIN: the GNU API unfortunately has no size argument.
            let bytes = dso.info.origin.as_bytes_with_nul();
            if !output_fits(result, bytes.len()) { return Err(ERR_OUTPUT); }
            // SAFETY: same output precondition as store; the retained origin
            // contains its terminator and does not depend on today's filesystem.
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), result.cast(), bytes.len()) };
            Ok(0)
        }
        9 => unsafe { store(result, if dso.tls.is_some() { dso.id } else { 0usize }) },
        10 => { // RTLD_DI_TLS_DATA: soft lookup, never tls::address.
            let address = dso.tls.as_ref().map_or(std::ptr::null_mut(), tls::allocated_address);
            unsafe { store(result, address) }
        }
        11 => { // RTLD_DI_PHDR returns the COUNT, not zero, on success.
            let (headers, count) = dso.phdrs.as_ptr_len();
            let count = c_int::try_from(count).map_err(|_| ERR_QUERY)?;
            unsafe { store(result, headers) }?;
            Ok(count)
        }
        // In particular, do not fabricate SERINFO/SERINFOSIZE. Their variable
        // size search-path ABI needs a separate implementation.
        _ => Err(ERR_REQUEST),
    }
}

/// None is an unowned handle; Some(Err) is an authoritative native refusal.
/// Classify by ID or by a live public link-map address WITHOUT dereferencing the
/// input. A stale tagged ID must never be forwarded as a host link_map pointer.
unsafe fn native_query(handle: *mut c_void, request: c_int, result: *mut c_void)
    -> Option<Outcome>
{
    let id = native_dso_id_from_handle(handle);
    let Some(registry) = NATIVE_DSOS.get() else {
        return id.map(|_| Err(core::ERR_INVALID_HANDLE));
    };
    let _operation = OPERATIONS.lock();
    let Ok(dsos) = registry.lock() else { return Some(Err(ERR_QUERY)); };
    let dso = dsos.iter().find(|dso| id == Some(dso.id) || dso.info.address() == handle);
    match dso {
        // Finalizers may inspect their still-mapped retiring batch.
        Some(dso) => Some(unsafe { inspect(dso, request, result) }),
        None => id.map(|_| Err(core::ERR_INVALID_HANDLE)),
    }
}

#[cfg(not(feature = "standalone"))]
unsafe fn host_query(handle: *mut c_void, request: c_int, result: *mut c_void) -> Outcome {
    type Info = unsafe extern "C" fn(*mut c_void, c_int, *mut c_void) -> c_int;
    type Error = unsafe extern "C" fn() -> *const c_char;
    type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
    type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
    let resolve = crate::host_resolve::resolve_host_symbol_raw;
    let info = resolve("dlinfo").ok_or(ERR_QUERY)?;
    let error = resolve("dlerror").ok_or(ERR_QUERY)?;
    // Resolve all helpers before clearing host error state. A synthetic native
    // main handle is translated to a balanced real host main handle; the
    // sentinel itself is NEVER passed to glibc's dlinfo.
    let main = if abi::is_main_program_handle(handle) {
        Some((resolve("dlopen").ok_or(ERR_QUERY)?, resolve("dlclose").ok_or(ERR_QUERY)?))
    } else { None };
    // SAFETY: only the trusted host resolver supplies these exact ABI symbols.
    let info: Info = unsafe { std::mem::transmute(info) };
    let error: Error = unsafe { std::mem::transmute(error) };
    let (handle, close) = if let Some((open, close)) = main {
        let open: Open = unsafe { std::mem::transmute(open) };
        let close: Close = unsafe { std::mem::transmute(close) };
        let handle = unsafe { open(std::ptr::null(), core::RTLD_NOW) };
        if handle.is_null() { unsafe { error() }; return Err(ERR_QUERY); }
        (handle, Some(close))
    } else { (handle, None) };
    unsafe { error() };
    // No native loader lock crosses a host call. Capture failure before close
    // can change its error buffer; report a stable native-owned error string.
    let rc = unsafe { info(handle, request, result) };
    let failed = !unsafe { error() }.is_null() || rc < 0;
    if let Some(close) = close { let _ = unsafe { close(handle) }; }
    if failed { Err(ERR_QUERY) } else { Ok(rc) }
}

/// Native-plugin dlinfo routing for native, synthetic-main and host handles.
/// Native imports and caller-relative lookups bind here; the older direct
/// public compatibility export is a separate integration surface.
///
/// # Safety
/// result obeys the GNU request-specific writable-buffer contract; handle is
/// a live loader handle (stale tagged native handles are rejected defensively).
pub unsafe extern "C" fn query(handle: *mut c_void, request: c_int, result: *mut c_void) -> c_int {
    let outcome = if handle.is_null() || handle as usize == core::RTLD_NEXT {
        Err(core::ERR_INVALID_HANDLE)
    } else if result.is_null() {
        // Preserve the public wrapper's existing null-output errno contract.
        unsafe { crate::errno_abi::set_abi_errno(libc::EINVAL) };
        Err(ERR_OUTPUT)
    } else if ifunc::active() {
        // No unpublished native identity can masquerade as a host handle.
        Err(ERR_QUERY)
    } else {
        // The main sentinel is byte-aligned and can have any low byte: test it
        // before applying the tagged-native-ID classifier.
        let owned = if abi::is_main_program_handle(handle) {
            None
        } else { unsafe { native_query(handle, request, result) } };
        if let Some(outcome) = owned {
            return match outcome {
                Ok(rc) => { abi::clear_dlerror(); rc }
                Err(message) => { abi::set_dlerror(message); -1 }
            };
        }
        #[cfg(not(feature = "standalone"))]
        { unsafe { host_query(handle, request, result) } }
        #[cfg(feature = "standalone")]
        {
            // Main-object PHDR/origin/TLS integration is not inferred from a
            // host process or hardcoded placeholders in standalone builds.
            if abi::is_main_program_handle(handle) && request == 1 {
                unsafe { store(result, 0 as c_long) }
            } else { Err(core::ERR_INVALID_HANDLE) }
        }
    };
    match outcome {
        Ok(rc) => { abi::clear_dlerror(); rc }
        Err(message) => { abi::set_dlerror(message); -1 }
    }
}

/// These versions belong to the introspection functions, not the generic
/// builtin allowlist. An ordinary DSO definition is considered before fallback.
pub(crate) fn resolver_address(name: &str, version: Option<&str>) -> Option<u64> {
    let compatibility = if cfg!(target_arch = "aarch64") { "GLIBC_2.17" } else { "GLIBC_2.3.3" };
    if version.is_some_and(|version| version != compatibility && version != "GLIBC_2.34") {
        return None;
    }
    match name {
        "dlinfo" => Some(query as *const () as usize as u64),
        "dladdr1" => Some(address_query as *const () as usize as u64),
        _ => None,
    }
}

/// Native-aware dladdr1 used by plugin imports and dynamically obtained APIs.
/// Public compatibility exports remain in glibc_internal_abi; fallback there
/// handles host/startup addresses without recursively invoking this entry.
///
/// # Safety
/// The output objects must satisfy dladdr1's request-specific C ABI contract.
pub unsafe extern "C" fn address_query(
    address: *const c_void,
    info: *mut c_void,
    extra: *mut *mut c_void,
    flags: c_int,
) -> c_int {
    if unsafe { super::inspection::address_info_extra(address, info.cast(), extra, flags) } {
        return 1;
    }
    unsafe { crate::glibc_internal_abi::dladdr1(address, info, extra, flags) }
}
