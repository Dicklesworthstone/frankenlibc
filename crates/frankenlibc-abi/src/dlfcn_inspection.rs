//! Inspection of ABI-owned native DSOs, independent of the host link map.
//!
//! Object and symbol names belong to the resident DSO, not temporary lookup
//! buffers. No registry reference escapes a lookup. Program-header iteration
//! (below) separately pins the complete snapshot across foreign callbacks.

use std::ffi::{CStr, c_void};

use frankenlibc_core::elf::{Elf64Symbol, LoadedObject};

use super::{NativeDso, NATIVE_DSOS, OPERATIONS};

/// Match the loaded image, including its inter-segment reservation, but not
/// the page-rounded tail after the last PT_LOAD's p_memsz. No queried address
/// is dereferenced. The ABI loader currently requires a zero low_vaddr.
fn contains_address(dso: &NativeDso, address: usize) -> bool {
    let Some(offset) = (address as u64).checked_sub(dso.object.base) else {
        return false;
    };
    let end = dso.object.program_headers.iter()
        .filter(|header| header.is_load())
        .filter_map(|header| header.p_vaddr.checked_add(header.p_memsz))
        .max()
        .unwrap_or(0);
    offset < end && offset < dso.mapping.len as u64
}

fn symbol_name<'a>(object: &'a LoadedObject, symbol: &Elf64Symbol) -> Option<&'a CStr> {
    // ELF names are bytes, not necessarily UTF-8. Reuse the retained dynstr
    // allocation so the returned C string survives subsequent dlfcn calls.
    let bytes = object.dynstr.get(symbol.st_name as usize..)?;
    let name = CStr::from_bytes_until_nul(bytes).ok()?;
    (!name.to_bytes().is_empty()).then_some(name)
}

fn symbol_start(object: &LoadedObject, symbol: &Elf64Symbol, address: u64) -> Option<u64> {
    // STB_GLOBAL, STB_WEAK and STB_GNU_UNIQUE; STV_DEFAULT or STV_PROTECTED.
    // TLS values are offsets, not process addresses. Merely inspecting an
    // IFUNC must never invoke its resolver.
    if !symbol.is_defined()
        || !matches!(symbol.st_info >> 4, 1 | 2 | 10)
        || !matches!(symbol.st_other & 3, 0 | 3)
        || !matches!(symbol.st_info & 15, 0 | 1 | 2 | 10)
    {
        return None;
    }
    let start = symbol.definition_address(object.base)?;
    let offset = address.checked_sub(start)?;
    // A zero-sized symbol matches its exact address, not all later bytes.
    // A nonzero-sized symbol does not claim its one-past-the-end address.
    (offset < symbol.st_size || (symbol.st_size == 0 && offset == 0)).then_some(start)
}

/// Resolve a native object without invoking user code or a host loader.
///
/// # Safety
/// `info` must be writable Dl_info storage. The caller must retain the DSO
/// while using returned pointers, just as for host dladdr/dlsym pointers.
pub(crate) unsafe fn address_info(address: *const c_void, info: *mut libc::Dl_info) -> bool {
    if address.is_null() || info.is_null() {
        return false;
    }
    // Do not initialize the native loader merely because bootstrap code asks
    // about an address in the host. No native DSO can predate this registry.
    let Some(registry) = NATIVE_DSOS.get() else {
        return false;
    };
    let _operation = OPERATIONS.lock();
    let Ok(dsos) = registry.lock() else {
        return false;
    };
    let Some(dso) = dsos.iter().find(|dso| contains_address(dso, address as usize)) else {
        return false;
    };
    // Retiring DSOs remain inspectable while their finalizers execute.
    let mut result = libc::Dl_info {
        dli_fname: dso.name.as_ptr(),
        dli_fbase: dso.object.base as usize as *mut c_void,
        dli_sname: std::ptr::null(),
        dli_saddr: std::ptr::null_mut(),
    };
    let mut best = None;
    for symbol in &dso.object.dynsym {
        let Some(start) = symbol_start(&dso.object, symbol, address as usize as u64) else {
            continue;
        };
        if best.is_some_and(|previous| start <= previous) {
            continue;
        }
        let Some(name) = symbol_name(&dso.object, symbol) else {
            continue;
        };
        best = Some(start);
        result.dli_sname = name.as_ptr();
        result.dli_saddr = start as usize as *mut c_void;
    }
    // SAFETY: caller supplies valid writable storage; resident allocations
    // backing both strings cannot move while this registry guard is held.
    unsafe { info.write(result) };
    true
}
