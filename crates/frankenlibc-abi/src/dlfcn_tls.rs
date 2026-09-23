//! Owned general-/local-dynamic TLS for native x86-64 DSO groups.
//!
//! DTPMOD64 names a native object, DTPOFF64 is an offset in its PT_TLS block.
//! These IDs NEVER enter the host DTV: only relocations in native mappings are
//! bound to our private __tls_get_addr. Initial-exec and TLSDESC remain rejected.
//! Templates are captured after relocation, before any constructor executes.

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::cell::RefCell;
use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::{Arc, Weak};

use frankenlibc_core::elf::{Elf64Rela, Elf64Symbol, LoadedObject, ProgramType, RelocationType};

use super::{NativeDso, OPERATIONS, Resolver, registry};

pub(super) fn handles(relocation: &Elf64Rela) -> bool {
    matches!(relocation.reloc_type(), RelocationType::DtpMod64 | RelocationType::DtpOff64)
}

fn load_contains(object: &LoadedObject, start: u64, size: u64) -> bool {
    let Some(end) = start.checked_add(size) else { return false; };
    object.program_headers.iter().any(|header| {
        header.is_load() && header.p_vaddr <= start
            && header.p_vaddr.checked_add(header.p_memsz).is_some_and(|limit| end <= limit)
    })
}

pub(super) fn validate(object: &LoadedObject, bytes: &[u8]) -> Option<()> {
    if object.program_headers.iter().filter(|header| header.p_type == ProgramType::Tls).count() > 1 {
        return None;
    }
    if let Some(segment) = &object.tls_segment {
        let size = usize::try_from(segment.memsz).ok()?;
        let align = usize::try_from(segment.align.max(1)).ok()?;
        if !align.is_power_of_two() || segment.filesz > segment.memsz { return None; }
        let first_byte = usize::try_from(segment.vaddr % align as u64).ok()?;
        Layout::from_size_align(size.checked_add(first_byte)?.max(1), align).ok()?;
        let start = usize::try_from(segment.file_offset).ok()?;
        let count = usize::try_from(segment.filesz).ok()?;
        bytes.get(start..start.checked_add(count)?)?;
        if count != 0 {
            // The initialized template must agree with the PT_LOAD file view,
            // not point into an anonymous hole or an unrelated file range.
            let backed = object.program_headers.iter().any(|header| {
                if !header.is_load() || header.p_vaddr > segment.vaddr { return false; }
                let offset = segment.vaddr - header.p_vaddr;
                header.p_offset.checked_add(offset) == Some(segment.file_offset)
                    && offset.checked_add(segment.filesz).is_some_and(|end| end <= header.p_filesz)
            });
            if !backed || !load_contains(object, segment.vaddr, segment.filesz) { return None; }
        }
    }
    for symbol in &object.dynsym {
        if symbol.is_tls() && !symbol.is_undefined() { symbol_offset(object, symbol)?; }
    }
    for relocation in object.rela_dyn.iter().chain(&object.rela_plt) {
        if handles(relocation) {
            if !load_contains(object, relocation.r_offset, 8) { return None; }
        } else {
            if !relocation.reloc_type().is_supported() { return None; }
            // A TLS offset is not an ordinary load-biased data address.
            if relocation.symbol_index() != 0
                && object.dynsym.get(relocation.symbol_index() as usize).is_some_and(|symbol| symbol.is_tls())
            { return None; }
        }
    }
    Some(())
}

fn symbol_offset(object: &LoadedObject, symbol: &Elf64Symbol) -> Option<u64> {
    if !symbol.is_tls() || !symbol.is_defined() || symbol.st_shndx >= 0xff00 { return None; }
    let segment = object.tls_segment.as_ref()?;
    (symbol.st_value.checked_add(symbol.st_size)? <= segment.memsz).then_some(symbol.st_value)
}

/// Move the ABI-owned relocations out of the pure core relocation engine.
/// Keep them on NativeDso so they cannot be silently skipped or double-applied.
pub(super) fn take_relocations(object: &mut LoadedObject) -> Vec<Elf64Rela> {
    let mut tls = Vec::new();
    for relocations in [&mut object.rela_dyn, &mut object.rela_plt] {
        relocations.retain(|relocation| {
            if handles(relocation) { tls.push(*relocation); false } else { true }
        });
    }
    tls
}

fn definition<'a>(dso: &'a NativeDso, resolver: &Resolver<'a>, index: usize) -> Option<(&'a NativeDso, u64)> {
    if index == 0 {
        dso.object.tls_segment.as_ref()?;
        return Some((dso, 0));
    }
    let requested = dso.object.dynsym.get(index)?;
    if !requested.is_tls() { return None; }
    // Local/hidden/internal/protected definitions cannot be preempted.
    if requested.is_defined() && (requested.is_local() || requested.st_other & 3 != 0) {
        return Some((dso, symbol_offset(&dso.object, requested)?));
    }
    let name = dso.object.symbol_name(requested)?;
    let version = dso.object.symbol_version_by_index(index);
    for provider in &resolver.scope {
        if let Some(symbol) = provider.object.lookup_symbol_versioned(name, version) {
            return Some((provider, symbol_offset(&provider.object, symbol)?));
        }
    }
    // No host fallback: a host TLS offset/module ID is not usable in our DTV.
    None
}

pub(super) fn relocate(dso: &NativeDso, memory: &mut [u8], resolver: &Resolver<'_>) -> Option<()> {
    for relocation in &dso.tls_relocations {
        let (provider, offset) = definition(dso, resolver, relocation.symbol_index() as usize)?;
        let value = match relocation.reloc_type() {
            RelocationType::DtpMod64 => provider.id as u64,
            RelocationType::DtpOff64 => {
                let value = (offset as i128).checked_add(relocation.r_addend as i128)?;
                let value = u64::try_from(value).ok()?;
                if value > provider.object.tls_segment.as_ref()?.memsz { return None; }
                value
            }
            _ => return None,
        };
        let start = usize::try_from(relocation.r_offset).ok()?;
        memory.get_mut(start..start.checked_add(8)?)?.copy_from_slice(&value.to_le_bytes());
        let mut providers = resolver.providers.borrow_mut();
        if !providers.contains(&provider.id) { providers.push(provider.id); }
    }
    Some(())
}

#[derive(Debug)]
pub(super) struct Module {
    id: usize,
    size: usize,
    first_byte: usize,
    layout: Layout,
    template: Vec<u8>,
}

impl Module {
    pub(super) fn capture(dso: &NativeDso) -> Option<Option<Arc<Self>>> {
        let Some(segment) = &dso.object.tls_segment else { return Some(None); };
        let size = usize::try_from(segment.memsz).ok()?;
        let align = usize::try_from(segment.align.max(1)).ok()?;
        let first_byte = usize::try_from(segment.vaddr % align as u64).ok()?;
        let layout = Layout::from_size_align(size.checked_add(first_byte)?.max(1), align).ok()?;
        let count = usize::try_from(segment.filesz).ok()?;
        let start = usize::try_from(segment.vaddr).ok()?;
        if start.checked_add(count)? > dso.mapping.len { return None; }
        let mut template = Vec::new();
        template.try_reserve_exact(count).ok()?;
        if count != 0 {
            // SAFETY: validated PT_TLS/PT_LOAD range of an unpublished RW
            // mapping. Capture AFTER all relocations, not from raw file bytes.
            let bytes = unsafe { std::slice::from_raw_parts((dso.mapping.base + start) as *const u8, count) };
            template.extend_from_slice(bytes);
        }
        Some(Some(Arc::new(Self { id: dso.id, size, first_byte, layout, template })))
    }
}

struct Block {
    id: usize,
    module: Weak<Module>,
    allocation: NonNull<u8>,
    data: NonNull<u8>,
    layout: Layout,
}

impl Block {
    fn new(module: &Arc<Module>) -> Option<Self> {
        // SAFETY: nonzero, validated allocation layout; matching dealloc below.
        let allocation = NonNull::new(unsafe { alloc_zeroed(module.layout) })?;
        // SAFETY: first_byte + size fits the allocation. The zero tail is .tbss.
        let data = unsafe { NonNull::new_unchecked(allocation.as_ptr().add(module.first_byte)) };
        unsafe { std::ptr::copy_nonoverlapping(module.template.as_ptr(), data.as_ptr(), module.template.len()) };
        Some(Self { id: module.id, module: Arc::downgrade(module), allocation, data, layout: module.layout })
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        // SAFETY: this thread exclusively owns the allocation and its layout.
        unsafe { dealloc(self.allocation.as_ptr(), self.layout) };
    }
}

std::thread_local! {
    static BLOCKS: RefCell<Vec<Block>> = const { RefCell::new(Vec::new()) };
}

pub(super) fn address(module: &Arc<Module>, offset: usize) -> Option<*mut c_void> {
    if offset > module.size { return None; }
    BLOCKS.try_with(|blocks| {
        let mut blocks = blocks.try_borrow_mut().ok()?;
        // Weak ownership permits dlclose to unload modules. Never reuse an ID:
        // stale per-thread blocks cannot become the TLS of a later dlopen.
        blocks.retain(|block| block.module.strong_count() != 0);
        let index = match blocks.iter().position(|block| block.id == module.id) {
            Some(index) => index,
            None => {
                blocks.try_reserve(1).ok()?;
                blocks.push(Block::new(module)?);
                blocks.len() - 1
            }
        };
        // SAFETY: checked module-relative offset, possibly one-past the block.
        Some(unsafe { blocks[index].data.as_ptr().add(offset) }.cast())
    }).ok().flatten()
}

#[repr(C)]
struct TlsIndex { module: usize, offset: usize }

unsafe extern "C" fn get_addr(index: *const TlsIndex) -> *mut c_void {
    if index.is_null() { return std::ptr::null_mut(); }
    // SAFETY: native compiler-emitted TLS sequences pass a readable GOT pair.
    let index = unsafe { std::ptr::read_unaligned(index) };
    let _operation = OPERATIONS.lock();
    let module = registry().lock().ok().and_then(|dsos| {
        dsos.iter().find(|dso| dso.id == index.module).and_then(|dso| dso.tls.clone())
    });
    module.and_then(|module| address(&module, index.offset)).unwrap_or(std::ptr::null_mut())
}

pub(super) fn resolver_address(version: Option<&str>) -> Option<u64> {
    // GLIBC_2.3 is the x86-64 __tls_get_addr symbol version. Keep this private;
    // interposing it on the host would interpret unrelated host module IDs.
    if version.is_some_and(|version| version != "GLIBC_2.3") { return None; }
    Some(get_addr as *const () as usize as u64)
}
