//! Eager GNU IFUNC/IRELATIVE execution for native x86-64 ELF groups.
//!
//! Ordinary relocations finish throughout the group before any resolver runs.
//! Resolver calls hold the recursive operation lock, never the registry mutex.
//! The unpublished group is visible only to its calling thread's TLS resolver.
//! Recursive native loader operations are rejected: returning a handle during
//! relocation would expose a transaction which can still fail and be unmapped.
//! Lazy PLT binding and IFUNC-valued TLS template relocations remain unsupported.

use std::cell::{Cell, RefCell};
use std::ffi::c_int;
use std::sync::Arc;

use frankenlibc_core::elf::{
    Elf64ProgramHeader, Elf64Rela, ProgramType, RelocationType,
};

use super::{NativeDso, binding, lifecycle, registry, tls};

std::thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static MODULES: RefCell<Vec<(usize, Arc<tls::Module>)>> = const { RefCell::new(Vec::new()) };
}

pub(super) fn active() -> bool {
    ACTIVE.try_with(Cell::get).unwrap_or(true)
}

pub(super) fn temporary_tls_module(id: usize) -> Option<Arc<tls::Module>> {
    MODULES.try_with(|modules| {
        modules.try_borrow().ok()?.iter().find(|(module, _)| *module == id)
            .map(|(_, module)| Arc::clone(module))
    }).ok().flatten()
}

struct Execution;
impl Execution {
    fn enter(modules: Vec<(usize, Arc<tls::Module>)>) -> Option<Self> {
        if ACTIVE.try_with(|active| active.replace(true)).ok()? { return None; }
        let guard = Self;
        MODULES.try_with(|slot| {
            *slot.try_borrow_mut().ok()? = modules;
            Some(())
        }).ok().flatten()?;
        Some(guard)
    }
}
impl Drop for Execution {
    fn drop(&mut self) {
        let _ = MODULES.try_with(|slot| slot.borrow_mut().clear());
        let _ = ACTIVE.try_with(|active| active.set(false));
    }
}

#[derive(Clone)]
struct ObjectImage {
    id: usize,
    base: usize,
    len: usize,
    headers: Vec<Elf64ProgramHeader>,
}

impl ObjectImage {
    fn executable(&self, address: usize) -> bool {
        let Some(offset) = address.checked_sub(self.base) else { return false; };
        if offset >= self.len { return false; }
        let offset = offset as u64;
        let mut backed = false;
        let mut executable = false;
        // Match native protect_object and lifecycle::executable_address,
        // including last-segment-wins page permissions and final RELRO.
        for header in &self.headers {
            if !header.is_load() || header.p_memsz == 0 { continue; }
            let Some(end) = header.p_vaddr.checked_add(header.p_memsz) else { return false; };
            let Some(page_end) = end.checked_add(4095).map(|end| end & !4095) else { return false; };
            backed |= header.p_vaddr <= offset && offset < end;
            if (header.p_vaddr & !4095) <= offset && offset < page_end {
                executable = header.p_flags.0 & 1 != 0;
            }
        }
        for header in &self.headers {
            if header.p_type != ProgramType::GnuRelro || header.p_memsz == 0 { continue; }
            let Some(end) = header.p_vaddr.checked_add(header.p_memsz)
                .and_then(|end| end.checked_add(4095)) else { return false; };
            if (header.p_vaddr & !4095) <= offset && offset < (end & !4095) { return false; }
        }
        backed && executable
    }
}

pub(super) struct Context {
    images: Vec<ObjectImage>,
    modules: Vec<(usize, Arc<tls::Module>)>,
}

impl Context {
    pub(super) fn new(resident: &[NativeDso], pending: &[NativeDso]) -> Self {
        let objects = resident.iter().chain(pending).filter(|dso| !dso.retiring);
        Self {
            images: objects.clone().map(|dso| ObjectImage {
                id: dso.id, base: dso.mapping.base, len: dso.mapping.len,
                headers: dso.object.program_headers.clone(),
            }).collect(),
            modules: objects.filter_map(|dso| {
                dso.tls.as_ref().map(|module| (dso.id, Arc::clone(module)))
            }).collect(),
        }
    }
    fn provider(&self, address: usize) -> Option<usize> {
        self.images.iter().find(|image| image.executable(address)).map(|image| image.id)
    }
}

#[derive(Clone)]
pub(super) struct Fixup {
    relocation: Elf64Rela,
    target: usize,
    resolver: usize,
    provider: usize,
}

// These are the dynamic IFUNC forms emitted by the supported PIC toolchains.
// Do not silently treat a resolver address as an implementation for other
// forms: reject them until their overflow/text-relocation contract is owned.
fn indirect_form(relocation: &Elf64Rela) -> bool {
    matches!(relocation.reloc_type(), RelocationType::R64 | RelocationType::GlobDat
        | RelocationType::JumpSlot | RelocationType::IRelative)
}

fn writable_target(dso: &NativeDso, offset: u64) -> Option<usize> {
    let end = offset.checked_add(8)?;
    if end > dso.mapping.len as u64 || !dso.object.program_headers.iter().any(|header| {
        header.is_load() && header.p_vaddr <= offset
            && header.p_vaddr.checked_add(header.p_memsz).is_some_and(|limit| end <= limit)
    }) { return None; }
    // A late write must stay in writable, non-executable pages before RELRO.
    // No temporary RWX permissions, and no write through an RX text mapping.
    for address in [offset, end - 1] {
        let mut flags = 0;
        for header in &dso.object.program_headers {
            if !header.is_load() || header.p_memsz == 0 { continue; }
            let page_end = header.p_vaddr.checked_add(header.p_memsz)?.checked_add(4095)? & !4095;
            if (header.p_vaddr & !4095) <= address && address < page_end { flags = header.p_flags.0; }
        }
        if flags & 3 != 2 { return None; }
    }
    // Capturing a template before a resolver must not freeze an unresolved
    // function pointer into the first thread's block or erase resolver writes.
    if let Some(segment) = &dso.object.tls_segment {
        let template_end = segment.vaddr.checked_add(segment.filesz)?;
        if offset < template_end && segment.vaddr < end { return None; }
    }
    dso.mapping.base.checked_add(usize::try_from(offset).ok()?)
}

/// Identify indirect relocations without calling any machine code. The core
/// continues to own all ordinary arithmetic, including compressed RELR.
pub(super) fn prepare(
    resident: &[NativeDso], pending: &mut [NativeDso], root: usize, flags: c_int,
) -> Option<Vec<Vec<Fixup>>> {
    let mut plans = Vec::new();
    for dso in pending.iter() {
        let scope = binding::scope(resident, pending, root, dso, flags)?;
        let mut fixups = Vec::new();
        for relocation in dso.object.rela_dyn.iter().chain(&dso.object.rela_plt) {
            let indirect = if relocation.reloc_type() == RelocationType::IRelative {
                if relocation.symbol_index() != 0 { return None; }
                let address = usize::try_from(dso.mapping.base as i128 + relocation.r_addend as i128).ok()?;
                Some((dso.id, address))
            } else if matches!(relocation.reloc_type(), RelocationType::None | RelocationType::Relative) {
                None
            } else if relocation.symbol_index() != 0 {
                let definition = binding::select(dso, relocation.symbol_index() as usize, &scope)?;
                if definition.indirect {
                    Some((definition.provider?, usize::try_from(definition.address).ok()?))
                } else { None }
            } else { None };
            if let Some((provider, address)) = indirect {
                if !indirect_form(relocation) { return None; }
                let owner = super::find(resident, pending, provider)?;
                if !lifecycle::executable_address(owner, address) { return None; }
                fixups.push(Fixup {
                    relocation: *relocation, resolver: address, provider,
                    target: writable_target(dso, relocation.r_offset)?,
                });
            }
        }
        plans.push(fixups);
    }
    // Validate every plan before removing any entry. The tables retained here
    // are exactly the ones subsequently submitted to the ordinary core engine.
    for (dso, plan) in pending.iter_mut().zip(&plans) {
        for table in [&mut dso.object.rela_dyn, &mut dso.object.rela_plt] {
            table.retain(|entry| !plan.iter().any(|fixup| {
                entry.r_offset == fixup.relocation.r_offset && entry.r_info == fixup.relocation.r_info
                    && entry.r_addend == fixup.relocation.r_addend
            }));
        }
    }
    Some(plans)
}

pub(super) fn execution_order(resident: &[NativeDso], pending: &[NativeDso], root: usize) -> Vec<usize> {
    let mut stack = vec![(root, false)];
    let mut seen = Vec::new();
    let mut order = Vec::new();
    while let Some((id, ready)) = stack.pop() {
        if ready {
            if let Some(index) = pending.iter().position(|dso| dso.id == id) { order.push(index); }
        } else if !seen.contains(&id) {
            seen.push(id);
            stack.push((id, true));
            if let Some(dso) = super::find(resident, pending, id) {
                stack.extend(dso.needed.iter().rev().map(|&id| (id, false)));
            }
        }
    }
    order
}

unsafe fn invoke(address: usize) -> usize {
    // SAFETY: callers validate executable native code and keep all owning
    // mappings alive. x86-64 GNU IFUNC resolvers take no arguments and return
    // the implementation address, not the result of calling that function.
    let resolver: unsafe extern "C" fn() -> usize = unsafe { std::mem::transmute(address) };
    unsafe { resolver() }
}

pub(super) fn execute(
    mut context: Context, plans: &[Vec<Fixup>], order: &[usize],
) -> Option<Vec<Vec<usize>>> {
    let _execution = Execution::enter(std::mem::take(&mut context.modules))?;
    let mut providers = vec![Vec::new(); plans.len()];
    for &index in order {
        for fixup in plans.get(index)? {
            // No registry lock or Rust reference to mapped bytes crosses this
            // call. Every ordinary relocation and TLS template is ready.
            let selected = unsafe { invoke(fixup.resolver) };
            if !providers[index].contains(&fixup.provider) { providers[index].push(fixup.provider); }
            if selected != 0 {
                let provider = context.provider(selected)?;
                if !providers[index].contains(&provider) { providers[index].push(provider); }
            }
            let value = if fixup.relocation.reloc_type() == RelocationType::R64 {
                usize::try_from(selected as i128 + fixup.relocation.r_addend as i128).ok()?
            } else { selected };
            // SAFETY: preflight checked the full eight-byte PT_LOAD range and
            // writable/non-executable stage permissions. RELRO is applied later.
            unsafe { std::ptr::write_unaligned(fixup.target as *mut usize, value) };
        }
    }
    Some(providers)
}

/// dlsym resolves IFUNC anew on every request; PLT/data relocations retain the
/// previously selected address. The caller holds OPERATIONS for this function.
pub(super) fn resolve_symbol(root: usize, resolver: usize) -> Option<usize> {
    let mut context = {
        let dsos = registry().lock().ok()?;
        let context = Context::new(&dsos, &[]);
        context.provider(resolver)?;
        context
    };
    let _execution = Execution::enter(std::mem::take(&mut context.modules))?;
    let selected = unsafe { invoke(resolver) };
    if selected != 0 {
        let provider = context.provider(selected)?;
        let mut dsos = registry().lock().ok()?;
        let owner = dsos.iter_mut().find(|dso| dso.id == root)?;
        if provider != root && !owner.dependencies.contains(&provider) { owner.dependencies.push(provider); }
    }
    Some(selected)
}
