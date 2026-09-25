//! Native ELF symbol preemption and per-load binding scopes.
//!
//! An ordinary default-visible definition is not necessarily its own provider.
//! Relocations search the load's scope; explicit-handle dlsym still searches
//! that handle's breadth-first dependency closure. Keep these two operations
//! separate. The pure core retains ownership of relocation arithmetic.

use std::ffi::c_int;

use frankenlibc_core::dlfcn::RTLD_DEEPBIND;
use frankenlibc_core::elf::{Elf64Rela, LoadedObject, ProgramType, RelocationType};
use frankenlibc_core::elf::relocation::{RelocationContext, compute_relocation};

use super::{NativeDso, Resolver, lookup_order};

/// Both the historical DT_SYMBOLIC tag and DF_SYMBOLIC request own-object
/// lookup before the normal global scope. Parse runtime metadata, not linker
/// command lines: a stripped or independently produced DSO has the same ABI.
pub(super) fn symbolic(bytes: &[u8], object: &LoadedObject) -> Option<bool> {
    let mut symbolic = false;
    for header in &object.program_headers {
        if header.p_type != ProgramType::Dynamic { continue; }
        let offset = usize::try_from(header.p_offset).ok()?;
        let size = usize::try_from(header.p_filesz).ok()?;
        let entries = bytes.get(offset..offset.checked_add(size)?)?;
        if size % 16 != 0 { return None; }
        let mut terminated = false;
        for entry in entries.chunks_exact(16) {
            let tag = i64::from_le_bytes(entry[..8].try_into().ok()?);
            let value = u64::from_le_bytes(entry[8..].try_into().ok()?);
            match tag {
                0 => { terminated = true; break; }
                16 => symbolic = true,
                30 => symbolic |= value & 2 != 0,
                _ => {}
            }
        }
        if !terminated { return None; }
    }
    Some(symbolic)
}

pub(super) fn scope<'a>(
    resident: &'a [NativeDso], pending: &'a [NativeDso], root: usize,
    requester: &'a NativeDso, flags: c_int,
) -> Option<Vec<&'a NativeDso>> {
    let local = lookup_order(resident, pending, root);
    let global = super::global_scope_order(resident);
    let mut ids = Vec::new();
    if requester.symbolic { ids.push(requester.id); }
    if flags & RTLD_DEEPBIND != 0 {
        ids.extend(local);
        ids.extend(global);
    } else {
        ids.extend(global);
        ids.extend(local);
    }
    let mut result = Vec::new();
    for id in ids {
        if !result.iter().any(|dso: &&NativeDso| dso.id == id) {
            let dso = super::find(resident, pending, id)?;
            if dso.retiring { return None; }
            result.push(dso);
        }
    }
    Some(result)
}

pub(super) struct Definition {
    pub(super) address: u64,
    pub(super) provider: Option<usize>,
    pub(super) indirect: bool,
}

fn own_definition(dso: &NativeDso, index: usize) -> Option<Definition> {
    let symbol = dso.object.dynsym.get(index)?;
    if !symbol.is_defined() || symbol.is_tls() { return None; }
    Some(Definition {
        address: symbol.definition_address(dso.object.base)?,
        provider: Some(dso.id), indirect: symbol.is_ifunc(),
    })
}

pub(super) fn select(dso: &NativeDso, index: usize, scope: &[&NativeDso]) -> Option<Definition> {
    let symbol = dso.object.dynsym.get(index)?;
    if symbol.is_tls() { return None; }
    // Local/hidden/internal/protected references cannot be interposed, even
    // when the process has an earlier definition with exactly the same name.
    if symbol.is_local() || symbol.st_other & 3 != 0 {
        if symbol.is_defined() { return own_definition(dso, index); }
        return symbol.is_weak().then_some(Definition { address: 0, provider: None, indirect: false });
    }
    let name = dso.object.symbol_name(symbol)?;
    let version = dso.versions.name(index);
    // Native module IDs and native __dso_handle values must never reach the
    // host runtime. Use the same version-checked private ABI path as ordinary
    // resolution; prebinding must not bypass newly implemented runtime hooks.
    if symbol.is_undefined() && matches!(name,
        "__tls_get_addr" | "__cxa_thread_atexit_impl" | "__cxa_atexit" | "__cxa_finalize")
    {
        let runtime = Resolver { scope: Vec::new(), providers: std::cell::RefCell::new(Vec::new()) };
        let address = frankenlibc_core::elf::SymbolLookup::lookup_versioned(&runtime, name, version)?;
        return Some(Definition { address, provider: None, indirect: false });
    }
    for provider in scope {
        if let Some(found) = provider.versions.lookup(&provider.object, name, version, dso.versions.relocation(index)) {
            if !found.is_defined() || matches!(found.st_other & 3, 1 | 2) { continue; }
            if found.is_tls() { return None; }
            return Some(Definition {
                address: found.definition_address(provider.object.base)?,
                provider: Some(provider.id), indirect: found.is_ifunc(),
            });
        }
    }
    // Keep ordinary builtin fallback on the same ABI/version path too. An
    // empty scope cannot accidentally select a different native provider.
    let runtime = Resolver { scope: Vec::new(), providers: std::cell::RefCell::new(Vec::new()) };
    if let Some(address) = frankenlibc_core::elf::SymbolLookup::lookup_versioned(&runtime, name, version) {
        return Some(Definition { address, provider: None, indirect: false });
    }
    symbol.is_weak().then_some(Definition { address: 0, provider: None, indirect: false })
}

struct Write {
    relocation: Elf64Rela,
    offset: usize,
    value: u64,
    width: usize,
}

pub(super) struct Plan {
    writes: Vec<Write>,
    providers: Vec<usize>,
}

fn same_entry(left: &Elf64Rela, right: &Elf64Rela) -> bool {
    left.r_offset == right.r_offset && left.r_info == right.r_info && left.r_addend == right.r_addend
}

/// Prebind ordinary symbol relocations using the runtime scope, instead of
/// submitting default-visible definitions to the core's definition-first
/// helper. Indirect selections stay in the tables for the explicit IFUNC pass.
/// No mapping, resident lifetime edge or symbol definition is mutated here.
pub(super) fn prepare(
    resident: &[NativeDso], pending: &mut [NativeDso], root: usize, flags: c_int,
) -> Option<Vec<Plan>> {
    let mut plans = Vec::new();
    for dso in pending.iter() {
        let scope = scope(resident, pending, root, dso, flags)?;
        let mut plan = Plan { writes: Vec::new(), providers: Vec::new() };
        for relocation in dso.object.rela_dyn.iter().chain(&dso.object.rela_plt) {
            if relocation.symbol_index() == 0 || matches!(relocation.reloc_type(),
                RelocationType::None | RelocationType::Relative | RelocationType::IRelative)
            { continue; }
            let definition = select(dso, relocation.symbol_index() as usize, &scope)?;
            if definition.indirect { continue; }
            let (value, width) = compute_relocation(relocation, definition.address,
                &RelocationContext::new(dso.object.base)).ok()?;
            let offset = usize::try_from(relocation.r_offset).ok()?;
            let end = offset.checked_add(width)?;
            if end > dso.mapping.len || !dso.object.program_headers.iter().any(|header| {
                header.is_load() && header.p_vaddr <= offset as u64
                    && header.p_vaddr.checked_add(header.p_memsz).is_some_and(|limit| end as u64 <= limit)
            }) { return None; }
            plan.writes.push(Write { relocation: *relocation, offset, value, width });
            if let Some(provider) = definition.provider {
                if provider != dso.id && !plan.providers.contains(&provider) { plan.providers.push(provider); }
            }
        }
        plans.push(plan);
    }
    for (dso, plan) in pending.iter_mut().zip(&plans) {
        for table in [&mut dso.object.rela_dyn, &mut dso.object.rela_plt] {
            table.retain(|entry| !plan.writes.iter().any(|write| same_entry(entry, &write.relocation)));
        }
    }
    Some(plans)
}

pub(super) fn apply(plan: &Plan, memory: &mut [u8], resolver: &Resolver<'_>) -> Option<()> {
    for write in &plan.writes {
        memory.get_mut(write.offset..write.offset.checked_add(write.width)?)?
            .copy_from_slice(write.value.to_le_bytes().get(..write.width)?);
    }
    let mut providers = resolver.providers.borrow_mut();
    for &provider in &plan.providers {
        if !providers.contains(&provider) { providers.push(provider); }
    }
    Some(())
}
