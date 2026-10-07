//! GNU unique definitions in the native link-map namespace.
//!
//! GCC emits STB_GNU_UNIQUE for C++ inline statics and template data. Ordinary
//! scope/version selection runs FIRST; only a selected unique definition is
//! canonicalized, by name, across otherwise independent RTLD_LOCAL groups.
//! Merely loading a DSO with an unused unique definition must not pin it.
//!
//! A load stages first selections until mapping, binding, TLS, IFUNC, callback
//! validation and protection all succeed. Failure drops the transaction without
//! publishing an address or changing a resident object's NODELETE state. A
//! successful first selection pins its provider and hence its dependency graph.
//! All entry points require OPERATIONS; lock order is registry -> UNIQUE. No
//! lock in this module crosses an initializer, finalizer or IFUNC callback.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use frankenlibc_core::elf::Elf64Symbol;

use super::NativeDso;

const STB_GNU_UNIQUE: u8 = 10;

/// Pointer-free definition metadata. In particular, a TLS definition is a
/// provider/offset pair, never the loading thread's address or a host DTV ID.
#[derive(Clone, Copy, Debug)]
pub(super) struct Selection {
    pub(super) provider: usize,
    pub(super) symbol: Elf64Symbol,
    base: u64,
    tls_size: Option<u64>,
}

impl Selection {
    pub(super) fn new(provider: &NativeDso, symbol: &Elf64Symbol) -> Option<Self> {
        if !symbol.is_defined() {
            return None;
        }
        let tls_size = if symbol.is_tls() {
            if symbol.st_shndx >= 0xff00 {
                return None;
            }
            let size = provider.object.tls_segment.as_ref()?.memsz;
            if symbol.st_value.checked_add(symbol.st_size)? > size {
                return None;
            }
            Some(size)
        } else {
            symbol.definition_address(provider.object.base)?;
            None
        };
        Some(Self {
            provider: provider.id,
            symbol: *symbol,
            base: provider.object.base,
            tls_size,
        })
    }

    pub(super) fn address(self) -> Option<u64> {
        if self.symbol.is_tls() {
            return None;
        }
        self.symbol.definition_address(self.base)
    }

    pub(super) fn tls_offset(self, addend: i64) -> Option<u64> {
        let size = self.tls_size?;
        let offset = u64::try_from(i128::from(self.symbol.st_value) + i128::from(addend)).ok()?;
        (offset <= size).then_some(offset)
    }

    pub(super) fn tls_limit(self) -> Option<u64> {
        self.tls_size
    }

    fn compatible(self, other: Self) -> bool {
        // Reject a malformed same-name definition instead of interpreting a
        // TLS offset as data or a resolver address as an ordinary function.
        self.symbol.is_tls() == other.symbol.is_tls()
            && self.symbol.is_ifunc() == other.symbol.is_ifunc()
    }
}

type Index = BTreeMap<String, Selection>;
static UNIQUE: OnceLock<Mutex<Index>> = OnceLock::new();

fn registry() -> &'static Mutex<Index> {
    UNIQUE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[derive(Default)]
pub(super) struct Transaction {
    // Only new first selections, not a copy of the process-lifetime index.
    // Repeated lookups allocate no additional symbol-name entries.
    selected: RefCell<Index>,
}

impl Transaction {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn select(
        &self,
        provider: &NativeDso,
        symbol: &Elf64Symbol,
    ) -> Option<Selection> {
        let candidate = Selection::new(provider, symbol)?;
        if symbol.st_info >> 4 != STB_GNU_UNIQUE {
            // GLOBAL/WEAK must retain ordinary scope/preemption semantics,
            // even if a unique definition of this name was selected earlier.
            return Some(candidate);
        }
        let name = provider.object.symbol_name(symbol)?;
        if name.is_empty() {
            return None;
        }
        let published = registry().lock().ok()?.get(name).copied();
        let mut selected = self.selected.try_borrow_mut().ok()?;
        if let Some(chosen) = published.or_else(|| selected.get(name).copied()) {
            return chosen.compatible(candidate).then_some(chosen);
        }
        if provider.retiring && !super::process_exit::unloading() {
            // A dlclose finalization batch cannot be resurrected. Normal
            // process shutdown is different: it intentionally keeps every
            // mapping alive for later exit callbacks, even after FINI.
            return None;
        }
        selected.insert(name.to_owned(), candidate);
        Some(candidate)
    }

    /// The last fallible step before a load is published. Validate every owner
    /// and conflict before mutating either the unique index or any NODELETE
    /// bit. The operation lock excludes competing publications throughout a
    /// transaction; the conflict check also catches accidental reentrant use.
    pub(super) fn commit(
        self,
        resident: &mut [NativeDso],
        pending: &mut [NativeDso],
    ) -> Option<()> {
        let selected = self.selected.into_inner();
        if selected.is_empty() {
            return Some(());
        }
        let mut published = registry().lock().ok()?;
        for (name, definition) in &selected {
            if published.contains_key(name)
                || !resident.iter().chain(pending.iter()).any(|dso| {
                    dso.id == definition.provider
                        && (!dso.retiring || super::process_exit::unloading())
                })
            {
                return None;
            }
        }
        // No error returns after the first mutation. BTreeMap allocation
        // failure, like the surrounding loader's Vec allocations, aborts; it
        // is not a recoverable load error with partially published ownership.
        for (name, definition) in selected {
            for dso in resident.iter_mut().chain(pending.iter_mut()) {
                if dso.id == definition.provider {
                    dso.nodelete = true;
                    break;
                }
            }
            published.insert(name, definition);
        }
        Some(())
    }
}
