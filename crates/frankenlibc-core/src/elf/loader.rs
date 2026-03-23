//! ELF object loader and symbol resolution.
//!
//! This module provides the high-level interface for loading shared objects
//! and resolving symbols. It coordinates parsing, relocation, and symbol
//! lookup across the ELF infrastructure.
//!
//! # Phase 1 Limitations
//!
//! - No IFUNC support
//! - No TLS support
//! - Single object loading only (no dependency resolution)
//! - x86_64 Linux only

use super::{
    ElfResult,
    header::Elf64Header,
    program::{Elf64ProgramHeader, ProgramType, parse_program_headers},
    relocation::{
        Elf64Rela, RelocationContext, RelocationResult, compute_relocation, parse_relocations,
    },
    section::{Elf64SectionHeader, SectionType, parse_section_headers},
    symbol::{Elf64Symbol, get_string, parse_symbols},
};

/// A loaded ELF object.
#[derive(Debug)]
pub struct LoadedObject {
    /// Base address where object is loaded
    pub base: u64,
    /// Entry point address (if executable)
    pub entry: Option<u64>,
    /// Program headers
    pub program_headers: Vec<Elf64ProgramHeader>,
    /// Section headers (if available)
    pub section_headers: Vec<Elf64SectionHeader>,
    /// Dynamic symbols
    pub dynsym: Vec<Elf64Symbol>,
    /// Dynamic string table
    pub dynstr: Vec<u8>,
    /// Relocations to apply
    pub rela_dyn: Vec<Elf64Rela>,
    /// PLT relocations
    pub rela_plt: Vec<Elf64Rela>,
    /// Initialization functions
    pub init_array: Vec<u64>,
    /// Finalization functions
    pub fini_array: Vec<u64>,
    /// RELRO start address (for mprotect)
    pub relro_start: Option<u64>,
    /// RELRO size
    pub relro_size: u64,
}

impl LoadedObject {
    /// Check if this object has any unsupported relocations.
    pub fn has_unsupported_relocations(&self) -> bool {
        self.rela_dyn
            .iter()
            .chain(self.rela_plt.iter())
            .any(|r| !r.reloc_type().is_supported())
    }

    /// Get the list of undefined symbols that need resolution.
    pub fn undefined_symbols(&self) -> impl Iterator<Item = (u32, &Elf64Symbol)> {
        self.dynsym
            .iter()
            .enumerate()
            .filter(|(_, sym)| sym.is_undefined() && !sym.is_local())
            .map(|(i, sym)| (i as u32, sym))
    }

    /// Look up a symbol by name in this object.
    pub fn lookup_symbol(&self, name: &str) -> Option<&Elf64Symbol> {
        let _name_bytes = name.as_bytes();
        self.dynsym.iter().find(|sym| {
            if sym.is_undefined() || sym.is_local() {
                return false;
            }
            if let Ok(sym_name) = get_string(&self.dynstr, sym.st_name) {
                sym_name == name
            } else {
                false
            }
        })
    }

    /// Get a symbol's name from the dynamic string table.
    pub fn symbol_name(&self, sym: &Elf64Symbol) -> Option<&str> {
        get_string(&self.dynstr, sym.st_name).ok()
    }
}

/// Symbol lookup trait for external symbol resolution.
pub trait SymbolLookup {
    /// Look up a symbol by name.
    ///
    /// Returns the symbol's runtime address, or None if not found.
    fn lookup(&self, name: &str) -> Option<u64>;

    /// Look up a symbol with version information.
    ///
    /// Default implementation ignores version and calls `lookup`.
    fn lookup_versioned(&self, name: &str, _version: Option<&str>) -> Option<u64> {
        self.lookup(name)
    }
}

/// Simple symbol lookup that returns None for all queries.
pub struct NullSymbolLookup;

impl SymbolLookup for NullSymbolLookup {
    fn lookup(&self, _name: &str) -> Option<u64> {
        None
    }
}

/// ELF loader for parsing and loading shared objects.
pub struct ElfLoader {
    /// Relocation context
    ctx: RelocationContext,
}

impl ElfLoader {
    /// Create a new ELF loader with the given base address.
    pub fn new(base: u64) -> Self {
        Self {
            ctx: RelocationContext::new(base),
        }
    }

    /// Set the GOT base address.
    pub fn with_got(mut self, got: u64) -> Self {
        self.ctx = self.ctx.with_got(got);
        self
    }

    /// Parse an ELF file from a byte slice.
    ///
    /// This parses all headers and tables but does not apply relocations.
    pub fn parse(&self, data: &[u8]) -> ElfResult<LoadedObject> {
        // Parse header
        let header = Elf64Header::parse(data)?;
        header.validate_for_x86_64()?;

        // Parse program headers
        let program_headers =
            parse_program_headers(data, header.e_phoff, header.e_phentsize, header.e_phnum)?;

        // Parse section headers (optional)
        let section_headers = if header.e_shoff != 0 && header.e_shnum != 0 {
            parse_section_headers(data, header.e_shoff, header.e_shentsize, header.e_shnum)?
        } else {
            Vec::new()
        };

        // Find dynamic segment
        let dynamic_phdr = program_headers
            .iter()
            .find(|ph| matches!(ph.p_type, ProgramType::Dynamic));

        // Extract dynamic info from PT_DYNAMIC segment
        let (dynsym, dynstr, rela_dyn, rela_plt, init_array, fini_array) =
            if let Some(dyn_phdr) = dynamic_phdr {
                self.parse_dynamic_segment(data, dyn_phdr, &section_headers)?
            } else {
                (
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )
            };

        // Find RELRO segment
        let (relro_start, relro_size) = program_headers
            .iter()
            .find(|ph| ph.is_relro())
            .map(|ph| (Some(self.ctx.base + ph.p_vaddr), ph.p_memsz))
            .unwrap_or((None, 0));

        // Determine entry point
        let entry = if header.e_entry != 0 {
            Some(self.ctx.base + header.e_entry)
        } else {
            None
        };

        Ok(LoadedObject {
            base: self.ctx.base,
            entry,
            program_headers,
            section_headers,
            dynsym,
            dynstr,
            rela_dyn,
            rela_plt,
            init_array,
            fini_array,
            relro_start,
            relro_size,
        })
    }

    /// Parse the dynamic segment to extract symbols, strings, and relocations.
    #[allow(clippy::type_complexity)]
    fn parse_dynamic_segment(
        &self,
        data: &[u8],
        _dyn_phdr: &Elf64ProgramHeader,
        sections: &[Elf64SectionHeader],
    ) -> ElfResult<(
        Vec<Elf64Symbol>,
        Vec<u8>,
        Vec<Elf64Rela>,
        Vec<Elf64Rela>,
        Vec<u64>,
        Vec<u64>,
    )> {
        // For now, fall back to section-based parsing
        // A full implementation would parse DT_* entries from the dynamic segment

        let mut dynsym = Vec::new();
        let mut dynstr = Vec::new();
        let mut rela_dyn = Vec::new();
        let rela_plt = Vec::new();
        let init_array = Vec::new();
        let fini_array = Vec::new();

        // Find .dynsym section
        for section in sections {
            match section.sh_type {
                SectionType::Dynsym => {
                    dynsym = parse_symbols(data, section.sh_offset, section.sh_size)?;
                }
                SectionType::Strtab if dynstr.is_empty() => {
                    // Assume first strtab is dynstr (simplification)
                    let start = section.sh_offset as usize;
                    let end = start + section.sh_size as usize;
                    if end <= data.len() {
                        dynstr = data[start..end].to_vec();
                    }
                }
                SectionType::Strtab => {}
                SectionType::Rela => {
                    let relocs = parse_relocations(data, section.sh_offset, section.sh_size)?;
                    // Distinguish .rela.dyn from .rela.plt by section name or flags
                    // For now, put all in rela_dyn
                    rela_dyn.extend(relocs);
                }
                _ => {}
            }
        }

        Ok((dynsym, dynstr, rela_dyn, rela_plt, init_array, fini_array))
    }

    /// Apply relocations to a loaded object.
    ///
    /// # Arguments
    ///
    /// * `obj` - The loaded object
    /// * `memory` - Mutable memory where relocations are applied
    /// * `resolver` - Symbol resolver for undefined symbols
    ///
    /// # Returns
    ///
    /// A list of relocation results (success, skipped, deferred, or error).
    pub fn apply_relocations<S: SymbolLookup>(
        &self,
        obj: &LoadedObject,
        memory: &mut [u8],
        resolver: &S,
    ) -> Vec<(usize, RelocationResult)> {
        let mut results = Vec::new();

        for (i, reloc) in obj.rela_dyn.iter().chain(obj.rela_plt.iter()).enumerate() {
            let result = self.apply_single_relocation(obj, memory, reloc, resolver);
            results.push((i, result));
        }

        results
    }

    /// Apply a single relocation.
    fn apply_single_relocation<S: SymbolLookup>(
        &self,
        obj: &LoadedObject,
        memory: &mut [u8],
        reloc: &Elf64Rela,
        resolver: &S,
    ) -> RelocationResult {
        let sym_idx = reloc.symbol_index();

        // Get symbol value
        let symbol_value = if sym_idx == 0 {
            0 // No symbol
        } else {
            let sym = match obj.dynsym.get(sym_idx as usize) {
                Some(s) => s,
                None => return RelocationResult::SymbolNotFound,
            };

            if sym.is_defined() {
                // Symbol defined in this object
                self.ctx.base + sym.st_value
            } else {
                // Need external resolution
                let name = match get_string(&obj.dynstr, sym.st_name) {
                    Ok(n) => n,
                    Err(_) => return RelocationResult::SymbolNotFound,
                };
                match resolver.lookup(name) {
                    Some(addr) => addr,
                    None if sym.is_weak() => 0, // Weak symbols resolve to 0 if not found
                    None => return RelocationResult::SymbolNotFound,
                }
            }
        };

        // Compute relocation value
        let (value, size) = match compute_relocation(reloc, symbol_value, &self.ctx) {
            Ok(v) => v,
            Err(r) => return r,
        };

        // Apply to memory
        let offset = reloc.r_offset as usize;
        if offset + size > memory.len() {
            return RelocationResult::Overflow;
        }

        match size {
            4 => {
                memory[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
            }
            8 => {
                memory[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            }
            _ => return RelocationResult::Overflow,
        }

        RelocationResult::Applied
    }
}

/// Statistics about relocation processing.
#[derive(Debug, Default, Clone, Copy)]
pub struct RelocationStats {
    /// Total relocations processed
    pub total: usize,
    /// Successfully applied
    pub applied: usize,
    /// Skipped (R_X86_64_NONE)
    pub skipped: usize,
    /// Deferred (e.g., COPY)
    pub deferred: usize,
    /// Failed due to missing symbol
    pub symbol_not_found: usize,
    /// Unsupported relocation type
    pub unsupported: usize,
    /// Overflow errors
    pub overflow: usize,
}

impl RelocationStats {
    /// Collect statistics from relocation results.
    pub fn from_results(results: &[(usize, RelocationResult)]) -> Self {
        let mut stats = Self {
            total: results.len(),
            ..Self::default()
        };

        for (_, result) in results {
            match result {
                RelocationResult::Applied => stats.applied += 1,
                RelocationResult::Skipped => stats.skipped += 1,
                RelocationResult::Deferred => stats.deferred += 1,
                RelocationResult::SymbolNotFound => stats.symbol_not_found += 1,
                RelocationResult::Unsupported(_) => stats.unsupported += 1,
                RelocationResult::Overflow => stats.overflow += 1,
            }
        }

        stats
    }

    /// Check if all relocations were successful.
    pub fn all_successful(&self) -> bool {
        self.symbol_not_found == 0 && self.unsupported == 0 && self.overflow == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    struct TestResolver {
        symbols: Vec<(&'static str, u64)>,
    }

    impl SymbolLookup for TestResolver {
        fn lookup(&self, name: &str) -> Option<u64> {
            self.symbols
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, addr)| *addr)
        }
    }

    #[test]
    fn test_null_lookup() {
        let resolver = NullSymbolLookup;
        assert!(resolver.lookup("anything").is_none());
    }

    #[test]
    fn test_relocation_stats() {
        let results = vec![
            (0, RelocationResult::Applied),
            (1, RelocationResult::Applied),
            (2, RelocationResult::Skipped),
            (3, RelocationResult::SymbolNotFound),
            (4, RelocationResult::Unsupported(99)),
        ];

        let stats = RelocationStats::from_results(&results);
        assert_eq!(stats.total, 5);
        assert_eq!(stats.applied, 2);
        assert_eq!(stats.skipped, 1);
        assert_eq!(stats.symbol_not_found, 1);
        assert_eq!(stats.unsupported, 1);
        assert!(!stats.all_successful());
    }

    #[test]
    fn test_stats_all_successful() {
        let results = vec![
            (0, RelocationResult::Applied),
            (1, RelocationResult::Skipped),
            (2, RelocationResult::Applied),
        ];

        let stats = RelocationStats::from_results(&results);
        assert!(stats.all_successful());
    }

    #[test]
    fn test_loader_creation() {
        let loader = ElfLoader::new(0x7f00_0000_0000);
        assert_eq!(loader.ctx.base, 0x7f00_0000_0000);
        assert!(loader.ctx.got.is_none());

        let loader = loader.with_got(0x7f00_0000_1000);
        assert_eq!(loader.ctx.got, Some(0x7f00_0000_1000));
    }
}
