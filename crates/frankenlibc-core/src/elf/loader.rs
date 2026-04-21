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
    hash::{ElfHashTable, GnuHashTable, elf_hash},
    header::Elf64Header,
    program::{Elf64ProgramHeader, ProgramType, parse_program_headers},
    relocation::{
        Elf64Rela, RelocationContext, RelocationResult, compute_relocation, parse_relocations,
    },
    section::{Elf64SectionHeader, SectionType, parse_section_headers},
    symbol::{Elf64Symbol, get_string, parse_symbols},
};
use std::collections::BTreeMap;

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
    /// GNU hash table for fast lookup
    pub gnu_hash: Option<GnuHashTable>,
    /// ELF hash table for legacy lookup
    pub elf_hash: Option<ElfHashTable>,
    /// Parsed symbol version names indexed by dynsym slot
    pub symbol_versions: Vec<Option<String>>,
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
        self.lookup_symbol_versioned(name, None)
    }

    /// Look up a symbol by name and version in this object.
    pub fn lookup_symbol_versioned(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Option<&Elf64Symbol> {
        self.lookup_symbol_index(name, version)
            .and_then(|idx| self.dynsym.get(idx))
    }

    /// Get a symbol's name from the dynamic string table.
    pub fn symbol_name(&self, sym: &Elf64Symbol) -> Option<&str> {
        get_string(&self.dynstr, sym.st_name).ok()
    }

    /// Get the parsed version string for the dynsym slot, if present.
    pub fn symbol_version_by_index(&self, index: usize) -> Option<&str> {
        self.symbol_versions
            .get(index)
            .and_then(|version| version.as_deref())
    }

    fn lookup_symbol_index(&self, name: &str, version: Option<&str>) -> Option<usize> {
        if let Some(gnu_hash) = &self.gnu_hash
            && let Some(idx) = gnu_hash.lookup(name.as_bytes(), &self.dynsym, &self.dynstr)
            && self.symbol_matches_request(idx as usize, name, version)
        {
            return Some(idx as usize);
        }

        if let Some(elf_hash_table) = &self.elf_hash {
            let hash = elf_hash(name.as_bytes());
            if let Some(idx) =
                elf_hash_table.lookup(hash, name.as_bytes(), &self.dynsym, &self.dynstr)
                && self.symbol_matches_request(idx as usize, name, version)
            {
                return Some(idx as usize);
            }
        }

        self.dynsym
            .iter()
            .enumerate()
            .find(|(idx, _)| self.symbol_matches_request(*idx, name, version))
            .map(|(idx, _)| idx)
    }

    fn symbol_matches_request(&self, idx: usize, name: &str, version: Option<&str>) -> bool {
        let Some(sym) = self.dynsym.get(idx) else {
            return false;
        };
        if sym.is_undefined() || sym.is_local() || sym.is_hidden() {
            return false;
        }
        let Ok(sym_name) = get_string(&self.dynstr, sym.st_name) else {
            return false;
        };
        if sym_name != name {
            return false;
        }
        version.is_none_or(|requested| self.symbol_version_by_index(idx) == Some(requested))
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
        let (
            dynsym,
            dynstr,
            gnu_hash,
            elf_hash,
            symbol_versions,
            rela_dyn,
            rela_plt,
            init_array,
            fini_array,
        ) = if let Some(dyn_phdr) = dynamic_phdr {
            self.parse_dynamic_segment(data, &header, dyn_phdr, &section_headers)?
        } else {
            (
                Vec::new(),
                Vec::new(),
                None,
                None,
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
            gnu_hash,
            elf_hash,
            symbol_versions,
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
        header: &Elf64Header,
        _dyn_phdr: &Elf64ProgramHeader,
        sections: &[Elf64SectionHeader],
    ) -> ElfResult<(
        Vec<Elf64Symbol>,
        Vec<u8>,
        Option<GnuHashTable>,
        Option<ElfHashTable>,
        Vec<Option<String>>,
        Vec<Elf64Rela>,
        Vec<Elf64Rela>,
        Vec<u64>,
        Vec<u64>,
    )> {
        let mut dynsym = Vec::new();
        let mut dynstr = Vec::new();
        let mut dynsym_section: Option<&Elf64SectionHeader> = None;
        let mut gnu_hash = None;
        let mut elf_hash = None;
        let mut rela_dyn = Vec::new();
        let mut rela_plt = Vec::new();
        let mut init_array = Vec::new();
        let mut fini_array = Vec::new();

        let shstrtab = section_string_table(data, header, sections);

        for section in sections {
            match section.sh_type {
                SectionType::Dynsym => {
                    dynsym = parse_symbols(data, section.sh_offset, section.sh_size)?;
                    dynsym_section = Some(section);
                }
                SectionType::Hash if elf_hash.is_none() => {
                    if let Some(bytes) = section_data(data, section) {
                        elf_hash = ElfHashTable::parse(bytes);
                    }
                }
                SectionType::GnuHash if gnu_hash.is_none() => {
                    if let Some(bytes) = section_data(data, section) {
                        gnu_hash = GnuHashTable::parse(bytes);
                    }
                }
                SectionType::Rela => {
                    let relocs = parse_relocations(data, section.sh_offset, section.sh_size)?;
                    let section_name = shstrtab.and_then(|table| section_name(section, table));
                    if section_name
                        .is_some_and(|name| name.contains(".plt") || name.contains(".iplt"))
                    {
                        rela_plt.extend(relocs);
                    } else {
                        rela_dyn.extend(relocs);
                    }
                }
                SectionType::InitArray => {
                    if let Some(bytes) = section_data(data, section) {
                        init_array = parse_u64_array(bytes);
                    }
                }
                SectionType::FiniArray => {
                    if let Some(bytes) = section_data(data, section) {
                        fini_array = parse_u64_array(bytes);
                    }
                }
                SectionType::Strtab if dynstr.is_empty() => {
                    if let Some(dynsym_section) = dynsym_section
                        && let Some(linked) = sections.get(dynsym_section.sh_link as usize)
                        && std::ptr::eq(linked, section)
                        && let Some(bytes) = section_data(data, section)
                    {
                        dynstr = bytes.to_vec();
                    }
                }
                _ => {}
            }
        }

        if dynstr.is_empty()
            && let Some(dynsym_section) = dynsym_section
            && let Some(linked) = sections.get(dynsym_section.sh_link as usize)
            && let Some(bytes) = section_data(data, linked)
        {
            dynstr = bytes.to_vec();
        }

        let symbol_versions = if dynsym.is_empty() {
            Vec::new()
        } else {
            parse_symbol_versions(data, sections, dynsym.len())
        };

        Ok((
            dynsym,
            dynstr,
            gnu_hash,
            elf_hash,
            symbol_versions,
            rela_dyn,
            rela_plt,
            init_array,
            fini_array,
        ))
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
                let version = obj.symbol_version_by_index(sym_idx as usize);
                match resolver.lookup_versioned(name, version) {
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

fn section_data<'a>(data: &'a [u8], section: &Elf64SectionHeader) -> Option<&'a [u8]> {
    let start = section.sh_offset as usize;
    let end = start.checked_add(section.sh_size as usize)?;
    data.get(start..end)
}

fn section_string_table<'a>(
    data: &'a [u8],
    header: &Elf64Header,
    sections: &[Elf64SectionHeader],
) -> Option<&'a [u8]> {
    sections
        .get(header.e_shstrndx as usize)
        .and_then(|section| section_data(data, section))
}

fn section_name<'a>(section: &Elf64SectionHeader, shstrtab: &'a [u8]) -> Option<&'a str> {
    get_string(shstrtab, section.sh_name).ok()
}

fn parse_u64_array(data: &[u8]) -> Vec<u64> {
    data.chunks_exact(8)
        .map(|chunk| {
            u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ])
        })
        .collect()
}

fn parse_symbol_versions(
    data: &[u8],
    sections: &[Elf64SectionHeader],
    dynsym_len: usize,
) -> Vec<Option<String>> {
    let mut versions = vec![None; dynsym_len];
    let mut version_map = BTreeMap::new();
    let mut versym = Vec::new();

    for section in sections {
        match section.sh_type {
            SectionType::GnuVersym => {
                if let Some(bytes) = section_data(data, section) {
                    versym = bytes
                        .chunks_exact(2)
                        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect();
                }
            }
            SectionType::GnuVerdef => {
                if let Some(strings) = linked_string_table(data, sections, section)
                    && let Some(bytes) = section_data(data, section)
                {
                    parse_verdef_section(bytes, strings, &mut version_map);
                }
            }
            SectionType::GnuVerneed => {
                if let Some(strings) = linked_string_table(data, sections, section)
                    && let Some(bytes) = section_data(data, section)
                {
                    parse_verneed_section(bytes, strings, &mut version_map);
                }
            }
            _ => {}
        }
    }

    for (idx, raw) in versym.into_iter().enumerate().take(dynsym_len) {
        let version_idx = raw & 0x7fff;
        if version_idx > 1 {
            versions[idx] = version_map.get(&version_idx).cloned();
        }
    }

    versions
}

fn linked_string_table<'a>(
    data: &'a [u8],
    sections: &[Elf64SectionHeader],
    section: &Elf64SectionHeader,
) -> Option<&'a [u8]> {
    sections
        .get(section.sh_link as usize)
        .and_then(|linked| section_data(data, linked))
}

fn parse_verdef_section(data: &[u8], strings: &[u8], version_map: &mut BTreeMap<u16, String>) {
    let mut offset = 0usize;
    while offset + 20 <= data.len() {
        let version_index = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
        let aux_offset = u32::from_le_bytes([
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]) as usize;
        let next_offset = u32::from_le_bytes([
            data[offset + 16],
            data[offset + 17],
            data[offset + 18],
            data[offset + 19],
        ]) as usize;

        if let Some(name) = parse_verdef_name(data, offset, aux_offset, strings) {
            version_map.insert(version_index, name);
        }

        if next_offset == 0 {
            break;
        }
        let Some(next) = offset.checked_add(next_offset) else {
            break;
        };
        if next <= offset {
            break;
        }
        offset = next;
    }
}

fn parse_verdef_name(
    data: &[u8],
    base: usize,
    aux_offset: usize,
    strings: &[u8],
) -> Option<String> {
    let aux = base.checked_add(aux_offset)?;
    let name_offset = u32::from_le_bytes([
        *data.get(aux)?,
        *data.get(aux + 1)?,
        *data.get(aux + 2)?,
        *data.get(aux + 3)?,
    ]);
    get_string(strings, name_offset).ok().map(str::to_owned)
}

fn parse_verneed_section(data: &[u8], strings: &[u8], version_map: &mut BTreeMap<u16, String>) {
    let mut offset = 0usize;
    while offset + 16 <= data.len() {
        let aux_offset = u32::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]) as usize;
        let next_offset = u32::from_le_bytes([
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]) as usize;

        let mut aux = match offset.checked_add(aux_offset) {
            Some(aux) => aux,
            None => break,
        };

        while aux + 16 <= data.len() {
            let version_index = u16::from_le_bytes([data[aux + 6], data[aux + 7]]) & 0x7fff;
            let name_offset =
                u32::from_le_bytes([data[aux + 8], data[aux + 9], data[aux + 10], data[aux + 11]]);
            let aux_next = u32::from_le_bytes([
                data[aux + 12],
                data[aux + 13],
                data[aux + 14],
                data[aux + 15],
            ]) as usize;

            if version_index > 1
                && let Ok(name) = get_string(strings, name_offset)
            {
                version_map.insert(version_index, name.to_owned());
            }

            if aux_next == 0 {
                break;
            }
            let Some(next_aux) = aux.checked_add(aux_next) else {
                break;
            };
            if next_aux <= aux {
                break;
            }
            aux = next_aux;
        }

        if next_offset == 0 {
            break;
        }
        let Some(next) = offset.checked_add(next_offset) else {
            break;
        };
        if next <= offset {
            break;
        }
        offset = next;
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
    use std::cell::RefCell;

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

    fn empty_loaded_object() -> LoadedObject {
        LoadedObject {
            base: 0,
            entry: None,
            program_headers: Vec::new(),
            section_headers: Vec::new(),
            dynsym: Vec::new(),
            dynstr: Vec::new(),
            gnu_hash: None,
            elf_hash: None,
            symbol_versions: Vec::new(),
            rela_dyn: Vec::new(),
            rela_plt: Vec::new(),
            init_array: Vec::new(),
            fini_array: Vec::new(),
            relro_start: None,
            relro_size: 0,
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

    #[test]
    fn test_lookup_symbol_versioned_prefers_matching_version() {
        let mut obj = empty_loaded_object();
        obj.dynstr = b"\0foo\0".to_vec();
        obj.dynsym = vec![
            Elf64Symbol {
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            },
            Elf64Symbol {
                st_name: 1,
                st_info: 0x12,
                st_other: 0,
                st_shndx: 1,
                st_value: 0x1000,
                st_size: 0,
            },
            Elf64Symbol {
                st_name: 1,
                st_info: 0x12,
                st_other: 0,
                st_shndx: 1,
                st_value: 0x2000,
                st_size: 0,
            },
        ];
        obj.symbol_versions = vec![None, Some("VER_1".to_owned()), Some("VER_2".to_owned())];

        assert_eq!(obj.lookup_symbol("foo").unwrap().st_value, 0x1000);
        assert_eq!(
            obj.lookup_symbol_versioned("foo", Some("VER_2"))
                .unwrap()
                .st_value,
            0x2000
        );
        assert!(obj.lookup_symbol_versioned("foo", Some("VER_X")).is_none());
    }

    #[test]
    fn test_apply_relocations_passes_symbol_version_to_resolver() {
        struct RecordingResolver {
            resolved: u64,
            calls: RefCell<Vec<(String, Option<String>)>>,
        }

        impl SymbolLookup for RecordingResolver {
            fn lookup(&self, _name: &str) -> Option<u64> {
                None
            }

            fn lookup_versioned(&self, name: &str, version: Option<&str>) -> Option<u64> {
                self.calls
                    .borrow_mut()
                    .push((name.to_owned(), version.map(str::to_owned)));
                Some(self.resolved)
            }
        }

        let loader = ElfLoader::new(0x7f00_0000_0000);
        let mut obj = empty_loaded_object();
        obj.dynstr = b"\0malloc\0".to_vec();
        obj.dynsym = vec![
            Elf64Symbol {
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            },
            Elf64Symbol {
                st_name: 1,
                st_info: 0x12,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            },
        ];
        obj.symbol_versions = vec![None, Some("GLIBC_2.2.5".to_owned())];
        obj.rela_dyn = vec![Elf64Rela {
            r_offset: 0,
            r_info: ((1u64) << 32) | 6,
            r_addend: 0,
        }];

        let resolver = RecordingResolver {
            resolved: 0x7f00_1234_5678,
            calls: RefCell::new(Vec::new()),
        };
        let mut memory = [0u8; 8];
        let results = loader.apply_relocations(&obj, &mut memory, &resolver);

        assert_eq!(results, vec![(0, RelocationResult::Applied)]);
        assert_eq!(u64::from_le_bytes(memory), resolver.resolved);
        assert_eq!(
            resolver.calls.into_inner(),
            vec![("malloc".to_owned(), Some("GLIBC_2.2.5".to_owned()))]
        );
    }
}
