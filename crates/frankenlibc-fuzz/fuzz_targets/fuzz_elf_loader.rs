#![no_main]
//! Structure-aware fuzz target for FrankenLibC ELF parsing and relocation.
//!
//! Exercises raw parser rejection paths and a normalized ELF64 object that
//! drives the loader through symbol lookup and relocation application.
//!
//! Coverage goals:
//! - ELF header parsing and x86_64 validation
//! - program/section/symbol/relocation table parsers
//! - ELF and GNU hash helpers
//! - loader parse, symbol lookup, undefined-symbol iteration
//! - relocation application with missing and present resolvers
//!
//! Bead: bd-hnec

use libfuzzer_sys::fuzz_target;

use frankenlibc_core::elf::hash::ElfHashTable;
use frankenlibc_core::elf::program::{ProgramType, parse_program_headers};
use frankenlibc_core::elf::relocation::{
    RelocationContext, RelocationType, compute_relocation, parse_relocations,
};
use frankenlibc_core::elf::section::{SectionType, parse_section_headers};
use frankenlibc_core::elf::symbol::{Elf64Symbol, get_string, parse_symbols};
use frankenlibc_core::elf::{
    self, Elf64Header, ElfLoader, GnuHashTable, NullSymbolLookup, RelocationResult,
    RelocationStats, SymbolLookup, elf_hash, gnu_hash,
};

const MAX_INPUT: usize = 16 * 1024;
const MAX_TABLE_COUNT: usize = 8;
const PROGRAM_HEADER_COUNT: usize = 2;
const SECTION_HEADER_COUNT: usize = 4;
const SYMBOL_COUNT: usize = 3;
const RELOCATION_COUNT: usize = 3;
const DYNSTR: &[u8] = b"\0alpha\0beta\0gamma\0";

const ELF_HEADER_SIZE: usize = Elf64Header::SIZE;
const PROGRAM_HEADER_SIZE: usize = elf::program::Elf64ProgramHeader::SIZE;
const SECTION_HEADER_SIZE: usize = elf::section::Elf64SectionHeader::SIZE;
const SYMBOL_SIZE: usize = Elf64Symbol::SIZE;
const RELA_SIZE: usize = elf::relocation::Elf64Rela::SIZE;

const PROGRAM_HEADER_OFFSET: usize = ELF_HEADER_SIZE;
const SECTION_HEADER_OFFSET: usize =
    PROGRAM_HEADER_OFFSET + PROGRAM_HEADER_COUNT * PROGRAM_HEADER_SIZE;
const DYNSYM_OFFSET: usize = SECTION_HEADER_OFFSET + SECTION_HEADER_COUNT * SECTION_HEADER_SIZE;
const DYNSYM_SIZE: usize = SYMBOL_COUNT * SYMBOL_SIZE;
const DYNSTR_OFFSET: usize = DYNSYM_OFFSET + DYNSYM_SIZE;
const RELA_OFFSET: usize = DYNSTR_OFFSET + DYNSTR.len();
const RELA_SECTION_SIZE: usize = RELOCATION_COUNT * RELA_SIZE;
const PAYLOAD_OFFSET: usize = RELA_OFFSET + RELA_SECTION_SIZE;
const NORMALIZED_MEMORY_SIZE: usize = 0x80;

struct ProgramHeaderSpec {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

struct SectionHeaderSpec {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT {
        return;
    }

    fuzz_raw_views(data);

    let image = build_normalized_elf_image(data);
    fuzz_normalized_loader(data, &image);
});

fn fuzz_raw_views(data: &[u8]) {
    let name = &data[..data.len().min(64)];

    assert_eq!(elf_hash(name), elf_hash(name));
    assert_eq!(gnu_hash(name), gnu_hash(name));

    if let Some(table) = GnuHashTable::parse(data) {
        let _ = table.bloom_check(gnu_hash(name));
    }
    if let Some(table) = ElfHashTable::parse(data) {
        let _ = table.lookup(elf_hash(name), name);
    }

    if let Ok(header) = Elf64Header::parse(data) {
        let _ = header.class();
        let _ = header.data();
        let _ = header.osabi();
        let _ = header.abi_version();
        let _ = header.is_shared_object();
        let _ = header.is_executable();
        let _ = header.validate_for_x86_64();
    }

    let phoff = bounded_offset(data, 0);
    let shoff = bounded_offset(data, 2);
    let symoff = bounded_offset(data, 4);
    let reloff = bounded_offset(data, 6);

    let phnum = bounded_count(data, 8);
    let shnum = bounded_count(data, 9);
    let symnum = bounded_count(data, 10);
    let reloc_count = bounded_count(data, 11);

    let _ = parse_program_headers(data, phoff as u64, PROGRAM_HEADER_SIZE as u16, phnum as u16);
    let _ = parse_section_headers(data, shoff as u64, SECTION_HEADER_SIZE as u16, shnum as u16);

    if let Ok(symbols) = parse_symbols(data, symoff as u64, (symnum * SYMBOL_SIZE) as u64) {
        for symbol in symbols.iter().take(4) {
            let _ = symbol.binding();
            let _ = symbol.symbol_type();
            let _ = symbol.visibility();
            let _ = symbol.is_undefined();
            let _ = symbol.is_function();
            let _ = symbol.is_object();
            let _ = symbol.is_ifunc();
            let _ = symbol.is_tls();
        }
    }

    let ctx = RelocationContext::new(derived_base(data)).with_got(derived_got(data));
    if let Ok(relocs) = parse_relocations(data, reloff as u64, (reloc_count * RELA_SIZE) as u64) {
        for reloc in relocs.iter().take(4) {
            let _ = reloc.reloc_type();
            let _ = reloc.symbol_index();
            let _ = compute_relocation(reloc, derived_symbol_value(data), &ctx);
        }
    }

    let string_index = bounded_offset(data, 12).min(data.len() - 1) as u32;
    let _ = get_string(data, string_index);
}

fn fuzz_normalized_loader(seed: &[u8], image: &[u8]) {
    let base = derived_base(seed);
    let got = derived_got(seed);
    let ctx = RelocationContext::new(base).with_got(got);

    let header = match Elf64Header::parse(image) {
        Ok(header) => header,
        Err(_) => return,
    };
    assert!(header.is_x86_64());
    assert!(header.validate_for_x86_64().is_ok());

    let program_headers = match parse_program_headers(
        image,
        PROGRAM_HEADER_OFFSET as u64,
        PROGRAM_HEADER_SIZE as u16,
        PROGRAM_HEADER_COUNT as u16,
    ) {
        Ok(headers) => headers,
        Err(_) => return,
    };
    assert_eq!(program_headers.len(), PROGRAM_HEADER_COUNT);
    assert!(program_headers.iter().any(|header| header.is_load()));
    assert!(program_headers.iter().any(|header| header.is_dynamic()));
    assert!(
        program_headers
            .iter()
            .any(|header| matches!(header.p_type, ProgramType::Dynamic))
    );

    let section_headers = match parse_section_headers(
        image,
        SECTION_HEADER_OFFSET as u64,
        SECTION_HEADER_SIZE as u16,
        SECTION_HEADER_COUNT as u16,
    ) {
        Ok(headers) => headers,
        Err(_) => return,
    };
    assert_eq!(section_headers.len(), SECTION_HEADER_COUNT);
    assert!(
        section_headers
            .iter()
            .any(|header| matches!(header.sh_type, SectionType::Dynsym))
    );
    assert!(
        section_headers
            .iter()
            .any(|header| matches!(header.sh_type, SectionType::Strtab))
    );
    assert!(
        section_headers
            .iter()
            .any(|header| matches!(header.sh_type, SectionType::Rela))
    );

    let symbols = match parse_symbols(image, DYNSYM_OFFSET as u64, DYNSYM_SIZE as u64) {
        Ok(symbols) => symbols,
        Err(_) => return,
    };
    assert_eq!(symbols.len(), SYMBOL_COUNT);

    let relocs = match parse_relocations(image, RELA_OFFSET as u64, RELA_SECTION_SIZE as u64) {
        Ok(relocs) => relocs,
        Err(_) => return,
    };
    assert_eq!(relocs.len(), RELOCATION_COUNT);

    let loader = ElfLoader::new(base).with_got(got);
    let obj = match loader.parse(image) {
        Ok(obj) => obj,
        Err(_) => return,
    };

    assert_eq!(obj.base, base);
    assert_eq!(obj.entry, Some(base + 0x80));
    assert_eq!(obj.dynstr.as_slice(), DYNSTR);
    assert_eq!(obj.program_headers.len(), PROGRAM_HEADER_COUNT);
    assert_eq!(obj.section_headers.len(), SECTION_HEADER_COUNT);
    assert_eq!(obj.dynsym.len(), SYMBOL_COUNT);
    assert_eq!(obj.rela_dyn.len(), RELOCATION_COUNT);
    assert!(obj.rela_plt.is_empty());
    assert!(!obj.has_unsupported_relocations());

    assert_eq!(get_string(obj.dynstr.as_slice(), 1).ok(), Some("alpha"));
    assert_eq!(get_string(obj.dynstr.as_slice(), 7).ok(), Some("beta"));

    let alpha = match obj.lookup_symbol("alpha") {
        Some(symbol) => symbol,
        None => return,
    };
    assert!(alpha.is_defined());
    assert!(!alpha.is_local());
    assert_eq!(obj.symbol_name(alpha), Some("alpha"));
    assert!(obj.lookup_symbol("beta").is_none());

    let undefined: Vec<_> = obj.undefined_symbols().collect();
    assert_eq!(undefined.len(), 1);
    assert_eq!(obj.symbol_name(undefined[0].1), Some("beta"));

    let null = NullSymbolLookup;
    let mut null_memory = vec![0u8; NORMALIZED_MEMORY_SIZE];
    let null_results = loader.apply_relocations(&obj, &mut null_memory, &null);
    let null_stats = RelocationStats::from_results(&null_results);
    assert_eq!(null_stats.total, RELOCATION_COUNT);
    assert_eq!(null_stats.symbol_not_found, 1);
    assert!(!null_stats.all_successful());

    let resolver = DeterministicResolver;
    let mut memory = vec![0u8; NORMALIZED_MEMORY_SIZE];
    let results = loader.apply_relocations(&obj, &mut memory, &resolver);
    let stats = RelocationStats::from_results(&results);
    assert_eq!(stats.total, RELOCATION_COUNT);
    assert_eq!(
        stats.applied
            + stats.skipped
            + stats.deferred
            + stats.symbol_not_found
            + stats.unsupported
            + stats.overflow,
        stats.total
    );
    assert_eq!(stats.applied, RELOCATION_COUNT);
    assert!(stats.all_successful());

    for (index, result) in &results {
        assert_eq!(*result, RelocationResult::Applied);
        if *index >= obj.rela_dyn.len() {
            continue;
        }
        let reloc = &obj.rela_dyn[*index];
        let symbol_value = resolved_symbol_value(&obj, reloc, &resolver, base);
        let (expected, size) = match compute_relocation(reloc, symbol_value, &ctx) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let offset = reloc.r_offset as usize;
        assert!(offset + size <= memory.len());
        let stored = read_written_value(&memory, offset, size);
        assert_eq!(stored, expected);
    }
}

fn build_normalized_elf_image(seed: &[u8]) -> Vec<u8> {
    let payload_len = seed.len().min(256);
    let mut image = vec![0u8; PAYLOAD_OFFSET + payload_len];
    let image_len = image.len() as u64;

    if payload_len != 0 {
        image[PAYLOAD_OFFSET..PAYLOAD_OFFSET + payload_len].copy_from_slice(&seed[..payload_len]);
    }

    image[0..4].copy_from_slice(&elf::ELF_MAGIC);
    image[4] = 2;
    image[5] = 1;
    image[6] = 1;
    image[7] = 3;
    image[16..18].copy_from_slice(&elf_type(seed).to_le_bytes());
    image[18..20].copy_from_slice(&62u16.to_le_bytes());
    image[20..24].copy_from_slice(&1u32.to_le_bytes());
    image[24..32].copy_from_slice(&0x80u64.to_le_bytes());
    image[32..40].copy_from_slice(&(PROGRAM_HEADER_OFFSET as u64).to_le_bytes());
    image[40..48].copy_from_slice(&(SECTION_HEADER_OFFSET as u64).to_le_bytes());
    image[52..54].copy_from_slice(&(ELF_HEADER_SIZE as u16).to_le_bytes());
    image[54..56].copy_from_slice(&(PROGRAM_HEADER_SIZE as u16).to_le_bytes());
    image[56..58].copy_from_slice(&(PROGRAM_HEADER_COUNT as u16).to_le_bytes());
    image[58..60].copy_from_slice(&(SECTION_HEADER_SIZE as u16).to_le_bytes());
    image[60..62].copy_from_slice(&(SECTION_HEADER_COUNT as u16).to_le_bytes());
    image[62..64].copy_from_slice(&0u16.to_le_bytes());

    write_program_header(
        &mut image[PROGRAM_HEADER_OFFSET..PROGRAM_HEADER_OFFSET + PROGRAM_HEADER_SIZE],
        ProgramHeaderSpec {
            p_type: 1,
            p_flags: load_flags(seed),
            p_offset: 0,
            p_vaddr: 0,
            p_filesz: image_len,
            p_memsz: image_len,
            p_align: 0x1000,
        },
    );
    write_program_header(
        &mut image[PROGRAM_HEADER_OFFSET + PROGRAM_HEADER_SIZE
            ..PROGRAM_HEADER_OFFSET + PROGRAM_HEADER_COUNT * PROGRAM_HEADER_SIZE],
        ProgramHeaderSpec {
            p_type: 2,
            p_flags: 4,
            p_offset: DYNSYM_OFFSET as u64,
            p_vaddr: DYNSYM_OFFSET as u64,
            p_filesz: (PAYLOAD_OFFSET - DYNSYM_OFFSET) as u64,
            p_memsz: (PAYLOAD_OFFSET - DYNSYM_OFFSET) as u64,
            p_align: 8,
        },
    );

    write_section_header(
        &mut image[SECTION_HEADER_OFFSET + SECTION_HEADER_SIZE
            ..SECTION_HEADER_OFFSET + 2 * SECTION_HEADER_SIZE],
        SectionHeaderSpec {
            sh_name: 0,
            sh_type: 11,
            sh_flags: 2,
            sh_addr: DYNSYM_OFFSET as u64,
            sh_offset: DYNSYM_OFFSET as u64,
            sh_size: DYNSYM_SIZE as u64,
            sh_link: 2,
            sh_info: 1,
            sh_addralign: 8,
            sh_entsize: SYMBOL_SIZE as u64,
        },
    );
    write_section_header(
        &mut image[SECTION_HEADER_OFFSET + 2 * SECTION_HEADER_SIZE
            ..SECTION_HEADER_OFFSET + 3 * SECTION_HEADER_SIZE],
        SectionHeaderSpec {
            sh_name: 0,
            sh_type: 3,
            sh_flags: 2,
            sh_addr: DYNSTR_OFFSET as u64,
            sh_offset: DYNSTR_OFFSET as u64,
            sh_size: DYNSTR.len() as u64,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
        },
    );
    write_section_header(
        &mut image[SECTION_HEADER_OFFSET + 3 * SECTION_HEADER_SIZE
            ..SECTION_HEADER_OFFSET + 4 * SECTION_HEADER_SIZE],
        SectionHeaderSpec {
            sh_name: 0,
            sh_type: 4,
            sh_flags: 2,
            sh_addr: RELA_OFFSET as u64,
            sh_offset: RELA_OFFSET as u64,
            sh_size: RELA_SECTION_SIZE as u64,
            sh_link: 1,
            sh_info: 0,
            sh_addralign: 8,
            sh_entsize: RELA_SIZE as u64,
        },
    );

    write_symbol(
        &mut image[DYNSYM_OFFSET + SYMBOL_SIZE..DYNSYM_OFFSET + 2 * SYMBOL_SIZE],
        1,
        0x12,
        0,
        1,
        0x120,
        0x20,
    );
    write_symbol(
        &mut image[DYNSYM_OFFSET + 2 * SYMBOL_SIZE..DYNSYM_OFFSET + 3 * SYMBOL_SIZE],
        7,
        0x12,
        0,
        0,
        0,
        0x10,
    );
    image[DYNSTR_OFFSET..DYNSTR_OFFSET + DYNSTR.len()].copy_from_slice(DYNSTR);

    write_relocation(
        &mut image[RELA_OFFSET..RELA_OFFSET + RELA_SIZE],
        0x20,
        0,
        RelocationType::Relative.to_u32(),
        i64::from(seed_byte(seed, 5) & 0x3f),
    );
    write_relocation(
        &mut image[RELA_OFFSET + RELA_SIZE..RELA_OFFSET + 2 * RELA_SIZE],
        0x28,
        2,
        loader_symbol_reloc(seed).to_u32(),
        0,
    );
    write_relocation(
        &mut image[RELA_OFFSET + 2 * RELA_SIZE..RELA_OFFSET + 3 * RELA_SIZE],
        0x30,
        1,
        data_symbol_reloc(seed).to_u32(),
        i64::from(seed_byte(seed, 6) as i8),
    );

    image
}

fn elf_type(seed: &[u8]) -> u16 {
    if seed_byte(seed, 4) & 1 == 0 { 3 } else { 2 }
}

fn load_flags(seed: &[u8]) -> u32 {
    4 | u32::from(seed_byte(seed, 1) & 0x3)
}

fn loader_symbol_reloc(seed: &[u8]) -> RelocationType {
    if seed_byte(seed, 7) & 1 == 0 {
        RelocationType::JumpSlot
    } else {
        RelocationType::GlobDat
    }
}

fn data_symbol_reloc(seed: &[u8]) -> RelocationType {
    if seed_byte(seed, 8) & 1 == 0 {
        RelocationType::Pc32
    } else {
        RelocationType::R64
    }
}

fn derived_base(seed: &[u8]) -> u64 {
    0x0040_0000 + (u64::from(seed_byte(seed, 13)) << 12)
}

fn derived_got(seed: &[u8]) -> u64 {
    derived_base(seed) + 0x3000 + (u64::from(seed_byte(seed, 14)) << 4)
}

fn derived_symbol_value(seed: &[u8]) -> u64 {
    derived_base(seed) + 0x100 + u64::from(seed_byte(seed, 15))
}

fn resolved_symbol_value<S: SymbolLookup>(
    obj: &elf::LoadedObject,
    reloc: &elf::Elf64Rela,
    resolver: &S,
    base: u64,
) -> u64 {
    let sym_idx = reloc.symbol_index();
    if sym_idx == 0 {
        return 0;
    }
    let symbol = match obj.dynsym.get(sym_idx as usize) {
        Some(symbol) => symbol,
        None => return 0,
    };
    if symbol.is_defined() {
        return base + symbol.st_value;
    }
    let name = match obj.symbol_name(symbol) {
        Some(name) => name,
        None => return 0,
    };
    match resolver.lookup(name) {
        Some(address) => address,
        None if symbol.is_weak() => 0,
        None => 0,
    }
}

fn read_written_value(memory: &[u8], offset: usize, size: usize) -> u64 {
    match size {
        4 => u32::from_le_bytes([
            memory[offset],
            memory[offset + 1],
            memory[offset + 2],
            memory[offset + 3],
        ]) as u64,
        8 => u64::from_le_bytes([
            memory[offset],
            memory[offset + 1],
            memory[offset + 2],
            memory[offset + 3],
            memory[offset + 4],
            memory[offset + 5],
            memory[offset + 6],
            memory[offset + 7],
        ]),
        _ => 0,
    }
}

fn bounded_offset(data: &[u8], seed_idx: usize) -> usize {
    let len = data.len();
    let lo = seed_byte(data, seed_idx);
    let hi = seed_byte(data, seed_idx + 1);
    usize::from(u16::from_le_bytes([lo, hi])) % len
}

fn bounded_count(data: &[u8], seed_idx: usize) -> usize {
    1 + usize::from(seed_byte(data, seed_idx) % MAX_TABLE_COUNT as u8)
}

fn seed_byte(data: &[u8], index: usize) -> u8 {
    match data.get(index) {
        Some(byte) => *byte,
        None => 0,
    }
}

fn write_program_header(out: &mut [u8], spec: ProgramHeaderSpec) {
    out[0..4].copy_from_slice(&spec.p_type.to_le_bytes());
    out[4..8].copy_from_slice(&spec.p_flags.to_le_bytes());
    out[8..16].copy_from_slice(&spec.p_offset.to_le_bytes());
    out[16..24].copy_from_slice(&spec.p_vaddr.to_le_bytes());
    out[24..32].copy_from_slice(&spec.p_vaddr.to_le_bytes());
    out[32..40].copy_from_slice(&spec.p_filesz.to_le_bytes());
    out[40..48].copy_from_slice(&spec.p_memsz.to_le_bytes());
    out[48..56].copy_from_slice(&spec.p_align.to_le_bytes());
}

fn write_section_header(out: &mut [u8], spec: SectionHeaderSpec) {
    out[0..4].copy_from_slice(&spec.sh_name.to_le_bytes());
    out[4..8].copy_from_slice(&spec.sh_type.to_le_bytes());
    out[8..16].copy_from_slice(&spec.sh_flags.to_le_bytes());
    out[16..24].copy_from_slice(&spec.sh_addr.to_le_bytes());
    out[24..32].copy_from_slice(&spec.sh_offset.to_le_bytes());
    out[32..40].copy_from_slice(&spec.sh_size.to_le_bytes());
    out[40..44].copy_from_slice(&spec.sh_link.to_le_bytes());
    out[44..48].copy_from_slice(&spec.sh_info.to_le_bytes());
    out[48..56].copy_from_slice(&spec.sh_addralign.to_le_bytes());
    out[56..64].copy_from_slice(&spec.sh_entsize.to_le_bytes());
}

fn write_symbol(
    out: &mut [u8],
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
) {
    out[0..4].copy_from_slice(&st_name.to_le_bytes());
    out[4] = st_info;
    out[5] = st_other;
    out[6..8].copy_from_slice(&st_shndx.to_le_bytes());
    out[8..16].copy_from_slice(&st_value.to_le_bytes());
    out[16..24].copy_from_slice(&st_size.to_le_bytes());
}

fn write_relocation(
    out: &mut [u8],
    r_offset: u64,
    symbol_index: u32,
    reloc_type: u32,
    addend: i64,
) {
    let r_info = (u64::from(symbol_index) << 32) | u64::from(reloc_type);
    out[0..8].copy_from_slice(&r_offset.to_le_bytes());
    out[8..16].copy_from_slice(&r_info.to_le_bytes());
    out[16..24].copy_from_slice(&addend.to_le_bytes());
}

struct DeterministicResolver;

impl SymbolLookup for DeterministicResolver {
    fn lookup(&self, name: &str) -> Option<u64> {
        Some(0x7000_0000 + u64::from(gnu_hash(name.as_bytes()) & 0xffff))
    }
}
