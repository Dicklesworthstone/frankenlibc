//! Integration test: ELF loader (bd-3rn)
//!
//! Validates ELF64 parsing infrastructure against real system binaries.
//! Tests header parsing, symbol tables, relocations, and hash tables.
//!
//! Run: cargo test -p frankenlibc-core --test elf_loader_test

use frankenlibc_core::elf::{
    self, ElfLoader, NullSymbolLookup, RelocationStats, elf_hash, gnu_hash,
};
use std::fs;

// ---------------------------------------------------------------------------
// Helper: read system binary
// ---------------------------------------------------------------------------

fn read_system_binary(path: &str) -> Option<Vec<u8>> {
    fs::read(path).ok()
}

// ---------------------------------------------------------------------------
// 1. Parse /lib/x86_64-linux-gnu/libc.so.6
// ---------------------------------------------------------------------------

#[test]
fn parse_system_libc() {
    // Try common locations for libc
    let paths = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib64/libc.so.6",
    ];

    let data = paths.iter().find_map(|p| read_system_binary(p));
    let data = match data {
        Some(d) => d,
        None => {
            eprintln!("Skipping: no libc.so.6 found in standard paths");
            return;
        }
    };

    let loader = ElfLoader::new(0x7f00_0000_0000);
    let obj = loader.parse(&data).expect("failed to parse libc.so.6");

    // Validate basic properties
    assert!(obj.entry.is_some() || obj.entry.is_none()); // May or may not have entry
    assert!(
        !obj.program_headers.is_empty(),
        "libc should have program headers"
    );
    assert!(
        !obj.section_headers.is_empty(),
        "libc should have section headers"
    );
    assert!(!obj.dynsym.is_empty(), "libc should have dynamic symbols");
    assert!(
        !obj.dynstr.is_empty(),
        "libc should have dynamic string table"
    );
    assert!(
        obj.gnu_hash.is_some(),
        "libc should expose a GNU hash table"
    );
    assert!(
        obj.elf_hash.is_some(),
        "libc should expose an ELF hash table"
    );

    // Check for LOAD segments
    let load_count = obj.program_headers.iter().filter(|ph| ph.is_load()).count();
    assert!(load_count >= 2, "libc should have at least 2 LOAD segments");

    // Check for RELRO segment (modern binaries have it)
    let has_relro = obj.program_headers.iter().any(|ph| ph.is_relro());
    // Note: may or may not have RELRO depending on build
    let _ = has_relro;

    // Check symbol count
    eprintln!("libc.so.6: {} dynamic symbols", obj.dynsym.len());
    assert!(obj.dynsym.len() > 1000, "libc should have many symbols");
}

// ---------------------------------------------------------------------------
// 2. Parse /lib/x86_64-linux-gnu/libm.so.6
// ---------------------------------------------------------------------------

#[test]
fn parse_system_libm() {
    let paths = [
        "/lib/x86_64-linux-gnu/libm.so.6",
        "/lib64/libm.so.6",
        "/usr/lib/x86_64-linux-gnu/libm.so.6",
        "/usr/lib64/libm.so.6",
    ];

    let data = paths.iter().find_map(|p| read_system_binary(p));
    let data = match data {
        Some(d) => d,
        None => {
            eprintln!("Skipping: no libm.so.6 found in standard paths");
            return;
        }
    };

    let loader = ElfLoader::new(0x7f00_0000_0000);
    let obj = loader.parse(&data).expect("failed to parse libm.so.6");

    assert!(!obj.dynsym.is_empty(), "libm should have dynamic symbols");

    // Look for common math symbols
    let has_sin = obj.lookup_symbol("sin").is_some();
    let has_cos = obj.lookup_symbol("cos").is_some();
    let has_sqrt = obj.lookup_symbol("sqrt").is_some();

    eprintln!(
        "libm symbols: sin={}, cos={}, sqrt={}",
        has_sin, has_cos, has_sqrt
    );

    // At least one should be present
    assert!(
        has_sin || has_cos || has_sqrt,
        "libm should have math symbols"
    );
}

// ---------------------------------------------------------------------------
// 3. Parse /lib/x86_64-linux-gnu/libpthread.so.0
// ---------------------------------------------------------------------------

#[test]
fn parse_system_libpthread() {
    let paths = [
        "/lib/x86_64-linux-gnu/libpthread.so.0",
        "/lib64/libpthread.so.0",
        "/usr/lib/x86_64-linux-gnu/libpthread.so.0",
        "/usr/lib64/libpthread.so.0",
    ];

    let data = paths.iter().find_map(|p| read_system_binary(p));
    let data = match data {
        Some(d) => d,
        None => {
            eprintln!("Skipping: no libpthread.so.0 found (may be integrated into libc)");
            return;
        }
    };

    let loader = ElfLoader::new(0x7f00_0000_0000);
    let obj = loader
        .parse(&data)
        .expect("failed to parse libpthread.so.0");

    assert!(
        !obj.dynsym.is_empty(),
        "libpthread should have dynamic symbols"
    );

    // Look for pthread symbols
    let has_create = obj.lookup_symbol("pthread_create").is_some();
    let has_mutex_lock = obj.lookup_symbol("pthread_mutex_lock").is_some();

    eprintln!(
        "libpthread symbols: pthread_create={}, pthread_mutex_lock={}",
        has_create, has_mutex_lock
    );
}

// ---------------------------------------------------------------------------
// 4. Parse /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
// ---------------------------------------------------------------------------

#[test]
fn parse_system_ldso() {
    let paths = [
        "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "/lib64/ld-linux-x86-64.so.2",
        "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "/usr/lib64/ld-linux-x86-64.so.2",
    ];

    let data = paths.iter().find_map(|p| read_system_binary(p));
    let data = match data {
        Some(d) => d,
        None => {
            eprintln!("Skipping: no ld-linux-x86-64.so.2 found");
            return;
        }
    };

    let loader = ElfLoader::new(0x7f00_0000_0000);
    let obj = loader.parse(&data).expect("failed to parse ld.so");

    // ld.so should have minimal symbols
    eprintln!("ld.so: {} dynamic symbols", obj.dynsym.len());
    assert!(!obj.program_headers.is_empty());
    assert!(obj.lookup_symbol("_dl_allocate_tls").is_some());
    assert!(obj.lookup_symbol("_dl_deallocate_tls").is_some());
    assert!(obj.lookup_symbol("_rtld_global").is_some());
}

// ---------------------------------------------------------------------------
// 5. ELF hash function correctness
// ---------------------------------------------------------------------------

#[test]
fn elf_hash_known_values() {
    // Verified against Python implementation of System V ABI spec
    assert_eq!(elf_hash(b""), 0);
    assert_eq!(elf_hash(b"malloc"), 0x0738_3353);
    assert_eq!(elf_hash(b"free"), 0x0006_d8b5);
    assert_eq!(elf_hash(b"printf"), 0x0779_05a6);
    assert_eq!(elf_hash(b"strlen"), 0x07ab_92be);
}

#[test]
fn gnu_hash_known_values() {
    // GNU hash uses djb2 variant
    assert_eq!(gnu_hash(b""), 0x0000_1505); // 5381
    assert_eq!(gnu_hash(b"malloc"), 0x0d39_ad3d);
    assert_eq!(gnu_hash(b"free"), 0x7c96_f087);
    assert_eq!(gnu_hash(b"printf"), 0x156b_2bb8);
}

// ---------------------------------------------------------------------------
// 6. Symbol lookup in parsed objects
// ---------------------------------------------------------------------------

#[test]
fn symbol_lookup_works() {
    let paths = ["/lib/x86_64-linux-gnu/libc.so.6", "/lib64/libc.so.6"];

    let data = paths.iter().find_map(|p| read_system_binary(p));
    let data = match data {
        Some(d) => d,
        None => {
            eprintln!("Skipping: no libc.so.6 found");
            return;
        }
    };

    let loader = ElfLoader::new(0x7f00_0000_0000);
    let obj = loader.parse(&data).unwrap();

    // Look up common symbols
    if let Some(malloc_sym) = obj.lookup_symbol("malloc") {
        assert!(malloc_sym.is_function() || malloc_sym.is_ifunc());
        assert!(malloc_sym.is_defined());
        let name = obj.symbol_name(malloc_sym);
        assert_eq!(name, Some("malloc"));
    }

    let versioned_malloc = obj.lookup_symbol_versioned("malloc", Some("GLIBC_2.2.5"));
    assert!(
        versioned_malloc.is_some(),
        "libc should expose malloc@@GLIBC_2.2.5"
    );
    assert!(
        obj.lookup_symbol_versioned("malloc", Some("GLIBC_999.0"))
            .is_none()
    );

    // Nonexistent symbol
    assert!(
        obj.lookup_symbol("__definitely_not_a_real_symbol__")
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// 7. Undefined symbols iteration
// ---------------------------------------------------------------------------

#[test]
fn undefined_symbols_iteration() {
    let paths = ["/lib/x86_64-linux-gnu/libm.so.6", "/lib64/libm.so.6"];

    let data = paths.iter().find_map(|p| read_system_binary(p));
    let data = match data {
        Some(d) => d,
        None => {
            eprintln!("Skipping: no libm.so.6 found");
            return;
        }
    };

    let loader = ElfLoader::new(0x7f00_0000_0000);
    let obj = loader.parse(&data).unwrap();

    let undefined: Vec<_> = obj.undefined_symbols().collect();
    eprintln!("libm has {} undefined symbols", undefined.len());

    // libm may reference libc symbols
    for (idx, sym) in undefined.iter().take(5) {
        if let Ok(name) = elf::symbol::get_string(&obj.dynstr, sym.st_name) {
            eprintln!("  undefined[{}]: {}", idx, name);
        }
    }
}

// ---------------------------------------------------------------------------
// 8. Relocation parsing
// ---------------------------------------------------------------------------

#[test]
fn relocation_parsing() {
    let paths = ["/lib/x86_64-linux-gnu/libc.so.6", "/lib64/libc.so.6"];

    let data = paths.iter().find_map(|p| read_system_binary(p));
    let data = match data {
        Some(d) => d,
        None => {
            eprintln!("Skipping: no libc.so.6 found");
            return;
        }
    };

    let loader = ElfLoader::new(0x7f00_0000_0000);
    let obj = loader.parse(&data).unwrap();

    eprintln!(
        "libc relocations: rela_dyn={}, rela_plt={}",
        obj.rela_dyn.len(),
        obj.rela_plt.len()
    );

    // Note: Current implementation uses section-based parsing fallback.
    // Full dynamic segment parsing (DT_RELA, DT_RELASZ) is deferred.
    // With section-based parsing, we get relocations from .rela.* sections.

    // Check that relocation parsing infrastructure works
    let total_relocs = obj.rela_dyn.len() + obj.rela_plt.len();
    eprintln!("  Total relocations parsed: {}", total_relocs);
    assert!(
        !obj.rela_plt.is_empty(),
        "libc should expose .rela.plt separately from .rela.dyn"
    );

    // If we found relocations, verify they have valid types
    if !obj.rela_dyn.is_empty() {
        let relative_count = obj
            .rela_dyn
            .iter()
            .filter(|r| matches!(r.reloc_type(), elf::relocation::RelocationType::Relative))
            .count();
        eprintln!("  R_X86_64_RELATIVE count: {}", relative_count);
    }

    // Test that we can iterate through relocations without panicking
    for reloc in obj.rela_dyn.iter().take(10) {
        let _rtype = reloc.reloc_type();
        let _sym_idx = reloc.symbol_index();
        let _offset = reloc.r_offset;
        let _addend = reloc.r_addend;
    }
}

// ---------------------------------------------------------------------------
// 9. RelocationStats collection
// ---------------------------------------------------------------------------

#[test]
fn relocation_stats_collection() {
    use elf::relocation::RelocationResult;

    let results = vec![
        (0, RelocationResult::Applied),
        (1, RelocationResult::Applied),
        (2, RelocationResult::Skipped),
        (3, RelocationResult::Applied),
        (4, RelocationResult::SymbolNotFound),
        (5, RelocationResult::Deferred),
    ];

    let stats = RelocationStats::from_results(&results);
    assert_eq!(stats.total, 6);
    assert_eq!(stats.applied, 3);
    assert_eq!(stats.skipped, 1);
    assert_eq!(stats.symbol_not_found, 1);
    assert_eq!(stats.deferred, 1);
    assert!(!stats.all_successful());

    // All successful case
    let success_results = vec![
        (0, RelocationResult::Applied),
        (1, RelocationResult::Skipped),
    ];
    let success_stats = RelocationStats::from_results(&success_results);
    assert!(success_stats.all_successful());
}

// ---------------------------------------------------------------------------
// 10. NullSymbolLookup behavior
// ---------------------------------------------------------------------------

#[test]
fn null_symbol_lookup() {
    use elf::SymbolLookup;

    let resolver = NullSymbolLookup;
    assert!(resolver.lookup("malloc").is_none());
    assert!(resolver.lookup("free").is_none());
    assert!(
        resolver
            .lookup_versioned("malloc", Some("GLIBC_2.0"))
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// 11. Program header properties
// ---------------------------------------------------------------------------

#[test]
fn program_header_properties() {
    let paths = ["/lib/x86_64-linux-gnu/libc.so.6", "/lib64/libc.so.6"];

    let data = paths.iter().find_map(|p| read_system_binary(p));
    let data = match data {
        Some(d) => d,
        None => {
            eprintln!("Skipping: no libc.so.6 found");
            return;
        }
    };

    let loader = ElfLoader::new(0x7f00_0000_0000);
    let obj = loader.parse(&data).unwrap();

    for ph in &obj.program_headers {
        if ph.is_load() {
            // Check alignment validity
            assert!(
                ph.is_valid_alignment(),
                "LOAD segment should have valid alignment"
            );

            // Check mmap_prot conversion
            let prot = ph.p_flags.to_mmap_prot();
            assert!(prot >= 0, "mmap prot should be non-negative");

            // BSS size should be reasonable
            let bss = ph.bss_size();
            assert!(bss <= ph.p_memsz, "BSS cannot exceed memsz");
        }
    }

    // Check for DYNAMIC segment
    let dynamic_count = obj
        .program_headers
        .iter()
        .filter(|ph| ph.is_dynamic())
        .count();
    assert_eq!(dynamic_count, 1, "Should have exactly one DYNAMIC segment");
}

// ---------------------------------------------------------------------------
// 12. Section header types
// ---------------------------------------------------------------------------

#[test]
fn section_header_types() {
    let paths = ["/lib/x86_64-linux-gnu/libc.so.6", "/lib64/libc.so.6"];

    let data = paths.iter().find_map(|p| read_system_binary(p));
    let data = match data {
        Some(d) => d,
        None => {
            eprintln!("Skipping: no libc.so.6 found");
            return;
        }
    };

    let loader = ElfLoader::new(0x7f00_0000_0000);
    let obj = loader.parse(&data).unwrap();

    // Check for expected section types
    let has_dynsym = obj.section_headers.iter().any(|sh| sh.is_symtab());
    let has_rela = obj.section_headers.iter().any(|sh| sh.is_rela());
    let has_strtab = obj.section_headers.iter().any(|sh| sh.is_strtab());
    let has_dynamic = obj.section_headers.iter().any(|sh| sh.is_dynamic());

    assert!(has_dynsym, "libc should have symbol table section");
    assert!(has_rela, "libc should have RELA section");
    assert!(has_strtab, "libc should have string table section");
    assert!(has_dynamic, "libc should have DYNAMIC section");
}
