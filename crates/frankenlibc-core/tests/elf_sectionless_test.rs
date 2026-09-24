#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use frankenlibc_core::elf::{ElfLoader, LoadedObject, ProgramType};
use std::path::Path;

#[path = "../../../tests/fixtures/elf_sectionless/support.rs"]
mod fixtures;

fn symbol_rows(object: &LoadedObject) -> Vec<(u32, u8, u8, u16, u64, u64)> {
    object.dynsym.iter().map(|symbol| (
        symbol.st_name, symbol.st_info, symbol.st_other, symbol.st_shndx,
        symbol.st_value, symbol.st_size,
    )).collect()
}

fn relocation_rows(object: &LoadedObject, plt: bool) -> Vec<(u64, u64, i64)> {
    let table = if plt { &object.rela_plt } else { &object.rela_dyn };
    table.iter().map(|entry| (entry.r_offset, entry.r_info, entry.r_addend)).collect()
}

fn read(directory: &Path, object: &str, unstripped: bool) -> Vec<u8> {
    let suffix = if unstripped { ".unstripped" } else { "" };
    std::fs::read(directory.join(format!("libsectionless_{object}{suffix}.so"))).unwrap()
}

#[test]
fn compiled_sectionless_objects_preserve_runtime_metadata() {
    let loader = ElfLoader::new(0);
    for style in ["gnu", "sysv", "both"] {
        for packing in ["plain", "relr"] {
            let directory = fixtures::build(style, packing);
            for object_name in ["dep", "root"] {
                let original_bytes = read(&directory, object_name, true);
                let stripped_bytes = read(&directory, object_name, false);
                let original = loader.parse(&original_bytes).unwrap();
                let stripped = loader.parse(&stripped_bytes).unwrap();
                assert!(!original.section_headers.is_empty());
                assert!(stripped.section_headers.is_empty());
                assert!(!stripped.dynsym.is_empty(), "{style}/{packing}/{object_name}");
                assert_eq!(symbol_rows(&stripped), symbol_rows(&original));
                assert_eq!(stripped.dynstr, original.dynstr);
                assert_eq!(stripped.needed_libraries, original.needed_libraries);
                assert_eq!(stripped.soname, original.soname);
                assert_eq!(stripped.symbol_versions, original.symbol_versions);
                assert_eq!(relocation_rows(&stripped, false), relocation_rows(&original, false));
                assert_eq!(relocation_rows(&stripped, true), relocation_rows(&original, true));
                assert_eq!(stripped.relr_dyn, original.relr_dyn);
                assert_eq!(stripped.init_array, original.init_array);
                assert_eq!(stripped.fini_array, original.fini_array);
                assert_eq!(stripped.legacy_init, original.legacy_init);
                assert_eq!(stripped.legacy_fini, original.legacy_fini);
                assert_eq!(stripped.relro_start, original.relro_start);
                assert_eq!(stripped.relro_size, original.relro_size);
                assert_eq!(stripped.tls_segment, original.tls_segment);
                assert_eq!(stripped.gnu_hash.is_some(), style != "sysv");
                assert_eq!(stripped.elf_hash.is_some(), style != "gnu");
                let symbol = if object_name == "root" { "answer" } else { "dep_value" };
                assert!(stripped.lookup_symbol_versioned(symbol, Some("FIXTURE_1.0")).is_some());
                assert!(stripped.lookup_symbol_versioned(symbol, Some("MISSING_VERSION")).is_none());
                let original_image = loader.materialize_load_image(&original_bytes, &original).unwrap();
                let stripped_image = loader.materialize_load_image(&stripped_bytes, &stripped).unwrap();
                // The only changed loaded bytes are the ELF header's section-table fields.
                assert_eq!(stripped_image.memory[64..], original_image.memory[64..]);
                if object_name == "root" {
                    assert_eq!(stripped.needed_libraries, ["libsectionless_dep.so"]);
                    assert!(!stripped.rela_plt.is_empty());
                    assert!(stripped.tls_segment.is_some());
                    assert!(!stripped.init_array.is_empty());
                    assert!(!stripped.fini_array.is_empty());
                    assert_eq!(!stripped.relr_dyn.is_empty(), packing == "relr");
                }
            }
        }
    }
}

fn tag_value_offset(bytes: &[u8], tag: i64) -> usize {
    let object = ElfLoader::new(0).parse(bytes).unwrap();
    let dynamic = object.program_headers.iter().find(|header| header.p_type == ProgramType::Dynamic).unwrap();
    let start = dynamic.p_offset as usize;
    let end = start + dynamic.p_filesz as usize;
    for offset in (start..end).step_by(16) {
        let found = i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        if found == tag { return offset + 8; }
        if found == 0 { break; }
    }
    panic!("required fixture dynamic tag {tag:#x} is missing");
}

#[test]
fn sectionless_dynamic_metadata_rejects_corrupt_tables_without_panicking() {
    let directory = fixtures::build("both", "relr");
    let bytes = read(&directory, "root", false);
    let loader = ElfLoader::new(0);
    for (tag, value) in [(5, u64::MAX), (10, u64::MAX), (11, 8), (9, 8), (37, 16), (0x6fff_fffd, u64::MAX)] {
        let offset = tag_value_offset(&bytes, tag);
        let mut invalid = bytes.clone();
        invalid[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        assert!(loader.parse(&invalid).is_err(), "corrupt tag {tag:#x} accepted");
    }
    // GNU ld places JMPREL immediately after RELA in this fixture. Extend
    // RELASZ over JMPREL to exercise the valid subset layout; each PLT entry
    // must still appear exactly once in the PLT table, not in both tables.
    let value = |tag| {
        let offset = tag_value_offset(&bytes, tag);
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    };
    assert_eq!(value(23), value(7) + value(8));
    let mut overlapping = bytes.clone();
    let size_offset = tag_value_offset(&bytes, 8);
    overlapping[size_offset..size_offset + 8].copy_from_slice(&(value(8) + value(2)).to_le_bytes());
    let canonical = loader.parse(&bytes).unwrap();
    let parsed_overlap = loader.parse(&overlapping).unwrap();
    assert_eq!(relocation_rows(&parsed_overlap, false), relocation_rows(&canonical, false));
    assert_eq!(relocation_rows(&parsed_overlap, true), relocation_rows(&canonical, true));
    let object = loader.parse(&bytes).unwrap();
    let dynamic = object.program_headers.iter().find(|header| header.p_type == ProgramType::Dynamic).unwrap();
    let mut unterminated = bytes.clone();
    for offset in (dynamic.p_offset as usize..(dynamic.p_offset + dynamic.p_filesz) as usize).step_by(16) {
        if unterminated[offset..offset + 8] == [0; 8] {
            unterminated[offset..offset + 8].copy_from_slice(&21i64.to_le_bytes()); // DT_DEBUG, not DT_NULL
        }
    }
    assert!(loader.parse(&unterminated).is_err());
    for length in (0..bytes.len()).step_by(37) {
        assert!(std::panic::catch_unwind(|| loader.parse(&bytes[..length])).is_ok(), "panic at prefix {length}");
    }
}
