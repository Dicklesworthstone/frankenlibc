#![cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]

use std::ffi::CStr;
use frankenlibc_core::elf::{Elf64Symbol, ElfLoader, LoadedObject};

#[path = "../src/dlfcn_object_info.rs"]
mod metadata;
#[path = "../../../tests/fixtures/elf_introspection/support.rs"]
mod support;

fn object() -> LoadedObject {
    let path = support::fixture();
    ElfLoader::new(0x1000_0000).parse(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn real_elf_function_data_protected_and_header_metadata() {
    let object = object();
    let info = metadata::ObjectInfo::new(b"/vendor/libinspect.so", &object).unwrap();
    for name in ["inspect_answer", "inspect_values", "inspect_protected"] {
        let symbol = object.lookup_symbol_versioned(name, None).unwrap();
        let address = symbol.definition_address(object.base).unwrap() as usize;
        let found = info.address_info(address).unwrap();
        assert_eq!(unsafe { CStr::from_ptr(found.dli_sname) }.to_bytes(), name.as_bytes());
        assert_eq!(found.dli_saddr as usize, address);
        assert_eq!(found.dli_fbase as usize, object.base as usize);
        assert_eq!(unsafe { CStr::from_ptr(found.dli_fname) }.to_bytes(), b"/vendor/libinspect.so");
        assert!(symbol.st_size > 1);
        assert_eq!(info.address_info(address + symbol.st_size as usize - 1).unwrap().dli_saddr as usize, address);
    }
    assert_eq!(info.phdrs.len(), object.program_headers.len());
    for (abi, parsed) in info.phdrs.iter().zip(&object.program_headers) {
        assert_eq!((abi.p_vaddr, abi.p_memsz, abi.p_filesz, abi.p_offset, abi.p_flags),
            (parsed.p_vaddr, parsed.p_memsz, parsed.p_filesz, parsed.p_offset, parsed.p_flags.0));
    }
    assert!(info.phdrs.iter().any(|p| p.p_type == 0x6474_e550), "real unwind header required");
}

#[test]
fn metadata_owns_non_utf8_path_and_names_after_parser_drop() {
    let mut object = object();
    let symbol = object.dynsym.iter_mut().find(|symbol| symbol.is_object() && symbol.is_global()).unwrap();
    let address = (object.base + symbol.st_value) as usize;
    symbol.st_name = object.dynstr.len() as u32;
    object.dynstr.extend_from_slice(b"symbol-\xff\0");
    let info = metadata::ObjectInfo::new(b"/vendor/\xfe.so", &object).unwrap();
    drop(object);
    let found = info.address_info(address).unwrap();
    assert_eq!(unsafe { CStr::from_ptr(found.dli_fname) }.to_bytes(), b"/vendor/\xfe.so");
    assert_eq!(unsafe { CStr::from_ptr(found.dli_sname) }.to_bytes(), b"symbol-\xff");
}

#[test]
fn ownership_excludes_gaps_and_half_open_load_end() {
    let mut object = object();
    let load = object.program_headers.iter().find(|header| header.is_load()).unwrap().clone();
    object.program_headers = vec![load.clone(), load];
    object.program_headers[0].p_vaddr = 0x1000;
    object.program_headers[0].p_memsz = 0x100;
    object.program_headers[1].p_vaddr = 0x3000;
    object.program_headers[1].p_memsz = 0x100;
    object.dynsym.clear();
    let info = metadata::ObjectInfo::new(b"/gap.so", &object).unwrap();
    let base = object.base as usize;
    for offset in [0, 0xfff, 0x1100, 0x2000, 0x3100] { assert!(info.address_info(base + offset).is_none()); }
    for offset in [0x1000, 0x10ff, 0x3000, 0x30ff] {
        let found = info.address_info(base + offset).unwrap();
        assert!(found.dli_sname.is_null() && found.dli_saddr.is_null());
    }
}

#[test]
fn zero_size_and_overlapping_symbols_have_bounded_matches() {
    let mut object = object();
    let symbol = *object.lookup_symbol_versioned("inspect_values", None).unwrap();
    let base = (object.base + symbol.st_value) as usize;
    object.dynsym = vec![Elf64Symbol { st_size: 0, ..symbol }];
    let info = metadata::ObjectInfo::new(b"/zero.so", &object).unwrap();
    assert!(!info.address_info(base).unwrap().dli_sname.is_null());
    assert!(info.address_info(base + 1).unwrap().dli_sname.is_null());
    object.dynsym = vec![symbol, Elf64Symbol { st_value: symbol.st_value + 4, st_size: 4, ..symbol }];
    let info = metadata::ObjectInfo::new(b"/overlap.so", &object).unwrap();
    assert_eq!(info.address_info(base + 5).unwrap().dli_saddr as usize, base + 4);
    assert_eq!(info.address_info(base + 8).unwrap().dli_saddr as usize, base);
}

#[test]
fn invisible_invalid_and_tls_symbols_cannot_claim_an_address() {
    let mut object = object();
    let symbol = *object.lookup_symbol_versioned("inspect_values", None).unwrap();
    let address = (object.base + symbol.st_value) as usize;
    for rejected in [
        Elf64Symbol { st_info: 1, ..symbol },
        Elf64Symbol { st_info: 0x16, ..symbol },
        Elf64Symbol { st_other: 1, ..symbol },
        Elf64Symbol { st_other: 2, ..symbol },
        Elf64Symbol { st_shndx: 0, ..symbol },
        Elf64Symbol { st_shndx: 0xfff1, ..symbol },
        Elf64Symbol { st_name: u32::MAX, ..symbol },
    ] {
        object.dynsym = vec![rejected];
        let info = metadata::ObjectInfo::new(b"/invalid.so", &object).unwrap();
        assert!(info.address_info(address).unwrap().dli_sname.is_null());
    }
    object.dynsym = vec![Elf64Symbol { st_name: object.dynstr.len() as u32, ..symbol }];
    object.dynstr.extend_from_slice(b"unterminated");
    let info = metadata::ObjectInfo::new(b"/invalid.so", &object).unwrap();
    assert!(info.address_info(address).unwrap().dli_sname.is_null());
    object.base = u64::MAX - 1;
    assert!(metadata::ObjectInfo::new(b"/overflow.so", &object).is_none());
}
