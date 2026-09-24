//! Immutable inspection metadata for a native ELF image.
//!
//! Own the pathname, dynamic strings and ABI-shaped program headers: pointers
//! returned to inspection callers must not refer to a temporary parser buffer.
//! This module never reads the queried address or executes an IFUNC resolver.

use std::ffi::{CString, c_void};
use std::fmt;

use frankenlibc_core::elf::{Elf64ProgramHeader, LoadedObject, ProgramType};

struct AddressSymbol {
    address: usize,
    size: usize,
    name: usize,
}

pub(super) struct ObjectInfo {
    pub(super) name: CString,
    pub(super) base: usize,
    pub(super) phdrs: Box<[libc::Elf64_Phdr]>,
    loads: Vec<(usize, usize)>,
    strings: Box<[u8]>,
    symbols: Vec<AddressSymbol>,
}

impl fmt::Debug for ObjectInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectInfo")
            .field("name", &self.name)
            .field("base", &self.base)
            .field("phnum", &self.phdrs.len())
            .field("symbols", &self.symbols.len())
            .finish()
    }
}

impl ObjectInfo {
    pub(super) fn new(name: &[u8], object: &LoadedObject) -> Option<Self> {
        let name = CString::new(name).ok()?;
        let base = usize::try_from(object.base).ok()?;
        if object.program_headers.len() > u16::MAX as usize {
            return None;
        }
        let mut loads = Vec::new();
        for header in object.program_headers.iter().filter(|header| header.is_load()) {
            let start = base.checked_add(usize::try_from(header.p_vaddr).ok()?)?;
            let end = start.checked_add(usize::try_from(header.p_memsz).ok()?)?;
            if start != end {
                loads.push((start, end));
            }
        }
        let strings = object.dynstr.clone().into_boxed_slice();
        let mut symbols = Vec::new();
        for symbol in &object.dynsym {
            // Include protected and GNU-unique exports, but not local, hidden,
            // internal, undefined, absolute, common or TLS-offset definitions.
            if !matches!(symbol.st_info >> 4, 1 | 2 | 10)
                || matches!(symbol.st_other & 3, 1 | 2)
                || symbol.st_shndx == 0 || symbol.st_shndx >= 0xff00
                || !matches!(symbol.st_info & 15, 0 | 1 | 2 | 10)
            {
                continue;
            }
            let Some(address) = usize::try_from(symbol.st_value).ok()
                .and_then(|offset| base.checked_add(offset)) else { continue; };
            let Ok(size) = usize::try_from(symbol.st_size) else { continue; };
            let Ok(name) = usize::try_from(symbol.st_name) else { continue; };
            let Some(tail) = strings.get(name..) else { continue; };
            if !tail.iter().position(|&byte| byte == 0).is_some_and(|len| len != 0) {
                continue;
            }
            if !loads.iter().any(|&(start, end)| start <= address && address < end) {
                continue;
            }
            symbols.push(AddressSymbol { address, size, name });
        }
        Some(Self {
            name, base, loads, strings, symbols,
            phdrs: object.program_headers.iter().map(abi_phdr).collect(),
        })
    }

    pub(super) fn address_info(&self, address: usize) -> Option<libc::Dl_info> {
        // The reserved image extent can contain unmapped gaps. Only PT_LOAD
        // intervals establish ownership; do not attribute an arbitrary hole.
        if !self.loads.iter().any(|&(start, end)| start <= address && address < end) {
            return None;
        }
        let symbol = self.symbols.iter().filter(|symbol| {
            address >= symbol.address
                && if symbol.size == 0 { address == symbol.address }
                   else { address - symbol.address < symbol.size }
        }).max_by_key(|symbol| symbol.address);
        Some(libc::Dl_info {
            dli_fname: self.name.as_ptr(),
            dli_fbase: self.base as *mut c_void,
            dli_sname: symbol.map_or(std::ptr::null(), |symbol| {
                // The name and its terminator were checked at construction.
                self.strings[symbol.name..].as_ptr().cast()
            }),
            dli_saddr: symbol.map_or(std::ptr::null_mut(), |symbol| symbol.address as *mut c_void),
        })
    }
}

fn abi_phdr(header: &Elf64ProgramHeader) -> libc::Elf64_Phdr {
    libc::Elf64_Phdr {
        p_type: match header.p_type {
            ProgramType::Null => 0,
            ProgramType::Load => 1,
            ProgramType::Dynamic => 2,
            ProgramType::Interp => 3,
            ProgramType::Note => 4,
            ProgramType::Shlib => 5,
            ProgramType::Phdr => 6,
            ProgramType::Tls => 7,
            ProgramType::GnuEhFrame => 0x6474_e550,
            ProgramType::GnuStack => 0x6474_e551,
            ProgramType::GnuRelro => 0x6474_e552,
            ProgramType::GnuProperty => 0x6474_e553,
            ProgramType::Unknown(raw) => raw,
        },
        p_flags: header.p_flags.0,
        p_offset: header.p_offset,
        p_vaddr: header.p_vaddr,
        p_paddr: header.p_paddr,
        p_filesz: header.p_filesz,
        p_memsz: header.p_memsz,
        p_align: header.p_align,
    }
}
