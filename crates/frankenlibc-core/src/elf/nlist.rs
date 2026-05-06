//! Safe ELF64 symbol-table loading for BSD `nlist(3)` style lookups.
//!
//! This module owns the file-format parsing and symbol lookup logic used by
//! the ABI layer. It intentionally returns a Rust value object instead of C
//! `struct nlist`; pointer validation and caller-memory writes stay in
//! `frankenlibc-abi`.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const ELFMAG: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const SHT_SYMTAB: u32 = 2;
const EHDR64_SIZE: usize = 64;
const SHDR64_SIZE: usize = 64;
const SYM64_SIZE: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NlistSymbol {
    pub n_type: u8,
    pub n_other: u8,
    pub n_desc: u16,
    pub n_value: u64,
}

#[derive(Debug, Clone)]
pub struct NlistSymtab {
    symtab: Vec<u8>,
    strtab: Vec<u8>,
    sym_stride: usize,
}

#[derive(Debug, Clone, Copy)]
struct Ehdr64 {
    shoff: u64,
    shentsize: u16,
    shnum: u16,
}

#[derive(Debug, Clone, Copy)]
struct Shdr64 {
    sh_type: u32,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_entsize: u64,
}

#[derive(Debug, Clone, Copy)]
struct Sym64 {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
}

impl NlistSymtab {
    pub fn load(path: &Path) -> Option<Self> {
        let mut file = File::open(path).ok()?;
        let ehdr_buf = read_at(&mut file, 0, EHDR64_SIZE)?;
        let ehdr_arr: [u8; EHDR64_SIZE] = ehdr_buf.as_slice().try_into().ok()?;
        let ehdr = parse_ehdr64(&ehdr_arr)?;
        if (ehdr.shentsize as usize) < SHDR64_SIZE || ehdr.shnum == 0 {
            return None;
        }

        let entsize = ehdr.shentsize as usize;
        let sht_size = (ehdr.shnum as usize).checked_mul(entsize)?;
        let sht_buf = read_at(&mut file, ehdr.shoff, sht_size)?;

        let mut symtab_idx: Option<usize> = None;
        for i in 0..ehdr.shnum as usize {
            let shdr = parse_shdr64(section_entry(&sht_buf, i, entsize)?)?;
            if shdr.sh_type == SHT_SYMTAB {
                symtab_idx = Some(i);
                break;
            }
        }

        let symtab_idx = symtab_idx?;
        let symtab_hdr = parse_shdr64(section_entry(&sht_buf, symtab_idx, entsize)?)?;
        if symtab_hdr.sh_entsize == 0 || (symtab_hdr.sh_entsize as usize) < SYM64_SIZE {
            return None;
        }

        let strtab_idx = symtab_hdr.sh_link as usize;
        if strtab_idx >= ehdr.shnum as usize {
            return None;
        }
        let strtab_hdr = parse_shdr64(section_entry(&sht_buf, strtab_idx, entsize)?)?;
        if symtab_hdr.sh_size == 0 || strtab_hdr.sh_size == 0 {
            return None;
        }

        Some(Self {
            symtab: read_at(
                &mut file,
                symtab_hdr.sh_offset,
                usize::try_from(symtab_hdr.sh_size).ok()?,
            )?,
            strtab: read_at(
                &mut file,
                strtab_hdr.sh_offset,
                usize::try_from(strtab_hdr.sh_size).ok()?,
            )?,
            sym_stride: symtab_hdr.sh_entsize as usize,
        })
    }

    pub fn lookup(&self, name: &[u8]) -> Option<NlistSymbol> {
        let mut off = 0usize;
        while let Some(end) = off.checked_add(SYM64_SIZE) {
            let Some(sym_buf) = self.symtab.get(off..end) else {
                break;
            };
            let sym = parse_sym64(sym_buf)?;
            if sym.st_name != 0
                && let Some(found) = lookup_strtab_name(&self.strtab, sym.st_name)
                && found == name
            {
                return Some(NlistSymbol {
                    n_type: sym.st_info,
                    n_other: sym.st_other,
                    n_desc: sym.st_shndx,
                    n_value: sym.st_value,
                });
            }
            off = off.checked_add(self.sym_stride)?;
        }
        None
    }
}

fn parse_ehdr64(buf: &[u8; EHDR64_SIZE]) -> Option<Ehdr64> {
    if buf.get(0..4)? != ELFMAG.as_slice() {
        return None;
    }
    if byte_at(buf, 4)? != ELFCLASS64 || byte_at(buf, 5)? != ELFDATA2LSB {
        return None;
    }
    Some(Ehdr64 {
        shoff: read_u64_le(buf, 40)?,
        shentsize: read_u16_le(buf, 58)?,
        shnum: read_u16_le(buf, 60)?,
    })
}

fn parse_shdr64(buf: &[u8]) -> Option<Shdr64> {
    if buf.len() < SHDR64_SIZE {
        return None;
    }
    Some(Shdr64 {
        sh_type: read_u32_le(buf, 4)?,
        sh_offset: read_u64_le(buf, 24)?,
        sh_size: read_u64_le(buf, 32)?,
        sh_link: read_u32_le(buf, 40)?,
        sh_entsize: read_u64_le(buf, 56)?,
    })
}

fn parse_sym64(buf: &[u8]) -> Option<Sym64> {
    if buf.len() < SYM64_SIZE {
        return None;
    }
    Some(Sym64 {
        st_name: read_u32_le(buf, 0)?,
        st_info: byte_at(buf, 4)?,
        st_other: byte_at(buf, 5)?,
        st_shndx: read_u16_le(buf, 6)?,
        st_value: read_u64_le(buf, 8)?,
    })
}

fn read_at(file: &mut File, offset: u64, len: usize) -> Option<Vec<u8>> {
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut out = vec![0u8; len];
    file.read_exact(&mut out).ok()?;
    Some(out)
}

fn section_entry(buf: &[u8], index: usize, entsize: usize) -> Option<&[u8]> {
    let off = index.checked_mul(entsize)?;
    buf.get(off..off.checked_add(SHDR64_SIZE)?)
}

fn lookup_strtab_name(strtab: &[u8], offset: u32) -> Option<&[u8]> {
    let start = offset as usize;
    let tail = strtab.get(start..)?;
    let end = tail.iter().position(|&b| b == 0)?;
    tail.get(..end)
}

fn byte_at(buf: &[u8], start: usize) -> Option<u8> {
    buf.get(start).copied()
}

fn read_u16_le(buf: &[u8], start: usize) -> Option<u16> {
    let end = start.checked_add(2)?;
    Some(u16::from_le_bytes(buf.get(start..end)?.try_into().ok()?))
}

fn read_u32_le(buf: &[u8], start: usize) -> Option<u32> {
    let end = start.checked_add(4)?;
    Some(u32::from_le_bytes(buf.get(start..end)?.try_into().ok()?))
}

fn read_u64_le(buf: &[u8], start: usize) -> Option<u64> {
    let end = start.checked_add(8)?;
    Some(u64::from_le_bytes(buf.get(start..end)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf_header() {
        let mut buf = [0u8; EHDR64_SIZE];
        buf[0..4].copy_from_slice(b"nope");
        assert!(parse_ehdr64(&buf).is_none());
    }

    #[test]
    fn parses_minimal_elf64_little_endian_section_table_fields() {
        let mut buf = [0u8; EHDR64_SIZE];
        buf[0..4].copy_from_slice(&ELFMAG);
        buf[4] = ELFCLASS64;
        buf[5] = ELFDATA2LSB;
        buf[40..48].copy_from_slice(&128u64.to_le_bytes());
        buf[58..60].copy_from_slice(&64u16.to_le_bytes());
        buf[60..62].copy_from_slice(&3u16.to_le_bytes());

        let parsed = parse_ehdr64(&buf).expect("valid header");
        assert_eq!(parsed.shoff, 128);
        assert_eq!(parsed.shentsize, 64);
        assert_eq!(parsed.shnum, 3);
    }

    #[test]
    fn lookup_strtab_name_rejects_out_of_range_and_unterminated_names() {
        assert_eq!(lookup_strtab_name(b"\0main\0", 1), Some(&b"main"[..]));
        assert!(lookup_strtab_name(b"\0main", 1).is_none());
        assert!(lookup_strtab_name(b"\0main\0", 99).is_none());
    }
}
