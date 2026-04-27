//! BSD `nlist(3)` — read symbol table entries from an ELF binary.
//!
//! `nlist(filename, nl)` opens `filename`, parses its ELF symbol
//! table, and for each entry in the caller-supplied `nl` array
//! looks up the named symbol and fills in `n_type`, `n_other`,
//! `n_desc`, and `n_value`. The array is terminated by an entry
//! whose `n_name` is NULL or whose first character is `\0`.
//!
//! Returns -1 on file-open or parse error, otherwise the number of
//! requested symbols that were not found. Unfound entries have
//! their output fields zeroed.
//!
//! Only ELF64 little-endian (the dominant Linux variant) is
//! parsed. ELF32, big-endian, and non-ELF files cause -1 to be
//! returned, matching libbsd's behavior on unsupported formats.

use std::ffi::{OsStr, c_char, c_int, c_ulong};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::malloc_abi::known_remaining;
use crate::util::scan_c_string;

/// C-compatible `struct nlist` matching libbsd's `<nlist.h>` on
/// x86_64 Linux. The first field models the
/// `union { char *n_name; long n_strx; }` as a raw pointer (8
/// bytes); we only ever read `n_name` from caller memory.
///
/// Total size is 24 bytes (8 + 1 + 1 + 2 + 4 padding + 8).
#[repr(C)]
pub struct CNlist {
    pub n_name: *const c_char,
    pub n_type: u8,
    pub n_other: c_char,
    pub n_desc: i16,
    pub n_value: c_ulong,
}

const ELFMAG: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const SHT_SYMTAB: u32 = 2;
const EHDR64_SIZE: usize = 64;
const SHDR64_SIZE: usize = 64;
const SYM64_SIZE: usize = 24;

unsafe fn read_bounded_cstr(ptr: *const c_char) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: ptr is a caller-supplied C string pointer; known_remaining
    // bounds tracked malloc-backed storage so scans cannot cross allocation.
    let (len, terminated) = unsafe { scan_c_string(ptr, known_remaining(ptr as usize)) };
    if !terminated {
        return None;
    }
    // SAFETY: scan_c_string observed a terminator after len readable bytes.
    let bytes = unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    Some(bytes.to_vec())
}

struct Ehdr64 {
    shoff: u64,
    shentsize: u16,
    shnum: u16,
}

fn parse_ehdr64(buf: &[u8; EHDR64_SIZE]) -> Option<Ehdr64> {
    if buf[0..4] != ELFMAG {
        return None;
    }
    if buf[4] != ELFCLASS64 || buf[5] != ELFDATA2LSB {
        return None;
    }
    let shoff = u64::from_le_bytes(buf[40..48].try_into().ok()?);
    let shentsize = u16::from_le_bytes(buf[58..60].try_into().ok()?);
    let shnum = u16::from_le_bytes(buf[60..62].try_into().ok()?);
    Some(Ehdr64 {
        shoff,
        shentsize,
        shnum,
    })
}

struct Shdr64 {
    sh_type: u32,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_entsize: u64,
}

fn parse_shdr64(buf: &[u8]) -> Option<Shdr64> {
    if buf.len() < SHDR64_SIZE {
        return None;
    }
    let sh_type = u32::from_le_bytes(buf[4..8].try_into().ok()?);
    let sh_offset = u64::from_le_bytes(buf[24..32].try_into().ok()?);
    let sh_size = u64::from_le_bytes(buf[32..40].try_into().ok()?);
    let sh_link = u32::from_le_bytes(buf[40..44].try_into().ok()?);
    let sh_entsize = u64::from_le_bytes(buf[56..64].try_into().ok()?);
    Some(Shdr64 {
        sh_type,
        sh_offset,
        sh_size,
        sh_link,
        sh_entsize,
    })
}

struct Sym64 {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
}

fn parse_sym64(buf: &[u8]) -> Option<Sym64> {
    if buf.len() < SYM64_SIZE {
        return None;
    }
    let st_name = u32::from_le_bytes(buf[0..4].try_into().ok()?);
    let st_info = buf[4];
    let st_other = buf[5];
    let st_shndx = u16::from_le_bytes(buf[6..8].try_into().ok()?);
    let st_value = u64::from_le_bytes(buf[8..16].try_into().ok()?);
    Some(Sym64 {
        st_name,
        st_info,
        st_other,
        st_shndx,
        st_value,
    })
}

fn read_at(file: &mut File, offset: u64, len: usize) -> Option<Vec<u8>> {
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut out = vec![0u8; len];
    file.read_exact(&mut out).ok()?;
    Some(out)
}

fn lookup_strtab_name(strtab: &[u8], offset: u32) -> Option<&[u8]> {
    let start = offset as usize;
    if start >= strtab.len() {
        return None;
    }
    let end = strtab[start..].iter().position(|&b| b == 0)?;
    Some(&strtab[start..start + end])
}

struct ParsedSymtab {
    symtab: Vec<u8>,
    strtab: Vec<u8>,
    sym_stride: usize,
}

fn load_symtab(path: &Path) -> Option<ParsedSymtab> {
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
        let off = i * entsize;
        let shdr = parse_shdr64(&sht_buf[off..off + SHDR64_SIZE])?;
        if shdr.sh_type == SHT_SYMTAB {
            symtab_idx = Some(i);
            break;
        }
    }
    let symtab_idx = symtab_idx?;
    let symtab_off = symtab_idx * entsize;
    let symtab_hdr = parse_shdr64(&sht_buf[symtab_off..symtab_off + SHDR64_SIZE])?;
    if symtab_hdr.sh_entsize == 0 || (symtab_hdr.sh_entsize as usize) < SYM64_SIZE {
        return None;
    }
    let strtab_idx = symtab_hdr.sh_link as usize;
    if strtab_idx >= ehdr.shnum as usize {
        return None;
    }
    let strtab_off = strtab_idx * entsize;
    let strtab_hdr = parse_shdr64(&sht_buf[strtab_off..strtab_off + SHDR64_SIZE])?;
    if symtab_hdr.sh_size == 0 || strtab_hdr.sh_size == 0 {
        return None;
    }
    let symtab = read_at(&mut file, symtab_hdr.sh_offset, symtab_hdr.sh_size as usize)?;
    let strtab = read_at(&mut file, strtab_hdr.sh_offset, strtab_hdr.sh_size as usize)?;
    Some(ParsedSymtab {
        symtab,
        strtab,
        sym_stride: symtab_hdr.sh_entsize as usize,
    })
}

fn lookup_in_symtab(parsed: &ParsedSymtab, name: &[u8]) -> Option<Sym64> {
    let mut off = 0usize;
    while off + SYM64_SIZE <= parsed.symtab.len() {
        let sym = parse_sym64(&parsed.symtab[off..off + SYM64_SIZE])?;
        if sym.st_name != 0
            && let Some(found) = lookup_strtab_name(&parsed.strtab, sym.st_name)
            && found == name
        {
            return Some(sym);
        }
        off += parsed.sym_stride;
    }
    None
}

/// libbsd `nlist(filename, nl)` — see module-level docs.
///
/// # Safety
///
/// `filename` must be a NUL-terminated C string. `nl` must point
/// to a writable array of `struct nlist` whose entries each have
/// their `n_name` field set to a valid (NUL-terminated) string
/// pointer or NULL/empty as the array terminator.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nlist(filename: *const c_char, nl: *mut CNlist) -> c_int {
    if nl.is_null() {
        return -1;
    }
    let Some(path_bytes) = (unsafe { read_bounded_cstr(filename) }) else {
        return -1;
    };
    let path = Path::new(OsStr::from_bytes(&path_bytes));

    let parsed = match load_symtab(path) {
        Some(p) => p,
        None => return -1,
    };

    let mut idx: isize = 0;
    let mut unfound: c_int = 0;
    loop {
        // SAFETY: caller-supplied array; we stop at the first NULL or
        // empty n_name and bound the walk to defend against missing
        // terminators.
        let entry_ptr = unsafe { nl.offset(idx) };
        let n_name = unsafe { (*entry_ptr).n_name };
        if n_name.is_null() {
            break;
        }
        let Some(name_bytes) = (unsafe { read_bounded_cstr(n_name) }) else {
            return -1;
        };
        if name_bytes.is_empty() {
            break;
        }

        if let Some(sym) = lookup_in_symtab(&parsed, &name_bytes) {
            // SAFETY: writable caller-supplied entry.
            unsafe {
                (*entry_ptr).n_type = sym.st_info;
                (*entry_ptr).n_other = sym.st_other as c_char;
                (*entry_ptr).n_desc = sym.st_shndx as i16;
                (*entry_ptr).n_value = sym.st_value as c_ulong;
            }
        } else {
            // SAFETY: writable caller-supplied entry.
            unsafe {
                (*entry_ptr).n_type = 0;
                (*entry_ptr).n_other = 0;
                (*entry_ptr).n_desc = 0;
                (*entry_ptr).n_value = 0;
            }
            unfound += 1;
        }

        idx += 1;
        if idx > 65_536 {
            return -1;
        }
    }

    unfound
}
