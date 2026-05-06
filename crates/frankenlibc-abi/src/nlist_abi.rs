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
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::malloc_abi::known_remaining;
use crate::util::scan_c_string;
use frankenlibc_core::elf::NlistSymtab;

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

    let parsed = match NlistSymtab::load(path) {
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

        if let Some(sym) = parsed.lookup(&name_bytes) {
            // SAFETY: writable caller-supplied entry.
            unsafe {
                (*entry_ptr).n_type = sym.n_type;
                (*entry_ptr).n_other = sym.n_other as c_char;
                (*entry_ptr).n_desc = sym.n_desc as i16;
                (*entry_ptr).n_value = sym.n_value as c_ulong;
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
