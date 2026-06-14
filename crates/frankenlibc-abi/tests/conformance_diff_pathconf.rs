#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Differential gate: fl `pathconf` must match glibc. _PC_2_SYMLINKS and the
//! record/allocation limits (_PC_REC_MIN_XFER_SIZE / _PC_REC_XFER_ALIGN /
//! _PC_ALLOC_SIZE_MIN, which glibc derives from statvfs f_bsize) used to fall
//! through to EINVAL (returning -1). _PC_FILESIZEBITS is intentionally excluded:
//! glibc maps it from the filesystem f_type magic and fl returns -1 (POSIX
//! "indeterminate"), a deliberate divergence.

use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_long};
use frankenlibc_abi::unistd_abi as fu;
unsafe extern "C" {
    fn pathconf(p: *const c_char, n: c_int) -> c_long;
}

#[test]
fn pathconf_matches_glibc() {
    let keys: &[(&str, c_int)] = &[
        ("_PC_LINK_MAX", libc::_PC_LINK_MAX), ("_PC_MAX_CANON", libc::_PC_MAX_CANON),
        ("_PC_MAX_INPUT", libc::_PC_MAX_INPUT), ("_PC_NAME_MAX", libc::_PC_NAME_MAX),
        ("_PC_PATH_MAX", libc::_PC_PATH_MAX), ("_PC_PIPE_BUF", libc::_PC_PIPE_BUF),
        ("_PC_CHOWN_RESTRICTED", libc::_PC_CHOWN_RESTRICTED), ("_PC_NO_TRUNC", libc::_PC_NO_TRUNC),
        ("_PC_VDISABLE", libc::_PC_VDISABLE), ("_PC_SYNC_IO", libc::_PC_SYNC_IO),
        ("_PC_REC_MIN_XFER_SIZE", libc::_PC_REC_MIN_XFER_SIZE),
        ("_PC_REC_XFER_ALIGN", libc::_PC_REC_XFER_ALIGN),
        ("_PC_ALLOC_SIZE_MIN", libc::_PC_ALLOC_SIZE_MIN),
        ("_PC_2_SYMLINKS", libc::_PC_2_SYMLINKS),
    ];
    let path = CString::new("/tmp").unwrap();
    let mut div = Vec::new();
    for &(n, k) in keys {
        let f = unsafe { fu::pathconf(path.as_ptr(), k) };
        let g = unsafe { pathconf(path.as_ptr(), k) };
        if f != g {
            div.push(format!("{n}: fl={f} glibc={g}"));
        }
    }
    assert!(div.is_empty(), "pathconf divergences vs glibc ({}):\n  {}", div.len(), div.join("\n  "));
}
