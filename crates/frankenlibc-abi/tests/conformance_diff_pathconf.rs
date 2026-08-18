#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Differential gate: fl `pathconf` must match glibc. _PC_2_SYMLINKS and the
//! record/allocation limits (_PC_REC_MIN_XFER_SIZE / _PC_REC_XFER_ALIGN /
//! _PC_ALLOC_SIZE_MIN, which glibc derives from statvfs f_bsize) used to fall
//! through to EINVAL (returning -1). _PC_FILESIZEBITS is now also covered: fl
//! maps it from the filesystem f_type magic (fs_filesizebits_for_type, mirroring
//! glibc __statfs_filesize_max), so it must match glibc on the test fs. bd-eqcn80.

use frankenlibc_abi::unistd_abi as fu;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_long};
unsafe extern "C" {
    fn pathconf(p: *const c_char, n: c_int) -> c_long;
}

#[test]
fn pathconf_matches_glibc() {
    let keys: &[(&str, c_int)] = &[
        ("_PC_LINK_MAX", libc::_PC_LINK_MAX),
        ("_PC_MAX_CANON", libc::_PC_MAX_CANON),
        ("_PC_MAX_INPUT", libc::_PC_MAX_INPUT),
        ("_PC_NAME_MAX", libc::_PC_NAME_MAX),
        ("_PC_PATH_MAX", libc::_PC_PATH_MAX),
        ("_PC_PIPE_BUF", libc::_PC_PIPE_BUF),
        ("_PC_CHOWN_RESTRICTED", libc::_PC_CHOWN_RESTRICTED),
        ("_PC_NO_TRUNC", libc::_PC_NO_TRUNC),
        ("_PC_VDISABLE", libc::_PC_VDISABLE),
        ("_PC_SYNC_IO", libc::_PC_SYNC_IO),
        ("_PC_REC_MIN_XFER_SIZE", libc::_PC_REC_MIN_XFER_SIZE),
        ("_PC_REC_XFER_ALIGN", libc::_PC_REC_XFER_ALIGN),
        ("_PC_ALLOC_SIZE_MIN", libc::_PC_ALLOC_SIZE_MIN),
        ("_PC_2_SYMLINKS", libc::_PC_2_SYMLINKS),
        ("_PC_FILESIZEBITS", libc::_PC_FILESIZEBITS),
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
    assert!(
        div.is_empty(),
        "pathconf divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}

#[test]
fn fpathconf_matches_glibc() {
    use std::os::raw::c_void;
    unsafe extern "C" {
        fn fpathconf(fd: c_int, n: c_int) -> c_long;
        fn open(p: *const c_char, fl: c_int) -> c_int;
        fn close(fd: c_int) -> c_int;
    }
    let _ = std::ptr::null::<c_void>();
    let p = CString::new("/tmp").unwrap();
    let fd = unsafe { open(p.as_ptr(), 0) };
    assert!(fd >= 0, "open(/tmp) failed");
    let keys: &[(&str, c_int)] = &[
        ("_PC_LINK_MAX", libc::_PC_LINK_MAX),
        ("_PC_NAME_MAX", libc::_PC_NAME_MAX),
        ("_PC_PATH_MAX", libc::_PC_PATH_MAX),
        ("_PC_PIPE_BUF", libc::_PC_PIPE_BUF),
        ("_PC_CHOWN_RESTRICTED", libc::_PC_CHOWN_RESTRICTED),
        ("_PC_NO_TRUNC", libc::_PC_NO_TRUNC),
        ("_PC_REC_MIN_XFER_SIZE", libc::_PC_REC_MIN_XFER_SIZE),
        ("_PC_REC_XFER_ALIGN", libc::_PC_REC_XFER_ALIGN),
        ("_PC_ALLOC_SIZE_MIN", libc::_PC_ALLOC_SIZE_MIN),
        ("_PC_2_SYMLINKS", libc::_PC_2_SYMLINKS),
        ("_PC_FILESIZEBITS", libc::_PC_FILESIZEBITS),
    ];
    let mut div = Vec::new();
    for &(n, k) in keys {
        let f = unsafe { fu::fpathconf(fd, k) };
        let g = unsafe { fpathconf(fd, k) };
        if f != g {
            div.push(format!("{n}: fl={f} glibc={g}"));
        }
    }
    unsafe { close(fd) };
    assert!(
        div.is_empty(),
        "fpathconf divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}

/// Seeded so "errno untouched" is distinguishable from "errno set to 0".
const SENTINEL_ERRNO: c_int = 4242;

/// Selectors glibc answers as INDETERMINATE: -1 with errno UNTOUCHED, as opposed
/// to an unknown selector, which is -1 with EINVAL.
///
/// `_PC_SYNC_IO` is in the value list above and has been since this gate was
/// written -- and that did not help, because both sides return -1 and the gate
/// compared only values. fl was reaching these through the EINVAL default, so it
/// told every caller "unknown selector" where glibc says "no limit defined".
/// Measured on live glibc 2.42 against ".", /tmp, /proc and /dev/shm: identical
/// on all four, so this is a per-selector fact, not a per-filesystem one.
///
/// _PC_REC_MIN_XFER_SIZE / _PC_REC_XFER_ALIGN / _PC_ALLOC_SIZE_MIN are
/// deliberately NOT here: glibc answers those from the filesystem block size.
/// The REC_* family splits, so each member is measured, not inferred.
const INDETERMINATE_PC: &[(&str, c_int)] = &[
    ("_PC_SYNC_IO", libc::_PC_SYNC_IO),
    ("_PC_ASYNC_IO", libc::_PC_ASYNC_IO),
    ("_PC_PRIO_IO", libc::_PC_PRIO_IO),
    ("_PC_SOCK_MAXBUF", libc::_PC_SOCK_MAXBUF),
    ("_PC_REC_INCR_XFER_SIZE", libc::_PC_REC_INCR_XFER_SIZE),
    ("_PC_REC_MAX_XFER_SIZE", libc::_PC_REC_MAX_XFER_SIZE),
    ("_PC_SYMLINK_MAX", libc::_PC_SYMLINK_MAX),
];

#[test]
fn indeterminate_pathconf_keys_preserve_errno() {
    // Several paths, because "indeterminate" must not turn out to be
    // "this filesystem happens to say -1".
    for dir in ["/tmp", ".", "/proc"] {
        let path = CString::new(dir).unwrap();
        for &(name, key) in INDETERMINATE_PC {
            let (g, g_errno) = unsafe {
                *libc::__errno_location() = SENTINEL_ERRNO;
                let r = pathconf(path.as_ptr(), key);
                (r, *libc::__errno_location())
            };
            // Host premise first: if glibc ever starts answering one of these,
            // this gate must fail loudly rather than keep asserting fl's -1.
            assert_eq!(g, -1, "host premise: glibc {name} on {dir} must be -1");
            assert_eq!(
                g_errno, SENTINEL_ERRNO,
                "host premise: glibc must leave errno untouched for {name} on {dir}"
            );

            let (f, f_errno) = unsafe {
                *libc::__errno_location() = SENTINEL_ERRNO;
                let r = fu::pathconf(path.as_ptr(), key);
                (r, *libc::__errno_location())
            };
            assert_eq!(f, g, "{name} on {dir}: fl={f} glibc={g}");
            assert_eq!(
                f_errno, SENTINEL_ERRNO,
                "fl must leave errno untouched for indeterminate {name} on {dir}: setting \
                 EINVAL reports an unknown selector, which is a different answer"
            );
        }
    }
}
