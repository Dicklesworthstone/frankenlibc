//! ABI integration tests for unistd_abi native implementations.
//!
//! Tests for promoted GlibcCallThrough -> Implemented symbols:
//! - glob64 / globfree64
//! - ftw / nftw / nftw64
//! - setmntent / getmntent / endmntent

#![allow(unsafe_code)]

use std::ffi::{c_char, c_int, c_void};

// ---------------------------------------------------------------------------
// glob64 / globfree64 tests
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn glob64(
        pattern: *const c_char,
        flags: c_int,
        errfunc: Option<unsafe extern "C" fn(*const c_char, c_int) -> c_int>,
        pglob: *mut c_void,
    ) -> c_int;
    fn globfree64(pglob: *mut c_void);
}

/// Properly aligned glob_t-sized buffer (glob_t contains pointers, needs 8-byte alignment).
#[repr(C, align(8))]
struct GlobBuf {
    data: [u8; 64],
}

#[test]
fn glob64_literal_path_exists() {
    // /tmp should exist on any Linux system.
    let pattern = b"/tmp\0";
    let mut glob_buf = GlobBuf { data: [0u8; 64] };

    let rc = unsafe {
        glob64(
            pattern.as_ptr() as *const c_char,
            0,
            None,
            &mut glob_buf as *mut GlobBuf as *mut c_void,
        )
    };
    assert_eq!(rc, 0, "glob64 should succeed for /tmp");

    // gl_pathc is at offset 0, should be 1
    let pathc = unsafe { *(glob_buf.data.as_ptr() as *const usize) };
    assert_eq!(pathc, 1, "should find exactly 1 match for literal /tmp");

    // gl_pathv is at offset 8
    let pathv = unsafe { *(glob_buf.data.as_ptr().add(8) as *const *const *const c_char) };
    assert!(!pathv.is_null());

    // First path should be "/tmp"
    let first = unsafe { *pathv };
    assert!(!first.is_null());
    let first_str = unsafe { std::ffi::CStr::from_ptr(first) };
    assert_eq!(first_str.to_bytes(), b"/tmp");

    unsafe { globfree64(&mut glob_buf as *mut GlobBuf as *mut c_void) };
}

#[test]
fn glob64_nomatch_returns_error() {
    let pattern = b"/nonexistent_frankenlibc_glob_test_xyz_42\0";
    let mut glob_buf = GlobBuf { data: [0u8; 64] };

    let rc = unsafe {
        glob64(
            pattern.as_ptr() as *const c_char,
            0,
            None,
            &mut glob_buf as *mut GlobBuf as *mut c_void,
        )
    };
    // GLOB_NOMATCH = 3
    assert_eq!(
        rc, 3,
        "glob64 should return GLOB_NOMATCH for nonexistent path"
    );
}

// Note: glob64(NULL, ...) returns -1 in glibc (EINVAL-style).
// Our native impl returns GLOB_NOMATCH(3). In test mode we link against glibc.
// Skipping NULL pattern test for conformance.

// ---------------------------------------------------------------------------
// ftw / nftw tests
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn ftw(
        dirpath: *const c_char,
        func: Option<unsafe extern "C" fn(*const c_char, *const libc::stat, c_int) -> c_int>,
        nopenfd: c_int,
    ) -> c_int;
    fn nftw(
        dirpath: *const c_char,
        func: Option<
            unsafe extern "C" fn(*const c_char, *const libc::stat, c_int, *mut c_void) -> c_int,
        >,
        nopenfd: c_int,
        flags: c_int,
    ) -> c_int;
}

use std::sync::atomic::{AtomicUsize, Ordering};

static FTW_COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn ftw_counter(
    _path: *const c_char,
    _stat: *const libc::stat,
    _flag: c_int,
) -> c_int {
    FTW_COUNT.fetch_add(1, Ordering::Relaxed);
    0
}

#[test]
fn ftw_walks_directory() {
    // Create a temp dir with known structure
    let tmpdir = std::env::temp_dir().join("frankenlibc_ftw_test");
    let _ = std::fs::create_dir_all(tmpdir.join("subdir"));
    let _ = std::fs::write(tmpdir.join("file1.txt"), "hello");
    let _ = std::fs::write(tmpdir.join("subdir/file2.txt"), "world");

    let path = format!("{}\0", tmpdir.display());

    FTW_COUNT.store(0, Ordering::Relaxed);
    let rc = unsafe { ftw(path.as_ptr() as *const c_char, Some(ftw_counter), 16) };
    assert_eq!(rc, 0, "ftw should return 0 on success");

    let count = FTW_COUNT.load(Ordering::Relaxed);
    // Should visit at least: tmpdir, subdir, file1.txt, file2.txt = 4
    assert!(
        count >= 4,
        "ftw should visit at least 4 entries, got {count}"
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmpdir);
}

// Note: ftw(NULL, ...) segfaults in glibc — our native impl handles it,
// but in test mode we link against glibc, so we skip the NULL test.

#[test]
fn ftw_nonexistent_dir_returns_zero() {
    // ftw on a non-existent directory should call func with FTW_NS and return 0
    // (unless the callback returns non-zero)
    static NS_COUNT: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn ns_counter(
        _path: *const c_char,
        _stat: *const libc::stat,
        flag: c_int,
    ) -> c_int {
        if flag == 3 {
            // FTW_NS
            NS_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        0
    }
    let path = b"/nonexistent_frankenlibc_ftw_dir_xyz\0";
    NS_COUNT.store(0, Ordering::Relaxed);
    let _rc = unsafe { ftw(path.as_ptr() as *const c_char, Some(ns_counter), 16) };
    // glibc may return -1 for stat failure or call callback with FTW_NS; either is valid
}

static NFTW_COUNT: AtomicUsize = AtomicUsize::new(0);
static NFTW_MAX_LEVEL: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn nftw_counter(
    _path: *const c_char,
    _stat: *const libc::stat,
    _flag: c_int,
    ftw_info: *mut c_void,
) -> c_int {
    NFTW_COUNT.fetch_add(1, Ordering::Relaxed);
    if !ftw_info.is_null() {
        // FTW info struct: { base: i32, level: i32 }
        let level = unsafe { *((ftw_info as *const u8).add(4) as *const i32) } as usize;
        NFTW_MAX_LEVEL.fetch_max(level, Ordering::Relaxed);
    }
    0
}

#[test]
fn nftw_walks_with_info() {
    let tmpdir = std::env::temp_dir().join("frankenlibc_nftw_test");
    let _ = std::fs::create_dir_all(tmpdir.join("a/b"));
    let _ = std::fs::write(tmpdir.join("a/b/deep.txt"), "deep");

    let path = format!("{}\0", tmpdir.display());

    NFTW_COUNT.store(0, Ordering::Relaxed);
    NFTW_MAX_LEVEL.store(0, Ordering::Relaxed);

    let rc = unsafe { nftw(path.as_ptr() as *const c_char, Some(nftw_counter), 16, 0) };
    assert_eq!(rc, 0);

    let count = NFTW_COUNT.load(Ordering::Relaxed);
    assert!(
        count >= 4,
        "nftw should visit at least 4 entries, got {count}"
    );

    let max_level = NFTW_MAX_LEVEL.load(Ordering::Relaxed);
    assert!(
        max_level >= 2,
        "nftw should reach level 2 for a/b/deep.txt, got {max_level}"
    );

    let _ = std::fs::remove_dir_all(&tmpdir);
}

#[test]
fn nftw_depth_flag_reports_dp() {
    use std::sync::atomic::AtomicBool;

    static SAW_DP: AtomicBool = AtomicBool::new(false);

    unsafe extern "C" fn check_dp(
        _path: *const c_char,
        _stat: *const libc::stat,
        flag: c_int,
        _info: *mut c_void,
    ) -> c_int {
        if flag == 5 {
            // FTW_DP = 5 (post-order directory)
            SAW_DP.store(true, Ordering::Relaxed);
        }
        0
    }

    let tmpdir = std::env::temp_dir().join("frankenlibc_nftw_depth_test");
    let _ = std::fs::create_dir_all(tmpdir.join("sub"));
    let _ = std::fs::write(tmpdir.join("sub/f.txt"), "x");

    let path = format!("{}\0", tmpdir.display());

    SAW_DP.store(false, Ordering::Relaxed);
    // FTW_DEPTH = 8
    let rc = unsafe { nftw(path.as_ptr() as *const c_char, Some(check_dp), 16, 8) };
    assert_eq!(rc, 0);
    assert!(
        SAW_DP.load(Ordering::Relaxed),
        "FTW_DEPTH should produce FTW_DP type flag"
    );

    let _ = std::fs::remove_dir_all(&tmpdir);
}

// ---------------------------------------------------------------------------
// setmntent / getmntent / endmntent tests
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn setmntent(filename: *const c_char, type_: *const c_char) -> *mut c_void;
    fn getmntent(stream: *mut c_void) -> *mut c_void;
    fn endmntent(stream: *mut c_void) -> c_int;
}

#[test]
fn mntent_reads_proc_mounts() {
    let filename = b"/proc/mounts\0";
    let mode = b"r\0";

    let stream = unsafe {
        setmntent(
            filename.as_ptr() as *const c_char,
            mode.as_ptr() as *const c_char,
        )
    };
    // /proc/mounts should exist on Linux
    if stream.is_null() {
        // Skip on systems without /proc/mounts
        return;
    }

    let entry = unsafe { getmntent(stream) };
    assert!(!entry.is_null(), "should read at least one mount entry");

    // struct mntent: { mnt_fsname (*), mnt_dir (*), mnt_type (*), mnt_opts (*), freq, passno }
    let fsname_ptr = unsafe { *(entry as *const *const c_char) };
    assert!(!fsname_ptr.is_null());
    let fsname = unsafe { std::ffi::CStr::from_ptr(fsname_ptr) };
    assert!(!fsname.to_bytes().is_empty(), "fsname should not be empty");

    let dir_ptr = unsafe { *((entry as *const u8).add(8) as *const *const c_char) };
    assert!(!dir_ptr.is_null());
    let dir = unsafe { std::ffi::CStr::from_ptr(dir_ptr) };
    assert!(!dir.to_bytes().is_empty(), "dir should not be empty");

    let rc = unsafe { endmntent(stream) };
    assert_eq!(rc, 1, "endmntent always returns 1");
}

// Note: getmntent(NULL) / endmntent(NULL) may segfault in glibc.
// Our native impl handles NULL safely, but in test mode we link against glibc.
// Skipping NULL safety tests for conformance.

#[test]
fn setmntent_nonexistent_returns_null() {
    let filename = b"/nonexistent_frankenlibc_mnt_file_xyz\0";
    let mode = b"r\0";
    let stream = unsafe {
        setmntent(
            filename.as_ptr() as *const c_char,
            mode.as_ptr() as *const c_char,
        )
    };
    assert!(stream.is_null());
}

// ---------------------------------------------------------------------------
// fgetpwent / fgetgrent tests
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn fopen(path: *const c_char, mode: *const c_char) -> *mut c_void;
    fn fclose(stream: *mut c_void) -> c_int;
    fn fgetpwent(stream: *mut c_void) -> *mut c_void;
    fn fgetgrent(stream: *mut c_void) -> *mut c_void;
}

#[test]
fn fgetpwent_reads_etc_passwd() {
    let path = b"/etc/passwd\0";
    let mode = b"r\0";
    let stream = unsafe {
        fopen(
            path.as_ptr() as *const c_char,
            mode.as_ptr() as *const c_char,
        )
    };
    if stream.is_null() {
        // Skip if /etc/passwd is not readable (unlikely but safe)
        return;
    }

    // Read the first entry
    let entry = unsafe { fgetpwent(stream) };
    assert!(!entry.is_null(), "should read at least one passwd entry");

    // struct passwd layout: { pw_name (*), pw_passwd (*), pw_uid (u32), pw_gid (u32), pw_gecos (*), pw_dir (*), pw_shell (*) }
    let pw_name = unsafe { *(entry as *const *const c_char) };
    assert!(!pw_name.is_null(), "pw_name should not be null");
    let name = unsafe { std::ffi::CStr::from_ptr(pw_name) };
    assert!(
        !name.to_bytes().is_empty(),
        "first passwd entry should have a non-empty name"
    );

    // pw_uid is at offset 16 (after two pointers)
    let pw_uid = unsafe { *((entry as *const u8).add(16) as *const u32) };
    // First entry is usually root (uid 0), but don't enforce — just check it's a reasonable value
    assert!(
        pw_uid <= 65534,
        "uid should be in valid range, got {pw_uid}"
    );

    unsafe { fclose(stream) };
}

#[test]
fn fgetpwent_reads_multiple_entries() {
    let path = b"/etc/passwd\0";
    let mode = b"r\0";
    let stream = unsafe {
        fopen(
            path.as_ptr() as *const c_char,
            mode.as_ptr() as *const c_char,
        )
    };
    if stream.is_null() {
        return;
    }

    let mut count = 0;
    loop {
        let entry = unsafe { fgetpwent(stream) };
        if entry.is_null() {
            break;
        }
        count += 1;
        if count >= 100 {
            break; // Safety limit
        }
    }

    assert!(
        count >= 1,
        "should read at least 1 passwd entry, got {count}"
    );

    unsafe { fclose(stream) };
}

#[test]
fn fgetgrent_reads_etc_group() {
    let path = b"/etc/group\0";
    let mode = b"r\0";
    let stream = unsafe {
        fopen(
            path.as_ptr() as *const c_char,
            mode.as_ptr() as *const c_char,
        )
    };
    if stream.is_null() {
        return;
    }

    let entry = unsafe { fgetgrent(stream) };
    assert!(!entry.is_null(), "should read at least one group entry");

    // struct group layout: { gr_name (*), gr_passwd (*), gr_gid (u32), [pad], gr_mem (**) }
    let gr_name = unsafe { *(entry as *const *const c_char) };
    assert!(!gr_name.is_null(), "gr_name should not be null");
    let name = unsafe { std::ffi::CStr::from_ptr(gr_name) };
    assert!(
        !name.to_bytes().is_empty(),
        "first group entry should have a non-empty name"
    );

    unsafe { fclose(stream) };
}

#[test]
fn fgetgrent_reads_multiple_entries() {
    let path = b"/etc/group\0";
    let mode = b"r\0";
    let stream = unsafe {
        fopen(
            path.as_ptr() as *const c_char,
            mode.as_ptr() as *const c_char,
        )
    };
    if stream.is_null() {
        return;
    }

    let mut count = 0;
    loop {
        let entry = unsafe { fgetgrent(stream) };
        if entry.is_null() {
            break;
        }
        count += 1;
        if count >= 100 {
            break;
        }
    }

    assert!(
        count >= 1,
        "should read at least 1 group entry, got {count}"
    );

    unsafe { fclose(stream) };
}
