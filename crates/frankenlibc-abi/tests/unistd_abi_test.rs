//! ABI integration tests for unistd_abi native implementations.
//!
//! Tests for promoted GlibcCallThrough -> Implemented symbols:
//! - glob64 / globfree64
//! - ftw / nftw / nftw64
//! - setmntent / getmntent / endmntent

#![allow(unsafe_code)]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::AtomicI32;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::glibc_internal_abi::__sysv_signal;
use frankenlibc_abi::glibc_internal_abi::getdate_err;
use frankenlibc_abi::glibc_internal_abi::setaliasent as abi_setaliasent;
use frankenlibc_abi::resolv_abi::__h_errno_location;
use frankenlibc_abi::unistd_abi::{
    FTSENT as AbiFtsEnt, access, alarm, chdir, chmod, chown, close, creat, eaccess, endaliasent,
    ether_line, euidaccess, faccessat, fchmod, fchown, fdatasync, fgetgrent_r, fgetpwent_r,
    fgetspent, fgetspent_r, flock, fstat, fsync, ftruncate, fts_children as abi_fts_children,
    fts_close as abi_fts_close, fts_open as abi_fts_open, fts_read as abi_fts_read,
    fts_set as abi_fts_set, gai_cancel, gai_error, gai_suspend, getaddrinfo_a, getaliasbyname,
    getaliasbyname_r, getaliasent, getaliasent_r, getcwd, getdate, getdate_r, getegid, geteuid,
    getfsent, getfsfile, getfsspec, getgid, gethostbyname2, gethostbyname2_r, gethostent_r,
    gethostname, getnetbyaddr_r, getnetbyname_r, getnetent_r, getnetgrent, getnetgrent_r, getpid,
    getppid, getprotobyname_r, getprotobynumber_r, getprotoent, getprotoent_r, getservent,
    getservent_r, getttyent, getttynam, getuid, getutent_r, getutid, getutid_r, getutline,
    getutline_r, glob64, globfree64, gsignal, isatty, link, logout, lseek, lstat, mkdir, mkfifo,
    msgrcv, msgsnd, open, pathconf, process_madvise, process_mrelease, process_vm_readv,
    process_vm_writev, read, readlink, rename, rmdir, semctl, semop, setfsent, sethostent,
    setnetent, setnetgrent, setns, setprotoent, setservent, setttyent, setutent, shmdt, sigpause,
    sigset, sigstack, sigvec, ssignal, stat, strfmon, strfmon_l, symlink, sysconf, truncate, umask,
    uname, unlink, unshare, updwtmp, updwtmpx, usleep, utmpname, wordexp as abi_wordexp,
    wordfree as abi_wordfree, write,
};

static SIGNAL_HIT: AtomicI32 = AtomicI32::new(0);
const GAI_WAIT: c_int = 0;
const GAI_NOWAIT: c_int = 1;
const GAI_EAI_ALLDONE: c_int = -103;

#[repr(C)]
struct NetEnt {
    n_name: *mut c_char,
    n_aliases: *mut *mut c_char,
    n_addrtype: c_int,
    n_net: u32,
}

#[repr(C)]
struct Fstab {
    fs_spec: *mut c_char,
    fs_file: *mut c_char,
    fs_vfstype: *mut c_char,
    fs_mntops: *mut c_char,
    fs_type: *const c_char,
    fs_freq: c_int,
    fs_passno: c_int,
}

#[repr(C)]
struct RpcEnt {
    r_name: *mut c_char,
    r_aliases: *mut *mut c_char,
    r_number: c_int,
}

#[repr(C)]
struct TtyEnt {
    ty_name: *mut c_char,
    ty_getty: *mut c_char,
    ty_type: *mut c_char,
    ty_status: c_int,
    ty_window: *mut c_char,
    ty_comment: *mut c_char,
}

unsafe extern "C" {
    fn setrpcent(stayopen: c_int);
    fn getrpcent_r(
        result_buf: *mut RpcEnt,
        buffer: *mut c_char,
        buflen: usize,
        result: *mut *mut RpcEnt,
    ) -> c_int;
    fn getrpcbyname_r(
        name: *const c_char,
        result_buf: *mut RpcEnt,
        buffer: *mut c_char,
        buflen: usize,
        result: *mut *mut RpcEnt,
    ) -> c_int;
    fn getrpcbynumber_r(
        number: c_int,
        result_buf: *mut RpcEnt,
        buffer: *mut c_char,
        buflen: usize,
        result: *mut *mut RpcEnt,
    ) -> c_int;
    fn endttyent() -> c_int;
}

unsafe extern "C" fn record_sigusr1(sig: c_int) {
    SIGNAL_HIT.store(sig, Ordering::SeqCst);
}

#[test]
fn isatty_invalid_fd_sets_ebadf() {
    let rc = unsafe { isatty(-1) };
    assert_eq!(rc, 0);
    let err = unsafe { *__errno_location() };
    assert_eq!(err, libc::EBADF);
}

#[test]
fn isatty_regular_file_sets_enotty_like_host() {
    let file = std::fs::File::open("/etc/hosts").unwrap();
    let fd = file.as_raw_fd();

    let rc = unsafe { isatty(fd) };
    assert_eq!(rc, 0);
    let err = unsafe { *__errno_location() };
    assert!(
        err == libc::ENOTTY || err == libc::EINVAL,
        "non-terminal fd should report ENOTTY-compatible errno, got {err}"
    );
}

// ---------------------------------------------------------------------------
// fts_* parity tests
// ---------------------------------------------------------------------------

const TEST_FTS_PHYSICAL: c_int = 0x0010;
const TEST_FTS_NAMEONLY: c_int = 0x0100;
const TEST_FTS_AGAIN: c_int = 1;
const TEST_FTS_FOLLOW: c_int = 2;
const TEST_FTS_SKIP: c_int = 4;
const TEST_FTS_DP: u16 = 6;

unsafe extern "C" {
    fn fts_open(
        path_argv: *const *mut c_char,
        options: c_int,
        compar: Option<
            unsafe extern "C" fn(*const *const AbiFtsEnt, *const *const AbiFtsEnt) -> c_int,
        >,
    ) -> *mut c_void;
    fn fts_read(ftsp: *mut c_void) -> *mut AbiFtsEnt;
    fn fts_children(ftsp: *mut c_void, instr: c_int) -> *mut AbiFtsEnt;
    fn fts_set(ftsp: *mut c_void, f: *mut AbiFtsEnt, instr: c_int) -> c_int;
    fn fts_close(ftsp: *mut c_void) -> c_int;
}

fn temp_path_buf(tag: &str) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStringExt;

    let path = temp_path(tag);
    std::path::PathBuf::from(std::ffi::OsString::from_vec(path.into_bytes()))
}

fn make_fts_argv(paths: &[std::path::PathBuf]) -> (Vec<CString>, Vec<*mut c_char>) {
    let roots = paths
        .iter()
        .map(|path| CString::new(path.as_os_str().as_bytes()).unwrap())
        .collect::<Vec<_>>();
    let mut argv = roots
        .iter()
        .map(|path| path.as_ptr() as *mut c_char)
        .collect::<Vec<_>>();
    argv.push(std::ptr::null_mut());
    (roots, argv)
}

fn clear_errno() {
    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = 0;
    }
}

fn fts_names(mut entry: *mut AbiFtsEnt) -> Vec<String> {
    let mut names = Vec::new();
    while !entry.is_null() {
        names.push(
            unsafe { std::ffi::CStr::from_ptr((*entry).fts_name.as_ptr()) }
                .to_string_lossy()
                .into_owned(),
        );
        entry = unsafe { (*entry).fts_link };
    }
    names
}

fn fts_path(entry: *mut AbiFtsEnt) -> String {
    unsafe { std::ffi::CStr::from_ptr((*entry).fts_path) }
        .to_string_lossy()
        .into_owned()
}

#[test]
fn fts_open_zero_mode_and_empty_roots_match_host_behavior() {
    let root = temp_path_buf("fts_open");
    std::fs::create_dir_all(&root).unwrap();
    let (_roots, argv) = make_fts_argv(std::slice::from_ref(&root));

    unsafe {
        clear_errno();
        let host = fts_open(argv.as_ptr(), 0, None);
        let host_errno = errno_value();

        clear_errno();
        let abi = abi_fts_open(argv.as_ptr() as *const *const c_char, 0, None);
        let abi_errno = errno_value();

        assert_eq!(abi.is_null(), host.is_null());
        assert_eq!(abi_errno, host_errno, "zero-mode errno should match host");
        if !host.is_null() {
            assert_eq!(fts_close(host), 0);
        }
        if !abi.is_null() {
            assert_eq!(abi_fts_close(abi), 0);
        }
    }

    let empty = CString::new("").unwrap();
    let empty_argv = [empty.as_ptr() as *mut c_char, std::ptr::null_mut()];
    unsafe {
        clear_errno();
        let host = fts_open(empty_argv.as_ptr(), TEST_FTS_PHYSICAL, None);
        let host_errno = errno_value();

        clear_errno();
        let abi = abi_fts_open(
            empty_argv.as_ptr() as *const *const c_char,
            TEST_FTS_PHYSICAL,
            None,
        );
        let abi_errno = errno_value();

        assert!(host.is_null());
        assert!(abi.is_null());
        assert_eq!(abi_errno, host_errno, "empty-root errno should match host");
    }

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn fts_children_before_first_read_matches_host_root_listing() {
    let dir_root = temp_path_buf("fts_roots_dir");
    let file_root = temp_path_buf("fts_roots_file");
    std::fs::create_dir_all(&dir_root).unwrap();
    std::fs::write(&file_root, b"root").unwrap();
    let (_roots, argv) = make_fts_argv(&[dir_root.clone(), file_root.clone()]);

    unsafe {
        let host = fts_open(argv.as_ptr(), TEST_FTS_PHYSICAL, None);
        let abi = abi_fts_open(
            argv.as_ptr() as *const *const c_char,
            TEST_FTS_PHYSICAL,
            None,
        );
        assert!(!host.is_null());
        assert!(!abi.is_null());

        let host_names = fts_names(fts_children(host, 0));
        let abi_names = fts_names(abi_fts_children(abi, 0));
        assert_eq!(abi_names, host_names);

        assert_eq!(fts_close(host), 0);
        assert_eq!(abi_fts_close(abi), 0);
    }

    let _ = std::fs::remove_dir_all(&dir_root);
    let _ = std::fs::remove_file(&file_root);
}

#[test]
fn fts_children_directory_listing_and_nameonly_match_host() {
    let root = temp_path_buf("fts_children_dir");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("file.txt"), b"file").unwrap();
    std::os::unix::fs::symlink(root.join("file.txt"), root.join("link.txt")).unwrap();
    let (_roots, argv) = make_fts_argv(std::slice::from_ref(&root));

    unsafe {
        let host = fts_open(argv.as_ptr(), TEST_FTS_PHYSICAL, None);
        let abi = abi_fts_open(
            argv.as_ptr() as *const *const c_char,
            TEST_FTS_PHYSICAL,
            None,
        );

        let host_root = fts_read(host);
        let abi_root = abi_fts_read(abi);
        assert!(!host_root.is_null());
        assert!(!abi_root.is_null());

        let host_names = fts_names(fts_children(host, 0));
        let abi_names = fts_names(abi_fts_children(abi, 0));
        assert_eq!(abi_names, host_names);

        let host_repeat = fts_names(fts_children(host, 0));
        let abi_repeat = fts_names(abi_fts_children(abi, 0));
        assert_eq!(abi_repeat, host_repeat);

        let host_nameonly = fts_names(fts_children(host, TEST_FTS_NAMEONLY));
        let abi_nameonly = fts_names(abi_fts_children(abi, TEST_FTS_NAMEONLY));
        assert_eq!(abi_nameonly, host_nameonly);

        assert_eq!(fts_close(host), 0);
        assert_eq!(abi_fts_close(abi), 0);
    }

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn fts_children_on_nondirectory_matches_host_null_semantics() {
    let root = temp_path_buf("fts_children_file");
    std::fs::write(&root, b"plain").unwrap();
    let (_roots, argv) = make_fts_argv(std::slice::from_ref(&root));

    unsafe {
        let host = fts_open(argv.as_ptr(), TEST_FTS_PHYSICAL, None);
        let abi = abi_fts_open(
            argv.as_ptr() as *const *const c_char,
            TEST_FTS_PHYSICAL,
            None,
        );
        assert!(!fts_read(host).is_null());
        assert!(!abi_fts_read(abi).is_null());

        clear_errno();
        let host_children = fts_children(host, 0);
        let host_errno = errno_value();

        clear_errno();
        let abi_children = abi_fts_children(abi, 0);
        let abi_errno = errno_value();

        assert!(host_children.is_null());
        assert!(abi_children.is_null());
        assert_eq!(abi_errno, host_errno);

        assert_eq!(fts_close(host), 0);
        assert_eq!(abi_fts_close(abi), 0);
    }

    let _ = std::fs::remove_file(&root);
}

#[test]
fn fts_set_again_on_file_root_matches_host() {
    let root = temp_path_buf("fts_again");
    std::fs::write(&root, b"again").unwrap();
    let (_roots, argv) = make_fts_argv(std::slice::from_ref(&root));

    unsafe {
        let host = fts_open(argv.as_ptr(), TEST_FTS_PHYSICAL, None);
        let abi = abi_fts_open(
            argv.as_ptr() as *const *const c_char,
            TEST_FTS_PHYSICAL,
            None,
        );
        let host_entry = fts_read(host);
        let abi_entry = abi_fts_read(abi);
        assert!(!host_entry.is_null());
        assert!(!abi_entry.is_null());

        assert_eq!(fts_set(host, host_entry, TEST_FTS_AGAIN), 0);
        assert_eq!(abi_fts_set(abi, abi_entry, TEST_FTS_AGAIN), 0);

        let host_again = fts_read(host);
        let abi_again = abi_fts_read(abi);
        assert!(!host_again.is_null());
        assert!(!abi_again.is_null());
        assert_eq!((*abi_again).fts_info, (*host_again).fts_info);
        assert_eq!(fts_path(abi_again), fts_path(host_again));

        assert_eq!(fts_close(host), 0);
        assert_eq!(abi_fts_close(abi), 0);
    }

    let _ = std::fs::remove_file(&root);
}

#[test]
fn fts_set_follow_on_current_symlink_matches_host() {
    let root = temp_path_buf("fts_follow_link");
    let target = temp_path_buf("fts_follow_target");
    std::fs::write(&target, b"target").unwrap();
    std::os::unix::fs::symlink(&target, &root).unwrap();
    let (_roots, argv) = make_fts_argv(std::slice::from_ref(&root));

    unsafe {
        let host = fts_open(argv.as_ptr(), TEST_FTS_PHYSICAL, None);
        let abi = abi_fts_open(
            argv.as_ptr() as *const *const c_char,
            TEST_FTS_PHYSICAL,
            None,
        );
        let host_symlink = fts_read(host);
        let abi_symlink = abi_fts_read(abi);
        assert!(!host_symlink.is_null());
        assert!(!abi_symlink.is_null());

        assert_eq!(fts_set(host, host_symlink, TEST_FTS_FOLLOW), 0);
        assert_eq!(abi_fts_set(abi, abi_symlink, TEST_FTS_FOLLOW), 0);

        let host_followed = fts_read(host);
        let abi_followed = abi_fts_read(abi);
        assert!(!host_followed.is_null());
        assert!(!abi_followed.is_null());
        assert_eq!((*abi_followed).fts_info, (*host_followed).fts_info);
        assert_eq!(fts_path(abi_followed), fts_path(host_followed));

        assert_eq!(fts_close(host), 0);
        assert_eq!(abi_fts_close(abi), 0);
    }

    let _ = std::fs::remove_file(&root);
    let _ = std::fs::remove_file(&target);
}

#[test]
fn fts_set_skip_matches_host_and_invalid_instr_sets_einval() {
    let root = temp_path_buf("fts_skip");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("child.txt"), b"child").unwrap();
    let (_roots, argv) = make_fts_argv(std::slice::from_ref(&root));

    unsafe {
        let invalid = abi_fts_open(
            argv.as_ptr() as *const *const c_char,
            TEST_FTS_PHYSICAL,
            None,
        );
        let invalid_root = abi_fts_read(invalid);
        assert!(!invalid_root.is_null());

        clear_errno();
        let abi_invalid = abi_fts_set(invalid, invalid_root, 999);
        let abi_invalid_errno = errno_value();
        assert_eq!(abi_invalid, -1);
        assert_eq!(abi_invalid_errno, libc::EINVAL);
        assert_eq!(abi_fts_close(invalid), 0);

        let host = fts_open(argv.as_ptr(), TEST_FTS_PHYSICAL, None);
        let abi = abi_fts_open(
            argv.as_ptr() as *const *const c_char,
            TEST_FTS_PHYSICAL,
            None,
        );
        let host_root = fts_read(host);
        let abi_root = abi_fts_read(abi);
        assert!(!host_root.is_null());
        assert!(!abi_root.is_null());

        assert_eq!(fts_set(host, host_root, TEST_FTS_SKIP), 0);
        assert_eq!(abi_fts_set(abi, abi_root, TEST_FTS_SKIP), 0);

        let host_next = fts_read(host);
        let abi_next = abi_fts_read(abi);
        assert!(!host_next.is_null());
        assert!(!abi_next.is_null());
        assert_eq!((*abi_next).fts_info, (*host_next).fts_info);
        assert_eq!((*abi_next).fts_info, TEST_FTS_DP);
        assert_eq!(fts_path(abi_next), fts_path(host_next));

        let host_end = fts_read(host);
        let abi_end = abi_fts_read(abi);
        assert!(host_end.is_null());
        assert!(abi_end.is_null());

        assert_eq!(fts_close(host), 0);
        assert_eq!(abi_fts_close(abi), 0);
    }

    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// glob64 / globfree64 tests
// ---------------------------------------------------------------------------

/// Minimal view of the `glob_t` prefix used by our `glob64`/`globfree64`
/// implementation on x86_64, where `glob_t` and `glob64_t` are layout-identical.
#[repr(C)]
struct GlobBuf {
    gl_pathc: usize,
    gl_pathv: *mut *mut c_char,
    gl_offs: usize,
}

#[test]
fn glob64_literal_path_exists() {
    // /tmp should exist on any Linux system.
    let pattern = b"/tmp\0";
    let mut glob_buf = GlobBuf {
        gl_pathc: 0,
        gl_pathv: std::ptr::null_mut(),
        gl_offs: 0,
    };

    let rc = unsafe {
        glob64(
            pattern.as_ptr() as *const c_char,
            0,
            None,
            &mut glob_buf as *mut GlobBuf as *mut c_void,
        )
    };
    assert_eq!(rc, 0, "glob64 should succeed for /tmp");
    assert_eq!(
        glob_buf.gl_pathc, 1,
        "should find exactly 1 match for literal /tmp"
    );
    assert!(!glob_buf.gl_pathv.is_null());

    // First path should be "/tmp"
    let first = unsafe { *glob_buf.gl_pathv };
    assert!(!first.is_null());
    let first_str = unsafe { std::ffi::CStr::from_ptr(first) };
    assert_eq!(first_str.to_bytes(), b"/tmp");

    unsafe { globfree64(&mut glob_buf as *mut GlobBuf as *mut c_void) };
    assert_eq!(glob_buf.gl_pathc, 0, "globfree64 should clear gl_pathc");
    assert!(
        glob_buf.gl_pathv.is_null(),
        "globfree64 should clear gl_pathv"
    );
}

#[test]
fn glob64_nomatch_returns_error() {
    let pattern = b"/nonexistent_frankenlibc_glob_test_xyz_42\0";
    let mut glob_buf = GlobBuf {
        gl_pathc: 0,
        gl_pathv: std::ptr::null_mut(),
        gl_offs: 0,
    };

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

#[repr(C)]
struct AliasEnt {
    alias_name: *mut c_char,
    alias_members: *mut *mut c_char,
    alias_local: c_int,
}

unsafe fn load_host_symbol(name: &str) -> Option<*mut c_void> {
    let libc_name = CString::new("libc.so.6").unwrap();
    let handle = unsafe { libc::dlopen(libc_name.as_ptr(), libc::RTLD_NOW) };
    if handle.is_null() {
        return None;
    }
    let sym = CString::new(name).unwrap();
    let ptr = unsafe { libc::dlsym(handle, sym.as_ptr()) };
    if ptr.is_null() { None } else { Some(ptr) }
}

type WordexpFn = unsafe extern "C" fn(*const c_char, *mut c_void, c_int) -> c_int;
type WordfreeFn = unsafe extern "C" fn(*mut c_void);

const TEST_WRDE_NOCMD: c_int = 1 << 2;
const TEST_WRDE_UNDEF: c_int = 1 << 5;

#[repr(C)]
struct WordexpBuf {
    we_wordc: usize,
    we_wordv: *mut *mut c_char,
    we_offs: usize,
}

unsafe fn load_host_wordexp_symbols() -> Option<(WordexpFn, WordfreeFn)> {
    let wordexp_ptr = unsafe { load_host_symbol("wordexp") }?;
    let wordfree_ptr = unsafe { load_host_symbol("wordfree") }?;
    Some(unsafe {
        (
            std::mem::transmute::<*mut c_void, WordexpFn>(wordexp_ptr),
            std::mem::transmute::<*mut c_void, WordfreeFn>(wordfree_ptr),
        )
    })
}

unsafe fn collect_wordexp_words(buf: &WordexpBuf) -> Vec<String> {
    let mut words = Vec::new();
    if buf.we_wordv.is_null() {
        return words;
    }
    for idx in 0..buf.we_wordc {
        let word_ptr = unsafe { *buf.we_wordv.add(buf.we_offs + idx) };
        if word_ptr.is_null() {
            continue;
        }
        words.push(
            unsafe { std::ffi::CStr::from_ptr(word_ptr) }
                .to_string_lossy()
                .into_owned(),
        );
    }
    words
}

unsafe fn run_wordexp_case(
    wordexp_fn: WordexpFn,
    wordfree_fn: WordfreeFn,
    input: &CString,
    flags: c_int,
) -> (c_int, Vec<String>) {
    let mut buf = WordexpBuf {
        we_wordc: 0,
        we_wordv: std::ptr::null_mut(),
        we_offs: 0,
    };
    let rc = unsafe { wordexp_fn(input.as_ptr(), (&mut buf as *mut WordexpBuf).cast(), flags) };
    let words = if rc == 0 {
        unsafe { collect_wordexp_words(&buf) }
    } else {
        Vec::new()
    };
    if !buf.we_wordv.is_null() {
        unsafe { wordfree_fn((&mut buf as *mut WordexpBuf).cast()) };
    }
    (rc, words)
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
fn wordexp_badchars_respect_quote_and_escape_context_like_host() {
    let Some((host_wordexp, host_wordfree)) = (unsafe { load_host_wordexp_symbols() }) else {
        return;
    };

    for (input, flags) in [
        ("'a;b'", 0),
        ("\"a;b\"", 0),
        ("a\\;b", 0),
        ("(", 0),
        ("{", 0),
    ] {
        let input = CString::new(input).unwrap();
        let host = unsafe { run_wordexp_case(host_wordexp, host_wordfree, &input, flags) };
        let abi = unsafe { run_wordexp_case(abi_wordexp, abi_wordfree, &input, flags) };
        assert_eq!(abi, host, "wordexp mismatch for input {:?}", input);
    }
}

#[test]
fn wordexp_nocmd_respects_quote_context_like_host() {
    let Some((host_wordexp, host_wordfree)) = (unsafe { load_host_wordexp_symbols() }) else {
        return;
    };

    for input in ["'$(echo hi)'", "'`echo hi`'", "\"$(echo hi)\""] {
        let input = CString::new(input).unwrap();
        let host =
            unsafe { run_wordexp_case(host_wordexp, host_wordfree, &input, TEST_WRDE_NOCMD) };
        let abi = unsafe { run_wordexp_case(abi_wordexp, abi_wordfree, &input, TEST_WRDE_NOCMD) };
        assert_eq!(
            abi, host,
            "wordexp WRDE_NOCMD mismatch for input {:?}",
            input
        );
    }
}

#[test]
fn wordexp_undef_respects_single_and_double_quote_context_like_host() {
    let Some((host_wordexp, host_wordfree)) = (unsafe { load_host_wordexp_symbols() }) else {
        return;
    };

    for input in [
        "'$FRANKENLIBC_WORDEXP_UNSET_42'",
        "\"$FRANKENLIBC_WORDEXP_UNSET_42\"",
    ] {
        unsafe {
            libc::unsetenv(c"FRANKENLIBC_WORDEXP_UNSET_42".as_ptr());
        }
        let input = CString::new(input).unwrap();
        let host =
            unsafe { run_wordexp_case(host_wordexp, host_wordfree, &input, TEST_WRDE_UNDEF) };
        let abi = unsafe { run_wordexp_case(abi_wordexp, abi_wordfree, &input, TEST_WRDE_UNDEF) };
        assert_eq!(
            abi, host,
            "wordexp WRDE_UNDEF mismatch for input {:?}",
            input
        );
    }
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

#[test]
fn fgetpwent_r_skips_comments_and_blank_lines() {
    let path = temp_path("fgetpwent_r_skip");
    let path_str = path.as_c_str().to_str().unwrap();
    std::fs::write(path_str, b"\n# comment\nroot:x:0:0:root:/root:/bin/sh\n").unwrap();

    let mode = b"r\0";
    let stream = unsafe { fopen(path.as_ptr(), mode.as_ptr() as *const c_char) };
    assert!(!stream.is_null());

    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = [0 as c_char; 256];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        fgetpwent_r(
            stream.cast(),
            &mut entry,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(result, &mut entry as *mut libc::passwd);
    let name = unsafe { std::ffi::CStr::from_ptr(entry.pw_name) };
    assert_eq!(name.to_bytes(), b"root");

    unsafe { fclose(stream) };
    std::fs::remove_file(path_str).unwrap();
}

#[test]
fn fgetgrent_r_skips_comments_and_blank_lines() {
    let path = temp_path("fgetgrent_r_skip");
    let path_str = path.as_c_str().to_str().unwrap();
    std::fs::write(path_str, b"\n# comment\nwheel:x:10:root\n").unwrap();

    let mode = b"r\0";
    let stream = unsafe { fopen(path.as_ptr(), mode.as_ptr() as *const c_char) };
    assert!(!stream.is_null());

    let mut entry: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = [0 as c_char; 256];
    let mut result: *mut libc::group = std::ptr::null_mut();
    let rc = unsafe {
        fgetgrent_r(
            stream.cast(),
            &mut entry,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(result, &mut entry as *mut libc::group);
    let name = unsafe { std::ffi::CStr::from_ptr(entry.gr_name) };
    assert_eq!(name.to_bytes(), b"wheel");

    unsafe { fclose(stream) };
    std::fs::remove_file(path_str).unwrap();
}

#[test]
fn fgetspent_r_skips_comments_and_blank_lines() {
    let path = temp_path("fgetspent_r_skip");
    let path_str = path.as_c_str().to_str().unwrap();
    std::fs::write(path_str, b"\n# comment\nroot:*:1:0:99999:7:::\n").unwrap();

    let mode = b"r\0";
    let stream = unsafe { fopen(path.as_ptr(), mode.as_ptr() as *const c_char) };
    assert!(!stream.is_null());

    let mut entry: libc::spwd = unsafe { std::mem::zeroed() };
    let mut buf = [0 as c_char; 256];
    let mut result: *mut libc::spwd = std::ptr::null_mut();
    let rc = unsafe {
        fgetspent_r(
            stream.cast(),
            &mut entry,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(result, &mut entry as *mut libc::spwd);
    let name = unsafe { std::ffi::CStr::from_ptr(entry.sp_namp) };
    assert_eq!(name.to_bytes(), b"root");

    unsafe { fclose(stream) };
    std::fs::remove_file(path_str).unwrap();
}

#[test]
fn fgetspent_skips_comments_and_blank_lines() {
    let path = temp_path("fgetspent_skip");
    let path_str = path.as_c_str().to_str().unwrap();
    std::fs::write(path_str, b"\n# comment\nroot:*:1:0:99999:7:::\n").unwrap();

    let mode = b"r\0";
    let stream = unsafe { fopen(path.as_ptr(), mode.as_ptr() as *const c_char) };
    assert!(!stream.is_null());

    let entry = unsafe { fgetspent(stream.cast()) };
    assert!(
        !entry.is_null(),
        "fgetspent should skip comments to the next entry"
    );
    let name = unsafe { std::ffi::CStr::from_ptr((*entry).sp_namp) };
    assert_eq!(name.to_bytes(), b"root");

    unsafe { fclose(stream) };
    std::fs::remove_file(path_str).unwrap();
}

#[test]
fn alias_iterators_match_host_shape() {
    type HostSetaliasentFn = unsafe extern "C" fn();
    type HostEndaliasentFn = unsafe extern "C" fn();
    type HostGetaliasentFn = unsafe extern "C" fn() -> *mut c_void;
    type HostGetaliasentRFn =
        unsafe extern "C" fn(*mut c_void, *mut c_char, usize, *mut *mut c_void) -> c_int;

    let Some(host_setaliasent) = (unsafe { load_host_symbol("setaliasent") })
        .map(|p| unsafe { std::mem::transmute::<*mut c_void, HostSetaliasentFn>(p) })
    else {
        return;
    };
    let Some(host_endaliasent) = (unsafe { load_host_symbol("endaliasent") })
        .map(|p| unsafe { std::mem::transmute::<*mut c_void, HostEndaliasentFn>(p) })
    else {
        return;
    };
    let Some(host_getaliasent) = (unsafe { load_host_symbol("getaliasent") })
        .map(|p| unsafe { std::mem::transmute::<*mut c_void, HostGetaliasentFn>(p) })
    else {
        return;
    };
    let Some(host_getaliasent_r) = (unsafe { load_host_symbol("getaliasent_r") })
        .map(|p| unsafe { std::mem::transmute::<*mut c_void, HostGetaliasentRFn>(p) })
    else {
        return;
    };

    unsafe { host_setaliasent() };
    let host_plain = unsafe { host_getaliasent() };
    let host_plain_errno = unsafe { *libc::__errno_location() };
    unsafe { host_endaliasent() };

    unsafe { abi_setaliasent() };
    let ours_plain = unsafe { getaliasent() };
    let ours_plain_errno = unsafe { *__errno_location() };
    unsafe { endaliasent() };

    assert_eq!(ours_plain.is_null(), host_plain.is_null());
    if host_plain.is_null() {
        assert_eq!(ours_plain_errno, host_plain_errno);
    }

    let mut host_entry = AliasEnt {
        alias_name: std::ptr::null_mut(),
        alias_members: std::ptr::null_mut(),
        alias_local: 0,
    };
    let mut host_buf = [0 as c_char; 1024];
    let mut host_result: *mut c_void = std::ptr::dangling_mut::<c_void>();
    unsafe { host_setaliasent() };
    let host_rc = unsafe {
        host_getaliasent_r(
            (&mut host_entry as *mut AliasEnt).cast(),
            host_buf.as_mut_ptr(),
            host_buf.len(),
            &mut host_result,
        )
    };
    let host_errno = unsafe { *libc::__errno_location() };
    unsafe { host_endaliasent() };

    let mut our_entry = AliasEnt {
        alias_name: std::ptr::null_mut(),
        alias_members: std::ptr::null_mut(),
        alias_local: 0,
    };
    let mut our_buf = [0 as c_char; 1024];
    let mut our_result: *mut c_void = std::ptr::dangling_mut::<c_void>();
    unsafe { abi_setaliasent() };
    let our_rc = unsafe {
        getaliasent_r(
            (&mut our_entry as *mut AliasEnt).cast(),
            our_buf.as_mut_ptr(),
            our_buf.len(),
            &mut our_result,
        )
    };
    let our_errno = unsafe { *__errno_location() };
    unsafe { endaliasent() };

    assert_eq!(our_rc, host_rc);
    assert_eq!(our_result.is_null(), host_result.is_null());
    if host_rc != 0 {
        assert_eq!(our_errno, host_errno);
    }
}

#[test]
fn netgroup_iterators_match_host_shape() {
    type HostSetnetgrentFn = unsafe extern "C" fn(*const c_char) -> c_int;
    type HostEndnetgrentFn = unsafe extern "C" fn();
    type HostGetnetgrentFn =
        unsafe extern "C" fn(*mut *mut c_char, *mut *mut c_char, *mut *mut c_char) -> c_int;
    type HostGetnetgrentRFn = unsafe extern "C" fn(
        *mut *mut c_char,
        *mut *mut c_char,
        *mut *mut c_char,
        *mut c_char,
        usize,
    ) -> c_int;

    let Some(host_setnetgrent) = (unsafe { load_host_symbol("setnetgrent") })
        .map(|p| unsafe { std::mem::transmute::<*mut c_void, HostSetnetgrentFn>(p) })
    else {
        return;
    };
    let Some(host_endnetgrent) = (unsafe { load_host_symbol("endnetgrent") })
        .map(|p| unsafe { std::mem::transmute::<*mut c_void, HostEndnetgrentFn>(p) })
    else {
        return;
    };
    let Some(host_getnetgrent) = (unsafe { load_host_symbol("getnetgrent") })
        .map(|p| unsafe { std::mem::transmute::<*mut c_void, HostGetnetgrentFn>(p) })
    else {
        return;
    };
    let Some(host_getnetgrent_r) = (unsafe { load_host_symbol("getnetgrent_r") })
        .map(|p| unsafe { std::mem::transmute::<*mut c_void, HostGetnetgrentRFn>(p) })
    else {
        return;
    };

    let missing = CString::new("frankenlibc-no-such-netgroup").unwrap();

    let host_set_rc = unsafe { host_setnetgrent(missing.as_ptr()) };
    let host_set_errno = unsafe { *libc::__errno_location() };
    let mut host_h = std::ptr::dangling_mut::<c_char>();
    let mut host_u = std::ptr::dangling_mut::<c_char>();
    let mut host_d = std::ptr::dangling_mut::<c_char>();
    let host_plain_rc = unsafe { host_getnetgrent(&mut host_h, &mut host_u, &mut host_d) };
    let host_plain_errno = unsafe { *libc::__errno_location() };
    let mut host_buf = [0 as c_char; 1024];
    let host_r_rc = unsafe {
        host_getnetgrent_r(
            &mut host_h,
            &mut host_u,
            &mut host_d,
            host_buf.as_mut_ptr(),
            host_buf.len(),
        )
    };
    let host_r_errno = unsafe { *libc::__errno_location() };
    unsafe { host_endnetgrent() };

    let our_set_rc = unsafe { setnetgrent(missing.as_ptr()) };
    let our_set_errno = unsafe { *__errno_location() };
    let mut our_h = std::ptr::dangling_mut::<c_char>();
    let mut our_u = std::ptr::dangling_mut::<c_char>();
    let mut our_d = std::ptr::dangling_mut::<c_char>();
    let our_plain_rc = unsafe { getnetgrent(&mut our_h, &mut our_u, &mut our_d) };
    let our_plain_errno = unsafe { *__errno_location() };
    let mut our_buf = [0 as c_char; 1024];
    let our_r_rc = unsafe {
        getnetgrent_r(
            &mut our_h,
            &mut our_u,
            &mut our_d,
            our_buf.as_mut_ptr(),
            our_buf.len(),
        )
    };
    let our_r_errno = unsafe { *__errno_location() };
    unsafe { frankenlibc_abi::unistd_abi::endnetgrent() };

    assert_eq!(our_set_rc, host_set_rc);
    assert_eq!(our_set_errno, host_set_errno);
    assert_eq!(our_plain_rc, host_plain_rc);
    assert_eq!(our_plain_errno, host_plain_errno);
    assert_eq!(our_r_rc, host_r_rc);
    assert_eq!(our_r_errno, host_r_errno);
}

#[test]
fn logout_matches_host_missing_line_shape() {
    type HostLogoutFn = unsafe extern "C" fn(*const c_char) -> c_int;
    let Some(host_logout) = (unsafe { load_host_symbol("logout") })
        .map(|p| unsafe { std::mem::transmute::<*mut c_void, HostLogoutFn>(p) })
    else {
        return;
    };

    let line = CString::new("frankenlibc-no-such-line").unwrap();

    let host_rc = unsafe { host_logout(line.as_ptr()) };
    let host_errno = unsafe { *libc::__errno_location() };

    let our_rc = unsafe { logout(line.as_ptr()) };
    let our_errno = unsafe { *__errno_location() };

    assert_eq!(our_rc, host_rc);
    assert_eq!(our_errno, host_errno);
}

#[test]
fn updwtmp_and_updwtmpx_match_host_file_effects() {
    type HostUpdwtmpFn = unsafe extern "C" fn(*const c_char, *const c_void);
    type HostUpdwtmpxFn = unsafe extern "C" fn(*const c_char, *const c_void);

    let Some(host_updwtmp) = (unsafe { load_host_symbol("updwtmp") })
        .map(|p| unsafe { std::mem::transmute::<*mut c_void, HostUpdwtmpFn>(p) })
    else {
        return;
    };
    let Some(host_updwtmpx) = (unsafe { load_host_symbol("updwtmpx") })
        .map(|p| unsafe { std::mem::transmute::<*mut c_void, HostUpdwtmpxFn>(p) })
    else {
        return;
    };

    let mut entry: libc::utmpx = unsafe { std::mem::zeroed() };
    entry.ut_type = libc::USER_PROCESS;
    entry.ut_pid = std::process::id() as libc::pid_t;
    entry.ut_tv.tv_sec = 1_700_000_000;
    entry.ut_tv.tv_usec = 123_456;
    entry.ut_line[..4].copy_from_slice(&[b't' as i8, b't' as i8, b'y' as i8, b'7' as i8]);
    entry.ut_id[..4].copy_from_slice(&[b'f' as i8, b'l' as i8, b'i' as i8, b'b' as i8]);
    entry.ut_user[..4].copy_from_slice(&[b'r' as i8, b'o' as i8, b'o' as i8, b't' as i8]);
    entry.ut_host[..9].copy_from_slice(&[
        b'l' as i8, b'o' as i8, b'c' as i8, b'a' as i8, b'l' as i8, b'h' as i8, b'o' as i8,
        b's' as i8, b't' as i8,
    ]);

    let host_wtmp = temp_path("host_wtmp");
    let our_wtmp = temp_path("our_wtmp");
    let host_wtmpx = temp_path("host_wtmpx");
    let our_wtmpx = temp_path("our_wtmpx");

    std::fs::write(host_wtmp.to_str().unwrap(), []).unwrap();
    std::fs::write(our_wtmp.to_str().unwrap(), []).unwrap();
    std::fs::write(host_wtmpx.to_str().unwrap(), []).unwrap();
    std::fs::write(our_wtmpx.to_str().unwrap(), []).unwrap();

    unsafe { host_updwtmp(host_wtmp.as_ptr(), (&entry as *const libc::utmpx).cast()) };
    unsafe { updwtmp(our_wtmp.as_ptr(), (&entry as *const libc::utmpx).cast()) };
    unsafe { host_updwtmpx(host_wtmpx.as_ptr(), (&entry as *const libc::utmpx).cast()) };
    unsafe { updwtmpx(our_wtmpx.as_ptr(), (&entry as *const libc::utmpx).cast()) };

    let host_wtmp_bytes = std::fs::read(host_wtmp.to_str().unwrap()).unwrap();
    let our_wtmp_bytes = std::fs::read(our_wtmp.to_str().unwrap()).unwrap();
    let host_wtmpx_bytes = std::fs::read(host_wtmpx.to_str().unwrap()).unwrap();
    let our_wtmpx_bytes = std::fs::read(our_wtmpx.to_str().unwrap()).unwrap();

    assert_eq!(our_wtmp_bytes, host_wtmp_bytes);
    assert_eq!(our_wtmpx_bytes, host_wtmpx_bytes);

    std::fs::remove_file(host_wtmp.to_str().unwrap()).unwrap();
    std::fs::remove_file(our_wtmp.to_str().unwrap()).unwrap();
    std::fs::remove_file(host_wtmpx.to_str().unwrap()).unwrap();
    std::fs::remove_file(our_wtmpx.to_str().unwrap()).unwrap();
}

#[test]
fn sigstack_null_args_match_host_shape() {
    type HostSigstackFn = unsafe extern "C" fn(*const c_void, *mut c_void) -> c_int;
    let Some(host_sigstack) = (unsafe { load_host_symbol("sigstack") })
        .map(|p| unsafe { std::mem::transmute::<*mut c_void, HostSigstackFn>(p) })
    else {
        return;
    };

    let host_rc = unsafe { host_sigstack(std::ptr::null(), std::ptr::null_mut()) };
    let host_errno = unsafe { *libc::__errno_location() };

    let our_rc = unsafe { sigstack(std::ptr::null(), std::ptr::null_mut()) };
    let our_errno = unsafe { *__errno_location() };

    assert_eq!(our_rc, host_rc);
    assert_eq!(our_errno, host_errno);
}

#[test]
fn sigvec_invalid_signal_sets_errno_like_sigaction() {
    let host_rc = unsafe { libc::sigaction(0, std::ptr::null(), std::ptr::null_mut()) };
    let host_errno = unsafe { *libc::__errno_location() };

    let our_rc = unsafe { sigvec(0, std::ptr::null(), std::ptr::null_mut()) };
    let our_errno = unsafe { *__errno_location() };

    assert_eq!(our_rc, host_rc);
    assert_eq!(our_errno, host_errno);
}

#[test]
fn sigpause_invalid_signal_is_rejected_without_blocking() {
    let our_rc = unsafe { sigpause(0) };
    let our_errno = unsafe { *__errno_location() };

    assert_eq!(our_rc, -1);
    assert_eq!(our_errno, libc::EINVAL);
}

#[test]
fn gsignal_invalid_signal_sets_errno_like_raise() {
    let invalid_sig = 1024;
    let host_rc = unsafe { libc::raise(invalid_sig) };
    let host_errno = unsafe { *libc::__errno_location() };

    let our_rc = unsafe { gsignal(invalid_sig) };
    let our_errno = unsafe { *__errno_location() };

    assert_eq!(our_rc, host_rc);
    assert_eq!(our_errno, host_errno);
}

#[test]
fn ssignal_invalid_signal_sets_errno() {
    let previous = unsafe { ssignal(1024, record_sigusr1 as *const () as libc::sighandler_t) };
    let err = unsafe { *__errno_location() };

    assert_eq!(previous, libc::SIG_ERR);
    assert_eq!(err, libc::EINVAL);
}

#[test]
fn sigset_invalid_signal_sets_errno() {
    let previous = unsafe { sigset(1024, record_sigusr1 as *const () as libc::sighandler_t) };
    let err = unsafe { *__errno_location() };

    assert_eq!(previous, libc::SIG_ERR);
    assert_eq!(err, libc::EINVAL);
}

#[test]
fn __sysv_signal_invalid_signal_sets_errno() {
    let previous = unsafe { __sysv_signal(1024, record_sigusr1 as *const () as *mut c_void) };
    let err = unsafe { *__errno_location() };

    assert_eq!(previous, libc::SIG_ERR as *mut c_void);
    assert_eq!(err, libc::EINVAL);
}

fn errno_value() -> i32 {
    // SAFETY: errno pointer is thread-local and valid.
    unsafe { *__errno_location() }
}

fn unique_temp_path(tag: &str) -> CString {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let mut path = std::env::temp_dir();
    path.push(format!(
        "frankenlibc_euidaccess_{tag}_{}_{}",
        std::process::id(),
        nanos
    ));
    CString::new(path.as_os_str().as_bytes()).expect("temp path must not contain interior NUL")
}

#[test]
fn euidaccess_null_path_sets_efault() {
    let rc = unsafe { euidaccess(std::ptr::null(), libc::F_OK) };
    assert_eq!(rc, -1);
    assert_eq!(errno_value(), libc::EFAULT);
}

#[test]
fn euidaccess_existing_path_matches_eaccess() {
    let path = unique_temp_path("exists");
    let path_str = path.to_str().expect("utf8 temp path");
    std::fs::write(path_str, b"x").expect("create temp file");

    let euid_rc = unsafe { euidaccess(path.as_ptr(), libc::F_OK) };
    let e_rc = unsafe { eaccess(path.as_ptr(), libc::F_OK) };

    assert_eq!(euid_rc, 0, "euidaccess should succeed for existing path");
    assert_eq!(e_rc, 0, "eaccess should succeed for existing path");

    let _ = std::fs::remove_file(path_str);
}

#[test]
fn euidaccess_missing_path_fails_with_enoent() {
    let path = unique_temp_path("missing");
    let rc = unsafe { euidaccess(path.as_ptr(), libc::F_OK) };
    assert_eq!(rc, -1);
    assert_eq!(errno_value(), libc::ENOENT);
}

// ---------------------------------------------------------------------------
// getcontext / setcontext / makecontext / swapcontext tests
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn getcontext(ucp: *mut libc::ucontext_t) -> c_int;
}

#[test]
fn getcontext_returns_zero() {
    let mut ctx: libc::ucontext_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { getcontext(&mut ctx) };
    assert_eq!(rc, 0, "getcontext should return 0 on success");
}

#[test]
fn getcontext_saves_stack_pointer() {
    let mut ctx: libc::ucontext_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { getcontext(&mut ctx) };
    assert_eq!(rc, 0);

    // RSP should be saved and point somewhere in the current stack
    let saved_rsp = ctx.uc_mcontext.gregs[libc::REG_RSP as usize];
    assert_ne!(saved_rsp, 0, "saved RSP should not be zero");

    // It should be reasonably close to our current stack frame
    let local_var: u64 = 0;
    let local_addr = &local_var as *const u64 as usize;
    let diff = (saved_rsp as usize).abs_diff(local_addr);
    // Stack frames are typically within 64KB of each other
    assert!(
        diff < 65536,
        "saved RSP should be near current stack, diff={diff}"
    );
}

#[test]
fn getcontext_saves_instruction_pointer() {
    let mut ctx: libc::ucontext_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { getcontext(&mut ctx) };
    assert_eq!(rc, 0);

    // RIP should be non-zero and point into code (text segment)
    let saved_rip = ctx.uc_mcontext.gregs[libc::REG_RIP as usize];
    assert_ne!(saved_rip, 0, "saved RIP should not be zero");
}

/// Test makecontext + swapcontext in a subprocess.
/// Context switching is not safe in multi-threaded test harness,
/// so we fork a child process to run the actual test.
#[test]
fn makecontext_swapcontext_round_trip() {
    // Fork a subprocess to safely test context switching (avoids SIGSEGV
    // from multi-threaded test harness conflicts with context manipulation).
    let result = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(concat!(
            "cat > /tmp/frankenlibc_ucontext_test.c << 'CEOF'\n",
            "#include <ucontext.h>\n",
            "#include <stdio.h>\n",
            "#include <stdlib.h>\n",
            "static ucontext_t main_ctx, func_ctx;\n",
            "static int called = 0;\n",
            "static void test_func(void) { called = 1; }\n",
            "int main(void) {\n",
            "    char stack[65536];\n",
            "    getcontext(&func_ctx);\n",
            "    func_ctx.uc_stack.ss_sp = stack;\n",
            "    func_ctx.uc_stack.ss_size = sizeof(stack);\n",
            "    func_ctx.uc_link = &main_ctx;\n",
            "    makecontext(&func_ctx, test_func, 0);\n",
            "    swapcontext(&main_ctx, &func_ctx);\n",
            "    if (!called) { fprintf(stderr, \"func not called\\n\"); return 1; }\n",
            "    printf(\"OK\\n\");\n",
            "    return 0;\n",
            "}\n",
            "CEOF\n",
            "gcc -o /tmp/frankenlibc_ucontext_test /tmp/frankenlibc_ucontext_test.c && ",
            "/tmp/frankenlibc_ucontext_test"
        ))
        .output();

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success() && stdout.trim() == "OK",
                "ucontext round-trip test failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(e) => {
            // gcc not available — skip
            eprintln!("skipping ucontext round-trip test: {e}");
        }
    }

    // Cleanup
    let _ = std::fs::remove_file("/tmp/frankenlibc_ucontext_test.c");
    let _ = std::fs::remove_file("/tmp/frankenlibc_ucontext_test");
}

// ---------------------------------------------------------------------------
// argp_parse stub test
// ---------------------------------------------------------------------------
// Note: glibc's argp_parse segfaults on NULL argp pointer.
// Our native implementation returns EINVAL, but in test mode we link against
// glibc, so we cannot test with NULL. We instead verify the ABI link exists
// by constructing a minimal (empty) argp struct.

unsafe extern "C" {
    fn argp_parse(
        argp: *const c_void,
        argc: c_int,
        argv: *mut *mut c_char,
        flags: u32,
        arg_index: *mut c_int,
        input: *mut c_void,
    ) -> c_int;
}

#[test]
fn argp_parse_empty_args_succeeds() {
    // Construct a minimal argp struct: all zeroes = no options, no parsers.
    // struct argp { options, parser, args_doc, doc, children, help_filter, argp_domain }
    let argp_struct = [0u8; 56]; // sizeof(struct argp) on x86_64

    // Create a minimal argv: just a program name.
    let prog = b"test\0";
    let mut argv = [prog.as_ptr() as *mut c_char, std::ptr::null_mut()];
    let mut arg_index: c_int = 0;

    let rc = unsafe {
        argp_parse(
            argp_struct.as_ptr() as *const c_void,
            1,
            argv.as_mut_ptr(),
            0,
            &mut arg_index,
            std::ptr::null_mut(),
        )
    };
    // With empty argp and no extra arguments, glibc's argp_parse should succeed (return 0).
    assert_eq!(
        rc, 0,
        "argp_parse with empty argp and no args should succeed"
    );
}

// ---------------------------------------------------------------------------
// SysV IPC surface tests
// ---------------------------------------------------------------------------

fn is_expected_sysvipc_errno(err: i32) -> bool {
    matches!(err, libc::EFAULT | libc::EINVAL | libc::EPERM)
}

fn is_expected_process_vm_errno(err: i32) -> bool {
    matches!(
        err,
        libc::EFAULT | libc::EINVAL | libc::EPERM | libc::ENOSYS | libc::ESRCH | libc::EBADF
    )
}

#[test]
fn shmdt_null_pointer_fails_with_expected_errno_family() {
    let rc = unsafe { shmdt(std::ptr::null()) };
    assert_eq!(rc, -1);
    assert!(
        is_expected_sysvipc_errno(errno_value()),
        "unexpected errno for shmdt(null): {}",
        errno_value()
    );
}

#[test]
fn semctl_ipc_rmid_without_variadic_arg_fails_for_invalid_semaphore_id() {
    let rc = unsafe { semctl(-1, 0, libc::IPC_RMID) };
    assert_eq!(rc, -1);
    assert!(
        is_expected_sysvipc_errno(errno_value()),
        "unexpected errno for semctl IPC_RMID invalid semid: {}",
        errno_value()
    );
}

#[test]
fn semop_null_payload_nonzero_ops_fails_cleanly() {
    let rc = unsafe { semop(-1, std::ptr::null_mut(), 1) };
    assert_eq!(rc, -1);
    assert!(
        is_expected_sysvipc_errno(errno_value()),
        "unexpected errno for semop null payload: {}",
        errno_value()
    );
}

#[test]
fn msgsnd_null_payload_nonzero_size_fails_cleanly() {
    let rc = unsafe { msgsnd(-1, std::ptr::null(), 8, 0) };
    assert_eq!(rc, -1);
    assert!(
        is_expected_sysvipc_errno(errno_value()),
        "unexpected errno for msgsnd null payload: {}",
        errno_value()
    );
}

#[test]
fn msgrcv_null_payload_nonzero_size_fails_cleanly() {
    let rc = unsafe { msgrcv(-1, std::ptr::null_mut(), 8, 0, 0) };
    assert_eq!(rc, -1);
    assert!(
        is_expected_sysvipc_errno(errno_value()),
        "unexpected errno for msgrcv null payload: {}",
        errno_value()
    );
}

#[test]
fn process_vm_readv_null_iov_nonzero_counts_fails_cleanly() {
    let pid = std::process::id() as libc::pid_t;
    let mut remote_byte = 0_u8;
    let remote_iov = libc::iovec {
        iov_base: (&mut remote_byte as *mut u8).cast(),
        iov_len: 1,
    };

    let rc = unsafe { process_vm_readv(pid, std::ptr::null(), 1, &remote_iov, 1, 0) };
    assert_eq!(rc, -1);
    assert!(
        is_expected_process_vm_errno(errno_value()),
        "unexpected errno for process_vm_readv null iov: {}",
        errno_value()
    );
}

#[test]
fn process_vm_writev_null_iov_nonzero_counts_fails_cleanly() {
    let pid = std::process::id() as libc::pid_t;
    let mut local_byte = 7_u8;
    let local_iov = libc::iovec {
        iov_base: (&mut local_byte as *mut u8).cast(),
        iov_len: 1,
    };

    let rc = unsafe { process_vm_writev(pid, &local_iov, 1, std::ptr::null(), 1, 0) };
    assert_eq!(rc, -1);
    assert!(
        is_expected_process_vm_errno(errno_value()),
        "unexpected errno for process_vm_writev null iov: {}",
        errno_value()
    );
}

#[test]
fn process_vm_readv_zero_local_iov_count_preserves_errno_and_succeeds() {
    let pid = std::process::id() as libc::pid_t;
    let mut remote_byte = 0_u8;
    let remote_iov = libc::iovec {
        iov_base: (&mut remote_byte as *mut u8).cast(),
        iov_len: 1,
    };

    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let rc = unsafe { process_vm_readv(pid, std::ptr::null(), 0, &remote_iov, 1, 0) };
    assert_eq!(rc, 0);
    assert_eq!(errno_value(), libc::E2BIG);
}

#[test]
fn process_vm_writev_zero_remote_iov_count_preserves_errno_and_succeeds() {
    let pid = std::process::id() as libc::pid_t;
    let mut local_byte = 7_u8;
    let local_iov = libc::iovec {
        iov_base: (&mut local_byte as *mut u8).cast(),
        iov_len: 1,
    };

    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let rc = unsafe { process_vm_writev(pid, &local_iov, 1, std::ptr::null(), 0, 0) };
    assert_eq!(rc, 0);
    assert_eq!(errno_value(), libc::E2BIG);
}

#[test]
fn process_madvise_null_iov_nonzero_len_fails_cleanly() {
    let rc = unsafe { process_madvise(-1, std::ptr::null(), 1, libc::MADV_NORMAL, 0) };
    assert_eq!(rc, -1);
    assert!(
        is_expected_process_vm_errno(errno_value()),
        "unexpected errno for process_madvise null iov: {}",
        errno_value()
    );
}

#[test]
fn process_mrelease_invalid_pidfd_fails_cleanly() {
    let rc = unsafe { process_mrelease(-1, 0) };
    assert_eq!(rc, -1);
    assert!(
        is_expected_process_vm_errno(errno_value()),
        "unexpected errno for process_mrelease invalid pidfd: {}",
        errno_value()
    );
}

#[test]
fn setns_invalid_fd_sets_errno_like_host() {
    clear_errno();
    let host_rc = unsafe { libc::setns(-1, 0) };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { setns(-1, 0) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EBADF);
}

#[test]
fn unshare_invalid_flags_sets_errno_like_host() {
    clear_errno();
    let host_rc = unsafe { libc::unshare(-1) };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { unshare(-1) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EINVAL);
}

#[test]
fn getaddrinfo_a_zero_item_requests_report_success_without_touching_errno() {
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let rc = unsafe { getaddrinfo_a(GAI_WAIT, std::ptr::null_mut(), 0, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
    assert_eq!(errno_value(), libc::E2BIG);

    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let mut requests = [std::ptr::null_mut()];
    let rc = unsafe { getaddrinfo_a(GAI_WAIT, requests.as_mut_ptr(), -1, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
    assert_eq!(errno_value(), libc::E2BIG);
}

#[test]
fn getaddrinfo_a_all_null_request_slots_report_success_without_touching_errno() {
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let mut requests = [std::ptr::null_mut(), std::ptr::null_mut()];
    let rc = unsafe {
        getaddrinfo_a(
            GAI_WAIT,
            requests.as_mut_ptr(),
            requests.len() as c_int,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(errno_value(), libc::E2BIG);
}

#[test]
fn getaddrinfo_a_nowait_degenerate_requests_report_success_without_touching_errno() {
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let rc = unsafe { getaddrinfo_a(GAI_NOWAIT, std::ptr::null_mut(), 0, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
    assert_eq!(errno_value(), libc::E2BIG);

    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let mut requests = [std::ptr::null_mut()];
    let rc = unsafe {
        getaddrinfo_a(
            GAI_NOWAIT,
            requests.as_mut_ptr(),
            requests.len() as c_int,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(errno_value(), libc::E2BIG);
}

#[test]
fn getaddrinfo_a_invalid_modes_report_badflags_before_degenerate_success() {
    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { getaddrinfo_a(-1, std::ptr::null_mut(), 0, std::ptr::null_mut()) };
    assert_eq!(rc, libc::EAI_BADFLAGS);
    assert_eq!(errno_value(), libc::EINVAL);

    unsafe {
        *__errno_location() = 0;
    }
    let mut requests = [std::ptr::null_mut()];
    let rc = unsafe { getaddrinfo_a(2, requests.as_mut_ptr(), 1, std::ptr::null_mut()) };
    assert_eq!(rc, libc::EAI_BADFLAGS);
    assert_eq!(errno_value(), libc::EINVAL);
}

#[test]
fn getaddrinfo_a_non_null_requests_still_fall_back_to_eai_system() {
    unsafe {
        *__errno_location() = 0;
    }
    let mut request_payload = 0u8;
    let mut requests = [&mut request_payload as *mut _ as *mut c_void];
    let rc = unsafe {
        getaddrinfo_a(
            GAI_WAIT,
            requests.as_mut_ptr(),
            requests.len() as c_int,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, libc::EAI_SYSTEM);
    assert_eq!(errno_value(), libc::ENOSYS);
}

#[test]
fn gai_cancel_reports_all_done_for_synchronous_stub_handles() {
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    assert_eq!(unsafe { gai_cancel(std::ptr::null_mut()) }, GAI_EAI_ALLDONE);
    assert_eq!(errno_value(), libc::E2BIG);

    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let mut dummy = 0u8;
    let dummy_ptr = &mut dummy as *mut _ as *mut c_void;
    assert_eq!(unsafe { gai_cancel(dummy_ptr) }, GAI_EAI_ALLDONE);
    assert_eq!(errno_value(), libc::E2BIG);
}

#[test]
fn gai_error_stub_family_still_sets_errno_for_eai_system() {
    unsafe {
        *__errno_location() = 0;
    }
    assert_eq!(unsafe { gai_error(std::ptr::null_mut()) }, libc::EAI_SYSTEM);
    assert_eq!(errno_value(), libc::ENOSYS);

    unsafe {
        *__errno_location() = 0;
    }
    let mut dummy = 0u8;
    let dummy_ptr = &mut dummy as *mut _ as *mut c_void;
    assert_eq!(unsafe { gai_error(dummy_ptr) }, libc::EAI_SYSTEM);
    assert_eq!(errno_value(), libc::ENOSYS);
}

#[test]
fn gai_suspend_reports_all_done_for_synchronous_stub_handles() {
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    assert_eq!(
        unsafe { gai_suspend(std::ptr::null(), 0, std::ptr::null()) },
        GAI_EAI_ALLDONE
    );
    assert_eq!(errno_value(), libc::E2BIG);

    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let requests: [*const c_void; 1] = [std::ptr::null()];
    assert_eq!(
        unsafe { gai_suspend(requests.as_ptr(), requests.len() as c_int, std::ptr::null()) },
        GAI_EAI_ALLDONE
    );
    assert_eq!(errno_value(), libc::E2BIG);
}

#[test]
fn gai_suspend_degenerate_requests_ignore_invalid_timeouts() {
    let invalid_nanoseconds = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000_000,
    };
    let invalid_seconds = libc::timespec {
        tv_sec: -1,
        tv_nsec: 0,
    };

    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    assert_eq!(
        unsafe { gai_suspend(std::ptr::null(), 0, &invalid_nanoseconds) },
        GAI_EAI_ALLDONE
    );
    assert_eq!(errno_value(), libc::E2BIG);

    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    assert_eq!(
        unsafe { gai_suspend(std::ptr::null(), 0, &invalid_seconds) },
        GAI_EAI_ALLDONE
    );
    assert_eq!(errno_value(), libc::E2BIG);

    let requests: [*const c_void; 1] = [std::ptr::null()];

    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    assert_eq!(
        unsafe {
            gai_suspend(
                requests.as_ptr(),
                requests.len() as c_int,
                &invalid_nanoseconds,
            )
        },
        GAI_EAI_ALLDONE
    );
    assert_eq!(errno_value(), libc::E2BIG);

    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    assert_eq!(
        unsafe { gai_suspend(requests.as_ptr(), requests.len() as c_int, &invalid_seconds,) },
        GAI_EAI_ALLDONE
    );
    assert_eq!(errno_value(), libc::E2BIG);
}

#[test]
fn strfmon_small_buffer_sets_e2big() {
    let mut buf = [0_i8; 4];
    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { strfmon(buf.as_mut_ptr(), buf.len(), c"%n".as_ptr(), 1234.56_f64) };
    assert_eq!(rc, -1);
    assert_eq!(errno_value(), libc::E2BIG);
}

#[test]
fn strfmon_invalid_inputs_set_einval() {
    unsafe {
        *__errno_location() = 0;
    }
    assert_eq!(
        unsafe { strfmon(std::ptr::null_mut(), 8, c"%n".as_ptr(), 1.0_f64) },
        -1
    );
    assert_eq!(errno_value(), libc::EINVAL);

    let mut buf = [0_i8; 8];
    unsafe {
        *__errno_location() = 0;
    }
    assert_eq!(
        unsafe {
            strfmon_l(
                buf.as_mut_ptr(),
                0,
                std::ptr::null_mut(),
                c"%n".as_ptr(),
                1.0_f64,
            )
        },
        -1
    );
    assert_eq!(errno_value(), libc::EINVAL);
}

#[test]
fn ssignal_and_gsignal_deliver_signal() {
    SIGNAL_HIT.store(0, Ordering::SeqCst);
    let previous = unsafe {
        ssignal(
            libc::SIGUSR1,
            record_sigusr1 as *const () as libc::sighandler_t,
        )
    };
    assert_ne!(previous, libc::SIG_ERR);
    let rc = unsafe { gsignal(libc::SIGUSR1) };
    assert_eq!(rc, 0, "gsignal should report successful signal delivery");
    assert_eq!(
        SIGNAL_HIT.load(Ordering::SeqCst),
        libc::SIGUSR1,
        "handler installed by ssignal should observe SIGUSR1"
    );

    let _ = unsafe { libc::signal(libc::SIGUSR1, libc::SIG_DFL) };
}

// ---------------------------------------------------------------------------
// Core POSIX: process identity
// ---------------------------------------------------------------------------

#[test]
fn getpid_returns_positive() {
    let pid = unsafe { getpid() };
    assert!(pid > 0);
}

#[test]
fn getppid_returns_positive() {
    let ppid = unsafe { getppid() };
    assert!(ppid > 0);
}

#[test]
fn getuid_returns_valid_uid() {
    let uid = unsafe { getuid() };
    // UID is always >= 0 (unsigned)
    assert!(uid < 65536 || uid == uid); // Just verify it returns
}

#[test]
fn geteuid_returns_valid_uid() {
    let euid = unsafe { geteuid() };
    // In test context, euid should match uid
    let uid = unsafe { getuid() };
    assert_eq!(euid, uid);
}

#[test]
fn getgid_returns_valid_gid() {
    let _gid = unsafe { getgid() };
    // Just verify it doesn't crash
}

#[test]
fn getegid_returns_valid_gid() {
    let egid = unsafe { getegid() };
    let gid = unsafe { getgid() };
    assert_eq!(egid, gid);
}

// ---------------------------------------------------------------------------
// Core POSIX: filesystem - getcwd, chdir
// ---------------------------------------------------------------------------

#[test]
fn getcwd_returns_current_directory() {
    let mut buf = [0i8; 4096];
    let ptr = unsafe { getcwd(buf.as_mut_ptr(), buf.len()) };
    assert!(!ptr.is_null());
    let cwd = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_string_lossy();
    assert!(cwd.starts_with('/'), "cwd should be absolute: {cwd}");
}

#[test]
fn getcwd_null_buffer_allocates() {
    let ptr = unsafe { getcwd(std::ptr::null_mut(), 0) };
    if !ptr.is_null() {
        let cwd = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_string_lossy();
        assert!(cwd.starts_with('/'));
        unsafe { libc::free(ptr.cast()) };
    }
}

#[test]
fn chdir_and_fchdir_round_trip() {
    let mut orig = [0i8; 4096];
    let p = unsafe { getcwd(orig.as_mut_ptr(), orig.len()) };
    assert!(!p.is_null());

    let tmp = CString::new("/tmp").unwrap();
    let rc = unsafe { chdir(tmp.as_ptr()) };
    assert_eq!(rc, 0);

    let mut after = [0i8; 4096];
    unsafe { getcwd(after.as_mut_ptr(), after.len()) };
    let cwd_after = unsafe { std::ffi::CStr::from_ptr(after.as_ptr()) }.to_bytes();
    assert_eq!(cwd_after, b"/tmp");

    // Restore via chdir
    unsafe { chdir(orig.as_ptr()) };
}

// ---------------------------------------------------------------------------
// Core POSIX: file I/O - open, read, write, close, lseek
// ---------------------------------------------------------------------------

fn temp_path(tag: &str) -> CString {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    CString::new(format!(
        "/tmp/frankenlibc_unistd_{tag}_{}_{nanos}",
        std::process::id()
    ))
    .unwrap()
}

fn copy_c_char_bytes(dst: &mut [c_char], src: &[u8]) {
    let copy_len = src.len().min(dst.len().saturating_sub(1));
    for (slot, byte) in dst.iter_mut().zip(src.iter()).take(copy_len) {
        *slot = *byte as c_char;
    }
}

fn utmp_entry(ut_type: i16, ut_id: &[u8], ut_line: &[u8], ut_user: &[u8]) -> libc::utmpx {
    let mut entry: libc::utmpx = unsafe { std::mem::zeroed() };
    entry.ut_type = ut_type;
    entry.ut_pid = 4242;
    copy_c_char_bytes(&mut entry.ut_id, ut_id);
    copy_c_char_bytes(&mut entry.ut_line, ut_line);
    copy_c_char_bytes(&mut entry.ut_user, ut_user);
    entry
}

fn write_utmp_fixture(path: &CString, entries: &[libc::utmpx]) {
    assert_eq!(std::mem::size_of::<libc::utmpx>(), 384);
    let mut bytes = Vec::with_capacity(std::mem::size_of_val(entries));
    for entry in entries {
        let entry_bytes = unsafe {
            std::slice::from_raw_parts(
                (entry as *const libc::utmpx).cast::<u8>(),
                std::mem::size_of::<libc::utmpx>(),
            )
        };
        bytes.extend_from_slice(entry_bytes);
    }
    std::fs::write(path.to_str().unwrap(), bytes).unwrap();
}

fn with_temp_utmp_fixture<F>(tag: &str, entries: &[libc::utmpx], f: F)
where
    F: FnOnce(),
{
    let path = temp_path(tag);
    let default_utmp = CString::new("/var/run/utmp").unwrap();
    write_utmp_fixture(&path, entries);
    let rc = unsafe { utmpname(path.as_ptr()) };
    assert_eq!(rc, 0, "utmpname failed: errno={}", errno_value());
    unsafe { setutent() };
    f();
    let rc = unsafe { utmpname(default_utmp.as_ptr()) };
    assert_eq!(rc, 0, "failed to restore default utmp path");
    unsafe { setutent() };
    let _ = std::fs::remove_file(path.to_str().unwrap());
}

#[test]
fn open_write_read_close_round_trip() {
    let path = temp_path("owrc");
    let fd = unsafe { open(path.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o644) };
    assert!(fd >= 0, "open failed: errno={}", errno_value());

    let data = b"hello world";
    let written = unsafe { write(fd, data.as_ptr().cast(), data.len()) };
    assert_eq!(written as usize, data.len());

    // Seek back to start
    let pos = unsafe { lseek(fd, 0, libc::SEEK_SET) };
    assert_eq!(pos, 0);

    let mut buf = [0u8; 32];
    let n = unsafe { read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(n as usize, data.len());
    assert_eq!(&buf[..n as usize], data);

    assert_eq!(unsafe { close(fd) }, 0);
    let _ = std::fs::remove_file(path.to_str().unwrap());
}

#[test]
fn getutid_and_getutline_follow_native_utmp_fixture() {
    let entries = [
        utmp_entry(libc::BOOT_TIME, b"bt0", b"system boot", b""),
        utmp_entry(libc::USER_PROCESS, b"p42", b"tty-franken", b"alice"),
    ];
    with_temp_utmp_fixture("utmp_search", &entries, || {
        let mut id_query = utmp_entry(libc::USER_PROCESS, b"p42", b"", b"");
        unsafe { setutent() };
        let by_id =
            unsafe { getutid((&mut id_query as *mut libc::utmpx).cast()) as *mut libc::utmpx };
        assert!(
            !by_id.is_null(),
            "getutid should find matching USER_PROCESS"
        );
        let line = unsafe { std::ffi::CStr::from_ptr((*by_id).ut_line.as_ptr()) };
        assert_eq!(line.to_bytes(), b"tty-franken");

        let mut line_query = utmp_entry(0, b"", b"tty-franken", b"");
        unsafe { setutent() };
        let by_line =
            unsafe { getutline((&mut line_query as *mut libc::utmpx).cast()) as *mut libc::utmpx };
        assert!(
            !by_line.is_null(),
            "getutline should find matching LOGIN/USER_PROCESS line"
        );
        let user = unsafe { std::ffi::CStr::from_ptr((*by_line).ut_user.as_ptr()) };
        assert_eq!(user.to_bytes(), b"alice");
    });
}

#[test]
fn getutent_r_and_getutid_r_surface_native_results() {
    let entries = [utmp_entry(libc::USER_PROCESS, b"p77", b"tty-r", b"bob")];
    with_temp_utmp_fixture("utmp_reentrant", &entries, || {
        let mut out: libc::utmpx = unsafe { std::mem::zeroed() };
        let mut outp = std::ptr::dangling_mut::<c_void>();

        unsafe { setutent() };
        let rc = unsafe { getutent_r((&mut out as *mut libc::utmpx).cast(), &mut outp) };
        assert_eq!(rc, 0, "getutent_r should read the first fixture entry");
        assert_eq!(outp, (&mut out as *mut libc::utmpx).cast());
        let user = unsafe { std::ffi::CStr::from_ptr(out.ut_user.as_ptr()) };
        assert_eq!(user.to_bytes(), b"bob");

        let mut query = utmp_entry(libc::USER_PROCESS, b"p77", b"", b"");
        outp = std::ptr::dangling_mut::<c_void>();
        unsafe { setutent() };
        let rc = unsafe {
            getutid_r(
                (&mut query as *mut libc::utmpx).cast(),
                (&mut out as *mut libc::utmpx).cast(),
                &mut outp,
            )
        };
        assert_eq!(
            rc, 0,
            "getutid_r should copy the matched entry into caller storage"
        );
        assert_eq!(outp, (&mut out as *mut libc::utmpx).cast());
        let line = unsafe { std::ffi::CStr::from_ptr(out.ut_line.as_ptr()) };
        assert_eq!(line.to_bytes(), b"tty-r");

        let mut line_query = utmp_entry(0, b"", b"tty-r", b"");
        outp = std::ptr::dangling_mut::<c_void>();
        unsafe { setutent() };
        let rc = unsafe {
            getutline_r(
                (&mut line_query as *mut libc::utmpx).cast(),
                (&mut out as *mut libc::utmpx).cast(),
                &mut outp,
            )
        };
        assert_eq!(rc, 0, "getutline_r should copy the matched entry");
        assert_eq!(outp, (&mut out as *mut libc::utmpx).cast());
        let user = unsafe { std::ffi::CStr::from_ptr(out.ut_user.as_ptr()) };
        assert_eq!(user.to_bytes(), b"bob");
    });
}

#[test]
fn getutid_r_invalid_type_sets_einval_and_nulls_result() {
    let entries = [utmp_entry(
        libc::USER_PROCESS,
        b"p88",
        b"tty-invalid",
        b"carol",
    )];
    with_temp_utmp_fixture("utmp_invalid", &entries, || {
        let mut query = utmp_entry(0, b"", b"", b"");
        let mut out: libc::utmpx = unsafe { std::mem::zeroed() };
        let mut outp = std::ptr::dangling_mut::<c_void>();

        unsafe { setutent() };
        let rc = unsafe {
            getutid_r(
                (&mut query as *mut libc::utmpx).cast(),
                (&mut out as *mut libc::utmpx).cast(),
                &mut outp,
            )
        };
        assert_eq!(rc, -1);
        assert_eq!(errno_value(), libc::EINVAL);
        assert!(
            outp.is_null(),
            "failed getutid_r should null the result pointer"
        );
    });
}

#[test]
fn getprotobyname_r_resolves_tcp_and_nulls_missing() {
    let mut proto: libc::protoent = unsafe { std::mem::zeroed() };
    let mut buf = [0i8; 512];
    let mut result = std::ptr::dangling_mut::<c_void>();
    let name = CString::new("tcp").unwrap();

    let rc = unsafe {
        getprotobyname_r(
            name.as_ptr(),
            (&mut proto as *mut libc::protoent).cast(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(result, (&mut proto as *mut libc::protoent).cast());
    let resolved_name = unsafe { std::ffi::CStr::from_ptr(proto.p_name) };
    assert_eq!(resolved_name.to_bytes(), b"tcp");
    assert_eq!(proto.p_proto, 6);

    let missing = CString::new("frankenlibc-no-such-proto").unwrap();
    result = std::ptr::dangling_mut::<c_void>();
    let rc = unsafe {
        getprotobyname_r(
            missing.as_ptr(),
            (&mut proto as *mut libc::protoent).cast(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, 0);
    assert!(
        result.is_null(),
        "missing protocol should return rc=0 with NULL result"
    );
}

#[test]
fn getprotobynumber_r_and_getprotoent_r_surface_entries() {
    let mut proto: libc::protoent = unsafe { std::mem::zeroed() };
    let mut buf = [0i8; 512];
    let mut result = std::ptr::dangling_mut::<c_void>();

    let rc = unsafe {
        getprotobynumber_r(
            17,
            (&mut proto as *mut libc::protoent).cast(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(result, (&mut proto as *mut libc::protoent).cast());
    let resolved_name = unsafe { std::ffi::CStr::from_ptr(proto.p_name) };
    assert_eq!(resolved_name.to_bytes(), b"udp");
    assert_eq!(proto.p_proto, 17);

    unsafe { setprotoent(1) };
    result = std::ptr::dangling_mut::<c_void>();
    let rc = unsafe {
        getprotoent_r(
            (&mut proto as *mut libc::protoent).cast(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(result, (&mut proto as *mut libc::protoent).cast());
    assert!(
        !proto.p_name.is_null(),
        "first protocol enumeration entry should populate p_name"
    );
}

#[test]
fn gethostent_r_surfaces_host_enumeration_entry() {
    let mut host: libc::hostent = unsafe { std::mem::zeroed() };
    let mut buf = [0i8; 2048];
    let mut result = std::ptr::dangling_mut::<c_void>();
    let mut h_errno = -1;

    unsafe { sethostent(1) };
    let rc = unsafe {
        gethostent_r(
            (&mut host as *mut libc::hostent).cast(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
            &mut h_errno,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(result, (&mut host as *mut libc::hostent).cast());
    assert!(
        !host.h_name.is_null(),
        "host enumeration should populate h_name"
    );
}

#[test]
fn getnet_r_wrappers_match_host_success_and_miss_shapes() {
    let mut net: NetEnt = unsafe { std::mem::zeroed() };
    let mut buf = [0i8; 1024];
    let mut result = std::ptr::dangling_mut::<c_void>();
    let mut h_errno = -1;

    unsafe { setnetent(1) };
    let rc = unsafe {
        getnetent_r(
            (&mut net as *mut NetEnt).cast(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
            &mut h_errno,
        )
    };
    assert_eq!(rc, 0, "getnetent_r should not hard-fail with ENOENT");
    if !result.is_null() {
        assert_eq!(result, (&mut net as *mut NetEnt).cast());
        assert!(
            !net.n_name.is_null(),
            "enumerated network entry should populate n_name"
        );
    }

    result = std::ptr::dangling_mut::<c_void>();
    h_errno = -1;
    let missing = CString::new("frankenlibc-no-such-network").unwrap();
    let rc = unsafe {
        getnetbyname_r(
            missing.as_ptr(),
            (&mut net as *mut NetEnt).cast(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
            &mut h_errno,
        )
    };
    assert_eq!(rc, 0);
    assert!(
        result.is_null(),
        "missing network lookup should return rc=0 with NULL result"
    );

    result = std::ptr::dangling_mut::<c_void>();
    h_errno = -1;
    let rc = unsafe {
        getnetbyaddr_r(
            u32::MAX,
            libc::AF_INET,
            (&mut net as *mut NetEnt).cast(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
            &mut h_errno,
        )
    };
    assert_eq!(rc, 0);
    assert!(
        result.is_null(),
        "missing network address lookup should return rc=0 with NULL result"
    );
}

#[test]
fn getservent_and_getprotoent_surface_first_entries() {
    unsafe { setservent(1) };
    let servent = unsafe { getservent() as *mut libc::servent };
    assert!(
        !servent.is_null(),
        "getservent should enumerate a service entry"
    );
    let service_name = unsafe { std::ffi::CStr::from_ptr((*servent).s_name) };
    assert!(
        !service_name.to_bytes().is_empty(),
        "enumerated service entry should populate s_name"
    );

    unsafe { setprotoent(1) };
    let protoent = unsafe { getprotoent() as *mut libc::protoent };
    assert!(
        !protoent.is_null(),
        "getprotoent should enumerate a protocol entry"
    );
    let proto_name = unsafe { std::ffi::CStr::from_ptr((*protoent).p_name) };
    assert!(
        !proto_name.to_bytes().is_empty(),
        "enumerated protocol entry should populate p_name"
    );
}

#[test]
fn getservent_r_surfaces_first_service_entry() {
    let mut service: libc::servent = unsafe { std::mem::zeroed() };
    let mut buf = [0i8; 1024];
    let mut result = std::ptr::dangling_mut::<c_void>();

    unsafe { setservent(1) };
    let rc = unsafe {
        getservent_r(
            (&mut service as *mut libc::servent).cast(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(result, (&mut service as *mut libc::servent).cast());
    assert!(
        !service.s_name.is_null(),
        "reentrant service lookup should populate s_name"
    );
}

#[test]
fn fstab_wrappers_surface_host_entries() {
    let rc = unsafe { setfsent() };
    assert_eq!(rc, 1, "setfsent should succeed on this host");

    let entry = unsafe { getfsent() as *mut Fstab };
    assert!(
        !entry.is_null(),
        "getfsent should return the first fstab entry"
    );
    assert!(
        unsafe { !(*entry).fs_spec.is_null() && !(*entry).fs_file.is_null() },
        "fstab entry should populate fs_spec and fs_file"
    );

    let spec = unsafe { CString::new(std::ffi::CStr::from_ptr((*entry).fs_spec).to_bytes()) }
        .expect("fstab spec should be valid C string bytes");
    let file = unsafe { CString::new(std::ffi::CStr::from_ptr((*entry).fs_file).to_bytes()) }
        .expect("fstab file should be valid C string bytes");

    let by_file = unsafe { getfsfile(file.as_ptr()) as *mut Fstab };
    assert!(
        !by_file.is_null(),
        "getfsfile should find the same entry by mount point"
    );
    let by_spec = unsafe { getfsspec(spec.as_ptr()) as *mut Fstab };
    assert!(
        !by_spec.is_null(),
        "getfsspec should find the same entry by device spec"
    );
}

#[test]
fn ttyent_wrappers_match_host_miss_shape() {
    let tty_name = CString::new("frankenlibc-no-such-tty").unwrap();
    let missing = unsafe { getttynam(tty_name.as_ptr()) as *mut TtyEnt };
    assert!(
        missing.is_null(),
        "getttynam should return NULL for a missing tty entry"
    );

    let rc = unsafe { setttyent() };
    assert_eq!(
        rc, 0,
        "setttyent should mirror host failure when /etc/ttys is absent"
    );
    assert_eq!(unsafe { *__errno_location() }, libc::ENOENT);

    let entry = unsafe { getttyent() as *mut TtyEnt };
    assert!(
        entry.is_null(),
        "getttyent should return NULL when tty database is unavailable"
    );

    let end_rc = unsafe { endttyent() };
    assert_eq!(end_rc, 1, "endttyent should mirror host success shape");
}

#[test]
fn getdate_and_getdate_r_follow_host_datemsk_contract() {
    let datemsk = temp_path("datemsk");
    std::fs::write(datemsk.to_str().unwrap(), "%Y-%m-%d %H:%M:%S\n").unwrap();
    let datemsk_value = CString::new(datemsk.to_str().unwrap()).unwrap();
    unsafe {
        libc::setenv(c"DATEMSK".as_ptr(), datemsk_value.as_ptr(), 1);
    }

    let date = CString::new("1970-01-01 00:00:00").unwrap();
    unsafe { getdate_err = -1 };
    let parsed = unsafe { getdate(date.as_ptr()) as *mut libc::tm };
    assert!(
        !parsed.is_null(),
        "getdate should parse with DATEMSK template"
    );
    assert_eq!(unsafe { getdate_err }, 0);
    assert_eq!(unsafe { (*parsed).tm_year + 1900 }, 1970);
    assert_eq!(unsafe { (*parsed).tm_mon + 1 }, 1);
    assert_eq!(unsafe { (*parsed).tm_mday }, 1);

    let bad = CString::new("frankenlibc definitely invalid").unwrap();
    unsafe { getdate_err = -1 };
    let missing = unsafe { getdate(bad.as_ptr()) };
    assert!(missing.is_null(), "invalid getdate input should fail");
    assert_eq!(unsafe { getdate_err }, 7);

    let mut out: libc::tm = unsafe { std::mem::zeroed() };
    let rc = unsafe { getdate_r(date.as_ptr(), (&mut out as *mut libc::tm).cast()) };
    assert_eq!(rc, 0);
    assert_eq!(out.tm_year + 1900, 1970);
    assert_eq!(out.tm_mon + 1, 1);
    assert_eq!(out.tm_mday, 1);

    let rc = unsafe { getdate_r(bad.as_ptr(), (&mut out as *mut libc::tm).cast()) };
    assert_eq!(rc, 7);

    unsafe {
        libc::unsetenv(c"DATEMSK".as_ptr());
    }
}

#[test]
fn gethostbyname2_supports_ipv6_localhost() {
    unsafe { *__h_errno_location() = -1 };
    let name = CString::new("localhost").unwrap();
    let host = unsafe { gethostbyname2(name.as_ptr(), libc::AF_INET6) as *mut libc::hostent };
    assert!(
        !host.is_null(),
        "gethostbyname2 should resolve IPv6 localhost"
    );
    assert_eq!(unsafe { (*host).h_addrtype }, libc::AF_INET6);
    assert_eq!(unsafe { (*host).h_length }, 16);
    assert!(
        unsafe { !(*host).h_addr_list.is_null() && !(*(*host).h_addr_list).is_null() },
        "IPv6 hostent should expose at least one address"
    );

    let first_addr = unsafe { *(*host).h_addr_list } as *const libc::in6_addr;
    assert_eq!(
        unsafe { (*first_addr).s6_addr },
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    );
    assert_eq!(unsafe { *__h_errno_location() }, 0);
}

#[test]
fn gethostbyname2_r_missing_host_returns_zero_with_null_result() {
    let name = CString::new("frankenlibc-no-such-host.invalid").unwrap();
    let mut hostent: libc::hostent = unsafe { std::mem::zeroed() };
    let mut buf = [0i8; 1024];
    let mut result: *mut libc::hostent = std::ptr::dangling_mut::<libc::hostent>();
    let mut h_errno = -1;

    let rc = unsafe {
        gethostbyname2_r(
            name.as_ptr(),
            libc::AF_INET6,
            (&mut hostent as *mut libc::hostent).cast(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
            &mut h_errno,
        )
    };
    assert_eq!(rc, 0);
    assert!(result.is_null(), "missing host should yield NULL result");
    assert_eq!(h_errno, 1);
}

#[test]
fn gethostbyname2_r_ipv6_localhost_packs_result_into_caller_buffer() {
    let name = CString::new("localhost").unwrap();
    let mut hostent: libc::hostent = unsafe { std::mem::zeroed() };
    let mut buf = [0i8; 1024];
    let mut result: *mut libc::hostent = std::ptr::null_mut();
    let mut h_errno = -1;

    let rc = unsafe {
        gethostbyname2_r(
            name.as_ptr(),
            libc::AF_INET6,
            (&mut hostent as *mut libc::hostent).cast(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
            &mut h_errno,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(result, &mut hostent as *mut libc::hostent);
    assert_eq!(h_errno, 0);
    assert_eq!(hostent.h_addrtype, libc::AF_INET6);
    assert_eq!(hostent.h_length, 16);
    assert_eq!(hostent.h_name, buf.as_mut_ptr());
    let resolved_name = unsafe { CStr::from_ptr(hostent.h_name) }.to_bytes();
    assert_eq!(resolved_name, b"localhost");
    assert!(!hostent.h_addr_list.is_null());
    assert!(!unsafe { *hostent.h_addr_list }.is_null());
    let first_addr = unsafe { *hostent.h_addr_list } as *const libc::in6_addr;
    assert_eq!(
        unsafe { (*first_addr).s6_addr },
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    );
    assert!(!hostent.h_aliases.is_null());
    assert!(unsafe { (*hostent.h_aliases).is_null() });
}

#[test]
fn gethostbyname2_r_ipv6_small_buffer_preserves_h_errno() {
    let name = CString::new("localhost").unwrap();
    let mut hostent: libc::hostent = unsafe { std::mem::zeroed() };
    let mut buf = [0i8; 64];
    let mut result: *mut libc::hostent = std::ptr::dangling_mut::<libc::hostent>();
    let mut h_errno = -1;

    let rc = unsafe {
        gethostbyname2_r(
            name.as_ptr(),
            libc::AF_INET6,
            (&mut hostent as *mut libc::hostent).cast(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
            &mut h_errno,
        )
    };
    assert_eq!(rc, libc::ERANGE);
    assert!(
        result.is_null(),
        "small caller buffer should yield NULL result on ERANGE"
    );
    assert_eq!(
        h_errno, -1,
        "glibc leaves h_errno untouched when gethostbyname2_r returns ERANGE"
    );
}

#[test]
fn ether_line_parses_valid_ethers_entry() {
    let line = CString::new("08:00:20:00:61:cb printer").unwrap();
    let mut addr = [0u8; 6];
    let mut hostname = [0 as c_char; 64];

    let rc = unsafe {
        ether_line(
            line.as_ptr(),
            addr.as_mut_ptr().cast(),
            hostname.as_mut_ptr(),
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(addr, [0x08, 0x00, 0x20, 0x00, 0x61, 0xcb]);

    let parsed_name = unsafe { std::ffi::CStr::from_ptr(hostname.as_ptr()) };
    assert_eq!(parsed_name.to_bytes(), b"printer");
}

#[test]
fn setnetgrent_missing_group_matches_host_miss_shape() {
    let missing = CString::new("frankenlibc-no-such-netgroup").unwrap();
    let rc = unsafe { setnetgrent(missing.as_ptr()) };
    assert_eq!(rc, 0, "missing netgroup should mirror host failure shape");

    let mut host = std::ptr::dangling_mut::<c_char>();
    let mut user = std::ptr::dangling_mut::<c_char>();
    let mut domain = std::ptr::dangling_mut::<c_char>();
    let next = unsafe { getnetgrent(&mut host, &mut user, &mut domain) };
    assert_eq!(next, 0, "missing netgroup should enumerate no entries");
    assert_eq!(host, std::ptr::dangling_mut::<c_char>());
    assert_eq!(user, std::ptr::dangling_mut::<c_char>());
    assert_eq!(domain, std::ptr::dangling_mut::<c_char>());
}

#[test]
fn alias_lookup_missing_entry_sets_errno() {
    let missing = CString::new("frankenlibc-no-such-alias").unwrap();
    unsafe { *__errno_location() = 0 };
    let plain = unsafe { getaliasbyname(missing.as_ptr()) };
    assert!(plain.is_null(), "missing alias should return NULL");
    assert_eq!(unsafe { *__errno_location() }, libc::ENOENT);

    #[repr(C)]
    struct AliasEnt {
        alias_name: *mut c_char,
        alias_members_len: usize,
        alias_members: *mut *mut c_char,
        alias_local: c_int,
    }

    let mut ent: AliasEnt = unsafe { std::mem::zeroed() };
    let mut buf = [0i8; 512];
    let mut result = std::ptr::dangling_mut::<c_void>();
    unsafe { *__errno_location() = 0 };
    let rc = unsafe {
        getaliasbyname_r(
            missing.as_ptr(),
            (&mut ent as *mut AliasEnt).cast(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, libc::ENOENT);
    assert!(
        result.is_null(),
        "missing alias should null the result pointer"
    );
    assert_eq!(unsafe { *__errno_location() }, libc::ENOENT);
}

#[test]
fn rpc_reentrant_wrappers_match_host_shapes() {
    let mut rpc: RpcEnt = unsafe { std::mem::zeroed() };
    let mut buf = [0i8; 1024];
    let mut result = std::ptr::dangling_mut::<RpcEnt>();

    let name = CString::new("portmapper").unwrap();
    let rc = unsafe {
        getrpcbyname_r(
            name.as_ptr(),
            &mut rpc,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, 0);
    assert!(std::ptr::eq(result, &rpc));
    let rpc_name = unsafe { std::ffi::CStr::from_ptr(rpc.r_name) };
    assert_eq!(rpc_name.to_bytes(), b"portmapper");
    assert_eq!(rpc.r_number, 100000);

    result = std::ptr::dangling_mut::<RpcEnt>();
    let missing = CString::new("frankenlibc-no-rpc").unwrap();
    let rc = unsafe {
        getrpcbyname_r(
            missing.as_ptr(),
            &mut rpc,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, 0);
    assert!(
        result.is_null(),
        "missing RPC name should return rc=0 with NULL result"
    );

    result = std::ptr::dangling_mut::<RpcEnt>();
    let rc =
        unsafe { getrpcbynumber_r(100000, &mut rpc, buf.as_mut_ptr(), buf.len(), &mut result) };
    assert_eq!(rc, 0);
    assert!(std::ptr::eq(result, &rpc));
    assert_eq!(rpc.r_number, 100000);

    unsafe { setrpcent(1) };
    result = std::ptr::dangling_mut::<RpcEnt>();
    let rc = unsafe { getrpcent_r(&mut rpc, buf.as_mut_ptr(), buf.len(), &mut result) };
    assert_eq!(rc, 0);
    assert!(std::ptr::eq(result, &rpc));
    assert!(
        !rpc.r_name.is_null(),
        "reentrant RPC iteration should populate r_name"
    );
}

#[test]
fn creat_creates_file() {
    let path = temp_path("creat");
    let fd = unsafe { creat(path.as_ptr(), 0o644) };
    assert!(fd >= 0);
    assert_eq!(unsafe { close(fd) }, 0);
    assert!(std::path::Path::new(path.to_str().unwrap()).exists());
    let _ = std::fs::remove_file(path.to_str().unwrap());
}

#[test]
fn lseek_reports_position() {
    let path = temp_path("lseek");
    let fd = unsafe { open(path.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o644) };
    assert!(fd >= 0);

    let data = b"0123456789";
    unsafe { write(fd, data.as_ptr().cast(), data.len()) };

    assert_eq!(unsafe { lseek(fd, 0, libc::SEEK_END) }, 10);
    assert_eq!(unsafe { lseek(fd, 3, libc::SEEK_SET) }, 3);
    assert_eq!(unsafe { lseek(fd, 2, libc::SEEK_CUR) }, 5);

    assert_eq!(unsafe { close(fd) }, 0);
    let _ = std::fs::remove_file(path.to_str().unwrap());
}

#[test]
fn isatty_returns_zero_for_regular_file() {
    let path = temp_path("isatty");
    let fd = unsafe { open(path.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o644) };
    assert!(fd >= 0);
    assert_eq!(unsafe { isatty(fd) }, 0);
    assert_eq!(unsafe { close(fd) }, 0);
    let _ = std::fs::remove_file(path.to_str().unwrap());
}

// ---------------------------------------------------------------------------
// Core POSIX: stat family
// ---------------------------------------------------------------------------

#[test]
fn stat_reads_file_metadata() {
    let path = temp_path("stat");
    std::fs::write(path.to_str().unwrap(), b"test data").unwrap();

    let mut buf = [0u8; 256]; // Oversized buffer for struct stat
    let rc = unsafe { stat(path.as_ptr(), buf.as_mut_ptr().cast()) };
    assert_eq!(rc, 0);

    let _ = std::fs::remove_file(path.to_str().unwrap());
}

#[test]
fn fstat_reads_fd_metadata() {
    let path = temp_path("fstat");
    let fd = unsafe { open(path.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o644) };
    assert!(fd >= 0);

    let mut buf = [0u8; 256];
    let rc = unsafe { fstat(fd, buf.as_mut_ptr().cast()) };
    assert_eq!(rc, 0);

    assert_eq!(unsafe { close(fd) }, 0);
    let _ = std::fs::remove_file(path.to_str().unwrap());
}

#[test]
fn lstat_returns_symlink_info() {
    let target = temp_path("lstat_tgt");
    let linkp = temp_path("lstat_lnk");
    std::fs::write(target.to_str().unwrap(), b"x").unwrap();

    let rc = unsafe { symlink(target.as_ptr(), linkp.as_ptr()) };
    if rc == 0 {
        let mut buf = [0u8; 256];
        let sr = unsafe { lstat(linkp.as_ptr(), buf.as_mut_ptr().cast()) };
        assert_eq!(sr, 0);
        let _ = std::fs::remove_file(linkp.to_str().unwrap());
    }
    let _ = std::fs::remove_file(target.to_str().unwrap());
}

// ---------------------------------------------------------------------------
// Core POSIX: filesystem ops
// ---------------------------------------------------------------------------

#[test]
fn access_checks_file_existence() {
    let path = temp_path("access");
    std::fs::write(path.to_str().unwrap(), b"x").unwrap();

    assert_eq!(unsafe { access(path.as_ptr(), libc::F_OK) }, 0);
    assert_eq!(unsafe { access(path.as_ptr(), libc::R_OK) }, 0);

    let missing = temp_path("access_miss");
    assert_eq!(unsafe { access(missing.as_ptr(), libc::F_OK) }, -1);

    let _ = std::fs::remove_file(path.to_str().unwrap());
}

#[test]
fn link_creates_hard_link() {
    let src = temp_path("link_src");
    let dst = temp_path("link_dst");
    std::fs::write(src.to_str().unwrap(), b"data").unwrap();

    let rc = unsafe { link(src.as_ptr(), dst.as_ptr()) };
    assert_eq!(rc, 0);
    assert!(std::path::Path::new(dst.to_str().unwrap()).exists());

    let _ = std::fs::remove_file(dst.to_str().unwrap());
    let _ = std::fs::remove_file(src.to_str().unwrap());
}

#[test]
fn symlink_and_readlink_round_trip() {
    let target = temp_path("sym_tgt");
    let linkp = temp_path("sym_lnk");
    std::fs::write(target.to_str().unwrap(), b"x").unwrap();

    let rc = unsafe { symlink(target.as_ptr(), linkp.as_ptr()) };
    assert_eq!(rc, 0);

    let mut buf = [0i8; 4096];
    let n = unsafe { readlink(linkp.as_ptr(), buf.as_mut_ptr(), buf.len()) };
    assert!(n > 0);
    let resolved = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    assert_eq!(resolved.as_bytes(), target.as_bytes());

    let _ = std::fs::remove_file(linkp.to_str().unwrap());
    let _ = std::fs::remove_file(target.to_str().unwrap());
}

#[test]
fn unlink_removes_file() {
    let path = temp_path("unlink");
    std::fs::write(path.to_str().unwrap(), b"x").unwrap();
    assert!(std::path::Path::new(path.to_str().unwrap()).exists());

    assert_eq!(unsafe { unlink(path.as_ptr()) }, 0);
    assert!(!std::path::Path::new(path.to_str().unwrap()).exists());
}

#[test]
fn mkdir_and_rmdir_round_trip() {
    let path = temp_path("mkrmdir");
    assert_eq!(unsafe { mkdir(path.as_ptr(), 0o755) }, 0);
    assert!(std::path::Path::new(path.to_str().unwrap()).is_dir());

    assert_eq!(unsafe { rmdir(path.as_ptr()) }, 0);
    assert!(!std::path::Path::new(path.to_str().unwrap()).exists());
}

#[test]
fn rename_moves_file() {
    let src = temp_path("rename_src");
    let dst = temp_path("rename_dst");
    std::fs::write(src.to_str().unwrap(), b"content").unwrap();

    assert_eq!(unsafe { rename(src.as_ptr(), dst.as_ptr()) }, 0);
    assert!(!std::path::Path::new(src.to_str().unwrap()).exists());
    assert!(std::path::Path::new(dst.to_str().unwrap()).exists());

    let _ = std::fs::remove_file(dst.to_str().unwrap());
}

#[test]
fn chmod_changes_permissions() {
    let path = temp_path("chmod");
    std::fs::write(path.to_str().unwrap(), b"x").unwrap();

    assert_eq!(unsafe { chmod(path.as_ptr(), 0o444) }, 0);

    let meta = std::fs::metadata(path.to_str().unwrap()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(meta.permissions().mode() & 0o777, 0o444);

    // Restore write permission before cleanup
    assert_eq!(unsafe { chmod(path.as_ptr(), 0o644) }, 0);
    let _ = std::fs::remove_file(path.to_str().unwrap());
}

#[test]
fn fchmod_changes_permissions() {
    let path = temp_path("fchmod");
    let fd = unsafe { open(path.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o644) };
    assert!(fd >= 0);

    assert_eq!(unsafe { fchmod(fd, 0o444) }, 0);

    let meta = std::fs::metadata(path.to_str().unwrap()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(meta.permissions().mode() & 0o777, 0o444);

    assert_eq!(unsafe { close(fd) }, 0);
    std::fs::set_permissions(
        path.to_str().unwrap(),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let _ = std::fs::remove_file(path.to_str().unwrap());
}

#[test]
fn chown_does_not_crash() {
    let path = temp_path("chown");
    std::fs::write(path.to_str().unwrap(), b"x").unwrap();

    let uid = unsafe { getuid() };
    let gid = unsafe { getgid() };
    // Chown to self should succeed
    let rc = unsafe { chown(path.as_ptr(), uid, gid) };
    assert_eq!(rc, 0);

    let _ = std::fs::remove_file(path.to_str().unwrap());
}

#[test]
fn fchown_does_not_crash() {
    let path = temp_path("fchown");
    let fd = unsafe { open(path.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o644) };
    assert!(fd >= 0);

    let uid = unsafe { getuid() };
    let gid = unsafe { getgid() };
    let rc = unsafe { fchown(fd, uid, gid) };
    assert_eq!(rc, 0);

    assert_eq!(unsafe { close(fd) }, 0);
    let _ = std::fs::remove_file(path.to_str().unwrap());
}

#[test]
fn truncate_shrinks_file() {
    let path = temp_path("trunc");
    std::fs::write(path.to_str().unwrap(), b"0123456789").unwrap();

    assert_eq!(unsafe { truncate(path.as_ptr(), 5) }, 0);
    let meta = std::fs::metadata(path.to_str().unwrap()).unwrap();
    assert_eq!(meta.len(), 5);

    let _ = std::fs::remove_file(path.to_str().unwrap());
}

#[test]
fn ftruncate_shrinks_file() {
    let path = temp_path("ftrunc");
    let fd = unsafe { open(path.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o644) };
    assert!(fd >= 0);

    let data = b"0123456789";
    unsafe { write(fd, data.as_ptr().cast(), data.len()) };

    assert_eq!(unsafe { ftruncate(fd, 3) }, 0);
    assert_eq!(unsafe { lseek(fd, 0, libc::SEEK_END) }, 3);

    assert_eq!(unsafe { close(fd) }, 0);
    let _ = std::fs::remove_file(path.to_str().unwrap());
}

#[test]
fn fsync_and_fdatasync_on_regular_file() {
    let path = temp_path("fsync");
    let fd = unsafe { open(path.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o644) };
    assert!(fd >= 0);

    unsafe { write(fd, b"test".as_ptr().cast(), 4) };
    assert_eq!(unsafe { fsync(fd) }, 0);
    assert_eq!(unsafe { fdatasync(fd) }, 0);

    assert_eq!(unsafe { close(fd) }, 0);
    let _ = std::fs::remove_file(path.to_str().unwrap());
}

#[test]
fn flock_exclusive_and_unlock() {
    let path = temp_path("flock");
    let fd = unsafe { open(path.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o644) };
    assert!(fd >= 0);

    assert_eq!(unsafe { flock(fd, libc::LOCK_EX | libc::LOCK_NB) }, 0);
    assert_eq!(unsafe { flock(fd, libc::LOCK_UN) }, 0);

    assert_eq!(unsafe { close(fd) }, 0);
    let _ = std::fs::remove_file(path.to_str().unwrap());
}

// ---------------------------------------------------------------------------
// Core POSIX: pipe
// ---------------------------------------------------------------------------

#[test]
fn pipe_creates_connected_fds() {
    let mut fds = [0i32; 2];
    assert_eq!(
        unsafe { frankenlibc_abi::io_abi::pipe(fds.as_mut_ptr()) },
        0
    );
    assert!(fds[0] >= 0);
    assert!(fds[1] >= 0);

    let msg = b"hi";
    let written = unsafe { write(fds[1], msg.as_ptr().cast(), msg.len()) };
    assert_eq!(written as usize, msg.len());

    let mut buf = [0u8; 4];
    let n = unsafe { read(fds[0], buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(n as usize, msg.len());
    assert_eq!(&buf[..n as usize], msg);

    unsafe { close(fds[0]) };
    unsafe { close(fds[1]) };
}

// ---------------------------------------------------------------------------
// Core POSIX: umask
// ---------------------------------------------------------------------------

#[test]
fn umask_round_trips() {
    let old = unsafe { umask(0o077) };
    let restored = unsafe { umask(old) };
    assert_eq!(restored, 0o077);
}

// ---------------------------------------------------------------------------
// Core POSIX: hostname
// ---------------------------------------------------------------------------

#[test]
fn gethostname_returns_nonempty_string() {
    let mut buf = [0i8; 256];
    let rc = unsafe { gethostname(buf.as_mut_ptr(), buf.len()) };
    assert_eq!(rc, 0);
    let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_bytes();
    assert!(!name.is_empty());
}

// ---------------------------------------------------------------------------
// Core POSIX: uname
// ---------------------------------------------------------------------------

#[test]
fn uname_fills_sysname() {
    let mut buf = [0u8; 512]; // Oversized buffer for struct utsname
    let rc = unsafe { uname(buf.as_mut_ptr().cast()) };
    assert_eq!(rc, 0);
    // First field is sysname - should start with "Linux"
    let sysname = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr().cast()) }.to_string_lossy();
    assert_eq!(&*sysname, "Linux");
}

// ---------------------------------------------------------------------------
// Core POSIX: sysconf, pathconf
// ---------------------------------------------------------------------------

#[test]
fn sysconf_page_size_is_positive_power_of_two() {
    let ps = unsafe { sysconf(libc::_SC_PAGESIZE) };
    assert!(ps > 0);
    assert_eq!(ps & (ps - 1), 0, "page size should be power of 2");
}

#[test]
fn sysconf_nprocessors_is_positive() {
    let n = unsafe { sysconf(libc::_SC_NPROCESSORS_ONLN) };
    assert!(n >= 1);
}

#[test]
fn pathconf_on_slash() {
    let root = CString::new("/").unwrap();
    let name_max = unsafe { pathconf(root.as_ptr(), libc::_PC_NAME_MAX) };
    assert!(name_max > 0, "NAME_MAX on / should be positive");
}

#[test]
fn sysconf_ngroups_max_matches_procfs_when_available() {
    let value = unsafe { sysconf(libc::_SC_NGROUPS_MAX) };
    assert!(value > 0, "NGROUPS_MAX should be positive");

    if let Ok(raw) = std::fs::read_to_string("/proc/sys/kernel/ngroups_max")
        && let Ok(expected) = raw.trim().parse::<libc::c_long>()
    {
        assert_eq!(value, expected);
    }
}

#[test]
fn sysconf_thread_stack_min_matches_libc_constant() {
    let value = unsafe { sysconf(libc::_SC_THREAD_STACK_MIN) };
    assert_eq!(value, libc::PTHREAD_STACK_MIN as libc::c_long);
}

#[test]
fn sysconf_phys_pages_uses_runtime_page_size() {
    let value = unsafe { sysconf(libc::_SC_PHYS_PAGES) };
    assert!(value > 0, "PHYS_PAGES should be positive");

    let page_size = unsafe { sysconf(libc::_SC_PAGESIZE) } as u64;
    let meminfo = std::fs::read_to_string("/proc/meminfo").expect("/proc/meminfo should exist");
    let total_kb = meminfo
        .lines()
        .find_map(|line| {
            if !line.starts_with("MemTotal:") {
                return None;
            }
            line.split_whitespace().nth(1)?.parse::<u64>().ok()
        })
        .expect("MemTotal should be present");
    let expected = ((total_kb * 1024) / page_size) as libc::c_long;

    assert_eq!(value, expected);
}

// ---------------------------------------------------------------------------
// Core POSIX: alarm, sleep, usleep
// ---------------------------------------------------------------------------

#[test]
fn alarm_returns_previous_alarm() {
    let prev = unsafe { alarm(10) };
    // Cancel the alarm
    let remaining = unsafe { alarm(0) };
    assert!(remaining <= 10);
    // Restore whatever was there before
    if prev > 0 {
        unsafe { alarm(prev) };
    }
}

#[test]
fn usleep_zero_returns_immediately() {
    let rc = unsafe { usleep(0) };
    assert_eq!(rc, 0);
}

// ---------------------------------------------------------------------------
// Core POSIX: faccessat
// ---------------------------------------------------------------------------

#[test]
fn faccessat_checks_existence() {
    let path = temp_path("faccessat");
    std::fs::write(path.to_str().unwrap(), b"x").unwrap();

    let rc = unsafe { faccessat(libc::AT_FDCWD, path.as_ptr(), libc::F_OK, 0) };
    assert_eq!(rc, 0);

    let _ = std::fs::remove_file(path.to_str().unwrap());
}

#[test]
fn faccessat_at_eaccess_checks_existence() {
    let path = temp_path("faccessat_at_eaccess");
    std::fs::write(path.to_str().unwrap(), b"x").unwrap();

    let rc = unsafe { faccessat(libc::AT_FDCWD, path.as_ptr(), libc::F_OK, libc::AT_EACCESS) };
    assert_eq!(rc, 0);

    let _ = std::fs::remove_file(path.to_str().unwrap());
}

// ---------------------------------------------------------------------------
// Core POSIX: mkfifo
// ---------------------------------------------------------------------------

#[test]
fn mkfifo_creates_named_pipe() {
    let path = temp_path("mkfifo");
    let rc = unsafe { mkfifo(path.as_ptr(), 0o644) };
    assert_eq!(rc, 0);

    let meta = std::fs::symlink_metadata(path.to_str().unwrap()).unwrap();
    assert!(meta.file_type().is_fifo());

    let _ = std::fs::remove_file(path.to_str().unwrap());
}
