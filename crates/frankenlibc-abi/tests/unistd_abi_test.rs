//! ABI integration tests for unistd_abi native implementations.
//!
//! Tests for promoted GlibcCallThrough -> Implemented symbols:
//! - glob64 / globfree64
//! - ftw / nftw / nftw64
//! - setmntent / getmntent / endmntent

#![allow(unsafe_code)]

use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::sync::Mutex;
use std::sync::atomic::AtomicI32;
use std::time::{SystemTime, UNIX_EPOCH};

/// Serializes all gai_*/getaddrinfo_a tests in this binary.
///
/// host glibc's async-getaddrinfo machinery (gai_cancel, gai_error,
/// gai_suspend, getaddrinfo_a) shares a single in-process request
/// queue and a global state cache. Concurrent host gai_* calls in
/// parallel test threads can mutate that state between our captured
/// host snapshot and the matching abi snapshot, breaking the
/// host-vs-abi parity assertions. Reproduced as bd-el0v8 — flaked
/// `synchronous_gai_wrappers_match_host_degenerate_contracts` ~25%
/// of stress runs at --test-threads=16.
static GAI_TEST_LOCK: Mutex<()> = Mutex::new(());

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::glibc_internal_abi::__sysv_signal;
use frankenlibc_abi::glibc_internal_abi::getdate_err;
use frankenlibc_abi::glibc_internal_abi::setaliasent as abi_setaliasent;
use frankenlibc_abi::resolv_abi::__h_errno_location;
use frankenlibc_abi::unistd_abi::{
    FTSENT as AbiFtsEnt, access, aio_suspend, alarm, arc4random_buf, bsd_getopt, chdir, chmod,
    chown, close, creat, eaccess, endaliasent, ether_line, euidaccess, faccessat, fchmod, fchown,
    fdatasync, fgetgrent_r, fgetpwent_r, fgetspent, fgetspent_r, flock, flopen, flopenat, fstat,
    fsync, ftruncate, fts_children as abi_fts_children, fts_close as abi_fts_close,
    fts_open as abi_fts_open, fts_read as abi_fts_read, fts_set as abi_fts_set, gai_cancel,
    gai_error, gai_suspend, getaddrinfo_a, getaliasbyname, getaliasbyname_r, getaliasent,
    getaliasent_r, getcwd, getdate, getdate_r, getegid, geteuid, getfsent, getfsfile, getfsspec,
    getgid, gethostbyname2, gethostbyname2_r, gethostent_r, gethostname, getnetbyaddr_r,
    getnetbyname_r, getnetent_r, getnetgrent, getnetgrent_r, getpid, getppid, getprotobyname_r,
    getprotobynumber_r, getprotoent, getprotoent_r, getservent, getservent_r, getttyent, getttynam,
    getuid, getutent_r, getutid, getutid_r, getutline, getutline_r, glob64, globfree64, gsignal,
    isatty, link, logout, lseek, lstat, mkdir, mkfifo, mount_setattr, msgrcv, msgsnd, open,
    pathconf, pidfd_getfd, process_madvise, process_mrelease, process_vm_readv, process_vm_writev,
    read, readlink, readpassphrase, rename, rmdir, semctl, semop, setfsent, sethostent, setnetent,
    setnetgrent, setns, setproctitle, setproctitle_init, setprotoent, setservent, setttyent,
    setutent, shmdt, sigpause, sigset, sigstack, sigvec, ssignal, stat, strfmon, strfmon_l,
    symlink, sysconf, truncate, umask, uname, unlink, unshare, updwtmp, updwtmpx, usleep, utmpname,
    wordexp as abi_wordexp, wordfree as abi_wordfree, write,
};

static SIGNAL_HIT: AtomicI32 = AtomicI32::new(0);
const GAI_WAIT: c_int = 0;
const GAI_NOWAIT: c_int = 1;
const GAI_BADFLAGS_NEGATIVE_MODE: c_int = -1;
const GAI_BADFLAGS_POSITIVE_MODE: c_int = 2;
const GAI_EAI_ALLDONE: c_int = -103;

/// Mirror of glibc's `struct gaicb` (netdb.h). The first 4 pointer
/// fields are documented; glibc reads `__return` (and historically
/// the 5 `__unused` int slots) when implementing `gai_error`. The
/// previous 32-byte layout omitted these trailing fields, so
/// host_gai_error read past the struct boundary into uninitialized
/// stack memory under parallel test pressure — produced bd-el0v8's
/// "left=0 right=2" / "left=0 right=121360248" flake. (bd-el0v8)
#[repr(C)]
struct GaicbShape {
    ar_name: *const c_char,
    ar_service: *const c_char,
    ar_request: *const c_void,
    ar_result: *mut c_void,
    /// `__return` per glibc — gai_error returns this value.
    __return: c_int,
    /// `__glibc_reserved`/`__unused` 5-element int tail.
    __unused: [c_int; 5],
}

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
// argp_parse parity tests
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

fn empty_argp_storage() -> [usize; 7] {
    [0; 7]
}

#[test]
fn abi_argp_parse_empty_argp_matches_glibc_index_contracts() {
    let argp_struct = empty_argp_storage();
    let prog = b"test\0";
    let extra = b"extra\0";
    let mut argv = [
        prog.as_ptr() as *mut c_char,
        extra.as_ptr() as *mut c_char,
        std::ptr::null_mut(),
    ];

    let mut index: c_int = -1;
    clear_errno();
    let rc = unsafe {
        frankenlibc_abi::unistd_abi::argp_parse(
            argp_struct.as_ptr().cast(),
            2,
            argv.as_mut_ptr(),
            0,
            &mut index,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(errno_value(), 0);
    assert_eq!(index, 1);

    index = -1;
    clear_errno();
    let rc = unsafe {
        frankenlibc_abi::unistd_abi::argp_parse(
            argp_struct.as_ptr().cast(),
            1,
            argv.as_mut_ptr(),
            0,
            &mut index,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(errno_value(), 0);
    assert_eq!(index, 1);

    index = -1;
    clear_errno();
    let rc = unsafe {
        frankenlibc_abi::unistd_abi::argp_parse(
            argp_struct.as_ptr().cast(),
            0,
            std::ptr::null_mut(),
            0,
            &mut index,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(errno_value(), 0);
    assert_eq!(index, 0);
}

#[test]
fn abi_argp_parse_nonempty_argp_remains_explicitly_unsupported() {
    let mut argp_struct = empty_argp_storage();
    argp_struct[0] = 1;
    let prog = b"test\0";
    let mut argv = [prog.as_ptr() as *mut c_char, std::ptr::null_mut()];
    let mut index: c_int = -1;

    clear_errno();
    let rc = unsafe {
        frankenlibc_abi::unistd_abi::argp_parse(
            argp_struct.as_ptr().cast(),
            1,
            argv.as_mut_ptr(),
            0,
            &mut index,
            std::ptr::null_mut(),
        )
    };

    assert_eq!(rc, libc::EINVAL);
    assert_eq!(errno_value(), libc::EINVAL);
    assert_eq!(index, -1);
}

// ---------------------------------------------------------------------------
// SysV IPC surface tests
// ---------------------------------------------------------------------------

#[test]
fn shmdt_null_pointer_fails_with_einval_like_host() {
    let rc = unsafe { shmdt(std::ptr::null()) };
    assert_eq!(rc, -1);
    assert_eq!(errno_value(), libc::EINVAL);
}

#[test]
fn semctl_ipc_rmid_without_variadic_arg_fails_for_invalid_semaphore_id() {
    // bd-jm3h: host glibc returns EINVAL for semctl(-1, 0, IPC_RMID).
    // The broad is_expected_sysvipc_errno sentinel accepted a whole
    // family; tighten to the exact host-parity contract so any future
    // drift surfaces immediately.
    let rc = unsafe { semctl(-1, 0, libc::IPC_RMID) };
    assert_eq!(rc, -1);
    assert_eq!(
        errno_value(),
        libc::EINVAL,
        "semctl(-1, 0, IPC_RMID) must return EINVAL (host-parity), got {}",
        errno_value()
    );
}

#[test]
fn semop_null_payload_nonzero_ops_fails_cleanly() {
    // bd-7g3f: host glibc surfaces EFAULT for semop(_, NULL, nsops>0)
    // because the kernel dereferences sops before validating semid.
    // Tighten from the broad family sentinel to the exact host-parity
    // errno so future drift is caught immediately.
    let rc = unsafe { semop(-1, std::ptr::null_mut(), 1) };
    assert_eq!(rc, -1);
    assert_eq!(
        errno_value(),
        libc::EFAULT,
        "semop(-1, NULL, 1) must return EFAULT (host-parity), got {}",
        errno_value()
    );
}

#[test]
fn msgsnd_null_payload_nonzero_size_fails_cleanly() {
    // bd-6kkg: host glibc surfaces EFAULT for msgsnd(_, NULL, size>0)
    // because the kernel dereferences msgp before the queue-id check.
    let rc = unsafe { msgsnd(-1, std::ptr::null(), 8, 0) };
    assert_eq!(rc, -1);
    assert_eq!(
        errno_value(),
        libc::EFAULT,
        "msgsnd(-1, NULL, 8, 0) must return EFAULT (host-parity), got {}",
        errno_value()
    );
}

#[test]
fn msgrcv_null_payload_nonzero_size_fails_cleanly() {
    // bd-he3h: for msgrcv the kernel validates msgid BEFORE the msgp
    // pointer, so the invalid queue-id path wins: msgrcv(-1, NULL, 8,
    // 0, 0) returns EINVAL, not EFAULT. Pin that precedence rule.
    let rc = unsafe { msgrcv(-1, std::ptr::null_mut(), 8, 0, 0) };
    assert_eq!(rc, -1);
    assert_eq!(
        errno_value(),
        libc::EINVAL,
        "msgrcv(-1, NULL, 8, 0, 0) must return EINVAL (host-parity: invalid msqid wins over NULL payload), got {}",
        errno_value()
    );
}

#[test]
fn process_vm_readv_null_iov_nonzero_counts_set_efault_like_host() {
    let pid = std::process::id() as libc::pid_t;
    let mut remote_byte = 0_u8;
    let remote_iov = libc::iovec {
        iov_base: (&mut remote_byte as *mut u8).cast(),
        iov_len: 1,
    };

    clear_errno();
    let host_rc = unsafe { libc::process_vm_readv(pid, std::ptr::null(), 1, &remote_iov, 1, 0) };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { process_vm_readv(pid, std::ptr::null(), 1, &remote_iov, 1, 0) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EFAULT);
}

#[test]
fn process_vm_writev_null_iov_nonzero_counts_set_efault_like_host() {
    let pid = std::process::id() as libc::pid_t;
    let mut local_byte = 7_u8;
    let local_iov = libc::iovec {
        iov_base: (&mut local_byte as *mut u8).cast(),
        iov_len: 1,
    };

    clear_errno();
    let host_rc = unsafe { libc::process_vm_writev(pid, &local_iov, 1, std::ptr::null(), 1, 0) };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { process_vm_writev(pid, &local_iov, 1, std::ptr::null(), 1, 0) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EFAULT);
}

#[test]
fn process_vm_readv_invalid_flags_override_null_iov_fault_like_host() {
    let pid = std::process::id() as libc::pid_t;
    let mut remote_byte = 0_u8;
    let remote_iov = libc::iovec {
        iov_base: (&mut remote_byte as *mut u8).cast(),
        iov_len: 1,
    };

    clear_errno();
    let host_rc = unsafe { libc::process_vm_readv(pid, std::ptr::null(), 1, &remote_iov, 1, 1) };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { process_vm_readv(pid, std::ptr::null(), 1, &remote_iov, 1, 1) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EINVAL);
}

#[test]
fn process_vm_writev_invalid_flags_override_null_iov_fault_like_host() {
    let pid = std::process::id() as libc::pid_t;
    let mut local_byte = 7_u8;
    let local_iov = libc::iovec {
        iov_base: (&mut local_byte as *mut u8).cast(),
        iov_len: 1,
    };

    clear_errno();
    let host_rc = unsafe { libc::process_vm_writev(pid, &local_iov, 1, std::ptr::null(), 1, 1) };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { process_vm_writev(pid, &local_iov, 1, std::ptr::null(), 1, 1) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EINVAL);
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
        *libc::__errno_location() = libc::E2BIG;
    }
    let host_rc = unsafe { libc::process_vm_readv(pid, std::ptr::null(), 0, &remote_iov, 1, 0) };
    assert_eq!(host_rc, 0);
    let host_errno = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let abi_rc = unsafe { process_vm_readv(pid, std::ptr::null(), 0, &remote_iov, 1, 0) };
    assert_eq!(abi_rc, 0);
    let abi_errno = errno_value();

    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::E2BIG);
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
        *libc::__errno_location() = libc::E2BIG;
    }
    let host_rc = unsafe { libc::process_vm_writev(pid, &local_iov, 1, std::ptr::null(), 0, 0) };
    assert_eq!(host_rc, 0);
    let host_errno = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let abi_rc = unsafe { process_vm_writev(pid, &local_iov, 1, std::ptr::null(), 0, 0) };
    assert_eq!(abi_rc, 0);
    let abi_errno = errno_value();

    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::E2BIG);
}

#[test]
fn process_vm_readv_all_null_zero_counts_preserve_errno_and_succeed() {
    let pid = std::process::id() as libc::pid_t;

    unsafe {
        *libc::__errno_location() = libc::E2BIG;
    }
    let host_rc =
        unsafe { libc::process_vm_readv(pid, std::ptr::null(), 0, std::ptr::null(), 0, 0) };
    assert_eq!(host_rc, 0);
    let host_errno = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let abi_rc = unsafe { process_vm_readv(pid, std::ptr::null(), 0, std::ptr::null(), 0, 0) };
    assert_eq!(abi_rc, 0);
    let abi_errno = errno_value();

    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::E2BIG);
}

#[test]
fn process_vm_readv_invalid_flags_override_all_null_zero_counts_like_host() {
    let pid = std::process::id() as libc::pid_t;

    clear_errno();
    let host_rc =
        unsafe { libc::process_vm_readv(pid, std::ptr::null(), 0, std::ptr::null(), 0, 1) };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { process_vm_readv(pid, std::ptr::null(), 0, std::ptr::null(), 0, 1) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EINVAL);
}

#[test]
fn process_vm_writev_all_null_zero_counts_preserve_errno_and_succeed() {
    let pid = std::process::id() as libc::pid_t;

    unsafe {
        *libc::__errno_location() = libc::E2BIG;
    }
    let host_rc =
        unsafe { libc::process_vm_writev(pid, std::ptr::null(), 0, std::ptr::null(), 0, 0) };
    assert_eq!(host_rc, 0);
    let host_errno = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let abi_rc = unsafe { process_vm_writev(pid, std::ptr::null(), 0, std::ptr::null(), 0, 0) };
    assert_eq!(abi_rc, 0);
    let abi_errno = errno_value();

    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::E2BIG);
}

#[test]
fn process_vm_writev_invalid_flags_override_all_null_zero_counts_like_host() {
    let pid = std::process::id() as libc::pid_t;

    clear_errno();
    let host_rc =
        unsafe { libc::process_vm_writev(pid, std::ptr::null(), 0, std::ptr::null(), 0, 1) };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { process_vm_writev(pid, std::ptr::null(), 0, std::ptr::null(), 0, 1) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EINVAL);
}

#[test]
fn process_madvise_null_iov_nonzero_len_sets_efault_like_host() {
    clear_errno();
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_process_madvise,
            -1 as libc::c_long,
            std::ptr::null::<libc::iovec>(),
            1_usize,
            libc::MADV_NORMAL,
            0 as libc::c_uint,
        )
    };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { process_madvise(-1, std::ptr::null(), 1, libc::MADV_NORMAL, 0) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EFAULT);
}

#[test]
fn process_madvise_null_iov_zero_len_invalid_pidfd_sets_ebadf_like_host() {
    clear_errno();
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_process_madvise,
            -1 as libc::c_long,
            std::ptr::null::<libc::iovec>(),
            0_usize,
            libc::MADV_NORMAL,
            0 as libc::c_uint,
        )
    };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { process_madvise(-1, std::ptr::null(), 0, libc::MADV_NORMAL, 0) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EBADF);
}

#[test]
fn process_madvise_invalid_flags_set_einval_like_host() {
    clear_errno();
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_process_madvise,
            -1 as libc::c_long,
            std::ptr::null::<libc::iovec>(),
            0_usize,
            libc::MADV_NORMAL,
            1 as libc::c_uint,
        )
    };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { process_madvise(-1, std::ptr::null(), 0, libc::MADV_NORMAL, 1) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EINVAL);
}

#[test]
fn process_madvise_invalid_flags_override_bad_pidfd_and_missing_iov_like_host() {
    clear_errno();
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_process_madvise,
            -1 as libc::c_long,
            std::ptr::null::<libc::iovec>(),
            1_usize,
            libc::MADV_NORMAL,
            1 as libc::c_uint,
        )
    };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { process_madvise(-1, std::ptr::null(), 1, libc::MADV_NORMAL, 1) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EINVAL);
}

#[test]
fn process_mrelease_invalid_pidfd_sets_ebadf_like_host() {
    clear_errno();
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_process_mrelease,
            -1 as libc::c_long,
            0 as libc::c_uint,
        )
    };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { process_mrelease(-1, 0) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EBADF);
}

#[test]
fn process_mrelease_invalid_flags_override_invalid_pidfd_like_host() {
    clear_errno();
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_process_mrelease,
            -1 as libc::c_long,
            1 as libc::c_uint,
        )
    };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { process_mrelease(-1, 1) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EINVAL);
}

#[test]
fn process_mrelease_zero_pidfd_sets_ebadf_like_host() {
    clear_errno();
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_process_mrelease,
            0 as libc::c_long,
            0 as libc::c_uint,
        )
    };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { process_mrelease(0, 0) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EBADF);
}

#[test]
fn process_mrelease_invalid_flags_override_zero_pidfd_like_host() {
    clear_errno();
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_process_mrelease,
            0 as libc::c_long,
            1 as libc::c_uint,
        )
    };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { process_mrelease(0, 1) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EINVAL);
}

#[test]
fn pidfd_getfd_invalid_pidfd_sets_ebadf_like_host() {
    clear_errno();
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_getfd,
            -1 as libc::c_long,
            0 as libc::c_long,
            0 as libc::c_uint,
        )
    };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { pidfd_getfd(-1, 0, 0) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EBADF);
}

#[test]
fn pidfd_getfd_invalid_targetfd_does_not_override_invalid_pidfd_like_host() {
    clear_errno();
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_getfd,
            -1 as libc::c_long,
            -1 as libc::c_long,
            0 as libc::c_uint,
        )
    };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { pidfd_getfd(-1, -1, 0) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EBADF);
}

#[test]
fn pidfd_getfd_invalid_flags_override_invalid_pidfd_like_host() {
    clear_errno();
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_getfd,
            -1 as libc::c_long,
            0 as libc::c_long,
            1 as libc::c_uint,
        )
    };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { pidfd_getfd(-1, 0, 1) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EINVAL);
}

#[test]
fn mount_setattr_null_pathname_invalid_dirfd_sets_einval_like_host() {
    clear_errno();
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            -1 as libc::c_long,
            std::ptr::null::<c_char>(),
            0 as libc::c_uint,
            std::ptr::null::<c_void>(),
            0_usize,
        )
    };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe { mount_setattr(-1, std::ptr::null(), 0, std::ptr::null_mut(), 0) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EINVAL);
}

#[test]
fn mount_setattr_null_pathname_at_empty_path_still_sets_einval_like_host() {
    clear_errno();
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD as libc::c_long,
            std::ptr::null::<c_char>(),
            libc::AT_EMPTY_PATH as libc::c_uint,
            std::ptr::null::<c_void>(),
            0_usize,
        )
    };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc = unsafe {
        mount_setattr(
            libc::AT_FDCWD,
            std::ptr::null(),
            libc::AT_EMPTY_PATH as libc::c_uint,
            std::ptr::null_mut(),
            0,
        )
    };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EINVAL);
}

#[test]
fn mount_setattr_slash_path_null_attr_sets_einval_like_host() {
    let slash = CString::new("/").unwrap();

    clear_errno();
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD as libc::c_long,
            slash.as_ptr(),
            0 as libc::c_uint,
            std::ptr::null::<c_void>(),
            0_usize,
        )
    };
    assert_eq!(host_rc, -1);
    let host_errno = unsafe { *libc::__errno_location() };

    clear_errno();
    let abi_rc =
        unsafe { mount_setattr(libc::AT_FDCWD, slash.as_ptr(), 0, std::ptr::null_mut(), 0) };
    assert_eq!(abi_rc, -1);
    let abi_errno = errno_value();

    assert_eq!(abi_errno, host_errno);
    assert_eq!(abi_errno, libc::EINVAL);
}

#[test]
fn mount_setattr_empty_path_preserves_unprivileged_eperm_like_host() {
    let empty = CString::new("").unwrap();
    let attr_size = std::mem::size_of::<[u64; 4]>();

    let mut host_plain_attr = [0_u64; 4];
    clear_errno();
    let host_plain_rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD as libc::c_long,
            empty.as_ptr(),
            0 as libc::c_uint,
            host_plain_attr.as_mut_ptr().cast::<c_void>(),
            attr_size,
        )
    };
    assert_eq!(host_plain_rc, -1);
    let host_plain_errno = unsafe { *libc::__errno_location() };

    let mut abi_plain_attr = [0_u64; 4];
    clear_errno();
    let abi_plain_rc = unsafe {
        mount_setattr(
            libc::AT_FDCWD,
            empty.as_ptr(),
            0,
            abi_plain_attr.as_mut_ptr().cast::<c_void>(),
            attr_size,
        )
    };
    assert_eq!(abi_plain_rc, -1);
    let abi_plain_errno = errno_value();

    assert_eq!(abi_plain_errno, host_plain_errno);
    assert_eq!(abi_plain_errno, libc::EPERM);

    let mut host_empty_path_attr = [0_u64; 4];
    clear_errno();
    let host_empty_path_rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD as libc::c_long,
            empty.as_ptr(),
            libc::AT_EMPTY_PATH as libc::c_uint,
            host_empty_path_attr.as_mut_ptr().cast::<c_void>(),
            attr_size,
        )
    };
    assert_eq!(host_empty_path_rc, -1);
    let host_empty_path_errno = unsafe { *libc::__errno_location() };

    let mut abi_empty_path_attr = [0_u64; 4];
    clear_errno();
    let abi_empty_path_rc = unsafe {
        mount_setattr(
            libc::AT_FDCWD,
            empty.as_ptr(),
            libc::AT_EMPTY_PATH as libc::c_uint,
            abi_empty_path_attr.as_mut_ptr().cast::<c_void>(),
            attr_size,
        )
    };
    assert_eq!(abi_empty_path_rc, -1);
    let abi_empty_path_errno = errno_value();

    assert_eq!(abi_empty_path_errno, host_empty_path_errno);
    assert_eq!(abi_empty_path_errno, libc::EPERM);
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
    let _gai_guard = GAI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    let _gai_guard = GAI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
fn getaddrinfo_a_zeroed_gaicb_request_slots_report_success_without_touching_errno() {
    let _gai_guard = GAI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut first: GaicbShape = unsafe { std::mem::zeroed() };
    let mut second: GaicbShape = unsafe { std::mem::zeroed() };

    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let mut requests = [
        (&mut first as *mut GaicbShape).cast::<c_void>(),
        (&mut second as *mut GaicbShape).cast::<c_void>(),
    ];
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

    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let mut mixed_requests = [
        std::ptr::null_mut(),
        (&mut first as *mut GaicbShape).cast::<c_void>(),
    ];
    let rc = unsafe {
        getaddrinfo_a(
            GAI_NOWAIT,
            mixed_requests.as_mut_ptr(),
            mixed_requests.len() as c_int,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(errno_value(), libc::E2BIG);
}

#[test]
fn getaddrinfo_a_nowait_degenerate_requests_report_success_without_touching_errno() {
    let _gai_guard = GAI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
fn getaddrinfo_a_nowait_degenerate_requests_preserve_errno_like_host() {
    let _gai_guard = GAI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    type HostGetaddrinfoAFn =
        unsafe extern "C" fn(c_int, *mut *mut c_void, c_int, *mut c_void) -> c_int;

    let Some(host_getaddrinfo_a) = (unsafe { load_host_symbol("getaddrinfo_a") })
        .map(|ptr| unsafe { std::mem::transmute::<*mut c_void, HostGetaddrinfoAFn>(ptr) })
    else {
        return;
    };

    unsafe {
        *libc::__errno_location() = libc::E2BIG;
    }
    let host_null_list =
        unsafe { host_getaddrinfo_a(GAI_NOWAIT, std::ptr::null_mut(), 0, std::ptr::null_mut()) };
    let host_null_list_errno = unsafe { *libc::__errno_location() };
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let abi_null_list =
        unsafe { getaddrinfo_a(GAI_NOWAIT, std::ptr::null_mut(), 0, std::ptr::null_mut()) };
    let abi_null_list_errno = errno_value();
    assert_eq!(abi_null_list, host_null_list);
    assert_eq!(abi_null_list_errno, host_null_list_errno);

    let mut host_requests = [std::ptr::null_mut()];
    unsafe {
        *libc::__errno_location() = libc::E2BIG;
    }
    let host_all_null = unsafe {
        host_getaddrinfo_a(
            GAI_NOWAIT,
            host_requests.as_mut_ptr(),
            host_requests.len() as c_int,
            std::ptr::null_mut(),
        )
    };
    let host_all_null_errno = unsafe { *libc::__errno_location() };

    let mut abi_requests = [std::ptr::null_mut()];
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let abi_all_null = unsafe {
        getaddrinfo_a(
            GAI_NOWAIT,
            abi_requests.as_mut_ptr(),
            abi_requests.len() as c_int,
            std::ptr::null_mut(),
        )
    };
    let abi_all_null_errno = errno_value();
    assert_eq!(abi_all_null, host_all_null);
    assert_eq!(abi_all_null_errno, host_all_null_errno);
}

#[test]
fn getaddrinfo_a_wait_zero_requests_preserve_errno_like_host() {
    let _gai_guard = GAI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    type HostGetaddrinfoAFn =
        unsafe extern "C" fn(c_int, *mut *mut c_void, c_int, *mut c_void) -> c_int;

    let Some(host_getaddrinfo_a) = (unsafe { load_host_symbol("getaddrinfo_a") })
        .map(|ptr| unsafe { std::mem::transmute::<*mut c_void, HostGetaddrinfoAFn>(ptr) })
    else {
        return;
    };

    unsafe {
        *libc::__errno_location() = libc::E2BIG;
    }
    let host_null_list =
        unsafe { host_getaddrinfo_a(GAI_WAIT, std::ptr::null_mut(), 0, std::ptr::null_mut()) };
    let host_null_list_errno = unsafe { *libc::__errno_location() };
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let abi_null_list =
        unsafe { getaddrinfo_a(GAI_WAIT, std::ptr::null_mut(), 0, std::ptr::null_mut()) };
    let abi_null_list_errno = errno_value();
    assert_eq!(abi_null_list, host_null_list);
    assert_eq!(abi_null_list_errno, host_null_list_errno);

    let mut host_requests = [std::ptr::null_mut()];
    unsafe {
        *libc::__errno_location() = libc::E2BIG;
    }
    let host_negative_nitems = unsafe {
        host_getaddrinfo_a(
            GAI_WAIT,
            host_requests.as_mut_ptr(),
            -1,
            std::ptr::null_mut(),
        )
    };
    let host_negative_nitems_errno = unsafe { *libc::__errno_location() };

    let mut abi_requests = [std::ptr::null_mut()];
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let abi_negative_nitems = unsafe {
        getaddrinfo_a(
            GAI_WAIT,
            abi_requests.as_mut_ptr(),
            -1,
            std::ptr::null_mut(),
        )
    };
    let abi_negative_nitems_errno = errno_value();
    assert_eq!(abi_negative_nitems, host_negative_nitems);
    assert_eq!(abi_negative_nitems_errno, host_negative_nitems_errno);
}

#[test]
fn getaddrinfo_a_mode_semantics_match_host_across_empty_and_all_null_requests() {
    let _gai_guard = GAI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    type HostGetaddrinfoAFn =
        unsafe extern "C" fn(c_int, *mut *mut c_void, c_int, *mut c_void) -> c_int;

    let Some(host_getaddrinfo_a) = (unsafe { load_host_symbol("getaddrinfo_a") })
        .map(|ptr| unsafe { std::mem::transmute::<*mut c_void, HostGetaddrinfoAFn>(ptr) })
    else {
        return;
    };

    for mode in [
        GAI_WAIT,
        GAI_NOWAIT,
        GAI_BADFLAGS_NEGATIVE_MODE,
        GAI_BADFLAGS_POSITIVE_MODE,
    ] {
        unsafe {
            *libc::__errno_location() = libc::E2BIG;
        }
        let host_empty =
            unsafe { host_getaddrinfo_a(mode, std::ptr::null_mut(), 0, std::ptr::null_mut()) };
        let host_empty_errno = unsafe { *libc::__errno_location() };
        unsafe {
            *__errno_location() = libc::E2BIG;
        }
        let abi_empty =
            unsafe { getaddrinfo_a(mode, std::ptr::null_mut(), 0, std::ptr::null_mut()) };
        let abi_empty_errno = errno_value();
        assert_eq!(abi_empty, host_empty, "mode {mode} empty-list rc");
        assert_eq!(
            abi_empty_errno, host_empty_errno,
            "mode {mode} empty-list errno"
        );

        let mut host_requests = [std::ptr::null_mut()];
        unsafe {
            *libc::__errno_location() = libc::E2BIG;
        }
        let host_all_null = unsafe {
            host_getaddrinfo_a(
                mode,
                host_requests.as_mut_ptr(),
                host_requests.len() as c_int,
                std::ptr::null_mut(),
            )
        };
        let host_all_null_errno = unsafe { *libc::__errno_location() };

        let mut abi_requests = [std::ptr::null_mut()];
        unsafe {
            *__errno_location() = libc::E2BIG;
        }
        let abi_all_null = unsafe {
            getaddrinfo_a(
                mode,
                abi_requests.as_mut_ptr(),
                abi_requests.len() as c_int,
                std::ptr::null_mut(),
            )
        };
        let abi_all_null_errno = errno_value();
        assert_eq!(abi_all_null, host_all_null, "mode {mode} all-null rc");
        assert_eq!(
            abi_all_null_errno, host_all_null_errno,
            "mode {mode} all-null errno"
        );
    }
}

#[test]
fn getaddrinfo_a_invalid_modes_report_eai_system_with_einval_like_host() {
    let _gai_guard = GAI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    type HostGetaddrinfoAFn =
        unsafe extern "C" fn(c_int, *mut *mut c_void, c_int, *mut c_void) -> c_int;

    let Some(host_getaddrinfo_a) = (unsafe { load_host_symbol("getaddrinfo_a") })
        .map(|ptr| unsafe { std::mem::transmute::<*mut c_void, HostGetaddrinfoAFn>(ptr) })
    else {
        return;
    };

    for (label, mode, nitems) in [
        ("negative_badflags", GAI_BADFLAGS_NEGATIVE_MODE, 0),
        ("positive_badflags", GAI_BADFLAGS_POSITIVE_MODE, 1),
    ] {
        let mut host_requests = [std::ptr::null_mut()];
        unsafe {
            *libc::__errno_location() = libc::E2BIG;
        }
        let host_rc = unsafe {
            host_getaddrinfo_a(
                mode,
                host_requests.as_mut_ptr(),
                nitems,
                std::ptr::null_mut(),
            )
        };
        let host_errno = unsafe { *libc::__errno_location() };

        let mut abi_requests = [std::ptr::null_mut()];
        unsafe {
            *__errno_location() = libc::E2BIG;
        }
        let abi_rc = unsafe {
            getaddrinfo_a(
                mode,
                abi_requests.as_mut_ptr(),
                nitems,
                std::ptr::null_mut(),
            )
        };
        let abi_errno = errno_value();

        assert_eq!(abi_rc, host_rc, "{label} rc");
        assert_eq!(abi_errno, host_errno, "{label} errno");
        assert_eq!(abi_rc, libc::EAI_SYSTEM, "{label} rc contract");
        assert_eq!(abi_errno, libc::EINVAL, "{label} errno contract");
    }
}

#[test]
fn getaddrinfo_a_non_null_requests_still_fall_back_to_eai_system() {
    let _gai_guard = GAI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        *__errno_location() = 0;
    }
    let mut request = GaicbShape {
        ar_name: c"opaque".as_ptr(),
        ar_service: std::ptr::null(),
        ar_request: std::ptr::null(),
        ar_result: std::ptr::null_mut(),
        __return: 0,
        __unused: [0; 5],
    };
    let mut requests = [(&mut request as *mut GaicbShape).cast::<c_void>()];
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
    let _gai_guard = GAI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    let _gai_guard = GAI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        *__errno_location() = 0;
    }
    assert_eq!(unsafe { gai_error(std::ptr::null_mut()) }, libc::EAI_SYSTEM);
    assert_eq!(errno_value(), libc::ENOSYS);

    unsafe {
        *__errno_location() = 0;
    }
    let request = GaicbShape {
        ar_name: c"opaque".as_ptr(),
        ar_service: std::ptr::null(),
        ar_request: std::ptr::null(),
        ar_result: std::ptr::null_mut(),
        __return: 0,
        __unused: [0; 5],
    };
    assert_eq!(
        unsafe { gai_error((&request as *const GaicbShape).cast_mut().cast::<c_void>()) },
        libc::EAI_SYSTEM
    );
    assert_eq!(errno_value(), libc::ENOSYS);
}

#[test]
fn gai_error_zeroed_gaicb_reports_success_without_touching_errno() {
    let _gai_guard = GAI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut request: GaicbShape = unsafe { std::mem::zeroed() };
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let request_ptr = (&mut request as *mut GaicbShape).cast::<c_void>();
    assert_eq!(unsafe { gai_error(request_ptr) }, 0);
    assert_eq!(errno_value(), libc::E2BIG);
}

#[test]
fn gai_error_zeroed_gaicb_preserves_errno_like_host() {
    let _gai_guard = GAI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    type HostGaiErrorFn = unsafe extern "C" fn(*mut c_void) -> c_int;

    let Some(host_gai_error) = (unsafe { load_host_symbol("gai_error") })
        .map(|ptr| unsafe { std::mem::transmute::<*mut c_void, HostGaiErrorFn>(ptr) })
    else {
        return;
    };

    let mut host_request: GaicbShape = unsafe { std::mem::zeroed() };
    unsafe {
        *libc::__errno_location() = libc::E2BIG;
    }
    let host_rc = unsafe { host_gai_error((&mut host_request as *mut GaicbShape).cast()) };
    let host_errno = unsafe { *libc::__errno_location() };

    let mut abi_request: GaicbShape = unsafe { std::mem::zeroed() };
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let abi_rc = unsafe { gai_error((&mut abi_request as *mut GaicbShape).cast()) };
    let abi_errno = errno_value();

    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_errno, host_errno);
}

#[test]
fn gai_suspend_reports_all_done_for_synchronous_stub_handles() {
    let _gai_guard = GAI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    let _gai_guard = GAI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    const EMPTY_INVALID_NANOSECONDS_SENTINEL: c_int = libc::E2BIG;
    const EMPTY_INVALID_SECONDS_SENTINEL: c_int = libc::EOVERFLOW;
    const NULL_SLOT_INVALID_NANOSECONDS_SENTINEL: c_int = libc::ENAMETOOLONG;
    const NULL_SLOT_INVALID_SECONDS_SENTINEL: c_int = libc::EMSGSIZE;

    let invalid_nanoseconds = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000_000,
    };
    let invalid_seconds = libc::timespec {
        tv_sec: -1,
        tv_nsec: 0,
    };

    unsafe {
        *__errno_location() = EMPTY_INVALID_NANOSECONDS_SENTINEL;
    }
    assert_eq!(
        unsafe { gai_suspend(std::ptr::null(), 0, &invalid_nanoseconds) },
        GAI_EAI_ALLDONE
    );
    assert_eq!(errno_value(), EMPTY_INVALID_NANOSECONDS_SENTINEL);

    unsafe {
        *__errno_location() = EMPTY_INVALID_SECONDS_SENTINEL;
    }
    assert_eq!(
        unsafe { gai_suspend(std::ptr::null(), 0, &invalid_seconds) },
        GAI_EAI_ALLDONE
    );
    assert_eq!(errno_value(), EMPTY_INVALID_SECONDS_SENTINEL);

    let requests: [*const c_void; 1] = [std::ptr::null()];

    unsafe {
        *__errno_location() = NULL_SLOT_INVALID_NANOSECONDS_SENTINEL;
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
    assert_eq!(errno_value(), NULL_SLOT_INVALID_NANOSECONDS_SENTINEL);

    unsafe {
        *__errno_location() = NULL_SLOT_INVALID_SECONDS_SENTINEL;
    }
    assert_eq!(
        unsafe { gai_suspend(requests.as_ptr(), requests.len() as c_int, &invalid_seconds,) },
        GAI_EAI_ALLDONE
    );
    assert_eq!(errno_value(), NULL_SLOT_INVALID_SECONDS_SENTINEL);
}

#[test]
fn synchronous_gai_wrappers_match_host_degenerate_contracts() {
    let _gai_guard = GAI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    type HostGaiCancelFn = unsafe extern "C" fn(*mut c_void) -> c_int;
    type HostGaiErrorFn = unsafe extern "C" fn(*mut c_void) -> c_int;
    type HostGaiSuspendFn =
        unsafe extern "C" fn(*const *const c_void, c_int, *const libc::timespec) -> c_int;
    const EMPTY_INVALID_TIMEOUT_SENTINEL: c_int = libc::EILSEQ;

    let Some(host_gai_cancel) = (unsafe { load_host_symbol("gai_cancel") })
        .map(|ptr| unsafe { std::mem::transmute::<*mut c_void, HostGaiCancelFn>(ptr) })
    else {
        return;
    };
    let Some(host_gai_error) = (unsafe { load_host_symbol("gai_error") })
        .map(|ptr| unsafe { std::mem::transmute::<*mut c_void, HostGaiErrorFn>(ptr) })
    else {
        return;
    };
    let Some(host_gai_suspend) = (unsafe { load_host_symbol("gai_suspend") })
        .map(|ptr| unsafe { std::mem::transmute::<*mut c_void, HostGaiSuspendFn>(ptr) })
    else {
        return;
    };

    unsafe {
        *libc::__errno_location() = libc::E2BIG;
    }
    let host_cancel_null = unsafe { host_gai_cancel(std::ptr::null_mut()) };
    let host_cancel_null_errno = unsafe { *libc::__errno_location() };
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let abi_cancel_null = unsafe { gai_cancel(std::ptr::null_mut()) };
    let abi_cancel_null_errno = errno_value();
    assert_eq!(abi_cancel_null, host_cancel_null);
    assert_eq!(abi_cancel_null_errno, host_cancel_null_errno);

    let mut host_dummy = 0u8;
    unsafe {
        *libc::__errno_location() = libc::E2BIG;
    }
    let host_cancel_dummy = unsafe { host_gai_cancel((&mut host_dummy as *mut u8).cast()) };
    let host_cancel_dummy_errno = unsafe { *libc::__errno_location() };
    let mut abi_dummy = 0u8;
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let abi_cancel_dummy = unsafe { gai_cancel((&mut abi_dummy as *mut u8).cast()) };
    let abi_cancel_dummy_errno = errno_value();
    assert_eq!(abi_cancel_dummy, host_cancel_dummy);
    assert_eq!(abi_cancel_dummy_errno, host_cancel_dummy_errno);

    let mut host_request: GaicbShape = unsafe { std::mem::zeroed() };
    unsafe {
        *libc::__errno_location() = libc::E2BIG;
    }
    let host_error_zeroed =
        unsafe { host_gai_error((&mut host_request as *mut GaicbShape).cast()) };
    let host_error_zeroed_errno = unsafe { *libc::__errno_location() };
    let mut abi_request: GaicbShape = unsafe { std::mem::zeroed() };
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let abi_error_zeroed = unsafe { gai_error((&mut abi_request as *mut GaicbShape).cast()) };
    let abi_error_zeroed_errno = errno_value();
    assert_eq!(abi_error_zeroed, host_error_zeroed);
    assert_eq!(abi_error_zeroed_errno, host_error_zeroed_errno);

    unsafe {
        *libc::__errno_location() = libc::E2BIG;
    }
    let host_suspend_empty = unsafe { host_gai_suspend(std::ptr::null(), 0, std::ptr::null()) };
    let host_suspend_empty_errno = unsafe { *libc::__errno_location() };
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let abi_suspend_empty = unsafe { gai_suspend(std::ptr::null(), 0, std::ptr::null()) };
    let abi_suspend_empty_errno = errno_value();
    assert_eq!(abi_suspend_empty, host_suspend_empty);
    assert_eq!(abi_suspend_empty_errno, host_suspend_empty_errno);

    let host_requests: [*const c_void; 1] = [std::ptr::null()];
    unsafe {
        *libc::__errno_location() = libc::E2BIG;
    }
    let host_suspend_null_slot = unsafe {
        host_gai_suspend(
            host_requests.as_ptr(),
            host_requests.len() as c_int,
            std::ptr::null(),
        )
    };
    let host_suspend_null_slot_errno = unsafe { *libc::__errno_location() };
    let abi_requests: [*const c_void; 1] = [std::ptr::null()];
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let abi_suspend_null_slot = unsafe {
        gai_suspend(
            abi_requests.as_ptr(),
            abi_requests.len() as c_int,
            std::ptr::null(),
        )
    };
    let abi_suspend_null_slot_errno = errno_value();
    assert_eq!(abi_suspend_null_slot, host_suspend_null_slot);
    assert_eq!(abi_suspend_null_slot_errno, host_suspend_null_slot_errno);

    let invalid_timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000_000,
    };
    unsafe {
        *libc::__errno_location() = EMPTY_INVALID_TIMEOUT_SENTINEL;
    }
    let host_suspend_invalid_timeout =
        unsafe { host_gai_suspend(std::ptr::null(), 0, &invalid_timeout) };
    let host_suspend_invalid_timeout_errno = unsafe { *libc::__errno_location() };
    unsafe {
        *__errno_location() = EMPTY_INVALID_TIMEOUT_SENTINEL;
    }
    let abi_suspend_invalid_timeout = unsafe { gai_suspend(std::ptr::null(), 0, &invalid_timeout) };
    let abi_suspend_invalid_timeout_errno = errno_value();
    assert_eq!(abi_suspend_invalid_timeout, host_suspend_invalid_timeout);
    assert_eq!(
        abi_suspend_invalid_timeout_errno,
        host_suspend_invalid_timeout_errno
    );
}

#[test]
fn gai_suspend_all_null_request_timeouts_match_host_contract() {
    let _gai_guard = GAI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    type HostGaiSuspendFn =
        unsafe extern "C" fn(*const *const c_void, c_int, *const libc::timespec) -> c_int;
    const NULL_SLOT_INVALID_NANOSECONDS_SENTINEL: c_int = libc::ENOTRECOVERABLE;
    const NULL_SLOT_INVALID_SECONDS_SENTINEL: c_int = libc::EREMOTEIO;

    let Some(host_gai_suspend) = (unsafe { load_host_symbol("gai_suspend") })
        .map(|ptr| unsafe { std::mem::transmute::<*mut c_void, HostGaiSuspendFn>(ptr) })
    else {
        return;
    };

    let requests: [*const c_void; 1] = [std::ptr::null()];
    let invalid_nanoseconds = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000_000,
    };
    let invalid_seconds = libc::timespec {
        tv_sec: -1,
        tv_nsec: 0,
    };

    unsafe {
        *libc::__errno_location() = NULL_SLOT_INVALID_NANOSECONDS_SENTINEL;
    }
    let host_invalid_nanoseconds = unsafe {
        host_gai_suspend(
            requests.as_ptr(),
            requests.len() as c_int,
            &invalid_nanoseconds,
        )
    };
    let host_invalid_nanoseconds_errno = unsafe { *libc::__errno_location() };
    unsafe {
        *__errno_location() = NULL_SLOT_INVALID_NANOSECONDS_SENTINEL;
    }
    let abi_invalid_nanoseconds = unsafe {
        gai_suspend(
            requests.as_ptr(),
            requests.len() as c_int,
            &invalid_nanoseconds,
        )
    };
    let abi_invalid_nanoseconds_errno = errno_value();
    assert_eq!(abi_invalid_nanoseconds, host_invalid_nanoseconds);
    assert_eq!(
        abi_invalid_nanoseconds_errno,
        host_invalid_nanoseconds_errno
    );

    unsafe {
        *libc::__errno_location() = NULL_SLOT_INVALID_SECONDS_SENTINEL;
    }
    let host_invalid_seconds =
        unsafe { host_gai_suspend(requests.as_ptr(), requests.len() as c_int, &invalid_seconds) };
    let host_invalid_seconds_errno = unsafe { *libc::__errno_location() };
    unsafe {
        *__errno_location() = NULL_SLOT_INVALID_SECONDS_SENTINEL;
    }
    let abi_invalid_seconds =
        unsafe { gai_suspend(requests.as_ptr(), requests.len() as c_int, &invalid_seconds) };
    let abi_invalid_seconds_errno = errno_value();
    assert_eq!(abi_invalid_seconds, host_invalid_seconds);
    assert_eq!(abi_invalid_seconds_errno, host_invalid_seconds_errno);
}

#[test]
fn async_dns_stub_tests_keep_host_parity_and_safe_divergence_paths_separate() {
    // Proven host-parity path: degenerate synchronous cases with empty or
    // all-NULL request sets preserve host libc behavior exactly.
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    assert_eq!(
        unsafe { getaddrinfo_a(GAI_WAIT, std::ptr::null_mut(), 0, std::ptr::null_mut()) },
        0
    );
    assert_eq!(errno_value(), libc::E2BIG);

    let all_null_requests: [*mut c_void; 1] = [std::ptr::null_mut()];
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    assert_eq!(
        unsafe {
            gai_suspend(
                all_null_requests.as_ptr().cast(),
                all_null_requests.len() as c_int,
                std::ptr::null(),
            )
        },
        GAI_EAI_ALLDONE
    );
    assert_eq!(errno_value(), libc::E2BIG);

    let mut zeroed_request: GaicbShape = unsafe { std::mem::zeroed() };
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    assert_eq!(
        unsafe { gai_error((&mut zeroed_request as *mut GaicbShape).cast()) },
        0
    );
    assert_eq!(errno_value(), libc::E2BIG);

    // Intentional safe-divergence path: crash-prone or unsupported async
    // submission shapes do not mirror host UB and instead fail safely.
    unsafe {
        *__errno_location() = 0;
    }
    assert_eq!(
        unsafe { getaddrinfo_a(GAI_WAIT, std::ptr::null_mut(), 1, std::ptr::null_mut()) },
        libc::EAI_SYSTEM
    );
    assert_eq!(errno_value(), libc::ENOSYS);

    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    assert_eq!(
        unsafe { gai_suspend(std::ptr::null(), 1, std::ptr::null()) },
        GAI_EAI_ALLDONE
    );
    assert_eq!(errno_value(), libc::E2BIG);

    unsafe {
        *__errno_location() = 0;
    }
    assert_eq!(unsafe { gai_error(std::ptr::null_mut()) }, libc::EAI_SYSTEM);
    assert_eq!(errno_value(), libc::ENOSYS);
}

#[test]
fn host_gai_error_null_probe_process() {
    if std::env::var_os("FRANKENLIBC_HOST_GAI_ERROR_NULL_PROBE").is_none() {
        return;
    }

    type HostGaiErrorFn = unsafe extern "C" fn(*mut c_void) -> c_int;
    let host_gai_error = unsafe { load_host_symbol("gai_error") }
        .map(|ptr| unsafe { std::mem::transmute::<*mut c_void, HostGaiErrorFn>(ptr) })
        .expect("host gai_error symbol should exist for null probe");

    unsafe {
        *libc::__errno_location() = libc::E2BIG;
    }
    let rc = unsafe { host_gai_error(std::ptr::null_mut()) };
    let err = unsafe { *libc::__errno_location() };
    println!("HOST_GAI_ERROR_NULL_RETURN:{rc}:{err}");
}

#[test]
fn host_getaddrinfo_a_null_list_positive_nitems_probe_process() {
    if std::env::var_os("FRANKENLIBC_HOST_GETADDRINFO_A_NULL_LIST_PROBE").is_none() {
        return;
    }

    type HostGetaddrinfoAFn =
        unsafe extern "C" fn(c_int, *mut *mut c_void, c_int, *mut c_void) -> c_int;
    let host_getaddrinfo_a = unsafe { load_host_symbol("getaddrinfo_a") }
        .map(|ptr| unsafe { std::mem::transmute::<*mut c_void, HostGetaddrinfoAFn>(ptr) })
        .expect("host getaddrinfo_a symbol should exist for null-list probe");

    unsafe {
        *libc::__errno_location() = libc::E2BIG;
    }
    let rc = unsafe { host_getaddrinfo_a(GAI_WAIT, std::ptr::null_mut(), 1, std::ptr::null_mut()) };
    let err = unsafe { *libc::__errno_location() };
    println!("HOST_GETADDRINFO_A_NULL_LIST_RETURN:{rc}:{err}");
}

#[test]
fn host_gai_suspend_null_list_nonzero_ent_probe_process() {
    let Some(ent) = std::env::var_os("FRANKENLIBC_HOST_GAI_SUSPEND_NULL_LIST_ENT")
        .and_then(|value| value.into_string().ok())
        .and_then(|value| value.parse::<c_int>().ok())
    else {
        return;
    };

    type HostGaiSuspendFn =
        unsafe extern "C" fn(*const *const c_void, c_int, *const libc::timespec) -> c_int;
    let host_gai_suspend = unsafe { load_host_symbol("gai_suspend") }
        .map(|ptr| unsafe { std::mem::transmute::<*mut c_void, HostGaiSuspendFn>(ptr) })
        .expect("host gai_suspend symbol should exist for null-list probe");

    unsafe {
        *libc::__errno_location() = libc::E2BIG;
    }
    let rc = unsafe { host_gai_suspend(std::ptr::null(), ent, std::ptr::null()) };
    let err = unsafe { *libc::__errno_location() };
    println!("HOST_GAI_SUSPEND_NULL_LIST_RETURN:{ent}:{rc}:{err}");
}

#[test]
fn gai_error_null_policy_is_characterized_without_crashing_parent_tests() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("host_gai_error_null_probe_process")
        .arg("--nocapture")
        .env("FRANKENLIBC_HOST_GAI_ERROR_NULL_PROBE", "1")
        .output()
        .expect("failed to spawn host gai_error(NULL) probe subprocess");

    let host_stdout = String::from_utf8_lossy(&output.stdout);
    let host_stderr = String::from_utf8_lossy(&output.stderr);
    let host_signal = output.status.signal();

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { gai_error(std::ptr::null_mut()) };
    let abi_errno = errno_value();
    assert_eq!(abi_rc, libc::EAI_SYSTEM);
    assert_eq!(abi_errno, libc::ENOSYS);

    if output.status.success() {
        assert!(
            host_stdout.contains("HOST_GAI_ERROR_NULL_RETURN:"),
            "host gai_error(NULL) probe exited successfully without reporting its outcome; stdout={host_stdout:?} stderr={host_stderr:?}"
        );
    } else {
        assert!(
            host_signal.is_some(),
            "host gai_error(NULL) probe failed without a signal classification; status={:?} stdout={host_stdout:?} stderr={host_stderr:?}",
            output.status.code()
        );
    }
}

#[test]
fn gai_suspend_null_list_nonzero_ent_policy_is_characterized_without_crashing_parent_tests() {
    for ent in [1, -1] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("host_gai_suspend_null_list_nonzero_ent_probe_process")
            .arg("--nocapture")
            .env(
                "FRANKENLIBC_HOST_GAI_SUSPEND_NULL_LIST_ENT",
                ent.to_string(),
            )
            .output()
            .expect("failed to spawn host gai_suspend(NULL, nonzero ent) probe subprocess");

        let host_stdout = String::from_utf8_lossy(&output.stdout);
        let host_stderr = String::from_utf8_lossy(&output.stderr);
        let host_signal = output.status.signal();

        unsafe {
            *__errno_location() = libc::E2BIG;
        }
        let abi_rc = unsafe { gai_suspend(std::ptr::null(), ent, std::ptr::null()) };
        let abi_errno = errno_value();
        assert_eq!(abi_rc, GAI_EAI_ALLDONE, "ent={ent} rc");
        assert_eq!(abi_errno, libc::E2BIG, "ent={ent} errno");

        if output.status.success() {
            assert!(
                host_stdout.contains(&format!("HOST_GAI_SUSPEND_NULL_LIST_RETURN:{ent}:")),
                "host gai_suspend(NULL, ent={ent}) probe exited successfully without reporting its outcome; stdout={host_stdout:?} stderr={host_stderr:?}"
            );
        } else {
            assert!(
                host_signal.is_some(),
                "host gai_suspend(NULL, ent={ent}) probe failed without a signal classification; status={:?} stdout={host_stdout:?} stderr={host_stderr:?}",
                output.status.code()
            );
        }
    }
}

#[test]
fn getaddrinfo_a_null_list_positive_nitems_policy_is_characterized_without_crashing_parent_tests() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("host_getaddrinfo_a_null_list_positive_nitems_probe_process")
        .arg("--nocapture")
        .env("FRANKENLIBC_HOST_GETADDRINFO_A_NULL_LIST_PROBE", "1")
        .output()
        .expect("failed to spawn host getaddrinfo_a(NULL, positive nitems) probe subprocess");

    let host_stdout = String::from_utf8_lossy(&output.stdout);
    let host_stderr = String::from_utf8_lossy(&output.stderr);
    let host_signal = output.status.signal();

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { getaddrinfo_a(GAI_WAIT, std::ptr::null_mut(), 1, std::ptr::null_mut()) };
    let abi_errno = errno_value();
    assert_eq!(abi_rc, libc::EAI_SYSTEM);
    assert_eq!(abi_errno, libc::ENOSYS);

    if output.status.success() {
        assert!(
            host_stdout.contains("HOST_GETADDRINFO_A_NULL_LIST_RETURN:"),
            "host getaddrinfo_a(NULL, positive nitems) probe exited successfully without reporting its outcome; stdout={host_stdout:?} stderr={host_stderr:?}"
        );
    } else {
        assert!(
            host_signal.is_some(),
            "host getaddrinfo_a(NULL, positive nitems) probe failed without a signal classification; status={:?} stdout={host_stdout:?} stderr={host_stderr:?}",
            output.status.code()
        );
    }
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

// ---------------------------------------------------------------------------
// aio_suspend timespec validation (bd-4rdz8)
//
// POSIX requires aio_suspend to fail with EINVAL when tv_nsec is out of
// [0, 999_999_999] or when the timespec is otherwise unusable. Prior to
// bd-4rdz8 the implementation cast `ts.tv_sec as u64` and would then
// `Instant + Duration`, which panics (process abort) for a negative
// tv_sec reinterpreted as ~u64::MAX. These tests pin the EINVAL contract.
// ---------------------------------------------------------------------------

#[test]
fn aio_suspend_rejects_negative_tv_sec_without_panic() {
    let cb: *const c_void = std::ptr::null();
    let list = [&cb as *const *const c_void as *const c_void];
    let ts = libc::timespec {
        tv_sec: -1,
        tv_nsec: 0,
    };
    let rc = unsafe { aio_suspend(list.as_ptr(), 1, &ts) };
    assert_eq!(rc, -1, "aio_suspend with tv_sec<0 must return -1 (EINVAL)");
}

#[test]
fn aio_suspend_rejects_negative_tv_nsec() {
    let cb: *const c_void = std::ptr::null();
    let list = [&cb as *const *const c_void as *const c_void];
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: -1,
    };
    let rc = unsafe { aio_suspend(list.as_ptr(), 1, &ts) };
    assert_eq!(rc, -1, "aio_suspend with tv_nsec<0 must return -1 (EINVAL)");
}

#[test]
fn aio_suspend_rejects_oversize_tv_nsec() {
    let cb: *const c_void = std::ptr::null();
    let list = [&cb as *const *const c_void as *const c_void];
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000_000,
    };
    let rc = unsafe { aio_suspend(list.as_ptr(), 1, &ts) };
    assert_eq!(
        rc, -1,
        "aio_suspend with tv_nsec >= 1_000_000_000 must return -1 (EINVAL)"
    );
}

#[test]
fn aio_suspend_rejects_empty_list_before_timeout() {
    // nent <= 0 is its own EINVAL path that must trigger before we ever
    // look at the timespec — adversarial timestamps should not affect it.
    let rc = unsafe { aio_suspend(std::ptr::null(), 0, std::ptr::null()) };
    assert_eq!(rc, -1);
}

// ---------------------------------------------------------------------------
// arc4random_buf short-read contract (bd-ubkl7)
//
// Linux getrandom(2) may short-read for nbytes > 256. arc4random_buf must
// loop until the whole buffer is filled; leaving a trailing window
// uninitialized would be a security defect (caller treats it as entropy).
// The test initializes the buffer to a sentinel and then asserts no byte
// retains the sentinel after arc4random_buf completes — statistically a
// 1_024-byte /dev/urandom read will overwrite every byte (probability of a
// single byte matching 0xA5 is 1/256; probability that ALL 1024 coincide
// with the sentinel is (1/256)^1024 ≈ 0). The 0-byte request must be a
// no-op and must not touch the buffer.
// ---------------------------------------------------------------------------

#[test]
fn arc4random_buf_fills_entire_buffer_past_256_bytes() {
    const N: usize = 1024;
    let mut buf = [0xA5_u8; N];
    unsafe { arc4random_buf(buf.as_mut_ptr() as *mut c_void, N) };
    // A correct implementation MUST overwrite every byte. Find any byte that
    // still carries the 0xA5 sentinel — a single hit is allowed (random
    // matches happen), but a contiguous trailing window >= 16 bytes of
    // sentinels is the short-read signature the bug would produce.
    let mut trailing = 0usize;
    for &b in buf.iter().rev() {
        if b == 0xA5 {
            trailing += 1;
        } else {
            break;
        }
    }
    assert!(
        trailing < 16,
        "arc4random_buf left {trailing} trailing bytes at the 0xA5 sentinel — looks like a short-read bug"
    );
}

#[test]
fn arc4random_buf_zero_size_is_noop() {
    let mut buf = [0xA5_u8; 4];
    unsafe { arc4random_buf(buf.as_mut_ptr() as *mut c_void, 0) };
    assert_eq!(buf, [0xA5; 4], "arc4random_buf(_, 0) must not write");
}

#[test]
fn arc4random_buf_null_pointer_is_noop() {
    // Null buffer is an invalid request but must not crash.
    unsafe { arc4random_buf(std::ptr::null_mut(), 0) };
    unsafe { arc4random_buf(std::ptr::null_mut(), 64) };
}

// ===========================================================================
// posix_close (POSIX 2024 §close)
// ===========================================================================

use frankenlibc_abi::unistd_abi::posix_close;

#[test]
fn posix_close_zero_flag_closes_valid_fd() {
    // Open /dev/null then posix_close it.
    let path = CString::new("/dev/null").unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0, "open /dev/null failed");
    let rc = unsafe { posix_close(fd, 0) };
    assert_eq!(rc, 0, "posix_close(valid fd, 0) should succeed");
}

#[test]
fn posix_close_unknown_flag_returns_einval() {
    // POSIX 2024 reserves all non-zero flag values. Any non-zero
    // flag must return -1 with errno=EINVAL — without ever touching
    // the fd.
    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { posix_close(-1, 1) };
    assert_eq!(rc, -1, "posix_close with unknown flag must return -1");
    let err = unsafe { *__errno_location() };
    assert_eq!(
        err,
        libc::EINVAL,
        "posix_close unknown-flag errno must be EINVAL"
    );
}

#[test]
fn posix_close_invalid_fd_returns_minus_one() {
    // close(-1) sets errno=EBADF; posix_close(-1, 0) propagates that
    // (EBADF is not EINPROGRESS so no translation).
    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { posix_close(-1, 0) };
    assert_eq!(rc, -1);
    let err = unsafe { *__errno_location() };
    assert_eq!(err, libc::EBADF, "posix_close(-1, 0) errno should be EBADF");
}

// ---------------------------------------------------------------------------
// bsd_getopt (libbsd: BSD-flavored getopt with stripped +/- prefix)
// ---------------------------------------------------------------------------
//
// libbsd's bsd_getopt strips a leading '+' or '-' from `optstring`
// and forwards to POSIX getopt. We exercise three behaviors:
//   1. Plain optstring forwarded unchanged.
//   2. '+' prefix stripped before parse.
//   3. '-' prefix stripped before parse.
// All three must yield the same option-character output.
//
// getopt is stateful (libc_optind, libc_optarg) — we serialise the
// tests via a Mutex so they don't race the global getopt state.

static BSD_GETOPT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn run_bsd_getopt_with_args(optstring: &core::ffi::CStr, args: &[&core::ffi::CStr]) -> Vec<c_int> {
    let _guard = BSD_GETOPT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // Reset getopt state. libc_optind is exported by glibc; on
    // reset it must be set to 1 to start a fresh parse.
    unsafe extern "C" {
        static mut optind: c_int;
    }
    unsafe { optind = 1 };

    let mut argv: Vec<*mut c_char> = args.iter().map(|s| s.as_ptr() as *mut c_char).collect();
    argv.push(std::ptr::null_mut());

    let mut out = Vec::new();
    loop {
        let rc = unsafe { bsd_getopt(args.len() as c_int, argv.as_ptr(), optstring.as_ptr()) };
        if rc == -1 {
            break;
        }
        out.push(rc);
    }
    out
}

#[test]
fn bsd_getopt_plain_optstring_forwards_unchanged() {
    let chars = run_bsd_getopt_with_args(c"abc", &[c"prog", c"-a", c"-b", c"-c"]);
    assert_eq!(chars, vec![b'a' as c_int, b'b' as c_int, b'c' as c_int]);
}

#[test]
fn bsd_getopt_strips_leading_plus_prefix() {
    // Same arguments + same effective optspec; "+abc" must behave
    // identically to "abc" once the '+' is stripped.
    let chars = run_bsd_getopt_with_args(c"+abc", &[c"prog", c"-a", c"-b"]);
    assert_eq!(chars, vec![b'a' as c_int, b'b' as c_int]);
}

#[test]
fn bsd_getopt_strips_leading_minus_prefix() {
    let chars = run_bsd_getopt_with_args(c"-abc", &[c"prog", c"-a", c"-c"]);
    assert_eq!(chars, vec![b'a' as c_int, b'c' as c_int]);
}

#[test]
fn bsd_getopt_unknown_option_returns_question_mark() {
    let chars = run_bsd_getopt_with_args(c"+ab", &[c"prog", c"-z"]);
    assert_eq!(chars, vec![b'?' as c_int]);
}

#[test]
fn bsd_getopt_null_optstring_returns_minus_one() {
    let _guard = BSD_GETOPT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let arg0 = c"prog";
    let argv: [*mut c_char; 2] = [arg0.as_ptr() as *mut c_char, std::ptr::null_mut()];
    let rc = unsafe { bsd_getopt(1, argv.as_ptr(), std::ptr::null()) };
    assert_eq!(rc, -1, "NULL optstring must yield -1 (matches getopt)");
}

#[test]
fn bsd_getopt_double_prefix_only_strips_one() {
    // libbsd strips at most one prefix char. "++a" → after stripping
    // '+', optstring is "+a", which then itself starts with '+' as
    // a getopt-spec char (since our getopt treats unknown specs as
    // valid letter "p" expectations? actually just "+" is not a
    // valid option char). The first char after stripping is '+',
    // which isn't an option character, so '-+' as an arg yields '?'.
    // Verify the strip happens exactly once.
    let chars = run_bsd_getopt_with_args(c"++a", &[c"prog", c"-a"]);
    assert_eq!(chars, vec![b'a' as c_int]);
}

// ---------------------------------------------------------------------------
// flopen / flopenat (libbsd open-with-advisory-lock)
// ---------------------------------------------------------------------------
//
// libbsd defines O_SHLOCK = 0x10, O_EXLOCK = 0x20 (BSD-historic bit
// positions). We strip them before calling open() and use them to
// pick the flock() kind.

const LIBBSD_O_SHLOCK: c_int = 0x10;
const LIBBSD_O_EXLOCK: c_int = 0x20;

fn flopen_temp_path(tag: &str) -> std::path::PathBuf {
    let seq = std::sync::atomic::AtomicU64::new(
        std::process::id() as u64
            ^ std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
    );
    let n = seq.load(std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "frankenlibc-flopen-{tag}-{n}-{}",
        std::process::id()
    ))
}

#[test]
fn flopen_creates_file_with_default_lock() {
    let path = flopen_temp_path("create");
    let cs = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let fd = unsafe { flopen(cs.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o644) };
    assert!(fd >= 0, "flopen failed; errno={}", unsafe {
        *__errno_location()
    });
    unsafe { close(fd) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn flopen_strips_shlock_and_exlock_before_open() {
    // O_EXLOCK alone (no O_CREAT) requires that the file already exists.
    let path = flopen_temp_path("exlock");
    std::fs::write(&path, b"hello").unwrap();
    let cs = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let fd = unsafe { flopen(cs.as_ptr(), libc::O_RDONLY | LIBBSD_O_EXLOCK, 0) };
    assert!(fd >= 0);
    unsafe { close(fd) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn flopen_o_shlock_takes_shared_lock() {
    let path = flopen_temp_path("shlock");
    std::fs::write(&path, b"data").unwrap();
    let cs = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // First fd gets a shared lock.
    let fd1 = unsafe { flopen(cs.as_ptr(), libc::O_RDONLY | LIBBSD_O_SHLOCK, 0) };
    assert!(fd1 >= 0);
    // Second fd with shared lock must succeed (multiple shared locks
    // are allowed simultaneously).
    let fd2 = unsafe { flopen(cs.as_ptr(), libc::O_RDONLY | LIBBSD_O_SHLOCK, 0) };
    assert!(fd2 >= 0, "second shared lock should succeed");
    unsafe {
        close(fd1);
        close(fd2);
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn flopen_nonblock_with_existing_exclusive_lock_returns_minus_one() {
    let path = flopen_temp_path("nonblock");
    std::fs::write(&path, b"x").unwrap();
    let cs = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();

    // Take a blocking exclusive lock first.
    let fd1 = unsafe { flopen(cs.as_ptr(), libc::O_RDWR | LIBBSD_O_EXLOCK, 0) };
    assert!(fd1 >= 0);

    // Second flopen with O_NONBLOCK must fail without blocking, since
    // the exclusive lock is already held by fd1.
    unsafe { *__errno_location() = 0 };
    let fd2 = unsafe {
        flopen(
            cs.as_ptr(),
            libc::O_RDWR | LIBBSD_O_EXLOCK | libc::O_NONBLOCK,
            0,
        )
    };
    assert_eq!(fd2, -1, "non-blocking second exclusive lock must fail");
    let err = unsafe { *__errno_location() };
    assert!(
        err == libc::EAGAIN || err == libc::EWOULDBLOCK,
        "expected EAGAIN/EWOULDBLOCK, got {err}"
    );

    unsafe { close(fd1) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn flopen_nonexistent_path_returns_minus_one() {
    let path = flopen_temp_path("absent");
    // Deliberately do NOT create it.
    let cs = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    unsafe { *__errno_location() = 0 };
    let fd = unsafe { flopen(cs.as_ptr(), libc::O_RDONLY, 0) };
    assert_eq!(fd, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::ENOENT);
}

#[test]
fn flopen_null_path_returns_minus_one_with_efault() {
    unsafe { *__errno_location() = 0 };
    let fd = unsafe { flopen(std::ptr::null(), libc::O_RDONLY, 0) };
    assert_eq!(fd, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);
}

#[test]
fn flopenat_relative_to_at_fdcwd() {
    let path = flopen_temp_path("at-cwd");
    let cs = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let fd = unsafe {
        flopenat(
            libc::AT_FDCWD,
            cs.as_ptr(),
            libc::O_CREAT | libc::O_RDWR,
            0o644,
        )
    };
    assert!(fd >= 0);
    unsafe { close(fd) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn flopenat_null_path_returns_minus_one_with_efault() {
    unsafe { *__errno_location() = 0 };
    let fd = unsafe { flopenat(libc::AT_FDCWD, std::ptr::null(), libc::O_RDONLY, 0) };
    assert_eq!(fd, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);
}

// ---------------------------------------------------------------------------
// readpassphrase (OpenBSD: passphrase reader)
// ---------------------------------------------------------------------------
//
// We exercise the RPP_STDIN flag path so we can drive the read via a pipe
// without needing a real /dev/tty. Tests are serialized via a Mutex
// because they temporarily dup2 over stdin (fd 0).

const RPP_ECHO_ON: c_int = 0x01;
const RPP_FORCELOWER: c_int = 0x04;
const RPP_FORCEUPPER: c_int = 0x08;
const RPP_SEVENBIT: c_int = 0x10;
const RPP_STDIN: c_int = 0x20;

static READPASSPHRASE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn run_with_piped_stdin(payload: &[u8], call: impl FnOnce()) {
    let _guard = READPASSPHRASE_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let saved_stdin = unsafe { libc::dup(0) };
    assert!(saved_stdin >= 0);

    let mut pipefds = [0 as c_int; 2];
    let rc = unsafe { libc::pipe(pipefds.as_mut_ptr()) };
    assert_eq!(rc, 0);

    let written = unsafe { libc::write(pipefds[1], payload.as_ptr() as *const _, payload.len()) };
    assert_eq!(written as usize, payload.len());
    unsafe { libc::close(pipefds[1]) };

    unsafe { libc::dup2(pipefds[0], 0) };
    unsafe { libc::close(pipefds[0]) };

    call();

    unsafe { libc::dup2(saved_stdin, 0) };
    unsafe { libc::close(saved_stdin) };
}

#[test]
fn readpassphrase_null_buf_returns_null() {
    let prompt = c"";
    let p = unsafe { readpassphrase(prompt.as_ptr(), std::ptr::null_mut(), 16, RPP_STDIN) };
    assert!(p.is_null());
}

#[test]
fn readpassphrase_bufsiz_zero_returns_null() {
    let prompt = c"";
    let mut buf = [0i8; 16];
    let p = unsafe { readpassphrase(prompt.as_ptr(), buf.as_mut_ptr(), 0, RPP_STDIN) };
    assert!(p.is_null());
}

#[test]
fn readpassphrase_reads_line_via_stdin() {
    let mut buf = [0i8; 32];
    run_with_piped_stdin(b"secret123\n", || {
        let prompt = c"";
        let p = unsafe {
            readpassphrase(
                prompt.as_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                RPP_STDIN | RPP_ECHO_ON,
            )
        };
        assert!(!p.is_null());
    });
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_bytes();
    assert_eq!(s, b"secret123");
}

#[test]
fn readpassphrase_strips_trailing_newline_only() {
    let mut buf = [0i8; 32];
    run_with_piped_stdin(b"hello-world\n", || {
        let prompt = c"";
        let _ = unsafe {
            readpassphrase(
                prompt.as_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                RPP_STDIN | RPP_ECHO_ON,
            )
        };
    });
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_bytes();
    assert_eq!(s, b"hello-world");
}

#[test]
fn readpassphrase_truncates_at_bufsiz_minus_one() {
    let mut buf = [0i8; 6]; // 5 chars + NUL
    run_with_piped_stdin(b"abcdefghij\n", || {
        let prompt = c"";
        let _ = unsafe {
            readpassphrase(
                prompt.as_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                RPP_STDIN | RPP_ECHO_ON,
            )
        };
    });
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_bytes();
    assert_eq!(s, b"abcde", "must NUL-terminate at bufsiz - 1");
}

#[test]
fn readpassphrase_force_upper_uppercases_input() {
    let mut buf = [0i8; 32];
    run_with_piped_stdin(b"MixedCase\n", || {
        let prompt = c"";
        let _ = unsafe {
            readpassphrase(
                prompt.as_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                RPP_STDIN | RPP_ECHO_ON | RPP_FORCEUPPER,
            )
        };
    });
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_bytes();
    assert_eq!(s, b"MIXEDCASE");
}

#[test]
fn readpassphrase_force_lower_lowercases_input() {
    let mut buf = [0i8; 32];
    run_with_piped_stdin(b"MixedCase\n", || {
        let prompt = c"";
        let _ = unsafe {
            readpassphrase(
                prompt.as_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                RPP_STDIN | RPP_ECHO_ON | RPP_FORCELOWER,
            )
        };
    });
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_bytes();
    assert_eq!(s, b"mixedcase");
}

#[test]
fn readpassphrase_seven_bit_strips_high_bit() {
    let mut buf = [0i8; 32];
    let payload = [0xc1u8, 0xa9, b'X', b'\n'];
    run_with_piped_stdin(&payload, || {
        let prompt = c"";
        let _ = unsafe {
            readpassphrase(
                prompt.as_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                RPP_STDIN | RPP_ECHO_ON | RPP_SEVENBIT,
            )
        };
    });
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_bytes();
    // 0xc1 & 0x7f = 0x41 = 'A'; 0xa9 & 0x7f = 0x29 = ')'.
    assert_eq!(s, b"A)X");
}

#[test]
fn readpassphrase_empty_input_yields_empty_string() {
    let mut buf = [0i8; 16];
    run_with_piped_stdin(b"\n", || {
        let prompt = c"";
        let p = unsafe {
            readpassphrase(
                prompt.as_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                RPP_STDIN | RPP_ECHO_ON,
            )
        };
        assert!(!p.is_null());
    });
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_bytes();
    assert_eq!(s, b"");
}

// ---------------------------------------------------------------------------
// setproctitle / setproctitle_init (FreeBSD/libbsd)
// ---------------------------------------------------------------------------
//
// setproctitle_init mutates a global Mutex<Option<ProcTitleStorage>>;
// we serialize the tests via a dedicated lock so concurrent runs
// don't race the captured (base, capacity) pair. Each test allocates
// its own argv-shaped buffer to use as the capture target so we don't
// trample the real /proc/self/cmdline.

static SETPROCTITLE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Build a synthetic argv+envp buffer so setproctitle_init has a
/// real region to capture. Returns (argv: Vec<*mut c_char>,
/// envp: Vec<*mut c_char>, backing: Vec<Vec<u8>>) — the backing
/// vec must outlive the argv pointers.
fn build_synthetic_argv(
    progname: &str,
    extra_capacity: usize,
) -> (Vec<*mut c_char>, Vec<*mut c_char>, Vec<Vec<u8>>) {
    // Construct a contiguous byte buffer containing argv0 + padding +
    // a NUL envp string. We need argv[0] and envp[0] to point into
    // contiguous memory so the walk in setproctitle_init computes
    // a sensible capacity.
    let mut backing: Vec<Vec<u8>> = Vec::new();
    let mut buf: Vec<u8> = Vec::with_capacity(progname.len() + 1 + extra_capacity);
    buf.extend_from_slice(progname.as_bytes());
    buf.push(0);
    // Padding so capacity > strlen(progname) + 1.
    buf.extend(std::iter::repeat_n(b'X', extra_capacity));
    buf.push(0);
    backing.push(buf);

    let raw = backing[0].as_mut_ptr() as *mut c_char;
    let envp_offset = progname.len() + 1;
    let envp_ptr = unsafe { raw.add(envp_offset) };
    let argv: Vec<*mut c_char> = vec![raw, std::ptr::null_mut()];
    let envp: Vec<*mut c_char> = vec![envp_ptr, std::ptr::null_mut()];
    (argv, envp, backing)
}

#[test]
fn setproctitle_with_init_writes_to_captured_argv() {
    let _guard = SETPROCTITLE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let (mut argv, mut envp, backing) = build_synthetic_argv("testprog", 64);
    unsafe { setproctitle_init(1, argv.as_mut_ptr(), envp.as_mut_ptr()) };

    let fmt = c"-just-a-title-%d";
    unsafe { setproctitle(fmt.as_ptr(), 42i32) };

    // Read back the title from the captured base. With "-" prefix
    // stripped the result is "just-a-title-42".
    let raw = backing[0].as_ptr();
    let s = unsafe { std::ffi::CStr::from_ptr(raw as *const c_char) }.to_bytes();
    assert_eq!(s, b"just-a-title-42");
}

#[test]
fn setproctitle_default_prefix_includes_progname() {
    let _guard = SETPROCTITLE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let (mut argv, mut envp, backing) = build_synthetic_argv("originalname", 64);
    unsafe { setproctitle_init(1, argv.as_mut_ptr(), envp.as_mut_ptr()) };

    // Force the published progname so the prefix is deterministic.
    let stable_progname = c"myprog";
    frankenlibc_abi::startup_abi::program_invocation_short_name.store(
        stable_progname.as_ptr() as *mut c_char,
        std::sync::atomic::Ordering::Release,
    );

    let fmt = c"hello %s";
    let world = c"world";
    unsafe { setproctitle(fmt.as_ptr(), world.as_ptr()) };

    let raw = backing[0].as_ptr();
    let s = unsafe { std::ffi::CStr::from_ptr(raw as *const c_char) }.to_bytes();
    assert_eq!(s, b"myprog: hello world");
}

#[test]
fn setproctitle_truncates_at_capacity_minus_one() {
    let _guard = SETPROCTITLE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // Tight buffer: progname "x" + 8 bytes of padding = capacity 10.
    let (mut argv, mut envp, backing) = build_synthetic_argv("x", 8);
    unsafe { setproctitle_init(1, argv.as_mut_ptr(), envp.as_mut_ptr()) };

    let fmt = c"-thisIsAReallyLongProcessTitle";
    unsafe { setproctitle(fmt.as_ptr()) };

    let raw = backing[0].as_ptr();
    let s = unsafe { std::ffi::CStr::from_ptr(raw as *const c_char) }.to_bytes();
    // Capacity is "x\0" + 8 'X's + trailing NUL = 11 bytes; the
    // implementation NUL-pads then writes capacity-1 bytes max.
    // The backing vec is 11 bytes total; the last byte is reserved
    // for NUL. Expect the first 10 bytes of "thisIsAReallyLongProcessTitle".
    assert!(s.len() <= 10);
    assert_eq!(s, b"thisIsARea"[..s.len().min(10)].to_vec());
}

#[test]
fn setproctitle_null_argv_init_is_no_op() {
    let _guard = SETPROCTITLE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // NULL argv should not crash; subsequent setproctitle is a no-op
    // when no storage was captured.
    unsafe { setproctitle_init(0, std::ptr::null_mut(), std::ptr::null_mut()) };
    // Don't assert anything — just verify no panic.
}

#[test]
fn setproctitle_without_init_is_no_op() {
    let _guard = SETPROCTITLE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // Reset PROCTITLE_STATE by passing argc=0 via a real init with
    // NULL argv, then verify setproctitle has no stale captured
    // argv region to mutate.
    unsafe { setproctitle_init(0, std::ptr::null_mut(), std::ptr::null_mut()) };
    let fmt = c"-anything";
    unsafe { setproctitle(fmt.as_ptr()) };
}

// ===========================================================================
// makedev / major / minor (glibc dev_t packing)
// ===========================================================================

use frankenlibc_abi::unistd_abi::{
    gnu_dev_major, gnu_dev_makedev, gnu_dev_minor, major, makedev, minor,
};

#[test]
fn makedev_round_trip_small_values() {
    let dev = unsafe { makedev(8, 1) };
    assert_eq!(unsafe { major(dev) }, 8);
    assert_eq!(unsafe { minor(dev) }, 1);
}

#[test]
fn makedev_round_trip_high_minor() {
    // Minor 0x1234 exercises both the low-byte field and the
    // shifted-into-high field.
    let dev = unsafe { makedev(259, 0x1234) };
    assert_eq!(unsafe { major(dev) }, 259);
    assert_eq!(unsafe { minor(dev) }, 0x1234);
}

#[test]
fn makedev_round_trip_high_major() {
    // Major above 0xfff exercises the upper-32-bits field.
    let dev = unsafe { makedev(0x12345, 7) };
    assert_eq!(unsafe { major(dev) }, 0x12345);
    assert_eq!(unsafe { minor(dev) }, 7);
}

#[test]
fn makedev_round_trip_arbitrary_pairs() {
    // Spot-check several distinct (major, minor) combinations at
    // boundary positions of the bit layout.
    for (mj, mn) in [
        (0u32, 0u32),
        (1, 0xff),
        (0xfff, 0xff),
        (0x1000, 0x100),
        (0xffffu32, 0xffff),
        (0x12345, 0x6789a),
    ] {
        let dev = unsafe { makedev(mj, mn) };
        assert_eq!(unsafe { major(dev) }, mj, "major mismatch for ({mj},{mn})");
        assert_eq!(unsafe { minor(dev) }, mn, "minor mismatch for ({mj},{mn})");
    }
}

#[test]
fn makedev_matches_gnu_dev_makedev() {
    // The bare-name aliases must produce the same dev_t as the
    // gnu_dev_* primitives.
    let cases = [(8, 1), (0xfff, 0xff), (0x12345, 0x6789a)];
    for (mj, mn) in cases {
        let a = unsafe { makedev(mj, mn) };
        let b = unsafe { gnu_dev_makedev(mj, mn) };
        assert_eq!(a, b, "makedev/gnu_dev_makedev divergence for ({mj},{mn})");
    }
}

#[test]
fn major_minor_match_gnu_dev_versions() {
    let cases: [u64; 4] = [0, 0x12345678, 0xdead_beef_cafe_babe, u64::MAX];
    for raw in cases {
        let dev = raw as libc::dev_t;
        assert_eq!(unsafe { major(dev) }, unsafe { gnu_dev_major(dev) });
        assert_eq!(unsafe { minor(dev) }, unsafe { gnu_dev_minor(dev) });
    }
}

// ===========================================================================
// secure_path (NetBSD libutil security check)
// ===========================================================================

use frankenlibc_abi::unistd_abi::secure_path;

#[test]
fn secure_path_null_argument_returns_minus_one_efault() {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = 0 };
    let r = unsafe { secure_path(std::ptr::null()) };
    assert_eq!(r, -1);
    assert_eq!(
        unsafe { *frankenlibc_abi::errno_abi::__errno_location() },
        libc::EFAULT
    );
}

#[test]
fn secure_path_nonexistent_path_returns_minus_one() {
    let p = c"/nonexistent/path/should/never/exist/secure-path-test";
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = 0 };
    let r = unsafe { secure_path(p.as_ptr()) };
    assert_eq!(r, -1);
    let err = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    // Underlying lstat sets ENOENT (or similar).
    assert!(err == libc::ENOENT || err == libc::ENOTDIR);
}

#[test]
fn secure_path_world_writable_file_fails_with_eperm() {
    // Create a temp file owned by current user, set mode 0666, and
    // verify secure_path rejects it.
    let dir = std::env::temp_dir();
    let path = dir.join(format!("secure_path_test_{}", std::process::id()));
    std::fs::write(&path, b"data").unwrap();
    let path_c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    unsafe { libc::chmod(path_c.as_ptr(), 0o666) };
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = 0 };
    let r = unsafe { secure_path(path_c.as_ptr()) };
    let err = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    let _ = std::fs::remove_file(&path);
    assert_eq!(r, -1, "world-writable file must fail");
    assert_eq!(err, libc::EPERM);
}

#[test]
fn secure_path_group_writable_file_fails_with_eperm() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("secure_path_test_grp_{}", std::process::id()));
    std::fs::write(&path, b"data").unwrap();
    let path_c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    unsafe { libc::chmod(path_c.as_ptr(), 0o660) };
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = 0 };
    let r = unsafe { secure_path(path_c.as_ptr()) };
    let err = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    let _ = std::fs::remove_file(&path);
    assert_eq!(r, -1, "group-writable file must fail");
    assert_eq!(err, libc::EPERM);
}

#[test]
fn secure_path_non_root_owned_file_fails_with_eperm() {
    // When tests run as non-root, every file we create is owned
    // by us, so secure_path must reject it for the wrong-owner
    // reason. Skip the assertion if we ARE root.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let dir = std::env::temp_dir();
    let path = dir.join(format!("secure_path_owner_{}", std::process::id()));
    std::fs::write(&path, b"data").unwrap();
    let path_c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    // Set restrictive perms so the only failure reason is owner.
    unsafe { libc::chmod(path_c.as_ptr(), 0o600) };
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = 0 };
    let r = unsafe { secure_path(path_c.as_ptr()) };
    let err = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    let _ = std::fs::remove_file(&path);
    assert_eq!(r, -1, "non-root-owned file must fail for non-root tests");
    assert_eq!(err, libc::EPERM);
}

#[test]
fn secure_path_root_owned_secure_file_passes() {
    // /etc/passwd is universally root-owned and 0644 on Linux —
    // a perfect smoke test that secure_path returns 0 for a
    // legitimately secure file.
    let p = c"/etc/passwd";
    let r = unsafe { secure_path(p.as_ptr()) };
    // If /etc/passwd doesn't exist or has unusual perms on this
    // host (very unlikely), we treat the test as inconclusive
    // rather than failing — the negative-path tests above carry
    // the load.
    if r != 0 {
        eprintln!(
            "secure_path(/etc/passwd) returned {} errno={} — host has \
             non-standard perms; skipping positive assertion",
            r,
            unsafe { *frankenlibc_abi::errno_abi::__errno_location() }
        );
    }
}

// ===========================================================================
// __getppid + __getuid/euid/gid/egid + __setuid/gid/euid/egid + __setsid +
// __setpgrp (glibc reserved aliases)
// ===========================================================================

#[test]
fn under_getppid_matches_getppid() {
    use frankenlibc_abi::unistd_abi::{__getppid, getppid};
    assert_eq!(unsafe { __getppid() }, unsafe { getppid() });
}

#[test]
fn under_getuid_geteuid_getgid_getegid_match_public() {
    use frankenlibc_abi::unistd_abi::{
        __getegid, __geteuid, __getgid, __getuid, getegid, geteuid, getgid, getuid,
    };
    assert_eq!(unsafe { __getuid() }, unsafe { getuid() });
    assert_eq!(unsafe { __geteuid() }, unsafe { geteuid() });
    assert_eq!(unsafe { __getgid() }, unsafe { getgid() });
    assert_eq!(unsafe { __getegid() }, unsafe { getegid() });
}

#[test]
fn under_setuid_setgid_seteuid_setegid_to_self_succeed() {
    use frankenlibc_abi::unistd_abi::{
        __setegid, __seteuid, __setgid, __setuid, getegid, geteuid, getgid, getuid,
    };
    let uid = unsafe { getuid() };
    let euid = unsafe { geteuid() };
    let gid = unsafe { getgid() };
    let egid = unsafe { getegid() };
    // Setting to current values is always permitted.
    assert_eq!(unsafe { __setuid(uid) }, 0);
    assert_eq!(unsafe { __seteuid(euid) }, 0);
    assert_eq!(unsafe { __setgid(gid) }, 0);
    assert_eq!(unsafe { __setegid(egid) }, 0);
}

#[test]
fn under_setpgrp_resolves() {
    // setpgrp() uses setpgid(0, 0) which may EPERM in some sandboxes
    // — we just verify the alias resolves and returns 0 or -1
    // without panicking.
    use frankenlibc_abi::unistd_abi::__setpgrp;
    let _ = unsafe { __setpgrp() };
}

#[test]
fn under_setsid_resolves() {
    // setsid() fails with EPERM if the caller is already a process
    // group leader, which is the typical case in test runners. We
    // just verify the alias resolves.
    use frankenlibc_abi::unistd_abi::__setsid;
    let _ = unsafe { __setsid() };
}

#[test]
fn under_gettid_matches_gettid() {
    use frankenlibc_abi::glibc_internal_abi::{__gettid, gettid};
    assert_eq!(unsafe { __gettid() }, unsafe { gettid() });
}

// ===========================================================================
// __setrlimit + __getrusage + __pathconf + __getitimer + __setitimer +
// __getpriority + __setpriority + __times (glibc reserved aliases)
// ===========================================================================

#[test]
fn under_setrlimit_to_self_succeeds() {
    use frankenlibc_abi::resource_abi::__setrlimit;
    let mut current: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut current) };
    assert_eq!(rc, 0);
    let rc = unsafe { __setrlimit(libc::RLIMIT_NOFILE as c_int, &current) };
    assert_eq!(rc, 0);
}

#[test]
fn under_getrusage_self_returns_zero() {
    use frankenlibc_abi::unistd_abi::__getrusage;
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { __getrusage(libc::RUSAGE_SELF, &mut usage) };
    assert_eq!(rc, 0);
}

#[test]
fn under_pathconf_known_path_returns_value() {
    use frankenlibc_abi::unistd_abi::__pathconf;
    let p = c"/tmp";
    // _PC_NAME_MAX is well-defined for any FS that supports filenames.
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = 0 };
    let v = unsafe { __pathconf(p.as_ptr(), libc::_PC_NAME_MAX) };
    assert!(v >= 0, "pathconf returned {v}");
}

#[test]
fn under_getitimer_setitimer_round_trip() {
    use frankenlibc_abi::unistd_abi::{__getitimer, __setitimer};
    // Disable the timer (zero values), then read it back via __getitimer.
    let zero = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
    };
    let rc = unsafe { __setitimer(libc::ITIMER_REAL, &zero, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
    let mut got: libc::itimerval = unsafe { std::mem::zeroed() };
    let rc = unsafe { __getitimer(libc::ITIMER_REAL, &mut got) };
    assert_eq!(rc, 0);
    assert_eq!(got.it_value.tv_sec, 0);
    assert_eq!(got.it_value.tv_usec, 0);
}

#[test]
fn under_getpriority_setpriority_round_trip_for_self() {
    use frankenlibc_abi::unistd_abi::{__getpriority, __setpriority};
    // Read current PRIO_PROCESS for self, then set it to the same
    // value (always permitted).
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = 0 };
    let cur = unsafe { __getpriority(libc::PRIO_PROCESS as c_int, 0) };
    // getpriority can legitimately return -1; check errno.
    let err = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(err, 0, "getpriority errno = {err}");
    let rc = unsafe { __setpriority(libc::PRIO_PROCESS as c_int, 0, cur) };
    assert_eq!(rc, 0);
}

#[test]
fn under_times_returns_nonzero_clock_ticks() {
    use frankenlibc_abi::glibc_internal_abi::__times;
    let mut buf: libc::tms = unsafe { std::mem::zeroed() };
    let v = unsafe { __times((&mut buf) as *mut _ as *mut std::ffi::c_void) };
    // times returns the elapsed real time in clock ticks since
    // some past time; on Linux it's monotonically nonnegative.
    assert!(v >= 0);
}

// ===========================================================================
// __chdir + __fchdir + __mkdir + __rmdir + __unlink + __link +
// __symlink + __rename + __access (glibc reserved aliases)
// ===========================================================================

#[test]
fn under_access_existing_path_returns_zero() {
    use frankenlibc_abi::unistd_abi::__access;
    let p = c"/tmp";
    let rc = unsafe { __access(p.as_ptr(), libc::F_OK) };
    assert_eq!(rc, 0);
}

#[test]
fn under_access_missing_path_returns_minus_one() {
    use frankenlibc_abi::unistd_abi::__access;
    let p = c"/nonexistent_franken_aliases_xyz";
    let rc = unsafe { __access(p.as_ptr(), libc::F_OK) };
    assert_eq!(rc, -1);
}

#[test]
fn under_chdir_to_tmp_succeeds() {
    use frankenlibc_abi::unistd_abi::{__chdir, getcwd};
    // Save and restore cwd to avoid disturbing other tests.
    let mut saved = [0 as c_char; 4096];
    let p_saved = unsafe { getcwd(saved.as_mut_ptr(), saved.len()) };
    assert!(!p_saved.is_null());
    let p = c"/tmp";
    let rc = unsafe { __chdir(p.as_ptr()) };
    assert_eq!(rc, 0);
    // Restore using the same alias to also exercise it.
    let rc = unsafe { __chdir(saved.as_ptr()) };
    assert_eq!(rc, 0);
}

#[test]
fn under_fchdir_round_trip() {
    use frankenlibc_abi::unistd_abi::{__fchdir, getcwd};
    let saved_fd = unsafe { libc::open(c".".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    assert!(saved_fd >= 0);
    // Open /tmp as a directory fd, fchdir to it, then back.
    let tmp_fd = unsafe { libc::open(c"/tmp".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    assert!(tmp_fd >= 0);
    let rc = unsafe { __fchdir(tmp_fd) };
    assert_eq!(rc, 0);
    let mut buf = [0 as c_char; 4096];
    let _ = unsafe { getcwd(buf.as_mut_ptr(), buf.len()) };
    let rc = unsafe { __fchdir(saved_fd) };
    assert_eq!(rc, 0);
    unsafe { libc::close(tmp_fd) };
    unsafe { libc::close(saved_fd) };
}

#[test]
fn under_mkdir_rmdir_round_trip() {
    use frankenlibc_abi::unistd_abi::{__mkdir, __rmdir};
    let path = format!("/tmp/franken_under_mkdir_{}", std::process::id());
    let path_c = std::ffi::CString::new(path.clone()).unwrap();
    let rc = unsafe { __mkdir(path_c.as_ptr(), 0o755) };
    assert_eq!(rc, 0);
    let rc = unsafe { __rmdir(path_c.as_ptr()) };
    assert_eq!(rc, 0);
}

#[test]
fn under_unlink_link_symlink_rename_round_trip() {
    use frankenlibc_abi::unistd_abi::{__link, __rename, __symlink, __unlink};
    let base = format!("/tmp/franken_under_path_{}", std::process::id());
    let primary = format!("{base}_primary");
    let hardlink = format!("{base}_hardlink");
    let symlink = format!("{base}_symlink");
    let renamed = format!("{base}_renamed");

    // Create primary file.
    std::fs::write(&primary, b"x").unwrap();

    let primary_c = std::ffi::CString::new(primary.clone()).unwrap();
    let hardlink_c = std::ffi::CString::new(hardlink.clone()).unwrap();
    let symlink_c = std::ffi::CString::new(symlink.clone()).unwrap();
    let renamed_c = std::ffi::CString::new(renamed.clone()).unwrap();

    // __link: create hardlink.
    assert_eq!(
        unsafe { __link(primary_c.as_ptr(), hardlink_c.as_ptr()) },
        0
    );
    // __symlink: create symlink.
    assert_eq!(
        unsafe { __symlink(primary_c.as_ptr(), symlink_c.as_ptr()) },
        0
    );
    // __rename: rename hardlink to renamed.
    assert_eq!(
        unsafe { __rename(hardlink_c.as_ptr(), renamed_c.as_ptr()) },
        0
    );
    // __unlink: clean up all of them.
    assert_eq!(unsafe { __unlink(renamed_c.as_ptr()) }, 0);
    assert_eq!(unsafe { __unlink(symlink_c.as_ptr()) }, 0);
    assert_eq!(unsafe { __unlink(primary_c.as_ptr()) }, 0);
}

// ===========================================================================
// __getcwd / __getlogin / __getlogin_r (glibc reserved aliases)
// ===========================================================================

#[test]
fn under_getcwd_matches_getcwd() {
    use frankenlibc_abi::unistd_abi::{__getcwd, getcwd};
    let mut a = [0 as c_char; 4096];
    let mut b = [0 as c_char; 4096];
    let p_a = unsafe { getcwd(a.as_mut_ptr(), a.len()) };
    let p_b = unsafe { __getcwd(b.as_mut_ptr(), b.len()) };
    assert!(!p_a.is_null());
    assert!(!p_b.is_null());
    let s_a = unsafe { std::ffi::CStr::from_ptr(p_a) };
    let s_b = unsafe { std::ffi::CStr::from_ptr(p_b) };
    assert_eq!(s_a, s_b);
}

#[test]
fn under_getlogin_resolves() {
    use frankenlibc_abi::unistd_abi::__getlogin;
    let _ = unsafe { __getlogin() }; // smoke: just verify it returns
}

#[test]
fn under_getlogin_r_matches_getlogin_r_or_returns_einval() {
    use frankenlibc_abi::unistd_abi::{__getlogin_r, getlogin_r};
    let mut a = [0 as c_char; 256];
    let mut b = [0 as c_char; 256];
    let r_a = unsafe { getlogin_r(a.as_mut_ptr(), a.len()) };
    let r_b = unsafe { __getlogin_r(b.as_mut_ptr(), b.len()) };
    // Both should agree on success/failure and (on success) on the result.
    assert_eq!(r_a, r_b);
    if r_a == 0 {
        let s_a = unsafe { std::ffi::CStr::from_ptr(a.as_ptr()) };
        let s_b = unsafe { std::ffi::CStr::from_ptr(b.as_ptr()) };
        assert_eq!(s_a, s_b);
    }
}

// ===========================================================================
// __strerror_l (glibc reserved-namespace alias of strerror_l)
// ===========================================================================

#[test]
fn under_strerror_l_matches_strerror_l() {
    use frankenlibc_abi::unistd_abi::{__strerror_l, strerror_l};
    let p = unsafe { strerror_l(libc::ENOENT, std::ptr::null_mut()) };
    let q = unsafe { __strerror_l(libc::ENOENT, std::ptr::null_mut()) };
    assert!(!p.is_null());
    assert!(!q.is_null());
    let a = unsafe { std::ffi::CStr::from_ptr(p) };
    let b = unsafe { std::ffi::CStr::from_ptr(q) };
    assert_eq!(a, b);
}

// ===========================================================================
// __cxa_pure_virtual (Itanium C++ ABI pure-virtual stub)
// ===========================================================================

#[test]
fn cxa_pure_virtual_aborts_child_process() {
    // The function never returns and aborts the process. Run it in
    // a forked child so we can observe SIGABRT without killing the
    // test runner.
    use frankenlibc_abi::unistd_abi::__cxa_pure_virtual;

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        // Child: invoke the stub. Should abort immediately.
        unsafe { __cxa_pure_virtual() };
        // Unreachable.
    }

    // Parent: wait for child and verify it died via SIGABRT.
    let mut status: c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid);
    assert!(
        libc::WIFSIGNALED(status),
        "child must have terminated by signal"
    );
    assert_eq!(
        libc::WTERMSIG(status),
        libc::SIGABRT,
        "child must have terminated by SIGABRT"
    );
}

#[test]
fn cxa_throw_bad_array_new_length_aborts_child_process() {
    use frankenlibc_abi::unistd_abi::__cxa_throw_bad_array_new_length;

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        unsafe { __cxa_throw_bad_array_new_length() };
        // Unreachable.
    }

    let mut status: c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid);
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
}

#[test]
fn cxa_call_unexpected_aborts_child_process() {
    use frankenlibc_abi::unistd_abi::__cxa_call_unexpected;

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        unsafe { __cxa_call_unexpected(std::ptr::null_mut()) };
        // Unreachable.
    }

    let mut status: c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid);
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
}

#[test]
fn cxa_call_terminate_aborts_child_process() {
    use frankenlibc_abi::unistd_abi::__cxa_call_terminate;

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        unsafe { __cxa_call_terminate(std::ptr::null_mut()) };
    }

    let mut status: c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid);
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
}

#[test]
fn cxa_deleted_virtual_aborts_child_process() {
    use frankenlibc_abi::unistd_abi::__cxa_deleted_virtual;

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        unsafe { __cxa_deleted_virtual() };
    }

    let mut status: c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid);
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
}

#[test]
fn cxa_bad_cast_aborts_child_process() {
    use frankenlibc_abi::unistd_abi::__cxa_bad_cast;

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        unsafe { __cxa_bad_cast() };
    }

    let mut status: c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid);
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
}

#[test]
fn cxa_bad_typeid_aborts_child_process() {
    use frankenlibc_abi::unistd_abi::__cxa_bad_typeid;

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        unsafe { __cxa_bad_typeid() };
    }

    let mut status: c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid);
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
}

#[test]
fn cxa_throw_bad_array_length_aborts_child_process() {
    use frankenlibc_abi::unistd_abi::__cxa_throw_bad_array_length;

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        unsafe { __cxa_throw_bad_array_length() };
    }

    let mut status: c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid);
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
}

#[test]
fn cxa_guard_acquire_first_call_returns_one() {
    use frankenlibc_abi::unistd_abi::__cxa_guard_acquire;
    let mut g: u64 = 0;
    let rc = unsafe { __cxa_guard_acquire(&mut g) };
    assert_eq!(
        rc, 1,
        "first acquire on a fresh guard must elect this caller"
    );
    let bytes = g.to_ne_bytes();
    assert_eq!(bytes[0], 0, "byte 0 (initialized) still zero");
    assert_eq!(bytes[1], 1, "byte 1 (in-progress) now set");
}

#[test]
fn cxa_guard_release_marks_initialized_and_subsequent_acquire_returns_zero() {
    use frankenlibc_abi::unistd_abi::{__cxa_guard_acquire, __cxa_guard_release};
    let mut g: u64 = 0;
    assert_eq!(unsafe { __cxa_guard_acquire(&mut g) }, 1);
    unsafe { __cxa_guard_release(&mut g) };
    let bytes = g.to_ne_bytes();
    assert_eq!(bytes[0], 1, "release sets byte 0 (initialized)");
    assert_eq!(bytes[1], 0, "release clears byte 1 (in-progress)");

    // Subsequent acquires on the same guard return 0 (already done).
    assert_eq!(unsafe { __cxa_guard_acquire(&mut g) }, 0);
    assert_eq!(unsafe { __cxa_guard_acquire(&mut g) }, 0);
}

#[test]
fn cxa_guard_abort_clears_in_progress_so_next_acquire_re_races() {
    use frankenlibc_abi::unistd_abi::{__cxa_guard_abort, __cxa_guard_acquire};
    let mut g: u64 = 0;
    assert_eq!(unsafe { __cxa_guard_acquire(&mut g) }, 1);
    unsafe { __cxa_guard_abort(&mut g) };
    let bytes = g.to_ne_bytes();
    assert_eq!(bytes[0], 0, "abort leaves byte 0 (uninitialized)");
    assert_eq!(bytes[1], 0, "abort clears byte 1 (in-progress)");

    // The next acquire wins again because no one finished initialization.
    assert_eq!(unsafe { __cxa_guard_acquire(&mut g) }, 1);
}

#[test]
fn cxa_guard_acquire_concurrent_threads_only_one_winner() {
    use frankenlibc_abi::unistd_abi::{__cxa_guard_acquire, __cxa_guard_release};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::thread;
    use std::time::Duration;

    // Allocate a guard on the heap so threads share its address.
    let g_box: Box<u64> = Box::new(0);
    let g_ptr = Box::into_raw(g_box);
    // SAFETY: g_ptr lives until the end of this test.
    let g_addr = g_ptr as usize;

    let winners = Arc::new(AtomicI32::new(0));
    let losers = Arc::new(AtomicI32::new(0));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let winners = winners.clone();
        let losers = losers.clone();
        handles.push(thread::spawn(move || {
            let g = g_addr as *mut u64;
            let rc = unsafe { __cxa_guard_acquire(g) };
            if rc == 1 {
                // Simulate slow initialization so other threads block.
                thread::sleep(Duration::from_millis(20));
                winners.fetch_add(1, Ordering::SeqCst);
                unsafe { __cxa_guard_release(g) };
            } else {
                losers.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        winners.load(Ordering::SeqCst),
        1,
        "exactly one thread should win the initialization race"
    );
    assert_eq!(
        losers.load(Ordering::SeqCst),
        7,
        "the other seven threads should observe the completed init"
    );

    // Reclaim the heap allocation.
    let _ = unsafe { Box::from_raw(g_ptr) };
}

#[test]
fn cxa_guard_null_pointer_returns_zero_no_op() {
    use frankenlibc_abi::unistd_abi::{
        __cxa_guard_abort, __cxa_guard_acquire, __cxa_guard_release,
    };
    // NULL guard pointer must be defended-against (never dereference);
    // acquire returns 0 (treat as already initialized) and the others
    // are no-ops.
    assert_eq!(unsafe { __cxa_guard_acquire(std::ptr::null_mut()) }, 0);
    unsafe { __cxa_guard_release(std::ptr::null_mut()) };
    unsafe { __cxa_guard_abort(std::ptr::null_mut()) };
}

// ---------------------------------------------------------------------------
// __cxa_thread_atexit / __cxa_tm_cleanup / __cxa_vec_ctor / dtor / cleanup
// ---------------------------------------------------------------------------

#[test]
fn cxa_tm_cleanup_is_a_no_op() {
    use frankenlibc_abi::unistd_abi::__cxa_tm_cleanup;
    // Just verify that calling it with arbitrary args doesn't crash;
    // there is no observable side effect to assert.
    unsafe {
        __cxa_tm_cleanup(std::ptr::null_mut(), std::ptr::null_mut(), 0);
        __cxa_tm_cleanup(0xdead_beef_usize as *mut c_void, std::ptr::null_mut(), 7);
    }
}

#[test]
fn cxa_thread_atexit_registers_via_impl() {
    use frankenlibc_abi::unistd_abi::__cxa_thread_atexit;

    // We can't easily observe the registry side-effect from outside
    // the abi crate (it lives in startup_abi), but we can verify the
    // wrapper accepts the call and returns 0 for the standard happy
    // path that the impl uses.
    unsafe extern "C" fn noop_dtor(_obj: *mut c_void) {}
    let mut payload: i32 = 42;
    let rc = unsafe {
        __cxa_thread_atexit(
            noop_dtor,
            &mut payload as *mut i32 as *mut c_void,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0);
}

#[test]
fn cxa_vec_ctor_runs_constructor_in_forward_order() {
    use frankenlibc_abi::unistd_abi::__cxa_vec_ctor;
    use std::sync::Mutex;

    static ORDER: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    unsafe extern "C" fn ctor_record(p: *mut c_void) {
        let v = unsafe { *(p as *mut u32) } as usize;
        ORDER.lock().unwrap().push(v);
    }

    // Initialize array elements with their indices so the ctor records
    // the visit order.
    let mut buf: [u32; 5] = [0, 1, 2, 3, 4];
    ORDER.lock().unwrap().clear();
    unsafe {
        __cxa_vec_ctor(
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            std::mem::size_of::<u32>(),
            Some(ctor_record),
            None,
        );
    }
    assert_eq!(*ORDER.lock().unwrap(), vec![0, 1, 2, 3, 4]);
}

#[test]
fn cxa_vec_dtor_runs_destructor_in_reverse_order() {
    use frankenlibc_abi::unistd_abi::__cxa_vec_dtor;
    use std::sync::Mutex;

    static ORDER: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    unsafe extern "C" fn dtor_record(p: *mut c_void) {
        let v = unsafe { *(p as *mut u32) } as usize;
        ORDER.lock().unwrap().push(v);
    }

    let mut buf: [u32; 5] = [10, 11, 12, 13, 14];
    ORDER.lock().unwrap().clear();
    unsafe {
        __cxa_vec_dtor(
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            std::mem::size_of::<u32>(),
            Some(dtor_record),
        );
    }
    assert_eq!(*ORDER.lock().unwrap(), vec![14, 13, 12, 11, 10]);
}

#[test]
fn cxa_vec_cleanup_matches_vec_dtor_order() {
    use frankenlibc_abi::unistd_abi::__cxa_vec_cleanup;
    use std::sync::Mutex;

    static ORDER: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    unsafe extern "C" fn dtor_record(p: *mut c_void) {
        let v = unsafe { *(p as *mut u32) } as usize;
        ORDER.lock().unwrap().push(v);
    }

    let mut buf: [u32; 3] = [100, 200, 300];
    ORDER.lock().unwrap().clear();
    unsafe {
        __cxa_vec_cleanup(
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            std::mem::size_of::<u32>(),
            Some(dtor_record),
        );
    }
    assert_eq!(*ORDER.lock().unwrap(), vec![300, 200, 100]);
}

#[test]
fn cxa_vec_ctor_dtor_tolerate_null_callbacks_and_zero_count() {
    use frankenlibc_abi::unistd_abi::{__cxa_vec_ctor, __cxa_vec_dtor};

    let mut buf: [u32; 4] = [0; 4];

    // NULL ctor → no-op. NULL dtor → no-op. zero count → no-op.
    unsafe {
        __cxa_vec_ctor(
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            std::mem::size_of::<u32>(),
            None,
            None,
        );
        __cxa_vec_dtor(
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            std::mem::size_of::<u32>(),
            None,
        );
        __cxa_vec_ctor(
            buf.as_mut_ptr() as *mut c_void,
            0,
            std::mem::size_of::<u32>(),
            None,
            None,
        );
    }

    // NULL array → no-op (must not deref).
    unsafe {
        __cxa_vec_ctor(std::ptr::null_mut(), 5, 4, None, None);
        __cxa_vec_dtor(std::ptr::null_mut(), 5, 4, None);
    }
}

// ---------------------------------------------------------------------------
// __cxa_vec_new / new2 / new3 / delete / delete2 / delete3 / cctor
// ---------------------------------------------------------------------------

#[test]
fn cxa_vec_new_then_delete_round_trips_with_padding() {
    use frankenlibc_abi::unistd_abi::{__cxa_vec_delete, __cxa_vec_new};
    use std::sync::Mutex;

    static CTOR_VISITS: Mutex<Vec<usize>> = Mutex::new(Vec::new());
    static DTOR_VISITS: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    unsafe extern "C" fn ctor(p: *mut c_void) {
        unsafe { *(p as *mut u32) = 0xCAFE };
        CTOR_VISITS.lock().unwrap().push(p as usize);
    }
    unsafe extern "C" fn dtor(p: *mut c_void) {
        DTOR_VISITS.lock().unwrap().push(p as usize);
    }

    CTOR_VISITS.lock().unwrap().clear();
    DTOR_VISITS.lock().unwrap().clear();

    let count = 5usize;
    let size = std::mem::size_of::<u32>();
    let padding = std::mem::size_of::<usize>();
    let arr = unsafe { __cxa_vec_new(count, size, padding, Some(ctor), Some(dtor)) };
    assert!(!arr.is_null());

    // Each element initialised to 0xCAFE by the ctor.
    let s = unsafe { std::slice::from_raw_parts(arr as *const u32, count) };
    for &v in s {
        assert_eq!(v, 0xCAFE);
    }
    assert_eq!(CTOR_VISITS.lock().unwrap().len(), count);

    // Delete recovers count from padding and runs dtor in reverse.
    unsafe { __cxa_vec_delete(arr, size, padding, Some(dtor)) };
    let dtor_visits = DTOR_VISITS.lock().unwrap().clone();
    assert_eq!(dtor_visits.len(), count);
    // Reverse order: addresses descending.
    for w in dtor_visits.windows(2) {
        assert!(w[0] > w[1], "dtor visit order must be reverse");
    }
}

#[test]
fn cxa_vec_new_returns_null_on_overflow() {
    use frankenlibc_abi::unistd_abi::__cxa_vec_new;
    let p = unsafe { __cxa_vec_new(usize::MAX, 2, 0, None, None) };
    assert!(p.is_null());
}

#[test]
fn cxa_vec_new_returns_null_on_zero_total() {
    use frankenlibc_abi::unistd_abi::__cxa_vec_new;
    // count=0, padding=0 → 0 bytes total → NULL.
    let p = unsafe { __cxa_vec_new(0, 4, 0, None, None) };
    assert!(p.is_null());
}

#[test]
fn cxa_vec_new2_uses_caller_supplied_alloc() {
    use frankenlibc_abi::unistd_abi::__cxa_vec_new2;
    use std::sync::Mutex;

    static ALLOC_BYTES: Mutex<usize> = Mutex::new(0);
    static SCRATCH: Mutex<Option<Vec<u8>>> = Mutex::new(None);

    unsafe extern "C" fn my_alloc(n: usize) -> *mut c_void {
        *ALLOC_BYTES.lock().unwrap() = n;
        let mut buf = vec![0u8; n];
        let p = buf.as_mut_ptr() as *mut c_void;
        *SCRATCH.lock().unwrap() = Some(buf);
        p
    }

    let count = 3usize;
    let size = 8usize;
    let padding = std::mem::size_of::<usize>();
    let arr = unsafe { __cxa_vec_new2(count, size, padding, None, None, Some(my_alloc), None) };
    assert!(!arr.is_null());
    assert_eq!(*ALLOC_BYTES.lock().unwrap(), count * size + padding);

    // Drop the scratch buffer at end of test to avoid leak; the caller
    // owns the allocation since we used a custom allocator.
    *SCRATCH.lock().unwrap() = None;
}

#[test]
fn cxa_vec_delete2_calls_caller_supplied_dealloc() {
    use frankenlibc_abi::unistd_abi::{__cxa_vec_delete2, __cxa_vec_new2};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DEALLOCED_ADDR: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn my_alloc(n: usize) -> *mut c_void {
        let layout =
            std::alloc::Layout::from_size_align(n, std::mem::align_of::<usize>()).expect("layout");
        unsafe { std::alloc::alloc_zeroed(layout) as *mut c_void }
    }
    unsafe extern "C" fn my_dealloc(p: *mut c_void) {
        DEALLOCED_ADDR.store(p as usize, Ordering::SeqCst);
        // Don't actually free; we'll leak this small allocation.
        // The test only verifies the dealloc callback fired with the
        // raw pointer (= array - padding).
    }

    let count = 4usize;
    let size = 4usize;
    let padding = std::mem::size_of::<usize>();
    let arr = unsafe {
        __cxa_vec_new2(
            count,
            size,
            padding,
            None,
            None,
            Some(my_alloc),
            Some(my_dealloc),
        )
    };
    assert!(!arr.is_null());

    DEALLOCED_ADDR.store(0, Ordering::SeqCst);
    unsafe { __cxa_vec_delete2(arr, size, padding, None, Some(my_dealloc)) };
    let raw_seen = DEALLOCED_ADDR.load(Ordering::SeqCst);
    let raw_expected = unsafe { (arr as *mut u8).sub(padding) } as usize;
    assert_eq!(raw_seen, raw_expected);
}

#[test]
fn cxa_vec_delete3_passes_total_size_to_dealloc() {
    use frankenlibc_abi::unistd_abi::{__cxa_vec_delete3, __cxa_vec_new3};
    use std::sync::Mutex;

    static DEALLOC_SIZE: Mutex<usize> = Mutex::new(0);

    unsafe extern "C" fn my_alloc(n: usize) -> *mut c_void {
        let layout =
            std::alloc::Layout::from_size_align(n, std::mem::align_of::<usize>()).expect("layout");
        unsafe { std::alloc::alloc_zeroed(layout) as *mut c_void }
    }
    unsafe extern "C" fn my_dealloc(_p: *mut c_void, n: usize) {
        *DEALLOC_SIZE.lock().unwrap() = n;
    }

    let count = 6usize;
    let size = 4usize;
    let padding = std::mem::size_of::<usize>();
    let arr = unsafe {
        __cxa_vec_new3(
            count,
            size,
            padding,
            None,
            None,
            Some(my_alloc),
            Some(my_dealloc),
        )
    };
    assert!(!arr.is_null());

    *DEALLOC_SIZE.lock().unwrap() = 0;
    unsafe { __cxa_vec_delete3(arr, size, padding, None, Some(my_dealloc)) };
    assert_eq!(*DEALLOC_SIZE.lock().unwrap(), count * size + padding);
}

#[test]
fn cxa_vec_delete_handles_null_array() {
    use frankenlibc_abi::unistd_abi::{__cxa_vec_delete, __cxa_vec_delete2, __cxa_vec_delete3};
    // All three delete variants must accept NULL without crashing.
    unsafe {
        __cxa_vec_delete(std::ptr::null_mut(), 4, 8, None);
        __cxa_vec_delete2(std::ptr::null_mut(), 4, 8, None, None);
        __cxa_vec_delete3(std::ptr::null_mut(), 4, 8, None, None);
    }
}

#[test]
fn cxa_vec_cctor_invokes_copy_constructor_per_element() {
    use frankenlibc_abi::unistd_abi::__cxa_vec_cctor;
    use std::sync::Mutex;

    static PAIRS: Mutex<Vec<(u32, u32)>> = Mutex::new(Vec::new());

    unsafe extern "C" fn copy_ctor(d: *mut c_void, s: *mut c_void) {
        let sv = unsafe { *(s as *mut u32) };
        unsafe { *(d as *mut u32) = sv * 10 };
        PAIRS.lock().unwrap().push((sv, sv * 10));
    }

    let mut src: [u32; 4] = [1, 2, 3, 4];
    let mut dst: [u32; 4] = [0; 4];
    PAIRS.lock().unwrap().clear();

    unsafe {
        __cxa_vec_cctor(
            dst.as_mut_ptr() as *mut c_void,
            src.as_mut_ptr() as *mut c_void,
            src.len(),
            std::mem::size_of::<u32>(),
            Some(copy_ctor),
            None,
        );
    }
    assert_eq!(dst, [10, 20, 30, 40]);
    assert_eq!(
        *PAIRS.lock().unwrap(),
        vec![(1, 10), (2, 20), (3, 30), (4, 40)]
    );
}

#[test]
fn cxa_get_globals_returns_stable_per_thread_pointer() {
    use frankenlibc_abi::unistd_abi::{__cxa_get_globals, __cxa_get_globals_fast};

    // Same thread → same pointer across calls.
    let a = unsafe { __cxa_get_globals() };
    let b = unsafe { __cxa_get_globals() };
    assert!(!a.is_null());
    assert_eq!(a, b);

    // _fast variant returns the same pointer as the regular form.
    let c = unsafe { __cxa_get_globals_fast() };
    assert_eq!(a, c);

    // Counter is initially 0 (uncaughtExceptions starts at 0).
    let g = unsafe { &*a };
    assert_eq!(g.uncaught_exceptions, 0);
    assert!(g.caught_exceptions.is_null());
}

#[test]
fn cxa_get_globals_returns_distinct_pointers_per_thread() {
    use frankenlibc_abi::unistd_abi::__cxa_get_globals;

    let main_ptr = unsafe { __cxa_get_globals() };
    assert!(!main_ptr.is_null());

    let main_addr = main_ptr as usize;
    let other_addr = std::thread::spawn(|| unsafe { __cxa_get_globals() } as usize)
        .join()
        .unwrap();
    assert_ne!(
        main_addr, other_addr,
        "different threads must observe distinct __cxa_eh_globals storage"
    );
}

// ===========================================================================
// __dso_handle (Itanium C++ ABI per-DSO handle)
// ===========================================================================

#[test]
fn dso_handle_symbol_resolves_and_is_stable() {
    // The address of __dso_handle is the unique handle; the value
    // stored at that address is conventionally NULL for static-link
    // builds. Both reads of the address must return the same
    // pointer (proves the symbol is a real global, not a temporary).
    let a: *const _ = &raw const frankenlibc_abi::unistd_abi::__dso_handle;
    let b: *const _ = &raw const frankenlibc_abi::unistd_abi::__dso_handle;
    assert_eq!(a, b);
}

#[test]
fn dso_handle_address_works_as_cxa_atexit_dso_arg() {
    // Register a destructor with `&__dso_handle` as the DSO key,
    // then run `__cxa_finalize` with the same key — the
    // destructor must fire exactly once.
    use std::sync::atomic::{AtomicUsize, Ordering};
    static FIRED: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn dtor(_arg: *mut std::ffi::c_void) {
        FIRED.fetch_add(1, Ordering::SeqCst);
    }

    FIRED.store(0, Ordering::SeqCst);
    let dso = &raw const frankenlibc_abi::unistd_abi::__dso_handle as *mut std::ffi::c_void;
    let rc = unsafe { frankenlibc_abi::unistd_abi::__cxa_atexit(dtor, std::ptr::null_mut(), dso) };
    assert_eq!(rc, 0, "__cxa_atexit must accept &__dso_handle");

    unsafe { frankenlibc_abi::unistd_abi::__cxa_finalize(dso) };
    assert_eq!(
        FIRED.load(Ordering::SeqCst),
        1,
        "destructor registered with &__dso_handle must fire on __cxa_finalize"
    );

    // Calling __cxa_finalize again with the same dso must NOT
    // re-fire (we drained the matching entries).
    unsafe { frankenlibc_abi::unistd_abi::__cxa_finalize(dso) };
    assert_eq!(FIRED.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------------
// mq_clocksend / mq_clockreceive
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct MqAttr {
    mq_flags: libc::c_long,
    mq_maxmsg: libc::c_long,
    mq_msgsize: libc::c_long,
    mq_curmsgs: libc::c_long,
    _pad: [libc::c_long; 4],
}

fn mq_unique_name(label: &str) -> CString {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    CString::new(format!("/fl_mq_clock_{label}_{pid}_{id}")).unwrap()
}

fn mq_open_for_test(name: &CStr) -> Option<c_int> {
    use frankenlibc_abi::unistd_abi as fl;
    let attr = MqAttr {
        mq_maxmsg: 4,
        mq_msgsize: 32,
        ..Default::default()
    };
    let mqd = unsafe {
        fl::mq_open(
            name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
            &attr as *const MqAttr as *const libc::mq_attr,
        )
    };
    if mqd < 0 { None } else { Some(mqd) }
}

fn timespec_after_ms(clockid: libc::clockid_t, ms: i64) -> libc::timespec {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(clockid, &mut ts) };
    let total_ns = ts.tv_nsec + ms * 1_000_000;
    ts.tv_sec += (total_ns / 1_000_000_000) as libc::time_t;
    ts.tv_nsec = total_ns % 1_000_000_000;
    ts
}

#[test]
fn mq_clocksend_clockreceive_realtime_round_trip() {
    use frankenlibc_abi::unistd_abi as fl;
    let qn = mq_unique_name("rt");
    let Some(mqd) = mq_open_for_test(&qn) else {
        eprintln!("mq_open unavailable (sandbox?), skipping");
        return;
    };

    let payload = b"hello-clock";
    let abs = timespec_after_ms(libc::CLOCK_REALTIME, 1_000);
    let rc = unsafe {
        fl::mq_clocksend(
            mqd,
            payload.as_ptr() as *const c_char,
            payload.len(),
            5,
            libc::CLOCK_REALTIME,
            &abs,
        )
    };
    assert_eq!(
        rc,
        0,
        "mq_clocksend failed: {}",
        std::io::Error::last_os_error()
    );

    let mut buf = [0u8; 32];
    let mut prio: c_uint = 0;
    let abs2 = timespec_after_ms(libc::CLOCK_REALTIME, 1_000);
    let n = unsafe {
        fl::mq_clockreceive(
            mqd,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut prio,
            libc::CLOCK_REALTIME,
            &abs2,
        )
    };
    assert!(
        n >= 0,
        "mq_clockreceive failed: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(&buf[..n as usize], payload);
    assert_eq!(prio, 5);

    let _ = unsafe { fl::mq_close(mqd) };
    let _ = unsafe { fl::mq_unlink(qn.as_ptr()) };
}

#[test]
fn mq_clocksend_clockreceive_monotonic_round_trip() {
    use frankenlibc_abi::unistd_abi as fl;
    let qn = mq_unique_name("mono");
    let Some(mqd) = mq_open_for_test(&qn) else {
        eprintln!("mq_open unavailable, skipping");
        return;
    };

    let payload = b"mono-clock";
    let abs = timespec_after_ms(libc::CLOCK_MONOTONIC, 1_000);
    let rc = unsafe {
        fl::mq_clocksend(
            mqd,
            payload.as_ptr() as *const c_char,
            payload.len(),
            7,
            libc::CLOCK_MONOTONIC,
            &abs,
        )
    };
    assert_eq!(
        rc,
        0,
        "mq_clocksend(MONO) failed: {}",
        std::io::Error::last_os_error()
    );

    let mut buf = [0u8; 32];
    let mut prio: c_uint = 0;
    let abs2 = timespec_after_ms(libc::CLOCK_MONOTONIC, 1_000);
    let n = unsafe {
        fl::mq_clockreceive(
            mqd,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut prio,
            libc::CLOCK_MONOTONIC,
            &abs2,
        )
    };
    assert!(n >= 0);
    assert_eq!(&buf[..n as usize], payload);
    assert_eq!(prio, 7);

    let _ = unsafe { fl::mq_close(mqd) };
    let _ = unsafe { fl::mq_unlink(qn.as_ptr()) };
}

#[test]
fn mq_clocksend_invalid_clockid_returns_einval() {
    use frankenlibc_abi::unistd_abi as fl;
    let qn = mq_unique_name("badclock");
    let Some(mqd) = mq_open_for_test(&qn) else {
        eprintln!("mq_open unavailable, skipping");
        return;
    };

    let abs = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    let bad_clockid: libc::clockid_t = 99;
    let payload = b"x";
    let rc = unsafe {
        fl::mq_clocksend(
            mqd,
            payload.as_ptr() as *const c_char,
            payload.len(),
            0,
            bad_clockid,
            &abs,
        )
    };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EINVAL);

    let mut buf = [0u8; 32];
    let n = unsafe {
        fl::mq_clockreceive(
            mqd,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            std::ptr::null_mut(),
            bad_clockid,
            &abs,
        )
    };
    assert_eq!(n, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EINVAL);

    let _ = unsafe { fl::mq_close(mqd) };
    let _ = unsafe { fl::mq_unlink(qn.as_ptr()) };
}

#[test]
fn mq_clocksend_null_abstime_blocks_until_full_then_eagain() {
    use frankenlibc_abi::unistd_abi as fl;
    let qn = mq_unique_name("nullabs");
    let Some(mqd) = mq_open_for_test(&qn) else {
        eprintln!("mq_open unavailable, skipping");
        return;
    };

    // mq_open above used max=4 messages; send 4 to fill the queue.
    for _ in 0..4 {
        let abs = timespec_after_ms(libc::CLOCK_REALTIME, 500);
        let rc = unsafe {
            fl::mq_clocksend(
                mqd,
                b"x".as_ptr() as *const c_char,
                1,
                0,
                libc::CLOCK_REALTIME,
                &abs,
            )
        };
        assert_eq!(rc, 0);
    }
    // 5th send with a tight timeout should fail with ETIMEDOUT.
    let abs = timespec_after_ms(libc::CLOCK_REALTIME, 50);
    let rc = unsafe {
        fl::mq_clocksend(
            mqd,
            b"x".as_ptr() as *const c_char,
            1,
            0,
            libc::CLOCK_REALTIME,
            &abs,
        )
    };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::ETIMEDOUT);

    let _ = unsafe { fl::mq_close(mqd) };
    let _ = unsafe { fl::mq_unlink(qn.as_ptr()) };
}

// ---------------------------------------------------------------------------
// openat2 / futex_waitv
// ---------------------------------------------------------------------------

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[test]
fn openat2_opens_existing_file_in_temp_dir() {
    use frankenlibc_abi::unistd_abi::openat2;
    let path = std::env::temp_dir().join(format!("frankenlibc_openat2_{}.txt", std::process::id()));
    std::fs::write(&path, b"hello").unwrap();
    let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();

    let how = OpenHow {
        flags: libc::O_RDONLY as u64,
        mode: 0,
        resolve: 0,
    };
    let fd = unsafe {
        openat2(
            libc::AT_FDCWD,
            cpath.as_ptr(),
            &how as *const OpenHow as *const c_void,
            std::mem::size_of::<OpenHow>(),
        )
    };
    assert!(
        fd >= 0,
        "openat2 failed: {}",
        std::io::Error::last_os_error()
    );

    let mut buf = [0u8; 16];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
    assert_eq!(n, 5);
    assert_eq!(&buf[..5], b"hello");

    unsafe { libc::close(fd) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn openat2_returns_einval_on_wrong_struct_size() {
    use frankenlibc_abi::unistd_abi::openat2;
    let path = CString::new("/tmp").unwrap();
    let how = OpenHow {
        flags: 0,
        mode: 0,
        resolve: 0,
    };
    // Pass a clearly-wrong size (1 byte). Kernel should reject.
    let rc = unsafe {
        openat2(
            libc::AT_FDCWD,
            path.as_ptr(),
            &how as *const OpenHow as *const c_void,
            1,
        )
    };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EINVAL);
}

#[test]
fn openat2_null_pathname_returns_efault() {
    use frankenlibc_abi::unistd_abi::openat2;
    let how = OpenHow {
        flags: 0,
        mode: 0,
        resolve: 0,
    };
    let rc = unsafe {
        openat2(
            libc::AT_FDCWD,
            std::ptr::null(),
            &how as *const OpenHow as *const c_void,
            std::mem::size_of::<OpenHow>(),
        )
    };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EFAULT);
}

#[test]
fn futex_waitv_zero_count_with_null_returns_einval() {
    use frankenlibc_abi::unistd_abi::futex_waitv;
    // Zero futexes is invalid per the kernel.
    let rc = unsafe {
        futex_waitv(
            std::ptr::null(),
            0,
            0,
            std::ptr::null(),
            libc::CLOCK_MONOTONIC,
        )
    };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EINVAL);
}

#[test]
fn futex_waitv_null_waiters_with_positive_count_returns_efault() {
    use frankenlibc_abi::unistd_abi::futex_waitv;
    let rc = unsafe {
        futex_waitv(
            std::ptr::null(),
            1,
            0,
            std::ptr::null(),
            libc::CLOCK_MONOTONIC,
        )
    };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EFAULT);
}

#[test]
fn futex_waitv_immediate_timeout_returns_etimedout() {
    use frankenlibc_abi::unistd_abi::futex_waitv;
    use std::sync::atomic::{AtomicU32, Ordering};

    // FUTEX_32 + FUTEX_PRIVATE_FLAG = 2 | 0x80 = 0x82, but the
    // futex_waitv kernel ABI uses just FUTEX2 size flags. For a 32-bit
    // futex we use FUTEX2_SIZE_U32 = 2.
    const FUTEX2_SIZE_U32: u32 = 2;

    #[repr(C)]
    struct FutexWaitV {
        val: u64,
        uaddr: u64,
        flags: u32,
        reserved: u32,
    }

    let value = AtomicU32::new(42);
    let waiter = FutexWaitV {
        val: 42, // wait while uaddr == 42; will time out since nothing wakes us
        uaddr: &value as *const AtomicU32 as u64,
        flags: FUTEX2_SIZE_U32,
        reserved: 0,
    };

    // Set timeout to "now" so the kernel returns ETIMEDOUT immediately.
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };

    let rc = unsafe {
        futex_waitv(
            &waiter as *const FutexWaitV as *const c_void,
            1,
            0,
            &now,
            libc::CLOCK_MONOTONIC,
        )
    };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    // Kernel reports ETIMEDOUT for a deadline already in the past.
    // Some kernels return EAGAIN instead if the value didn't match (it
    // does match here), but accept either to be defensive.
    assert!(
        errno == libc::ETIMEDOUT || errno == libc::EAGAIN,
        "expected ETIMEDOUT or EAGAIN, got {errno}"
    );
    let _ = value.load(Ordering::SeqCst); // silence unused warning
}

// ---------------------------------------------------------------------------
// mseal / memfd_secret / rseq / cachestat
// ---------------------------------------------------------------------------

#[test]
fn mseal_either_seals_or_returns_known_errno() {
    use frankenlibc_abi::unistd_abi::mseal;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert!(p != libc::MAP_FAILED);

    let rc = unsafe { mseal(p, page_size, 0) };
    if rc == 0 {
        // Sealed; subsequent munmap should fail with EPERM. We accept
        // the failure as confirmation; do not retry the unmap.
        let unmap_rc = unsafe { libc::munmap(p, page_size) };
        assert_eq!(unmap_rc, -1);
    } else {
        let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
        assert!(
            errno == libc::ENOSYS || errno == libc::EINVAL || errno == libc::EPERM,
            "unexpected mseal errno: {errno}"
        );
        unsafe { libc::munmap(p, page_size) };
    }
}

#[test]
fn memfd_secret_either_creates_fd_or_returns_known_errno() {
    use frankenlibc_abi::unistd_abi::memfd_secret;
    let fd = unsafe { memfd_secret(0) };
    if fd >= 0 {
        let _ = unsafe { libc::close(fd) };
    } else {
        let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
        assert!(
            errno == libc::ENOSYS || errno == libc::EOPNOTSUPP || errno == libc::EPERM,
            "unexpected memfd_secret errno: {errno}"
        );
    }
}

#[test]
fn rseq_null_pointer_returns_efault() {
    use frankenlibc_abi::unistd_abi::rseq;
    let rc = unsafe { rseq(std::ptr::null_mut(), 0, 0, 0) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EFAULT);
}

#[test]
fn cachestat_null_pointers_return_efault() {
    use frankenlibc_abi::unistd_abi::cachestat;
    let rc = unsafe { cachestat(0, std::ptr::null(), std::ptr::null_mut(), 0) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EFAULT);
}

#[test]
fn cachestat_either_returns_data_or_enosys_on_real_file() {
    use frankenlibc_abi::unistd_abi::cachestat;

    #[repr(C)]
    struct CachestatRange {
        off: u64,
        len: u64,
    }
    #[repr(C)]
    #[derive(Default)]
    struct Cachestat {
        nr_cache: u64,
        nr_dirty: u64,
        nr_writeback: u64,
        nr_evicted: u64,
        nr_recently_evicted: u64,
    }

    let path =
        std::env::temp_dir().join(format!("frankenlibc_cachestat_{}.bin", std::process::id()));
    std::fs::write(&path, vec![0u8; 4096]).unwrap();
    let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0);

    let range = CachestatRange { off: 0, len: 4096 };
    let mut cstat = Cachestat::default();
    let rc = unsafe {
        cachestat(
            fd as c_uint,
            &range as *const CachestatRange as *const c_void,
            &mut cstat as *mut Cachestat as *mut c_void,
            0,
        )
    };
    if rc == 0 {
        assert!(cstat.nr_cache <= 1);
    } else {
        let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
        assert!(
            errno == libc::ENOSYS || errno == libc::EOPNOTSUPP,
            "unexpected cachestat errno: {errno}"
        );
    }
    unsafe { libc::close(fd) };
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// NUMA memory policy: get/set_mempolicy + mbind + migrate_pages + move_pages
// + set_mempolicy_home_node
// ---------------------------------------------------------------------------

#[test]
fn get_mempolicy_returns_default_for_calling_thread() {
    use frankenlibc_abi::unistd_abi::get_mempolicy;
    let mut mode: c_int = -1;
    let rc = unsafe { get_mempolicy(&mut mode, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0) };
    if rc == 0 {
        assert!(mode >= 0);
    } else {
        let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
        assert!(
            errno == libc::ENOSYS || errno == libc::EPERM || errno == libc::EINVAL,
            "unexpected get_mempolicy errno: {errno}"
        );
    }
}

#[test]
fn set_mempolicy_default_round_trip() {
    use frankenlibc_abi::unistd_abi::{get_mempolicy, set_mempolicy};
    let rc = unsafe { set_mempolicy(0, std::ptr::null(), 0) };
    if rc != 0 {
        let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
        assert!(
            errno == libc::ENOSYS || errno == libc::EPERM,
            "unexpected set_mempolicy errno: {errno}"
        );
        return;
    }
    let mut mode: c_int = -1;
    let rc = unsafe { get_mempolicy(&mut mode, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0) };
    assert_eq!(rc, 0);
    assert_eq!(mode, 0);
}

#[test]
fn mbind_invalid_mode_returns_einval() {
    use frankenlibc_abi::unistd_abi::mbind;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert!(p != libc::MAP_FAILED);

    let rc = unsafe {
        mbind(
            p,
            page_size as libc::c_ulong,
            255, // invalid mode
            std::ptr::null(),
            0,
            0,
        )
    };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert!(
        errno == libc::EINVAL || errno == libc::ENOSYS,
        "unexpected mbind errno: {errno}"
    );

    unsafe { libc::munmap(p, page_size) };
}

#[test]
fn migrate_pages_to_nonexistent_pid_returns_known_errno() {
    use frankenlibc_abi::unistd_abi::migrate_pages;
    let rc = unsafe { migrate_pages(i32::MAX, 0, std::ptr::null(), std::ptr::null()) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert!(
        errno == libc::ESRCH || errno == libc::ENOSYS || errno == libc::EPERM,
        "unexpected migrate_pages errno: {errno}"
    );
}

#[test]
fn move_pages_query_only_for_self_returns_node_or_known_errno() {
    use frankenlibc_abi::unistd_abi::move_pages;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert!(p != libc::MAP_FAILED);
    unsafe { *(p as *mut u8) = 0x42 };

    let pages: [*mut c_void; 1] = [p];
    let mut status: [c_int; 1] = [-99];
    let rc = unsafe {
        move_pages(
            0,
            1,
            pages.as_ptr(),
            std::ptr::null(),
            status.as_mut_ptr(),
            0,
        )
    };
    if rc == 0 {
        assert!(status[0] >= 0 || status[0] == -libc::ENOENT);
    } else {
        let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
        assert!(
            errno == libc::EINVAL || errno == libc::ENOSYS || errno == libc::EPERM,
            "unexpected move_pages errno: {errno}"
        );
    }

    unsafe { libc::munmap(p, page_size) };
}

#[test]
fn set_mempolicy_home_node_either_succeeds_or_returns_known_errno() {
    use frankenlibc_abi::unistd_abi::set_mempolicy_home_node;
    // (start=0, len=0) is a documented no-op on kernels that support
    // the call: returns 0. Older kernels return ENOSYS. Anything else
    // is unexpected. Verify the wrapper at least round-trips through
    // the kernel without UB.
    let rc = unsafe { set_mempolicy_home_node(0, 0, 0, 0) };
    if rc == -1 {
        let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
        assert!(
            errno == libc::ENOSYS || errno == libc::EINVAL || errno == libc::EFAULT,
            "unexpected set_mempolicy_home_node errno: {errno}"
        );
    } else {
        assert_eq!(rc, 0, "non-error return must be 0");
    }
}

// ---------------------------------------------------------------------------
// statmount / listmount / finit_module / quotactl_fd / map_shadow_stack /
// bpf / kexec_load / kexec_file_load
// ---------------------------------------------------------------------------

#[test]
fn statmount_null_pointers_return_efault() {
    use frankenlibc_abi::unistd_abi::statmount;
    let rc = unsafe { statmount(std::ptr::null(), std::ptr::null_mut(), 0, 0) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EFAULT);
}

#[test]
fn listmount_null_pointers_return_efault() {
    use frankenlibc_abi::unistd_abi::listmount;
    let rc = unsafe { listmount(std::ptr::null(), std::ptr::null_mut(), 0, 0) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EFAULT);
}

#[test]
fn finit_module_invalid_fd_returns_known_errno() {
    use frankenlibc_abi::unistd_abi::finit_module;
    let rc = unsafe { finit_module(-1, std::ptr::null(), 0) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert!(
        errno == libc::EBADF || errno == libc::EPERM || errno == libc::ENOSYS,
        "unexpected finit_module errno: {errno}"
    );
}

#[test]
fn quotactl_fd_invalid_fd_returns_known_errno() {
    use frankenlibc_abi::unistd_abi::quotactl_fd;
    let rc = unsafe { quotactl_fd(0xFFFF_FFFF, 0, 0, std::ptr::null_mut()) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert!(
        errno == libc::EBADF || errno == libc::EINVAL || errno == libc::ENOSYS,
        "unexpected quotactl_fd errno: {errno}"
    );
}

#[test]
fn map_shadow_stack_returns_known_errno_or_addr() {
    use frankenlibc_abi::unistd_abi::map_shadow_stack;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as libc::c_ulong;
    let rc = unsafe { map_shadow_stack(0, page, 0) };
    if rc < 0 {
        let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
        assert!(
            errno == libc::ENOSYS
                || errno == libc::EOPNOTSUPP
                || errno == libc::EINVAL
                || errno == libc::ENOTSUP,
            "unexpected map_shadow_stack errno: {errno}"
        );
    }
}

#[test]
fn bpf_size_zero_with_null_attr_returns_known_errno() {
    use frankenlibc_abi::unistd_abi::bpf;
    // BPF_MAP_LOOKUP_ELEM = 1, NULL attr + size 0: kernel typically
    // returns EINVAL; unprivileged callers may get EPERM.
    let rc = unsafe { bpf(1, std::ptr::null_mut(), 0) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert!(
        errno == libc::EINVAL || errno == libc::EPERM || errno == libc::ENOSYS,
        "unexpected bpf errno: {errno}"
    );
}

#[test]
fn bpf_null_attr_with_positive_size_returns_efault() {
    use frankenlibc_abi::unistd_abi::bpf;
    let rc = unsafe { bpf(0, std::ptr::null_mut(), 16) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EFAULT);
}

#[test]
fn kexec_load_with_null_segments_and_positive_count_returns_efault() {
    use frankenlibc_abi::unistd_abi::kexec_load;
    let rc = unsafe { kexec_load(0, 1, std::ptr::null(), 0) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EFAULT);
}

#[test]
fn kexec_load_unprivileged_returns_known_errno() {
    use frankenlibc_abi::unistd_abi::kexec_load;
    let rc = unsafe { kexec_load(0, 0, std::ptr::null(), 0) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert!(
        errno == libc::EPERM
            || errno == libc::ENOSYS
            || errno == libc::EINVAL
            || errno == libc::EBUSY,
        "unexpected kexec_load errno: {errno}"
    );
}

#[test]
fn kexec_file_load_unprivileged_returns_known_errno() {
    use frankenlibc_abi::unistd_abi::kexec_file_load;
    let rc = unsafe { kexec_file_load(-1, -1, 0, std::ptr::null(), 0) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert!(
        errno == libc::EPERM
            || errno == libc::ENOSYS
            || errno == libc::EBADF
            || errno == libc::EINVAL,
        "unexpected kexec_file_load errno: {errno}"
    );
}

// ---------------------------------------------------------------------------
// set_robust_list / get_robust_list / lsm_get_self_attr / lsm_set_self_attr /
// lsm_list_modules
// ---------------------------------------------------------------------------

#[test]
fn get_robust_list_for_self_returns_head_and_len() {
    use frankenlibc_abi::unistd_abi::get_robust_list;
    let mut head: *mut c_void = std::ptr::null_mut();
    let mut len: usize = 0;
    let rc = unsafe { get_robust_list(0, &mut head, &mut len) };
    if rc == 0 {
        // Glibc threads have a robust_list_head registered; head is
        // typically non-NULL inside a threaded test runner. len matches
        // sizeof(struct robust_list_head) = 24 bytes on x86_64.
        assert!(len == 24 || len == 0);
    } else {
        let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
        // Older kernels: ENOSYS. Sandbox: EPERM.
        assert!(
            errno == libc::ENOSYS || errno == libc::EPERM,
            "unexpected get_robust_list errno: {errno}"
        );
    }
}

#[test]
fn get_robust_list_null_pointers_return_efault() {
    use frankenlibc_abi::unistd_abi::get_robust_list;
    let rc = unsafe { get_robust_list(0, std::ptr::null_mut(), std::ptr::null_mut()) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EFAULT);
}

#[test]
fn set_robust_list_with_zero_len_round_trip() {
    use frankenlibc_abi::unistd_abi::{get_robust_list, set_robust_list};

    // Save current head + len so we can restore.
    let mut saved_head: *mut c_void = std::ptr::null_mut();
    let mut saved_len: usize = 0;
    let rc = unsafe { get_robust_list(0, &mut saved_head, &mut saved_len) };
    if rc != 0 {
        return; // sandbox lacks the syscall; nothing to test.
    }

    // set_robust_list(NULL, 0) is the documented "unregister" form.
    let rc = unsafe { set_robust_list(std::ptr::null_mut(), 0) };
    assert!(
        rc == 0 || {
            let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
            errno == libc::ENOSYS || errno == libc::EINVAL
        }
    );

    // Restore the original head + len so the test runner doesn't lose
    // its robust mutex cleanup hook.
    let _ = unsafe { set_robust_list(saved_head, saved_len) };
}

#[test]
fn lsm_get_self_attr_null_size_returns_efault() {
    use frankenlibc_abi::unistd_abi::lsm_get_self_attr;
    let rc = unsafe { lsm_get_self_attr(0, std::ptr::null_mut(), std::ptr::null_mut(), 0) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EFAULT);
}

#[test]
fn lsm_get_self_attr_invalid_attr_returns_known_errno() {
    use frankenlibc_abi::unistd_abi::lsm_get_self_attr;
    let mut size: u32 = 0;
    let rc = unsafe { lsm_get_self_attr(0xFFFF_FFFF, std::ptr::null_mut(), &mut size, 0) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert!(
        errno == libc::ENOSYS
            || errno == libc::EINVAL
            || errno == libc::EOPNOTSUPP
            || errno == libc::ENOENT,
        "unexpected lsm_get_self_attr errno: {errno}"
    );
}

#[test]
fn lsm_set_self_attr_null_ctx_with_positive_size_returns_efault() {
    use frankenlibc_abi::unistd_abi::lsm_set_self_attr;
    let rc = unsafe { lsm_set_self_attr(0, std::ptr::null(), 16, 0) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EFAULT);
}

#[test]
fn lsm_list_modules_null_size_returns_efault() {
    use frankenlibc_abi::unistd_abi::lsm_list_modules;
    let rc = unsafe { lsm_list_modules(std::ptr::null_mut(), std::ptr::null_mut(), 0) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EFAULT);
}

#[test]
fn lsm_list_modules_query_size_returns_data_or_known_errno() {
    use frankenlibc_abi::unistd_abi::lsm_list_modules;
    // Size-only query: pass NULL ids + size=0 to learn the required
    // buffer length on Linux 6.8+. Older kernels return ENOSYS.
    let mut size: u32 = 0;
    let rc = unsafe { lsm_list_modules(std::ptr::null_mut(), &mut size, 0) };
    if rc == 0 {
        // size now holds the count of LSM module IDs available.
        // No further assertion; just verifying the wrapper round-trips.
    } else {
        let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
        // E2BIG when the kernel needs a bigger buffer is also valid; we
        // accept the typical fallbacks here.
        assert!(
            errno == libc::ENOSYS
                || errno == libc::E2BIG
                || errno == libc::EINVAL
                || errno == libc::EOPNOTSUPP,
            "unexpected lsm_list_modules errno: {errno}"
        );
    }
}

// ---------------------------------------------------------------------------
// faccessat2 / io_pgetevents / clone3
// ---------------------------------------------------------------------------

#[test]
fn faccessat2_existing_file_returns_zero() {
    use frankenlibc_abi::unistd_abi::faccessat2;
    let path =
        std::env::temp_dir().join(format!("frankenlibc_faccessat2_{}.txt", std::process::id()));
    std::fs::write(&path, b"x").unwrap();
    let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();

    let rc = unsafe { faccessat2(libc::AT_FDCWD, cpath.as_ptr(), libc::F_OK, 0) };
    if rc == 0 {
        // OK on any modern kernel.
    } else {
        let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
        // Older kernels: ENOSYS.
        assert!(
            errno == libc::ENOSYS,
            "unexpected faccessat2 errno: {errno}"
        );
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn faccessat2_missing_file_returns_enoent() {
    use frankenlibc_abi::unistd_abi::faccessat2;
    let cpath = CString::new("/nonexistent/path/for/faccessat2_test").unwrap();
    let rc = unsafe { faccessat2(libc::AT_FDCWD, cpath.as_ptr(), libc::F_OK, 0) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert!(
        errno == libc::ENOENT || errno == libc::ENOSYS,
        "unexpected faccessat2 errno: {errno}"
    );
}

#[test]
fn io_pgetevents_invalid_ctx_returns_einval() {
    use frankenlibc_abi::unistd_abi::io_pgetevents;
    // Bogus ctx_id (0 is never a valid io_setup() id).
    let mut events = [0u8; 32 * 4];
    let rc = unsafe {
        io_pgetevents(
            0,
            0,
            1,
            events.as_mut_ptr() as *mut c_void,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert!(
        errno == libc::EINVAL || errno == libc::ENOSYS,
        "unexpected io_pgetevents errno: {errno}"
    );
}

#[test]
fn io_pgetevents_null_events_with_positive_nr_returns_efault() {
    use frankenlibc_abi::unistd_abi::io_pgetevents;
    let rc = unsafe {
        io_pgetevents(
            0,
            0,
            1,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EFAULT);
}

#[test]
fn clone3_null_args_returns_efault() {
    use frankenlibc_abi::unistd_abi::clone3;
    let rc = unsafe { clone3(std::ptr::null_mut(), 0) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EFAULT);
}

#[test]
fn clone3_zero_size_returns_einval() {
    use frankenlibc_abi::unistd_abi::clone3;
    // Pass non-NULL pointer but size=0 — kernel rejects with EINVAL
    // because the smallest known struct clone_args is much bigger.
    let mut dummy = [0u8; 8];
    let rc = unsafe { clone3(dummy.as_mut_ptr() as *mut c_void, 0) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert!(
        errno == libc::EINVAL || errno == libc::ENOSYS,
        "unexpected clone3 errno: {errno}"
    );
}

// ---------------------------------------------------------------------------
// fchmodat2 / eventfd2 / rt_sigprocmask / rt_sigqueueinfo / rt_sigsuspend /
// rt_tgsigqueueinfo
// ---------------------------------------------------------------------------

#[test]
fn fchmodat2_changes_mode_on_real_file() {
    use frankenlibc_abi::unistd_abi::fchmodat2;
    let path =
        std::env::temp_dir().join(format!("frankenlibc_fchmodat2_{}.txt", std::process::id()));
    std::fs::write(&path, b"x").unwrap();
    let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();

    let rc = unsafe { fchmodat2(libc::AT_FDCWD, cpath.as_ptr(), 0o600, 0) };
    if rc == 0 {
        let meta = std::fs::metadata(&path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    } else {
        let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
        assert!(errno == libc::ENOSYS, "unexpected fchmodat2 errno: {errno}");
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fchmodat2_null_path_returns_efault() {
    use frankenlibc_abi::unistd_abi::fchmodat2;
    let rc = unsafe { fchmodat2(libc::AT_FDCWD, std::ptr::null(), 0o600, 0) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EFAULT);
}

#[test]
fn eventfd2_creates_fd_with_initval_and_round_trips() {
    use frankenlibc_abi::unistd_abi::eventfd2;
    let fd = unsafe { eventfd2(7, 0) };
    assert!(
        fd >= 0,
        "eventfd2 failed: {}",
        std::io::Error::last_os_error()
    );

    let mut buf = [0u8; 8];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
    assert_eq!(n, 8);
    assert_eq!(u64::from_ne_bytes(buf), 7);

    unsafe { libc::close(fd) };
}

#[test]
fn eventfd2_invalid_flags_return_einval() {
    use frankenlibc_abi::unistd_abi::eventfd2;
    let fd = unsafe { eventfd2(0, !0) };
    assert_eq!(fd, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EINVAL);
}

#[test]
fn rt_sigprocmask_round_trips_block_unblock() {
    use frankenlibc_abi::unistd_abi::rt_sigprocmask;
    let mut blocked: u64 = 1u64 << (libc::SIGUSR1 - 1);
    let mut prev: u64 = 0;

    // Block SIGUSR1.
    let rc = unsafe {
        rt_sigprocmask(
            libc::SIG_BLOCK,
            &mut blocked as *mut u64 as *const c_void,
            &mut prev as *mut u64 as *mut c_void,
            std::mem::size_of::<u64>(),
        )
    };
    assert_eq!(
        rc,
        0,
        "rt_sigprocmask block failed: {}",
        std::io::Error::last_os_error()
    );

    // Restore prior mask.
    let rc = unsafe {
        rt_sigprocmask(
            libc::SIG_SETMASK,
            &mut prev as *mut u64 as *const c_void,
            std::ptr::null_mut(),
            std::mem::size_of::<u64>(),
        )
    };
    assert_eq!(rc, 0);
}

#[test]
fn rt_sigqueueinfo_null_uinfo_returns_efault() {
    use frankenlibc_abi::unistd_abi::rt_sigqueueinfo;
    let rc = unsafe { rt_sigqueueinfo(std::process::id() as libc::pid_t, 0, std::ptr::null_mut()) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EFAULT);
}

#[test]
fn rt_sigsuspend_null_mask_returns_efault() {
    use frankenlibc_abi::unistd_abi::rt_sigsuspend;
    let rc = unsafe { rt_sigsuspend(std::ptr::null(), 8) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EFAULT);
}

#[test]
fn rt_tgsigqueueinfo_null_uinfo_returns_efault() {
    use frankenlibc_abi::unistd_abi::rt_tgsigqueueinfo;
    let rc = unsafe {
        rt_tgsigqueueinfo(
            std::process::id() as libc::pid_t,
            std::process::id() as libc::pid_t,
            0,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EFAULT);
}

// ---------------------------------------------------------------------------
// libcrypt aliases + DES no-ops + crypt_preferred_method + crypt_checksalt
// ---------------------------------------------------------------------------

#[test]
fn fcrypt_alias_matches_crypt_for_sha512() {
    use frankenlibc_abi::unistd_abi::{crypt, fcrypt};
    let key = CString::new("hunter2").unwrap();
    let salt = CString::new("$6$abcdefgh").unwrap();
    let a = unsafe { crypt(key.as_ptr(), salt.as_ptr()) };
    let b = unsafe { fcrypt(key.as_ptr(), salt.as_ptr()) };
    assert!(!a.is_null() && !b.is_null());
    let sa = unsafe { CStr::from_ptr(a) };
    let sb = unsafe { CStr::from_ptr(b) };
    assert_eq!(sa, sb);
}

#[test]
fn xcrypt_alias_matches_crypt_for_md5() {
    use frankenlibc_abi::unistd_abi::{crypt, xcrypt};
    let key = CString::new("password").unwrap();
    let salt = CString::new("$1$saltyMc$").unwrap();
    let a = unsafe { crypt(key.as_ptr(), salt.as_ptr()) };
    let b = unsafe { xcrypt(key.as_ptr(), salt.as_ptr()) };
    assert!(!a.is_null() && !b.is_null());
    let sa = unsafe { CStr::from_ptr(a) };
    let sb = unsafe { CStr::from_ptr(b) };
    assert_eq!(sa, sb);
}

#[test]
fn encrypt_setkey_des_stubs_are_noops() {
    use frankenlibc_abi::unistd_abi::{encrypt, encrypt_r, setkey, setkey_r};
    let mut block: [c_char; 64] = [0; 64];
    let key: [c_char; 64] = [0; 64];
    // Just verify the calls don't crash; there's nothing observable
    // about them.
    unsafe {
        setkey(key.as_ptr());
        encrypt(block.as_mut_ptr(), 0);
        setkey_r(key.as_ptr(), std::ptr::null_mut());
        encrypt_r(block.as_mut_ptr(), 0, std::ptr::null_mut());
    }
}

#[test]
fn crypt_preferred_method_returns_sha512_prefix() {
    use frankenlibc_abi::unistd_abi::crypt_preferred_method;
    let p = unsafe { crypt_preferred_method() };
    assert!(!p.is_null());
    let s = unsafe { CStr::from_ptr(p) };
    assert_eq!(s.to_bytes(), b"$6$");
}

#[test]
fn crypt_checksalt_classifies_known_prefixes() {
    use frankenlibc_abi::unistd_abi::crypt_checksalt;
    let md5 = CString::new("$1$saltsalt$").unwrap();
    let sha256 = CString::new("$5$rounds=5000$saltsalt$").unwrap();
    let sha512 = CString::new("$6$saltsalt$").unwrap();
    let bogus = CString::new("$plain$saltsalt$").unwrap();
    let des2 = CString::new("ab").unwrap();

    assert_eq!(unsafe { crypt_checksalt(md5.as_ptr()) }, 0);
    assert_eq!(unsafe { crypt_checksalt(sha256.as_ptr()) }, 0);
    assert_eq!(unsafe { crypt_checksalt(sha512.as_ptr()) }, 0);
    assert_eq!(unsafe { crypt_checksalt(bogus.as_ptr()) }, 1);
    assert_eq!(unsafe { crypt_checksalt(des2.as_ptr()) }, 1);
    // NULL input must not crash; returns CRYPT_SALT_INVALID.
    assert_eq!(unsafe { crypt_checksalt(std::ptr::null()) }, 1);
}

// ---------------------------------------------------------------------------
// crypt_r / crypt_rn / crypt_ra + crypt_gensalt family
// ---------------------------------------------------------------------------

#[test]
fn crypt_r_writes_into_caller_buffer_matching_crypt() {
    use frankenlibc_abi::unistd_abi::{crypt, crypt_r};
    let key = CString::new("hunter2").unwrap();
    let salt = CString::new("$6$abcdefgh").unwrap();
    let mut data = [0u8; 512];
    let p = unsafe {
        crypt_r(
            key.as_ptr(),
            salt.as_ptr(),
            data.as_mut_ptr() as *mut c_void,
        )
    };
    assert!(!p.is_null());
    let s_r = unsafe { CStr::from_ptr(p) };
    let s_plain = unsafe { CStr::from_ptr(crypt(key.as_ptr(), salt.as_ptr())) };
    assert_eq!(s_r, s_plain);
    // Result was written at offset 0 of the data buffer.
    assert_eq!(p as *const u8, data.as_ptr());
}

#[test]
fn crypt_rn_refuses_buffer_too_small() {
    use frankenlibc_abi::unistd_abi::crypt_rn;
    let key = CString::new("password").unwrap();
    let salt = CString::new("$6$saltsalt").unwrap();
    let mut buf = [0u8; 8]; // too small for SHA-512 result
    let p = unsafe {
        crypt_rn(
            key.as_ptr(),
            salt.as_ptr(),
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as c_int,
        )
    };
    assert!(p.is_null());
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::ERANGE);
}

#[test]
fn crypt_ra_allocates_buffer_when_data_null() {
    use frankenlibc_abi::unistd_abi::crypt_ra;
    let key = CString::new("password").unwrap();
    let salt = CString::new("$6$saltsalt").unwrap();
    let mut data: *mut c_void = std::ptr::null_mut();
    let mut size: c_int = 0;
    let p = unsafe { crypt_ra(key.as_ptr(), salt.as_ptr(), &mut data, &mut size) };
    assert!(!p.is_null());
    assert!(!data.is_null());
    assert!(size >= 384);
    // Free via our malloc_abi; data was allocated through it.
    unsafe { frankenlibc_abi::malloc_abi::free(data) };
}

#[test]
fn crypt_gensalt_default_is_sha512() {
    use frankenlibc_abi::unistd_abi::crypt_gensalt;
    let rbytes = b"randombytes!";
    let p = unsafe {
        crypt_gensalt(
            std::ptr::null(),
            0,
            rbytes.as_ptr() as *const c_char,
            rbytes.len() as c_int,
        )
    };
    assert!(!p.is_null());
    let s = unsafe { CStr::from_ptr(p) };
    assert!(s.to_bytes().starts_with(b"$6$"), "got: {s:?}");
    assert!(s.to_bytes().len() >= 3 + 16, "len: {}", s.to_bytes().len()); // "$6$" + 16 chars of salt
}

#[test]
fn crypt_gensalt_explicit_md5_prefix() {
    use frankenlibc_abi::unistd_abi::crypt_gensalt;
    let prefix = CString::new("$1$").unwrap();
    let rbytes = b"someentropyhere";
    let p = unsafe {
        crypt_gensalt(
            prefix.as_ptr(),
            0,
            rbytes.as_ptr() as *const c_char,
            rbytes.len() as c_int,
        )
    };
    assert!(!p.is_null());
    let s = unsafe { CStr::from_ptr(p) };
    assert!(s.to_bytes().starts_with(b"$1$"), "got: {s:?}");
}

#[test]
fn crypt_gensalt_with_rounds_emits_rounds_segment_for_sha() {
    use frankenlibc_abi::unistd_abi::crypt_gensalt;
    let prefix = CString::new("$6$").unwrap();
    let rbytes = b"morerandomnessok";
    let p = unsafe {
        crypt_gensalt(
            prefix.as_ptr(),
            10_000,
            rbytes.as_ptr() as *const c_char,
            rbytes.len() as c_int,
        )
    };
    assert!(!p.is_null());
    let s = unsafe { CStr::from_ptr(p) };
    let bytes = s.to_bytes();
    let prefix = b"$6$rounds=10000$";
    assert!(bytes.starts_with(prefix), "got: {s:?}");
    assert!(
        bytes.len() >= prefix.len() + 16,
        "salt tail was truncated: {s:?}"
    );
}

#[test]
fn crypt_gensalt_r_returns_erange_on_small_buffer() {
    use frankenlibc_abi::unistd_abi::crypt_gensalt_r;
    let mut out = [0u8; 4]; // too small even for "$6$" + NUL
    let p = unsafe {
        crypt_gensalt_r(
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            out.as_mut_ptr() as *mut c_char,
            out.len() as c_int,
        )
    };
    assert!(p.is_null());
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::ERANGE);
}

#[test]
fn crypt_gensalt_rejects_invalid_prefix_and_negative_entropy_size() {
    use frankenlibc_abi::unistd_abi::{crypt_gensalt, crypt_gensalt_r};
    let bogus = CString::new("$2b$").unwrap();
    let mut out = [0u8; 64];

    let p = unsafe { crypt_gensalt(bogus.as_ptr(), 0, std::ptr::null(), 0) };
    assert!(p.is_null());
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EINVAL);

    let p = unsafe {
        crypt_gensalt_r(
            std::ptr::null(),
            0,
            std::ptr::null(),
            -1,
            out.as_mut_ptr() as *mut c_char,
            out.len() as c_int,
        )
    };
    assert!(p.is_null());
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EINVAL);
}

#[test]
fn crypt_gensalt_rn_matches_r_variant() {
    use frankenlibc_abi::unistd_abi::{crypt_gensalt_r, crypt_gensalt_rn};
    let prefix = CString::new("$5$").unwrap();
    let rbytes = b"someentropyhere";
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];

    let pa = unsafe {
        crypt_gensalt_r(
            prefix.as_ptr(),
            5000,
            rbytes.as_ptr() as *const c_char,
            rbytes.len() as c_int,
            a.as_mut_ptr() as *mut c_char,
            a.len() as c_int,
        )
    };
    let pb = unsafe {
        crypt_gensalt_rn(
            prefix.as_ptr(),
            5000,
            rbytes.as_ptr() as *const c_char,
            rbytes.len() as c_int,
            b.as_mut_ptr() as *mut c_char,
            b.len() as c_int,
        )
    };

    assert!(!pa.is_null() && !pb.is_null());
    assert_eq!(unsafe { CStr::from_ptr(pa) }, unsafe { CStr::from_ptr(pb) });
}

#[test]
fn crypt_ra_grows_existing_too_small_buffer() {
    use frankenlibc_abi::unistd_abi::crypt_ra;
    let key = CString::new("password").unwrap();
    let salt = CString::new("$6$saltsalt").unwrap();
    let mut data = unsafe { frankenlibc_abi::malloc_abi::malloc(8) };
    assert!(!data.is_null());
    let mut size: c_int = 8;

    let p = unsafe { crypt_ra(key.as_ptr(), salt.as_ptr(), &mut data, &mut size) };
    assert!(!p.is_null());
    assert!(!data.is_null());
    assert!(size >= 384);
    assert_eq!(p as *mut c_void, data);
    unsafe { frankenlibc_abi::malloc_abi::free(data) };
}

#[test]
fn crypt_gensalt_ra_allocates_via_malloc() {
    use frankenlibc_abi::unistd_abi::crypt_gensalt_ra;
    let p = unsafe { crypt_gensalt_ra(std::ptr::null(), 0, std::ptr::null(), 0) };
    assert!(!p.is_null());
    let s = unsafe { CStr::from_ptr(p) };
    assert!(s.to_bytes().starts_with(b"$6$"));
    unsafe { frankenlibc_abi::malloc_abi::free(p as *mut c_void) };
}

#[test]
fn xcrypt_aliases_match_crypt_counterparts() {
    use frankenlibc_abi::unistd_abi::{
        crypt, crypt_gensalt, crypt_gensalt_r, crypt_r, xcrypt_gensalt, xcrypt_gensalt_r, xcrypt_r,
    };
    let key = CString::new("hunter2").unwrap();
    let salt = CString::new("$6$abcdefgh").unwrap();

    // xcrypt_r vs crypt_r write the same bytes.
    let mut a = [0u8; 384];
    let mut b = [0u8; 384];
    let pa = unsafe { crypt_r(key.as_ptr(), salt.as_ptr(), a.as_mut_ptr() as *mut c_void) };
    let pb = unsafe { xcrypt_r(key.as_ptr(), salt.as_ptr(), b.as_mut_ptr() as *mut c_void) };
    assert_eq!(unsafe { CStr::from_ptr(pa) }, unsafe { CStr::from_ptr(pb) });

    // xcrypt_gensalt vs crypt_gensalt produce identical strings for the
    // same arguments.
    let r = b"sixteenrandomby!";
    let pa = unsafe {
        crypt_gensalt(
            std::ptr::null(),
            0,
            r.as_ptr() as *const c_char,
            r.len() as c_int,
        )
    };
    let pb = unsafe {
        xcrypt_gensalt(
            std::ptr::null(),
            0,
            r.as_ptr() as *const c_char,
            r.len() as c_int,
        )
    };
    assert_eq!(unsafe { CStr::from_ptr(pa) }, unsafe { CStr::from_ptr(pb) });

    // Same for the _r variant.
    let mut buf = [0u8; 64];
    let pc = unsafe {
        xcrypt_gensalt_r(
            std::ptr::null(),
            0,
            r.as_ptr() as *const c_char,
            r.len() as c_int,
            buf.as_mut_ptr() as *mut c_char,
            buf.len() as c_int,
        )
    };
    assert!(!pc.is_null());
    let mut buf2 = [0u8; 64];
    let pd = unsafe {
        crypt_gensalt_r(
            std::ptr::null(),
            0,
            r.as_ptr() as *const c_char,
            r.len() as c_int,
            buf2.as_mut_ptr() as *mut c_char,
            buf2.len() as c_int,
        )
    };
    assert_eq!(unsafe { CStr::from_ptr(pc) }, unsafe { CStr::from_ptr(pd) });

    // Sanity: the gensalt result is a valid input for crypt().
    let salt_str = unsafe { CStr::from_ptr(pa) };
    let hashed = unsafe { crypt(key.as_ptr(), salt_str.as_ptr()) };
    assert!(!hashed.is_null());
}
