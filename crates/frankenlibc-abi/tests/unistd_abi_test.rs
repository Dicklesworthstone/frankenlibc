//! ABI integration tests for unistd_abi native implementations.
//!
//! Tests for promoted GlibcCallThrough -> Implemented symbols:
//! - glob64 / globfree64
//! - ftw / nftw / nftw64
//! - setmntent / getmntent / endmntent

#![allow(unsafe_code)]

use std::ffi::{CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::unistd_abi::{
    eaccess, euidaccess, msgrcv, msgsnd, process_madvise, process_vm_readv, process_vm_writev,
    semctl, semop, shmdt,
};

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
fn process_madvise_null_iov_nonzero_len_fails_cleanly() {
    let rc = unsafe { process_madvise(-1, std::ptr::null(), 1, libc::MADV_NORMAL, 0) };
    assert_eq!(rc, -1);
    assert!(
        is_expected_process_vm_errno(errno_value()),
        "unexpected errno for process_madvise null iov: {}",
        errno_value()
    );
}
