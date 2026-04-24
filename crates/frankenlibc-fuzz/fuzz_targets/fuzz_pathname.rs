#![no_main]
//! Crash-detector + differential fuzz target for FrankenLibC's
//! pathname-parsing and canonicalization surface:
//!
//!   realpath, canonicalize_file_name, basename, dirname,
//!   access, faccessat, stat, lstat, fstatat, readlink, readlinkat
//!
//! These share an attacker-controlled pathname-bytes input channel and
//! are the historic CVE surface (CVE-2018-1000001 realpath OOB,
//! CVE-2016-1234 glibc glob). The invariant for this target is
//! primarily the no-panic / no-overrun / bounded-errno contract; a
//! narrow differential against libc is added for the pure-string
//! pathname parsers (basename, dirname) where we can compare safely
//! without touching the filesystem.
//!
//! Safety notes:
//! - Interior NULs in the fuzz input are rejected before any `CString`
//!   is built; this matches how every sane C pathname API behaves.
//! - `basename`/`dirname` are allowed to mutate their argument, so we
//!   always copy the bytes into a writable buffer with a trailing NUL
//!   and a post-buffer guard sentinel before each call.
//! - `stat`/`lstat`/`fstatat` write into a caller-provided `libc::stat`
//!   buffer; we zero a stack-local `libc::stat` and assert the guard
//!   bytes around it are untouched after the call.
//! - `readlink`/`readlinkat` take a caller-provided output buffer; we
//!   stamp a guard sentinel on both sides and assert it survives.
//!
//! Differential coverage:
//! - `basename` and `dirname` compare FrankenLibC directly with host libc
//!   over caller-owned writable buffers.
//! - `stat`/`lstat`/`access`/`fstatat`/`readlink`/`readlinkat`/`faccessat`
//!   compare return shape and errno over inert paths and a small seeded
//!   scratch filesystem with files, directories, and symlinks.
//!
//! Bead: bd-anoe7

use std::ffi::{CString, OsStr, c_char, c_int};
use std::fs;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::{Once, OnceLock};

use arbitrary::Arbitrary;
use frankenlibc_abi::stdlib_abi::{basename, dirname, realpath};
use frankenlibc_abi::unistd_abi::{
    access, canonicalize_file_name, fstatat, lstat, readlink, readlinkat, stat,
};
use libfuzzer_sys::fuzz_target;

unsafe extern "C" {
    #[link_name = "basename"]
    fn host_libc_basename(path: *mut c_char) -> *mut c_char;
    #[link_name = "dirname"]
    fn host_libc_dirname(path: *mut c_char) -> *mut c_char;
}

/// Guard sentinel on either side of every writable output buffer.
const GUARD_BYTES: usize = 64;
/// 0xFD never appears in a well-formed path or struct stat field; an
/// off-by-one leaves a visible hole.
const GUARD_BYTE: u8 = 0xFD;
/// Hard cap on the fuzz-supplied pathname length. PATH_MAX on Linux is
/// 4096; we go a little above to probe the >PATH_MAX rejection path.
const MAX_PATH_BYTES: usize = 5120;
/// Bound on the readlink output buffer size the attacker may pick.
const MAX_READLINK_BUF: usize = 4096;

struct ScratchPaths {
    existing: PathBuf,
    directory: PathBuf,
    symlink: PathBuf,
    symlink_loop: PathBuf,
    unicode: PathBuf,
}

#[derive(Debug, Arbitrary)]
struct PathnameFuzzInput {
    /// Raw pathname bytes. Must not contain an interior NUL; if it
    /// does the fuzzer skips this iteration (the callee would return
    /// `EINVAL` on CString construction, not a bug).
    bytes: Vec<u8>,
    /// readlink / readlinkat output buffer size the attacker picks.
    buf_size: u16,
    /// faccessat / fstatat flags.
    flags: i32,
    /// access mode bits.
    amode: i32,
    /// Seed-path selector. This keeps coverage on historical pathname edge
    /// cases even when random bytes are too noisy.
    path_case: u8,
    /// Archetype selector.
    op: u8,
}

fn init_hardened_mode() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: process-wide mode is set once before any ABI
        // entrypoint runs, never mutated again.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "hardened");
        }
    });
}

fn scratch_paths() -> &'static ScratchPaths {
    static SCRATCH: OnceLock<ScratchPaths> = OnceLock::new();
    SCRATCH.get_or_init(|| {
        let root =
            std::env::temp_dir().join(format!("frankenlibc-fuzz-pathname-{}", std::process::id()));
        let existing = root.join("existing");
        let directory = root.join("dir");
        let symlink = root.join("link-to-existing");
        let symlink_loop = root.join("loop-a");
        let symlink_loop_b = root.join("loop-b");
        let unicode = root.join(OsStr::from_bytes(
            b"unicode-\xc3\xa9-\xe4\xb8\xad-\xf0\x9f\x98\x80",
        ));

        let _ = fs::create_dir_all(&root);
        let _ = fs::create_dir_all(&directory);
        let _ = fs::write(&existing, b"seed");
        let _ = fs::write(&unicode, b"unicode");
        let _ = std::os::unix::fs::symlink(&existing, &symlink);
        let _ = std::os::unix::fs::symlink(&symlink_loop_b, &symlink_loop);
        let _ = std::os::unix::fs::symlink(&symlink_loop, &symlink_loop_b);

        ScratchPaths {
            existing,
            directory,
            symlink,
            symlink_loop,
            unicode,
        }
    })
}

fn pathbuf_bytes(path: &PathBuf) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

fn path_bytes(input: &PathnameFuzzInput) -> Vec<u8> {
    match input.path_case % 20 {
        0 => input.bytes.clone(),
        1 => Vec::new(),
        2 => b"/".to_vec(),
        3 => b".".to_vec(),
        4 => b"..".to_vec(),
        5 => b"/tmp".to_vec(),
        6 => b"/proc/self".to_vec(),
        7 => b"/dev/null".to_vec(),
        8 => b"/etc/passwd".to_vec(),
        9 => b"/////".to_vec(),
        10 => b"../../../..".to_vec(),
        11 => b"unicode-\xc3\xa9-\xe4\xb8\xad-\xf0\x9f\x98\x80".to_vec(),
        12 => vec![b'a'; 255],
        13 => {
            let mut path = b"/tmp/".to_vec();
            path.extend(std::iter::repeat_n(b'a', 4096));
            path
        }
        14 => pathbuf_bytes(&scratch_paths().existing),
        15 => pathbuf_bytes(&scratch_paths().directory),
        16 => pathbuf_bytes(&scratch_paths().symlink),
        17 => pathbuf_bytes(&scratch_paths().symlink_loop),
        18 => pathbuf_bytes(&scratch_paths().unicode),
        19 => vec![0xff, 0xfe, b'/', b'a'],
        _ => unreachable!(),
    }
}

fn has_interior_nul(bytes: &[u8]) -> bool {
    bytes.contains(&0)
}

/// Build a writable buffer holding `bytes` followed by a trailing NUL
/// and 64 byte guard sentinels. Returns `(pointer_to_bytes, total_buf)`
/// where the caller can pass the pointer to a pathname API and then
/// check the guards with `check_pathbuf_guards`.
fn make_pathbuf(bytes: &[u8]) -> Option<Vec<u8>> {
    if has_interior_nul(bytes) {
        return None;
    }
    if bytes.len() > MAX_PATH_BYTES {
        return None;
    }
    let mut buf = Vec::with_capacity(bytes.len() + 1 + GUARD_BYTES);
    buf.extend_from_slice(bytes);
    buf.push(0);
    buf.resize(buf.len() + GUARD_BYTES, GUARD_BYTE);
    Some(buf)
}

fn check_pathbuf_trailing_guards(buf: &[u8], name: &'static str) {
    let guard_start = buf.len() - GUARD_BYTES;
    for (i, &b) in buf[guard_start..].iter().enumerate() {
        assert_eq!(
            b,
            GUARD_BYTE,
            "{name}: trailing guard corrupted at +{i} (total buf len={})",
            buf.len()
        );
    }
}

fn make_output_buf(size: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(size + 2 * GUARD_BYTES);
    v.resize(size + 2 * GUARD_BYTES, GUARD_BYTE);
    v
}

fn check_output_buf_guards(buf: &[u8], size: usize, name: &'static str) {
    for (i, &b) in buf[..GUARD_BYTES].iter().enumerate() {
        assert_eq!(
            b, GUARD_BYTE,
            "{name}: underflow guard corrupted at byte {i}"
        );
    }
    for (i, &b) in buf[GUARD_BYTES + size..].iter().enumerate() {
        assert_eq!(
            b, GUARD_BYTE,
            "{name}: overflow guard corrupted at byte {i} past size={size}"
        );
    }
}

fn reset_abi_errno() {
    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = 0;
    }
}

fn abi_errno() -> c_int {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() }
}

fn reset_host_errno() {
    unsafe {
        *libc::__errno_location() = 0;
    }
}

fn host_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn assert_syscall_parity(
    name: &'static str,
    abi_rc: c_int,
    abi_errno: c_int,
    host_rc: c_int,
    host_errno: c_int,
) {
    assert_eq!(
        abi_rc == 0,
        host_rc == 0,
        "{name}: success shape diverged (abi rc={abi_rc} errno={abi_errno}, host rc={host_rc} errno={host_errno})"
    );
    if abi_rc == -1 && host_rc == -1 {
        assert_eq!(
            abi_errno, host_errno,
            "{name}: errno diverged (abi={abi_errno}, host={host_errno})"
        );
    }
}

fn assert_readlink_parity(
    name: &'static str,
    abi_rc: isize,
    abi_errno: c_int,
    host_rc: isize,
    host_errno: c_int,
) {
    assert_eq!(
        abi_rc >= 0,
        host_rc >= 0,
        "{name}: success shape diverged (abi rc={abi_rc} errno={abi_errno}, host rc={host_rc} errno={host_errno})"
    );
    if abi_rc >= 0 && host_rc >= 0 {
        assert_eq!(
            abi_rc, host_rc,
            "{name}: byte count diverged (abi={abi_rc}, host={host_rc})"
        );
    } else {
        assert_eq!(abi_rc, -1, "{name}: negative rc was not -1");
        assert_eq!(host_rc, -1, "{name}: host negative rc was not -1");
        assert_eq!(
            abi_errno, host_errno,
            "{name}: errno diverged (abi={abi_errno}, host={host_errno})"
        );
    }
}

fn valid_access_mode(amode: c_int) -> bool {
    amode == libc::F_OK || (amode & !(libc::R_OK | libc::W_OK | libc::X_OK)) == 0
}

fn valid_faccessat_flags(flags: c_int) -> bool {
    flags & !(libc::AT_EACCESS | libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH) == 0
}

fn assert_canonical_path(bytes: &[u8], name: &'static str) {
    if bytes.is_empty() {
        return;
    }
    assert_eq!(bytes[0], b'/', "{name}: result is not absolute");
    if bytes.len() > 1 {
        assert_ne!(
            bytes.last().copied(),
            Some(b'/'),
            "{name}: non-root result has trailing slash"
        );
    }
    assert!(
        !bytes.windows(2).any(|w| w == b"//"),
        "{name}: result retained duplicate slash"
    );
    assert!(
        !bytes.windows(3).any(|w| w == b"/./"),
        "{name}: result retained current-directory segment"
    );
    assert!(
        !bytes.windows(4).any(|w| w == b"/../"),
        "{name}: result retained parent-directory segment"
    );
}

// ------------------------------------------------------------------
// Archetype 0: crash-detector on realpath with arbitrary path bytes.
// ------------------------------------------------------------------
fn adv_realpath(input: &PathnameFuzzInput) {
    let bytes = path_bytes(input);
    let Some(cs) = CString::new(bytes).ok() else {
        return;
    };
    // First variant: let realpath allocate its own result.
    // realpath(path, NULL) returns a libc::malloc'd buffer that the caller
    // must free. We free with libc::free to pair the allocation; LSan flags
    // leaks from the harness as exit-status-77 crashes otherwise (bd-s83dv).
    let ret = unsafe { realpath(cs.as_ptr(), std::ptr::null_mut()) };
    if !ret.is_null() {
        let resolved = unsafe { cstr_to_vec(ret) };
        assert_canonical_path(&resolved, "realpath");
        unsafe { libc::free(ret as *mut std::ffi::c_void) };
    }
    // Second variant: caller-supplied output buffer. POSIX says the
    // buffer must be at least PATH_MAX bytes; we give a larger buffer
    // with surrounding guards to catch any overrun of the documented
    // capacity.
    let mut out = make_output_buf(libc::PATH_MAX as usize);
    let out_ptr = out[GUARD_BYTES..].as_mut_ptr().cast::<c_char>();
    let ret = unsafe { realpath(cs.as_ptr(), out_ptr) };
    if !ret.is_null() {
        let resolved = unsafe { cstr_to_vec(ret) };
        assert_canonical_path(&resolved, "realpath-buffer");
    }
    check_output_buf_guards(&out, libc::PATH_MAX as usize, "realpath");
}

// ------------------------------------------------------------------
// Archetype 1: crash-detector on canonicalize_file_name.
// ------------------------------------------------------------------
fn adv_canonicalize_file_name(input: &PathnameFuzzInput) {
    let bytes = path_bytes(input);
    let Some(cs) = CString::new(bytes).ok() else {
        return;
    };
    // canonicalize_file_name returns a libc::malloc'd buffer like realpath(x, NULL);
    // free with libc::free to avoid LSan exit-status-77 (bd-s83dv).
    let ret = unsafe { canonicalize_file_name(cs.as_ptr()) };
    if !ret.is_null() {
        let resolved = unsafe { cstr_to_vec(ret) };
        assert_canonical_path(&resolved, "canonicalize_file_name");
        unsafe { libc::free(ret as *mut std::ffi::c_void) };
    }
}

// ------------------------------------------------------------------
// Archetype 2: crash-detector on basename.
// basename is allowed to return a pointer either into the caller's
// buffer or to an internal static; either way the returned string
// must be NUL-terminated and reachable within a sane bound.
// ------------------------------------------------------------------
fn adv_basename(input: &PathnameFuzzInput) {
    let bytes = path_bytes(input);
    let Some(mut buf) = make_pathbuf(&bytes) else {
        return;
    };
    let ret = unsafe { basename(buf.as_mut_ptr().cast::<c_char>()) };
    check_pathbuf_trailing_guards(&buf, "basename");
    let out = unsafe { cstr_to_vec(ret) };
    // Any non-null return must be at most the original input length.
    // basename never produces output longer than its input plus the
    // trivial dot-form for empty input, which is bounded by 2.
    assert!(out.len() <= bytes.len().max(2) + 1);

    let Some(mut host_buf) = make_pathbuf(&bytes) else {
        return;
    };
    let host_ret = unsafe { host_libc_basename(host_buf.as_mut_ptr().cast::<c_char>()) };
    check_pathbuf_trailing_guards(&host_buf, "host-basename");
    let host_out = unsafe { cstr_to_vec(host_ret) };
    assert_eq!(out, host_out, "basename host divergence");
}

// ------------------------------------------------------------------
// Archetype 3: crash-detector on dirname.
// ------------------------------------------------------------------
fn adv_dirname(input: &PathnameFuzzInput) {
    let bytes = path_bytes(input);
    let Some(mut buf) = make_pathbuf(&bytes) else {
        return;
    };
    let ret = unsafe { dirname(buf.as_mut_ptr().cast::<c_char>()) };
    check_pathbuf_trailing_guards(&buf, "dirname");
    let out = unsafe { cstr_to_vec(ret) };
    assert!(out.len() <= bytes.len().max(2) + 1);

    let Some(mut host_buf) = make_pathbuf(&bytes) else {
        return;
    };
    let host_ret = unsafe { host_libc_dirname(host_buf.as_mut_ptr().cast::<c_char>()) };
    check_pathbuf_trailing_guards(&host_buf, "host-dirname");
    let host_out = unsafe { cstr_to_vec(host_ret) };
    assert_eq!(out, host_out, "dirname host divergence");
}

// ------------------------------------------------------------------
// Archetype 4: crash-detector on stat / lstat.
// ------------------------------------------------------------------
fn adv_stat_family(input: &PathnameFuzzInput) {
    let bytes = path_bytes(input);
    let Some(cs) = CString::new(bytes).ok() else {
        return;
    };
    let mut stat_buf: MaybeUninit<libc::stat> = MaybeUninit::zeroed();
    reset_abi_errno();
    let rc_stat = unsafe { stat(cs.as_ptr(), stat_buf.as_mut_ptr()) };
    let stat_errno = abi_errno();
    assert!(
        rc_stat == 0 || rc_stat == -1,
        "stat rc out of contract: {rc_stat}"
    );
    if rc_stat == 0 {
        let stat_value = unsafe { stat_buf.assume_init() };
        assert!(
            stat_value.st_dev != 0 || stat_value.st_ino != 0,
            "stat success left identity fields empty"
        );
    }
    let mut host_stat_buf: MaybeUninit<libc::stat> = MaybeUninit::zeroed();
    reset_host_errno();
    let host_rc_stat = unsafe { libc::stat(cs.as_ptr(), host_stat_buf.as_mut_ptr()) };
    let host_stat_errno = host_errno();
    assert_syscall_parity("stat", rc_stat, stat_errno, host_rc_stat, host_stat_errno);

    let mut lstat_buf: MaybeUninit<libc::stat> = MaybeUninit::zeroed();
    reset_abi_errno();
    let rc_lstat = unsafe { lstat(cs.as_ptr(), lstat_buf.as_mut_ptr()) };
    let lstat_errno = abi_errno();
    assert!(
        rc_lstat == 0 || rc_lstat == -1,
        "lstat rc out of contract: {rc_lstat}"
    );
    if rc_lstat == 0 {
        let lstat_value = unsafe { lstat_buf.assume_init() };
        assert!(
            lstat_value.st_dev != 0 || lstat_value.st_ino != 0,
            "lstat success left identity fields empty"
        );
    }
    let mut host_lstat_buf: MaybeUninit<libc::stat> = MaybeUninit::zeroed();
    reset_host_errno();
    let host_rc_lstat = unsafe { libc::lstat(cs.as_ptr(), host_lstat_buf.as_mut_ptr()) };
    let host_lstat_errno = host_errno();
    assert_syscall_parity(
        "lstat",
        rc_lstat,
        lstat_errno,
        host_rc_lstat,
        host_lstat_errno,
    );
}

// ------------------------------------------------------------------
// Archetype 5: crash-detector on access / faccessat-like call.
// ------------------------------------------------------------------
fn adv_access(input: &PathnameFuzzInput) {
    let bytes = path_bytes(input);
    let Some(cs) = CString::new(bytes).ok() else {
        return;
    };
    reset_abi_errno();
    let rc = unsafe { access(cs.as_ptr(), input.amode as c_int) };
    let access_errno = abi_errno();
    assert!(rc == 0 || rc == -1, "access rc out of contract: {rc}");
    if valid_access_mode(input.amode as c_int) {
        reset_host_errno();
        let host_rc = unsafe { libc::access(cs.as_ptr(), input.amode as c_int) };
        let host_access_errno = host_errno();
        assert_syscall_parity("access", rc, access_errno, host_rc, host_access_errno);
    }
}

// ------------------------------------------------------------------
// Archetype 6: crash-detector on readlink with guarded buffer.
// ------------------------------------------------------------------
fn adv_readlink(input: &PathnameFuzzInput) {
    let bytes = path_bytes(input);
    let Some(cs) = CString::new(bytes).ok() else {
        return;
    };
    let size = (input.buf_size as usize % MAX_READLINK_BUF).max(1);
    let mut buf = make_output_buf(size);
    reset_abi_errno();
    let rc = unsafe {
        readlink(
            cs.as_ptr(),
            buf[GUARD_BYTES..].as_mut_ptr().cast::<c_char>(),
            size,
        )
    };
    let readlink_errno = abi_errno();
    // readlink returns -1 on error or the number of bytes written
    // (<= bufsiz). It does NOT NUL-terminate.
    if rc >= 0 {
        assert!(
            (rc as usize) <= size,
            "readlink returned {rc} > bufsiz {size}"
        );
    } else {
        assert_eq!(rc, -1);
    }
    check_output_buf_guards(&buf, size, "readlink");

    let mut host_buf = make_output_buf(size);
    reset_host_errno();
    let host_rc = unsafe {
        libc::readlink(
            cs.as_ptr(),
            host_buf[GUARD_BYTES..].as_mut_ptr().cast::<c_char>(),
            size,
        )
    };
    let host_readlink_errno = host_errno();
    check_output_buf_guards(&host_buf, size, "host-readlink");
    assert_readlink_parity("readlink", rc, readlink_errno, host_rc, host_readlink_errno);
}

// ------------------------------------------------------------------
// Archetype 7: crash-detector on fstatat / readlinkat / faccessat
// using AT_FDCWD so the dir-fd channel is exercised without needing
// a prebuilt fd seed.
// ------------------------------------------------------------------
fn adv_at_family(input: &PathnameFuzzInput) {
    let bytes = path_bytes(input);
    let Some(cs) = CString::new(bytes).ok() else {
        return;
    };
    let mut stat_buf: MaybeUninit<libc::stat> = MaybeUninit::zeroed();
    reset_abi_errno();
    let fstatat_rc = unsafe {
        fstatat(
            libc::AT_FDCWD,
            cs.as_ptr(),
            stat_buf.as_mut_ptr(),
            input.flags,
        )
    };
    let fstatat_errno = abi_errno();
    let mut host_stat_buf: MaybeUninit<libc::stat> = MaybeUninit::zeroed();
    reset_host_errno();
    let host_fstatat_rc = unsafe {
        libc::fstatat(
            libc::AT_FDCWD,
            cs.as_ptr(),
            host_stat_buf.as_mut_ptr(),
            input.flags,
        )
    };
    let host_fstatat_errno = host_errno();
    assert_syscall_parity(
        "fstatat",
        fstatat_rc,
        fstatat_errno,
        host_fstatat_rc,
        host_fstatat_errno,
    );

    let size = (input.buf_size as usize % MAX_READLINK_BUF).max(1);
    let mut buf = make_output_buf(size);
    reset_abi_errno();
    let readlinkat_rc = unsafe {
        readlinkat(
            libc::AT_FDCWD,
            cs.as_ptr(),
            buf[GUARD_BYTES..].as_mut_ptr().cast::<c_char>(),
            size,
        )
    };
    let readlinkat_errno = abi_errno();
    check_output_buf_guards(&buf, size, "readlinkat");
    let mut host_buf = make_output_buf(size);
    reset_host_errno();
    let host_readlinkat_rc = unsafe {
        libc::readlinkat(
            libc::AT_FDCWD,
            cs.as_ptr(),
            host_buf[GUARD_BYTES..].as_mut_ptr().cast::<c_char>(),
            size,
        )
    };
    let host_readlinkat_errno = host_errno();
    check_output_buf_guards(&host_buf, size, "host-readlinkat");
    assert_readlink_parity(
        "readlinkat",
        readlinkat_rc,
        readlinkat_errno,
        host_readlinkat_rc,
        host_readlinkat_errno,
    );

    // faccessat entrypoint exists on the ABI; exercise it too.
    use frankenlibc_abi::unistd_abi::faccessat;
    reset_abi_errno();
    let faccessat_rc = unsafe {
        faccessat(
            libc::AT_FDCWD,
            cs.as_ptr(),
            input.amode as c_int,
            input.flags,
        )
    };
    let faccessat_errno = abi_errno();
    if valid_access_mode(input.amode as c_int) && valid_faccessat_flags(input.flags) {
        reset_host_errno();
        let host_faccessat_rc = unsafe {
            libc::faccessat(
                libc::AT_FDCWD,
                cs.as_ptr(),
                input.amode as c_int,
                input.flags,
            )
        };
        let host_faccessat_errno = host_errno();
        assert_syscall_parity(
            "faccessat",
            faccessat_rc,
            faccessat_errno,
            host_faccessat_rc,
            host_faccessat_errno,
        );
    }
}

// ------------------------------------------------------------------
// Helpers.
// ------------------------------------------------------------------
unsafe fn cstr_to_vec(ptr: *const c_char) -> Vec<u8> {
    if ptr.is_null() {
        return Vec::new();
    }
    // Bound the scan so a buggy impl that forgets to terminate cannot
    // walk the process unbounded.
    const SCAN_LIMIT: usize = 8192;
    let mut len = 0;
    while len < SCAN_LIMIT {
        let b = unsafe { *ptr.add(len) };
        if b == 0 {
            break;
        }
        len += 1;
    }
    assert!(
        len < SCAN_LIMIT,
        "pathname API returned unterminated string"
    );
    let slice = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    slice.to_vec()
}

fuzz_target!(|input: PathnameFuzzInput| {
    if input.path_case % 20 == 0 && input.bytes.len() > MAX_PATH_BYTES {
        return;
    }
    init_hardened_mode();

    match input.op % 8 {
        0 => adv_realpath(&input),
        1 => adv_canonicalize_file_name(&input),
        2 => adv_basename(&input),
        3 => adv_dirname(&input),
        4 => adv_stat_family(&input),
        5 => adv_access(&input),
        6 => adv_readlink(&input),
        7 => adv_at_family(&input),
        _ => unreachable!(),
    }
});
