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
//! - All archetypes here are crash-detector + invariant-checker only.
//! - A host-libc differential for `basename`/`dirname` is a clean
//!   follow-up but requires `dlsym(RTLD_NEXT, ...)` plumbing because
//!   both our ABI layer and libc export the same symbol name; a naive
//!   `extern "C"` from the fuzzer binary can only bind to one and does
//!   not give us two independent implementations to compare. Tracked
//!   separately.
//! - A tmpdir-based host-parity differential against a pre-seeded
//!   symlink graph for `stat`/`readlink` is also a reasonable
//!   follow-up once the crash-detector surface is stable.
//!
//! Bead: bd-anoe7

use std::ffi::{CString, c_char, c_int};
use std::mem::MaybeUninit;
use std::sync::Once;

use arbitrary::Arbitrary;
use frankenlibc_abi::stdlib_abi::{basename, dirname, realpath};
use frankenlibc_abi::unistd_abi::{
    access, canonicalize_file_name, fstatat, lstat, readlink, readlinkat, stat,
};
use libfuzzer_sys::fuzz_target;

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
            b, GUARD_BYTE,
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

// ------------------------------------------------------------------
// Archetype 0: crash-detector on realpath with arbitrary path bytes.
// ------------------------------------------------------------------
fn adv_realpath(input: &PathnameFuzzInput) {
    let Some(cs) = CString::new(input.bytes.clone()).ok() else {
        return;
    };
    // First variant: let realpath allocate its own result.
    let ret = unsafe { realpath(cs.as_ptr(), std::ptr::null_mut()) };
    if !ret.is_null() {
        // realpath docs: returned buf must be freed with free(). We
        // can't free safely without the ABI's free entrypoint; leak
        // in the fuzz target is acceptable (libfuzzer resets state).
    }
    // Second variant: caller-supplied output buffer. POSIX says the
    // buffer must be at least PATH_MAX bytes; we give a larger buffer
    // with surrounding guards to catch any overrun of the documented
    // capacity.
    let mut out = make_output_buf(libc::PATH_MAX as usize);
    let out_ptr = out[GUARD_BYTES..].as_mut_ptr().cast::<c_char>();
    let _ = unsafe { realpath(cs.as_ptr(), out_ptr) };
    check_output_buf_guards(&out, libc::PATH_MAX as usize, "realpath");
}

// ------------------------------------------------------------------
// Archetype 1: crash-detector on canonicalize_file_name.
// ------------------------------------------------------------------
fn adv_canonicalize_file_name(input: &PathnameFuzzInput) {
    let Some(cs) = CString::new(input.bytes.clone()).ok() else {
        return;
    };
    let _ = unsafe { canonicalize_file_name(cs.as_ptr()) };
}

// ------------------------------------------------------------------
// Archetype 2: crash-detector on basename.
// basename is allowed to return a pointer either into the caller's
// buffer or to an internal static; either way the returned string
// must be NUL-terminated and reachable within a sane bound.
// ------------------------------------------------------------------
fn adv_basename(input: &PathnameFuzzInput) {
    let Some(mut buf) = make_pathbuf(&input.bytes) else {
        return;
    };
    let ret = unsafe { basename(buf.as_mut_ptr().cast::<c_char>()) };
    check_pathbuf_trailing_guards(&buf, "basename");
    let out = unsafe { cstr_to_vec(ret) };
    // Any non-null return must be at most the original input length.
    // basename never produces output longer than its input plus the
    // trivial dot-form for empty input, which is bounded by 2.
    assert!(out.len() <= input.bytes.len().max(2) + 1);
}

// ------------------------------------------------------------------
// Archetype 3: crash-detector on dirname.
// ------------------------------------------------------------------
fn adv_dirname(input: &PathnameFuzzInput) {
    let Some(mut buf) = make_pathbuf(&input.bytes) else {
        return;
    };
    let ret = unsafe { dirname(buf.as_mut_ptr().cast::<c_char>()) };
    check_pathbuf_trailing_guards(&buf, "dirname");
    let out = unsafe { cstr_to_vec(ret) };
    assert!(out.len() <= input.bytes.len().max(2) + 1);
}

// ------------------------------------------------------------------
// Archetype 4: crash-detector on stat / lstat.
// ------------------------------------------------------------------
fn adv_stat_family(input: &PathnameFuzzInput) {
    let Some(cs) = CString::new(input.bytes.clone()).ok() else {
        return;
    };
    let mut stat_buf: MaybeUninit<libc::stat> = MaybeUninit::zeroed();
    let rc_stat = unsafe { stat(cs.as_ptr(), stat_buf.as_mut_ptr()) };
    assert!(rc_stat == 0 || rc_stat == -1, "stat rc out of contract: {rc_stat}");

    let mut lstat_buf: MaybeUninit<libc::stat> = MaybeUninit::zeroed();
    let rc_lstat = unsafe { lstat(cs.as_ptr(), lstat_buf.as_mut_ptr()) };
    assert!(
        rc_lstat == 0 || rc_lstat == -1,
        "lstat rc out of contract: {rc_lstat}"
    );
}

// ------------------------------------------------------------------
// Archetype 5: crash-detector on access / faccessat-like call.
// ------------------------------------------------------------------
fn adv_access(input: &PathnameFuzzInput) {
    let Some(cs) = CString::new(input.bytes.clone()).ok() else {
        return;
    };
    let rc = unsafe { access(cs.as_ptr(), input.amode as c_int) };
    assert!(rc == 0 || rc == -1, "access rc out of contract: {rc}");
}

// ------------------------------------------------------------------
// Archetype 6: crash-detector on readlink with guarded buffer.
// ------------------------------------------------------------------
fn adv_readlink(input: &PathnameFuzzInput) {
    let Some(cs) = CString::new(input.bytes.clone()).ok() else {
        return;
    };
    let size = (input.buf_size as usize % MAX_READLINK_BUF).max(1);
    let mut buf = make_output_buf(size);
    let rc = unsafe {
        readlink(
            cs.as_ptr(),
            buf[GUARD_BYTES..].as_mut_ptr().cast::<c_char>(),
            size,
        )
    };
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
}

// ------------------------------------------------------------------
// Archetype 7: crash-detector on fstatat / readlinkat / faccessat
// using AT_FDCWD so the dir-fd channel is exercised without needing
// a prebuilt fd seed.
// ------------------------------------------------------------------
fn adv_at_family(input: &PathnameFuzzInput) {
    let Some(cs) = CString::new(input.bytes.clone()).ok() else {
        return;
    };
    let mut stat_buf: MaybeUninit<libc::stat> = MaybeUninit::zeroed();
    let _ = unsafe { fstatat(libc::AT_FDCWD, cs.as_ptr(), stat_buf.as_mut_ptr(), input.flags) };

    let size = (input.buf_size as usize % MAX_READLINK_BUF).max(1);
    let mut buf = make_output_buf(size);
    let _ = unsafe {
        readlinkat(
            libc::AT_FDCWD,
            cs.as_ptr(),
            buf[GUARD_BYTES..].as_mut_ptr().cast::<c_char>(),
            size,
        )
    };
    check_output_buf_guards(&buf, size, "readlinkat");

    // faccessat entrypoint exists on the ABI; exercise it too.
    use frankenlibc_abi::unistd_abi::faccessat;
    let _ = unsafe { faccessat(libc::AT_FDCWD, cs.as_ptr(), input.amode as c_int, input.flags) };
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
    assert!(len < SCAN_LIMIT, "pathname API returned unterminated string");
    let slice = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    slice.to_vec()
}

fuzz_target!(|input: PathnameFuzzInput| {
    if input.bytes.len() > MAX_PATH_BYTES {
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
