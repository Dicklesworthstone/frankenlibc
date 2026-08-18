#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc getmntent_r oracle

//! `getmntent`'s freq/passno fields are read by glibc with
//! `sscanf(rest, "%d %d", &freq, &passno)`, and that is not the same as parsing
//! each whitespace token as an integer.
//!
//! Two consequences a per-token parse gets wrong, both asserted here:
//!   * COUPLING — if the first conversion stops mid-token, the second never
//!     matches and passno keeps its initial 0, even when the text after it is a
//!     perfectly good number. `"12abc 3"` is freq 12, passno 0.
//!   * WRAPPING — `%d` is strtol into a long (saturating at the long ends) kept
//!     in an int, so out-of-range input keeps its low 32 bits instead of being
//!     rejected. `"99999999999"` is 1215752191, not 0.
//!
//! THE ORACLE NEEDS NO FILE. `fmemopen` turns a byte string into a `FILE*`, so
//! host `getmntent_r` can be driven over synthetic mount-table lines without
//! writing anything to disk — which also means the test cannot be affected by,
//! or corrupt, the real /etc/mtab.

use std::ffi::{c_char, c_int, c_void};

#[repr(C)]
struct Mntent {
    mnt_fsname: *mut c_char,
    mnt_dir: *mut c_char,
    mnt_type: *mut c_char,
    mnt_opts: *mut c_char,
    mnt_freq: c_int,
    mnt_passno: c_int,
}

unsafe extern "C" {
    fn fmemopen(buf: *mut c_void, size: usize, mode: *const c_char) -> *mut c_void;
    fn fclose(stream: *mut c_void) -> c_int;
    fn getmntent_r(
        stream: *mut c_void,
        result: *mut Mntent,
        buffer: *mut c_char,
        bufsize: c_int,
    ) -> *mut Mntent;
}

/// Drive host glibc over one synthetic line; returns (freq, passno).
fn host_freq_passno(tail: &str) -> Option<(i32, i32)> {
    let line = format!("dev /d ext4 rw {tail}\n");
    let mut data = line.into_bytes();
    let mode = c"r";
    let stream = unsafe { fmemopen(data.as_mut_ptr().cast(), data.len(), mode.as_ptr()) };
    if stream.is_null() {
        return None;
    }
    let mut entry = Mntent {
        mnt_fsname: std::ptr::null_mut(),
        mnt_dir: std::ptr::null_mut(),
        mnt_type: std::ptr::null_mut(),
        mnt_opts: std::ptr::null_mut(),
        mnt_freq: 0,
        mnt_passno: 0,
    };
    let mut scratch = vec![0 as c_char; 4096];
    let got = unsafe {
        getmntent_r(
            stream,
            &mut entry,
            scratch.as_mut_ptr(),
            scratch.len() as c_int,
        )
    };
    let out = if got.is_null() {
        None
    } else {
        Some((entry.mnt_freq, entry.mnt_passno))
    };
    unsafe { fclose(stream) };
    out
}

/// Cases chosen so each one fails a DIFFERENT plausible shortcut: a per-token
/// parse, a non-wrapping parse, a base-detecting parse, a parse that rejects
/// trailing garbage instead of stopping at it.
const CASES: &[&str] = &[
    "0 0",
    "7 3",
    "007 3",
    "+5 6",
    "-1 -2",
    "12abc 3", // coupling: passno must be 0, not 3
    "abc 3",   // first conversion matches nothing: both stay 0
    "0x10 3",  // base 10, so "0" then stop: both 0
    "1e3 3",   // 1 then stop
    "3 12xy",  // second may stop early; nothing follows it
    "3 abc",
    "99999999999 3", // low 32 bits
    "-99999999999 3",
    "2147483647 3",
    "2147483648 3", // wraps to i32::MIN
    "4294967296 3", // exactly 2^32 -> 0
    "4294967297 3",
    "9223372036854775808 3", // beyond i64: saturates, low 32 bits are -1
    "99999999999999999999999 3",
    "-9223372036854775809 3",
    "3 99999999999",
    "5",
    "+ 3", // sign with no digits is not a match
    "- 3",
    "3 +",
    "0 007",
];

#[test]
fn freq_passno_matches_glibc_sscanf_semantics() {
    let mut compared = 0usize;
    let mut divergences = Vec::new();
    for &tail in CASES {
        let Some((g_freq, g_passno)) = host_freq_passno(tail) else {
            continue;
        };
        // Split the way fl's line parser does, then hand the two tokens over.
        let mut tokens = tail.split_whitespace();
        let freq_s = tokens.next().unwrap_or("0").as_bytes();
        let passno_s = tokens.next().unwrap_or("0").as_bytes();
        let (f_freq, f_passno) =
            frankenlibc_core::mntent::parse_mntent_freq_passno(freq_s, passno_s);
        compared += 1;
        if (f_freq, f_passno) != (g_freq, g_passno) {
            divergences.push(format!(
                "{tail:?}: fl=({f_freq}, {f_passno}) glibc=({g_freq}, {g_passno})"
            ));
        }
    }

    assert_eq!(
        compared,
        CASES.len(),
        "the fmemopen oracle failed to parse some cases; a skipped case is not a pass"
    );
    assert!(
        divergences.is_empty(),
        "mntent freq/passno divergences ({} of {compared}):\n  {}",
        divergences.len(),
        divergences.join("\n  ")
    );
}
