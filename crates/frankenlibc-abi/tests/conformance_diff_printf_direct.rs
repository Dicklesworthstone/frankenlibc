#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc snprintf/fprintf oracles resolved by dlsym

//! Differential gate for the direct `printf`/`snprintf` payload paths (bd-xh08pf).
//!
//! ## Replaces three tests that had never run
//!
//! `stdio_abi.rs` is `#[cfg(not(test))] pub mod` in lib.rs, so its inline
//! `#[cfg(test)]` block compiles in neither configuration. Three of its stranded
//! tests covered the direct payload paths, each by driving a module-private
//! item:
//!
//! | stranded test | private item it drove |
//! |---|---|
//! | `printf_direct_payload_classifies_string_newline_only_for_nonnull_s` | `direct_printf_string_payload` |
//! | `printf_direct_payload_copy_preserves_snprintf_truncation_boundary` | `copy_direct_printf_payload` |
//! | `printf_direct_unsigned_decimal_preserves_full_length_and_truncation` | `strict_direct_snprintf_u` |
//!
//! They are rewritten here against the public entry points and live glibc. The
//! originals asserted fl's private helpers matched fl's own expectations; these
//! assert fl's OUTPUT matches glibc's, which is the contract that actually binds.
//!
//! ## The stream case uses a TEMP FILE, not stdout capture
//!
//! The `%s\n` classifier exists for the printf-to-stream path, so it needs a
//! stream. It deliberately does NOT redirect the process's fd 1: tests in this
//! suite that do so are flaky under default libtest parallelism, because other
//! threads' progress lines land in the capture — observed on
//! `conformance_diff_error_at_line` on 2026-09-01, where a byte comparison over
//! a captured buffer failed while the arms had produced identical output. A
//! per-call `fopen`/`fprintf`/`fclose` on a private temp file has no such
//! coupling, and it still exercises the stream writer.

use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

type Snprintf = unsafe extern "C" fn(*mut c_char, usize, *const c_char, ...) -> c_int;
type Fopen = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type Fprintf = unsafe extern "C" fn(*mut c_void, *const c_char, ...) -> c_int;
type Fclose = unsafe extern "C" fn(*mut c_void) -> c_int;

union SymSnprintf {
    raw: *mut c_void,
    function: Snprintf,
}
union SymFopen {
    raw: *mut c_void,
    function: Fopen,
}
union SymFprintf {
    raw: *mut c_void,
    function: Fprintf,
}
union SymFclose {
    raw: *mut c_void,
    function: Fclose,
}

fn host_handle() -> *mut c_void {
    // SAFETY: the name is a NUL-terminated constant; RTLD_LOCAL keeps the handle
    // out of the global namespace.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6 — the oracle is unavailable");
    handle
}

fn raw_sym(handle: *mut c_void, name: &CStr, fl_addr: usize) -> *mut c_void {
    // SAFETY: handle came from dlopen; the name is NUL-terminated.
    let raw = unsafe { libc::dlsym(handle, name.as_ptr()) };
    assert!(!raw.is_null(), "dlsym {name:?}");
    assert_ne!(
        raw as usize, fl_addr,
        "the resolved oracle IS fl's {name:?} — this gate would compare fl to itself (bd-v0388t)"
    );
    raw
}

const CAP: usize = 32;
/// Poison, so bytes past the terminator are observable: a path that writes one
/// byte too many, or fails to terminate, changes this pattern.
const POISON: u8 = 0x55;

/// Compare fl and glibc `snprintf` on one call: return value AND the whole
/// destination buffer, including everything past the NUL.
fn both_snprintf_str(host: Snprintf, fmt: &CStr, arg: *const c_char, size: usize, label: &str) {
    assert!(size <= CAP);
    let mut fl = [POISON; CAP];
    let mut gl = [POISON; CAP];
    // SAFETY: both buffers are CAP bytes, size <= CAP, and the format takes
    // exactly the one `*const c_char` supplied.
    let fl_rc = unsafe {
        frankenlibc_abi::stdio_abi::snprintf(fl.as_mut_ptr().cast::<c_char>(), size, fmt.as_ptr(), arg)
    };
    // SAFETY: same shape into the dlsym-resolved glibc.
    let gl_rc = unsafe { host(gl.as_mut_ptr().cast::<c_char>(), size, fmt.as_ptr(), arg) };
    assert_eq!(
        (fl_rc, &fl[..]),
        (gl_rc, &gl[..]),
        "{label}: fl=({fl_rc}, {:?}) glibc=({gl_rc}, {:?})",
        String::from_utf8_lossy(&fl),
        String::from_utf8_lossy(&gl),
    );
}

/// The `strict_direct_snprintf_u` contract, through the public `snprintf`.
///
/// The stranded original called the private unsigned-decimal writer directly and
/// checked the return length and the truncation boundary. Restated: glibc is the
/// authority on both. Every size from 0 past the full length is swept, so the cut
/// falls before, inside and after the digits.
#[test]
fn unsigned_decimal_length_and_truncation_match_glibc() {
    let handle = host_handle();
    let raw = raw_sym(
        handle,
        c"snprintf",
        frankenlibc_abi::stdio_abi::snprintf as *const () as usize,
    );
    // SAFETY: the symbol is glibc's snprintf with this signature.
    let host: Snprintf = unsafe { SymSnprintf { raw }.function };

    for value in [0u32, 9, 10, 1_000_000, u32::MAX] {
        for size in 0..=12usize {
            let mut fl = [POISON; CAP];
            let mut gl = [POISON; CAP];
            // SAFETY: buffers are CAP bytes and size <= CAP; "%u" takes one c_uint.
            let fl_rc = unsafe {
                frankenlibc_abi::stdio_abi::snprintf(
                    fl.as_mut_ptr().cast::<c_char>(), size, c"%u".as_ptr(), value as c_uint)
            };
            // SAFETY: same shape into glibc.
            let gl_rc = unsafe { host(gl.as_mut_ptr().cast::<c_char>(), size, c"%u".as_ptr(), value as c_uint) };
            assert_eq!(
                (fl_rc, &fl[..]),
                (gl_rc, &gl[..]),
                "%u value={value} size={size}: fl=({fl_rc}, {:?}) glibc=({gl_rc}, {:?})",
                String::from_utf8_lossy(&fl),
                String::from_utf8_lossy(&gl),
            );
            // Pin the ORACLE's own answer, not just that the arms agree: C
            // requires the length that WOULD have been written.
            assert_eq!(
                gl_rc as usize,
                value.to_string().len(),
                "glibc should report the untruncated length for {value} at size={size}"
            );
        }
    }
}

/// The `copy_direct_printf_payload` contract, through the public `snprintf`.
///
/// The original copied `b"abcdef"` with a trailing newline into 8- and 4-byte
/// buffers and checked where the NUL landed. Restated as `"%s\n"` against glibc
/// over every size, which covers those two cases and the boundaries either side.
#[test]
fn string_newline_payload_truncation_matches_glibc() {
    let handle = host_handle();
    let raw = raw_sym(
        handle,
        c"snprintf",
        frankenlibc_abi::stdio_abi::snprintf as *const () as usize,
    );
    // SAFETY: the symbol is glibc's snprintf with this signature.
    let host: Snprintf = unsafe { SymSnprintf { raw }.function };

    for size in 0..=10usize {
        both_snprintf_str(host, c"%s\n", c"abcdef".as_ptr(), size, &format!("%s\\n size={size}"));
    }
    // The shapes the original asserted the classifier must DECLINE. They must
    // still format correctly, which is the only externally visible consequence.
    for size in [0usize, 1, 4, 8, CAP] {
        both_snprintf_str(host, c"[%s]\n", c"status=ok".as_ptr(), size, &format!("[%s]\\n size={size}"));
    }
}

/// A NULL `%s` argument, which the original asserted the classifier declines.
///
/// This is the externally visible half of that rule and it is a real divergence
/// risk rather than an internal detail: glibc prints `(null)` for a NULL `%s`,
/// so a direct path that took the pointer would fault or print nothing. Kept in
/// its own test because it is the one case where the two impls could differ in
/// a way that is not merely a truncation offset.
#[test]
fn null_string_argument_matches_glibc() {
    let handle = host_handle();
    let raw = raw_sym(
        handle,
        c"snprintf",
        frankenlibc_abi::stdio_abi::snprintf as *const () as usize,
    );
    // SAFETY: the symbol is glibc's snprintf with this signature.
    let host: Snprintf = unsafe { SymSnprintf { raw }.function };

    for size in [0usize, 1, 3, 6, 7, CAP] {
        both_snprintf_str(host, c"%s\n", std::ptr::null(), size, &format!("NULL %s size={size}"));
    }
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_path(tag: &str) -> (std::path::PathBuf, std::ffi::CString) {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-printf-direct-{}-{tag}-{n}", std::process::id()));
    let c = std::ffi::CString::new(p.to_string_lossy().as_bytes()).unwrap();
    (p, c)
}

/// The stream half of the direct `%s\n` payload path.
///
/// Each impl opens its OWN temp file with its OWN `fopen`, writes with its own
/// `fprintf`, and closes with its own `fclose`, so neither can be measured
/// through the other's buffering. The files are compared byte for byte along
/// with both return values.
///
/// Deliberately NOT stdout capture — see the module comment.
#[test]
fn stream_string_newline_matches_glibc_on_a_private_file() {
    let handle = host_handle();
    // SAFETY: each symbol is glibc's, with the signature its type states, and
    // each is checked against fl's own export for the collapse case.
    let fopen: Fopen = unsafe {
        SymFopen { raw: raw_sym(handle, c"fopen", frankenlibc_abi::stdio_abi::fopen as *const () as usize) }.function
    };
    let fprintf: Fprintf = unsafe {
        SymFprintf { raw: raw_sym(handle, c"fprintf", frankenlibc_abi::stdio_abi::fprintf as *const () as usize) }.function
    };
    let fclose: Fclose = unsafe {
        SymFclose { raw: raw_sym(handle, c"fclose", frankenlibc_abi::stdio_abi::fclose as *const () as usize) }.function
    };

    for (fmt, arg) in [
        (c"%s\n", c"status=ok"),
        (c"[%s]\n", c"status=ok"),
        (c"%s", c"no-newline"),
    ] {
        let (fl_path, fl_c) = temp_path("fl");
        let (gl_path, gl_c) = temp_path("gl");

        // SAFETY: both paths are NUL-terminated; the format takes the one
        // `*const c_char` supplied; each stream is closed exactly once.
        let fl_rc = unsafe {
            let f = frankenlibc_abi::stdio_abi::fopen(fl_c.as_ptr(), c"w".as_ptr());
            assert!(!f.is_null(), "fl fopen");
            let rc = frankenlibc_abi::stdio_abi::fprintf(f, fmt.as_ptr(), arg.as_ptr());
            frankenlibc_abi::stdio_abi::fclose(f);
            rc
        };
        // SAFETY: same shape into the dlsym-resolved glibc.
        let gl_rc = unsafe {
            let f = fopen(gl_c.as_ptr(), c"w".as_ptr());
            assert!(!f.is_null(), "glibc fopen");
            let rc = fprintf(f, fmt.as_ptr(), arg.as_ptr());
            fclose(f);
            rc
        };

        let fl_bytes = std::fs::read(&fl_path).expect("read fl output");
        let gl_bytes = std::fs::read(&gl_path).expect("read glibc output");
        let _ = std::fs::remove_file(&fl_path);
        let _ = std::fs::remove_file(&gl_path);

        assert_eq!(
            (fl_rc, &fl_bytes[..]),
            (gl_rc, &gl_bytes[..]),
            "fprintf {:?}: fl=({fl_rc}, {:?}) glibc=({gl_rc}, {:?})",
            fmt.to_str().unwrap_or("<bad utf8>"),
            String::from_utf8_lossy(&fl_bytes),
            String::from_utf8_lossy(&gl_bytes),
        );
    }
}
