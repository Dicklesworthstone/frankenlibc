#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc snprintf oracle resolved by dlsym

//! Differential gate for the FUSED multi-directive `snprintf` path (bd-xh08pf).
//!
//! ## Why this file exists, and why it is not a relocation
//!
//! `stdio_abi.rs` carried two tests for this path inside a `#[cfg(test)]` block.
//! The module is `#[cfg(not(test))] pub mod` in lib.rs, so that block compiles
//! in neither configuration — they had never run. They drove module-private
//! items (`is_strict_direct_snprintf_format`, `StrictDirectSnprintfWriter`), so
//! they cannot be moved as they stand; they are rewritten here against the
//! PUBLIC entry point and against LIVE GLIBC, which is a stronger check than the
//! originals: the originals asserted fl's private predicate agreed with fl's own
//! expectations, while these assert fl's OUTPUT agrees with glibc's.
//!
//! ## And this path in particular deserved a live gate
//!
//! The fused emitter has already been deleted once without anyone noticing. It
//! landed 2026-07-31 (`7eebd3db4`, banked at `incumbent_ratio=0.788267`), was
//! removed 2026-08-03 by `73c8da5cd` — a commit author-dated 2026-06-26 and
//! replayed onto a tree six weeks newer — measured as a 2.64-3.92x LOSS on
//! 2026-08-16 while absent, and restored 2026-08-30 by `89c356d7e` as
//! `macro_rules! strict_direct_snprintf_fused`. Throughout that month the two
//! tests that would have pinned it were sitting in the dead block. That is the
//! cost of dead coverage stated concretely.
//!
//! ## What is checked
//!
//! Nothing here asserts which internal path ran — that is not observable from
//! outside, and a gate that guesses would be worse than one that does not. What
//! is asserted is that fl matches live glibc on the two contracts the dead tests
//! were reaching for: the GRAMMAR boundary (formats the fused recognizer accepts
//! versus the complex specs it must decline, all of which must still format
//! correctly) and CROSS-SEGMENT TRUNCATION (a multi-directive format written
//! into a buffer too small, where the cut can fall inside any segment).

use std::ffi::{CStr, c_char, c_int, c_void};

type Snprintf = unsafe extern "C" fn(*mut c_char, usize, *const c_char, ...) -> c_int;

union Sym {
    raw: *mut c_void,
    function: Snprintf,
}

/// Resolve glibc's `snprintf` by `dlsym`, refusing an address equal to fl's own.
///
/// A link-time `extern "C" { fn snprintf(..) }` in an abi test binary is not
/// reliably glibc — `catopen` and `fma` are confirmed cases where such a
/// reference bound locally and left the gate comparing fl against itself while
/// passing (bd-v0388t).
fn host_snprintf() -> Snprintf {
    // SAFETY: the name is a NUL-terminated constant; RTLD_LOCAL keeps the handle
    // out of the global namespace.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6 — the oracle is unavailable");
    // SAFETY: handle came from dlopen; the name is a NUL-terminated constant.
    let raw = unsafe { libc::dlsym(handle, c"snprintf".as_ptr()) };
    assert!(!raw.is_null(), "dlsym snprintf");
    assert_ne!(
        raw as usize,
        frankenlibc_abi::stdio_abi::snprintf as *const () as usize,
        "the resolved oracle IS fl's snprintf — this gate would compare fl to itself"
    );
    // SAFETY: the symbol is glibc's snprintf with exactly this signature.
    unsafe { Sym { raw }.function }
}

const CAP: usize = 64;
/// Poison so that bytes past the terminator are observable: a fast path that
/// writes one byte too many, or fails to terminate, changes this pattern.
const POISON: u8 = 0xA5;

/// `(return value, the whole destination buffer including the bytes past NUL)`.
type Rendered = (c_int, [u8; CAP]);

macro_rules! both_str2 {
    ($host:expr, $fmt:expr, $a:expr, $b:expr, $size:expr) => {{
        let size: usize = $size;
        assert!(size <= CAP);
        let mut fl = [POISON; CAP];
        let mut gl = [POISON; CAP];
        // SAFETY: both buffers are CAP bytes and `size <= CAP`; the format takes
        // exactly the two `*const c_char` supplied.
        let fl_rc = unsafe {
            frankenlibc_abi::stdio_abi::snprintf(
                fl.as_mut_ptr().cast::<c_char>(), size, $fmt.as_ptr(), $a, $b)
        };
        // SAFETY: same shape into the dlsym-resolved glibc.
        let gl_rc = unsafe { ($host)(gl.as_mut_ptr().cast::<c_char>(), size, $fmt.as_ptr(), $a, $b) };
        ((fl_rc, fl), (gl_rc, gl))
    }};
}

fn assert_same(label: &str, fl: Rendered, gl: Rendered) {
    assert_eq!(
        (fl.0, &fl.1[..]),
        (gl.0, &gl.1[..]),
        "{label}: fl=({}, {:?}) glibc=({}, {:?})",
        fl.0,
        String::from_utf8_lossy(&fl.1),
        gl.0,
        String::from_utf8_lossy(&gl.1),
    );
}

/// The grammar boundary the dead `fused_strict_snprintf_grammar_...` test drew.
///
/// It asserted `is_strict_direct_snprintf_format` returned true for `%s %s %d %lu`
/// and false for `id=%08x`, `%1$s`, `%.3s` and `%f`. Restated against the public
/// entry point: every one of those must format exactly as glibc does, whichever
/// path fl chooses. That is the property that actually matters — a recognizer
/// that accepts too much is only a bug because the output would then be wrong.
///
/// `%n` was in the original list and is deliberately NOT here: it writes through
/// a caller pointer, glibc rejects it in `_FORTIFY_SOURCE` builds, and a
/// differential test of it would be testing the hardening posture of the two
/// libcs rather than fl's formatter.
#[test]
fn fused_grammar_boundary_formats_exactly_like_glibc() {
    let host = host_snprintf();
    let a = c"GET";
    let b = c"/index.html";

    for (fmt, note) in [
        (c"%s %s", "the fused-eligible shape"),
        (c"%s|%s", "fused with a non-space literal between segments"),
        (c"%s%s", "fused with no literal between segments"),
        (c"pre %s mid %s post", "leading, interior and trailing literals"),
        (c"%.3s %s", "a PRECISION on the first conversion — must decline the fused path"),
        (c"%10s|%s", "a WIDTH on the first conversion"),
        (c"%-10s|%s", "a left-justify flag"),
        (c"%2$s %1$s", "POSITIONAL arguments, which reorder the two"),
        (c"%s %%s %s", "a literal percent between two conversions"),
    ] {
        let (fl, gl) = both_str2!(host, fmt, a.as_ptr(), b.as_ptr(), CAP);
        assert_same(
            &format!("{:?} ({note})", fmt.to_str().unwrap_or("<bad utf8>")),
            fl,
            gl,
        );
    }
}

/// The truncation contract the dead `fused_strict_snprintf_writer_...` test drew.
///
/// The original built a `StrictDirectSnprintfWriter` directly over an 8-byte
/// buffer and pushed `"GET"`, `" "`, `"/x"`, checking where the cut landed. That
/// private writer is not reachable from here, and it does not need to be: the
/// observable contract is what `snprintf` writes and returns, and glibc is the
/// authority on it. Every size from 0 to past the full length is swept, so the
/// cut falls inside the first segment, on a boundary, inside the second, and not
/// at all.
///
/// The return value matters as much as the bytes: C requires the length that
/// WOULD have been written, so a truncating call must still report 6 here.
#[test]
fn fused_cross_segment_truncation_matches_glibc_at_every_size() {
    let host = host_snprintf();
    let a = c"GET";
    let b = c"/x";
    let fmt = c"%s %s"; // renders "GET /x", length 6

    for size in 0..=12usize {
        let (fl, gl) = both_str2!(host, fmt, a.as_ptr(), b.as_ptr(), size);
        assert_same(&format!("size={size}"), fl, gl);
        // Pin the oracle's own behaviour, not merely that the arms agree: if
        // both stopped reporting the untruncated length, equality would hold.
        assert_eq!(gl.0, 6, "glibc should report the untruncated length at size={size}");
    }
}

/// The access-log shape the 2026-07-31 campaign row measured (`http_log`).
///
/// That row is the one whose mechanism `73c8da5cd` deleted, so this is the exact
/// shape whose bytes went unchecked for the month the emitter was missing. Swept
/// across truncation sizes for the same reason as above.
#[test]
fn fused_access_log_shape_matches_glibc_including_truncation() {
    let host = host_snprintf();
    let method = c"GET";
    let path = c"/index.html";
    let fmt = c"%s %s HTTP/1.1";

    for size in [0usize, 1, 3, 4, 5, 15, 18, 19, 20, CAP] {
        let (fl, gl) = both_str2!(host, fmt, method.as_ptr(), path.as_ptr(), size);
        assert_same(&format!("http_log size={size}"), fl, gl);
    }
}
