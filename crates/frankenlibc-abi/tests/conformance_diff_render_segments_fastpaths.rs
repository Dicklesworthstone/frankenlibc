#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc snprintf oracle
//! Differential gate for the per-conversion fast paths inside `render_segments`
//! (bd-ntb9fq): the plain `%s` path and the bare-integer path.
//!
//! Every format here carries at least TWO conversions on purpose. A format with
//! a single conversion is captured by the `exact_direct_*` probes in `snprintf`
//! and never reaches `render_segments` at all, so a single-conversion test would
//! pass while proving nothing about the code under test — the same
//! measure-the-wrong-thing failure that let `conformance_diff_fma` run 40,000
//! comparisons against itself (bd-h95z6y).
//!
//! The fast paths claim to be byte-identical to the general path, so the
//! assertions compare the FULL destination and the return value against live
//! glibc, not merely the prefix.
//!
//! The host arm is resolved with `dlsym` rather than declared at link time: fl
//! exports its own `snprintf`, and a link-time reference can bind to it, which
//! would make both arms fl (bd-v0388t).

use std::ffi::{CString, c_char, c_int, c_void};

type SnprintfFn = unsafe extern "C" fn(*mut c_char, usize, *const c_char, ...) -> c_int;

union SnprintfSym {
    raw: *mut c_void,
    function: SnprintfFn,
}

fn host_snprintf() -> SnprintfFn {
    // SAFETY: libc.so.6 is the process host libc; flags request a local handle.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6");
    // SAFETY: the handle came from dlopen; the name is a NUL-terminated constant.
    let raw = unsafe { libc::dlsym(handle, c"snprintf".as_ptr()) };
    assert!(!raw.is_null(), "dlsym snprintf");
    assert_ne!(
        raw as usize,
        frankenlibc_abi::stdio_abi::snprintf as usize,
        "the resolved oracle IS fl's snprintf — this gate would compare fl to itself"
    );
    // SAFETY: the resolved symbol has C's documented snprintf signature.
    unsafe { SnprintfSym { raw }.function }
}

const BUF: usize = 256;
const FILL: u8 = 0xAB;

/// Compare fl against glibc for one format plus its arguments, over several
/// destination sizes including the truncating and zero cases.
macro_rules! compare {
    ($label:expr, $fmt:expr $(, $arg:expr)* $(,)?) => {{
        let host = host_snprintf();
        for size in [0usize, 1, 2, 7, 16, BUF] {
            let mut fl_buf = [FILL; BUF];
            let mut gl_buf = [FILL; BUF];
            // SAFETY: both destinations are BUF bytes; `size` never exceeds it.
            let fl_rc = unsafe {
                frankenlibc_abi::stdio_abi::snprintf(
                    fl_buf.as_mut_ptr().cast::<c_char>(), size, $fmt $(, $arg)*
                )
            };
            // SAFETY: as above, against the host.
            let gl_rc = unsafe {
                host(gl_buf.as_mut_ptr().cast::<c_char>(), size, $fmt $(, $arg)*)
            };
            assert_eq!(
                fl_rc, gl_rc,
                "{} size={size}: return value fl={fl_rc} glibc={gl_rc}", $label
            );
            assert_eq!(
                fl_buf, gl_buf,
                "{} size={size}: destination bytes differ", $label
            );
        }
    }};
}

#[test]
fn plain_string_fast_path_matches_glibc() {
    let a = CString::new("alpha").unwrap();
    let b = CString::new("").unwrap();
    let long = CString::new("a rather longer value than the destination").unwrap();

    compare!("two %s", c"%s %s".as_ptr(), a.as_ptr(), a.as_ptr());
    // Empty string: the fast path copies zero bytes, which is the case a
    // length-driven implementation is most likely to get wrong.
    compare!("empty %s", c"%s=%s".as_ptr(), b.as_ptr(), a.as_ptr());
    compare!(
        "truncating %s",
        c"%s %s".as_ptr(),
        long.as_ptr(),
        long.as_ptr()
    );
    // NULL: the general path renders "(null)" at Precision::None, and the fast
    // path must reproduce that spelling exactly rather than emitting nothing.
    compare!(
        "null %s",
        c"[%s][%s]".as_ptr(),
        std::ptr::null::<c_char>(),
        a.as_ptr()
    );
}

#[test]
fn bare_integer_fast_path_matches_glibc() {
    compare!("%d %d", c"%d %d".as_ptr(), 0i32, -1i32);
    compare!("%d bounds", c"%d/%d".as_ptr(), i32::MIN, i32::MAX);
    compare!("%u bounds", c"%u %u".as_ptr(), 0u32, u32::MAX);
    compare!(
        "%x case pair",
        c"%x %X".as_ptr(),
        0xdead_beefu32,
        0xdead_beefu32
    );
    compare!("%o", c"%o %o".as_ptr(), 0u32, 0o7777u32);
    // Length modifiers stay on the fast path because the spec is handed to the
    // same renderer; these pin that.
    compare!("%ld %lu", c"%ld %lu".as_ptr(), i64::MIN, u64::MAX);
    compare!("%zu %zd", c"%zu %zd".as_ptr(), usize::MAX, isize::MIN);
}

#[test]
fn shapes_the_fast_paths_must_decline_still_match_glibc() {
    let a = CString::new("alpha").unwrap();

    // Width, precision, and flags must all fall through to the general path.
    compare!("width", c"%8s|%-8s".as_ptr(), a.as_ptr(), a.as_ptr());
    compare!("precision", c"%.2s|%.0s".as_ptr(), a.as_ptr(), a.as_ptr());
    compare!("star width", c"%*d|%d".as_ptr(), 6i32, 42i32, 7i32);
    compare!(
        "flagged ints",
        c"%+d % d %#x %05d".as_ptr(),
        5i32,
        5i32,
        255u32,
        42i32
    );
    compare!("precision int", c"%.5d|%d".as_ptr(), 42i32, 1i32);
    // Mixed: fast-path-eligible conversions interleaved with ineligible ones, so
    // an argument-index slip between the two paths shows up as wrong VALUES
    // rather than merely wrong padding.
    compare!(
        "interleaved",
        c"%s %8s %d %+d %u".as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        7i32,
        7i32,
        7u32
    );
    // %% and %c neighbour the fast paths in the same match; pin that they are
    // unaffected.
    compare!(
        "percent and char",
        c"%d%% %c%s".as_ptr(),
        50i32,
        b'x' as c_int,
        a.as_ptr()
    );
}

// ---------------------------------------------------------------------------
// Segment-count coverage across the inline/heap boundary (bd-mh2ev3).
//
// `FormatSegments` holds `INLINE_SEGMENTS` segments inline and spills to a heap
// `Vec` past that. A format of n conversions separated by single spaces parses
// to n specs plus n-1 literals, so the segment count is 2n-1 and the boundary
// is crossed part-way up this range.
//
// Both sides of it are exercised on purpose. The POSITIVE case is that a format
// which fits inline renders correctly; the NEGATIVE case — the one that matters
// when the constant is raised — is that a format which STILL spills renders
// correctly too. Raising `INLINE_SEGMENTS` without a case past the new boundary
// would silently stop testing the spill path altogether: every existing format
// would fit, the heap `Vec` would never be constructed, and a bug in it would
// become invisible rather than fixed. The 20-conversion case below is 39
// segments, so it spills at any plausible value of the constant.

#[test]
fn segment_counts_across_the_inline_boundary_match_glibc() {
    let a = CString::new("alpha").unwrap();

    // 2n-1 segments for n conversions: 3, 9, 15, 17, 19, 21, 39.
    // 8 and 16 both fall inside this sweep, so it brackets the old constant and
    // the new one regardless of which is in force.
    compare!("n=2 (3 seg)", c"%s %s".as_ptr(), a.as_ptr(), a.as_ptr());
    compare!(
        "n=5 (9 seg)",
        c"%s %s %s %s %s".as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
    );
    compare!(
        "n=8 (15 seg)",
        c"%s %s %s %s %s %s %s %s".as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
    );
    compare!(
        "n=9 (17 seg)",
        c"%s %s %s %s %s %s %s %s %s".as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
    );
    // NEGATIVE CASE: still spills at INLINE_SEGMENTS = 16, and at 32, and at 38.
    // This is what keeps the heap path under test as the constant grows.
    compare!(
        "n=20 (39 seg) — spills at any plausible constant",
        c"%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s".as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
        a.as_ptr(),
    );
}

#[test]
fn mixed_conversions_past_the_boundary_match_glibc() {
    let a = CString::new("alpha").unwrap();
    // Interleaves both fast paths and the general path past the spill point, so
    // an argument-index slip between inline and heap storage shows up as wrong
    // VALUES rather than merely a wrong length.
    compare!(
        "mixed, 12 conversions",
        c"%s %d %s %u %s %x %s %d %8s %s %+d %s".as_ptr(),
        a.as_ptr(),
        1i32,
        a.as_ptr(),
        2u32,
        a.as_ptr(),
        0x3fu32,
        a.as_ptr(),
        -4i32,
        a.as_ptr(),
        a.as_ptr(),
        5i32,
        a.as_ptr(),
    );
}
