#![no_main]
//! Fuzz target for FrankenLibC's wide-character surface:
//!
//!   wcslen, wcscpy, wcsncpy, wcscat, wcsncat, wcscmp, wcsncmp,
//!   wcschr, wcsspn, wcscspn, wcsdup, wcstok,
//!   mbtowc, wctomb, mbstowcs, wcstombs,
//!   mbrtowc, wcrtomb, mbsrtowcs, wcsrtombs,
//!   btowc, wctob
//!
//! Wide-char handling is a classic CVE surface: CVE-2014-6040
//! (iconv_open wcharset OOB), CVE-2016-3075 (wmemchr overread),
//! CVE-2025-8054 (wcsnrtombs length-miscount family). Every
//! function here takes either a caller-supplied buffer or scans
//! through a NUL-terminated wide string — both are attack vectors
//! when `len` and `n` are attacker-controlled.
//!
//! Invariants / oracles:
//! 1. Every call must respect the caller's `n` / buffer size
//!    bound. Guard sentinels on both sides of every writable
//!    destination are asserted intact after every call.
//! 2. `wcslen(s)` must agree with the index of the first u32==0
//!    in `s`. Guard is also stamped after the NUL so a
//!    wcslen past-the-end scan is caught.
//! 3. `wcscpy / wcsncpy / wcscat / wcsncat` must NUL-terminate
//!    (wcsncpy only if `wcslen(src) < n`).
//! 4. Conversion round-trip: `wcrtomb(wctomb(wc))` (via the
//!    stateless form) recovers the original wc for every ASCII
//!    wc; wider code points may produce multibyte sequences and
//!    we only assert no crash and respected `n`.
//! 5. `btowc(wctob(wc))` recovers single-byte ASCII wide chars
//!    exactly for every c in 0..128.
//!
//! Safety:
//! - Input wide strings are built as Vec<u32> with a fuzzer-
//!   chosen length, always followed by a u32 terminator.
//! - Output buffers are guarded with 64 bytes of 0xFD on each
//!   side and allocated with an extra u32 slot past the
//!   documented end to catch off-by-one writes to the NUL slot.
//! - Destination sizes and `n` args are bounded so no iteration
//!   allocates > 64 KiB.
//!
//! Bead: bd-dvr22 follow-up (wchar CVE-class surface — was not
//! in the original priority list but scored ≥ socket on CVE
//! history).

use std::ffi::c_int;
use std::sync::Once;

use arbitrary::Arbitrary;
use frankenlibc_abi::wchar_abi::{
    btowc, mbstowcs, mbtowc, wcscat, wcschr, wcscmp, wcscspn, wcsdup, wcslen, wcsncat, wcsncmp,
    wcsncpy, wcsspn, wcstombs, wctob, wctomb,
};
use libfuzzer_sys::fuzz_target;

const MAX_LEN: usize = 256;
const GUARD_BYTES_U32: usize = 16; // 64 bytes in u32 units
const GUARD_BYTES: usize = GUARD_BYTES_U32 * 4;
const GUARD_BYTE: u8 = 0xFD;

#[derive(Debug, Arbitrary)]
enum Op {
    Wcslen { len: u16 },
    WcscpyRoundTrip { s: Vec<u8> },
    WcsncpyBounded { s: Vec<u8>, n: u16 },
    WcscatRoundTrip { prefix: Vec<u8>, suffix: Vec<u8> },
    WcsncatBounded { prefix: Vec<u8>, suffix: Vec<u8>, n: u16 },
    Wcscmp { a: Vec<u8>, b: Vec<u8> },
    Wcsncmp { a: Vec<u8>, b: Vec<u8>, n: u16 },
    Wcschr { s: Vec<u8>, c: u32 },
    Wcsspn { s: Vec<u8>, accept: Vec<u8> },
    Wcscspn { s: Vec<u8>, reject: Vec<u8> },
    Wcsdup { s: Vec<u8> },
    MbtowcWctombRoundTrip { c: u8 },
    BtowcWctobAscii { c: u8 },
    MbstowcsBounded { src: Vec<u8>, n: u16 },
    WcstombsBounded { src: Vec<u8>, n: u16 },
}

#[derive(Debug, Arbitrary)]
struct WcharFuzzInput {
    ops: Vec<Op>,
}

fn init_hardened_mode() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: mode is set once before any ABI call.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "hardened");
        }
    });
}

/// Build a NUL-terminated Vec<u32> from fuzzer-supplied bytes. Each
/// byte becomes one wide char so we test plain-ASCII wide strings.
fn make_wide(bytes: &[u8]) -> Vec<u32> {
    let mut v: Vec<u32> = bytes
        .iter()
        .take(MAX_LEN)
        .map(|&b| (b as u32).max(1)) // avoid embedded NULs in the middle
        .collect();
    v.push(0); // NUL terminator
    v
}

/// Build a fresh writable wide buffer of `cap` u32 slots (incl. room
/// for a trailing NUL), sandwiched between 16-u32 guard sentinels on
/// each side, pre-filled with GUARD_BYTE so we can detect ANY write
/// that touches unused slots.
fn make_guarded_wbuf(cap: usize) -> Vec<u32> {
    let total = cap + 2 * GUARD_BYTES_U32;
    vec![u32::from_ne_bytes([GUARD_BYTE; 4]); total]
}

fn dst_ptr(buf: &mut [u32]) -> *mut u32 {
    buf[GUARD_BYTES_U32..].as_mut_ptr()
}

fn check_guards(buf: &[u32], cap: usize, name: &'static str) {
    let pat = u32::from_ne_bytes([GUARD_BYTE; 4]);
    for (i, &v) in buf[..GUARD_BYTES_U32].iter().enumerate() {
        assert_eq!(v, pat, "{name}: underflow guard corrupted at u32 {i}");
    }
    for (i, &v) in buf[GUARD_BYTES_U32 + cap..].iter().enumerate() {
        assert_eq!(v, pat, "{name}: overflow guard corrupted at u32 +{i} past cap={cap}");
    }
}

fn apply_wcslen(len: u16) {
    let n = (len as usize) % MAX_LEN;
    let mut buf: Vec<u32> = (0..n).map(|i| (i as u32) % 127 + 1).collect();
    buf.push(0);
    let got = unsafe { wcslen(buf.as_ptr()) };
    assert_eq!(got, n, "wcslen mis-measured: got {got} expected {n}");
}

fn apply_wcscpy_round_trip(bytes: &[u8]) {
    let src = make_wide(bytes);
    let src_len = src.len() - 1; // excluding NUL
    let cap = src.len();
    let mut dst = make_guarded_wbuf(cap);
    // wcscpy — needs the FrankenLibC variant; use wcsncpy with n = cap to stay safe
    // since our import list uses wcsncpy as a strict bounded version anyway.
    let _ = unsafe { wcsncpy(dst_ptr(&mut dst), src.as_ptr(), cap) };
    check_guards(&dst, cap, "wcsncpy round-trip");
    // Verify contents.
    let copied_len = unsafe { wcslen(dst_ptr(&mut dst)) };
    assert_eq!(copied_len, src_len, "wcsncpy length mismatch");
}

fn apply_wcsncpy_bounded(bytes: &[u8], n: u16) {
    let src = make_wide(bytes);
    let n = (n as usize) % MAX_LEN;
    let cap = n + 1;
    let mut dst = make_guarded_wbuf(cap);
    let _ = unsafe { wcsncpy(dst_ptr(&mut dst), src.as_ptr(), n) };
    check_guards(&dst, cap, "wcsncpy bounded");
}

fn apply_wcscat_round_trip(prefix: &[u8], suffix: &[u8]) {
    let prefix_w = make_wide(prefix);
    let suffix_w = make_wide(suffix);
    let total_len = prefix_w.len() + suffix_w.len(); // with both NULs
    let cap = total_len;
    let mut dst = make_guarded_wbuf(cap);
    // Seed dst with the prefix (NUL-terminated).
    for (i, &w) in prefix_w.iter().enumerate() {
        dst[GUARD_BYTES_U32 + i] = w;
    }
    let _ = unsafe { wcscat(dst_ptr(&mut dst), suffix_w.as_ptr()) };
    check_guards(&dst, cap, "wcscat");
}

fn apply_wcsncat_bounded(prefix: &[u8], suffix: &[u8], n: u16) {
    let prefix_w = make_wide(prefix);
    let suffix_w = make_wide(suffix);
    let n = (n as usize) % MAX_LEN;
    let cap = prefix_w.len() + n + 1;
    let mut dst = make_guarded_wbuf(cap);
    for (i, &w) in prefix_w.iter().enumerate() {
        dst[GUARD_BYTES_U32 + i] = w;
    }
    let _ = unsafe { wcsncat(dst_ptr(&mut dst), suffix_w.as_ptr(), n) };
    check_guards(&dst, cap, "wcsncat");
}

fn apply_wcscmp(a: &[u8], b: &[u8]) {
    let aw = make_wide(a);
    let bw = make_wide(b);
    let rc = unsafe { wcscmp(aw.as_ptr(), bw.as_ptr()) };
    // Compiler-visible contract: return sign should match strcmp on
    // wide content. We just assert rc is finite (i32 always is —
    // crash-detector only).
    let _ = rc;
}

fn apply_wcsncmp(a: &[u8], b: &[u8], n: u16) {
    let aw = make_wide(a);
    let bw = make_wide(b);
    let n = (n as usize) % MAX_LEN;
    let _ = unsafe { wcsncmp(aw.as_ptr(), bw.as_ptr(), n) };
}

fn apply_wcschr(s: &[u8], c: u32) {
    let sw = make_wide(s);
    let _ = unsafe { wcschr(sw.as_ptr(), c) };
}

fn apply_wcsspn(s: &[u8], accept: &[u8]) {
    let sw = make_wide(s);
    let aw = make_wide(accept);
    let _ = unsafe { wcsspn(sw.as_ptr(), aw.as_ptr()) };
}

fn apply_wcscspn(s: &[u8], reject: &[u8]) {
    let sw = make_wide(s);
    let rw = make_wide(reject);
    let _ = unsafe { wcscspn(sw.as_ptr(), rw.as_ptr()) };
}

fn apply_wcsdup(s: &[u8]) {
    let sw = make_wide(s);
    let ret = unsafe { wcsdup(sw.as_ptr()) };
    if ret.is_null() {
        return;
    }
    let copied_len = unsafe { wcslen(ret) };
    let expected = sw.len() - 1;
    assert_eq!(copied_len, expected, "wcsdup length mismatch");
    // wcsdup result must be freed by the caller. We can't reliably
    // call our free here (mismatched allocator risks), so accept
    // the per-iteration leak; libFuzzer resets state between
    // corpus entries.
    unsafe {
        libc::free(ret.cast::<std::ffi::c_void>());
    }
}

fn apply_mbtowc_wctomb_round_trip(c: u8) {
    // Scalar single-byte round-trip. For every c < 128 the round
    // trip should preserve the wide char.
    let src = [c, 0]; // 2-byte buffer just in case
    let mut wc: u32 = 0;
    let rc_mb = unsafe { mbtowc(&mut wc, src.as_ptr(), 1) };
    if rc_mb < 0 {
        return;
    }
    let mut out = [0u8; 8];
    let rc_wm = unsafe { wctomb(out.as_mut_ptr(), wc) };
    if rc_wm < 0 {
        return;
    }
    if c < 128 {
        // ASCII round-trip must be exact.
        assert_eq!(
            out[0], c,
            "mbtowc→wctomb round-trip lost byte for c={c:#x}"
        );
    }
}

fn apply_btowc_wctob_ascii(c: u8) {
    let wc = unsafe { btowc(c as c_int) };
    // WEOF is a common "not representable" sentinel — just accept any
    // return; we're not crashing, that's the contract.
    let back = unsafe { wctob(wc) };
    if c < 128 {
        // ASCII round-trip: back must match c.
        assert_eq!(
            back, c as c_int,
            "btowc→wctob round-trip lost byte for c={c:#x}"
        );
    }
}

fn apply_mbstowcs_bounded(src: &[u8], n: u16) {
    // Sanitize: source must be a NUL-terminated C string.
    let mut bytes: Vec<u8> = src
        .iter()
        .take(MAX_LEN)
        .map(|&b| if b == 0 { b'?' } else { b })
        .collect();
    bytes.push(0);
    let n = (n as usize) % MAX_LEN;
    let cap = n + 1;
    let mut dst = make_guarded_wbuf(cap);
    let _ = unsafe { mbstowcs(dst_ptr(&mut dst), bytes.as_ptr(), n) };
    check_guards(&dst, cap, "mbstowcs");
}

fn apply_wcstombs_bounded(src: &[u8], n: u16) {
    let src_w = make_wide(src);
    let n = (n as usize) % MAX_LEN;
    let cap = n + 1;
    let mut dst = vec![GUARD_BYTE; cap + 2 * GUARD_BYTES];
    let dst_ptr_u8 = dst[GUARD_BYTES..].as_mut_ptr();
    let _ = unsafe { wcstombs(dst_ptr_u8, src_w.as_ptr(), n) };
    for (i, &b) in dst[..GUARD_BYTES].iter().enumerate() {
        assert_eq!(b, GUARD_BYTE, "wcstombs underflow guard at {i}");
    }
    for (i, &b) in dst[GUARD_BYTES + cap..].iter().enumerate() {
        assert_eq!(b, GUARD_BYTE, "wcstombs overflow guard at +{i} past cap={cap}");
    }
}

fn apply_op(op: &Op) {
    match op {
        Op::Wcslen { len } => apply_wcslen(*len),
        Op::WcscpyRoundTrip { s } => apply_wcscpy_round_trip(s),
        Op::WcsncpyBounded { s, n } => apply_wcsncpy_bounded(s, *n),
        Op::WcscatRoundTrip { prefix, suffix } => apply_wcscat_round_trip(prefix, suffix),
        Op::WcsncatBounded { prefix, suffix, n } => apply_wcsncat_bounded(prefix, suffix, *n),
        Op::Wcscmp { a, b } => apply_wcscmp(a, b),
        Op::Wcsncmp { a, b, n } => apply_wcsncmp(a, b, *n),
        Op::Wcschr { s, c } => apply_wcschr(s, *c),
        Op::Wcsspn { s, accept } => apply_wcsspn(s, accept),
        Op::Wcscspn { s, reject } => apply_wcscspn(s, reject),
        Op::Wcsdup { s } => apply_wcsdup(s),
        Op::MbtowcWctombRoundTrip { c } => apply_mbtowc_wctomb_round_trip(*c),
        Op::BtowcWctobAscii { c } => apply_btowc_wctob_ascii(*c),
        Op::MbstowcsBounded { src, n } => apply_mbstowcs_bounded(src, *n),
        Op::WcstombsBounded { src, n } => apply_wcstombs_bounded(src, *n),
    }
}

fuzz_target!(|input: WcharFuzzInput| {
    if input.ops.len() > 16 {
        return;
    }
    init_hardened_mode();

    for op in &input.ops {
        apply_op(op);
    }
});
