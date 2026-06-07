#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc iconv oracle (lives in libc.so, linked by std)

//! Randomized differential fuzzer for `iconv(3)`: FrankenLibC vs host glibc.
//!
//! The fixed-case `conformance_diff_iconv.rs` only exercises ASCII / ISO-8859-1
//! / UTF-8 and compares *only* the output bytes + open-success. This fuzzer goes
//! much wider — many single-byte codepages (ISO-8859-*, CP125x, CP437/850/866,
//! KOI8-R) ↔ UTF-8, over deterministic random byte corpora — and compares the
//! FULL observable iconv contract:
//!   - the return value (clean vs `(size_t)-1` error, and the non-reversible
//!     count on success),
//!   - `errno` on error (EILSEQ vs EINVAL — invalid sequence vs incomplete tail),
//!   - the exact output bytes written, AND
//!   - `*inbytesleft` after the call (i.e. *where* conversion stopped).
//!
//! Those last three are precisely where iconv parity bugs hide: codepage holes
//! (undefined byte positions glibc rejects with EILSEQ), the UTF-8 decoder's
//! incomplete-vs-invalid distinction, and the post-error input position. fl
//! mirrors errno to the host slot in interpose mode, so the host
//! `__errno_location` reflects both implementations.

use std::ffi::{CString, c_char, c_void};

use frankenlibc_abi::iconv_abi as fl;

unsafe extern "C" {
    fn iconv_open(tocode: *const c_char, fromcode: *const c_char) -> *mut c_void;
    fn iconv_close(cd: *mut c_void) -> std::ffi::c_int;
    fn iconv(
        cd: *mut c_void,
        inbuf: *mut *mut c_char,
        inbytesleft: *mut usize,
        outbuf: *mut *mut c_char,
        outbytesleft: *mut usize,
    ) -> usize;
}

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}
fn clear_errno() {
    unsafe { *libc::__errno_location() = 0 };
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct Out {
    /// `iconv` returned `(size_t)-1`.
    err: bool,
    /// errno (meaningful only when `err`).
    eno: i32,
    /// Non-reversible conversion count (meaningful only when `!err`).
    nonrev: usize,
    /// Bytes written to the output buffer.
    out: Vec<u8>,
    /// `*inbytesleft` remaining after the call (where conversion stopped).
    in_left: usize,
}

type OpenFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type CloseFn = unsafe extern "C" fn(*mut c_void) -> std::ffi::c_int;
type ConvFn =
    unsafe extern "C" fn(*mut c_void, *mut *mut c_char, *mut usize, *mut *mut c_char, *mut usize) -> usize;

/// `None` means iconv_open failed (codec unsupported by this implementation).
unsafe fn run(
    open_fn: OpenFn,
    close_fn: CloseFn,
    conv_fn: ConvFn,
    to: &CString,
    from: &CString,
    src: &[u8],
) -> Option<Out> {
    let cd = unsafe { open_fn(to.as_ptr(), from.as_ptr()) };
    if cd as isize == -1 || cd.is_null() {
        return None;
    }
    let mut src_buf = src.to_vec();
    // Generous output buffer so E2BIG never fires — this fuzzer targets the
    // EILSEQ/EINVAL/clean + return-value + position contract, not flushing.
    let mut dst_buf = vec![0u8; src.len() * 8 + 64];
    let mut sp: *mut c_char = src_buf.as_mut_ptr() as *mut c_char;
    let mut dp: *mut c_char = dst_buf.as_mut_ptr() as *mut c_char;
    let mut sl: usize = src_buf.len();
    let mut dl: usize = dst_buf.len();
    clear_errno();
    let r = unsafe { conv_fn(cd, &mut sp, &mut sl, &mut dp, &mut dl) };
    let eno = errno();
    let written = dst_buf.len() - dl;
    let _ = unsafe { close_fn(cd) };
    let err = r == usize::MAX;
    Some(Out {
        err,
        eno: if err { eno } else { 0 },
        nonrev: if err { 0 } else { r },
        out: dst_buf[..written].to_vec(),
        in_left: sl,
    })
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 33) as u8
    }
}

/// Single-byte codepages (each round-tripped against UTF-8 both directions),
/// plus a couple of UTF families. Only pairs where BOTH fl and host open
/// succeed are compared, so an unsupported alias is silently skipped.
const CODECS: &[&str] = &[
    "ISO-8859-1",
    "ISO-8859-2",
    "ISO-8859-5",
    "ISO-8859-7",
    "ISO-8859-9",
    "ISO-8859-15",
    "CP1251",
    "CP1252",
    "CP1253",
    "KOI8-R",
    "CP437",
    "CP850",
    "CP866",
    "ASCII",
];

#[test]
fn iconv_differential_fuzz_vs_glibc() {
    let utf8 = CString::new("UTF-8").unwrap();
    let mut r = Lcg(0xa1b2_c3d4_e5f6_0718);

    let mut divs: Vec<String> = Vec::new();
    let mut open_gaps: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for codec in CODECS {
        let cp = CString::new(*codec).unwrap();

        // Sanity: do both implementations even open this codec (both directions)?
        // Record (don't fail) when glibc opens a codec fl doesn't — a coverage gap.
        for (to, from, label) in [(&cp, &utf8, "utf8->cp"), (&utf8, &cp, "cp->utf8")] {
            let fl_ok = {
                let cd = unsafe { fl::iconv_open(to.as_ptr(), from.as_ptr()) };
                let ok = !(cd as isize == -1 || cd.is_null());
                if ok {
                    unsafe { fl::iconv_close(cd) };
                }
                ok
            };
            let host_ok = {
                let cd = unsafe { iconv_open(to.as_ptr(), from.as_ptr()) };
                let ok = !(cd as isize == -1 || cd.is_null());
                if ok {
                    unsafe { iconv_close(cd) };
                }
                ok
            };
            if fl_ok != host_ok {
                open_gaps.push(format!("{codec} {label}: fl_open={fl_ok} host_open={host_ok}"));
            }
        }

        // Random byte corpora in BOTH directions.
        for _ in 0..1500 {
            let len = (r.next() % 13) as usize;
            let src: Vec<u8> = (0..len).map(|_| r.byte()).collect();

            for (to, from) in [(&cp, &utf8), (&utf8, &cp)] {
                let fl_out = unsafe { run(fl::iconv_open, fl::iconv_close, fl::iconv, to, from, &src) };
                let host_out = unsafe { run(iconv_open, iconv_close, iconv, to, from, &src) };
                let (Some(f), Some(h)) = (fl_out, host_out) else {
                    continue; // codec unsupported by one side — skip
                };
                compared += 1;
                if f != h {
                    let dir = if to.as_bytes() == utf8.as_bytes() {
                        format!("{codec}->UTF-8")
                    } else {
                        format!("UTF-8->{codec}")
                    };
                    if divs.len() < 40 {
                        divs.push(format!(
                            "{dir} src={src:02x?}\n      fl  ={f:02x?}\n      glibc={h:02x?}"
                        ));
                    }
                }
            }
        }
    }

    if !open_gaps.is_empty() {
        eprintln!(
            "iconv open-gaps (fl vs glibc codec availability, non-fatal): {}\n{}",
            open_gaps.len(),
            open_gaps.join("\n")
        );
    }
    assert!(
        divs.is_empty(),
        "iconv diverged from host glibc on conversion contract (showing up to 40):\n{}",
        divs.join("\n")
    );
    eprintln!("iconv differential fuzz: {compared} conversions, 0 divergences vs host glibc");
}

/// The unmarked `UTF-16`/`UTF-32` codecs must consume/honor a leading BOM
/// exactly like glibc: an LE BOM => LE, a BE BOM => BE, no BOM => the native LE
/// default; the BOM itself is stripped from the decoded output, and on encode it
/// is emitted (LE) only alongside real output.
#[test]
fn iconv_unmarked_bom_vs_glibc() {
    let utf8 = CString::new("UTF-8").unwrap();
    let mut divs: Vec<String> = Vec::new();
    let mut checked = 0u32;

    // (codec, decode cases). Astral char U+1F600 exercises surrogate pairs (16)
    // / a >BMP scalar (32).
    let utf32: &[(&str, &[u8])] = &[
        ("no-BOM", &[0x00, 0x00, 0x00, 0x41]),
        ("LE-BOM", &[0xFF, 0xFE, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00]),
        ("BE-BOM", &[0x00, 0x00, 0xFE, 0xFF, 0x00, 0x00, 0x00, 0x41]),
        ("LE-BOM only", &[0xFF, 0xFE, 0x00, 0x00]),
        ("BE-BOM only", &[0x00, 0x00, 0xFE, 0xFF]),
        ("LE-BOM + astral", &[0xFF, 0xFE, 0x00, 0x00, 0x00, 0xF6, 0x01, 0x00]),
        ("BE-BOM + astral", &[0x00, 0x00, 0xFE, 0xFF, 0x00, 0x01, 0xF6, 0x00]),
    ];
    let utf16: &[(&str, &[u8])] = &[
        ("no-BOM", &[0x00, 0x41]),
        ("LE-BOM", &[0xFF, 0xFE, 0x41, 0x00]),
        ("BE-BOM", &[0xFE, 0xFF, 0x00, 0x41]),
        ("LE-BOM only", &[0xFF, 0xFE]),
        ("BE-BOM only", &[0xFE, 0xFF]),
        ("LE-BOM + astral", &[0xFF, 0xFE, 0x3D, 0xD8, 0x00, 0xDE]),
        ("BE-BOM + astral", &[0xFE, 0xFF, 0xD8, 0x3D, 0xDE, 0x00]),
    ];

    for (codec, cases) in [("UTF-32", utf32), ("UTF-16", utf16)] {
        let w = CString::new(codec).unwrap();
        for (label, src) in cases {
            let f = unsafe { run(fl::iconv_open, fl::iconv_close, fl::iconv, &utf8, &w, src) };
            let h = unsafe { run(iconv_open, iconv_close, iconv, &utf8, &w, src) };
            let (Some(f), Some(h)) = (f, h) else { continue };
            checked += 1;
            if f != h {
                divs.push(format!("{codec}->UTF-8 [{label}] src={src:02x?}\n    fl   ={f:02x?}\n    glibc={h:02x?}"));
            }
        }
    }
    assert!(
        divs.is_empty(),
        "unmarked UTF-16/UTF-32 BOM handling diverged from glibc:\n{}",
        divs.join("\n")
    );
    eprintln!("iconv unmarked BOM: {checked} cases, 0 divergences vs host glibc");
}

/// Append the UTF-8 encoding of `cp` (assumed a valid scalar value) to `v`.
fn push_utf8(v: &mut Vec<u8>, cp: u32) {
    if let Some(c) = char::from_u32(cp) {
        let mut buf = [0u8; 4];
        v.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
}

/// Wide-codec differential fuzz: UTF-16LE/BE and UTF-32LE/BE <-> UTF-8 over
/// (a) random raw bytes (even AND odd lengths — exercises the incomplete-tail
/// EINVAL boundary and surrogate/range EILSEQ classification + stop position)
/// and (b) valid UTF-8 built from random scalar values incl. astral planes
/// (exercises surrogate-pair encoding on the UTF-8->UTF-16 side). The explicit
/// endianness codecs have no BOM ambiguity, so fl and glibc must agree on the
/// full contract (return value + errno + output bytes + *inbytesleft).
#[test]
fn iconv_wide_differential_fuzz_vs_glibc() {
    let utf8 = CString::new("UTF-8").unwrap();
    let mut r = Lcg(0x5151_2727_9393_0f0f);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    const WIDE: &[&str] = &["UTF-16LE", "UTF-16BE", "UTF-32LE", "UTF-32BE", "UTF-32", "UTF-16"];

    for codec in WIDE {
        let w = CString::new(*codec).unwrap();
        for _ in 0..2000 {
            // Two corpora: raw bytes (any length) and valid UTF-8.
            let raw: Vec<u8> = {
                let len = (r.next() % 14) as usize;
                (0..len).map(|_| r.byte()).collect()
            };
            let valid_utf8: Vec<u8> = {
                let n = (r.next() % 4) as usize;
                let mut v = Vec::new();
                for _ in 0..n {
                    // Bias toward BMP, but reach astral + surrogate-gap edges.
                    let pick = r.next() % 8;
                    let cp = match pick {
                        0 => r.next() as u32 % 0x80,            // ASCII
                        1 | 2 => r.next() as u32 % 0x800,       // 2-byte
                        3 | 4 => r.next() as u32 % 0x10000,     // 3-byte (may be surrogate -> skipped)
                        _ => 0x10000 + (r.next() as u32 % 0x100000), // astral (surrogate pair in UTF-16)
                    };
                    push_utf8(&mut v, cp);
                }
                v
            };

            for src in [&raw, &valid_utf8] {
                for (to, from, dir) in [
                    (&w, &utf8, format!("UTF-8->{codec}")),
                    (&utf8, &w, format!("{codec}->UTF-8")),
                ] {
                    let f = unsafe { run(fl::iconv_open, fl::iconv_close, fl::iconv, to, from, src) };
                    let h = unsafe { run(iconv_open, iconv_close, iconv, to, from, src) };
                    let (Some(f), Some(h)) = (f, h) else { continue };
                    compared += 1;
                    if f != h && divs.len() < 40 {
                        divs.push(format!(
                            "{dir} src={src:02x?}\n      fl  ={f:02x?}\n      glibc={h:02x?}"
                        ));
                    }
                }
            }
        }
    }

    assert!(
        divs.is_empty(),
        "wide iconv diverged from host glibc on conversion contract (showing up to 40):\n{}",
        divs.join("\n")
    );
    eprintln!("iconv wide differential fuzz: {compared} conversions, 0 divergences vs host glibc");
}

/// CJK 2-byte codec differential fuzz: SHIFT_JIS and BIG5 <-> UTF-8 over (a)
/// random raw bytes (exercises the decode tables + the incomplete-tail EINVAL /
/// invalid-pair EILSEQ classification + stop position) and (b) valid UTF-8
/// biased toward CJK / fullwidth ranges (exercises the encode tables, incl.
/// unrepresentable -> EILSEQ). Now that fl drives these codecs from glibc-derived
/// tables (bd-2g7oyh.195), the full contract — return value + errno + output
/// bytes + *inbytesleft — must match host glibc.
#[test]
fn iconv_cjk_differential_fuzz_vs_glibc() {
    let utf8 = CString::new("UTF-8").unwrap();
    let mut r = Lcg(0xa5f0_0d12_3490_9bce);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    const CJK: &[&str] = &["SHIFT_JIS", "BIG5", "EUC-JP", "GBK", "EUC-KR", "CP949", "GB2312"];

    for codec in CJK {
        let c = CString::new(*codec).unwrap();
        for _ in 0..6000 {
            let raw: Vec<u8> = {
                let len = (r.next() % 6) as usize;
                (0..len).map(|_| r.byte()).collect()
            };
            let valid_utf8: Vec<u8> = {
                let n = (r.next() % 4) as usize;
                let mut v = Vec::new();
                for _ in 0..n {
                    let cp = match r.next() % 8 {
                        0 => r.next() as u32 % 0x80,                  // ASCII
                        1 => 0xFF61 + (r.next() as u32 % 0x3F),       // half-width kana
                        2 | 3 => 0x3000 + (r.next() as u32 % 0x100),  // CJK symbols/kana
                        _ => 0x4E00 + (r.next() as u32 % 0x5200),     // CJK unified ideographs
                    };
                    push_utf8(&mut v, cp);
                }
                v
            };
            for src in [&raw, &valid_utf8] {
                for (to, from, dir) in [
                    (&c, &utf8, format!("UTF-8->{codec}")),
                    (&utf8, &c, format!("{codec}->UTF-8")),
                ] {
                    let f = unsafe { run(fl::iconv_open, fl::iconv_close, fl::iconv, to, from, src) };
                    let h = unsafe { run(iconv_open, iconv_close, iconv, to, from, src) };
                    let (Some(f), Some(h)) = (f, h) else { continue };
                    compared += 1;
                    if f != h && divs.len() < 40 {
                        divs.push(format!(
                            "{dir} src={src:02x?}\n      fl  ={f:02x?}\n      glibc={h:02x?}"
                        ));
                    }
                }
            }
        }
    }

    assert!(
        divs.is_empty(),
        "CJK iconv diverged from host glibc (showing up to 40):\n{}",
        divs.join("\n")
    );
    eprintln!("iconv CJK differential fuzz: {compared} conversions, 0 divergences vs host glibc");
}
