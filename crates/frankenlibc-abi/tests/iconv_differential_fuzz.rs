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
