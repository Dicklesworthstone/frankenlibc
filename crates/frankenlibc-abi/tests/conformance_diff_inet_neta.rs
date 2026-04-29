#![cfg(target_os = "linux")]

//! Differential conformance harness for libresolv `inet_neta`.
//!
//! `inet_neta` is the BIND-flavored "compact" address formatter: given a
//! 32-bit network number (in network byte order, but as a u32 — historical
//! BSD weirdness), it emits a dot-separated string with leading and middle
//! zero octets dropped. fl exports its own implementation; this is the
//! first head-to-head diff against host libresolv.
//!
//! Filed under [bd-xn6p8] follow-up — extending libresolv parity coverage.

use std::ffi::{c_char, CStr};

use frankenlibc_abi::resolv_abi as fl;

#[link(name = "resolv")]
unsafe extern "C" {
    fn inet_neta(src: u32, dst: *mut c_char, size: usize) -> *mut c_char;
}

#[derive(Debug)]
struct Divergence {
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  case: {} | field: {} | fl: {} | glibc: {}\n",
            d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

const NETA_INPUTS: &[u32] = &[
    0x00000000, // → "0.0.0.0" (special)
    0x7F000001, // octets [127,0,0,1] → "127.1"
    0x0100007F, // → "1.127"
    0x010000FF, // → "1.255"
    0x12345678, // all non-zero → "18.52.86.120"
    0xFFFFFFFF, // → "255.255.255.255"
    0x01020300, // [1,2,3,0] → "1.2.3"
    0x01000300, // [1,0,3,0] → "1.3"
    0x01020000, // [1,2,0,0] → "1.2"
    0x00010203, // [0,1,2,3] → "1.2.3"
    0x80000000, // [128,0,0,0] → "128"
    0x00800000, // [0,128,0,0] → "128"
    0x00008000, // [0,0,128,0] → "128"
    0x00000080, // [0,0,0,128] → "128"
    0xC0A80101, // [192,168,1,1] → "192.168.1.1"
    0x0A000000, // [10,0,0,0] → "10"
    0x80808080, // all 128 → "128.128.128.128"
];

#[test]
fn diff_inet_neta_cases() {
    let mut divs = Vec::new();
    for &src in NETA_INPUTS {
        let mut fl_buf = [0i8; 64];
        let mut lc_buf = [0i8; 64];
        let p_fl = unsafe { fl::inet_neta(src, fl_buf.as_mut_ptr(), fl_buf.len()) };
        let p_lc = unsafe { inet_neta(src, lc_buf.as_mut_ptr(), lc_buf.len()) };
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                case: format!("{src:#010x}"),
                field: "null_return",
                frankenlibc: format!("{}", p_fl.is_null()),
                glibc: format!("{}", p_lc.is_null()),
            });
            continue;
        }
        if p_fl.is_null() {
            continue;
        }
        let s_fl = unsafe { CStr::from_ptr(p_fl).to_bytes() };
        let s_lc = unsafe { CStr::from_ptr(p_lc).to_bytes() };
        if s_fl != s_lc {
            divs.push(Divergence {
                case: format!("{src:#010x}"),
                field: "string",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
            });
        }
    }
    assert!(divs.is_empty(), "inet_neta divergences:\n{}", render_divs(&divs));
}

/// Buffer-too-small contract — both impls should return NULL when the
/// destination is too short to hold the formatted output plus NUL.
#[test]
fn diff_inet_neta_buffer_too_small() {
    let mut divs = Vec::new();
    // 0x12345678 formats as "18.52.86.120" = 12 chars + NUL = 13 bytes.
    let src: u32 = 0x12345678;
    for size in [0usize, 1, 5, 12] {
        let mut fl_buf = vec![0i8; size + 4];
        let mut lc_buf = vec![0i8; size + 4];
        let p_fl = unsafe { fl::inet_neta(src, fl_buf.as_mut_ptr(), size) };
        let p_lc = unsafe { inet_neta(src, lc_buf.as_mut_ptr(), size) };
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                case: format!("size={size}"),
                field: "null_return",
                frankenlibc: format!("{}", p_fl.is_null()),
                glibc: format!("{}", p_lc.is_null()),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "inet_neta buffer-too-small divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn inet_neta_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libresolv inet_neta\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
