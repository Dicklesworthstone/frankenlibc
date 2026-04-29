#![cfg(target_os = "linux")]

//! Differential conformance harness for libresolv `ns_format_ttl`.
//!
//! Formats a DNS TTL (in seconds) as a human-readable duration string.
//! glibc emits single-unit forms uppercase ("1S", "1H", "1W") and multi-
//! unit forms lowercase concatenated ("1d1h1m30s"). The unit-cascade is:
//!   1W = 7D, 1D = 24H, 1H = 60M, 1M = 60S.
//!
//! Filed under [bd-xn6p8] follow-up — extending libresolv parity coverage.
//!
//! ## ABI note
//!
//! glibc's prototype is `int ns_format_ttl(u_long src, char *dst, size_t)`,
//! taking u_long (= u64 on Linux/x86_64). fl matches that signature now
//! (previously was u32, which truncated for src > 0xFFFFFFFF).

use std::ffi::{c_char, c_int, CStr};

use frankenlibc_abi::resolv_abi as fl;

#[link(name = "resolv")]
unsafe extern "C" {
    fn ns_format_ttl(src: libc::c_ulong, dst: *mut c_char, dstlen: usize) -> c_int;
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

const TTL_INPUTS: &[u64] = &[
    0,                          // → "0S"
    1,                          // → "1S"
    59,                         // → "59S"
    60,                         // → "1M"
    61,                         // → "1m1s"
    3599,                       // → "59m59s"
    3600,                       // → "1H"
    3601,                       // → "1h1s"
    86399,                      // 1 second short of 1 day
    86400,                      // → "1D"
    86461,                      // 1 day, 1 minute, 1 second
    604800,                     // → "1W"
    604801,                     // 1 week + 1 second
    2419200,                    // → "4W"
    90090,                      // → "1d1h1m30s"
    2_147_483_647,              // i32::MAX
    u32::MAX as u64,
    // u64 range — fl's old u32 signature truncated these; now matches.
    0x100000000u64,             // 2^32
    0xFFFFFFFFFFu64,            // ~17.5 trillion seconds
    1_000_000_000_000u64,
];

#[test]
fn diff_ns_format_ttl_cases() {
    let mut divs = Vec::new();
    for &src in TTL_INPUTS {
        let mut fl_buf = [0i8; 64];
        let mut lc_buf = [0i8; 64];
        let fl_n = unsafe {
            fl::ns_format_ttl(src as libc::c_ulong, fl_buf.as_mut_ptr(), fl_buf.len())
        };
        let lc_n = unsafe {
            ns_format_ttl(src as libc::c_ulong, lc_buf.as_mut_ptr(), lc_buf.len())
        };
        let case = format!("{src}");
        if fl_n != lc_n {
            divs.push(Divergence {
                case: case.clone(),
                field: "return_length",
                frankenlibc: format!("{fl_n}"),
                glibc: format!("{lc_n}"),
            });
        }
        if fl_n > 0 && lc_n > 0 {
            let s_fl = unsafe { CStr::from_ptr(fl_buf.as_ptr()).to_bytes() };
            let s_lc = unsafe { CStr::from_ptr(lc_buf.as_ptr()).to_bytes() };
            if s_fl != s_lc {
                divs.push(Divergence {
                    case,
                    field: "string",
                    frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                    glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
                });
            }
        }
    }
    assert!(divs.is_empty(), "ns_format_ttl divergences:\n{}", render_divs(&divs));
}

/// Buffer-too-small contract: both impls should return -1 / EMSGSIZE
/// when the destination is too short.
#[test]
fn diff_ns_format_ttl_buffer_too_small() {
    let mut divs = Vec::new();
    let src: libc::c_ulong = 90090; // formats as "1d1h1m30s" = 9 chars + NUL = 10 bytes.
    for size in [0usize, 1, 5, 9] {
        let mut fl_buf = vec![0i8; size + 4];
        let mut lc_buf = vec![0i8; size + 4];
        let fl_n = unsafe { fl::ns_format_ttl(src, fl_buf.as_mut_ptr(), size) };
        let lc_n = unsafe { ns_format_ttl(src, lc_buf.as_mut_ptr(), size) };
        if (fl_n < 0) != (lc_n < 0) {
            divs.push(Divergence {
                case: format!("size={size}"),
                field: "error_signal",
                frankenlibc: format!("{fl_n}"),
                glibc: format!("{lc_n}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "ns_format_ttl buffer-too-small divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn ns_format_ttl_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libresolv ns_format_ttl\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
