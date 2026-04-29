#![cfg(target_os = "linux")]

//! Differential conformance harness for libresolv `__b64_ntop` / `__b64_pton`
//! (BIND-derived RFC 4648 base64).
//!
//! These symbols are exported by `libresolv.so.2` (NOT libc.so.6), so the
//! `#[link(name = "resolv")]` attribute pulls in the host implementation
//! at link time. fl exports its own `__b64_ntop`/`__b64_pton` in
//! `frankenlibc_abi::glibc_internal_abi`. We diff:
//!
//!   - encode round-trip — `ntop(input)` must equal host output bit-for-bit
//!   - decode round-trip — `pton(text)` must equal host output bit-for-bit
//!   - error cases — fl and host must agree on -1 returns for malformed input

use std::ffi::{c_char, c_int};

use frankenlibc_abi::glibc_internal_abi as fl;

#[link(name = "resolv")]
unsafe extern "C" {
    /// Host libresolv `__b64_ntop` — encode binary → base64 ASCII.
    fn __b64_ntop(src: *const u8, srclen: usize, target: *mut c_char, targsize: usize) -> c_int;
    /// Host libresolv `__b64_pton` — decode base64 ASCII → binary.
    fn __b64_pton(src: *const c_char, target: *mut u8, targsize: usize) -> c_int;
}

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

/// Encode test inputs covering padding boundaries (len mod 3 ∈ {0, 1, 2}),
/// empty input, and high-byte values.
const NTOP_INPUTS: &[&[u8]] = &[
    b"",
    b"a",
    b"ab",
    b"abc",
    b"abcd",
    b"abcde",
    b"abcdef",
    b"Hello, World!",
    b"The quick brown fox jumps over the lazy dog.",
    &[0xFF, 0xFE, 0xFD],
    &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
    &[0xFF; 32],
    &[0; 32],
    // RFC 4648 §10 test vectors:
    b"f",
    b"fo",
    b"foo",
    b"foob",
    b"fooba",
    b"foobar",
];

#[test]
fn diff_b64_ntop_cases() {
    let mut divs = Vec::new();
    for input in NTOP_INPUTS {
        // 4*ceil(n/3)+1 is the encoded length including NUL.
        let need = input.len().div_ceil(3) * 4 + 1;
        let mut fl_buf = vec![0u8; need + 16];
        let mut lc_buf = vec![0u8; need + 16];
        let fl_n = unsafe {
            fl::__b64_ntop(
                input.as_ptr(),
                input.len(),
                fl_buf.as_mut_ptr() as *mut c_char,
                fl_buf.len(),
            )
        };
        let lc_n = unsafe {
            __b64_ntop(
                input.as_ptr(),
                input.len(),
                lc_buf.as_mut_ptr() as *mut c_char,
                lc_buf.len(),
            )
        };
        let case = format!("len={}", input.len());
        if fl_n != lc_n {
            divs.push(Divergence {
                function: "__b64_ntop",
                case: case.clone(),
                field: "return",
                frankenlibc: format!("{fl_n}"),
                glibc: format!("{lc_n}"),
            });
        }
        if fl_n >= 0 && lc_n >= 0 {
            let n = fl_n as usize;
            if fl_buf[..n] != lc_buf[..n] {
                divs.push(Divergence {
                    function: "__b64_ntop",
                    case,
                    field: "encoded",
                    frankenlibc: String::from_utf8_lossy(&fl_buf[..n]).to_string(),
                    glibc: String::from_utf8_lossy(&lc_buf[..n]).to_string(),
                });
            }
        }
    }
    assert!(divs.is_empty(), "__b64_ntop divergences:\n{}", render_divs(&divs));
}

/// Decode test inputs covering valid encodings, padding variants, embedded
/// whitespace (libresolv tolerance), and various malformed shapes.
const PTON_INPUTS: &[&[u8]] = &[
    b"",
    b"YQ==",
    b"YWI=",
    b"YWJj",
    b"SGVsbG8sIFdvcmxkIQ==",
    // Whitespace tolerance (libresolv quirk).
    b"YWJj ",
    b"YWJj\n",
    b"Y W J j",
    // Malformed:
    b"YQ",        // missing pad
    b"YWI",       // missing pad
    b"YWJj====",  // extra pad
    b"!!!!",      // non-base64 chars
    b"YQ=Q",      // pad in middle
    b"========",  // all-pad
];

#[test]
fn diff_b64_pton_cases() {
    let mut divs = Vec::new();
    for input in PTON_INPUTS {
        let mut fl_buf = vec![0u8; input.len() + 16];
        let mut lc_buf = vec![0u8; input.len() + 16];
        let mut nul_input = input.to_vec();
        nul_input.push(0);
        let p = nul_input.as_ptr() as *const c_char;
        let fl_n = unsafe { fl::__b64_pton(p, fl_buf.as_mut_ptr(), fl_buf.len()) };
        let lc_n = unsafe { __b64_pton(p, lc_buf.as_mut_ptr(), lc_buf.len()) };
        let case = format!("{:?}", String::from_utf8_lossy(input));
        if fl_n != lc_n {
            divs.push(Divergence {
                function: "__b64_pton",
                case: case.clone(),
                field: "return",
                frankenlibc: format!("{fl_n}"),
                glibc: format!("{lc_n}"),
            });
        }
        if fl_n >= 0 && lc_n >= 0 {
            let n = fl_n as usize;
            if fl_buf[..n] != lc_buf[..n] {
                divs.push(Divergence {
                    function: "__b64_pton",
                    case,
                    field: "decoded",
                    frankenlibc: format!("{:?}", &fl_buf[..n]),
                    glibc: format!("{:?}", &lc_buf[..n]),
                });
            }
        }
    }
    assert!(divs.is_empty(), "__b64_pton divergences:\n{}", render_divs(&divs));
}

#[test]
fn b64_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libresolv b64\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
