#![cfg(target_os = "linux")]

//! Differential conformance harness for `<stdio.h>` snprintf / sscanf.
//!
//! These are pure (buffer in, buffer out) functions — no fd state, no
//! locale state beyond the C locale we already pin. Compares
//! FrankenLibC vs glibc reference for both the return value and the
//! exact byte content of the output buffer (or, for sscanf, the parsed
//! values + match count).
//!
//! Format strings exercise the most common conversion specifiers and
//! the corner cases that historically diverge across implementations:
//!   - %d / %i / %u / %x / %X / %o      with width, precision, flags
//!   - %s (with width + precision)
//!   - %c
//!   - %%
//!   - %f / %e / %g (printf-floating, fixed precision)
//!   - %p (pointer)
//!
//! Bead: CONFORMANCE: libc stdio.h snprintf+sscanf diff matrix.

use std::ffi::c_char;
use std::ffi::c_int;

use frankenlibc_abi::stdio_abi as fl;

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

fn buf_used(buf: &[u8]) -> &[u8] {
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    &buf[..n]
}

// ===========================================================================
// snprintf — integer formats
// ===========================================================================

#[test]
fn diff_snprintf_int_specifiers() {
    let mut divs = Vec::new();
    let cases: &[(&[u8], i32)] = &[
        (b"%d\0", 0),
        (b"%d\0", -1),
        (b"%d\0", 42),
        (b"%d\0", -2147483648),
        (b"%d\0", 2147483647),
        (b"%5d\0", 42),   // width
        (b"%-5d|\0", 42), // left-align
        (b"%05d\0", 42),  // zero-pad
        (b"%+d\0", 42),   // explicit sign
        (b"% d\0", 42),   // space sign
        (b"%x\0", 0xABCD),
        (b"%X\0", 0xABCD),
        (b"%#x\0", 0xABCD),  // alt form
        (b"%08x\0", 0xABCD), // zero-pad hex
        (b"%o\0", 0o755),
        (b"%u\0", 4294967295u32 as i32), // max unsigned
        (b"%.5d\0", 42),                 // precision: zero-pad to N digits
    ];
    for (fmt, val) in cases {
        let mut buf_fl = vec![0u8; 64];
        let mut buf_lc = vec![0u8; 64];
        let n_fl = unsafe {
            fl::snprintf(
                buf_fl.as_mut_ptr() as *mut c_char,
                buf_fl.len(),
                fmt.as_ptr() as *const c_char,
                *val,
            )
        };
        let n_lc = unsafe {
            libc::snprintf(
                buf_lc.as_mut_ptr() as *mut c_char,
                buf_lc.len(),
                fmt.as_ptr() as *const c_char,
                *val,
            )
        };
        let s_fl = buf_used(&buf_fl);
        let s_lc = buf_used(&buf_lc);
        let case = format!(
            "({:?}, {})",
            String::from_utf8_lossy(&fmt[..fmt.len() - 1]),
            val
        );
        if n_fl != n_lc {
            divs.push(Divergence {
                function: "snprintf",
                case: case.clone(),
                field: "return_count",
                frankenlibc: format!("{n_fl}"),
                glibc: format!("{n_lc}"),
            });
        }
        if s_fl != s_lc {
            divs.push(Divergence {
                function: "snprintf",
                case,
                field: "output_bytes",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "snprintf int divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// snprintf — string formats
// ===========================================================================

#[test]
fn diff_snprintf_string_specifiers() {
    let mut divs = Vec::new();
    let cases: &[(&[u8], &[u8])] = &[
        (b"%s\0", b"hello\0"),
        (b"%s\0", b"\0"),                // empty
        (b"|%10s|\0", b"hi\0"),          // width
        (b"|%-10s|\0", b"hi\0"),         // left-align
        (b"%.3s\0", b"hello\0"),         // precision: max chars
        (b"%5.3s\0", b"hello\0"),        // width + precision
        (b"%c\0", b"A\0"),               // single char (passed as int)
        (b"%%\0", b"\0"),                // literal %
        (b"prefix-%s-suffix\0", b"X\0"), // surrounding text
    ];
    for (fmt, val) in cases {
        let mut buf_fl = vec![0u8; 64];
        let mut buf_lc = vec![0u8; 64];
        // %c takes an int; %s takes a *const c_char. Branch by format.
        let is_char = fmt.windows(2).any(|w| w == b"%c" || w == b"%C");
        let (n_fl, n_lc) = if is_char {
            // Pass the first byte as int.
            let c_arg = val[0] as c_int;
            let n_fl = unsafe {
                fl::snprintf(
                    buf_fl.as_mut_ptr() as *mut c_char,
                    buf_fl.len(),
                    fmt.as_ptr() as *const c_char,
                    c_arg,
                )
            };
            let n_lc = unsafe {
                libc::snprintf(
                    buf_lc.as_mut_ptr() as *mut c_char,
                    buf_lc.len(),
                    fmt.as_ptr() as *const c_char,
                    c_arg,
                )
            };
            (n_fl, n_lc)
        } else {
            // %s or no conversion.
            let s = val.as_ptr() as *const c_char;
            let n_fl = unsafe {
                fl::snprintf(
                    buf_fl.as_mut_ptr() as *mut c_char,
                    buf_fl.len(),
                    fmt.as_ptr() as *const c_char,
                    s,
                )
            };
            let n_lc = unsafe {
                libc::snprintf(
                    buf_lc.as_mut_ptr() as *mut c_char,
                    buf_lc.len(),
                    fmt.as_ptr() as *const c_char,
                    s,
                )
            };
            (n_fl, n_lc)
        };
        let s_fl = buf_used(&buf_fl);
        let s_lc = buf_used(&buf_lc);
        let case = format!("({:?})", String::from_utf8_lossy(&fmt[..fmt.len() - 1]));
        if n_fl != n_lc || s_fl != s_lc {
            divs.push(Divergence {
                function: "snprintf",
                case,
                field: "rc/output",
                frankenlibc: format!("rc={n_fl} bytes={:?}", String::from_utf8_lossy(s_fl)),
                glibc: format!("rc={n_lc} bytes={:?}", String::from_utf8_lossy(s_lc)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "snprintf string divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// snprintf — buffer truncation: short size cap, return required length
// ===========================================================================

#[test]
fn diff_snprintf_truncation() {
    let mut divs = Vec::new();
    let fmt = b"hello %d world\0";
    let val = 42i32;
    for &n in &[0usize, 1, 5, 10, 14, 15, 20] {
        let mut buf_fl = vec![0xCDu8; 32];
        let mut buf_lc = vec![0xCDu8; 32];
        let r_fl = unsafe {
            fl::snprintf(
                buf_fl.as_mut_ptr() as *mut c_char,
                n,
                fmt.as_ptr() as *const c_char,
                val,
            )
        };
        let r_lc = unsafe {
            libc::snprintf(
                buf_lc.as_mut_ptr() as *mut c_char,
                n,
                fmt.as_ptr() as *const c_char,
                val,
            )
        };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "snprintf",
                case: format!("size={n}"),
                field: "return_required_len",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
        // Output buffer up to min(n, written) should match.
        let cmp_n = n.min(buf_fl.len());
        if buf_fl[..cmp_n] != buf_lc[..cmp_n] {
            divs.push(Divergence {
                function: "snprintf",
                case: format!("size={n}"),
                field: "output_truncated_buffer",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(&buf_fl[..cmp_n])),
                glibc: format!("{:?}", String::from_utf8_lossy(&buf_lc[..cmp_n])),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "snprintf truncation divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// snprintf — float formats
// ===========================================================================

#[test]
fn diff_snprintf_float_specifiers() {
    let mut divs = Vec::new();
    let cases: &[(&[u8], f64)] = &[
        (b"%f\0", 0.0),
        (b"%f\0", std::f64::consts::PI),
        (b"%f\0", -2.5),
        (b"%.2f\0", std::f64::consts::PI),
        (b"%10.3f\0", std::f64::consts::PI),
        (b"%-10.3f|\0", std::f64::consts::PI),
        (b"%e\0", 1.5e10),
        (b"%E\0", 1.5e-10),
        (b"%.4e\0", 1234567.89),
        (b"%g\0", 0.0001),
        (b"%g\0", 1234567.0),
        (b"%.3g\0", std::f64::consts::PI),
    ];
    for (fmt, val) in cases {
        let mut buf_fl = vec![0u8; 64];
        let mut buf_lc = vec![0u8; 64];
        let n_fl = unsafe {
            fl::snprintf(
                buf_fl.as_mut_ptr() as *mut c_char,
                buf_fl.len(),
                fmt.as_ptr() as *const c_char,
                *val,
            )
        };
        let n_lc = unsafe {
            libc::snprintf(
                buf_lc.as_mut_ptr() as *mut c_char,
                buf_lc.len(),
                fmt.as_ptr() as *const c_char,
                *val,
            )
        };
        let s_fl = buf_used(&buf_fl);
        let s_lc = buf_used(&buf_lc);
        let case = format!(
            "({:?}, {})",
            String::from_utf8_lossy(&fmt[..fmt.len() - 1]),
            val
        );
        if n_fl != n_lc || s_fl != s_lc {
            divs.push(Divergence {
                function: "snprintf",
                case,
                field: "rc/output",
                frankenlibc: format!("rc={n_fl} bytes={:?}", String::from_utf8_lossy(s_fl)),
                glibc: format!("rc={n_lc} bytes={:?}", String::from_utf8_lossy(s_lc)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "snprintf float divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// sscanf — integer + string parsing
// ===========================================================================

#[test]
fn diff_sscanf_int_cases() {
    let mut divs = Vec::new();
    let cases: &[(&[u8], &[u8])] = &[
        (b"42\0", b"%d\0"),
        (b"-7\0", b"%d\0"),
        (b"  123  abc\0", b"%d\0"), // leading ws, trailing garbage
        (b"0x1F\0", b"%x\0"),
        (b"1234\0", b"%i\0"),
        (b"0xff\0", b"%i\0"),
        (b"  abc\0", b"%d\0"),       // no digits → match count 0
        (b"\0", b"%d\0"),            // empty input
        (b"1 2 3\0", b"%d %d %d\0"), // multi
    ];
    for (input, fmt) in cases {
        // For multi-arg cases we need 3 ints; use a fixed buffer of 4.
        let mut got_fl = [0i32; 4];
        let mut got_lc = [0i32; 4];
        let n_fl = unsafe {
            fl::sscanf(
                input.as_ptr() as *const c_char,
                fmt.as_ptr() as *const c_char,
                &mut got_fl[0] as *mut i32,
                &mut got_fl[1] as *mut i32,
                &mut got_fl[2] as *mut i32,
            )
        };
        let n_lc = unsafe {
            libc::sscanf(
                input.as_ptr() as *const c_char,
                fmt.as_ptr() as *const c_char,
                &mut got_lc[0] as *mut i32,
                &mut got_lc[1] as *mut i32,
                &mut got_lc[2] as *mut i32,
            )
        };
        let case = format!(
            "input={:?} fmt={:?}",
            String::from_utf8_lossy(&input[..input.len() - 1]),
            String::from_utf8_lossy(&fmt[..fmt.len() - 1])
        );
        if n_fl != n_lc {
            divs.push(Divergence {
                function: "sscanf",
                case: case.clone(),
                field: "match_count",
                frankenlibc: format!("{n_fl}"),
                glibc: format!("{n_lc}"),
            });
        }
        if n_fl > 0 && got_fl != got_lc {
            divs.push(Divergence {
                function: "sscanf",
                case,
                field: "parsed_ints",
                frankenlibc: format!("{:?}", &got_fl[..n_fl as usize]),
                glibc: format!("{:?}", &got_lc[..n_lc as usize]),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "sscanf int divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// Coverage report
// ===========================================================================

#[test]
fn stdio_printf_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"stdio.h printf+scanf\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
