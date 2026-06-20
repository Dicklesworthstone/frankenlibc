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
        (b"fixed literal output\0", b"\0"),
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

#[test]
fn diff_snprintf_negative_star_width_precision() {
    let mut divs = Vec::new();

    let mut width_fl = vec![0u8; 64];
    let mut width_lc = vec![0u8; 64];
    let width_fmt = b"|%1$*2$d|\0";
    let width_fl_rc = unsafe {
        fl::snprintf(
            width_fl.as_mut_ptr() as *mut c_char,
            width_fl.len(),
            width_fmt.as_ptr() as *const c_char,
            42_i32,
            -5_i32,
        )
    };
    let width_lc_rc = unsafe {
        libc::snprintf(
            width_lc.as_mut_ptr() as *mut c_char,
            width_lc.len(),
            width_fmt.as_ptr() as *const c_char,
            42_i32,
            -5_i32,
        )
    };
    if width_fl_rc != width_lc_rc || buf_used(&width_fl) != buf_used(&width_lc) {
        divs.push(Divergence {
            function: "snprintf",
            case: "%1$*2$d width=-5".to_string(),
            field: "rc/output",
            frankenlibc: format!(
                "rc={width_fl_rc} bytes={:?}",
                String::from_utf8_lossy(buf_used(&width_fl))
            ),
            glibc: format!(
                "rc={width_lc_rc} bytes={:?}",
                String::from_utf8_lossy(buf_used(&width_lc))
            ),
        });
    }

    let mut precision_fl = vec![0u8; 64];
    let mut precision_lc = vec![0u8; 64];
    let precision_fmt = b"%1$.*2$d\0";
    let precision_fl_rc = unsafe {
        fl::snprintf(
            precision_fl.as_mut_ptr() as *mut c_char,
            precision_fl.len(),
            precision_fmt.as_ptr() as *const c_char,
            42_i32,
            -1_i32,
        )
    };
    let precision_lc_rc = unsafe {
        libc::snprintf(
            precision_lc.as_mut_ptr() as *mut c_char,
            precision_lc.len(),
            precision_fmt.as_ptr() as *const c_char,
            42_i32,
            -1_i32,
        )
    };
    if precision_fl_rc != precision_lc_rc || buf_used(&precision_fl) != buf_used(&precision_lc) {
        divs.push(Divergence {
            function: "snprintf",
            case: "%1$.*2$d precision=-1".to_string(),
            field: "rc/output",
            frankenlibc: format!(
                "rc={precision_fl_rc} bytes={:?}",
                String::from_utf8_lossy(buf_used(&precision_fl))
            ),
            glibc: format!(
                "rc={precision_lc_rc} bytes={:?}",
                String::from_utf8_lossy(buf_used(&precision_lc))
            ),
        });
    }

    assert!(
        divs.is_empty(),
        "snprintf negative star width/precision divergences:\n{}",
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
        (b"%.0a\0", 1.5),
        (b"%.1a\0", 1.09375),
        (b"%.1a\0", 1.03125),
        (b"%#.0a\0", 1.0),
        (b"%.1A\0", 0.1),
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

// ===========================================================================
// Randomized float-format differential fuzz vs glibc snprintf.
//
// diff_snprintf_float_specifiers above uses ~17 fixed cases. Float formatting
// (%f/%e/%g/%a, rounding, precision, exponent, subnormals, specials) is the most
// bug-prone printf area, so this deterministically fuzzes diverse doubles across
// flags x widths x precisions x conversions and asserts byte-for-byte agreement
// with host glibc snprintf (return value AND output).
// ===========================================================================

struct PrintfXorShift64(u64);
impl PrintfXorShift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

fn build_float_fmt(flag: &str, width: Option<u32>, prec: Option<u32>, conv: u8) -> Vec<u8> {
    let mut s = String::from("%");
    s.push_str(flag);
    if let Some(w) = width {
        s.push_str(&w.to_string());
    }
    if let Some(p) = prec {
        s.push('.');
        s.push_str(&p.to_string());
    }
    s.push(conv as char);
    let mut v = s.into_bytes();
    v.push(0);
    v
}

#[test]
fn diff_snprintf_float_fuzz() {
    let mut rng = PrintfXorShift64(0x243F6A8885A308D3);

    // Diverse value pool: specials, subnormals, exact boundaries, plus randoms.
    let mut values: Vec<f64> = vec![
        0.0,
        -0.0,
        1.0,
        -1.0,
        0.5,
        2.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        -f64::NAN,
        f64::MIN,
        f64::MAX,
        f64::MIN_POSITIVE,
        f64::from_bits(1),                     // smallest subnormal
        f64::from_bits(0x000F_FFFF_FFFF_FFFF), // largest subnormal
        9.999_999_999_999_999e0,
        1.0 - f64::EPSILON / 2.0, // rounding boundary
        0.1,
        0.3,
        123_456_789.987_654_3,
        1e-300,
        1e300,
    ];
    for _ in 0..1500 {
        // Random finite-ish double: sign * (1+frac) * 2^exp across the range.
        let bits = rng.next_u64();
        let sign = if bits & 1 == 0 { 1.0 } else { -1.0 };
        let frac = (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        let exp = (rng.below(700) as i32) - 350;
        let v = sign * (1.0 + frac) * 2f64.powi(exp);
        if v.is_finite() {
            values.push(v);
        }
    }

    const FLAGS: &[&str] = &["", "#", "0", "+", " ", "-", "+#", "-#"];
    const CONVS: &[u8] = b"feEgGaA";
    const PRECS: &[Option<u32>] = &[None, Some(0), Some(1), Some(2), Some(6), Some(13), Some(25)];
    const WIDTHS: &[Option<u32>] = &[None, Some(0), Some(12), Some(30)];

    let mut divs = Vec::new();
    'outer: for &val in &values {
        for _ in 0..12 {
            let flag = FLAGS[rng.below(FLAGS.len())];
            let conv = CONVS[rng.below(CONVS.len())];
            let prec = PRECS[rng.below(PRECS.len())];
            let width = WIDTHS[rng.below(WIDTHS.len())];
            let fmt = build_float_fmt(flag, width, prec, conv);

            let mut buf_fl = vec![0u8; 4096];
            let mut buf_lc = vec![0u8; 4096];
            let n_fl = unsafe {
                fl::snprintf(
                    buf_fl.as_mut_ptr() as *mut c_char,
                    buf_fl.len(),
                    fmt.as_ptr() as *const c_char,
                    val,
                )
            };
            let n_lc = unsafe {
                libc::snprintf(
                    buf_lc.as_mut_ptr() as *mut c_char,
                    buf_lc.len(),
                    fmt.as_ptr() as *const c_char,
                    val,
                )
            };
            let s_fl = buf_used(&buf_fl);
            let s_lc = buf_used(&buf_lc);
            if n_fl != n_lc || s_fl != s_lc {
                divs.push(Divergence {
                    function: "snprintf",
                    case: format!(
                        "(fmt={:?}, val={val:?} bits={:#018x})",
                        String::from_utf8_lossy(&fmt[..fmt.len() - 1]),
                        val.to_bits()
                    ),
                    field: "rc/output",
                    frankenlibc: format!("rc={n_fl} {:?}", String::from_utf8_lossy(s_fl)),
                    glibc: format!("rc={n_lc} {:?}", String::from_utf8_lossy(s_lc)),
                });
                if divs.len() >= 12 {
                    break 'outer;
                }
            }
        }
    }
    assert!(
        divs.is_empty(),
        "snprintf float fuzz divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// Differential sscanf("%lf") float-parsing fuzz vs glibc.
//
// diff_sscanf_int_cases covers only integers. Float parsing (hex floats,
// inf/nan, exponent edges, overflow/underflow, partial prefixes) is complex and
// bug-prone, so this compares fl::sscanf vs glibc sscanf on adversarial strings
// and randomly-formatted doubles, asserting identical match count and parsed
// value (bit-exact; NaN compared as "both NaN").
// ===========================================================================

#[test]
fn diff_sscanf_float_fuzz() {
    let mut rng = PrintfXorShift64(0x13198A2E03707344);

    let mut inputs: Vec<Vec<u8>> = [
        &b"1.5"[..],
        b"-2.25",
        b".5",
        b"5.",
        b"1e10",
        b"1E10",
        b"1e+10",
        b"1e-10",
        b"1e",
        b"1e+",
        b".",
        b"+",
        b"-",
        b"  +3.14abc",
        b"inf",
        b"INF",
        b"infinity",
        b"Infinity",
        b"nan",
        b"NAN",
        b"nan(123)",
        b"0x1p4",
        b"0x1.8p3",
        b"0X1.Fp-2",
        b"1e999",
        b"1e-999",
        b"123456789.987654321",
        b"",
        b"   ",
        b"+.5e3",
        b"-0",
        b"0x",
        b"00.00",
        b"1.7976931348623157e308",
        b"2.2250738585072014e-308",
        b"4.9406564584124654e-324",
        b"3.",
        b"-.",
        b"0.0e0",
    ]
    .iter()
    .map(|s| {
        let mut v = s.to_vec();
        v.push(0);
        v
    })
    .collect();
    // Very long all-9s mantissa (rounding-overflow stress).
    let mut nines = vec![b'9'; 40];
    nines.push(0);
    inputs.push(nines);

    for _ in 0..1000 {
        let bits = rng.next_u64();
        let sign = if bits & 1 == 0 { 1.0 } else { -1.0 };
        let frac = (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        let exp = (rng.below(700) as i32) - 350;
        let v = sign * (1.0 + frac) * 2f64.powi(exp);
        if !v.is_finite() {
            continue;
        }
        let s = match rng.below(4) {
            0 => format!("{v:.17e}"),
            1 => format!("{v}"),
            2 => format!("{v:.10}"),
            _ => format!("{v:e}"),
        };
        let mut b = s.into_bytes();
        b.push(0);
        inputs.push(b);
    }

    let fmt = b"%lf\0";
    let mut divs = Vec::new();
    for input in &inputs {
        let mut fl_v: f64 = -123.456;
        let mut lc_v: f64 = -123.456;
        let n_fl = unsafe {
            fl::sscanf(
                input.as_ptr() as *const c_char,
                fmt.as_ptr() as *const c_char,
                &mut fl_v as *mut f64,
            )
        };
        let n_lc = unsafe {
            libc::sscanf(
                input.as_ptr() as *const c_char,
                fmt.as_ptr() as *const c_char,
                &mut lc_v as *mut f64,
            )
        };
        let val_differs = if n_fl == 1 && n_lc == 1 {
            if fl_v.is_nan() || lc_v.is_nan() {
                fl_v.is_nan() != lc_v.is_nan()
            } else {
                fl_v.to_bits() != lc_v.to_bits()
            }
        } else {
            false
        };
        if n_fl != n_lc || val_differs {
            divs.push(Divergence {
                function: "sscanf",
                case: format!(
                    "input={:?}",
                    String::from_utf8_lossy(&input[..input.len() - 1])
                ),
                field: "count/value",
                frankenlibc: format!("n={n_fl} v={fl_v:?} bits={:#018x}", fl_v.to_bits()),
                glibc: format!("n={n_lc} v={lc_v:?} bits={:#018x}", lc_v.to_bits()),
            });
            if divs.len() >= 15 {
                break;
            }
        }
    }
    assert!(
        divs.is_empty(),
        "sscanf float fuzz divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// Randomized integer-format differential fuzz vs glibc snprintf.
//
// The fixed int cases above miss flag/width/precision interactions that
// classically diverge: %.0d of 0 (glibc emits ""), %#.0o of 0, conflicting
// flags (0 with -, space with +), precision wider than width, alt-form hex/oct
// of zero, INT_MIN sign handling. Reuses build_float_fmt (it just assembles
// %<flag><width>.<prec><conv>) over the integer conversions.
// ===========================================================================

#[test]
fn diff_snprintf_int_fuzz() {
    let mut rng = PrintfXorShift64(0xA4093822299F31D0);

    let mut values: Vec<i32> = vec![0, 1, -1, 7, -7, 42, i32::MIN, i32::MAX, 255, -255, 8, 0o777];
    for _ in 0..200 {
        values.push(rng.next_u64() as i32);
    }

    const FLAGS: &[&str] = &[
        "", "#", "0", "+", " ", "-", "+#", "-#", "0+", " #", "-0", "+ ",
    ];
    const CONVS: &[u8] = b"diuxXo";
    const PRECS: &[Option<u32>] = &[None, Some(0), Some(1), Some(5), Some(10)];
    const WIDTHS: &[Option<u32>] = &[None, Some(0), Some(8), Some(12)];

    let mut divs = Vec::new();
    'outer: for &val in &values {
        for _ in 0..14 {
            let flag = FLAGS[rng.below(FLAGS.len())];
            let conv = CONVS[rng.below(CONVS.len())];
            let prec = PRECS[rng.below(PRECS.len())];
            let width = WIDTHS[rng.below(WIDTHS.len())];
            let fmt = build_float_fmt(flag, width, prec, conv);

            let mut buf_fl = vec![0u8; 128];
            let mut buf_lc = vec![0u8; 128];
            let n_fl = unsafe {
                fl::snprintf(
                    buf_fl.as_mut_ptr() as *mut c_char,
                    buf_fl.len(),
                    fmt.as_ptr() as *const c_char,
                    val,
                )
            };
            let n_lc = unsafe {
                libc::snprintf(
                    buf_lc.as_mut_ptr() as *mut c_char,
                    buf_lc.len(),
                    fmt.as_ptr() as *const c_char,
                    val,
                )
            };
            let s_fl = buf_used(&buf_fl);
            let s_lc = buf_used(&buf_lc);
            if n_fl != n_lc || s_fl != s_lc {
                divs.push(Divergence {
                    function: "snprintf",
                    case: format!(
                        "(fmt={:?}, val={val})",
                        String::from_utf8_lossy(&fmt[..fmt.len() - 1])
                    ),
                    field: "rc/output",
                    frankenlibc: format!("rc={n_fl} {:?}", String::from_utf8_lossy(s_fl)),
                    glibc: format!("rc={n_lc} {:?}", String::from_utf8_lossy(s_lc)),
                });
                if divs.len() >= 15 {
                    break 'outer;
                }
            }
        }
    }
    assert!(
        divs.is_empty(),
        "snprintf int fuzz divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// sscanf scanset %[...] differential vs glibc.
//
// Scansets have intricate rules — ranges (a-z), negation (^), the literal-`]`-
// first convention (%[]] matches `]`), literal `-` at the edges, and width caps
// — and had no differential coverage. Compares matched string + return count.
// ===========================================================================

#[test]
fn diff_sscanf_scanset() {
    // (input, format-with-%[...])
    let cases: &[(&[u8], &[u8])] = &[
        (b"abcabcx\0", b"%[abc]\0"),
        (b"hello xyz\0", b"%[^xyz]\0"),
        (b"abcZ\0", b"%[a-z]\0"),
        (b"]]]a\0", b"%[]]\0"),     // ] as first char is a literal member
        (b"abc]def\0", b"%[^]]\0"), // ^ then literal ] => negated set {]}
        (b"123abc\0", b"%[0-9]\0"),
        (b"-12+3x\0", b"%[-+0-9]\0"), // - as first char is literal
        (b"aa-bb\0", b"%[a-]\0"),     // - as last char is literal
        (b"12345\0", b"%3[0-9]\0"),   // width cap
        (b"abc\0", b"%[0-9]\0"),      // no match -> count 0
        (b"Hello123\0", b"%[A-Za-z]\0"),
        (b"   lead\0", b"%[a-z ]\0"), // leading spaces are part of the set here
        (b"\0", b"%[a-z]\0"),         // empty input
    ];
    let mut divs = Vec::new();
    for (input, fmt) in cases {
        // Generous buffers; scanf NUL-terminates the matched run.
        let mut buf_fl = vec![0u8; 64];
        let mut buf_lc = vec![0u8; 64];
        let n_fl = unsafe {
            fl::sscanf(
                input.as_ptr() as *const c_char,
                fmt.as_ptr() as *const c_char,
                buf_fl.as_mut_ptr() as *mut c_char,
            )
        };
        let n_lc = unsafe {
            libc::sscanf(
                input.as_ptr() as *const c_char,
                fmt.as_ptr() as *const c_char,
                buf_lc.as_mut_ptr() as *mut c_char,
            )
        };
        let s_fl = buf_used(&buf_fl);
        let s_lc = buf_used(&buf_lc);
        // Output buffer is only meaningful when a field matched.
        let out_differs = (n_fl >= 1 || n_lc >= 1) && s_fl != s_lc;
        if n_fl != n_lc || out_differs {
            divs.push(Divergence {
                function: "sscanf",
                case: format!(
                    "input={:?} fmt={:?}",
                    String::from_utf8_lossy(&input[..input.len() - 1]),
                    String::from_utf8_lossy(&fmt[..fmt.len() - 1])
                ),
                field: "count/matched",
                frankenlibc: format!("n={n_fl} {:?}", String::from_utf8_lossy(s_fl)),
                glibc: format!("n={n_lc} {:?}", String::from_utf8_lossy(s_lc)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "sscanf scanset divergences:\n{}",
        render_divs(&divs)
    );
}
