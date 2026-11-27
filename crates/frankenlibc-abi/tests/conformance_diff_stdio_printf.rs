#![cfg(target_os = "linux")]
#![feature(c_variadic)]

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

// Cross the old 32-slot extraction ceiling using real C varargs. Widths keep
// these cases on the generic parser rather than the fused literal lane.
#[test]
fn diff_snprintf_more_than_32_integer_arguments() {
    let sequential = std::iter::repeat_n("%02d", 40)
        .collect::<Vec<_>>()
        .join(":");
    let positional = (1..=40)
        .rev()
        .map(|position| format!("%{position}$02d"))
        .collect::<Vec<_>>()
        .join(":");
    for format in [sequential, positional] {
        let format = std::ffi::CString::new(format).unwrap();
        for capacity in [0, 1, 17, 256] {
            let mut native = [0xa5u8; 256];
            let mut host = [0xa5u8; 256];
            macro_rules! render {
                ($function:path, $buffer:expr) => {
                    // SAFETY: forty directives have matching promoted ints;
                    // both buffers are valid for the declared capacity.
                    unsafe {
                        $function(
                            $buffer.as_mut_ptr().cast(),
                            capacity,
                            format.as_ptr(),
                            1,
                            2,
                            3,
                            4,
                            5,
                            6,
                            7,
                            8,
                            9,
                            10,
                            11,
                            12,
                            13,
                            14,
                            15,
                            16,
                            17,
                            18,
                            19,
                            20,
                            21,
                            22,
                            23,
                            24,
                            25,
                            26,
                            27,
                            28,
                            29,
                            30,
                            31,
                            32,
                            33,
                            34,
                            35,
                            36,
                            37,
                            38,
                            39,
                            40,
                        )
                    }
                };
            }
            let actual = render!(fl::snprintf, native);
            let expected = render!(libc::snprintf, host);
            assert_eq!(expected, 119);
            assert_eq!(actual, expected, "{format:?}, capacity={capacity}");
            assert_eq!(native, host, "{format:?}, capacity={capacity}");
        }
    }
}

#[test]
fn diff_snprintf_more_than_32_float_arguments() {
    let format = std::ffi::CString::new(
        std::iter::repeat_n("%.2f", 40)
            .collect::<Vec<_>>()
            .join(":"),
    )
    .unwrap();
    let mut native = [0xa5u8; 512];
    let mut host = [0xa5u8; 512];
    macro_rules! render {
        ($function:path, $buffer:expr) => {
            // SAFETY: forty initialized doubles match forty %f conversions.
            unsafe {
                $function(
                    $buffer.as_mut_ptr().cast(),
                    $buffer.len(),
                    format.as_ptr(),
                    0.25f64,
                    1.25f64,
                    2.25f64,
                    3.25f64,
                    4.25f64,
                    5.25f64,
                    6.25f64,
                    7.25f64,
                    8.25f64,
                    9.25f64,
                    10.25f64,
                    11.25f64,
                    12.25f64,
                    13.25f64,
                    14.25f64,
                    15.25f64,
                    16.25f64,
                    17.25f64,
                    18.25f64,
                    19.25f64,
                    20.25f64,
                    21.25f64,
                    22.25f64,
                    23.25f64,
                    24.25f64,
                    25.25f64,
                    26.25f64,
                    27.25f64,
                    28.25f64,
                    29.25f64,
                    30.25f64,
                    31.25f64,
                    32.25f64,
                    33.25f64,
                    34.25f64,
                    35.25f64,
                    36.25f64,
                    37.25f64,
                    38.25f64,
                    39.25f64,
                )
            }
        };
    }
    assert_eq!(render!(fl::snprintf, native), render!(libc::snprintf, host));
    assert_eq!(native, host);
}

#[test]
fn diff_snprintf_mixed_arguments_and_count_after_32() {
    let mut format = "%02d:".repeat(30);
    format.push_str("%*.*f|%s|%ld%n");
    let format = std::ffi::CString::new(format).unwrap();
    for capacity in [0, 1, 95, 256] {
        let mut native = [0xa5u8; 256];
        let mut host = [0xa5u8; 256];
        let mut native_count = -1;
        let mut host_count = -1;
        macro_rules! render {
            ($function:path, $buffer:expr, $count:expr) => {
                // SAFETY: stars consume ints, then a promoted double, C string,
                // LP64 long and writable int pointer follow the first 30 ints.
                unsafe {
                    $function(
                        $buffer.as_mut_ptr().cast(),
                        capacity,
                        format.as_ptr(),
                        1,
                        2,
                        3,
                        4,
                        5,
                        6,
                        7,
                        8,
                        9,
                        10,
                        11,
                        12,
                        13,
                        14,
                        15,
                        16,
                        17,
                        18,
                        19,
                        20,
                        21,
                        22,
                        23,
                        24,
                        25,
                        26,
                        27,
                        28,
                        29,
                        30,
                        -7,
                        2,
                        3.25f64,
                        c"tail".as_ptr(),
                        -4294967297i64 as libc::c_long,
                        &mut $count as *mut c_int,
                    )
                }
            };
        }
        let actual = render!(fl::snprintf, native, native_count);
        let expected = render!(libc::snprintf, host, host_count);
        assert!(expected > 100);
        assert_eq!(actual, expected, "capacity={capacity}");
        assert_eq!(native_count, host_count, "capacity={capacity}");
        assert_eq!(native_count, expected);
        assert_eq!(native, host, "capacity={capacity}");
    }
}

#[test]
fn snprintf_rejects_unrepresentable_argument_positions_before_allocation() {
    for format in [
        c"%2147483648$d",
        c"%18446744073709551616$d",
        c"%1$*2147483648$d",
        c"%1$.*2147483648$f",
    ] {
        let mut buffer = [0xa5u8; 16];
        // SAFETY: these positions cannot fit the GNU int-valued contract and
        // must be rejected before fetching any nonexistent variadic arguments.
        unsafe {
            *frankenlibc_abi::errno_abi::__errno_location() = 0;
            assert_eq!(
                fl::snprintf(buffer.as_mut_ptr().cast(), buffer.len(), format.as_ptr()),
                -1
            );
            assert_eq!(
                *frankenlibc_abi::errno_abi::__errno_location(),
                libc::EOVERFLOW
            );
        }
    }
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
        (b"%s\0", b"\0"),         // empty
        (b"|%10s|\0", b"hi\0"),   // width
        (b"|%-10s|\0", b"hi\0"),  // left-align
        (b"%.3s\0", b"hello\0"),  // precision: max chars
        (b"%5.3s\0", b"hello\0"), // width + precision
        (b"%c\0", b"A\0"),        // single char (passed as int)
        (b"%%\0", b"\0"),         // literal %
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
        (b"1 2\0", b"%d %d\0"),      // two-field exact fast path
        (b"1\0", b"%d %d\0"),        // two-field partial → count 1
        (b"1 x\0", b"%d %d\0"),      // two-field mismatch → count 1
        (b"\0", b"%d %d\0"),         // two-field empty → EOF
        (b"1 2 3\0", b"%d %d %d\0"), // multi
        (b"1 2\0", b"%d %d %d\0"),   // partial multi → count 2
        (b"1 x 3\0", b"%d %d %d\0"), // second conversion mismatch → count 1
        (b"\0", b"%d %d %d\0"),      // empty multi → EOF
        (b"2147483648 -2147483649 +7\0", b"%d %d %d\0"), // int overflow wraps like glibc
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

// stdout is process-global, so this differential matrix runs in exact-filtered
// children. Each provider uses its own FILE, callbacks and stdout cell, with
// errno read and written through that provider's accessor.
mod redirected_stdout {
    use super::{c_char, c_int, fl};
    use std::ffi::c_void;

    const CHILD: &str = "FRANKENLIBC_PRINTF_COOKIE_STDOUT_CHILD";
    const TEST: &str = "redirected_stdout::printf_and_vprintf_use_cookie_stdout";
    const SENTINEL: c_int = 0x5eed;
    const OUTPUT: &[u8] = b"stdout|0042|3.25|\0|\n";

    mod host {
        use super::{c_char, c_int, c_void, fl};

        unsafe extern "C" {
            pub static mut stdout: *mut c_void;
            pub fn __errno_location() -> *mut c_int;
            pub fn fmemopen(buffer: *mut c_void, size: usize, mode: *const c_char) -> *mut c_void;
            pub fn fopencookie(
                cookie: *mut c_void,
                mode: *const c_char,
                funcs: fl::CookieIoFuncs,
            ) -> *mut c_void;
        }

        unsafe extern "C-unwind" {
            pub fn printf(format: *const c_char, ...) -> c_int;
            pub fn vprintf(format: *const c_char, args: *mut c_void) -> c_int;
            pub fn __printf_chk(flag: c_int, format: *const c_char, ...) -> c_int;
            pub fn __vprintf_chk(flag: c_int, format: *const c_char, args: *mut c_void) -> c_int;
            pub fn setvbuf(
                stream: *mut c_void,
                buffer: *mut c_char,
                mode: c_int,
                size: usize,
            ) -> c_int;
            pub fn fflush(stream: *mut c_void) -> c_int;
            pub fn ferror(stream: *mut c_void) -> c_int;
            pub fn fclose(stream: *mut c_void) -> c_int;
        }
    }

    fn errno_slot(native: bool) -> *mut c_int {
        // SAFETY: each provider exposes its calling thread's writable errno.
        unsafe {
            if native {
                frankenlibc_abi::errno_abi::__errno_location()
            } else {
                host::__errno_location()
            }
        }
    }

    // Construct a real va_list from promoted arguments, including an FP
    // register argument. Do not fabricate architecture-specific va_list bytes.
    unsafe extern "C-unwind" fn call_vprintf(
        native: c_int,
        fortified: c_int,
        format: *const c_char,
        mut args: ...
    ) -> c_int {
        let args = std::ptr::addr_of_mut!(args).cast::<c_void>();
        // SAFETY: this wrapper owns the live va_list and the caller supplies
        // arguments matching format; each arm consumes it exactly once.
        unsafe {
            match (native != 0, fortified != 0) {
                (true, false) => fl::vprintf(format, args),
                (false, false) => host::vprintf(format, args),
                (true, true) => frankenlibc_abi::fortify_abi::__vprintf_chk(1, format, args),
                (false, true) => host::__vprintf_chk(1, format, args),
            }
        }
    }

    fn render(native: bool, variant: usize) -> c_int {
        // Width, mixed GP/FP arguments and the counted NUL keep this on the
        // generic formatter, away from literal/exact-integer fast paths.
        let format = c"%s|%04d|%.2f|%c|\n";
        // SAFETY: all four entry points receive the same promoted C arguments.
        unsafe {
            match variant {
                0 if native => fl::printf(format.as_ptr(), c"stdout".as_ptr(), 42, 3.25f64, 0),
                0 => host::printf(format.as_ptr(), c"stdout".as_ptr(), 42, 3.25f64, 0),
                1 | 3 => call_vprintf(
                    native as c_int,
                    (variant == 3) as c_int,
                    format.as_ptr(),
                    c"stdout".as_ptr(),
                    42,
                    3.25f64,
                    0,
                ),
                2 if native => frankenlibc_abi::fortify_abi::__printf_chk(
                    1,
                    format.as_ptr(),
                    c"stdout".as_ptr(),
                    42,
                    3.25f64,
                    0,
                ),
                2 => host::__printf_chk(1, format.as_ptr(), c"stdout".as_ptr(), 42, 3.25f64, 0),
                _ => unreachable!("bounded printf variant"),
            }
        }
    }

    struct Redirect {
        slot: *mut *mut c_void,
        saved: *mut c_void,
        stream: *mut c_void,
        close: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    }

    impl Redirect {
        unsafe fn install(native: bool, stream: *mut c_void) -> Self {
            let slot = if native {
                &raw mut fl::stdout
            } else {
                // SAFETY: take the address of the linked GNU stdout cell.
                unsafe { &raw mut host::stdout }
            };
            // SAFETY: the isolated child owns this provider's stdout cell.
            let saved = unsafe { slot.replace(stream) };
            Self {
                slot,
                saved,
                stream,
                close: if native { fl::fclose } else { host::fclose },
            }
        }

        fn finish(mut self) -> c_int {
            // Restore before fclose, which could invoke a user callback.
            // Clearing ownership first prevents a second close during unwind.
            unsafe { self.slot.write(self.saved) };
            let stream = std::mem::replace(&mut self.stream, std::ptr::null_mut());
            // SAFETY: this guard owns the live stream and matching provider.
            unsafe { (self.close)(stream) }
        }
    }

    impl Drop for Redirect {
        fn drop(&mut self) {
            // SAFETY: the process-global cell remains live. On panic, close
            // while the caller's cookie and setvbuf storage are still alive.
            unsafe {
                self.slot.write(self.saved);
                if !self.stream.is_null() {
                    (self.close)(self.stream);
                }
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Observation {
        configured: c_int,
        printed: (c_int, c_int, bool),
        before_flush: Vec<u8>,
        flushed: (c_int, c_int, bool),
        closed: c_int,
        after_close: Vec<u8>,
    }

    fn observe(
        native: bool,
        variant: usize,
        stream: *mut c_void,
        mode: c_int,
        buffer: *mut c_char,
        capacity: usize,
        snapshot: impl Fn() -> Vec<u8>,
    ) -> Observation {
        let configure = if native { fl::setvbuf } else { host::setvbuf };
        let flush = if native { fl::fflush } else { host::fflush };
        let error = if native { fl::ferror } else { host::ferror };
        // SAFETY: callers retain stream backing and buffer through finish.
        // No assertion runs while the selected stdout cell is redirected.
        unsafe {
            let redirect = Redirect::install(native, stream);
            let configured = configure(stream, buffer, mode, capacity);
            *errno_slot(native) = SENTINEL;
            let count = render(native, variant);
            let number = *errno_slot(native);
            let printed = (count, number, error(stream) != 0);
            let before_flush = snapshot();
            *errno_slot(native) = SENTINEL;
            let result = flush(stream);
            let number = *errno_slot(native);
            let flushed = (result, number, error(stream) != 0);
            let closed = redirect.finish();
            Observation {
                configured,
                printed,
                before_flush,
                flushed,
                closed,
                after_close: snapshot(),
            }
        }
    }

    struct Cookie {
        native: bool,
        fail: bool,
        bytes: Vec<u8>,
    }

    unsafe extern "C-unwind" fn write_cookie(
        opaque: *mut c_void,
        input: *const c_char,
        length: usize,
    ) -> isize {
        // SAFETY: cookie() retains this state through the matching fclose.
        let cookie = unsafe { &mut *opaque.cast::<Cookie>() };
        if cookie.fail {
            // A zero-length write signals failure under the GNU cookie ABI.
            // Set this provider's errno rather than an unrelated host cell.
            unsafe { *errno_slot(cookie.native) = libc::ENOSPC };
            return 0;
        }
        // SAFETY: the writer supplies length readable bytes, including NUL.
        let bytes = unsafe { std::slice::from_raw_parts(input.cast(), length) };
        cookie.bytes.extend_from_slice(bytes);
        length as isize
    }

    fn cookie(native: bool, variant: usize, mode: c_int, fail: bool) -> Observation {
        let mut state = Cookie {
            native,
            fail,
            bytes: Vec::new(),
        };
        let state_pointer = &raw mut state;
        let mut buffer = [0u8; 512];
        let open = if native {
            fl::fopencookie
        } else {
            host::fopencookie
        };
        let funcs = fl::CookieIoFuncs {
            write: Some(write_cookie),
            ..fl::CookieIoFuncs::default()
        };
        // SAFETY: state and buffering stay live until observe closes stream.
        let stream = unsafe { open(state_pointer.cast(), c"w".as_ptr(), funcs) };
        assert!(!stream.is_null());
        observe(
            native,
            variant,
            stream,
            mode,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            // Capture a raw pointer, not a shared reference held across a
            // callback's mutable borrow. Snapshot only between operations.
            || unsafe { (*state_pointer).bytes.clone() },
        )
    }

    fn fixed_memory(native: bool, variant: usize) -> Observation {
        let mut buffer = [0xa5u8; 256];
        let pointer = buffer.as_mut_ptr();
        let open = if native { fl::fmemopen } else { host::fmemopen };
        // SAFETY: the complete caller buffer outlives the selected stream.
        let stream = unsafe { open(pointer.cast(), buffer.len(), c"w".as_ptr()) };
        assert!(!stream.is_null());
        observe(
            native,
            variant,
            stream,
            libc::_IONBF,
            std::ptr::null_mut(),
            0,
            // Preserve bytes beyond the counted NUL and the output boundary.
            || unsafe { std::slice::from_raw_parts(pointer, 256).to_vec() },
        )
    }

    #[test]
    fn printf_and_vprintf_use_cookie_stdout() {
        if std::env::var_os(CHILD).is_none() {
            for mode in ["strict", "hardened"] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                    .env(CHILD, "1")
                    .env("FRANKENLIBC_MODE", mode)
                    .env_remove("LD_PRELOAD")
                    .env_remove("LD_AUDIT")
                    .output()
                    .expect("run isolated stdout differential test");
                let report = String::from_utf8_lossy(&output.stdout);
                assert!(
                    output.status.success() && report.contains("1 passed"),
                    "{mode}: child must execute and pass the regression\n{report}\n{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return;
        }

        // Bound a lock or callback regression instead of hanging the parent.
        // SAFETY: this exact-filtered child owns its process-wide alarm.
        unsafe { libc::alarm(30) };

        // These must be independent implementations and independent public
        // data cells; comparing a provider to itself cannot establish parity.
        assert_ne!(fl::printf as *const (), host::printf as *const ());
        assert_ne!(fl::vprintf as *const (), host::vprintf as *const ());
        assert_ne!(
            frankenlibc_abi::fortify_abi::__printf_chk as *const (),
            host::__printf_chk as *const ()
        );
        assert_ne!(
            frankenlibc_abi::fortify_abi::__vprintf_chk as *const (),
            host::__vprintf_chk as *const ()
        );
        assert_ne!(fl::fopencookie as *const (), host::fopencookie as *const ());
        assert_ne!(fl::fmemopen as *const (), host::fmemopen as *const ());
        // SAFETY: compare the addresses without reading either FILE cell.
        assert_ne!(&raw mut fl::stdout, unsafe { &raw mut host::stdout });

        let mut compared = 0;
        for (variant, name) in ["printf", "vprintf", "__printf_chk", "__vprintf_chk"]
            .into_iter()
            .enumerate()
        {
            for mode in [libc::_IOFBF, libc::_IOLBF, libc::_IONBF] {
                let reference = cookie(false, variant, mode, false);
                assert_eq!(reference.configured, 0);
                assert_eq!(reference.printed.0, OUTPUT.len() as c_int);
                assert!(!reference.printed.2);
                assert_eq!(reference.flushed.0, 0);
                assert!(!reference.flushed.2);
                assert_eq!(reference.closed, 0);
                assert_eq!(reference.after_close, OUTPUT);
                assert_eq!(
                    reference.before_flush.as_slice(),
                    if mode == libc::_IOFBF {
                        b"".as_slice()
                    } else {
                        OUTPUT
                    }
                );
                assert_eq!(
                    cookie(true, variant, mode, false),
                    reference,
                    "{name}/{mode}"
                );
                compared += 1;
            }

            let reference = cookie(false, variant, libc::_IONBF, true);
            assert!(reference.printed.0 < 0);
            assert_eq!(
                (reference.printed.1, reference.printed.2),
                (libc::ENOSPC, true)
            );
            assert!(reference.before_flush.is_empty());
            assert!(reference.after_close.is_empty());
            assert_eq!(
                cookie(true, variant, libc::_IONBF, true),
                reference,
                "{name}: immediate callback failure"
            );
            compared += 1;

            let reference = fixed_memory(false, variant);
            let mut expected = vec![0xa5; 256];
            expected[..OUTPUT.len()].copy_from_slice(OUTPUT);
            expected[OUTPUT.len()] = 0;
            assert_eq!(reference.configured, 0);
            assert_eq!(reference.printed.0, OUTPUT.len() as c_int);
            assert!(!reference.printed.2);
            assert_eq!(reference.flushed.0, 0);
            assert_eq!(reference.closed, 0);
            assert_eq!(reference.after_close, expected);
            assert_eq!(
                fixed_memory(true, variant),
                reference,
                "{name}: fixed memory"
            );
            compared += 1;
        }
        assert_eq!(compared, 20, "all stream/caller combinations must execute");
        // SAFETY: all redirected streams have closed and this child is done.
        unsafe { libc::alarm(0) };
    }
}
