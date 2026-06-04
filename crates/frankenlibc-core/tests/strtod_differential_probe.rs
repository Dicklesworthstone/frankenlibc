//! Differential probe: frankenlibc strtod vs glibc, focused on the bespoke
//! hex-float path (the decimal path delegates to Rust std, but hex floats —
//! significand*16 + ldexp — are hand-written) plus special values, overflow,
//! and subnormals. Compared via exact IEEE-754 bits + bytes consumed; NaN is
//! compared as is-NaN (payload/sign unspecified). glibc reference captured from
//! a C probe.

use frankenlibc_core::stdlib::conversion::strtod;

fn run(s: &str) -> (u64, usize, bool) {
    let mut b = s.as_bytes().to_vec();
    b.push(0); // strtod expects a NUL-terminated slice
    let (v, consumed) = strtod(&b);
    (v.to_bits(), consumed, v.is_nan())
}

#[test]
fn strtod_differential_battery() {
    // (input, glibc bits, consumed, is_nan)
    let cases: &[(&str, u64, usize, bool)] = &[
        ("0x1p0", 0x3ff0000000000000, 5, false),
        ("0x1.8p1", 0x4008000000000000, 7, false),
        ("0x1.0p-1", 0x3fe0000000000000, 8, false),
        ("0xAp0", 0x4024000000000000, 5, false),
        ("0x1p-1074", 0x0000000000000001, 9, false),
        ("0x0p0", 0x0000000000000000, 5, false),
        ("-0x1p0", 0xbff0000000000000, 6, false),
        ("0x.8p1", 0x3ff0000000000000, 6, false),
        ("0x10", 0x4030000000000000, 4, false),
        ("0x1.999999999999ap-4", 0x3fb999999999999a, 20, false),
        ("inf", 0x7ff0000000000000, 3, false),
        ("-inf", 0xfff0000000000000, 4, false),
        ("infinity", 0x7ff0000000000000, 8, false),
        ("nan", 0, 3, true),
        ("nan(123)", 0, 8, true),
        ("1e308", 0x7fe1ccf385ebc8a0, 5, false),
        ("1e400", 0x7ff0000000000000, 5, false),
        ("1e-400", 0x0000000000000000, 6, false),
        ("3.14159265358979", 0x400921fb54442d11, 16, false),
        (".5", 0x3fe0000000000000, 2, false),
        ("0x", 0x0000000000000000, 1, false),
        ("0X1.Fp4", 0x403f000000000000, 7, false),
        ("0x1.0p+4", 0x4030000000000000, 8, false),
        ("  0x1p2xyz", 0x4010000000000000, 7, false),
    ];

    let mut diffs = Vec::new();
    for (s, exp_bits, exp_consumed, exp_nan) in cases {
        let (bits, consumed, is_nan) = run(s);
        if *exp_nan {
            if !is_nan || consumed != *exp_consumed {
                diffs.push(format!(
                    "strtod({s:?}): frankenlibc=(nan={is_nan}, consumed={consumed}) glibc=(nan=true, consumed={exp_consumed})"
                ));
            }
        } else if bits != *exp_bits || consumed != *exp_consumed {
            diffs.push(format!(
                "strtod({s:?}): frankenlibc=(0x{bits:016x}, consumed={consumed}) glibc=(0x{exp_bits:016x}, consumed={exp_consumed})"
            ));
        }
    }
    assert!(
        diffs.is_empty(),
        "strtod diverges from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
