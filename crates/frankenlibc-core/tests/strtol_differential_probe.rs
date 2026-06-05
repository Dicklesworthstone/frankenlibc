//! Differential probe: frankenlibc strtol vs glibc strtol over an edge-case
//! battery (base auto-detection, overflow/underflow clamping + ERANGE, invalid
//! bases, exact INT64 boundaries, partial consumption). glibc reference values
//! captured from a C probe. Compares (value, bytes consumed, ERANGE flag).

use frankenlibc_core::stdlib::conversion::{ConversionStatus, strtol_impl};

#[test]
fn strtol_differential_battery() {
    // (input, base)
    let cases: &[(&str, i32)] = &[
        ("0", 0),
        ("0x1A", 0),
        ("010", 0),
        ("0x", 0),
        ("  +42xyz", 10),
        ("  -42", 10),
        ("9999999999999999999999", 10),
        ("-9999999999999999999999", 10),
        ("ff", 16),
        ("0xff", 16),
        ("z", 36),
        ("z", 35),
        ("", 10),
        ("+", 10),
        ("0x", 16),
        ("7fffffffffffffff", 16),
        ("8000000000000000", 16),
        ("-1", 10),
        ("  0X1p", 0),
        ("123", 1),
        ("123", 37),
        ("\t\n 10", 10),
        ("-8000000000000000", 16),
        ("-8000000000000001", 16),
        ("+0x10", 0),
        ("  ", 10),
        ("-0", 10),
        ("2147483648", 10),
        ("0777", 8),
        ("777", 8),
        ("+-5", 10),
        ("0Xg", 0),
        ("100", 2),
        ("102", 2),
        ("ZZ", 36),
        ("   0x", 0),
        ("9223372036854775807", 10),
        ("9223372036854775808", 10),
        ("-9223372036854775808", 10),
        ("-9223372036854775809", 10),
    ];

    // glibc reference: (value, consumed, erange), captured from a C probe.
    let glibc: &[(i64, usize, u8)] = &[
        (0, 1, 0),
        (26, 4, 0),
        (8, 3, 0),
        (0, 1, 0),
        (42, 5, 0),
        (-42, 5, 0),
        (9223372036854775807, 22, 1),
        (-9223372036854775808, 23, 1),
        (255, 2, 0),
        (255, 4, 0),
        (35, 1, 0),
        (0, 0, 0),
        (0, 0, 0),
        (0, 0, 0),
        (0, 1, 0),
        (9223372036854775807, 16, 0),
        (9223372036854775807, 16, 1),
        (-1, 2, 0),
        (1, 5, 0),
        (0, 0, 0),
        (0, 0, 0),
        (10, 5, 0),
        (-9223372036854775808, 17, 0),
        (-9223372036854775808, 17, 1),
        (16, 5, 0),
        (0, 0, 0),
        (0, 2, 0),
        (2147483648, 10, 0),
        (511, 4, 0),
        (511, 3, 0),
        (0, 0, 0),
        (0, 1, 0),
        (4, 3, 0),
        (2, 2, 0),
        (1295, 2, 0),
        (0, 4, 0),
        (9223372036854775807, 19, 0),
        (9223372036854775807, 19, 1),
        (-9223372036854775808, 20, 0),
        (-9223372036854775808, 20, 1),
    ];

    let mut diffs = Vec::new();
    for (i, &(s, base)) in cases.iter().enumerate() {
        let (val, consumed, status) = strtol_impl(s.as_bytes(), base);
        let erange = matches!(
            status,
            ConversionStatus::Overflow | ConversionStatus::Underflow
        );
        let erange_n = if erange { 1u8 } else { 0u8 };
        let (gv, gc, ge) = glibc[i];
        if val != gv || consumed != gc || erange_n != ge {
            diffs.push(format!(
                "case {i}: input={s:?} base={base} -> frankenlibc=({val}, {consumed}, {erange_n}) glibc=({gv}, {gc}, {ge})"
            ));
        }
    }
    assert!(
        diffs.is_empty(),
        "strtol diverges from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
