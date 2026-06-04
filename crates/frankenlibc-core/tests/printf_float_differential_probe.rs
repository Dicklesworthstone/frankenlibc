//! Differential probe: frankenlibc printf float formatting (%f/%e/%g and
//! upper variants) vs glibc, over a battery stressing round-half-to-even,
//! %g trailing-zero stripping + exponent threshold, alt-form (#), sign/space
//! flags, width/zero-pad/left-justify, and negative zero. glibc reference
//! strings captured from a C snprintf probe.

use frankenlibc_core::stdio::printf::{FormatSegment, format_float, parse_format_string};

fn render(fmt: &str, val: f64) -> String {
    let segs = parse_format_string(fmt.as_bytes());
    let spec = segs
        .as_slice()
        .iter()
        .find_map(|s| match s {
            FormatSegment::Spec(spec) => Some(*spec),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no spec parsed from {fmt:?}"));
    let mut buf = Vec::new();
    format_float(val, &spec, &mut buf);
    String::from_utf8(buf).expect("utf8")
}

#[test]
fn printf_float_differential_battery() {
    let cases: &[(&str, f64)] = &[
        ("%.0f", 0.5), ("%.0f", 1.5), ("%.0f", 2.5), ("%.0f", 3.5), ("%.0f", -0.5),
        ("%.0f", -2.5),
        ("%.1f", 0.25), ("%.1f", 0.35), ("%.1f", 0.45), ("%.1f", 0.55), ("%.1f", 2.675),
        ("%f", 0.0), ("%f", -0.0), ("%f", 1.0), ("%f", 0.1), ("%f", 123.456),
        ("%f", 999999.5), ("%f", 0.0001),
        ("%#.0f", 5.0), ("%#.0e", 5.0), ("%#.0g", 5.0), ("%#g", 100.0),
        ("%+f", 1.0), ("% f", 1.0), ("%+.2f", -0.0), ("% .2e", 3.0),
        ("%-10.2f", 3.14), ("%010.3f", -3.14), ("%12.4e", 1234.5), ("%012.4e", -1.5),
        ("%e", 0.0), ("%e", 1.0), ("%.3e", 123456.0), ("%E", 0.00012345),
        ("%.0e", 9.6), ("%e", 1e20), ("%e", 1e-20),
        ("%g", 0.0), ("%g", 100000.0), ("%g", 1000000.0), ("%g", 0.0001),
        ("%g", 0.00001), ("%g", 123.456), ("%g", 100.0), ("%.0g", 5.0),
        ("%.17g", 0.1), ("%.3g", 0.0001234), ("%g", 0.5), ("%G", 1e-20),
        ("%g", 1234567.0), ("%g", 9.999999e5), ("%g", 9.9999995e5),
        ("%.10f", 3.14159265358979), ("%.2f", 65.0),
        ("%g", -0.0), ("%e", -0.0), ("%.0f", -0.4),
    ];

    // glibc reference strings, captured from a C snprintf probe.
    let glibc: &[&str] = &[
        "0", "2", "2", "4", "-0", "-2",
        "0.2", "0.3", "0.5", "0.6", "2.7",
        "0.000000", "-0.000000", "1.000000", "0.100000", "123.456000",
        "999999.500000", "0.000100",
        "5.", "5.e+00", "5.", "100.000",
        "+1.000000", " 1.000000", "-0.00", " 3.00e+00",
        "3.14      ", "-00003.140", "  1.2345e+03", "-01.5000e+00",
        "0.000000e+00", "1.000000e+00", "1.235e+05", "1.234500E-04",
        "1e+01", "1.000000e+20", "1.000000e-20",
        "0", "100000", "1e+06", "0.0001",
        "1e-05", "123.456", "100", "5",
        "0.10000000000000001", "0.000123", "0.5", "1E-20",
        "1.23457e+06", "1e+06", "1e+06",
        "3.1415926536", "65.00",
        "-0", "-0.000000e+00", "-0",
    ];

    assert_eq!(cases.len(), glibc.len(), "battery length mismatch");

    let mut diffs = Vec::new();
    for (i, &(fmt, val)) in cases.iter().enumerate() {
        let got = render(fmt, val);
        if got != glibc[i] {
            diffs.push(format!(
                "case {i}: fmt={fmt:?} val={val:?} -> frankenlibc={got:?} glibc={:?}",
                glibc[i]
            ));
        }
    }
    assert!(
        diffs.is_empty(),
        "printf float formatting diverges from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
