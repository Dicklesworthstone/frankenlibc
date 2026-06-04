//! Differential probe: frankenlibc printf %a/%A (hexadecimal float) vs glibc.
//! %a is a bespoke hand-written formatter (hex mantissa + binary 'p' exponent);
//! exercises normalized form, the 0x1.8 fractional mantissa, subnormals
//! (0x0.…p-1022), precision padding/rounding (%.3a, %.0a round-half-to-even),
//! negative zero (-0x0p+0), upper-case (%A), and DBL_MAX. glibc reference
//! captured from a C probe. inf/nan compared loosely (sign/payload unspecified).

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
fn printf_hexfloat_differential_battery() {
    let cases: &[(&str, f64, &str)] = &[
        ("%a", 1.0, "0x1p+0"),
        ("%a", 0.5, "0x1p-1"),
        ("%a", 2.0, "0x1p+1"),
        ("%a", 3.0, "0x1.8p+1"),
        ("%a", 0.1, "0x1.999999999999ap-4"),
        ("%a", 0.0, "0x0p+0"),
        ("%a", -0.0, "-0x0p+0"),
        ("%A", 1.0, "0X1P+0"),
        ("%.3a", 1.0, "0x1.000p+0"),
        ("%a", -2.0, "-0x1p+1"),
        ("%a", f64::MAX, "0x1.fffffffffffffp+1023"),
        ("%a", f64::from_bits(1), "0x0.0000000000001p-1022"),
        ("%.0a", 1.5, "0x2p+0"),
        ("%a", 255.0, "0x1.fep+7"),
    ];

    let mut diffs = Vec::new();
    for (fmt, val, expected) in cases {
        let got = render(fmt, *val);
        if got != *expected {
            diffs.push(format!("printf({fmt:?}, {val:?}) -> frankenlibc={got:?} glibc={expected:?}"));
        }
    }

    // inf/nan: compare loosely (sign/payload unspecified by the standard).
    let inf = render("%a", f64::INFINITY);
    if inf != "inf" {
        diffs.push(format!("printf(\"%a\", inf) -> frankenlibc={inf:?} glibc=\"inf\""));
    }
    let nan = render("%a", f64::NAN);
    if !nan.contains("nan") {
        diffs.push(format!("printf(\"%a\", nan) -> frankenlibc={nan:?} (expected to contain \"nan\")"));
    }

    assert!(
        diffs.is_empty(),
        "printf %a hex-float diverges from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
