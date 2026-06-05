//! Differential probe: frankenlibc sscanf vs glibc sscanf over a battery
//! exercising the matching/counting contract: multi-conversion counts, EOF vs
//! match-failure return (-1 vs 0), base detection (%i), %x/%o, field width
//! (%3d/%2s/%3c), assignment suppression (%*d), scansets (%[a-z]/%[^0-9]/%[]a]),
//! %c, %n (not counted), literal matching, and float parsing (compared via exact
//! IEEE bits). glibc reference captured from a C sscanf probe.

use frankenlibc_core::stdio::scanf::{ScanValue, parse_scanf_format, scan_input};

fn run(fmt: &str, input: &str) -> String {
    let dirs = parse_scanf_format(fmt.as_bytes());
    let r = scan_input(input.as_bytes(), &dirs);
    // Map to the C sscanf return convention: EOF (-1) when an input failure
    // occurs before any assignment, otherwise the assignment count.
    let ret = if r.count == 0 && r.input_failure {
        -1
    } else {
        r.count
    };
    let mut s = format!("{ret}");
    for v in &r.values {
        match v {
            ScanValue::SignedInt(i) => s += &format!(" i{i}"),
            ScanValue::UnsignedInt(u) => s += &format!(" u{u}"),
            ScanValue::Float(f) => s += &format!(" f{:016x}", f.to_bits()),
            ScanValue::Char(b) | ScanValue::String(b) => {
                s += " s";
                s += &String::from_utf8_lossy(b);
            }
            ScanValue::CharsConsumed(n) => s += &format!(" n{n}"),
            ScanValue::Pointer(p) => s += &format!(" p{p}"),
        }
    }
    s
}

#[test]
fn scanf_differential_battery() {
    let cases: &[(&str, &str)] = &[
        ("%d %d", "12 34"),
        ("%d %d", "12"),
        ("%d", "   42"),
        ("%d", "abc"),
        ("%i", "0x1F"),
        ("%i", "010"),
        ("%x", "ff"),
        ("%o", "777"),
        ("%3d%s", "12abc"),
        ("%s", "hello world"),
        ("%s", "  hello"),
        ("%d%*d%d", "12 34"),
        ("%2s", "99x"),
        ("%[a-z]", "abc123"),
        ("%[^0-9]", "abc123"),
        ("%[a-z]", "123abc"),
        ("%c", "xy"),
        ("%3c", "abcd"),
        ("%d%n", "42xy"),
        ("%d,%d", "12,34"),
        ("%d,%d", "12;34"),
        ("%lf", "3.14"),
        ("%lf", "1e10"),
        ("%lf", ".5"),
        ("%d", "-2147483648"),
        ("%d %s", "  +5  hi"),
        ("%d", ""),
        ("%d %d %d", "1 2 3"),
        ("%[]a]", "a]b"),
    ];

    // glibc reference lines, captured from a C sscanf probe.
    let glibc: &[&str] = &[
        "2 i12 i34",
        "1 i12",
        "1 i42",
        "0",
        "1 i31",
        "1 i8",
        "1 u255",
        "1 u511",
        "2 i12 sabc",
        "1 shello",
        "1 shello",
        "1 i12",
        "1 s99",
        "1 sabc",
        "1 sabc",
        "0",
        "1 sx",
        "1 sabc",
        "1 i42 n2",
        "2 i12 i34",
        "1 i12",
        "1 f40091eb851eb851f",
        "1 f4202a05f20000000",
        "1 f3fe0000000000000",
        "1 i-2147483648",
        "2 i5 shi",
        "-1",
        "3 i1 i2 i3",
        "1 sa]",
    ];

    assert_eq!(cases.len(), glibc.len(), "battery length mismatch");

    let mut diffs = Vec::new();
    for (i, &(fmt, input)) in cases.iter().enumerate() {
        let got = run(fmt, input);
        if got != glibc[i] {
            diffs.push(format!(
                "case {i}: fmt={fmt:?} input={input:?} -> frankenlibc={got:?} glibc={:?}",
                glibc[i]
            ));
        }
    }
    assert!(
        diffs.is_empty(),
        "sscanf diverges from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
