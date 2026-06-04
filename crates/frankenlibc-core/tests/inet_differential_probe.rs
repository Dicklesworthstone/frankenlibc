//! Differential probe: frankenlibc inet_pton/inet_ntop vs glibc. Covers IPv4
//! strictness (leading-zero rejection, octet range, field count, trailing/
//! leading junk), IPv6 forms (::, embedded IPv4, double-::, oversize groups,
//! 9 groups), and inet_ntop :: compression rules (leftmost-longest zero run,
//! no single-zero compression, IPv4-mapped). glibc reference captured from a C
//! probe (return code + packed hex for pton; text for ntop).

use frankenlibc_core::inet::{inet_ntop, inet_pton};

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;

fn pton(af: i32, src: &str) -> String {
    let mut buf = [0u8; 16];
    let r = inet_pton(af, src.as_bytes(), &mut buf);
    if r == 1 {
        let n = if af == AF_INET { 4 } else { 16 };
        let hex: String = buf[..n].iter().map(|b| format!("{b:02x}")).collect();
        format!("1 {hex}")
    } else {
        r.to_string()
    }
}

fn ntop(af: i32, bytes: &[u8]) -> String {
    match inet_ntop(af, bytes) {
        Some(v) => String::from_utf8(v).unwrap_or_else(|_| "BADUTF8".to_string()),
        None => "NULL".to_string(),
    }
}

#[test]
fn inet_pton_differential_battery() {
    let v4: &[&str] = &[
        "1.2.3.4", "0.0.0.0", "255.255.255.255", "127.0.0.1", "1.2.3.256", "1.2.3",
        "1.2.3.4.5", "01.2.3.4", "1.2.3.04", " 1.2.3.4", "1.2.3.4 ", "256.1.1.1",
        "1..2.3", "", "1.2.3.4x", "0x1.2.3.4",
    ];
    let v4_glibc: &[&str] = &[
        "1 01020304", "1 00000000", "1 ffffffff", "1 7f000001", "0", "0", "0", "0",
        "0", "0", "0", "0", "0", "0", "0", "0",
    ];
    let v6: &[&str] = &[
        "::1", "::", "1::", "2001:db8::1", "::ffff:1.2.3.4", "::g", "1:2:3:4:5:6:7:8",
        "1:2:3:4:5:6:7:8:9", "1::2::3", "12345::", "::ffff:1.2.3.256", "2001:db8:::1",
        "fe80::1", "0:0:0:0:0:0:0:0", ":::", "abcd:ef01:2345:6789:abcd:ef01:2345:6789",
    ];
    let v6_glibc: &[&str] = &[
        "1 00000000000000000000000000000001",
        "1 00000000000000000000000000000000",
        "1 00010000000000000000000000000000",
        "1 20010db8000000000000000000000001",
        "1 00000000000000000000ffff01020304",
        "0",
        "1 00010002000300040005000600070008",
        "0",
        "0",
        "0",
        "0",
        "0",
        "1 fe800000000000000000000000000001",
        "1 00000000000000000000000000000000",
        "0",
        "1 abcdef0123456789abcdef0123456789",
    ];

    let mut diffs = Vec::new();
    for (i, &s) in v4.iter().enumerate() {
        let got = pton(AF_INET, s);
        if got != v4_glibc[i] {
            diffs.push(format!("pton4 {s:?}: frankenlibc={got:?} glibc={:?}", v4_glibc[i]));
        }
    }
    for (i, &s) in v6.iter().enumerate() {
        let got = pton(AF_INET6, s);
        if got != v6_glibc[i] {
            diffs.push(format!("pton6 {s:?}: frankenlibc={got:?} glibc={:?}", v6_glibc[i]));
        }
    }
    assert!(
        diffs.is_empty(),
        "inet_pton diverges from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}

#[test]
fn inet_ntop_differential_battery() {
    // (af, bytes, glibc text)
    let cases: &[(i32, Vec<u8>, &str)] = &[
        (AF_INET, vec![1, 2, 3, 4], "1.2.3.4"),
        (AF_INET, vec![255, 255, 255, 255], "255.255.255.255"),
        (AF_INET, vec![0, 0, 0, 0], "0.0.0.0"),
        (AF_INET6, {
            let mut b = vec![0u8; 16];
            b[15] = 1;
            b
        }, "::1"),
        (AF_INET6, vec![0u8; 16], "::"),
        (AF_INET6, vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], "2001:db8::1"),
        (AF_INET6, vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4], "::ffff:1.2.3.4"),
        (AF_INET6, vec![0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0], "1:0:2:0:3:0:4:0"),
        (AF_INET6, vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0], "0:1::2:0"),
        (AF_INET6, vec![0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89], "abcd:ef01:2345:6789:abcd:ef01:2345:6789"),
    ];

    let mut diffs = Vec::new();
    for (af, bytes, expected) in cases {
        let got = ntop(*af, bytes);
        if got != *expected {
            diffs.push(format!("ntop af={af} {bytes:02x?}: frankenlibc={got:?} glibc={expected:?}"));
        }
    }
    assert!(
        diffs.is_empty(),
        "inet_ntop diverges from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
