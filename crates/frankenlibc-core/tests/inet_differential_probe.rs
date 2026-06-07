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
        "1.2.3.4",
        "0.0.0.0",
        "255.255.255.255",
        "127.0.0.1",
        "1.2.3.256",
        "1.2.3",
        "1.2.3.4.5",
        "01.2.3.4",
        "1.2.3.04",
        " 1.2.3.4",
        "1.2.3.4 ",
        "256.1.1.1",
        "1..2.3",
        "",
        "1.2.3.4x",
        "0x1.2.3.4",
    ];
    let v4_glibc: &[&str] = &[
        "1 01020304",
        "1 00000000",
        "1 ffffffff",
        "1 7f000001",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
    ];
    let v6: &[&str] = &[
        "::1",
        "::",
        "1::",
        "2001:db8::1",
        "::ffff:1.2.3.4",
        "::g",
        "1:2:3:4:5:6:7:8",
        "1:2:3:4:5:6:7:8:9",
        "1::2::3",
        "12345::",
        "::ffff:1.2.3.256",
        "2001:db8:::1",
        "fe80::1",
        "0:0:0:0:0:0:0:0",
        ":::",
        "abcd:ef01:2345:6789:abcd:ef01:2345:6789",
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
            diffs.push(format!(
                "pton4 {s:?}: frankenlibc={got:?} glibc={:?}",
                v4_glibc[i]
            ));
        }
    }
    for (i, &s) in v6.iter().enumerate() {
        let got = pton(AF_INET6, s);
        if got != v6_glibc[i] {
            diffs.push(format!(
                "pton6 {s:?}: frankenlibc={got:?} glibc={:?}",
                v6_glibc[i]
            ));
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
        (
            AF_INET6,
            {
                let mut b = vec![0u8; 16];
                b[15] = 1;
                b
            },
            "::1",
        ),
        (AF_INET6, vec![0u8; 16], "::"),
        (
            AF_INET6,
            vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            "2001:db8::1",
        ),
        (
            AF_INET6,
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4],
            "::ffff:1.2.3.4",
        ),
        (
            AF_INET6,
            vec![0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0],
            "1:0:2:0:3:0:4:0",
        ),
        (
            AF_INET6,
            vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0],
            "0:1::2:0",
        ),
        (
            AF_INET6,
            vec![
                0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
                0x67, 0x89,
            ],
            "abcd:ef01:2345:6789:abcd:ef01:2345:6789",
        ),
    ];

    let mut diffs = Vec::new();
    for (af, bytes, expected) in cases {
        let got = ntop(*af, bytes);
        if got != *expected {
            diffs.push(format!(
                "ntop af={af} {bytes:02x?}: frankenlibc={got:?} glibc={expected:?}"
            ));
        }
    }
    assert!(
        diffs.is_empty(),
        "inet_ntop diverges from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}

/// Live differential fuzz of `inet_aton` (BSD numbers-and-dots grammar) against
/// the host glibc `inet_aton`: 1/2/3/4-part forms, decimal/octal/hex octets,
/// overflow, leading zeros, and trailing junk — the quirky legacy surface that
/// `inet_pton`'s strict parser deliberately omits. Compares success and the
/// packed 4-byte (network-order) result over ~26k generated inputs.
#[test]
#[allow(unsafe_code)] // host-glibc inet_aton oracle
fn inet_aton_live_differential_vs_glibc() {
    use frankenlibc_core::inet::inet_aton as fl_inet_aton;
    use std::ffi::c_char;
    unsafe extern "C" {
        #[link_name = "inet_aton"]
        fn c_inet_aton(cp: *const c_char, inp: *mut u32) -> i32;
    }

    // Tokens exercising decimal / octal (leading 0) / hex (0x) / overflow / junk.
    let tokens: &[&str] = &[
        "0",
        "1",
        "9",
        "10",
        "08",
        "00",
        "01",
        "07",
        "010",
        "0377",
        "0400",
        "0x0",
        "0xff",
        "0x100",
        "127",
        "128",
        "255",
        "256",
        "65535",
        "65536",
        "16777215",
        "16777216",
        "4294967295",
        "4294967296",
        "",
        "1a",
        "0x",
        "999",
        "0xFFFFFFFF",
        "0xG",
        "+1",
        "-1",
    ];
    // Smaller core for the deeper (3/4-part) cartesian products.
    let core: &[&str] = &[
        "0",
        "1",
        "08",
        "010",
        "0377",
        "0x0",
        "0xff",
        "0x100",
        "255",
        "256",
        "65536",
        "16777216",
        "4294967296",
        "",
        "999",
        "0xG",
    ];
    let core4: &[&str] = &[
        "0", "1", "08", "0377", "0xff", "255", "256", "65536", "", "999", "0xG", "0x100",
    ];

    let mut inputs: Vec<String> = Vec::new();
    for &a in tokens {
        inputs.push(a.to_string());
    }
    for &a in tokens {
        for &b in tokens {
            inputs.push(format!("{a}.{b}"));
        }
    }
    for &a in core {
        for &b in core {
            for &c in core {
                inputs.push(format!("{a}.{b}.{c}"));
            }
        }
    }
    for &a in core4 {
        for &b in core4 {
            for &c in core4 {
                for &d in core4 {
                    inputs.push(format!("{a}.{b}.{c}.{d}"));
                }
            }
        }
    }
    // Curated quirks: trailing junk/whitespace, empty parts, max forms.
    for q in [
        "127.0.0.1",
        "0177.0.0.1",
        "0x7f.0.0.1",
        "127.1",
        "127.0.1",
        "2130706433",
        "0x7f000001",
        "017700000001",
        "1.2.3.4 ",
        " 1.2.3.4",
        "1.2.3.4\t",
        "1.2.3.4\n",
        "1.2.3.4x",
        "1..2.3",
        ".1.2.3",
        "1.2.3.",
        "1.2.3.4.5",
        "255.255.255.255",
        "256.256.256.256",
        "0.0.0.0",
        "00.00.00.00",
        "0x.0x.0x.0x",
        "1.2.3.4.",
    ] {
        inputs.push(q.to_string());
    }

    let mut diffs: Vec<String> = Vec::new();
    let mut checked: u64 = 0;
    for input in &inputs {
        let mut fl_dst = [0u8; 4];
        let fl_rc = fl_inet_aton(input.as_bytes(), &mut fl_dst);
        let mut cstr = input.as_bytes().to_vec();
        cstr.push(0);
        let mut g_addr: u32 = 0xDEAD_BEEF;
        let g_rc = unsafe { c_inet_aton(cstr.as_ptr() as *const c_char, &mut g_addr) };
        let g_dst = g_addr.to_ne_bytes();
        let fl_ok = fl_rc == 1;
        let g_ok = g_rc == 1;
        checked += 1;
        if fl_ok != g_ok || (fl_ok && fl_dst != g_dst) {
            diffs.push(format!(
                "input={input:?} -> fl=(rc={fl_rc}, {fl_dst:02x?}) glibc=(rc={g_rc}, {g_dst:02x?})"
            ));
            if diffs.len() >= 60 {
                break;
            }
        }
    }
    eprintln!(
        "inet_aton live diff: {checked} comparisons, {} divergence(s)",
        diffs.len()
    );
    assert!(
        diffs.is_empty(),
        "inet_aton diverges from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
