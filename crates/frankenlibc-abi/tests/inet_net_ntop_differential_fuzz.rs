#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc inet_net_ntop/pton oracle (libc, linked by std)

//! Randomized live differential fuzzer for `inet_net_ntop` / `inet_net_pton`
//! (AF_INET) vs host glibc. These are the CIDR-network conversions: ntop renders
//! `ceil(bits/8)` octets of the address with a `/bits` suffix (glibc's quirky
//! class-based abbreviation), and pton parses `a.b.c.d/bits` back. This sweeps
//! random addresses × random bit counts (ntop) and canonical round-trips +
//! random network strings (pton), comparing the exact output / bytes / bits /
//! return.

use std::ffi::{CStr, CString, c_char, c_int, c_void};

use frankenlibc_abi::glibc_internal_abi::{inet_net_ntop as fl_ntop, inet_net_pton as fl_pton};

// inet_net_ntop / inet_net_pton live in libresolv, not libc.
#[link(name = "resolv")]
unsafe extern "C" {
    fn inet_net_ntop(
        af: c_int,
        src: *const c_void,
        bits: c_int,
        dst: *mut c_char,
        size: usize,
    ) -> *mut c_char;
    fn inet_net_pton(af: c_int, src: *const c_char, dst: *mut c_void, size: usize) -> c_int;
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 33) as u8
    }
}

fn ntop(
    f: unsafe extern "C" fn(c_int, *const c_void, c_int, *mut c_char, usize) -> *mut c_char,
    src: &[u8; 4],
    bits: c_int,
) -> String {
    let mut buf = [0u8; 64];
    let r = unsafe {
        f(
            libc::AF_INET,
            src.as_ptr() as *const c_void,
            bits,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        )
    };
    if r.is_null() {
        return "<null>".into();
    }
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

fn pton(
    f: unsafe extern "C" fn(c_int, *const c_char, *mut c_void, usize) -> c_int,
    s: &CStr,
) -> (c_int, [u8; 4]) {
    let mut buf = [0u8; 4];
    let r = unsafe {
        f(
            libc::AF_INET,
            s.as_ptr(),
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
        )
    };
    (r, buf)
}

#[test]
fn inet_net_ntop_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x1be7_4e70_5566_0001);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..200_000 {
        // ---- ntop ----
        let src = [r.byte(), r.byte(), r.byte(), r.byte()];
        let bits = (r.next() % 33) as c_int; // 0..=32
        let fl = ntop(fl_ntop, &src, bits);
        let host = ntop(inet_net_ntop, &src, bits);
        compared += 1;
        if fl != host && divs.len() < 40 {
            divs.push(format!(
                "ntop src={src:02x?} bits={bits}\n    fl   ={fl:?}\n    glibc={host:?}"
            ));
        }

        // ---- pton (round-trip glibc's own output + a random network string) ----
        // Sweep the quirky libresolv grammar: classful (no /bits), hex (0x..),
        // uppercase 0X, leading zeros, partial octets, over/under-size prefixes,
        // trailing junk — that is where divergences from glibc actually hide.
        let s = match r.next() % 8 {
            0 => {
                if host == "<null>" {
                    continue;
                }
                host.clone()
            }
            1 => {
                // Decimal a.b.c.d/bits with bits possibly out of [0,32].
                let parts = 1 + (r.next() % 4);
                let octs: Vec<String> = (0..parts).map(|_| format!("{}", r.byte())).collect();
                format!("{}/{}", octs.join("."), r.next() % 40)
            }
            2 => {
                // Classful: decimal octets, NO /bits suffix (libresolv infers).
                let parts = 1 + (r.next() % 4);
                let octs: Vec<String> = (0..parts).map(|_| format!("{}", r.byte())).collect();
                octs.join(".")
            }
            3 => {
                // Hex 0x form, random nibble count, optional /bits.
                let nibbles = 1 + (r.next() % 9);
                let hex: String = (0..nibbles)
                    .map(|_| char::from_digit((r.next() % 16) as u32, 16).unwrap())
                    .collect();
                if r.next() & 1 == 0 {
                    format!("0x{hex}")
                } else {
                    format!("0x{hex}/{}", r.next() % 40)
                }
            }
            4 => {
                // Uppercase 0X with uppercase hex digits.
                let nibbles = 1 + (r.next() % 9);
                let hex: String = (0..nibbles)
                    .map(|_| {
                        char::from_digit((r.next() % 16) as u32, 16)
                            .unwrap()
                            .to_ascii_uppercase()
                    })
                    .collect();
                format!("0X{hex}")
            }
            5 => {
                // Leading-zero decimal octets (libresolv treats as decimal, not octal).
                let parts = 1 + (r.next() % 4);
                let octs: Vec<String> = (0..parts).map(|_| format!("{:03}", r.byte())).collect();
                format!("{}/{}", octs.join("."), r.next() % 33)
            }
            6 => {
                // Malformed: double dots, trailing dot, trailing junk, empty.
                let pick = r.next() % 5;
                match pick {
                    0 => "1..2".into(),
                    1 => "10.0.0.1.".into(),
                    2 => format!("{}.{}/{}x", r.byte(), r.byte(), r.next() % 33),
                    3 => "".into(),
                    _ => format!("{}/", r.byte()),
                }
            }
            _ => {
                // Random byte soup of the legal alphabet (digits, dots, x, slash).
                const ALPHA: &[u8] = b"0123456789.xX/abcdefABCDEF";
                let len = 1 + (r.next() % 12) as usize;
                let bytes: Vec<u8> = (0..len)
                    .map(|_| ALPHA[(r.next() as usize) % ALPHA.len()])
                    .collect();
                String::from_utf8(bytes).unwrap()
            }
        };
        if let Ok(cs) = CString::new(s.as_str()) {
            let (flr, flb) = pton(fl_pton, &cs);
            let (hor, hob) = pton(inet_net_pton, &cs);
            compared += 1;
            // Compare return (bits / -1); address bytes only when both succeeded.
            let fl_repr = if flr >= 0 {
                format!("bits={flr} {flb:02x?}")
            } else {
                format!("ret={flr}")
            };
            let host_repr = if hor >= 0 {
                format!("bits={hor} {hob:02x?}")
            } else {
                format!("ret={hor}")
            };
            if fl_repr != host_repr && divs.len() < 40 {
                divs.push(format!(
                    "pton src={s:?}\n    fl   ={fl_repr}\n    glibc={host_repr}"
                ));
            }
        }
    }

    assert!(
        divs.is_empty(),
        "inet_net_ntop/pton diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("inet_net_ntop/pton fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
