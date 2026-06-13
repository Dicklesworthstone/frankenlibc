#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc ether_ntoa/ether_aton oracle (libc, linked by std)

//! Randomized live differential fuzzer for `ether_ntoa_r` / `ether_aton_r` vs
//! host glibc. glibc's ether_ntoa uses "%x:%x:%x:%x:%x:%x" — NO leading zeros,
//! lowercase (e.g. {0,1,10,11,12,255} -> "0:1:a:b:c:ff"), and a corresponding
//! parser. This sweeps random 6-byte addresses (ntoa) and random/edge MAC
//! strings (aton), comparing the exact output / parsed bytes / accept-reject.

use std::ffi::{CStr, CString, c_char, c_void};

use frankenlibc_abi::unistd_abi::{ether_aton_r as fl_aton_r, ether_ntoa_r as fl_ntoa_r};

unsafe extern "C" {
    fn ether_ntoa_r(addr: *const c_void, buf: *mut c_char) -> *mut c_char;
    fn ether_aton_r(asc: *const c_char, addr: *mut c_void) -> *mut c_void;
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
        // Bias toward small values (<0x10) so the leading-zero behavior shows.
        if self.next() & 1 == 0 {
            (self.next() % 16) as u8
        } else {
            (self.next() >> 24) as u8
        }
    }
}

fn ntoa(
    f: unsafe extern "C" fn(*const c_void, *mut c_char) -> *mut c_char,
    addr: &[u8; 6],
) -> String {
    let mut buf = [0u8; 32];
    let r = unsafe {
        f(
            addr.as_ptr() as *const c_void,
            buf.as_mut_ptr() as *mut c_char,
        )
    };
    if r.is_null() {
        return "<null>".into();
    }
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// Returns (parsed-ok, 6 bytes).
fn aton(
    f: unsafe extern "C" fn(*const c_char, *mut c_void) -> *mut c_void,
    s: &CStr,
) -> (bool, [u8; 6]) {
    let mut out = [0u8; 6];
    let r = unsafe { f(s.as_ptr(), out.as_mut_ptr() as *mut c_void) };
    (!r.is_null(), out)
}

#[test]
fn ether_ntoa_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0xe1f0_4e10_a155_0001);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..200_000 {
        // ---- ether_ntoa_r ----
        let addr = [r.byte(), r.byte(), r.byte(), r.byte(), r.byte(), r.byte()];
        let fl = ntoa(fl_ntoa_r, &addr);
        let host = ntoa(ether_ntoa_r, &addr);
        compared += 1;
        if fl != host && divs.len() < 40 {
            divs.push(format!(
                "ntoa addr={addr:02x?}\n    fl   ={fl:?}\n    glibc={host:?}"
            ));
        }

        // ---- ether_aton_r (feed back glibc's own ntoa output + raw strings) ----
        let s = if r.next() & 1 == 0 {
            host.clone()
        } else {
            // a random "a:b:c:d:e:f"-ish string with mixed widths
            let parts: Vec<String> = (0..6).map(|_| format!("{:x}", r.byte())).collect();
            parts.join(":")
        };
        if let Ok(cs) = CString::new(s.as_str()) {
            let (flok, flb) = aton(fl_aton_r, &cs);
            let (hok, hb) = aton(ether_aton_r, &cs);
            compared += 1;
            if (flok != hok || (flok && flb != hb)) && divs.len() < 40 {
                divs.push(format!(
                    "aton src={s:?}\n    fl   =ok={flok} {flb:02x?}\n    glibc=ok={hok} {hb:02x?}"
                ));
            }
        }
    }

    assert!(
        divs.is_empty(),
        "ether_ntoa/aton diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!(
        "ether ntoa/aton differential fuzz: {compared} comparisons, 0 divergences vs host glibc"
    );
}
