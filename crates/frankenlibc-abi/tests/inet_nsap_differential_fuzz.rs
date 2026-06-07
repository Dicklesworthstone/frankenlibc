#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc inet_nsap_addr/ntoa oracle (libresolv)

//! Randomized live differential fuzzer for `inet_nsap_addr` / `inet_nsap_ntoa`
//! (ISO 8348 / RFC 1629 NSAP hex addresses) vs host glibc. `inet_nsap_addr`
//! parses pairs of hex digits with `.`/`+`/`/` separators allowed only between
//! complete byte pairs; `inet_nsap_ntoa` renders binary as uppercase hex with a
//! `.` after every even-indexed byte. The existing core unit tests are
//! fixed-case; this sweeps random hex strings (with separators, junk, odd
//! counts, leading/trailing seps) for ntoa round-trips AND random binary for
//! addr, comparing the exact byte count / output string vs the libresolv oracle.

use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};

use frankenlibc_abi::glibc_internal_abi::{
    inet_nsap_addr as fl_addr, inet_nsap_ntoa as fl_ntoa,
};

// inet_nsap_addr / inet_nsap_ntoa live in libresolv, not libc.
#[link(name = "resolv")]
unsafe extern "C" {
    fn inet_nsap_addr(cp: *const c_char, buf: *mut c_void, buflen: c_int) -> c_uint;
    fn inet_nsap_ntoa(len: c_int, cp: *const c_void, buf: *mut c_char) -> *mut c_char;
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

fn call_addr(
    f: unsafe extern "C" fn(*const c_char, *mut c_void, c_int) -> c_uint,
    s: &CStr,
    buflen: usize,
) -> (c_uint, Vec<u8>) {
    let mut buf = vec![0u8; buflen.max(1)];
    let n = unsafe { f(s.as_ptr(), buf.as_mut_ptr() as *mut c_void, buflen as c_int) };
    buf.truncate(n as usize);
    (n, buf)
}

fn call_ntoa(
    f: unsafe extern "C" fn(c_int, *const c_void, *mut c_char) -> *mut c_char,
    bin: &[u8],
) -> String {
    // Generous caller buffer: each byte -> 2 hex + up to 1 sep, + NUL.
    let mut out = vec![0u8; bin.len() * 3 + 16];
    let r = unsafe {
        f(bin.len() as c_int, bin.as_ptr() as *const c_void, out.as_mut_ptr() as *mut c_char)
    };
    if r.is_null() {
        return "<null>".into();
    }
    let n = out.iter().position(|&b| b == 0).unwrap_or(out.len());
    String::from_utf8_lossy(&out[..n]).into_owned()
}

#[test]
fn inet_nsap_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x4e5a_4150_0bad_f00d);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..150_000 {
        // ---- ntoa: random binary of random length (incl 0 and >255 clamp) ----
        let blen = (r.next() % 40) as usize;
        let bin: Vec<u8> = (0..blen).map(|_| r.byte()).collect();
        let fl_s = call_ntoa(fl_ntoa, &bin);
        let host_s = call_ntoa(inet_nsap_ntoa, &bin);
        compared += 1;
        if fl_s != host_s && divs.len() < 40 {
            divs.push(format!("ntoa bin={bin:02x?}\n    fl   ={fl_s:?}\n    glibc={host_s:?}"));
        }

        // ---- addr: parse a generated hex/sep/junk string ----
        let s = match r.next() % 6 {
            0 => fl_s.clone(), // round-trip our own ntoa output
            1 => {
                // Clean hex pairs with random `.`/`+`/`/` separators between.
                let pairs = r.next() % 12;
                let seps = *b".+/";
                let mut t = String::new();
                for k in 0..pairs {
                    if k > 0 {
                        // 0..=2 random separators between pairs.
                        for _ in 0..(r.next() % 3) {
                            t.push(seps[(r.next() % 3) as usize] as char);
                        }
                    }
                    t.push_str(&format!("{:02x}", r.byte()));
                }
                t
            }
            2 => {
                // Odd hex-digit counts, leading/trailing separators.
                let digits = r.next() % 9;
                let mut t = String::new();
                if r.next() & 1 == 0 {
                    t.push('.');
                }
                for _ in 0..digits {
                    t.push(char::from_digit((r.next() % 16) as u32, 16).unwrap());
                }
                if r.next() & 1 == 0 {
                    t.push('/');
                }
                t
            }
            3 => {
                // Mid-byte separators (should reject), uppercase hex.
                format!("{:X}.{:X}", r.byte(), r.byte())
            }
            4 => {
                // Whitespace and 0x prefixes (glibc rejects both).
                let pick = r.next() % 4;
                match pick {
                    0 => "01 23".into(),
                    1 => "0xab".into(),
                    2 => "ab cd".into(),
                    _ => "  ".into(),
                }
            }
            _ => {
                // Random byte soup over the relevant alphabet.
                const ALPHA: &[u8] = b"0123456789abcdefABCDEF.+/ xX\t";
                let len = 1 + (r.next() % 14) as usize;
                let bytes: Vec<u8> = (0..len)
                    .map(|_| ALPHA[(r.next() as usize) % ALPHA.len()])
                    .collect();
                String::from_utf8(bytes).unwrap()
            }
        };
        if let Ok(cs) = CString::new(s.as_str()) {
            // Random output capacity, including tight buffers that truncate.
            let buflen = 1 + (r.next() % 40) as usize;
            let (fln, flb) = call_addr(fl_addr, &cs, buflen);
            let (hon, hob) = call_addr(inet_nsap_addr, &cs, buflen);
            compared += 1;
            if (fln, &flb) != (hon, &hob) && divs.len() < 40 {
                divs.push(format!(
                    "addr src={s:?} buflen={buflen}\n    fl   =n={fln} {flb:02x?}\n    glibc=n={hon} {hob:02x?}"
                ));
            }
        }
    }

    assert!(
        divs.is_empty(),
        "inet_nsap_addr/ntoa diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("inet_nsap fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
