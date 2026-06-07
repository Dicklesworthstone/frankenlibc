#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc c8rtomb oracle (libc, linked by std)

//! Randomized live differential fuzzer for C23 `c8rtomb` (char8_t/UTF-8 ->
//! multibyte) vs host glibc, C.UTF-8 locale. c8rtomb accumulates UTF-8 code
//! units in `ps` and, only when a code unit COMPLETES a valid sequence, writes
//! the multibyte character and returns its byte count; mid-sequence it returns
//! 0, and on an invalid code unit it returns (size_t)-1 / EILSEQ. This feeds the
//! bytes of random UTF-8 strings (plus injected invalid bytes) one char8_t per
//! call with a shared mbstate and compares the (return, bytes-written) sequence.

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_abi::unistd_abi::c8rtomb as fl_c8rtomb;

unsafe extern "C" {
    fn c8rtomb(s: *mut c_char, c8: u8, ps: *mut c_void) -> usize;
    fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
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
    fn below(&mut self, n: u64) -> u64 {
        (self.next() >> 11) % n
    }
}

fn enc(cp: u32, out: &mut Vec<u8>) {
    match cp {
        0..=0x7F => out.push(cp as u8),
        0x80..=0x7FF => {
            out.push(0xC0 | (cp >> 6) as u8);
            out.push(0x80 | (cp & 0x3F) as u8);
        }
        0x800..=0xFFFF => {
            out.push(0xE0 | (cp >> 12) as u8);
            out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
            out.push(0x80 | (cp & 0x3F) as u8);
        }
        _ => {
            out.push(0xF0 | (cp >> 18) as u8);
            out.push(0x80 | ((cp >> 12) & 0x3F) as u8);
            out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
            out.push(0x80 | (cp & 0x3F) as u8);
        }
    }
}

fn gen_cp(r: &mut Lcg) -> u32 {
    let cp = match r.below(4) {
        0 => r.below(0x80) as u32,
        1 => 0x80 + r.below(0x780) as u32,
        2 => 0x800 + r.below(0xF800) as u32,
        _ => 0x10000 + r.below(0x100000) as u32,
    };
    if (0xD800..=0xDFFF).contains(&cp) { 0x41 } else { cp }
}

/// Feed each byte of `bytes` to one c8rtomb implementation with a shared
/// mbstate, returning the (return-as-i64, bytes-written) sequence.
fn drive(
    f: unsafe extern "C" fn(*mut c_char, u8, *mut c_void) -> usize,
    bytes: &[u8],
) -> Vec<(i64, Vec<u8>)> {
    let mut st = [0u8; 16];
    let mut out = Vec::new();
    for &c8 in bytes {
        let mut buf = [0u8; 8];
        let ret =
            unsafe { f(buf.as_mut_ptr() as *mut c_char, c8, st.as_mut_ptr() as *mut c_void) };
        let ri = ret as i64;
        let written = if (1..=4).contains(&ri) {
            buf[..ri as usize].to_vec()
        } else {
            Vec::new()
        };
        out.push((ri, written));
        if ri < 0 {
            break; // EILSEQ: errno/state past here is unspecified
        }
    }
    out
}

#[test]
fn c8rtomb_differential_fuzz_vs_glibc() {
    unsafe { setlocale(libc::LC_ALL, c"C.UTF-8".as_ptr()) };
    let mut r = Lcg(0xc8_1234_5678_9abc);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..100_000 {
        let nchars = 1 + r.below(5);
        let mut bytes = Vec::new();
        for _ in 0..nchars {
            enc(gen_cp(&mut r), &mut bytes);
        }
        if r.below(3) == 0 {
            let extra = 1 + r.below(3);
            for _ in 0..extra {
                bytes.push((0x80 + r.below(0x80)) as u8); // lead/continuation soup
            }
        }
        let fl = drive(fl_c8rtomb, &bytes);
        let host = drive(c8rtomb, &bytes);
        compared += 1;
        if fl != host && divs.len() < 30 {
            divs.push(format!(
                "bytes={:02x?}\n    fl   ={fl:?}\n    glibc={host:?}",
                bytes
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "c8rtomb diverged from host glibc on {} cases (showing up to 30):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("c8rtomb differential fuzz: {compared} strings, 0 divergences vs host glibc");
}
