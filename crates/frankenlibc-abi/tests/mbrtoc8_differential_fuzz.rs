#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc mbrtoc8 oracle (libc, linked by std)

//! Randomized live differential fuzzer for C23 `mbrtoc8` (multibyte -> char8_t,
//! UTF-8) vs host glibc, C.UTF-8 locale. mbrtoc8 converts ONE multibyte
//! character per "logical" step but emits its UTF-8 bytes one char8_t at a time:
//! the first call for a char consumes all its input bytes (return = count) and
//! stores the remaining output bytes, which subsequent calls return as
//! (size_t)-3 without consuming input. This drives the full conversion of random
//! UTF-8 strings through both implementations and compares the (return, char8)
//! sequence plus input advancement.

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_abi::unistd_abi::mbrtoc8 as fl_mbrtoc8;

unsafe extern "C" {
    fn mbrtoc8(pc8: *mut u8, s: *const c_char, n: usize, ps: *mut c_void) -> usize;
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
    if (0xD800..=0xDFFF).contains(&cp) {
        0x41
    } else {
        cp
    }
}

/// Drive a full mbrtoc8 conversion over `bytes`, returning the (return-as-i64,
/// char8) sequence. Feeds the whole remaining buffer each call (so -2 only
/// occurs at a genuinely truncated tail).
fn drive(
    f: unsafe extern "C" fn(*mut u8, *const c_char, usize, *mut c_void) -> usize,
    bytes: &[u8],
) -> Vec<(i64, u8)> {
    let mut st = [0u8; 16];
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut guard = 0;
    loop {
        guard += 1;
        if guard > 10_000 {
            break;
        }
        let mut c8: u8 = 0;
        let remaining = &bytes[i..];
        let ret = unsafe {
            f(
                &mut c8,
                remaining.as_ptr() as *const c_char,
                remaining.len(),
                st.as_mut_ptr() as *mut c_void,
            )
        };
        let ri = ret as i64;
        out.push((ri, c8));
        match ri {
            -3 => {}     // buffered output byte; no input consumed
            -2 => break, // incomplete tail
            -1 => break, // EILSEQ
            0 => break,  // NUL
            k if k > 0 => i += k as usize,
            _ => break,
        }
        if i >= bytes.len() {
            break;
        }
    }
    out
}

#[test]
fn mbrtoc8_differential_fuzz_vs_glibc() {
    unsafe { setlocale(libc::LC_ALL, c"C.UTF-8".as_ptr()) };
    let mut r = Lcg(0xc8de_ad08_1122_3344);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..100_000 {
        let nchars = 1 + r.below(5);
        let mut bytes = Vec::new();
        for _ in 0..nchars {
            enc(gen_cp(&mut r), &mut bytes);
        }
        // Sometimes append raw (often invalid/truncated) bytes to exercise the
        // EILSEQ and incomplete-tail paths against the oracle.
        if r.below(3) == 0 {
            let extra = 1 + r.below(3);
            for _ in 0..extra {
                bytes.push((0x80 + r.below(0x80)) as u8); // lead/continuation soup
            }
        }
        let fl = drive(fl_mbrtoc8, &bytes);
        let host = drive(mbrtoc8, &bytes);
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
        "mbrtoc8 diverged from host glibc on {} cases (showing up to 30):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("mbrtoc8 differential fuzz: {compared} strings, 0 divergences vs host glibc");
}
