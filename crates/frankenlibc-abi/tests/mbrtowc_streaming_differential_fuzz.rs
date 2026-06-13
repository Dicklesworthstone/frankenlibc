#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc mbrtowc oracle (libc, linked by std)

//! Randomized live differential fuzzer for `mbrtowc` fed a multibyte stream in
//! SMALL CHUNKS with a shared `mbstate_t`, vs host glibc (C.UTF-8). POSIX
//! requires mbrtowc to store an incomplete multibyte sequence in `ps` and resume
//! from it on the next call; this exercises exactly that — random UTF-8 strings
//! consumed 1..=2 bytes per call — and compares the full (return, wide-char)
//! sequence against glibc.

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_abi::wchar_abi::mbrtowc as fl_mbrtowc;

unsafe extern "C" {
    fn mbrtowc(pwc: *mut libc::wchar_t, s: *const c_char, n: usize, ps: *mut c_void) -> usize;
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

/// Encode a code point to UTF-8.
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

/// A random valid (non-surrogate, in-range) code point biased toward multibyte.
fn gen_cp(r: &mut Lcg) -> u32 {
    let cp = match r.below(4) {
        0 => r.below(0x80) as u32,
        1 => 0x80 + r.below(0x780) as u32,
        2 => 0x800 + r.below(0xF800) as u32,
        _ => 0x10000 + r.below(0x100000) as u32,
    };
    // Skip surrogates (not valid scalar values).
    if (0xD800..=0xDFFF).contains(&cp) {
        0x41
    } else {
        cp
    }
}

/// Feed `bytes` to one mbrtowc implementation in chunks of 1..=2 bytes with a
/// shared mbstate, returning the sequence of (return-as-i64, wide-char-or-(-1)).
fn stream(
    f: unsafe extern "C" fn(*mut libc::wchar_t, *const c_char, usize, *mut c_void) -> usize,
    bytes: &[u8],
    r: &mut Lcg,
) -> Vec<(i64, i64)> {
    let mut st = [0u8; 16];
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut guard = 0;
    while i < bytes.len() {
        guard += 1;
        if guard > 100_000 {
            break;
        }
        let chunk = (1 + r.below(2) as usize).min(bytes.len() - i);
        let mut wc: libc::wchar_t = 0;
        let ret = unsafe {
            f(
                &mut wc,
                bytes[i..].as_ptr() as *const c_char,
                chunk,
                st.as_mut_ptr() as *mut c_void,
            )
        };
        let ri = ret as i64;
        let wc_field = if ri >= 0 { wc as i64 } else { -1 };
        out.push((ri, wc_field));
        match ri {
            -2 => i += chunk, // incomplete: whole chunk consumed
            -1 => break,      // EILSEQ: stop (errno state differs)
            0 => break,       // NUL
            k if k >= 0 => i += k as usize,
            _ => break,
        }
    }
    out
}

#[test]
fn mbrtowc_streaming_differential_fuzz_vs_glibc() {
    unsafe { setlocale(libc::LC_ALL, c"C.UTF-8".as_ptr()) };
    let mut r = Lcg(0x6d62_7257_4321_8765);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..50_000 {
        // Build a short random UTF-8 string.
        let nchars = 1 + r.below(5);
        let mut bytes = Vec::new();
        for _ in 0..nchars {
            enc(gen_cp(&mut r), &mut bytes);
        }
        // Two independent chunk schedules (one per impl) would diverge in chunk
        // sizes; use a fixed schedule so both libs see identical call shapes.
        let mut r_fl = Lcg(0xabcd_0000 ^ compared);
        let mut r_host = Lcg(0xabcd_0000 ^ compared);
        let fl = stream(fl_mbrtowc, &bytes, &mut r_fl);
        let host = stream(mbrtowc, &bytes, &mut r_host);
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
        "mbrtowc streaming diverged from host glibc on {} cases (showing up to 30):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!(
        "mbrtowc streaming differential fuzz: {compared} strings, 0 divergences vs host glibc"
    );
}
