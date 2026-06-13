#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc swprintf oracle

//! Randomized differential fuzzer for WIDE `swprintf` with NARROW `%s` / `%c`
//! conversions vs host glibc, under a UTF-8 locale.
//!
//! This is the mirror of `printf_wide_string_differential_fuzz` (narrow printf
//! `%ls`). In the WIDE printf family, a `%s` argument is a `char*` whose
//! multibyte content is converted to wide characters, and — per C99 §7.24.2.x —
//! the precision and field width count WIDE CHARACTERS, not bytes. The shared
//! `render_printf` core applies byte-based precision/width to `%s`, which is
//! correct for narrow output but wrong when the same core serves wide output and
//! the `char*` holds multibyte (non-ASCII) text. The swprintf fixed battery only
//! covers `%ls`/`%lc` (wide args), never narrow `%s`/`%c`, so this path was
//! unexercised. Compares the produced wide buffer and the return value.

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::wchar_abi as fl;

type Wc = libc::wchar_t;

unsafe extern "C" {
    fn swprintf(s: *mut Wc, n: usize, format: *const Wc, ...) -> c_int;
    fn setlocale(category: c_int, locale: *const c_char) -> *const c_char;
}
const LC_ALL: c_int = 6;

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 11) as usize % n
    }
}

fn wfmt(s: &str) -> Vec<Wc> {
    let mut v: Vec<Wc> = s.chars().map(|c| c as u32 as Wc).collect();
    v.push(0);
    v
}

fn used(buf: &[Wc], n: c_int) -> Vec<Wc> {
    if n < 0 {
        return Vec::new();
    }
    buf[..(n as usize).min(buf.len())].to_vec()
}

fn to_s(v: &[Wc]) -> String {
    v.iter()
        .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
        .collect()
}

/// A code point of UTF-8 byte width 1, 2, or 3 (never a surrogate).
fn gen_cp(r: &mut Lcg) -> char {
    let v = match r.below(3) {
        0 => 0x41 + r.below(0x39) as u32,
        1 => 0x80 + r.below(0x780) as u32,
        _ => {
            let c = 0x800 + r.below(0xF800) as u32;
            if (0xD800..=0xDFFF).contains(&c) {
                0x4E00
            } else {
                c
            }
        }
    };
    char::from_u32(v).unwrap_or('?')
}

fn gen_utf8(r: &mut Lcg) -> String {
    (0..r.below(7)).map(|_| gen_cp(r)).collect()
}

fn gen_fmt_s(r: &mut Lcg) -> String {
    let mut f = String::from("%");
    if r.below(2) == 0 {
        f.push('-');
    }
    if r.below(2) == 0 {
        f.push_str(&r.below(10).to_string());
    }
    if r.below(2) == 0 {
        f.push('.');
        f.push_str(&r.below(10).to_string());
    }
    f.push('s');
    f
}

#[test]
fn swprintf_narrow_string_differential_fuzz_vs_glibc() {
    let utf8 = CString::new("C.UTF-8").unwrap();
    if unsafe { setlocale(LC_ALL, utf8.as_ptr()) }.is_null() {
        let alt = CString::new("en_US.UTF-8").unwrap();
        if unsafe { setlocale(LC_ALL, alt.as_ptr()) }.is_null() {
            eprintln!("no UTF-8 locale available; skipping wide %s/%c differential");
            return;
        }
    }

    let mut r = Lcg(0x5eed_5113_c0de_0007);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..120_000 {
        // ----- wide printf, narrow %s -----
        let arg = gen_utf8(&mut r);
        let Ok(carg) = CString::new(arg.as_str()) else {
            continue;
        };
        let fmt = gen_fmt_s(&mut r);
        let wf = wfmt(&fmt);
        let mut fb = vec![0 as Wc; 256];
        let mut lb = vec![0 as Wc; 256];
        let nfl = unsafe {
            fl::swprintf(
                fb.as_mut_ptr(),
                256,
                wf.as_ptr(),
                carg.as_ptr() as *const c_char,
            )
        };
        let nlc = unsafe {
            swprintf(
                lb.as_mut_ptr(),
                256,
                wf.as_ptr(),
                carg.as_ptr() as *const c_char,
            )
        };
        compared += 1;
        let (fs, ls) = (used(&fb, nfl), used(&lb, nlc));
        if (nfl != nlc || fs != ls) && divs.len() < 40 {
            divs.push(format!(
                "fmt={fmt:?} arg={arg:?}\n    fl   =(n={nfl}, {:?})\n    glibc=(n={nlc}, {:?})",
                to_s(&fs),
                to_s(&ls)
            ));
        }

        // ----- wide printf, narrow %c (ASCII byte; non-ASCII bytes are btowc
        // WEOF edge cases, out of scope here) -----
        let ch = 0x20 + r.below(0x5f) as c_int; // printable ASCII
        let mut fmt2 = String::from("%");
        if r.below(2) == 0 {
            fmt2.push('-');
        }
        if r.below(2) == 0 {
            fmt2.push_str(&(1 + r.below(8)).to_string());
        }
        fmt2.push('c');
        let wf2 = wfmt(&fmt2);
        let mut fb2 = vec![0 as Wc; 64];
        let mut lb2 = vec![0 as Wc; 64];
        let nfl2 = unsafe { fl::swprintf(fb2.as_mut_ptr(), 64, wf2.as_ptr(), ch) };
        let nlc2 = unsafe { swprintf(lb2.as_mut_ptr(), 64, wf2.as_ptr(), ch) };
        compared += 1;
        let (fs2, ls2) = (used(&fb2, nfl2), used(&lb2, nlc2));
        if (nfl2 != nlc2 || fs2 != ls2) && divs.len() < 40 {
            divs.push(format!(
                "fmt={fmt2:?} ch={ch}\n    fl   =(n={nfl2}, {:?})\n    glibc=(n={nlc2}, {:?})",
                to_s(&fs2),
                to_s(&ls2)
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "swprintf narrow %s/%c diverged from host glibc on some of {compared} cases (up to 40):\n{}",
        divs.join("\n")
    );
    eprintln!("swprintf narrow %s/%c fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
