#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc swscanf oracle

//! Randomized differential fuzzer for WIDE `swscanf` with NARROW `%s` / `%c`
//! conversions vs host glibc, under a UTF-8 locale.
//!
//! `%s`/`%c` (no `l`) in the wide scanf family read WIDE input characters and
//! convert each to a multibyte sequence stored into a `char*`. The field width
//! counts WIDE INPUT CHARACTERS, not output bytes. fl converts the wide input to
//! UTF-8 and runs the narrow scanf core, so a `%Ns`/`%Nc` width risks being
//! applied as a BYTE count over the multibyte text. The swscanf battery only
//! covers `%ls`/`%lc` (wide-arg) and never narrow `%s`/`%c`, so this path was
//! unexercised. Both output buffers are pre-filled with a sentinel and compared
//! in full (covers the no-NUL `%c` case too) alongside the return value.

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::wchar_abi as fl;

type Wc = libc::wchar_t;

unsafe extern "C" {
    fn swscanf(s: *const Wc, format: *const Wc, ...) -> c_int;
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

/// A code point of UTF-8 byte width 1, 2, or 3 (never a surrogate). Unicode
/// whitespace IS allowed: in a wide scanf stream glibc bounds `%s` tokens and
/// skips leading whitespace with `iswspace` (U+2003, U+205F, U+3000, …), and fl
/// now matches that (bd-xu09cn), so an interior/leading wide-space must terminate
/// or be skipped identically on both sides.
fn gen_cp(r: &mut Lcg) -> char {
    loop {
        let v = match r.below(4) {
            0 => 0x41 + r.below(0x39) as u32, // A..z-ish
            1 => 0x80 + r.below(0x780) as u32,
            2 => {
                let c = 0x800 + r.below(0xF800) as u32;
                if (0xD800..=0xDFFF).contains(&c) {
                    0x4E00
                } else {
                    c
                }
            }
            // Bias toward Unicode whitespace so token boundaries get exercised.
            _ => *[
                0x2003u32, 0x205F, 0x3000, 0x00A0, 0x2009, 0x1680, 0x202F, 0x0085,
            ]
            .get(r.below(8))
            .unwrap_or(&0x2003),
        };
        if let Some(c) = char::from_u32(v) {
            return c;
        }
    }
}

fn gen_wide_input(r: &mut Lcg) -> Vec<Wc> {
    // 1..6 non-whitespace chars, optionally followed by whitespace + a few more.
    let mut s: String = (0..(1 + r.below(6))).map(|_| gen_cp(r)).collect();
    if r.below(2) == 0 {
        s.push(' ');
        for _ in 0..r.below(4) {
            s.push(gen_cp(r));
        }
    }
    let mut v: Vec<Wc> = s.chars().map(|c| c as u32 as Wc).collect();
    v.push(0);
    v
}

#[test]
fn swscanf_narrow_string_differential_fuzz_vs_glibc() {
    let utf8 = CString::new("C.UTF-8").unwrap();
    if unsafe { setlocale(LC_ALL, utf8.as_ptr()) }.is_null() {
        let alt = CString::new("en_US.UTF-8").unwrap();
        if unsafe { setlocale(LC_ALL, alt.as_ptr()) }.is_null() {
            eprintln!("no UTF-8 locale; skipping swscanf narrow %s/%c differential");
            return;
        }
    }

    let mut r = Lcg(0xab1e_5caf_f01d_0008);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..120_000 {
        let inp = gen_wide_input(&mut r);

        // Choose %s or %c with an optional field width.
        let is_char = r.below(2) == 0;
        let width = if r.below(2) == 0 {
            Some(1 + r.below(6))
        } else {
            None
        };
        let fmt_s = match (is_char, width) {
            (false, None) => "%s".to_string(),
            (false, Some(w)) => format!("%{w}s"),
            (true, None) => "%c".to_string(),
            (true, Some(w)) => format!("%{w}c"),
        };
        let wf = wfmt(&fmt_s);

        // Pre-fill both output buffers with a sentinel so a full-buffer compare
        // catches the no-NUL %c case and any over/under-write.
        let mut fb = vec![0xCDu8; 64];
        let mut lb = vec![0xCDu8; 64];
        let nfl = unsafe { fl::swscanf(inp.as_ptr(), wf.as_ptr(), fb.as_mut_ptr() as *mut c_char) };
        let nlc = unsafe { swscanf(inp.as_ptr(), wf.as_ptr(), lb.as_mut_ptr() as *mut c_char) };
        compared += 1;
        if (nfl != nlc || fb != lb) && divs.len() < 40 {
            let ins: String = inp[..inp.len() - 1]
                .iter()
                .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
                .collect();
            divs.push(format!(
                "fmt={fmt_s:?} in={ins:?}\n    fl   =(n={nfl}, {:?})\n    glibc=(n={nlc}, {:?})",
                String::from_utf8_lossy(&fb),
                String::from_utf8_lossy(&lb),
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "swscanf narrow %s/%c diverged from host glibc on some of {compared} cases (up to 40):\n{}",
        divs.join("\n")
    );
    eprintln!("swscanf narrow %s/%c fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
