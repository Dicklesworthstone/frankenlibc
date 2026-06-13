#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc snprintf oracle

//! Randomized differential fuzzer for narrow `snprintf` `%ls` (wide string) and
//! `%lc` (wide char) vs host glibc, under a UTF-8 locale.
//!
//! No existing printf fuzzer exercises `%ls`/`%lc`. fl converts the wide
//! argument to UTF-8 in the ABI layer; the open question is whether its
//! field-WIDTH and PRECISION semantics match glibc. Per C99 §7.19.6.1, `%ls`
//! precision is a BYTE limit on the converted multibyte output (no partial
//! multibyte character), and the field width is likewise a byte count — NOT a
//! wide-character count. This pins fl against glibc over mixed-width code points
//! (1/2/3-byte UTF-8) with random width / precision / left-justify, comparing
//! the rendered bytes and the return value.

use std::ffi::{CString, c_char, c_int, c_uint};

use frankenlibc_abi::stdio_abi::snprintf as fl_snprintf;

unsafe extern "C" {
    fn snprintf(s: *mut c_char, n: usize, fmt: *const c_char, ...) -> c_int;
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

fn buf_used(b: &[u8]) -> Vec<u8> {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    b[..n].to_vec()
}

/// A code point of a chosen UTF-8 byte width (1, 2, or 3) — never a surrogate.
fn gen_cp(r: &mut Lcg) -> u32 {
    match r.below(3) {
        0 => 0x41 + r.below(0x39) as u32,  // 1-byte ASCII A..z-ish
        1 => 0x80 + r.below(0x780) as u32, // 2-byte U+0080..U+07FF
        _ => {
            // 3-byte U+0800..U+FFFF, skipping the surrogate range.
            let v = 0x800 + r.below(0xF800) as u32;
            if (0xD800..=0xDFFF).contains(&v) {
                0x4E00
            } else {
                v
            }
        }
    }
}

fn gen_wide(r: &mut Lcg) -> Vec<libc::wchar_t> {
    let n = r.below(7);
    let mut v: Vec<libc::wchar_t> = (0..n).map(|_| gen_cp(r) as libc::wchar_t).collect();
    v.push(0);
    v
}

fn gen_format_ls(r: &mut Lcg) -> String {
    let mut f = String::from("%");
    if r.below(2) == 0 {
        f.push('-');
    }
    if r.below(2) == 0 {
        f.push_str(&r.below(10).to_string()); // width 0..9
    }
    if r.below(2) == 0 {
        f.push('.');
        f.push_str(&r.below(10).to_string()); // precision 0..9 (BYTES)
    }
    f.push_str("ls");
    f
}

fn gen_format_lc(r: &mut Lcg) -> String {
    let mut f = String::from("%");
    if r.below(2) == 0 {
        f.push('-');
    }
    if r.below(2) == 0 {
        f.push_str(&(1 + r.below(8)).to_string()); // width 1..8
    }
    f.push_str("lc");
    f
}

#[test]
fn printf_wide_string_differential_fuzz_vs_glibc() {
    // %ls/%lc multibyte encoding is locale-defined; fl encodes UTF-8, so match
    // the host to a UTF-8 locale. Skip the test if none is available.
    let utf8 = CString::new("C.UTF-8").unwrap();
    let got = unsafe { setlocale(LC_ALL, utf8.as_ptr()) };
    if got.is_null() {
        let alt = CString::new("en_US.UTF-8").unwrap();
        let got2 = unsafe { setlocale(LC_ALL, alt.as_ptr()) };
        if got2.is_null() {
            eprintln!("no UTF-8 locale available; skipping %ls/%lc differential");
            return;
        }
    }

    let mut r = Lcg(0x7c0d_e15a_b1e2_0006);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..120_000 {
        // ----- %ls -----
        let ws = gen_wide(&mut r);
        let fmt = gen_format_ls(&mut r);
        let cf = CString::new(fmt.as_str()).unwrap();
        let mut bfl = vec![0u8; 256];
        let mut blc = vec![0u8; 256];
        let nfl = unsafe {
            fl_snprintf(
                bfl.as_mut_ptr() as *mut c_char,
                bfl.len(),
                cf.as_ptr(),
                ws.as_ptr(),
            )
        };
        let nlc = unsafe {
            snprintf(
                blc.as_mut_ptr() as *mut c_char,
                blc.len(),
                cf.as_ptr(),
                ws.as_ptr(),
            )
        };
        compared += 1;
        let (sfl, slc) = (buf_used(&bfl), buf_used(&blc));
        if (nfl != nlc || sfl != slc) && divs.len() < 40 {
            let wstr: String = ws[..ws.len() - 1]
                .iter()
                .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
                .collect();
            divs.push(format!(
                "fmt={fmt:?} ws={wstr:?}\n    fl   =(n={nfl}, {:?})\n    glibc=(n={nlc}, {:?})",
                String::from_utf8_lossy(&sfl),
                String::from_utf8_lossy(&slc),
            ));
        }

        // ----- %lc -----
        let cp = gen_cp(&mut r);
        let fmt2 = gen_format_lc(&mut r);
        let cf2 = CString::new(fmt2.as_str()).unwrap();
        let mut bfl2 = vec![0u8; 256];
        let mut blc2 = vec![0u8; 256];
        let wc = cp as c_uint;
        let nfl2 = unsafe {
            fl_snprintf(
                bfl2.as_mut_ptr() as *mut c_char,
                bfl2.len(),
                cf2.as_ptr(),
                wc,
            )
        };
        let nlc2 = unsafe {
            snprintf(
                blc2.as_mut_ptr() as *mut c_char,
                blc2.len(),
                cf2.as_ptr(),
                wc,
            )
        };
        compared += 1;
        let (sfl2, slc2) = (buf_used(&bfl2), buf_used(&blc2));
        if (nfl2 != nlc2 || sfl2 != slc2) && divs.len() < 40 {
            divs.push(format!(
                "fmt={fmt2:?} cp=U+{cp:04X}\n    fl   =(n={nfl2}, {:?})\n    glibc=(n={nlc2}, {:?})",
                String::from_utf8_lossy(&sfl2),
                String::from_utf8_lossy(&slc2),
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "snprintf %ls/%lc diverged from host glibc on some of {compared} cases (up to 40):\n{}",
        divs.join("\n")
    );
    eprintln!("printf %ls/%lc fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
