#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wcstod/wcstof oracle

//! Randomized differential fuzzer for the wide-char float parsers `wcstod` /
//! `wcstof` vs a LIVE host glibc oracle.
//!
//! The fixed battery in `conformance_diff_wchar.rs` (`diff_wcstod_cases`) pins
//! ~15 hand-picked inputs. This fuzzer randomizes the input shape to reach the
//! edges that battery cannot: variable-width mantissa/exponent, hex floats,
//! `inf`/`infinity`/`nan(payload)` case variants, leading-whitespace variety,
//! trailing garbage, and — crucially — NON-ASCII wide chars injected mid-string.
//!
//! The fl path projects the wide buffer to ASCII (`project_wide_ascii`, which
//! stops at the first code point > 0x7F) and delegates to the byte
//! `strtod_impl`/`strtof_impl`, then maps the consumed count back to an `endptr`
//! in wide units. glibc's `wcstod` scans wide chars directly; in the C locale it
//! recognizes only the ASCII numeric grammar, so a non-ASCII code point must
//! terminate the scan at exactly the same offset. We compare the f64/f32 return
//! bit-pattern (NaN-insensitive: both-NaN counts as equal) AND the consumed
//! `endptr` offset, which is where a projection/boundary bug would surface.

use std::ffi::{c_char, c_int};

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn wcstod(nptr: *const libc::wchar_t, endptr: *mut *mut libc::wchar_t) -> f64;
    fn wcstof(nptr: *const libc::wchar_t, endptr: *mut *mut libc::wchar_t) -> f32;
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
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn ptr_off(base: *const libc::wchar_t, end: *const libc::wchar_t) -> isize {
    let stride = std::mem::size_of::<libc::wchar_t>() as isize;
    ((end as isize) - (base as isize)) / stride
}

/// Build a NUL-terminated wide buffer (`libc::wchar_t` is `i32` on Linux).
fn wide_buf(chars: &[i32]) -> Vec<libc::wchar_t> {
    let mut v: Vec<libc::wchar_t> = chars.to_vec();
    v.push(0);
    v
}

/// Push an ASCII string as code points.
fn push_ascii(v: &mut Vec<i32>, s: &str) {
    for b in s.bytes() {
        v.push(b as i32);
    }
}

fn digits(r: &mut Lcg, max: u64) -> String {
    let n = r.below(max + 1);
    let mut s = String::new();
    for _ in 0..n {
        s.push((b'0' + r.below(10) as u8) as char);
    }
    s
}

fn hex_digits(r: &mut Lcg, max: u64) -> String {
    const H: &[u8] = b"0123456789abcdefABCDEF";
    let n = r.below(max + 1);
    let mut s = String::new();
    for _ in 0..n {
        s.push(H[r.below(H.len() as u64) as usize] as char);
    }
    s
}

fn maybe_ws(r: &mut Lcg, v: &mut Vec<i32>) {
    match r.below(5) {
        0 => push_ascii(v, " "),
        1 => push_ascii(v, "  "),
        2 => push_ascii(v, "\t "),
        3 => push_ascii(v, "\n"),
        _ => {}
    }
}

fn maybe_sign(r: &mut Lcg, v: &mut Vec<i32>) {
    match r.below(4) {
        0 => push_ascii(v, "+"),
        1 => push_ascii(v, "-"),
        _ => {}
    }
}

/// Non-ASCII code points whose presence must terminate a C-locale numeric scan.
/// Includes a fullwidth digit (U+FF10) and Arabic-Indic zero (U+0660) — these
/// are *digits* in Unicode but NOT in the C locale, so glibc must stop at them.
const NON_ASCII: &[i32] = &[
    0x00A0, // NBSP
    0x0660, // Arabic-Indic digit zero
    0x2003, // EM SPACE
    0x3000, // ideographic space
    0xFF10, // fullwidth digit zero
    0x00B2, // superscript two
    0x0301, // combining acute
    0x20AC, // euro sign
];

fn gen_case(r: &mut Lcg) -> Vec<i32> {
    let mut v: Vec<i32> = Vec::new();
    match r.below(10) {
        0..=2 => {
            // Decimal float with variable mantissa/exponent.
            maybe_ws(r, &mut v);
            maybe_sign(r, &mut v);
            let int_part = digits(r, 20);
            push_ascii(&mut v, &int_part);
            if r.below(2) == 0 {
                push_ascii(&mut v, ".");
                push_ascii(&mut v, &digits(r, 20));
            }
            // Ensure at least one digit usually; sometimes leave it degenerate.
            if int_part.is_empty() && r.below(2) == 0 {
                push_ascii(&mut v, &digits(r, 3));
            }
            if r.below(2) == 0 {
                push_ascii(&mut v, if r.below(2) == 0 { "e" } else { "E" });
                maybe_sign(r, &mut v);
                // wide exponent range to hit overflow -> inf and underflow -> 0.
                let exp = r.below(400);
                push_ascii(&mut v, &exp.to_string());
            }
        }
        3 | 4 => {
            // Hex float.
            maybe_ws(r, &mut v);
            maybe_sign(r, &mut v);
            push_ascii(&mut v, if r.below(2) == 0 { "0x" } else { "0X" });
            push_ascii(&mut v, &hex_digits(r, 14));
            if r.below(2) == 0 {
                push_ascii(&mut v, ".");
                push_ascii(&mut v, &hex_digits(r, 14));
            }
            if r.below(3) != 0 {
                push_ascii(&mut v, if r.below(2) == 0 { "p" } else { "P" });
                maybe_sign(r, &mut v);
                push_ascii(&mut v, &r.below(80).to_string());
            }
        }
        5 => {
            // inf / infinity with case variation.
            maybe_ws(r, &mut v);
            maybe_sign(r, &mut v);
            let word = if r.below(2) == 0 { "inf" } else { "infinity" };
            for (i, b) in word.bytes().enumerate() {
                let c = if (r.next() >> (i & 31)) & 1 == 0 {
                    b.to_ascii_uppercase()
                } else {
                    b
                };
                v.push(c as i32);
            }
        }
        6 => {
            // nan with optional (n-char-sequence) payload.
            maybe_ws(r, &mut v);
            maybe_sign(r, &mut v);
            push_ascii(&mut v, if r.below(2) == 0 { "nan" } else { "NAN" });
            if r.below(2) == 0 {
                push_ascii(&mut v, "(");
                // payload chars: alnum + underscore
                let n = r.below(6);
                for _ in 0..n {
                    let pick = r.below(3);
                    let c = match pick {
                        0 => b'0' + r.below(10) as u8,
                        1 => b'a' + r.below(26) as u8,
                        _ => b'_',
                    };
                    v.push(c as i32);
                }
                if r.below(4) != 0 {
                    push_ascii(&mut v, ")");
                }
            }
        }
        7 => {
            // Degenerate / garbage: lone sign, lone dot, letters, empty.
            match r.below(5) {
                0 => push_ascii(&mut v, "+"),
                1 => push_ascii(&mut v, "."),
                2 => push_ascii(&mut v, "-.e"),
                3 => push_ascii(&mut v, "abc"),
                _ => {}
            }
        }
        _ => {
            // A normal-ish float, then trailing garbage (tests endptr cutoff).
            maybe_sign(r, &mut v);
            push_ascii(&mut v, &digits(r, 8));
            push_ascii(&mut v, ".");
            push_ascii(&mut v, &digits(r, 8));
            // trailing letters/punct
            let tail = *b"abxpe.-";
            let n = r.below(4);
            for _ in 0..n {
                v.push(tail[r.below(tail.len() as u64) as usize] as i32);
            }
        }
    }

    // Occasionally inject a non-ASCII wide char at a random position. This is the
    // edge the byte-string oracle cannot reach: glibc must terminate the scan at
    // the non-ASCII code point, and fl's endptr must land on the same offset.
    if r.below(3) == 0 {
        let cp = NON_ASCII[r.below(NON_ASCII.len() as u64) as usize];
        let pos = if v.is_empty() {
            0
        } else {
            r.below(v.len() as u64 + 1) as usize
        };
        v.insert(pos, cp);
    }

    v
}

fn run_pair_d(chars: &[i32]) -> ((u64, isize), (u64, isize)) {
    let buf = wide_buf(chars);
    let p = buf.as_ptr();
    let mut fl_end: *mut libc::wchar_t = std::ptr::null_mut();
    let mut lc_end: *mut libc::wchar_t = std::ptr::null_mut();
    let fl_v = unsafe { fl::wcstod(p as *const libc::wchar_t, &mut fl_end) };
    let lc_v = unsafe { wcstod(p as *const libc::wchar_t, &mut lc_end) };
    (
        (fl_v.to_bits(), ptr_off(p, fl_end)),
        (lc_v.to_bits(), ptr_off(p, lc_end)),
    )
}

fn run_pair_f(chars: &[i32]) -> ((u32, isize), (u32, isize)) {
    let buf = wide_buf(chars);
    let p = buf.as_ptr();
    let mut fl_end: *mut libc::wchar_t = std::ptr::null_mut();
    let mut lc_end: *mut libc::wchar_t = std::ptr::null_mut();
    let fl_v = unsafe { fl::wcstof(p as *const libc::wchar_t, &mut fl_end) };
    let lc_v = unsafe { wcstof(p as *const libc::wchar_t, &mut lc_end) };
    (
        (fl_v.to_bits(), ptr_off(p, fl_end)),
        (lc_v.to_bits(), ptr_off(p, lc_end)),
    )
}

fn render(chars: &[i32]) -> String {
    let mut s = String::new();
    for &c in chars {
        if (0x20..0x7f).contains(&c) {
            s.push(c as u8 as char);
        } else {
            s.push_str(&format!("\\u{{{c:04x}}}"));
        }
    }
    s
}

#[test]
fn wcstod_wide_differential_fuzz_vs_glibc() {
    // C locale: numeric grammar is ASCII-only; decimal point is '.'.
    let c = std::ffi::CString::new("C").unwrap();
    unsafe { setlocale(LC_ALL, c.as_ptr()) };

    let mut r = Lcg(0x9e37_79b9_7f4a_7c15);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..250_000 {
        let chars = gen_case(&mut r);
        compared += 1;

        // wcstod (f64)
        let (fl, lc) = run_pair_d(&chars);
        let val_ok =
            fl.0 == lc.0 || (f64::from_bits(fl.0).is_nan() && f64::from_bits(lc.0).is_nan());
        if (!val_ok || fl.1 != lc.1) && divs.len() < 40 {
            divs.push(format!(
                "wcstod input={:?}\n    fl   =(bits={:#018x} off={})\n    glibc=(bits={:#018x} off={})",
                render(&chars),
                fl.0,
                fl.1,
                lc.0,
                lc.1
            ));
        }

        // wcstof (f32)
        let (fl2, lc2) = run_pair_f(&chars);
        let val_ok2 =
            fl2.0 == lc2.0 || (f32::from_bits(fl2.0).is_nan() && f32::from_bits(lc2.0).is_nan());
        if (!val_ok2 || fl2.1 != lc2.1) && divs.len() < 40 {
            divs.push(format!(
                "wcstof input={:?}\n    fl   =(bits={:#010x} off={})\n    glibc=(bits={:#010x} off={})",
                render(&chars),
                fl2.0,
                fl2.1,
                lc2.0,
                lc2.1
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "wide float parser diverged from host glibc on some of {compared} cases (showing up to 40):\n{}",
        divs.join("\n")
    );
    eprintln!("wcstod/wcstof wide fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
