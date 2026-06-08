#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strptime oracle

//! Randomized differential fuzzer for `strptime`'s conversion PREFIX grammar
//! `%[flags][width][E|O]<spec>` vs host glibc.
//!
//! glibc strptime accepts (and ignores) GNU flags `- _ 0` and a field width
//! before a conversion, and an `E`/`O` locale modifier on a per-specifier subset
//! (a no-op in the C locale; a rejected combination such as `%EH`/`%Oa` is a
//! match failure). fl previously read the byte after `%` as the specifier
//! directly, so any of these prefixes turned a valid directive into a parse
//! failure. This pins fl against glibc over each specifier with random
//! flag/width/modifier prefixes, comparing the match decision, consumed offset,
//! and the parsed `tm` year/mon/mday/hour/min/sec.

use std::ffi::{c_char, c_int};

use frankenlibc_abi::time_abi;

unsafe extern "C" {
    fn setlocale(category: c_int, locale: *const c_char) -> *const c_char;
    fn strptime(s: *const c_char, format: *const c_char, tm: *mut libc::tm) -> *mut c_char;
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

// Each specifier with a standalone input that bare `%<spec>` parses.
const CASES: &[(u8, &str)] = &[
    (b'Y', "1993"),
    (b'C', "19"),
    (b'y', "93"),
    (b'm', "06"),
    (b'd', "08"),
    (b'e', "8"),
    (b'H', "14"),
    (b'I', "02"),
    (b'M', "30"),
    (b'S', "45"),
    (b'j', "100"),
    (b'U', "20"),
    (b'W', "20"),
    (b'V', "20"),
    (b'G', "1993"),
    (b'g', "93"),
    (b'w', "3"),
    (b'u', "3"),
    (b'a', "Mon"),
    (b'A', "Monday"),
    (b'b', "Jun"),
    (b'B', "June"),
    (b'h', "Jun"),
    (b'p', "AM"),
    (b'D', "06/08/93"),
    (b'T', "14:30:45"),
    (b'R', "14:30"),
    (b'F', "1993-06-08"),
    (b'r', "02:30:45 PM"),
    (b'x', "06/08/93"),
    (b'X', "14:30:45"),
    (b'c', "Mon Jun  8 14:30:45 1993"),
];

const FLAGS: &[u8] = b"-_0";

fn fl_run(input: &[u8], fmt: &[u8]) -> Option<(usize, [c_int; 6])> {
    let mut ib = input.to_vec();
    ib.push(0);
    let mut fb = fmt.to_vec();
    fb.push(0);
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let r = unsafe {
        time_abi::strptime(
            ib.as_ptr() as *const c_char,
            fb.as_ptr() as *const c_char,
            &mut tm,
        )
    };
    if r.is_null() {
        return None;
    }
    let consumed = (r as usize) - (ib.as_ptr() as usize);
    Some((
        consumed,
        [
            tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
        ],
    ))
}

fn host_run(input: &[u8], fmt: &[u8]) -> Option<(usize, [c_int; 6])> {
    let mut ib = input.to_vec();
    ib.push(0);
    let mut fb = fmt.to_vec();
    fb.push(0);
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let r = unsafe {
        strptime(
            ib.as_ptr() as *const c_char,
            fb.as_ptr() as *const c_char,
            &mut tm,
        )
    };
    if r.is_null() {
        return None;
    }
    let consumed = (r as usize) - (ib.as_ptr() as usize);
    Some((
        consumed,
        [
            tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
        ],
    ))
}

fn gen_case(r: &mut Lcg) -> (Vec<u8>, Vec<u8>) {
    let (spec, input) = CASES[r.below(CASES.len())];
    let mut fmt = vec![b'%'];
    if r.below(3) == 0 {
        fmt.push(FLAGS[r.below(FLAGS.len())]);
    }
    if r.below(3) == 0 {
        fmt.extend_from_slice(r.below(5).to_string().as_bytes()); // width 0..4
    }
    if r.below(2) == 0 {
        fmt.push(if r.below(2) == 0 { b'E' } else { b'O' });
    }
    fmt.push(spec);
    (fmt, input.as_bytes().to_vec())
}

#[test]
fn strptime_modifier_differential_fuzz_vs_glibc() {
    let c = std::ffi::CString::new("C").unwrap();
    unsafe { setlocale(LC_ALL, c.as_ptr()) };

    let mut r = Lcg(0x70b1_9c0d_e571_0011);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..200_000 {
        let (fmt, input) = gen_case(&mut r);
        let fl = fl_run(&input, &fmt);
        let host = host_run(&input, &fmt);
        compared += 1;
        if fl != host && divs.len() < 40 {
            divs.push(format!(
                "fmt={:?} input={:?}\n    fl   ={:?}\n    glibc={:?}",
                String::from_utf8_lossy(&fmt),
                String::from_utf8_lossy(&input),
                fl,
                host
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "strptime modifier/flag parsing diverged from host glibc on some of {compared} cases (up to 40):\n{}",
        divs.join("\n")
    );
    eprintln!("strptime modifier fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
