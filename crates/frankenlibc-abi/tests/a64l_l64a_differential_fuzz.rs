#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc a64l/l64a oracle

//! Randomized differential fuzzer for the SVID radix-64 long codec `a64l` /
//! `l64a` vs host glibc. The fixed batteries (`diff_a64l_cases` /
//! `diff_l64a_cases`) pin the documented edges; this sweeps the parts they don't
//! reach: a64l over strings that mix VALID alphabet chars with INVALID ones (so
//! the "stop at the first non-alphabet character" rule and the 6-character cap
//! are exercised at random positions), and l64a over the full `c_long` range
//! including negatives and values straddling the 2^32 low-word boundary.

use std::ffi::{CString, c_char, c_long};

use frankenlibc_abi::stdlib_abi as fl;

unsafe extern "C" {
    fn a64l(s: *const c_char) -> c_long;
    fn l64a(value: c_long) -> *mut c_char;
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
    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 11) as usize % n
    }
}

// The 64 valid radix-64 digits plus a spread of INVALID bytes that must
// terminate an a64l scan.
const VALID: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const INVALID: &[u8] = b":;<=>?@[\\]^_`{|}~! #$%&*+,-";

fn gen_a64l_input(r: &mut Lcg) -> Vec<u8> {
    let len = r.below(10); // 0..9 chars — past the 6-char cap
    (0..len)
        .map(|_| {
            // ~25% invalid so the stop-at-invalid rule is hit mid-string.
            if r.below(4) == 0 {
                INVALID[r.below(INVALID.len())]
            } else {
                VALID[r.below(VALID.len())]
            }
        })
        .collect()
}

fn host_l64a_str(v: c_long) -> Vec<u8> {
    // l64a writes to a static buffer; copy immediately.
    let p = unsafe { l64a(v) };
    if p.is_null() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 0isize;
    loop {
        let b = unsafe { *p.offset(i) } as u8;
        if b == 0 {
            break;
        }
        out.push(b);
        i += 1;
    }
    out
}

fn fl_l64a_str(v: c_long) -> Vec<u8> {
    let p = unsafe { fl::l64a(v) };
    if p.is_null() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 0isize;
    loop {
        let b = unsafe { *p.offset(i) } as u8;
        if b == 0 {
            break;
        }
        out.push(b);
        i += 1;
    }
    out
}

#[test]
fn a64l_l64a_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x6a17_b64a_c0de_0013);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..200_000 {
        // ---- a64l ----
        let input = gen_a64l_input(&mut r);
        if let Ok(cs) = CString::new(input.clone()) {
            let fl_v = unsafe { fl::a64l(cs.as_ptr() as *const c_char) };
            let lc_v = unsafe { a64l(cs.as_ptr() as *const c_char) };
            compared += 1;
            if fl_v != lc_v && divs.len() < 40 {
                divs.push(format!(
                    "a64l({:?}): fl={fl_v} glibc={lc_v}",
                    String::from_utf8_lossy(&input)
                ));
            }
        }

        // ---- l64a ----
        let v = match r.below(4) {
            0 => r.next() as i64,                      // any 64-bit pattern
            1 => -((r.next() % 0x1_0000_0000) as i64), // negatives
            2 => (r.next() % 0x1_0000_0008) as i64,    // around the 2^32 boundary
            _ => r.below(70) as i64,                   // small values
        };
        let fl_s = fl_l64a_str(v);
        let lc_s = host_l64a_str(v);
        compared += 1;
        if fl_s != lc_s && divs.len() < 40 {
            divs.push(format!(
                "l64a({v}): fl={:?} glibc={:?}",
                String::from_utf8_lossy(&fl_s),
                String::from_utf8_lossy(&lc_s)
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "a64l/l64a diverged from host glibc on some of {compared} cases (up to 40):\n{}",
        divs.join("\n")
    );
    eprintln!("a64l/l64a fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
