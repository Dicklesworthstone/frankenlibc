#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc strfromf oracle (libc, linked by std)

//! Randomized live differential fuzzer for C23 `strfromf` vs host glibc.
//!
//! `strfromd` (f64) already has a randomized fuzzer; its f32 sibling `strfromf`
//! had none. fl implements `strfromf` by widening the `float` argument to `f64`
//! and delegating to `strfromd` — which is only correct if widening-then-format
//! is byte-identical to glibc's native single-precision formatting for EVERY
//! in-spec format. f32 -> f64 widening is exact, so it should be; this fuzzer
//! pins that across the full format matrix (`%{a,A,e,E,f,F,g,G}` with optional
//! `.precision`) over normals, subnormals, ±0 (signbit!), ±inf, nan, and random
//! bit patterns, comparing the rendered string AND the returned length
//! byte-for-byte. `strfroml` takes an 80-bit `long double`, which the Rust ABI
//! cannot pass, so it is out of scope here.

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::string_abi::strfromf as fl_strfromf;

unsafe extern "C" {
    fn strfromf(s: *mut c_char, n: usize, format: *const c_char, value: f32) -> c_int;
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

#[derive(PartialEq, Eq, Debug)]
struct Out {
    ret: c_int,
    s: String,
}

fn run(
    f: unsafe extern "C" fn(*mut c_char, usize, *const c_char, f32) -> c_int,
    fmt: &CString,
    v: f32,
) -> Out {
    let mut buf = [0u8; 1024];
    let ret = unsafe { f(buf.as_mut_ptr() as *mut c_char, buf.len(), fmt.as_ptr(), v) };
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Out {
        ret,
        s: String::from_utf8_lossy(&buf[..n]).into_owned(),
    }
}

/// An in-spec strfromf format: `%` + optional `.precision` + one of aAeEfFgG.
fn gen_format(r: &mut Lcg) -> String {
    const SPEC: &[u8] = b"aAeEfFgG";
    let mut f = String::from("%");
    if r.below(3) != 0 {
        f.push('.');
        f.push_str(&r.below(25).to_string()); // precision 0..24
    }
    f.push(SPEC[r.below(SPEC.len())] as char);
    f
}

/// A wide spread of f32 values, including the awkward ones.
fn gen_value(r: &mut Lcg) -> f32 {
    match r.below(10) {
        0 => 0.0,
        1 => -0.0,
        2 => f32::INFINITY,
        3 => f32::NEG_INFINITY,
        4 => f32::NAN,
        5 => f32::from_bits(r.next() as u32), // any bit pattern (incl. subnormals/nan)
        6 => (r.below(1_000_000) as f32) / 100.0, // nice 2-decimal
        7 => (r.below(1 << 18) as f32) / (1u32 << 10) as f32, // exact binary fractions (ties)
        8 => f32::from_bits((r.next() as u32 & 0x007f_ffff) | 0x0000_0001), // subnormal-ish
        _ => {
            let m = (r.below(1_000_000_000) as f32) / 1000.0;
            if r.next() & 1 == 0 { -m } else { m }
        }
    }
}

#[test]
fn strfromf_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x5f3f_100f_2bad_c0de);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..200_000 {
        let fmt = gen_format(&mut r);
        let v = gen_value(&mut r);
        let cf = CString::new(fmt.as_str()).unwrap();
        let fl = run(fl_strfromf, &cf, v);
        let host = run(strfromf, &cf, v);
        compared += 1;
        if fl != host && divs.len() < 40 {
            divs.push(format!(
                "fmt={fmt:?} v={v:?} (bits={:#010x})\n    fl   ={fl:?}\n    glibc={host:?}",
                v.to_bits()
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "strfromf diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("strfromf differential fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
