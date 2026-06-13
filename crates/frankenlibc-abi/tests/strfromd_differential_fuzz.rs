#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc strfromd oracle (libc, linked by std)

//! Randomized live differential fuzzer for C23 `strfromd` vs host glibc. The
//! existing conformance_diff_string_mut test is fixed-case; this sweeps the
//! in-spec format set (`%{a,A,e,E,f,F,g,G}` with an optional `.precision`) over a
//! wide range of f64 values — normals, subnormals, ±0, ±inf, nan, huge/tiny, and
//! round-half-even ties — comparing the rendered string AND the returned length
//! byte-for-byte. strfromd is stateless (output to a caller buffer, value by
//! value, no shared globals or heap handoff), so the live differential is clean.

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::string_abi::strfromd as fl_strfromd;

unsafe extern "C" {
    fn strfromd(s: *mut c_char, n: usize, format: *const c_char, value: f64) -> c_int;
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
    f: unsafe extern "C" fn(*mut c_char, usize, *const c_char, f64) -> c_int,
    fmt: &CString,
    v: f64,
) -> Out {
    let mut buf = [0u8; 1024];
    let ret = unsafe { f(buf.as_mut_ptr() as *mut c_char, buf.len(), fmt.as_ptr(), v) };
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Out {
        ret,
        s: String::from_utf8_lossy(&buf[..n]).into_owned(),
    }
}

/// An in-spec strfromd format: `%` + optional `.precision` + one of aAeEfFgG.
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

/// A wide spread of f64 values, including the awkward ones.
fn gen_value(r: &mut Lcg) -> f64 {
    match r.below(10) {
        0 => 0.0,
        1 => -0.0,
        2 => f64::INFINITY,
        3 => f64::NEG_INFINITY,
        4 => f64::NAN,
        5 => f64::from_bits(r.next()),            // any bit pattern
        6 => (r.below(1_000_000) as f64) / 100.0, // nice 2-decimal
        7 => (r.below(1 << 20) as f64) / (1u64 << 10) as f64, // exact binary fractions (ties)
        8 => f64::from_bits((r.next() & 0x000f_ffff_ffff_ffff) | 0x0000_0000_0000_0001), // subnormal-ish
        _ => {
            let m = (r.below(1_000_000_000) as f64) / 1000.0;
            if r.next() & 1 == 0 { -m } else { m }
        }
    }
}

#[test]
fn strfromd_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x57f_d00d_1234_abcd);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..200_000 {
        let fmt = gen_format(&mut r);
        let v = gen_value(&mut r);
        let cf = CString::new(fmt.as_str()).unwrap();
        let fl = run(fl_strfromd, &cf, v);
        let host = run(strfromd, &cf, v);
        compared += 1;
        if fl != host && divs.len() < 40 {
            divs.push(format!(
                "fmt={fmt:?} v={v:?} (bits={:#018x})\n    fl   ={fl:?}\n    glibc={host:?}",
                v.to_bits()
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "strfromd diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("strfromd differential fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
