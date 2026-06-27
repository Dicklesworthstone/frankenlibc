#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc snprintf oracle (libc)

//! Randomized live differential fuzzer for frankenlibc printf float formatting
//! (`%e/%E/%f/%F/%g/%G`) vs host glibc `snprintf`. The existing
//! `printf_float_differential_probe` is a fixed ~50-case battery with statically
//! captured reference strings; this sweeps random doubles (every regime: signed
//! zero, subnormal, integer, huge/tiny, inf, nan, fully-random bits) crossed
//! with random `%[flags][width][.prec][conv]` specs and compares the exact
//! output string against a live glibc oracle. fl's formatter applies the flags,
//! width, zero-pad and rounding itself, so this exercises round-half-to-even,
//! %g trailing-zero stripping and exponent threshold, alt-form, sign/space,
//! and width/precision interactions.

use std::ffi::{CString, c_char, c_int};

use frankenlibc_core::stdio::printf::{FormatSegment, format_float, parse_format_string};

unsafe extern "C" {
    // Single f64 vararg: on x86-64 SysV the value is passed in xmm0 whether or
    // not the prototype is variadic, so a fixed prototype matches the ABI.
    fn snprintf(s: *mut c_char, n: usize, fmt: *const c_char, val: f64) -> c_int;
}

fn fl_render(fmt: &str, val: f64) -> Option<String> {
    let segs = parse_format_string(fmt.as_bytes());
    let spec = segs.as_slice().iter().find_map(|s| match s {
        FormatSegment::Spec(spec) => Some(*spec),
        _ => None,
    })?;
    let mut buf = Vec::new();
    format_float(val, &spec, &mut buf);
    String::from_utf8(buf).ok()
}

fn host_render(fmt: &str, val: f64) -> String {
    let cfmt = CString::new(fmt).unwrap();
    // First call with a 0-length buffer to learn the required size, then size
    // exactly (huge value x high precision can exceed any fixed buffer).
    let need = unsafe { snprintf(std::ptr::null_mut(), 0, cfmt.as_ptr(), val) };
    let need = need.max(0) as usize;
    let mut buf = vec![0u8; need + 1];
    let n = unsafe { snprintf(buf.as_mut_ptr() as *mut c_char, buf.len(), cfmt.as_ptr(), val) };
    let n = (n.max(0) as usize).min(buf.len() - 1);
    String::from_utf8_lossy(&buf[..n]).into_owned()
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
}

fn rand_val(r: &mut Lcg) -> f64 {
    match r.next() % 18 {
        0 => 0.0,
        1 => -0.0,
        2 => f64::INFINITY,
        3 => f64::NEG_INFINITY,
        4 => f64::NAN,
        5 => 1.0,
        6 => -1.0,
        7 => 0.5,
        8 => 2.5,
        9 => (r.next() % 1_000_000) as f64,
        10 => -((r.next() % 1_000_000) as f64),
        // subnormal
        11 => f64::from_bits(r.next() & 0x000f_ffff_ffff_ffff),
        // value near a rounding boundary (k + 0.5 at various scales)
        12 => {
            let k = (r.next() % 1000) as f64;
            let e = (r.next() % 30) as i32 - 15;
            (k + 0.5) * 10f64.powi(e)
        }
        // scaled uniform across a wide exponent range
        13..=15 => {
            let e = (r.next() % 600) as i32 - 300;
            (r.next() as f64 / u64::MAX as f64) * 10f64.powi(e)
        }
        // any double, including inf/nan
        _ => f64::from_bits(r.next()),
    }
}

fn rand_fmt(r: &mut Lcg) -> String {
    let specs = b"eEfFgGaA";
    let spec = specs[(r.next() as usize) % specs.len()] as char;
    let mut s = String::from("%");
    for &flag in b"-+ 0#" {
        if r.next() & 7 == 0 {
            s.push(flag as char);
        }
    }
    if r.next() & 3 == 0 {
        s.push_str(&(r.next() % 40).to_string());
    }
    if r.next() & 1 == 0 {
        s.push('.');
        // Reach into the high-precision regime where the exact decimal / hex
        // expansion of the double must match glibc digit-for-digit.
        let p = if r.next() & 1 == 0 {
            r.next() % 25
        } else {
            r.next() % 320
        };
        s.push_str(&p.to_string());
    }
    s.push(spec);
    s
}

#[test]
fn printf_float_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x70cf_10a7_5ee0_0001);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;
    for _ in 0..300_000 {
        let val = rand_val(&mut r);
        let fmt = rand_fmt(&mut r);
        let host = host_render(&fmt, val);
        let Some(fl) = fl_render(&fmt, val) else {
            continue;
        };
        compared += 1;
        if fl != host && divs.len() < 40 {
            divs.push(format!(
                "fmt={fmt:?} val={:#018x}({val:e})\n    fl   ={fl:?}\n    glibc={host:?}",
                val.to_bits()
            ));
        }
    }
    assert!(
        divs.is_empty(),
        "printf float formatting diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("printf float fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
