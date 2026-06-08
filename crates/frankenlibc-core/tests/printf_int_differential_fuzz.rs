#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc snprintf oracle (libc)

//! Randomized live differential fuzzer for frankenlibc printf integer formatting
//! (`format_signed` / `format_unsigned`, conversions d/i/u/o/x/X) vs host glibc
//! `snprintf`. The existing `printf_int_differential_probe` is a fixed battery;
//! this sweeps random 64-bit values (every regime: 0, +-1, small, INT64_MIN/MAX,
//! powers of two, fully-random bits) crossed with random `%[flags][width][.prec]`
//! specs and compares the exact output string against a live glibc oracle.
//!
//! `format_signed`/`format_unsigned` format whatever 64-bit value they are given
//! (the length modifier is consumed by the variadic ABI, not these functions),
//! so the format string carries `ll` purely so the host `snprintf` reads a full
//! 64-bit arg matching the value handed to fl. This exercises the precision-0
//! rules, `#` alt-form for octal/hex, the `0`-flag/precision interaction,
//! sign/space flags, width/zero-pad, and the INT64_MIN edge.

use std::ffi::{CString, c_char, c_int, c_longlong};

use frankenlibc_core::stdio::printf::{
    FormatSegment, FormatSpec, format_signed, format_unsigned, parse_format_string,
};

unsafe extern "C" {
    // c_longlong is 64-bit on x86-64 Linux; the conversion (`%lld` vs `%llu`/
    // `%llx`/...) decides signed vs unsigned interpretation of the same bits.
    fn snprintf(s: *mut c_char, n: usize, fmt: *const c_char, val: c_longlong) -> c_int;
}

fn spec_of(fmt: &str) -> Option<FormatSpec> {
    parse_format_string(fmt.as_bytes())
        .as_slice()
        .iter()
        .find_map(|s| match s {
            FormatSegment::Spec(spec) => Some(*spec),
            _ => None,
        })
}

fn host_render(fmt: &str, bits: i64) -> String {
    let cfmt = CString::new(fmt).unwrap();
    let need = unsafe { snprintf(std::ptr::null_mut(), 0, cfmt.as_ptr(), bits as c_longlong) };
    let need = need.max(0) as usize;
    let mut buf = vec![0u8; need + 1];
    let n = unsafe {
        snprintf(
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            cfmt.as_ptr(),
            bits as c_longlong,
        )
    };
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

fn rand_bits(r: &mut Lcg) -> u64 {
    match r.next() % 12 {
        0 => 0,
        1 => 1,
        2 => u64::MAX,             // -1 signed / max unsigned
        3 => i64::MIN as u64,      // 0x8000...0
        4 => i64::MAX as u64,      // 0x7fff...f
        5 => r.next() % 1000,
        6 => (r.next() % 1000).wrapping_neg(),
        7 => 1u64 << (r.next() % 64), // power of two
        8 => (1u64 << (r.next() % 64)).wrapping_sub(1),
        _ => r.next(),
    }
}

fn rand_fmt(r: &mut Lcg, conv: char) -> String {
    let mut s = String::from("%");
    for &flag in b"-+ 0#" {
        if r.next() & 7 == 0 {
            s.push(flag as char);
        }
    }
    if r.next() & 3 == 0 {
        s.push_str(&(r.next() % 25).to_string());
    }
    if r.next() & 1 == 0 {
        s.push('.');
        s.push_str(&(r.next() % 25).to_string());
    }
    s.push_str("ll");
    s.push(conv);
    s
}

#[test]
fn printf_int_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x1117_d161_7ee0_0001);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..400_000 {
        let bits = rand_bits(&mut r);
        let signed = r.next() & 1 == 0;
        let conv = if signed {
            b"di"[(r.next() % 2) as usize] as char
        } else {
            b"uoxX"[(r.next() % 4) as usize] as char
        };
        let fmt = rand_fmt(&mut r, conv);
        let Some(spec) = spec_of(&fmt) else {
            continue;
        };

        let mut buf = Vec::new();
        if signed {
            format_signed(bits as i64, &spec, &mut buf);
        } else {
            format_unsigned(bits, &spec, &mut buf);
        }
        let Ok(fl) = String::from_utf8(buf) else {
            continue;
        };
        let host = host_render(&fmt, bits as i64);
        compared += 1;
        if fl != host && divs.len() < 40 {
            divs.push(format!(
                "fmt={fmt:?} bits={bits:#018x}\n    fl   ={fl:?}\n    glibc={host:?}"
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "printf integer formatting diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("printf int fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
