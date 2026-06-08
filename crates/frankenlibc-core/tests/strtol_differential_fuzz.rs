#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc strtol/strtoul oracle (libc)

//! Randomized live differential fuzzer for `strtol_impl` / `strtoul_impl` vs
//! host glibc `strtol`/`strtoul`. The existing `strtol_differential_probe` is a
//! fixed battery; this sweeps random input strings (digits across bases, signs,
//! leading whitespace, `0x`/`0`/`0b` prefixes, garbage tails, overflow-length
//! runs) crossed with random bases (0, 2..=36, plus a few invalid) and compares
//! the parsed value, the number of consumed characters (endptr position), and
//! whether the result overflowed (ERANGE), against the live glibc oracle.

use std::ffi::{CString, c_char, c_int, c_long, c_ulong};

use frankenlibc_core::stdlib::conversion::{ConversionStatus, strtol_impl, strtoul_impl};

unsafe extern "C" {
    fn strtol(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int) -> c_long;
    fn strtoul(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int) -> c_ulong;
    fn __errno_location() -> *mut c_int;
}

/// ERANGE on Linux.
const ERANGE: c_int = 34;

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

fn gen_input(r: &mut Lcg) -> Vec<u8> {
    const ALPHA: &[u8] = b"0123456789abcdefABCDEFxXoObB+-  \t.gG@zZ_";
    // Occasionally lead with a structured prefix to stress the special parses
    // (0x / signed / octal-0 / leading-space-sign / overflow run).
    let prefix: &[u8] = match r.next() % 8 {
        0 => b"0x",
        1 => b"-0X",
        2 => b"0",
        3 => b"  +",
        4 => b"99999999999999999999",
        _ => b"",
    };
    let len = (r.next() % 22) as usize;
    let mut v: Vec<u8> = prefix.to_vec();
    v.extend((0..len).map(|_| ALPHA[(r.next() as usize) % ALPHA.len()]));
    v.retain(|&b| b != 0);
    v
}

fn gen_base(r: &mut Lcg) -> c_int {
    match r.next() % 10 {
        0 => 0,
        1 => 10,
        2 => 16,
        3 => 8,
        4 => 2,
        5 => [1, 37, -1, 100][(r.next() % 4) as usize], // invalid bases
        _ => (2 + r.next() % 35) as c_int,              // 2..=36
    }
}

fn host_strtol(input: &[u8], base: c_int) -> (i64, usize, bool) {
    let c = CString::new(input).unwrap();
    let mut end: *mut c_char = c.as_ptr() as *mut c_char;
    unsafe {
        *__errno_location() = 0;
        let v = strtol(c.as_ptr(), &mut end as *mut *mut c_char, base);
        let consumed = end as usize - c.as_ptr() as usize;
        let erange = *__errno_location() == ERANGE;
        (v, consumed, erange)
    }
}

fn host_strtoul(input: &[u8], base: c_int) -> (u64, usize, bool) {
    let c = CString::new(input).unwrap();
    let mut end: *mut c_char = c.as_ptr() as *mut c_char;
    unsafe {
        *__errno_location() = 0;
        let v = strtoul(c.as_ptr(), &mut end as *mut *mut c_char, base);
        let consumed = end as usize - c.as_ptr() as usize;
        let erange = *__errno_location() == ERANGE;
        (v as u64, consumed, erange)
    }
}

#[test]
fn strtol_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x5720_10a7_5ee0_0001);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..300_000 {
        let input = gen_input(&mut r);
        let base = gen_base(&mut r);
        let unsigned = r.next() & 1 == 0;

        if unsigned {
            let (fv, fc, fs) = strtoul_impl(&input, base);
            let fl = (fv, fc, matches!(fs, ConversionStatus::Overflow));
            let host = host_strtoul(&input, base);
            compared += 1;
            if fl != host && divs.len() < 40 {
                divs.push(format!(
                    "strtoul base={base} input={:?}\n    fl   ={fl:?}\n    glibc={host:?}",
                    String::from_utf8_lossy(&input)
                ));
            }
        } else {
            let (fv, fc, fs) = strtol_impl(&input, base);
            let fl = (
                fv,
                fc,
                matches!(fs, ConversionStatus::Overflow | ConversionStatus::Underflow),
            );
            let host = host_strtol(&input, base);
            compared += 1;
            if fl != host && divs.len() < 40 {
                divs.push(format!(
                    "strtol base={base} input={:?}\n    fl   ={fl:?}\n    glibc={host:?}",
                    String::from_utf8_lossy(&input)
                ));
            }
        }
    }

    assert!(
        divs.is_empty(),
        "strtol/strtoul diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("strtol/strtoul fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
