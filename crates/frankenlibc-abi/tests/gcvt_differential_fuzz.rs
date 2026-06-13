#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc gcvt oracle

//! Randomized live differential fuzzer for `gcvt` vs host glibc. `gcvt(value,
//! ndigit, buf)` formats `value` with `ndigit` significant digits into `buf`
//! (roughly `%.*g` but with glibc's exact rounding, exponent and trailing-zero
//! behavior). fl implements it natively; this drives random doubles (normals,
//! subnormals, powers of ten, halfway cases, inf/nan, signed zero) across a
//! range of `ndigit` and asserts fl's string equals glibc's byte-for-byte.

use std::ffi::CStr;

use frankenlibc_abi::stdlib_abi as fl;

unsafe extern "C" {
    fn gcvt(
        value: libc::c_double,
        ndigit: libc::c_int,
        buf: *mut libc::c_char,
    ) -> *mut libc::c_char;
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

/// A random double biased toward the formatting-significant shapes.
fn gen_double(r: &mut Lcg) -> f64 {
    match r.below(10) {
        0 => 0.0,
        1 => -0.0,
        2 => f64::INFINITY * (if r.below(2) == 0 { 1.0 } else { -1.0 }),
        3 => f64::NAN,
        4 => {
            // Power of ten, +/- .
            let e = r.below(40) as i32 - 20;
            let v = 10f64.powi(e);
            if r.below(2) == 0 { v } else { -v }
        }
        5 => {
            // Halfway-ish: k + 0.5 scaled.
            let k = r.below(1000) as f64 + 0.5;
            k * 10f64.powi(r.below(12) as i32 - 6)
        }
        6 => {
            // Subnormal / tiny.
            f64::from_bits(r.next() & 0x000f_ffff_ffff_ffff)
        }
        _ => {
            // Arbitrary finite double from random bits, rejecting inf/nan.
            let b = r.next();
            let v = f64::from_bits(b);
            if v.is_finite() {
                v
            } else {
                (b as i64) as f64 / 1000.0
            }
        }
    }
}

fn run(
    f: unsafe extern "C" fn(libc::c_double, libc::c_int, *mut libc::c_char) -> *mut libc::c_char,
    v: f64,
    nd: i32,
) -> Vec<u8> {
    // glibc gcvt needs ndigit+~10 bytes of headroom; give plenty.
    let mut buf = [0u8; 128];
    let ret = unsafe { f(v, nd, buf.as_mut_ptr() as *mut libc::c_char) };
    if ret.is_null() {
        return b"<NULL>".to_vec();
    }
    unsafe { CStr::from_ptr(ret) }.to_bytes().to_vec()
}

#[test]
fn gcvt_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x9c47_a1b2_5ee0_3311);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..200_000 {
        let v = gen_double(&mut r);
        // glibc clamps/handles ndigit; cover 0..=20 and a couple wild values.
        let nd = match r.below(9) {
            0 => 0,
            1 => 1,
            7 => r.below(40) as i32,
            8 => -(1 + r.below(120) as i32), // negative precision → glibc default 6
            n => n as i32,
        };

        let fl_s = run(fl::gcvt, v, nd);
        let lc_s = run(gcvt, v, nd);
        compared += 1;
        if fl_s != lc_s && divs.len() < 40 {
            divs.push(format!(
                "gcvt({:.17e}, {nd}) fl={:?} glibc={:?}",
                v,
                String::from_utf8_lossy(&fl_s),
                String::from_utf8_lossy(&lc_s),
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "gcvt diverged from glibc ({compared} compared):\n{}",
        divs.join("\n")
    );
    eprintln!("gcvt fuzz: {compared} compared, 0 divergences vs host glibc");
}
