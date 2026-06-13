#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strcoll/strxfrm oracle

//! Randomized differential fuzzer for `strcoll` / `strxfrm` in the C locale vs
//! host glibc. The fixed batteries (`diff_strcoll_c_locale`,
//! `diff_strxfrm_c_locale_ordering`) check only the comparison SIGN / ordering
//! property. This additionally pins, over random inputs:
//!   - strcoll's sign for random (often prefix-sharing) string pairs;
//!   - strxfrm's RETURN VALUE (the transformed length) and its exact OUTPUT
//!     BUFFER for a random destination size `n` — including the truncation
//!     contract (write at most `n-1` bytes + a NUL; the return is the full
//!     transformed length regardless of `n`).

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::string_abi as fl;

unsafe extern "C" {
    fn strcoll(s1: *const c_char, s2: *const c_char) -> c_int;
    fn strxfrm(dst: *mut c_char, src: *const c_char, n: usize) -> usize;
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

/// A random NUL-free byte string (so it round-trips through `CString`), drawn
/// from a small alphabet so prefix collisions / ties are common.
fn gen_str(r: &mut Lcg) -> Vec<u8> {
    const ALPHA: &[u8] = b"ab YZ\x01\x02\x7f\x80\xff09";
    let len = r.below(13);
    (0..len).map(|_| ALPHA[r.below(ALPHA.len())]).collect()
}

#[test]
fn strcoll_strxfrm_differential_fuzz_vs_glibc() {
    let c = CString::new("C").unwrap();
    unsafe { setlocale(LC_ALL, c.as_ptr()) };

    let mut r = Lcg(0xc011_5f12_a64d_0017);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..200_000 {
        // ---- strcoll: sign over a random pair (sometimes a shared prefix) ----
        let a = gen_str(&mut r);
        let mut b = if r.below(2) == 0 {
            // share a's prefix to force near-ties
            let k = if a.is_empty() {
                0
            } else {
                r.below(a.len() + 1)
            };
            let mut v = a[..k].to_vec();
            v.extend(gen_str(&mut r));
            v
        } else {
            gen_str(&mut r)
        };
        if b.contains(&0) {
            b.retain(|&x| x != 0);
        }
        if let (Ok(ca), Ok(cb)) = (CString::new(a.clone()), CString::new(b.clone())) {
            let s_fl = unsafe { fl::strcoll(ca.as_ptr(), cb.as_ptr()) }.signum();
            let s_lc = unsafe { strcoll(ca.as_ptr(), cb.as_ptr()) }.signum();
            compared += 1;
            if s_fl != s_lc && divs.len() < 40 {
                divs.push(format!(
                    "strcoll({:?},{:?}) sign: fl={s_fl} glibc={s_lc}",
                    String::from_utf8_lossy(&a),
                    String::from_utf8_lossy(&b)
                ));
            }
        }

        // ---- strxfrm: return value + exact output buffer for random n ----
        let s = gen_str(&mut r);
        if let Ok(cs) = CString::new(s.clone()) {
            let n = r.below(18); // 0..17 — straddles the transformed length
            let mut buf_fl = vec![0xCDu8; 32];
            let mut buf_lc = vec![0xCDu8; 32];
            let ret_fl = unsafe { fl::strxfrm(buf_fl.as_mut_ptr() as *mut c_char, cs.as_ptr(), n) };
            let ret_lc = unsafe { strxfrm(buf_lc.as_mut_ptr() as *mut c_char, cs.as_ptr(), n) };
            compared += 1;
            if (ret_fl != ret_lc || buf_fl != buf_lc) && divs.len() < 40 {
                divs.push(format!(
                    "strxfrm({:?}, n={n}): fl=(ret={ret_fl}, {:?}) glibc=(ret={ret_lc}, {:?})",
                    String::from_utf8_lossy(&s),
                    String::from_utf8_lossy(&buf_fl),
                    String::from_utf8_lossy(&buf_lc),
                ));
            }
        }
    }

    assert!(
        divs.is_empty(),
        "strcoll/strxfrm diverged from host glibc on some of {compared} cases (up to 40):\n{}",
        divs.join("\n")
    );
    eprintln!("strcoll/strxfrm fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
