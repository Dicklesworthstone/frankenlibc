#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc swab/memfrob oracle + raw buffers

//! Differential + metamorphic gate for swab and memfrob (bd-janwpo) — neither
//! had a committed gate. swab(from,to,n) copies n bytes swapping each adjacent
//! byte pair (a trailing odd byte is left untouched in the destination);
//! memfrob(s,n) XORs each byte with 42 and is its own inverse. For randomised
//! buffers fl's output must equal host glibc's byte-for-byte, plus the
//! documented invariants. No mocks.

use std::ffi::c_void;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn swab(from: *const c_void, to: *mut c_void, n: isize);
        pub fn memfrob(s: *mut c_void, n: usize) -> *mut c_void;
    }
}
use frankenlibc_abi::string_abi::swab as fl_swab;
use frankenlibc_abi::unistd_abi::memfrob as fl_memfrob;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64)) as usize
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
}

const FILL: u8 = 0x5C;

#[test]
fn swab_matches_glibc() {
    let mut rng = Rng(0x5741_4200_0000_0001);
    for _ in 0..6000 {
        let n = rng.below(40); // includes 0, odd and even lengths
        let src: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
        let mut gd = vec![FILL; n.max(1)];
        let mut fd = vec![FILL; n.max(1)];
        unsafe {
            g::swab(src.as_ptr().cast(), gd.as_mut_ptr().cast(), n as isize);
            fl_swab(src.as_ptr().cast(), fd.as_mut_ptr().cast(), n as isize);
        }
        assert_eq!(fd, gd, "swab(n={n}) src={src:?}: fl={fd:?} glibc={gd:?}");
        // METAMORPHIC: even-index byte <- src[i+1], odd-index byte <- src[i-1],
        // for the floor(n/2) full pairs; a trailing odd byte is untouched.
        let pairs = n / 2;
        for p in 0..pairs {
            assert_eq!(fd[2 * p], src[2 * p + 1], "swab hi byte of pair {p}");
            assert_eq!(fd[2 * p + 1], src[2 * p], "swab lo byte of pair {p}");
        }
        if n % 2 == 1 {
            assert_eq!(fd[n - 1], FILL, "swab must not touch the trailing odd byte");
        }
    }
}

#[test]
fn memfrob_matches_glibc_and_is_involutive() {
    let mut rng = Rng(0x4652_4F42_0000_0001);
    for _ in 0..6000 {
        let n = rng.below(48);
        let base: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
        let mut gb = base.clone();
        let mut fb = base.clone();
        unsafe {
            g::memfrob(gb.as_mut_ptr().cast(), n);
            fl_memfrob(fb.as_mut_ptr().cast(), n);
        }
        assert_eq!(fb, gb, "memfrob(n={n}) base={base:?}");
        // Each byte is XORed with 42.
        for i in 0..n {
            assert_eq!(fb[i], base[i] ^ 42, "memfrob byte {i}");
        }
        // Involutive: applying memfrob twice restores the original.
        unsafe { fl_memfrob(fb.as_mut_ptr().cast(), n) };
        assert_eq!(fb, base, "memfrob must be its own inverse");
    }
}

#[test]
fn swab_zero_and_one_byte() {
    // n <= 1: no full pairs, destination untouched (both impls).
    let src = [0xAAu8, 0xBB];
    let mut gd = [FILL; 2];
    let mut fd = [FILL; 2];
    for n in [0isize, 1] {
        gd = [FILL; 2];
        fd = [FILL; 2];
        unsafe {
            g::swab(src.as_ptr().cast(), gd.as_mut_ptr().cast(), n);
            fl_swab(src.as_ptr().cast(), fd.as_mut_ptr().cast(), n);
        }
        assert_eq!(fd, gd, "swab(n={n}) edge");
    }
}
