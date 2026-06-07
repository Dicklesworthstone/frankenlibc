#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc mbrtoc16 oracle (libc, linked by std)

//! Randomized live differential fuzzer for `mbrtoc16` (UTF-8 -> char16_t) vs
//! host glibc, exercising the supplementary-plane SURROGATE-PAIR state across
//! TWO INDEPENDENT conversion streams (distinct `mbstate_t`). glibc keeps the
//! pending low surrogate in the caller's `mbstate_t`, so interleaving two
//! streams must keep their surrogates independent; fl previously kept it in a
//! thread-local, so stream B's high surrogate clobbered stream A's pending low.
//! Each iteration interleaves two random supplementary code points
//! (A.high, B.high, A.low, B.low) on per-stream state and asserts fl's
//! (return, char16) sequence matches glibc byte-for-byte.

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_abi::wchar_abi::mbrtoc16 as fl_mbrtoc16;

unsafe extern "C" {
    fn mbrtoc16(pc16: *mut u16, s: *const c_char, n: usize, ps: *mut c_void) -> usize;
    fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
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
    fn below(&mut self, n: u64) -> u64 {
        (self.next() >> 11) % n
    }
}

/// UTF-8 encoding of a supplementary code point (always 4 bytes).
fn utf8_4(cp: u32) -> [u8; 4] {
    [
        0xF0 | (cp >> 18) as u8,
        0x80 | ((cp >> 12) & 0x3F) as u8,
        0x80 | ((cp >> 6) & 0x3F) as u8,
        0x80 | (cp & 0x3F) as u8,
    ]
}

/// One mbrtoc16 call rendered comparably: (return as i64, char16 written).
fn call(
    f: unsafe extern "C" fn(*mut u16, *const c_char, usize, *mut c_void) -> usize,
    bytes: &[u8],
    st: &mut [u8; 16],
) -> (i64, u16) {
    let mut c16: u16 = 0xFFFF;
    let ret = unsafe {
        f(
            &mut c16,
            bytes.as_ptr() as *const c_char,
            bytes.len(),
            st.as_mut_ptr() as *mut c_void,
        )
    };
    (ret as i64, c16)
}

/// Replay the interleaved two-stream scenario against one implementation.
fn replay(
    f: unsafe extern "C" fn(*mut u16, *const c_char, usize, *mut c_void) -> usize,
    cp_a: u32,
    cp_b: u32,
) -> Vec<(i64, u16)> {
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    let ba = utf8_4(cp_a);
    let bb = utf8_4(cp_b);
    let dummy = *b"x\0";
    vec![
        call(f, &ba, &mut a),    // A high surrogate (consumes 4)
        call(f, &bb, &mut b),    // B high surrogate (consumes 4)
        call(f, &dummy, &mut a), // A low surrogate (-3, consumes 0)
        call(f, &dummy, &mut b), // B low surrogate (-3, consumes 0)
    ]
}

#[test]
fn mbrtoc16_interleaved_differential_fuzz_vs_glibc() {
    unsafe { setlocale(libc::LC_ALL, c"C.UTF-8".as_ptr()) };
    let mut r = Lcg(0x16de_ad16_5566_7788);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..100_000 {
        let cp_a = 0x10000 + r.below(0x100000) as u32;
        let cp_b = 0x10000 + r.below(0x100000) as u32;
        let fl = replay(fl_mbrtoc16, cp_a, cp_b);
        let host = replay(mbrtoc16, cp_a, cp_b);
        compared += 1;
        if fl != host && divs.len() < 40 {
            divs.push(format!(
                "cp_a={cp_a:#x} cp_b={cp_b:#x}\n    fl   ={fl:?}\n    glibc={host:?}"
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "mbrtoc16 interleaved streams diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!(
        "mbrtoc16 interleaved differential fuzz: {compared} scenarios, 0 divergences vs host glibc"
    );
}
