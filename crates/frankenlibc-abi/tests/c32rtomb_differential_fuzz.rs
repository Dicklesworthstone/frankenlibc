#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc c32rtomb oracle (libc, linked by std)

//! Randomized live differential fuzzer for C11 `c32rtomb` (char32_t -> UTF-8) vs
//! host glibc, in the C.UTF-8 locale. c32rtomb is stateless per call (single
//! code point, caller-owned mbstate zeroed each time, no global, no heap
//! handoff), so the live differential is clean. We sweep the full u32 range with
//! heavy bias toward the awkward inputs — ASCII, 2/3/4-byte boundaries, the
//! UTF-16 surrogate block (0xD800..=0xDFFF, which c32rtomb must REJECT), the
//! 0x10FFFF max, and out-of-range > 0x10FFFF — comparing the return value, errno,
//! and the written bytes.

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_abi::wchar_abi::c32rtomb as fl_c32rtomb;

unsafe extern "C" {
    fn c32rtomb(s: *mut c_char, c32: u32, ps: *mut c_void) -> usize;
    fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
    fn __errno_location() -> *mut c_int;
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

#[derive(PartialEq, Eq, Debug)]
struct Out {
    ret: i64,
    errno: c_int,
    bytes: Vec<u8>,
}

fn run(
    f: unsafe extern "C" fn(*mut c_char, u32, *mut c_void) -> usize,
    c32: u32,
) -> Out {
    let mut buf = [0u8; 16];
    // Zeroed mbstate_t (glibc's is 8 bytes; give it plenty and pass a pointer).
    let mut state = [0u8; 16];
    unsafe { *__errno_location() = 0 };
    let ret = unsafe {
        f(
            buf.as_mut_ptr() as *mut c_char,
            c32,
            state.as_mut_ptr() as *mut c_void,
        )
    };
    let errno = unsafe { *__errno_location() };
    let ret_i = ret as i64; // (size_t)-1 -> -1
    let bytes = if ret_i >= 0 && (ret as usize) <= buf.len() {
        buf[..ret as usize].to_vec()
    } else {
        Vec::new()
    };
    Out {
        ret: ret_i,
        errno: if ret_i < 0 { errno } else { 0 },
        bytes,
    }
}

/// A code point biased toward boundaries and invalid regions.
fn gen_c32(r: &mut Lcg) -> u32 {
    match r.below(12) {
        0 => r.below(0x80) as u32,                       // ASCII
        1 => 0x80 + r.below(0x780) as u32,               // 2-byte
        2 => 0x800 + r.below(0xF800) as u32,             // 3-byte (incl surrogate block)
        3 => 0x10000 + r.below(0x100000) as u32,         // 4-byte supplementary
        4 => 0xD800 + r.below(0x800) as u32,             // surrogate block (invalid)
        5 => 0x110000 + r.below(0x1000) as u32,          // just over max (invalid)
        6 => r.next() as u32,                            // any 32-bit (mostly huge/invalid)
        7 => [0x0, 0x7F, 0x80, 0x7FF, 0x800, 0xFFFF, 0x10000, 0x10FFFF, 0x110000][r.below(9) as usize]
            as u32,
        8 => 0xFFFE + r.below(4) as u32,                 // noncharacters near BMP top
        9 => 0xD7FF + r.below(4) as u32,                 // around the surrogate lower edge
        10 => 0xDFFF + r.below(4) as u32,                // around the surrogate upper edge
        _ => 0x10FFFD + r.below(6) as u32,               // around the max edge
    }
}

#[test]
fn c32rtomb_differential_fuzz_vs_glibc() {
    unsafe { setlocale(libc::LC_ALL, c"C.UTF-8".as_ptr()) };
    let mut r = Lcg(0xc32d_0d1e_2233_4455);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..300_000 {
        let c32 = gen_c32(&mut r);
        let fl = run(fl_c32rtomb, c32);
        let host = run(c32rtomb, c32);
        compared += 1;
        if fl != host && divs.len() < 40 {
            divs.push(format!(
                "c32={c32:#x}\n    fl   ={fl:?}\n    glibc={host:?}"
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "c32rtomb diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("c32rtomb differential fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
