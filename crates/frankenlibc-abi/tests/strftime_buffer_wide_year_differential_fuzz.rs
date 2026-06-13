#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc strftime oracle (libc, linked by std)

//! Randomized live differential fuzzer for `strftime`'s BUFFER BOUNDARY at
//! EXTREME years vs host glibc. strftime returns the byte count (excl NUL) only
//! when the result PLUS the NUL fits `maxsize`, else 0 (contents undefined). The
//! existing strftime_buffer probe is fixed-case with a normal year (2026); this
//! sweeps random formats whose conversions vary in length (%Y/%C with years far
//! outside 4 digits, including negatives) against random small `maxsize`, hitting
//! the exact off-by-one boundary at variable-length output. Compares the return
//! value AND the written bytes.

use std::ffi::{CString, c_char};

use frankenlibc_abi::time_abi::strftime as fl_strftime;

unsafe extern "C" {
    fn strftime(s: *mut c_char, max: usize, fmt: *const c_char, tm: *const libc::tm) -> usize;
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
    ret: usize,
    s: Vec<u8>,
}

fn run(
    f: unsafe extern "C" fn(*mut c_char, usize, *const c_char, *const libc::tm) -> usize,
    fmt: &CString,
    max: usize,
    tm: &libc::tm,
) -> Out {
    let mut buf = vec![b'#'; max.max(1) + 8];
    let ret = unsafe { f(buf.as_mut_ptr() as *mut c_char, max, fmt.as_ptr(), tm) };
    let s = if ret > 0 {
        buf[..ret.min(buf.len())].to_vec()
    } else {
        Vec::new()
    };
    Out { ret, s }
}

/// Build a random strftime format from length-varying, TZ-independent pieces.
fn gen_fmt(r: &mut Lcg) -> String {
    // %Y / %C vary with the (possibly extreme) year; the others are fixed width.
    const PIECES: &[&str] = &[
        "%Y", "%C", "%y", "%m", "%d", "%H", "%M", "%S", "%%", "x", "-", ":", " ", "%Y%C",
    ];
    let n = 1 + r.below(4);
    (0..n)
        .map(|_| PIECES[r.below(PIECES.len() as u64) as usize])
        .collect()
}

#[test]
fn strftime_buffer_wide_year_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x7374_7266_7469_0001);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..300_000 {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        tm.tm_sec = r.below(60) as i32;
        tm.tm_min = r.below(60) as i32;
        tm.tm_hour = r.below(24) as i32;
        tm.tm_mday = 1 + r.below(28) as i32;
        tm.tm_mon = r.below(12) as i32;
        // Wide tm_year: normal, near the +/- 4-digit boundary, and extreme.
        tm.tm_year = match r.below(4) {
            0 => r.below(8000) as i32 - 2000,
            1 => r.below(400) as i32 + 8000, // around year ~9999/10000
            2 => -(r.below(4000) as i32),    // negative years
            _ => r.below(2_000_000) as i32 - 1_000_000,
        };
        let fmt = gen_fmt(&mut r);
        let cf = CString::new(fmt.as_str()).unwrap();
        let max = r.below(40) as usize; // small, to straddle the boundary

        let fl = run(fl_strftime, &cf, max, &tm);
        let host = run(strftime, &cf, max, &tm);
        compared += 1;
        // When ret == 0 the buffer is undefined, so only compare the return value.
        let mismatch = fl.ret != host.ret || (fl.ret > 0 && fl.s != host.s);
        if mismatch && divs.len() < 40 {
            divs.push(format!(
                "fmt={fmt:?} year={} max={max}\n    fl   ={fl:?}\n    glibc={host:?}",
                tm.tm_year + 1900
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "strftime buffer/wide-year diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!(
        "strftime buffer wide-year fuzz: {compared} comparisons, 0 divergences vs host glibc"
    );
}
