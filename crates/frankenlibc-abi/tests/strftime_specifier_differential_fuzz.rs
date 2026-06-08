#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strftime oracle

//! Randomized differential fuzzer for `strftime` over the FULL conversion-
//! specifier surface vs host glibc, under the C locale and TZ=UTC.
//!
//! The fixed battery in `conformance_diff_time::diff_strftime_cases` pins ~21
//! formats over a handful of fixed epochs and omits most specifiers (`%d %e %H
//! %M %S %m %V %u %r %R %T %k %l %P %h %D %x %X`). This sweeps EVERY conversion
//! specifier against a random `tm` (always a consistent struct from `gmtime_r`,
//! so `tm_wday`/`tm_yday`/`tm_gmtoff`/`tm_zone` agree with the date) over a wide
//! date range, comparing the rendered bytes and return value exactly.
//!
//! Scope: BARE specifiers only. The GNU field-width / `- _ 0 ^ #` flags and the
//! `E`/`O` locale modifiers are a separate, multi-faceted gap (fl emits literal
//! `%OW`, ignores width on string specifiers, etc.) tracked in bd-hfoqbf.

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::time_abi as fl;

unsafe extern "C" {
    fn strftime(s: *mut c_char, max: usize, fmt: *const c_char, tm: *const libc::tm) -> usize;
    fn gmtime_r(t: *const libc::time_t, tm: *mut libc::tm) -> *mut libc::tm;
    fn setlocale(category: c_int, locale: *const c_char) -> *const c_char;
    fn tzset();
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

// Every glibc strftime conversion specifier (sans %% which we add as a literal).
const SPECS: &[u8] = b"aAbBcCdDeFgGhHIjklmMnpPrRsStTuUVwWxXyYzZ";

fn gen_format(r: &mut Lcg) -> Vec<u8> {
    let mut f = Vec::new();
    if r.below(3) == 0 {
        f.extend_from_slice(b"[");
    }
    f.push(b'%');
    f.push(SPECS[r.below(SPECS.len())]);
    if r.below(3) == 0 {
        f.extend_from_slice(b"]");
    }
    f
}

fn run(
    f: unsafe extern "C" fn(*mut c_char, usize, *const c_char, *const libc::tm) -> usize,
    fmt: &CString,
    tm: &libc::tm,
) -> (usize, Vec<u8>) {
    let mut buf = vec![0u8; 512];
    let n = unsafe { f(buf.as_mut_ptr() as *mut c_char, buf.len(), fmt.as_ptr(), tm) };
    let n = n.min(buf.len());
    (n, buf[..n].to_vec())
}

#[test]
fn strftime_specifier_differential_fuzz_vs_glibc() {
    // Deterministic locale/timezone: C locale, UTC.
    unsafe {
        std::env::set_var("TZ", "UTC");
        tzset();
        let c = CString::new("C").unwrap();
        setlocale(LC_ALL, c.as_ptr());
    }

    let mut r = Lcg(0x57f7_16ed_a7e0_0009);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..200_000 {
        // A consistent broken-down time from a random epoch (years ~1906..2160).
        let epoch: libc::time_t =
            ((r.next() % 8_000_000_000) as i64) - 2_000_000_000;
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        if unsafe { gmtime_r(&epoch, &mut tm) }.is_null() {
            continue;
        }

        let fmt = gen_format(&mut r);
        let Ok(cf) = CString::new(fmt.clone()) else {
            continue;
        };
        let (fl_n, fl_s) = run(fl::strftime, &cf, &tm);
        let (lc_n, lc_s) = run(strftime, &cf, &tm);
        compared += 1;
        if (fl_n != lc_n || fl_s != lc_s) && divs.len() < 40 {
            divs.push(format!(
                "fmt={:?} epoch={epoch}\n    fl   =(n={fl_n}, {:?})\n    glibc=(n={lc_n}, {:?})",
                String::from_utf8_lossy(&fmt),
                String::from_utf8_lossy(&fl_s),
                String::from_utf8_lossy(&lc_s),
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "strftime diverged from host glibc on some of {compared} cases (up to 40):\n{}",
        divs.join("\n")
    );
    eprintln!("strftime specifier fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
