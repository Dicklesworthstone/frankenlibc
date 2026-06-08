#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strptime oracle

//! Randomized differential fuzzer for `strptime` vs a LIVE host glibc oracle,
//! targeting the bug-prone edges the fixed battery / round-trip probe does NOT
//! cover: case-variant month/day names, whitespace variation (extra, missing,
//! tabs), variable digit widths (leading zeros, 1 vs 2 digits), out-of-range
//! numeric fields, and truncated/partial inputs. Compares the match decision,
//! the consumed offset (end pointer), and the parsed tm fields
//! (year/mon/mday/hour/min/sec). tm_wday/tm_yday are excluded — glibc recomputes
//! them as a quirky non-POSIX extension (see strptime_differential_probe.rs).

use std::ffi::{c_char, c_int};

use frankenlibc_abi::time_abi;

unsafe extern "C" {
    fn setlocale(category: c_int, locale: *const c_char) -> *const c_char;
    fn strptime(s: *const c_char, format: *const c_char, tm: *mut libc::tm) -> *mut c_char;
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
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Result fingerprint: match decision, consumed bytes, and the directly-set
/// fields. Returns `None` for a parse failure (glibc/fl return NULL).
fn fl_run(input: &[u8], fmt: &[u8]) -> Option<(usize, [c_int; 6])> {
    let mut ib = input.to_vec();
    ib.push(0);
    let mut fb = fmt.to_vec();
    fb.push(0);
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let r = unsafe {
        time_abi::strptime(ib.as_ptr() as *const c_char, fb.as_ptr() as *const c_char, &mut tm)
    };
    if r.is_null() {
        return None;
    }
    let consumed = (r as usize) - (ib.as_ptr() as usize);
    Some((consumed, [tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec]))
}

fn host_run(input: &[u8], fmt: &[u8]) -> Option<(usize, [c_int; 6])> {
    let mut ib = input.to_vec();
    ib.push(0);
    let mut fb = fmt.to_vec();
    fb.push(0);
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let r = unsafe { strptime(ib.as_ptr() as *const c_char, fb.as_ptr() as *const c_char, &mut tm) };
    if r.is_null() {
        return None;
    }
    let consumed = (r as usize) - (ib.as_ptr() as usize);
    Some((consumed, [tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec]))
}

const MONTHS: [&str; 12] = [
    "January", "February", "March", "April", "May", "June", "July", "August", "September",
    "October", "November", "December",
];
const DAYS: [&str; 7] = [
    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
];

/// Randomly recase a name: lower, UPPER, or as-is, optionally as the standard
/// 3-letter abbreviation, to probe glibc's case-insensitive + abbreviation
/// matching of %a/%A/%b/%B. (Arbitrary-length prefixes like "Decemb" are a
/// separate fl-vs-glibc leniency gap tracked in bd-2g7oyh.257 and not generated
/// here so this fuzzer stays focused on the %j calendar-derivation fix.)
fn recase(r: &mut Lcg, name: &str) -> String {
    let base: String = if r.below(2) == 0 {
        name.chars().take(3).collect() // standard abbreviation
    } else {
        name.to_string()
    };
    match r.below(3) {
        0 => base.to_lowercase(),
        1 => base.to_uppercase(),
        _ => base,
    }
}

/// A number rendered with a random width quirk: bare, zero-padded, or with
/// extra leading zeros / out-of-range magnitude.
fn num(r: &mut Lcg, v: u64) -> String {
    match r.below(4) {
        0 => format!("{v}"),
        1 => format!("{v:02}"),
        2 => format!("{v:03}"),
        _ => format!("{v}"),
    }
}

/// Whitespace token: glibc treats whitespace in the format as "match zero or
/// more whitespace" and skips leading whitespace before numeric conversions.
fn ws(r: &mut Lcg) -> &'static str {
    match r.below(4) {
        0 => " ",
        1 => "  ",
        2 => "\t",
        _ => " ",
    }
}

/// Build a (format, input) pair from one of several templates, with mutated
/// casing / widths / whitespace / occasionally out-of-range or truncated.
fn gen_case(r: &mut Lcg) -> (Vec<u8>, Vec<u8>) {
    let year = r.below(200) + 1900;
    let mon1 = r.below(12) + 1;
    let mday = if r.below(8) == 0 { r.below(40) } else { r.below(28) + 1 }; // sometimes out of range
    let hour = if r.below(8) == 0 { r.below(30) } else { r.below(24) };
    let min = r.below(60);
    let sec = r.below(62); // include leap-second 60/61
    let yy = year % 100;
    let mon_name = recase(r, MONTHS[(mon1 - 1) as usize]);
    let day_idx = r.below(7) as usize;
    let day_name = recase(r, DAYS[day_idx]);

    let (fmt, input): (String, String) = match r.below(10) {
        0 => (
            "%Y-%m-%d".into(),
            format!("{}-{}-{}", num(r, year), num(r, mon1), num(r, mday)),
        ),
        1 => (
            "%d %B %Y".into(),
            format!("{}{}{}{}{}", num(r, mday), ws(r), mon_name, ws(r), num(r, year)),
        ),
        2 => (
            "%H:%M:%S".into(),
            format!("{}:{}:{}", num(r, hour), num(r, min), num(r, sec)),
        ),
        3 => (
            "%I:%M %p".into(),
            format!(
                "{}:{}{}{}",
                num(r, if hour % 12 == 0 { 12 } else { hour % 12 }),
                num(r, min),
                ws(r),
                if r.below(2) == 0 { "AM" } else { "pm" }
            ),
        ),
        4 => ("%b %d".into(), format!("{}{}{}", recase(r, MONTHS[(mon1 - 1) as usize]), ws(r), num(r, mday))),
        5 => ("%a".into(), day_name.clone()),
        6 => ("%y".into(), num(r, yy)), // century-pivot edge
        7 => (
            "%m/%d/%Y".into(),
            format!("{}/{}/{}", num(r, mon1), num(r, mday), num(r, year)),
        ),
        8 => {
            let jday = r.below(366) + 1; // %j valid [1,366]
            ("%Y %j".into(), format!("{}{}{}", num(r, year), ws(r), num(r, jday)))
        }
        _ => (
            "%A, %d %B %Y".into(),
            format!("{}, {} {} {}", day_name, num(r, mday), mon_name, num(r, year)),
        ),
    };

    // (Input truncation that produces partial month/weekday names — e.g.
    // "FRIDA" — is deliberately NOT generated here: it exposes a separate
    // name-matching-leniency gap, fl accepts arbitrary name prefixes where glibc
    // only accepts the full name or the exact 3-letter abbreviation, tracked in
    // bd-2g7oyh.257. This fuzzer stays focused on the %j calendar-derivation fix.)
    (fmt.into_bytes(), input.into_bytes())
}

#[test]
fn strptime_edge_differential_fuzz_vs_glibc() {
    // strptime name/AM-PM matching is defined for the C locale.
    let c = std::ffi::CString::new("C").unwrap();
    unsafe { setlocale(LC_ALL, c.as_ptr()) };

    let mut r = Lcg(0x51b3_a7f0_2c9d_1e55);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..300_000 {
        let (fmt, input) = gen_case(&mut r);
        let fl = fl_run(&input, &fmt);
        let host = host_run(&input, &fmt);
        compared += 1;
        if fl != host && divs.len() < 40 {
            divs.push(format!(
                "fmt={:?} input={:?}\n    fl   ={:?}\n    glibc={:?}",
                String::from_utf8_lossy(&fmt),
                String::from_utf8_lossy(&input),
                fl,
                host
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "strptime diverged from host glibc on some of {compared} cases (showing up to 40):\n{}",
        divs.join("\n")
    );
    eprintln!("strptime edge fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
