#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc gmtime_r oracle (libc, linked by std)

//! Randomized wide-range differential fuzzer for `gmtime_r` vs host glibc. The
//! existing conformance_diff_time uses a fixed epoch list; this sweeps the full
//! i64 epoch space — heavily biased toward the OVERFLOW BOUNDARY where the year
//! stops fitting `tm_year` (a c_int) and glibc must return NULL — comparing both
//! the NULL-return decision and every `struct tm` field.

use std::ffi::c_int;

use frankenlibc_abi::time_abi::gmtime_r as fl_gmtime_r;

unsafe extern "C" {
    fn gmtime_r(timer: *const i64, result: *mut libc::tm) -> *mut libc::tm;
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

#[derive(PartialEq, Eq, Debug)]
struct Tm {
    null: bool,
    f: [c_int; 8],
}

fn run(g: unsafe extern "C" fn(*const i64, *mut libc::tm) -> *mut libc::tm, epoch: i64) -> Tm {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let r = unsafe { g(&epoch, &mut tm) };
    if r.is_null() {
        Tm {
            null: true,
            f: [0; 8],
        }
    } else {
        Tm {
            null: false,
            f: [
                tm.tm_sec, tm.tm_min, tm.tm_hour, tm.tm_mday, tm.tm_mon, tm.tm_year, tm.tm_wday,
                tm.tm_yday,
            ],
        }
    }
}

/// A random epoch, heavily biased toward the year-overflow boundary
/// (~±6.78e16 s) and the absolute extremes.
fn gen_epoch(r: &mut Lcg) -> i64 {
    match r.next() % 8 {
        0 => 0,
        1 => i64::MAX,
        2 => i64::MIN,
        3 => (r.next() % 4_000_000_000) as i64 - 2_000_000_000, // normal +/- range
        4 | 5 => {
            // Near the +/- year-overflow boundary (glibc cutoff is around here).
            let base: i64 = 67_768_036_191_676_800;
            let jitter = (r.next() % 200_000_000) as i64 - 100_000_000;
            let v = base + jitter;
            if r.next() & 1 == 0 { v } else { -v }
        }
        _ => r.next() as i64, // any 64-bit pattern
    }
}

#[test]
fn gmtime_r_wide_range_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x6770_7469_6d65_0001);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..400_000 {
        let epoch = gen_epoch(&mut r);
        let fl = run(fl_gmtime_r, epoch);
        let host = run(gmtime_r, epoch);
        compared += 1;
        if fl != host && divs.len() < 40 {
            divs.push(format!(
                "epoch={epoch}\n    fl   ={fl:?}\n    glibc={host:?}"
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "gmtime_r diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("gmtime_r wide-range fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
