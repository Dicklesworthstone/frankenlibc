#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc timegm oracle (libc, linked by std)

//! Randomized wide-range differential fuzzer for `timegm` vs host glibc. timegm
//! normalizes a (possibly out-of-range) broken-down UTC time IN PLACE and returns
//! the epoch. The existing conformance_diff_timegm_normalize is fixed-case; this
//! sweeps random tm structs with out-of-range fields (tm_mon, tm_mday, tm_hour,
//! tm_min, tm_sec well outside their normal ranges, incl. negatives) across a
//! wide year span, comparing BOTH the returned epoch AND every normalized struct
//! tm field written back.

use std::ffi::c_int;

use frankenlibc_abi::time_abi::timegm as fl_timegm;

unsafe extern "C" {
    fn timegm(tm: *mut libc::tm) -> i64;
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
    fn range(&mut self, lo: i64, hi: i64) -> i32 {
        (lo + (self.next() % (hi - lo + 1) as u64) as i64) as i32
    }
}

#[derive(PartialEq, Eq, Debug)]
struct Out {
    ret: i64,
    f: [c_int; 8],
}

fn run(g: unsafe extern "C" fn(*mut libc::tm) -> i64, fields: [c_int; 6]) -> Out {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_sec = fields[0];
    tm.tm_min = fields[1];
    tm.tm_hour = fields[2];
    tm.tm_mday = fields[3];
    tm.tm_mon = fields[4];
    tm.tm_year = fields[5];
    tm.tm_isdst = 0;
    let ret = unsafe { g(&mut tm) };
    Out {
        ret,
        f: [
            tm.tm_sec, tm.tm_min, tm.tm_hour, tm.tm_mday, tm.tm_mon, tm.tm_year, tm.tm_wday,
            tm.tm_yday,
        ],
    }
}

#[test]
fn timegm_wide_range_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x7469_6d65_676d_0001);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..300_000 {
        // Out-of-range fields force the normalization paths; wide year span.
        let fields = [
            r.range(-120, 180),         // tm_sec
            r.range(-120, 180),         // tm_min
            r.range(-50, 80),           // tm_hour
            r.range(-40, 70),           // tm_mday
            r.range(-30, 40),           // tm_mon
            r.range(-2000, 1_000_000),  // tm_year (year - 1900)
        ];
        let fl = run(fl_timegm, fields);
        let host = run(timegm, fields);
        compared += 1;
        if fl != host && divs.len() < 40 {
            divs.push(format!(
                "fields(sec,min,hour,mday,mon,year)={fields:?}\n    fl   ={fl:?}\n    glibc={host:?}"
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "timegm diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("timegm wide-range fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
