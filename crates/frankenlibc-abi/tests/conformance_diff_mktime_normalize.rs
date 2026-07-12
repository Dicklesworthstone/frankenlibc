//! Differential gate: mktime() field normalization matches glibc (in UTC).
//!
//! mktime must normalize out-of-range tm fields (carry/borrow across
//! sec/min/hour/mday/mon/year) and write back the corrected fields plus
//! tm_wday/tm_yday. fl implements UTC-only time, so we pin glibc to TZ=UTC and
//! compare the returned epoch and every normalized field across a battery of
//! in- and out-of-range inputs.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::time_abi as fl;

unsafe extern "C" {
    fn tzset();
}

fn mk(year: i32, mon: i32, mday: i32, hour: i32, min: i32, sec: i32) -> libc::tm {
    let mut t: libc::tm = unsafe { std::mem::zeroed() };
    t.tm_year = year - 1900;
    t.tm_mon = mon;
    t.tm_mday = mday;
    t.tm_hour = hour;
    t.tm_min = min;
    t.tm_sec = sec;
    t.tm_isdst = 0;
    t
}

fn fields(t: &libc::tm) -> (i32, i32, i32, i32, i32, i32, i32, i32) {
    (
        t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, t.tm_wday, t.tm_yday,
    )
}

#[test]
fn mktime_normalization_matches_glibc_utc() {
    // Force UTC so glibc's local-time mktime matches fl's UTC-only mktime.
    unsafe {
        std::env::set_var("TZ", "UTC");
        tzset();
    }

    let cases: &[libc::tm] = &[
        mk(2024, 0, 1, 0, 0, 0),      // ordinary
        mk(2021, 2, 14, 9, 30, 15),   // ordinary
        mk(2024, 1, 29, 12, 0, 0),    // leap day
        mk(2023, 1, 29, 12, 0, 0),    // Feb 29 in a non-leap year -> Mar 1
        mk(2024, 12, 1, 0, 0, 0),     // month 12 -> next year Jan
        mk(2024, 13, 1, 0, 0, 0),     // month 13 -> Feb next year
        mk(2024, -1, 15, 0, 0, 0),    // month -1 -> previous Dec
        mk(2024, 0, 0, 0, 0, 0),      // mday 0 -> last day of prev month
        mk(2024, 0, 32, 0, 0, 0),     // mday 32 -> Feb 1
        mk(2024, 0, 1, 25, 0, 0),     // hour 25 -> next day 01:00
        mk(2024, 0, 1, -1, 0, 0),     // hour -1 -> prev day 23:00
        mk(2024, 0, 1, 0, 0, 60),     // sec 60 -> next minute
        mk(2024, 0, 1, 0, 0, 61),     // sec 61
        mk(2024, 0, 1, 0, 70, 0),     // min 70 -> +1h10m
        mk(2024, 0, 1, 0, -5, -5),    // negative min+sec borrow
        mk(1969, 11, 31, 23, 59, 59), // just before the epoch (negative result)
        mk(1970, 0, 1, 0, 0, 0),      // the epoch
        mk(2000, 0, 1, 0, 0, 0),      // y2k
        mk(2038, 0, 19, 3, 14, 8),    // past the 32-bit wrap
        mk(2024, 5, 100, 0, 0, 0),    // large mday carry
    ];

    let mut mism = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        let mut tg = *c;
        let mut tf = *c;
        let eg = unsafe { libc::mktime(&mut tg) };
        let ef = unsafe { fl::mktime(&mut tf) };
        if eg != ef as libc::time_t || fields(&tg) != fields(&tf) {
            mism.push(format!(
                "case {i}: in y={} mon={} mday={} {}:{}:{}\n  glibc epoch={} fields={:?}\n  fl    epoch={} fields={:?}",
                c.tm_year + 1900, c.tm_mon, c.tm_mday, c.tm_hour, c.tm_min, c.tm_sec,
                eg, fields(&tg), ef, fields(&tf)
            ));
        }
    }
    assert!(
        mism.is_empty(),
        "mktime diverged from glibc (UTC):\n{}",
        mism.join("\n")
    );
}
