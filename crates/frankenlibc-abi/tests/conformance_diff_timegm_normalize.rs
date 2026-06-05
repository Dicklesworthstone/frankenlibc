#![cfg(target_os = "linux")]

//! Differential conformance for `timegm` field NORMALIZATION vs host glibc.
//!
//! The existing time harness only feeds timegm/mktime already-normalized tm
//! structs (from gmtime_r of valid epochs). This probes the bug-prone inverse:
//! OUT-OF-RANGE broken-down fields (tm_mon>11 / <0, tm_mday=0/40, tm_hour=25,
//! negative sec/min, etc.) that timegm must normalize via carry/borrow. We
//! compare BOTH the returned epoch AND the normalized struct written back
//! (incl. tm_wday/tm_yday) against glibc, pinned to UTC0 so fl's UTC-only mktime
//! and glibc's TZ-independent timegm coincide.

use std::ffi::c_int;
use std::sync::Mutex;

use frankenlibc_abi::time_abi as fl;

unsafe extern "C" {
    fn tzset();
}

static TZ_LOCK: Mutex<()> = Mutex::new(());

fn base_tm() -> libc::tm {
    libc::tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 1,
        tm_mon: 0,
        tm_year: 100, // 2000
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: std::ptr::null(),
    }
}

/// A divergence record: which input, and the differing field.
fn cmp(tm: libc::tm, divs: &mut Vec<String>) {
    let mut fl_tm = tm;
    let mut lc_tm = tm;
    let fl_r = unsafe { fl::timegm(&mut fl_tm) };
    let lc_r = unsafe { libc::timegm(&mut lc_tm) };
    let label = format!(
        "y={} mon={} mday={} h={} m={} s={}",
        tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec
    );
    if fl_r != lc_r {
        divs.push(format!("  [{label}] epoch: fl={fl_r} glibc={lc_r}"));
        return; // field comparison only meaningful when epoch agrees
    }
    let fields: &[(&str, c_int, c_int)] = &[
        ("tm_sec", fl_tm.tm_sec, lc_tm.tm_sec),
        ("tm_min", fl_tm.tm_min, lc_tm.tm_min),
        ("tm_hour", fl_tm.tm_hour, lc_tm.tm_hour),
        ("tm_mday", fl_tm.tm_mday, lc_tm.tm_mday),
        ("tm_mon", fl_tm.tm_mon, lc_tm.tm_mon),
        ("tm_year", fl_tm.tm_year, lc_tm.tm_year),
        ("tm_wday", fl_tm.tm_wday, lc_tm.tm_wday),
        ("tm_yday", fl_tm.tm_yday, lc_tm.tm_yday),
    ];
    for &(name, f, l) in fields {
        if f != l {
            divs.push(format!("  [{label}] {name}: fl={f} glibc={l}"));
        }
    }
}

#[test]
fn diff_timegm_out_of_range_normalization() {
    let _g = TZ_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        std::env::set_var("TZ", "UTC0");
        tzset();
    }

    let mut divs: Vec<String> = Vec::new();

    // Curated out-of-range fields (carry/borrow stress).
    let mons = [-25, -13, -12, -1, 0, 11, 12, 13, 24, 25];
    let mdays = [-30, -1, 0, 1, 28, 29, 30, 31, 32, 40, 60, 366];
    let hours = [-25, -1, 0, 23, 24, 25, 48];
    let secs = [-3600, -61, -1, 0, 59, 60, 61, 3600];

    for &mon in &mons {
        for &mday in &mdays {
            let mut tm = base_tm();
            tm.tm_mon = mon;
            tm.tm_mday = mday;
            cmp(tm, &mut divs);
        }
    }
    for &h in &hours {
        for &s in &secs {
            let mut tm = base_tm();
            tm.tm_hour = h;
            tm.tm_sec = s;
            tm.tm_min = s; // also exercise minute carry
            cmp(tm, &mut divs);
        }
    }

    // Deterministic random sweep across all fields, including negatives and
    // wide year range (leap-year boundaries).
    let mut state: u64 = 0x1234_5678_9abc_def1;
    let mut next = |lo: i64, hi: i64| -> c_int {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (lo + (state % ((hi - lo + 1) as u64)) as i64) as c_int
    };
    for _ in 0..200_000 {
        let mut tm = base_tm();
        tm.tm_year = next(1, 200); // 1901..2100
        tm.tm_mon = next(-20, 30);
        tm.tm_mday = next(-40, 70);
        tm.tm_hour = next(-30, 50);
        tm.tm_min = next(-70, 120);
        tm.tm_sec = next(-70, 120);
        cmp(tm, &mut divs);
    }

    unsafe {
        std::env::remove_var("TZ");
        tzset();
    }

    assert!(
        divs.is_empty(),
        "{} timegm normalization divergences vs glibc (first 30):\n{}",
        divs.len(),
        divs.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
