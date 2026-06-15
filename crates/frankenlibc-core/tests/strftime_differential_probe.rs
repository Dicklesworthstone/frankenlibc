//! Differential probe: frankenlibc strftime vs glibc strftime (C locale) over
//! padding variants (%e/%k/%l/%d/%H), C-locale names (%a/%A/%b/%B/%c/%x/%X/%r),
//! AM/PM (%p/%P), day-of-year (%j), and the notoriously divergent ISO-week
//! family (%G/%g/%V/%U/%W) at year boundaries. glibc reference strings captured
//! from a C strftime probe with setlocale(LC_ALL,"C").

use frankenlibc_core::time::BrokenDownTime;
use frankenlibc_core::time::format_strftime;

fn bdt(fields: [i32; 8]) -> BrokenDownTime {
    let [sec, min, hour, mday, mon, year, wday, yday] = fields;
    BrokenDownTime {
        tm_sec: sec,
        tm_min: min,
        tm_hour: hour,
        tm_mday: mday,
        tm_mon: mon,
        tm_year: year,
        tm_wday: wday,
        tm_yday: yday,
        tm_isdst: 0,
        tm_gmtoff: 0,
        zone: [0; 16],
    }
}

fn render(fmt: &str, bd: &BrokenDownTime) -> String {
    let mut buf = vec![0u8; 256];
    let n = format_strftime(fmt.as_bytes(), bd, &mut buf);
    String::from_utf8(buf[..n].to_vec()).expect("utf8")
}

#[test]
fn strftime_differential_battery() {
    // t0: 2026-06-04 13:07:09 Thursday (yday 154)
    let t0 = bdt([9, 7, 13, 4, 5, 126, 4, 154]);
    // t1: 2027-01-01 00:00:00 Friday (yday 0) — ISO week 53 of 2026
    let t1 = bdt([0, 0, 0, 1, 0, 127, 5, 0]);
    // t2: 2024-12-30 23:59:60 Monday (yday 364) — ISO week 1 of 2025, leap second
    let t2 = bdt([60, 59, 23, 30, 11, 124, 1, 364]);

    let cases: &[(&BrokenDownTime, &str)] = &[
        (&t0, "%Y"),
        (&t0, "%y"),
        (&t0, "%C"),
        (&t0, "%m"),
        (&t0, "%d"),
        (&t0, "%e"),
        (&t0, "%H"),
        (&t0, "%I"),
        (&t0, "%M"),
        (&t0, "%S"),
        (&t0, "%p"),
        (&t0, "%P"),
        (&t0, "%A"),
        (&t0, "%a"),
        (&t0, "%B"),
        (&t0, "%b"),
        (&t0, "%h"),
        (&t0, "%j"),
        (&t0, "%u"),
        (&t0, "%w"),
        (&t0, "%k"),
        (&t0, "%l"),
        (&t0, "%D"),
        (&t0, "%F"),
        (&t0, "%T"),
        (&t0, "%R"),
        (&t0, "%r"),
        (&t0, "%c"),
        (&t0, "%x"),
        (&t0, "%X"),
        (&t0, "%n%t%%"),
        (&t0, "%G"),
        (&t0, "%g"),
        (&t0, "%V"),
        (&t0, "%U"),
        (&t0, "%W"),
        (&t0, "[%Y-%m-%dT%H:%M:%S]"),
        (&t1, "%G"),
        (&t1, "%g"),
        (&t1, "%V"),
        (&t1, "%U"),
        (&t1, "%W"),
        (&t1, "%a"),
        (&t1, "%A"),
        (&t1, "%j"),
        (&t1, "%u"),
        (&t1, "%w"),
        (&t2, "%G"),
        (&t2, "%g"),
        (&t2, "%V"),
        (&t2, "%U"),
        (&t2, "%W"),
        (&t2, "%S"),
        (&t2, "%j"),
        (&t2, "%a"),
        (&t2, "%B"),
    ];

    // glibc reference (C locale), captured from a C strftime probe.
    let glibc: &[&str] = &[
        "2026",
        "26",
        "20",
        "06",
        "04",
        " 4",
        "13",
        "01",
        "07",
        "09",
        "PM",
        "pm",
        "Thursday",
        "Thu",
        "June",
        "Jun",
        "Jun",
        "155",
        "4",
        "4",
        "13",
        " 1",
        "06/04/26",
        "2026-06-04",
        "13:07:09",
        "13:07",
        "01:07:09 PM",
        "Thu Jun  4 13:07:09 2026",
        "06/04/26",
        "13:07:09",
        "\n\t%",
        "2026",
        "26",
        "23",
        "22",
        "22",
        "[2026-06-04T13:07:09]",
        "2026",
        "26",
        "53",
        "00",
        "00",
        "Fri",
        "Friday",
        "001",
        "5",
        "5",
        "2025",
        "25",
        "01",
        "52",
        "53",
        "60",
        "365",
        "Mon",
        "December",
    ];

    assert_eq!(cases.len(), glibc.len(), "battery length mismatch");

    let mut diffs = Vec::new();
    for (i, &(bd, fmt)) in cases.iter().enumerate() {
        let got = render(fmt, bd);
        if got != glibc[i] {
            diffs.push(format!(
                "case {i}: fmt={fmt:?} -> frankenlibc={got:?} glibc={:?}",
                glibc[i]
            ));
        }
    }
    assert!(
        diffs.is_empty(),
        "strftime diverges from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}

/// Live differential sweep: render every common specifier against the host glibc
/// `strftime` over a structured calendar sweep (100 years × 12 months × day/week
/// boundaries), normalizing each date through `timegm`/`gmtime_r` so `tm_wday`
/// and `tm_yday` are exact. Targets the ISO-week family (`%G/%g/%V` and `%U/%W`)
/// at year boundaries where week/year ownership flips — the classic divergence.
#[test]
#[allow(unsafe_code)] // live FFI to host glibc strftime/timegm/gmtime_r for the oracle
fn strftime_live_differential_sweep() {
    #[repr(C)]
    struct CTm {
        sec: i32,
        min: i32,
        hour: i32,
        mday: i32,
        mon: i32,
        year: i32,
        wday: i32,
        yday: i32,
        isdst: i32,
        gmtoff: i64,
        zone: *const u8,
    }
    unsafe extern "C" {
        fn setlocale(category: i32, locale: *const u8) -> *const u8;
        fn timegm(tm: *mut CTm) -> i64;
        fn gmtime_r(t: *const i64, tm: *mut CTm) -> *mut CTm;
        fn strftime(s: *mut u8, max: usize, fmt: *const u8, tm: *const CTm) -> usize;
    }
    // LC_ALL == 6 on glibc; the strftime probe is defined for the C locale.
    unsafe {
        setlocale(6, c"C".as_ptr().cast());
    }

    // Timezone-independent specifiers only (skip %Z/%z/%s which depend on tm_gmtoff).
    let specs: &[&str] = &[
        "%a",
        "%A",
        "%b",
        "%B",
        "%c",
        "%C",
        "%d",
        "%D",
        "%e",
        "%F",
        "%G",
        "%g",
        "%h",
        "%H",
        "%I",
        "%j",
        "%k",
        "%l",
        "%m",
        "%M",
        "%n",
        "%p",
        "%P",
        "%r",
        "%R",
        "%S",
        "%T",
        "%u",
        "%U",
        "%V",
        "%w",
        "%W",
        "%x",
        "%X",
        "%y",
        "%Y",
        "%%",
        "%G-W%V-%u",
        "%Y-%j",
    ];

    let new_tm = || CTm {
        sec: 0,
        min: 0,
        hour: 0,
        mday: 0,
        mon: 0,
        year: 0,
        wday: 0,
        yday: 0,
        isdst: 0,
        gmtoff: 0,
        zone: core::ptr::null(),
    };

    let mut diffs: Vec<String> = Vec::new();
    let mut checked: u64 = 0;
    'outer: for year in 1950i32..2050 {
        for mon in 0i32..12 {
            for &mday in &[1i32, 2, 3, 4, 5, 6, 7, 15, 27, 28, 29, 30, 31] {
                let mut tm = new_tm();
                tm.sec = 30;
                tm.min = 45;
                tm.hour = 13;
                tm.mday = mday;
                tm.mon = mon;
                tm.year = year - 1900;
                let t = unsafe { timegm(&mut tm as *mut CTm) };
                let mut norm = new_tm();
                let r = unsafe { gmtime_r(&t as *const i64, &mut norm as *mut CTm) };
                if r.is_null() {
                    continue;
                }
                let bd = BrokenDownTime {
                    tm_sec: norm.sec,
                    tm_min: norm.min,
                    tm_hour: norm.hour,
                    tm_mday: norm.mday,
                    tm_mon: norm.mon,
                    tm_year: norm.year,
                    tm_wday: norm.wday,
                    tm_yday: norm.yday,
                    tm_isdst: 0,
                    tm_gmtoff: 0,
                    zone: [0; 16],
                };
                for &fmt in specs {
                    let mut gbuf = [0u8; 256];
                    let mut cfmt = fmt.as_bytes().to_vec();
                    cfmt.push(0);
                    let gn = unsafe {
                        strftime(gbuf.as_mut_ptr(), 256, cfmt.as_ptr(), &norm as *const CTm)
                    };
                    let g = String::from_utf8_lossy(&gbuf[..gn]).into_owned();
                    let f = render(fmt, &bd);
                    checked += 1;
                    if f != g {
                        diffs.push(format!(
                            "{:04}-{:02}-{:02} (wday={}, yday={}) fmt={fmt:?} -> fl={f:?} glibc={g:?}",
                            norm.year + 1900,
                            norm.mon + 1,
                            norm.mday,
                            norm.wday,
                            norm.yday
                        ));
                        if diffs.len() >= 40 {
                            break 'outer;
                        }
                    }
                }
            }
        }
    }
    eprintln!(
        "strftime live sweep: {checked} comparisons, {} divergence(s)",
        diffs.len()
    );
    assert!(
        diffs.is_empty(),
        "strftime live-differential divergences ({}):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
