//! Differential probe: frankenlibc strftime vs glibc strftime (C locale) over
//! padding variants (%e/%k/%l/%d/%H), C-locale names (%a/%A/%b/%B/%c/%x/%X/%r),
//! AM/PM (%p/%P), day-of-year (%j), and the notoriously divergent ISO-week
//! family (%G/%g/%V/%U/%W) at year boundaries. glibc reference strings captured
//! from a C strftime probe with setlocale(LC_ALL,"C").

use frankenlibc_core::time::BrokenDownTime;
use frankenlibc_core::time::format_strftime;

fn bdt(
    sec: i32, min: i32, hour: i32, mday: i32, mon: i32, year: i32, wday: i32, yday: i32,
) -> BrokenDownTime {
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
    let t0 = bdt(9, 7, 13, 4, 5, 126, 4, 154);
    // t1: 2027-01-01 00:00:00 Friday (yday 0) — ISO week 53 of 2026
    let t1 = bdt(0, 0, 0, 1, 0, 127, 5, 0);
    // t2: 2024-12-30 23:59:60 Monday (yday 364) — ISO week 1 of 2025, leap second
    let t2 = bdt(60, 59, 23, 30, 11, 124, 1, 364);

    let cases: &[(&BrokenDownTime, &str)] = &[
        (&t0, "%Y"), (&t0, "%y"), (&t0, "%C"), (&t0, "%m"), (&t0, "%d"), (&t0, "%e"),
        (&t0, "%H"), (&t0, "%I"), (&t0, "%M"), (&t0, "%S"), (&t0, "%p"), (&t0, "%P"),
        (&t0, "%A"), (&t0, "%a"), (&t0, "%B"), (&t0, "%b"), (&t0, "%h"), (&t0, "%j"),
        (&t0, "%u"), (&t0, "%w"), (&t0, "%k"), (&t0, "%l"),
        (&t0, "%D"), (&t0, "%F"), (&t0, "%T"), (&t0, "%R"), (&t0, "%r"),
        (&t0, "%c"), (&t0, "%x"), (&t0, "%X"), (&t0, "%n%t%%"),
        (&t0, "%G"), (&t0, "%g"), (&t0, "%V"), (&t0, "%U"), (&t0, "%W"),
        (&t0, "[%Y-%m-%dT%H:%M:%S]"),
        (&t1, "%G"), (&t1, "%g"), (&t1, "%V"), (&t1, "%U"), (&t1, "%W"), (&t1, "%a"), (&t1, "%A"),
        (&t1, "%j"), (&t1, "%u"), (&t1, "%w"),
        (&t2, "%G"), (&t2, "%g"), (&t2, "%V"), (&t2, "%U"), (&t2, "%W"), (&t2, "%S"),
        (&t2, "%j"), (&t2, "%a"), (&t2, "%B"),
    ];

    // glibc reference (C locale), captured from a C strftime probe.
    let glibc: &[&str] = &[
        "2026", "26", "20", "06", "04", " 4",
        "13", "01", "07", "09", "PM", "pm",
        "Thursday", "Thu", "June", "Jun", "Jun", "155",
        "4", "4", "13", " 1",
        "06/04/26", "2026-06-04", "13:07:09", "13:07", "01:07:09 PM",
        "Thu Jun  4 13:07:09 2026", "06/04/26", "13:07:09", "\n\t%",
        "2026", "26", "23", "22", "22",
        "[2026-06-04T13:07:09]",
        "2026", "26", "53", "00", "00", "Fri", "Friday",
        "001", "5", "5",
        "2025", "25", "01", "52", "53", "60",
        "365", "Mon", "December",
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
