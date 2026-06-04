//! Differential probe: frankenlibc strptime vs glibc strptime over a battery
//! exercising century rules (%y), %I+%p 12-hour conversion, case-insensitive
//! name matching (%a/%A/%b/%B), %j, %C%y, partial consumption, and match
//! failures. Compares the directly-parsed fields (matched, bytes consumed,
//! year/mon/mday/hour/min/sec); tm_wday/tm_yday are intentionally excluded
//! because glibc *recomputes* them as a non-POSIX extension with quirky results
//! (e.g. yday=-1 or yday from a partial date). glibc reference captured from a
//! C strptime probe.

use std::ffi::c_char;

use frankenlibc_abi::time_abi;

fn run(input: &str, fmt: &str) -> String {
    // NUL-terminate.
    let mut ib = input.as_bytes().to_vec();
    ib.push(0);
    let mut fb = fmt.as_bytes().to_vec();
    fb.push(0);
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let r = unsafe {
        time_abi::strptime(
            ib.as_ptr() as *const c_char,
            fb.as_ptr() as *const c_char,
            &mut tm,
        )
    };
    if r.is_null() {
        return "0".to_string();
    }
    let consumed = (r as usize) - (ib.as_ptr() as usize);
    format!(
        "1 {} {} {} {} {} {} {}",
        consumed, tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec
    )
}

#[test]
fn strptime_differential_battery() {
    let cases: &[(&str, &str)] = &[
        ("2026-02-25", "%Y-%m-%d"),
        ("13:07:09", "%H:%M:%S"),
        ("25/02/26", "%d/%m/%y"),
        ("25/02/69", "%d/%m/%y"),
        ("25/02/68", "%d/%m/%y"),
        ("Jun 04 2026", "%b %d %Y"),
        ("June 4", "%B %d"),
        ("thu", "%a"),
        ("Thursday", "%A"),
        ("01:30 PM", "%I:%M %p"),
        ("12:00 AM", "%I:%M %p"),
        ("12:00 PM", "%I:%M %p"),
        ("155", "%j"),
        ("2026", "%Y"),
        ("  2026", "%Y"),
        ("xyz", "%Y"),
        ("2026-02", "%Y-%m-%d"),
        ("2026/02", "%Y-%m"),
        ("99", "%y"),
        ("00", "%y"),
        ("Jan", "%b"),
        ("DEC", "%b"),
        ("2026-06-04 extra", "%Y-%m-%d"),
        ("%", "%%"),
        ("13", "%H"),
        ("2026", "%C%y"),
        ("Tue Jun  4 13:07:09 2026", "%a %b %e %H:%M:%S %Y"),
    ];

    // glibc reference: "matched consumed year mon mday hour min sec" (or "0").
    let glibc: &[&str] = &[
        "1 10 126 1 25 0 0 0",
        "1 8 0 0 0 13 7 9",
        "1 8 126 1 25 0 0 0",
        "1 8 69 1 25 0 0 0",
        "1 8 168 1 25 0 0 0",
        "1 11 126 5 4 0 0 0",
        "1 6 0 5 4 0 0 0",
        "1 3 0 0 0 0 0 0",
        "1 8 0 0 0 0 0 0",
        "1 8 0 0 0 13 30 0",
        "1 8 0 0 0 0 0 0",
        "1 8 0 0 0 12 0 0",
        "1 3 0 0 0 0 0 0",
        "1 4 126 0 0 0 0 0",
        "1 6 126 0 0 0 0 0",
        "0",
        "0",
        "0",
        "1 2 99 0 0 0 0 0",
        "1 2 100 0 0 0 0 0",
        "1 3 0 0 0 0 0 0",
        "1 3 0 11 0 0 0 0",
        "1 10 126 5 4 0 0 0",
        "1 1 0 0 0 0 0 0",
        "1 2 0 0 0 13 0 0",
        "1 4 126 0 0 0 0 0",
        "1 24 126 5 4 13 7 9",
    ];

    assert_eq!(cases.len(), glibc.len(), "battery length mismatch");

    let mut diffs = Vec::new();
    for (i, &(input, fmt)) in cases.iter().enumerate() {
        let got = run(input, fmt);
        if got != glibc[i] {
            diffs.push(format!(
                "case {i}: input={input:?} fmt={fmt:?} -> frankenlibc={got:?} glibc={:?}",
                glibc[i]
            ));
        }
    }
    assert!(
        diffs.is_empty(),
        "strptime diverges from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}

fn run_z(input: &str) -> String {
    let mut ib = input.as_bytes().to_vec();
    ib.push(0);
    let fb = b"%z\0";
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let r = unsafe {
        time_abi::strptime(
            ib.as_ptr() as *const c_char,
            fb.as_ptr() as *const c_char,
            &mut tm,
        )
    };
    if r.is_null() {
        return "0".to_string();
    }
    let consumed = (r as usize) - (ib.as_ptr() as usize);
    format!("1 {} {}", consumed, tm.tm_gmtoff)
}

/// %z is a glibc extension with intricate rules; test consumed bytes + the
/// resulting tm_gmtoff against glibc (captured from a C probe).
#[test]
fn strptime_z_differential_battery() {
    let cases: &[&str] = &[
        "+0530", "+05:30", "+05", "+05:", "-0800", "+5", "Z", "+0560", "+1200",
        "-1259", "GMT", "+053012", "+2500", "z", "+1799", "+05 30",
    ];
    // glibc reference: "matched consumed gmtoff" (or "0").
    let glibc: &[&str] = &[
        "1 5 19800",
        "1 6 19800",
        "1 3 18000",
        "1 3 18000",
        "1 5 -28800",
        "0",
        "1 1 0",
        "0",
        "1 5 43200",
        "1 5 -46740",
        "0",
        "1 5 19800",
        "1 5 90000",
        "0",
        "0",
        "1 3 18000",
    ];
    assert_eq!(cases.len(), glibc.len(), "battery length mismatch");

    let mut diffs = Vec::new();
    for (i, &input) in cases.iter().enumerate() {
        let got = run_z(input);
        if got != glibc[i] {
            diffs.push(format!(
                "case {i}: input={input:?} -> frankenlibc={got:?} glibc={:?}",
                glibc[i]
            ));
        }
    }
    assert!(
        diffs.is_empty(),
        "strptime %z diverges from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
