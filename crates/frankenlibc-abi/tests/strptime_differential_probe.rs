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
        "+0530", "+05:30", "+05", "+05:", "-0800", "+5", "Z", "+0560", "+1200", "-1259", "GMT",
        "+053012", "+2500", "z", "+1799", "+05 30",
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

/// Live round-trip differential: for a structured calendar sweep, format each
/// date with the host glibc `strftime` to obtain a well-formed input string, then
/// parse it with BOTH frankenlibc `strptime` and host glibc `strptime`, comparing
/// the match result, bytes consumed, and the six core fields (tm_wday/tm_yday are
/// excluded — glibc recomputes them as a quirky non-POSIX extension). Covers the
/// %y century rule, %I+%p 12-hour conversion, %b/%B/%a name matching, and
/// multi-field composites across ~1968 dates × many formats.
#[test]
fn strptime_live_roundtrip_vs_glibc() {
    unsafe extern "C" {
        fn setlocale(category: i32, locale: *const c_char) -> *const c_char;
        fn timegm(tm: *mut libc::tm) -> libc::time_t;
        fn gmtime_r(t: *const libc::time_t, tm: *mut libc::tm) -> *mut libc::tm;
        fn strftime(s: *mut c_char, max: usize, fmt: *const c_char, tm: *const libc::tm) -> usize;
        fn strptime(s: *const c_char, fmt: *const c_char, tm: *mut libc::tm) -> *mut c_char;
    }
    unsafe {
        setlocale(6, b"C\0".as_ptr() as *const c_char);
    }

    // Symmetric specifiers whose strftime output strptime parses back into the six
    // compared fields (avoid %j/%V/%G which only touch the excluded yday/wday).
    let fmts: &[&str] = &[
        "%Y-%m-%d",
        "%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%d/%m/%y",
        "%m/%d/%Y",
        "%b %d %Y",
        "%B %d, %Y",
        "%I:%M:%S %p",
        "%T",
        "%F",
        "%R",
        "%a %b %e %H:%M:%S %Y",
        "%Y%m%d",
        "%y-%m-%d %I:%M %p",
    ];

    let fields = |t: &libc::tm| {
        (
            t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec,
        )
    };

    let mut diffs: Vec<String> = Vec::new();
    let mut checked: u64 = 0;
    'outer: for year in 1970i32..2038 {
        for mon in 0i32..12 {
            for &mday in &[1i32, 9, 15, 28] {
                for &(h, mi, s) in &[(0i32, 0i32, 0i32), (13, 45, 30), (23, 59, 59), (9, 5, 7)] {
                    let mut base: libc::tm = unsafe { std::mem::zeroed() };
                    base.tm_year = year - 1900;
                    base.tm_mon = mon;
                    base.tm_mday = mday;
                    base.tm_hour = h;
                    base.tm_min = mi;
                    base.tm_sec = s;
                    let t = unsafe { timegm(&mut base) };
                    let mut norm: libc::tm = unsafe { std::mem::zeroed() };
                    if unsafe { gmtime_r(&t, &mut norm) }.is_null() {
                        continue;
                    }
                    for &fmt in fmts {
                        let mut cfmt = fmt.as_bytes().to_vec();
                        cfmt.push(0);
                        let mut sbuf = [0u8; 128];
                        let n = unsafe {
                            strftime(
                                sbuf.as_mut_ptr() as *mut c_char,
                                128,
                                cfmt.as_ptr() as *const c_char,
                                &norm,
                            )
                        };
                        if n == 0 {
                            continue;
                        }
                        let mut input = sbuf[..n].to_vec();
                        input.push(0);

                        let mut tf: libc::tm = unsafe { std::mem::zeroed() };
                        let mut tg: libc::tm = unsafe { std::mem::zeroed() };
                        let rf = unsafe {
                            time_abi::strptime(
                                input.as_ptr() as *const c_char,
                                cfmt.as_ptr() as *const c_char,
                                &mut tf,
                            )
                        };
                        let rg = unsafe {
                            strptime(
                                input.as_ptr() as *const c_char,
                                cfmt.as_ptr() as *const c_char,
                                &mut tg,
                            )
                        };
                        let cf = if rf.is_null() {
                            -1i64
                        } else {
                            (rf as usize - input.as_ptr() as usize) as i64
                        };
                        let cg = if rg.is_null() {
                            -1i64
                        } else {
                            (rg as usize - input.as_ptr() as usize) as i64
                        };
                        checked += 1;
                        if cf != cg || fields(&tf) != fields(&tg) {
                            diffs.push(format!(
                                "fmt={fmt:?} input={:?} -> fl(consumed={cf}, {:?}) glibc(consumed={cg}, {:?})",
                                String::from_utf8_lossy(&input[..n]),
                                fields(&tf),
                                fields(&tg),
                            ));
                            if diffs.len() >= 40 {
                                break 'outer;
                            }
                        }
                    }
                }
            }
        }
    }
    eprintln!(
        "strptime live roundtrip: {checked} comparisons, {} divergence(s)",
        diffs.len()
    );
    assert!(
        diffs.is_empty(),
        "strptime live round-trip divergences ({}):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
