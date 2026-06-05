//! Differential probe: frankenlibc format_strftime tight-buffer / truncation
//! behavior vs glibc strftime. glibc returns 0 (and leaves the buffer
//! undefined) unless the formatted result PLUS the terminating NUL fits in
//! maxsize; otherwise it returns the byte count (excluding NUL). This exercises
//! the exact off-by-one boundary (content N needs buffer >= N+1) that the
//! 256-byte core strftime test never hit. glibc reference captured from a C
//! probe.

use frankenlibc_core::time::BrokenDownTime;
use frankenlibc_core::time::format_strftime;

fn t0() -> BrokenDownTime {
    BrokenDownTime {
        tm_sec: 9,
        tm_min: 7,
        tm_hour: 13,
        tm_mday: 4,
        tm_mon: 5,
        tm_year: 126,
        tm_wday: 4,
        tm_yday: 154,
        tm_isdst: 0,
    }
}

fn run(fmt: &str, maxsize: usize) -> String {
    let bd = t0();
    let mut buf = vec![b'#'; maxsize];
    let n = format_strftime(fmt.as_bytes(), &bd, &mut buf);
    if n > 0 {
        format!("{n}:{}", String::from_utf8_lossy(&buf[..n]))
    } else {
        "0".to_string()
    }
}

#[test]
fn strftime_buffer_truncation_differential() {
    // (fmt, maxsize, glibc result) — "0" or "<n>:<string>".
    let cases: &[(&str, usize, &str)] = &[
        ("%Y", 0, "0"),
        ("%Y", 1, "0"),
        ("%Y", 4, "0"),
        ("%Y", 5, "4:2026"),
        ("%Y", 10, "4:2026"),
        ("%T", 8, "0"),
        ("%T", 9, "8:13:07:09"),
        ("%T", 100, "8:13:07:09"),
        ("%%", 1, "0"),
        ("%%", 2, "1:%"),
        ("", 1, "0"),
        ("", 0, "0"),
        ("abc", 3, "0"),
        ("abc", 4, "3:abc"),
        ("%Y-%m-%d", 10, "0"),
        ("%Y-%m-%d", 11, "10:2026-06-04"),
        ("x%Yx", 6, "0"),
        ("x%Yx", 7, "6:x2026x"),
    ];

    let mut diffs = Vec::new();
    for (fmt, maxsize, expected) in cases {
        let got = run(fmt, *maxsize);
        if got != *expected {
            diffs.push(format!(
                "strftime({fmt:?}, max={maxsize}): frankenlibc={got:?} glibc={expected:?}"
            ));
        }
    }
    assert!(
        diffs.is_empty(),
        "strftime buffer/truncation diverges from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
