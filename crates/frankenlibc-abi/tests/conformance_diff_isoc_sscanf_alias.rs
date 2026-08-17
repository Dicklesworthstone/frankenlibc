#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // variadic scanf calls + a counting global allocator

//! `__isoc99_sscanf` / `__isoc23_sscanf` must be `sscanf`, not a slower relative.
//!
//! ## Why these symbols and not `sscanf`
//!
//! No compiled C calls `sscanf`. `<stdio.h>` redirects the name: to
//! `__isoc99_sscanf` since glibc 2.7, and to `__isoc23_sscanf` under a C23
//! default (gcc 15). The plain symbol survives only for objects compiled long
//! ago and for code that calls it through a resolved pointer — which is what
//! every test in this repo and every benchmark arm had been doing.
//!
//! That split hid a real gap. `sscanf` carries a fast path
//! (`strict_decimal_int_format_count` + `strict_scan_decimal_ints`) that serves
//! pure-decimal-int formats without entering the parsing engine; both aliases
//! forwarded straight to `vsscanf` and got none of it. Measured with
//! `frankenlibc-bench/examples/sscanf_icount` on `sscanf("42", "%d")`:
//! **250 instructions per call through `sscanf`, 864 through the alias** — the
//! same call, 3.5x apart, and the expensive one is the only one a C program can
//! actually reach.
//!
//! ## The two properties, and which arm proves which
//!
//! 1. **ROUTING** — [`the_aliases_take_the_decimal_int_fast_path`]. Correctness
//!    alone cannot prove this: the fast path and the engine agree by
//!    construction, so a gate that only compares return values passes whether or
//!    not the routing exists. Allocation count separates them. The fast path
//!    fills a fixed `[c_int; 3]` and allocates nothing; the engine spills its
//!    directive list past the inline capacity and allocates. The test carries a
//!    POSITIVE CONTROL — a four-field format, which
//!    `strict_decimal_int_format_count` rejects by construction — so the zero it
//!    asserts is read against an observed non-zero from the same counter in the
//!    same process, not against an assumption that the counter works.
//!
//! 2. **CORRECTNESS** — [`the_aliases_agree_with_host_glibc`]. Both aliases are
//!    compared against the HOST `__isoc23_sscanf` through `dlsym`, on return
//!    code and on every value the return code says was written.

use std::ffi::{CString, c_char, c_int};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

#[path = "common/alloc_counter.rs"]
mod alloc_counter;
use alloc_counter::count_allocs;

#[global_allocator]
static ALLOCATOR: alloc_counter::Counting = alloc_counter::Counting;

type SscanfFn = unsafe extern "C" fn(*const c_char, *const c_char, ...) -> c_int;

/// The three fl entry points under test, plus the name each row prints.
fn fl_arms() -> [(&'static str, SscanfFn); 3] {
    [
        ("sscanf", frankenlibc_abi::stdio_abi::sscanf as SscanfFn),
        (
            "__isoc99_sscanf",
            frankenlibc_abi::stdio_abi::__isoc99_sscanf as SscanfFn,
        ),
        (
            "__isoc23_sscanf",
            frankenlibc_abi::isoc_abi::__isoc23_sscanf as SscanfFn,
        ),
    ]
}

/// Number of `int *` handed to every call. It is the widest conversion count in
/// [`CASES`], and it must never be less: passing three for the four-conversion
/// row had the callee read a fourth variadic argument that was never pushed,
/// which took the binary down with SIGSEGV. It happened a SECOND time when the
/// int fast path grew to four fields and the five-field control moved in without
/// a fifth pointer — a null-pointer abort that time. Extra pointers a format
/// never reads cost nothing, so one call shape for the whole table is both safe
/// and simpler.
const ARGS: usize = 5;

/// Call one entry point with [`ARGS`] `int *` and return `(rc, values)`.
fn scan_args(f: SscanfFn, input: &str, format: &str) -> (c_int, [c_int; ARGS]) {
    let cin = CString::new(input).expect("input has NUL");
    let cfmt = CString::new(format).expect("format has NUL");
    let mut v: [c_int; ARGS] = [-777; ARGS];
    // SAFETY: no format in the table has more than ARGS conversions, and ARGS
    // `int *` are supplied. Both strings are NUL-terminated across the call.
    let rc = unsafe {
        f(
            cin.as_ptr(),
            cfmt.as_ptr(),
            &mut v[0] as *mut c_int,
            &mut v[1] as *mut c_int,
            &mut v[2] as *mut c_int,
            &mut v[3] as *mut c_int,
            &mut v[4] as *mut c_int,
        )
    };
    (rc, v)
}

/// Cases that exercise the fast path and the ways it can decline.
///
/// Every format here must have at most [`ARGS`] conversions.
///
/// Integer OVERFLOW is deliberately absent: `%d` on a value outside `int` is
/// unspecified in C and glibc does not document what it stores, so a differential
/// row there would pin an accident rather than a contract.
///
/// So are WIDE conversions (`%ld`, `%lld`): every row here is called with
/// `int *`, and a `%ld` would have the callee write eight bytes into a four-byte
/// slot. That is not a hypothetical — it was in this table for one run and took
/// the binary down with SIGSEGV, which is the correct outcome for a test that
/// lies to a variadic callee about its argument types.
const CASES: &[(&str, &str)] = &[
    // Accepted by the fast path (one, two and three fields).
    ("42", "%d"),
    ("  42", "%d"),
    ("\t\n 5", "%d"),
    ("+42", "%d"),
    ("-42", "%d"),
    ("0012", "%d"),
    ("2147483647", "%d"),
    ("-2147483648", "%d"),
    ("1 2", "%d %d"),
    ("7 8 9", "%d %d %d"),
    // Accepted format, input that stops early — the paths that return EOF, a
    // matching failure, and a partial count.
    ("", "%d"),
    ("abc", "%d"),
    ("1 x", "%d %d"),
    ("7 8", "%d %d %d"),
    ("1,2", "%d %d"),
    ("   ", "%d"),
    ("-", "%d"),
    ("+", "%d"),
    // Four fields are now the WIDEST shape the fast path accepts, so this one
    // exercises the boundary rather than the fallback.
    ("1 2 3 4", "%d %d %d %d"),
    // Literal-separated int lists — the shape the fast path gained for IPv4,
    // dates and times. The declines matter as much as the matches.
    ("192.168.1.1", "%d.%d.%d.%d"),
    ("192.168.1", "%d.%d.%d.%d"),
    ("1/2/3", "%d/%d/%d"),
    ("11:22:33", "%d:%d:%d"),
    ("1 .2", "%d.%d"),
    ("1..2", "%d.%d"),
    ("1", "%d.%d"),
    ("", "%d.%d"),
    ("1.2", "%d,%d"),
    ("1.2:3", "%d.%d:%d"),
    // Formats the fast path must DECLINE, so these fall to the engine through
    // every arm and check the fallback still works.
    ("1 2 3 4 5", "%d %d %d %d %d"),
    ("5", "%5d"),
    ("5", " %d"),
    ("x=5", "x=%d"),
    ("5", "%u"),
];

/// Inputs for the `"%s"` fast path, which serves the exact format and nothing
/// else. The engine handled these before and must keep agreeing with the host:
/// leading whitespace of every ASCII kind, a token that runs to the terminator,
/// an input that is only whitespace (input failure, EOF) and an empty input.
const STRING_CASES: &[&str] = &[
    "hello world",
    "hello",
    "   leading",
    "\t\n\x0b\x0c\r mixed",
    "trailing   ",
    "",
    "   ",
    "\t",
    "a",
    "one_very_long_token_that_exceeds_any_inline_capacity_used_anywhere_here",
];

/// Mixed `%d`/`%s` field lists, and the trap in mixing them.
///
/// `%s` stops only at WHITESPACE, so in `"%s,%s"` the first conversion swallows
/// `"a,b"` whole and the literal `,` then has nothing left to match — glibc
/// reports ONE field, not two. The probe declines any format with a `%s` before
/// a literal separator for exactly that reason, and the cases below check both
/// that the declines still agree and that the accepted shapes do.
#[test]
fn the_field_list_matches_glibc_on_separators() {
    let glibc: SscanfFn = unsafe {
        host_fn(
            c"__isoc23_sscanf",
            frankenlibc_abi::isoc_abi::__isoc23_sscanf as *const (),
        )
    };

    // Two `char*` destinations and two `int*`, so every shape below has real
    // storage for whatever it writes, and a sentinel past each buffer catches a
    // run-on or a missing terminator.
    let scan = |f: SscanfFn, input: &str, format: &str| -> (c_int, String, String, c_int, c_int) {
        let cin = CString::new(input).expect("input has NUL");
        let cfmt = CString::new(format).expect("format has NUL");
        let mut a = [0xAAu8; 64];
        let mut b = [0xAAu8; 64];
        let mut i0: c_int = -777;
        let mut i1: c_int = -777;
        // SAFETY: no format below has more than four conversions, and four
        // destinations are supplied in the order the formats consume them.
        let rc = unsafe {
            match format {
                "%s %s" => f(
                    cin.as_ptr(),
                    cfmt.as_ptr(),
                    a.as_mut_ptr().cast::<c_char>(),
                    b.as_mut_ptr().cast::<c_char>(),
                ),
                "%s %d" => f(
                    cin.as_ptr(),
                    cfmt.as_ptr(),
                    a.as_mut_ptr().cast::<c_char>(),
                    &mut i0 as *mut c_int,
                ),
                "%d %s" => f(
                    cin.as_ptr(),
                    cfmt.as_ptr(),
                    &mut i0 as *mut c_int,
                    a.as_mut_ptr().cast::<c_char>(),
                ),
                "%s,%s" | "%s.%s" => f(
                    cin.as_ptr(),
                    cfmt.as_ptr(),
                    a.as_mut_ptr().cast::<c_char>(),
                    b.as_mut_ptr().cast::<c_char>(),
                ),
                "%d,%s" => f(
                    cin.as_ptr(),
                    cfmt.as_ptr(),
                    &mut i0 as *mut c_int,
                    a.as_mut_ptr().cast::<c_char>(),
                ),
                "%s %d %d" => f(
                    cin.as_ptr(),
                    cfmt.as_ptr(),
                    a.as_mut_ptr().cast::<c_char>(),
                    &mut i0 as *mut c_int,
                    &mut i1 as *mut c_int,
                ),
                "%s %s %s" => f(
                    cin.as_ptr(),
                    cfmt.as_ptr(),
                    a.as_mut_ptr().cast::<c_char>(),
                    b.as_mut_ptr().cast::<c_char>(),
                    a.as_mut_ptr().cast::<c_char>(),
                ),
                other => panic!("unhandled format {other:?}"),
            }
        };
        let text = |buf: &[u8; 64]| {
            let end = buf.iter().position(|&x| x == 0).unwrap_or(0);
            String::from_utf8_lossy(&buf[..end]).into_owned()
        };
        (rc, text(&a), text(&b), i0, i1)
    };

    let cases: &[(&str, &str)] = &[
        ("hello world", "%s %s"),
        ("hello 42", "%s %d"),
        ("42 hello", "%d %s"),
        ("hello", "%s %s"),
        ("", "%s %s"),
        ("   ", "%s %d"),
        ("hello notanint", "%s %d"),
        ("hello 1 2", "%s %d %d"),
        ("a b c", "%s %s %s"),
        // DECLINED by the probe: a `%s` before a literal separator.
        ("a,b", "%s,%s"),
        ("a.b", "%s.%s"),
        // Accepted: the literal comes after an INT, which stops at the comma.
        ("42,tail", "%d,%s"),
    ];

    let mut compared = 0usize;
    for (input, format) in cases {
        let want = scan(glibc, input, format);
        for (name, arm) in fl_arms() {
            let got = scan(arm, input, format);
            assert_eq!(
                got, want,
                "{name}({input:?}, {format:?}) produced {got:?}, host glibc produced {want:?}"
            );
            compared += 1;
        }
    }
    assert_eq!(compared, cases.len() * 3, "the loop skipped cases");
    println!("compared {compared} field-list arms across {} cases", cases.len());
}

/// `%[^X]` as a FIELD of a list, which is what `"%[^=]=%s"` needs.
///
/// A one-character negated scanset stops exactly at its delimiter, so unlike
/// `%s` it can be followed by a literal separator — that asymmetry is the whole
/// reason this shape is reachable and `"%s,%s"` is not.
#[test]
fn the_scanset_field_list_agrees_with_host_glibc() {
    let glibc: SscanfFn = unsafe {
        host_fn(
            c"__isoc23_sscanf",
            frankenlibc_abi::isoc_abi::__isoc23_sscanf as *const (),
        )
    };

    let scan = |f: SscanfFn, input: &str, format: &str| -> (c_int, String, String, c_int) {
        let cin = CString::new(input).expect("input has NUL");
        let cfmt = CString::new(format).expect("format has NUL");
        // 0xAA fill plus a comparison of the whole head: on a matching failure
        // glibc writes NOTHING for the field, not even a terminator, so a fast
        // path that helpfully terminated would otherwise pass.
        let mut a = [0xAAu8; 64];
        let mut b = [0xAAu8; 64];
        let mut i0: c_int = -777;
        // SAFETY: each format below takes the destinations supplied for it, in
        // the order it consumes them.
        let rc = unsafe {
            match format {
                "%[^=]=%s" | "%[^:]:%s" | "%[^,],%[^,]" => f(
                    cin.as_ptr(),
                    cfmt.as_ptr(),
                    a.as_mut_ptr().cast::<c_char>(),
                    b.as_mut_ptr().cast::<c_char>(),
                ),
                "%[^=]=%d" => f(
                    cin.as_ptr(),
                    cfmt.as_ptr(),
                    a.as_mut_ptr().cast::<c_char>(),
                    &mut i0 as *mut c_int,
                ),
                "%[^ ] %s" => f(
                    cin.as_ptr(),
                    cfmt.as_ptr(),
                    a.as_mut_ptr().cast::<c_char>(),
                    b.as_mut_ptr().cast::<c_char>(),
                ),
                other => panic!("unhandled format {other:?}"),
            }
        };
        let text = |buf: &[u8; 64]| {
            let end = buf.iter().position(|&x| x == 0).unwrap_or(0);
            String::from_utf8_lossy(&buf[..end]).into_owned()
        };
        (rc, text(&a), text(&b), i0)
    };

    let cases: &[(&str, &str)] = &[
        ("key=value", "%[^=]=%s"),
        ("key=", "%[^=]=%s"),
        ("=value", "%[^=]=%s"),
        ("novalue", "%[^=]=%s"),
        ("", "%[^=]=%s"),
        ("key=42", "%[^=]=%d"),
        ("key=notanint", "%[^=]=%d"),
        ("host:port", "%[^:]:%s"),
        ("a,b", "%[^,],%[^,]"),
        (",b", "%[^,],%[^,]"),
        ("word rest", "%[^ ] %s"),
        // The scanset's delimiter and the separator need not agree: here the
        // field runs to the end and the separator then has nothing to match.
        ("nodelim here", "%[^=]=%s"),
    ];

    let mut compared = 0usize;
    for (input, format) in cases {
        let want = scan(glibc, input, format);
        for (name, arm) in fl_arms() {
            let got = scan(arm, input, format);
            assert_eq!(
                got, want,
                "{name}({input:?}, {format:?}) produced {got:?}, host glibc produced {want:?}"
            );
            compared += 1;
        }
    }
    assert_eq!(compared, cases.len() * 3, "the loop skipped cases");
    println!("compared {compared} scanset-field arms across {} cases", cases.len());
}

/// A LONE `%s` or `%[^X]` must not be taken by the list path.
///
/// The list probe runs first and would accept either as a one-field list. Both
/// have leaner dedicated paths — measured 0.254x and 0.186x of host glibc, the
/// two best cases in the family — so the probe declines single non-`%d` fields.
/// Allocation count is what distinguishes the routes observably: all three are
/// allocation-free, so this asserts the property that would break if the lone
/// forms were ever routed through the engine instead.
#[test]
fn a_lone_string_or_scanset_still_takes_its_own_fast_path() {
    for (input, format) in [
        ("hello world", "%s"),
        ("key=value", "%[^=]"),
        ("line\nnext", "%[^\n]"),
    ] {
        // Built OUTSIDE the counting window: `CString::new` allocates, and
        // measuring that instead of the call is how this gate would fool itself.
        let cin = CString::new(input).expect("input has NUL");
        let cfmt = CString::new(format).expect("format has NUL");
        let mut buf = [0u8; 128];
        let arm = frankenlibc_abi::isoc_abi::__isoc23_sscanf as SscanfFn;

        // Warm any one-time lazy initialisation so it is not billed to the call.
        // SAFETY: each format takes exactly one `char *`, and `buf` outsizes
        // every token here.
        unsafe {
            arm(
                cin.as_ptr(),
                cfmt.as_ptr(),
                buf.as_mut_ptr().cast::<c_char>(),
            );
        }
        let n = count_allocs(|| {
            // SAFETY: the same call, now inside the armed window.
            unsafe {
                arm(
                    std::hint::black_box(cin.as_ptr()),
                    std::hint::black_box(cfmt.as_ptr()),
                    buf.as_mut_ptr().cast::<c_char>(),
                );
            }
        });
        println!("__isoc23_sscanf({input:?}, {format:?}) allocations={n}");
        assert_eq!(
            n, 0,
            "a lone {format:?} allocated {n} times; it should still be served by its \
             own fast path, not routed through the list machinery or the engine"
        );
    }
}

/// Float FIELDS of a list — `"%s %d %lf"` is the shape of a whole log record.
///
/// The float grammar is not reimplemented: the fast path calls the engine's own
/// `scan_default_float`. What IS new here is the boundary handling — where the
/// conversion stops, and whether an exhausted input reports EOF or a matching
/// failure — so the cases below lean on hex floats, infinities, NaN and
/// exponents to check that the shared scanner is really being reached, and on
/// empty and non-numeric tails to check the boundary.
#[test]
fn float_fields_agree_with_host_glibc() {
    let glibc: SscanfFn = unsafe {
        host_fn(
            c"__isoc23_sscanf",
            frankenlibc_abi::isoc_abi::__isoc23_sscanf as *const (),
        )
    };

    let scan = |f: SscanfFn, input: &str, format: &str| -> (c_int, String, c_int, u64, u32) {
        let cin = CString::new(input).expect("input has NUL");
        let cfmt = CString::new(format).expect("format has NUL");
        let mut text = [0xAAu8; 64];
        let mut i0: c_int = -777;
        let mut d0: f64 = -7.0;
        let mut f0: f32 = -7.0;
        // SAFETY: each format takes the destinations supplied for it, in order,
        // and `%lf` gets a `double *` where `%f` gets a `float *`.
        let rc = unsafe {
            match format {
                "%s %d %lf" => f(
                    cin.as_ptr(),
                    cfmt.as_ptr(),
                    text.as_mut_ptr().cast::<c_char>(),
                    &mut i0 as *mut c_int,
                    &mut d0 as *mut f64,
                ),
                "%lf" | "%lf %lf" => f(
                    cin.as_ptr(),
                    cfmt.as_ptr(),
                    &mut d0 as *mut f64,
                    &mut f0 as *mut f32,
                ),
                "%f %f" => f(
                    cin.as_ptr(),
                    cfmt.as_ptr(),
                    &mut f0 as *mut f32,
                    &mut f0 as *mut f32,
                ),
                "%d %lf" => f(
                    cin.as_ptr(),
                    cfmt.as_ptr(),
                    &mut i0 as *mut c_int,
                    &mut d0 as *mut f64,
                ),
                other => panic!("unhandled format {other:?}"),
            }
        };
        let end = text.iter().position(|&x| x == 0).unwrap_or(0);
        (
            rc,
            String::from_utf8_lossy(&text[..end]).into_owned(),
            i0,
            // Bit patterns, not values: a NaN compares unequal to itself and a
            // -0.0 compares equal to 0.0, so a value comparison would pass on
            // divergences that matter.
            d0.to_bits(),
            f0.to_bits(),
        )
    };

    let cases: &[(&str, &str)] = &[
        ("tag 7 3.5", "%s %d %lf"),
        ("tag 7 -0.0", "%s %d %lf"),
        ("tag 7 1e10", "%s %d %lf"),
        ("tag 7 0x1p3", "%s %d %lf"),
        ("tag 7 inf", "%s %d %lf"),
        ("tag 7 -infinity", "%s %d %lf"),
        ("tag 7 nan", "%s %d %lf"),
        ("tag 7 notanumber", "%s %d %lf"),
        ("tag 7", "%s %d %lf"),
        ("tag 7 ", "%s %d %lf"),
        ("1 2.5", "%d %lf"),
        ("1 .5", "%d %lf"),
        ("1", "%d %lf"),
        ("", "%d %lf"),
        ("   ", "%d %lf"),
    ];

    let mut compared = 0usize;
    for (input, format) in cases {
        let want = scan(glibc, input, format);
        for (name, arm) in fl_arms() {
            let got = scan(arm, input, format);
            assert_eq!(
                got, want,
                "{name}({input:?}, {format:?}) produced {got:?}, host glibc produced {want:?}"
            );
            compared += 1;
        }
    }
    assert_eq!(compared, cases.len() * 3, "the loop skipped cases");
    println!("compared {compared} float-field arms across {} cases", cases.len());
}

#[test]
fn the_string_fast_path_agrees_with_host_glibc() {
    let glibc: SscanfFn = unsafe {
        host_fn(
            c"__isoc23_sscanf",
            frankenlibc_abi::isoc_abi::__isoc23_sscanf as *const (),
        )
    };

    // A sentinel byte after the destination: `%s` must NUL-terminate exactly at
    // the token end and write nothing past it. Without this a fast path that
    // forgot the terminator, or ran on, would still compare equal.
    let scan_one = |f: SscanfFn, input: &str| -> (c_int, String, u8) {
        let cin = CString::new(input).expect("input has NUL");
        let cfmt = CString::new("%s").expect("format has NUL");
        let mut buf = [0xAAu8; 128];
        // SAFETY: the format takes one `char *`; the buffer is far longer than
        // any token in the table.
        let rc = unsafe { f(cin.as_ptr(), cfmt.as_ptr(), buf.as_mut_ptr().cast::<c_char>()) };
        let end = buf.iter().position(|&b| b == 0).unwrap_or(0);
        (
            rc,
            String::from_utf8_lossy(&buf[..end]).into_owned(),
            buf[127],
        )
    };

    let mut compared = 0usize;
    for input in STRING_CASES {
        let want = scan_one(glibc, input);
        for (name, arm) in fl_arms() {
            let got = scan_one(arm, input);
            assert_eq!(
                got, want,
                "{name}(\"%s\") on {input:?} produced {got:?}, host glibc produced {want:?}"
            );
            compared += 1;
        }
    }
    assert_eq!(
        compared,
        STRING_CASES.len() * 3,
        "compared {compared} arms, expected {}",
        STRING_CASES.len() * 3
    );
    println!("compared {compared} %s arms across {} inputs", STRING_CASES.len());
}

/// `(input, format)` for the bare negated-scanset fast path.
///
/// The delimiter cases matter more than the matching ones. `%[` does NOT skip
/// leading whitespace, a first byte equal to the delimiter is a MATCHING failure
/// (0, and glibc writes nothing — not even a terminator), and an exhausted input
/// is an INPUT failure (EOF). Those three are encoded from the standard and are
/// exactly what a live oracle is for; the formats the probe must decline are
/// here too, so a fast path that over-claimed the grammar shows up as a
/// divergence rather than as a silent behaviour change.
const SCANSET_CASES: &[(&str, &str)] = &[
    ("key=value", "%[^=]"),
    ("=value", "%[^=]"),
    ("key", "%[^=]"),
    ("", "%[^=]"),
    ("  spaced=x", "%[^=]"),
    ("\tno-skip=x", "%[^=]"),
    ("line one\nline two", "%[^\n]"),
    ("\nempty first", "%[^\n]"),
    ("a,b,c", "%[^,]"),
    (",lead", "%[^,]"),
    // Grammar the probe must DECLINE, so these stay on the engine.
    ("abc]def", "%[^]]"),
    ("abcXdef", "%[^a-c]"),
    ("abcdef", "%[abc]"),
    ("abcdef", "%[^abc]"),
    ("abcdef", "%5[^x]"),
];

#[test]
fn the_scanset_fast_path_agrees_with_host_glibc() {
    let glibc: SscanfFn = unsafe {
        host_fn(
            c"__isoc23_sscanf",
            frankenlibc_abi::isoc_abi::__isoc23_sscanf as *const (),
        )
    };

    // The whole 128-byte destination is compared, not just up to the first NUL:
    // on a matching failure glibc writes NOTHING, and a fast path that helpfully
    // wrote a terminator would otherwise pass.
    let scan_one = |f: SscanfFn, input: &str, format: &str| -> (c_int, [u8; 16]) {
        let cin = CString::new(input).expect("input has NUL");
        let cfmt = CString::new(format).expect("format has NUL");
        let mut buf = [0xAAu8; 128];
        // SAFETY: every format here takes one `char *`; the buffer is longer
        // than any field in the table.
        let rc = unsafe { f(cin.as_ptr(), cfmt.as_ptr(), buf.as_mut_ptr().cast::<c_char>()) };
        let mut head = [0u8; 16];
        head.copy_from_slice(&buf[..16]);
        (rc, head)
    };

    let mut compared = 0usize;
    for (input, format) in SCANSET_CASES {
        let want = scan_one(glibc, input, format);
        for (name, arm) in fl_arms() {
            let got = scan_one(arm, input, format);
            assert_eq!(
                got, want,
                "{name}({input:?}, {format:?}) produced rc={} buf={:?}, host glibc produced rc={} buf={:?}",
                got.0, got.1, want.0, want.1
            );
            compared += 1;
        }
    }
    assert_eq!(
        compared,
        SCANSET_CASES.len() * 3,
        "compared {compared} arms, expected {}",
        SCANSET_CASES.len() * 3
    );
    println!("compared {compared} scanset arms across {} cases", SCANSET_CASES.len());
}

#[test]
fn the_aliases_agree_with_host_glibc() {
    // The oracle. `host_fn` asserts the resolved address is NOT fl's own, so a
    // collapsed arm fails loudly instead of comparing fl against itself.
    let glibc: SscanfFn = unsafe {
        host_fn(
            c"__isoc23_sscanf",
            frankenlibc_abi::isoc_abi::__isoc23_sscanf as *const (),
        )
    };

    let mut compared = 0usize;
    for (input, format) in CASES {
        let (want_rc, want_v) = scan_args(glibc, input, format);
        for (name, arm) in fl_arms() {
            let (got_rc, got_v) = scan_args(arm, input, format);
            assert_eq!(
                got_rc, want_rc,
                "{name}({input:?}, {format:?}) returned {got_rc}, host glibc returned {want_rc}"
            );
            // Only the values the return code claims were written are defined.
            let written = want_rc.max(0) as usize;
            for idx in 0..written.min(ARGS) {
                assert_eq!(
                    got_v[idx], want_v[idx],
                    "{name}({input:?}, {format:?}) wrote {} at arg {idx}, host glibc wrote {}",
                    got_v[idx], want_v[idx]
                );
            }
            compared += 1;
        }
    }
    // Assert the positive fact: a green run above means nothing unless the loop
    // actually ran the table.
    assert_eq!(
        compared,
        CASES.len() * 3,
        "the differential loop compared {compared} arms, expected {}",
        CASES.len() * 3
    );
    println!("compared {compared} fl-vs-glibc arms across {} cases", CASES.len());
}

// ---------------------------------------------------------------------------
// Routing proof
// ---------------------------------------------------------------------------

/// Allocations one call makes, with setup left outside the armed window.
fn allocs_for(f: SscanfFn, input: &str, format: &str) -> usize {
    let cin = CString::new(input).expect("input has NUL");
    let cfmt = CString::new(format).expect("format has NUL");
    let mut v: [c_int; 5] = [0; 5];

    // Warm one-time lazy initialisation so it is not billed to the measured call.
    // SAFETY: at most four `int *` are read; four are supplied.
    unsafe {
        f(
            cin.as_ptr(),
            cfmt.as_ptr(),
            &mut v[0] as *mut c_int,
            &mut v[1] as *mut c_int,
            &mut v[2] as *mut c_int,
            &mut v[3] as *mut c_int,
            &mut v[4] as *mut c_int,
        );
    }
    count_allocs(|| {
        // SAFETY: the same call, now inside the armed window.
        unsafe {
            f(
                std::hint::black_box(cin.as_ptr()),
                std::hint::black_box(cfmt.as_ptr()),
                &mut v[0] as *mut c_int,
                &mut v[1] as *mut c_int,
                &mut v[2] as *mut c_int,
                &mut v[3] as *mut c_int,
                &mut v[4] as *mut c_int,
            );
        }
    })
}

#[test]
fn the_aliases_take_the_decimal_int_fast_path() {
    // POSITIVE CONTROL first. `strict_decimal_int_format_count` accepts at most
    // STRICT_INT_LIST_MAX (four) `%d` fields, so a FIVE-field format cannot be
    // served by the fast path through ANY arm and must reach the engine — whose directive list spills
    // past its inline capacity and allocates. If this reads zero the counter is
    // blind and every zero below is worthless, so it is asserted before them.
    let control = allocs_for(fl_arms()[0].1, "1 2 3 4 5", "%d %d %d %d %d");
    println!("CONTROL sscanf(\"1 2 3 4 5\", \"%d %d %d %d %d\") allocations={control} (engine path)");
    assert!(
        control >= 1,
        "the engine path allocated {control} times, so allocation count cannot \
         discriminate the fast path from the engine and this gate proves nothing"
    );

    // Now the routing itself, on the three-field format — the widest one the fast
    // path accepts, and the one whose engine equivalent allocates.
    for (name, arm) in fl_arms() {
        let n = allocs_for(arm, "7 8 9", "%d %d %d");
        println!("{name}(\"7 8 9\", \"%d %d %d\") allocations={n}");
        assert_eq!(
            n, 0,
            "{name} allocated {n} times on a pure-decimal-int format, so it took the \
             ENGINE and not the fast path. That is exactly the defect this gate exists \
             for: both __isoc aliases used to forward to vsscanf, and since <stdio.h> \
             redirects every compiled `sscanf` call to one of them, no C program could \
             reach the fast path at all (864 instructions per call against 250)."
        );
    }
}
