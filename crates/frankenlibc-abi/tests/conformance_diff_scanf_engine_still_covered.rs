#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // variadic sscanf against the host oracle

//! The parsing ENGINE must still agree with glibc on the shapes the fast paths
//! now intercept.
//!
//! ## The hazard this closes, which I created
//!
//! Three strict fast paths landed today: `%d`-only formats, a bare `%s`, and a
//! bare `%[^X]`. Each serves its shape without entering the engine at all — that
//! is the whole point, and it is worth 2.8x to 3.5x in instructions.
//!
//! But every existing differential in this repo reaches the engine THROUGH
//! `sscanf`, and those suites are full of exactly these three shapes. So the day
//! the fast paths landed, the engine's coverage of `%d`, `%s` and `%[^X]` did
//! not fail — it silently moved. The suites still pass, still print the same
//! counts, and now exercise a different implementation. An engine regression on
//! those shapes would be invisible until some other format dragged it out.
//!
//! That is the same class as the hollow oracle arms this repo already found
//! twice (a `dlsym` arm that resolved back to fl, a test target that never
//! linked): the gate stays green while what it guards stops being tested.
//!
//! ## Why this reaches the engine when `sscanf` no longer does
//!
//! It calls the engine DIRECTLY — `parse_scanf_format` then `scan_input` from
//! `frankenlibc_core` — rather than going through the ABI entry point, so no
//! fast-path probe sits in front of it. The oracle is the host's
//! `__isoc23_sscanf` through `dlsym`, the same one the ABI gates use, so the
//! engine is held to the same standard as the fast path rather than to a
//! remembered expectation.
//!
//! Reaching the engine by forcing hardened mode was the other candidate and is
//! deliberately not used: it changes membrane behaviour as well as routing, so a
//! divergence would not be attributable to the engine.

use frankenlibc_core::stdio::scanf::{ScanValue, parse_scanf_format, scan_input};
use std::ffi::{CString, c_char, c_int};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

type SscanfFn = unsafe extern "C" fn(*const c_char, *const c_char, ...) -> c_int;

fn glibc_sscanf() -> SscanfFn {
    // SAFETY: NUL-terminated name, paired with fl's own definition so a
    // collapsed arm is detected rather than silently compared against itself.
    unsafe {
        host_fn(
            c"__isoc23_sscanf",
            frankenlibc_abi::isoc_abi::__isoc23_sscanf as *const (),
        )
    }
}

/// What the ENGINE produced, rendered so it can be compared with the host.
fn engine(input: &str, format: &str) -> (i32, Vec<String>) {
    let directives = parse_scanf_format(format.as_bytes());
    let result = scan_input(input.as_bytes(), &directives);
    let rendered = result
        .values
        .as_slice()
        .iter()
        .filter_map(|v| match v {
            ScanValue::Unset => None,
            ScanValue::SignedInt(i) => Some(i.to_string()),
            ScanValue::UnsignedInt(u) => Some(u.to_string()),
            ScanValue::String(b) | ScanValue::Char(b) => {
                Some(String::from_utf8_lossy(b.as_slice()).into_owned())
            }
            other => Some(format!("{other:?}")),
        })
        .collect();
    // The engine reports EOF as a count of 0 with `input_failure` set, where C
    // reports -1; normalise so the two are comparable on the same axis.
    let count = if result.input_failure && result.count == 0 {
        -1
    } else {
        result.count
    };
    (count, rendered)
}

/// `%d` shapes, now served by `strict_scan_decimal_ints`.
#[test]
fn the_engine_still_matches_glibc_on_decimal_int_formats() {
    let glibc = glibc_sscanf();
    let cases: &[(&str, &str, usize)] = &[
        ("42", "%d", 1),
        ("  42", "%d", 1),
        ("-42", "%d", 1),
        ("+42", "%d", 1),
        ("0012", "%d", 1),
        ("1 2", "%d %d", 2),
        ("7 8 9", "%d %d %d", 3),
        ("1 x", "%d %d", 2),
        ("abc", "%d", 1),
        ("", "%d", 1),
    ];

    let mut compared = 0usize;
    for (input, format, nargs) in cases {
        let cin = CString::new(*input).expect("input has NUL");
        let cfmt = CString::new(*format).expect("format has NUL");
        let mut v: [c_int; 3] = [-777; 3];
        // SAFETY: no format here has more than three conversions and three
        // `int *` are supplied.
        let rc = unsafe {
            glibc(
                cin.as_ptr(),
                cfmt.as_ptr(),
                &mut v[0] as *mut c_int,
                &mut v[1] as *mut c_int,
                &mut v[2] as *mut c_int,
            )
        };
        let want: Vec<String> = (0..rc.max(0) as usize)
            .take(*nargs)
            .map(|i| v[i].to_string())
            .collect();

        let (got_rc, got) = engine(input, format);
        assert_eq!(
            got_rc, rc,
            "engine({input:?}, {format:?}) returned {got_rc}, host glibc returned {rc}"
        );
        assert_eq!(
            got, want,
            "engine({input:?}, {format:?}) produced {got:?}, host glibc produced {want:?}"
        );
        compared += 1;
    }
    assert_eq!(compared, cases.len(), "the loop skipped cases");
    println!("engine vs glibc: {compared} decimal-int cases");
}

/// `%s` and `%[^X]` shapes, now served by `strict_scan_single_string` and
/// `strict_scan_negated_scanset`.
#[test]
fn the_engine_still_matches_glibc_on_string_and_scanset_formats() {
    let glibc = glibc_sscanf();
    let cases: &[(&str, &str)] = &[
        // %s — the fast path skips leading whitespace and stops at the next.
        ("hello world", "%s"),
        ("   leading", "%s"),
        ("\t\n\x0b\x0c\r mixed", "%s"),
        ("trailing   ", "%s"),
        ("a", "%s"),
        ("", "%s"),
        ("   ", "%s"),
        // %[^X] — no leading-whitespace skip, and a delimiter first is a
        // MATCHING failure rather than an input failure.
        ("key=value", "%[^=]"),
        ("=value", "%[^=]"),
        ("  spaced=x", "%[^=]"),
        ("line one\nline two", "%[^\n]"),
        ("a,b,c", "%[^,]"),
        ("", "%[^=]"),
    ];

    let mut compared = 0usize;
    for (input, format) in cases {
        let cin = CString::new(*input).expect("input has NUL");
        let cfmt = CString::new(*format).expect("format has NUL");
        let mut buf = [0u8; 128];
        // SAFETY: each format takes one `char *`; the buffer outsizes every
        // token in the table.
        let rc = unsafe {
            glibc(
                cin.as_ptr(),
                cfmt.as_ptr(),
                buf.as_mut_ptr().cast::<c_char>(),
            )
        };
        let want: Vec<String> = if rc == 1 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            vec![String::from_utf8_lossy(&buf[..end]).into_owned()]
        } else {
            Vec::new()
        };

        let (got_rc, got) = engine(input, format);
        assert_eq!(
            got_rc, rc,
            "engine({input:?}, {format:?}) returned {got_rc}, host glibc returned {rc}"
        );
        assert_eq!(
            got, want,
            "engine({input:?}, {format:?}) produced {got:?}, host glibc produced {want:?}"
        );
        compared += 1;
    }
    assert_eq!(compared, cases.len(), "the loop skipped cases");
    println!("engine vs glibc: {compared} string/scanset cases");
}

/// The engine is genuinely being driven here, not a fast path in disguise.
///
/// Without this, every assertion above would still pass if `scan_input` were
/// somehow routed through the same strict helpers — which is precisely the
/// failure this file exists to prevent, so it is asserted rather than assumed.
/// A format the fast paths decline BY CONSTRUCTION must produce the same answer
/// through the engine as through the ABI entry point that does have the probes.
#[test]
fn the_engine_and_the_abi_agree_on_a_format_no_fast_path_accepts() {
    // Four `%d` conversions: `strict_decimal_int_format_count` accepts at most
    // three, so the ABI entry point cannot fast-path this and both sides run the
    // engine. If these ever disagree, the two routes have diverged.
    let (engine_rc, engine_vals) = engine("1 2 3 4", "%d %d %d %d");

    let cin = CString::new("1 2 3 4").expect("input has NUL");
    let cfmt = CString::new("%d %d %d %d").expect("format has NUL");
    let mut v: [c_int; 4] = [-777; 4];
    // SAFETY: four conversions, four `int *`.
    let abi_rc = unsafe {
        frankenlibc_abi::stdio_abi::sscanf(
            cin.as_ptr(),
            cfmt.as_ptr(),
            &mut v[0] as *mut c_int,
            &mut v[1] as *mut c_int,
            &mut v[2] as *mut c_int,
            &mut v[3] as *mut c_int,
        )
    };
    let abi_vals: Vec<String> = (0..abi_rc.max(0) as usize)
        .map(|i| v[i].to_string())
        .collect();

    assert_eq!(engine_rc, 4, "the engine did not scan the control format");
    assert_eq!(abi_rc, 4, "the ABI did not scan the control format");
    assert_eq!(
        engine_vals, abi_vals,
        "engine produced {engine_vals:?} and the ABI produced {abi_vals:?} for a \
         format no fast path accepts; the two routes have diverged"
    );
}

/// Grouping literals must not make every directive bigger.
///
/// `InlineVec<ScanDirective, 4>` is built on the stack for EVERY scanf call, so
/// the enum's size is per-call cost paid by formats that contain no literal run
/// at all. `LITERAL_RUN_CAP` is chosen to fit inside the existing largest
/// variant, `Spec(ScanSpec)`, and this pins that choice: if someone raises the
/// cap past what `ScanSpec` occupies, the enum grows and the cost lands on every
/// format in the library.
///
/// This repo has the scar for it — `SCAN_DIRECTIVES_INLINE = 8` was measured at
/// +12-23% instructions on the engine path purely from initialising slots — and
/// a size-pin test is the cheap way to keep a structural choice from drifting.
#[test]
fn a_literal_run_does_not_grow_the_directive() {
    use frankenlibc_core::stdio::scanf::{LITERAL_RUN_CAP, ScanDirective, ScanSpec};

    let directive = std::mem::size_of::<ScanDirective>();
    let spec = std::mem::size_of::<ScanSpec>();
    println!(
        "size_of ScanDirective={directive} ScanSpec={spec} LITERAL_RUN_CAP={LITERAL_RUN_CAP}"
    );

    // The run must fit in the space `Spec` already forces the enum to reserve.
    assert!(
        LITERAL_RUN_CAP + 1 <= spec,
        "a {LITERAL_RUN_CAP}-byte run plus its length no longer fits inside \
         Spec(ScanSpec) at {spec} bytes, so ScanDirective grew for every format"
    );
    // And the enum itself must still be bounded by the Spec variant plus a tag.
    assert!(
        directive <= spec + 8,
        "ScanDirective is {directive} bytes against a {spec}-byte ScanSpec; the \
         literal run has become the largest variant and every call pays for it"
    );
}
