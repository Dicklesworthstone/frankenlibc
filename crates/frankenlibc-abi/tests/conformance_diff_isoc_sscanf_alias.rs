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
/// which took the binary down with SIGSEGV. Extra pointers a format never reads
/// cost nothing, so one call shape for the whole table is both safe and simpler.
const ARGS: usize = 4;

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
    // Formats the fast path must DECLINE, so these fall to the engine through
    // every arm and check the fallback still works.
    ("1 2 3 4", "%d %d %d %d"),
    ("5", "%5d"),
    ("5", " %d"),
    ("x=5", "x=%d"),
    ("5", "%u"),
];

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
    let mut v: [c_int; 4] = [0; 4];

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
            );
        }
    })
}

#[test]
fn the_aliases_take_the_decimal_int_fast_path() {
    // POSITIVE CONTROL first. `strict_decimal_int_format_count` accepts at most
    // three `%d` fields, so a four-field format cannot be served by the fast path
    // through ANY arm and must reach the engine — whose directive list spills
    // past its inline capacity and allocates. If this reads zero the counter is
    // blind and every zero below is worthless, so it is asserted before them.
    let control = allocs_for(fl_arms()[0].1, "1 2 3 4", "%d %d %d %d");
    println!("CONTROL sscanf(\"1 2 3 4\", \"%d %d %d %d\") allocations={control} (engine path)");
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
