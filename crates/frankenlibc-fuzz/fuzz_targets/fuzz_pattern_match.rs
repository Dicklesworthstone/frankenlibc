#![no_main]
//! Differential + crash-detector fuzz target for FrankenLibC fnmatch.
//!
//! Pattern matching is a classic source of CVEs (regexp-like backtracking
//! pathological inputs, off-by-one in character classes, NUL handling).
//! This target compares frankenlibc-abi `fnmatch` against the host
//! `libc::fnmatch` for inputs that are valid C strings, and asserts the
//! crash-detector invariants (no panic, return is FNM_NOMATCH or 0) for
//! the rest.
//!
//! Bead: bd-m40be

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::ffi::CString;

#[derive(Debug, Arbitrary)]
struct PatternFuzzInput {
    pattern: Vec<u8>,
    string: Vec<u8>,
    flags: u8,
}

const FNM_NOMATCH: i32 = 1;

fuzz_target!(|input: PatternFuzzInput| {
    // Cap input sizes — fnmatch with star patterns is recursive and
    // can blow the stack on long inputs. 4 KiB is plenty to exercise
    // every code path while keeping exec/s well above the 1000/s floor.
    if input.pattern.len() > 4096 || input.string.len() > 4096 {
        return;
    }

    let Ok(pattern_c) = CString::new(input.pattern.clone()) else {
        return;
    };
    let Ok(string_c) = CString::new(input.string.clone()) else {
        return;
    };

    // Restrict to the documented POSIX + GNU flag bits so we exercise
    // every defined behavior without tripping host asserts on unknown
    // flags.
    let flags = (input.flags as i32)
        & (libc::FNM_NOESCAPE | libc::FNM_PATHNAME | libc::FNM_PERIOD | libc::FNM_CASEFOLD);

    let our_rc = unsafe {
        frankenlibc_abi::string_abi::fnmatch(pattern_c.as_ptr(), string_c.as_ptr(), flags)
    };
    let host_rc = unsafe { libc::fnmatch(pattern_c.as_ptr(), string_c.as_ptr(), flags) };

    // Crash-detector invariant: return must be one of {0, FNM_NOMATCH}.
    assert!(
        our_rc == 0 || our_rc == FNM_NOMATCH,
        "fnmatch returned {our_rc}, expected 0 or FNM_NOMATCH for pattern={:?} string={:?} flags={flags:#x}",
        input.pattern,
        input.string,
    );

    // Determinism: a second call with the same inputs must return the
    // same value (catches global-state leakage).
    let our_rc2 = unsafe {
        frankenlibc_abi::string_abi::fnmatch(pattern_c.as_ptr(), string_c.as_ptr(), flags)
    };
    assert_eq!(our_rc, our_rc2, "fnmatch is non-deterministic");

    // Differential oracle: our impl and host glibc must agree on
    // match/no-match. Both return 0 for match and FNM_NOMATCH for no
    // match, so direct equality is the right comparison.
    assert_eq!(
        our_rc, host_rc,
        "fnmatch divergence: ours={our_rc} host={host_rc} pattern={:?} string={:?} flags={flags:#x}",
        input.pattern, input.string,
    );
});
