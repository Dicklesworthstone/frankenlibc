//! Robustness probe: GLOB_BRACE must not crash or OOM on adversarial patterns.
//!
//! glibc itself SIGSEGVs on deeply-nested `{{{...}}}` (unbounded recursion) and
//! hangs/OOMs on `{a,b}{a,b}...` (2^N cartesian product). A safe-Rust libc must
//! instead bound brace expansion and report GLOB_NOSPACE (POSIX out-of-resources)
//! — a strictly safer divergence that never changes the result for any pattern
//! glibc handles successfully. This test pins both guards plus the normal path.

use frankenlibc_core::string::glob::{GLOB_BRACE, GLOB_NOCHECK, GLOB_NOSPACE, glob_expand};

#[test]
fn deep_nesting_returns_nospace_not_stack_overflow() {
    // {{{ ... x ... }}} with 50_000 levels — would blow an 8 MiB stack if the
    // brace expander recursed without a depth cap (glibc crashes here).
    let n = 50_000usize;
    let mut pat = vec![b'{'; n];
    pat.push(b'x');
    pat.extend(std::iter::repeat_n(b'}', n));
    let got = glob_expand(&pat, GLOB_BRACE | GLOB_NOCHECK).err();
    assert_eq!(
        got,
        Some(GLOB_NOSPACE),
        "deeply nested braces must yield GLOB_NOSPACE, got {got:?}"
    );
}

#[test]
fn combinatorial_blowup_returns_nospace_not_oom() {
    // {a,b} repeated 30 times => 2^30 (~1e9) expansions if unbounded.
    let mut pat = Vec::new();
    for _ in 0..30 {
        pat.extend_from_slice(b"{a,b}");
    }
    let got = glob_expand(&pat, GLOB_BRACE | GLOB_NOCHECK).err();
    assert_eq!(
        got,
        Some(GLOB_NOSPACE),
        "combinatorial brace blow-up must yield GLOB_NOSPACE, got {got:?}"
    );
}

#[test]
fn legitimate_large_expansion_does_not_false_positive() {
    // {a,b} repeated 10 times => 2^10 = 1024 expansions, well under the guard
    // limit. The DoS guards must NOT trip here; any pattern glibc handles must
    // still succeed. With GLOB_NOCHECK and no filesystem matches, glob echoes
    // the original pattern (POSIX behavior) rather than erroring.
    let mut pat = Vec::new();
    for _ in 0..10 {
        pat.extend_from_slice(b"{a,b}");
    }
    let r = glob_expand(&pat, GLOB_BRACE | GLOB_NOCHECK)
        .expect("a 1024-expansion pattern must not trip the DoS guard");
    // GLOB_NOCHECK on a total no-match returns the original (un-expanded) pattern.
    assert_eq!(r.paths, vec![pat]);
}
