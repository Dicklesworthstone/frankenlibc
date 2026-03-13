#![no_main]
//! Structure-aware fuzz target for FrankenLibC stdlib conversion functions.
//!
//! Exercises strtol/strtoul/strtoll/strtoull/strtoimax/strtoumax, strtod/strtof,
//! atoi/atol/atoll/atof, qsort, and bsearch from `frankenlibc-core`.
//!
//! Invariants:
//! - No function should panic or corrupt memory on any well-typed input
//! - Signed/unsigned parse round-trips should be consistent
//! - Endptr offsets must always be within input bounds
//! - qsort output must be sorted according to the comparator
//!
//! Bead: bd-2hh.4

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::stdlib::{conversion, sort};

/// Maximum input size to prevent OOM while covering large-input paths.
const MAX_INPUT: usize = 256;

#[derive(Debug, Arbitrary)]
struct StdlibFuzzInput {
    /// Input bytes for conversion (will be NUL-terminated).
    data: Vec<u8>,
    /// Base for integer conversion (0 = auto-detect, 2-36 = explicit).
    base: u8,
    /// Operation selector.
    op: u8,
    /// Array of values for sort/search operations.
    values: Vec<i32>,
}

/// Ensure NUL termination.
fn with_nul(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len().min(MAX_INPUT) + 1);
    out.extend_from_slice(&v[..v.len().min(MAX_INPUT)]);
    if out.last() != Some(&0) {
        out.push(0);
    }
    out
}

/// Normalize base: 0 (auto), or 2..=36.
fn normalize_base(b: u8) -> i32 {
    let b = b as i32;
    if b == 0 {
        0
    } else {
        (b % 35) + 2 // maps to 2..=36
    }
}

fuzz_target!(|input: StdlibFuzzInput| {
    if input.data.len() > MAX_INPUT {
        return;
    }

    match input.op % 8 {
        0 => fuzz_strtol(&input),
        1 => fuzz_strtoul(&input),
        2 => fuzz_strtod(&input),
        3 => fuzz_atoi(&input),
        4 => fuzz_strtoll(&input),
        5 => fuzz_strtoull(&input),
        6 => fuzz_qsort(&input),
        7 => fuzz_consistency(&input),
        _ => unreachable!(),
    }
});

fn fuzz_strtol(input: &StdlibFuzzInput) {
    let s = with_nul(&input.data);
    let base = normalize_base(input.base);

    let (val, endptr) = conversion::strtol(&s, base);
    assert!(endptr <= s.len(), "endptr out of bounds");

    // Self-consistency: re-parsing should give same result
    let (val2, endptr2) = conversion::strtol(&s, base);
    assert_eq!(val, val2);
    assert_eq!(endptr, endptr2);

    let _ = val;
}

fn fuzz_strtoul(input: &StdlibFuzzInput) {
    let s = with_nul(&input.data);
    let base = normalize_base(input.base);

    let (val, endptr) = conversion::strtoul(&s, base);
    assert!(endptr <= s.len(), "endptr out of bounds");

    // Compare with strtoumax (should be identical on 64-bit)
    let (val_max, endptr_max) = conversion::strtoumax(&s, base);
    assert_eq!(val, val_max);
    assert_eq!(endptr, endptr_max);

    let _ = val;
}

fn fuzz_strtoll(input: &StdlibFuzzInput) {
    let s = with_nul(&input.data);
    let base = normalize_base(input.base);

    let (val, endptr) = conversion::strtoll(&s, base);
    assert!(endptr <= s.len(), "endptr out of bounds");

    // Compare with strtoimax (should be identical on 64-bit)
    let (val_max, endptr_max) = conversion::strtoimax(&s, base);
    assert_eq!(val, val_max);
    assert_eq!(endptr, endptr_max);

    let _ = val;
}

fn fuzz_strtoull(input: &StdlibFuzzInput) {
    let s = with_nul(&input.data);
    let base = normalize_base(input.base);

    let (val, endptr) = conversion::strtoull(&s, base);
    assert!(endptr <= s.len(), "endptr out of bounds");

    let _ = val;
}

fn fuzz_strtod(input: &StdlibFuzzInput) {
    let s = with_nul(&input.data);

    let (val, endptr) = conversion::strtod(&s);
    assert!(endptr <= s.len(), "endptr out of bounds");

    // strtof should also not panic
    let (valf, endptrf) = conversion::strtof(&s);
    assert!(endptrf <= s.len(), "strtof endptr out of bounds");

    // If strtod parsed something, strtof should parse the same prefix
    if endptr > 0 && endptrf > 0 {
        assert_eq!(endptr, endptrf, "strtod and strtof should consume same prefix");
    }

    // NaN/Inf should be handled gracefully
    let _ = val;
    let _ = valf;
}

fn fuzz_atoi(input: &StdlibFuzzInput) {
    let s = with_nul(&input.data);

    let i = conversion::atoi(&s);
    let l = conversion::atol(&s);
    let ll = conversion::atoll(&s);

    // atoi should be consistent with strtol base 10 (within i32 range)
    let (strtol_val, _) = conversion::strtol(&s, 10);
    assert_eq!(l, strtol_val, "atol and strtol(10) should agree");
    assert_eq!(ll, strtol_val, "atoll and strtol(10) should agree");
    assert_eq!(i, strtol_val as i32, "atoi should be truncated strtol");

    // atof should be consistent with strtod
    let f = conversion::atof(&s);
    let (strtod_val, _) = conversion::strtod(&s);
    assert_eq!(f.to_bits(), strtod_val.to_bits(), "atof and strtod should agree");
}

fn fuzz_qsort(input: &StdlibFuzzInput) {
    if input.values.is_empty() || input.values.len() > 1024 {
        return;
    }

    let width = std::mem::size_of::<i32>();
    let mut buf: Vec<u8> = Vec::with_capacity(input.values.len() * width);
    for &v in &input.values {
        buf.extend_from_slice(&v.to_ne_bytes());
    }

    sort::qsort(&mut buf, width, |a, b| {
        let va = i32::from_ne_bytes(a.try_into().unwrap_or([0; 4]));
        let vb = i32::from_ne_bytes(b.try_into().unwrap_or([0; 4]));
        va.cmp(&vb) as i32
    });

    // Verify sorted order
    for i in 1..input.values.len() {
        let prev = i32::from_ne_bytes(buf[(i - 1) * width..i * width].try_into().unwrap());
        let curr = i32::from_ne_bytes(buf[i * width..(i + 1) * width].try_into().unwrap());
        assert!(prev <= curr, "qsort output not sorted: {} > {}", prev, curr);
    }
}

fn fuzz_consistency(input: &StdlibFuzzInput) {
    let s = with_nul(&input.data);
    let base = normalize_base(input.base);

    // For base 10, strtol and strtoul should agree on non-negative values
    let (signed_val, signed_end) = conversion::strtol(&s, base);
    let (unsigned_val, unsigned_end) = conversion::strtoul(&s, base);

    // Both should consume the same prefix
    if signed_end > 0 && unsigned_end > 0 {
        // If the value is non-negative and fits in both, endptrs should match
        if signed_val >= 0 && (signed_val as u64) == unsigned_val {
            assert_eq!(signed_end, unsigned_end);
        }
    }
}
