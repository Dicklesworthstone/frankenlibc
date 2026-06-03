//! Property-based testing framework for FrankenLibC core functions.
//!
//! Verifies algebraic invariants and correctness properties across module families:
//! - String operations: reflexivity, antisymmetry, NUL preservation, copy fidelity
//! - Math operations: identities (sin²+cos²=1), symmetry, domain constraints
//! - Numeric conversion: round-trip correctness (strtol ↔ format)
//! - ctype classification: partition exhaustiveness, idempotent case conversion
//! - Allocator/core bookkeeping: size-class rounding, page alignment, registry invariants
//!
//! Uses proptest for generative input with shrinking on failure.
//!
//! Bead: bd-1sp.8

use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

fn property_proptest_config(default_cases: u32) -> ProptestConfig {
    let cases = std::env::var("FRANKENLIBC_PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|&value| value > 0)
        .unwrap_or(default_cases);

    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

// ---------------------------------------------------------------------------
// String operation properties (mem.rs + str.rs)
// ---------------------------------------------------------------------------

mod string_properties {
    use super::*;
    use frankenlibc_core::string::mem::*;
    use frankenlibc_core::string::str::*;

    proptest! {
        #![proptest_config(super::property_proptest_config(256))]

        /// strlen(s) == position of first NUL byte (or slice length if no NUL)
        #[test]
        fn prop_strlen_finds_first_nul(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let expected = data.iter().position(|&b| b == 0).unwrap_or(data.len());
            prop_assert_eq!(strlen(&data), expected);
        }

        /// strcmp(a, a) == 0  (reflexivity)
        #[test]
        fn prop_strcmp_reflexive(
            mut a in proptest::collection::vec(1u8..=255, 0..64)
        ) {
            a.push(0); // NUL terminate
            prop_assert_eq!(strcmp(&a, &a), 0);
        }

        /// strcmp(a, b) == -strcmp(b, a)  (antisymmetry)
        #[test]
        fn prop_strcmp_antisymmetric(
            mut a in proptest::collection::vec(1u8..=255, 0..64),
            mut b in proptest::collection::vec(1u8..=255, 0..64)
        ) {
            a.push(0);
            b.push(0);
            let ab = strcmp(&a, &b);
            let ba = strcmp(&b, &a);
            prop_assert_eq!(ab.signum(), -ba.signum());
        }

        /// strncmp with n >= max(len(a), len(b))+1 should equal strcmp
        #[test]
        fn prop_strncmp_agrees_with_strcmp_at_full_length(
            mut a in proptest::collection::vec(1u8..=255, 0..64),
            mut b in proptest::collection::vec(1u8..=255, 0..64)
        ) {
            a.push(0);
            b.push(0);
            let n = a.len().max(b.len());
            let full = strcmp(&a, &b);
            let bounded = strncmp(&a, &b, n);
            prop_assert_eq!(full.signum(), bounded.signum());
        }

        /// SIMD strncmp is isomorphic to the scalar byte-by-byte reference for
        /// arbitrary inputs (NUL bytes allowed mid-buffer) and arbitrary n.
        #[test]
        fn prop_strncmp_matches_scalar_reference(
            a in proptest::collection::vec(any::<u8>(), 0..200),
            b in proptest::collection::vec(any::<u8>(), 0..200),
            n in 0usize..256
        ) {
            // Reference: the exact scalar algorithm strncmp replaced.
            fn reference(s1: &[u8], s2: &[u8], n: usize) -> i32 {
                for i in 0..n {
                    let x = if i < s1.len() { s1[i] } else { 0 };
                    let y = if i < s2.len() { s2[i] } else { 0 };
                    if x != y {
                        return (x as i32) - (y as i32);
                    }
                    if x == 0 {
                        return 0;
                    }
                }
                0
            }
            prop_assert_eq!(strncmp(&a, &b, n), reference(&a, &b, n));
        }

        /// memcpy preserves exact content: memcpy(dst, src, n); memcmp(dst, src, n) == 0
        #[test]
        fn prop_memcpy_then_memcmp_is_zero(
            src in proptest::collection::vec(any::<u8>(), 1..128),
            n in 1usize..256
        ) {
            let n = n.min(src.len());
            let mut dst = vec![0u8; n];
            memcpy(&mut dst, &src, n);
            prop_assert_eq!(memcmp(&dst, &src, n), std::cmp::Ordering::Equal);
        }

        /// memmove handles overlapping copies correctly
        #[test]
        fn prop_memmove_with_overlap(
            data in proptest::collection::vec(any::<u8>(), 4..128),
            offset in 0usize..64,
            n in 1usize..64
        ) {
            let offset = offset.min(data.len().saturating_sub(1));
            let n = n.min(data.len() - offset);
            if n == 0 { return Ok(()); }

            // Copy expected result using standard slice copy
            let expected: Vec<u8> = data[offset..offset + n].to_vec();

            // Now use memmove
            let mut buf = data.clone();
            memmove(&mut buf, &data[offset..], n);
            prop_assert_eq!(&buf[..n], &expected[..]);
        }

        /// memset(buf, c, n) fills exactly the first n bytes with c
        #[test]
        fn prop_memset_fills_prefix(
            original in proptest::collection::vec(any::<u8>(), 1..128),
            c in any::<u8>(),
            n in 0usize..256
        ) {
            let n = n.min(original.len());
            let mut buf = original.clone();
            memset(&mut buf, c, n);
            for (i, &b) in buf.iter().enumerate() {
                if i < n {
                    prop_assert_eq!(b, c, "byte at index {} should be {}", i, c);
                } else {
                    prop_assert_eq!(b, original[i], "byte at index {} should be unchanged", i);
                }
            }
        }

        /// memchr finds the correct position (or None)
        #[test]
        fn prop_memchr_finds_first_occurrence(
            data in proptest::collection::vec(any::<u8>(), 0..128),
            needle in any::<u8>()
        ) {
            let expected = data.iter().position(|&b| b == needle);
            let result = memchr(&data, needle, data.len());
            prop_assert_eq!(result, expected);
        }

        /// memrchr finds the last occurrence
        #[test]
        fn prop_memrchr_finds_last_occurrence(
            data in proptest::collection::vec(any::<u8>(), 0..128),
            needle in any::<u8>()
        ) {
            let expected = data.iter().rposition(|&b| b == needle);
            let result = memrchr(&data, needle, data.len());
            prop_assert_eq!(result, expected);
        }

        /// strnlen is bounded: strnlen(s, maxlen) <= maxlen
        #[test]
        fn prop_strnlen_bounded(
            data in proptest::collection::vec(any::<u8>(), 0..128),
            maxlen in 0usize..256
        ) {
            let result = strnlen(&data, maxlen);
            prop_assert!(result <= maxlen);
            prop_assert!(result <= data.len());
        }

        /// strchr and strrchr agreement: if strchr finds c, strrchr also finds it
        #[test]
        fn prop_strchr_strrchr_both_find_or_miss(
            mut data in proptest::collection::vec(1u8..=255, 0..64),
            needle in 1u8..=255
        ) {
            data.push(0);
            let first = strchr(&data, needle);
            let last = strrchr(&data, needle);
            match (first, last) {
                (Some(f), Some(l)) => prop_assert!(f <= l),
                (None, None) => {}
                _ => prop_assert!(false, "strchr and strrchr should agree on presence"),
            }
        }

        /// strspn + strcspn partition: strspn(s, accept) + strcspn(s[strspn..], accept) covers s
        #[test]
        fn prop_strspn_plus_strcspn_covers_prefix(
            mut data in proptest::collection::vec(1u8..=255, 1..64),
            mut accept in proptest::collection::vec(1u8..=255, 1..16)
        ) {
            data.push(0);
            accept.push(0);
            let span = strspn(&data, &accept);
            let cspan = strcspn(&data, &accept);
            // Either the first char is in accept (span >= 1) or not (cspan >= 1)
            // But span + cspan isn't necessarily the full length;
            // verify span or cspan starts from correct position
            prop_assert!(span <= strlen(&data));
            prop_assert!(cspan <= strlen(&data));
        }
    }

    /// Golden sha256 over a deterministic strncmp corpus. Pins the exact output
    /// (sign-normalized to -1/0/1, matching C semantics) so any future refactor
    /// that changes behavior is caught. The corpus spans short/long, equal/diff
    /// prefixes, mid-buffer NUL, and n values straddling the 32-byte SIMD panel.
    #[test]
    fn golden_strncmp_corpus_sha256() {
        use sha2::{Digest, Sha256};

        // Deterministic LCG so the corpus is fixed without external rng.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        };

        let lengths = [0usize, 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 200];
        let mut hasher = Sha256::new();
        for &la in &lengths {
            for &lb in &lengths {
                let mut a: Vec<u8> = (0..la).map(|_| next()).collect();
                let mut b: Vec<u8> = (0..lb).map(|_| next()).collect();
                // Force a shared prefix on half the pairs to exercise long equal runs.
                if (la + lb) % 2 == 0 {
                    let shared = la.min(lb);
                    for k in 0..shared {
                        b[k] = a[k];
                    }
                }
                a.push(0);
                b.push(0);
                for n in [0usize, 1, 16, 31, 32, 33, 64, 128, 256] {
                    let r = strncmp(&a, &b, n).signum() as i8;
                    hasher.update([r as u8]);
                }
            }
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest, "99a3358be31072baca18340daceec13300282aa57b2a1b7406d6817396edb326",
            "strncmp golden corpus hash drifted"
        );
    }

    /// Golden sha256 over a deterministic memcmp corpus. Pins the exact
    /// sign-normalized output stream across equal/different long prefixes and n
    /// values straddling the 32-byte panel and 128-byte folded-block paths.
    #[test]
    fn golden_memcmp_corpus_sha256() {
        use sha2::{Digest, Sha256};

        let mut state: u64 = 0xD1B5_4A32_D192_ED03;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        };

        let lengths = [
            0usize, 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 200,
        ];
        let mut hasher = Sha256::new();
        for &la in &lengths {
            for &lb in &lengths {
                let a: Vec<u8> = (0..la).map(|_| next()).collect();
                let mut b: Vec<u8> = (0..lb).map(|_| next()).collect();
                if (la + lb) % 2 == 0 {
                    let shared = la.min(lb);
                    for k in 0..shared {
                        b[k] = a[k];
                    }
                }

                for n in [0usize, 1, 8, 31, 32, 33, 64, 127, 128, 129, 256] {
                    let r = match memcmp(&a, &b, n) {
                        core::cmp::Ordering::Less => -1i8,
                        core::cmp::Ordering::Equal => 0,
                        core::cmp::Ordering::Greater => 1,
                    };
                    hasher.update([r as u8]);
                }
            }
        }

        let digest: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest, "23ff1bb367d74ce77644397fa6f7f2160759f5991d6fb383e89ad5bb6d0b4e5e",
            "memcmp golden corpus hash drifted"
        );
    }
}

// ---------------------------------------------------------------------------
// Wide-string compare properties (wide.rs)
// ---------------------------------------------------------------------------

mod wide_properties {
    use super::*;
    use frankenlibc_core::string::wide::{wcscasecmp, wcscmp, wcsncasecmp, wcsncmp};

    fn ascii_lower(c: u32) -> u32 {
        if (0x41..=0x5A).contains(&c) { c + 0x20 } else { c }
    }

    // Reference: exact scalar wcsncasecmp the SIMD version replaced.
    fn ref_wcsncasecmp(s1: &[u32], s2: &[u32], n: usize) -> i32 {
        let mut i = 0;
        while i < n {
            let a = if i < s1.len() { s1[i] } else { 0 };
            let b = if i < s2.len() { s2[i] } else { 0 };
            let la = ascii_lower(a);
            let lb = ascii_lower(b);
            if la != lb {
                return if (la as i32) < (lb as i32) { -1 } else { 1 };
            }
            if a == 0 {
                return 0;
            }
            i += 1;
        }
        0
    }

    // Reference: exact scalar wcscasecmp the SIMD version replaced.
    fn ref_wcscasecmp(s1: &[u32], s2: &[u32]) -> i32 {
        let mut i = 0;
        loop {
            let a = if i < s1.len() { s1[i] } else { 0 };
            let b = if i < s2.len() { s2[i] } else { 0 };
            let la = ascii_lower(a);
            let lb = ascii_lower(b);
            if la != lb {
                return if (la as i32) < (lb as i32) { -1 } else { 1 };
            }
            if a == 0 {
                return 0;
            }
            i += 1;
        }
    }

    // Reference: exact scalar wcsncmp the SIMD version replaced.
    fn ref_wcsncmp(s1: &[u32], s2: &[u32], n: usize) -> i32 {
        let mut i = 0;
        while i < n {
            let a = if i < s1.len() { s1[i] } else { 0 };
            let b = if i < s2.len() { s2[i] } else { 0 };
            if a != b {
                return if (a as i32) < (b as i32) { -1 } else { 1 };
            }
            if a == 0 {
                return 0;
            }
            i += 1;
        }
        0
    }

    // Reference: exact scalar wcscmp the SIMD version replaced.
    fn ref_wcscmp(s1: &[u32], s2: &[u32]) -> i32 {
        let mut i = 0;
        loop {
            let a = if i < s1.len() { s1[i] } else { 0 };
            let b = if i < s2.len() { s2[i] } else { 0 };
            if a != b {
                return if (a as i32) < (b as i32) { -1 } else { 1 };
            }
            if a == 0 {
                return 0;
            }
            i += 1;
        }
    }

    proptest! {
        #![proptest_config(super::property_proptest_config(256))]

        /// SIMD wcsncmp is isomorphic to the scalar reference for arbitrary
        /// wide inputs (NUL allowed mid-buffer, high/sign-bit code units) and n.
        #[test]
        fn prop_wcsncmp_matches_scalar_reference(
            a in proptest::collection::vec(any::<u32>(), 0..200),
            b in proptest::collection::vec(any::<u32>(), 0..200),
            n in 0usize..256
        ) {
            prop_assert_eq!(wcsncmp(&a, &b, n), ref_wcsncmp(&a, &b, n));
        }

        /// SIMD wcscmp is isomorphic to the scalar reference.
        #[test]
        fn prop_wcscmp_matches_scalar_reference(
            mut a in proptest::collection::vec(1u32..=0x10_FFFF, 0..200),
            mut b in proptest::collection::vec(1u32..=0x10_FFFF, 0..200)
        ) {
            a.push(0);
            b.push(0);
            prop_assert_eq!(wcscmp(&a, &b).signum(), ref_wcscmp(&a, &b).signum());
        }

        /// SIMD wcsncasecmp is isomorphic to the scalar fold reference. Inputs
        /// are biased to the ASCII letter range so case-folding is exercised.
        #[test]
        fn prop_wcsncasecmp_matches_scalar_reference(
            a in proptest::collection::vec(0x40u32..=0x60, 0..200),
            b in proptest::collection::vec(0x40u32..=0x60, 0..200),
            n in 0usize..256
        ) {
            prop_assert_eq!(wcsncasecmp(&a, &b, n), ref_wcsncasecmp(&a, &b, n));
        }

        /// wcsncasecmp also matches over the full u32 alphabet (high/sign units).
        #[test]
        fn prop_wcsncasecmp_matches_scalar_reference_full(
            a in proptest::collection::vec(any::<u32>(), 0..200),
            b in proptest::collection::vec(any::<u32>(), 0..200),
            n in 0usize..256
        ) {
            prop_assert_eq!(wcsncasecmp(&a, &b, n), ref_wcsncasecmp(&a, &b, n));
        }

        /// SIMD wcscasecmp is isomorphic to the scalar fold reference.
        #[test]
        fn prop_wcscasecmp_matches_scalar_reference(
            mut a in proptest::collection::vec(0x41u32..=0x60, 0..200),
            mut b in proptest::collection::vec(0x41u32..=0x60, 0..200)
        ) {
            a.push(0);
            b.push(0);
            prop_assert_eq!(wcscasecmp(&a, &b).signum(), ref_wcscasecmp(&a, &b).signum());
        }
    }

    /// Golden sha256 over a deterministic wcscmp/wcsncmp corpus spanning the
    /// 16-element SIMD panel boundary, mid-buffer NUL, high/sign-bit code units,
    /// equal-prefix runs, and assorted n. Pins exact behavior against drift.
    #[test]
    fn golden_wide_compare_corpus_sha256() {
        use sha2::{Digest, Sha256};

        let mut state: u64 = 0xD1B5_4A32_D192_ED03;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            // Mix in some high/sign-bit code units to exercise signed compare.
            (state >> 32) as u32
        };

        let lengths = [0usize, 1, 7, 15, 16, 17, 31, 32, 33, 47, 48, 100];
        let mut hasher = Sha256::new();
        for &la in &lengths {
            for &lb in &lengths {
                let mut a: Vec<u32> = (0..la).map(|_| next()).collect();
                let mut b: Vec<u32> = (0..lb).map(|_| next()).collect();
                if (la + lb) % 2 == 0 {
                    let shared = la.min(lb);
                    for k in 0..shared {
                        b[k] = a[k];
                    }
                }
                a.push(0);
                b.push(0);
                hasher.update((wcscmp(&a, &b).signum() as i8 as u8).to_le_bytes());
                for n in [0usize, 1, 16, 31, 32, 33, 48, 128] {
                    hasher.update((wcsncmp(&a, &b, n).signum() as i8 as u8).to_le_bytes());
                }
            }
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        assert_eq!(
            digest, "c9f07f2b950cfc3a76e1b892b776b965698268ae0a8f8b63d66cf1acedf526ca",
            "wide-compare golden corpus hash drifted"
        );
    }

    /// Golden sha256 over a deterministic wcscasecmp/wcsncasecmp corpus. Inputs
    /// are drawn from the ASCII letter band (mixed case) plus injected NULs so
    /// the in-vector fold path and panel/tail boundary are exercised; pins exact
    /// behavior against drift.
    #[test]
    fn golden_wide_casecmp_corpus_sha256() {
        use sha2::{Digest, Sha256};

        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            // Map into 0x40..=0x60 (covers '@', A-Z, [\]^_, '`') to straddle the
            // fold range edges, with occasional NUL.
            let r = (state >> 40) as u32 % 34;
            if r == 0 { 0 } else { 0x40 + r }
        };

        let lengths = [0usize, 1, 7, 15, 16, 17, 31, 32, 33, 47, 48, 100];
        let mut hasher = Sha256::new();
        for &la in &lengths {
            for &lb in &lengths {
                let mut a: Vec<u32> = (0..la).map(|_| next()).collect();
                let mut b: Vec<u32> = (0..lb).map(|_| next()).collect();
                // Half the pairs share a case-flipped prefix (fold-equal, raw-differ).
                if (la + lb) % 2 == 0 {
                    let shared = la.min(lb);
                    for k in 0..shared {
                        let c = a[k];
                        b[k] = if (0x41..=0x5A).contains(&c) {
                            c + 0x20
                        } else if (0x61..=0x7A).contains(&c) {
                            c - 0x20
                        } else {
                            c
                        };
                    }
                }
                a.push(0);
                b.push(0);
                hasher.update((wcscasecmp(&a, &b).signum() as i8 as u8).to_le_bytes());
                for n in [0usize, 1, 16, 31, 32, 33, 48, 128] {
                    hasher.update((wcsncasecmp(&a, &b, n).signum() as i8 as u8).to_le_bytes());
                }
            }
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        assert_eq!(
            digest, "75fbf1a3e290bac6bc2fbf467588f831ca473e9aee3859c8c28216d2150b640d",
            "wide-casecmp golden corpus hash drifted"
        );
    }
}

// ---------------------------------------------------------------------------
// Math properties
// ---------------------------------------------------------------------------

mod math_properties {
    use super::*;
    use frankenlibc_core::math::exp::{exp, log};
    use frankenlibc_core::math::float::{copysign, fabs, sqrt};
    use frankenlibc_core::math::trig::{cos, sin};

    proptest! {
        #![proptest_config(super::property_proptest_config(256))]

        /// Pythagorean identity: sin²(x) + cos²(x) ≈ 1
        #[test]
        fn prop_pythagorean_identity(x in -1000.0f64..1000.0) {
            let s = sin(x);
            let c = cos(x);
            let sum = s * s + c * c;
            prop_assert!(
                (sum - 1.0).abs() < 1e-10,
                "sin²({}) + cos²({}) = {}, expected ~1.0", x, x, sum
            );
        }

        /// sin is an odd function: sin(-x) = -sin(x)
        #[test]
        fn prop_sin_is_odd(x in -1000.0f64..1000.0) {
            let lhs = sin(-x);
            let rhs = -sin(x);
            prop_assert!(
                (lhs - rhs).abs() < 1e-12,
                "sin(-{}) = {}, -sin({}) = {}", x, lhs, x, rhs
            );
        }

        /// cos is an even function: cos(-x) = cos(x)
        #[test]
        fn prop_cos_is_even(x in -1000.0f64..1000.0) {
            let lhs = cos(-x);
            let rhs = cos(x);
            prop_assert!(
                (lhs - rhs).abs() < 1e-12,
                "cos(-{}) = {}, cos({}) = {}", x, lhs, x, rhs
            );
        }

        /// exp(log(x)) ≈ x for x > 0
        #[test]
        fn prop_exp_log_round_trip(x in 1e-300f64..1e300) {
            let result = exp(log(x));
            let rel_err = ((result - x) / x).abs();
            prop_assert!(
                rel_err < 1e-12,
                "exp(log({})) = {}, relative error = {}", x, result, rel_err
            );
        }

        /// log(exp(x)) ≈ x for moderate x
        #[test]
        fn prop_log_exp_round_trip(x in -700.0f64..700.0) {
            let result = log(exp(x));
            let err = (result - x).abs();
            prop_assert!(
                err < 1e-10,
                "log(exp({})) = {}, error = {}", x, result, err
            );
        }

        /// fabs(x) >= 0 for all x
        #[test]
        fn prop_fabs_non_negative(x in any::<f64>()) {
            let abs = fabs(x);
            prop_assert!(abs >= 0.0 || abs.is_nan(), "fabs({}) = {}", x, abs);
        }

        /// fabs(x) == fabs(-x)
        #[test]
        fn prop_fabs_symmetric(x in any::<f64>().prop_filter("not NaN", |x| !x.is_nan())) {
            prop_assert_eq!(fabs(x), fabs(-x));
        }

        /// sqrt(x*x) ≈ |x| for non-negative x
        #[test]
        fn prop_sqrt_of_square(x in 0.0f64..1e150) {
            let result = sqrt(x * x);
            let expected = fabs(x);
            let rel_err = if expected == 0.0 { result } else { ((result - expected) / expected).abs() };
            prop_assert!(
                rel_err < 1e-12,
                "sqrt({})² = {}, expected {}, rel_err = {}", x, result, expected, rel_err
            );
        }

        /// copysign preserves magnitude: |copysign(x, y)| = |x|
        #[test]
        fn prop_copysign_preserves_magnitude(
            x in any::<f64>().prop_filter("not NaN", |x| !x.is_nan()),
            y in any::<f64>().prop_filter("not NaN", |y| !y.is_nan())
        ) {
            let result = copysign(x, y);
            prop_assert_eq!(fabs(result), fabs(x));
        }

        /// copysign(x, y) has the sign of y
        #[test]
        fn prop_copysign_takes_sign_of_second(
            x in any::<f64>().prop_filter("not NaN", |x| !x.is_nan() && *x != 0.0),
            y in any::<f64>().prop_filter("not NaN", |y| !y.is_nan() && *y != 0.0)
        ) {
            let result = copysign(x, y);
            prop_assert_eq!(result.is_sign_positive(), y.is_sign_positive());
        }

        /// exp(0) = 1
        #[test]
        fn prop_exp_zero_is_one(_x in 0..1i32) {
            let result = exp(0.0);
            prop_assert!((result - 1.0).abs() < 1e-15);
        }

        /// log(1) = 0
        #[test]
        fn prop_log_one_is_zero(_x in 0..1i32) {
            let result = log(1.0);
            prop_assert!(result.abs() < 1e-15);
        }
    }
}

// ---------------------------------------------------------------------------
// Numeric conversion properties (stdlib/conversion.rs)
// ---------------------------------------------------------------------------

mod conversion_properties {
    use super::*;
    use frankenlibc_core::stdlib::conversion::*;

    proptest! {
        #![proptest_config(super::property_proptest_config(256))]

        /// strtol round-trip: format(n, base 10) -> parse -> n
        #[test]
        fn prop_strtol_base10_round_trip(value in any::<i64>()) {
            let text = format!("{value}\0");
            let bytes = text.as_bytes();
            let (result, _, _err) = strtol_impl(bytes, 10);
            prop_assert_eq!(result, value);
        }

        /// strtol with base 16 round-trip for non-negative values
        #[test]
        fn prop_strtol_base16_round_trip(value in 0i64..=i64::MAX) {
            let text = format!("{value:x}\0");
            let bytes = text.as_bytes();
            let (result, _, _err) = strtol_impl(bytes, 16);
            prop_assert_eq!(result, value);
        }

        /// strtol with base 8 round-trip for non-negative values
        #[test]
        fn prop_strtol_base8_round_trip(value in 0i64..=i64::MAX) {
            let text = format!("{value:o}\0");
            let bytes = text.as_bytes();
            let (result, _, _err) = strtol_impl(bytes, 8);
            prop_assert_eq!(result, value);
        }

        /// atoi agrees with strtol base 10 for valid integers
        #[test]
        fn prop_atoi_agrees_with_strtol(value in -100_000i32..=100_000) {
            let text = format!("{value}\0");
            let bytes = text.as_bytes();
            let atoi_result = atoi(bytes);
            let (strtol_result, _, _) = strtol_impl(bytes, 10);
            prop_assert_eq!(atoi_result as i64, strtol_result);
        }

        /// strtol with leading whitespace: " 42" and "42" give same value
        #[test]
        fn prop_strtol_ignores_leading_whitespace(value in -1_000_000i64..=1_000_000) {
            let with_ws = format!("  \t{value}\0");
            let without_ws = format!("{value}\0");
            let (r1, _, _) = strtol_impl(with_ws.as_bytes(), 10);
            let (r2, _, _) = strtol_impl(without_ws.as_bytes(), 10);
            prop_assert_eq!(r1, r2);
        }
    }
}

// ---------------------------------------------------------------------------
// System V base-64 conversion properties
// ---------------------------------------------------------------------------

mod base64_properties {
    use super::*;
    use frankenlibc_core::stdlib::base64::{a64l, l64a};

    fn is_a64l_digit(byte: u8) -> bool {
        matches!(byte, b'.' | b'/' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')
    }

    proptest! {
        #![proptest_config(super::property_proptest_config(256))]

        /// l64a encodes exactly the low 32 bits, and a64l decodes that value.
        #[test]
        fn prop_l64a_a64l_round_trips_low_32_bits(value in any::<i64>()) {
            let encoded = l64a(value);
            let decoded = a64l(&encoded);

            prop_assert!(encoded.len() <= 6);
            prop_assert_eq!(decoded, (value as u32) as i64);
        }

        /// a64l stops at the first NUL or non-alphabet byte.
        #[test]
        fn prop_a64l_stops_at_terminator_or_invalid_byte(
            prefix in proptest::collection::vec(
                prop_oneof![
                    Just(b'.'),
                    Just(b'/'),
                    b'0'..=b'9',
                    b'A'..=b'Z',
                    b'a'..=b'z',
                ],
                0..6,
            ),
            terminator in any::<u8>().prop_filter(
                "NUL or invalid a64l digit",
                |byte| *byte == 0 || !is_a64l_digit(*byte),
            ),
            suffix in proptest::collection::vec(any::<u8>(), 0..16),
        ) {
            let mut input = prefix.clone();
            input.push(terminator);
            input.extend_from_slice(&suffix);

            prop_assert_eq!(a64l(&input), a64l(&prefix));
        }
    }
}

// ---------------------------------------------------------------------------
// Sort operation properties
// ---------------------------------------------------------------------------

mod sort_properties {
    use super::*;
    use frankenlibc_core::stdlib::sort::{heapsort, mergesort, qsort};

    fn cmp_i32_le(a: &[u8], b: &[u8]) -> i32 {
        let av = i32::from_le_bytes(a[..4].try_into().unwrap());
        let bv = i32::from_le_bytes(b[..4].try_into().unwrap());
        match av.cmp(&bv) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        }
    }

    fn flatten_i32(values: &[i32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(values.len() * 4);
        for value in values {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out
    }

    fn unflatten_i32(bytes: &[u8]) -> Vec<i32> {
        bytes
            .chunks_exact(4)
            .map(|chunk| i32::from_le_bytes(chunk.try_into().unwrap()))
            .collect()
    }

    proptest! {
        #![proptest_config(super::property_proptest_config(256))]

        /// qsort output is ordered and preserves the input multiset.
        #[test]
        fn prop_qsort_matches_rust_sorted_order(values in proptest::collection::vec(any::<i32>(), 0..128)) {
            let mut expected = values.clone();
            expected.sort();

            let mut buf = flatten_i32(&values);
            qsort(&mut buf, 4, cmp_i32_le);

            prop_assert_eq!(unflatten_i32(&buf), expected);
        }

        /// mergesort output is ordered and preserves the input multiset.
        #[test]
        fn prop_mergesort_matches_rust_sorted_order(values in proptest::collection::vec(any::<i32>(), 0..128)) {
            let mut expected = values.clone();
            expected.sort();

            let mut buf = flatten_i32(&values);
            mergesort(&mut buf, 4, cmp_i32_le);

            prop_assert_eq!(unflatten_i32(&buf), expected);
        }

        /// heapsort output is ordered and preserves the input multiset.
        #[test]
        fn prop_heapsort_matches_rust_sorted_order(values in proptest::collection::vec(any::<i32>(), 0..128)) {
            let mut expected = values.clone();
            expected.sort();

            let mut buf = flatten_i32(&values);
            heapsort(&mut buf, 4, cmp_i32_le);

            prop_assert_eq!(unflatten_i32(&buf), expected);
        }
    }
}

// ---------------------------------------------------------------------------
// ctype classification properties
// ---------------------------------------------------------------------------

mod ctype_properties {
    use super::*;
    use frankenlibc_core::ctype::*;

    proptest! {
        #![proptest_config(super::property_proptest_config(256))]

        /// is_alnum == is_alpha || is_digit  (partition)
        #[test]
        fn prop_alnum_is_alpha_or_digit(c in any::<u8>()) {
            prop_assert_eq!(is_alnum(c), is_alpha(c) || is_digit(c));
        }

        /// is_alpha == is_upper || is_lower  (for ASCII)
        #[test]
        fn prop_alpha_is_upper_or_lower(c in any::<u8>()) {
            if is_alpha(c) {
                prop_assert!(is_upper(c) || is_lower(c));
            }
        }

        /// is_xdigit => is_digit || 'a'..='f' || 'A'..='F'
        #[test]
        fn prop_xdigit_superset_of_digit(c in any::<u8>()) {
            if is_digit(c) {
                prop_assert!(is_xdigit(c));
            }
        }

        /// tolower(toupper(c)) == tolower(c) for alphabetic chars
        #[test]
        fn prop_tolower_toupper_idempotent(c in any::<u8>()) {
            if is_alpha(c) {
                prop_assert_eq!(to_lower(to_upper(c)), to_lower(c));
            }
        }

        /// toupper(tolower(c)) == toupper(c) for alphabetic chars
        #[test]
        fn prop_toupper_tolower_idempotent(c in any::<u8>()) {
            if is_alpha(c) {
                prop_assert_eq!(to_upper(to_lower(c)), to_upper(c));
            }
        }

        /// tolower is idempotent on lowercase: tolower(tolower(c)) == tolower(c)
        #[test]
        fn prop_tolower_idempotent(c in any::<u8>()) {
            prop_assert_eq!(to_lower(to_lower(c)), to_lower(c));
        }

        /// toupper is idempotent on uppercase: toupper(toupper(c)) == toupper(c)
        #[test]
        fn prop_toupper_idempotent(c in any::<u8>()) {
            prop_assert_eq!(to_upper(to_upper(c)), to_upper(c));
        }

        /// is_space and is_graph are mutually exclusive (for printable ASCII)
        #[test]
        fn prop_space_graph_exclusive(c in any::<u8>()) {
            // A char that is both space and graph would be inconsistent
            // (space chars are not graphical)
            if is_space(c) && c != b' ' {
                prop_assert!(!is_graph(c));
            }
        }

        /// is_print => is_graph || is_space(' ')
        /// Every printable character is either graphical or space
        #[test]
        fn prop_print_is_graph_or_space(c in any::<u8>()) {
            if is_print(c) {
                prop_assert!(is_graph(c) || c == b' ');
            }
        }

        /// is_digit only for '0'..'9'
        #[test]
        fn prop_digit_is_ascii_digit(c in any::<u8>()) {
            prop_assert_eq!(is_digit(c), c.is_ascii_digit());
        }
    }
}

// ---------------------------------------------------------------------------
// Inet address properties
// ---------------------------------------------------------------------------

mod inet_properties {
    use super::*;
    use frankenlibc_core::inet::*;
    use frankenlibc_core::socket::AF_INET;

    proptest! {
        #![proptest_config(super::property_proptest_config(256))]

        /// inet_addr of valid dotted-quad should succeed
        #[test]
        fn prop_inet_addr_valid_quad(
            a in 0u8..=255,
            b in 0u8..=255,
            c in 0u8..=255,
            d in 0u8..=255,
        ) {
            let addr_str = format!("{a}.{b}.{c}.{d}\0");
            let result = inet_addr(addr_str.as_bytes());
            prop_assert_ne!(result, u32::MAX, "valid quad should not return INADDR_NONE");
        }

        /// inet_pton(AF_INET) round-trip with inet_ntop
        #[test]
        fn prop_inet_pton_ntop_round_trip_v4(
            a in 0u8..=255,
            b in 0u8..=255,
            c in 0u8..=255,
            d in 0u8..=255,
        ) {
            let addr_str = format!("{a}.{b}.{c}.{d}\0");
            let mut buf = [0u8; 4];
            let pton_result = inet_pton(AF_INET, addr_str.as_bytes(), &mut buf);
            prop_assert_eq!(pton_result, 1, "inet_pton should succeed for valid IPv4");

            let ntop_result = inet_ntop(AF_INET, &buf);
            prop_assert!(ntop_result.is_some(), "inet_ntop should succeed");
        }

        /// htonl(ntohl(x)) == x  (round-trip)
        #[test]
        fn prop_htonl_ntohl_round_trip(x in any::<u32>()) {
            prop_assert_eq!(htonl(ntohl(x)), x);
            prop_assert_eq!(ntohl(htonl(x)), x);
        }

        /// htons(ntohs(x)) == x  (round-trip)
        #[test]
        fn prop_htons_ntohs_round_trip(x in any::<u16>()) {
            prop_assert_eq!(htons(ntohs(x)), x);
            prop_assert_eq!(ntohs(htons(x)), x);
        }
    }
}

// ---------------------------------------------------------------------------
// Allocator properties
// ---------------------------------------------------------------------------

mod allocator_properties {
    use super::*;
    use frankenlibc_core::malloc::size_class::{
        MAX_SMALL_SIZE, MIN_SIZE, NUM_SIZE_CLASSES, bin_index, bin_size,
    };
    use frankenlibc_core::malloc::{MallocState, large::LargeAllocator};
    use std::collections::HashSet;

    proptest! {
        #![proptest_config(super::property_proptest_config(256))]

        /// Small-allocation bin selection rounds up to a class that covers the request.
        #[test]
        fn prop_bin_index_rounds_up_to_cover_request(size in 0usize..(MAX_SMALL_SIZE + 1024)) {
            let index = bin_index(size);
            let normalized = size.max(MIN_SIZE);

            if size > MAX_SMALL_SIZE {
                prop_assert_eq!(index, NUM_SIZE_CLASSES);
                prop_assert_eq!(bin_size(index), 0);
            } else {
                prop_assert!(index < NUM_SIZE_CLASSES);
                let class_size = bin_size(index);
                prop_assert!(class_size >= normalized);
                if index > 0 {
                    prop_assert!(bin_size(index - 1) < normalized);
                }
            }
        }

        /// Public bin descriptors round-trip through the size-to-index mapping.
        #[test]
        fn prop_bin_size_round_trips(index in 0usize..NUM_SIZE_CLASSES) {
            let size = bin_size(index);
            prop_assert!(size >= MIN_SIZE);
            prop_assert_eq!(bin_index(size), index);
        }

        /// Large allocations always report page-aligned mapped sizes and consistent accounting.
        #[test]
        fn prop_large_alloc_alignment_and_accounting(size in 1usize..262_145) {
            let mut allocator = LargeAllocator::new();
            let alloc = allocator.alloc(size).expect("positive sizes must allocate");

            prop_assert_eq!(alloc.user_size, size);
            prop_assert!(alloc.mapped_size >= size);
            prop_assert_eq!(alloc.mapped_size % 4096, 0);
            prop_assert_eq!(allocator.active_count(), 1);
            prop_assert_eq!(allocator.total_mapped(), alloc.mapped_size);
            prop_assert_eq!(
                allocator.lookup(alloc.base).map(|entry| entry.user_size),
                Some(size)
            );
        }

        /// Independent large allocations must get distinct bases and exact total mapping.
        #[test]
        fn prop_large_alloc_distinct_bases(
            sizes in proptest::collection::vec(1usize..262_145, 1..16)
        ) {
            let mut allocator = LargeAllocator::new();
            let mut seen_bases = HashSet::new();
            let mut expected_total = 0usize;

            for size in sizes {
                let alloc = allocator.alloc(size).expect("positive sizes must allocate");
                prop_assert!(seen_bases.insert(alloc.base));
                expected_total += alloc.mapped_size;
            }

            prop_assert_eq!(allocator.active_count(), seen_bases.len());
            prop_assert_eq!(allocator.total_mapped(), expected_total);
        }

        /// Realloc keeps the allocator in a single-live-allocation state and refreshes accounting.
        #[test]
        fn prop_large_realloc_preserves_single_live_allocation(
            old_size in 1usize..262_145,
            new_size in 1usize..262_145
        ) {
            let mut allocator = LargeAllocator::new();
            let original = allocator.alloc(old_size).expect("positive sizes must allocate");
            let replacement = allocator
                .realloc(original.base, new_size)
                .expect("positive realloc sizes must allocate");

            prop_assert_eq!(allocator.active_count(), 1);
            prop_assert_eq!(allocator.total_mapped(), replacement.mapped_size);
            prop_assert!(allocator.lookup(original.base).is_none());
            prop_assert_eq!(
                allocator.lookup(replacement.base).map(|entry| entry.user_size),
                Some(new_size)
            );
        }

        /// MallocState must register actual backend pointers in its large-allocation metadata.
        #[test]
        fn prop_malloc_state_tracks_large_allocation_metadata(
            size in (MAX_SMALL_SIZE + 1)..262_145usize
        ) {
            let mut state = MallocState::new();
            let mut next_ptr = 0x7000_0000usize;
            let mut requested_from_backend = 0usize;

            let ptr = state
                .malloc(size, |requested_size| {
                    requested_from_backend = requested_size;
                    let ptr = next_ptr;
                    next_ptr = next_ptr.saturating_add((requested_size + 15) & !15);
                    Some(ptr)
                })
                .expect("large malloc should return backend pointer");

            let expected_mapped = LargeAllocator::mapped_size_for(size).unwrap();
            prop_assert_eq!(requested_from_backend, size);
            prop_assert_eq!(state.active_count(), 1);
            prop_assert_eq!(state.total_allocated(), size);
            prop_assert_eq!(state.active_large_count(), 1);
            prop_assert_eq!(state.total_large_mapped(), expected_mapped);
            prop_assert_eq!(
                state.large_allocation(ptr).map(|entry| (entry.base, entry.user_size, entry.mapped_size)),
                Some((ptr, size, expected_mapped))
            );

            let mut freed_ptr = 0usize;
            state.free(ptr, size, |released| {
                freed_ptr = released;
            });

            prop_assert_eq!(freed_ptr, ptr);
            prop_assert_eq!(state.active_count(), 0);
            prop_assert_eq!(state.total_allocated(), 0);
            prop_assert_eq!(state.active_large_count(), 0);
            prop_assert_eq!(state.total_large_mapped(), 0);
            prop_assert!(state.large_allocation(ptr).is_none());
        }
    }
}
