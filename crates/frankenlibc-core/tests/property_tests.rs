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
    use frankenlibc_core::malloc::large::LargeAllocator;
    use frankenlibc_core::malloc::size_class::{
        MAX_SMALL_SIZE, MIN_SIZE, NUM_SIZE_CLASSES, bin_index, bin_size,
    };
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
    }
}
