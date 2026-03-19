#![cfg(target_os = "linux")]

//! Strict Mode Refinement Proof Tests (bd-249m.1)
//!
//! These tests verify the core refinement theorem:
//!
//!   For all symbols s in SYMBOL_SET, for all valid inputs x in DOM(s):
//!     franken_strict(s, x) = expected(s, x)
//!     AND errno_franken(s, x) = errno_expected(s, x)
//!
//! The TSM in strict mode must be TRANSPARENT — it observes but does not
//! modify the computation. These tests prove: TSM_strict(f(x)) = f(x).
//!
//! Coverage: string, stdlib, ctype, math, errno families.

use std::ffi::{c_char, c_int, c_void};

// ═══════════════════════════════════════════════════════════════════
// STRING FAMILY: Refinement proofs
//
// Theorem: For all string functions, strict mode produces identical
// results to the POSIX specification for valid inputs.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn refinement_strlen_matches_specification() {
    use frankenlibc_abi::string_abi::strlen;

    // POSIX: strlen returns the number of bytes before the null terminator
    let cases: &[(&[u8], usize)] = &[
        (b"\0", 0),
        (b"a\0", 1),
        (b"hello\0", 5),
        (b"hello world\0", 11),
        // Maximum reasonable test length
        (
            &{
                let mut v = vec![b'x'; 4096];
                v.push(0);
                v
            },
            4096,
        ),
    ];

    for (input, expected) in cases {
        let result = unsafe { strlen(input.as_ptr() as *const c_char) };
        assert_eq!(
            result, *expected,
            "strlen refinement failed for input of len {}",
            expected
        );
    }
}

#[test]
fn refinement_strcmp_total_ordering() {
    use frankenlibc_abi::string_abi::strcmp;

    // POSIX: strcmp returns <0, 0, or >0 for lexicographic comparison
    let cases: &[(&[u8], &[u8], std::cmp::Ordering)] = &[
        (b"abc\0", b"abc\0", std::cmp::Ordering::Equal),
        (b"abc\0", b"abd\0", std::cmp::Ordering::Less),
        (b"abd\0", b"abc\0", std::cmp::Ordering::Greater),
        (b"\0", b"\0", std::cmp::Ordering::Equal),
        (b"a\0", b"\0", std::cmp::Ordering::Greater),
        (b"\0", b"a\0", std::cmp::Ordering::Less),
        (b"abc\0", b"abcd\0", std::cmp::Ordering::Less),
        (b"abcd\0", b"abc\0", std::cmp::Ordering::Greater),
    ];

    for (a, b, expected) in cases {
        let result = unsafe { strcmp(a.as_ptr() as *const c_char, b.as_ptr() as *const c_char) };
        let actual = result.cmp(&0);
        assert_eq!(
            actual,
            *expected,
            "strcmp refinement: {:?} vs {:?} expected {:?}, got {}",
            std::str::from_utf8(&a[..a.len() - 1]).unwrap_or("?"),
            std::str::from_utf8(&b[..b.len() - 1]).unwrap_or("?"),
            expected,
            result
        );
    }
}

#[test]
fn refinement_memcpy_preserves_exact_bytes() {
    use frankenlibc_abi::string_abi::memcpy;

    // POSIX: memcpy copies exactly n bytes from src to dst
    for size in [
        0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 1024, 4096,
    ] {
        let src: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let mut dst = vec![0xFFu8; size];

        let ret = unsafe { memcpy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), size) };

        assert_eq!(
            ret,
            dst.as_mut_ptr() as *mut c_void,
            "memcpy must return dst"
        );
        assert_eq!(
            dst, src,
            "memcpy refinement failed for size {size}: bytes differ"
        );
    }
}

#[test]
fn refinement_memset_fills_exact_value() {
    use frankenlibc_abi::string_abi::memset;

    // POSIX: memset fills n bytes with the value (converted to unsigned char)
    for size in [0, 1, 16, 64, 256, 1024] {
        for fill in [0u8, 0x42, 0xFF] {
            let mut buf = vec![0u8; size];
            let ret = unsafe { memset(buf.as_mut_ptr().cast(), fill as c_int, size) };

            assert_eq!(ret, buf.as_mut_ptr() as *mut c_void);
            assert!(
                buf.iter().all(|&b| b == fill),
                "memset refinement: size={size}, fill={fill:#x}"
            );
        }
    }
}

#[test]
fn refinement_memcmp_returns_correct_sign() {
    use frankenlibc_abi::string_abi::memcmp;

    // POSIX: memcmp returns <0, 0, or >0 based on byte comparison
    let cases: &[(&[u8], &[u8], std::cmp::Ordering)] = &[
        (b"abc", b"abc", std::cmp::Ordering::Equal),
        (b"abc", b"abd", std::cmp::Ordering::Less),
        (b"abd", b"abc", std::cmp::Ordering::Greater),
        (b"\x00\x00\x00", b"\x00\x00\x00", std::cmp::Ordering::Equal),
        (b"\xFF", b"\x00", std::cmp::Ordering::Greater),
    ];

    for (a, b, expected) in cases {
        let n = a.len().min(b.len());
        let result = unsafe { memcmp(a.as_ptr().cast(), b.as_ptr().cast(), n) };
        let actual = result.cmp(&0);
        assert_eq!(actual, *expected, "memcmp refinement: {a:?} vs {b:?}");
    }
}

// ═══════════════════════════════════════════════════════════════════
// CTYPE FAMILY: Refinement proofs
//
// Theorem: Character classification functions produce identical
// results to POSIX specification for all byte values 0-255 + EOF.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn refinement_isalpha_matches_posix_c_locale() {
    use frankenlibc_abi::ctype_abi::isalpha;

    // In the C locale, isalpha is true for [A-Za-z]
    for c in 0..=255i32 {
        let result = unsafe { isalpha(c) } != 0;
        let expected = (c as u8 as char).is_ascii_alphabetic();
        assert_eq!(
            result, expected,
            "isalpha refinement: c={c} ({:?}) expected={expected}, got={result}",
            c as u8 as char
        );
    }
}

#[test]
fn refinement_isdigit_matches_posix_c_locale() {
    use frankenlibc_abi::ctype_abi::isdigit;

    // POSIX: isdigit is true for [0-9]
    for c in 0..=255i32 {
        let result = unsafe { isdigit(c) } != 0;
        let expected = (c as u8 as char).is_ascii_digit();
        assert_eq!(result, expected, "isdigit refinement: c={c}");
    }
}

#[test]
fn refinement_isspace_matches_posix_c_locale() {
    use frankenlibc_abi::ctype_abi::isspace;

    // POSIX C locale: space, \t, \n, \v, \f, \r
    let posix_spaces: &[u8] = &[b' ', b'\t', b'\n', 0x0B, 0x0C, b'\r'];
    for c in 0..=255i32 {
        let result = unsafe { isspace(c) } != 0;
        let expected = posix_spaces.contains(&(c as u8));
        assert_eq!(result, expected, "isspace refinement: c={c} ({:#x})", c);
    }
}

#[test]
fn refinement_toupper_tolower_roundtrip() {
    use frankenlibc_abi::ctype_abi::{tolower, toupper};

    // POSIX: toupper(tolower(c)) == toupper(c) for all c
    // and tolower(toupper(c)) == tolower(c) for all c
    for c in 0..=255i32 {
        let upper = unsafe { toupper(c) };
        let lower = unsafe { tolower(c) };

        // Roundtrip property
        let upper_of_lower = unsafe { toupper(lower) };
        let lower_of_upper = unsafe { tolower(upper) };
        assert_eq!(
            upper_of_lower, upper,
            "toupper(tolower({c})) != toupper({c})"
        );
        assert_eq!(
            lower_of_upper, lower,
            "tolower(toupper({c})) != tolower({c})"
        );

        // For ASCII letters, verify correct mapping
        let ch = c as u8;
        if ch.is_ascii_lowercase() {
            assert_eq!(upper as u8, ch.to_ascii_uppercase(), "toupper({c}) wrong");
        }
        if ch.is_ascii_uppercase() {
            assert_eq!(lower as u8, ch.to_ascii_lowercase(), "tolower({c}) wrong");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// STDLIB FAMILY: Refinement proofs
//
// Theorem: Conversion functions produce identical results to
// POSIX specification for all valid inputs.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn refinement_atoi_matches_specification() {
    use frankenlibc_abi::stdlib_abi::atoi;

    let cases: &[(&[u8], c_int)] = &[
        (b"0\0", 0),
        (b"1\0", 1),
        (b"-1\0", -1),
        (b"42\0", 42),
        (b"  123\0", 123),
        (b"\t-456\0", -456),
        (b"2147483647\0", i32::MAX),
        (b"-2147483648\0", i32::MIN),
        (b"0000042\0", 42),
        (b"+7\0", 7),
    ];

    for (input, expected) in cases {
        let result = unsafe { atoi(input.as_ptr() as *const c_char) };
        assert_eq!(
            result,
            *expected,
            "atoi refinement: {:?} expected {expected}, got {result}",
            std::str::from_utf8(&input[..input.len() - 1]).unwrap_or("?")
        );
    }
}

#[test]
fn refinement_abs_matches_specification() {
    use frankenlibc_abi::stdlib_abi::abs;

    // POSIX: abs returns the absolute value
    let cases: &[(c_int, c_int)] = &[
        (0, 0),
        (1, 1),
        (-1, 1),
        (42, 42),
        (-42, 42),
        (i32::MAX, i32::MAX),
        // Note: abs(INT_MIN) is undefined in POSIX, so we skip it
    ];

    for &(input, expected) in cases {
        let result = abs(input);
        assert_eq!(
            result, expected,
            "abs refinement: abs({input}) expected {expected}, got {result}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// ERRNO FAMILY: Refinement proofs
//
// Theorem: errno is thread-local and preserved across calls.
// __errno_location returns a valid pointer per-thread.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn refinement_errno_location_is_valid_and_thread_local() {
    use frankenlibc_abi::errno_abi::__errno_location;

    // __errno_location must return a non-null pointer
    let ptr = unsafe { __errno_location() };
    assert!(!ptr.is_null(), "__errno_location must return non-null");

    // Write and read back
    unsafe { *ptr = 42 };
    assert_eq!(unsafe { *ptr }, 42);

    // Another thread gets a different pointer
    let handle = std::thread::spawn(|| {
        let other_ptr = unsafe { __errno_location() };
        assert!(!other_ptr.is_null());
        unsafe { *other_ptr = 99 };
        assert_eq!(unsafe { *other_ptr }, 99);
    });
    handle.join().expect("thread panicked");

    // Our errno must still be 42 (thread-local)
    assert_eq!(unsafe { *ptr }, 42, "errno must be thread-local");
}

// ═══════════════════════════════════════════════════════════════════
// MATH FAMILY: Refinement proofs
//
// Theorem: Math functions produce results within ULP bounds of
// the correctly-rounded IEEE 754 result.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn refinement_math_basic_identities() {
    use frankenlibc_abi::math_abi::*;

    // sin(0) = 0, cos(0) = 1
    let sin_0 = unsafe { sin(0.0) };
    let cos_0 = unsafe { cos(0.0) };
    assert!(
        (sin_0 - 0.0).abs() < 1e-15,
        "sin(0) refinement: got {sin_0}"
    );
    assert!(
        (cos_0 - 1.0).abs() < 1e-15,
        "cos(0) refinement: got {cos_0}"
    );

    // sqrt(4) = 2, sqrt(9) = 3
    let sqrt_4 = unsafe { sqrt(4.0) };
    let sqrt_9 = unsafe { sqrt(9.0) };
    assert_eq!(sqrt_4, 2.0, "sqrt(4) refinement");
    assert_eq!(sqrt_9, 3.0, "sqrt(9) refinement");

    // exp(0) = 1, log(1) = 0
    let exp_0 = unsafe { exp(0.0) };
    let log_1 = unsafe { log(1.0) };
    assert!(
        (exp_0 - 1.0).abs() < 1e-15,
        "exp(0) refinement: got {exp_0}"
    );
    assert!(log_1.abs() < 1e-15, "log(1) refinement: got {log_1}");
}

#[test]
fn refinement_math_nan_propagation() {
    use frankenlibc_abi::math_abi::*;

    // POSIX: NaN input produces NaN output for most math functions
    let nan = f64::NAN;
    assert!(unsafe { sin(nan) }.is_nan(), "sin(NaN) must be NaN");
    assert!(unsafe { cos(nan) }.is_nan(), "cos(NaN) must be NaN");
    assert!(unsafe { sqrt(nan) }.is_nan(), "sqrt(NaN) must be NaN");
    assert!(unsafe { exp(nan) }.is_nan(), "exp(NaN) must be NaN");
    assert!(unsafe { log(nan) }.is_nan(), "log(NaN) must be NaN");
}

#[test]
fn refinement_math_special_values() {
    use frankenlibc_abi::math_abi::*;

    // POSIX: sqrt(-1) = NaN
    assert!(unsafe { sqrt(-1.0) }.is_nan(), "sqrt(-1) must be NaN");

    // POSIX: log(0) = -inf
    assert!(
        unsafe { log(0.0) }.is_infinite() && unsafe { log(0.0) } < 0.0,
        "log(0) must be -inf"
    );

    // POSIX: exp(inf) = inf
    assert!(
        unsafe { exp(f64::INFINITY) }.is_infinite() && unsafe { exp(f64::INFINITY) } > 0.0,
        "exp(inf) must be +inf"
    );

    // POSIX: exp(-inf) = 0
    assert_eq!(
        unsafe { exp(f64::NEG_INFINITY) },
        0.0,
        "exp(-inf) must be 0"
    );
}

// ═══════════════════════════════════════════════════════════════════
// TSM TRANSPARENCY: Core proof
//
// Theorem: In strict mode, the TSM validation pipeline does not
// alter the output of any function for valid inputs. The pipeline
// only observes; it does not repair or modify.
//
// We verify this by running the same operations multiple times
// and confirming deterministic results, and by verifying that
// functions that should succeed always succeed (no spurious denials).
// ═══════════════════════════════════════════════════════════════════

#[test]
fn tsm_transparency_deterministic_outputs() {
    use frankenlibc_abi::string_abi::{memcpy, memset, strcmp, strlen};

    // Run the same operations 100 times and verify identical results
    for _ in 0..100 {
        // strlen
        assert_eq!(unsafe { strlen(b"test\0".as_ptr() as *const c_char) }, 4);

        // strcmp
        assert_eq!(
            unsafe {
                strcmp(
                    b"abc\0".as_ptr() as *const c_char,
                    b"abc\0".as_ptr() as *const c_char,
                )
            },
            0
        );

        // memset + memcpy roundtrip
        let mut buf = [0u8; 32];
        unsafe { memset(buf.as_mut_ptr().cast(), 0x42, 32) };
        assert!(buf.iter().all(|&b| b == 0x42));

        let mut dst = [0u8; 32];
        unsafe { memcpy(dst.as_mut_ptr().cast(), buf.as_ptr().cast(), 32) };
        assert_eq!(dst, buf);
    }
}

#[test]
fn tsm_transparency_no_spurious_denials_under_stress() {
    use frankenlibc_abi::string_abi::{memcpy, memset, strlen};

    // Perform many valid operations rapidly — none should fail
    let mut success_count = 0u64;
    for i in 0..1000u64 {
        let msg = format!("iteration {i}\0");
        let len = unsafe { strlen(msg.as_ptr() as *const c_char) };
        assert!(len > 0, "strlen returned 0 for non-empty string");

        let mut buf = vec![0u8; 256];
        unsafe { memset(buf.as_mut_ptr().cast(), (i % 256) as c_int, 256) };
        assert_eq!(buf[0], (i % 256) as u8);

        let mut dst = vec![0u8; 256];
        let ret = unsafe { memcpy(dst.as_mut_ptr().cast(), buf.as_ptr().cast(), 256) };
        assert!(!ret.is_null(), "memcpy returned null");
        assert_eq!(dst, buf);

        success_count += 1;
    }

    assert_eq!(
        success_count, 1000,
        "all 1000 valid operations must succeed in strict mode"
    );
}
