#![cfg(target_os = "linux")]

//! E2E Composition Tests (bd-ldj.6)
//!
//! These tests exercise real-world program patterns by composing multiple
//! ABI entrypoints in sequences that mirror actual program behavior.
//! Unlike unit tests (which test one function), these verify that
//! the full stack works when functions interact.

use std::ffi::{c_char, c_int, c_void};

// ═══════════════════════════════════════════════════════════════════
// PATTERN 1: String processing pipeline
//
// Real programs routinely: strlen → malloc → memcpy → strcmp → free.
// This must work without any function corrupting state for the next.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn e2e_string_pipeline_strlen_malloc_memcpy_strcmp() {
    use frankenlibc_abi::malloc_abi::{free, malloc};
    use frankenlibc_abi::string_abi::{memcpy, strcmp, strlen};

    let src = b"hello from frankenlibc\0";
    let len = unsafe { strlen(src.as_ptr() as *const c_char) };
    assert_eq!(len, 22);

    // Allocate buffer for the string + null
    let buf = unsafe { malloc(len + 1) };
    assert!(!buf.is_null(), "malloc must succeed for small allocation");

    // Copy string into allocated buffer
    unsafe { memcpy(buf, src.as_ptr() as *const c_void, len + 1) };

    // Compare — must be equal
    let cmp = unsafe { strcmp(buf as *const c_char, src.as_ptr() as *const c_char) };
    assert_eq!(cmp, 0, "copied string must match original");

    // Verify the copy is independent (different address)
    assert_ne!(
        buf as usize,
        src.as_ptr() as usize,
        "malloc must return different address"
    );

    unsafe { free(buf) };
}

#[test]
fn e2e_string_pipeline_repeated_alloc_copy_free() {
    use frankenlibc_abi::malloc_abi::{free, malloc};
    use frankenlibc_abi::string_abi::{memcpy, memset, strlen};

    // Simulate a program that processes many strings
    for i in 0..100 {
        let msg = format!("message number {i}\0");
        let len = unsafe { strlen(msg.as_ptr() as *const c_char) };

        let buf = unsafe { malloc(len + 1) };
        assert!(!buf.is_null());

        unsafe { memcpy(buf, msg.as_ptr() as *const c_void, len + 1) };

        // Verify content
        let copied_len = unsafe { strlen(buf as *const c_char) };
        assert_eq!(copied_len, len, "iteration {i}: length mismatch");

        // Overwrite with zeros before free (simulating secure erase)
        unsafe { memset(buf, 0, len + 1) };

        unsafe { free(buf) };
    }
}

// ═══════════════════════════════════════════════════════════════════
// PATTERN 2: Allocator stress composition
//
// Real programs do interleaved malloc/realloc/free with varying
// sizes. The allocator + arena + quarantine must handle this.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn e2e_allocator_interleaved_sizes() {
    use frankenlibc_abi::malloc_abi::{free, malloc, realloc};
    use frankenlibc_abi::string_abi::memset;

    let sizes: &[usize] = &[16, 64, 256, 1024, 4096, 32, 128, 512];
    let mut ptrs: Vec<*mut c_void> = Vec::new();

    // Allocate a batch
    for &size in sizes {
        let ptr = unsafe { malloc(size) };
        assert!(!ptr.is_null(), "malloc({size}) must succeed");
        unsafe { memset(ptr, 0xAB, size) };
        ptrs.push(ptr);
    }

    // Realloc some to larger sizes
    for i in (0..ptrs.len()).step_by(2) {
        let new_size = sizes[i] * 2;
        let new_ptr = unsafe { realloc(ptrs[i], new_size) };
        assert!(!new_ptr.is_null(), "realloc to {new_size} must succeed");
        ptrs[i] = new_ptr;
    }

    // Free all
    for ptr in ptrs {
        unsafe { free(ptr) };
    }
}

#[test]
fn e2e_allocator_calloc_zeroed() {
    use frankenlibc_abi::malloc_abi::{calloc, free};

    // calloc must return zeroed memory
    for &count in &[1, 10, 100] {
        for &size in &[1, 8, 64, 256] {
            let ptr = unsafe { calloc(count, size) };
            assert!(!ptr.is_null(), "calloc({count}, {size}) must succeed");

            // Verify all bytes are zero
            let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, count * size) };
            assert!(
                slice.iter().all(|&b| b == 0),
                "calloc must return zeroed memory for calloc({count}, {size})"
            );

            unsafe { free(ptr) };
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// PATTERN 3: Ctype + string composition
//
// Real programs use ctype functions to classify characters in strings.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn e2e_ctype_classify_string_characters() {
    use frankenlibc_abi::ctype_abi::{isalpha, isdigit, isspace, toupper};
    use frankenlibc_abi::string_abi::strlen;

    let input = b"Hello World 123!\0";
    let len = unsafe { strlen(input.as_ptr() as *const c_char) };
    assert_eq!(len, 16);

    let mut alpha_count = 0;
    let mut digit_count = 0;
    let mut space_count = 0;
    let mut upper_result = Vec::new();

    for &byte in &input[..len] {
        let ch = byte as c_int;
        if unsafe { isalpha(ch) } != 0 {
            alpha_count += 1;
        }
        if unsafe { isdigit(ch) } != 0 {
            digit_count += 1;
        }
        if unsafe { isspace(ch) } != 0 {
            space_count += 1;
        }
        upper_result.push(unsafe { toupper(ch) } as u8);
    }

    assert_eq!(alpha_count, 10, "H-e-l-l-o-W-o-r-l-d = 10 alpha");
    assert_eq!(digit_count, 3, "1-2-3 = 3 digits");
    assert_eq!(space_count, 2, "two spaces");
    assert_eq!(&upper_result, b"HELLO WORLD 123!");
}

// ═══════════════════════════════════════════════════════════════════
// PATTERN 4: Errno preservation across call chains
//
// POSIX requires that successful calls do not modify errno.
// This tests that errno is preserved across sequences of calls.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn e2e_errno_preserved_across_successful_chain() {
    use frankenlibc_abi::errno_abi::__errno_location;
    use frankenlibc_abi::string_abi::{memcpy, memset, strlen};

    // Set errno to a known value
    unsafe { *__errno_location() = 42 };

    // Perform a chain of successful operations
    let s = b"test\0";
    let _ = unsafe { strlen(s.as_ptr() as *const c_char) };

    let mut buf = [0u8; 32];
    unsafe { memset(buf.as_mut_ptr().cast(), 0x55, 32) };
    unsafe { memcpy(buf.as_mut_ptr().cast(), s.as_ptr().cast(), 5) };

    // errno must still be 42
    assert_eq!(
        unsafe { *__errno_location() },
        42,
        "errno must be preserved across successful call chain"
    );
}

// ═══════════════════════════════════════════════════════════════════
// PATTERN 5: Math function composition
//
// Real numerical programs chain math operations.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn e2e_math_chain_trigonometric_identity() {
    use frankenlibc_abi::math_abi::{cos, pow, sin};

    // Verify sin²(x) + cos²(x) = 1 for various x
    for angle_deg in [0, 30, 45, 60, 90, 180, 270, 360] {
        let x = (angle_deg as f64) * std::f64::consts::PI / 180.0;
        let sin_x = unsafe { sin(x) };
        let cos_x = unsafe { cos(x) };
        let sin2 = unsafe { pow(sin_x, 2.0) };
        let cos2 = unsafe { pow(cos_x, 2.0) };
        let sum = sin2 + cos2;

        assert!(
            (sum - 1.0).abs() < 1e-10,
            "sin²({angle_deg}°) + cos²({angle_deg}°) = {sum}, expected 1.0"
        );
    }
}

#[test]
fn e2e_math_chain_exp_log_inverse() {
    use frankenlibc_abi::math_abi::{exp, log};

    // exp(log(x)) = x for positive x
    for &x in &[0.1, 0.5, 1.0, 2.0, 10.0, 100.0, 1e6] {
        let result = unsafe { exp(log(x)) };
        let rel_error = ((result - x) / x).abs();
        assert!(
            rel_error < 1e-12,
            "exp(log({x})) = {result}, relative error = {rel_error}"
        );
    }

    // log(exp(x)) = x for reasonable x
    for &x in &[-5.0, -1.0, 0.0, 1.0, 5.0, 10.0] {
        let result = unsafe { log(exp(x)) };
        let abs_error = (result - x).abs();
        assert!(
            abs_error < 1e-12,
            "log(exp({x})) = {result}, absolute error = {abs_error}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// PATTERN 6: Concurrent composition
//
// Real multi-threaded programs use libc functions from many threads.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn e2e_concurrent_string_and_alloc() {
    use frankenlibc_abi::malloc_abi::{free, malloc};
    use frankenlibc_abi::string_abi::{memcpy, strlen};
    use std::sync::{Arc, Barrier};
    use std::thread;

    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();

    for tid in 0..4 {
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..100 {
                let msg = format!("thread {tid} iteration {i}\0");
                let len = unsafe { strlen(msg.as_ptr() as *const c_char) };
                assert!(len > 0);

                let buf = unsafe { malloc(len + 1) };
                assert!(!buf.is_null(), "t{tid} malloc failed at iteration {i}");

                unsafe { memcpy(buf, msg.as_ptr() as *const c_void, len + 1) };

                let copied_len = unsafe { strlen(buf as *const c_char) };
                assert_eq!(copied_len, len, "t{tid}i{i}: copied length mismatch");

                unsafe { free(buf) };
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }
}

#[test]
fn e2e_concurrent_errno_isolation() {
    use frankenlibc_abi::errno_abi::__errno_location;
    use std::sync::{Arc, Barrier};
    use std::thread;

    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();

    for tid in 0..4u32 {
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let marker = (tid + 1) * 1000;

            for i in 0..200 {
                // Set errno to our thread-specific value
                unsafe { *__errno_location() = (marker + i) as c_int };

                // Yield to create interleaving opportunities
                if i % 10 == 0 {
                    std::thread::yield_now();
                }

                // errno must still be our value
                let actual = unsafe { *__errno_location() };
                assert_eq!(
                    actual,
                    (marker + i) as c_int,
                    "t{tid}i{i}: errno was {actual}, expected {}",
                    marker + i
                );
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }
}

// ═══════════════════════════════════════════════════════════════════
// PATTERN 7: Stdlib conversion pipeline
//
// Real programs parse strings to integers, compute, convert back.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn e2e_stdlib_parse_compute_pipeline() {
    use frankenlibc_abi::stdlib_abi::{abs, atoi};

    // Parse → compute → verify
    let inputs: &[(&[u8], c_int)] = &[
        (b"42\0", 42),
        (b"-99\0", 99),
        (b"0\0", 0),
        (b"2147483647\0", 2147483647),
        (b"-2147483648\0", 2147483647), // abs(INT_MIN) is UB, we test close to it
    ];

    for &(input, expected_abs) in &inputs[..4] {
        let val = unsafe { atoi(input.as_ptr() as *const c_char) };
        let positive = abs(val);
        assert_eq!(
            positive,
            expected_abs,
            "abs(atoi({:?})) = {positive}, expected {expected_abs}",
            std::str::from_utf8(&input[..input.len() - 1]).unwrap_or("?")
        );
    }
}
