#![cfg(target_os = "linux")]

//! Integration tests for `<string.h>` ABI entrypoints.

use frankenlibc_abi::htm_fast_path::{
    HtmTestMode, htm_restore_test_mode_for_tests, htm_swap_abort_code_for_tests,
    htm_swap_test_mode_for_tests,
};
use frankenlibc_abi::string_abi::*;
use frankenlibc_abi::unistd_abi::strerror_l;
use serde_json::Value;
use std::ffi::{CStr, c_char, c_int, c_void};

fn with_simd_mask<T>(mask: u32, f: impl FnOnce() -> T) -> T {
    let previous = string_simd_swap_feature_mask_for_tests(Some(mask));
    let outcome = f();
    string_simd_restore_feature_mask_for_tests(previous);
    outcome
}

// ===========================================================================
// memcpy / memmove / memset / memcmp / memchr / memrchr
// ===========================================================================

#[test]
fn memcpy_copies_bytes() {
    let src = b"hello world";
    let mut dst = [0u8; 16];
    let ret = unsafe { memcpy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), src.len()) };
    assert_eq!(ret, dst.as_mut_ptr().cast::<c_void>());
    assert_eq!(&dst[..src.len()], src);
}

#[test]
fn memcpy_records_ffi_pcc_gate_when_runtime_ready() {
    signal_runtime_ready_for_tests();
    let _ = take_last_decision_gate_for_tests();

    let src = b"pcc-fast-path";
    let mut dst = [0u8; 16];
    let ret = unsafe { memcpy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), src.len()) };

    assert_eq!(ret, dst.as_mut_ptr().cast::<c_void>());
    assert_eq!(&dst[..src.len()], src);
    assert_eq!(
        take_last_decision_gate_for_tests(),
        Some("runtime_policy.ffi_pcc.decide")
    );
}

#[test]
fn memcpy_zero_length_is_noop() {
    let src = b"data";
    let mut dst = [0u8; 8];
    unsafe { memcpy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), 0) };
    assert_eq!(dst, [0u8; 8]);
}

#[test]
fn memcpy_htm_fast_path_commits_when_forced() {
    memcpy_htm_reset_for_tests();
    let previous_mode = htm_swap_test_mode_for_tests(HtmTestMode::ForceCommit);
    let before = memcpy_htm_snapshot_for_tests();

    let src = *b"speculative-copy-works";
    let mut dst = [0u8; 22];
    let ret = unsafe { memcpy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), src.len()) };

    let after = memcpy_htm_snapshot_for_tests();
    htm_restore_test_mode_for_tests(previous_mode);

    assert_eq!(ret, dst.as_mut_ptr().cast::<c_void>());
    assert_eq!(&dst[..src.len()], &src);
    assert!(
        after.commits > before.commits,
        "memcpy should record an HTM commit before={before:?} after={after:?}"
    );
    assert_eq!(after.fallbacks, before.fallbacks);
}

#[test]
fn memcpy_htm_abort_falls_back_and_preserves_bytes() {
    memcpy_htm_reset_for_tests();
    let previous_mode = htm_swap_test_mode_for_tests(HtmTestMode::ForceAbort);
    let previous_code = htm_swap_abort_code_for_tests(0x55AA);
    let before = memcpy_htm_snapshot_for_tests();

    let src = *b"fallback-copy-preserves-data";
    let mut dst = [0u8; 28];
    let ret = unsafe { memcpy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), src.len()) };

    let after = memcpy_htm_snapshot_for_tests();
    htm_restore_test_mode_for_tests(previous_mode);
    let _ = htm_swap_abort_code_for_tests(previous_code);

    assert_eq!(ret, dst.as_mut_ptr().cast::<c_void>());
    assert_eq!(&dst[..src.len()], &src);
    assert!(
        after.aborts > before.aborts,
        "memcpy should record an HTM abort before={before:?} after={after:?}"
    );
    assert!(
        after.fallbacks > before.fallbacks,
        "memcpy aborts should take the software fallback before={before:?} after={after:?}"
    );
    assert_eq!(after.last_abort_code, 0x55AA);
}

#[test]
fn memmove_handles_overlapping_forward() {
    let mut buf = *b"abcdefghij";
    // Move "cdefgh" forward by 2 (overlapping)
    unsafe {
        memmove(
            buf.as_mut_ptr().add(2).cast(),
            buf.as_ptr().add(0).cast(),
            6,
        );
    }
    assert_eq!(&buf[2..8], b"abcdef");
}

#[test]
fn memmove_handles_overlapping_backward() {
    let mut buf = *b"abcdefghij";
    unsafe {
        memmove(
            buf.as_mut_ptr().add(0).cast(),
            buf.as_ptr().add(2).cast(),
            6,
        );
    }
    assert_eq!(&buf[..6], b"cdefgh");
}

#[test]
fn memset_fills_buffer() {
    let mut buf = [0u8; 10];
    let ret = unsafe { memset(buf.as_mut_ptr().cast(), 0x42, 5) };
    assert_eq!(ret, buf.as_mut_ptr().cast::<c_void>());
    assert_eq!(&buf, &[0x42, 0x42, 0x42, 0x42, 0x42, 0, 0, 0, 0, 0]);
}

#[test]
fn memcmp_equal() {
    let a = b"hello";
    let b = b"hello";
    assert_eq!(
        unsafe { memcmp(a.as_ptr().cast(), b.as_ptr().cast(), 5) },
        0
    );
}

#[test]
fn memcmp_less_than() {
    let a = b"abc";
    let b = b"abd";
    assert!(unsafe { memcmp(a.as_ptr().cast(), b.as_ptr().cast(), 3) } < 0);
}

#[test]
fn memcmp_greater_than() {
    let a = b"abd";
    let b = b"abc";
    assert!(unsafe { memcmp(a.as_ptr().cast(), b.as_ptr().cast(), 3) } > 0);
}

#[test]
fn simd_audit_lists_memcpy_memcmp_and_strlen_certificates() {
    let audit: Value = serde_json::from_str(simd_isomorphism_audit_json_for_tests())
        .expect("simd audit JSON should parse");
    let entries = audit["entries"]
        .as_array()
        .expect("entries must be an array");
    for symbol in ["memcpy", "memcmp", "strlen"] {
        assert!(
            entries.iter().any(|entry| entry["function"] == symbol),
            "missing audit row for {symbol}"
        );
    }
}

#[test]
fn memcpy_dispatch_prefers_avx2_when_available() {
    with_simd_mask(string_simd_feature_mask_avx2_sse42_for_tests(), || {
        let src = [0u8; 256];
        let mut dst = [0u8; 256];
        assert_eq!(
            memcpy_dispatch_label_for_tests(dst.as_mut_ptr() as usize, src.as_ptr() as usize, 256),
            "avx2"
        );
    });
}

#[test]
fn memcmp_dispatch_uses_neon_when_forced() {
    with_simd_mask(string_simd_feature_mask_neon_for_tests(), || {
        let a = [0u8; 64];
        let b = [0u8; 64];
        assert_eq!(
            memcmp_dispatch_label_for_tests(a.as_ptr() as usize, b.as_ptr() as usize, 64),
            "neon"
        );
    });
}

#[test]
fn memcpy_forced_avx2_handles_all_16_alignments() {
    with_simd_mask(string_simd_feature_mask_avx2_for_tests(), || {
        let mut src = [0u8; 160];
        for (i, byte) in src.iter_mut().enumerate() {
            *byte = i as u8;
        }

        for src_offset in 0..16 {
            for dst_offset in 0..16 {
                let mut dst = [0u8; 160];
                unsafe {
                    memcpy(
                        dst.as_mut_ptr().add(dst_offset).cast(),
                        src.as_ptr().add(src_offset).cast(),
                        64,
                    );
                }
                assert_eq!(
                    &dst[dst_offset..dst_offset + 64],
                    &src[src_offset..src_offset + 64],
                    "src_offset={src_offset} dst_offset={dst_offset}"
                );
            }
        }
    });
}

#[test]
fn memcmp_forced_sse42_matches_reference_on_all_16_alignments() {
    with_simd_mask(string_simd_feature_mask_sse42_for_tests(), || {
        let mut lhs = [0u8; 160];
        let mut rhs = [0u8; 160];
        for (i, byte) in lhs.iter_mut().enumerate() {
            *byte = i as u8;
        }
        for lhs_offset in 0..16 {
            for rhs_offset in 0..16 {
                rhs.fill(0xA5);
                rhs[rhs_offset..rhs_offset + 32].copy_from_slice(&lhs[lhs_offset..lhs_offset + 32]);
                assert_eq!(
                    unsafe {
                        memcmp(
                            lhs.as_ptr().add(lhs_offset).cast(),
                            rhs.as_ptr().add(rhs_offset).cast(),
                            32,
                        )
                    },
                    0,
                    "lhs_offset={lhs_offset} rhs_offset={rhs_offset}"
                );
            }
        }

        rhs[63] = rhs[63].wrapping_add(1);
        let cmp = unsafe { memcmp(lhs.as_ptr().add(1).cast(), rhs.as_ptr().add(1).cast(), 64) };
        assert!(cmp < 0);
    });
}

#[test]
fn memchr_finds_byte() {
    let data = b"hello world";
    let ptr = unsafe { memchr(data.as_ptr().cast(), b'w' as c_int, data.len()) };
    assert!(!ptr.is_null());
    let offset = unsafe { (ptr as *const u8).offset_from(data.as_ptr()) };
    assert_eq!(offset, 6);
}

#[test]
fn memchr_not_found_returns_null() {
    let data = b"hello";
    let ptr = unsafe { memchr(data.as_ptr().cast(), b'z' as c_int, data.len()) };
    assert!(ptr.is_null());
}

#[test]
fn memrchr_finds_last_occurrence() {
    let data = b"abcabc";
    let ptr = unsafe { memrchr(data.as_ptr().cast(), b'a' as c_int, data.len()) };
    assert!(!ptr.is_null());
    let offset = unsafe { (ptr as *const u8).offset_from(data.as_ptr()) };
    assert_eq!(offset, 3);
}

// ===========================================================================
// strlen / strcmp / strcpy / strncpy / strcat / strncat
// ===========================================================================

#[test]
fn strlen_measures_correctly() {
    assert_eq!(unsafe { strlen(c"".as_ptr()) }, 0);
    assert_eq!(unsafe { strlen(c"hello".as_ptr()) }, 5);
    assert_eq!(unsafe { strlen(c"a".as_ptr()) }, 1);
}

#[test]
fn strlen_dispatch_prefers_avx2_for_wide_strings() {
    with_simd_mask(string_simd_feature_mask_avx2_for_tests(), || {
        let buf = [b'x'; 96];
        assert_eq!(
            strlen_dispatch_label_for_tests(buf.as_ptr() as usize, buf.len()),
            "avx2"
        );
    });
}

#[test]
fn strlen_forced_neon_matches_scalar_reference_on_all_16_alignments() {
    with_simd_mask(string_simd_feature_mask_neon_for_tests(), || {
        for offset in 0..16 {
            let mut buf = [0i8; 80];
            for byte in &mut buf[offset..offset + 31] {
                *byte = b'z' as i8;
            }
            buf[offset + 31] = 0;
            let ptr = unsafe { buf.as_ptr().add(offset) };
            assert_eq!(unsafe { strlen(ptr) }, 31, "offset={offset}");
        }
    });
}

#[test]
fn strcmp_equal_strings() {
    assert_eq!(unsafe { strcmp(c"abc".as_ptr(), c"abc".as_ptr()) }, 0);
}

#[test]
fn strcmp_less_than() {
    assert!(unsafe { strcmp(c"abc".as_ptr(), c"abd".as_ptr()) } < 0);
}

#[test]
fn strcmp_greater_than() {
    assert!(unsafe { strcmp(c"abd".as_ptr(), c"abc".as_ptr()) } > 0);
}

#[test]
fn strcmp_empty_strings() {
    assert_eq!(unsafe { strcmp(c"".as_ptr(), c"".as_ptr()) }, 0);
}

#[test]
fn strcmp_prefix() {
    assert!(unsafe { strcmp(c"abc".as_ptr(), c"abcdef".as_ptr()) } < 0);
}

#[test]
fn strcpy_copies_string() {
    let mut dst = [0_i8; 16];
    let ret = unsafe { strcpy(dst.as_mut_ptr(), c"hello".as_ptr()) };
    assert_eq!(ret, dst.as_mut_ptr());
    let s = unsafe { CStr::from_ptr(dst.as_ptr()) };
    assert_eq!(s.to_bytes(), b"hello");
}

#[test]
fn strncpy_copies_and_pads() {
    let mut dst = [0xFF_u8; 10];
    unsafe { strncpy(dst.as_mut_ptr().cast(), c"hi".as_ptr(), 5) };
    assert_eq!(&dst[..5], &[b'h', b'i', 0, 0, 0]);
    // Bytes beyond n should be untouched
    assert_eq!(dst[5], 0xFF);
}

#[test]
fn strcat_appends() {
    let mut buf = [0_i8; 32];
    unsafe {
        strcpy(buf.as_mut_ptr(), c"hello".as_ptr());
        strcat(buf.as_mut_ptr(), c" world".as_ptr());
    }
    let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(s.to_bytes(), b"hello world");
}

#[test]
fn strncat_appends_with_limit() {
    let mut buf = [0_i8; 32];
    unsafe {
        strcpy(buf.as_mut_ptr(), c"hello".as_ptr());
        strncat(buf.as_mut_ptr(), c" world!!".as_ptr(), 6);
    }
    let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(s.to_bytes(), b"hello world");
}

// ===========================================================================
// strncmp / strnlen / stpcpy / stpncpy / strchrnul (original tests)
// ===========================================================================

#[test]
fn strncmp_returns_zero_for_n_zero() {
    let result = unsafe { strncmp(c"alpha".as_ptr(), c"beta".as_ptr(), 0) };
    assert_eq!(result, 0);
}

#[test]
fn strncmp_obeys_count_limit() {
    let lhs = c"abcdef".as_ptr();
    let rhs = c"abcxyz".as_ptr();
    assert_eq!(unsafe { strncmp(lhs, rhs, 3) }, 0);
    assert!(unsafe { strncmp(lhs, rhs, 4) } < 0);
}

#[test]
fn strncmp_stops_after_nul_terminator() {
    let lhs_buf = [b'a', b'b', 0, b'c', b'd', 0];
    let rhs_buf = [b'a', b'b', 0, b'e', b'f', 0];
    assert_eq!(
        unsafe { strncmp(lhs_buf.as_ptr().cast(), rhs_buf.as_ptr().cast(), 8) },
        0
    );
}

#[test]
fn strnlen_stops_at_nul() {
    assert_eq!(unsafe { strnlen(c"hello".as_ptr(), 16) }, 5);
}

#[test]
fn strnlen_respects_maximum_count() {
    assert_eq!(unsafe { strnlen(c"hello".as_ptr(), 3) }, 3);
}

#[test]
fn stpcpy_returns_pointer_to_trailing_nul() {
    let mut dst = [0_i8; 16];
    let end = unsafe { stpcpy(dst.as_mut_ptr(), c"hello".as_ptr()) };
    let offset = unsafe { end.offset_from(dst.as_ptr()) };
    assert_eq!(offset, 5);
}

#[test]
fn stpncpy_returns_n_when_source_exhausts_count() {
    let mut dst = [0_i8; 16];
    let end = unsafe { stpncpy(dst.as_mut_ptr(), c"world".as_ptr(), 3) };
    let offset = unsafe { end.offset_from(dst.as_ptr()) };
    assert_eq!(offset, 3);
}

#[test]
fn stpncpy_returns_first_nul_when_source_shorter() {
    let mut dst = [0_i8; 16];
    let end = unsafe { stpncpy(dst.as_mut_ptr(), c"hi".as_ptr(), 5) };
    let offset = unsafe { end.offset_from(dst.as_ptr()) };
    assert_eq!(offset, 2);
}

#[test]
fn strchrnul_returns_match_when_present() {
    let pos = unsafe { strchrnul(c"franken".as_ptr(), b'n' as c_int) };
    let offset = unsafe { pos.offset_from(c"franken".as_ptr()) };
    assert_eq!(offset, 3);
}

#[test]
fn strchrnul_returns_terminator_when_absent() {
    let haystack = c"franken".as_ptr();
    let pos = unsafe { strchrnul(haystack, b'z' as c_int) };
    let offset = unsafe { pos.offset_from(haystack) };
    assert_eq!(offset, 7);
}

// ===========================================================================
// strchr / strrchr / strstr / strcasestr
// ===========================================================================

#[test]
fn strchr_finds_first_occurrence() {
    let ptr = unsafe { strchr(c"abcabc".as_ptr(), b'b' as c_int) };
    assert!(!ptr.is_null());
    let offset = unsafe { ptr.offset_from(c"abcabc".as_ptr()) };
    assert_eq!(offset, 1);
}

#[test]
fn strchr_finds_nul_terminator() {
    let ptr = unsafe { strchr(c"hello".as_ptr(), 0) };
    assert!(!ptr.is_null());
    let offset = unsafe { ptr.offset_from(c"hello".as_ptr()) };
    assert_eq!(offset, 5);
}

#[test]
fn strchr_not_found_returns_null() {
    let ptr = unsafe { strchr(c"hello".as_ptr(), b'z' as c_int) };
    assert!(ptr.is_null());
}

#[test]
fn strrchr_finds_last_occurrence() {
    let ptr = unsafe { strrchr(c"abcabc".as_ptr(), b'a' as c_int) };
    assert!(!ptr.is_null());
    let offset = unsafe { ptr.offset_from(c"abcabc".as_ptr()) };
    assert_eq!(offset, 3);
}

#[test]
fn strstr_finds_substring() {
    let ptr = unsafe { strstr(c"hello world".as_ptr(), c"world".as_ptr()) };
    assert!(!ptr.is_null());
    let offset = unsafe { ptr.offset_from(c"hello world".as_ptr()) };
    assert_eq!(offset, 6);
}

#[test]
fn strstr_empty_needle_returns_haystack() {
    let hay = c"hello".as_ptr();
    let ptr = unsafe { strstr(hay, c"".as_ptr()) };
    assert_eq!(ptr, hay as *mut c_char);
}

#[test]
fn strstr_not_found_returns_null() {
    let ptr = unsafe { strstr(c"hello".as_ptr(), c"xyz".as_ptr()) };
    assert!(ptr.is_null());
}

#[test]
fn strcasestr_case_insensitive() {
    let ptr = unsafe { strcasestr(c"Hello World".as_ptr(), c"world".as_ptr()) };
    assert!(!ptr.is_null());
    let offset = unsafe { ptr.offset_from(c"Hello World".as_ptr()) };
    assert_eq!(offset, 6);
}

// ===========================================================================
// strcasecmp / strncasecmp
// ===========================================================================

#[test]
fn strcasecmp_ignores_case() {
    assert_eq!(
        unsafe { strcasecmp(c"Hello".as_ptr(), c"hello".as_ptr()) },
        0
    );
    assert_eq!(unsafe { strcasecmp(c"ABC".as_ptr(), c"abc".as_ptr()) }, 0);
}

#[test]
fn strcasecmp_detects_difference() {
    assert_ne!(unsafe { strcasecmp(c"abc".as_ptr(), c"abd".as_ptr()) }, 0);
}

#[test]
fn strncasecmp_with_limit() {
    assert_eq!(
        unsafe { strncasecmp(c"ABCdef".as_ptr(), c"abcXYZ".as_ptr(), 3) },
        0
    );
    assert_ne!(
        unsafe { strncasecmp(c"ABCdef".as_ptr(), c"abcXYZ".as_ptr(), 4) },
        0
    );
}

// ===========================================================================
// strspn / strcspn / strpbrk
// ===========================================================================

#[test]
fn strspn_counts_accepted_prefix() {
    assert_eq!(
        unsafe { strspn(c"12345abc".as_ptr(), c"0123456789".as_ptr()) },
        5
    );
}

#[test]
fn strspn_zero_when_no_match() {
    assert_eq!(
        unsafe { strspn(c"abc".as_ptr(), c"0123456789".as_ptr()) },
        0
    );
}

#[test]
fn strcspn_counts_rejected_prefix() {
    assert_eq!(
        unsafe { strcspn(c"hello, world".as_ptr(), c", ".as_ptr()) },
        5
    );
}

#[test]
fn strpbrk_finds_first_matching_char() {
    let ptr = unsafe { strpbrk(c"hello world".as_ptr(), c"aeiou".as_ptr()) };
    assert!(!ptr.is_null());
    let offset = unsafe { ptr.offset_from(c"hello world".as_ptr()) };
    assert_eq!(offset, 1); // 'e' at position 1
}

#[test]
fn strpbrk_not_found_returns_null() {
    let ptr = unsafe { strpbrk(c"xyz".as_ptr(), c"aeiou".as_ptr()) };
    assert!(ptr.is_null());
}

// ===========================================================================
// strtok_r / strsep
// ===========================================================================

#[test]
fn strtok_r_tokenizes_string() {
    let mut buf = *b"hello,world,test\0";
    let mut saveptr: *mut c_char = std::ptr::null_mut();

    let tok1 = unsafe { strtok_r(buf.as_mut_ptr().cast(), c",".as_ptr(), &mut saveptr) };
    assert!(!tok1.is_null());
    assert_eq!(unsafe { CStr::from_ptr(tok1) }.to_bytes(), b"hello");

    let tok2 = unsafe { strtok_r(std::ptr::null_mut(), c",".as_ptr(), &mut saveptr) };
    assert!(!tok2.is_null());
    assert_eq!(unsafe { CStr::from_ptr(tok2) }.to_bytes(), b"world");

    let tok3 = unsafe { strtok_r(std::ptr::null_mut(), c",".as_ptr(), &mut saveptr) };
    assert!(!tok3.is_null());
    assert_eq!(unsafe { CStr::from_ptr(tok3) }.to_bytes(), b"test");

    let tok4 = unsafe { strtok_r(std::ptr::null_mut(), c",".as_ptr(), &mut saveptr) };
    assert!(tok4.is_null());
}

#[test]
fn strsep_tokenizes_string() {
    let mut buf = *b"a:b:c\0";
    let mut ptr: *mut c_char = buf.as_mut_ptr().cast();

    let tok1 = unsafe { strsep(&mut ptr, c":".as_ptr()) };
    assert!(!tok1.is_null());
    assert_eq!(unsafe { CStr::from_ptr(tok1) }.to_bytes(), b"a");

    let tok2 = unsafe { strsep(&mut ptr, c":".as_ptr()) };
    assert!(!tok2.is_null());
    assert_eq!(unsafe { CStr::from_ptr(tok2) }.to_bytes(), b"b");

    let tok3 = unsafe { strsep(&mut ptr, c":".as_ptr()) };
    assert!(!tok3.is_null());
    assert_eq!(unsafe { CStr::from_ptr(tok3) }.to_bytes(), b"c");
}

// ===========================================================================
// strdup / strndup
// ===========================================================================

#[test]
fn strdup_copies_string() {
    let dup = unsafe { strdup(c"hello".as_ptr()) };
    assert!(!dup.is_null());
    assert_eq!(unsafe { CStr::from_ptr(dup) }.to_bytes(), b"hello");
    unsafe { frankenlibc_abi::malloc_abi::free(dup.cast()) };
}

#[test]
fn strndup_copies_with_limit() {
    let dup = unsafe { strndup(c"hello world".as_ptr(), 5) };
    assert!(!dup.is_null());
    assert_eq!(unsafe { CStr::from_ptr(dup) }.to_bytes(), b"hello");
    unsafe { frankenlibc_abi::malloc_abi::free(dup.cast()) };
}

// ===========================================================================
// memmem / mempcpy / memccpy
// ===========================================================================

#[test]
fn memmem_finds_subsequence() {
    let haystack = b"hello world";
    let needle = b"world";
    let ptr = unsafe {
        memmem(
            haystack.as_ptr().cast(),
            haystack.len(),
            needle.as_ptr().cast(),
            needle.len(),
        )
    };
    assert!(!ptr.is_null());
    let offset = unsafe { (ptr as *const u8).offset_from(haystack.as_ptr()) };
    assert_eq!(offset, 6);
}

#[test]
fn memmem_not_found_returns_null() {
    let haystack = b"hello";
    let needle = b"xyz";
    let ptr = unsafe {
        memmem(
            haystack.as_ptr().cast(),
            haystack.len(),
            needle.as_ptr().cast(),
            needle.len(),
        )
    };
    assert!(ptr.is_null());
}

#[test]
fn mempcpy_returns_past_end() {
    let src = b"data";
    let mut dst = [0u8; 8];
    let ret = unsafe { mempcpy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), src.len()) };
    let offset = unsafe { (ret as *const u8).offset_from(dst.as_ptr()) };
    assert_eq!(offset, 4);
    assert_eq!(&dst[..4], b"data");
}

#[test]
fn memccpy_stops_at_character() {
    let src = b"hello\nworld";
    let mut dst = [0u8; 16];
    let ret = unsafe {
        memccpy(
            dst.as_mut_ptr().cast(),
            src.as_ptr().cast(),
            b'\n' as c_int,
            src.len(),
        )
    };
    assert!(!ret.is_null());
    // memccpy copies up to and including the stop character
    let offset = unsafe { (ret as *const u8).offset_from(dst.as_ptr()) };
    assert_eq!(offset, 6); // "hello\n" = 6 bytes
    assert_eq!(&dst[..6], b"hello\n");
}

// ===========================================================================
// bzero / bcmp / strerror / strerror_r
// ===========================================================================

#[test]
fn bzero_zeroes_buffer() {
    let mut buf = [0xFF_u8; 8];
    unsafe { bzero(buf.as_mut_ptr().cast(), 4) };
    assert_eq!(&buf, &[0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]);
}

#[test]
fn bcmp_equal() {
    let a = b"hello";
    let b = b"hello";
    assert_eq!(unsafe { bcmp(a.as_ptr().cast(), b.as_ptr().cast(), 5) }, 0);
}

#[test]
fn bcmp_not_equal() {
    let a = b"hello";
    let b = b"world";
    assert_ne!(unsafe { bcmp(a.as_ptr().cast(), b.as_ptr().cast(), 5) }, 0);
}

#[test]
fn strerror_returns_message_for_known_errno() {
    let msg = unsafe { strerror(libc::ENOENT) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) };
    assert!(!s.to_bytes().is_empty());
}

#[test]
fn strerror_r_populates_buffer() {
    let mut buf = [0_i8; 128];
    let rc = unsafe { strerror_r(libc::EACCES, buf.as_mut_ptr(), buf.len()) };
    assert_eq!(rc, 0);
    let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
    assert!(!s.to_bytes().is_empty());
}

// ===========================================================================
// strlcpy / strlcat
// ===========================================================================

#[test]
fn strlcpy_copies_with_truncation() {
    let mut dst = [0_i8; 6];
    let len = unsafe { strlcpy(dst.as_mut_ptr(), c"hello world".as_ptr(), 6) };
    assert_eq!(len, 11); // returns full source length
    let s = unsafe { CStr::from_ptr(dst.as_ptr()) };
    assert_eq!(s.to_bytes(), b"hello"); // truncated to 5+NUL
}

#[test]
fn strlcat_appends_with_truncation() {
    let mut buf = [0_i8; 10];
    unsafe { strcpy(buf.as_mut_ptr(), c"hello".as_ptr()) };
    let len = unsafe { strlcat(buf.as_mut_ptr(), c" world".as_ptr(), 10) };
    assert_eq!(len, 11); // 5 + 6 = would need 12 bytes
    let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(s.to_bytes(), b"hello wor"); // truncated
}

// ===========================================================================
// strverscmp
// ===========================================================================

#[test]
fn strverscmp_numeric_ordering() {
    assert!(unsafe { strverscmp(c"file2".as_ptr(), c"file10".as_ptr()) } < 0);
    assert!(unsafe { strverscmp(c"file10".as_ptr(), c"file2".as_ptr()) } > 0);
    assert_eq!(
        unsafe { strverscmp(c"file10".as_ptr(), c"file10".as_ptr()) },
        0
    );
}

#[test]
fn strverscmp_plain_strings() {
    assert!(unsafe { strverscmp(c"abc".as_ptr(), c"abd".as_ptr()) } < 0);
    assert_eq!(unsafe { strverscmp(c"abc".as_ptr(), c"abc".as_ptr()) }, 0);
}

// ===========================================================================
// swab
// ===========================================================================

#[test]
fn swab_swaps_byte_pairs() {
    let src = b"ABCDEF";
    let mut dst = [0u8; 6];
    unsafe { swab(src.as_ptr().cast(), dst.as_mut_ptr().cast(), 6) };
    assert_eq!(&dst, b"BADCFE");
}

// ===========================================================================
// strsignal
// ===========================================================================

#[test]
fn strsignal_returns_message() {
    let msg = unsafe { strsignal(libc::SIGTERM) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) };
    assert!(!s.to_bytes().is_empty());
}

// ===========================================================================
// strcoll / strxfrm
// ===========================================================================

#[test]
fn strcoll_equal_strings() {
    assert_eq!(unsafe { strcoll(c"hello".as_ptr(), c"hello".as_ptr()) }, 0);
}

#[test]
fn strcoll_different_strings() {
    let result = unsafe { strcoll(c"abc".as_ptr(), c"abd".as_ptr()) };
    assert!(result < 0);
}

#[test]
fn strxfrm_returns_transformed_length() {
    let mut dst = [0_i8; 32];
    let len = unsafe { strxfrm(dst.as_mut_ptr(), c"hello".as_ptr(), 32) };
    assert!(len > 0);
    assert!(len < 32);
}

// ===========================================================================
// index / rindex (BSD aliases)
// ===========================================================================

#[test]
fn index_finds_first_char() {
    let ptr = unsafe { index(c"abcabc".as_ptr(), b'b' as c_int) };
    assert!(!ptr.is_null());
    let offset = unsafe { ptr.offset_from(c"abcabc".as_ptr()) };
    assert_eq!(offset, 1);
}

#[test]
fn rindex_finds_last_char() {
    let haystack = c"abcabc".as_ptr();
    let ptr = unsafe { rindex(haystack, b'b' as c_int) };
    assert!(!ptr.is_null());
    let offset = unsafe { ptr.offset_from(haystack) };
    assert_eq!(offset, 4);
}

// ===========================================================================
// rawmemchr
// ===========================================================================

#[test]
fn rawmemchr_finds_byte() {
    let data = b"hello";
    let ptr = unsafe { rawmemchr(data.as_ptr().cast(), b'l' as c_int) };
    assert!(!ptr.is_null());
    let offset = unsafe { (ptr as *const u8).offset_from(data.as_ptr()) };
    assert_eq!(offset, 2);
}

// ===========================================================================
// fnmatch
// ===========================================================================

#[test]
fn fnmatch_simple_star() {
    assert_eq!(
        unsafe { fnmatch(c"*.txt".as_ptr(), c"hello.txt".as_ptr(), 0) },
        0
    );
}

#[test]
fn fnmatch_star_no_match() {
    assert_ne!(
        unsafe { fnmatch(c"*.txt".as_ptr(), c"hello.rs".as_ptr(), 0) },
        0
    );
}

#[test]
fn fnmatch_question_mark() {
    assert_eq!(unsafe { fnmatch(c"a?c".as_ptr(), c"abc".as_ptr(), 0) }, 0);
    assert_ne!(unsafe { fnmatch(c"a?c".as_ptr(), c"abbc".as_ptr(), 0) }, 0);
}

#[test]
fn fnmatch_bracket() {
    let pat = c"[abc]at".as_ptr();
    assert_eq!(unsafe { fnmatch(pat, c"cat".as_ptr(), 0) }, 0);
    assert_eq!(unsafe { fnmatch(pat, c"bat".as_ptr(), 0) }, 0);
    assert_ne!(unsafe { fnmatch(pat, c"dat".as_ptr(), 0) }, 0);
}

#[test]
fn fnmatch_bracket_range() {
    let pat = c"[a-z]".as_ptr();
    assert_eq!(unsafe { fnmatch(pat, c"m".as_ptr(), 0) }, 0);
    assert_ne!(unsafe { fnmatch(pat, c"M".as_ptr(), 0) }, 0);
}

#[test]
fn fnmatch_negated_bracket() {
    let pat = c"[!0-9]".as_ptr();
    assert_eq!(unsafe { fnmatch(pat, c"a".as_ptr(), 0) }, 0);
    assert_ne!(unsafe { fnmatch(pat, c"5".as_ptr(), 0) }, 0);
}

#[test]
fn fnmatch_pathname_flag() {
    assert_eq!(
        unsafe { fnmatch(c"*.c".as_ptr(), c"src/main.c".as_ptr(), 0) },
        0
    );
    assert_ne!(
        unsafe { fnmatch(c"*.c".as_ptr(), c"src/main.c".as_ptr(), 2) },
        0
    );
}

#[test]
fn fnmatch_casefold() {
    assert_ne!(
        unsafe { fnmatch(c"hello".as_ptr(), c"HELLO".as_ptr(), 0) },
        0
    );
    assert_eq!(
        unsafe { fnmatch(c"hello".as_ptr(), c"HELLO".as_ptr(), 16) },
        0
    );
}

#[test]
fn fnmatch_exact_match() {
    assert_eq!(
        unsafe { fnmatch(c"hello".as_ptr(), c"hello".as_ptr(), 0) },
        0
    );
}

#[test]
fn fnmatch_empty_pattern_empty_string() {
    assert_eq!(unsafe { fnmatch(c"".as_ptr(), c"".as_ptr(), 0) }, 0);
}

// ===========================================================================
// GNU errno-name helpers / locale aliases / C23 strfrom*
// ===========================================================================

#[test]
fn strerror_l_returns_message_for_known_errno() {
    let msg = unsafe { strerror_l(libc::EACCES, std::ptr::null_mut()) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) };
    assert!(!s.to_bytes().is_empty());
}

#[test]
fn strerrordesc_np_reports_known_errno_and_null_for_unknown() {
    let known = strerrordesc_np(libc::ENOENT);
    assert!(!known.is_null());
    assert_eq!(
        unsafe { CStr::from_ptr(known) }.to_bytes(),
        b"No such file or directory"
    );
    assert!(strerrordesc_np(0x7fff).is_null());
}

#[test]
fn strerrorname_np_reports_known_errno_and_null_for_unknown() {
    let known = strerrorname_np(libc::ENOENT);
    assert!(!known.is_null());
    assert_eq!(unsafe { CStr::from_ptr(known) }.to_bytes(), b"ENOENT");
    assert!(strerrorname_np(0x7fff).is_null());
}

#[test]
fn strcasecmp_l_ignores_locale_argument() {
    assert_eq!(
        unsafe {
            strcasecmp_l(
                c"FrAnKeN".as_ptr(),
                c"franken".as_ptr(),
                std::ptr::null_mut(),
            )
        },
        0
    );
}

#[test]
fn strncasecmp_l_respects_length_limit() {
    assert_eq!(
        unsafe {
            strncasecmp_l(
                c"AlphaBeta".as_ptr(),
                c"alphaZeta".as_ptr(),
                5,
                std::ptr::null_mut(),
            )
        },
        0
    );
    assert_ne!(
        unsafe {
            strncasecmp_l(
                c"AlphaBeta".as_ptr(),
                c"alphaZeta".as_ptr(),
                6,
                std::ptr::null_mut(),
            )
        },
        0
    );
}

#[test]
fn strfromd_formats_output_and_returns_full_length() {
    let mut buf = [0_i8; 32];
    let len = unsafe { strfromd(buf.as_mut_ptr(), buf.len(), c"%.2f".as_ptr(), 12.345) };
    assert_eq!(len, 5);
    assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()) }.to_bytes(), b"12.35");
}

#[test]
fn strfromd_truncates_output_but_reports_untruncated_length() {
    let mut buf = [0_i8; 5];
    let len = unsafe { strfromd(buf.as_mut_ptr(), buf.len(), c"%.2f".as_ptr(), 12.345) };
    assert_eq!(len, 5);
    assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()) }.to_bytes(), b"12.3");
}

#[test]
fn strfromf_and_strfroml_delegate_to_shared_formatter() {
    let mut f_buf = [0_i8; 32];
    let mut l_buf = [0_i8; 32];

    let f_len = unsafe { strfromf(f_buf.as_mut_ptr(), f_buf.len(), c"%.1f".as_ptr(), 3.25) };
    let l_len = unsafe { strfroml(l_buf.as_mut_ptr(), l_buf.len(), c"%.3e".as_ptr(), 3.25) };

    assert_eq!(f_len, 3);
    assert_eq!(unsafe { CStr::from_ptr(f_buf.as_ptr()) }.to_bytes(), b"3.2");
    assert_eq!(l_len, 7);
    assert_eq!(
        unsafe { CStr::from_ptr(l_buf.as_ptr()) }.to_bytes(),
        b"3.250e0"
    );
}

#[repr(C)]
struct LegacyRegexBuffer {
    allocated: usize,
    used: usize,
    syntax: u64,
    fastmap: *mut c_char,
    translate: *mut c_char,
    re_nsub: usize,
    can_be_null: u8,
    regs_allocated: u8,
    fastmap_accurate: u8,
    no_sub: u8,
    not_bol: u8,
    not_eol: u8,
    newline_anchor: u8,
    pad: [u8; 1],
    buffer: *mut c_void,
    startp: *mut *mut c_char,
    endp: *mut *mut c_char,
}

#[test]
fn re_compile_pattern_accepts_non_utf8_bytes() {
    let pattern = [b'a' as c_char, -1_i8 as c_char, b'b' as c_char];
    let mut buffer = LegacyRegexBuffer {
        allocated: 0,
        used: 0,
        syntax: 0,
        fastmap: std::ptr::null_mut(),
        translate: std::ptr::null_mut(),
        re_nsub: 0,
        can_be_null: 0,
        regs_allocated: 0,
        fastmap_accurate: 0,
        no_sub: 0,
        not_bol: 0,
        not_eol: 0,
        newline_anchor: 0,
        pad: [0],
        buffer: std::ptr::null_mut(),
        startp: std::ptr::null_mut(),
        endp: std::ptr::null_mut(),
    };

    let err = unsafe {
        re_compile_pattern(
            pattern.as_ptr(),
            pattern.len(),
            (&mut buffer as *mut LegacyRegexBuffer).cast(),
        )
    };
    assert!(err.is_null(), "expected non-UTF8 byte patterns to compile");

    unsafe {
        regfree((&mut buffer as *mut LegacyRegexBuffer).cast());
    }
}

#[test]
fn re_search_scans_backwards_for_negative_range() {
    let mut buffer = LegacyRegexBuffer {
        allocated: 0,
        used: 0,
        syntax: 0,
        fastmap: std::ptr::null_mut(),
        translate: std::ptr::null_mut(),
        re_nsub: 0,
        can_be_null: 0,
        regs_allocated: 0,
        fastmap_accurate: 0,
        no_sub: 0,
        not_bol: 0,
        not_eol: 0,
        newline_anchor: 0,
        pad: [0],
        buffer: std::ptr::null_mut(),
        startp: std::ptr::null_mut(),
        endp: std::ptr::null_mut(),
    };

    let err = unsafe {
        re_compile_pattern(
            b"abc".as_ptr().cast(),
            3,
            (&mut buffer as *mut LegacyRegexBuffer).cast(),
        )
    };
    assert!(err.is_null());

    let haystack = b"abcabc";
    let pos = unsafe {
        re_search(
            (&buffer as *const LegacyRegexBuffer).cast(),
            haystack.as_ptr().cast(),
            haystack.len() as c_int,
            5,
            -5,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(pos, 3);

    unsafe {
        regfree((&mut buffer as *mut LegacyRegexBuffer).cast());
    }
}
