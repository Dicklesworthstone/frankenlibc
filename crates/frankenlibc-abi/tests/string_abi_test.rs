#![cfg(target_os = "linux")]

//! Integration tests for `<string.h>` ABI entrypoints.

use frankenlibc_abi::htm_fast_path::{
    HtmTestMode, htm_restore_test_mode_for_tests, htm_swap_abort_code_for_tests,
    htm_swap_test_mode_for_tests,
};
use frankenlibc_abi::string_abi::*;
use frankenlibc_abi::unistd_abi::strerror_l;
use serde_json::Value;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::{Mutex, MutexGuard};

fn with_simd_mask<T>(mask: u32, f: impl FnOnce() -> T) -> T {
    let previous = string_simd_swap_feature_mask_for_tests(Some(mask));
    let outcome = f();
    string_simd_restore_feature_mask_for_tests(previous);
    outcome
}

static LEGACY_REGEX_TEST_MUTEX: Mutex<()> = Mutex::new(());
static HTM_TEST_MUTEX: Mutex<()> = Mutex::new(());

fn legacy_regex_test_guard() -> MutexGuard<'static, ()> {
    LEGACY_REGEX_TEST_MUTEX
        .lock()
        .unwrap_or_else(|err| err.into_inner())
}

fn htm_test_guard() -> MutexGuard<'static, ()> {
    HTM_TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner())
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
    let _guard = htm_test_guard();
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
    let _guard = htm_test_guard();
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

#[test]
fn strl_destination_bound_clamps_only_in_repair_mode() {
    assert_eq!(
        clamp_destination_size_for_tests(12, Some(5), true),
        (5, true)
    );
    assert_eq!(
        clamp_destination_size_for_tests(12, Some(12), true),
        (12, false)
    );
    assert_eq!(
        clamp_destination_size_for_tests(12, Some(5), false),
        (12, false)
    );
    assert_eq!(
        clamp_destination_size_for_tests(12, None, true),
        (12, false)
    );
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

#[test]
fn strverscmp_leading_zero_prefix_ordering() {
    assert!(unsafe { strverscmp(c"000".as_ptr(), c"00".as_ptr()) } < 0);
    assert!(unsafe { strverscmp(c"00".as_ptr(), c"000".as_ptr()) } > 0);
    assert!(unsafe { strverscmp(c"001".as_ptr(), c"01".as_ptr()) } < 0);
    assert!(unsafe { strverscmp(c"01".as_ptr(), c"001".as_ptr()) } > 0);
    assert!(unsafe { strverscmp(c"009".as_ptr(), c"0009".as_ptr()) } > 0);
    assert!(unsafe { strverscmp(c"0009".as_ptr(), c"009".as_ptr()) } < 0);
}

#[test]
fn strverscmp_bounds_tracked_unterminated_inputs() {
    unsafe {
        let raw = malloc_unterminated(b"file2");

        assert!(strverscmp(raw, c"file10".as_ptr()) < 0);
        assert!(strverscmp(c"file10".as_ptr(), raw) > 0);
        assert_eq!(strverscmp(raw, raw), 0);

        frankenlibc_abi::malloc_abi::free(raw.cast());
    }
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
        unsafe { fnmatch(c"*.c".as_ptr(), c"src/main.c".as_ptr(), libc::FNM_PATHNAME) },
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
        unsafe { fnmatch(c"hello".as_ptr(), c"HELLO".as_ptr(), libc::FNM_CASEFOLD) },
        0
    );
}

/// Regression for bd-64uch: glibc's handling of unterminated `[`
/// brackets is nuanced — a benign unterminated bracket is treated as
/// a literal `[`, but one that ends mid-range (`-` immediately before
/// NUL with prior content) is rejected with FNM_NOMATCH. Surfaced via
/// fuzz_pattern_match.
#[test]
fn fnmatch_unterminated_bracket_matches_glibc() {
    // Lone '[' is literal '['.
    assert_eq!(unsafe { fnmatch(c"[".as_ptr(), c"[".as_ptr(), 0) }, 0);
    // '[ab' (no closing ']') is literal '[' + 'a' + 'b'.
    assert_eq!(unsafe { fnmatch(c"[ab".as_ptr(), c"[ab".as_ptr(), 0) }, 0);
    // '[a-b' (looks like a range but unterminated) is literal.
    assert_eq!(unsafe { fnmatch(c"[a-b".as_ptr(), c"[a-b".as_ptr(), 0) }, 0);
    // '[-' with '-' as the first content char is literal '[-'.
    assert_eq!(unsafe { fnmatch(c"[-".as_ptr(), c"[-".as_ptr(), 0) }, 0);
    // '[a-' (incomplete range trailing '-') must NOT match.
    assert_eq!(
        unsafe { fnmatch(c"[a-".as_ptr(), c"[a-".as_ptr(), 0) },
        libc::FNM_NOMATCH
    );
    // '[abc-' (incomplete range trailing '-') must NOT match.
    assert_eq!(
        unsafe { fnmatch(c"[abc-".as_ptr(), c"[abc-".as_ptr(), 0) },
        libc::FNM_NOMATCH
    );
}

/// Regression for bd-64uch: `at_start` for the leading-period rule
/// must reset to false once any string character is consumed.
/// Otherwise pattern '\xff*?*' against '\xff.' (with FNM_PERIOD set)
/// incorrectly rejects '.' as a leading period even though it sits at
/// position 1. Surfaced via fuzz_pattern_match.
#[test]
fn fnmatch_leading_period_only_at_string_start() {
    let pat = b"\xff*?*\0";
    let s = b"\xff.\0";
    let flags = libc::FNM_PATHNAME | libc::FNM_PERIOD | libc::FNM_CASEFOLD;
    let rc = unsafe {
        fnmatch(
            pat.as_ptr() as *const std::ffi::c_char,
            s.as_ptr() as *const std::ffi::c_char,
            flags,
        )
    };
    assert_eq!(
        rc, 0,
        "FNM_PERIOD must only reject '.' at string position 0, not after any consumed char"
    );
}

/// Regression for bd-m40be: our fnmatch flag bits must match
/// /usr/include/fnmatch.h exactly because callers include the system
/// header and pass those bit values directly. PATHNAME and NOESCAPE
/// were previously swapped, so any caller passing FNM_PATHNAME from
/// the system header silently exercised our FNM_NOESCAPE branch.
#[test]
fn fnmatch_flag_bits_match_glibc_header() {
    // Pattern "*" against string "/" with FNM_PATHNAME must NOT match
    // (POSIX: with FNM_PATHNAME, '*' may not match '/').
    assert_eq!(
        unsafe { fnmatch(c"*".as_ptr(), c"/".as_ptr(), libc::FNM_PATHNAME) },
        libc::FNM_NOMATCH,
        "fnmatch with FNM_PATHNAME should refuse '*' matching '/' (FNM_PATHNAME bit must equal libc::FNM_PATHNAME)"
    );
    // With NO flag, '*' matches '/'.
    assert_eq!(
        unsafe { fnmatch(c"*".as_ptr(), c"/".as_ptr(), 0) },
        0,
        "fnmatch with no flags should let '*' match '/'"
    );
    // FNM_NOESCAPE: backslash is a literal character.
    // Pattern '\\a' against string '\\a' matches when NOESCAPE is set,
    // but matches against 'a' when NOESCAPE is unset.
    assert_eq!(
        unsafe { fnmatch(c"\\a".as_ptr(), c"a".as_ptr(), 0) },
        0,
        "without FNM_NOESCAPE, backslash quotes the next char"
    );
    assert_eq!(
        unsafe { fnmatch(c"\\a".as_ptr(), c"\\a".as_ptr(), libc::FNM_NOESCAPE) },
        0,
        "with FNM_NOESCAPE, backslash is literal"
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

#[test]
fn strfromd_rejects_tracked_unterminated_format() {
    unsafe {
        let raw = malloc_unterminated(b"%.2f");
        let mut buf = [0_i8; 32];

        assert_eq!(strfromd(buf.as_mut_ptr(), buf.len(), raw, 12.345), -1);

        frankenlibc_abi::malloc_abi::free(raw.cast());
    }
}

fn collect_argz_entries(argz: *mut c_char, argz_len: usize) -> Vec<Vec<u8>> {
    let mut entries = Vec::new();
    let mut entry = unsafe { argz_next(argz, argz_len, std::ptr::null()) };
    while !entry.is_null() {
        entries.push(unsafe { CStr::from_ptr(entry) }.to_bytes().to_vec());
        entry = unsafe { argz_next(argz, argz_len, entry) };
    }
    entries
}

unsafe fn malloc_unterminated(bytes: &[u8]) -> *mut c_char {
    let raw = unsafe { frankenlibc_abi::malloc_abi::malloc(bytes.len()) }.cast::<u8>();
    assert!(!raw.is_null());
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), raw, bytes.len()) };
    raw.cast()
}

#[test]
fn argz_replace_updates_replace_count_and_contents() {
    let mut argz = std::ptr::null_mut();
    let mut argz_len = 0usize;
    let mut replace_count: libc::c_uint = 7;

    assert_eq!(
        unsafe { argz_add(&mut argz, &mut argz_len, c"aa".as_ptr()) },
        0
    );
    assert_eq!(
        unsafe { argz_add(&mut argz, &mut argz_len, c"bb".as_ptr()) },
        0
    );
    assert_eq!(
        unsafe { argz_add(&mut argz, &mut argz_len, c"aa".as_ptr()) },
        0
    );

    let rc = unsafe {
        argz_replace(
            &mut argz,
            &mut argz_len,
            c"aa".as_ptr(),
            c"xyz".as_ptr(),
            &mut replace_count,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(replace_count, 9);
    assert_eq!(
        collect_argz_entries(argz, argz_len),
        vec![b"xyz".to_vec(), b"bb".to_vec(), b"xyz".to_vec()]
    );

    let rc = unsafe {
        argz_replace(
            &mut argz,
            &mut argz_len,
            c"nomatch".as_ptr(),
            c"z".as_ptr(),
            &mut replace_count,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(replace_count, 9);
    assert_eq!(
        collect_argz_entries(argz, argz_len),
        vec![b"xyz".to_vec(), b"bb".to_vec(), b"xyz".to_vec()]
    );

    unsafe {
        frankenlibc_abi::malloc_abi::free(argz.cast());
    }
}

#[test]
fn argz_delete_last_entry_clears_pointer_and_length() {
    let mut argz = std::ptr::null_mut();
    let mut argz_len = 0usize;

    assert_eq!(
        unsafe { argz_add(&mut argz, &mut argz_len, c"one".as_ptr()) },
        0
    );
    assert!(!argz.is_null());

    unsafe {
        argz_delete(&mut argz, &mut argz_len, argz);
    }

    assert!(argz.is_null());
    assert_eq!(argz_len, 0);
}

#[test]
fn argz_create_sep_discards_empty_segments_like_glibc() {
    let cases: &[(&str, &[&[u8]])] = &[
        ("", &[]),
        (":", &[b""]),
        ("::", &[b""]),
        (":a", &[b"a"]),
        ("a:", &[b"a", b""]),
        (":a:", &[b"a", b""]),
        ("a::b", &[b"a", b"b"]),
        (":a::b:", &[b"a", b"b", b""]),
    ];

    for (input, expected) in cases {
        let input_cstr = CString::new(*input).unwrap();
        let mut argz = std::ptr::null_mut();
        let mut argz_len = usize::MAX;

        let rc = unsafe {
            argz_create_sep(input_cstr.as_ptr(), b':' as c_int, &mut argz, &mut argz_len)
        };
        assert_eq!(rc, 0, "input={input:?}");

        let expected_entries: Vec<Vec<u8>> = expected.iter().map(|entry| entry.to_vec()).collect();
        assert_eq!(
            collect_argz_entries(argz, argz_len),
            expected_entries,
            "input={input:?}"
        );

        if expected.is_empty() {
            assert!(argz.is_null(), "input={input:?}");
            assert_eq!(argz_len, 0, "input={input:?}");
        } else {
            assert!(!argz.is_null(), "input={input:?}");
            assert_eq!(
                argz_len,
                expected.iter().map(|entry| entry.len() + 1).sum::<usize>(),
                "input={input:?}"
            );
            unsafe {
                frankenlibc_abi::malloc_abi::free(argz.cast());
            }
        }
    }
}

#[test]
fn argz_add_sep_discards_empty_segments_and_keeps_terminal_empty() {
    let input_cstr = CString::new(":a::b:").unwrap();
    let mut argz = std::ptr::null_mut();
    let mut argz_len = 0usize;

    assert_eq!(
        unsafe {
            argz_add_sep(
                &mut argz,
                &mut argz_len,
                CString::new("").unwrap().as_ptr(),
                b':' as c_int,
            )
        },
        0
    );
    assert!(argz.is_null());
    assert_eq!(argz_len, 0);

    assert_eq!(
        unsafe { argz_add(&mut argz, &mut argz_len, c"head".as_ptr()) },
        0
    );
    assert_eq!(
        unsafe { argz_add_sep(&mut argz, &mut argz_len, input_cstr.as_ptr(), b':' as c_int) },
        0
    );
    assert_eq!(
        collect_argz_entries(argz, argz_len),
        vec![b"head".to_vec(), b"a".to_vec(), b"b".to_vec(), b"".to_vec()]
    );
    assert_eq!(argz_len, 10);

    unsafe {
        frankenlibc_abi::malloc_abi::free(argz.cast());
    }
}

#[test]
fn argz_rejects_tracked_unterminated_inputs() {
    unsafe {
        let raw = malloc_unterminated(b"one:two");
        let mut argz = std::ptr::null_mut();
        let mut argz_len = 0usize;

        assert_eq!(argz_add(&mut argz, &mut argz_len, raw), libc::EINVAL);
        assert!(argz.is_null());
        assert_eq!(argz_len, 0);

        let argv = [raw as *const c_char, std::ptr::null()];
        assert_eq!(
            argz_create(argv.as_ptr(), &mut argz, &mut argz_len),
            libc::EINVAL
        );
        assert!(argz.is_null());
        assert_eq!(argz_len, 0);

        assert_eq!(
            argz_create_sep(raw, b':' as c_int, &mut argz, &mut argz_len),
            libc::EINVAL
        );
        assert!(argz.is_null());
        assert_eq!(argz_len, 0);

        assert_eq!(
            argz_add_sep(&mut argz, &mut argz_len, raw, b':' as c_int),
            libc::EINVAL
        );
        assert!(argz.is_null());
        assert_eq!(argz_len, 0);

        assert_eq!(argz_add(&mut argz, &mut argz_len, c"head".as_ptr()), 0);
        let before = argz;
        assert_eq!(
            argz_insert(&mut argz, &mut argz_len, before, raw),
            libc::EINVAL
        );
        let mut replacements = 0;
        assert_eq!(
            argz_replace(
                &mut argz,
                &mut argz_len,
                c"head".as_ptr(),
                raw,
                &mut replacements,
            ),
            libc::EINVAL
        );

        frankenlibc_abi::malloc_abi::free(raw.cast());
        frankenlibc_abi::malloc_abi::free(argz.cast());
    }
}

#[test]
fn argz_delete_and_extract_bound_malformed_entries() {
    let mut storage = *b"abc";
    let mut argz = storage.as_mut_ptr().cast::<c_char>();
    let mut argz_len = storage.len();
    let mut argv = [c"stale".as_ptr().cast_mut(), std::ptr::null_mut()];

    unsafe {
        argz_extract(argz, argz_len, argv.as_mut_ptr());
    }
    assert!(argv[0].is_null());

    unsafe {
        argz_delete(&mut argz, &mut argz_len, argz);
    }
    assert_eq!(argz_len, storage.len());
    assert_eq!(&storage, b"abc");
}

#[test]
fn argz_add_and_append_ignore_stale_len_when_buffer_is_null() {
    unsafe {
        let mut argz = std::ptr::null_mut();
        let mut argz_len = 1024usize;

        assert_eq!(argz_add(&mut argz, &mut argz_len, c"one".as_ptr()), 0);
        assert_eq!(argz_len, 4);
        assert_eq!(collect_argz_entries(argz, argz_len), vec![b"one".to_vec()]);
        frankenlibc_abi::malloc_abi::free(argz.cast());

        argz = std::ptr::null_mut();
        argz_len = 1024;
        let entry = b"two\0";
        assert_eq!(
            argz_append(&mut argz, &mut argz_len, entry.as_ptr().cast(), entry.len()),
            0
        );
        assert_eq!(argz_len, 4);
        assert_eq!(collect_argz_entries(argz, argz_len), vec![b"two".to_vec()]);
        frankenlibc_abi::malloc_abi::free(argz.cast());
    }
}

#[test]
fn envz_add_get_merge_and_strip_entries() {
    unsafe {
        let mut envz = std::ptr::null_mut();
        let mut envz_len = 0usize;

        assert_eq!(
            envz_add(&mut envz, &mut envz_len, c"A".as_ptr(), c"1".as_ptr()),
            0
        );
        assert_eq!(
            envz_add(&mut envz, &mut envz_len, c"FLAG".as_ptr(), std::ptr::null()),
            0
        );

        let value = envz_get(envz, envz_len, c"A".as_ptr());
        assert!(!value.is_null());
        assert_eq!(CStr::from_ptr(value).to_bytes(), b"1");
        assert!(envz_get(envz, envz_len, c"FLAG".as_ptr()).is_null());

        let envz2 = b"A=2\0B=3\0";
        assert_eq!(
            envz_merge(
                &mut envz,
                &mut envz_len,
                envz2.as_ptr().cast(),
                envz2.len(),
                0,
            ),
            0
        );
        assert_eq!(
            CStr::from_ptr(envz_get(envz, envz_len, c"A".as_ptr())).to_bytes(),
            b"1"
        );
        assert_eq!(
            CStr::from_ptr(envz_get(envz, envz_len, c"B".as_ptr())).to_bytes(),
            b"3"
        );

        assert_eq!(
            envz_merge(
                &mut envz,
                &mut envz_len,
                envz2.as_ptr().cast(),
                envz2.len(),
                1,
            ),
            0
        );
        assert_eq!(
            CStr::from_ptr(envz_get(envz, envz_len, c"A".as_ptr())).to_bytes(),
            b"2"
        );

        envz_strip(&mut envz, &mut envz_len);
        assert!(envz_entry(envz, envz_len, c"FLAG".as_ptr()).is_null());

        frankenlibc_abi::malloc_abi::free(envz.cast());
    }
}

#[test]
fn envz_rejects_tracked_unterminated_name_and_value() {
    unsafe {
        let raw_name = malloc_unterminated(b"KEY");
        let raw_value = malloc_unterminated(b"value");
        let mut envz = std::ptr::null_mut();
        let mut envz_len = 0usize;

        assert_eq!(
            envz_add(&mut envz, &mut envz_len, c"KEY".as_ptr(), c"valid".as_ptr(),),
            0
        );

        assert!(envz_entry(envz, envz_len, raw_name).is_null());
        assert!(envz_get(envz, envz_len, raw_name).is_null());
        assert_eq!(
            envz_add(&mut envz, &mut envz_len, raw_name, c"value".as_ptr()),
            libc::EINVAL
        );
        assert_eq!(
            envz_add(&mut envz, &mut envz_len, c"KEY".as_ptr(), raw_value),
            libc::EINVAL
        );

        frankenlibc_abi::malloc_abi::free(raw_name.cast());
        frankenlibc_abi::malloc_abi::free(raw_value.cast());
        frankenlibc_abi::malloc_abi::free(envz.cast());
    }
}

#[test]
fn envz_merge_rejects_malformed_envz2_entry() {
    unsafe {
        let mut envz = std::ptr::null_mut();
        let mut envz_len = 0usize;
        let envz2 = b"A=1";

        assert_eq!(
            envz_merge(
                &mut envz,
                &mut envz_len,
                envz2.as_ptr().cast(),
                envz2.len(),
                1,
            ),
            libc::EINVAL
        );
        assert!(envz.is_null());
        assert_eq!(envz_len, 0);
    }
}

#[test]
fn argz_next_matches_glibc_for_interior_and_foreign_pointers() {
    let mut argz = std::ptr::null_mut();
    let mut argz_len = 0usize;

    assert_eq!(
        unsafe { argz_add(&mut argz, &mut argz_len, c"one".as_ptr()) },
        0
    );
    assert_eq!(
        unsafe { argz_add(&mut argz, &mut argz_len, c"two".as_ptr()) },
        0
    );

    let interior_next = unsafe { argz_next(argz, argz_len, argz.add(1)) };
    assert!(!interior_next.is_null());
    assert_eq!(unsafe { CStr::from_ptr(interior_next) }.to_bytes(), b"two");

    let foreign_next = unsafe { argz_next(argz, argz_len, c"zzz".as_ptr()) };
    assert!(foreign_next.is_null());

    unsafe {
        frankenlibc_abi::malloc_abi::free(argz.cast());
    }
}

#[repr(C)]
struct PublicRegexBuffer {
    buffer: *mut c_void,
    allocated: libc::c_long,
    used: libc::c_long,
    syntax: u64,
    fastmap: *mut c_char,
    translate: *mut u8,
    re_nsub: usize,
    flags: u8,
    reserved: [u8; 7],
}

#[repr(C)]
struct LegacyReRegisters {
    num_regs: usize,
    start: *mut c_int,
    end: *mut c_int,
}

#[repr(C)]
struct PublicGlobT {
    gl_pathc: usize,
    gl_pathv: *mut *mut c_char,
    gl_offs: usize,
}

impl Default for PublicRegexBuffer {
    fn default() -> Self {
        Self {
            buffer: std::ptr::null_mut(),
            allocated: 0,
            used: 0,
            syntax: 0,
            fastmap: std::ptr::null_mut(),
            translate: std::ptr::null_mut(),
            re_nsub: 0,
            flags: 0,
            reserved: [0; 7],
        }
    }
}

#[test]
fn public_regex_buffer_matches_glibc_size() {
    assert_eq!(std::mem::size_of::<PublicRegexBuffer>(), 64);
}

#[test]
fn pattern_adapters_reject_tracked_unterminated_c_strings() {
    let _guard = legacy_regex_test_guard();
    unsafe {
        let raw = malloc_unterminated(b"a*");
        let mut regex_buffer = PublicRegexBuffer::default();

        assert_ne!(
            regcomp((&mut regex_buffer as *mut PublicRegexBuffer).cast(), raw, 0,),
            0
        );
        assert!(regex_buffer.buffer.is_null());

        assert_eq!(fnmatch(raw, c"abc".as_ptr(), 0), libc::FNM_NOMATCH);
        assert_eq!(fnmatch(c"a*".as_ptr(), raw, 0), libc::FNM_NOMATCH);

        let mut glob_buffer = PublicGlobT {
            gl_pathc: 0,
            gl_pathv: std::ptr::null_mut(),
            gl_offs: 0,
        };
        assert_ne!(
            glob(raw, 0, None, (&mut glob_buffer as *mut PublicGlobT).cast(),),
            0
        );
        assert!(glob_buffer.gl_pathv.is_null());

        assert_eq!(
            regcomp(
                (&mut regex_buffer as *mut PublicRegexBuffer).cast(),
                c"a.*".as_ptr(),
                0,
            ),
            0
        );
        assert_ne!(
            regexec(
                (&regex_buffer as *const PublicRegexBuffer).cast(),
                raw,
                0,
                std::ptr::null_mut(),
                0,
            ),
            0
        );

        regfree((&mut regex_buffer as *mut PublicRegexBuffer).cast());
        frankenlibc_abi::malloc_abi::free(raw.cast());
    }
}

const RE_BACKSLASH_ESCAPE_IN_LISTS: u64 = 1;
const RE_CHAR_CLASSES: u64 = RE_BACKSLASH_ESCAPE_IN_LISTS << 2;
const RE_CONTEXT_INDEP_ANCHORS: u64 = RE_CHAR_CLASSES << 1;
const RE_CONTEXT_INDEP_OPS: u64 = RE_CONTEXT_INDEP_ANCHORS << 1;
const RE_CONTEXT_INVALID_OPS: u64 = RE_CONTEXT_INDEP_OPS << 1;
const RE_DOT_NEWLINE: u64 = RE_CONTEXT_INVALID_OPS << 1;
const RE_DOT_NOT_NULL: u64 = RE_DOT_NEWLINE << 1;
const RE_INTERVALS: u64 = RE_DOT_NOT_NULL << 2;
const RE_NO_BK_BRACES: u64 = RE_INTERVALS << 3;
const RE_NO_BK_PARENS: u64 = RE_NO_BK_BRACES << 1;
const RE_NO_BK_VBAR: u64 = RE_NO_BK_PARENS << 2;
const RE_NO_EMPTY_RANGES: u64 = RE_NO_BK_VBAR << 1;
const RE_NO_SUB: u64 = 1 << 25;
const RE_UNMATCHED_RIGHT_PAREN_ORD: u64 = RE_NO_EMPTY_RANGES << 1;
const RE_SYNTAX_POSIX_EXTENDED: u64 = RE_CHAR_CLASSES
    | RE_DOT_NEWLINE
    | RE_DOT_NOT_NULL
    | RE_INTERVALS
    | RE_NO_EMPTY_RANGES
    | RE_CONTEXT_INDEP_ANCHORS
    | RE_CONTEXT_INDEP_OPS
    | RE_CONTEXT_INVALID_OPS
    | RE_NO_BK_BRACES
    | RE_NO_BK_PARENS
    | RE_NO_BK_VBAR
    | RE_UNMATCHED_RIGHT_PAREN_ORD;

#[test]
fn re_compile_pattern_accepts_non_utf8_bytes() {
    let _guard = legacy_regex_test_guard();
    let pattern = [b'a' as c_char, -1_i8 as c_char, b'b' as c_char];
    let mut buffer = PublicRegexBuffer::default();

    let err = unsafe {
        re_compile_pattern(
            pattern.as_ptr(),
            pattern.len(),
            (&mut buffer as *mut PublicRegexBuffer).cast(),
        )
    };
    assert!(err.is_null(), "expected non-UTF8 byte patterns to compile");
    assert!(
        !buffer.buffer.is_null(),
        "compiled regex handle should be stored in the public buffer field"
    );

    unsafe {
        regfree((&mut buffer as *mut PublicRegexBuffer).cast());
    }
}

#[test]
fn re_search_scans_backwards_for_negative_range() {
    let _guard = legacy_regex_test_guard();
    let mut buffer = PublicRegexBuffer::default();

    let err = unsafe {
        re_compile_pattern(
            b"abc".as_ptr().cast(),
            3,
            (&mut buffer as *mut PublicRegexBuffer).cast(),
        )
    };
    assert!(err.is_null());

    let haystack = b"abcabc";
    let pos = unsafe {
        re_search(
            (&buffer as *const PublicRegexBuffer).cast(),
            haystack.as_ptr().cast(),
            haystack.len() as c_int,
            5,
            -5,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(pos, 3);

    unsafe {
        regfree((&mut buffer as *mut PublicRegexBuffer).cast());
    }
}

#[test]
fn re_search_2_matches_across_split_boundary_and_reports_regs() {
    let _guard = legacy_regex_test_guard();
    let mut buffer = PublicRegexBuffer::default();
    let mut regs = LegacyReRegisters {
        num_regs: 0,
        start: std::ptr::null_mut(),
        end: std::ptr::null_mut(),
    };

    let err = unsafe {
        re_compile_pattern(
            b"abc".as_ptr().cast(),
            3,
            (&mut buffer as *mut PublicRegexBuffer).cast(),
        )
    };
    assert!(err.is_null());

    let pos = unsafe {
        re_search_2(
            (&buffer as *const PublicRegexBuffer).cast(),
            b"ab".as_ptr().cast(),
            2,
            b"cxxabc".as_ptr().cast(),
            6,
            0,
            8,
            (&mut regs as *mut LegacyReRegisters).cast(),
            8,
        )
    };
    assert_eq!(pos, 0);
    assert!(regs.num_regs >= 2);
    assert!(!regs.start.is_null());
    assert!(!regs.end.is_null());
    unsafe {
        assert_eq!(*regs.start.add(0), 0);
        assert_eq!(*regs.end.add(0), 3);
        frankenlibc_abi::malloc_abi::free(regs.start.cast());
        frankenlibc_abi::malloc_abi::free(regs.end.cast());
        regfree((&mut buffer as *mut PublicRegexBuffer).cast());
    }
}

#[test]
fn re_search_2_honors_absolute_stop_limit() {
    let _guard = legacy_regex_test_guard();
    let mut buffer = PublicRegexBuffer::default();

    let err = unsafe {
        re_compile_pattern(
            b"abc".as_ptr().cast(),
            3,
            (&mut buffer as *mut PublicRegexBuffer).cast(),
        )
    };
    assert!(err.is_null());

    let blocked = unsafe {
        re_search_2(
            (&buffer as *const PublicRegexBuffer).cast(),
            b"ab".as_ptr().cast(),
            2,
            b"cxxabc".as_ptr().cast(),
            6,
            0,
            8,
            std::ptr::null_mut(),
            2,
        )
    };
    assert_eq!(blocked, -1);

    let matched = unsafe {
        re_search_2(
            (&buffer as *const PublicRegexBuffer).cast(),
            b"ab".as_ptr().cast(),
            2,
            b"cxxabc".as_ptr().cast(),
            6,
            0,
            8,
            std::ptr::null_mut(),
            3,
        )
    };
    assert_eq!(matched, 0);

    unsafe {
        regfree((&mut buffer as *mut PublicRegexBuffer).cast());
    }
}

#[test]
fn re_search_honors_explicit_length_past_embedded_nul() {
    let _guard = legacy_regex_test_guard();
    let mut buffer = PublicRegexBuffer::default();
    let haystack = [b'a', b'b', 0, b'c'];

    let err = unsafe {
        re_compile_pattern(
            b"c".as_ptr().cast(),
            1,
            (&mut buffer as *mut PublicRegexBuffer).cast(),
        )
    };
    assert!(err.is_null());

    let pos = unsafe {
        re_search(
            (&buffer as *const PublicRegexBuffer).cast(),
            haystack.as_ptr().cast(),
            haystack.len() as c_int,
            0,
            haystack.len() as c_int,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(pos, 3);

    unsafe {
        regfree((&mut buffer as *mut PublicRegexBuffer).cast());
    }
}

#[test]
fn re_compile_pattern_honors_explicit_pattern_length_past_embedded_nul() {
    let _guard = legacy_regex_test_guard();
    let mut buffer = PublicRegexBuffer::default();
    let pattern = [b'c', 0, b'd'];
    let haystack = [b'x', b'c', 0, b'd', b'y'];

    let err = unsafe {
        re_compile_pattern(
            pattern.as_ptr().cast(),
            pattern.len(),
            (&mut buffer as *mut PublicRegexBuffer).cast(),
        )
    };
    assert!(err.is_null());

    let pos = unsafe {
        re_search(
            (&buffer as *const PublicRegexBuffer).cast(),
            haystack.as_ptr().cast(),
            haystack.len() as c_int,
            0,
            haystack.len() as c_int,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(pos, 1);

    let matched = unsafe {
        re_match(
            (&buffer as *const PublicRegexBuffer).cast(),
            haystack.as_ptr().cast(),
            haystack.len() as c_int,
            1,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(matched, 3);

    unsafe {
        regfree((&mut buffer as *mut PublicRegexBuffer).cast());
    }
}

#[test]
fn re_search_2_backward_search_respects_absolute_stop_limit() {
    let _guard = legacy_regex_test_guard();
    let mut buffer = PublicRegexBuffer::default();

    let err = unsafe {
        re_compile_pattern(
            b"abc".as_ptr().cast(),
            3,
            (&mut buffer as *mut PublicRegexBuffer).cast(),
        )
    };
    assert!(err.is_null());

    let early = unsafe {
        re_search_2(
            (&buffer as *const PublicRegexBuffer).cast(),
            std::ptr::null(),
            0,
            b"abcabc".as_ptr().cast(),
            6,
            5,
            -5,
            std::ptr::null_mut(),
            3,
        )
    };
    assert_eq!(early, 0);

    let late = unsafe {
        re_search_2(
            (&buffer as *const PublicRegexBuffer).cast(),
            std::ptr::null(),
            0,
            b"abcabc".as_ptr().cast(),
            6,
            5,
            -5,
            std::ptr::null_mut(),
            6,
        )
    };
    assert_eq!(late, 3);

    unsafe {
        regfree((&mut buffer as *mut PublicRegexBuffer).cast());
    }
}

#[test]
fn re_match_honors_explicit_length_past_embedded_nul() {
    let _guard = legacy_regex_test_guard();
    let mut buffer = PublicRegexBuffer::default();
    let haystack = [b'a', b'b', 0, b'c'];

    let err = unsafe {
        re_compile_pattern(
            b"c".as_ptr().cast(),
            1,
            (&mut buffer as *mut PublicRegexBuffer).cast(),
        )
    };
    assert!(err.is_null());

    let matched = unsafe {
        re_match(
            (&buffer as *const PublicRegexBuffer).cast(),
            haystack.as_ptr().cast(),
            haystack.len() as c_int,
            3,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(matched, 1);

    unsafe {
        regfree((&mut buffer as *mut PublicRegexBuffer).cast());
    }
}

#[test]
fn re_match_2_honors_split_boundary_and_absolute_stop_limit() {
    let _guard = legacy_regex_test_guard();
    let mut buffer = PublicRegexBuffer::default();

    let err = unsafe {
        re_compile_pattern(
            b"abc".as_ptr().cast(),
            3,
            (&mut buffer as *mut PublicRegexBuffer).cast(),
        )
    };
    assert!(err.is_null());

    let matched = unsafe {
        re_match_2(
            (&buffer as *const PublicRegexBuffer).cast(),
            b"xxab".as_ptr().cast(),
            4,
            b"cxx".as_ptr().cast(),
            3,
            2,
            std::ptr::null_mut(),
            5,
        )
    };
    assert_eq!(matched, 3);

    let blocked = unsafe {
        re_match_2(
            (&buffer as *const PublicRegexBuffer).cast(),
            b"xxab".as_ptr().cast(),
            4,
            b"cxx".as_ptr().cast(),
            3,
            2,
            std::ptr::null_mut(),
            4,
        )
    };
    assert_eq!(blocked, -1);

    unsafe {
        regfree((&mut buffer as *mut PublicRegexBuffer).cast());
    }
}

#[test]
fn re_search_returns_position_under_re_no_sub_without_touching_registers() {
    let _guard = legacy_regex_test_guard();
    let previous = unsafe { re_set_syntax(RE_NO_SUB) };
    let mut buffer = PublicRegexBuffer::default();
    let mut starts = [111, 222];
    let mut ends = [333, 444];
    let mut regs = LegacyReRegisters {
        num_regs: starts.len(),
        start: starts.as_mut_ptr(),
        end: ends.as_mut_ptr(),
    };

    let err = unsafe {
        re_compile_pattern(
            b"abc".as_ptr().cast(),
            b"abc".len(),
            (&mut buffer as *mut PublicRegexBuffer).cast(),
        )
    };
    unsafe {
        re_set_syntax(previous);
    }
    assert!(err.is_null());

    let pos = unsafe {
        re_search(
            (&buffer as *const PublicRegexBuffer).cast(),
            b"zzabc".as_ptr().cast(),
            5,
            0,
            5,
            (&mut regs as *mut LegacyReRegisters).cast(),
        )
    };
    assert_eq!(pos, 2);
    assert_eq!(regs.num_regs, 2);
    assert_eq!(starts, [111, 222]);
    assert_eq!(ends, [333, 444]);

    unsafe {
        regfree((&mut buffer as *mut PublicRegexBuffer).cast());
    }
}

#[test]
fn re_match_returns_length_under_re_no_sub_without_touching_registers() {
    let _guard = legacy_regex_test_guard();
    let previous = unsafe { re_set_syntax(RE_NO_SUB) };
    let mut buffer = PublicRegexBuffer::default();
    let mut starts = [111, 222];
    let mut ends = [333, 444];
    let mut regs = LegacyReRegisters {
        num_regs: starts.len(),
        start: starts.as_mut_ptr(),
        end: ends.as_mut_ptr(),
    };

    let err = unsafe {
        re_compile_pattern(
            b"abc".as_ptr().cast(),
            b"abc".len(),
            (&mut buffer as *mut PublicRegexBuffer).cast(),
        )
    };
    unsafe {
        re_set_syntax(previous);
    }
    assert!(err.is_null());

    let matched = unsafe {
        re_match(
            (&buffer as *const PublicRegexBuffer).cast(),
            b"zzabc".as_ptr().cast(),
            5,
            2,
            (&mut regs as *mut LegacyReRegisters).cast(),
        )
    };
    assert_eq!(matched, 3);
    assert_eq!(regs.num_regs, 2);
    assert_eq!(starts, [111, 222]);
    assert_eq!(ends, [333, 444]);

    unsafe {
        regfree((&mut buffer as *mut PublicRegexBuffer).cast());
    }
}

#[test]
fn re_compile_pattern_honors_re_set_syntax_extended() {
    let _guard = legacy_regex_test_guard();
    let previous = unsafe { re_set_syntax(RE_SYNTAX_POSIX_EXTENDED) };
    let mut buffer = PublicRegexBuffer::default();
    let mut regs = LegacyReRegisters {
        num_regs: 0,
        start: std::ptr::null_mut(),
        end: std::ptr::null_mut(),
    };

    let err = unsafe {
        re_compile_pattern(
            b"(ab)(c)".as_ptr().cast(),
            b"(ab)(c)".len(),
            (&mut buffer as *mut PublicRegexBuffer).cast(),
        )
    };
    unsafe {
        re_set_syntax(previous);
    }
    assert!(err.is_null());
    assert_eq!(buffer.syntax, RE_SYNTAX_POSIX_EXTENDED);
    assert_eq!(buffer.re_nsub, 2);

    let pos = unsafe {
        re_search(
            (&buffer as *const PublicRegexBuffer).cast(),
            b"zzabc".as_ptr().cast(),
            5,
            0,
            5,
            (&mut regs as *mut LegacyReRegisters).cast(),
        )
    };
    assert_eq!(pos, 2);
    unsafe {
        assert_eq!(*regs.start.add(0), 2);
        assert_eq!(*regs.end.add(0), 5);
        assert_eq!(*regs.start.add(1), 2);
        assert_eq!(*regs.end.add(1), 4);
        assert_eq!(*regs.start.add(2), 4);
        assert_eq!(*regs.end.add(2), 5);
        frankenlibc_abi::malloc_abi::free(regs.start.cast());
        frankenlibc_abi::malloc_abi::free(regs.end.cast());
        regfree((&mut buffer as *mut PublicRegexBuffer).cast());
    }
}

#[test]
fn re_set_registers_binds_caller_arrays_for_search() {
    let _guard = legacy_regex_test_guard();
    let mut buffer = PublicRegexBuffer::default();
    let mut regs = LegacyReRegisters {
        num_regs: 0,
        start: std::ptr::null_mut(),
        end: std::ptr::null_mut(),
    };
    let mut starts = [111, 222, 333, 444];
    let mut ends = [555, 666, 777, 888];

    let err = unsafe {
        re_compile_pattern(
            b"\\(ab\\)\\(c\\)".as_ptr().cast(),
            b"\\(ab\\)\\(c\\)".len(),
            (&mut buffer as *mut PublicRegexBuffer).cast(),
        )
    };
    assert!(err.is_null());

    unsafe {
        re_set_registers(
            (&mut buffer as *mut PublicRegexBuffer).cast(),
            (&mut regs as *mut LegacyReRegisters).cast(),
            starts.len() as u32,
            starts.as_mut_ptr(),
            ends.as_mut_ptr(),
        );
    }
    assert_eq!(regs.num_regs, starts.len());
    assert_eq!(regs.start, starts.as_mut_ptr());
    assert_eq!(regs.end, ends.as_mut_ptr());

    let pos = unsafe {
        re_search(
            (&buffer as *const PublicRegexBuffer).cast(),
            b"zzabc".as_ptr().cast(),
            5,
            0,
            5,
            (&mut regs as *mut LegacyReRegisters).cast(),
        )
    };
    assert_eq!(pos, 2);
    assert_eq!(starts, [2, 2, 4, -1]);
    assert_eq!(ends, [5, 4, 5, -1]);

    unsafe {
        regfree((&mut buffer as *mut PublicRegexBuffer).cast());
    }
}

// ---------------------------------------------------------------------------
// timingsafe_bcmp / timingsafe_memcmp (OpenBSD constant-time comparators)
// ---------------------------------------------------------------------------

use frankenlibc_abi::string_abi::{timingsafe_bcmp, timingsafe_memcmp};

#[test]
fn timingsafe_bcmp_equal_returns_zero() {
    let a = b"hello world";
    let b = b"hello world";
    let r = unsafe { timingsafe_bcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) };
    assert_eq!(r, 0);
}

#[test]
fn timingsafe_bcmp_different_returns_one() {
    let a = b"hello world";
    let b = b"hellp world";
    let r = unsafe { timingsafe_bcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) };
    assert_eq!(r, 1);
}

#[test]
fn timingsafe_bcmp_zero_n_returns_zero() {
    // Even with NULL pointers, n == 0 must return 0 (and not deref).
    let r = unsafe { timingsafe_bcmp(std::ptr::null(), std::ptr::null(), 0) };
    assert_eq!(r, 0);
}

#[test]
fn timingsafe_bcmp_null_pointer_safe() {
    // One NULL, one non-NULL with n > 0 — must not deref the non-NULL,
    // and must return non-zero. (Pre-shim guard catches this.)
    let buf = [0u8; 4];
    let r = unsafe { timingsafe_bcmp(std::ptr::null(), buf.as_ptr().cast(), 4) };
    assert_eq!(r, 1);
}

#[test]
fn timingsafe_memcmp_equal_returns_zero() {
    let a = b"\x00\x01\x02\x03\x04";
    let b = b"\x00\x01\x02\x03\x04";
    let r = unsafe { timingsafe_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) };
    assert_eq!(r, 0);
}

#[test]
fn timingsafe_memcmp_first_less_returns_negative() {
    let a = b"abc";
    let b = b"abd";
    let r = unsafe { timingsafe_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) };
    assert!(r < 0);
}

#[test]
fn timingsafe_memcmp_first_greater_returns_positive() {
    let a = b"abd";
    let b = b"abc";
    let r = unsafe { timingsafe_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) };
    assert!(r > 0);
}

#[test]
fn timingsafe_memcmp_unsigned_byte_compare() {
    // 0xff > 0x00 under memcmp's unsigned-byte semantics.
    let a = [0xffu8];
    let b = [0x00u8];
    let r = unsafe { timingsafe_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), 1) };
    assert!(r > 0);
}

#[test]
fn timingsafe_memcmp_zero_n_returns_zero() {
    let r = unsafe { timingsafe_memcmp(std::ptr::null(), std::ptr::null(), 0) };
    assert_eq!(r, 0);
}

#[test]
fn timingsafe_memcmp_pins_first_difference() {
    // Two differences: index 1 (b<c, b1 less) and index 3 (z>a, b1 greater).
    // Result must reflect only the first → negative.
    let a = b"abXz";
    let b = b"acXa";
    let r = unsafe { timingsafe_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), 4) };
    assert!(r < 0);
}

// ---------------------------------------------------------------------------
// consttime_memequal (NetBSD constant-time byte equality)
// ---------------------------------------------------------------------------

use frankenlibc_abi::string_abi::consttime_memequal;

#[test]
fn consttime_memequal_equal_returns_one() {
    let a = b"hello, world";
    let b = b"hello, world";
    let r = unsafe { consttime_memequal(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) };
    assert_eq!(r, 1);
}

#[test]
fn consttime_memequal_different_returns_zero() {
    let a = b"hello, world";
    let b = b"hello, World";
    let r = unsafe { consttime_memequal(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) };
    assert_eq!(r, 0);
}

#[test]
fn consttime_memequal_zero_len_returns_one() {
    let r = unsafe { consttime_memequal(std::ptr::null(), std::ptr::null(), 0) };
    assert_eq!(r, 1);
}

#[test]
fn consttime_memequal_single_byte_difference_at_end() {
    // Differs only at the last byte — verify it's still detected.
    let a = b"AAAAAAAA";
    let b = b"AAAAAAAB";
    let r = unsafe { consttime_memequal(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) };
    assert_eq!(r, 0);
}

#[test]
fn consttime_memequal_single_byte_difference_at_start() {
    let a = b"BAAAAAAA";
    let b = b"AAAAAAAA";
    let r = unsafe { consttime_memequal(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) };
    assert_eq!(r, 0);
}

#[test]
fn consttime_memequal_null_pointers_treated_as_equal_only_if_same() {
    // Inherits timingsafe_bcmp's NULL convention: same pointer → equal.
    let r = unsafe { consttime_memequal(std::ptr::null(), std::ptr::null(), 4) };
    assert_eq!(r, 1);
    // One NULL one non-NULL → not equal.
    let nonnull = b"abcd";
    let r = unsafe { consttime_memequal(std::ptr::null(), nonnull.as_ptr().cast(), 4) };
    assert_eq!(r, 0);
}

#[test]
fn consttime_memequal_examines_all_bytes_for_full_buffer_equality() {
    // Build two 1024-byte buffers identical except for byte 800.
    let mut a = vec![0xa5u8; 1024];
    let mut b = vec![0xa5u8; 1024];
    b[800] = 0x5a;
    let r = unsafe { consttime_memequal(a.as_ptr().cast(), b.as_ptr().cast(), 1024) };
    assert_eq!(r, 0);
    a[800] = 0x5a;
    let r = unsafe { consttime_memequal(a.as_ptr().cast(), b.as_ptr().cast(), 1024) };
    assert_eq!(r, 1);
}

// ---------------------------------------------------------------------------
// strmode (BSD mode-bit-to-`ls -l`-style-string)
// ---------------------------------------------------------------------------

use frankenlibc_abi::string_abi::strmode;

#[test]
fn strmode_writes_11_chars_plus_nul_for_directory() {
    let mut buf = [0xffu8; 12];
    let mode: libc::mode_t = libc::S_IFDIR | 0o755;
    unsafe { strmode(mode, buf.as_mut_ptr().cast()) };
    assert_eq!(&buf[..11], b"drwxr-xr-x ");
    assert_eq!(buf[11], 0, "trailing byte must be NUL");
}

#[test]
fn strmode_regular_file_no_perms() {
    let mut buf = [0xffu8; 12];
    let mode: libc::mode_t = libc::S_IFREG;
    unsafe { strmode(mode, buf.as_mut_ptr().cast()) };
    assert_eq!(&buf[..11], b"---------- ");
    assert_eq!(buf[11], 0);
}

#[test]
fn strmode_sticky_directory_matches_tmp() {
    // /tmp is the canonical example: drwxrwxrwt + space + NUL.
    let mut buf = [0xffu8; 12];
    let mode: libc::mode_t = libc::S_IFDIR | 0o1777;
    unsafe { strmode(mode, buf.as_mut_ptr().cast()) };
    assert_eq!(&buf[..11], b"drwxrwxrwt ");
    assert_eq!(buf[11], 0);
}

#[test]
fn strmode_setuid_with_exec_renders_lowercase_s() {
    let mut buf = [0xffu8; 12];
    let mode: libc::mode_t = libc::S_IFREG | 0o4755;
    unsafe { strmode(mode, buf.as_mut_ptr().cast()) };
    assert_eq!(&buf[..11], b"-rwsr-xr-x ");
    assert_eq!(buf[11], 0);
}

#[test]
fn strmode_setuid_without_exec_renders_uppercase_s() {
    let mut buf = [0xffu8; 12];
    let mode: libc::mode_t = libc::S_IFREG | 0o4644;
    unsafe { strmode(mode, buf.as_mut_ptr().cast()) };
    assert_eq!(&buf[..11], b"-rwSr--r-- ");
    assert_eq!(buf[11], 0);
}

#[test]
fn strmode_symlink_full() {
    let mut buf = [0xffu8; 12];
    let mode: libc::mode_t = libc::S_IFLNK | 0o777;
    unsafe { strmode(mode, buf.as_mut_ptr().cast()) };
    assert_eq!(&buf[..11], b"lrwxrwxrwx ");
    assert_eq!(buf[11], 0);
}

#[test]
fn strmode_null_pointer_is_no_op() {
    // NULL must not segfault. The contract is undefined in BSD but we
    // choose a defensive no-op rather than UB.
    unsafe { strmode(libc::S_IFREG | 0o644, std::ptr::null_mut()) };
}

#[test]
fn strmode_does_not_overrun_caller_buffer() {
    // Place a sentinel byte at index 12 and verify it survives — the
    // shim must never write past the documented 12-byte window.
    let mut buf = [0u8; 16];
    buf[12] = 0xab;
    buf[13] = 0xcd;
    buf[14] = 0xef;
    buf[15] = 0x42;
    unsafe { strmode(libc::S_IFDIR | 0o755, buf.as_mut_ptr().cast()) };
    assert_eq!(&buf[..11], b"drwxr-xr-x ");
    assert_eq!(buf[11], 0);
    assert_eq!(buf[12], 0xab, "byte past the 12-byte window was clobbered");
    assert_eq!(buf[13], 0xcd);
    assert_eq!(buf[14], 0xef);
    assert_eq!(buf[15], 0x42);
}

// ---------------------------------------------------------------------------
// strnstr (BSD bounded substring search)
// ---------------------------------------------------------------------------

use frankenlibc_abi::string_abi::strnstr;

#[test]
fn strnstr_finds_within_bound() {
    let hay = b"hello world\0";
    let needle = b"world\0";
    let p = unsafe { strnstr(hay.as_ptr().cast(), needle.as_ptr().cast(), 11) };
    assert!(!p.is_null());
    let off = unsafe { p.offset_from(hay.as_ptr().cast()) };
    assert_eq!(off, 6);
}

#[test]
fn strnstr_returns_null_when_match_truncated_by_bound() {
    let hay = b"hello world\0";
    let needle = b"world\0";
    // n=10 cuts off the 'd' — no match.
    let p = unsafe { strnstr(hay.as_ptr().cast(), needle.as_ptr().cast(), 10) };
    assert!(p.is_null());
}

#[test]
fn strnstr_empty_needle_returns_haystack() {
    let hay = b"abc\0";
    let needle = b"\0";
    let p = unsafe { strnstr(hay.as_ptr().cast(), needle.as_ptr().cast(), 3) };
    assert_eq!(p as *const i8, hay.as_ptr().cast());
    // Even with n=0 the empty-needle case must return haystack.
    let p0 = unsafe { strnstr(hay.as_ptr().cast(), needle.as_ptr().cast(), 0) };
    assert_eq!(p0 as *const i8, hay.as_ptr().cast());
}

#[test]
fn strnstr_n_zero_with_real_needle_returns_null() {
    let hay = b"abc\0";
    let needle = b"a\0";
    let p = unsafe { strnstr(hay.as_ptr().cast(), needle.as_ptr().cast(), 0) };
    assert!(p.is_null());
}

#[test]
fn strnstr_null_haystack_returns_null() {
    let needle = b"a\0";
    let p = unsafe { strnstr(std::ptr::null(), needle.as_ptr().cast(), 5) };
    assert!(p.is_null());
}

#[test]
fn strnstr_null_needle_returns_haystack() {
    // BSD-style: NULL needle treated as empty → returns haystack.
    let hay = b"abc\0";
    let p = unsafe { strnstr(hay.as_ptr().cast(), std::ptr::null(), 3) };
    assert_eq!(p as *const i8, hay.as_ptr().cast());
}

#[test]
fn strnstr_haystack_truncated_by_internal_nul() {
    // NUL inside haystack truncates the search — needle past the NUL
    // must not be found even with a generous n.
    let hay = b"abc\0def\0";
    let needle = b"def\0";
    let p = unsafe { strnstr(hay.as_ptr().cast(), needle.as_ptr().cast(), 100) };
    assert!(p.is_null());
}

#[test]
fn strnstr_does_not_read_past_n_for_unterminated_haystack() {
    // Unterminated 4-byte buffer with n=4 — must not read byte 5 even
    // though there's a needle that would otherwise match starting at 1.
    let hay = b"xabcGARBAGE-PAST-THE-WINDOW";
    let needle = b"abc\0";
    let p = unsafe { strnstr(hay.as_ptr().cast(), needle.as_ptr().cast(), 4) };
    assert!(!p.is_null());
    let off = unsafe { p.offset_from(hay.as_ptr().cast()) };
    assert_eq!(off, 1);
}

#[test]
fn strnstr_finds_first_of_repeated_pattern() {
    let hay = b"abcabc\0";
    let needle = b"abc\0";
    let p = unsafe { strnstr(hay.as_ptr().cast(), needle.as_ptr().cast(), 6) };
    assert!(!p.is_null());
    let off = unsafe { p.offset_from(hay.as_ptr().cast()) };
    assert_eq!(off, 0);
}

#[test]
fn strnstr_match_at_zero() {
    let hay = b"hello\0";
    let needle = b"hello\0";
    let p = unsafe { strnstr(hay.as_ptr().cast(), needle.as_ptr().cast(), 5) };
    assert_eq!(p as *const i8, hay.as_ptr().cast());
}

// ---------------------------------------------------------------------------
// __strchrnul / __memrchr (glibc reserved-namespace aliases)
// ---------------------------------------------------------------------------

use frankenlibc_abi::string_abi::{__memrchr, __strchrnul, memrchr, strchrnul};

#[test]
fn under_strchrnul_matches_strchrnul_for_match() {
    let s = c"hello, world";
    let a = unsafe { strchrnul(s.as_ptr(), b'w' as c_int) };
    let b = unsafe { __strchrnul(s.as_ptr(), b'w' as c_int) };
    assert_eq!(a, b);
    assert_eq!(unsafe { *a } as u8, b'w');
}

#[test]
fn under_strchrnul_matches_strchrnul_for_no_match() {
    let s = c"hello";
    let a = unsafe { strchrnul(s.as_ptr(), b'z' as c_int) };
    let b = unsafe { __strchrnul(s.as_ptr(), b'z' as c_int) };
    assert_eq!(a, b);
    // Should point at the trailing NUL.
    assert_eq!(unsafe { *a } as u8, 0);
}

#[test]
fn under_strchrnul_null_input_returns_null() {
    let r = unsafe { __strchrnul(std::ptr::null(), b'x' as c_int) };
    assert!(r.is_null());
}

#[test]
fn under_memrchr_matches_memrchr_for_match() {
    let s: &[u8] = b"abcXdefXghi";
    let a = unsafe { memrchr(s.as_ptr().cast(), b'X' as c_int, s.len()) };
    let b = unsafe { __memrchr(s.as_ptr().cast(), b'X' as c_int, s.len()) };
    assert_eq!(a, b);
    let off = unsafe { (a as *const u8).offset_from(s.as_ptr()) };
    assert_eq!(off, 7); // last 'X' is at index 7
}

#[test]
fn under_memrchr_matches_memrchr_for_no_match() {
    let s: &[u8] = b"abcdef";
    let a = unsafe { memrchr(s.as_ptr().cast(), b'z' as c_int, s.len()) };
    let b = unsafe { __memrchr(s.as_ptr().cast(), b'z' as c_int, s.len()) };
    assert_eq!(a, b);
    assert!(a.is_null());
}

#[test]
fn under_memrchr_zero_length_returns_null() {
    let s: &[u8] = b"abc";
    let r = unsafe { __memrchr(s.as_ptr().cast(), b'a' as c_int, 0) };
    assert!(r.is_null());
}

// ---------------------------------------------------------------------------
// sys_siglist (deprecated glibc signal-description array)
// ---------------------------------------------------------------------------

use frankenlibc_abi::string_abi::{_sys_siglist, sys_siglist};

fn read_sys_siglist_str(idx: usize) -> &'static [u8] {
    let p = sys_siglist.0[idx];
    assert!(!p.is_null());
    let s = unsafe { CStr::from_ptr(p) };
    s.to_bytes()
}

fn read_under_sys_siglist_str(idx: usize) -> &'static [u8] {
    let p = _sys_siglist.0[idx];
    assert!(!p.is_null());
    let s = unsafe { CStr::from_ptr(p) };
    s.to_bytes()
}

#[test]
fn sys_siglist_has_65_entries() {
    // NSIG on Linux x86_64 = 65 (signals 0..64).
    assert_eq!(sys_siglist.0.len(), 65);
}

#[test]
fn under_sys_siglist_has_65_populated_entries() {
    assert_eq!(_sys_siglist.0.len(), sys_siglist.0.len());
    for i in 0..sys_siglist.0.len() {
        assert_eq!(read_under_sys_siglist_str(i), read_sys_siglist_str(i));
    }
}

#[test]
fn sys_siglist_index_zero_is_empty_string() {
    assert_eq!(read_sys_siglist_str(0), b"");
}

#[test]
fn sys_siglist_well_known_descriptions() {
    assert_eq!(read_sys_siglist_str(1), b"Hangup"); // SIGHUP
    assert_eq!(read_sys_siglist_str(2), b"Interrupt"); // SIGINT
    assert_eq!(read_sys_siglist_str(9), b"Killed"); // SIGKILL
    assert_eq!(read_sys_siglist_str(11), b"Segmentation fault"); // SIGSEGV
    assert_eq!(read_sys_siglist_str(15), b"Terminated"); // SIGTERM
}

#[test]
fn sys_siglist_realtime_signals_share_placeholder() {
    // Indices 32..=64 use a generic "Real-time signal" string.
    for i in 32..=64usize {
        assert_eq!(
            read_sys_siglist_str(i),
            b"Real-time signal",
            "rt slot {i} should be the placeholder",
        );
    }
}

#[test]
fn sys_siglist_matches_strsignal_for_well_known_signals() {
    // For non-realtime entries the wording must match strsignal.
    use frankenlibc_abi::string_abi::strsignal;
    for sig in [1, 2, 9, 11, 15] {
        let from_array = read_sys_siglist_str(sig as usize);
        let from_strsignal = unsafe { CStr::from_ptr(strsignal(sig)) }.to_bytes();
        assert_eq!(
            from_array, from_strsignal,
            "sys_siglist[{sig}] differs from strsignal({sig})",
        );
    }
}

// ---------------------------------------------------------------------------
// sys_signame (BSD short signal-name array)
// ---------------------------------------------------------------------------

use frankenlibc_abi::string_abi::sys_signame;

fn read_sys_signame_str(idx: usize) -> &'static [u8] {
    let p = sys_signame.0[idx];
    assert!(!p.is_null());
    let s = unsafe { CStr::from_ptr(p) };
    s.to_bytes()
}

#[test]
fn sys_signame_has_65_entries() {
    assert_eq!(sys_signame.0.len(), 65);
}

#[test]
fn sys_signame_index_zero_is_empty_string() {
    assert_eq!(read_sys_signame_str(0), b"");
}

#[test]
fn sys_signame_well_known_short_names() {
    assert_eq!(read_sys_signame_str(1), b"HUP"); // SIGHUP
    assert_eq!(read_sys_signame_str(2), b"INT"); // SIGINT
    assert_eq!(read_sys_signame_str(9), b"KILL"); // SIGKILL
    assert_eq!(read_sys_signame_str(11), b"SEGV"); // SIGSEGV
    assert_eq!(read_sys_signame_str(15), b"TERM"); // SIGTERM
    assert_eq!(read_sys_signame_str(17), b"CHLD"); // SIGCHLD
    assert_eq!(read_sys_signame_str(28), b"WINCH"); // SIGWINCH
    assert_eq!(read_sys_signame_str(31), b"SYS"); // SIGSYS
}

#[test]
fn sys_signame_realtime_signals_share_placeholder() {
    for i in 32..=64usize {
        assert_eq!(
            read_sys_signame_str(i),
            b"RT",
            "rt slot {i} should be the placeholder",
        );
    }
}

#[test]
fn sys_signame_matches_sigabbrev_np_for_well_known_signals() {
    // For non-realtime entries the short name must match
    // sigabbrev_np (which is the modern POSIX-2024 entry point).
    use frankenlibc_abi::signal_abi::sigabbrev_np;
    for sig in [1, 2, 9, 11, 13, 15, 17, 28] {
        let from_array = read_sys_signame_str(sig as usize);
        let p = unsafe { sigabbrev_np(sig) };
        assert!(!p.is_null());
        let from_sigabbrev = unsafe { CStr::from_ptr(p) }.to_bytes();
        assert_eq!(
            from_array, from_sigabbrev,
            "sys_signame[{sig}] differs from sigabbrev_np({sig})",
        );
    }
}

// ---------------------------------------------------------------------------
// Tests for explicit_memset + consttime_bcmp (bd-jt6vm)
// ---------------------------------------------------------------------------

#[test]
fn bd_jt6vm_explicit_memset_writes_byte_value_and_returns_buffer() {
    use frankenlibc_abi::string_abi::explicit_memset;
    let mut buf = [0u8; 32];
    let p = unsafe { explicit_memset(buf.as_mut_ptr() as *mut std::ffi::c_void, 0xAB, buf.len()) };
    assert_eq!(p, buf.as_mut_ptr() as *mut std::ffi::c_void);
    assert!(buf.iter().all(|b| *b == 0xAB));
}

#[test]
fn bd_jt6vm_explicit_memset_null_nonzero_uses_memset_null_guard() {
    use frankenlibc_abi::string_abi::explicit_memset;
    let p = unsafe { explicit_memset(std::ptr::null_mut(), 0xAB, 4) };
    assert!(p.is_null());
}

#[test]
fn bd_jt6vm_memset_explicit_alias_writes_byte_value() {
    use frankenlibc_abi::string_abi::memset_explicit;
    let mut buf = [0u8; 16];
    let p = unsafe { memset_explicit(buf.as_mut_ptr() as *mut std::ffi::c_void, 0x5A, buf.len()) };
    assert_eq!(p, buf.as_mut_ptr() as *mut std::ffi::c_void);
    assert!(buf.iter().all(|b| *b == 0x5A));
}

#[test]
fn bd_jt6vm_explicit_memset_zero_length_is_noop() {
    use frankenlibc_abi::string_abi::explicit_memset;
    let mut buf = [0xCDu8; 8];
    let snapshot = buf;
    let _ = unsafe { explicit_memset(buf.as_mut_ptr() as *mut std::ffi::c_void, 0xFF, 0) };
    assert_eq!(buf, snapshot);
}

#[test]
fn bd_jt6vm_consttime_bcmp_returns_zero_for_equal_buffers() {
    use frankenlibc_abi::string_abi::consttime_bcmp;
    let a = b"FrankenLibC";
    let b = b"FrankenLibC";
    let r = unsafe { consttime_bcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) };
    assert_eq!(r, 0);
}

#[test]
fn bd_jt6vm_consttime_bcmp_returns_one_for_different_buffers() {
    use frankenlibc_abi::string_abi::consttime_bcmp;
    let a = b"FrankenLibc";
    let b = b"FrankenLibC";
    let r = unsafe { consttime_bcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) };
    assert_eq!(r, 1);
}

#[test]
fn bd_jt6vm_consttime_bcmp_zero_len_returns_zero() {
    use frankenlibc_abi::string_abi::consttime_bcmp;
    let r = unsafe { consttime_bcmp(std::ptr::null(), std::ptr::null(), 0) };
    assert_eq!(r, 0);
}
