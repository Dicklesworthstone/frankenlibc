#![cfg(target_os = "linux")]

//! Integration tests for `<wchar.h>` ABI entrypoints.

use std::ffi::{CStr, c_char, c_int, c_void};

use frankenlibc_abi::glibc_internal_abi::fwide;
use frankenlibc_abi::io_internal_abi::verify_native_file;
use frankenlibc_abi::malloc_abi::{free, malloc};
use frankenlibc_abi::stdlib_abi::{basename, dirname, realpath};
use frankenlibc_abi::wchar_abi::*;

fn errno_value() -> i32 {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() }
}

fn set_errno(value: i32) {
    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = value;
    }
}

/// Helper: build a NUL-terminated wide string from ASCII bytes.
fn wstr(s: &[u8]) -> Vec<u32> {
    let mut v: Vec<u32> = s.iter().map(|&b| b as u32).collect();
    v.push(0);
    v
}

// ── wcslen ──────────────────────────────────────────────────────────────────

#[test]
fn wcslen_counts_to_nul() {
    let s = wstr(b"hello");
    assert_eq!(unsafe { wcslen(s.as_ptr()) }, 5);
}

#[test]
fn wcslen_empty_string() {
    let s = wstr(b"");
    assert_eq!(unsafe { wcslen(s.as_ptr()) }, 0);
}

// ── wcscpy / wcsncpy ───────────────────────────────────────────────────────

#[test]
fn wcscpy_copies_full_string() {
    let src = wstr(b"abc");
    let mut dst = [0u32; 8];
    let ret = unsafe { wcscpy(dst.as_mut_ptr(), src.as_ptr()) };
    assert_eq!(ret, dst.as_mut_ptr());
    assert_eq!(dst[0], b'a' as u32);
    assert_eq!(dst[1], b'b' as u32);
    assert_eq!(dst[2], b'c' as u32);
    assert_eq!(dst[3], 0);
}

#[test]
fn wcsncpy_pads_with_nul() {
    let src = wstr(b"hi");
    let mut dst = [0xFFu32; 6];
    let ret = unsafe { wcsncpy(dst.as_mut_ptr(), src.as_ptr(), 5) };
    assert_eq!(ret, dst.as_mut_ptr());
    assert_eq!(dst[0], b'h' as u32);
    assert_eq!(dst[1], b'i' as u32);
    // Positions 2..5 should be NUL-padded.
    assert_eq!(dst[2], 0);
    assert_eq!(dst[3], 0);
    assert_eq!(dst[4], 0);
    // Position 5 untouched.
    assert_eq!(dst[5], 0xFF);
}

#[test]
fn wcsncpy_truncates_when_n_smaller() {
    let src = wstr(b"hello");
    let mut dst = [0u32; 4];
    unsafe { wcsncpy(dst.as_mut_ptr(), src.as_ptr(), 3) };
    assert_eq!(dst[0], b'h' as u32);
    assert_eq!(dst[1], b'e' as u32);
    assert_eq!(dst[2], b'l' as u32);
}

// ── wcscat / wcsncat ────────────────────────────────────────────────────────

#[test]
fn wcscat_appends_source() {
    let suffix = wstr(b"world");
    let mut buf = [0u32; 16];
    buf[0] = b'h' as u32;
    buf[1] = b'i' as u32;
    buf[2] = 0;
    let ret = unsafe { wcscat(buf.as_mut_ptr(), suffix.as_ptr()) };
    assert_eq!(ret, buf.as_mut_ptr());
    assert_eq!(unsafe { wcslen(buf.as_ptr()) }, 7);
}

#[test]
fn wcsncat_limits_appended_chars() {
    let suffix = wstr(b"world");
    let mut buf = [0u32; 16];
    buf[0] = b'h' as u32;
    buf[1] = b'i' as u32;
    buf[2] = 0;
    unsafe { wcsncat(buf.as_mut_ptr(), suffix.as_ptr(), 3) };
    // "hi" + "wor" = 5
    assert_eq!(unsafe { wcslen(buf.as_ptr()) }, 5);
    assert_eq!(buf[4], b'r' as u32);
    assert_eq!(buf[5], 0); // NUL-terminated
}

// ── wcscmp / wcsncmp ────────────────────────────────────────────────────────

#[test]
fn wcscmp_compares_strings() {
    let a = wstr(b"abc");
    let b = wstr(b"abd");
    assert!(unsafe { wcscmp(a.as_ptr(), b.as_ptr()) } < 0);
    assert!(unsafe { wcscmp(b.as_ptr(), a.as_ptr()) } > 0);
    assert_eq!(unsafe { wcscmp(a.as_ptr(), a.as_ptr()) }, 0);
}

#[test]
fn wcsncmp_compares_up_to_n() {
    let a = wstr(b"abcX");
    let b = wstr(b"abcY");
    assert_eq!(unsafe { wcsncmp(a.as_ptr(), b.as_ptr(), 3) }, 0);
    assert_ne!(unsafe { wcsncmp(a.as_ptr(), b.as_ptr(), 4) }, 0);
    assert_eq!(unsafe { wcsncmp(a.as_ptr(), b.as_ptr(), 0) }, 0);
}

// ── wcschr / wcsrchr / wcschrnul ────────────────────────────────────────────

#[test]
fn wcschr_finds_first_occurrence() {
    let s = wstr(b"abcbc");
    let ptr = unsafe { wcschr(s.as_ptr(), b'b' as u32) };
    assert!(!ptr.is_null());
    assert_eq!(unsafe { ptr.offset_from(s.as_ptr()) }, 1);
}

#[test]
fn wcschr_returns_null_for_missing() {
    let s = wstr(b"abc");
    assert!(unsafe { wcschr(s.as_ptr(), b'z' as u32) }.is_null());
}

#[test]
fn wcschr_finds_nul_terminator() {
    let s = wstr(b"abc");
    let ptr = unsafe { wcschr(s.as_ptr(), 0) };
    assert!(!ptr.is_null());
    assert_eq!(unsafe { ptr.offset_from(s.as_ptr()) }, 3);
}

#[test]
fn wcsrchr_finds_last_occurrence() {
    let s = wstr(b"abcbc");
    let ptr = unsafe { wcsrchr(s.as_ptr(), b'b' as u32) };
    assert!(!ptr.is_null());
    assert_eq!(unsafe { ptr.offset_from(s.as_ptr()) }, 3);
}

#[test]
fn wcsrchr_returns_null_for_missing() {
    let s = wstr(b"abc");
    assert!(unsafe { wcsrchr(s.as_ptr(), b'z' as u32) }.is_null());
}

#[test]
fn wcschrnul_returns_nul_position_for_missing() {
    let s = wstr(b"abc");
    let ptr = unsafe { wcschrnul(s.as_ptr() as *const libc::wchar_t, b'z' as libc::wchar_t) };
    assert!(!ptr.is_null());
    assert_eq!(
        unsafe { ptr.offset_from(s.as_ptr() as *const libc::wchar_t) },
        3
    );
    assert_eq!(unsafe { *ptr }, 0);
}

// ── wcsstr ──────────────────────────────────────────────────────────────────

#[test]
fn wcsstr_finds_substring() {
    let hay = wstr(b"hello world");
    let needle = wstr(b"world");
    let ptr = unsafe { wcsstr(hay.as_ptr(), needle.as_ptr()) };
    assert!(!ptr.is_null());
    assert_eq!(unsafe { ptr.offset_from(hay.as_ptr()) }, 6);
}

#[test]
fn wcsstr_returns_null_for_missing() {
    let hay = wstr(b"hello");
    let needle = wstr(b"xyz");
    assert!(unsafe { wcsstr(hay.as_ptr(), needle.as_ptr()) }.is_null());
}

#[test]
fn wcsstr_empty_needle_returns_haystack() {
    let hay = wstr(b"hello");
    let needle = wstr(b"");
    let ptr = unsafe { wcsstr(hay.as_ptr(), needle.as_ptr()) };
    assert_eq!(ptr, hay.as_ptr() as *mut u32);
}

// ── wcsspn / wcscspn / wcspbrk ──────────────────────────────────────────────

#[test]
fn wcsspn_counts_accepted_prefix() {
    let s = wstr(b"abcdef");
    let accept = wstr(b"cba");
    assert_eq!(unsafe { wcsspn(s.as_ptr(), accept.as_ptr()) }, 3);
}

#[test]
fn wcscspn_counts_rejected_prefix() {
    let s = wstr(b"abcdef");
    let reject = wstr(b"dc");
    assert_eq!(unsafe { wcscspn(s.as_ptr(), reject.as_ptr()) }, 2);
}

#[test]
fn wcspbrk_finds_first_matching_char() {
    let s = wstr(b"hello world");
    let accept = wstr(b"ow");
    let ptr = unsafe { wcspbrk(s.as_ptr(), accept.as_ptr()) };
    assert!(!ptr.is_null());
    assert_eq!(unsafe { *ptr }, b'o' as u32);
}

#[test]
fn wcspbrk_returns_null_when_no_match() {
    let s = wstr(b"hello");
    let accept = wstr(b"xyz");
    assert!(unsafe { wcspbrk(s.as_ptr(), accept.as_ptr()) }.is_null());
}

// ── wcstok ──────────────────────────────────────────────────────────────────

#[test]
fn wcstok_splits_on_delimiters() {
    let mut s = wstr(b"one,two,,three");
    let delim = wstr(b",");
    let mut save: *mut u32 = std::ptr::null_mut();

    let tok1 = unsafe { wcstok(s.as_mut_ptr(), delim.as_ptr(), &mut save) };
    assert!(!tok1.is_null());
    assert_eq!(unsafe { wcslen(tok1) }, 3); // "one"

    let tok2 = unsafe { wcstok(std::ptr::null_mut(), delim.as_ptr(), &mut save) };
    assert!(!tok2.is_null());
    assert_eq!(unsafe { wcslen(tok2) }, 3); // "two"

    let tok3 = unsafe { wcstok(std::ptr::null_mut(), delim.as_ptr(), &mut save) };
    assert!(!tok3.is_null());
    assert_eq!(unsafe { wcslen(tok3) }, 5); // "three"

    let tok4 = unsafe { wcstok(std::ptr::null_mut(), delim.as_ptr(), &mut save) };
    assert!(tok4.is_null());
}

// ── wmemcpy / wmemmove / wmemset / wmemcmp / wmemchr / wmemrchr ─────────────

#[test]
fn wmemcpy_copies_elements() {
    let src = wstr(b"abcde");
    let mut dst = [0u32; 5];
    let ret = unsafe { wmemcpy(dst.as_mut_ptr(), src.as_ptr(), 5) };
    assert_eq!(ret, dst.as_mut_ptr());
    assert_eq!(dst[0], b'a' as u32);
    assert_eq!(dst[4], b'e' as u32);
}

#[test]
fn wmemmove_handles_overlap() {
    let mut buf = [1u32, 2, 3, 4, 5, 0, 0, 0];
    // Move [1,2,3,4,5] two positions right.
    unsafe { wmemmove(buf.as_mut_ptr().add(2), buf.as_ptr(), 5) };
    assert_eq!(buf[2], 1);
    assert_eq!(buf[6], 5);
}

#[test]
fn wmemset_fills_elements() {
    let mut buf = [0u32; 5];
    let ret = unsafe { wmemset(buf.as_mut_ptr(), 42, 3) };
    assert_eq!(ret, buf.as_mut_ptr());
    assert_eq!(buf[0], 42);
    assert_eq!(buf[2], 42);
    assert_eq!(buf[3], 0); // Untouched
}

#[test]
fn wmemcmp_compares_elements() {
    let a = [1u32, 2, 3];
    let b = [1u32, 2, 4];
    assert_eq!(unsafe { wmemcmp(a.as_ptr(), b.as_ptr(), 2) }, 0);
    assert!(unsafe { wmemcmp(a.as_ptr(), b.as_ptr(), 3) } < 0);
    assert!(unsafe { wmemcmp(b.as_ptr(), a.as_ptr(), 3) } > 0);
    assert_eq!(unsafe { wmemcmp(a.as_ptr(), b.as_ptr(), 0) }, 0);
}

#[test]
fn wmemchr_finds_element() {
    let buf = [10u32, 20, 30, 40];
    let ptr = unsafe { wmemchr(buf.as_ptr(), 30, 4) };
    assert!(!ptr.is_null());
    assert_eq!(unsafe { ptr.offset_from(buf.as_ptr()) }, 2);
}

#[test]
fn wmemchr_returns_null_when_not_found() {
    let buf = [10u32, 20, 30];
    assert!(unsafe { wmemchr(buf.as_ptr(), 99, 3) }.is_null());
}

#[test]
fn wmemrchr_finds_last_element() {
    let buf = [10u32, 20, 30, 20, 40];
    let ptr = unsafe { wmemrchr(buf.as_ptr(), 20, 5) };
    assert!(!ptr.is_null());
    assert_eq!(unsafe { ptr.offset_from(buf.as_ptr()) }, 3);
}

// ── wcsdup ──────────────────────────────────────────────────────────────────

#[test]
fn wcsdup_duplicates_string() {
    let s = wstr(b"test");
    let dup = unsafe { wcsdup(s.as_ptr()) };
    assert!(!dup.is_null());
    assert_eq!(unsafe { wcslen(dup) }, 4);
    assert_eq!(unsafe { *dup }, b't' as u32);
    assert_eq!(unsafe { *dup.add(3) }, b't' as u32);
    assert_eq!(unsafe { *dup.add(4) }, 0);
    unsafe { frankenlibc_abi::malloc_abi::free(dup.cast()) };
}

// ── wcpcpy / wcpncpy ───────────────────────────────────────────────────────

#[test]
fn wcpcpy_returns_pointer_to_nul() {
    let src = wstr(b"abc");
    let mut dst = [0u32; 8];
    let end = unsafe { wcpcpy(dst.as_mut_ptr(), src.as_ptr()) };
    // wcpcpy returns pointer to the NUL terminator.
    assert_eq!(unsafe { end.offset_from(dst.as_ptr()) }, 3);
    assert_eq!(unsafe { *end }, 0);
    assert_eq!(dst[0], b'a' as u32);
}

#[test]
fn wcpncpy_returns_pointer_past_last_written() {
    let src = wstr(b"hi");
    let mut dst = [0xFFu32; 6];
    let end = unsafe { wcpncpy(dst.as_mut_ptr(), src.as_ptr(), 5) };
    // wcpncpy returns dst + min(wcslen(src), n), padded with NULs.
    assert_eq!(unsafe { end.offset_from(dst.as_ptr()) }, 2);
    assert_eq!(dst[2], 0);
    assert_eq!(dst[4], 0);
}

// ── wcscasecmp / wcsncasecmp ────────────────────────────────────────────────

#[test]
fn wcscasecmp_ignores_case() {
    let a = wstr(b"Hello");
    let b = wstr(b"hELLO");
    assert_eq!(unsafe { wcscasecmp(a.as_ptr(), b.as_ptr()) }, 0);

    let c = wstr(b"abc");
    let d = wstr(b"abd");
    assert!(unsafe { wcscasecmp(c.as_ptr(), d.as_ptr()) } < 0);
}

#[test]
fn wcsncasecmp_compares_up_to_n() {
    let a = wstr(b"Hello World");
    let b = wstr(b"hELLO EARTH");
    assert_eq!(unsafe { wcsncasecmp(a.as_ptr(), b.as_ptr(), 5) }, 0);
    assert_eq!(unsafe { wcsncasecmp(a.as_ptr(), b.as_ptr(), 6) }, 0); // space == space
    assert_ne!(unsafe { wcsncasecmp(a.as_ptr(), b.as_ptr(), 7) }, 0); // W != E
}

// ── wcslcpy / wcslcat ───────────────────────────────────────────────────────

#[test]
fn wcslcpy_copies_and_returns_src_len() {
    let src = wstr(b"hello");
    let mut dst = [0u32; 4];
    let n = unsafe {
        wcslcpy(
            dst.as_mut_ptr() as *mut libc::wchar_t,
            src.as_ptr() as *const libc::wchar_t,
            4,
        )
    };
    assert_eq!(n, 5); // Length of src
    // Should truncate to "hel\0"
    assert_eq!(dst[0], b'h' as u32);
    assert_eq!(dst[2], b'l' as u32);
    assert_eq!(dst[3], 0);
}

#[test]
fn wcslcat_appends_and_returns_total_len() {
    let suffix = wstr(b"world");
    let mut buf = [0u32; 10];
    buf[0] = b'h' as u32;
    buf[1] = b'i' as u32;
    buf[2] = 0;
    let n = unsafe {
        wcslcat(
            buf.as_mut_ptr() as *mut libc::wchar_t,
            suffix.as_ptr() as *const libc::wchar_t,
            10,
        )
    };
    assert_eq!(n, 7); // 2 + 5
    assert_eq!(unsafe { wcslen(buf.as_ptr()) }, 7);
}

// ── wcstoimax / wcstoumax ───────────────────────────────────────────────────

#[test]
fn wcstoimax_parses_signed() {
    let s = wstr(b"-42");
    let mut end: *mut u32 = std::ptr::null_mut();
    let v = unsafe { wcstoimax(s.as_ptr(), &mut end, 10) };
    assert_eq!(v, -42);
    assert_eq!(unsafe { end.offset_from(s.as_ptr()) }, 3);
}

#[test]
fn wcstoumax_parses_unsigned() {
    let s = wstr(b"99");
    let mut end: *mut u32 = std::ptr::null_mut();
    let v = unsafe { wcstoumax(s.as_ptr(), &mut end, 10) };
    assert_eq!(v, 99);
}

// ── towupper / towlower ─────────────────────────────────────────────────────

#[test]
fn towupper_converts_lowercase() {
    assert_eq!(unsafe { towupper(b'a' as u32) }, b'A' as u32);
    assert_eq!(unsafe { towupper(b'Z' as u32) }, b'Z' as u32);
    assert_eq!(unsafe { towupper(b'5' as u32) }, b'5' as u32);
}

#[test]
fn towlower_converts_uppercase() {
    assert_eq!(unsafe { towlower(b'A' as u32) }, b'a' as u32);
    assert_eq!(unsafe { towlower(b'z' as u32) }, b'z' as u32);
    assert_eq!(unsafe { towlower(b'5' as u32) }, b'5' as u32);
}

// ── isw* classification ─────────────────────────────────────────────────────

#[test]
fn iswalnum_identifies_alphanumerics() {
    assert_ne!(unsafe { iswalnum(b'a' as u32) }, 0);
    assert_ne!(unsafe { iswalnum(b'Z' as u32) }, 0);
    assert_ne!(unsafe { iswalnum(b'5' as u32) }, 0);
    assert_eq!(unsafe { iswalnum(b' ' as u32) }, 0);
    assert_eq!(unsafe { iswalnum(b'!' as u32) }, 0);
}

#[test]
fn iswalpha_identifies_letters() {
    assert_ne!(unsafe { iswalpha(b'a' as u32) }, 0);
    assert_ne!(unsafe { iswalpha(b'Z' as u32) }, 0);
    assert_eq!(unsafe { iswalpha(b'5' as u32) }, 0);
}

#[test]
fn iswdigit_identifies_digits() {
    assert_ne!(unsafe { iswdigit(b'0' as u32) }, 0);
    assert_ne!(unsafe { iswdigit(b'9' as u32) }, 0);
    assert_eq!(unsafe { iswdigit(b'a' as u32) }, 0);
}

#[test]
fn iswlower_and_iswupper() {
    assert_ne!(unsafe { iswlower(b'a' as u32) }, 0);
    assert_eq!(unsafe { iswlower(b'A' as u32) }, 0);
    assert_ne!(unsafe { iswupper(b'A' as u32) }, 0);
    assert_eq!(unsafe { iswupper(b'a' as u32) }, 0);
}

#[test]
fn iswspace_identifies_whitespace() {
    assert_ne!(unsafe { iswspace(b' ' as u32) }, 0);
    assert_ne!(unsafe { iswspace(b'\t' as u32) }, 0);
    assert_ne!(unsafe { iswspace(b'\n' as u32) }, 0);
    assert_eq!(unsafe { iswspace(b'a' as u32) }, 0);
}

#[test]
fn iswprint_identifies_printable() {
    assert_ne!(unsafe { iswprint(b'a' as u32) }, 0);
    assert_ne!(unsafe { iswprint(b' ' as u32) }, 0);
    assert_eq!(unsafe { iswprint(0x01) }, 0); // SOH control char
}

#[test]
fn iswblank_identifies_horizontal_whitespace() {
    assert_ne!(unsafe { iswblank(b' ' as u32) }, 0);
    assert_ne!(unsafe { iswblank(b'\t' as u32) }, 0);
    assert_eq!(unsafe { iswblank(b'\n' as u32) }, 0);
    assert_eq!(unsafe { iswblank(b'a' as u32) }, 0);
}

#[test]
fn iswcntrl_identifies_control_chars() {
    assert_ne!(unsafe { iswcntrl(0x00) }, 0); // NUL
    assert_ne!(unsafe { iswcntrl(0x1F) }, 0); // US
    assert_ne!(unsafe { iswcntrl(0x7F) }, 0); // DEL
    assert_eq!(unsafe { iswcntrl(b'a' as u32) }, 0);
}

#[test]
fn iswgraph_identifies_visible_chars() {
    assert_ne!(unsafe { iswgraph(b'a' as u32) }, 0);
    assert_ne!(unsafe { iswgraph(b'!' as u32) }, 0);
    assert_eq!(unsafe { iswgraph(b' ' as u32) }, 0);
    assert_eq!(unsafe { iswgraph(0x01) }, 0);
}

#[test]
fn iswpunct_identifies_punctuation() {
    assert_ne!(unsafe { iswpunct(b'!' as u32) }, 0);
    assert_ne!(unsafe { iswpunct(b'.' as u32) }, 0);
    assert_eq!(unsafe { iswpunct(b'a' as u32) }, 0);
    assert_eq!(unsafe { iswpunct(b' ' as u32) }, 0);
}

#[test]
fn iswxdigit_identifies_hex_digits() {
    assert_ne!(unsafe { iswxdigit(b'0' as u32) }, 0);
    assert_ne!(unsafe { iswxdigit(b'a' as u32) }, 0);
    assert_ne!(unsafe { iswxdigit(b'F' as u32) }, 0);
    assert_eq!(unsafe { iswxdigit(b'g' as u32) }, 0);
}

// ── wcwidth ─────────────────────────────────────────────────────────────────

#[test]
fn wcwidth_reports_display_width() {
    assert_eq!(unsafe { wcwidth(b'A' as u32) }, 1);
    assert_eq!(unsafe { wcwidth(0x754c) }, 2); // CJK char '界'
    assert_eq!(unsafe { wcwidth(0) }, 0); // NUL
}

// ── wctype / iswctype ───────────────────────────────────────────────────────

#[test]
fn wctype_and_iswctype_classify_by_name() {
    let alpha = unsafe { wctype(c"alpha".as_ptr().cast()) };
    assert_ne!(alpha, 0);
    assert_ne!(unsafe { iswctype(b'A' as u32, alpha) }, 0);
    assert_eq!(unsafe { iswctype(b'5' as u32, alpha) }, 0);

    let digit = unsafe { wctype(c"digit".as_ptr().cast()) };
    assert_ne!(digit, 0);
    assert_ne!(unsafe { iswctype(b'9' as u32, digit) }, 0);
    assert_eq!(unsafe { iswctype(b'A' as u32, digit) }, 0);
}

#[test]
fn wctype_returns_zero_for_unknown() {
    assert_eq!(unsafe { wctype(c"bogus".as_ptr().cast()) }, 0);
}

// ── towupper_l / towlower_l (null locale = C locale) ────────────────────────

#[test]
fn towupper_l_null_locale_matches_base() {
    let loc = std::ptr::null_mut();
    for c in 0u32..=127 {
        assert_eq!(
            unsafe { towupper_l(c, loc) },
            unsafe { towupper(c) },
            "mismatch at {c}"
        );
    }
}

#[test]
fn towlower_l_null_locale_matches_base() {
    let loc = std::ptr::null_mut();
    for c in 0u32..=127 {
        assert_eq!(
            unsafe { towlower_l(c, loc) },
            unsafe { towlower(c) },
            "mismatch at {c}"
        );
    }
}

// ── isw*_l locale variants sweep ────────────────────────────────────────────

#[test]
fn iswalnum_l_matches_base_for_ascii() {
    let loc = std::ptr::null_mut();
    for c in 0u32..=127 {
        assert_eq!(
            unsafe { iswalnum_l(c, loc) },
            unsafe { iswalnum(c) },
            "iswalnum mismatch at {c}"
        );
    }
}

#[test]
fn iswalpha_l_matches_base_for_ascii() {
    let loc = std::ptr::null_mut();
    for c in 0u32..=127 {
        assert_eq!(
            unsafe { iswalpha_l(c, loc) },
            unsafe { iswalpha(c) },
            "iswalpha mismatch at {c}"
        );
    }
}

#[test]
fn iswdigit_l_matches_base_for_ascii() {
    let loc = std::ptr::null_mut();
    for c in 0u32..=127 {
        assert_eq!(
            unsafe { iswdigit_l(c, loc) },
            unsafe { iswdigit(c) },
            "iswdigit mismatch at {c}"
        );
    }
}

#[test]
fn iswspace_l_matches_base_for_ascii() {
    let loc = std::ptr::null_mut();
    for c in 0u32..=127 {
        assert_eq!(
            unsafe { iswspace_l(c, loc) },
            unsafe { iswspace(c) },
            "iswspace mismatch at {c}"
        );
    }
}

// ── mblen / mbtowc / wctomb ────────────────────────────────────────────────

#[test]
fn mblen_measures_ascii_and_multibyte() {
    let ascii = [b'A'];
    assert_eq!(unsafe { mblen(ascii.as_ptr(), 1) }, 1);

    let utf8 = [0xC3u8, 0xA9]; // é
    assert_eq!(unsafe { mblen(utf8.as_ptr(), 2) }, 2);

    // NUL byte returns 0
    let nul = [0u8];
    assert_eq!(unsafe { mblen(nul.as_ptr(), 1) }, 0);
}

#[test]
fn mbtowc_converts_ascii() {
    let mut wc: u32 = 0;
    let ascii = [b'X'];
    let n = unsafe { mbtowc(&mut wc, ascii.as_ptr(), 1) };
    assert_eq!(n, 1);
    assert_eq!(wc, b'X' as u32);
}

#[test]
fn mbtowc_converts_multibyte() {
    let mut wc: u32 = 0;
    let utf8 = [0xC3u8, 0xA9]; // é
    let n = unsafe { mbtowc(&mut wc, utf8.as_ptr(), 2) };
    assert_eq!(n, 2);
    assert_eq!(wc, 'é' as u32);
}

#[test]
fn wctomb_encodes_ascii() {
    let mut buf = [0u8; 4];
    let n = unsafe { wctomb(buf.as_mut_ptr(), b'A' as u32) };
    assert_eq!(n, 1);
    assert_eq!(buf[0], b'A');
}

#[test]
fn wctomb_encodes_multibyte() {
    let mut buf = [0u8; 4];
    let n = unsafe { wctomb(buf.as_mut_ptr(), 'é' as u32) };
    assert_eq!(n, 2);
    assert_eq!(buf[0], 0xC3);
    assert_eq!(buf[1], 0xA9);
}

// ── mbstowcs / wcstombs ────────────────────────────────────────────────────

#[test]
fn mbstowcs_converts_utf8_to_wide() {
    let src = b"A\xC3\xA9\0"; // "Aé"
    let mut dst = [0u32; 4];
    let n = unsafe { mbstowcs(dst.as_mut_ptr(), src.as_ptr(), 4) };
    assert_eq!(n, 2);
    assert_eq!(dst[0], b'A' as u32);
    assert_eq!(dst[1], 'é' as u32);
    assert_eq!(dst[2], 0);
}

#[test]
fn mbstowcs_rejects_unterminated_known_input() {
    unsafe {
        let src = malloc(3).cast::<u8>();
        assert!(!src.is_null());
        std::ptr::copy_nonoverlapping(b"ABC".as_ptr(), src, 3);

        let mut dst = [0u32; 4];
        set_errno(0);
        let n = mbstowcs(dst.as_mut_ptr(), src, dst.len());
        assert_eq!(n, usize::MAX);
        assert_eq!(errno_value(), libc::EILSEQ);

        free(src.cast());
    }
}

#[test]
fn wcstombs_converts_wide_to_utf8() {
    let src = [b'A' as u32, 'é' as u32, 0];
    let mut dst = [0u8; 8];
    let n = unsafe { wcstombs(dst.as_mut_ptr(), src.as_ptr(), 8) };
    assert_eq!(n, 3);
    assert_eq!(dst[0], b'A');
    assert_eq!(dst[1], 0xC3);
    assert_eq!(dst[2], 0xA9);
    assert_eq!(dst[3], 0);
}

// ── mbsinit / mbrlen ────────────────────────────────────────────────────────

#[test]
fn mbsinit_returns_nonzero_for_null() {
    assert_ne!(unsafe { mbsinit(std::ptr::null()) }, 0);
}

#[test]
fn mbsinit_returns_nonzero_for_initial_state() {
    let state = [0u8; 64]; // Zero-initialized mbstate_t
    assert_ne!(unsafe { mbsinit(state.as_ptr().cast()) }, 0);
}

#[test]
fn mbrlen_measures_multibyte() {
    let ascii = [b'X'];
    let n = unsafe { mbrlen(ascii.as_ptr() as *const c_char, 1, std::ptr::null_mut()) };
    assert_eq!(n, 1);

    let utf8 = [0xC3u8, 0xA9]; // é
    let n = unsafe { mbrlen(utf8.as_ptr() as *const c_char, 2, std::ptr::null_mut()) };
    assert_eq!(n, 2);
}

// ── mbsnrtowcs / wcsnrtombs ────────────────────────────────────────────────

#[test]
fn mbsnrtowcs_converts_bounded() {
    let src_bytes = b"AB\0";
    let mut src_ptr: *const c_char = src_bytes.as_ptr() as *const c_char;
    let mut dst = [0i32; 8];
    let written = unsafe {
        mbsnrtowcs(
            dst.as_mut_ptr(),
            &mut src_ptr as *mut *const c_char,
            3, // nms: max bytes to examine
            dst.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(written, 2);
    assert!(src_ptr.is_null()); // Consumed entire string
    assert_eq!(dst[0], b'A' as i32);
    assert_eq!(dst[1], b'B' as i32);
}

#[test]
fn wcsnrtombs_converts_bounded() {
    let src_wcs: [libc::wchar_t; 3] = [b'A' as libc::wchar_t, b'B' as libc::wchar_t, 0];
    let mut src_ptr: *const libc::wchar_t = src_wcs.as_ptr();
    let mut dst = [0i8; 8];
    // nwc=3 allows processing through the NUL terminator
    let written = unsafe {
        wcsnrtombs(
            dst.as_mut_ptr(),
            &mut src_ptr,
            3,
            dst.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(written, 2);
    assert!(src_ptr.is_null()); // NUL was reached → src set to null
    assert_eq!(dst[0] as u8, b'A');
    assert_eq!(dst[1] as u8, b'B');
}

// ── basename / dirname ──────────────────────────────────────────────────────

#[test]
fn basename_extracts_filename() {
    let mut path = b"/usr/lib/libm.so\0".to_vec();
    let result = unsafe { basename(path.as_mut_ptr() as *mut c_char) };
    assert!(!result.is_null());
    let name = unsafe { CStr::from_ptr(result) }.to_bytes();
    assert_eq!(name, b"libm.so");
}

#[test]
fn basename_handles_trailing_slash() {
    let mut path = b"/usr/lib/\0".to_vec();
    let result = unsafe { basename(path.as_mut_ptr() as *mut c_char) };
    assert!(!result.is_null());
    let name = unsafe { CStr::from_ptr(result) }.to_bytes();
    // POSIX: trailing slash means last component is empty or "lib"
    // Our implementation removes trailing slashes first.
    assert!(!name.is_empty());
}

#[test]
fn dirname_extracts_directory() {
    let mut path = b"/usr/lib/libm.so\0".to_vec();
    let result = unsafe { dirname(path.as_mut_ptr() as *mut c_char) };
    assert!(!result.is_null());
    let dir = unsafe { CStr::from_ptr(result) }.to_bytes();
    assert_eq!(dir, b"/usr/lib");
}

#[test]
fn dirname_root_path() {
    let mut path = b"/foo\0".to_vec();
    let result = unsafe { dirname(path.as_mut_ptr() as *mut c_char) };
    assert!(!result.is_null());
    let dir = unsafe { CStr::from_ptr(result) }.to_bytes();
    assert_eq!(dir, b"/");
}

#[test]
fn dirname_no_slash() {
    let mut path = b"file.txt\0".to_vec();
    let result = unsafe { dirname(path.as_mut_ptr() as *mut c_char) };
    assert!(!result.is_null());
    let dir = unsafe { CStr::from_ptr(result) }.to_bytes();
    assert_eq!(dir, b".");
}

// ── swprintf / swscanf ─────────────────────────────────────────────────────

#[test]
fn swprintf_formats_integer() {
    let mut buf = [0u32; 32];
    // Format: "%d"
    let fmt = [b'%' as u32, b'd' as u32, 0];
    let n = unsafe {
        swprintf(
            buf.as_mut_ptr() as *mut libc::wchar_t,
            32,
            fmt.as_ptr() as *const libc::wchar_t,
            42i32,
        )
    };
    assert!(n > 0);
    let rendered: Vec<u8> = buf[..n as usize].iter().map(|&c| c as u8).collect();
    assert_eq!(rendered, b"42");
}

#[test]
fn swprintf_formats_string() {
    let mut buf = [0u32; 32];
    // Format: "%s" (narrow string)
    let fmt = [b'%' as u32, b's' as u32, 0];
    let n = unsafe {
        swprintf(
            buf.as_mut_ptr() as *mut libc::wchar_t,
            32,
            fmt.as_ptr() as *const libc::wchar_t,
            c"hi".as_ptr(),
        )
    };
    assert!(n > 0);
    let rendered: Vec<u8> = buf[..n as usize].iter().map(|&c| c as u8).collect();
    assert_eq!(rendered, b"hi");
}

#[test]
fn swscanf_parses_integer() {
    let input = wstr(b"42 hello");
    let mut val: c_int = 0;
    let n = unsafe {
        swscanf(
            input.as_ptr() as *const libc::wchar_t,
            wstr(b"%d").as_ptr() as *const libc::wchar_t,
            &mut val as *mut c_int,
        )
    };
    assert_eq!(n, 1);
    assert_eq!(val, 42);
}

#[test]
fn wide_vscanf_null_va_list_fails_closed() {
    let input = wstr(b"42");
    let fmt = wstr(b"%d");

    let rc = unsafe {
        vswscanf(
            input.as_ptr() as *const libc::wchar_t,
            fmt.as_ptr() as *const libc::wchar_t,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, libc::EOF);

    let rc = unsafe { vwscanf(fmt.as_ptr() as *const libc::wchar_t, std::ptr::null_mut()) };
    assert_eq!(rc, libc::EOF);

    let rc = unsafe {
        vfwscanf(
            std::ptr::null_mut(),
            fmt.as_ptr() as *const libc::wchar_t,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, libc::EOF);
}

// ── c32rtomb / mbrtoc32 ────────────────────────────────────────────────────

#[test]
fn c32rtomb_encodes_ascii() {
    let mut buf = [0i8; 4];
    let n = unsafe { c32rtomb(buf.as_mut_ptr(), b'A' as u32, std::ptr::null_mut()) };
    assert_eq!(n, 1);
    assert_eq!(buf[0] as u8, b'A');
}

#[test]
fn c32rtomb_encodes_multibyte() {
    let mut buf = [0i8; 4];
    let n = unsafe { c32rtomb(buf.as_mut_ptr(), 'é' as u32, std::ptr::null_mut()) };
    assert_eq!(n, 2);
    assert_eq!(buf[0] as u8, 0xC3);
    assert_eq!(buf[1] as u8, 0xA9);
}

#[test]
fn mbrtoc32_decodes_ascii() {
    let mut c32: u32 = 0;
    let input = [b'X' as i8];
    let n = unsafe { mbrtoc32(&mut c32, input.as_ptr(), 1, std::ptr::null_mut()) };
    assert_eq!(n, 1);
    assert_eq!(c32, b'X' as u32);
}

#[test]
fn mbrtoc32_decodes_multibyte() {
    let mut c32: u32 = 0;
    let input = [0xC3u8 as i8, 0xA9u8 as i8]; // é
    let n = unsafe { mbrtoc32(&mut c32, input.as_ptr(), 2, std::ptr::null_mut()) };
    assert_eq!(n, 2);
    assert_eq!(c32, 'é' as u32);
}

// ── c16rtomb / mbrtoc16 ────────────────────────────────────────────────────

#[test]
fn c16rtomb_encodes_bmp_char() {
    let mut buf = [0i8; 4];
    let n = unsafe { c16rtomb(buf.as_mut_ptr(), b'A' as u16, std::ptr::null_mut()) };
    assert_eq!(n, 1);
    assert_eq!(buf[0] as u8, b'A');
}

#[test]
fn mbrtoc16_decodes_ascii() {
    let mut c16: u16 = 0;
    let input = [b'X' as i8];
    let n = unsafe { mbrtoc16(&mut c16, input.as_ptr(), 1, std::ptr::null_mut()) };
    assert_eq!(n, 1);
    assert_eq!(c16, b'X' as u16);
}

// ── Locale _l conversion variants ───────────────────────────────────────────

#[test]
fn wcstol_l_null_locale_matches_base() {
    let input = wstr(b"99");
    let mut end: *mut libc::wchar_t = std::ptr::null_mut();
    let loc = std::ptr::null_mut();
    let v = unsafe { wcstol_l(input.as_ptr() as *const libc::wchar_t, &mut end, 10, loc) };
    assert_eq!(v, 99);
}

#[test]
fn wcstod_l_null_locale_matches_base() {
    let input = wstr(b"2.5");
    let mut end: *mut libc::wchar_t = std::ptr::null_mut();
    let loc = std::ptr::null_mut();
    let v = unsafe { wcstod_l(input.as_ptr() as *const libc::wchar_t, &mut end, loc) };
    assert!((v - 2.5).abs() < 1e-10);
}

// ── Existing tests (preserved) ──────────────────────────────────────────────

#[test]
fn mkstemp_creates_unique_file_and_rewrites_template() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let mut template = format!("/tmp/frankenlibc-wchar-mkstemp-{stamp}-XXXXXX\0").into_bytes();

    let fd = unsafe { mkstemp(template.as_mut_ptr().cast()) };
    assert!(fd >= 0);

    let path = unsafe { CStr::from_ptr(template.as_ptr().cast()) }
        .to_string_lossy()
        .into_owned();
    assert!(!path.ends_with("XXXXXX"));

    assert_eq!(unsafe { libc::close(fd) }, 0);
    let _ = std::fs::remove_file(path);
}

#[test]
fn realpath_resolves_existing_path_into_caller_buffer() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let base = std::env::temp_dir().join(format!("frankenlibc-realpath-{stamp}"));
    let nested = base.join("sub");
    std::fs::create_dir_all(&nested).expect("create temp test dir");
    let file = nested.join("x.txt");
    std::fs::write(&file, b"ok").expect("write temp test file");

    let input = std::ffi::CString::new(format!("{}/sub/../sub/x.txt", base.to_string_lossy()))
        .expect("path should not contain NUL");
    let expected = std::fs::canonicalize(&file).expect("canonicalize expected file");

    let mut out = vec![0_i8; 4096];
    let result = unsafe { realpath(input.as_ptr(), out.as_mut_ptr()) };
    assert_eq!(result, out.as_mut_ptr());
    assert!(!result.is_null());

    let resolved = unsafe { CStr::from_ptr(result) }
        .to_string_lossy()
        .into_owned();
    assert_eq!(resolved, expected.to_string_lossy());

    let _ = std::fs::remove_file(file);
    let _ = std::fs::remove_dir(nested);
    let _ = std::fs::remove_dir(base);
}

#[test]
fn wcsnlen_stops_at_nul_and_bound() {
    let value: [libc::wchar_t; 4] = [
        b'a' as libc::wchar_t,
        b'b' as libc::wchar_t,
        0,
        b'c' as libc::wchar_t,
    ];

    assert_eq!(unsafe { wcsnlen(value.as_ptr(), 8) }, 2);
    assert_eq!(unsafe { wcsnlen(value.as_ptr(), 1) }, 1);
}

#[test]
fn wcswidth_reports_width_and_nonprintable() {
    let printable: [libc::wchar_t; 3] = [b'A' as libc::wchar_t, 0x754c_i32, 0];
    let non_printable: [libc::wchar_t; 2] = [0x07, 0];

    assert_eq!(unsafe { wcswidth(printable.as_ptr(), 8) }, 3);
    assert_eq!(unsafe { wcswidth(printable.as_ptr(), 1) }, 1);
    assert_eq!(unsafe { wcswidth(non_printable.as_ptr(), 8) }, -1);
}

#[test]
fn wctob_and_btowc_roundtrip_ascii_only() {
    assert_eq!(unsafe { wctob(b'Z' as u32) }, b'Z' as i32);
    assert_eq!(unsafe { wctob(0x80) }, libc::EOF);
    assert_eq!(unsafe { btowc(libc::EOF) }, u32::MAX);
    assert_eq!(unsafe { btowc(b'Z' as i32) }, b'Z' as u32);
    assert_eq!(unsafe { btowc(0x80) }, u32::MAX);
}

#[test]
fn wcrtomb_encodes_ascii_and_reports_invalid() {
    let mut out = [0_i8; 4];

    let n = unsafe {
        wcrtomb(
            out.as_mut_ptr(),
            b'A' as libc::wchar_t,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(n, 1);
    assert_eq!(out[0] as u8, b'A');

    set_errno(0);
    let invalid = unsafe { wcrtomb(out.as_mut_ptr(), 0x110000_i32, std::ptr::null_mut()) };
    assert_eq!(invalid, usize::MAX);
    assert_eq!(errno_value(), libc::EILSEQ);
}

#[test]
fn mbrtowc_handles_success_incomplete_and_invalid() {
    let mut wc: libc::wchar_t = 0;
    let ascii = [b'Z' as i8];

    let ok = unsafe {
        mbrtowc(
            &mut wc as *mut libc::wchar_t,
            ascii.as_ptr(),
            ascii.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(ok, 1);
    assert_eq!(wc as u32, b'Z' as u32);

    let incomplete = [0xC3_u8 as i8];
    let short = unsafe {
        mbrtowc(
            &mut wc as *mut libc::wchar_t,
            incomplete.as_ptr(),
            incomplete.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(short, usize::MAX - 1);

    let invalid = [0xFF_u8 as i8];
    set_errno(0);
    let bad = unsafe {
        mbrtowc(
            &mut wc as *mut libc::wchar_t,
            invalid.as_ptr(),
            invalid.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(bad, usize::MAX);
    assert_eq!(errno_value(), libc::EILSEQ);
}

#[test]
fn mbsrtowcs_converts_and_updates_source_pointer() {
    let src = [0xC3_u8 as i8, 0xA9_u8 as i8, b'A' as i8, 0];
    let mut src_ptr = src.as_ptr();
    let mut dst = [0_i32; 8];

    let written = unsafe {
        mbsrtowcs(
            dst.as_mut_ptr(),
            &mut src_ptr as *mut *const i8,
            dst.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(written, 2);
    assert!(src_ptr.is_null());
    assert_eq!(dst[0] as u32, 'é' as u32);
    assert_eq!(dst[1] as u32, 'A' as u32);
}

#[test]
fn mbsrtowcs_rejects_unterminated_known_input() {
    unsafe {
        let src = malloc(2).cast::<i8>();
        assert!(!src.is_null());
        std::ptr::copy_nonoverlapping(b"AZ".as_ptr().cast::<i8>(), src, 2);

        let mut src_ptr = src as *const i8;
        let mut dst = [0_i32; 4];
        set_errno(0);
        let written = mbsrtowcs(
            dst.as_mut_ptr(),
            &mut src_ptr as *mut *const i8,
            dst.len(),
            std::ptr::null_mut(),
        );
        assert_eq!(written, usize::MAX);
        assert_eq!(errno_value(), libc::EILSEQ);
        assert_eq!(src_ptr, src as *const i8);

        free(src.cast());
    }
}

#[test]
fn wcsrtombs_converts_and_updates_source_pointer() {
    let src = [b'A' as i32, 0x754c_i32, 0];
    let mut src_ptr = src.as_ptr();
    let mut dst = [0_i8; 16];

    let written = unsafe {
        wcsrtombs(
            dst.as_mut_ptr(),
            &mut src_ptr as *mut *const i32,
            dst.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(written, 4);
    assert!(src_ptr.is_null());
    assert_eq!(dst[0] as u8, b'A');
    assert_eq!(dst[1] as u8, 0xE7);
    assert_eq!(dst[2] as u8, 0x95);
    assert_eq!(dst[3] as u8, 0x8C);
}

#[test]
fn wcstol_parses_and_updates_endptr() {
    let input: [libc::wchar_t; 6] = [
        b' ' as libc::wchar_t,
        b'-' as libc::wchar_t,
        b'1' as libc::wchar_t,
        b'2' as libc::wchar_t,
        b'x' as libc::wchar_t,
        0,
    ];
    let mut end: *mut libc::wchar_t = std::ptr::null_mut();

    let value = unsafe { wcstol(input.as_ptr(), &mut end as *mut *mut libc::wchar_t, 10) };
    assert_eq!(value, -12);
    assert_eq!(
        unsafe { end.offset_from(input.as_ptr() as *mut libc::wchar_t) },
        4
    );

    set_errno(0);
    end = std::ptr::null_mut();
    let invalid_base = unsafe { wcstol(input.as_ptr(), &mut end as *mut *mut libc::wchar_t, 1) };
    assert_eq!(invalid_base, 0);
    assert_eq!(errno_value(), libc::EINVAL);
    assert_eq!(
        unsafe { end.offset_from(input.as_ptr() as *mut libc::wchar_t) },
        0
    );
}

#[test]
fn wcstoul_reports_overflow_and_aliases_follow() {
    let digits = "18446744073709551616";
    let mut wide: Vec<libc::wchar_t> = digits.bytes().map(|b| b as libc::wchar_t).collect();
    wide.push(0);

    let mut end: *mut libc::wchar_t = std::ptr::null_mut();
    set_errno(0);
    let value = unsafe { wcstoul(wide.as_ptr(), &mut end as *mut *mut libc::wchar_t, 10) };
    assert_eq!(value as u64, u64::MAX);
    assert_eq!(errno_value(), libc::ERANGE);
    assert_eq!(
        unsafe { end.offset_from(wide.as_ptr() as *mut libc::wchar_t) },
        digits.len() as isize
    );

    end = std::ptr::null_mut();
    set_errno(0);
    let alias = unsafe { wcstoull(wide.as_ptr(), &mut end as *mut *mut libc::wchar_t, 10) };
    assert_eq!(alias, u64::MAX);
    assert_eq!(errno_value(), libc::ERANGE);
}

#[test]
fn wcstod_family_parses_ascii_and_updates_endptr() {
    let input: [libc::wchar_t; 6] = [
        b'1' as libc::wchar_t,
        b'2' as libc::wchar_t,
        b'.' as libc::wchar_t,
        b'5' as libc::wchar_t,
        b'Z' as libc::wchar_t,
        0,
    ];
    let mut end: *mut libc::wchar_t = std::ptr::null_mut();

    let d = unsafe { wcstod(input.as_ptr(), &mut end as *mut *mut libc::wchar_t) };
    assert!((d - 12.5).abs() < 1e-10);
    assert_eq!(
        unsafe { end.offset_from(input.as_ptr() as *mut libc::wchar_t) },
        4
    );

    end = std::ptr::null_mut();
    let f = unsafe { wcstof(input.as_ptr(), &mut end as *mut *mut libc::wchar_t) };
    assert!((f - 12.5_f32).abs() < 1e-5);
    assert_eq!(
        unsafe { end.offset_from(input.as_ptr() as *mut libc::wchar_t) },
        4
    );

    end = std::ptr::null_mut();
    let ld = unsafe { wcstold(input.as_ptr(), &mut end as *mut *mut libc::wchar_t) };
    assert!((ld - 12.5).abs() < 1e-10);

    let signed: [libc::wchar_t; 4] = [
        b'-' as libc::wchar_t,
        b'7' as libc::wchar_t,
        b'9' as libc::wchar_t,
        0,
    ];
    end = std::ptr::null_mut();
    let ll = unsafe { wcstoll(signed.as_ptr(), &mut end as *mut *mut libc::wchar_t, 10) };
    assert_eq!(ll, -79);
}

#[test]
fn wcscoll_and_wcsxfrm_follow_c_locale_contract() {
    let a: [libc::wchar_t; 3] = [b'a' as libc::wchar_t, b'b' as libc::wchar_t, 0];
    let b: [libc::wchar_t; 3] = [b'a' as libc::wchar_t, b'c' as libc::wchar_t, 0];

    assert!(unsafe { wcscoll(a.as_ptr(), b.as_ptr()) } < 0);
    assert!(unsafe { wcscoll(b.as_ptr(), a.as_ptr()) } > 0);
    assert_eq!(unsafe { wcscoll(a.as_ptr(), a.as_ptr()) }, 0);

    let src: [libc::wchar_t; 4] = [
        b'a' as libc::wchar_t,
        b'b' as libc::wchar_t,
        b'c' as libc::wchar_t,
        0,
    ];
    let mut dst = [0_i32; 2];
    let needed = unsafe { wcsxfrm(dst.as_mut_ptr(), src.as_ptr(), dst.len()) };
    assert_eq!(needed, 3);
    assert_eq!(dst[0] as u8, b'a');
    assert_eq!(dst[1], 0);
}

#[test]
fn wcsftime_formats_via_native_bridge() {
    let mut out = [0_i32; 32];
    let fmt: [libc::wchar_t; 9] = [
        b'%' as libc::wchar_t,
        b'Y' as libc::wchar_t,
        b'-' as libc::wchar_t,
        b'%' as libc::wchar_t,
        b'm' as libc::wchar_t,
        b'-' as libc::wchar_t,
        b'%' as libc::wchar_t,
        b'd' as libc::wchar_t,
        0,
    ];

    let tm = libc::tm {
        tm_sec: 5,
        tm_min: 4,
        tm_hour: 3,
        tm_mday: 2,
        tm_mon: 0,
        tm_year: 126,
        tm_wday: 5,
        tm_yday: 1,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: std::ptr::null(),
    };

    let written = unsafe {
        wcsftime(
            out.as_mut_ptr(),
            out.len(),
            fmt.as_ptr(),
            &tm as *const libc::tm as *const c_void,
        )
    };
    assert_eq!(written, 10);
    let rendered: Vec<u32> = out[..written].iter().map(|&ch| ch as u32).collect();
    assert_eq!(
        rendered,
        "2026-01-02".bytes().map(u32::from).collect::<Vec<_>>()
    );
}

#[test]
fn wide_stream_char_roundtrip_and_pushback() {
    let stream = unsafe { frankenlibc_abi::stdio_abi::tmpfile() };
    assert!(!stream.is_null());

    assert_eq!(unsafe { fputwc('é' as u32, stream) }, 'é' as u32);
    assert_eq!(unsafe { fputwc('A' as u32, stream) }, 'A' as u32);
    assert_eq!(
        unsafe { frankenlibc_abi::stdio_abi::fseek(stream, 0, libc::SEEK_SET) },
        0
    );

    assert_eq!(unsafe { fgetwc(stream) }, 'é' as u32);
    assert_eq!(unsafe { fgetwc(stream) }, 'A' as u32);
    assert_eq!(unsafe { fgetwc(stream) }, u32::MAX); // WEOF

    assert_eq!(
        unsafe { frankenlibc_abi::stdio_abi::fseek(stream, 0, libc::SEEK_SET) },
        0
    );
    assert_eq!(unsafe { ungetwc('Z' as u32, stream) }, 'Z' as u32);
    assert_eq!(unsafe { fgetwc(stream) }, 'Z' as u32);
    assert_eq!(unsafe { fgetwc(stream) }, 'é' as u32);

    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fclose(stream) }, 0);
}

#[test]
fn wide_stream_string_io_handles_newline_splitting() {
    let stream = unsafe { frankenlibc_abi::stdio_abi::tmpfile() };
    assert!(!stream.is_null());

    let src: [libc::wchar_t; 9] = [
        b'h' as libc::wchar_t,
        b'i' as libc::wchar_t,
        b'\n' as libc::wchar_t,
        b't' as libc::wchar_t,
        b'h' as libc::wchar_t,
        b'e' as libc::wchar_t,
        b'r' as libc::wchar_t,
        b'e' as libc::wchar_t,
        0,
    ];

    assert_eq!(unsafe { fputws(src.as_ptr(), stream) }, 0);
    assert_eq!(
        unsafe { frankenlibc_abi::stdio_abi::fseek(stream, 0, libc::SEEK_SET) },
        0
    );

    let mut buf = [0_i32; 16];
    let first = unsafe { fgetws(buf.as_mut_ptr(), buf.len() as i32, stream) };
    assert!(!first.is_null());
    let first_len = buf.iter().position(|&ch| ch == 0).unwrap_or(buf.len());
    let first_text: Vec<u8> = buf[..first_len].iter().map(|&ch| ch as u8).collect();
    assert_eq!(first_text, b"hi\n");

    buf.fill(0);
    let second = unsafe { fgetws(buf.as_mut_ptr(), buf.len() as i32, stream) };
    assert!(!second.is_null());
    let second_len = buf.iter().position(|&ch| ch == 0).unwrap_or(buf.len());
    let second_text: Vec<u8> = buf[..second_len].iter().map(|&ch| ch as u8).collect();
    assert_eq!(second_text, b"there");

    assert!(unsafe { fgetws(buf.as_mut_ptr(), buf.len() as i32, stream) }.is_null());

    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fclose(stream) }, 0);
}

#[test]
fn open_wmemstream_flushes_wide_buffer_and_reports_orientation() {
    let mut buf: *mut u32 = std::ptr::null_mut();
    let mut size = 0usize;
    let stream = unsafe { open_wmemstream(&mut buf, &mut size) };
    assert!(!stream.is_null());
    assert!(!buf.is_null());
    assert_eq!(size, 0);
    assert!(verify_native_file(stream).is_some());
    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fileno(stream) }, -1);

    assert!(unsafe { fwide(stream, 0) } > 0);
    assert!(unsafe { fwide(stream, -1) } > 0);

    assert_eq!(unsafe { fputwc('é' as u32, stream) }, 'é' as u32);
    assert_eq!(unsafe { fputwc('A' as u32, stream) }, 'A' as u32);
    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fflush(stream) }, 0);

    assert_eq!(size, 2);
    let written = unsafe { std::slice::from_raw_parts(buf, size + 1) };
    assert_eq!(written[0], 'é' as u32);
    assert_eq!(written[1], 'A' as u32);
    assert_eq!(written[2], 0);

    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fclose(stream) }, 0);
    assert!(verify_native_file(stream).is_none());
    assert_eq!(size, 2);
    let written = unsafe { std::slice::from_raw_parts(buf, size + 1) };
    assert_eq!(written[0], 'é' as u32);
    assert_eq!(written[1], 'A' as u32);
    assert_eq!(written[2], 0);

    unsafe { frankenlibc_abi::malloc_abi::free(buf.cast::<c_void>()) };
}
