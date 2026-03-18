#![cfg(target_os = "linux")]

//! Integration tests for `<ctype.h>` ABI entrypoints.
//!
//! Tests cover: character classification (isalpha, isdigit, etc.),
//! case conversion (toupper, tolower), ctype table accessors,
//! locale-aware variants, and glibc internal __is*_l aliases.

use std::ffi::c_int;

use frankenlibc_abi::ctype_abi::*;

// ===========================================================================
// Character classification: isalpha, isdigit, isalnum, etc.
// ===========================================================================

#[test]
fn isalpha_letters_only() {
    assert_ne!(unsafe { isalpha(b'A' as c_int) }, 0);
    assert_ne!(unsafe { isalpha(b'Z' as c_int) }, 0);
    assert_ne!(unsafe { isalpha(b'a' as c_int) }, 0);
    assert_ne!(unsafe { isalpha(b'z' as c_int) }, 0);
    assert_eq!(unsafe { isalpha(b'0' as c_int) }, 0);
    assert_eq!(unsafe { isalpha(b' ' as c_int) }, 0);
    assert_eq!(unsafe { isalpha(b'!' as c_int) }, 0);
}

#[test]
fn isdigit_digits_only() {
    for d in b'0'..=b'9' {
        assert_ne!(
            unsafe { isdigit(d as c_int) },
            0,
            "isdigit('{}')",
            d as char
        );
    }
    assert_eq!(unsafe { isdigit(b'a' as c_int) }, 0);
    assert_eq!(unsafe { isdigit(b'A' as c_int) }, 0);
    assert_eq!(unsafe { isdigit(b' ' as c_int) }, 0);
}

#[test]
fn isalnum_letters_and_digits() {
    assert_ne!(unsafe { isalnum(b'A' as c_int) }, 0);
    assert_ne!(unsafe { isalnum(b'z' as c_int) }, 0);
    assert_ne!(unsafe { isalnum(b'5' as c_int) }, 0);
    assert_eq!(unsafe { isalnum(b'!' as c_int) }, 0);
    assert_eq!(unsafe { isalnum(b' ' as c_int) }, 0);
}

#[test]
fn isspace_whitespace() {
    assert_ne!(unsafe { isspace(b' ' as c_int) }, 0);
    assert_ne!(unsafe { isspace(b'\t' as c_int) }, 0);
    assert_ne!(unsafe { isspace(b'\n' as c_int) }, 0);
    assert_ne!(unsafe { isspace(b'\r' as c_int) }, 0);
    assert_ne!(unsafe { isspace(b'\x0C' as c_int) }, 0); // form feed
    assert_ne!(unsafe { isspace(b'\x0B' as c_int) }, 0); // vertical tab
    assert_eq!(unsafe { isspace(b'a' as c_int) }, 0);
    assert_eq!(unsafe { isspace(b'0' as c_int) }, 0);
}

#[test]
fn isupper_and_islower() {
    for c in b'A'..=b'Z' {
        assert_ne!(unsafe { isupper(c as c_int) }, 0);
        assert_eq!(unsafe { islower(c as c_int) }, 0);
    }
    for c in b'a'..=b'z' {
        assert_eq!(unsafe { isupper(c as c_int) }, 0);
        assert_ne!(unsafe { islower(c as c_int) }, 0);
    }
}

#[test]
fn isprint_and_isgraph() {
    // Space is printable but not graphical
    assert_ne!(unsafe { isprint(b' ' as c_int) }, 0);
    assert_eq!(unsafe { isgraph(b' ' as c_int) }, 0);

    // Letters are both
    assert_ne!(unsafe { isprint(b'A' as c_int) }, 0);
    assert_ne!(unsafe { isgraph(b'A' as c_int) }, 0);

    // Control characters are neither
    assert_eq!(unsafe { isprint(0x01) }, 0);
    assert_eq!(unsafe { isgraph(0x01) }, 0);
}

#[test]
fn ispunct_punctuation() {
    assert_ne!(unsafe { ispunct(b'!' as c_int) }, 0);
    assert_ne!(unsafe { ispunct(b'.' as c_int) }, 0);
    assert_ne!(unsafe { ispunct(b'@' as c_int) }, 0);
    assert_eq!(unsafe { ispunct(b'A' as c_int) }, 0);
    assert_eq!(unsafe { ispunct(b'0' as c_int) }, 0);
    assert_eq!(unsafe { ispunct(b' ' as c_int) }, 0);
}

#[test]
fn isxdigit_hex() {
    for c in b'0'..=b'9' {
        assert_ne!(unsafe { isxdigit(c as c_int) }, 0);
    }
    for c in b'a'..=b'f' {
        assert_ne!(unsafe { isxdigit(c as c_int) }, 0);
    }
    for c in b'A'..=b'F' {
        assert_ne!(unsafe { isxdigit(c as c_int) }, 0);
    }
    assert_eq!(unsafe { isxdigit(b'g' as c_int) }, 0);
    assert_eq!(unsafe { isxdigit(b'G' as c_int) }, 0);
}

#[test]
fn isblank_tab_and_space() {
    assert_ne!(unsafe { isblank(b' ' as c_int) }, 0);
    assert_ne!(unsafe { isblank(b'\t' as c_int) }, 0);
    assert_eq!(unsafe { isblank(b'\n' as c_int) }, 0);
    assert_eq!(unsafe { isblank(b'a' as c_int) }, 0);
}

#[test]
fn iscntrl_control_chars() {
    assert_ne!(unsafe { iscntrl(0x00) }, 0); // NUL
    assert_ne!(unsafe { iscntrl(0x1F) }, 0); // US
    assert_ne!(unsafe { iscntrl(0x7F) }, 0); // DEL
    assert_eq!(unsafe { iscntrl(b'A' as c_int) }, 0);
    assert_eq!(unsafe { iscntrl(b' ' as c_int) }, 0);
}

// ===========================================================================
// Case conversion: toupper, tolower
// ===========================================================================

#[test]
fn toupper_conversion() {
    assert_eq!(unsafe { toupper(b'a' as c_int) }, b'A' as c_int);
    assert_eq!(unsafe { toupper(b'z' as c_int) }, b'Z' as c_int);
    assert_eq!(unsafe { toupper(b'A' as c_int) }, b'A' as c_int); // already upper
    assert_eq!(unsafe { toupper(b'0' as c_int) }, b'0' as c_int); // non-alpha unchanged
}

#[test]
fn tolower_conversion() {
    assert_eq!(unsafe { tolower(b'A' as c_int) }, b'a' as c_int);
    assert_eq!(unsafe { tolower(b'Z' as c_int) }, b'z' as c_int);
    assert_eq!(unsafe { tolower(b'a' as c_int) }, b'a' as c_int); // already lower
    assert_eq!(unsafe { tolower(b'0' as c_int) }, b'0' as c_int); // non-alpha unchanged
}

// ===========================================================================
// isascii / toascii
// ===========================================================================

#[test]
fn isascii_range() {
    assert_ne!(unsafe { isascii(0) }, 0);
    assert_ne!(unsafe { isascii(127) }, 0);
    assert_eq!(unsafe { isascii(128) }, 0);
    assert_eq!(unsafe { isascii(255) }, 0);
    assert_eq!(unsafe { isascii(-1) }, 0);
}

#[test]
fn toascii_masks() {
    assert_eq!(unsafe { toascii(0x41) }, 0x41); // 'A'
    assert_eq!(unsafe { toascii(0xC1) }, 0x41); // high bit stripped
    assert_eq!(unsafe { toascii(0xFF) }, 0x7F);
}

// ===========================================================================
// Out-of-range inputs
// ===========================================================================

#[test]
fn classify_out_of_range() {
    assert_eq!(unsafe { isalpha(-1) }, 0);
    assert_eq!(unsafe { isalpha(256) }, 0);
    assert_eq!(unsafe { isdigit(-1) }, 0);
    assert_eq!(unsafe { isdigit(256) }, 0);
}

#[test]
fn convert_out_of_range_passthrough() {
    assert_eq!(unsafe { toupper(-1) }, -1);
    assert_eq!(unsafe { toupper(256) }, 256);
    assert_eq!(unsafe { tolower(-1) }, -1);
    assert_eq!(unsafe { tolower(256) }, 256);
}

// ===========================================================================
// ctype table accessors
// ===========================================================================

#[test]
fn ctype_b_loc_returns_valid_table() {
    let pp = unsafe { __ctype_b_loc() };
    assert!(!pp.is_null());

    let p = unsafe { *pp };
    assert!(!p.is_null());

    // 'A' (65) should have alpha + upper + print + graph + alnum bits set
    let flags = unsafe { *p.offset(b'A' as isize) };
    assert_ne!(flags & (1 << 0), 0, "'A' should have UPPER bit"); // _ISUPPER
    assert_ne!(flags & (1 << 2), 0, "'A' should have ALPHA bit"); // _ISALPHA
}

#[test]
fn ctype_toupper_loc_returns_valid_table() {
    let pp = unsafe { __ctype_toupper_loc() };
    assert!(!pp.is_null());

    let p = unsafe { *pp };
    assert!(!p.is_null());

    assert_eq!(unsafe { *p.offset(b'a' as isize) }, b'A' as i32);
    assert_eq!(unsafe { *p.offset(b'A' as isize) }, b'A' as i32);
}

#[test]
fn ctype_tolower_loc_returns_valid_table() {
    let pp = unsafe { __ctype_tolower_loc() };
    assert!(!pp.is_null());

    let p = unsafe { *pp };
    assert!(!p.is_null());

    assert_eq!(unsafe { *p.offset(b'A' as isize) }, b'a' as i32);
    assert_eq!(unsafe { *p.offset(b'a' as isize) }, b'a' as i32);
}

// ===========================================================================
// Locale-aware _l variants (C locale passthrough)
// ===========================================================================

#[test]
fn locale_variants_match_base() {
    let locale = std::ptr::null_mut();
    for c in 0..=127i32 {
        assert_eq!(
            unsafe { isalpha_l(c, locale) },
            unsafe { isalpha(c) },
            "isalpha_l mismatch at c={c}"
        );
        assert_eq!(
            unsafe { isdigit_l(c, locale) },
            unsafe { isdigit(c) },
            "isdigit_l mismatch at c={c}"
        );
        assert_eq!(
            unsafe { toupper_l(c, locale) },
            unsafe { toupper(c) },
            "toupper_l mismatch at c={c}"
        );
        assert_eq!(
            unsafe { tolower_l(c, locale) },
            unsafe { tolower(c) },
            "tolower_l mismatch at c={c}"
        );
    }
}

#[test]
fn locale_alnum_l_matches_base() {
    let locale = std::ptr::null_mut();
    for c in 0..=127i32 {
        assert_eq!(
            unsafe { isalnum_l(c, locale) },
            unsafe { isalnum(c) },
            "isalnum_l mismatch at c={c}"
        );
    }
}

#[test]
fn locale_space_l_matches_base() {
    let locale = std::ptr::null_mut();
    for c in 0..=127i32 {
        assert_eq!(
            unsafe { isspace_l(c, locale) },
            unsafe { isspace(c) },
            "isspace_l mismatch at c={c}"
        );
    }
}

#[test]
fn locale_upper_lower_l_matches_base() {
    let locale = std::ptr::null_mut();
    for c in 0..=127i32 {
        assert_eq!(
            unsafe { isupper_l(c, locale) },
            unsafe { isupper(c) },
            "isupper_l mismatch at c={c}"
        );
        assert_eq!(
            unsafe { islower_l(c, locale) },
            unsafe { islower(c) },
            "islower_l mismatch at c={c}"
        );
    }
}

#[test]
fn locale_print_graph_l_matches_base() {
    let locale = std::ptr::null_mut();
    for c in 0..=127i32 {
        assert_eq!(
            unsafe { isprint_l(c, locale) },
            unsafe { isprint(c) },
            "isprint_l mismatch at c={c}"
        );
        assert_eq!(
            unsafe { isgraph_l(c, locale) },
            unsafe { isgraph(c) },
            "isgraph_l mismatch at c={c}"
        );
    }
}

#[test]
fn locale_punct_xdigit_l_matches_base() {
    let locale = std::ptr::null_mut();
    for c in 0..=127i32 {
        assert_eq!(
            unsafe { ispunct_l(c, locale) },
            unsafe { ispunct(c) },
            "ispunct_l mismatch at c={c}"
        );
        assert_eq!(
            unsafe { isxdigit_l(c, locale) },
            unsafe { isxdigit(c) },
            "isxdigit_l mismatch at c={c}"
        );
    }
}

#[test]
fn locale_blank_cntrl_l_matches_base() {
    let locale = std::ptr::null_mut();
    for c in 0..=127i32 {
        assert_eq!(
            unsafe { isblank_l(c, locale) },
            unsafe { isblank(c) },
            "isblank_l mismatch at c={c}"
        );
        assert_eq!(
            unsafe { iscntrl_l(c, locale) },
            unsafe { iscntrl(c) },
            "iscntrl_l mismatch at c={c}"
        );
    }
}

// ===========================================================================
// Double-underscore __is*_l aliases
// ===========================================================================

#[test]
fn double_underscore_aliases_match() {
    let locale = std::ptr::null_mut();
    assert_eq!(unsafe { __isalnum_l(b'5' as c_int, locale) }, unsafe {
        isalnum_l(b'5' as c_int, locale)
    });
    assert_eq!(unsafe { __isalpha_l(b'A' as c_int, locale) }, unsafe {
        isalpha_l(b'A' as c_int, locale)
    });
    assert_eq!(unsafe { __isascii_l(0x80, locale) }, 0);
    assert_eq!(unsafe { __isascii_l(0x41, locale) }, 1);
    assert_eq!(unsafe { __toascii_l(0xFF, locale) }, 0x7F);
    assert_eq!(unsafe { __toupper_l(b'a' as c_int, locale) }, b'A' as c_int);
    assert_eq!(unsafe { __tolower_l(b'A' as c_int, locale) }, b'a' as c_int);
}

#[test]
fn double_underscore_classification_sweep() {
    let locale = std::ptr::null_mut();
    for c in 0..=127i32 {
        assert_eq!(
            unsafe { __isblank_l(c, locale) },
            unsafe { isblank_l(c, locale) },
            "__isblank_l mismatch at c={c}"
        );
        assert_eq!(
            unsafe { __iscntrl_l(c, locale) },
            unsafe { iscntrl_l(c, locale) },
            "__iscntrl_l mismatch at c={c}"
        );
        assert_eq!(
            unsafe { __isdigit_l(c, locale) },
            unsafe { isdigit_l(c, locale) },
            "__isdigit_l mismatch at c={c}"
        );
        assert_eq!(
            unsafe { __isgraph_l(c, locale) },
            unsafe { isgraph_l(c, locale) },
            "__isgraph_l mismatch at c={c}"
        );
        assert_eq!(
            unsafe { __islower_l(c, locale) },
            unsafe { islower_l(c, locale) },
            "__islower_l mismatch at c={c}"
        );
        assert_eq!(
            unsafe { __isprint_l(c, locale) },
            unsafe { isprint_l(c, locale) },
            "__isprint_l mismatch at c={c}"
        );
        assert_eq!(
            unsafe { __ispunct_l(c, locale) },
            unsafe { ispunct_l(c, locale) },
            "__ispunct_l mismatch at c={c}"
        );
        assert_eq!(
            unsafe { __isspace_l(c, locale) },
            unsafe { isspace_l(c, locale) },
            "__isspace_l mismatch at c={c}"
        );
        assert_eq!(
            unsafe { __isupper_l(c, locale) },
            unsafe { isupper_l(c, locale) },
            "__isupper_l mismatch at c={c}"
        );
        assert_eq!(
            unsafe { __isxdigit_l(c, locale) },
            unsafe { isxdigit_l(c, locale) },
            "__isxdigit_l mismatch at c={c}"
        );
    }
}

// ===========================================================================
// EOF handling: -1 (EOF) should classify as false for all
// ===========================================================================

#[test]
fn eof_classifies_as_false() {
    let eof: c_int = -1;
    assert_eq!(unsafe { isalpha(eof) }, 0, "isalpha(EOF)");
    assert_eq!(unsafe { isdigit(eof) }, 0, "isdigit(EOF)");
    assert_eq!(unsafe { isalnum(eof) }, 0, "isalnum(EOF)");
    assert_eq!(unsafe { isspace(eof) }, 0, "isspace(EOF)");
    assert_eq!(unsafe { isupper(eof) }, 0, "isupper(EOF)");
    assert_eq!(unsafe { islower(eof) }, 0, "islower(EOF)");
    assert_eq!(unsafe { isprint(eof) }, 0, "isprint(EOF)");
    assert_eq!(unsafe { isgraph(eof) }, 0, "isgraph(EOF)");
    assert_eq!(unsafe { ispunct(eof) }, 0, "ispunct(EOF)");
    assert_eq!(unsafe { isxdigit(eof) }, 0, "isxdigit(EOF)");
    assert_eq!(unsafe { isblank(eof) }, 0, "isblank(EOF)");
    assert_eq!(unsafe { iscntrl(eof) }, 0, "iscntrl(EOF)");
}

// ===========================================================================
// toupper/tolower full alphabet round-trip
// ===========================================================================

#[test]
fn toupper_tolower_round_trip() {
    for c in b'a'..=b'z' {
        let upper = unsafe { toupper(c as c_int) };
        let back = unsafe { tolower(upper) };
        assert_eq!(back, c as c_int, "round-trip failed for '{}'", c as char);
    }
}

#[test]
fn tolower_toupper_round_trip() {
    for c in b'A'..=b'Z' {
        let lower = unsafe { tolower(c as c_int) };
        let back = unsafe { toupper(lower) };
        assert_eq!(back, c as c_int, "round-trip failed for '{}'", c as char);
    }
}

// ===========================================================================
// Boundary characters
// ===========================================================================

#[test]
fn nul_is_control() {
    assert_ne!(unsafe { iscntrl(0) }, 0, "NUL should be control");
    assert_eq!(unsafe { isprint(0) }, 0, "NUL should not be printable");
}

#[test]
fn del_is_control() {
    assert_ne!(unsafe { iscntrl(0x7F) }, 0, "DEL should be control");
    assert_eq!(unsafe { isprint(0x7F) }, 0, "DEL should not be printable");
}

#[test]
fn all_control_chars_classified() {
    // 0x00-0x1F and 0x7F are control characters
    for c in 0..=0x1F {
        assert_ne!(unsafe { iscntrl(c) }, 0, "0x{c:02X} should be control");
    }
    assert_ne!(unsafe { iscntrl(0x7F) }, 0, "0x7F should be control");
}

// ===========================================================================
// Table accessor for digits
// ===========================================================================

#[test]
fn ctype_b_loc_digit_bits() {
    let pp = unsafe { __ctype_b_loc() };
    let p = unsafe { *pp };
    for d in b'0'..=b'9' {
        let flags = unsafe { *p.offset(d as isize) };
        // Digit bit should be set (bit position varies by glibc version, just check non-zero classification)
        assert_ne!(
            flags, 0,
            "digit '{}' should have classification bits",
            d as char
        );
    }
}

#[test]
fn ctype_toupper_loc_non_alpha_passthrough() {
    let pp = unsafe { __ctype_toupper_loc() };
    let p = unsafe { *pp };
    // Digits and punctuation should map to themselves
    for c in b'0'..=b'9' {
        assert_eq!(
            unsafe { *p.offset(c as isize) },
            c as i32,
            "toupper table should pass through '{}'",
            c as char
        );
    }
}

#[test]
fn ctype_tolower_loc_non_alpha_passthrough() {
    let pp = unsafe { __ctype_tolower_loc() };
    let p = unsafe { *pp };
    for c in b'0'..=b'9' {
        assert_eq!(
            unsafe { *p.offset(c as isize) },
            c as i32,
            "tolower table should pass through '{}'",
            c as char
        );
    }
}

// ===========================================================================
// Comprehensive sweep: all printable ASCII
// ===========================================================================

#[test]
fn all_ascii_classification_consistency() {
    for c in 0..=127i32 {
        let alpha = unsafe { isalpha(c) } != 0;
        let digit = unsafe { isdigit(c) } != 0;
        let alnum = unsafe { isalnum(c) } != 0;
        let upper = unsafe { isupper(c) } != 0;
        let lower = unsafe { islower(c) } != 0;
        let print = unsafe { isprint(c) } != 0;
        let graph = unsafe { isgraph(c) } != 0;
        let cntrl = unsafe { iscntrl(c) } != 0;
        let space = unsafe { isspace(c) } != 0;

        // isalnum == isalpha || isdigit
        assert_eq!(alnum, alpha || digit, "alnum inconsistency at c={c}");
        // isalpha == isupper || islower
        assert_eq!(alpha, upper || lower, "alpha inconsistency at c={c}");
        // isgraph implies isprint (but not vice versa — space is print but not graph)
        if graph {
            assert!(print, "graph implies print at c={c}");
        }
        // iscntrl and isprint are mutually exclusive
        assert!(!(cntrl && print), "cntrl and print are exclusive at c={c}");
        // Space is not a control character (in our POSIX locale)
        if c == b' ' as i32 {
            assert!(space, "space should be space");
            assert!(print, "space should be printable");
        }
    }
}
