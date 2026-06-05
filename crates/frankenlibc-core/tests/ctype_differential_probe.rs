//! Differential probe: frankenlibc ctype classifiers + case conversion vs glibc
//! over the full 0..=255 byte range. The reference formulas are the canonical
//! C-locale ctype definitions, which were verified to match glibc exactly for
//! all 256 values + toupper/tolower via a C probe (0 mismatches). Catches
//! boundary bugs (0x7F DEL, control range, isgraph vs isprint, ispunct
//! boundaries, isxdigit a-f/A-F, isblank).

use frankenlibc_core::ctype::{
    is_alnum, is_alpha, is_blank, is_cntrl, is_digit, is_graph, is_lower, is_print, is_punct,
    is_space, is_upper, is_xdigit, to_lower, to_upper,
};

// Canonical C-locale references (== glibc, verified for all 0..=255).
fn r_digit(c: u8) -> bool {
    c.is_ascii_digit()
}
fn r_upper(c: u8) -> bool {
    c.is_ascii_uppercase()
}
fn r_lower(c: u8) -> bool {
    c.is_ascii_lowercase()
}
fn r_alpha(c: u8) -> bool {
    r_upper(c) || r_lower(c)
}
fn r_alnum(c: u8) -> bool {
    r_alpha(c) || r_digit(c)
}
fn r_xdigit(c: u8) -> bool {
    c.is_ascii_hexdigit()
}
fn r_space(c: u8) -> bool {
    c == b' ' || (9..=13).contains(&c)
}
fn r_blank(c: u8) -> bool {
    c == b' ' || c == 9
}
fn r_cntrl(c: u8) -> bool {
    c <= 0x1f || c == 0x7f
}
fn r_print(c: u8) -> bool {
    (0x20..=0x7e).contains(&c)
}
fn r_graph(c: u8) -> bool {
    (0x21..=0x7e).contains(&c)
}
fn r_punct(c: u8) -> bool {
    r_graph(c) && !r_alnum(c)
}
fn r_toupper(c: u8) -> u8 {
    if r_lower(c) { c - 0x20 } else { c }
}
fn r_tolower(c: u8) -> u8 {
    if r_upper(c) { c + 0x20 } else { c }
}

#[test]
fn ctype_differential_full_range() {
    let mut diffs = Vec::new();
    for c in 0u8..=255 {
        let checks: &[(&str, bool, bool)] = &[
            ("isalpha", is_alpha(c), r_alpha(c)),
            ("isdigit", is_digit(c), r_digit(c)),
            ("isalnum", is_alnum(c), r_alnum(c)),
            ("isspace", is_space(c), r_space(c)),
            ("isupper", is_upper(c), r_upper(c)),
            ("islower", is_lower(c), r_lower(c)),
            ("isprint", is_print(c), r_print(c)),
            ("ispunct", is_punct(c), r_punct(c)),
            ("isxdigit", is_xdigit(c), r_xdigit(c)),
            ("isblank", is_blank(c), r_blank(c)),
            ("iscntrl", is_cntrl(c), r_cntrl(c)),
            ("isgraph", is_graph(c), r_graph(c)),
        ];
        for (name, got, exp) in checks {
            if got != exp {
                diffs.push(format!("{name}(0x{c:02x}): frankenlibc={got} glibc={exp}"));
            }
        }
        if to_upper(c) != r_toupper(c) {
            diffs.push(format!(
                "toupper(0x{c:02x}): frankenlibc=0x{:02x} glibc=0x{:02x}",
                to_upper(c),
                r_toupper(c)
            ));
        }
        if to_lower(c) != r_tolower(c) {
            diffs.push(format!(
                "tolower(0x{c:02x}): frankenlibc=0x{:02x} glibc=0x{:02x}",
                to_lower(c),
                r_tolower(c)
            ));
        }
    }
    assert!(
        diffs.is_empty(),
        "ctype diverges from glibc (C locale) in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
