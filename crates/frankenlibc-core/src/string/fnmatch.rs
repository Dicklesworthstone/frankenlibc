//! POSIX `<fnmatch.h>` shell-pattern matcher.
//!
//! Pure-safe Rust port of the engine that previously lived in
//! frankenlibc-abi/src/string_abi.rs. Operates on `&[u8]` slices —
//! the abi layer adapts NUL-terminated C strings via
//! `CStr::to_bytes()`.
//!
//! Supported pattern syntax: literal bytes, `?`, `*`, bracket expressions
//! with optional ranges and `!`/`^` negation, POSIX character classes
//! (`[:alpha:]` …), collating elements (`[.x.]`) and equivalence classes
//! (`[=x=]`), and `\X` escapes unless [`FnmatchFlags::NOESCAPE`] is set.
//!
//! Flag bits match POSIX/glibc `<fnmatch.h>` so the abi layer can pass
//! the user's `c_int` flags through unchanged.

/// Pattern-match flags, bit-compatible with POSIX `<fnmatch.h>`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FnmatchFlags {
    bits: u32,
}

impl FnmatchFlags {
    pub const NONE: FnmatchFlags = FnmatchFlags { bits: 0 };
    /// `*` and `?` do not match `/`; leading `.` after `/` requires
    /// explicit match when [`PERIOD`](Self::PERIOD) is also set.
    pub const PATHNAME: FnmatchFlags = FnmatchFlags { bits: 1 << 0 };
    /// Backslash is literal (no escape semantics).
    pub const NOESCAPE: FnmatchFlags = FnmatchFlags { bits: 1 << 1 };
    /// Leading `.` in `text` (or after `/` if PATHNAME) must be matched
    /// explicitly, never by `*`/`?`/bracket.
    pub const PERIOD: FnmatchFlags = FnmatchFlags { bits: 1 << 2 };
    /// GNU: pattern matches a leading directory prefix of `text`.
    pub const LEADING_DIR: FnmatchFlags = FnmatchFlags { bits: 1 << 3 };
    /// GNU: case-insensitive ASCII matching.
    pub const CASEFOLD: FnmatchFlags = FnmatchFlags { bits: 1 << 4 };

    pub const fn from_bits(b: u32) -> Self {
        FnmatchFlags { bits: b }
    }

    pub const fn bits(self) -> u32 {
        self.bits
    }

    pub const fn contains(self, other: FnmatchFlags) -> bool {
        (self.bits & other.bits) == other.bits
    }
}

impl core::ops::BitOr for FnmatchFlags {
    type Output = FnmatchFlags;
    fn bitor(self, rhs: FnmatchFlags) -> FnmatchFlags {
        FnmatchFlags {
            bits: self.bits | rhs.bits,
        }
    }
}

impl core::ops::BitOrAssign for FnmatchFlags {
    fn bitor_assign(&mut self, rhs: FnmatchFlags) {
        self.bits |= rhs.bits;
    }
}

/// Pre-classification of a `[...]` bracket expression. POSIX leaves
/// unterminated bracket behavior implementation-defined; this matches
/// glibc.
///
/// `Terminated`: closed `]` found, parse as bracket.
/// `LiteralFallback`: unterminated, treat the leading `[` as a literal.
/// `Invalid`: unterminated with a final *unescaped* `-` content byte
/// (an incomplete range); match fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BracketShape {
    Terminated,
    LiteralFallback,
    Invalid,
}

fn classify_bracket(pat: &[u8], pi: usize, noescape: bool) -> BracketShape {
    let mut scan = pi + 1; // skip the opening '['
    if let Some(&b'!') | Some(&b'^') = pat.get(scan) {
        scan += 1;
    }
    let mut content_count = 0usize;
    let mut last_was_dash = false;
    loop {
        let bc = match pat.get(scan) {
            None => {
                if last_was_dash && content_count > 1 {
                    return BracketShape::Invalid;
                }
                return BracketShape::LiteralFallback;
            }
            Some(&b) => b,
        };
        // POSIX: `]` as the first content byte (after optional !/^)
        // is literal, not a closer — gated by content_count > 0.
        if bc == b']' && content_count > 0 {
            return BracketShape::Terminated;
        }
        // An escaped byte (`\X`) is one literal content element; the
        // bracket parser consumes it as such, so the classifier must
        // too. Without this an escaped trailing `-` (`[a\-`) is misread
        // as an incomplete range (`Invalid`) when it is actually a
        // literal dash — glibc treats the unterminated bracket as a
        // literal `[` there and the pattern still matches.
        if bc == b'\\' && !noescape && scan + 1 < pat.len() {
            content_count += 1;
            last_was_dash = false;
            scan += 2;
            continue;
        }
        last_was_dash = bc == b'-';
        content_count += 1;
        scan += 1;
    }
}

/// ASCII case-swap (`A`↔`a`); other bytes are returned unchanged. Used so
/// [`posix_class_match`] can honor [`FnmatchFlags::CASEFOLD`] for the
/// `[:upper:]` / `[:lower:]` classes.
fn swap_ascii_case(c: u8) -> u8 {
    if c.is_ascii_uppercase() {
        c.to_ascii_lowercase()
    } else if c.is_ascii_lowercase() {
        c.to_ascii_uppercase()
    } else {
        c
    }
}

/// Test `c` against a POSIX named character class. Returns `None` when
/// `name` is not one of the twelve POSIX classes — the caller then treats
/// the enclosing `[` as a literal byte.
fn posix_class_match(name: &[u8], c: u8) -> Option<bool> {
    let hit = match name {
        b"alpha" => c.is_ascii_alphabetic(),
        b"digit" => c.is_ascii_digit(),
        b"alnum" => c.is_ascii_alphanumeric(),
        b"upper" => c.is_ascii_uppercase(),
        b"lower" => c.is_ascii_lowercase(),
        // POSIX `space`: ' ' \t \n \v \f \r  (0x20 and 0x09..=0x0d).
        b"space" => c == b' ' || (b'\t'..=b'\r').contains(&c),
        b"blank" => c == b' ' || c == b'\t',
        b"print" => c.is_ascii_graphic() || c == b' ',
        b"graph" => c.is_ascii_graphic(),
        b"cntrl" => c.is_ascii_control(),
        b"punct" => c.is_ascii_punctuation(),
        b"xdigit" => c.is_ascii_hexdigit(),
        _ => return None,
    };
    Some(hit)
}

/// Parse a POSIX bracket sub-expression that begins at `pat[open] == b'['`
/// with `pat[open + 1] == kind` — `:` (character class), `.` (collating
/// element), or `=` (equivalence class).
///
/// On success returns `(next_pi, member)` where `next_pi` is the index just
/// past the closing `]` and `member` reports whether `c` belongs to the
/// sub-expression. Returns `None` only when the sub-expression is not even
/// structurally closed (no `kind]` terminator); the caller then treats the
/// leading `[` as an ordinary literal byte. A structurally-closed but
/// unrecognized sub-expression (unknown class name, multi-byte collating
/// element) is consumed and matches nothing — as glibc rejects it too.
fn parse_bracket_subexpr(
    pat: &[u8],
    open: usize,
    kind: u8,
    c: u8,
    casefold: bool,
) -> Option<(usize, bool)> {
    let content_start = open + 2;
    let mut j = content_start;
    loop {
        let b = *pat.get(j)?;
        if b == kind && pat.get(j + 1) == Some(&b']') {
            break;
        }
        j += 1;
    }
    let content = &pat[content_start..j];
    let next_pi = j + 2; // index just past `kind` and `]`
    let member = match kind {
        // Character class. An unrecognized class name is a well-formed
        // sub-expression that matches nothing.
        b':' => match posix_class_match(content, c) {
            Some(true) => true,
            Some(false) => casefold && posix_class_match(content, swap_ascii_case(c)) == Some(true),
            None => false,
        },
        // Collating element / equivalence class. The C locale has only
        // single-byte elements; anything else matches nothing.
        b'.' | b'=' => {
            content.len() == 1
                && if casefold {
                    content[0].eq_ignore_ascii_case(&c)
                } else {
                    content[0] == c
                }
        }
        _ => return None,
    };
    Some((next_pi, member))
}

/// Match `text` against `pattern` per POSIX fnmatch semantics + the
/// flags. Returns `true` if the entire `text` matches (modulo
/// [`FnmatchFlags::LEADING_DIR`]).
pub fn fnmatch_match(pattern: &[u8], text: &[u8], flags: FnmatchFlags) -> bool {
    fnmatch_inner(pattern, 0, text, 0, flags, true)
}

fn fnmatch_inner(
    pat: &[u8],
    mut pi: usize,
    text: &[u8],
    mut si: usize,
    flags: FnmatchFlags,
    at_start_in: bool,
) -> bool {
    let pathname = flags.contains(FnmatchFlags::PATHNAME);
    let period = flags.contains(FnmatchFlags::PERIOD);
    let noescape = flags.contains(FnmatchFlags::NOESCAPE);
    let casefold = flags.contains(FnmatchFlags::CASEFOLD);
    let leading_dir = flags.contains(FnmatchFlags::LEADING_DIR);
    let mut at_start = at_start_in;

    loop {
        let pc = pat.get(pi).copied();
        let sc = text.get(si).copied();

        // Pattern exhausted.
        if pc.is_none() {
            if sc.is_none() {
                return true;
            }
            // GNU FNM_LEADING_DIR: pattern matched a prefix; if the
            // remainder of `text` starts with '/', accept.
            if leading_dir && sc == Some(b'/') {
                return true;
            }
            return false;
        }
        let pc = pc.unwrap();

        // Helper: is the current text position considered "at-start"
        // for leading-period purposes?
        let leading_period_blocked = |c: u8, si: usize| -> bool {
            period
                && c == b'.'
                && (at_start || (pathname && si > 0 && text.get(si - 1) == Some(&b'/')))
        };

        match pc {
            b'?' => {
                let c = match sc {
                    None => return false,
                    Some(c) => c,
                };
                if pathname && c == b'/' {
                    return false;
                }
                if leading_period_blocked(c, si) {
                    return false;
                }
                pi += 1;
                si += 1;
                at_start = false;
            }
            b'*' => {
                // Skip consecutive '*'s
                while pat.get(pi) == Some(&b'*') {
                    pi += 1;
                }

                if let Some(c) = sc
                    && leading_period_blocked(c, si)
                {
                    return false;
                }

                // If pattern is exhausted after the '*', match the rest.
                if pi >= pat.len() {
                    if pathname {
                        // Disallow matching '/' under PATHNAME
                        let mut j = si;
                        while let Some(&c) = text.get(j) {
                            if c == b'/' {
                                // Under PATHNAME alone, the trailing '*'
                                // cannot consume a '/'. Under PATHNAME +
                                // LEADING_DIR, accept up to the '/'.
                                if leading_dir {
                                    return true;
                                }
                                return false;
                            }
                            j += 1;
                        }
                    }
                    return true;
                }

                // Try matching the rest of the pattern against
                // increasingly long prefixes of the text.
                let mut j = si;
                loop {
                    if fnmatch_inner(pat, pi, text, j, flags, false) {
                        return true;
                    }
                    let c = match text.get(j) {
                        None => break,
                        Some(&c) => c,
                    };
                    if pathname && c == b'/' {
                        break;
                    }
                    j += 1;
                }
                return false;
            }
            b'[' => match classify_bracket(pat, pi, noescape) {
                BracketShape::Invalid => return false,
                BracketShape::LiteralFallback => {
                    let c = match sc {
                        None => return false,
                        Some(c) => c,
                    };
                    if pathname && c == b'/' {
                        return false;
                    }
                    if leading_period_blocked(c, si) {
                        return false;
                    }
                    let eq = if casefold {
                        b'['.eq_ignore_ascii_case(&c)
                    } else {
                        c == b'['
                    };
                    if !eq {
                        return false;
                    }
                    pi += 1;
                    si += 1;
                    at_start = false;
                }
                BracketShape::Terminated => {
                    let c = match sc {
                        None => return false,
                        Some(c) => c,
                    };
                    if pathname && c == b'/' {
                        return false;
                    }
                    if leading_period_blocked(c, si) {
                        return false;
                    }

                    pi += 1; // skip '['
                    let negated = matches!(pat.get(pi), Some(&b'!') | Some(&b'^'));
                    if negated {
                        pi += 1;
                    }

                    let mut matched = false;
                    let mut first = true;
                    loop {
                        let bc = match pat.get(pi) {
                            None => return false, // unterminated (shouldn't reach here)
                            Some(&b) => b,
                        };
                        if bc == b']' && !first {
                            break;
                        }
                        first = false;

                        // POSIX bracket sub-expressions: `[:class:]`,
                        // `[.collating.]`, `[=equivalence=]`. A `[` followed
                        // by `:`/`.`/`=` introduces one; anything else
                        // (including a literal `[`) falls through below.
                        if bc == b'['
                            && let Some(&kind) = pat.get(pi + 1)
                            && matches!(kind, b':' | b'.' | b'=')
                            && let Some((next_pi, member)) =
                                parse_bracket_subexpr(pat, pi, kind, c, casefold)
                        {
                            if member {
                                matched = true;
                            }
                            pi = next_pi;
                            continue;
                        }

                        let mut low = bc;
                        pi += 1;

                        // Escape inside bracket
                        if low == b'\\' && !noescape {
                            low = match pat.get(pi) {
                                None => return false,
                                Some(&b) => b,
                            };
                            pi += 1;
                        }

                        // Range: low '-' high (where high is not ']' / EOF)
                        let next = pat.get(pi);
                        let nextnext = pat.get(pi + 1);
                        if next == Some(&b'-') && nextnext != Some(&b']') && nextnext.is_some() {
                            pi += 1; // skip '-'
                            let mut high = pat.get(pi).copied().unwrap_or(0);
                            if high == b'\\' && !noescape {
                                pi += 1;
                                high = match pat.get(pi) {
                                    None => return false,
                                    Some(&b) => b,
                                };
                            }
                            pi += 1;

                            let test_ch = if casefold { c.to_ascii_lowercase() } else { c };
                            if casefold {
                                for r_ch in low..=high {
                                    if test_ch == r_ch.to_ascii_lowercase() {
                                        matched = true;
                                        break;
                                    }
                                }
                            } else {
                                if test_ch >= low && test_ch <= high {
                                    matched = true;
                                }
                            }
                        } else {
                            let test_ch = if casefold { c.to_ascii_lowercase() } else { c };
                            let low_cmp = if casefold {
                                low.to_ascii_lowercase()
                            } else {
                                low
                            };
                            if test_ch == low_cmp {
                                matched = true;
                            }
                        }
                    }
                    pi += 1; // skip ']'

                    if negated {
                        matched = !matched;
                    }
                    if !matched {
                        return false;
                    }
                    si += 1;
                    at_start = false;
                }
            },
            b'\\' if !noescape => {
                pi += 1;
                let escaped = match pat.get(pi) {
                    None => return false,
                    Some(&b) => b,
                };
                let c = match sc {
                    None => return false,
                    Some(c) => c,
                };
                let eq = if casefold {
                    escaped.eq_ignore_ascii_case(&c)
                } else {
                    escaped == c
                };
                if !eq {
                    return false;
                }
                pi += 1;
                si += 1;
                at_start = false;
            }
            _ => {
                let c = match sc {
                    None => return false,
                    Some(c) => c,
                };
                let eq = if casefold {
                    pc.eq_ignore_ascii_case(&c)
                } else {
                    pc == c
                };
                if !eq {
                    return false;
                }
                pi += 1;
                si += 1;
                at_start = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, t: &str, f: FnmatchFlags) -> bool {
        fnmatch_match(p.as_bytes(), t.as_bytes(), f)
    }

    #[test]
    fn literal_match() {
        assert!(m("hello", "hello", FnmatchFlags::NONE));
        assert!(!m("hello", "world", FnmatchFlags::NONE));
        assert!(!m("hello", "hell", FnmatchFlags::NONE));
        assert!(!m("hell", "hello", FnmatchFlags::NONE));
    }

    #[test]
    fn empty_pattern_matches_empty_text() {
        assert!(m("", "", FnmatchFlags::NONE));
        assert!(!m("", "x", FnmatchFlags::NONE));
        assert!(!m("x", "", FnmatchFlags::NONE));
    }

    #[test]
    fn question_mark_matches_one_byte() {
        assert!(m("?", "a", FnmatchFlags::NONE));
        assert!(!m("?", "", FnmatchFlags::NONE));
        assert!(!m("?", "ab", FnmatchFlags::NONE));
        assert!(m("h?llo", "hello", FnmatchFlags::NONE));
        assert!(m("h?llo", "hxllo", FnmatchFlags::NONE));
        assert!(!m("h?llo", "hllo", FnmatchFlags::NONE));
    }

    #[test]
    fn star_matches_zero_or_more() {
        assert!(m("*", "anything", FnmatchFlags::NONE));
        assert!(m("*", "", FnmatchFlags::NONE));
        assert!(m("a*b", "ab", FnmatchFlags::NONE));
        assert!(m("a*b", "axxxb", FnmatchFlags::NONE));
        assert!(!m("a*b", "aXc", FnmatchFlags::NONE));
        assert!(m("*.txt", "file.txt", FnmatchFlags::NONE));
        assert!(!m("*.txt", "file.csv", FnmatchFlags::NONE));
    }

    #[test]
    fn bracket_class_matches_one_of() {
        assert!(m("[abc]", "a", FnmatchFlags::NONE));
        assert!(m("[abc]", "b", FnmatchFlags::NONE));
        assert!(m("[abc]", "c", FnmatchFlags::NONE));
        assert!(!m("[abc]", "d", FnmatchFlags::NONE));
    }

    #[test]
    fn bracket_negation() {
        assert!(m("[!abc]", "d", FnmatchFlags::NONE));
        assert!(!m("[!abc]", "a", FnmatchFlags::NONE));
        assert!(m("[^abc]", "d", FnmatchFlags::NONE));
    }

    #[test]
    fn bracket_range() {
        assert!(m("[a-c]", "b", FnmatchFlags::NONE));
        assert!(!m("[a-c]", "d", FnmatchFlags::NONE));
        assert!(m("[0-9]", "5", FnmatchFlags::NONE));
        assert!(!m("[0-9]", "x", FnmatchFlags::NONE));
    }

    #[test]
    fn pathname_blocks_slash_in_star() {
        let f = FnmatchFlags::PATHNAME;
        assert!(m("a/b", "a/b", f));
        assert!(!m("*", "a/b", f));
        assert!(m("*", "a/b", FnmatchFlags::NONE));
        assert!(m("a/*", "a/b", f));
        assert!(!m("a/*", "a/b/c", f));
        assert!(m("a/*/c", "a/b/c", f));
    }

    #[test]
    fn period_blocks_leading_dot_match() {
        let f = FnmatchFlags::PERIOD;
        assert!(!m("*", ".hidden", f));
        assert!(m("*", ".hidden", FnmatchFlags::NONE));
        assert!(!m("?bashrc", ".bashrc", f));
        assert!(m("?bashrc", ".bashrc", FnmatchFlags::NONE));
        assert!(m(".bashrc", ".bashrc", f)); // explicit '.'
    }

    #[test]
    fn period_pathname_combined() {
        let f = FnmatchFlags::PERIOD | FnmatchFlags::PATHNAME;
        // After '/' a leading '.' is also blocked by PERIOD+PATHNAME.
        assert!(!m("a/*", "a/.hidden", f));
        assert!(m("a/.*", "a/.hidden", f));
    }

    #[test]
    fn noescape_makes_backslash_literal() {
        let f = FnmatchFlags::NOESCAPE;
        assert!(m(r"\*", r"\*", f));
        assert!(!m(r"\*", "x", f));
        // Without NOESCAPE, \* matches literal *
        assert!(m(r"\*", "*", FnmatchFlags::NONE));
        assert!(!m(r"\*", "x", FnmatchFlags::NONE));
    }

    #[test]
    fn casefold() {
        let f = FnmatchFlags::CASEFOLD;
        assert!(m("HELLO", "hello", f));
        assert!(m("hello", "HELLO", f));
        assert!(!m("HELLO", "hello", FnmatchFlags::NONE));
        assert!(m("[a-z]", "M", f));
        // Testing tricky range with casefold
        assert!(m("[Z-a]", "z", f));
        assert!(m("[Z-a]", "[", f));
    }

    #[test]
    fn leading_dir_allows_path_prefix() {
        let f = FnmatchFlags::LEADING_DIR;
        // pattern matches a directory prefix when text continues with '/'
        assert!(m("a/b", "a/b/c", f));
        assert!(m("a/b", "a/b", f));
        assert!(!m("a/b", "a/b.txt", f));
        assert!(!m("a/b", "a/c", f));
    }

    #[test]
    fn unterminated_bracket_literal_fallback() {
        // glibc treats '[abc' as literal '[' followed by 'abc'
        assert!(m("[abc", "[abc", FnmatchFlags::NONE));
        assert!(!m("[abc", "a", FnmatchFlags::NONE));
    }

    #[test]
    fn unterminated_bracket_with_dash_invalid() {
        // '[a-' — incomplete range, never matches
        assert!(!m("[a-", "a", FnmatchFlags::NONE));
        assert!(!m("[a-", "[a-", FnmatchFlags::NONE));
    }

    #[test]
    fn unterminated_bracket_with_escaped_dash_is_literal() {
        // '[a\-' — the trailing '-' is escaped, so it is a literal dash,
        // NOT an incomplete range. glibc treats the unterminated bracket
        // as a literal '[', so the pattern matches the literal text
        // "[a-" (verified against host glibc fnmatch). The classifier
        // must be escape-aware to avoid the bogus `Invalid` verdict.
        assert!(m(r"[a\-", "[a-", FnmatchFlags::NONE));
        assert!(!m(r"[a\-", "a", FnmatchFlags::NONE));
        // With NOESCAPE the backslash is literal: '[a\-' really does end
        // in an unescaped '-' → incomplete range → never matches.
        assert!(!m(r"[a\-", "[a-", FnmatchFlags::NOESCAPE));
    }

    #[test]
    fn bracket_close_first_is_literal() {
        // POSIX: ']' as first content byte is literal
        assert!(m("[]ab]", "]", FnmatchFlags::NONE));
        assert!(m("[]ab]", "a", FnmatchFlags::NONE));
        assert!(!m("[]ab]", "c", FnmatchFlags::NONE));
    }

    #[test]
    fn posix_character_classes() {
        let none = FnmatchFlags::NONE;
        assert!(m("[[:digit:]]", "5", none));
        assert!(!m("[[:digit:]]", "a", none));
        assert!(m("[[:alpha:]]", "Z", none));
        assert!(!m("[[:alpha:]]", "5", none));
        assert!(m("[[:alnum:]]", "x", none));
        assert!(m("[[:space:]]", " ", none));
        assert!(m("[[:space:]]", "\t", none));
        assert!(m("[[:xdigit:]]", "f", none));
        assert!(!m("[[:xdigit:]]", "g", none));
        assert!(m("[[:upper:]]", "A", none));
        assert!(!m("[[:upper:]]", "a", none));
        assert!(m("[[:lower:]]", "a", none));
        assert!(m("[[:punct:]]", "!", none));
        assert!(m("[[:cntrl:]]", "\x07", none));
        // A class combined with literals / ranges in the same bracket.
        assert!(m("[[:digit:]abc]", "b", none));
        assert!(m("[[:digit:]abc]", "7", none));
        assert!(!m("[[:digit:]abc]", "z", none));
        assert!(m("[[:digit:]A-F]", "D", none));
        assert!(m("x[[:digit:]]y", "x4y", none));
        assert!(!m("x[[:digit:]]y", "xZy", none));
        // Negated class.
        assert!(m("[![:digit:]]", "a", none));
        assert!(!m("[![:digit:]]", "3", none));
        assert!(m("[^[:space:]]", "q", none));
        // An unknown class name is a recognized form that matches nothing.
        assert!(!m("[[:bogus:]]", "[", none));
        assert!(!m("[[:bogus:]]", "x", none));
    }

    #[test]
    fn posix_class_casefold() {
        let f = FnmatchFlags::CASEFOLD;
        // [:upper:] / [:lower:] fold under FNM_CASEFOLD.
        assert!(m("[[:upper:]]", "a", f));
        assert!(m("[[:lower:]]", "A", f));
        assert!(m("[[:digit:]]", "5", f));
        assert!(!m("[[:digit:]]", "x", f));
    }

    #[test]
    fn collating_and_equivalence_elements() {
        let none = FnmatchFlags::NONE;
        assert!(m("[[.a.]]", "a", none));
        assert!(!m("[[.a.]]", "b", none));
        assert!(m("[[=e=]]", "e", none));
        assert!(!m("[[=e=]]", "f", none));
        // Mixed with ordinary members.
        assert!(m("[[.a.]xyz]", "y", none));
        assert!(m("[[.a.]xyz]", "a", none));
    }
}
