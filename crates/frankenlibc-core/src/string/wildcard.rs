//! Simple shell-wildcard matcher (`*`, `?` only).
//!
//! Pure-safe Rust port of `glob_match_bytes` from
//! frankenlibc-abi/src/unistd_abi.rs (used by `wordexp` for argument
//! pattern expansion). This is the simpler subset of pattern matching:
//!   - `*` matches any sequence of bytes (zero or more)
//!   - `?` matches exactly one byte
//!   - all other bytes — including `[`, `\`, `]`, `{`, `}` — are
//!     literal
//!
//! For full POSIX fnmatch semantics (bracket character classes,
//! backslash escapes, the `FNM_PATHNAME` / `FNM_NOESCAPE` /
//! `FNM_PERIOD` / `FNM_LEADING_DIR` / `FNM_CASEFOLD` flags), use
//! [`crate::string::fnmatch::fnmatch_match`] instead.

/// Match `text` against `pattern`, returning `true` if the entire
/// text is consumed by the pattern.
///
/// The matcher is the classic two-pointer linear walk with a single
/// backtrack point on `*`. Time complexity is O(n*m) worst case but
/// the constant factor is tiny — no allocations, no recursion, no
/// regex compilation.
pub fn wildcard_match(pattern: &[u8], text: &[u8]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi = usize::MAX;
    let mut star_ti = 0;

    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pattern_matches_only_empty_text() {
        assert!(wildcard_match(b"", b""));
        assert!(!wildcard_match(b"", b"x"));
    }

    #[test]
    fn empty_text_matches_only_empty_or_all_stars_pattern() {
        assert!(wildcard_match(b"", b""));
        assert!(wildcard_match(b"*", b""));
        assert!(wildcard_match(b"**", b""));
        assert!(wildcard_match(b"***", b""));
        assert!(!wildcard_match(b"?", b""));
        assert!(!wildcard_match(b"a", b""));
        assert!(!wildcard_match(b"a*", b""));
    }

    #[test]
    fn literal_match() {
        assert!(wildcard_match(b"hello", b"hello"));
        assert!(!wildcard_match(b"hello", b"hellz"));
        assert!(!wildcard_match(b"hello", b"hell"));
        assert!(!wildcard_match(b"hello", b"helloo"));
    }

    #[test]
    fn star_matches_zero_bytes() {
        assert!(wildcard_match(b"a*b", b"ab"));
        assert!(wildcard_match(b"*hello", b"hello"));
        assert!(wildcard_match(b"hello*", b"hello"));
    }

    #[test]
    fn star_matches_single_byte() {
        assert!(wildcard_match(b"a*b", b"axb"));
        assert!(wildcard_match(b"*x", b"yx"));
    }

    #[test]
    fn star_matches_many_bytes() {
        assert!(wildcard_match(b"a*z", b"abcxyz"));
        assert!(wildcard_match(b"*", b"any string at all"));
        assert!(wildcard_match(b"a*", b"abcdefghijk"));
    }

    #[test]
    fn question_matches_exactly_one_byte() {
        assert!(wildcard_match(b"?", b"a"));
        assert!(wildcard_match(b"???", b"abc"));
        assert!(wildcard_match(b"a?c", b"abc"));
        assert!(!wildcard_match(b"?", b""));
        assert!(!wildcard_match(b"?", b"ab"));
        assert!(!wildcard_match(b"???", b"ab"));
    }

    #[test]
    fn star_question_combinations() {
        assert!(wildcard_match(b"*?", b"a"));
        assert!(wildcard_match(b"*?", b"abc"));
        assert!(wildcard_match(b"?*", b"a"));
        assert!(wildcard_match(b"?*", b"abc"));
        assert!(!wildcard_match(b"*?", b""));
        assert!(!wildcard_match(b"?*", b""));
    }

    #[test]
    fn leading_and_trailing_stars() {
        assert!(wildcard_match(b"*foo*", b"xfoox"));
        assert!(wildcard_match(b"*foo*", b"foo"));
        assert!(wildcard_match(b"*foo*", b"prefixfoo"));
        assert!(wildcard_match(b"*foo*", b"foosuffix"));
        assert!(!wildcard_match(b"*foo*", b"baz"));
    }

    #[test]
    fn brackets_treated_literally() {
        // Distinguishing test vs fnmatch_match: `[abc]` matches only
        // the literal 5-byte sequence "[abc]", not any of a/b/c.
        assert!(wildcard_match(b"[abc]", b"[abc]"));
        assert!(!wildcard_match(b"[abc]", b"a"));
        assert!(!wildcard_match(b"[abc]", b"b"));
    }

    #[test]
    fn backslash_treated_literally() {
        // Distinguishing test vs fnmatch_match: `\\*` matches the
        // literal 2-byte sequence "\\*", not "*"-as-literal-asterisk.
        assert!(wildcard_match(b"\\*", b"\\anything"));
        assert!(wildcard_match(b"\\?", b"\\x"));
    }

    #[test]
    fn trailing_star_after_text_exhausted() {
        // After all text is consumed, trailing `*`s in the pattern
        // are absorbed.
        assert!(wildcard_match(b"abc***", b"abc"));
        assert!(wildcard_match(b"abc*?*", b"abcd"));
        // But `abc?*` with no chars after `c` still fails (`?` needs a byte).
        assert!(!wildcard_match(b"abc?*", b"abc"));
    }

    #[test]
    fn multi_star_stress() {
        // Pathological backtracking case for the simple matcher.
        let pat = b"a*a*a*a*a*b";
        let text = b"aaaaaaaaaaaaaaaaaaaab";
        assert!(wildcard_match(pat, text));
        let bad_text = b"aaaaaaaaaaaaaaaaaaaa";
        assert!(!wildcard_match(pat, bad_text));
    }

    #[test]
    fn star_only_matches_anything() {
        assert!(wildcard_match(b"*", b""));
        assert!(wildcard_match(b"*", b"x"));
        assert!(wildcard_match(b"*", b"some longer string"));
        assert!(wildcard_match(b"**", b"anything"));
    }

    #[test]
    fn no_partial_text_match() {
        // Text "hello world" with pattern "hello" — must reject.
        assert!(!wildcard_match(b"hello", b"hello world"));
        // But trailing `*` lets the pattern absorb the suffix.
        assert!(wildcard_match(b"hello*", b"hello world"));
    }

    #[test]
    fn binary_safe_bytes() {
        // Embedded NUL and high bytes are matched verbatim.
        let pattern = &[b'a', 0, b'b', b'?', 0xFF];
        let text = &[b'a', 0, b'b', b'X', 0xFF];
        assert!(wildcard_match(pattern, text));
        let bad = &[b'a', 0, b'b', b'X', 0x00];
        assert!(!wildcard_match(pattern, bad));
    }

    #[test]
    fn star_at_end_consumes_remaining() {
        for trailing_count in 0..10 {
            let mut text = b"prefix".to_vec();
            text.extend(std::iter::repeat_n(b'x', trailing_count));
            assert!(wildcard_match(b"prefix*", &text), "len={trailing_count}");
        }
    }
}
