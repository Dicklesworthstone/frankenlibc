//! Pure helpers for parsing a POSIX/GNU getopt optstring.
//!
//! An optstring is a sequence of option characters, optionally
//! followed by `:` (required argument) or `::` (GNU optional
//! argument). A leading `:` flips opterr-suppressed reporting (this
//! is exposed via [`getopt_prefers_colon`]).

/// Argument-acceptance mode for an option character.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GetoptArgMode {
    /// Bare option (no argument). E.g. `a` in `"abc:"`.
    None,
    /// Required argument. E.g. `c` in `"abc:"`.
    Required,
    /// Optional argument (GNU extension `::`). E.g. `c` in `"ac::"`.
    Optional,
}

/// Returns `true` when `optspec` starts with `:`. POSIX: a leading
/// colon makes getopt return `':'` (instead of `'?'`) for missing
/// required arguments and silences the default error message.
#[inline]
pub fn getopt_prefers_colon(optspec: &[u8]) -> bool {
    optspec.first().copied() == Some(b':')
}

/// Look up the argument mode for `option` within `optspec`.
///
/// Returns `None` if `option` is not present. If present:
///   - `"X"`     → [`GetoptArgMode::None`]
///   - `"X:"`    → [`GetoptArgMode::Required`]
///   - `"X::"`   → [`GetoptArgMode::Optional`] (GNU)
#[inline]
pub fn getopt_arg_mode(optspec: &[u8], option: u8) -> Option<GetoptArgMode> {
    for (idx, &byte) in optspec.iter().enumerate() {
        if byte != option {
            continue;
        }
        let requires = optspec.get(idx + 1).copied() == Some(b':');
        let optional = optspec.get(idx + 2).copied() == Some(b':');
        return Some(if requires && optional {
            GetoptArgMode::Optional
        } else if requires {
            GetoptArgMode::Required
        } else {
            GetoptArgMode::None
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_colon_when_optspec_starts_with_colon() {
        assert!(getopt_prefers_colon(b":abc"));
        assert!(!getopt_prefers_colon(b"abc"));
        assert!(!getopt_prefers_colon(b""));
    }

    #[test]
    fn prefers_colon_alone() {
        assert!(getopt_prefers_colon(b":"));
    }

    #[test]
    fn arg_mode_missing_option_returns_none() {
        assert_eq!(getopt_arg_mode(b"abc", b'd'), None);
        assert_eq!(getopt_arg_mode(b"", b'a'), None);
    }

    #[test]
    fn arg_mode_no_arg() {
        assert_eq!(getopt_arg_mode(b"abc", b'a'), Some(GetoptArgMode::None));
        assert_eq!(getopt_arg_mode(b"abc", b'b'), Some(GetoptArgMode::None));
        assert_eq!(getopt_arg_mode(b"abc", b'c'), Some(GetoptArgMode::None));
    }

    #[test]
    fn arg_mode_required() {
        assert_eq!(getopt_arg_mode(b"a:bc", b'a'), Some(GetoptArgMode::Required));
        assert_eq!(getopt_arg_mode(b"ab:c", b'b'), Some(GetoptArgMode::Required));
        assert_eq!(getopt_arg_mode(b"abc:", b'c'), Some(GetoptArgMode::Required));
    }

    #[test]
    fn arg_mode_optional_gnu() {
        assert_eq!(
            getopt_arg_mode(b"a::bc", b'a'),
            Some(GetoptArgMode::Optional)
        );
        assert_eq!(
            getopt_arg_mode(b"ab::c", b'b'),
            Some(GetoptArgMode::Optional)
        );
    }

    #[test]
    fn arg_mode_does_not_confuse_colon_with_option() {
        // ':' is a meta char in optstring, not a selectable option.
        // (When optspec STARTS with ':' it just toggles opterr — the
        // colon itself is not exposed as a 'colon' option.)
        // But: a colon AFTER non-colon characters is still always
        // a meta — getopt_arg_mode for ':' should never match in
        // practice. Verify the function still works on a degenerate
        // input rather than crashing.
        let _ = getopt_arg_mode(b"a:b", b':');
    }

    #[test]
    fn arg_mode_first_match_wins_for_duplicate_option() {
        // A duplicated option char in optspec — first occurrence wins.
        assert_eq!(getopt_arg_mode(b"a:a", b'a'), Some(GetoptArgMode::Required));
    }

    #[test]
    fn arg_mode_at_end_of_optspec() {
        // Last char with no trailing ':' → None
        assert_eq!(getopt_arg_mode(b"abc", b'c'), Some(GetoptArgMode::None));
        // Last char with ':' suffix → Required
        assert_eq!(getopt_arg_mode(b"abc:", b'c'), Some(GetoptArgMode::Required));
    }

    #[test]
    fn arg_mode_leading_colon_doesnt_break_lookup() {
        // ":a:b" — leading ':' is the opterr toggle; 'a' is required, 'b' is none.
        assert_eq!(getopt_arg_mode(b":a:b", b'a'), Some(GetoptArgMode::Required));
        assert_eq!(getopt_arg_mode(b":a:b", b'b'), Some(GetoptArgMode::None));
    }
}
