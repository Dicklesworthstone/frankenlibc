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

/// Fused classification for one optstring byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GetoptSpecMatch {
    /// Argument mode selected by the first matching option byte.
    pub arg_mode: GetoptArgMode,
    /// GNU `W;`-style long-option route marker for the same byte.
    pub w_extension: bool,
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
    getopt_spec_match(optspec, option).map(|m| m.arg_mode)
}

/// Look up an option byte once and classify both its argument mode and GNU
/// `W;`-style long-option route marker.
#[inline]
pub(crate) fn getopt_spec_match(optspec: &[u8], option: u8) -> Option<GetoptSpecMatch> {
    for (idx, &byte) in optspec.iter().enumerate() {
        // ':' and ';' are optstring metacharacters, never selectable options
        // (glibc forces `c == ':' || c == ';'` to the unknown-option path). ';'
        // is the GNU `W;` long-route marker; ':' marks argument modes.
        if byte == b':' || byte == b';' {
            continue;
        }
        if byte != option {
            continue;
        }
        let requires = optspec.get(idx + 1).copied() == Some(b':');
        let optional = optspec.get(idx + 2).copied() == Some(b':');
        let arg_mode = if requires && optional {
            GetoptArgMode::Optional
        } else if requires {
            GetoptArgMode::Required
        } else {
            GetoptArgMode::None
        };
        return Some(GetoptSpecMatch {
            arg_mode,
            w_extension: optspec.get(idx + 1).copied() == Some(b';'),
        });
    }
    None
}

/// Returns `true` when `option` appears in `optspec` immediately followed by
/// `;` — the GNU `W;` extension marker. When set, `-option ARG` / `-optionARG`
/// is processed as the long option `--ARG` (the canonical spelling is `W;`).
///
/// Mirrors [`getopt_arg_mode`]'s first-occurrence, `:`-skipping scan so the two
/// agree on which optspec byte a given option character refers to.
#[inline]
pub fn getopt_is_w_extension(optspec: &[u8], option: u8) -> bool {
    getopt_spec_match(optspec, option).is_some_and(|m| m.w_extension)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semicolon_is_never_a_selectable_option() {
        // glibc forces `c == ';'` to the unknown-option path; ';' is only the
        // `W;` marker, never `-;`.
        assert_eq!(getopt_arg_mode(b"W;ab", b';'), None);
        assert_eq!(getopt_arg_mode(b";", b';'), None);
        assert!(!getopt_is_w_extension(b";;", b';'));
        // The marker does not disturb a real option that follows it.
        assert_eq!(getopt_arg_mode(b"W;ab:", b'b'), Some(GetoptArgMode::Required));
        assert_eq!(getopt_arg_mode(b"W;ab", b'a'), Some(GetoptArgMode::None));
    }

    #[test]
    fn w_extension_detected_only_with_trailing_semicolon() {
        assert!(getopt_is_w_extension(b"W;ab:", b'W'));
        assert!(getopt_is_w_extension(b"ab:W;c", b'W'));
        assert!(!getopt_is_w_extension(b"W;ab:", b'a'));
        assert!(!getopt_is_w_extension(b"Wab:", b'W')); // no ';'
        assert!(!getopt_is_w_extension(b"W:ab", b'W')); // ':' not ';'
        assert!(!getopt_is_w_extension(b"abc", b'W')); // absent
        // Any character may carry the marker, not just 'W'.
        assert!(getopt_is_w_extension(b"X;ab", b'X'));
    }

    #[test]
    fn fused_lookup_preserves_first_match_for_duplicates() {
        let w = getopt_spec_match(b"W;W:a", b'W').expect("first W selected");
        assert_eq!(w.arg_mode, GetoptArgMode::None);
        assert!(w.w_extension);

        let a = getopt_spec_match(b"a:a::", b'a').expect("first a selected");
        assert_eq!(a.arg_mode, GetoptArgMode::Required);
        assert!(!a.w_extension);
    }

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
        assert_eq!(
            getopt_arg_mode(b"a:bc", b'a'),
            Some(GetoptArgMode::Required)
        );
        assert_eq!(
            getopt_arg_mode(b"ab:c", b'b'),
            Some(GetoptArgMode::Required)
        );
        assert_eq!(
            getopt_arg_mode(b"abc:", b'c'),
            Some(GetoptArgMode::Required)
        );
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
        // A colon AFTER non-colon characters is still metadata for
        // the preceding option argument mode, not a real option.
        assert_eq!(getopt_arg_mode(b":a:b::c", b':'), None);
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
        assert_eq!(
            getopt_arg_mode(b"abc:", b'c'),
            Some(GetoptArgMode::Required)
        );
    }

    #[test]
    fn arg_mode_leading_colon_doesnt_break_lookup() {
        // ":a:b" — leading ':' is the opterr toggle; 'a' is required, 'b' is none.
        assert_eq!(
            getopt_arg_mode(b":a:b", b'a'),
            Some(GetoptArgMode::Required)
        );
        assert_eq!(getopt_arg_mode(b":a:b", b'b'), Some(GetoptArgMode::None));
    }
}
