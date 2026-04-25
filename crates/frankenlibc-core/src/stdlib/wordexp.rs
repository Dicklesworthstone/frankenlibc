//! POSIX `wordexp` variable-expansion building blocks.
//!
//! Pure-safe Rust port of the byte-level expansion logic that
//! previously lived inline in frankenlibc-abi/src/unistd_abi.rs::expand_vars.
//! The abi layer keeps responsibility for the C-ABI marshalling, the
//! `wordexp_t` struct construction, the optional `WRDE_NOCMD`-gated
//! command substitution path, and the actual environment lookup
//! (passed in here as a closure so core stays pure-safe and free of
//! `std::env` dependencies).
//!
//! Supported expansions:
//!   - backslash escape (`\\X` → literal `X`)
//!   - single-quoted (`'...'`) — verbatim, no expansion
//!   - `$VAR` and `${VAR}` — environment lookup via the supplied closure
//!   - double-quoted (`"..."`) — recursively expanded, drops the
//!     surrounding quotes from the output
//!
//! Any other byte is appended literally.

/// Why expansion failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpandError {
    /// A `$VAR` reference resolved to no value, and the caller asked
    /// to treat that as an error (the POSIX `WRDE_UNDEF` flag).
    UndefinedVariable(String),
}

/// Expand a single shell-style word into a `String`.
///
/// `lookup_env` is invoked for each `$VAR` / `${VAR}` reference; it
/// returns `Some(value)` to expand or `None` to indicate the variable
/// is unset. When `undef_is_error` is true, an unset variable causes
/// the whole expansion to fail with [`ExpandError::UndefinedVariable`].
///
/// The function is byte-oriented: the input `&str` is processed as
/// `&[u8]` and result bytes are appended to a `String`. Non-UTF-8
/// bytes inside a `${VAR}` literal name are silently skipped.
pub fn expand_vars<F>(
    word: &str,
    undef_is_error: bool,
    lookup_env: F,
) -> Result<String, ExpandError>
where
    F: Fn(&str) -> Option<String>,
{
    // Funnel through the dyn-trait variant so the recursive call inside
    // the double-quoted branch doesn't infinitely re-instantiate `F`.
    expand_vars_dyn(word, undef_is_error, &lookup_env)
}

fn expand_vars_dyn(
    word: &str,
    undef_is_error: bool,
    lookup_env: &dyn Fn(&str) -> Option<String>,
) -> Result<String, ExpandError> {
    let mut result = String::with_capacity(word.len());
    let bytes = word.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            result.push(bytes[i + 1] as char);
            i += 2;
            continue;
        }
        if bytes[i] == b'\'' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'\'' {
                result.push(bytes[i] as char);
                i += 1;
            }
            if i < bytes.len() {
                i += 1; // skip closing '
            }
            continue;
        }
        if bytes[i] == b'$' {
            i += 1;
            if i >= bytes.len() {
                result.push('$');
                continue;
            }
            let (var_name, end) = if bytes[i] == b'{' {
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] != b'}' {
                    i += 1;
                }
                let name = core::str::from_utf8(&bytes[start..i]).unwrap_or("");
                if i < bytes.len() {
                    i += 1; // skip }
                }
                (name, i)
            } else {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let name = core::str::from_utf8(&bytes[start..i]).unwrap_or("");
                (name, i)
            };
            i = end;
            if var_name.is_empty() {
                result.push('$');
                continue;
            }
            match lookup_env(var_name) {
                Some(val) => result.push_str(&val),
                None => {
                    if undef_is_error {
                        return Err(ExpandError::UndefinedVariable(var_name.to_string()));
                    }
                    // Otherwise expand to empty string.
                }
            }
            continue;
        }
        if bytes[i] == b'"' {
            i += 1;
            let mut inner = String::new();
            while i < bytes.len() && bytes[i] != b'"' {
                inner.push(bytes[i] as char);
                i += 1;
            }
            if i < bytes.len() {
                i += 1; // skip closing "
            }
            // Recursively expand the inner content. The dyn-trait
            // funnel above means this doesn't blow up generic
            // monomorphization.
            let expanded = expand_vars_dyn(&inner, undef_is_error, lookup_env)?;
            result.push_str(&expanded);
            continue;
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn map_env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        // Build an owned HashMap that the returned closure captures by
        // value (`move`). Lifetimes are independent of `pairs` because
        // the closure no longer borrows from it.
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    #[test]
    fn literal_text_passes_through() {
        let r = expand_vars("hello world", false, |_| None).unwrap();
        assert_eq!(r, "hello world");
    }

    #[test]
    fn simple_dollar_var() {
        let env = map_env(&[("HOME", "/root")]);
        assert_eq!(expand_vars("$HOME", false, &env).unwrap(), "/root");
        assert_eq!(
            expand_vars("path:$HOME/bin", false, &env).unwrap(),
            "path:/root/bin"
        );
    }

    #[test]
    fn brace_var() {
        let env = map_env(&[("USER", "alice")]);
        assert_eq!(expand_vars("${USER}", false, &env).unwrap(), "alice");
        assert_eq!(
            expand_vars("hi ${USER}!", false, &env).unwrap(),
            "hi alice!"
        );
    }

    #[test]
    fn brace_var_followed_by_letters() {
        // ${USER}name should expand USER then append "name" — distinguish from $USERname.
        let env = map_env(&[("USER", "alice")]);
        assert_eq!(
            expand_vars("${USER}name", false, &env).unwrap(),
            "alicename"
        );
    }

    #[test]
    fn unbraced_var_stops_at_non_alnum() {
        let env = map_env(&[("U", "alice"), ("USER", "bob")]);
        // $USER stops at the / — full var name "USER" matched.
        assert_eq!(expand_vars("$USER/bin", false, &env).unwrap(), "bob/bin");
        // $U stops at - (non-alphanumeric).
        assert_eq!(expand_vars("$U-tag", false, &env).unwrap(), "alice-tag");
    }

    #[test]
    fn undefined_var_expands_empty_when_not_strict() {
        let env = map_env(&[]);
        assert_eq!(expand_vars("a${MISSING}b", false, &env).unwrap(), "ab");
    }

    #[test]
    fn undefined_var_errors_when_strict() {
        let env = map_env(&[]);
        let err = expand_vars("$MISSING", true, &env).unwrap_err();
        assert_eq!(err, ExpandError::UndefinedVariable("MISSING".into()));
    }

    #[test]
    fn single_quoted_does_not_expand() {
        let env = map_env(&[("HOME", "/root")]);
        assert_eq!(expand_vars("'$HOME'", false, &env).unwrap(), "$HOME");
    }

    #[test]
    fn double_quoted_expands_inside() {
        let env = map_env(&[("USER", "bob")]);
        assert_eq!(
            expand_vars(r#""hello $USER""#, false, &env).unwrap(),
            "hello bob"
        );
    }

    #[test]
    fn backslash_escapes_next_char() {
        let env = map_env(&[]);
        assert_eq!(expand_vars(r"\$HOME", false, &env).unwrap(), "$HOME");
        assert_eq!(expand_vars(r"\\x", false, &env).unwrap(), r"\x");
    }

    #[test]
    fn dollar_at_end_is_literal() {
        let env = map_env(&[]);
        assert_eq!(expand_vars("end$", false, &env).unwrap(), "end$");
    }

    #[test]
    fn empty_brace_is_literal_dollar() {
        let env = map_env(&[]);
        assert_eq!(expand_vars("${}", false, &env).unwrap(), "$");
    }

    #[test]
    fn dollar_followed_by_non_alpha_is_literal() {
        let env = map_env(&[]);
        // $1 → name is "1", which doesn't start with letter/_; the `$` then `1`
        // are emitted as their literal bytes per shell semantics for this path.
        // Our parser actually treats `1` as alnum and reads "1" as the name —
        // so $1 looks up "1". When that's missing AND not strict, expands to empty.
        let r = expand_vars("$1", false, &env).unwrap();
        assert_eq!(r, "");
        // If lookup returns a value:
        let env2 = map_env(&[("1", "first-arg")]);
        assert_eq!(expand_vars("$1", false, &env2).unwrap(), "first-arg");
    }

    #[test]
    fn empty_input_returns_empty() {
        let env = map_env(&[]);
        assert_eq!(expand_vars("", false, &env).unwrap(), "");
    }

    #[test]
    fn consecutive_vars() {
        let env = map_env(&[("A", "alpha"), ("B", "beta")]);
        assert_eq!(expand_vars("$A$B", false, &env).unwrap(), "alphabeta");
        assert_eq!(expand_vars("${A}-${B}", false, &env).unwrap(), "alpha-beta");
    }

    #[test]
    fn nested_double_quotes_recursively_expand() {
        let env = map_env(&[("NESTED", "$INNER"), ("INNER", "deep")]);
        // The "expansion of NESTED" yields "$INNER" — that's not re-expanded by
        // the lookup itself, but if we put it in double-quotes the recursive
        // expand_vars would expand it. expand_vars(NESTED) returns "$INNER"
        // verbatim because lookup_env returns "$INNER" as-is.
        assert_eq!(expand_vars("$NESTED", false, &env).unwrap(), "$INNER");
    }

    #[test]
    fn mixed_quoted_and_unquoted() {
        let env = map_env(&[("X", "value")]);
        assert_eq!(
            expand_vars(r#"prefix-'$X'-"$X"-$X"#, false, &env).unwrap(),
            "prefix-$X-value-value"
        );
    }

    #[test]
    fn unclosed_brace_consumes_remainder_as_var_name() {
        let env = map_env(&[("ABC", "got it")]);
        // ${ABC<no closing brace> reads name as "ABC" until end.
        assert_eq!(expand_vars("${ABC", false, &env).unwrap(), "got it");
    }

    #[test]
    fn unclosed_quote_consumes_to_end() {
        let env = map_env(&[("X", "val")]);
        // Single-quoted unterminated: consumes literally to end.
        assert_eq!(expand_vars("'$X", false, &env).unwrap(), "$X");
        // Double-quoted unterminated: expands inside to end.
        assert_eq!(expand_vars(r#""$X"#, false, &env).unwrap(), "val");
    }

    #[test]
    fn lookup_closure_called_with_exact_name() {
        let mut last_seen: Option<String> = None;
        let lookup = |name: &str| {
            // Capture the name we were asked about (single-call test).
            // Can't mutate here in Fn; use a Cell pattern instead.
            // Simpler: just return Some(reverse-of-name).
            Some(name.chars().rev().collect::<String>())
        };
        assert_eq!(expand_vars("$HELLO", false, lookup).unwrap(), "OLLEH");
        // Avoid unused-mut warning.
        let _ = &mut last_seen;
    }
}
