//! Environment variable validation and parsing helpers.
//!
//! The core module provides safe validation logic. Actual environment
//! access (`environ` pointer manipulation) lives in the ABI layer since
//! it requires unsafe pointer operations.

/// Validates that `name` is a legal environment variable name.
///
/// POSIX requires: non-empty, no `'='` character, no embedded NUL.
pub fn valid_env_name(name: &[u8]) -> bool {
    !name.is_empty() && !name.contains(&b'=') && !name.contains(&0)
}

/// Validates that `value` contains no embedded NUL bytes.
pub fn valid_env_value(value: &[u8]) -> bool {
    !value.contains(&0)
}

/// Given a `NAME=VALUE` entry, check if `name` matches the key portion.
///
/// Returns `true` if `entry` starts with `name` followed by `'='`.
pub fn entry_matches(entry: &[u8], name: &[u8]) -> bool {
    if entry.len() <= name.len() {
        return false;
    }
    entry[..name.len()] == *name && entry[name.len()] == b'='
}

/// Extract the value portion from a `NAME=VALUE` entry.
///
/// Returns `None` if no `'='` is found.
pub fn entry_value(entry: &[u8]) -> Option<&[u8]> {
    let eq_pos = entry.iter().position(|&b| b == b'=')?;
    Some(&entry[eq_pos + 1..])
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // valid_env_name
    // ---------------------------------------------------------------

    #[test]
    fn valid_name_normal() {
        assert!(valid_env_name(b"HOME"));
        assert!(valid_env_name(b"PATH"));
        assert!(valid_env_name(b"_"));
        assert!(valid_env_name(b"LD_LIBRARY_PATH"));
        assert!(valid_env_name(b"a"));
    }

    #[test]
    fn invalid_name_empty() {
        assert!(!valid_env_name(b""));
    }

    #[test]
    fn invalid_name_contains_equals() {
        assert!(!valid_env_name(b"FOO=BAR"));
        assert!(!valid_env_name(b"="));
        assert!(!valid_env_name(b"A="));
    }

    #[test]
    fn invalid_name_contains_nul() {
        assert!(!valid_env_name(b"FOO\0BAR"));
        assert!(!valid_env_name(b"\0"));
    }

    // ---------------------------------------------------------------
    // valid_env_value
    // ---------------------------------------------------------------

    #[test]
    fn valid_value_normal() {
        assert!(valid_env_value(b"/usr/bin:/usr/local/bin"));
        assert!(valid_env_value(b""));
        assert!(valid_env_value(b"hello world"));
    }

    #[test]
    fn invalid_value_nul() {
        assert!(!valid_env_value(b"hello\0world"));
    }

    // ---------------------------------------------------------------
    // entry_matches
    // ---------------------------------------------------------------

    #[test]
    fn entry_matches_positive() {
        assert!(entry_matches(b"HOME=/home/user", b"HOME"));
        assert!(entry_matches(b"A=", b"A"));
        assert!(entry_matches(b"PATH=/usr/bin", b"PATH"));
    }

    #[test]
    fn entry_matches_negative() {
        assert!(!entry_matches(b"HOME=/home/user", b"HOM"));
        assert!(!entry_matches(b"HOME=/home/user", b"HOME2"));
        assert!(!entry_matches(b"HOME", b"HOME")); // no '='
        assert!(!entry_matches(b"", b"HOME"));
    }

    #[test]
    fn entry_matches_prefix_attack() {
        // "HOMEPATH=..." should not match "HOME"
        assert!(!entry_matches(b"HOMEPATH=/foo", b"HOME"));
    }

    // ---------------------------------------------------------------
    // entry_value
    // ---------------------------------------------------------------

    #[test]
    fn entry_value_normal() {
        assert_eq!(entry_value(b"HOME=/home/user"), Some(&b"/home/user"[..]));
        assert_eq!(entry_value(b"A="), Some(&b""[..]));
        assert_eq!(entry_value(b"X=a=b"), Some(&b"a=b"[..]));
    }

    #[test]
    fn entry_value_no_equals() {
        assert_eq!(entry_value(b"HOME"), None);
        assert_eq!(entry_value(b""), None);
    }

    // ===== glibc parity tests =====
    // Verified against glibc via scripts/c_probes/probe_env_edge.c

    #[test]
    fn glibc_setenv_rejects_equals_in_name() {
        // setenv("BAD=NAME", ...) returns -1, errno=EINVAL
        assert!(!valid_env_name(b"BAD=NAME"));
    }

    #[test]
    fn glibc_setenv_rejects_empty_name() {
        // setenv("", "value", 1) returns -1, errno=EINVAL
        assert!(!valid_env_name(b""));
    }

    #[test]
    fn glibc_setenv_accepts_empty_value() {
        // setenv("VAR", "", 1) is valid (empty string)
        assert!(valid_env_value(b""));
    }

    #[test]
    fn glibc_setenv_accepts_equals_in_value() {
        // setenv("VAR", "a=b=c", 1) is valid
        assert!(valid_env_value(b"a=b=c"));
    }

    #[test]
    fn glibc_entry_value_extracts_after_first_equals() {
        // NAME=a=b=c should extract "a=b=c" as the value
        assert_eq!(entry_value(b"NAME=a=b=c"), Some(&b"a=b=c"[..]));
    }

    #[test]
    fn glibc_entry_value_empty_after_equals() {
        // NAME= should extract "" as the value
        assert_eq!(entry_value(b"NAME="), Some(&b""[..]));
    }
}
