//! POSIX glob — pathname pattern expansion.
//!
//! Clean-room implementation of `glob()` per POSIX.1-2017 §12.
//! Uses `readdir`/`opendir` via std::fs and fnmatch-style pattern matching.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

// ---------------------------------------------------------------------------
// POSIX glob constants (must match <glob.h> on glibc x86_64)
// ---------------------------------------------------------------------------

// Flags for glob()
pub const GLOB_ERR: i32 = 0x01;
pub const GLOB_MARK: i32 = 0x02;
pub const GLOB_NOSORT: i32 = 0x04;
pub const GLOB_DOOFFS: i32 = 0x08;
pub const GLOB_NOCHECK: i32 = 0x10;
pub const GLOB_APPEND: i32 = 0x20;
pub const GLOB_NOESCAPE: i32 = 0x40;
// GNU extensions
pub const GLOB_PERIOD: i32 = 0x80;
pub const GLOB_MAGCHAR: i32 = 0x100;
pub const GLOB_TILDE: i32 = 0x1000;
pub const GLOB_ONLYDIR: i32 = 0x2000;
pub const GLOB_TILDE_CHECK: i32 = 0x4000;

// Error return values
pub const GLOB_NOSPACE: i32 = 1;
pub const GLOB_ABORTED: i32 = 2;
pub const GLOB_NOMATCH: i32 = 3;

// ---------------------------------------------------------------------------
// Core glob result
// ---------------------------------------------------------------------------

/// Result of a glob expansion.
#[derive(Debug)]
pub struct GlobResult {
    /// Matched pathnames as null-terminated byte strings.
    pub paths: Vec<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Pattern analysis helpers
// ---------------------------------------------------------------------------

/// Check if a byte is a glob metacharacter.
fn is_glob_meta(ch: u8) -> bool {
    matches!(ch, b'*' | b'?' | b'[')
}

/// Check if a pattern contains glob metacharacters.
fn has_magic(pat: &[u8], noescape: bool) -> bool {
    let mut i = 0;
    while i < pat.len() {
        if pat[i] == b'\\' && !noescape {
            i += 2;
            continue;
        }
        if is_glob_meta(pat[i]) {
            return true;
        }
        i += 1;
    }
    false
}

/// Split pattern into directory prefix (no metacharacters) and the rest.
/// Returns (dir, pattern_tail).
fn split_pattern(pat: &[u8]) -> (&[u8], &[u8]) {
    // Find the last '/' before the first metacharacter.
    let mut first_meta = pat.len();
    let mut i = 0;
    while i < pat.len() {
        if pat[i] == b'\\' {
            i += 2;
            continue;
        }
        if is_glob_meta(pat[i]) {
            first_meta = i;
            break;
        }
        i += 1;
    }

    // Walk back from first_meta to find the last '/'.
    let mut last_slash = None;
    for j in (0..first_meta).rev() {
        if pat[j] == b'/' {
            last_slash = Some(j);
            break;
        }
    }

    match last_slash {
        Some(pos) => (&pat[..pos + 1], &pat[pos + 1..]),
        None => (b"", pat),
    }
}

// ---------------------------------------------------------------------------
// fnmatch (simplified, matching only single path component)
// ---------------------------------------------------------------------------

/// Simple fnmatch for a single component (no '/' in string).
fn fnmatch_component(pat: &[u8], name: &[u8], noescape: bool) -> bool {
    fn do_match(pat: &[u8], pi: usize, name: &[u8], ni: usize, noescape: bool) -> bool {
        if pi >= pat.len() {
            return ni >= name.len();
        }

        match pat[pi] {
            b'*' => {
                // Skip consecutive *'s
                let mut p = pi;
                while p < pat.len() && pat[p] == b'*' {
                    p += 1;
                }
                // Try matching against rest
                let mut n = ni;
                loop {
                    if do_match(pat, p, name, n, noescape) {
                        return true;
                    }
                    if n >= name.len() {
                        break;
                    }
                    n += 1;
                }
                false
            }
            b'?' => {
                if ni >= name.len() {
                    return false;
                }
                do_match(pat, pi + 1, name, ni + 1, noescape)
            }
            b'[' => {
                if ni >= name.len() {
                    return false;
                }
                let ch = name[ni];
                let (matched, end) = bracket_match(pat, pi + 1, ch);
                if !matched || end > pat.len() {
                    return false;
                }
                do_match(pat, end, name, ni + 1, noescape)
            }
            b'\\' if !noescape => {
                if pi + 1 >= pat.len() {
                    return false;
                }
                if ni >= name.len() || pat[pi + 1] != name[ni] {
                    return false;
                }
                do_match(pat, pi + 2, name, ni + 1, noescape)
            }
            c => {
                if ni >= name.len() || c != name[ni] {
                    return false;
                }
                do_match(pat, pi + 1, name, ni + 1, noescape)
            }
        }
    }

    do_match(pat, 0, name, 0, noescape)
}

/// Match a character against a bracket expression [...]
/// Returns (matched, position after closing ']')
fn bracket_match(pat: &[u8], start: usize, ch: u8) -> (bool, usize) {
    let mut negated = false;
    let mut i = start;

    if i < pat.len() && (pat[i] == b'!' || pat[i] == b'^') {
        negated = true;
        i += 1;
    }

    // First char after [ or [! can be ]
    let mut found = false;
    let mut first = true;

    while i < pat.len() {
        if pat[i] == b']' && !first {
            let result = if negated { !found } else { found };
            return (result, i + 1);
        }
        first = false;

        let lo = pat[i];
        if i + 2 < pat.len() && pat[i + 1] == b'-' && pat[i + 2] != b']' {
            // Range expression
            let hi = pat[i + 2];
            if ch >= lo && ch <= hi {
                found = true;
            }
            i += 3;
        } else {
            if ch == lo {
                found = true;
            }
            i += 1;
        }
    }

    // No closing bracket found
    (false, i)
}

// ---------------------------------------------------------------------------
// Directory reading and expansion
// ---------------------------------------------------------------------------

/// Expand a glob pattern and return matching paths.
///
/// `flags` are the POSIX glob flags (GLOB_ERR, GLOB_MARK, etc.).
/// `errfunc` is currently ignored (always returns error on directory failure
/// if GLOB_ERR is set).
pub fn glob_expand(pattern: &[u8], flags: i32) -> Result<GlobResult, i32> {
    // Find the pattern up to first null byte.
    let pat_len = pattern
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(pattern.len());
    let pat = &pattern[..pat_len];

    if pat.is_empty() {
        return Err(GLOB_NOMATCH);
    }

    // Handle tilde expansion
    let expanded;
    let pat = if (flags & GLOB_TILDE != 0 || flags & GLOB_TILDE_CHECK != 0) && pat[0] == b'~' {
        expanded = expand_tilde(pat);
        &expanded
    } else {
        pat
    };
    let noescape = flags & GLOB_NOESCAPE != 0;

    // If no metacharacters, just check existence.
    if !has_magic(pat, noescape) {
        let path = Path::new(OsStr::from_bytes(pat));
        if path.exists() {
            let mut p = pat.to_vec();
            if flags & GLOB_MARK != 0 && path.is_dir() && !p.ends_with(b"/") {
                p.push(b'/');
            }
            return Ok(GlobResult { paths: vec![p] });
        }
        if flags & GLOB_NOCHECK != 0 {
            return Ok(GlobResult {
                paths: vec![pat.to_vec()],
            });
        }
        return Err(GLOB_NOMATCH);
    }

    let mut results = Vec::new();
    glob_recursive(pat, flags, &mut results)?;

    if results.is_empty() {
        if flags & GLOB_NOCHECK != 0 {
            return Ok(GlobResult {
                paths: vec![pat.to_vec()],
            });
        }
        return Err(GLOB_NOMATCH);
    }

    // Sort unless GLOB_NOSORT
    if flags & GLOB_NOSORT == 0 {
        results.sort();
    }

    Ok(GlobResult { paths: results })
}

/// Recursively expand a glob pattern with directory traversal.
fn glob_recursive(pat: &[u8], flags: i32, results: &mut Vec<Vec<u8>>) -> Result<(), i32> {
    let (dir_prefix, tail) = split_pattern(pat);

    // Split tail at the next '/' to get the component pattern.
    let (component_pat, rest) = match tail.iter().position(|&b| b == b'/') {
        Some(pos) => (&tail[..pos], &tail[pos + 1..]),
        None => (tail, &[] as &[u8]),
    };

    // Determine the directory to read.
    let dir_path = if dir_prefix.is_empty() {
        Path::new(".")
    } else {
        Path::new(OsStr::from_bytes(dir_prefix))
    };

    // Read directory entries.
    let entries = match std::fs::read_dir(dir_path) {
        Ok(e) => e,
        Err(_) => {
            if flags & GLOB_ERR != 0 {
                return Err(GLOB_ABORTED);
            }
            return Ok(());
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let name = entry.file_name();
        let name_bytes = name.as_bytes();

        // Skip hidden files unless pattern starts with '.' or GLOB_PERIOD
        if name_bytes.starts_with(b".")
            && (component_pat.is_empty() || component_pat[0] != b'.')
            && flags & GLOB_PERIOD == 0
        {
            continue;
        }

        if !fnmatch_component(component_pat, name_bytes, noescape) {
            continue;
        }

        // Build the full path.
        let mut full_path = Vec::new();
        if !dir_prefix.is_empty() {
            full_path.extend_from_slice(dir_prefix);
        }
        full_path.extend_from_slice(name_bytes);

        if rest.is_empty() {
            // No more pattern components — this is a final match.
            if flags & GLOB_ONLYDIR != 0 && !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            if flags & GLOB_MARK != 0 && entry.file_type().is_ok_and(|t| t.is_dir()) {
                full_path.push(b'/');
            }
            results.push(full_path);
        } else if entry.file_type().is_ok_and(|t| t.is_dir()) {
            // More pattern components remain — recurse into directory.
            full_path.push(b'/');
            full_path.extend_from_slice(rest);
            glob_recursive(&full_path, flags, results)?;
        }
    }

    Ok(())
}

/// Expand ~ to $HOME.
fn expand_tilde(pat: &[u8]) -> Vec<u8> {
    if pat.is_empty() || pat[0] != b'~' {
        return pat.to_vec();
    }

    // Find end of username (next / or end)
    let end = pat[1..]
        .iter()
        .position(|&b| b == b'/')
        .map_or(pat.len(), |p| p + 1);

    if end == 1 {
        // Just ~ or ~/... — use $HOME.
        if let Ok(home) = std::env::var("HOME") {
            let mut result = home.into_bytes();
            result.extend_from_slice(&pat[1..]);
            return result;
        }
    }
    // ~user expansion not supported; return as-is.
    pat.to_vec()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_magic() {
        assert!(!has_magic(b"hello", false));
        assert!(!has_magic(b"/usr/lib", false));
        assert!(has_magic(b"*.txt", false));
        assert!(has_magic(b"file?.log", false));
        assert!(has_magic(b"[abc]", false));
        assert!(!has_magic(b"\\*escaped", false));
        assert!(has_magic(b"\\*", true));
    }

    #[test]
    fn test_split_pattern() {
        let (dir, tail) = split_pattern(b"/usr/lib/*.so");
        assert_eq!(dir, b"/usr/lib/");
        assert_eq!(tail, b"*.so");

        let (dir, tail) = split_pattern(b"*.txt");
        assert_eq!(dir, b"");
        assert_eq!(tail, b"*.txt");

        let (dir, tail) = split_pattern(b"/absolute/path");
        assert_eq!(dir, b"/absolute/");
        assert_eq!(tail, b"path");
    }

    #[test]
    fn test_fnmatch_component_basic() {
        assert!(fnmatch_component(b"*", b"hello", false));
        assert!(fnmatch_component(b"*.txt", b"file.txt", false));
        assert!(!fnmatch_component(b"*.txt", b"file.rs", false));
        assert!(fnmatch_component(b"file?", b"file1", false));
        assert!(!fnmatch_component(b"file?", b"file12", false));
        assert!(fnmatch_component(b"hello", b"hello", false));
        assert!(!fnmatch_component(b"hello", b"world", false));
    }

    #[test]
    fn test_fnmatch_component_brackets() {
        assert!(fnmatch_component(b"[abc]", b"a", false));
        assert!(fnmatch_component(b"[abc]", b"b", false));
        assert!(!fnmatch_component(b"[abc]", b"d", false));
        assert!(fnmatch_component(b"[a-z]", b"m", false));
        assert!(!fnmatch_component(b"[a-z]", b"M", false));
        assert!(fnmatch_component(b"[!abc]", b"d", false));
        assert!(!fnmatch_component(b"[!abc]", b"a", false));
    }

    #[test]
    fn test_fnmatch_component_escape() {
        assert!(fnmatch_component(b"\\*", b"*", false));
        assert!(!fnmatch_component(b"\\*", b"hello", false));
        // With noescape, backslash is literal
        assert!(!fnmatch_component(b"\\*", b"*", true));
        assert!(fnmatch_component(b"\\*", b"\\anything", true));
    }

    #[test]
    fn test_glob_expand_literal() {
        // A literal pattern that exists
        let result = glob_expand(b"/tmp\0", 0);
        assert!(result.is_ok());
        let res = result.unwrap();
        assert_eq!(res.paths.len(), 1);
        assert_eq!(res.paths[0], b"/tmp");
    }

    #[test]
    fn test_glob_expand_nonexistent_nocheck() {
        let result = glob_expand(b"/nonexistent_path_xyz\0", GLOB_NOCHECK);
        assert!(result.is_ok());
        let res = result.unwrap();
        assert_eq!(res.paths.len(), 1);
        assert_eq!(res.paths[0], b"/nonexistent_path_xyz");
    }

    #[test]
    fn test_glob_expand_nonexistent_nomatch() {
        let result = glob_expand(b"/nonexistent_path_xyz\0", 0);
        assert_eq!(result.unwrap_err(), GLOB_NOMATCH);
    }

    #[test]
    fn test_glob_expand_wildcard() {
        // /tmp should exist and contain entries
        let result = glob_expand(b"/tmp/*\0", 0);
        // On most systems /tmp has at least something; if not, NOMATCH is ok
        match result {
            Ok(res) => {
                assert!(!res.paths.is_empty());
                // All paths should start with /tmp/
                for p in &res.paths {
                    assert!(p.starts_with(b"/tmp/"));
                }
                // Should be sorted
                for w in res.paths.windows(2) {
                    assert!(w[0] <= w[1]);
                }
            }
            Err(GLOB_NOMATCH) => {} // empty /tmp is fine
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_tilde_expansion() {
        let expanded = expand_tilde(b"~/test");
        if let Ok(home) = std::env::var("HOME") {
            let expected = format!("{home}/test");
            assert_eq!(expanded, expected.as_bytes());
        }
    }

    #[test]
    fn test_glob_mark() {
        let result = glob_expand(b"/tmp\0", GLOB_MARK);
        assert!(result.is_ok());
        let res = result.unwrap();
        assert_eq!(res.paths.len(), 1);
        // /tmp is a directory, so GLOB_MARK appends /
        assert!(res.paths[0].ends_with(b"/"));
    }

    #[test]
    fn noescape_treats_backslash_star_as_magic() {
        let result = glob_expand(b"\\*\0", GLOB_NOESCAPE | GLOB_NOCHECK);
        assert!(result.is_ok());
        let res = result.unwrap();
        assert_eq!(res.paths, vec![b"\\*".to_vec()]);
        assert!(has_magic(b"\\*", true));
    }
}
