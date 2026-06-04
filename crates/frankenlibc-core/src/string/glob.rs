//! POSIX glob — pathname pattern expansion.
//!
//! Clean-room implementation of `glob()` per POSIX.1-2017 §12.
//! Uses `readdir`/`opendir` via std::fs and fnmatch-style pattern matching.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::fnmatch;

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
/// GNU `GLOB_BRACE`: expand `{a,b,...}` alternations before globbing. Value
/// matches glibc's `<glob.h>` (`GLOB_ALTDIRFUNC` 0x200 remains unimplemented;
/// see bd-2g7oyh.92).
pub const GLOB_BRACE: i32 = 0x400;
/// GNU `GLOB_NOMAGIC`: if the pattern contains no metacharacters, return it as
/// the sole match even when no file matches — like `GLOB_NOCHECK`, but only for
/// magic-free patterns (a magic pattern with no match still yields GLOB_NOMATCH
/// unless GLOB_NOCHECK is also set). Value matches glibc's `<glob.h>`.
pub const GLOB_NOMAGIC: i32 = 0x800;
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
///
/// Mirrors `has_magic` in honoring `GLOB_NOESCAPE`: under `noescape`, `\` is a
/// literal byte rather than an escape, so the metacharacter scan must not skip
/// past it. If it did, a pattern such as `foo\*bar/baz` would have its magic
/// `*` folded into the literal directory prefix and `read_dir` would be called
/// on the literal path `foo\*bar` instead of pattern-matching `foo\*bar` as a
/// directory-component pattern with `\` literal and `*` wild.
fn split_pattern(pat: &[u8], noescape: bool) -> (&[u8], &[u8]) {
    // Find the last '/' before the first metacharacter.
    let mut first_meta = pat.len();
    let mut i = 0;
    while i < pat.len() {
        if pat[i] == b'\\' && !noescape {
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
// fnmatch (single path component)
// ---------------------------------------------------------------------------

/// Match a single path component against `pat`.
///
/// Delegates to the shared POSIX fnmatch engine so bracket expressions —
/// ranges, `!`/`^` negation, `[[:alpha:]]` character classes, `[.x.]`
/// collating elements, and `\` escapes — all behave per POSIX. Path
/// components never contain `/`, and leading-`.` handling is performed by
/// the directory walk, so no `FNM_PATHNAME` / `FNM_PERIOD` flags are needed.
fn fnmatch_component(pat: &[u8], name: &[u8], noescape: bool) -> bool {
    let flags = if noescape {
        fnmatch::FnmatchFlags::NOESCAPE
    } else {
        fnmatch::FnmatchFlags::NONE
    };
    fnmatch::fnmatch_match(pat, name, flags)
}

// ---------------------------------------------------------------------------
// Directory reading and expansion
// ---------------------------------------------------------------------------

/// Expand a glob pattern and return matching paths.
///
pub fn glob_expand(pattern: &[u8], flags: i32) -> Result<GlobResult, i32> {
    glob_expand_with_error_handler(pattern, flags, |_, _| false)
}

/// Maximum brace-nesting recursion depth before brace expansion bails out.
/// Bounds stack use; glibc itself stack-overflows (SIGSEGV) on deeply nested
/// `{{{...}}}`, so a safe-Rust libc must cap this rather than crash.
const BRACE_MAX_DEPTH: usize = 256;
/// Maximum number of expanded patterns. Bounds the cartesian-product memory
/// blow-up of `{a,b}{a,b}...` (2^N); glibc OOMs/hangs, we return GLOB_NOSPACE.
const BRACE_MAX_EXPANSIONS: usize = 65_536;

/// Expand GNU brace alternations (`GLOB_BRACE`) into a list of concrete
/// patterns, matching glibc semantics: the leftmost balanced `{...}` group is
/// split on its top-level commas, each alternative is substituted into
/// prefix+alt+suffix, and the result is expanded recursively (yielding the
/// cartesian product across multiple groups and handling nesting). Braces with
/// no comma still expand (`{x}` -> `x`, `{}` -> ``); an unbalanced `{` or an
/// escaped `\{` is left literal. Numeric/alpha ranges (`{1..9}`) are NOT a
/// glibc GLOB_BRACE feature and remain literal.
///
/// Returns `Some(vec![pattern])` when no expansion applies, or `None` when the
/// pattern would exceed [`BRACE_MAX_DEPTH`] nesting or [`BRACE_MAX_EXPANSIONS`]
/// total expansions — a DoS guard the caller maps to `GLOB_NOSPACE`. (glibc has
/// no such guard and crashes/OOMs on these inputs.)
fn brace_expand(pat: &[u8], noescape: bool) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    brace_expand_into(pat, noescape, 0, &mut out)?;
    Some(out)
}

fn brace_expand_into(
    pat: &[u8],
    noescape: bool,
    depth: usize,
    out: &mut Vec<Vec<u8>>,
) -> Option<()> {
    if depth > BRACE_MAX_DEPTH || out.len() >= BRACE_MAX_EXPANSIONS {
        return None;
    }

    // Locate the first unescaped '{'.
    let mut i = 0;
    let open = loop {
        if i >= pat.len() {
            out.push(pat.to_vec()); // no brace -> literal
            return Some(());
        }
        let b = pat[i];
        if b == b'\\' && !noescape && i + 1 < pat.len() {
            i += 2;
            continue;
        }
        if b == b'{' {
            break i;
        }
        i += 1;
    };

    // Find the matching '}' (track nesting depth, respect escapes).
    let mut bdepth = 1;
    let mut j = open + 1;
    let close = loop {
        if j >= pat.len() {
            out.push(pat.to_vec()); // unbalanced -> literal
            return Some(());
        }
        let b = pat[j];
        if b == b'\\' && !noescape && j + 1 < pat.len() {
            j += 2;
            continue;
        }
        if b == b'{' {
            bdepth += 1;
        } else if b == b'}' {
            bdepth -= 1;
            if bdepth == 0 {
                break j;
            }
        }
        j += 1;
    };

    // Split the brace body on top-level commas.
    let inner = &pat[open + 1..close];
    let mut alts: Vec<&[u8]> = Vec::new();
    let mut start = 0;
    let mut d = 0;
    let mut k = 0;
    while k < inner.len() {
        let b = inner[k];
        if b == b'\\' && !noescape && k + 1 < inner.len() {
            k += 2;
            continue;
        }
        if b == b'{' {
            d += 1;
        } else if b == b'}' {
            d -= 1;
        } else if b == b',' && d == 0 {
            alts.push(&inner[start..k]);
            start = k + 1;
        }
        k += 1;
    }
    alts.push(&inner[start..]);

    let prefix = &pat[..open];
    let suffix = &pat[close + 1..];
    for alt in alts {
        let mut combined = Vec::with_capacity(prefix.len() + alt.len() + suffix.len());
        combined.extend_from_slice(prefix);
        combined.extend_from_slice(alt);
        combined.extend_from_slice(suffix);
        brace_expand_into(&combined, noescape, depth + 1, out)?;
    }
    Some(())
}

/// Expand a glob pattern and invoke `errfunc` on directory traversal errors.
///
/// The handler receives the path that failed and the raw OS errno. Returning
/// true requests POSIX `GLOB_ABORTED`; returning false lets traversal continue
/// unless `GLOB_ERR` is set.
pub fn glob_expand_with_error_handler<F>(
    pattern: &[u8],
    flags: i32,
    mut errfunc: F,
) -> Result<GlobResult, i32>
where
    F: FnMut(&[u8], i32) -> bool,
{
    glob_expand_dyn(pattern, flags, &mut errfunc)
}

// Non-generic core taking the error handler via dynamic dispatch so the
// GLOB_BRACE recursion (and glob_recursive) do not blow the monomorphization
// recursion limit by nesting `&mut F` ever deeper.
fn glob_expand_dyn(
    pattern: &[u8],
    flags: i32,
    errfunc: &mut dyn FnMut(&[u8], i32) -> bool,
) -> Result<GlobResult, i32> {
    // Find the pattern up to first null byte.
    let pat_len = pattern
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(pattern.len());
    let pat = &pattern[..pat_len];

    if pat.is_empty() {
        return Err(GLOB_NOMATCH);
    }

    // GLOB_BRACE: expand `{a,b,...}` alternations before globbing. Each expansion
    // is globbed independently and the per-expansion result batches are
    // concatenated in expansion order (no global re-sort, no de-duplication),
    // matching glibc. On a total no-match, GLOB_NOCHECK returns the original
    // (un-expanded) pattern. Done before tilde expansion so each expansion gets
    // its own tilde handling, exactly like glibc.
    if flags & GLOB_BRACE != 0 {
        let noescape = flags & GLOB_NOESCAPE != 0;
        // A pathological pattern (excessive brace nesting or cartesian blow-up)
        // returns None; surface it as GLOB_NOSPACE rather than crashing/OOMing.
        let expansions = match brace_expand(pat, noescape) {
            Some(e) => e,
            None => return Err(GLOB_NOSPACE),
        };
        if expansions.len() > 1 || expansions[0].as_slice() != pat {
            let inner_flags = flags & !(GLOB_BRACE | GLOB_NOCHECK | GLOB_APPEND);
            let mut combined: Vec<Vec<u8>> = Vec::new();
            for sub in &expansions {
                match glob_expand_dyn(sub, inner_flags, errfunc) {
                    Ok(res) => combined.extend(res.paths),
                    Err(GLOB_NOMATCH) => {}
                    Err(e) => return Err(e),
                }
            }
            if combined.is_empty() {
                if flags & GLOB_NOCHECK != 0 {
                    return Ok(GlobResult {
                        paths: vec![pat.to_vec()],
                    });
                }
                return Err(GLOB_NOMATCH);
            }
            return Ok(GlobResult { paths: combined });
        }
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
        // The pattern is magic-free, so both GLOB_NOCHECK and GLOB_NOMAGIC make
        // an absent pattern its own sole result (GLOB_NOMAGIC applies ONLY to
        // magic-free patterns, which is exactly this branch).
        if flags & (GLOB_NOCHECK | GLOB_NOMAGIC) != 0 {
            return Ok(GlobResult {
                paths: vec![pat.to_vec()],
            });
        }
        return Err(GLOB_NOMATCH);
    }

    let mut results = Vec::new();
    glob_recursive(b"", pat, flags, &mut results, errfunc)?;

    if results.is_empty() {
        if flags & GLOB_NOCHECK != 0 {
            return Ok(GlobResult {
                paths: vec![pat.to_vec()],
            });
        }
        return Err(GLOB_NOMATCH);
    }

    // Sort unless GLOB_NOSORT. glibc's glob() collates via strcoll() rather
    // than raw byte order so non-C locales sort by the user's collation rules.
    // Our strcoll currently degrades to strcmp under the C/POSIX locale (the
    // default), so behavior matches the previous byte-order sort there; this
    // routing means glob picks up real locale-aware collation automatically
    // when strcoll grows it.
    if flags & GLOB_NOSORT == 0 {
        results.sort_by(|a, b| super::str::strcoll(a, b).cmp(&0));
    }

    Ok(GlobResult { paths: results })
}

/// Recursively expand a glob pattern with directory traversal.
///
/// `resolved_prefix` is the already-resolved literal directory path produced by
/// matching outer pattern components (or empty at the top level). It is treated
/// as literal bytes and never re-split for metacharacters, so a real directory
/// whose name legally contains `*`, `?`, or `[` is not re-interpreted as a
/// pattern on subsequent recursions. The previous design rebuilt the full path
/// (`resolved + name + "/" + rest`) and re-ran `split_pattern` on the whole
/// string, which let a literal `*` in a resolved directory name match
/// outer-level siblings and could recurse without progress.
fn glob_recursive(
    resolved_prefix: &[u8],
    pattern: &[u8],
    flags: i32,
    results: &mut Vec<Vec<u8>>,
    errfunc: &mut dyn FnMut(&[u8], i32) -> bool,
) -> Result<(), i32> {
    let noescape = flags & GLOB_NOESCAPE != 0;
    let (dir_prefix, tail) = split_pattern(pattern, noescape);

    // Split tail at the next '/' to get the component pattern.
    let (component_pat, rest) = match tail.iter().position(|&b| b == b'/') {
        Some(pos) => (&tail[..pos], &tail[pos + 1..]),
        None => (tail, &[] as &[u8]),
    };

    // The directory to read is the literal resolved_prefix concatenated with
    // the pattern's pre-magic literal prefix that split_pattern just returned.
    let mut full_dir = Vec::with_capacity(resolved_prefix.len() + dir_prefix.len());
    full_dir.extend_from_slice(resolved_prefix);
    full_dir.extend_from_slice(dir_prefix);

    let dir_path = if full_dir.is_empty() {
        Path::new(".")
    } else {
        Path::new(OsStr::from_bytes(&full_dir))
    };

    // Read directory entries.
    let entries = match std::fs::read_dir(dir_path) {
        Ok(e) => e,
        Err(error) => {
            let errno = error.raw_os_error().unwrap_or(crate::errno::EIO);
            if errno == crate::errno::ENOTDIR {
                return Ok(());
            }
            let failed_path = failed_directory_path(&full_dir);
            let callback_aborted = errfunc(&failed_path, errno);
            if callback_aborted || flags & GLOB_ERR != 0 {
                return Err(GLOB_ABORTED);
            }
            return Ok(());
        }
    };

    // Rust's `read_dir` never yields "." or "..", but glibc's `readdir` does,
    // and a component pattern that explicitly begins with '.' (e.g. ".*", ".",
    // "..") matches them. Re-introduce the two synthetic entries so glob results
    // match glibc exactly; `fnmatch_component` below still filters them, so they
    // only appear when the pattern actually matches.
    let mut names: Vec<Vec<u8>> = Vec::new();
    if component_pat.first() == Some(&b'.') {
        names.push(b".".to_vec());
        names.push(b"..".to_vec());
    }
    for entry in entries.flatten() {
        names.push(entry.file_name().as_bytes().to_vec());
    }

    for name_bytes in &names {
        let name_bytes = name_bytes.as_slice();

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

        // Build the full path = resolved_prefix + dir_prefix + name.
        let mut full_path = Vec::with_capacity(full_dir.len() + name_bytes.len());
        full_path.extend_from_slice(&full_dir);
        full_path.extend_from_slice(name_bytes);

        // Resolve whether this entry is (or points to) a directory.
        // `DirEntry::file_type()` reflects `lstat` — it does NOT follow
        // symlinks, so a symlink-to-directory would report as a plain
        // symlink. glibc's glob() stats (follows symlinks) here, so a
        // symlinked directory is traversed for intermediate components,
        // gets a trailing '/' under GLOB_MARK, and is accepted under
        // GLOB_ONLYDIR. Use a symlink-following stat to match. A broken
        // symlink errors out and is treated as a non-directory.
        let resolves_to_dir = std::fs::metadata(Path::new(OsStr::from_bytes(&full_path)))
            .map(|m| m.is_dir())
            .unwrap_or(false);

        if rest.is_empty() {
            // No more pattern components — this is a final match.
            if flags & GLOB_ONLYDIR != 0 && !resolves_to_dir {
                continue;
            }
            if flags & GLOB_MARK != 0 && resolves_to_dir {
                full_path.push(b'/');
            }
            results.push(full_path);
        } else if resolves_to_dir {
            // More pattern components remain — recurse with the matched
            // directory absorbed into resolved_prefix (treated as literal),
            // and `rest` as the new pattern to split. This prevents
            // metacharacters in the resolved name (`*`, `?`, `[` are all
            // legal POSIX filename bytes) from being re-interpreted as
            // pattern syntax on subsequent recursions.
            full_path.push(b'/');
            glob_recursive(&full_path, rest, flags, results, errfunc)?;
        }
    }

    Ok(())
}

fn failed_directory_path(dir_prefix: &[u8]) -> Vec<u8> {
    if dir_prefix.is_empty() {
        return b".".to_vec();
    }
    if dir_prefix.len() > 1 && dir_prefix.ends_with(b"/") {
        return dir_prefix[..dir_prefix.len() - 1].to_vec();
    }
    dir_prefix.to_vec()
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
    use std::os::unix::fs::PermissionsExt;

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
        let (dir, tail) = split_pattern(b"/usr/lib/*.so", false);
        assert_eq!(dir, b"/usr/lib/");
        assert_eq!(tail, b"*.so");

        let (dir, tail) = split_pattern(b"*.txt", false);
        assert_eq!(dir, b"");
        assert_eq!(tail, b"*.txt");

        let (dir, tail) = split_pattern(b"/absolute/path", false);
        assert_eq!(dir, b"/absolute/");
        assert_eq!(tail, b"path");
    }

    #[test]
    fn split_pattern_honors_glob_noescape() {
        // Without GLOB_NOESCAPE the backslash escapes the next byte, so the
        // metacharacter scan correctly skips past `\*` and `*` does not count
        // as magic; the whole prefix `foo\*bar/` is the literal directory.
        let (dir, tail) = split_pattern(b"foo\\*bar/baz", false);
        assert_eq!(dir, b"foo\\*bar/");
        assert_eq!(tail, b"baz");

        // Under GLOB_NOESCAPE the backslash is a literal byte; the `*` keeps
        // its magic meaning, so the literal directory prefix is empty (there
        // is no `/` before the first metacharacter).
        let (dir, tail) = split_pattern(b"foo\\*bar/baz", true);
        assert_eq!(dir, b"");
        assert_eq!(tail, b"foo\\*bar/baz");

        // Agreement with has_magic, which is the contract this split assumes.
        assert!(has_magic(b"foo\\*bar/baz", true));
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
    fn test_fnmatch_component_posix_classes() {
        // POSIX character classes inside bracket expressions (bd-u1358).
        assert!(fnmatch_component(b"[[:digit:]]", b"7", false));
        assert!(!fnmatch_component(b"[[:digit:]]", b"x", false));
        assert!(fnmatch_component(
            b"file[[:digit:]].txt",
            b"file3.txt",
            false
        ));
        assert!(!fnmatch_component(
            b"file[[:digit:]].txt",
            b"filex.txt",
            false
        ));
        assert!(fnmatch_component(b"[[:alpha:]]*", b"hello", false));
        assert!(!fnmatch_component(b"[[:alpha:]]*", b"1abc", false));
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
    fn test_glob_nomagic_returns_magic_free_pattern() {
        // GLOB_NOMAGIC: a magic-free pattern with no match returns itself.
        let res = glob_expand(b"/nonexistent_path_xyz\0", GLOB_NOMAGIC).unwrap();
        assert_eq!(res.paths.len(), 1);
        assert_eq!(res.paths[0], b"/nonexistent_path_xyz");
    }

    #[test]
    fn test_glob_nomagic_does_not_apply_to_magic_pattern() {
        // GLOB_NOMAGIC applies ONLY to magic-free patterns; a no-match magic
        // pattern still yields GLOB_NOMATCH (unlike GLOB_NOCHECK).
        let result = glob_expand(b"/nonexistent_dir_xyz/*.nope\0", GLOB_NOMAGIC);
        assert_eq!(result.unwrap_err(), GLOB_NOMATCH);
        // GLOB_NOCHECK on the same magic pattern DOES return the pattern.
        let res = glob_expand(b"/nonexistent_dir_xyz/*.nope\0", GLOB_NOCHECK).unwrap();
        assert_eq!(res.paths[0], b"/nonexistent_dir_xyz/*.nope");
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
    fn directory_error_callback_can_abort() {
        let (blocked_dir, pattern) = unreadable_directory_pattern("errfunc_abort");

        let mut calls = 0;
        let mut observed_path = Vec::new();
        let mut observed_errno = 0;
        let result = glob_expand_with_error_handler(&pattern, 0, |path, errno| {
            calls += 1;
            observed_path = path.to_vec();
            observed_errno = errno;
            true
        });
        restore_directory(&blocked_dir);

        assert_eq!(result.unwrap_err(), GLOB_ABORTED);
        assert_eq!(calls, 1);
        assert_eq!(observed_path, blocked_dir.as_os_str().as_bytes());
        assert_ne!(observed_errno, 0);
    }

    #[test]
    fn directory_error_callback_can_continue() {
        let (blocked_dir, pattern) = unreadable_directory_pattern("errfunc_continue");

        let mut calls = 0;
        let result = glob_expand_with_error_handler(&pattern, 0, |_, _| {
            calls += 1;
            false
        });
        restore_directory(&blocked_dir);

        assert_eq!(result.unwrap_err(), GLOB_NOMATCH);
        assert_eq!(calls, 1);
    }

    #[test]
    fn glob_err_aborts_after_callback() {
        let (blocked_dir, pattern) = unreadable_directory_pattern("errfunc_glob_err");

        let mut calls = 0;
        let result = glob_expand_with_error_handler(&pattern, GLOB_ERR, |_, _| {
            calls += 1;
            false
        });
        restore_directory(&blocked_dir);

        assert_eq!(result.unwrap_err(), GLOB_ABORTED);
        assert_eq!(calls, 1);
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
        let temp = unique_glob_test_dir("noescape");
        std::fs::create_dir_all(&temp).unwrap();
        let escaped_name = b"\\alpha";
        let escaped_path = temp.join(OsStr::from_bytes(escaped_name));
        std::fs::write(&escaped_path, b"test").unwrap();

        let mut pattern = temp.as_os_str().as_bytes().to_vec();
        pattern.extend_from_slice(b"/\\*\0");

        let result = glob_expand(&pattern, GLOB_NOESCAPE);
        assert!(result.is_ok(), "pattern should be treated as magic");
        let res = result.unwrap();
        assert_eq!(res.paths.len(), 1);
        assert_eq!(res.paths[0], escaped_path.as_os_str().as_bytes());
        assert!(has_magic(b"\\*", true));
    }

    #[test]
    fn glob_traverses_and_marks_symlinked_directories() {
        // glibc's glob() stats (follows symlinks) when deciding whether an
        // entry is a directory, so a symlink-to-directory is recursed into
        // for intermediate components and marked with '/' under GLOB_MARK.
        // A regression guard: DirEntry::file_type() does not follow symlinks.
        let temp = unique_glob_test_dir("symlink_dir");
        let real_dir = temp.join("realdir");
        std::fs::create_dir_all(&real_dir).unwrap();
        std::fs::write(real_dir.join("target.txt"), b"hi").unwrap();
        let link_dir = temp.join("linkdir");
        std::os::unix::fs::symlink("realdir", &link_dir).unwrap();

        // Intermediate component: must recurse through the symlink.
        let mut recurse_pat = temp.as_os_str().as_bytes().to_vec();
        recurse_pat.extend_from_slice(b"/linkdir/*\0");
        let res = glob_expand(&recurse_pat, 0).expect("symlinked dir must be traversed");
        assert_eq!(res.paths.len(), 1);
        assert!(res.paths[0].ends_with(b"/linkdir/target.txt"));

        // GLOB_MARK: the symlink-to-directory must get a trailing '/'.
        let mut mark_pat = temp.as_os_str().as_bytes().to_vec();
        mark_pat.extend_from_slice(b"/link*\0");
        let marked = glob_expand(&mark_pat, GLOB_MARK).expect("linkdir must match");
        assert_eq!(marked.paths.len(), 1);
        assert!(
            marked.paths[0].ends_with(b"/"),
            "symlinked directory must be marked with trailing slash"
        );

        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn glob_expand_sorts_via_strcoll() {
        // glibc's glob() collates results via strcoll() rather than raw byte
        // order; FrankenLibC's strcoll degrades to strcmp under the C/POSIX
        // locale so the ordering still matches byte order. This regression
        // pins that the routing exists (glob_expand calls strcoll, not just
        // Vec::sort), and that under the default locale ordering is the
        // expected C-locale byte order with uppercase ASCII before lowercase.
        let temp = unique_glob_test_dir("strcoll_sort");
        std::fs::create_dir_all(&temp).unwrap();
        for name in [b"Apple" as &[u8], b"banana", b"Cherry", b"apple"] {
            std::fs::write(temp.join(OsStr::from_bytes(name)), b"").unwrap();
        }

        let mut pat = temp.as_os_str().as_bytes().to_vec();
        pat.extend_from_slice(b"/*\0");
        let res = glob_expand(&pat, 0).expect("glob must match files");
        let basenames: Vec<&[u8]> = res
            .paths
            .iter()
            .map(|p| p.rsplit(|&b| b == b'/').next().unwrap_or(p))
            .collect();

        // C-locale strcmp byte order: uppercase ASCII (0x41..) precedes
        // lowercase ASCII (0x61..).
        assert_eq!(
            basenames,
            vec![&b"Apple"[..], b"Cherry", b"apple", b"banana"],
            "glob results must collate via strcoll (byte order under C locale)"
        );

        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn glob_does_not_reinterpret_resolved_directory_names_as_patterns() {
        // A real directory whose name legally contains a glob metacharacter
        // (here `*`) must not be re-interpreted as a pattern when the glob
        // recursion descends through it. The previous design rebuilt the
        // full path (`dir_prefix + name + "/" + rest`) and re-ran
        // `split_pattern` on the whole string, which let the literal `*` in
        // the resolved name re-match outer-level siblings on each recursion
        // and could recurse without progress (effectively unbounded).
        let temp = unique_glob_test_dir("literal_star_dir");
        let star_dir = temp.join("a*b");
        let sibling = temp.join("axxb");
        std::fs::create_dir_all(&star_dir).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        std::fs::write(star_dir.join("inside.txt"), b"target").unwrap();
        std::fs::write(sibling.join("inside.txt"), b"decoy").unwrap();

        // Outer-level pattern `a*b` legitimately matches both `a*b` (a
        // wildcard-style match against the literal `*` in the name) and
        // `axxb`; within each, `inside.txt` is matched literally. What must
        // NOT happen is unbounded recursion or duplicate hits from
        // re-running the splitter on the resolved name.
        let mut pat = temp.as_os_str().as_bytes().to_vec();
        pat.extend_from_slice(b"/a*b/inside.txt\0");

        let res = glob_expand(&pat, 0).expect("must match across both real dirs");
        let mut found: Vec<&[u8]> = res.paths.iter().map(|p| p.as_slice()).collect();
        found.sort();
        assert_eq!(found.len(), 2, "got {:?}", res.paths);
        assert!(found[0].ends_with(b"/a*b/inside.txt"));
        assert!(found[1].ends_with(b"/axxb/inside.txt"));

        let _ = std::fs::remove_dir_all(&temp);
    }

    fn unique_glob_test_dir(name: &str) -> std::path::PathBuf {
        let unique = format!(
            "frankenlibc_glob_{name}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }

    fn unreadable_directory_pattern(name: &str) -> (std::path::PathBuf, Vec<u8>) {
        let temp = unique_glob_test_dir(name);
        let blocked_dir = temp.join("blocked");
        std::fs::create_dir_all(&blocked_dir).unwrap();
        set_directory_mode(&blocked_dir, 0o000);

        let mut pattern = blocked_dir.as_os_str().as_bytes().to_vec();
        pattern.extend_from_slice(b"/*\0");
        (blocked_dir, pattern)
    }

    fn restore_directory(path: &std::path::Path) {
        set_directory_mode(path, 0o700);
    }

    fn set_directory_mode(path: &std::path::Path, mode: u32) {
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(mode);
        std::fs::set_permissions(path, permissions).unwrap();
    }
}
