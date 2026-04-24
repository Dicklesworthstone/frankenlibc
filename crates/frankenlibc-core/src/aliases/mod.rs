//! `<aliases.h>` — sendmail-style /etc/aliases parser.
//!
//! Pure-safe Rust port of the byte-slice logic that previously lived
//! inline in frankenlibc-abi/src/unistd_abi.rs::parse_aliases_line.
//!
//! `/etc/aliases` line shape:
//!   `<name>: <member1>, <member2>, ...`
//!
//! Lines beginning with `#` (after leading whitespace) are comments
//! and yield `None`. The line may also contain a trailing comment
//! after `#`; everything from `#` onward is stripped before parsing.

/// Parsed aliases-file entry.
///
/// Owned-Vec form so the entry can be stored or returned by lookup
/// helpers without borrowing the caller's content slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasEntry {
    /// Alias name (left of the `:`, trimmed).
    pub name: Vec<u8>,
    /// Member targets (comma-separated after `:`, each trimmed).
    /// Empty members are filtered out.
    pub members: Vec<Vec<u8>>,
}

/// Parse a single line from /etc/aliases.
///
/// Returns `None` for blank, comment-only, or malformed lines (no `:`,
/// empty name).
pub fn parse_aliases_line(line: &[u8]) -> Option<AliasEntry> {
    // Strip inline comments
    let line = if let Some(pos) = line.iter().position(|&b| b == b'#') {
        &line[..pos]
    } else {
        line
    };
    // Strip trailing whitespace and EOL bytes
    let line = trim_trailing_ws(line);

    // Find colon separator
    let colon = line.iter().position(|&b| b == b':')?;
    let name = trim_ascii(&line[..colon]);
    if name.is_empty() {
        return None;
    }

    // Parse comma-separated members after colon
    let rest = &line[colon + 1..];
    let members: Vec<Vec<u8>> = rest
        .split(|&b| b == b',')
        .filter_map(|m| {
            let m = trim_ascii(m);
            if m.is_empty() { None } else { Some(m.to_vec()) }
        })
        .collect();

    Some(AliasEntry {
        name: name.to_vec(),
        members,
    })
}

/// Look up an alias entry by name in /etc/aliases content.
///
/// Returns the first matching entry. Names are matched
/// case-insensitively per RFC 5321 (mailbox local-parts are
/// technically case-sensitive but in practice every MTA folds them).
pub fn lookup_alias_by_name(content: &[u8], name: &[u8]) -> Option<AliasEntry> {
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = parse_aliases_line(line)
            && eq_ignore_ascii_case(&entry.name, name)
        {
            return Some(entry);
        }
    }
    None
}

/// Parse all valid alias entries from a /etc/aliases buffer.
pub fn parse_all_aliases(content: &[u8]) -> Vec<AliasEntry> {
    let mut out = Vec::new();
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = parse_aliases_line(line) {
            out.push(entry);
        }
    }
    out
}

fn trim_trailing_ws(s: &[u8]) -> &[u8] {
    let mut end = s.len();
    while end > 0 && matches!(s[end - 1], b' ' | b'\t' | b'\n' | b'\r') {
        end -= 1;
    }
    &s[..end]
}

fn trim_ascii(s: &[u8]) -> &[u8] {
    let start = s
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(s.len());
    let mut end = s.len();
    while end > start && matches!(s[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    &s[start..end]
}

fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_one_member() {
        let e = parse_aliases_line(b"postmaster: root").unwrap();
        assert_eq!(e.name, b"postmaster");
        assert_eq!(e.members, vec![b"root".to_vec()]);
    }

    #[test]
    fn parse_multiple_members() {
        let e = parse_aliases_line(b"webteam: alice, bob, carol").unwrap();
        assert_eq!(e.name, b"webteam");
        assert_eq!(
            e.members,
            vec![b"alice".to_vec(), b"bob".to_vec(), b"carol".to_vec()]
        );
    }

    #[test]
    fn parse_strips_inline_comment() {
        let e = parse_aliases_line(b"foo: bar # this is a comment").unwrap();
        assert_eq!(e.name, b"foo");
        assert_eq!(e.members, vec![b"bar".to_vec()]);
    }

    #[test]
    fn parse_skips_comment_only_line() {
        assert!(parse_aliases_line(b"# this is just a comment").is_none());
        assert!(parse_aliases_line(b"   # leading ws comment").is_none());
        assert!(parse_aliases_line(b"\t# tab indent").is_none());
    }

    #[test]
    fn parse_skips_blank_line() {
        assert!(parse_aliases_line(b"").is_none());
        assert!(parse_aliases_line(b"   ").is_none());
        assert!(parse_aliases_line(b"\t\n").is_none());
    }

    #[test]
    fn parse_rejects_missing_colon() {
        assert!(parse_aliases_line(b"foo bar baz").is_none());
    }

    #[test]
    fn parse_rejects_empty_name() {
        assert!(parse_aliases_line(b": bar").is_none());
        assert!(parse_aliases_line(b"   : bar").is_none());
    }

    #[test]
    fn parse_handles_leading_trailing_whitespace_in_name() {
        let e = parse_aliases_line(b"  hostmaster   : root").unwrap();
        assert_eq!(e.name, b"hostmaster");
    }

    #[test]
    fn parse_trims_member_whitespace() {
        let e = parse_aliases_line(b"team:  alice ,  bob  ,carol").unwrap();
        assert_eq!(
            e.members,
            vec![b"alice".to_vec(), b"bob".to_vec(), b"carol".to_vec()]
        );
    }

    #[test]
    fn parse_filters_empty_members() {
        let e = parse_aliases_line(b"x: a,,,b,").unwrap();
        assert_eq!(e.members, vec![b"a".to_vec(), b"b".to_vec()]);
    }

    #[test]
    fn parse_no_members_yields_empty_vec() {
        let e = parse_aliases_line(b"x:").unwrap();
        assert_eq!(e.name, b"x");
        assert!(e.members.is_empty());
    }

    #[test]
    fn parse_strips_trailing_newline_and_cr() {
        let e = parse_aliases_line(b"x: y\r\n").unwrap();
        assert_eq!(e.name, b"x");
        assert_eq!(e.members, vec![b"y".to_vec()]);
    }

    #[test]
    fn lookup_by_name_case_insensitive() {
        let content = b"postmaster: root\nwebmaster: alice, bob\n";
        let e = lookup_alias_by_name(content, b"WEBMASTER").unwrap();
        assert_eq!(e.name, b"webmaster");
        assert_eq!(e.members.len(), 2);
    }

    #[test]
    fn lookup_returns_first_match() {
        let content = b"foo: a\nfoo: b\n";
        let e = lookup_alias_by_name(content, b"foo").unwrap();
        assert_eq!(e.members, vec![b"a".to_vec()]);
    }

    #[test]
    fn lookup_returns_none_for_missing() {
        let content = b"foo: a\nbar: b\n";
        assert!(lookup_alias_by_name(content, b"baz").is_none());
    }

    #[test]
    fn lookup_skips_comment_and_blank_lines() {
        let content = b"# comment\n\nfoo: bar\n";
        let e = lookup_alias_by_name(content, b"foo").unwrap();
        assert_eq!(e.members, vec![b"bar".to_vec()]);
    }

    #[test]
    fn parse_all_collects_only_valid() {
        let content = b"# header\nfoo: a\nbad line\nbar: b, c\n\n";
        let entries = parse_all_aliases(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, b"foo");
        assert_eq!(entries[1].name, b"bar");
        assert_eq!(entries[1].members.len(), 2);
    }

    #[test]
    fn parse_real_world_aliases_line() {
        // Typical /etc/aliases entries
        let e = parse_aliases_line(b"abuse:    postmaster, security@example.com").unwrap();
        assert_eq!(e.name, b"abuse");
        assert_eq!(
            e.members,
            vec![b"postmaster".to_vec(), b"security@example.com".to_vec()]
        );
    }
}
