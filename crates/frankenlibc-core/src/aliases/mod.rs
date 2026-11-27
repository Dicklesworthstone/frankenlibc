//! `<aliases.h>` — sendmail-style /etc/aliases parser.
//!
//! Logical records have the form `<name>: <member1>, <member2>, ...`.
//! A following physical line beginning with whitespace continues the record;
//! a bare newline does not. Each physical line ends at its first comment,
//! newline or NUL. GNU files lookups remove leading whitespace from names and
//! members but preserve trailing whitespace, including a carriage return.
//!
//! [`next_alias`] and [`lookup_alias_by_name_with_includes`] accept an include
//! reader supplied by the ABI. The core performs no I/O. Included files contain
//! member lists, not alias definitions: their `:include:` tokens stay literal.
//! Expansion is therefore one level deep and cannot recurse through cycles.

/// Parsed aliases-file entry.
///
/// Owned-Vec form so the entry can be stored or returned by lookup
/// helpers without borrowing the caller's content slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasEntry {
    /// Alias name (left of the `:`, with leading whitespace removed).
    pub name: Vec<u8>,
    /// Member targets with leading whitespace removed and trailing bytes intact.
    /// Empty members are filtered out.
    pub members: Vec<Vec<u8>>,
}

/// Parse a single line from /etc/aliases.
///
/// Returns `None` for blank, comment-only, or malformed lines (no `:`,
/// empty name). This physical-line helper retains literal include directives;
/// use [`next_alias`] for complete records and include expansion.
pub fn parse_aliases_line(line: &[u8]) -> Option<AliasEntry> {
    let (name, rest) = alias_header(line)?;
    Some(AliasEntry {
        name: name.to_vec(),
        members: member_tokens(rest).map(<[u8]>::to_vec).collect(),
    })
}

/// Read the next nonempty logical alias, advancing `offset` past its complete
/// physical record. Start with offset zero; an exhausted or out-of-range cursor
/// returns `None`. Empty, comment-only and malformed records are skipped.
///
/// `include` receives the bytes immediately after `:include:` without path
/// normalization or whitespace rewriting. `None` omits an unavailable include;
/// the ABI owns any resulting I/O error side effects. Includes are expanded in
/// place and their individual lines are comma-separated member lists.
pub fn next_alias(
    content: &[u8],
    offset: &mut usize,
    mut include: impl FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Option<AliasEntry> {
    next_matching_alias(content, offset, None, &mut include)
}

/// Look up an alias entry by name in /etc/aliases content.
///
/// Returns the first nonempty matching record using GNU's ASCII-insensitive
/// lookup. Includes are unavailable to this I/O-free convenience function.
pub fn lookup_alias_by_name(content: &[u8], name: &[u8]) -> Option<AliasEntry> {
    lookup_alias_by_name_with_includes(content, name, |_| None)
}

/// Look up a logical alias with includes. Nonmatching records are skipped
/// before their include reader is invoked, preserving the files provider's
/// lookup behavior even when another record names an inaccessible include.
pub fn lookup_alias_by_name_with_includes(
    content: &[u8],
    name: &[u8],
    mut include: impl FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Option<AliasEntry> {
    let mut offset = 0;
    next_matching_alias(content, &mut offset, Some(name), &mut include)
}

/// Parse all valid alias entries from a /etc/aliases buffer.
pub fn parse_all_aliases(content: &[u8]) -> Vec<AliasEntry> {
    let mut out = Vec::new();
    let mut offset = 0;
    while let Some(entry) = next_alias(content, &mut offset, |_| None) {
        out.push(entry);
    }
    out
}

fn next_matching_alias(
    content: &[u8],
    offset: &mut usize,
    wanted: Option<&[u8]>,
    include: &mut impl FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Option<AliasEntry> {
    while let Some(line) = physical_line(content, offset) {
        let Some((name, rest)) = alias_header(line) else {
            continue;
        };
        let selected = wanted.is_none_or(|wanted| name.eq_ignore_ascii_case(wanted));
        let mut members = Vec::new();
        if selected {
            append_members(rest, &mut members, include);
        }
        while content
            .get(*offset)
            .is_some_and(|&byte| byte != b'\n' && is_space(byte))
        {
            let line = physical_line(content, offset)?;
            if selected {
                append_members(line, &mut members, include);
            }
        }
        if selected && !members.is_empty() {
            return Some(AliasEntry {
                name: name.to_vec(),
                members,
            });
        }
    }
    None
}

fn append_members(
    line: &[u8],
    members: &mut Vec<Vec<u8>>,
    include: &mut impl FnMut(&[u8]) -> Option<Vec<u8>>,
) {
    for member in member_tokens(line) {
        if let Some(path) = member.strip_prefix(b":include:") {
            if let Some(content) = include(path) {
                for line in content.split(|&byte| byte == b'\n') {
                    // Included text is a member list. Never call include here:
                    // a nested directive is a literal member in GNU's backend.
                    members.extend(member_tokens(line).map(<[u8]>::to_vec));
                }
            }
        } else {
            members.push(member.to_vec());
        }
    }
}

fn physical_line<'a>(content: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let tail = content.get(*offset..)?;
    if tail.is_empty() {
        return None;
    }
    let length = tail
        .iter()
        .position(|&byte| byte == b'\n')
        .map_or(tail.len(), |newline| newline + 1);
    // length is bounded by content.len() - offset, so this cannot overflow.
    *offset += length;
    Some(&tail[..length])
}

fn alias_header(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let line = trim_leading(text(line));
    let colon = line.iter().position(|&byte| byte == b':')?;
    (colon != 0).then_some((&line[..colon], &line[colon + 1..]))
}

fn member_tokens(line: &[u8]) -> impl Iterator<Item = &[u8]> {
    text(line)
        .split(|&byte| byte == b',')
        .map(trim_leading)
        .filter(|member| !member.is_empty())
}

fn text(line: &[u8]) -> &[u8] {
    let end = line
        .iter()
        .position(|byte| matches!(*byte, 0 | b'#' | b'\n'))
        .unwrap_or(line.len());
    &line[..end]
}

fn trim_leading(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&byte| !is_space(byte))
        .unwrap_or(bytes.len());
    &bytes[start..]
}

fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
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
        assert_eq!(e.members, vec![b"bar ".to_vec()]);
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
    fn parse_preserves_trailing_whitespace_in_name() {
        let e = parse_aliases_line(b"  hostmaster   : root").unwrap();
        assert_eq!(e.name, b"hostmaster   ");
    }

    #[test]
    fn parse_trims_only_leading_member_whitespace() {
        let e = parse_aliases_line(b"team:  alice ,  bob  ,carol").unwrap();
        assert_eq!(
            e.members,
            vec![b"alice ".to_vec(), b"bob  ".to_vec(), b"carol".to_vec()]
        );
    }

    #[test]
    fn parse_filters_empty_members() {
        let e = parse_aliases_line(b"x: a,,,b,").unwrap();
        assert_eq!(e.members, vec![b"a".to_vec(), b"b".to_vec()]);
    }

    #[test]
    fn parse_filters_whitespace_only_members() {
        let e = parse_aliases_line(b"x:  a,   ,\t,b  ,  ").unwrap();
        assert_eq!(e.members, vec![b"a".to_vec(), b"b  ".to_vec()]);
    }

    #[test]
    fn parse_no_members_yields_empty_vec() {
        let e = parse_aliases_line(b"x:").unwrap();
        assert_eq!(e.name, b"x");
        assert!(e.members.is_empty());
    }

    #[test]
    fn parse_strips_newline_but_preserves_member_cr() {
        let e = parse_aliases_line(b"x: y\r\n").unwrap();
        assert_eq!(e.name, b"x");
        assert_eq!(e.members, vec![b"y\r".to_vec()]);
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

    #[test]
    fn logical_record_folds_lines_without_requiring_commas() {
        let content = b"foo: alice\n  bob,\n\tcarol\nbar: dave\n";
        let mut offset = 0;
        let first = next_alias(content, &mut offset, |_| None).unwrap();
        assert_eq!(first.name, b"foo");
        assert_eq!(
            first.members,
            vec![b"alice".to_vec(), b"bob".to_vec(), b"carol".to_vec()]
        );
        assert_eq!(&content[offset..], b"bar: dave\n");
        assert_eq!(
            next_alias(content, &mut offset, |_| None).unwrap().name,
            b"bar"
        );
        assert_eq!(offset, content.len());
        assert!(next_alias(content, &mut offset, |_| None).is_none());
    }

    #[test]
    fn blank_and_unindented_comment_lines_end_a_record() {
        let content = b"foo: alice\n\n  ignored,member\nbar: bob\n# boundary\n  third: carol\n";
        let entries = parse_all_aliases(content);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].members, vec![b"alice".to_vec()]);
        assert_eq!(entries[1].members, vec![b"bob".to_vec()]);
        assert_eq!(entries[2].name, b"third");
    }

    #[test]
    fn indented_comments_and_whitespace_lines_continue_a_record() {
        let content = b"foo: alice # first\n  # next\n \n\tbob # last\nbar: end\n";
        let entries = parse_all_aliases(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].members,
            vec![b"alice ".to_vec(), b"bob ".to_vec()]
        );
    }

    #[test]
    fn physical_nul_ends_text_without_losing_continuations() {
        let content = b"foo: a\0b,c\n  d\nbar: q\n";
        let entries = parse_all_aliases(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].members, vec![b"a".to_vec(), b"d".to_vec()]);
    }

    #[test]
    fn includes_expand_in_place_once_and_leave_nested_directives_literal() {
        let content = b"foo: a,:include:/members,c\nbar: d\n";
        let mut paths = Vec::new();
        let mut offset = 0;
        let entry = next_alias(content, &mut offset, |path| {
            paths.push(path.to_vec());
            Some(b"alice, bob  # first\n carol,\tdave\n#skip\n:include:/members\n".to_vec())
        })
        .unwrap();
        assert_eq!(paths, vec![b"/members".to_vec()]);
        assert_eq!(
            entry.members,
            vec![
                b"a".to_vec(),
                b"alice".to_vec(),
                b"bob  ".to_vec(),
                b"carol".to_vec(),
                b"dave".to_vec(),
                b":include:/members".to_vec(),
                b"c".to_vec(),
            ]
        );
        assert_eq!(&content[offset..], b"bar: d\n");
    }

    #[test]
    fn include_paths_preserve_whitespace_and_missing_includes_are_omitted() {
        let mut paths = Vec::new();
        let entry = next_alias(b"foo: :include: /a, :include:/b ,end\n", &mut 0, |path| {
            paths.push(path.to_vec());
            None
        })
        .unwrap();
        assert_eq!(paths, vec![b" /a".to_vec(), b"/b ".to_vec()]);
        assert_eq!(entry.members, vec![b"end".to_vec()]);
    }

    #[test]
    fn lookup_skips_nonmatching_includes_before_io() {
        let content =
            b"other: :include:/must-not-read\n  :include:/also-skipped\nfoo: :include:/selected\n";
        let mut paths = Vec::new();
        let entry = lookup_alias_by_name_with_includes(content, b"FOO", |path| {
            paths.push(path.to_vec());
            Some(b"alice,bob\n".to_vec())
        })
        .unwrap();
        assert_eq!(entry.name, b"foo");
        assert_eq!(entry.members, vec![b"alice".to_vec(), b"bob".to_vec()]);
        assert_eq!(paths, vec![b"/selected".to_vec()]);
    }

    #[test]
    fn empty_logical_records_are_skipped_after_include_expansion() {
        let content = b"zero:\nmissing: :include:/absent\nfoo: alice\n";
        let entries = parse_all_aliases(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, b"foo");
        assert!(lookup_alias_by_name(content, b"zero").is_none());
        assert!(lookup_alias_by_name(content, b"missing").is_none());
    }

    #[test]
    fn whitespace_in_names_is_significant_to_lookup() {
        let content = b"  foo   : alice\n";
        assert!(lookup_alias_by_name(content, b"foo").is_none());
        assert_eq!(
            lookup_alias_by_name(content, b"FOO   ").unwrap().name,
            b"foo   "
        );
    }

    #[test]
    fn trailing_continuation_and_invalid_cursor_are_bounded() {
        let content = b"foo: alice\n \t";
        let mut offset = 0;
        let entry = next_alias(content, &mut offset, |_| None).unwrap();
        assert_eq!(entry.members, vec![b"alice".to_vec()]);
        assert_eq!(offset, content.len());
        let mut invalid = usize::MAX;
        assert!(next_alias(content, &mut invalid, |_| None).is_none());
        assert!(next_alias(b"", &mut 0, |_| None).is_none());
    }

    #[test]
    fn logical_records_have_no_fixed_name_or_member_limit() {
        let name = vec![b'x'; 400];
        let mut content = name.clone();
        content.extend_from_slice(b": first\n");
        for _ in 0..100 {
            content.extend_from_slice(b"  another\n");
        }
        let entry = next_alias(&content, &mut 0, |_| None).unwrap();
        assert_eq!(entry.name, name);
        assert_eq!(entry.members.len(), 101);
        assert_eq!(entry.members[100], b"another");
    }
}
