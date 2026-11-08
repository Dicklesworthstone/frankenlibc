//! `<netgroup.h>` — /etc/netgroup triple parser.
//!
//! Pure-safe Rust port of the byte-slice logic that previously lived
//! inline in frankenlibc-abi/src/unistd_abi.rs::parse_netgroup_triples.
//!
//! `/etc/netgroup` line shape:
//!   `<groupname> (<host>,<user>,<domain>) (<host>,<user>,<domain>) ...`
//!
//! Fields within parentheses can be empty (denoting a wildcard). Group
//! lines may also include other group names as bare tokens (group
//! references).
//!
//! [`parse_netgroup_triples`] returns only the triples written in the group's
//! first logical record and IGNORES those references. It used to claim that
//! matched "the minimal glibc files-backend behavior"; it does not — see
//! [`expand_netgroup`], which follows them the way the incumbent does.

use std::borrow::Cow;

/// Parsed netgroup triple.
///
/// All three fields are owned byte vectors. An empty field denotes a
/// wildcard (matches anything).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetgroupTriple {
    pub host: Vec<u8>,
    pub user: Vec<u8>,
    pub domain: Vec<u8>,
}

/// Parse triples for the named group from a /etc/netgroup buffer.
///
/// Returns an empty `Vec` when `group` is not present. The first definition
/// wins, including an empty one; backslash-newline continues its body. Group
/// names start at the beginning of a physical line and match byte-exactly.
/// A `#` in the body is an ordinary reference token, not an inline comment.
///
/// Each `(host,user,domain)` triple is extracted as it appears;
/// per-field whitespace delimits the value and missing trailing fields
/// default to empty.
pub fn parse_netgroup_triples(content: &[u8], group: &[u8]) -> Vec<NetgroupTriple> {
    let mut result = Vec::new();
    if let Some(body) = group_body(content, group) {
        extract_triples_into(&body, &mut result);
    }
    result
}

/// Whether the files backend knows this group, including an empty group.
///
/// NSS distinguishes a present group with no triples (SUCCESS) from a missing
/// group (NOTFOUND). Both expand to an empty vector, so callers must not infer
/// the lookup status from the expanded members.
#[must_use]
pub fn contains_netgroup(content: &[u8], group: &[u8]) -> bool {
    group_body(content, group).is_some()
}

/// Select the first complete logical record for a name. Every record's
/// continuation chain is consumed before considering the next name, even when
/// the record is unrelated or looks like a comment. Otherwise a continued line
/// could become a false independent group. GNU's files backend keeps the name
/// on the first physical line and treats body continuation boundaries as spaces.
fn group_body<'a>(content: &'a [u8], group: &[u8]) -> Option<Cow<'a, [u8]>> {
    if group.is_empty() {
        return None;
    }

    let mut start = 0;
    while start < content.len() {
        let first_end = physical_line_end(content, start);
        let first = &content[start..first_end];
        let name_end = first
            .iter()
            .position(u8::is_ascii_whitespace)
            .unwrap_or(first.len());
        let mut end = first_end;
        while end < content.len() && end > start && content[end - 1] == b'\\' {
            end = physical_line_end(content, end + 1);
        }
        let next = if end < content.len() { end + 1 } else { end };

        if name_end != 0 && netgroup_name_matches(&first[..name_end], group) {
            let body = &content[start + name_end..end];
            if end == first_end {
                return Some(Cow::Borrowed(body));
            }
            // Joining only shortens the source span; capacity is bounded by
            // the input length, and unrelated records never allocate a body.
            let mut joined = Vec::with_capacity(body.len());
            let mut cursor = 0;
            while cursor < body.len() {
                if body[cursor] == b'\\' && cursor + 1 < body.len() && body[cursor + 1] == b'\n' {
                    joined.push(b' ');
                    cursor += 2;
                } else {
                    joined.push(body[cursor]);
                    cursor += 1;
                }
            }
            return Some(Cow::Owned(joined));
        }
        start = next;
    }
    None
}

fn physical_line_end(content: &[u8], start: usize) -> usize {
    content[start..]
        .iter()
        .position(|&byte| byte == b'\n')
        .map_or(content.len(), |length| start + length)
}

/// Expand a netgroup, following NESTED GROUP REFERENCES.
///
/// A /etc/netgroup line may name other groups as bare tokens beside its
/// parenthesised triples, and their members belong to this group too.
/// [`parse_netgroup_triples`] ignores those tokens; this walks them.
///
/// glibc DOES follow them, which is measurable without an /etc/netgroup file:
/// `_nss_netgroup_parseline` tests the token's first byte against `'('`
/// (libc.so.6 at +0x6a) and, when it is not a paren, scans the bare token and
/// stores `type = 1` — `group_val` in glibc's `struct __netgrent` — together
/// with the name pointer, returning success. The caller then expands it, which
/// is what `innetgr`'s malloc/free worklist is for. fl's doc previously claimed
/// ignoring these tokens "matches the minimal glibc files-backend behavior";
/// the incumbent's own code refutes that.
///
/// CYCLES ARE THE REASON FOR THE VISITED SET, not defensive habit: netgroup
/// references may legitimately form a cycle (`a` names `b`, `b` names `a`), and
/// glibc keeps a "known groups" list for exactly this. Without one this walk
/// would not terminate.
///
/// Group names are matched byte-exactly, the same rule
/// [`parse_netgroup_triples`] uses for the top-level name.
#[must_use]
pub fn expand_netgroup(content: &[u8], group: &[u8]) -> Vec<NetgroupTriple> {
    let mut out = Vec::new();
    let mut visited: Vec<Vec<u8>> = Vec::new();
    let mut pending: Vec<Vec<u8>> = vec![group.to_vec()];

    while let Some(name) = pending.pop() {
        if visited
            .iter()
            .any(|seen| netgroup_name_matches(seen, &name))
        {
            continue;
        }
        visited.push(name.clone());

        if let Some(body) = group_body(content, &name) {
            extract_triples_into(&body, &mut out);
            collect_group_refs_into(&body, &mut pending);
        }
    }
    out
}

/// Collect the bare tokens on a netgroup line — the nested group references.
///
/// Everything that is not part of a `(...)` triple is a group name. The scan
/// skips parenthesised spans wholesale so a host or user containing spaces
/// cannot be mistaken for a reference.
fn collect_group_refs_into(bytes: &[u8], out: &mut Vec<Vec<u8>>) {
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            byte if byte.is_ascii_whitespace() => i += 1,
            b'(' => {
                // Skip the whole triple, closing paren included.
                match bytes[i..].iter().position(|&b| b == b')') {
                    Some(close) => i += close + 1,
                    // Unclosed paren: the rest of the line is not parseable,
                    // and extract_triples_into gives up here too.
                    None => return,
                }
            }
            _ => {
                let start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                out.push(bytes[start..i].to_vec());
            }
        }
    }
}

fn extract_triples_into(bytes: &[u8], out: &mut Vec<NetgroupTriple>) {
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if bytes[i] != b'(' {
            // Parentheses inside a bare reference token are not triples.
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            continue;
        }
        let Some(close_offset) = bytes[i..].iter().position(|&b| b == b')') else {
            // Unclosed paren: stop scanning this line gracefully.
            return;
        };
        let inner = &bytes[i + 1..i + close_offset];
        let mut parts = inner.split(|&b| b == b',');
        let host = parts.next().unwrap_or(&[]);
        let user = parts.next().unwrap_or(&[]);
        let domain = parts.next().unwrap_or(&[]);
        out.push(NetgroupTriple {
            host: field_value(host).to_vec(),
            user: field_value(user).to_vec(),
            domain: field_value(domain).to_vec(),
        });
        i += close_offset + 1;
    }
}

fn field_value(s: &[u8]) -> &[u8] {
    let start = s
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(s.len());
    let length = s[start..]
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(s.len() - start);
    &s[start..start + length]
}

fn netgroup_name_matches(a: &[u8], b: &[u8]) -> bool {
    a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(host: &[u8], user: &[u8], domain: &[u8]) -> NetgroupTriple {
        NetgroupTriple {
            host: host.to_vec(),
            user: user.to_vec(),
            domain: domain.to_vec(),
        }
    }

    #[test]
    fn parse_single_triple() {
        let content = b"admins (host1,alice,example.com)\n";
        let r = parse_netgroup_triples(content, b"admins");
        assert_eq!(r, vec![t(b"host1", b"alice", b"example.com")]);
    }

    #[test]
    fn lookup_distinguishes_empty_missing_and_nested_only_groups() {
        let content = b"# absent\nempty # no triples\nparent child\nchild (h,u,d)\n";
        assert!(contains_netgroup(content, b"empty"));
        assert!(expand_netgroup(content, b"empty").is_empty());
        assert!(contains_netgroup(content, b"parent"));
        assert_eq!(
            expand_netgroup(content, b"parent"),
            vec![t(b"h", b"u", b"d")]
        );
        for missing in [b"absent".as_slice(), b"Empty", b"", b"chil"] {
            assert!(!contains_netgroup(content, missing));
        }
    }

    #[test]
    fn parse_multiple_triples() {
        let content = b"team (h1,u1,d1) (h2,u2,d2) (h3,u3,d3)\n";
        let r = parse_netgroup_triples(content, b"team");
        assert_eq!(
            r,
            vec![
                t(b"h1", b"u1", b"d1"),
                t(b"h2", b"u2", b"d2"),
                t(b"h3", b"u3", b"d3"),
            ]
        );
    }

    #[test]
    fn parse_empty_fields_are_wildcards() {
        // (host,,) is "any user, any domain on host"
        let content = b"x (h,,)\n";
        let r = parse_netgroup_triples(content, b"x");
        assert_eq!(r, vec![t(b"h", b"", b"")]);
    }

    #[test]
    fn parse_all_empty_triple() {
        let content = b"x (,,)\n";
        let r = parse_netgroup_triples(content, b"x");
        assert_eq!(r, vec![t(b"", b"", b"")]);
    }

    #[test]
    fn parse_missing_trailing_fields_default_empty() {
        // (host) -> (host, "", "")
        let content = b"x (h)\n";
        let r = parse_netgroup_triples(content, b"x");
        assert_eq!(r, vec![t(b"h", b"", b"")]);
        // (host,user) -> (host, user, "")
        let content = b"x (h,u)\n";
        let r = parse_netgroup_triples(content, b"x");
        assert_eq!(r, vec![t(b"h", b"u", b"")]);
    }

    #[test]
    fn parse_strips_field_whitespace() {
        let content = b"x ( host , user , domain )\n";
        let r = parse_netgroup_triples(content, b"x");
        assert_eq!(r, vec![t(b"host", b"user", b"domain")]);
    }

    #[test]
    fn parse_hash_reference_tokens_without_triples() {
        let content = b"x (h,u,d) # this is a comment\n";
        let r = parse_netgroup_triples(content, b"x");
        assert_eq!(r, vec![t(b"h", b"u", b"d")]);
    }

    #[test]
    fn parse_hash_is_not_an_inline_comment_delimiter() {
        let content = b"x (h,u,d) # (next,user,domain)\n";
        let r = parse_netgroup_triples(content, b"x");
        assert_eq!(r, vec![t(b"h", b"u", b"d"), t(b"next", b"user", b"domain")]);
        // A parenthesized suffix inside a reference is not a new triple.
        let content = b"x (h,u,d) #(bad,bad,bad)\n";
        assert_eq!(
            parse_netgroup_triples(content, b"x"),
            vec![t(b"h", b"u", b"d")]
        );
    }

    #[test]
    fn parse_group_name_comment_has_no_triple_tail() {
        let content = b"x#comment (bad,bad,bad)\n";
        let r = parse_netgroup_triples(content, b"x");
        assert!(r.is_empty());
        assert!(!contains_netgroup(content, b"x"));
        assert_eq!(
            parse_netgroup_triples(content, b"x#comment"),
            vec![t(b"bad", b"bad", b"bad")]
        );
    }

    #[test]
    fn parse_skips_blank_and_comment_lines() {
        let content = b"\n# nothing\n   # also nothing\nx (h,u,d)\n";
        let r = parse_netgroup_triples(content, b"x");
        assert_eq!(r, vec![t(b"h", b"u", b"d")]);
    }

    #[test]
    fn parse_group_name_case_sensitive() {
        let content = b"AdMiNs (h,u,d)\n";
        assert!(parse_netgroup_triples(content, b"admins").is_empty());
        assert_eq!(
            parse_netgroup_triples(content, b"ADMINS"),
            Vec::<NetgroupTriple>::new()
        );
        assert_eq!(
            parse_netgroup_triples(content, b"AdMiNs"),
            vec![t(b"h", b"u", b"d")]
        );
    }

    #[test]
    fn parse_returns_empty_for_unknown_group() {
        let content = b"foo (h,u,d)\n";
        assert!(parse_netgroup_triples(content, b"bar").is_empty());
    }

    #[test]
    fn parse_unclosed_paren_does_not_panic() {
        let content = b"x (h,u,d  \n";
        // Unclosed paren: stop scanning this line; no triples emitted.
        let r = parse_netgroup_triples(content, b"x");
        assert!(r.is_empty());
    }

    #[test]
    fn parse_ignores_bare_group_references() {
        // "x other_group (h,u,d)" — the bare token "other_group"
        // is a group reference; we don't expand it but we DO still
        // emit any inline triples on the same line.
        let content = b"x other_group (h,u,d)\n";
        let r = parse_netgroup_triples(content, b"x");
        assert_eq!(r, vec![t(b"h", b"u", b"d")]);
    }

    #[test]
    fn parse_first_definition_shadows_later_members() {
        let content = b"x (h1,u1,d1)\nx (h2,u2,d2)\n";
        let r = parse_netgroup_triples(content, b"x");
        assert_eq!(r, vec![t(b"h1", b"u1", b"d1")]);
        assert_eq!(expand_netgroup(content, b"x"), r);
        let content = b"x\nx (h2,u2,d2)\n";
        assert!(contains_netgroup(content, b"x"));
        assert!(parse_netgroup_triples(content, b"x").is_empty());
        assert!(expand_netgroup(content, b"x").is_empty());
    }

    #[test]
    fn continued_triples_and_references_share_one_record() {
        let content = b"team (first,u,d) \\\n child \\\n (last,u,d)\nchild (nested,u,d)\n";
        assert_eq!(
            parse_netgroup_triples(content, b"team"),
            vec![t(b"first", b"u", b"d"), t(b"last", b"u", b"d")]
        );
        assert_eq!(
            expand_netgroup(content, b"team"),
            vec![
                t(b"first", b"u", b"d"),
                t(b"last", b"u", b"d"),
                t(b"nested", b"u", b"d"),
            ]
        );
        let swallowed = b"other (first,u,d) \\\nteam (hidden,u,d)\n";
        assert!(!contains_netgroup(swallowed, b"team"));
        assert!(parse_netgroup_triples(swallowed, b"team").is_empty());
        assert!(expand_netgroup(swallowed, b"team").is_empty());
    }

    #[test]
    fn continuation_boundaries_and_comment_records_do_not_create_groups() {
        for content in [
            b"# comment \\\nteam (hidden,u,d)\n".as_slice(),
            b"# comment \\\n \\\nteam (hidden,u,d)\n".as_slice(),
            b" team (hidden,u,d)\n".as_slice(),
            b"\tteam (hidden,u,d)\n".as_slice(),
        ] {
            assert!(!contains_netgroup(content, b"team"));
            assert!(expand_netgroup(content, b"team").is_empty());
        }
        for content in [
            b"team (first,u,d) \\ \n (hidden,u,d)\n".as_slice(),
            b"team (first,u,d) \\\r\n (hidden,u,d)\n".as_slice(),
            b"team (first,u,d) \\\n\n (hidden,u,d)\n".as_slice(),
        ] {
            assert_eq!(
                expand_netgroup(content, b"team"),
                vec![t(b"first", b"u", b"d")]
            );
        }
        for content in [
            b"team (first,u,d) \\\n".as_slice(),
            b"team (first,u,d) \\".as_slice(),
        ] {
            assert_eq!(
                expand_netgroup(content, b"team"),
                vec![t(b"first", b"u", b"d")]
            );
        }
    }

    #[test]
    fn continued_references_keep_lifo_order_and_cycle_detection() {
        let content = b"root (root,u,d) \\\n first \\\n second\nfirst root (first,u,d)\nsecond first (second,u,d)\nsecond (hidden,u,d)\n";
        assert_eq!(
            expand_netgroup(content, b"root"),
            vec![
                t(b"root", b"u", b"d"),
                t(b"second", b"u", b"d"),
                t(b"first", b"u", b"d"),
            ]
        );
    }

    #[test]
    fn continuation_is_whitespace_and_preserves_non_utf8_bytes() {
        let content = b"g\xff (bu\\\nild,alice,domain) \\\n (h\x80,\\\nuser,domain)\n";
        assert!(contains_netgroup(content, b"g\xff"));
        assert_eq!(
            expand_netgroup(content, b"g\xff"),
            vec![
                t(b"bu", b"alice", b"domain"),
                t(b"h\x80", b"user", b"domain"),
            ]
        );
    }

    #[test]
    fn parse_real_world_line() {
        let content =
            b"trusted (apollo,alice,example.org) (zeus,bob,example.org) (-,carol,example.org)\n";
        let r = parse_netgroup_triples(content, b"trusted");
        assert_eq!(r.len(), 3);
        assert_eq!(r[2].host, b"-");
        assert_eq!(r[2].user, b"carol");
        assert_eq!(r[2].domain, b"example.org");
    }

    #[test]
    fn parse_handles_tab_separated_input() {
        let content = b"team\t(h,u,d)\n";
        let r = parse_netgroup_triples(content, b"team");
        assert_eq!(r, vec![t(b"h", b"u", b"d")]);
    }
}
