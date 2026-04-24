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
//! references), which this parser ignores — matching the minimal
//! glibc files-backend behavior.

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
/// Returns an empty `Vec` when `group` is not present. Comments
/// (`#` to end-of-line) and blank lines are skipped. Group name
/// matching is case-insensitive (matches the glibc files backend).
///
/// Each `(host,user,domain)` triple is extracted as it appears;
/// per-field whitespace is trimmed and missing trailing fields
/// default to empty.
pub fn parse_netgroup_triples(content: &[u8], group: &[u8]) -> Vec<NetgroupTriple> {
    let mut result = Vec::new();
    for line in content.split(|&b| b == b'\n') {
        let line = strip_inline_comment(line);
        let mut fields = line
            .split(|&b| b == b' ' || b == b'\t')
            .filter(|f| !f.is_empty());
        let Some(name) = fields.next() else {
            continue;
        };
        if !eq_ignore_ascii_case(name, group) {
            continue;
        }
        // Re-scan from after the name to extract paren-bounded triples.
        let rest_start = name.as_ptr() as usize - line.as_ptr() as usize + name.len();
        extract_triples_into(&line[rest_start..], &mut result);
    }
    result
}

fn extract_triples_into(bytes: &[u8], out: &mut Vec<NetgroupTriple>) {
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'(' {
            i += 1;
            continue;
        }
        let Some(close_offset) = bytes[i..].iter().position(|&b| b == b')') else {
            // Unclosed paren: stop scanning this line gracefully.
            return;
        };
        let inner = &bytes[i + 1..i + close_offset];
        let parts: Vec<&[u8]> = inner.split(|&b| b == b',').collect();
        let host = parts.first().copied().unwrap_or(&[]);
        let user = parts.get(1).copied().unwrap_or(&[]);
        let domain = parts.get(2).copied().unwrap_or(&[]);
        out.push(NetgroupTriple {
            host: trim_ascii(host).to_vec(),
            user: trim_ascii(user).to_vec(),
            domain: trim_ascii(domain).to_vec(),
        });
        i += close_offset + 1;
    }
}

fn strip_inline_comment(line: &[u8]) -> &[u8] {
    if let Some(pos) = line.iter().position(|&b| b == b'#') {
        &line[..pos]
    } else {
        line
    }
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
    fn parse_strips_inline_comment() {
        let content = b"x (h,u,d) # this is a comment\n";
        let r = parse_netgroup_triples(content, b"x");
        assert_eq!(r, vec![t(b"h", b"u", b"d")]);
    }

    #[test]
    fn parse_skips_blank_and_comment_lines() {
        let content = b"\n# nothing\n   # also nothing\nx (h,u,d)\n";
        let r = parse_netgroup_triples(content, b"x");
        assert_eq!(r, vec![t(b"h", b"u", b"d")]);
    }

    #[test]
    fn parse_group_name_case_insensitive() {
        let content = b"AdMiNs (h,u,d)\n";
        assert_eq!(
            parse_netgroup_triples(content, b"admins"),
            vec![t(b"h", b"u", b"d")]
        );
        assert_eq!(
            parse_netgroup_triples(content, b"ADMINS"),
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
    fn parse_multiple_lines_for_same_group() {
        // Multiple lines with the same group name: triples accumulate.
        let content = b"x (h1,u1,d1)\nx (h2,u2,d2)\n";
        let r = parse_netgroup_triples(content, b"x");
        assert_eq!(r, vec![t(b"h1", b"u1", b"d1"), t(b"h2", b"u2", b"d2")]);
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
