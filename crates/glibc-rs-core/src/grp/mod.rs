//! Group database functions.
//!
//! Implements a files backend for `<grp.h>` functions: `getgrnam`, `getgrgid`.
//! Parses `/etc/group` in the standard colon-delimited format.

/// A parsed group entry (analogous to `struct group`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Group name.
    pub gr_name: Vec<u8>,
    /// Encrypted password (usually "x" or empty).
    pub gr_passwd: Vec<u8>,
    /// Group ID.
    pub gr_gid: u32,
    /// Member list (comma-separated in file, split here).
    pub gr_mem: Vec<Vec<u8>>,
}

/// Parse a single line from `/etc/group`.
///
/// Format: `name:passwd:gid:members`
/// Members is a comma-separated list (may be empty).
/// Returns `None` for comments, blank lines, or malformed entries.
pub fn parse_group_line(line: &[u8]) -> Option<Group> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.is_empty() || line.starts_with(b"#") {
        return None;
    }

    let fields: Vec<&[u8]> = line.split(|&b| b == b':').collect();
    if fields.len() != 4 {
        return None;
    }

    let gid = core::str::from_utf8(fields[2]).ok()?.parse::<u32>().ok()?;

    if fields[0].is_empty() {
        return None;
    }

    let members = if fields[3].is_empty() {
        Vec::new()
    } else {
        fields[3]
            .split(|&b| b == b',')
            .map(|m| m.to_vec())
            .collect()
    };

    Some(Group {
        gr_name: fields[0].to_vec(),
        gr_passwd: fields[1].to_vec(),
        gr_gid: gid,
        gr_mem: members,
    })
}

/// Look up a group entry by name.
///
/// Scans `content` (expected to be the full `/etc/group` file) line by line.
/// Returns the first matching entry (case-sensitive, matching glibc behavior).
pub fn lookup_by_name(content: &[u8], name: &[u8]) -> Option<Group> {
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = parse_group_line(line)
            && entry.gr_name == name
        {
            return Some(entry);
        }
    }
    None
}

/// Look up a group entry by GID.
///
/// Scans `content` (expected to be the full `/etc/group` file) line by line.
/// Returns the first matching entry.
pub fn lookup_by_gid(content: &[u8], gid: u32) -> Option<Group> {
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = parse_group_line(line)
            && entry.gr_gid == gid
        {
            return Some(entry);
        }
    }
    None
}

/// Parse all valid entries from group content.
pub fn parse_all(content: &[u8]) -> Vec<Group> {
    content
        .split(|&b| b == b'\n')
        .filter_map(parse_group_line)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_GROUP: &[u8] = b"\
root:x:0:
daemon:x:1:
bin:x:2:
adm:x:4:syslog,ubuntu
sudo:x:27:ubuntu
users:x:100:alice,bob,charlie
ubuntu:x:1000:
";

    #[test]
    fn parse_valid_line_no_members() {
        let entry = parse_group_line(b"root:x:0:").unwrap();
        assert_eq!(entry.gr_name, b"root");
        assert_eq!(entry.gr_passwd, b"x");
        assert_eq!(entry.gr_gid, 0);
        assert!(entry.gr_mem.is_empty());
    }

    #[test]
    fn parse_valid_line_with_members() {
        let entry = parse_group_line(b"adm:x:4:syslog,ubuntu").unwrap();
        assert_eq!(entry.gr_name, b"adm");
        assert_eq!(entry.gr_gid, 4);
        assert_eq!(entry.gr_mem.len(), 2);
        assert_eq!(entry.gr_mem[0], b"syslog");
        assert_eq!(entry.gr_mem[1], b"ubuntu");
    }

    #[test]
    fn parse_single_member() {
        let entry = parse_group_line(b"wheel:x:10:root").unwrap();
        assert_eq!(entry.gr_mem.len(), 1);
        assert_eq!(entry.gr_mem[0], b"root");
    }

    #[test]
    fn parse_many_members() {
        let entry = parse_group_line(b"dev:x:500:a,b,c,d,e").unwrap();
        assert_eq!(entry.gr_mem.len(), 5);
        assert_eq!(entry.gr_mem[4], b"e");
    }

    #[test]
    fn parse_empty_password() {
        let entry = parse_group_line(b"nopass::99:").unwrap();
        assert_eq!(entry.gr_passwd, b"");
        assert_eq!(entry.gr_gid, 99);
        assert!(entry.gr_mem.is_empty());
    }

    #[test]
    fn skip_comment_line() {
        assert!(parse_group_line(b"# comment").is_none());
    }

    #[test]
    fn skip_blank_line() {
        assert!(parse_group_line(b"").is_none());
        assert!(parse_group_line(b"\n").is_none());
    }

    #[test]
    fn reject_wrong_field_count() {
        assert!(parse_group_line(b"root:x:0").is_none()); // 3 fields
        assert!(parse_group_line(b"root:x:0:members:extra").is_none()); // 5 fields
    }

    #[test]
    fn reject_non_numeric_gid() {
        assert!(parse_group_line(b"root:x:abc:").is_none());
    }

    #[test]
    fn reject_empty_name() {
        assert!(parse_group_line(b":x:0:").is_none());
    }

    #[test]
    fn lookup_by_name_found() {
        let entry = lookup_by_name(SAMPLE_GROUP, b"sudo").unwrap();
        assert_eq!(entry.gr_gid, 27);
        assert_eq!(entry.gr_mem, vec![b"ubuntu".to_vec()]);
    }

    #[test]
    fn lookup_by_name_not_found() {
        assert!(lookup_by_name(SAMPLE_GROUP, b"nonexistent").is_none());
    }

    #[test]
    fn lookup_by_name_case_sensitive() {
        assert!(lookup_by_name(SAMPLE_GROUP, b"Root").is_none());
        assert!(lookup_by_name(SAMPLE_GROUP, b"root").is_some());
    }

    #[test]
    fn lookup_by_gid_found() {
        let entry = lookup_by_gid(SAMPLE_GROUP, 0).unwrap();
        assert_eq!(entry.gr_name, b"root");
    }

    #[test]
    fn lookup_by_gid_not_found() {
        assert!(lookup_by_gid(SAMPLE_GROUP, 99999).is_none());
    }

    #[test]
    fn lookup_by_gid_users() {
        let entry = lookup_by_gid(SAMPLE_GROUP, 100).unwrap();
        assert_eq!(entry.gr_name, b"users");
        assert_eq!(entry.gr_mem.len(), 3);
    }

    #[test]
    fn parse_all_entries() {
        let entries = parse_all(SAMPLE_GROUP);
        assert_eq!(entries.len(), 7);
        assert_eq!(entries[0].gr_name, b"root");
        assert_eq!(entries[6].gr_name, b"ubuntu");
    }

    #[test]
    fn parse_line_with_crlf() {
        let entry = parse_group_line(b"test:x:500:a,b\r\n").unwrap();
        assert_eq!(entry.gr_name, b"test");
        assert_eq!(entry.gr_mem, vec![b"a".to_vec(), b"b".to_vec()]);
    }

    #[test]
    fn first_match_wins_for_duplicate_names() {
        let content = b"dup:x:100:\ndup:x:200:user\n";
        let entry = lookup_by_name(content, b"dup").unwrap();
        assert_eq!(entry.gr_gid, 100);
    }

    #[test]
    fn first_match_wins_for_duplicate_gids() {
        let content = b"alpha:x:500:a\nbeta:x:500:b\n";
        let entry = lookup_by_gid(content, 500).unwrap();
        assert_eq!(entry.gr_name, b"alpha");
    }

    #[test]
    fn skip_malformed_lines_in_lookup() {
        let content = b"bad line\nroot:x:0:\n";
        let entry = lookup_by_name(content, b"root").unwrap();
        assert_eq!(entry.gr_gid, 0);
    }

    #[test]
    fn large_gid() {
        let entry = parse_group_line(b"biggroup:x:4294967295:").unwrap();
        assert_eq!(entry.gr_gid, u32::MAX);
    }

    #[test]
    fn member_with_trailing_comma_produces_empty_entry() {
        // glibc treats trailing commas as producing an empty member name
        let entry = parse_group_line(b"test:x:50:a,b,").unwrap();
        assert_eq!(entry.gr_mem.len(), 3);
        assert_eq!(entry.gr_mem[2], b"");
    }
}
