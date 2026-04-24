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

/// Aggregate parser accounting for group file scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ParseStats {
    /// Number of logical lines inspected.
    pub total_lines: usize,
    /// Number of valid group entries produced.
    pub parsed_entries: usize,
    /// Number of malformed non-comment lines.
    pub malformed_lines: usize,
    /// Number of comment/blank lines skipped.
    pub skipped_lines: usize,
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

/// Append a serialized group line to `out`.
///
/// Produces `"name:passwd:gid:m1,m2,...\n"` — the canonical
/// `/etc/group` shape consumed by `parse_group_line`. Members are
/// joined with `,` and yield an empty trailing field when the slice
/// is empty. Field bytes are written verbatim.
pub fn format_group_line(
    name: &[u8],
    passwd: &[u8],
    gid: u32,
    members: &[&[u8]],
    out: &mut Vec<u8>,
) {
    out.extend_from_slice(name);
    out.push(b':');
    out.extend_from_slice(passwd);
    out.push(b':');
    write_u32_decimal(out, gid);
    out.push(b':');
    for (i, m) in members.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(m);
    }
    out.push(b'\n');
}

fn write_u32_decimal(out: &mut Vec<u8>, mut n: u32) {
    if n == 0 {
        out.push(b'0');
        return;
    }
    let mut tmp = [0u8; 10];
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    for j in 0..i {
        out.push(tmp[i - 1 - j]);
    }
}

/// Parse all valid entries from group content.
pub fn parse_all(content: &[u8]) -> Vec<Group> {
    parse_all_with_stats(content).0
}

/// Parse all valid entries from group content with deterministic accounting.
pub fn parse_all_with_stats(content: &[u8]) -> (Vec<Group>, ParseStats) {
    let mut entries = Vec::new();
    let mut stats = ParseStats::default();

    for raw_line in content.split(|&b| b == b'\n') {
        stats.total_lines += 1;

        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() || line.starts_with(b"#") {
            stats.skipped_lines += 1;
            continue;
        }

        match parse_group_line(raw_line) {
            Some(entry) => {
                stats.parsed_entries += 1;
                entries.push(entry);
            }
            None => {
                stats.malformed_lines += 1;
            }
        }
    }

    (entries, stats)
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

    #[test]
    fn parse_all_with_stats_counts_malformed_lines() {
        let content = b"root:x:0:\n# comment\nmalformed\n\nsudo:x:27:ubuntu";
        let (entries, stats) = parse_all_with_stats(content);

        assert_eq!(entries.len(), 2);
        assert_eq!(stats.total_lines, 5);
        assert_eq!(stats.parsed_entries, 2);
        assert_eq!(stats.malformed_lines, 1);
        assert_eq!(stats.skipped_lines, 2);
    }

    #[test]
    fn parse_all_with_stats_tracks_trailing_newline_segment() {
        let content = b"root:x:0:\n";
        let (entries, stats) = parse_all_with_stats(content);

        assert_eq!(entries.len(), 1);
        assert_eq!(stats.total_lines, 2);
        assert_eq!(stats.parsed_entries, 1);
        assert_eq!(stats.malformed_lines, 0);
        assert_eq!(stats.skipped_lines, 1);
    }

    #[test]
    fn format_basic_no_members() {
        let mut out = Vec::new();
        format_group_line(b"root", b"x", 0, &[], &mut out);
        assert_eq!(out, b"root:x:0:\n".to_vec());
    }

    #[test]
    fn format_with_single_member() {
        let mut out = Vec::new();
        format_group_line(b"sudo", b"x", 27, &[b"alice"], &mut out);
        assert_eq!(out, b"sudo:x:27:alice\n".to_vec());
    }

    #[test]
    fn format_with_multiple_members() {
        let mut out = Vec::new();
        format_group_line(b"adm", b"x", 4, &[b"alice", b"bob", b"carol"], &mut out);
        assert_eq!(out, b"adm:x:4:alice,bob,carol\n".to_vec());
    }

    #[test]
    fn format_round_trip_with_members() {
        let mut out = Vec::new();
        format_group_line(b"team", b"x", 1000, &[b"alice", b"bob"], &mut out);
        let parsed = parse_group_line(&out).expect("reparsed");
        assert_eq!(parsed.gr_name, b"team");
        assert_eq!(parsed.gr_gid, 1000);
        assert_eq!(parsed.gr_mem.len(), 2);
        assert_eq!(parsed.gr_mem[0], b"alice");
        assert_eq!(parsed.gr_mem[1], b"bob");
    }

    #[test]
    fn format_round_trip_no_members() {
        let mut out = Vec::new();
        format_group_line(b"empty", b"x", 999, &[], &mut out);
        let parsed = parse_group_line(&out).expect("reparsed");
        assert_eq!(parsed.gr_mem.len(), 0);
    }

    #[test]
    fn format_handles_max_gid() {
        let mut out = Vec::new();
        format_group_line(b"big", b"x", u32::MAX, &[], &mut out);
        assert_eq!(out, b"big:x:4294967295:\n".to_vec());
    }

    #[test]
    fn format_appends_to_existing_buffer() {
        let mut out = b"# header\n".to_vec();
        format_group_line(b"a", b"x", 0, &[], &mut out);
        assert_eq!(out, b"# header\na:x:0:\n".to_vec());
    }
}
