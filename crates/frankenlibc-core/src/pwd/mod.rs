//! Password database functions.
//!
//! Implements a files backend for `<pwd.h>` functions: `getpwnam`, `getpwuid`.
//! Parses `/etc/passwd` in the standard colon-delimited format.

pub mod gshadow;
pub mod shadow;

/// A parsed passwd entry (analogous to `struct passwd`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passwd {
    /// Login name.
    pub pw_name: Vec<u8>,
    /// Encrypted password (usually "x" for shadow).
    pub pw_passwd: Vec<u8>,
    /// User ID.
    pub pw_uid: u32,
    /// Group ID.
    pub pw_gid: u32,
    /// User information (GECOS field).
    pub pw_gecos: Vec<u8>,
    /// Home directory.
    pub pw_dir: Vec<u8>,
    /// Login shell.
    pub pw_shell: Vec<u8>,
}

/// Aggregate parser accounting for passwd file scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ParseStats {
    /// Number of logical lines inspected.
    pub total_lines: usize,
    /// Number of valid passwd entries produced.
    pub parsed_entries: usize,
    /// Number of malformed non-comment lines.
    pub malformed_lines: usize,
    /// Number of comment/blank lines skipped.
    pub skipped_lines: usize,
}

/// Parse a single line from `/etc/passwd`.
///
/// Format: `name:passwd:uid:gid:gecos:dir:shell`
/// Returns `None` for comments, blank lines, or malformed entries.
pub fn parse_passwd_line(line: &[u8]) -> Option<Passwd> {
    // Skip comments and blank lines
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.is_empty() || line.starts_with(b"#") {
        return None;
    }

    let fields: Vec<&[u8]> = line.split(|&b| b == b':').collect();
    if fields.len() != 7 {
        return None;
    }

    let uid = core::str::from_utf8(fields[2]).ok()?.parse::<u32>().ok()?;
    let gid = core::str::from_utf8(fields[3]).ok()?.parse::<u32>().ok()?;

    // Name must be non-empty
    if fields[0].is_empty() {
        return None;
    }

    Some(Passwd {
        pw_name: fields[0].to_vec(),
        pw_passwd: fields[1].to_vec(),
        pw_uid: uid,
        pw_gid: gid,
        pw_gecos: fields[4].to_vec(),
        pw_dir: fields[5].to_vec(),
        pw_shell: fields[6].to_vec(),
    })
}

/// Look up a passwd entry by username.
///
/// Scans `content` (expected to be the full `/etc/passwd` file) line by line.
/// Returns the first matching entry (case-sensitive, matching glibc behavior).
pub fn lookup_by_name(content: &[u8], name: &[u8]) -> Option<Passwd> {
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = parse_passwd_line(line)
            && entry.pw_name == name
        {
            return Some(entry);
        }
    }
    None
}

/// Look up a passwd entry by UID.
///
/// Scans `content` (expected to be the full `/etc/passwd` file) line by line.
/// Returns the first matching entry.
pub fn lookup_by_uid(content: &[u8], uid: u32) -> Option<Passwd> {
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = parse_passwd_line(line)
            && entry.pw_uid == uid
        {
            return Some(entry);
        }
    }
    None
}

/// Append a serialized passwd line to `out`.
///
/// Produces `"name:passwd:uid:gid:gecos:dir:shell\n"` — the canonical
/// `/etc/passwd` line shape consumed by `parse_passwd_line`. Field
/// bytes are written verbatim; the caller is responsible for ensuring
/// no embedded `:` or `\n` would corrupt the format.
pub fn format_passwd_line(
    name: &[u8],
    passwd: &[u8],
    uid: u32,
    gid: u32,
    gecos: &[u8],
    dir: &[u8],
    shell: &[u8],
    out: &mut Vec<u8>,
) {
    out.extend_from_slice(name);
    out.push(b':');
    out.extend_from_slice(passwd);
    out.push(b':');
    write_u32_decimal(out, uid);
    out.push(b':');
    write_u32_decimal(out, gid);
    out.push(b':');
    out.extend_from_slice(gecos);
    out.push(b':');
    out.extend_from_slice(dir);
    out.push(b':');
    out.extend_from_slice(shell);
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

/// Parse all valid entries from passwd content.
pub fn parse_all(content: &[u8]) -> Vec<Passwd> {
    parse_all_with_stats(content).0
}

/// Parse all valid entries from passwd content with deterministic accounting.
pub fn parse_all_with_stats(content: &[u8]) -> (Vec<Passwd>, ParseStats) {
    let mut entries = Vec::new();
    let mut stats = ParseStats::default();

    for raw_line in content.split(|&b| b == b'\n') {
        stats.total_lines += 1;

        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() || line.starts_with(b"#") {
            stats.skipped_lines += 1;
            continue;
        }

        match parse_passwd_line(raw_line) {
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

    const SAMPLE_PASSWD: &[u8] = b"\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu,,,:/home/ubuntu:/bin/bash
";

    #[test]
    fn parse_valid_line() {
        let entry = parse_passwd_line(b"root:x:0:0:root:/root:/bin/bash").unwrap();
        assert_eq!(entry.pw_name, b"root");
        assert_eq!(entry.pw_passwd, b"x");
        assert_eq!(entry.pw_uid, 0);
        assert_eq!(entry.pw_gid, 0);
        assert_eq!(entry.pw_gecos, b"root");
        assert_eq!(entry.pw_dir, b"/root");
        assert_eq!(entry.pw_shell, b"/bin/bash");
    }

    #[test]
    fn parse_line_with_gecos_commas() {
        let entry =
            parse_passwd_line(b"ubuntu:x:1000:1000:Ubuntu,,,:/home/ubuntu:/bin/bash").unwrap();
        assert_eq!(entry.pw_name, b"ubuntu");
        assert_eq!(entry.pw_gecos, b"Ubuntu,,,");
        assert_eq!(entry.pw_uid, 1000);
    }

    #[test]
    fn parse_line_empty_fields() {
        let entry = parse_passwd_line(b"test:*:500:500:::/bin/false").unwrap();
        assert_eq!(entry.pw_gecos, b"");
        assert_eq!(entry.pw_dir, b"");
    }

    #[test]
    fn skip_comment_line() {
        assert!(parse_passwd_line(b"# comment").is_none());
    }

    #[test]
    fn skip_blank_line() {
        assert!(parse_passwd_line(b"").is_none());
        assert!(parse_passwd_line(b"\n").is_none());
    }

    #[test]
    fn reject_wrong_field_count() {
        assert!(parse_passwd_line(b"root:x:0:0:root:/root").is_none()); // 6 fields
        assert!(parse_passwd_line(b"root:x:0:0:root:/root:/bin/bash:extra").is_none()); // 8 fields
    }

    #[test]
    fn reject_non_numeric_uid() {
        assert!(parse_passwd_line(b"root:x:abc:0:root:/root:/bin/bash").is_none());
    }

    #[test]
    fn reject_non_numeric_gid() {
        assert!(parse_passwd_line(b"root:x:0:xyz:root:/root:/bin/bash").is_none());
    }

    #[test]
    fn reject_empty_name() {
        assert!(parse_passwd_line(b":x:0:0::/:/bin/sh").is_none());
    }

    #[test]
    fn lookup_by_name_found() {
        let entry = lookup_by_name(SAMPLE_PASSWD, b"ubuntu").unwrap();
        assert_eq!(entry.pw_uid, 1000);
        assert_eq!(entry.pw_dir, b"/home/ubuntu");
    }

    #[test]
    fn lookup_by_name_not_found() {
        assert!(lookup_by_name(SAMPLE_PASSWD, b"nonexistent").is_none());
    }

    #[test]
    fn lookup_by_name_case_sensitive() {
        assert!(lookup_by_name(SAMPLE_PASSWD, b"Root").is_none());
        assert!(lookup_by_name(SAMPLE_PASSWD, b"root").is_some());
    }

    #[test]
    fn lookup_by_uid_found() {
        let entry = lookup_by_uid(SAMPLE_PASSWD, 0).unwrap();
        assert_eq!(entry.pw_name, b"root");
    }

    #[test]
    fn lookup_by_uid_not_found() {
        assert!(lookup_by_uid(SAMPLE_PASSWD, 99999).is_none());
    }

    #[test]
    fn lookup_by_uid_nobody() {
        let entry = lookup_by_uid(SAMPLE_PASSWD, 65534).unwrap();
        assert_eq!(entry.pw_name, b"nobody");
    }

    #[test]
    fn parse_all_entries() {
        let entries = parse_all(SAMPLE_PASSWD);
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].pw_name, b"root");
        assert_eq!(entries[4].pw_name, b"ubuntu");
    }

    #[test]
    fn parse_line_with_crlf() {
        let entry = parse_passwd_line(b"test:x:500:500:test:/home/test:/bin/sh\r\n").unwrap();
        assert_eq!(entry.pw_name, b"test");
        assert_eq!(entry.pw_shell, b"/bin/sh");
    }

    #[test]
    fn first_match_wins_for_duplicate_names() {
        let content =
            b"dup:x:100:100:first:/home/dup:/bin/sh\ndup:x:200:200:second:/home/dup2:/bin/bash\n";
        let entry = lookup_by_name(content, b"dup").unwrap();
        assert_eq!(entry.pw_uid, 100);
    }

    #[test]
    fn first_match_wins_for_duplicate_uids() {
        let content =
            b"alice:x:500:500:Alice:/home/alice:/bin/sh\nbob:x:500:500:Bob:/home/bob:/bin/bash\n";
        let entry = lookup_by_uid(content, 500).unwrap();
        assert_eq!(entry.pw_name, b"alice");
    }

    #[test]
    fn skip_malformed_lines_in_lookup() {
        let content = b"bad line\nroot:x:0:0:root:/root:/bin/bash\n";
        let entry = lookup_by_name(content, b"root").unwrap();
        assert_eq!(entry.pw_uid, 0);
    }

    #[test]
    fn large_uid_gid() {
        let entry = parse_passwd_line(b"biguser:x:4294967295:4294967295::/:/bin/sh").unwrap();
        assert_eq!(entry.pw_uid, u32::MAX);
        assert_eq!(entry.pw_gid, u32::MAX);
    }

    #[test]
    fn parse_all_with_stats_counts_malformed_lines() {
        let content =
            b"root:x:0:0:root:/root:/bin/bash\n# comment\nbadline\n\nuser:x:1:1::/home/user:/bin/sh";
        let (entries, stats) = parse_all_with_stats(content);

        assert_eq!(entries.len(), 2);
        assert_eq!(stats.total_lines, 5);
        assert_eq!(stats.parsed_entries, 2);
        assert_eq!(stats.malformed_lines, 1);
        assert_eq!(stats.skipped_lines, 2);
    }

    #[test]
    fn parse_all_with_stats_tracks_trailing_newline_segment() {
        let content = b"root:x:0:0:root:/root:/bin/bash\n";
        let (entries, stats) = parse_all_with_stats(content);

        assert_eq!(entries.len(), 1);
        assert_eq!(stats.total_lines, 2);
        assert_eq!(stats.parsed_entries, 1);
        assert_eq!(stats.malformed_lines, 0);
        assert_eq!(stats.skipped_lines, 1);
    }

    #[test]
    fn format_basic_round_trip() {
        let mut out = Vec::new();
        format_passwd_line(
            b"root", b"x", 0, 0, b"root", b"/root", b"/bin/bash", &mut out,
        );
        assert_eq!(out, b"root:x:0:0:root:/root:/bin/bash\n".to_vec());
        let parsed = parse_passwd_line(&out).expect("reparsed");
        assert_eq!(parsed.pw_name, b"root");
        assert_eq!(parsed.pw_uid, 0);
        assert_eq!(parsed.pw_shell, b"/bin/bash");
    }

    #[test]
    fn format_handles_max_uid_gid() {
        let mut out = Vec::new();
        format_passwd_line(
            b"big",
            b"x",
            u32::MAX,
            u32::MAX,
            b"",
            b"/",
            b"/bin/sh",
            &mut out,
        );
        assert_eq!(out, b"big:x:4294967295:4294967295::/:/bin/sh\n".to_vec());
    }

    #[test]
    fn format_handles_empty_optional_fields() {
        let mut out = Vec::new();
        format_passwd_line(b"u", b"", 1, 2, b"", b"", b"", &mut out);
        // 7 fields, 6 separators: name:passwd:uid:gid:gecos:dir:shell
        assert_eq!(out, b"u::1:2:::\n".to_vec());
    }

    #[test]
    fn format_appends_to_existing_buffer() {
        let mut out = b"# header\n".to_vec();
        format_passwd_line(b"a", b"x", 0, 0, b"", b"/", b"/", &mut out);
        assert_eq!(out, b"# header\na:x:0:0::/:/\n".to_vec());
    }

    #[test]
    fn format_round_trip_with_gecos_commas() {
        let mut out = Vec::new();
        format_passwd_line(
            b"ubuntu",
            b"x",
            1000,
            1000,
            b"Ubuntu,,,",
            b"/home/ubuntu",
            b"/bin/bash",
            &mut out,
        );
        let parsed = parse_passwd_line(&out).expect("reparsed");
        assert_eq!(parsed.pw_gecos, b"Ubuntu,,,");
        assert_eq!(parsed.pw_uid, 1000);
    }
}
