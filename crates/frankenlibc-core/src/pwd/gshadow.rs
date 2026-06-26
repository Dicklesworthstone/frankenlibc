//! `/etc/gshadow` parser — group shadow password database (bd-ta3b).
//!
//! Format: `group_name:encrypted_password:administrators:members`
//! Each field is colon-delimited. Administrators and members are
//! comma-separated lists (may be empty).

/// Parsed gshadow entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gshadow {
    /// Group name (non-empty).
    pub sg_namp: Vec<u8>,
    /// Encrypted password (`!` = locked, `*` = no password, empty = none set).
    pub sg_passwd: Vec<u8>,
    /// Comma-separated administrator list (raw, may be empty).
    pub sg_adm: Vec<u8>,
    /// Comma-separated member list (raw, may be empty).
    pub sg_mem: Vec<u8>,
}

/// Parse a single `/etc/gshadow` line into a [`Gshadow`] entry.
///
/// Returns `None` for comments (`#`-prefixed), blank lines, or malformed
/// entries (wrong number of fields, empty group name).
pub fn parse_gshadow_line(line: &[u8]) -> Option<Gshadow> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.is_empty() || line.starts_with(b"#") {
        return None;
    }

    // glibc requires only a non-empty group name; passwd, the administrator
    // list, and the member list are all optional. When extra colons appear,
    // glibc's last field absorbs them, so the member list is everything past the
    // third colon ("g:x:a:b:c" -> members "b:c", later comma-split).
    let mut fields = line.splitn(4, |&b| b == b':');
    let sg_namp = fields.next()?;
    if sg_namp.is_empty() {
        return None;
    }

    let sg_passwd = fields.next().unwrap_or(b"");
    let sg_adm = fields.next().unwrap_or(b"");
    let sg_mem = fields.next().unwrap_or(b"");

    Some(Gshadow {
        sg_namp: sg_namp.to_vec(),
        sg_passwd: sg_passwd.to_vec(),
        sg_adm: sg_adm.to_vec(),
        sg_mem: sg_mem.to_vec(),
    })
}

/// Look up a gshadow entry by group name.
///
/// Scans `content` (the full `/etc/gshadow` file) line by line.
/// Returns the first matching entry (case-sensitive).
pub fn lookup_gshadow_by_name(content: &[u8], name: &[u8]) -> Option<Gshadow> {
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = parse_gshadow_line(line)
            && entry.sg_namp == name
        {
            return Some(entry);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_full_line() {
        let entry = parse_gshadow_line(b"sudo:!:admin1,admin2:user1,user2").unwrap();
        assert_eq!(entry.sg_namp, b"sudo");
        assert_eq!(entry.sg_passwd, b"!");
        assert_eq!(entry.sg_adm, b"admin1,admin2");
        assert_eq!(entry.sg_mem, b"user1,user2");
    }

    #[test]
    fn parse_minimal_line() {
        let entry = parse_gshadow_line(b"root:*::").unwrap();
        assert_eq!(entry.sg_namp, b"root");
        assert_eq!(entry.sg_passwd, b"*");
        assert_eq!(entry.sg_adm, b"");
        assert_eq!(entry.sg_mem, b"");
    }

    #[test]
    fn parse_empty_password() {
        let entry = parse_gshadow_line(b"grp:::").unwrap();
        assert_eq!(entry.sg_passwd, b"");
    }

    #[test]
    fn parse_locked_password() {
        let entry = parse_gshadow_line(b"grp:!::").unwrap();
        assert_eq!(entry.sg_passwd, b"!");
    }

    #[test]
    fn parse_with_admins_and_members() {
        let entry = parse_gshadow_line(b"dev:x:alice:alice,bob").unwrap();
        assert_eq!(entry.sg_adm, b"alice");
        assert_eq!(entry.sg_mem, b"alice,bob");
    }

    #[test]
    fn accepts_short_lines() {
        // glibc needs only a non-empty name; passwd/admins/members are optional.
        let e = parse_gshadow_line(b"root:*:").unwrap(); // 3 fields
        assert_eq!(
            (e.sg_adm.as_slice(), e.sg_mem.as_slice()),
            (&b""[..], &b""[..])
        );
        let f = parse_gshadow_line(b"root").unwrap(); // 1 field
        assert_eq!(f.sg_namp, b"root");
        assert_eq!(
            (
                f.sg_passwd.as_slice(),
                f.sg_adm.as_slice(),
                f.sg_mem.as_slice()
            ),
            (&b""[..], &b""[..], &b""[..])
        );
    }

    #[test]
    fn extra_colons_absorbed_into_members() {
        // glibc's last field absorbs trailing colons (members = past 3rd colon).
        let e = parse_gshadow_line(b"g:x:a:b:c").unwrap();
        assert_eq!(e.sg_adm, b"a");
        assert_eq!(e.sg_mem, b"b:c");
        let f = parse_gshadow_line(b"root:*:::extra").unwrap();
        assert_eq!(f.sg_mem, b":extra");
    }

    #[test]
    fn splitn_scanner_preserves_short_lines_and_tail() {
        let one = parse_gshadow_line(b"wheel").unwrap();
        assert_eq!(one.sg_namp, b"wheel");
        assert_eq!(one.sg_passwd, b"");
        assert_eq!(one.sg_adm, b"");
        assert_eq!(one.sg_mem, b"");

        let empty_optionals = parse_gshadow_line(b"wheel:::").unwrap();
        assert_eq!(empty_optionals.sg_passwd, b"");
        assert_eq!(empty_optionals.sg_adm, b"");
        assert_eq!(empty_optionals.sg_mem, b"");

        let tail = parse_gshadow_line(b"wheel:!:root::alice:bob").unwrap();
        assert_eq!(tail.sg_passwd, b"!");
        assert_eq!(tail.sg_adm, b"root");
        assert_eq!(tail.sg_mem, b":alice:bob");
    }

    #[test]
    fn reject_empty_name() {
        assert!(parse_gshadow_line(b":*::").is_none());
    }

    #[test]
    fn reject_comment_line() {
        assert!(parse_gshadow_line(b"# comment").is_none());
    }

    #[test]
    fn reject_empty_line() {
        assert!(parse_gshadow_line(b"").is_none());
    }

    #[test]
    fn strip_trailing_newline() {
        let entry = parse_gshadow_line(b"grp:*::\n").unwrap();
        assert_eq!(entry.sg_namp, b"grp");
    }

    #[test]
    fn lookup_finds_entry() {
        let content = b"root:*::\nsudo:!::alice\ndev:x:bob:bob,charlie\n";
        let entry = lookup_gshadow_by_name(content, b"sudo").unwrap();
        assert_eq!(entry.sg_namp, b"sudo");
        assert_eq!(entry.sg_mem, b"alice");
    }

    #[test]
    fn lookup_returns_none_for_missing() {
        let content = b"root:*::\nsudo:!::\n";
        assert!(lookup_gshadow_by_name(content, b"nonexistent").is_none());
    }

    #[test]
    fn lookup_is_case_sensitive() {
        let content = b"root:*::\n";
        assert!(lookup_gshadow_by_name(content, b"ROOT").is_none());
    }
}
