//! `/etc/gshadow` parser — group shadow password database (bd-ta3b).
//!
//! Format: `group_name:encrypted_password:administrators:members`
//! Each field is colon-delimited. Administrators and members are
//! comma-separated lists (may be empty).

/// Parsed gshadow entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gshadow {
    /// Group name. MAY be empty: glibc yields an entry with `sg_namp == NULL`
    /// for a line beginning with `:`, and this owned vector cannot express
    /// NULL, so such a name arrives here as empty.
    pub sg_namp: Vec<u8>,
    /// Encrypted password (`!` = locked, `*` = no password, empty = none set).
    pub sg_passwd: Vec<u8>,
    /// Comma-separated administrator list (raw, may be empty).
    pub sg_adm: Vec<u8>,
    /// Comma-separated member list (raw, may be empty).
    pub sg_mem: Vec<u8>,
}

/// Parse a single `/etc/gshadow` line into a [`Gshadow`] entry — the STRING
/// rule, as used by `sgetsgent`.
///
/// Splits and does not validate. Comments and blank lines are NOT special here
/// and an empty group name is accepted, because that is what host `sgetsgent`
/// does. For the FILE rule — which skips comments and blanks and strips leading
/// whitespace — use [`parse_gshadow_file_line`].
///
/// Returns `None` only when there is no first field at all.
pub fn parse_gshadow_line(line: &[u8]) -> Option<Gshadow> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);

    // NO comment or blank-line handling here, and no leading-whitespace trim:
    // this is the STRING entry point's rule, and glibc's sgetsgent is a splitter
    // rather than a validator. Measured against host sgetsgent:
    //     "# comment"    -> an entry whose NAME is "# comment"
    //     ""             -> an entry with everything empty
    //     "  grp:x:a:m"  -> name "  grp", blanks kept
    //     "grp"          -> name "grp", no passwd, empty lists
    // Skipping comments here made sgetsgent("# x") return NULL where glibc
    // returns an entry. The FILE rule is different and lives in
    // `parse_gshadow_file_line`.

    // glibc requires only a group name; passwd, the administrator list, and the
    // member list are all optional. When extra colons appear, glibc's last field
    // absorbs them, so the member list is everything past the third colon
    // ("g:x:a:b:c" -> members "b:c", later comma-split).
    let mut fields = line.splitn(4, |&b| b == b':');
    let sg_namp = fields.next()?;

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

/// Parse one line of an /etc/gshadow FILE.
///
/// The file rule is not the string rule, which is why this exists separately.
/// Measured against host fgetsgent over an fmemopen'd buffer: a `#` comment and
/// a blank line are SKIPPED, and leading whitespace is STRIPPED so
/// `"  spaced:x:b:m"` yields the name `"spaced"` — where sgetsgent on the same
/// text yields `"  spaced"`. fl used one function for both entry points and so
/// applied the file rule to strings and the string rule to files.
///
/// An entry with an empty name is still yielded, not dropped: glibc reports it
/// with `sg_namp == NULL`. fl's `Gshadow` models the name as an owned byte
/// vector and cannot express NULL, so it surfaces as empty — closer than
/// discarding the entry, but not identical. Recorded rather than papered over.
#[must_use]
pub fn parse_gshadow_file_line(line: &[u8]) -> Option<Gshadow> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let start = line
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(line.len());
    let line = &line[start..];
    if line.is_empty() || line.starts_with(b"#") {
        return None;
    }
    parse_gshadow_line(line)
}

/// Look up a gshadow entry by group name.
///
/// Scans `content` (the full `/etc/gshadow` file) line by line.
/// Returns the first matching entry (case-sensitive).
pub fn lookup_gshadow_by_name(content: &[u8], name: &[u8]) -> Option<Gshadow> {
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = parse_gshadow_file_line(line)
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
        // glibc needs only a first field; passwd/admins/members are optional,
        // and the name may be empty (see file_line_yields_an_empty_name...).
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

    // These three assert the FILE rule and now name the file function. They
    // used to be written against parse_gshadow_line, which conflated the two
    // entry points: host sgetsgent accepts all three of these inputs, and only
    // fgetsgent skips the comment and the blank line.

    #[test]
    fn file_line_yields_an_empty_name_rather_than_dropping_it() {
        // glibc reports this entry with sg_namp == NULL, NOT by skipping it.
        // fl cannot express NULL in an owned Vec, so the name is empty.
        let e = parse_gshadow_file_line(b":*::").expect("glibc yields this entry");
        assert_eq!(e.sg_namp, b"");
        assert_eq!(e.sg_passwd, b"*");
    }

    #[test]
    fn file_line_skips_comment() {
        assert!(parse_gshadow_file_line(b"# comment").is_none());
        // ...but the STRING entry point does not: sgetsgent("# comment")
        // returns an entry whose name is the whole text.
        assert_eq!(
            parse_gshadow_line(b"# comment")
                .expect("string rule keeps it")
                .sg_namp,
            b"# comment"
        );
    }

    #[test]
    fn file_line_skips_blank_but_string_rule_does_not() {
        assert!(parse_gshadow_file_line(b"").is_none());
        assert!(parse_gshadow_line(b"").is_some());
    }

    #[test]
    fn file_line_strips_leading_blanks_and_string_rule_keeps_them() {
        // Measured: fgetsgent("  spaced:x:b:m") -> "spaced";
        //           sgetsgent("  spaced:x:b:m") -> "  spaced".
        assert_eq!(
            parse_gshadow_file_line(b"  spaced:x:b:m").unwrap().sg_namp,
            b"spaced"
        );
        assert_eq!(
            parse_gshadow_line(b"  spaced:x:b:m").unwrap().sg_namp,
            b"  spaced"
        );
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
