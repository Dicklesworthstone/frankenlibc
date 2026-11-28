//! Native policy for the NSS `compat` account-file format.
//!
//! The directive contract comes from nsswitch.conf(5), "Compatibility mode":
//! passwd/shadow accept `+name`, `-name`, `+@netgroup`, `-@netgroup` and `+`;
//! groups accept named inclusion/exclusion and `+`. The backing service is
//! selected by the corresponding `*_compat` database, defaulting to `nis`.
//! Field and parser details are measured through the real GNU provider with
//! isolated account files, not translated from its implementation.
//!
//! This module owns bytes, parsing, overrides and name-selection state only.
//! The ABI owns backend calls and cursors. In particular, importing an account
//! must not advance a remote cursor or mark its name consumed on an ERANGE
//! retry until the caller's result can be published.

use std::collections::HashSet;

use crate::grp::Group;
use crate::pwd::Passwd;
use crate::pwd::shadow::ShadowEntry;

/// The accounts selected by one compatibility directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    All,
    Name(Vec<u8>),
    Netgroup(Vec<u8>),
}

/// One valid local account or compatibility directive, in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record<T, O> {
    Local(T),
    Include { selector: Selector, overrides: O },
    Exclude(Selector),
}

pub type PasswdRecord = Record<Passwd, PasswdOverrides>;
pub type GroupRecord = Record<Group, GroupOverrides>;
pub type ShadowRecord = Record<ShadowEntry, ShadowOverrides>;

/// Nonempty passwd text fields replace their remote counterparts. The uid,
/// gid and account name always belong to the selected remote account.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasswdOverrides {
    pub passwd: Option<Vec<u8>>,
    pub gecos: Option<Vec<u8>>,
    pub dir: Option<Vec<u8>>,
    pub shell: Option<Vec<u8>>,
}

impl PasswdOverrides {
    pub fn apply(&self, entry: &mut Passwd) {
        if let Some(value) = &self.passwd {
            entry.pw_passwd.clone_from(value);
        }
        if let Some(value) = &self.gecos {
            entry.pw_gecos.clone_from(value);
        }
        if let Some(value) = &self.dir {
            entry.pw_dir.clone_from(value);
        }
        if let Some(value) = &self.shell {
            entry.pw_shell.clone_from(value);
        }
    }
}

/// GNU validates a group's directive fields but returns the remote group
/// unchanged, including its password and membership list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GroupOverrides;

impl GroupOverrides {
    pub fn apply(&self, _entry: &mut Group) {}
}

/// Shadow directives distinguish omitted fields from the empty numeric
/// fields of a complete row. In a complete row, the first three empty
/// numeric fields replace the remote value with -1; empty later fields
/// preserve their remote values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShadowOverrides {
    pub passwd: Option<Vec<u8>>,
    pub lstchg: Option<i64>,
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub warn: Option<i64>,
    pub inact: Option<i64>,
    pub expire: Option<i64>,
    pub flag: Option<u64>,
}

impl ShadowOverrides {
    pub fn apply(&self, entry: &mut ShadowEntry) {
        if let Some(value) = &self.passwd {
            entry.passwd.clone_from(value);
        }
        if let Some(value) = self.lstchg {
            entry.lstchg = value;
        }
        if let Some(value) = self.min {
            entry.min = value;
        }
        if let Some(value) = self.max {
            entry.max = value;
        }
        if let Some(value) = self.warn {
            entry.warn = value;
        }
        if let Some(value) = self.inact {
            entry.inact = value;
        }
        if let Some(value) = self.expire {
            entry.expire = value;
        }
        if let Some(value) = self.flag {
            entry.flag = value;
        }
    }
}

/// Names already excluded or successfully imported by this traversal.
///
/// Local accounts do not enter this set: a local row and an imported row may
/// have the same name and both appear in enumeration. Repeated imports are
/// suppressed, including an explicit `+name` followed by a bare `+`.
#[derive(Debug, Clone, Default)]
pub struct Selection {
    blocked: HashSet<Vec<u8>>,
}

impl Selection {
    pub fn permits_remote(&self, name: &[u8]) -> bool {
        !self.blocked.contains(name)
    }

    pub fn exclude(&mut self, name: &[u8]) {
        self.blocked.insert(name.to_vec());
    }

    /// Record an imported account only after successful publication. Keeping
    /// this separate from `permits_remote` leaves a failed packing retry live.
    pub fn record_remote(&mut self, name: &[u8]) {
        self.blocked.insert(name.to_vec());
    }

    pub fn clear(&mut self) {
        self.blocked.clear();
    }
}

fn account_line(line: &[u8]) -> Option<&[u8]> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let first = line
        .iter()
        .position(|&byte| byte != b' ' && byte != b'\t')
        .unwrap_or(line.len());
    let line = &line[first..];
    (!line.is_empty() && line[0] != b'#').then_some(line)
}

fn is_directive(name: &[u8]) -> bool {
    matches!(name.first(), Some(b'+') | Some(b'-'))
}

fn marker_only(fields: &[&[u8]]) -> bool {
    fields.len() == 1 || (fields.len() == 2 && fields[1].is_empty())
}

fn directive<T, O>(name: &[u8], netgroups: bool, overrides: O) -> Option<Record<T, O>> {
    let (&operation, name) = name.split_first()?;
    let selector = if name.is_empty() {
        if operation != b'+' {
            return None;
        }
        Selector::All
    } else if netgroups && name[0] == b'@' {
        Selector::Netgroup(name[1..].to_vec())
    } else {
        Selector::Name(name.to_vec())
    };
    match operation {
        b'+' => Some(Record::Include {
            selector,
            overrides,
        }),
        b'-' => Some(Record::Exclude(selector)),
        _ => None,
    }
}

fn nonempty(bytes: &[u8]) -> Option<Vec<u8>> {
    (!bytes.is_empty()).then(|| bytes.to_vec())
}

/// Empty numeric fields in compatibility directives mean "use the remote
/// id". They still need a following separator; an empty, unterminated last
/// id field is a short record. Nonempty ids retain the ordinary parser's
/// complete decimal and u32-range validation but are never applied remotely.
fn normalized_ids(fields: &[&[u8]], indices: &[usize]) -> Option<Vec<u8>> {
    for &index in indices {
        let field = fields.get(index)?;
        if field.is_empty() && index + 1 == fields.len() {
            return None;
        }
    }
    let mut normalized = Vec::new();
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            normalized.push(b':');
        }
        if indices.contains(&index) && field.is_empty() {
            normalized.push(b'0');
        } else {
            normalized.extend_from_slice(field);
        }
    }
    Some(normalized)
}

/// Parse one physical passwd line without advancing any caller cursor.
/// Comments, malformed rows and bare `-` do not produce a record.
pub fn parse_passwd_record(line: &[u8]) -> Option<PasswdRecord> {
    let line = account_line(line)?;
    if !is_directive(line) {
        return crate::pwd::parse_passwd_line(line).map(Record::Local);
    }
    let fields: Vec<_> = line.splitn(7, |&byte| byte == b':').collect();
    let overrides = if marker_only(&fields) {
        PasswdOverrides::default()
    } else {
        let normalized = normalized_ids(&fields, &[2, 3])?;
        let parsed = crate::pwd::parse_passwd_line(&normalized)?;
        PasswdOverrides {
            passwd: nonempty(&parsed.pw_passwd),
            gecos: nonempty(&parsed.pw_gecos),
            dir: nonempty(&parsed.pw_dir),
            shell: nonempty(&parsed.pw_shell),
        }
    };
    directive(fields[0], true, overrides)
}

/// Parse one group line. An `@` after the sign is part of a literal group
/// name, because group compatibility does not expand netgroups.
pub fn parse_group_record(line: &[u8]) -> Option<GroupRecord> {
    let line = account_line(line)?;
    if !is_directive(line) {
        return crate::grp::parse_group_line(line).map(Record::Local);
    }
    let fields: Vec<_> = line.splitn(4, |&byte| byte == b':').collect();
    if !marker_only(&fields) {
        let normalized = normalized_ids(&fields, &[2])?;
        crate::grp::parse_group_line(&normalized)?;
    }
    directive(fields[0], false, GroupOverrides)
}

/// GNU compatibility accepts the old shadow form `name:password:chg:min:max:`
/// as well as the complete nine-field form. The last old-format field must
/// be empty. Reuse the existing numeric parser after filling its absent tail.
fn shadow_entry(line: &[u8], fields: &[&[u8]]) -> Option<ShadowEntry> {
    match fields.len() {
        6 if fields[5].is_empty() => {
            let mut complete = line.to_vec();
            complete.extend_from_slice(b":::");
            crate::pwd::shadow::parse_shadow_line(&complete)
        }
        9 => crate::pwd::shadow::parse_shadow_line(line),
        _ => None,
    }
}

/// Parse one shadow line, preserving the distinction between a bare marker
/// and a full row whose empty first three numeric fields clear remote values.
pub fn parse_shadow_record(line: &[u8]) -> Option<ShadowRecord> {
    let line = account_line(line.trim_ascii_start())?;
    let fields: Vec<_> = line.split(|&byte| byte == b':').collect();
    if !is_directive(line) {
        return shadow_entry(line, &fields).map(Record::Local);
    }
    let overrides = if marker_only(&fields) {
        ShadowOverrides::default()
    } else {
        let parsed = shadow_entry(line, &fields)?;
        ShadowOverrides {
            passwd: nonempty(&parsed.passwd),
            lstchg: Some(parsed.lstchg),
            min: Some(parsed.min),
            max: Some(parsed.max),
            warn: fields
                .get(5)
                .filter(|field| !field.is_empty())
                .map(|_| parsed.warn),
            inact: fields
                .get(6)
                .filter(|field| !field.is_empty())
                .map(|_| parsed.inact),
            expire: fields
                .get(7)
                .filter(|field| !field.is_empty())
                .map(|_| parsed.expire),
            flag: fields
                .get(8)
                .filter(|field| !field.is_empty())
                .map(|_| parsed.flag),
        }
    };
    directive(fields[0], true, overrides)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote_passwd() -> Passwd {
        crate::pwd::parse_passwd_line(b"alice:x:4201:4301:Remote User:/home/alice:/bin/sh").unwrap()
    }

    fn remote_group() -> Group {
        crate::grp::parse_group_line(b"staff:x:4301:alice,bob").unwrap()
    }

    fn remote_shadow() -> ShadowEntry {
        crate::pwd::shadow::parse_shadow_line(b"alice:hash:19001:2:300:13:14:15:16").unwrap()
    }

    #[test]
    fn ordinary_accounts_keep_their_existing_fields_and_short_forms() {
        assert_eq!(
            parse_passwd_record(b" \talice:x:4201:4301:Remote User:/home/alice:/bin/sh\n"),
            Some(Record::Local(remote_passwd()))
        );
        assert_eq!(
            parse_group_record(b"staff:x:4301:alice,bob\r\n"),
            Some(Record::Local(remote_group()))
        );
        let Some(Record::Local(passwd)) = parse_passwd_record(b"alice:x:4201:4301") else {
            panic!("ordinary passwd rows may end at a nonempty gid");
        };
        assert_eq!((passwd.pw_uid, passwd.pw_gid), (4201, 4301));
        assert!(
            passwd.pw_gecos.is_empty() && passwd.pw_dir.is_empty() && passwd.pw_shell.is_empty()
        );
        let Some(Record::Local(group)) = parse_group_record(b"staff:x:4301") else {
            panic!("ordinary group rows may end at a nonempty gid");
        };
        assert!(group.gr_mem.is_empty());
        assert_eq!(group.gr_gid, 4301);
    }

    #[test]
    fn signs_select_remote_names_and_netgroups_without_creating_local_accounts() {
        assert_eq!(
            parse_passwd_record(b"+alice"),
            Some(Record::Include {
                selector: Selector::Name(b"alice".to_vec()),
                overrides: PasswdOverrides::default(),
            })
        );
        assert_eq!(
            parse_shadow_record(b"-@blocked\n"),
            Some(Record::Exclude(Selector::Netgroup(b"blocked".to_vec())))
        );
        assert_eq!(
            parse_group_record(b"+@staff"),
            Some(Record::Include {
                selector: Selector::Name(b"@staff".to_vec()),
                overrides: GroupOverrides,
            }),
            "group compatibility treats @ as part of the group name"
        );
        assert_eq!(
            parse_passwd_record(b"+"),
            Some(Record::Include {
                selector: Selector::All,
                overrides: PasswdOverrides::default(),
            })
        );
        for ignored in [b"".as_slice(), b" \t", b" # comment", b"-", b"-:"] {
            assert!(parse_passwd_record(ignored).is_none(), "{ignored:?}");
            assert!(parse_group_record(ignored).is_none(), "{ignored:?}");
            assert!(parse_shadow_record(ignored).is_none(), "{ignored:?}");
        }
    }

    #[test]
    fn empty_field_shapes_match_the_measured_gnu_directive_grammar() {
        for colons in 0..=9 {
            let line = format!("+alice{}", ":".repeat(colons));
            assert_eq!(
                parse_passwd_record(line.as_bytes()).is_some(),
                colons <= 1 || colons >= 4,
                "passwd {line}"
            );
            assert_eq!(
                parse_group_record(line.as_bytes()).is_some(),
                colons <= 1 || colons >= 3,
                "group {line}"
            );
            assert_eq!(
                parse_shadow_record(line.as_bytes()).is_some(),
                matches!(colons, 0 | 1 | 5 | 8),
                "shadow {line}"
            );
        }
        for line in [b"+alice:password".as_slice(), b"-alice:password"] {
            assert!(parse_passwd_record(line).is_none());
            assert!(parse_group_record(line).is_none());
            assert!(parse_shadow_record(line).is_none());
        }
    }

    #[test]
    fn passwd_overrides_change_text_but_never_remote_identity() {
        let Some(Record::Include { overrides, .. }) =
            parse_passwd_record(b"+alice:override:123:456:Local User:/special:/bin/false")
        else {
            panic!("valid passwd directive");
        };
        let mut entry = remote_passwd();
        overrides.apply(&mut entry);
        assert_eq!(entry.pw_name, b"alice");
        assert_eq!((entry.pw_uid, entry.pw_gid), (4201, 4301));
        assert_eq!(entry.pw_passwd, b"override");
        assert_eq!(entry.pw_gecos, b"Local User");
        assert_eq!(entry.pw_dir, b"/special");
        assert_eq!(entry.pw_shell, b"/bin/false");
        assert!(!entry.nis_compat_null_fields);
    }

    #[test]
    fn empty_passwd_overrides_preserve_fields_and_extra_colons_remain_shell_text() {
        for line in [b"+alice".as_slice(), b"+alice:", b"+alice::::::"] {
            let Some(Record::Include { overrides, .. }) = parse_passwd_record(line) else {
                panic!("valid marker {line:?}");
            };
            let mut entry = remote_passwd();
            overrides.apply(&mut entry);
            assert_eq!(entry, remote_passwd());
        }
        let Some(Record::Include { overrides, .. }) = parse_passwd_record(b"+alice::::::::") else {
            panic!("colons after the shell delimiter are shell bytes");
        };
        let mut entry = remote_passwd();
        overrides.apply(&mut entry);
        assert_eq!(entry.pw_shell, b"::");
        assert_eq!(entry.pw_dir, b"/home/alice");
    }

    #[test]
    fn compatibility_ids_are_validated_even_though_not_applied() {
        for uid in ["-1", "4294967296", "bad", "1x", " "] {
            let passwd = format!("+alice:pw:{uid}:4:");
            let group = format!("+staff:pw:{uid}:");
            assert!(parse_passwd_record(passwd.as_bytes()).is_none(), "{uid}");
            assert!(parse_group_record(group.as_bytes()).is_none(), "{uid}");
        }
        for line in [
            b"+alice:pw:123:456".as_slice(),
            b"+alice:pw::456",
            b"+alice:pw:123::",
            b"+alice:pw:4294967295:4294967295",
        ] {
            let Some(Record::Include { overrides, .. }) = parse_passwd_record(line) else {
                panic!("valid ids {line:?}");
            };
            let mut entry = remote_passwd();
            overrides.apply(&mut entry);
            assert_eq!((entry.pw_uid, entry.pw_gid), (4201, 4301));
            assert_eq!(entry.pw_passwd, b"pw");
        }
        assert!(parse_passwd_record(b"+alice:pw:123:").is_none());
        assert!(parse_group_record(b"+staff:pw:").is_none());
    }

    #[test]
    fn group_directive_fields_do_not_replace_remote_password_or_members() {
        for line in [
            b"+staff:changed:123:local,other".as_slice(),
            b"+staff:pw:123",
            b"+staff:::",
        ] {
            let Some(Record::Include { overrides, .. }) = parse_group_record(line) else {
                panic!("valid group directive {line:?}");
            };
            let mut entry = remote_group();
            overrides.apply(&mut entry);
            assert_eq!(entry, remote_group());
        }
    }

    #[test]
    fn shadow_bare_markers_preserve_all_remote_fields() {
        for line in [b"+".as_slice(), b"+:", b"+alice", b"+alice:", b"+@staff"] {
            let Some(Record::Include { overrides, .. }) = parse_shadow_record(line) else {
                panic!("valid shadow marker {line:?}");
            };
            let mut entry = remote_shadow();
            overrides.apply(&mut entry);
            assert_eq!(entry, remote_shadow());
        }
    }

    #[test]
    fn shadow_empty_fields_clear_only_the_first_three_numeric_values() {
        for line in [b"+alice:changed:::::::".as_slice(), b"+alice:changed::::"] {
            let Some(Record::Include { overrides, .. }) = parse_shadow_record(line) else {
                panic!("valid full or old shadow row {line:?}");
            };
            let mut entry = remote_shadow();
            overrides.apply(&mut entry);
            assert_eq!(entry.name, b"alice");
            assert_eq!(entry.passwd, b"changed");
            assert_eq!((entry.lstchg, entry.min, entry.max), (-1, -1, -1));
            assert_eq!(
                (entry.warn, entry.inact, entry.expire, entry.flag),
                (13, 14, 15, 16)
            );
        }
    }

    #[test]
    fn shadow_nonempty_numeric_overrides_and_old_format_are_distinct() {
        let Some(Record::Include { overrides, .. }) =
            parse_shadow_record(b"+alice:changed:1:2:3:4:5:6:7")
        else {
            panic!("full shadow overrides");
        };
        let mut entry = remote_shadow();
        overrides.apply(&mut entry);
        assert_eq!((entry.lstchg, entry.min, entry.max), (1, 2, 3));
        assert_eq!(
            (entry.warn, entry.inact, entry.expire, entry.flag),
            (4, 5, 6, 7)
        );
        let Some(Record::Include { overrides, .. }) =
            parse_shadow_record(b"+alice:changed:11:22:33:")
        else {
            panic!("old shadow overrides");
        };
        let mut entry = remote_shadow();
        overrides.apply(&mut entry);
        assert_eq!((entry.lstchg, entry.min, entry.max), (11, 22, 33));
        assert_eq!(
            (entry.warn, entry.inact, entry.expire, entry.flag),
            (13, 14, 15, 16)
        );
        assert!(parse_shadow_record(b"+alice:changed:11:22:33:44").is_none());
    }

    #[test]
    fn shadow_literal_negative_fields_and_extra_columns_are_rejected() {
        for index in 2..9 {
            let mut fields = ["+alice", "changed", "", "", "", "", "", "", ""];
            fields[index] = "-1";
            assert!(parse_shadow_record(fields.join(":").as_bytes()).is_none());
        }
        assert!(parse_shadow_record(b"+alice:changed:1:2:3:4:5:6:7:").is_none());
        assert!(parse_shadow_record(b"+alice:changed:1:2:3:4:5:6").is_none());
    }

    #[test]
    fn ordinary_shadow_records_support_old_format_without_remote_defaults() {
        let Some(Record::Local(entry)) = parse_shadow_record(b"alice:hash:11:22:33:") else {
            panic!("old local shadow row");
        };
        assert_eq!((entry.lstchg, entry.min, entry.max), (11, 22, 33));
        assert_eq!(
            (entry.warn, entry.inact, entry.expire, entry.flag),
            (-1, -1, -1, u64::MAX)
        );
        assert_eq!(
            parse_shadow_record(b"alice:hash:19001:2:300:13:14:15:16"),
            Some(Record::Local(remote_shadow()))
        );
    }

    #[test]
    fn remote_selection_does_not_consume_failed_publications_or_local_names() {
        let mut selection = Selection::default();
        selection.exclude(b"blocked");
        assert!(!selection.permits_remote(b"blocked"));
        assert!(selection.permits_remote(b"alice"));
        // Checking/packing an account can fail repeatedly without advancing
        // its name selection. The ABI calls record_remote only on publication.
        assert!(selection.permits_remote(b"alice"));
        selection.record_remote(b"alice");
        assert!(!selection.permits_remote(b"alice"));
        assert!(selection.permits_remote(b"local"));
        selection.clear();
        assert!(selection.permits_remote(b"alice"));
        assert!(selection.permits_remote(b"blocked"));
    }
}
