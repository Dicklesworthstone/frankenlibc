//! Name Service Switch dispatch policy for the passwd, group, shadow and
//! initgroups databases.
//!
//! Clean-room from the GNU libc manual ("The NSS Configuration File",
//! "Actions in the NSS configuration") and behaviour measured against glibc
//! 2.39 with a dlopen'ed test service module (`tests/integration/
//! fixture_nss_module_lib.c`, driven by `fixture_nss_modules.c` under a
//! bind-mounted nsswitch.conf). This module is pure policy: it parses the
//! configuration and decides which source answers. Running a source -- the
//! native files backend or a `libnss_<service>.so.2` module -- is the ABI
//! layer's job.
//!
//! Measured rules encoded here:
//! - A database line lists sources in order, each optionally followed by
//!   `[STATUS=ACTION ...]` blocks (`!STATUS` negates; case-insensitive). The
//!   default actions are SUCCESS=return, everything else continue.
//! - The last line for a database wins; a missing line means `files` alone,
//!   except that `initgroups` falls back to the `group` line and `shadow` to
//!   the `passwd` line when they have none. An explicitly empty line means no
//!   sources at all.
//! - `merge` (group database only): a SUCCESS result is held and the next
//!   source's SUCCESS result is merged into it when the group name and gid
//!   both match (members appended, no de-duplication, the first result's
//!   name/password/gid kept). A non-matching or failed later result leaves
//!   the held result in place as that source's SUCCESS, so its SUCCESS action
//!   decides what happens next.
//! - initgroups sources from the `group:` line never stop on SUCCESS: every
//!   source is consulted unless a non-SUCCESS status maps to `return`. An
//!   explicit `initgroups:` line honours all actions, including the default
//!   SUCCESS=return. Each source's gids are appended and
//!   any gid already contributed by an EARLIER source (or the base group) is
//!   removed by moving the segment's last gid into its slot and re-checking
//!   that slot.

/// A service's answer, as an NSS module reports it (`enum nss_status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Success,
    NotFound,
    Unavailable,
    TryAgain,
}

impl Status {
    const ALL: [Self; 4] = [
        Self::Success,
        Self::NotFound,
        Self::Unavailable,
        Self::TryAgain,
    ];

    fn index(self) -> usize {
        match self {
            Self::Success => 0,
            Self::NotFound => 1,
            Self::Unavailable => 2,
            Self::TryAgain => 3,
        }
    }

    fn parse(token: &[u8]) -> Option<Self> {
        [b"success".as_slice(), b"notfound", b"unavail", b"tryagain"]
            .iter()
            .position(|name| token.eq_ignore_ascii_case(name))
            .map(|index| Self::ALL[index])
    }

    /// Map a module's `enum nss_status` value. `NSS_STATUS_RETURN` (2) is an
    /// internal glibc status no module should report; treat it, and anything
    /// else unexpected, as an unavailable source.
    pub fn from_raw(raw: i32) -> Self {
        match raw {
            1 => Self::Success,
            0 => Self::NotFound,
            -2 => Self::TryAgain,
            _ => Self::Unavailable,
        }
    }
}

/// What the switch does after a source answers with a given status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Return,
    Continue,
    Merge,
}

/// How a configured source is executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// The native files backend (`files`, and `compat`, whose NIS `+`/`-`
    /// records the files parser already reports verbatim).
    Files,
    /// A `libnss_<name>.so.2` service module.
    Module,
}

/// One configured source and its status actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    name: Vec<u8>,
    actions: [Action; 4],
}

impl Service {
    fn new(name: &[u8]) -> Self {
        Self {
            name: name.to_vec(),
            actions: [
                Action::Return,
                Action::Continue,
                Action::Continue,
                Action::Continue,
            ],
        }
    }

    /// The service name as written (`files`, `sss`, `systemd`, ...).
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    pub fn kind(&self) -> SourceKind {
        match self.name.as_slice() {
            b"files" | b"compat" => SourceKind::Files,
            _ => SourceKind::Module,
        }
    }

    pub fn action(&self, status: Status) -> Action {
        self.actions[status.index()]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError;

/// The databases this policy engine dispatches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Database {
    Passwd,
    Group,
    Shadow,
    Initgroups,
}

impl Database {
    fn key(self) -> &'static [u8] {
        match self {
            Self::Passwd => b"passwd",
            Self::Group => b"group",
            Self::Shadow => b"shadow",
            Self::Initgroups => b"initgroups",
        }
    }
}

/// The source list of one database, resolved from an nsswitch.conf image.
///
/// `None` content (no readable file) and a file without a line for the
/// database both mean glibc's built-in default, `files`. A malformed line is
/// skipped as if absent, so an earlier well-formed line can still apply.
pub fn services_for(config: Option<&[u8]>, database: Database) -> Vec<Service> {
    let Some(config) = config else {
        return vec![Service::new(b"files")];
    };
    if let Some(services) = parse_database(config, database.key()) {
        return services;
    }
    let fallback = match database {
        Database::Initgroups => Some(Database::Group),
        Database::Shadow => Some(Database::Passwd),
        Database::Passwd | Database::Group => None,
    };
    if let Some(fallback) = fallback
        && let Some(services) = parse_database(config, fallback.key())
    {
        return services;
    }
    vec![Service::new(b"files")]
}

/// The last well-formed line for `database`, or `None` when there is none.
fn parse_database(config: &[u8], database: &[u8]) -> Option<Vec<Service>> {
    let mut selected = None;
    for line in config.split(|&b| b == b'\n') {
        let line = line.split(|&b| b == b'#').next().unwrap_or_default();
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        if line[..colon].trim_ascii() != database {
            continue;
        }
        if let Ok(services) = parse_sources(&line[colon + 1..]) {
            selected = Some(services);
        }
    }
    selected
}

fn parse_sources(line: &[u8]) -> Result<Vec<Service>, ParseError> {
    let mut input = Scanner {
        bytes: line,
        pos: 0,
    };
    let mut services = Vec::new();
    loop {
        input.whitespace();
        if input.end() {
            return Ok(services);
        }
        let name = input.word();
        if name.is_empty()
            || !name
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'-' | b'.'))
        {
            return Err(ParseError);
        }
        let mut service = Service::new(name);
        input.whitespace();
        while input.take(b'[') {
            let mut count = 0;
            loop {
                input.whitespace();
                if input.take(b']') {
                    if count == 0 {
                        return Err(ParseError);
                    }
                    break;
                }
                let negate = input.take(b'!');
                input.whitespace();
                let status = Status::parse(input.word()).ok_or(ParseError)?;
                input.whitespace();
                if !input.take(b'=') {
                    return Err(ParseError);
                }
                input.whitespace();
                let token = input.word();
                let action = if token.eq_ignore_ascii_case(b"return") {
                    Action::Return
                } else if token.eq_ignore_ascii_case(b"continue") {
                    Action::Continue
                } else if token.eq_ignore_ascii_case(b"merge") {
                    Action::Merge
                } else {
                    return Err(ParseError);
                };
                for candidate in Status::ALL {
                    if (candidate == status) != negate {
                        service.actions[candidate.index()] = action;
                    }
                }
                count += 1;
            }
            input.whitespace();
        }
        services.push(service);
    }
}

struct Scanner<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Scanner<'a> {
    fn end(&self) -> bool {
        self.pos == self.bytes.len()
    }
    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.pos)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.pos += 1;
        }
    }
    fn take(&mut self, byte: u8) -> bool {
        if self.bytes.get(self.pos) == Some(&byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn word(&mut self) -> &'a [u8] {
        let start = self.pos;
        while self
            .bytes
            .get(self.pos)
            .is_some_and(|b| !b.is_ascii_whitespace() && !matches!(*b, b'[' | b']' | b'=' | b'!'))
        {
            self.pos += 1;
        }
        &self.bytes[start..self.pos]
    }
}

/// One source's answer to a keyed lookup.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer<T> {
    Found(T),
    NotFound,
    /// The source could not be used; carries the errno it reported.
    Unavailable(i32),
    /// A temporary failure; carries the errno it reported.
    TryAgain(i32),
    /// TRYAGAIN with ERANGE: the caller's buffer is too small. The switch
    /// stops here whatever the configured action says.
    BufferTooSmall,
}

impl<T> Answer<T> {
    fn status(&self) -> Status {
        match self {
            Self::Found(_) => Status::Success,
            Self::NotFound => Status::NotFound,
            Self::Unavailable(_) | Self::BufferTooSmall => Status::Unavailable,
            Self::TryAgain(_) => Status::TryAgain,
        }
    }
}

/// Folds a later SUCCESS result into a held one; false when the two do not
/// describe the same entry (the later one is then discarded).
pub type MergeFn<'a, T> = &'a mut dyn FnMut(&mut T, T) -> bool;

/// Run a keyed lookup (`getpwnam`, `getgrgid`, ...) across `services`.
///
/// Pass a [`MergeFn`] for the group database; `None` for databases without
/// merge semantics, where `merge` acts as `return`. An empty source list
/// answers NotFound.
pub fn lookup<T>(
    services: &[Service],
    mut query: impl FnMut(&Service) -> Answer<T>,
    mut merge: Option<MergeFn<'_, T>>,
) -> Answer<T> {
    let mut held: Option<T> = None;
    for (index, service) in services.iter().enumerate() {
        let answer = query(service);
        if matches!(answer, Answer::BufferTooSmall) {
            return Answer::BufferTooSmall;
        }
        let answer = match held.take() {
            Some(mut kept) => {
                if let (Answer::Found(next), Some(merge)) = (answer, merge.as_mut()) {
                    // A mismatched entry is discarded; `kept` stands either way.
                    let _ = merge(&mut kept, next);
                }
                Answer::Found(kept)
            }
            None => answer,
        };
        let action = match service.action(answer.status()) {
            Action::Merge if merge.is_none() => Action::Return,
            action => action,
        };
        let is_last = index + 1 == services.len();
        match (answer, action) {
            (Answer::Found(value), Action::Merge) if !is_last => held = Some(value),
            (answer, Action::Return | Action::Merge) => return answer,
            (answer, Action::Continue) if is_last => return answer,
            (_, Action::Continue) => {}
        }
    }
    Answer::NotFound
}

/// Whether enumeration (`getpwent` and friends) moves on to the next source
/// after `service` answered `status` for the current entry.
///
/// SUCCESS normally returns the entry and stays on the same source; a source
/// that is exhausted (NOTFOUND) or unusable hands over to the next one unless
/// its action for that status is `return`, which ends the enumeration.
pub fn enumeration_advances(service: &Service, status: Status) -> bool {
    status != Status::Success && service.action(status) == Action::Continue
}

/// Whether initgroups stops after `service` answered `status`.
///
/// With an explicit `initgroups:` line every action is honoured, so the
/// default SUCCESS=return stops at the first source that found groups. When
/// the sources come from the `group:` line instead, SUCCESS never stops the
/// walk (a compatibility rule measured on glibc 2.39): only a non-SUCCESS
/// status whose action is `return` does.
pub fn initgroups_stops(service: &Service, status: Status, explicit_line: bool) -> bool {
    (explicit_line || status != Status::Success) && service.action(status) == Action::Return
}

/// Whether nsswitch.conf has its own well-formed line for `database`
/// (rather than a fallback or the built-in default).
pub fn has_database_line(config: Option<&[u8]>, database: Database) -> bool {
    config.is_some_and(|config| parse_database(config, database.key()).is_some())
}

/// Append one source's gids to `groups`, dropping any gid that an earlier
/// source (or the base group, `groups[0]`) already contributed: the dropped
/// slot takes the segment's last gid and is examined again.
pub fn append_initgroups_segment(groups: &mut Vec<u32>, segment: &[u32]) {
    let prev = groups.len();
    groups.extend_from_slice(segment);
    let mut cursor = prev;
    while cursor < groups.len() {
        if groups[..prev].contains(&groups[cursor]) {
            groups.swap_remove(cursor);
        } else {
            cursor += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(db: &str, sources: &str) -> Vec<Service> {
        services_for(
            Some(format!("{db}: {sources}\n").as_bytes()),
            match db {
                "passwd" => Database::Passwd,
                "group" => Database::Group,
                "shadow" => Database::Shadow,
                _ => Database::Initgroups,
            },
        )
    }

    fn names(services: &[Service]) -> Vec<&[u8]> {
        services.iter().map(Service::name).collect()
    }

    #[test]
    fn missing_file_or_line_defaults_to_files() {
        assert_eq!(names(&services_for(None, Database::Passwd)), [b"files"]);
        assert_eq!(
            names(&services_for(Some(b"hosts: dns\n"), Database::Group)),
            [b"files"]
        );
    }

    #[test]
    fn explicit_empty_line_has_no_sources() {
        assert!(services_for(Some(b"initgroups:\n"), Database::Initgroups).is_empty());
        let got: Answer<()> = lookup(&[], |_| panic!("no source"), None);
        assert_eq!(got, Answer::NotFound);
    }

    #[test]
    fn initgroups_falls_back_to_group_line() {
        let cfg = b"group: files sss\n";
        assert_eq!(
            names(&services_for(Some(cfg), Database::Initgroups)),
            [b"files".as_slice(), b"sss"]
        );
        let cfg = b"group: files sss\ninitgroups: files\n";
        assert_eq!(
            names(&services_for(Some(cfg), Database::Initgroups)),
            [b"files"]
        );
    }

    #[test]
    fn shadow_falls_back_to_passwd_line_but_group_does_not() {
        let cfg = b"passwd: sss files\n";
        assert_eq!(
            names(&services_for(Some(cfg), Database::Shadow)),
            [b"sss".as_slice(), b"files"]
        );
        assert_eq!(names(&services_for(Some(cfg), Database::Group)), [b"files"]);
        let cfg = b"passwd: sss files\nshadow: files\n";
        assert_eq!(
            names(&services_for(Some(cfg), Database::Shadow)),
            [b"files"]
        );
    }

    #[test]
    fn last_well_formed_line_wins_and_comments_are_stripped() {
        let cfg = b"passwd: files\npasswd: sss [bogus\npasswd: systemd files # sss\n";
        assert_eq!(
            names(&services_for(Some(cfg), Database::Passwd)),
            [b"systemd".as_slice(), b"files"]
        );
        let cfg = b"passwd: files sss\npasswd: [x\n";
        assert_eq!(
            names(&services_for(Some(cfg), Database::Passwd)),
            [b"files".as_slice(), b"sss"]
        );
    }

    #[test]
    fn source_kinds() {
        let s = line("passwd", "files compat sss systemd");
        let kinds: Vec<_> = s.iter().map(Service::kind).collect();
        assert_eq!(
            kinds,
            [
                SourceKind::Files,
                SourceKind::Files,
                SourceKind::Module,
                SourceKind::Module
            ]
        );
    }

    #[test]
    fn actions_parse_with_negation_and_case() {
        let s = line("group", "files [ !UNavail = REturn ] sss [SUCCESS=merge]");
        assert_eq!(s[0].action(Status::Success), Action::Return);
        assert_eq!(s[0].action(Status::NotFound), Action::Return);
        assert_eq!(s[0].action(Status::Unavailable), Action::Continue);
        assert_eq!(s[0].action(Status::TryAgain), Action::Return);
        assert_eq!(s[1].action(Status::Success), Action::Merge);
        assert_eq!(s[1].action(Status::NotFound), Action::Continue);
    }

    #[test]
    fn default_order_returns_first_success() {
        let s = line("passwd", "files sss");
        let mut calls = Vec::new();
        let got = lookup(
            &s,
            |svc| {
                calls.push(svc.name().to_vec());
                Answer::Found(1)
            },
            None,
        );
        assert_eq!(got, Answer::Found(1));
        assert_eq!(calls, [b"files".to_vec()]);
    }

    #[test]
    fn notfound_continues_and_return_stops() {
        let s = line("passwd", "files sss");
        let got = lookup(
            &s,
            |svc| match svc.name() {
                b"files" => Answer::NotFound,
                _ => Answer::Found(7),
            },
            None,
        );
        assert_eq!(got, Answer::Found(7));
        let s = line("passwd", "sss [UNAVAIL=return] files");
        let got: Answer<i32> = lookup(
            &s,
            |svc| match svc.name() {
                b"sss" => Answer::Unavailable(2),
                _ => panic!("files must not run"),
            },
            None,
        );
        assert_eq!(got, Answer::Unavailable(2));
    }

    #[test]
    fn final_failure_is_reported_from_the_last_source() {
        let s = line("passwd", "sss files");
        let got: Answer<i32> = lookup(
            &s,
            |svc| match svc.name() {
                b"sss" => Answer::TryAgain(11),
                _ => Answer::NotFound,
            },
            None,
        );
        assert_eq!(got, Answer::NotFound);
    }

    #[test]
    fn buffer_too_small_stops_even_with_continue() {
        let s = line("passwd", "files [TRYAGAIN=continue] sss");
        let got: Answer<i32> = lookup(
            &s,
            |svc| match svc.name() {
                b"files" => Answer::BufferTooSmall,
                _ => panic!("sss must not run"),
            },
            None,
        );
        assert_eq!(got, Answer::BufferTooSmall);
    }

    type Grp = (&'static str, u32, Vec<&'static str>);

    fn merge_grp(held: &mut Grp, next: Grp) -> bool {
        if held.0 != next.0 || held.1 != next.1 {
            return false;
        }
        held.2.extend(next.2);
        true
    }

    #[test]
    fn group_merge_appends_members_of_matching_entries() {
        let s = line("group", "files [SUCCESS=merge] sss [SUCCESS=merge] files");
        let mut merge = merge_grp;
        let got = lookup(
            &s,
            |svc| match svc.name() {
                b"files" => Answer::Found(("g", 1, vec!["a"])),
                _ => Answer::Found(("g", 1, vec!["b"])),
            },
            Some(&mut merge),
        );
        assert_eq!(got, Answer::Found(("g", 1, vec!["a", "b", "a"])));
    }

    #[test]
    fn group_merge_discards_mismatch_but_keeps_merging() {
        let s = line("group", "files [SUCCESS=merge] sss [SUCCESS=merge] files");
        let mut merge = merge_grp;
        let got = lookup(
            &s,
            |svc| match svc.name() {
                b"files" => Answer::Found(("g", 9, vec!["c"])),
                _ => Answer::Found(("g", 4, vec!["x"])),
            },
            Some(&mut merge),
        );
        assert_eq!(got, Answer::Found(("g", 9, vec!["c", "c"])));
        // Default SUCCESS action after a mismatch: the held entry returns.
        let s = line("group", "files [SUCCESS=merge] sss files");
        let got = lookup(
            &s,
            |svc| match svc.name() {
                b"files" => Answer::Found(("g", 9, vec!["c"])),
                _ => Answer::Found(("g", 4, vec!["x"])),
            },
            Some(&mut merge),
        );
        assert_eq!(got, Answer::Found(("g", 9, vec!["c"])));
    }

    #[test]
    fn merge_held_entry_survives_a_later_miss_and_terminal_merge_returns() {
        let s = line("group", "files [SUCCESS=merge] sss");
        let mut merge = merge_grp;
        let got = lookup(
            &s,
            |svc| match svc.name() {
                b"files" => Answer::Found(("g", 1, vec!["a"])),
                _ => Answer::Unavailable(2),
            },
            Some(&mut merge),
        );
        assert_eq!(got, Answer::Found(("g", 1, vec!["a"])));
        let s = line("group", "files [SUCCESS=merge]");
        let got = lookup(&s, |_| Answer::Found(("g", 1, vec!["a"])), Some(&mut merge));
        assert_eq!(got, Answer::Found(("g", 1, vec!["a"])));
    }

    #[test]
    fn merge_without_merge_semantics_acts_as_return() {
        let s = line("passwd", "files [SUCCESS=merge] sss");
        let got = lookup(
            &s,
            |svc| match svc.name() {
                b"files" => Answer::Found(1),
                _ => panic!("passwd has no merge"),
            },
            None,
        );
        assert_eq!(got, Answer::Found(1));
    }

    #[test]
    fn enumeration_and_initgroups_actions() {
        let s = line("group", "files [NOTFOUND=return SUCCESS=return] sss");
        assert!(!enumeration_advances(&s[0], Status::Success));
        assert!(!enumeration_advances(&s[0], Status::NotFound));
        assert!(enumeration_advances(&s[0], Status::Unavailable));
        assert!(enumeration_advances(&s[1], Status::NotFound));
        assert!(!initgroups_stops(&s[0], Status::Success, false));
        assert!(initgroups_stops(&s[0], Status::NotFound, false));
        assert!(!initgroups_stops(&s[1], Status::Unavailable, false));
        // An explicit initgroups line honours SUCCESS=return (the default).
        assert!(initgroups_stops(&s[0], Status::Success, true));
        assert!(initgroups_stops(&s[1], Status::Success, true));
        let s = line("initgroups", "files [SUCCESS=continue] sss");
        assert!(!initgroups_stops(&s[0], Status::Success, true));
    }

    #[test]
    fn database_line_presence() {
        let cfg = b"group: files sss\n";
        assert!(has_database_line(Some(cfg), Database::Group));
        assert!(!has_database_line(Some(cfg), Database::Initgroups));
        assert!(!has_database_line(None, Database::Group));
        assert!(has_database_line(
            Some(b"initgroups:\n"),
            Database::Initgroups
        ));
    }

    #[test]
    fn initgroups_dedup_moves_last_gid_into_dropped_slot_and_rechecks() {
        // Measured on glibc 2.39: base 4301, module {4302,4303,0}, then files
        // {4400,4303,10,29,44} -> 4301 4302 4303 0 4400 44 10 29.
        let mut g = vec![4301];
        append_initgroups_segment(&mut g, &[4302, 4303, 0]);
        append_initgroups_segment(&mut g, &[4400, 4303, 10, 29, 44]);
        assert_eq!(g, [4301, 4302, 4303, 0, 4400, 44, 10, 29]);
        // files {0,4400,4303,10,4302}: the swapped-in 4302 is checked too.
        let mut g = vec![4301];
        append_initgroups_segment(&mut g, &[4302, 4303, 0]);
        append_initgroups_segment(&mut g, &[0, 4400, 4303, 10, 4302]);
        assert_eq!(g, [4301, 4302, 4303, 0, 10, 4400]);
        // Duplicates inside one segment are kept.
        let mut g = vec![1];
        append_initgroups_segment(&mut g, &[2, 2]);
        assert_eq!(g, [1, 2, 2]);
    }

    #[test]
    fn status_from_raw_module_values() {
        assert_eq!(Status::from_raw(1), Status::Success);
        assert_eq!(Status::from_raw(0), Status::NotFound);
        assert_eq!(Status::from_raw(-1), Status::Unavailable);
        assert_eq!(Status::from_raw(-2), Status::TryAgain);
        assert_eq!(Status::from_raw(2), Status::Unavailable);
    }
}
